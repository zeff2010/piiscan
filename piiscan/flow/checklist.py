"""把「测评项状态」装配成「报告模板的 22 项」。

这一层是**模板与测评项之间唯一的翻译点**。
加一份新模板 = 在 checkflow.yaml 里加一组 report_items，
测评项库（checkitems.yaml）和采集层都不用动 —— 这是当初定下的扩展原则。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from . import attribution as ATTR
from .models import (FAIL, NOT_TESTED, PASS, SUSPECT, STATE_LABELS, STATE_ORDER,
                     FlowResult, ItemState, ReportRow)

_ROOT = Path(__file__).resolve().parents[2]
CHECKFLOW = _ROOT / "analysis" / "checkflow.yaml"
CHECKITEMS = _ROOT / "analysis" / "checkitems.yaml"


def load_checkflow(path: Path = CHECKFLOW) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_checkitems(path: Path = CHECKITEMS) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def report_items(flow: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return (flow or load_checkflow()).get("report_items") or []


def phases(flow: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return (flow or load_checkflow()).get("phases") or []


def items_index(items: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    d = items or load_checkitems()
    return {it["id"]: it for it in (d.get("items") or [])}


def new_item(qid: str, index: Optional[Dict[str, Dict[str, Any]]] = None) -> ItemState:
    """造一个「未测」状态的测评项。任何没被证据喂到的项都从这里出发。"""
    idx = index or items_index()
    it = idx.get(qid, {})
    return ItemState(
        qid=qid,
        title=it.get("title", qid),
        category=it.get("category", ""),
        basis=it.get("basis", ""),
        automation=it.get("automation", ""),
        state=NOT_TESTED,
        reason="本次流程未取得判定所需的证据",
    )


def _basis_sentence(row: Dict[str, Any], state: str = "") -> str:
    """拼「依据…（认定为 / 未发现 / 疑似）…」这句话。

    模板里有两种写法：有测评单元的（GB/T 42582）和只有法规名的（个保法）。
    没有 clause 时不能硬塞一个空的「中 测评单元（）」进去，
    那样输出会变成「依据《个人信息保护法》中 测评单元（）」——看着就像机器写坏了。

    ★ 结论动词必须随状态变（自设捏脸第 4 轮实测发现的措辞事故）：
      22 项报告项的题面**全是否定式**（"未公开收集使用规则""未经用户同意收集…"）。
      早先不管什么状态都写「认定为“未公开收集使用规则”」——
      一个"未发现问题"的条目，描述却写着"认定为未公开收集使用规则"，
      复核员一眼扫过去只会读出"这是个问题项"。
      题面已经带"未"了，动词再不跟着变，整句就成了反话。
    """
    std = (row.get("standard") or "").strip()
    clause = (row.get("clause") or "").strip()
    unit = (row.get("unit") or "").strip()
    conclusion = (row.get("conclusion") or "").strip()
    head = "依据《%s》" % std if std else "依据相关规定"
    if clause and unit:
        head += "中%s 测评单元（%s）" % (clause, unit)
    if state == PASS:
        return "%s，未发现“%s”的情形。" % (head, conclusion)
    if state == SUSPECT:
        return "%s，疑似存在“%s”的情形，需人工复核确认。" % (head, conclusion)
    return "%s，认定为“%s”。" % (head, conclusion)


def _desc_for(row: Dict[str, Any], st: ItemState) -> str:
    if st.state == FAIL:
        body = st.desc.strip() or "具体问题描述待补充。"
        return "%s。%s" % (body, _basis_sentence(row, FAIL))
    if st.state == SUSPECT:
        body = st.desc.strip() or "发现疑似线索，需人工复核。"
        return "%s。%s" % (body, _basis_sentence(row, SUSPECT))
    if st.state == PASS:
        # ★「未发现问题」也必须说清**凭什么**是这个结论。
        #   早先这里是一句固定套话（"本次检测已取得证据，未发现…的情形"），
        #   22 项里凡是 pass 的全是同一句 —— 复核员看不出结论建立在什么之上，
        #   既没法核对，也没法判断这个"没问题"是不是真的测过。
        #   阶段里写好的具体依据（如"取得政策正文 31955 字""未观测到同意前收集"）
        #   必须原样带出来。
        body = (st.desc or "").strip()
        if body:
            return "%s。%s" % (body.rstrip("。"), _basis_sentence(row, PASS))
        return "本次检测已取得证据，未发现%s的情形。" % (
            row.get("conclusion") or row.get("title", "该项问题"))
    # not_tested
    why = st.reason.strip() or "未取得判定所需的证据"
    # reason 本身已经是一句完整的话时，不要再套一层括号 —— 两层括号读起来
    # 会变成「未覆盖该项（……（……）……），跳过未测」，复核员得倒着断句。
    if len(why) > 30 or "。" in why:
        return "跳过未测。%s" % why if why.endswith("。") else "跳过未测。%s。" % why
    return "本次检测未覆盖该项（%s），跳过未测。" % why


def build_rows(fr: FlowResult,
               flow: Optional[Dict[str, Any]] = None) -> List[ReportRow]:
    """按模板 22 项装配输出行。

    聚合规则：一项报告项可能挂着多个测评项，
    取其中最严重的那个状态（fail > suspect > pass > not_tested）。
    """
    flow = flow or load_checkflow()
    rows: List[ReportRow] = []
    for spec in report_items(flow):
        qids = spec.get("checks") or []
        subs: List[Dict[str, Any]] = []
        worst: Optional[ItemState] = None
        for qid in qids:
            st = fr.items.get(qid) or new_item(qid)
            subs.append({
                "qid": qid,
                "title": st.title,
                "state": st.state,
                "state_label": STATE_LABELS.get(st.state, st.state),
                "reason": st.reason,
                "level": st.level,
                "phase": st.source_phase,
            })
            if worst is None or STATE_ORDER.get(st.state, 9) < STATE_ORDER.get(worst.state, 9):
                worst = st
        if worst is None:
            # 报告项没挂任何测评项 —— 说明模板与库没对上，这是配置错误，
            # 必须显式地当作"未测"暴露出来，而不是静默丢弃。
            worst = ItemState(qid="", title=spec.get("title", ""), state=NOT_TESTED,
                              reason="该报告项未关联任何测评项（配置缺失）")
        # ★ 一个报告项常挂多个测评项（第 3 项 = Q002+Q003、第 11 项 =
        #   Q010+Q004+Q012）。证据清单必须把**所有**子项的事实并进来，
        #   只留最严重那一个的会整段丢掉另一条判定所依据的观测数据 ——
        #   实测出现过：第 4 项只显示"政策列明了目的/方式/范围"，
        #   而"本轮实际只观测到 1 种收集类型、覆盖受遍历深度限制"这条
        #   限定观测面的事实完全不见，复核员会以为收集行为已被穷尽核对。
        #   最严重子项的事实排在最前，便于复核员先看主结论的依据。
        facts: List[List[str]] = []
        links: List[str] = []
        seen: set = set()
        order = [worst] + [fr.items[q] for q in qids
                           if fr.items.get(q) is not None and fr.items[q] is not worst]
        for st_o in order:
            for f in (st_o.facts or []):
                if not f or len(f) < 2:
                    continue
                key = (str(f[0]), str(f[1]))
                if key in seen:
                    continue
                seen.add(key)
                facts.append([f[0], f[1]])
            for u in (st_o.links or []):
                if u and u not in links:
                    links.append(u)
        row = ReportRow(
            num=spec.get("num") or 0,
            title=spec.get("title", ""),
            standard=spec.get("standard", ""),
            clause=spec.get("clause", ""),
            unit=spec.get("unit", ""),
            conclusion=spec.get("conclusion", ""),
            state=worst.state,
            desc=_desc_for(spec, worst),
            example=spec.get("example", ""),
            note=spec.get("note", ""),
            checks=list(qids),
            phases=list(spec.get("phases") or []),
            auto=spec.get("auto", ""),
            shots=list(worst.shots),
            stacks=list(worst.stacks),
            # 栈与调用参数必须成对搬过去：`_stack_block` 按下标把参数
            # 贴到对应那条栈上，错一位就会"结论里的取值挂到别人的栈上"。
            stack_meta=list(getattr(worst, "stack_meta", None) or []),
            facts=facts,
            links=links,
            # 归因只对**这一行要展示的那批栈**做，保证"结论说 SDK、
            # 下面挂的栈也是 SDK"；拿全部子项的栈汇总会出现结论与证据错位。
            attribution=ATTR.summarize(list(worst.stacks), fr.package or ""),
            needs_stack=bool(worst.stacks) or any(
                (getattr(e, "kind", "") or "") in ("frida", "traffic")
                for st in order for e in (st.evidence or [])),
            sub=subs,
        )
        rows.append(row)
    return rows


def covered_phases_for(qid: str, flow: Optional[Dict[str, Any]] = None) -> List[str]:
    """这个测评项由哪些阶段负责产出证据（用于说明"为什么没测到"）。"""
    flow = flow or load_checkflow()
    out = []
    for p in phases(flow):
        if qid in (p.get("feeds") or []):
            out.append(p["id"])
    return out


# new_item() 给所有项填的占位原因。finalize 遇到它时必须重算 ——
# 否则报告里 22 项的「跳过未测」全是同一句套话，等于没说。
PLACEHOLDER_REASON = "本次流程未取得判定所需的证据"

# 自动化等级 → 人话。L3/L4 的项本来就不该指望自动出结论，
# 说清楚"需人工专业判断"，复核的人才知道该自己上，而不是以为机器漏了。
_AUTO_HINT = {
    "L3": "该项自动化程度为 L3（仅辅助），需人工确认",
    "L4": "该项自动化程度为 L4（暂不可自动化），需人工专业判断",
}

# 「阶段都跑了、却还是没结论」时，光写一句"未取得充分证据"等于没说 ——
# 复核员既不知道缺的是哪个观测，也不知道该补什么动作。
# 下面这几项的缺口是**可描述**的：不是没测，而是没触发到。
_QID_SPECIFIC = {
    "Q017": "本轮只执行了一次冷启动，开屏阶段直接进入隐私政策弹窗，未记录到跳转广告"
            "相关事件。该项判定的是「**频繁**意外跳转」，需要多次冷启动统计比例，"
            "单次采集不足以判定；需人工在不同网络与时段多次启动复现",
    "Q019": "该项需要「必须同意收集非必要个人信息才能继续使用」或「拒绝非必要授权即"
            "无法使用某功能」这类证据。本轮遍历未登录、未走到相关业务功能，"
            "未取得该证据；且「非必要」还须结合 App 业务类型判断，留有裁量",
    "Q023": "该项要求先执行「关闭个性化推荐」，再观测是否仍在收集。本轮遍历未走通"
            "关闭个性化推荐的功能路径（相关入口需登录），缺少关闭后的观测窗口",
    "Q026": "本轮界面遍历未捕获到系统权限申请弹窗（遍历路径未触发需要授权的功能，"
            "采集侧也未记录到权限申请类事件），因此缺少判定要件 ——"
            "「弹窗之前的界面上下文」与「弹窗上的目的说明文案」两者必须成对取得，"
            "只有弹窗本身无法归因为哪个功能索权",
}


# 测评项 → 遍历阶段的定向目标名（见 flow/crawl.py::TARGETS）。
# 这些项判的正是"App 有没有提供某个权利入口"，而遍历器会把入口位置记下来 ——
# 有了这条映射，"跳过未测"的原因就能写成"已定位到入口但未执行操作"或
# "未到达入口所在界面（未覆盖）"，而不是一句泛泛的"未取得证据"。
QID_TARGET = {
    "Q013": "注销账号入口",
    "Q014": "投诉举报/意见反馈入口",
    "Q015": "更正/删除个人信息",
    "Q022": "个性化推荐开关",
    "Q023": "个性化推荐开关",
}

# 判定完全依赖"在 App 内走某条界面路径"的项。这类项没结论时，
# 必须带上本轮的覆盖面事实，否则复核员分不清是"没走到"还是"没有这功能"。
_QID_UI_DEPENDENT = {
    "Q004", "Q010", "Q014", "Q015", "Q016", "Q019", "Q020", "Q022", "Q023",
}

# 判定依赖**流量内容**（发了什么字段、是否加密）的项。
# ★ 用户明确要求：监测不到「对外发了什么个人信息」时，就不要把网络外发行为
#   当作关注点。所以这两项不该落在"界面没走到"的文案上 —— 那会误导复核员
#   去补遍历，而真正缺的是抓包。原因必须直接写清缺的是哪个观测。
_NEED_TRAFFIC = {
    "Q024": "该项本质是渗透测试（越权、明文传输、日志泄露、组件暴露等），"
            "本平台未实现对应的专项检测器；本轮也未部署流量监测，"
            "无法评估网络外发环节，故不作结论",
    "Q025": "该项需要解密 HTTPS 流量、检查上报字段是否含明文手机号/设备号等；"
            "本轮未部署流量监测（抓包），不具备观测传输内容的能力，"
            "故不对「是否采取加密措施」下结论。如需要，应以 mitmproxy 抓包另测",
}


def _coverage_reason(qid: str, fr: FlowResult) -> str:
    """用本轮的界面覆盖事实，给"没测到"写一句**可核对**的原因。

    ★ 这是 Step 3 的口径落点：只在到达过的界面里能说"未发现"，没走到的
      一律说"未覆盖"。所以原因里必须出现"到达了多少界面 / 这个入口在不在"，
      不能只写"未取得证据"——那句话既没说清是没测还是没走到，也没法验证。
    """
    cov = getattr(fr, "coverage", None) or {}
    if not cov or not cov.get("app_states"):
        return ""
    detail = cov.get("detail") or {}
    ratio = detail.get("explore_ratio")
    try:
        pct = "%.0f%%" % (float(ratio) * 100)
    except Exception:
        pct = "—"
    scope = ("本轮遍历到达被测应用界面 %d 个、入口探索率 %s"
             % (int(cov.get("app_states") or 0), pct))

    name = QID_TARGET.get(qid)
    if name:
        tgt = {str(t.get("name") or ""): t for t in (cov.get("targets") or [])}
        t = tgt.get(name)
        if t and t.get("found"):
            where = t.get("where") or "—"
            lab = t.get("label") or name
            if t.get("blocked"):
                return ("%s。已在「%s」界面定位到「%s」入口，但按检测规范仅记录"
                        "入口位置、不实际执行该操作（注销/退出类不可逆），"
                        "故其功能是否有效仍需人工判断" % (scope, where, lab))
            return ("%s。已在「%s」界面定位到「%s」入口，但未完成该项所需的"
                    "完整操作链路，结论仍需人工确认" % (scope, where, lab))
        return ("%s，未到达「%s」所在界面（**未覆盖**）；该项不能据此认为不存在，"
                "需人工补测或延长遍历时长后重跑" % (scope, name))

    if qid in _QID_UI_DEPENDENT:
        return ("%s；该项依赖 App 内的界面操作路径，未到达部分按「未覆盖」计，"
                "不能据此认为不存在该行为" % scope)
    return ""


def not_tested_reason(qid: str, fr: FlowResult,
                      flow: Optional[Dict[str, Any]] = None,
                      index: Optional[Dict[str, Dict[str, Any]]] = None) -> str:
    """给「跳过未测」写一句人话原因。

    写「未测」很容易，写清「为什么没测」才有用 ——
    人工复核时看到"P4 未执行（无设备）"就知道补跑一次即可，
    看到"需人工判断"就知道这事得自己来，两者后续动作完全不同。
    """
    flow = flow or load_checkflow()
    auto = (index or items_index()).get(qid, {}).get("automation", "")

    # ★ 前提不成立时，所有"未测"的原因只有一个：App 没运行起来。
    #   不这么写的话，22 项会各自落到"缺少 P4 的证据"这类话术上，
    #   复核员逐条读下来会以为"是流程没跑全"，而真相是"设备上根本打不开"。
    if getattr(fr, "app_start_failed", False):
        # ★ 措辞按 run_health 的三种情形分开（2026-10-27 洋葱学园）：
        #   "界面读不出来"不等于"应用没打开"，混着写会让复核员看到
        #   与肉眼所见相矛盾的结论。
        from . import models as _M
        _head, _why = _M.start_failed_reason(fr)
        return ("%s，本轮未取得该项所需的任何行为证据；"
                "%s取证与复现命令见「目标应用启动状态」章节"
                % (_head, _why))

    # 依赖流量内容的项：先把"缺的是抓包"说清楚，别落到"界面没走到"或
    # 泛泛的"需人工判断"上 —— 复核员据此才知道该补什么动作。
    # 放在阶段判断之前：Q024 这类项本来就没有阶段 feeds，否则永远走不到这里。
    if qid in _NEED_TRAFFIC:
        return _NEED_TRAFFIC[qid]

    owners = covered_phases_for(qid, flow)
    if not owners:
        return _AUTO_HINT.get(auto, "该测评项未纳入当前流程的阶段划分")
    done, missing = [], []
    for pid in owners:
        p = fr.phase(pid)
        if p is None:
            missing.append("%s(未执行)" % pid)
        elif p.status in ("done", "partial"):
            done.append(pid)
        else:
            missing.append("%s(%s)" % (pid, p.status))
    if missing:
        return "缺少阶段 %s 的证据" % "、".join(missing)
    # 阶段都跑了还是没结论 → 先把「缺的是哪个观测」说清楚，
    # 能落到"本轮的界面覆盖面"上的，优先用覆盖面事实（可核对），
    # 说不清的（或本就要人工上）再退回自动化等级提示
    spec = _coverage_reason(qid, fr) or _QID_SPECIFIC.get(qid)
    if spec:
        return spec
    return _AUTO_HINT.get(auto, "相关阶段均已执行，但未取得充分证据")


def finalize(fr: FlowResult, flow: Optional[Dict[str, Any]] = None) -> FlowResult:
    """收尾：给所有未测项补上原因，装配报告 22 项。"""
    flow = flow or load_checkflow()
    idx = items_index()
    for qid, st in fr.items.items():
        if st.state != NOT_TESTED:
            continue
        # ★ 目标应用没启动时，所有未测项的原因**只有一个**，而且是同一个：
        #   App 没跑起来。不能让各项保留"未能取得隐私政策正文"这类局部原因 ——
        #   复核员逐条读下来会以为要补的动作各不相同，实际上要做的是同一件事：
        #   换到 App 能启动的设备上重测。所以这里强制统一覆盖。
        if getattr(fr, "app_start_failed", False):
            st.reason = not_tested_reason(qid, fr, flow, idx)
            continue
        # 占位原因必须重算，否则整份报告里所有「跳过未测」都是同一句套话
        if not st.reason or st.reason == PLACEHOLDER_REASON:
            st.reason = not_tested_reason(qid, fr, flow, idx)
    fr.rows = build_rows(fr, flow)
    return fr


__all__ = ["load_checkflow", "load_checkitems", "report_items", "phases",
           "items_index", "new_item", "build_rows", "finalize",
           "covered_phases_for", "not_tested_reason"]
