"""按「专项行动APP检测报告」模板输出正式报告。

和阶段 0 初筛报告（renderer.py）的区别：
  · 那份是**给检测员看的**（事件流、堆栈、漏斗），越详细越好；
  · 这份是**按模板出的**（22 项逐项结论），结构和人工报告一模一样，
    可以直接作为工作底稿往模板里搬。

最重要的一条：模板里 22 项**每一项都要出现**，不许因为没测到就不写。
没测到就写「跳过未测」并注明原因 —— 这既是给复核的人看的，
也是给将来的自己看的（不然三个月后拿到报告根本不知道这项是没测还是没问题）。
"""
from __future__ import annotations

import html
import re
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional, Sequence, Set

from ..flow.checklist import load_checkflow
from ..flow.models import FAIL, NOT_TESTED, PASS, SUSPECT, STATE_LABELS, FlowResult

_TPL = Path(__file__).with_name("sop_template.html")


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def _rich(s: Any) -> str:
    """转义之后再把 **强调** 变成 <strong>。

    报告正文里有几处用 `**…**` 点出关键动作（"**先不要点同意**"、
    "判定的是「**频繁**意外跳转」"）。这些文字一路 `_esc` 过来，
    星号会原样印在报告里（实测见过「**频繁**意外跳转」）。
    顺序必须是**先转义再替换** —— 反过来会把抓来的文本里
    本该显示成 `<b>` 的内容当成标签插进 DOM。
    """
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", _esc(s))


def _stack_block(stacks: Sequence[Sequence[str]], app_package: str = "",
                 metas: Optional[Sequence[Dict[str, Any]]] = None) -> str:
    """调用栈块：每条栈都先给一句归因，再给逐帧标注。

    为什么不能只贴原始栈：复核员拿到「App 收集了 IMEI」这条结论，
    第一件事是问「是 App 自己读的，还是哪个 SDK 读的」—— 原始栈里
    框架帧和业务帧混在一起，要人肉数到第三行才看得出调用者是谁。
    标注过的栈一眼就能看出来，而且是判定链的一部分（SDK 行为对应
    「未列明第三方 SDK」，不笼统算 App 违规）。

    ★ `metas`：与 stacks 一一对应的调用现场（api/args/result/时刻）。
      用户 2026-10-28 意见：报告写"已收集 Android ID，取值 0408…"，
      而栈里只有一行 `Settings$Secure.getString` —— 复核员没法从栈看出
      读的是哪个 key、读到什么。参数必须贴在**被 hook 的那一帧**上，
      因为那一帧才是"读了什么"发生的地方（见 `_attach_stack_meta`）。
    """
    from ..flow import attribution as ATTR

    metas = list(metas or [])
    out = []
    for i, st in enumerate(stacks or []):
        if not st:
            continue
        info = ATTR.analyze_stack(st, app_package)
        note = ""
        if info.get("owner") == "sdk":
            s = (info.get("sdk") or [{}])[0]
            note = " · 主体：第三方 SDK（%s）" % ATTR.display_name(
                s.get("name") or "名称未识别")
        elif info.get("owner") == "app":
            note = " · 主体：应用自身"
        elif info.get("owner") == "framework":
            note = " · 主体：系统框架"
        else:
            note = " · 主体：未能归属"
        meta = metas[i] if i < len(metas) and isinstance(metas[i], dict) else {}
        lines = ATTR.annotated_frames(info)
        # 参数贴到第一帧（被 hook 的那个 API）：
        # 它说的是"这次调用传了什么、拿到了什么"，与"谁调用的"分属两行，
        # 混在一起会把框架帧的标签挤掉。
        _args = str(meta.get("args") or "").strip()
        _val = str(meta.get("result") or "").strip()
        if lines and (_args or _val):
            _bits = []
            if _args:
                _bits.append("参数 %s" % _args)
            if _val:
                _bits.append("取值 %s" % _val)
            lines[0] = "%s　← %s" % (lines[0], "；".join(_bits))
        # 调用时刻单独一行：同意前/后是判定分水岭，不能只靠正文里的一句话。
        _when = ""
        if meta.get("elapsed_ms") is not None:
            try:
                _sec = float(meta["elapsed_ms"]) / 1000.0
                _when = "调用时刻：启动后 %.1f 秒（%s）" % (
                    _sec, "早于同意事件" if meta.get("before") else "晚于同意事件")
            except Exception:
                _when = ""
        out.append("<details%s><summary>调用栈 %d（%d 层%s）</summary>"
                   "<div class='stackattr'>直接发起点：%s —— %s</div>"
                   "%s<pre class='stack'>%s</pre></details>"
                   % (" open" if i == 0 else "", i + 1, len(st), _esc(note),
                      _esc(info.get("initiator") or "（无业务帧）"),
                      _esc(info.get("owner_label") or ""),
                      ("<div class='stackattr'>%s</div>" % _esc(_when)) if _when else "",
                      _esc("\n".join(lines))))
    return "".join(out)


def _facts_block(facts: Sequence[Sequence[str]]) -> str:
    rows = [list(x) for x in (facts or []) if x and len(x) >= 2]
    if not rows:
        return ""
    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _esc(v)) for k, v in rows)
    return "<table class='facts'>%s</table>" % body


# 与权限申请直接相关的报告项（Q010 超范围 / Q011 频率 / Q012 提前索权 /
# Q026 未同步告知目的）。这几项没有"弹窗本身"的截图时，必须明说缺的是什么，
# 不能让复核员把同阶段的一张首页图当成权限弹窗的留痕。
_PERM_QIDS = ("Q010", "Q011", "Q012", "Q026")


def _is_perm_row(row: Dict[str, Any]) -> bool:
    qids = {str(s.get("qid") or "") for s in (row.get("sub") or [])}
    return bool(qids & set(_PERM_QIDS))


def _item_shots(row: Dict[str, Any], shot_map: Dict[int, Dict[str, Any]]) -> str:
    """把截图**直接**放在这个问题项里（用户明确要求，不再集中到文末图集）。

    同一张图会被多个项引用 —— 这是有意接受的代价：复核员读一项就看到这一项
    到底拍到了什么，不必来回翻到附录再对编号。同一张图重复出现几次，
    比"图在别处、编号还得自己找"更符合人工复核的实际动作。
    """
    shots = row.get("shots") or []
    perm = _is_perm_row(row)
    if not shots:
        if perm:
            return ("<p class='evidence warn'>证据截图：<b>该项涉及权限申请，"
                    "但本轮未取得权限弹窗的界面截图</b>，需人工复测补充"
                    "（Q026 这类结论必须能对着弹窗原文核对）。</p>")
        return ("<p class='evidence'>证据截图：（本次自动化未采集到该项的界面截图，"
                "需人工补充）</p>")

    figs = []
    for s in shots:
        it = shot_map.get(s.get("index")) or {}
        b64 = it.get("b64") or ""
        if not b64:
            continue
        figs.append(
            "<figure><img src='data:image/jpeg;base64,%s' alt='%s'/>"
            "<figcaption>附图 %s：%s</figcaption></figure>"
            % (b64, _esc(s.get("label", "")), _esc(s.get("index")),
               _esc(s.get("label", ""))))
    if not figs:
        return "<p class='evidence'>证据截图：（截图压缩失败，原图见采集存档）</p>"

    tail = ""
    if shots and shots[0].get("kind") == "phase":
        # 权限项走了阶段图兜底 —— 必须当场说清，否则等于用错图冒充证据。
        tail = ("<p class='muted'>注：以上是该结论所处阶段的界面截图，"
                "<b>不是权限弹窗本身</b>；本轮未捕获到权限弹窗截图。</p>"
                if perm else "")
    return ("<div class='label'>证据截图</div><div class='shots'>%s</div>%s"
            % ("".join(figs), tail))


def _item_block(row: Dict[str, Any], app_package: str = "",
                shot_map: Optional[Dict[int, Dict[str, Any]]] = None) -> str:
    """一个问题块。fail/suspect 的排在最前，pass 与 not_tested 各归各类。"""
    state = row.get("state", NOT_TESTED)
    label = STATE_LABELS.get(state, state)
    cls = state
    num = row.get("num")
    head = "<div class='item %s'><div class='hd'><span>%s. 问题：%s</span><span class='tag'>%s</span></div><div class='bd'>" % (
        cls, num, _esc(row.get("title", "")), _esc(label))
    body = ["<p class='desc'><span class='label'>问题描述：</span>%s</p>"
            % _rich(row.get("desc", ""))]

    # ---- 行为主体：App 自己 / 第三方 SDK / 系统框架 ----
    # 放在事实表之前，因为复核员看问题描述后会先问"谁干的"，
    # 这直接决定整改方向（改代码 vs 换 SDK）与对应条款。
    attr = row.get("attribution") or {}
    if attr.get("owner_label"):
        body.append("<p class='attr'><span class='label'>行为主体：</span>"
                    "<b>%s</b></p><p class='attrnote'>%s</p>"
                    % (_esc(attr["owner_label"]), _esc(attr.get("text") or "")))
        # ★ 主体区分出来后必须说清它对**责任**有没有影响，否则复核员会问：
        #   "既然是 SDK 干的，为什么判这个 App 违规？" 两件事要分开讲——
        #   收集类项（同意前收集、超范围等）由 App 承担，SDK 只是整改方向不同；
        #   第三方列明项（Q007）才是"主体是谁"直接决定结论与整改对象的地方。
        if attr.get("owner") in ("sdk", "mixed", "unknown"):
            qids = {str(s.get("qid") or s.get("id") or "") for s in (row.get("sub") or [])}
            if attr.get("owner") == "unknown":
                # 「未能归属」最容易被读成"那就不是 App 的事"。必须当场说清：
                # 归属不明只影响整改对象，不影响本项成立 —— 无论那是自研代码
                # 还是没被 SDK 库收录的第三方库，都在这个 App 的进程里跑。
                tip = ("直接发起点未能归属，可能是自研代码，也可能是未收录进 SDK 库的第三方库；"
                       "本项认定的是该 App 的个人信息处理行为，二者的合规责任都在 App，"
                       "归属不明不影响本项成立 —— 只是整改对象需按原始栈逐帧核对后确定。")
            elif "Q007" in qids:
                tip = ("第三方 SDK 发起的调用而政策未列明时，整改对象是第三方共享清单："
                       "需补列接收方名称、联系方式、共享目的与所涉信息种类，或更换该 SDK。")
            else:
                tip = ("本项认定的是该 App 的个人信息处理行为 —— 即便由内嵌第三方 SDK 代为发起，"
                       "仍由 App 承担合规责任；主体区分只影响整改方向"
                       "（修改自有代码，或更换/升级该 SDK），不影响本项是否成立。")
            body.append("<p class='attrnote'>%s</p>" % _esc(tip))

    facts = _facts_block(row.get("facts") or [])
    if facts:
        body.append(facts)
    links = [u for u in (row.get("links") or []) if u]
    if links:
        items = "".join("<li><a href='%s' target='_blank'>%s</a></li>" % (_esc(u), _esc(u))
                        for u in links)
        body.append("<p class='evidence'>核对链接：</p><ul class='lk'>%s</ul>" % items)
    stacks = _stack_block(row.get("stacks") or [], app_package,
                           row.get("stack_meta"))
    if stacks:
        body.append(stacks)
    elif row.get("needs_stack"):
        # 采集类结论却没有栈 —— 必须说出来。静默略过会让复核员
        # 以为"这条不需要栈"，而实际上无法回答"App 还是 SDK"这个必答题。
        body.append("<p class='attr warn'>调用栈：<b>本次未捕获到该行为的调用栈</b>，"
                    "无法据此区分是应用自身还是第三方 SDK 发起，"
                    "需结合沙箱精检或加大采样深度复核。</p>")
    # 截图直接内嵌在本项（见 _item_shots）：复核员不需要跳到文末对编号。
    body.append(_item_shots(row, shot_map or {}))
    sub = row.get("sub") or []
    if len(sub) > 1:
        body.append("<details><summary>关联测评项 %d 个</summary><table class='facts'>%s</table></details>"
                    % (len(sub), "".join(
                        "<tr><th>%s</th><td>%s（%s）</td></tr>"
                        % (_esc(s["qid"]), _esc(s.get("title", "")), _esc(s.get("state_label", "")))
                        for s in sub)))
    return head + "".join(body) + "</div></div>"


def _flow_table(fr: FlowResult, flow: Dict[str, Any]) -> str:
    rows = []
    # 本轮没有任何设备侧锚点 = 服务器部署的"仅静态 + 政策"形态。
    # 此时六行耗时全都只能写"未记录"，复核员会读成"平台没测时间"；
    # 用一句说明交代清楚，表格里留"—"。
    no_dev = bool(fr.phases) and all(p.real_ms < 0 for p in fr.phases)
    for p in fr.phases:
        spec = next((x for x in (flow.get("phases") or []) if x.get("id") == p.phase_id), {})
        guard = spec.get("guard") or []
        gtxt = ""
        if guard:
            gtxt = "<br/><span class='muted'>约束：%s</span>" % _esc("；".join(guard))
        # ★ 耗时列必须用采集侧的真实耗时，不能用编排器墙钟。
        #   编排器是在真机采集之后才跑的，它的 duration 只覆盖"读存档 + 算判定"，
        #   直接显示会变成"检测一台手机每个阶段 0.2 秒"——复核员一眼就看出不对。
        if p.real_ms > 0:
            dur = "%.1fs" % p.real_seconds
        elif p.real_ms == 0:
            dur = "—"          # 瞬时边界点，如"同意"这一步
        elif no_dev:
            dur = "—"          # 见上方说明：本轮没有设备操作时长
        else:
            dur = "未记录"
        tip = ("<br/><span class='muted'>%s</span>" % _esc(p.timing)) if p.timing else ""
        rows.append(
            "<tr><th>%s、%s</th><td>%s</td><td>%s%s</td><td>%s%s</td></tr>"
            % (_esc(p.num), _esc(p.name), _esc(spec.get("goal", "")[:60]),
               dur, tip,
               _esc({"done": "已完成", "partial": "部分完成", "skipped": "已跳过",
                     "failed": "失败", "pending": "未开始",
                     "running": "进行中"}.get(p.status, p.status)), gtxt))
    note = ("<p class='lead'>说明：本次未执行设备侧动态采集（未接入检测设备或未启用），"
            "各阶段不存在设备操作耗时，故「耗时」列留空；表中「已完成」指该阶段的"
            "静态分析 / 政策分析已完成，不代表已核对真机上的实际行为。</p>"
            if no_dev else "")
    return (note
            + "<table class='cover'><tr><th style='width:150px'>阶段</th><th>目标</th>"
            "<th style='width:70px'>耗时</th><th style='width:190px'>结果</th></tr>"
            + "".join(rows) + "</table>")


def _jiagu_text(s: Dict[str, Any]) -> str:
    """加固信息排成人话。

    数据来自静态分析：`[{"name":..., "vendor":..., "signature":...}]`。
    早先直接 `str(x)` 拼进报告，页面上原样印出一个 Python 字典
    （`{'name': '…', 'vendor': …}`）—— 复核员看到的是源码而不是结论。

    ★ 加固只认 APK 里真实存在的特征文件（`evidence=file`）。
      dex 字符串命中的（`jiagu_hints`）不参与认定 —— 实测 uni-app 应用会因
      某个 SDK 内嵌的「加固检测清单」一次命中 26 家厂商，全属误报。
      但完全不提也不行：复核员会以为没查过。故在无文件级命中时如实说明。
    """
    items = s.get("jiagu") or []
    if not items:
        hints = s.get("jiagu_hints") or []
        if not hints:
            return "未识别"
        names = "、".join(str(h.get("name") or h.get("signature")) for h in hints[:6])
        tail = "等 %d 个" % len(hints) if len(hints) > 6 else ""
        return ("未识别（未在 APK 内发现加固组件文件）。"
                "注：DEX 字符串中出现 %s%s 等加固库名称，"
                "经核对为某 SDK 内嵌的「加固库检测清单」，非本应用实际使用的加固，"
                "故不作认定。" % (names, tail))
    out = []
    for it in items:
        if isinstance(it, dict):
            n, v, sig = (it.get("name") or "").strip(), (it.get("vendor") or "").strip(), (it.get("signature") or "").strip()
            t = n or sig or "未知加固"
            if v and v not in t:
                t += "（%s）" % v
            if sig:
                t += "［识别特征文件：%s］" % sig
            out.append(t)
        else:
            out.append(str(it))
    return "、".join(out)


def _static_table(fr: FlowResult) -> str:
    """静态档案。

    对应人工「在沙箱里随时可以看静态参数」——检测过程中随时要查 minSdk、
    权限声明、集成了哪些 SDK，所以这些事实要摆在报告靠前的位置，
    而不是散落在各阶段的证据里。
    """
    s = fr.static or {}
    if not s:
        return "<p class='muted'>本次未提供 APK，未执行静态分析。</p>"
    perms = s.get("permissions") or []
    sdks = s.get("sdks") or []
    # permissions 是字符串列表；直接按 dict 取 dangerous 会恒为 False，
    # 报告就会写成"49 项权限、危险权限 0 项"（简小知实测踩到过）。
    from ..flow.compare import dangerous_permissions
    risky = dangerous_permissions(perms)
    rows = [
        ("包名", s.get("package", "")),
        ("应用名称", s.get("app_label", "")),
        ("版本", "%s（%s）" % (s.get("version_name", ""), s.get("version_code", ""))
         if s.get("version_name") else ""),
        ("minSdkVersion", s.get("min_sdk", "")),
        ("targetSdkVersion", s.get("target_sdk", "")),
        ("DEX 数量", s.get("dex_count", "")),
        ("权限声明", "%d 项（其中危险权限 %d 项）" % (len(perms), len(risky)) if perms else ""),
        ("第三方 SDK", "%d 个" % len(sdks) if sdks else ""),
        ("加固", _jiagu_text(s)),
        ("可调试", "是" if s.get("debuggable") else "否"),
        ("明文流量", "允许" if s.get("cleartext") else "否"),
        ("允许备份", "是" if s.get("allow_backup") else "否"),
        ("签名", str((s.get("signature") or {}).get("subject", "") or
                     (s.get("signature") or {}).get("cn", ""))),
    ]
    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _esc(v))
                   for k, v in rows if v not in ("", None))
    table = "<table class='meta'>%s</table>" % body
    extra = ""
    if sdks:
        names = []
        for x in sdks[:40]:
            names.append(str(x.get("name", x) if isinstance(x, dict) else x))
        extra += ("<details><summary>第三方 SDK 清单（%d 个）</summary>"
                  "<p class='muted'>%s</p></details>" % (len(sdks), _esc("、".join(names))))
    if risky:
        extra += ("<details><summary>危险权限清单（%d 项）</summary>"
                  "<p class='muted'>%s</p></details>"
                  % (len(risky), _esc("、".join(str(p.get("name", "")) for p in risky))))
    return table + extra


def _app_status(fr: FlowResult) -> str:
    """「目标应用启动状态」—— 只在**没能启动**时输出，否则返回空串。

    为什么单独立一节：这决定的不是某一项合不合规，而是**这次检测成不成立**。
    报告里所有"跳过未测"必须有一个统一、明确的原因，复核员才不用逐条去猜
    "是流程没跑到，还是 App 本来就没这功能"。

    本节只放**读到的原文**（信号、地址、转储路径、内存段、调用栈、原始异常串）。
    成因分析另起一段并显式标注为推断 —— 事实与推测混排，等于把推测洗成事实。
    """
    if not getattr(fr, "app_start_failed", False):
        return ""
    cr = fr.app_crash or {}
    st = fr.stats()
    rows: List[str] = []

    def add(k: str, v: Any, html: bool = False) -> None:
        """`html=True` 表示 v 是本函数自己拼好的标签串，不能再转义。

        踩过的坑：调用栈 / 复现命令这些值是带 `<pre>` `<code>` 的，
        统一走 _rich()（先转义再渲染强调）会把标签原样印成 `&lt;pre&gt;`，
        复核员看到的就是一堆实体字符。
        """
        if v:
            body = str(v) if html else _rich(str(v))
            rows.append("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), body))

    sig = cr.get("signal") or ""
    if sig:
        add("崩溃信号", "%s（code %s）" % (sig, cr.get("signal_code") or "—"))
    add("出错地址", cr.get("fault_addr"))
    add("崩溃时刻", cr.get("crash_time"))
    add("系统崩溃转储", (cr.get("tombstone") or "") and
        "%s（设备端 /data/tombstones 转储文件，root 可读）" % cr.get("tombstone"))
    add("证据来源", {
        "tombstone": "系统崩溃转储（/data/tombstones）",
        "logcat": "系统日志（logcat FATAL/DEBUG 段，未取得转储时的兜底）",
    }.get(cr.get("source", ""), ""))

    reg = cr.get("fault_region") or {}
    if reg.get("path"):
        add("出错地址所属内存段",
            "%s　权限 <code>%s</code>　%s" % (_esc(reg.get("range", "")), _esc(reg.get("perms", "")),
                                            _esc(reg.get("path", ""))), html=True)
        if "x" not in (reg.get("perms") or ""):
            add("该段的含义",
                "此段权限为 <code>%s</code> —— <b>只读、不可执行</b>；而崩溃时程序计数器（pc）"
                "正指向这个地址，即进程在试图执行一段不可执行的页面。" % _esc(reg.get("perms", "")),
                html=True)

    bt = cr.get("backtrace") or []
    if bt:
        add("调用栈（系统转储原文前 %d 帧）" % len(bt),
            "<pre class='x'>%s</pre>" % _esc("\n".join(bt)), html=True)
    # ★ "即可复现同一崩溃"只在**真的取到崩溃记录**时才能写（2026-10-27 洋葱学园）：
    #   那一轮崩溃取证是空的（"未能取到任何崩溃记录"），报告却跟着写
    #   "即可复现同一崩溃" —— 没复现出来的东西不能声称可复现。
    if cr.get("repro_cmd"):
        _suffix = ("（在任意已连接的 adb 环境执行，即可复现同一崩溃）" if sig else
                   "（在任意已连接的 adb 环境执行，用于复现本次启动过程；"
                   "本轮未取到崩溃记录，该命令不构成「崩溃可复现」的证据）")
        add("复现命令", "<code>%s</code>%s" % (_esc(cr["repro_cmd"]), _suffix),
            html=True)
    # ---- 不注入直接启动的观察（注入不可用时才有）：区分"起不来"与"注入不了" ----
    # 2026-10-27 小盒课堂（爱加密）：旧报告写"检测手段受限，不代表应用自身无法
    # 运行"，而实测它不注入也活不过 60 ms（SELinux 拦 execmod）。这段就是那条
    # 判据的出处，必须进报告，否则复核员无法自己判断到底是谁的问题。
    _probe = (getattr(fr, "run_health", None) or {}).get("app_start_probe") or {}
    if _probe:
        add("无注入启动观察", _probe.get("why"))
        if _probe.get("evidence"):
            add("启动失败现场（logcat 原文）",
                "<pre class='x'>%s</pre>" % _esc(_probe["evidence"]), html=True)
    add("设备指纹", cr.get("device_fingerprint"))

    errs = [e for e in (fr.scan_errors or []) if e]
    if errs:
        add("采集器记录到的异常（原文）",
            "<ul class='lk'>%s</ul>" % "".join("<li>%s</li>" % _rich(e) for e in errs),
            html=True)

    # ---- 成因分析：显式标注为推断，不与上面的事实混排 ----
    infer = ""
    if reg.get("path"):
        # 从调用栈里认出"应用自带"的那个库（/data/app/…），它才是嫌疑点
        bt_lib = ""
        for f in (cr.get("backtrace") or []):
            m = re.search(r"/data/app/\S+?/([^/\s]+\.so)", f)
            if m:
                bt_lib = m.group(1)
                break
        infer = (
            "<p class='muted'><b>成因分析（推断，不作为检测结论）：</b>"
            "崩溃地址落在 <code>%s</code> 上（权限 <code>%s</code>）—— "
            "该段不属于本应用自带的代码；而调用栈顶端直接命中应用自带的加固组件%s。"
            "据此可推断：问题出现在<b>应用自带加固壳的初始化过程</b>中，"
            "壳跳转到了一个不可执行的地址。"
            "至于是加固壳与当前系统运行时的兼容性问题，还是壳在识别到环境异常后主动中止，"
            "本工具无法区分，需由应用提供方或加固服务方确认。</p>"
            "<p class='muted'>上述推断不影响事实本身：在本次检测设备（%s）上，"
            "该应用启动即崩溃，无法进入任何界面。</p>"
            % (_esc(reg.get("path", "")), _esc(reg.get("perms", "")),
               (" <code>%s</code>" % _esc(bt_lib)) if bt_lib else "",
               _esc(cr.get("device_fingerprint") or "见上")))

    # ★ 「为什么算没跑起来」要按实测写（2026-10-27 用户第 4 条）：
    #   同一句"连续 N 次发现进程已不存在"套在"进程活着但界面全是桌面"
    #   或者"进过 10 屏但一个字读不到"上，就是编。判据见 assess_run_health。
    _rh = getattr(fr, "run_health", {}) or {}
    _rh_state = str(_rh.get("state") or "")
    _hook_blocked = bool(_rh.get("hook_blocked"))
    _probe = _rh.get("app_start_probe") or {}
    _probe_dead = _probe.get("started") is False
    if _rh_state == "no_app" and _probe_dead and not cr.get("signal"):
        # ★ 有"不注入直接启动"的实测时以它为准（小盒课堂 2026-10-27）：
        #   旧文案"采集期间前台从未切换到被测应用"是猜的，而且把原因指向了
        #   "我们没让它到前台"；实测它自己就活不过 60 ms。
        _head = "本次检测中，目标应用在检测设备上无法启动。"
        _why = ("实测结果：%s。因此没有取得任何属于该应用的界面与行为数据。"
                % _esc(_probe.get("why") or "应用未能稳定存活"))
    elif _rh_state == "no_app" and not cr.get("signal"):
        _head = "本次检测中，目标应用未能正常运行。"
        _why = ("采集期间前台<b>从未切换到被测应用</b>（桌面上共取到 %d 屏），"
                "因此没有取得任何属于该应用的界面与行为数据。"
                % int(_rh.get("desktop") or 0))
    elif _rh_state == "no_ui":
        # ★ 不能说成"未能正常运行"（2026-10-27 用户第 4 条的反面）：
        #   应用进程就在前台，用户站在手机前也看得见，只是我们读不出界面。
        _head = "本次检测中，目标应用已启动，但界面无法读取，动态检测未能开展。"
        _why = ("被测应用进程在前台，但取得的 %d 屏界面<b>都没有可读的文字内容</b>"
                "（结构树为空或只有无法解析的 WebView），无法据此判定任何功能与权限行为。"
                % int(_rh.get("app_any") or 0))
    elif _rh_state == "no_dump":
        _head = "本次检测中，目标应用已启动，但界面未能留下记录，动态检测未能开展。"
        _why = ("采集期已确认前台切换到被测应用，但界面结构始终未能导出"
                "（uiautomator dump 无输出，屏幕记录共 %d 屏），"
                "无法据此判定任何功能与权限行为。"
                % int((_rh.get("app_any") or 0) + (_rh.get("desktop") or 0)))
    else:
        _head = "本次检测中，目标应用未能正常运行。"
        _why = ("采集器每 5 秒探测一次目标进程，连续 <b>%d</b> 次发现进程已不存在，"
                "UI 遍历中止，本轮未取得任何可用于判定的运行期行为数据。"
                % int(fr.relaunch_count or 0))
    if _hook_blocked:
        if _probe_dead:
            # ★ 这里是最容易被写错的一句：注入确实被拦了，但应用**自己**也起不来。
            #   写成"检测手段受限，不代表应用本身没有相应行为"，等于替应用开脱
            #   （小盒课堂 2026-10-27 旧报告就是这么写的，而实测它 60 ms 就死）。
            _why += ("<br><b>另需说明：</b>本轮注入尝试也被加固机制拦截了 %d 次，"
                     "但这<b>不是</b>本次检测失败的原因 —— 不注入时应用同样无法启动"
                     "（见上表「无注入启动观察」）。本轮证据缺失属于"
                     "<b>应用在本次检测设备上无法运行</b>，不能归因于检测手段。"
                     % int(_rh.get("hook_hostile") or 0))
        elif int(_rh.get("hook_spawn_killed") or 0):
            _seen = int(_rh.get("app_any") or 0)
            _fact = ("前台确实切换到了被测应用（本次记录 %d 屏）" % _seen if _seen
                     else "本轮未单独做「不注入直接启动」的观察")
            _why += ("<br><b>另需说明：</b>加固机制对冷启动注入同样会判定为调试"
                     "（%d 次），%s —— 本轮界面与事件偏少属于"
                     "<b>检测手段受限</b>，不代表应用本身没有相应行为；"
                     "如需完整动态数据，建议改用不注入的沙箱方案复核。"
                     % (int(_rh.get("hook_spawn_killed") or 0), _esc(_fact)))
        else:
            _why += ("<br><b>另需说明：</b>本轮注入尝试被加固机制拦截 %d 次"
                     "（重新附着后应用立即退出，或冷启动注入无法完成）—— "
                     "该应用带加固保护，注入会被判定为调试并触发自杀。界面与事件偏少"
                     "属于<b>检测手段受限</b>，不代表应用本身没有相应行为；"
                     "如需完整动态数据，建议改用不注入的沙箱方案复核。"
                     % int(_rh.get("hook_hostile") or 0))

    # 加固对抗的可操作提示：只在本轮确实被壳拦、且应用自己能跑起来时才说。
    # 应用压根起不来的那种情况（_probe_dead）说"去做环境隐匿"是误导。
    if _hook_blocked and not _probe_dead:
        _why += ("<br>如需进一步尝试，可在检测设备上做<b>环境隐匿</b>后重跑"
                 "（把 frida-server 换成非默认文件名、避免默认端口特征被壳识别）——"
                 "本轮未做该处理，因此这部分缺失属于<b>检测环境限制</b>，"
                 "不能据此推断应用没有相应行为。")

    # ---- 系统侧旁路取证（2026-10-31）----
    # ★ 措辞必须钉死它的边界：这些记录能证明"用过"，给不出调用栈、无法归因，
    #   只能算"待人工确认"。写成"已确认收集"就是把旁证当实证，方向错了。
    _by = getattr(fr, "bypass", None) or {}
    if _by.get("ok"):
        _ops = _by.get("appops") or []
        _hot = ((_by.get("permissions") or {}).get("hot_granted")) or []
        _bits = []
        if _ops:
            _bits.append("系统记录到的近期敏感操作 <b>%d</b> 项（%s）"
                         % (len(_ops), _esc("、".join(o.get("label") or ""
                                                      for o in _ops[:8]))))
        if _hot:
            _bits.append("运行时权限已授予 <b>%d</b> 项（%s）"
                         % (len(_hot), _esc("、".join(x.get("label") or ""
                                                      for x in _hot[:8]))))
        _why += ("<br><b>系统侧旁路取证：</b>%s。这些数据取自系统自身的操作账本"
                 "（<code>dumpsys appops</code> / <code>dumpsys package</code>），"
                 "不需要注入、不受加固影响。它只能证明<b>该操作被使用过</b>，"
                 "给不出调用栈，因此<b>无法归属</b>到应用自身或某个第三方 SDK —— "
                 "相关项目按「待人工确认」处理，<b>不作为认定依据</b>。"
                 % "；".join(_bits))
    elif _by:
        _why += ("<br><b>系统侧旁路取证：</b>未取得数据（%s）。"
                 "该系统未能提供操作账本，不能据此推断「应用没有相应行为」。"
                 % _esc(_by.get("why") or "系统未提供"))

    # 标题不能一律叫"启动状态"：no_ui / no_dump 时应用其实起来了，
    # 出问题的是界面读取（2026-10-27 用户第 4 条）。
    _weak_read = _rh_state in ("no_ui", "no_dump")
    _title = ("目标应用启动与界面读取状态（异常）" if _weak_read
              else "目标应用启动状态（异常）")
    _tail = ("是否重测，取决于该应用能否在检测设备上被读取；" if _weak_read
             else "是否重测，取决于该应用能否在检测设备上正常启动；")
    return "".join([
        "<h2 class='sec'>%s</h2>" % _title,
        "<div class='warnbox'>",
        "<p><b>%s</b>%s</p>" % (_head, _why),
        "<p>因此本报告 <b>%d</b> 个检测项中的 <b>%d</b> 项标注为「跳过未测」——"
        "其含义是<b>没有测</b>，<b>不代表</b>这些项目已合规。"
        "「未发现问题」一项也没有输出，因为本次确实没有任何证据可依据。</p>"
        % (st["total"], st["not_tested"]),
        "<p>%s下表证据可用于定位与向应用方反馈。</p>" % _tail,
        "</div>",
        "<table class='facts'>%s</table>%s" % ("".join(rows), infer),
    ])


def _declare_matrix(fr: FlowResult) -> str:
    """声明与实测的逐 SDK 对照（正文不含章标题，编号由调用方统一编排）。

    为什么要单列一节：报告前面按模板 22 项写的是**结论**，
    而这一节回答的是"结论是怎么比出来的"—— App 自己声明采什么、
    每个 SDK 声明采什么、实际采了什么、差在哪。缺了这一节，
    「第 5 项：未列明第三方 SDK」就只是一句话，复核员无法逐条验。
    """
    m = fr.sdk_matrix or {}
    if not m:
        return ""
    out = ["<p class='muted'>「清单声明」摘自隐私政策正文与第三方共享清单原文；"
           "「实际采集」为本轮采集到、取到有效值并完成调用栈归因的事件。"
           "同一厂商（如腾讯、字节、阿里）旗下只要有一个 SDK 或品牌被列明，"
           "该厂商的其他 SDK 按厂商口径视为已声明，并在「命中方式」里注明，"
           "不计为未列明。</p>"]

    # ---- App 自身 ----
    app = m.get("app_row") or {}
    if app:
        rows = []
        for p in (app.get("observed_pi") or [])[:12]:
            miss = any(x.get("pi") == p.get("pi") for x in (app.get("missing_pi") or []))
            mem = "、".join(x.get("name", "") for x in (p.get("members") or [])[:4])
            rows.append(
                "<tr><td>%s</td><td>%s</td><td>%d 次</td><td>%s</td></tr>"
                % (_esc(p.get("name", "")),
                   ("<span class='muted'>（%s）</span>" % _esc(mem)) if mem else "—",
                   int(p.get("count", 0)),
                   ("<b>未声明</b>" if miss else "已声明")))
        out.append("<h4>（1）App 自身实际采集</h4><table class='meta'>"
                   "<tr><th>个人信息类型</th><th>具体项</th><th>次数</th>"
                   "<th>政策/收集清单是否声明</th></tr>%s</table>" % "".join(rows))
    cl = m.get("collect_list") or []
    if cl:
        rows = "".join(
            "<tr><td>%s</td><td>%s</td></tr>"
            % (_esc(x.get("scene", "")),
               _esc("、".join(x.get("pi_names") or x.get("pi_terms") or []) or "—"))
            for x in cl[:20])
        out.append("<details><summary>App 声明的个人信息收集清单（%d 个功能场景）"
                   "</summary><table class='meta'><tr><th>功能场景</th>"
                   "<th>声明收集的信息</th></tr>%s</table></details>" % (len(cl), rows))

    # ---- 第三方 SDK ----
    sdk_rows = m.get("sdk_rows") or []
    if sdk_rows:
        rows = []
        for r in sdk_rows[:40]:
            obs = "、".join(p.get("name", "") for p in (r.get("observed_pi") or [])) or "—"
            mems = []
            for p in (r.get("observed_pi") or []):
                for x in (p.get("members") or []):
                    if x.get("name") and x["name"] not in mems:
                        mems.append(x["name"])
            if mems:
                obs += "（%s）" % "、".join(mems[:4])
            decl = "、".join(p.get("name", "") for p in (r.get("declared_pi") or [])) or "—"
            miss = "、".join(p.get("name", "") for p in (r.get("missing_pi") or []))
            if r.get("matched_by") == "未列明":
                concl = "<b>未列明</b>"
            elif miss:
                concl = "<b>声明范围不足</b>"
            elif (r.get("matched_by") or "").startswith("同厂商"):
                concl = "同厂商已列明"
            else:
                concl = "已列明"
            rows.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                "<td>%s</td><td>%s</td></tr>"
                % (_esc(r.get("name", "")),
                   _esc(r.get("group") or r.get("vendor") or "—"),
                   _esc(obs), _esc(decl),
                   _esc(miss or "—"),
                   _esc(r.get("matched_by") or "—"), concl))
        out.append("<h4>（2）第三方 SDK 逐条对照</h4>"
                   "<table class='cover'><tr><th>SDK</th><th>厂商/集团</th>"
                   "<th>实际采集</th><th>清单声明</th><th>未列明</th>"
                   "<th>命中方式</th><th>结论</th></tr>%s</table>" % "".join(rows))
    else:
        out.append("<p class='muted'>本轮调用栈中未识别出可归属的第三方 SDK 采集行为，"
                   "故无逐条对照。</p>")

    unobs = m.get("declared_unobserved") or []
    if unobs:
        out.append("<details><summary>清单里声明了、但本轮未观测到采集的 SDK（%d 个）"
                   "</summary><p class='muted'>%s</p></details>"
                   % (len(unobs), _esc("、".join(x.get("name", "") for x in unobs))))
    unk = m.get("unknown_row") or {}
    if unk:
        out.append("<p class='muted'>另有 %d 次采集的调用点既不在被测 App 包内、"
                   "也不在已收录的 SDK 名单内（%s），未计入任何一方的差集，需人工确认归属。</p>"
                   % (int(unk.get("count", 0)), _esc(unk.get("name", ""))))
    return "".join(out)


def _login_account(fr: FlowResult) -> str:
    """本次检测使用的测试账号（正文不含章标题，编号由调用方统一编排）。

    ★ 为什么必须写进报告
      登录态下才能到"我的/设置/注销/隐私设置"这些最容易出问题的入口；
      用了账号就等于**改变了检测条件**。复核员必须知道：
      这个结论是在游客态还是登录态下得出的、用的是哪个号、
      登录到底成没成 —— 否则同一款 App 复跑出不同结论时无从判断原因。

    ★ 号码脱敏
      报告是内部底稿，但底稿会被传阅、归档、打印。完整号码没有技术必要性
      （133****0822 已足够让检测方认出自己用的是哪个号），所以只写脱敏形式。
    """
    lg = fr.login or {}
    if not lg:
        return ("<p class='muted'>本次未启用登录辅助（提交时未填写测试手机号），"
                "遍历仅覆盖无需登录即可进入的界面。凡需登录后才能到达的功能"
                "（如账号设置、注销入口、订单/个人信息页），本轮未覆盖，"
                "相关检测项按「跳过未测」处理，不据此认定未发现问题。</p>")

    phone = lg.get("phone") or ""
    rows = [
        ("测试手机号", phone or "—"),
        ("登录方式", lg.get("method") or "短信验证码登录"),
        ("登录界面", lg.get("title") or "—"),
        ("是否已申请验证码", "是" if lg.get("code_requested") else "否（未找到「获取验证码」按钮）"),
        ("登录结果", "已登录，登录态下继续遍历" if lg.get("ok") else "<b>未完成登录</b>"),
        ("说明", lg.get("note") or "—"),
    ]
    if lg.get("at_ms"):
        _sec = float(lg.get("at_ms") or 0) / 1000.0
        rows.append(("进入登录页的时间点", "采集开始后 %d 分 %d 秒"
                     % (int(_sec // 60), int(_sec % 60))))
    if lg.get("shot") not in (None, "", -1):
        rows.append(("附图", "附图 %s（%s）" % (lg.get("shot"),
                     "登录后界面" if lg.get("ok") else "未完成登录时的界面")))
    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _rich(str(v)))
                   for k, v in rows if v not in ("", None))

    tail = ("<p class='muted'>该号码为检测方自有测试号，仅用于本次检测的登录环节；"
            "验证码由检测人员现场回填，<b>不写入报告、不落库、用完即删</b>。")
    if lg.get("ok"):
        tail += ("若该应用采用「验证码登录即注册」的方式，本次检测相当于在该应用上"
                 "产生了一个以该号码为凭据的账号；本工具不对该账号执行注销等写操作，"
                 "如需注销请人工按应用内路径处理并在复核记录中注明。")
    else:
        tail += ("本次未完成登录，因此登录后才可见的功能未被覆盖 —— "
                 "报告中没有出现在登录态界面上的采集行为，不构成「该功能不存在」的结论。")
    tail += "</p>"
    return "<table class='meta'>%s</table>%s" % (body, tail)


def _consent_section(fr: FlowResult) -> str:
    """同意动作（「同意前 / 同意后」的分水岭）。

    ★ 这一节为什么必须存在
      「用户同没同意隐私政策」是整份报告唯一的时间分界点。它一旦记错，
      「征得同意前就开始收集个人信息」这一项会直接反向 —— 要么把违规洗白，
      要么把合规的冤枉了。所以不能只给一个"已同意"的开关，必须把
      「什么时候、点了哪个按钮、从哪条路径点的、凭什么算数」摊开给复核员。

    ★ 真机教训（以观书法 mbsf6）
      AI 在政策下钻时顺手点了「同意并继续」，界面确实变了，但那条点击
      走的不是任何一条既有登记路径 → 布尔位始终 False、50 条事件全标
      "同意前"、P3 写"未捕获到同意事件"，而正文却写着"时序不可分辨"。
      自相矛盾的底稿比没有底稿更糟：复核员不知道该信哪一句。
    """
    cs = fr.consent or {}
    recs = list(cs.get("events") or [])
    given = bool(cs.get("given"))
    markers = int(cs.get("markers") or 0)

    if not given and not recs:
        return ("<p class='muted'>本轮<b>未捕获到同意动作</b>。"
                "因此无法划分「同意前 / 同意后」的时间边界，凡依赖该边界的结论"
                "（如「征得同意前即开始收集」）在本轮均按<b>跳过未测</b>处理，"
                "不据此认定未发现问题。常见原因：App 无首启隐私弹窗"
                "（以静默方式取得同意）、同意按钮由 WebView 绘制非原生控件、"
                "或采集窗口内未走到该界面。</p>")

    ws = next((r for r in recs if r.get("watershed")), None)
    ms = cs.get("elapsed_ms")
    if ws is None and ms is None and recs:
        ms = recs[0].get("elapsed_ms")

    rows: List[Any] = []
    if ws:
        _m = int(ws.get("elapsed_ms") or 0)
        rows.append(("同意时刻", "冷启动后 <b>%.1f 秒</b>（%d 毫秒）"
                     % (_m / 1000.0, _m)))
        rows.append(("所点按钮", "「%s」" % _esc(ws.get("label") or "—")))
        rows.append(("触发路径", ws.get("via") or "—"))
        rows.append(("认定强度", "%s%s" % (
            _esc(ws.get("strength_label") or cs.get("strength") or "—"),
            "" if ws.get("verified", True) else "（界面变化未确证）")))
        rows.append(("脚本同步", {
            "ok": "已同步（此后脚本侧事件按「同意后」标记）",
            "failed": "同步失败",
            "not_attempted": "未尝试同步",
            "not_applicable": "不适用（该路径无脚本句柄）",
        }.get(str(ws.get("sync") or ""), str(ws.get("sync") or "未记录"))))
        if ws.get("why"):
            rows.append(("判定依据", _esc(ws["why"])))
    elif given:
        rows.append(("同意时刻", ("冷启动后 %.1f 秒" % (int(ms) / 1000.0))
                     if ms is not None else "未记录"))
        rows.append(("所点按钮", _esc(cs.get("source") or "—")))
        rows.append(("认定强度", _esc(cs.get("strength") or "—")))

    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), str(v))
                   for k, v in rows)

    # ---- 所有"看起来像同意"的点击，逐条列出 ----
    tbl = ""
    if len(recs) > 1:
        trs = []
        for r in recs:
            _mm = int(r.get("elapsed_ms") or 0)
            trs.append(
                "<tr><td>%.1fs</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                % (_mm / 1000.0,
                   _esc(r.get("label") or "—"),
                   _esc(r.get("via") or "—"),
                   "<b>分水岭</b>" if r.get("watershed") else "重复动作",
                   _esc(r.get("why") or "")))
        tbl = ("<table class='cover'><tr><th style='width:60px'>时刻</th>"
               "<th>按钮文字</th><th>触发路径</th><th style='width:90px'>是否分界</th>"
               "<th>说明</th></tr>%s</table>"
               "<p class='muted'>用户在一次检测中可能多次点击同意类按钮"
               "（首启弹窗 → 登录页勾选协议）。分界只认<b>第一条</b>，"
               "后续动作逐条留痕但不改边界。</p>" % "".join(trs))

    # ---- 分水岭取证图 ----
    fig = ""
    _idx = int(ws.get("screenshot_idx", -1)) if ws else -1
    if _idx >= 0:
        it = next((s for s in (fr.shots or []) if int(s.get("index", -1)) == _idx), None)
        b64 = (it or {}).get("b64") or ""
        if b64:
            fig = ("<div class='label'>同意动作取证图</div><div class='shots'>"
                   "<figure><img src='data:image/jpeg;base64,%s' alt='同意动作'/>"
                   "<figcaption>附图 %d：同意动作当时的界面</figcaption></figure>"
                   "</div>" % (b64, _idx))

    tail = ""
    if given and markers == 0:
        tail = ("<p class='evidence warn'>注意：已认定用户同意，但事件流中"
                "<b>缺少分水岭标记事件</b>，时间线的同意边界不可定位。</p>")
    elif not given and recs:
        tail = ("<p class='evidence warn'>注意：采集到 %d 次同意类点击，"
                "但均<b>未达认定门槛</b>（按钮文字为中性确认，或点击未产生"
                "界面变化），故本轮不认定已取得同意。</p>" % len(recs))
    return ("<table class='meta'>%s</table>%s%s%s" % (body, tbl, fig, tail))


def _perm_scenes(fr: FlowResult) -> str:
    """权限申请场景：申请了什么权限、当时界面有没有说明目的（不含章标题）。"""
    scenes = fr.perm_scenes or []
    if not scenes:
        return ""
    rows = []
    for s in scenes[:30]:
        told = s.get("purpose", "")
        if told == "dialog":
            verdict = "弹窗内已说明"
        elif told == "pre":
            verdict = "申请前已说明"
        elif told == "none":
            verdict = "<b>未同步告知</b>"
        else:
            verdict = "证据不足"
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (_esc(s.get("perm") or s.get("perm_raw") or "—"),
               _esc((s.get("pre_text") or "—")[:80]),
               _esc((s.get("dialog_text") or "—")[:80]),
               _esc(s.get("explain") or "—"), verdict))
    return ("<p class='muted'>每次系统权限弹窗单独一条。判断依据按优先级："
            "① 系统弹窗内是否带有 App 提供的说明文字；② 弹窗出现前 App 是否弹出过"
            "说明目的的浮窗/页面；③ 弹窗所在功能界面的文字是否说明了用途。"
            "三者都没有才记为「未同步告知」。</p>"
            "<table class='cover'><tr><th>权限</th><th>申请前界面</th>"
            "<th>系统弹窗原文</th><th>App 给出的目的说明</th><th>判定</th></tr>"
            "%s</table>" % "".join(rows))


def _repro_results(fr: FlowResult) -> str:
    """复现确认结果（正文不含章标题，编号由调用方统一编排）。"""
    rs = fr.repro_results or []
    if not rs:
        return ""
    rows = []
    for r in rs:
        rep = r.get("reproduced")
        # 三态各有各的颜色：已复现=红（问题成立）、未复现=黄（改名"疑似"）、
        # 未能判定=灰。把"没跑成"画成和"未复现"一样，等于用工具的失败
        # 去暗示问题不成立。
        if rep is True:
            label = "<span class='chip c-high'>%s</span>" % _esc(r.get("result_label") or "已复现")
        elif rep is False:
            label = "<span class='chip c-mid'>%s</span>" % _esc(r.get("result_label") or "未复现")
        else:
            label = "<span class='muted'>%s</span>" % _esc(r.get("result_label") or "未能判定")
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (_esc(r.get("qid", "")), _esc((r.get("title") or "")[:34]),
               label, _esc(r.get("how") or ""), _esc(r.get("note") or "—")))
    n_ok = sum(1 for r in rs if r.get("reproduced") is True)
    n_no = sum(1 for r in rs if r.get("reproduced") is False)
    n_mid = len(rs) - n_ok - n_no
    tail = ("<p class='muted'>本轮对方：已复现 %d 项、未复现 %d 项、未能判定 %d 项。"
            "「未复现」的项已按「疑似」处理，需人工复核；"
            "「未能判定」的项状态不变，原因见说明列 —— 那不代表「问题不存在」，"
            "而是这一轮的复现没有取得可对照的数据。"
            "权限申请类条目尤其常见「未能判定」：系统可能记住此前的拒绝而不再询问，"
            "或本轮没有再走到会索权的那个功能，两种情况都取不到可对照的弹窗。</p>"
            % (n_ok, n_no, n_mid))
    _td = fr.repro_teardown or {}
    if _td:
        tail += ("<p class='muted'>复现轮结束后已再次卸载被测应用：%s</p>"
                 % _esc(_td.get("note") or "已处理"))
    return ("<p class='muted'>复现方法：清除应用数据<b>并收回运行时权限</b>"
            "（把 App 恢复到「刚安装、从未授权」的状态，否则权限弹窗不会再出现），"
            "<b>按首轮记录的点击路径逐步重放</b>（不是重新探索，也不调用模型），"
            "以「同一调用／同一类信息再次被采集」为判据，不以后台重新启动 App 为准。"
            "两轮走的是同一批界面，因此「判据没再出现」才作为未复现的依据；"
            "复现不成功的保留为疑似，不写成确证。</p>"
            + _replay_note(fr) +
            "<table class='cover'><tr><th>项</th><th>检测项</th><th>复现结果</th>"
            "<th>复现方法</th><th>说明</th></tr>" + "".join(rows) + "</table>" + tail)


def _ai_usage(fr: FlowResult) -> str:
    """「AI 参与情况」：本轮哪些环节调了模型、结果是什么状态。

    ★ 为什么必须写
      报告里的结论在纸面上长得一样，来源却不同。复核员要能回答"这条是模型
      读出来的，还是关键词配上的"—— 前者换一个模型/换一次采样就可能变，
      后者是确定性的。不写清这一点，整份报告就是黑盒。

    ★ 口径
      只写**实际发生过**的：开关开着但没产出结果的，写"已开启但未产出结果"
      并带上流程自己记的原因，不写成"已完成"。没有这些字样的判定（权限兜底、
      SDK 对照、时序统计、政策类型闸门）一律由确定性规则得出。
    """
    au = dict(getattr(fr, "ai_used", None) or {})
    stats = dict(au.get("stats") or {})
    if not au and not stats:
        return ""
    rows: List[tuple] = []

    # ★ 开关状态一律取**采集存档**里的事实，不取渲染时的配置。
    #   真机实测踩过：用默认配置离线重渲染（--from-result，没带 --ai-vision），
    #   报告里写"视觉未开启"，而同一张表下面又写着"带图片 8 次" —— 自相矛盾。
    #   存档里记的是采集那一刻发生了什么，这才是复核员要问的东西。
    _vision_n = int(stats.get("vision") or 0)
    _vision_on = (bool(au.get("vision")) or bool(stats.get("vision_enabled"))
                  or _vision_n > 0)
    rows.append(("视觉能力（截图识别）",
                 ("已启用，本轮带图片调用 %d 次（用于政策入口识别、页面类型判断）"
                  % _vision_n) if _vision_on else
                 "未启用（政策入口识别与页面类型判断回退到结构树与关键词）"))
    _ai_walk = []
    if fr.ai_guided or fr.ai_free:
        _ai_walk.append("已参与：图引导 %d 步 / 自由规划 %d 步"
                        % (fr.ai_guided, fr.ai_free))
    else:
        _ai_walk.append("未参与：本轮遍历全部由规则调度完成")
    rows.append(("UI 遍历 AI 引导", "，".join(_ai_walk)))

    # ---- 政策正文深读：三种状态分开写，不合并成一句"AI 已参与" ----
    deep = dict(au.get("policy_deep") or {})
    _st = str(deep.get("status") or "")
    if _st == "完成":
        _cover = float(deep.get("coverage") or 1.0)
        deep_txt = ("完成：声明类型 %d 项，覆盖 %d 段中 %.0f%%（失败 %d 段）"
                    % (int(deep.get("declared_types") or 0),
                       int(deep.get("chunks_total") or 1),
                       _cover * 100, int(deep.get("chunks_failed") or 0)))
    elif _st:
        deep_txt = "%s：%s" % (_st, deep.get("detail") or "—")
    else:
        deep_txt = "未执行"
    rows.append(("政策正文深读（分段抽取）", deep_txt))

    if stats:
        rows.append(("模型调用统计",
                     "共 %s 次（成功 %s / 失败 %s，带图片 %s 次），累计等待 %.0f 秒"
                     % (stats.get("total", 0), stats.get("ok", 0),
                        stats.get("failed", 0), stats.get("vision", 0),
                        float(au.get("wait_seconds") or 0))))
        if stats.get("model"):
            rows.append(("模型", "%s（视觉：%s）"
                         % (stats.get("model"), stats.get("vision_model") or "同上")))
    _errs = [str(x) for x in (au.get("errors") or []) if str(x).strip()]
    if _errs:
        rows.append(("模型侧异常", "；".join(x[:120] for x in _errs[:4])))

    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _rich(v))
                   for k, v in rows)
    return ("<table class='meta'>%s</table>"
            "<p class='muted'>本节「是否启用」取自采集存档（采集那一刻的事实），"
            "不是本报告渲染时的配置 —— 换一份配置重新渲染，这些字样不会变。"
            "需要说明的是：<b>政策深读的条目数由模型给出</b>，用同一份存档"
            "重新出报告（--from-result）会重新调用一次模型，数字可能小幅变动；"
            "除此之外的判定（权限申请兜底、SDK「声明 vs 实测」对照、"
            "同意前后时序统计、政策类型闸门、加固识别）全部由确定性规则得出，"
            "重新渲染结果不变。</p>" % body)


def _replay_note(fr: FlowResult) -> str:
    """复现轮路径重放的具体情况：走了多少步、有没有走完。

    这一段存在的理由：报告正文写了「按首轮路径重放」，就必须能回答
    「重放了多少、有没有跳过」。跳过或中途停止时，后面的问题项**没有**
    被真正验证过 —— 不写出来，复核员会以为每一项都重放过。
    """
    rp = fr.repro_replay or {}
    if not rp:
        return ""
    total = int(rp.get("total") or 0)
    done = int(rp.get("done") or 0)
    skip = len(rp.get("skipped") or []) + len(rp.get("not_replayable") or [])
    txt = "首轮共记录 %d 个动作，复现轮重放 %d 个" % (total, done)
    if skip:
        txt += "，跳过 %d 个（元素在当前版本找不到或属危险/提交类）" % skip
    txt += "。"
    # 具体跳过了哪几步：只写"跳过 2 个"，复核员没法判断那两步是不是触发点。
    _sn = [str(x) for x in (rp.get("skip_notes") or []) if str(x).strip()]
    if _sn:
        txt += "跳过的是：%s%s。" % (
            "；".join(_sn[:6]), "等" if len(_sn) > 6 else "")
    # 耗时与每步均值：改造的目的是"照着首轮的点法再走一遍"，因此这几个数字
    # 本身就是验收指标 —— 不写出来，复核员没法判断复现轮是"重走了路径"还是
    # "又整轮跑了一遍"。
    _el = rp.get("elapsed")
    _sps = rp.get("sec_per_step")
    if isinstance(_el, (int, float)) and _el > 0:
        txt += "重放耗时 %.0f 秒" % float(_el)
        if isinstance(_sps, (int, float)) and _sps > 0:
            txt += "（平均 %.1f 秒/步）" % float(_sps)
        txt += "，期间不调用模型、不做新的界面决策。"
    if rp.get("drift"):
        txt += ("重放中途判定为路径漂移（连续若干步找不到目标）后停止："
                "未执行到的步骤所对应的问题项一律记为「未能判定」，"
                "不因「判据没出现」而降为疑似。")
    elif rp.get("timed_out"):
        txt += ("到复现轮时长上限时仍未重放完，未执行到的步骤所对应的问题项记为"
                "「未能判定」，不因「判据没出现」而降为疑似。")
    elif rp.get("stopped"):
        # 中途停手（被测应用崩溃/退出、登录没成）也是"没走完"。
        # 这一档原先漏了，于是报告只写"重放 24 个"，却不写为什么停在 24 ——
        # 复核员会以为整条路径都走过了。
        txt += ("重放提前停止（%s）：未执行到的步骤所对应的问题项记为"
                "「未能判定」，不因「判据没出现」而降为疑似。"
                % str(rp.get("stopped") or ""))
    elif rp.get("complete") or (total and done >= total):
        # 「走完」要按 complete 判，不能只看 done>=total：跳过的步本就不算
        # 重放成功，53 步里重放 51 + 跳过 2 也是走完（mbsf19 实测）。
        if skip:
            txt += ("整条路径已按首轮顺序执行完，其中 %d 步未执行（跳过原因见上）。"
                    "若某项判据恰好由被跳过的那几步触发，本轮的「未复现」需人工确认。"
                    % skip)
        else:
            txt += "整条路径已走完，因此本轮「判据未再出现」是有效的未复现依据。"
    elif total and done < total:
        # 既没漂移、没超时、也没登记停止原因，却还没走完：不能默认为"走完了"。
        txt += ("重放未覆盖全部步骤（%d/%d），未执行到的步骤所对应的问题项"
                "不因「判据没出现」而降为疑似。" % (done, total))
    return "<p class='muted'>路径重放：%s</p>" % _esc(txt)


_CN_NUM = "一二三四五六七八九十"


def _review_materials(fr: FlowResult) -> str:
    """人工复核材料。

    自动检测的产出不只是一句结论，还得让复核员**有办法验**。
    这里给三样东西：能点开的链接、能照着重走的步骤、能查的静态事实。
    全部来自本次实测，没有一项是推出来的。

    ★ 章节编号在这里统一编排，不在各小节里写死
      各小节是**按条件渲染**的（没抓到政策就没第一节、没做复现就没那一节），
      编号写死就会出现"一、… 五、… 六、…"这种跳号，看起来像漏印了内容。
      编号一律由本节按实际渲染顺序生成。
    """
    secs: List[tuple] = []          # [(标题, 正文)]

    # ---- 检测能力边界 ----
    # 放在最前面：复核员需要先知道"哪些东西这份报告压根没看"，再看结论。
    # 尤其是网络外发 —— 本平台没有抓包能力，如果报告里出现"外发"字样，
    # 很容易被读成"监测到传了个人信息"。这里一次说清，后面各条目不再重复。
    secs.append((
        "检测能力边界（本报告不评估的范围）",
        "<p>本轮检测<b>不具备流量监测能力</b>（未部署抓包/mitmproxy），"
        "因此<b>不评估「应用对外发送了哪些个人信息」</b>："
        "报告正文中出现的第三方地址，只表示应用运行期<b>连接到了该地址</b>，"
        "不表示已确认传输了个人信息。</p>"
        "<p>「未对个人信息采取加密、去标识化等安全技术措施」（Q025）与"
        "「存在个人信息泄露风险隐患」（Q024）因此标注为「跳过未测」——"
        "其含义是<b>没有测</b>，不代表这两项合规；如需认定，应以抓包方式另测。</p>"
        "<p>权限申请类条目（Q010/Q011/Q012/Q026）：检测过程中每次系统权限弹窗"
        "<b>均单独截图</b>，截图直接附在对应检测项下方，可与弹窗原文、"
        "弹窗前的界面上下文逐条核对；若某项未附截图，该项会明确写出"
        "「未取得权限弹窗截图」，需人工复测补充。</p>"
    ))

    # 被排除的政策正文（第三方 SDK 的政策）。这段话必须出现在政策章节里：
    # 复核员看到"本轮未取得政策"时，有权知道我们其实读到过一份、以及为什么不用它。
    _rej = ""
    if getattr(fr, "policy_rejected", None):
        _r = fr.policy_rejected
        _rej = ("<p class='muted'><strong>已排除的政策正文：</strong>%s"
                "（%d 字，来源：%s）。该文本不作为被测应用的政策依据，"
                "因此本节与政策相关的结论均未使用它。</p>"
                % (_esc(_r.get("reason") or ""), int(_r.get("chars") or 0),
                   _esc(_r.get("url") or "本次采集")))

    # 采集期拒收 / 被顶替的候选正文。为什么不省略：
    # 复核员看到"政策只有 1652 字"时会怀疑没翻到全文，而这里能说清
    # "确实翻到过一份 2674 字的《VIP会员服务协议》，但它是协议不是隐私政策"。
    # 反之，如果政策正文被换了，也必须写清换掉的是哪一份。
    _side = list(getattr(fr, "policy_side_texts", None) or [])
    if _side:
        _rows = "".join(
            "<tr><th>%s</th><td>%s</td><td style='width:64px'>%d 字</td><td>%s</td></tr>"
            % (_esc(x.get("kind") or ""), _esc(x.get("url") or "（未记录地址）"),
               int(x.get("chars") or 0), _esc(x.get("why") or ""))
            for x in _side[:8])
        _rej += ("<p class='muted'><strong>采集期看到的其他长文本（均未用作政策依据）：</strong></p>"
                 "<table><tr><th>处置</th><th>来源</th><th>字数</th><th>理由</th></tr>%s</table>"
                 % _rows)

    # ---- 本轮读到的各类声明文档（政策 / 用户协议 / 收集清单 / 共享清单）----
    # ★ 为什么要按"文档类型"分行（用户 2026-10-28 意见）：
    #   检 App 时真正要用的不只隐私政策 —— 「是否逐一列明接收方」看共享清单、
    #   「未成年人专门规则」看未成年人政策、收集清单看收集范围。
    #   旧版只列"政策正文 + 弹窗摘要"，其余要么不出现、要么混进
    #   「采集期看到的其他长文本（均未用作政策依据）」，复核员会以为没抓到。
    if fr.policy_refs:
        rows = []
        for r in fr.policy_refs:
            url = r.get("url") or ""
            path = r.get("path") or ""
            # ★ 只有真正的 http(s) 地址才做成可点链接。安装包内置文档的路径
            #   （assets/vivo_private.html）曾经也被塞进 url 字段，渲染出来是
            #   `<a href="assets/vivo_private.html">` —— 复核员点不开，还以为是
            #   政策链接抓错了（Hi投屏 2026-10-26 那轮就是这么被问的）。
            #   更严重的一种：把界面收割的来源标签当地址，渲染成
            #   `file:///…/政策页面文本（滚动后）`（金考典 2026-10-28）。
            if url.lower().startswith("http"):
                link = "<a href='%s' target='_blank'>%s</a>" % (_esc(url), _esc(url))
            elif path:
                link = ("<span class='muted'>安装包内 %s（非网址，解包可对照）</span>"
                        % _esc(path))
            else:
                link = "<span class='muted'>（内嵌于报告，见下方全文）</span>"
            rows.append(
                "<tr><th>%s</th><td>%s</td>"
                "<td style='width:150px'>%s</td>"
                "<td style='width:70px'>%s</td></tr>"
                % (_esc(r.get("kind") or "文档"), link,
                   _esc(r.get("title", "")),
                   ("%d 字" % r["chars"]) if r.get("chars") else "—"))
        body = ("<table class='meta'><tr><th>文档类型</th><th>地址／包内路径</th>"
                "<th>名称</th><th>字数</th></tr>" + "".join(rows) + "</table>")
        # 全文内嵌：内嵌在安装包里的政策（金考典这类）没有可点开的链接，
        # 只给"开头 200 字"等于让复核员自己去解包 —— 索性把全文放进报告。
        for r in fr.policy_refs:
            full = (r.get("text") or "").strip()
            if not full:
                if r.get("excerpt"):
                    body += ("<details><summary>%s · 开头 200 字</summary>"
                             "<pre class='x'>%s</pre></details>"
                             % (_esc(r.get("title", "")), _esc(r["excerpt"])))
                continue
            _cap = 30000
            _tail = ""
            if len(full) > _cap:
                _tail = ("\n\n……（全文 %d 字，此处显示前 %d 字；"
                         "完整原文见采集存档 policy_capture）" % (len(full), _cap))
                full = full[:_cap]
            body += ("<details><summary>%s · %s · 全文 %d 字</summary>"
                     "<pre class='doc'>%s%s</pre></details>"
                     % (_esc(r.get("title", "")), _esc(r.get("kind") or "文档"),
                        int(r.get("chars") or len(r.get("text") or "")),
                        _esc(full), _esc(_tail)))
            if r.get("how"):
                body += "<p class='muted'>取得方式：%s</p>" % _esc(r["how"])
        secs.append(("本次读取到的政策与共享清单（可直接打开核对）",
                     body + _rej))
    else:
        secs.append(("本次读取到的政策与共享清单",
                     "<p class='muted'>本次未取得政策正文，无链接可留。</p>" + _rej))

    # ---- 复现步骤 ----
    if fr.repro:
        items = "".join("<li>%s</li>" % _rich(s) for s in fr.repro)
        title = ("复现步骤（复现启动崩溃）" if getattr(fr, "app_start_failed", False)
                 else "复现步骤（照此可重走一遍）")
        secs.append((title, "<ol class='repro'>%s</ol>" % items))

    # ---- 静态事实 ----
    s = fr.static or {}
    if s:
        perms = s.get("permissions") or []
        rows = [
            ("包名", s.get("package", "")),
            ("minSdkVersion", s.get("min_sdk", "")),
            ("targetSdkVersion", s.get("target_sdk", "")),
            ("权限声明总数", "%d 项" % len(perms) if perms else ""),
            ("第三方 SDK", "%d 个" % len(s.get("sdks") or []) if s.get("sdks") else ""),
            ("签名", str((s.get("signature") or {}).get("subject", "")
                         or (s.get("signature") or {}).get("cn", ""))),
            ("加固", _jiagu_text(s)),
        ]
        body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _esc(v))
                       for k, v in rows if v not in ("", None))
        if perms:
            body += ("<details><summary>权限声明全表（%d 项）</summary>"
                     "<p class='muted'>%s</p></details>"
                     % (len(perms),
                        _esc("、".join(str(p.get("name", p) if isinstance(p, dict) else p)
                                      for p in perms))))
        secs.append(("静态检测关键内容", "<table class='meta'>%s</table>" % body))

    # ---- AI 参与情况 ----
    # 紧跟在静态检测之后：前面是"从包里读出来的事实"，这里是"哪些结论多走了
    # 一道模型"。复核员看后面 22 项时，需要知道某条是关键词命中的还是模型读出来的。
    _aiu = _ai_usage(fr)
    if _aiu:
        secs.append(("AI 参与情况（哪些结论是模型读出的）", _aiu))

    # ---- 收尾：卸载被测应用 ----
    # 流程最后一步固定卸载。写进报告有两个用处：
    #   ① 复核员知道设备现状（App 已不在，需先重装才能复现）；
    #   ② 卸载失败时不会被静默吞掉 —— 残留会污染下一轮的"首启"前提。
    td = fr.teardown or {}
    if td:
        rows_t = [
            ("被测应用", td.get("package", "")),
            ("卸载前状态", ("已安装，版本 %s" % (td.get("before") or {}).get("version")
                            if (td.get("before") or {}).get("installed")
                            else "未安装（无需卸载）")),
            ("安装路径", "；".join((td.get("before") or {}).get("paths") or [])),
            ("执行命令", td.get("command", "")),
            ("设备返回", td.get("output", "")),
            ("卸载后复查", ("设备上已查不到该包" if not (td.get("after") or {}).get("installed")
                            else "**仍能查到该包**")),
            ("结论", td.get("note", "")),
        ]
        body_t = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _rich(str(v)))
                         for k, v in rows_t if v not in ("", None))
        secs.append(("收尾处理（卸载被测应用）",
                     "<table class='meta'>%s</table>"
                     "<p class='muted'>本报告出具时，被测应用已从检测设备卸载；"
                     "如需复核，请按上文「复现步骤」一节重新安装。</p>" % body_t))

    # ---- 本次检测使用的测试账号 ----
    # 放在收尾之后、对照之前：复核员先知道"用没用账号、登成没登成"，
    # 再看后面那几张"声明 vs 实测""权限申请"的表才不会被误导 ——
    # 游客态采到的行为不能代表登录态，反之亦然。
    secs.append(("本次检测使用的测试账号", _login_account(fr)))

    # ---- 同意动作（分水岭）----
    # 放在测试账号之后、对照之前：后面几张表（声明 vs 实测、权限场景、
    # 同意前/后事件统计）全部以"同意时刻"为界。先说清分界点是怎么定的，
    # 复核员才好判断那些"同意前 N 条"到底算不算数。
    secs.append(("同意动作（「同意前 / 同意后」的分水岭）", _consent_section(fr)))

    # ---- 声明与实测的逐 SDK 对照 ----
    _dm = _declare_matrix(fr)
    if _dm:
        secs.append(("声明与实测对照（App 自身 + 逐个第三方 SDK）", _dm))

    # ---- 权限申请场景 ----
    _ps = _perm_scenes(fr)
    if _ps:
        secs.append(("权限申请场景（是否同步告知目的）", _ps))

    # ---- 复现确认结果 ----
    _rr = _repro_results(fr)
    if _rr:
        _rs = fr.repro_results or []
        secs.append(("问题复现确认（%d 项中 %d 项已复现）"
                     % (len(_rs), sum(1 for r in _rs if r.get("reproduced"))), _rr))

    # ---- 未挂载的截图 ----
    # ★ 截图已经分散放在各个检测项下面（见 _item_shots），这里**只补**那些
    #   没有对应到任何一项的图（没触发判定的中间界面等）。它们是遍历留痕，
    #   复核员可能正是靠它判断"到底走到了哪一屏"，所以不删，但不再重复主体。
    unused = list(getattr(fr, "shots_unused", None) or [])
    if unused:
        ph_name = {"P1": "P1 首次运行·未同意阶段", "P2": "P2 隐私政策采集",
                   "P3": "P3 同意（边界点）", "P4": "P4 同意后遍历"}
        figs = []
        for it in unused:
            figs.append(
                "<figure><img src='data:image/jpeg;base64,%s' alt='%s'/>"
                "<figcaption>附图 %s：%s　<span class='muted'>（%s）</span></figcaption>"
                "</figure>" % (it.get("b64", ""), _esc(it.get("label", "")),
                               it.get("index"), _esc(it.get("label", "")),
                               _esc(ph_name.get(it.get("phase"), it.get("phase") or ""))))
        secs.append(("未挂到具体检测项的界面截图（%d 张）" % len(unused),
                     "<p class='muted'>各检测项的截图已直接放在该项正文下方。"
                     "下面这些是本轮采集到、但没有对应到任何单项结论的界面留痕，"
                     "供复核时判断遍历实际走到了哪里；图上若带有编号方框，"
                     "是检测工具为定位可点元素所画的标注，不影响画面内容。</p>"
                     "<div class='gallery'>%s</div>" % "".join(figs)))

    # ---- 外跳去向 ----
    # 放在「界面覆盖情况」之前：覆盖情况回答"走到了 App 的哪些界面"，
    # 而外跳回答的是"有哪些入口把界面带出了 App、去了哪里"。
    # 后者不占覆盖率的分母（外部界面不是被测 App 的界面），但它是
    # 「权限管理是自建开关还是跳系统设置」「有没有第三方授权登录」的唯一来源 ——
    # 只看覆盖率的话，这两条事实在报告里一个字都不会出现。
    _fj = _foreign_jumps(fr, {int(it.get("index")): it for it in (fr.shots or [])
                              if it.get("index") is not None})
    if _fj:
        secs.append(("外部跳转去向（离开被测应用后到了哪里）", _fj))

    # ---- 界面覆盖情况 ----
    # 放在复核材料的最后：复核员读完"依据了什么"之后，紧接着就能看到
    # "这些依据覆盖了哪些界面、哪些没走到"。没有这一节，"未发现"与"没走到"
    # 在纸面上无法区分。
    _uc = _ui_coverage(fr)
    if _uc:
        secs.append(("界面覆盖情况（本轮遍历实际到达的界面）", _uc))

    # ---- 界面跳转图谱 ----
    # 紧跟在覆盖情况之后：先看"走到了哪"，再看"界面之间怎么连、还剩什么没试"。
    # 两节分开写是因为口径不同（范围 vs 路径），合成一节会让复核员
    # 分不清"没覆盖"到底是没走到、还是走到了但没得点。
    _kg = _kg_section(fr)
    if _kg:
        secs.append(("界面跳转图谱（界面之间的跳转、未试入口与权利入口可达性）", _kg))

    # ---- 证据取舍说明 ----
    # 采集存档里存在、但**经核对不成立**的证据（例如标着"政策页"、字节却与
    # 首启弹窗完全相同的截图）。这类东西必须明写"已剔除"，否则复核员在
    # 采集原始数据里看到那张图，会以为报告漏用了证据。
    _notes = [str(x).strip() for x in (getattr(fr, "notes", None) or [])
              if str(x).strip()]
    if _notes:
        secs.append(("证据取舍说明（哪些采集结果未被采用）",
                     "<ul class='plain'>%s</ul>"
                     % "".join("<li>%s</li>" % _rich(n) for n in _notes)))

    out = []
    for i, (title, body) in enumerate(secs):
        n = _CN_NUM[i] if i < len(_CN_NUM) else str(i + 1)
        out.append("<h3>%s、%s</h3>%s" % (n, title, body))
    return "".join(out)


# ---------------------------------------------------------------- 外跳去向

def _foreign_jumps(fr: FlowResult,
                   shot_map: Optional[Dict[int, Dict[str, Any]]] = None) -> str:
    """「外部跳转去向」章节：点了哪些入口把人带出了被测应用，各自算不算证据。

    ★ 为什么必须写进报告：
      报告里若只写"未发现隐私政策未列明第三方 SDK"，复核员看不出这个 App
      有没有「权限管理」入口 —— 而真机上这类入口常常**不是自建开关**，
      而是跳到系统设置的权限页。不说清这一点，"App 没有权限管理"和
      "有权入口但把开关交给系统"会被读成同一件事，二者在整改要求上完全相反。
      同理，跳微信授权登录意味着设备标识/头像昵称会流向第三方，这条与
      「第三方共享清单」一项直接相关。

    ★ 只写看到的事实：跳过去了、落点是什么、截了图。**不据此认定违规** ——
      授权登录本身是合法功能，是否合规要看那个第三方有没有在政策里列明、
      授权前有没有告知。
    ★ 也说清边界：行为采集装在被测应用进程里，外部应用内的操作与网络传输
      不在采集范围，这里只能证明"去了哪里、那一页写了什么"。
    """
    rows = [j for j in (getattr(fr, "external_jumps", None) or [])
            if isinstance(j, dict)]
    if not rows:
        return ""
    shot_map = shot_map or {}
    from ..flow import foreign as FJ
    sm = FJ.summarize(rows)

    kinds = {str(j.get("kind") or "") for j in rows}
    valuable = [j for j in rows if j.get("valuable")]

    # ---- 概览 ----
    meta = [
        ("本轮离开被测应用的次数", "%d 次" % sm["total"]),
        ("其中有取证价值的跳转", "%d 次（系统设置页 / 授权登录 / 外部支付）" % sm["valuable"]),
        ("无意义跳转（已即时返回）", "%d 次（应用商店 / 系统选择器 / 浏览器普通网页等）"
         % sm["meaningless"]),
    ]
    if sm["left_app"]:
        meta.append(("落到系统桌面（应用被退出）", "%d 次，均已重新拉起" % sm["left_app"]))
    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _rich(v))
                   for k, v in meta)
    out = ["<table class='meta'>%s</table>" % body]

    # ---- 结论段（按类型说，不堆术语）----
    notes: List[str] = []

    def _entries(kind_set: Set[str], limit: int = 3) -> str:
        labs: List[str] = []
        for j in rows:
            if str(j.get("kind") or "") not in kind_set:
                continue
            lab = (j.get("entry") or "").strip()
            if lab and lab not in labs:
                labs.append(lab)
        if not labs:
            return ""
        shown = "」「".join(_esc(x) for x in labs[:limit])
        more = "等" if len(labs) > limit else ""
        return "「%s」%s" % (shown, more)

    if "settings_perm" in kinds:
        notes.append(
            "%s入口跳转至<b>系统设置的权限管理页</b>：被测应用未内置权限开关，"
            "用户需到系统设置中关闭授权。这一事实影响「权限管理入口是否可用」"
            "与「撤回同意的便利性」两项的判断 —— 不能读成「该应用没有权限相关入口」。"
            % (_entries({"settings_perm"}) or "权限相关"))
    if "settings_plain" in kinds:
        notes.append(
            "%s入口跳转至系统设置的其他页面：应用把该项配置交给系统承接，"
            "自身界面内没有对应的开关。" % (_entries({"settings_plain"}) or "部分"))
    if kinds & {"sns_auth", "browser_auth", "unknown_auth"}:
        targets: List[str] = []
        for j in rows:
            if str(j.get("kind") or "") not in ("sns_auth", "browser_auth", "unknown_auth"):
                continue
            lab = str(j.get("label") or "")
            if lab and lab not in targets:
                targets.append(lab)
        notes.append(
            "%s存在<b>第三方授权登录</b>路径（去向：%s）：授权过程在被测应用之外完成，"
            "本工具未记录该过程的传输内容；该第三方是否已在隐私政策或第三方共享清单中"
            "列明，见「声明与实测对照」一节。"
            % (_entries({"sns_auth", "browser_auth", "unknown_auth"}) or "",
               "、".join(_esc(t) for t in targets[:3]) or "外部应用"))
    if "sns_pay" in kinds:
        notes.append(
            "%s跳转至外部支付应用：该功能需第三方收银台结算，"
            "支付环节收集的信息不在本轮采集范围内。" % (_entries({"sns_pay"}) or "部分"))
    if sm["meaningless"] and not valuable:
        notes.append(
            "本轮没有跳转提供取证价值；%d 次跳转均为应用商店、系统选择器、"
            "浏览器普通网页等与被测应用行为无关的界面，已即时返回，"
            "未计入界面覆盖。" % sm["meaningless"])

    if notes:
        out.append("<ul class='plain'>%s</ul>"
                   % "".join("<li>%s</li>" % n for n in notes))

    # ---- 明细 ----
    trs = []
    for j in rows:
        idx = j.get("shot_index")
        shot_cell = ("附图 %s" % _esc(idx)) if idx else "未留证"
        trs.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (_esc(j.get("seq") or ""),
               _esc(j.get("entry") or "—"),
               _esc(j.get("label") or "—"),
               _esc(j.get("pkg") or "—"),
               # 判定列直接对应整改方向：值得留证 vs 与本轮无关
               ("<b>有取证价值</b>（已留证后返回）" if j.get("valuable")
                else "无意义跳转（已即时返回）"),
               shot_cell))
    out.append(
        "<div class='label'>明细</div>"
        "<table class='meta'><tr><th>#</th><th>入口</th><th>去向</th>"
        "<th>宿主包名</th><th>判定</th><th>截图</th></tr>%s</table>"
        % "".join(trs))

    # ---- 每条的判决理由（写清"凭什么这么判"，避免只给结论）----
    reasons = []
    for j in rows:
        why = str(j.get("why") or "").strip()
        if not why:
            continue
        line = "「%s」→ %s：%s" % (_esc(j.get("entry") or "未知入口"),
                                   _esc(j.get("label") or "其他应用"), _esc(why))
        if line not in reasons:
            reasons.append(line)
    if reasons:
        out.append("<div class='label'>判定理由</div><ul class='plain'>%s</ul>"
                   % "".join("<li>%s</li>" % x for x in reasons[:8]))

    # ---- 截图（有价值的跳转）----
    figs = []
    for j in rows:
        idx = j.get("shot_index")
        if not idx:
            continue
        it = shot_map.get(int(idx)) or {}
        b64 = it.get("b64") or ""
        if not b64:
            continue
        figs.append(
            "<figure><img src='data:image/jpeg;base64,%s' alt='%s'/>"
            "<figcaption>附图 %s：进入%s后的界面（入口「%s」）</figcaption></figure>"
            % (b64, _esc(j.get("label") or ""), _esc(idx),
               _esc(j.get("label") or "外部应用"), _esc(j.get("entry") or "—")))
    if figs:
        out.append("<div class='label'>跳转落点截图</div><div class='shots'>%s</div>"
                   % "".join(figs))
        if any(j.get("kind", "").startswith("settings") for j in rows):
            out.append("<p class='muted'>注：以上截图拍的是<b>系统设置里的界面</b>，"
                       "不是被测应用自己的页面。它证明的是「该入口把用户交给了系统」，"
                       "图上的开关属于设备侧设置。</p>")

    out.append(
        "<p class='muted'>说明：本工具的行为采集运行在被测应用进程内。"
        "跳转到其他应用或系统页面后，外部界面里的操作与网络传输不在采集范围，"
        "本节的证据只能说明「从哪个入口去了哪里、落点界面写了什么」。"
        "对无取证价值的跳转（应用商店、系统选择器、浏览器普通网页等），"
        "检测过程在识别后立即返回，避免占用遍历预算。</p>")
    return "".join(out)


# ---------------------------------------------------------------- 界面覆盖

def _ui_coverage(fr: FlowResult) -> str:
    """「界面覆盖情况」章节：这个结论覆盖了哪些界面、还有哪些没走到。

    ★ 为什么必须有这一节：
      报告里 22 项写的"未发现…"。复核员凭什么信？凭的只能是"我们确实走到了那些
      界面并且看过"。没有这一节，"未发现"与"没走到"在纸面上长得一模一样 ——
      这违反真实性第一原则。
    ★ 口径铁律（写进正文，不只是内部约定）：
      只在**已到达的界面**里可以写"未发现"；没走到的区域一律写"未覆盖"，
      并给出未覆盖的具体入口数。**不许把没走到写成没这个行为**。
    """
    c = dict(fr.coverage or {})
    if not c or not c.get("app_states"):
        return ""
    d = dict(c.get("detail") or {})
    sched = dict(c.get("scheduler") or {})
    targets = list(c.get("targets") or [])

    def _pct(x: Any) -> str:
        try:
            return "%.0f%%" % (float(x) * 100)
        except Exception:
            return "—"

    explored = int(d.get("explored") or 0)
    todo = int(d.get("unexplored") or 0)
    total = explored + todo

    def _sec_txt(sec: Any) -> str:
        """秒 → 人话。一小时档跑完是"1 小时 3 分"，不是"3810 秒"。"""
        try:
            s = int(float(sec))
        except Exception:
            return "—"
        if s <= 0:
            return "—"
        if s < 60:
            return "%d 秒" % s
        h, m = s // 3600, (s % 3600) // 60
        if h:
            return "%d 小时%s" % (h, " %d 分" % m if m else "")
        return "%d 分%s" % (m, " %d 秒" % (s % 60) if s % 60 else "")

    rows = []
    # ---- 档位与预算（2026-11-01）----
    # 放在最前面：复核"这一轮结论能代表多少"时，第一个要确认的就是"测了多久"。
    # 预算与实际耗时分开写，因为它们经常不相等：提前终止（连续重启超限）、
    # AI 等待补偿都会让两者差出几十分钟。只写一个数就分不清
    # "没给足时间"与"给了时间但没跑满"。
    # 2026-11-19 三档。extreme 只为读得懂旧存档（原 4 档，预算与现在的
    # 3 档相同 3600 秒），新任务不会再出现这个值。
    _DEPTH_NAME = {"pre": "1 档 · 仅同意前", "light": "2 档 · 二级菜单",
                   "deep": "3 档 · 全功能",
                   "extreme": "3 档 · 全功能（旧 4 档存档）",
                   "normal": "常规（旧档）"}
    _dn = _DEPTH_NAME.get(str(fr.depth or ""), str(fr.depth or ""))
    if _dn or fr.budget_seconds:
        _txt = _dn or "未记录"
        if fr.budget_seconds:
            _txt += "（采集预算 %s" % _sec_txt(fr.budget_seconds)
            if fr.scan_elapsed:
                _txt += "，实际采集 %s）" % _sec_txt(fr.scan_elapsed)
            else:
                _txt += "）"
        elif fr.scan_elapsed:
            _txt += "（实际采集 %s）" % _sec_txt(fr.scan_elapsed)
        rows.append(("检测档位与耗时", _txt))

    rows.extend([
        ("到达的被测应用界面", "%d 个（另有 %d 个系统界面未计入：权限弹窗等）"
         % (c.get("app_states") or 0, c.get("system_states") or 0)),
        ("界面跳转（边）", "%d 条" % (c.get("edges") or 0)),
        ("最大层级深度", "%d 层" % (d.get("max_depth") or 0)),
        ("入口探索比例", "%d / %d（%s）" % (explored, total, _pct(d.get("explore_ratio")))),
        ("列表界面", ("%d 个，已加载 %d 页"
                      % (d.get("list_states") or 0, d.get("pages_loaded") or 0))
         if d.get("list_states") else "本轮未识别到列表界面"),
        ("点击 / 重复点击", "%d 次 / %d 次" % (c.get("taps") or 0, c.get("repeat_taps") or 0)),
        ("点了无反应的入口", "%d 个" % (d.get("dead") or 0)),
        ("干扰类弹窗（广告/评分/活动）", "%d 次" % (d.get("dialogs") or 0)),
        ("本轮中断原因", c.get("interrupt") or "时间预算耗尽"),
    ])
    # ---- 循环防护的口径（2026-11-01）----
    # 一轮 1 小时的任务最后只走了几十个界面时，复核员一定要问"剩下的时间呢"。
    # 这一行就是答案：拦掉了多少次重复点击、几次整屏冻结、几次判定为循环。
    # 放在"中断原因"之前 —— 它们读起来是同一个问题的两半。
    _led = dict(c.get("ledger") or {})
    _loop = dict(c.get("loop") or {})
    if _led or _loop:
        _parts = []
        if _led.get("blocked_taps") or _led.get("blocked_frozen"):
            _parts.append("重复点击拦截 %d 次、整屏冻结拦截 %d 次"
                          % (int(_led.get("blocked_taps") or 0),
                             int(_led.get("blocked_frozen") or 0)))
        if _loop.get("osc_hits"):
            _parts.append("识别到界面循环 %d 次" % int(_loop["osc_hits"]))
        if _led.get("tap_limit"):
            _parts.append("同一界面同一入口最多点 %d 次（再多也不产生新信息）"
                          % int(_led["tap_limit"]))
        if _parts:
            _idx = next((i for i, (k, _v) in enumerate(rows) if k == "本轮中断原因"),
                        len(rows))
            rows.insert(_idx, ("循环防护", "；".join(_parts)))
    # 「未探索入口」里有多少是结构树没给出名字的可点容器。不说明的话，
    # 「还有 105 个入口没点」读起来像漏了一大片功能，其实大半是 FrameLayout 这类外框。
    if d.get("unexplored_opaque"):
        rows.append(("其中无文字可点容器",
                     "%d 个（结构树未给出可读名称，点击去向不可预期）"
                     % int(d.get("unexplored_opaque") or 0)))
    # 内容型列表（资讯/文章/商品）的抽样口径（2026-11-03）。
    # 不写这一行，「还有 200 个入口没点」会被读成"测得很浅"，而其中大半是
    # 同一模板渲染出来的内容卡片 —— 点第 2 条开始就是同一套页面（真机实测：
    # 川剧迷 80% 的采集时间耗在这里）。
    if d.get("content_states") or sched.get("content_pages"):
        rows.append(("内容型列表（资讯/商品）",
                     "%d 个页面；同模板条目 %d 条按同构跳过（每页只展开 1 条）"
                     % (int(d.get("content_states") or sched.get("content_pages") or 0),
                        int(d.get("unexplored_content")
                            or sched.get("content_items_skipped") or 0))))
    if sched.get("drift"):
        rows.append(("界面漂移", "%d 次（返回时被拦截页/广告页插队）" % sched["drift"]))
    # 登录状态直接决定"哪些界面本轮根本进不去"。不写这一句，
    # 「我的」下面那一片未覆盖会被读成"App 没有这些功能"。
    _lg = fr.login or {}
    if _lg.get("attempted"):
        rows.append(("登录状态", ("已登录（测试账号 %s，%s）"
                                  % (_lg.get("phone") or "—", _lg.get("method") or "—"))
                     if _lg.get("ok") else
                     ("未完成登录（%s）；账号类界面（我的/设置/账号安全等）本轮未覆盖"
                      % (_lg.get("note") or "登录流程未走通"))))
    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _rich(v))
                   for k, v in rows)
    out = ["<table class='meta'>%s</table>" % body]

    # ---- 各一级 tab 的覆盖 ----
    tabs = list(d.get("tabs") or [])
    if tabs:
        trs = []
        for t in tabs:
            trs.append("<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>"
                       % (_esc(t.get("tab") or ""), t.get("states") or 0,
                          t.get("depth") or 0, t.get("clicked") or 0,
                          t.get("todo") or 0))
        out.append("<p class='muted'>各主导航（tab）下的覆盖情况：</p>"
                   "<table class='cover'><tr><th>主导航</th><th style='width:78px'>界面数</th>"
                   "<th style='width:64px'>深度</th><th style='width:78px'>已点入口</th>"
                   "<th style='width:78px'>未点入口</th></tr>"
                   + "".join(trs) + "</table>")

    # ---- 权利入口定位结果（定向期）----
    if targets:
        trs = []
        for t in targets:
            if t.get("found"):
                note = ("入口被安全规则拦截，未点击（注销/退出类不可执行）"
                        if t.get("blocked") else "已定位")
                state = "已找到"
            else:
                # ★ 找不到 ≠ 没有。只写"本轮未到达"，不写"未提供"。
                note = "本次遍历未到达该入口所在界面"
                state = "未覆盖"
            trs.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                       % (_esc(t.get("name") or ""), _esc(state),
                          _esc(t.get("where") or "—"),
                          _esc(t.get("label") or "—"), _esc(note)))
        out.append("<p class='muted'>定向查找的权利行使入口（PIPL 第 15/17/45/47 条）："
                   "「已找到」表示该入口确实存在于下列界面；"
                   "<strong>「未覆盖」只表示本轮没走到，不代表 App 未提供</strong>。</p>"
                   "<table class='cover'><tr><th>权利入口</th><th style='width:60px'>结果</th>"
                   "<th style='width:130px'>所在界面</th><th style='width:110px'>入口文字</th>"
                   "<th>说明</th></tr>" + "".join(trs) + "</table>")

    # ---- 未探索入口（具体是哪些）----
    gaps = list(d.get("gaps") or [])
    if gaps:
        trs = []
        for g in gaps:
            trs.append("<tr><td>%s</td><td>%d</td><td>%s</td></tr>"
                       % (_esc(g.get("activity") or ""), g.get("count") or 0,
                          _esc("、".join(g.get("examples") or []))))
        out.append("<p class='muted'>还有入口没点到的界面（按缺口数排序）：</p>"
                   "<table class='cover'><tr><th>界面</th><th style='width:70px'>未点入口</th>"
                   "<th>示例</th></tr>" + "".join(trs) + "</table>")

    # ---- 被安全规则挡住的入口（该看见、不许点）----
    blocked = list(d.get("blocked_points") or [])
    if blocked:
        names = []
        for b in blocked:
            lab = b.get("label") or ""
            if lab not in names:
                names.append(lab)
        out.append("<p class='muted'>遍历中出现的「不可点击」入口（不同意/注销/退出登录等，"
                   "按检测规范仅记录不执行）：%s。</p>" % _esc("、".join(names[:12])))

    dead = list(d.get("dead_points") or [])
    if dead:
        ds = ["%s（%s）" % (x.get("label") or "", x.get("activity") or "")
              for x in dead[:10]]
        out.append("<p class='muted'>点击后界面无变化的入口（死点，可能是功能未开放或"
                   "被环境限制）：%s。</p>" % _esc("；".join(ds)))

    out.append("<p class='muted'><strong>口径说明：</strong>本节列出的是本轮遍历"
               "**实际到达**的界面范围。报告中「未发现问题」类结论仅对上述已到达界面成立；"
               "「未覆盖」表示本轮未走到该入口所在界面，**不代表被测应用不存在该行为**，"
               "需人工补充检测或延长遍历时长。</p>")
    return "".join(out)


def _mmss(t: Any) -> str:
    try:
        s = int(float(t))
    except Exception:
        return "—"
    return "%02d:%02d" % (s // 60, s % 60)


def _click_trail(fr: FlowResult) -> str:
    """「点击留痕」章节：每一次点击的界面图 + 点击位置 + 判读 + 预判 + 结果。

    ★ 为什么单独一节（用户 2026-11-05 要求）：
      报告原来只有"UI 点击 124 次"这种合计数字。复核员看不到"点在哪、凭什么点、
      点完有没有反应"，于是"测得够不够"只能靠感觉。逐次留痕把这三问一次答完；
      它同时是**自查工具** —— 换屏率低、空点集中在某类入口，说明候选生成有问题。

    图是**点击之前**那一屏（红圈＋十字＝点击位置），不是点完之后的界面：
    拿结果当证据是最常见的一类假证据。
    """
    items = [it for it in (getattr(fr, "click_shots", None) or [])
             if isinstance(it, dict) and it.get("b64")]
    if not items:
        # 旧存档 / 未启用界面遍历：不能默默空着，否则读的人以为是漏印了。
        return ("<p class='muted'>本轮未取得逐次点击留痕（旧版本采集存档或未启用"
                "界面遍历），仅有点击次数统计。如需逐次证据，请在当前版本下重跑。</p>")
    stats = getattr(fr, "click_stats", None) or {}
    n = int(stats.get("total") or len(items))
    n_new = int(stats.get("new") or 0)
    n_same = int(stats.get("same") or 0)
    n_unk = int(stats.get("unknown") or 0)
    rate = float(stats.get("new_rate") or 0.0)
    dropped = int(stats.get("dropped") or 0)

    out: List[str] = []
    out.append(
        "<p class='muted'>本节按时间顺序列出遍历期间的每一次点击：<b>左边是点击之前的"
        "界面，红圈＋十字标出点击位置</b>；右边写明点的是哪个元素、<b>这一步凭什么点"
        "（判读）</b>、<b>点下去之前预计会发生什么（预判）</b>，以及点完之后界面"
        "<b>实际</b>有没有变化。共 %d 次点击，其中 %d 次换到了新界面（%.1f%%）、"
        "%d 次界面无变化、%d 次未观测到下一屏。</p>"
        % (n, n_new, rate, n_same, n_unk))
    if dropped:
        out.append("<p class='muted'>另有 %d 次点击未内嵌截图（超出单份报告上限），"
                   "其动作与判读仍完整记在点击路径里。</p>" % dropped)

    # ★ 只说"共 3 次点击"会让人以为工具点不动（携船网实测就是这样：
    #   3 次点击背后是"首页所有入口都指向登录页"）。提前收工的原因必须紧跟在
    #   数字后面 —— 否则读者拿到的印象与事实相反，等于另一种假话。
    _itp = str((getattr(fr, "coverage", None) or {}).get("interrupt") or "")
    if _itp and _itp != "时间预算耗尽":
        out.append("<p class='muted'>本轮遍历提前结束，原因：%s（详见「界面覆盖情况」。"
                   "点击次数少不等于没点，而是可点的地方已经点完了）。</p>" % _esc(_itp))

    out.append("<div class='kpis'>"
               "<div class='kpi p'><div class='kpi-v'>%d</div><div class='kpi-l'>换到新界面</div></div>"
               "<div class='kpi s'><div class='kpi-v'>%d</div><div class='kpi-l'>界面无变化</div></div>"
               "<div class='kpi n'><div class='kpi-v'>%d</div><div class='kpi-l'>未观测到下一屏</div></div>"
               "</div>" % (n_new, n_same, n_unk))

    # 按预判种类统计有效率：这是"我们的预判准不准"的直接读数。
    bk = stats.get("by_kind") or {}
    if bk:
        rows = []
        for k, b in sorted(bk.items(), key=lambda kv: -int(kv[1].get("n") or 0)):
            nn = int(b.get("n") or 0)
            nw = int(b.get("new") or 0)
            label = _KIND_NAMES.get(k, k)
            rows.append("<tr><th>%s</th><td>%d 次点击，%d 次换到新界面（%d%%）</td></tr>"
                        % (_esc(label), nn, nw, round(100.0 * nw / nn) if nn else 0))
        out.append("<table class='facts'>%s</table>" % "".join(rows))

    rows_html: List[str] = []
    for it in items[:200]:
        res = str(it.get("result") or "")
        rl = {"new": "切换到新界面", "same": "界面无变化",
              "external": "前台切到别的应用"}.get(res, "未判定（未观测到下一屏）")
        cls = "citem" + (" same" if res == "same" else "")
        at = it.get("at") or []
        xy = "(%s, %s)" % (at[0], at[1]) if len(at) == 2 else "（坐标未记录）"
        lab = str(it.get("label") or "").strip() or "（无文字）"
        # 结构树里很多入口的"文字"其实就是类名（FrameLayout / ViewGroup）。
        # 直接印成「FrameLayout」（FrameLayout）看着像机器输出，复核员读不出信息 ——
        # 这类一律写"无文字入口"，与点击留痕的口径保持一致。
        try:
            from .. import clickev as _ce
            lab = _ce.plain_label(it.get("label") or "", it.get("cls") or "") \
                or "无文字入口"
        except Exception:
            pass
        rows_html.append(
            "<div class='%s'>"
            "<figure><img src='data:image/jpeg;base64,%s' alt='第 %s 次点击'/>"
            "<figcaption>#%s · %s · 点击位置 %s</figcaption></figure>"
            "<div class='cbody'>"
            "<div class='chead'>#%s 「%s」<span class='muted'>%s</span>"
            "<span class='tag'>%s</span></div>"
            "<p><span class='label'>判读：</span>%s</p>"
            "<p><span class='label'>预判：</span>%s（%s）</p>"
            "</div></div>"
            % (cls, it.get("b64"), _esc(it.get("i") or ""),
               _esc(it.get("i") or ""), _mmss(it.get("t")), _esc(xy),
               _esc(it.get("i") or ""), _esc(lab), _esc(it.get("cls") or ""),
               _esc(rl), _esc(it.get("why") or "（未记录）"),
               _esc(it.get("expect") or "（未预判）"),
               _esc(it.get("kind_label") or "")))
    out.append("<div class='ctrail'>%s</div>" % "".join(rows_html))
    return "".join(out)


# 预判种类的中文名（与 clickev.KIND_LABELS 同口径，报告层单独留一份
# 是为了旧存档里可能出现新代码没有的种类时也能正常显示）。
_KIND_NAMES = {
    "policy": "政策/协议入口", "logout": "权利入口", "consent": "同意类按钮",
    "disagree": "拒绝类按钮", "login": "登录/注册入口", "perm": "权限弹窗按钮",
    "setting": "设置/说明入口", "close": "关闭/返回", "form": "列表/筛选控件",
    "widget": "控件", "unknown": "无文字容器", "text": "文字入口",
}

_LANDING_ACTION_NAMES = {
    "tap": "点击", "swipe": "滑动", "back": "返回", "wait": "等待",
    "give_up": "停止（不再尝试）", "done": "结束（已到主页面）",
}
_LANDING_RESULT_NAMES = {
    "new": "换来新界面", "same": "界面未变", "give_up": "在此停下",
    "tap_failed": "点击未生效", "back_unsafe": "返回不安全，未执行",
    "ai_done_pending": "模型判断已到主页面，待本地确认",
    # 走到视觉判据那一步必须有自己的结果名：它原来是空的，表里渲染成「—」，
    # 而这一行恰恰是**整个着陆阶段的结论行**，读起来像"这一步什么也没发生"。
    "vision_home": "据此判定已到主页面",
    # 登录接力（2026-11-06）：着陆阶段遇到登录墙时用测试号登录。
    # 三种结果必须分开写 —— "发起登录"与"登录成功"是两件事，
    # 只记"发起"会让报告读起来像已经进了登录态。
    "login_assist": "转交登录辅助（发起了登录）",
    "login_ok": "登录成功，继续着陆",
    "login_fail": "登录未完成（未取得验证码或被风控）",
}


def _landing_section(fr: FlowResult) -> str:
    """「首启着陆」章节：点了同意之后，App 把我们带到了哪里、怎么走过来的。

    ★ 为什么单独列一节（用户 2026-11-06 意见）：
      同意之后的界面不是功能界面 —— 开屏广告、年龄门、欢迎引导页、促销弹窗、
      兴趣收集页都可能出现，而且四台真机上四种形态各不相同。这一段以前是空白，
      于是报告里"只点了 3 次"看起来像工具不行；实际是应用把登录墙立在首屏。
      把这段过程写出来，读者才能判断"未覆盖"是应用的限制还是检测的疏漏。

    只陈述"经过了什么、做了什么、结果如何"，**不对这些界面是否合规下结论** ——
    弹窗里有没有违规收集，要看 P4/P5 的证据。
    """
    d = dict(getattr(fr, "landing", None) or {})
    if not d:
        return ("<p class='muted'>本轮未记录首启着陆过程（旧版本采集存档、"
                "1 档只测同意前，或应用未能启动）。</p>")

    reached = bool(d.get("reached_home"))
    names = [str(x) for x in (d.get("form_names") or []) if x]
    taps = int(d.get("taps") or 0)
    swipes = int(d.get("swipes") or 0)
    secs = float(d.get("secs") or 0)
    detail = [x for x in (d.get("detail") or []) if isinstance(x, dict)]
    why = str(d.get("why") or "")

    out: List[str] = []
    if reached:
        if not names or names == ["主页面"]:
            lead = ("点击同意后<b>直接进入主页面</b>，中间没有额外环节，"
                    "功能遍历从主页面开始。")
        elif taps + swipes == 0:
            # 「用 0 次点击完成着陆」读起来像程序没动过（携船网实测就是
            # 开屏广告的「跳过」在结构树里不可点）。必须写清"为什么是 0"。
            lead = ("点击同意后依次经过 <b>%s</b>，这些界面没有可点击的关闭/跳过入口，"
                    "等待应用自行跳转后<b>已进入主页面</b>（未执行点击或滑动）。"
                    % " → ".join(names))
        else:
            lead = ("点击同意后依次经过 <b>%s</b>，用 %d 次点击、%d 次滑动完成着陆，"
                    "<b>已进入主页面</b>，功能遍历从主页面开始。"
                    % (" → ".join(names), taps, swipes))
    else:
        lead = ("点击同意后依次经过 <b>%s</b>，<b>未能进入主页面</b>（%s）。"
                "后续功能遍历从停留界面开始，与主页面功能相关的测评项按实际"
                "到达情况记录，未覆盖的部分在「界面覆盖情况」中说明。"
                % (" → ".join(names) or "无可记录界面", _esc(why or "原因未记录")))
    out.append("<p class='muted'>%s</p>" % lead)
    if reached and str(d.get("home_by") or "") == "vision":
        # 视觉判据与结构判据的证据强度不同，必须写出来：结构树里有底部导航
        # 是任何人重跑都能复现的；靠模型看图判的，换一次运行可能结论不同。
        out.append(
            "<p class='muted'>说明：本应用的主页面是 H5 / 自绘界面，"
            "<b>底部导航栏不进入 Android 界面结构树</b>（结构树里看不到「首页 / 我的」"
            "这些入口）。因此「是否已进入主页面」这一判据来自模型对截图的判读，"
            "且要求连续两次判读一致、界面未变动才采信；它不是结构层面的确认。</p>")

    # KPI 三格：到没到、花了多久、动了多少次。三个数合起来才说明"这一步难不难"。
    out.append(
        "<div class='kpis'>"
        "<div class='kpi %s'><div class='kpi-v'>%s</div>"
        "<div class='kpi-l'>是否进入主页面</div></div>"
        "<div class='kpi n'><div class='kpi-v'>%.1fs</div>"
        "<div class='kpi-l'>着陆耗时</div></div>"
        "<div class='kpi n'><div class='kpi-v'>%d</div>"
        "<div class='kpi-l'>点击 / 滑动</div></div>"
        "</div>"
        % ("p" if reached else "s", "已进入" if reached else "未进入",
           secs, taps + swipes))

    if detail:
        rows: List[str] = []
        for it in detail[:40]:
            act = str(it.get("action") or "")
            tgt = str(it.get("target") or "")
            act_txt = _LANDING_ACTION_NAMES.get(act, act or "—")
            if tgt:
                act_txt = "%s「%s」" % (act_txt, tgt)
            res = str(it.get("result") or "")
            res_txt = _LANDING_RESULT_NAMES.get(res, "—" if not res else res)
            ai_txt = str(it.get("ai") or "")
            rows.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                "<td>%s</td><td>%s</td><td>%s</td></tr>"
                % (_esc(it.get("n") or ""), _esc(it.get("form_name") or ""),
                   _esc(it.get("read") or "—"), _esc(act_txt),
                   _esc(it.get("why") or "—"),
                   _esc(ai_txt) if ai_txt else "未询问模型",
                   _esc(res_txt)))
        out.append(
            "<table class='ltable'>"
            "<tr><th>步</th><th>这一屏是什么</th><th>凭什么这么判</th>"
            "<th>做了什么</th><th>为什么这么做</th><th>模型意见</th>"
            "<th>结果</th></tr>%s</table>" % "".join(rows))
        out.append(
            "<p class='muted'>本阶段只做「把应用带到主页面」：关闭弹窗、跳过广告、"
            "走过引导页。因此表中没有进入任何功能页面，也不对列表做上拉加载 —— "
            "功能遍历是下一阶段（「点击留痕（逐次）」一节）的事。</p>")
    return "".join(out)


def _kg_section(fr: FlowResult) -> str:
    """「界面跳转图谱」章节：界面之间怎么连、还剩什么没试、权利入口几步可达。

    ★ 与上一节「界面覆盖情况」的分工必须写清楚，否则两节会互相稀释：
      · 覆盖情况回答「走到了哪」——覆盖率的分母与缺口；
      · 本节回答「凭什么这么走」——每一屏是什么、哪些动作试过、哪些没试、
        去权利入口要几步、哪里断了。
      复核员判断"未发现"可不可信，两节要一起看：覆盖说明范围，图谱说明路径。
    ★ 数据全部来自**存档里的图**（`scan.result.json` 的 `kgraph`），渲染时不重算：
      重算会拿到"存档里的图"与"当前代码"两套口径，同一份存档隔天重渲染就变数。
    """
    kg = dict(fr.kgraph or {})
    nodes = list(kg.get("nodes") or [])
    if not kg or not nodes:
        return ""
    st = dict(kg.get("stats") or {})
    targets = list(kg.get("targets") or [])
    names = dict(kg.get("names") or {})

    rows = [
        ("语义界面（合并后）", "%d 个" % int(st.get("nodes") or 0)),
        ("已探明跳转", "%d 条（点过并观测到落点）" % int(st.get("edges") or 0)),
        ("未探索动作", "%d 个" % int(st.get("explore") or 0)),
        ("死点 / 陷阱",
         "%d 个 / %d 个（死点=点了没反应；陷阱=点了崩溃或跳出 App）"
         % (int(st.get("dead") or 0), int(st.get("traps") or 0))),
    ]
    if st.get("merges"):
        rows.append(("结构指纹合并",
                     "%d 次（同一界面因列表滚动/内容变化产生多个结构指纹，已归并为"
                     "同一语义节点）" % int(st["merges"])))
    if fr.ai_guided or fr.ai_free:
        rows.append(("AI 遍历参与度",
                     "图引导 %d 步 / 自由规划 %d 步%s"
                     % (fr.ai_guided, fr.ai_free,
                        "（图引导=只在当前界面的有限动作里选择；自由规划=结构树无可点"
                        "元素时看截图决定）" if fr.ai_guided else "")))
    body = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _rich(v))
                   for k, v in rows)
    out = ["<table class='meta'>%s</table>" % body]

    # ---- 语义界面表 ----
    trs = []
    for n in sorted(nodes, key=lambda x: (x.get("depth") or 0,
                                          int(str(x.get("nid") or "N0")[1:] or 0)))[:16]:
        nid = str(n.get("nid") or "")
        title = "%s %s" % (nid, n.get("role") or "")
        desc = (n.get("desc") or "").strip()
        if desc and desc != (n.get("role") or ""):
            title += "·" + desc[:20]
        todo = list(n.get("todo") or [])
        todo_txt = "、".join(((t.get("label") or "")[:14] or "无文字容器")
                             for t in todo[:4]) or "—"
        risk = []
        if n.get("dead"):
            risk.append("死点：%s" % "、".join((x or "")[:10]
                                             for x in list(n["dead"])[:2]))
        if n.get("traps"):
            risk.append("陷阱：%s" % "、".join((x or "")[:10]
                                             for x in list(n["traps"])[:2]))
        trs.append("<tr><td>%s</td><td style='text-align:center'>%d</td>"
                   "<td style='text-align:center'>%d</td><td>%s</td><td>%s</td></tr>"
                   % (_esc(title[:40]), int(n.get("depth") or 0),
                      int(n.get("visits") or 0), _esc(todo_txt),
                      _esc("；".join(risk) or "—")))
    if trs:
        out.append("<p class='muted'>本轮实际走出的界面图谱（按层级排序，"
                   "「未试入口」是这些界面上还没点过的动作）：</p>"
                   "<table class='cover'><tr><th>界面</th>"
                   "<th style='width:52px'>层级</th><th style='width:52px'>到访</th>"
                   "<th style='width:200px'>未试入口</th>"
                   "<th style='width:190px'>风险</th></tr>" + "".join(trs) + "</table>")

    # ---- 权利入口的可达性 ----
    if targets:
        hit = [t for t in targets if t.get("found")]
        trs = []
        for t in targets:
            if t.get("found"):
                if t.get("blocked"):
                    state, note = "已定位·未点击", "被安全规则拦截（注销/退出类不执行）"
                elif t.get("tried"):
                    state, note = "已定位·已进入", "入口已点击并观测到落点"
                else:
                    state, note = "已定位·未进入", "入口在本轮界面上出现过，但未轮到点击"
            else:
                state, note = "未覆盖", "本轮未走到该入口所在界面"
            trs.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                       % (_esc(t.get("name") or ""), _esc(state),
                          _esc(t.get("where") or "—"),
                          _esc(((t.get("label") + "｜") if t.get("label") else "")
                               + note)))
        out.append("<p class='muted'>权利行使入口在图谱上的可达情况（共 %d 类，"
                   "本轮定位到 %d 类）：</p>"
                   "<table class='cover'><tr><th style='width:150px'>权利入口</th>"
                   "<th style='width:96px'>图谱状态</th><th style='width:150px'>所在界面</th>"
                   "<th>说明</th></tr>" % (len(targets), len(hit))
                   + "".join(trs) + "</table>")

    out.append("<p class='muted'><strong>本节口径：</strong>「未覆盖」只表示本轮遍历"
               "没有走到该界面，<strong>不代表 App 未提供该功能</strong>；"
               "「已定位·未进入」表示入口确实出现在屏幕上，但没有轮到执行"
               "（预算耗尽或属于不可点击类别）。节点合并只发生在同一 Activity、"
               "同一导航状态且结构文字高度重合的界面之间，合并记录见存档 "
               "<code>kgraph.merges</code>。</p>")
    return "".join(out)


def _coverage_table(fr: FlowResult) -> str:
    rows = []
    for r in fr.rows:
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (r.num, _esc(r.title[:46]), _esc(STATE_LABELS.get(r.state, r.state)),
               _esc(r.auto or ""), _esc("、".join(r.phases or []))))
    return ("<table class='cover'><tr><th style='width:38px'>项</th><th>检测项</th>"
            "<th style='width:88px'>结论</th><th style='width:52px'>自动化</th>"
            "<th style='width:90px'>来源阶段</th></tr>" + "".join(rows) + "</table>")


def render(fr: FlowResult, flow: Optional[Dict[str, Any]] = None,
           *, app_name: str = "", version: str = "", source_market: str = "",
           operator: str = "", published_at: str = "") -> str:
    flow = flow or load_checkflow()
    footer = flow.get("footer") or {}
    meta = flow.get("meta") or {}
    stds = meta.get("standards") or []

    name = app_name or fr.app_name or fr.package or "XXX"
    ver = version or fr.version or ""
    st = fr.stats()

    # 违规项：fail 与 suspect 都算，suspect 明确标注需人工复核
    problems = [r for r in fr.rows if r.state in (FAIL, SUSPECT)]
    passed = [r for r in fr.rows if r.state == PASS]
    skipped = [r for r in fr.rows if r.state == NOT_TESTED]

    # 模板原文：依据《个人信息保护法》《App违法违规…认定方法》等法律法规和
    # 《GB/T 42582-2023…》等标准。standards 里已经自带书名号，
    # 这里再套一层就会变成「《《个人信息保护法》》」。
    def _w(s: str) -> str:
        s = (s or "").strip()
        return s if s.startswith("《") else "《%s》" % s
    if len(stds) >= 3:
        laws = "%s等法律法规和%s等标准" % ("、".join(_w(s) for s in stds[:2]), _w(stds[2]))
    else:
        laws = "%s等法律法规和标准" % "、".join(_w(s) for s in stds)
    if getattr(fr, "app_start_failed", False):
        # 前提没成立时，"发现违规 / 未发现违规"都是不成立的表述 ——
        # 只能如实说"没测成，原因见上"。
        # ★ 也不能一律说"崩溃"（小盒课堂 2026-10-27）：它没有崩溃信号，
        #   是被 SELinux 拦下 execmod 后进程反复重建。按实测状态分开写。
        _rh0 = getattr(fr, "run_health", {}) or {}
        _p0 = _rh0.get("app_start_probe") or {}
        if _p0.get("started") is False:
            _why0 = ("但<b>目标应用在检测设备上无法启动</b>（不注入直接启动时同样无法"
                     "稳定存活，现场证据见「目标应用启动状态」一节）")
        elif str(_rh0.get("state") or "") in ("no_ui", "no_dump"):
            _why0 = ("但<b>目标应用的界面无法读取</b>（进程在前台，结构树导不出内容，"
                     "见「目标应用启动状态」一节）")
        else:
            _why0 = ("但<b>目标应用在检测设备上未能正常启动</b>"
                     "（进程反复退出，崩溃证据见上一节）")
        lead = ("依据%s对%s App 开展检测，%s。本轮未取得任何运行期行为数据，"
                "故不对合规性作出结论；全部 %d 个检测项标注为「跳过未测」，"
                "需在应用可正常启动的环境下重测。"
                % (laws, _esc(name), _why0, st["total"]))
    elif problems:
        lead = ("依据%s对%s App违法违规收集使用个人信息问题情况进行分析，"
                "发现其存在如下违规项：" % (laws, _esc(name)))
    else:
        lead = ("依据%s对%s App违法违规收集使用个人信息问题情况进行分析，"
                "本次自动化检测未发现明确的违规项（其中 %d 项因证据不足跳过未测，需人工补充检测）。"
                % (laws, _esc(name), len(skipped)))

    # 截图按编号回查（row.shots 只存 index，不存 base64）。
    # 图直接内嵌到各个问题项里 —— 同一张图被多项引用就重复内嵌，
    # 这是用户明确要的：复核时不必来回翻附录对编号。
    shot_map: Dict[int, Dict[str, Any]] = {
        int(it.get("index")): it for it in (fr.shots or [])
        if it.get("index") is not None
    }

    parts: List[str] = []
    if problems:
        # 这批里多数是「疑似」，标题写成"发现的问题"会让复核的人误以为都已定论。
        #
        # ★ 「确证 / 疑似」必须按**置信度**拆，不能按 state 拆。
        #   真机实测（以观书法 mbsf6）：Q006 的 state=FAIL 但 confidence=疑似，
        #   按 state 数就被算进"确证"，标题写着"确证 1 项"，
        #   可那一项的结论正文白纸黑字写着"疑似…需人工复核" —— 自相矛盾。
        #   判定的权威口径是 `ItemState.confidence`（确证/疑似），
        #   没有置信度时退回按 state：FAIL 当确证、SUSPECT 当疑似。
        def _conf(r) -> str:
            c = (getattr(r, "confidence", "") or "").strip()
            if c:
                return c
            return "确证" if getattr(r, "state", None) == FAIL else "疑似"
        n_sure = sum(1 for r in problems if _conf(r) == "确证")
        parts.append(
            "<h3 style='font-size:15px;margin:18px 0 6px'>一、问题项（%d 项，其中确证 %d、疑似待复核 %d）</h3>"
            % (len(problems), n_sure, len(problems) - n_sure))
        parts.extend(_item_block(r.to_dict(), fr.package or "", shot_map) for r in problems)
    if skipped:
        parts.append("<h3 style='font-size:15px;margin:26px 0 6px'>二、跳过未测项（%d 项）</h3>"
                     % len(skipped))
        parts.append("<p class='muted'>以下项目本次检测未获取到判定所需的证据，不做结论，需人工补充检测：</p>")
        parts.extend(_item_block(r.to_dict(), fr.package or "", shot_map) for r in skipped)
    if passed:
        parts.append("<h3 style='font-size:15px;margin:26px 0 6px'>%s、未发现问题项（%d 项）</h3>"
                     % ("三" if skipped else "二", len(passed)))
        parts.extend(_item_block(r.to_dict(), fr.package or "", shot_map) for r in passed)

    kpis = (
        "<div class='kpis'>"
        "<div class='kpi f'><div class='kpi-v'>%d</div><div class='kpi-l'>发现问题</div></div>"
        "<div class='kpi s'><div class='kpi-v'>%d</div><div class='kpi-l'>疑似待复核</div></div>"
        "<div class='kpi p'><div class='kpi-v'>%d</div><div class='kpi-l'>未发现问题</div></div>"
        "<div class='kpi n'><div class='kpi-v'>%d</div><div class='kpi-l'>跳过未测</div></div>"
        "</div>" % (st["fail"], st["suspect"], st["pass"], st["not_tested"])
    )

    coverage_note = (
        "本次共检测报告模板 %d 个检测项：发现问题 %d 项、疑似 %d 项、未发现问题 %d 项、跳过未测 %d 项。"
        "「跳过未测」表示本次流程未取得该项判定所需的证据，并非该项合规。"
        % (st["total"], st["fail"], st["suspect"], st["pass"], st["not_tested"]))

    tpl = Template(_TPL.read_text(encoding="utf-8"))
    return tpl.safe_substitute(
        title="%s App 个人信息保护合规检测报告" % _esc(name),
        app_name=_esc(name),
        version=_esc(ver),
        source_market=_esc(source_market or fr.source_market or "—"),
        operator=_esc(operator or fr.operator or "—"),
        published_at=_esc(published_at or fr.published_at or "—"),
        static_table=_static_table(fr),
        flow_table=kpis + _flow_table(fr, flow),
        app_status=_app_status(fr),
        lead=lead,
        items_html="".join(parts) if parts else "<p class='muted'>本次未输出检测项结论。</p>",
        coverage_note=coverage_note,
        coverage_table=_coverage_table(fr),
        click_trail=_click_trail(fr),
        landing_section=_landing_section(fr),
        review_materials=_review_materials(fr),
        advise=_esc(footer.get("advise", "").strip()),
        issuer=_esc(footer.get("issuer", "")),
    )


__all__ = ["render"]
