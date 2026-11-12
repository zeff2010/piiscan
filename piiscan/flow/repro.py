"""问题复现的判据与判定：把"第二轮的采集"和"第一轮的结论"对上。

**为什么要单独一个模块**

    `p7_repro()` 原本只搭了架子：列一遍待复现项，然后写"本次未执行"。
    原因不是偷懒，而是**复现在架构上跨了两层**：
      · 第二轮采集必须动设备（清数据、重装、再遍历）—— 那是 collector 的事；
      · 复现成不成立是判定 —— 那是 flow 的事。
    把两者揉在一起，flow 就会去碰 adb，离线重渲染（`--from-result`）也就废了。

    所以这里只做判定：拿到第二轮的 ScanResult，对着第一轮的结论逐项问
    "这一条在重跑里又出现了吗"。谁去跑第二轮由调用方决定（sop_job 传
    `repro_runner` 进来）。

**三种结论，不能只有两种**

    · 已复现 —— 同一判据在重跑中再次出现，按原状态保留（确证）。
    · 未复现 —— 重跑**正常完成**、该条目的判据可对照，但没再出现。
      按"疑似"处理：可能是偶发、可能依赖特定账号/设备状态，需要人工复核。
    · 未能判定 —— 重跑没完成 / 一条事件都没采到 / 判据无法落到可重放的粒度。
      **状态不动**，如实写"本轮未能完成复现"。

    第三类必须单独存在。把"没跑成"算成"未复现"，等于因为工具没电而宣布
    发现的问题不成立 —— 这比不复现更危险，因为它看起来像做过验证。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from . import compare as CMP
from . import permissions as PERM

# 判断一个条目属于哪一类复现判据
_EVENT_KINDS = ("frida", "stack")
_POLICY_KINDS = ("policy", "doc", "manifest")

# API / 标识符形态的 token：够长且带点，避免把 "SDK"、"App" 这种词当成判据
_API_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$.]{7,}")


# ---------------------------------------------------------------- 观测集
def _post_events(scan: Any) -> List[Any]:
    """同意后的有效事件。复现只认同意之后 —— 未同意阶段是另一项结论。"""
    return [e for e in (getattr(scan, "events", None) or [])
            if not getattr(e, "before_consent", False)]


def observe(scan: Any) -> Dict[str, Set[str]]:
    """把一轮采集压成可比较的观测集。

    压成集合而不是保留全量：复现要回答的是"还出现吗"，不是"出现几次"。
    次数本身就不可复现（每轮点击路径不同），拿次数比会得出"没复现"的假结论。
    """
    sm = CMP._signal_map()
    idx = CMP.build_signal_index(sm)
    vocab = {v["id"]: v for v in CMP.pi_vocab(sm)}

    apis: Set[str] = set()
    pis: Set[str] = set()
    members: Set[str] = set()
    for e in _post_events(scan):
        api = (getattr(e, "api", "") or "").strip()
        if api:
            apis.add(api)
        hook = (getattr(e, "hook_id", "") or "").strip()
        if hook:
            apis.add(hook)
        pid, mem, _sg = CMP.event_pi(e, idx, vocab, sm)
        if pid:
            pis.add(pid)
            if mem:
                members.add(mem)

    perms: Set[str] = set()            # 证据完整、且当时未告知目的
    perms_explained: Set[str] = set()  # 证据完整、且当时可见用途说明
    perms_all: Set[str] = set()        # 申请过（含证据不足的）
    for s in (getattr(scan, "perm_scenes", None) or []):
        name = (s.get("perm") or s.get("perm_raw") or "").strip()
        if not name:
            continue
        perms_all.add(name)
        # ★ 以存档为准：采集时已算出的 purpose 直接沿用（那是当时看着界面
        #   得出的结论）；只有老存档缺这个字段才重算。
        #   并且 `purpose == ""`（弹窗前那一屏没取到文字）**不算未告知** ——
        #   把空当 none 等于把"证据不足"读成"未告知"，方向上是加责：
        #   复现轮明明什么都没看清，也会被判成"同一问题再次出现"。
        p = str(s.get("purpose") or "")
        if not p:
            p = str(PERM.judge_scene(s).get("purpose") or "")
        if p == "none":
            perms.add(name)
        elif p in ("dialog", "pre"):
            perms_explained.add(name)

    cap = getattr(scan, "policy_capture", None) or {}
    # 采集侧的正文放在 bestText（最优一次抓取），离线存档里也可能是 text。
    # 两个都认：只认一个的话，重渲染出来的"政策获取结论"会和采集端不一致。
    txt = str(cap.get("bestText") or cap.get("text") or "")
    policy = {
        "outcome": str(cap.get("outcome") or ""),
        "has_text": "1" if len(txt) > 60 else "0",
    }

    return {"apis": apis, "pis": pis, "members": members, "perms": perms,
            "perms_all": perms_all, "perms_explained": perms_explained,
            "policy": policy,
            "n_events": len(_post_events(scan)),
            # 复现轮的路径重放结果（首轮为空 dict）。判定要用它区分
            # "走完了但判据没再出现"和"根本没走到那一步" —— 后者不能算未复现。
            "replay": dict(getattr(scan, "ui_replay", None) or {})}


# ---------------------------------------------------------------- 判据
def _texts_of(it: Any) -> List[str]:
    """一个条目的全部文字材料（证据标题/摘要/事实值/描述）。"""
    out: List[str] = []
    for ev in (getattr(it, "evidence", None) or []):
        out.append(str(getattr(ev, "title", "") or ""))
        out.append(str(getattr(ev, "detail", "") or ""))
        data = getattr(ev, "data", None)
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, str):
                    out.append(v)
                elif isinstance(v, (list, tuple)):
                    out.extend(str(x) for x in v[:20])
    for row in (getattr(it, "facts", None) or []):
        out.extend(str(x) for x in row if isinstance(x, (str, int, float)))
    out.append(str(getattr(it, "desc", "") or ""))
    out.append(str(getattr(it, "reason", "") or ""))
    return [t for t in out if t]


def _pi_name_index() -> Dict[str, str]:
    """个人信息类型的中文名 → id。用于从文字里认出"通讯录""位置信息"。"""
    sm = CMP._signal_map()
    out: Dict[str, str] = {}
    for v in CMP.pi_vocab(sm):
        name = (v.get("name") or "").strip()
        if name:
            out[name] = v["id"]
        for alias in (v.get("aliases") or []):
            a = str(alias).strip()
            if a:
                out[a] = v["id"]
    return out


def criteria(it: Any, obs1: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """从条目文字里抽出"可重放的判据"。

    抽不出东西是常态（比如 Q001 讲的是"隐私政策总体质量"），
    那种条目本来就无法用运行期事件复现 —— 抽不出就返回空集，
    由 `judge()` 归到"未能判定"，而不是硬凑一个判据出来。
    """
    texts = _texts_of(it)
    blob = " ".join(texts)
    apis = {t for t in _API_RE.findall(blob) if t in obs1["apis"]}
    pis = {pid for name, pid in _pi_name_index().items()
           if name and name in blob and pid in obs1["pis"]}
    # 对照哪个权限：取"本轮申请过的权限"里、在条目文字中出现过的那个。
    # 不用 obs1["perms"]（只含证据完整的未告知场景）—— 首轮那次弹窗若没取到
    # 弹窗前界面，权限名就落不进 perms，判据会被抽成空集，整项退化成
    # "未能判定"。对照对象和"当时有没有告知"是两件事，不该绑在一起。
    perms = {p for p in obs1.get("perms_all", set()) if p and p in blob}
    return {"apis": apis, "pis": pis, "perms": perms}


def _kind_of(it: Any) -> str:
    kinds = {str(getattr(ev, "kind", "") or "") for ev in (getattr(it, "evidence", None) or [])}
    if kinds & set(_EVENT_KINDS):
        return "event"
    if "ui" in kinds:
        return "perm"
    if kinds & set(_POLICY_KINDS):
        return "policy"
    return ""


def _sdk_gap_verdict(fr: Any, scan2: Any) -> Optional[Dict[str, Any]]:
    """Q007 类（清单未列明 / 声明范围不足）的复现判据：按 SDK 名 + 信息类型比对第二轮。

    为什么不能用通用的事件 token 比对：
      Q007 的证据文字写的是「穿山甲广告SDK 采集了设备标识但清单未列明」，
      里面没有可执行的 API 名；而 API 名恰恰是通用比对唯一的抓手。
      靠文字猜 API 会得出"未能判定"，而这一项恰恰是最该被复现的一类。

    判据（与 `declaration.py` 的口径一致）：
      第二轮里**同一个 SDK 仍在采同一类个人信息** → 已复现；
      第二轮该 SDK 一条都没采 → 未复现；
      第二轮没有可归属的 SDK 事件 → 未能判定。
    """
    m = getattr(fr, "sdk_matrix", None) or {}
    gaps = list(m.get("gap_sdk") or [])
    if not gaps:
        return None
    try:
        from . import declaration as DCL
        got = DCL.observed_inventory(getattr(scan2, "events", None) or [],
                                     getattr(fr, "package", "") or "")
    except Exception:
        return None
    # observed_inventory 返回 {"by_key": {...}, "vocab": {...}}，按 key 取实际的分桶。
    buckets = (got.get("by_key") if isinstance(got, dict) else None) or {}

    seen = [(str(rec.get("name") or ""), rec) for rec in buckets.values()
            if rec.get("kind") == "sdk"]
    # 有多少事件能完成归因（不管归到 App 还是 SDK）。这个数用来区分两种情况：
    #   · 复现轮采到了、但该 SDK 没出现  → 未复现
    #   · 复现轮什么都没采到            → 未能判定（不是"没复现"）
    attributed = sum(1 for rec in buckets.values()
                     if rec.get("kind") in ("sdk", "app"))
    if not attributed:
        return {"reproduced": None, "how": "清数据重跑一轮",
                "note": "复现轮没有任何能完成归因的采集事件，无法对照"}

    hits, miss = [], []
    for g in gaps:
        name = str(g.get("name") or "")
        want = {p.get("pi") for p in (g.get("missing_pi") or []) if p.get("pi")}
        rec = None
        for nm, r in seen:
            if nm and name and (nm == name or nm in name or name in nm):
                rec = r
                break
        if rec is not None and (not want or want & set(rec.get("pi") or {})):
            hits.append(name)
        else:
            miss.append(name)
    if hits:
        return {"reproduced": True,
                "how": "清除应用数据后重跑一轮，同一 SDK 仍在采集同一类个人信息",
                "note": "再次出现：%s" % "、".join(hits[:6])}
    return {"reproduced": False,
            "how": "清除应用数据后重跑一轮，未再观测到该 SDK 采集同类信息",
            "note": "复现轮未再出现：%s（复现轮可归属 SDK：%s）"
                    % ("、".join(miss[:6]),
                       "、".join(nm for nm, _ in seen[:6]) or "无")}


# ---------------------------------------------------------------- 判定
def _replay_gap(obs2: Dict[str, Any]) -> str:
    """复现轮路径没走完时的说明；走完了（或没启用重放）返回空串。

    ★ 这个判据为什么必须存在
      改成"按首轮路径重放"之后，复现轮**应该**走到与首轮同一批界面。
      但中途可能漂移（元素改版、登录态不同）、到时长上限、或 App 退出，
      后面那些步骤根本没执行。此时"判据没再出现"只说明"没走到"，
      不等于"问题不存在"。把它算成未复现会把 fail 降成 suspect ——
      用"工具没走完"给被测应用减责，是最不该出现的一类假阴性。
    """
    r = obs2.get("replay") or {}
    if not r or r.get("complete"):
        return ""
    total = int(r.get("total") or 0)
    done = int(r.get("done") or 0)
    why = (str(r.get("stopped") or "") or
           ("路径漂移" if r.get("drift") else
            ("到时长上限" if r.get("timed_out") else "其余步骤未能重放")))
    return "复现轮路径未走完（%d/%d 步，%s）" % (done, total, why)


def path_gap(scan1: Any, scan2: Any, obs2: Dict[str, Any]) -> str:
    """复现轮"没走到"的说明；真正走到并走完了返回空串。

    两种"没走到"，必须一并挡住：
      · **重放中途停了**（漂移 / 超时 / 应用退出）→ `_replay_gap` 的摘要；
      · **压根没进入重放**：首轮记了路径，复现轮却一次都没点 —— 典型原因是
        首启阶段把采集时长用完了（mbsf15：找政策入口点了 13 个采样点、花
        203 秒，120 秒预算归零，一步没重放）。不单独挡这一道，报告就会写着
        "按首轮路径重放"而实际一步没走。
    """
    gap = _replay_gap(obs2)
    if gap:
        return gap
    if obs2.get("replay"):
        return ""
    p1 = getattr(scan1, "ui_path", None) or []
    if p1 and int(getattr(scan2, "ui_taps", 0) or 0) == 0:
        return ("复现轮未进入路径重放（首轮记录了 %d 步，复现轮点击 0 次，"
                "首启阶段已用完整轮采集时长）" % len(p1))
    return ""


def judge(fr: Any, scan1: Any, scan2: Any,
          log=lambda *_a, **_k: None) -> List[Dict[str, Any]]:
    """逐项判定复现结果。不修改 fr，只返回结果列表。

    scan1 是第一轮采集（判据来源），scan2 是清数据重跑的那一轮。
    scan2 为 None 表示"没跑成"，全部如实标成未能判定 —— 不猜。
    """
    items = getattr(fr, "items", None) or {}
    targets = [(qid, it) for qid, it in sorted(items.items())
               if getattr(it, "state", "") in ("fail", "suspect")]

    if scan2 is None:
        return [{"qid": qid, "title": getattr(it, "title", ""), "reproduced": None,
                 "result_label": "未能判定", "how": "未执行第二轮采集",
                 "note": "本轮未执行复现采集，结论状态保持不变"}
                for qid, it in targets]

    obs1 = observe(scan1) if scan1 is not None else {
        "apis": set(), "pis": set(), "members": set(), "perms": set(),
        "policy": {}, "n_events": 0}
    obs2 = observe(scan2)
    sdk_v = _sdk_gap_verdict(fr, scan2)
    gap = path_gap(scan1, scan2, obs2)
    if gap:
        log("[复现] %s —— 未走完的步骤不能算作「未复现」" % gap)
    out: List[Dict[str, Any]] = []
    for qid, it in targets:
        kind = _kind_of(it)
        crit = criteria(it, obs1)
        # 这条结论有没有用到政策/静态证据。有的话，在"运行期判据抽不出来"时
        # 退回政策获取结论做对照 —— Q007 这类"政策没抓到 ⇒ 无法核对第三方"
        # 的结论就是这样：它不靠某个 API 重现，靠的是政策能不能拿到。
        has_policy = any(str(getattr(ev, "kind", "") or "") in _POLICY_KINDS
                         for ev in (getattr(it, "evidence", None) or []))
        rec = _judge_one(qid, it, kind, crit, obs1, obs2, sdk_v, has_policy,
                         replay_gap=gap)
        if rec.get("reproduced") is None:
            log("[复现] %s 未能判定：%s" % (qid, rec.get("note") or ""))
        else:
            log("[复现] %s %s" % (qid, "已复现" if rec["reproduced"] else "未复现"))
        out.append(rec)
    return out


def _judge_one(qid: str, it: Any, kind: str, crit: Dict[str, Set[str]],
               obs1: Dict[str, Set[str]], obs2: Dict[str, Set[str]],
               sdk_v: Optional[Dict[str, Any]] = None,
               has_policy: bool = False,
               replay_gap: str = "") -> Dict[str, Any]:
    """单项判定的口径集中在这一处。

    `replay_gap` 非空表示复现轮的路径没走完：此时**不能**判"未复现"，
    因为判据没出现可能只是"没走到那一步"。只有运行期事件/权限两类受影响 ——
    政策正文的获取发生在遍历之前，与路径走没走完无关。
    """
    title = getattr(it, "title", "") or ""
    base = {"qid": qid, "title": title, "reproduced": None,
            "result_label": "未能判定", "how": "", "note": ""}

    # ① 第三方声明缺口（Q007）：优先用按 SDK 的判据。
    #    这一类的证据文字里没有 API 名，走通用 token 比对必然落到"未能判定"。
    if sdk_v is not None and ("第三方" in title or "列明" in title):
        rep = sdk_v.get("reproduced")
        if rep is False and replay_gap:
            # "这一轮没采到该 SDK" 可能是没走到触发它的功能，不是它不采了。
            base.update(note="%s，无法确认该 SDK 是否仍会采集" % replay_gap)
            return base
        base.update(reproduced=rep, how=sdk_v.get("how") or "",
                    note=sdk_v.get("note") or "",
                    result_label=("已复现" if rep is True else
                                  ("未复现" if rep is False else "未能判定")))
        return base

    hit_api = crit["apis"] & obs2["apis"]
    hit_pi = crit["pis"] & obs2["pis"]
    hit_perm = crit["perms"] & obs2["perms"]

    if kind in ("event", "", "perm") and (crit["apis"] or crit["pis"]):
        if hit_api or hit_pi:
            base.update(reproduced=True, result_label="已复现",
                        how="清除应用数据后按首轮路径重放，同一调用/同一类信息再次被采集",
                        note="再次出现：%s" % "、".join(sorted(hit_api | hit_pi))[:120])
        elif obs2["n_events"] == 0:
            base.update(note="复现轮未采到任何同意后事件，本轮无法对照")
        elif replay_gap:
            # 路径没走完：判据没出现可能只是"没走到"，不能算未复现。
            base.update(note="%s，无法确认判据是否还会出现；结论状态保持不变"
                             % replay_gap)
        else:
            base.update(reproduced=False, result_label="未复现",
                        how="清除应用数据后按首轮路径重放，判据未再出现",
                        note="复现轮共采到 %d 条同意后事件，但未包含本轮判据（%s）"
                             % (obs2["n_events"],
                                "、".join(sorted(crit["apis"] | crit["pis"]))[:120]))
        return base

    if kind == "perm" or crit["perms"]:
        if hit_perm:
            base.update(reproduced=True, result_label="已复现",
                        how="清数据后按首轮路径重放，再次申请同一权限且仍未同步告知目的",
                        note="再次出现：%s（未同步告知）" % "、".join(sorted(hit_perm)))
        elif not crit["perms"]:
            # ★ 抽不出"该对照哪个权限"就不判未复现。
            #   没抓到判据时，复现轮里**任何**一次无关的权限申请都会被当成
            #   "又申请了但这次说明了目的"，从而把 fail 降成 suspect ——
            #   这是拿别的权限申请给本项减责。宁可未能判定。
            base.update(note="本项未能抽出可对照的权限判据（证据文字里没有具体权限名），"
                             "复现轮不做对照")
        elif not (crit["perms"] & obs2.get("perms_all", set())):
            # ★ 本项涉及的那个权限，这一轮**压根没再申请** —— 不能算未复现。
            #   Android 会记住"拒绝过"，同一个权限第二次常常不再弹窗；
            #   复现轮清数据重置了 App，但系统侧的拒绝记录不一定复位。
            #   没弹窗等于没取到判据，不是"问题消失了"。
            base.update(note="复现轮未再申请本项涉及的权限（%s），未能取得对照 ——"
                             "系统可能已记住此前的拒绝而不再询问，不能据此认定问题消失"
                             % "、".join(sorted(crit["perms"])))
        elif replay_gap:
            base.update(note="%s；复现轮记录的权限申请：%s，无法确认未告知申请是否还会出现"
                             % (replay_gap, "、".join(sorted(obs2["perms_all"]))))
        elif crit["perms"] & obs2.get("perms_explained", set()):
            # 同一权限这次又申请了，而且申请时的弹窗/前屏能看到目的说明 ——
            # 这才是真正的"没再复现"。
            # 判据必须是「同一权限 + 证据完整」，不能是「这一轮申请过任何权限」：
            # 后者会把别的权限（甚至无关功能）拿来给本项减责。
            base.update(reproduced=False, result_label="未复现",
                        how="清数据后按首轮路径重放，同一权限再次申请时可见用途说明",
                        note="复现轮再次申请了 %s，申请时可见用途说明：%s"
                             % ("、".join(sorted(crit["perms"] & obs2["perms_all"])),
                                "、".join(sorted(crit["perms"] & obs2["perms_explained"]))))
        else:
            # 同一权限又申请了，但弹窗前那一屏没取到文字 —— 证据不足，
            # 既不能说"又没告知"，也不能说"这次告知了"。
            base.update(note="复现轮再次申请了 %s，但申请前的界面文字未取得，"
                             "无法判断这次是否同步告知" %
                             "、".join(sorted(crit["perms"] & obs2["perms_all"])))
        return base

    if kind == "policy" or (has_policy and not (crit["apis"] or crit["pis"])):
        k1 = (obs1.get("policy") or {})
        k2 = (obs2.get("policy") or {})
        if not k1.get("outcome") or not k2.get("outcome"):
            base.update(note="两轮中至少一轮未记录政策获取结论，无法对照")
            return base
        # ★ 首轮拿到了正文、复现轮没拿到 ≠ 政策变了。
        #   抓正文要过 WebView，网络抖动或页面停在"请阅读隐私政策"的提示上
        #   都会让这一轮只记 notice_only（mbsf15 实测：首轮 full/9219 字，
        #   复现轮 notice_only/0 字）。那不是"问题没复现"，是"这次没取到"。
        if k1.get("has_text") == "1" and k2.get("has_text") != "1":
            base.update(note="复现轮未取得政策正文（第一轮为 %s），无法判断政策是否变化；"
                             "这不是「未复现」，问题状态保持不变" % k1.get("outcome"))
            return base
        same = (k1.get("outcome") == k2.get("outcome")
                and k1.get("has_text") == k2.get("has_text"))
        base.update(reproduced=same,
                    result_label="已复现" if same else "未复现",
                    how="清除应用数据后重新获取隐私政策正文（这一步发生在遍历之前，与路径重放无关）",
                    note=("两轮结论一致：%s" % k2.get("outcome")) if same else
                         ("第一轮 %s，复现轮 %s" % (k1.get("outcome"), k2.get("outcome"))))
        return base

    base.update(note="该结论来自文本比对（政策原文 / 静态清单），"
                     "本轮复现只重放运行期行为，无法改变这类判断；"
                     "如需复核请对照上一节的政策原文与 SDK 清单逐条核对")
    return base


def apply(fr: Any, results: List[Dict[str, Any]],
          log=lambda *_a, **_k: None) -> None:
    """把复现结果写进 fr，并对"未复现"的项做降级。

    ★ 只降不升
      复现成功不改状态（本来就该是确证）；
      未复现把 fail 降成 suspect 并写明原因 —— 结论动词随之从"认定为"
      变成"疑似…需人工复核"，这是报告层的既有规则，这里只改状态。
      "未能判定"不动状态，但要写清为什么没复现成。
    """
    fr.repro_results = results
    by_qid = {r.get("qid"): r for r in results}
    for qid, r in by_qid.items():
        it = (getattr(fr, "items", None) or {}).get(qid)
        if it is None:
            continue
        if r.get("reproduced") is False and getattr(it, "state", "") == "fail":
            it.state = "suspect"
            it.confidence = "疑似"
            extra = ("该项在清除数据重跑后未再次出现，按「疑似·需人工复核」处理：%s"
                     % (r.get("note") or ""))
            it.reason = ((it.reason or "") + "；" + extra).strip("；")
            log("[复现] %s 降级为疑似（未复现）" % qid)


__all__ = ["observe", "criteria", "judge", "apply"]
