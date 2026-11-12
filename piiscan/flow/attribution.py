"""调用栈归因：这条采集行为到底是谁发起的。

报告里写「App 收集了 IMEI」，复核员第一个问题必然是：**是 App 自己读的，
还是它集成的某个 SDK 读的？** 两者整改方向完全不同 ——

  · App 自身   → 改代码、改权限申请时点、改业务必要性
  · 第三方 SDK → 升级/替换 SDK、延迟初始化、在隐私政策与共享清单里列明

判定口径也不一样：SDK 在 App 未告知用户的情况下取设备标识，对应的是
「未列明第三方 SDK / 未说明共享」这一支，不能笼统算成「App 未按规则处理」。
所以归属不是报告里的装饰，它是判定链的一部分。

## 判定方法

Android 的 `Throwable.getStackTrace()` 由内向外排列：`frames[0]` 是最深的
调用点（被 hook 的那个 API），往后是它的调用者。所以：

  **跳过框架帧后遇到的第一个帧 = 直接发起方**

框架帧（android.* / java.* / androidx.* / com.android.* …）要跳过，因为
`TelephonyManager.getDeviceId` 自身永远在栈顶，它只是被执行的方法，
不是"谁决定要读"。这与采集侧 `hooks/collector.js` 的 `FRAMEWORK_RE`
必须是同一套前缀 —— 两侧口径不一致会出现"采集时剔除了、报告里又算成 App"。

## 前缀匹配的两级

SDK 库（`reference/sdk_package/sdk.json`）里的前缀粒度并不均匀：
既有 `com.example.adsdk.core` 这种到类包的，也有 `com.example.adsdk` 这种只到根段。
真实栈里的类常常落在两者之间的空档（`com.example.adsdk.core.aq` 谁都不匹配）。
所以做两级：

  ① 最长前缀精确匹配 —— 命中即 `exact`，可写进报告
  ② 退化到前三段根（`com.umeng`），库里存在以该根开头的条目即算命中，
     但记为 `root`（弱匹配），报告措辞用"疑似"，不写成定论

第 ② 级有个必须的护栏：**根段与被测 App 的根段相同时不匹配**。
被测 App 若是 `com.tencent.mm`，栈里所有 `com.tencent.*` 都是它自己的类，
按根段退化会把 App 自己的代码判成腾讯的 SDK，等于把 App 的行为洗成第三方。
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# 与 `piiscan/hooks/collector.js` 的 FRAMEWORK_RE 保持完全一致。
# 除了 java/android 这些标准命名空间，还包含：
#   com.android.okhttp —— 系统内置 OkHttp，App 通过 HttpURLConnection 走到这里，
#                         归到"系统框架"而不是某个第三方网络库
#   org.chromium / com.android.webview —— WebView 内部
#   com.google.android.gms.common —— GMS 基础库，属系统服务层
FRAMEWORK_PREFIXES: Tuple[str, ...] = (
    "android.", "androidx.", "com.android.", "java.", "javax.",
    "kotlin.", "kotlinx.", "org.chromium", "com.android.webview",
    "dalvik.", "libcore.", "sun.", "org.json", "com.google.android.gms.common",
)

# 传输/序列化层：不承担采集逻辑，只是把数据送出去。
# 网络类调用栈的栈顶永远是 Http 客户端 —— 不跳过它，归因结论就会变成
# 「外发行为由 okhttp3 发起」，等于什么都没回答。
# 实测一条栈：okhttp3.RealCall.enqueue ← cj.mobile.p.f.a ← CJMobileAd.init
# ← App.registerAD，真正的发起方是「某广告 SDK」，跳过 OkHttp 才看得出来。
#
# 与 FRAMEWORK_PREFIXES 分开的原因：采集侧（hooks/collector.js）把 okhttp3
# 当业务帧保留是对的（说明这一轮确实有网络行为），只有归因时才需要穿过它。
TRANSPORT_PREFIXES: Tuple[str, ...] = (
    "okhttp3.", "okio.", "retrofit2.", "com.squareup.okhttp",
    "com.squareup.okio", "com.squareup.retrofit", "com.android.okhttp",
    "com.google.gson", "org.apache.http", "ch.qos.logback",
)

KIND_LABELS = {
    "app": "应用自身",
    "sdk": "第三方 SDK",
    "framework": "系统框架",
    "transport": "传输层",
    "unknown": "未能归属",
    "mixed": "应用自身与第三方 SDK",
}

# 报告里逐帧使用的短标记
FRAME_TAGS = {
    "app": "App",
    "sdk": "SDK",
    "framework": "框架",
    "transport": "通道",
    "unknown": "未知",
}


def frame_class(frame: str) -> str:
    """从一帧里取出类名：`com.x.Y.z(File.java:12)` → `com.x.Y.z`。"""
    s = str(frame or "").strip()
    if not s:
        return ""
    if s.startswith("at "):
        s = s[3:].strip()
    if s.startswith("<"):                      # <调用栈获取失败: …>
        return ""
    i = s.find("(")
    return (s[:i] if i > 0 else s).strip()


def is_framework(cls: str) -> bool:
    return any(cls.startswith(p) for p in FRAMEWORK_PREFIXES)


def is_transport(cls: str) -> bool:
    return any(cls.startswith(p) for p in TRANSPORT_PREFIXES)


def _skip_for_owner(kind: str) -> bool:
    """这两种帧不能当"发起方"：框架不是"谁决定要读"，传输层只是通道。"""
    return kind in ("framework", "transport")


def _root(cls: str, segs: int = 3) -> str:
    parts = cls.split(".")
    return ".".join(parts[:segs]) if len(parts) >= segs else ""


@lru_cache(maxsize=1)
def _sdk_table() -> Tuple[Tuple[str, str, str, str], ...]:
    """[(前缀, 名称, 类型, 厂商)]，按前缀长度降序 —— 最长前缀优先。

    库加载失败（缺文件/格式变）时返回空表，归因降级为"未能归属"，
    绝不让报告生成因为一个参考数据缺失而失败。
    """
    try:
        from .. import resources
        lib = resources.sdk_library()
    except Exception:
        return ()
    return tuple(sorted(lib, key=lambda t: len(t[0]), reverse=True))


@lru_cache(maxsize=1)
def _sdk_roots() -> Dict[str, Tuple[str, str, str]]:
    """根段 → (前缀, 名称, 厂商)，仅供弱匹配退化用。取每个根下最短的那个前缀。"""
    out: Dict[str, Tuple[str, str, str]] = {}
    for prefix, name, _typ, vendor in _sdk_table():
        r = _root(prefix)
        if not r or len(r.split(".")) < 2:
            continue
        cur = out.get(r)
        if cur is None or len(prefix) < len(cur[0]):
            out[r] = (prefix, name or prefix, vendor)
    return out


def classify_frame(frame: str, app_package: str = "") -> Dict[str, Any]:
    """给一帧定性。

    返回 `{kind, cls, tag, name, vendor, prefix, match}`：
      kind   app / sdk / framework / unknown
      match  exact（最长前缀命中）/ root（根段退化命中）/ ""（未命中）
    """
    cls = frame_class(frame)
    out: Dict[str, Any] = {"kind": "unknown", "cls": cls, "tag": FRAME_TAGS["unknown"],
                           "name": "", "vendor": "", "prefix": "", "match": ""}
    if not cls:
        return out
    if is_framework(cls):
        out.update(kind="framework", tag=FRAME_TAGS["framework"])
        return out
    if is_transport(cls):
        out.update(kind="transport", tag=FRAME_TAGS["transport"])
        return out

    app = (app_package or "").strip()
    # App 自身：完整包名前缀。**不做"同厂商"推断**（见模块注释的护栏说明）。
    if app and (cls == app or cls.startswith(app + ".")):
        out.update(kind="app", tag=FRAME_TAGS["app"])
        return out

    for prefix, name, _typ, vendor in _sdk_table():
        if len(prefix) < 4:
            continue
        if cls == prefix or cls.startswith(prefix + ".") or cls.startswith(prefix):
            out.update(kind="sdk", tag=FRAME_TAGS["sdk"], name=name or prefix,
                       vendor=vendor or "", prefix=prefix, match="exact")
            return out

    # ② 根段退化。护栏：根段与 App 包名的根段相同 → 不认（那是 App 自己的类）。
    root = _root(cls)
    if root and not (app and (app == root or app.startswith(root + "."))):
        hit = _sdk_roots().get(root)
        if hit:
            out.update(kind="sdk", tag=FRAME_TAGS["sdk"], name=hit[1],
                       vendor=hit[2] or "", prefix=hit[0], match="root")
            return out

    # 未收录的第三方库 / 混淆后的自研代码 —— 记下包名供人工判断，
    # 不硬塞进 app 或 sdk（错认主体比不认更糟）。
    out["name"] = _root(cls, 2)
    return out


def analyze_stack(frames: Sequence[str], app_package: str = "") -> Dict[str, Any]:
    """分析一条栈：谁是发起方、栈里都有谁。

    返回：
      owner             app / sdk / framework / unknown
      owner_label       人话，可直接进报告
      initiator         直接发起点的类名
      sdk               [{name, vendor, prefix, match}]（栈内出现的 SDK，按出现顺序去重）
      app_frames / sdk_frames / framework_frames / unknown_frames   各多少层
      sdk_called_by_app SDK 帧之后（更外层）出现 App 帧 → App 主动调用了这个 SDK
      frames            逐帧标注 [{tag, cls, kind, note}]
    """
    rows = [classify_frame(f, app_package) for f in (frames or []) if str(f or "").strip()]
    counts = {"app": 0, "sdk": 0, "framework": 0, "transport": 0, "unknown": 0}
    for r in rows:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1

    first = next((i for i, r in enumerate(rows) if not _skip_for_owner(r["kind"])), None)
    # 一个业务帧都没有时，要分清是"全是系统框架"还是"全是传输层" ——
    # 前者说明是系统自己干的，后者说明我们没抓全（可能是子线程没挂上 hook）。
    out: Dict[str, Any] = {
        "owner": (rows[first]["kind"] if first is not None else
                  ("transport" if counts.get("transport") else "framework")),
        "owner_label": "",
        "initiator": "" if first is None else rows[first]["cls"],
        "sdk": [],
        "app_frames": counts["app"], "sdk_frames": counts["sdk"],
        "framework_frames": counts["framework"], "transport_frames": counts["transport"],
        "unknown_frames": counts["unknown"],
        "sdk_called_by_app": False,
        "frames": [],
        "depth": len(rows),
    }

    seen_sdk: Dict[str, Dict[str, str]] = {}
    for r in rows:
        out["frames"].append({"tag": r["tag"], "cls": r["cls"], "kind": r["kind"],
                              "note": r["name"] if r["kind"] == "sdk" else ""})
        if r["kind"] == "sdk":
            # 同厂商同根包在库里常有多条（友盟统计 / 友盟+ 移动统计…），
            # 归并成一个实体，否则一条栈会显示"命中两个 SDK"。
            key = r["vendor"] or _root(r["prefix"])
            if not key:
                key = r["name"] or r["prefix"]
            if key and key not in seen_sdk:
                seen_sdk[key] = {"name": r["name"], "vendor": r["vendor"],
                                 "prefix": r["prefix"], "match": r["match"]}
    out["sdk"] = list(seen_sdk.values())

    # SDK 帧之后（更外层）出现 App 帧 = App 调了 SDK 的接口，SDK 在替 App 干活。
    # 这条对判定很关键：同一段 SDK 代码，App 主动调用与 SDK 自启动，
    # 整改建议完全不同（前者改调用时机，后者改 SDK 初始化策略）。
    if first is not None and rows[first]["kind"] == "sdk":
        out["sdk_called_by_app"] = any(r["kind"] == "app" for r in rows[first + 1:])

    out["owner_label"] = _owner_label(out, app_package)
    return out


def _owner_label(info: Dict[str, Any], app_package: str) -> str:
    kind = info.get("owner")
    if kind == "app":
        return "应用自身（%s）" % (app_package or "被测应用")
    if kind == "sdk":
        s = (info.get("sdk") or [{}])[0]
        name = display_name(s.get("name") or s.get("prefix") or "未命名 SDK")
        vendor = s.get("vendor") or ""
        weak = "（疑似，根包名匹配）" if s.get("match") == "root" else ""
        return "第三方 SDK（%s%s）%s" % (name, "，" + vendor if vendor else "", weak)
    if kind == "framework":
        # 纯框架栈没有业务帧，initiator 为空 —— 用栈顶那一帧说明"读的是什么"，
        # 否则报告里只剩一句"系统框架"，复核员不知道它到底读了什么。
        top = next((f.get("cls") for f in (info.get("frames") or []) if f.get("cls")), "")
        return "系统框架（%s，未发现应用或第三方代码的调用痕迹）" % (top or "调用点不明")
    if kind == "transport":
        top = next((f.get("cls") for f in (info.get("frames") or []) if f.get("cls")), "")
        return "仅网络传输层（%s），栈里没有应用或第三方代码的调用痕迹" % (top or "调用点不明")
    init = info.get("initiator") or ""
    return "未能归属（%s 不在已收录的 SDK 名单内，可能为自研代码或未收录的第三方库）" % (init or "调用点不明")


def summarize(stacks: Sequence[Sequence[str]], app_package: str = "") -> Dict[str, Any]:
    """多条栈汇总成一个结论（报告里"行为主体"那一行就用它）。

    多条栈可能指向不同主体（App 初始化时自己读一次、SDK 启动后又读一次）。
    这种情况不掩盖：按条数给出 `mixed`，并把每一方的条数与代表调用点都列出来。
    """
    infos = [analyze_stack(s, app_package) for s in (stacks or []) if s]
    infos = [i for i in infos if i.get("depth")]
    if not infos:
        return {"owner": "", "owner_label": "", "counts": {}, "sdk": [],
                "initiators": [], "total": 0, "text": ""}

    counts: Dict[str, int] = {}
    for i in infos:
        counts[i["owner"]] = counts.get(i["owner"], 0) + 1

    sdk_all: Dict[str, Dict[str, str]] = {}
    for i in infos:
        for s in i.get("sdk") or []:
            # 同一厂商同一根包在库里常有多条（友盟统计 / 友盟+ 移动统计…），
            # 它们是同一个 SDK 实体的不同条目。按 vendor+根包归并，
            # 否则报告会把一次采集写成"同时命中了两个 SDK"。
            key = s.get("vendor") or _root(s.get("prefix") or "")
            if not key:
                key = s.get("name") or s.get("prefix")
            if key:
                sdk_all.setdefault(key, s)
    initiators: List[str] = []
    for i in infos:
        if i.get("initiator") and i["initiator"] not in initiators:
            initiators.append(i["initiator"])

    # 纯框架/纯传输层的栈（整条都没有业务帧）不参与主体投票，单独计数 ——
    # 混在分母里会让"3 条 App 行为 + 1 条框架兜底"变成"4 条里只有 3 条算"，
    # 措辞上就说不清到底几条是应用行为。
    biz = {k: v for k, v in counts.items() if k not in ("framework", "transport")}
    non_biz = counts.get("framework", 0) + counts.get("transport", 0)
    if not biz:
        owner = "transport" if counts.get("transport") else "framework"
    elif len(biz) == 1:
        owner = next(iter(biz))
    else:
        owner = "mixed"
    # 只有一类占 80% 以上时仍判单一主体，避免一条边缘栈把整体结论搅成"混合"
    if owner == "mixed" and biz:
        top = max(biz.values())
        if top >= sum(biz.values()) * 0.8:
            owner = max(biz, key=lambda k: biz[k])

    main = next((i for i in infos if i.get("owner") == owner), infos[0])
    label = _mixed_label(owner, infos, counts, app_package, main)
    return {
        "owner": owner,
        "owner_label": label,
        "counts": counts,
        "sdk": list(sdk_all.values()),
        "initiators": initiators[:4],
        "total": sum(biz.values()),
        "framework_only": counts.get("framework", 0),
        "transport_only": counts.get("transport", 0),
        "non_biz": non_biz,
        "sdk_called_by_app": any(i.get("sdk_called_by_app") for i in infos),
        "text": _summary_text(owner, infos, counts, initiators, app_package, main),
    }


def _mixed_label(owner: str, infos: List[Dict[str, Any]], counts: Dict[str, int],
                 app_package: str, main: Dict[str, Any]) -> str:
    if owner != "mixed":
        return main.get("owner_label") or KIND_LABELS.get(owner, owner)
    parts: List[str] = []
    if counts.get("app"):
        parts.append("应用自身 %d 条" % counts["app"])
    if counts.get("sdk"):
        names: List[str] = []
        for i in infos:
            for s in (i.get("sdk") or []):
                n = s.get("name") or s.get("prefix") or ""
                if n and n not in names:
                    names.append(n)
        parts.append("第三方 SDK %d 条%s"
                     % (counts["sdk"],
                        "（%s）" % "、".join(names[:3]) if names else "（名称未识别）"))
    if counts.get("unknown"):
        parts.append("未能归属 %d 条" % counts["unknown"])
    # 前缀要按实际参与的主体拼，不能写死"应用自身与第三方 SDK 均有发起" ——
    # 实测出现过只有 SDK + 未能归属的混合，写死会让报告凭空多出一个 App 行为。
    kinds = [k for k in ("app", "sdk", "unknown") if counts.get(k)]
    head = "、".join(KIND_LABELS.get(k, k) for k in kinds)
    return "%s均有发起：%s" % (head, "，".join(parts))


def _summary_text(owner: str, infos: List[Dict[str, Any]], counts: Dict[str, int],
                  initiators: List[str], app_package: str,
                  main: Dict[str, Any]) -> str:
    """一句话分析，进报告正文（复核员不需要读原始栈也能知道结论怎么来的）。"""
    n = counts.get("app", 0) + counts.get("sdk", 0) + counts.get("unknown", 0)
    parts: List[str] = []
    if owner == "app":
        mine = [i for i in infos if i.get("owner") == "app"]
        # 80% 规则会把"4 条 App + 1 条 SDK"判成 App，但**不能写成"均位于"** ——
        # 那一条 SDK 栈是真的存在，用"均"字等于把它藏起来。
        other = n - len(mine)
        parts.append("本次共 %d 条业务调用栈，跳过系统框架帧后的直接发起点%s位于应用自身代码"
                     "（%s），可认定为 App 自主发起的采集行为"
                     % (n, "均" if not other else "多数（%d/%d）" % (len(mine), n),
                        app_package or "被测应用"))
        if mine and mine[0].get("initiator"):
            parts.append("代表调用点 %s" % mine[0]["initiator"])
    elif owner == "sdk":
        s = (main.get("sdk") or [{}])[0]
        who = display_name(s.get("name") or "未命名 SDK")
        vendor = s.get("vendor") or ""
        weak = "（根包名匹配，建议人工确认）" if s.get("match") == "root" else ""
        parts.append("本次共 %d 条业务调用栈，直接发起点位于第三方 SDK「%s」%s%s，"
                     "属于 SDK 自身发起的采集" % (n, who, "（%s）" % vendor if vendor else "", weak))
        if any(i.get("sdk_called_by_app") for i in infos):
            parts.append("栈的下层可见应用代码调用该 SDK 的接口，"
                         "即 App 主动触发了这次 SDK 读取")
        else:
            parts.append("栈中未见应用代码调用该 SDK 的痕迹，"
                         "倾向于 SDK 初始化后自行发起")
    elif owner == "framework":
        parts.append("本次 %d 条调用栈的调用点全部位于系统框架内部，"
                     "未发现应用或第三方代码的调用痕迹，不应计为应用侧收集行为"
                     % counts.get("framework", 0))
    elif owner == "transport":
        parts.append("本次 %d 条调用栈从栈顶到栈底都是网络传输层（OkHttp 一类），"
                     "没有捕获到发起调用的业务代码，无法判断是应用还是 SDK 发出的"
                     % counts.get("transport", 0))
    elif owner == "mixed":
        parts.append("本次共 %d 条业务调用栈分属不同主体（应用自身 %d 条、第三方 SDK %d 条、"
                     "未能归属 %d 条），需分别看待"
                     % (n, counts.get("app", 0), counts.get("sdk", 0), counts.get("unknown", 0)))
    else:
        parts.append("本次共 %d 条业务调用栈，直接发起点均不在已收录的 SDK 名单内"
                     "（%s），无法可靠区分是自研代码还是未收录的第三方库，需人工确认"
                     % (n, "、".join(initiators[:2]) or "调用点不明"))

    # 主主体占多数时，少数派也必须点名 —— 报告里只留一句"App 自主发起"，
    # 复核员就不会去查那几条 SDK 栈，而这恰恰是整改时最该改的部分。
    if owner != "mixed":
        for kind in ("app", "sdk", "unknown"):
            if kind == owner:
                continue
            c = counts.get(kind, 0)
            if c:
                parts.append("另有 %d 条调用栈的主体为%s" % (c, KIND_LABELS.get(kind, kind)))

    if counts.get("transport") and owner not in ("transport",):
        parts.append("另有 %d 条调用栈的栈顶为传输层（OkHttp 等网络库），"
                     "已穿过它们定位真正的调用方" % counts["transport"])
    if counts.get("framework"):
        parts.append("另有 %d 条调用栈全部位于系统框架内部（%s），不计为应用侧行为"
                     % (counts["framework"],
                        "、".join(i.get("frames")[0]["cls"] for i in infos
                                  if i.get("owner") == "framework" and i.get("frames"))[:90]
                        or "调用点不明"))
    return "；".join(parts) + "。"


def display_name(name: str) -> str:
    """SDK 显示名：库里的写法常带 `@厂商` 后缀（`某广告SDK@某厂商`），
    直接印在报告里又长又重复，逐帧标注只需要最短的那个名字。"""
    s = str(name or "").strip()
    return s.split("@")[0].strip() or s


def annotated_frames(info: Dict[str, Any]) -> List[str]:
    """把逐帧标注拼成可直接显示的文本行。

    形如 `[SDK 友盟统计分析] com.umeng.analytics.pro.aq.a(Analytics.java:88)`。
    缩进后放进 <pre> 不会破坏等宽对齐（标记在行首，左对齐）。
    """
    out = []
    for f in (info.get("frames") or []):
        tag = f.get("tag") or FRAME_TAGS["unknown"]
        note = display_name(f.get("note") or "") if f.get("note") else ""
        out.append("[%s%s] %s" % (tag, " " + note if note else "", f.get("cls") or ""))
    return out


def sdk_names(stacks: Sequence[Sequence[str]], app_package: str = "") -> List[str]:
    """从一批栈里取出"实际观测到的第三方 SDK 名称"（去重、保序）。"""
    seen: List[str] = []
    for s in stacks or ():
        for item in (analyze_stack(s, app_package).get("sdk") or []):
            name = item.get("name") or item.get("prefix")
            if name and name not in seen:
                seen.append(name)
    return seen


def sdk_specs(stacks: Sequence[Sequence[str]], app_package: str = "") -> List[str]:
    """同上，但带厂商与包前缀：`名称|厂商|com.umeng.analytics`。

    下游（政策「未列明 SDK」比对）需要这三样才能生成多种写法去检索 ——
    只给一个中文名，政策里写成"umeng"或"友盟同欣"就搜不到。

    同一厂商的多条库记录（友盟统计 / 友盟+ 移动统计…）在这里就归并掉：
    否则报告里会写"识别出 15 个 SDK"，实际只是 6 家厂商的 15 条词条，
    复核员按 15 个去政策里逐个核对，会白花一倍时间。
    """
    seen: List[str] = []
    keys = set()
    for s in stacks or ():
        for item in (analyze_stack(s, app_package).get("sdk") or []):
            key = item.get("vendor") or _root(item.get("prefix") or "") \
                or item.get("name") or item.get("prefix")
            if not key or key in keys:
                continue
            keys.add(key)
            seen.append("|".join([item.get("name") or item.get("prefix") or "",
                                  item.get("vendor") or "",
                                  item.get("prefix") or ""]))
    return seen


def owner_of_events(events: Iterable[Any], app_package: str = "") -> Dict[str, Any]:
    """对一批采集事件做归属汇总（sop 里按事件批直接调）。"""
    stacks = [list(getattr(e, "stack", []) or []) for e in (events or ())]
    return summarize(stacks, app_package)


def stacks_with_sdks(stacks: Sequence[Sequence[str]], app_package: str,
                     names: Iterable[str]) -> List[List[str]]:
    """挑出"栈里确实出现了这些 SDK"的那些栈。

    支撑「某 SDK 未在政策中列明」时，挂的必须是**这个 SDK 自己的栈**。
    随手拿前三条栈充数，会出现"结论说 A SDK 未列明、证据是 B SDK 的调用栈"，
    复核员一比对就整条作废。

    ★ 名字比对要宽容（金考典 2026-10-28）：同一个 SDK 在不同调用点有多个写法 ——
      库里的 `SdkName` 是「某广告 SDK@某厂商」，比较侧拿到的可能只是
      「优推广告 SDK」（报告展示用的短名）。要求全等会让这一支**一条栈都挑不到**，
      于是报告里挂着上一条结论残留的栈，看上去就是"对不上"。
    """
    def _norm(s: str) -> str:
        # 去掉 @厂商 后缀与空白：`某广告 SDK@某厂商` → `某广告sdk`
        return re.sub(r"\s+", "", str(s or "").split("@")[0]).lower()

    want = {_norm(n) for n in (names or ()) if str(n).strip()}
    want |= {str(n) for n in (names or ()) if str(n).strip()}
    if not want:
        return [list(s) for s in (stacks or ()) if s][:3]
    out: List[List[str]] = []
    for s in stacks or ():
        info = analyze_stack(s, app_package)
        if any((x.get("name") or x.get("prefix")) in want
               or _norm(x.get("name") or "") in want
               for x in (info.get("sdk") or [])):
            out.append(list(s))
        if len(out) >= 3:
            break
    return out


__all__ = ["FRAMEWORK_PREFIXES", "KIND_LABELS", "FRAME_TAGS",
           "frame_class", "is_framework", "classify_frame", "analyze_stack",
           "summarize", "annotated_frames", "sdk_names", "sdk_specs",
           "stacks_with_sdks", "owner_of_events"]
