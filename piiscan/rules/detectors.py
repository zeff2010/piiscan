"""检测器实现：把规则库 + 采集证据转换成「不符合项」。

每个检测器函数签名为 fn(ctx) -> Optional[Finding]。
用 @detector("Q0xx", requires=...) 注册到引擎；requires 表示该检测器需要哪类证据：
    ""        静态信息即可
    "policy"  需要隐私政策文本
    "dynamic" 需要设备上的动态采集结果

误报控制 —— 五级漏斗（对动态事件）：
    ① hook 命中      必要但不充分，仅作线索
    ② 取到有效值     排除 null / 占位值（Android 10+ IMEI 返回 null 等）
    ③ 堆栈与包名排除 排除框架 / WebView 自身触发的调用
    ④ 有去向下落     网络上报 / 持久化 / 日志（采集脚本以 sink 事件单独上报）
    ⑤ 进报告         仅通过前四者的事件可支撑结论

其中 ②③ 在采集脚本内完成（事件自带 evidence 等级），④ 作为佐证单独评估。
本模块的 funnel() 负责复核 ② 级、把 sink 事件与「收集事件」分离，并统计各级损耗，
使报告能如实说明「原始命中 N 条 → 过滤后 M 条」。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import Evidence, Finding
from .rulebase import checkitems, signal_map

# ---------------------------------------------------------------- 注册机制

DetectorFn = Callable[[Any], Optional[Finding]]
_REGISTRY: List[Tuple[str, DetectorFn, str]] = []


def _policy_src_label(p) -> str:
    """证据明细表里的「政策来源」描述。

    早先的 fallback 是硬编码的「（人工提供文本）」：一旦政策来自 APK 内置文档
    （按设计 url 为空），报告就会写"人工提供文本" —— 明明是程序从包里提取的全文，
    却暗示是人手输入的。人工复核时会据此误判证据强度，必须改成真实来源。
    """
    url = getattr(p, "final_url", "") or getattr(p, "url", "") or ""
    if url:
        return url
    try:
        from ..pipeline import POLICY_SOURCE_LABELS
    except Exception:
        POLICY_SOURCE_LABELS = {}
    src = str(getattr(p, "source", "") or "")
    return POLICY_SOURCE_LABELS.get(src, "来源未记录")


def detector(qid: str, requires: str = ""):
    def deco(fn: DetectorFn) -> DetectorFn:
        _REGISTRY.append((qid, fn, requires))
        return fn
    return deco


def registry() -> List[Tuple[str, DetectorFn, str]]:
    return list(_REGISTRY)


# ---------------------------------------------------------------- 上下文

@dataclass
class ScanContext:
    static: Any = None                     # apkstatic.StaticResult
    policy: Any = None                     # policy.PolicyResult
    dynamic: Any = None                    # collector.ScanResult
    log: Callable[[str], None] = print

    def has_static(self) -> bool:
        return self.static is not None and bool(getattr(self.static, "package", ""))

    def has_policy(self) -> bool:
        p = self.policy
        return bool(p is not None and getattr(p, "ok", False) and getattr(p, "text", ""))

    def has_dynamic(self) -> bool:
        return self.dynamic is not None and bool(getattr(self.dynamic, "events", None))


# ---------------------------------------------------------------- 构造辅助

def make(qid: str, **kw) -> Finding:
    """按测评项元数据构造 Finding，显式传入的字段优先。"""
    ci = checkitems()
    item = ci.get(qid) or {}
    f = Finding(
        rule_id=qid,
        title=kw.pop("title", item.get("title", qid)),
        category_id=item.get("category", ""),
        category_name=ci.category_name(qid),
        basis=ci.basis(qid),
        unit=ci.unit(qid),
        automation=ci.automation(qid),
        freq=ci.freq(qid),
        pain=ci.pain(qid),
    )
    for k, v in kw.items():
        setattr(f, k, v)
    return f


def f2(kind: str, title: str, detail: str = "", **data) -> Evidence:
    return Evidence(kind=kind, title=title, detail=detail, data=data)


# ============================================================================
#  误报控制：有效值与堆栈排除
# ============================================================================

# 取到这些值等同于没取到（signal_map.yaml 的返回值黑名单）
INVALID_VALUES = {
    "", "null", "none", "nil", "unknown", "undefined", "false",
    "0", "-1", "000000000000000", "02:00:00:00:00:00",
    "00000000-0000-0000-0000-000000000000", "00:00:00:00:00:00",
    "unknown", "0.0", "0,0", "n/a", "na", "null,null",
}

# 框架/WebView 自身触发的调用，不构成 App 的收集行为
FRAMEWORK_STACK = (
    "org.chromium.", "com.android.webview", "android.webkit.",
    "com.android.internal.os.", "dalvik.system.",
)

# 这些调用点通常是系统/框架内部查询，不是 App 主动收集
EXCLUDE_METHODS = (
    "queryIntentActivities", "getInstallerPackageName", "getPackageInfo",
    "resolveActivity", "resolveIntent", "queryBroadcastReceivers",
    "getRunningAppProcesses",  # 由系统自身触发时排除（下方按栈判断）
)


def is_valid_value(result: str) -> bool:
    """② 取到有效值：排除 null / 占位值。"""
    if result is None:
        return False
    v = str(result).strip().strip('"').strip("'").lower()
    if v in INVALID_VALUES:
        return False
    if set(v) <= {"0"} or set(v) <= {"f"}:
        return False
    return True


def stack_excluded(stack: List[str]) -> Tuple[bool, str]:
    """③ 堆栈与包名排除：返回 (是否应排除, 原因)。"""
    if not stack:
        return False, ""
    joined = " | ".join(stack)
    for pkg in FRAMEWORK_STACK:
        if pkg in joined:
            return True, "调用来自框架/WebView 内部（%s）" % pkg
    head = stack[0] if stack else ""
    if any(m in head for m in EXCLUDE_METHODS):
        return True, "调用点为系统内部查询（%s）" % head
    return False, ""


SINK_CATEGORIES = ("network_sink", "storage_sink", "log_sink")


def funnel(events: List[Any], include_behavior: bool = False
           ) -> Tuple[List[Any], Dict[str, int]]:
    """对原始事件跑五级漏斗，返回 (通过的事件, 各级计数)。

    include_behavior=True 时保留 C 级「纯行为」事件（如权限申请），
    供不要求取到值的检测项（Q012 提前索要权限）使用。
    """
    stats = {"raw": len(events), "sink_events": 0, "dropped_low": 0,
             "invalid_value": 0, "a_level": 0, "b_level": 0, "c_level": 0,
             "noise": 0, "passed": 0}
    out: List[Any] = []
    for e in events:
        # 第 ⑤ 级：系统/框架自身行为。收集阶段按"栈顶是否全在框架里""是不是
        # classpath 资源/建表语句/公共目录路径"等机械判据标了 noise ——
        # 这些事件的值可能是真值，但**不是这个 App 在收集**，不能作为 App 的违规证据。
        if getattr(e, "noise", ""):
            stats["noise"] += 1
            continue

        cat = getattr(e, "category", "")
        if cat in SINK_CATEGORIES:
            stats["sink_events"] += 1        # 去向事件不单独当「收集」结论
            continue

        ev = str(getattr(e, "evidence", "") or "").upper()
        if ev:
            if ev in ("A", "B"):
                out.append(e)
                stats["a_level" if ev == "A" else "b_level"] += 1
            elif ev == "C" and include_behavior:
                out.append(e)
                stats["c_level"] += 1
            else:
                stats["dropped_low"] += 1
            continue

        # 兼容不带 evidence 字段的事件（旧数据 / 外部导入）
        if not is_valid_value(getattr(e, "result", "")):
            stats["invalid_value"] += 1
            continue
        ex, _why = stack_excluded(list(getattr(e, "stack", []) or []))
        if ex:
            stats["dropped_low"] += 1
            continue
        out.append(e)
    stats["passed"] = len(out)
    return out, stats


def sink_corroboration(dynamic: Any) -> Dict[str, Any]:
    """第 ④ 级：评估「数据去向」佐证。

    返回 {hosts, before_consent_hosts, total} —— 有外发即说明数据真的离开了设备，
    可将结论从「疑似」提升到「确证」。注意：无外发不等于没收集（可能走 native 层
    或长连接），报告中须如实说明。
    """
    sinks = list(getattr(dynamic, "network_sinks", None) or [])
    bc = [s for s in sinks if int(s.get("before_consent") or 0) > 0]
    return {
        "hosts": [s.get("host") for s in sinks[:12]],
        "before_consent_hosts": [s.get("host") for s in bc[:12]],
        "total": sum(int(s.get("count") or 0) for s in sinks),
        "domain_count": len(sinks),
    }


# ---------------------------------------------------------------- 类别 → 个人信息类型

CATEGORY_TO_PI = {
    "device_id": "P01", "network": "P02", "location": "P04", "contacts": "P05",
    "sms": "P06", "call_log": "P06", "app_list": "P07", "account": "P08",
    "subscriber_id": "P08", "clipboard": "P09", "calendar": "P10",
    "media": "P11", "storage": "P12", "sensor": "P13", "other": "",
}


def pi_of_event(e: Any) -> Tuple[str, str]:
    """事件的个人信息类型。

    优先用采集脚本按映射表打好的标签（e.pi），它比按 API 名反查更准
    —— 例如此外 `Settings.Secure.getString` 既可算"设备标识"也可算"系统设置"，
    只有脚本侧的精确 key 判断才知道到底是哪个。
    """
    sm = signal_map()
    label = str(getattr(e, "pi", "") or "")
    if label:
        for kw, pid in PI_NAME_HINTS:
            if kw in label:
                if not pid:
                    return "", ""        # 去向/权限类不算个人信息类型
                return pid, sm.pi_name(pid) or label

    sig = sm.match_api(getattr(e, "api", "") or "")
    if sig and sig.get("pi"):
        return sig["pi"], sm.pi_name(sig["pi"])
    pid = CATEGORY_TO_PI.get(getattr(e, "category", ""), "")
    return pid, sm.pi_name(pid) if pid else ""


# 采集脚本给的 pi 标签 → 统一编号。顺序有意义（先匹配到的优先）。
PI_NAME_HINTS: List[Tuple[str, str]] = [
    ("OAID", "P01"), ("设备标识", "P01"), ("系统属性", "P15"),
    ("SIM", "P08"), ("手机号", "P08"), ("账号列表", "P08"),
    ("位置", "P04"), ("通讯录", "P05"),
    ("短信", "P06"), ("通话记录", "P06"),
    ("应用列表", "P07"), ("运行中应用", "P07"),
    ("剪贴板", "P09"), ("日历", "P10"),
    ("相册", "P11"), ("相机", "P11"), ("麦克风", "P11"), ("媒体", "P11"),
    ("外部存储", "P12"), ("本地留存", "P12"), ("存储", "P12"),
    ("传感器", "P13"), ("用户词典", "P14"),
    ("WiFi", "P02"), ("MAC", "P02"), ("网络", "P02"), ("运营商", "P02"),
    ("设备信息", "P03"),
    # 以下不属于「个人信息类型」，用于避免把去向/权限事件错误计入差集
    ("外发数据", ""), ("权限", ""), ("日志泄露", ""),
]


# ============================================================================
#  一、纯政策 / 静态类检测器
# ============================================================================

@detector("Q014", requires="policy")
def q014_complaint(ctx: ScanContext) -> Optional[Finding]:
    """未有效建立、公布个人信息安全投诉举报渠道。"""
    p = ctx.policy
    if not ctx.has_policy():
        return None
    issues: List[str] = []
    facts: List[Tuple[str, str]] = []

    if not p.has_complaint:
        issues.append("隐私政策全文中未出现投诉、举报、申诉或意见反馈相关的渠道说明")
    else:
        if not p.complaint_channels:
            issues.append("政策虽提及投诉举报，但未给出可用的具体联系方式（邮箱 / 电话 / 在线入口）")
        else:
            facts.append(("已公布渠道", "、".join(p.complaint_channels)))

    if p.processing_days is not None:
        facts.append(("承诺处理时限", "%d 个工作日" % p.processing_days))
        if p.processing_days > 15:
            issues.append("承诺的处理时限为 %d 个工作日，超过 15 个工作日" % p.processing_days)
    else:
        issues.append("未明确承诺投诉举报的处理时限")

    if not issues:
        return None

    facts.insert(0, ("政策来源", _policy_src_label(p)))
    facts.insert(1, ("政策正文长度", "%d 字" % p.text_len))
    descending = "；".join(issues)
    return make(
        "Q014", level="中" if len(issues) == 1 else "高",
        confidence="确证" if (not p.has_complaint) else "疑似",
        source="policy",
        description=("隐私政策中%s。依据《个人信息保护法》第五十条及"
                     "《App违法违规收集使用个人信息行为认定方法》，"
                     "个人信息处理者应当建立便捷的个人信息保护投诉举报渠道并及时受理处理。"
                     % descending),
        facts=facts,
        advise="建议在隐私政策中明确公布投诉举报渠道（邮箱、电话或在线入口），"
               "并承诺在十五个工作日内受理并反馈处理结果。",
        evidence=[f2("policy", "隐私政策文本", "投诉渠道抽取结果：%s" % descending,
                     has_complaint=p.has_complaint,
                     channels=p.complaint_channels,
                     processing_days=p.processing_days)],
    )


@detector("Q013", requires="policy")
def q013_cancel_account(ctx: ScanContext) -> Optional[Finding]:
    """未提供有效的注销用户账号功能。"""
    p = ctx.policy
    if not ctx.has_policy():
        return None
    issues: List[str] = []
    facts: List[Tuple[str, str]] = [("政策来源", _policy_src_label(p))]

    if not p.has_cancel_account:
        issues.append("隐私政策全文中未说明注销账号的途径或方式")
    else:
        if p.cancel_paths:
            facts.append(("政策所述注销路径", "；".join(p.cancel_paths[:2])))
        else:
            issues.append("政策提及注销，但未给出可操作的具体路径")
        if p.processing_days is not None and p.processing_days > 15:
            issues.append("注销的处理时限为 %d 个工作日，超过 15 个工作日" % p.processing_days)

    if not issues:
        return None
    return make(
        "Q013", level="高", confidence="确证" if not p.has_cancel_account else "疑似",
        source="policy",
        description=("隐私政策中%s。依据《App违法违规收集使用个人信息行为认定方法》"
                     "及 GB/T 42582-2023（RPI-11），"
                     "个人信息处理者应当提供有效的注销账号功能，且不得设置不合理条件。"
                     % "；".join(issues)),
        facts=facts,
        advise="建议在应用内提供独立、便捷的账号注销入口，并在隐私政策中明确注销路径与处理时限。",
        evidence=[f2("policy", "注销条款抽取", "；".join(issues))],
    )


@detector("Q015", requires="policy")
def q015_correct_delete(ctx: ScanContext) -> Optional[Finding]:
    """未提供更正、删除、撤回同意等权利的行使渠道。"""
    p = ctx.policy
    if not ctx.has_policy():
        return None
    missing = []
    facts: List[Tuple[str, str]] = [("政策来源", _policy_src_label(p))]
    checks = [
        ("更正个人信息", p.has_correct_delete, "更正/修改个人信息的途径"),
        ("删除个人信息", p.has_correct_delete, "删除个人信息的途径"),
        ("撤回同意", p.withdraw_consent, "撤回同意/授权的途径"),
    ]
    for label, ok, desc in checks:
        facts.append((label, "已提及" if ok else "未提及"))
        if not ok:
            missing.append(desc)
    if p.processing_days is None or p.processing_days > 15:
        facts.append(("处理时限", "%s" % (("%d 个工作日" % p.processing_days)
                                      if p.processing_days else "未承诺")))
        if p.processing_days is None:
            missing.append("承诺处理时限")

    if not missing:
        return None
    return make(
        "Q015", level="中" if len(missing) <= 1 else "高",
        confidence="疑似", source="policy",
        description=("隐私政策中未完整提供用户行使个人信息权利的渠道，缺少：%s。"
                     "依据 GB/T 42582-2023（RPI-05），"
                     "个人信息处理者应当提供便捷的更正、删除及撤回同意的途径。"
                     % "、".join(missing)),
        facts=facts,
        advise="建议在应用内及隐私政策中同时提供更正、删除个人信息与撤回同意的便捷入口，并注明处理时限。",
        evidence=[f2("policy", "权利条款抽取", "缺少：%s" % "、".join(missing))],
    )


@detector("Q001", requires="")
def q001_no_policy(ctx: ScanContext) -> Optional[Finding]:
    """未公开收集使用规则（未通过明显方式提示阅读隐私政策 / 政策不可访问）。"""
    st, p = ctx.static, ctx.policy
    issues: List[str] = []
    facts: List[Tuple[str, str]] = []
    steps: List[str] = []
    shots: List[Dict[str, str]] = []

    if st is not None:
        facts.append(("被测应用", "%s（%s）" % (st.app_label or "—", st.package or "—")))
        if not st.policy_urls:
            issues.append("在 APK 的字符串资源中未发现任何隐私政策 / 用户协议类的链接")

    # ---- 运行时证据（首选）：首启是否真的弹出了隐私政策 ----
    runtime_confirmed = False
    if ctx.has_dynamic():
        d = ctx.dynamic
        cap = getattr(d, "policy_capture", None) or {}
        entries = [t for t in (cap.get("entryTexts") or []) if t]
        urls = [u.get("url") for u in (cap.get("urls") or []) if u.get("url")]
        popup = bool(getattr(d, "first_launch_popup", False))
        facts.append(("首启弹窗实测", "已观测到隐私政策相关界面" if popup
                      else "首启观测期内未出现隐私政策提示"))
        if popup:
            runtime_confirmed = True
            facts.append(("弹窗内政策入口", "、".join(entries[:3])[:120] or "—"))
            steps = [s for s in (getattr(d, "ui_steps", []) or []) if "同意" in s]
        if urls:
            facts.append(("运行时捕获的政策链接", "、".join(urls[:3])[:160]))
        if cap.get("bestText"):
            facts.append(("运行时获取的政策正文", "%d 字（来源：%s）"
                          % (len(cap["bestText"]), cap.get("bestTextUrl") or "运行中页面")))
        # ★ 入口点开后是错误页 —— 这是「未提供可查阅的收集使用规则」的直接证据，
        #   比"没找到政策入口"有力得多：入口是有的，点开却拿不到条款。
        #   真机实测（赣警办）：入口指向 /webchat/#/privacy，服务端 404。
        if cap.get("errorPage"):
            issues.append(
                "首启弹窗内的政策入口点击后打开的是错误页（命中特征「%s」），"
                "未能获取政策条款%s"
                % (cap["errorPage"], ("；实际加载地址：%s" % urls[0]) if urls else ""))
            facts.append(("政策入口可用性", "不可用：打开后为错误页"))
        for ev in (getattr(d, "popup_evidence", []) or []):
            facts.append(("首启观测记录", ev[:120]))
        for sc in (getattr(d, "screens", []) or []):
            if any(k in (sc.get("label") or "") for k in ("首启", "隐私政策页面", "同意")):
                idx = sc.get("screenshot")
                if idx is not None and 0 <= idx < len(getattr(d, "screenshots", []) or []):
                    shots.append(d.screenshots[idx])
        if not popup and not entries:
            issues.append("设备端首启实测未观测到隐私政策弹窗，也未发现可点击的政策入口")

    if p is not None and p.ok:
        if p.text_len < 300:
            issues.append("隐私政策正文仅 %d 字，明显不完整或无法完整访问" % p.text_len)
        if not p.declared_behaviors:
            issues.append("政策正文中未发现对个人信息收集使用规则的完整说明")
        facts.append(("政策正文长度", "%d 字（来源：%s）" % (p.text_len, policy_source_label(p))))
    elif p is not None and not p.ok:
        issues.append("未能获取隐私政策正文（%s）" % (p.error or "定位失败"))

    # 动态侧：同意前已出现有效收集行为，却未捕获到同意动作
    if ctx.has_dynamic():
        d = ctx.dynamic
        events, _ = funnel(list(d.events))
        before = [e for e in events if getattr(e, "before_consent", False)]
        if before and not getattr(d, "consent_given", False):
            issues.append("运行期间未捕获到任何隐私政策同意操作，但已观测到 %d 次个人信息收集"
                          % len(before))
            facts.append(("同意前收集次数", "%d 次" % len(before)))

    if not issues:
        return None
    confidence = "确证" if (runtime_confirmed and not ctx.has_policy()) else "疑似"
    return make(
        "Q001", level="高", confidence=confidence,
        source="dynamic" if runtime_confirmed else "static",
        description=("检测发现应用%s。依据《App违法违规收集使用个人信息行为认定方法》"
                     "第一条，App 应当通过弹窗、链接等明显方式提示用户阅读个人信息"
                     "收集使用规则。" % "；".join(issues)),
        facts=facts, steps=steps, shots=shots,
        advise="建议在首次启动时以显著方式弹出隐私政策并获得用户明示同意，"
               "并在应用内及官网提供可随时访问的完整政策文本。",
        evidence=[f2("ui" if runtime_confirmed else "static", "首启隐私提示实测",
                     "；".join(issues))],
    )


def policy_source_label(p: Any) -> str:
    """政策来源的中文说明（报告里要能看出证据是怎么来的）。"""
    src = str(getattr(p, "source", "") or "")
    return {
        "runtime_text": "设备运行中读取（首启弹窗/政策页的真实文本）",
        "runtime_url": "首启弹窗捕获的真实链接",
        "apk_asset": "APK 内置政策文档（随包下发的全文）",
        "url": "链接抓取（人工指定）",
        "text": "人工提供全文",
        "static": "APK 静态提取的候选链接（可能是第三方 SDK 内置政策）",
        "none": "未获取到",
    }.get(src, src or "未知")


@detector("Q005", requires="policy")
def q005_incomplete_notice(ctx: ScanContext) -> Optional[Finding]:
    """未逐一列出收集、使用个人信息的目的、方式、范围。"""
    p = ctx.policy
    if not ctx.has_policy():
        return None
    elements = {
        "收集的目的": ["目的", "用途", "用于", "以便"],
        "收集的方式": ["方式", "通过", "收集方式"],
        "收集的范围": ["范围", "类型", "种类"],
        "保存期限": ["保存期限", "存储期限", "保留期限", "保存时间"],
    }
    missing = [k for k, words in elements.items() if not any(w in p.text for w in words)]
    if not missing:
        return None
    facts = [("政策来源", _policy_src_label(p)),
             ("已声明收集项", "%d 类" % len(p.declared_behaviors))]
    for k in elements:
        facts.append((k, "已说明" if k not in missing else "未说明"))
    return make(
        "Q005", level="中", confidence="疑似", source="policy",
        description=("隐私政策中未完整列出个人信息收集使用的%s。"
                     "依据 GB/T 42582-2023（PIC-19）及《个人信息保护法》第十七条，"
                     "处理个人信息前应当以显著方式、清晰易懂的语言真实准确完整地"
                     "告知处理目的、方式、种类与保存期限。"
                     % "、".join(missing)),
        facts=facts,
        advise="建议逐项列明所收集个人信息的目的、方式、范围与保存期限，"
               "并对敏感个人信息单独说明必要性与影响。",
        evidence=[f2("policy", "政策要素完整性", "缺少：%s" % "、".join(missing))],
    )


@detector("Q007", requires="")
def q007_third_party_sdk(ctx: ScanContext) -> Optional[Finding]:
    """未列明向第三方提供个人信息的种类、目的、方式及接收方名称。"""
    st = ctx.static
    if st is None:
        return None
    # 只关心会处理个人信息的 SDK 类型
    PII_SDK_TYPES = ("广告", "推送", "统计", "分析", "地图", "定位", "支付",
                     "社交", "认证", "营销", "风控", "性能监控", "消息推送", "实时音视频")
    risky = [s for s in st.sdks
             if any(t in (s.get("type") or "") for t in PII_SDK_TYPES)]
    if not risky:
        return None

    p = ctx.policy
    declared_names = set()
    if p is not None and p.ok:
        declared_names = {n for n in (p.third_party_names or [])}
        for s in risky:
            declared_names.add(s["name"])  # 政策里出现即视为已列明（下方再判定）

    undeclared = []
    for s in risky:
        name = s.get("name", "")
        short = re.split(r"[@（(]", name)[0].strip()
        if not ctx.has_policy():
            undeclared.append(s)
            continue
        if not any(k in p.text for k in {name, short} if k):
            undeclared.append(s)

    if not undeclared:
        return None
    facts = [
        ("内嵌第三方 SDK 总数", "%d 个" % len(st.sdks)),
        ("处理个人信息的 SDK", "%d 个" % len(risky)),
        ("未在政策中列明的", "%d 个" % len(undeclared)),
    ]
    for s in undeclared[:8]:
        facts.append((s.get("name", ""), "%s｜%s" % (s.get("type", ""), s.get("author", ""))))

    return make(
        "Q007", level="中" if len(undeclared) < 5 else "高", confidence="疑似", source="static",
        description=("检测出应用内嵌 %d 个会处理个人信息的第三方 SDK，"
                     "其中 %d 个未见诸隐私政策的第三方清单（如 %s 等）。"
                     "依据 GB/T 42582-2023（PIC-19）与《个人信息保护法》第二十三条，"
                     "向第三方提供个人信息应当告知接收方名称、联系方式、处理目的、"
                     "处理方式与个人信息种类。"
                     % (len(risky), len(undeclared),
                        "、".join(s["name"] for s in undeclared[:3]))),
        facts=facts,
        advise="建议在隐私政策中逐一列明接入的第三方 SDK 名称、提供方公司、"
               "收集的个人信息种类、使用目的与共享方式，并提供其隐私政策链接。",
        evidence=[f2("manifest", "内嵌 SDK 清单", "共 %d 个，其中 %d 个未列明"
                     % (len(st.sdks), len(undeclared)),
                     sdks=[{"name": s.get("name"), "type": s.get("type"),
                            "author": s.get("author")} for s in undeclared[:20]])],
    )


@detector("Q009", requires="policy")
def q009_minor_rule(ctx: ScanContext) -> Optional[Finding]:
    """处理未成年人个人信息未制定专门规则。"""
    p, st = ctx.policy, ctx.static
    if not ctx.has_policy():
        return None
    if p.children_rule:
        return None
    facts = [("政策来源", _policy_src_label(p)),
             ("儿童/未成年人专门规则", "未发现")]
    if st is not None:
        facts.append(("应用名称", st.app_label or "—"))
    return make(
        "Q009", level="低", confidence="疑似", source="policy",
        description=("隐私政策中未发现针对不满十四周岁未成年人的个人信息处理规则，"
                     "亦未见取得监护人单独同意的说明。依据 GB/T 42582-2023（PIC-22）"
                     "与《个人信息保护法》第三十一条，处理不满十四周岁未成年人"
                     "个人信息应当取得父母或其他监护人同意，并制定专门的处理规则。"),
        facts=facts,
        advise="若应用面向或可能被未成年人使用，建议制定独立的儿童个人信息保护规则，"
               "并设置监护人同意的交互流程。",
        evidence=[f2("policy", "儿童规则检查", "政策未含未成年人专门条款")],
    )


@detector("Q010", requires="")
def q010_excess_scope(ctx: ScanContext) -> Optional[Finding]:
    """超出必要范围收集：声明了与业务弱相关的敏感权限。"""
    st = ctx.static
    if st is None:
        return None
    # 需要重点审视的高敏感权限
    HIGH_RISK = {
        "android.permission.ACCESS_FINE_LOCATION": "精确位置",
        "android.permission.ACCESS_COARSE_LOCATION": "粗略位置",
        "android.permission.ACCESS_BACKGROUND_LOCATION": "后台位置",
        "android.permission.READ_CONTACTS": "通讯录",
        "android.permission.READ_SMS": "短信",
        "android.permission.READ_CALL_LOG": "通话记录",
        "android.permission.READ_CALENDAR": "日历",
        "android.permission.RECORD_AUDIO": "麦克风",
        "android.permission.CAMERA": "摄像头",
        "android.permission.BODY_SENSORS": "身体传感器",
        "android.permission.QUERY_ALL_PACKAGES": "全部应用列表",
        "android.permission.REQUEST_INSTALL_PACKAGES": "安装应用",
    }
    hit = [(perm, label) for perm, label in HIGH_RISK.items() if perm in st.permissions]
    if not hit:
        return None
    facts = [("被测应用", "%s（%s）" % (st.app_label or "—", st.package or "—"))]
    for perm, label in hit:
        facts.append((label, perm))
    return make(
        "Q010", level="低", confidence="疑似", source="static",
        description=("应用声明了 %d 项高敏感权限（%s）。这些权限属于个人敏感信息范畴，"
                     "需要结合具体业务类型判断其必要性；若应用主体功能不依赖相应场景，"
                     "则可能构成超出必要范围收集。依据 GB/T 42582-2023（PIC-05）"
                     "与《常见类型移动互联网应用程序必要个人信息范围规定》。"
                     % (len(hit), "、".join(l for _p, l in hit[:4]))),
        facts=facts,
        advise="建议逐项复核上述权限与业务功能的对应关系，遵循最小必要原则；"
               "对确无必要的权限予以移除，并确保在具体功能场景触发时再动态申请。",
        evidence=[f2("manifest", "高敏感权限声明", "共 %d 项" % len(hit),
                     permissions=[p for p, _ in hit])],
    )


@detector("Q025", requires="")
def q025_no_encryption(ctx: ScanContext) -> Optional[Finding]:
    """未对个人信息采取加密、去标识化等安全技术措施（静态线索）。"""
    st = ctx.static
    if st is None:
        return None
    signals: List[str] = []
    if str(st.cleartext).lower() == "true":
        signals.append("应用显式允许明文 HTTP 传输（usesCleartextTraffic=true）")
    if not signals:
        return None
    return make(
        "Q025", level="低", confidence="疑似", source="static",
        description=("静态分析发现%s。依据 GB/T 42582-2023（PIS-04），"
                     "个人信息处理者应当采取加密、去标识化等安全技术措施。"
                     "该发现为静态线索，实际是否以明文传输个人信息需结合网络抓包确认。"
                     % "；".join(signals)),
        facts=[("检测线索", "；".join(signals)),
               ("应用名称", st.app_label or "—")],
        advise="建议关闭明文流量许可，全站启用 HTTPS，"
               "并对上报的个人信息字段做加密或去标识化处理。",
        evidence=[f2("static", "明文传输线索", "；".join(signals))],
    )


# ============================================================================
#  二、动态类检测器（需要设备采集）
# ============================================================================

@detector("Q002", requires="dynamic")
def q002_before_consent(ctx: ScanContext) -> Optional[Finding]:
    """征得用户同意前就开始收集个人信息 —— 证据力最强的一项。"""
    d = ctx.dynamic
    events, fstats = funnel(list(d.events))
    before = [e for e in events if getattr(e, "before_consent", False)]
    if not before:
        return None

    # 按个人信息类型聚合
    groups: Dict[str, List[Any]] = {}
    for e in before:
        pid, pname = pi_of_event(e)
        key = pname or getattr(e, "category", "other")
        groups.setdefault(key, []).append(e)

    facts = [
        ("同意状态", "未捕获到用户同意操作" if not getattr(d, "consent_given", False)
         else "同意操作发生于第 %.1fs（%s）" % (getattr(d, "consent_elapsed_ms", 0) / 1000.0,
                                              getattr(d, "consent_source", "") or "界面点击")),
        ("漏斗筛选", "原始事件 %d 条 → 通过 %d 条（A 级 %d / B 级 %d，"
                     "剔除低频行为 %d 条、去向事件 %d 条另计）"
         % (fstats["raw"], fstats["passed"], fstats.get("a_level", 0),
            fstats.get("b_level", 0), fstats.get("dropped_low", 0),
            fstats.get("sink_events", 0))),
        ("同意前收集次数", "%d 次" % len(before)),
        ("涉及信息类型", "、".join(groups.keys())),
    ]
    first = min(before, key=lambda e: getattr(e, "elapsed_ms", 0))
    facts.append(("最早一次调用", "冷启动后第 %.1fs，调用 %s"
                  % (getattr(first, "elapsed_ms", 0) / 1000.0, first.api)))

    # ---- 第 ④ 级：数据去向佐证 ----
    corroboration = sink_corroboration(d)
    if corroboration["total"]:
        facts.append(("数据去向（外发佐证）",
                      "同意前观测到 %d 次网络上报，涉及 %d 个域名%s"
                      % (corroboration["total"], corroboration["domain_count"],
                         ("：" + "、".join(corroboration["before_consent_hosts"][:5]))
                         if corroboration["before_consent_hosts"] else "")))
    else:
        facts.append(("数据去向（外发佐证）",
                      "本次未捕获到网络上报事件；不等于未收集（可能经 native 层或长连接发送）"))

    # 堆栈要先取出来：confidence 依赖它（有 A 级证据 + 能定位到业务方堆栈才算「确证」）
    stacks = [list(e.stack) for e in before[:3] if getattr(e, "stack", None)]
    a_level = fstats.get("a_level", 0)
    confidence = "确证" if (a_level > 0 and stacks) else "疑似"

    steps = []
    for i, e in enumerate(sorted(before, key=lambda x: getattr(x, "elapsed_ms", 0))[:8], 1):
        steps.append("%d. 第 %.1fs 调用 %s，返回 %s"
                     % (i, getattr(e, "elapsed_ms", 0) / 1000.0, e.api,
                        (e.result or "—")[:40]))

    # 截图优先取「触发该行为时所处界面」的那张
    shots: List[Dict[str, str]] = []
    all_shots = list(getattr(d, "screenshots", []) or [])
    for e in before[:3]:
        idx = int(getattr(e, "screenshot_idx", -1))
        if 0 <= idx < len(all_shots) and all_shots[idx] not in shots:
            shots.append(all_shots[idx])
    if not shots:
        shots = all_shots[:3]

    return make(
        "Q002", level="高", confidence=confidence, source="dynamic",
        description=("应用在用户确认隐私政策之前，即开始调用系统接口收集个人信息，"
                     "共观测到 %d 次有效调用，涉及%s等类型。"
                     "依据 GB/T 42582-2023 6.1.4.1 测评单元（PIC-19）"
                     "及《App违法违规收集使用个人信息行为认定方法》第一条，"
                     "属于「征得用户同意前就开始收集个人信息」。"
                     % (len(before), "、".join(list(groups.keys())[:4]))),
        facts=facts, steps=steps, stacks=stacks, shots=shots,
        advise="建议将个人信息收集行为推迟到用户明示同意隐私政策之后，"
               "并对首启阶段的第三方 SDK 初始化做延迟处理。",
        signals=sorted({getattr(e, "hook_id", "") for e in before if getattr(e, "hook_id", "")}),
        evidence=[f2("frida", "同意前 API 调用证据",
                     "共 %d 条有效事件（已通过有效值与堆栈双重过滤）" % len(before),
                     groups={k: len(v) for k, v in groups.items()},
                     funnel=fstats, sink=corroboration)],
    )


@detector("Q003", requires="dynamic")
def q003_undeclared_collection(ctx: ScanContext) -> Optional[Finding]:
    """未经用户同意收集使用个人信息 —— 实测收集与政策声明做差集。"""
    d = ctx.dynamic
    events, fstats = funnel(list(d.events))
    if not events:
        return None
    sm = signal_map()

    # 实测收集到的个人信息类型
    observed: Dict[str, List[Any]] = {}
    for e in events:
        pid, pname = pi_of_event(e)
        if not pid:
            continue
        observed.setdefault(pid, []).append(e)
    if not observed:
        return None

    if not ctx.has_policy():
        # 无政策文本时无法做差集，退化为「已收集但政策不可核验」的提示项
        return make(
            "Q003", level="低", confidence="疑似", source="dynamic",
            description=("检测到应用在运行期间收集了 %d 类个人信息，但由于未能获取隐私政策正文，"
                         "无法核验其收集范围是否与声明一致，建议人工比对。"
                         "依据 GB/T 42582-2023 6.1.4.1 测评单元（PIC-19）。"
                         % len(observed)),
            facts=[("实测收集类型", "、".join(sm.pi_name(p) for p in observed)),
                   ("漏斗筛选", "原始 %d 条 → 通过 %d 条（剔除低证据级 %d 条）"
                    % (fstats["raw"], fstats["passed"], fstats.get("dropped_low", 0)))],
            advise="请人工获取隐私政策并与实测收集范围逐项比对。",
            evidence=[f2("frida", "实测收集类型", "政策缺失，未能完成差集比对")],
        )

    p = ctx.policy
    declared = set(p.declared_behaviors or [])
    # 政策声明里出现过的政策表述词集合
    declared_terms = set(p.declared_types or [])

    undeclared: Dict[str, List[Any]] = {}
    for pid, evs in observed.items():
        pv = sm.pi.get(pid) or {}
        terms = list(pv.get("policy_terms") or [])
        # 判定口径：政策中未出现该类型的任何常见表述
        if not any(t in p.text for t in terms if t):
            undeclared[pid] = evs

    if not undeclared:
        return None

    facts = [
        ("政策来源", _policy_src_label(p)),
        ("实测收集类型", "%d 类" % len(observed)),
        ("政策已声明类型", "%d 类" % (len(observed) - len(undeclared))),
        ("未见声明类型", "%d 类" % len(undeclared)),
        ("漏斗筛选", "原始 %d 条 → 通过 %d 条（A 级 %d / B 级 %d，剔除低证据级 %d 条）"
         % (fstats["raw"], fstats["passed"], fstats.get("a_level", 0),
            fstats.get("b_level", 0), fstats.get("dropped_low", 0))),
    ]
    detail_lines = []
    for pid, evs in list(undeclared.items())[:8]:
        sample = evs[0]
        detail_lines.append("%s：%d 次，如 %s" % (sm.pi_name(pid), len(evs), sample.api))
    for line in detail_lines:
        facts.append(("未声明", line))

    return make(
        "Q003", level="高", confidence="疑似", source="dynamic",
        description=("实测收集的个人信息类型中，有 %d 类（%s）未在隐私政策中找到对应声明。"
                     "依据 GB/T 42582-2023 6.1.4.1 测评单元（PIC-19）"
                     "与《个人信息保护法》第十七条，属于「未完整准确告知」或"
                     "「收集了未声明的个人信息」。"
                     % (len(undeclared), "、".join(sm.pi_name(x) for x in undeclared))),
        facts=facts,
        steps=["1. 静态解析隐私政策，抽取其声明的个人信息类型",
               "2. 动态采集运行期 API 调用，归一化为个人信息类型",
               "3. 求差集：实测有、政策无 → 列入本项"],
        advise="建议在隐私政策中补充说明上述个人信息的收集目的、方式与范围，"
               "或在业务上停止对应收集行为。",
        signals=sorted({getattr(e, "hook_id", "") for evs in undeclared.values()
                        for e in evs if getattr(e, "hook_id", "")}),
        evidence=[f2("frida", "实测与声明差异",
                     "未声明类型：%s" % "、".join(sm.pi_name(x) for x in undeclared),
                     observed={sm.pi_name(k): len(v) for k, v in observed.items()},
                     undeclared=[sm.pi_name(k) for k in undeclared])],
    )


@detector("Q011", requires="dynamic")
def q011_frequency(ctx: ScanContext) -> Optional[Finding]:
    """超出最低必要频率调用权限（纯量化规则）。"""
    d = ctx.dynamic
    events, _ = funnel(list(d.events))
    if not events:
        return None
    total = max(1.0, float(getattr(d, "duration", 0) or 1.0))
    counts: Dict[str, List[Any]] = {}
    for e in events:
        counts.setdefault(getattr(e, "api", ""), []).append(e)

    hot = []
    for api, evs in counts.items():
        rate = len(evs) / total * 60.0     # 次/分钟
        if len(evs) >= 20 and rate >= 12:
            hot.append((api, len(evs), rate))
    if not hot:
        return None
    hot.sort(key=lambda x: -x[2])

    facts = [("采集时长", "%.0f 秒" % total)]
    for api, n, rate in hot[:6]:
        facts.append((api, "%d 次 / %.0f 次每分钟" % (n, rate)))
    return make(
        "Q011", level="低", confidence="疑似", source="dynamic",
        description=("检测到以下接口在单位时间内的调用频次明显偏高，"
                     "可能存在超出最低必要频率的调用：%s。"
                     "依据 GB/T 42582-2023 6.1.2.2 测评单元（PIC-05）。"
                     % "；".join("%s 达 %.0f 次/分钟" % (a, r) for a, _n, r in hot[:3])),
        facts=facts,
        advise="建议按业务需要降低调用频率，并对频繁调用的信息做本地缓存或去重处理。",
        evidence=[f2("frida", "调用频次统计", "高频接口 %d 个" % len(hot))],
    )


@detector("Q012", requires="dynamic")
def q012_early_permission(ctx: ScanContext) -> Optional[Finding]:
    """提前要求非当前功能所需的权限（基于权限申请弹窗的界面上下文）。"""
    d = ctx.dynamic
    # 权限申请属「纯行为」事件（C 级），需显式保留
    events, _ = funnel(list(d.events), include_behavior=True)
    # 权限申请类事件：hook_id / api 中含 requestPermissions 或权限名
    reqs = [e for e in events
            if re.search(r"requestPermission|Permission", getattr(e, "api", ""), re.I)]
    if not reqs:
        return None
    early = [e for e in reqs if getattr(e, "before_consent", False)]
    if not early:
        return None
    facts = [("权限申请事件", "%d 条，其中同意前 %d 条" % (len(reqs), len(early)))]
    for e in early[:6]:
        facts.append(("同意前申请", "%s（第 %.1fs）"
                      % (e.api, getattr(e, "elapsed_ms", 0) / 1000.0)))
    return make(
        "Q012", level="中", confidence="疑似", source="dynamic",
        description=("应用在用户确认隐私政策之前即发起权限申请，共 %d 次。"
                     "依据 GB/T 42582-2023 6.1.2.2 测评单元（PIC-05），"
                     "不应在无相关功能或未使用相关功能时调用非必要权限。"
                     % len(early)),
        facts=facts,
        advise="建议将权限申请调整到具体功能触发时进行，并在申请前同步告知使用目的。",
        evidence=[f2("frida", "权限申请时序", "同意前 %d 次" % len(early))],
    )


@detector("Q006", requires="policy")
def q006_permission_notice(ctx: ScanContext) -> Optional[Finding]:
    """未同步告知目的：声明了敏感权限，但政策未说明对应信息类型的收集目的。"""
    st, p = ctx.static, ctx.policy
    if st is None or not ctx.has_policy():
        return None
    from .. import resources
    words = resources.policy_words()

    # 权限 → 政策常见表述词
    perm_words = {
        "android.permission.READ_PHONE_STATE": ["IMEI", "IMSI", "设备标识", "手机序列号",
                                                "设备识别码", "本机号码", "设备ID", "OAID"],
        "android.permission.ACCESS_FINE_LOCATION": ["定位", "位置信息", "地理", "行踪轨迹"],
        "android.permission.ACCESS_COARSE_LOCATION": ["定位", "位置信息", "地理"],
        "android.permission.READ_CONTACTS": ["通讯录", "联系人"],
        "android.permission.CAMERA": ["相机", "摄像头", "拍照", "拍摄"],
        "android.permission.RECORD_AUDIO": ["麦克风", "录音", "语音"],
        "android.permission.READ_SMS": ["短信"],
        "android.permission.READ_CALL_LOG": ["通话记录", "通讯记录"],
        "android.permission.READ_CALENDAR": ["日历", "日程"],
        "android.permission.GET_ACCOUNTS": ["账号", "账户"],
        "android.permission.BODY_SENSORS": ["传感器", "身体", "心率"],
        "android.permission.READ_EXTERNAL_STORAGE": ["存储", "相册", "文件", "图片"],
        "android.permission.WRITE_EXTERNAL_STORAGE": ["存储", "文件"],
    }
    silent = []
    for perm, ws in perm_words.items():
        if perm not in st.permissions:
            continue
        if not any(w in p.text for w in ws):
            silent.append(perm)
    if not silent:
        return None
    labels = resources.permission_labels()
    facts = [("政策来源", _policy_src_label(p)),
             ("未说明用途的权限", "%d 项" % len(silent))]
    for perm in silent[:8]:
        facts.append((labels.get(perm) or perm.split(".")[-1], perm))
    return make(
        "Q006", level="中", confidence="疑似", source="policy",
        description=("应用声明了 %d 项涉及个人信息的权限，但隐私政策中未见对相应"
                     "个人信息收集目的与用途的说明（%s）。"
                     "依据 GB/T 42582-2023 6.1.4.1 测评单元（PIC-19），"
                     "收集使用个人信息应当同步告知用户其目的。"
                     % (len(silent), "、".join(labels.get(x) or x.split(".")[-1]
                                            for x in silent[:4]))),
        facts=facts,
        advise="建议在隐私政策与权限申请弹窗中，同步告知每项敏感权限对应收集的"
               "个人信息及其使用目的。",
        evidence=[f2("policy", "权限用途告知检查", "未告知 %d 项" % len(silent),
                     permissions=silent)],
    )


@detector("Q008", requires="")
def q008_ad_profile(ctx: ScanContext) -> Optional[Finding]:
    """收集的个人信息用于广告、用户画像等功能但未在规则中明确。"""
    st, p = ctx.static, ctx.policy
    if st is None:
        return None
    ad_sdks = [s for s in st.sdks if "广告" in (s.get("type") or "")
               or any(k in (s.get("name") or "") for k in ("广告", "Ad", "AD", "AdScope",
                                                           "穿山甲", "优量汇", "广点通"))]
    if not ad_sdks:
        return None
    if not ctx.has_policy():
        return None
    AD_WORDS = ["广告", "个性化推荐", "用户画像", "精准营销", "商业推广", "程序化",
                "标签", "定向推送", "广告标识符"]
    if any(w in p.text for w in AD_WORDS):
        return None
    facts = [("政策来源", _policy_src_label(p)),
             ("涉及广告的 SDK", "%d 个" % len(ad_sdks))]
    for s in ad_sdks[:6]:
        facts.append((s.get("name", ""), s.get("author", "")))
    return make(
        "Q008", level="中", confidence="疑似", source="static",
        description=("应用内嵌 %d 个广告类 SDK（%s），但隐私政策中未见将个人信息"
                     "用于广告投放、用户画像或个性化推荐的说明。"
                     "依据 GB/T 42582-2023 6.1.5.1 测评单元（PIC-26），"
                     "应当明确告知个人信息用于广告、用户画像等功能的处理规则。"
                     % (len(ad_sdks), "、".join(s["name"] for s in ad_sdks[:3]))),
        facts=facts,
        advise="建议在隐私政策中明确说明广告与个性化推荐场景下个人信息的"
               "使用方式、涉及的第三方，并提供关闭个性化推荐的选项。",
        evidence=[f2("manifest", "广告类 SDK", "共 %d 个" % len(ad_sdks),
                     sdks=[s.get("name") for s in ad_sdks[:10]])],
    )
