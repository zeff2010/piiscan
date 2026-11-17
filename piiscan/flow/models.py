"""标准作业流程（SOP）的数据模型。

这一层刻意做得「薄」：只描述**状态**和**证据索引**，不碰任何采集逻辑。
原因是流程会变（加阶段、换顺序），但状态的含义不该跟着变 ——
一份报告最后能不能站得住，靠的就是每个测评项的状态都是明确的、
且有据可查的，而不是"没报问题"就默认"没问题"。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# 测评项的四种状态。注意 not_tested 与 pass 的区别：
# not_tested = 没拿到证据，不敢说；pass = 拿到证据了，确实没问题。
# 这两者在人工复核时意义完全不同，绝不能合并。
NOT_TESTED = "not_tested"
PASS = "pass"
SUSPECT = "suspect"
FAIL = "fail"

STATE_ORDER = {FAIL: 0, SUSPECT: 1, PASS: 2, NOT_TESTED: 3}

STATE_LABELS = {
    NOT_TESTED: "跳过未测",
    PASS: "未发现问题",
    SUSPECT: "疑似",
    FAIL: "发现问题",
}

# 阶段状态
PHASE_PENDING = "pending"
PHASE_RUNNING = "running"
PHASE_DONE = "done"
PHASE_PARTIAL = "partial"      # 跑了一半（部分步骤失败），证据不完整
PHASE_SKIPPED = "skipped"
PHASE_FAILED = "failed"

PHASE_LABELS = {
    PHASE_PENDING: "未开始",
    PHASE_RUNNING: "进行中",
    PHASE_DONE: "已完成",
    PHASE_PARTIAL: "部分完成",
    PHASE_SKIPPED: "已跳过",
    PHASE_FAILED: "失败",
}


# ---------------------------------------------------------------------------
# 「这次到底跑起来了没有」
#
# 用户口径（2026-10-27）：App 根本没跑起来，就不该算「已完成」——
# 国象联盟、火花思维课堂那两轮，22 项全「跳过未测」，截图全是手机桌面，
# 却挂在「已完成」里，看报告的人会以为测过了。这类任务应当直接判失败。
#
# 判据不看"点击了几次"，看**屏幕上到底有没有被测应用的界面内容**：
#   · app_ui  —— 前台是被测应用且读到了界面文字（≥2 条）的屏数
#   · app_any —— 前台是被测应用的屏数（哪怕结构树是空的）
#   · desktop —— 前台上是桌面的屏数
# 四个数就能把四种情形分开：
#   ok      至少有一屏真的看到了 App 的界面内容 → 能做动态检测
#   no_ui   进过 App，但界面结构完全读不出来（加固壳 / 纯 Surface 渲染）
#           → 动态检测同样做不了，只是原因不同，报告里要写清楚是哪一种
#   no_dump 亲眼确认前台切到了 App，却一屏都没留下来（dump 卡死/失败）
#           → 同样是"检测受限"，不能写成"应用没运行"
#   no_app  一次都没进过 App（启动即崩 / 一直停在桌面）—— 这种才是应用的问题
# ---------------------------------------------------------------------------
_DESKTOP_ACTIVITIES = ("launcher", "com.miui.home", "com.android.systemui",
                       "com.google.android.apps.nexuslauncher")


def assess_run_health(screens, package: str = "",
                      foreground_seen: bool = False,
                      hook_hostile: int = 0,
                      app_start_probe: Optional[Dict[str, Any]] = None,
                      hook_spawn_killed: int = 0) -> Dict[str, Any]:
    """由采集期记录的屏幕序列判断"App 是否真的跑起来了"。

    foreground_seen：采集期有没有**亲眼确认前台切到了被测应用**
    （`await_app_foreground` 成功过一次）。它把两种完全不同的情形分开：
      · 应用根本没起来（前台一直是桌面）—— 该判失败；
      · 应用起来了，但界面结构导不出来（加固壳 / 纯 Surface 渲染 / dump 卡死）
        —— 这是"检测受限"，不能说成"应用跑不起来"（洋葱学园 2026-10-27：
          用户站在手机前看 App 明明开着，报告却写"前台从未切换到被测应用"）。

    hook_hostile：注入被加固机制打断的次数。>0 说明界面/事件缺失里有
    **检测手段**的一份责任 —— 但这不等于应用自己没问题，见 app_start_probe。

    app_start_probe：注入不可用时，**不注入**直接启动的观察结果
    （`collector.probe_start_without_hook`）。它回答一个旧报告答错的问题：
    小盒课堂（爱加密）报告写"检测手段受限，不代表应用自身无法运行"，
    而实测它不注入也活不过 60 ms（SELinux 拦 execmod）—— 就是起不来。
    started=False 时本函数直接判 no_app，不再把责任推给检测手段。
    """
    pkg = (package or "").strip()
    app_ui = app_any = desktop = 0
    for s in (screens or []):
        if not isinstance(s, dict):
            continue
        # ★ hook 报上来的 Activity 生命周期事件不是"界面"（2026-11-10 CNC宝典）：
        #   它没有结构树、没有焦点证据，`activity` 还可能是壳/子进程里的另一个包名
        #   （那一轮 29 条里写的是 com.lathe.fanuc）。拿它计数会把"有没有拿到
        #   应用界面"整个判错，所以这里只认真正观测过的那几屏。
        if s.get("source") == "hook" or (
                str(s.get("label") or "") == "Activity" and not (s.get("texts") or [])):
            continue
        act = str(s.get("activity") or "")
        low = act.lower()
        texts = s.get("texts") or []
        # ★ 有采集侧算好的 `on_app` 就听它的（2026-11-10 健康深圳）：
        #   它是"窗口焦点 + 结构树节点包名"两个来源合成的结论；而 `activity`
        #   有可能来自 `mResumedActivity` —— 加固壳/uni-app 的应用可以
        #   "Activity resumed 但窗口从未画出来"。健康深圳在本机启动后约 150ms
        #   就 has died，`current_focus()` 却一直返回 PandoraEntry，于是这里把
        #   **系统桌面**那几屏全算成了"应用界面"，判出 no_ui/ok，报告于是拿
        #   桌面图当首启证据、还给出「未观测到收集行为」的 pass。
        _on = s.get("on_app")
        _vis = s.get("visible")
        if isinstance(_on, bool):
            on_app = _on
        elif isinstance(_vis, bool):
            on_app = _vis
        else:
            on_app = bool(act) and (act.startswith(pkg) if pkg else False)
        if on_app:
            app_any += 1
            # 只数**有内容**的文字节点：结构树里常见"节点在、text 是空串"，
            # 按 len(texts) 数会把"完全读不出内容的一屏"当成拿到了界面
            # （有朋公社就是这样：10 屏全空，却会被判成 ok）。
            if len([t for t in texts if str(t).strip()]) >= 2:
                app_ui += 1
        elif any(h in low for h in _DESKTOP_ACTIVITIES):
            desktop += 1
    _probe = app_start_probe if isinstance(app_start_probe, dict) else {}
    # 只有"确实一屏界面都没拿到"时，才用探测结果改判 —— 探到手上有界面，
    # 说明应用明明跑起来了，探测的否定结论不成立（比如启动极慢超了观察窗）。
    _probe_dead = bool(_probe) and _probe.get("started") is False and not app_ui
    if _probe_dead:
        state = "no_app"
        why = str(_probe.get("why") or "不注入直接启动时，应用无法稳定存活")
        _ev = str(_probe.get("evidence") or "").strip()
        if _ev:
            _last = _ev.splitlines()[-1]
            why += "；启动失败现场：%s" % _last[:240]
    elif app_ui:
        state, why = "ok", "已取得被测应用界面内容（%d 屏）" % app_ui
    elif app_any:
        state = "no_ui"
        why = ("已进入被测应用（%d 屏），但界面结构树读不到文字内容，"
               "无法据界面开展动态检测" % app_any)
    elif foreground_seen:
        state = "no_dump"
        # ★ "屏幕记录 0 屏"这句话本身可能是假的（2026-10-27 小盒课堂）：采集侧
        #   记了 3 屏，只是那 3 屏都没能确定所属 Activity（dump 成功但 activity
        #   取不到）。把"总屏数"与"能归类到桌面/应用的屏数"分开写。
        _rec = sum(1 for s in (screens or []) if isinstance(s, dict))
        _extra = max(0, _rec - (app_any + desktop))
        if _extra:
            _desc = ("屏幕记录共 %d 屏，其中 %d 屏可归类（桌面 %d 屏），"
                     "另有 %d 屏没能确定所属 Activity"
                     % (_rec, app_any + desktop, desktop, _extra))
        else:
            _desc = "屏幕记录共 %d 屏（其中桌面 %d 屏）" % (_rec, desktop)
        why = ("已确认前台切换到被测应用，但界面结构未能导出（%s），"
               "无法据界面开展动态检测" % _desc)
    else:
        # ★ 录了屏、却一屏都归不了类时，不许写"前台从未切换"（2026-10-30 补）：
        #   `activity` 取不到时采集侧仍会留一条屏记录（dump 成功、Activity 字段空），
        #   这种情况我们手上是"看不清"，不是"看见了没进"。"前台从未切换到被测应用"
        #   是一句很硬的否定结论，拿不准就该说拿不准 —— 与 no_dump 同归"检测受限"。
        _rec = sum(1 for s in (screens or []) if isinstance(s, dict))
        if _rec and not desktop:
            # 一屏都归不了类（含桌面）才走这里；只要看得到桌面，就说明前台确实
            # 一直在桌面，那 no_app 是站得住的结论。
            state = "no_dump"
            why = ("记录了 %d 屏，但没有一屏能确定所属界面（Activity 取不到，"
                   "dump 卡死或页面切换中常见），因此无法确认前台是否切到了被测应用"
                   % _rec)
        else:
            state = "no_app"
            why = "采集期间前台从未切换到被测应用（桌面屏 %d 个）" % desktop
    out = {"state": state, "app_ui": app_ui, "app_any": app_any,
           "desktop": desktop, "why": why,
           "screens": sum(1 for s in (screens or []) if isinstance(s, dict)),
           "foreground_seen": bool(foreground_seen),
           "hook_blocked": bool(hook_hostile)}
    if _probe:
        out["app_start_probe"] = {
            "started": bool(_probe.get("started")),
            "why": str(_probe.get("why") or "")[:400],
            "evidence": str(_probe.get("evidence") or "")[:800],
            "pids": list(_probe.get("pids") or [])[:6],
        }
    if hook_hostile or hook_spawn_killed:
        out["hook_hostile"] = int(hook_hostile)
        # 报告层要按它区分"注入被杀但应用能跑"与"两条都不通"，必须带出去
        if hook_spawn_killed:
            out["hook_spawn_killed"] = int(hook_spawn_killed)
        if _probe_dead:
            # 这里最要紧的是不许再说"不代表应用自身无法运行"——实测它就是不运行。
            out["why"] += ("；另：本轮注入尝试被加固机制拦截 %d 次，"
                           "但不注入时应用**自身也起不来**（见启动失败现场），"
                           "证据缺失不能只归因于检测手段" % int(hook_hostile))
        elif hook_spawn_killed:
            # ★ "应用本身能跑"必须是本轮实测的，不能靠推断（2026-10-27）：
            #   前台确实切到过它（app_any 屏）才是事实；没到过就别替应用下结论。
            _seen = int(out.get("app_any") or 0)
            _fact = ("前台确实切换到了被测应用（本次记录 %d 屏）" % _seen if _seen
                     else "本轮未单独做「不注入直接启动」的观察")
            out["why"] += ("；另：加固机制对冷启动注入同样会判定为调试（%d 次），"
                           "%s —— 事件证据缺失属检测手段受限，"
                           "不代表应用没有相应行为" % (int(hook_spawn_killed), _fact))
        else:
            out["why"] += ("；另：本轮注入尝试被加固机制拦截 %d 次"
                           "（重新附着后应用立即退出，或冷启动注入无法完成），"
                           "界面/事件证据的缺失是检测手段受限所致，"
                           "不代表应用自身无法运行" % int(hook_hostile))
    return out


def start_failed_reason(fr) -> Tuple[str, str]:
    """前提不成立时的一句话原因（head）+ 补充说明（why）。

    三种情形必须分开写（洋葱学园 2026-10-27）：用户站在手机前看着 App
    明明开着，报告却写"采集期间前台从未切换到被测应用" —— 因为界面结构
    读不出来被当成了"没起来"。分开之后：
      · no_app  —— 真的没到前台，才写"未能启动"；
      · no_ui   —— 进了应用、但结构树没有文字节点（加固壳/自绘渲染）；
      · no_dump —— 确认到前台、但结构树没导出来（dump 卡死/切换中）。
    """
    h = fr.run_health or {}
    st = str(h.get("state") or "")
    rn = int(getattr(fr, "relaunch_count", 0) or 0)
    if st == "no_ui":
        head = "已进入目标应用，但界面结构树读不出文字内容"
        why = ("前台确实切到了被测应用（%d 屏），但结构树里没有可用的文字节点 —— "
               "加固壳或自绘/网页渲染会导致这种情形，它不是「应用没打开」。"
               % int(h.get("app_any") or 0))
    elif st == "no_dump":
        if not h.get("foreground_seen"):
            # 录到屏了，但一屏都没能归类（Activity 取不到）—— 没有"亲眼确认前台"
            # 这一步，就不能写"已确认前台切换到目标应用"（2026-10-30）。
            head = "未能确认被测应用是否到过前台"
            why = str(h.get("why") or "")
        else:
            head = "已确认前台切换到目标应用，但界面结构未能导出"
            _rec = int(h.get("screens") or 0)
            why = ("uiautomator 未能导出结构树（页面切换 / WebView / 加固壳常见），"
                   "屏幕记录共 %d 屏%s。"
                   % (_rec,
                      "，其中可归类到桌面/应用界面的 0 屏" if _rec else ""))
    else:
        _probe = h.get("app_start_probe") or {}
        if _probe and _probe.get("started") is False:
            # 有"不注入直接启动"的实测数据时，用它说话 —— 比"进程反复退出 N 次"
            # 精确得多：那 N 次里可能有一半是我们注入造成的。
            # ★ 这里只给一句话 + 指针，不贴 logcat 原文：这条原因会出现在
            #   **每一个未测项**里，22 项各贴 200 字现场，报告既膨胀又难读。
            #   原文统一放在「目标应用启动状态」章节的表格里。
            head = "目标应用未能启动"
            why = str(_probe.get("why") or "")
            why += "（启动失败现场原文见「目标应用启动状态」章节）"
        else:
            head = "目标应用未能启动（进程反复退出 %d 次）" % rn
            why = ("采集期间每 5 秒探测一次进程，连续 %d 次发现进程已不存在。"
                   % rn)
    if h.get("hook_blocked"):
        _probe2 = h.get("app_start_probe") or {}
        if _probe2.get("started") is False and st == "no_app":
            # 应用自己也起不来时，别把"注入被拦"写成主要原因
            why += ("；另：本轮注入尝试被加固机制拦截 %d 次；"
                    "但不注入时应用同样无法启动，见上文启动失败现场。"
                    % int(h.get("hook_hostile") or 0))
        else:
            head += "，且注入被加固机制拦截"
            why += ("另：本轮注入尝试被加固机制拦截 %d 次，"
                    "API 调用证据缺失是检测手段受限所致。"
                    % int(h.get("hook_hostile") or 0))
    return head, why


@dataclass
class Evidence:
    """一条证据。只存索引与摘要，大件（截图、堆栈、正文）留在采集侧按 key 取。"""
    kind: str                       # manifest / policy / frida / ui / traffic / stack
    title: str
    detail: str = ""
    phase: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "title": self.title, "detail": self.detail,
                "phase": self.phase, "data": self.data}


@dataclass
class PhaseResult:
    """一个阶段的执行结果。"""
    phase_id: str = ""
    num: str = ""
    name: str = ""
    status: str = PHASE_PENDING
    started_at: float = 0.0
    ended_at: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)   # 对应 yaml 的 produces
    steps: List[str] = field(default_factory=list)           # 实际做了什么
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        if self.ended_at and self.started_at:
            return self.ended_at - self.started_at
        return 0.0

    # ---- 真实耗时（来自采集侧锚点，而不是编排器的墙钟）----
    # ★ 为什么要有两套时间（简小知 flow_live2 实测发现）：
    #   真机采集在流程编排**之前**就跑完了，编排器自己的墙钟只覆盖
    #   "读存档 + 算判定"，于是报告里 P1~P4 全是 0.0~0.2 秒。
    #   人工复核员看到「检测 3 分钟、每个阶段 0.2 秒」必然怀疑检测方法有问题。
    #   duration  = 编排器算判定花的时间（分析耗时）
    #   real_ms   = 采集侧在设备前真实花掉的时间（操作耗时），-1 表示不适用
    real_ms: int = -1
    timing: str = ""

    @property
    def real_seconds(self) -> float:
        return round(self.real_ms / 1000.0, 1) if self.real_ms and self.real_ms > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase_id": self.phase_id, "num": self.num, "name": self.name,
            "status": self.status, "duration": round(self.duration, 1),
            "real_ms": self.real_ms, "real_seconds": self.real_seconds,
            "timing": self.timing,
            "evidence": self.evidence, "steps": self.steps,
            "notes": self.notes, "warnings": self.warnings,
        }


@dataclass
class ItemState:
    """一个测评项（Q001…Q026）的判定状态。"""
    qid: str = ""
    title: str = ""
    category: str = ""
    state: str = NOT_TESTED
    reason: str = ""              # 未测原因，或判定依据
    desc: str = ""                # 问题描述（进报告正文）
    basis: str = ""               # 法规依据
    unit: str = ""
    level: str = "中"             # 高 / 中 / 低
    confidence: str = ""          # 确证 / 疑似
    automation: str = ""
    source_phase: str = ""        # 结论来自哪个阶段
    evidence: List[Evidence] = field(default_factory=list)
    facts: List[List[str]] = field(default_factory=list)   # 事实表（键值）
    stacks: List[List[str]] = field(default_factory=list)
    # 与 stacks 一一对应的调用现场：{api, args, result, before, elapsed_ms, thread}。
    # 报告里把它贴在被 hook 的那一帧上 —— 「读了什么、读到什么」必须和
    # 「谁读的」放在一起看，否则结论里的取值在栈里无处可查。
    stack_meta: List[Dict[str, Any]] = field(default_factory=list)
    shots: List[Dict[str, str]] = field(default_factory=list)
    # 调用栈归因结果（谁发起的：App / 第三方 SDK / 系统框架）。
    # 结构见 flow/attribution.py::summarize()。不放 facts 里是因为
    # 报告需要按它分栏渲染，而 facts 只是键值对表格。
    attribution: Dict[str, Any] = field(default_factory=dict)
    # 可点开核对的链接（政策 / 共享清单）。给人工复核用：
    # 结论说"政策未列明"，复核员得能自己打开那份政策看一眼。
    links: List[str] = field(default_factory=list)

    def merge(self, other: "ItemState") -> None:
        """同一测评项可能被多个阶段喂给，取更严重的那个（fail > suspect > pass）。

        为什么不取"最后一个"？因为阶段是按时间顺序跑的，
        而后面的阶段（比如 P6 逐项检测）拿到的证据往往比前面更弱，
        让弱证据覆盖强结论会让前面的实质发现凭空消失。
        """
        if STATE_ORDER.get(other.state, 9) < STATE_ORDER.get(self.state, 9):
            self.state = other.state
            self.desc = other.desc or self.desc
            self.reason = other.reason or self.reason
            self.level = other.level or self.level
            self.confidence = other.confidence or self.confidence
            self.source_phase = other.source_phase or self.source_phase
        self.evidence.extend(other.evidence)
        self.facts.extend(other.facts)
        self.stacks.extend(other.stacks)
        self.stack_meta.extend(other.stack_meta)
        self.shots.extend(other.shots)
        if other.attribution and not self.attribution:
            self.attribution = dict(other.attribution)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qid": self.qid, "title": self.title, "category": self.category,
            "state": self.state, "state_label": STATE_LABELS.get(self.state, self.state),
            "reason": self.reason, "desc": self.desc, "basis": self.basis,
            "unit": self.unit, "level": self.level, "confidence": self.confidence,
            "automation": self.automation, "source_phase": self.source_phase,
            "evidence": [e.to_dict() for e in self.evidence],
            "facts": [list(x) for x in self.facts],
            "stacks": self.stacks, "stack_meta": self.stack_meta,
            "shots": self.shots,
            "attribution": self.attribution,
        }


@dataclass
class ReportRow:
    """报告输出的一行（对应模板 22 项之一）。"""
    num: int = 0
    title: str = ""
    standard: str = ""
    clause: str = ""
    unit: str = ""
    conclusion: str = ""
    state: str = NOT_TESTED
    desc: str = ""                # 拼好的「问题描述 + 依据 + 认定为」
    example: str = ""
    note: str = ""
    checks: List[str] = field(default_factory=list)
    phases: List[str] = field(default_factory=list)
    auto: str = ""
    shots: List[Dict[str, str]] = field(default_factory=list)
    stacks: List[List[str]] = field(default_factory=list)
    # 与 stacks 一一对应的调用参数/取值（见 ItemState.stack_meta）
    stack_meta: List[Dict[str, Any]] = field(default_factory=list)
    facts: List[List[str]] = field(default_factory=list)   # 人工可逐条核对的事实表
    links: List[str] = field(default_factory=list)         # 可点开核对的链接
    attribution: Dict[str, Any] = field(default_factory=dict)  # 行为主体归因
    # 这一条结论是否建立在设备侧采集行为上（frida/traffic 证据）。
    # 采集类问题**必须**有调用栈；没有时报告要明说"未捕获"，
    # 而不是让读者以为"这条没有栈所以不用看栈"。
    needs_stack: bool = False
    sub: List[Dict[str, Any]] = field(default_factory=list)   # 各测评项的明细

    @property
    def is_problem(self) -> bool:
        return self.state in (FAIL, SUSPECT)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "num": self.num, "title": self.title, "standard": self.standard,
            "clause": self.clause, "unit": self.unit, "conclusion": self.conclusion,
            "state": self.state, "state_label": STATE_LABELS.get(self.state, self.state),
            "desc": self.desc, "example": self.example, "note": self.note,
            "checks": self.checks, "phases": self.phases, "auto": self.auto,
            "shots": self.shots, "stacks": self.stacks,
            "stack_meta": self.stack_meta, "sub": self.sub,
            "facts": self.facts, "links": self.links,
            "attribution": self.attribution,
            "needs_stack": self.needs_stack,
        }


@dataclass
class FlowResult:
    """一次完整流程的结果。"""
    package: str = ""
    app_name: str = ""
    version: str = ""
    source_market: str = ""
    operator: str = ""
    published_at: str = ""
    mode: str = "expert"
    started_at: float = 0.0
    ended_at: float = 0.0
    phases: List[PhaseResult] = field(default_factory=list)
    items: Dict[str, ItemState] = field(default_factory=dict)
    rows: List[ReportRow] = field(default_factory=list)
    static: Dict[str, Any] = field(default_factory=dict)
    link_inventory: List[Dict[str, str]] = field(default_factory=list)
    gaps: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    # ---- 交给人工复核员的材料 ----
    # 自动检测的价值在于「人工能快速验出我测的对不对」。光有结论不行，
    # 必须把可点开的链接、可重走的步骤、可查的静态事实一并留下：
    #   复核员不用重跑一遍，就能判断这个结论站不站得住。
    # policy_refs: 政策/共享清单文档（含完整 URL，可直接打开核对）
    # repro:       复现步骤（从清数据开始，写到第几步点哪里、看到什么）
    policy_refs: List[Dict[str, Any]] = field(default_factory=list)
    repro: List[str] = field(default_factory=list)
    apk_path: str = ""
    # ---- 目标应用本次是否压根没能启动 ----
    # 这一条决定的不是"某一项合不合规"，而是"这次检测成不成立"。
    # 三一卡车实测：App 冷启动即 SIGSEGV（阿里 AShield 加固壳与 MIUI 定制
    # boot classpath 冲突），采集期间进程反复退出 4 次、事件 5 条、UI 点击 0 次。
    # 此时若只在每项写"跳过未测"，复核员无从判断该不该重测 ——
    # 必须把"App 没打开"这个前提单独提出来，并把崩溃证据附上。
    app_crash: Dict[str, Any] = field(default_factory=dict)
    relaunch_count: int = 0
    # 采集侧搬来的运行期数据量（ui_steps / screens / events）。
    # 用来区分「压根没启动」与「跑起来了、中途重启过几次」——见 has_runtime_data。
    runtime_data: Dict[str, Any] = field(default_factory=dict)
    # 采集器本轮记录的异常原文（"App 进程退出，已第 N 次重启并重新注入"、
    # "采集脚本中途失效" 等）。原文照录，不做转述 ——
    # 复核员要判断的正是"检测工具当时到底遇到了什么"。
    scan_errors: List[str] = field(default_factory=list)
    # ---- 收尾：卸载被测应用 ----
    # 流程最后一步。既是为了不污染下一轮的"首启"前提，也是为了在共用设备上
    # 不留残余。结果进报告：命令、设备返回原文、卸载后复查结论，失败要写明。
    teardown: Dict[str, Any] = field(default_factory=dict)
    # ---- 证据图集 ----
    # 采集侧本来就把界面截图存了下来（`ScanResult.screenshots`，含 base64 PNG），
    # 但此前没有任何一处把它挂到报告项上 —— 每个问题块都印着
    # "本次自动化未采集到该项的界面截图，需人工补充"。人工复核的核心诉求正是
    # "看当时界面长什么样"，这一栏空着等于把最直观的证据丢掉了。
    #
    # 这里放**缩略图**（统一压到 420px 宽），整份报告只存一份；
    # 报告项用 index 引用（见 ReportRow.shots），不重复内嵌 base64。
    shots: List[Dict[str, Any]] = field(default_factory=list)
    # ---- 逐次点击留痕（2026-11-05）----
    # 一条一次点击：带点击标记的缩略图 + 点击目标/坐标 + 判读（谁选的、凭什么）
    # + 预判（点下去应该发生什么）+ 结果（实际换没换界面）。
    # ★ 与 `shots` 的分工：`shots` 是**按阶段抽的界面图**（support 某项结论），
    #   这里是**按动作留的过程图**（回答"你到底点了什么、有没有用"）。
    #   两者不能混：前者要给结论作证，后者要给过程作证。
    click_shots: List[Dict[str, Any]] = field(default_factory=list)
    # 点击留痕的汇总（换屏率、按预判种类的有效率、空点清单）。渲染时算，
    # 但也要落存档 —— 报告里那几个数字和存档必须一致。
    click_stats: Dict[str, Any] = field(default_factory=dict)
    # ---- 首启着陆（P3.5）----
    # 「点了同意」到「站在主页面」之间那一段：经过哪些形态、各用几步、
    # 有没有真的进主页面、没进去卡在哪。这一段以前是空白，报告读者看到
    # "只点了 3 次"会以为工具点不动，实际是应用把登录墙立在首屏。
    landing: Dict[str, Any] = field(default_factory=dict)
    # ---- 没被任何报告项引用的截图 ----
    # 报告项自己内嵌图之后，文末图集就只剩"这些图没挂到具体哪一项上"。
    # 仍然要列出：它们同样是本轮实测的界面留痕（例如没触发任何判定的中间页），
    # 复核员可能正是靠它看出"遍历走到了哪里"。
    shots_unused: List[Dict[str, Any]] = field(default_factory=list)
    # ---- 声明与实测的逐 SDK 对照（flow/declaration.py 产出）----
    # 报告里要能直接回答三句话：App 自己声明采了什么、每个 SDK 声明采了什么、
    # 哪个 SDK 实际采的比声明的多。只给一句"政策未列明设备标识符"回答不了。
    sdk_matrix: Dict[str, Any] = field(default_factory=dict)
    # ---- 权限申请场景（采集侧取证）----
    # 每次系统权限弹窗一条：权限名、弹窗原文、弹窗前的 App 界面说明、截图编号。
    # Q026「申请权限未同步告知目的」的全部依据都在这里。
    perm_scenes: List[Dict[str, Any]] = field(default_factory=list)
    # ---- 外跳去向（离开被测应用时去了哪里）----
    # 每条：入口文字 / 宿主包名 / Activity / 类别 / 是否留证 / 判决理由 / 截图编号。
    # ★ 与 `perm_scenes` 的分工：权限场景记的是"系统在哪一屏要权限"，
    #   外跳记的是"点了这个入口之后人到了哪个应用"。后者是两件事的唯一来源 ——
    #   「权限管理」入口是自建开关还是只能跳系统设置、有没有第三方授权登录。
    external_jumps: List[Dict[str, Any]] = field(default_factory=list)
    # ---- 测试账号 ----
    # 本轮是否注册/登录了测试账号（含脱敏号码与注册方式）。报告须说明，
    # 否则复核员不知道这份数据是在登录态还是游客态下采的。
    login: Dict[str, Any] = field(default_factory=dict)
    # ---- 同意动作（「同意前 / 同意后」的分水岭）----
    # 同意是整份报告唯一的时间分界点：它一旦记错，「未经同意收集」这一项
    # 会直接反向。所以不能只带一个布尔位上来 —— 要把每一次"看起来像同意"
    # 的点击都带上（时刻 / 按钮文字 / 触发路径 / 强度 / 是否确证 / 截图），
    # 让复核员能自己判断"凭什么认定用户在这儿同意了"。
    # 真机实测（以观书法 mbsf6）：AI 在政策下钻时顺手点了「同意并继续」，
    # 走的不是任何一条既有登记路径 → 布尔位始终 False、50 条事件全标
    # "同意前"、P3 写"未捕获到同意事件"，与正文时序结论互相打架。
    consent: Dict[str, Any] = field(default_factory=dict)
    # ---- 复现确认结果 ----
    # 每个 fail/suspect 项一条：是否复现、复现了几次、判据是什么、复现截图编号。
    repro_results: List[Dict[str, Any]] = field(default_factory=list)
    # 复现轮结束后的收尾（再次卸载被测应用）。第一轮的收尾记录在 teardown 里，
    # 复现又装了一次，就必须再说一次"装过、也卸了"，否则报告会少一段设备现状。
    repro_teardown: Dict[str, Any] = field(default_factory=dict)
    # 复现轮的**路径重放**结果：共几步、重放了几步、哪几步跳过、是否漂移/超时。
    # 报告要据此写清"这次复现走的是首轮同一条路径"，以及"有没有没走完的步"——
    # 没走完的步对应的项不能被算成"未复现"（见 flow/repro.py 的 `_replay_gap`）。
    repro_replay: Dict[str, Any] = field(default_factory=dict)
    # ---- P4 遍历的界面覆盖情况 ----
    # ★ 这一栏回答的是「这个结论覆盖了哪些界面、还有哪些没走到」。
    #   没有它，报告只能说"界面记录 25 个"——复核员既看不出 25 个够不够，
    #   也看不出"未发现该行为"是因为 App 没做，还是因为我们压根没走到那一屏。
    #   口径铁律：只在**到达过的界面**写"未发现"；没走到的写"未覆盖"。
    coverage: Dict[str, Any] = field(default_factory=dict)
    # ---- App 知识图谱（语义界面 + 跳转 + 权利入口可达性）----
    # ★ 与 `coverage` 的区别：coverage 是"走到了哪"，回答覆盖率；
    #   kgraph 是"这些界面之间怎么连、还剩什么没试、去权利入口要几步"，
    #   回答的是"凭什么这么走、凭什么说没找到"。
    #   两节在报告里分开写，混在一起复核员就分不清结论与路径。
    kgraph: Dict[str, Any] = field(default_factory=dict)
    # 图引导遍历的步数 / 自由规划步数（AI 究竟在哪一层起作用）
    ai_guided: int = 0
    ai_free: int = 0
    # ---- 本轮检测里 AI 到底参与了哪些环节 ----
    # ★ 为什么必须进报告：报告里 22 项结论长得一模一样，但来源不同 ——
    #   有的是关键词/结构树命中的，有的是模型读完政策正文补充的。复核员追问
    #   "这条是怎么来的"，只给结论就是黑盒。这里记开关状态 + 政策深读的实际
    #   状态（完成/跳过/失败原因）+ 覆盖段数，让每一处"模型读过"都能回溯。
    ai_used: Dict[str, Any] = field(default_factory=dict)
    # ---- 被排除的政策正文（第三方 SDK 的政策）----
    # 深挖遍历会点进意见反馈/客服这类第三方 SDK 页面，它们自带《隐私保护指引》。
    # 一旦被当成被测 App 的政策，所有政策类结论都会对着错误的文件下。
    # 排除动作与理由必须进报告：复核员要知道"我们看过、但认定它不是 App 的"。
    policy_rejected: Dict[str, Any] = field(default_factory=dict)
    # 采信的那份隐私政策的网址（只存 http(s)；正文来自安装包时为空）。
    # 对外版报告「隐私政策」一节靠它给链接，此前只能去 rows.links 里猜，
    # 猜到的常是界面收割的来源标签（"政策页面文本（滚动后）"），点不开。
    policy_url: str = ""
    # ---- 采集期被拒收 / 被顶替的候选正文 ----
    # P4 遍历会点开一堆长文本页面（会员协议、活动规则、第三方指引）。采集侧按
    # "是不是隐私政策"和"同不同站点"决定收不收，但**拒收本身也是证据**：
    #   · otherPolicyTexts    —— 看过但不是隐私政策（或异站），没收；
    #   · replacedPolicyTexts —— 收过，后来被更完整的同站正文顶掉。
    # 复核员据此能判断"政策确实是这份吗"，也能看出遍历到底翻到了什么。
    policy_side_texts: List[Dict[str, Any]] = field(default_factory=list)
    # ---- 测试机真实标识（设备标识符取值的比对基准）----
    # 船顺 2026-10-30：报告把百度统计 SDK 的 deviceId 写成「IMEI，取值 2Ees9i…」。
    # 没有这台机器的真实 IMEI/MEID/Android ID/序列号/MAC，就没法证伪，也没法证实。
    # 结构见 piiscan/device_ids.py:capture()。
    device_identities: Dict[str, Any] = field(default_factory=dict)
    # ---- 本轮检测档位与采集预算（2026-11-01）----
    # 报告要回答一个很具体的问题："这一轮到底按几档、给了多少时间、
    # 实际跑了多久"。没有这三项，"1 小时档没跑出更多东西"就只能靠猜 ——
    # 是档位没生效？是预算被提前终止？还是时间确实花掉了但没换来界面？
    depth: str = ""
    budget_seconds: int = 0
    scan_elapsed: int = 0
    # ---- 1 档「未同意状态探索」的实况（2026-11-17）----
    # 结构见 collector.ScanResult.pre_explore（taps/screens/refused_exit/
    # escapes/respawns/why）。必须进 flow.json：简版报告是使用者最先看的那份，
    # 里面若不写"这一轮到底点了几次、卡在哪"，"未发现问题"和"没测"在纸面上
    # 就还是一句话——这正是使用者质疑"跑了十几个 App 一个实锤都没有"的由来。
    pre_explore: Dict[str, Any] = field(default_factory=dict)
    # ---- 旁路取证（注入被加固拦死时的系统侧补证）----
    # 结构见 piiscan/bypass.py:collect()。报告里必须写清它的边界：
    # 只能证明"用过"，给不出调用栈、无法归因 —— 只能算"待人工确认"，不能当认定依据。
    bypass: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_runtime_data(self) -> bool:
        """本轮是否真的跑起来了（有可用运行期数据）。

        优先用采集侧直接搬来的计数（`runtime_data`），离线重渲染也走同一份；
        拿不到计数时退回"阶段状态 / 已判定项 / 界面覆盖"这三个侧面。
        """
        rd = self.runtime_data or {}
        if rd:
            return (int(rd.get("ui_steps") or 0) >= 5
                    or int(rd.get("screens") or 0) >= 5
                    or int(rd.get("events") or 0) >= 10)
        cov = self.coverage or {}
        if int(cov.get("app_states") or 0) > 0:
            return True
        p4 = self.phase("P4")
        if p4 is not None and p4.status in ("done", "partial"):
            return True
        return any(v.state != NOT_TESTED for v in (self.items or {}).values())

    @property
    def run_health(self) -> Dict[str, Any]:
        """采集期算好的「跑起来没有」。没有这份数据（旧存档）时返回空 dict。"""
        rd = self.runtime_data or {}
        h = rd.get("run_health")
        return dict(h) if isinstance(h, dict) else {}

    @property
    def app_start_failed(self) -> bool:
        cr = self.app_crash or {}
        # ★ 优先用"屏幕上有没有被测应用界面内容"这个判据（见 assess_run_health）。
        #   它比"点击次数/事件条数"更贴近用户能看见的事实：国象联盟那轮
        #   screens=4、events=5、点击 1 次，旧判据靠 relaunch_count>=4 才勉强判对；
        #   有朋公社 screens=13、events=45，旧判据判"跑起来了"，
        #   而那 12 屏全是读不到文字的空结构树，截图清一色是桌面。
        h = self.run_health
        if h.get("state"):
            return h["state"] in ("no_app", "no_ui", "no_dump")
        # 旧存档没有 run_health → 退回原来的三个侧面
        # 「过程中反复重启」不等于「压根没启动」：以观书法 mbsf6 遍历中退出 4 次
        # 被重启，但同轮完成 45 次点击、102 个界面、50 条事件。
        if self.has_runtime_data:
            return False
        if cr.get("found"):
            return True
        return int(self.relaunch_count or 0) >= 4

    @property
    def run_failed(self) -> bool:
        """整轮检测是否因「App 跑不起来」而作废（平台任务应据此判失败）。

        与 `app_start_failed` 同义，但语义更贴调用方：平台用它决定
        "这条任务算完成还是算失败"，不看报告里有多少项。
        """
        return bool(self.app_start_failed)

    @property
    def duration(self) -> float:
        return (self.ended_at - self.started_at) if self.ended_at else 0.0

    def phase(self, pid: str) -> Optional[PhaseResult]:
        for p in self.phases:
            if p.phase_id == pid:
                return p
        return None

    def stats(self) -> Dict[str, int]:
        s = {NOT_TESTED: 0, PASS: 0, SUSPECT: 0, FAIL: 0}
        for r in self.rows:
            s[r.state] = s.get(r.state, 0) + 1
        return {
            "total": len(self.rows),
            "fail": s[FAIL], "suspect": s[SUSPECT],
            "pass": s[PASS], "not_tested": s[NOT_TESTED],
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package, "app_name": self.app_name,
            "version": self.version, "source_market": self.source_market,
            "operator": self.operator, "published_at": self.published_at,
            "mode": self.mode, "duration": round(self.duration, 1),
            # 绝对时间也存一份：简版报告的「检测日期」、以及离线重渲染时
            # 判断"这批结论是哪天做的"，都只能从这里取（phases 里是相对耗时）。
            "started_at": self.started_at, "ended_at": self.ended_at,
            "phases": [p.to_dict() for p in self.phases],
            "items": {k: v.to_dict() for k, v in self.items.items()},
            "rows": [r.to_dict() for r in self.rows],
            "static": self.static,
            "link_inventory": self.link_inventory,
            "gaps": self.gaps,
            "notes": self.notes,
            "app_crash": self.app_crash,
            "relaunch_count": self.relaunch_count,
            "runtime_data": self.runtime_data,
            "scan_errors": self.scan_errors,
            "teardown": self.teardown,
            "shots": self.shots,
            # 点击留痕进存档，但**不带图**：图已经在 `scan.result.json` 里
            # （采集侧原样存着），flow.json 是给简版报告与看板用的，它不渲染
            # 点击图。带 200 张 base64 会把 flow.json 从几百 KB 撑到 4MB 以上，
            # 而每个页面加载都要读它。详细报告的重渲染走 --from-result，
            # 那条路径从 scan.result.json 取图，不受这里影响。
            "click_shots": [{k: v for k, v in it.items() if k != "b64"}
                            for it in self.click_shots],
            "click_stats": self.click_stats,
            "landing": self.landing,
            "shots_unused": [{k: it.get(k) for k in ("index", "label", "phase")}
                             for it in self.shots_unused],
            "sdk_matrix": self.sdk_matrix,
            "perm_scenes": self.perm_scenes,
            "external_jumps": self.external_jumps,
            "login": self.login,
            "consent": self.consent,
            "repro_results": self.repro_results,
            "repro_teardown": self.repro_teardown,
            "repro_replay": self.repro_replay,
            "coverage": self.coverage,
            "kgraph": self.kgraph,
            "ai_guided": self.ai_guided,
            "ai_free": self.ai_free,
            "ai_used": self.ai_used,
            "policy_rejected": self.policy_rejected,
            "policy_url": self.policy_url,
            "policy_side_texts": self.policy_side_texts,
            "device_identities": self.device_identities,
            "depth": self.depth, "budget_seconds": self.budget_seconds,
            "pre_explore": self.pre_explore,
            "scan_elapsed": self.scan_elapsed,
            "bypass": self.bypass,
            # 本次读到的各类声明文档（隐私政策 / 用户协议 / 清单…，带全文）。
            # 简版报告要内嵌"包内政策全文"——用户 2026-10-29 意见：详细版有全文，
            # 简版却只写"未取得隐私政策链接"，同一次检测两份报告自相矛盾。
            # 简版是**事后按 flow.json 现渲染**的，所以正文必须落在存档里。
            "policy_refs": self.policy_refs,
            "stats": self.stats(),
        }


__all__ = [
    "Evidence", "PhaseResult", "ItemState", "ReportRow", "FlowResult",
    "NOT_TESTED", "PASS", "SUSPECT", "FAIL", "STATE_LABELS", "STATE_ORDER",
    "PHASE_DONE", "PHASE_PARTIAL", "PHASE_SKIPPED", "PHASE_FAILED",
    "PHASE_PENDING", "PHASE_RUNNING", "PHASE_LABELS",
]
