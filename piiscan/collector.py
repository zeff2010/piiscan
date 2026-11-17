"""采集驱动：安装 -> 清除数据 -> 冷启动 -> 首启弹窗捕获政策 -> UI 遍历 -> 收集事件 -> 截图。

与旧版的区别（这是本轮重做的核心）：
  1. **先安装并清除应用数据**。不装不装、不清数据，App 就不会走「首启」流程，
     隐私弹窗不会出现，隐私政策也就无从获取 —— 这是之前「跑得飞快却没结果」的根因。
  2. **首启弹窗阶段**：优先观测第一个界面，识别隐私政策入口并点击，
     抓取真实的政策链接与 WebView 渲染正文（JS 渲染页也能拿到）。
  3. **同意判定改为显式驱动**：UI 遍历用 `input tap` 注入的是触摸事件，
     不经过 `Button.performClick`，所以靠 hook 按钮点击判断同意必然失效。
     现在由 Python 侧按「点击到的文字」显式调用脚本的 setConsent()。
  4. **分步截图 + 界面序列**：每个关键节点留截图与界面指纹，作为证据链。
  5. **网络去向归类**：把 K1 类外发事件按域名聚合，补齐误报漏斗第 4 级。
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
import threading
import time
from urllib.parse import urlsplit
from dataclasses import asdict, dataclass, field, fields as _dc_fields
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:                      # noqa: SIM105
    import frida
except Exception:         # pragma: no cover - 取决于部署形态
    # frida 是**动态采集**的依赖，不是整个平台的依赖：服务器上只跑
    # 静态分析 + 政策分析时不需要它（Alpine 上也没有现成 wheel）。
    # 顶层硬 import 会让 report/checklist/sop_job 这些都 import 不了，
    # 等于"没装 frida 连报告都渲染不出来"。
    frida = None


def _need_frida():
    if frida is None:
        raise RuntimeError(
            "未安装 frida（动态采集依赖）。仅做静态分析/政策分析时不需要；"
            "要跑动态采集请执行 pip install frida==16.7.18，"
            "版本须与设备上的 frida-server 一致")

from . import uiwalk
from . import policy as _POL
from . import device_ids as _DIDS
from . import bypass as _bypass
from . import clickev
from . import frida_guard as _fguard
from . import landing as landing_mod
from .ai import AITasks, build_tasks_safe
from .models import PIIEvent

# 页面图观测（P4 遍历的轨迹记录）。只观测不决策，见 flow/graph.py 文件头。
# 用 try 包住：观测是可选能力，绝不能因为它 import 失败让采集起不来。
try:
    from .flow import graph as pagegraph
except Exception:                     # pragma: no cover
    pagegraph = None                  # type: ignore[assignment]

# 遍历调度器（DFS + 价值表 + 死点）。见 flow/crawl.py 文件头。
try:
    from .flow import crawl as crawlsched
except Exception:                     # pragma: no cover
    crawlsched = None                 # type: ignore[assignment]

# App 知识图谱（语义节点 + 边 + 前沿/路径查询）。见 flow/kgraph.py 文件头。
# 同样用 try 包住：图引导是**增强**，import 失败就退回"规则调度 + 自由规划"，
# 采集本身不能因此起不来。
try:
    from .flow import kgraph as kgmod
except Exception:                     # pragma: no cover
    kgmod = None                      # type: ignore[assignment]

# 点击路径的规整与重放匹配（P7 复现按首轮路径重放）。见 flow/replay.py 文件头。
# 纯逻辑模块，不碰设备；try 包住的原因同上：缺了它就退回"整轮重跑"，
# 采集与判定都不受影响。
try:
    from .flow import replay as replaymod
except Exception:                     # pragma: no cover
    replaymod = None                  # type: ignore[assignment]

# 外跳判定：跳到系统设置/浏览器/别的 App 时，是"必留证的跳转"还是"没意义的跳转"。
# 见 flow/foreign.py 文件头。缺失时退回旧行为（一律返回 + 拉黑入口）。
try:
    from .flow import foreign as foreignmod
except Exception:                     # pragma: no cover
    foreignmod = None                 # type: ignore[assignment]

# 「政策由系统浏览器打开」时在浏览器里读正文（2026-11-03）。见 flow/docread.py：
# 春雨诊所/高途/携船网的政策都不在应用内，正文在浏览器那几屏里。
try:
    from .flow import docread as docread
except Exception:                     # pragma: no cover
    docread = None                    # type: ignore[assignment]

# 遍历台账 + 循环观测（2026-11-01）。见 flow/ledger.py 文件头：
# 台账让"AI 点的"和"规则点的"记进同一份账，LoopWatch 判振荡与僵局。
# 纯逻辑模块，import 失败就退回旧行为（只少了这三道闸，采集本身不受影响）。
try:
    from .flow import ledger as ledgermod
except Exception:                     # pragma: no cover
    ledgermod = None                  # type: ignore[assignment]

# 外部决策通道（2026-11-01）。见 flow/oracle.py 文件头：把"这一步点哪里"
# 交给外部（人/更强的模型），默认关闭，只在设了环境变量时才启用。
try:
    from .flow import oracle as oraclemod
except Exception:                     # pragma: no cover
    oraclemod = None                  # type: ignore[assignment]

HOOK_SCRIPT = Path(__file__).resolve().parent / "hooks" / "collector.js"

# 截图上限（内嵌进报告，过多会让 HTML 过大）
MAX_SHOTS = 14        # 只作为 ScanResult.max_shots 的默认值，实际以配置为准

# ★ 权限申请弹窗的截图**不占**普通配额，额外给这么多张。
#   为什么必须独立：`max_shots` 是给"沿路看看"的遍历截图用的，权限弹窗
#   却是要写进报告、让复核员确认"申请了什么权限、当时 App 说了什么用途"的
#   硬证据。真机实测（以观书法 mbsf5）14 张配额在遍历途中就用完了，
#   两次「照片」权限申请全部 shot=-1 —— 报告里权限项写着"未见用途说明"，
#   却连一张弹窗截图都拿不出来，人工复核无从下手。
#   权限弹窗数量有限（一轮通常 1~8 次），额外 20 张足够。
PERM_SHOT_EXTRA = 20

# ★ 同意动作（分水岭）的截图同样独立于普通配额。
#   同意那一刻是整份报告里唯一的时间分界点：复核员要判断"同意前收集"这一项时，
#   第一件事就是看当时的弹窗长什么样、点的是哪个按钮。让这张图去和遍历截图
#   抢 14 张的配额，等于把最关键的证据放在最容易被挤掉的位置。
CONSENT_SHOT_EXTRA = 2

# ★ 外跳取证图的配额，同样独立。
#   理由与权限弹窗同构，但多一层：外跳图**只给有价值的跳转**（系统设置里的权限页、
#   第三方授权页），一张图就是一条结论 —— "权限开关在系统里，App 自己没做"，
#   或者"这个功能要跳微信授权"。这类跳转一轮通常 1~5 次，8 张足够；
#   无意义的跳转（商店/相册/桌面）不占配额、也不留图，截了也没人看。
FOREIGN_SHOT_EXTRA = 8

# 外跳记录上限。一次异常 App 可能在几百次点击里反复外跳，无界增长会让
# result.json 与报告一起膨胀；超过上限后只累加计数，不再追加明细。
FOREIGN_MAX_ROWS = 40

# 「这次离开是点击造成的」的时间窗口（秒）。
# ★ 为什么必须有这道闸：设备上可能本来就开着别的应用（插着 USB 时的
#   「USB 详情」设置页、上一轮没退干净的浏览器、用户手动切走的微信）。
#   没有这道闸，这些东西会被归因到"最近点过的那个入口"，在报告里写成
#   "点『权限管理』跳到了系统设置"—— 一句凭空编出来的因果。
#   只在点击后 12 秒内（够 AI 决策 + 点击间隔 + 页面加载）才认这个因果。
FOREIGN_CAUSE_WINDOW = 12.0


def _is_perm_shot(sh: Dict[str, Any]) -> bool:
    """这张截图是不是权限申请弹窗的取证图。"""
    return str(sh.get("label") or "").startswith("权限申请")


def _is_consent_shot(sh: Dict[str, Any]) -> bool:
    """这张截图是不是同意动作（分水岭）的取证图。"""
    return str(sh.get("label") or "").startswith("同意动作")


def _is_foreign_shot(sh: Dict[str, Any]) -> bool:
    """这张截图是不是外跳去向的取证图。"""
    return str(sh.get("label") or "").startswith("外跳")


def _ordinary_shot_count(res: Any) -> int:
    """已占用的**普通**截图数（不含权限弹窗、同意动作、外跳取证图）。

    普通截图点用它与 `max_shots` 比较，让权限弹窗、同意动作、外跳去向各享一份配额。
    """
    return sum(1 for s in (getattr(res, "screenshots", None) or [])
               if isinstance(s, dict)
               and not _is_perm_shot(s) and not _is_consent_shot(s)
               and not _is_foreign_shot(s))


def _foreign_shot_count(res: Any) -> int:
    """已占用的外跳取证图数（有独立配额，不挤占普通遍历截图）。"""
    return sum(1 for s in (getattr(res, "screenshots", None) or [])
               if isinstance(s, dict) and _is_foreign_shot(s))

# 送给视觉模型的候选人选上限。
# 为什么限流：候选全画上去，截图会被几十个框糊住，
# 模型的判断反而变差（实测框超过 ~25 个时，它开始漏看关键元素）。
# 因此只把"最可能是政策入口/最值得点"的那批送过去，其余交给规则兜底。
AI_CANDIDATE_CAP = 26

# 首启观测阶段：最多等这么久来找隐私弹窗
POPUP_WAIT_DEFAULT = 22

# 冷启动等待上限。frida 默认只有 10s，对大厂 App（滴滴出行等）不够：
# 类加载 + 加固壳解密 + Application.onCreate 动辄十几秒，超时后报
# "unexpectedly timed out while waiting for app to launch"，
# 于是「App 退出 → 重启并重新注入」这条自愈链路会 100% 失败，
# 整个遍历随之报废（实测滴滴出行连续 4 次重启全部失败，UI 点击 0 次）。
SPAWN_TIMEOUT = 30


def _stop_requested(should_stop: Optional[Callable[[], bool]]) -> bool:
    """外部是否要求停止采集。

    任何异常都当作"不停止"：取消检查本身绝不能成为新的崩溃点 ——
    它只是让采集能早点收工，不该有资格搞坏一次正常检测。
    """
    if should_stop is None:
        return False
    try:
        return bool(should_stop())
    except Exception:
        return False


def _check_screen(serial: str, log: Callable[[str], None],
                  last: Dict[str, float], min_gap: float = 15.0) -> str:
    """定期看屏幕是不是黑的；睡了就点亮。返回本次查到的状态（可能为空）。

    ★ 为什么值得单独做（2026-11-11 用户报障："手机界面一直全黑"）
      黑屏时 uiautomator 拿不到任何界面，遍历每轮都在"点不到东西"——
      日志读起来像应用坏了，但可能只是屏幕睡了。两者处置完全不同：
      屏幕睡了叫醒就行；应用黑了才该按"界面无法读取"记账。
      查得太勤会白花 adb 往返（一次 ~0.4s），所以按 min_gap 限制频率。
    """
    now = time.time()
    if now - float(last.get("t", 0.0)) < min_gap:
        return ""
    last["t"] = now
    st = uiwalk.screen_state(serial)
    if st and st != "Awake":
        log("[!] 屏幕处于 %s：先点亮再继续（黑屏时点击与结构导出都拿不到界面）" % st)
        uiwalk.wake(serial)
        time.sleep(1.0)
        uiwalk.dismiss_keyguard(serial)
    return st


def _sleep_cancellable(seconds: float,
                       should_stop: Optional[Callable[[], bool]] = None,
                       slice_s: float = 0.4) -> bool:
    """可被打断的等待。返回 True 表示等待期间被要求停止。

    为什么不用一次 time.sleep：首启观测要等 20 多秒，遍历预算动辄半小时，
    一次 sleep 下去，停止请求就得等它睡醒才生效 —— 使用者会以为按钮没反应。
    按片睡，最迟 slice_s 秒内响应。
    """
    left = max(0.0, float(seconds))
    while left > 0:
        if _stop_requested(should_stop):
            return True
        step = min(slice_s, left)
        time.sleep(step)
        left -= step
    return _stop_requested(should_stop)


class _Live:
    """当前活跃的 Frida 会话句柄。

    因为 App 可能在采集期间退出，需要在遍历中重新 spawn + 重新注入，
    所以会话不能在 run_scan 里用局部变量锁死，要用可变对象持有。
    """

    def __init__(self) -> None:
        self.pid: Optional[int] = None
        self.session: Any = None
        self.script: Any = None
        # 本轮到底有没有真的注入成功。False 时 `script` 是 `_NoScript`，
        # 所有"向脚本要数据"的调用都会拿到 None，调用方必须容忍。
        self.hooked: bool = False


class _NoExports:
    """`_NoScript.exports_sync` 的替身：任何方法调用都返回 None，永不抛异常。"""

    def __getattr__(self, name):
        def _noop(*_a, **_k):
            return None
        return _noop


class _NoScript:
    """未注入时的脚本替身。

    2026-10-27 小盒课堂（爱加密）实测：`device.spawn` 在加固壳解壳期间
    干等 30 秒后抛 `TimedOutError: unexpectedly timed out while waiting for
    app to launch`，整轮任务直接判失败，连一张截图、一个字政策正文都没留下。
    但"注入不了"和"应用跑不起来"是两件事 —— 加固包不给 hook 机会，
    界面/政策/权限弹窗这些肉眼可见的证据照样能采。

    所以注入失败时降级为"仅界面采集"，用这个替身接住下游所有
    `script.post(...)` / `exports_sync.xxx()` 调用，保证采集流程继续走完。
    报告侧通过 `res.hook_hostile` → `hook_blocked` 说明"检测手段受限"。
    """

    def __init__(self) -> None:
        self.exports_sync = _NoExports()

    def post(self, *_a, **_k) -> None:
        return None

    def on(self, *_a, **_k) -> None:
        return None

    def load(self, *_a, **_k) -> None:
        return None

    def unload(self, *_a, **_k) -> None:
        return None


@dataclass
class ScanResult:
    package: str
    device_serial: str = ""
    device_model: str = ""
    android_version: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0
    events: List[PIIEvent] = field(default_factory=list)
    hooks_installed: List[str] = field(default_factory=list)
    hooks_failed: List[str] = field(default_factory=list)
    # ---- 旁路取证（2026-10-31）----
    # 注入被加固拦死时，改从系统侧取"这个包最近用过哪些敏感操作、运行时权限授没授"。
    # 见 piiscan/bypass.py 文件头：证据力弱于调用栈，但足以把"跳过未测"变成
    # "有旁证、待人工确认"。取不到就写成空字典，报告里如实说"系统未提供"。
    bypass: Dict[str, Any] = field(default_factory=dict)
    consent_given: bool = False
    consent_elapsed_ms: Optional[int] = None
    consent_source: str = ""
    # ---- 同意动作的逐条取证（分水岭）----
    # ★ 为什么光有上面三个字段不够：
    #   `consent_given` 只是一个布尔位，报告里说不清"凭什么认定用户同意了"。
    #   而"同意"恰恰是整份报告里唯一的时间分界点 —— 它一错，
    #   「未经同意收集」这一项就直接反向（把违规洗白，或把合规冤枉）。
    #   真机实测（以观书法 mbsf6）：政策下钻时 AI 顺手点了「同意并继续」，
    #   界面确实变了，但那条点击走的不是"点同意"那条代码路径，
    #   于是 consent_given 一直是 False、50 条事件全标"同意前"，
    #   P3 写"未捕获到同意事件"，与正文"时序不可分辨"互相打架。
    # 这里逐条记下每一次"看起来像同意"的点击：
    #   {"elapsed_ms", "label", "via", "strength", "watershed", "verified",
    #    "screen_label", "screenshot_idx", "sync", "why"}
    #   watershed=True 的那一条才是分水岭（只认第一条）。
    consent_events: List[Dict[str, Any]] = field(default_factory=list)
    # 静态分析挑出的政策候选链接。开局就按它直取全文，取不到才回界面滑读。
    policy_urls: List[str] = field(default_factory=list)
    # ---- 测试机真实标识（取值比对基准）----
    # ★ 船顺 2026-10-30：报告把百度统计 SDK 的 deviceId（base64 的 16 字节摘要）
    #   写成了「IMEI，取值 2Ees9iP1Vln2NcCzcUVVHg==」。要证伪这种写法，只能靠
    #   开测前把本机真实的 IMEI / MEID / Android ID / 序列号 / MAC 取下来比对。
    #   结构见 piiscan/device_ids.py:capture()。
    device_identities: Dict[str, Any] = field(default_factory=dict)
    # 本轮实际生效的检测档位与采集预算（秒）（2026-11-01）。
    # 为什么要落盘到结果里：查"1 小时档为什么没比 15 分钟多出东西"时，
    # 第一件事就是确认这一轮到底按几档、多少预算在跑。以前这些只在启动日志，
    # 结果文件与报告里都查不到，隔一天就只能靠回忆当时点的是哪个档。
    depth: str = ""
    budget_seconds: int = 0
    # 分水岭的认证强度：explicit（弹窗明示「同意」按钮）/
    # checkbox（登录页勾选「我已阅读并同意」）/ script（采集脚本观测到 performClick）
    consent_strength: str = ""
    summary: Dict[str, Any] = field(default_factory=dict)
    screenshots: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    # UI 遍历统计
    ui_taps: int = 0
    ui_steps: List[str] = field(default_factory=list)
    # ---- 可重放的点击路径（P7 复现用）----
    # `ui_steps` 是给人看的字符串（"3. 点击「我的」（RadioButton）"），
    # 没法据此再点一遍。这里按执行顺序记结构化动作，复现轮照着走：
    #   {"kind":"tap","label":"我的","cls":"...","uid":"id/tab_4",
    #    "bounds":[..],"at":[x,y],"fp":"<执行前界面指纹>","src":"ai|sched|rule","t":12.3}
    #   {"kind":"back"} / {"kind":"swipe","dir":"down","scroll":true} / {"kind":"pull"}
    # 只记**执行成功**的动作：点了没反应、被危险闸门拦下的都不进路径，
    # 否则复现轮会把首轮的空转也复现一遍，白花时间还污染事件。
    ui_path: List[Dict[str, Any]] = field(default_factory=list)
    # 复现轮的回放结果摘要（首轮为空）
    ui_replay: Dict[str, Any] = field(default_factory=dict)
    # 1 档「未同意状态探索」的结果摘要（其他档位为空）
    #   {"taps":12, "screens":5, "visited":[...], "refused_exit":[{...}],
    #    "budget":240.0, "why":""}
    # ★ 为什么单独记一个字段、而不是去 ui_steps 里数：
    #   ui_steps 是给人看的字符串，判定"有没有探索过"要靠文本匹配
    #   （原来的写法是找"同意"二字之前的步数）。可"点击「不同意」"里
    #   就带"同意"两个字，一匹配就被当成同意动作截断 —— 探索记录反而
    #   把探索判成没做。结构化字段没有这个问题。
    pre_explore: Dict[str, Any] = field(default_factory=dict)
    locked_at_start: bool = False
    # 新增：界面序列 / 政策捕获 / 网络去向 / SDK / 安装情况
    screens: List[Dict[str, Any]] = field(default_factory=list)
    policy_capture: Dict[str, Any] = field(default_factory=dict)
    network_sinks: List[Dict[str, Any]] = field(default_factory=list)
    sdks_detected: List[Dict[str, Any]] = field(default_factory=list)
    install: Dict[str, Any] = field(default_factory=dict)
    first_launch_popup: bool = False
    popup_evidence: List[str] = field(default_factory=list)
    overlays_dismissed: List[str] = field(default_factory=list)
    # 反自动化拦截（滑块/人机验证）——命中时本轮采集的"界面行为"证据基本作废，
    # 必须在报告里显著标注，否则会把「采不到」误读成「App 没做」
    captcha_hits: List[str] = field(default_factory=list)
    # ---- AI 参与过程（可审计）----
    # 每次让模型做判断都留一条记录：看了哪张图、模型的结论、我们据此做了什么。
    # 报告里要能回答「这个结论是 AI 判的还是规则判的、依据是什么」——
    # 否则 AI 的参与就变成了不可复核的黑盒，检测底稿也就失去意义。
    ai_enabled: bool = False
    ai_vision: bool = False
    ai_trace: List[Dict[str, Any]] = field(default_factory=list)
    # 等模型回答累计耗时。这段设备只是在等，不是采集时间；
    # 采集预算会把它扣回去，避免"AI 一慢，遍历就没时间跑"。
    ai_wait_seconds: float = 0.0
    # 其中"遍历开始之前"（首启观测 + 着陆）花掉的那一份（2026-11-10）。
    # ★ 为什么必须单记：`ai_wait_seconds` 是整轮累计，而 SOP 的 P1 只覆盖
    #   "冷启动 → 同意"这一段。拿全局数往 P1 上贴，就会写出
    #   "P1 其中等待模型判断累计 118s"，而日志里 P1 实际只等了 4 秒 ——
    #   那一轮 118 秒里的大部分发生在遍历阶段，与 P1 无关。
    #   CNC宝典 4 档实测：P1 真值 4s，旧口径写成 118s（差 30 倍）。
    ai_wait_pre_walk: float = 0.0
    ai_errors: List[str] = field(default_factory=list)
    ai_stats: Dict[str, Any] = field(default_factory=dict)
    ai_notes: List[str] = field(default_factory=list)
    # ---- 报告层生成的问题描述（落盘保留）----
    # ★ 为什么必须存进 result.json（简小知 jxz3 发现）：
    #   报告叙述原本只在渲染那一刻生成、用完即弃，于是 `tools/rerender_report.py`
    #   重渲染时只能改用内置模板 —— 同一份采集样本，隔一天再出一份报告，
    #   AI 写过的文字就没了。改一次排版要重新花十几分钟跑真机才能拿回原文。
    #   存下来之后：AI 成果可复现、可离线改模板、可对比两版模型输出。
    #   形如 [{"group_key": "...", "narrative": "...", "source": "ai|template"}]。
    narratives: List[Dict[str, Any]] = field(default_factory=list)
    # ---- 阶段真实耗时锚点（相对冷启动的毫秒）----
    # ★ 为什么必须记在采集侧（简小知 flow_live2 实测发现）：
    #   流程编排器（flow/sop.py）是在真机采集**结束之后**才跑的，它自己的墙钟
    #   只覆盖"读存档 + 算判定"，于是报告里 P1~P4 的耗时全是 0.0~0.2 秒 ——
    #   人工复核员一看「检测了 3 分钟，每个阶段却只花 0.2 秒」，立刻会怀疑
    #   检测方法有问题。真实耗时只有采集器自己知道：它确实在设备前等了那么久。
    #   记的是**相对冷启动的毫秒**。锚点名与含义：
    #     scan_start=0 / app_launched=进程起来 / observe_start=开始找隐私弹窗 /
    #     policy_tap=点到政策入口 / policy_text=取到政策正文 / consent=捕获到同意 /
    #     walk_start=开始遍历 / scan_end=采集结束
    marks: Dict[str, int] = field(default_factory=dict)
    # ---- 目标应用「起不来」的取证（三一卡车实测发现）----
    # 那一轮采集：App 每次冷启动都 SIGSEGV，进程起来 0 秒即死，反复重启 4 次后放弃。
    # 22 项报告项全部落到"跳过未测"，但报告里**没有一个字**说明 App 根本没打开 ——
    # 复核员只会读成"没测出来"。所以把崩溃事实与证据（信号 / 出错地址 /
    # 地址落在哪个库的哪个段 / 复现命令）一并存档，报告层必须显式写出来。
    app_crash: Dict[str, Any] = field(default_factory=dict)
    relaunch_count: int = 0
    # ---- 加固机制拦截注入（洋葱学园 2026-10-27）----
    # 真机实测：百度加固的 App 会 fork 出新进程跑真实代码，我们开场注入的是
    # 被 fork 掉的那个；等检测到"脚本失效"再 re-attach 新进程时，
    # **加固机制立刻判定为调试并自杀**（3 秒内 pid 消失、前台退回桌面）。
    # 旧逻辑把它当成"App 进程退出 → 重启 → 再注入"，于是自己把应用一遍遍弄死，
    # 最后写进报告"应用未能正常运行"—— 而用户站在手机前看，应用明明开着。
    # 计数 ≥1 即表示"重新附着会杀应用"，此后一律不注入、只做界面采集。
    hook_hostile: int = 0
    hook_reattach_at: float = 0.0
    # ★ 2026-10-27 真机对照实验（洋葱学园），把"注入失败"拆成了两种，
    #   因为它们的补救办法完全相反：
    #     · 不注入：进程 14 秒稳定、首启隐私弹窗完整显示；
    #     · spawn 注入：2 秒内进程消失、系统重新拉起（壳判调试后自杀）。
    #   所以"re-attach 被杀就改用 spawn 重建"这条思路，在**壳连 spawn 都杀**
    #   的应用上是无效的 —— 重建一次就多杀一次应用、多丢一次界面进度。
    #   只有 spawn 注入本身活得好、只有 re-attach 会触发自杀时，重建才值得。
    # hook_spawn_at：最近一次"新建注入会话（spawn + 注入）"的时刻，
    #                用来判定紧随其后的进程消失是不是我们注入造成的。
    # hook_spawn_killed：spawn 注入后 12 秒内进程消失的次数。>0 = 壳连冷启动
    #                注入都杀 → 此后一律不注入，只做界面采集。
    hook_spawn_at: float = 0.0
    hook_spawn_killed: int = 0
    # re-attach 致死过 → 禁止再 rehook，但**允许**用 spawn 重建顶上。
    reattach_banned: bool = False
    # spawn 走不通时"先启动、再附着"的结果：ok / failed / skipped / ""
    # （2026-10-27 用户建议的降级链第二级：spawn 超时不等于注入无望）
    attach_after_spawn_fail: str = ""
    # 不注入时应用自己能不能活：{"started": bool, "pids": [...], "why": str,
    # "evidence": "..."}。用来把"应用在本机起不来"与"检测手段受限"分开 ——
    # 旧报告对小盒课堂写的是后者，而实测它 60 ms 就死（SELinux 拦 execmod）。
    app_start_probe: Dict[str, Any] = field(default_factory=dict)
    # 是否亲眼确认过"前台切到了被测应用"（await_app_foreground 成功过一次）。
    # 用它区分"应用没起来"与"应用起来了但界面读不出来"—— 两者结论完全不同。
    app_foreground_seen: bool = False
    # 设备侧记下的该应用最近崩溃记录（`am_crash` / `am_proc_died` 原始行）。
    # ★ 为什么必须落这条（2026-11-08 小包搜题）：加固壳被注入后自杀，界面上
    #   只表现为"应用一直没出现"。报告若只写"未观测到前台"，读者无法区分
    #   "应用起得慢"和"应用被我们弄死了"—— 而这两件事的整改建议完全不同。
    #   `am_crash` 是系统自己记的，带信号类型（实测：Native crash /
    #   Segmentation fault，发生在进程启动后 1.4 秒），属于可复核的现场证据。
    app_crash_evidence: List[str] = field(default_factory=list)
    # ---- 协作式取消（暂停/停止）----
    # ★ 为什么采集要能被中断：一轮真机采集动辄 20~45 分钟。任务一旦交出去，
    #   使用者随时可能想停下来（发现传错包、要优先跑别的）—— 若只能等它跑完，
    #   "停止任务"就成了一句空话。中断时**已采到的数据全部保留**，
    #   aborted=True 用来告诉上层"这份存档不完整，不要拿它出正式结论"。
    aborted: bool = False
    abort_reason: str = ""
    # ---- 系统权限申请场景 ----
    # 每一次系统权限弹窗一条：权限名、弹窗原文、弹窗**之前**那一屏的文字
    # （用途说明往往在前一屏或前一个浮窗里）、截图编号、检测脚本代点的选项。
    # Q026「申请权限未同步告知目的」的全部依据都在这里；没有这一栏，
    # 报告对权限就只剩一句"未获取到权限场景"。
    perm_scenes: List[Dict[str, Any]] = field(default_factory=list)
    # ---- 外跳（离开被测应用的去向）----
    # ★ 为什么必须单独记：遍历里"跳到系统设置 / 浏览器 / 微信"跟"点了没反应"
    #   在旧代码里是同一件事 —— 一律按返回键退回来，什么也不留。于是报告无法
    #   回答两个很关键的问题：
    #     · 「权限管理」入口是本 App 自建的开关，还是只能把用户推去系统设置？
    #     · 有没有第三方授权登录（微信/一键登录）—— 那意味着设备标识与头像昵称
    #       会流向第三方，与「第三方共享清单」一项直接相关。
    #   这里逐条记下：在哪个入口点的、去了哪个应用/页面、判定为必要还是无意义、
    #   有没有留证截图。无意义的跳转同样要记 —— 它是"这个入口对取证无用"的结论。
    #   形如 {"seq", "entry", "pkg", "activity", "kind", "label", "valuable",
    #         "why", "screenshot", "ts"}
    external_jumps: List[Dict[str, Any]] = field(default_factory=list)
    # ---- 登录 / 注册辅助 ----
    # 本轮是否用测试账号登录过（含注册方式、脱敏号码、成功与否）。
    # 报告必须写明，否则复核员不知道这批数据是登录态还是游客态采的。
    login: Dict[str, Any] = field(default_factory=dict)
    # ---- 复现轮次记录 ----
    # P7 复现是第二轮采集，单独记录结果，不与首轮证据混在一起。
    repro: Dict[str, Any] = field(default_factory=dict)
    # ---- 本轮截图上限 ----
    # 为什么挂在结果对象上而不是模块常量：深/常规两档的证据量差四五倍，
    # 而模块常量是进程级共享的 —— 平台一次跑多个任务时，
    # 后启动的任务会把前一个任务正在用的上限改掉（改小的那一瞬间，
    # 前一个任务的截图就被静默截断了）。放在结果上就没有这个问题。
    max_shots: int = 14
    # ---- 逐次点击留痕（2026-11-05 用户要求）----
    # 每一次点击一条：点击前的界面截图（已在点击位置画了标记，JPEG base64）、
    # 点的是哪个元素、坐标、这一步是谁选的/凭什么、点下去之前的**预判**、
    # 以及点完之后界面到底有没有变。
    #
    # 为什么不能再靠"UI 点击 124 次"这种合计数字：复核员没法判断这 124 次
    # 里有多少是有效的。真机实测里有整轮 124 次点击、结果 75 屏"点了没反应"，
    # 只看总数会得出"遍历很充分"的错误印象。
    #
    # 只存压缩后的缩略图（360px / q66，约 20KB），不存原图：整屏 PNG 一张
    # 1~2MB，120 次点击就是 200MB，存档和报告都打不开。
    click_shots: List[Dict[str, Any]] = field(default_factory=list)
    max_click_shots: int = 400
    # 首启着陆（P3.5）：从「点了同意」走到「站在主页面」之间的过程。
    # 空字典 = 没走到这一步（1 档 / 应用起不来 / 旧存档）。
    landing: Dict[str, Any] = field(default_factory=dict)
    # ---- P4 遍历的页面图观测（Step 1：只记录，不参与决策）----
    # 为什么要存下来：现在报告只能说"界面记录 25 个"，无法回答"还有哪些入口
    # 没走到"。这张图是覆盖率度量的底料 —— 状态（界面）与边（点了哪个元素、
    # 跳到了哪、结果如何），以及重复点击/死点/未探索入口三项指标。
    # 结构见 flow/graph.py：{"stats": {...}, "states": [...], "edges": [...]}。
    graph: Dict[str, Any] = field(default_factory=dict)
    # 观测口径的摘要（与 graph.stats() 同源，单独留一份便于报告层直接读）。
    coverage: Dict[str, Any] = field(default_factory=dict)
    # ---- App 知识图谱（语义节点 + 图引导）----
    # 与上面 `graph` 的区别：`graph` 是**结构记账**（结构指纹、点击、死点），
    # 给报告算覆盖率；`kgraph` 是**语义视图 + 决策依据**（界面角色、未探索动作、
    # 目标路径）。两者同源不同口径，报告里分别对应「界面覆盖情况」与
    # 「界面跳转图谱」两节 —— 混成一个会让人分不清"走到哪"和"凭什么这么走"。
    kgraph: Dict[str, Any] = field(default_factory=dict)
    # 图引导遍历的步数（在有限动作集里选）与自由规划步数（无选项时回头看图）。
    # 报告要能说清"这一轮 AI 究竟在哪一层起作用"，否则"AI 遍历"是个空口径。
    ai_guided: int = 0
    ai_free: int = 0
    # AI 给界面起的名字（fp → 一句话），复核员用它读懂"这一屏是什么"。
    kg_names: Dict[str, str] = field(default_factory=dict)

    @property
    def marks_sorted(self) -> List[Tuple[str, int]]:
        return sorted(self.marks.items(), key=lambda kv: kv[1])

    @property
    def has_runtime_data(self) -> bool:
        """本轮是否真的跑起来了（有可用运行期数据）。

        判据取"确有交互痕迹"：UI 点击步骤、界面记录、行为事件三者任一够量。
        """
        return (len(self.ui_steps or []) >= 5
                or len(self.screens or []) >= 5
                or len(self.events or []) >= 10)

    @property
    def app_start_failed(self) -> bool:
        """目标应用是否压根没能跑起来（而非"跑起来了但没采到行为"）。

        ★ 判据是「进程反复退出 **且** 没有任何运行期数据」。
          只说 relaunch_count 是不够的：真机实测（以观书法 mbsf6）遍历过程中
          App 因客服页/悬浮窗退出 4 次被自动重启，但同一轮完成了 45 次点击、
          记录 102 个界面、50 条事件 —— 照旧判"未能启动"，报告就会写
          "本轮未取得任何运行期行为数据"，与它自己后面的界面覆盖表直接打架。
          崩溃转储同理：中途崩过不等于没启动过。
        """
        if self.has_runtime_data:
            return False
        return int(self.relaunch_count or 0) >= 4 or bool(
            (self.app_crash or {}).get("found"))

    @property
    def duration(self) -> float:
        return max(0.0, self.ended_at - self.started_at)

    @property
    def before_consent_events(self) -> List[PIIEvent]:
        return [e for e in self.events if e.before_consent]

    @property
    def events_by_level(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for e in self.events:
            out[e.evidence] = out.get(e.evidence, 0) + 1
        return out

    # ------------------------------------------------------------ 存档 / 复现
    def to_dict(self) -> Dict[str, Any]:
        """完整导出本次采集（含事件与政策捕获），用于落盘 result.json。

        为什么要有：报告模板或渲染代码每改一次，就得重跑一次真机采集
        （十几分钟，且真机每次状态不同、样本不可复现），成本高到无法迭代。
        落盘之后，报告层改动可以秒级重渲染校验，同一份样本反复比对。
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScanResult":
        """从 result.json 还原。

        事件要还原成 PIIEvent 对象而不是留在 dict ——
        报告层（renderer / group_events / 规则层）都是按对象属性访问的，
        留成 dict 会在渲染时才炸，且报错位置离根因很远。
        """
        known = {f.name for f in _dc_fields(cls)}
        kwargs: Dict[str, Any] = {k: v for k, v in (d or {}).items() if k in known}
        evs = kwargs.get("events") or []
        kwargs["events"] = [e if isinstance(e, PIIEvent) else PIIEvent(**{
            k: v for k, v in e.items()
            if k in {f.name for f in _dc_fields(PIIEvent)}}) for e in evs]
        return cls(**kwargs)


def _adb_args(serial: str) -> List[str]:
    # 路径解析统一在 adbtool（2026-11-12）：这里若自己读 `ADB` 环境变量，
    # 用户没配 ADB 但 adb 在 PATH / SDK 目录里时，本模块就找不到它。
    from .adbtool import adb_exe
    return [adb_exe()] + (["-s", serial] if serial else [])


def _run(args: List[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, timeout=timeout)


def capture_screenshot(serial: str) -> Optional[bytes]:
    try:
        proc = _run(_adb_args(serial) + ["exec-out", "screencap", "-p"], timeout=25)
        if proc.returncode == 0 and proc.stdout[:8] == b"\x89PNG\r\n\x1a\n":
            return proc.stdout
    except Exception:
        return None
    return None


def app_in_foreground(serial: str, package: str) -> Optional[bool]:
    """被测应用是否在前台。True / False；取不到前台信息时返回 None（不确定）。

    ★ 为什么单独抽出来（2026-11-09 聚橙票务 / 爱思投屏）：
      截图落在系统桌面上，但报告把它当成"应用在运行中弹出的权限框"的证据。
      真相是那一轮应用已经被加固壳杀掉、或正在重新拉起，屏幕上根本没有应用。
      取不到前台信息时返回 None，调用方要按"不确定"处理 —— 不能拿 None
      当成"在前台"，也不能当成"不在前台"。两种误判都会写错结论。

    ★ 判据只认**窗口焦点**（2026-11-10 铁路火车票）：原来调 `current_focus()`，
      它在 `mCurrentFocus` 为空时兜底读 `mResumedActivity`，于是"应用还活着但
      屏幕上是桌面/系统界面"这种情形一律被判成"应用在前台"。现在改由
      `uiwalk.foreground()` 统一读，`via != window` 就直接返回 None（读不到就
      说读不到），不再拿 Activity 的运行态冒充"用户看得到"。
    """
    try:
        fg = uiwalk.foreground(serial)
    except Exception:
        return None
    if (fg.get("via") or "") != "window":
        return None
    return uiwalk.visible_from_focus(fg.get("focus") or "", package)


def device_info(serial: str) -> Dict[str, str]:
    def prop(name: str) -> str:
        try:
            proc = _run(_adb_args(serial) + ["shell", "getprop", name], timeout=10)
            return proc.stdout.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""
    return {
        "model": prop("ro.product.model"),
        "android": prop("ro.build.version.release"),
        "sdk": prop("ro.build.version.sdk"),
    }


def find_running_pid(serial: str, package: str) -> Optional[int]:
    """通过 pidof 查进程。

    注意：Frida 枚举出的进程名往往是 App 的中文/英文标签（如 "Frida 0x1"），
    而不是包名，直接用包名匹配会找不到。所以这里问系统拿 pid 更可靠。
    """
    try:
        proc = _run(_adb_args(serial) + ["shell", "pidof", package], timeout=15)
        out = proc.stdout.decode("utf-8", errors="replace").strip()
        if out:
            return int(out.split()[0])
    except Exception:
        pass
    return None


def resolve_device(cfg):
    _need_frida()
    if cfg.device.serial:
        try:
            return frida.get_device(cfg.device.serial, timeout=10)
        except Exception:
            pass
    return frida.get_usb_device(timeout=10)


# ---------------------------------------------------------------- 安装与清数据

def is_installed(serial: str, package: str) -> bool:
    try:
        p = _run(_adb_args(serial) + ["shell", "pm", "path", package], timeout=20)
        return b"package:" in (p.stdout or b"")
    except Exception:
        return False


def installed_version(serial: str, package: str) -> str:
    try:
        p = _run(_adb_args(serial) + ["shell", "dumpsys", "package", package], timeout=25)
        out = (p.stdout or b"").decode("utf-8", errors="replace")
        m = re.search(r"versionName=(\S+)", out)
        return m.group(1) if m else ""
    except Exception:
        return ""


def install_apk(serial: str, apk_path: str, package: str = "",
                log: Callable[[str], None] = print) -> Dict[str, Any]:
    """安装待测 APK 到设备。

    关键：**不加 `-g`**。`-g` 会在安装时一次性授予全部运行时权限，
    那样 App 就不会弹权限框，我们就看不到「申请权限未同步告知目的」这类行为。
    """
    info: Dict[str, Any] = {"ok": False, "steps": [], "note": ""}
    apk_path = str(apk_path)
    if not Path(apk_path).exists():
        info["note"] = "APK 文件不存在"
        return info

    existed = is_installed(serial, package) if package else False
    old_ver = installed_version(serial, package) if existed else ""

    def do_install() -> subprocess.CompletedProcess:
        return _run(_adb_args(serial) + ["install", "-r", "-d", apk_path], timeout=420)

    log("[*] 安装待测应用：%s" % Path(apk_path).name)
    p = do_install()
    out = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace")
    if "Success" not in out and existed:
        # 签名不一致等情况无法覆盖安装 → 先卸载再装
        log("[!] 覆盖安装失败（%s），先卸载再安装" % out.strip().splitlines()[-1][:70])
        info["steps"].append("覆盖安装失败，已卸载重装")
        _run(_adb_args(serial) + ["uninstall", package], timeout=180)
        p = do_install()
        out = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace")

    info["ok"] = "Success" in out
    info["raw"] = out.strip()[:300]
    info["existed"] = existed
    info["previous_version"] = old_ver
    info["installed_version"] = installed_version(serial, package) if package else ""
    info["upgraded"] = bool(existed and info["ok"] and old_ver and old_ver != info["installed_version"])
    if not info["ok"]:
        log("[!] 安装失败：%s" % out.strip()[:150])
    else:
        log("[*] 安装成功（%s）" % (info["installed_version"] or "版本未知"))
    return info


def clear_app_data(serial: str, package: str, log: Callable[[str], None] = print) -> bool:
    """清除应用数据 —— 不清数据 App 不会走首启流程，隐私弹窗不会出现。

    真机验证：MIUI 上 `pm clear` 以 shell 身份执行会抛
    `SecurityException: PID ... `，必须经 `su -c` 以 root 执行。
    """
    for args in (["shell", "su -c 'pm clear %s'" % package],
                 ["shell", "pm", "clear", package]):
        try:
            p = _run(_adb_args(serial) + args, timeout=60)
            out = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace").strip()
            if "Success" in out:
                log("[*] 清除应用数据：成功（下次启动即首启流程）")
                return True
        except Exception as e:
            log("[!] 清除应用数据异常：%s" % e)
    log("[!] 清除应用数据失败，App 可能不是首启流程，隐私弹窗可能不出现")
    return False


def force_stop(serial: str, package: str) -> None:
    try:
        _run(_adb_args(serial) + ["shell", "am", "force-stop", package], timeout=30)
    except Exception:
        pass


# 会弹系统弹窗的运行时权限。开测前逐个收回。
#
# ★ 为什么必须收回
#   `pm clear` 只清 App 数据，**不动已授予的运行时权限**。上一轮在权限弹窗上
#   代点了「允许」，这些授权会一路留下来：
#     · 下一轮首轮采集时，App 申请同一权限不再弹窗 → Q026 只能记「跳过未测」，
#       而上一轮同样的操作却抓到了弹窗、判了「认定」—— 同一个包、同一版本，
#       五轮里各轮结论不同，根子就在这里；
#     · 复现轮必然抓不到（清数据不清权限），于是 Q026 每轮复现都写「未能判定」，
#       白占一行却什么也没验证。
#   开测前统一收回，等于把每轮起点固定成「从未授权」。这是结论能对齐的前提，
#   不是可选优化。
_REVOKE_PERMS = (
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.POST_NOTIFICATIONS",
)


def reset_permissions(serial: str, package: str,
                      log: Callable[[str], None] = print) -> List[str]:
    """把运行时权限收回未授予状态。返回收回成功的权限短名。

    MIUI 上以 shell 身份 `pm revoke` 会抛 SecurityException，必须经 `su -c`；
    与 `clear_app_data` 同一套降级顺序：先 root，再裸 shell。
    单条权限收不回来不算失败（比如该版本根本没声明、或系统不支持），
    只看总体：一条都没收回说明这条路走不通，如实记一行告警。
    """
    ok: List[str] = []
    denied: List[str] = []
    for perm in _REVOKE_PERMS:
        got = False
        for args in (["shell", "su -c 'pm revoke %s %s'" % (package, perm)],
                     ["shell", "pm", "revoke", package, perm]):
            try:
                p = _run(_adb_args(serial) + args, timeout=20)
                out = ((p.stdout or b"") + (p.stderr or b"")).decode(
                    "utf-8", errors="replace")
            except Exception:
                continue
            low = out.lower()
            if "exception" in low or "error" in low or "unknown permission" in low:
                continue
            # 成功时无输出；"not granted" 也算已处于未授予（同样是我们想要的）
            got = True
            break
        (ok if got else denied).append(perm.split(".")[-1])
    if ok:
        log("[*] 已收回运行时权限 %d 项（下次申请会重新弹窗）：%s"
            % (len(ok), "、".join(ok[:6]) + ("…" if len(ok) > 6 else "")))
    if not ok:
        log("[!] 运行时权限一项都没收回 —— 本轮权限弹窗可能不再出现，"
            "Q026 的结论可能只反映上一轮遗留的授权状态")
    return ok


def pids_of(serial: str, package: str) -> List[int]:
    """该包名当前的全部进程号（多进程 App 会有 :remote 等子进程）。"""
    try:
        p = _run(_adb_args(serial) + ["shell", "pidof", package], timeout=15)
        out = (p.stdout or b"").decode("utf-8", errors="replace").strip()
        return [int(x) for x in out.split() if x.isdigit()]
    except Exception:
        return []


def device_online(serial: str, host: str = "223.5.5.5") -> bool:
    """测试机当前能不能上网。

    ★ 为什么采集流程里必须问这一句（2026-11-09 小包搜题 land36/38/39）：
      那三轮里政策页一直显示「网页无法打开」，报告差点写成
      「应用把政策交给了一个打不开的地址」—— 而真实原因是**测试机在飞行
      模式下、Wi-Fi 也关着**，ping 连域名都解析不出来。设备没网时任何
      WebView 都会显示这个页面，把它算成应用的问题就是彻底的误报。
      自检不拦这一条，整份报告的可信度都会被它拖下水。

    判两层，任一层能下结论就算：
      ① `ping` 一个纯 IP（不依赖 DNS）；
      ② `dumpsys connectivity` 里有没有 active default network。
    都判不出来时**返回 True** —— 宁可漏报"离线"，也不能把正常轮次
    误标成离线（那会把真实的应用问题一起洗掉）。
    """
    try:
        p = _run(_adb_args(serial) + ["shell", "ping", "-c", "1", "-W", "2", host],
                 timeout=12)
        if p.returncode == 0:
            return True
    except Exception:
        pass
    try:
        p = _run(_adb_args(serial) + ["shell", "dumpsys", "connectivity"], timeout=20)
        out = (p.stdout or b"").decode("utf-8", errors="replace")
        if re.search(r"Active default network:\s*none", out):
            return False
    except Exception:
        pass
    return True


def app_crash_evidence(serial: str, package: str,
                       within_s: int = 300) -> List[str]:
    """取该应用最近 `within_s` 秒内、由系统记下的崩溃/进程死亡记录。

    只读 `logcat -b events`（系统事件缓冲），不改动设备状态。
    返回原始行（截断到 220 字），供报告原样引用 —— 这一条的作用是让
    "应用是被注入弄死的"从推断变成**有系统日志编号的事实**。

    取不到就返回空列表：调用方必须按"没有证据"处理，不能倒过来当成
    "应用没死"。加固壳自杀未必都会记 `am_crash`（有些是 SIGKILL）。
    """
    try:
        p = _run(_adb_args(serial) + ["shell", "logcat", "-b", "events",
                                     "-d", "-t", "800"], timeout=25)
        out = (p.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return []
    if not out:
        return []
    now = time.time()
    hits: List[str] = []
    for line in out.splitlines():
        if package not in line:
            continue
        if "am_crash" not in line and "am_proc_died" not in line \
                and "am_kill" not in line:
            continue
        # 只认最近的记录：事件缓冲会跨轮次留存，上一轮的崩溃不能算这一轮的证据。
        m = re.match(r"\s*(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})", line)
        if m:
            try:
                _lt = time.localtime(now)
                _ts = time.mktime((_lt.tm_year, int(m.group(1)), int(m.group(2)),
                                   int(m.group(3)), int(m.group(4)),
                                   int(m.group(5)), 0, 0, -1))
                if now - _ts > within_s:
                    continue
            except Exception:
                pass
        hits.append(line.strip()[:220])
    return hits[-6:]


# ---------------------------------------------------------------- 界面观测

# 冷启动后等前台切到被测应用的上限（秒）。
# 实测 K30 上 `am start` 到前台切换 0.8~2.5s，给到 8s 仍等不到就是真没起来。
FIRST_SCREEN_WAIT = 8.0

# 冷启动到前台的最大等待（秒）。带加固的包要解壳，实测金考典（2026-10-27）
# 从 spawn 到首启弹窗出现用了 70 秒以上；旧逻辑观测窗一共才 25~45 秒，
# App 还没起来窗口就过完了，于是首启阶段一张图没留、政策结论写成"未观测到入口"，
# 而遍历阶段其实点到的就是同一个弹窗。**等前台的时间不算观测窗口**。
FIRST_APPEAR_MAX = 90.0

def await_app_foreground(serial: str, package: str,
                         wait_s: float = FIRST_SCREEN_WAIT,
                         poll: float = 0.4) -> Tuple[bool, str]:
    """等前台切到被测应用。返回 (是否已到前台, 最后看到的前台页面)。

    ★ 为什么必须等（金考典 2026-10-26 实测）：`am start` 返回后
      冷启动还要 1~3 秒才把前台切过来，这期间截图拍到的就是**手机桌面**。
      金考典那轮三张"首启界面"全是桌面，后面的遍历图却正常 ——
      不是 App 没起来，是截图比界面早了一步。国象联盟那种启动即崩的，
      等满 wait_s 也等不到，于是这一屏会被标成"App 未到前台"而不是"首启界面"。
    """
    pkg = (package or "").strip()
    if not pkg:
        return True, ""
    t0 = time.time()
    fg = ""
    while time.time() - t0 < max(0.5, wait_s):
        try:
            # ★ 判"到了前台"只认**窗口焦点**（2026-11-10 健康深圳）：
            #   `current_focus()` 拿不到 `mCurrentFocus` 时会兜底读
            #   `mResumedActivity`，而加固壳 / uni-app 的应用可以"Activity
            #   resumed 但窗口从未画出来"。健康深圳在本机启动后约 150ms 就
            #   `has died`，mCurrentFocus 一直是 null，这里却一直判"已到前台"，
            #   于是首启观测、着陆判主页面、甚至 Q002「未观测到收集行为」
            #   全部建立在一个**从来没有显示过的应用**上。
            _fg = uiwalk.foreground(serial)
            fg = _fg.get("focus") or ""
            _vis = uiwalk.visible_from_focus(
                fg if _fg.get("via") == "window" else "", pkg)
        except Exception:
            fg, _vis = "", None
        if _vis is True:
            # 前台已切过来，再给一帧渲染时间：冷启动首帧常常还是白屏/黑屏，
            # 立刻截图会得到一张"什么都没有"的图。
            time.sleep(0.6)
            return True, fg
        time.sleep(poll)
    return False, fg


def observe_screen(res: ScanResult, label: str, serial: str,
                   take_shot: bool = True, xml: Optional[str] = None,
                   require_app: bool = False) -> Optional[str]:
    """dump 当前界面，记录界面指纹与文字，并按需截图。返回 XML。

    xml（可选）：调用方**已经抓到手**的结构树。给了就不再 dump ——
    政策页这类"转瞬即逝"的界面必须用点击瞬间抓到的那一份，
    重新 dump 一次要 2~3 秒（真机实测 uiautomator dump 约 2.8s），
    那时页面往往已经退回去了，采到的会是别的界面。

    require_app（可选）：只在前台确实是被测应用时才截图。
    用于"首启界面"这类**必须拍到 App 自己**的节点：前台还在桌面时拍下来的图
    既不能当首启界面，又会白白吃掉一张普通截图配额（金考典那轮 3 张配额
    全被桌面图占掉，进入 App 后只剩 1 张遍历图）。
    """
    if xml is None:
        xml = uiwalk.dump_retry(serial, tries=2, wait=0.5)
    # ★ 界面归因用"当前拿到输入焦点的窗口"，不是 `mResumedActivity`
    #   （2026-11-10 健康深圳 / 搜题）：uni-app 的 `io.dcloud.PandoraEntry`
    #   可以处于 resumed 却始终没画窗口，用户眼前是系统桌面。按 resumed 判，
    #   整轮 8 屏 5 张截图全是桌面，报告拿它当"首启界面"证据。
    #
    #   `foreground()` 把**来源**一起返回，这里必须分开用：
    #     · 窗口焦点（via=window）→ 既能归因，也能证明"用户看到了应用"；
    #     · resumed 兜底（via=resumed）→ **只能归因**（这一屏属于哪个 Activity），
    #       不能作为"应用可见"的依据。健康深圳本轮实测：应用启动后 150ms 就
    #       `has died`，mCurrentFocus 一直是 null，`current_focus()` 却一直返回
    #       PandoraEntry —— 再拿它判可见性，等于把桌面当应用。
    _fg = uiwalk.foreground(serial)
    _focus = _fg.get("focus") or ""
    _via = _fg.get("via") or ""
    _fpkg = (_fg.get("pkg") or (_focus.split("/")[0] or "")).strip()
    _on_home = uiwalk.is_launcher_pkg(_fpkg)
    activity = "" if _on_home else (_focus or uiwalk.top_activity(serial))
    fp = uiwalk.screen_fingerprint(xml) if xml else ""
    texts = uiwalk.screen_texts(xml)[:60] if xml else []
    _nodes = uiwalk.parse_all(xml) if xml else []
    idx = len(res.screens)
    rec: Dict[str, Any] = {
        "index": idx, "label": label, "activity": activity,
        "fingerprint": fp, "texts": texts, "ts": time.time(),
        "node_count": len(_nodes),
        "focus": _focus,
    }
    _pkg = (getattr(res, "package", "") or "").strip()
    # 只有窗口焦点能证明"这一屏用户真的看得见应用"。取不到焦点（null）记 None，
    # 一律按"不确定"处理 —— 不确定就不截图，宁可少一张图，也不留假证据。
    _vis = uiwalk.visible_from_focus(_focus if _via == "window" else "", _pkg)
    # ★ 焦点取不到时（mCurrentFocus=null）还有一路旁证：**结构树里节点自带的
    #   package 属性**。桌面那几屏的节点包名是 `com.miui.home`，应用自己的
    #   界面上是应用包名 —— 这能直接证明"这棵树的 UI 属于谁"。
    #   只用焦点一个来源会漏掉 mCurrentFocus 短暂为空的正常帧；
    #   只用结构树又会被 WebView/Surface 渲染骗过。两个来源取"能证明的那个"。
    _dom_pkgs = {str(getattr(n, "package", "") or "") for n in _nodes}
    _app_dom = bool(_pkg) and _pkg in _dom_pkgs
    if _vis is True:
        _on_app = True
    elif _vis is None:
        _on_app = _app_dom           # 焦点读不到：看结构树到底属于谁
    else:
        _on_app = False              # 焦点明确是别的界面（桌面/第三方），不采信
    rec["on_app"] = bool(_on_app)
    rec["on_home"] = bool(_on_home)
    rec["focus_via"] = _via
    rec["visible"] = (None if _vis is None else bool(_vis))
    rec["app_dom"] = bool(_app_dom)
    # 桌面截图永远没有证据价值：既不能当"应用界面"，也不能当"首启弹窗"。
    # 留下来只会让复核员以为应用真的长这样，还会吃掉普通截图配额。
    #
    # ★ 截图条件里必须有 `_on_app`（2026-11-10 二次修正）：原来写成
    #   `(not require_app or _on_app)`，遍历期的普通截图因为 require_app=False
    #   直接短路通过 —— 健康深圳第二轮照样拍了 2 张桌面图。也就是说那个门
    #   只对"首启界面"生效，对遍历截图形同不存在。
    if take_shot and _on_app and not _on_home \
            and _ordinary_shot_count(res) < res.max_shots:
        shot = capture_screenshot(serial)
        if shot:
            rec["screenshot"] = len(res.screenshots)
            res.screenshots.append({
                "label": label, "activity": activity,
                "b64": base64.b64encode(shot).decode("ascii"),
            })
    res.screens.append(rec)
    return xml


def has_phase1_shot(res: ScanResult) -> bool:
    """本轮有没有留下「同意前的那一屏」截图。

    报告里 Q002/Q003 讲的是"同意之前发生了什么"，没有这张图，
    结论就是无图孤证 —— 复核员无法确认当时屏幕上到底有没有隐私弹窗
    （金考典 2026-10-27：首启观测窗口没等到 App 到前台，整段 P1 一张图都没有，
    而遍历阶段点「同意并继续」时，弹窗就明明白白在屏幕上）。
    """
    try:
        for s in res.screenshots or []:
            if str(s.get("label") or "").startswith(("首启界面", "启动后界面")):
                return True
    except Exception:
        pass
    return False


# 权限弹窗"粘住"的计数（见 _capture_perm_dialog）。按 (权限, 界面指纹) 记：
# 换了一屏就是另一个弹窗，不该继承上一屏的"关不掉"计数。
_PERM_STICKY: Dict[tuple, int] = {}
_PERM_STICKY_TRIES = 3


def _capture_perm_dialog(res: ScanResult, xml: str, serial: str,
                         log: Callable[[str], None], phase: str = "P4",
                         pre_text: str = "",
                         seen: Optional[set] = None) -> bool:
    """若当前屏是系统权限弹窗：取证 → 代点「允许」→ 继续遍历。

    为什么必须专门处理（而不是当成普通一屏点掉）：
      遍历原本会把权限弹窗按普通界面处理，点「允许」继续走，**什么也没留下**。
      于是报告的 Q026 只能写"未获取到权限场景"，而权限申请恰恰是人工报告里
      出现频次最高的一项。这里把三样东西固定下来：
        · 申请了哪个权限（弹窗原文 + 权限分组名）；
        · 弹窗**之前**那一屏 App 界面写了什么（用途说明通常在那里）；
        · 弹窗内有没有 App 提供的解释文字。
    判定留给 `flow/permissions.py`，这里只保证事实齐、可核对。

    返回 True 表示这一屏确实是权限弹窗（调用方应跳过本轮普通点击逻辑）。
    """
    pd = uiwalk.perm_dialog(xml)
    if not pd:
        return False
    perm = str(pd.get("perm") or "")
    fp = uiwalk.screen_fingerprint(xml)
    key = (perm, fp)
    if seen is not None:
        if key in seen:
            # ★ 同一弹窗还没消失 —— **不能只是 return True 然后 continue**。
            #   高途 2026-11-03：存储权限弹窗弹出来时"未找到允许类按钮"，
            #   于是它一直挂在那儿，而主循环每一轮都走到这里 → return True →
            #   continue：界面没变、动作没发生、日志只剩心跳，3518 秒里
            #   3357 秒停在这一屏，台账/振荡/僵化三条判据全部失明。
            #   这里补一道：连着几轮都关不掉，就按返回键把它关掉（等同拒绝），
            #   并把这件事写进报告 —— "弹窗没代点成、应用也没再往下走"本身
            #   就是一条事实，不该被吞掉。
            n = _PERM_STICKY.get(key, 0) + 1
            _PERM_STICKY[key] = n
            if n <= _PERM_STICKY_TRIES:
                log("[.] 权限弹窗仍在屏上（第 %d 次），按返回键关闭（等同拒绝）后继续" % n)
                uiwalk.back(serial)
                time.sleep(0.9)
            if n == _PERM_STICKY_TRIES:
                _why = ("权限弹窗「%s」在屏上停留超过 %d 轮未能代点「允许」，"
                        "已按返回键关闭（等同拒绝）；该权限的授权场景只保留弹窗原文与截图"
                        % (perm or "未知权限", n))
                if _why not in res.errors:
                    res.errors.append(_why)
            return True          # 同一弹窗还没消失，别重复记
        _PERM_STICKY.pop(key, None)
        seen.add(key)

    label = "权限申请·%s·%s" % (phase, perm or "未知权限")
    shot_idx = -1
    # ★ 先确认应用还在前台（2026-11-09 聚橙票务）：
    #   截图背景是系统桌面，却被当成"应用在运行中申请权限"的证据 ——
    #   那一轮应用已被加固壳杀掉、正在重新拉起，弹窗是系统残留。
    #   这种图**不能**当应用行为的证据，但也不能悄悄丢掉：
    #   记成"弹窗出现时应用不在前台"，并说明该截图不能用于认定授权场景。
    #
    # ★ 三态而不是两态（2026-11-10 铁路火车票）：`app_in_foreground` 现在只认
    #   窗口焦点，取不到就返回 None。None 的含义是"读不到"，既不能算在、也不能
    #   算不在 —— 但它同样**不能**拿来当"运行中申请权限"的证据。
    #   所以"能不能当证据"的判据是 `is not True`，而写进报告的措辞要分三种。
    _fg_state = app_in_foreground(serial, getattr(res, "package", "") or "")
    _evidable = (_fg_state is True)      # 只有明确在前台才算有效证据
    if _fg_state is False:
        label += "·应用不在前台"
    elif _fg_state is None:
        label += "·前台未确认"
    # ★ 权限弹窗截图**必截**，不与遍历截图抢配额（见 PERM_SHOT_EXTRA 的说明）。
    #   只有在总张数已经爆到离谱时才放弃 —— 那种情况说明采集本身出了问题。
    if len(res.screenshots) < res.max_shots + PERM_SHOT_EXTRA:
        raw = capture_screenshot(serial)
        if raw:
            shot_idx = len(res.screenshots)
            res.screenshots.append({
                "label": label, "activity": uiwalk.top_activity(serial),
                "b64": base64.b64encode(raw).decode("ascii"),
                "offApp": (None if _fg_state is None else (not _fg_state)),
            })
        else:
            log("[!] 权限弹窗截图失败（capture_screenshot 返回空），"
                "该项将缺少界面截图，需人工补充")
    else:
        log("[!] 截图总量已达上限（%d 张），权限弹窗未能留图，需人工补充"
            % (res.max_shots + PERM_SHOT_EXTRA))
    if not _evidable:
        if _fg_state is False:
            _off = ("权限弹窗「%s」出现时被测应用已不在前台（截图背景为系统桌面），"
                    "该弹窗可能是系统残留或应用被退出/重新拉起过程中弹出的；"
                    "此场景只记录弹窗原文，不作为「应用在运行中申请该权限」的证据"
                    % (perm or "未知权限"))
        else:
            _off = ("权限弹窗「%s」出现时读不到窗口焦点，无法确认当时屏幕上是不是"
                    "被测应用（该轮应用可能正在被重新拉起）；此场景只记录弹窗原文，"
                    "不作为「应用在运行中申请该权限」的证据"
                    % (perm or "未知权限"))
        if _off not in res.errors:
            res.errors.append(_off)
    at_ms = int((time.time() - (res.started_at or time.time())) * 1000)
    allow = str(pd.get("allow_label") or "")
    scene = {
        "perm": perm,
        "perm_raw": pd.get("perm_raw") or "",
        "dialog_text": pd.get("dialog_text") or "",
        "options": list(pd.get("options") or []),
        "has_purpose": bool(pd.get("has_purpose")),
        "purpose_quote": pd.get("purpose_quote") or "",
        "pre_text": (pre_text or "").strip()[:600],
        "phase": phase,
        "at_ms": at_ms,
        "shot": shot_idx,
        "action": ("代点「%s」" % allow) if allow else "未代点（未找到允许类按钮）",
        "pkg": pd.get("pkg") or "",
        # 「这次申请能不能当证据」：只有**明确确认应用在前台**才算。
        # 判定层（flow/permissions.py）必须读这两个字段，否则会出现
        # "errors 说这场景不能当证据、Q026 却拿它判 pass" 的自相矛盾
        # （2026-11-10 铁路火车票真机实测）。
        "off_app": (None if _fg_state is None else (not _fg_state)),
        "evidable": bool(_evidable),
    }
    res.perm_scenes.append(scene)
    res.ui_steps.append("权限弹窗：%s → %s" % (perm or "未知权限", scene["action"]))
    log("    [权限] 捕获到系统权限申请：%s（弹窗前界面 %d 字，弹窗内%s用途说明）→ %s"
        % (perm or "未知权限", len(scene["pre_text"]),
           "有" if scene["has_purpose"] else "无", scene["action"]))

    if allow:
        for n in uiwalk.clickable(xml):
            t = (n.text or n.content_desc or "").strip()
            if t == allow:
                x1, y1, x2, y2 = n.bounds
                uiwalk.tap(serial, (x1 + x2) // 2, (y1 + y2) // 2)
                break
        time.sleep(0.8)
    return True


LOGIN_HELP = """很多功能页（我的 / 设置 / 注销 / 订单）在登录态后面。本次检测使用
检测人员提供的测试手机号，由脚本代填并申请短信验证码，验证码由检测人员在平台上回填。
账号只用于本次检测，检测结束后随应用数据一并清除。"""


def _mask_phone(p: str) -> str:
    s = str(p or "").strip()
    return (s[:3] + "****" + s[-4:]) if len(s) >= 8 else s


def _login_set_field(serial: str, node, text: str) -> bool:
    """点进输入框、清空、再输入。

    抽成模块级是为了让「密码登录」与「注册」两条路共用同一份输入逻辑：
    两份实现迟早会在"清空"这一步分叉（一份清、一份不清），
    表现是"手机号变成 1380000000013800000000"这种只在真机上才看得见的事故。
    """
    if node is None:
        return False
    uiwalk.tap_node(serial, node)
    time.sleep(0.6)
    # 清空已有内容：光标移到行尾再连按删除
    uiwalk._inject(serial, "input keyevent 123")        # MOVE_END
    for _ in range(20):
        uiwalk._inject(serial, "input keyevent 67")     # DEL
    return uiwalk.input_text(serial, text)


def _need_register_dialog(serial: str, log: Callable[[str], None]) -> str:
    """点「获取验证码」后，应用可能弹「您还未注册，请先注册」。

    2026-11-06 春雨诊所实测：勾好协议、点「获取短信验证码」，界面弹出一个
    只有两个按钮的框——「您还未注册，请先注册 / 取消 / 去注册」，短信一条都没发。
    没有这一步的话，我们只会干等到超时，然后把"应用根本没打算给这个号发码"
    记成"我们没收到码"——又是一个把原因找错地方的结论。

    返回值：点进注册页后的界面 xml；没出现这个提示就返回空串。
    """
    xml = uiwalk.dump_retry(serial, tries=2, wait=0.6) or ""
    if not xml:
        return ""
    texts = " ".join((n.text or "") for n in uiwalk.parse_all(xml))
    if not any(w in texts for w in ("未注册", "请先注册", "尚未注册")):
        return ""
    for words in (("去注册", "立即注册", "马上注册", "去注册账号"), ("注册",)):
        hit = None
        for n in uiwalk.clickable(xml):
            t = (n.text or "").strip()
            if t in words:
                hit = n
                break
        if hit is not None:
            t = (hit.text or "").strip()
            uiwalk.tap_node(serial, hit)
            log("[*] 应用提示「该手机号未注册」，已点「%s」转入注册流程" % t)
            time.sleep(2.0)
            return uiwalk.dump_retry(serial, tries=2, wait=1.0) or ""
    log("[!] 出现「未注册」提示，但没找到「去注册」按钮（可能需要人工注册）")
    return ""


def _find_code_field(xml: str) -> Optional[Any]:
    """在"请输入验证码"那一屏上找验证码输入框。

    `login_screen` 是按"登录页整体"判的，遇到只输入验证码的**独立页面**
    （点完获取验证码后跳过去的那种）就取不到 `code_field`。
    这里的备选顺序：
      ① 提示文字/描述里带「验证码」的可编辑框；
      ② 整屏只有一个可编辑框、且它不像手机号框（没有 11 位数字提示）→ 就是它。
    取不到就返回 None，由调用方如实记"没有可填的验证码框"，绝不瞎填。
    """
    nodes = uiwalk.parse_all(xml)
    edits = [n for n in nodes
             if "EditText" in (n.cls or "") and n.enabled]
    for n in edits:
        lab = (n.text or "") + (n.content_desc or "")
        if "验证码" in lab or "校验码" in lab or "动态码" in lab:
            return n
    if len(edits) == 1:
        lab = (edits[0].text or "") + (edits[0].content_desc or "")
        if "手机" not in lab and "账号" not in lab and "密码" not in lab:
            return edits[0]
    return None


def _tap_agree_by_text(serial: str, log: Callable[[str], None],
                       force: bool = False) -> bool:
    """勾上登录页的「我已阅读并同意《…》《…》」。

    为什么不能只靠 `login_screen` 的 `agree_cb`（2026-11-06 春雨诊所）：
        那一屏的勾选框是 `android.widget.CheckBox`，**文字为空**，紧挨着一个
        `clickable=false` 的 TextView「我已阅读并同意《春雨诊所协议》《隐私政策》」。
        先按"文字节点的左边 10px"去点，点到的是那个不可点的 TextView ——
        界面毫无变化、日志却写着"已勾选"，接着点「获取验证码」只弹一句
        toast「请先阅读并同意协议」，短信一条都没发。
        所以判据交给 `uiwalk.find_agree_target()`：**认的是那个空勾选框**，
        不是那行字。这里只负责点它、并确认点完没跑偏。
    """
    xml = uiwalk.dump_retry(serial, tries=2, wait=0.5) or ""
    if not xml:
        return False
    act0 = uiwalk.top_activity(serial)
    target = uiwalk.find_agree_target(uiwalk.parse_all(xml))
    if target is None:
        return False
    if target.checkable and target.checked and not force:
        return False              # 已经勾上了，再点就取消
    if target.checkable and target.checked:
        return False
    x, y = target.center
    uiwalk.tap_node(serial, target)
    time.sleep(0.9)
    act1 = uiwalk.top_activity(serial)
    if act1 and act1 != act0:
        log("[.] 勾选协议时意外跳到了 %s，返回" % act1.split(".")[-1])
        uiwalk.back(serial)
        time.sleep(0.9)
        return False
    log("[*] 已勾选登录页的「我已阅读并同意」（勾选框 x=%d,y=%d）" % (x, y))
    return True


def _wait_sms_code(get_code: Optional[Callable[[], str]], timeout: int,
                   should_stop: Optional[Callable[[], bool]],
                   log: Callable[[str], None],
                   serial: str = "", since_ms: int = 0,
                   res: Optional[ScanResult] = None) -> str:
    """等验证码：**优先读设备自己的收件箱**，读不到才等人工回填。

    为什么改（2026-11-06 春雨诊所）：
        旧实现只会等 `sms.txt`（检测人员在平台手填）。那一单等了 600 秒没等到，
        报告写下"已申请验证码，但 600 秒内未收到检测人员回填"。
        事后翻设备收件箱：**当天一条短信都没有** —— 压根没发出去
        （登录页的「我已阅读并同意」没勾，点发码只弹了一个 toast）。
        于是报告替应用编了一个"我们等了但没到"的理由。

        测试机的 SIM 就在被测设备里，短信落在这台机器上，`content query` 能直接读
        （本机 Magisk 已 root）。这条路既省掉人工回填，又让"到底收到没有"
        变成一个可核验的事实，而不是一句推测。

    `since_ms` 必须是**点击发码那一刻**的时间戳，否则会捡到上一轮的过期码 ——
    那会填错码、失败，再被记成"验证码错误"。
    """
    from . import smsbox

    dev_ok = bool(serial) and smsbox.available(serial) if serial else False
    if res is not None:
        res.login["code_source"] = "设备收件箱" if dev_ok else "人工回填"
    t0 = time.time()
    next_poll = 0.0
    while time.time() - t0 < max(10, timeout):
        if _stop_requested(should_stop):
            return ""
        code = ""
        if get_code is not None:
            try:
                code = str(get_code() or "").strip()
            except Exception:
                code = ""
        if code:
            if res is not None:
                res.login["code_source"] = "人工回填"
            return code
        if dev_ok and time.time() >= next_poll:
            next_poll = time.time() + 3.0
            code = smsbox.wait_code(serial, since_ms or int(t0 * 1000),
                                    timeout=4.0, log=log)
            if code:
                return code
        time.sleep(1.5)
    return ""


def _sms_arrived(serial: str, since_ms: int) -> Tuple[bool, str]:
    """这段时间设备上**有没有收到任何**短信。返回 (有没有, 收到的是什么)。

    ★ 这是"没发出去"与"发了没到"的唯一分界线（2026-11-06 春雨诊所）：
      读不到收件箱时返回 (False, "") —— 但调用方必须把它当成"不知道"，
      不许当成"没收到"。这条区别决定报告里写"未发出"还是"未收到"。
    """
    from . import smsbox

    if not serial or not smsbox.available(serial):
        return False, ""
    rows = smsbox.latest(serial, since_ms, limit=4)
    if not rows:
        return False, ""
    return True, smsbox.text_after(serial, since_ms, limit=2)


def _password_login(res: ScanResult, xml: str, serial: str,
                    log: Callable[[str], None], phone: str, password: str
                    ) -> bool:
    """用台账里的密码登录（只给"手机号 + 密码"的登录页用）。

    为什么不复用 `_login_assist`：那条链的主干是"申请验证码"，而这一屏
    根本没有验证码入口 —— 硬塞进去会让它走"没找到获取验证码 → 直接点登录"
    的老路，也就是 2026-11-06 春雨诊所那次空提交。
    """
    info = uiwalk.login_screen(xml)
    if not info or info.get("phone_field") is None:
        return False
    # ★ 台账密码登录要求"这一屏有密码框"（2026-11-06 land20 实测）：
    #   登陆辅助的 prep 会把页面切到**验证码**表单，之后再用台账密码登，
    #   会发现页面上根本没有密码框 —— 旧代码照样点了「登录」（密码为空），
    #   失败后再判定"密码错了/账号被注销"，把一次**根本没提交的登录**，
    #   写成了账号问题。正确做法是先切回「密码登录」。
    if not (info.get("pwd_field") is not None or info.get("pwd_fields")):
        for n in uiwalk.parse_all(xml):
            t = (n.text or "").strip()
            if not t or "忘记" in t or len(t) > 8:
                continue
            if "密码" in t and "登录" in t:
                uiwalk.tap_node(serial, n)
                log("[*] 切回「%s」表单（台账密码要用密码框）" % t)
                time.sleep(1.5)
                _x = uiwalk.dump_retry(serial, tries=2, wait=0.8) or ""
                _i = uiwalk.login_screen(_x) if _x else None
                if _i and _i.get("pwd_field") is not None:
                    xml, info = _x, _i
                break
    if not (info.get("pwd_field") is not None or info.get("pwd_fields")):
        log("[!] 台账密码登录：这一屏没有密码输入框，不提交空密码")
        res.login["note"] = ("台账里有账号，但当前登录页没有密码输入框"
                             "（页面停在验证码表单），未提交登录请求")
        res.login["no_pwd_field"] = True
        return False
    if info.get("agree_cb") is not None:
        uiwalk.tap_node(serial, info["agree_cb"])
        time.sleep(0.6)
        _x = uiwalk.dump_retry(serial, tries=2, wait=0.6) or xml
        info = uiwalk.login_screen(_x) or info
    if not _login_set_field(serial, info.get("phone_field"), phone):
        log("[!] 台账密码登录：手机号没输进去")
        return False
    fields = list(info.get("pwd_fields") or [])
    if not fields and info.get("pwd_field") is not None:
        fields = [info["pwd_field"]]
    for f in fields:
        _login_set_field(serial, f, password)
    # 填完后「登录」才从 disabled 变可点，必须重新 dump 再取
    _x2 = uiwalk.dump_retry(serial, tries=2, wait=0.6) or ""
    _i2 = uiwalk.login_screen(_x2) if _x2 else None
    if _i2 and _i2.get("submit") is not None:
        info = _i2
    if info.get("submit") is None:
        log("[!] 台账密码登录：没找到「登录」按钮")
        return False
    uiwalk.tap_node(serial, info["submit"])
    time.sleep(3.0)
    _x3 = uiwalk.dump_retry(serial, tries=2, wait=0.8)
    still = uiwalk.login_screen(_x3) if _x3 else None
    ok = bool(_x3) and still is None
    res.login["ok"] = ok
    res.login["note"] = ("已用本地台账里的账号密码登录成功"
                         if ok else "用本地台账里的密码登录后仍停留在登录页")
    return ok


def _register_assist(res: ScanResult, xml: str, serial: str,
                     log: Callable[[str], None], phone: str,
                     get_code: Optional[Callable[[], str]] = None,
                     timeout: int = 180,
                     should_stop: Optional[Callable[[], bool]] = None,
                     on_register_page: bool = False
                     ) -> bool:
    """从登录页走「注册」：用测试号建一个账号（并通常直接登录）。

    ★ 为什么允许注册（2026-11-06 用户拍板）：
      春雨诊所（验证码入口在更深一屏时会先走验证码那条）与万步健康
      只有「手机号 + 密码」，没有游客入口。手里只有测试手机号时，
      不注册就永远只能在登录页外围打转，登录后的功能一项都测不到。

    ★ 三条自律：
      1. **先查台账**（调用方做）：同一台机器反复注册会在厂商侧堆废号；
      2. 密码用 `accounts.make_password()` 的固定规则生成并落盘 ——
         下轮能直接登，不会出现"注过但忘了密码"；
      3. 只走"手机号 + 验证码 + 设密码"这一种注册表单。遇到要实名/
         要证件照/要邀请码的注册页，立刻停手并如实记"需人工注册"——
         那不是能自动化的东西，硬试只会触发风控。

    返回 True 表示**尝试过**（与 `_login_assist` 同一约定），
    真实结果看 `res.login["ok"]`。
    """
    from . import accounts as accounts_mod

    if on_register_page:
        # 已经在注册页上（登录页弹「该手机号未注册 → 去注册」之后走的那条路），
        # 别再找「注册」入口 —— 那一屏没有入口，找到了也不是入口。
        _x = xml
        log("[*] 已在注册页，直接按注册表单填写")
    else:
        btn = uiwalk.find_register_entry(xml)
        if btn is None:
            return False
        log("[*] 登录页没有可用的验证码入口，改用注册：「%s」"
            % ((getattr(btn, "text", "") or "注册").strip()[:10]))
        uiwalk.tap_node(serial, btn)
        time.sleep(1.5)
        _x = uiwalk.dump_retry(serial, tries=2, wait=0.8) or ""
    # ★ 注册页有**专用解析器**（2026-11-06 万步健康真机）：
    #   它的注册页是 6 个输入框（昵称 / 手机 / 密码 / 确认密码 / 验证码 / 邀请码），
    #   提交按钮叫「完成注册」。而 `login_screen` 把 edits[0] 当手机号框，
    #   还会因为"完成注册"不等于"注册"把整页判成"不是登录/注册页"返回 None，
    #   于是这一轮报告写出了两句互相矛盾的话：
    #     「登录页没有可用的验证码入口，改用注册：「注册」」
    #     「也不存在可用的注册入口」
    #   前一句证明我们点进了注册页，后一句是判据写窄的产物。
    info = uiwalk.register_form(_x) if _x else None
    if info is None and _x:
        # 页面可能还在跳转动画里（冷启动第一次进注册页尤其慢），再等一拍重读
        time.sleep(1.5)
        _x2 = uiwalk.dump_retry(serial, tries=2, wait=0.8) or ""
        if _x2:
            _x = _x2
            info = uiwalk.register_form(_x)
    if info is None:
        # 兜底：有的 App 注册页就是标准单列表单（手机号+验证码+密码），
        # 那种形状 login_screen 拿得下来（edits[0] 恰好就是手机号框）。
        info = uiwalk.login_screen(_x) if _x else None
    if not info or info.get("code_btn") is None:
        log("[!] 注册页上没有识别到「获取验证码」，不猜着填，放弃注册")
        res.login["note"] = ("该应用的登录页只提供账号密码登录，尝试走注册但"
                            "注册页未识别到验证码入口，需人工注册后补测")
        return False
    # ---- 勾同意（不勾则「获取验证码」只弹 toast，界面毫无变化）
    if info.get("agree_cb") is not None:
        uiwalk.tap_node(serial, info["agree_cb"])
        time.sleep(0.6)
        _x = uiwalk.dump_retry(serial, tries=2, wait=0.6) or _x
        info = uiwalk.register_form(_x) or info
    if not _login_set_field(serial, info.get("phone_field"), phone):
        log("[!] 注册：手机号没输进去")
        res.login["note"] = "注册页上手机号未能输入，注册未完成"
        return True
    # ---- 申请验证码（填完号按钮才可点，必须重新 dump）
    _x = uiwalk.dump_retry(serial, tries=2, wait=0.8) or _x
    _i = uiwalk.register_form(_x) if _x else None
    if _i:
        info = _i
    _tap_agree_by_text(serial, log)
    _x = uiwalk.dump_retry(serial, tries=2, wait=0.6) or _x
    _i = uiwalk.register_form(_x) if _x else None
    if _i:
        info = _i
    if info.get("code_btn") is None:
        log("[!] 注册：填完手机号后没找到「获取验证码」")
        res.login["note"] = "注册页上未找到「获取验证码」，注册未完成"
        return True
    req_ms = int(time.time() * 1000)
    uiwalk.tap_node(serial, info["code_btn"])
    log("[*] 已申请注册验证码，等待回填（最多 %d 秒）…" % int(timeout))
    res.login["code_requested"] = True
    code = _wait_sms_code(get_code, timeout, should_stop, log,
                          serial=serial, since_ms=req_ms, res=res)
    if not code:
        _got, _what = _sms_arrived(serial, req_ms)
        res.login["note"] = (
            "注册时点击「获取验证码」后设备收件箱没有任何短信到达，"
            "可判定发码请求没有真正发出，注册未完成；登录态后的功能未覆盖"
            if not _got else
            "已申请注册验证码且设备收到短信，但未能从正文取出验证码，注册未完成；"
            "登录态后的功能未覆盖")
        log("[!] 未取得注册验证码，注册未完成")
        return True
    res.login["code_len"] = len(code)
    _x = uiwalk.dump_retry(serial, tries=2, wait=0.6) or _x
    _i = uiwalk.register_form(_x) if _x else None
    if _i:
        info = _i
    if not _login_set_field(serial, info.get("code_field"), code):
        res.login["note"] = "注册：验证码没输进去，注册未完成"
        return True
    # ---- 设密码：注册页常有两个框（密码 + 确认密码），都要填同一个值
    pwd = accounts_mod.make_password(phone)
    pwd_fields = list(info.get("pwd_fields") or [])
    if not pwd_fields and info.get("pwd_field") is not None:
        pwd_fields = [info["pwd_field"]]
    for f in pwd_fields:
        _login_set_field(serial, f, pwd)
    log("[*] 已填入注册密码（%d 位，规则固定，台账会记下来）" % len(pwd))
    # ---- 提交
    _x = uiwalk.dump_retry(serial, tries=2, wait=0.8) or _x
    _i = uiwalk.register_form(_x) if _x else None
    if _i and _i.get("submit") is not None:
        info = _i
    if info.get("submit") is None:
        res.login["note"] = "注册信息已填完，但没找到提交按钮，注册未完成"
        return True
    uiwalk.tap_node(serial, info["submit"])
    time.sleep(4.0)
    _x2 = uiwalk.dump_retry(serial, tries=2, wait=1.0)
    still = uiwalk.register_form(_x2) if _x2 else None
    ok = bool(_x2) and still is None
    res.login["ok"] = ok
    res.login["registered"] = True
    if ok:
        accounts_mod.upsert(res.package, phone, password=pwd,
                            app=getattr(res, "app_name", "") or "",
                            ok=True, note="本轮自动注册并登录成功")
        res.login["note"] = ("已用测试手机号 %s 注册新账号并登录（密码见本地台账 "
                             "accounts.json）" % _mask_phone(phone))
        res.ui_steps.append("注册测试账号并登录（%s）" % _mask_phone(phone))
        log("[+] 注册并登录成功，账号已记入本地台账")
    else:
        # 注册提交了但界面没走：可能是"注册成功、请登录"，也可能是校验失败。
        # 两种都不猜 —— 先把账号记进台账（它可能真的建成了），再如实写结果。
        accounts_mod.upsert(res.package, phone, password=pwd,
                            app=getattr(res, "app_name", "") or "",
                            ok=False, note="注册已提交但界面未离开注册页")
        res.login["note"] = ("已提交注册（手机号 %s），但界面仍停留在注册页；"
                             "账号信息已记入本地台账，需人工确认注册结果"
                             % _mask_phone(phone))
        log("[!] 注册提交后界面未变化，结果待人工确认")
    return True


def _login_assist(res: ScanResult, xml: str, serial: str,
                  log: Callable[[str], None], phone: str,
                  get_code: Optional[Callable[[], str]] = None,
                  timeout: int = 180,
                  should_stop: Optional[Callable[[], bool]] = None) -> bool:
    """遇到登录/注册页：代填测试手机号 → 申请验证码 → 等人工回填 → 提交。

    为什么必须做：不登录，遍历只能走游客可见的那几屏，"我的/设置/注销/隐私设置"
    这些最容易出问题的入口一个都到不了，报告里只能写"需登录后补测" ——
    而人工报告的痛点恰恰是这一步重复劳动。

    验证码不走自动化（收不到），由检测人员在平台回填，脚本轮询等待。
    等不到就如实记录"未取得验证码，未完成登录"，不编造成功。
    """
    # ★ 只在"已经发过验证码"之后才彻底封口。
    #   原来的判据是"尝试过就不再尝试"，但真机上第一次常常只是**结构没就绪**
    #   （登录方式页还没切过去、按钮还是灰的），一条短信都没发。这种情况封口
    #   等于把一次可恢复的界面时序问题，写成了"登录失败"。
    #   发过码就必须封口：重发会刷短信、还可能触发风控。
    _prev = dict(res.login or {})
    _tries = int(_prev.get("tries") or 0)
    if _prev.get("attempted") and (_tries >= 2 or _prev.get("code_requested")):
        return False
    info = uiwalk.login_screen(xml)
    if not info:
        return False
    # ---- 登录页的两道前置：勾「我已阅读并同意」、切到「手机验证码登录」----
    # 不做这两步，后面的"代填手机号 → 申请验证码"全是空转：
    #   · 不勾 → 点「获取验证码」只弹 toast，界面不动；
    #   · 不切 → 那一屏只有三个登录方式，连输入框都没有。
    # 真机实测（以观书法 5.4.2）：原先直接走"未找到手机号输入框"分支放弃，
    # 报告里只能写"登录未完成"，账号页全部未覆盖。
    prep: List[str] = []
    # ★ 第三条触发条件：这一屏有「短信验证码登录」的切换入口也要先 prep
    #   （2026-11-06 春雨诊所）。它默认停在「手机号 + 密码」表单上，
    #   切换入口是底部一行小字。不点那一行，我们手里只有手机号、没有密码，
    #   整条登录链一步都走不动。
    if (info.get("agree_cb") is not None
            or info.get("phone_field") is None
            or info.get("switch_btn") is not None):
        xml, prep = uiwalk.login_prepare(serial, xml)
        info2 = uiwalk.login_screen(xml) if xml else None
        if info2:
            info = info2
        if prep:
            log("[*] 登录页准备：%s" % "；".join(prep))
    res.login = {
        "attempted": True, "phone": _mask_phone(phone), "phone_full": str(phone),
        "method": "短信验证码注册/登录", "ok": False, "note": "",
        "at_ms": int((time.time() - (res.started_at or time.time())) * 1000),
        "title": info.get("title") or "",
        "tries": _tries + 1,
    }
    if prep:
        res.login["prep"] = prep
    log("[*] 检测到登录/注册页（%s），开始代填测试账号 %s"
        % (info.get("title") or "登录页", _mask_phone(phone)))

    def _shot(label: str) -> int:
        if _ordinary_shot_count(res) >= res.max_shots:
            return -1
        raw = capture_screenshot(serial)
        if not raw:
            return -1
        idx = len(res.screenshots)
        res.screenshots.append({"label": label, "activity": uiwalk.top_activity(serial),
                                "b64": base64.b64encode(raw).decode("ascii")})
        return idx

    def _set_field(node, text: str) -> bool:
        return _login_set_field(serial, node, text)

    # ★ 两件事要分开写（2026-11-05 万步健康）：**没找到输入框** 与
    #   **找到了但文字没输进去** 是两种完全不同的故障，对策也不同。
    #   旧代码把两者都写成"未找到手机号输入框" —— 报告读者会去改字段识别逻辑，
    #   而真相可能是"这一屏被弹窗盖住、输入法没就绪"。这就是假话。
    if info.get("phone_field") is None:
        res.login["note"] = "未找到手机号输入框，未能代填"
        log("[!] 未找到手机号输入框，跳过登录")
        return True
    ok_phone = _set_field(info.get("phone_field"), phone)
    if not ok_phone:
        res.login["note"] = ("已定位手机号输入框，但文本未能输入（输入法未就绪"
                             "或控件不可编辑），未完成代填")
        log("[!] 手机号输入框定位到了，但输入失败（输入法未就绪或控件不可编辑）")
        return True

    # ★ 填完手机号必须**重新 dump 再取按钮**。
    #   真机实测（以观书法 5.4.2）：手机号为空时「获取短信验证码」「登录」是
    #   `enabled="false"`，而 `uiwalk.clickable()` 会过滤掉 disabled 节点 ——
    #   拿着填号前那份 info 去找按钮，永远是 None。表现就是整条登录链"静默为空"：
    #   不报错、不发码、不登录，报告里只留一句"登录未完成"。
    _x1 = uiwalk.dump_retry(serial, tries=2, wait=0.8)
    _i1 = uiwalk.login_screen(_x1) if _x1 else None
    if _i1:
        info = _i1

    _submitted_code = False
    if info.get("code_btn") is not None:
        from . import smsbox

        # ★ 发码之前必须先确保「我已阅读并同意」是勾上的（2026-11-06 春雨诊所）：
        #   那一屏的勾选框是自绘控件（不是 CheckBox 类、也没有 checkable 标记），
        #   `login_screen` 找不到它，于是没勾就点了「获取短信验证码」——
        #   应用只弹一句 toast「请先阅读并同意协议」，请求根本没发出去。
        #   而我们的日志写的是"已点击获取验证码"，报告写的是"已申请验证码"。
        #   两句话都是假的，且复核员去查短信记录只会更困惑。
        #   这里按"看不见就按文字找、点它包围盒的左端（勾选框在那里）"处理。
        _agree_before = _tap_agree_by_text(serial, log)
        if _agree_before:
            _x0 = uiwalk.dump_retry(serial, tries=2, wait=0.6)
            _i0 = uiwalk.login_screen(_x0) if _x0 else None
            if _i0 and _i0.get("code_btn") is not None:
                info = _i0

        req_ms = int(time.time() * 1000)
        uiwalk.tap_node(serial, info["code_btn"])
        _dev_ok = bool(serial) and smsbox.available(serial)
        log("[*] 已点击「%s」，%s（最多 %d 秒）…"
            % ((info["code_btn"].text or "获取验证码").strip(),
               "从设备收件箱取验证码" if _dev_ok else "等待检测人员回填验证码",
               timeout))
        res.login["code_requested"] = True
        # ★ 先看应用是不是直接拒绝了（"您还未注册，请先注册"）——
        #   这种情形下短信永远不会来，等满 timeout 是纯粹的浪费，
        #   而且会把原因记错（见 _need_register_dialog 的说明）。
        time.sleep(1.6)
        _reg_x = _need_register_dialog(serial, log)
        if _reg_x:
            res.login["need_register"] = True
            res.login["code_sent"] = False
            res.login["note"] = "该手机号在此应用尚未注册，已转入注册流程"
            if _register_assist(res, _reg_x, serial, log, phone, get_code,
                                timeout, should_stop, on_register_page=True):
                res.login.setdefault("account_source", "本轮注册")
            return True
        code = _wait_sms_code(get_code, timeout, should_stop, log,
                              serial=serial, since_ms=req_ms, res=res)

        # ★ 一次码都没到 → 先判"到底发出去没有"，再决定要不要重发
        if not code:
            got_any, _what = _sms_arrived(serial, req_ms)
            if _dev_ok and not got_any:
                # 设备上一丁点短信都没有：几乎可以断定请求被页面拦下了
                # （协议没勾、按钮还是灰的、被图形验证码挡住）。勾一次协议再发一次。
                res.login["code_sent"] = False
                log("[!] 点击后设备**一条短信都没收到** → 判定发码请求未真正发出")
                if _tap_agree_by_text(serial, log, force=True):
                    _x3 = uiwalk.dump_retry(serial, tries=2, wait=0.8)
                    _i3 = uiwalk.login_screen(_x3) if _x3 else None
                    if _i3 and _i3.get("code_btn") is not None:
                        req_ms = int(time.time() * 1000)
                        uiwalk.tap_node(serial, _i3["code_btn"])
                        log("[*] 已勾选协议并重新点击「%s」，再等一次"
                            % (_i3["code_btn"].text or "获取验证码").strip())
                        res.login["code_retry"] = True
                        code = _wait_sms_code(get_code, timeout, should_stop, log,
                                              serial=serial, since_ms=req_ms,
                                              res=res)
            elif not _dev_ok:
                res.login["code_sent"] = None      # 不知道，不许写成"没发出"
            else:
                res.login["code_sent"] = True
                res.login["sms_seen"] = _what
        if not code:
            if res.login.get("code_sent") is False:
                res.login["note"] = (
                    "点击「获取验证码」后设备收件箱在本轮没有任何短信到达，"
                    "可判定**发码请求没有真正发出**（登录页提示需先同意协议 / "
                    "按钮未生效），未登录；登录态后的功能未覆盖")
            elif res.login.get("code_sent") is None:
                res.login["note"] = (
                    "已点击「获取验证码」，但本机无法读取短信收件箱，"
                    "也没有收到人工回填的验证码，登录未完成；"
                    "登录态后的功能未覆盖")
            else:
                res.login["note"] = (
                    "已点击「获取验证码」且设备收到短信，但未能从短信正文取出验证码，"
                    "登录未完成；登录态后的功能未覆盖")
            res.login["shot"] = _shot("登录页·等待验证码超时")
            log("[!] 未取得验证码，登录未完成（该事实会写进报告）")
            return True
        res.login["code_len"] = len(code)
        # ★ 拿到码之前往往已经**换了界面**（2026-11-06 春雨诊所实测）：
        #   点完「获取短信验证码」，应用跳到「请输入验证码」那一屏，
        #   而 `info` 还是点之前的（那一屏没有验证码输入框）。
        #   旧代码直接拿旧 info 去填 → "已取得验证码，但未找到验证码输入框"，
        #   码拿到了却填不进去，等于白等。必须先重读界面再定位。
        _xc = uiwalk.dump_retry(serial, tries=2, wait=0.8) or ""
        _ic = uiwalk.login_screen(_xc) if _xc else None
        if _ic:
            info = _ic
        _code_node = info.get("code_field")
        if _code_node is None and _xc:
            _code_node = _find_code_field(_xc)
        if not _set_field(_code_node, code):
            res.login["note"] = ("已取得验证码，但当前界面上没有可填写的验证码输入框，"
                                 "登录未完成")
            res.login["shot"] = _shot("登录页·取到验证码但无输入框")
            log("[!] 取到验证码，但这一屏没有验证码输入框")
            return True
        log("[*] 已填入验证码（%d 位）" % len(code))
        _submitted_code = True
        # 同理：验证码为空时「登录」也是灰的，填完码要再取一次节点
        _x2 = uiwalk.dump_retry(serial, tries=2, wait=0.8)
        _i2 = uiwalk.login_screen(_x2) if _x2 else None
        if _i2 and _i2.get("submit") is not None:
            info = _i2
    elif info.get("pwd_field") is not None and info.get("code_field") is None:
        # ★ 只有账号密码登录的页面（2026-11-06 春雨诊所 / 万步健康实测）：
        #   那一屏是「手机号 + 密码 + 登录」，没有「获取验证码」。
        #   旧代码照样点了一次「登录」（密码为空），然后把结果写成
        #   "已提交，但界面仍停留在登录页（可能校验码错误或被风控）"——
        #   一次登录请求都没成功发出过，却把原因归到"校验码错误"。
        #   这类假话比"没登录上"严重得多：复核员会去查短信记录，那里什么都没有。
        #
        #   现在的处置顺序（每一步都留下证据）：
        #     ① 台账里有这个包的账号 → 用台账密码登录（不新建账号）
        #     ② 没有 → 走「注册」（用户 2026-11-06 拍板允许，密码规则固定并落盘）
        #     ③ 连注册入口都没有 → 如实写能力边界，一个字都不编
        from . import accounts as accounts_mod
        _acc = accounts_mod.find(res.package, phone)
        if _acc and _acc.get("password"):
            log("[*] 本地台账里已有该应用的测试账号（%s），直接用台账密码登录，"
                "不重复注册" % accounts_mod.masked(phone))
            if _password_login(res, xml, serial, log, phone,
                               str(_acc["password"])):
                res.login["account_source"] = "台账（此前注册过）"
                return True
            # ★ 失败原因要分开看，不能一律当成"账号没了去重注册一个"：
            #   · 页面上没有密码框（prep 把页面切到验证码表单了）→ 这是我们的
            #     页面状态问题，**绝不能**因此去注册（会重复建号）；
            #   · 真的提交了但没过 → 才可能是密码改过/账号注销。
            if res.login.get("no_pwd_field"):
                log("[!] 台账密码登录没做：当前页面没有密码输入框，不重复注册")
                return True
            log("[!] 台账密码登录提交后仍停在登录页（密码可能已改/账号已注销），"
                "改为尝试注册")
            res.login["account_stale"] = True
        res.login["password_only"] = True
        if _register_assist(res, xml, serial, log, phone,
                            get_code, timeout, should_stop):
            res.login.setdefault("account_source", "本轮注册")
            return True
        res.login["note"] = (
            "该应用的登录页只提供账号密码登录（页面上没有「获取验证码」入口），"
            "也没有可用的注册入口；本轮只有测试手机号、没有该账号的密码，"
            "因此没有提交任何登录请求；登录态后的功能按「跳过未测」处理，"
            "不代表应用没有这些功能")
        res.login["shot"] = _shot("登录页·仅账号密码登录（未提交）")
        log("[!] 登录页没有短信验证码入口、也没有注册入口，未提交登录请求；"
            "登录态后的功能按「跳过未测」处理")
        return True

    if info.get("submit") is not None:
        uiwalk.tap_node(serial, info["submit"])
        time.sleep(3.0)
    else:
        res.login["note"] = "已填手机号与验证码，但未找到「登录」按钮，登录未完成"

    # 判定成功：登录页消失，且不再是"手机号+验证码"那种形态
    xml2 = uiwalk.dump_retry(serial, tries=2, wait=0.8)
    texts2 = uiwalk.screen_texts(xml2) if xml2 else []
    still = uiwalk.login_screen(xml2) if xml2 else None
    res.login["ok"] = bool(xml2) and still is None
    res.login["after_texts"] = texts2[:8]
    res.login["shot"] = _shot("登录后界面" if res.login["ok"] else "登录失败界面")
    if res.login["ok"]:
        res.login["note"] = ("已用测试手机号 %s 完成登录，登录态下继续遍历"
                             % _mask_phone(phone))
        res.ui_steps.append("代填测试账号并完成登录（%s）" % _mask_phone(phone))
        log("[*] 登录成功，继续遍历登录态页面")
    else:
        # 失败原因要按**实际做过什么**分开写：填过验证码与没填过，
        # 对复核员是两条完全不同的排查路径（查短信记录 vs 查为什么没发码）。
        if _submitted_code:
            res.login["note"] = res.login.get("note") or (
                "已填入验证码并提交登录，但界面仍停留在登录页"
                "（可能验证码错误、已过期或被风控拦截）")
        else:
            res.login["note"] = res.login.get("note") or "已提交登录请求，但界面仍停留在登录页"
        log("[!] 登录后界面仍在登录页，按未登录继续遍历")
    return True


POLICY_ENTRY_STRICT = ("个人信息保护政策", "隐私政策", "隐私权政策", "隐私权声明",                       "个人信息保护指引", "隐私保护政策", "用户隐私政策",
                       "隐私协议", "个人信息保护规则", "隐私条款", "用户协议",
                       # ---- 实测补充（来自 33 个真实受测 App 的样本库复核）----
                       # 滴滴出行首启弹窗里的入口文字是「服务协议及个人信息处理规则」，
                       # 而《个人信息保护法》正文用的词也是「个人信息处理规则」，
                       # 不是「保护政策/保护规则」。缺了这几个词，整个弹窗会被漏掉，
                       # 于是走到"形态 C"分支、报出「首启未提示隐私政策」——
                       # 那是**假阳性**，属于最不能接受的一类误报。
                       "个人信息处理规则", "个人信息处理政策", "个人信息处理",
                       "服务协议及个人信息处理规则", "协议与规则")

# 「查看/详情」这类指向政策的按钮文字
POLICY_ACTION_HINT = ("查看", "详情", "链接", "全文", "点击查看", "查看详情")

# 弱关键词：只用于判断「这一屏上到底有没有政策相关表述」。
# 与 STRICT 的区别在于它**不参与挑选点击入口**（挑入口必须精确，否则会点错东西），
# 只影响 has_policy_word 这个布尔量。加入「协议」「规则」是因为首启弹窗上
# 只要出现这两个词，几乎必然是协议类内容，值得让流程多花几秒去收割。
POLICY_WORD_WEAK = ("隐私", "个人信息", "服务协议", "用户协议", "协议与规则", "处理规则")


def _harvest_ui_text(xml: str, min_len: int = 120) -> str:
    """把界面上的长文本当作政策正文候选。

    这是真机实测得出的结论：相当多的 App（尤其政务/金融类）**不提供可点击的政策
    链接**，而是把《隐私协议》全文直接铺在弹窗或政策页里（一个长 TextView）。
    此时 uiautomator dump 就能直接拿到全文，比点击链接可靠得多。
    """
    chunks: List[str] = []
    for n in uiwalk.parse_all(xml):
        t = (n.text or "").strip()
        if len(t) >= min_len:
            chunks.append(t)
    if not chunks:
        return ""
    chunks.sort(key=len, reverse=True)
    out: List[str] = []
    for c in chunks[:3]:
        if c not in out:
            out.append(c)
    return "\n".join(out)


def page_full_text(xml: str, max_len: int = 60000) -> str:
    """按文档顺序把界面上所有文本节点拼起来（不是"取最长的三段"）。

    ★ 为什么必须单独有这一条（2026-11-08 小包搜题）：
      政策页是 WebView，正文被拆成 100 多个虚拟文本节点，每个 50~200 字，
      谁都不长。`_harvest_ui_text` 只取最长的 3 段，于是拿到的是正文**中段**
      （「设备品牌、型号、软件系统版本…」共 852 字），开头那句
      「隐私政策 / 本政策仅适用于广州小宇宙科技有限公司…」被丢掉了 ——
      类型闸门 `looks_like_privacy_policy` 因此判 False，整页 6624 字
      一个都没进 bestText，结论退化成「打开了页面但取不到条款」。
      按文档顺序拼接后 6970 字，闸门通过，政策全文到手。

    `&#10;` 是 uiautomator 对换行的转义，按空白处理；相邻重复节点去掉
    （WebView 常把同一段落拆成"正文 + 换行"两个节点）。
    """
    out: List[str] = []
    last = None
    for n in uiwalk.parse_all(xml or ""):
        t = (n.text or "").replace("&#10;", " ").strip()
        if not t or t == last:
            continue
        last = t
        out.append(t)
        if sum(len(s) for s in out) >= max_len:
            break
    return "\n".join(out)


def policy_page_text(xml: str) -> str:
    """政策页正文的取法：**按文档顺序拼全页**，取不到才退回"最长的三段"。

    为什么不再以 `_harvest_ui_text` 为主（2026-11-09 快搜搜题实测）：
    它按长度排序取前 3 段，出来的正文**没有顺序、也不含开头** ——
    那一轮 bestText 只有 2502 字，开头是「1.您通过快搜搜题指定的方式依约
    支付费用后即开通本服务」，即服务协议的中段；政策正文的第一句
    「本政策仅适用于…」根本不在里面。用户要的是"全文"，中段截取不是全文。

    全量拼接的代价是会把按钮/导航文案（「同意并继续」「返回」）也拼进来，
    所以它只用在**政策页**这一处；弹窗那类界面仍走 `_harvest_ui_text`。
    """
    full = page_full_text(xml)
    if full.strip():
        return full
    return _harvest_ui_text(xml)


def _looks_like_html(txt: str) -> bool:
    """这段"政策正文"其实是 HTML 源码吗？

    ★ 2026-11-09 Q船 4.4.2：`bestText` 以 `<html>` 开头、10321 字里全是
      `<div>` / `<p>` / `<li style="list-style: none;">`。原因是该 App 用
      `WebView.loadDataWithBaseURL(base, html, "text/html", …)` 把**源码**
      直接交给 WebView，注入脚本抓到的是 `args[1]`（源码），不是渲染后的文字。
      这不是个别现象：Flutter / uniapp 类应用把政策当资源文件塞进 WebView 时
      很常见。后果有两层 —— 报告里的"政策正文"读起来像代码（用户第 5 条
      抱怨的"可读性非常差"），以及关键词/声明抽取被标签污染。
    """
    t = (txt or "").lstrip()
    if not t.startswith("<"):
        return False
    head = t[:400].lower()
    return ("<html" in head or "<body" in head or "<div" in head
            or "<p>" in head or "<!doctype" in head)


def html_to_text(html: str) -> str:
    """HTML 源码 → 纯文本。保留段落换行，去掉脚本/样式/标签，解常见实体。

    只求"读得懂、能检索"，不追求版式还原：政策正文用于关键词匹配、声明类型
    抽取与人工复核，段落顺序与文字本身才是要点。
    """
    s = str(html or "")
    if not s.strip():
        return ""
    # ★ 先交给 policy 模块里基于 html.parser 的抽取器：它按标记状态机走，
    #   对"被截断在标签中间"的输入天然安全（镜像投屏那 20 万字正好断在
    #   `<span style="…` 里）。下面的正则路径是它的兜底，两者结果不一致时
    #   以解析器为准 —— 正则剥标签在超长 style 属性上很容易漏。
    try:
        _parsed, _ = _POL.html_to_text(s)
        if len((_parsed or "").strip()) >= 200:
            return _parsed.strip()
    except Exception:
        pass
    s = s.replace("\r\n", "\n").replace("\r", "\n")   # 统一换行，否则 `\n\r\n` 排不干净
    s = re.sub(r"(?is)<script.*?</script>", " ", s)
    s = re.sub(r"(?is)<style.*?</style>", " ", s)
    s = re.sub(r"(?is)<head.*?</head>", " ", s)
    s = re.sub(r"(?s)<!--.*?-->", " ", s)
    # ★ 截断的 HTML 会留下半截标签（镜像投屏 2026-11-09 实测）：
    #   采集时正文按 200000 字截断，正好切在 `<span style="font-size: 11pt;
    #   font-family: …` 中间。下面的剥标签正则要求 `<…>` 闭合，这半截整个
    #   留在正文里，于是"纯文本"以 `l; background-size: initial; …` 收尾。
    #   先把没有闭合的尾段切掉，比事后清 CSS 干净得多。
    _lt = s.rfind("<")
    if _lt > 0 and ">" not in s[_lt:]:
        s = s[:_lt]
    s = re.sub(r"(?i)<br\s*/?>", "\n", s)
    s = re.sub(r"(?i)</(p|div|li|tr|h[1-6]|section|article|ul|ol|table)\s*>", "\n", s)
    # ★ 不设长度上限（原来是 `<[^>]{1,400}>`）：公众号排版类政策的内联样式
    #   常有上千字符的 style 属性，超过 400 就整段匹配不上，CSS 会原样留在正文里
    #   （镜像投屏 2026-11-09：转出来的"纯文本"结尾是 `font-family: NSimSun,…`）。
    s = re.sub(r"(?s)<[^<>]*>", " ", s)
    _ent = {"&nbsp;": " ", "&lt;": "<", "&gt;": ">", "&quot;": '"',
            "&#39;": "'", "&apos;": "'", "&emsp;": " ", "&ensp;": " ",
            "&amp;": "&"}
    for k, v in _ent.items():
        s = s.replace(k, v)
    s = re.sub(r"&#(\d{2,5});", lambda m: chr(int(m.group(1))), s)
    s = s.replace("\u00a0", " ")
    # 属性值里带分号的 CSS 片段（`background-size: initial; …`）成串出现时清掉：
    # 要求至少两条"键: 值;"才算，中文正文里的"电话: 123456;"不会命中。
    s = re.sub(r"(?:(?:[a-z-]{2,20})\s*:\s*[^;\"\n]{1,60};\s*){2,}", " ", s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n[ \t]+", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def _merge_chunks(parts: List[str]) -> str:
    """合并多次滚动采集到的文本块，去掉重复片段。"""
    seen: List[str] = []
    for p in parts:
        p = (p or "").strip()
        if not p:
            continue
        # 已经是包含关系就跳过
        if any(p in s for s in seen):
            continue
        seen = [s for s in seen if s not in p]
        seen.append(p)
    return "\n".join(seen)


def _pick_policy_entry(xml: str) -> Optional[uiwalk.UiNode]:
    """在界面中挑出**真正可点击**的隐私政策入口。

    坑：很多弹窗的标题就叫「隐私政策」，但它 clickable=false，点它毫无反应。
    因此这里要求节点必须 clickable，并且优先选短文字（标题/按钮）而不是
    整段声明正文 —— 点正文只会滚动或选中文本。
    """
    nodes = [n for n in uiwalk.parse_all(xml) if n.clickable and n.enabled]
    cands = uiwalk.find_by_keywords(nodes, POLICY_ENTRY_STRICT)
    cands = [n for n in cands if len(n.text.strip()) <= 30 or n.content_desc]
    if not cands:
        return None

    def score(n: uiwalk.UiNode) -> tuple:
        x1, y1, x2, y2 = n.bounds
        return (0 if any(h in n.text for h in POLICY_ACTION_HINT) else 1,
                len(n.text), abs((x2 - x1) * (y2 - y1)))
    cands.sort(key=score)
    return cands[0]


# ---------------------------------------------------------------- 内联政策链接
#
# ★ 为什么单开一路（2026-11-08，岛 2.2.0 实测）：
#   首启弹窗把《用户协议》《隐私协议》写在一段正文里：
#     · 与正文同色、无下划线，视觉上完全看不出可点；
#     · 结构树里没有独立节点（整段正文只有 1 个 TextView）——
#       `_pick_policy_entry()` 要求节点 clickable，必然落空；
#     · 也没有 ClickableSpan —— AI 视觉只能说"仅有一段告知文本"。
#   结果：入口一次没点过，报告写"未观测到政策入口"。
#   **但真机上按文字位置点下去确实能打开政策页**（前台切到 BrowserActivity，
#   正文《隐私政策》全文可读，URL 在 Activity intent 的 extra 里）。
#
#   所以补这条路：让 App 进程自己按 TextView 的 Layout 把
#   「书名号片段 / 政策关键词」算成屏幕坐标（见 hooks/collector.js
#   的 collectPolicyLinks），再逐个真实点击。
#   注意顺序：弹窗（dialog/popup）里的点优先 —— 界面上的模态弹窗会吃掉
#   下面 Activity 的触摸事件，点 activity 里被盖住的链接毫无反应（岛实测）。

# 每轮最多试几个候选点（弹窗正文里通常只有 2~4 个书名号片段）
INLINE_LINK_TRY_MAX = 6


def _link_tried_key(link: Dict[str, Any]) -> str:
    xy = link.get("xy") or [0, 0]
    return "%s@%s,%s" % ((link.get("text") or "")[:20], xy[0], xy[1])


def _rank_inline_links(links: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """候选点排序：弹窗内的 > 带 URL 的 > 含"隐私"的 > 书名号 > 关键词。"""
    def score(ln: Dict[str, Any]) -> tuple:
        win = str(ln.get("win") or "")
        txt = str(ln.get("text") or "")
        src = str(ln.get("src") or "")
        return (
            0 if win in ("dialog", "popup") else 1,     # 弹窗在最上层，能收到触摸
            0 if ln.get("url") else 1,                  # 自带 URL 的最可靠
            0 if "隐私" in txt else 1,
            0 if src == "anchor" else (1 if src == "span" else 2),
            -len(txt),
        )
    return sorted([ln for ln in links or [] if ln.get("xy")], key=score)


def _inline_policy_entry(serial: str, res: Optional["ScanResult"], cap: Dict[str, Any],
                         log: Callable[[str], None],
                         get_script: Callable[[], Any]) -> Optional[uiwalk.UiNode]:
    """结构树与 AI 都没给出入口时，从 App 进程内算出"内联链接"的可点坐标。

    每次只返回**一个**尚未试过的候选点（返回 UiNode，坐标就是精确的点击点），
    由调用方走既有的「点击 → 判定是否进入新页面 → 收割正文」流程。
    试过哪些点记在 cap["inlineTried"]，下一轮换下一个 —— 这样即使某个候选
    是"标题文字、点不动"，也不会一直卡在它身上。
    """
    tried = cap.setdefault("inlineTried", [])
    links: List[Dict[str, Any]] = []
    try:
        links = list(get_script().exports_sync.policy_links(24) or [])
    except Exception as e:
        cap.setdefault("inlineNotes", []).append("读取内联链接坐标失败：%s" % e)
        return None
    if not links:
        return None
    if not cap.get("inlineLinks"):
        cap["inlineLinks"] = links
    fresh = [ln for ln in _rank_inline_links(links) if _link_tried_key(ln) not in tried]
    if not fresh:
        return None
    if len(tried) >= INLINE_LINK_TRY_MAX:
        return None
    ln = fresh[0]
    key = _link_tried_key(ln)
    tried.append(key)
    x, y = int(ln["xy"][0]), int(ln["xy"][1])
    # 小框只为了携带精确中心：调用方按 center 点，不需要在框内采样。
    node = uiwalk.UiNode(
        text=str(ln.get("text") or "隐私政策"),
        cls="inline-link",
        resource_id="",
        bounds=(x - 2, y - 2, x + 2, y + 2),
        clickable=True,
    )
    where = {"dialog": "弹窗内", "popup": "浮层内", "activity": "页面内"}.get(
        str(ln.get("win") or ""), "未知窗口")
    log("[*] 结构树与 AI 都没找到可点的政策入口；改按文字位置点击内联链接："
        "「%s」(%d,%d)（%s，来源=%s）"
        % (node.text[:24], x, y, where, ln.get("src") or "?"))
    if res is not None:
        res.ui_steps.append("按文字位置点击内联政策链接：「%s」(%d,%d)" % (node.text[:20], x, y))
    if ln.get("url"):
        cap.setdefault("inlineUrlFromSpan", []).append(ln["url"])
    return node


# 拒绝/退出类文字：绝不能当作"同意"点击。
# 「同意」是「不同意」的子串，这是全项目最容易踩、后果最重的一个中文匹配坑。
REJECTION_WORDS = ("不同意", "不接受", "不认可", "拒绝", "暂不", "以后再说",
                   "残忍", "放弃", "退出", "取消", "关闭")


def _is_rejection_label(text: str) -> bool:
    """按钮文字是否属于「拒绝 / 退出」语义。"""
    t = (text or "").strip()
    return bool(t) and any(w in t for w in REJECTION_WORDS)


# ---------------------------------------------------------------- 同意动作（分水岭）
#
# ★ 为什么不能直接复用 `uiwalk.CONSENT_KEYWORDS`：
#   那张表的用途是"把弹窗点掉、别把流程卡死"，里面含「确定」「允许」「好的」
#   这类中性按钮 —— 拿它判定"用户是否同意隐私政策"，点一次「确定」就会被记成
#   同意了整套政策。分水岭一旦标早，之后所有行为都落进"同意后"，
#   「未经同意收集」这一项直接消失 —— 这是把违规洗白的方向，最不能错。
#
# 因此按证据强度分三档：
#   explicit —— 弹窗/按钮文字本身就是"同意"语义（同意并继续、同意并接受…）
#   checkbox —— 登录页勾选"我已阅读并同意《隐私政策》"（比按钮弱，但仍属明示）
#   weak     —— 「确定」「允许」「好的」这类中性确认（**不作为分水岭**）
CONSENT_LABEL_MAX = 40
# 「这一行里有政策文档名」与「这一行里有同意表述」两件事分开判：
# 只有同时命中才叫"同一行里既有同意又有协议链接"，见 `_mark_consent_after_tap`。
_DOC_PHRASE = re.compile(r"《[^》]{2,24}》|隐私政策|隐私协议|用户协议|服务协议|隐私权政策")
_CONSENT_PHRASE = re.compile(r"同意|接受|允许|确认")

CONSENT_CHECKBOX_WORDS = ("我已阅读并同意", "已阅读并同意", "阅读并同意",
                          "我已阅读并接受", "已阅读并接受")

CONSENT_EXPLICIT_WORDS = ("同意并继续", "同意并接受", "同意并开始", "同意并进入",
                          "同意并登录", "同意并使用", "同意后继续", "同意并同意",
                          "同意并前往", "我同意", "同意")

CONSENT_WEAK_WORDS = ("接受", "允许", "我知道了", "知道了", "好的", "确定", "继续")


def _consent_label_kind(text: str, *, in_policy_dialog: bool = False
                        ) -> Tuple[str, str]:
    """按钮文字 → (强度, 理由)。强度为空表示"这不是一个同意动作"。

    `in_policy_dialog=True` 时，中性确认词（确定/接受/继续）在**隐私政策告知弹窗**
    上也算明示同意 —— 弹窗上只有一个「确定」，点它就是对这段告知的接受。
    这个参数只在首启弹窗那条路径上传 True（那里的界面已被判定为政策告知框）；
    遍历途中的「确定」一律按 weak 处理，避免把普通对话框的确认当成同意。
    """
    t = (text or "").strip()
    if not t:
        return "", "无文字"
    if len(t) > CONSENT_LABEL_MAX:
        return "", "文字过长（%d 字），是正文而非按钮" % len(t)
    # ★ 先把空白抹掉再匹配（2026-11-09 岛 2.2.0 实测）：
    #   它的按钮文字是「同  意」—— 两个汉字之间夹了空格，排版上更居中，
    #   代价是我们的子串匹配整场落空：`"同意" in "同  意"` 为假 →
    #   这个按钮被判成"与同意无关" → 点了不算同意 → 之后 133 条事件
    #   全部落在"同意前"，P3 报「未捕获到同意事件」，报告里那 20 多项
    #   行为项全部没法用。抹掉空白只影响匹配，`why` 里仍写原文，便于核对。
    _m = re.sub(r"[\s\u00a0\u3000]+", "", t)
    if _is_rejection_label(_m):
        return "", "含否定词（不同意/拒绝/取消/跳过），不视为同意"
    # 勾选框要排在最前面：「我已阅读并同意」同时含「同意」，先判会落到 explicit
    if any(w in _m for w in CONSENT_CHECKBOX_WORDS):
        return "checkbox", "勾选「%s」" % t
    if any(w in _m for w in CONSENT_EXPLICIT_WORDS):
        return "explicit", "点击「%s」" % t
    if any(w in _m for w in CONSENT_WEAK_WORDS):
        if in_policy_dialog:
            return "explicit", "隐私政策告知弹窗上点击「%s」" % t
        return "weak", "「%s」属中性确认，未作为同意分水岭" % t
    return "", "与同意无关"


_STRENGTH_LABELS = {
    "explicit": "弹窗/按钮明示同意",
    "checkbox": "登录页勾选协议",
    "script": "采集脚本观测到点击",
    "weak": "中性确认（不计为分水岭）",
}


def _mark_consent(res: ScanResult, label: str, via: str,
                  log: Callable[[str], None] = print, *,
                  set_consent: Optional[Callable[[str], None]] = None,
                  strength: str = "explicit",
                  elapsed_ms: Optional[int] = None,
                  screen_label: str = "",
                  verified: bool = True,
                  why: str = "") -> bool:
    """登记一次同意动作；成为"分水岭"时返回 True。

    ★ 这是**唯一**的同意登记入口。此前 consent_given 在 4 处各写一遍
      （首启点同意、首启 AI 无节点屏、遍历调度器、脚本消息），写法还不一致：
      有的记得同步脚本、有的不记时刻、有的连 consent_source 都不写。
      真机实测（以观书法 mbsf6）就吃在这个缝里 —— 政策下钻时 AI 顺手点了
      「同意并继续」，走的是第 5 条路径（下钻点击），一处都没登记，
      于是 50 条事件全标"同意前"，P3 报"未捕获到同意事件"。

    分水岭只认**第一条**有效（explicit / checkbox / script）记录：
    用户可能点多次同意（弹窗 → 登录页），但"同意前/后"的分界只有一条。

    同时往 `res.events` 里插一条 `signal=CONSENT` 的边界事件，让事件流里
    有一个显式的分水岭；该事件带 `noise` 标记，不参与任何"收集了什么"的统计
    （见 compare.event_pi），但仍留在存档里可审计。
    """
    now_ms = int(elapsed_ms) if elapsed_ms is not None else int(
        (time.time() - float(getattr(res, "started_at", 0) or time.time())) * 1000)
    lab = (label or "").strip()[:CONSENT_LABEL_MAX]
    strength = strength or "explicit"
    rec: Dict[str, Any] = {
        "elapsed_ms": now_ms,
        "label": lab,
        "via": via,
        "strength": strength,
        "strength_label": _STRENGTH_LABELS.get(strength, strength),
        "watershed": False,
        "verified": bool(verified),
        "screen_label": screen_label or "",
        "screenshot_idx": -1,
        "sync": "not_attempted",
        "why": why or "",
    }
    res.consent_events.append(rec)

    if strength == "weak":
        rec["why"] = why or ("「%s」是中性确认按钮，不作为隐私政策同意的分水岭"
                             % (lab or "该按钮"))
        log("[.] 记录到中性确认点击「%s」（%s），不计入同意分水岭" % (lab, via))
        return False

    if res.consent_given:
        rec["why"] = "分水岭已定在冷启动后 %.1fs，本条为后续重复的同意动作" % (
            (res.consent_elapsed_ms or 0) / 1000.0)
        log("[.] 又捕获到一次同意类点击「%s」（%s），分水岭不重复登记" % (lab, via))
        return False

    # ---- 成为分水岭 ----
    rec["watershed"] = True
    res.consent_given = True
    res.consent_strength = strength
    res.consent_source = "ui:%s" % (lab or via)
    res.consent_elapsed_ms = now_ms
    mark(res, "consent", now_ms)

    # 分水岭取证图（独立配额，不和遍历截图抢名额）
    try:
        if len(res.screenshots) < res.max_shots + PERM_SHOT_EXTRA + CONSENT_SHOT_EXTRA:
            raw = capture_screenshot(getattr(res, "device_serial", "") or "")
            if raw:
                rec["screenshot_idx"] = len(res.screenshots)
                res.screenshots.append({
                    "label": "同意动作·分水岭（冷启动后 %.1fs）" % (now_ms / 1000.0),
                    "activity": uiwalk.top_activity(res.device_serial),
                    "b64": base64.b64encode(raw).decode("ascii"),
                })
            else:
                # 没拍到也要留一句：不留的话"为什么这张图是空的"无从查起，
                # 复核员会以为我们漏拍了某个环节。
                rec["why"] = (rec["why"] + "；" if rec["why"] else "") + "截图失败：未取到图像数据"
    except Exception as e:            # 截图失败不影响同意事实本身
        rec["why"] = (rec["why"] + "；" if rec["why"] else "") + "截图失败：%s" % e

    # 同步给采集脚本：此后 hook 侧上报的事件才会被标成"同意后"
    if set_consent is not None:
        try:
            set_consent(lab or "同意")
            rec["sync"] = "ok"
        except Exception as e:
            rec["sync"] = "failed:%s" % type(e).__name__
            res.errors.append(
                "同意状态未能同步到采集脚本（%s）；同意事实已按 UI 点击记录，"
                "但脚本侧无法据此区分「同意前/后」，本报告的事件时序字段请谨慎使用"
                % type(e).__name__)
    else:
        rec["sync"] = "not_applicable"

    # 分水岭事件：让事件流里有一条显式的边界（不进任何收集统计）
    res.events.append(PIIEvent(
        hook_id="CONSENT",
        category="consent",
        api="用户点击「%s」" % (lab or via),
        args="触发方式：%s｜强度：%s" % (via, _STRENGTH_LABELS.get(strength, strength)),
        result="同意",
        ts=int(time.time() * 1000),
        elapsed_ms=now_ms,
        # 本条既不是"同意前"也不是"同意后"的行为：它就是分界点本身。
        # 记成 False 是为了不让它落进 before_consent_events（会多报一条"同意前收集"）。
        before_consent=False,
        signal="CONSENT",
        group="同意动作",
        pi="",
        evidence="A",
        sink="",
        activity=screen_label or "",
        ui_action=lab,
        screenshot_idx=int(rec["screenshot_idx"]),
        noise="同意动作标记：这是判定「同意前/后」的分界点，本身不是个人信息收集行为",
    ))
    log("[*] 同意分水岭已登记：%s（冷启动后 %.1fs，%s，强度=%s，脚本同步=%s）"
        % (lab or via, now_ms / 1000.0, via,
           _STRENGTH_LABELS.get(strength, strength), rec["sync"]))
    return True


def _ensure_consent_marker(res: ScanResult,
                           log: Callable[[str], None] = print) -> bool:
    """收尾兜底：同意了就必须有分水岭事件。

    有些路径只知道"同意了"而没有登记过程 —— 例如脚本 summary 回执
    （`summary.consent=True`）、或旧存档里只有 `consent_given`。
    缺了边界事件，报告的时间线就断了，P3 又会写回"未捕获到同意事件"。
    """
    if not res.consent_given:
        return False
    if any(getattr(e, "signal", "") == "CONSENT" for e in res.events):
        return False
    src = (res.consent_source or "").strip()
    lab = src[3:] if src.startswith("ui:") else (src or "同意（来源未记录）")
    strength = res.consent_strength or "script"
    ms = int(res.consent_elapsed_ms or 0)
    ev = PIIEvent(
        hook_id="CONSENT", category="consent",
        api="用户点击「%s」" % lab[:CONSENT_LABEL_MAX],
        args="触发方式：收尾补齐（采集过程中未走到登记点）",
        result="同意",
        ts=int((res.started_at or time.time()) * 1000) + ms,
        elapsed_ms=ms,
        before_consent=False, signal="CONSENT", group="同意动作", pi="",
        evidence="A", sink="", ui_action=lab[:CONSENT_LABEL_MAX],
        noise="同意动作标记：这是判定「同意前/后」的分界点，本身不是个人信息收集行为",
    )
    # 按时刻插回事件流，别直接 append 到末尾 ——
    # 报告的时间线是按列表顺序画的，分水岭贴在最后会让人以为同意发生在收尾时。
    _pos = len(res.events)
    for _i, _e in enumerate(res.events):
        if int(getattr(_e, "elapsed_ms", 0) or 0) > ms:
            _pos = _i
            break
    res.events.insert(_pos, ev)
    if not res.consent_events:
        res.consent_events.append({
            "elapsed_ms": ms, "label": lab, "via": "收尾补齐",
            "strength": strength,
            "strength_label": _STRENGTH_LABELS.get(strength, strength),
            "watershed": True, "verified": False, "screen_label": "",
            "screenshot_idx": -1, "sync": "not_applicable",
            "why": "采集过程中未走到同意登记点，按已有结论补齐分水岭事件",
        })
    log("[*] 收尾补齐同意分水岭事件（来源：%s）" % (src or "未记录"))
    return True


def _mark_consent_after_tap(res: Optional[ScanResult], node: Any, via: str,
                            log: Callable[[str], None] = print, *,
                            signal: str = "",
                            screen_label: str = "",
                            set_consent: Optional[Callable[[str], None]] = None) -> bool:
    """点击之后补登记：这次点的按钮是不是同意按钮。

    为什么要在"点击"这一层兜一道：同意入口可能从任意一条路径被点到 ——
    首启弹窗的显式点击、政策下钻时 AI 顺手点的、遍历调度器点的。
    只在这些路径各写一遍判定，迟早漏掉一条（mbsf6 漏的就是 AI 下钻那条）。

    ★ `set_consent` 必须由调用方传进来（拿当前有效的脚本句柄去同步）。
      本函数是模块级的，取不到采集现场那个闭包里的 `_fresh_script()`——
      早先在函数体内直接写 `_fresh_script()` 会抛 NameError，
      反而把"同意"这件事整个吞掉。不具备同步条件的调用点传 None 即可，
      此时只记事实、同步状态写 not_attempted。

    `signal` 是 `_tap_entry_robust` 的点击有效性判定：
      focus/ui   —— 前台切换或界面内容变化，确认点中了；
      unknown    —— dump 失败，按已点中处理；
      ""（空串） —— 框内所有采样点都没反应，**不能**据此认定用户同意了。
    """
    if res is None:
        return False
    if signal == "":
        return False
    label = (getattr(node, "text", "") or getattr(node, "label", "") or "").strip()
    # ★ 一行里同时含"同意"和《隐私政策》时，点中哪里决定性质，而我们只知道
    #   "点了这一行"（2026-11-10 全国铁路火车票查询）：入口文案就是
    #   「已阅读并同意《用户协议》及《隐私政策》」，点击被登记成"登录页勾选协议"，
    #   而当时页面一寸没动、政策也没打开 —— 分水岭被记在一次**没发生的同意**上，
    #   之后所有"同意前/同意后"的划分全部失真，这才是最贵的错误。
    #   处置：只记一条 weak 候选（写明无法判断），不登记分水岭。
    if _DOC_PHRASE.search(label) and _CONSENT_PHRASE.search(label):
        log("[.] 「%s」同一行内既有同意表述又有协议链接，无法判断点中哪个 ——"
            "本次点击不登记为同意分水岭" % label[:26])
        return _mark_consent(
            res, label, via, log, set_consent=set_consent, strength="weak",
            screen_label=screen_label, verified=False,
            why="同一行内既有同意表述又有协议链接，无法判断点中哪个，不计为分水岭")
    strength, why = _consent_label_kind(label)
    if strength == "":
        return False
    # weak（中性确认）也要留一条候选记录：复核员要能看见"我们点过它、但因为
    # 它不是明示同意所以没算"，而不是看起来像压根没走到过这个按钮。
    return _mark_consent(
        res, label, via, log, set_consent=set_consent,
        strength=strength, screen_label=screen_label,
        verified=(signal in ("focus", "ui")), why=why)



def _pick_consent_button(xml: str) -> Optional[uiwalk.UiNode]:
    """在界面中挑出「同意」按钮（用于显式驱动同意状态）。

    只取短文字的节点（长段声明点下去没意义）。

    ★ 真机血案（滴滴出行）：早先只按子串匹配 —— `"同意" in "不同意"` 为真，
    再加上排序偏好"文字更短"，于是「不同意」(3 字) 稳定击败
    「同意并开始使用」(7 字) 被选中。后果是连锁的：
      点「不同意」→ App 主动退出 → 遍历器判定"App 没了"自动重启 →
      反复冷启被服务端识别为异常 → 弹出滑块验证码接管界面 →
      最终采到的是验证码页，报告里却写着"已捕获同意动作"。
    所以这里必须显式排除否定式，并要求按钮文字以同意词**开头**。

    ★ 第二个真机血案（自设捏脸）：早先只在 `clickable or cls.endswith("Button")`
    的节点里找文字，而 uni-app / 各类自定义弹窗的按钮结构是
    「可点击的 RelativeLayout（无文字）套一层不可点击的 TextView（有文字）」——
    可点的没文字、有文字的不可点，两个条件同时落空，
    于是弹窗上明明写着「同意并接受」，采集器却报"未发现同意按钮"，
    同意时刻没被捕获 → 该轮 102 条事件全被划到"同意前"。
    现改为枚举全部节点，命中文字后交给**包含它的最小可点击祖先**（坐标回退到文字自身）。
    """
    nodes = uiwalk.parse_all(xml)
    clickables = [n for n in nodes if n.clickable]

    def _host_for(n: uiwalk.UiNode) -> uiwalk.UiNode:
        """不可点的文字节点 → 交给包含它的最小可点击祖先；找不到就用文字自身坐标。"""
        if n.clickable:
            return n
        cx, cy = n.center
        best_host = None
        for c in clickables:
            x1, y1, x2, y2 = c.bounds
            if x1 <= cx <= x2 and y1 <= cy <= y2:
                area = max(0, x2 - x1) * max(0, y2 - y1)
                if best_host is None or area < best_host[0]:
                    best_host = (area, c)
        return best_host[1] if best_host else n

    best: Optional[uiwalk.UiNode] = None
    for kw in uiwalk.CONSENT_KEYWORDS:
        hits: List[uiwalk.UiNode] = []
        for n in nodes:
            t = (n.text or "").strip()
            if not t or len(t) > 14 or kw not in t:
                continue
            if _is_rejection_label(t):
                continue
            hits.append(n)
        if hits:
            # 以同意词开头的优先（「同意并开始使用」> 「我已阅读并同意」），
            # 同级再偏好可点击节点、原生 Button，最后取更短的
            hits.sort(key=lambda n: (0 if (n.text or "").strip().startswith(kw) else 1,
                                     0 if n.clickable else 1,
                                     0 if n.cls.endswith("Button") else 1,
                                     len(n.text)))
            best = hits[0]
            break
    if best is None:
        return None
    host = _host_for(best)
    if host is best:
        return best
    # 坐标用可点的祖先，标签保留按钮文字 ——
    # res.consent_source 会写成「ui:同意并接受」，报告要靠这行证明"点的是同意而不是别的"
    from dataclasses import replace
    return replace(host, text=(best.text or "").strip())


# ---------------------------------------------------------------- 按 URL 直取政策
#
# ★ 为什么要「先拿 URL，再拿全文」（用户 2026-10-21 明确提的第一条意见）：
#   在界面上一屏屏上滑读政策，是整轮采集里最贵的一段 ——
#   每滑一次要 1 秒等待 + 一次 uiautomator dump（真机约 2.8s），
#   还要再问模型一次"还要不要再滑"（单次 3~4s）；一页政策滑四五屏就是半分钟，
#   深挖三层就是好几分钟，而这些时间全是从遍历预算里扣的。
#   政策页本身几乎都对应一个 URL（WebView.getUrl / 弹窗里的超链接 / APK 内登记），
#   直接 HTTP 取 HTML 转正文只要 1~2 秒，且拿到的是**完整全文**，
#   比滑动截图拼出来的碎片更可靠。
#   所以顺序必须是：有 URL → 直接抓；抓不到（无 URL / 页面是 JS 渲染 /
#   抓回来太短）→ 才退化成"不断上滑截图阅读"。
_POLICY_URL_HINT = re.compile(
    r"(privacy|policy|agreement|protocol|secret|yinsi|privacypolicy|useragree)", re.I)
# 一眼就不该抓的（图片/下载/接口/第三方客服域名留给人工判断）
_POLICY_URL_SKIP = re.compile(
    r"\.(apk|png|jpe?g|gif|svg|ico|css|js|woff2?|mp4|pdf|zip)(\?|$)", re.I)


def _rank_policy_urls(urls: Sequence[Any]) -> List[str]:
    """把候选 URL 按"像不像隐私政策"排序并去重。

    排序不等于认定：这里只决定**先试哪个**，抓回来的正文仍要过
    `_POL.looks_like_privacy_policy()` 那道类型闸门 —— 顺序可以错，
    闸门不能错（以观书法实测：真正的教训是"文档拿错"而不是"顺序不对"）。
    """
    out: List[str] = []
    seen: set = set()
    for u in urls or []:
        if isinstance(u, dict):
            u = u.get("url") or ""
        u = str(u or "").strip()
        if not u or not u.lower().startswith(("http://", "https://")):
            continue
        if u in seen:
            continue
        seen.add(u)
        if _POLICY_URL_SKIP.search(u):
            continue
        out.append(u)
    out.sort(key=lambda s: (0 if _POLICY_URL_HINT.search(s) else 1, len(s)))
    return out


def fetch_policy_by_url(urls: Sequence[Any], log: Callable[[str], None] = print,
                        min_len: int = 800, timeout: int = 12,
                        max_try: int = 3) -> Dict[str, Any]:
    """按 URL 直接取政策全文。

    恒返回一个 dict：`{"ok", "url", "text", "title", "chars", "tried"}`。
    为什么不成功就返回 None —— 因为"试过哪几个、各自为什么没成"本身就是
    要写进报告的取证（复核员要知道我们不是没试过，而是试了没拿到）；
    返回 None 就把这段证据丢了。

    ★ 只在"确实拿到了像样的隐私政策"时才算成功：
        · 抓回来过短（< min_len）→ 多半是 JS 渲染或跳板页，不算；
        · 不像隐私政策（类型闸门）→ 宁可不认，也不能拿会员协议当政策
          （《VIP会员服务协议》顶掉真政策那次就是这个坑）；
        · 命中第三方品牌（腾讯兔小巢那类）→ 不认。
      任何一步不过，就如实记一条 `tried` 留痕，让调用方退回滑动采集。
    """
    tried: List[Dict[str, Any]] = []
    for u in _rank_policy_urls(urls)[:max_try]:
        try:
            r = _POL.fetch(u, timeout=timeout, log=log)
        except Exception as e:
            tried.append({"url": u, "ok": False, "why": "%s: %s" % (type(e).__name__, e)})
            continue
        txt = (getattr(r, "text", "") or "").strip()
        why = ""
        if getattr(r, "error", ""):
            why = str(r.error)
        if len(txt) < min_len:
            tried.append({"url": u, "ok": False, "chars": len(txt),
                          "why": why or "正文过短（%d 字），可能是 JS 动态渲染" % len(txt)})
            continue
        if not _POL.looks_like_privacy_policy(txt):
            tried.append({"url": u, "ok": False, "chars": len(txt),
                          "why": "抓到的正文不像隐私政策（开头为「%s」）"
                                 % txt[:20].replace("\n", " ")})
            continue
        tp = _POL.third_party_reason(txt, package="", url=u) or ""
        if tp:
            tried.append({"url": u, "ok": False, "chars": len(txt),
                          "why": "疑似第三方政策（%s）" % tp})
            continue
        log("[+] 已按链接直接取得政策全文：%d 字（%s）" % (len(txt), u))
        return {"ok": True, "url": u, "text": txt,
                "title": getattr(r, "title", "") or "",
                "chars": len(txt), "tried": tried}
    if tried:
        log("[.] 按链接取政策未成功（试了 %d 个）：%s"
            % (len(tried), "；".join(str(t.get("why") or "")[:40] for t in tried[:3])))
    return {"ok": False, "url": "", "text": "", "title": "",
            "chars": 0, "tried": tried}


# ---------------------------------------------------------------- AI 辅助
#
# 设计原则：AI 是**增强**而非**依赖**。
# 下面每个函数都可能返回 None，调用方一律准备好回退到关键词/结构树策略。
# 原因是现实的：内网可能拉不到模型、模型可能挂、prompt 可能被模型理解偏。
# 任何一环出问题，检测都必须照常给出报告 —— 顶多是能力弱一点，不能跑不出来。

def _build_ai(cfg, log: Callable[[str], None]) -> Optional[AITasks]:
    """按配置构造 AI 能力；任何异常都降级为 None（整条链路走确定性策略）。

    实际构造逻辑在 piiscan.ai.factory.build_tasks_safe 里 —— 平台与命令行
    共用同一套，避免两处实现漂移。
    """
    return build_tasks_safe(cfg.ai, log)


def _ai_record(res: ScanResult, stage: str, ret, action: str = "",
               extra: Optional[Dict[str, Any]] = None) -> None:
    """把一次 AI 判断记入轨迹。

    为什么记这么细：报告要能回答「这一步到底是 AI 判的还是规则判的、依据是什么」。
    少了这层留痕，AI 的参与就成了不可复核的黑盒，检测底稿也就失去意义。
    """
    if ret is None:
        return
    rec: Dict[str, Any] = {
        "stage": stage,
        "ok": bool(getattr(ret, "ok", False)),
        "action": action,
        "ts": time.time(),
        "raw": (getattr(ret, "raw", "") or "")[:1500],
        "error": getattr(ret, "error", "") or "",
    }
    data = getattr(ret, "data", None) or {}
    if isinstance(data, dict):
        rec["decision"] = {k: v for k, v in data.items() if k != "annotated"}
    if extra:
        rec.update(extra)
    res.ai_trace.append(rec)


def _ai_candidates(xml: str, limit: int = AI_CANDIDATE_CAP) -> List[Any]:
    """挑选送给视觉模型的候选控件。

    两类都要给，缺一不可：
      ① 可点击的短文本节点（按钮 / 链接）→ 坐标来自结构树，精确到像素，
         模型只需回答"是第几号"，不必给坐标，可靠性最高。
      ② **不可点击的长文本节点** → 里面常常藏着 ClickableSpan 超链接。
         典型例子（实测赣警办首启弹窗）：正文里「《个人信息保护》」「《隐私协议》」
         是蓝色可点超链接，但它们**在 uiautomator 结构树里不是独立节点** ——
         结构树只能看到包裹它们的那一整段 TextView。
         老方案因此完全够不到这两个链接，只能把 428 字的弹窗摘要当成政策全文。
         交给视觉模型后，它能按截图上看到的蓝色文字给出归一化坐标，
         我们再换算成像素去 tap —— ClickableSpan 靠触摸命中区域工作，
         只要坐标落在链接文字上就能点开。这条缺口只有"看图"能补。
    """
    out: List[Any] = []
    for n in uiwalk.parse_all(xml or ""):
        if not n.enabled:
            continue
        t = (n.text or "").strip()
        if n.clickable and 0 < len(t) <= 40:
            out.append(n)
        elif not n.clickable and len(t) >= 150:
            out.append(n)
    # 短文本（按钮）优先：它们更可能是入口，也更容易被模型看准
    out.sort(key=lambda n: (0 if n.clickable else 1, len((n.text or "").strip())))
    return out[:limit]


def _ai_popup_view(res: ScanResult, ai_tasks: Optional[AITasks], serial: str,
                   xml: str, texts: Any, package: str, app_label: str,
                   log: Callable[[str], None], stage: str = "首启弹窗") -> Optional[Dict[str, Any]]:
    """让 AI 看一眼当前界面，返回它对「政策在哪」的判断；不可用则 None。"""
    if ai_tasks is None or not ai_tasks.can_vision():
        return None
    cands = _ai_candidates(xml)
    shot = capture_screenshot(serial)
    if not shot:
        return None
    t_ai = time.time()
    try:
        ret = ai_tasks.locate_policy_entry(shot, cands, list(texts or [])[:25],
                                           package=package, app_label=app_label)
    except Exception as e:
        res.ai_errors.append("%s AI 判断异常：%s" % (stage, e))
        return None
    finally:
        # ★ 等模型的时间不是"采集时间"。中继模式或本地 CPU 推理下一次回答可能
        # 要几十秒，设备就停在那里等 —— 把这笔账记下来，稍后从采集预算里扣回去，
        # 否则遍历会被挤到只剩几秒（实测：100 秒设定里 90 秒耗在等 AI 上）。
        res.ai_wait_seconds += max(0.0, time.time() - t_ai)
    if ret is None:
        return None
    action = ""
    if ret.ok:
        d = ret.data
        if d.get("display_form") == "entry_link" and d.get("entry_bounds"):
            action = "定位到入口「%s」" % (d.get("entry_text") or "?")[:30]
        elif d.get("display_form") == "inline_full":
            action = "判定政策正文内联在弹窗上"
        elif d.get("display_form") == "notice_only":
            action = "判定只有告知、无政策入口"
        elif d.get("display_form") == "none":
            action = "判定界面无政策内容"
    else:
        res.ai_errors.append("%s AI 输出无法解析，已回退规则策略" % stage)
    _ai_record(res, stage, ret, action,
               extra={"candidates": len(cands), "texts": len(list(texts or []))})
    return ret.data if ret.ok else None


def _node_from_bounds(label: str, bounds: Any) -> Optional[Any]:
    """把「像素坐标 + 文字」包装成一个 uiwalk.UiNode 形态的轻量对象。

    为什么要包一层：调用方（首启弹窗阶段、遍历）大量使用 `node.center`、
    `node.label`、`node.key`。让 AI 给出的坐标也满足同一套接口，
    就不用改那些代码 —— 少改一处就少一处引入回归的机会。
    """
    try:
        x1, y1, x2, y2 = (int(v) for v in bounds)
    except Exception:
        return None
    # ★ 外层变量必须换个名字，否则类体里的 `text = text` 会抛 NameError。
    # 类体的作用域规则很坑：类体里一旦对某个名字赋值，这个名字就被认定为
    # **类体局部**，右边的同名引用不会去外层函数取 —— 直接 NameError。
    # 真机实测（赣警办）：这个 bug 让「AI 定位政策入口」的坐标每次都被异常吞掉，
    # AI 明明指出了《隐私协议》超链接的位置，点击却退回关键词策略、什么也点不到。
    # 同理，方法体内（如下面的 label）也读不到类体属性，只能读外层闭包变量。
    label_text = str(label or "AI 定位的目标")

    class _Entry:
        clickable = True
        enabled = True
        scrollable = False
        cls = "ai.located"
        resource_id = ""
        package = ""
        content_desc = ""
        text = label_text
        bounds = (x1, y1, x2, y2)

        @property
        def center(self):
            return (x1 + x2) // 2, (y1 + y2) // 2

        @property
        def label(self):
            return label_text

        @property
        def key(self):
            return "ai@%s" % (self.bounds,)

    return _Entry()


_CONSENT_VISION_PROMPT = """这是一张 Android 手机截图。请只回答两个问题：
1) 界面里是否存在"要求用户同意隐私政策"的弹窗或首屏告知？
   （典型按钮文字：同意、同意并继续、我同意、同意并接受、同意并使用、同意并进入、确定）
2) 若存在，请给出那个**同意按钮**的边界框。

只输出 JSON，不要任何解释：
{"has_consent": true, "button_text": "按钮上的文字", "bbox": [x1, y1, x2, y2]}

bbox 用 0~1 的相对坐标（原点在左上角），框住整个按钮的可见区域。
不要返回「不同意」「拒绝」「退出」「放弃」「暂不」这一类按钮。
如果界面上根本没有隐私政策弹窗，输出 {"has_consent": false}。"""

_CONSENT_VISION_SYSTEM = (
    "你是手机界面识别的辅助工具，只做定位，不做任何合规判断。"
    "必须输出 JSON，不要输出解释或 Markdown。"
)


def _ai_consent_button(ai_tasks: Any, res: "ScanResult", serial: str,
                       log: Callable[[str], None],
                       cap: Optional[Dict[str, Any]] = None) -> Optional[Any]:
    """结构树里找不到「同意」时，用视觉在截图上把它找出来。

    ★ 为什么必须有这条路（2026-11-09 天优家教，用户第 7 条）：
      它的首启弹窗是一个 `APPLICATION_PANEL` 类型的 PopupWindow，
      uiautomator 完全读不到（整屏只导出 10 个节点，文字只有版本号「2.2.3」）。
      `_pick_consent_button()` 于是恒为 None → 「同意」一次都没点 →
      分水岭没记录 → 之后 100 多条事件全被算成"同意前"，
      而它们实际都发生在同意之后。这类错会让报告整体口径偏向"更严重"，
      看起来像"发现了更多问题"，实际是把时间轴搞错了。
      截图里那个蓝色按钮清清楚楚，视觉一次就能定位。

    只在"结构树完全没给出同意按钮"时才调用，且必须过否定词闸门 ——
    宁可不点，也不能把「不同意」当成「同意」。
    """
    if ai_tasks is None or res is None:
        return None
    # 每轮最多问模型 2 次：首启循环会反复调用这里，不设上限会把时间全花在
    # 同一个界面上（一次视觉约 4~6 秒）。两次都看不出同意按钮，就说明
    # 这一屏确实没有，后面的轮次不必再问。
    if cap is not None:
        _n = int(cap.get("_aiConsentCalls") or 0)
        if _n >= 2:
            return None
        cap["_aiConsentCalls"] = _n + 1
    try:
        if not ai_tasks.can_vision():
            return None
    except Exception:
        return None
    png = capture_screenshot(serial)
    if not png:
        return None
    try:
        from .ai import vision as _V
        _cfg = getattr(ai_tasks, "cfg", None)
        prep = _V.prepare(
            png,
            max_width=int(getattr(_cfg, "vision_max_width", 720) or 720),
            quality=int(getattr(_cfg, "vision_quality", 72) or 72))
    except Exception as e:
        log("[.] 同意按钮视觉定位：截图预处理失败（%s）" % str(e)[:60])
        return None
    try:
        raw = ai_tasks.ai.chat_vision(_CONSENT_VISION_PROMPT, [prep.jpeg],
                                      system=_CONSENT_VISION_SYSTEM)
    except Exception as e:
        log("[.] 同意按钮视觉定位失败：%s" % str(e)[:80])
        return None
    parsed = None
    try:
        from .ai import vision as _V
        parsed = _V.parse_json(raw)
    except Exception:
        parsed = None
    if not isinstance(parsed, dict):
        return None
    try:
        from .ai import vision as _V
        if not _V.as_bool(parsed.get("has_consent")):
            return None
        px = _V.norm_to_px(parsed.get("bbox") or [],
                           prep.orig_w, prep.orig_h)
        if not px or not _V.plausible_box(px, prep.orig_w, prep.orig_h, min_side=16):
            return None
    except Exception:
        return None
    label = str(parsed.get("button_text") or "同意").strip()[:12]
    if _is_rejection_label(re.sub(r"\s+", "", label)):
        log("[.] 视觉把「%s」当成了同意按钮，但它是否定词，已放弃" % label)
        return None
    kind, why = _consent_label_kind(label, in_policy_dialog=True)
    if not kind:
        log("[.] 视觉定位到的按钮「%s」不是同意动作（%s），已放弃" % (label, why))
        return None
    node = _node_from_bounds(label, px)
    if node is not None:
        log("[*] 结构树里没有同意按钮，改用视觉定位：「%s」%s（原文：%s）"
            % (label, tuple(px), str(parsed.get("reason") or "")[:60]))
    return node


def _consent_tap_once(res: ScanResult, serial: str, cap: Dict[str, Any],
                      policy_resolved: bool, log: Callable[[str], None],
                      set_consent: Optional[Callable[[str], None]] = None,
                      ai_tasks: Any = None) -> bool:
    """尝试点掉首启弹窗上的「同意」按钮；真点到了返回 True。

    ★ 为什么是模块级函数、而不是写在首启观测函数的循环里：
      原先「点同意」写在 while 循环的**末尾**，而政策下钻分支末尾是 `continue` ——
      只要进过一次下钻分支，下一轮又会进同一分支，循环末尾的同意逻辑
      **一次都执行不到**。自设捏脸实测就是这样：弹窗上明明有
      `android.widget.Button / text="同意并接受" / clickable=true`，
      两轮采集下来没人点它，同意时刻没记录 → 102 条事件全被划成"同意前"，
      而它们实际大半发生在同意之后。
      抽出来之后，下钻一结束就就地调用，不再依赖循环骨架。

    依赖项全部走参数：本函数不碰闭包变量，避免嵌套作用域带来的
    nonlocal / 定义顺序问题（吃过一次亏：把嵌套函数挪出循环后直接语法报错）。
    """
    # 用最新一帧结构树：下钻/返回之后界面可能已换，旧帧坐标会点空
    xml_now = uiwalk.dump_retry(serial, tries=2, wait=0.4) or ""
    btn = _pick_consent_button(xml_now)
    if btn is None:
        # 结构树里看不见（PopupWindow / WebView 弹窗 / 自绘浮层）→ 交给视觉。
        btn = _ai_consent_button(ai_tasks, res, serial, log, cap)
    if btn is None:
        return False
    x, y = btn.center
    log("[*] 点击同意入口：%s" % btn.label[:40])
    res.ui_steps.append("同意：点击「%s」" % btn.label)
    fp_before = uiwalk.screen_fingerprint(xml_now)
    uiwalk.tap(serial, x, y)
    time.sleep(2.0)

    # 点击有效性校验：若界面毫无变化，多半是被系统悬浮窗吃了触摸
    # （实测 MIUI 屏幕录制条压住「同意并继续」，点击落到悬浮条上跳到相册，
    #   遍历器误判成"离开 App"，反复重拉形成死循环）。
    after = uiwalk.dump_retry(serial, tries=2, wait=0.5) or ""
    if after and uiwalk.screen_fingerprint(after) == fp_before:
        log("[!] 点击同意后界面无变化，疑似被悬浮窗遮挡，清理后重试一次")
        try:
            killed = uiwalk.dismiss_overlays(serial, log=log,
                                             target_pkg=res.package)
            if killed:
                res.overlays_dismissed = list(set(res.overlays_dismissed + killed))
                res.errors.append("同意按钮被系统悬浮窗（%s）遮挡，已关闭并重试"
                                  % "、".join(killed))
                time.sleep(1.0)
                uiwalk.tap(serial, x, y)
                time.sleep(2.0)
        except Exception:
            pass

    # ★ 同意事实必须以「UI 上确实点到了同意」为准，**不能**依赖脚本调用成功。
    # 真机实测（滴滴出行）：set_consent 抛异常（Frida 脚本已被销毁）时，
    # 早先的写法把 res.consent_given=True 也一起吞掉了 → 之后所有事件
    # 都被标成 before_consent → 直接多报一条「征得同意前就开始收集」。
    # 这是误报里最严重的方向：把"我们没记录到"写成"App 违规"。
    # 登记动作统一走 `_mark_consent`：它同时写分水岭事件、时刻、截图、同步结果。
    # 这里的按钮是 `_pick_consent_button` 从**政策告知弹窗**上挑出来的，
    # 所以中性确认词（如「确定」）在这个上下文里也算明示同意。
    _strength, _why = _consent_label_kind(btn.label, in_policy_dialog=True)
    # 来源要写对：结构树里本来就没有这个按钮时（PopupWindow / WebView 弹窗），
    # 是视觉在截图上定位的。写成"结构树定位"会让复核员以为结构树里能看到它。
    _src_label = ("首启隐私弹窗点击（AI 视觉定位）"
                  if str(getattr(btn, "cls", "")) == "ai.located"
                  else "首启隐私弹窗点击（结构树定位）")
    _mark_consent(res, btn.label,
                  _src_label, log,
                  set_consent=set_consent,
                  strength=_strength or "explicit",
                  screen_label="首启弹窗", why=_why)
    observe_screen(res, "同意后界面", serial)
    return True


def _text_at_bounds(xml: str, bounds: Any) -> str:
    """取「这个坐标上的真实文字」。

    AI 按坐标定位时不带文字（它只告诉我们"这一点有个可点元素"），
    而下游有多处靠文字判断语义 —— 最典型的是遍历阶段「点到同意按钮即认定同意」，
    判据就是被点元素的文字里有没有同意词。

    自设捏脸实测：AI 用坐标点了弹窗上的「同意并接受」，
    构造出的节点文字却是占位的"AI 目标"，于是同意没被记录 →
    采集脚本继续认为用户没同意 → 整轮 102 条事件全被划到"同意前"，
    而按真实时序它们大半发生在同意之后。
    """
    if not xml:
        return ""
    try:
        x1, y1, x2, y2 = (int(v) for v in bounds)
    except Exception:
        return ""
    best = None
    for n in uiwalk.parse_all(xml):
        t = (n.text or "").strip()
        if not t:
            continue
        nx1, ny1, nx2, ny2 = n.bounds
        cx, cy = (nx1 + nx2) // 2, (ny1 + ny2) // 2
        if x1 <= cx <= x2 and y1 <= cy <= y2:
            area = max(0, nx2 - nx1) * max(0, ny2 - ny1)
            if best is None or area < best[0]:
                best = (area, t)
    return best[1] if best else ""


def _ai_policy_entry(ai_view: Optional[Dict[str, Any]]) -> Optional[Any]:
    """从 AI 对首启弹窗的判断里取出可点击的政策入口。"""
    if not ai_view:
        return None
    b = ai_view.get("entry_bounds")
    if not b:
        return None
    return _node_from_bounds(ai_view.get("entry_text") or "AI 定位的政策入口", b)


# 政策入口点开后落到的「错误页」特征。命中任意一条即认为政策条款没拿到。
# 政策"全文"的最小字数。低于它的只能算弹窗告知摘要，不是可做条款比对的正文。
# 放在模块级：判定结论的函数（judge_policy_outcome）与报告层都要用同一个阈值，
# 各写一份迟早会漂移。
INLINE_POLICY_MIN = 1200


def _url_host(u: str) -> str:
    """从 URL（或我们的来源标签）里取主机名。取不到返回空串。"""
    s = (u or "").strip()
    if not s or "://" not in s:
        return ""
    try:
        return (urlsplit(s).hostname or "").lower()
    except Exception:
        return ""


def _policy_same_site(a: str, b: str) -> bool:
    """两份政策文本是不是来自同一站点（同站/子域都算）。"""
    ha, hb = _url_host(a), _url_host(b)
    if not ha or not hb:
        return False
    return ha == hb or ha.endswith("." + hb) or hb.endswith("." + ha)


def _record_side_text(cap: Dict[str, Any], url: str, chars: int, why: str) -> None:
    """记一份"看过但没用"的长文本，按正文开头去重、限条数。

    为什么必须去重：同一个页面会被反复收割（滚动分块、多个 VNK 哈希指向同一份
    H5），实测一份 1652 字的课程页能记出 6 条几乎相同的记录，
    报告里那张表会被同一条内容灌满，复核员反而看不到别的候选。
    """
    bucket = cap.setdefault("otherPolicyTexts", [])
    for it in bucket:
        # 同一段内容可能从多个 URL 取到（H5 用 VNK 哈希区分地址，内容一样）。
        # 按「字数 + 判定理由」去重，否则同一份课程页能在表里重复 6 行。
        if it.get("chars") == chars and (it.get("why") or "") == why:
            return
    if len(bucket) >= 12:
        return
    bucket.append({"url": url, "chars": chars, "why": why})


def _record_document(cap: Dict[str, Any], url: str, txt: str,
                     kind: str = "", title: str = "", how: str = "",
                     note: str = "") -> Dict[str, Any]:
    """把一份**已取到正文**的文档登记进政策采集结果（按类分列）。

    为什么要单独登记而不是只留"没被采用的长文本"（用户 2026-10-28 意见）：
      《用户协议》《未成年人隐私政策》《收集个人信息清单》《第三方共享清单》
      对检测都是**直接证据** —— 「是否逐一列明接收方」看共享清单，
      「未成年人专门规则」看未成年人政策。它们不该只在
      「采集期看到的其他长文本（均未用作政策依据）」里露一行，
      那样复核员会以为这些文档没抓到。
    去重按正文开头（同一份文档常有多个入口，抓回来一字不差）。
    """
    body = (txt or "").strip()
    if not body:
        return {}
    bucket = cap.setdefault("documents", [])
    head = re.sub(r"\s+", "", body)[:60]
    for it in bucket:
        if it.get("head") == head:
            # 同一份文档从另一个地址又抓到一次：记下地址，正文只留一份
            if url and url not in (it.get("urls") or []):
                it.setdefault("urls", []).append(url)
            return it
    k = kind or _POL.classify_doc(body, title or "", url or "")
    item = {
        "url": url if str(url or "").lower().startswith("http") else "",
        "urls": [url] if str(url or "").lower().startswith("http") else [],
        "kind": k,
        "kind_label": _POL.doc_kind_label(k),
        "title": (title or "").strip()[:120],
        "chars": len(body),
        "head": head,
        "text": body[:200000],
        "how": how,
        "note": note,
    }
    bucket.append(item)
    return item


def _same_doc_head(a: str, b: str, n: int = 60) -> bool:
    """两段正文是不是同一份文档（比对归一化后的开头）。

    用于判断"界面读到的那一页"与"安装包里那份"是否同一份 —— 是的话就没必要
    再一屏屏滑动去读（金考典 2026-10-28：界面上只读出 844 字，
    而同一份文件在 APK 里有完整的 8422 字）。
    """
    na = re.sub(r"\s+", "", a or "")[:n]
    nb = re.sub(r"\s+", "", b or "")[:n]
    return bool(na) and bool(nb) and (na == nb or na in nb or nb in na)


def _keep_policy_text(cap: Dict[str, Any], txt: str, url: str,
                      label: str = "") -> bool:
    """决定这份政策正文要不要覆盖已有的。返回 True 表示已采纳。

    ★ 为什么需要这道闸门（赣警办 P4 深挖实测）：
      遍历深入到「意见反馈」时点开了腾讯兔小巢页面，它的《隐私保护指引》
      有 14902 字，比 App 自己的政策长得多。旧逻辑"谁长用谁"，
      于是整份报告的政策类结论——未成年人专门规则、个性化推荐说明、
      SDK 列明——全部变成了对**第三方 SDK 政策**的核查结果。
      文档拿错，结论必然错，而且错得看不出来。

    规则：
      · 手上还没有像样的政策（<1200 字，多为错误页/弹窗摘要）→ 采纳；
      · 同一个站点 → 采纳（同一份政策的更完整版本）；
      · 不同站点且已有像样正文 → **不覆盖**，记进 `otherPolicyTexts` 备查。

    ★ 再加一道「文本类型」闸门（以观书法 5.4.2 实测）：
      首启拿到了真正的《隐私政策》（1652 字），P4 点开《VIP会员服务协议》
      （2674 字，同站点、更长）就把它顶掉了。之后"实际收集设备属性但政策未列明"
      被判成**认定**——而真政策里可能写着。同站点+更长 这条规则本身没问题，
      缺的是"这份到底是不是隐私政策"。不是隐私政策的一律不覆盖。
    """
    cur = (cap.get("bestText") or "")
    cur_url = (cap.get("bestTextUrl") or "")
    _is_url = str(url or "").lower().startswith("http")
    # ---- HTML 源码兜底（2026-11-09 Q船 4.4.2，见 _looks_like_html 的说明）----
    # 脚本侧已经把 loadDataWithBaseURL 的内容转成纯文本了；这里再兜一次，
    # 是为了覆盖旧存档、以及 js 未生效（注入受限）时从别处拿到的源码。
    _raw_kind = ""
    if _looks_like_html(txt):
        _plain = html_to_text(txt)
        if len(_plain) >= 200:
            _raw_kind = "HTML 源码（%d 字）" % len(txt)
            txt = _plain
    # ---- "没有可访问地址"要能说清是**哪一种**没有 ----
    # 用户 2026-11-09 第 1 条：「页面确实点开了、正文确实记录了，为什么说没拿到链接？」
    # 因为这类 App 的政策根本**不通过网络地址加载**：它把 HTML 直接塞给 WebView
    # （about:blank#inline）或读本地资源文件。没有 URL 不是我们漏记，是客观没有。
    # 把原始来源记下来，报告就能照实写，而不是含糊一句"未记录到可访问地址"。
    _src_kind = ""
    _u = str(url or "").strip()
    if not _is_url and _u:
        if "inline" in _u or "about:blank" in _u:
            _src_kind = "inline_html"
        elif _u.lower().startswith("file://"):
            _src_kind = "local_file"
        elif not _u.startswith("政策") and "用户协议" not in _u:
            _src_kind = "other"
    if _src_kind:
        cap["bestTextSourceKind"] = _src_kind
        cap["bestTextSourceRaw"] = _u[:200]
    if _raw_kind:
        cap["bestTextRawForm"] = _raw_kind
    # ★ `url` 这个形参有两种来源：真地址（WebView.getUrl / 按链接抓取），
    #   以及界面收割时的**来源标签**（"政策页面文本（滚动后）"）。
    #   旧代码不分，把标签当地址写进 bestTextUrl，报告于是渲染出一条
    #   `file:///…/政策页面文本（滚动后）` 的死链（金考典 2026-10-28 实测）。
    #   现在只认 http(s)；标签单独记到 bestTextFrom，供报告写"取得方式"。
    # ---- 来源闸门：链接域名属于第三方 SDK 厂商 → 直接不收 ----
    # ★ 免费手机投屏神器 2026-10-26 实测：APK 里同时登记了自家政策链接与
    #   穿山甲、QQ互联等 SDK 的政策链接，采集侧按"正文最长"选中了
    #   www.pangle.cn（9971 字），报告把《穿山甲广告SDK隐私政策》当成了
    #   App 自己的隐私政策 —— 后面所有政策类比对全部对错了对象。
    #   正文可以伪造、导航栏可以改版，来源域名不会变，所以这一道先于类型闸门。
    _host_bad = _POL.policy_host_reason(url) if _is_url else ""
    if _host_bad:
        _record_side_text(cap, url, len(txt), _host_bad + "，未采纳")
        return False
    # ---- 文档类型闸门 ----
    # ★ Hi投屏 2026-10-28：WebView 加载了 `/protocol/share`（第三方共享数据清单），
    #   它通篇都在讲"个人信息"，走原来的"像不像隐私政策"判据一路通过，
    #   被当成政策正文写进报告 —— 链接也指向了共享清单。
    #   现在先分类：清单/协议/权限说明各自入档，不当政策用（但**要展示**）。
    _kind = _POL.classify_doc(txt, "", url if _is_url else "")
    if _kind in ("user_agreement", "collection_list", "third_party_list",
                 "permission_list"):
        # 只入"文档清单"，不再同时记进「采集期看到的其他长文本」——
        # 那张表的语义是"看过但没用"，而这类文档是**要用的直接证据**
        # （共享清单回答接收方是否列明），两处都写会让复核员以为它没被抓到。
        _record_document(cap, url if _is_url else "", txt, _kind,
                         how=("按链接抓取" if _is_url else (label or "界面读取")),
                         note="已归档为「%s」，不作为隐私政策正文" % _POL.doc_kind_label(_kind))
        return False
    # ---- 类型闸门：候选正文得像隐私政策 ----
    if not _POL.looks_like_privacy_policy(txt):
        _record_side_text(cap, url if _is_url else (label or "界面文本"), len(txt),
                          "候选正文不是隐私政策（开头为「%s」），未覆盖"
                          % (txt or "").strip()[:20].replace("\n", " "))
        return False
    # ---- 告知摘要闸门：弹窗上那段"请阅读政策"的话不是条款正文 ----
    # ★ 春雨诊所 / 高途 2026-10-30：359 字、279 字的告知语被当成政策正文，
    #   报告写着"已取得政策全文"，实际一条条款都没有；高途那份还因为末尾提到
    #   《儿童隐私保护规则》被判成了未成年人规则。这类文字只进 noticeText。
    if _POL.is_notice_summary(txt):
        _body = (txt or "").strip()
        if len(_body) > len((cap.get("noticeText") or "").strip()):
            cap["noticeText"] = _body
            cap["noticeFrom"] = label or ("界面读取" if not _is_url else "按链接抓取")
        _record_side_text(cap, url if _is_url else (label or "界面文本"), len(_body),
                          "这是告知语/摘要（%d 字），不是政策条款正文，未采纳" % len(_body))
        return False
    if len(cur.strip()) < INLINE_POLICY_MIN or _policy_same_site(url if _is_url else "",
                                                                cur_url):
        if len(txt) > len(cur):
            # 被顶掉的旧正文留档：报告里要能回答"这份是不是当时看到的那一份"
            if cur.strip():
                cap.setdefault("replacedPolicyTexts", []).append({
                    "url": cur_url, "chars": len(cur),
                    "head": cur.strip()[:40].replace("\n", " "),
                })
            cap["bestText"] = txt
            if _is_url:
                cap["bestTextUrl"] = url
            cap["bestTextFrom"] = ("按链接抓取" if _is_url
                                   else (label or "界面读取"))
            _record_document(cap, url if _is_url else "", txt, _kind or "privacy",
                             how=cap["bestTextFrom"], note="作为隐私政策正文使用")
            return True
        return False
    _record_side_text(cap, url if _is_url else (label or "界面文本"), len(txt),
                      "与已取得的政策正文不同站点（多为第三方 SDK 的政策），未覆盖")
    return False


def collect_documents(cap: Dict[str, Any], urls: Sequence[Any],
                      log: Callable[[str], None] = print,
                      budget: int = 6, timeout: int = 10,
                      min_len: int = 120) -> List[Dict[str, Any]]:
    """按已知链接把「政策以外的各类声明文档」逐份取回来并分类入档。

    ★ 为什么要单独做这一趟（用户 2026-10-28 意见）：
      《用户协议》《未成年人隐私政策》《收集个人信息清单》《第三方共享清单》
      都是检测要用的直接证据 —— 「是否逐一列明接收方」要看共享清单，
      「未成年人专门规则」要看未成年人政策。它们以前只有在 UI 上**恰好点开**时
      才留下一点线索（还常被当成"不是政策的候选长文本"丢掉），
      而 APK 里登记 / WebView 加载过的地址其实已经拿到手了 ——
      一次 HTTP 就能取回全文，比在界面上翻五分钟便宜得多。

    只做三件事：取、分类、登记。**不**改变政策正文的选择
    （那是 `_keep_policy_text` 的职责），避免又多出一条"谁顶掉谁"的路径。
    """
    docs = cap.setdefault("documents", [])
    have = {(d.get("url") or "") for d in docs}
    tried: set = set(cap.setdefault("docTried", []))
    cand: List[str] = []
    for u in urls or []:
        if isinstance(u, dict):
            u = u.get("url") or ""
        u = str(u or "").strip()
        if not u.lower().startswith(("http://", "https://")):
            continue
        if u in have or u in tried or u in cand:
            continue
        cand.append(u)
    if not cand:
        return []
    # 像文档的先试（同一批地址里，"加载中"之类的跳板页排在后面）
    _HINT = re.compile(r"(privacy|private|policy|protocol|agreement|share|collect|"
                       r"minor|child|term|yinsi|list|statement)", re.I)
    cand.sort(key=lambda s: (0 if _HINT.search(s) else 1, len(s)))
    n_ok = 0
    for u in cand[:max(0, budget)]:
        tried.add(u)
        if _POL.policy_host_reason(u):
            continue          # 第三方 SDK 厂商的政策站：与被测应用无关
        try:
            r = _POL.fetch(u, timeout=timeout, log=None)
        except Exception as e:
            log("[.] 取文档失败（%s）：%s: %s" % (u, type(e).__name__, e))
            continue
        txt = (getattr(r, "text", "") or "").strip()
        if len(txt) < min_len:
            continue
        kind = _POL.classify_doc(txt, getattr(r, "title", "") or "", u)
        if kind == "other":
            # 判不出类型的长文本不登记：报告里那张表只放**说得清是什么**的文档，
            # 否则又变成"一堆不知道是什么的长文本"，复核员无法使用。
            continue
        _record_document(cap, u, txt, kind,
                         title=getattr(r, "title", "") or "",
                         how="按链接抓取（%s）" % u)
        n_ok += 1
        log("[*] 取得文档：%s（%s，%d 字）" % (_POL.doc_kind_label(kind), u, len(txt)))
    cap["docTried"] = sorted(tried)
    if n_ok:
        log("[+] 本轮共取回 %d 份政策/协议类文档" % n_ok)
    return docs


def same_focus(a: str, b: str) -> bool:
    """两个「前台页面」标识是否指同一个界面。

    ★ 为什么需要它（简小知真机，2026-10-16）：
      「前台页面」这个字符串有**两种写法**，来自两条不同的采集路径 ——
        · dumpsys activity 的原始输出：`com.jz.jxz/.ui.web.CommonH5Activity`
          （包名 + `/` + 以点开头的**相对**类名）
        · ui 遍历器统一后的结果：`com.jz.jxz/com.jz.jxz.ui.web.CommonH5Activity`
          （包名 + `/` + **全限定**类名）
      直接 `!=` 比较会把同一个页面判成两个页面。真机上造成的后果是：
      政策页刚被点开（前台从 SplashActivity 变成 CommonH5Activity），
      滚动前的那次「还在不在原页面」的自检立刻误判成「政策页已被关闭」，
      于是**一层都不滚动**，日志里还留下一句自相矛盾的话：
        `[!] 政策页已被关闭（前台变为 com.jz.jxz.ui.web.CommonH5Activity）` ——
      前台明明就是政策页。

    这里把两种写法都归一到「全限定类名」再比。真实的页面切换
    （Splash ↔ CommonH5）仍然会被正确判为不同。
    """
    def _key(f: str) -> str:
        return uiwalk.focus_key(f)
    ka, kb = _key(a), _key(b)
    return bool(ka) and ka == kb


_ERROR_PAGE_MARKERS = (    "页面不存在", "页面已删除", "页面找不到", "网页无法打开", "无法访问此网站",
    "网络连接错误", "加载失败", "服务器异常", "访问出错",
    "not found", "404", "err_connection", "err_name_not_resolved",
)


# WebView 读不出正文时，屏幕上至少得有这么多字才算"读到了"。
# 40 这个量级是"一个标题 + 一行说明"，低于它基本可以确定是空树。
WEBVIEW_WAKE_MIN_TEXT = 40


def webview_text_blind(xml: str) -> bool:
    """结构树里明明有 WebView，却一个字都没读到 —— 这是"瞎"而不是"空白页"。

    单独抽成纯函数，因为判据要用在两处（决策与记账），且必须能被离线用例覆盖。
    """
    if not xml:
        return False
    nodes = uiwalk.parse_all(xml)
    has_wv = any((getattr(n, "cls", "") or "").endswith("webkit.WebView")
                 for n in nodes)
    if not has_wv:
        return False
    try:
        text = "".join(uiwalk.screen_texts(xml) or [])
    except Exception:
        text = ""
    return len(text.strip()) < WEBVIEW_WAKE_MIN_TEXT


def wake_webview_text(serial: str, xml: str,
                      log: Callable[[str], None] = print,
                      *, package: str = "") -> Tuple[str, str]:
    """WebView 正文读不出来时，先等、再点一下，然后重读（2026-11-08 小包搜题）。

    现场（不注入模式）：政策页开在 `WebActivity` 的 `android.webkit.WebView` 里，
    截图明明是整页《隐私政策》（AI 视觉能读出来），但 `uiautomator dump`
    只回来一个**空 WebView 节点** —— 界面文字 0 条、0 字。
    等两屏仍为空时，在 WebView 区域里点一下、再 dump：164 个文本节点、
    7136 字，正是政策全文。原因是 Chrome WebView 只有在拿到输入焦点之后
    才构建无障碍节点树。

    ★ 顺序很重要：**先等两屏再点**（2026-11-09 land36/land38）。
      空 WebView 有两种含义 —— 页面还在加载，或无障碍树还没建。
      对着还在加载的页面点一下，会把加载打断、显示出「网页无法打开」，
      报告于是把时序问题写成"应用给了死链"。等两屏（约 2.4 秒）几乎总能
      把这两种情况分开，且不花额外代价。land40 实测就是这一支：
      「首读为空、1.2s 后自行渲染出文字，无需点击」。

    ★ 点的是页面正文处，并且**只**在"树里有 WebView、整屏一个字都没有"时
      动手 —— 有文字就原样返回，绝不为了保险而多点一下。

    返回 `(结构树, 怎么读到的)`，第二项用于报告如实描述：
      ""        没动过（本来就有文字 / 不是 WebView 屏）；
      settled   等它自己渲染出来的，全程没点；
      tap       点了一下之后才读出来；
      failed    两条路都没读出文字。
    """
    if not webview_text_blind(xml):
        return xml, ""
    # ★ 先"等它自己出来"，再考虑点（2026-11-09 land36/land38 实测）：
    #   空 WebView 有两种含义 —— (a) 页面还在加载；(b) 无障碍树没建起来。
    #   对 (a) 动手就会**打断加载**：点下去之后页面上出现的是
    #   Chrome 的「网页无法打开」，于是报告把一个纯时序问题写成了
    #   「应用把政策交给了一个打不开的地址」—— 这正是最不该出现的误报。
    #   所以这里先补读两屏，文字出来了就原样返回，一个字都不点。
    for _i in range(2):
        time.sleep(1.2)
        _again = uiwalk.dump_retry(serial, tries=2, wait=0.8) or ""
        if not _again:
            continue
        if not webview_text_blind(_again):
            log("[*] WebView 首读为空、%.1fs 后自行渲染出文字，无需点击"
                % (1.2 * (_i + 1)))
            return _again, "settled"
        xml = _again
    nodes = uiwalk.parse_all(xml)
    wv = [n for n in nodes
          if (getattr(n, "cls", "") or "").endswith("webkit.WebView")]
    if not wv:
        return xml, ""
    node = wv[0]
    try:
        x, y = node.center
    except Exception:
        return xml, ""
    try:
        _before = uiwalk.current_focus(serial) or ""
    except Exception:
        _before = ""
    log("[*] WebView 等了两轮仍读不出正文：点一下页面让它构建无障碍节点树，"
        "再读一次")
    try:
        uiwalk.tap(serial, x, y)
    except Exception as e:
        log("[.] 点击 WebView 失败（不影响后续）：%s" % e)
        return xml, ""
    time.sleep(0.8)
    try:
        _after = uiwalk.current_focus(serial) or ""
    except Exception:
        _after = ""
    if _before and _after and _before != _after:
        # 点出了一个新页面 —— 那不是我们要的，退回去并把现场交回调用方。
        log("[!] 唤醒 WebView 时前台被切到 %s，按返回退回"
            % (_after.split("/")[-1] or "?")[:30])
        try:
            uiwalk.back(serial)
        except Exception:
            pass
        time.sleep(0.6)
        return xml, ""
    new_xml = uiwalk.dump_retry(serial, tries=2, wait=0.8) or ""
    if not new_xml:
        return xml, ""
    try:
        got = len("".join(uiwalk.screen_texts(new_xml) or []).strip())
    except Exception:
        got = 0
    if got >= WEBVIEW_WAKE_MIN_TEXT:
        log("[+] 唤醒后读到 %d 字（WebView 无障碍树已建立）" % got)
        return new_xml, "tap"
    log("[.] 唤醒后仍只有 %d 字 —— 该 WebView 可能禁用了无障碍，按原样继续" % got)
    return new_xml, "failed"


def _looks_like_error_page(text: str) -> str:
    """判断一段页面文本其实是「错误页」而不是政策正文。返回命中的特征，未命中返回空串。

    ★ 为什么要单独测这一条（真机实测 · 赣警办）：
      首启弹窗里的《隐私协议》超链接指向
      `https://wmfw.gat.jiangxi.gov.cn/webchat/#/privacy`，服务端对这个路径返回
      **404**，WebView 里显示的是该站自己的错误页 —— 标题恰好由 App 设成「隐私协议」，
      正文却只有「非常抱歉您访问的页面不存在!」加一行 `power by ucox.cn`。
      如果只看「页面标题对不对 / 有没有文字」，这种错误页会被当成政策页，
      报告于是得出「政策已公开」的结论 —— 而事实完全相反：
      **App 未能提供可查阅的政策条款**，这本身就是应当写进报告的问题项。

      错误页都很短，因此对长文本直接放过，避免正文里偶然出现 "404" 被误判。
    """
    t = (text or "").strip()
    if not t or len(t) > 800:
        return ""
    low = t.lower()
    for m in _ERROR_PAGE_MARKERS:
        if m in t or m in low:
            return m
    return ""


def detect_policy_error_page(text: str, ui_xml: str = "") -> str:
    """从两处找「错误页」特征：① WebView 回读到的正文；② 界面结构树里的文字。

    ★ 为什么必须看第二处（真机教训 · 赣警办 e2e5）：
      那个失效的政策链接是 SPA 路由 `/webchat/#/privacy`，WebView 侧
      回读不到任何正文（text 为空），但界面上明明白白写着
      「您所访问的页面不存在! / power by ucox.cn」。
      只拿回读正文去判，一个特征都命中不了，结论就退化成
      「仅取得弹窗告知摘要 0 字」—— 明明是"链接是死的"，
      报告却写成了"政策没读到"，把最该报的问题漏掉了。
    """
    hit = _looks_like_error_page(text)
    if hit or not ui_xml:
        return hit
    try:
        for seg in uiwalk.screen_texts(ui_xml):
            hit = _looks_like_error_page(seg)
            if hit:
                return hit
    except Exception:
        pass
    return ""


def policy_open_probe(xmls: List[str], best_text: str = "",
                      retries: int = 2) -> Dict[str, Any]:
    """对「刚点开政策入口」的连续几屏做定格探测，返回最早命中的错误页特征。

    抽成纯函数（不碰设备）是为了把真机时序钉住 —— 这段逻辑一旦被改回
    「先滚动再判断」，报告就会把「链接是死的」写成「只拿到弹窗摘要」。

    真机时序（赣警办 · 时间序列实测）：
        t+1s  前台 WebAndroidActivity，界面文字「隐私协议」
        t+2s  同一前台，文字变为「隐私协议 / 页面不存在」
        t+3s~t+8s 稳定停留在错误页
    即错误文案**要第二屏才出现**。只采一屏会漏，所以默认补读一次。

    返回：``{"errHit", "screenIndex", "textLen", "xml"}``
    ``errHit`` 非空 ⇒ 这一页是错误页，调用方应**立刻停止滚动与下钻**，
    否则滚动会把 App 带离该页，证据在最终判定时就没了。
    """
    out: Dict[str, Any] = {"errHit": "", "screenIndex": -1, "textLen": 0, "xml": ""}
    seq = [x for x in (xmls or []) if x][:max(1, retries)]
    for i, x in enumerate(seq):
        txt = _harvest_ui_text(x) or ""
        hit = detect_policy_error_page(
            "%s\n%s" % (best_text or "", txt), x)
        out["xml"] = x
        out["textLen"] = len(txt.strip())
        out["screenIndex"] = i
        if hit:
            out["errHit"] = hit
            return out
    return out


def judge_policy_outcome(got: str, err_hit: str = "", navigated: bool = False,
                         min_chars: int = 0) -> str:
    """由三件事定出政策获取结论：拿到多少正文、是不是错误页、界面有没有换页。

    抽成纯函数是为了能离线回归 —— 这段判断的分支一旦走错，
    报告会把"链接失效"写成"政策已获取"（历史上真发生过），
    而它又依赖真实设备行为，不抽出来就没法在改代码时立刻验证。
    """
    got = (got or "").strip()
    limit = min_chars or INLINE_POLICY_MIN
    if err_hit:
        return "error_page"
    if len(got) >= limit:
        return "full"
    if navigated:
        # 页面确实换了，但取不到条款文本：可能是 JS 动态渲染、反自动化拦截或加载失败
        return "no_text"
    # 没换页 —— 多半是点击没落到链接上，界面还停在首启弹窗
    return "notice_only"


def entry_sample_points(bounds: Any) -> List[Tuple[int, int]]:
    """在一个候选框里取若干个点击采样点，**第一个是框中心**。

    为什么不是只点中心：语义模型给的框通常比文字本身大（常高出半个行高），
    误差又主要在竖直方向。真机实测（赣警办首启弹窗）：

        AI 给的框       (76, 878, 356, 965)   中心 (216, 921)
        链接真实范围    (115, 875, 340, 914)  中心 (227, 894)
        → y 偏低 27px，中心落在链接下缘之外 7px，点击完全落空。

    按下面的取法，第二个采样点 `(216, 899)` 就落在链接带 875..914 内 —— 命中。
    所以「框内多采样 + 用界面是否变化判定」比信任单点可靠得多。

    纯函数（不碰设备），方便离线回归把上面这组真实坐标钉住。
    """
    try:
        x1, y1, x2, y2 = (int(v) for v in bounds)
    except Exception:
        return []
    h = max(1, y2 - y1)
    cx = (x1 + x2) // 2
    pts: List[Tuple[int, int]] = []
    for frac in (0.5, 0.25, 0.75, 0.125, 0.875):
        py_ = y1 + int(h * frac)
        if y1 <= py_ <= y2 and (cx, py_) not in pts:
            pts.append((cx, py_))
    return pts


def entry_sample_points_wide(bounds: Any,
                             rows: Sequence[float] = (0.5, 0.3, 0.7),
                             cols: Sequence[float] = (0.25, 0.5, 0.75),
                             ) -> List[Tuple[int, int]]:
    """在框内**横向**也取点，给"可点文字只是段落中的一小段"这种情形用。

    ★ 真机实测（以观书法 5.4.2，2026-10-20，连续两轮同一现象）：
      首启弹窗的正文是一整段话，《以观书法隐私政策》只是段落中间的一小段
      可点击文字。AI 给的框框住了整段（宽约 300px、高约 100px），而
      `entry_sample_points` 只在**竖向中线**上取 5 个 y、x 恒定不变 ——
      5 次点击全落在同一列的非链接文字上，界面纹丝不动，
      于是结论写成"入口可能不可点击"，政策正文一份也没拿到。
      上一轮（mbsf3）能点开纯属那一列恰好压在链接上，换个框就废。

    只在第一遍**完全没反应**时才用（见 `_tap_entry_robust`），
    因此多花的几次点击不会影响正常命中路径。
    """
    try:
        x1, y1, x2, y2 = (int(v) for v in bounds)
    except Exception:
        return []
    w = max(1, x2 - x1)
    h = max(1, y2 - y1)
    pts: List[Tuple[int, int]] = []
    for fy in rows:
        py_ = y1 + int(h * fy)
        for fx in cols:
            px_ = x1 + int(w * fx)
            if (px_, py_) not in pts:
                pts.append((px_, py_))
    return pts


_EXTERNAL_FOCUS_MARKS = _POL._EXTERNAL_APP_MARKS


def _is_external_focus(focus: str, package: str = "") -> bool:
    """这个前台页面是不是"系统组件/外部应用"，而不是被测应用自己。

    实现放在 policy 模块（报告层离线重渲染时也要用同一套判据）。
    """
    return _POL.is_external_app_focus(focus, package)


def _text_anchor_points(text: str, bounds: Any,
                        words: Sequence[str] = ("隐私政策", "隐私协议", "隐私权政策",
                                                "个人信息保护政策")) -> List[Tuple[int, int]]:
    """按**字符比例**把目标词定位到框里的坐标。

    为什么需要（万步健康 2026-10-30）：首启弹窗的入口是整句
    「我已阅读并同意万步健康《服务协议》和《隐私政策》」，「隐私政策」四个字
    只是这句话里的一小段，而且视觉上还会折行。AI 给的框框住整句/折行的一部分，
    框中心落在"和"字附近，框内规则采样点也大多落在文字之间的空隙上 ——
    点了十几次都没反应，报告于是写"未取得政策正文"。

    字符是等宽排列的（中文尤其如此），所以按"目标词在字符串里的位置比例"
    去推坐标，比按框的几何中心靠谱得多。折行时文本里没有换行符，只能凭
    行数未知来补偿：同时给出几个纵向候选点，让上层逐个试。
    """
    body = (text or "").strip()
    try:
        x1, y1, x2, y2 = (int(v) for v in bounds)
    except Exception:
        return []
    w = max(1, x2 - x1)
    h = max(1, y2 - y1)
    lines = [ln for ln in body.splitlines() if ln.strip()] or [body]
    pts: List[Tuple[int, int]] = []
    for word in words:
        if not word or word not in body:
            continue
        # 换行可见时：定位到具体那一行，纵向只取该行中线
        if len(lines) > 1:
            for i, ln in enumerate(lines):
                idx = ln.find(word)
                if idx < 0:
                    continue
                frac = (idx + len(word) / 2.0) / max(1, len(ln))
                pts.append((x1 + int(w * frac), y1 + int(h * (i + 0.5) / len(lines))))
            continue
        # 单行字符串（折行不可见）：横向按整段比例，纵向给三个候选
        idx = body.find(word)
        frac = (idx + len(word) / 2.0) / max(1, len(body))
        px = x1 + int(w * frac)
        for fy in (0.5, 0.33, 0.67):
            pts.append((px, y1 + int(h * fy)))
    out: List[Tuple[int, int]] = []
    for p in pts:
        if p not in out:
            out.append(p)
    return out


def _tap_entry_robust(serial: str, entry, log: Callable[[str], None],
                      ai_sourced: bool, res: Optional[ScanResult] = None,
                      refined_bounds: Optional[Tuple[int, int, int, int]] = None,
                      info: Optional[Dict[str, Any]] = None,
                      ) -> Tuple[int, int]:
    """点击政策入口，并在 AI 给的框内做「多点重试」，返回实际点击的坐标。

    ★ 为什么必须重试 —— 真机实测（赣警办首启弹窗，1080×2400）：
        AI 认出正文里的《隐私协议》超链接，给出框 (76,878,356,965)，中心 (216,921)；
        而用像素颜色实测，该链接的真实范围是 (115,875,340,914)，中心 (227,894)。
        水平只差 11px（无妨），**竖直偏低 27px —— 中心正好落在链接下缘之外 7px**，
        点击完全落空：弹窗没动，界面文本仍是那 428 字告知摘要，
        于是 428 字的摘要被当成"政策正文"，报告得出「政策已获取」的错误结论。
        把 y 收回到 894，立刻点开。

    关键词 / 结构树来源的坐标是真实控件 bounds，本身准确，
    因此不做重试、保持原有行为（AI 只做增强，不改变确定性路径）。

    refined_bounds（可选）：用像素校准过的框（见 vision.refine_click_point）。
    给了就优先在它里面采样 —— 它比 AI 的框更贴合链接文字那一行。

    info（可选）：传一个 dict 进来，函数会把关键事实写进去，供调用方紧接着使用：
      ``xy`` / ``signal`` / ``focus_before`` / ``focus_after`` /
      ``post_xml``（**前台刚切换那一瞬间**抓到的结构树）。
    ``post_xml`` 是最要紧的：政策页（尤其失效链接的错误页）在真机上只存在几秒，
    晚一步 dump 就什么都没有了 —— 调用方应当直接拿它当"政策页那一屏"，
    而不是再 sleep 一段时间后重新 dump。
    """
    if info is not None:
        info.update({"xy": tuple(entry.center), "signal": "", "focus_before": "",
                     "focus_after": "", "post_xml": ""})

    x, y = entry.center
    if not ai_sourced:
        uiwalk.tap(serial, x, y)
        return x, y

    pts = list(entry_sample_points(getattr(entry, "bounds", None)))
    if not pts:
        uiwalk.tap(serial, x, y)
        return x, y
    # ★ 先按"入口文本里的字符位置"点一次（万步健康 2026-10-30）：
    #   入口往往是整句「我已阅读并同意…《服务协议》和《隐私政策》」，
    #   可点区域只有书名号里那几段，框中心与规则采样点都会落在文字空隙上。
    #   按字符比例直接压到"隐私政策"四个字上，命中率高得多。
    _anchors = _text_anchor_points(getattr(entry, "text", "") or
                                   getattr(entry, "label", "") or "",
                                   getattr(entry, "bounds", None))
    if _anchors:
        pts = _anchors + [p for p in pts if p not in _anchors]

    # ★ 先用像素把点击点校准到链接那一行，再开始采样。
    #   原因：AI 给的是"大概在哪一块"，而弹窗每次启动的竖直位置会浮动
    #   （同一台机同一 App，上一轮链接在 y 875..914，这一轮在 843..873）。
    #   照搬坐标会让采样点整体落在一个错误的带里 —— 那时多点重试也救不了。
    #   链接文字是彩色的、正文是黑灰的，这个差异比位置稳定得多，用它校准。
    # ★ 校准点要**接在锚点后面**，不能顶掉锚点（2026-10-30 修）：
    #   旧写法是 `pts = list(entry_sample_points(refined) or pts)` —— 一旦像素
    #   校准出了框，前面按字符比例算好的锚点整批作废。而万步健康那类"整句里
    #   只有书名号可点"的弹窗，恰恰是锚点能中、框内规则采样点中不了。
    if refined_bounds is not None:
        _ref = entry_sample_points(refined_bounds) or []
        if _ref:
            pts = _ref + [p for p in pts if p not in _ref]

    ui_changed_at: Optional[Tuple[int, int]] = None
    _wide_used = False
    _i = 0
    while _i < len(pts):
        px_, py_ = pts[_i]
        focus_before = uiwalk.current_focus(serial)
        before = uiwalk.dump_retry(serial, tries=2, wait=0.4) or ""
        fp_before = uiwalk.screen_fingerprint(before) if before else ""
        uiwalk.tap(serial, px_, py_)
        # ★★ 点击后【立刻】盯住前台页面，一旦切换就马上抓一屏结构树。
        #   真机实测（赣警办 e2e11）：点击 (229,895) 确实把前台切到了
        #   WebAndroidActivity，但**几秒后就退回首启弹窗**（同时 Frida 脚本失效，
        #   已重新附着）。旧代码在这里固定 sleep(2.4s)、后面再 sleep(1.2s) 才 dump，
        #   等它拿到结构树时页面早已不在 —— dump 到的是弹窗那 428 字，
        #   于是错误页特征一个都命中不了，结论退化成 notice_only。
        #   受控实验（tools/exp_policy_timeline.py，不挂 Frida）证明：
        #   点击后 t+1s 结构树里就有「您所访问的页面不存在!」，能稳定保持 14s 以上。
        #   所以证据是"确实存在过"，我们只是**观测太晚**。
        focus_after = ""
        switched = False
        for _poll in range(6):
            time.sleep(0.4)
            focus_after = uiwalk.current_focus(serial) or ""
            if focus_after and (not focus_before or focus_after != focus_before):
                switched = True
                break
        # 前台刚切换 ⇒ 权利上"点中了"；立刻取一屏，别再多等
        post_xml = uiwalk.dump_retry(serial, tries=1, wait=0.0) or "" if switched else ""
        if switched:
            signal = "focus"
        else:
            after = uiwalk.dump_retry(serial, tries=2, wait=0.5) or ""
            if not after:
                # dump 失败时无法判断界面是否变化，保守认为已点中，
                # 避免在一个已经跳走的界面上继续乱点。
                # ★ 必须留痕：这条分支是静默返回的，一旦 dump 在真机上不稳定，
                #   整条政策获取链路会"看起来点了、其实什么也没点"，
                #   而日志里一句都没有（e2e9/e2e10 就是这么查了两轮才定位到的）。
                log("[!] 采样点 (%d,%d) 点击后 uiautomator dump 失败，无法判断界面是否变化，"
                    "按已点中处理 —— 后续观测可能不可靠" % (px_, py_))
                if res is not None:
                    res.errors.append("政策入口点击后界面 dump 失败（(%d,%d)），"
                                      "该次点击是否生效未能确认" % (px_, py_))
                if info is not None:
                    info.update({"xy": (px_, py_), "signal": "unknown",
                                 "focus_before": focus_before, "focus_after": focus_after})
                return px_, py_
            fp_after = uiwalk.screen_fingerprint(after)
            signal = uiwalk.tap_hit_signal(focus_before, focus_after, fp_before, fp_after)
            post_xml = after
        log("[.] 采样点 %d/%d (%d,%d)：dump %s，前台 %s → %s，判定 %s"
            % (_i + 1, len(pts), px_, py_, "有" if post_xml else "**失败**",
               (focus_before.split("/")[-1] or "?")[:28],
               (focus_after.split("/")[-1] or "?")[:28], signal or "无变化"))
        if info is not None:
            info.update({"xy": (px_, py_), "signal": signal,
                         "focus_before": focus_before, "focus_after": focus_after,
                         "post_xml": post_xml})
        if signal == "focus":
            if _i:
                log("[*] AI 框中心未点中，第 %d 个采样点 (%d,%d) 命中「%s」（前台页面已切换）"
                    % (_i + 1, px_, py_, (entry.label or "")[:24]))
            return px_, py_

        if signal == "ui":
            if not focus_before:
                # 拿不到前台页面信息，只能靠界面内容变化判断
                return px_, py_
            # ★ 能测到前台页面、而页面**没有**切换时，仅"内容变了"不足以判定命中：
            #   真机实测（赣警办 e2e6）—— 点击落在弹窗滚动区域上，
            #   弹窗滚了一下（文字集合变了），被当成"点开了政策页"，
            #   于是后续把弹窗内容当作政策页判断，结论在"已点开/未跳转"之间摇摆。
            #   这里改记为"疑似"，继续换采样点；全部试完再回退采用它。
            if ui_changed_at is None:
                ui_changed_at = (px_, py_)
                if info is not None:
                    info["post_xml"] = post_xml

        _i += 1
        if _i >= len(pts) and not _wide_used:
            # 第一遍（竖向中线）全部落空 → 补一遍横向。
            # 只在"确实什么都没发生"时才补：已经有过 ui 变化说明点到了东西，
            # 再横扫一遍只会把弹窗点乱。
            _wide_used = True
            _extra = [p for p in entry_sample_points_wide(
                getattr(entry, "bounds", None)) if p not in pts]
            if _extra and ui_changed_at is None:
                pts.extend(_extra)
                log("[.] 竖向 %d 个采样点无反应，改在框内横向补点 %d 个"
                    "（可点文字可能只是段落中的一小段）" % (_i, len(_extra)))

    if ui_changed_at is not None:
        log("[*] 框内各采样点都没切换前台页面，但界面内容有变化（%d,%d）——"
            "可能是在同一页面内展开/滚动，按已点中处理"
            % (ui_changed_at[0], ui_changed_at[1]))
        if info is not None:
            info["signal"] = "ui"
        return ui_changed_at

    log("[!] AI 框内 %d 个采样点都没能让界面/前台页面发生变化，入口「%s」可能不可点击"
        % (len(pts), (entry.label or "")[:24]))
    if res is not None:
        res.errors.append("AI 定位的政策入口「%s」在框内多次点击均无响应"
                          % (entry.label or "")[:30])
    return x, y


def _ai_decide_drill(res: ScanResult, ai_tasks: Optional[AITasks], serial: str,
                     xml: str, opened_from: str, log: Callable[[str], None]
                     ) -> Dict[str, Any]:
    """让 AI 判断当前政策页的性质，并给出下一步该点哪里。

    返回 {"page_kind": str, "target": node|None, "links": [...], "links_text": [...]}。
    任何失败都返回空 dict，调用方回退到「正文不够长就继续下钻」的老启发式。

    为什么这一步值得让模型参与：老策略只看"文本够不够长"，遇到两种情况会做错：
      · **登录墙**：政策入口点进去先要登录，页面很短 → 老策略认为"不是正文，
        继续找入口下钻" → 在登录页上找"入口"，很可能点到登录/注册按钮。
      · **目录页**：不区分「个人信息处理规则」和「软件使用协议」，
        按元素面积和文字长度排序，常常先点进次级文档（如软件使用协议），
        采到的根本不是隐私政策。
    """
    out: Dict[str, Any] = {"page_kind": "", "target": None, "links": []}
    if ai_tasks is None or not ai_tasks.can_vision():
        return out
    shot = capture_screenshot(serial)
    if not shot:
        return out
    cands = _ai_candidates(xml)
    t_ai = time.time()
    try:
        ret = ai_tasks.classify_policy_page(shot, cands,
                                            list(uiwalk.screen_texts(xml))[:25],
                                            opened_from=opened_from)
    except Exception as e:
        res.ai_errors.append("政策页 AI 判定异常：%s" % e)
        return out
    finally:
        res.ai_wait_seconds += max(0.0, time.time() - t_ai)   # 同 _ai_popup_view：不算采集时间
    if ret is None:
        return out
    kind = str(ret.data.get("page_kind") or "") if ret.ok else ""
    _ai_record(res, "政策页判定", ret, action=kind or "（解析失败）",
               extra={"candidates": len(cands)})
    out["page_kind"] = kind
    if not ret.ok:
        return out
    out["links"] = list(ret.data.get("links") or [])
    out["is_policy_content"] = bool(ret.data.get("is_policy_content"))
    # next_targets 已按 AI 给的优先级排好序，取第一个可用的
    for t in (ret.data.get("next_targets") or []):
        node = _node_from_bounds(t.get("text") or "", t.get("bounds"))
        if node is not None:
            out["target"] = node
            out["target_why"] = t.get("why") or ""
            break
    if kind == "login_wall":
        note = ("政策入口点开后要求登录，未能获取政策正文"
                "（AI 视觉判定）。这是需要人工复核的发现："
                "政策应当在无需登录的情况下可查阅。")
        if note not in res.policy_capture.setdefault("notes", []):
            res.policy_capture["notes"].append(note)
        res.errors.append("隐私政策可能要求在登录后才能查看，已记录待人工确认")
    elif kind == "captcha":
        note = "政策页被验证码/人机校验拦截，未能获取正文（AI 视觉判定）"
        if note not in res.policy_capture.setdefault("notes", []):
            res.policy_capture["notes"].append(note)
    return out


def _agent_goal(elapsed_ratio: float) -> str:
    """按采集进度给出这一阶段的目标。

    为什么目标要分阶段：整个遍历如果只有一个笼统目标（"探索 App"），
    模型会一直在首页附近打转，因为它不知道"什么时候该深入"。
    按进度给目标，等于把它从"随机漫步"变成"有优先级的探索"：
      前期跟着 App 自己的首次使用流程走（引导页 → 权限弹窗），
        这一段最容易触发真实的权限申请与信息收集行为；
      中期主动去「设置 / 我的 / 账号」这类页面 —— 权限管理、隐私开关、
        个性化推荐关闭、第三方共享清单通常都藏在这里，而这些恰好是
        报告里"有没有提供撤回同意/关闭渠道"类判定项需要的证据；
      后期专门找注销账号 / 更正删除入口，并确认操作路径是否可达。
    """
    if elapsed_ratio < 0.3:
        return ("跟随 App 的首次使用流程往前走：完成引导页、处理权限申请弹窗、"
                "进入主要功能页面。目标是触发 App 在正常使用下的真实行为。")
    if elapsed_ratio < 0.7:
        return ("主动探索「设置 / 我的 / 个人中心 / 账号」这类页面，"
                "重点找：隐私设置、权限管理、个人信息副本、"
                "个性化推荐开关、已收集的个人信息清单。")
    return ("寻找并进入「注销账号 / 账号注销 / 删除个人信息 / 更正个人信息 / "
            "撤回同意 / 投诉举报」相关入口，确认操作路径是否存在、是否可达。")


# 同屏重复动作的容忍次数：超过就说明这个动作在这一屏已经没有作用。
#
# ★ 数值来自真机实测，不是拍脑袋（2026-10-31 那批 4 档 / 1 小时）：
#   看个比赛 387 步 / 4526 秒里，297 步是「返回上一级」、67 步是滑动，
#   真正点击只有 9 次；冰纷万象 191 步里 176 步是「向 up 滑动」，点击 4 次。
#   也就是说：**时间预算翻了几倍，可探索的界面一个没多**。
#
#   各动作的容忍度不同，因为"重复"的含义不一样：
#     · back    —— 有效返回一定换屏。连着 3 次没换屏，说明返回被吃掉
#                  （WebView 自己消费了返回，或者卡在同一个弹窗上）；
#     · swipe   —— 长列表要滚很多次才到底，所以给 4 次；同向 4 次界面纹丝
#                  不动就是到底了（继续滑只会把预算烧在空屏上）；
#     · pull    —— 上拉加载只该触发一次，第二次还不变就是没有下一页。
STUCK_RUN_LIMIT = {"back": 3, "swipe:up": 4, "swipe:down": 4,
                   "swipe:left": 3, "swipe:right": 3, "pull": 2}
# 本屏连续多少个动作都没换来新界面 → 这屏已经榨干，强制换屏（而不是继续问模型）。
# 取 12：一个正常信息量大的页面（设置页、我的页）通常在 10 个动作内能翻完；
# 超过 12 个还没变化，基本可以断定这屏没有可探索的东西了。
STUCK_TOTAL_LIMIT = 12

# ---- 秒级停滞熔断（2026-11-09 镜像投屏事故）----
# 事故现场：extreme 档 3600 秒，前 14.6 分钟做了 64 个动作（正常），之后 **2760 秒
# 一个动作都没有**，界面前台一直是 MainActivity，只有友盟 SDK 每分钟上报一次。
# 轮次看门狗（_IDLE_RESPAWN_AT）为什么没拦住？因为它的"进展"标尺里带了
# `len(kg.nodes)`，而图谱每轮 sync 都在小幅重建（14↔15 抖动），`_prog_sig`
# 每轮都不同 → idle_rounds 永远被清零 → 8 轮重拉、20 轮收工两条判据都到不了。
# 辙：另立一条**与任何计数无关**的判据 —— 只看"多久没有新界面 / 新入口"。
#   · 主循环 5~10 秒必出一个动作，240 秒毫无新界面已经远超正常节奏；
#   · 阈值必须大于登录辅助等验证码的 180 秒，否则会在验证码到达前把应用重拉掉。
#   · 重拉一次仍不前进，说明不是脏状态，直接收工（不把剩余预算换成重启次数）。
_STALL_RESPAWN_SECS = 240
_STALL_GIVEUP_SECS = 540


# ---- 连续读不到界面结构时的处置阈值（2026-11-02 川剧迷事故）----
# 事故现场：点到搜索页后 uiautomator 再也导不出结构树，连续 63 次失败，
# 每轮 18s 超时 + 补读 + 清理 ≈ 49 秒，第 51~111 轮烧掉 2954 秒（49 分钟）
# 却**一个动作都没做**，最后写成"时间预算耗尽"。
# 单个软失败是常态（WebView/动画），但连续失败说明设备侧已经读不出来了：
#   · 到 2 次 → 发 ESC 收软键盘（点进搜索框后键盘占焦点，是导不出结构树
#     最常见的一类；ESC 不改页面、不动返回栈，比重启 App 温和得多）；
#   · 到 4 次 → 重启被测应用自愈一次（输入法/WebView 的脏状态多半能清掉）；
#   · 到 8 次 → 判死，明确终止并把原因写进报告，不再空转。
_DUMP_BLUR_AT = 2
_DUMP_RESET_AT = 4
_DUMP_GIVEUP = 8

# ---- 无进展看门狗（2026-11-03 高途 56 分钟空转）----
# 上面那套 dump 阈值只管"读不到结构树"。高途的形态更隐蔽：结构树**读得到**，
# 只是每一轮都走进「系统权限弹窗 → 已记过 → continue」这条路 ——
# 界面没变、动作没发生，台账/振荡/僵化三条判据全部失明（它们都只看执行过的动作），
# 于是 3518 秒里 3357 秒在重读同一个弹窗。
# 判据改成「已执行动作数 + 留痕条数 + 图谱界面数」都不动：
#   · 连续 8 轮不动 → 重新拉起应用自愈（一次约 20~30 秒，比继续空转便宜）；
#   · 连续 20 轮不动 → 明确收工，把原因写进 stop_reason。
# 取 8/20 而不是更小的数：页面切换、WebView 首屏渲染本来就会有几轮没有动作，
# 太敏感会在正常页面上反复重启，那会把预算换成重启次数。
#
# ★ 2026-11-09 修两个真机暴露的洞（镜像投屏 / 天优家教 各跑满 1 小时）：
#   ① 判据里原来含"界面指纹"。镜像投屏首页有轮播与实时画面，同一屏每轮算出来
#      的指纹都不一样 → 每轮都被当成"换屏了"，看门狗永远不响，47 分钟零动作。
#      指纹只能说明"画面在变"，**不能**说明"探索在推进"。真正算推进的只有：
#      执行了动作、产生了留痕、图谱里多了新界面。
#   ② 重拉之后把 idle_rounds 清 0，于是"8 轮重拉 → 清 0 → 再 8 轮重拉"无限循环，
#      下面 >=20 的收工判据永远到不了。天优家教因此重拉了 84 次。
#      现在按屏记次数：同一屏最多重拉 2 次，全局最多 4 次，超了就带着原因收工。
_IDLE_RESPAWN_AT = 8
_IDLE_GIVEUP = 20
_IDLE_RESPAWN_PER_SCREEN = 2
_IDLE_RESPAWN_TOTAL = 4

# ---- 流程推进按钮（2026-11-05 高途实测）----
# 「我已年满14周岁」「同意」「确认」「进入」「跳过」这类按钮点下去之后落到登录页，
# 是 App 的设计（先过年龄/告知关，再登录），不是"这个入口需要登录"。
# 归错因的代价很实际：把首屏唯一的入口记成"需登录"并从候选剔除，整轮只点了 1 次。
_GATE_FLOW_WORDS = ("同意", "已满", "年满", "确认", "我知道了", "开始使用",
                    "进入", "跳过", "继续", "下一步")



def ui_walk_blur(serial: str) -> bool:
    """收起软键盘（ESC / keyevent 111）。

    点进搜索框后键盘占住焦点，`uiautomator dump` 会一直等 idle 直到超时 ——
    真机上的表现就是"点开某一页之后突然再也导不出结构树"（川剧迷事故）。
    ESC 只让输入法收键盘，不改页面、不动返回栈，比"重启 App"温和得多，
    所以放在自愈的第一档。
    """
    try:
        return bool(uiwalk._inject(serial, "input keyevent 111"))
    except Exception:
        return False


def _event_silence(res) -> float:
    """距离最近一条 hook 事件的秒数（判断"应用是不是不干活了"）。

    ★ 单看"这段时间没有事件"没有意义：一个静止页面本来就不调 API。
      必须和"界面结构也导不出来"合起来看 —— 两条同时成立才是「应用无响应」。
      川剧迷 2026-11-02 那次就是这样：点进 SearchActivity 之后 3154 秒
      0 条事件、0 次界面变化、63 次 dump 失败，报告却只写了"有 63 次导出失败"。
    """
    try:
        if not res.events:
            return 0.0
        ts = float(res.events[-1].get("ts") or 0)
        if ts > 1e12:            # 毫秒时间戳
            ts /= 1000.0
        if ts <= 0:
            return 0.0
        return max(0.0, time.time() - ts)
    except Exception:
        return 0.0

# 封禁提示里给使用者看的名字。用报告里的说法（"返回上一级"）而不是代码里的
# `back` —— 这句会原样写进报告的"未测原因"，写英文键名等于没解释。
ACT_LABEL = {"back": "返回上一级", "swipe:up": "向上滑动", "swipe:down": "向下滑动",
             "swipe:left": "向左滑动", "swipe:right": "向右滑动", "pull": "上拉加载"}


def _note_act_result(changed: bool, act_sig: str, run: Dict[str, int],
                     banned: set) -> Optional[str]:
    """结算"上一步动作有没有换来新界面"，返回刚被封禁的动作（没有则 None）。

    ★ 判据只看一件事：**界面指纹变没变**。
      变了 → 清零。之前那句"这个动作在这屏没用"只对旧界面成立，
             新界面上返回/滑动完全可能重新有效。
      没变 → 该动作在本屏的连续无效次数 +1，到量就封禁。

    封禁不是"跳过这一步"，而是此后每个执行分支都要查 `banned` ——
    只在决策处过滤、执行处不查，等于没封（AI 仍会把它选出来）。
    """
    if changed:
        run.clear()
        banned.clear()
    # ★ 清零要在"没有动作签名"之前判：
    #   权限弹窗、登录代填这些分支只 `continue`，不留动作签名；
    #   但它们后面界面往往已经变了。若因为签名为空就提前 return，
    #   上一屏的封禁会带到新界面上 —— 新界面明明可以返回，却被判"返回无效"。
    if not act_sig or changed:
        return None
    n = int(run.get(act_sig, 0) or 0) + 1
    run[act_sig] = n
    run["__total__"] = int(run.get("__total__", 0) or 0) + 1
    if act_sig == "tap":
        # 点击的"无效"由另一条 `stuck` 判据负责（它还要负责清悬浮窗），
        # 这里只把点击算进本屏空转总量，免得两套阈值各自报一遍。
        return None
    lim = int(STUCK_RUN_LIMIT.get(act_sig, 4))
    if n >= lim and act_sig not in banned:
        banned.add(act_sig)
        return act_sig
    return None


def _act_blocked(act_sig: str, banned: set) -> bool:
    """这个动作在本屏是不是已经被判无效。

    `back` 与 `swipe:*` 分开封：封了返回不该连带把滑动也封掉
    （那会让遍历彻底停在原地，比原来的死循环更糟）。
    """
    return bool(act_sig) and act_sig in banned


def _should_skip_ai(options: Sequence[Any], asked: int, per_node: int,
                    last_act: str) -> bool:
    """这一屏要不要跳过模型，直接按图上排序执行。

    ★ 判据：**这个界面已经问过 per_node 次**，且当前有图选项可用。

    ★ 2026-11-01 改：不再要求"上次模型选的是 tap"。
      旧版只在"上一步点了东西"时才敢跳过模型，理由是"模型选 back 说明它
      判断这屏该离开，换成图排序去点入口方向就反了"。
      但真机数据表明那条规则的代价远比它防住的问题大：
      模型连续几轮都选 back、界面又纹丝不动时，旧逻辑会**每步都重新问模型**
      （一次十几秒），问出来的还是同一个 back，于是无限返回 ——
      2026-10-31 的 4 档任务里，看个比赛 387 步中 297 步是「返回上一级」，
      1 小时预算只换来 9 次真实点击。
      "界面没变"这件事本身就说明模型上一轮的判断没起作用；这时再问一遍，
      得到的必然是同一个答案。真正该做的是换策略（换入口/换屏），
      而"换策略"由 `act_banned` 与"榨干换屏"负责，不需要再问一次模型。
      界面一旦变化，`ai_asked` 按新指纹重新计数，模型又会重新参与决策。
    """
    return bool(options) and per_node > 0 and asked >= per_node


def _option_to_step(opt: Any, why: str = "") -> Dict[str, Any]:
    """把一个图选项翻成执行层的 step dict。

    ★ 抽成函数是因为有**两个**来源会产出"该做什么"：模型选中的编号，
      以及"这一屏已经问过模型、直接按图上排序取第一项"。两处各写一份，
      迟早有一边漏掉 scroll→swipe 的语义映射（up = 手指上滑 = 看下面）。
    """
    act = str(getattr(opt, "action", "") or "")
    out: Dict[str, Any] = {
        "action": act,
        "reason": why or (getattr(opt, "why", "") or ""),
        "expect": "", "oid": "", "opt_why": getattr(opt, "why", "") or "",
    }
    if act == "tap":
        out["node"] = getattr(opt, "node", None)
    elif act == "scroll":
        out["action"] = "swipe"
        out["direction"] = "up"
    return out


def _ai_choose_step(res: ScanResult, ai_tasks: Optional[AITasks], kg: Any,
                    fp: str, options: Sequence[Any], goal: str, xml: str,
                    serial: str, log: Callable[[str], None]
                    ) -> Optional[Dict[str, Any]]:
    """在当前节点的**有限动作集**里让模型选一个（UI-KOBE 的 graph-guided）。

    与 `_ai_plan_step`（自由规划）的分工写在 `AITasks.choose_action` 的注释里。
    这里只负责：截图 → 交给模型 → 把选中的编号映射回本地选项。

    ★ 返回值刻意做成与 `_ai_plan_step` 同一套字段（action / node / direction），
      这样执行段一行都不用改 —— 图引导与自由规划可以随时互相兜底，
      而不是两套执行路径各写一份（那份必然有一边会漏掉危险按钮拦截）。
    """
    if ai_tasks is None or kg is None or not options:
        return None
    shot = capture_screenshot(serial)
    if not shot:
        return None
    try:
        memory = kg.memory_text(fp)
    except Exception:
        memory = ""
    try:
        ret = ai_tasks.choose_action(
            shot, options, memory, goal,
            screen_texts=list(uiwalk.screen_texts(xml))[:12])
    except Exception as e:
        res.ai_errors.append("图引导选择异常：%s" % e)
        return None
    if ret is None:
        return None
    if not ret.ok:
        _ai_record(res, "图引导选择", ret, action="（解析失败）")
        return None
    d = ret.data
    oid = str(d.get("choice") or "")
    opt = None
    for o in options:
        if str(getattr(o, "oid", "")) == oid:
            opt = o
            break
    if opt is None:
        return None
    out = _option_to_step(opt)
    out["oid"] = oid
    out["reason"] = d.get("reason") or out["reason"]
    out["page"] = d.get("page") or ""
    return out


def _ai_plan_step(res: ScanResult, ai_tasks: Optional[AITasks], serial: str,
                  xml: str, cands: List[Any], goal: str, step: int,
                  back_unsafe: bool, log: Callable[[str], None]
                  ) -> Optional[Dict[str, Any]]:
    """问 AI 下一步该做什么。返回 {"action","node"/"direction","reason"} 或 None。

    候选**包含**危险按钮（如「不同意并退出」）：这是有意的 —— 让模型看到它们，
    自己用语义判断绕开。执行前本地还会再拦一次（见调用处），是纵深防御而非重复。
    """
    if ai_tasks is None or not ai_tasks.can_vision():
        return None
    shot = capture_screenshot(serial)
    if not shot:
        return None
    # 只把最值得看的一批送过去；顺序上把"未点过、非危险"的放前面，
    # 这样即使被截断，模型也优先看到有价值的候选。
    ordered = sorted(cands, key=lambda n: (1 if uiwalk.is_dangerous(n) else 0,
                                           len((n.text or "").strip())))[:AI_CANDIDATE_CAP]
    history = [s for s in res.ui_steps[-14:]]
    try:
        ret = ai_tasks.plan_ui_action(
            shot, [(n.label, n.bounds, "可点击") for n in ordered],
            list(uiwalk.screen_texts(xml))[:25], goal=goal, step=step,
            history=history, package=res.package, back_unsafe=back_unsafe)
    except Exception as e:
        res.ai_errors.append("UI 决策异常：%s" % e)
        return None
    if ret is None:
        return None
    if not ret.ok:
        _ai_record(res, "UI 决策 #%d" % step, ret, action="（解析失败）")
        return None

    d = ret.data
    action = str(d.get("action") or "")
    out: Dict[str, Any] = {"action": action, "reason": d.get("reason") or "",
                           "expect": d.get("expect") or ""}
    # 把 AI 选中的目标映射回候选节点。三条路径，按可靠性排序：
    #
    # ① 坐标（首选）：tasks 返回的 target_bounds 取自它**画给模型的那张编号表**，
    #    编号与坐标天然对齐，且本来就是结构树的精确 bounds。
    #
    # ② 文字（次选）：按 target_text 在本地候选表里找同名节点。
    #
    # ③ 序号（最后）：**这一步必须放在最后**。真机实测踩过坑：
    #    annotate 会把「整屏容器」跳过（如 dialog_dim_bg 这种覆盖全屏的遮罩，
    #    画上去只会糊住别的框），跳过后**重新编号**。于是"提示词里的 2 号"
    #    与"本地列表的第 2 个"根本不是同一个元素 —— 模型选 2 号「本次运行允许」，
    #    按序号取却拿到了 1 号容器，点下去落在一处空白上，弹窗纹丝不动。
    #    所以序号只能当兜底，且必须排在坐标与文字之后。
    idx = d.get("index")
    node = None
    if d.get("target_bounds"):
        node = _node_from_bounds(d.get("target_text") or "AI 目标", d["target_bounds"])
        # 坐标路径拿不到真实文字，用结构树按坐标回填 —— 否则 label 会是"AI 目标"，
        # 遍历阶段的同意检测（按文字命中同意词）就永远不会生效。
        real = _text_at_bounds(xml, d["target_bounds"])
        if real:
            node = _node_from_bounds(real, d["target_bounds"])
    if node is None and d.get("target_text"):
        want = str(d["target_text"]).strip()
        for n in ordered:
            if (n.label or "").strip() == want:
                node = n
                break
    if node is None and isinstance(idx, int) and 1 <= idx <= len(ordered):
        node = ordered[idx - 1]
    if action == "tap" and node is not None and len(ordered) > 1:
        # 便于出问题时定位：把「模型选的编号」与「本地候选表」一起留痕。
        # 两者错位是这个环节唯一会「点错地方」的失败模式，值得每次都有记录。
        log("    [AI] 选中 #%s「%s」｜候选表 %s"
            % (idx, (node.label or "")[:20],
               " / ".join("#%d %s" % (i + 1, (n.label or "")[:14])
                          for i, n in enumerate(ordered[:6]))))
    if action == "tap" and node is not None:
        out["node"] = node
    elif action == "swipe":
        out["direction"] = d.get("direction") or "up"
    elif action == "input":
        out["text"] = d.get("text") or ""
    _ai_record(res, "UI 决策 #%d" % step, ret,
               action="%s %s" % (action, getattr(node, "label", "") or out.get("direction", "")))
    return out


# ---------------------------------------------------------------- 首启弹窗阶段

def note_captcha(res: "ScanResult", xml: str, log: Callable[[str], None],
                 where: str = "") -> bool:
    """识别并记录反自动化验证界面（滑块/人机验证）。

    为什么必须显式记录：验证码界面会接管整个 App，之后采集到的界面与行为
    都不是"App 正常运行时"的表现。如果不标注，报告读起来就跟
    "App 没有这些行为"一模一样 —— 结论会朝相反方向偏。
    """
    hits = uiwalk.captcha_markers(xml or "")
    if not hits:
        return False
    # 把命中处的界面文本一并留下：只写"命中：验证码"是没法核对的，
    # 人工复核时需要看到"它到底看到了什么"才能判断告警是否成立。
    ctx = uiwalk.marker_context(xml or "", hits[0])
    where_s = where + " " if where else ""
    tag = "%s命中：%s" % (where_s, "、".join(sorted(set(hits))[:4]))
    if ctx:
        tag += "｜界面片段：%s" % ctx
    if tag in res.captcha_hits:
        return True
    res.captcha_hits.append(tag)
    msg = ("检测到疑似反自动化/人机验证界面（%s）。该界面上的 UI 行为与权限场景"
           "证据不可作为判定依据，相关结论请以人工沙箱复核为准。" % tag)
    if msg not in res.errors:
        res.errors.append(msg)
    log("[!] 疑似反自动化验证界面（%s）——本次 UI 行为证据降级" % tag)
    return True


def _read_policy_in_foreign(serial: str, res: Optional["ScanResult"],
                            cap: Dict[str, Any],
                            log: Callable[[str], None],
                            remember: Callable[[str, str], None],
                            focus_post: str, label: str,
                            stop_if: Optional[Callable[[], bool]] = None
                            ) -> Tuple[Dict[str, Any], float]:
    """政策入口被外部宿主接管时，**进到那个界面里把正文读出来**，读完退回应用。

    ★ 为什么抽成独立一步（2026-11-05 复跑春雨诊所的教训）：
      2026-11-03 那版只在"点击瞬间就抓到前台切换"的分支里做了这件事，
      而该 App 点击后 uiautomator 慢了半拍 —— `focus_after` 是空的，
      于是被判成"点了没反应"，浏览器里那 312 条文字、826 字政策正文
      一个字都没读到，报告照旧写"未取得条款"。
      判据必须能复算：**此刻前台在外部、且是浏览器**就够了，不依赖"哪一刻抓到的"。

    返回 `(read, elapsed)`。`read` 为空表示没读（宿主不是浏览器 / 读库不可用）；
    `elapsed` 是这一趟花掉的时间，调用方要把它加回 deadline ——
    读正文的时间不该挤占"等同意按钮"的窗口。
    """
    out: Dict[str, Any] = {}
    if docread is None or not focus_post:
        return out, 0.0
    _pkg, _act = ("", "")
    if foreignmod is not None:
        try:
            _pkg, _act = foreignmod.parse_focus(focus_post)
        except Exception:
            _pkg, _act = ("", "")
    _kind = (foreignmod.host_kind(_pkg, _act) if foreignmod is not None else "")
    # ★ 类名兜底不能只在 `_kind` 为空时生效。高途 2026-11-05：前台只有
    #   `.BrowserActivity`，`_kind` 拿到了 "unknown"（非空），旧写法于是
    #   跳过类名判断，判"不是浏览器"→ 一个字都不读。
    _is_browser = (_kind == "browser"
                   or "browser" in (focus_post or "").lower())
    cap["externalOpen"] = focus_post
    log("[.] 政策入口由系统组件/外部应用接管（前台 %s，类别 %s）——%s"
        % ((focus_post.split("/")[-1] or "?")[:32], _kind or "未知",
           "按「在外部界面里读正文」处理" if _is_browser
           else "不是浏览器，只记事实、不读取"))
    if not _is_browser:
        # 系统选择器 / 别的 App：不读，只记事实（读也读不到政策）。
        if res is not None:
            res.errors.append(
                "政策入口「%s」点击后由系统组件/外部应用接管（前台 %s），"
                "未在被测应用内打开政策页，政策正文需人工核对"
                % ((label or "")[:30], (focus_post.split("/")[-1] or "?")[:32]))
        return out, 0.0

    _t0 = time.time()
    # 浏览器里滚动读：最多 8 屏 / 100 秒。政策正文通常 20~80 屏，
    # 读不全没关系 —— 读到多少算多少，报告按"浏览器内读取（部分）"标注；
    # 读到 0 字（打不开、白屏）也如实写。
    out = docread.read_page(serial, log, max_scrolls=8, budget=100.0,
                            min_chars=INLINE_POLICY_MIN, stop_if=stop_if)
    cap["externalRead"] = {
        "chars": int(out.get("chars") or 0),
        "screens": int(out.get("screens") or 0),
        "err": out.get("err") or "",
        "why": out.get("why") or "",
        "kind": _kind,
        # ★ 留一段开头样本（2026-11-05 高途）：读到 7815 字却被判"不像隐私政策"
        #   时，存档里只剩一个字数，人工没法复核"到底读到了什么"—— 是浏览器首页？
        #   还是真政策但判据太严？没有样本就只能猜。存前 300 字、压掉换行。
        "sample": " ".join((out.get("text") or "").split())[:300],
    }
    _btxt = (out.get("text") or "").strip()
    if out.get("err"):
        log("[!] 浏览器里的政策页打不开（%s），跳过并退回应用" % out.get("why"))
        if res is not None:
            res.errors.append(
                "政策入口「%s」由系统浏览器打开，但页面打不开（%s）；"
                "该页已跳过，政策正文未能取得，需人工核对"
                % ((label or "")[:30], out.get("why") or "未知原因"))
    elif _btxt:
        # 归属闸门照旧走 `remember`：浏览器里可能是任意网页。
        _before = len((cap.get("bestText") or "").strip())
        remember(_btxt, "政策正文（应用内入口由浏览器打开）")
        _now_len = len((cap.get("bestText") or "").strip())
        if _now_len >= INLINE_POLICY_MIN:
            cap["bestTextFrom"] = "浏览器内页面（应用内入口打开）"
            log("[+] 政策正文已在浏览器内取得 %d 字（%d 屏），已跳过应用内滚动"
                % (int(out.get("chars") or 0), int(out.get("screens") or 0)))
        elif _now_len > _before:
            log("[.] 浏览器内读到 %d 字（%d 屏），其中约 %d 字通过判据、未达正文长度，"
                "继续按应用内路径取证"
                % (int(out.get("chars") or 0), int(out.get("screens") or 0), _now_len))
        else:
            # ★ 这句以前写的是"未达可作为正文的长度"，但 7815 字（高途 2026-11-05）
            #   远长于任何门槛 —— 真正的原因是被「像不像隐私政策」判据挡掉了
            #   （读到的是浏览器首页/搜索页/跳转提示）。写错原因会让人去调阈值，
            #   而阈值根本不是问题所在。
            log("[!] 浏览器内读到 %d 字（%d 屏），但没有通过「像隐私政策」判据"
                "（页面可能是浏览器首页/搜索页/跳转提示），不作为政策正文；"
                "继续按应用内路径取证"
                % (int(out.get("chars") or 0), int(out.get("screens") or 0)))
    # 留一张浏览器里政策页的图：报告写"政策在系统浏览器里"必须有图可看，
    # 而且必须在**退回应用之前**截 —— 退回去屏幕就变回首启弹窗了。
    try:
        if res is not None:
            observe_screen(res, "政策页（系统浏览器内）", serial)
    except Exception:
        pass
    # 读完必须退回被测应用：后面所有判断都建立在"在 App 里"。
    _ret = False
    for _ in range(3):
        uiwalk.back(serial)
        time.sleep(0.5)
        try:
            if not _is_external_focus(uiwalk.current_focus(serial) or "",
                                      res.package if res is not None else ""):
                _ret = True
                break
        except Exception:
            _ret = True
            break
    if not _ret:
        launch_app(serial, res.package if res is not None else "")
        time.sleep(2.0)
    return out, max(0.0, time.time() - _t0)


def _probe_first_launch(res: ScanResult, script, serial: str, log: Callable[[str], None],
                        wait_seconds: int = POPUP_WAIT_DEFAULT,
                        ai_tasks: Optional[AITasks] = None,
                        rehook: Optional[Callable[[], bool]] = None,
                        get_script: Optional[Callable[[], Any]] = None,
                        should_stop: Optional[Callable[[], bool]] = None,
                        on_stage: Optional[Callable[[str, int], None]] = None,
                        builtin_policy: Optional[Dict[str, Any]] = None,
                        consent_only: bool = False,
                        abandon_inject: Optional[Callable[[], bool]] = None,
                        probe_urls: Optional[Callable[[], List[Dict[str, str]]]] = None,
                        ) -> None:
    """首启观测：找隐私弹窗 -> 取政策正文 -> 点同意。

    `consent_only=True`（1 档「仅同意前」）：取到政策正文后**不点同意**就收工。
    这一档要的正是"同意之前它做了什么"，点了同意就把口径整个破坏掉了 ——
    而且这个动作不可撤销（App 会记住同意状态，除非清数据重来）。

    真机实测归纳出隐私政策的三种呈现形态，本函数按可靠性依次处理：
      形态 A 政策全文直接铺在弹窗/页面里（长 TextView，通常无链接可点）
             → 直接 dump 界面收割文本，必要时滚动几次读全
      形态 B 弹窗里有可点击的「查看/隐私政策」入口，点开是 WebView 页面
             → 点击 -> 读 WebView 渲染正文 -> 再收割界面文本 -> 返回
      形态 C 首启根本没提供政策提示
             → 记录为重要发现（对应 Q001）

    ★ AI 的参与方式（开启 ai.features.policy_vision 时）：
      每轮先让视觉模型看一眼当前截图，它的判断**优先于**关键词/长度启发式：
        · 它说"入口是编号 4 / 在这个坐标"→ 我们就点那儿（能认出
          「服务协议及个人信息处理规则」这种关键词表覆盖不到的写法，
          也能指出正文里那些结构树看不见的 ClickableSpan 超链接）
        · 它说"只有告知没有入口"→ 这是一条重要发现，同时仍用关键词兜底再试一次
        · 它挂掉 / 没配 → 一个字都不影响下面的原逻辑，照跑

    注意踩过的坑：
      · 弹窗标题常叫「隐私政策」但 clickable=false，点它没有反应；
      · UI 遍历用 input tap 注入触摸事件，不经过 Button.performClick，
        所以同意时刻必须由这里显式告知脚本（setConsent）。
    """
    cap = res.policy_capture
    cap.setdefault("urls", [])
    cap.setdefault("entryTexts", [])
    cap.setdefault("entryClicked", "")
    # 内联链接（正文里的《用户协议》《隐私政策》）：候选点、已试过的点、
    # 以及"从 span 直接读到的 URL"。报告要靠这些说清"试了哪几个位置、
    # 为什么没打开"，而不是只留一句"未观测到入口"。
    cap.setdefault("inlineLinks", [])
    cap.setdefault("inlineTried", [])
    cap.setdefault("inlineNotes", [])
    # WebView 补判的调用预算（见循环里那段注释）：限次 + 限间隔。
    _wv_probe = 0
    _wv_probe_at = 0.0

    def _fresh_script():
        """取当前**仍然有效**的脚本句柄。

        真机教训（赣警办）：报告里出现「读取政策捕获结果失败：script has been
        destroyed」—— 点开政策页/App 起新进程后，老的 Frida 脚本句柄被销毁，
        而我们一直拿开局那个引用去调 exports，于是政策 URL 和正文一个都没取回来。
        所以每次读之前都要重新问一次"现在是哪个脚本"，必要时重附着。
        """
        s = script
        if get_script is not None:
            try:
                cur = get_script()
                if cur is not None:
                    s = cur
            except Exception:
                pass
        return s

    def _policy_via(live_script):
        try:
            return live_script.exports_sync.get_policy() or {}
        except Exception as e:
            msg = str(e).lower()
            if ("destroyed" in msg or "closed" in msg or "disposed" in msg) \
                    and not res.reattach_banned \
                    and rehook is not None and rehook():
                log("[*] 读政策结果时脚本已失效，已重新附着后重试")
                return _fresh_script().exports_sync.get_policy() or {}
            raise
    cap.setdefault("bestText", "")        # 政策**正文**（政策页 / 足够长的内联全文）
    cap.setdefault("bestTextUrl", "")
    # 正文的取得方式（"按链接抓取" / "界面读取" / "政策页面文本（滚动后）"…）。
    # 与 bestTextUrl 分开：前者是人话，后者必须是能点开的地址。
    cap.setdefault("bestTextFrom", "")
    # 本轮取到的各类文档（隐私政策 / 用户协议 / 收集清单 / 共享清单…）。
    # 见 `_record_document`：四类都对判定有用，报告要逐份列出来。
    cap.setdefault("documents", [])
    # 安装包里已经有的政策全文（由上游静态分析传入）。有它就不再靠滑动去"读"。
    _builtin_text = str((builtin_policy or {}).get("text") or "").strip()
    _builtin_path = str((builtin_policy or {}).get("path") or "")
    if _builtin_text:
        cap["builtinPolicy"] = {"path": _builtin_path, "chars": len(_builtin_text)}
    cap.setdefault("noticeText", "")      # 首启弹窗上的"告知摘要" —— 不是政策全文
    cap.setdefault("noticeFrom", "")
    cap.setdefault("notes", [])
    cap.setdefault("webviewCount", 0)
    cap.setdefault("uiHarvested", False)
    cap.setdefault("pageLinks", [])      # 政策页上看到的其它文档链接（AI 读出）
    # 政策获取的最终结论（结构化）：not_run / full / full_inline / notice_only /
    # error_page / no_text / no_entry。报告与规则层都读这个字段，不再各自猜。
    #
    # ★ 这里**不能**预置 "not_run"（2026-11-01 修正）。
    #   末尾那段 `if not cap.get("outcome")` 负责按 bestText / urls / entryClicked
    #   算出真实结论；预置一个非空值会让它永远不执行 —— 于是只要没走到某个
    #   显式赋值分支，最终结论一律是 "not_run"。
    #   后果很严重：看个比赛 2026-10-31（跑了 75 分钟、首启观测 156 秒）报告写
    #   「本次未执行首启政策捕获」，读者会以为我们没测 —— 而事实是我们测了、
    #   只是没定位到入口。把"我们没找到"写成"我们没测"，方向正好反了。
    #   预置空串之后由末尾统一结算，取不到值时才由报告层兜底成 not_run。
    cap.setdefault("outcome", "")

    # ★ 先等 App 真正到前台，再开始算「首启观测」的时间窗（金考典 2026-10-27）。
    #   加固包冷启动 + 解壳实测要 60s 以上；这段等待本身也要记进日志，
    #   否则报告里只剩一句"未观测到政策入口"，看不出其实是没等到界面。
    _appear_max = max(FIRST_SCREEN_WAIT,
                      min(FIRST_APPEAR_MAX, max(20.0, float(wait_seconds) * 2)))
    _t_appear = time.time()
    try:
        _fg, _fg_last = await_app_foreground(
            serial, getattr(res, "package", "") or "",
            wait_s=_appear_max, poll=0.8)
    except Exception:
        _fg, _fg_last = True, ""
    _waited = time.time() - _t_appear
    if _fg:
        res.app_foreground_seen = True
        if _waited > FIRST_SCREEN_WAIT:
            log("[*] 冷启动到前台用了 %.0fs，现在开始观测首启界面" % _waited)
            res.errors.append("冷启动到前台耗时 %.0fs（超过首屏等待阈值 %.0fs，"
                              "加固包解壳常见），首启观测已顺延，未影响取证"
                              % (_waited, FIRST_SCREEN_WAIT))
    else:
        log("[!] 等待 %.0fs 后仍未看到被测应用：%s——"
            "首启观测与政策取证无法开展" % (_waited, _foreground_note(serial)))
        res.errors.append(
            "冷启动后 %.0fs 内屏幕上始终没有出现被测应用（%s），"
            "首启观测与政策取证无法开展" % (_waited, _foreground_note(serial)))

    # ★ "没界面"有两种，处置完全相反（2026-11-08 小包搜题 1.9.5）：
    #   (a) 还在解壳、界面没画出来        → 等，把窗口顺延（下面的 _grace）；
    #   (b) 进程已经没了（注入被壳判成调试 → 应用自杀）→ 等多久都不会有界面，
    #       必须**放弃注入、不注入重新拉起**，否则整轮只能在桌面上"观测"。
    #   实测证据：hook 回执写着"安装成功 70 个"，紧接着 `am_crash: Native crash,
    #   Segmentation fault`；遍历阶段"重新拉起并注入"又把它杀了 4 次，
    #   整轮只点了 2 次、界面 3 个。反证是同一台机器**不注入**时它能正常跑到
    #   `.ui.AgreementActivity`（首启协议页）7 次 —— 政策链接就在那一页上。
    #   也就是说，注入在这类应用上带来的不是"事件更多"，而是"界面都看不到"。
    #
    #   判据与遍历阶段的存活检查**一致**，两个条件同时成立才算死：
    #     · `pidof 包名` 取不到 —— 它按进程名精确匹配，多进程/加固包主进程名
    #       未必等于包名，只看它会误判（小盒课堂 2026-10-27 吃过这个亏）；
    #     · 前台也不在被测应用里 —— 真的不在屏幕上了。
    #   land35 补的一课：崩溃发生在启动后 1.4 秒，活动页**短暂到过前台**，
    #   所以这条检查不能只在"前台没来"时才做，必须无条件做一次。
    _pkg = getattr(res, "package", "") or ""
    if _pkg and abandon_inject is not None:
        _now_fg = ""
        try:
            _now_fg = uiwalk.current_focus(serial) or ""
        except Exception:
            _now_fg = ""
        _alive = None
        try:
            _alive = find_running_pid(serial, _pkg)
        except Exception:
            _alive = None
        if _alive is None and not _now_fg.startswith(_pkg):
            log("[!] 被测进程已不存在（pidof 取不到、前台也不在应用内）：判定为加固壳"
                "把注入当成调试并触发了自杀，不是「启动慢」；改为不注入重新拉起，"
                "先把界面与政策拿到")
            _ok = False
            try:
                _ok = bool(abandon_inject())
            except Exception as e:
                log("[!] 放弃注入并重新拉起失败：%s" % e)
            if _ok:
                try:
                    _fg2, _fg_last2 = await_app_foreground(
                        serial, _pkg, wait_s=_appear_max, poll=0.8)
                except Exception:
                    _fg2, _fg_last2 = False, ""
                if _fg2:
                    _fg = True
                    _waited = time.time() - _t_appear
                    res.app_foreground_seen = True
                    log("[*] 不注入拉起后共 %.0fs 到达前台，首启观测从这一屏开始"
                        "（运行期 API 事件会缺失，报告会写明原因）" % _waited)
                    res.errors.append(
                        "冷启动注入被加固壳拦截（应用随即自杀），已改为不注入拉起并"
                        "继续首启观测：政策正文与界面证据不受影响，"
                        "运行期 API 事件因未注入而缺失")
                else:
                    log("[!] 不注入拉起后 %.0fs 仍未到前台（当前前台：%s）"
                        % (time.time() - _t_appear,
                           ((_fg_last2 or "").split("/")[-1] or "未知")[:30]))
                    res.errors.append("改为不注入拉起后仍未能到达前台，"
                                      "本轮首启界面证据缺失")

    deadline = time.time() + max(5, wait_seconds)
    # ★ 前台迟迟不来时，等待时间不能从"政策观测窗口"里扣（2026-11-08）。
    #   小包搜题 / 快搜搜题：加固壳冷启动，等了整整 50 秒前台还是桌面，
    #   而窗口本来只有 25 秒 —— App 刚起来窗口就结束了，同意页是在
    #   遍历阶段才第一次被看见，政策自然一个字节都没取到。
    #   这里的等待不是"观测"，把窗口等量顺延（上限一个窗口长度，防无限拖）。
    if not _fg:
        _grace = min(_waited, float(max(5, wait_seconds)))
        if _grace > 0:
            deadline += _grace
            log("[*] 前台一直没切过来，首启观测窗口顺延 %.0fs（不计入窗口消耗）" % _grace)
    harvested: List[str] = []
    policy_resolved = False
    consent_done = False
    rounds = 0
    # 屏幕状态检查的节流表（见 `_check_screen`）：黑屏会让整个首启观测
    # 变成"对着黑屏找弹窗"，而屏幕睡了与弹窗没出现是两件事。
    _scr: Dict[str, float] = {}
    # AI 看弹窗的次数上限（详见循环内的说明）
    ai_calls = 0
    ai_view: Optional[Dict[str, Any]] = None
    AI_MAX_CALLS = 2

    # 形态 A 的判定阈值：真把整份政策铺在界面上的，正文必然很长。
    # 几百字的短文本是"弹窗告知摘要"，与政策全文语义完全不同 ——
    # 拿摘要去当政策做条款比对，会把「已公开收集使用规则」判成未公开（假阳性），
    # 也会因为摘要里缺少必要信息而误报「未完整准确告知」。
    # 阈值已提到模块级（见 INLINE_POLICY_MIN），因为判定函数在模块层也要用它。


    def remember(text: str, source_label: str, origin: str = "policy") -> None:
        """把界面收割到的文本归档进两个**互不混淆**的通道。

        origin="popup"  → 首启弹窗上的告知摘要（cap["noticeText"]）
        origin="policy" → 政策页 / 内联全文（cap["bestText"]）

        真机教训（滴滴出行）：把弹窗摘要写进 bestText 后，pipeline 会认为
        「已在运行时读到政策全文」并把 source 标成 runtime_text，
        于是报告中出现「隐私政策：设备运行时读取」，而实际只有 525 字的摘要。
        """
        if not text:
            return
        if origin == "popup":
            if len(text) > len(cap.get("noticeText") or ""):
                cap["noticeText"] = text
                cap["noticeFrom"] = source_label
            return
        merged = _merge_chunks(harvested + [text])
        # ★ 收割通道也必须过类型闸门（以观书法 5.4.2 实测，2026-10-20）：
        #   App 自己的课程 H5（Android/data/<pkg>/files/Download/shuyuan.html）
        #   被 WebView 收割当成"政策正文"，1652 字的课程列表占了 bestText，
        #   报告据此判「实际收集设备属性但政策未列明」= 认定 —— 而那份"政策"
        #   全文连"隐私"两个字都没有。这里不再自行比长度，统一交给闸门。
        ok = _keep_policy_text(cap, merged, "", source_label)
        if not ok:
            # 累积缓冲里可能混进了别的页面碎片（同一 WebView 先后渲染多个 H5）。
            # 若本屏这段文字本身像政策，就以它重新起算，别让旧碎片把真政策拖下水。
            if _POL.looks_like_privacy_policy(text):
                harvested.clear()
                harvested.append(text)
                ok = _keep_policy_text(cap, text, "", source_label)
            if not ok:
                return
        # 只有达到"可做条款比对"的正文长度才算真的拿到了政策，
        # 几百字的弹窗摘要不能记成 policy_text（会让人以为已取得全文）。
        if len((cap.get("bestText") or "").strip()) >= INLINE_POLICY_MIN:
            mark(res, "policy_text")
            # ---- 趁政策页还在前台，立刻读一次地址（2026-11-09 天优家教）----
            # ★ 为什么必须在这里、而不是等首启阶段收尾再读：
            #   本轮的实测时间线是 policy_tap=158.8s → policy_text=174.9s →
            #   首启阶段 189.2s 结束。中间这段里采集器要"返回、判定着陆点"，
            #   等它收尾时政策页早就被关掉了 —— 那时再 attach 只能读到空表，
            #   报告照旧写"未记录到可访问地址"。
            #   正文刚到手这一瞬间是唯一"页面确定在前台"的时刻，读完即可。
            if (probe_urls is not None
                    and not cap.get("bestTextUrl")
                    and isinstance(script, _NoScript)
                    and not cap.get("_urlProbed")):
                cap["_urlProbed"] = True
                try:
                    _pu = probe_urls() or []
                except Exception as _pe:
                    _pu = []
                    log("[.] 补读 WebView 地址失败：%s" % str(_pe)[:80])
                if not _apply_probed_urls(cap, _pu, log) and _pu:
                    cap.setdefault("notes", []).append(
                        "临时附着读到 %d 个 WebView 地址，但没有一个标题指向隐私政策，"
                        "未作为政策链接采用" % len(_pu))

    # 未同意阶段的权限弹窗：这是"提前索权"的直接证据，必须单独留下来。
    # 用独立集合，避免与 P4 的同一权限弹窗互相顶掉（两阶段的取证意义不同）。
    perm_seen_p1: set = set()
    prev_app_texts = ""

    # ---- ★ 开局先按已知 URL 取一次政策全文 ----
    # 静态分析 / APK 内登记的政策链接在开跑前就拿到了，一次 HTTP 只要 1~2 秒。
    # 取到了就不用再在界面上点入口、下钻、一屏屏滑 —— 那一段是整轮最贵的开销
    # （每滑一次 ≈1s 等待 + 2.8s dump，外加一次 3~4s 的模型问答）。
    # 取不到也不损失什么：下面照旧走界面采集，只是多花一两秒试了一次。
    _pre_urls = list(getattr(res, "policy_urls", None) or [])
    if _pre_urls and len((cap.get("bestText") or "").strip()) < INLINE_POLICY_MIN:
        _pre = fetch_policy_by_url(_pre_urls, log,
                                   min_len=INLINE_POLICY_MIN, timeout=12)
        cap["urlFetch"] = {
            "url": _pre.get("url") or "",
            "chars": int(_pre.get("chars") or 0),
            "title": _pre.get("title") or "",
            "tried": _pre.get("tried") or [],
            "stage": "首启前",
        }
        if _pre.get("ok"):
            remember(_pre["text"], "政策全文（按链接抓取）")
            if len((cap.get("bestText") or "").strip()) >= INLINE_POLICY_MIN:
                cap["bestTextUrl"] = _pre["url"]
                cap["policyUrlFetched"] = True
                cap["outcome"] = "full"
                policy_resolved = True
                log("[+] 开局已按链接取得政策全文（%d 字），跳过入口点击与页面下钻"
                    % int(_pre.get("chars") or 0))

    while time.time() < deadline:
        if _stop_requested(should_stop):
            log("[*] 收到停止请求，提前结束首启观测")
            res.aborted = True
            res.abort_reason = "首启观测阶段被中断"
            # 这里直接 return，走不到末尾的结论结算 —— 必须自己写清楚
            # "是被中断的"，否则报告层会兜底成 not_run，读起来像没测。
            cap["outcome"] = cap.get("outcome") or "not_run"
            return
        # 黑屏先叫醒：否则下面每一轮都在对着一块黑屏找政策弹窗。
        _check_screen(serial, log, _scr)
        # ★ 先确认前台已经切到被测应用再拍「首启界面」：
        #   冷启动的前 1~3 秒前台还是桌面，此时截到的图不能叫首启界面，
        #   还会把普通截图配额吃掉（金考典 2026-10-26 那轮三张全是桌面）。
        #   只在前两轮等满 8 秒：启动即崩的 App 等不到，一直等只是白烧预算。
        _fg_ok, _fg_now = await_app_foreground(
            serial, getattr(res, "package", "") or "",
            wait_s=FIRST_SCREEN_WAIT if rounds < 2 else 1.5)
        if _fg_ok:
            res.app_foreground_seen = True
        _lab = ("首启界面 %d" % (rounds + 1)) if _fg_ok else (
            "首启界面 %d（App 未到前台）" % (rounds + 1))
        if not _fg_ok and rounds == 0:
            log("[!] 启动后 %.0fs 内仍未看到被测应用：%s——本屏不计作首启界面"
                % (FIRST_SCREEN_WAIT, _foreground_note(serial)))
        xml = observe_screen(res, _lab, serial, require_app=True)
        rounds += 1
        # 首启观测同样要报进度：这一阶段最多等 POPUP_WAIT 秒，
        # 期间百分比一动不动会被看门狗当成卡死（见 _walk_ui 里的同一条说明）。
        if on_stage is not None:
            _done = min(1.0, max(0.0,
                                 (time.time() - (deadline - max(5, wait_seconds)))
                                 / max(1.0, float(max(5, wait_seconds)))))
            try:
                on_stage("首启观测（第 %d 轮）" % rounds, 42 + int(_done * 13))
            except Exception:
                pass
        if not xml:
            time.sleep(1.2)
            continue
        note_captcha(res, xml, log, "首启阶段")

        texts = uiwalk.screen_texts(xml)
        # ---- 未同意阶段就弹出系统权限框：先取证（这本身是重要线索）----
        if _capture_perm_dialog(res, xml, serial, log, "P1",
                                pre_text=prev_app_texts, seen=perm_seen_p1):
            time.sleep(0.8)
            continue
        if texts:
            prev_app_texts = " ".join(texts)[:600]
        hit_words = [k for k in POLICY_ENTRY_STRICT if any(k in t for t in texts)]
        # 弱词兜底：入口文案千奇百怪（「协议与规则」这类标题就常出现），
        # 严格词没命中不代表屏上没有政策内容，否则会把弹窗误判成"未提示政策"。
        weak_hits = [k for k in POLICY_WORD_WEAK if any(k in t for t in texts)]
        has_policy_word = bool(hit_words or weak_hits)
        scrollables = [n for n in uiwalk.parse_all(xml) if n.scrollable]

        # ---- WebView 弹窗补判（2026-11-01）----
        # ★ 为什么需要：uniapp / 混合开发的隐私弹窗整块是 WebView，uiautomator
        #   dump 出来的节点**没有文字**，但注入脚本 hook 了 WebView，能读到 DOM。
        #   看个比赛 com.kgbs.ticket 就是这么漏的：屏幕上明明写着《隐私权政策》，
        #   dump 文本里一个字都没有 → has_policy_word=False → 形态 A/B 全不触发，
        #   入口一次没点开，报告里政策全文字段为空（前一晚同一个包拿到过 16411 字）。
        #   脚本侧的 entryTexts 当时其实已经记下了「个人信息保护指引」和整段告知语，
        #   只是没有任何一处拿它来参与判断 —— 证据在手边却没用上。
        #
        #   代价是一次 get_policy() 调用（几十毫秒），所以限次数、限间隔：
        #   首启阶段最多 4 次，两次之间至少隔 3 秒（WebView 加载需要时间）。
        if not has_policy_word and _wv_probe < 4 and time.time() - _wv_probe_at >= 3.0:
            _wv_probe += 1
            _wv_probe_at = time.time()
            try:
                _wv = _policy_via(_fresh_script())
                _wv_texts = [_wv.get("entryTexts") or []]
                _wv_texts.extend((_wv.get("texts") or {}).values())
                _wv_flat = " ".join(str(x) for x in _wv_texts if x)
                _wv_hit = [k for k in POLICY_ENTRY_STRICT if k in _wv_flat]
                if not _wv_hit:
                    _wv_hit = [k for k in POLICY_WORD_WEAK if k in _wv_flat]
                if _wv_hit:
                    has_policy_word = True
                    res.first_launch_popup = True
                    ev = ("首启界面是 WebView，界面结构树读不到文字；"
                          "从 WebView 内容中读到政策表述：%s"
                          % "、".join(_wv_hit[:4]))
                    if ev not in res.popup_evidence:
                        res.popup_evidence.append(ev)
                    log("[*] 界面结构树读不到政策字样，但 WebView 内容里有：%s"
                        % "、".join(_wv_hit[:4]))
                # WebView 里已经加载的就是政策页时，正文其实已经到手了，
                # 不必再去点入口。过长/不像政策的文本由 `_keep_policy_text`
                # 自己挡掉（类型闸门），这里不做二次判断。
                for _u, _t in (_wv.get("texts") or {}).items():
                    if _t:
                        _keep_policy_text(cap, _t, _u)
            except Exception as _e:
                res.ai_notes.append("读取 WebView 文本补判政策入口失败：%s" % _e)

        # ---- AI 看一眼这一屏（开启 policy_vision 时）----
        # 次数上限的存在是必要的：不设上限会每轮都请求模型，一次检测白等好几分钟；
        # 留 2 次是因为第一轮可能 dump 到启动页（splash），此时问模型没有意义。
        if (ai_tasks is not None and ai_calls < AI_MAX_CALLS and not policy_resolved
                and (has_policy_word or rounds >= 3)):
            v = _ai_popup_view(res, ai_tasks, serial, xml, texts, res.package, "",
                               log, stage="首启弹窗")
            ai_calls += 1
            if v is not None:
                ai_view = v
                form = str(v.get("display_form") or "")
                if v.get("policy_present"):
                    # AI 看见了政策内容 → 即使关键词没命中，也算"首启有政策提示"。
                    # 这条很关键：漏判"没提示政策"是假阳性，而假阳性会直接冤枉一个 App。
                    res.first_launch_popup = True
                    ev = ("AI 视觉判定：%s（%s）"
                          % (form or "未知", (v.get("reason") or "").strip()[:70]))
                    if ev not in res.popup_evidence:
                        res.popup_evidence.append(ev)
                if form == "notice_only":
                    # AI 认为只有告知、没有可访问的入口。这是重要发现，
                    # 但**不据此直接定性**：继续让关键词策略兜底再找一次 ——
                    # 漏判的代价（完整政策采不到、后面所有条款比对落空）
                    # 远大于多找一次的代价。
                    res.policy_capture.setdefault("notes", []).append(
                        "AI 视觉判断：首启界面仅有一段告知文本，未发现可点击的隐私政策入口"
                        "（已继续用规则策略复核一次）")
                if form == "inline_full":
                    res.policy_capture.setdefault("notes", []).append(
                        "AI 视觉判断：隐私政策正文直接内联在首启界面上")

        if has_policy_word:
            res.first_launch_popup = True
            # 严格词优先展示；只有弱词命中时也如实记录，保证证据可追溯
            shown = hit_words[:4] or ["(弱) " + k for k in weak_hits[:4]]
            ev = "首启界面出现隐私政策相关文字：" + "、".join(shown)
            if ev not in res.popup_evidence:
                res.popup_evidence.append(ev)

        # ---- 形态 A：界面本身就是政策正文 ----
        if has_policy_word and not policy_resolved and not consent_done:
            # 弹窗"告知摘要"本来就短（实测乐心只有 141 字），门槛设 120 会整个漏掉，
            # 所以这一路用 60 字；政策正文另由 INLINE_POLICY_MIN 把关，不会混淆。
            chunk = _harvest_ui_text(xml, min_len=60)
            if chunk:
                # 先按"弹窗告知摘要"归档；若长到一定规模，才同时认定为政策全文
                remember(chunk, "首启弹窗告知文本", "popup")
                if len(chunk) >= INLINE_POLICY_MIN:
                    remember(chunk, "首启弹窗内联全文", "policy")
                    cap["uiHarvested"] = True
                    log("[*] 首启界面内联政策全文（%d 字），尝试滚动读全" % len(chunk))
                    # ★ 除非 AI 在正文里看到了可点开的链接，否则到此为止。
                    # 有链接就不锁定：点开链接能拿到**正式完整条款**，
                    # 比弹窗里这段（常常只是摘要或缺章节）可靠得多。
                    # 实测赣警办弹窗里的《个人信息保护》《隐私协议》就是这种
                    # ClickableSpan 超链接 —— 结构树里看不见，只有视觉模型能指出位置。
                    if not (ai_view and ai_view.get("entry_bounds")):
                        policy_resolved = True
                else:
                    log("[*] 首启弹窗告知文本 %d 字（不足 %d 字，暂不作为政策全文）"
                        % (len(chunk), INLINE_POLICY_MIN))

            # 若正文可能被滚动截断，滚动几次补齐。
            # ★ 但 AI 已经指出"正文里有可点开的政策链接"时**不滚动**：
            #   一是这种情况我们要靠点链接去取正式完整条款，弹窗这段多半只是摘要，
            #      多收几百字意义不大；
            #   二是滚动会改变界面布局，让 AI 依据原截图给出的坐标失效 ——
            #      实测赣警办：滚动后按原坐标点下去，落到的是一段普通正文，
            #      链接根本没点开，整条「打开完整政策」的路径就此断掉。
            ai_link_ahead = bool(ai_view and ai_view.get("entry_bounds"))
            if not ai_link_ahead and (scrollables or len(chunk) < 4000):
                for si in range(3):
                    before_len = len(cap.get("bestText") or "")
                    uiwalk.scroll(serial, "down")
                    time.sleep(1.0)
                    xml2 = observe_screen(res, "政策滚动第 %d 屏" % (si + 1), serial,
                                          take_shot=(si == 0))
                    if not xml2:
                        break
                    more = _harvest_ui_text(xml2, min_len=60)
                    if more:
                        remember(more, "首启弹窗告知文本（滚动后）", "popup")
                        if len(more) >= INLINE_POLICY_MIN:
                            remember(more, "首启弹窗内联全文（滚动后）", "policy")
                    if len(cap.get("bestText") or "") <= before_len + 20:
                        break            # 没有新增内容，说明到底了
                # 滚回顶部，便于后续点同意
                for _ in range(3):
                    uiwalk.scroll(serial, "up")
                time.sleep(0.6)

        # ---- 形态 B：存在可点击的政策入口 ----
        # ★ 顺序是「结构树优先、AI 补位」，不是 AI 优先。
        #   结构树命中意味着拿到了**精确坐标**，点下去就是那个控件；
        #   AI 给的是看图估算的框，还要再过一层像素校准，误差来源多。
        #   真实事故（学丞 v1.5.6）：AI 定位《隐私协议》→ 像素校准把点往下拉了
        #   85px（落到「同意」按钮上）→ 页面直接跳到 GuideActivity，政策正文 0 字，
        #   整轮从「5 项判定 / 17 项未测」退化到「1 项判定 / 21 项未测」。
        #   同一个界面，结构树那条路一次就点中了，拿到 31061 字全文。
        #   AI 的价值仍然保留在它真正不可替代的地方：结构树看不见的超链接
        #   （ClickableSpan）、关键词覆盖不到的写法 —— 那时才轮到它上场。
        if not policy_resolved:
            tree_entry = _pick_policy_entry(xml)
            ai_entry = None if tree_entry is not None else _ai_policy_entry(ai_view)
            entry = tree_entry or ai_entry
            # ★ 第三路：结构树与 AI 都没有入口时，让 App 自己按文字布局
            #   算出"内联链接"的坐标再点（岛 2.2.0 就是这样才打开政策页的）。
            #   每轮只取一个未试过的候选，试过不中下一轮换下一个。
            _inline_entry = None
            if entry is None:
                try:
                    _inline_entry = _inline_policy_entry(
                        serial, res, cap, log,
                        lambda: _fresh_script())
                except Exception as _e:
                    res.ai_notes.append("内联链接定位失败：%s" % _e)
                if _inline_entry is not None:
                    entry = _inline_entry
            if entry is not None:
                res.first_launch_popup = True
                label = entry.label
                if label not in cap["entryTexts"]:
                    cap["entryTexts"].append(label)
                if ai_entry is not None:
                    res.ui_steps.append("AI 定位政策入口：「%s」" % label[:30])
                elif _inline_entry is not None:
                    cap["entrySource"] = "内联链接（按文字布局算坐标）"
                log("[*] 发现可点击的政策入口%s：%s"
                    % ("（AI 视觉定位）" if ai_entry is not None
                       else ("（内联链接·按文字位置）" if _inline_entry is not None else ""),
                       label[:60]))
                try:
                    _fresh_script().exports_sync.note_policy_click(label)
                except Exception:
                    pass
                cap["entryClicked"] = label
                # 入口是怎么被找到的，要写进报告：
                # 「AI 看图找到蓝色超链接」与「结构树关键词命中按钮」在证据强度上不同 ——
                # 前者能发现 ClickableSpan 这类结构树看不见的入口，后者不能。
                cap["entrySource"] = ("AI 视觉定位（看图识别界面元素）"
                                      if ai_entry is not None else "结构树关键词匹配")
                # 点击前记下前台页面，用于后面判断"这一次点击到底有没有打开新页面"。
                # 用前台 Activity 比用界面文字可靠：WebView 页面可能渲染不出结构树，
                # 而弹窗自己滚动又会让文字集合变化（假阳性）。
                _focus_before_tap = uiwalk.current_focus(serial)
                # AI 的框只保证"大概在哪一块"，先用像素把点击点校准到彩色链接文字那一行。
                # 必须用**原始截图**（不带标注框）：标注框本身也是彩色的，
                # 会把彩色像素统计污染掉，反而找不到真正的链接。
                _refined = None
                if ai_entry is not None:
                    try:
                        _shot = capture_screenshot(serial)
                        if _shot:
                            from .ai import vision as _vision
                            _box = tuple(int(v) for v in entry.bounds)
                            _refined = _vision.refine_click_point(_shot, _box)
                            if _refined:
                                log("[*] 像素校准：AI 框 %s → 彩色文字带 %s，按后者取点击点"
                                    % (_box, _refined))
                    except Exception as _e:
                        res.ai_notes.append("像素校准失败（仍按 AI 框点击）：%s" % _e)
                # ★ AI 给的框在竖直方向常有半个行高的偏差，只点中心会整场落空：
                #   真机实测（赣警办）中心落在链接下缘之外 7px，
                #   弹窗没动，428 字的告知摘要被当成"政策正文"，政策一个字都没拿到。
                _tap_info: Dict[str, Any] = {}
                x, y = _tap_entry_robust(serial, entry, log,
                                         ai_sourced=ai_entry is not None, res=res,
                                         refined_bounds=_refined, info=_tap_info)
                cap["entryTapXY"] = [x, y]
                mark(res, "policy_tap")
                # 万一 AI 把"同意"按钮当成政策入口指了出来，这里也要登记分水岭：
                # 判据用点击有效性（signal），框内所有采样点都没反应时不算同意。
                _mark_consent_after_tap(
                    res, entry, "政策入口点击", log,
                    signal=(_tap_info.get("signal") or "")
                    or ("hit" if ai_entry is None else ""),
                    screen_label="首启弹窗",
                    set_consent=lambda l: _fresh_script().exports_sync.set_consent(True, l))
                try:
                    _fresh_script().exports_sync.read_web_views()
                except Exception:
                    pass
                # ★ 不再 sleep(1.2) 等"页面稳定"再 dump —— 政策页在真机上只存在几秒，
                #   等出来的只会是已经退回去的首启弹窗。直接用点击瞬间抓到的那一屏
                #   （_tap_info["post_xml"]）；只有它为空时才补一次 dump。
                # ★ 点击到底有没有把界面带进政策页，是这一段所有后续动作的前提。
                #   判定只用点击那一刻的既有事实（signal / 前台是否切换），不额外等待：
                #     · signal=focus —— 前台页面切了，确证进入了新页面；
                #     · signal=ui    —— 前台没切但界面内容变了（可能是同页展开，
                #                       也可能是把弹窗滚动了一下），存疑；
                #     · signal=""    —— 框内采样点全都没反应，压根没点开。
                #   旧代码不看这个信号，点没点开都照样截一张图取名「隐私政策页面」、
                #   再上滑截图并取名「政策页滚动第 N 屏」—— Hi投屏 2026-10-26 那轮，
                #   报告里的"政策页滚动第 1 屏"其实就是开屏弹窗（三张图字节完全相同）。
                #   没进去政策页就没有"政策页截图"这回事，标题必须是事实。
                _tap_sig = str(_tap_info.get("signal") or "")
                _focus_pre = str(_tap_info.get("focus_before") or "") or _focus_before_tap
                _focus_post = str(_tap_info.get("focus_after") or "")
                if not _focus_post:
                    # ★ 点击那一瞬没抓到前台（2026-11-05 春雨诊所实测）：
                    #   该 App 点击后 uiautomator 慢了半拍，`focus_after` 是空的，
                    #   于是 `_focus_changed`/`_external` 全判 False →
                    #   "点了没反应"，浏览器里 826 字政策正文一个字没读到。
                    #   补一次短轮询（最多 ~1.2 秒），拿到就按正常路径处置。
                    for _ in range(4):
                        try:
                            _focus_post = uiwalk.current_focus(serial) or ""
                        except Exception:
                            _focus_post = ""
                        if _focus_post:
                            break
                        time.sleep(0.3)
                _focus_changed = (_tap_sig == "focus") or bool(
                    _focus_pre and _focus_post
                    and same_focus(_focus_pre, _focus_post) is False)
                _txt_after = len((_harvest_ui_text(_tap_info.get("post_xml") or "") or "").strip())
                # ★ 前台确实变了，但接手的可能**不是被测应用**（作业帮 2026-10-30）：
                #   点「《作业帮用户隐私政策》」后跳到了
                #   `android/com.android.internal.app.MiuiChooserActivity` ——
                #   系统在问"用哪个浏览器打开"。旧代码只看"前台变了"就判 entered，
                #   于是把选择器、以及随后的浏览器页面当成"政策页"截图留证，
                #   报告里那张"政策正文页"其实是浏览器的搜索页。
                _external = bool(_focus_changed and _focus_post
                                 and res is not None
                                 and _is_external_focus(_focus_post, res.package))
                _entered = (not _external) and bool(
                    _focus_changed
                    or (_tap_sig == "ui" and _txt_after >= 200)
                    or (_tap_sig == "unknown"))   # dump 失败：无法判断，按已点中处理
                _browser_read: Dict[str, Any] = {}
                if _external:
                    # 政策入口交给系统浏览器 / 系统组件，不等于"读不到"（2026-11-03）。
                    # 具体读取与退回逻辑见 `_read_policy_in_foreign`：
                    # 同一个处置在"定格观测"之后还有一次兜底调用（见下）。
                    _browser_read, _el = _read_policy_in_foreign(
                        serial, res, cap, log, remember, _focus_post,
                        (entry.label or ""), stop_if=should_stop)
                    deadline += _el
                    if _browser_read:
                        _focus_post = uiwalk.current_focus(serial) or _focus_post
                        _external = False
                if _external is False and _browser_read:
                    # 浏览器里已经读过（或确认打不开）：不再按"没进入新页面"处理，
                    # 下面也不该再把浏览器那一屏当"政策页截图"。
                    _entered = False
                if not _entered and not _browser_read:
                    log("[!] 政策入口点击后未进入新页面（前台仍是 %s，界面文字 %d 字）——"
                        "不截「政策页」、不滚动，避免把弹窗当成政策页留证"
                        % ((_focus_post.split("/")[-1] or "?" )[:28], _txt_after))
                    if res is not None:
                        res.errors.append(
                            "政策入口「%s」点击后未进入政策页（前台未切换、界面未变化），"
                            "未取得政策页截图" % (entry.label or "")[:30])
                elif not _entered and _browser_read and (
                        int(_browser_read.get("chars") or 0) > 0):
                    log("[.] 政策页在系统浏览器内：已读 %d 字，不再按「未进入政策页」记"
                        % int(_browser_read.get("chars") or 0))
                xml3 = observe_screen(
                    res,
                    ("隐私政策页面" if _entered
                     else ("政策页（系统浏览器内）" if _browser_read
                           else "政策入口点击后（仍为首启弹窗）")),
                    serial, xml=_tap_info.get("post_xml") or None)

                # ---- ★ 点开之后【立刻】定格：先判"这一页是什么"，再决定要不要滚动 ----
                # 真机教训（赣警办 e2e5/e2e6/e2e8/e2e9/e2e10/e2e11）：
                #   点击 → 前台 1 秒内切到 WebAndroidActivity，
                #         t+1s 结构树里就有「您所访问的页面不存在!」（受控实验已证）；
                #         但**几秒后这一页就消失了**（前台退回 SplashActivity、
                #         Frida 脚本同时失效），窗口非常窄。
                # 旧代码在这里先 sleep(2.4) 再 sleep(1.2) 才 dump，
                # 等它拿到结构树时页面早已不在 —— dump 到的是弹窗那 428 字，
                # 错误页特征一个都命中不了，outcome 退化成 notice_only（与事实相反）。
                # 修法三条，缺一不可：
                #   ① 点击后立刻轮询前台，一切换就马上抓那一屏（_tap_info["post_xml"]）；
                #   ② 用"点开瞬间"这一屏先判是不是错误页，是就**不再滚动下钻**（保住现场）；
                #   ③ 只有在既没命中错误页、正文又不够长时才补读一屏。
                # 另外 uiautomator dump 本身要 ~2.8s，所以"抓得早"比"抓得全"更重要。
                # ---- ★ WebView 读不出正文 ≠ 页面是空的（2026-11-08 小包搜题）----
                # 不注入时拿不到 WebView.getUrl / 正文，结构树里也只有一个空的
                # `android.webkit.WebView` 节点 —— 界面文字 0 条、0 字，
                # 而屏幕上明明是整页《隐私政策》。点一下页面让 WebView 建立
                # 无障碍节点树，再读就有 7136 字（已实测）。
                # 放在"定格观测"之前：后面所有判读（错误页 / 正文长度 / 下钻）
                # 都基于这个 xml3，越早补越好。
                if _entered and webview_text_blind(xml3 or ""):
                    _woke, _woke_how = wake_webview_text(serial, xml3 or "", log,
                                                         package=res.package)
                    if _woke and _woke != (xml3 or ""):
                        _woke_chars = len("".join(
                            uiwalk.screen_texts(_woke) or "").strip())
                        if _woke_chars >= WEBVIEW_WAKE_MIN_TEXT:
                            xml3 = _woke
                            cap["webviewWake"] = {"chars": _woke_chars,
                                                  "at": "政策页",
                                                  "how": _woke_how}
                            cap.setdefault("notes", []).append(
                                "政策页在 WebView 里：首次读取结构树为空，%s后读到"
                                " %d 字"
                                % ("页面自行渲染" if _woke_how == "settled"
                                   else "点击页面唤醒无障碍树",
                                   _woke_chars))
                _open_screens = [xml3 or ""]
                _probe = policy_open_probe(_open_screens, cap.get("bestText") or "")
                # ---- ★ 错误页要复核一次再落结论（2026-11-08 小包搜题 land36）----
                # 点开瞬间 WebView 往往还没把正文拉下来，会先渲染「网页无法打开」，
                # 一两秒后正文才出来。只凭第一眼就写"应用把政策交给了一个打不开的
                # 地址"，是把加载时序当成了应用的问题 —— 误报也是假话。
                # 复核这一次同时能反向加强证据：真的打不开，两屏都会命中同一特征。
                #
                # 但复核之前先问一句"测试机有网吗"（2026-11-09）：设备处于飞行
                # 模式时任何页面都会显示「网页无法打开」，那不是应用的问题。
                if _entered and _probe.get("errHit") and not device_online(serial):
                    cap["deviceOffline"] = True
                    log("[!] 政策页显示「%s」，但测试机当前**没有网络**"
                        "（飞行模式/未联网）：按环境原因处理，不记作应用的问题"
                        % (_probe.get("errHit") or ""))
                    res.errors.append(
                        "测试机在采集期间无网络（飞行模式或未连接 Wi-Fi/数据），"
                        "政策页加载失败属环境原因；本轮**未**将其记作"
                        "「应用提供的政策地址无法打开」")
                    cap.setdefault("notes", []).append(
                        "政策页打开后显示「%s」，但测试机当时没有网络连接，"
                        "该现象按环境原因记录，不作为「应用未提供可查阅的政策」的依据。"
                        % (_probe.get("errHit") or ""))
                    _probe["errHit"] = ""      # 清掉，后面不再按错误页定论
                if _entered and _probe.get("errHit"):
                    time.sleep(1.5)
                    _confirm = observe_screen(res, "隐私政策页面（错误页复核）", serial,
                                              take_shot=False)
                    if _confirm:
                        if webview_text_blind(_confirm):
                            _confirm, _ = wake_webview_text(serial, _confirm, log,
                                                            package=res.package)
                        _c2 = policy_page_text(_confirm)
                        _p2 = policy_open_probe([_confirm], cap.get("bestText") or "")
                        cap["errorPageRecheck"] = {
                            "firstHit": _probe.get("errHit") or "",
                            "againHit": _p2.get("errHit") or "",
                            "chars": len((_c2 or "").strip()),
                        }
                        if _c2 and not _p2.get("errHit") \
                                and len(_c2.strip()) >= INLINE_POLICY_MIN:
                            log("[*] 错误页复核：正文已加载（%d 字），不以「%s」定论"
                                % (len(_c2.strip()), _probe.get("errHit") or ""))
                            _open_screens.append(_confirm)
                            _probe = _p2
                            xml3 = _confirm
                        else:
                            log("[.] 错误页复核：%d 秒后仍为「%s」（%d 字），按错误页记录"
                                % (2, (_p2.get("errHit") or "非错误页"),
                                   len((_c2 or "").strip())))
                _reread = None
                if _entered and not _probe.get("errHit") and not (
                        len((cap.get("bestText") or "").strip()) >= INLINE_POLICY_MIN):
                    # 还没命中错误页、正文也还不够长 → 补读一屏：
                    # 404/SPA 页的错误文案常要 2 秒才渲染出来（见 policy_open_probe）；
                    # 已经确认是错误页时就不再补读，免得把界面带离现场。
                    # 没进入政策页（_entered=False）时不补读：多读一屏也只是
                    # 多一张弹出窗截图，还会让界面在弹窗上多滚一次。
                    time.sleep(0.6)
                    _reread = observe_screen(res, "隐私政策页面（补读）", serial,
                                             take_shot=False)
                    if _reread:
                        _open_screens.append(_reread)
                        _probe = policy_open_probe(_open_screens, cap.get("bestText") or "")
                _open_xml = _probe.get("xml") or (xml3 or "")
                _open_err = _probe.get("errHit") or ""
                # 点开瞬间的前台页面：优先用点击时抓到的（最贴近"那一刻"），
                # 读不到时才当场补一次 —— 晚了页面可能已经退回去了。
                _open_focus = _tap_info.get("focus_after") or ""
                if not _open_focus:
                    try:
                        _open_focus = uiwalk.current_focus(serial) or ""
                    except Exception:
                        pass
                # 地址也要在这一刻抓：晚一步页面被滚走/回退，URL 列表就不再含政策页。
                try:
                    for _u in (_fresh_script().exports_sync.current_urls() or []):
                        if (_u and _u.startswith("http")
                                and _u not in [d.get("url") for d in cap["urls"]]):
                            cap["urls"].append({"url": _u, "from": "WebView.getUrl"})
                except Exception:
                    pass
                # ★ 政策页由 App 自己的 Activity（如 BrowserActivity）承载时，
                #   WebView.getUrl() 可能拿不到（页面不是标准 WebView 或已销毁），
                #   但 URL 就在这个 Activity 的 intent 里 —— 岛 2.2.0 实测：
                #   extra "url" = https://www.iiisland.com/privacy?show=app&t=...
                #   这条同时是"政策链接"本身，报告里要能给出可直接复核的地址。
                try:
                    for _u in (_fresh_script().exports_sync.activity_url() or []):
                        if (_u and _u.startswith("http")
                                and _u not in [d.get("url") for d in cap["urls"]]):
                            cap["urls"].append({"url": _u, "from": "Activity.getIntent"})
                except Exception:
                    pass
                cap["openSnapshot"] = {
                    "errHit": _open_err,
                    "textLen": _probe.get("textLen") or 0,
                    "focus": _open_focus,
                    # 点击之前那一屏（弹窗所在界面）。收尾时按它把界面退回去：
                    # 政策页开着不关，着陆阶段会把它当成"启动/加载页"放弃
                    # （天优家教 2026-11-09 实测）。
                    "focusBefore": _focus_before_tap,
                    "screenIndex": _probe.get("screenIndex"),
                    # 点没点开政策页：这一条决定报告里有没有"政策页截图"，
                    # 也决定复现步骤能不能写"政策页打开并取得正文"。
                    "entered": bool(_entered),
                    "tapSignal": _tap_sig,
                    "focusChanged": bool(_focus_changed),
                }
                log("[.] 定格观测：点击前前台 %s → 点击后前台 %s；"
                    "首屏结构树 %s（界面文字 %d 条 / 长文本 %d 字）；补读 %s；错误页特征 %s"
                    % ((_focus_before_tap.split("/")[-1] or "?")[:30],
                       (_open_focus.split("/")[-1] or "?")[:30],
                       "有" if (xml3 or "") else "**空**",
                       len(uiwalk.screen_texts(xml3)) if xml3 else 0,
                       len((_harvest_ui_text(xml3 or "") or "").strip()),
                       "有" if _reread else "未补读",
                       ("命中「%s」" % _open_err) if _open_err else "未命中"))
                if _open_err:
                    log("[!] 政策入口点开即为错误页（命中「%s」），跳过滚动与下钻以保留现场"
                        % _open_err)

                # ---- ★ 兜底：点击瞬间没抓到前台，但此刻前台已经在外部浏览器 ----
                # 春雨诊所 2026-11-05 走的就是这条路：`focus_after` 为空 →
                # 上面 `_external` 判 False（"点了没反应"），直到这里才看到
                # 前台是 com.android.browser。同一个处置再做一次，幂等：
                # `_browser_read` 非空就不会重复读。不补这一步，浏览器里
                # 那 826 字政策正文一辈子读不到 —— 报告照旧写"未取得条款"。
                if (not _browser_read and _open_focus and res is not None
                        and _is_external_focus(_open_focus, res.package)):
                    _browser_read, _el = _read_policy_in_foreign(
                        serial, res, cap, log, remember, _open_focus,
                        (entry.label or ""), stop_if=should_stop)
                    deadline += _el
                    if _browser_read:
                        # 浏览器那一屏不是"应用内政策页"：不滚动、不把它当政策页截图。
                        _entered = False
                        try:
                            _open_focus = uiwalk.current_focus(serial) or _open_focus
                        except Exception:
                            pass

                # ---- ★ 有 URL 就直接按 URL 取全文，不再一屏屏上滑 ----
                # 用户明确要求（2026-10-21）：优先拿到政策 URL 直接取全文，
                # 只有在拿不到 URL（或取回来不像政策）时才退化成滑动截图阅读。
                # 这里已经拿到了「刚点开的那一屏」的 WebView 地址，是最高质量的候选。
                _url_ok = False
                if not _open_err:
                    _cands: List[Any] = []
                    for _d in (cap.get("urls") or []):
                        _u = (_d or {}).get("url") if isinstance(_d, dict) else _d
                        if _u:
                            _cands.append(_u)
                    _cands.extend(getattr(res, "policy_urls", None) or [])
                    if _cands:
                        _by_url = fetch_policy_by_url(
                            _cands, log, min_len=INLINE_POLICY_MIN, timeout=12)
                        cap["urlFetch"] = {
                            "url": _by_url.get("url") or "",
                            "chars": int(_by_url.get("chars") or 0),
                            "title": _by_url.get("title") or "",
                            "tried": _by_url.get("tried") or [],
                        }
                        if _by_url.get("ok"):
                            _before_len = len((cap.get("bestText") or "").strip())
                            remember(_by_url["text"], "政策全文（按链接抓取）")
                            # ★ 只有真的被采纳（类型闸门过了、长度达标）才算拿到。
                            #   抓到了但不采纳却照样跳过滚动，等于白丢一次取证机会。
                            _url_ok = (len((cap.get("bestText") or "").strip())
                                       >= INLINE_POLICY_MIN
                                       and len((cap.get("bestText") or "").strip())
                                       > _before_len)
                            if _url_ok:
                                cap["bestTextUrl"] = _by_url["url"]
                                cap["policyUrlFetched"] = True
                                log("[+] 政策已按链接取得（%d 字），"
                                    "跳过滚动与下钻，把时间还给遍历" % _by_url["chars"])
                            else:
                                log("[.] 链接取回 %d 字但未被采纳（已有更可靠的正文），"
                                    "继续按界面采集" % int(_by_url.get("chars") or 0))

                # ---- 目录页下钻 ----
                # 不少 App（滴滴出行即是）的「服务协议及个人信息处理规则」点进去只是一个
                # **目录页**，真正正文要再点一层：目录里列着「个人信息处理规则 /
                # 软件使用协议 / 网约车乘客用户服务协议 / 儿童个人信息处理规则」。
                # 只采目录页 = 政策根本没拿到，后面所有条款比对都会落空。
                # 策略：采当前页 → 若正文仍不够长，就把它当目录页挑一个入口继续下钻，
                # 最多 3 层；并记下"离首启弹窗有几层"，收尾时按层数逐级 BACK 回去。
                # ★ 收割要用「最好的一屏」，不是「第一屏」（携船网 2026-10-30）：
                #   `_probe["xml"]` 可能是补读的那一屏 —— 首屏往往还在加载
                #   （WebView 白屏/骨架），文字在第 2 屏才渲染出来。旧代码固定拿
                #   xml3（首屏）去收割，于是探针明明量到 775 字、正文却一个字没进
                #   bestText，结论退化成"未取得政策条款"。两处读同一份数据即可。
                cur = _open_xml or xml3
                backs_to_popup = 1
                _drill_started = time.time()
                _page_gone = False
                # ★ 安装包里已经躺着一份**同一份**政策全文时，界面侧只留证据，
                #   不再一屏屏滑动去"读"（金考典 2026-10-28 用户意见）：
                #   那份政策是内嵌在 APK 里的 assets/privacy.htm，界面上
                #   一轮轮上滑只读出 844 字，而安装包里是完整的 8422 字。
                #   滚动是**最后没办法的办法**，不是默认动作。
                _builtin_same = False
                if _builtin_text:
                    log("[*] 安装包内已有同一份政策全文（%d 字），界面侧只取证据截图，"
                        "不再逐屏滑动读取" % len(_builtin_text))
                # ★ 已按 URL 取到全文 → 一层都不滚、一层都不钻。
                #   界面上逐屏滑读政策是最耗时的一段，能用一次 HTTP 拿到完整全文
                #   却还要滑，等于把遍历预算白扔在"读同一篇文档"上。
                if _url_ok:
                    cur = None
                # 已确认是错误页时一层都不下钻：滚动会把界面带离错误页，
                # 让刚拿到的证据在最终判定时消失（这正是前三轮 outcome 错判的根因）。
                # ★ 没进入政策页时也一层都不滚：在首启弹窗上上滑不会得到任何政策
                #   正文，只会把弹窗滚走、把界面弄乱，还会产出标题为
                #   「政策页滚动第 N 屏」的假证据（Hi投屏 2026-10-26 实测）。
                if not _entered:
                    cur = None
                for depth in range(0 if (_open_err or _url_ok or not _entered) else 3):
                    if not cur or _page_gone:
                        break
                    # ★ 用 policy_page_text：WebView 把正文拆成上百个短节点时，
                    #   "取最长的三段"会丢掉开头那句「隐私政策/本政策仅适用于…」，
                    #   类型闸门随即判 False，整页正文一个字节都进不来。
                    more = policy_page_text(cur)
                    if more:
                        harvested.append(more)
                        remember(more, "政策页面文本" if depth == 0 else "政策正文页文本")
                        # 界面这一页与安装包那份是同一份文档 → 不必再滑。
                        # 判据只看开头 60 字（归一化后），不依赖长度：
                        # 界面上永远读不全，比长度必然判成"不是同一份"。
                        if _builtin_text and _same_doc_head(more, _builtin_text):
                            _builtin_same = True
                            if depth == 0:
                                cap.setdefault("notes", []).append(
                                    "界面打开的政策页与安装包内置文档为同一份"
                                    "（开头一致）；正文以安装包内 %s 的完整全文"
                                    "（%d 字）为准，界面侧只保留截图与已读到的 %d 字，"
                                    "未再逐屏滑动读取"
                                    % (_builtin_path or "文档", len(_builtin_text),
                                       len(more)))
                            break
                    for si in range(4 if depth == 0 else 8):
                        # ★ 滚动之前先确认「我们还在那一页上」。
                        #   真机上出现过：政策页是 WebView，一次上滑被 WebView 当成
                        #   **返回导航**，页面被关掉、App 回到首启弹窗 —— 此后继续滚
                        #   只是把弹窗滚走，而刚打开时看到的页面内容再也回不来，
                        #   结论就会从「打开了 X 页」退化成「什么也没打开」。
                        _now_focus = uiwalk.current_focus(serial)
                        # ★ 用 same_focus 而不是 != ：两条采集路径的前台串写法不同
                        #   （`pkg/.Rel` vs `pkg/pkg.Full`），直接比较会把政策页自己
                        #   判成"已关闭"，导致一次都不滚动。详见 same_focus 的注释。
                        if (same_focus(_open_focus, _now_focus) is False
                                and _open_focus and _now_focus):
                            log("[!] 政策页已被关闭（前台变为 %s），停止滚动以免把界面滚离现场"
                                % _now_focus.split("/")[-1])
                            _page_gone = True
                            break
                        before_len = len(cap.get("bestText") or "")
                        uiwalk.scroll(serial, "down")
                        time.sleep(1.0)
                        x4 = observe_screen(res, "政策页滚动第 %d 屏" % (si + 1), serial,
                                            take_shot=(si == 0))
                        if not x4:
                            break
                        m2 = policy_page_text(x4)
                        if m2:
                            harvested.append(m2)
                            remember(m2, "政策页面文本（滚动后）" if depth == 0
                                     else "政策正文页文本（滚动后）")
                        if len(cap.get("bestText") or "") <= before_len + 20:
                            break
                    if len((cap.get("bestText") or "").strip()) >= INLINE_POLICY_MIN:
                        break          # 正文够长，收工
                    if _builtin_same:
                        break          # 已有安装包全文，不再下钻/滚动

                    # ---- 决定要不要继续下钻 ----
                    # 老策略是「正文不够长就再点一个入口」，两个场景会做错：
                    #   · 登录墙：点进去先要登录，页面当然短 → 继续在登录页上找"入口"，
                    #     很容易点到登录/注册按钮，把采集带偏；
                    #   · 目录页：不区分主次，可能先点进「软件使用协议」这种次级文档。
                    # 现在先让 AI 判页面性质，再由它指定该点哪一个。
                    fresh = observe_screen(res, "政策页入口定位", serial, take_shot=False)
                    fresh_xml = fresh or cur
                    ai_dec = _ai_decide_drill(res, ai_tasks, serial, fresh_xml,
                                              cap.get("entryClicked") or "", log)
                    for lk in (ai_dec.get("links") or []):
                        lt = str(lk.get("text") or "").strip()
                        if lt and lt not in cap.setdefault("pageLinks", []):
                            cap["pageLinks"].append(lt)
                    kind = ai_dec.get("page_kind") or ""
                    if kind:
                        # 记到 cap 上：报告要能直接说明「模型对这一页的定性」，
                        # 否则"为什么停止下钻"在报告里无从解释。
                        cap["pageKind"] = {
                            "full_text": "政策正文",
                            "document_index": "文档目录页（需再下钻）",
                            "login_wall": "登录墙（要求先登录）",
                            "captcha": "人机/短信验证页",
                            "other": "其它（首页/错误页等）",
                        }.get(kind, kind)
                    if kind == "full_text":
                        log("[*] AI 判定本页已是政策正文，停止下钻")
                        break
                    if kind in ("login_wall", "captcha"):
                        log("[!] AI 判定本页为%s，停止下钻并记录待人工确认"
                            % ("登录墙" if kind == "login_wall" else "验证码页"))
                        break

                    sub = ai_dec.get("target") or _pick_policy_entry(fresh_xml)
                    if sub is None:
                        break
                    if ai_dec.get("target") is not None:
                        log("[*] AI 指定下钻目标：%s（%s）"
                            % (sub.label[:40], (ai_dec.get("target_why") or "")[:40]))
                    else:
                        log("[*] 政策页疑似目录页，继续点击二级入口：%s" % sub.label[:50])
                    if sub.label not in cap["entryTexts"]:
                        cap["entryTexts"].append(sub.label)
                    cap["entryClicked"] = "%s → %s" % (cap["entryClicked"], sub.label)
                    _drill_tap: Dict[str, Any] = {}
                    sx, sy = _tap_entry_robust(
                        serial, sub, log,
                        ai_sourced=ai_dec.get("target") is not None, res=res,
                        info=_drill_tap)
                    # ★ 政策下钻这条路也点到过「同意」—— 必须登记分水岭。
                    #   真机实测（以观书法 mbsf6）：AI 把「同意并继续」当成
                    #   打开政策的入口点了下去（它的理由写着"这是同意弹窗，
                    #   需先点击同意才能进入 App 找到真正的隐私政策"），
                    #   界面也确实变了，但这条点击走的是下钻路径，
                    #   四条登记点一个都没走到 → consent_given 始终 False、
                    #   50 条事件全标"同意前"、P3 报"未捕获到同意事件"。
                    _mark_consent_after_tap(
                        res, sub, "政策下钻点击（AI 指定目标）", log,
                        signal=(_drill_tap.get("signal") or "hit"),
                        screen_label="首启弹窗",
                        set_consent=lambda l: _fresh_script().exports_sync.set_consent(True, l))
                    try:
                        _fresh_script().exports_sync.read_web_views()
                    except Exception:
                        pass
                    time.sleep(1.2)
                    nxt = observe_screen(res, "政策正文页 %d" % (depth + 1), serial)
                    if not nxt:
                        break
                    cur = nxt
                    backs_to_popup += 1
                try:
                    urls = _fresh_script().exports_sync.current_urls() or []
                    for u in urls:
                        if u and u.startswith("http") and u not in [
                                d.get("url") for d in cap["urls"]]:
                            cap["urls"].append({"url": u, "from": "WebView.getUrl"})
                except Exception:
                    pass
                # ---- 判定：这一次点击到底有没有拿到政策条款 ----
                # 三种结果必须分开记，否则报告会把「打开失败」读成「政策已获取」。
                # 真机教训（赣警办）：入口指向的 /webchat/#/privacy 返回 404，
                # WebView 里显示的是该站自己的错误页；若不加区分，
                # 报告会写「政策已公开」，而事实是 App 根本没提供可查阅的条款。
                got = (cap.get("bestText") or "").strip()
                notice = (cap.get("noticeText") or "").strip()

                # ★ 错误页的文字**不在** WebView 回读结果里：
                #   那个失效链接是 SPA 路由，WebView 侧取不到正文（got 为空），
                #   但界面上明明白白写着「您所访问的页面不存在!」——
                #   这段文字只能从 **UI 结构树**拿到。
                #   真机实测（赣警办 e2e5）：只拿 got 去判，命中不了任何特征，
                #   结论就退化成"仅取得弹窗告知摘要 0 字"，与事实不符。
                # 下钻过的话，最终停在哪一页要看 cur（逐层更新过），
                # 否则只看第一层，会把"下钻后落到错误页"漏掉。
                # 但**点开瞬间就抓到错误页**时，cur 已被滚动/下钻带离现场，
                # 这时候必须以那一刻的快照为准（否则又回到 e2e5~e2e8 的错判）。
                _last_xml = (_open_xml if (_open_err or _page_gone) else (cur or xml3))
                err_hit = _open_err or detect_policy_error_page(got, _last_xml or "")
                if _page_gone and not _open_err:
                    # ★ 「页面被关掉」≠「正文没拿到」。
                    #   这里原本写死"实际内容未被完整采集，需人工复核"，于是简小知那轮
                    #   报告一边写「已取得完整政策条款 / 条款正文长度 31955 字」，
                    #   一边又写「该页的实际内容未被完整采集」—— 自相矛盾。
                    #   完不完整要看**真正拿到多少字**，不是看页面有没有被滚走。
                    _gone_focus = (uiwalk.current_focus(serial).split("/")[-1]
                                   or "上一级")
                    _got_len = len((got or "").strip())
                    if _got_len >= INLINE_POLICY_MIN:
                        cap.setdefault("notes", []).append(
                            "政策页在滚动过程中被关闭（前台页面回到 %s）—— "
                            "可能是页面自身把上滑手势当作返回导航。"
                            "关闭前已取得 %d 字条款正文，可支撑条款比对。"
                            % (_gone_focus, _got_len))
                    else:
                        cap.setdefault("notes", []).append(
                            "政策页在滚动过程中被关闭（前台页面回到 %s）—— "
                            "可能是页面自身把上滑手势当作返回导航。"
                            "该页实际仅采集到 %d 字，正文可能不完整，需人工复核。"
                            % (_gone_focus, _got_len))

                # 点击后界面有没有真的换页：用来区分
                #   「点了没反应、还停在首启弹窗」（→ 连页面都没打开）
                #   与「打开了新页面、但取不到条款文本」（→ 页面打开了但拿不到内容）
                # 判据与点击环节保持一致（前台页面优先，界面内容次之），
                # 免得"点的时候算命中、判的时候算没跳转"这种自相矛盾的结论。
                navigated = False
                try:
                    navigated = uiwalk.page_switched(
                        _focus_before_tap, uiwalk.current_focus(serial),
                        uiwalk.screen_fingerprint(xml or ""),
                        uiwalk.screen_fingerprint(_last_xml or ""))
                except Exception:
                    pass
                # 兜底：终点那一屏可能已经滚回弹窗，但"点开瞬间"确实换了前台页面。
                # 这时也要算跳转过（否则「打开了错误页」会被写成「点击没生效」）。
                if not navigated and _open_focus:
                    try:
                        navigated = uiwalk.page_switched(_focus_before_tap, _open_focus,
                                                         "", "")
                    except Exception:
                        pass

                page_url = ""
                for d in (cap.get("urls") or []):
                    u = str(d.get("url") or "")
                    if "http" in u and "appversion" not in u:
                        page_url = u
                        break
                cap["outcome"] = judge_policy_outcome(got, err_hit, navigated)
                # ---- 浏览器内读取的结果要反映到结论上（2026-11-03）----
                # 旧口径只有"应用内取到 / 取不到"两档，于是"政策页在浏览器里、
                # 我们逐屏读了 800 字"会被写成「未取得条款：点击入口后没有政策文本」，
                # 和"点了没反应"混为一谈 —— 复核员据此会以为入口是坏的。
                _er = cap.get("externalRead") or {}
                if _er:
                    _erc = int(_er.get("chars") or 0)
                    if _er.get("err") and cap["outcome"] in ("no_text", "notice_only"):
                        cap["outcome"] = "error_page"
                        cap["errorPage"] = cap.get("errorPage") or _er.get("err")
                        cap.setdefault("notes", []).append(
                            "政策页由系统浏览器打开，但页面打不开（%s）；"
                            "已跳过该页，未取得条款正文。" % (_er.get("err"),))
                    elif _erc >= INLINE_POLICY_MIN:
                        # ★ 读到多少字 ≠ 这段文字能当政策正文（2026-11-05 高途实测）：
                        #   浏览器里逐屏读出 7815 字，但这 7815 字**没有通过**
                        #   「像隐私政策」的闸门（是浏览器首页/搜索页/跳转提示），
                        #   bestText 仍是 0 字。旧代码只看字数就写 outcome="full" ——
                        #   报告于是变成"已取得政策全文"而正文一个字都没有。
                        #   这类"结论说有、证据是空"的错最难发现，必须按 bestText 定。
                        if len((cap.get("bestText") or "").strip()) >= INLINE_POLICY_MIN:
                            cap["outcome"] = "full"
                            cap.setdefault("notes", []).append(
                                "政策页不在应用内：入口点击后由系统浏览器打开，"
                                "已在浏览器界面中逐屏读取到 %d 字条款正文（%d 屏）。"
                                % (_erc, int(_er.get("screens") or 0)))
                        else:
                            cap["outcome"] = "external_unverified"
                            _smp = str(_er.get("sample") or "")[:160]
                            cap.setdefault("notes", []).append(
                                "政策页不在应用内：入口点击后由系统浏览器打开，"
                                "浏览器界面里读到 %d 字（%d 屏），但这段文字没有通过"
                                "「像隐私政策」的判据（页面可能是浏览器首页、搜索结果或"
                                "跳转提示），未作为政策正文使用；需人工在浏览器中核对。%s"
                                % (_erc, int(_er.get("screens") or 0),
                                   ("读到内容的开头：「%s…」" % _smp) if _smp else ""))
                    elif _erc > 0 and cap["outcome"] in ("no_text", "notice_only"):
                        cap["outcome"] = "external_partial"
                        cap.setdefault("notes", []).append(
                            "政策页不在应用内：入口点击后由系统浏览器打开，"
                            "本次在浏览器界面中逐屏读取到 %d 字（%d 屏），"
                            "未达完整条款的长度，条款比对只能覆盖已读到的部分。"
                            % (_erc, int(_er.get("screens") or 0)))
                if cap["outcome"] == "error_page":
                    # ★ "页面打不开"必须分清是**应用的链接坏了**还是**测试机没网**
                    #   （2026-11-10 EV投屏/电视投屏/易投屏/中医针灸）：那一批连跑
                    #   15 单，从第 10 单起 Wi-Fi 掉了，后 8 单一律 "网页无法打开"。
                    #   如果照旧记成 error_page，报告会把"测试机断网"写成"应用提供
                    #   的政策地址无法访问"，还据此判成问题项 —— 这是最严重的一类误报。
                    #   离线时结论单列 ``offline_unverified``：既不算通过，也不算问题，
                    #   明确写"本轮无法判断"，要求联网重跑。
                    _off_now = False
                    try:
                        _off_now = not device_online(serial)
                    except Exception:
                        _off_now = bool(cap.get("deviceOffline"))
                    if _off_now or cap.get("deviceOffline"):
                        cap["deviceOffline"] = True
                        cap["pageErrorRaw"] = err_hit
                        cap["outcome"] = "offline_unverified"
                        cap.setdefault("notes", []).append(
                            "点击政策入口后页面显示「%s」，但测试机当时没有网络连接 ——"
                            "该现象按环境原因记录，**不能**据此判断应用的政策地址是否可用。"
                            "需要联网后重跑本应用才能得出结论。" % (err_hit or "错误页"))
                        if not cap.get("_offlineNoted"):
                            cap["_offlineNoted"] = True
                            res.errors.append(
                                "测试机在采集期间无网络（飞行模式或未连接 Wi-Fi/数据），"
                                "政策页加载失败属环境原因；本轮**未**将其记作"
                                "「应用提供的政策地址无法打开」，该结论需联网重跑后才成立")
                        err_hit = ""
                    cap["errorPage"] = err_hit
                    if cap["outcome"] == "offline_unverified":
                        log("[!] 政策页显示「%s」，但测试机无网络：本项按环境原因处理，"
                            "不下「应用政策地址不可用」的结论（需联网重跑）"
                            % (cap.get("pageErrorRaw") or "错误页"))
                    else:
                        # 前台 Activity 变化是"入口确实被点开、且跳转到了承载政策的
                        # 页面"的硬证据：它把「点击没生效（还在弹窗上）」与「打开了
                        # 页面但页面是死的」这两件性质完全不同的事区分开 ——
                        # 后者才是 App 的责任。
                        _focus_note = ""
                        if (_open_focus and _focus_before_tap
                                and not same_focus(_open_focus, _focus_before_tap)):
                            _focus_note = "；点击后前台页面由 %s 切换到 %s" % (
                                _focus_before_tap.split("/")[-1], _open_focus.split("/")[-1])
                        cap["notes"].append(
                            "点击政策入口后打开的是**错误页**（命中特征「%s」），"
                            "未能获取政策条款%s。%s"
                            % (err_hit, ("；实际加载地址：%s" % page_url) if page_url else "",
                               ("该页由系统浏览器打开，界面本身提示「%s」——"
                                "应用把政策交给了一个打不开的地址，用户实际也无法查阅。"
                                % err_hit)
                               if (cap.get("externalRead") or {}).get("err")
                               else "该入口指向的链接已失效 —— "
                                    "这是「未提供可查阅的收集使用规则」的重要证据。")
                            + _focus_note)
                        log("[!] 政策入口打开的是错误页（%s），政策条款未获取%s"
                            % (err_hit, ("：%s" % page_url) if page_url else ""))
                elif cap["outcome"] == "full":
                    pass
                elif cap["outcome"] == "offline_unverified":
                    # 已在上面的 error_page 分支里写过 note 与错误说明，这里不重复。
                    pass
                elif cap["outcome"] == "no_text":
                    cap["notes"].append(
                        "政策入口已点击且界面发生跳转（%s），但未能从该页提取到政策条款文本"
                        "（累计 %d 字）。可能原因：页面内容由 JS 动态渲染、"
                        "被反自动化拦截、或加载失败。需人工复核该页实际呈现的内容。"
                        % ("已捕获地址：%s" % page_url if page_url else "地址未捕获", len(got)))
                    log("[!] 政策入口已跳转新页面，但取不到条款文本（%d 字）" % len(got))
                else:
                    cap["notes"].append(
                        "政策入口点击后界面未发生跳转（仍停留在首启弹窗），"
                        "累计正文仅 %d 字，与首启弹窗的告知摘要（%d 字）相当，"
                        "判断**未取得完整政策条款**。" % (len(got), len(notice)))
                    log("[!] 点击政策入口后界面未跳转、正文仅 %d 字，未取得完整政策条款" % len(got))
                # ★ 浏览器那一支已经自己退回来了，这里不能再按一次返回 ——
                #   多按一下会把首启弹窗按掉（后面还要在它上面点同意）。
                for _ in range(0 if _browser_read else max(1, backs_to_popup)):
                    uiwalk.back(serial)
                    time.sleep(1.0)
                # 读政策页花掉的时间不该挤占「等同意按钮」的时间窗：
                # 否则下钻一深，while 条件立刻为假，循环直接退出，
                # 同意按钮根本没机会被点（实测就因此漏掉了滴滴的同意动作）。
                deadline += max(0.0, time.time() - _drill_started)
                observe_screen(res, "返回首启界面", serial, take_shot=False)
                policy_resolved = True
                # ★ 下钻一结束就地尝试同意。本分支末尾是 continue，下一轮还会再进来，
                #   循环末尾的同意逻辑**永远到不了** —— 自设捏脸实测两轮都因此漏掉同意。
                if not consent_done and not consent_only:
                    if _consent_tap_once(
                            res, serial, cap, policy_resolved, log,
                            set_consent=lambda lab: _fresh_script().exports_sync.set_consent(True, lab),
                            ai_tasks=ai_tasks):
                        consent_done = True
                continue
            elif has_policy_word and (cap.get("bestText") or "").strip():
                # 有政策文字、界面上却没有可点击入口 —— 有两种可能，必须分开：
                #   ① 正文确实很长 → 内联全文形态，采到了，标记完成
                #   ② 只有一段短告知 → 那是"弹窗告知摘要"，不是政策全文。
                #      此时**不能**标记 policy_resolved，否则后面不会再尝试打开政策页，
                #      报告会误以为"政策已获取"，条款比对全部落空。
                inline_len = len((cap.get("bestText") or "").strip())
                if inline_len >= INLINE_POLICY_MIN:
                    ai_link = bool(ai_view and ai_view.get("entry_bounds"))
                    cap["notes"].append(
                        "隐私政策以内联全文形式呈现（%d 字）" % inline_len
                        + ("；AI 视觉在正文中定位到可点击的政策超链接，"
                           "已尝试点开获取正式完整条款"
                           if ai_link else
                           "；界面上未发现可点击的跳转入口"
                           "（部分 App 用 ClickableSpan 在段落中插入超链接，"
                           "该类富文本在 uiautomator 结构导出中不是独立节点，"
                           "旧策略无法点击；启用视觉识别后可定位并点开）"))
                    # 只有 AI 没发现链接时才认定"到此为止"：有链接就交给形态 B
                    # 点开 —— 正式完整条款优先于弹窗里的内联文本。
                    if not ai_link:
                        policy_resolved = True
                        cap["outcome"] = "full_inline"


        # ---- 形态 C：等不到政策 → 也允许先同意，避免卡死 ----
        # 1 档例外：它的口径就是"同意前"，点掉同意等于把这一档测废了。
        # ★ 同意之前最后一次尝试打开政策（2026-11-08 用户明确要求）：
        #   "确保在同意隐私政策前，一定要通过 App 的实际页面访问到隐私政策"。
        #   窗口里没取到（入口藏在正文里、弹窗晚出现、加固壳启动慢）时，
        #   不许直接点同意 —— 先把政策点开、读正文、拿链接，再回来同意。
        # ★ 1 档也要走这一步（2026-11-11 学习通）：这一档不点同意，所以这里
        #   不存在"替用户同意"的风险；而它的整个目标就是拿到政策正文 ——
        #   窗口里没取到就收工，等于 1 档什么都没测。真机现场：加固壳冷启动
        #   自杀、重新拉起后弹窗才出现，窗口按秒走完，随后直接写了
        #   "未观测到政策入口"，可弹窗就在屏上。
        if (not consent_done and not policy_resolved
                and not _policy_evidence_ok(res)):
            try:
                if grab_policy_once(serial, res, log, _fresh_script,
                                    "首启观测窗口结束前"):
                    policy_resolved = True
                    consent_done = False
                    continue
            except Exception as _e:
                cap.setdefault("notes", []).append("同意前补做政策访问异常：%s" % _e)

        if not consent_done and not consent_only and _consent_tap_once(
                res, serial, cap, policy_resolved, log,
                set_consent=lambda lab: _fresh_script().exports_sync.set_consent(True, lab),
                            ai_tasks=ai_tasks):
            consent_done = True
            if not policy_resolved:
                if (cap.get("noticeText") or "").strip():
                    cap["notes"].append(
                        "首启弹窗只给出了 %d 字的政策告知摘要，未能在弹窗内打开政策全文"
                        "（入口文字不在已知命名集合内，或入口节点不可点击）；"
                        "本报告的政策正文改由 APK 内置文档 / 后续遍历补采。"
                        % len(cap["noticeText"]))
                break       # 政策未取得、弹窗又没了，继续等下去只是空转
            continue

        if policy_resolved and consent_done:
            break
        if consent_only and policy_resolved:
            # 1 档：政策这件事处理完了，任务目标达成。剩下的界面证据（首启弹窗本身）
            # 在循环里已经拍过，继续等只是让 App 停在弹窗上烧时间。
            # ★ "处理完"≠"拿到了正文"（2026-11-11 学习通）：`grab_policy_once`
            #   在"点开了政策页"时也返回 True，于是这里曾写成"已取得政策正文"，
            #   而同一条日志上一行还写着"正文 0 字" —— 报告自己打自己的脸。
            _bt = len((cap.get("bestText") or "").strip())
            _pcg = cap.get("preConsentGrab") or {}
            if _bt >= INLINE_POLICY_MIN:
                cap["notes"].append(
                    "1 档（仅同意前）：政策正文已取得（%d 字），**未点击同意**；"
                    "首启观测阶段到此结束，随后在未同意状态下继续点击界面，"
                    "以触发只在特定界面才初始化的采集行为。" % _bt)
                log("[*] 1 档：已取得政策正文 %d 字，不点同意，转入未同意探索" % _bt)
            elif _pcg.get("opened"):
                cap["notes"].append(
                    "1 档（仅同意前）：政策入口已点开（%s），但正文未能读取；"
                    "**未点击同意**，转入未同意状态探索。"
                    % (_pcg.get("focusAfter") or "政策页"))
                log("[!] 1 档：政策页已打开但正文读不到（0 字），不点同意，转入未同意探索")
            else:
                cap["notes"].append(
                    "1 档（仅同意前）：未定位到可打开的政策入口，**未点击同意**；"
                    "转入未同意状态探索。结构树看不见的超链接需人工复核。")
                log("[!] 1 档：未定位到政策入口，不点同意，转入未同意探索")
            break
        if rounds >= 8 and not consent_done and not has_policy_word:
            res.popup_evidence.append("首启 %ds 内未发现隐私政策提示，也未发现同意按钮"
                                      % wait_seconds)
            break
        time.sleep(1.5)

    # 收尾：把脚本侧捕获到的政策信息取回来（不覆盖界面收割到的更长文本）
    try:
        pol = _policy_via(_fresh_script())
        for u in (pol.get("urls") or []):
            if u.get("url") and u["url"] not in [d.get("url") for d in cap["urls"]]:
                cap["urls"].append(u)
        for t in (pol.get("entryTexts") or []):
            if t not in cap["entryTexts"]:
                cap["entryTexts"].append(t)
        if pol.get("entryClicked") and not cap.get("entryClicked"):
            cap["entryClicked"] = pol["entryClicked"]
        cap["webviewCount"] = int(pol.get("webviewCount") or 0)
        texts = pol.get("texts") or {}
        for u, t in texts.items():
            # 同一条闸门：脚本侧抓到的 WebView 正文也可能是 App 自己的业务 H5
            _keep_policy_text(cap, t, u)
    except Exception as e:
        res.errors.append("读取政策捕获结果失败：%s" % e)

    # ---- 把「政策以外的声明文档」也取回来（用户协议 / 各类清单 / 未成年人规则）----
    # 候选来源：WebView 实际加载过的地址 + 静态分析从 APK 里挑出的政策类链接。
    # 这一步**不**改变政策正文（`_keep_policy_text` 才管那个），只补充证据。
    try:
        _doc_urls: List[Any] = []
        for d in (cap.get("urls") or []):
            _doc_urls.append(d.get("url") if isinstance(d, dict) else d)
        _doc_urls.extend(getattr(res, "policy_urls", None) or [])
        collect_documents(cap, _doc_urls, log, budget=5)
    except Exception as e:
        res.errors.append("取回政策/协议类文档失败：%s" % e)

    # ---- 汇总：把这一轮「政策到底拿到了没有」定成结构化结论 ----
    # 为什么要有 outcome 这个字段：报告层与规则层都需要一个**明确态**，
    # 而不是各自去猜 bestText/urls/errorPage 的组合。真机教训（赣警办）：
    # 弹窗告知摘要 428 字被当成政策正文，报告写成"政策已获取"，
    # 而真实情况是入口指向的链接 404、条款根本没拿到 —— 结论完全反了。
    # ---- 结论必须先与"手上有没有正文"自洽（2026-11-09 镜像投屏）----
    # 那一轮：入口判定写的是「未定位到政策入口」（no_entry），可 bestText 里
    # 躺着 200001 字的政策正文（HTML 源码）。同一份报告里"没找到入口"和
    # "正文 20 万字"并存，读的人只能怀疑整份报告。
    # 原因：outcome 在"点击后立刻判"时定下（那一刻页面还在加载、正文为空），
    # 之后 WebView 补判把正文收了进来，却没有回头改结论。
    _bt_now = len((cap.get("bestText") or "").strip())
    if _bt_now >= INLINE_POLICY_MIN and str(cap.get("outcome") or "") in (
            "", "not_run", "no_entry", "no_text", "notice_only"):
        _old_oc = str(cap.get("outcome") or "（空）")
        cap["outcome"] = "full_inline"
        cap.setdefault("notes", []).append(
            "结论修正：入口判定原记为「%s」，但本轮实际取得政策正文 %d 字"
            "（取得方式：%s），按实证改为「已取得条款正文」"
            % (_old_oc, _bt_now, cap.get("bestTextFrom") or "界面读取"))
    if not cap.get("outcome"):
        bt = len((cap.get("bestText") or "").strip())
        if cap.get("externalOpen") and bt < INLINE_POLICY_MIN:
            # 政策链接被交给系统组件/外部浏览器：应用内不存在政策页，
            # 采集器读不到它的正文（作业帮 2026-10-30）。
            cap["outcome"] = "external_app"
        elif cap.get("deviceOffline") and bt < INLINE_POLICY_MIN:
            # 离线时页面打不开，无从判断链接好坏 —— 不能落到 error_page。
            cap["outcome"] = "offline_unverified"
        elif cap.get("errorPage"):
            cap["outcome"] = "error_page"
        elif bt >= INLINE_POLICY_MIN:
            cap["outcome"] = "full_inline"
        elif bt or cap.get("urls") or cap.get("entryClicked"):
            cap["outcome"] = "no_text"
        else:
            cap["outcome"] = "no_entry"

    # ---- 不注入模式下补读一次 WebView 地址（2026-11-09 天优家教）----
    # 注入受限时 WebView.getUrl 通道是死的，但"临时附着读一次"并不需要装 hook，
    # 实测也不会被杀。拿到的地址比"未记录到可访问地址"有用得多。
    if (probe_urls is not None
            and not cap.get("bestTextUrl")
            and isinstance(script, _NoScript)
            and len((cap.get("bestText") or "").strip()) >= INLINE_POLICY_MIN
            and not cap.get("_urlProbed")):
        cap["_urlProbed"] = True
        try:
            _urls = probe_urls() or []
        except Exception as _pe:
            _urls = []
            log("[.] 补读 WebView 地址失败：%s" % str(_pe)[:80])
        if not _apply_probed_urls(cap, _urls, log) and _urls:
            cap.setdefault("notes", []).append(
                "临时附着读到 %d 个 WebView 地址，但没有一个标题指向隐私政策，"
                "未作为政策链接采用" % len(_urls))

    # ★ 广告地址不许混进"政策地址"（Q船 2026-11-09）。放在这里是因为
    #   URL 有三个来源（WebView.loadUrl / Intent.extra / 临时附着补读），
    #   逐个入口过滤总会漏；在结论结算前统一清一遍最稳。
    _drop_ad_urls(cap, log)

    _outcome = cap["outcome"]
    # 本轮注入是否可用：不可用时 WebView 地址通道（getUrl / loadUrl hook）拿不到，
    # "没有链接"的原因是"注入受限"，与"应用本就内置 HTML"是两回事。
    # 判据用 isinstance(_NoScript)：注入受限时这里是"空脚本"替身，
    # 它照样有 exports_sync（全返回 None），所以不能按属性有无判断。
    try:
        cap["_notInjected"] = isinstance(script, _NoScript)
    except Exception:
        pass
    if _outcome == "external_app":
        log("[!] 政策结论：入口把链接交给了系统组件/外部应用（%s），"
            "应用内没有政策页，未取得条款 —— 需人工在浏览器中核对"
            % str(cap.get("externalOpen") or "").split("/")[-1][:32])
    elif _outcome in ("full", "full_inline"):
        # 没有链接不等于没有来源：不注入模式下 WebView.getUrl 拿不到，
        # 正文是靠界面读的 —— 这时候要写"界面读取"，不能只印一个「—」，
        # 否则看日志的人会以为这份正文来路不明。
        _src = cap.get("bestTextUrl") or ""
        if not _src:
            _why = _POL.no_url_reason(cap)
            _src = "界面读取（%s）" % (cap.get("bestTextFrom") or "取得方式未记录")
            if _why:
                _src += "；" + _why.split("；")[0]
        log("[*] 已取得政策全文 %d 字（来源：%s）"
            % (len(cap.get("bestText") or ""), _src))
    elif _outcome == "error_page":
        log("[!] 政策结论：入口打开的是错误页（%s），未取得政策条款 —— 属问题项"
            % cap["errorPage"])
    elif _outcome == "offline_unverified":
        log("[!] 政策结论：测试机无网络，政策页打不开；本轮**不判断**该链接是否可用"
            "（需联网重跑）")
    elif _outcome == "notice_only":
        # 报的是"弹窗摘要"的字数，就不能拿 bestText 的长度充数
        # （实测出现过"仅取得弹窗告知摘要 1652 字"，而弹窗实际只有 97 字）
        log("[!] 政策结论：仅取得弹窗告知摘要 %d 字，未取得完整政策条款"
            % len((cap.get("noticeText") or "").strip()))
    elif _outcome == "external_unverified":
        _er = cap.get("externalRead") or {}
        log("[!] 政策结论：入口由系统浏览器打开，界面里读到 %d 字（%d 屏），"
            "但内容不像隐私政策、未认定为条款正文 —— 需人工在浏览器中核对"
            % (int(_er.get("chars") or 0), int(_er.get("screens") or 0)))
    elif _outcome == "no_text":
        log("[!] 政策结论：点了入口但未取到政策条款（候选链接 %d 个）"
            % len(cap.get("urls") or []))
    else:
        log("[!] 政策结论：未观测到政策入口，也未取到政策正文（属重要发现，将写入报告）")

    try:
        _fresh_script().exports_sync.mark_ui_action("首启弹窗处理完成")
    except Exception:
        pass

    # ---- 把界面退回"入口那一屏"（2026-11-09 天优家教）----
    # ★ 为什么必须做：取到政策正文之后，界面还停在政策 H5 上。紧接着的着陆阶段
    #   按"可点元素 0 个 / 文字 1 条"把它判成"启动加载页"，等 3 次就放弃，
    #   于是遍历从政策页开始 —— **首启那次"同意"整个丢了**。
    #   分水岭一错，后面所有事件都被算作"同意前"，整份报告后半段不可信。
    #   这里按点击政策入口之前记录的前台界面退回去，最多退 2 次；
    #   已经切到外部浏览器的不退（那是别人的界面，退会退到桌面）。
    _snap = cap.get("openSnapshot") or {}
    _page_focus = str(_snap.get("focus") or "")
    _want_focus = str(_snap.get("focusBefore") or "")
    if _snap.get("entered") and _page_focus and _want_focus and res is not None:
        try:
            for _i in range(2):
                _now = uiwalk.current_focus(serial) or ""
                # ★ 只有界面**还停在政策页**时才退。已经自己跳走（同意后进了主页面、
                #   或者应用自己关了政策页）就绝不能按返回 —— 天优家教这一轮就是
                #   这么退到桌面去的：同意之后前台已经是主界面，还按计划退两次，
                #   直接把应用退掉，着陆阶段只好重新拉起。
                if not _now or not same_focus(_page_focus, _now):
                    break
                if _is_external_focus(_now, res.package):
                    break
                uiwalk.back(serial)
                time.sleep(1.0)
            _now = uiwalk.current_focus(serial) or ""
            if _now and same_focus(_want_focus, _now):
                log("[*] 已从政策页退回入口屏（%s），继续首启流程"
                    % ((_want_focus.split("/")[-1] or "")[:30]))
            elif _now and same_focus(_page_focus, _now):
                log("[!] 政策页未能退回入口屏（当前前台 %s）——"
                    "着陆与同意判定可能受影响，报告会注明"
                    % ((_now.split("/")[-1] or "未知")[:30]))
        except Exception:
            pass


# ---------------------------------------------------------------- 主遍历

def launch_app(serial: str, package: str) -> bool:
    """用 monkey 唤起 App 的 launcher activity（不需要知道具体类名）。"""
    try:
        p = _run(_adb_args(serial) + ["shell", "monkey", "-p", package,
                                      "-c", "android.intent.category.LAUNCHER", "1"],
                 timeout=30)
        out = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace")
        return "Events injected" in out
    except Exception:
        return False


def app_pids(serial: str, package: str) -> List[int]:
    """按包名前缀匹配 `ps` 输出，拿到该应用的全部进程号（**含 :xxx 子进程**）。

    ★ 为什么不用 `pidof 包名`：它只认精确进程名。加固包常把主进程命名成
      `<包名>:privacy_policy`、`<包名>:push` 之类，`pidof` 一律返回空 ——
      于是"进程明明在跑"被判成"进程不存在"。小盒课堂（爱加密）2026-10-27
      实测：界面在崩溃循环里反复重建，`pidof` 全程为空，正是这个原因。
    """
    try:
        p = _run(_adb_args(serial) + ["shell", "ps", "-A", "-o", "PID,NAME"], timeout=20)
        out = (p.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return []
    pids: List[int] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].startswith(package) and parts[0].isdigit():
            pids.append(int(parts[0]))
    return pids


def launcher_activity(serial: str, package: str) -> str:
    """解析 launcher activity（形如 `包名/.XxxActivity`），拿不到返回空串。

    比 monkey 可靠的地方：monkey 只回一句 `Events injected: 1`，哪怕这个包
    根本没有可启动的 activity 也照样回"成功"；`resolve-activity` 会明确给出
    真实入口，没有就是没有。
    """
    try:
        p = _run(_adb_args(serial) + ["shell", "cmd", "package", "resolve-activity",
                                      "--brief", package], timeout=25)
        out = (p.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(package + "/") and " " not in line:
            return line
    return ""


def _start_failure_evidence(serial: str, package: str) -> str:
    """抓"应用为什么起不来"的现场：崩溃信号、SELinux 拒绝、进程死亡记录。

    小盒课堂的答案就在这里：`avc: denied { execmod } for /system/lib64/liblog.so`
    —— 加固壳要改系统库的代码段，SELinux 不允许，于是每次启动 60 ms 就死。
    没有这条证据，报告只能含糊地说"应用未能启动"。

    ★ 必须按"根因 / 现象"分层（2026-10-27 实测踩到）：logcat 里
      `Process ... has died` 每条崩溃都会刷一遍，且总在最后；如果按时间取末尾
      几条，拿到的全是"进程死了"这种现象，真正的原因（execmod / Fatal signal）
      反而被挤掉了 —— 报告里就只剩一句无用的"它死了"。
    """
    try:
        p = _run(_adb_args(serial) + ["logcat", "-d", "-t", "800"], timeout=30)
        txt = (p.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return ""
    root: List[str] = []      # 根因级：SELinux 拒绝、崩溃信号、abort
    died: List[str] = []      # 现象级：进程死亡 / 被系统回收
    low_pkg = package.lower()
    for line in txt.splitlines():
        low = line.lower()
        if low_pkg not in low:
            continue
        if ("avc: denied" in low or "execmod" in low or "fatal signal" in low
                or "abort message" in low or "sigsegv" in low or "sigabrt" in low):
            root.append(line.strip())
        elif "has died" in low or "anr in" in low:
            died.append(line.strip())
    return "\n".join((root or died)[-4:])


def _foreground_note(serial: str) -> str:
    """给「前台没切过来」这件事一句**准确**的话。

    ★ 为什么不能直接写"当前前台：<Activity 名>"（2026-11-10 健康深圳）：
      `current_focus()` 拿不到 `mCurrentFocus` 时会兜底读 `mResumedActivity`。
      健康深圳启动后约 150ms 就 has died、窗口从未绘制，兜底读到的却是它自己的
      `io.dcloud.PandoraEntry`。报告若照抄成"前台仍未切到被测应用（当前前台：
      io.dcloud.PandoraEntry）"，读者只会看到一句自相矛盾的话 ——
      括号里明明就是被测应用的 Activity。
      准确的写法是把"窗口焦点"和"Activity 运行态"分开说：
      前者能证明用户看得到，后者只能证明这个 Activity 还活着。
    """
    try:
        fg = uiwalk.foreground(serial)
    except Exception:
        return "前台信息取不到"
    via = fg.get("via") or ""
    foc = fg.get("focus") or ""
    if via == "window":
        return "当前窗口焦点是 %s" % (foc or "未知")
    if via == "resumed":
        return ("窗口焦点取不到（mCurrentFocus 为空），只读到处于运行态的 Activity %s"
                "（这只能说明它没被销毁，不代表界面已绘制出来）" % (foc or "未知"))
    return "窗口焦点与 Activity 都取不到"


def probe_start_without_hook(serial: str, package: str,
                             observe: float = 12.0, tick: float = 2.0) -> Dict[str, Any]:
    """**不注入**，只用 adb 把 App 拉起来，看它自己能不能活。

    2026-10-27 的原因为何要单独做这一步（真机对照实测）：

      · 洋葱学园：不注入时进程 14 秒稳定、首启隐私弹窗完整显示；
        一旦 spawn 注入，2 秒内进程消失、系统重新拉起。→ "注入不了"可以退到
        仅界面采集，前提是**应用本身能跑**，这一点必须实测，不能假设。
      · 小盒课堂（爱加密）：`device.spawn` 干等 30 秒超时；不注入启动也活不过
        60 ms。旧报告写"检测手段受限，不代表应用自身无法运行"—— 这句话是假的。

    判据：观察窗内**至少 3 次**采到进程，且前后是**同一个 pid**，才算"能稳定
    启动"。只看"采到过 pid"会把崩溃循环判成正常（进程 60 ms 一换，总能撞上）。
    """
    out: Dict[str, Any] = {"started": False, "pids": [], "activity": "",
                           "why": "", "evidence": ""}
    force_stop(serial, package)
    time.sleep(1.0)

    act = launcher_activity(serial, package)
    out["activity"] = act
    started_by_adb = False
    if act:
        try:
            p = _run(_adb_args(serial) + ["shell", "am", "start", "-n", act], timeout=30)
            txt = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace")
            if "Error" not in txt and "Exception" not in txt:
                started_by_adb = True
            else:
                out["am_error"] = " ".join(txt.split())[:300]
        except Exception as e:
            out["am_error"] = str(e)[:200]
    if not started_by_adb:
        launch_app(serial, package)

    seen: List[int] = []
    t0 = time.time()
    while time.time() - t0 < observe:
        seen.extend(app_pids(serial, package))
        time.sleep(tick)

    uniq = sorted(set(seen))
    out["pids"] = uniq
    out["samples"] = len(seen)
    # ★ "进程活着"不等于"用户看得到"（2026-11-10 健康深圳）：
    #   进程可以稳定存活却始终不画窗口（纯 Surface 渲染 / 壳把界面藏了），
    #   这种情形下界面证据同样是零。两项都要如实记，结论才站得住。
    try:
        out["visible"] = (uiwalk.app_visible(serial, package) is True)
    except Exception:
        out["visible"] = None
    if len(seen) >= 3 and len(uniq) == 1:
        out["started"] = True
        out["pid"] = uniq[0]
        out["why"] = ("不注入时进程稳定存活（%d 次采样均为同一 pid %d）"
                      % (len(seen), uniq[0]))
        if out["visible"] is False:
            out["why"] += "，但窗口焦点始终不在该应用上（界面上看不到它）"
    else:
        if not uniq:
            out["why"] = ("不注入直接启动时，%.0f 秒内一次都没有采到存活进程 —— "
                          "应用在本机无法启动" % observe)
        else:
            out["why"] = ("不注入直接启动时，%.0f 秒内进程反复重建"
                          "（共出现 %d 个不同 pid：%s）—— 应用在本机无法稳定启动"
                          % (observe, len(uniq), "、".join(str(x) for x in uniq[:6])))
        out["evidence"] = _start_failure_evidence(serial, package)
    return out



# ============================================================ 首启着陆（P3.5）
# 预算：这一段不该吃掉遍历的时间，但也不能太少 —— 开屏广告就要 3~5 秒，
# 引导页翻 4 屏、弹窗关两层，正常都在 20 秒以内。给到剩余时间的 35%，
# 上不封顶 150 秒（真机实测最差的一单是"广告→年龄门→兴趣页→登录页"，
# 用了 41 秒），下限 30 秒，否则预算紧的档位会一步都不敢走。
_LANDING_BUDGET_CAP = 150.0
_LANDING_BUDGET_MIN = 30.0
# 最多走多少步。14 步足够覆盖"广告 + 弹窗 x2 + 引导 5 屏 + 兴趣页"的最坏组合；
# 再多说明不是在着陆，是在里面转圈了。
_LANDING_MAX_STEPS = 14
# 着陆阶段"前台不在应用内"时最多重拉几次（2026-11-09 爱思投屏/聚橙票务）。
# 这些应用带加固壳：spawn 一次 30~60 秒，而且拉起来又被壳杀掉 ——
# 旧代码每轮都重拉、不计数，120 秒预算全换了无效冷启动，截图全在桌面。
_LANDING_RESPAWN_MAX = 2
# 遍历期"重拉之后应用仍然没出现在前台"的连续上限（2026-11-10 搜题 / 健康深圳）。
# 这两单的 uni-app 每次都"启动成功"却从不画窗口，旧逻辑重拉 10 次、烧掉 430 秒，
# 期间拍的每一张截图都是系统桌面。连续 4 次拉不回来就不该再花时间了。
_APP_NEVER_VISIBLE_MAX = 4

# 交给模型的目标。**必须写清"不要做什么"** —— 只写"进主页面"，模型会为了
# 进主页面去点广告、点兴趣标签、点"立即更新"，这些正是着陆阶段要避免的。
_LANDING_GOAL = (
    "目标：把应用从首次启动的过渡界面带到主页面。"
    "只做「关闭弹窗 / 跳过广告 / 走过引导页 / 关掉更新提示 / 完成首启调研」"
    "这几类动作。"
    "遇到调研/选择页（让用户选学段、身份、角色、使用目的这类问卷）："
    "先看页面上有没有「跳过/暂不」，有就优先跳过；没有跳过入口时，"
    "模仿真实用户——先点其中一个选项，再点「进入首页/下一步/完成」提交，"
    "一次只选一个。"
    "禁止：点广告主体（会外跳）、点下载/安装/立即更新/立即领取/购买、"
    "进入任何功能页面、填写任何个人信息表单。"
    "若当前已经是主页面（有底部导航栏），回答 action=done。"
)


def _policy_evidence_ok(res: ScanResult) -> bool:
    """是否已经"通过应用页面拿到隐私政策"。

    口径（2026-11-08 用户要求："同意前一定要通过 App 的实际页面访问到隐私政策"）：
      · bestText ≥ INLINE_POLICY_MIN —— 拿到了能做条款比对的正文；
      · openSnapshot.entered —— 确实打开过政策页（哪怕正文没读全）；
      · documents 非空 —— 至少一份文档正文入库。

    ★ **只有 URL 不算**：抓到一条链接但页面从未打开，
      等于没验证过"这个地址在应用里能不能读"——
      岛的 www.iiisland.com/privacy 直接 HTTP 取回 0 字（反爬/JS 渲染），
      而 App 内打开是完整正文。链接只能作为产出，不能代替"访问到"。
    """
    cap = (res.policy_capture or {}) if res is not None else {}
    if len((cap.get("bestText") or "").strip()) >= INLINE_POLICY_MIN:
        return True
    if (cap.get("openSnapshot") or {}).get("entered"):
        return True
    if cap.get("documents"):
        return True
    return False


_WV_URL_PROBE_JS = r"""
Java.perform(function () {
  var out = [];
  var done = false;
  function finish() {
    if (done) { return; }
    done = true;
    send({urls: out});
  }
  Java.scheduleOnMainThread(function () {
    try {
      Java.choose('android.webkit.WebView', {
        onMatch: function (wv) {
          try {
            out.push({url: String(wv.getUrl() || ''), title: String(wv.getTitle() || '')});
          } catch (e) { out.push({err: String(e)}); }
        },
        onComplete: function () {}
      });
    } catch (e) { out.push({fatal: String(e)}); }
    setTimeout(finish, 300);
  });
  setTimeout(finish, 4000);
});
"""


def probe_webview_urls(device: Any = None, serial: str = "", package: str = "",
                       log: Callable[[str], None] = print,
                       timeout: float = 6.0) -> List[Dict[str, str]]:
    """**临时附着**读一次当前 WebView 的地址与标题，读完立刻断开。

    ★ 为什么需要（用户 2026-11-09 第 7 条，天优家教）：
      该应用带加固壳，冷启动注入会让它自杀，所以本轮走的是"不注入"模式 ——
      政策页确实点开了、正文 2703 字也读到了，但 WebView.getUrl 这条通道
      随之失效，报告只能写"未记录到可访问地址"。
      而真机实测：**应用已经在跑的时候临时 attach 一次并不会被杀**（pid 不变），
      主线程里调 getUrl 就能拿到
      `https://www.tianyoujiajiao.com/privacy?container=1&LogoutFromApp=1`（标题「隐私政策」）。
      所以"注入受限 ⇒ 一定拿不到链接"这个推论是错的，代价只是一次 2 秒的附着。

    ★ 与正式注入的区别（很重要）：
      · 只读，不装任何 hook，不碰业务逻辑，读完立刻 detach；
      · 失败一律静默（返回空表）—— 有的壳确实会"附着即自杀"，
        那种情况调用方按"拿不到地址"处理，不能因此把整轮判失败。

    返回 `[{"url": ..., "title": ...}, …]`，只保留 http(s) 的项。
    """
    out: List[Dict[str, str]] = []
    ses = None
    try:
        pid = find_running_pid(serial, package)
        if pid is None:
            return []
        if device is None:
            import frida                       # 延迟导入：单元测试不装 frida 也能跑
            device = frida.get_device(serial, timeout=8)
        ses = _fguard.attach(device, pid)
        scr = _fguard.wrap_script(ses.create_script(_WV_URL_PROBE_JS))
        got: List[Dict[str, str]] = []

        def _on(msg, _data):
            try:
                if msg.get("type") != "send":
                    return
                for it in ((msg.get("payload") or {}).get("urls") or []):
                    if isinstance(it, dict) and str(it.get("url") or "").startswith("http"):
                        got.append({"url": str(it["url"]), "title": str(it.get("title") or "")})
            except Exception:
                pass

        scr.on("message", _on)
        scr.load()
        _t0 = time.time()
        while time.time() - _t0 < timeout and not got:
            time.sleep(0.2)
        out = got
        if out:
            log("[*] 临时附着读到 WebView 地址 %d 条（不注入模式下的补读）：%s"
                % (len(out), out[0]["url"][:90]))
    except Exception as e:                       # 附着被壳拦、进程正忙……都不算错
        log("[.] 临时附着读 WebView 地址失败（不影响结论）：%s" % str(e)[:100])
    finally:
        try:
            if ses is not None:
                ses.detach()
        except Exception:
            pass
    return out


def _drop_ad_urls(cap: Dict[str, Any], log: Callable[[str], None] = print) -> int:
    """把混进"政策地址"里的广告域名挪到 `cap["adUrls"]`，返回挪走的条数。

    ★ Q船 4.4.2（2026-11-09）实测：`policy_capture.urls` 里 10 条地址有 9 条是广告 ——
      `p3-app-package-sign.byteimg.com/ad-app-package/…`（`Intent.extra:dialog_icon_url`
      顺手抓到的下载弹窗图标）和 `apps.bytesfield.com/…?package_name=com.xingin.xhs`
      （点广告位后 WebView.loadUrl 的落地页）。
      报告的「打开的地址」会把这些印成"隐私政策所在页面" —— 这比"没有链接"更糟：
      它给了一条查不到政策的广告地址当作取证依据。
      剔除而不是丢弃：留在 `adUrls` 里，报告可以直接写"本轮还打开了 N 个广告页"，
      这本身就是用户第 2 条要的那个证据。
    """
    keep: List[Dict[str, Any]] = []
    ads: List[Dict[str, Any]] = []
    for d in (cap.get("urls") or []):
        if not isinstance(d, dict):
            continue
        u = str(d.get("url") or "")
        try:
            _is_ad = bool(foreignmod is not None and foreignmod.is_ad_url(u))
        except Exception:
            _is_ad = False
        (ads if _is_ad else keep).append(d)
    if not ads:
        return 0
    cap["urls"] = keep
    _old = cap.get("adUrls") or []
    cap["adUrls"] = list(_old) + [a for a in ads
                                  if a.get("url") not in [x.get("url") for x in _old]]
    if cap.get("bestTextUrl") and any(str(a.get("url") or "") == str(cap["bestTextUrl"])
                                      for a in ads):
        cap["bestTextUrl"] = ""
    _hosts = []
    for a in ads:
        h = str(a.get("url") or "").split("://")[-1].split("/")[0]
        if h and h not in _hosts:
            _hosts.append(h)
    log("[!] 政策地址里混进了 %d 条广告域名（%s），已从政策地址中剔除"
        % (len(ads), "、".join(_hosts[:4])))
    cap.setdefault("notes", []).append(
        "本轮共记录到 %d 条广告/推广应用类地址（%s）。这些地址来自点击广告位后的"
        "落地页与下载弹窗，**不是**被测应用的政策页，已单独归档、不计入政策链接。"
        % (len(ads), "、".join(_hosts[:4])))
    return len(ads)


_POLICY_URL_TITLE_RE = re.compile("隐私|政策|协议|条款")


def _apply_probed_urls(cap: Dict[str, Any], urls: Sequence[Dict[str, str]],
                       log: Callable[[str], None] = print) -> str:
    """把"临时附着读到的 WebView 地址"归档进政策采集结果，返回选中的政策地址。

    单独抽出来是因为有两个调用点，判据必须完全一致：
      · 首启阶段刚取到政策正文那一刻（页面还在前台，地址一定读得到）；
      · `grab_policy_once` 里 `current_urls`/`activity_url` 两条通道都空的时候。

    ★ 选哪个当政策链接：只认**标题**指向隐私/政策/协议/条款的。
      真机上 WebView 常常同时存在好几个（弹窗里的、广告页的、预加载的），
      挑第一个 http 地址会把广告落地页写成"隐私政策链接" —— 那是比
      "没有链接"更糟的假话。
    """
    picked = ""
    seen = [str(d.get("url") or "") for d in (cap.get("urls") or [])]
    for it in urls or []:
        u = str(it.get("url") or "")
        ti = str(it.get("title") or "")
        if not u.startswith("http"):
            continue
        if u not in seen:
            cap.setdefault("urls", []).append(
                {"url": u, "from": "临时附着读 WebView.getUrl",
                 "policyLikely": bool(_POLICY_URL_TITLE_RE.search(ti))})
            seen.append(u)
        if not picked and _POLICY_URL_TITLE_RE.search(ti):
            picked = u
    if picked:
        cap["bestTextUrl"] = picked
        cap.setdefault("notes", []).append(
            "页面地址由「临时附着读取 WebView.getUrl」补得（本轮未注入，"
            "该操作只读、不装 hook，应用未受影响）：%s" % picked)
        log("[+] 补得政策页面地址：%s" % picked)
    return picked


_POLICY_ENTRY_TREE_WORDS = ("隐私政策", "隐私协议", "隐私权政策", "隐私保护政策",
                            "个人信息保护政策", "用户协议", "服务协议", "协议与规则")


def _policy_link_points_from_tree(serial: str,
                                  log: Callable[[str], None] = print,
                                  max_cands: int = 6) -> List[Dict[str, Any]]:
    """**不注入时**从结构树里算出政策链接的可点坐标。

    ★ 为什么需要（2026-11-09 天优家教）：
      该应用带加固壳，注入会被杀 → 走不注入模式。此时 `policy_links()`
      （由 App 进程内的 TextView.Layout 算坐标）拿不到，`grab_policy_once`
      在第一步就写了"当前界面没有可定位的政策链接文字"然后收工。
      可首启弹窗上明明有《隐私政策》四个字，人工点下去就进了
      `WebWrapperActivity`。所以不能因为"进程内算不出来"就认定"屏上没有"。

    ★ 与 `_text_anchor_points` 的分工：
      那个负责"给定一句话和它的框，把目标词换算成坐标"；
      这个负责"先在树上找到那句话"，然后调它。两者都不需要注入。

    返回 `[{"text": …, "xy": (x, y)}, …]`，已按"含隐私 → 文字短"排序。
    """
    try:
        xml = uiwalk.dump_retry(serial, tries=1, wait=0.6) or ""
    except Exception:
        return []
    if not xml:
        return []
    out: List[Dict[str, Any]] = []
    seen: set = set()
    try:
        nodes = uiwalk.parse_all(xml)
    except Exception:
        return []
    # 像素校准只截一次图，所有候选共用（一次 screencap ≈ 0.4 秒）
    _png: Dict[str, bytes] = {}

    def _pixel_point(bounds: Any) -> Optional[Tuple[int, int]]:
        """在节点框里找「彩色文字带」，返回它的中心；找不到返回 None。

        ★ 为什么必须做（学习通 7.0.6，2026-11-11 真机）：
          弹窗正文那句「亲爱的用户，请仔细阅读《隐私政策》和《用户协议》…」
          dump 出来是**一个** TextView，bounds [166,624][914,725]，实际屏幕上是
          **折成两行**的：第一行到「…和《用」，第二行才是「户协议》特向您说明如下：」。
          `_text_anchor_points` 按「整段 32 字均分 748px」算，把《隐私政策》算到
          (493,674) —— 横向落在「阅」字上、纵向正好落在两行之间的空隙，
          点下去纹丝不动。而按颜色实测，蓝字《隐私政策》在 x 581..760 / y 632..665，
          点 (670,648) 立刻打开 WebAppViewerActivity，页面就是完整隐私政策。
          「链接是彩色的、正文是黑灰的」这个特征比任何按字符比例的位置推算都稳。
        """
        if not bounds:
            return None
        try:
            from .ai import vision as _V
        except Exception:
            return None
        if "png" not in _png:
            try:
                _png["png"] = capture_screenshot(serial) or b""
            except Exception:
                _png["png"] = b""
        if not _png["png"]:
            return None
        try:
            got = _V.find_colored_text_run(_png["png"], tuple(int(v) for v in bounds))
        except Exception:
            return None
        if not got:
            return None
        return ((got[0] + got[2]) // 2, (got[1] + got[3]) // 2)

    for n in nodes:
        body = (getattr(n, "text", "") or "").strip()
        if not body and getattr(n, "content_desc", ""):
            body = (n.content_desc or "").strip()
        # 整段政策正文也可能含"隐私政策"四个字，但点它只会选中文字；
        # 这里不按长度一刀切 —— 万步健康那种"整句只有一个 TextView"正是长文本，
        # 只按"目标词在句子里的比例"取点，长句也能压在那四个字上。
        if not body or len(body) > 600:
            continue
        hit = [w for w in _POLICY_ENTRY_TREE_WORDS if w in body]
        if not hit:
            continue
        # ★ 文字**恰好等于**关键词、又不带 clickable → 那是弹窗标题/小标题。
        #   学习通这一单就是栽在这里：标题「隐私政策」bounds [440,502][640,569]，
        #   中心正好 (540,535)，而旧排序「含隐私 + 文字越短越靠前」把它排到了第一，
        #   于是点的是标题 —— 前台没切换、正文 0 字，报告就成了"点了入口没取到"。
        #   真正可点的是正文里那句（clickable=true）。标题再怎么点都不会有反应，
        #   留着它只会浪费一次点击、把结论带偏，直接剔除。
        _bare = body in _POLICY_ENTRY_TREE_WORDS
        _clickable = bool(getattr(n, "clickable", False))
        if _bare and not _clickable:
            continue
        pts = _text_anchor_points(body, getattr(n, "bounds", None), words=hit)
        _ref = _pixel_point(getattr(n, "bounds", None))
        if _ref:
            pts = [_ref] + [p for p in pts if abs(p[0] - _ref[0]) > 6 or abs(p[1] - _ref[1]) > 6]
        for (px, py) in pts[:2]:
            if px <= 2 or py <= 2:
                continue
            k = (px // 8, py // 8)
            if k in seen:
                continue
            seen.add(k)
            # 排序口径（越小越先试）：
            #   0 整句/长句 + 可点 —— 最像真入口
            #   1 整句/长句 + 不可点 —— URLSpan 常挂在这种 TextView 上，仍值得点
            #   2 短标题 + 可点 —— 也有 App 把入口做成一个短按钮，放最后
            _rank = 2 if _bare else (0 if _clickable else 1)
            out.append({"text": body[:40], "xy": (px, py),
                        "src": "tree", "rank": (_rank, len(body))})
    out.sort(key=lambda d: d["rank"])
    if out:
        log("[*] 不注入模式下按结构树文字位置算出 %d 个政策链接候选点"
            % min(len(out), max_cands))
    return out[:max_cands]


def grab_policy_once(serial: str, res: ScanResult, log: Callable[[str], None],
                     get_script: Callable[[], Any], reason: str = "") -> bool:
    """同意之前最后一次"把政策打开看看"。

    返回 True 表示这一次确实打开了政策页并留下了证据。

    为什么要有这一步（2026-11-08，用户明确要求）：
      政策采集窗口一旦错过（加固壳冷启动慢、弹窗延迟出现、入口藏在正文里），
      后面就是着陆/遍历直接点「同意」——**在没有任何政策证据的情况下替用户同意**。
      之后十几项条款比对全部落空，报告只能整片写"跳过未测"。
      所以把"打开政策"这件事挂到同意动作前面：最后一次机会，仍然按
      "点开 → 读正文 → 拿 URL → 返回"的完整流程做，而不是草草收场。

    与 `_inline_policy_entry` 的分工：
      · 那个在政策采集循环里，每轮试一个候选、由主流程判决；
      · 这个在同意之前，自己做完"点击—取证—返回"，不依赖调用方上下文。
    """
    cap = res.policy_capture
    try:
        links = list(get_script().exports_sync.policy_links(24) or [])
    except Exception as e:
        cap.setdefault("notes", []).append("同意前补做政策访问：读取链接坐标失败（%s）" % e)
        return False
    ranked = _rank_inline_links(links)
    # 优先点"隐私"；没有就点第一个书名号/span 候选；再没有就用排序第一的。
    pick: Optional[Dict[str, Any]] = None
    for ln in ranked:
        if "隐私" in (ln.get("text") or ""):
            pick = ln
            break
    if pick is None:
        for ln in ranked:
            if str(ln.get("src") or "") in ("span", "anchor"):
                pick = ln
                break
    if pick is None and ranked:
        pick = ranked[0]
    # ★ 进程内算不出坐标（不注入时 `policy_links()` 恒为 None）→ 退到结构树，
    #   按"目标词在句子里的字符比例"算点。天优家教那轮就是在这里断的：
    #   只写了句"当前界面没有可定位的政策链接文字"就收工，可屏上明明有
    #   《隐私政策》，人工点下去就进了政策页。
    _tree_cands: List[Dict[str, Any]] = []
    if pick is None:
        _tried = cap.get("inlineTried") or []
        _tree_cands = [c for c in _policy_link_points_from_tree(serial, log)
                       if _link_tried_key(c) not in _tried]
        pick = _tree_cands[0] if _tree_cands else None
    if pick is None:
        cap.setdefault("notes", []).append(
            "同意前补做政策访问：进程内链接坐标与结构树文字都没定位到政策入口（%s）"
            % (reason or "同意前"))
        return False

    # ★ 一次点不中就换下一个候选（最多 3 个）。
    #   2026-11-11 学习通：算出 6 个候选却只点了第 1 个（弹窗标题，不可点），
    #   点空之后就当"没打开"收工 —— 明明屏上还有真正可点的那句。
    #   "算得出多个候选"却不"逐个试"，等于白算。
    _attempts = [pick]
    for c in _tree_cands:
        if len(_attempts) >= 3:
            break
        if _link_tried_key(c) == _link_tried_key(pick):
            continue
        _attempts.append(c)

    x, y = int(pick["xy"][0]), int(pick["xy"][1])
    label = str(pick.get("text") or "隐私政策")[:24]
    before = ""
    after = ""
    opened = False
    for _idx, _cand in enumerate(_attempts):
        x, y = int(_cand["xy"][0]), int(_cand["xy"][1])
        label = str(_cand.get("text") or "隐私政策")[:24]
        log("[*] 同意前补做政策访问（%s）：点击「%s」(%d,%d)%s"
            % (reason or "同意之前", label, x, y,
               "" if _idx == 0 else "（第 %d 次尝试：上一个候选点空了）" % (_idx + 1)))
        try:
            before = uiwalk.current_focus(serial) or ""
        except Exception:
            before = ""
        cap["entryClicked"] = label
        cap["entrySource"] = "内联链接（同意前补做）"
        cap["entryTapXY"] = [x, y]
        tried = cap.setdefault("inlineTried", [])
        _k = _link_tried_key(_cand)
        if _k not in tried:
            tried.append(_k)
        res.ui_steps.append("同意前补做政策访问：点击「%s」(%d,%d)" % (label, x, y))
        if not uiwalk.tap(serial, x, y):
            cap.setdefault("notes", []).append("同意前补做政策访问：点击「%s」失败" % label)
            if _idx + 1 >= len(_attempts):
                return False
            continue
        time.sleep(2.0)
        try:
            after = uiwalk.current_focus(serial) or ""
        except Exception:
            after = ""
        opened = bool(before and after and same_focus(before, after) is False)
        if opened:
            break
    # 地址先抓（页面可能很快就没了）
    got_url = ""
    for getter in ("current_urls", "activity_url"):
        try:
            fn = getattr(get_script().exports_sync, getter)
            # current_urls 收一个 reset 参数，activity_url 不收
            urls = fn(True) if getter == "current_urls" else fn()
            for u in (urls or []):
                if u and str(u).startswith("http"):
                    got_url = str(u)
                    break
        except Exception:
            pass
        if got_url:
            break
    # 不注入模式下上面两个 getter 全是 None（`_NoScript` 的替身永不报错、
    # 只返回 None），于是"点了政策页、正文也读到了，却没有链接"。
    # 这里补一次临时附着读 WebView.getUrl —— 只需要 2 秒，且不会杀应用。
    if not got_url and isinstance(get_script(), _NoScript):
        try:
            _pu = probe_webview_urls(None, serial,
                                     str(getattr(res, "package", "") or ""), log)
        except Exception as _pe:
            _pu = []
            log("[.] 同意前补做：临时附着读地址失败（不影响结论）：%s" % str(_pe)[:80])
        got_url = _apply_probed_urls(cap, _pu, log)
    # ---- 政策页刚打开时往往还没渲染完，别急着判"正文 0 字"----
    # 镜像投屏 4.0（2026-11-09）：`grab_policy_once` 点开《隐私政策》后只等了 2 秒，
    # dump 到的是空白页 → "正文 0 字；链接 未取到"，而遍历阶段同一份政策却读到了
    # 20 万字。差别只在于**等没等它加载**。
    # 这里给 8 秒窗口：每 1.4 秒让注入脚本重新收割一次 WebView 正文，
    # 读到够长就停；不注入的模式下这段会自然空转（exports 全返回 None），不额外耗时。
    _wv_text = ""
    try:
        for _i in range(5):
            try:
                get_script().exports_sync.read_web_views()
            except Exception:
                pass
            try:
                _pol = get_script().exports_sync.get_policy() or {}
            except Exception:
                _pol = {}
            for _u2, _t2 in (_pol.get("texts") or {}).items():
                if _t2 and len(str(_t2)) > len(_wv_text):
                    _wv_text = str(_t2)
            for _d2 in (_pol.get("urls") or []):
                _u2 = str((_d2 or {}).get("url") or "")
                if (not got_url and _u2.startswith("http")
                        and not _u2.startswith("about:")):
                    got_url = _u2
            if len(_wv_text.strip()) >= INLINE_POLICY_MIN:
                break
            time.sleep(1.4)
    except Exception:
        pass
    try:
        xml = uiwalk.dump_retry(serial, tries=2, wait=0.8) or ""
    except Exception:
        xml = ""
    text = ""
    if xml:
        try:
            text = _harvest_ui_text(xml, min_len=60) or ""
        except Exception:
            text = ""
    if len(_wv_text.strip()) > len(text.strip()):
        # WebView 里的正文比结构树读到的多（政策页整块是 H5 时几乎总是如此）
        text = _wv_text
        _text_from = "政策页 WebView 正文（同意前补做）"
    else:
        _text_from = "政策页面文本（同意前补做）"
    if text:
        _keep_policy_text(cap, text, got_url, _text_from)
        if not cap.get("bestTextUrl") and got_url:
            cap["bestTextUrl"] = got_url
    if got_url and got_url not in [d.get("url") for d in (cap.get("urls") or [])]:
        cap.setdefault("urls", []).append({"url": got_url, "from": "同意前补做"})
    _drop_ad_urls(cap, log)
    cap["preConsentGrab"] = {
        "label": label, "xy": [x, y], "opened": opened,
        "focusBefore": before, "focusAfter": after,
        "textChars": len(text or ""), "url": got_url,
        "reason": reason or "同意之前",
    }
    log("[%s] 同意前补做政策访问：%s；正文 %d 字；链接 %s"
        % ("+" if (opened or text) else "!", "已打开政策页" if opened else "点击后前台未切换",
           len(text or ""), got_url or "未取到"))
    # ★ 打开了、却一个字的正文都读不到 → 留一张截图。
    #   学习通 7.0.6（2026-11-11 真机）：政策页确实打开了（WebAppViewerActivity，
    #   标题「学习通隐私政策」，页面上是完整条款），但加固壳拒绝 frida 附着
    #   （attach 直接 ProcessNotRespondingError），页面又是 X5 内核的 H5，
    #   uiautomator 只读得到一个标题节点 —— 正文 0 字、URL 也拿不到。
    #   这种"打开了读不到"与"根本没点开"是两件事，报告里必须能分开：
    #   没有这张图，只能写"未取得政策正文"，看不出到底是哪一种。
    if opened and not text:
        try:
            observe_screen(res, "政策页（已打开但正文不可读）", serial)
        except Exception:
            pass
    # 回到原界面（同意按钮所在的那一屏）
    if opened:
        try:
            uiwalk.back(serial)
            time.sleep(1.2)
        except Exception:
            pass
    return bool(opened or len((cap.get("bestText") or "").strip()) >= INLINE_POLICY_MIN)


def _landing(res: ScanResult, cfg, live, deadline: float,
             log: Callable[[str], None],
             ai_tasks: Optional[AITasks] = None,
             back_unsafe: bool = False,
             respawn=None,
             should_stop: Optional[Callable[[], bool]] = None,
             on_stage: Optional[Callable[[str, int], None]] = None,
             login_phone: str = "",
             get_sms_code: Optional[Callable[[], str]] = None,
             login_timeout: int = 180,
             get_script: Optional[Callable[[], Any]] = None,
             ) -> Dict[str, Any]:
    """P3.5 首启着陆：从「点完同意」走到「站在主页面」。

    这一段为什么不能交给通用遍历，见 `piiscan/landing.py` 文件头（那里有
    2026-11-05 四台真机的形态对照表）。这里只说执行层的三条约束：

      1. **只做 landing 批准的动作**：动作与目标是 `landing.plan()` 定的，
         本函数不自己发明点击。模型给的答案要再过一遍 `landing.forbidden()`。
      2. **每一步都留痕**：点击前截图 + 标注 + 判读，与功能遍历的留痕同构，
         报告里能并排看。着陆阶段点错是最贵的，恰恰最需要能复核。
      3. **判"到了"要连续两次**：见 `landing.confirm_home`，避免在骨架屏上
         开工（骨架屏有 tab 却没有入口，遍历会在上面点一堆空气）。

    返回 `landing.summary()` 的结果，同时写进 `res.landing`。
    """
    serial = res.device_serial
    t0 = time.time()
    room = max(0.0, deadline - t0)
    budget = max(_LANDING_BUDGET_MIN, min(_LANDING_BUDGET_CAP, room * 0.35))
    # 预算再紧也不能超过剩余时间（否则这一步会把后面全挤掉）
    end = min(deadline, t0 + budget)
    log("[*] 首启着陆：先渡过开屏广告 / 弹窗 / 引导页，把应用带到主页面"
        "（预算 %ds；这段时间只走流程，不做功能遍历）" % int(max(1, end - t0)))
    if on_stage:
        try:
            on_stage("首启着陆", 50)
        except Exception:
            pass

    history: List[Dict[str, Any]] = []      # 逐屏形态，供 confirm_home 用
    steps: List[Dict[str, Any]] = []
    tried: Dict[str, int] = {}              # 已点过的 node_key → 次数
    swipe_rounds = 0
    wait_rounds = 0                         # 启动页"等它自己跳"的次数
    # 「到主页面」是靠什么判出来的：structure（结构树有底部导航）/
    # vision（结构树没有，模型看图判的）。报告里必须区分 —— 前者可复现，
    # 后者依赖模型，证据强度不一样。
    home_by = "structure"
    ai_home_run = 0                         # 模型连续说"已到"的次数
    ai_home_fp = ""
    # 模型在**同一屏**上说"已到主页面"却没被采信的次数（fp → 次数）。
    # 春雨诊所 2026-11-06 实测：登录墙上模型连答 5 次 done，本地一次次
    # 驳回，于是同一屏问了 5 次模型、白烧 10 步。同一屏问两次就够了 ——
    # 再问下去答案不会变，只是把预算换成同样的字。
    ai_done_denied: Dict[str, int] = {}
    # 连续"点了界面没反应"的次数。用来识别**结构树里残留的假按钮**：
    # uni-app 的开屏引导层在视觉上早已消失，节点却还留在结构树里，
    # 于是每轮都能"看到一个跳过、点下去、界面不变"（携船网 2026-11-06 实测）。
    same_run = 0
    reached = False
    why = ""
    pending = 0                             # 待结算的留痕编号（1 基）
    pending_fp = ""
    pending_step: Optional[Tuple[int, str]] = None   # (steps 下标, 动作时的指纹)
    # 待登记的同意动作（点下去时只记事实，等下一屏指纹回来再落定）。
    # 见下方 tap 分支的说明。
    pending_consent: Optional[Dict[str, Any]] = None
    stuck_fp = ""
    stuck_run = 0
    dump_fail = 0
    dump_fail_t0 = 0.0                      # 连续 dump 失败是从什么时候开始的
    offapp_run = 0                          # 连续"前台不在应用内"的轮数（重拉上限）
    respawn_total = 0                       # 本轮着陆阶段累计重拉次数（总上限）
    _home_denied = [False]                  # "结构像首页但焦点不在应用内"只记一次
    step = 0

    while step < _LANDING_MAX_STEPS:
        if time.time() >= end:
            why = "着陆预算用尽（%d 秒 / %d 步）" % (int(time.time() - t0), step)
            break
        if should_stop is not None:
            try:
                if should_stop():
                    why = "任务被外部中止"
                    break
            except Exception:
                pass
        step += 1

        # ---- 读界面
        xml = uiwalk.dump_retry(serial, tries=3, wait=1.0)
        if not xml:
            dump_fail += 1
            # ★ 判据是"连续失败了多久"，不是"连续失败了几次"（2026-11-06 实测）：
            #   App 冷启动 + 注入 hook 的那几秒里，`uiautomator dump` 会
            #   因为拿不到 idle state 而**快速失败**（1.6 秒就返回），
            #   连失败 5 次只花了 8 秒 —— 按次数判会让着陆在 8 秒就放弃，
            #   随后整轮遍历从"不知道是什么界面"开始。
            #   着陆本来留了 150 秒预算，按时间判才符合真实意图。
            if dump_fail == 1:
                dump_fail_t0 = time.time()
            if dump_fail >= 3 and (time.time() - dump_fail_t0) > 45:
                why = ("界面结构读不出来（连续 %.0f 秒 / %d 次 dump 失败）"
                       % (time.time() - dump_fail_t0, dump_fail))
                break
            time.sleep(min(3.0, 1.0 + dump_fail))
            step -= 1                  # 没做事的一轮不该吃掉步数预算
            continue
        dump_fail = 0
        try:
            _fg = uiwalk.foreground(serial)
            act_focus = _fg.get("focus") or ""
        except Exception:
            _fg = {"focus": "", "pkg": "", "via": ""}
            act_focus = ""
        # 用户眼前到底是不是被测应用：只有"窗口焦点"能证明（`via=window`）。
        # `via=resumed` 是兜底读到的 ActivityRecord —— 它可能在应用根本没画
        # 窗口的情况下仍然是应用自己（uni-app 的 PandoraEntry 就是这样）。
        _vis: Optional[bool] = None
        if _fg.get("via") == "window" and _fg.get("pkg"):
            if uiwalk.is_launcher_pkg(_fg["pkg"]):
                _vis = False
            elif not res.package or _fg["pkg"] == res.package:
                _vis = True
            elif (_fg["pkg"].startswith("com.android.")
                  or _fg["pkg"].startswith("com.miui.")
                  or _fg["pkg"] == "android"
                  or "inputmethod" in _fg["pkg"]):
                _vis = True            # 系统弹窗盖在应用上，应用仍在
            else:
                _vis = False

        # ★ 前台已经不在被测应用里：多半是上一步「返回」把 App 退掉了。
        #   春雨诊所实测：登录页上按返回直接回桌面（它把这个键当"退出"）。
        #   在着陆阶段这比遍历阶段更致命 —— 桌面会被判成"未识别界面"，
        #   然后继续按返回、继续不认识，一路空转到预算耗尽。
        #   处置：把 back 标记为不安全（此后不再按返回），重拉一次应用回到
        #   首启流程的入口，再继续判形态。
        if _vis is False or (act_focus and res.package
                             and not act_focus.startswith(res.package)):
            if not back_unsafe:
                log("    [着陆] 前台已不在被测应用内（%s）：上一步动作把应用退出了，"
                    "此后不再按返回" % (act_focus[:40] or _fg.get("pkg") or "未知"))
            back_unsafe = True
            # ★ 重拉要计数（2026-11-09 爱思投屏 / 聚橙票务）：
            #   旧代码这里是"每轮都 respawn() 然后 continue" —— 应用被加固壳
            #   杀掉后永远回不到前台，于是每一轮都再 spawn 一次（每次 30~60 秒，
            #   还顺手把应用再杀一次），着陆 120 秒预算换 7 次无效冷启动，
            #   截图全落在桌面。两次拉不回来就停：把原因写清楚，交给遍历阶段
            #   用"不注入拉起"继续。
            offapp_run += 1
            respawn_total += 1
            # ★ 两个上限缺一不可（爱思投屏 2026-11-09 实测）：
            #   "连续 N 次回不来"挡不住"每次都能拉起来、但一操作就退出"这种情况 ——
            #   那一轮就是 offapp_run 每轮被下面 `offapp_run = 0` 清零，于是
            #   "第 1 次，上限 2 次"这句话在日志里重复了 6 遍，着陆 150 秒全花在
            #   "拉起→点同意→应用死掉"的循环上，截下来的全是桌面。
            #   所以再加一个**本轮总重拉次数**上限：到量就停，并把原因写进报告。
            if respawn_total > _LANDING_RESPAWN_MAX:
                why = ("应用每次拉起后都在下一次操作时立刻退出（本轮共重拉 %d 次，"
                       "均为加固壳所致）；无法进入主页面，首启界面证据以已采截图为准"
                       % (respawn_total - 1))
                log("[!] %s" % why)
                res.errors.append(why)
                break
            if offapp_run > _LANDING_RESPAWN_MAX:
                why = ("应用被退出且 %d 次重拉都未能回到前台（当前前台：%s）；"
                       "判定该应用在本机无法稳定保持前台，首启界面证据缺失"
                       % (offapp_run - 1, act_focus[:30]))
                log("[!] %s" % why)
                res.errors.append(why)
                break
            log("    [着陆] 重新拉起应用（第 %d 次，上限 %d 次）"
                % (offapp_run, _LANDING_RESPAWN_MAX))
            if respawn is not None:
                try:
                    respawn()
                except Exception as e:
                    log("    [.] 重拉应用失败：%s" % e)
            time.sleep(1.2)
            if time.time() >= end:
                why = "应用被退出且未能回到前台（前台：%s）" % act_focus[:30]
                break
            continue
        offapp_run = 0

        fp = ""
        try:
            fp = uiwalk.screen_fingerprint(xml, act_focus) or ""
        except Exception:
            fp = ""

        # ---- 结算上一步点击：只有到了这一屏才知道它有没有用
        if pending and 0 < pending <= len(res.click_shots):
            _pc = res.click_shots[pending - 1]
            if not _pc.get("result"):
                _pc["result"] = "new" if (fp and fp != pending_fp) else "same"
                _pc["result_fp"] = (fp or "")[:24]
            pending = 0
        # 等待 / 滑动 / 返回也要结算：携船网这一单 3 步全是"等待"，
        # 报告里"结果"一列如果全是"—"，读者就看不出等了之后到底有没有用
        # （实际是第 3 次等待之后广告结束、露出了主页面）。
        if pending_step is not None:
            _idx, _fp0 = pending_step
            if 0 <= _idx < len(steps) and not steps[_idx].get("result"):
                steps[_idx]["result"] = "new" if (fp and fp != _fp0) else "same"
            pending_step = None

        # ---- 结算上一步的同意登记（2026-11-08）
        # 为什么不像政策阶段那样"点完就记"：着陆阶段手里没有 `_tap_entry_robust`
        # 那种点击有效性信号，唯一的证据是"下一屏变没变"。而"同意"一旦被记错，
        # 整轮事件的"同意前/后"归属就全反了 —— 宁可晚一屏，也要拿指纹说话。
        #   fp 变了（new） → signal=ui，界面确实被推进了，登记为已同意；
        #   fp 没变（same）→ 不登记：点下去没反应不能算应用接受了同意。
        if pending_consent is not None:
            _pc_c = pending_consent
            pending_consent = None
            _csig = "ui" if (fp and fp != str(_pc_c.get("fp") or "")) else ""
            if _csig:
                try:
                    _mark_consent_after_tap(
                        res, _pc_c.get("node"), "首启着陆点击", log,
                        signal=_csig,
                        screen_label=str(_pc_c.get("form") or ""),
                        set_consent=(None if get_script is None else
                                     (lambda l: get_script().exports_sync
                                      .set_consent(True, l))))
                except Exception as _e:
                    log("    [.] 着陆同意登记异常（不影响后续）：%s" % _e)
            else:
                log("    [.] 上一步点的是同意类按钮，但界面没变，未登记同意动作"
                    "（避免把没生效的点击当成已同意）")
        if steps:
            _last = str(steps[-1].get("result") or "")
            if _last == "same":
                same_run += 1
            elif _last == "new":
                same_run = 0
            # ★ 其余结果（`ai_done_pending` / `tap_failed` / 空）**不动** same_run。
            #   原来写的是"只要有结果就清零"，于是 `ai_done_pending` 把它清成了 0，
            #   而 `ai_done_pending` 恰好在"卡住"时才出现 —— 等于每次刚攒起来的
            #   "这屏没反应"证据都被下一步抹掉。携船网 land5 实测就是这样死锁的：
            #   第 3、4 步各攒 1 次 → 第 5 步模型说 done（结果 ai_done_pending）
            #   → same_run 归零 → 视觉判据的门槛 `same_run >= 2` 永远不成立
            #   → 第 6 步重新数 → 10 步全在"再确认"。
            #   same_run 的语义是"连续几步没换来新界面"，只有"换了"才该清零。

        nodes = uiwalk.clickable(xml)
        # 全部节点单独留一份：开屏广告的「跳过」在很多实现里是
        # `clickable=false` 的 text 节点（uni-app / H5 / 自绘控件），
        # 只给 `clickable()` 的话会出现"认得出来、点不到"——
        # 携船网实测就是这个下场：连等 3 轮广告自己结束。
        all_nodes = uiwalk.parse_all(xml)
        texts = list(uiwalk.screen_texts(xml))
        c = landing_mod.classify(xml, res.package, nodes)
        form = str(c.get("form") or "unknown")

        # ★ 登录成功之后又回到登录页 = 登录态没保持。这时**必须收手**
        #   （2026-11-06 春雨诊所实测）：着陆会问模型"怎么进主页面"，
        #   模型看到登录页就建议点「获取短信验证码」，于是又发一条短信，
        #   发完还是进不去 —— 短信白烧，报告里却多了一行"已申请验证码"。
        #   这属于"应用没保持登录态"的事实，该如实记下并交给后续遍历，
        #   而不是靠着陆反复试。
        if res.login.get("ok") and form == "login":
            log("[!] 登录成功后又一次落回登录页（登录态未保持），着陆不再重复登录")
            res.login["dropped_after_ok"] = True
            why = "登录成功后应用又回到登录页（登录态未保持），着陆不再重复登录"
            break

        # 卡住判定：界面指纹连续不变说明这一屏没被推进
        if fp and fp == stuck_fp:
            stuck_run += 1
        else:
            stuck_run = 0
            stuck_fp = fp
            # 换了界面说明流程在推进，等待计数与滑动计数一起归零 ——
            # 否则"启动页等了 2 次 → 进了引导页 → 又等 1 次"会被误算成等满 3 次。
            wait_rounds = 0

        history.append({"form": form, "is_home": bool(c.get("is_home")), "fp": fp})
        log("    [着陆 %d] %s｜%s" % (step, c.get("name"), c.get("why")))

        # ---- ★ 到主页面了？先确认"眼前真的是这个应用"
        #   桌面也有底部导航栏（MIUI 的 dock：浏览器/电话/短信/相机），
        #   `is_home` 的结构判据会照样命中 —— 健康深圳 2026-11-10 就是这样：
        #   着陆在第 1 步把**系统桌面**判成"已到主页面"，随后整轮遍历在桌面上
        #   进行，8 屏 5 张截图全是桌面，报告还拿它当首启界面证据。
        #   闸门放在这里而不是 classify 里：classify 只看结构树，拿不到包名。
        if c.get("is_home") and _vis is not True:
            if not _home_denied[0]:
                _home_denied[0] = True
                # 措辞必须把"证据来源"写准（2026-11-10 健康深圳）：
                #   via=resumed 时 `focus` 里装的**是被测应用自己的 Activity**
                #   （`com.xky.app.patient/io.dcloud.PandoraEntry`），若照抄成
                #   "焦点不在被测应用内"，读者只会看到一句自相矛盾的话。
                #   实际情况是：窗口焦点根本取不到（mCurrentFocus=null），
                #   只知道 Activity 处于 resumed —— 它可能压根没绘制过。
                if _fg.get("via") == "resumed":
                    _why_vis = ("窗口焦点取不到（mCurrentFocus 为空），只读到 resumed 的 "
                                "Activity（%s）—— 该 Activity 可能从未真正绘制，"
                                "眼前很可能还是系统桌面" % (_fg.get("focus") or "未知"))
                elif _fg.get("via") == "window":
                    _why_vis = "当前窗口焦点是 %s（不是被测应用）" % (_fg.get("focus") or "未知")
                else:
                    _why_vis = "前台信息完全取不到（dumpsys 无输出）"
                log("[!] 结构判据判为「主页面」，但不采信：%s" % _why_vis)
                res.errors.append(
                    "着陆阶段有一次「已到主页面」未被采信：结构上出现了底部导航栏"
                    "（与系统桌面 dock 形态相同），但%s。该屏按「未能确认属于被测"
                    "应用」处理，不计入首启观测；相关界面结论只以确认在应用内的"
                    "截图为准" % _why_vis)
            c["is_home"] = False
            form = "unknown"
            history[-1]["is_home"] = False
            history[-1]["form"] = "unknown"

        # ---- 到主页面了？要连续两次（含指纹稳定）才作数
        if c.get("is_home"):
            ok, why2 = landing_mod.confirm_home(history, 2)
            if ok:
                reached = True
                home_by = "structure"
                why = why2
                log("[+] 首启着陆完成：%s" % why2)
                break
            log("    [着陆] %s，等转场稳定" % why2)
            time.sleep(0.9)
            continue

        # ---- 定动作（本地判据优先）
        act = landing_mod.plan(form, all_nodes, texts,
                               tried=list(tried.keys()),
                               back_unsafe=back_unsafe,
                               swipe_rounds=swipe_rounds,
                               wait_rounds=wait_rounds)
        used_ai = False
        ai_note = ""

        # ---- 什么时候问模型：本地判不出来、走不动了、或者本地只会"放弃"
        #   注意门槛用 can_vision() 而不是 ui_agent 开关：着陆正确与否决定
        #   整份报告能不能用，不属于"效率优化"，不该被遍历开关关掉。
        want_ai = False
        if ai_tasks is not None and ai_tasks.can_vision():
            if form == "splash_wait":
                # 启动页没什么可"看"的，问了也是白问，还占预算
                want_ai = False
            elif form == "realname_gate":
                # ★ 实名/资质认证页**不许问模型**（2026-11-06 春雨诊所）：
                #   模型的任务描述是"想办法进主页面"，看到一张表单就会建议
                #   "填写并点下一步"。而这一屏要的是真实姓名、执业证件、
                #   人脸、手写签名 —— 照它做等于替被测应用伪造一份身份材料。
                #   这不是"能不能做到"的问题，是**不许做**。
                want_ai = False
            elif ai_done_denied.get(fp, 0) >= 2:
                # 这一屏已经问过两次、模型两次都说"到了"、本地两次都不采信 ——
                # 再问只会拿到同一个答案。剩下的路交给本地判据。
                want_ai = False
                log("    [AI] 这一屏已问过 %d 次且答案不变，不再询问，按本地判据继续"
                    % ai_done_denied.get(fp, 0))
            elif form == "unknown":
                want_ai = True
            elif stuck_run >= 2:
                want_ai = True
            elif act.get("action") == "give_up" and nodes:
                want_ai = True
        if want_ai:
            ai_step = _ai_plan_step(res, ai_tasks, serial, xml, nodes,
                                    _LANDING_GOAL, step, back_unsafe, log)
            if ai_step is not None:
                ai_note = str(ai_step.get("reason") or "")[:150]
                a_node = ai_step.get("node")
                # ★ "已到主页面"不是模型有权说的话（春雨诊所 2026-11-06 实测）。
                #   门禁形态是**结构事实**：有手机号/密码输入框和注册按钮的那一屏
                #   就不是主页面，模型看截图说"到底部了"必然错。而模型在没有
                #   出路时（登录墙）特别喜欢答 done —— 因为它的任务描述是
                #   "想办法进主页面"，进不去就只能说"已经到了"。
                #   不拦的后果很具体：本地 give_up 被顶掉 → 一轮轮"再确认" →
                #   同一屏问 5 次模型、烧 10 步 92 秒，最后仍停在登录页，
                #   而且报告里那 10 步全是"判断已到主页面"，读起来像在胡说。
                #
                # ★ 但"门禁形态"这个标签本身也可能不准（携船网 2026-11-06）：
                #   uni-app 的引导层在视觉上早就消失了，节点还留在结构树里，
                #   于是本地一直认得"开屏广告页"——而截图上是清清楚楚的首页
                #   底部导航栏。留痕 #3 已经在点 y=2211 的「我的」，说明那时人
                #   就在主页面。这种"树与屏不符"有个可测的特征：**树自己列出来
                #   的控件点了没反应**（`same_run >= 2`，连点/连等都没换来新界面）。
                #   反过来，春雨诊所的登录墙是"树里根本没有能做的动作"
                #   （give_up，一个动作都没试过，`same_run == 0`）——树与屏是
                #   一致的，只是我们没有账号。两者证据强度不同，不能一刀切：
                #     · same_run <  2 → 树可信 → 形态可信 → 驳回 done，照本地走
                #     · same_run >= 2 → 树与屏不符 → 形态标签不可信 → 交给视觉
                #
                # ★ `login` 不参与上面这条豁免（故意的不对称）：
                #   真登录页都是原生控件，树与屏一般一致；而"登录页被误判成
                #   主页面"的代价是报告里写下「已进入主页面」这句**事实错误**，
                #   后面还会在登录表单上开始功能遍历。宁可这一单记"未进入"、
                #   多花几步，也不能出一句假话 —— 误报也是假话。
                _stale = same_run >= 2 and form != "login"
                if (str(ai_step.get("action") or "") == "done"
                        and landing_mod.is_gate(form) and not _stale):
                    ai_done_denied[fp] = ai_done_denied.get(fp, 0) + 1
                    log("    [AI] 模型判「已到主页面」不采信：本地看这一屏是%s，"
                        "这是明确还没到主页面的结构证据（%s），视觉判断不能推翻它"
                        % (landing_mod.form_name(form),
                           str(c.get("why") or "")[:40]))
                    # ★ 驳回也要留痕。只清空 ai 字段的话，报告那一行会写
                    #   「未询问模型」—— 而事实是我们问了、模型说"到了"、
                    #   我们没采信。两种情况对复核员的意义完全不同：
                    #   前者是"没看"，后者是"看了但判据更强的一方赢了"。
                    ai_note = ("模型答「已到主页面」，未采信：本地判据显示"
                               "这一屏是%s" % landing_mod.form_name(form))
                    ai_step = None
                    act = landing_mod.plan(form, all_nodes, texts,
                                           tried=list(tried.keys()),
                                           back_unsafe=back_unsafe,
                                           swipe_rounds=swipe_rounds,
                                           wait_rounds=wait_rounds)
                if ai_step is not None and a_node is not None:
                    # ★ 模型的答案必须过本地黑名单。它看的是截图，看不出
                    #   "这个『立即领取』点下去会拉起支付"，本地判据看得出来。
                    fr = landing_mod.forbidden(a_node, form)
                    if fr:
                        log("    [AI] 建议点「%s」被拦下：%s，改按本地判据执行"
                            % ((getattr(a_node, "label", "") or "")[:16], fr))
                        ai_note = "（模型建议被本地规则拦下：%s）" % fr
                        ai_step = None
                if ai_step is not None:
                    act = ai_step
                    used_ai = True
                    log("    [AI] %s → %s %s" % (
                        (ai_note or "（未给理由）")[:60], act.get("action"),
                        (getattr(act.get("node"), "label", "") or
                         act.get("direction", "") or "")[:16]))

        action = str(act.get("action") or "")
        node = act.get("node")

        rec: Dict[str, Any] = {
            "n": step,
            "form": form,
            "form_name": landing_mod.form_name(form),
            "read": str(c.get("why") or ""),
            "action": action,
            "target": (getattr(node, "label", "") or "").strip()[:40]
                      if node is not None else str(act.get("direction") or ""),
            "why": str(act.get("why") or act.get("reason") or ""),
            "expect": str(act.get("expect") or ""),
            "code": str(act.get("code") or ""),
            # 模型决策时，具体理由已经写进「为什么这么做」那一列，这里只说明
            # "这一步是模型定的、且过了本地禁点检查" —— 否则两列内容完全一样，
            # 读者会以为其中一列是多余的。
            "ai": ("由模型决定（已过本地禁点检查）" if used_ai
                   else (ai_note or "")),
            "anchor": bool(act.get("text_anchor")),
            "fp": (fp or "")[:24],
            "result": "",
        }

        # ---- 执行
        if action == "done":
            steps.append(rec)
            if used_ai:
                # ★ 模型说"到了"只能当**线索**，不能当结论（2026-11-06 携船网实测）：
                #   开屏广告是盖在首页之上的浮层，structure 里同时能看到
                #   `pages/expand/entry/guide` 和底下的 `pages/index/index`，
                #   模型看截图说"底部有导航栏、已到主页面"，而广告其实还没走。
                #   在广告上开始功能遍历 = 点到的都是广告位。
                #   所以这里只记一笔，回到循环顶部让本地判据（连续两次 + 指纹稳定）
                #   再确认一遍：真到了就下一轮确认成立，没到就继续渡过。
                #
                # ★ 但本地判据也有够不着的地方（同一天携船网实测）：
                #   uni-app 首页的底部导航栏渲染在 WebView 里、**不进程结构树** ——
                #   本地看到的是"底部无导航栏（0 个）、导航词 0 个、可点 5 个"，
                #   而截图上有清清楚楚的"首页 / 资讯 / 消息 / 我的"。
                #   此时若一刀切"只信本地"，就会在一个真正的主页面上反复判
                #   unknown，把整段预算耗光。折中：只有**本地判 unknown**
                #   （没有任何首启形态特征＝没有要渡过的环节）且可点元素 ≥3
                #   （排除全屏单图的广告页）且**连续两次同一界面**都这么说，
                #   才采信视觉判据，并把"这是视觉判的"写进结果。
                #
                # ★ 还有一种更隐蔽的（携船网 2026-11-06 复验）：结构树里
                #   **残留着已消失的引导层节点**（同一棵树里既有 guide 又有
                #   index），于是每轮都"看见跳过 → 点下去 → 界面不变"。
                #   这时本地永远判"广告页"，而视觉上是首页。
                #   判据：连续 2 次点击都没换来新界面（`same_run`）→ 这个
                #   "按钮"是残留的，本地判据不成立，可以采信视觉。
                # 两个入口的门槛不一样：
                #   · form == unknown：本地什么都没认出来，只能靠"可点元素够多"
                #     这一个旁证来排除全屏单图广告 → 要求 ≥3；
                #   · same_run >= 2：已经**实测**连点两次界面不变，"这个按钮是
                #     残留的"这件事本身就有证据，不该再拿可点数量当门槛 ——
                #     广告页恰恰可点最少（携船网实测 2 个），一加门槛就永远不触发。
                if (form == "unknown" and len(nodes) >= 3) or same_run >= 2:
                    if fp and fp == ai_home_fp:
                        ai_home_run += 1
                    else:
                        ai_home_run = 1
                        ai_home_fp = fp
                    if ai_home_run >= 2:
                        reached = True
                        home_by = "vision"
                        # 这一步就是结论行，必须有自己的结果与说明，否则报告里
                        # 那一行的"结果"是空的（渲染成「—」），读者看不出
                        # 是靠这一步判定的。
                        rec["result"] = "vision_home"
                        rec["form_name"] = (landing_mod.form_name(form)
                                            + "（结构树判据与截图不符）")
                        # 措辞要与**实际发生的事**对得上：这一单里 `same_run`
                        # 是"等了两轮也没跳转"攒出来的，不是"连点了两次"。
                        # 写成"连点两次没反应"会让复核员以为我们点过（携船网
                        # land7 实测：2 次点击都有反应，界面确实换了）。
                        why = ("结构树判据不成立（%s），模型连续 %d 次看图判为主页面"
                               % ("H5/自绘首页的导航栏不进入结构树" if form == "unknown"
                                  else "连续 %d 步没有换来新界面，结构树里残留着"
                                       "已经消失的节点" % same_run,
                                  ai_home_run))
                        log("[+] 首启着陆完成（视觉判据）：%s" % why)
                        break
                else:
                    ai_home_run = 0
                rec["result"] = "ai_done_pending"
                log("    [AI] 判断已到主页面；按本地判据（连续两次 + 界面稳定）再确认")
                time.sleep(0.8)
                continue
            reached = True
            why = str(act.get("why") or "已处于主页面")
            break

        if action == "give_up":
            # ★ 登录墙 + 有测试号 = 还没走完，不是"到此为止"（2026-11-06 用户口径：
            #   登录测试默认开启）。着陆阶段遇到登录页时 `landing.plan()` 只会
            #   give_up，因为 landing 模块刻意不碰账号代填 —— 那是登录辅助的活。
            #   但如果这里直接收工，默认开着登录也进不了主页面：春雨诊所、万步健康
            #   这两家同意完就落在登录/注册页，游客入口也没有。
            #   所以在这里把接力棒交给 `_login_assist()`：它负责勾同意、切短信登录、
            #   代填号码、申请验证码、等人工回填、提交。登录成功后再回到着陆循环，
            #   由本地判据重新确认主页面。
            #
            #   三条边界：
            #     · 只接 `login_wall`（游客入口 / 可关弹窗都还有别的路，先走那条）；
            #     · 整轮只接一次（`res.login["attempted"]`）—— 再试只会多刷短信；
            #     · 剩余时间不够等验证码就不开这个头（半路放弃比不开始更糟：
            #       短信已经发出去了，人还在等码）。
            _code = str(rec.get("code") or "")
            _can_login = (
                _code == "login_wall"
                and bool(login_phone)
                and not res.login.get("attempted")
                and (deadline - time.time()) > 15
            )
            if _can_login:
                steps.append(rec)
                rec["result"] = "login_assist"
                rec["why"] = ("此界面是登录/注册页且没有游客入口，但本轮配置了测试手机号，"
                              "转交登录辅助（代填号码 + 申请验证码 + 等人工回填）")
                rec["expect"] = "登录成功后回到着陆流程，重新判定主页面"
                log("[*] 登录墙：转交登录辅助，测试号 %s，等待验证码最多 %ds"
                    % (_mask_phone(login_phone), int(login_timeout)))
                try:
                    _login_assist(res, xml, serial, log, login_phone,
                                  get_sms_code, login_timeout, should_stop)
                except Exception as e:
                    log("[!] 登录辅助异常：%s" % e)
                _ok = bool((res.login or {}).get("ok"))
                if _ok:
                    rec["result"] = "login_ok"
                    log("[+] 登录成功，继续把应用带到主页面")
                    # 登录换了整套界面，之前攒的"这屏没反应""这一屏问过模型"
                    # 全部失效：不清零会让登录后的主页面被上一屏的证据拖住。
                    tried.clear()
                    same_run = 0
                    stuck_fp = ""
                    stuck_run = 0
                    wait_rounds = 0
                    swipe_rounds = 0
                    ai_done_denied.clear()
                    ai_home_run = 0
                    ai_home_fp = ""
                    # 登录本身可能超过着陆原定预算（要等人回填验证码）。
                    # 给留出几步判定主页面的余地，但不能越过整轮 deadline。
                    end = min(deadline, max(end, time.time() + 25))
                    time.sleep(1.5)
                    continue
                rec["result"] = "login_fail"
                why = ("登录页上已尝试用测试号登录，但没有完成（%s）；"
                       "不重复尝试以免重复发短信"
                       % ((res.login or {}).get("note") or "未取得验证码"))
                log("[!] 登录未完成：%s" % why)
                break
            rec["result"] = "give_up"
            steps.append(rec)
            why = str(act.get("why") or "无法继续")
            log("[!] 首启着陆停下：%s" % why)
            break

        if action == "tap" and node is not None:
            x, y = node.center
            # ★ 着陆阶段也不许"没看政策就同意"（2026-11-08）：
            #   岛 2.2.0 实测：首启隐私弹窗被判成"权限引导页"，模型直接给出
            #   tap「同 意」——政策一个字没取到，之后十几项条款比对全部落空，
            #   报告只能整片写"跳过未测"。而弹窗正文里的《隐私协议》其实点得开。
            #   所以在这里拦一次：先把政策打开读一遍（读正文 + 拿链接），
            #   回到这一屏之后下一轮再点同意。
            #   只在"确实还没拿到政策证据"时触发，拿过一次就不再打扰。
            _cst = ""
            try:
                _cst, _ = _consent_label_kind(getattr(node, "text", "") or "")
            except Exception:
                _cst = ""
            if _cst and get_script is not None and not _policy_evidence_ok(res):
                _grabbed = False
                try:
                    _grabbed = grab_policy_once(serial, res, log, get_script,
                                                "着陆阶段点同意前")
                except Exception as _e:
                    log("    [.] 同意前补做政策访问异常：%s" % _e)
                if _grabbed:
                    # 这里用独立字典，不能复用 rec：末尾还有一次
                    # `steps.append(rec)`，复用会让同一步在报告里出现两行。
                    steps.append({
                        "n": step,
                        "form": form,
                        "form_name": landing_mod.form_name(form),
                        "read": str(c.get("why") or ""),
                        "action": "policy_before_consent",
                        "target": "先打开隐私政策（再点同意）",
                        "why": ("同意之前尚未取得政策：先从当前界面打开政策页、"
                                "读取正文并取链接，回到本屏后再同意"),
                        "expect": "政策页打开并留下正文/链接证据",
                        "code": "",
                        "ai": "本地闸门（同意前强制取证）",
                        "anchor": False,
                        "fp": (fp or "")[:24],
                        "result": "policy_grabbed",
                    })
                    log("    [着陆] 政策已补做取证，下一轮再点「%s」"
                        % (getattr(node, "label", "") or "")[:14])
                    time.sleep(0.6)
                    continue
            if act.get("text_anchor"):
                # 这类点击没有"可点属性"作依据，位置对不对只能靠文字自己，
                # 所以必须写进日志：出问题时一眼能看出是这一种点击。
                log("    [着陆] 「%s」在结构树里不可点，按文字位置 (%d,%d) 点击"
                    % ((getattr(node, "label", "") or "")[:14], x, y))
            # 留痕：点之前那一屏（与功能遍历同一套标注与判读口径）
            shot_no = 0
            if len(res.click_shots) < res.max_click_shots:
                try:
                    raw = capture_screenshot(serial)
                    if raw:
                        lab = (getattr(node, "label", "") or "").strip() or "无文字入口"
                        ann = clickev.annotate(
                            raw, x, y, "%d %s" % (res.ui_taps + 1, lab[:10]))
                        tb64 = clickev.thumb(ann)
                        if tb64:
                            pred = clickev.predict(getattr(node, "label", ""),
                                                   getattr(node, "cls", ""))
                            res.click_shots.append({
                                "i": res.ui_taps + 1,
                                "t": round(time.time() - (res.started_at
                                                         or time.time()), 1),
                                "label": lab[:40],
                                "cls": (getattr(node, "cls", "") or "").split(".")[-1],
                                "uid": landing_mod.node_key(node)[:60],
                                "at": [x, y],
                                "bounds": list(node.bounds),
                                "src": "ai" if used_ai else "landing",
                                "why": clickev.describe(
                                    "ai" if used_ai else "landing",
                                    rec["why"], label=lab),
                                "kind": pred["kind"],
                                "kind_label": pred["kind_label"],
                                "expect": pred["expect"],
                                "risk": pred["risk"],
                                "fp": (fp or "")[:24],
                                "result": "",
                                "b64": tb64,
                            })
                            shot_no = len(res.click_shots)
                except Exception as e:
                    log("    [.] 着陆留痕失败（不影响点击本身）：%s" % e)
            if uiwalk.tap(serial, x, y):
                res.ui_taps += 1
                tried[landing_mod.node_key(node)] = tried.get(
                    landing_mod.node_key(node), 0) + 1
                pending = shot_no
                pending_fp = fp
                rec["target_xy"] = [x, y]
                # ★ 同意登记（2026-11-08）：着陆阶段的点击**从来**没有登记过
                #   分水岭。岛 2.2.0 land31 实测：模型在这一屏点了「同 意」，
                #   报告 P3 却写"未捕获到同意事件"——于是后面采到的每一条事件
                #   都被划进"同意前"，P1/P4 的归属全错。
                #   `_mark_consent_after_tap` 原本只在政策入口点击、政策下钻
                #   两条路上被调用，着陆这条路一处都没有。此处补上：
                #   点下去先挂起（pending_consent），下一屏指纹回来再落定。
                if _cst:
                    pending_consent = {"node": node, "form": form, "fp": fp,
                                       "label": (getattr(node, "text", "") or ""),
                                       "strength": _cst}
            else:
                rec["result"] = "tap_failed"
        elif action == "swipe":
            direction = str(act.get("direction") or "left")
            try:
                uiwalk.swipe_side(serial, direction)
            except Exception:
                pass
            swipe_rounds += 1
        elif action == "back":
            if back_unsafe:
                why = "需要返回上一级，但返回键在该界面不安全"
                rec["result"] = "back_unsafe"
                steps.append(rec)
                break
            try:
                uiwalk.back(serial)
            except Exception:
                pass
        elif action == "wait":
            wait_rounds += 1
            time.sleep(2.0)
        else:
            # 动作不认识（模型给了新词）——记下来但不动手，交给下一轮
            log("    [.] 着陆收到未知动作「%s」，本轮不执行" % action)

        steps.append(rec)
        # 动作做完先把位置记下来，下一屏拿到指纹时回写"有没有用"。
        # 只有 tap 失败这种当场就知道结局的情况不再挂结算。
        if action in ("tap", "swipe", "back", "wait") and not rec.get("result"):
            pending_step = (len(steps) - 1, fp)
        # 留一点时间等界面响应；短了下一轮读到的还是旧界面，会误判"没换屏"
        time.sleep(max(0.4, float(getattr(cfg.scan, "ui_tap_interval", 1.2)) * 0.7))

    else:
        why = why or "着陆步数用尽（%d 步）" % _LANDING_MAX_STEPS

    secs = time.time() - t0
    out = landing_mod.summary(steps, reached, why, secs)
    out["steps_detail"] = steps
    out["home_by"] = home_by if reached else ""
    out["budget"] = round(budget, 1)
    out["goal"] = _LANDING_GOAL
    res.landing = out
    if reached:
        log("[+] 首启着陆结束（%.1fs / %d 步）：%s"
            % (secs, len(steps), landing_mod.describe_path(out)))
    else:
        log("[!] 首启着陆未完成（%.1fs / %d 步）：%s；"
            "遍历将从当前界面开始，报告会注明未覆盖部分的实际原因"
            % (secs, len(steps), why))
        res.errors.append(
            "首启着陆未完成：%s。遍历从「%s」界面开始，"
            "与主页面功能相关的测评项按实际到达情况记录"
            % (why, (steps[-1]["form_name"] if steps else "未记录")))
    if on_stage:
        try:
            on_stage("首启着陆完成", 54)
        except Exception:
            pass
    return out


# ---------------------------------------------------------------- 1 档：未同意状态探索
#
# ★ 2026-11-17 使用者提出：「跑了十几个 App 的 1 档，一个同意前的实锤都没有，
#   比例上说不通；以前用 4 档还能测出来。」
#   查证结果不是判定错，而是**这一档从来没有点过任何东西**：16 轮 1 档的
#   `ui_steps` 全部 ≤1，全程静置在隐私弹窗上。合规整改之后 App 普遍把 SDK
#   初始化推迟到同意之后，静置自然一个标识符都读不到 —— 一项都判不出来，
#   不是因为"这些 App 都干净"，而是因为"我们没让它动"。
#
# 这一档的口径本来就该是「同意之前的所有界面都可以探索」：
#   · 弹窗上的政策链接、设置、关闭 —— 点了仍然在未同意状态；
#   · 「不同意 / 仅浏览 / 游客模式 / 跳过」之后的界面 —— 只要没同意，
#     主界面里的每一次读取同样发生在同意之前，而且这里恰恰是 SDK 初始化的地方。
# 所以这里比主遍历**多允许**点「不同意」「拒绝」「跳过」这类按钮：它们不会让
# 同意发生，反而是进入"未同意可用界面"的唯一入口（主遍历禁点它们，是因为
# 主遍历已在同意之后，点一下只会让 App 退出、白掉一轮）。
#
# 三条硬红线（任何一条被触碰，这一档的结论就作废）：
#   ① 同意类标签一律不点 —— `_consent_label_kind(in_policy_dialog=True)` 返回
#      非空即跳过。注意弹窗上的「确定 / 接受 / 继续」也算同意：在政策告知框上
#      点确定，就是对这段告知的接受。
#   ② 账号销毁类不点 —— 点下去账号没了，对"同意前收集"这个话题零信息量。
#   ③ 系统权限弹窗整屏不动 —— 点「允许」等于替用户授权，点「拒绝」等于替
#      用户拒绝，两者都会改写被测状态，测出来的就不再是"App 原本的行为"。
_PRE_EXPLORE_STATE_TAPS = 8      # 同一个界面最多点几个元素
_PRE_EXPLORE_IDLE = 3            # 连续几次点击界面无变化就退一层
_PRE_EXPLORE_TAP_CAP = 90        # 单轮总点击数上限（防某页面无限刷新）

# 能把"弹窗挡住的主界面"解锁出来的按钮：优先点它们，否则在一个模态弹窗上
# 点二十个背景元素也全是空转。
_PRE_EXIT_WORDS = ("不同意", "拒绝", "暂不", "仅浏览", "游客", "跳过",
                   "以后再说", "残忍", "放弃", "关闭", "不开启", "先逛逛")

# 1 档探索**额外**要拦的一批 —— 它们不是"同意"，但点了会造成不可逆后果，
# 而对这些后果，"同意前收集了什么"这个问题一点信息都换不回来：
#   · 账号销毁 / 关系解除：注销、退出登录、解绑，做了一次就没有第二次；
#   · 真实交易：点「立即支付」会真的下单扣款（被测 App 是真实环境）；
#   · 产生费用的系统动作：拨号、发短信；
#   · 直接退出应用：点了只是白掉一次 respawn，纯亏。
# 用**短语**而不是单词："支付"会误伤「支付设置」这种无害入口，
# "立即支付 / 确认支付"才是真的会扣钱的那一下。
_PRE_FORBID_WORDS = (
    "注销", "删除账号", "退出登录", "解绑", "解除绑定", "确认卸载",
    "立即支付", "确认支付", "去支付", "提交订单", "确认下单",
    "立即购买", "确认购买", "立即充值", "确认充值", "开通会员", "立即开通",
    "拨号", "呼叫", "发送短信", "发短信",
    "退出应用", "退出程序", "关闭应用",
)


def _pre_exit_word(label: str) -> bool:
    t = (label or "").strip()
    return bool(t) and any(w in t for w in _PRE_EXIT_WORDS)


def _pre_may_tap(label: str) -> bool:
    """1 档探索：这个标签能不能点。

    与主遍历的 `uiwalk.is_dangerous` 是两套口径，不能混用：
    主遍历禁「不同意/拒绝/跳过」，是因为它已在同意之后，点这些只会让 App
    退出；这一档本来就没同意，点它们正是进入未同意可用界面的唯一入口。
    """
    t = (label or "").strip()
    if not t:
        return False
    # ① 同意类：一律按"这张屏幕是政策告知框"从严判定。
    #    在告知框上，「确定 / 接受 / 继续 / 允许」都等于同意，所以整类跳过。
    kind, _why = _consent_label_kind(t, in_policy_dialog=True)
    if kind:
        return False
    # ② 不可逆 / 会花钱的动作（见 _PRE_FORBID_WORDS）
    for kw in _PRE_FORBID_WORDS:
        if kw in t:
            return False
    # ③ 二次确认型销毁动作
    for kw in uiwalk.DANGEROUS_CONFIRM_LABELS:
        if kw in t:
            return False
    return True


def _explore_pre_consent(res: ScanResult, cfg, live, deadline: float,
                         log: Callable[[str], None], *, respawn=None,
                         should_stop: Optional[Callable[[], bool]] = None,
                         on_stage: Optional[Callable[[str, int], None]] = None
                         ) -> Dict[str, Any]:
    """1 档：在**未同意**状态下尽量多点几个界面（绝不点同意）。

    返回值同时写进 `res.pre_explore`：报告要能回答"这一轮到底点了几屏、
    卡在哪一步"，否则"没发现问题"和"没测"在纸面上长得一模一样。
    """
    serial = res.device_serial
    package = cfg.scan.package
    interval = max(0.4, float(getattr(cfg.scan, "ui_tap_interval", 1.4)))
    t0 = time.time()
    span = max(1.0, deadline - t0)
    out: Dict[str, Any] = {
        "taps": 0, "screens": 0, "visited": [], "refused_exit": [],
        "skipped_consent": 0, "perm_dialogs": 0, "budget": round(span, 1), "why": "",
    }
    # 先落盘再干活：中途异常中断时，报告仍能看到"点过几屏"，
    # 而不是因为异常回滚成"没探索"。
    res.pre_explore = out
    seen: set = set()
    idle = 0
    state_taps = 0
    state_key = ""
    no_cand = 0
    last_label = ""
    last_was_exit = False
    _cached_xml = None       # 点击后抓到的结构树，界面没再变就下一轮直接复用
    log("[*] 1 档探索：在未同意状态下点击界面（上限 %ds / %d 次，绝不点同意）…"
        % (int(span), _PRE_EXPLORE_TAP_CAP))

    while time.time() < deadline:
        if should_stop and should_stop():
            out["why"] = "收到停止请求"
            break
        # ★ 硬断言：同意一旦被登记，这一档的口径就作废了。宁可停在这里，
        #   也不能把"同意后"的行为记成"同意前"——那是把违规洗白的方向。
        if getattr(res, "consent_given", False):
            out["why"] = "检测到已登记同意动作，立即中止"
            res.errors.append(
                "1 档探索途中检测到「同意」动作已被登记，已立即中止探索；"
                "本轮不能作为「同意前」的证据使用")
            log("[!] 1 档探索：检测到同意动作已登记，立即中止")
            break
        if out["taps"] >= _PRE_EXPLORE_TAP_CAP:
            out["why"] = "达到单轮点击数上限 %d" % _PRE_EXPLORE_TAP_CAP
            break

        fg = uiwalk.foreground(serial)
        pkg_now = str(fg.get("package") or "").strip()
        act_now = str(fg.get("activity") or "").strip()

        # ---- 前台不在被测应用上 ----
        if pkg_now and pkg_now != package:
            # ① 系统权限弹窗：**整屏不点**。点「允许」等于替用户授权，
            #    点「拒绝」等于替用户拒绝 —— 两者都会改写被测状态，之后
            #    测到的就不再是"App 原本的行为"。直接退掉，只记一笔事实。
            #    这里也绝不能当成"App 退出"去 respawn：弹窗一出现就重启，
            #    一轮下来什么都测不到。
            if any(pkg_now == p or pkg_now.startswith(p + ".")
                   for p in uiwalk.PERM_PACKAGES):
                out["perm_dialogs"] = int(out.get("perm_dialogs") or 0) + 1
                log("[*] 1 档探索：出现系统权限弹窗（%s），按 BACK 关闭、不代为作答"
                    % pkg_now)
                uiwalk.back(serial)
                time.sleep(max(0.8, interval * 0.6))
                state_key = ""
                _cached_xml = None
                continue
            # ② 跳到别的应用（浏览器看政策、拉起微信登录）：先 BACK 一次看能不能回来。
            #    直接 respawn 的代价是 5~30 秒重注入，而多数外跳一步 BACK 就回来了。
            if not uiwalk.is_launcher_pkg(pkg_now):
                uiwalk.back(serial)
                time.sleep(max(0.8, interval * 0.6))
                fg = uiwalk.foreground(serial)
                pkg_now = str(fg.get("package") or "").strip()
                act_now = str(fg.get("activity") or "").strip()
                _cached_xml = None
                if pkg_now == package:
                    continue
            # ③ 确实退出了（点了「不同意」/被系统清掉）
            if last_was_exit and last_label:
                out["refused_exit"].append({"label": last_label, "pkg_after": pkg_now})
                # 这条本身就是一个可复核的事实：未同意时该应用不给用。
                # 报告里要能看到"点了哪个按钮之后退到了哪"，否则这一整轮
                # 就只剩一句"没采到"。
                res.ui_steps.append(
                    "未同意状态：点击「%s」后应用退出（前台 %s）"
                    % (last_label[:20], pkg_now))
                log("[*] 1 档探索：点「%s」后应用退出（前台 %s）"
                    % (last_label[:20], pkg_now))
                out["why"] = "点击「%s」后应用退出" % last_label[:20]
                last_was_exit = False
                last_label = ""
            if callable(respawn):
                try:
                    if respawn():
                        time.sleep(max(2.0, interval))
                        state_key = ""
                        state_taps = 0
                        no_cand = 0
                        _cached_xml = None
                        continue
                except Exception as e:
                    log("[!] 1 档探索：重新拉起失败：%s" % e)
            out["why"] = out["why"] or "应用已不在前台，无法继续探索"
            break

        # 上一轮点击后刚 dump 过、且界面没再变动，就直接复用那份结构树。
        # 一次 dump 在真机上要 2~8 秒，每一步都重抓等于把预算砍掉一半。
        xml = _cached_xml or uiwalk.dump_retry(serial, tries=2, wait=0.5)
        _cached_xml = None
        if not xml:
            out["why"] = "结构树连续取不到（设备侧 uiautomator 无响应）"
            break

        # 换屏了才记一屏、才拍一张图（1 档总共 20 张配额）
        fkey = uiwalk.focus_key(act_now) if act_now else ""
        if fkey and fkey != state_key:
            state_key = fkey
            state_taps = 0
            out["screens"] += 1
            _lam = act_now.split(".")[-1] if act_now else "未知界面"
            if _lam not in out["visited"]:
                out["visited"].append(_lam)
            observe_screen(res, "未同意探索：%s" % _lam, serial, xml=xml)
            log("[*] 1 档探索：进入「%s」（第 %d 屏）" % (_lam, out["screens"]))

        if state_taps >= _PRE_EXPLORE_STATE_TAPS:
            uiwalk.back(serial)
            time.sleep(max(0.8, interval * 0.6))
            state_taps = 0
            state_key = ""
            _cached_xml = None
            continue

        nodes = [n for n in uiwalk.parse_all(xml)
                 if n.clickable and n.enabled and not uiwalk.is_no_use(n)]
        cands = []
        for n in nodes:
            lab = (n.label or "").strip()
            if not lab or n.key in seen:
                continue
            if not _pre_may_tap(lab):
                # 同意类：记一笔就永久跳过，绝不因为"这一屏别的都点过了"再回来点它
                out["skipped_consent"] += 1
                seen.add(n.key)
                continue
            cands.append(n)

        if not cands:
            no_cand += 1
            if no_cand >= 2:
                out["why"] = out["why"] or "当前界面没有未点过的可点元素"
                break
            uiwalk.back(serial)
            time.sleep(max(0.8, interval * 0.6))
            state_key = ""
            _cached_xml = None
            continue
        no_cand = 0

        # 解锁类按钮优先：模态弹窗上点背景元素全是空转
        cands.sort(key=lambda n: (0 if _pre_exit_word(n.label) else 1,
                                  len((n.label or "").strip())))
        node = cands[0]
        label = (node.label or "").strip()[:20]
        before_texts = set(uiwalk.screen_texts(xml))

        try:
            uiwalk.tap(serial, *node.center)
        except Exception as e:
            log("[!] 1 档探索：点击「%s」失败：%s" % (label, e))
            seen.add(node.key)
            continue
        res.ui_taps += 1
        out["taps"] += 1
        state_taps += 1
        seen.add(node.key)
        last_label = label
        last_was_exit = _pre_exit_word(label)
        # 步骤文字里必然带「同意」二字（「未同意状态：点击「不同意」」），
        # 所以判定层**不能**再靠"遇到含同意的步骤就切分"来数探索步数 ——
        # 那样会把整段探索当成同意动作截掉。判定层改读 `res.pre_explore`。
        res.ui_steps.append("未同意状态：点击「%s」" % label)
        if on_stage:
            try:
                on_stage("未同意探索", min(84, 58 + int(24 * min(1.0, (time.time() - t0) / span))))
            except Exception:
                pass
        time.sleep(interval)

        # ---- 这一下有没有效果 ----
        fg2 = uiwalk.foreground(serial)
        pkg2 = str(fg2.get("package") or "").strip()
        if pkg2 and pkg2 != package:
            continue            # 退出到别的应用，回到循环开头处理
        xml2 = uiwalk.dump_retry(serial, tries=1, wait=0.3)
        after_texts = set(uiwalk.screen_texts(xml2)) if xml2 else set()
        if act_now != str(fg2.get("activity") or "").strip() or before_texts != after_texts:
            idle = 0
            _cached_xml = xml2      # 界面确实变了：下一轮直接复用这份，省一次 dump
        else:
            idle += 1
            if idle >= _PRE_EXPLORE_IDLE:
                uiwalk.back(serial)
                time.sleep(max(0.8, interval * 0.6))
                idle = 0
                state_key = ""
                state_taps = 0

    out["seconds"] = round(time.time() - t0, 1)
    if not out["why"]:
        out["why"] = "时间用尽" if time.time() >= deadline else "已结束"
    log("[*] 1 档探索结束：点击 %d 次、经过 %d 屏、跳过同意类 %d 个（%s）"
        % (out["taps"], out["screens"], out["skipped_consent"], out["why"]))
    # 日志里点了几屏这件事必须同时在界面上可见：否则"这一档到底测了什么"
    # 只能靠翻 result.json 猜。
    if out["taps"]:
        res.errors.append(
            "1 档（仅同意前）：在未同意状态下点击 %d 次、经过 %d 屏（%s）；"
            "全程未点击同意，本轮所有事件均属同意前"
            % (out["taps"], out["screens"], out["why"]))
    else:
        res.errors.append(
            "1 档（仅同意前）：未能在未同意状态下点到任何界面元素（%s）；"
            "同意前的收集行为可能未被触发，结论偏保守" % out["why"])
    return out


def _walk_ui(res: ScanResult, cfg, live, deadline: float,
             log: Callable[[str], None], respawn=None, rehook=None,
             ai_tasks: Optional[AITasks] = None,
             started_at: float = 0.0,
             should_stop: Optional[Callable[[], bool]] = None,
             login_phone: str = "",
             get_sms_code: Optional[Callable[[], str]] = None,
             login_timeout: int = 180,
             on_stage: Optional[Callable[[str, int], None]] = None) -> None:
    """UI 自动遍历：反复 dump 界面并点击未见过的元素，直到时间耗尽。

    三条防线（都是真机踩出来的）：
      · **锁在目标 App 内**：每轮先看前台包名，一旦跑到桌面/别的应用，
        立刻 BACK 返回，连续两次回不来就重新拉起 App。
      · **不点危险按钮**：点中「不同意」会让 App 退出，再拉起又弹同一个框，
        形成死循环（实测 50 秒点了 5 次「不同意」，一无所获）。
      · **App 崩溃/退出后自动重启并重新注入**：不重新注入的话，进程一死
        hook 全丢，后面全是空转 —— 这是"感觉没利用手机"的直接原因。

    ★ AI 的参与方式（开启 ai.features.ui_agent 时）：
      每一步把**当前截图 + 可点元素清单 + 已做过的操作 + 本阶段目标**交给
      视觉模型，由它决定点哪里/往哪滑。相比原来「按优先级取第一个可点节点」，
      区别在于模型知道自己在找什么、走到第几步了、这一屏哪个元素最接近目标。
      安全上没有放松：模型选中的目标在执行前仍要过一遍本地的危险按钮检查，
      模型连续失败会自动停用并退回规则遍历。
    """
    seen: set = set()
    visited_fps: Dict[str, int] = {}
    # 诊断计时（PIISCAN_PROF=1）：把每轮 adb 往返计入 PROF，心跳处按轮打印。
    if os.environ.get("PIISCAN_PROF") == "1":
        uiwalk.prof_enable(True)
        uiwalk.prof_reset()
        log("[耗时] 已开启轮级计时（PIISCAN_PROF=1）")
    p1_shot_tries = 0        # 「同意前那屏」补拍次数（见下方补拍逻辑）
    hook_dead_noted = False  # 注入已被加固终止这件事只提示一次，避免刷屏
    interval = max(0.4, float(getattr(cfg.scan, "ui_tap_interval", 1.2)))
    shot_every = max(1, int(getattr(cfg.scan, "shot_every_taps", 4)))
    package = cfg.scan.package
    idle = 0
    dumps_failed = 0
    # 屏幕状态检查的节流表（见 `_check_screen`）
    _scr_walk: Dict[str, float] = {}
    dump_run = 0             # 连续导出失败次数（成功一次即清零，见 _DUMP_GIVEUP）
    ui_degraded = False
    deg_loops = 0
    escapes = 0
    # 有取证价值的外跳次数（系统设置里的权限页、第三方授权页）。
    # ★ 与 `escapes` 分开：`escapes` 是"无效点击"的熔断计数（跳商店/相册/桌面），
    #   一次"点微信登录拿到了授权页"不该算进无效点击，否则一轮里跳三次登录
    #   就会触发"多次离开目标 App，停止遍历"。
    jumps = 0
    _jump_warned = False
    relaunches = 0
    # 本档允许的重启次数（见下面"重启上限按档位给"的注释）。
    _max_relaunch = max(1, int(getattr(cfg.scan, "max_relaunch", 4) or 4))
    last_alive_check = 0.0
    last_hook_check = 0.0
    # ---- 注入自救的次数上限（2026-11-05）----
    # 万步健康那一单：3693 秒里 frida 脚本失效 126 次（重新附着 43 次、冷启动重建
    # 83 次），每次 20~30 秒 —— 一小时预算几乎全花在"重新注入"上，真正点到的
    # 只有 6 次。加固类应用会让脚本反复失效，重注入救不回来，这是事实；
    # 但**继续重试是错的处置**：界面覆盖、政策、权限弹窗不依赖 hook，仍然有效。
    # 到量就转"仅界面采集"，并把"从此刻起事件不完整"写进报告。
    hook_tries = 0
    HOOK_TRY_CAP = 6
    last_escape_at = 0.0
    overlay_checked_at = 0.0
    prev_fp = ""
    # 待结算的点击留痕编号（res.click_shots 的 1 基下标）。点击之后要等下一屏
    # 出来才知道"这一击到底有没有换界面"，所以记在这里等下一轮补写。
    pending_click = 0
    last_tap_key = ""
    last_tap_node: Any = None
    # 上一次点击的时刻。用来判断「这次离开被测应用」是不是由这次点击造成的
    # （见 FOREIGN_CAUSE_WINDOW）：没有这道判据，设备上原本开着的设置页/浏览器
    # 会被归因到最近点过的入口，报告里就凭空多出一条因果。
    last_tap_at = 0.0
    # 点了会跳出被测应用的入口（按标签记）。会话内不再点第二次。
    #
    # ★ 为什么需要：收回运行时权限之后，「相册」这类入口会拉起系统的图片
    #   选择器，前台包名当场变成别人的 → 按返回退回来 → `seen.clear()` 之后
    #   这一屏的入口又变成"可点"的，于是下一轮调度再点一次。
    #   mbsf20 实测：同一屏的「相册」被点了 4 次（第 12/13/19/20 步），
    #   每次都只是进系统选择器再退回来，一次新界面都没多到。
    #   不把这类入口记下来，权限一收回就会稳定浪费预算 —— 而浪费多少
    #   取决于系统选择器弹几次，这本身就是轮次之间覆盖差异的来源。
    foreign_labels: set = set()
    stuck = 0
    back_unsafe = False
    # ---- 空转熔断（2026-11-01）----
    # 原来的 `stuck` 只统计"点击后界面没变"，返回与滑动一次都不计。
    # 真机实测（2026-10-31 那批 4 档 / 1 小时）：
    #   · 看个比赛 387 步里 297 步是「AI：返回上一级」、67 步是滑动，真点击 9 次；
    #   · 冰纷万象 191 步里 176 步是「AI：向 up 滑动」，真点击 4 次。
    # 一小时预算全花在同一屏上反复返回/滑动，可探索的界面一个都没多 ——
    # 这就是"1 小时档和 15 分钟档结果没有本质区别"的全部原因。
    # 所以要把"同一界面上同一个动作连续无效"也管起来，到量就封禁该动作。
    act_run: Dict[str, int] = {}     # 本屏各动作连续无效次数（键含 "__total__"）
    act_banned: set = set()          # 本屏已判定无效、不许再执行的动作
    # 已判定「无可探索入口」的界面指纹。再次回到这些界面时不再重复探测 ——
    # 否则"离开失败 → 重来 12 个动作 → 再离开"会把整轮预算吃光
    # （高途 2026-11-05：75 次「连续 12 个动作没换界面」）。
    exhausted_fps: set = set()
    # 已榨干界面上"按了返回却仍停在这一屏"的次数。两次不走就改重拉 —— 表单页/
    # WebView 会把 BACK 吃掉当作历史导航，只按返回永远出不去。
    exhausted_backs: Dict[str, int] = {}
    last_act_sig = ""                # 上一步执行的动作签名（见 _note_act_result）
    last_act_uid = ""                # 上一步若是点击，记下被点的元素身份（循环观测用）

    # ---- 遍历台账 + 循环观测（2026-11-01）----
    # 上面那套 `act_run/act_banned` 只看"界面指纹变没变"，对 A↔B 这种**每步都换屏**
    # 的振荡完全失明。真机实测（川剧迷 / 冰纷万象 两个 1 小时档）：
    #   496 步里 410~449 步是同一对「点一下 → 退回」的来回，
    #   每一步"界面都变了"，熔断一次都没触发，1 小时预算 90% 花在同一处。
    # 所以补两层：
    #   · `ledger` 记 (界面, 元素) 的**执行次数**，超过上限就不许再点 ——
    #     这一层不看是谁选的（模型/图排序/规则），是唯一的一份账；
    #   · `watch` 看**动作序列的周期性**与"距上一个新界面多少步"，
    #     判振荡（还能救：换屏）与僵局（救不回来：提前收工）。
    ledger = (ledgermod.ActionLedger(
        tap_limit=int(getattr(cfg.scan, "walk_tap_limit", 2) or 2),
        freeze_sec=float(getattr(cfg.scan, "walk_freeze_sec", 180) or 0))
        if ledgermod is not None else None)
    watch = (ledgermod.LoopWatch(
        sat_actions=int(getattr(cfg.scan, "walk_sat_actions", 30) or 30),
        min_actions=int(getattr(cfg.scan, "walk_sat_min_actions", 45) or 0))
        if ledgermod is not None else None)
    osc_rounds = 0                   # 本轮已处理的振荡次数（升级用：封屏 → 重启 → 收工）
    led_blocks = 0                   # 被台账拦下的点击次数
    # 同一屏被台账连续拦下的次数。★ 必须有这道计数：被拦下的点击**不产生动作**，
    # 循环观测里的动作数不增加，`stalled()` 永远不会成立 —— 万一某个界面所有入口
    # 都被点满，这里就会变成"每 1.2 秒判一次、永远不前进"的空转。
    led_streak = 0
    led_streak_fp = ""
    stop_reason = ""                 # 提前收工的原因（写进报告）
    # 无进展看门狗（见 _IDLE_RESPAWN_AT 的说明）：进展 = 执行了动作 / 多了留痕 /
    # 图谱多了新界面。**不含界面指纹** —— 轮播、动画、实时画面会让同一屏的指纹
    # 每轮都变，那会把"零进展"伪装成"一直在推进"。
    last_progress: tuple = (-1, -1, -1)
    idle_rounds = 0
    idle_fp = ""                     # 停在哪个界面（按屏限次重拉）
    idle_respawn_by_fp: Dict[str, int] = {}
    idle_respawn_total = 0
    # 秒级停滞熔断（见 _STALL_RESPAWN_SECS 的说明）。用 list 包一层是为了让
    # 下面的闭包/内联赋值都能改到它，不需要 nonlocal。
    _stall_clock = [time.time()]     # 上一次"真的有进展"的时刻
    _stall_seen = [-1, -1]           # 快照：见过的界面数 / 点过的不同入口数
    _stall_respawned = [False]       # 秒级判据是否已经重拉过一次
    # 登录门：哪些入口点进去只是登录页（下一轮不再点它），以及连续被挡的轮数。
    # ★ 按**元素身份**记而不是按文字：携船网首页那些入口全是「FrameLayout」
    #   （没有文字也没有 id），按文字记会把整屏入口一起剔掉。
    login_gate_uids: set = set()
    login_gate_labels: List[str] = []  # 被登录门挡住的入口名（只用于写报告文案）
    # 登录墙早停（2026-11-04）：确认这么多个**不同入口**都只是登录页后收工。
    # 依据是携船网实测：首页 12 个入口点进去全是同一个登录页，40+ 轮里
    # 41 次是"从登录页退回上一级"，一次新界面都没换来 —— 继续点的边际收益是 0。
    # 定 5 而不是 2~3：避免把"某几个入口恰好要登录、其余能看"误判成整站要登录。
    _LOGIN_GATE_STOP = 5
    login_gate_hits = 0
    # 连续"停在登录页"的轮数：用来判返回键失效（见登录门里的说明）。
    # 走到正常界面（clicks_all 那一行之前）即清零，所以它只累计"没走出去"的连续次数。
    gate_back_run = 0
    # 因"登录页返回无效"重拉应用的次数。非零 + 重拉后仍是登录页 = 冷启动就落在
    # 登录页（没有"无需登录的首屏"），属于登录墙的第二种形态。
    gate_respawns = 0
    # 上一轮结束时是否停在登录页（判"进登录页"还是"在登录页里点来点去"）。
    _login_prev_round = False
    # 登录页上的返回键会把 App 退掉（春雨诊所 SignInActivity）：确认过一次就换招。
    login_back_unsafe = False
    login_repeat_fp: set = set()      # 登录成功后又回到登录页的界面（只记一次）
    lost_focus_n = 0                  # "前台不在 App 里却归因不到点击"的次数
    # 连续"重拉之后应用仍然没出现在前台"的次数。到量就收工：这类应用
    # （加固壳自杀 / uni-app 起不来）再拉多少次都不会产生新证据。
    visible_fail = 0

    def _led_uid(node: Any) -> str:
        """当前界面上这个元素的**统一身份**（与图谱、调度器同一套 uid）。"""
        if obs is None:
            return ""
        try:
            return obs.uid_for(node)
        except Exception:
            return ""

    def _led_ok(fp: str, node: Any) -> str:
        """这个点击还能不能做。返回空串 = 可以，否则是拦截原因。"""
        if ledger is None:
            return ""
        return ledger.tap_blocked(fp, _led_uid(node))

    # 当前界面 fp 的持有者：`_do_back` 这类深层函数拿不到循环里的局部变量，
    # 但台账要按"在哪个界面按的返回"记账（同一屏返回 225 次就是循环的证据）。
    _fp_now: Dict[str, str] = {"fp": ""}
    # 外部接管时"本屏已排好的后续步骤"（见 `_oracle_step`）。
    # 用 dict 持有而不是两个变量：闭包里改 dict 内容不需要 nonlocal。
    _oplan: Dict[str, Any] = {"fp": "", "items": []}
    # 已经提示过"本屏有遮挡"的界面（同一个界面只报一次，不然 errors 会被灌满）
    occ_seen_fp: set = set()
    # 已经提示过"本屏有入口因需登录被剔除"的界面（同一个界面只报一次）
    gate_seen_fp: set = set()
    # 已经留过证的"打不开的页面"（同一个错误页只记一次、只拍一张）
    err_page_fp: set = set()
    err_shots = 0
    # 广告落地页：同一页只记一次、只拍两张（见下面「广告落地页」那段）
    ad_page_fp: set = set()
    ad_shots = 0
    # 调研/选择页（2026-11-06 高途实测）：首启问卷（选学段/身份 →「进入首页」）
    # 被当成功能遍历、选项被逐个当"入口"点。改为模仿真实用户：选一项 + 提交。
    # survey_steps 封顶：多题问卷（学段→年级→科目）常见 2~4 屏，超过 8 步
    # 还在同一类页面上打转，说明判据出问题了，宁可退回普通遍历。
    survey_steps = 0
    survey_tried: List[str] = []
    SURVEY_STEP_CAP = 8

    def _led_act(sig: str) -> str:
        """返回/滑动在本屏是否已超次数上限。空串 = 还可以做。"""
        if ledger is None:
            return ""
        return ledger.act_blocked(_fp_now["fp"], sig)

    def _plan_to_step(item: Dict[str, Any],
                      pool: List[Any]) -> Optional[Dict[str, Any]]:
        """把外部排好的一条计划转成可执行的 step。

        元素在这一屏上已经不存在 → 返回 None（调用方作废整份计划）。
        绝不"按老坐标点一下试试"：点空位置只会换来一次无效动作，
        还会被记成"点过了"。
        """
        try:
            act = str(item.get("action") or "")
            why = "接管（计划）：" + (str(item.get("why") or "").strip() or "—")
            if act == "tap":
                uid = str(item.get("uid") or "")
                for n in pool:
                    try:
                        if (_led_uid(n) or ("xy:%d,%d" % n.center)) == uid:
                            return {"action": "tap", "node": n, "reason": why,
                                    "oracle": True}
                    except Exception:
                        continue
                return None
            if act in ("back", "swipe"):
                out: Dict[str, Any] = {"action": act, "reason": why, "oracle": True}
                if act == "swipe":
                    out["direction"] = str(item.get("dir") or "up")
                return out
        except Exception:
            return None
        return None

    def _oracle_step(xml_now: str, back_ok: bool,
                     hint: str = "") -> Optional[Dict[str, Any]]:
        """问外部"这一步做什么"，返回与 `_ai_plan_step` 同格式的 step。

        候选**照搬程序化探测的优先级**，不重排 —— 外部看到的应当是
        "程序认为该点的顺序 + 每项在本屏已点几次"，据此判断跳过哪个。
        若要重排，就等于把程序化探测的结果丢掉一半。
        """
        if _oracle is None:
            return None
        # 与规则分支同一口径：被压住的入口不给外部选，免得它也点空。
        try:
            _occ = uiwalk.occluded_map(xml_now)
        except Exception:
            _occ = {}
        # 先看有没有"本屏已排好的计划"：一屏一次往返太慢（人也有别的事），
        # 允许外部一次给这一屏要点的几步。界面一变，计划立刻作废 ——
        # 上一屏排的步骤套到新界面上，就是照着旧地图走新路。
        if _oplan["items"] and _oplan["fp"] == (_cur_fp or ""):
            try:
                _pool0 = [n for n in uiwalk.clickable(xml_now)
                          if uiwalk.node_key(n) not in _occ]
            except Exception:
                _pool0 = []
            item = _oplan["items"].pop(0)
            step_i = _plan_to_step(item, _pool0)
            if step_i is not None:
                return step_i
            _oplan["items"].clear()
        elif _oplan["items"]:
            _oplan["items"].clear()
        try:
            pool = uiwalk.clickable(xml_now)
        except Exception:
            return None
        if _occ:
            pool = [n for n in pool if uiwalk.node_key(n) not in _occ]
        rows: List[Dict[str, Any]] = []
        by_uid: Dict[str, Any] = {}
        for n in pool:
            try:
                if uiwalk.is_dangerous(n) or uiwalk.is_no_use(n):
                    continue
                uid = _led_uid(n) or ("xy:%d,%d" % n.center)
            except Exception:
                continue
            if not uid or uid in by_uid:
                continue
            by_uid[uid] = n
            rows.append({
                "i": len(rows),
                "uid": uid,
                "label": (getattr(n, "label", "") or "")[:60],
                "cls": (getattr(n, "cls", "") or "").split(".")[-1],
                "b": list(getattr(n, "bounds", (0, 0, 0, 0))),
                "c": list(getattr(n, "center", (0, 0))),
                "tapped": (ledger.tap_count(_cur_fp, uid)
                           if ledger is not None else 0),
            })
        try:
            payload = oraclemod.build_payload(
                activity=str(getattr(obs, "activity", "") or "") if obs is not None else "",
                fp=_cur_fp or "",
                cands=rows,
                prev=list(res.ui_path[-10:]),
                states=len(getattr(watch, "states", []) or []),
                taps=res.ui_taps or 0,
                steps=len(res.ui_path),
                blocked=list(act_banned),
                allow_back=bool(back_ok),
                hint=hint)
            ans = _oracle.ask(payload, capture_screenshot(res.device_serial), log)
        except Exception as e:                # 外部通道自身出错不能拖垮采集
            log("    [接管] 通道异常（%s），退回本地 AI" % e)
            return None
        if not ans:
            return None
        act = str(ans.get("action") or "").strip()
        why = "接管：" + (str(ans.get("why") or "").strip() or "（外部未给理由）")
        # 本屏后续步骤（可选）。约定 plan 只放**当前动作之后**的步骤，
        # 否则同一个元素会被点两次（一次现在、一次按计划）。
        if isinstance(ans.get("plan"), list):
            _items = [p for p in ans["plan"] if isinstance(p, dict)]
            _oplan["fp"] = _cur_fp or ""
            _oplan["items"] = _items
        if act == "tap":
            node = by_uid.get(str(ans.get("uid") or ""))
            if node is None:
                # 也允许按序号指定：uid 很长，手抄容易错一位。
                try:
                    node = by_uid[rows[int(ans.get("i"))]["uid"]]
                except Exception:
                    node = None
            if node is None:
                log("    [接管] 指定的目标不在本屏候选里，退回本地 AI")
                return None
            return {"action": "tap", "node": node, "reason": why, "oracle": True}
        if act in ("back", "swipe"):
            out: Dict[str, Any] = {"action": act, "reason": why, "oracle": True}
            if act == "swipe":
                out["direction"] = str(ans.get("dir") or "up")
            return out
        log("    [接管] 未识别的动作 %r，退回本地 AI" % act)
        return None


    # ---- 可重放路径的记账入口 ----
    # 只在动作**真的执行成功**时调用。判据统一在这里，免得每个执行点各写一遍
    # （写漏一处，复现轮就会少走一步，报告却说"按原路径重放"）。
    def _rec(kind: str, **kw: Any) -> None:
        if replaymod is None:
            return
        try:
            it = replaymod.norm(kind, **kw)
            if not it:
                return
            # 用遍历起点算相对时刻，和 `ui_steps` 的序号能对上，
            # 排查"第 17 步为什么没复现"时不用自己数。
            if "t" not in it and started_at:
                it["t"] = round(time.time() - started_at, 1)
            res.ui_path.append(it)
        except Exception:
            pass
    # 权限弹窗取证用：已记录过的弹窗指纹（避免同一弹窗反复记），
    # 以及"弹窗之前那一屏 App 界面"的文字（用途说明常在这里）。
    perm_seen: set = set()
    last_app_texts = ""
    # AI 相关状态。连续失败若干次就停用它 —— 模型服务中途挂掉时，
    # 继续每步都等它超时会把整个采集时间耗光。
    ai_fails = 0
    ai_steps = 0
    ai_waits = 0                # 连续"等一等"次数（空白页会让模型一直等下去）
    ai_disabled = False
    # ★ 2026-11-01 二审：原来"连续失败 3 次"是**永久停用**，且不区分
    #   "这屏模型答不出来"与"模型服务挂了"。真机踩得很重：冰纷万象是
    #   自绘界面（结构树几乎没节点），模型在引导页连答 3 次空 → AI 被永久关掉
    #   → 之后 4300 秒全走兜底滑动，连后面正常的设置页也没再过问 AI。
    #   现在分两层：本屏连败 3 次只停这一屏，换屏自动恢复；
    #   全程累计失败到 AI_FAIL_CAP 才认定是服务真的不可用、彻底停掉
    #   （超时一次 90 秒，12 次封顶，不会把预算烧穿）。
    ai_fails_total = 0
    ai_fail_fp = ""
    AI_FAIL_CAP = 12
    # 外部决策通道（见 flow/oracle.py）。默认关闭；设了 PIISCAN_ORACLE_DIR 才启用。
    _oracle: Any = None
    oracle_steps = 0                 # 由外部接管的步数（写进报告，便于对照）
    if oraclemod is not None:
        try:
            if oraclemod.enabled():
                _oracle = oraclemod.Oracle()
                log("[*] 外部接管已启用：遍历每一步的决策交外部（%s），本地模型不参与选择"
                    % oraclemod.root())
        except Exception:
            _oracle = None
    ai_used = 0                 # 实际发起过的 AI 决策次数
    ai_capped_logged = False
    loop_i = 0                  # 遍历循环次数（用于节流）
    # 节流闸门：遍历每步都问模型在真实环境里代价很高 —— 本地 CPU 推理每步几十秒、
    # 云端 API 按量计费、中继模式下更会产生上百次人工往返。用「每 N 步问一次」
    # 与「总次数上限」两个旋钮把成本压在可接受范围，中间步骤照旧走规则遍历。
    ai_every = max(1, int(getattr(cfg.ai, "ui_agent_every", 1) or 1))
    ai_max = max(0, int(getattr(cfg.ai, "ui_agent_max_calls", 0) or 0))
    # 节点级节流：同一个界面最多问几次模型（0 = 不限，等于每步都问）。
    # ★ "这屏该点哪个入口"是**节点级决策**：界面没变时重复问，答案不会变，
    #   只是把点击预算换成等待时间。真机实测（mbsf9，每步都问）：26 次决策
    #   换 12 次点击，而无 AI 遍历的同预算能点 45 次。
    ai_per_node = max(0, int(getattr(cfg.ai, "ui_agent_per_node", 1) or 0))
    ai_asked: Dict[str, int] = {}
    # 模型对该界面最后一次选中**什么动作**。
    # ★ 节流只允许在"模型上次选的是 tap"时生效 —— 如果它选的是 back/scroll，
    #   说明它判断这屏该离开（真机 mbsf10：模型说"登录非合规入口，返回"，
    #   节流却按图排序把「登录」点了，方向被规则反过来）。那种情况下宁可再问一次。
    ai_last_action: Dict[str, str] = {}
    # 走过的节点序列（只在换屏时追加），用来给选项生成器传"上一步在哪"。
    # 目的只有一个：掐住 A↔B 的两节点死循环（见 kgraph.options 的 avoid_nid）。
    visit_nids: List[str] = []
    # ★ 等 AI 的时间不算采集时间。
    # 中继模式（对话里的 AI 作答）或本地 CPU 推理，一次决策可能要几十秒，
    # 而这段时间设备只是停在原地等。若把它算进预算，遍历会被挤到只剩几秒 ——
    # 实测：100 秒的设定里 90 秒耗在等 AI 上，遍历只跑了 1 次点击。
    # 所以把「明显在等模型」的那部分补回 deadline，并同时从阶段目标的时间进度里扣掉。
    ai_extra = 0.0
    AI_WAIT_FREE = 3.0        # 本地模型通常几秒内返回，不补；超过这个数才算"在等人/慢模型"
    AI_WAIT_CAP = 1800.0      # 补偿上限，避免异常情况下无限延长
    span = max(1.0, deadline - (started_at or res.started_at or time.time()))
    last_ai_reason = ""

    # ---- 页面图观测（Step 1：只记录轨迹，不参与任何决策）----
    # 打开它，遍历行为与关闭时**逐字节一致**，只是多记一份"走到过哪里"；
    # 关掉（scan.crawl_observe=false）则完全回到旧行为。所有观测代码都包了
    # try/except —— 记轨迹失败绝不能拖垮采集。
    obs = None
    if pagegraph is not None:
        try:
            if pagegraph.enabled(cfg):
                obs = pagegraph.PageGraph(package)
        except Exception:
            obs = None

    # ---- App 知识图谱（语义节点 + 图引导）----
    # 必须有 PageGraph 才建：图谱是它的语义视图，没有结构记账就没有"节点"。
    # `scan.crawl_strategy=rule` 可一键关掉图引导（回到"规则调度 + 自由规划"），
    # 出问题时不必回滚版本。
    kg = None
    if obs is not None and kgmod is not None:
        try:
            _strategy = str(getattr(cfg.scan, "crawl_strategy", "guided") or "guided")
            if _strategy.lower() != "rule":
                kg = kgmod.AppKG(package)
        except Exception:
            kg = None

    # ---- 遍历调度器（Step 2：DFS 栈 + tab 铺开 + 价值表 + 死点）----
    # 只在"有图"时才启用：调度依赖页面图的本界面 clicked/dead 记账，
    # 没有图就没有 per-state 命名空间，退化为旧逻辑比半吊子调度安全。
    # `scan.crawl_mode=legacy` 可一键回到 Step 1（只观测不决策）。
    sched = None
    if obs is not None and crawlsched is not None:
        try:
            mode = str(getattr(cfg.scan, "crawl_mode", "graph") or "graph").lower()
            if mode != "legacy":
                sched = crawlsched.Scheduler(
                    obs,
                    max_taps_per_state=int(getattr(cfg.scan, "max_taps_per_state",
                                                  30) or 30),
                    # 上拉次数可配：设 0 等于关掉列表上拉（退回 Step 2 行为）。
                    max_pulls=int(getattr(cfg.scan, "list_pull_max", 2) or 0),
                    # 层级上限：2 档"只点二级目录"用 2，其余档 0（不限）。
                    max_depth=int(getattr(cfg.scan, "max_depth", 0) or 0),
                    log=log)
        except Exception:
            sched = None
    _act_cache = {"act": "", "ts": 0.0}

    def _activity() -> str:
        """当前 Activity（15 秒缓存）。

        dumpsys 一次约 100~200ms，每轮都取会吃掉可观预算；而 Activity 只在
        跨页时才变，15 秒的滞后对"界面身份"这个用途足够。
        """
        now = time.time()
        if _act_cache["act"] and now - _act_cache["ts"] < 15:
            return _act_cache["act"]
        try:
            a = uiwalk.top_activity(res.device_serial) or ""
        except Exception:
            a = ""
        if a:
            _act_cache["act"] = a
            _act_cache["ts"] = now
        return _act_cache["act"]

    def _obs_tap(node: Any, label: str = "") -> None:
        """登记"在哪个界面点了哪个元素"。落点要等下一屏观测到才判定。"""
        if obs is None:
            return
        try:
            if not obs.current:
                return
            obs.mark_tap(obs.current, obs.uid_for(node),
                         label or (getattr(node, "label", "") or ""), res.ui_taps)
        except Exception:
            pass

    def _obs_resolve(to_fp: str, **kw: Any) -> None:
        if obs is None:
            return
        try:
            if obs.has_pending:
                obs.resolve(to_fp, **kw)
        except Exception:
            pass

    def _do_back(why: str) -> bool:
        """按一次返回键，并检查是不是把 App 退掉了。返回 True 表示 App 已不在前台。

        ★ 单独抽出来的原因：Step 2 之后有**两处**会按返回 —— 调度器的 DFS 回退
          和"本屏没有可点入口"时的三拍。两处各写一遍退出检测，迟早漏掉一处，
          漏掉的那处就会在桌面上继续点，一整轮白跑。
        """
        nonlocal back_unsafe
        uiwalk.back(res.device_serial)
        if ledger is not None:
            # 记在"按返回时所在的那一屏"上：同一屏按 225 次返回（冰纷万象实测）
            # 是循环的直接证据，只按全局次数记就看不出来了。
            ledger.note_act(_fp_now["fp"], "back")
        time.sleep(0.8)
        gone = (uiwalk.is_foreign_screen(res.device_serial, package)
                or not pids_of(res.device_serial, package))
        if not gone:
            return False
        back_unsafe = True
        # 文案要跟实际行为一致：Step 2 起 BACK 只在"根界面"被禁，
        # 进入内页后仍会使用（否则 DFS 回不去，遍历只能浅一层）。
        res.errors.append("BACK 键导致 App 退出（%s）；此后仅在进入内页后使用返回键，"
                          "根界面改用滚动/左右滑" % why)
        log("[!] BACK 键把 App 退出了（%s），根界面不再使用返回键" % why)
        if respawn is not None:
            try:
                respawn()
            except Exception:
                pass
        else:
            launch_app(res.device_serial, package)
        time.sleep(2.5)
        seen.clear()
        return True

    def _ai_ratio() -> float:
        """当前采集进度（0~1）。按**真实采集时间**算：等模型的时间要扣掉，
        否则中继模式下第 2 步就被推到"找注销入口"阶段，节奏全乱。"""
        base = started_at or res.started_at or time.time()
        return min(1.0, max(0.0, (time.time() - base - ai_extra) / span))

    def _ui_agent_on() -> bool:
        """「AI 指挥遍历」总开关。必须先看 `ui_agent` 功能开关，不能只看「有没有
        视觉能力」：`AITasks.plan_ui_action()` 在 ui_agent 关闭时直接返回 None，
        而调用方把 None 一律当"AI 失败"计数 → 三次之后打出「AI 遍历决策连续失败，
        停用 AI」并写进 res.ai_errors。实测 jxz4 只开了 policy_vision，日志与报告里
        就凭空多出一条"AI 失败"，排查时被误导半天。"""
        if ai_tasks is None:
            return False
        try:
            return bool(ai_tasks.cfg.feature("ui_agent"))
        except Exception:
            return False

    def _ai_gate_ok() -> bool:
        """这一步能不能问模型 —— 开关 / 视觉能力 / 熔断 / 次数上限 / 节流，五处合一处。

        单独抽出来是因为循环体里有**两个**问模型的地方（常规决策，以及
        「本屏结构树没有可点节点」时的视觉补位）。两处各写一遍闸门，迟早漏掉一环。
        """
        if not (_ui_agent_on() and ai_tasks is not None):
            return False
        if ai_disabled or not ai_tasks.can_vision():
            return False
        if ai_max > 0 and ai_used >= ai_max:
            return False
        if ai_every > 1 and (loop_i - 1) % ai_every != 0:
            return False
        return True

    # ---- 开跑前先清掉遮挡触摸的系统悬浮窗（屏幕录制条等） ----
    # 真机实测：MIUI 屏幕录制控制条压住首启弹窗的「同意并继续」，点击落到悬浮条上，
    # 跳到相册 → 判定"离开 App" → 重拉 → 再点，形成死循环，一个真实事件都采不到。
    try:
        killed = uiwalk.dismiss_overlays(res.device_serial, log=log,
                                                    target_pkg=res.package)
        if killed:
            res.errors.append("检测到系统悬浮窗遮挡触摸（%s），已强制关闭后继续"
                              % "、".join(killed))
            res.overlays_dismissed = list(set((res.overlays_dismissed or []) + killed))
            time.sleep(1.0)
    except Exception as e:
        log("[!] 悬浮窗检查失败（忽略）：%s" % e)

    # ---- 遍历进度回传 ----
    # ★ 为什么不打一次 55% 就完事：看板上那一格会**整整二十分钟不动**，
    #   而看门狗恰好是拿"进度有没有变"判断死活的 —— 于是真在一步步点击的
    #   任务被判成"20 分钟没有变化"，日志里还劝人去查设备连接（用户 2026-10-21 提的）。
    #   遍历的进度只能用"时间过了多少 + 实际走到哪"来算：
    #   界面数/点击数是真实的活儿，比一个常量百分比诚实得多。
    _walk_t0 = time.time()
    _walk_span = max(1.0, (deadline + ai_extra) - _walk_t0)
    _last_post_at = 0.0

    def _post_walk_progress(force: bool = False) -> None:
        nonlocal _last_post_at
        if on_stage is None:
            return
        now = time.time()
        if not force and now - _last_post_at < 10:
            return
        _last_post_at = now
        done = min(1.0, max(0.0, (now - _walk_t0) / _walk_span))
        # 55 → 88 是采集段里分给遍历的区间（见 run_scan 的打点）
        pct = 55 + int(done * 33)
        try:
            on_stage("界面遍历（点击 %d 次 / 界面 %d）"
                     % (res.ui_taps or 0, len(res.screens or [])), min(87, pct))
        except Exception:
            pass

    while time.time() < deadline + ai_extra:
        if _stop_requested(should_stop):
            log("[*] 收到停止请求，结束 UI 遍历（已采数据保留）")
            res.aborted = True
            res.abort_reason = "UI 遍历阶段被中断"
            break
        # 15 秒一次的屏幕状态检查：黑了就点亮，别对着黑屏点到预算耗尽。
        _check_screen(res.device_serial, log, _scr_walk)
        loop_i += 1
        # ---- 秒级停滞熔断（2026-11-09 镜像投屏事故）----
        # 放在**循环最顶部**：下面的分支里有一堆 `continue`（dump 失败、外跳、
        # 权限弹窗、登录门……），放在中段就会被其中任何一条绕过 —— 事故里
        # 2760 秒零动作正是"每一轮都在某个 continue 里打转"。
        # 判据只看"界面多久没换过"，与动作数、轮次、图谱节点数都无关。
        # ★ 重置时钟的条件必须是**真进展**：见到以前没见过的界面，或点到以前没点过的
        #   入口。A↔B 来回跳、反复点同一个「确定」都不算 —— 镜像投屏 46 分钟里
        #   正是"界面在变、动作在记，但一个新东西都没多出来"。
        _n_vis = len(ledger.visits) if ledger is not None else 0
        _n_tap = len(ledger.taps) if ledger is not None else 0
        if (_n_vis, _n_tap) != (_stall_seen[0], _stall_seen[1]):
            _stall_seen[0], _stall_seen[1] = _n_vis, _n_tap
            _stall_clock[0] = time.time()
        _stall_secs = time.time() - _stall_clock[0]
        if _stall_secs >= _STALL_GIVEUP_SECS:
            stop_reason = (
                "已连续 %d 秒（约 %.1f 分钟）没有发现任何新的界面或新的可点入口，"
                "当前停在「%s」；期间点击/返回/滑动都有执行，但换来的都是去过的界面%s，"
                "继续采集不可能产生新证据，因此在此收工。未覆盖部分按「跳过未测」计，"
                "不代表应用没有该功能"
                % (int(_stall_secs), _stall_secs / 60.0, (_activity() or "未知界面"),
                   "，重拉应用后仍未恢复" if _stall_respawned[0] else ""))
            res.errors.append(stop_reason)
            log("[!] %s" % stop_reason)
            break
        if _stall_secs >= _STALL_RESPAWN_SECS:
            if _stall_respawned[0]:
                stop_reason = (
                    "重拉应用后仍连续 %d 秒（约 %.1f 分钟）没有发现新的界面或新的可点"
                    "入口，当前停在「%s」，判定该应用已无更多可遍历内容，提前收工；"
                    "未覆盖部分按「跳过未测」计，不代表应用没有该功能"
                    % (int(_stall_secs), _stall_secs / 60.0, (_activity() or "未知界面")))
                res.errors.append(stop_reason)
                log("[!] %s" % stop_reason)
                break
            _stall_respawned[0] = True
            relaunches += 1
            res.relaunch_count = max(res.relaunch_count, relaunches)
            res.errors.append(
                "已连续 %d 秒没有发现任何新的界面或新的可点入口，已重新拉起应用复位后再试"
                % int(_stall_secs))
            log("[!] 已连续 %d 秒没有新界面/新入口（%s），重新拉起应用复位"
                % (int(_stall_secs), (_activity() or "未知界面")))
            if respawn is not None:
                try:
                    respawn()
                except Exception:
                    pass
            else:
                launch_app(res.device_serial, package)
            time.sleep(2.0)
            seen.clear()
            # ★ 不重置 _stall_clock：重拉后若还是这一屏，时钟必须继续走，
            #   否则"重拉 → 又是同屏 → 再等 180 秒 → 再重拉"会无限循环。
            continue
        _post_walk_progress()
        # ---- 采集通道健康检查（每 ~15 秒一次） ----
        # 只看"进程还在不在"是不够的：实测滴滴出行的安全 SDK 会让我们的 Frida
        # 脚本中途失效，而 App 进程照常在跑。此时遍历继续点击、用户以为在采集，
        # 实际上 hook 一个都没了，事件数少得可怜 —— 这才是真正的"白跑"。
        if time.time() - last_hook_check > 15:
            last_hook_check = time.time()
            try:
                live.script.exports_sync.summary()
            except Exception:
                if hook_tries >= HOOK_TRY_CAP:
                    # 已经反复证明"救不回来"：停止重注入，把剩下的预算还给界面遍历。
                    # 继续试下去的期望收益是 0（每次都很快再失效），代价却是每分钟
                    # 一次 20~30 秒的冷启动 —— 等于用整轮预算换一句"还是不行"。
                    if not hook_dead_noted:
                        hook_dead_noted = True
                        res.errors.append(
                            "采集脚本在本应用上反复失效（已尝试 %d 次重新附着/冷启动重建，"
                            "均很快再次失效），此后改为<b>仅界面采集</b>：界面覆盖、"
                            "政策取证、权限弹窗仍然有效，但自此刻起的接口调用事件不完整"
                            % hook_tries)
                        log("[!] 注入反复失效 %d 次，停止重注入，改为仅界面采集"
                            "（界面/政策/权限证据不受影响，事件从此刻起不完整）"
                            % hook_tries)
                elif res.hook_spawn_killed:
                    # 已经证明"冷启动注入"也会被杀：宁可没有事件，也不能把被测
                    # 应用一遍遍弄死。剩下的时间继续做界面采集（截图、路径、
                    # 权限弹窗仍然有效）。
                    if not hook_dead_noted:
                        hook_dead_noted = True
                        log("[!] 注入已被加固机制终止（冷启动路径同样被拦），"
                            "本轮改为仅界面采集（行为事件缺失的原因会写进报告）")
                elif res.reattach_banned:
                    # 该应用能识别"附着到已运行进程"，但冷启动注入本来是好的
                    # —— 这时重注入改走 spawn 重建（代价：界面回到首启）。
                    hook_tries += 1
                    if respawn is not None and respawn():
                        res.errors.append(
                            "采集脚本中途失效；该应用能识别附着式注入，已改用冷启动"
                            "重建注入（界面进度回到首启，失效期间的界面未能遍历）")
                        log("[*] 附着会被该应用识别，已改用冷启动重建注入")
                        seen.clear()
                    else:
                        res.errors.append("采集脚本中途失效，冷启动重建注入也失败；"
                                          "后续事件采集不完整")
                elif rehook is not None and rehook():
                    hook_tries += 1
                    res.errors.append("采集脚本中途失效（App 仍在运行），已重新附着主进程并"
                                      "重新注入 hook；失效期间的事件未能采集")
                    log("[*] 采集脚本中途失效，已重新附着主进程并重新注入 hook")
                elif respawn is not None and respawn():
                    hook_tries += 1
                    res.errors.append("采集脚本中途失效且无法重新附着，已改用冷启动重建注入")
                    log("[*] 采集脚本中途失效，已改用冷启动重建注入")
                    seen.clear()
                else:
                    res.errors.append("采集脚本中途失效，且无法重新附着；后续事件采集不完整")

        # ---- 悬浮窗巡检（每 ~12 秒一次） ----
        if time.time() - overlay_checked_at > 12:
            overlay_checked_at = time.time()
            try:
                killed = uiwalk.dismiss_overlays(res.device_serial, log=log,
                                                    target_pkg=res.package)
                if killed:
                    res.overlays_dismissed = list(set((res.overlays_dismissed or []) + killed))
                    time.sleep(0.6)
            except Exception:
                pass

        # ---- App 存活检查（每 ~5 秒一次） ----
        if time.time() - last_alive_check > 5:
            last_alive_check = time.time()
            # ★ `pidof 包名` 取不到 ≠ 进程不存在（2026-10-27 小盒课堂）：它是按
            #   进程名精确匹配，加固包/多进程 App 的主进程名未必等于包名。
            #   无注入模式下曾因此 109 秒内连判 5 次"App 已退出"，而界面一直在前台，
            #   遍历被提前中止（预算还剩 136 秒）。取不到 pid 时先看前台 Activity。
            _pids = pids_of(res.device_serial, package)
            _fg = ""
            if not _pids:
                try:
                    _fg = uiwalk.current_focus(res.device_serial) or ""
                except Exception:
                    _fg = ""
            if not _pids and not _fg.startswith(package):
                # ★ 先判一件事：这次退出是不是**我们自己**造成的。
                #   两种注入方式都会被加固壳判死，但补救办法相反（2026-10-27 实测）：
                #     · re-attach 到已运行进程 → 壳自杀（洋葱学园 3 秒内）；
                #       含义是"以后不要 re-attach"，可以改用 spawn 重建顶上。
                #     · spawn 冷启动注入     → 同样被杀，系统随后重新拉起（2 秒内）；
                #       含义是"这个壳连冷启动注入都杀"，重建只会反复杀应用、
                #       把已走的界面进度全部作废 —— 不能再注入。
                #   混成一个 hook_hostile，会让"只被 re-attach 杀"的应用白丢数据。
                _reattach_hit = bool(res.hook_reattach_at
                                     and time.time() - res.hook_reattach_at < 12.0)
                _spawn_hit = bool(res.hook_spawn_at
                                  and time.time() - res.hook_spawn_at < 12.0)
                if _reattach_hit:
                    res.hook_hostile += 1
                    res.reattach_banned = True
                    res.hook_reattach_at = 0.0
                    log("[!] 重新附着 hook 后 App 立刻退出 —— 加固机制拦截注入"
                        "（第 %d 次），此后不再附着；需要重注入时改走冷启动" % res.hook_hostile)
                    res.errors.append(
                        "重新附着 hook 后 App 立即退出：该应用带加固保护，附着会被"
                        "判定为调试并触发自杀。已停止「附着式」注入，需要重注入时"
                        "改用冷启动重建；本轮行为事件偏少是注入受限所致。")
                elif _spawn_hit:
                    res.hook_hostile += 1
                    res.hook_spawn_killed += 1
                    res.hook_spawn_at = 0.0
                    log("[!] 冷启动注入后 App 立刻消失 —— 加固机制连 spawn 路径也拦"
                        "（第 %d 次），此后一律不注入，改为仅界面采集"
                        % res.hook_spawn_killed)
                    res.errors.append(
                        "冷启动注入后 App 立即退出：该应用的加固机制对冷启动注入同样"
                        "会判定为调试并触发自杀。重建注入只会反复把应用杀掉、丢掉已"
                        "采集的界面进度，因此改为仅界面（截图）采集；"
                        "本轮行为事件偏少是注入受限所致，不代表应用没有该行为。")
                relaunches += 1
                res.relaunch_count = max(res.relaunch_count, relaunches)
                # 重启上限按档位给（2026-11-01）：原来一律 4 次，对 1 小时档
                # 太紧 —— 冰纷万象（4 档）实测在 1851 秒时因"前台反复不在应用内"
                # 触发第 5 次重启而直接收工，1 小时预算只用了 31 分钟。
                # 反过来说，短档也不该无限重启：每次冷启动 30~60 秒，
                # 在 5 分钟档里重启 10 次等于什么都没测。
                if relaunches > _max_relaunch:
                    stop_reason = ("App 反复退出/被切到后台（已重启 %d 次，本档上限 %d 次），"
                                   "停止遍历" % (relaunches - 1, _max_relaunch))
                    res.errors.append(stop_reason)
                    log("[!] %s" % stop_reason)
                    break
                if res.hook_spawn_killed:
                    # 壳连冷启动注入都杀：只拉起、不再注入，保住界面采集
                    log("[!] App 已退出，仅拉起（不注入 hook，第 %d 次）…" % relaunches)
                    res.errors.append("采集期间 App 进程退出，已第 %d 次重新拉起（不注入）"
                                      % relaunches)
                else:
                    log("[!] App 进程已退出，重新拉起并重新注入 hook（第 %d 次）…" % relaunches)
                    res.errors.append("采集期间 App 进程退出，已第 %d 次自动重启并重新注入"
                                      % relaunches)
                _obs_resolve("", alive=False)          # 上一次点击的落点：崩溃
                if respawn is not None and not res.hook_spawn_killed:
                    try:
                        respawn()
                    except Exception as e:
                        log("[!] 重新注入失败：%s" % e)
                else:
                    launch_app(res.device_serial, package)
                time.sleep(3.0)
                seen.clear()
                continue

        # ---- 前台去向检查：跳出了被测 App / 落到系统设置页 ----
        #
        # ★ 这一段要回答两个问题，旧逻辑只答了后半个：
        #   ① 现在还在不在被测 App 里。旧判据（`is_foreign_screen`）把
        #      `com.miui.securitycenter` 当白名单放行 —— 那是为了权限确认框，
        #      但「权限管理」入口跳的也是这个宿主（只是 activity 不同），于是
        #      "点权限管理 → 进 MIUI 的权限页"根本没被识别成外跳，被当成 App
        #      界面继续遍历：那一屏全是系统 ROM 的开关，点一次就改一次设备设置，
        #      而 App 的行为一个都拿不到。
        #   ② 这次出去**值不值得留证**。系统设置的权限页、第三方授权页是证据
        #      （"App 未自建权限开关""存在微信授权登录"），要截图入册；
        #      商店/相册/浏览器首页只是烧预算，要**立刻**退（见 flow/foreign.py）。
        # ★ 用"窗口焦点"而不是 `current_focus()`（2026-11-10 健康深圳 / 搜题）。
        #   `current_focus()` 在焦点为空时会兜底读 `mResumedActivity`，而 uni-app
        #   的 `io.dcloud.PandoraEntry` 可以 resumed 却从不画窗口 —— 于是循环
        #   一路认为"还在应用内"，实际每一步都点在桌面上，8 屏 5 张截图全是桌面。
        _fg_now = uiwalk.foreground(res.device_serial)
        _focus_line = _fg_now.get("focus") or ""
        if foreignmod is not None:
            _pkg_now, _act_now = foreignmod.parse_focus(_focus_line)
        else:                                            # pragma: no cover
            _pkg_now, _act_now = "", ""
        if not _pkg_now:
            _pkg_now = uiwalk.current_package(res.device_serial)
        if foreignmod is not None:
            # ★ 先排除"被测 App 自己"再判设置页：`is_settings_page()` 只看宿主包名，
            #   不知道谁是目标 —— 万一测的就是系统设置本身（或它的子包），
            #   不排除会把 App 自己的每一屏都当成"跳到系统设置"。
            _is_app_now = bool(_pkg_now) and (
                _pkg_now == package or _pkg_now.startswith(package + ":"))
            _outside = bool(_pkg_now) and not _is_app_now and (
                foreignmod.is_foreign(_pkg_now, package)
                or foreignmod.is_settings_page(_pkg_now, _act_now))
        else:                                            # pragma: no cover
            _outside = uiwalk.is_foreign_screen(res.device_serial, package)

        def _still_outside() -> bool:
            """此刻是否仍在被测 App 之外（外跳判定的复查口径，只有一份）。"""
            f = uiwalk.foreground(res.device_serial).get("focus") or ""
            p, a = (foreignmod.parse_focus(f) if foreignmod is not None else ("", ""))
            if not p:
                p = uiwalk.current_package(res.device_serial)
            if not p:
                return False          # 读不到就交给下一轮主循环判，不在这里瞎猜
            if foreignmod is not None:
                if p == package or p.startswith(package + ":"):
                    return False
                return (foreignmod.is_foreign(p, package)
                        or foreignmod.is_settings_page(p, a))
            return uiwalk.is_foreign_screen(res.device_serial, package)  # pragma: no cover

        def _leave_foreign(limit: int = 2, pause: float = 0.5) -> bool:
            """从外部界面退回被测 App。返回 True 表示已回来。

            ★ 为什么允许连按两次：浏览器常常有"重定向中间页 → 落地页"两层，
              一次 BACK 只退到上一页，人还在别人家里。而连按的代价很低 ——
              退的都是**外部应用**的页面，被测 App 的栈没被动过。
            ★ 退不掉就 `launch_app` 拉回前台：某些跳转（支付、系统设置）
              用 BACK 是退不回来的（Activity 自己拦了返回键）。
            """
            for _ in range(max(1, int(limit))):
                uiwalk.back(res.device_serial)
                time.sleep(pause)
                if not _still_outside():
                    return True
            launch_app(res.device_serial, package)
            time.sleep(2.0)
            return not _still_outside()

        if _outside:
            # 连续快速判定为"在外面"时不重复计数（避免 back 后状态未刷新就再判一次）
            if time.time() - last_escape_at > 1.5:
                last_escape_at = time.time()
                _entry = (getattr(last_tap_node, "label", "") or "").strip()
                # 这次离开是不是**刚刚那次点击**造成的？（见 FOREIGN_CAUSE_WINDOW）
                # ★ 这道闸拦的是"凭空归因"：设备上本来就开着 USB 详情页/浏览器/
                #   微信（插着线、上一轮没退干净、用户手动切走），若照旧读
                #   `last_tap_node` 当入口，报告里就会写"点『权限管理』跳到了
                #   系统设置"——一个从来没发生过的因果。
                _fresh = bool(last_tap_node) and (
                    time.time() - last_tap_at) <= FOREIGN_CAUSE_WINDOW
                # ---- 判定：必要跳转（留证）/ 无意义跳转（立刻退）/ App 退出 ----
                _v: Dict[str, Any] = {
                    "action": "back", "kind": "unknown", "label": "其他应用",
                    "why": "跳到其他应用，与被测应用的行为无关",
                    "wait": 0.0, "valuable": False, "end_call": False,
                }
                if not _fresh:
                    _v = {
                        "action": "relaunch", "kind": "lost_focus",
                        "label": "前台不在被测应用",
                        "why": "检测期间前台离开被测应用，但没有可归因的点击；"
                               "按失焦处理并重新拉起，不计入外跳证据",
                        "wait": 0.0, "valuable": False, "end_call": False,
                    }
                elif foreignmod is not None:
                    try:
                        _v = foreignmod.classify(_pkg_now, activity=_act_now,
                                                 entry=_entry, app_package=package)
                        if _v.get("need_text"):
                            # 光看包名定不了性（浏览器/别的 App）：dump 一次落点文字。
                            # 这一两秒只花在这里 —— 商店/相册/桌面当场就判完了。
                            _ext_xml = uiwalk.dump_retry(res.device_serial, tries=2, wait=0.5)
                            _ext_txt = (" ".join(uiwalk.screen_texts(_ext_xml))[:500]
                                        if _ext_xml else "")
                            if _ext_txt:
                                _v = foreignmod.classify(
                                    _pkg_now, activity=_act_now, entry=_entry,
                                    screen_text=_ext_txt, app_package=package)
                    except Exception as e:            # 判定失败不能打断遍历
                        log("[!] 外跳判定失败（按无意义跳转处理）：%s" % e)
                _obs_resolve("", foreign=True)        # 上一次点击的落点：跑到别的 App
                # 该入口本会话不再点：落点类型已经拿到了，再点一次不会有新事实。
                # （保留这条记忆比"按标签去重"更必要 —— `seen.clear()` 之后
                #   同一个入口会重新变成可点，实测一次「相册」被点过 4 次。）
                # ★ 失焦（lost_focus）不拉黑：那时 `_entry` 是上一次点击的残留，
                #   拉黑它等于把一个无关入口永久排除，下一轮少点一个该点的地方。
                if _entry and _v.get("kind") != "lost_focus":
                    foreign_labels.add(_entry)

                _row = {
                    "seq": len(res.external_jumps) + 1,
                    "entry": _entry[:40],
                    "pkg": _pkg_now,
                    "activity": _act_now,
                    "kind": _v.get("kind") or "unknown",
                    "label": _v.get("label") or "其他应用",
                    "valuable": bool(_v.get("valuable")),
                    "why": _v.get("why") or "",
                    "screenshot": None,
                    "texts": [],
                    "ts": round(time.time() - (res.started_at or time.time()), 1),
                }

                if _v.get("action") == "relaunch":
                    # ★ 「前台不在 App 里、又归因不到点击」不等于"App 在乱跳"：
                    #   浏览器退不干净、上一轮的页面还没关掉都会这样。旧逻辑把它
                    #   和外跳一起计数，春雨诊所就因此累计到 9 次把整轮遍历停掉。
                    #   现在只在**反复出现**时才计入（第一次按失焦处理并重拉）。
                    if _v.get("kind") == "lost_focus":
                        lost_focus_n += 1
                        if lost_focus_n > 3:
                            escapes += 1
                    else:
                        escapes += 1
                    if _v.get("kind") == "lost_focus":
                        # 不是跳转，也不是 App 崩溃：就是"我们不在 App 里"。
                        # ★ 不入 `external_jumps` —— 那份记录是"点了哪个入口去了哪"，
                        #   凭空往里塞一条，报告就会凭空写出一句因果。
                        # ★ 先按一次返回，别急着冷启动（2026-11-05）。
                        #   春雨诊所整轮被弹到 com.android.browser 4 次，每次
                        #   `launch_app` 要 ~10 秒，界面栈还全丢 —— 而多数情况下
                        #   浏览器只是"停在那儿"，一次 BACK 就回来了。
                        #   错误也只在头两次记：同一条事实记 4 遍，报告会被噪声淹没。
                        if lost_focus_n <= 2:
                            res.errors.append(
                                "遍历中发现前台不在被测应用内（当前=%s），且无法归因到"
                                "任何点击，已先按返回退出该系统界面（返回无效才重新拉起）"
                                % (_pkg_now or "未知"))
                        log("[!] 前台不在被测应用内（%s），无对应点击，先按返回"
                            % (_pkg_now or "未知"))
                        _ret_ok = False
                        try:
                            uiwalk.back(res.device_serial)
                            time.sleep(0.9)
                            # ★ 判据必须是"窗口焦点"，不能用 `current_focus()`：
                            #   后者拿不到 mCurrentFocus 时会兜底读
                            #   `mResumedActivity`，健康深圳那类应用可以
                            #   "resumed 但从不画窗口"。用它判，这里每次都判
                            #   "已回到被测应用"，`visible_fail` 被反复清零 ——
                            #   于是重拉十几次、烧掉几百秒，熔断永远不会触发。
                            try:
                                _ret_ok = (uiwalk.app_visible(
                                    res.device_serial, package) is True)
                            except Exception:
                                _ret_ok = False
                        except Exception:
                            _ret_ok = False
                        if _ret_ok:
                            log("[.] 一次返回已回到被测应用，不再冷启动")
                            visible_fail = 0
                        else:
                            log("[.] 返回没回到被测应用，改为重新拉起")
                            launch_app(res.device_serial, package)
                            time.sleep(2.0)
                            # ★ 拉起之后必须复核"眼前到底有没有应用"
                            #   （2026-11-10 搜题 / 健康深圳）：`am start` 返回 0
                            #   只代表指令下发成功。这两单的 uni-app 每次都"启动成功"
                            #   却从不画窗口，循环于是重拉 10 次、烧掉 430 秒，
                            #   期间拍的每一张都是桌面。连续几次拉不回来就该收工。
                            if uiwalk.app_visible(res.device_serial, package) is not True:
                                visible_fail += 1
                            else:
                                visible_fail = 0
                        seen.clear()
                    else:
                        # 桌面：不是跳转，是 App 被退出（崩溃/误触）
                        res.errors.append("遍历中落到系统桌面（入口「%s」），已重新拉起被测应用"
                                          % (_entry or "未知"))
                        log("[!] 落在系统桌面（入口「%s」），重新拉起 App"
                            % (_entry or "未知"))
                        if len(res.external_jumps) < FOREIGN_MAX_ROWS:
                            res.external_jumps.append(_row)
                        launch_app(res.device_serial, package)
                        time.sleep(2.0)
                        if uiwalk.app_visible(res.device_serial, package) is not True:
                            visible_fail += 1
                        else:
                            visible_fail = 0
                        seen.clear()
                    if visible_fail >= _APP_NEVER_VISIBLE_MAX:
                        stop_reason = (
                            "连续 %d 次重新拉起后，被测应用始终没有出现在前台"
                            "（前台一直是 %s）——应用在本机启动后即退出/不显示界面，"
                            "本轮无法在其界面上取证；不含应用自身的功能缺陷结论，"
                            "未覆盖项按「跳过未测」计"
                            % (visible_fail, _pkg_now or "系统界面"))
                        res.errors.append(stop_reason)
                        log("[!] %s" % stop_reason)
                        break
                elif _v.get("valuable"):
                    # ---- 必要跳转：留证（截图 + 落点文字）后返回 ----
                    jumps += 1
                    if _v.get("wait"):
                        time.sleep(min(3.0, float(_v["wait"])))
                    if _foreign_shot_count(res) < FOREIGN_SHOT_EXTRA:
                        _shot = capture_screenshot(res.device_serial)
                        if _shot:
                            _row["screenshot"] = len(res.screenshots)
                            res.screenshots.append({
                                "label": "外跳：%s" % (_v.get("label") or "其他应用"),
                                "activity": _act_now,
                                "b64": base64.b64encode(_shot).decode("ascii"),
                            })
                    _keep_xml = uiwalk.dump_retry(res.device_serial, tries=1, wait=0.3)
                    if _keep_xml:
                        _row["texts"] = uiwalk.screen_texts(_keep_xml)[:20]
                    if len(res.external_jumps) < FOREIGN_MAX_ROWS:
                        res.external_jumps.append(_row)
                    res.ui_steps.append("外跳留证：「%s」→ %s"
                                        % (_entry or "未知入口", _v.get("label") or "其他应用"))
                    log("[外跳] 「%s」→ %s ｜ %s ｜ 已截图留证，随即返回"
                        % (_entry or "未知入口", _v.get("label") or "其他应用",
                           _v.get("why") or ""))
                    if _v.get("end_call"):
                        # 拨号类：真拨出去了要挂断（外呼有社会成本，也不该占着线路）
                        try:
                            uiwalk.end_call(res.device_serial)
                        except Exception:
                            pass
                    if not _leave_foreign(limit=2, pause=0.45):
                        res.errors.append("外跳后无法退回被测应用（去向：%s），已尝试重新拉起"
                                          % (_v.get("label") or "其他应用"))
                    seen.clear()
                else:
                    # ---- 无意义跳转：**不等**，立刻退（这是本次改进的核心）----
                    # 旧逻辑固定 sleep(1.0) 再按返回，而"跳到商店/浏览器首页"这一秒
                    # 纯属浪费；更糟的是返回发生在下一轮循环，中间可能又多跳一屏。
                    # ★ 浏览器类不计入"外跳过多"（2026-11-03）：登录页勾选框、
                    #   弹窗里的协议链接都会临时开浏览器，退回来就结束 ——
                    #   它既没烧预算也没带来新界面，拿它当"应用乱跳"的证据
                    #   把整轮停掉，春雨诊所正是这样只跑了 8 分钟。
                    if not str(_v.get("kind") or "").startswith("browser"):
                        escapes += 1
                    if len(res.external_jumps) < FOREIGN_MAX_ROWS:
                        res.external_jumps.append(_row)
                    log("[外跳] 「%s」→ %s ｜ %s ｜ 立即返回（不计入有效覆盖）"
                        % (_entry or "未知入口", _v.get("label") or "其他应用",
                           _v.get("why") or ""))
                    if _v.get("end_call"):
                        try:
                            uiwalk.end_call(res.device_serial)
                        except Exception:
                            pass
                    _leave_foreign(limit=2, pause=0.4)
                    seen.clear()
            if escapes > 8:
                # ★ 必须写 stop_reason：只 append 到 errors 的话，报告头部的
                #   「本轮中断原因」会落到后面那几个描述性分支上（真机实测川剧迷
                #   就被写成"App 期间退出并重新拉起 1 次"），看起来像设备问题，
                #   实际是反复外跳被主动停掉的 —— 结论会因此偏一大截。
                stop_reason = ("遍历中 %d 次离开被测应用（其中 %d 次有取证价值），"
                               "已停止遍历以避免无效点击" % (escapes, jumps))
                res.errors.append(stop_reason)
                log("[!] %s，停止遍历" % stop_reason)
                break
            if len(res.external_jumps) >= FOREIGN_MAX_ROWS and not _jump_warned:
                _jump_warned = True
                res.errors.append("外跳次数过多，明细仅保留前 %d 条" % FOREIGN_MAX_ROWS)
            continue

        # 心跳：每 5 轮报一次"预算还剩多少、其中多少是在等模型"。
        # 没有这行的话，"遍历跑了 7 分钟只点了 4 次"在日志里完全看不出来 ——
        # 事后要么怀疑统计错误、要么怀疑测试方法，唯独看不出真实原因。
        if loop_i % 5 == 1:
            log("    [遍历] 第 %d 轮：预算剩 %ds（本轮之前等 AI 累计 %.0fs，已补回）"
                % (loop_i, int(deadline + ai_extra - time.time()), ai_extra))
            # 每轮时间都花在哪（2026-11-10）：只在 PIISCAN_PROF=1 时输出。
            # 上一次真机（CNC宝典 4 档）45 分钟遍历 306 轮、平均 8.9 秒/轮，
            # 而"同样的点击+导出"在复现轮只要 3.4 秒/步 —— 中间那 5 秒必须
            # 能拆开看，否则只能靠猜，猜出来的东西写进报告就是假话。
            if getattr(uiwalk, "PROF", {}).get("on"):
                _ps = uiwalk.prof_summary()
                log("    [耗时] 轮 %d（近 20 轮）：adb %d 次 / %.1fs ｜ %s"
                    % (loop_i, _ps["calls"], _ps["secs"],
                       " ".join("%s=%.0fs" % (k, v[1])
                                for k, v in list(_ps["tags"].items())[:6])))
                if _ps["slow"]:
                    log("    [耗时] 近 20 轮里 ≥5s 的单次调用：%s"
                        % " ".join("%s×%.0fs" % (t, d) for d, t in _ps["slow"][:8]))
                uiwalk.prof_reset()
            # 诊断（2026-11-09）：镜像投屏 extreme 档出现"11.8 分钟后零动作、
            # 却把剩下 46.8 分钟烧完"。原因要么是 dump 静默失败轮次绕过了看门狗，
            # 要么是 `_prog_sig` 每轮都在变导致 idle_rounds 永远清零。
            # 这两个数打出来就能一眼分清，平时不影响任何逻辑。
            log("    [看门狗] 轮 %d：idle=%d 同屏=%.0fs dump连败=%d 台账动作=%s 不同入口=%d 步数=%d 图节点=%d"
                % (loop_i, idle_rounds, _stall_secs, dump_run,
                   (ledger.actions if ledger is not None else "-"),
                   (len(ledger.taps) if ledger is not None else 0),
                   len(res.ui_steps),
                   len(getattr(kg, "nodes", None) or {}) if kg is not None else 0))

        xml = uiwalk.dump_retry(res.device_serial, tries=2, wait=0.4)
        if not xml:
            dumps_failed += 1
            dump_run += 1
            hp = uiwalk.dump_health(res.device_serial)
            # ★ 连续读不到结构树，三个梯度的处置（2026-11-02 川剧迷事故）。
            #   事故现场：点到搜索页后连续 63 次都导不出界面，每轮 18s 超时
            #   + 补读 + 清理 ≈ 49 秒，第 51~111 轮烧掉 2954 秒（49 分钟）
            #   一个动作没做，最后写成"时间预算耗尽"——看起来像正常跑完了。
            #   原来的分支只管"降级期内"，而单次失败被判成软失败（不进降级），
            #   于是"连续软失败"这条路根本没有任何上限。
            if dump_run == _DUMP_BLUR_AT:
                # 最轻的一档自愈：收软键盘。点进搜索框后键盘占住焦点，
                # uiautomator 等 idle 等到超时，是"点开某一页之后突然全导不出
                # 结构树"最常见的原因（川剧迷就是点到搜索之后开始连败）。
                log("[.] 连续 %d 次读不到界面结构，先收起软键盘再试" % dump_run)
                ui_walk_blur(res.device_serial)
                uiwalk.reset_soft_run(res.device_serial)
                time.sleep(0.8)
                continue
            if dump_run == _DUMP_RESET_AT:
                # 先自愈：重新拉起被测应用（顺带把输入法/WebView 的脏状态清掉）。
                # 只做一次 —— 反复重启会把预算换成重启次数。
                _sil = _event_silence(res)
                log("[!] 连续 %d 次读不到界面结构（%s），重启被测应用后再试"
                    % (dump_run, hp["reason"] or "uiautomator 无响应"))
                res.errors.append(
                    "遍历中连续 %d 次无法导出界面结构（%s），已重启被测应用复位后再试"
                    % (dump_run, hp["reason"] or "uiautomator 无响应"))
                if _sil >= 60:
                    # 界面读不出来 + 同期事件静默 = 应用侧不干活了（无响应/ANR）。
                    # 这条必须单独立项：只写"导出失败"会被读成"采集器不行"，
                    # 而实际被测应用在我们点进某一页之后就没有再响应过。
                    _frozen = ("遍历到「%s」后已 %d 秒没有收到任何应用事件，"
                               "界面结构同时也全部导不出，疑为该界面无响应（ANR）；"
                               "已重启应用复位后再试"
                               % (_activity() or "未知界面", int(_sil)))
                    res.errors.append(_frozen)
                    log("[!] %s" % _frozen)
                if respawn is not None:
                    try:
                        respawn()
                    except Exception:
                        pass
                else:
                    launch_app(res.device_serial, package)
                uiwalk.reset_soft_run(res.device_serial)
                time.sleep(2.0)
                seen.clear()
                continue
            if dump_run >= _DUMP_GIVEUP:
                # 两次自愈都失败了：再循环也只是把每一秒换成超时，直接收工。
                # 这一步必须写 stop_reason —— 否则报告会把它写成"时间预算耗尽"，
                # 读者会以为遍历跑了整个 60 分钟，实际后半段一个字都没采到。
                stop_reason = (
                    "连续 %d 次无法导出界面结构（%s），收键盘与重启应用两次自愈均未恢复，"
                    "判定设备侧界面读取已不可用，UI 遍历提前终止；未覆盖部分按"
                    "「跳过未测」计，不代表应用没有该功能"
                    % (dump_run, hp["reason"] or "uiautomator 无响应"))
                res.errors.append(stop_reason)
                log("[!] %s" % stop_reason)
                break
            if hp["degraded"]:
                # 设备侧 UI 服务已经读不出来了（uiautomator 卡死）。
                # 这时候继续循环既点不动也看不到界面，只会把采集预算烧完 ——
                # 明确停下来并把原因交给报告，而不是安静地"空转到结束"。
                ui_degraded = True
                deg_loops += 1
                log("[!] 设备侧界面结构读取不可用（%s），已降级；第 %d 次等待恢复"
                    % (hp["reason"] or "uiautomator 无响应", deg_loops))
                if deg_loops >= 6:
                    stop_reason = (
                        "设备侧界面结构连续 %d 次读取失败（%s），已等待恢复仍不可用，"
                        "UI 遍历提前终止；界面相关证据仅剩截图，未覆盖部分按「跳过未测」计"
                        % (dump_run, hp["reason"] or "uiautomator 无响应"))
                    res.errors.append(stop_reason)
                    log("[!] 界面结构持续不可用，终止 UI 遍历")
                    break
                time.sleep(5.0)
                continue
            time.sleep(max(0.8, interval * 0.6))
            continue
        dump_run = 0
        if ui_degraded:
            ui_degraded = False
            deg_loops = 0
            log("[*] 设备侧界面结构读取已恢复")
        fp = uiwalk.screen_fingerprint(xml)
        visited_fps[fp] = visited_fps.get(fp, 0) + 1

        # ---- 页面图观测：登记本屏 + 结算上一次点击的落点（不改变任何决策）----
        # 位置很关键：必须在"权限弹窗/登录/政策"这些拦截分支之前，也不依赖它们，
        # 否则那几类界面就进不了图，覆盖率会凭空少一截。
        snap_nav: List[Any] = []
        want_respawn = False
        if obs is not None:
            try:
                snap = obs.observe(xml, _activity(), ui_step=res.ui_taps)
                if snap is not None:
                    snap_nav = list(snap.nav)
                    if obs.has_pending:
                        obs.resolve(snap.fp, is_dialog=snap.is_dialog)
                    if sched is not None:
                        # 栈同步必须在"结算落点"之后：先认清落点，再按落点修栈，
                        # 顺序反了会拿上一屏的 pending 去决定这一屏压不压栈。
                        sched.sync(snap.fp)
                        want_respawn = sched.take_respawn_request()
            except Exception:
                pass
        # 图谱同步单独一个 try：它读的是刚记好的图，失败只该退化成"没有图素材"，
        # 不能把上面那段的观测结果一起带走（观测与图谱是两条独立的增强链）。
        # 放在落点结算之后：先把这一击记进图（边、死点），再算"还剩哪些没探索"。
        # 顺序反了，本屏新出现的入口会被算成"已探索过"，选项表直接少一项。
        if kg is not None and obs is not None:
            try:
                kg.sync(obs)
            except Exception:
                pass

        # ---- 台账/循环观测：登记这一屏 ----
        # ★ 界面身份统一用**页面图的指纹**（`obs.current`），与 `uid_for`、
        #   图谱、调度器同一套。用 `uiwalk.screen_fingerprint`（含可见文字）
        #   会让同一个界面在文字变化时算出两个身份 —— 台账就白记了。
        #   位置必须在 obs.observe 之后：那之前 `obs.current` 还是上一屏。
        _cur_fp = (obs.current if obs is not None else "") or fp
        _fp_now["fp"] = _cur_fp
        # 秒级停滞时钟在**循环顶部**维护（见 _STALL_RESPAWN_SECS 说明），
        # 这里不再重复重置 —— 两处都改会让时钟互相抵消。
        _stall_secs = time.time() - _stall_clock[0]
        # ---- 无进展看门狗（2026-11-03）----
        # 高途那一单 3518 秒里有 3357 秒停在一个系统权限弹窗上：弹窗没能代点、
        # 也没被关掉，主循环每一轮都走到「同一弹窗 → 已记过 → continue」，
        # 界面没变、动作没发生、日志只剩心跳 —— 台账、振荡、僵化三条判据全部
        # 失明（它们都只看"执行过的动作"），于是 56 分钟一个动作都没做。
        # 辙：以「界面指纹 + 执行动作数」为进展标尺，连续多轮都不动就升级处置。
        # ★ 标尺换血（2026-11-09 镜像投屏事故）：原来是「动作总数 + 步数 + 图节点数」，
        #   三项都会骗人 —— 反复点同一个「确定」让动作总数一直涨、图谱每次 sync 又
        #   在 14↔15 抖动，于是 idle_rounds 每轮清零，8 轮重拉 / 20 轮收工全失效，
        #   2760 秒零进展被记成"一直在推进"。
        #   现在只认"真的多探索到东西"：点过的**不同入口数**、见过的**界面数**。
        #   重复点同一按钮不会增加任何一个 → 该停就会停。
        _prog_sig = (len(ledger.taps) if ledger is not None else 0,
                     len(ledger.visits) if ledger is not None else 0,
                     len(res.ui_steps),
                     _cur_fp or "")
        if _prog_sig == last_progress:
            idle_rounds += 1
            idle_fp = _cur_fp or idle_fp
        else:
            if idle_rounds >= 4:
                log("[.] 界面恢复到有进展的状态（此前连续 %d 轮没有任何动作）" % idle_rounds)
            last_progress = _prog_sig
            idle_rounds = 0
            idle_fp = ""
        if idle_rounds and idle_rounds % _IDLE_RESPAWN_AT == 0:
            # 同一屏重拉过 2 次还是没进展 —— 再拉也是同一个结果，直接收工。
            _n_here = idle_respawn_by_fp.get(idle_fp or "?", 0)
            if (_n_here >= _IDLE_RESPAWN_PER_SCREEN
                    or idle_respawn_total >= _IDLE_RESPAWN_TOTAL):
                stop_reason = (
                    "连续 %d 轮停在「%s」没有任何动作发生，其间已重新拉起应用 %d 次仍未"
                    "恢复（同屏限 %d 次、全局限 %d 次）；继续重拉只会把剩余预算换成"
                    "重复冷启动，因此在此收工。未覆盖部分按「跳过未测」计，不代表"
                    "应用没有该功能"
                    % (idle_rounds, _activity() or "未知界面", _n_here,
                       _IDLE_RESPAWN_PER_SCREEN, _IDLE_RESPAWN_TOTAL))
                res.errors.append(stop_reason)
                log("[!] %s" % stop_reason)
                break
            # 先自愈：重新拉起应用（系统弹窗/输入法/WebView 的脏状态多半能清掉）。
            log("[!] 连续 %d 轮在同一界面没有任何动作（%s），重新拉起应用复位后继续"
                % (idle_rounds, (_activity() or "未知界面")))
            res.errors.append(
                "遍历中连续 %d 轮停在「%s」没有任何动作发生（既没点成、也没换屏），"
                "已重新拉起应用复位" % (idle_rounds, _activity() or "未知界面"))
            idle_respawn_by_fp[idle_fp or "?"] = _n_here + 1
            idle_respawn_total += 1
            relaunches += 1                     # ★ 必须计数：否则重启上限形同虚设
            res.relaunch_count = max(res.relaunch_count, relaunches)
            if respawn is not None:
                try:
                    respawn()
                except Exception:
                    pass
            else:
                launch_app(res.device_serial, package)
            time.sleep(2.0)
            seen.clear()
            # 不把 idle_rounds 清 0：清了就永远到不了收工判据（本次修的就是这个）。
            continue
        if idle_rounds >= _IDLE_GIVEUP:
            # 自愈也没用：不再把剩下的预算换成空转，明确收工并写清原因。
            stop_reason = (
                "连续 %d 轮停在「%s」没有任何动作发生（重新拉起应用也未恢复），"
                "判定该界面无法继续有效遍历，UI 遍历提前终止；未覆盖部分按"
                "「跳过未测」计，不代表应用没有该功能"
                % (idle_rounds, _activity() or "未知界面"))
            res.errors.append(stop_reason)
            log("[!] %s" % stop_reason)
            break

        # ---- 已榨干的界面：不再重复"12 个动作"（2026-11-05）----
        # 高途那一单：75 次「连续 12 个动作都没切换界面」。症结不是这 12 个动作
        # 判得不对，而是**离开没成功**（返回被拦）之后又回到同一屏，重新把
        # 12 个动作走一遍确认同一件事。榨干过的屏再进来，直接走人。
        if _cur_fp and _cur_fp in exhausted_fps:
            log("[.] 这一屏此前已判定「无可探索入口」，跳过重复探测、直接离开")
            _fc_now = ""
            try:
                _fc_now = uiwalk.current_focus(res.device_serial) or ""
            except Exception:
                _fc_now = ""
            # ★ 返回也走不通时必须有第二档（2026-11-05）：注册/表单页常把 BACK
            #   当成 WebView 的历史导航吃掉，按下去界面不变 —— 于是"已榨干 →
            #   再按返回 → 还是这屏"会无限循环。连按两次没离开就改成重拉。
            _n_back = exhausted_backs.get(_cur_fp, 0)
            if _n_back >= 2:
                log("[.] 这一屏按返回两次都没离开，改为重新拉起应用复位")
                exhausted_backs[_cur_fp] = 0
                if respawn is not None:
                    try:
                        respawn()
                    except Exception:
                        pass
                else:
                    launch_app(res.device_serial, package)
                time.sleep(2.0)
            elif not back_unsafe and _fc_now.startswith(package):
                exhausted_backs[_cur_fp] = _n_back + 1
                _do_back("已榨干的界面")
                if sched is not None:
                    try:
                        sched.note_back(killed=False)
                    except Exception:
                        pass
            elif respawn is not None:
                try:
                    respawn()
                except Exception:
                    pass
            seen.clear()
            prev_fp = ""
            act_run.clear()
            act_banned.clear()
            time.sleep(max(0.4, interval * 0.6))
            continue

        # 换屏恢复 AI：本屏连败只停本屏（见 ai_fails_total 的说明）。
        # 判据用界面身份变化，不是"又走了几步" —— 同一屏上再问还是同一个答案。
        if ai_disabled and ai_fail_fp and _cur_fp != ai_fail_fp \
                and ai_fails_total < AI_FAIL_CAP:
            ai_disabled = False
            ai_fails = 0
            log("    [AI] 已到新界面，恢复 AI 决策")
        if ledger is not None:
            ledger.visit(_cur_fp)
        if watch is not None:
            _new_state = watch.note_state(_cur_fp)
            if _new_state:
                # ★ 出现了新界面 = 这一轮确实在前进，把"连续陷入循环"的累计清零。
                #   否则一次长跑里三次**互不相干**的振荡会把整轮判成"绕圈到底"
                #   提前结束（携船网那种"每次都绕回登录页"是真的，但
                #   冰纷万象这类正常 App 跑久了也会零星撞上两三次）。
                osc_rounds = 0
            if _new_state and len(watch.states) in (6, 12, 20, 30, 45, 60):
                log("[*] 遍历进度：已到达 %d 个界面（第 %d 步）"
                    % (len(watch.states), watch.actions))
        # 漂移纠偏放在观测的 try 之外：它要调 adb 重拉 App（几秒），
        # 塞进"绝不抛异常"的观测块里，一旦失败会把观测本身也带崩。
        if want_respawn:
            log("[!] 连续三次返回都没回到预期界面（有拦截页插队），重新拉起 App 复位后继续")
            res.errors.append(
                "遍历中界面连续漂移（返回落点与预期不符 3 次），"
                "已重新拉起 App 复位；漂移期间的路径未能按原栈回退")
            if respawn is not None:
                try:
                    respawn()
                except Exception:
                    pass
            else:
                launch_app(res.device_serial, package)
            time.sleep(2.5)
            seen.clear()
            continue

        if note_captcha(res, xml, log, "遍历中"):
            # ★ 人机验证界面接管整屏时不参与遍历（2026-11-05）。
            #   高途那一单撞到「安全验证／拖动滑块」后仍在上面点了十几下：
            #   这类界面点不动（要拖、要等、要真手机号），而且上面的任何 UI 证据
            #   都不能作为判定依据（报告已声明降级）。留着只会白烧预算。
            if _cur_fp and _cur_fp not in exhausted_fps:
                exhausted_fps.add(_cur_fp)
                log("[.] 该屏是人机验证界面，不参与遍历，退出后继续其它界面")
                _fc_cap = ""
                try:
                    _fc_cap = uiwalk.current_focus(res.device_serial) or ""
                except Exception:
                    _fc_cap = ""
                if not back_unsafe and _fc_cap.startswith(package):
                    _do_back("人机验证界面")
                elif respawn is not None:
                    try:
                        respawn()
                    except Exception:
                        pass
                seen.clear()
                prev_fp = ""
                time.sleep(max(0.4, interval * 0.6))
                continue

        # ---- 卡死检测：连续点击界面毫无变化，多半是被悬浮窗/蒙层吃了触摸 ----
        # ★ 先结算上一步的"空转"，且必须在 `prev_fp = fp` 之前 ——
        #   顺序反了就是拿这一屏和它自己比，永远判成"变了"。
        _changed = bool(prev_fp) and fp != prev_fp
        # ---- 结算上一步点击的"实际结果"（逐次留痕的后半句）----
        # 留痕记的是"点之前"的界面；点完之后到底换没换屏，只有到了这一屏才知道。
        # 这个对照是自查遍历质量的核心数据：如果大量点击都"界面无变化"，
        # 那是候选生成有问题，不是"这个 App 没什么可点的"。
        if pending_click and 0 < pending_click <= len(res.click_shots):
            _pc = res.click_shots[pending_click - 1]
            if not _pc.get("result"):
                _pc["result"] = "new" if _changed else "same"
                _pc["result_fp"] = (fp or "")[:24]
            pending_click = 0
        _just_banned = _note_act_result(_changed, last_act_sig, act_run, act_banned)
        if _just_banned:
            _lim = int(STUCK_RUN_LIMIT.get(_just_banned, 4))
            _nm = ACT_LABEL.get(_just_banned, _just_banned)
            log("[!] 本屏「%s」连续 %d 次都没换来新界面，停用该动作改走其它路径"
                % (_nm, _lim))
            res.errors.append(
                "遍历在「%s」上连续 %d 次都没切换界面，已停用该动作、改走其它"
                "路径（否则剩余预算会全部耗在同一屏上）" % (_nm, _lim))
        # ---- 把上一步动作记进循环观测 ----
        # 在这里补记而不是每个执行分支各写一遍：动作分支有 9 处，
        # 写漏一处就会出现"某类动作永远不参与振荡判定"——那正是原来
        # 只看点击、看不到"返回↔点击"来回的原因。
        # `prev_fp` 此刻仍是**上一步所在界面**（本轮的 fp 在下面才赋给它）。
        if watch is not None and last_act_sig:
            watch.note(prev_fp or fp, last_act_sig, last_act_uid if last_act_sig == "tap" else "")
            last_act_uid = ""
        last_act_sig = ""
        if last_tap_key and prev_fp and fp == prev_fp:
            stuck += 1
        else:
            stuck = 0
        prev_fp = fp
        last_tap_key = ""

        # ---- 本屏榨干：连续 STUCK_TOTAL_LIMIT 个动作都没换来新界面 ----
        # 这是"1 小时档没跑出更多东西"的最后一道闸：到这步说明这一屏确实
        # 没有可探索的入口了（不是模型没想好，是这屏真没了）。
        # 硬换屏比继续问模型有效：一次模型往返十几秒，问十次也是一样的答案。
        if int(act_run.get("__total__", 0) or 0) >= STUCK_TOTAL_LIMIT:
            act_run.clear()
            act_banned.clear()
            seen.clear()
            # ★ 记住"这一屏已经榨干"（2026-11-05）。高途那一单整轮触发 75 次
            #   "连续 12 个动作没换界面"：每次离开失败（返回被拦）就重来一遍 12 个
            #   动作，62 分钟里绝大多数动作都花在**重复确认同一屏没有入口**上。
            #   榨干过的界面再进来，不再花 12 个动作复核 —— 直接离开。
            exhausted_fps.add(_cur_fp)
            log("[!] 本屏连续 %d 个动作都没有切换界面，判定本屏已无可探索入口，强制离开"
                % STUCK_TOTAL_LIMIT)
            res.errors.append(
                "同一界面连续 %d 个动作（点击/滑动/返回）都没有切换到新界面，"
                "已判定该界面无可继续探索的入口并离开" % STUCK_TOTAL_LIMIT)
            if not back_unsafe and uiwalk.current_focus(res.device_serial).startswith(package):
                _do_back("本屏无新界面")
                if sched is not None:
                    try:
                        sched.note_back(killed=False)
                    except Exception:
                        pass
            elif respawn is not None:
                try:
                    respawn()
                except Exception:
                    pass
            stuck = 0
            prev_fp = ""
            time.sleep(interval)
            continue
        # ---- 循环与饱和判定（台账层，2026-11-01）----
        # 与上面那段的分工：上面看"这一屏点不动了"，这里看"整条路在绕圈"。
        # 两个真机样本都是后者：界面一直在变（A→B→A→B），所以上面那段永远不触发。
        if watch is not None:
            _period = watch.period()
            if _period:
                watch.osc_hits += 1
                osc_rounds += 1
                # 升级策略：先冻结这一屏（换条路继续）→ 再不行就重启应用 →
                # 重启过还不走就是这轮真的没得测了，提前收工。
                # 用户 2026-11-01 明确要求"哪怕要重启应用"，重启的代价（30~60 秒）
                # 远小于把剩下半小时全花在两屏来回。
                if ledger is not None:
                    # 冻结用**页面图指纹**（`_cur_fp`）：台账里记的身份都是它，
                    # 混用 `uiwalk.screen_fingerprint` 会冻不上（两套指纹不通用）。
                    ledger.freeze(_cur_fp,
                                  ttl=float(getattr(cfg.scan, "walk_freeze_sec", 180) or 0))
                log("[!] 检测到界面循环：最近 %d 步与再往前 %d 步完全重复（第 %d 次）"
                    % (2 * _period, _period, osc_rounds))
                res.errors.append(
                    "遍历在第 %d 步陷入界面循环（%d 步一循环、只在少数几屏之间来回），"
                    "已冻结该界面并改走其它路径" % (watch.actions, _period))
                watch.reset_window()
                act_run.clear()
                act_banned.clear()
                seen.clear()
                if osc_rounds >= 3:
                    stop_reason = ("遍历连续 %d 次陷入界面循环（每次都已改换路径仍绕回原处），"
                                   "判定无法继续有效遍历" % osc_rounds)
                    log("[!] %s，提前结束遍历" % stop_reason)
                    res.errors.append(stop_reason)
                    break
                if osc_rounds >= 2 and respawn is not None:
                    # 第二次循环：清一次现场。冷启动会回到首启，界面栈全清，
                    # 但台账**不清** —— 哪些入口已经点过是跨重启有效的事实，
                    # 清掉就会把刚走过的路重新走一遍（这也是原来反复重启没用的原因）。
                    log("[!] 已第 %d 次陷入循环，重启应用以清空界面栈后继续" % osc_rounds)
                    res.errors.append("遍历反复陷入循环，已第 %d 次重启被测应用以复位界面栈"
                                      % osc_rounds)
                    try:
                        respawn()
                    except Exception:
                        pass
                    time.sleep(2.5)
                    prev_fp = ""
                    stuck = 0
                    continue
                if not back_unsafe:
                    _do_back("界面循环")
                    if sched is not None:
                        try:
                            sched.note_back(killed=False)
                        except Exception:
                            pass
                prev_fp = ""
                stuck = 0
                time.sleep(interval)
                continue
            if watch.stalled():
                # 完结判据：走了一大段、见过足够多界面，却再也没有新界面。
                # 这时候继续跑只是把预算换成重复截图 —— 用户 2026-11-01 提的
                # "已经完结的不必非得用尽时间，可以提前进入下一检测阶段"。
                watch.stall_hits += 1
                stop_reason = ("连续 %d 个动作未发现新界面（累计 %d 个界面 / %d 步），"
                               "判定功能遍历已完结，提前结束遍历"
                               % (watch.novel_gap(), len(watch.states), watch.actions))
                log("[!] %s" % stop_reason)
                res.errors.append(stop_reason)
                break

        if stuck >= 3:
            log("[!] 连续 %d 次点击界面无变化，疑似被悬浮窗/蒙层拦截，清理并返回" % stuck)
            try:
                killed = uiwalk.dismiss_overlays(res.device_serial, log=log,
                                                    target_pkg=res.package)
                if killed:
                    res.overlays_dismissed = list(set((res.overlays_dismissed or []) + killed))
                    res.errors.append("遍历中被悬浮窗（%s）拦截触摸，已关闭" % "、".join(killed))
            except Exception:
                pass
            if not back_unsafe:
                uiwalk.back(res.device_serial)
            else:
                uiwalk.swipe_side(res.device_serial, "left")
            seen.clear()
            stuck = 0
            prev_fp = ""
            time.sleep(interval)
            continue

        # 遍历途中若碰到政策页，顺手把正文收割了（很多 App 在设置里放政策入口）
        texts = uiwalk.screen_texts(xml)

        # ---- 广告落地页 / 应用下载页：留证后立刻退，**绝不在上面点任何东西** ----
        # 2026-11-09 Q船实测：点新闻卡片上的广告位，落地页开在应用自己的
        # WebView 里（chengzijianzhan.com / apps.bytesfield.com）。前台包名还是
        # 被测应用，于是被当普通功能页继续点：点「立即下载」→ 真下载了 APK，
        # 点「打开App」→ 跳去夸克/小红书。这既不是应用的功能，也不是它的行为，
        # 却占着步数和截图，还会把设备搞乱（装上一堆推广 App）。
        _ad_why = ""
        if foreignmod is not None and texts:
            try:
                _ad_url = ""
                if getattr(live, "hooked", False):
                    try:
                        _us = live.script.exports_sync.current_urls() or []
                        _ad_url = str(_us[0] if _us else "") or ""
                    except Exception:
                        _ad_url = ""
                _ad_why = foreignmod.looks_like_ad_landing(
                    " ".join(texts[:80]), url=_ad_url,
                    app_name=str(getattr(res, "app_name", "") or ""))
            except Exception:
                _ad_why = ""
        if _ad_why:
            if _cur_fp not in ad_page_fp:
                ad_page_fp.add(_cur_fp)
                _alab = (getattr(last_tap_node, "label", "") or "").strip()
                log("[!] 当前页是广告落地/下载页（%s，入口「%s」）—— 留证后返回，"
                    "本页不点击任何按钮（避免触发下载/跳转推广应用）"
                    % (_ad_why, _alab or "未知"))
                res.errors.append(
                    "遍历中打开了广告落地/下载页（%s，入口「%s」）；该页不是被测"
                    "应用的业务功能，已截图留证后返回，未在其上执行任何点击"
                    % (_ad_why, _alab or "未知入口"))
                res.ui_steps.append("广告页：「%s」→ %s，跳过" % (_alab or "未知", _ad_why))
                if ad_shots < 2:
                    _raw = capture_screenshot(res.device_serial)
                    if _raw:
                        ad_shots += 1
                        res.screenshots.append({
                            "label": "广告落地页：%s" % _ad_why[:40],
                            "activity": _activity(),
                            "b64": base64.b64encode(_raw).decode("ascii"),
                        })
                if _alab:
                    foreign_labels.add(_alab)
            if (not back_unsafe
                    and uiwalk.current_focus(res.device_serial).startswith(package)):
                _do_back("广告页跳过")
                if sched is not None:
                    try:
                        sched.note_back(killed=False)
                    except Exception:
                        pass
            elif respawn is not None:
                try:
                    respawn()
                except Exception:
                    pass
            prev_fp = ""
            seen.clear()
            time.sleep(max(0.7, interval * 0.6))
            continue

        # ---- 打不开的页面：留一张证据图，然后立刻退（2026-11-03 高途/万步健康）----
        # 用户的原话：「网络链接有问题的页面，这种我觉得实在看不了，也可以跳过」。
        # 这类页面（"网络连接有问题""无法访问此网站""404"）既没有功能入口，
        # 也不是应用的真实界面，停在上面的每一秒都是纯浪费 —— 更糟的是它会被
        # 当成"一个普通界面"记进覆盖度，让人误以为走到过一个功能页。
        # 处置：留一图（最多 2 张，不抢遍历配额）→ 记一条事实 → 立刻退。
        _errsign = ""
        if docread is not None and texts:
            try:
                _errsign = docread.error_sign(texts)
            except Exception:
                _errsign = ""
            # ★ 长度闸门：错误页都很短（几十到两三百字）。一屏正常内容里
            #   夹一句"加载失败，点击重试"（列表底部、评论区很常见）不该
            #   被当成错误页退出去 —— 那会把整页的功能入口一起丢掉。
            if _errsign and len(" ".join(texts)) > 800:
                _errsign = ""
        if _errsign:
            if _cur_fp not in err_page_fp:
                err_page_fp.add(_cur_fp)
                _elab = (getattr(last_tap_node, "label", "") or "").strip()
                log("[!] 当前页面打不开（命中「%s」，入口「%s」）——留证后返回，跳过该页"
                    % (_errsign, _elab or "未知"))
                res.errors.append(
                    "遍历中打开的页面无法访问（命中「%s」，入口「%s」）；"
                    "该页没有可用功能，已跳过，对应功能按「跳过未测」处理"
                    % (_errsign, _elab or "未知入口"))
                res.ui_steps.append("错误页：「%s」→ 命中「%s」，跳过" % (_elab or "未知", _errsign))
                if err_shots < 2:
                    _raw = capture_screenshot(res.device_serial)
                    if _raw:
                        err_shots += 1
                        res.screenshots.append({
                            "label": "错误页：%s" % _errsign,
                            "activity": _activity(),
                            "b64": base64.b64encode(_raw).decode("ascii"),
                        })
            if (not back_unsafe
                    and uiwalk.current_focus(res.device_serial).startswith(package)):
                _do_back("错误页跳过")
                if sched is not None:
                    try:
                        sched.note_back(killed=False)
                    except Exception:
                        pass
            elif respawn is not None:
                # 错误页本身就是根界面（没有上一级可退）：重拉一次再看。
                try:
                    respawn()
                except Exception:
                    pass
            prev_fp = ""
            seen.clear()
            time.sleep(max(0.7, interval * 0.6))
            continue

        # ---- 系统权限弹窗：先取证，再代点「允许」继续 ----
        # 必须在普通点击之前拦下来：若交给规则遍历，它会点完就走，
        # 弹窗原文与弹窗前界面都不会被记录，Q026 便无从判定。
        if _capture_perm_dialog(res, xml, res.device_serial, log, "P4",
                                pre_text=last_app_texts, seen=perm_seen):
            last_tap_key = ""
            prev_fp = fp
            time.sleep(max(0.6, interval * 0.5))
            continue
        # 普通 App 界面 → 记为"下一个权限弹窗的前一屏"
        if texts:
            last_app_texts = " ".join(texts)[:600]

        # ---- 登录 / 注册页：代填测试账号（整轮只尝试一次）----
        # 不登录，遍历只能走游客可见的那几屏，"我的/设置/注销"永远到不了。
        _login_info = None
        # ★ 无论有没有配测试手机号都要识别登录页（2026-11-05）：
        #   识别它的第一目的是"别在登录页上瞎点"，其次才是代填。
        #   旧代码写成 `if login_phone or attempted:`，没配号就等于不认识登录页
        #   —— 春雨诊所在 H5 登录页上点了「注册→立即注册→短信验证码登录→忘记密码」，
        #   半轮预算没了，而首页就在后面。
        try:
            _login_info = uiwalk.login_screen(xml)
        except Exception:
            _login_info = None
        if _login_info is None:
            try:
                _login_info = uiwalk.login_screen_weak(xml)
            except Exception:
                _login_info = None

        # ★ 实名 / 资质认证页：**一个字都不许填，也不要往下点**
        #   （2026-11-06 春雨诊所实测：登录成功后落在「实名认证」，
        #    要姓名、执业科室、执业证件、人脸认证、手写签名）。
        #   遍历比着陆更危险：它会按候选表一路点「下一步」，等于替被测应用
        #   索要真实身份材料。所以这里只做一件事——认出来、记一句、退回去。
        try:
            _rn = landing_mod.classify(xml, res.package,
                                       uiwalk.parse_all(xml))
        except Exception:
            _rn = {"form": "unknown"}
        if str(_rn.get("form") or "") == "realname_gate":
            if not res.login.get("realname_gate"):
                res.login["realname_gate"] = True
                log("[!] 当前界面是实名/资质认证页（%s），本轮不去填它："
                    "这类表单要真实身份、证件与人脸，检测不代填"
                    % str(_rn.get("why") or "")[:60])
                res.errors.append(
                    "登录后进入实名/资质认证页（%s）；检测方不具备真实身份与"
                    "执业资质，认证后的功能未覆盖，该页全程未做任何填写"
                    % str(_rn.get("why") or "")[:40])
            _rn_tried = int(res.login.get("realname_back") or 0)
            if _rn_tried < 2:
                res.login["realname_back"] = _rn_tried + 1
                if not back_unsafe:
                    _do_back("实名认证页")
                    time.sleep(interval)
                    continue
            else:
                # ★ 退两次还回到原地 → 判定为硬墙，收工（2026-11-06 春雨诊所 land28）。
                #   真相是：实名/资质认证页就是**登录流程的下一屏**，按返回退回登录页，
                #   而登录页上的「登录」「注册」一点又撞回实名页。
                #   不刹车时那一轮的实测代价：240 秒预算里点了 9 次
                #   （登录/注册/立即注册）、按了 11 次返回、5 次"重新登录成功"，
                #   新增功能页 0 个，还在报告里留下"登录态未保持"这条**假原因**。
                #   墙后的功能整体不可达，继续跑只会污染覆盖率数字。
                stop_reason = (
                    "登录后首屏即实名/资质认证页（%s），退回两次仍回到原地："
                    "墙后的功能整体不可达，遍历到此为止；该页全程未做任何填写"
                    % str(_rn.get("why") or "")[:40])
                log("[!] %s" % stop_reason)
                res.errors.append(stop_reason)
                res.login["realname_wall_stop"] = True
                break

        # ---- 调研 / 选择页：按问卷流程处理，不当功能遍历 ----
        # ★ 2026-11-06 高途实测（用户反馈）：首启学段选择页（选项从小学到
        #   成人教育，底部「进入首页」）被当成功能遍历 —— 选项被逐个当
        #   "功能入口"点过去，「进入首页」是碰巧点到的，问卷的证据
        #   （应用首启即收集学段/身份画像）被打散在遍历轨迹里。
        #   正确做法 = 模仿真实用户：选一项 + 点提交，两步各留痕；
        #   走完这道问卷继续正常遍历。判据复用上面实名墙那份 classify。
        if (str(_rn.get("form") or "") == "survey_gate"
                and survey_steps < SURVEY_STEP_CAP):
            _sv_nodes = uiwalk.parse_all(xml)
            _sv_texts = list(uiwalk.screen_texts(xml))
            _sv_act = landing_mod.plan("survey_gate", _sv_nodes, _sv_texts,
                                       tried=list(survey_tried),
                                       back_unsafe=back_unsafe)
            _sv_node = _sv_act.get("node")
            if _sv_act.get("action") == "tap" and _sv_node is not None:
                survey_steps += 1
                survey_tried.append(landing_mod.node_key(_sv_node))
                _sv_lab = (getattr(_sv_node, "label", "")
                           or getattr(_sv_node, "text", "") or "").strip()[:14]
                log("[*] 调研/选择页：按问卷流程处理 —— 「%s」（%s）"
                    % (_sv_lab, _sv_act.get("code")))
                if _sv_act.get("code") == "survey_select":
                    # 问卷作答留一张证（提交那步通常界面就换了，截图意义不大）
                    try:
                        _raw = capture_screenshot(res.device_serial)
                        if _raw:
                            res.screenshots.append({
                                "label": "调研页作答：选「%s」（%s）"
                                         % (_sv_lab, str(_rn.get("why") or "")[:40]),
                                "activity": _activity(),
                                "b64": base64.b64encode(_raw).decode("ascii"),
                            })
                    except Exception:
                        pass
                res.ui_steps.append("调研页：%s（%s）"
                                    % (_sv_lab, _sv_act.get("code")))
                # 回放按 tap 执行（KINDS 里没有 survey，塞进去复现轮不会执行）；
                # `src=survey` 标明这是问卷作答，不是功能入口点击。
                try:
                    _sb = _sv_node.bounds
                    _sx = (_sb[0] + _sb[2]) // 2
                    _sy = (_sb[1] + _sb[3]) // 2
                except Exception:
                    _sx = _sy = 0
                _rec("tap", label=_sv_lab, cls=_sv_node.cls,
                     uid=getattr(_sv_node, "resource_id", ""),
                     at=[_sx, _sy], bounds=list(getattr(_sv_node, "bounds", [])
                                                or [0, 0, 0, 0]),
                     src="survey")
                uiwalk.tap_node(res.device_serial, _sv_node)
                prev_fp = ""
                seen.clear()
                time.sleep(max(1.0, interval))
                continue
            # plan 给不出动作（选项/提交都找不到）→ 不拦着，按普通页面继续

        # ★ "上一屏是不是登录页"（2026-11-05 万步健康）：登录门只该在
        #   **从非登录页进入登录页**时成立。它的首屏同意完就是注册/登录页，
        #   在那页上点「注册」单选钮（rb_easy）、返回箭头（iv_back），
        #   都被记成"入口 rb_easy 需要登录才能使用"，还把同屏候选剔掉。
        #   这两行必须在所有 continue 之前更新，否则计数会漏轮。
        _was_login_prev = _login_prev_round
        _login_prev_round = _login_info is not None
        if _login_info is None and login_gate_hits:
            # 已经离开登录页：门的计数归零（下次再被挡是另一件事）
            login_gate_hits = 0
        if _login_info is not None and login_phone and not res.login.get("attempted"):
            if _login_assist(res, xml, res.device_serial, log, login_phone,
                             get_sms_code, login_timeout, should_stop):
                # ★ 登录本身也要记进路径，但**只有真登录成功才记**。
                #   `_login_assist` 只要"尝试过"就返回 True（它还要负责
                #   `seen.clear()` 与重新 dump），真实结果在 `res.login["ok"]`。
                #   按返回值记会把"验证码没到/被风控"也记成一次登录，
                #   复现轮照着去登录 → 两轮登录态不同 → 从登录点往后全对不上
                #   （mbsf17 实测：首轮登录失败、复现轮登录成功）。
                if res.login.get("ok"):
                    _rec("login", src="assist")
                    login_gate_hits = 0
                    login_gate_uids.clear()
                prev_fp = ""
                seen.clear()
                time.sleep(1.2)
                continue
        # ---- 登录门（2026-11-03 携船网 / 万步健康）----
        # 这两家的形态一样：**点首页任何一个功能都跳登录页**。
        # 旧代码把它当成"又一个界面"继续点，于是：
        #   · 携船网 3 次循环 → 判"陷入界面循环"整轮结束（实际主页还没看几眼）；
        #   · 万步健康在同一屏点了 275 次（全被台账拦下），烧掉 68 分钟。
        # 正确的处置是用户指出的那条：**先试着登录；登不上就把这个入口记成
        # "需登录"，退回去继续走不需要登录的功能**，而不是在原地打转。
        if res.login.get("attempted") and not res.login.get("ok") and _login_info is None:
            # 登录尝试过但已经不在登录页（登进去了 / 被弹回首页）：不算门。
            login_gate_hits = 0
        # ★ 登录后首屏即实名墙时，"又回到登录页"是**我们自己按返回退回来的**，
        #   不是登录态丢失（2026-11-06 春雨诊所 land28 实测：实名页按 back 就回登录页）。
        #   旧代码无条件写成「登录态未保持，可能与多端登录限制有关」——复核员会
        #   顺着这句去查会话/设备锁，而真正的原因是资质门槛。假原因比没原因更糟。
        if (_login_info is not None and res.login.get("ok")
                and res.login.get("realname_gate")
                and _cur_fp not in login_repeat_fp):
            login_repeat_fp.add(_cur_fp)
            res.login["bounced_from_realname"] = True
            log("[.] 实名墙退回登录页（预期）：登录态仍在，不重登、不记错误")
        elif _login_info is not None and res.login.get("ok") and _cur_fp not in login_repeat_fp:
            # 刚登录成功又回到登录页：这是"登录态没有保持"的事实，值得记一句，
            # 但不能当成"需要登录"的门 —— 再登录一次只会刷短信、还可能触发风控。
            login_repeat_fp.add(_cur_fp)
            log("[!] 登录成功后又回到登录页（登录态未保持），不再重复登录，直接退回")
            res.errors.append(
                "测试账号登录成功后再次进入登录页（登录态未保持），未重复登录；"
                "该现象可能与账号会话/多端登录限制有关，需人工复核")
            # ★ 但"再登一次"不等于"再发一次短信"（2026-11-06 春雨诊所实测）：
            #   那一单刚注册成功就被弹回登录页，如果就此封口，登录后的功能
            #   一项都测不到。台账里已经有号，用密码登一次**不产生任何短信**，
            #   成本极低；失败也只试一次，不会锁号。
            #   上限 2 次：登进去又被弹回来，说明卡在后面某道我们过不去的门
            #   （春雨是"实名认证"），这时继续登只会空转，不是登录本身的问题。
            res.login["bounces"] = int(res.login.get("bounces") or 0) + 1
            if (not res.login.get("pwd_relogin")
                    and int(res.login.get("bounces") or 0) <= 2):
                from . import accounts as _acc_mod
                _ph = str(res.login.get("phone_full") or "")
                _acc = _acc_mod.find(res.package, _ph) if _ph else None
                if _acc and _acc.get("password"):
                    res.login["pwd_relogin"] = True
                    log("[*] 台账里有这个应用的账号：用密码重新登录一次（不重发短信）")
                    if _password_login(res, xml, res.device_serial, log, _ph,
                                       str(_acc["password"])):
                        log("[+] 用台账密码重新登录成功")
                        res.login["account_source"] = res.login.get("account_source") \
                            or "台账"
                        login_gate_hits = 0
                        login_repeat_fp.clear()
                    else:
                        log("[!] 台账密码也没登进去（可能密码被改或账号未真正建成）")
        if _login_info is not None and (
                (res.login.get("attempted") and not res.login.get("ok"))
                or not login_phone):
            _gate_label = (clickev.plain_label(
                getattr(last_tap_node, "label", "") or "",
                getattr(last_tap_node, "cls", "") or "") or "无文字入口")
            # 名字是资源 id（tvConfirm/iv_back/rb_easy）的，读不出它是什么入口 ——
            # 这种情况下**不能断言"这个入口需要登录"**，只能记"点了它之后到了登录页"。
            _gate_unreadable = clickev.unreadable(_gate_label)
            _gate_title = (_login_info.get("title") or "登录/注册页")
            _gate_uid = _led_uid(last_tap_node) if last_tap_node is not None else ""
            login_gate_hits += 1
            _gate_new_entry = bool(_gate_uid) and _gate_uid not in login_gate_uids
            # ★ 同意/确认类按钮不是"需要登录的入口"（2026-11-05 高途实测）：
            #   它首屏是「我已年满14周岁」+「同意」，点了之后就进 LoginActivity。
            #   旧代码把那个「tvConfirm」记成"入口「tvConfirm」需要登录才能使用"，
            #   并把它从候选里剔除 —— 结果整轮只点了 1 次就收工（基线同样 8 分钟
            #   能点几十次）。**流程推进按钮之后落登录页**是 App 的正常设计，
            #   不是"这个入口需要登录"，归因错了会连带把整屏候选一起剔掉。
            _gate_is_flow = (_was_login_prev
                             or any(w in (_gate_label or "") for w in _GATE_FLOW_WORDS))
            if _gate_is_flow:
                if login_gate_hits <= 1:
                    log("[.] 点击「%s」后在登录流程内跳转（进入「%s」），"
                        "不计作「该入口需要登录」" % (_gate_label, _gate_title))
                _gate_new_entry = False
            if _gate_new_entry:
                login_gate_uids.add(_gate_uid)
                # 只用于报告文案：入口名可能为空（携船网首页全是无文字的 FrameLayout），
                # 那种情况写"无文字入口"，不能写空串让报告出现「、」这种断句。
                login_gate_labels.append(_gate_label or "无文字入口")
                if _gate_unreadable:
                    # 名字是资源 id 时，只能陈述"点了它之后到了登录页"，
                    # 不能断言"这个入口是需要登录的功能入口"—— 我们分辨不出来。
                    log("[!] 点击「%s」（无中文文字的可点控件）后进入「%s」；登录未完成，"
                        "本轮不再点它" % (_gate_label, _gate_title))
                    res.errors.append(
                        "界面上一个无文字的可点控件（标识「%s」）点击后进入「%s」；"
                        "测试账号登录未成功，该路径按「跳过未测」处理"
                        "（不代表应用没有该功能）" % (_gate_label, _gate_title))
                else:
                    log("[!] 入口「%s」需要登录才能使用（进入「%s」）；登录未完成，"
                        "本轮不再点它，改走其它无需登录的入口" % (_gate_label, _gate_title))
                    res.errors.append(
                        "入口「%s」点击后进入「%s」，需登录后使用；测试账号登录未成功，"
                        "该入口对应的功能按「跳过未测」处理（不代表应用没有该功能）"
                        % (_gate_label, _gate_title))
            # ★ 登录墙的第二种形态：重拉之后**还是**登录页（2026-11-05 携船网实测）。
            #   返回键失效 → 重拉应用 → uni-app 恢复路由栈，冷启动直接落在
            #   同一个登录页上，期间一个新入口都没试过。这时继续重拉只是在
            #   同一个页面上反复冷启动（实测 3 次、每次约 10 秒，界面数一个没涨）。
            #   判据要求"重拉过 + 这一轮没有新入口"，所以"重拉后回到首页、
            #   再点下一个入口"的正常路径不会被误判。
            #   ★ 阈值是**连续 2 次**而不是 1 次：携船网的路由恢复不稳定，
            #     有时重拉回首页、有时回登录页。按 1 次判，第 4 轮实测在
            #     第 1 次重拉就收工，只点了 3 个入口（剩下 2 个没试过）；
            #     而按 3 次判，第 3 轮实测有 25 轮空转。2 次是这两者的折中：
            #     最多花两次重拉（约 20 秒）确认"回不去"，不再往里填预算。
            if gate_respawns >= 2 and not _gate_new_entry:
                stop_reason = (
                    "登录页不响应返回键，连续 2 次重拉应用后仍然直接落在登录页"
                    "（冷启动恢复的是登录页而不是首页），期间没有可试的新入口；"
                    "该应用登录前的可见界面已走到尽头，登录后才可用的功能"
                    "按「跳过未测」处理（不代表应用没有这些功能）")
                res.errors.append(stop_reason)
                log("[!] %s，提前结束遍历" % stop_reason)
                break
            # ★ 返回键在这个登录页上无效（2026-11-05 携船网实测）：
            # uni-app 的 H5 登录页把 KEYCODE_BACK 吃掉了 —— 整轮 300 秒里
            # 只点了 1 次，按了 51 次返回，界面一次没换（界面上 12 个界面里
            # 有 10 个是登录页重复记录）。这不是"需要登录"，是**返回失效**：
            # 连续两轮"进了登录页、按返回还停在登录页"就判定失效，
            # 直接重拉应用回首页，让遍历去试下一个入口。
            gate_back_run += 1
            # ★ 登录页上的返回键会**把 App 退掉**（春雨诊所 2026-11-05）：
            #   它的 SignInActivity 按返回直接回到桌面，采集侧却在日志里写
            #   "从登录页退回上一级"——然后失焦重拉，回来还是登录页，再按再退。
            #   一旦确认过就该换招：此后在这个登录页上直接重拉应用，不再按返回。
            if login_back_unsafe and gate_back_run < 2:
                gate_back_run = 2
            if gate_back_run >= 2:
                log("[!] 登录页不响应返回键（连续 %d 次按返回仍停在登录页），"
                    "改为重拉应用回首页继续" % gate_back_run)
                res.errors.append(
                    "该应用的登录页不响应返回键：在登录页连按 %d 次返回仍停留原页，"
                    "已改为重拉应用返回首页；登录页自身的元素因此无法遍历"
                    % gate_back_run)
                gate_back_run = 0
                gate_respawns += 1
                try:
                    if respawn is not None:
                        respawn()
                    else:
                        launch_app(res.device_serial, package)
                except Exception:
                    pass
                if sched is not None:
                    try:
                        sched.note_back(killed=False)
                    except Exception:
                        pass
                prev_fp = ""
                seen.clear()
                act_run.clear()
                act_banned.clear()
                time.sleep(1.5)
                continue
            _depth = int(getattr(sched, "depth", 0) or 0) if sched is not None else 0
            if _depth >= 1:
                # 有上一屏可回：退回并继续走其它入口（这是"放弃登录功能"的正常路径）。
                log("[.] 从登录页退回上一级，继续遍历无需登录的功能")
                if not back_unsafe:
                    _do_back("登录门退回")
                    # 按完立刻看前台：离开了被测应用 = 这个登录页上的返回键会退掉
                    # App（春雨诊所 SignInActivity）。记下来，下次直接重拉，
                    # 不然会陷入"按返回→退到桌面→重拉→又是登录页→再按返回"。
                    try:
                        # ★ 这里原来写的是裸 `serial`（该作用域里没有这个名字），
                        #   NameError 被下面的 except 吞掉 → `_foc_after` 永远是空
                        #   → "登录页按返回会退掉 App"这个判据**从来没生效过**。
                        #   真机表现就是：按返回退到桌面 → 重拉 → 又是登录页 →
                        #   再按返回，来回打转（2026-11-06 春雨诊所实测）。
                        _foc_after = uiwalk.current_focus(res.device_serial) or ""
                    except Exception:
                        _foc_after = ""
                    if (_foc_after and package
                            and not _foc_after.startswith(package + "/")
                            and not _is_external_focus(_foc_after, package)):
                        login_back_unsafe = True
                        log("[!] 登录页上按返回把 App 退出了（前台 %s）；"
                            "此后改用重拉应用，不再按返回"
                            % (_foc_after.split("/")[-1] or "?"))
                        res.errors.append(
                            "该应用的登录页上按返回键会把 App 退出到桌面（前台变为 %s）；"
                            "已改为重拉应用返回首页后继续"
                            % (_foc_after.split("/")[-1] or "?"))
                elif respawn is not None:
                    # 返回键在这个 App 上会把进程退掉（back_unsafe），
                    # 改用"重拉应用"回首页 —— 总比卡在登录页上强。
                    try:
                        respawn()
                    except Exception:
                        pass
                if sched is not None:
                    try:
                        sched.note_back(killed=False)
                    except Exception:
                        pass
                prev_fp = ""
                seen.clear()
                time.sleep(max(0.8, interval * 0.7))
                continue
            # 没有上一屏：应用首屏就是登录门。给一次机会找"游客/跳过"，
            # 再不行就明确收工 —— 继续点只是把预算换成同一个登录页。
            if _login_info.get("weak"):
                # 结构树里连输入框都没有（WebView/自绘登录页）：在上面找"游客/跳过"
                # 是徒劳的，点击也换不来新界面。重拉一次应用回首页 ——
                # 多数 App 首启弹窗点过同意后，重拉会直接落到首页而不是登录页。
                exhausted_fps.add(_cur_fp)
                log("[.] 登录页（结构树无输入框）在首屏，重拉应用回首页再继续")
                if respawn is not None:
                    try:
                        respawn()
                    except Exception:
                        pass
                else:
                    launch_app(res.device_serial, package)
                seen.clear()
                prev_fp = ""
                act_run.clear()
                act_banned.clear()
                time.sleep(2.0)
                continue
            if login_gate_hits >= 3:
                stop_reason = (
                    "应用首屏即为「%s」，测试账号未能完成登录（%s）；"
                    "登录前的可见功能已遍历完，登录后才可用的功能按「跳过未测」处理"
                    % (_gate_title, (res.login.get("note") or "未配置可用的登录凭据")))
                res.errors.append(stop_reason)
                log("[!] %s，提前结束遍历" % stop_reason)
                break

        # ---- 登录墙：把"这条路全被登录挡住"认下来，别把预算换成来回 (2026-11-05) ----
        # 携船网实测：首页每个入口点进去都是登录页，退回来再点下一个 ——
        # 一轮 40 次"进登录页 → 退回"，界面数没长，预算全花在往返上。
        # 用户的口径是"登不上就放弃需要登录的功能，遍历其它无需登录的"：
        # 当已经确认 ≥N 个不同入口都指向登录页时，剩下的入口基本都是同一堵墙，
        # 该停就停，并把"是登录墙，不是没功能"写清楚。
        if (not _login_info and not res.login.get("ok")
                and len(login_gate_uids) >= _LOGIN_GATE_STOP):
            stop_reason = (
                "已确认 %d 个不同入口（%s 等）点进去都是登录/注册页，测试账号未完成登录；"
                "其余功能同样在登录态之后，继续点击只会在首页与登录页之间往返。"
                "按「跳过未测」处理，不代表应用没有这些功能"
                % (len(login_gate_uids), "、".join(login_gate_labels[:4]) or "多个入口"))
            res.errors.append(stop_reason)
            log("[!] %s，提前结束遍历" % stop_reason)
            break
            log("[.] 首屏是登录页且无法登录，尝试寻找「游客 / 跳过」类入口（第 %d 次）"
                % login_gate_hits)
            seen.clear()
            act_run.clear()
            act_banned.clear()
            time.sleep(max(0.8, interval))
            continue

        if any(k in t for t in texts for k in ("隐私政策", "个人信息保护政策", "隐私协议")):
            chunk = _harvest_ui_text(xml)
            # 同样要过归属闸门：深挖之后，界面上出现的"隐私政策"未必是 App 的
            # （意见反馈 SDK、客服 SDK、小程序容器都有自己的政策页）。
            if chunk and _keep_policy_text(res.policy_capture, chunk, "",
                                           "遍历中界面文本"):
                log("    [UI] 遍历中捕获到政策文本 %d 字" % len(chunk))

        # 走到这里说明这一屏不是登录门（能出候选了）：返回键是有效的，
        # "连续停在登录页"的计数清零。放在候选生成之前而不是循环开头，
        # 是因为循环里有若干 continue 会跳过本行 —— 那样计数会被误清。
        gate_back_run = 0
        clicks_all = uiwalk.clickable(xml)
        # ---- 登录门剔除（2026-11-03）----
        # 已经验证过"点进去只是登录页"的入口，本会话不再点：携船网/万步健康
        # 都是在同一屏反复点同一个入口进登录页，一次新的东西都没多到。
        # 剔除放在**候选生成之前**，规则 / 图引导 / 自由规划三条路因此都看不到它
        # （以前只在调度器里剔除，AI 那条路照样会把它选回来）。
        if login_gate_uids:
            _gbefore = len(clicks_all)
            clicks_all = [n for n in clicks_all
                          if _led_uid(n) not in login_gate_uids]
            if len(clicks_all) != _gbefore and _cur_fp not in gate_seen_fp:
                gate_seen_fp.add(_cur_fp)
                log("    [登录门] 本屏 %d 个入口因「需登录」从候选剔除，剩余 %d 个"
                    % (_gbefore - len(clicks_all), len(clicks_all)))
            # ★ 本屏已经没有"不需要登录"的入口了（2026-11-05 携船网实测）：
            #   日志原话「本屏 1 个入口因「需登录」从候选剔除，剩余 0 个」，
            #   之后 25 轮里一次点击都没有 —— 调度器认为"本屏入口已点完/已到底"，
            #   在首页上按返回把 App 退出、失焦重拉、又回到同一个首页，
            #   300 秒预算里有 150 秒烧在这条回路上，界面数一个没涨。
            #   这不是"界面榨干"，是**登录墙**：所有结构树可见的入口都指向登录页。
            #   判据要求"只剩登录门入口"而不是"点过几次"，所以它不会误伤
            #   那种"首页一大半入口不用登录"的应用（那时 clicks_all 非空）。
            _depth_now = int(getattr(sched, "depth", 0) or 0) if sched is not None else 0
            if not clicks_all and len(login_gate_uids) >= 2 and _depth_now <= 0:
                stop_reason = (
                    "首页结构树里可点的入口（%s）点进全部是登录/注册页，"
                    "剔除这些入口后本屏已无可遍历的候选，测试账号未完成登录；"
                    "其余功能都在登录态之后，继续遍历只会在首页与登录页之间往返。"
                    "按「跳过未测」处理，不代表应用没有这些功能"
                    % ("、".join(login_gate_labels[:4]) or "多个入口"))
                res.errors.append(stop_reason)
                log("[!] %s，提前结束遍历" % stop_reason)
                break

        # ---- 遮挡剔除（2026-11-01 人工接管实测）----
        # 设置页「关于」的 bounds 与底部**固定**导航栏「图片墙」几乎重合，
        # 点「关于」实际切到了图片墙 tab：白花一步之外，更糟的是后面每一步
        # 的判断都建立在"我在关于页"这个错误前提上。这类入口直接从候选拿掉，
        # 并且在日志与报告里留一句 —— 否则"这屏为什么少点了几个"没法回答。
        try:
            occ = uiwalk.occluded_map(xml)
        except Exception:
            occ = {}
        if occ:
            _ofp = _cur_fp or fp or ""
            if _ofp not in occ_seen_fp:
                occ_seen_fp.add(_ofp)
                _onm = "、".join(sorted({v for v in occ.values()})[:3])
                log("    [遮挡] 本屏 %d 个可点入口被其它控件压住（如被「%s」遮挡），"
                    "已从候选剔除" % (len(occ), _onm))
                res.errors.append(
                    "界面布局中有 %d 个可点入口被其它控件遮挡（点它实际会落到遮挡物上），"
                    "已从遍历候选剔除；该界面的覆盖可能因此减少" % len(occ))
        sched_step = None
        if sched is not None:
            # ---- 调度期：候选由调度器按**本界面**记账过滤 ----
            # 刻意不用全局 `seen`：旧逻辑里 A 屏点完进 B 屏、再返回 A 时，
            # A 的元素仍算"已点过"，于是什么都点不到 → 触发无候选三拍 → 又离开 A。
            # "回到上一级后复查"（开关点完会不会变、再进一次还弹不弹窗）是取证重点。
            nodes = [n for n in uiwalk.sort_by_priority(clicks_all)
                     if not uiwalk.is_dangerous(n) and not uiwalk.is_no_use(n)
                     and uiwalk.node_key(n) not in occ]
            # 台账过滤（第三层，与上面两处同一份账）：本屏已经点够次的入口
            # 不再作为候选。调度器自己的 `uids_clicked` 认不出 AI 点的那些 ——
            # 那正是"规则说点完了、AI 又点一遍"的来源。
            if ledger is not None:
                nodes = [n for n in nodes if not ledger.tap_blocked(_cur_fp, _led_uid(n))]
            try:
                # 政策正文到手了没有？每步同步一次（只是 dict.get，成本可忽略）。
                # 取到了 —— DEEPEN 里「隐私政策」这类入口往后压，省下预算；
                # 没取到 —— 它是最后能拿到条款的地方，必须排在前面。
                sched.policy_ready = bool(
                    ((getattr(res, "policy_capture", None) or {}).get("bestText")
                     or "").strip())
                sched_step = sched.decide(
                    obs.current if obs is not None else "",
                    clicks_all, snap_nav,
                    progress=_ai_ratio(), back_unsafe=back_unsafe)
            except Exception:
                sched_step = None
            # 调度器选中的那个也要查账：它只按 `uids_clicked` 判"点过没有"，
            # 而台账还管着"点过几次""这屏是不是刚被冻结"。
            if (sched_step is not None and sched_step.action == "tap"
                    and sched_step.node is not None and ledger is not None
                    and ledger.tap_blocked(_cur_fp, _led_uid(sched_step.node))):
                sched_step = None
            has_cand = bool(sched_step is not None and sched_step.action == "tap")
        else:
            nodes = [n for n in uiwalk.sort_by_priority(clicks_all)
                     if n.key not in seen and not uiwalk.is_dangerous(n)
                     and not uiwalk.is_no_use(n)
                     and uiwalk.node_key(n) not in occ]
            if ledger is not None:
                nodes = [n for n in nodes if not ledger.tap_blocked(_cur_fp, _led_uid(n))]
            has_cand = bool(nodes)

        # ---- 内容型页面：同构条目也不给 AI 补位当候选（2026-11-03）----
        # 调度器已经把"每页只抽 1 条"做完，但它返回 scroll/back 之后，调用方还会
        # 用 AI 补位；模型看截图分不出"这 8 张卡片是同一模板"，会一张张点下去。
        # 规则 / AI 图引导 / AI 自由规划三条路共用这份候选表，堵一处等于全堵。
        _cst = obs.states.get(_cur_fp) if obs is not None else None
        _cskip = set(getattr(_cst, "content_items", set()) or set())
        if _cskip and nodes and obs is not None:
            nodes = [n for n in nodes if obs.uid_for(n) not in _cskip]
            if not has_cand:
                has_cand = bool(nodes)

        if not has_cand:
            # ---- 调度器要求先滚动或回退时，直接照办 ----
            # 它已经知道"本屏的入口都点完了"，再让视觉补位在这屏上耗一次
            # 模型调用就是纯浪费；而"本屏已到底"时继续盲滑也找不到新东西。
            if sched_step is not None and sched_step.action == "scroll":
                # ★ 传给调度器的必须是**图指纹**（`obs.current`），不是上面那个
                #   `uiwalk.screen_fingerprint`：两套指纹算法不同，混用会让"滚完
                #   界面变没变"永远判成"变了"，于是永远不标记"已滚到底"——
                #   真机实测就卡在这里：原地滚 9 次、一次都没回退。
                sched.note_scroll(obs.current if obs is not None else "")
                uiwalk.scroll(res.device_serial, "down")
                _rec("swipe", dir="down", scroll=True, src="sched",
                     fp=(obs.current if obs is not None else ""))
                res.ui_steps.append("调度：本屏入口已点完，向下滚动")
                log("    [调度] %s" % sched_step.reason)
                last_act_sig = "swipe:down"
                time.sleep(interval)
                continue
            if sched_step is not None and sched_step.action == "pull":
                # 已滚到底的列表页：再"甩"一次，触发上拉加载下一页。
                # 用普通 scroll 碰不到加载阈值，表现就是"滚十几次还是那批内容"。
                sched.note_scroll(obs.current if obs is not None else "", kind="pull")
                uiwalk.pull_up(res.device_serial)
                _rec("pull", src="sched",
                     fp=(obs.current if obs is not None else ""))
                res.ui_steps.append("调度：列表已到底，上拉尝试加载下一页")
                log("    [调度] %s" % sched_step.reason)
                last_act_sig = "pull"
                time.sleep(max(1.0, interval))
                continue
            if sched_step is not None and sched_step.action == "back":
                # ★ 本屏返回已经被判无效时，调度器这条路也要堵住。
                #   原来只有 AI 分支受限，调度器照旧返回 —— 两边一边堵一边放，
                #   死循环只是换了个入口继续跑。
                # ★ 台账上限另算一道：`act_banned` 只认"**连续**无效"，
                #   一旦两次返回之间夹了一次点击（A 屏点一下 → B 屏返回 → …），
                #   计数就被清零，于是同一屏返回 225 次也不触发（冰纷万象实测）。
                _back_cap = _led_act("back")
                if _act_blocked("back", act_banned) or _back_cap:
                    log("    [调度] 本屏返回已不可用（%s），跳过该动作，改找其它出口"
                        % (_back_cap or "连续无效"))
                    sched_step = None
                else:
                    log("    [调度] %s" % sched_step.reason)
                    res.ui_steps.append("调度：返回上一级")
                    _rec("back", src="sched",
                         fp=(obs.current if obs is not None else ""))
                    last_act_sig = "back"
                    killed = _do_back("调度回退")
                    try:
                        sched.note_back(killed=killed)
                    except Exception:
                        pass
                    if killed:
                        res.errors.append("遍历回退时 App 被返回键退出，已重新拉起并继续")
                    time.sleep(max(0.8, interval * 0.7))
                    continue

            # ★ 视觉补位：这一屏「结构树里没有（没点过的）可点元素」时，恰恰是视觉最该
            #   上场的时刻。WebView / Canvas / 自绘界面里，用户看得见的按钮在结构树里
            #   根本不是独立可点节点 —— 真机踩过：富文本 ClickableSpan 超链接
            #   （乐心/赣警办/简小知的《用户隐私政策》）、uni-app 捏脸编辑器的分页条与
            #   色块、卡片流里的半透明遮罩层。以前这里只会盲滑（滑 → 左右滑 → 返回），
            #   实测一轮遍历的预算大半耗在这条分支上，一次真实交互都没多采到。
            #   所以：先问一次模型，并明确告诉它"本屏结构树点不到"，允许它**按坐标**
            #   点击肉眼可见的按钮。危险按钮本地仍拦一道（纵深防御不变）。
            if _ai_gate_ok():
                ai_steps += 1
                ai_used += 1
                t_ai = time.time()
                _vcands = uiwalk.clickable(xml)
                if ledger is not None:
                    _vcands = [n for n in _vcands
                               if not ledger.tap_blocked(_cur_fp, _led_uid(n))]
                v_step = _ai_plan_step(
                    res, ai_tasks, res.device_serial, xml, _vcands,
                    _agent_goal(_ai_ratio()) +
                    "【本屏提示】界面结构树里没有可点击节点（WebView／自绘界面常见），"
                    "若要点击肉眼可见的元素，请在 bbox 里给出坐标。",
                    ai_steps, back_unsafe, log)
                dt_ai = time.time() - t_ai
                if dt_ai >= AI_WAIT_FREE and ai_extra < AI_WAIT_CAP:
                    ai_extra = min(AI_WAIT_CAP, ai_extra + dt_ai)
                    res.ai_wait_seconds += dt_ai
                if v_step is None:
                    ai_fails += 1
                    ai_fails_total += 1
                    ai_fail_fp = _cur_fp
                    log("    [AI] 无节点屏决策失败（本屏连续第 %d 次 / 全程第 %d 次）"
                        % (ai_fails, ai_fails_total))
                    if ai_fails >= 3 and ai_fails_total < AI_FAIL_CAP:
                        # 只停这一屏：模型对自绘界面答不出很常见，
                        # 不该把后面正常页面上的 AI 一并废掉。
                        ai_disabled = True
                        res.ai_errors.append(
                            "AI 在同一个界面上连续 %d 次给不出可用动作，本界面上暂停 AI、"
                            "转规则遍历（换到新界面会自动恢复）" % ai_fails)
                        log("[!] 本屏 AI 连续失败，本屏暂停 AI（换屏恢复）")
                    elif ai_fails_total >= AI_FAIL_CAP:
                        ai_disabled = True
                        res.ai_errors.append(
                            "AI 遍历决策全程累计失败 %d 次（含超时），已停用 AI 并转回"
                            "规则遍历（其余环节不受影响）" % ai_fails_total)
                        log("[!] AI 全程累计失败达上限，停用 AI")
                else:
                    ai_fails = 0
                    vact = str(v_step.get("action") or "")
                    log("    [AI] %.1fs 决策（本屏结构树无节点）：%s（%s）"
                        % (dt_ai, vact, (v_step.get("reason") or "")[:50]))
                    vnode = v_step.get("node")
                    if (vact == "tap" and vnode is not None
                            and not uiwalk.is_dangerous(vnode)
                            and not uiwalk.is_no_use(vnode)
                            and not (crawlsched is not None
                                     and crawlsched.is_soft_commit(vnode))):
                        # 无节点屏的点击是"按坐标"给出来的：先对齐回真实节点
                        # （能对上就拿到正式身份，对不上说明确实是结构树外的
                        #   自绘元素，只能按坐标记账 —— 但坐标同样要进台账，
                        #   否则同一个自绘按钮会被反复点）。
                        _rv = uiwalk.match_real_node(uiwalk.clickable(xml), vnode)
                        if _rv is not None:
                            vnode = _rv
                            _vuid = _led_uid(vnode)
                        else:
                            # 结构树外的自绘元素：`node_uid` 会给所有合成节点同一个
                            # 身份（都用占位 label），按它记账会把整屏的坐标点击
                            # 一起封掉。这类点击只能用**坐标**当身份。
                            _vx, _vy = vnode.center
                            _vuid = "xy:%d,%d" % (_vx, _vy)
                        _vblk = (_led_ok(_cur_fp, vnode) if _rv is not None else
                                 (ledger.tap_blocked(_cur_fp, _vuid) if ledger is not None else ""))
                        if _vblk:
                            if ledger is not None:
                                ledger.note_blocked(_vblk)
                            led_blocks += 1
                            log("    [台账] 跳过坐标点「%s」：%s"
                                % ((vnode.label or "")[:18], _vblk))
                            # 这一屏是"结构树没有可点节点"的自绘界面，模型给的
                            # 坐标点也被点满了，说明这屏真的到头 —— 直接走换屏，
                            # 不在这里靠 continue 反复问模型（那会空转且不计数）。
                            act_run["__total__"] = STUCK_TOTAL_LIMIT
                            time.sleep(max(0.6, interval * 0.6))
                            continue
                        vx, vy = vnode.center
                        seen.add(vnode.key)
                        last_tap_key = vnode.key
                        last_act_sig = "tap"
                        last_act_uid = _vuid
                        if ledger is not None:
                            ledger.note_tap(_cur_fp, _vuid, (vnode.label or "")[:40])
                        if uiwalk.tap(res.device_serial, vx, vy):
                            res.ui_taps += 1
                            _obs_tap(vnode)
                            # 结构树外点击（WebView/Canvas）：多数没有 text，
                            # 所以同时记坐标，回放时前三级匹配全落空才用它。
                            _rec("tap", label=vnode.label, cls=vnode.cls,
                                 uid=getattr(vnode, "resource_id", ""),
                                 at=[vx, vy], bounds=list(vnode.bounds),
                                 coord=True, src="ai_free",
                                 fp=(obs.current if obs is not None else ""))
                            if sched is not None:
                                try:
                                    # 同样要带 uid：AI 点的入口若"点了没换屏"，
                                    # 下一轮别再让它反复选中（见 `_noop_uids`）。
                                    sched.note_tap(tab=False, uid=_led_uid(vnode),
                                                   label=(vnode.label or ""))
                                except Exception:
                                    pass
                            res.ui_steps.append(
                                "%d. 点击「%s」（%s／结构树外坐标）"
                                % (res.ui_taps, vnode.label, vnode.cls.split(".")[-1]))
                            try:
                                live.script.exports_sync.mark_ui_action(vnode.label)
                            except Exception:
                                pass
                            # 与常规路径一致：遍历器也可能点到「同意」类按钮，
                            # 不记录的话之后所有事件都会被算成"同意前"（高危误报）。
                            # 判据交给 `_consent_label_kind`：「确定」这类中性确认
                            # 只记一笔候选，不改分水岭（见该函数的说明）。
                            _kind, _why = _consent_label_kind(vnode.label or "")
                            if _kind:
                                _mark_consent(
                                    res, vnode.label or "", "遍历·AI 无节点屏点击", log,
                                    set_consent=lambda l: live.script.exports_sync.set_consent(True, l),
                                    strength=_kind, why=_why,
                                    screen_label=(res.screens[-1].get("label", "")
                                                  if res.screens else ""))
                            if res.ui_taps % shot_every == 0:
                                observe_screen(res, "UI 遍历第 %d 步" % res.ui_taps,
                                               res.device_serial)
                        time.sleep(interval)
                        continue
                    if vact == "swipe":
                        vd = str(v_step.get("direction") or "up")
                        # 方向语义约定：up = 手指上滑 = 看下面的内容。
                        # ★ 左右必须走 `swipe_side`：引导页/轮播是要**横着**翻的，
                        #   一律当上下滚等于原地打转（真机实测：模型说 left，
                        #   旧代码执行的是 scroll，引导页永远翻不过去）。
                        if vd in ("left", "right"):
                            uiwalk.swipe_side(res.device_serial, vd)
                            _rec("swipe", dir=vd, scroll=False, src="ai_free")
                        else:
                            uiwalk.scroll(res.device_serial, "down" if vd == "up" else "up")
                            _rec("swipe", dir=("down" if vd == "up" else "up"),
                                 scroll=True, src="ai_free")
                        res.ui_steps.append("AI：向%s滑动（无节点屏）" % vd)
                        last_act_sig = "swipe:" + vd
                        time.sleep(interval)
                        continue
                    if vact == "back" and not back_unsafe:
                        _rec("back", src="ai_free")
                        last_act_sig = "back"
                        killed = _do_back("AI 建议返回（无节点屏）")
                        if sched is not None:
                            try:
                                sched.note_back(killed=killed)
                            except Exception:
                                pass
                        res.ui_steps.append("AI：返回上一级")
                        time.sleep(max(0.8, interval * 0.7))
                        continue
            idle += 1
            # 「这一屏没有可点节点」有三种成因，处理方式必须分开：
            #   a) 长页面/列表 → 纵向滚动
            #   b) 引导页 / 轮播 / 卡片流（ViewPager）→ 界面结构里一个 clickable 都没有，
            #      只能左右滑翻页。实测赣警办的首启引导页就是这种，缺了这步会一直"没东西可点"。
            #   c) 想回上一级 → BACK。但**入口界面按 BACK 会直接退出 App**
            #      （实测：App 停在引导页时按 BACK → 退回桌面 → 后续全在桌面上空转，
            #        一个真实事件都采不到，这是"感觉没用到手机"的主因之一）。
            #      所以这里（还没进入内页时）不用 BACK，只滚动与左右滑。
            step = idle % 3
            # 返回键能不能用，判据交给调度器（与 DFS 回退共用同一份）：
            # 栈里只剩入口界面时不按 —— 真机实测那样会把 App 退掉、白重启一次。
            if sched is not None:
                allow_back = sched.can_back(back_unsafe)
            else:
                allow_back = not back_unsafe
            # ★ 2026-11-01 二审补丁：这条分支原来是**熔断的法外之地**。
            #   它执行动作时从不设 `last_act_sig`，而 `_note_act_result` 收到空签名
            #   就直接 return —— 于是"动作连续无效即封禁""本屏榨干强制离开"
            #   "循环观测"三道闸在这里全部失效，一条告警都不会留。
            #   真机实测（冰纷万象 4 档）：在这条分支上「向左滑动」连跑 432 次、
            #   烧掉 67% 的预算，界面数一个没涨，`errors` 里干干净净。
            #   现在与其它分支同一套账：动作照记签名，已被判无效的动作不再执行，
            #   首选被封就退让到还能用的那个，全都封了就当场离开这一屏。
            _plan = (["swipe:down"] if step == 1 else
                     ("swipe:left" if step == 2 else
                      ("back" if allow_back else "swipe:left")))
            _plan = [_plan] if isinstance(_plan, str) else _plan
            _order = list(_plan) + ["swipe:down", "swipe:left"]
            if allow_back:
                _order.append("back")
            _pick = next((a for a in _order if not _act_blocked(a, act_banned)), "")
            if not _pick:
                # 纵向滑、横向滑、返回全被判过无效 —— 这屏确实没有能改变界面的动作了。
                log("[!] 无可点节点界面的滑动与返回均已被判无效，强制离开本屏")
                res.errors.append(
                    "一个无可点节点的界面（自绘/WebView 常见）上，纵向滑动、横向滑动与"
                    "返回键都已连续判为无效，判定该界面无可探索入口并离开")
                act_run.clear()
                act_banned.clear()
                seen.clear()
                if (not back_unsafe
                        and uiwalk.current_focus(res.device_serial).startswith(package)):
                    _do_back("无节点屏滑不动")
                    if sched is not None:
                        try:
                            sched.note_back(killed=False)
                        except Exception:
                            pass
                elif respawn is not None:
                    try:
                        respawn()
                    except Exception:
                        pass
                else:
                    launch_app(res.device_serial, package)
                time.sleep(interval)
                continue
            last_act_sig = _pick
            if _pick == "back":
                _rec("back", src="rule")
                killed = _do_back("入口/引导界面")
                if sched is not None:
                    try:
                        sched.note_back(killed=killed)
                    except Exception:
                        pass
            elif _pick == "swipe:down":
                uiwalk.scroll(res.device_serial, "down")
                _rec("swipe", dir="down", scroll=True, src="rule")
            else:
                uiwalk.swipe_side(res.device_serial, "left")
                _rec("swipe", dir="left", scroll=False, src="rule")
            visited_fps[fp] = visited_fps.get(fp, 0) + 1
            time.sleep(interval)
            continue

        idle = 0

        # ---- ① 由 AI 决定这一步做什么（开启 ui_agent 时）----
        ai_step = None
        # ★ 必须先看 `ui_agent` 功能开关，不能只看「有没有视觉能力」：
        #   `AITasks.plan_ui_action()` 在 ui_agent 关闭时会直接返回 None，
        #   而调用方把 None 一律当"AI 失败"计数 → 三次之后打出
        #   「AI 遍历决策连续失败，停用 AI」并写进 res.ai_errors。
        #   结果是：只开了 policy_vision 的轮次（如 jxz4）日志与报告里
        #   凭空多出一条"AI 失败"，排查时被误导半天。
        _agent_on = False
        if ai_tasks is not None:
            try:
                _agent_on = bool(ai_tasks.cfg.feature("ui_agent"))
            except Exception:
                _agent_on = False
        # 外部接管时，本地模型的"图引导/自由规划"两条路整体让位 ——
        # 否则"我来决策"只是又多加了一次询问，本地模型照样按它的意思点。
        ai_allowed = bool(_agent_on and not ai_disabled and ai_tasks.can_vision()
                          and _oracle is None)
        if ai_allowed and ai_max > 0 and ai_used >= ai_max:
            ai_allowed = False
            if not ai_capped_logged:
                ai_capped_logged = True
                msg = ("UI 遍历的 AI 决策已达设定上限 %d 次，后续改用规则遍历"
                       "（把 ai.ui_agent_max_calls 设为 0 可取消上限）" % ai_max)
                res.ai_notes.append(msg)
                log("[*] " + msg)
        # 节流：只在第 1、1+N、1+2N… 步问模型，中间步骤走规则遍历。
        # 节奏放慢的代价是「AI 少看几屏」，换来的是整轮检测能在可接受时间内跑完。
        if ai_allowed and ai_every > 1 and (loop_i - 1) % ai_every != 0:
            ai_allowed = False
        if ai_allowed:
            # 候选给"所有可点节点"而不是只给"没点过的"：模型可能需要回到
            # 已经点过的入口去完成目标（例如从首页再进另一个设置项）。
            all_cands = uiwalk.clickable(xml)
            # ★ 自由规划的候选要单独过一遍台账。
            #   `kg.options` 的输出会在下面被台账过滤；一旦被滤空，就会退回
            #   自由规划 —— 而自由规划拿到的是**全量**候选，模型会从里面
            #   把同一个已经点废的元素又选回来：白等一次模型、白点一次空，
            #   然后被台账拦下、下一轮再来一遍。真机上这就是"看起来在思考，
            #   其实一步没走"。
            free_cands = all_cands
            if ledger is not None and obs is not None:
                _full = len(all_cands)
                free_cands = [n for n in all_cands
                              if not ledger.tap_blocked(obs.current, _led_uid(n))]
                if len(free_cands) != _full:
                    log("    [台账] 本屏 %d 个入口中 %d 个已达点击上限，只把剩下的交给模型"
                        % (_full, _full - len(free_cands)))
            # 阶段目标按**真实采集时间**推进：把等 AI 的时间扣掉，
            # 否则中继模式下第 2 步就被推到"找注销入口"阶段，节奏全乱。
            elapsed_real = (time.time() - (started_at or res.started_at) - ai_extra)
            ratio = min(1.0, max(0.0, elapsed_real / span))
            _goal = _agent_goal(ratio)
            ai_step = None
            t_ai = 0.0          # 只有真的发起了模型调用才置位（节点级节流会跳过）
            # ---- 先算"这个界面还能做什么"（本地算，零成本）----
            # 放在问模型之前：即使这一屏决定不问模型（见下面的节点级节流），
            # 也可以用图上排序直接推进 —— 图的排序本身就是一份可执行的策略。
            _opts: List[Any] = []
            if kg is not None and obs is not None and obs.current:
                try:
                    _cur_st = obs.states.get(obs.current)
                    _back_ok = (sched.can_back(back_unsafe) if sched is not None
                                else (not back_unsafe))
                    _back_name = ""
                    if _back_ok and sched is not None and len(sched.stack) >= 2:
                        _bn = kg.node_of(sched.stack[-2])
                        _back_name = _bn.title() if _bn is not None else ""
                    # 上一步所在节点：用来掐"两节点来回"。真机 mbsf12 实测，
                    # 节流生效后 44 次动作里 26 次是「查看历史↔返回」死循环。
                    _cn = kg.fp2nid.get(obs.current, "")
                    if _cn and (not visit_nids or visit_nids[-1] != _cn):
                        visit_nids.append(_cn)
                    _avoid = visit_nids[-2] if len(visit_nids) >= 2 else ""
                    # ★ 传 `free_cands` 而不是 `all_cands`（2026-11-03 万步健康）：
                    #   图选项是按 clicks 建 uid→节点表再按节点出的，把已点满的元素
                    #   传进去，它照样能出现在选项里；下面那道"按 uid 过滤"又因为
                    #   uid 与台账键不一致而漏掉（同一个元素在两条路上算出两个身份），
                    #   于是「图上排序」每轮都取到同一个被台账拦下的元素 ——
                    #   真机 275 次拦截、68 分钟、4 个界面就是这么来的。
                    #   从这里就不给它节点，选项自然不会有它。
                    _opts = kg.options(
                        obs.current, free_cands,
                        can_back=_back_ok, back_target=_back_name,
                        scroll_exhausted=bool(getattr(_cur_st, "scroll_exhausted", False)),
                        list_like=bool(getattr(_cur_st, "list_like", False)),
                        phase=(sched.phase if sched is not None else ""),
                        avoid_nid=_avoid)
                except Exception as e:
                    res.ai_errors.append("动作集生成失败（退回自由规划）：%s" % e)
                    _opts = []
            # ---- 台账过滤：本屏已经点够次的元素，不摆到模型面前 ----
            # 这是"AI 与程序化探测协同"的落地点：模型看到的候选表与调度器、
            # 规则用的是**同一份记账**。以前两边各记一套，模型不知道规则点过什么，
            # 真机上表现为它把同一个入口选了 200 多次（川剧迷「檢舉」、冰纷万象
            # 「Layout_area_code」）。
            if ledger is not None and obs is not None and _opts:
                # 过滤时**同时**按 option.uid 与节点的真实身份查账：两者本该相同，
                # 但 `node_uid` 依赖传入的候选顺序，AI 目标对齐前后可能算出不同
                # 的 uid。只查一个就等于给了另一条漏网的路。
                _kept: List[Any] = []
                for o in _opts:
                    if str(getattr(o, "action", "")) != "tap":
                        _kept.append(o)
                        continue
                    _ou = str(getattr(o, "uid", "") or "")
                    _on = getattr(o, "node", None)
                    _blk_o = (ledger.tap_blocked(obs.current, _ou) if _ou else "")
                    _blk_n = (ledger.tap_blocked(obs.current, _led_uid(_on))
                              if (_on is not None and not _blk_o) else "")
                    if not _blk_o and not _blk_n:
                        _kept.append(o)
                if len(_kept) != len(_opts):
                    log("    [台账] 本屏 %d 个动作选项里 %d 个已点满，不摆给模型"
                        % (len(_opts), len(_opts) - len(_kept)))
                _opts = _kept
            # ---- 节点级节流：同一界面只问模型 N 次 ----
            # ★ 真机实测（以观书法 mbsf9，每步都问）：420 秒里模型决策 26 次、
            #   实际点击只有 12 次 —— 光等模型就吃掉 60 多秒，点击量从 45 降到 12。
            #   而"这个界面该点哪个入口"是**节点级决策**：界面没变，答案不会变。
            #   所以问过一次之后，后续同屏动作直接按图上排序取第一项执行，
            #   把省下的时间全部还给点击。模型失败/被拦时允许再问一次。
            _asked = 0
            if obs is not None:
                _asked = int(ai_asked.get(obs.current, 0) or 0)
            _last_act = (ai_last_action.get(obs.current, "")
                         if obs is not None else "")
            if _should_skip_ai(_opts, _asked, ai_per_node, _last_act):
                ai_step = _option_to_step(
                    _opts[0], "图上排序（本界面已问过模型，按图谱优先级执行）")
                ai_step["from_graph"] = True
            else:
                ai_steps += 1
                ai_used += 1
                t_ai = time.time()
                # ---- ① 图引导：把"当前节点的有限动作集"交给模型，只让它选编号 ----
                # 这是本轮改造的关键。改造前是"每步从零规划整条路径"：模型要同时
                # 判断"我在哪 / 做过什么 / 目标在哪 / 先点哪个"，真机上表现为
                # 在同一屏反复点、或者往运营位走。现在"我在哪、还剩什么、目标几步"
                # 全由本地图算好，模型只做局部选择。
                if _opts:
                    ai_step = _ai_choose_step(res, ai_tasks, kg, obs.current, _opts,
                                              _goal, xml, res.device_serial, log)
                    if ai_step is not None:
                        res.ai_guided += 1
                        if obs is not None:
                            ai_asked[obs.current] = _asked + 1
                            ai_last_action[obs.current] = str(ai_step.get("action") or "")
                        # 模型顺带命名的页面，写回图（只在第一次生效）。
                        # 这一步零成本：命名本来就写在同一个 JSON 里。
                        _pg = str(ai_step.get("page") or "").strip()
                        if _pg:
                            try:
                                if kg.note_desc(obs.current, _pg):
                                    res.kg_names[obs.current] = _pg[:40]
                            except Exception:
                                pass
            # ---- ② 自由规划（兜底）：本屏没有可选动作（WebView/自绘界面），
            #      或图引导失败 → 回到"看截图自己决定"，保持原来的能力不丢。
            if ai_step is None:
                ai_step = _ai_plan_step(res, ai_tasks, res.device_serial, xml, free_cands,
                                        _goal, ai_steps, back_unsafe, log)
                if ai_step is not None:
                    res.ai_free += 1
            if ai_step is None:
                ai_fails += 1
                ai_fails_total += 1
                ai_fail_fp = _cur_fp
                if ai_fails >= 3 and ai_fails_total < AI_FAIL_CAP:
                    ai_disabled = True
                    res.ai_errors.append(
                        "AI 在同一个界面上连续 %d 次给不出可用动作，本界面上暂停 AI、"
                        "转规则遍历（换到新界面会自动恢复）" % ai_fails)
                    log("[!] 本屏 AI 连续失败，本屏暂停 AI（换屏恢复）")
                elif ai_fails_total >= AI_FAIL_CAP:
                    ai_disabled = True
                    res.ai_errors.append(
                        "AI 遍历决策全程累计失败 %d 次（含超时），已停用 AI 并转回"
                        "规则遍历（其余环节不受影响）" % ai_fails_total)
                    log("[!] AI 全程累计失败达上限，停用 AI")
            else:
                ai_fails = 0
                dt_ai = (time.time() - t_ai) if t_ai else 0.0
                # 日志必须能分辨"图引导 / 图上排序 / 自由规划"三种来源：它们的
                # 可靠性与成本完全不同，混在一起就分不清"AI 到底在哪一层起作用"。
                if ai_step.get("oid"):
                    _mk = "图引导 " + str(ai_step.get("oid"))
                elif ai_step.get("from_graph"):
                    _mk = "图上排序"
                else:
                    _mk = "自由规划"
                _why = str(ai_step.get("reason") or "")
                if ai_step.get("opt_why"):
                    _why = ("%s｜%s" % (_why, ai_step["opt_why"])) if _why else ai_step["opt_why"]
                log("    [AI] %.1fs %s：%s（%s）"
                    % (dt_ai, _mk, ai_step.get("action"), _why[:60]))
                if str(ai_step.get("action") or "") != "wait":
                    ai_waits = 0        # 有实际动作就把"连续等待"清零
                if dt_ai >= AI_WAIT_FREE and ai_extra < AI_WAIT_CAP:
                    ai_extra = min(AI_WAIT_CAP, ai_extra + dt_ai)
                    res.ai_wait_seconds += dt_ai

        # ---- ①.5 外部接管：这一步由外部（人 / 更强的模型）判断 ----
        # 接管开启时 `ai_allowed` 恒为 False，本地两条 AI 路都不跑，
        # `ai_step` 到这里必定还是 None —— 所以这里是唯一入口，不会重复问。
        if ai_step is None and _oracle is not None:
            _back_ok = (sched.can_back(back_unsafe) if sched is not None
                        else not back_unsafe)
            ai_step = _oracle_step(xml, _back_ok)
            if ai_step is not None:
                oracle_steps += 1
                log("    [接管] %s %s（%s）"
                    % (ai_step.get("action"),
                       (getattr(ai_step.get("node"), "label", "")
                        or ai_step.get("direction") or ""),
                       str(ai_step.get("reason") or "")[:60]))
                ai_step["oracle"] = True

        # ---- ② 执行 AI 的动作。无法执行 / 命中危险目标 → 退回规则策略 ----
        node = None
        if ai_step is not None:
            act = str(ai_step.get("action") or "")
            if act == "done":
                # 模型认为本阶段没得可探索了 —— 清掉"已点击"记录重新走一遍，
                # 而不是就此退出：换个阶段目标后往往还有没去过的地方。
                log("    [AI] 本阶段目标已完成，重置已访问记录后继续")
                seen.clear()
                ai_step = None
            elif act == "wait":
                # ★ 连续"等一等"要设上限。真机实测（以观书法 5.4.2）：点开
                #   《用户协议》后是一个加载不出来的 WebView，结构树为空，
                #   模型每轮都答"等待加载完成"—— 连等 2 分钟、一步没走，
                #   而这段时间是算在采集预算里的。等三次还没动静就交回规则兜底
                #   （滚动 → 左右滑 → 回退），至少能把界面换掉。
                ai_waits += 1
                if ai_waits >= 3:
                    ai_waits = 0
                    log("    [AI] 连续等待无进展，改为回退/滚动")
                    ai_step = None
                else:
                    time.sleep(max(1.0, interval))
                    continue
            elif act == "swipe":
                # 方向语义约定（提示词里已写明）："up" = 手指上滑 = 看下面的内容。
                # 所以 up 要映射到 scroll("down")（内容下移），别搞反。
                d = str(ai_step.get("direction") or "up")
                # ★ 同一屏同一方向连续滑到底还让模型选它，就是空转。
                #   先换反方向；两个方向都无效，说明这屏没有可滚的内容，
                #   直接把本屏空转计数拉满，交给循环顶部的"榨干换屏"处理 ——
                #   比在这里再写一段换屏逻辑可靠（那两处迟早会走偏）。
                if _act_blocked("swipe:" + d, act_banned):
                    _alt = {"up": "down", "down": "up",
                            "left": "right", "right": "left"}.get(d, "up")
                    if _act_blocked("swipe:" + _alt, act_banned):
                        log("    [AI] 本屏双向滑动已连续无效，判定本屏无可滚动内容，准备换屏")
                        act_run["__total__"] = STUCK_TOTAL_LIMIT
                        continue
                    log("    [AI] 向%s 已连续无效，改向%s 滑动" % (d, _alt))
                    d = _alt
                if d == "left":
                    uiwalk.swipe_side(res.device_serial, "left")
                    _rec("swipe", dir="left", scroll=False, src="ai")
                elif d == "right":
                    uiwalk.swipe_side(res.device_serial, "right")
                    _rec("swipe", dir="right", scroll=False, src="ai")
                elif d == "down":
                    uiwalk.scroll(res.device_serial, "up")      # 看上面的内容
                    _rec("swipe", dir="up", scroll=True, src="ai",
                         fp=(obs.current if obs is not None else ""))
                else:
                    uiwalk.scroll(res.device_serial, "down")    # 看下面的内容
                    _rec("swipe", dir="down", scroll=True, src="ai",
                         fp=(obs.current if obs is not None else ""))
                # ★ 纵向滑动也要记进调度器的滚动账：AI 接管遍历时若不记，
                #   "连续滚两次界面没变→已到底→上拉加载下一页"这条链永远不会触发，
                #   列表页的后半截就没人点了。真机实测：一轮 16 次点击、0 次滚动记录，
                #   3 个列表界面一个都没走到第二页。
                if d in ("up", "down") and sched is not None:
                    try:
                        sched.note_scroll(obs.current if obs is not None else "")
                    except Exception:
                        pass
                res.ui_steps.append("AI：向%s滑动" % d)
                last_act_sig = "swipe:" + d
                time.sleep(interval)
                continue
            elif act == "pull":
                # 图引导的选项里有"上拉加载下一页"（列表已到底时）。
                # 必须走 `pull_up` 而不是普通 scroll：普通滑动碰不到加载阈值，
                # 表现就是"滚十几次还是那批内容"，列表后半截永远点不到。
                if _act_blocked("pull", act_banned):
                    log("    [AI] 本屏上拉已连续无效（没有下一页），改走其它路径")
                    ai_step = None
                    act_run["__total__"] = STUCK_TOTAL_LIMIT
                    continue
                if sched is not None:
                    try:
                        sched.note_scroll(obs.current if obs is not None else "",
                                          kind="pull")
                    except Exception:
                        pass
                uiwalk.pull_up(res.device_serial)
                _rec("pull", src="ai",
                     fp=(obs.current if obs is not None else ""))
                res.ui_steps.append("AI：列表已到底，上拉加载下一页")
                last_act_sig = "pull"
                time.sleep(max(1.0, interval))
                continue
            elif act == "back":
                # 是否允许返回，判据与调度器一致（`_can_back`）：
                #   · 已确认 BACK 会退出 App → 只在**根界面**否决；
                #   · 已经在内页 → 允许（否则 DFS 回不去，遍历只能浅一层）。
                #   · 彻底止损（内页也两次把 App 弄没）由调度器 `no_back` 兜住。
                root_blocked = back_unsafe and (sched is None or sched.depth <= 0)
                stopped = sched is not None and sched.no_back
                # ★ 本屏返回已被判无效（连着 3 次没换屏）：这时候再返回，
                #   只会把剩下几十分钟全耗在同一屏。这是 2026-10-31 那批
                #   4 档任务里最贵的空转 —— 看个比赛 297 次「返回上一级」。
                banned = _act_blocked("back", act_banned)
                if root_blocked or stopped or banned:
                    log("    [AI] 建议返回，但当前不允许使用返回键（%s），忽略该动作"
                        % ("已确认会退出 App" if root_blocked else
                           ("已两次退出 App" if stopped else "本屏返回已连续无效")))
                    ai_step = None
                    if banned:
                        # 返回都不能用了，这屏基本到头，交给"榨干换屏"立即处理。
                        act_run["__total__"] = STUCK_TOTAL_LIMIT
                else:
                    _rec("back", src="ai",
                         fp=(obs.current if obs is not None else ""))
                    last_act_sig = "back"
                    killed = _do_back("AI 建议返回")
                    if sched is not None:
                        try:
                            sched.note_back(killed=killed)
                        except Exception:
                            pass
                    res.ui_steps.append("AI：返回上一级")
                    time.sleep(max(0.8, interval * 0.7))
                    continue
            elif act == "tap":
                cand = ai_step.get("node")
                if cand is None:
                    node = None
                elif uiwalk.is_dangerous(cand):
                    # 纵深防御：提示词里已明确禁止点这类按钮，但模型仍可能选到。
                    # 这里做最后一道闸门 —— 点了「退出/注销/拒绝」会让采集崩掉，
                    # 是唯一一类"点错就白跑一趟"的操作，不能只靠模型自觉。
                    res.ai_errors.append(
                        "AI 选中了危险操作「%s」，已拒绝执行并改用规则策略"
                        % (cand.label or "")[:30])
                    log("    [!] AI 想点「%s」，属危险操作，已拦截" % (cand.label or "")[:30])
                    node = None
                elif crawlsched is not None and crawlsched.is_soft_commit(cand):
                    # 「提交类」动作同样要拦：点了就是真的下单/真发短信/真提交实名。
                    # 检测是**观测**不是操作，产生真实业务后果的动作一律不执行。
                    # 规则路径由调度器过滤，AI 路径必须在这里补上同一道闸门。
                    res.ai_errors.append(
                        "AI 选中了提交类动作「%s」，已拒绝执行（只进入页面取证，不提交）"
                        % (cand.label or "")[:30])
                    log("    [!] AI 想点「%s」，属提交类动作，已拦截" % (cand.label or "")[:30])
                    node = None
                elif uiwalk.is_no_use(cand):
                    # 输入框/图形验证码点了没有采集价值：前者弹键盘盖住半屏，
                    # 后者会刷新验证码、打断正在进行的登录。
                    log("    [!] AI 想点「%s」（输入框/验证码），无采集价值，已跳过"
                        % (cand.label or "")[:20])
                    node = None
                else:
                    node = cand
            else:
                node = None

        # ---- ③ 兜底：调度器 → 规则 ----
        # 调度器给的是"本屏还没点过的入口里，按阶段策略最该点的那个"；
        # AI 若能给出合法目标则优先（它可能知道该去哪个入口完成本阶段目标），
        # 规则排序只作为最后一道。三者都不成立时说明这屏确实没得点了。
        if node is None:
            if sched_step is not None and sched_step.action == "tap" and sched_step.node:
                node = sched_step.node
                log("    [调度] 点「%s」（%s）" % ((node.label or "")[:20], sched_step.reason))
            elif nodes:
                node = nodes[0]
        if node is None:
            time.sleep(max(0.6, interval * 0.5))
            continue
        # ★ 把 AI 描述出来的目标对齐回结构树里的**真实节点**。
        #   模型走坐标/文字给目标时，本地包出来的是轻量对象（无 resource-id、
        #   文字可能是占位的"AI 目标"）。直接拿它算 uid，同一个按钮在
        #   「AI 点」和「规则点」两条路上就是两个身份 —— 台账记不到一起，
        #   重复点击也就拦不住。对齐之后两条路共用一份记账。
        _real = uiwalk.match_real_node(clicks_all, node)
        if _real is not None:
            node = _real
        # ---- 台账闸门：这个元素在这屏已经点过够多次了 ----
        # 放在所有"来源"之后、真正下手之前，所以 AI/调度器/规则三条路都过这里。
        _blk = (_led_ok(_cur_fp, node) if ledger is not None else "")
        if _blk:
            if ledger is not None:
                ledger.note_blocked(_blk)
            led_blocks += 1
            log("    [台账] 跳过「%s」：%s（改找本屏其它入口）"
                % ((node.label or "")[:20], _blk))
            seen.add(node.key)
            # 连续被拦 = 这屏已经没有"还没点满"的入口了。攒够 3 次就走
            # "本屏榨干"那条路强制换屏 —— 否则这里会一直转圈且不计数。
            if _cur_fp != led_streak_fp:
                led_streak_fp, led_streak = _cur_fp, 1
            else:
                led_streak += 1
            if led_streak >= 3:
                led_streak = 0
                led_streak_fp = ""
                act_run["__total__"] = STUCK_TOTAL_LIMIT
            elif _blk.startswith("该界面刚判定为循环"):
                # 整屏都别再点了：交给循环/饱和判定处理换屏。
                act_run["__total__"] = STUCK_TOTAL_LIMIT
            continue
        # 纵深防御：不管 node 来自 AI、调度器还是规则表，落地前再过一遍危险检查。
        # 点错一次「不同意」就会让 App 退出并重新弹同一个框，白烧几十秒。
        if uiwalk.is_dangerous(node):
            log("    [!] 选中了危险操作「%s」，跳过" % (node.label or "")[:20])
            seen.add(node.key)
            if sched is not None:
                try:
                    sched.note_tap(tab=False)
                except Exception:
                    pass
            time.sleep(max(0.4, interval * 0.4))
            continue
        # 已经验证过"点了会跳出 App"的入口：不再点。放行一次都只是进系统界面
        # 再退回来，一次新界面都多不到，还会因为 `seen.clear()` 被反复选中。
        _nl = (node.label or "").strip()
        if _nl and _nl in foreign_labels:
            seen.add(node.key)
            continue
        x, y = node.center
        seen.add(node.key)
        last_tap_key = node.key
        last_tap_node = node
        last_tap_at = time.time()
        last_act_sig = "tap"
        sched_tab = bool(sched_step is not None and sched_step.tab
                         and sched_step.node is node)
        # ★ 动第一下手之前，先确认"同意前那一屏"留了证据（金考典 2026-10-27）。
        #   首启观测窗口没等到 App 到前台时，整段 P1 会一张图都没有；
        #   而这一刻屏幕上往往正是那个隐私弹窗 —— 补拍一张，标成首启界面，
        #   报告里 Q002/Q003 才有图可挂。最多试 3 次，不占遍历截图配额之外的份额。
        if (not res.consent_given and not has_phase1_shot(res)
                and p1_shot_tries < 3):
            p1_shot_tries += 1
            observe_screen(res, "首启界面（遍历起始·尚未同意）",
                           res.device_serial, require_app=True)
            if has_phase1_shot(res):
                log("    [+] 同意前界面已补拍（首启观测未取到时的兜底）")
        # ---- ★ 逐次点击留痕（2026-11-05 用户要求）----
        # 每一次点击都要留下：点之前那一屏（在点击位置画好标记）、点的是哪个元素、
        # 这一步是谁选的/凭什么、点下去之前的预判、点完之后界面有没有变。
        #
        # 时机铁律：**必须在 tap 之前**截图。点完之后界面已经换了，拿后面的图
        # 当"点之前的图"，就是把"结果"当"证据"。
        # 失败一律吞掉：一张缩略图存不下来，不能连累这次点击本身。
        _src = "ai" if (ai_step is not None
                        and str(ai_step.get("action")) == "tap") else (
            "sched" if sched_step is not None and sched_step.node is node else "rule")
        _why_src = ""
        if _src == "ai":
            _why_src = str(ai_step.get("reason") or "").strip()
            if ai_step.get("opt_why"):
                _why_src = ("%s｜%s" % (_why_src, ai_step["opt_why"])).strip("｜")
        elif _src == "sched":
            _why_src = str(getattr(sched_step, "reason", "") or "").strip()
        _tu0 = _led_uid(node)
        _taps_before = (ledger.tap_count(_cur_fp, _tu0)
                        if ledger is not None else 0)
        _why_txt = clickev.describe(_src, _why_src, label=(node.label or ""),
                                    taps_before=_taps_before)
        _shot_no = 0
        if len(res.click_shots) < res.max_click_shots:
            try:
                _raw = capture_screenshot(res.device_serial)
                if _raw:
                    _lab = ((node.label or "").strip()
                            or (node.cls or "").split(".")[-1])
                    _ann = clickev.annotate(
                        _raw, x, y, "%d %s" % (res.ui_taps + 1, _lab[:10]))
                    _tb64 = clickev.thumb(_ann)
                    if _tb64:
                        _pred = clickev.predict(node.label, node.cls, uid=_tu0)
                        res.click_shots.append({
                            "i": res.ui_taps + 1,
                            "t": round(time.time() - (started_at or time.time()), 1),
                            "label": _lab[:40],
                            "cls": (node.cls or "").split(".")[-1],
                            "uid": _tu0[:60],
                            "at": [x, y],
                            "bounds": list(node.bounds),
                            "src": _src,
                            "why": _why_txt,
                            "kind": _pred["kind"],
                            "kind_label": _pred["kind_label"],
                            "expect": _pred["expect"],
                            "risk": _pred["risk"],
                            "fp": _cur_fp or "",
                            "result": "",
                            "b64": _tb64,
                        })
                        _shot_no = len(res.click_shots)
            except Exception as _e:
                log("    [.] 点击留痕失败（不影响点击本身）：%s" % _e)
        if uiwalk.tap(res.device_serial, x, y):
            res.ui_taps += 1
            # 这一击的"结果"要等下一屏才判得出来，先挂个待结算编号。
            pending_click = _shot_no
            _obs_tap(node)
            # ---- 台账落账：这一击真的发生了 ----
            # `last_act_uid` 供下一轮的循环观测使用（点击的"元素身份"必须带上，
            # 否则 A 屏点甲和点乙会被当成同一个动作，周期检测就失效了）。
            _tu = _led_uid(node)
            last_act_uid = _tu
            if ledger is not None:
                ledger.note_tap(_cur_fp, _tu, (node.label or "")[:40])
            # 记一条可重放动作。`src` 只用于统计"这段路径是谁选的"，
            # 回放时不看它 —— 复现轮照抄动作，不再重新决策。
            # `why` / `shot` 只为报告服务（重放不看）：报告要把"这一点
            # 凭什么点、点完变成了什么"和那张带标记的图摆在同一行。
            _rec("tap", label=node.label, cls=node.cls,
                 uid=getattr(node, "resource_id", ""),
                 at=[x, y], bounds=list(node.bounds), src=_src,
                 why=_why_txt, shot=_shot_no,
                 fp=(obs.current if obs is not None else ""))
            if sched is not None:
                try:
                    # ★ uid 必须**每次都带上**，不能只在 tab 时带（2026-11-10）：
                    #   调度器靠它结算"点了这个入口界面有没有变"，
                    #   没带上就永远记不成无效入口，标题栏会被反复点。
                    sched.note_tap(tab=sched_tab,
                                   uid=(_tu or (sched_step.uid if sched_step else "")),
                                   label=(node.label or ""))
                except Exception:
                    pass
            step = "%d. 点击「%s」（%s）" % (res.ui_taps, node.label,
                                            node.cls.split(".")[-1])
            res.ui_steps.append(step)
            try:
                live.script.exports_sync.mark_ui_action(node.label)
            except Exception:
                pass

            # ★ 遍历器也要维护"同意状态"。
            # 真机实测（滴滴出行）：首启弹窗里的「同意并开始使用」有时候是**遍历器**点到的
            # （首启探测阶段被政策页下钻用光了时间窗）。如果这里不记录同意，
            # 之后所有事件都会被算成"同意前"，白送一条「征得同意前就开始收集」（高危误报）。
            # 登记一律走 `_mark_consent`：分水岭事件、时刻、截图、脚本同步一次写全。
            _kind, _why = _consent_label_kind(node.label or "")
            if _kind:
                _mark_consent(
                    res, node.label or "", "遍历·调度器点击", log,
                    set_consent=lambda l: live.script.exports_sync.set_consent(True, l),
                    strength=_kind, why=_why,
                    screen_label=(res.screens[-1].get("label", "")
                                  if res.screens else ""))

            log("    [UI] %s" % step)
            if res.ui_taps % shot_every == 0:
                observe_screen(res, "UI 遍历第 %d 步" % res.ui_taps,
                               res.device_serial)
        time.sleep(interval)

    if dumps_failed:
        res.errors.append("UI 遍历期间有 %d 次界面结构导出失败（页面切换/WebView 常见），"
                          "已自动跳过" % dumps_failed)
    hp = uiwalk.dump_health(res.device_serial)
    if hp["kills"]:
        res.errors.append("设备端 uiautomator 进程卡死，程序已自动清理 %d 次（%s）；"
                          "受影响时段的界面证据以截图为准"
                          % (hp["kills"], hp["reason"] or "进程无响应"))
    if hp["degraded"]:
        res.errors.append("采集结束时设备侧界面结构仍不可用，UI 遍历可能未完成既定步数")
    # ---- 页面图观测收尾：结算最后一击，把图与口径摘存进结果 ----
    if obs is not None:
        try:
            _obs_resolve("")          # 最后一击之后没等到下一屏，记为 UNKNOWN
            res.coverage = dict(obs.stats())
            res.graph = obs.to_dict()
            # 图谱存档：补一次 sync（最后一击结算后图可能又多了边/死点），
            # 再整份存进结果。报告用**存档里的图**重渲染，不重算 ——
            # 重算会拿到"存档里的图"和"当前代码"两套口径，同一份存档
            # 隔天重渲染数字就变了，复核员没法核对。
            if kg is not None:
                try:
                    kg.sync(obs)
                    res.kgraph = kg.to_dict()
                    res.kgraph["names"] = dict(res.kg_names)
                    log("[*] " + kg.summary_line())
                    _hint = kg.path_to_target(
                        kg.fp2nid.get(getattr(obs, "current", "") or "", ""))
                    if _hint:
                        log("    [图谱] 最近的可达方向：%s（%s，%d 步）"
                            % (_hint["target"], _hint["node"], _hint["steps"]))
                except Exception as e:
                    log("[!] 知识图谱存档失败（忽略，不影响采集结果）：%s" % e)
            # 覆盖明细：各 tab 子树、死点、未探索入口样例、被拦入口（注销/退出）。
            # 报告「界面覆盖情况」一节直接读它，不在渲染时重算 ——
            # 渲染时重算会拿到"存档里的图"和"当前代码"两套口径，同一份存档
            # 隔一天重渲染就变了数，复核员没法核对。
            try:
                res.coverage["detail"] = obs.coverage_detail()
            except Exception as e:
                log("[!] 覆盖明细统计失败（忽略，不影响采集结果）：%s" % e)
            # 中断原因：报告要能说清"为什么只走到这里"，否则"未覆盖"会被
            # 读成"App 没有这个功能"。
            _why = "时间预算耗尽"
            if res.aborted:
                _why = "任务被中止（%s）" % (res.abort_reason or "外部停止")
            elif stop_reason:
                # 提前收工：要么判定遍历已完结（没有新界面可去），要么反复陷入循环。
                # 这两句必须写进报告 —— 否则"没跑满预算"会被读成"预算不够"，
                # 而真相是"再跑也不会更多"。
                _why = stop_reason
            elif ui_degraded or hp["degraded"]:
                _why = "设备侧界面结构读取失败，遍历提前终止"
            elif relaunches:
                _why = "App 期间退出并重新拉起 %d 次" % relaunches
            elif sched is not None and sched.no_back:
                _why = "返回键两次导致 App 退出后被停用，深层界面无法复查"
            elif dumps_failed >= 5:
                _why = "有 %d 次界面结构导出失败" % dumps_failed
            res.coverage["interrupt"] = _why
            # ---- 台账与循环观测的口径存档 ----
            # 报告「界面覆盖情况」要能回答"为什么这块没测到"：
            # 是因为入口点过两次就不许再点，还是整条路在绕圈被掐断了。
            if ledger is not None or watch is not None:
                try:
                    res.coverage["ledger"] = dict(ledger.stats()) if ledger is not None else {}
                    res.coverage["loop"] = dict(watch.stats()) if watch is not None else {}
                    res.coverage["stop_reason"] = stop_reason
                    res.coverage["ledger"]["blocked_at_exec"] = led_blocks
                except Exception:
                    pass
            # 外部接管的口径：问了几次、答了几次、超时几次。
            # 这几个数直接决定"这轮结论能不能算数"—— 答得少说明外部没跟上，
            # 那些步其实是规则兜底走出来的，和"接管"不是一回事。
            if _oracle is not None:
                try:
                    res.coverage["oracle"] = dict(_oracle.stats(), steps=oracle_steps)
                except Exception:
                    pass
            # 调度口径单独一栏：图上"走到哪"和"为什么这么走"是两回事，
            # 事后核对时要能分开看（例如"未探索 40 个"是因为预算耗尽还是因为
            # BACK 被停用导致退不回来）。
            if sched is not None:
                try:
                    res.coverage["scheduler"] = sched.stats()
                    res.coverage["crawl_mode"] = "graph"
                    res.coverage["targets"] = sched.target_report()
                except Exception:
                    pass
            else:
                res.coverage["crawl_mode"] = "legacy"
            log("[*] " + obs.summary_line())
            if ledger is not None:
                log("[*] " + ledger.summary_line())
            if watch is not None:
                log("[*] " + watch.summary_line())
            if sched is not None:
                log("[*] " + sched.summary_line())
                try:
                    for row in sched.target_report():
                        if row.get("found"):
                            log("    [定向] %s：%s（%s）%s"
                                % (row["name"], row.get("label") or "",
                                   row.get("where") or "",
                                   "｜入口被安全规则拦截，未点击" if row.get("blocked") else ""))
                except Exception:
                    pass
                if sched.no_back:
                    res.errors.append(
                        "遍历期间返回键两次导致 App 退出，已停用返回键；"
                        "部分深层界面的复查未完成（未探索入口数受影响）")
            for row in obs.top_states(5):
                log("    [图] %s ｜ 访问 %d 次 / 深度 %d / 已点 %d / 待点 %d%s%s"
                    % (row["activity"] or row["fp"], row["visits"], row["depth"],
                       row["clicked"], row["todo"],
                       ("｜tab:" + row["tab"]) if row["tab"] else "",
                       "（系统界面）" if row["system"] else ""))
        except Exception as e:
            log("[!] 页面图统计失败（忽略，不影响采集结果）：%s" % e)
    log("[*] UI 遍历结束：点击 %d 次，界面记录 %d 个" % (res.ui_taps, len(res.screens)))
    if jumps or escapes:
        # 两个数要分开报：`jumps` 是"跳出去拿到了证据"，`escapes` 是
        # "跳出去纯属浪费（商店/相册/失焦）"。合成一个数会让"有效跳转 3 次"
        # 与"无效点击 3 次"看起来是同一件事，而它们的处置完全相反。
        log("[*] 外跳：有取证价值 %d 次（已留证并返回），无意义/失焦 %d 次"
            "（已即时返回，未计入覆盖）" % (jumps, escapes))
        res.ui_steps.append("外跳：留证 %d 次，无意义返回 %d 次" % (jumps, escapes))


# ---------------------------------------------------------------- 路径重放（P7 复现）

def _replay_ui(res: ScanResult, cfg, live, deadline: float,
               log: Callable[[str], None],
               steps: Sequence[Dict[str, Any]],
               should_stop: Optional[Callable[[], bool]] = None,
               on_stage: Optional[Callable[[str, int], None]] = None,
               login_phone: str = "",
               get_sms_code: Optional[Callable[[], str]] = None,
               login_timeout: int = 180) -> None:
    """按首轮记录的点击路径逐步重放，不重新决策。

    ★ 和 `_walk_ui` 到底差在哪
      `_walk_ui` 每一步都要**决定点什么**：图引导（问一次模型，本地推理
      2~3 秒）、自由规划、规则调度三层轮着来。复现轮不决策，照抄首轮的动作
      顺序，一个动作一次 adb 调用。首轮 mbsf14 的 32 步在真机上花 399 秒，
      其中约 60 秒是在等模型回答；同一批动作重放约 50 秒。

    ★ 为什么不接 `ai_tasks`
      复现要的是"同样的条件再来一次"。让模型临场重新选一遍，等于换了实验
      条件——两轮走的界面不同，判据没出现时就分不清"问题不再出现"和
      "这轮没走到那屏"。后者会被判成未复现、把 fail 降成 suspect，是假降级。

    ★ 找不到目标时只跳过，不猜
      `flow/replay.py` 的四级匹配（文字+类型 → 文字 → 控件 id → 坐标包含）
      全落空就算这一步重放不了，如实记账。连续 `DRIFT_LIMIT` 步落空说明已经
      不在首轮那条路径上，此时停手 —— 在错误界面上继续点，会产出一批与问题项
      无关的事件，反过来污染判定。

    ★ App 中途退出 → 直接中止，不重启
      重启后界面栈回到首启，与首轮路径对不上，继续按记录点没有意义。
      `res.aborted=True` 让上层知道"这份存档不完整"，复现判定据此改判
      "未能判定"而不是"未复现"。
      但**"前台不是本应用"不等于"应用退出了"**：路径里本来就有跳到别的
      App 的入口（客服/外链/拨号）。这种情况先按返回退回来再继续 ——
      一见不在前台就中止，等于为一个外跳入口丢掉后半条路径（mbsf18
      实测停在 24/51）。判断依据是 `pidof`：进程没了才算真退出。
    """
    package = cfg.scan.package
    serial = res.device_serial
    # 回放间隔比首轮点击间隔短：首轮那 1.2 秒里有一部分是留给"观察加载中界面"
    # 的（模型下一轮要看新截图），回放只看动作结果，0.8 秒足够。
    interval = max(0.3, float(getattr(cfg.scan, "replay_interval", 0.8) or 0.8))
    # 截图在复现轮只用来证明"确实走回了同一批界面"，不需要像首轮那样密。
    # 每张截图要 1~2 秒，密度减半就能多走十几步。
    shot_every = max(8, int(getattr(cfg.scan, "shot_every_taps", 4)))
    total = len(steps)
    done = 0
    stopped = ""                     # 停手的直接原因（登录失败 / 应用退出）
    skipped: List[int] = []          # 这一步找不到目标
    not_replayable: List[int] = []   # 这一步不能执行（危险/提交类）
    # 跳过的步骤写成"第 N 步「入口名」原因"，进存档也进报告。
    # 只记下标不够：复核员要判断"判据会不会正由被跳过的那一步触发"，
    # 必须能看到是哪一步、点的是什么（mbsf19 跳过的两步是「my_vip_open」
    # 与「拍照识字」—— 光看下标完全看不出这两步是否有关系）。
    skip_notes: List[str] = []
    by_kind: Dict[str, int] = {}
    drift = False
    timed_out = False
    miss_streak = 0
    # 权限弹窗取证的跨步状态：`_replay_perm_seen` 防同一弹窗记两次，
    # `_replay_pre_text` 是"上一次点击前那一屏"的文字（弹窗前界面）。
    _replay_perm_seen: set = set()
    _replay_pre_text = ""
    # 屏幕状态检查的节流表（见 `_check_screen`）
    _scr_replay: Dict[str, float] = {}

    log("[复现] 按首轮点击路径重放：共 %d 步（不调用模型，不做新决策）" % total)
    # 记录重放自身的耗时：报告里要能回答"复现一轮到底花了多久"，
    # 这是用户改造成"按路径重放"的核心诉求（对比改造前的整轮重跑）。
    t_begin = time.time()

    def _stop_now() -> str:
        """该不该停。返回原因字符串，空串表示继续。"""
        if should_stop is not None and should_stop():
            return "任务被要求停止"
        if time.time() >= deadline:
            return "到达采集时长上限"
        return ""

    def _ensure_in_app() -> str:
        """确认被测应用还在、且在前台。返回空串表示可以继续，否则返回原因。

        ★ "前台不是本应用" ≠ "应用退出了"
          首轮路径里本来就有会跳到别的 App 的入口 —— mbsf18 第 24 步点
          「去咨询」，客服页在外部打开，前台包名当即变成别的应用。首轮
          遇到这种情况是**按一次返回把它退掉再继续**（`_walk_ui` 里的
          `is_foreign_screen` 分支，退不掉才 launch 回首页）。
          复现轮如果一见"不在前台"就中止，等于为了一个外跳入口丢掉后面
          26 步 —— mbsf18 实测正是这么停在 24/51 的。

        ★ 进程真没了就直接返回原因，不做重启
          重启后界面栈回到首启，与首轮路径对不上，继续按记录点没有意义。
        """
        try:
            if not pids_of(serial, package):
                return "被测应用进程已退出"
            if not uiwalk.is_foreign_screen(serial, package):
                return ""
        except Exception:
            # adb 一时读不到不算"退出"：交给下一步的 dump 去证伪，
            # 这里误判的成本是整条路径作废，比漏判高得多。
            return ""
        for _ in range(2):
            uiwalk.back(serial)
            time.sleep(0.8)
            try:
                if not uiwalk.is_foreign_screen(serial, package):
                    log("    [复现] 前台跑到别的应用（外跳入口），已按返回键回到被测应用")
                    return ""
            except Exception:
                return ""

        # ★ 按两次返回还退不回来就**拉起被测应用**，不要直接中止（2026-10-26）。
        #   实测：首轮点了「备案号:皖ICP备…」（首页页脚的 ICP 号）会打开系统
        #   浏览器，浏览器有"重定向中间页 → 落地页"多层，两次 BACK 只退到上一层。
        #   复现轮于是停在 29/87，而**设备就那样留在浏览器里进了下一个任务** ——
        #   人看到的现象就是"界面上卡着系统浏览器"。
        #   首轮遍历遇到同类情况的兜底本来就是 launch_app（见 `_walk_ui` 的外跳
        #   分支），复现轮只是漏了这一步。补上不是"新行为"，是把两条路径拉齐。
        try:
            launch_app(serial, package)
            time.sleep(2.0)
            if not uiwalk.is_foreign_screen(serial, package):
                log("    [复现] 前台停在别的应用且按返回退不掉，已重新拉起被测应用")
                return ""
        except Exception:
            pass

        fg = ""
        try:
            fg = uiwalk.current_package(serial) or ""
        except Exception:
            pass
        return ("前台停在别的应用上（当前=%s），按两次返回并重新拉起后仍未能回到被测应用"
                % (fg or "未知"))

    def _note_skip(i: int, st: Dict[str, Any], why: str) -> None:
        """跳过一步时留一句人话（步骤号 + 入口名 + 原因）。"""
        lab = (st.get("label") or st.get("uid") or st.get("kind") or "?")
        skip_notes.append("第 %d 步「%s」%s" % (i + 1, str(lab)[:20], why))

    def _stop_on_gone(i: int) -> bool:
        """真回不到被测应用就登记中止原因并返回 True。

        ★ 单独抽出来的原因：这条判据有两个调用点 —— 定期的存活检查，和
          "这一步找不到目标"时的回查。两处各写一遍，迟早在其中一处漏掉
          `res.aborted`（报告就不知道这份存档不完整），或者漏掉 stopped 原因
          （报告只写"重放 24 个"，不写为什么停在 24）。
        """
        nonlocal stopped
        why = _ensure_in_app()
        if not why:
            return False
        res.aborted = True
        res.errors.append(
            "复现重放到第 %d 步时%s，回放中止"
            "（不重启：重启后界面栈与首轮路径对不上）" % (i, why))
        log("[!] 复现重放中止：第 %d 步时%s" % (i, why))
        stopped = "第 %d 步时%s，回放中止" % (i, why)
        return True

    for idx, st in enumerate(steps):
        # 每 10 步报一次"走了多少、每步多少秒"。
        # 没有这行的话，"复现轮只走了 24 步"在日志里看不出是被 adb 拖慢、
        # 被 setTimeout 卡住、还是在等登录 —— 事后只能猜。
        if idx and idx % 10 == 0:
            _el = max(0.0, time.time() - t_begin)
            log("    [复现] 进度 %d/%d 步，已用 %.0fs（约 %.1f 秒/步）"
                % (idx, total, _el, _el / idx))
        why_stop = _stop_now()
        if why_stop:
            timed_out = True
            log("[复现] %s，只重放了 %d/%d 步" % (why_stop, done, total))
            break
        # 黑屏在复现轮同样致命：路径里的坐标是按首轮界面算的，
        # 对着黑屏点等于乱点，会把"没复现"记成"复现失败"。
        _check_screen(serial, log, _scr_replay)
        if on_stage is not None:
            try:
                on_stage("复现重放 %d/%d" % (idx + 1, total),
                         89 + int(2 * (idx + 1) / max(1, total)))
            except Exception:
                pass

        # App 已经不在了：重启会回到首启界面，路径对不上，停了比乱点强。
        #
        # ★ 这个检查**每 4 步做一次**，不是每步。
        #   它由 `dumpsys window` + `pidof` 两条 adb 命令组成，其中 dumpsys
        #   在真机上要 1~5 秒。每步都查，回放会被它拖到约 9 秒/步
        #   （mbsf17 实测：180 秒只走了 12 步）。中间的步骤靠"dump 拿不到界面"
        #   间接发现 —— 真没了的话下一步的 dump 会失败、tap 会落空。
        if idx % 4 == 0 and _stop_on_gone(idx + 1):
            break

        kind = str(st.get("kind") or "")
        by_kind[kind] = by_kind.get(kind, 0) + 1

        if kind == "login":
            # 首轮在这一步登录过，回放必须照做。不登录，后面所有登录后的
            # 界面都到不了 —— 真机实测（mbsf16）：前 8 步全命中，登录点之后
            # 第 10 步起连续落空，整条路径只走了 9/50。
            if not login_phone:
                skipped.append(idx)
                _note_skip(idx, st, "是登录动作，但本轮没有手机号")
                log("    [复现] 第 %d 步是登录动作，但本轮没有手机号，跳过"
                    % (idx + 1))
                continue
            _xml = uiwalk.dump_retry(serial, tries=1, wait=0.3) or ""
            _login_assist(res, _xml, serial, log, login_phone,
                          get_sms_code, login_timeout, should_stop)
            # 成败只看 `res.login["ok"]`：`_login_assist` 的返回值表示
            # "处理过登录页"，不表示"登录成功"（见它的文档与末尾 return）。
            if not res.login.get("ok"):
                # 登录没成，后面每一步都在登录后的界面上，继续点只会全落空。
                stopped = "第 %d 步登录未完成，登录之后的步骤无法重放" % (idx + 1)
                log("[!] 复现重放中止：%s" % stopped)
                break
            done += 1
            res.ui_steps.append("重放：代填测试账号并登录")
            log("    [复现] 第 %d 步：登录完成" % (idx + 1))
            time.sleep(1.0)
            continue

        if kind == "tap":
            xml = uiwalk.dump_retry(serial, tries=2, wait=0.5) or ""
            # ★ 权限弹窗清障。
            #   首轮 `_walk_ui` 每次点击前都有这道（`_capture_perm_dialog`），
            #   复现轮原来漏了。后果是两重的：弹窗一出来就把整屏遮住，
            #   后续步骤连续匹配落空、最后被判成"路径漂移"；弹窗原文也没记，
            #   Q026 在复现轮永远拿不到对照。
            #   只在**真的命中弹窗**时才多 dump 一次，正常路径零额外开销。
            for _pc in range(2):
                if not _capture_perm_dialog(res, xml, serial, log, "P4",
                                            pre_text=_replay_pre_text,
                                            seen=_replay_perm_seen):
                    break
                time.sleep(interval)
                xml = uiwalk.dump_retry(serial, tries=2, wait=0.5) or ""
            nodes = uiwalk.parse_all(xml) if xml else []
            # 记住"这一屏的文字"作为下一屏的"弹窗前界面"。权限弹窗往往在
            # 点击后才弹，下一次 dump 拿到的就是弹窗本身，那时要对照的正是
            # 上一屏（也就是这里存下来的这段文字）。
            _txts = uiwalk.screen_texts(xml)
            if _txts:
                _replay_pre_text = " ".join(_txts)[:600]
            node, how = replaymod.match(nodes, st) if replaymod is not None else (None, "")
            if node is None:
                # ★ 找不到目标先回查前台：很可能这一步把界面带到了别的应用
                #   （外跳入口），在那里匹配必然全落空，接着的几拍会盲点进
                #   别人的界面 —— 那既不可控也解释不了"为什么没复现"。
                #   回查只在这一处加：匹配成功的步不额外花 adb 时间。
                if _stop_on_gone(idx + 1):
                    break
                skipped.append(idx)
                _note_skip(idx, st, "在当前界面找不到")
                miss_streak += 1
                log("    [复现] 第 %d 步找不到「%s」，跳过"
                    % (idx + 1, (st.get("label") or st.get("uid") or "?")[:20]))
                if miss_streak >= (replaymod.DRIFT_LIMIT if replaymod else 3):
                    drift = True
                    log("[!] 连续 %d 步找不到目标，判定路径漂移，停止重放"
                        % miss_streak)
                    break
                continue
            # 纵深防御：首轮没点过危险/提交类动作，但词表可能在本轮之后扩过。
            # 复现是"再看一遍"，绝不能因为回放而真的把账号注销掉。
            if uiwalk.is_dangerous(node) or (
                    crawlsched is not None and crawlsched.is_soft_commit(node)):
                not_replayable.append(idx)
                _note_skip(idx, st, "属危险/提交类，回放不执行")
                log("    [复现] 第 %d 步「%s」属危险/提交类，跳过"
                    % (idx + 1, (getattr(node, "label", "") or "")[:20]))
                continue
            # 输入框 / 图形验证码：点开只会弹键盘盖住半屏、或刷新验证码打断
            # 正在进行的登录。首轮有过滤，回放这一层也要有 —— 漏了这一道，
            # 真机上第 9 步就去点了登录页的手机号输入框（mbsf16 实测）。
            if uiwalk.is_no_use(node):
                not_replayable.append(idx)
                _note_skip(idx, st, "是输入框/验证码，回放不点")
                log("    [复现] 第 %d 步「%s」是输入框/验证码，跳过"
                    % (idx + 1, (getattr(node, "label", "") or "")[:20]))
                continue
            x, y = node.center
            if not uiwalk.tap(serial, x, y):
                skipped.append(idx)
                _note_skip(idx, st, "点击未送达")
                miss_streak += 1
                continue
            miss_streak = 0
            done += 1
            res.ui_taps += 1
            lab = (getattr(node, "label", "") or "")[:20]
            step_txt = "%d. 重放点击「%s」（%s）" % (res.ui_taps, lab, how)
            res.ui_steps.append(step_txt)
            log("    [复现] %s" % step_txt)
            try:
                live.script.exports_sync.mark_ui_action(lab)
            except Exception:
                pass
            # 同意登记必须照做：复现轮也会点到「同意」类按钮，不记的话
            # 之后所有事件都被算成"同意前"，白送一条高危误报。
            _kind, _why = _consent_label_kind(lab)
            if _kind:
                _mark_consent(
                    res, lab, "复现重放", log,
                    set_consent=lambda l: live.script.exports_sync.set_consent(True, l),
                    strength=_kind, why=_why,
                    screen_label=(res.screens[-1].get("label", "")
                                  if res.screens else ""))
            if res.ui_taps % shot_every == 0:
                observe_screen(res, "复现重放第 %d 步" % res.ui_taps, serial)
            time.sleep(interval)
            continue

        if kind == "back":
            uiwalk.back(serial)
            done += 1
            res.ui_steps.append("重放：返回上一级")
            time.sleep(max(0.5, interval))
            continue

        if kind == "swipe":
            d = str(st.get("dir") or "down")
            if bool(st.get("scroll", d in ("up", "down"))):
                uiwalk.scroll(serial, d)
            else:
                uiwalk.swipe_side(serial, d)
            done += 1
            res.ui_steps.append("重放：向%s滑动" % d)
            time.sleep(max(0.4, interval))
            continue

        if kind == "pull":
            uiwalk.pull_up(serial)
            done += 1
            res.ui_steps.append("重放：上拉加载下一页")
            time.sleep(max(0.6, interval))
            continue

        # 未知动作（旧存档里可能有）：记账后跳过，不猜它是什么意思
        not_replayable.append(idx)
        _note_skip(idx, st, "是本版本不认识的动作类型")

    if not stopped and res.aborted and res.errors:
        # App 中途消失也是"没走完"的一种，原因要跟着摘要走，
        # 否则报告只会说"其余步骤未能重放"，看不出是崩溃而非路径变化。
        stopped = "被测应用在第 %d 步后不在前台，回放中止" % (done + 1)
    res.ui_replay = (replaymod.summarize(
        steps, done, skipped, drift=drift, timed_out=timed_out,
        by_kind=by_kind, not_replayable=not_replayable, stopped=stopped,
        skip_notes=skip_notes)
        if replaymod is not None else
        {"total": total, "done": done, "complete": False})
    # 重放自身耗时（秒）。报告拿它回答"复现这个阶段花了多久"，
    # 也是事后判断"是不是又被 adb 拖慢了"的唯一依据。
    _span = max(0.0, time.time() - t_begin)
    res.ui_replay["elapsed"] = round(_span, 1)
    res.ui_replay["sec_per_step"] = round(_span / max(1, done), 2)
    if replaymod is not None:
        log("[复现] 重放结果：%s" % replaymod.describe(res.ui_replay))
        log("[复现] 重放耗时 %.0fs，平均 %.1f 秒/步"
            % (_span, _span / max(1, done)))


# ---------------------------------------------------------------- 多进程注入

def _attach_extra_processes(device, serial: str, package: str, script_src: str,
                            res: ScanResult, sessions: List[Any],
                            attached: set, on_message) -> int:
    """把采集脚本注入到同一 App 的其它进程。

    很多 App（尤其带加固壳、推送、小程序容器、人脸/活体 SDK 的）会把采集行为放在
    子进程里（com.xxx:push、com.xxx:leakcanary…）。只注入主进程会大量漏采。
    """
    n = 0
    for pid in pids_of(serial, package):
        if pid in attached:
            continue
        try:
            ses = _fguard.attach(device, pid)
            scr = _fguard.wrap_script(ses.create_script(script_src))
            scr.on("message", on_message)
            scr.load()
            sessions.append(ses)
            attached.add(pid)
            n += 1
        except Exception as e:
            res.errors.append("注入子进程 pid=%s 失败：%s" % (pid, e))
    if n:
        log("[*] 额外注入 %d 个 App 子进程" % n)
    return n


# ---------------------------------------------------------------- 去向归类

_HOST_RE = re.compile(r"(?:url=|host=)https?://([^/\s:]+)|(?:url=|host=)([^/\s:]+)")


def _summarize_sinks(res: ScanResult) -> None:
    """把 K1（网络上报）事件按域名聚合，产出「数据去向」表。

    这是误报漏斗第 4 级的落地：值有效 + 有去向下落，才够格进报告。
    """
    buckets: Dict[str, Dict[str, Any]] = {}
    for e in res.events:
        if e.sink != "K1" or getattr(e, "noise", ""):
            continue
        m = _HOST_RE.search(e.args or "")
        host = ""
        if m:
            host = (m.group(1) or m.group(2) or "").strip().lower()
        if not host and e.api.startswith("Socket"):
            host = (e.args or "").replace("host=", "").strip()
        if not host:
            host = "(未解析)"
        b = buckets.setdefault(host, {"host": host, "count": 0, "apis": [],
                                      "before_consent": 0, "examples": []})
        b["count"] += 1
        if e.api not in b["apis"]:
            b["apis"].append(e.api)
        if e.before_consent:
            b["before_consent"] += 1
        if len(b["examples"]) < 2:
            b["examples"].append(e.args[:150])
    res.network_sinks = sorted(buckets.values(), key=lambda d: -d["count"])[:40]


# ---------------------------------------------------------------- 误报漏斗第 5 级
#
# 前四级解决的是「这个值是不是真的个人信息」（hook 命中 → 取到有效值 → 有去向下落 → 进报告）。
# 还有一类事件：值是真的、去向也有，但**根本不是这个 App 在收集** —— 是框架/系统自己在跑。
# 简小知 jxz3 真机实测吃到的典型（都曾以"高风险"姿态进了报告）：
#   · `SystemProperties.get("persist.sys.spc.whitepkg")` —— 调用栈顶是
#     `miui.process.ProcessManager.<clinit>` / `android.app.ApplicationImpl.onCreate`，
#     是 MIUI 在 Application 创建时读自己的配置，App 只是被"路过"；
#   · `URL.openStream` → `libcore.io.ClassPathURLStreamHandler` —— 读 APK 自带资源；
#   · `SQLiteDatabase.execSQL("create table …")` —— 建表，没写任何用户数据；
#   · `Environment.getExternalStorageDirectory()` —— 返回 `/storage/emulated/0` 这个**路径字符串**。
# 不排除的话，人工复核就得逐条读文字才能把它们挑出去 —— 等于把筛选成本又还给了人。
# 这里按可机械判定的模式直接标 `noise`：报告与规则层都不再计入，但**保留在存档里**可审计。

_SYS_STACK_PREFIXES = (
    "miui.", "com.android.internal.", "libcore.", "com.android.server.",
    "android.os.SystemProperties", "android.app.ApplicationImpl",
    "android.app.Instrumentation", "dalvik.system", "java.lang.ClassLoader",
)

# SystemProperties.get 里这些 key 属于 ROM/厂商/构建信息，不是用户个人信息。
# ⚠ 必须按 key 精确/前缀匹配：`SystemProperties.get` 语义极宽，是最高频的误报来源。
_SYS_PROP_NOISE_KEYS = (
    "persist.sys.spc.", "ro.build.", "ro.product.", "ro.miui.", "ro.hardware",
    "persist.sys.timezone", "gsm.version", "ro.debuggable", "ro.secure",
)


def _stack_top_is_framework(ev: "PIIEvent") -> str:
    """调用栈**顶部**几帧是否全在框架里 —— 是则说明是框架主动发起，不是 App 业务代码调的。"""
    frames = [str(x).strip() for x in (ev.stack or []) if str(x).strip()]
    if not frames:
        return ""
    top = frames[:3]
    for f in top:
        if not any(f.startswith(p) for p in _SYS_STACK_PREFIXES):
            return ""
    return "调用栈顶部为系统框架（%s），是框架自身在初始化阶段发起" % top[0][:70]


def noise_reason(ev: "PIIEvent", package: str = "") -> str:
    """判定一条事件是否属于「系统/框架自身行为」。返回排除原因，不属于噪声则返回空串。"""
    api = ev.api or ""
    args = ev.args or ""
    out = ev.result or ""

    # ① classpath / jar / file 等本地协议：JDK 内部读 APK 自带资源，永远不联网
    if "ClassPathURL" in out or "classpath:" in out.lower():
        return "读取 APK 自带的 classpath 资源（本地协议，不涉及网络外发）"
    if "URL.open" in api:
        low = (out + " " + args).lower()
        if "http://" not in low and "https://" not in low and (
                "jar:" in low or "file:" in low or "classpath:" in low):
            return "本地协议 URL（jar/file/classpath），不涉及网络外发"

    # ② 只返回公共存储目录的**路径字符串**，不含任何用户个人信息
    if "getExternalStorageDirectory" in api or "getExternalStoragePublicDirectory" in api:
        return "仅返回公共存储目录路径，不含用户个人信息"

    # ③ 建表/索引等 DDL：只改结构，没有写入用户数据
    low = args.strip().lower()
    if "SQLiteDatabase.execSQL" in api and low.startswith(
            ("create table", "create  table", "create index", "create unique index",
             "drop table", "alter table", "create trigger")):
        return "数据库结构语句（DDL），未写入用户个人信息"

    # ④ 系统属性：读的是 ROM/厂商/构建配置，不是用户信息（必须按 key 精确匹配）
    if "SystemProperties.get" in api:
        for k in _SYS_PROP_NOISE_KEYS:
            if k in args:
                return "读取 ROM/厂商系统属性（%s），不含用户个人信息" % k

    # ⑤ 网络 sink / 系统属性：栈顶全在框架里 → 框架自身行为
    if "SystemProperties" in api or api.startswith(("URL.", "Socket", "HttpURLConnection")):
        r = _stack_top_is_framework(ev)
        if r:
            return r
    return ""


def drop_noise_events(res: ScanResult, log: Callable[[str], None] = print) -> int:
    """标记（不删除）系统/框架自身行为的事件。返回排除条数。"""
    n = 0
    for ev in res.events:
        if getattr(ev, "noise", ""):
            continue
        r = noise_reason(ev, res.package)
        if r:
            ev.noise = r
            n += 1
    if n:
        log("[*] 误报漏斗第 5 级：排除 %d 条系统/框架自身行为（不进问题项，存档保留可审计）" % n)
        res.ai_notes.append(
            "已排除 %d 条系统/框架自身行为（如 MIUI 读系统属性、classpath 资源读取、"
            "建表语句、公共存储目录路径），详见存档中事件的 noise 字段。" % n)
    return n


# ---------------------------------------------------------------- 阶段锚点

def mark(res: "ScanResult", name: str, ms: Optional[int] = None) -> None:
    """在采集流程的关键节点打一个时间戳（相对冷启动的毫秒）。

    只记**第一次**打点的值：同意事件可能重复上报、遍历可能重启，
    阶段"开始"的时间是唯一的，被后来的覆盖掉就失去意义了。

    ms 给定时直接用（同意时刻是脚本侧从 App 进程启动算起的，比本地时钟准，
    能拿到就用它，不要退化成"本地估计"）。
    """
    t0 = float(getattr(res, "started_at", 0) or 0)
    try:
        if name in res.marks:
            return
        if ms is not None:
            res.marks[name] = int(ms)
        elif t0 > 0:
            res.marks[name] = int((time.time() - t0) * 1000)
    except Exception:
        pass


# ---------------------------------------------------------------- 主入口

def run_scan(cfg, log: Callable[[str], None] = print, *,
             apk_path: str = "", reset_app: bool = True,
             policy_wait: int = POPUP_WAIT_DEFAULT,
             ai_tasks: Optional[AITasks] = None,
             should_stop: Optional[Callable[[], bool]] = None,
             on_stage: Optional[Callable[[str, int], None]] = None,
             login_phone: str = "",
             get_sms_code: Optional[Callable[[], str]] = None,
             login_timeout: int = 180,
             policy_urls: Optional[Sequence[str]] = None,
             builtin_policy: Optional[Dict[str, Any]] = None,
             replay_path: Optional[Sequence[Dict[str, Any]]] = None) -> ScanResult:
    """真机动态采集。

    should_stop：协作式取消。返回 True 时采集尽快收工，**已采数据全部保留**，
    `res.aborted=True` 标明这份存档不完整。上层据此决定是丢弃还是留档。
    on_stage：阶段进度回调 (阶段名, 百分比)，供任务看板展示真实进度。
    policy_urls：静态分析挑出的政策候选链接。有它就先按 URL 直取全文，
    取不到才回到"在界面上滑着读"的老路 —— 后者是整轮最耗时的一段。
    replay_path：首轮记录的点击路径（`ScanResult.ui_path`）。给了它就走**路径重放**
    而不是重新遍历：首启/政策/同意/登录照旧（清数据后必须重做），进入 UI 阶段后
    照着这条路径逐步执行，不调用模型、不做新决策。P7 复现轮用它，
    见 `flow/replay.py` 文件头。
    """
    def stage(name: str, pct: int) -> None:
        if on_stage is not None:
            try:
                on_stage(name, pct)
            except Exception:
                pass

    res = ScanResult(package=cfg.scan.package)
    # ---- 首启观测窗口：档位值是**下限**（2026-11-08）----
    # ★ 真机教训（小包搜题 / 快搜搜题）：任务表单传了 policy_wait=25，
    #   把档位里写好的 60 秒顶掉了。日志与报告仍写着"极致档：首启观测 60 秒"，
    #   实际只等了 25 秒 —— 这两个 App 是加固壳，50 秒都还没到前台，
    #   于是"首启观测"整段作废，等遍历时才看到同意页，政策一个字节没取到。
    #   两个口径互相矛盾，报告里却看不出来。
    #   现在取 max(传入值, 档位值)：用户想等更久可以，但不能低于该档声明的时间。
    _pw_cfg = int(getattr(cfg.scan, "policy_wait", 0) or 0)
    if _pw_cfg and int(policy_wait or 0) < _pw_cfg:
        if policy_wait:
            log("[*] 首启观测窗口按档位校正：%ds → %ds（档位声明值不低于表单值）"
                % (int(policy_wait), _pw_cfg))
        policy_wait = _pw_cfg
    # 档位与预算落盘：报告要能回答"这一轮到底按几档跑的、给了多少时间"。
    # 不落盘就只能翻启动日志，而平台任务跑完日志往往已经被下一轮顶掉。
    res.depth = str(getattr(cfg.scan, "depth", "") or "")
    res.budget_seconds = int(getattr(cfg.scan, "duration", 0) or 0)
    # ---- 档位对采集口径的两个约束（2026-10-31）----
    # 1) 1 档只测同意前：不点同意，也不进主遍历；
    # 2) 2 档不登录：表单里即使填了手机号也不去点登录页 ——
    #    "游客可见范围"是这一档的口径，登进去之后测到的是另一批界面。
    # 两处都在采集层强制，而不是只靠前端不传值：任务也可能来自 API / 重跑脚本。
    _consent_only = bool(getattr(cfg.scan, "consent_only", False))
    if not bool(getattr(cfg.scan, "login_enabled", True)) and login_phone:
        log("[*] 本档不做登录（当前档位只覆盖游客可见范围），已忽略表单里的测试手机号")
        login_phone = ""
    # 截图上限按本轮配置走（深度模式 60 张，常规 14 张）。写进结果对象，
    # 后面所有截图点都用 res.max_shots，不再读进程级常量。
    res.max_shots = max(1, int(getattr(cfg.scan, "max_shots", MAX_SHOTS) or MAX_SHOTS))
    res.started_at = time.time()
    # 静态分析给的政策候选链接：开局与点开政策页后各试一次（见 fetch_policy_by_url）
    res.policy_urls = [str(u).strip() for u in (policy_urls or []) if str(u or "").strip()]
    mark(res, "scan_start")

    # ---- 开测前先记下本机真实标识（取值比对的唯一标尺）----
    # 放在最前面：这些值必须在 App 还没被装/没被 hook 之前取，且一旦采集开始
    # 就没有第二次机会（清数据、卸载都会改变部分标识）。
    # 取不到不阻断采集 —— 只是报告里要老实说"取值类型按形态推断"。
    #
    # ★ 必须先 resolve_device、再用 device.id 去取（2026-11-10 接入第二台机时暴露）：
    #   这里原先传的是 `res.device_serial`，而它在下面几行才被赋值 —— 一直是空串。
    #   只有一台设备时 `adb shell` 会自动选中它，所以看不出问题；接上第二台，
    #   `adb shell` 直接报 "more than one device/emulator"，capture() 静默返回空，
    #   报告里就退化成"取值类型按形态推断"，而**这条假阴性完全不会报错**。
    try:
        _dev0 = resolve_device(cfg)
        res.device_serial = _dev0.id
        res.device_identities = _DIDS.capture(_dev0.id, log)
    except Exception as e:
        res.errors.append("记录测试机真实标识失败：%s" % e)

    # ---- AI 能力（可选，构造失败自动降级为 None）----
    # 优先用调用方传进来的实例：整条流水线共用一个，调用留痕才能集中到一处。
    # 单独使用本模块（命令行）时没传，就自己构造一个。
    ai_tasks = ai_tasks if ai_tasks is not None else _build_ai(cfg, log)
    if ai_tasks is not None:
        res.ai_enabled = True
        res.ai_vision = ai_tasks.can_vision()

    script_src = (HOOK_SCRIPT.read_text(encoding="utf-8")
                  .replace("__MAX_EVENTS__", str(int(cfg.scan.max_events_per_hook)))
                  .replace("__GLOBAL_CAP__", str(int(getattr(cfg.scan, "global_event_cap", 2000)))))

    device = resolve_device(cfg)
    res.device_serial = device.id
    info = device_info(res.device_serial)
    res.device_model = info.get("model", "")
    res.android_version = info.get("android", "")
    log("[*] 设备：%s（Android %s / SDK %s）"
        % (info.get("model"), info.get("android"), info.get("sdk")))
    # ★ 先确认测试机有没有网（2026-11-09）。政策页、共享清单、第三方 SDK 的
    #   政策页全是在线页面；设备在飞行模式时它们一律显示「网页无法打开」，
    #   而报告差一点把它写成"应用给了死链"。与其等发现异常再回头查，
    #   不如开局就查一句 —— 这一步只花 1 秒。
    try:
        if not device_online(res.device_serial):
            log("[!] 测试机当前没有网络（飞行模式 / 未连接 Wi-Fi 或数据）——"
                "在线政策页会显示「网页无法打开」，相关现象一律按环境原因记录，"
                "不计入应用问题")
            res.errors.append(
                "测试机开始时无网络：在线政策页/共享清单无法加载，"
                "本轮涉网证据不完整；相关现象按环境原因记录，不作为应用问题")
    except Exception as e:
        log("[.] 网络连通性检查失败（忽略）：%s" % e)
    stage("设备就绪", 10)

    # 每个阶段的边界都查一次停止请求：这些点之外的动作（安装、注入）
    # 一旦开始就不该被打断，否则设备会停在"装了一半"的中间态。
    if _stop_requested(should_stop):
        res.aborted = True
        res.abort_reason = "设备就绪后收到停止请求"
        res.ended_at = time.time()
        return res

    # ---- 0. 屏幕与锁屏 ----
    uiwalk.keep_screen_on(res.device_serial)
    uiwalk.wake(res.device_serial)
    time.sleep(0.8)
    if uiwalk.is_locked(res.device_serial):
        log("[*] 检测到锁屏，尝试自动解锁…")
        if not uiwalk.try_unlock(res.device_serial, log=log):
            res.locked_at_start = True
            log("[!] 设备处于锁屏状态 —— UI 自动遍历无法执行。")
            log("[!] 请解锁手机并保持亮屏后重跑，否则采集结果会不完整。")
            res.errors.append("检测开始时设备处于锁屏状态，UI 自动遍历未能执行，"
                              "采集到的行为可能不完整。")

    # ---- 1. 安装 + 清数据 ----
    if apk_path:
        res.install = install_apk(res.device_serial, apk_path, cfg.scan.package, log=log)
        if not res.install.get("ok"):
            res.errors.append("待测应用安装失败，动态采集无法进行：%s"
                              % (res.install.get("raw") or "")[:200])
            res.ended_at = time.time()
            log("[!] 安装失败，跳过动态采集")
            return res
    if reset_app:
        force_stop(res.device_serial, cfg.scan.package)
        time.sleep(0.8)
        if not clear_app_data(res.device_serial, cfg.scan.package, log=log):
            res.errors.append("清除应用数据失败，App 可能不是首启流程，"
                              "隐私弹窗可能不出现。")
        # 清数据不动运行时权限：不收回，上一轮的"允许"会带到这一轮，
        # 权限弹窗不再出现 → Q026 在轮次之间给出不同结论。
        try:
            reset_permissions(res.device_serial, cfg.scan.package, log=log)
        except Exception as e:
            log("[!] 收回运行时权限异常：%s" % e)
    else:
        log("[*] 按配置保留应用数据（不执行首启重置）")
    stage("安装与重置", 25)

    live = _Live()
    hooks_ready = threading.Event()
    extra_sessions: List[Any] = []          # 子进程注入的会话
    attached_pids: set = set()

    try:
        hook_degraded = ""      # 非空 = 本轮放弃注入，只做界面采集
        if cfg.scan.spawn:
            log("[*] 冷启动 %s 并注入" % cfg.scan.package)
            try:
                live.pid = device.spawn([cfg.scan.package], timeout=SPAWN_TIMEOUT)
                # 记下注入会话建立的时刻：紧接着进程就没了的话，要能判断
                # 是不是我们自己注入造成的（见存活检查里的 hook_spawn_killed）。
                res.hook_spawn_at = time.time()
                live.session = _fguard.attach(device, live.pid)
            except Exception as e:
                # ★ 加固包让"暂停 → 注入 → 恢复"这条路走不通：小盒课堂（爱加密）
                #   实测 spawn 干等 30 秒抛 `unexpectedly timed out while waiting
                #   for app to launch`，整轮直接判失败，一张截图、一个字正文都没留。
                #   但"注入不了"≠"应用跑不起来"——界面、政策、权限弹窗照样能采。
                #   所以降级为"仅界面采集"，而不是判死整轮。
                hook_degraded = ("冷启动注入失败（%s），本轮改为不注入、仅界面采集："
                                 "取不到 API 调用证据，依赖运行期事件的行为项只能记「未测」"
                                 % str(e)[:140])
                log("[!] %s" % hook_degraded)
                res.hook_hostile += 1
                res.errors.append(hook_degraded)
        else:
            live.pid = find_running_pid(res.device_serial, cfg.scan.package)
            if live.pid is None:
                raise RuntimeError("进程未在运行：%s（可将 scan.spawn 设为 true）" % cfg.scan.package)
            log("[*] 附着到已运行进程 pid=%d" % live.pid)
            try:
                live.session = _fguard.attach(device, live.pid)
            except Exception as e:
                hook_degraded = ("附着已运行进程失败（%s），本轮改为不注入、仅界面采集"
                                 % str(e)[:120])
                log("[!] %s" % hook_degraded)
                res.hook_hostile += 1
                res.errors.append(hook_degraded)
        if live.pid:
            attached_pids.add(live.pid)
        pid = live.pid
        mark(res, "app_launched")

        if hook_degraded:
            # 进程可能停在 spawn 的挂起态：先收拾干净，否则界面一直停在黑屏/白屏，
            # 后面的"无注入启动探测"会把黑屏误判成"应用起不来"。
            if pid:
                try:
                    device.resume(pid)
                except Exception:
                    pass
            live.script = _NoScript()
            log("[*] 注入不可用：先探测应用自己能否启动，再决定要不要改用附着方式")
        else:
            # ★ 注入会话刚建立就断，也要走"仅界面采集"这条降级路（2026-11-08）。
            #   小包搜题 land37 实测：spawn + attach 都成功，紧接着
            #   `TransportError: the connection is closed`（应用在注入那一瞬间
            #   就被壳弄死了，比"装不上 hook"更早）。原先这里没有 try，
            #   异常直接冒到任务层 → 整单判失败，连一张截图都没留下。
            #   而"注入拿不到事件"与"应用不能测"是两件事，不能混成一个结论。
            try:
                live.script = _fguard.wrap_script(
                    live.session.create_script(script_src))
                live.hooked = True
            except Exception as e:
                hook_degraded = ("注入会话建立后立即失效（%s）：应用在被注入的瞬间"
                                 "退出，本轮改为不注入、仅界面采集" % str(e)[:120])
                log("[!] %s" % hook_degraded)
                res.hook_hostile += 1
                res.hook_spawn_killed += 1
                res.errors.append(hook_degraded)
                live.hooked = False
                live.script = _NoScript()
                if pid:
                    try:
                        device.resume(pid)
                    except Exception:
                        pass
        script = live.script

        def on_message(msg, data):
            if msg.get("type") == "send":
                payload = msg.get("payload") or {}
                kind = payload.get("type")
                if kind == "event":
                    res.events.append(PIIEvent.from_msg(payload))
                elif kind == "hooks":
                    res.hooks_installed = list(payload.get("installed") or [])
                    res.hooks_failed = list(payload.get("failed") or [])
                    hooks_ready.set()
                elif kind == "consent":
                    # ★ 只认第一次（自设捏脸第 4 轮实测）：进程重启后恢复状态若再发
                    # 一次 consent，它的 elapsedMs 是新进程的时钟（几百毫秒），
                    # 会把真实的同意时刻冲掉 → 同意前事件全部落进"同意后"。
                    # 这条通道是"脚本侧亲眼看到 performClick"，属于强证据，
                    # 但强度写作 script（与 UI 侧点击区分，报告里要能看出依据）。
                    _mark_consent(
                        res, str(payload.get("text") or "同意"),
                        "采集脚本侧（performClick 观测）", log,
                        strength="script",
                        elapsed_ms=int(payload.get("elapsedMs") or 0),
                        verified=True,
                        why="脚本 hook 到按钮点击：%s" % (payload.get("via") or ""))
                    res.consent_source = res.consent_source or str(payload.get("via") or "")
                    log("[*] 脚本侧捕获到同意操作（%s）" % payload.get("text"))
                elif kind == "policy":
                    if payload.get("kind") == "url":
                        res.policy_capture.setdefault("urls", []).append(
                            {"url": payload.get("url"), "from": payload.get("from"),
                             "policyLikely": payload.get("policyLikely")})
                    elif payload.get("kind") == "entry":
                        txt = payload.get("text") or ""
                        if txt and txt not in res.policy_capture.setdefault("entryTexts", []):
                            res.policy_capture["entryTexts"].append(txt)
                    elif payload.get("kind") == "text":
                        txt = payload.get("text") or ""
                        # 必须过归属闸门：深挖遍历会打开第三方 SDK 的政策页，
                        # "谁长用谁"会把 App 政策顶掉（见 `_keep_policy_text`）。
                        if txt and _keep_policy_text(res.policy_capture, txt,
                                                     payload.get("url") or ""):
                            if len(txt) >= INLINE_POLICY_MIN:
                                mark(res, "policy_text")
                elif kind == "activity":
                    # ★ 这不是"一屏界面"，是 hook 报上来的一条 Activity 生命周期事件
                    #   （2026-11-10 CNC宝典：33 条"界面"里 29 条是这种，没有结构树、
                    #   没有焦点证据，`activity` 甚至是另一个包名 com.lathe.fanuc）。
                    #   打上 `source=hook` 让 `assess_run_health` 别拿它当界面计数 ——
                    #   否则"有没有拿到应用界面"会被这类空记录撑起来。
                    res.screens.append({"index": len(res.screens), "label": "Activity",
                                        "activity": payload.get("name"), "ts": time.time(),
                                        "via": payload.get("via"), "texts": [],
                                        "source": "hook"})
                elif kind == "sdks":
                    res.sdks_detected = list(payload.get("sdks") or [])
            elif msg.get("type") == "error":
                res.errors.append(str(msg.get("description")))

        # ---- 注入失败的第二级：先看应用能不能自己起来，能起来就改用附着 ----
        # 2026-10-27：spawn 超时（爱加密/小盒课堂）并不等于"注入无望"，但
        # **前提是应用本身能跑**。所以顺序是：不注入启动并观察 → 活着才值得
        # attach；起不来就直接判"应用在本机无法启动"，不再含糊地写"检测手段受限"。
        if hook_degraded:
            _probe = probe_start_without_hook(res.device_serial, cfg.scan.package)
            res.app_start_probe = _probe
            log("[*] 无注入启动探测：%s" % (_probe.get("why") or ""))
            if _probe.get("evidence"):
                _ev = _probe["evidence"].splitlines()
                if _ev:
                    log("[!] 启动失败现场：%s" % _ev[-1][:170])
            if _probe.get("started"):
                try:
                    live.pid = int(_probe["pid"])
                    attached_pids.add(live.pid)
                    live.session = _fguard.attach(device, live.pid)
                    live.script = _fguard.wrap_script(
                        live.session.create_script(script_src))
                    live.hooked = True
                    script = live.script
                    res.attach_after_spawn_fail = "ok"
                    res.errors.append(
                        "冷启动注入失败，已改为「先启动、后附着」注入（pid=%d）—— "
                        "附着发生在应用启动之后，启动阶段的 API 调用未能采集" % live.pid)
                    log("[*] 应用能正常启动，已改用「先启动、后附着」注入（pid=%d）"
                        % live.pid)
                except Exception as e:
                    res.attach_after_spawn_fail = "failed"
                    res.errors.append("改附着已运行进程同样失败：%s" % str(e)[:160])
                    log("[!] 附着同样失败：%s" % str(e)[:140])
                    live.script = _NoScript()
            else:
                res.attach_after_spawn_fail = "skipped"
                res.errors.append("不注入时应用同样无法启动：%s"
                                  % (_probe.get("why") or ""))
                live.script = _NoScript()

        if live.hooked:
            _load_err = ""
            try:
                script.on("message", on_message)
                script.load()
            except Exception as e:
                # 同上：脚本装载期间进程就没了，同样只能降级、不能判死整轮。
                _load_err = str(e)[:120]
                log("[!] 注入脚本装载失败（%s）：应用在装载期间退出，改为不注入、"
                    "仅界面采集" % _load_err)
                res.hook_hostile += 1
                res.hook_spawn_killed += 1
                res.errors.append("注入脚本装载失败（%s）：应用在装载期间退出，"
                                  "本轮改为仅界面采集；行为项只能记「未测」" % _load_err)
                live.hooked = False
                live.script = _NoScript()
                script = live.script

            # 冷启动时必须先 resume，Java 层才会初始化、hook 才会装上
            if live.hooked and cfg.scan.spawn and pid is not None:
                try:
                    device.resume(pid)
                except Exception:
                    pass        # 该 pid 可能已随加固壳自杀而消失，无妨

        # 加固包解壳慢（洋葱学园实测 13 秒才回 hook 回执），12 秒太紧
        if live.hooked and hooks_ready.wait(20):
            log("[*] hook 安装成功 %d 个，失败 %d 个"
                % (len(res.hooks_installed), len(res.hooks_failed)))
            if res.hooks_failed:
                log("    ↳ 失败项（多为未集成该 SDK，属正常）：%s"
                    % "；".join(res.hooks_failed[:4]))
        elif live.hooked:
            res.errors.append("未收到 hook 安装回执（Java 层可能未就绪或脚本加载异常）")
            log("[!] 未收到 hook 安装回执")

        # spawn-and-inject 连续失败次数（见下方的熔断说明）
        _respawn_fail = [0]

        def respawn() -> bool:
            """App 退出后重新冷启动并重新注入 hooks。

            关键：**必须把同意状态带过去**。新进程里脚本的 consent 默认是 False，
            如果不恢复，重启之后的每一次调用都会被标成"同意前"，把 Q002 直接
            变成误报（这是最危险的一类误报，因为它指向"未经同意收集"的结论）。

            ★ 熔断（2026-11-09 聚橙票务 / 爱思投屏）：
              带加固壳的 App 上 `device.spawn()` 会超时（"unexpectedly timed out
              while waiting for app to launch"）—— 这一次尝试就等于把应用按死
              30~60 秒，而失败后调用方还会再来一次。聚橙票务实测连续 26 次失败：
              724 秒预算全花在冷启动上，界面一张没多，截图还落在桌面上。
              所以连续失败 2 次就**永久**改成"只拉起、不注入"，不再尝试 spawn。
            """
            try:
                # 本轮没注入成功（加固壳）：重新 spawn 只会再赔 30 秒再失败一次，
                # 直接用 adb 唤起即可 —— 本来就没有 hook 需要重装。
                if not live.hooked:
                    ok = launch_app(res.device_serial, cfg.scan.package)
                    log("[*] 重新拉起应用（不注入）：%s" % ("成功" if ok else "未确认"))
                    return ok
                old = live.session
                new_pid = device.spawn([cfg.scan.package], timeout=SPAWN_TIMEOUT)
                res.hook_spawn_at = time.time()
                new_ses = _fguard.attach(device, new_pid)
                new_scr = _fguard.wrap_script(new_ses.create_script(script_src))
                new_scr.on("message", on_message)
                new_scr.load()
                device.resume(new_pid)
                live.pid, live.session, live.script = new_pid, new_ses, new_scr
                attached_pids.add(new_pid)
                _respawn_fail[0] = 0
                if res.consent_given:
                    try:
                        # 脚本侧会自己拼 "ui:" 前缀，这里先剥掉，避免出现 "ui:ui:同意并继续"
                        _src = res.consent_source or "respawn"
                        if _src.startswith("ui:"):
                            _src = _src[3:]
                        # 第三个参数 silent=True：这是"状态恢复"，不是一次新的同意动作。
                        # 若让它走正常分支，新进程会按自己的 startTs 报一个几百毫秒的
                        # elapsedMs，把真实同意时刻冲掉（见 hooks/collector.js 的注释）。
                        new_scr.exports_sync.set_consent(True, _src, True)
                        log("    ↳ 已把同意状态带入新进程（避免误报为「同意前收集」）")
                    except Exception:
                        pass
                extra_sessions.append(new_ses)
                try:
                    if old is not None:
                        old.detach()
                except Exception:
                    pass
                _attach_extra_processes(device, res.device_serial, cfg.scan.package,
                                        script_src, res, extra_sessions,
                                        attached_pids, on_message)
                return True
            except Exception as e:
                _respawn_fail[0] += 1
                res.errors.append("重新注入 hook 失败：%s" % e)
                log("[!] 重新注入 hook 失败：%s" % e)
                if _respawn_fail[0] >= 2 and live.hooked:
                    # 连续两次 spawn+注入都没成 —— 不再试。这类壳上每次尝试都要
                    # 30~60 秒，而失败后应用还停在启动前的状态（界面上是桌面），
                    # 既丢预算又丢证据。改成只拉起，界面采集照常。
                    live.hooked = False
                    live.script = _NoScript()
                    try:
                        if live.session is not None:
                            live.session.detach()
                    except Exception:
                        pass
                    live.session = None
                    res.errors.append(
                        "冷启动注入连续 %d 次失败（最后一次：%s）：已停止「重建注入」，"
                        "改为只拉起应用、仅做界面采集。后续行为事件缺失是注入受限所致，"
                        "不代表应用没有这些行为" % (_respawn_fail[0], str(e)[:100]))
                    log("[!] 连续 %d 次重建注入失败，此后只拉起、不再注入" % _respawn_fail[0])
                return False

        def rehook() -> bool:
            """App 仍在运行、但我们的 Frida 会话已失效时，重新附着重注入。

            与 respawn 的区别：respawn 走的是"进程没了 → 冷启动"，这里走的是
            "进程还在 → 直接 attach"。实测滴滴出行的 `com.didi.security.wireless`
            会在首启阶段就让脚本失效而进程不退出，只靠 pidof 判断永远等不到重注入。
            """
            try:
                # 本轮本来就没注入（加固壳拦截）：没有会话可"重附着"，
                # 硬 attach 一次反而可能让加固包发现调试器并自杀。
                if not live.hooked:
                    return False
                pid = find_running_pid(res.device_serial, cfg.scan.package)
                if pid is None:
                    return False
                ses = _fguard.attach(device, pid)
                scr = _fguard.wrap_script(ses.create_script(script_src))
                scr.on("message", on_message)
                scr.load()
                attached_pids.add(pid)
                extra_sessions.append(ses)
                if res.consent_given:
                    try:
                        _src = res.consent_source or "rehook"
                        if _src.startswith("ui:"):
                            _src = _src[3:]
                        scr.exports_sync.set_consent(True, _src, True)
                    except Exception:
                        pass
                old = live.session
                live.pid, live.session, live.script = pid, ses, scr
                try:
                    if old is not None:
                        old.detach()
                except Exception:
                    pass
                # 记下时刻：紧接着 App 就没了的话，说明是加固机制把这次附着
                # 判定成了调试（见存活检查里的 hook_hostile 判定）。
                res.hook_reattach_at = time.time()
                return True
            except Exception as e:
                res.errors.append("重新附着主进程失败：%s" % e)
                return False

        def abandon_inject() -> bool:
            """放弃本轮注入，改成"不注入拉起"，只为把界面与政策先拿到。

            什么时候会走到这里：冷启动注入成功、hook 回执也回来了，
            但应用随即自己消失（pidof 取不到）。这是加固壳把注入判成调试后的
            标准动作。小包搜题 1.9.5（2026-11-08）实测：
              · 注入后进程消失 → 首启观测整段在桌面上空转 66 秒，政策 0 字；
              · 遍历阶段又"重新拉起并注入"4 次，每次都把它再杀一遍，
                整轮点击 2 次、界面 3 个；
              · 而**不注入**时同一台机器上它能跑到 `.ui.AgreementActivity`
                （首启协议页）7 次 —— 政策链接就在那一页。
            所以"注入"在这里的净收益是负的：少了几条事件，丢了整个首启流程。
            把 `live.hooked` 置 False 之后，`respawn()` / `rehook()` 都会自动
            走"只拉起、不注入"的分支，后续阶段不会再反复杀应用。
            """
            try:
                try:
                    if live.session is not None:
                        live.session.detach()
                except Exception:
                    pass
                live.session = None
                live.hooked = False
                live.script = _NoScript()
                res.hook_hostile += 1
                res.hook_spawn_killed += 1
                # 先把系统侧的现场记录抓下来，再拉起 —— 拉起之后缓冲里会混进
                # 大量新日志，越早取越干净。
                _crash = app_crash_evidence(res.device_serial, cfg.scan.package)
                if _crash:
                    res.app_crash_evidence = list(_crash)
                    _c0 = _crash[-1]
                    log("[!] 系统侧崩溃记录：%s" % _c0[:150])
                res.errors.append(
                    "冷启动注入后应用立即退出（加固壳判定为调试并自杀）：已放弃注入，"
                    "改为不注入拉起后继续采集；本轮行为事件缺失是注入受限所致，"
                    "不代表应用没有该行为")
                ok = launch_app(res.device_serial, cfg.scan.package)
                log("[*] 已放弃注入并以不注入方式拉起应用：%s"
                    % ("成功" if ok else "未确认"))
                return ok
            except Exception as e:
                log("[!] 放弃注入失败：%s" % e)
                return False

        # 等界面渲染出来
        time.sleep(2.5)

        # 多进程 App：把脚本也注入到子进程（推送/加固壳/活体 SDK 常在子进程干活）
        try:
            if live.hooked:
                _attach_extra_processes(device, res.device_serial, cfg.scan.package, script_src,
                                        res, extra_sessions, attached_pids, on_message)
        except Exception as e:
            res.errors.append("子进程注入失败：%s" % e)

        total = max(5, int(cfg.scan.duration))
        deadline = time.time() + total

        # ---- 2. 首启弹窗阶段（拿隐私政策 与 同意时刻） ----
        if cfg.scan.ui_walk and not res.locked_at_start:
            # 先清悬浮窗：屏幕录制条之类会压住「同意并继续」，点了等于点到别处
            try:
                killed = uiwalk.dismiss_overlays(res.device_serial, log=log,
                                                    target_pkg=res.package)
                if killed:
                    res.overlays_dismissed = list(set(res.overlays_dismissed + killed))
                    res.errors.append("采集前发现并关闭了遮挡触摸的系统悬浮窗：%s"
                                      % "、".join(killed))
                    time.sleep(0.8)
            except Exception as e:
                log("[!] 悬浮窗检查失败（忽略）：%s" % e)
            log("[*] 首启观测：寻找隐私政策弹窗（最多 %ds）…" % policy_wait)
            mark(res, "observe_start")
            stage("首启观测", 42)
            try:
                _probe_first_launch(res, script, res.device_serial, log,
                                    wait_seconds=min(policy_wait, total),
                                    ai_tasks=ai_tasks,
                                    rehook=rehook,
                                    get_script=lambda: live.script,
                                    should_stop=should_stop,
                                    on_stage=stage,
                                    builtin_policy=builtin_policy,
                                    consent_only=_consent_only,
                                    abandon_inject=abandon_inject,
                                    probe_urls=lambda: probe_webview_urls(
                                        device, res.device_serial, cfg.scan.package, log))
            except Exception as e:
                res.errors.append("首启弹窗捕获异常：%s" % e)
                log("[!] 首启弹窗捕获异常：%s" % e)
        else:
            observe_screen(res, "启动后界面", res.device_serial)

        # 子进程常在启动后才创建，这里再补一次
        try:
            if live.hooked:
                _attach_extra_processes(device, res.device_serial, cfg.scan.package, script_src,
                                        res, extra_sessions, attached_pids, on_message)
        except Exception:
            pass

        # ---- 3. 主遍历 ----
        # ★ 把前面等 AI 的时间还给采集预算。首启阶段为了让模型看首启截图、
        # 判断页面性质，可能等了好几轮；那段时间设备只是停在原地等，
        # 不该从"采集时间"里扣 —— 否则遍历一开头就只剩几秒。
        if res.ai_wait_seconds > 0.5:
            deadline += res.ai_wait_seconds
            log("[*] 首启阶段等待 AI 累计 %.0f 秒，已从采集预算中补回"
                % res.ai_wait_seconds)
        # ★ 复现轮的时长口径：`repro_duration` 是**重放阶段**的预算，不含首启。
        #   真机实测（mbsf15）：复现轮没带政策链接，首启阶段为了找政策入口
        #   点了 13 个采样点、花了 203 秒，把 120 秒预算吃光 → 一步都没重放，
        #   而报告仍写着"按首轮路径重放"。这里按路径长度保底给足时间，
        #   上限 1.5 倍总时长（防异常卡死），并在日志里写明放宽了多少。
        _path = [s for s in (replay_path or []) if isinstance(s, dict)]
        if _path:
            # 每步按 3 秒估：一次 dump（约 1s）+ 动作 + 界面稳定等待。
            # 实测（mbsf17）原来每步约 9 秒，其中大头是"每步都查一次前台包名
            # + 进程号"；那两处已改成每 4 步一次，这里按优化后的量级估。
            _n_login = sum(1 for s in _path if s.get("kind") == "login")
            _wait = min(int(login_timeout or 180), 120) * _n_login
            _need = len(_path) * 3.0 + 20 + _wait
            _cap = max(_need, total * 3.0)
            _want = time.time() + min(_need, _cap)
            if deadline < _want:
                deadline = _want
                log("[*] 复现轮：首启阶段已用掉采集预算，为重放 %d 步把时限放宽 %d 秒%s"
                    % (len(_path), int(min(_need, _cap)),
                       ("（含 %d 处登录等待）" % _n_login) if _n_login else ""))
        _probe_dead = (res.app_start_probe or {}).get("started") is False
        if _probe_dead:
            # ★ 应用在本机起不来时，遍历只能空转：小盒课堂 2026-10-27 实测
            #   白跑 113 秒、点击 0 次、界面记录 0 个，纯粹烧预算。
            #   停在这里，已拍的截图足够说明"屏幕上看不到它的界面"。
            log("[!] 无注入启动探测已确认应用无法运行，跳过 UI 遍历"
                "（界面证据以已采截图为准）")
            res.errors.append("应用无法稳定启动，跳过 UI 遍历：%s"
                              % ((res.app_start_probe or {}).get("why") or ""))
        elif _consent_only:
            # 1 档：口径是"同意之前"。这一档不能走主遍历（主遍历会在着陆阶段
            # 点同意），但**必须动起来** —— 静置在弹窗上，整改后的 App
            # 一个标识符都不读，于是"同意前收集"永远判不出来。
            # 探索的点击闸门在 `_explore_pre_consent` 里，只放行非同意元素。
            if res.locked_at_start:
                res.errors.append("设备锁屏，1 档未同意探索未能执行")
            elif time.time() >= deadline:
                res.errors.append("采集预算已用尽，1 档未同意探索未能执行")
            else:
                log("[*] 1 档（仅同意前）：进入未同意状态探索（不点同意）")
                stage("未同意探索", 55)
                try:
                    _explore_pre_consent(
                        res, cfg, live, deadline, log,
                        respawn=respawn, should_stop=should_stop,
                        on_stage=stage)
                except Exception as e:
                    res.errors.append("1 档未同意探索异常：%s" % e)
                    log("[!] 1 档未同意探索异常：%s" % e)
                stage("未同意探索完成", 88)
        elif cfg.scan.ui_walk and not res.locked_at_start and time.time() < deadline:
            remain = int(max(1, deadline - time.time()))
            if _path:
                # 复现轮：照首轮路径重放。不做图观测、不调模型 ——
                # 复现要的是"同样的条件再来一次"，不是"再探一遍"。
                mark(res, "replay_start")
                stage("复现重放", 55)
                log("[*] 开始按首轮路径重放，剩余 %ds，共 %d 步"
                    % (remain, len(_path)))
                _replay_ui(res, cfg, live, deadline, log, _path,
                           should_stop=should_stop, on_stage=stage,
                           login_phone=login_phone, get_sms_code=get_sms_code,
                           login_timeout=login_timeout)
                stage("复现重放完成", 88)
            else:
                # ★ 先着陆，再遍历（2026-11-06）。
                #   同意之后的界面不是功能界面：开屏广告、年龄门、引导页、
                #   促销弹窗、兴趣选择页都在这一层。拿通用遍历去闯，代价不是
                #   "多花几步"，而是整份报告作废（外跳 / 写画像 / 换掉被测版本）。
                mark(res, "landing_start")
                _land = _landing(res, cfg, live, deadline, log,
                                 ai_tasks=ai_tasks, respawn=respawn,
                                 should_stop=should_stop, on_stage=stage,
                                 login_phone=login_phone,
                                 get_sms_code=get_sms_code,
                                 login_timeout=login_timeout,
                                 get_script=lambda: live.script)
                mark(res, "landing_end")
                # 着陆用掉的时间要在这里扣掉，remain 不能沿用旧值 ——
                # 否则日志与看板会显示"剩余 300s"而实际只剩 240s。
                remain = int(max(1, deadline - time.time()))
                if not _land.get("reached_home") and time.time() >= deadline:
                    log("[!] 着陆已用尽本轮预算，跳过功能遍历")
                    res.errors.append(
                        "首启着陆用尽全部预算（%s），未进入功能遍历；"
                        "本轮界面证据仅覆盖首启流程"
                        % (_land.get("why") or "原因未记录"))
                else:
                    log("[*] 开始 UI 自动遍历，剩余 %ds …" % remain)
                    mark(res, "walk_start")
                    # 冻结"遍历之前"累计的模型等待（见 ai_wait_pre_walk 的说明）
                    res.ai_wait_pre_walk = float(res.ai_wait_seconds or 0.0)
                    stage("界面遍历", 55)
                    _walk_ui(res, cfg, live, deadline, log, respawn=respawn, rehook=rehook,
                             ai_tasks=ai_tasks, started_at=res.started_at,
                             should_stop=should_stop,
                             login_phone=login_phone, get_sms_code=get_sms_code,
                             login_timeout=login_timeout, on_stage=stage)
                    stage("界面遍历完成", 88)
        else:
            # 静置观察同样要报进度：否则看板停在一格不动，看门狗照样会误报
            _idle_t0 = time.time()
            _idle_span = max(1.0, deadline - _idle_t0)
            _idle_posted = 0.0
            while time.time() < deadline:
                if time.time() - _idle_posted > 10:
                    _idle_posted = time.time()
                    stage("静置观察", 55 + int(min(1.0, (time.time() - _idle_t0)
                                                  / _idle_span) * 33))
                if _sleep_cancellable(0.5, should_stop):
                    res.aborted = True
                    res.abort_reason = "静置观察阶段被中断"
                    log("[*] 收到停止请求，结束静置观察")
                    break

        # ---- 4. 收尾 ----
        stage("采集收尾", 90)
        # ★ 被取消时跳过「出具报告用的收尾取证」。
        #   结束界面截图、WebView 正文回读、summary、政策再取一遍，都要走
        #   adb/frida 往返；App 已被打断的状态下实测要多花 20~30 秒。
        #   取消的语义是"现在停"，不是"再做三十秒收尾"—— 这一轮数据本来就不
        #   完整、不会出报告，多这几张图也进不了结论，只让人觉得按钮没反应。
        #   注意：**下面的噪声过滤、去向聚合、同意时刻自愈仍要执行**，
        #   它们不碰设备，且是存档可用性的前提。
        if res.aborted:
            log("[*] 本轮为中断收尾：跳过结束界面截图与政策回读")
        elif cfg.scan.capture_screenshot:
            observe_screen(res, "采集结束界面", res.device_serial)

        if not res.aborted:
            # 再取一次 WebView 正文（有些 App 是在主界面上打开政策）
            try:
                live.script.exports_sync.read_web_views()
            except Exception:
                pass
            try:
                res.summary = live.script.exports_sync.summary() or {}
                # ---- 单信号限流的如实交代（2026-11-05）----
                # 注入脚本会给每个信号设上限（1/3 总额度），防止一个高频轮询接口
                # 把额度吃光。这件事必须写进报告，否则"某接口只出现 40 次"
                # 会被读成"该接口只调了 40 次"——那就成了假数据。
                _sk = (res.summary or {}).get("signalSkipped") or {}
                if isinstance(_sk, dict) and _sk:
                    _tot = sum(int(v or 0) for v in _sk.values())
                    _top = sorted(_sk.items(), key=lambda kv: -int(kv[1] or 0))[:3]
                    res.errors.append(
                        "事件上报做了单信号限流：共 %d 条同类调用未逐条上报（%s）。"
                        "这些调用确实发生过（完整次数见各接口调用计数），"
                        "限流是为避免单个高频轮询接口耗尽事件总额度、"
                        "让后面真正有价值的采集被整批丢弃" % (
                            _tot, "、".join("%s×%d" % (k, int(v or 0)) for k, v in _top)))
            except Exception as e:
                res.errors.append("获取统计信息失败：%s" % e)
            try:
                pol = live.script.exports_sync.get_policy() or {}
                for u in (pol.get("urls") or []):
                    if u.get("url") and u["url"] not in [d.get("url")
                                                         for d in res.policy_capture.get("urls", [])]:
                        res.policy_capture.setdefault("urls", []).append(u)
                texts = pol.get("texts") or {}
                for _u, t in texts.items():
                    _keep_policy_text(res.policy_capture, t, _u or "")
                    if int(pol.get("webviewCount") or 0):
                        res.policy_capture["webviewCount"] = int(pol["webviewCount"])
            except Exception:
                pass

        # ---- AI 参与情况汇总（供报告展示与人工复核）----
        if ai_tasks is not None:
            try:
                res.ai_notes = list(ai_tasks.notes)
                res.ai_stats = dict(ai_tasks.ai.call_stats())
                res.ai_stats["provider"] = ai_tasks.ai.describe()
                res.ai_stats["provider_name"] = getattr(ai_tasks.ai, "name", "")
                res.ai_stats["model"] = cfg.ai.model
                res.ai_stats["vision_model"] = (getattr(cfg.ai, "vision_model", "")
                                                or cfg.ai.model)
                res.ai_stats["vision_enabled"] = res.ai_vision
                res.ai_stats["ui_throttle"] = {
                    "every": int(getattr(cfg.ai, "ui_agent_every", 1) or 1),
                    "max_calls": int(getattr(cfg.ai, "ui_agent_max_calls", 0) or 0),
                }
                # 等模型花了多少时间（已从采集预算中扣除，不计入"采集时长"）
                res.ai_stats["wait_seconds"] = round(res.ai_wait_seconds, 1)
                # 中继模式：把会话目录写进结果，人工可回看当时模型看到的每一张图
                relay_stats = None
                if hasattr(ai_tasks.ai, "stats"):
                    try:
                        relay_stats = ai_tasks.ai.stats()
                    except Exception:
                        relay_stats = None
                if relay_stats:
                    res.ai_stats["relay"] = relay_stats
                    res.ai_stats["relay_dir"] = relay_stats.get("dir", "")
                if res.ai_errors:
                    res.ai_stats["errors"] = len(res.ai_errors)
            except Exception:
                pass

    finally:
        for ses in extra_sessions:
            try:
                ses.detach()
            except Exception:
                pass
        try:
            if live.session is not None:
                live.session.detach()
        except Exception:
            pass
        if cfg.scan.spawn and live.pid is not None:
            try:
                device.kill(live.pid)
            except Exception:
                pass

    # ---- 旁路取证：注入被拦时从系统侧补证据（2026-10-31）----
    # ★ 判据取"注入受限"的三种表现：壳杀注入（hook_hostile）、壳连冷启动都杀
    #   （hook_spawn_killed）、一个 hook 都没装上。单看 events 少不够 ——
    #   有些 App 本来就不读个人信息，事件少是正常的。
    if res.hook_hostile or res.hook_spawn_killed or not res.hooks_installed:
        try:
            log("[*] 注入受限，改从系统侧旁路取证（appops / 运行时权限）…")
            res.bypass = _bypass.collect(res.device_serial, res.package, log)
            if res.bypass.get("ok"):
                _ops = res.bypass.get("appops") or []
                _detail = ("（%s）" % "、".join(o["label"] for o in _ops[:6])) if _ops else ""
                res.errors.append(
                    "本轮注入受限，敏感操作记录改由系统侧旁路取证：appops 记录到 %d 项近期"
                    "操作%s。旁证只能证明「用过」，不能替代调用栈，相关行为项按「待人工"
                    "确认」处理。" % (len(_ops), _detail))
            else:
                res.errors.append("注入受限，系统侧旁路取证也未取得数据：%s"
                                  % (res.bypass.get("why") or "原因未知"))
        except Exception as e:
            res.errors.append("旁路取证异常：%s" % e)

    # 先剔噪声再聚合去向：否则"数据去向"表里会混进 classpath/许可服务这类噪声域名
    drop_noise_events(res, log)
    _summarize_sinks(res)

    # ---- 目标应用是否压根没能启动 → 取证存档 ----
    # 触发条件刻意保守：**重启过进程 + 几乎没采到事件 + 没捕获到同意**三条同时成立。
    # 正常 App 偶发一次重启（内存回收等）不会被误判成"启动失败"，
    # 而"起来 0 秒就死、反复重启"这种情形一定会被抓住。
    try:
        if (res.relaunch_count or 0) >= 1 and not res.consent_given and len(res.events) < 10:
            from . import crashinfo
            log("[*] 目标应用疑似未能正常启动，开始取崩溃证据…")
            res.app_crash = crashinfo.collect(res.device_serial, res.package,
                                              since_ts=res.started_at, log=log)
            # ★ 再补一步：**不注入**时它到底能不能跑起来（2026-11-10 健康深圳）。
            #   用户会问"这是不是加固壳导致的"—— 只有做过这个对照实验才答得出来：
            #     · 不注入能稳定显示 → 是**我们的注入**把它弄死了（检测侧的责任），
            #       报告不能写成应用缺陷，应写"检测手段受限"并给出复现命令；
            #     · 不注入也起不来   → 是**应用自己**在本机跑不起来（或加固壳
            #       检测到 root/调试环境后自杀），这属于客观事实，写进报告头。
            #   没有这一步，报告只能含糊地说"未能取得界面"，等于把两种完全
            #   不同的责任混在一起。
            if not (res.app_start_probe or {}).get("why"):
                try:
                    _p = probe_start_without_hook(res.device_serial, res.package)
                    res.app_start_probe = _p
                    log("[*] 无注入启动探测：%s" % (_p.get("why") or "未取得结论"))
                    if _p.get("evidence"):
                        _evl = str(_p["evidence"]).splitlines()
                        if _evl:
                            log("[!] 启动失败现场：%s" % _evl[-1][:170])
                except Exception as e:
                    log("[!] 无注入启动探测失败：%s" % e)
    except Exception as e:
        res.errors.append("崩溃取证失败：%s" % e)

    mark(res, "scan_end")
    res.ended_at = time.time()

    # 从 summary 回填同意信息
    if res.summary:
        if res.summary.get("consent"):
            res.consent_given = True
        # 脚本侧的耗时是"从 App 进程启动算起"，比我们本地时钟估的更准，能拿到就覆盖。
        # 但必须**两个时间戳都在**且差值合理：early 版本少了这个校验，
        # 脚本没给 startTs 时算出来是 epoch 毫秒，报告写成"冷启动后 1792074259.6 秒同意"。
        _ca = res.summary.get("consentAt")
        _st = res.summary.get("startTs")
        # ★ summary 可能来自**重启后的另一个进程**（自设捏脸第 4 轮实测：
        #   事件时间轴的进程起点在冷启动后 9.2s，而 summary 的 startTs 是
        #   重启后那个进程、相差 612s）。拿它的 startTs 去算同意时刻，
        #   等于拿一把别的尺子量同一段时间。进程对不上就宁可不用。
        #
        # ★★ 但"哪个进程"要取**最新的那个**（ts - elapsed_ms 的最大值），
        #    不能取最小值。真机实测（以观书法 mbsf7）：App 中途重启过一次，
        #    事件里既留有旧进程的（起点 A），也有新进程的（起点 A+7.3s），
        #    summary 是在收尾时向**当前**脚本要的，当然属于新进程。
        #    早先取最小值 → 拿旧进程起点去比对 → 明明对得上却被判"来自别的进程"，
        #    脚本给出的精确同意时刻被丢弃，退回本地时钟估算值（相差 6.5s）。
        #    这直接削弱「同意前 / 同意后」的边界精度 —— 边界正是本报告唯一的时序锚。
        _p0 = None
        for _e in res.events:
            _t = getattr(_e, "ts", None)
            _el = getattr(_e, "elapsed_ms", None)
            if _t and isinstance(_el, (int, float)):
                _v = int(_t) - int(_el)
                if _p0 is None or _v > _p0:
                    _p0 = _v
        if _ca and _st:
            try:
                _d = int(_ca) - int(_st)
                _same_proc = (_p0 is None or abs(int(_st) - _p0) <= 3000)
                if 0 <= _d <= 30 * 60 * 1000 and _same_proc:
                    res.consent_elapsed_ms = _d
                elif 0 <= _d <= 30 * 60 * 1000:
                    res.errors.append(
                        "脚本 summary 来自重启后的进程（起点相差 %.1fs），"
                        "其同意时刻不予采用" % (abs(int(_st) - (_p0 or int(_st))) / 1000.0))
            except Exception:
                pass
        if res.summary.get("consentSource") and not res.consent_source:
            res.consent_source = res.summary["consentSource"]
    # 同意时刻若与事件序列矛盾（存在晚于它的同意前事件），按事件序列重建
    try:
        from .flow import compare as _CMP
        _fixed, _note = _CMP.heal_consent_ms(res.events, res.consent_elapsed_ms)
        if _note:
            res.consent_elapsed_ms = _fixed
            res.errors.append(_note)
            log("[!] %s" % _note)
    except Exception:
        pass
    # 同意时刻是划分「同意前 / 同意后」的唯一边界，用脚本侧给的精确值
    if res.consent_given and res.consent_elapsed_ms is not None:
        mark(res, "consent", int(res.consent_elapsed_ms))
    # ★ 分水岭标记事件的时刻跟着最终值走。
    #   登记那一刻用的是本地时钟（相对采集开始），收尾可能被脚本侧更精确的
    #   「相对 App 进程启动」的值覆盖；两个时刻不统一的话，事件流里的标记
    #   会落在与其他事件不同的时基上，时间线上看着像"同意发生在另一个位置"。
    for _e in res.events:
        if getattr(_e, "signal", "") == "CONSENT":
            _e.elapsed_ms = int(res.consent_elapsed_ms or 0)
            if getattr(res, "started_at", 0):
                _e.ts = int(float(res.started_at) * 1000) + int(
                    res.consent_elapsed_ms or 0)
    # 拿不到可靠耗时就留 None —— 报告会写"耗时未记录"。
    # 早先这里硬填 0，报告会显示"冷启动后 0.0 秒同意"，比不写更容易误导。

    # ---- 收尾：同意了就必须在事件流里留下分水岭 ----
    # 放在时刻修正之后：分水岭事件要带上修正过的 elapsed_ms，
    # 否则它会落在时间轴上错误的位置，比没有更糟。
    try:
        _ensure_consent_marker(res, log)
    except Exception as e:
        res.errors.append("同意分水岭事件补齐失败：%s" % e)

    log("[*] 采集结束：事件 %d 条（同意前 %d 条），UI 点击 %d 次，"
        "截图 %d 张，界面 %d 个，外发域名 %d 个"
        % (len(res.events), len(res.before_consent_events), res.ui_taps,
           len(res.screenshots), len(res.screens), len(res.network_sinks)))
    return res
