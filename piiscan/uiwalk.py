"""UI 自动遍历与界面解析。

用途：替代人工点击，触发 App 内部的敏感行为；同时承担「首启弹窗识别」，
因为合规检测最关键的两个入口（隐私政策链接、同意按钮）都在首个弹窗里。

做法：uiautomator dump 界面 -> 解析节点 -> 按策略点击/滑动 -> 循环。

注意：部分定制系统（如 MIUI）会限制 adb shell 注入输入事件
（SecurityException: Injecting to another application requires INJECT_EVENTS permission）。
因此这里默认通过 `su -c` 以 root 身份注入，绕过该限制。

已知坑：`uiautomator dump` 在 WebView / 部分自绘页面上会返回空或极简结构，
所以调用方必须容忍 dump 失败并降级（保留截图作为兜底证据）。
"""
from __future__ import annotations

import hashlib
import itertools
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

_BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")

# 优先点击的按钮文字（按合规检测场景排序）
PRIORITY_KEYWORDS = ("同意", "允许", "确定", "我知道了", "同意并继续", "好的",
                     "下一步", "继续", "进入", "开始", "跳过", "以后再说")

# 「同意」类关键词（与采集脚本共用一套语义）
CONSENT_KEYWORDS = ("同意并继续", "同意并接受", "同意并登录", "同意", "接受", "允许",
                    "我知道了", "知道了", "好的", "确定")

# 隐私政策入口的关键词（覆盖常见命名）
# 命名极度不统一 —— 实测见过：「隐私政策」「个人信息保护指引」「用户隐私政策」，
# 也有按 PIPL 正文措辞叫「个人信息处理规则」的（如滴滴出行首启弹窗里
# 「服务协议及个人信息处理规则」）。关键词库必须跟着法规措辞一起长。
POLICY_KEYWORDS = ("个人信息保护政策", "隐私政策", "隐私权政策", "隐私权声明",
                   "个人信息保护指引", "隐私保护政策", "用户隐私政策",
                   "隐私协议", "个人信息保护规则", "隐私条款", "用户协议和隐私政策",
                   "个人信息处理规则", "个人信息处理政策", "协议与规则")

# 点击策略优先级：处理弹窗 > 进入主功能 > 其余
DIALOG_CLASS_HINT = ("Dialog", "AlertDialog", "PopupWindow")

# 遍历时**禁止点击**的文字：点下去会让 App 退出/拒绝授权，导致采集中断或行为失真
# 真机教训：遍历点中「不同意」→ App 退出 → 掉到桌面 → 重新拉起 → 再点「不同意」，
# 形成死循环，几十秒一无所获。
DANGEROUS_LABELS = (
    "不同意", "不同意并退出", "不同意并离开", "拒绝", "残忍拒绝", "暂不使用",
    "退出应用", "退出程序", "关闭应用", "以后再说", "放弃", "注销账号", "删除账号",
    "退出登录", "取消订单", "确认卸载",
    # ★ 「取消」必须禁 —— 它与 AI 提示词里声明的红线保持一致。
    #   真机实测（赣警办 e2e5）：规则遍历走到系统权限弹窗时点了「取消」，
    #   等于替用户拒绝了权限，后面的权限相关行为就被"改"掉了 ——
    #   检测结果失真比采不到更糟，因为报告会把"拒绝后没收集"读成"App 没这个行为"。
    #   同一轮里 AI 决策的候选表也含该按钮，靠的是模型语义绕开；
    #   规则兜底没有语义能力，只能靠这张表硬拦。
    "取消", "不允许", "禁止", "拒绝授权",
)

# 「二次确认型」销毁动作：入口本身（注销账号 / 删除账号）上面已经拦了，
# 但真正执行销毁的是确认弹窗上那个按钮，措辞是「确定注销」而不是「注销账号」。
# ★ 真机实测（以观书法 mbsf13）：这个按钮没被拦住 —— 点下去账号真的被注销、
#   App 进程退出、重新注入 hook，白烧 15 轮预算（第 28 步到第 41 步都在恢复），
#   而且账号没了之后账号页再也进不去，9 类权利入口一个都到不了。
#   合规上更关键：**「有注销入口、且需要二次确认」这个事实在确认页出现时就
#   已经取证到了**，再点确认不增加任何新的合规事实，只破坏后续采集。
DANGEROUS_CONFIRM_LABELS = (
    "确定注销", "确认注销", "确定注销账号", "确认注销账号", "注销并退出",
    "确定删除", "确认删除", "永久删除", "确定清空", "确认清空",
    "确定解绑", "确认解绑",
)


def is_dangerous(node: "UiNode") -> bool:
    """该节点是否属于「不能点」的危险操作。"""
    label = (node.label or "").strip()
    if not label:
        return False
    for kw in DANGEROUS_LABELS:
        if kw in label:
            return True
    for kw in DANGEROUS_CONFIRM_LABELS:
        if kw in label:
            return True
    return False


# 「点了没用、还可能有副作用」的控件。
#   · 输入框：点下去只是聚焦并弹出键盘，键盘会盖住下半屏，后面的 dump 全是键盘布局；
#   · 图形验证码：点一下就换一张，正在走的登录流程会被打断。
# 真机实测（赣警办注册页）：遍历连着点了「请输入手机号」「请输入验证码」
# 「img_verificationcode」三次，一无所获，还把界面顶成了输入法。
NO_USE_CLASSES = ("EditText", "AutoCompleteTextView", "SearchView")
NO_USE_ID_HINTS = ("verificationcode", "verif", "captcha", "vcode", "img_code", "codeimg")


def is_no_use(node: "UiNode") -> bool:
    """这个控件点了没有采集价值（还可能带来副作用）。"""
    cls = (node.cls or "").split(".")[-1]
    if cls in NO_USE_CLASSES:
        return True
    # 注意用**最后一段** id，不能拿整条匹配：包名里带 "com.verif.xxx" 的会误伤。
    sid = (node.resource_id or "").split("/")[-1].lower()
    return bool(sid) and any(k in sid for k in NO_USE_ID_HINTS)


# 反自动化/人机验证的界面特征。
# 实测（滴滴出行）：因为早期 bug 点到了「不同意」，App 反复冷启，
# 服务端判定异常后直接下发滑块验证码接管整个界面 —— 后续遍历全在验证码页上打转，
# 采到的界面证据全部无效。若不显式识别并标注，报告会把这些"采不到"
# 误读成"App 没有该行为"，方向完全反了。
#
# 但要区分**强特征**与**弱特征**：「验证码」这个词太常见了，
# 登录页的"请输入短信验证码 / 60 秒后重新获取"也会命中 —— 那是正常业务界面，
# 不是反自动化拦截。误报一条"被验证码拦截"会让人对整个报告的判断力产生怀疑，
# 所以只有弱特征命中时，必须再看一眼上下文是不是登录发码。
CAPTCHA_STRONG = ("拖动滑块", "滑块验证", "滑动验证", "拖动下方滑块", "安全验证",
                  "人机验证", "请完成验证", "点击完成验证", "行为验证", "滑动验证码")
CAPTCHA_WEAK = ("验证码",)
CAPTCHA_LOGIN_HINT = ("获取验证码", "短信验证码", "重新获取", "秒后重新", "请输入验证码",
                      "手机号", "手机号码", "登录", "注册")


def captcha_markers(xml: str) -> List[str]:
    """返回界面上命中的**反自动化验证**特征词（已排除登录短信验证码）。"""
    if not xml:
        return []
    strong = [m for m in CAPTCHA_STRONG if m in xml]
    if strong:
        return strong
    if any(m in xml for m in CAPTCHA_WEAK):
        # 只有"验证码"这种弱特征：若同时像登录发码界面，就不算拦截
        if any(h in xml for h in CAPTCHA_LOGIN_HINT):
            return []
        return ["验证码"]
    return []


def marker_context(xml: str, marker: str, span: int = 40) -> str:
    """取特征词附近的上下文片段，便于人工核对告警是否成立。"""
    if not xml or not marker:
        return ""
    i = xml.find(marker)
    if i < 0:
        return ""
    seg = xml[max(0, i - span): i + len(marker) + span]
    # 界面上真正可读的是 text= / content-desc= 的值，把标签本身压掉一些
    return re.sub(r'\s+', " ", seg)[:120]


# ---- 诊断计时（只在 PIISCAN_PROF=1 时工作，生产路径零开销）----
# 为什么要这一层：真机一轮遍历 306 步花掉 45 分钟，光看日志只能看到
# "第几轮点了什么"，看不到"这一轮 9 秒里 adb 占了几秒、模型占了几秒"。
# 事后想回答"时间是被功能多耗掉的还是被无谓开销耗掉的"就只能靠猜 ——
# 而猜出来的数字会直接写进报告，那是假话。
# 这里把所有 adb 往返集中计时（`_adb` 是唯一出口），再由调用方按轮打印。
PROF: Dict[str, Any] = {"on": False, "calls": 0, "secs": 0.0,
                        "tags": {}, "slow": []}


def prof_reset() -> None:
    PROF["calls"] = 0
    PROF["secs"] = 0.0
    PROF["tags"] = {}
    PROF["slow"] = []


def _prof_tag(args: Sequence[str]) -> str:
    """把一次 adb 调用压成可读标签（`shell uiautomator dump` 之类）。"""
    head = [a for a in args[:4] if a and not a.startswith("/")]
    t = " ".join(head[:3])
    if "uiautomator" in t:
        return "dump"
    if "screencap" in t:
        return "screencap"
    if t.startswith("pull"):
        return "pull"
    if "input" in t:
        return "input"
    if "dumpsys" in t:
        return "dumpsys"
    if "am " in t or t.startswith("shell am"):
        return "am"
    if "pidof" in t:
        return "pidof"
    return t[:24] or "?"


def _adb(serial: str, *args: str, timeout: int = 25) -> subprocess.CompletedProcess:
    cmd = [_adb_bin()] + (["-s", serial] if serial else []) + list(args)
    if not PROF["on"]:
        return subprocess.run(cmd, capture_output=True, timeout=timeout)
    _t = time.time()
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout)
    finally:
        _d = time.time() - _t
        PROF["calls"] += 1
        PROF["secs"] += _d
        _tag = _prof_tag(args)
        _rec = PROF["tags"].setdefault(_tag, [0, 0.0])
        _rec[0] += 1
        _rec[1] += _d
        if _d >= 5.0:
            PROF["slow"].append((round(_d, 1), _tag))


def prof_enable(on: bool = True) -> None:
    PROF["on"] = bool(on)


def prof_summary() -> Dict[str, Any]:
    tags = {k: (v[0], round(v[1], 1)) for k, v in
            sorted(PROF["tags"].items(), key=lambda kv: -kv[1][1])}
    return {"calls": PROF["calls"], "secs": round(PROF["secs"], 1),
            "tags": tags, "slow": list(PROF["slow"])}


_ADB_CACHE: list = []          # 只缓存一次，避免每次 dump 都 stat 文件


def _adb_bin() -> str:
    """找 adb 可执行文件。

    ★ 这里原先写死 `"adb"`（2026-11-06 发现）：全项目其它模块
      （collector / preflight / teardown / crashinfo / device_ids）都认
      `ADB` 环境变量，唯独**真正干活的这一层**不认。后果是 adb 不在 PATH 时，
      上层自检拿着 ADB 指向的真实路径报告"adb 正常"，而所有点击、dump、
      content query 全部静默失败 —— 现象是"界面一直没变化"，最难查的那类。
    """
    if _ADB_CACHE:
        return _ADB_CACHE[0]
    import os
    import shutil

    cand = [os.environ.get("ADB", ""), os.environ.get("ADB_PATH", "")]
    for env_name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(env_name) or ""
        if root:
            cand.append(os.path.join(root, "platform-tools",
                                     "adb.exe" if os.name == "nt" else "adb"))
    cand.append(shutil.which("adb") or "")
    found = "adb"
    for p in cand:
        if p and os.path.exists(p):
            found = p
            break
    _ADB_CACHE.append(found)
    return found


# ------------------------------------------------------------ 设备掉线自愈
#
# ★ 为什么需要这一层（2026-10-26 批量实测取证）：
#   批量跑到某个 APK 时，USB 会偶发重新枚举，`adb get-state` 报
#   `error: no devices/emulators found`，而**设备两秒左右就自己回来了**
#   （同一次运行里收尾等待的记录是「已等 0 秒」→ 2.2 秒后「设备已就绪」）。
#   自检恰好落在这两秒里，就把「设备暂时不在」判成了「环境不可用」，
#   整轮检测直接失败；而人看到的建议是「拔插数据线后重试」 ——
#   于是现象被解释成「必须拔插才恢复」。
#
#   这一层只做一件事：**先等它回来，等不到再报错**。所有判据都取自
#   `adb get-state` 的原文，不猜测、不掩盖；确实回不来时照样把原因说清。

_LINK_DOWN_MARKS = (
    "no devices/emulators found",
    "device not found",
    "device offline",
    "device still authorizing",
    "device unauthorized",
    "error: closed",
    "cannot connect to daemon",
    "connection reset",
    "protocol fault",
)

# `adb -s a1b2c3d4 get-state` 在设备不在时给的是
# `error: device 'a1b2c3d4' not found` —— 中间夹着序列号，没法用固定子串匹配；
# 而宽松到只认 "not found" 会连 `package not found` 一起吞掉（那是应用侧的事）。
_LINK_DOWN_RE = re.compile(r"device\s+['\"][^'\"]*['\"]\s+not\s+found", re.I)


def link_down(text: Any) -> bool:
    """这段输出（或异常文本）是不是「设备从 adb 掉线」这一类。"""
    t = str(text or "").lower()
    if any(m in t for m in _LINK_DOWN_MARKS):
        return True
    return bool(_LINK_DOWN_RE.search(str(text or "")))


def device_state(serial: str = "") -> str:
    """`adb get-state` 的原文；取不到时返回带错误原因的一行。

    ★ stdout 优先、stderr 只兜底。真机实测：adb server 刚被拉起时，
      stdout 是干净的 `device`，而 stderr 会多出两行
      `* daemon not running; starting now at tcp:5037` / `* daemon started successfully`。
      两者一拼，`"device" != "device\n* daemon not running…"` —— 于是"设备明明
      在线"被判成"不在 adb 里"，自愈逻辑就会白等一轮。这类误判最隐蔽：
      状态看着像有内容，实际是噪音把判等搞坏了。
    """
    try:
        r = _adb(serial, "get-state", timeout=10)
    except subprocess.TimeoutExpired:
        return "adb get-state 超时（10s）"
    except Exception as e:
        return "adb 调用失败：%s" % e
    out = (r.stdout or b"").decode("utf-8", errors="replace").strip()
    if not out:
        out = (r.stderr or b"").decode("utf-8", errors="replace").strip()
    return (out.replace("\n", " ") or "(空)")[:200]


def ensure_device(serial: str = "", wait_s: float = 45.0,
                  log: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
    """等设备重新出现在 adb 里。返回 `(是否就绪, 说明)`。

    分三段，代价从低到高：
      ① 先轮询 `get-state`。USB 重新枚举通常几秒内自愈，绝大多数情况
         走到这里就结束了 —— 不会碰 `reconnect`，更不会碰 `kill-server`。
      ② 若看到 `offline` / `unauthorized`，发一次 `adb reconnect offline`
         （只对这类连接有效，不动别的）。
      ③ 走到时限仍未回来，才 `adb reconnect`；仍不行再 `kill-server`
         + `start-server`。**这一步会踢掉本机所有 adb 会话**（包括 frida 的），
         所以只在最后 1/3 时间窗口里做一次，且必须留痕。

    为什么不当场判死：一次误判的成本是整整一轮检测（十几分钟 + 一台手机），
    而等 45 秒的成本只是 45 秒。两者不在一个量级上。
    """
    say = log or (lambda _s: None)
    t0 = time.time()
    deadline = t0 + max(1.0, float(wait_s))

    state = device_state(serial)
    if state == "device":
        return True, ""

    say("[*] 设备不在 adb 里（%s），等待它自行恢复（上限 %.0fs）…" % (state, wait_s))
    reconn = False
    hard = False
    last = ""

    # ★ offline / unauthorized 与「no devices」不是一回事：
    #   前者是"设备在总线上但连不上"（授权失效、adbd 卡住），`reconnect`
    #   是标准解法，早做早好；后者是"还没枚举上来"，只能等。
    #   把两者混在一起、一律等到 1/3 时限再动手，等于白等十几秒。
    if ("offline" in state.lower()) or ("unauthorized" in state.lower()):
        reconn = True
        try:
            _adb("", "reconnect", "offline", timeout=10)
            say("    处于 %s，已执行 adb reconnect offline" % state)
        except Exception as e:
            say("    adb reconnect offline 失败：%s" % e)
    while time.time() < deadline:
        if state != last:
            last = state
            say("    当前状态：%s（已等 %.1fs）" % (state, time.time() - t0))
        # ② 中段：明确的离线态才发 reconnect
        if (not reconn) and time.time() - t0 >= min(6.0, wait_s / 3.0):
            reconn = True
            try:
                _adb("", "reconnect", "offline", timeout=10)
                say("    已执行 adb reconnect offline")
            except Exception as e:
                say("    adb reconnect offline 失败：%s" % e)
        # ③ 末段：还没回来才动 server（代价最高）
        if (not hard) and time.time() - t0 >= wait_s * 0.66:
            hard = True
            try:
                _adb("", "reconnect", timeout=10)
                say("    已执行 adb reconnect")
            except Exception:
                pass
            if device_state(serial) != "device":
                try:
                    _adb("", "kill-server", timeout=15)
                    time.sleep(1.0)
                    _adb("", "start-server", timeout=25)
                    say("    已重启 adb server（会断开所有既有 adb 会话）")
                except Exception as e:
                    say("    adb server 重启失败：%s" % e)
        time.sleep(0.8)
        state = device_state(serial)
        if state == "device":
            say("[+] 设备自行恢复（等待 %.1fs）：已重新可见"
                % (time.time() - t0))
            # 只报「等了多久、回来了」。掉线时的原文由调用方自己带（它有 st），
            # 塞进返回值会让 detail 里出现两遍同样的错误行。
            return True, "等待 %.1fs 后恢复" % (time.time() - t0)

    return False, "等待 %.0fs 仍未恢复，最后状态：%s" % (time.time() - t0, device_state(serial))


def _inject(serial: str, cmd: str, root: bool = True) -> bool:
    """注入输入事件。默认走 root，规避 MIUI 等系统的权限限制。"""
    try:
        if root:
            r = _adb(serial, "shell", "su -c '%s'" % cmd, timeout=20)
        else:
            r = _adb(serial, "shell", *cmd.split(), timeout=20)
        blob = (r.stdout or b"") + (r.stderr or b"")
        return b"Exception" not in blob and b"Error:" not in blob
    except Exception:
        return False


@dataclass
class UiNode:
    text: str
    cls: str
    resource_id: str
    bounds: Tuple[int, int, int, int]
    clickable: bool = False
    scrollable: bool = False
    enabled: bool = True
    package: str = ""
    content_desc: str = ""
    # 勾选态（CheckBox）。登录页的「我已阅读并同意《用户协议》」必须勾上，
    # 否则「获取验证码」「登录」点了没反应 —— 只弹一个 toast。
    checked: bool = False
    checkable: bool = False
    # 后代文字（自身没有文字时用）。真机上大量可点条目是"空壳容器"：
    # clickable=true 的 LinearLayout，text / content-desc 全空，文字在子 TextView 里。
    # 见 parse_all 里 `_collect_text` 的说明。
    sub_text: str = ""
    # 主导航条里的次序（1 起算；0 = 不在导航条上）。无文字的自绘底栏靠它命名。
    nav_slot: int = 0
    # 主导航条共有几项。命名成「底部导航第3/4项」才能在报告里说清位置。
    nav_total: int = 0
    # 自身或后代里有没有图标（ImageView）。底栏 tab 几乎都带图标，
    # 而内容区等宽排布的文字格子没有 —— 这是区分两者的硬特征。
    has_icon: bool = False

    @property
    def center(self) -> Tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return (x1 + x2) // 2, (y1 + y2) // 2

    @property
    def label(self) -> str:
        return (self.text.strip()
                or self.content_desc.strip()
                or self.sub_text.strip()
                or self.resource_id.split("/")[-1]
                or self.cls.split(".")[-1]
                or "未命名元素")

    @property
    def key(self) -> str:
        return "%s@%s" % (self.label, self.bounds)

    def to_dict(self) -> Dict[str, object]:
        return {"label": self.label, "text": self.text, "cls": self.cls,
                "id": self.resource_id, "bounds": list(self.bounds)}


# ---------------------------------------------------------------- 界面 dump

_DUMP_DIRS = ("/sdcard", "/data/local/tmp")
_dump_seq = itertools.count(1)

# uiautomator dump 的单步耗时预算。
# 正常 2~8 秒（MIUI 上每次都往 logcat 里刷一条 theme_compatibility.xml 的
# FileNotFoundException，纯属噪声，不影响结果）。给到 18 秒已经足够覆盖慢页面。
_DUMP_TIMEOUT = 18
_CAT_TIMEOUT = 12
_RM_TIMEOUT = 8

# ★ 设备端 uiautomator 卡死 —— 无人值守下最致命的一种故障。
# 症状（真机实测）：`uiautomator` 进程驻留在 `SyS_nanosleep` 不可中断状态，
# adb 侧 subprocess 超时后进程**并不会退**，于是后续每一次 dump 都排在同一次
# 死锁后面，一次 25 秒、重试两次、两三个落盘目录各试一遍 —— 单次 dump_retry
# 能吃掉 3 分钟以上，整条任务队列就冻在「采集收尾」不动了。
# 更糟的是这类卡死会跨任务传染：上一个任务留下的僵死进程会拖死下一轮检测。
# 因此：超时后必须**主动杀掉设备端残留**，并且硬故障累积到阈值就熔断降级
# （纯截图），宁可少采也不能让队列停摆。
#
# ★ 为什么只让"硬故障"计入熔断：
#   `uiautomator dump` 在 WebView / 动画 / 页面切换时拿不到结构树是**常态**，
#   遍历里这种软失败很常见（真机一次遍历十几二十次）。若它们也计数，
#   一个正常的 WebView 页面就会把整轮遍历打进降级期，反而把能用的界面也停了。
#   所以：软失败只统计、不熔断；只有"超时"和"进程还赖着"才算硬故障。
_DEGRADE_AFTER = 2          # 硬故障累计到几次判为「设备侧 UI 服务不可用」
_DEGRADE_COOL = 90.0        # 降级持续时长；到期后再探一次，恢复即自动解除

# ★ 连续软失败也必须熔断（2026-11-02 川剧迷事故）。
#   上面那段说"软失败只统计、不熔断"，针对的是**偶发**：一次 WebView 失败，
#   下一屏就成功，`soft_run` 归零，确实不该熔断。
#   但**连续**软失败是另一回事 —— 那说明设备侧 uiautomator 已经彻底拿不到
#   结构树了，再试也只是把预算烧成超时。真机记录：川剧迷点到搜索页之后
#   连续 63 次软失败，每轮老实等满 18s + 补读 + 清理 ≈ 49 秒，
#   第 51~111 轮整整烧掉 2954 秒（49 分钟）**一个动作都没做**，
#   最后还被写成"时间预算耗尽"，看起来像正常跑完了 60 分钟。
#   因此：连续到阈值就升级成硬故障（进降级期），并改用短超时快速失败。
_SOFT_RUN_LIMIT = 5         # 连续软失败到几次，升级为「设备侧 UI 服务不可用」
_SOFT_FAST_AFTER = 2        # 连续失败到几次改用短超时（快速失败，别再等满 18s）
_DUMP_FAST_TIMEOUT = 6      # 快速失败档的单次超时

_HEALTH: Dict[str, Dict[str, float]] = {}


def _hp(serial: str) -> Dict[str, float]:
    return _HEALTH.setdefault(serial or "-", {
        "harm": 0.0, "fails": 0, "ok": 0, "skipped": 0, "kills": 0,
        "soft_run": 0, "last_kill_at": 0.0,
        "degraded_until": 0.0, "since": 0.0, "reason": "", "harm_reason": "",
    })


def dump_health(serial: str) -> Dict[str, object]:
    """当前设备侧界面读取健康状态，供上层写进日志与报告。

    `degraded=True` 意味着「本轮已经读不到界面结构树」，报告里必须显式说明，
    否则读者会把"没采到界面证据"误读成"App 没有这个行为"。
    """
    d = _hp(serial)
    now = time.time()
    return {
        "degraded": now < d["degraded_until"],
        "fails": int(d["fails"]),
        "ok": int(d["ok"]),
        "skipped": int(d["skipped"]),
        "kills": int(d["kills"]),
        "harm": int(d["harm"]),
        "soft_run": int(d.get("soft_run", 0)),
        "reason": d["reason"],
        "seconds_left": max(0, int(d["degraded_until"] - now)),
    }


def reset_dump_health(serial: str = "") -> None:
    """清空健康计数（新任务开始 / 单元测试用）。"""
    if serial:
        _HEALTH.pop(serial or "-", None)
    else:
        _HEALTH.clear()


def reset_soft_run(serial: str) -> None:
    """清空「连续失败」计数（上层做过自愈动作之后调用）。

    收了键盘 / 重启了被测应用，环境已经不是刚才那个了 —— 这时候还拿旧的
    连续失败次数去熔断，等于"刚救回来就判死"。计数重来，才给得了一次机会。
    """
    d = _hp(serial)
    d["soft_run"] = 0
    d["harm"] = 0.0
    d["harm_reason"] = ""
    d["degraded_until"] = 0.0


def _pidof(serial: str, name: str = "uiautomator") -> List[str]:
    try:
        r = _adb(serial, "shell", "pidof", name, timeout=10)
    except Exception:
        return []
    out = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", errors="replace")
    return [p for p in out.split() if p.isdigit()]


def kill_stale_uiautomator(serial: str) -> Tuple[int, List[str]]:
    """杀掉设备端卡死的 `uiautomator` 进程。

    返回 `(杀掉的个数, 仍然存活的 pid 列表)`。**第二个值比第一个重要**：
    杀不掉也是一种病态（权限不足 / 进程进了 D 状态），调用方必须据此判定
    "设备侧不可用"，否则会陷入"每次都试杀、每次都失败、每次都照样等 18 秒"
    的死循环 —— 那和没修是一样的。

    为什么一定要 `kill -9`：卡在 `SyS_nanosleep` 里的进程对 SIGTERM 不响应，
    `pkill` 默认发的是 SIGTERM，杀不掉。
    """
    pids = _pidof(serial)
    if not pids:
        return 0, []
    for pid in pids:
        for cmd in ("su -c 'kill -9 %s'" % pid, "su -c \"kill -9 %s\"" % pid,
                    "kill -9 %s" % pid):
            try:
                _adb(serial, "shell", cmd, timeout=10)
            except Exception:
                continue
            if not _pidof(serial):
                break
    alive = _pidof(serial)
    if alive:
        try:
            _adb(serial, "shell", "su -c 'pkill -9 -f uiautomator'", timeout=10)
        except Exception:
            pass
        alive = _pidof(serial)
    killed = len([p for p in pids if p not in alive])
    return killed, alive


def _mark_fail(serial: str, reason: str, harm: int = 0) -> None:
    """记一次界面导出失败。`harm>0` 表示硬故障（超时 / 进程赖着），会计入熔断。

    ★ 这里**不**累计 `soft_run`：一次 `dump()` 内部会按落盘目录重试多次，
    按 `_mark_fail` 计数会让"一次调用"变成两三次额度，阈值等于打了个对折。
    连续失败由 `_bump_soft()` 在 `dump()` 整体返回 None 时记一次。
    """
    d = _hp(serial)
    d["fails"] += 1
    d["harm"] += harm
    # 硬故障的原因不能被后续软失败覆盖 —— 报告里要写清"是设备卡死"，
    # 而不是笼统的"页面切换常见"。
    if harm > 0:
        d["harm_reason"] = reason
        d["reason"] = reason
    elif not d.get("harm_reason"):
        d["reason"] = reason
    if d["harm"] >= _DEGRADE_AFTER and time.time() >= d["degraded_until"]:
        d["degraded_until"] = time.time() + _DEGRADE_COOL

        d["since"] = time.time()


def _bump_soft(serial: str) -> None:
    """一次 `dump()` 整体失败后记一次「连续失败」，到阈值即升级为熔断。

    判据用**连续**而不是累计：中间只要成功一次，`_mark_ok` 就把它清零，
    偶发的 WebView/动画失败不会被当成设备故障（否则正常页面也会被停掉）。
    """
    d = _hp(serial)
    d["soft_run"] = int(d.get("soft_run", 0)) + 1
    if d["soft_run"] < _SOFT_RUN_LIMIT:
        return
    if time.time() < d["degraded_until"]:
        return
    # 直接补足到熔断阈值：连续这么多次已经能判"读不出来"了，
    # 不必再等下一轮才降级（每多等一轮就是十几秒白等）。
    d["harm"] = max(int(d["harm"]), _DEGRADE_AFTER)
    d["harm_reason"] = ("连续 %d 次无法读取界面结构（最后一次：%s）"
                        % (d["soft_run"], d["reason"] or "uiautomator 无有效输出"))
    d["reason"] = d["harm_reason"]
    d["degraded_until"] = time.time() + _DEGRADE_COOL
    d["since"] = time.time()


def _mark_ok(serial: str) -> None:
    d = _hp(serial)
    d["ok"] += 1
    d["harm"] = 0.0
    d["harm_reason"] = ""
    d["soft_run"] = 0
    d["degraded_until"] = 0.0


def _read_dump_file(serial: str, path: str, retry_read: bool = True) -> Optional[str]:
    """把设备端已经落盘的 dump 读回来并校验完整性。

    `</hierarchy>` 是硬条件：超时后那只进程可能还在写，读到半截 XML 会被
    当成"界面结构"去解析，节点坐标全错 —— 宁可判失败也不能用半截文件。

    `retry_read=False` 用于连续失败后的快速档：这时设备端 uiautomator
    基本已经不干活了，再等第二次 `cat` 只是把单步再多赔 12 秒。
    """
    try:
        r = _adb(serial, "shell", "cat", path, timeout=_CAT_TIMEOUT)
    except Exception:
        return None
    blob = (r.stdout or b"")
    if r.returncode != 0 or not blob:
        return None
    text = blob.decode("utf-8", errors="replace")
    if "<hierarchy" not in text:
        return None
    if "</hierarchy>" in text:
        return text
    if not retry_read:
        return None
    # 可能还没写完：等一拍再读一次，仍不完整就放弃。
    time.sleep(0.6)
    try:
        r2 = _adb(serial, "shell", "cat", path, timeout=_CAT_TIMEOUT)
        t2 = (r2.stdout or b"").decode("utf-8", errors="replace")
        if "<hierarchy" in t2 and "</hierarchy>" in t2:
            return t2
    except Exception:
        pass
    return None


def _cleanup(serial: str, path: str) -> None:
    try:
        _adb(serial, "shell", "rm", "-f", path, timeout=_RM_TIMEOUT)
    except Exception:
        pass


def dump(serial: str, remote: str = "", force: bool = False) -> Optional[str]:
    """导出界面 XML。

    **必须用一次性文件名**：早期版本用固定路径 `/sdcard/piiscan_ui.xml`，
    而 `uiautomator dump` 在页面切换 / 动画 / WebView 上失败率很高，
    一旦失败，紧接着的 `cat` 会读到**上一次留下的旧文件** —— 调用方于是拿到
    过期的界面结构，按里面的坐标去点，点到的东西和它以为的完全不是一回事。
    现在每次生成唯一文件名并先 `rm -f`，失败就没有文件可读，交给上层重试。

    **熔断**：硬故障（超时 / 进程赖着不走）累积到阈值后进入降级期，期间直接返回
    None 不再碰设备 ——
    这几十毫秒的"空返回"换的是整条队列不被一个僵死进程拖住。降级到期后
    自动放一次探测（`force=True` 可强制探测），成功即恢复。
    """
    d = _hp(serial)
    if not force and time.time() < d["degraded_until"]:
        d["skipped"] += 1
        return None

    # 连续失败后进快速档：超时 18s→6s，超时后也不再补读一次。
    # 这一档不改变"能不能读到"的判据，只保证读不到的时候别把预算烧光
    # （川剧迷那次每轮 49 秒、烧了 49 分钟，主要就是这两笔）。
    _fast = int(d.get("soft_run", 0)) >= _SOFT_FAST_AFTER
    _to = _DUMP_FAST_TIMEOUT if _fast else _DUMP_TIMEOUT

    if remote:
        cands = [remote]
    else:
        n = next(_dump_seq)
        cands = ["%s/piiscan_ui_%d.xml" % (d_, n) for d_ in _DUMP_DIRS]

    # 上一次是硬故障退出的（harm>0）：先清设备端残留，别让新一轮继续排队。
    # 上一次干净成功过就不做这一步 —— 每次 dump 都 pidof 一遍等于给遍历加
    # 一次额外的 adb 往返，几十步下来是实打实的时间。
    # 连续失败时这一步限频到 12 秒一次：真卡住的时候 pidof 自己也会超时，
    # 每轮都清等于每轮多赔 10 秒（川剧迷事故里的一半时间就这么没的）。
    if d["harm"] > 0 and time.time() - float(d.get("last_kill_at", 0.0)) >= 12:
        d["last_kill_at"] = time.time()
        n, _alive = kill_stale_uiautomator(serial)
        if n:
            d["kills"] += n
            d["reason"] = "清理设备端残留 uiautomator 进程 %d 个" % n

    for path in cands:
        try:
            _adb(serial, "shell", "rm", "-f", path, timeout=_RM_TIMEOUT)
        except Exception:
            pass

        timed_out = False
        try:
            # 不用 --compressed：真机实测它把节点从 212 砍到 112（父容器被剪掉），
            # 耗时却一样（都是 3.4s）。而 _host_for / 弹窗归因都依赖父容器结构，
            # 少一半节点换不到任何速度，只会让证据变薄。
            _adb(serial, "shell", "uiautomator", "dump", path,
                 timeout=_to)
        except subprocess.TimeoutExpired:
            timed_out = True
        except Exception as e:
            _mark_fail(serial, "uiautomator dump 调用异常：%s" % e)
            continue

        if timed_out:
            # ★ 超时先别判死（2026-10-27 洋葱学园批量事故）：`uiautomator dump`
            #   在动画 / WebView / 正在切换的页面上会先等 idle（约 10 秒），等不到
            #   就打印 "could not get idle state" **然后照样落盘**。客户端 18 秒
            #   到点退出时，设备端往往刚好写完 —— 真机实测 self-check 报
            #   "无敌输出（23.4s）"，而 /sdcard 上的 XML 是完好的 63 KB。
            #   所以先看看文件在不在：白捡一次成功，比再赔一次超时划算。
            late = _read_dump_file(serial, path, retry_read=not _fast)
            killed, _alive = kill_stale_uiautomator(serial)
            d["kills"] += killed
            if late:
                _mark_ok(serial)
                d["reason"] = ""
                _cleanup(serial, path)
                return late
            # 文件也没有 → 才认定设备端卡死：adb 客户端被打死了，设备上的
            # uiautomator 还活着并继续占着 accessibility 服务，不杀就永远卡。
            _mark_fail(serial, "uiautomator dump 超时（%ds），清理设备端残留 %d 个"
                       % (_to, killed), harm=1)
            # 不要再试第二个落盘目录 —— 同一台设备上换目录也一样卡，
            # 只会把 18 秒再赔一遍。
            break

        try:
            r = _adb(serial, "shell", "cat", path, timeout=_CAT_TIMEOUT)
        except subprocess.TimeoutExpired:
            _mark_fail(serial, "读取界面 XML 超时", harm=1)
            break
        except Exception as e:
            _mark_fail(serial, "读取界面 XML 异常：%s" % e)
            continue

        blob = (r.stdout or b"")
        if r.returncode == 0 and blob:
            text = blob.decode("utf-8", errors="replace")
            if "<hierarchy" in text:
                try:
                    _adb(serial, "shell", "rm", "-f", path, timeout=_RM_TIMEOUT)
                except Exception:
                    pass
                _mark_ok(serial)
                return text

        # 走到这里说明没拿到结构树。两种情况必须分开：
        #   · 页面本身导不出来（切换中 / WebView / 动画）→ 换目录再试一次就够；
        #   · 设备端 uiautomator 进程被占住/卡死（实测 `uiautomator events`
        #     之类残留进程会让 dump 直接报 "could not get idle state"，
        #     进程却一直不退）→ 必须杀掉，否则后续每次都不出来。
        # 判据就是 pidof —— 正常 dump 结束进程即退，还活着就说明它没正常收工。
        # ★ 注意这里判的是"清理后是否还有存活进程"，而不是"杀掉了几个"：
        #   杀不掉同样意味着设备侧不可用，若只看杀掉个数，一个杀不掉的僵死进程
        #   会让程序永远认为"设备没问题"，每次都白等一轮超时。
        stuck, alive = kill_stale_uiautomator(serial)
        d["kills"] += stuck
        if alive:
            _mark_fail(serial, "设备端 uiautomator 进程无响应且未能清理（pid %s）"
                       % ",".join(alive), harm=1)
        elif stuck:
            _mark_fail(serial, "设备端 uiautomator 进程无响应，已清理 %d 个残留进程" % stuck,
                       harm=1)
        else:
            _mark_fail(serial, "uiautomator dump 无有效输出（页面切换 / WebView 常见）")

    # 一次 dump() 彻底失败（含 fallback 目录都试过）：连续计数只加一次，
    # 到阈值就把设备侧判死、进降级期 —— 见 `_SOFT_RUN_LIMIT` 的说明。
    _bump_soft(serial)
    return None


def current_focus(serial: str) -> str:
    """当前前台窗口 `包名/Activity`，取不到返回空串。

    ★ 为什么需要它来判断"点中了没有"：
      结构树指纹（screen_fingerprint）在两种情况下会骗人 ——
        · App 打开的是一个 **WebView 页面**：内容由 JS 渲染，结构树可能长期为空
          或与前一屏文字高度重合 → 指纹不变 → 明明点开了却被判成"没点中"；
        · 点击只是让**弹窗滚动**了一下 → 文字集合变了 → 被判成"点中了"，
          其实政策页根本没打开。
      而"前台 Activity 有没有换"是操作系统层面的客观事实，不受页面渲染影响。
      真机实测（赣警办 e2e6）：只靠指纹判断，同一组坐标有时算命中、有时不算，
      结论随之在"已点开"和"未跳转"之间摇摆 —— 报告结论不能建立在这种抖动上。
    """
    out = ""
    # 子命令在不同 ROM 上差异很大：MIUI(Android 12) 上 `dumpsys window windows`
    # 返回空，只有 `dumpsys window` 才有内容 —— 两个都试，拿第一个有输出的。
    for args in (("shell", "dumpsys", "window"), ("shell", "dumpsys", "window", "windows")):
        try:
            proc = _adb(serial, *args, timeout=20)
            got = proc.stdout.decode("utf-8", errors="replace")
        except Exception:
            continue
        if "mCurrentFocus" in got or "mFocusedApp" in got:
            out = got
            break
    if not out:
        return ""
    # 优先取 mCurrentFocus / mFocusedApp 行；不同 Android 版本字段名不同，都试一遍
    for key in ("mCurrentFocus", "mFocusedApp", "mFocusedWindow"):
        for line in out.splitlines():
            if key in line:
                m = re.search(r"([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)", line)
                if m:
                    return "%s/%s" % (m.group(1), m.group(2))

    # ★ 兜底：有些窗口**不拿输入焦点**，`mCurrentFocus` 就是 null，而 Activity
    #   明明在前台。洋葱学园 2026-10-27 实测：屏幕上明明是完整的首启隐私政策
    #   弹窗（有「同意并继续」按钮），`mCurrentFocus=null`，只有
    #   `mResumedActivity` 是它的 LoginRootActivity。只认 window 的焦点字段会
    #   把这种应用判成"前台从未切换"——用户站在手机前看 App 明明开着，
    #   报告却说他没打开，正是这条错误的来源。
    #   `dumpsys activity activities` 输出大、慢，所以只在上面全部落空时才走。
    try:
        proc = _adb(serial, "shell", "dumpsys", "activity", "activities", timeout=25)
        got = (proc.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return ""
    for key in ("topResumedActivity", "mResumedActivity"):
        for line in got.splitlines():
            if key in line:
                m = re.search(r"([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)", line)
                if m:
                    return "%s/%s" % (m.group(1), m.group(2))
    return ""


#: 各 ROM 的系统桌面（Launcher）包名。桌面上拍到的截图永远不能当应用证据。
_LAUNCHER_PKGS = ("com.miui.home", "com.huawei.android.launcher",
                  "com.bbk.launcher2", "com.oppo.launcher",
                  "com.android.launcher", "com.android.launcher3",
                  "com.google.android.apps.nexuslauncher")


def is_launcher_pkg(pkg: str) -> bool:
    """这个包名是不是系统桌面。"""
    p = (pkg or "").strip().lower()
    if not p:
        return False
    if p in _LAUNCHER_PKGS:
        return True
    return ("launcher" in p or "lawnchair" in p) and "launcherprovider" not in p


def window_focus_pkg(serial: str) -> str:
    """当前**真正拿到输入焦点**的窗口包名，取不到返回空串。

    ★ 为什么不直接用 `current_focus()`（2026-11-10 健康深圳 / 搜题）：
      `current_focus()` 在拿不到 `mCurrentFocus` 时会兜底去读
      `mResumedActivity`，而这两件事在真机上**会不一致** —— 那两单是
      uni-app（`io.dcloud.PandoraEntry`），Activity 已经 resumed，
      窗口却一直没画出来，用户看到的是系统桌面。`top_activity()` /
      `current_focus()` 于是返回"应用在前台"，截图却全是桌面，
      整轮报告拿桌面图当应用界面证据。

      判"用户现在看到的是不是被测应用"只能用**窗口焦点**这一个来源；
      它为空就是"不知道"，必须由调用方按不确定处理。
    """
    for args in (("shell", "dumpsys", "window"),
                 ("shell", "dumpsys", "window", "windows")):
        try:
            proc = _adb(serial, *args, timeout=20)
            got = (proc.stdout or b"").decode("utf-8", errors="replace")
        except Exception:
            continue
        if "mCurrentFocus" not in got:
            continue
        for line in got.splitlines():
            if "mCurrentFocus" not in line:
                continue
            if "mCurrentFocus=null" in line.replace(" ", ""):
                return ""
            m = re.search(r"([A-Za-z0-9_.]+)/", line)
            if m:
                return m.group(1)
        return ""
    return ""


def visible_from_focus(focus: str, package: str) -> Optional[bool]:
    """按**窗口焦点字符串**判断用户眼前是不是被测应用。

    True / False；焦点为空（`mCurrentFocus=null`，没有任何窗口拿到输入焦点）
    时返回 None（**不确定**）。调用方不能把 None 当成 True ——
    那正是"桌面截图当应用证据"的来路。

    ★ 单独抽出来是因为 `foreground()` 已经花一次 dumpsys 把焦点读回来了，
      调用方不该为了判可见性再读一次（真机上一次 dumpsys window 要 1~2 秒）。
      判据只有这一份，`app_visible()` 与它共用，避免两处写法漂移。
    """
    pkg = ((focus or "").split("/")[0] or "").strip()
    if not pkg:
        return None
    if is_launcher_pkg(pkg):
        return False
    if not package or pkg == package:
        return True
    # 系统弹窗（权限 / 安装器 / 输入法）会盖在应用上，前台包名变成系统宿主。
    # 这类不算"应用不在前台"，否则正常的权限取证会被整批判掉。
    #
    # ★ 白名单要**窄**（2026-11-10）：早先写成 `com.android.*` / `com.miui.*`
    #   一概放行，那连 `com.android.chrome` 也算"应用可见" —— 外跳到浏览器时
    #   这一屏会被当成应用界面记一笔、还占一张截图配额。
    #   这里改用 `FOREIGN_ALLOWED`（那几家的权限确认框 / 安装器 / 系统对话框），
    #   再用关键片段兜住各厂商五花八门的宿主名。
    for _allow in FOREIGN_ALLOWED:
        if pkg == _allow or pkg.startswith(_allow):
            return True
    _low = pkg.lower()
    if "permission" in _low or "inputmethod" in _low or "keyboard" in _low:
        return True
    return False


def app_visible(serial: str, package: str) -> Optional[bool]:
    """用户眼前是否真的是被测应用（或被它盖在上面的系统弹窗）。

    只认**窗口焦点**（`mCurrentFocus`），不认 `mResumedActivity` ——
    原因见 `window_focus_pkg` 的说明。
    """
    return visible_from_focus(window_focus_pkg(serial), package)


def foreground(serial: str) -> Dict[str, str]:
    """一次读取"前台是什么"，并把**来源**一起返回。

    返回 {"focus": "包名/类名", "pkg": "包名", "via": "window"|"resumed"|""}。

    `via` 必须跟着走，因为两者证明力不同（2026-11-10 健康深圳 / 搜题）：
      · window  —— `mCurrentFocus`，用户眼前真正拿到输入焦点的窗口；
      · resumed —— 只在焦点为空时兜底读 `mResumedActivity`。uni-app 的
        `io.dcloud.PandoraEntry` 可以 resumed 却不画窗口，此时 resumed 说
        "应用在前台"、屏幕上是桌面。所以 `via=resumed` 能用来做**归因**
        （这一屏属于哪个 Activity），但不能用来证明"用户看到了应用"。
    """
    out = {"focus": "", "pkg": "", "via": ""}
    text = ""
    for args in (("shell", "dumpsys", "window"),
                 ("shell", "dumpsys", "window", "windows")):
        try:
            proc = _adb(serial, *args, timeout=20)
            got = (proc.stdout or b"").decode("utf-8", errors="replace")
        except Exception:
            continue
        if "mCurrentFocus" in got:
            text = got
            break
    if text:
        for line in text.splitlines():
            if "mCurrentFocus" not in line:
                continue
            if "mCurrentFocus=null" in line.replace(" ", ""):
                break
            m = re.search(r"([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)", line)
            if m:
                out["focus"] = "%s/%s" % (m.group(1), m.group(2))
                out["pkg"] = m.group(1)
                out["via"] = "window"
                return out
    f = current_focus(serial) or ""
    if f:
        out["focus"] = f
        out["pkg"] = (f.split("/")[0] or "").strip()
        out["via"] = "resumed"
    return out


def focus_key(focus: str) -> str:
    """把「前台页面」标识归一到**全限定类名**，用于可靠比较。

    ★ 同一个界面有两种写法，来自两条采集路径（简小知真机，2026-10-16）：
        · `dumpsys activity activities` 的 mResumedActivity →
          `com.jz.jxz/.ui.web.CommonH5Activity`（包名 + `/` + **相对**类名）
        · `dumpsys window` 的 mCurrentFocus →
          `com.jz.jxz/com.jz.jxz.ui.web.CommonH5Activity`（**全限定**类名）
      直接比字符串会把同一个政策页判成两个页面。后果不是"少记一条日志"级别：
      政策页刚点开时"还在不在原页面"的自检会立刻失败，于是**一次都不滚动**，
      正文采不全；报告里还会写出"政策页已被关闭（前台变为 …CommonH5Activity）"
      这种自相矛盾的句子。
    """
    f = (focus or "").strip()
    if not f:
        return ""
    if " " in f:                    # ActivityRecord{...} 之类的杂交串
        f = f.split()[-1]
    if "/" in f:
        pkg, _, act = f.partition("/")
        act = act.strip()
        if act.startswith("."):
            act = pkg + act
        return act or pkg
    return f


def same_focus(a: str, b: str) -> bool:
    """两个前台标识是否指同一个界面（见 focus_key 的说明）。"""
    ka, kb = focus_key(a), focus_key(b)
    return bool(ka) and ka == kb


def tap_hit_signal(focus_before: str, focus_after: str,
                   fp_before: str, fp_after: str) -> str:
    """综合两个信号判断"这一次点击有没有生效"。

    返回 "focus"（前台 Activity 换了，最可靠）/ "ui"（界面文字变了）/ ""（都没变）。

    顺序是有讲究的：Activity 变化优先。结构树可能在 WebView 页面上完全看不出变化，
    却也可能因为弹窗自己滚动而变化 —— 后者是**假阳性**，
    会把"没点开"误报成"点开了"，进而让报告漏掉「政策链接打不开」这种关键问题。
    """
    if focus_before and focus_after and not same_focus(focus_before, focus_after):
        return "focus"
    if fp_before and fp_after and fp_before != fp_after:
        return "ui"
    return ""


def page_switched(focus_before: str, focus_after: str,
                  fp_before: str, fp_after: str) -> bool:
    """前台页面是否**真的切换**了。

    比 `tap_hit_signal` 严格：只要前后两次都读到了前台页面，就以它为准 ——
    两个都读到且相同，说明还停在同一页，此时界面文字的变化只是同页内滚动/展开，
    不能算"政策页打开了"。这个区别直接决定报告写「未取得条款（点击无效）」
    还是「打开了页面但取不到内容」，错一边就会把关键问题描述错。

    只有当读不到前台页面时（部分机型/权限下 dumpsys 拿不到），才退回用界面文字判断。
    """
    if focus_before and focus_after:
        return not same_focus(focus_before, focus_after)
    return bool(fp_before and fp_after and fp_before != fp_after)


def dump_retry(serial: str, tries: int = 3, wait: float = 0.6) -> Optional[str]:
    """多次重试导出界面；一旦进入降级期就立刻返回 None。

    降级期间还按原样重试的话，等于把熔断的意义抹掉 —— 每次调用照样要
    走满 tries 遍空转，遍历循环仍然被拖死。
    """
    for i in range(max(1, tries)):
        xml = dump(serial)
        if xml:
            return xml
        if dump_health(serial)["degraded"]:
            return None
        if i < tries - 1:
            time.sleep(wait)
    return None


def _collect_text(el, out: List[str], limit: int = 6) -> None:
    """收集 `el` 所有后代的可读文字（按文档顺序，去重，最多 limit 段）。

    ★ 为什么要继承子节点文字（2026-11-10 CNC宝典真机实测）：
      真机上大量可点条目是"空壳容器"——`clickable="true"` 的 LinearLayout，
      自身 `text` 与 `content-desc` 全为空，文字在子 TextView 里。
      实测该 App「数控」页 18 个功能入口**全是**这种形态（连同 id 都没有），
      「我的」页的隐私政策/用户协议/设置也是（只有 `loginPrivacyPolicy`
      这类 id）。于是在调度器眼里，18 个入口同名同形（`cl:LinearLayout`）：
        · 没法判断哪个是「设置 / 关于我们」这类高价值入口 → "优先深入设置"无从执行
        · 报告里只能写"点击 LinearLayout"，复核员看不出点了什么
      继承一层之后 identity 变成「数控基础 / 数控工艺 / 隐私政策」，
      "按价值排序"才有依据。
    """
    for ch in el:
        if ch.tag != "node":
            continue
        t = (ch.get("text") or "").strip()
        if t and t not in out:
            out.append(t)
            if len(out) >= limit:
                return
        _collect_text(ch, out, limit)


def _has_icon(el) -> bool:
    """该节点自身或后代里有没有 ImageView（图标）。

    用来区分「真底栏」和「底部一排等宽文字格子」：两者几何形态几乎一样
    （等宽、无缝、顶满屏宽），但底栏 tab 几乎必带图标。
    """
    if (el.get("class") or "").endswith("ImageView"):
        return True
    for ch in el:
        if ch.tag == "node" and _has_icon(ch):
            return True
    return False


def _iter_nodes(el):
    """按文档顺序递归产出所有 node 元素（保留父子关系，供文字继承用）。"""
    for ch in el:
        if ch.tag != "node":
            continue
        yield ch
        yield from _iter_nodes(ch)


def parse_all(xml: str) -> List[UiNode]:
    """解析全部有意义的节点（不限 clickable）。

    政策链接常常是 TextView + URLSpan（clickable=false），只枚举 clickable
    会漏掉，所以这里返回全量，由调用方按需过滤。
    """
    nodes: List[UiNode] = []
    if not xml:
        return nodes
    try:
        root = ET.fromstring(xml)
    except Exception:
        return nodes
    for n in _iter_nodes(root):
        m = _BOUNDS.search(n.get("bounds") or "")
        if not m:
            continue
        x1, y1, x2, y2 = (int(v) for v in m.groups())
        text = n.get("text") or ""
        cdesc = n.get("content-desc") or ""
        subs: List[str] = []
        _collect_text(n, subs)
        sub_text = " ".join(subs)[:60]
        if (not text and not cdesc and n.get("clickable") != "true"
                and n.get("scrollable") != "true"):
            # 纯容器节点，无信息 —— 但**可滚动的容器必须留下**：
            # RecyclerView / ScrollView 通常既没有文字也不可点击，只带
            # `scrollable="true"`。以前把它一并丢掉，导致「这屏是不是列表」
            # 永远算成 0 行，列表遍历与上拉加载整套逻辑都没了判据
            # （真机表现：一屏列表被当成普通页面，滚一屏就回退）。
            continue
        nodes.append(UiNode(
            text=text,
            cls=n.get("class") or "",
            resource_id=n.get("resource-id") or "",
            bounds=(x1, y1, x2, y2),
            clickable=(n.get("clickable") == "true"),
            scrollable=(n.get("scrollable") == "true"),
            enabled=(n.get("enabled") != "false"),
            package=n.get("package") or "",
            content_desc=cdesc,
            checked=(n.get("checked") == "true"),
            checkable=(n.get("checkable") == "true"),
            sub_text=sub_text,
            has_icon=_has_icon(n),
        ))
    return nodes


def clickable(xml: str, min_size: int = 24) -> List[UiNode]:
    """可点击且尺寸合理的节点（用于常规遍历）。"""
    out: List[UiNode] = []
    for n in parse_all(xml):
        if not n.clickable or not n.enabled:
            continue
        x1, y1, x2, y2 = n.bounds
        if (x2 - x1) < min_size or (y2 - y1) < min_size:
            continue
        out.append(n)
    return out


def occluded_map(xml: str) -> Dict[int, str]:
    """找出"点它其实会落到别人身上"的元素 —— 被同位置的更上层元素盖住了。

    为什么需要（2026-11-01 人工接管实测，川剧迷设置页）：
    「关于」那一行的 bounds 是 [14,2195,1066,2261]，而底部**固定**导航栏
    「图片墙」正好压在 [14,2195,1066,2261] 附近。点「关于」，实际触发的是
    「图片墙」tab —— 于是人/模型以为"我进了关于页"，实际到了完全不同的地方，
    后面每一步的判断都建立在错误前提上。日志里只写"点击了关于"，
    从日志完全看不出这件事。

    判据：`parse_all` 是前序遍历（父在子前、兄弟按文档顺序），
    同一坐标上**最后出现的节点**就是视觉上最上层。若它不是目标本身、
    也不在目标内部，说明目标被它盖住。

    返回 {node_key(node): 遮挡者标签}。

    ★ 键用属性组合而不是 `id()`：每次 `parse_all` 都会新建对象，
      两次解析出来的同一条目 `id()` 并不相同 —— 拿 id 当键会永远查不到。
    """
    nodes = [n for n in parse_all(xml)
             if n.bounds[2] > n.bounds[0] and n.bounds[3] > n.bounds[1]]
    out: Dict[Tuple[Any, ...], str] = {}
    for n in nodes:
        if not n.clickable or not n.enabled:
            continue
        cx, cy = n.center
        nx1, ny1, nx2, ny2 = n.bounds
        top = None
        for m in nodes:
            x1, y1, x2, y2 = m.bounds
            if x1 <= cx <= x2 and y1 <= cy <= y2:
                top = m
        if top is None or top is n:
            continue
        tx1, ty1, tx2, ty2 = top.bounds
        inside = (tx1 >= nx1 and ty1 >= ny1 and tx2 <= nx2 and ty2 <= ny2
                  and top.bounds != n.bounds)
        if inside:
            # 在目标内部的子元素（图标、文字）属正常，不是遮挡。
            continue
        try:
            name = top.label or (top.cls or "").split(".")[-1] or "其它元素"
        except Exception:
            name = "其它元素"
        out[node_key(n)] = name[:24]
    return out


def node_key(n: "UiNode") -> Tuple[Any, ...]:
    """节点的稳定键（跨两次解析也能对上）。给 `occluded_map` 的返回值用。"""
    return (n.resource_id or "", n.text or "", n.content_desc or "", n.bounds)


def screen_texts(xml: str) -> List[str]:
    """界面上所有可见文字（用于界面指纹与报告留证）。"""
    seen: List[str] = []
    for n in parse_all(xml):
        t = n.text.strip()
        if t and t not in seen:
            seen.append(t)
    return seen


def screen_fingerprint(xml: str, activity: str = "") -> str:
    """界面指纹 = Activity + 可见文字集合哈希。

    用于两点：① 判断一次点击是否真的跳转了界面；② 避免在同一界面反复点击
    （早期实现用 seen.clear() 会在无新元素时不停 back，形成死循环）。
    """
    texts = sorted(screen_texts(xml))
    raw = (activity or "") + "|" + "|".join(texts[:120])
    return hashlib.md5(raw.encode("utf-8", errors="replace")).hexdigest()[:12]


def find_by_keywords(nodes: Iterable[UiNode],
                     keywords: Sequence[str]) -> List[UiNode]:
    """按关键词匹配节点，返回按「关键词在表里的顺序」排序的结果。

    越靠前的关键词优先级越高（例如"个人信息保护政策"比"用户协议"更精准）。
    """
    out: List[Tuple[int, UiNode]] = []
    for n in nodes:
        hay = (n.text or "") + " " + (n.content_desc or "")
        for i, kw in enumerate(keywords):
            if kw in hay:
                out.append((i, n))
                break
    out.sort(key=lambda kv: kv[0])
    return [n for _r, n in out]


def find_policy_entries(xml: str) -> List[UiNode]:
    """在界面里找隐私政策入口（文字或 content-desc 命中政策关键词）。"""
    return find_by_keywords(parse_all(xml), POLICY_KEYWORDS)


def find_dialog_nodes(xml: str) -> List[UiNode]:
    """找出属于弹窗的节点（类名含 Dialog/AlertDialog/PopupWindow）。"""
    return [n for n in parse_all(xml)
            if any(h in n.cls for h in DIALOG_CLASS_HINT)]


def find_url_spans(xml: str) -> List[str]:
    """从 content-desc / text 里抽取 URL（部分 App 会把链接暴露在节点属性中）。"""
    urls: List[str] = []
    for n in parse_all(xml):
        for m in re.finditer(r"https?://[^\s\"'<>）)】]+", (n.text or "") + (n.content_desc or "")):
            u = m.group(0).rstrip(".,;")
            if u not in urls:
                urls.append(u)
    return urls


def is_dialog_present(xml: str) -> bool:
    return bool(find_dialog_nodes(xml))


def sort_by_priority(nodes: List[UiNode]) -> List[UiNode]:
    def rank(n: UiNode) -> int:
        for i, kw in enumerate(PRIORITY_KEYWORDS):
            if kw in n.text:
                return i
        return len(PRIORITY_KEYWORDS)
    return sorted(nodes, key=rank)


# ---------------------------------------------------------------- 输入注入

def tap(serial: str, x: int, y: int, root: bool = True) -> bool:
    return _inject(serial, "input tap %d %d" % (x, y), root)


def back(serial: str, root: bool = True) -> bool:
    return _inject(serial, "input keyevent KEYCODE_BACK", root)


def end_call(serial: str, root: bool = True) -> bool:
    """挂断当前通话（KEYCODE_ENDCALL）。

    ★ 为什么需要：遍历里点「客服/联系我们」这类入口，真机上往往是**直接拨号**。
      退回界面不等于挂断，通话会一直在后台占着线路，也可能产生真实外呼。
      外跳判定把它记为"拨号界面"，留证之后调这里挂断。
    """
    return _inject(serial, "input keyevent KEYCODE_ENDCALL", root)


def home(serial: str, root: bool = True) -> bool:
    return _inject(serial, "input keyevent KEYCODE_HOME", root)


def screen_state(serial: str) -> str:
    """屏幕当前状态：Awake / Asleep / Dozing / 空串（取不到）。

    ★ 为什么要把"屏幕睡了"单独辨认出来（2026-11-11 用户报障）
      手机界面全黑时，uiautomator 拿不到任何界面，遍历每轮都在"点不到东西"，
      日志看起来像应用坏了；而真实原因可能只是屏幕睡了（省电策略、
      录屏/投屏类 App 自己关屏）。这两件事的处置完全不同：
        · 屏幕睡了 → 叫醒即可，继续采；
        · 应用黑了 → 应用的问题，该按"界面无法读取"记账。
      取不到状态就返回空串，**不猜 Awake** —— 猜错会让程序对着一块黑屏
      继续点，把整轮预算烧在无意义的动作上。
    """
    try:
        r = _adb(serial, "shell", "dumpsys power", timeout=10)
    except Exception:
        return ""
    txt = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")
    m = re.search(r"mWakefulness=(\w+)", txt)
    return m.group(1) if m else ""


def wake(serial: str, root: bool = True) -> None:
    """点亮屏幕。

    坑：KEYCODE_POWER(26) 是「切换」语义，屏幕已亮时按下去反而会关屏；
    必须用 KEYCODE_WAKEUP(224) 才是「只亮不灭」。
    另：MIUI 等系统会拦截非 root 的输入注入，所以默认走 su。
    """
    _inject(serial, "input keyevent 224", root)


def dismiss_keyguard(serial: str, root: bool = True) -> None:
    """解除无密码锁屏（实际测试中这是最有效的一步）。"""
    try:
        if root:
            _adb(serial, "shell", "su -c 'wm dismiss-keyguard'", timeout=15)
        else:
            _adb(serial, "shell", "wm", "dismiss-keyguard", timeout=15)
    except Exception:
        pass


def menu_unlock(serial: str, root: bool = True) -> None:
    """发送 KEYCODE_MENU，可绕过部分设备的"滑动解锁"（无密码锁屏）。"""
    _inject(serial, "input keyevent 82", root)


def swipe_up(serial: str, root: bool = True) -> None:
    """上滑解锁（无密码锁屏）。"""
    _inject(serial, "input swipe 540 2000 540 500 180", root)


def scroll(serial: str, direction: str = "down", root: bool = True) -> bool:
    """滚动列表。down=内容向上翻（看后面的内容）。"""
    if direction == "down":
        cmd = "input swipe 540 1500 540 700 260"
    else:
        cmd = "input swipe 540 700 540 1500 260"
    return _inject(serial, cmd, root)


def pull_up(serial: str, root: bool = True) -> bool:
    """上拉加载：从底部快速甩到顶部（fling）。

    与 `scroll` 的区别是**幅度与速度**：普通滚动 1500→700 / 260ms，只翻一屏；
    这里 1600→300 / 120ms，是"甩"到底并继续拉。很多列表的"加载下一页"只在
    到达边界后再拉一下时触发（下拉刷新/上拉加载的手势阈值），
    用普通滚动永远碰不到那个阈值 —— 表现就是"滚了十几次还是那批内容"。
    """
    return _inject(serial, "input swipe 540 1600 540 300 120", root)


def swipe_side(serial: str, direction: str = "left", root: bool = True) -> bool:
    """左右滑。

    引导页（ViewPager / 卡片流 / 轮播）在界面结构里**没有任何可点击节点**，
    只能靠左右滑翻页。缺了这一步，遍历器会误判"这页没东西可点"。
    """
    if direction == "left":
        cmd = "input swipe 900 1150 180 1150 240"
    else:
        cmd = "input swipe 180 1150 900 1150 240"
    return _inject(serial, cmd, root)


# ---------------------------------------------------------------- 屏幕状态

def focus_window(serial: str) -> str:
    try:
        r = _adb(serial, "shell", "dumpsys", "window", timeout=20)
        out = (r.stdout or b"").decode("utf-8", errors="replace")
        for line in out.splitlines():
            if "mCurrentFocus" in line:
                return line.strip()
    except Exception:
        pass
    return ""


# 这些包虽不是目标 App，但属于「App 流程的一部分」，可以点（权限框、系统确认框等）
FOREIGN_ALLOWED = (
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
    "com.miui.securitycenter",          # MIUI 的权限/风险确认框
    "com.lbe.security.miui",
    "android",                          # 系统原生对话框
)


def current_package(serial: str) -> str:
    """当前前台窗口所属包名。

    真机教训：UI 遍历若不锁定目标 App，一旦 App 退出/崩溃就会开始在
    **系统桌面**上乱点（实测点了桌面文件夹、天气小组件），既浪费时间又
    产生无意义截图。因此每一步都要先确认前台包名。
    """
    f = focus_window(serial)
    m = re.search(r"u\d+\s+([A-Za-z0-9_.$:]+)/", f)
    if m:
        return m.group(1)
    m = re.search(r"Window\{[^}]*\s([A-Za-z0-9_.$:]+)/", f)
    return m.group(1) if m else ""


def is_foreign_screen(serial: str, package: str) -> bool:
    """前台是否已经不在目标 App（且不是允许的系统弹窗）。"""
    cur = current_package(serial)
    if not cur:
        return False
    if cur == package or cur.startswith(package + ":"):
        return False
    for allow in FOREIGN_ALLOWED:
        if cur == allow or cur.startswith(allow):
            return False
    return True


# ============================================================================
#  系统权限弹窗识别
#
#  为什么要单独识别：Q026「申请权限或收集敏感信息时未同步告知目的」的全部依据
#  都在"弹窗出现前 App 说了什么"与"弹窗本身说了什么"这两处。若不专门抓，
#  权限弹窗只是遍历里的一屏 —— 点了「允许」继续走，什么证据都没留下，
#  报告只能写"未获取到权限场景"。
#
#  判定口径（与 flow/permissions.py 对齐，那边做结论，这里只取事实）：
#    · 系统弹窗文案本身带 App 提供的用途说明 → 已同步告知
#    · 弹窗出现前 App 弹出过说明浮窗/页面          → 已同步告知
#    · 弹窗前的功能界面文字说明了用途              → 已同步告知（弱证据）
#    · 三者都没有                                → 未同步告知
# ============================================================================

PERM_PACKAGES = (
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
    "com.miui.securitycenter",
    "com.lbe.security.miui",
    "com.oppo.safetycenter",
    "com.vivo.permissionmanager",
    "com.huawei.permissionmanager",
    "android",
)

# 权限分组的中文名。系统弹窗里出现的一定是这些词之一（"访问您的…"）。
PERM_LABELS = (
    "位置信息", "位置", "定位信息", "定位", "通讯录", "联系人", "相机",
    "拍摄照片和视频", "照片和视频", "照片", "麦克风", "录音", "存储", "文件",
    "电话", "通话记录", "短信", "日历", "身体传感器", "身体活动", "通知",
    "蓝牙", "附近设备", "媒体",
)

# 系统弹窗按钮的典型写法（各家 ROM 不同，全部见过）
PERM_OPTION_HINTS = (
    "仅在使用该应用时允许", "仅在使用中允许", "仅在使用时允许", "使用应用时允许",
    "仅本次允许", "仅此一次", "始终允许", "每次询问", "询问每次", "不允许", "拒绝",
)

# 「用途说明」的措辞。只认这些**表示目的**的词，不认"为了保障您的账号安全"
# 这种从政策里抄来的套话 —— 套话里也常出现"安全"，但没说明这次要干什么。
PURPOSE_WORDS = ("用于", "以便", "为了", "方便", "目的", "以提供", "以为您",
                 "以向您", "以帮助", "帮助您", "便于")


def _perm_option_labels(nodes: Sequence["UiNode"]) -> List[str]:
    out: List[str] = []
    for n in nodes:
        t = (n.text or n.content_desc or "").strip()
        if not t:
            continue
        if any(h in t for h in PERM_OPTION_HINTS) and len(t) <= 20:
            if t not in out:
                out.append(t)
    return out


def perm_dialog(xml: str, app_pkg: str = "") -> Optional[Dict[str, object]]:
    """判断这一屏是不是系统权限弹窗；是则返回弹窗事实，否则 None。

    只取事实，不下结论：`has_purpose` 仅表示"弹窗文案里出现了表示目的的词"，
    最终判定在 flow/permissions.py，因为还要结合弹窗前的界面上下文。
    """
    if not xml:
        return None
    nodes = parse_all(xml)
    if not nodes:
        return None
    pkgs = {n.package for n in nodes if n.package}
    sys_hit = [p for p in pkgs
               if any(p == x or p.startswith(x + ".") for x in PERM_PACKAGES)]
    texts = [n.text.strip() for n in nodes if (n.text or "").strip()]
    blob = " ".join(texts)
    options = _perm_option_labels(nodes)
    # 双重判据：① 节点包名属于系统权限组件；② 文案是"允许…访问…"且带权限类按钮。
    # 只看文案会把 App 自己的"允许通知"弹窗误判成系统权限框。
    looks = bool(options) and ("访问" in blob or "允许" in blob)
    if not sys_hit and not looks:
        return None
    if not looks and not any(h in blob for h in ("允许", "访问")):
        return None

    perm = ""
    for lab in PERM_LABELS:
        if lab in blob:
            perm = lab
            break
    # 弹窗内是否自带 App 提供的用途说明。
    # 系统模板句是"允许「X」访问您的位置信息吗？"，不含目的词；
    # 若出现"用于/以便/为了…"，说明这段文字是 App 通过 `shouldShowRequestPermissionRationale`
    # 之外的说明或定制 ROM 的用途字段带进来的。
    has_purpose = any(w in blob for w in PURPOSE_WORDS) and len(blob) > 24
    quote = ""
    if has_purpose:
        for w in PURPOSE_WORDS:
            i = blob.find(w)
            if i >= 0:
                quote = blob[max(0, i - 20): i + 60]
                break
    # 该点哪个：优先"仅在使用时允许"（不给后台权限，行为最接近真实用户），
    # 其次"允许"。刻意不点"始终允许" —— 一次性放开后台定位会把后续行为带偏。
    allow = ""
    for want in ("仅在使用该应用时允许", "仅在使用中允许", "仅在使用时允许",
                 "使用应用时允许", "仅本次允许", "允许"):
        for o in options:
            if o == want or (want in o and len(o) <= len(want) + 2):
                allow = o
                break
        if allow:
            break
    return {
        "pkg": (sys_hit[0] if sys_hit else ""),
        "perm": perm,
        "perm_raw": blob[:200],
        "dialog_text": " | ".join(texts)[:600],
        "options": options[:6],
        "allow_label": allow,
        "has_purpose": has_purpose,
        "purpose_quote": quote,
    }


def is_perm_dialog(xml: str) -> bool:
    return perm_dialog(xml) is not None


def input_text(serial: str, text: str, root: bool = True) -> bool:
    """向当前焦点输入框输入文本（adb input text）。

    只支持 ASCII 安全字符；中文/特殊字符会被 `input text` 吞掉（实测），
    所以调用方要么只输入数字，要么先把中文转成剪贴板 —— 这里不做那套，
    只保证"输进去了/没输进去"是明确的。
    """
    s = str(text or "")
    if not s:
        return False
    # 空格在 adb input text 里要写成 %s
    s = s.replace(" ", "%s")
    return _inject(serial, "input text '%s'" % s.replace("'", ""), root=root)


# ============================================================================
#  登录 / 注册界面识别
#
#  很多功能（我的、设置、注销、订单）都在登录态后面。遍历不进登录态，
#  这些页面就永远走不到，报告里只能写"需登录后补测"。
#  这里只负责**认出这是登录页并给出可操作的控件**，具体怎么填由采集侧决定
#  （测试手机号来自检测人员的输入，脚本不编造账号）。
# ============================================================================

LOGIN_WORDS = ("登录", "登陆", "注册")
PHONE_WORDS = ("手机号", "手机号码", "请输入手机", "请输入您的手机", "手机验证码")
# 账号类字样：很多 App 的登录框提示写「用户名/昵称/手机」，一个"手机号"都命中不了，
# 于是整页登录页**从未被识别**（万步健康 2026-11-03：采集侧把它当普通页面点了 275 次，
# 68 分钟只走了 4 个界面）。词表之外补一条只看结构的判据，见 login_screen。
ACCOUNT_WORDS = ("账号", "帐号", "用户名", "昵称", "手机", "邮箱", "密码")
CODE_WORDS = ("获取验证码", "发送验证码", "获取短信验证码", "重新获取", "发送")
SUBMIT_WORDS = ("登录", "立即登录", "注册", "登录/注册", "同意并登录", "确定")
# 「切换到验证码登录」的入口（有的 App 先给一屏登录方式选择）。
# 刻意不含"密码登录"：密码路径要先有账号密码，不在自动登录的能力范围内。
LOGIN_SWITCH_WORDS = ("手机验证码登录", "短信验证码登录", "验证码登录",
                      "手机号验证码登录", "手机登录")
# 「我已阅读并同意《用户协议》」这类勾选框的文字特征
AGREE_WORDS = ("我已阅读并同意", "已阅读并同意", "我已阅读", "阅读并同意",
               "同意用户协议", "同意协议")


def find_agree_target(nodes: Iterable["UiNode"]) -> Optional["UiNode"]:
    """找登录页「我已阅读并同意《…》」的**勾选框**（不是那行文字）。

    ★ 这一条是被春雨诊所逼出来的（2026-11-06 实测结构）：
        该页的勾选框是 `android.widget.CheckBox`，`text=""`；
        它右边紧挨一个 `TextView`，文字是「我已阅读并同意《春雨诊所协议》《隐私政策》」，
        `clickable="false"`。
      也就是说：
        · 认文字 → 只能拿到那个 TextView，点它没有任何反应（它不是链接也不是开关）；
        · 认 CheckBox → 它自己一个字都没有，跟"同意"关联不上。
      表现就是：脚本"点了同意"，界面毫无变化，接着点「获取验证码」只弹一句
      toast「请先阅读并同意协议」，短信一条都没发 —— 而日志与报告都写着"已申请验证码"。

    所以判据要合起来看：**先找有标签的勾选框，再找"文字标签左边那个空勾选框"**。
    几何判据：同一行（纵向重叠）+ 在文字左侧且相距很近（≤120px）。
    """
    nodes = list(nodes)
    if not nodes:
        return None

    def _is_box(n) -> bool:
        return bool(n.checkable or "CheckBox" in (n.cls or "")
                    or "Switch" in (n.cls or ""))

    # ① 勾选框自带「同意」字样（不少 App 把文字写进 CheckBox 的 text）
    for n in nodes:
        lab = (n.text or "") + (n.content_desc or "")
        if lab and _is_box(n) and any(w in lab for w in AGREE_WORDS):
            return n
    # ② 文字标签 + 左边一个空勾选框（春雨诊所就是这一种）
    labels = [n for n in nodes
              if (n.text or "").strip()
              and any(w in (n.text or "") for w in AGREE_WORDS)]
    for lab in labels:
        lx1, ly1, _lx2, ly2 = lab.bounds
        best = None
        best_dx = 10 ** 9
        for n in nodes:
            if n is lab or not _is_box(n):
                continue
            if (n.text or "").strip():
                continue          # 有文字的那个是标签本身，别再拿回来
            x1, y1, x2, y2 = n.bounds
            if min(ly2, y2) - max(ly1, y1) <= 0:
                continue          # 不在同一行
            dx = lx1 - x2         # 勾选框右边缘 → 文字左边缘的距离
            if -10 <= dx <= 120 and dx < best_dx:
                best, best_dx = n, dx
        if best is not None:
            return best
    # ③ 兜底：整屏只有一个勾选框，且它附近有「同意」文字
    boxes = [n for n in nodes if _is_box(n) and not (n.text or "").strip()]
    if len(boxes) == 1 and labels:
        return boxes[0]
    return None


def _squash(text: str) -> str:
    """去掉全部空白字符（含全角空格）。

    ★ 只用于**文字匹配**，不改节点、不改点击坐标。
      很多 App 把按钮文字排成「登  录」「立 即 登 录」做字间距，
      带空格的串一律匹配不上 —— 万步健康 2026-11-03 就因此整页登录页
      没被识别，采集侧拿它当普通页面点了 275 次。
    """
    return re.sub(r"[\s 　]+", "", text or "")


def login_screen(xml: str) -> Optional[Dict[str, object]]:
    """判断这一屏是不是登录/注册页；是则返回输入框与按钮。

    只认"同时出现登录/注册字样 + 手机号输入提示"的界面 ——
    只有"登录"两个字的界面到处都是（我的页面的入口），不能算登录页。
    """
    if not xml:
        return None
    nodes = parse_all(xml)
    if not nodes:
        return None
    texts = [(n.text or "").strip() for n in nodes if (n.text or "").strip()]
    blob = " ".join(texts)
    # ★ 去掉所有空白再匹配（2026-11-03 万步健康）：按钮文字常被排版成「登  录」
    #   （中间两个空格，做字间距），`"登录" in blob` 直接不成立 ——
    #   整页登录页因此从未被识别，采集侧拿它当普通页面点了 275 次。
    #   这里只影响**判定**用的串，不动节点本身（点击仍按原节点）。
    flat = _squash(blob)
    # ★ 政策 / 协议正文不是登录页（2026-11-10 CNC宝典 真机实测）：
    #   设置页的「隐私政策」点进去是政策全文，正文里有
    #   「我们为您提供微信分享、登录、收藏、支付等功能」「收集您的手机号」,
    #   同时命中 LOGIN_WORDS 与 PHONE_WORDS；正文里又常出现"输入"二字，
    #   被下面"自绘输入框"那条兜底当成输入框 —— 于是整屏被判成登录页，
    #   报告写成「入口『隐私政策』…需登录后使用」。这不是事实：
    #   用户看到的是政策全文，与登录无关。
    #   判据：登录页文字量小（标题+提示+几个按钮），政策正文动辄上千字。
    if len(flat) >= 900:
        return None
    if not any(w in flat for w in LOGIN_WORDS):
        return None
    if not any(w in flat for w in PHONE_WORDS):
        # 结构判据：有输入框 + 有「登录/注册」提交按钮 + 提示里有账号类字样。
        # 只认这三条同时成立 —— 单独一条都太松（"我的"页面也有登录按钮，
        # 搜索页也有输入框）。
        _edits0 = [n for n in nodes if "EditText" in (n.cls or "")]
        _submit0 = [n for n in (clickable(xml) or [])
                    if _squash(n.text or "") in SUBMIT_WORDS]
        _acct = any(w in flat for w in ACCOUNT_WORDS)
        if not (_edits0 and _submit0 and _acct):
            return None
    edits = [n for n in nodes if "EditText" in (n.cls or "")]
    # 有的 App 用自绘输入框（class 是 View），退而找"请输入手机号"附近的节点。
    # ★ 但候选必须是**短文本**（2026-11-10 CNC宝典 真机实测）：
    #   原来只要求含"输入"二字，政策正文里「您在使用输入功能时提供的信息」
    #   这种句子就会把整段正文（几百字）认成手机号输入框，
    #   于是整页被判成"可代填的登录页"，报告写成
    #   「入口『隐私政策』…需登录后使用」。输入框提示语不可能长达几十字。
    if not edits:
        edits = [n for n in nodes
                 if "输入" in ((n.text or "") + (n.content_desc or ""))
                 and len((n.text or n.content_desc or "").strip()) <= 24]
    # ★ 没有任何输入控件、文字又是"隐私弹窗告知语"的，不是登录页。
    #   模态弹窗盖住登录页时，`uiautomator dump` 只返回弹窗那一层 ——
    #   万步健康 2026-11-05 就是这样：弹窗里写着「请你务必审慎阅读…」，
    #   因为含"手机"命中了 PHONE_WORDS，于是被当成可代填的登录页，
    #   采集侧对着弹窗点手机号框，55 分钟后只留下"未找到手机号输入框"。
    #   判据只认告知语特征句（不看长度）：登录方式选择页只有几十个字，
    #   按长度判会把"微信登录/验证码登录"那种页误杀。
    if not edits:
        try:
            from .policy import has_notice_phrase
            if has_notice_phrase(blob):
                return None
        except Exception:
            pass
    # ★ 没有输入框、又是一屏长文本的，不是登录页（2026-11-10 CNC宝典 真机实测）。
    #   "登录方式选择页"（微信登录 / 手机验证码登录）也没有输入框，但它只有
    #   几十个字；一屏几百字的只可能是政策、协议、共享清单正文。这类页面
    #   同时含「登录」「手机号」「验证码」（都是条款内容），旧逻辑会把它
    #   整屏判成可代填的登录页，报告写成「入口『隐私政策』…需登录后使用」。
    if not edits and len(flat) >= 240:
        return None
    btns = [n for n in clickable(xml) if (n.text or "").strip()]

    def _find(words):
        for w in words:
            for b in btns:
                _t = _squash(b.text or "")
                if _t == w or w in _t:
                    return b
        return None

    code_btn = _find(CODE_WORDS)
    submit = _find(SUBMIT_WORDS)
    phone_field = edits[0] if edits else None    # ★ 第二个输入框**不一定是验证码框**（2026-11-06 春雨诊所实测）：
    #   它的登录页是「手机号 + 密码」，只有密码框、没有验证码框，也没有
    #   「获取验证码」按钮。旧代码一律把 edits[1] 当验证码框，于是
    #   `_login_assist` 认为"有验证码路径"，在没申请到验证码的情况下
    #   直接点了「登录」（密码是空的），然后把这个失败写成
    #   "已提交，但界面仍停留在登录页（可能校验码错误或被风控）"——
    #   我们根本没提交过验证码。这是假话，必须按框上的提示分开认。
    code_field = None
    pwd_field = None
    pwd_fields = []          # 注册页常有两个密码框（密码 + 确认密码）
    for _n in edits[1:]:
        _lab = _squash((_n.text or "") + (_n.content_desc or ""))
        if "密码" in _lab or "password" in _lab.lower():
            pwd_fields.append(_n)
            if pwd_field is None:
                pwd_field = _n
        elif code_field is None:
            code_field = _n
    if code_field is None and pwd_field is None and len(edits) >= 2:
        # 两个框的提示都读不出来（自绘控件常见）：沿用旧口径，
        # 但后面的判定会因为"没有验证码按钮"而拒绝空提交。
        code_field = edits[1]
    # ---- 登录页的两道前置（不做就无法登录，且不报错）----
    # ① 同意勾选框：多数 App 不勾就点「获取验证码」，只弹一个 toast，
    #    界面毫无变化，采集侧会把它读成"点了没用"。
    # ② 登录方式入口：先给一屏「微信登录 / 手机验证码登录 / 用户名密码登录」，
    #    不点进去连输入框都没有 —— assist 会走"未找到手机号输入框"分支放弃。
    #    真机实测（以观书法 5.4.2）两者都踩，只靠原有逻辑一个字段都填不进去。
    # 已经勾上的不再返回：每轮都点一次会把勾选点掉（真机上就是"越点越勾不上"）
    _agree = find_agree_target(nodes)
    agree_cb = None if (_agree is not None and _agree.checkable
                        and _agree.checked) else _agree
    switch_btn = None
    # ★ 不能只在"这一屏没有输入框"时才找切换入口（2026-11-06 春雨诊所
    #   SignInActivity 实测）：那一屏**同时有**「手机号 / 密码」两个输入框
    #   和一行小字「短信验证码登录」。旧代码把查找关在 `if not edits:` 里，
    #   于是永远看不到那行小字 —— 一个明明支持验证码登录的应用，被我们
    #   判成"只提供账号密码登录"然后放弃。用户看图一眼就指出有那一行，
    #   说明这不是应用缺功能，是判据写窄了。
    for b in btns:
        t = (b.text or "").strip()
        if "密码" in t:
            # 密码登录要先有账号密码；只走验证码这条路
            continue
        if any(w in t for w in LOGIN_SWITCH_WORDS):
            switch_btn = b
            break
    # 再找"文字不可点、监听在父容器上"的那种（以观书法就是这样）
    if switch_btn is None:
        for n in nodes:
            t = (n.text or "").strip()
            if not t or "密码" in t:
                continue
            if not any(w in t for w in LOGIN_SWITCH_WORDS):
                continue
            switch_btn = _clickable_at(nodes, n) or n
            break
    return {
        "blob": blob[:200],
        "phone_field": phone_field,
        "code_field": code_field,
        "pwd_field": pwd_field,
        "pwd_fields": pwd_fields,
        "code_btn": code_btn,
        "submit": submit,
        "has_code": bool(code_btn),
        "title": next((t for t in texts if any(w in t for w in LOGIN_WORDS)), "")[:40],
        "agree_cb": agree_cb,
        "switch_btn": switch_btn,
    }


def register_form(xml: str) -> Optional[Dict[str, object]]:
    """解析「注册」页表单，按每个输入框自己的提示文字定位。

    ★ 为什么不能复用 `login_screen`（2026-11-06 万步健康真机）：
      它的注册页是 6 个输入框 ——
          昵称 3-15个字符 / 手机 / 请输入密码 / 请再次输入密码 / 验证码 / 邀请码(选填)
      而 `login_screen` 把 **edits[0] 当手机号框**、edits[1:] 按"密码"字样分配。
      照它填，手机号会进昵称框、验证码会进手机框 —— 一次注册必然失败，
      而报告会写成"注册页上没识别到验证码入口"，把判据写窄说成应用缺功能。
      同一轮日志里其实已经出现了「改用注册：注册」，前后矛盾，就是这里来的。

    ★ 也不靠"整屏像不像登录页"来判：那一页的提交按钮文字是「完成注册」，
      而 `login_screen` 的 `_submit0` 要求完全等于 SUBMIT_WORDS 里的词
      （"注册"≠"完成注册"）→ 整页被判成"不是登录/注册页"而直接返回 None。

    必要条件（缺一个就返回 None，不猜）：手机框 + 验证码框 + 获取验证码按钮。
    注册页千奇百怪，只走"手机号 + 验证码 + 设密码"这一种；要实名、要证件、
    要邀请码才能注册的，交给调用方如实记"需人工注册"。
    """
    if not xml:
        return None
    nodes = parse_all(xml)
    edits = [n for n in nodes if "EditText" in (n.cls or "")]

    def _hint(n) -> str:
        return _squash((n.text or "") + " " + (n.content_desc or "")).lower()

    out: Dict[str, object] = {
        "phone_field": None, "code_field": None, "code_btn": None,
        "pwd_field": None, "pwd_fields": [], "nick_field": None,
        "submit": None, "agree_cb": None,
    }
    for n in edits:
        h = _hint(n)
        if "邀请码" in (n.text or ""):
            continue                     # 选填项，不碰
        if "验证码" in h and out["code_field"] is None:
            out["code_field"] = n
        elif ("手机" in h or "电话" in h) and out["phone_field"] is None:
            out["phone_field"] = n
        elif ("昵称" in h or "用户名" in h or "账号" in h) and out["nick_field"] is None:
            out["nick_field"] = n
        elif "密码" in h:
            out["pwd_fields"].append(n)
            if out["pwd_field"] is None:
                out["pwd_field"] = n
    # 「获取验证码」是可点文字，不一定是 Button 类
    for b in clickable(xml) or []:
        t = _squash(b.text or "")
        if "验证码" in t and any(k in t for k in ("获取", "发送", "重新")):
            out["code_btn"] = b
            break
    # 提交按钮：「完成注册」「立即注册」「注册」都算；优先 Button 类
    for b in clickable(xml) or []:
        t = _squash(b.text or "")
        if "注册" in t and "登录" not in t and len(t) <= 8:
            if out["submit"] is None or "Button" in (b.cls or ""):
                out["submit"] = b
    _agree = find_agree_target(nodes)
    out["agree_cb"] = None if (_agree is not None and _agree.checkable
                               and _agree.checked) else _agree
    if not (out["phone_field"] and out["code_field"] and out["code_btn"]):
        return None
    return out


def find_register_entry(xml: str) -> Optional["UiNode"]:
    """在登录页上找「注册」入口（去注册一个新账号）。

    为什么需要（2026-11-06）：春雨诊所 / 万步健康的登录页只有
    「手机号 + 密码」，没有验证码登录（万步）、或者验证码入口在更深一屏（春雨）。
    手里只有测试手机号时，注册是唯一能进去的路。

    判据刻意窄：
      · 文字里要有「注册」；
      · 不能同时含「登录」（「登录/注册」是提交按钮，点了等于空提交）；
      · 优先短文字（「注册」「立即注册」「注册账号」），长句子多半是
        协议条款里的"注册"两个字 —— 点它毫无意义。
    """
    if not xml:
        return None
    nodes = parse_all(xml)
    if not nodes:
        return None
    _EXACT = ("注册", "立即注册", "注册账号", "新用户注册", "我要注册", "去注册")
    cands: List["UiNode"] = []
    for n in nodes:
        t = _squash(n.text or "")
        if not t or "注册" not in t:
            continue
        if "登录" in t or "登陆" in t:
            continue
        if len(t) > 12:
            continue
        cands.append(n)
    if not cands:
        return None
    for n in cands:
        if _squash(n.text or "") in _EXACT:
            return _clickable_at(nodes, n) or n
    return _clickable_at(nodes, cands[0]) or cands[0]


def login_screen_weak(xml: str) -> Optional[Dict[str, object]]:
    """登录/注册页的**弱判据**：结构树里没有输入框时用它兜底。

    ★ 为什么需要（2026-11-05 春雨诊所实测）：
      它的登录页是 H5。`login_screen` 要求"有 EditText + 有提交按钮"，
      一个都拿不到 → 整页当普通页面点：点「注册」→「立即注册」→
      「短信验证码登录」→「密码登录」→「忘记密码」，半轮预算烧在这上面，
      而首页就在这页后面。日志里连"登录门"三个字都没出现，因为
      **采集侧只在配了测试手机号时才去识别登录页** —— 没配就等于不认识。

    判据刻意窄（宁可漏判也不要把首页判成登录页）：
      · 出现登录类字样；
      · 且有「验证码」（最强信号），或「密码」+ 至少 3 个账号类词；
      · 且可点元素 ≤ 8（首页/设置页可点元素远多于此）。
    """
    if not xml:
        return None
    try:
        nodes = parse_all(xml)
    except Exception:
        return None
    if not nodes:
        return None
    texts = [(n.text or "").strip() for n in nodes if (n.text or "").strip()]
    if not texts:
        return None
    flat = _squash(" ".join(texts))
    # 长文本页（政策/协议/清单正文）一律不认登录页，理由同 `login_screen`：
    # 正文里的"登录""手机号""验证码"都是条款内容，不是登录动作。
    if len(flat) >= 900:
        return None
    if not any(w in flat for w in LOGIN_WORDS):
        return None
    _hits = sum(1 for w in ("验证码", "密码", "手机号", "注册", "登录", "账号") if w in flat)
    if not ("验证码" in flat or ("密码" in flat and _hits >= 3)):
        return None
    try:
        _cl = clickable(xml)
    except Exception:
        _cl = []
    if len(_cl) > 8:
        return None
    return {
        "blob": " ".join(texts)[:200],
        "title": next((t for t in texts if any(w in t for w in LOGIN_WORDS)), "")[:40],
        "weak": True,
        "phone_field": None, "code_field": None, "code_btn": None,
        "submit": None, "has_code": "验证码" in flat, "agree_cb": None,
        "switch_btn": None,
    }


def _clickable_at(nodes: List["UiNode"], node: "UiNode") -> Optional["UiNode"]:
    """找"覆盖该文字、且可点击"的容器（面积最小的那个）。

    ★ 为什么需要：安卓里"点了有反应"的常常是**父容器**，文字节点自己是
      `clickable="false"`。以观书法 5.4.2 的登录方式入口就是这样 ——
      `手机验证码登录` 是 TextView（不可点），可点的是它的父容器
      `com.ltzk.mbsf:id/login_phone`（没有文字）。
      于是"按文字找可点按钮"永远找不到它，登录辅助只会停在"未找到输入框"。
    点坐标时事件会冒泡到父容器，所以拿到容器按中心点点击就行。
    """
    if node is None:
        return None
    if node.clickable:
        return node
    cx, cy = node.center
    best: Optional[Tuple[int, "UiNode"]] = None
    for n in nodes:
        if not n.clickable or not n.enabled:
            continue
        x1, y1, x2, y2 = n.bounds
        if not (x1 <= cx <= x2 and y1 <= cy <= y2):
            continue
        area = (x2 - x1) * (y2 - y1)
        if best is None or area < best[0]:
            best = (area, n)
    return best[1] if best else None


def login_prepare(serial: str, xml: str, root: bool = True,
                  rounds: int = 2) -> Tuple[str, List[str]]:
    """把登录页推到"能填手机号"的状态：先勾同意框，再切到验证码登录。

    为什么单独抽一个函数：这两步都是"点了界面会变"，变完得重新 dump 才能
    拿到输入框节点。散在调用方里最容易写成"拿着旧 XML 继续找字段"，
    找得到才怪。

    返回 (准备后的 xml, 做过的动作列表)。一个动作都没做就原样返回，
    调用方据此判断"这页本来就准备好了"。
    """
    acts: List[str] = []
    for _ in range(max(1, rounds)):
        info = login_screen(xml)
        if not info:
            break
        acted = False
        cb = info.get("agree_cb")
        if cb is not None:
            tap_node(serial, cb, root=root)
            acts.append("勾选「%s」" % ((cb.text or "同意").strip()[:14]))
            acted = True
            time.sleep(0.6)
        # ★ 判据从"没有输入框"改成"还没有验证码按钮"（2026-11-06 春雨诊所）：
        #   它的登录页有「手机号 / 密码」两个框，**同时**底部有一行小字
        #   「短信验证码登录」。按旧判据（phone_field 为 None）永远不切，
        #   结果拿着手机号去填密码表单 —— 那一步注定走不通。
        if info.get("switch_btn") is not None and info.get("code_btn") is None:
            sb = info["switch_btn"]
            tap_node(serial, sb, root=root)
            # 可点的是父容器，本身没有文字 —— 日志别写成"点「」"
            acts.append("点「%s」进入表单"
                        % ((sb.text or "").strip() or "手机验证码登录"))
            acted = True
            time.sleep(1.2)
        if not acted:
            break
        xml = dump_retry(serial, tries=2, wait=0.8) or xml
    return xml, acts


def tap_node(serial: str, node: "UiNode", root: bool = True) -> bool:
    """点一个节点（取包围盒中心）。"""
    if node is None:
        return False
    x1, y1, x2, y2 = node.bounds
    return tap(serial, (x1 + x2) // 2, (y1 + y2) // 2, root=root)


def match_real_node(nodes: Iterable["UiNode"], target: "UiNode"
                    ) -> Optional["UiNode"]:
    """把「AI 描述出来的目标」对齐回结构树里**真实**的可点节点。

    ★ 为什么必须有这一步：模型给目标时走坐标或文字，本地会先包成一个轻量对象
      （`_node_from_bounds`），它的 `resource_id` 是空的、label 可能是占位的
      "AI 目标"。如果直接拿它算 uid，同一个按钮在「AI 点」与「规则点」两条路上
      会得到**两个身份**：台账记不到一起、`uids_clicked` 也认不出是同一个人，
      于是就出现"同一屏同一个按钮被点 200 多次"（2026-11-01 川剧迷/冰纷万象）。
      对齐之后，两条路共用同一份记账 —— 这才是"AI 与程序化探测协同"的落地点。

    判据按可靠性排序：几何包含（中心落在谁里面，取面积最小的那个）→ 文字全等。
    只认这两个，不做模糊匹配：模糊匹配会把"同意"对到"不同意"上。
    """
    if target is None:
        return None
    try:
        cx, cy = target.center
    except Exception:
        return None
    best: Optional[UiNode] = None
    best_area = 0
    for n in nodes or ():
        try:
            x1, y1, x2, y2 = n.bounds
        except Exception:
            continue
        if x1 <= cx <= x2 and y1 <= cy <= y2:
            area = max(1, (x2 - x1) * (y2 - y1))
            if best is None or area < best_area:
                best, best_area = n, area
    if best is not None:
        return best
    # 几何对不上（AI 给的框偏了）再退回文字：只认完全相同，且同名的取最小框。
    want = ((getattr(target, "text", "") or "").strip()
            or (getattr(target, "content_desc", "") or "").strip())
    if not want:
        return None
    for n in nodes or ():
        lab = ((n.text or "").strip() or (n.content_desc or "").strip())
        if lab and lab == want:
            try:
                x1, y1, x2, y2 = n.bounds
                area = max(1, (x2 - x1) * (y2 - y1))
            except Exception:
                area = 0
            if best is None or (area and area < best_area):
                best, best_area = n, area
    return best



# ============================================================================
#  系统悬浮窗检测 / 清理
#
#  真机教训（重大）：`uiautomator dump` **只导出前台窗口**，系统悬浮窗不在 XML 里，
#  但它会真实拦截触摸。实测 MIUI 屏幕录制控制条正好压住首启弹窗的「同意并继续」，
#  点击落到悬浮条上 → 跳到相册 → 遍历器判定"离开 App" → 重拉 App → 再点 → 死循环
#  （50 秒点了 8 次「同意并继续」，一个真实事件都没采到）。
#
#  判据用 `mAttrs={... ty=<窗口类型>}`：只有 APPLICATION_OVERLAY / SYSTEM_ALERT /
#  PHONE 这一类才能盖在别的 App 上收触摸；STATUS_BAR / NAVIGATION_BAR /
#  BASE_APPLICATION 都不会，因此天然被排除，不会误杀系统 UI 或桌面。
# ============================================================================

# 可以覆盖在其他 App 之上、并能拦截触摸事件的窗口类型
OVERLAY_WINDOW_TYPES = (
    "APPLICATION_OVERLAY",   # 2038，绝大多数第三方悬浮窗/录制条
    "SYSTEM_ALERT",          # 2003
    "SYSTEM_OVERLAY",        # 2006
    "PRIORITY_PHONE",        # 2010
    "PHONE",                 # 2002
    "APPLICATION_PANEL",     # 1000
)

# 这些包即使在上面也绝不能杀（杀桌面会让设备回到主屏；杀 systemui 会掉状态栏）
OVERLAY_SAFE_PKGS = (
    "com.android.systemui",
    "android",
    "com.miui.home",
    "com.android.launcher",
    "com.miui.securitycenter",     # 权限框是我们自己要用的
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.packageinstaller",
)

_WINDOW_HEAD = re.compile(r"^Window #\d+ Window\{[0-9a-f]+ u\d+ ([^}]+)\}:")


def overlay_windows(serial: str, target_pkg: str = "") -> List[Dict[str, str]]:
    """列出当前**可见**的、能拦截触摸的悬浮窗。

    返回 [{pkg, name, ty}]。

    ★ `target_pkg` 是被测应用包名：它自己的窗口一律不算"外部悬浮窗"。
      真机教训（天优家教 2026-11-09）：它的首启隐私弹窗是一个
      `APPLICATION_PANEL` 类型的 PopupWindow，包名就是被测应用自己；
      采集前那一步"清悬浮窗"把它当成遮挡物 `am force-stop` 掉了 ——
      等于在取证之前亲手关掉了唯一的同意界面，之后整轮只能写
      "未观测到政策入口"（而报告读者会以为这个应用根本没弹）。
      任何情况下都不能为了"看清屏幕"去杀掉被测应用。
    """
    try:
        r = _adb(serial, "shell", "dumpsys", "window", "windows", timeout=25)
        out = (r.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return []

    found: List[Dict[str, str]] = []
    cur: Optional[Dict[str, str]] = None
    for line in out.splitlines():
        m = _WINDOW_HEAD.match(line.strip())
        if m:
            if cur:
                found.append(cur)
            name = m.group(1).strip()
            cur = {"name": name, "pkg": "", "ty": "", "visible": "false"}
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("isVisible="):
            cur["visible"] = "true" if "isVisible=true" in s else "false"
        elif s.startswith("mOwnerUid=") and "package=" in s:
            mm = re.search(r"package=(\S+)", s)
            if mm:
                cur["pkg"] = mm.group(1)
        elif s.startswith("mAttrs=") and " ty=" in s:
            mm = re.search(r"\bty=(\w+)", s)
            if mm:
                cur["ty"] = mm.group(1)
    if cur:
        found.append(cur)

    out_list: List[Dict[str, str]] = []
    for w in found:
        if w["visible"] != "true":
            continue
        ty = w["ty"]
        if not ty or not any(t in ty for t in OVERLAY_WINDOW_TYPES):
            continue
        pkg = w["pkg"] or (w["name"].split("/")[0] if "/" in w["name"] else "")
        if not pkg or pkg == "android":
            continue
        if target_pkg and (pkg == target_pkg or pkg.startswith(target_pkg + ".")):
            # 被测应用自己的弹窗/浮层（含首启隐私弹窗）—— 那是要观察的对象，
            # 不是遮挡物。宁可让触摸被吃掉，也不能把取证现场拆了。
            continue
        if any(pkg == p or pkg.startswith(p + ".") for p in OVERLAY_SAFE_PKGS):
            continue
        w["pkg"] = pkg
        out_list.append(w)
    return out_list


def dismiss_overlays(serial: str, log=None, target_pkg: str = "") -> List[str]:
    """强制停止遮挡触摸的悬浮窗（需 root）。

    只处理「可见 + 覆盖型窗口类型 + 非系统关键包 + **不是被测应用自己**」的窗口，
    安全性由 `overlay_windows()` 的判据保证。返回被强制停止的包名列表。

    `target_pkg` 必传：漏传就会把被测应用的首启隐私弹窗当成遮挡物杀掉
    （天优家教 2026-11-09 实测，see `overlay_windows` 的说明）。
    """
    killed: List[str] = []
    for w in overlay_windows(serial, target_pkg=target_pkg):
        pkg = w["pkg"]
        if pkg in killed:
            continue
        try:
            r = _adb(serial, "shell", "su -c 'am force-stop %s'" % pkg, timeout=15)
            blob = (r.stdout or b"") + (r.stderr or b"")
            if b"Exception" in blob or b"Error:" in blob:
                continue
        except Exception:
            continue
        killed.append(pkg)
        if log:
            log("[!] 检测到系统悬浮窗遮挡触摸：%s（%s / ty=%s），已强制关闭"
                % (pkg, w["name"], w["ty"]))
    return killed


def top_activity(serial: str) -> str:
    """当前顶层界面名（用于界面归因）。"""
    try:
        r = _adb(serial, "shell", "dumpsys", "activity", "activities", timeout=20)
        out = (r.stdout or b"").decode("utf-8", errors="replace")
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("mResumedActivity") or s.startswith("mFocusedActivity"):
                m = re.search(r"([\w.$]+/[\w.$]+)", s)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return ""


def is_locked(serial: str) -> bool:
    """判断是否处于锁屏（keyguard 正在显示）。

    精确解析 KeyguardServiceDelegate 段的第一行 showing=，避免被 dumpsys 里
    其他 showing=true 的字段误判（早期版本曾因此误报锁屏，导致跳过 UI 遍历）。
    """
    try:
        r = _adb(serial, "shell", "dumpsys", "window", timeout=25)
        out = (r.stdout or b"").decode("utf-8", errors="replace")
        idx = out.find("KeyguardServiceDelegate")
        if idx >= 0:
            seg = out[idx:idx + 300]
            for line in seg.splitlines()[1:]:
                s = line.strip()
                if s.startswith("showing="):
                    return s.startswith("showing=true")
        f = focus_window(serial)
        return ("NotificationShade" in f) or ("Keyguard" in f)
    except Exception:
        return False


def try_unlock(serial: str, log=None) -> bool:
    """尽力自动解锁（无密码/图案锁屏场景），返回是否已解锁。

    顺序经过真机验证：点亮 → dismiss-keyguard → menu → 上滑。
    其中 dismiss-keyguard 最有效；若设了密码/图案则必然失败，需人工解锁。
    """
    log = log or (lambda *_: None)
    if not is_locked(serial):
        return True
    wake(serial)
    time.sleep(0.8)
    dismiss_keyguard(serial)
    time.sleep(1.0)
    if not is_locked(serial):
        log("[*] 屏幕已点亮并解除锁屏")
        return True
    menu_unlock(serial)
    time.sleep(0.8)
    if not is_locked(serial):
        log("[*] 屏幕已点亮（menu 键解锁）")
        return True
    swipe_up(serial)
    time.sleep(1.0)
    if not is_locked(serial):
        log("[*] 屏幕已点亮（上滑解锁）")
        return True
    log("[!] 设备仍处于锁屏，无法自动解锁（设置了密码/图案时需人工解锁一次）")
    return False


def keep_screen_on(serial: str) -> None:
    """USB 连接时保持屏幕常亮，避免检测中途息屏。"""
    try:
        _adb(serial, "shell", "svc", "power", "stayon", "usb", timeout=10)
    except Exception:
        pass


def screen_size(serial: str) -> Tuple[int, int]:
    try:
        r = _adb(serial, "shell", "wm", "size", timeout=10)
        out = (r.stdout or b"").decode("utf-8", errors="replace")
        m = re.search(r"(\d+)x(\d+)", out)
        if m:
            return int(m.group(1)), int(m.group(2))
    except Exception:
        pass
    return 1080, 1920
