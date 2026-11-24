"""P5 政策对照分析：把「实际收集了什么」和「政策声明了什么」做差集。

这是整个流程里**替代人工工作量最大**的一环，也是唯一一个
「不做 AI 复核就一定会误报」的环节。

为什么必须用 AI 复核：
  差集是字符串匹配算出来的。而隐私政策的写法五花八门 ——
  「设备标识符」「设备识别码」「设备唯一标识」「IMEI/IMSI」指的都是同一件事。
  只用词表做差集，「政策写了『设备识别码』、我记录的是『设备标识符』」
  会被判成"未列明"，这是纯误报，而且量不小。
  所以：机械算差集 → AI 逐条判断是不是同义表述 → 只剩真差集才报。

对应人工的话：「对照隐私政策，看看 app 本身所采集的信息、sdk 所采集的信息，
是否都能在隐私政策或者 SDK 共享清单里面找到，如果找不到，就说明隐私政策内容写的不全」。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

_ROOT = Path(__file__).resolve().parents[2]
SIGNAL_MAP = _ROOT / "analysis" / "signal_map.yaml"

# 政策里必须出现的要素（对应 Q005「未逐一列出目的、方式、范围」）
_REQUIRED_ELEMENTS = {
    "目的": ["目的", "用途", "用于", "为了", "以便"],
    "方式": ["方式", "如何收集", "收集方式", "通过", "技术手段"],
    "范围": ["范围", "种类", "类型", "包括", "清单"],
    "保存期限": ["保存期限", "存储期限", "留存", "保存时间", "保留期限", "存储时间"],
    "第三方共享": ["第三方", "共享", "转让", "委托处理", "SDK", "对外提供"],
    "撤回同意": ["撤回", "撤销同意", "拒绝"],
    "投诉举报": ["投诉", "举报", "反馈"],
    "注销": ["注销", "删除账号", "销户"],
}


def _signal_map(path: Path = SIGNAL_MAP) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def pi_vocab(sm: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return (sm or _signal_map()).get("pi_vocab") or []


def signals(sm: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return (sm or _signal_map()).get("signals") or []


# ---------------------------------------------------------------------------
# ① 行为 → 个人信息类型
# ---------------------------------------------------------------------------

def _api_keys(api: str) -> Set[str]:
    """把一个 api 串拆成可用于匹配的一组键。

    事件里的 api 是简写（SystemProperties.get、Settings.Secure.getString），
    signal_map 里是全称（android.provider.Settings$Secure#getString(...)）。
    两边都取「末段类名 + 方法名」来对齐，忽略包名差异和参数。
    """
    s = (api or "").strip()
    if not s:
        return set()
    s = s.replace("#", ".").replace("$", ".")
    s = re.sub(r"\(.*\)", "", s)
    parts = [p for p in s.split(".") if p]
    if not parts:
        return set()
    method = parts[-1]
    cls = parts[-2] if len(parts) >= 2 else ""
    keys = {method}
    if cls:
        keys.add("%s.%s" % (cls, method))
    return keys


def _is_sink(e: Any) -> bool:
    """这条事件是「数据去向下落」还是「采集动作」。"""
    cat = getattr(e, "category", "") or ""
    if cat.endswith("_sink"):
        return True
    return bool(getattr(e, "sink", "") or "")


def sink_summary(events: Iterable[Any]) -> Dict[str, Any]:
    """单独统计外发：向哪些地址发了多少次，其中多少发生在同意前。

    为什么单独算：外发是第③级证据，它只能佐证「采集到的东西被送出去了」，
    单凭外发不能证明"收集了什么"。但同意前的外发本身值得报疑似 ——
    推送 SDK 建连常常就带着设备标识，只是抓不到明文时不能下定论。
    """
    total = before = 0
    hosts: Dict[str, int] = {}
    before_hosts: Dict[str, int] = {}
    import re as _re
    for e in events:
        if getattr(e, "noise", "") or not _is_sink(e):
            continue
        total += 1
        pre = bool(getattr(e, "before_consent", False))
        if pre:
            before += 1
        blob = "%s %s" % (getattr(e, "args", "") or "", getattr(e, "result", "") or "")
        m = _re.search(r"https?://([^/\s]+)", blob)
        h = m.group(1).lower() if m else ""
        if not h:
            m2 = _re.search(r"host=([^\s,;]+)", blob)
            h = (m2.group(1) or "").lower() if m2 else ""
        if h:
            hosts[h] = hosts.get(h, 0) + 1
            if pre:
                before_hosts[h] = before_hosts.get(h, 0) + 1
    return {
        "total": total,
        "before_consent": before,
        "hosts": dict(sorted(hosts.items(), key=lambda kv: -kv[1])),
        "before_hosts": dict(sorted(before_hosts.items(), key=lambda kv: -kv[1])),
    }


def build_signal_index(sm: Optional[Dict[str, Any]] = None
                       ) -> Dict[str, Dict[str, Any]]:
    """method / cls.method → signal（含 pi 字段的才有意义）。"""
    idx: Dict[str, Dict[str, Any]] = {}
    for sg in signals(sm):
        if not sg.get("pi"):
            continue
        for a in (sg.get("api") or []):
            for k in _api_keys(a):
                # 后出现的覆盖先出现的：同一 method 在多个信号里出现时保留最后一个，
                # 与 signal_map 的书写顺序一致（靠后的通常是更具体的定义）
                idx[k] = sg
    return idx


# 「取到了值」不等于「取到了有效值」。下面这些是 Frida 侧没能把对象展开、
# 或者系统直接给了占位值的情况 —— 计进收集量就是纯误报。
_INVALID_RESULTS = {
    "", "null", "unknown", "unknown]", "(null)", "n/a", "[]", "{}",
    "[object Object]", "[object Array]", "[object]",
    "02:00:00:00:00:00",               # Android 6+ 第三方 app 拿到的假 MAC
    "00000000-0000-0000-0000-000000000000",
}
# 这些 api 拿到的通常是「对象/列表」，采集侧展开不了，
# 光凭调用本身无法证明取到了个人信息 —— 一律不计入收集类型。
_OPAQUE_APIS = {
    "getRunningAppProcesses", "getRunningTasks", "getInstalledPackages",
    "getInstalledApplications", "queryIntentActivities", "getInstallerPackageName",
}


def _valid_value(res: str, api: str = "") -> bool:
    """四级漏斗第②级：这个值是不是真的个人信息。"""
    r = (res or "").strip()
    if not r or r.lower() in _INVALID_RESULTS:
        return False
    # ★ 调用被系统拒绝（2026-11-10，Android 10 起 IMEI/序列号一律抛 SecurityException）：
    #   采集侧现在会把异常也记成事件（"调用了"这一事实是确凿证据），但**没取到值**。
    #   不在这里排除的话，`(java.lang.SecurityException…)` 这种字符串会被当成有效取值，
    #   「尝试读取被拒」就被算成「已收集设备标识」—— 正是最危险的那类误报。
    if r.startswith("调用被拒绝"):
        return False
    if r.startswith("[object") or r.startswith("[java."):
        return False
    tail = (api or "").split(".")[-1]
    if tail in _OPAQUE_APIS:
        return False
    return True


# 同一个 API 因为「取哪个 key」不同，语义完全不同。
# signal_map 只能给一个粗粒度的 pi，这里按实参把结论改准。
# 不然报告会写成「同意前收集了系统设置」——而实际读的是 Android ID，
# 前者听着无害，后者是明确的设备标识符，性质差很远。
_KEY_REFINE = [
    # (api 末段, 实参关键词, 改判为的 pi)
    ("Settings.Secure.getString", ("android_id", "bluetooth_name", "device_name"), "P01"),
    ("Settings.System.getString", ("android_id", "bluetooth_name", "device_name"), "P01"),
    ("SystemProperties.get", ("ro.serialno", "ro.boot.serialno", "gsm.sim", "ro.product.model"), "P01"),
]

# ★ API 语义对 signal 字段的**覆盖**（不要拿它当分类依据做正则大杂烩，
#   只收"语义唯一、写错代价极大"的那几个）。
#
#   为什么需要：事件自带 `signal` 是采集脚本填的，填错时下游一路错到底 ——
#   传感器 hook 曾把 signal 写成 S060（写SDCard → P12 存储文件），
#   于是"注册传感器监听"被当成"收集存储文件"，报告据此出认定项，
#   而下面挂的栈全是 SystemSensorManager.registerListener，描述与证据打架。
#   已修 hook，但**旧存档（--from-result 重渲染）不会重新采集**，
#   所以在判定层再兜一道：api 里带 registerListener 的，一律判 P13 传感器信息。
_API_PI_FORCE: Tuple[Tuple[str, str], ...] = (
    ("registerListener", "P13"),
    ("SystemSensorManager", "P13"),
)

# 这些 API 的返回值只说明"动作成功"，不含个人信息取值本身。
# registerListener 返回 true = 监听注册成功，传感器数据还没来得及产生；
# getDefaultSensor 返回的是传感器元数据描述符，不是用户数据。
# 把它们与 "读到了 IMEI=866…" 同等看待，会让"取证强度"这一栏失真。
_WEAK_ONLY_APIS = {
    "registerListener", "registerListenerImpl", "getDefaultSensor",
}

# 只按末段名字判断不够的地方：`open`、`$init` 这类词太通用，拿末段一比
# 会把 URL.openConnection 之类一起算进来。这几个 API 用全名精确匹配。
#   · Camera#open()        —— 只是把相机打开（多数 App 是扫码/预览），证明不了取到图像
#   · AudioRecord#$init()  —— 构造录音对象，真正采集要等 startRecording()
# 把它们当成"已收集照片/录音"，就是拿准备动作当收集事实（免费投屏神器 2026-10-27）。
_WEAK_FULL_APIS = {
    "android.hardware.Camera#open",
    "android.media.AudioRecord#$init",
}


def _is_weak_api(api: str) -> bool:
    """这条 API 的返回值是不是只代表"动作成功"，而不是"取到了个人信息"。"""
    api = api or ""
    if api.replace("()", "").strip() in _WEAK_FULL_APIS:
        return True
    tail = (api.split(".")[-1] or "").split("#")[-1]
    return tail in _WEAK_ONLY_APIS


def _refine_pi(pi: str, api: str, args: str) -> str:
    # 表里写的是 api 全名（Settings.Secure.getString），
    # 这里必须用 endswith 而不是拿末段去比 —— 末段只是 "getString"，
    # 一比就永远不相等，整张表形同虚设（第一次写就是这么错的）。
    api = api or ""
    low = (args or "").lower()
    for token, forced in _API_PI_FORCE:
        if token in api:
            return forced
    for api_name, keys, new_pi in _KEY_REFINE:
        if not api.endswith(api_name):
            continue
        if any(k.lower() in low for k in keys):
            return new_pi
    return pi


# --------------------------------------------------------------------------
# 具体到「是哪一个标识符」
#
# 只写「收集了设备标识符」是不够的：人工复核员拿到报告，第一件事就是
# 「到底是 IMEI、Android ID 还是 OAID」——这三者在法规上的定性、在政策里
# 该不该列明、能不能被用户重置，都不一样。写不出具体名字，这条证据就没法核。
#
# 判定依据按可靠度排序（2026-10-30 船顺实测后重排）：
#   ① **与测试机真实标识比对**（唯一能把一个值称成某种标识符的硬证据）
#   ② **实参里的 key**（代码里写死的字面量，可靠）
#   ③ **返回值的形态**（15 位数字≈IMEI、16 位十六进制≈Android ID）
#   ④ **hook 点 / 方法名**（最弱，只说明"它想读什么"，不代表读到的就是这个）
#
# ★ 为什么把方法名压到最后（船顺 `2Ees9iP1Vln2NcCzcUVVHg==` 事故）：
#   原表里 `("getdeviceid", "IMEI（…由 getDeviceId 判定）")` 是硬规则，任何
#   包名下只要有个方法叫 getDeviceId 就被写成 IMEI。而百度统计 SDK 的
#   `com.baidu.mobstat.CooperService.getDeviceId` 返回的是它自家的 deviceId
#   （base64 的 16 字节摘要）—— 报告因此把一个 App 私有标识写成了 IMEI。
#   方法名只能说明意图，取值才能说明事实。
# --------------------------------------------------------------------------
_ARG_RULES = [
    # 参数名里出现这些 key，基本可以直接定性（代码自己说了要读什么）
    ("android_id", "Android ID"),
    ("androidid", "Android ID"),
    ("oaid", "OAID（匿名设备标识符）"),
    ("vaid", "VAID（开发者匿名设备标识符）"),
    ("aaid", "AAID（应用匿名设备标识符）"),
    ("gaid", "GAID（广告标识符）"),
    ("adid", "广告标识符（ADID）"),
    ("imei", "IMEI（国际移动设备识别码）"),
    ("imsi", "IMSI（国际移动用户识别码）"),
    ("meid", "MEID（移动设备识别码）"),
    ("iccid", "ICCID（SIM 卡识别码）"),
]

_API_RULES = [
    # 方法名 / hook 点里的关键词（弱证据）
    ("android_id", "Android ID"),
    ("androidid", "Android ID"),
    ("oaid", "OAID（匿名设备标识符）"),
    ("vaid", "VAID（开发者匿名设备标识符）"),
    ("aaid", "AAID（应用匿名设备标识符）"),
    ("gaid", "GAID（广告标识符）"),
    ("adid", "广告标识符（ADID）"),
    ("imei", "IMEI（国际移动设备识别码）"),
    ("imsi", "IMSI（国际移动用户识别码）"),
    ("meid", "MEID（移动设备识别码）"),
    ("iccid", "ICCID（SIM 卡识别码）"),
    ("wlan0", "MAC 地址"),
    ("mac_addr", "MAC 地址"),
    ("macaddr", "MAC 地址"),
    ("getmacaddress", "MAC 地址"),
    ("serial", "硬件序列号"),
    ("bluetooth", "蓝牙地址"),
    ("boot_id", "Boot ID"),
]

# 兼容旧引用（有测试按名取表）；新代码请用上面两张分表。
_SPECIFIC_RULES = _ARG_RULES + _API_RULES

# 「系统设置/系统属性」在词表里的 id。读它是动作不是信息，需改判到具体成员
# 才算收集；改判不了就整体丢弃（见 collected_types）。
_SYS_SETTING_PI = "P15"


# ---------------------------------------------------------------------------
# 危险权限（Android 官方 dangerous 权限，按权限组列全）
#
# ★ 为什么要自己维护一张表（简小知实测）：静态分析返回的 permissions 是
#   **字符串列表**，而报告里按 `p.get("dangerous")` 去取（当成 dict）——
#   条件恒为 False，于是 49 项权限里"危险权限 0 项"这种明显错误就写进了报告。
#   简小知声明了 ACCESS_FINE_LOCATION / RECORD_AUDIO / READ_CONTACTS 等，
#   这些都是明确的危险权限。数错了会直接影响"是否超范围索权"的判断。
# ---------------------------------------------------------------------------
DANGEROUS_PERMS: Dict[str, str] = {
    # 日历
    "READ_CALENDAR": "日历", "WRITE_CALENDAR": "日历",
    # 通话记录
    "READ_CALL_LOG": "通话记录", "WRITE_CALL_LOG": "通话记录",
    "PROCESS_OUTGOING_CALLS": "通话记录",
    # 相机
    "CAMERA": "相机",
    # 联系人
    "READ_CONTACTS": "通讯录", "WRITE_CONTACTS": "通讯录", "GET_ACCOUNTS": "通讯录",
    # 位置
    "ACCESS_FINE_LOCATION": "位置", "ACCESS_COARSE_LOCATION": "位置",
    "ACCESS_BACKGROUND_LOCATION": "位置",
    # 麦克风
    "RECORD_AUDIO": "麦克风",
    # 电话
    "READ_PHONE_STATE": "电话", "READ_PHONE_NUMBERS": "电话", "CALL_PHONE": "电话",
    "ANSWER_PHONE_CALLS": "电话", "READ_PHONE_STATE_IMEI": "电话",
    # 身体传感器
    "BODY_SENSORS": "身体传感器",
    # 短信
    "SEND_SMS": "短信", "RECEIVE_SMS": "短信", "READ_SMS": "短信",
    "RECEIVE_WAP_PUSH": "短信", "RECEIVE_MMS": "短信",
    # 存储
    "READ_EXTERNAL_STORAGE": "存储", "WRITE_EXTERNAL_STORAGE": "存储",
    "MANAGE_EXTERNAL_STORAGE": "存储",
    "READ_MEDIA_IMAGES": "存储", "READ_MEDIA_VIDEO": "存储",
    "READ_MEDIA_AUDIO": "存储", "READ_MEDIA_VISUAL_USER_SELECTED": "存储",
    # 活动识别 / 通知 / 蓝牙 / WiFi
    "ACTIVITY_RECOGNITION": "活动识别",
    "POST_NOTIFICATIONS": "通知",
    "BLUETOOTH_CONNECT": "蓝牙", "BLUETOOTH_SCAN": "蓝牙",
    "BLUETOOTH_ADVERTISE": "蓝牙",
    "NEARBY_WIFI_DEVICES": "附近设备",
    "ACCESS_MEDIA_LOCATION": "媒体位置",
    "UWB_RANGING": "超宽带",
}


def dangerous_permissions(perms: Sequence[Any]) -> List[Dict[str, str]]:
    """挑出危险权限。兼容两种输入：字符串权限名，或带 name/dangerous 的 dict。"""
    out: List[Dict[str, str]] = []
    for p in perms or []:
        if isinstance(p, dict):
            name = str(p.get("name") or "")
            if p.get("dangerous") or _danger_group(name):
                out.append({"name": name, "group": p.get("group") or _danger_group(name)})
            continue
        name = str(p or "")
        g = _danger_group(name)
        if g:
            out.append({"name": name, "group": g})
    return out


def _danger_group(name: str) -> str:
    """权限全名 → 危险权限组名；不是危险权限返回空串。"""
    if not name:
        return ""
    short = name.rsplit(".", 1)[-1]
    return DANGEROUS_PERMS.get(short, "")


# ---------------------------------------------------------------------------
# 「可采集个人信息的权限」—— 用户 2026-11-18 口径
#
# 只算**系统弹窗向用户索要、且该权限对应可采集的个人信息**这几类（定位、
# 存储、相机……）。两条明确的排除：
#   · 「通知」：推送权限不采集任何个人信息（POST_NOTIFICATIONS 在危险权限
#     表里，但不该进这张表）；
#   · 写剪贴板：它不弹窗、也不采集个人信息，用户明确说不算问题。
# 特殊权限（无障碍 / 录屏 / 通知使用权）走的是「设置页开关」而不是权限弹窗，
# 不属于本条口径的范围，由别的检测项负责。
# ---------------------------------------------------------------------------
PII_PERM_GROUPS = frozenset({
    "位置", "存储", "相机", "麦克风", "通讯录", "电话", "通话记录",
    "短信", "日历", "身体传感器", "活动识别", "蓝牙", "附近设备",
    "媒体位置", "超宽带",
})

# 弹窗文字识别出来的组名与 DANGEROUS_PERMS 的组名不是同一套：`uiwalk.PERM_LABELS`
# 直接返回弹窗里命中的那个词（"位置信息""拍摄照片和视频"），所以必须逐个映射，
# 少一个就会整类漏判 —— 这类"看起来在跑、其实一条都没命中"的错最难发现。
_PERM_GROUP_ALIAS = {
    "位置信息": "位置", "定位信息": "位置", "定位": "位置",
    "地理位置": "位置", "位置": "位置",
    "照片": "存储", "照片和视频": "存储", "媒体": "存储",
    "文件": "存储", "存储": "存储",
    "拍摄照片和视频": "相机", "摄像": "相机",
    "录音": "麦克风", "联系人": "通讯录",
    "通话": "电话", "身体活动": "活动识别", "身体": "身体传感器",
}


def norm_perm_group(g: str) -> str:
    """把弹窗识别出的组名归一到 PII_PERM_GROUPS 的键上。"""
    s = (g or "").strip()
    return _PERM_GROUP_ALIAS.get(s, s)


_PERM_NAME_RE = re.compile(r"android\.permission\.[A-Z_]+")


def _perm_names_near(events: Optional[Iterable[Any]], at_ms: Any,
                     tol_ms: int = 3000) -> List[str]:
    """同一时段的 `requestPermissions` 事件里带出的权限全名。

    ★ 为什么需要这层兜底：`perm_scenes` 的权限名是从**弹窗文字**猜出来的
      （"读写设备上的照片及文件"→存储）。部分 ROM 的弹窗只有短文案甚至只有
      图标，读不出组名，这条索权就判不出来 —— 而 hook 侧的事件里 `args`
      带的是完整权限名（`android.permission.ACCESS_FINE_LOCATION|…`）。
      两侧时刻都相对采集开始，按 ±3 秒配对即可，不必求精确相等。
    """
    if not events or at_ms is None:
        return []
    out: List[str] = []
    try:
        at = int(at_ms)
    except Exception:
        return []
    for e in events:
        if getattr(e, "noise", ""):
            continue
        api = (getattr(e, "api", "") or "")
        if "requestPermissions" not in api and getattr(e, "signal", "") != "S069":
            continue
        em = getattr(e, "elapsed_ms", None)
        if em is None or abs(int(em) - at) > tol_ms:
            continue
        for nm in _PERM_NAME_RE.findall(getattr(e, "args", "") or ""):
            if nm not in out:
                out.append(nm)
    return out


def pre_consent_perm_requests(scenes: Iterable[Any],
                              events: Optional[Iterable[Any]] = None
                              ) -> List[Dict[str, Any]]:
    """未同意阶段（phase=P1）向用户索要「可采集个人信息的权限」的系统弹窗。

    ★ 用户 2026-11-18 口径（第 1/3 条）：同意前索要这类权限的行为，并入
      Q003「未经用户同意收集使用个人信息」；只认**系统弹窗**这一种形态。

    为什么要用 `app_before` 而不是现成的 `evidable`：权限弹窗一出现，窗口
    焦点必然离开被测应用，`evidable`（要求应用明确在前台）会把**每一条**都
    判成"不能当证据"。正确的判据是弹窗出现**之前**应用是否在前台 ——
    采集侧为此新增 `app_before`：
      · True  → 索权事实成立；
      · False → 弹窗前应用就不在前台，多半是系统残留，不认；
      · None  → 未确认（旧存档没有这个字段），保留但降级为"证据待补"。
    """
    out: List[Dict[str, Any]] = []
    for s in scenes or []:
        if not isinstance(s, dict):
            continue
        if str(s.get("phase") or "") != "P1":
            continue
        if s.get("app_before") is False:
            continue
        # 旧字段兜底：明确记录了"弹窗时应用不在前台"、又没有 app_before 佐证
        if s.get("app_before") is None and s.get("off_app") is True:
            continue
        g = norm_perm_group(str(s.get("perm") or ""))
        if g not in PII_PERM_GROUPS:
            # 弹窗文字没给出组名：用同时段 hook 事件里的权限全名补
            _gs = []
            for nm in _perm_names_near(events, s.get("at_ms")):
                _g = _danger_group(nm)
                if _g and _g in PII_PERM_GROUPS and _g not in _gs:
                    _gs.append(_g)
            if not _gs:
                continue
            s = dict(s)
            s["perm"] = _gs[0]
            s["perm_source"] = "hook"
        out.append(s)
    return out


# 光看返回值的形态也能定：16 位十六进制几乎只可能是 Android ID。
# 15 位纯数字且能通过 Luhn 校验的是 IMEI（拿不到校验就只按长度判，
# 并在名称后标注"形态推断"，不冒充确证）。
_HEX16 = re.compile(r"^[0-9a-f]{16}$")


# ---------------------------------------------------------------------------
# 同意边界窗口
#
# ★ 为什么必须做（简小知 flow_live2 实测发现的最严重误判）：
#   android_id 的读取时刻是 91755ms，同意事件是 91764ms —— 只早 **9 毫秒**。
#   再看调用栈：AgreementDialog$initView$4.invoke → SplashActivity...onConfirm
#   → initLiveSDK → getAppDeviceNo → getAndroidID，
#   这是**用户点了「同意并继续」之后、在同意回调链里**发生的读取，
#   不是"未征得同意就收集"。可报告当时直接判了"未经用户同意收集使用个人信息"。
#
#   根源是两条上报通道有延迟差：同意事件由脚本侧触发，采集事件由 hook 侧触发，
#   9ms 的差完全淹没在通道抖动里。只看 `before_consent` 布尔位必然误判。
#
#   所以判定要同时看两件事：
#     ① 与同意时刻的距离（差值小于窗口的一律不采信）
#     ② 调用栈是不是同意动作触发的（是则归入"同意后"）
# ---------------------------------------------------------------------------
CONSENT_EDGE_MS = 1500           # 同意时刻前后这个范围内视为时序不可分辨

# 栈里出现这些帧，说明这次调用是由「点击同意」这个动作链触发的
_CONSENT_STACK_HINTS = (
    "onconfirm", "agreementdialog", "agreement_dialog", "privacy_dialog",
    "consentdialog", "useragreement", "onagreed", "agreeclick", "onprivacyagree",
)


def looks_like_consent_action(ev: Any) -> bool:
    """调用栈是否显示这是「点同意」触发的调用链。"""
    frames = " ".join(str(x) for x in (getattr(ev, "stack", None) or [])).lower()
    if not frames:
        return False
    return any(h in frames for h in _CONSENT_STACK_HINTS)


def heal_consent_ms(events: Iterable[Any], consent_ms: Optional[int]) -> Tuple[
        Optional[int], str]:
    """「同意时刻」被污染时的自愈：返回 (修正后的时刻, 说明)。

    ★ 为什么需要（自设捏脸第 4 轮实测）：
      遍历中途 App 进程退出、重新注入时把同意状态带进了新进程，
      而新进程的时钟是从 0 起算的 → 同意时刻被覆盖成第 310 毫秒。
      于是 44 条真实发生在第 172~176 秒的「同意前」事件，
      全部被判成"同意之后"，「未经同意收集」这项直接从可判定退化成"跳过未测"。

      判据：同意时刻是「同意前 / 同意后」的唯一分界，
      因此**不可能**存在"晚于同意时刻的同意前事件"。一旦出现，
      说明这个时间戳不是真值，必须重建，而不是拿它继续下结论。

      重建口径（保守、可审计）：取「第一个发生在同意之后的事件」的时刻作为
      同意时刻的**上界** —— 同意必然发生在它之前。写成上界而不是取中点，
      是因为取任何中间值都是在编一个数。
    """
    if consent_ms is None:
        return None, ""
    evs = list(events or [])
    if not evs:
        return consent_ms, ""
    pre_max = None
    for e in evs:
        if getattr(e, "before_consent", False) and not getattr(e, "noise", ""):
            t = getattr(e, "elapsed_ms", None)
            if isinstance(t, (int, float)) and (pre_max is None or t > pre_max):
                pre_max = int(t)
    if pre_max is None or pre_max <= consent_ms + CONSENT_EDGE_MS:
        return consent_ms, ""
    cand = None
    for e in evs:
        if getattr(e, "before_consent", False):
            continue
        t = getattr(e, "elapsed_ms", None)
        if not isinstance(t, (int, float)):
            continue
        if t > pre_max and (cand is None or int(t) < cand):
            cand = int(t)
    if cand is None:
        return consent_ms, ""
    note = ("同意时刻（%d ms）与事件序列矛盾：存在晚于它的同意前事件（最晚 %d ms）。"
            "判定为进程重启导致时间戳被重置，已按事件序列重建为上界 %d ms"
            "（同意必然早于第一个「同意后」事件）" % (consent_ms, pre_max, cand))
    return cand, note


def classify_consent(ev: Any, consent_ms: Optional[int],
                     window: int = CONSENT_EDGE_MS,
                     consent_absent: bool = False) -> str:
    """把一个事件归入 before / edge / after。

    edge = 时序不可分辨（离同意太近，或明显是同意动作链里的一环）。
    这类事件**不能**用来支撑「未经同意收集」，也不能算作同意后，
    只能如实写"发生在同意动作前后，时序不可分辨"。

    `consent_absent=True` 表示**本轮压根没有同意动作**（1 档「仅同意前」：
    取到政策正文即收工，不点同意）。这时不存在"同意前后"这回事，
    所有读取都发生在未同意状态下 —— 必须归入 before。
    早先这里只看 `consent_ms is None` 就一律判 edge，于是 1 档跑出来写成
    "在同意动作前后 1500 ms 窗口内""同意时刻未记录"，等于说了一个
    根本不存在的窗口（使用者 2026-11-16 指出）。
    """
    if consent_absent:
        return "before"
    if looks_like_consent_action(ev):
        return "edge"
    t = getattr(ev, "elapsed_ms", None)
    if consent_ms is None or t is None:
        # 没有同意时刻就无法判断先后。此时 before_consent 布尔位也不可靠，
        # 一律按 edge 处理，避免用它下"未经同意"的结论。
        return "edge"
    if t > consent_ms:
        return "after"
    if consent_ms - t <= window:
        return "edge"
    return "before"


def split_by_consent(events: Iterable[Any], consent_ms: Optional[int],
                     window: int = CONSENT_EDGE_MS,
                     consent_absent: bool = False
                     ) -> Tuple[List[Any], List[Any], List[Any]]:
    """把事件切成 (确认在同意前, 时序不可分辨, 同意后)。

    `consent_absent=True`（本轮没有同意动作）时全部归入"确认在同意前"。
    """
    b, e, a = [], [], []
    for ev in events:
        k = classify_consent(ev, consent_ms, window, consent_absent)
        (b if k == "before" else e if k == "edge" else a).append(ev)
    return b, e, a


def specific_member(pi: str, api: str = "", args: str = "",
                    result: str = "", hook: str = "",
                    sm: Optional[Dict[str, Any]] = None,
                    device_ids: Optional[Dict[str, Any]] = None) -> str:
    """把「设备标识符」这类类别名，落到「Android ID」这种具体名字。

    拿不到就返回空串 —— 调用方应退回类别名，而不是编一个具体的。

    判定顺序（2026-10-30 重排，见 `_ARG_RULES` 上方注释）：
      ① 与测试机真实标识比对 —— 命中才敢写"就是它"
      ② 实参里写死的 key（`name=android_id`）
      ③ 返回值形态（15 位数字 / 16 位十六进制 / MAC 形式）
      ④ 方法名（只作最后线索，且 getDeviceId 不再等同 IMEI）
    """
    from .. import device_ids as _DI      # 延迟导入：flow ↔ 顶层互不依赖

    # ① 真实值比对：唯一硬证据
    _k, _d = _DI.match(result, device_ids)
    if _k:
        return _d

    # ② 实参里的 key
    blob_args = (args or "").lower()
    if blob_args:
        for kw, name in _ARG_RULES:
            if kw in blob_args:
                return name

    # ③ 返回值形态
    _shape = _DI.shape_guess(result)
    if _shape:
        return _shape
    # 老的形态兜底（无 device_ids 时也要能判 Android ID）：读系统设置拿到
    # 16 位十六进制，实际就是 android_id。不能拿 pi 做前置条件 —— 采集侧把
    # Settings.Secure.getString 统一标成了 P15，pi 是 P15 时形态判定会整条失效。
    r = (result or "").strip()
    low_api = (api or "").lower()
    if _HEX16.match(r.lower()) and ("settings" in low_api or "systemproperties" in low_api):
        return "Android ID（由返回值形态判定：16 位十六进制）"

    # ④ 方法名 / hook 点
    blob_api = " ".join([hook or "", api or ""]).lower()
    for kw, name in _API_RULES:
        if kw in blob_api:
            return name
    # getDeviceId 特判：它只是"取一个本机标识"的方法名，取到的可能是 IMEI、
    # 也可能是 SDK 自家的 deviceId。走到这里说明取值既没匹配上测试机真实标识、
    # 形态也不是 IMEI/MAC/Android ID —— 那就只能说"设备标识"。
    if "deviceid" in blob_api:
        return ("设备标识（TelephonyManager.getDeviceId，未匹配本机 IMEI）"
                if _short_method_is_telephony(api) else
                "设备标识（getDeviceId 返回值，非 IMEI）")
    return ""


def _short_method_is_telephony(api: str) -> bool:
    """这个 getDeviceId 是不是系统电话管理器那个（唯一与 IMEI 有关的那个）。"""
    a = (api or "").lower()
    return "telephony" in a or "iphonesubinfo" in a


# 具体成员 → 它真正所属的个人信息类别。
# 之所以要这一层：采集侧对 Settings.* / SystemProperties.* 统一给了 P15（系统设置），
# 只有当具体成员判出来之后才知道它其实是设备标识符一类。
_MEMBER_PI = {
    "Android ID": "P01", "OAID（匿名设备标识符）": "P01",
    "VAID（开发者匿名设备标识符）": "P01", "AAID（应用匿名设备标识符）": "P01",
    "GAID（广告标识符）": "P01", "广告标识符（ADID）": "P01",
    "IMEI（国际移动设备识别码）": "P01",
    "IMEI（国际移动设备识别码，由 getDeviceId 判定）": "P01",
    "IMSI（国际移动用户识别码）": "P01", "MEID（移动设备识别码）": "P01",
    "ICCID（SIM 卡识别码）": "P01", "MAC 地址": "P01",
    "硬件序列号": "P01", "蓝牙地址": "P01", "Boot ID": "P01",
    "设备标识（DeviceId）": "P01",
    # 2026-10-30 新增的带限定语的名称（判定依据不同，但类别仍是设备标识符）
    "设备标识（": "P01",
    "IMEI（按取值形态判定": "P01",
    "Android ID（按取值形态判定": "P01",
    "Android ID（由返回值形态判定": "P01",
    "MAC 地址（按取值形态判定": "P01",
    "Wi-Fi MAC 地址": "P01", "蓝牙 MAC 地址": "P01",
}


def member_pi(name: str) -> str:
    """具体成员名 → 所属类别 id（判不出返回空串）。"""
    if not name:
        return ""
    for k, v in _MEMBER_PI.items():
        if name.startswith(k):
            return v
    return ""


def collected_facts(collected: Dict[str, Dict[str, Any]],
                    consent_ms: Optional[int] = None) -> List[List[str]]:
    """把「收集了什么」做成人工可逐条核对的事实表。

    每一行都是可以直接拿去设备上验的东西：具体哪个标识符、取到的真实值、
    由哪个接口哪次调用取的、发生在冷启动后第几秒（相对于同意在第几秒）。
    宁可多写几行，也不要让复核的人去猜我到底说的是哪一个值。
    """
    rows: List[List[str]] = []
    for _pid, r in collected.items():
        members = r.get("members") or {}
        if not members:
            # 只有接口调用、没取到取值。事实表里**不再给它编一行"调用点与时刻 —"**：
            # 「—｜—」这种空行读过一遍就知道没信息，反而把表撑得看不出重点。
            # 次数留着（用户要的是"每类各发生多少次"），时间留空由调用方跳过。
            _n = int(r.get("count") or 0)
            rows.append([r["name"],
                         "未取得取值（仅观测到 %d 次接口调用）" % _n if _n
                         else "未取得取值（仅观测到接口调用）",
                         "—", ""])
            continue
        for name, m in list(members.items())[:4]:
            val = m["values"][0] if m.get("values") else "—"
            api = m["apis"][0] if m.get("apis") else "—"
            if m.get("at_ms"):
                _at = m["at_ms"][0]
                # 超过 10 秒就别再用毫秒报时刻：读报告的人对
                # 「冷启动后 267858.0 ms」没有直觉，换算成秒一眼就懂。
                t = ("冷启动后 %.1f 秒" % (_at / 1000.0) if _at >= 10000
                     else "冷启动后 %.1f ms" % _at)
                # ★ 措辞必须跟着时序走：早先说成"同意发生在 X 秒之前"，
                #   结果一条只早 9ms 的读取也被写成"同意之前"，
                #   复核员据此就会当成"未同意就收集"。差多少就写多少。
                if consent_ms:
                    d = (consent_ms - _at) / 1000.0
                    if d > CONSENT_EDGE_MS / 1000.0:
                        t += "（早于同意事件 %.1f 秒）" % d
                    elif d >= 0:
                        t += "（与同意事件仅相差 %.1f 秒，时序不可分辨）" % d
                    else:
                        t += "（晚于同意事件 %.1f 秒）" % (-d)
            else:
                t = "—"
            rows.append([r["name"], name, val, "%s｜%s" % (api, t)])
    return rows


def event_pi(e: Any, idx: Optional[Dict[str, Dict[str, Any]]] = None,
             vocab: Optional[Dict[str, Dict[str, Any]]] = None,
             sm: Optional[Dict[str, Any]] = None,
             device_ids: Optional[Dict[str, Any]] = None,
             require_value: bool = True
             ) -> Tuple[str, str, Optional[Dict[str, Any]]]:
    """单条事件 → (个人信息类型 id, 具体成员名, 命中的 signal)。

    判定口径与 `collected_types()` 完全一致，抽出来是为了让**按 SDK 汇总**和
    **按类型汇总**用的不是两套逻辑 —— 两套逻辑迟早对不上，报告里就会出现
    "总量说收集了 5 类、明细只列出 3 类"这种自相矛盾。

    返回空 pi 表示这条事件不构成"收集"（噪声 / 外发去向 / 没取到有效值 /
    读的是系统配置而非用户信息）。
    """
    if getattr(e, "noise", ""):
        return "", "", None
    if _is_sink(e):
        return "", "", None
    if require_value and not _valid_value(getattr(e, "result", ""),
                                          getattr(e, "api", "")):
        return "", "", None
    sm = sm or _signal_map()
    idx = idx if idx is not None else build_signal_index(sm)
    vocab = vocab if vocab is not None else {v["id"]: v for v in pi_vocab(sm)}
    sg = None
    for k in _api_keys(getattr(e, "api", "")):
        if k in idx:
            sg = idx[k]
            break
    if sg is None:
        sig_id = getattr(e, "signal", "") or ""
        if sig_id:
            for s2 in signals(sm):
                if s2.get("id") == sig_id:
                    sg = s2
                    break
        if sg is None:
            hook = (getattr(e, "hook_id", "") or "").lower()
            if hook:
                for s2 in signals(sm):
                    nm = (s2.get("name") or "").lower()
                    if nm and nm in hook:
                        sg = s2
                        break
    if sg is None:
        return "", "", None
    pid = sg.get("pi")
    if not pid or pid not in vocab:
        return "", "", None
    pid = _refine_pi(pid, getattr(e, "api", ""), getattr(e, "args", ""))
    mem = specific_member(pid, getattr(e, "api", ""), getattr(e, "args", ""),
                          getattr(e, "result", ""), getattr(e, "hook_id", ""), sm,
                          device_ids)
    # 「系统设置」不是一种个人信息：它只是"读了哪儿"。读 android_id 已在上一步
    # 改判成 P01；剩下的（白名单配置、时区、ROM 属性）属环境配置，不计收集。
    if pid == _SYS_SETTING_PI and not mem:
        return "", "", None
    mp = member_pi(mem)
    if mp and mp != pid and mp in vocab:
        pid = mp
    return pid, mem, sg


def collected_types(events: Iterable[Any],
                    sm: Optional[Dict[str, Any]] = None,
                    device_ids: Optional[Dict[str, Any]] = None
                    ) -> Dict[str, Dict[str, Any]]:
    """把采集到的事件汇总成「收集了哪些类型的个人信息」。

    只统计**取到了有效值**的事件 —— 光是 hook 命中不算收集，
    这条是四级证据漏斗的第②级，在这里同样要遵守。

    真机教训（简小知 jxz4）：ActivityManager.getRunningAppProcesses 被判成
    「收集应用信息」进了差集，但看堆栈是 SplashPresenter.getProcessName /
    isMainProcess —— 人家只是在判断当前是不是主进程，而且返回值是未展开的
    [object Object]。没做这层过滤时，政策对照会凭空多出一条"未列明"。
    """
    sm = sm or _signal_map()
    idx = build_signal_index(sm)
    vocab = {v["id"]: v for v in pi_vocab(sm)}
    out: Dict[str, Dict[str, Any]] = {}
    for e in events:
        # 口径统一由 event_pi() 提供（噪声 / 外发去向 / 无效值 / 系统配置已在那里剔除）。
        # 真机教训（简小知 jxz4）：URL.openConnection 这类外发事件被采集侧标成
        # signal=S090（读取WiFi状态，pi=P02），于是 31 次联网全被算成
        # 「收集网络标识与状态」；按证据漏斗，sink 是第③级，不能当"收集了什么"。
        pid, _mem, sg = event_pi(e, idx, vocab, sm, device_ids)
        if not pid:
            continue
        v = vocab[pid]
        rec = out.setdefault(pid, {
            "pi": pid, "name": v["name"], "class": v.get("class", ""),
            "count": 0, "before": 0, "signals": set(), "apis": set(),
            "samples": [], "members": {}, "weak": True,
        })
        rec["count"] += 1
        if not _is_weak_api(getattr(e, "api", "")):
            rec["weak"] = False
        if getattr(e, "before_consent", False):
            rec["before"] += 1
        rec["signals"].add(sg.get("id", ""))
        rec["apis"].add(getattr(e, "api", ""))
        if _mem:
            m = rec["members"].setdefault(
                _mem, {"count": 0, "before": 0, "values": [], "apis": [], "at_ms": []})
            m["count"] += 1
            if getattr(e, "before_consent", False):
                m["before"] += 1
            _val = (getattr(e, "result", "") or "").strip()
            if _val and len(m["values"]) < 3 and _val not in m["values"]:
                m["values"].append(_val)
            # 调用点与发生时点：人工复核要拿着它去日志里逐条对
            _api = "%s(%s)" % (getattr(e, "api", ""),
                               (getattr(e, "args", "") or "").strip())
            if len(m["apis"]) < 3 and _api not in m["apis"]:
                m["apis"].append(_api)
            _ms = getattr(e, "elapsed_ms", None)
            if _ms is not None and len(m["at_ms"]) < 3:
                m["at_ms"].append(int(_ms))
        if len(rec["samples"]) < 3:
            rec["samples"].append({
                "api": getattr(e, "api", ""),
                "args": (getattr(e, "args", "") or "")[:160],
                "result": (getattr(e, "result", "") or "")[:160],
                "before": bool(getattr(e, "before_consent", False)),
                "elapsed": getattr(e, "elapsed_ms", 0),
                "stack": list(getattr(e, "stack", []) or [])[:4],
            })
    for r in out.values():
        r["signals"] = sorted(x for x in r["signals"] if x)
        r["apis"] = sorted(x for x in r["apis"] if x)
        # members 按出现次数降序，描述里先说最主要的那个
        r["members"] = dict(sorted(
            ((k, v) for k, v in r["members"].items()),
            key=lambda kv: -kv[1]["count"]))
    return out


def _attempt_reason(res: str, api: str = "") -> str:
    """为什么这次调用没算成「取到值」。报告里要写人话，不能只写「失败」。"""
    r = (res or "").strip()
    if r.startswith("调用被拒绝"):
        return r[:80]                 # 采集侧已写成「调用被拒绝：<异常名>」
    if not r:
        return "取值为空"
    if r.startswith("[object") or r.startswith("[java."):
        return "返回对象/列表，无法展开为具体取值"
    tail = (api or "").split(".")[-1]
    if tail in _OPAQUE_APIS:
        return "该接口只返回对象/列表，无法展开为具体取值"
    if r.lower() in _INVALID_RESULTS:
        if r == "02:00:00:00:00:00":
            return "系统返回固定假值（Android 6 起不再向应用提供真实 MAC）"
        if r == "00000000-0000-0000-0000-000000000000":
            return "系统返回全零值"
        return "系统返回无效值「%s」" % r[:24]
    return "取值未通过有效性校验"


def attempted_types(events: Iterable[Any],
                    sm: Optional[Dict[str, Any]] = None,
                    device_ids: Optional[Dict[str, Any]] = None
                    ) -> Dict[str, Dict[str, Any]]:
    """尝试获取、但**没有取到有效值**的个人信息类型。

    ★ 用户 2026-11-18 口径（第 4 条）：这类行为要写进报告、明确标注「未成功」、
      但**不算违规**。两头都不能丢：

      · 不写 → 「App 尝试读 IMEI、被系统拒绝」这件事在报告里完全消失，
        复核员会以为它压根没试过；
      · 写成违规 → 那是最典型的假话。Android 10 起读 IMEI 必然抛
        SecurityException，任何 App 都会"失败"，据此定罪等于人人都违规。

    所以它不进 `collected_types`（不进认定），单独成一张表挂到事实里。
    与 `collected_types` 的差异只有一条：不走四级漏斗的第②级（取值有效性），
    专门收被它挡掉的那批；噪声与外发去向仍由 `event_pi` 统一剔除。
    """
    sm = sm or _signal_map()
    idx = build_signal_index(sm)
    vocab = {v["id"]: v for v in pi_vocab(sm)}
    out: Dict[str, Dict[str, Any]] = {}
    for e in events:
        # 取到值的属于"收集"，由 collected_types 负责，这里不重复统计。
        if _valid_value(getattr(e, "result", ""), getattr(e, "api", "")):
            continue
        pid, _mem, _sg = event_pi(e, idx, vocab, sm, device_ids,
                                  require_value=False)
        if not pid:
            continue
        _api = getattr(e, "api", "") or ""
        _why = _attempt_reason(getattr(e, "result", ""), _api)
        # ★ 返回对象/列表**不是**"失败"（2026-11-18 真机数据核对）：那是采集侧
        #   展开不了，App 很可能已经把对象拿到手了。写成"尝试获取未成功"会让
        #   读者以为它没拿到，方向正好相反 —— 实测有 8 份存档因此冒出
        #   153 条"未成功"，其中 115 条是 getSensorList / getRunningAppProcesses。
        #   这类留在「另见接口调用（未取得取值）」里，不冒充尝试失败。
        if "无法展开" in _why:
            continue
        rec = out.setdefault(pid, {
            "pi": pid, "name": vocab[pid]["name"], "count": 0,
            "apis": [], "reasons": [], "at_ms": [], "samples": [],
        })
        rec["count"] += 1
        if _api and _api not in rec["apis"] and len(rec["apis"]) < 4:
            rec["apis"].append(_api)
        if _why not in rec["reasons"] and len(rec["reasons"]) < 3:
            rec["reasons"].append(_why)
        _ms = getattr(e, "elapsed_ms", None)
        if _ms is not None and len(rec["at_ms"]) < 3:
            rec["at_ms"].append(int(_ms))
        if len(rec["samples"]) < 2:
            rec["samples"].append({
                "api": _api,
                "args": (getattr(e, "args", "") or "")[:80],
                "result": (getattr(e, "result", "") or "")[:80],
                "reason": _why,
            })
    return out


def describe_attempted(attempted: Dict[str, Dict[str, Any]],
                       limit: int = 6) -> str:
    """把「尝试获取但未成功」写成一句可直接放进事实表的话。"""
    if not attempted:
        return ""
    bits = []
    for r in sorted(attempted.values(), key=lambda x: -x["count"])[:limit]:
        _why = r["reasons"][0] if r["reasons"] else "未取到有效值"
        bits.append("%s（%d 次，%s）" % (r["name"], r["count"], _why))
    return "、".join(bits)


def describe_collected(collected: Dict[str, Dict[str, Any]],
                       only_with_value: bool = True,
                       with_count: bool = False) -> str:
    """把收集类型写成一句人话，带上具体标识符名字与**取到的取值**。

    「收集了设备标识符」→「收集了设备标识符（Android ID，取值 5a470fba…）」。
    人工复核员拿着这句就能直接去设备/日志上核对，不用再翻原始数据。

    ★ `only_with_value=True`（默认）是 2026-10-27 起的口径，来自用户对西五街
      那轮报告的意见：主句写了「已收集设备标识符、网络标识与状态、剪贴板」，
      但下面给的三个栈是两个 getRunningAppProcesses 加一个 getAndroidId ——
      描述里的三类有兩类根本没有对应证据。凡是拿不出"具体标识符 + 取值"的，
      都不该出现在这句结论里，只能进事实表的"另见接口调用"一行。
    """
    if not collected:
        return ""
    parts = []
    for _pid, r in collected.items():
        members = r.get("members") or {}
        if not members:
            if only_with_value:
                continue
            parts.append(r["name"])
            continue
        items = []
        for name, m in list(members.items())[:3]:
            val = m["values"][0] if m.get("values") else ""
            # 值原样给出（内部底稿，人工要能逐字核对）；过长才截断
            vs = ("，取值 %s" % (val[:40] + "…" if len(val) > 40 else val)) if val else ""
            items.append("%s%s" % (name, vs))
        tail = "；仅见接口调用，未取得取值" if r.get("weak") else ""
        # 用户口径（2026-10-27）：不要笼统的"同意前行为 68 次"，要的是
        # 「每一类采集行为各发生多少次」—— 68 次里可能 60 次是联网、
        # 只有 8 次真读了标识符，混成一个数看不出严重程度。
        cnt = (" %d 次" % int(r.get("count") or 0)) if with_count else ""
        parts.append("%s%s（%s%s）" % (r["name"], cnt, "、".join(items), tail))
    return "、".join(parts)


def describe_calls_only(collected: Dict[str, Dict[str, Any]]) -> str:
    """只写了接口调用、没取到取值的类型 —— 单独一句，进事实表不进主句。"""
    names = []
    for _pid, r in collected.items():
        if r.get("members"):
            continue
        names.append("%s（%d 次）" % (r["name"], int(r.get("count") or 0)))
    return "、".join(names)


def stacks_by_type(collected: Dict[str, Dict[str, Any]],
                   events: Iterable[Any],
                   per_type: int = 1,
                   limit: int = 4,
                   device_ids: Optional[Dict[str, Any]] = None
                   ) -> Tuple[List[List[str]], List[str]]:
    """按「描述里出现的类型顺序」取代表栈 —— 描述说了几类，就要有几类各自的栈。

    为什么不能像原来那样"取前 N 条事件的栈"（西五街 2026-10-26 实测）：
      结论写「已收集设备标识符、网络标识与状态、剪贴板」，
      而按事件顺序取到的三条栈是两个 getRunningAppProcesses 加一个 getAndroidId ——
      "网络标识"和"剪贴板"一条栈都没有，复核员拿到的是一份对不上的证据。
      证据与结论必须同源：主句里每出现一类，下面就一定有一条属于那一类的栈。

    返回 (栈列表, 无栈的类型名列表)。无栈的类型由调用方写进事实表，
    **不允许**它悄悄留在主句里。
    """
    evs = [e for e in (events or []) if not getattr(e, "noise", "")]
    out: List[List[str]] = []
    missing: List[str] = []
    seen: set = set()
    for pid, r in collected.items():
        if not (r.get("members") or {}):
            continue          # 无具体成员的类型本来就不进主句
        got = 0
        for e in evs:
            if got >= per_type or len(out) >= limit:
                break
            epid, _mem, _sg = event_pi(e, device_ids=device_ids)
            if epid != pid:
                continue
            st = list(getattr(e, "stack", []) or [])
            if not st:
                continue
            key = tuple(st[:4])
            if key in seen:
                continue
            seen.add(key)
            out.append(st)
            got += 1
        if not got:
            missing.append(r.get("name") or pid)
    return out, missing


# ---------------------------------------------------------------------------
# ② 政策文本 → 声明的类型
# ---------------------------------------------------------------------------

def declared_types(texts: Sequence[str],
                   sm: Optional[Dict[str, Any]] = None) -> Dict[str, List[str]]:
    """在政策/SDK清单文本里找「声明收集了哪些类型」。

    同时匹配 policy_terms（政策写法）和 members（技术写法）——
    有些政策会直接写技术名（"我们会收集您的 Android ID"）。
    """
    sm = sm or _signal_map()
    blob = "\n".join(t or "" for t in texts)
    if not blob.strip():
        return {}
    low = blob.lower()
    out: Dict[str, List[str]] = {}
    for v in pi_vocab(sm):
        hits = []
        for term in (v.get("policy_terms") or []) + (v.get("members") or []):
            t = (term or "").strip()
            if len(t) < 2:
                continue
            if t.lower() in low:
                hits.append(t)
        if hits:
            out[v["id"]] = sorted(set(hits))
    return out


# ---------------------------------------------------------------------------
# ②' 模型深读政策抽出的声明类型 → pi_vocab id
# ---------------------------------------------------------------------------
# 为什么需要这一层：上面的 declared_types 是纯字符串匹配，而政策的写法
# 千变万化 —— 词表里没有的写法一律算"未声明"，直接变成 Q006 的误报。
# 模型是逐段读过全文的（见 ai/tasks.analyze_policy 的 map-reduce），
# 它给出的类型名是最贴近原文的一份"声明清单"，必须参与差集计算。
#
# 但映射宁可严、不可宽：模型抽类型时极爱写"设备信息""个人信息"这类万能词，
# 一旦映射回 pi_vocab 会同时命中 P01/P03（甚至更多），把整片真差集"声明掉"。
# 差集少报比多报危险得多（多报只是人工多看一眼；少报等于把违规放过去），
# 所以万能词只留给关键词法，**不接受**由模型引入。
_GENERIC_TYPE_WORDS = {
    "设备信息", "个人信息", "信息", "数据", "用户信息", "系统信息",
    "网络信息", "其他信息", "相关信息", "各类信息", "基本信息",
    "设备", "账号", "账户", "资料", "个人资料",
}

_NORM_RE = re.compile(r"[\s\u3000（）()【】\[\]《》〈〉、，,。.;；:：/|｜\\\-_~·\"'“”‘’]")


def _norm_term(s: str) -> str:
    return _NORM_RE.sub("", s or "").lower()


def _ai_type_table(sm: Optional[Dict[str, Any]] = None) -> List[Tuple[str, str]]:
    """(归一化写法, pi_id) 表，涵盖类型名、members、policy_terms。

    长的排在前面：匹配时先拿最能说明问题的词去对（"OAID" 优于"设备"）。
    """
    table: List[Tuple[str, str]] = []
    for v in pi_vocab(sm):
        pid = str(v.get("id") or "")
        if not pid:
            continue
        words = [v.get("name") or ""]
        words += list(v.get("members") or [])
        words += list(v.get("policy_terms") or [])
        for w in words:
            n = _norm_term(str(w))
            if len(n) >= 2:
                table.append((n, pid))
    table.sort(key=lambda x: -len(x[0]))
    return table


def ai_declared_types(ai_policy: Any,
                      sm: Optional[Dict[str, Any]] = None) -> Dict[str, List[str]]:
    """把模型抽出的「声明收集的信息类型」映射成 pi_vocab 的键。

    命中条件（只有两条）：
      · 归一化后与某个写法完全相同（"日历"、"通讯录"这种短词靠这条）；
      · 某个写法（≥3 字）是 AI 类型名的子串 —— "设备唯一硬件编号" ← "设备唯一标识"。
    ★ 反过来（AI 名是某个写法的子串）**不做**：会出硬伤 ——
      "位置信息"是 P11 的 policy_term "图片位置信息"的子串，
      一条普普通通的位置信息声明就会被算成"声明了媒体文件采集"。
    命中值写成 `AI:<原文>`，这样报告里能看出「这一项是模型读出来的」，
    复核员可以回头核对原文，而不是面对一个黑箱结论。
    """
    data = ai_policy if isinstance(ai_policy, dict) else {}
    names = [str(x).strip() for x in (data.get("declared_types") or []) if str(x).strip()]
    if not names:
        return {}
    table = _ai_type_table(sm)
    out: Dict[str, List[str]] = {}
    for raw in names:
        n = _norm_term(raw)
        if not n or n in _GENERIC_TYPE_WORDS:
            continue
        for term, pid in table:
            if term == n:
                hit = True
            elif len(term) >= 3 and term in n:
                hit = True
            else:
                continue
            tag = "AI:%s" % raw[:40]
            bucket = out.setdefault(pid, [])
            if tag not in bucket:
                bucket.append(tag)
    return out


def _ai_policy_text(ai_policy: Any) -> str:
    """把模型抽到的要素原文拼成一段，供「必备要素」检查用。

    用途只有一个：政策里确实写了保存期限/注销途径，但用的是词表没收录的
    说法时，别把它算成"没写"。模型给的是原文摘录，比词表更接近事实。
    """
    data = ai_policy if isinstance(ai_policy, dict) else {}
    if not data:
        return ""

    def _flat(v: Any) -> str:
        if isinstance(v, str):
            return v
        if isinstance(v, dict):
            return " ".join(str(x) for x in v.values())
        if isinstance(v, (list, tuple)):
            return " ".join(_flat(x) for x in v)
        return ""

    fields = ("purposes", "retention", "cross_border", "cancel_account",
              "correct_delete", "complaint", "minor_rules",
              "personalized_ads_off", "third_party_docs")
    return "\n".join(_flat(data.get(f)) for f in fields).strip()


def elements_present(texts: Sequence[str]) -> Dict[str, List[str]]:
    """政策里有没有写「目的/方式/范围/保存期限/…」这些必备要素。"""
    blob = "\n".join(t or "" for t in texts)
    if not blob.strip():
        return {}
    out = {}
    for name, words in _REQUIRED_ELEMENTS.items():
        hit = [w for w in words if w in blob]
        out[name] = hit
    return out


# ---------------------------------------------------------------------------
# ③ 差集
# ---------------------------------------------------------------------------

def pi_gaps(collected: Dict[str, Dict[str, Any]],
            declared: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """收集了但政策没写 = 差集。按敏感程度排序（敏感个人信息优先）。"""
    gaps = []
    for pid, rec in collected.items():
        if pid in declared:
            continue
        gaps.append({
            "pi": pid,
            "name": rec["name"],
            "class": rec.get("class", ""),
            "count": rec["count"],
            "before_consent": rec["before"],
            "apis": rec["apis"],
            "samples": rec["samples"],
            # 证据强度：有具体成员（"Android ID=…"）才算"取到了什么"；
            # 只有接口调用（注册传感器监听这类）只能算线索。
            # Q006「告知与实际不一致」是不是认定，取决于这一栏（2026-10-27 用户意见）。
            "members": rec.get("members") or {},
            "weak": bool(rec.get("weak")),
        })
    gaps.sort(key=lambda g: (0 if "敏感" in (g.get("class") or "") else 1,
                             -g.get("count", 0)))
    return gaps


# 域名主域 → 厂商中文名。政策里通常写「友盟」而不是「umeng.com」，
# 只拿域名去政策里搜必然查不到，会把明明写清楚的 SDK 报成"未列明接收方"。
# 这张表不长，但能挡掉绝大部分这类误报。
HOST_VENDOR = {
    "umeng": "友盟", "jpush": "极光", "jiguang": "极光", "myqcloud": "腾讯云",
    "qcloud": "腾讯云", "tencent": "腾讯", "bugly": "Bugly", "weixin": "微信",
    "wechat": "微信", "alipay": "支付宝", "taobao": "淘宝", "aliyun": "阿里云",
    "baidu": "百度", "sensorsdata": "神策", "talkingdata": "TalkingData",
    "getui": "个推", "igexin": "个推", "xiaomi": "小米", "miui": "小米",
    "huawei": "华为", "hicloud": "华为", "oppo": "OPPO", "vivo": "vivo",
    "meizu": "魅族", "samsung": "三星", "bytedance": "字节", "toutiao": "巨量引擎",
    "pangle": "Pangle", "kuaishou": "快手", "sina": "新浪", "sohu": "搜狐",
    "qiniu": "七牛", "aliyuncs": "阿里云", "xunfei": "讯飞", "iflytek": "讯飞",
    "sentry": "Sentry", "jiagu": "360加固", "qhres": "360", "360": "360",
    "bugly": "腾讯Bugly", "tanx": "阿里妈妈", "mmstat": "阿里", "adsmogo": "芒果",
}


def _host_key(h: str) -> str:
    parts = [p for p in (h or "").split(".") if p]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def classify_hosts(hosts: Sequence[str]) -> Dict[str, List[str]]:
    """把外发域名分成「App 自有」和「第三方」。

    为什么必须分：把自家服务器算成"向第三方提供个人信息"是硬伤级别的误报。
    简小知的例子里 sentry.jianzhikeji.com、api-bda.jianzhikeji.com 都是
    自建服务，一次跑出来 8 个"未声明的第三方"里有一半是它自己。

    判定启发式（三步，按可靠度递减）：
      · 主域出现在已知厂商表（HOST_VENDOR）→ 第三方
      · 同一主域下聚集了 ≥2 个子域，且不是已知厂商 → 判为 App 自有域名族
        （自家服务才会有一堆 xx.company.com；接第三方 SDK 通常只有一两个域名）
      · 主域名与已认定的自有主域有足够长的公共前缀 → 同一家的另一个主域
        ★ 这一条是简小知 flow_live3 补的：一家公司注册了 jianzhikeji.com 和
          jianzhiweike.net 两个主域，前者 3 个子域判了自有，后者只有 1 个，
          于是 api-dsh.jianzhiweike.net（人家自家的接口域名）被当成"未声明的
          第三方"，第 5 项因此凭空冒出一个疑似。两个主域的公共前缀 "jianzhi"
          有 7 个字符，靠这个就能合起来。
          前缀阈值取 6：太短（如 api/data）会把不相干的公司合并，太长会漏。
      · 其余 → 未知，按第三方处理（宁可多报疑似）

    实现顺序很关键（第一版写错过）：必须**先按品牌把主域聚成组**，再看整组的
    子域总数是否 ≥2。早先是"先筛出 ≥2 子域的主域，再拿它去合并别的"——
    于是 jianzhikeji.com（1 个子域）+ jianzhiweike.net（1 个子域）各自都不达标，
    谁也没资格当参照物，两个都留在了第三方里。
    """
    from collections import defaultdict
    by_main: Dict[str, set] = defaultdict(set)
    for h in hosts or []:
        k = _host_key(h)
        if k:
            by_main[k].add(h)
    own, third = [], []
    third_keys = {k for k in by_main if k.lower() in HOST_VENDOR}
    third.extend(sorted(h for k in third_keys for h in by_main[k]))

    # 已知厂商之外的主域，按品牌前缀聚成组
    groups: List[List[str]] = []
    for k in sorted(by_main):
        if k in third_keys:
            continue
        for g in groups:
            if any(_same_brand(k.lower(), m.lower()) for m in g):
                g.append(k)
                break
        else:
            groups.append([k])

    for g in groups:
        subs = set()
        for m in g:
            subs |= by_main[m]
        # 整组子域数 ≥2 → 自家服务域名族；否则宁可算第三方（多报疑似）
        (own if len(subs) >= 2 else third).extend(sorted(subs))
    return {"own": sorted(set(own)), "third": sorted(set(third))}


# 两家公司主域的公共前缀达到这个长度，才认为是同一家注册的多个主域。
# 取 6 是权衡：简小知的 jianzhikeji / jianzhiweike 公共前缀 7；而 "api"/"data"
# 这类通用词只有 3，不会被误合并。
_BRAND_PREFIX_MIN = 6


def _same_brand(a: str, b: str) -> bool:
    """两个主域名是否属于同一家公司（只看公共前缀）。"""
    if not a or not b:
        return False
    if a == b:
        return True
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n >= _BRAND_PREFIX_MIN


# ---- 内容分发 / 静态资源域名 ------------------------------------------------
# 为什么要把它们单独标出来（2026-10-27 金考典）：政策正文解码修好之后，
# Q007 从"1 个 SDK 未列明"翻成了"5 个第三方地址未列明接收方"——而那 5 个
# 分别是 myqcloud / gdtimg / iqiyipic 的图片与静态资源域名。把 CDN 域名
# 算成"未列明的接收方"，复核员一眼就能推翻："那是图片地址，不是接收方"。
# 域名角色区分开之后，结论要么落在真正的接口域名上，要么明确写"只加载了
# 静态资源，是否构成提供个人信息需人工确认"。
_STATIC_SUFFIX = (
    "gdtimg.com", "ugdtimg.com", "gtimg.com", "iqiyipic.com", "iqiyi.com", "myqcloud.com",
    "qpic.cn", "alicdn.com", "byteimg.com", "hdslb.com", "bdimg.com",
    "qhimg.com", "pstatp.com", "kspkg.com", "douyincdn.com", "360buyimg.com",
    "sinaimg.cn", "zimg.cn", "upyun.com",
)
_STATIC_TOKENS = ("cdn", "static", "img", "pic", "image", "assets", "media",
                  "upload", "res")


def host_role(host: str) -> str:
    """把域名粗分成「静态资源/内容分发」与「接口」两类。

    只看域名形态，不看流量内容 —— 我们本来就没抓包，不能声称知道传了什么。
    取不到把握时一律算接口（宁可多报一条，也不把可疑的接口域名洗成 CDN）。
    """
    h = (host or "").lower().strip()
    if not h:
        return "api"
    if any(h == s or h.endswith("." + s) for s in _STATIC_SUFFIX):
        return "static"
    first = h.split(".")[0]
    if any(t in first for t in _STATIC_TOKENS):
        return "static"
    return "api"


def third_party_gaps(hosts: Sequence[str],
                     sdk_texts: Sequence[str]) -> List[Dict[str, Any]]:
    """外发域名里，哪些在 SDK 共享清单 / 政策第三方清单里查不到。

    三级判定，从宽到严：
      ① 域名主域直接出现在政策里 → 已声明
      ② 域名对应一个已知厂商（umeng→友盟），政策里写了厂商中文名 → 已声明
      ③ 都查不到 → 疑似未声明
    """
    blob = ("\n".join(sdk_texts or []))
    low = blob.lower()
    out = []
    for h in hosts:
        if not h:
            continue
        key = _host_key(h)
        if not key:
            continue
        if key.lower() in low:
            continue                                  # ①
        vendor = HOST_VENDOR.get(key.lower(), "")
        if vendor and (vendor.lower() in low or vendor in blob):
            continue                                  # ②
        item = {"host": h, "key": key, "role": host_role(h)}
        if vendor:
            item["vendor"] = vendor
            item["note"] = "疑似对应 %s，政策中未见其名称" % vendor
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# ④ AI 复核差集
# ---------------------------------------------------------------------------

_GAP_SYSTEM = (
    "你是个人信息保护合规检测的分析员。现在要判断：App 实际收集了某类个人信息，"
    "但隐私政策/第三方共享清单里似乎没有列明。请判断每一条是「真未列明」还是「同义表述」。\n"
    "只输出 JSON 数组，每项形如：\n"
    '  {"pi":"P01","verdict":"gap|covered","reason":"…"}\n'
    "verdict=gap 表示确属未列明；covered 表示政策里其实写了，只是用词不同（此时 reason 要给出政策里的原话）。\n"
    "不要输出 JSON 之外的内容。"
)


def ai_review_gaps(gaps: Sequence[Dict[str, Any]],
                   policy_text: str,
                   ai: Any,
                   log: Callable[[str], None] = print) -> List[Dict[str, Any]]:
    """让 AI 逐条复核差集，剔除「同义表述」造成的假差集。

    AI 不可用或返回格式不对时，原样返回 —— 宁可多报疑似，也不静默丢掉线索。
    """
    if not gaps:
        return []
    if ai is None or getattr(ai, "name", "none") == "none":
        log("[P5] 未启用模型，差集不做语义复核（可能存在同义表述造成的误报）")
        for g in gaps:
            g["verdict"] = "gap"
            g["reason"] = "未经模型复核"
        return list(gaps)

    # 政策摘录要按模型的实际上下文预算来给，不能拍一个 12000 字。
    # 小上下文模型（8K）下 12000 字会被静默截尾，模型只看到前三分之一，
    # 却仍然一本正经地给出 covered/gap —— 这种"看得不全但答得很肯定"
    # 正是最该防的。宁可摘录短一些，也别让它读到半截。
    budget = 6000
    try:
        budget = int(ai.input_budget_chars())
    except Exception:
        pass
    lines = []
    for g in gaps:
        lines.append("- %s（%s，%s）：实际调用 %s，共 %d 次%s"
                     % (g["pi"], g["name"], g.get("class", ""),
                        "、".join(g.get("apis", [])[:4]), g.get("count", 0),
                        "，其中 %d 次发生在同意前" % g["before_consent"]
                        if g.get("before_consent") else ""))
    head = ("以下是该 App 实际收集到、但在隐私政策文本里没直接匹配到的个人信息类型：\n")
    tail = "\n\n请逐条判断。"
    fixed = len(head) + len(tail) + len("\n\n隐私政策正文（摘录）：\n") + sum(
        len(x) + 1 for x in lines)
    room = max(800, budget - fixed - 200)
    policy_text = policy_text or ""
    excerpt = policy_text[:room]
    cut = len(excerpt) < len(policy_text)
    prompt = (
        head
        + "\n".join(lines)
        + "\n\n隐私政策正文（摘录%s）：\n" % ("，原文过长只给了前 %d 字" % len(excerpt)
                                            if cut else "")
        + excerpt
        + tail
    )
    try:
        raw = ai.chat([{"role": "user", "content": prompt}], system=_GAP_SYSTEM)
    except Exception as e:
        log("[P5] 模型复核失败（%s），保留原始差集" % e)
        for g in gaps:
            g["verdict"] = "gap"
            g["reason"] = "模型复核失败"
        return list(gaps)

    parsed = _parse_verdicts(raw)
    if parsed is None:
        log("[P5] 模型返回的格式无法解析，保留原始差集")
        for g in gaps:
            g["verdict"] = "gap"
            g["reason"] = "模型返回无法解析"
        return list(gaps)
    for g in gaps:
        v = parsed.get(g["pi"])
        if v:
            g["verdict"] = v.get("verdict", "gap")
            g["reason"] = v.get("reason", "")
        else:
            g["verdict"] = "gap"
            g["reason"] = "模型未覆盖该条"
    return list(gaps)


def _parse_verdicts(raw: str) -> Optional[Dict[str, Dict[str, str]]]:
    import json
    txt = (raw or "").strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```[a-zA-Z]*\s*", "", txt)
        txt = re.sub(r"```\s*$", "", txt)
    i, j = txt.find("["), txt.rfind("]")
    if i < 0 or j <= i:
        return None
    try:
        arr = json.loads(txt[i:j + 1])
    except Exception:
        return None
    out = {}
    for it in arr:
        if isinstance(it, dict) and it.get("pi"):
            out[str(it["pi"])] = {
                "verdict": str(it.get("verdict") or "gap"),
                "reason": str(it.get("reason") or ""),
            }
    return out or None


# ---------------------------------------------------------------------------
# ⑤ 汇总
# ---------------------------------------------------------------------------

def observed_sdk_gaps(observed: Sequence[str],
                      texts: Sequence[str]) -> List[Dict[str, str]]:
    """栈里识别出的第三方 SDK，在政策 / 共享清单文本里找不到对应表述。

    为什么这条比"按域名猜厂商"可靠：`third_party_gaps()` 只能拿到一个域名，
    再拿域名去猜是哪家（umeng.com → 友盟），猜错就整条作废。
    而调用栈里是**真实的 SDK 类名**，配上包名前缀库直接给出 SDK 名称与厂商，
    再回政策里搜这个名字 —— 链条短、可复核。

    ## 匹配为什么分两层

    政策里写 SDK 的方式极不统一：有的写全称"友盟统计分析"，
    有的只写品牌"友盟"，有的写包名"umeng"，有的只在共享清单列一行。
    只拿全名去搜（第一版做法）实测把这份政策里明明写了的 15 个 SDK
    全报成"未列明" —— 高召回瞬间变成全量误报，复核员会直接不信这一栏。

    所以：
      · 强命中：完整名 / 厂商全名 / 包名根，出现在正文任意位置；
      · 弱命中：品牌词（"友盟"、"阿里云"）出现的**那一句**里同时有
        SDK / 第三方 / 共享 / 委托 / 接收方 这类词 —— 说明它是在讲 SDK 清单，
        而不是在说"本 App 的服务器"或"小米手机"。
    两级都不中，才算未列明。
    """
    blob = "\n".join(t for t in (texts or []) if t)
    low = blob.lower()
    sents = _sentences(blob)
    out: List[Dict[str, str]] = []
    for raw in observed or ():
        name, vendor, prefix = _split_sdk_spec(raw)
        strong = _sdk_match_keys(name, vendor, prefix)
        brand = _sdk_brand(name, vendor)
        if (strong and any(_hit(k, blob, low) for k in strong)) or \
                (brand and _brand_in_sdk_sentence(brand, sents, low)):
            continue
        out.append({"name": name or prefix, "vendor": vendor, "prefix": prefix,
                    # 展示用短名（库里的写法常带 `@厂商` 后缀，报告里不必重复）
                    "display": (name or prefix).split("@")[0].strip() or (name or prefix),
                    "keys": "、".join(sorted(strong | ({brand} if brand else set()))[:5])})
    return out


# 政策里"这一句在讲 SDK/第三方"的信号词。弱命中必须落在这类句子里，
# 否则"小米手机"这种和硬件厂商同名的品牌词会被当成"已声明小米推送"。
_SDK_SENTENCE_WORDS = ("SDK", "sdk", "第三方", "共享", "委托", "接收方",
                       "合作方", "提供商", "服务商", "对外提供", "转让")

_SENT_SPLIT = re.compile(r"(?<=[。！？；\n])")


def _sentences(blob: str) -> List[str]:
    return [s for s in _SENT_SPLIT.split(blob or "") if s.strip()]


def _brand_in_sdk_sentence(brand: str, sents: Sequence[str], low: str) -> bool:
    b = brand.lower() if brand.isascii() else brand
    for s in sents:
        hay = s.lower() if brand.isascii() else s
        if b in hay and any(w in s for w in _SDK_SENTENCE_WORDS):
            return True
    return False


def _split_sdk_spec(spec: str) -> Tuple[str, str, str]:
    """把 attribution 给出的 SDK 标识拆成 (名称, 厂商, 包前缀)。

    支持两种输入：`名称` 或 `名称|厂商|包前缀`（后者由调用方显式传）。
    """
    s = str(spec or "").strip()
    if "|" in s:
        parts = (s.split("|") + ["", ""])[:3]
        return parts[0].strip(), parts[1].strip(), parts[2].strip()
    return s, "", ""


_GENERIC_BRAND_WORDS = ("系统", "服务", "移动", "数据", "信息", "智能", "网络",
                        "科技", "技术", "中国", "北京", "上海", "深圳", "平台",
                        "第三方", "未知", "公司", "有限")


def _sdk_brand(name: str, vendor: str) -> str:
    """取 SDK 的品牌词（政策里最可能出现的那个短名）。

    `友盟+移动统计SDK@友盟同欣` → `友盟`；`阿里云移动推送（淘宝通道服务）` → `阿里云`；
    `vivo推送SDK` → `vivo`。取不到就返回空（不做弱匹配）。
    """
    for raw in (name, vendor):
        s = re.sub(r"[（(][^）)]*[）)]", "", str(raw or ""))
        s = s.split("@")[0]
        # 不能用 \bsdk\b：中文与拉丁字母之间没有词边界，
        # "vivo推送SDK" 里的 SDK 去不掉，品牌词就成了 "vivo推送SDK"。
        s = re.sub(r"(?i)sdk", "", s)
        s = re.split(r"[+\-_/\s、·]", s)[0]
        for _ in range(3):
            s2 = re.sub(r"(移动统计|统计分析|移动推送|统计分析SDK|推送服务|开放平台|"
                        r"推送|分享|广告|统计|分析|服务|移动)$", "", s)
            if s2 == s:
                break
            s = s2
        s = s.strip()
        if 2 <= len(s) <= 10 and s not in _GENERIC_BRAND_WORDS:
            return s
    return ""


def _sdk_match_keys(name: str, vendor: str, prefix: str) -> set:
    """强命中键：完整名、厂商全名、包名根。

    不做"去掉通用后缀再拼"的处理 —— 第一版那样做把
    "友盟统计分析" 变成 "友盟分析"，政策里永远搜不到，整批 SDK 全成了未列明。
    """
    keys = set()
    for raw in (name, vendor):
        s = re.sub(r"[（(][^）)]*[）)]", "", str(raw or "")).split("@")[0].strip()
        if len(s) >= 2 and s not in _GENERIC_BRAND_WORDS:
            keys.add(s)
    # 包名根：com.umeng.xxx → umeng；cn.jpush.android → jpush
    for p in (prefix or "").split("."):
        if len(p) >= 4 and p.lower() not in ("com", "cn", "org", "net", "www", "android"):
            keys.add(p)
    return keys


def _hit(key: str, blob: str, low: str) -> bool:
    if not key:
        return False
    if key.isascii():
        return key.lower() in low
    return key in blob


def analyze(events: Sequence[Any],
            policy_texts: Sequence[str],
            sdk_texts: Sequence[str],
            hosts: Sequence[str],
            ai: Any = None,
            log: Callable[[str], None] = print,
            ai_policy: Any = None,
            observed_sdks: Sequence[str] = (),
            device_ids: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """P5 一站式入口，返回给报告用的对照结果。

    `ai_policy` 是 P2 阶段模型深读政策的结果（见 `ai_declared_types`）。
    它只做**加法**：把模型读出来、关键词没配上的声明类型并进 `declared`。
    不做减法 —— 模型说"政策没写"不构成未声明的证据（它可能只是没读到），
    差额依然由 `ai_review_gaps()` 逐条复核来处置。
    """
    sm = _signal_map()
    collected = collected_types(events, sm, device_ids)
    kw_declared = declared_types(list(policy_texts) + list(sdk_texts), sm)
    declared = {k: list(v) for k, v in kw_declared.items()}
    ai_add = ai_declared_types(ai_policy, sm)
    ai_extra: List[str] = []
    for pid, tags in ai_add.items():
        if pid in declared:
            declared[pid].extend(t for t in tags if t not in declared[pid])
        else:
            declared[pid] = list(tags)
            ai_extra.append(pid)
    if ai_extra:
        log("[P5] 模型深读政策补充了 %d 项关键词未命中的声明类型：%s"
            % (len(ai_extra),
               "、".join("%s(%s)" % (pid, declared[pid][0].replace("AI:", "", 1))
                         for pid in ai_extra[:12])))

    gaps = pi_gaps(collected, declared)
    gaps = ai_review_gaps(gaps, "\n".join(policy_texts or [])[:20000], ai, log)
    real_gaps = [g for g in gaps if g.get("verdict") != "covered"]
    # 关键词口径的差集留一份：并集让某条差集"消失"时，日志里必须看得到
    # 是哪一条、因为模型读出了哪句话而消失 —— 否则无从核查模型有没有放水。
    kw_gap_ids = {g["pi"] for g in pi_gaps(collected, kw_declared)}
    absorbed = sorted(kw_gap_ids - {g["pi"] for g in gaps})
    if absorbed:
        log("[P5] 其中 %d 项差集因模型读出了对应声明而不再计入：%s"
            % (len(absorbed), "、".join(absorbed[:12])))
    hcls = classify_hosts(hosts)
    tp = third_party_gaps(hcls["third"], list(sdk_texts) + list(policy_texts))
    # 第二路证据：栈里识别出的 SDK 名 / 厂商 / 包名根去政策与共享清单里搜。
    # 与按域名猜厂商是**互补**关系 —— 域名能抓到没有栈的外发，栈能抓到
    # 域名猜不出的 SDK（自建域名上报的 SDK 用前者必漏）。
    sdk_gaps = observed_sdk_gaps(observed_sdks, list(policy_texts) + list(sdk_texts))
    if observed_sdks:
        log("[P5] 调用栈中识别出第三方 SDK %d 个（%s），政策/清单未检索到 %d 个"
            % (len(observed_sdks), "、".join(list(observed_sdks)[:6]), len(sdk_gaps)))
    ai_text = _ai_policy_text(ai_policy)
    elems = elements_present(list(policy_texts) + ([ai_text] if ai_text else []))
    missing_elems = [k for k, v in elems.items() if not v]
    return {
        "hosts_own": hcls["own"],
        "hosts_third": hcls["third"],
        "collected": {k: {kk: vv for kk, vv in v.items() if kk != "samples"}
                      for k, v in collected.items()},
        "collected_detail": collected,
        "declared": declared,
        "declared_ai_extra": ai_extra,
        "gaps": gaps,
        "real_gaps": real_gaps,
        "third_party_gaps": tp,
        "observed_sdks": list(observed_sdks or ()),
        "sdk_gaps": sdk_gaps,
        "elements": elems,
        "missing_elements": missing_elems,
        "stats": {
            "collected_types": len(collected),
            "declared_types": len(declared),
            "declared_types_kw": len(kw_declared),
            "declared_ai_extra": len(ai_extra),
            "gap_raw": len(gaps),
            "gap_real": len(real_gaps),
            "gap_absorbed_by_ai": len(absorbed),
            "third_party_gap": len(tp),
            "observed_sdk": len(observed_sdks or ()),
            "sdk_gap": len(sdk_gaps),
        },
    }


__all__ = ["analyze", "collected_types", "declared_types", "pi_gaps",
           "third_party_gaps", "elements_present", "ai_review_gaps",
           "ai_declared_types", "observed_sdk_gaps", "pi_vocab", "signals",
           "build_signal_index", "event_pi", "specific_member", "member_pi"]
