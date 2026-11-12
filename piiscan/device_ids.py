"""测试机真实标识采集：为「这次读到的到底是什么标识符」提供唯一可信的标尺。

★ 为什么要有这个模块（船顺 2026-10-30 实测）
--------------------------------------------
报告写着「App 已收集设备标识符 1 次（IMEI（国际移动设备识别码，由 getDeviceId
判定），取值 2Ees9iP1Vln2NcCzcUVVHg==）」—— 那串东西是 base64 编码的 16 字节
摘要，既不是 15 位数字，也不等于测试机的 IMEI。真实情况是百度统计 SDK 的
`com.baidu.mobstat.CooperService.getDeviceId`，它返回的是自家的 deviceId。

误判来自两处叠加：
  ① `_SPECIFIC_RULES` 里把子串 "getdeviceid" 直接当成 IMEI —— 任何包名下的
     方法只要叫 getDeviceId 都被算成 IMEI；
  ② 没有任何"这个值到底是什么"的客观标尺可对。

所以判定顺序必须改成：**先拿真实值比对，再看取值形态，最后才参考方法名**。
本模块负责第一步的标尺：开测前把测试机的 IMEI / MEID / Android ID / 序列号 /
MAC 等真实值取下来，随采集结果一起落盘，供报告层比对。

★ 取不到的（OAID / VAID / AAID / GAID）不编造：
  这些标识符由 App 侧通过 MSA/Google Play 服务申请，adb 拿不到；
  本模块只记「不可用」及原因，绝不填一个"大概是"的值。
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

# 键 → 中文名（报告里直接显示）
IDENTITY_LABELS: Dict[str, str] = {
    "imei": "IMEI（国际移动设备识别码）",
    "meid": "MEID（移动设备识别码）",
    "android_id": "Android ID",
    "serialno": "硬件序列号",
    "wifi_mac": "Wi-Fi MAC 地址",
    "bt_mac": "蓝牙 MAC 地址",
    "imsi": "IMSI（国际移动用户识别码）",
    "iccid": "ICCID（SIM 卡识别码）",
}

# 取值形态：只用来"在没有任何真实值可对时"给出保守推断，不冒充确证
_RE_IMEI = re.compile(r"^\d{15}$")
_RE_MEID14 = re.compile(r"^[0-9A-Fa-f]{14}$")
_RE_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_RE_MAC = re.compile(r"^[0-9a-f]{2}([:-]?[0-9a-f]{2}){5}$")


def _adb_path() -> str:
    return os.environ.get("ADB", "adb")


def _sh(cmd: str, serial: str = "", timeout: int = 12) -> str:
    """跑一条 adb shell 命令；失败返回空串（本模块失败不影响主流程）。"""
    args: List[str] = [_adb_path()]
    if serial:
        args += ["-s", serial]
    args += ["shell", cmd]
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return (p.stdout or "").strip()
    except Exception:
        return ""


def _su_sh(cmd: str, serial: str = "") -> str:
    """带 root 跑（Magisk 已装）。没有 root 就返回空串，不报错。"""
    out = _sh("su -c '%s'" % cmd.replace("'", "'\\''"), serial)
    if out and "not found" not in out.lower() and "permission denied" not in out.lower():
        return out
    return ""


def _prop(name: str, serial: str = "") -> str:
    return _sh("getprop %s" % name, serial).strip()


def _clean(v: str) -> str:
    return (v or "").strip().strip('"').strip("'")


def _looks_like_imei(v: str) -> bool:
    return bool(_RE_IMEI.match(v or "")) and _luhn_ok(v)


def _luhn_ok(num: str) -> bool:
    """IMEI 末位是 Luhn 校验位。校验不过的 15 位数字不当作 IMEI 写进报告。

    标准算法从**右往左**数、第 2 位起加倍。写成"从左数第 1 位起加倍"会把
    真实 IMEI 判成校验失败（船顺 2026-10-30 第一版就踩了）。
    """
    if not _RE_IMEI.match(num or ""):
        return False
    total = 0
    for i, ch in enumerate(reversed(num)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def normalize(v: Any) -> str:
    """比对用归一化：去分隔符、转小写。

    MAC 的 `A4:45:19:D4:00:B5` 与 `a44519d400b5` 必须判成同一个值，
    否则"取值命中真实 MAC"就永远对不上。
    """
    return re.sub(r"[^0-9a-z]", "", str(v or "").lower())


def _parcel_text(txt: str) -> str:
    """把 `service call` 的 Parcel 十六进制转成可读字符串。

    ★ 为什么要这一步（2026-11-10 Android 10 实测）：
      `service call iphonesubinfo 1` 的输出不是明文，而是
          Result: Parcel(
            0x00000000: 00000000 0000000f 00360038 00340038 '........8.6.8.4.'
            ...)
      IMEI 以 **UTF-16BE** 存在里面（每个数字前补 00）。
      旧代码直接对这段十六进制跑 `\\d{15}` —— 永远匹配不到，
      于是 Android 10 的测试机一个 IMEI 都取不到，报告只能退化成
      "取值类型按形态推断"。这里按字节重组后解码，再交给调用方校验。
    解不出来就返回空串（不猜）。
    """
    words: List[str] = []
    for ln in (txt or "").splitlines():
        m = re.match(r"^\s*0x[0-9a-fA-F]+:\s+(.*)$", ln)
        if not m:
            continue
        body = m.group(1)
        # 行尾的 '...' 可读部分是注释，去掉它（里面可能有字母，混进 hex 会解错）
        body = body.split("'")[0]
        for tok in body.split():
            if re.fullmatch(r"[0-9a-fA-F]{8}", tok):
                words.append(tok)
    if not words:
        return ""
    raw = bytes.fromhex("".join(words))
    for enc in ("utf-16-be", "utf-16-le"):
        try:
            s = raw.decode(enc, errors="ignore")
        except Exception:
            continue
        # 只保留数字与分隔符，避免解码噪声干扰后面的 15 位匹配
        digits = re.sub(r"[^0-9]", "", s)
        if len(digits) >= 15:
            return digits
    return ""


def capture(serial: str = "", log=None) -> Dict[str, Any]:
    """取测试机真实标识。返回

    {
      "values": {"imei": ["861234567890123"], "android_id": ["4628..."], ...},
      "model": "Redmi K30", "android": "12", "serial": "a1b2c3d4",
      "captured_at": 1793...,
      "unavailable": {"oaid": "由应用侧申请，adb 读不到", ...}
    }

    同一键可能有多个值（双卡两个 IMEI），比对时按集合处理。
    """
    vals: Dict[str, List[str]] = {}
    reasons: Dict[str, str] = {}

    def _add(key: str, v: str) -> None:
        v = _clean(v)
        if not v or v.lower() in ("null", "unknown", "0"):
            return
        if v not in vals.setdefault(key, []):
            vals[key].append(v)

    _add("android_id", _sh("settings get secure android_id", serial))
    _add("serialno", _prop("ro.serialno", serial) or _sh(
        "getprop ro.boot.serialno", serial))

    # IMEI：优先 radio 属性（Magisk/root 环境可读），再试 service call 的
    # Parcel 输出。Android 11+ 普通三方应用读不到，但**系统侧仍然有**，
    # 这正是我们做比对基准的意义 —— 应用说"我读的是 IMEI"，我们得能证伪。
    for prop in ("persist.radio.imei", "persist.radio.imei1", "persist.radio.imei2",
                 "persist.radio.imei3", "gsm.sim.imei", "ro.telephony.imei",
                 "ril.gsm.imei"):
        v = _prop(prop, serial)
        if _looks_like_imei(_clean(v)):
            _add("imei", v)
    if not vals.get("imei"):
        for slot in (1, 2):
            txt = _su_sh("service call iphonesubinfo %d" % slot, serial)
            # Parcel 里是 UTF-16 编码的 IMEI，先解码再看 15 位数字（见 _parcel_text）
            for src in (txt, _parcel_text(txt)):
                if not src:
                    continue
                for m in re.finditer(r"\d{15}", src):
                    if _looks_like_imei(m.group(0)):
                        _add("imei", m.group(0))
    if not vals.get("imei"):
        reasons["imei"] = ("系统未暴露 IMEI（Android 11+ 限制或该机型为 Wi-Fi 版）")

    for prop in ("persist.radio.meid", "ro.radio.meid", "gsm.sim.meid"):
        v = _clean(_prop(prop, serial))
        if _RE_MEID14.match(v):
            _add("meid", v)

    # MAC：Android 10+ 三方应用拿到的是 02:00:00:00:00:00，系统侧才是真值
    for path in ("/sys/class/net/wlan0/address", "/sys/class/net/eth0/address"):
        v = _clean(_su_sh("cat %s" % path, serial))
        if _RE_MAC.match(v):
            _add("wifi_mac", v)
            break
    if not vals.get("wifi_mac"):
        m = re.search(r"link/ether\s+([0-9a-f:]{17})",
                      _sh("ip link show wlan0", serial), re.I)
        if m:
            _add("wifi_mac", m.group(1))
    _add("bt_mac", _sh("settings get secure bluetooth_address", serial))

    for key, why in (
            ("oaid", "由应用侧通过 MSA/移动安全联盟 SDK 申请，adb 读不到"),
            ("vaid", "由应用侧申请，adb 读不到"),
            ("aaid", "由应用侧申请，adb 读不到"),
            ("gaid", "由 Google Play 服务分配，本机无 GMS 时不存在")):
        reasons.setdefault(key, why)

    out = {
        "values": vals,
        "model": _prop("ro.product.model", serial),
        "android": _prop("ro.build.version.release", serial),
        "serial": serial,
        "captured_at": int(time.time() * 1000),
        "unavailable": reasons,
    }
    if log:
        log("[*] 已记录测试机真实标识：%s"
            % "、".join("%s×%d" % (IDENTITY_LABELS.get(k, k), len(v))
                        for k, v in vals.items()) if vals
            else "[!] 未取到测试机真实标识，取值类型只能按形态推断")
    return out


def match(value: Any, ids: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """把采集到的取值与真实标识比对。

    返回 (键, 说明)。命中时说明里写"与测试机一致"，这是**唯一**能把一个值
    称成特定标识符的硬证据；不命中返回 ("", "")。
    """
    v = normalize(value)
    if not v or not ids:
        return "", ""
    vals = (ids.get("values") or {})
    # 长的先比：MAC 归一化后 12 位，Android ID 16 位，避免短值误命中
    for key in ("imei", "meid", "android_id", "serialno", "wifi_mac", "bt_mac",
                "imsi", "iccid"):
        for real in (vals.get(key) or []):
            r = normalize(real)
            if r and r == v:
                label = IDENTITY_LABELS.get(key, key)
                # 标签本身以「）」结尾时拼成「（…，与测试机真实值一致）」，
                # 别写成「IMEI（国际移动设备识别码）（与测试机真实值一致）」那种双括号
                desc = (label[:-1] + "，与测试机真实值一致）"
                        if label.endswith("）") else
                        label + "（与测试机真实值一致）")
                return key, desc
    return "", ""


def _is_placeholder(v: str) -> bool:
    """占位值/空值不算标识符。

    `000000000000000` 居然能过 Luhn 校验（全 0 的校验位就是 0），
    `02:00:00:00:00:00` 是 Android 10+ 给三方应用的假 MAC ——
    这两类都必须判成"没取到值"，否则报告会凭空写出一条"收集了 IMEI"。
    """
    n = normalize(v)
    if not n or n in ("null", "unknown", "none", "0", "false", "true"):
        return True
    return len(set(n)) <= 1


def shape_guess(value: Any) -> str:
    """只看取值形态能判到的程度（没有真实值可对时的保守结论）。

    返回空串表示"从形态看不出是什么" —— 这时调用方必须退回"设备标识符"这种
    类别名，不能编一个具体名字。
    """
    v = _clean(value)
    if not v or _is_placeholder(v):
        return ""
    # 占位值不是标识符：Android 10+ 三方应用读 MAC 一律得到 02:00:00:00:00:00，
    # 这恰恰说明"没拿到真值"，不能反过来标成"MAC 地址"。
    if _RE_MAC.match(v.lower()) and normalize(v) in (
            "020000000000", "000000000000", "ffffffffffff"):
        return ""
    if _looks_like_imei(v):
        return "IMEI（按取值形态判定：15 位数字且校验位正确，未与测试机真实值比对）"
    if _RE_MAC.match(v.lower()):
        return "MAC 地址（按取值形态判定）"
    if _RE_HEX16.match(v.lower()):
        return "Android ID（按取值形态判定：16 位十六进制）"
    return ""


def report_rows(ids: Optional[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """给报告用的（名称, 取值）清单。取不到的也列出来并写原因。"""
    if not ids:
        return []
    vals = ids.get("values") or {}
    rows: List[Tuple[str, str]] = []
    for key, label in IDENTITY_LABELS.items():
        got = vals.get(key) or []
        if got:
            shown = "、".join(got[:3])
            if len(got) > 3:
                shown += " 等 %d 个" % len(got)
            rows.append((label, shown))
    for key, why in (ids.get("unavailable") or {}).items():
        if key in IDENTITY_LABELS and not (vals.get(key)):
            rows.append((IDENTITY_LABELS[key], "未记录（%s）" % why))
    return rows


__all__ = ["capture", "match", "shape_guess", "normalize", "report_rows",
           "IDENTITY_LABELS"]
