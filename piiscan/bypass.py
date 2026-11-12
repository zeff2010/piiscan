"""注入被加固拦死时的**旁路取证**。

## 为什么需要这一层

加固壳能杀掉 frida，但杀不掉系统自己的账本：

  · `dumpsys appops`  记着"这个包最近一次用相机 / 定位 / 剪贴板 / 麦克风是什么时候"
  · `dumpsys package` 记着运行时权限到底是 granted 还是 denied

这两样都不需要注入、不需要 App 配合、也不需要 root。它们的证据力弱于调用栈
（只能证明"用过"，证不出"读了什么、发给了谁"），但足以把报告里那句
**"跳过未测（注入被拦截）"** 变成 **"有系统侧旁证，待人工确认"**。
这两种写法在复核眼里的分量完全不同。

## 边界（必须写进报告，不能省）

  · 旁证**不能**证明"未同意前就开始收集"—— appops 只有最近一次时间，没有逐次记录，
    时间分辨率也不够（部分机型只给"几小时前"）。
  · 旁证**不能**替代调用栈：没有调用栈就没有归因（App 自身还是第三方 SDK），
    报告里必须写成"未能归属"。
  · 取不到就如实写"系统未提供"，不猜、不用"通常""可能"补位。

## 解析为什么要写得这么松

`dumpsys appops` 的输出随 Android 版本、厂商定制差异很大（MIUI、EMUI 都改过）。
写死一种格式的结果是：换个机型整段解析返回空，而报告会把它读成"没有旁证"。
所以这里只认"这一行里有一个全大写的操作名 + 一个时间标记"，其余一律跳过。
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from . import uiwalk

Log = Callable[[str], None]
_NOP: Log = lambda *_a, **_k: None

# 只关心这几类 —— 它们同时是「个人信息行为」和「系统会记账」的交集。
# 其余操作（VIBRATE、WAKE_LOCK 之类）记了也没人看，只会把报告撑长。
_WANTED = {
    "CAMERA": "相机",
    "RECORD_AUDIO": "麦克风",
    "FINE_LOCATION": "精确定位",
    "COARSE_LOCATION": "粗略定位",
    "READ_CLIPBOARD": "读取剪贴板",
    "WRITE_CLIPBOARD": "写入剪贴板",
    "READ_CONTACTS": "读取通讯录",
    "READ_CALL_LOG": "读取通话记录",
    "READ_SMS": "读取短信",
    "SEND_SMS": "发送短信",
    "READ_PHONE_STATE": "读取设备标识",
    "READ_PHONE_NUMBERS": "读取手机号",
    "READ_EXTERNAL_STORAGE": "读取外部存储",
    "WRITE_EXTERNAL_STORAGE": "写入外部存储",
    "BODY_SENSORS": "身体传感器",
    "ACTIVITY_RECOGNITION": "活动识别",
    "GET_USAGE_STATS": "读取应用使用记录",
    "REQUEST_INSTALL_PACKAGES": "请求安装应用",
    "SYSTEM_ALERT_WINDOW": "悬浮窗",
    "QUERY_ALL_PACKAGES": "读取已安装应用",
}

# `CAMERA: mode=allow; time=+1h2m3s4ms ago` / `access: 2026-10-31 22:00:00`
_OP_LINE = re.compile(r"^\s*([A-Z][A-Z0-9_]{3,})\s*[:：]")
_TIME_HINT = re.compile(r"(time=|access[:：]|\+\d+[dhms]|\d{4}-\d{2}-\d{2})")


def _adb(serial: str, *args: str, timeout: int = 30):
    return uiwalk._adb(serial, *args, timeout=timeout)


def _text(p: Any) -> str:
    out = getattr(p, "stdout", b"") or b""
    try:
        return out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)
    except Exception:
        return ""


def parse_appops(text: str, limit: int = 40) -> List[Dict[str, str]]:
    """从 `dumpsys appops` 里挑出"最近用过的敏感操作"。

    返回 `[{"op": "CAMERA", "label": "相机", "time": "+1h2m ago", "mode": "allow"}]`。
    同一个操作只保留第一次出现（dumpsys 会把同一个 op 在多个 uid 段里重复列）。
    """
    out: List[Dict[str, str]] = []
    seen: set = set()
    for raw in (text or "").splitlines():
        m = _OP_LINE.match(raw)
        if not m:
            continue
        op = m.group(1).upper()
        if op not in _WANTED or op in seen:
            continue
        if not _TIME_HINT.search(raw):
            # 没有时间标记的行多半是操作清单（"CAMERA: allow"），
            # 那说明的是"策略允许"，不是"最近用过"—— 两件事不能混。
            continue
        seen.add(op)
        t = ""
        mt = re.search(r"time=([^;,\)]+)", raw)
        if mt:
            t = mt.group(1).strip()
        else:
            mt2 = re.search(r"(access[:：]\s*.+)$", raw)
            if mt2:
                t = mt2.group(1).strip()
        mode = ""
        mm = re.search(r"mode=(\w+)", raw)
        if mm:
            mode = mm.group(1)
        out.append({"op": op, "label": _WANTED[op], "time": t[:60], "mode": mode})
        if len(out) >= limit:
            break
    return out


_PERM_LINE = re.compile(r"^\s*(android\.permission\.[A-Z_0-9]+)\s*:\s*granted\s*=\s*(true|false)",
                        re.I)

# 这几个权限和"收集个人信息"直接相关，报告里单独点出来。
_HOT_PERMS = {
    "android.permission.READ_PHONE_STATE": "读取电话状态（设备标识）",
    "android.permission.ACCESS_FINE_LOCATION": "精确位置",
    "android.permission.ACCESS_COARSE_LOCATION": "粗略位置",
    "android.permission.CAMERA": "相机",
    "android.permission.RECORD_AUDIO": "麦克风",
    "android.permission.READ_CONTACTS": "通讯录",
    "android.permission.READ_SMS": "短信",
    "android.permission.READ_CALL_LOG": "通话记录",
    "android.permission.READ_EXTERNAL_STORAGE": "外部存储",
    "android.permission.BODY_SENSORS": "身体传感器",
    "android.permission.POST_NOTIFICATIONS": "通知",
}


def parse_permissions(text: str) -> Dict[str, Any]:
    """从 `dumpsys package <pkg>` 里取运行时权限的授予状态。

    ★ 只取 `granted=true/false` 形式的行：
      `dumpsys package` 同时列"安装时声明的权限"，那些没有 granted 字段。
      把声明当授予会让报告写成"应用已获得通讯录权限"—— 而它可能只是申请了。
    """
    granted: List[Dict[str, str]] = []
    denied: List[Dict[str, str]] = []
    seen: set = set()
    for raw in (text or "").splitlines():
        m = _PERM_LINE.match(raw)
        if not m:
            continue
        perm = m.group(1)
        if perm in seen:
            continue
        seen.add(perm)
        item = {"perm": perm, "label": _HOT_PERMS.get(perm, perm.split(".")[-1])}
        (granted if m.group(2).lower() == "true" else denied).append(item)
    return {
        "granted": granted,
        "denied": denied,
        # 只把"热门权限"里已授予的单列一份，报告正文用得上
        "hot_granted": [x for x in granted if x["perm"] in _HOT_PERMS],
    }


def collect(serial: str, package: str, log: Log = _NOP) -> Dict[str, Any]:
    """采集一份旁路证据。任何一步失败都如实记录，不抛异常。

    返回
    ----
    {
      "ok": bool,            # 至少有一项取到了
      "appops": [...],       # 最近用过的敏感操作
      "permissions": {...},  # 授予/拒绝
      "why": "",             # 没取到时写原因
      "elapsed": 秒,
    }
    """
    import time as _t

    t0 = _t.time()
    out: Dict[str, Any] = {"ok": False, "appops": [], "permissions": {},
                           "why": "", "elapsed": 0.0}
    if not package:
        out["why"] = "没有包名，无法旁路取证"
        return out
    why: List[str] = []

    # ---- 1. appops：最近用过的敏感操作 ----
    try:
        p = _adb(serial, "shell", "dumpsys", "appops", "--package", package, timeout=40)
        txt = _text(p)
        if "Unknown option" in txt or "appops" in txt and "Package" not in txt and not txt.strip():
            why.append("系统不支持 dumpsys appops --package")
        ops = parse_appops(txt)
        out["appops"] = ops
        if ops:
            log("[*] 旁路取证：appops 记录到 %d 项敏感操作（%s）"
                % (len(ops), "、".join(o["label"] for o in ops[:5])))
        elif txt.strip():
            log("[*] 旁路取证：appops 里没有敏感操作的近期记录")
    except Exception as e:
        why.append("appops 读取失败：%s" % e)

    # ---- 2. 运行时权限授予状态 ----
    try:
        p = _adb(serial, "shell", "dumpsys", "package", package, timeout=40)
        perms = parse_permissions(_text(p))
        out["permissions"] = perms
        if perms.get("granted") or perms.get("denied"):
            log("[*] 旁路取证：运行时权限 已授予 %d 项 / 未授予 %d 项"
                % (len(perms["granted"]), len(perms["denied"])))
        else:
            why.append("未从 dumpsys package 里取到运行时权限授予状态")
    except Exception as e:
        why.append("dumpsys package 读取失败：%s" % e)

    out["ok"] = bool(out["appops"] or (out["permissions"].get("granted")
                                       or out["permissions"].get("denied")))
    out["why"] = "；".join(why)
    out["elapsed"] = round(_t.time() - t0, 1)
    return out
