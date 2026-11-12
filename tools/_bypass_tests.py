#!/usr/bin/env python3
"""旁路取证（注入被加固拦死时的系统侧补证）自测。

为什么要钉住：这一层的作用是**在采不到调用栈时，把"没测"变成"有旁证"**。
它解析的是 `dumpsys` 的文本，而不同 Android 版本/厂商的输出格式差异很大 ——
解析一旦静默失效，报告会写"系统未提供任何记录"，读起来像"这个 App 很干净"。
那是比"没测"更糟的一种假话。

跑法：python tools/_bypass_tests.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# 一份贴近 Android 12 / MIUI 的 appops 输出（含噪声行：没有时间标记的操作清单）
_APPOPS = """\
Current AppOps Service state:
  UID 10345:
    Package com.demo.app:
      VIBRATE: mode=allow; time=+1d2h3m4s5ms ago
      CAMERA: mode=allow; time=+12m34s ago
      RECORD_AUDIO: mode=allow; time=+5m1s ago
      READ_CLIPBOARD: mode=allow; time=+3m ago
      FINE_LOCATION: mode=allow; time=+1h ago
      COARSE_LOCATION: mode=allow
      READ_CONTACTS: mode=ignore; time=+2m ago
      ACTIVITY_RECOGNITION: mode=allow; time=+20s ago
  UID 10346:
    Package com.other.app:
      CAMERA: mode=allow; time=+9m ago
"""

_PACKAGE = """\
Packages:
  Package [com.demo.app] (a1b2c3):
    userId=10345
    requested permissions:
      android.permission.CAMERA
      android.permission.READ_CONTACTS
      android.permission.READ_PHONE_STATE
      android.permission.ACCESS_FINE_LOCATION
    install permissions:
      android.permission.INTERNET: granted=true, flags=[ INSTALLED ]
    runtime permissions:
      android.permission.CAMERA: granted=true, flags=[ USER_SET ]
      android.permission.READ_CONTACTS: granted=false, flags=[ USER_SET ]
      android.permission.READ_PHONE_STATE: granted=true, flags=[ USER_SET ]
      android.permission.POST_NOTIFICATIONS: granted=false
"""


def run(check) -> None:
    from piiscan import bypass

    # ---------------------------------------------------------------- appops
    ops = bypass.parse_appops(_APPOPS)
    names = [o["op"] for o in ops]
    check("appops：能解析出敏感操作", "CAMERA" in names, names)
    check("appops：无关操作（VIBRATE）被丢掉", "VIBRATE" not in names, names)
    check("appops：没有时间标记的行不算“最近用过”", "COARSE_LOCATION" not in names, names)
    check("appops：只保留第一次出现（跨 uid 去重）",
          names.count("CAMERA") == 1, names)
    cam = next(o for o in ops if o["op"] == "CAMERA")
    check("appops：时间被取出来", "12m" in cam["time"], cam)
    check("appops：mode 被取出来", cam["mode"] == "allow", cam)
    check("appops：中文标签齐备", cam["label"] == "相机", cam)
    check("appops：空输入不抛异常", bypass.parse_appops("") == [], "")
    check("appops：limit 生效", len(bypass.parse_appops(_APPOPS, limit=2)) == 2)

    # ---------------------------------------------------------------- 权限
    p = bypass.parse_permissions(_PACKAGE)
    granted = [x["perm"] for x in p["granted"]]
    denied = [x["perm"] for x in p["denied"]]
    check("权限：已授予的读得出来", "android.permission.CAMERA" in granted, granted)
    check("权限：未授予的读得出来", "android.permission.READ_CONTACTS" in denied, denied)
    check("权限：安装时权限也算 granted",
          "android.permission.INTERNET" in granted, granted)
    check("权限：只声明未授予的（ACCESS_FINE_LOCATION）不算授予",
          "android.permission.ACCESS_FINE_LOCATION" not in granted,
          [x for x in granted if "LOCATION" in x])
    check("权限：声明的 READ_PHONE_STATE 出现在 runtime 段里才算",
          "android.permission.READ_PHONE_STATE" in granted, granted)
    hot = [x["perm"] for x in p["hot_granted"]]
    check("权限：热门权限单独列出（已授予）", "android.permission.CAMERA" in hot, hot)
    check("权限：热门权限不含未授予的",
          "android.permission.READ_CONTACTS" not in hot, hot)
    check("权限：空输入返回空结构",
          bypass.parse_permissions("") == {"granted": [], "denied": [], "hot_granted": []})
    check("权限：标签有中文名",
          any(x["label"] == "相机" for x in p["granted"]), p["granted"])

    # ---------------------------------------------------------------- collect
    # 没有包名时必须直接返回、且写清原因（不能假装"没记录"）
    r = bypass.collect("", "", lambda *_a: None)
    check("collect：没有包名 → ok=False", r["ok"] is False, r)
    check("collect：没有包名要写原因", "包名" in (r.get("why") or ""), r)

    # ---------------------------------------------------------------- 存档字段
    from piiscan.collector import ScanResult
    s = ScanResult(package="com.demo.app")
    check("存档：默认有 bypass 字段", hasattr(s, "bypass") and s.bypass == {}, s.bypass)
    s.bypass = {"ok": True, "appops": [{"op": "CAMERA"}]}
    check("存档：bypass 会写进 to_dict", s.to_dict().get("bypass", {}).get("ok") is True)
    s2 = ScanResult.from_dict(s.to_dict())
    check("存档：from_dict 能还原 bypass", s2.bypass.get("ok") is True, s2.bypass)


if __name__ == "__main__":
    _ok = 0
    _bad = []

    def _check(name, cond, got=""):
        global _ok
        if cond:
            _ok += 1
        else:
            _bad.append("%s（实际：%r）" % (name, got))

    run(_check)
    print("通过 %d 项，失败 %d 项" % (_ok, len(_bad)))
    for b in _bad:
        print("  FAIL", b)
    sys.exit(1 if _bad else 0)
