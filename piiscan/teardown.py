"""检测收尾：卸载被测应用。

为什么要有这一步（用户明确要求）：
    检测员一轮接一轮地测，设备上的 App 会越堆越多；残留的登录态、缓存数据
    还会污染下一轮的「首启」判定 —— 首启观测的前提就是"这个 App 是全新的"。
    所以流程的最后一步固定为：把被测应用从设备上卸载掉，并把卸载结果写进报告。

原则与别处一致：**只记录真实发生的事**。
    - 卸载前先取证（包名、版本、安装路径），否则事后无法证明"当时装的是这个"；
    - 命令原文与设备返回原文都留档，不做转述；
    - 卸载后**再查一次**确认，不能只看 adb 那句 "Success"
      （实测过：Success 之后包仍在的情况并不少见）；
    - 失败就如实写失败，不静默通过。
"""

from __future__ import annotations

import os
import subprocess
from typing import Any, Callable, Dict, List, Optional


def _adb_args(serial: str) -> List[str]:
    return [os.environ.get("ADB", "adb")] + (["-s", serial] if serial else [])


def _run(args: List[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, timeout=timeout)


def _text(p: subprocess.CompletedProcess) -> str:
    return ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace").strip()


def installed_info(serial: str, package: str) -> Dict[str, Any]:
    """卸载前取证：装了没有、什么版本、装在哪个路径。"""
    info: Dict[str, Any] = {"installed": False, "version": "", "paths": []}
    try:
        p = _run(_adb_args(serial) + ["shell", "pm", "path", package], timeout=25)
        out = _text(p)
        if "package:" in out:
            info["installed"] = True
            info["paths"] = [ln.replace("package:", "").strip()
                             for ln in out.splitlines() if ln.strip().startswith("package:")]
    except Exception:
        pass
    if not info["installed"]:
        return info
    try:
        p = _run(_adb_args(serial) + ["shell", "dumpsys", "package", package], timeout=25)
        import re
        m = re.search(r"versionName=(\S+)", _text(p))
        if m:
            info["version"] = m.group(1)
    except Exception:
        pass
    return info


def uninstall(serial: str, package: str,
              log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """卸载被测应用，返回可供报告直接引用的证据字典。

    返回字段：
        package / before（卸载前取证）/ command / output（设备返回原文）
        / cmd_ok / after（卸载后再查）/ ok（最终结论）/ note
    """
    log = log or (lambda *_a, **_k: None)
    res: Dict[str, Any] = {
        "package": package,
        "device_serial": serial,
        "before": {}, "command": "", "output": "",
        "cmd_ok": False, "after": {}, "ok": False, "note": "",
    }
    if not package:
        res["note"] = "未指定包名，跳过卸载"
        return res

    before = installed_info(serial, package)
    res["before"] = before
    if not before.get("installed"):
        res["note"] = "卸载前设备上未安装该应用（可能采集期间已被移除），无需卸载"
        log("[*] 卸载步骤：设备上已无 %s，跳过" % package)
        return res

    cmd = "adb %sshell pm uninstall %s" % ("-s %s " % serial if serial else "", package)
    res["command"] = "adb %suninstall %s" % ("-s %s " % serial if serial else "", package)

    log("[*] 收尾：卸载被测应用 %s（版本 %s）"
        % (package, before.get("version") or "未知"))
    try:
        p = _run(_adb_args(serial) + ["uninstall", package], timeout=180)
        out = _text(p)
    except Exception as e:
        res["output"] = "执行异常：%s" % e
        res["note"] = "卸载命令未能执行：%s" % e
        log("[!] 卸载未能执行：%s" % e)
        return res

    res["output"] = out[:400]
    res["cmd_ok"] = out.strip().startswith("Success") or "Success" in out
    log("[*] 卸载返回：%s" % (out.strip().splitlines()[-1][:80] if out.strip() else "(空)"))

    # 不能只信那句 Success —— 再查一次
    after = installed_info(serial, package)
    res["after"] = after
    res["ok"] = (not after.get("installed")) and res["cmd_ok"]
    if not res["ok"]:
        if res["cmd_ok"]:
            res["note"] = "命令返回 Success，但复查发现设备上仍能查到该包（可能残留多用户/分身数据）"
            log("[!] 卸载返回 Success 但复查仍存在该包")
        else:
            res["note"] = "卸载失败：%s" % (out.strip().splitlines()[-1][:120] if out.strip() else "无返回")
            log("[!] 卸载失败：%s" % res["note"])
    else:
        res["note"] = "已从设备卸载，复查确认不存在"
    return res
