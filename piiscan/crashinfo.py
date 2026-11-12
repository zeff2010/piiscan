"""目标应用「起不来」时的取证。

为什么需要这个模块
------------------
采集器原本已经能发现"App 进程退出、反复退出"，也把这些写进了 `errors`，
但报告层完全没用到 —— 于是三一卡车那一轮跑出来是这样：

    22 项报告项 → 发现问题 0 / 疑似 0 / 未发现问题 0 / 跳过未测 22

人工复核员看到这行只会想"哦，没测出来"，**看不出这台设备上这个 App 根本打不开**，
更想不到要去翻 tombstone。对一份工作底稿来说，这是最糟的形态：
既没有结论，也没有说明为什么没有结论。

所以：一旦判定"目标应用未能正常启动"，就必须把 **可核对的崩溃证据** 带出来 ——
信号、出错地址、调用栈、地址落在哪个库的哪个段、复现命令。目标是让复核员
照着报告里的命令敲一遍，就能在自己眼前看到同一个崩溃。

取证来源（按可靠性排序）
------------------------
1. `/data/tombstones/tombstone_*`（需 root）—— 系统级崩溃转储，含 signal、
   fault addr、backtrace、**memory map**。最后一项是判定"崩在哪个库"的关键。
2. `logcat` —— 不需要 root，任何设备上都能取到 `Fatal signal` 与 DEBUG 段。
   作为兜底，也用于交叉印证（两份证据的 fault addr 应一致）。

本模块**只记录读到的原文**，不做因果推断。推断性文字由报告层单独标注，
避免"事实"与"分析"混在一起。
"""
from __future__ import annotations

import os
import re
import subprocess
from typing import Any, Dict, List, Optional

__all__ = ["collect", "parse_tombstone", "fault_region"]

_SIG_RE = re.compile(
    r"signal\s+(\d+)\s+\(([^)]+)\),\s*code\s+(-?\d+)\s*\(([^)]+)\),\s*fault addr\s+(0x[0-9a-fA-F]+)")
_MAP_RE = re.compile(
    r"^\s+([0-9a-fA-F']+)-([0-9a-fA-F']+)\s+([rwxps-]{3,4})\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s*(.*)$")


# ---------------------------------------------------------------- adb 封装

def _adb_raw(serial: str, args: List[str], timeout: int = 30) -> str:
    from .adbtool import adb_exe
    cmd = [adb_exe()]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _sh(serial: str, script: str, timeout: int = 30) -> str:
    """在设备上以 shell 身份执行。

    注意参数形态：整条 `su -c '…'` 必须是**一个** argv 元素。
    adb 会把所有元素用空格拼起来再送进设备 shell，拆成
    ["shell", "su", "-c", script] 的话，设备端会把 script 按空格重新切分，
    管道和重定向全部失效（踩过）。
    """
    return _adb_raw(serial, ["shell", script], timeout=timeout)


def _sh_root(serial: str, script: str, timeout: int = 30) -> str:
    if "'" in script:
        script = script.replace("'", "'\\''")
    return _adb_raw(serial, ["shell", "su -c '%s'" % script], timeout=timeout)


def _has_root(serial: str) -> bool:
    out = _sh_root(serial, "id", timeout=15)
    return "uid=0" in out


# ---------------------------------------------------------------- 解析

def _hex(s: str) -> int:
    return int(s.replace("'", ""), 16)


def fault_region(text: str, fault_addr: str) -> Optional[Dict[str, str]]:
    """在 tombstone 的 memory map 段里找出 fault addr 落在哪一段。

    这是整份取证里信息量最大的一条：它直接回答了"崩在哪个文件上"。
    例（三一卡车实测）：

        00000000'71f86000-00000000'71f87fff r--   0  2000  /system/framework/arm64/boot-QPerformance.oat

    权限位 `r--` + 它是 pc 指向的地址 ⇒ 在执行一个只读页 —— 这一条本身就说明了
    问题不在常规代码路径上。
    """
    try:
        addr = _hex(fault_addr)
    except Exception:
        return None
    for line in text.splitlines():
        m = _MAP_RE.match(line)
        if not m:
            continue
        try:
            lo, hi = _hex(m.group(1)), _hex(m.group(2))
        except Exception:
            continue
        if lo <= addr < hi:
            path = m.group(6).strip()
            return {
                "range": "%s-%s" % (m.group(1), m.group(2)),
                "perms": m.group(3),
                "offset": m.group(4),
                "path": path.split(" (BuildId")[0].strip(),
                "raw": line.strip(),
            }
    return None


def parse_tombstone(text: str, limit_frames: int = 12) -> Dict[str, Any]:
    """从一份 tombstone 正文里抽出报告用得上的字段。读不到就留空，不猜。"""
    out: Dict[str, Any] = {}
    lines = text.splitlines()

    for i, line in enumerate(lines):
        m = _SIG_RE.search(line)
        if m:
            out["signal"] = "SIG%s" % m.group(2).replace("SIG", "")
            out["signal_no"] = int(m.group(1))
            out["signal_code"] = m.group(4)
            out["fault_addr"] = m.group(5)
            # 上一行通常是 Timestamp
            for j in range(max(0, i - 6), i):
                if lines[j].startswith("Timestamp:"):
                    out["crash_time"] = lines[j].split(":", 1)[1].strip()
                    break
            break

    # backtrace：连续以 # 开头的行
    frames: List[str] = []
    for i, line in enumerate(lines):
        if line.strip().startswith("backtrace:"):
            for nl in lines[i + 1:]:
                s = nl.strip()
                if not s.startswith("#"):
                    break
                frames.append(re.sub(r"\s+", " ", s))
                if len(frames) >= limit_frames:
                    break
            break
    if frames:
        out["backtrace"] = frames

    if out.get("fault_addr"):
        reg = fault_region(text, out["fault_addr"])
        if reg:
            out["fault_region"] = reg
    return out


# ---------------------------------------------------------------- 采集

def _pick_tombstone(serial: str, package: str,
                    since_ts: Optional[float] = None) -> Optional[str]:
    """挑出属于该包名、且最新的一份 tombstone。

    `since_ts` 是本次采集的开始时刻（epoch 秒）。必须传 ——
    设备上往往还留着**别的 App 或上一轮检测**的转储，按包名匹配但时间对不上时
    取回来，报告就会挂着一份与本次无关的崩溃证据（比没有更坏：
    复核员照着转储编号去查，查到的是另一次事故）。
    """
    listing = _sh_root(
        serial,
        "for f in $(ls -t /data/tombstones/ | grep -E '^tombstone_[0-9]+$' | head -40); do "
        "echo \"$f $(stat -c %Y /data/tombstones/$f)\"; done", timeout=40)
    cands = []
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            cands.append((parts[0], int(parts[1])))
    for name, mtime in cands:
        if since_ts and mtime < int(since_ts) - 5:
            continue                      # 早于本次采集的，不冒充本次证据
        path = "/data/tombstones/%s" % name
        head = _sh_root(serial, "grep -m1 '^Cmdline:' %s" % path, timeout=20)
        if package and ("Cmdline: %s" % package) in head:
            return path
    return None


def _from_logcat(serial: str, package: str) -> Dict[str, Any]:
    """不需要 root 的兜底取证：从 logcat 里捞该进程的致命信号段。"""
    txt = _adb_raw(serial, ["logcat", "-d", "-t", "3000"], timeout=60)
    if not txt:
        return {}
    lines = txt.splitlines()
    hits = [l for l in lines if "Fatal signal" in l and package in l]
    if not hits:
        return {}
    last = hits[-1]
    m = _SIG_RE.search(last)
    out: Dict[str, Any] = {"from_logcat": True, "logcat_signal_line": last.strip()}
    if m:
        out["signal"] = "SIG%s" % m.group(2).replace("SIG", "")
        out["signal_no"] = int(m.group(1))
        out["signal_code"] = m.group(4)
        out["fault_addr"] = m.group(5)
    # DEBUG 段里该进程的 backtrace
    try:
        idx = max(i for i, l in enumerate(lines) if "Fatal signal" in l and package in l)
    except ValueError:
        return out
    frames: List[str] = []
    seen_bt = False
    for l in lines[idx: idx + 120]:
        if l.strip().endswith("backtrace:"):
            seen_bt = True
            continue
        if seen_bt:
            s = l.split("DEBUG   :", 1)[-1].strip()
            if s.startswith("#"):
                frames.append(re.sub(r"\s+", " ", s))
            elif frames:
                break
    if frames:
        out["backtrace"] = frames[:12]
    return out


def _launcher_of(serial: str, package: str) -> str:
    out = _sh(serial, "cmd package resolve-activity --brief %s" % package, timeout=20)
    for line in out.splitlines():
        line = line.strip()
        if "/" in line and not line.startswith("priority"):
            return line
    return package


def collect(serial: str, package: str, since_ts: Optional[float] = None,
            log=None) -> Dict[str, Any]:
    """抓取"目标应用未能启动"的证据。任何一步失败都不抛异常，只留缺口。

    `since_ts`：本次采集开始时刻。用于排除设备上残留的历史转储。
    """
    log = log or (lambda *_: None)
    res: Dict[str, Any] = {"package": package, "device_serial": serial}

    root = _has_root(serial)
    res["root_available"] = root

    ts_path = _pick_tombstone(serial, package, since_ts) if root else None
    if ts_path:
        body = _sh_root(serial, "cat %s" % ts_path, timeout=40)
        parsed = parse_tombstone(body)
        parsed["tombstone"] = ts_path
        res.update(parsed)
        res["source"] = "tombstone"
        log("[*] 崩溃取证：命中 %s（%s / fault addr %s）"
            % (ts_path, parsed.get("signal", "?"), parsed.get("fault_addr", "?")))
    else:
        fb = _from_logcat(serial, package)
        if fb:
            res.update(fb)
            res["source"] = "logcat"
            log("[*] 崩溃取证：由 logcat 取得（%s / fault addr %s）"
                % (fb.get("signal", "?"), fb.get("fault_addr", "?")))
        else:
            res["source"] = "none"
            log("[!] 崩溃取证：未能取到任何崩溃记录")

    launcher = _launcher_of(serial, package)
    res["launcher"] = launcher
    if launcher:
        res["repro_cmd"] = "adb shell am start -n %s" % launcher
    # 设备指纹：换台机器复现时，这一行能说明"是不是同一套 ROM"
    res["device_fingerprint"] = _sh(serial, "getprop ro.build.fingerprint", timeout=15).strip()
    res["found"] = bool(res.get("fault_addr") or res.get("backtrace") or res.get("source") == "tombstone")
    return res
