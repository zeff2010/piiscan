"""从**被测设备自己**的短信收件箱里取验证码。

为什么要这个模块（2026-11-06 春雨诊所实测）：

    登录页点了「获取短信验证码」，脚本开始按提示"请检测人员回填"。
    等了 600 秒没等到，报告写下"已申请验证码，但 600 秒内未收到检测人员回填"。
    事后去设备上翻收件箱：**当天一条短信都没有** —— 那句"已申请验证码"是假的。
    真实原因是登录页的「我已阅读并同意《春雨诊所协议》《隐私政策》」没勾，
    点发码只弹了一个 toast「请先阅读并同意协议」，请求根本没发出去。

    两层教训：
    ① 人工回填这条路本身就慢且容易失真（人不在就等 600 秒，人在就得盯着屏幕）。
       测试机的 SIM 就在被测设备里，短信落地在这台机器上，直接读它最可靠。
    ② "我等了但没等到"不等于"对方发了但没到"。必须能区分
       「压根没发出去」与「发了没到」，否则报告里就是替应用编理由。

实现：`content query content://sms/inbox`，需要 root（本机 Magisk 已具备）。
不 root 也能跑 —— 此时 `available()` 返回 False，调用方回落到人工回填（sms.txt），
一个字都不会因此写错。
"""

from __future__ import annotations

import re
import subprocess
import time
from typing import Callable, Dict, List, Optional

from . import uiwalk

# 关键词后面紧跟的数字最可信；没有关键词就退到"6 位数字"。
_KW = ("验证码", "校验码", "动态码", "确认码", "验证代码", "口令", "code")

_URI = ("content query --uri content://sms/inbox "
        "--projection address:body:date")


def _shell(serial: str, inner: str, timeout: int = 20) -> str:
    """命令行里的单引号外层由 `su -c "..."` 包住，内部用单引号给 SQL 用。"""
    try:
        r = uiwalk._adb(serial, "shell", 'su -c "%s"' % inner, timeout=timeout)
        return ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")
    except Exception:
        return ""


def available(serial: str) -> bool:
    """能不能读到收件箱。读不到绝不抛，调用方按"没有这个能力"处理。"""
    out = _shell(serial, _URI + " --where 'date > 0'", timeout=15)
    return "Row:" in out or "No result found" in out


def latest(serial: str, since_ms: int, limit: int = 8) -> List[Dict[str, str]]:
    """读 `since_ms` 之后收到的短信，新到旧。"""
    out = _shell(serial, _URI + " --where 'date > %d' --sort 'date DESC'"
                 % int(since_ms))
    rows: List[Dict[str, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("Row:"):
            continue
        # body 里可能有逗号，address 里没有 → 先切 address，再从右侧切 date
        m = re.match(r"Row:\s*\d+\s+address=(.*?),\s*body=(.*),\s*date=(\d+)\s*$",
                     line)
        if not m:
            continue
        rows.append({"address": m.group(1), "body": m.group(2),
                     "date": m.group(3)})
        if len(rows) >= limit:
            break
    return rows


def extract_code(body: str) -> str:
    """从一条短信正文里取验证码。

    取不到就返回空串 —— 宁可返回空，也不能拿正文里随便一个数字去填，
    填错了会把"没登录上"伪装成"验证码错误"，又是一句假话。
    """
    t = (body or "").strip()
    if not t:
        return ""
    for m in re.finditer("|".join(_KW), t, re.I):
        tail = t[m.end(): m.end() + 28]
        mm = re.search(r"(?<!\d)(\d{4,8})(?!\d)", tail)
        if mm:
            return mm.group(1)
        head = t[max(0, m.start() - 18): m.start()]
        mm = re.search(r"(?<!\d)(\d{4,8})(?!\d)", head)
        if mm:
            return mm.group(1)
    mm = re.search(r"(?<!\d)(\d{6})(?!\d)", t)
    if mm:
        return mm.group(1)
    # ★ 没有关键词时**不认 4 位数字**：银行/通知短信里的尾号、金额、单号
    #   全长得像验证码（"您尾号5697账户存入36.30元" → 5697）。
    #   拿错号码去填，失败后会被记成"验证码错误" —— 又一句假话。
    return ""


def text_after(serial: str, since_ms: int, limit: int = 4) -> str:
    """把新短信拼成一句话，用于报告里说明"这段时间设备到底收到了什么"。"""
    rows = latest(serial, since_ms, limit=limit)
    if not rows:
        return ""
    parts = []
    for r in rows:
        parts.append("%s：%s" % (r.get("address") or "未知号码",
                                (r.get("body") or "")[:60]))
    return "；".join(parts)


def wait_code(serial: str, since_ms: int, timeout: float,
              should_stop: Optional[Callable[[], bool]] = None,
              log: Optional[Callable[[str], None]] = None,
              poll: float = 3.0) -> str:
    """等一条**本次**请求之后到达的短信，取出验证码。超时返回空串。

    `since_ms` 必须是**点击发码那一刻**的时间戳：不然会捡到上一轮残留的
    验证码（那个码早过期了），填进去必然失败，还会被记成"验证码错误"。
    """
    t0 = time.time()
    while time.time() - t0 < timeout:
        if should_stop is not None and should_stop():
            return ""
        for row in latest(serial, since_ms):
            code = extract_code(row.get("body"))
            if code:
                if log is not None:
                    log("[*] 设备收件箱收到短信（%s），取到 %d 位验证码"
                        % (row.get("address") or "未知号码", len(code)))
                return code
        time.sleep(poll)
    return ""
