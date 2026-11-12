"""adb 定位与「为什么一台设备都没看到」的判定。

背景（2026-11-12）：项目被拉到另一台电脑上部署，Web 正常、手机插上，
界面却只写「未检测到测试机」。真实原因是那台机器上 adb 不在 PATH 里，
而 `list_test_devices()` 的 `except Exception: out = ""` 把
FileNotFoundError 一起吞了 —— 「没装 adb」和「手机没插」压成同一句话。

这些用例钉三件事：
  ① 解析 `adb devices -l` 不能把表头、`no permissions` 这类行当成设备；
  ② 结论的**判定顺序**必须是「先问 adb 在不在，再问看到几台」；
  ③ 各处不再自己拼 `os.environ.get("ADB", "adb")`（否则又回到多份实现）。
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _json(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, json.loads(r.read().decode())


def run(check):
    from piiscan import adbtool as T

    # ---- ① 解析 ----
    raw = (
        "List of devices attached\n"
        "a1b2c3d4\tdevice product:phoenix model:M2004K19C device:phoenix transport_id:3\n"
        "f6e5d4c3b2a1\tunauthorized usb:1-2 transport_id:5\n"
        "192.168.1.9:5555\toffline transport_id:7\n"
        "\n"
    )
    devs = T.parse_devices(raw)
    check("adb devices 表头不被当成设备", len(devs) == 3, devs)
    check("型号从 model: 里取", devs[0]["model"] == "M2004K19C", devs[0])
    check("unauthorized 原样保留（不能算连上）", devs[1]["state"] == "unauthorized", devs[1])
    check("表头行不进列表", all("List" not in d["serial"] for d in devs), devs)

    perm = T.parse_devices("List of devices attached\nabc\tno permissions (user in plugdev group)\n")
    check("`no permissions` 不解析成正常设备",
          len(perm) == 1 and perm[0]["state"] == "no permissions", perm)

    # ---- ② 判定顺序：找不到 adb 时，绝不能写成"没有设备" ----
    real_cands = T.candidates
    real_ver = T.version
    try:
        T.candidates = lambda: []
        T._RESOLVE_CACHE.clear()
        T.version = lambda *a, **k: ""
        info = T.snapshot([], "", missing=True)
        check("找不到 adb → found=False", info["found"] is False, info)
        check("★ 文案点明是 adb 找不到，而不是没有设备",
              "未找到 adb 可执行文件" in info["message"]
              and "未检测到测试机" not in info["message"], info["message"][:80])
        check("文案给出可执行的下一步",
              "PATH" in info["message"] and "重启" in info["message"], info["message"][:80])
    finally:
        T.candidates = real_cands
        T.version = real_ver
        T._RESOLVE_CACHE.clear()

    # ---- ③ adb 在、但设备列表为空：要能区分并给出排查顺序 ----
    info = T.snapshot([], "List of devices attached\n\n")
    if info["found"]:                      # 本机没装 adb 时跳过这两条（自检不能挑机器）
        check("adb 可用但没设备 → found=True 且 count=0",
              info["found"] is True and info["count"] == 0, info)
        check("★ 空列表文案给出排查顺序（USB 调试 / 授权 / 线 / 驱动 / 端口）",
              all(k in info["message"] for k in ("USB 调试", "允许 USB 调试", "数据线", "5037")),
              info["message"][:120])
        check("空列表文案带上实际使用的 adb 路径",
              info["exe"] in info["message"], info["message"][:80])

    # ---- ④ 有设备但未授权：说清是"没点允许"，不是"没检测到" ----
    info = T.snapshot([{"serial": "abc", "state": "unauthorized", "model": ""}])
    if info["found"]:
        check("未授权设备的文案指向手机上点「允许 USB 调试」",
              "允许 USB 调试" in info["message"] and "unauthorized" in info["message"],
              info["message"][:100])

    # ---- ⑤ 只有一份实现：各处不许再自己拼 ADB 环境变量 ----
    offenders = []
    for rel in ("piiscan/collector.py", "piiscan/teardown.py", "piiscan/crashinfo.py",
                "piiscan/device_ids.py", "piiscan/devices.py", "piiscan/preflight.py",
                "piiscan/uiwalk.py"):
        txt = (ROOT / rel).read_text(encoding="utf-8")
        for m in re.finditer(r'^.*os\.environ\.get\(\s*["\']ADB["\'].*$', txt, re.M):
            line = m.group(0).strip()
            # 只允许出现在 adbtool 之外的"文档性注释"里
            if line.startswith("#") or line.startswith('"""'):
                continue
            offenders.append("%s: %s" % (rel, line[:60]))
    check("★ 各处不再自行读 ADB 环境变量（唯一实现是 adbtool）",
          not offenders, offenders[:3])

    src = (ROOT / "piiscan" / "adbtool.py").read_text(encoding="utf-8")
    check("adbtool 搜索顺序含 SDK 目录与默认安装路径",
          all(k in src for k in ("ANDROID_HOME", "platform-tools", "shutil.which")), "")
    # 只查真正进界面的那段：message() 的返回值会被前端 innerHTML 直出，
    # 里面出现 `**` 就会原样显示成星号（2026-11-12 在 AI 提示文案上踩过）。
    _msg_at = src.find("def message(")
    _msg_end = src.find(chr(10) + "def ", _msg_at + 1) if _msg_at >= 0 else -1
    _msg_body = src[_msg_at:_msg_end] if _msg_at >= 0 and _msg_end > 0 else ""
    check("message() 里没有 markdown 星号（界面 innerHTML 直出会原样显示）",
          bool(_msg_body) and "**" not in _msg_body,
          "未找到 message()" if not _msg_body else "存在 **")

    # ---- ⑥ 接口把结论带出去（界面照实转述，不自己编原因）----
    html = (ROOT / "webapp" / "static" / "index.html").read_text(encoding="utf-8")
    check("界面接收 adb 结论", "ADB_INFO = (r && r.adb) || {}" in html, "")
    check("界面空列表时不写死原因，改走 adbTipHtml()", "adbTipHtml()" in html, "")
    check("界面能显示『未找到 adb』这一态", "（未找到 adb）" in html, "")

    srv = (ROOT / "webapp" / "server.py").read_text(encoding="utf-8")
    check("server 区分 FileNotFoundError 与其它异常",
          "except FileNotFoundError:" in srv and "missing = True" in srv, "")
    check("/api/devices 返回 adb 字段", '"adb": dict(_DEV_CACHE.get("adb") or {})' in srv, "")

    # ---- ⑦ 真起一个服务，确认接口形状（不依赖本机是否装 adb）----
    from webapp import server as S
    from webapp.db import JobDB

    tmp = Path(tempfile.mkdtemp(prefix="piiscan_adb_"))
    S.Handler.db = JobDB(tmp / "jobs.db")
    S.Handler.workdir = tmp
    S.Handler.device_enabled = True
    httpd = S.ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
    httpd.quiet = True
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        st, body = _json("http://127.0.0.1:%d/api/devices" % httpd.server_address[1])
        adb = body.get("adb") or {}
        check("/api/devices 含 adb 块", st == 200 and isinstance(adb, dict), (st, body.keys()))
        check("adb 块里有 found / message",
              isinstance(adb.get("found"), bool) and bool(adb.get("message")), adb)
        check("adb 块里的 exe 非空", bool(adb.get("exe")), adb)
    finally:
        httpd.shutdown()
