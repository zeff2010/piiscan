#!/usr/bin/env python3
"""设备瞬时掉线自愈 + 自检报错口径的自测。

为什么这些用例值得钉住
----------------------
2026-10-26 批量实测取证（从 jobs.db 的空闲页里捞回来的失败任务
`J20261026190340-a57041`）：

    [自检] [OK ] adb 可用 / 自动发现设备 / shell / 设备信息 / root / 屏幕
    [自检] [ERR] 界面结构可读取（uiautomator）：拔插数据线后重试
    [自检] [ERR] frida-server 运行中 / frida 可连接设备
    [!] 收尾后设备未就绪（adb get-state → error: no devices/emulators found）
    [=] 收尾完成，设备已就绪（耗时 2.2 秒）      ← 两秒后它自己回来了

也就是说：设备**没有坏**，只是 USB 偶发重新枚举时短暂从 adb 里消失；
自检恰好落在那两秒里，把「暂时不在」判成「环境不可用」，整轮检测失败。
而提示写的是「拔插数据线后重试」——真因被建议盖住了，只能靠人去试。

所以这里钉三条：
  ① `link_down()` 认得这类文本（device offline / no devices / closed…）；
  ② `ensure_device()` 会等，等到了就恢复；等不到也如实说最后状态；
  ③ 自检的报错文本**先给原因、再给建议**，不能只剩建议。

跑法：python tools/_device_recovery_tests.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from piiscan import uiwalk as U              # noqa: E402
from piiscan import preflight as P           # noqa: E402


class _Fake:
    """假 CompletedProcess：`ensure_device` 里会调 adb，测试不能真连设备。"""

    returncode = 0
    stdout = b""
    stderr = b""

    def __init__(self, out: str = "", code: int = 0):
        self.stdout = out.encode()
        self.returncode = code


def run(check):
    # ---------------------------------------------------------------- ① 文本判据
    for t in ("error: no devices/emulators found",
              "error: device offline",
              "error: device not found",
              "error: closed",
              "adb: device still authorizing",
              "ERROR: could not install *smartsocket* listener: cannot connect to daemon"):
        check("认得掉线文本：%s" % t[:32], U.link_down(t), t)

    for t in ("", None, "device", "error: package not found",
              "Failure [INSTALL_FAILED_ALREADY_EXISTS]", "Success"):
        check("不误判正常输出：%r" % (t,), not U.link_down(t), t)

    check("大小写不敏感", U.link_down("Error: Device Offline"), "")
    check("异常对象也能判", U.link_down(RuntimeError("error: closed")), "")

    # ---------------------------------------------------------------- ② 等待自愈
    calls = {"adb": 0, "logs": []}
    real_adb, real_state = U._adb, U.device_state

    def fake_adb(serial, *args, timeout=25, **kw):
        calls["adb"] += 1
        return _Fake()

    try:
        # (a) 一开始就在：立即返回，不碰 reconnect
        U._adb = fake_adb
        U.device_state = lambda serial="": "device"
        ok, note = U.ensure_device("S", wait_s=2.0, log=lambda s: calls["logs"].append(s))
        check("设备在线时立即通过", ok and note == "", (ok, note))
        check("设备在线时不调用任何 adb 命令", calls["adb"] == 0, calls["adb"])

        # (b) 抖三下再回来：应该等到，并且报告等了多久
        seq = ["error: no devices/emulators found"] * 3 + ["device"]
        U.device_state = lambda serial="": seq.pop(0) if seq else "device"
        t0 = time.time()
        ok, note = U.ensure_device("S", wait_s=10.0, log=lambda s: calls["logs"].append(s))
        dt = time.time() - t0
        check("掉线后能等到恢复", ok, (ok, note))
        check("说明里写了等待时长", "等待" in note and "恢复" in note, note)
        check("确实是等了一会儿（不是立即判死）", dt >= 1.5, "%.2fs" % dt)
        check("等待期间留下了日志", len(calls["logs"]) > 0, calls["logs"][:2])

        # (c) 一直不回来：如实返回 False + 最后状态，不假装成功
        U.device_state = lambda serial="": "error: no devices/emulators found"
        ok, note = U.ensure_device("S", wait_s=2.5, log=lambda s: None)
        check("设备不回来时判 False", ok is False, ok)
        check("失败说明里有最后状态", "no devices" in note, note)

        # (d) offline → 应发出 reconnect offline（设备端可能只是授权/重连）
        calls["adb"] = 0
        seq = ["offline", "offline", "offline", "device"]
        U.device_state = lambda serial="": seq.pop(0) if seq else "device"
        ok, _n = U.ensure_device("S", wait_s=8.0, log=lambda s: None)
        check("offline 场景也会等到恢复", ok, ok)
        check("中段发过 reconnect（offline 或普通）", calls["adb"] > 0, calls["adb"])

        # (e) 等待窗口很短时不能拖太久
        U.device_state = lambda serial="": "error: no devices/emulators found"
        t0 = time.time()
        U.ensure_device("S", wait_s=1.0, log=lambda s: None)
        check("wait_s=1 时不超时太久（<4s）", time.time() - t0 < 4.0,
              "%.1fs" % (time.time() - t0))
    finally:
        U._adb, U.device_state = real_adb, real_state

    # ---------------------------------------------------------------- ③ 报错口径
    c = P.Check("ui_dump", "界面结构可读取（uiautomator）", False,
                "uiautomator dump 无有效输出（18.0s）；此刻 adb get-state："
                "error: no devices/emulators found",
                "拔插数据线后重试")
    e = P._explain(c)
    check("报错里有真因（no devices）", "no devices" in e, e)
    check("报错里也有建议", "拔插" in e, e)
    check("真因排在建议之前", e.index("no devices") < e.index("拔插"), e)
    check("建议前面有「若持续出现」的分寸", "若持续出现" in e, e)

    c2 = P.Check("x", "某检查", False, "", "只给了建议")
    check("无 detail 时退回建议", P._explain(c2) == "只给了建议", P._explain(c2))
    c3 = P.Check("x", "某检查", False, "", "")
    check("两者都空也不留白", "未记录原因" in P._explain(c3), P._explain(c3))
    c4 = P.Check("x", "某检查", False, "x" * 600, "y" * 600)
    check("长输出被截断（<400 字）", len(P._explain(c4)) < 400, len(P._explain(c4)))

    rep = P.PreflightReport()
    rep.add(P.Check("ui_dump", "界面结构可读取（uiautomator）", False,
                    "此刻 adb get-state：error: no devices/emulators found",
                    "拔插数据线后重试"))
    rep.add(P.Check("adb", "adb 可用", True, "adb 1.0.41"))
    rep.ok = False
    s = rep.summary()
    check("汇总里带得出真因", "no devices" in s, s)
    check("汇总只列阻断项（通过的项不出现）", "adb 可用" not in s, s)
    b = " ".join(rep.brief())
    check("逐项简表也带真因", "no devices" in b, b)

    # ---------------------------------------------------------------- ④ 结构护栏
    # 这两条是"防回退"：改动很容易被下一次重构抹掉，而它们对应的都是
    # 已经真实发生过的事故（设备留在浏览器、复现轮为一次外跳丢掉整条路径）。
    src_col = (ROOT / "piiscan" / "collector.py").read_text(encoding="utf-8")
    i = src_col.find("def _ensure_in_app()")
    body = src_col[i:i + 4000]
    check("复现守卫里保留 launch_app 兜底", "launch_app(serial, package)" in body, "")
    check("复现守卫失败时写明当前前台包名", "当前=%s" in body, "")

    src_job = (ROOT / "piiscan" / "sop_job.py").read_text(encoding="utf-8")
    check("收尾有界面复位", "def _reset_screen()" in src_job, "")
    check("复位在三类收尾都调用（正常/取消/失败）",
          src_job.count("_reset_screen()") >= 3, src_job.count("_reset_screen()"))
    check("离线重渲染不碰设备", "if not do_device:" in src_job, "")

    src_pf = (ROOT / "piiscan" / "preflight.py").read_text(encoding="utf-8")
    check("自检失败后会先等设备回来（不是当场判死）",
          "ensure_device" in src_pf, "")
    check("界面导出失败时记录底层原因",
          "底层原因" in src_pf, "")
    check("自检的设备发现阶段也会等设备", "dev_wait" in src_pf, "")


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
