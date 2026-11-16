#!/usr/bin/env python3
"""平台层离线自测：任务状态机 / 环境自检 / 作业编排。

跑法：python tools/platform_selftest.py

这三块都要在没有真机、没有网络的情况下可验证 ——
因为它们恰好是"无人值守"时最先出事的地方：
设备没连上、任务停不下来、取消后没恢复环境。
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OK = 0
FAIL_C = 0
BAD = []


def check(name, cond, got=""):
    global OK, FAIL_C
    if cond:
        OK += 1
    else:
        FAIL_C += 1
        BAD.append("%s（实际：%r）" % (name, got))


# ============================================================================
#  ① 任务状态机
# ============================================================================

def t_db_create_is_atomic():
    """上传分支必须在一条 INSERT 里落地 apk_path。

    真实事故：create() 先置 queued、再 update(apk_path) 补文件路径。
    worker 恰好在这两步之间醒来取走任务，拿到的是 apk_path 为空的快照，
    于是明明传上来了 134MB 的 APK，任务却以「取不到目标包名」失败。
    """
    from webapp.db import JobDB

    with tempfile.TemporaryDirectory() as td:
        db = JobDB(Path(td) / "jobs.db")
        jid = db.create(source="upload", apk_name="x.apk",
                        apk_path="D:/tmp/x.apk", apk_size=140004505)
        j = db.get(jid)
        check("建任务即带 apk_path（不依赖后续 update）",
              j["apk_path"] == "D:/tmp/x.apk", j["apk_path"])
        check("建任务即带 apk_size", j["apk_size"] == 140004505, j["apk_size"])

        nq = db.next_queued()
        check("取队列时 apk_path 已是最终值", nq and nq["apk_path"] == "D:/tmp/x.apk",
              nq and nq["apk_path"])

        # 链接模式没有本地路径，取出来应是空串而不是 None —— 下游靠它判真假
        jid2 = db.create(source="url", apk_url="https://a/b.apk")
        nq2 = db.get(jid2)
        check("链接模式 apk_path 为空串", nq2["apk_path"] == "", nq2["apk_path"])
        check("链接模式 apk_size 为 0", nq2["apk_size"] == 0, nq2["apk_size"])


def t_db_state_machine():
    from webapp.db import JobDB

    with tempfile.TemporaryDirectory() as td:
        db = JobDB(Path(td) / "jobs.db")
        jid = db.create(source="upload", apk_name="a.apk")

        j = db.get(jid)
        check("新建任务为 queued", j["status"] == "queued", j["status"])

        # --- 排队中暂停 → paused，且不会被执行器取走 ---
        r = db.request(jid, "pause")
        check("排队中可暂停", r["ok"] and r["status"] == "paused", r)
        check("已暂停的任务不会被取出执行", db.next_queued() is None)
        check("暂停状态不丢", db.get(jid)["status"] == "paused")

        # --- 恢复 → 回到队列 ---
        r = db.request(jid, "resume")
        check("暂停可恢复", r["ok"] and r["status"] == "queued", r)
        check("恢复后能被取出执行", (db.next_queued() or {}).get("id") == jid)

        # --- 运行中：只能投递请求，不能直接改状态 ---
        job = db.get(jid)
        check("取出后状态为 running", job["status"] == "running", job["status"])
        r = db.request(jid, "cancel")
        check("运行中停止是投递请求而不是直接改状态",
              r["ok"] and r["status"] == "running", r)
        check("请求已写入信箱", db.take_request(jid) == "cancel", db.take_request(jid))
        check("请求生效前状态仍是 running", db.get(jid)["status"] == "running")

        # --- worker 收尾：请求清掉、状态落地 ---
        db.clear_request(jid, status="canceled", stage="已停止", progress=100)
        check("清请求后信箱为空", db.take_request(jid) == "")
        check("状态落到 canceled", db.get(jid)["status"] == "canceled")

        # --- 已停止的任务可重试 ---
        r = db.request(jid, "retry")
        check("已停止可重试", r["ok"] and r["status"] == "queued", r)

        # --- 非法操作要拒绝，且给出原因而不是静默 ---
        r = db.request(jid, "resume")
        check("排队中不能 resume", not r["ok"] and "只有已暂停" in r["error"], r)

        # --- 允许动作表与状态一致（前端据此渲染按钮）---
        from webapp.db import ALLOWED_ACTIONS
        # front＝置顶到队头，只有排队中的任务才有意义
        check("queued 可置顶/暂停/停止/删除",
              set(ALLOWED_ACTIONS["queued"]) == {"front", "pause", "cancel", "delete"})
        check("只有 queued 能置顶（跑着的没法提前）",
              all("front" in ALLOWED_ACTIONS[s] for s in ("queued",))
              and not any("front" in ALLOWED_ACTIONS[s]
                          for s in ("paused", "running", "done")),
              {s: ALLOWED_ACTIONS[s] for s in ("paused", "running", "done")})
        check("paused 可恢复/停止/删除",
              set(ALLOWED_ACTIONS["paused"]) == {"resume", "cancel", "delete"})
        check("running 不能删除（必须先停止）",
              "delete" not in ALLOWED_ACTIONS["running"])
        check("done 可重试/删除",
              set(ALLOWED_ACTIONS["done"]) == {"retry", "delete"})

        # --- 删除：running 拒删，其他连文件一起清 ---
        job2 = db.create(source="upload", apk_name="b.apk")
        db.next_queued()
        running_id = (db.get(job2) or {})
        # 上面 next_queued 取的可能是 job（已 queued），这里显式置 running 再删
        db.update(job2, status="running")
        r = db.delete(job2)
        check("运行中任务不允许删除", not r["ok"] and "先停止" in r["error"], r)

        wd = Path(td) / "jobdir"
        wd.mkdir()
        (wd / "report.html").write_text("x", encoding="utf-8")
        db.update(job2, status="done", workdir=str(wd))
        r = db.delete(job2)
        check("已结束任务可删除", r["ok"], r)
        check("任务记录已移除", db.get(job2) is None)
        check("工作目录一并清理", not wd.exists())

        # --- 服务重启：running 一律标记失败并留下提示 ---
        jid3 = db.create(source="upload", apk_name="c.apk")
        db.update(jid3, status="running")
        n = db.cleanup_stale()
        check("重启清理标记了 running 任务", n >= 1, n)
        j3 = db.get(jid3)
        check("重启后状态为 failed", j3["status"] == "failed", j3["status"])
        check("重启提示里写明可能未卸载",
              "卸载" in (j3["error"] or ""), j3["error"])


def t_db_stall_heartbeat():
    """进度心跳与"卡死可见"。

    无人值守时最危险的故障形态是：状态 running、进度条停着、日志停在半小时前，
    而队列后面还排着十个任务。没有心跳字段就无法把"正在慢慢跑"和"卡死了"分开。
    """
    from webapp.db import JobDB

    with tempfile.TemporaryDirectory() as td:
        db = JobDB(Path(td) / "jobs.db")
        jid = db.create(source="upload", apk_name="a.apk")
        db.next_queued()                      # 取出 → running
        j = db.get(jid)
        check("取出执行时写入心跳", j.get("heartbeat_at"), j.get("heartbeat_at"))

        rows = db.list(10)
        check("列表带 stall 字段", "stall" in (rows[0] if rows else {}), rows[0] if rows else None)
        check("刚启动不算停滞", (rows[0]["stall"] if rows else 999) < 5, rows)

        db.update(jid, stage="采集", progress=40)
        check("阶段更新刷新心跳", (time.time() - db.get(jid)["heartbeat_at"]) < 2)

        # --- 日志也算"活着"（用户 2026-10-21 第二条：遍历中百分比不动≠卡死）---
        db.update(jid, heartbeat_at=time.time() - 600)
        db.append_log(jid, "    [UI] 12. 点击「设置」（TextView）")
        check("★ 普通日志行刷新心跳（正在遍历 = 还活着）",
              (time.time() - db.get(jid)["heartbeat_at"]) < 2)
        db.update(jid, heartbeat_at=time.time() - 600)
        db.append_log(jid, "[!] 已 10 分钟没有日志", live=False)
        check("看门狗自己的提醒不刷新心跳（否则永远只提醒一次）",
              (time.time() - db.get(jid)["heartbeat_at"]) >= 590)

        # 伪造 10 分钟没动
        db.update(jid, heartbeat_at=time.time() - 600)
        row = [r for r in db.list(10) if r["id"] == jid][0]
        check("进度停滞能被算出", row["stall"] >= 590, row["stall"])

        # 已完成的任务不再报停滞
        db.update(jid, status="done", stage="完成", progress=100)
        row = [r for r in db.list(10) if r["id"] == jid][0]
        check("已完成任务不报停滞", row["stall"] == 0, row["stall"])

        # --- 服务重启恢复：running 的必须落到 failed 并留下提醒 ---
        jid2 = db.create(source="upload", apk_name="b.apk")
        db.next_queued()
        check("重启前存在 running 任务", db.get(jid2)["status"] == "running")
        n = db.cleanup_stale()
        check("重启恢复把中断任务标记为失败", n == 1 and db.get(jid2)["status"] == "failed",
              (n, db.get(jid2)["status"]))
        check("重启恢复时提示可能未完成卸载",
              "卸载" in (db.get(jid2)["error"] or ""), db.get(jid2)["error"])


def t_db_retry_archives_products():
    from webapp.db import JobDB
    with tempfile.TemporaryDirectory() as td:
        db = JobDB(Path(td) / "jobs.db")
        jid = db.create(source="upload", apk_name="a.apk")
        wd = Path(td) / "j1"
        wd.mkdir()
        (wd / "report.html").write_text("old", encoding="utf-8")
        db.update(jid, status="done", workdir=str(wd), report_path=str(wd / "report.html"))
        r = db.request(jid, "retry")
        check("重试后回到队列", r["ok"] and r["status"] == "queued", r)
        check("旧报告被改名留档（不被覆盖）",
              any(p.name.startswith("report.html.prev-") for p in wd.iterdir()),
              [p.name for p in wd.iterdir()])
        check("重试清掉上一轮的错误原因", db.get(jid)["error"] == "")


# ============================================================================
#  ② 环境自检（不接真机，靠桩）
# ============================================================================

class _FakeAdb:
    """按命令内容返回预设输出的假 adb。"""

    def __init__(self, devices="", props=None, root=True, procs="", ls=""):
        self.devices = devices
        self.props = props or {}
        self.root = root
        self.procs = procs
        self.ls = ls
        self.calls = []

    def __call__(self, args, timeout=30):
        self.calls.append(list(args))
        cmd = " ".join(args)
        out = ""
        if "devices" in args:
            out = "List of devices attached\n" + self.devices
        elif "getprop" in args:
            out = self.props.get(args[-1], "")
        elif "su -c id" in cmd:
            out = "uid=0(root) gid=0(root)" if self.root else "su: not found"
        elif "ps -A" in cmd:
            out = self.procs
        elif args[:2] == ["shell", "ls"] or cmd.startswith("shell ls"):
            out = self.ls
        elif "echo" in args:
            out = "piiscan-ok"
        return subprocess.CompletedProcess(args, 0, out.encode(), b"")


def _preflight_with(fake):
    from piiscan import preflight as PF
    old = PF._run
    PF._run = fake
    return PF, old


def t_preflight_device_selection():
    from piiscan import preflight as PF

    # --- 解析 adb devices -l ---
    fake = _FakeAdb(devices="abc123\tdevice product:phoenix model:Redmi_K30 device:phoenix\n")
    PF, old = _preflight_with(fake)
    try:
        devs = PF.list_devices()
        check("解析出设备", len(devs) == 1 and devs[0].serial == "abc123", devs)
        check("解析出型号", devs[0].model == "Redmi_K30", devs[0].model)
        check("解析出状态", devs[0].state == "device", devs[0].state)
    finally:
        PF._run = old

    # --- 没有设备：必须硬失败并说明怎么接 ---
    fake = _FakeAdb(devices="")
    PF, old = _preflight_with(fake)
    try:
        class C:
            class device:
                serial = ""
                frida_server = ""
            root = Path(".")
        rep = PF.run(C(), log=lambda *_a: None, auto_fix=False)
        check("无设备时自检不通过", rep.ok is False)
        chk = rep.get("device")
        check("无设备时给出接入提示",
              chk is not None and "USB" in chk.fix, chk.fix if chk else None)
    finally:
        PF._run = old

    # --- 多台设备：不猜，直接报错要求指定 ---
    fake = _FakeAdb(devices="aaa\tdevice model:A\nbbb\tdevice model:B\n")
    PF, old = _preflight_with(fake)
    try:
        class C:
            class device:
                serial = ""
                frida_server = ""
            root = Path(".")
        rep = PF.run(C(), log=lambda *_a: None, auto_fix=False)
        check("多台设备时不自动挑选", rep.ok is False)
        chk = rep.get("device")
        check("多台设备时要求显式指定 serial",
              chk is not None and "device.serial" in chk.fix, chk.fix if chk else None)
    finally:
        PF._run = old

    # --- 指定设备但离线 ---
    fake = _FakeAdb(devices="abc\toffline model:X\n")
    PF, old = _preflight_with(fake)
    try:
        class C:
            class device:
                serial = "abc"
                frida_server = ""
            root = Path(".")
        rep = PF.run(C(), log=lambda *_a: None, auto_fix=False)
        chk = rep.get("device")
        check("设备离线时判定失败", rep.ok is False and chk.ok is False)
        check("离线时提示授权/重插", "USB" in chk.fix or "offline" in chk.fix, chk.fix)
    finally:
        PF._run = old


def t_preflight_frida():
    from piiscan import preflight as PF

    # --- frida-server 已在跑且版本一致 → ok ---
    fake = _FakeAdb(
        devices="abc\tdevice model:X\n",
        props={"ro.product.model": "X", "ro.build.version.release": "12",
               "ro.build.version.sdk": "31", "ro.product.cpu.abi": "arm64-v8a"},
        procs="root 1 1 S frida-server-16.7.18-android-arm64\n")
    old_run, old_proc, old_ver = PF._run, PF._frida_proc, PF._local_frida_version
    PF._run = fake
    PF._frida_proc = lambda s: "frida-server-16.7.18-android-arm64"
    PF._local_frida_version = lambda: "16.7.18"
    try:
        c = PF.ensure_frida_server("abc", log=lambda *_a: None)
        check("frida-server 在跑 → ok", c.ok, c.detail)
        check("版本一致时不作额外动作", c.fixed is False)
    finally:
        PF._run, PF._frida_proc, PF._local_frida_version = old_run, old_proc, old_ver

    # --- 版本不一致 → 必须拦住（拦不住的后果是注入全失败）---
    old_run, old_proc, old_ver = PF._run, PF._frida_proc, PF._local_frida_version
    PF._run = fake
    PF._frida_proc = lambda s: "frida-server-16.5.0-android-arm64"
    PF._local_frida_version = lambda: "16.7.18"
    try:
        c = PF.ensure_frida_server("abc", log=lambda *_a: None)
        check("frida-server 版本不一致 → 失败", c.ok is False, c.detail)
        check("版本不一致时说明要换哪个版本",
              "16.7.18" in (c.fix or ""), c.fix)
    finally:
        PF._run, PF._frida_proc, PF._local_frida_version = old_run, old_proc, old_ver

    # --- frida-server 不在跑，但设备上已有二进制 → 自动启动 ---
    calls = {"n": 0}

    def _proc_after_start(s):
        # 第一次查为空，启动后查得到 —— 模拟真实时序
        calls["n"] += 1
        return "" if calls["n"] <= 1 else "frida-server-16.7.18-android-arm64"

    old_run, old_proc, old_ver, old_find = (
        PF._run, PF._frida_proc, PF._local_frida_version, PF._find_frida_bin)
    # 本机二进制用一个临时文件占位：原先这条用例依赖"开发机上恰好有个
    # frida-server 放在项目根/家目录"，在服务器上部署时那文件不存在，
    # 用例就变成假失败（报"本机也没找到可推送的二进制"）。测试不该
    # 依赖外部文件是否存在，这里显式造一个。
    _tmp_bin = Path(tempfile.mkdtemp(prefix="frida_bin_")) / "frida-server-16.7.18-android-arm64"
    _tmp_bin.write_bytes(b"\x7fELF fake")
    PF._run = fake
    PF._frida_proc = _proc_after_start
    PF._local_frida_version = lambda: "16.7.18"
    PF._find_frida_bin = lambda abi, ver, explicit="": (_tmp_bin, "测试用二进制")
    try:
        c = PF.ensure_frida_server("abc", log=lambda *_a: None)
        check("自动启动 frida-server 成功", c.ok, c.detail)
        check("自动启动的项标记为 fixed", c.fixed is True)
        check("启动命令带 -D（否则父进程一退服务就没了）",
              any("-D" in " ".join(x) for x in fake.calls), fake.calls[-3:])
    finally:
        PF._run, PF._frida_proc, PF._local_frida_version = old_run, old_proc, old_ver
        PF._find_frida_bin = old_find

    # --- 设备没有二进制、本机也没有 → 失败并说清怎么办 ---
    old_run, old_proc, old_ver, old_find = (
        PF._run, PF._frida_proc, PF._local_frida_version, PF._find_frida_bin)
    old_remotes = PF._remote_frida_names
    PF._run = fake
    PF._frida_proc = lambda s: ""
    PF._local_frida_version = lambda: "16.7.18"
    PF._remote_frida_names = lambda s: []
    PF._find_frida_bin = lambda abi, ver, explicit="": (
        None, "本机没找到任何 frida-server 二进制")
    try:
        c = PF.ensure_frida_server("abc", log=lambda *_a: None)
        check("两边都没有 frida-server → 失败", c.ok is False, c.detail)
        check("失败时告诉去哪放二进制或设环境变量",
              "FRIDA_SERVER" in (c.fix or ""), c.fix)
        check("失败时把设备 ABI 写进证据（否则会拿错 ABI 反复重试）",
              "arm64" in (c.detail or ""), c.detail)
    finally:
        PF._run, PF._frida_proc, PF._local_frida_version = old_run, old_proc, old_ver
        PF._find_frida_bin = old_find
        PF._remote_frida_names = old_remotes


def t_preflight_no_device_needed():
    from piiscan import preflight as PF
    fake = _FakeAdb(devices="")
    PF, old = _preflight_with(fake)
    try:
        class C:
            class device:
                serial = ""
                frida_server = ""
            root = Path(".")
        rep = PF.run(C(), log=lambda *_a: None, need_device=False)
        check("纯静态场景不要求设备", rep.ok is True, rep.summary())
        # adb 1 项 + 设备（不需要）1 项 + 模型接口 1 项
        check("纯静态场景只做必要检查", len(rep.checks) <= 3, len(rep.checks))
        # 静态阶段同样依赖模型（政策解析），所以纯静态也要验一次接口，
        # 但它是非致命项：模型挂了照样能出报告，只是少几项语义增强
        ai_c = [c for c in rep.checks if c.key == "ai_api"]
        check("纯静态也检查模型接口", len(ai_c) == 1, [c.key for c in rep.checks])
        check("模型检查是非致命项", bool(ai_c) and ai_c[0].fatal is False,
              ai_c[0].fatal if ai_c else None)
    finally:
        PF._run = old


# ============================================================================
#  ③ 作业编排（用例在 tools/_platform_job_tests.py）
# ============================================================================

def t_sop_job():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _platform_job_tests as JT
    JT.run(check)


# ============================================================================
#  ④ 界面导出的抗卡死能力（用例在 tools/_ui_dump_tests.py）
# ============================================================================

def t_ui_dump_resilience():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _ui_dump_tests as UT
    UT.run(check)


# ============================================================================
#  ⑤ 批量删除（用例在 tools/_batch_delete_tests.py）
# ============================================================================

def t_db_batch_delete():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _batch_delete_tests as BT
    BT.run(check)


def t_apk_store():
    """APK 共享存储：按内容去重、删任务按引用清理（离线）。

    这条链上最容易错的是"删"：删早了把别人还要用的包带走，删晚了磁盘
    永远不减少。用例同时钉住两种情况，以及"根目录之外的任何文件都不许碰"。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _apk_store_tests as AS
    AS.run(check)


# ============================================================================
#  ⑥ 调用栈归因（App 自身 / 第三方 SDK / 系统框架）
# ============================================================================

def t_stack_attribution():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _attribution_tests as AT
    AT.run(check)


# ============================================================================
#  ⑥ 前端批量选择的渲染逻辑（tools/ui_batch_check.js，用 node 跑）
# ============================================================================

def t_no_device_mode():
    """服务器部署形态：本机没有检测设备时的默认行为。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _no_device_tests as ND
    ND.run(check)


def t_queue_order():
    """排队顺序与置顶到队头（离线，不碰真机）。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _queue_tests as QT
    QT.run(check)


def t_device_lock():
    """设备占用只看内核文件锁，不看 .info 里的 PID（PID 会被复用）。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _device_lock_tests as DL
    DL.run(check)


def t_stuck_guard():
    """卡死与"停止无效"的防线：RPC 超时、失效快返、看门狗强制收工。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _stuck_guard_tests as SG
    SG.run(check)


def t_ui_pages():
    """界面分页结构：三页 + 侧边栏、默认落在系统状态、提交后跳列表。

    2026-11-11 用户要求：把「统计 + 设备 + 表单 + 列表」挤在一张长页上的
    界面改成侧边栏 + 三页。这里钉的是结构约定 —— 页容器与菜单项一一对应、
    每个区块归属正确的页、JS 引用的 id 都还在。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _ui_tests as UI
    UI.run(check)


def t_device_phone():
    """测试机 → 手机号的联动：选哪台就用那台的号，但显式空串仍是"不登录"。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _device_phone_tests as DP
    DP.run(check)


def t_device_mgmt():
    """手机管理：登记簿增删、接入流程（含失败停在正确步骤）、frida 二进制 ABI 匹配。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _device_mgmt_tests as DM
    DM.run(check)


def t_adb_diagnosis():
    """换一台机器部署时「未检测到测试机」的诊断：adb 找不到不能说成没设备。

    2026-11-12 用户把项目拉到另一台电脑上跑，Web 正常、手机插上，界面只写
    「未检测到测试机」。真实原因是那台机器上 adb 不在 PATH 里，而
    `list_test_devices()` 的 `except Exception: out = ""` 把 FileNotFoundError
    一起吞了 —— 没装 adb / 手机没插 / 没授权，三种毛病一句话。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _adb_tests as AD
    AD.run(check)


def t_ai_profile():
    """AI 模型服务档案（增删/启用/密钥不外泄/DeepSeek）+ 停止能打断模型调用。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _ai_profile_tests as AP
    AP.run(check)


def t_static_label():
    """没有 aapt 的机器（服务器）上，应用名会只剩一个资源引用。

    服务器上跑出来的第一版报告标题是「＠0x7f13003f App 个人信息保护合规
    检测报告」——AXML 里 label 是 resources.arsc 的索引，本机没 aapt 就
    解析不出显示名。换成包名，并且把"没拿到"写进 errors。
    """
    from piiscan import apkstatic as AS

    def _mk(label, pkg="cn.demo.app"):
        r = AS.StaticResult(apk_path="x.apk", filename="x.apk")
        r.package, r.app_label = pkg, label
        return r

    r1 = _mk("@0x7f13003f")
    AS._normalize_label(r1, lambda *_: None)
    check("资源引用型 label 退用包名", r1.app_label == "cn.demo.app", r1.app_label)
    check("解析失败记进 errors（不是悄悄换掉）",
          any("显示名未解析" in e for e in r1.errors), str(r1.errors)[:120])

    r2 = _mk("学丞")
    AS._normalize_label(r2, lambda *_: None)
    check("正常显示名不被改写", r2.app_label == "学丞", r2.app_label)
    check("正常显示名不产生 error", not r2.errors, str(r2.errors)[:120])

    r3 = _mk("@string/app_name")
    AS._normalize_label(r3, lambda *_: None)
    check("未解析的 @string/ 也退用包名", r3.app_label == "cn.demo.app", r3.app_label)

    r4 = _mk("@0x7f13003f", pkg="")
    AS._normalize_label(r4, lambda *_: None)
    check("连包名都没有时保持原样（不编造）", r4.app_label == "@0x7f13003f", r4.app_label)


def t_store_links():
    """应用商店链接：多行批量提交、失败跳过、队列继续。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _store_links_tests as ST
    ST.run(check)


def t_declaration():
    """政策/共享清单结构化解析 + 按 SDK 的声明与实测对照。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _declaration_tests as DT
    DT.run(check)


def t_perm_notice():
    """系统权限弹窗识别 + 「申请时是否同步告知目的」的判定分寸。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _perm_tests as PT
    PT.run(check)


def t_evidence():
    """结论与证据同源：描述里的每一类都要有栈、截图要对得上、跑不起来要算失败。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _evidence_tests as ET
    ET.run(check)


def t_hook_degrade():
    """注入失败要降级为「仅界面采集」，不能把整轮判死（小盒 2026-10-27）。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _hook_degrade_tests as HD
    HD.run(check)


def t_hook_js():
    """采集脚本的 install()/emit() 语义：被系统拒绝也要留痕（Android 10）。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _hook_js_tests as HJ
    HJ.run(check)


def t_login_assist():
    """登录辅助：验证码回填（文件轮询、用过即删）、手机号校验、报告账号口径。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _login_tests as LT
    LT.run(check)


def t_depth():
    """检测深度档：六个预算参数成套变化，且深度档不会被表单时长盖掉。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _depth_tests as DT
    DT.run(check)


def t_repro():
    """P7 复现：三种结论（已复现/未复现/未能判定）的口径与降级规则。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _repro_tests as RT
    RT.run(check)
    RT.run_sdk(check)
    RT.run_p7(check)


def t_crawl():
    """页面图观测（P4 Step 1）：指纹分寸、uid 稳定、落点判定、统计口径。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _crawl_tests as CT
    CT.run(check)


def t_sched():
    """遍历调度（P4 Step 2）：四态、tab 铺开、死点、回退、软禁、止损。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _sched_tests as ST
    ST.run(check)


def t_bypass():
    """旁路取证：注入被加固拦死时，从 appops / 运行时权限补系统侧证据。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _bypass_tests as BT
    BT.run(check)


def t_walk_guard():
    """遍历空转熔断：同一界面重复返回/滑动/上拉要判无效并换路径。

    2026-11-01：4 档（1 小时）实测只有 4~9 次真实点击，其余步数全是
    同一屏上的重复返回与滑动 —— 这是"1 小时档与 15 分钟档没区别"的根因。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _walk_guard_tests as WG
    WG.run(check)


def t_ledger():
    """遍历台账 + 循环/饱和判定（2026-11-01）。

    两个 1 小时档任务（川剧迷/冰纷万象）都在 A↔B 两屏来回，每步"界面都变了"，
    所以只看"界面没变"的熔断一次都没触发。这里测替代判据：同一元素能点几次、
    动作序列是否周期重复、还有没有新界面。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _ledger_tests as LT
    LT.run(check)


def t_occlusion():
    """遮挡剔除（2026-11-01 人工接管实测）。

    设置页「关于」被底部固定导航栏「图片墙」压住，点它实际切了 tab：
    白花一步，更糟的是后面每步判断都建立在错误前提上，日志里只写"点了关于"。
    这里守住两条边界：行内图标/文字不算遮挡（否则整页候选被误杀）、
    只压边角不算遮挡（点击打在中心点上）。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _occlusion_tests as OC
    OC.run(check)


def t_content_list():
    """内容型列表识别（2026-11-03）。

    川剧迷 1 小时档 80% 的时间花在公众号文章列表上：卡片没有文字也没有 id，
    原来的"同构抽样"认不出，于是一篇篇点进去。这里守住三条边界：
    资讯/商品列表要判得出、设置页绝不能误判、政策页与注销入口不受影响。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _content_tests as CT
    CT.run(check)


def t_docread():
    """外部界面读文档 / 登录门 / 无进展看门狗（2026-11-03）。

    春雨诊所的政策在系统浏览器里（正文就在屏幕上却被判"读不到"）；
    高途卡在一个没能代点的权限弹窗上空转 56 分钟；万步健康与携船网
    点哪里都跳登录页 —— 这一组守住对应的识别与兜底闸门。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _docread_tests as DT
    DT.run(check)


def t_clickev():
    """逐次点击留痕（2026-11-05 用户要求）。

    报告原来只有"点击 124 次"这种合计数字，复核员看不出点在哪、凭什么点、
    点完有没有反应。这一组守住"图在点击之前取、判读与结果要配对、
    报告里真有这一节"，以及配套的三条熔断（榨干界面复访、注入自救上限、
    人机验证屏不遍历）。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _clickev_tests as CT
    CT.run(check)


def t_landing():
    """首启着陆（P3.5，2026-11-06 用户要求）。

    「点了同意」到「站在主页面」之间那一段，四台真机实测出四种不同形态
    （开屏广告 / 年龄门 / 登录页 / 登录墙）。拿通用遍历去闯这一段，
    代价不是多走几步，而是整份报告作废 —— 所以判据必须离线钉死：
    广告主体、兴趣标签、立即更新一律不点，登录页不代填，主页面要连续两次
    且指纹稳定才算到。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _landing_tests as LD
    LD.run(check)


def t_policy_evidence():
    """政策取证（2026-11-08）：内联链接候选、取证判据、同意闸门、注入脚本能力。

    起因：岛 / 小包搜题 / 快搜搜题三家都没拿到隐私政策，但首启弹窗上确实
    有入口 —— 一个藏在正文文字里、两个因窗口错过而没测到，且三家都在
    "政策没取到"的情况下点了同意。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _policy_tests as PT
    PT.run(check)


def t_oracle():
    """外部决策通道（2026-11-01）。

    为了让"人/更强的模型"能接管遍历做诊断：把现场落盘、等回答、按回答执行。
    三条保命规则必须成立 —— 不回答要按时返回（不能挂死检测）、
    回答序号不符要丢弃（照它执行会点错界面）、通道异常不能让采集崩。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _oracle_tests as OT
    OT.run(check)


def t_list():
    """列表遍历（P4 Step 3）：列表识别、上拉加载、定向入口、覆盖明细与报告措辞。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _list_tests as LT
    LT.run(check)


def t_ui_batch_logic():
    """列表每 3 秒整体重渲，勾选状态、禁用规则、自动剔除都只活在前端。

    这部分坏了不会报错，只会表现成"勾了半天，点删除发现少了几项"。
    有 node 就跑，没有就跳过（不把磁盘环境当失败）。
    """
    node = shutil.which("node")
    if not node:
        for c in (Path.home() / ".workbuddy" / "binaries" / "node",
                  Path("C:/Users/mctc/.workbuddy/binaries/node")):
            if c.exists():
                cand = sorted(c.glob("versions/*/node.exe"))
                if cand:
                    node = str(cand[-1])
                    break
    if not node:
        print("  (跳过：未找到 node)")
        return
    r = subprocess.run([node, str(Path(__file__).resolve().parent / "ui_batch_check.js")],
                       capture_output=True, text=True)
    tail = (r.stdout or "").strip().splitlines()
    for line in tail[-2:]:
        print("  " + line.strip())
    check("前端批量选择逻辑（选中保留/禁用运行中/自动剔除）", r.returncode == 0,
          (r.stdout or "") + (r.stderr or ""))


def t_ai_locks():
    """AI 环节开关的固定/可选边界。

    政策视觉与政策深读**固定启用**（界面不给勾选、任务级传 0 也无效），
    UI 遍历是唯一可改项。这三条都属于"坏了不报错、只表现为界面与实际不一致"
    的类型，必须用测试钉住 —— 界面显示"没勾"而实际在跑，是检查报告里最看不
    出来的一种偏差。
    """
    from webapp.server import apply_ai_opts
    from piiscan.config import AppConfig

    def cfg_all_off():
        c = AppConfig()
        c.ai.provider = "ollama"
        c.ai.model = "m"
        c.ai.features = {"policy_vision": False, "policy_analyze": False,
                         "ui_agent": False}
        return c

    # ① 服务端配置写成 false、任务又不带参数 → 两项仍被强制启用
    c = cfg_all_off()
    logs = []
    apply_ai_opts(c, {}, logs.append)
    check("政策视觉固定启用（配置写成 false 也不生效）",
          c.ai.feature("policy_vision") is True)
    check("政策深读固定启用（配置写成 false 也不生效）",
          c.ai.feature("policy_analyze") is True)
    check("固定启用要写进日志（可自证）",
          any("固定启用" in x for x in logs), logs)

    # ② 前端显式传 0 → 仍然启用
    c = cfg_all_off()
    apply_ai_opts(c, {"ai_opts": json.dumps(
        {"ai_policy_vision": 0, "ai_policy_analyze": 0, "ai_ui_agent": 1})},
        lambda _m: None)
    check("任务级传 0 不能关掉政策视觉", c.ai.feature("policy_vision") is True)
    check("任务级传 0 不能关掉政策深读", c.ai.feature("policy_analyze") is True)

    # ③ UI 遍历必须能关，也必须是默认开（唯一可选项）
    c = cfg_all_off()
    apply_ai_opts(c, {"ai_opts": json.dumps(
        {"ai_policy_vision": 1, "ai_policy_analyze": 1, "ai_ui_agent": 0})},
        lambda _m: None)
    check("UI 遍历可以被关掉", c.ai.feature("ui_agent") is False)
    c2 = cfg_all_off()
    apply_ai_opts(c2, {"ai_opts": json.dumps(
        {"ai_policy_vision": 1, "ai_policy_analyze": 1, "ai_ui_agent": 1})},
        lambda _m: None)
    check("UI 遍历可以被打开", c2.ai.feature("ui_agent") is True)

    # ④ 没配模型服务时必须明说"会回退"，不能只说"已启用"
    c = cfg_all_off()
    c.ai.provider = "none"
    logs = []
    apply_ai_opts(c, {"ai_opts": json.dumps({"ai_ui_agent": 1})}, logs.append)
    check("未配模型服务时日志写明回退",
          any("回退到确定性策略" in x for x in logs), logs)

    # ⑤ 视觉闸门看"任一视觉环节"：只开 UI 遍历时也必须有视觉能力，
    #    否则 plan_ui_action/choose_action 全部返回 None 而日志仍写"参与 UI 遍历"
    c = cfg_all_off()
    c.ai.features["ui_agent"] = True
    check("只开 UI 遍历时 vision_ready 为真", c.ai.vision_ready() is True)
    c.ai.features["ui_agent"] = False
    check("两个视觉环节都关时 vision_ready 为假", c.ai.vision_ready() is False)

    # ⑥ 前端契约：锁定项 disabled+checked；UI 遍历默认勾且可改；
    #    提交时恒传前两项为 1 —— 否则"全不勾"会回落到 config.yaml（界面撒谎）
    html = (ROOT / "webapp" / "static" / "index.html").read_text(encoding="utf-8")
    for cid in ("ai_policy_vision", "ai_policy_analyze"):
        m = re.search(r'<input[^>]*id="%s"[^>]*>' % cid, html)
        tag = m.group(0) if m else ""
        check("前端「%s」锁定为 checked + disabled" % cid,
              bool(m) and "checked" in tag and "disabled" in tag, tag)
    m = re.search(r'<input[^>]*id="ai_ui_agent"[^>]*>', html)
    tag = m.group(0) if m else ""
    check("前端「ai_ui_agent」默认勾选且可取消",
          bool(m) and "checked" in tag and "disabled" not in tag, tag)
    check("前端恒提交 policy_vision=1",
          'fd.append("ai_policy_vision", "1")' in html)
    check("前端恒提交 policy_analyze=1",
          'fd.append("ai_policy_analyze", "1")' in html)
    check("前端 UI 遍历按勾选提交（取消即真的关）",
          'fd.append("ai_ui_agent", $("#ai_ui_agent").checked ? "1" : "0")' in html)


def main() -> int:
    print("平台层离线自测（任务状态机 / 环境自检 / 作业编排）")
    print("=" * 68)
    t_db_create_is_atomic()
    t_db_state_machine()
    t_db_stall_heartbeat()
    t_db_retry_archives_products()
    t_preflight_device_selection()
    t_preflight_frida()
    t_preflight_no_device_needed()
    t_sop_job()
    t_ui_dump_resilience()
    t_db_batch_delete()
    t_apk_store()
    t_stack_attribution()
    t_no_device_mode()
    t_queue_order()
    t_device_lock()
    t_device_phone()
    t_device_mgmt()
    t_adb_diagnosis()
    t_ai_profile()
    t_stuck_guard()
    t_ui_pages()
    t_static_label()
    t_store_links()
    t_declaration()
    t_perm_notice()
    t_evidence()
    t_hook_degrade()
    t_hook_js()
    t_login_assist()
    t_repro()
    t_depth()
    t_crawl()
    t_sched()
    t_bypass()
    t_walk_guard()
    t_ledger()
    t_content_list()
    t_docread()
    t_clickev()
    t_landing()
    t_policy_evidence()
    t_oracle()
    t_occlusion()
    t_list()
    t_ui_batch_logic()
    t_ai_locks()
    print("=" * 68)
    print("结果：%d 项通过，%d 项失败" % (OK, FAIL_C))
    if BAD:
        print("\n失败明细：")
        for b in BAD:
            print("  · %s" % b)
        return 1
    print("全部通过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
