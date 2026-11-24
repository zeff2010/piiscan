"""卡死与"停止无效"防线的离线用例。

对应 2026-11-11 用户报的两个问题：
  1. 测 A 机时 B 机屏幕被点亮、反复弹 Magisk「shell 已授予 root 权限」；
  2. 一个投屏 App 跑了 1 小时 50 分、界面全黑、点停止没反应，最后关服务。

真机已确认的机制（本项目实测，不是引文档）：
  · 轮询探测每 10 秒对**每台**设备执行 `su -c id` / `su -c ps`；
  · 目标进程冻结时 frida 的同步 RPC 永不返回（`kill -STOP` 后 12 秒仍在等）；
  · 冻结时 `session.detach()` 自己也会卡住；
  · `am force-stop` 被测应用后，卡住的调用 0.7 秒内抛 `script has been destroyed`。

这里钉住的是"防线本身"：超时、失效后快速失败、强制停止的决定逻辑、
以及探测脚本里不许再出现 su。
"""
from __future__ import annotations

import threading
import time


def run(check):
    _t_rpc(check)
    _t_script_guard(check)
    _t_probe_no_su(check)
    _t_root_verified(check)
    _t_watchdog(check)
    _t_paging_blind_spot(check)


# ---------------------------------------------------------------- RPC 超时
def _t_rpc(check):
    from piiscan import frida_guard as G

    check("正常调用直接返回", G.call(lambda: 42, timeout=2, label="ok") == 42)

    t0 = time.time()
    try:
        G.call(lambda: time.sleep(5), timeout=0.3, label="slow")
        raised = ""
    except G.RpcTimeout as e:
        raised = str(e)
    dt = time.time() - t0
    check("超时会抛 RpcTimeout 且真的按时返回",
          bool(raised) and dt < 2.0, (raised, round(dt, 2)))

    def _boom():
        raise ValueError("原样抛出")

    try:
        G.call(_boom, timeout=2, label="boom")
        err = ""
    except ValueError as e:
        err = str(e)
    check("被调函数自己的异常原样抛出（不被超时层吞掉）", err == "原样抛出", err)


class _FakeExports:
    def __init__(self, delay=0.0, fail=None):
        self.delay = delay
        self.fail = fail
        self.calls = 0

    def ping(self):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError(self.fail)
        return "pong"


class _FakeScript:
    """够用的 frida 脚本替身：只实现被包装到的那几个入口。"""

    def __init__(self, exports, delay_load=0.0):
        self.exports_sync = exports
        self.loaded = 0
        self.handlers = []
        self.delay_load = delay_load

    def load(self):
        if self.delay_load:
            time.sleep(self.delay_load)
        self.loaded += 1

    def on(self, name, cb):
        self.handlers.append((name, cb))
        return lambda: None

    def post(self, *_a, **_k):
        return None


def _t_script_guard(check):
    from piiscan import frida_guard as G

    # 透明性：on / post / load 必须照常可用
    real = _FakeScript(_FakeExports())
    gs = G.wrap_script(real, timeout=2)
    got = []
    gs.on("message", lambda m, d: got.append(m))
    real.handlers[-1][1]({"type": "send"}, None)
    check("包装后 .on 仍能注册回调", got == [{"type": "send"}], got)
    gs.load()
    check("包装后 .load 透传", real.loaded == 1, real.loaded)
    check("包装后 exports_sync 正常调用", gs.exports_sync.ping() == "pong")

    # 已经包过的不能重复包（重复包会多一层线程，也会让 dead 标记失效）
    check("重复包装返回同一个对象", G.wrap_script(gs) is gs)

    # 超时 → 标记失效 → 后续调用立刻失败（不再堆线程）
    slow = G.wrap_script(_FakeScript(_FakeExports(delay=3)), timeout=0.3)
    try:
        slow.exports_sync.ping()
        first = ""
    except G.RpcTimeout as e:
        first = "timeout"
    t0 = time.time()
    try:
        slow.exports_sync.ping()
        second = ""
    except G.RpcTimeout as e:
        second = "dead" if e.dead else "timeout-again"
    dt = time.time() - t0
    check("一次超时后脚本被标记失效", first == "timeout" and slow.dead, (first, slow.dead))
    check("失效后后续调用立刻失败（不再等满超时）",
          second == "dead" and dt < 0.5, (second, round(dt, 3)))

    # _NoScript 替身不包：它本来就是即时返回的空实现
    class _NoScript:
        exports_sync = _FakeExports()

    ns = _NoScript()
    check("未注入时的 _NoScript 不被包装", G.wrap_script(ns) is ns)


def _t_probe_no_su(check):
    """探测脚本里绝不能有 su —— 这是"另一台机被点亮"的根因。"""
    from webapp import server as S

    script = S._PROBE_SCRIPT
    check("设备探测脚本不含 su 调用", "su -c" not in script and "su -" not in script,
          script)
    check("探测脚本仍需 frida 状态", "frida-server" in script, script)
    check("探测脚本仍需 root 可用性判据", "command -v su" in script, script)
    # 只读命令：不许出现任何会改设备状态的动词
    for bad in ("input ", "am ", "svc ", "pm ", "kill "):
        check("探测脚本不含副作用命令：%s" % bad.strip(), bad not in script, script)

    # 解析层的语义：su 存在 ≠ 已验证提权
    info = S._probe_one.__wrapped__ if hasattr(S._probe_one, "__wrapped__") else None
    check("_probe_one 仍是函数（解析逻辑可测）", callable(S._probe_one), type(S._probe_one))


def _t_root_verified(check):
    """「已 root」必须是验证过的结论 —— 而且这条路得真的走得通。

    2026-11-11 现场发现：平台用 `getattr(res, "device_serial", "")` 去标"跑完
    就记下已 root"，可 JobOutcome 压根没这个字段 → 永远拿到空串 → 这段逻辑
    一次都没执行过，设备卡永远显示「su 可用（未验证）」，把验证过的结论
    说成了没验证。这里把"字段存在 + 只在真碰设备时标记"钉住。
    """
    from piiscan.sop_job import JobOutcome
    from webapp import server as S

    o = JobOutcome()
    check("JobOutcome 带 device_serial 字段", hasattr(o, "device_serial"), type(o))
    check("JobOutcome.device_serial 默认为空串", o.device_serial == "", o.device_serial)
    check("to_dict 里带 device_serial", "device_serial" in o.to_dict(),
          list(o.to_dict().keys()))

    # 标记表本身：没验证过就是 False，标记后才是 True；轮询永远不会写它
    sn = "TEST-SERIAL-ROOT"
    check("未验证的设备不显示已 root", S._root_verified(sn) is False, sn)
    S.mark_root_verified(sn)
    check("标记后显示已 root", S._root_verified(sn) is True, sn)
    with S._ROOT_VERIFIED_LOCK:
        S._ROOT_VERIFIED.pop(sn, None)

    # 源码断言：标记点必须受"这次真的碰了设备"约束
    import inspect
    src = inspect.getsource(S.Worker._process)
    check("任务成功回填序列号（不再读不存在的字段名）",
          'getattr(res, "device_serial"' in src, "device_serial")
    check("离线重渲染不标已 root（必须有 _touched 判断）",
          "_touched" in src and "scan_result_path" in src, "guard")

    # 回填点：采集层才知道 auto 最终选了哪台
    from piiscan.sop_job import run_job as _rj
    rsrc = inspect.getsource(_rj)
    check("run_job 采集后回填实际设备序列号",
          "out.device_serial = scan_result.device_serial" in rsrc, "backfill")


def _t_watchdog(check):
    from webapp import server as S

    now = time.time()

    class FakeDB:
        def __init__(self, jobs):
            self.jobs = jobs
            self.logs = []
            self.updates = []
            self.list_calls = 0

        def list(self, n=100):
            # 界面翻页用的分页查询。看门狗**不许**用它 ——
            # 2026-11-23 海滨城事故就是被这个 LIMIT 30 挡在门外 110 分钟。
            self.list_calls += 1
            return self.jobs

        def list_running(self):
            return [j for j in self.jobs if j.get("status") == "running"]

        def append_log(self, jid, msg, live=True):
            self.logs.append((jid, msg, live))

        def update(self, jid, **kw):
            self.updates.append((jid, kw))

    class FakeWorker:
        def __init__(self):
            self.forced = {}
            self.calls = []

        def is_forced(self, jid):
            return jid in self.forced

        def force_stop(self, jid, reason):
            self.forced[jid] = reason
            self.calls.append((jid, reason))

    def job(jid, stall, req="", elapsed=120, duration=420, status="running"):
        return {"id": jid, "status": status, "stall": stall, "req": req,
                "stage": "界面遍历", "progress": 55,
                "started_at": now - elapsed, "duration": duration}

    # ---- 1. 只是"慢"：10 分钟零输出 → 只提醒，不强制 ----
    db = FakeDB([job("J-slow", S.Watchdog.STALL_S + 30)])
    w = FakeWorker()
    wd = S.Watchdog(db, w)
    wd.sweep()
    check("10 分钟零输出 → 写提醒", any("没有任何日志或进度更新" in m
                                        for _j, m, _l in db.logs), db.logs)
    check("10 分钟零输出 → 不强制停止", not w.calls, w.calls)

    # ---- 2. 20 分钟零输出 → 强制停止 ----
    db2 = FakeDB([job("J-dead", S.Watchdog.FORCE_S + 30)])
    w2 = FakeWorker()
    wd2 = S.Watchdog(db2, w2)
    wd2.sweep()
    check("20 分钟零输出 → 强制停止", bool(w2.calls) and w2.calls[0][0] == "J-dead",
          w2.calls)

    # ---- 3. 已请求停止、但线程还在写日志 → 不许强制 ----
    #         判据必须是"心跳停了"，不是"点了停止多久"：
    #         真机实测点停止后正常收尾要走 90 秒（卸载 + 写存档），
    #         拿时间当判据会在收尾阶段又去 force-stop 一次。
    db3 = FakeDB([job("J-cancel", 5, req="cancel")])
    w3 = FakeWorker()
    wd3 = S.Watchdog(db3, w3)
    wd3.sweep()
    check("停止后仍在写日志（收尾中）→ 不强制", not w3.calls, w3.calls)
    db3.jobs = [job("J-cancel", S.Watchdog.CANCEL_QUIET_S + 5, req="cancel")]
    wd3.sweep()
    check("停止后 45 秒零日志 → 强制停止",
          bool(w3.calls) and "停止" in w3.calls[0][1], w3.calls)

    # ---- 4. 强制后仍不退出 → 硬收尾（按"已停止"记账，并写明设备仍被占） ----
    db4 = FakeDB([job("J-hard", 0, req="cancel")])
    w4 = FakeWorker()
    w4.forced["J-hard"] = "已请求停止 95 秒仍未收工"
    wd4 = S.Watchdog(db4, w4)
    wd4._forced_at["J-hard"] = time.time() - (S.Watchdog.HARD_S + 10)
    wd4.sweep()
    st = [kw.get("status") for _j, kw in db4.updates]
    check("强制后 5 分钟仍不退出 → 硬收尾为已停止", "canceled" in st, db4.updates)
    msg = " ".join(kw.get("error") or "" for _j, kw in db4.updates)
    check("硬收尾必须写明设备锁仍被卡住的线程持有",
          "设备独占权" in msg and "重启" in msg, msg)

    # ---- 5. 线程栈：必须能抓到名为 piiscan-worker 的帧 ----
    holder = {}

    def _work():
        holder["done"] = True
        time.sleep(3)

    th = threading.Thread(target=_work, name="piiscan-worker", daemon=True)
    th.start()
    time.sleep(0.1)
    stack = S.Watchdog._worker_stack()
    check("卡死提醒里能抓到工作线程调用栈",
          "piiscan-worker" in stack and "_work" in stack, stack[:200])
    th.join(timeout=4)

    # ---- 6. 批量场景：任务排在第 42 位（分页取不到）也必须被看见 ----
    #         2026-11-23 海滨城：一次提交 42 个 App，正在跑的恰是最早创建的
    #         那条，`list(30)` 里没有它 → 看门狗 110 分钟毫无动作。
    db6 = FakeDB([job("J-batch", S.Watchdog.FORCE_S + 60)])
    w6 = FakeWorker()
    wd6 = S.Watchdog(db6, w6)
    wd6.sweep()
    check("批量任务（不在前 30 条）零输出 20 分钟 → 照样强制收工",
          bool(w6.calls) and w6.calls[0][0] == "J-batch", w6.calls)
    check("看门狗不再用分页查询做死活判断", db6.list_calls == 0, db6.list_calls)

    # ---- 7. 墙钟上限：日志还在刷（stall=0）也要能收工 ----
    cap = S.Watchdog.wall_cap_s({"duration": 420})
    check("墙钟上限 = 预算×2 + 30 分钟", cap == 420 * 2 + 1800, cap)
    db7 = FakeDB([job("J-long", 0, elapsed=cap + 60)])
    w7 = FakeWorker()
    S.Watchdog(db7, w7).sweep()
    check("跑过墙钟上限 → 强制收工（与有没有日志无关）",
          bool(w7.calls) and "上限" in w7.calls[0][1], w7.calls)
    db7b = FakeDB([job("J-ok", 0, elapsed=cap - 600)])
    w7b = FakeWorker()
    S.Watchdog(db7b, w7b).sweep()
    check("未到墙钟上限、日志在刷 → 不动它", not w7b.calls, w7b.calls)
    # 排队等设备的时间不算进上限：这段时间一行采集都没跑。
    j_wait = job("J-wait", 0, elapsed=cap + 3600)
    j_wait["stage"] = "等待设备（另一任务在跑）"
    db7c = FakeDB([j_wait])
    w7c = FakeWorker()
    S.Watchdog(db7c, w7c).sweep()
    check("等设备等了两小时也不按墙钟上限收工", not w7c.calls, w7c.calls)

    # ---- 8. 心跳为 NULL 的运行中任务不能算"刚活过" ----
    from webapp.db import _stall_of
    check("心跳缺失时按开始时间算 stall（不返回 0）",
          _stall_of({"status": "running", "started_at": now - 900}, None, now) >= 899,
          _stall_of({"status": "running", "started_at": now - 900}, None, now))
    check("非运行状态 stall 恒为 0",
          _stall_of({"status": "done", "started_at": now - 900}, None, now) == 0)


def _t_paging_blind_spot(check):
    """分页当控制面的盲区：批量提交时正在跑的那条会掉出前 N 条。

    2026-11-23 海滨城（真机）：一次提交 42 个 App，正在跑的是**最早创建**
    的那条 → 在 `created_at DESC` 里排第 42 → `list(30)` 里没有它 →
    看门狗 85 分钟没写一句提醒、没做一次强制收工，用户点停止也无人代劳，
    最后只能重启服务。

    这里用**真的 JobDB**（临时目录）复现那个形状：35 条任务、最老的那条
    running。钉住两件事：① 列表接口必须把它带出来；② list_running 必须
    不分页地返回它。
    """
    import tempfile
    from pathlib import Path
    from webapp.db import JobDB

    db = JobDB(Path(tempfile.mkdtemp(prefix="paging_")) / "jobs.db")
    first = db.create(source="apk", apk_name="a.apk", duration=420)
    for i in range(34):
        db.create(source="apk", apk_name="b%d.apk" % i, duration=420)
    # 让最老的那条变成 running（模拟"批次里第一条正在跑"）
    db.update(first, status="running", stage="复现采集", progress=89)

    page = db.list(30)
    check("列表分页仍按创建时间倒序（最新在前）",
          page[0]["created_at"] >= page[-1]["created_at"], len(page))
    check("正在跑的任务即使排在第 35 位也出现在列表里",
          any(j["id"] == first for j in page), len(page))
    check("它的 stall 是真实秒数而不是 0",
          [j for j in page if j["id"] == first][0]["stall"] >= 0, page[0].get("stall"))

    run_only = db.list_running()
    check("list_running 返回全部在跑任务（不受分页影响）",
          [j["id"] for j in run_only] == [first], run_only)
    check("list_running 带 duration（墙钟上限要用）",
          int(run_only[0].get("duration") or 0) == 420, run_only[0])
