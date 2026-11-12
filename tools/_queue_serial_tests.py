# -*- coding: utf-8 -*-
"""「同时只有一个 App 在测」的回归测试。

用户 2026-10-25 的现象：批量提交商店链接后，两个 App 同时在跑，
而手机上只有一台检测机。根因不是队列写错，是**两个服务进程**：
Windows 上 `SO_REUSEADDR` 允许重复绑定同一端口（`netstat` 里
127.0.0.1:8760 出现 2 个 LISTENING），第二个 `run_platform.py`
静默成为第二个服务，各自一个 Worker 抢同一个 jobs.db。

因此这里的测试必须**跨进程**才有意义：同进程内加锁/取任务怎么测都通过，
真正出问题的是"两个操作系统进程"。所以：
  - 锁用子进程持有，主进程去抢
  - 服务用两次 `run_platform.py` 真启动（故意给不同端口，证明拦的是锁不是端口）
  - Worker 用两个 JobDB 连接、两把设备锁，验证执行区间不重叠

不碰 out/platform 里的真实任务，不连设备。
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiscan import runlock                    # noqa: E402
from webapp.db import JobDB                    # noqa: E402
from webapp.server import Worker               # noqa: E402

_ok = 0
_bad = 0


def check(name: str, cond: bool, detail=""):
    global _ok, _bad
    if cond:
        _ok += 1
    else:
        _bad += 1
        print("  [FAIL] %s  %s" % (name, detail))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_health(port: int, timeout: float = 25.0) -> bool:
    url = "http://127.0.0.1:%d/api/health" % port
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(url, timeout=1.5) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.2)
    return False


def _q(db, sql: str, args=()):
    """直接查库（测试断言用）。`_c()` 是 contextmanager，不能直接 .execute。"""
    with db._c() as c:
        return c.execute(sql, args).fetchall()


def _log_text(db, jid: str) -> str:
    """任务的日志是 jobs.log 里的长文本（不是独立表）。"""
    rows = _q(db, "SELECT log FROM jobs WHERE id=?", (jid,))
    return (rows[0][0] if rows else "") or ""


# ============================================================================
#  1. 跨进程文件锁
# ============================================================================

_HOLD_CHILD = r"""
import sys, time
sys.path.insert(0, sys.argv[1])
from piiscan import runlock
import os
lk = runlock.FileLock(sys.argv[2], {"pid": os.getpid(), "port": 4321, "workdir": "child-dir"})
assert lk.acquire(), "child failed to acquire"
print("LOCKED", flush=True)
time.sleep(float(sys.argv[3]))
lk.release()
print("RELEASED", flush=True)
"""


def test_cross_process_lock():
    tmp = Path(tempfile.mkdtemp(prefix="pilock_"))
    try:
        lock_path = tmp / ".platform.lock"
        proc = subprocess.Popen(
            [sys.executable, "-c", _HOLD_CHILD, str(ROOT), str(lock_path), "2.5"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace")
        line = proc.stdout.readline().strip()
        check("子进程成功持锁", line == "LOCKED", line)

        other = runlock.FileLock(lock_path, {"pid": os.getpid()})
        check("另一进程拿不到同一把锁", other.acquire() is False)

        holder = runlock.read_holder(other)
        check("能读出占用者信息（供提示用）", holder.get("port") == 4321, holder)
        check("占用者 PID 被标为存活", holder.get("alive") is True, holder)
        check("占用者描述里带 PID/端口/目录",
              all(x in runlock.describe_holder(holder, other) for x in ("PID", "端口", "child-dir")),
              runlock.describe_holder(holder, other))

        proc.wait(timeout=15)
        check("子进程正常释放退出", proc.returncode == 0, proc.stderr.read()[-300:])
        check("持锁进程退出后锁自动可用", other.acquire() is True)
        other.release()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_lock_wait():
    """`acquire_wait` 必须真的等（不是立刻返回 False 也不是立刻返回 True）。"""
    tmp = Path(tempfile.mkdtemp(prefix="pilockw_"))
    try:
        lock_path = tmp / "d.lock"
        proc = subprocess.Popen(
            [sys.executable, "-c", _HOLD_CHILD, str(ROOT), str(lock_path), "1.6"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace")
        check("子进程持锁（wait 用例）", proc.stdout.readline().strip() == "LOCKED")

        t0 = time.time()
        mine = runlock.FileLock(lock_path)
        got = mine.acquire_wait(0, poll_s=0.2)
        waited = time.time() - t0
        check("等锁最终拿到", got is True)
        check("确实等待了持锁进程（≥1.2 秒）", waited >= 1.2, "%.2f" % waited)
        mine.release()

        # 超时场景：不应无限等
        proc2 = subprocess.Popen(
            [sys.executable, "-c", _HOLD_CHILD, str(ROOT), str(lock_path), "2.0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace")
        proc2.stdout.readline()
        t0 = time.time()
        got2 = runlock.FileLock(lock_path).acquire_wait(0.5, poll_s=0.1)
        el = time.time() - t0
        check("wait_s 生效：超时返回 False", got2 is False and el < 1.5, "%.2f" % el)
        proc.wait(timeout=10)
        proc2.wait(timeout=10)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_stop_while_waiting():
    """服务停止时不该卡在等锁上。"""
    tmp = Path(tempfile.mkdtemp(prefix="pilocks_"))
    try:
        lock_path = tmp / "s.lock"
        holder = runlock.FileLock(lock_path)
        holder.acquire()
        mine = runlock.FileLock(lock_path)
        t0 = time.time()
        got = mine.acquire_wait(0, poll_s=0.1, should_stop=lambda: True)
        check("should_stop 为真时立刻放弃等锁",
              got is False and time.time() - t0 < 1.0, "%.2f" % (time.time() - t0))
        holder.release()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  2. 同一工作目录只能起一个服务（故意用不同端口）
# ============================================================================

def test_single_instance_server():
    tmp = Path(tempfile.mkdtemp(prefix="piserve_"))
    procs = []
    try:
        pa, pb = _free_port(), _free_port()
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=str(ROOT))
        a = subprocess.Popen(
            [sys.executable, "-u", str(ROOT / "run_platform.py"),
             "--port", str(pa), "--workdir", str(tmp), "--no-device", "--quiet"],
            cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace")
        procs.append(a)
        check("第一个服务正常启动", _wait_health(pa), "端口 %d" % pa)

        # ★ 关键：换一个端口，但工作目录相同。端口不冲突，只有锁能拦住。
        b = subprocess.Popen(
            [sys.executable, "-u", str(ROOT / "run_platform.py"),
             "--port", str(pb), "--workdir", str(tmp), "--no-device", "--quiet"],
            cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace")
        procs.append(b)
        try:
            out_b = b.communicate(timeout=40)[0] or ""
        except subprocess.TimeoutExpired:
            b.kill()
            out_b = b.communicate()[0] or ""
        check("第二个服务拒绝启动（不同端口也一样）", b.returncode == 3, b.returncode)
        check("拒绝信息说明是同一工作目录", "已经有一个检测服务在运行" in out_b, out_b[-400:])
        check("拒绝信息给出占用者 PID", "PID" in out_b, out_b[-400:])
        check("拒绝信息解释为什么要拦（一台手机）", "一台手机" in out_b, out_b[-400:])

        check("第一个服务未受影响", _wait_health(pa, 5), "")
        url = "http://127.0.0.1:%d/api/jobs" % pa
        with urllib.request.urlopen(url, timeout=5) as r:
            check("第一个服务接口仍可用", r.status == 200, r.status)
    finally:
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=10)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  3. next_queued 的原子性
# ============================================================================

def test_next_queued_atomic():
    tmp = Path(tempfile.mkdtemp(prefix="pidb_"))
    try:
        path = tmp / "jobs.db"
        seed = JobDB(path)
        for i in range(8):
            seed.create(source="upload", apk_name="a%d.apk" % i, apk_path="x.apk",
                        run_dynamic=False)

        # 两个独立连接（模拟两个进程各自的 JobDB）并发抢
        dbs = [JobDB(path), JobDB(path)]
        taken, lock = [], threading.Lock()

        def grab(db):
            while True:
                j = db.next_queued()
                if not j:
                    return
                with lock:
                    taken.append(j["id"])

        ts = [threading.Thread(target=grab, args=(d,)) for d in dbs for _ in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=30)

        check("8 条任务全部被取走", len(taken) == 8, len(taken))
        check("没有同一条被取两次", len(set(taken)) == len(taken), taken)
        running = [r[0] for r in _q(seed, "SELECT id FROM jobs WHERE status='running'")]
        check("库内 running 数与取走数一致", len(running) == 8, len(running))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================
#  4. Worker：单实例内串行 + 跨实例串行
# ============================================================================

def _mk_worker(db, tmp, run_log, dev_key):
    w = Worker(db, tmp, device_enabled=True, device_key=dev_key)
    w.SETTLE_S = 0
    w.SETTLE_TIMEOUT_S = 0
    w._settle = lambda jid: None      # 收尾单独测（会去调 adb）

    def fake_process(job):
        t0 = time.time()
        db.update(job["id"], status="running")
        run_log.append(("start", job["id"], t0))
        time.sleep(0.30)
        db.update(job["id"], status="done", finished_at=time.time())
        run_log.append(("end", job["id"], time.time()))

    w._process = fake_process
    return w


def _assert_no_overlap(events, label):
    starts = [e for e in events if e[0] == "start"]
    ends = [e for e in events if e[0] == "end"]
    check("%s：每个任务都有开始与结束" % label, len(starts) == len(ends),
          "%d/%d" % (len(starts), len(ends)))
    seq = sorted(events, key=lambda e: e[2])
    ok = True
    depth = 0
    for kind, jid, t in seq:
        depth += 1 if kind == "start" else -1
        if depth > 1:
            ok = False
            break
    check("%s：执行区间互不重叠（同时最多 1 个）" % label, ok,
          [(k, j, round(t, 2)) for k, j, t in seq])


def test_worker_serial_one_process():
    tmp = Path(tempfile.mkdtemp(prefix="piw1_"))
    key = "test-one-%d" % os.getpid()
    lock_path = runlock.device_lock_path(key)
    try:
        db = JobDB(tmp / "jobs.db")
        for i in range(3):
            db.create(source="upload", apk_name="w%d.apk" % i, apk_path="x.apk",
                      run_dynamic=False)
        events = []
        w = _mk_worker(db, tmp, events, key)
        w.start()
        t0 = time.time()
        while time.time() - t0 < 25:
            if db.list(10) and all(j["status"] == "done" for j in db.list(10)):
                break
            time.sleep(0.2)
        w.stop()
        w.join(timeout=10)
        _assert_no_overlap(events, "单服务")
        check("3 条任务都跑完", len([e for e in events if e[0] == "end"]) == 3, events)
    finally:
        try:
            lock_path.unlink()
        except OSError:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


def test_two_workers_one_device():
    """两个 Worker（模拟两个服务）共用一个队列 + 一台设备：必须串行。"""
    tmp = Path(tempfile.mkdtemp(prefix="piw2_"))
    key = "test-two-%d" % os.getpid()
    lock_path = runlock.device_lock_path(key)
    try:
        path = tmp / "jobs.db"
        seed = JobDB(path)
        for i in range(4):
            seed.create(source="upload", apk_name="t%d.apk" % i, apk_path="x.apk",
                        run_dynamic=False)

        events, elock = [], threading.Lock()

        def rec(kind, jid, t):
            with elock:
                events.append((kind, jid, t))

        workers = []
        for _ in range(2):
            db = JobDB(path)
            run_log = _Recorder(rec)
            w = _mk_worker(db, tmp, run_log, key)
            workers.append(w)
        for w in workers:
            w.start()

        t0 = time.time()
        while time.time() - t0 < 30:
            st = [r[0] for r in _q(seed, "SELECT status FROM jobs "
                                        "WHERE status IN ('queued','running')")]
            if not st:
                break
            time.sleep(0.2)
        for w in workers:
            w.stop()
        for w in workers:
            w.join(timeout=15)

        _assert_no_overlap(events, "两个服务")
        check("4 条任务都被处理", len([e for e in events if e[0] == "end"]) == 4, events)
        # 两个 worker 都必须真的参与了，否则这条用例可能只是串行跑了空转
        who = {jid for _, jid, _ in events}
        check("任务覆盖完整（无遗漏）", len(who) == 4, who)
    finally:
        try:
            lock_path.unlink()
        except OSError:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


class _Recorder(list):
    """把 Worker 的 (kind, id, t) 同时写进共享列表。"""

    def __init__(self, sink):
        super().__init__()
        self._sink = sink

    def append(self, item):  # type: ignore[override]
        self._sink(*item)


# ============================================================================
#  5. 收尾：冷却 + 等设备就绪（下一个任务不能马上开）
# ============================================================================

def test_settle():
    tmp = Path(tempfile.mkdtemp(prefix="pisettle_"))
    try:
        db = JobDB(tmp / "jobs.db")
        jid = db.create(source="upload", apk_name="s.apk", apk_path="x.apk",
                        run_dynamic=False)
        w = Worker(db, tmp, device_enabled=True, device_key="settle-test")
        w.SETTLE_S = 0.3
        w.SETTLE_POLL_S = 0.05
        seq = iter(["offline", "offline", "device"])
        w._adb_state = lambda: next(seq, "device")

        t0 = time.time()
        w._settle(jid)
        el = time.time() - t0
        check("收尾包含冷却时间（≥0.3 秒）", el >= 0.3, "%.2f" % el)
        logs = _log_text(db, jid)
        check("设备未就绪时写告警", "设备未就绪" in logs, logs)
        check("设备就绪后写「收尾完成」", "收尾完成" in logs and "已就绪" in logs, logs)

        # 一直不就绪 → 到上限后写超时告警，不无限阻塞
        w2 = Worker(db, tmp, device_enabled=True, device_key="settle-test2")
        w2.SETTLE_S = 0
        w2.SETTLE_TIMEOUT_S = 0.6
        w2.SETTLE_POLL_S = 0.05
        w2._adb_state = lambda: "offline"
        tmp_jid = db.create(source="upload", apk_name="s2.apk", apk_path="x.apk",
                            run_dynamic=False)
        t0 = time.time()
        w2._settle(tmp_jid)
        el = time.time() - t0
        check("不就绪时按上限退出（不会无限等）", el < 5, "%.2f" % el)
        logs2 = _log_text(db, tmp_jid)
        check("超时也留下告警", "超时" in logs2, logs2)

        # 无设备时直接返回
        w3 = Worker(db, tmp, device_enabled=False)
        t0 = time.time()
        w3._settle(jid)
        check("无设备时收尾不做等待", time.time() - t0 < 0.5, "")

        # adb 根本跑不起来：等也没用，必须立刻放行
        w4 = Worker(db, tmp, device_enabled=True, device_key="settle-test4")
        w4.SETTLE_S = 0
        w4._adb_state = lambda: "adb 调用失败：FileNotFoundError"
        t0 = time.time()
        w4._settle(jid)
        check("adb 不可用时不空等 180 秒", time.time() - t0 < 1.0, "%.2f" % (time.time() - t0))
        check("adb 不可用时留下告警", "无法执行 adb" in _log_text(db, jid), _log_text(db, jid)[-200:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_worker_waits_for_leased_device():
    """设备已被别人占着时，任务必须**等**，而不是照样开跑。

    这条是确定性的（不靠"两个线程碰巧撞上"）：先手动持锁 1.2 秒，
    期间任务应停在「等待设备」并写下原因；放锁之后才真正执行。
    """
    tmp = Path(tempfile.mkdtemp(prefix="piwait_"))
    key = "test-wait-%d" % os.getpid()
    lock_path = runlock.device_lock_path(key)
    holder = runlock.FileLock(lock_path, {"pid": os.getpid(), "job": "J-being-tested",
                                          "workdir": "another-dir"})
    holder.acquire()
    try:
        db = JobDB(tmp / "jobs.db")
        jid = db.create(source="upload", apk_name="q.apk", apk_path="x.apk",
                        run_dynamic=False)
        events = []
        w = _mk_worker(db, tmp, events, key)
        w.start()

        # 1) 持锁期间：任务不该被执行
        time.sleep(1.0)
        logs = _log_text(db, jid)
        check("被占时写下「正被另一个任务占用」", "正被另一个任务占用" in logs, logs)
        check("被占时说明是一台手机的限制", "一台手机同时只能跑一个 App" in logs, logs)
        check("被占时给出占用者信息", "another-dir" in logs, logs)
        check("被占期间任务没有开始执行", not [e for e in events if e[0] == "start"], events)
        row = _q(db, "SELECT stage FROM jobs WHERE id=?", (jid,))[0][0]
        check("阶段显示为等待设备", "等待设备" in (row or ""), row)

        # 2) 放锁后应自动接上
        holder.release()
        t0 = time.time()
        while time.time() - t0 < 15:
            if [e for e in events if e[0] == "end"]:
                break
            time.sleep(0.2)
        check("放锁后任务自动开始并完成", bool([e for e in events if e[0] == "end"]), events)
        w.stop()
        w.join(timeout=10)
    finally:
        try:
            holder.release()
        except Exception:
            pass
        try:
            lock_path.unlink()
        except OSError:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


def test_device_lock_key():
    check("设备锁落在用户目录（跨工作目录共享）",
          str(runlock.device_lock_path("abc")).startswith(str(Path.home())),
          runlock.device_lock_path("abc"))
    check("序列号里的非法字符被清洗",
          runlock.device_lock_path("192.168.1.5:5555").name.endswith(".lock"),
          runlock.device_lock_path("192.168.1.5:5555").name)
    check("空 key 退化为 auto",
          "auto" in runlock.device_lock_path("").name,
          runlock.device_lock_path("").name)


if __name__ == "__main__":
    test_device_lock_key()
    test_cross_process_lock()
    test_lock_wait()
    test_stop_while_waiting()
    test_next_queued_atomic()
    test_worker_serial_one_process()
    test_two_workers_one_device()
    test_worker_waits_for_leased_device()
    test_settle()
    test_single_instance_server()
    print("=" * 60)
    print("串行保障回归：通过 %d 项，失败 %d 项" % (_ok, _bad))
    sys.exit(1 if _bad else 0)
