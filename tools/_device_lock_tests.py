"""设备占用判定的自测：判据必须是内核文件锁，不是 .info 里的 PID。

真实事故（2026-11-11）：一条任务跑完、进程被杀，但 `<锁>.info` 留在原地；
那个 PID 随后被系统复用给了一个刚启动的浏览器。界面于是把那台**空闲**的
手机一直显示成"占用中 · J2026…"，提交时的提示还说"本任务会排队"。
用户没有任何办法从界面上分辨这是真是假 —— 这类"状态说假话"比报错更糟。

所以这里钉两件事：
  1. 锁空闲时，哪怕 .info 里写着一个**活着**的 PID，也必须判为不占用；
  2. 锁真被占用时，要能说出是谁（读 .info），并能区分"自己持有"。
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def run(check):
    from piiscan import runlock
    from webapp import server as S

    key = "LOCKTEST-1"
    lp = runlock.device_lock_path(key)
    ip = lp.with_name(lp.name + ".info")
    try:
        # ---------- 1. 没有任何锁文件 ----------
        for p in (lp, ip):
            if p.exists():
                p.unlink()
        check("锁文件不存在 → 判为空闲", runlock.probe_free(lp) is True,
              runlock.probe_free(lp))

        # ---------- 2. 真被锁住 ----------
        held = runlock.FileLock(lp, {"job": "JTEST", "device": key})
        check("加锁成功", held.acquire(), "acquire 返回 False")
        check("锁被持有时 probe_free 判为不空闲", runlock.probe_free(lp) is False,
              runlock.probe_free(lp))

        busy, job = S._device_busy(key)
        check("自己持有的锁不算'别人占用'", busy is False, (busy, job))

        # 假装我们是另一个进程：这时必须判为占用，并说出占用它的任务号
        busy, job = S._device_busy(key, my_pid=-1)
        check("别人持有 → 占用", busy is True, (busy, job))
        check("占用时能说出任务号", job == "JTEST", job)

        # ---------- 3. 释放后，.info 仍留着（这正是事故现场）----------
        held.release()
        check("释放后 probe_free 判为空闲", runlock.probe_free(lp) is True,
              runlock.probe_free(lp))
        check(".info 确实没被删（复现事故前提）", ip.exists(), ip.exists())

        # 把 info 里的 PID 改成一个**肯定活着**的进程（本进程自己），
        # 模拟"PID 被复用给别的活进程"。判据若还看 PID，这里就会误报占用。
        ip.write_text(json.dumps({"pid": os.getpid(), "job": "JSTALE",
                                  "device": key}), encoding="utf-8")
        busy, job = S._device_busy(key, my_pid=-1)
        check("锁空闲但 .info 里是活着的 PID → 仍判为空闲（P0 事故用例）",
              busy is False, (busy, job))

        # ---------- 4. 探测本身不能污染 .info ----------
        before = ip.read_text(encoding="utf-8")
        runlock.probe_free(lp)
        after = ip.read_text(encoding="utf-8")
        check("probe_free 不改写持有者信息", before == after,
              (before[:60], after[:60]))

        # ---------- 5. 与 FileLock 语义一致：空闲时能立刻拿到锁 ----------
        check("probe 说空闲 → 紧接着能拿到锁", runlock.FileLock(lp).acquire(),
              "probe 与真实的加锁结果不一致")
        runlock.FileLock  # noqa: B018  （保持引用，避免 linter 误报）
    finally:
        for p in (lp, ip):
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass
