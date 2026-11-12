"""uiwalk.dump 的抗卡死能力离线自测（不需要真机）。

为什么单独测这一块：`uiautomator dump` 卡死是无人值守场景下唯一能让**整条
任务队列无声停摆**的故障 —— 任务状态还显示"运行中"，看板上进度不动，日志不报错。
真机实测过一次卡 6 分钟以上，靠人工 `ps` 找到僵死进程才恢复。这类故障只能靠
离线用例把行为钉死，否则下次改动很容易把清理逻辑碰掉而不自知。
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from piiscan import uiwalk as UW  # noqa: E402

XML = ('<?xml version="1.0" encoding="UTF-8"?><hierarchy rotation="0">'
       '<node index="0" text="同意" resource-id="" class="android.widget.Button" '
       'clickable="true" bounds="[10,10][110,110]"/></hierarchy>')

SERIAL = "FAKE_SERIAL"


def _cp(args, rc, out=b"", err=b""):
    return subprocess.CompletedProcess(args, rc, out, err)


class FakeAdb:
    """只实现 dump() 用到的几条 adb 子命令。"""

    def __init__(self, mode="ok", pids=None):
        self.mode = mode            # ok | hang | silent
        self.pids = list(pids or [])
        self.calls = []
        self.kills = []
        self.dump_attempts = 0
        self.timeouts = []
        self.files = {}

    def __call__(self, serial, *args, timeout=25):
        self.calls.append(args)
        if not args or args[0] != "shell":
            return _cp(args, 0)
        sub = args[1] if len(args) > 1 else ""

        if sub == "pidof":
            out = (" ".join(self.pids) + "\n").encode() if self.pids else b""
            return _cp(args, 0 if self.pids else 1, out)

        if sub == "rm":
            return _cp(args, 0)

        if sub == "uiautomator":
            self.dump_attempts += 1
            self.timeouts.append(timeout)
            if self.mode == "hang":
                # 真实表现：adb 客户端被 timeout 打死，设备端进程仍在
                raise subprocess.TimeoutExpired(cmd="adb", timeout=timeout)
            if self.mode == "silent":
                return _cp(args, 0, b"ERROR: could not get idle state.\n")
            path = args[3]
            self.files[path] = XML
            return _cp(args, 0, ("UI hierchary dumped to: %s\n" % path).encode())

        if sub == "cat":
            path = args[2]
            if path in self.files:
                return _cp(args, 0, self.files[path].encode())
            return _cp(args, 1, b"cat: " + path.encode() + b": No such file or directory")

        if "kill" in sub:                     # su -c 'kill -9 xxx' / pkill
            self.kills.append(sub)
            if "pkill" in sub:
                self.pids.clear()
            else:
                for pid in list(self.pids):
                    if pid in sub:
                        self.pids.remove(pid)
            return _cp(args, 0)

        return _cp(args, 0)


class _Patch:
    def __init__(self, fake):
        self.fake = fake

    def __enter__(self):
        self.old = UW._adb
        UW._adb = self.fake
        UW.reset_dump_health()
        return self.fake

    def __exit__(self, *a):
        UW._adb = self.old
        UW.reset_dump_health()


def run(check):
    # ---- ① 正常路径：一次成功，不产生任何清理动作 ----
    with _Patch(FakeAdb()) as fake:
        xml = UW.dump(SERIAL)
        h = UW.dump_health(SERIAL)
        check("dump 正常时返回结构树", bool(xml) and "<hierarchy" in xml)
        check("dump 正常时节点可解析", len(UW.parse_all(xml)) == 1, len(UW.parse_all(xml)))
        check("dump 正常时只尝试一次", fake.dump_attempts == 1, fake.dump_attempts)
        check("dump 正常时不清理进程", not fake.kills and h["kills"] == 0, fake.kills)
        check("dump 正常时健康计数清零", h["fails"] == 0 and h["degraded"] is False, h)

    # ---- ② 设备端进程卡死（adb 超时）→ 必须杀掉，且不再试第二个目录 ----
    with _Patch(FakeAdb(mode="hang", pids=["4242"])) as fake:
        t0 = time.time()
        xml = UW.dump(SERIAL)
        cost = time.time() - t0
        h = UW.dump_health(SERIAL)
        check("超时后 dump 返回 None", xml is None)
        check("超时后杀掉设备端残留进程", fake.pids == [] and h["kills"] == 1, (fake.pids, h))
        check("超时后不再尝试第二个落盘目录", fake.dump_attempts == 1, fake.dump_attempts)
        check("超时原因写进健康信息", "超时" in (h["reason"] or ""), h["reason"])
        check("超时路径不引入额外等待", cost < 5.0, round(cost, 2))

    # ---- ③ 进程赖着不走、dump 出不了结构树 → 也要杀 ----
    with _Patch(FakeAdb(mode="silent", pids=["999"])) as fake:
        UW.dump(SERIAL)
        h = UW.dump_health(SERIAL)
        check("无输出但进程仍在 → 清理", fake.pids == [] and h["kills"] >= 1, (fake.pids, h))
        check("清理动作记进原因", "清理" in (h["reason"] or ""), h["reason"])

    # ---- ④ 硬故障累积到阈值 → 熔断，之后不再碰设备 ----
    with _Patch(FakeAdb(mode="hang", pids=[])) as fake:
        UW.dump(SERIAL)
        UW.dump(SERIAL)
        h = UW.dump_health(SERIAL)
        check("连续硬故障后进入降级", h["degraded"] is True, h)
        n_before = len(fake.calls)
        t0 = time.time()
        for _ in range(3):
            UW.dump(SERIAL)
        cost = time.time() - t0
        check("降级期间不再下发 adb 命令", len(fake.calls) == n_before,
              len(fake.calls) - n_before)
        check("降级期间 dump 立即返回", cost < 0.2, round(cost, 3))
        t0 = time.time()
        check("降级期间 dump_retry 不空转", UW.dump_retry(SERIAL, tries=3) is None)
        check("dump_retry 降级时立即返回", time.time() - t0 < 0.2)

    # ---- ⑤ 偶发软失败不能触发熔断（否则正常页面也被停掉）----
    with _Patch(FakeAdb(mode="silent", pids=[])) as fake:
        for _ in range(4):
            UW.dump(SERIAL)
        h = UW.dump_health(SERIAL)
        check("软失败累计但不熔断", h["degraded"] is False and h["fails"] >= 4, h)

    # ---- ⑥ 降级到期后自动探测，成功即恢复 ----
    with _Patch(FakeAdb(mode="hang", pids=[])) as fake:
        UW.dump(SERIAL)
        UW.dump(SERIAL)
        check("降级已生效", UW.dump_health(SERIAL)["degraded"] is True)
        UW._hp(SERIAL)["degraded_until"] = time.time() - 1     # 模拟冷却到期
        fake.mode = "ok"
        xml = UW.dump(SERIAL)
        h = UW.dump_health(SERIAL)
        check("冷却到期后自动探测成功", bool(xml), h)
        check("成功后自动解除降级", h["degraded"] is False and h["harm"] == 0, h)

    # ---- ⑦ 清理失败也不能死循环（pkill 兜底后仍失败就放手）----
    class Stubborn(FakeAdb):
        def __call__(self, serial, *args, timeout=25):
            if len(args) > 1 and "kill" in (args[1] or ""):
                self.calls.append(args)
                self.kills.append(args[1])
                return _cp(args, 0)          # 杀不掉，但也不报错
            return super().__call__(serial, *args, timeout=timeout)

    with _Patch(Stubborn(mode="silent", pids=["777"])) as fake:
        t0 = time.time()
        UW.dump(SERIAL)
        UW.dump(SERIAL)
        cost = time.time() - t0
        check("杀不掉时最终仍会熔断", UW.dump_health(SERIAL)["degraded"] is True,
              UW.dump_health(SERIAL))
        check("杀不掉时不死循环", cost < 5.0, round(cost, 2))

    # ---- ⑧ 连续软失败到阈值 → 熔断（2026-11-02 川剧迷事故）----
    #   事故：点到搜索页后连续 63 次导不出结构树，每轮 18s 超时 + 补读 +
    #   清理 ≈ 49 秒，第 51~111 轮烧掉 2954 秒（49 分钟）一个动作没做。
    #   根因是"软失败只统计不熔断"，而**连续**软失败这条路没有任何上限。
    with _Patch(FakeAdb(mode="silent", pids=[])) as fake:
        for _ in range(UW._SOFT_RUN_LIMIT):
            UW.dump(SERIAL)
        h = UW.dump_health(SERIAL)
        check("连续软失败到阈值即熔断", h["degraded"] is True, h)
        check("熔断原因写明是连续失败", "连续" in (h["reason"] or ""), h["reason"])
        n = fake.dump_attempts
        UW.dump(SERIAL)
        check("连续软失败熔断后不再碰设备", fake.dump_attempts == n,
              fake.dump_attempts - n)

    # ---- ⑨ 成功一次就清零：清零后必须重新"连续"才熔断 ----
    with _Patch(FakeAdb(mode="silent", pids=[])) as fake:
        for _ in range(4):
            UW.dump(SERIAL)
        fake.mode = "ok"
        check("失败 4 次后成功", bool(UW.dump(SERIAL)))
        check("成功一次即清零连续计数",
              UW.dump_health(SERIAL)["soft_run"] == 0, UW.dump_health(SERIAL))
        fake.mode = "silent"
        for _ in range(4):
            UW.dump(SERIAL)
        check("清零后又要重新连续满额才熔断",
              UW.dump_health(SERIAL)["degraded"] is False, UW.dump_health(SERIAL))

    # ---- ⑩ 连续失败后快速失败：单次超时 18s 必须缩到 6s ----
    #   这一条不改变"能不能读到"的判据，只保证读不到时别把预算烧光。
    with _Patch(FakeAdb(mode="silent", pids=[])) as fake:
        for _ in range(UW._SOFT_FAST_AFTER + 1):
            UW.dump(SERIAL)
        first = fake.timeouts[0]
        later = fake.timeouts[-1]
        check("首次失败按标准超时", first == UW._DUMP_TIMEOUT, first)
        check("连续失败后改用短超时", later == UW._DUMP_FAST_TIMEOUT,
              (first, later))
        check("短超时必须明显小于标准超时",
              UW._DUMP_FAST_TIMEOUT * 2 <= UW._DUMP_TIMEOUT,
              (UW._DUMP_FAST_TIMEOUT, UW._DUMP_TIMEOUT))

    # ---- ⑪ 自愈之后连续计数必须清零（"刚救回来就判死"没有意义）----
    with _Patch(FakeAdb(mode="silent", pids=[])) as fake:
        for _ in range(UW._SOFT_RUN_LIMIT - 1):
            UW.dump(SERIAL)
        check("未到阈值前不熔断",
              UW.dump_health(SERIAL)["degraded"] is False, UW.dump_health(SERIAL))
        UW.reset_soft_run(SERIAL)
        check("自愈后连续计数清零", UW.dump_health(SERIAL)["soft_run"] == 0,
              UW.dump_health(SERIAL))
        for _ in range(UW._SOFT_RUN_LIMIT - 1):
            UW.dump(SERIAL)
        check("清零后要重新连续满额才熔断",
              UW.dump_health(SERIAL)["degraded"] is False, UW.dump_health(SERIAL))
