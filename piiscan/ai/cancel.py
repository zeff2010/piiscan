"""AI 调用的取消令牌（2026-11-12）。

为什么需要单独一层
------------------
用户点了「停止」，平台却要等很久才响应 —— 跑金考典那一轮就是：AI 的 HTTP
请求挂在网络上（本地模型服务断了），采集线程正阻塞在 `urlopen` 里。
`should_stop()` 只在**两次调用之间**被检查，而一次 AI 调用本身可以占用
90 秒（文本）/ 180 秒（视觉）；分段抽取还会并发 4 路、每段失败再重试一次。
于是"停止"在界面上是个假动作：请求已经记下了，线程却一个检查点都到不了。

这里提供一个**进程级**的取消令牌：
  · 取消接口一收到请求就 `arm()`，不必等 worker 下一轮读库；
  · `_post_json` 把阻塞的 HTTP 调用放到后台线程，自己按 0.25 秒的粒度轮询
    令牌 —— 一旦置位立刻抛错，采集线程马上回到 `should_stop()`；
  · 任务开始/结束时 `disarm()`，确保上一个任务的停止不会误伤下一个。

★ 只用于"这次任务被要求停止"这一件事，不承担"任务超时"之类的语义：
  超时由 HTTP 自身的 timeout 管，混在一起会让日志说不清是哪一个原因。
"""
from __future__ import annotations

import threading

from .base import AIError


class CancelToken:
    """一次任务范围内的取消信号（可重复置位/复位）。"""

    def __init__(self) -> None:
        self._ev = threading.Event()
        self._reason = ""
        self._lock = threading.Lock()

    def arm(self, reason: str = "用户请求停止") -> None:
        with self._lock:
            self._reason = (reason or "用户请求停止").strip()
            self._ev.set()

    def disarm(self) -> None:
        with self._lock:
            self._reason = ""
            self._ev.clear()

    def is_set(self) -> bool:
        return self._ev.is_set()

    def reason(self) -> str:
        with self._lock:
            return self._reason or "用户请求停止"

    def check(self, what: str = "AI 调用") -> None:
        """已置位就直接抛错。在发起请求前、等待响应中、拿到结果后各查一次。"""
        if self._ev.is_set():
            raise AIError("%s已中断：%s" % (what, self.reason()))


# 全局唯一实例：整条流水线共用同一个 AI 任务实例，取消也只有一个来源。
ACTIVE = CancelToken()


def arm(reason: str = "用户请求停止") -> None:
    ACTIVE.arm(reason)


def disarm() -> None:
    ACTIVE.disarm()


def is_set() -> bool:
    return ACTIVE.is_set()


def check(what: str = "AI 调用") -> None:
    ACTIVE.check(what)


__all__ = ["CancelToken", "ACTIVE", "arm", "disarm", "is_set", "check"]
