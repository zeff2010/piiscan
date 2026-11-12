"""Frida 同步调用的超时保护与"卡死"兜底。

★ 为什么必须有这个模块（2026-11-11 真机实测，不是推测）
  目标进程被冻住时，frida 的 `script.exports_sync.xxx()` **永远不返回**。
  实测（Android 10 / com.android.settings）：正常时 `ping()` 0.0 秒返回；
  `kill -STOP <pid>` 之后再调，12 秒仍在等；`kill -CONT` 后立刻又返回。

  这件事的代价不是"慢"，而是**采集线程回不到任何取消检查点**：
  用户点了停止、看板写着"进度停滞"，而程序里连一次 `should_stop()` 都执行不到。
  真机事故：一条 extreme 任务停在「复现采集 89%」后 95 分钟零日志、
  停止按钮两次无效，最后只能关掉服务。

  同一实验还确认了两件事，决定了兜底手段：
    · `session.detach()` 在冻结状态下**自己也会卡住** —— 所以看门狗不能同步调它；
    · `am force-stop <包名>` 杀掉被测应用后，卡住的调用 0.7 秒内抛
      `InvalidOperationError: script has been destroyed` 解开 —— 这是唯一可靠的解药。

★ 这里做两件事
  1. 所有同步 RPC（attach / load / exports_sync.*）都走 `call()`：超时就抛
     `RpcTimeout`，调用线程一定回得来；
  2. 一旦某个脚本超时过，后续调用**立刻失败**（不再堆线程），让它走既有的
     "脚本失效 → 重新附着 / 降级为仅界面采集"路径，而不是一路挂着。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional, Set

# 25 秒：正常 RPC 都是毫秒级，最慢的 get_policy/read_web_views 实测 2~3 秒。
# 留到这个量级只为容忍一次设备端 GC 或 adb 抖动；超过就说明进程真的不动了。
DEFAULT_TIMEOUT = 25.0


class RpcTimeout(RuntimeError):
    """一次 frida 同步调用超时（进程不动 / 通道断了）。"""

    def __init__(self, label: str, timeout: float, *, dead: bool = False) -> None:
        self.label = label
        self.timeout = timeout
        self.dead = dead
        if dead:
            super().__init__("脚本已失效：%s 之前超时过，不再等待" % label)
        else:
            super().__init__("%s 超过 %.0f 秒没有返回（目标进程可能已卡死）"
                             % (label, timeout))


def call(fn: Callable[[], Any], timeout: Optional[float] = None,
         label: str = "frida") -> Any:
    """带超时地执行一次同步调用。

    用线程而不是信号：Windows 上没有可用的定时信号，而平台的实机采集
    固定跑在 Windows 本机（见 DEPLOY.md）。超时后线程留在后台（Python 无法
    强杀线程），但调用方一定能继续走 —— 这正是"停止按钮能生效"的前提。
    """
    box: dict = {}

    def _run() -> None:
        try:
            box["val"] = fn()
        except BaseException as e:            # noqa: BLE001  原样抛给调用方
            box["err"] = e

    t = threading.Thread(target=_run, daemon=True,
                         name="frida-rpc:%s" % label)
    t.start()
    t.join(DEFAULT_TIMEOUT if timeout is None else timeout)
    if t.is_alive():
        raise RpcTimeout(label, DEFAULT_TIMEOUT if timeout is None else timeout)
    if "err" in box:
        raise box["err"]
    return box.get("val")


# ---------------------------------------------------------------- 会话登记
# 看门狗"强制停止"时要能拿到当前活跃的会话。只存引用，不参与生命周期管理。
_SESSIONS: Set[Any] = set()
_SESSIONS_LOCK = threading.Lock()


def track_session(session: Any) -> None:
    with _SESSIONS_LOCK:
        _SESSIONS.add(session)


def untrack_session(session: Any) -> None:
    with _SESSIONS_LOCK:
        _SESSIONS.discard(session)


def active_sessions() -> list:
    with _SESSIONS_LOCK:
        return list(_SESSIONS)


def detach_all_async() -> int:
    """尽力把所有会话 detach 掉，**不等待**。

    必须异步：冻结状态下 `detach()` 自己会卡住（实测），同步调会把
    看门狗线程也一起搭进去。这里只负责把请求发出去。
    """
    ses_list = active_sessions()
    for ses in ses_list:
        threading.Thread(target=_safe_detach, args=(ses,), daemon=True,
                         name="frida-detach").start()
    return len(ses_list)


def _safe_detach(ses: Any) -> None:
    try:
        ses.detach()
    except Exception:
        pass
    finally:
        untrack_session(ses)


# ---------------------------------------------------------------- 脚本包装
class _Exports:
    """`script.exports_sync` 的替身：每次方法调用都带超时。"""

    def __init__(self, guard: "GuardedScript") -> None:
        self._g = guard

    def __getattr__(self, name: str) -> Callable[..., Any]:
        def _call(*a: Any, **kw: Any) -> Any:
            return self._g._invoke(name, lambda: getattr(self._g._real.exports_sync,
                                                        name)(*a, **kw))
        return _call


class GuardedScript:
    """给 frida 脚本套一层超时。行为上尽量透明（.on / .unload 等原样透传）。"""

    def __init__(self, real: Any, timeout: Optional[float] = None) -> None:
        self._real = real
        self._timeout = DEFAULT_TIMEOUT if timeout is None else float(timeout)
        self._dead = False
        self._exports = _Exports(self)

    # ---- 内部 ----
    def _invoke(self, label: str, fn: Callable[[], Any]) -> Any:
        if self._dead:
            raise RpcTimeout(label, self._timeout, dead=True)
        try:
            return call(fn, timeout=self._timeout, label=label)
        except RpcTimeout:
            # 标记失效：后续调用立刻失败，不再堆线程。
            # 上层既有"脚本失效 → rehook / 降级仅界面采集"的分支会接手。
            self._dead = True
            raise

    # ---- 对外接口 ----
    @property
    def exports_sync(self) -> _Exports:
        return self._exports

    def load(self, *a: Any, **kw: Any) -> Any:
        return self._invoke("load", lambda: self._real.load(*a, **kw))

    def post(self, *a: Any, **kw: Any) -> Any:
        # post 是单向消息，不会卡；原样透传。
        return self._real.post(*a, **kw)

    @property
    def dead(self) -> bool:
        return self._dead

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


def wrap_script(script: Any, timeout: Optional[float] = None) -> Any:
    """把 frida 脚本换成带超时的包装；已经包过或占位对象原样返回。"""
    if script is None or isinstance(script, GuardedScript):
        return script
    # `_NoScript`（未注入时的替身）没有真实通道，包了反而多一层，
    # 且它自己的方法本来就是立即返回。
    if script.__class__.__name__ == "_NoScript":
        return script
    return GuardedScript(script, timeout)


def attach(device: Any, pid: int, timeout: Optional[float] = None) -> Any:
    """带超时地 attach，并把会话登记进活跃表（供强制中止使用）。"""
    ses = call(lambda: device.attach(pid),
               timeout=DEFAULT_TIMEOUT if timeout is None else timeout,
               label="attach")
    track_session(ses)
    return ses


def stats() -> dict:
    with _SESSIONS_LOCK:
        n = len(_SESSIONS)
    return {"active_sessions": n, "default_timeout": DEFAULT_TIMEOUT}
