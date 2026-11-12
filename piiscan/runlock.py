"""跨进程独占锁 —— 「同时只有一个 App 在测」必须由操作系统作证。

## 为什么需要这一层

平台用单 Worker 顺序取任务，"只有一个 App 在测"这个结论**建立在
"只有一个服务进程"之上**。而 Windows 上 `SO_REUSEADDR` 的真实语义是
"允许重复绑定已被占用的端口"（不是 Linux 那种"只复用 TIME_WAIT"），
于是第二个 `run_platform.py` **不会**报"端口已被占用"，而是静默地
也绑上同一个 8760，再起一个自己的 Worker。

实测（2026-10-25，用户批量提交商店链接时发现）：`netstat` 里
`127.0.0.1:8760` 同时有 **2 个 LISTENING**，`run_platform.py` 有 4 个进程
（两次启动各一对父子）。两个 Worker 各自从同一个 jobs.db 取任务，
两个 App 装在同一台手机上同时跑 —— 截图、事件流、权限弹窗互相污染，
而报告里两条任务都写着"已完成"。这类污染**不会报错**，只会让结论
悄悄错掉，是最坏的一种。

## 两道锁，各自解决一类问题

    workdir 锁  一个工作目录只允许一个服务进程（跨端口也拦住）
    device 锁   一台设备只允许一个任务在跑（跨 workdir、跨端口仍然成立）

device 锁按**设备**而不是按目录加，因为真正的稀缺资源是那台手机：
有人用 `--workdir D:/out2 --port 9000` 再起一个服务时，workdir 锁形同虚设，
但两台服务看到的是同一台手机。

## 实现取舍

- 用**操作系统文件锁**（Windows `msvcrt.locking`，POSIX `flock`），
  不用"写个 pid 文件再判断进程是否存活"：后者在进程被强杀、
  PID 被复用、两个进程同时写入时会给出错误答案；文件锁由内核在
  进程退出时自动释放，不存在"锁没清掉"的状态。
- 锁文件与信息文件分开：锁只锁 1 个字节，持有者信息（PID/端口/
  启动时间）写进 `<锁名>.info`。避免"截断重写已锁区域"这种平台差异。
- 拿不到锁**不抛异常**，返回 False 让调用方决定是退出还是等 ——
  服务启动要退出（并告诉人是谁占着），任务执行要等（等到就说明上一位跑完了）。
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

IS_WIN = os.name == "nt"

# 锁文件占位字节。锁定区域必须在文件内，空文件在部分平台会被当成
# "越界区域"而报错（Linux flock 无所谓，Windows LockFile 允许越界，
# 但两边都写 1 字节最省心）。
_MARK = b"\0"


class FileLock:
    """进程级独占锁。`acquire()` 拿不到返回 False，不抛异常。"""

    def __init__(self, path: str | Path, info: Optional[Dict[str, Any]] = None):
        self.path = Path(path)
        self.info_path = self.path.with_name(self.path.name + ".info")
        self.info = dict(info or {})
        self._fh = None
        self.acquired = False

    # ---------------------------------------------------------------- 获取
    def acquire(self) -> bool:
        if self._fh is not None:
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fh = open(self.path, "a+b")
        except OSError:
            return False
        try:
            fh.seek(0)
            if fh.read(1) == b"":          # 空文件先写占位，再锁
                fh.seek(0)
                fh.write(_MARK)
                fh.flush()
            fh.seek(0)
            if IS_WIN:
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, len(_MARK))
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # 已被别人持有（Windows: EACCES/EDEADLK，POSIX: EWOULDBLOCK）
            try:
                fh.close()
            except OSError:
                pass
            return False
        self._fh = fh
        self.acquired = True
        self._write_info()
        return True

    def acquire_wait(self, wait_s: float, poll_s: float = 5.0,
                     on_wait=None, should_stop=None) -> bool:
        """等锁，最多 `wait_s` 秒（`wait_s<=0` 表示一直等）。

        `on_wait(elapsed)` 会被周期性回调（用于写"正在等另一位跑完"这类日志），
        只在第一次和之后每 `poll_s` 秒调用，避免刷屏。
        """
        t0 = time.time()
        last_notice = -1e9
        while True:
            if self.acquire():
                return True
            if should_stop is not None and should_stop():
                return False
            elapsed = time.time() - t0
            if wait_s and elapsed >= wait_s:
                return False
            # 第一次立刻提示，之后每 poll_s 秒一次（等 40 分钟不能只写一行）
            if on_wait is not None and elapsed - last_notice >= poll_s:
                last_notice = elapsed
                on_wait(elapsed)
            time.sleep(max(0.05, poll_s))

    # ---------------------------------------------------------------- 释放
    def release(self) -> None:
        fh, self._fh = self._fh, None
        self.acquired = False
        if fh is None:
            return
        try:
            fh.seek(0)
            if IS_WIN:
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, len(_MARK))
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            try:
                fh.close()
            except OSError:
                pass

    # ---------------------------------------------------------------- 信息
    def _write_info(self) -> None:
        data = dict(self.info)
        data.setdefault("pid", os.getpid())
        data.setdefault("started_at", time.time())
        data["updated_at"] = time.time()
        try:
            self.info_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError:
            pass

    # 供 with 语句使用
    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False


def read_holder(lock: FileLock) -> Dict[str, Any]:
    """读锁的持有者信息（拿不到锁时用来告诉人"是谁占着"）。

    崩溃残留的 info 不会被清掉，所以这里必须自己判断 PID 是否还活着，
    否则会出现"提示说 PID 1234 在跑，其实那个进程早没了"。
    """
    try:
        data = json.loads(lock.info_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    pid = data.get("pid")
    alive = pid_alive(pid) if isinstance(pid, int) else None
    data["alive"] = alive
    return data


def pid_alive(pid: int) -> bool:
    """进程是否还活着。只用于提示，不作为加锁依据。"""
    if not pid or pid <= 0:
        return False
    if IS_WIN:
        # os.kill(pid, 0) 在 Windows 上会真的终止进程（Python 的 CTRL_C/TERM 语义），
        # 绝不能用它探活。这里用 OpenProcess 查询。
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            h = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
            if not h:
                return False
            try:
                code = ctypes.c_ulong()
                ok = ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
                return bool(ok) and code.value == 259  # STILL_ACTIVE
            finally:
                ctypes.windll.kernel32.CloseHandle(h)
        except Exception:
            return True     # 探测失败就往"还活着"偏，宁可多提示也不误判
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


# ---------------------------------------------------------------- 路径约定

def workdir_lock_path(workdir: str | Path) -> Path:
    """服务实例锁：放在工作目录里，一个工作目录一个实例。"""
    return Path(workdir) / ".platform.lock"


def device_lock_path(key: str = "auto") -> Path:
    """设备锁：放在**用户目录**下而不是工作目录里。

    因为要覆盖"另一个人用别的 --workdir 又起了一个服务"这种情况 ——
    工作目录不同，但手机只有一台。
    """
    safe = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in (key or "auto"))
    return Path.home() / ".piiscan" / ("device-%s.lock" % safe)


def probe_free(path: str | Path) -> Optional[bool]:
    """锁现在是不是**空闲**的。只探测，不写入、不占用。

    返回 None 表示"探不出来"，调用方不能据此下任何结论。

    ★ 为什么要单独一个函数，而不是 `FileLock.acquire()` 试一下再放掉：
      `acquire()` 会把持有者信息**写进 .info**。用它来探测，等于每次查一下
      就把上一个持有者的信息覆盖成本进程的 —— 之后再 `read_holder()` 读到的
      是一份"我们自己的探测记录"，而不是"谁真的在跑"。

    ★ 为什么判据必须是内核锁而不是 .info 里的 PID：
      `.info` 在进程退出后不会被删，而 PID 会被系统复用。实测（2026-11-11）：
      一条任务的进程早就被杀，但它的 PID 恰好落到了刚启动的浏览器上，
      于是界面一直显示那台机"占用中"，队列提示也跟着说"要排队" ——
      实际上没有任何任务在跑。文件锁由内核在进程退出时释放，不会骗人。
    """
    p = Path(path)
    try:
        fh = open(p, "rb")
    except FileNotFoundError:
        return True                      # 锁文件都没有 = 没人锁
    except OSError:
        return None
    locked = False
    try:
        try:
            if IS_WIN:
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, len(_MARK))
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            locked = True                # 拿不到 = 有人在锁着
        if not locked:
            try:
                if IS_WIN:
                    import msvcrt
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, len(_MARK))
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        try:
            fh.close()
        except OSError:
            pass
    return not locked


def describe_holder(holder: Dict[str, Any], lock: FileLock) -> str:
    """把持有者信息写成一句人话（用于启动失败时的提示）。"""
    if not holder:
        return "（占用者信息缺失，锁文件：%s）" % lock.path
    bits = []
    pid = holder.get("pid")
    if pid:
        bits.append("PID %s" % pid)
    if holder.get("alive") is False:
        bits.append("该进程已不存在（锁会被内核在进程退出时释放，若仍占用请删除锁文件）")
    if holder.get("port"):
        bits.append("端口 %s" % holder.get("port"))
    if holder.get("started_at"):
        bits.append("启动于 %s" % time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(float(holder["started_at"]))))
    if holder.get("workdir"):
        bits.append("工作目录 %s" % holder.get("workdir"))
    if holder.get("job"):
        bits.append("正在跑 %s" % holder.get("job"))
    return "，".join(bits) or "（信息为空）"
