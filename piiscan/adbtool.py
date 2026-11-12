"""adb 可执行文件的定位、连通性探测，以及「为什么一台设备都看不到」的判定。

★ 为什么单独一个模块（2026-11-12，用户换机器部署时踩到）：
  平台把 APK 拉到别的电脑上跑，Web 页面正常、手机也插上了，界面却写
  「未检测到测试机」。真实原因是那台机器上 **adb 根本不在 PATH 里** ——
  而 `list_test_devices()` 原来是

      try:
          p = subprocess.run(["adb", "devices", "-l"], ...)
      except Exception:
          out = ""

  把 `FileNotFoundError` 一并吞掉了。于是「没装 adb」「手机没插」「USB 调试
  没开」「没点允许授权」四种完全不同的毛病，在界面上是同一句话。
  用户能做的只有猜。

  这里的职责只有两条，但必须是唯一实现：
    1. 找到 adb —— 环境变量 → SDK 目录 → PATH → 各平台默认安装位置；
    2. 把 adb 的答复**原样**转成一句人能照着做的话，不猜、不美化。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

# 显式指定 adb 路径的环境变量（两个都认：ADB 是历来口径，ADB_PATH 是历史兼容）
_ENV_KEYS = ("ADB", "ADB_PATH")

# Android SDK 根目录环境变量 → 其下的 platform-tools/adb
_SDK_ENV = ("ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_SDK_HOME")

# 各平台默认安装位置。列这些不是"猜"，是把官方安装器与 Android Studio
# 的默认路径写下来 —— 用户没配 PATH 时，绝大多数人的 adb 就在其中某一个。
_WIN_DEFAULTS = (
    r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe",
    r"%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe",
    r"%ProgramFiles%\Android\platform-tools\adb.exe",
    r"%ProgramFiles(x86)%\Android\platform-tools\adb.exe",
    r"%SystemDrive%\platform-tools\adb.exe",
    r"%SystemDrive%\adb\adb.exe",
    r"C:\adb\adb.exe",
)

_POSIX_DEFAULTS = (
    "~/Library/Android/sdk/platform-tools/adb",
    "~/Android/Sdk/platform-tools/adb",
    "/usr/local/platform-tools/adb",
    "/opt/android-sdk/platform-tools/adb",
    "/usr/lib/android-sdk/platform-tools/adb",
    "/usr/share/android-sdk/platform-tools/adb",
)

# 设备状态不是 device 时，报告里必须点名是哪种"不在"
_OFF_STATES = ("unauthorized", "offline", "recovery", "sideload", "bootloader", "no permissions")

_EXE_NAME = "adb.exe" if os.name == "nt" else "adb"

# 解析结果缓存：键里带上会影响结果的环境变量，用户改了 ADB 之后
# 不重启服务也能生效（下一次调用就会重算）。
_RESOLVE_CACHE: Dict[str, Tuple[str, str]] = {}
_VERSION_CACHE: Dict[str, Tuple[str, float]] = {}


def _expand(p: str) -> str:
    return os.path.expanduser(os.path.expandvars(p))


def _is_exe(p: str) -> bool:
    if not p:
        return False
    p = _expand(p)
    return os.path.isfile(p)


def _cache_key() -> str:
    return "|".join(
        [os.environ.get(k, "") for k in _ENV_KEYS]
        + [os.environ.get(k, "") for k in _SDK_ENV]
        + [os.environ.get("PATH", ""), os.name]
    )


def candidates() -> List[Tuple[str, str]]:
    """按优先级返回 (路径, 来源说明)，只含**确实存在**的文件。

    来源说明会原样出现在界面与自检里 —— 用户需要知道平台用的是哪一个 adb，
    机器上常常同时装着两三个（Android Studio 的、手机助手自带的、自己下的）。
    """
    out: List[Tuple[str, str]] = []
    seen = set()

    def add(p: str, src: str):
        if not p:
            return
        key = os.path.normcase(_expand(p))
        if key in seen:
            return
        seen.add(key)
        out.append((_expand(p), src))

    for k in _ENV_KEYS:
        v = os.environ.get(k, "").strip()
        if not v:
            continue
        if _is_exe(v):
            add(v, "环境变量 %s" % k)
        else:
            w = shutil.which(v)
            if w:
                add(w, "环境变量 %s" % k)

    for k in _SDK_ENV:
        root = os.environ.get(k, "").strip()
        if root:
            add(os.path.join(root, "platform-tools", _EXE_NAME), "环境变量 %s" % k)

    w = shutil.which("adb")
    if w:
        add(w, "PATH")

    for p in (_WIN_DEFAULTS if os.name == "nt" else _POSIX_DEFAULTS):
        add(p, "默认安装路径")

    return out


def resolve() -> Tuple[str, str]:
    """返回 (可执行文件, 来源)。一个都没找到时返回 ("adb", "未找到")。

    ★ 找不到也返回 "adb" 而不是抛异常：上层（自检、界面）要能拿到
      "我按名字调了，但系统里没有" 这个事实，而不是在异常里丢掉上下文。
      是否真的能用，看 `find()`。
    """
    key = _cache_key()
    hit = _RESOLVE_CACHE.get(key)
    if hit:
        return hit
    cand = candidates()
    res = cand[0] if cand else ("adb", "未找到")
    _RESOLVE_CACHE.clear()          # 只留当前环境的这一份，避免缓存无界增长
    _RESOLVE_CACHE[key] = res
    return res


def adb_exe() -> str:
    """给所有需要拼命令行的地方用：`[adbtool.adb_exe()] + args`。"""
    return resolve()[0]


def find() -> bool:
    """系统里到底有没有 adb。"""
    return bool(candidates())


def version(max_age: float = 300.0) -> str:
    """`adb version` 里的版本号，取不到返回空串。缓存 5 分钟。

    为什么要缓存：界面每 10 秒轮询一次设备清单，每次都起一个 adb 进程
    只为读一行版本号是浪费；而 adb 版本在一台机器上几乎不会变。
    """
    import time

    exe = adb_exe()
    now = time.time()
    hit = _VERSION_CACHE.get(exe)
    if hit and now - hit[1] < max_age:
        return hit[0]
    ver = ""
    try:
        p = subprocess.run([exe, "version"], capture_output=True, timeout=15)
        out = _text(p)
        m = re.search(r"version (\d+\.\d+\.\d+)", out)
        if m:
            ver = m.group(1)
    except Exception:
        ver = ""
    _VERSION_CACHE[exe] = (ver, now)
    return ver


def _text(p) -> str:
    return ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace").strip()


def parse_devices(raw: str) -> List[Dict[str, str]]:
    """解析 `adb devices -l`。第一行是表头，必须跳过。

    只做解析，不判可用性 —— 「连上了」和「能用来跑采集」是两件事
    （后者还要 root / frida / 未被占用，由 devices.py 负责）。
    """
    out: List[Dict[str, str]] = []
    for ln in (raw or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("List of devices") or ln.startswith("*"):
            continue
        parts = ln.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        # `adb devices` 在没权限时会打一行 `no permissions (user in plugdev...)`，
        # 那一行的第二列是 "permissions"，按状态收下，别当成一台正常设备。
        if state == "no":
            state = "no permissions"
        model = ""
        for tok in parts[2:]:
            if tok.startswith("model:"):
                model = tok.split(":", 1)[1]
        out.append({"serial": serial, "state": state, "model": model})
    return out


def snapshot(devices: List[Dict[str, str]], raw: str = "",
             error: str = "", missing: bool = False) -> Dict[str, Any]:
    """把「adb 在哪 / 能不能用 / 看到几台」整理成界面与自检共用的一份结论。

    ★ 判定顺序不能反：先问 adb 在不在，再问看到几台。
      反过来的话，「没装 adb」会被写成「没有设备」，又回到原来那句害人的话。
    """
    exe, source = resolve()
    # ★ 「找到没有」以**实际执行结果**为准，不只信搜索函数：搜索列表里没有、
    #   但按名字调用却成功的情况是存在的（PATH 里刚加进去、缓存还没刷新）。
    #   反过来把"跑通了"报成"没找到 adb"，界面就会一边列着设备一边说没有 adb。
    found = (not missing) and (
        find() or bool(devices) or "List of devices" in (raw or ""))
    info: Dict[str, Any] = {
        "found": found,
        "exe": exe,
        "source": source,
        "version": version() if found else "",
        "count": len(devices or []),
        "online": len([d for d in (devices or []) if d.get("state") == "device"]),
        "error": (error or "").strip(),
        "message": "",
    }
    info["message"] = message(info, devices or [], raw or "")
    return info


def _where_looked() -> str:
    return "环境变量 ADB / ADB_PATH、ANDROID_HOME、PATH、各平台默认安装路径"


def message(info: Dict[str, Any], devices: List[Dict[str, str]], raw: str = "") -> str:
    """一句话说清现状 + 下一步该做什么。界面直接显示这句，不再自己拼文案。"""
    if not info.get("found"):
        return (
            "未找到 adb 可执行文件（已查：%s）。"
            "装好 Android platform-tools 后，把 platform-tools 目录加入 PATH，"
            "或设环境变量 ADB 指向 %s，然后重启平台服务（环境变量只在新进程里生效）。"
            % (_where_looked(), _EXE_NAME)
        )

    head = "adb 可用（%s%s，来源：%s）" % (
        info.get("version") and "v" + info["version"] + " " or "", info["exe"], info["source"])

    if devices:
        off = [d for d in devices if d.get("state") != "device"]
        if not off:
            return head + "，看到 %d 台已连接。" % len(devices)
        unauth = [d for d in off if d.get("state") == "unauthorized"]
        if unauth:
            return (
                head + "，看到 %d 台，其中 %d 台显示 unauthorized —— "
                "意思是手机连上了但没给这台电脑授权。看手机屏幕，点「允许 USB 调试」"
                "（可勾「一律允许」）；没弹窗就在「开发者选项」里点一下「撤销 USB 调试授权」再插一次。"
                % (len(devices), len(unauth))
            )
        return (
            head + "，看到 %d 台，但状态不是 device（%s）。"
            "offline 多半是 adb 版本与本机服务不匹配：先 `adb kill-server` 再重插。"
            % (len(devices), "、".join("%s=%s" % (d["serial"], d["state"]) for d in off[:3]))
        )

    if info.get("error"):
        return head + "，但 `adb devices` 报错：%s" % info["error"][:300]

    low = (raw or "").lower()
    if "no permissions" in low:
        return (
            head + "，但 adb 没有访问 USB 设备的权限（Linux 上常见）。"
            "按发行版把当前用户加入 plugdev 组，或为设备写 udev 规则后重新插拔；"
            "Windows 上则检查是否装了厂商 USB 驱动。"
        )

    return (
        head + "，但设备列表是空的。按顺序查："
        "① 手机「开发者选项 → USB 调试」是否打开；"
        "② 插上后手机上弹出的「允许 USB 调试」是否点了允许；"
        "③ 数据线是否只能充电（换线或换 USB 口，别用扩展坞前置口）；"
        "④ Windows 设备管理器里是否出现 Android ADB Interface（没有就是驱动没装）；"
        "⑤ 是否被手机助手/别的 adb 抢了 5037 端口（`adb kill-server` 后重试）。"
    )


def probe(with_devices: bool = True, timeout: int = 25) -> Dict[str, Any]:
    """做一次完整探测：找 adb → 读版本 → 读设备列表 → 出结论。

    只在「用户点全部自检」「界面空列表要解释原因」这类低频路径上调用；
    10 秒一次的轮询走 `snapshot()`，不要重复起进程。
    """
    if not find():
        return snapshot([], "", missing=True)

    raw = ""
    error = ""
    devs: List[Dict[str, str]] = []
    if with_devices:
        try:
            p = subprocess.run([adb_exe(), "devices", "-l"],
                               capture_output=True, timeout=timeout)
            raw = _text(p)
            if p.returncode != 0:
                error = raw[:300] or ("adb devices 返回 %d" % p.returncode)
            devs = parse_devices(raw)
        except FileNotFoundError:
            return snapshot([], "", missing=True)
        except subprocess.TimeoutExpired:
            error = "adb devices 超时（%ds）：adb 服务可能卡住了，试 `adb kill-server` 后重试" % timeout
        except Exception as e:                       # noqa: BLE001
            error = "调用 adb devices 异常：%s" % e
    return snapshot(devs, raw, error)
