"""测试机的接入（enroll）：把"刚插上的一台手机"变成"平台可用的检测设备"。

## 这件事为什么需要一个独立流程

在此之前，测试机是**隐式**存在的：`adb devices` 里有什么，平台就显示什么。
于是"这台机能不能用"要靠人自己判断 —— 型号认不认识、USB 调试授权了没、
root 过没有、frida-server 起没起。任何一项缺了，症状都一样：
任务跑完，报告里全是"跳过未测"。

接入流程把这一串前提收成**有序、可观察、失败即止**的步骤，每一步都带
证据（命令 + 设备原文）和"人该做什么"。这样加一台手机不需要读文档。

## 与"轮询探测"的分界线

`webapp/server.py` 的 `_PROBE_SCRIPT` **绝不允许执行 su**（2026-11-11 定下的），
因为前端每 10 秒拉一次设备列表，su 会让 Magisk 每次弹授权通知、还会亮屏。

这里是**一次性的显式动作**：用户点了「添加手机」，就表示同意在这台机上
做一次提权验证。所以这里执行 `su -c id` 是对的 —— 而且必须真的执行，
否则"已 root"就只是"看到了 su 文件"（2026-11-11 已明确的口径）。

## 失败时的分寸

· root 拿不到 → 直接失败，**不登记**。登记一台不能跑动态采集的机器，
  只会让人在任务下拉里选到它，然后在自检里失败 —— 那是把问题推迟到更难查的地方。
· 唯一例外：`force=True`（界面上"仅登记信息，稍后再解决 root"）。
  此时登记的记录会带 `usable=False`，且下拉框里标记为不可用。
· frida-server 装不上 → 也失败。但会区分三种原因（本机没二进制 / push 被拦 /
  启动了没进程），因为三种原因的修法完全不同。
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

Log = Callable[[str], None]


# ============================================================================
#  步骤模型
# ============================================================================

@dataclass
class Step:
    key: str
    title: str
    state: str = "pending"       # pending / running / ok / fail / skip
    detail: str = ""
    fix: str = ""
    fixed: bool = False          # 这一步是本流程自动完成的"修复"
    fatal: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "title": self.title, "state": self.state,
                "detail": self.detail, "fix": self.fix,
                "fixed": self.fixed, "fatal": self.fatal}


@dataclass
class EnrollResult:
    ok: bool = False
    serial: str = ""
    steps: List[Step] = field(default_factory=list)
    info: Dict[str, str] = field(default_factory=dict)
    error: str = ""
    elapsed: float = 0.0
    #: 是否属于"仅登记信息"（root 未通过但用户坚持登记）
    degraded: bool = False

    def step(self, key: str) -> Optional[Step]:
        for s in self.steps:
            if s.key == key:
                return s
        return None

    def failed(self) -> List[Step]:
        return [s for s in self.steps if s.state == "fail"]

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "serial": self.serial,
                "steps": [s.to_dict() for s in self.steps],
                "info": dict(self.info), "error": self.error,
                "elapsed": round(self.elapsed, 1),
                "degraded": self.degraded}


#: 步骤清单（顺序即执行顺序）。前端在接入开始前就能把它们画成灰条，
#: 让人知道"还要等几步、到哪一步了"—— 比一个转圈更能让人等得住。
STEP_TITLES = [
    ("adb", "adb 可用"),
    ("online", "设备已连接并授权 USB 调试"),
    ("shell", "设备 shell 可执行"),
    ("info", "读取设备型号与系统版本"),
    ("root", "root 提权可用（su -c id 拿到 uid=0）"),
    ("frida_bin", "本机有匹配的 frida-server 二进制"),
    ("frida_server", "部署并启动 frida-server"),
    ("frida_conn", "frida 能连上设备"),
    ("screen", "屏幕已唤醒并解锁"),
    ("ui_dump", "界面结构可读取（uiautomator）"),
]


def _blank_steps() -> List[Step]:
    return [Step(k, t) for k, t in STEP_TITLES]


# ============================================================================
#  接入流程
# ============================================================================

def _adb(serial: str = "") -> List[str]:
    import os
    exe = os.environ.get("ADB", "adb")
    return [exe] + (["-s", serial] if serial else [])


def _run(args: List[str], timeout: int = 30):
    from . import preflight
    return preflight._run(args, timeout=timeout)


def _text(p) -> str:
    from . import preflight
    return preflight._text(p)


def _probe_root(serial: str, log: Log, tries: int = 3, gap: float = 6.0):
    """提权验证，带重试。返回 (ok, detail, fix)。

    ★ 为什么要重试：Magisk 默认对 `su` 是**弹窗询问**。第一次接入时弹窗弹出、
      人还没反应过来（或手机在桌上没看见），3 秒后请求就被拒了 ——
      报"未 root"是错话，真实情况是"授权还没给"。而这一项判错的后果很重：
      用户会去重新 root 一台本来就没问题的机器。
      所以这里试 3 次、每次隔 6 秒，并把"去手机上点允许"写进 detail。
    """
    last = ""
    for i in range(max(1, tries)):
        try:
            p = _run(_adb(serial) + ["shell", "su -c id"], timeout=20)
            out = _text(p).strip()
        except Exception as e:
            out = "调用异常：%s" % e
        if "uid=0" in out:
            return True, "su -c id → %s" % out.splitlines()[0][:80], ""
        last = out or "(无输出)"
        if i == 0:
            log("[!] su -c id 没有拿到 uid=0（%s）；如果手机屏幕上弹出了 Magisk 的"
                "「授权请求」，请在手机上点「允许」，本流程会再试两次"
                % last[:60])
        if i + 1 < tries:
            time.sleep(gap)
    return False, "su -c id 连续 %d 次都没有 uid=0，最后一次输出：%s" % (tries, last[:120]), (
        "① 这台机没装 root 方案 → 动态采集不可用（只能跑静态分析）；"
        "② 已装 Magisk → 在 Magisk「超级用户」里给「Shell」放行，或在弹窗上点「允许」；"
        "③ 已授权但仍失败 → 在手机终端确认 `su -c id` 能出 uid=0")


def _wait_online(serial: str, log: Log, res: EnrollResult, wait_s: float,
                 on_step: Optional[Callable[[EnrollResult], None]]) -> str:
    """等设备进入 device 状态。返回 "device" / 最后见到的状态。

    ★ 为什么这里要"等"而不是查一次就判死：
      `adb devices` 显示 `unauthorized` 时，人只需要在手机上点一下「允许 USB 调试」。
      如果程序当场判失败，用户点完允许还得自己回来重按一次「添加手机」；
      而这一步多半是他**第一次**接入时会遇到的。所以等（默认 90 秒），
      并在 detail 里写清"现在手机上该做什么"。
    """
    from . import preflight
    deadline = time.time() + max(5.0, wait_s)
    last_state = ""
    tick = 0
    st = res.step("online")
    while time.time() < deadline:
        try:
            devs = preflight.list_devices()
        except Exception:
            devs = []
        hit = next((d for d in devs if d.serial == serial), None)
        cur = hit.state if hit else "absent"
        if cur != last_state:
            last_state = cur
            tick = 0
            if cur == "device":
                break
            if cur == "unauthorized":
                st.detail = ("设备已插上，但**未授权 USB 调试**：请解锁手机，"
                             "在「允许 USB 调试吗？」弹窗上点「允许」"
                             "（勾选「一律允许」以后就不会再问）")
                log("[*] 设备 %s 处于 unauthorized：请在手机上点「允许 USB 调试」" % serial)
            elif cur == "offline":
                st.detail = ("设备处于 offline：USB 连接不稳或调试授权失效，"
                             "可以拔插数据线，或执行 adb kill-server 后重连")
            elif cur == "absent":
                st.detail = ("adb 里看不到这台设备（可能刚被拔掉，或 USB 模式不是"
                             "「传输文件/调试」）。正在等待它重新出现…")
            else:
                st.detail = "设备状态：%s（正在等待它变为 device）" % cur
            st.state = "running"
            if on_step:
                on_step(res)
        tick += 1
        if tick % 2 == 0:
            st.detail = re.sub(r"（已等待 \d+ 秒）", "", st.detail) + \
                        "（已等待 %d 秒）" % int(time.time() - (deadline - wait_s))
            if on_step:
                on_step(res)
        time.sleep(1.0)
    return last_state


def enroll(serial: str, *, log: Log = lambda *_a, **_k: None,
           on_step: Optional[Callable[[EnrollResult], None]] = None,
           allow_download: bool = True, wait_s: float = 90.0,
           force: bool = False) -> EnrollResult:
    """把一台手机接入为可用检测设备。同步执行，逐步回调 `on_step`。

    `on_step` 每完成/开始一步调用一次，调用方（HTTP 层）据此把进度推给前端。
    它必须足够轻 —— 会被调用几十次（等待授权时每秒一次）。
    """
    t0 = time.time()
    res = EnrollResult(serial=(serial or "").strip())
    res.steps = _blank_steps()

    def emit() -> None:
        if on_step:
            try:
                on_step(res)
            except Exception:
                pass

    def done(key: str, ok: bool, detail: str = "", fix: str = "", fixed: bool = False):
        s = res.step(key)
        if s is None:
            return
        s.state = "ok" if ok else "fail"
        s.detail = detail
        s.fix = fix if not ok else ""
        s.fixed = fixed
        emit()

    def fail_rest(from_key: str) -> None:
        """失败之后把剩下的步骤标成"未执行"。

        必须标出来而不是留着 pending：pending 在前端看起来像"还在跑"，
        而实际上流程已经停了 —— 那会让人一直等下去。
        """
        hit = False
        for s in res.steps:
            if s.key == from_key:
                hit = True
                continue
            if hit and s.state in ("pending", "running"):
                s.state = "skip"
                s.detail = "前一步失败，本步未执行"
        emit()

    if not res.serial:
        done("adb", False, "没有指定设备序列号", "先点「扫描设备」，从列表里选一台")
        fail_rest("adb")
        res.error = "没有指定设备序列号"
        res.elapsed = time.time() - t0
        return res

    # ---- 1. adb ----
    from . import preflight
    res.step("adb").state = "running"
    emit()
    try:
        p = _run(_adb() + ["version"], timeout=20)
        out = _text(p)
        m = re.search(r"version (\d+\.\d+\.\d+)", out)
        if p.returncode == 0 and m:
            done("adb", True, "adb %s" % m.group(1))
        else:
            done("adb", False, out[:160] or "adb version 执行失败",
                 "把 platform-tools 加进 PATH，或设置环境变量 ADB 指向 adb 可执行文件")
            fail_rest("adb")
            res.error = "adb 不可用"
            res.elapsed = time.time() - t0
            return res
    except FileNotFoundError:
        done("adb", False, "未找到 adb 可执行文件",
             "安装 Android platform-tools 并加入 PATH（或设置 ADB 环境变量）")
        fail_rest("adb")
        res.error = "adb 不可用"
        res.elapsed = time.time() - t0
        return res

    # ---- 2. 在线且已授权（可等待）----
    log("[*] 等待设备 %s 就绪（最多 %d 秒）…" % (res.serial, int(wait_s)))
    st = _wait_online(res.serial, log, res, wait_s, on_step)
    if st != "device":
        s = res.step("online")
        detail = s.detail or ("设备最终状态：%s" % (st or "未知"))
        done("online", False, detail,
             "USB 数据线要在「传输文件(MTP)」或「传输照片(PTP)」模式下，"
             "并允许 USB 调试；无线调试需先 adb connect <ip:端口>")
        fail_rest("online")
        res.error = "设备未就绪：%s" % (st or "未知")
        res.elapsed = time.time() - t0
        return res
    done("online", True, "设备已连接且 USB 调试已授权")

    # ---- 3. shell ----
    res.step("shell").state = "running"
    emit()
    try:
        p = _run(_adb(res.serial) + ["shell", "echo", "piiscan-enroll"], timeout=20)
        out = _text(p)
        if "piiscan-enroll" in out:
            done("shell", True, "adb shell 返回正常")
        else:
            done("shell", False, "adb shell 返回：%s" % (out[:120] or "(空)"),
                 "设备无响应。重启 adb（adb kill-server）或重新插拔 USB")
            fail_rest("shell")
            res.error = "设备 shell 不可用"
            res.elapsed = time.time() - t0
            return res
    except Exception as e:
        done("shell", False, "异常：%s" % e, "检查 adb 连接")
        fail_rest("shell")
        res.error = "设备 shell 不可用"
        res.elapsed = time.time() - t0
        return res

    # ---- 4. 设备信息 ----
    res.step("info").state = "running"
    emit()
    info = {
        "model": preflight._device_prop(res.serial, "ro.product.model"),
        "brand": preflight._device_prop(res.serial, "ro.product.brand"),
        "android": preflight._device_prop(res.serial, "ro.build.version.release"),
        "sdk": preflight._device_prop(res.serial, "ro.build.version.sdk"),
        "abi": preflight._device_prop(res.serial, "ro.product.cpu.abi"),
        "abis": preflight._device_prop(res.serial, "ro.product.cpu.abilist"),
    }
    res.info = info
    if info["model"]:
        done("info", True, "%s / %s / Android %s (API %s) / %s"
             % (info["model"], info["brand"] or "?", info["android"] or "?",
                info["sdk"] or "?", info["abi"] or "?"))
    else:
        done("info", False, "读不到 ro.product.model",
             "adb 授权可能不完整。在手机上撤销 USB 调试授权后重新插上并允许")
        fail_rest("info")
        res.error = "读不到设备信息"
        res.elapsed = time.time() - t0
        return res

    # ---- 5. root ----
    res.step("root").state = "running"
    emit()
    ok_root, detail, fix = _probe_root(res.serial, log)
    if ok_root:
        done("root", True, detail)
    elif force:
        # 用户明确选择"仅登记信息"。这是**降级**，不是成功 —— 必须标出来，
        # 否则任务下拉会让人以为这台机可用。
        res.degraded = True
        done("root", True, detail + "（用户选择仅登记信息，动态采集不可用）",
             fixed=False)
    else:
        done("root", False, detail, fix)
        fail_rest("root")
        res.error = "root 不可用：这台机现在无法用于动态采集"
        res.elapsed = time.time() - t0
        return res

    # ---- 6. frida-server 二进制 ----
    res.step("frida_bin").state = "running"
    emit()
    local_ver = ""
    try:
        from . import fridabin
        local_ver = fridabin.local_version()
    except Exception:
        fridabin = None                       # noqa: F841
    if not local_ver:
        done("frida_bin", False, "本机 Python 环境 import frida 失败",
             "在检测机的 Python 环境安装 frida（版本需与 frida-server 一致）")
        fail_rest("frida_bin")
        res.error = "本机没有 frida 运行库"
        res.elapsed = time.time() - t0
        return res

    # 设备上已经躺着一份匹配版本的，就不必再找本机二进制
    remote_hit = ""
    try:
        remotes = preflight._remote_frida_names(res.serial)
        remote_hit = next((r for r in remotes if local_ver in r), "")
    except Exception:
        remote_hit = ""
    bin_path = ""
    if remote_hit:
        done("frida_bin", True, "设备上已有 %s（与本机 frida %s 一致），无需推送"
             % (remote_hit, local_ver))
    else:
        path, why = fridabin.find(abi=info.get("abi") or "", version=local_ver,
                                  allow_download=bool(allow_download), log=log)
        if path is None:
            done("frida_bin", False, why,
                 "内网无法访问 GitHub 时，手工下载 frida-server-%s-android-%s 放到 %s/ 后重试"
                 % (local_ver, fridabin.norm_abi(info.get("abi") or ""), fridabin.BIN_DIR))
            fail_rest("frida_bin")
            res.error = "本机缺少匹配的 frida-server"
            res.elapsed = time.time() - t0
            return res
        bin_path = str(path)
        done("frida_bin", True, "已选定 %s（本机 frida %s，设备 ABI %s）"
             % (path.name, local_ver, info.get("abi") or "?"))

    # ---- 7. 部署并启动 ----
    res.step("frida_server").state = "running"
    emit()
    chk = preflight.ensure_frida_server(res.serial, log, bin_path)
    if chk.ok:
        done("frida_server", True, chk.detail, fixed=bool(chk.fixed))
    else:
        done("frida_server", False, chk.detail, chk.fix)
        fail_rest("frida_server")
        res.error = "frida-server 启动失败"
        res.elapsed = time.time() - t0
        return res

    # ---- 8. frida 连接 ----
    res.step("frida_conn").state = "running"
    emit()
    conn = preflight._frida_connect(res.serial)
    if conn.ok:
        done("frida_conn", True, conn.detail)
    else:
        done("frida_conn", False, conn.detail, conn.fix)
        fail_rest("frida_conn")
        res.error = "frida 连不上设备"
        res.elapsed = time.time() - t0
        return res

    # ---- 9. 屏幕 ----
    res.step("screen").state = "running"
    emit()
    try:
        from . import uiwalk as UW
        UW.keep_screen_on(res.serial)
        UW.wake(res.serial)
        time.sleep(0.6)
        if UW.is_locked(res.serial):
            log("[*] 设备处于锁屏，尝试自动解锁…")
            if UW.try_unlock(res.serial, log=log):
                done("screen", True, "检测到锁屏，已自动解锁", fixed=True)
            else:
                done("screen", False, "设备仍处于锁屏",
                     "自动化无法绕过锁屏密码。请设置无密码（滑动解锁），"
                     "或在手机上解锁后把「保持唤醒」打开")
                fail_rest("screen")
                res.error = "设备处于锁屏且无法自动解锁"
                res.elapsed = time.time() - t0
                return res
        else:
            done("screen", True, "屏幕已唤醒，当前为解锁状态")
    except Exception as e:
        done("screen", False, "检查过程异常：%s" % e, "手动确认设备亮屏且已解锁")
        fail_rest("screen")
        res.error = "无法确认屏幕状态"
        res.elapsed = time.time() - t0
        return res

    # ---- 10. 界面结构 ----
    res.step("ui_dump").state = "running"
    emit()
    try:
        from . import uiwalk as UW2
        UW2.reset_dump_health(res.serial)
        try:
            UW2.kill_stale_uiautomator(res.serial)
        except Exception:
            pass
        try:
            UW2.home(res.serial)      # 回桌面再测：测的是"设备"能不能导出界面
            time.sleep(1.5)
        except Exception:
            pass
        xml = ""
        for i in range(3):
            xml = UW2.dump(res.serial, force=True)
            if xml:
                break
            time.sleep(2.5)
        if xml:
            n = len(UW2.parse_all(xml))
            done("ui_dump", True, "本次导出节点 %d 个" % n)
        else:
            reason = ((UW2.dump_health(res.serial) or {}).get("reason") or "").strip()
            done("ui_dump", False,
                 "uiautomator dump 无有效输出" + ("；底层原因：%s" % reason if reason else ""),
                 "执行 `adb shell su -c 'pkill -9 -f uiautomator'` 后重试；"
                 "若始终失败，这台机的 UI 自动化不可用")
            fail_rest("ui_dump")
            res.error = "界面结构不可读取"
            res.elapsed = time.time() - t0
            return res
    except Exception as e:
        done("ui_dump", False, "检查过程异常：%s" % e, "重启 adb 服务后重试")
        fail_rest("ui_dump")
        res.error = "界面结构不可读取"
        res.elapsed = time.time() - t0
        return res

    res.ok = True
    res.elapsed = time.time() - t0
    return res


# ============================================================================
#  登记簿的判定（纯函数，便于单测）
# ============================================================================

def usable(entry: Optional[Dict[str, Any]], dev: Optional[Dict[str, Any]]) -> bool:
    """一条登记记录 + 这台机的实时探测结果 → 现在能不能用来跑动态采集。

    分三个层次，缺一不可：
      · 登记时验证过 root（entry.root_ok）—— 说明这台机当初达标；
      · 此刻在 adb 里且状态是 device（dev.state）—— 说明它现在插着；
      · 此刻 su 文件还在（dev.root）—— 说明 root 没在这之后被撤掉。
    只看登记记录会说谎（机器可能被换了一台同序列号的、或被刷回原厂），
    只看实时探测会把"从没验证过"当成"可用"。两边的条件都要。
    """
    if not entry:
        return False
    if not entry.get("root_ok"):
        return False
    if not dev:
        return False
    return dev.get("state") == "device" and bool(dev.get("root"))
