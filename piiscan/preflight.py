"""环境自检与自动准备（preflight）。

**为什么必须单独有这一层**

    这套程序最终要由别的系统（AI 编排器、调度平台、批处理脚本）无人值守地调用。
    此前的做法是人坐在旁边：手机连没连、frida-server 起没起、屏幕锁没锁，
    都是人肉看一眼才发现。人一撤走，"没连设备"就会变成任务跑到一半崩掉，
    "frida-server 没起"会变成整轮采集一条事件都没有 —— 而这两种情况
    在报告里看起来都像"这个 App 很干净"，是最危险的假阴性。

    所以把"开跑之前的全部前提"收成一个函数：检查 → 能修的自己修 → 修不了
    就带着可执行的原因失败。调用方拿到结果要么直接开跑，要么把 detail/fix
    原样回给人工，不存在"跑了一半才发现"。

**设计原则**

    · 每一项都返回**可核对的证据**（命令 + 设备/本机原文），不做"看起来没问题"。
    · 能自动修的（唤醒、解锁、启动 frida-server、端口转发）自己修，并在
      `fixed` 上标明"这一项是本轮自动修复的"，让日志能区分"本来就好的"和"修过的"。
    · 修不了的不猜、不降级掩盖：`ok=False` + `fix` 里写清人工要做什么。
    · 与设备的所有交互都走 adb / frida 官方接口，不假设 root 之外的权限。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

Log = Callable[[str], None]
_NOP: Log = lambda *_a, **_k: None

# frida-server 在设备上的固定落点。放 /data/local/tmp 是因为它可执行且
# 不需要动 /system；Magisk 机型上这已是通行做法。
DEVICE_TMP = "/data/local/tmp"

# 本机找 frida-server 二进制的搜索顺序。
# 之所以要搜索而不是写死一个路径：这套程序会被整体搬到别的机器/容器里跑，
# 那时 frida-server 可能放在项目目录、也可能放在某个固定目录。
_LOCAL_FRIDA_PATTERNS = (
    "tools/frida-server*", "frida-server*", "../frida-server*",
)


def _adb(serial: str = "") -> List[str]:
    # 找 adb 的唯一实现是 adbtool：环境变量 → SDK 目录 → PATH → 默认安装位置。
    # 原来只认 `ADB` 或 PATH 里的 `adb`，Android Studio 装好但从没配过 PATH 的
    # 机器上，自检会报「未找到 adb」，而它其实躺在 %LOCALAPPDATA%\Android\Sdk 下。
    from .adbtool import adb_exe
    return [adb_exe()] + (["-s", serial] if serial else [])


def _run(args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        raise
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, -9, b"", b"timeout")


def _text(p: subprocess.CompletedProcess) -> str:
    return ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace").strip()


# ============================================================================
#  结果模型
# ============================================================================

@dataclass
class Check:
    key: str                 # 稳定标识，供程序判断（不要用 title 做判断）
    title: str               # 给人看的一句话
    ok: bool
    detail: str = ""         # 证据：命令 + 原文输出
    fix: str = ""            # 不 ok 时：人工该做什么
    fixed: bool = False      # 是否本轮自动修复
    fatal: bool = True       # 不 ok 是否阻断整个检测

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "title": self.title, "ok": self.ok,
                "detail": self.detail, "fix": self.fix,
                "fixed": self.fixed, "fatal": self.fatal}


def _explain(c: "Check", with_fix: bool = True) -> str:
    """把一项失败讲清楚：**先给原因（detail），再给建议（fix）**。

    ★ 顺序不能反。旧版是 `fix or detail`，于是所有设备类失败都显示成同一句
      「拔插数据线后重试」，真实原因（`error: no devices/emulators found`、
      `device offline`、`dump 调用异常`）被建议盖住了。2026-10-26 批量自检
      失败时日志里只剩建议，只能靠人去拔插试出来是哪一类问题 ——
      这不叫"提示"，叫"猜谜"。
    """
    d = re.sub(r"\s+", " ", str(c.detail or "")).strip()
    f = re.sub(r"\s+", " ", str(c.fix or "")).strip()
    if len(d) > 200:
        d = d[:200] + "…"
    if len(f) > 140:
        f = f[:140] + "…"
    if d and f and with_fix:
        # 「若持续出现」这四个字是分寸：单次抖动靠自愈已经过去了，
        # 建议只在它复现时才有意义。
        return "%s；若持续出现，%s" % (d, f)
    if d:
        return d
    if f and with_fix:
        return f
    return "未记录原因"


@dataclass
class PreflightReport:
    ok: bool = False
    serial: str = ""
    device: Dict[str, str] = field(default_factory=dict)
    checks: List[Check] = field(default_factory=list)
    started_at: float = 0.0
    elapsed: float = 0.0

    def add(self, c: Check) -> Check:
        self.checks.append(c)
        return c

    def get(self, key: str) -> Optional[Check]:
        for c in self.checks:
            if c.key == key:
                return c
        return None

    def blockers(self) -> List[Check]:
        return [c for c in self.checks if not c.ok and c.fatal]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok, "serial": self.serial, "device": dict(self.device),
            "elapsed": round(self.elapsed, 2),
            "checks": [c.to_dict() for c in self.checks],
            "blockers": [c.key for c in self.blockers()],
        }

    def summary(self) -> str:
        bad = self.blockers()
        if self.ok:
            n_fix = sum(1 for c in self.checks if c.fixed)
            return "环境自检通过（%d 项）%s" % (
                len(self.checks),
                "，其中 %d 项由程序自动修复" % n_fix if n_fix else "")
        return "环境自检未通过：%s" % "；".join(
            "%s —— %s" % (c.title, _explain(c)) for c in bad)

    def brief(self) -> List[str]:
        """一行一项的简表，给日志用。"""
        out = []
        for c in self.checks:
            mark = "OK " if c.ok else "ERR"
            if c.ok and c.fixed:
                mark = "FIX"
            out.append("[%s] %s%s" % (mark, c.title, "" if c.ok else "：" + _explain(c, False)))
        return out


# ============================================================================
#  设备发现
# ============================================================================

@dataclass
class DeviceEntry:
    serial: str
    state: str               # device / offline / unauthorized …
    model: str = ""
    product: str = ""


def list_devices() -> List[DeviceEntry]:
    """解析 `adb devices -l`。只返回真实存在的行，不臆造。"""
    p = _run(_adb() + ["devices", "-l"], timeout=25)
    out = _text(p)
    devs: List[DeviceEntry] = []
    for ln in out.splitlines()[1:]:
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split()
        if len(parts) < 2:
            continue
        d = DeviceEntry(serial=parts[0], state=parts[1])
        for tok in parts[2:]:
            if tok.startswith("model:"):
                d.model = tok.split(":", 1)[1]
            elif tok.startswith("product:"):
                d.product = tok.split(":", 1)[1]
        devs.append(d)
    return devs


def _device_prop(serial: str, name: str) -> str:
    try:
        p = _run(_adb(serial) + ["shell", "getprop", name], timeout=15)
        return _text(p).strip()
    except Exception:
        return ""


def _has_root(serial: str) -> bool:
    """su 可用性。真机（Magisk）上是 frida-server 能否启动的前提。"""
    if not serial:
        return False
    try:
        p = _run(_adb(serial) + ["shell", "su -c id"], timeout=20)
        return "uid=0" in _text(p)
    except Exception:
        return False


# ============================================================================
#  frida-server 自动准备
# ============================================================================

def _local_frida_version() -> str:
    try:
        import frida
        return str(getattr(frida, "__version__", "") or "")
    except Exception:
        return ""


def find_local_frida_server(explicit: str = "") -> Optional[Path]:
    """在本机找 frida-server 可执行文件。找不到返回 None（不猜路径）。"""
    for cand in (explicit, os.environ.get("FRIDA_SERVER", "")):
        if cand and str(cand).strip():
            p = Path(str(cand).strip())
            if p.exists() and p.is_file():
                return p
    roots = [Path.cwd(), Path(__file__).resolve().parent.parent,
             Path(__file__).resolve().parent.parent.parent, Path.home()]
    seen = set()
    for root in roots:
        for pat in _LOCAL_FRIDA_PATTERNS:
            for p in sorted(root.glob(pat)):
                if not p.is_file() or p in seen:
                    continue
                seen.add(p)
                # 只认二进制本身：排除 .py/.txt/.json 之类的同名文件
                if p.suffix.lower() in (".py", ".txt", ".json", ".md", ".sh", ".exe"):
                    continue
                return p
    return None


def _remote_frida_names(serial: str) -> List[str]:
    """设备 /data/local/tmp 下已有的 frida-server 文件名（无需 root 也可 ls）。"""
    try:
        p = _run(_adb(serial) + ["shell", "ls %s" % DEVICE_TMP], timeout=20)
    except Exception:
        return []
    return [ln.strip() for ln in _text(p).splitlines()
            if ln.strip().startswith("frida-server")]


def _frida_proc(serial: str) -> str:
    """设备上正在跑的 frida-server 进程名（空串=没在跑）。"""
    try:
        p = _run(_adb(serial) + ["shell", "su -c 'ps -A | grep frida-server'"], timeout=20)
    except Exception:
        return ""
    for ln in _text(p).splitlines():
        if "frida-server" in ln and "grep" not in ln:
            return ln.split()[-1]
    return ""


def _start_frida(serial: str, remote: str, log: Log) -> tuple:
    """启动 frida-server。返回 (ok, detail)。

    `-D` 让它转入后台：不加的话 adb shell 会一直挂着，父进程一退服务就被收掉。
    这是实测踩过的坑 —— 前台启动看起来成功，之后 frida 连不上。
    """
    cmd = "su -c 'nohup %s/%s -D >/dev/null 2>&1 &'" % (DEVICE_TMP, remote)
    try:
        p = _run(_adb(serial) + ["shell", cmd], timeout=40)
        out = _text(p)
    except Exception as e:
        return False, "启动命令执行失败：%s" % e
    # 给守护进程一点启动时间再判定，否则 100% 误判为失败
    for _ in range(12):
        time.sleep(0.5)
        if _frida_proc(serial):
            return True, "已启动：%s（%s）" % (remote, out[:120] or "无输出")
    return False, "启动后未发现进程。命令输出：%s" % (out[:200] or "(空)")


def _find_frida_bin(abi: str, version: str, explicit: str = "") -> Tuple[Optional[Path], str]:
    """找一份能推给这台设备的 frida-server。返回 (路径, 说明)。

    ★ 为什么要换成 `fridabin`（2026-11-11）：旧实现 `find_local_frida_server`
      只按文件名找、**不看 ABI**。接入一台 32 位 arm 的手机时，它会把本机的
      arm64 二进制推上去 —— push 成功、chmod 成功、启动后"未发现进程"，
      而错误看起来像"su 没授权"。两个 ABI 的文件名只差几个字符，人眼看不过来。
      这里把"版本 + ABI 双匹配"交给唯一实现，找不到时说明差在哪。

    `explicit` 仍然优先（人明确指定的就该用），但会返回文件名以便日志留痕。
    """
    p = Path(str(explicit or "").strip()) if str(explicit or "").strip() else None
    if p is not None and p.exists() and p.is_file():
        return p, "使用指定的二进制：%s" % p.name
    try:
        from . import fridabin
        return fridabin.find(abi=abi or "", version=version or "",
                             allow_download=False)
    except Exception as e:                       # noqa: BLE001
        return None, "查找本机 frida-server 失败：%s" % e


def ensure_frida_server(serial: str, log: Log = _NOP,
                        explicit_path: str = "") -> Check:
    """确保 frida-server 在设备上运行；不在就自动装上并启动。

    这一项是无人值守里最容易失守的一环：frida-server 不是常驻服务，
    手机重启、被系统清理、换设备之后都不会自己回来。人不在旁边时，
    没有它整轮采集就是空跑。
    """
    local_ver = _local_frida_version()
    if not local_ver:
        return Check("frida_lib", "frida 运行库可用", False,
                     "本机 Python 环境里 import frida 失败",
                     "在检测机的 Python 环境安装 frida（版本需与 frida-server 一致）")

    proc = _frida_proc(serial)
    if proc:
        # 已在跑：再确认一次这个进程名与本地库版本是否对得上
        m = re.search(r"(\d+\.\d+\.\d+)", proc)
        sv = m.group(1) if m else ""
        if sv and sv != local_ver:
            return Check("frida_server", "frida-server 运行中（版本需匹配）", False,
                         "设备上运行 %s，本机 frida 库为 %s" % (proc, local_ver),
                         "版本不一致会导致脚本注入失败。请换成 frida-server-%s 并重启服务" % local_ver)
        return Check("frida_server", "frida-server 运行中", True,
                     "进程：%s（本机 frida 库 %s，版本一致）" % (proc, local_ver))

    # 没在跑 → 尝试自动准备
    log("[*] 设备上未发现 frida-server 进程，尝试自动启动…")
    remotes = _remote_frida_names(serial)
    # ABI 必须与设备一致：推错 ABI 的表现是"启动后没有进程"，
    # 与"su 没授权"长得一模一样，事后极难分辨。
    abi = _device_prop(serial, "ro.product.cpu.abi")
    local, why_local = _find_frida_bin(abi, local_ver, explicit_path)
    if local is None:
        log("[!] %s" % why_local)

    # ★ 先挑**版本完全一致**的那个，没有就自己推一个。
    #   2026-11-10 接入第二台测试机（Redmi 9 / Android 10）时踩到的：
    #   /data/local/tmp 里躺着别人留下的 frida-server-16.7.19，而本机 frida
    #   库是 16.7.18。旧逻辑"优先用一致的那个，没有就用 remotes[0]" →
    #   启动了 16.7.19，`frida.get_device()` 照样连得上（它只是握手），
    #   到 spawn + 加载脚本时才失败，而日志看起来像"脚本写错了"。
    #   设备上留着不同版本的二进制是常态（换机、升级客户端都会留），
    #   所以这一步必须自己纠偏，不能指望人先清干净。
    pick = next((r for r in remotes if local_ver and local_ver in r), "")
    if not pick and local is not None:
        m = re.search(r"(\d+\.\d+\.\d+)", local.name)
        lv = m.group(1) if m else ""
        if lv and lv != local_ver:
            return Check("frida_server", "frida-server 运行中", False,
                         "本机二进制 %s，但 frida 库为 %s" % (local.name, local_ver),
                         "版本不一致会导致注入失败。请换成 frida-server-%s" % local_ver)
        log("[*] 设备上没有与本地 frida %s 一致的二进制，推送：%s → %s/"
            % (local_ver, local.name, DEVICE_TMP))
        try:
            p = _run(_adb(serial) + ["push", str(local), "%s/%s" % (DEVICE_TMP, local.name)],
                     timeout=300)
            if p.returncode != 0:
                return Check("frida_server", "frida-server 运行中", False,
                             "推送失败：%s" % _text(p)[:200],
                             "确认 adb 可写 /data/local/tmp（部分定制系统会拦截）")
            _run(_adb(serial) + ["shell", "chmod 755 %s/%s" % (DEVICE_TMP, local.name)], timeout=20)
        except Exception as e:
            return Check("frida_server", "frida-server 运行中", False,
                         "推送过程异常：%s" % e, "手动 adb push 后重试")
        remotes = [local.name]
        pick = local.name

    if not pick:
        if not remotes:
            # 把"哪一份缺"写进 detail：设备 ABI 与本地 frida 版本是两个独立的
            # 前提，只说"没找到"会让人拿一个 ABI 不对的二进制反复重试。
            return Check("frida_server", "frida-server 运行中", False,
                         "设备上没有 frida-server；%s（设备 ABI %s，本机 frida %s）"
                         % (why_local or "本机也没找到可推送的二进制",
                            abi or "未知", local_ver),
                         "把与 frida %s 同版本、ABI 为 %s 的 frida-server 放到项目目录"
                         "（或 %s/），也可设置环境变量 FRIDA_SERVER 指向它"
                         % (local_ver, abi or "设备对应 ABI", "tools/frida"))
        # 走到这里说明版本对不上、本机也没得推 —— 仍然试一次，但把风险写明，
        # 免得后面"注入失败"看起来像别的原因。
        pick = remotes[0]
        log("[!] 设备上只有 %s，与本机 frida %s 版本不同；先尝试启动，"
            "若注入失败请换成 frida-server-%s" % (pick, local_ver, local_ver))
    ok, detail = _start_frida(serial, pick, log)
    if not ok:
        return Check("frida_server", "frida-server 运行中", False, detail,
                     "设备可能未授权 su（Magisk 超级用户里给 Shell 放行），"
                     "或 SELinux 阻止执行。可手动执行：adb shell su -c '%s/%s -D &'"
                     % (DEVICE_TMP, pick))
    log("[+] frida-server 已自动启动：%s" % pick)
    return Check("frida_server", "frida-server 运行中", True, detail, fixed=True)


def _frida_connect(serial: str) -> Check:
    """真正连一次 frida —— 进程在跑不等于能连（端口/权限/SELinux 都可能挡）。"""
    try:
        import frida
    except Exception as e:
        return Check("frida_conn", "frida 可连接设备", False, "import frida 失败：%s" % e,
                     "安装 frida 运行库")
    for attempt in range(2):
        try:
            dev = frida.get_device(serial, timeout=10)
            procs = dev.enumerate_processes()
            return Check("frida_conn", "frida 可连接设备", True,
                         "已连接 %s，可见进程 %d 个" % (serial, len(procs)))
        except Exception as e:
            err = str(e)
            if attempt == 0:
                time.sleep(1.5)
                continue
            return Check("frida_conn", "frida 可连接设备", False,
                         "连接失败：%s" % err,
                         "frida-server 在跑但连不上，通常是端口未转发或被 SELinux 拦。"
                         "可试：adb forward tcp:27042 tcp:27042")
    return Check("frida_conn", "frida 可连接设备", False, "未知错误", "检查 frida-server")


# ============================================================================
#  主流程
# ============================================================================

def check_ai(cfg: Any, log: Log = _NOP) -> Check:
    """模型接口是否真的能用。

    分三层验，缺一层都会在跑起来之后才炸：
      ① 端口通（能拿到模型列表）—— 只说明有服务在听
      ② 配置的模型确实在服务端 —— 名字写错时端口照样通，注入时才 404
      ③ **真跑一次推理** —— 服务在、模型在，也可能因为显存不足 / 权重损坏 /
         请求排队而实际不可用。只测前两层等于用"端口开着"冒充"能干活"。

    非致命项（fatal=False）：AI 是能力增强不是运行前提，模型挂了照样能出报告，
    只是少几项语义增强。但**必须显式报出来** —— 否则用户以为在用 AI 复核，
    实际全程走的是关键词，结论的强度就不一样了。
    """
    ai = getattr(cfg, "ai", None)
    if ai is None:
        return Check("ai_api", "模型接口在线", True, "未配置 ai 段，本轮走纯规则",
                     fatal=False)
    provider = str(getattr(ai, "provider", "none") or "none").lower()
    if provider in ("", "none"):
        return Check("ai_api", "模型接口在线", True,
                     "provider=none，本轮不调用模型（报告由内置模板生成）",
                     fatal=False)

    model = str(getattr(ai, "model", "") or "")
    base = str(getattr(ai, "base_url", "") or "")
    budget = int(getattr(ai, "context_tokens", 8192) or 8192)

    # ---- 中继模式：不连任何服务，只看落盘目录 ----
    if provider in ("agent", "relay"):
        try:
            from .ai.factory import build_ai
            p = build_ai(ai)
            ok = p.available()
            return Check("ai_api", "模型接口在线", ok,
                         "Agent 中继已就绪：%s" % p.describe() if ok
                         else "中继目录不可写", fatal=False)
        except Exception as e:
            return Check("ai_api", "模型接口在线", False, "中继初始化失败：%s" % e,
                         fatal=False)

    try:
        from .ai.factory import build_ai
        p = build_ai(ai)
    except Exception as e:
        return Check("ai_api", "模型接口在线", False,
                     "%s 配置无效：%s" % (provider, e),
                     "检查 config.yaml 的 ai 段（provider / base_url / model）",
                     fatal=False)

    t0 = time.time()
    try:
        reachable = p.available()
    except Exception as e:
        reachable = False
        log("[!] 模型服务探测异常：%s" % e)
    if not reachable:
        return Check("ai_api", "模型接口在线", False,
                     "连不上 %s（%s）" % (base, provider),
                     "确认模型服务已启动、地址可路由；本机 ollama 通常要设 "
                     "OLLAMA_HOST=0.0.0.0:11434 才能被别的机器访问",
                     fatal=False)

    # ---- ② 模型在不在（仅 ollama 能直接列出）----
    names: List[str] = []
    real_ctx = 0
    if provider == "ollama":
        try:
            names = _ollama_models(base)
        except Exception:
            names = []
        if names:
            want = model.split(":")[0].strip()
            hit = [n for n in names if n == model or n.split(":")[0] == want]
            if not hit:
                return Check("ai_api", "模型接口在线", False,
                             "服务可达，但未找到模型「%s」（可用的有：%s）"
                             % (model, "、".join(names[:6])),
                             "把 config.yaml 的 ai.model 改成已部署的模型名",
                             fatal=False)
            model = hit[0]
        # 顺带把模型**真实的** num_ctx 读回来（`/api/show`，只读元数据、不加载权重）。
        # 为什么必须核这一项：所有"可送多少字"的预算都是从配置里的 context_tokens
        # 推出来的。配置比模型实际大 → 正文被**静默截尾**，模型没看完却报"已分析全文"，
        # 这是最危险的假阴性；配置比实际小 → 只是白砍预算，结论不受影响。
        # 读不到就保持 0（按"未核实"处理，不拿配置值冒充）。
        try:
            info = p.show(model) if hasattr(p, "show") else {}
            real_ctx = int((info or {}).get("num_ctx") or 0)
        except Exception:
            real_ctx = 0

    # ---- ③ 真跑一次推理 ----
    # ★ 超时不能一律 60s：模型**未加载**时，这一次调用要先把权重载进来
    #   （qwen3.8-fast 是 16.9GB 量级，纯 CPU 上可能几分钟）。给 60s 会把
    #   "正在加载"误判成"推理失败"，而这恰恰是部署后第一次自检的常态。
    #   已加载就给短超时（很快该回来），未加载才放宽。
    warmed = False
    try:
        if hasattr(p, "loaded"):
            names = p.loaded()
            if names:
                want = model.split(":")[0].strip()
                warmed = any(n == model or n.split(":")[0] == want for n in names)
    except Exception:
        warmed = False
    base_tmo = int(getattr(ai, "timeout", 90) or 90)
    tmo = min(60, max(20, base_tmo)) if warmed else max(180, min(300, base_tmo * 3))
    try:
        r = p.chat([{"role": "user", "content": "只回复两个字：在线"}], timeout=tmo)
        cost = time.time() - t0
        ans = (r or "").strip().replace("\n", " ")[:24]
        if not ans:
            return Check("ai_api", "模型接口在线", False,
                         "服务可达但返回空内容（%.1fs）" % cost,
                         "确认模型能正常推理（显存/权重/排队情况）", fatal=False)
        # 未加载时这次耗时含"载入权重"，不等于推理速度，必须点明，
        # 否则使用者会以为模型慢到 30 秒才回一句话。
        load_note = "" if warmed else "；耗时含首次加载权重"
        # 配置与模型实际上下文不一致时的提示。方向不同、后果不同，措辞不能一样：
        # 配大了会截尾（假阴性），配小了只是浪费预算（不影响正确性）。
        ctx_note = ""
        if real_ctx and budget and real_ctx != budget:
            if budget > real_ctx:
                ctx_note = ("；⛔ 配置 context_tokens=%d **大于**模型实际 num_ctx=%d，"
                            "超长正文会被静默截尾（模型没看完却报告已分析全文），"
                            "请把 config.yaml 改成 %d" % (budget, real_ctx, real_ctx))
            else:
                ctx_note = ("；⚠ 配置 context_tokens=%d 小于模型实际 num_ctx=%d，"
                            "结论不受影响，但每段可送的字数被白砍了（可改成 %d）"
                            % (budget, real_ctx, real_ctx))
        return Check("ai_api", "模型接口在线", True,
                     "%s / %s 实测可用（%.1fs%s，返回「%s」）；单次可送正文约 %d 字"
                     "（上下文 %d token，含输出预留）%s"
                     % (provider, model, cost, load_note, ans,
                        p.input_budget_chars(), budget, ctx_note),
                     # 通过分支也要显式标非致命：Check 的默认值是 fatal=True，
                     # 漏写就会让「AI 在线」这条自检变成阻断项 —— 与另外五条
                     # 失败分支的口径不一致，将来有人改动这个分支就会踩到。
                     fatal=False)
    except Exception as e:
        return Check("ai_api", "模型接口在线", False,
                     "服务可达但推理失败：%s" % e,
                     "检查模型是否加载完整、显存是否够用", fatal=False)


def _ollama_models(base_url: str) -> List[str]:
    import json as _json
    import urllib.request as _ur
    url = base_url.rstrip("/") + "/api/tags"
    with _ur.urlopen(url, timeout=8) as resp:
        data = _json.loads(resp.read().decode("utf-8", "replace"))
    return [str(m.get("name") or "") for m in (data.get("models") or []) if m.get("name")]


def run(cfg: Any, log: Log = _NOP, *, apk_path: str = "",
        auto_fix: bool = True, need_device: bool = True) -> PreflightReport:
    """执行全部自检。cfg 为 AppConfig（需要 .device.serial / .root）。

    返回的 report.ok 是唯一判据：True 才可以开跑。
    """
    t0 = time.time()
    rep = PreflightReport(started_at=t0)

    # ---- 1. adb ----
    # ★ 必须走 `_adb()`，不能写死 "adb"：采集、收尾、设备标识、崩溃信息五处
    #   都认 `ADB` 环境变量，只有这里不认 —— 于是自检报"未找到 adb 可执行文件"，
    #   而它自己的建议正是"设置环境变量 ADB 指向 adb 可执行文件"。用户照着做
    #   还是不通过，因为这条检查压根没读那个变量（2026-11-06 实测踩到）。
    try:
        p = _run(_adb() + ["version"], timeout=20)
        out = _text(p)
        ver = ""
        m = re.search(r"version (\d+\.\d+\.\d+)", out)
        if m:
            ver = m.group(1)
        rep.add(Check("adb", "adb 可用", p.returncode == 0 and bool(ver),
                      ("adb %s" % ver) if ver else out[:200],
                      "把 platform-tools 加进 PATH，或设置环境变量 ADB 指向 adb 可执行文件"))
    except FileNotFoundError:
        rep.add(Check("adb", "adb 可用", False, "未找到 adb 可执行文件",
                      "安装 Android platform-tools 并加入 PATH（或设置 ADB 环境变量）"))
        rep.ok = False
        rep.elapsed = time.time() - t0
        return rep
    except Exception as e:
        rep.add(Check("adb", "adb 可用", False, "调用 adb 异常：%s" % e, "检查 adb 安装"))
        rep.elapsed = time.time() - t0
        return rep

    if not need_device:
        # 只做静态分析的场景：设备不是前提，直接收工
        rep.add(Check("device", "设备（本轮不需要）", True, "本次未启用动态采集", fatal=False))
        # 但模型接口仍要验——静态阶段的政策解析同样依赖它
        rep.add(check_ai(cfg, log))
        # ★ adb 不可用在这里**不算失败**：纯静态分析根本不碰设备。
        #   adb 那一项仍以红色显示，让人知道动态检测做不了；
        #   但不能因为它把"只跑静态"的作业拦下来。
        rep.ok = True
        rep.elapsed = time.time() - t0
        return rep

    # ---- 2. 设备发现与选择 ----
    want = (getattr(getattr(cfg, "device", None), "serial", "") or "").strip()
    devs = list_devices()

    # ★「设备暂时不在 adb 里」不等于「没插线」（2026-10-26 批量实测取证）。
    #   批量跑到某个 APK 时 USB 会偶发重新枚举：`adb devices` 短暂为空或
    #   offline，两秒左右自己回来。旧逻辑在这里当场判死，整轮检测白跑，
    #   而提示写的是「确认 USB 连接」—— 人只能靠拔插试。
    #   这里先等一次（上限 40s），等不到再照原样报错；判据仍是 adb 原文。
    def _usable(ds: List[DeviceEntry]) -> bool:
        if want:
            h = next((x for x in ds if x.serial == want), None)
            return h is not None and h.state == "device"
        return any(x.state == "device" for x in ds)

    dev_wait = ""
    if not _usable(devs):
        try:
            from . import uiwalk as _UW
            okd, note = _UW.ensure_device(want, wait_s=40.0, log=log)
            if okd:
                dev_wait = note or "已恢复"
                log("[*] 自检开始时设备不在 adb 里，等待后已恢复：%s" % dev_wait)
        except Exception as e:                     # 自愈本身失败不能掩盖原问题
            log("[!] 等待设备恢复时出错：%s" % e)
        devs = list_devices()

    online = [d for d in devs if d.state == "device"]
    offline = [d for d in devs if d.state != "device"]

    if want:
        hit = next((d for d in devs if d.serial == want), None)
        if hit is None:
            rep.add(Check("device", "目标设备在线", False,
                          "配置指定的设备 %s 不在线。当前 adb 可见：%s"
                          % (want, "、".join("%s(%s)" % (d.serial, d.state) for d in devs) or "无"),
                          "确认 USB 连接/无线调试，或把 config.yaml 的 device.serial 改成当前设备"))
            rep.elapsed = time.time() - t0
            return rep
        if hit.state != "device":
            rep.add(Check("device", "目标设备在线", False,
                          "设备 %s 状态为 %s（未授权时请在手机上点允许 USB 调试）"
                          % (want, hit.state),
                          "在手机上允许 USB 调试；若一直 offline，执行 adb kill-server 后重插"))
            rep.elapsed = time.time() - t0
            return rep
        serial = want
        rep.add(Check("device", "目标设备在线", True,
                      "%s（指定）%s" % (serial, hit.model)))
    else:
        if not online:
            detail = "adb 未发现任何在线设备"
            if offline:
                detail += "；存在但不可用：%s" % "、".join(
                    "%s(%s)" % (d.serial, d.state) for d in offline)
            rep.add(Check("device", "自动发现设备", False, detail,
                          "用 USB 连接测试机并允许 USB 调试；无线调试需先 adb connect"))
            rep.elapsed = time.time() - t0
            return rep
        if len(online) > 1:
            # ★ 多台设备时不猜。选错机器的代价是"测了另一个 App 的机器状态"，
            #   报告看起来完全正常，却全是错的 —— 这类错误无法事后从数据里发现。
            rep.add(Check("device", "自动发现设备", False,
                          "发现 %d 台在线设备：%s" % (len(online), "、".join(
                              "%s(%s)" % (d.serial, d.model) for d in online)),
                          "多台设备同时在线时程序不替你选。请在 config.yaml 的 "
                          "device.serial 指定要用的那台（命令行可加 -s <序列号>，"
                          "平台在「测试机」下拉框里选）"))
            rep.elapsed = time.time() - t0
            return rep
        serial = online[0].serial
        rep.add(Check("device", "自动发现设备", True,
                      "自动选中唯一在线设备 %s（%s）" % (serial, online[0].model)))
    rep.serial = serial

    # ---- 3. 设备响应与基础信息 ----
    try:
        p = _run(_adb(serial) + ["shell", "echo", "piiscan-ok"], timeout=20)
        ok = "piiscan-ok" in _text(p)
        rep.add(Check("shell", "设备 shell 可执行", ok,
                      "adb shell 返回：%s" % (_text(p)[:80] or "(空)"),
                      "设备无响应。重启 adb（adb kill-server）或重新插拔 USB"))
    except Exception as e:
        rep.add(Check("shell", "设备 shell 可执行", False, "异常：%s" % e, "检查 adb 连接"))
        rep.elapsed = time.time() - t0
        return rep

    info = {
        "model": _device_prop(serial, "ro.product.model"),
        "android": _device_prop(serial, "ro.build.version.release"),
        "sdk": _device_prop(serial, "ro.build.version.sdk"),
        "abi": _device_prop(serial, "ro.product.cpu.abi"),
        "brand": _device_prop(serial, "ro.product.brand"),
    }
    rep.device = info
    rep.add(Check("device_info", "设备信息可读", bool(info["model"]),
                  "%s / Android %s (SDK %s) / %s"
                  % (info["model"] or "未知", info["android"] or "?",
                     info["sdk"] or "?", info["abi"] or "?"),
                  "读不到设备型号，可能是 adb 授权不完整"))

    # ---- 4. root ----
    rooted = _has_root(serial)
    rep.add(Check("root", "设备具备 root（su）", rooted,
                  "su -c id：%s" % ("uid=0" if rooted else "不可用"),
                  "frida-server 需要 root 启动。Magisk 机型请在「超级用户」里给 Shell 授权；"
                  "未 root 的设备无法注入应用进程，动态采集不可用"))

    # ---- 5. 屏幕状态（唤醒 + 解锁）----
    try:
        from . import uiwalk as UW
        UW.keep_screen_on(serial)
        UW.wake(serial)
        time.sleep(0.6)
        locked = UW.is_locked(serial)
        if locked:
            log("[*] 设备处于锁屏，尝试自动解锁…")
            unlocked = UW.try_unlock(serial, log=log)
            if unlocked:
                rep.add(Check("screen", "屏幕已唤醒并解锁", True,
                              "检测到锁屏，已由程序自动解锁", fixed=True))
            else:
                rep.add(Check("screen", "屏幕已唤醒并解锁", False,
                              "设备仍处于锁屏",
                              "自动化无法绕过锁屏密码。请设置无密码（滑动解锁），"
                              "或人工解锁后把「保持唤醒」打开"))
        else:
            rep.add(Check("screen", "屏幕已唤醒并解锁", True, "当前为解锁状态"))
    except Exception as e:
        rep.add(Check("screen", "屏幕已唤醒并解锁", False, "检查过程异常：%s" % e,
                      "手动确认设备亮屏且已解锁"))

    # ---- 5.5 界面结构可读性（uiautomator）----
    # 为什么要在自检里管这个：UI 遍历、首启弹窗识别、政策入口点击全部依赖
    # `uiautomator dump`。上一个任务崩溃/取消后残留的僵死 `uiautomator` 进程会
    # 让它每次都超时（真机实测一次 25 秒且不返回），整条任务队列就卡在采集阶段
    # 看似"还在跑"、实际不动。事先探一次并清掉残留，比事后人工 ps 找 PID 靠谱。
    try:
        from . import uiwalk as UW2
        UW2.reset_dump_health(serial)
        stale = UW2._pidof(serial)
        killed = 0
        if stale:
            log("[*] 设备端存在 %d 个残留 uiautomator 进程（%s），正在清理…"
                % (len(stale), ",".join(stale)))
            killed, alive = UW2.kill_stale_uiautomator(serial)
            if alive:
                log("[!] 有 %d 个 uiautomator 进程杀不掉（pid %s），需重启设备"
                    % (len(alive), ",".join(alive)))
        # ★ 先回桌面再测（洋葱学园 2026-10-27 实测）：这一项检查的是**设备**的
        #   界面导出能力，不该被"此刻恰好停在哪个应用上"影响。洋葱学园的首启页
        #   窗口持续重绘，uiautomator 等 idle 超时后直接不落盘（`could not get
        #   idle state`）→ 自检判"界面结构不可读取"→ 整轮任务判失败；同一台设备
        #   回到桌面，190 个节点、65 KB 一次就出来了 —— 问题在那个页面，不在设备。
        try:
            UW2.home(serial)
            time.sleep(1.5)
        except Exception:
            pass
        t0 = time.time()
        xml = UW2.dump(serial, force=True)
        # ★ 失败后给设备几次机会，别一次就判死（2026-11-06 实测）：
        #   上一轮采集被强杀后，设备端 uiautomator 往往还卡着几秒，这时立刻
        #   启新一轮，自检 100% 挂在这一项（连续 3 次都是 2~3 秒内报"无有效输出"）。
        #   对着同一个瞬间反复判"设备不可用"，会把一个"等两秒就好"的问题
        #   变成"整轮检测失败"，用户只能反复点重试。
        for _try in range(3):
            if xml:
                break
            if UW2.device_state(serial) != "device":
                break                    # 链路问题走下面的掉线恢复逻辑
            if _try == 0:
                try:
                    UW2.kill_stale_uiautomator(serial)
                except Exception:
                    pass
            time.sleep(2.5)
            xml = UW2.dump(serial, force=True)
        cost = time.time() - t0

        # ★ 失败后**先分清是哪种失败**（2026-10-26 批量实测取证）：
        #   · 页面导不出来（WebView / 切换中）→ 老问题，记一笔即可；
        #   · 设备已从 adb 掉线 → `get-state` 会报 no devices/offline，
        #     等两秒它自己就回来了。旧逻辑把这两种混为一谈，一律判死，
        #     于是"USB 抖一下"变成"整轮检测失败"。
        #   判据只看 adb 原文，不看耗时、不猜。
        recovered = ""
        if not xml:
            st = UW2.device_state(serial)
            if UW2.link_down(st) or st != "device":
                okd, note = UW2.ensure_device(serial, wait_s=45.0, log=log)
                if okd:
                    # 掉线导致的失败不该计入"界面服务熔断"：这是链路的错，
                    # 不是设备端 UI 自动化的错。不重置的话，下一次真失败会被
                    # 上一次的账一起压进降级期。
                    UW2.reset_dump_health(serial)
                    killed = 0
                    t1 = time.time()
                    xml = UW2.dump(serial, force=True)
                    cost += time.time() - t1
                    if xml:
                        recovered = ("首次导出时设备已从 adb 掉线（%s）；%s；重新导出成功；"
                                     % (st, note or "已恢复"))

        if xml:
            n = len(UW2.parse_all(xml))
            detail = "%s本次导出耗时 %.1fs，节点 %d 个" % (recovered, cost, n)
            if killed:
                detail += "；已清理 %d 个卡死的 uiautomator 进程" % killed
            rep.add(Check("ui_dump", "界面结构可读取（uiautomator）", True, detail,
                          fixed=bool(killed or recovered)))
        else:
            # 真因必须写进 detail：旧版只写"无有效输出"，而 summary 又优先显示
            # 建议句，于是所有人看到的都是"拔插数据线后重试"，无从判断到底是
            # 设备掉了、还是页面导不出、还是 uiautomator 僵死。
            reason = ((UW2.dump_health(serial) or {}).get("reason") or "").strip()
            st2 = UW2.device_state(serial)
            detail = "uiautomator dump 无有效输出（%.1fs）" % cost
            if reason:
                detail += "；底层原因：%s" % reason
            detail += "；此刻 adb get-state：%s" % st2
            if killed:
                detail += "；已清理 %d 个残留进程仍未恢复" % killed
            fix = ("若 adb get-state 不是 device，检查数据线与接口后重试；"
                   "若是 device，执行 `adb shell su -c 'pkill -9 -f uiautomator'` 后重试")
            rep.add(Check("ui_dump", "界面结构可读取（uiautomator）", False,
                          detail, fix))
    except Exception as e:
        rep.add(Check("ui_dump", "界面结构可读取（uiautomator）", False,
                      "检查过程异常：%s" % e, "重启 adb 服务后重试"))

    # ---- 6. frida-server（含自动启动）----
    if auto_fix:
        rep.add(ensure_frida_server(
            serial, log, getattr(getattr(cfg, "device", None), "frida_server", "") or ""))
    else:
        proc = _frida_proc(serial)
        rep.add(Check("frida_server", "frida-server 运行中", bool(proc),
                      "进程：%s" % (proc or "未发现"),
                      "启动 frida-server（或允许程序自动启动）"))

    # ---- 7. frida 连接 ----
    if rep.get("frida_server") is not None and rep.get("frida_server").ok:
        rep.add(_frida_connect(serial))
    else:
        rep.add(Check("frida_conn", "frida 可连接设备", False,
                      "前置项 frida-server 未就绪，跳过连接测试",
                      "先解决 frida-server"))

    # ---- 8.5 模型接口（在线 + 模型存在 + 真跑一次）----
    # 放在设备检查之后、磁盘之前：设备全通了再发现模型挂了，至少人还在终端前，
    # 不至于等采集跑完、报告写出来才发现全程没用到 AI。
    rep.add(check_ai(cfg, log))

    # ---- 9. 磁盘空间 ----
    try:
        base = Path(getattr(cfg, "root", None) or Path.cwd())
        du = shutil.disk_usage(str(base))
        free_gb = du.free / (1024.0 ** 3)
        # 一轮检测的产物：APK 副本 + 截图 base64 + 采集存档 JSON，通常 < 1 GB。
        # 留 2 GB 余量，低于这个数就没有重试空间了。
        rep.add(Check("disk", "工作目录剩余空间", free_gb >= 2.0,
                      "%s 剩余 %.1f GB" % (base, free_gb),
                      "清理磁盘。采集存档含截图 base64，单个任务可达数百 MB",
                      fatal=False))
    except Exception as e:
        rep.add(Check("disk", "工作目录剩余空间", True, "无法读取：%s" % e, fatal=False))

    # ---- 10. APK（可选）----
    if apk_path:
        p = Path(apk_path)
        if p.exists() and p.is_file():
            size_mb = p.stat().st_size / 1048576.0
            rep.add(Check("apk", "待测 APK 可读", True,
                          "%s（%.1f MB）" % (p.name, size_mb)))
        else:
            rep.add(Check("apk", "待测 APK 可读", False, "文件不存在：%s" % apk_path,
                          "确认上传/下载是否成功、路径是否正确"))

    rep.ok = not rep.blockers()
    rep.elapsed = time.time() - t0
    return rep
