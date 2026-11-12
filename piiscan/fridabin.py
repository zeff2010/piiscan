"""为**指定 ABI + 指定版本**找（或下载）frida-server 二进制。

## 为什么单独抽出来

`preflight.find_local_frida_server()` 只按文件名找，**不看 ABI**。接入第二台
手机时这一点会直接坏事：本机放着 `frida-server-16.7.18-android-arm64`，
新插进来的是一台 32 位 arm 设备，旧逻辑照样把 arm64 推上去 —— push 成功、
`chmod` 成功、启动之后「未发现进程」，而错误信息看起来像"su 没授权"。
同一台机器的两个 ABI 二进制在文件名里只差几个字符，靠人眼看不过来。

所以这里把"匹配"讲清楚：

    · 版本必须与本地 `frida` Python 库**完全一致**（不一致会在注入时失败，
      而握手阶段照样能连上 —— 这正是最容易被误判成"脚本写错"的形态）。
    · ABI 必须与设备的 `ro.product.cpu.abi` 同族。`arm64-v8a` 与 `arm64`
      是同一个东西的两种叫法，必须归一化后再比。

## 另外两个口径

· **只在显式动作里下载**（`allow_download=True`，即"添加手机"）。
  环境自检跑在任务开跑前，断网环境下每次去 GitHub 试一下会拖慢几十秒 ——
  所以自检只搜本地，搜不到就如实报"本机没有匹配的二进制"。
· 下载目标固定为 `tools/frida/`：`tmp/` 会被清理，不能作为部署依赖。
"""
from __future__ import annotations

import lzma
import os
import re
import shutil
import time
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

#: 二进制落地目录（相对于项目根 piiscan/）。
BIN_DIR = "tools/frida"

#: frida 官方 release 的命名规则。`frida-server-16.7.18-android-arm64`
_NAME_RE = re.compile(
    r"^frida-server"
    r"(?:[-_](\d+\.\d+\.\d+))?"          # 版本（老包可能不带）
    r"(?:[-_]android[-_]([A-Za-z0-9_]+))?$"   # ABI
)

#: 设备端 ABI（`ro.product.cpu.abi`）→ frida 发布包里的 ABI 名。
_ABI_ALIAS = {
    "arm64-v8a": "arm64", "arm64": "arm64", "aarch64": "arm64",
    "armeabi-v7a": "arm", "armeabi": "arm", "armv7l": "arm", "arm": "arm",
    "x86": "x86", "i386": "x86", "i686": "x86",
    "x86_64": "x86_64", "amd64": "x86_64",
}


def norm_abi(raw: str) -> str:
    """把各种叫法归一到 frida 的发布名（arm64 / arm / x86 / x86_64）。

    认不出来就原样返回小写 —— **不猜**成 arm64：猜错等于推错二进制，
    表现是"启动后没有进程"，比当场报"不认识的 ABI"难查得多。
    """
    s = (raw or "").strip().lower()
    return _ABI_ALIAS.get(s, s)


def parse_name(path_or_name: str) -> Tuple[str, str]:
    """从文件名解析 (版本, ABI)。解析不出就返回空串，不臆造。"""
    name = os.path.basename(str(path_or_name or ""))
    # 允许 `frida-server-16.7.18-android-arm64.xz` / `.bak` 这类后缀
    name = re.sub(r"\.(xz|gz|bak|exe|bin)$", "", name, flags=re.I)
    m = _NAME_RE.match(name)
    if not m:
        return "", ""
    return (m.group(1) or ""), norm_abi(m.group(2) or "")


def _roots() -> List[Path]:
    """候选搜索根。项目根 + 当前工作目录 + 家目录。

    为什么不写死绝对路径：这套程序会被整体搬到别的机器/容器里跑，
    每台部署机的目录结构不一样。宁可多试几个相对位置。
    """
    here = Path(__file__).resolve().parent
    roots = [here.parent, here.parent.parent, Path.cwd(), Path.home()]
    out: List[Path] = []
    seen = set()
    for r in roots:
        try:
            k = str(r.resolve())
        except Exception:
            k = str(r)
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


#: 相对每个搜索根的候选子目录。`tmp/frida` 是历史遗留位置（早期手工放的），
#: 仍然认它，但下载落地只用 `tools/frida`。
_SUBDIRS = ("", "tools", "tools/frida", "frida", "tmp/frida", "bin", "vendor")


def search(abi: str = "", version: str = "") -> List[Tuple[Path, str, str]]:
    """在本地搜 frida-server 二进制，返回 [(路径, 版本, ABI)]，按匹配度排序。

    `abi` / `version` 都为空时返回全部；给了就只返回"同版本同 ABI"的，
    仍然保留"只差一项"的作为**诊断信息**（调用方据此说清"为什么不能用"）。
    """
    want_abi = norm_abi(abi) if abi else ""
    found: List[Tuple[Path, str, str]] = []
    seen = set()
    for root in _roots():
        if not root.exists():
            continue
        for sub in _SUBDIRS:
            d = (root / sub) if sub else root
            try:
                if not d.is_dir():
                    continue
                entries = list(d.glob("frida-server*"))
            except Exception:
                continue
            for p in entries:
                try:
                    if not p.is_file():
                        continue
                except Exception:
                    continue
                # 同名但明显不是二进制的（脚本/说明）跳过。
                # `.bak` 也要排除：备份文件往往就是上一版被替换下来的那个，
                # 名字里带着版本号，很容易在对版本"不挑"的场合被推上去。
                if p.suffix.lower() in (".py", ".txt", ".json", ".md", ".sh",
                                        ".xml", ".bak", ".old", ".part"):
                    continue
                key = str(p.resolve()).lower()
                if key in seen:
                    continue
                seen.add(key)
                ver, ab = parse_name(p.name)
                found.append((p, ver, ab))

    def score(item: Tuple[Path, str, str]) -> Tuple[int, int, str]:
        _, ver, ab = item
        s = 0
        if want_abi and ab == want_abi:
            s -= 4
        if version and ver == version:
            s -= 2
        # 版本对但 ABI 不对，比 ABI 对但版本不对更糟（后者能启动、只是注入失败；
        # 前者连启动都不行）。上面的权重已经体现了这一点。
        return (s, 0 if (ver and version and ver == version) else 1, str(item[0]))

    found.sort(key=score)
    return found


def find(abi: str = "", version: str = "",
         allow_download: bool = False, log=None) -> Tuple[Optional[Path], str]:
    """找一台设备能用的 frida-server。返回 (路径, 说明)。

    说明永远非空 —— 失败时它就是给人看的下一步（不要返回 (None, "")，
    那会让上层写出"未知错误"）。
    """
    _log = log or (lambda *_a, **_k: None)
    want_abi = norm_abi(abi)
    cands = search(want_abi, version)

    exact = [c for c in cands
             if (not want_abi or c[2] == want_abi) and (not version or c[1] == version)]
    if exact:
        p = exact[0][0]
        return p, "本机已有匹配的二进制：%s" % p.name

    # ---- 不够匹配：说清楚差在哪，别让上层误以为是"没授权 su" ----
    why = []
    if cands:
        for p, ver, ab in cands[:4]:
            bits = []
            if version and ver != version:
                bits.append("版本 %s（需要 %s）" % (ver or "未知", version))
            if want_abi and ab != want_abi:
                bits.append("ABI %s（设备是 %s）" % (ab or "未知", want_abi))
            why.append("%s：%s" % (p.name, "、".join(bits) or "不匹配"))
    else:
        why.append("本机没找到任何 frida-server 二进制")

    if allow_download and version and want_abi:
        ok, msg = download(version, want_abi, log=_log)
        if ok:
            return Path(msg), "已下载 %s" % Path(msg).name
        why.append("自动下载失败：%s" % msg)

    fix = ("把与本地 frida 库同版本（%s）、且 ABI 为 %s 的 frida-server 放进 %s/，"
           "或设置环境变量 FRIDA_SERVER 指向它"
           % (version or "?", want_abi or "?", BIN_DIR))
    return None, "；".join(why) + "。" + fix


def download(version: str, abi: str, timeout: int = 180, log=None) -> Tuple[bool, str]:
    """从 frida 官方 release 下载并解压。返回 (ok, 路径或错误原因)。

    `.xz` 用标准库 lzma 解，不需要外部 xz 工具（部署机上通常没有）。
    下载完立刻校验文件名能解析出"同版本同 ABI"—— 防止代理返回一个 HTML
    错误页被当成二进制存下来，那种文件 push 上去只会报"格式错误"。
    """
    _log = log or (lambda *_a, **_k: None)
    ver = (version or "").strip()
    ab = norm_abi(abi)
    if not re.fullmatch(r"\d+\.\d+\.\d+", ver):
        return False, "版本号不可用（%r），无法拼下载地址" % version
    if ab not in ("arm64", "arm", "x86", "x86_64"):
        return False, "frida 官方没有 ABI=%s 的 Android 包（支持 arm64/arm/x86/x86_64）" % ab

    out_dir = _roots()[0] / BIN_DIR
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return False, "创建目录失败：%s" % e

    name = "frida-server-%s-android-%s" % (ver, ab)
    dest = out_dir / name
    if dest.exists() and dest.stat().st_size > 1024 * 1024:
        return True, str(dest)

    url = ("https://github.com/frida/frida/releases/download/%s/%s.xz" % (ver, name))
    _log("[*] 本机缺少可用的 frida-server，尝试从官方 release 下载：%s" % url)
    tmp_xz = out_dir / (name + ".xz.part")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "piiscan/1.0"})
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp_xz, "wb") as f:
            shutil.copyfileobj(resp, f, length=1024 * 256)
        if time.time() - t0 > timeout:
            raise TimeoutError("下载超时")
    except Exception as e:
        try:
            tmp_xz.unlink()
        except Exception:
            pass
        return False, ("连不上 GitHub release（%s: %s）。内网部署可手工下载 %s 放到 %s/ 下"
                       % (type(e).__name__, str(e)[:120], name, BIN_DIR))

    try:
        with lzma.open(str(tmp_xz), "rb") as src, open(dest, "wb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 256)
        tmp_xz.unlink()
    except Exception as e:
        for p in (tmp_xz, dest):
            try:
                p.unlink()
            except Exception:
                pass
        return False, "解压 .xz 失败（%s）。可手工下载后直接放到 %s/" % (e, BIN_DIR)

    size = dest.stat().st_size
    if size < 1024 * 1024:
        # frida-server 静态链接，正常都是十几 MB。小于 1 MB 基本是错误页/空文件。
        try:
            dest.unlink()
        except Exception:
            pass
        return False, "下载到的文件只有 %d 字节，不像是二进制（可能是代理返回的错误页）" % size
    ver2, ab2 = parse_name(dest.name)
    if ver2 != ver or ab2 != ab:
        return False, "下载结果校验不通过（%s → 版本 %s / ABI %s）" % (dest.name, ver2, ab2)
    _log("[+] 已下载 frida-server：%s（%.1f MB）" % (name, size / 1048576.0))
    return True, str(dest)


def local_version() -> str:
    """本机 frida Python 库版本（空串=没装）。"""
    try:
        import frida
        return str(getattr(frida, "__version__", "") or "")
    except Exception:
        return ""
