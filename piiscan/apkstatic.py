"""APK 静态分析：不依赖设备即可产出的全部线索。

产出：
  · 基础信息    包名 / 应用名 / 版本 / minSdk / targetSdk
  · 权限清单    含中文标签与保护级别
  · 组件清单    导出的 Activity / Service / Receiver / Provider（隐私风险面）
  · 签名信息    证书主体、颁发者、有效期、指纹
  · SDK 清单    基于内置包名前缀库（reference/sdk_package/sdk.json）识别第三方 SDK
  · 加固识别    基于内置加固特征表（reference/sdk_package/jiagu.txt）
  · 敏感 API    静态敏感 API 命中（预判动态 hook 重点）
  · 隐私政策    APK 内出现的政策相关 URL
  · 外发域名    APK 内的网络域名及归属公司

实现策略：优先调用 Android SDK 的 aapt / apksigner（结果最权威），
失败时回退到内置的纯 Python 解析器（axml.py），保证换环境也能跑。
"""
from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from . import resources
from .apkfetch import hash_file
from .axml import parse_manifest_bytes

# ---------------------------------------------------------------- 工具定位

_SDK_HINTS = [
    os.environ.get("ANDROID_HOME", ""),
    os.environ.get("ANDROID_SDK_ROOT", ""),
    str(Path.home() / "AppData/Local/Android/Sdk"),
    "/usr/lib/android-sdk",
    "/opt/android-sdk",
]


def find_tool(name: str) -> Optional[str]:
    """在 PATH 与 Android SDK 常见位置查找可执行文件。"""
    p = shutil.which(name)
    if p:
        return p
    exts = [".bat", ".exe", ""] if os.name == "nt" else [""]
    for hint in _SDK_HINTS:
        if not hint:
            continue
        bt = Path(hint) / "build-tools"
        if not bt.is_dir():
            continue
        for ver in sorted((d.name for d in bt.iterdir() if d.is_dir()), reverse=True):
            for ext in exts:
                cand = bt / ver / (name + ext)
                if cand.exists():
                    return str(cand)
    return None


def _run(cmd: List[str], timeout: int = 90) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        return proc.returncode, out, err
    except FileNotFoundError:
        return 127, "", "命令不存在：%s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "命令超时"
    except Exception as e:
        return 1, "", str(e)


@contextlib.contextmanager
def _tool_path(apk: str) -> Iterator[str]:
    """给外部工具（aapt / apksigner）准备一个可用路径。

    Windows 上的 aapt 无法处理含非 ASCII 字符的路径（会报 Illegal byte
    sequence），而用户的 APK 文件名/目录很容易带中文，因此这里检测到非
    ASCII 路径就复制一份到临时目录再交给工具。
    """
    try:
        apk.encode("ascii")
        yield apk
        return
    except (UnicodeEncodeError, AttributeError):
        pass
    tmp_dir = Path(tempfile.mkdtemp(prefix="piiscan_tool_"))
    tmp_apk = tmp_dir / "target.apk"
    try:
        shutil.copy2(apk, tmp_apk)
        yield str(tmp_apk)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------- 结果模型

@dataclass
class StaticResult:
    apk_path: str = ""
    filename: str = ""
    size: int = 0
    md5: str = ""
    sha256: str = ""

    package: str = ""
    app_label: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""

    permissions: List[str] = field(default_factory=list)
    permission_details: List[Dict[str, str]] = field(default_factory=list)
    components: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    exported: List[str] = field(default_factory=list)

    signature: Dict[str, str] = field(default_factory=dict)
    sdks: List[Dict[str, str]] = field(default_factory=list)
    jiagu: List[Dict[str, str]] = field(default_factory=list)
    # 仅 dex 字符串命中的加固库名（弱线索）。多家同时命中时几乎可以肯定是
    # 某 SDK 内嵌的「加固检测清单」，不能当作本应用使用了加固。
    jiagu_hints: List[Dict[str, str]] = field(default_factory=list)

    cleartext: str = ""
    debuggable: str = ""
    allow_backup: str = ""

    dex_count: int = 0
    native_libs: List[str] = field(default_factory=list)
    sensitive_hits: List[Dict[str, Any]] = field(default_factory=list)
    policy_urls: List[str] = field(default_factory=list)
    policy_assets: List[Dict[str, Any]] = field(default_factory=list)
    domains: List[Dict[str, str]] = field(default_factory=list)

    manifest_source: str = ""
    errors: List[str] = field(default_factory=list)

    @property
    def sdk_names(self) -> List[str]:
        return [s["name"] for s in self.sdks]

    @property
    def dangerous_permissions(self) -> List[str]:
        return [p["name"] for p in self.permission_details if p.get("dangerous") == "是"]


# ---------------------------------------------------------------- 危险权限判定
_DANGEROUS_GROUPS = {
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO", "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS", "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL", "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS", "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
}

# 与个人信息收集强相关的权限（用于「必要范围」类判定）
PII_PERMISSIONS = {
    "android.permission.READ_PHONE_STATE", "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO", "android.permission.READ_SMS",
    "android.permission.READ_CALL_LOG", "android.permission.READ_CALENDAR",
    "android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.GET_ACCOUNTS", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.ACCESS_WIFI_STATE", "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.BLUETOOTH_SCAN", "android.permission.REQUEST_INSTALL_PACKAGES",
}


# ---------------------------------------------------------------- 主流程

def analyze(apk_path: str | os.PathLike,
            log: Optional[Callable[[str], None]] = None,
            deep: bool = True) -> StaticResult:
    log = log or (lambda *_: None)
    apk_path = str(apk_path)
    res = StaticResult(apk_path=apk_path, filename=Path(apk_path).name)
    res.size = os.path.getsize(apk_path)
    h = hash_file(apk_path)
    res.md5, res.sha256 = h["md5"], h["sha256"]
    log("[*] 静态分析开始：%s（%.1f MB）" % (res.filename, res.size / 1048576.0))

    # --- 1. 打开 ZIP 读 manifest / 目录结构 ---
    manifest = {}
    try:
        with zipfile.ZipFile(apk_path) as z:
            names = z.namelist()
            res.dex_count = sum(1 for n in names if n.endswith(".dex"))
            res.native_libs = sorted({Path(n).name for n in names
                                      if n.startswith("lib/") and n.endswith(".so")})[:120]
            if "AndroidManifest.xml" in names:
                raw = z.read("AndroidManifest.xml")
                manifest = parse_manifest_bytes(raw)
                res.manifest_source = "axml"
    except Exception as e:
        res.errors.append("读取 APK 结构失败：%s" % e)
        log("[!] 读取 APK 结构失败：%s" % e)
        return res

    # --- 2. aapt 优先补齐/覆盖 ---
    aapt = find_tool("aapt")
    if aapt:
        try:
            _apply_aapt(res, aapt, apk_path, log)
        except Exception as e:
            res.errors.append("aapt 解析失败（已回退内置解析器）：%s" % e)

    # 用 axml 结果兜底空缺字段
    _fill_from_manifest(res, manifest)
    _normalize_label(res, log)

    if not res.package:
        res.errors.append("未能解析出包名，静态信息可能不完整")
        log("[!] 未能解析出包名")

    # --- 3. 权限详情 ---
    ptable = resources.permission_table()
    for p in res.permissions:
        rec = ptable.get(p, {})
        level = rec.get("level", "") or ("dangerous" if p in _DANGEROUS_GROUPS else "")
        res.permission_details.append({
            "name": p,
            "label": rec.get("name", ""),
            "level": level or "normal",
            "dangerous": "是" if (level == "dangerous" or p in _DANGEROUS_GROUPS) else "否",
            "pii": "是" if p in PII_PERMISSIONS else "否",
        })

    # --- 4. 签名 ---
    try:
        _read_signature(res, apk_path, log)
    except Exception as e:
        res.errors.append("签名解析失败：%s" % e)

    # --- 5. 内置隐私政策文档（便宜，且与深度扫描无关，必须始终执行） ---
    try:
        res.policy_assets = _extract_policy_assets(apk_path, log)
    except Exception as e:
        res.errors.append("内置政策提取失败：%s" % e)

    # --- 6. 深度扫描 DEX 字符串 ---
    if deep:
        try:
            _deep_scan(res, apk_path, log)
        except Exception as e:
            res.errors.append("DEX 深度扫描失败：%s" % e)
            log("[!] DEX 深度扫描失败：%s" % e)

    log("[*] 静态分析完成：包名 %s｜权限 %d 项｜SDK %d 个｜加固 %s"
        % (res.package or "?", len(res.permissions), len(res.sdks),
           res.jiagu[0]["name"] if res.jiagu else "未识别"))
    return res


# ---------------------------------------------------------------- aapt

def _apply_aapt(res: StaticResult, aapt: str, apk: str,
                log: Callable[[str], None]) -> None:
    with _tool_path(apk) as tool_apk:
        code, out, err = _run([aapt, "dump", "badging", tool_apk], timeout=180)
    if code != 0:
        raise RuntimeError((err or out or "").strip()[:200])
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            m = re.search(r"name='([^']*)'", line)
            if m:
                res.package = m.group(1)
            m = re.search(r"versionCode='([^']*)'", line)
            if m:
                res.version_code = m.group(1)
            m = re.search(r"versionName='([^']*)'", line)
            if m:
                res.version_name = m.group(1)
        elif line.startswith("sdkVersion:"):
            res.min_sdk = line.split(":", 1)[1].strip().strip("'")
        elif line.startswith("targetSdkVersion:"):
            res.target_sdk = line.split(":", 1)[1].strip().strip("'")
        elif line.startswith("application-label:") or line.startswith("application-label-"):
            if not res.app_label and ":" in line:
                res.app_label = line.split(":", 1)[1].strip().strip("'")
        elif line.startswith("uses-permission:") or line.startswith("uses-permission-sdk-23:"):
            m = re.search(r"name='([^']*)'", line)
            if m and m.group(1) not in res.permissions:
                res.permissions.append(m.group(1))
        elif line.startswith("uses-feature:"):
            pass
    res.manifest_source = "aapt"
    log("[*] aapt 解析成功：%s v%s" % (res.package, res.version_name))


# ---------------------------------------------------------------- axml 兜底

# 资源引用：@0x7f13003f（已编译）/ @string/app_name（未解析）/ ?attr/x
_RES_REF = re.compile(r"^@(0x[0-9a-fA-F]+|[A-Za-z0-9_.]+/)|^\?[A-Za-z0-9_.]+/")


def _normalize_label(res: "StaticResult", log: Callable[[str], None]) -> None:
    """应用显示名只拿到资源引用时，退用包名。

    为什么在意这件事：报告标题是「<应用名> App 个人信息保护合规检测报告」。
    没有 build-tools 的机器（服务器部署）走不了 aapt，AXML 里的 label 只是
    resources.arsc 的索引，原样印出来就成了
    「＠0x7f13003f App 个人信息保护合规检测报告」——复核员看不出这是哪个 App，
    也没法在应用市场里核。包名是确定的，比一个资源 id 有用得多。

    解析失败这件事要进 errors 而不是悄悄换掉：显示名是"没拿到"，不是"叫这个"。
    """
    lab = (res.app_label or "").strip()
    if not lab or not _RES_REF.match(lab):
        return
    if not res.package:
        return
    log("[*] 应用名未能解析（%s 是资源引用，需 aapt 或 resources.arsc），改用包名"
        % lab)
    res.errors.append("应用显示名未解析（label=%s，本机无 aapt 且未解析 "
                      "resources.arsc）；报告标题改用包名" % lab)
    res.app_label = res.package


def _fill_from_manifest(res: StaticResult, m: Dict[str, Any]) -> None:
    if not m:
        return
    res.package = res.package or m.get("package", "")
    res.version_name = res.version_name or str(m.get("versionName", "") or "")
    res.version_code = res.version_code or str(m.get("versionCode", "") or "")
    res.min_sdk = res.min_sdk or str(m.get("minSdkVersion", "") or "")
    res.target_sdk = res.target_sdk or str(m.get("targetSdkVersion", "") or "")
    if not res.app_label:
        res.app_label = str(m.get("label", "") or "")
    if not res.permissions:
        res.permissions = list(m.get("permissions") or [])
    res.cleartext = res.cleartext or str(m.get("usesCleartextTraffic", "") or "")
    res.debuggable = res.debuggable or str(m.get("debuggable", "") or "")
    res.allow_backup = res.allow_backup or str(m.get("allowBackup", "") or "")

    if not res.components:
        res.components = {
            "activity": m.get("activities") or [],
            "service": m.get("services") or [],
            "receiver": m.get("receivers") or [],
            "provider": m.get("providers") or [],
        }
        exported = []
        for kind, items in res.components.items():
            for it in items:
                if str(it.get("exported", "")).lower() == "true":
                    exported.append("%s: %s" % (kind, it.get("name", "")))
        res.exported = exported


# ---------------------------------------------------------------- 签名

def _read_signature(res: StaticResult, apk: str, log: Callable[[str], None]) -> None:
    signer = find_tool("apksigner")
    if signer:
        with _tool_path(apk) as tool_apk:
            code, out, err = _run([signer, "verify", "--print-certs", "-v", tool_apk],
                                  timeout=240)
        text = out + "\n" + err
        schemes: List[str] = []
        for line in text.splitlines():
            line = line.strip()
            for key, k2 in (("Signer #1 certificate DN:", "subject"),
                            ("Signer #1 certificate SHA-256 digest:", "sha256"),
                            ("Signer #1 certificate SHA-1 digest:", "sha1"),
                            ("Signer #1 certificate MD5 digest:", "md5"),
                            ("Signer #1 certificate validity:", "validity")):
                if line.startswith(key):
                    res.signature[k2] = line.split(":", 1)[1].strip()
            if line.startswith("Verified using") and line.rstrip().lower().endswith("true"):
                schemes.append(line.split(":", 1)[0].replace("Verified using", "").strip())
        if schemes:
            res.signature["schemes"] = "、".join(schemes)
        if "DOES NOT VERIFY" in text.upper():
            res.signature["verified"] = "否"
        elif res.signature:
            res.signature["verified"] = "是"
    if not res.signature.get("sha256"):
        # 回退：至少列出签名文件并给出指纹
        try:
            import hashlib
            with zipfile.ZipFile(apk) as z:
                sf = [n for n in z.namelist()
                      if n.upper().startswith("META-INF/")
                      and n.upper().endswith((".RSA", ".DSA", ".EC"))
                      and not n.upper().endswith((".SF", ".MF"))]
                blob = z.read(sf[0]) if sf else b""
            if sf:
                res.signature.update({
                    "schemes": "、".join(sorted({Path(x).suffix[1:].upper() for x in sf})),
                    "sha256": hashlib.sha256(blob).hexdigest(),
                    "note": "由签名块直接计算，未做证书链解析（本机未找到 apksigner）",
                })
        except Exception:
            pass
    if res.signature.get("subject"):
        log("[*] 签名主体：%s" % res.signature["subject"][:90])


# ---------------------------------------------------------------- DEX 深度扫描

_ASCII_RE = re.compile(rb"[ -~]{4,}")


def _deep_scan(res: StaticResult, apk: str, log: Callable[[str], None]) -> None:
    with zipfile.ZipFile(apk) as z:
        names = [n for n in z.namelist() if n.endswith(".dex")]
        blob = b""
        for n in names:
            blob += z.read(n)
    log("[*] 已加载 DEX：%d 个 / %.1f MB，开始扫描" % (len(names), len(blob) / 1048576.0))

    if not blob:
        return

    strings = {s.decode("ascii", errors="ignore") for s in _ASCII_RE.findall(blob)}
    joined = "\n".join(strings)

    # --- SDK 识别 ---
    res.sdks = _match_sdks(joined)

    # --- 加固识别 ---
    res.jiagu = _match_jiagu(res, apk, joined)

    # --- 敏感 API 静态命中 ---
    res.sensitive_hits = _match_sensitive_api(strings)

    # --- 隐私政策 URL ---
    res.policy_urls = _extract_policy_urls(joined)

    # --- 域名与归属 ---
    res.domains = _extract_domains(joined)
    log("[*] 扫描完成：SDK %d / 敏感API命中 %d / 政策链接 %d / 内置政策 %d / 域名 %d"
        % (len(res.sdks), len(res.sensitive_hits), len(res.policy_urls),
           len(res.policy_assets), len(res.domains)))


# ---------------------------------------------------------------- 内置政策全文

_POLICY_ASSET_HINT = re.compile(
    r"(privacy|policy|agreement|protocol|statement|terms|licen[cs]e|private|service|"
    r"隐私|协议|政策|条款|声明|规则)", re.I)

# ★ 光看文件名会漏掉正文。「自设捏脸」（uni-app）的政策全文放在
#   assets/apps/__UNI__CA2D8BF/www/hybrid/html/private.html —— 23064 字，
#   但文件名 `private.html` 不含 privacy/policy/隐私 任何关键词，
#   于是只捞到了弹窗用的 androidPrivacy.json（1011 字），
#   报告里政策类检测项全部"跳过未测"。故增加**内容级**判定：
#   凡是 assets / res/raw 下的文本文件，正文里出现多个隐私政策特征词的，
#   一律视为候选政策文档。
_ASSET_CONTENT_HINT = re.compile(r"隐私|个人信息|收集.{0,8}使用|用户信息|个人敏感信息")

_ASSET_TEXT_EXT = (".html", ".htm", ".txt", ".md", ".json", ".xml")


def _extract_policy_assets(apk: str, log: Callable[[str], None]) -> List[Dict[str, Any]]:
    """从 APK 的 assets / res/raw 里提取内置的隐私政策全文。

    为什么需要这一步：很多 App（尤其政务、金融、银行类）**不把隐私政策放在网上**，
    而是随包内置一份 HTML/TXT，首启弹窗和「关于」页直接读它。这种情况下抓链接
    永远拿不到正文，但正文其实就在包里 —— 而且这正是 App 实际展示给用户的那一份，
    证据效力比任何在线抓取都强。

    返回 [{path, name, size, text_len, text}]，按与「隐私政策」的相关度排序。
    """
    out: List[Dict[str, Any]] = []
    try:
        with zipfile.ZipFile(apk) as z:
            for n in z.namelist():
                low = n.lower()
                if not low.startswith(("assets/", "res/raw/")):
                    continue
                if not low.endswith(_ASSET_TEXT_EXT):
                    continue
                by_name = bool(_POLICY_ASSET_HINT.search(n))
                try:
                    info = z.getinfo(n)
                    if info.file_size > 3 * 1024 * 1024:
                        continue
                    raw = z.read(n)
                except Exception:
                    continue
                text, _title = _asset_to_text(raw, low)
                if len(text) < 300:
                    continue
                # 文件名像政策 → 收；否则看正文：特征词命中 ≥2 类且正文够长才收
                by_text = (len(text) >= 800
                           and len(set(_ASSET_CONTENT_HINT.findall(text))) >= 2)
                if not (by_name or by_text):
                    continue
                out.append({
                    "path": n,
                    "name": n.split("/")[-1],
                    "size": len(raw),
                    "text_len": len(text),
                    "text": text,
                    "matched_by": "name" if by_name else "content",
                    # 弹窗配置 ≠ 政策正文。uni-app 的 androidPrivacy.json 只有
                    # 一句告知语和两个按钮文案，长度很短、字段固定，单独标记出来，
                    # 免得它凭名字里的 "Privacy" 排在 23000 字的政策正文前面 ——
                    # 报告里一旦把弹窗摘要当政策正文，后面所有政策类结论都会失真。
                    "role": ("prompt_config"
                             if (low.endswith(".json") and len(text) < 3000
                                 and ('"prompt"' in text or '"buttonAccept"' in text))
                             else "policy_text"),
                })
    except Exception as e:
        log("[!] 读取内置政策资产失败：%s" % e)
    # 政策正文优先（弹窗配置排最后）；同为主政策时，名字像隐私政策的靠前、
    # 正文长的靠前。
    def rank(d: Dict[str, Any]) -> tuple:
        nm = d["name"].lower()
        look_main = 0 if ("privacy" in nm or "private" in nm or "隐私" in nm) else 1
        return (0 if d.get("role") == "policy_text" else 1, look_main, -d["text_len"])
    out.sort(key=rank)
    if out:
        longest = max(out, key=lambda d: d["text_len"])
        log("[*] APK 内置政策文档 %d 份，最长 %d 字（%s）"
            % (len(out), longest["text_len"], longest["name"]))
    return out[:8]


def _asset_to_text(raw: bytes, name: str) -> tuple:
    """资产文件转纯文本：HTML 去标签，其它按多编码兜底解码。"""
    if name.endswith((".html", ".htm")):
        try:
            from .policy import html_to_text, _decode
            body = _decode(raw)
            text, title = html_to_text(body)
            return text, title
        except Exception:
            pass
    for enc in ("utf-8", "gb18030", "gbk", "utf-16"):
        try:
            return raw.decode(enc).strip(), ""
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace").strip(), ""


def _match_sdks(joined: str) -> List[Dict[str, str]]:
    """用包名前缀库匹配。DEX 中类名为 Lcom/umeng/a; 形式，需把点号换成斜杠。"""
    found: Dict[str, Dict[str, str]] = {}
    for prefix, name, typ, author in resources.sdk_library():
        if len(prefix) < 4:
            continue
        slash = prefix.replace(".", "/")
        if slash in joined or prefix in joined:
            key = name or prefix
            if key not in found:
                found[key] = {
                    "name": name or prefix, "type": typ or "未知",
                    "author": author or "未知", "package": prefix,
                }
    return sorted(found.values(), key=lambda d: d["name"])


def _match_jiagu(res: StaticResult, apk: str, joined: str) -> List[Dict[str, str]]:
    """识别加固壳。

    ★ 这里踩过一个很隐蔽的坑：早先只要 dex 字符串里出现加固库名就认定加固，
      结果给「子慎爱恋」（uni-app）一次判出 **26 家**加固厂商 ——
      娜迦、爱加密、梆梆、360、腾讯、阿里…… 全中。
      查下来：dex 里每个库名恰好只有一条、就是名字本身，
      这是**某个 SDK 内嵌的「加固检测清单」**（用于运行时判断环境），
      不是本应用真的用了加固。按字符串判定会把这类 App 全部误判成"多重加固"。

    加固壳必然以**文件**形式躺在 APK 里（lib/*.so，或 assets 下的特征文件）。
    所以判定只认文件；dex 字符串降级为弱线索（jiagu_hints），
    且当字符串级命中多家厂商时明确标注为"清单类字符串，不作为认定依据"。
    """
    out: List[Dict[str, str]] = []
    hints: List[Dict[str, str]] = []
    try:
        with zipfile.ZipFile(apk) as z:
            names = [n.lower() for n in z.namelist()]
    except Exception:
        names = []
    base = {Path(n).name for n in names}          # 仅文件名（含原大小写）
    base_l = {b.lower() for b in base}
    low = joined.lower()

    for sig, name, vendor in resources.jiagu_signatures():
        s = sig.lower()
        # 文件级：压缩包内确实存在该特征文件
        in_file = s in base_l or any(s in n for n in names)
        in_str = len(s) >= 6 and s in low
        if in_file:
            if not any(x["name"] == name for x in out):
                out.append({"name": name, "vendor": vendor,
                            "signature": sig, "evidence": "file"})
        elif in_str:
            if not any(x["name"] == name for x in hints):
                hints.append({"name": name, "vendor": vendor,
                              "signature": sig, "evidence": "string"})

    res.jiagu_hints = hints
    return out


def _match_sensitive_api(strings) -> List[Dict[str, Any]]:
    """静态命中敏感 API：要求类名（完整/斜杠形式）出现，
    或者「类名末段 + 方法名」同时出现，避免只凭一个通用方法名误判。"""
    hits: List[Dict[str, Any]] = []
    for item in resources.sensitive_api_table():
        matched = []
        for ext in (item.get("signatures") or []):
            cls, _, meth = ext.partition("#")
            meth = meth.split("(")[0].strip()
            if not cls:
                continue
            cls_tail = cls.split(".")[-1]
            slash = cls.replace(".", "/")
            # 完整类名（点/斜杠/描述符三种写法）出现在字符串池即判定命中
            present = any(s == cls or s == slash or s == "L" + slash + ";" for s in strings)
            if not present:
                present = (cls_tail in strings) and (meth in strings)
            if present:
                matched.append(ext)
        if matched:
            hits.append({
                "category": item.get("category", ""),
                "label": item.get("label", ""),
                "behavior": item.get("behavior_code", ""),
                "permission": item.get("required_permissions", ""),
                "apis": matched,
            })
    return hits


_URL_RE = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{6,200}")
_POLICY_KEY = re.compile(
    r"privac|policy|agreement|protocol|statement|terms|yinsi|zhengce|隐私|协议|政策|声明", re.I)


def _extract_policy_urls(joined: str) -> List[str]:
    out: List[str] = []
    for u in _URL_RE.findall(joined):
        u = u.rstrip(".,;\"'\\")
        # ★ 命名空间 / 标准组织地址不算政策链接（2026-11-10 CNC宝典真机）：
        #   `http://purl.org/dc/terms/` 里的 "terms" 命中了下面的 `_POLICY_KEY`，
        #   于是它被当成"政策候选链接"排在第一位，采集端真的去抓了一次、
        #   白等到超时，日志还写着"静态分析给出 1 个政策候选链接"。
        #   `purl.org` / `w3.org` / `schemas.android.com` 这类是 XML 命名空间，
        #   永远不可能放隐私政策。直接排除，与 `_IGNORE_DOMAIN` 用同一份判断。
        _host = _HOST_IN_URL.search(u)
        if _host and _IGNORE_DOMAIN.match(_host.group(1).lower().strip(".")):
            continue
        if _POLICY_KEY.search(u):
            if u not in out:
                out.append(u)
    # 去掉明显是 SDK 内部的（如 hangzhou.aliyuncs.com/privacy）优先级更低，排在后面
    out.sort(key=lambda x: (0 if re.search(r"privacy|policy|隐私|协议", x, re.I) else 1, len(x)))
    return out[:40]


_HOST_IN_URL = re.compile(r"https?://([A-Za-z0-9\-._]+)")

# 常见框架 / 标准组织域名，不是业务外发地址，直接排除
_IGNORE_DOMAIN = re.compile(
    r"^(schemas\.android\.com|www\.w3\.org|w3\.org|example\.com|localhost|"
    r"apache\.org|json\.org|github\.com|google\.com|googleapis\.com|gstatic\.com|"
    r"android\.com|java\.com|oracle\.com|kotlinlang\.org|jetbrains\.com|"
    r"squareup\.com|okhttp3\.|bouncycastle\.org|slf4j\.org|springframework\.org|"
    r"microsoft\.com|adobe\.com|w3\.org|ietf\.org|unicode\.org|"
    # XML/语义网命名空间（2026-11-10 CNC宝典：`purl.org/dc/terms/` 被当成政策链接）
    r"purl\.org|xml\.org|oasis-open\.org|semver\.org|"
    r"0\.0\.0\.0|127\.0\.0\.1|10\.0\.2\.2|.*\.local)$", re.I)


def _extract_domains(joined: str) -> List[Dict[str, str]]:
    """只从 URL 中提取域名 —— 比从任意类名反推准确得多，
    可避免 android.app / window.top 之类的假域名。"""
    counter: Dict[str, int] = {}
    for host in _HOST_IN_URL.findall(joined):
        h = host.lower().strip(".")
        if not h or _IGNORE_DOMAIN.match(h):
            continue
        if re.fullmatch(r"[\d.]+", h):      # 纯 IP
            continue
        if "." not in h:
            continue
        counter[h] = counter.get(h, 0) + 1
    out = []
    for d, c in sorted(counter.items(), key=lambda kv: -kv[1])[:60]:
        out.append({"domain": d, "count": str(c), "owner": resources.host_owner(d) or ""})
    return out
