"""APK 获取层：支持本地上传文件与远程下载链接。

设计要点：
- 远程下载走标准库 urllib，不引入 requests；支持重定向、自定义 UA、超时与体积上限。
- 无论来源，最终都落成本地文件并计算 MD5/SHA256，作为后续所有环节的唯一定位键。
- 下载失败不抛异常，返回带 error 字段的结果，便于平台把失败原因写进任务记录。
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

MAX_BYTES = 600 * 1024 * 1024  # 单文件上限 600MB


@dataclass
class FetchResult:
    ok: bool
    path: str = ""
    source: str = ""          # upload | url | store
    url: str = ""
    size: int = 0
    md5: str = ""
    sha256: str = ""
    filename: str = ""
    original_name: str = ""   # 用户上传时的原始名（含中文），仅供展示
    elapsed: float = 0.0
    error: str = ""
    log: list = field(default_factory=list)
    # 应用商店解析出来的元信息（只有 source="store" 时才有）。
    # 用途：静态分析取不到显示名（没有 aapt）时兜底，以及报告开头写清"从哪个市场取的"。
    market: str = ""
    package: str = ""
    version: str = ""
    app_name: str = ""


def hash_file(path: str | os.PathLike, log: Optional[Callable[[str], None]] = None) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha.update(chunk)
    if log:
        log("[*] 文件哈希计算完成")
    return {"md5": md5.hexdigest(), "sha256": sha.hexdigest()}


def is_apk(path: str | os.PathLike) -> bool:
    """粗校验：ZIP 魔数 + 内含 AndroidManifest.xml。"""
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"PK":
                return False
        import zipfile
        with zipfile.ZipFile(path) as z:
            return "AndroidManifest.xml" in z.namelist()
    except Exception:
        return False


def safe_filename(name: str, fallback: str = "target.apk") -> str:
    name = os.path.basename(urllib.parse.unquote(name or "")).strip()
    name = re.sub(r"[\\/:*?\"<>|\r\n\t]", "_", name)
    if not name:
        name = fallback
    if not name.lower().endswith(".apk"):
        name += ".apk"
    return name[:120]


def safe_ascii_filename(name: str, fallback: str = "target.apk") -> str:
    """生成纯 ASCII 的归档名，规避 adb/命令行编码问题。"""
    stem, ext = os.path.splitext(os.path.basename(name or ""))
    if ext.lower() not in (".apk", ".apks", ".xapk", ".zip"):
        ext = ".apk"
    ascii_stem = re.sub(r"[^A-Za-z0-9._-]", "_", stem).strip("._-")
    ascii_stem = re.sub(r"_{2,}", "_", ascii_stem)[:80]
    if not ascii_stem:
        ascii_stem = os.path.splitext(fallback)[0] or "target"
    return ascii_stem + ext


def fetch_url(url: str, dest_dir: str | os.PathLike, timeout: int = 60,
              log: Optional[Callable[[str], None]] = None,
              max_bytes: int = MAX_BYTES,
              extra_headers: Optional[Dict[str, str]] = None) -> FetchResult:
    """下载 APK 链接到 dest_dir。"""
    log = log or (lambda *_: None)
    t0 = time.time()
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    url = (url or "").strip()
    if not url:
        return FetchResult(ok=False, error="下载链接为空")
    if not re.match(r"^https?://", url, re.I):
        return FetchResult(ok=False, error="仅支持 http/https 链接：%s" % url)

    fname = safe_filename(urllib.parse.urlparse(url).path)
    dest = dest_dir / fname

    headers = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)

    log("[*] 下载：%s" % url)
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final_url = resp.geturl()
            ctype = resp.headers.get("Content-Type", "")
            clen = resp.headers.get("Content-Length")
            if clen and clen.isdigit():
                log("[*] 远端大小：%.1f MB" % (int(clen) / 1048576.0))
            # 若服务端给了文件名，优先用它
            cd = resp.headers.get("Content-Disposition", "")
            m = re.search(r"filename\*?=(?:UTF-8''|\")?([^\";]+)", cd or "", re.I)
            if m:
                dest = dest_dir / safe_filename(m.group(1))

            total = 0
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(256 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError("文件超过上限 %.0f MB" % (max_bytes / 1048576.0))
                    f.write(chunk)
    except urllib.error.HTTPError as e:
        return FetchResult(ok=False, error="HTTP %s %s" % (e.code, e.reason), url=url)
    except Exception as e:
        return FetchResult(ok=False, error="%s: %s" % (type(e).__name__, e), url=url)

    if not is_apk(dest):
        # 保留文件便于排查，但标记失败
        try:
            head = dest.read_bytes()[:512]
        except Exception:
            head = b""
        hint = "（看起来不是有效的 APK）"
        if b"<!DOCTYPE" in head or b"<html" in head.lower():
            hint = "（下载到的内容是一个网页，链接可能不是直链，需要先取得真实下载地址）"
        elif ctype and "text/" in ctype:
            hint += "（Content-Type: %s）" % ctype
        return FetchResult(ok=False, path=str(dest), url=url,
                           size=dest.stat().st_size, filename=dest.name,
                           error="文件内容校验失败 %s" % hint)

    h = hash_file(dest, log)
    log("[*] 已保存：%s（%.1f MB）" % (dest.name, dest.stat().st_size / 1048576.0))
    return FetchResult(ok=True, path=str(dest), source="url", url=url,
                       size=dest.stat().st_size, filename=dest.name,
                       elapsed=time.time() - t0, md5=h["md5"], sha256=h["sha256"])


def fetch_upload(src_path: str | os.PathLike, dest_dir: str | os.PathLike,
                 original_name: str = "",
                 log: Optional[Callable[[str], None]] = None) -> FetchResult:
    """把用户上传的 APK 归档到 dest_dir（复制而非移动，保留原文件）。

    归档名强制 ASCII：中文/空格文件名经命令行传给 `adb install` 时会被编码破坏，
    表现为「安装失败但 stderr 为空」。原始名保留在 FetchResult.original_name 里供界面展示。
    """
    log = log or (lambda *_: None)
    t0 = time.time()
    src = Path(src_path)
    if not src.exists():
        return FetchResult(ok=False, error="上传文件不存在：%s" % src)

    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    shown = os.path.basename(original_name or src.name) or "target.apk"
    name = safe_ascii_filename(shown)
    dest = dest_dir / name
    # 同名归档（如多次上传 gjb.apk）加序号，避免互相覆盖
    if dest.exists() and src.resolve() != dest.resolve():
        stem, ext = os.path.splitext(name)
        for i in range(2, 100):
            cand = dest_dir / ("%s_%d%s" % (stem, i, ext))
            if not cand.exists():
                dest = cand
                break

    try:
        if src.resolve() != dest.resolve():
            shutil.copy2(src, dest)
    except Exception as e:
        return FetchResult(ok=False, error="归档上传文件失败：%s" % e)

    if not is_apk(dest):
        return FetchResult(ok=False, path=str(dest), filename=dest.name,
                           original_name=shown,
                           size=dest.stat().st_size, error="上传的文件不是有效的 APK")

    h = hash_file(dest, log)
    log("[*] 已接收上传：%s（%.1f MB）" % (shown, dest.stat().st_size / 1048576.0))
    return FetchResult(ok=True, path=str(dest), source="upload", size=dest.stat().st_size,
                       filename=dest.name, original_name=shown,
                       elapsed=time.time() - t0,
                       md5=h["md5"], sha256=h["sha256"])
