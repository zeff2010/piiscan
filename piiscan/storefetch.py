"""应用商店链接 → 真实 APK 文件。

从 `tools/apk_dl.py`（2026-10-14 的独立下载器）迁入，按平台的要求改造了三处：

1. **错误一律抛 `StoreError`**。原实现用 `SystemExit`：在独立脚本里没问题，
   但在平台的 worker 线程里，`SystemExit` 会顺着调用栈往外走，被
   `except Exception` 吃掉之后任务会以「没有 APK」继续往下跑，最后出一份
   22 项全「跳过未测」的报告 —— 看起来像"这个 App 很干净"，是最危险的假阴性。
2. **返回值统一成 `apkfetch.FetchResult`**，与上传 / 直链下载同构，
   上层不需要按来源写两套分支。
3. **输出目录由调用方给**（平台的任务目录），不再默认 `downloads/`；
   并支持 `should_stop` 回调，取消任务时不必等几百 MB 下完。

支持的七个市场（各自的防盗链差异都是实测结论，别随手改）：

    应用宝   https://sj.qq.com/appdetail/<包名>
    华为     https://appgallery.huawei.com/app/<C数字ID>
    vivo     https://h5.appstore.vivo.com.cn/#/details?app_id=<数字ID>
    小米     https://app.mi.com/details?id=<包名>
    百度     https://shouji.baidu.com/item?docid=<数字ID>
    豌豆荚   https://www.wandoujia.com/apps/<数字ID 或 包名>
    360      https://zhushou.360.cn/detail?id=<数字ID>

设计说明：
  * 应用宝：普通 GET 会陷入 302 无限循环 → 必须用 Range 分块请求。
    直链来自移动版 https://a.app.qq.com/o/simple.jsp?pkgname=<pkg> 内嵌 JSON。
  * 华为：https://appgallery.cloud.huawei.<TLD>/appdl/<CID> 302 到 CDN；
    .com 常跳回首页，需按 .com → .com.cn → .asia → .eu 回退。
  * vivo：POST https://h5-api.appstore.vivo.com.cn/detailInfo (appId=<id>) 拿
    download_url，再取 302 的 Location；CDN 对 curl 默认 UA 返回 403，
    且 cdn3 边缘节点无 DNS，需把 host 规范化为 apkverifycdn1-v6dl.vivo.com.cn。
  * 小米：详情页 allowDownload 元素里取 appId，再 /download/<appId> 取 302。
    部分应用被标记"维护中"，网页端无直链（服务端策略，无法绕过）。
  * 百度：详情页 window.__INITIAL_STATE__ 内嵌 JSON 含 downloadUrl；
    直链必须带 Referer: https://shouji.baidu.com/ 否则 404。
  * 豌豆荚：POST /wdjweb/api/getDownloadAppByAppId (appId=<数字>) 返回 downloadUrl。
  * 360：详情页 <script id="__NUXT_DATA__"> 是 devalue 序列化数组，
    字段名→下标映射中 down_url=10、pname=20 等，按映射取值。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .apkfetch import MAX_BYTES, FetchResult, safe_ascii_filename

UA_DESKTOP = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
UA_MOBILE = ("Mozilla/5.0 (Linux; Android 13; zh-cn) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")

# 单次提交的网址上限。不是性能限制，是防误操作：
# 一次糊几百行进去，队列会被占满几个小时，而人根本不知道自己在等什么。
MAX_BATCH_URLS = 50


class StoreError(Exception):
    """解析或下载失败。消息直接面向使用者，要写清"为什么下不到、能不能绕"。"""


class StoreCancelled(Exception):
    """调用方要求中止（任务被暂停/停止）。"""


def _noop(_msg: str) -> None:
    pass


# --------------------------------------------------------------------------
# HTTP 基础
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER_FOLLOW = urllib.request.build_opener()
_OPENER_NOFOL = urllib.request.build_opener(_NoRedirect)


def http(url: str, headers: Optional[Dict[str, str]] = None, data: Any = None,
         timeout: int = 60, follow: bool = True, method: Optional[str] = None):
    """返回 (status, headers_obj, body_bytes)。不跟随重定向时返回 3xx 的 Location。"""
    h = dict(headers or {})
    if data is not None and not isinstance(data, (bytes, bytearray)):
        data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    opener = _OPENER_FOLLOW if follow else _OPENER_NOFOL
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            pass
        return e.code, e.headers, body


def http_text(url: str, headers: Optional[Dict[str, str]] = None, data: Any = None,
              timeout: int = 60, follow: bool = True) -> Tuple[int, Any, str]:
    st, hd, body = http(url, headers, data, timeout, follow)
    return st, hd, body.decode("utf-8", errors="ignore")


def location_of(url: str, headers: Optional[Dict[str, str]] = None,
                timeout: int = 60) -> Tuple[int, Optional[str]]:
    """发一个不跟随重定向的请求，取 Location。"""
    st, hd, _ = http(url, headers, timeout=timeout, follow=False)
    return st, (hd.get("Location") if hd else None)


def extract_json_object(text: str, marker: str) -> Optional[str]:
    """从 marker 之后提取一个配平的大括号 JSON 对象。"""
    i = text.find(marker)
    if i < 0:
        return None
    j = i + len(marker)
    while j < len(text) and text[j] not in "{[":
        j += 1
    if j >= len(text):
        return None
    depth = 0
    instr = False
    esc = False
    start = j
    while j < len(text):
        c = text[j]
        if esc:
            esc = False
        elif c == "\\":
            esc = True
        elif c == '"':
            instr = not instr
        elif not instr:
            if c in "{[":
                depth += 1
            elif c in "}]":
                depth -= 1
                if depth == 0:
                    return text[start:j + 1]
        j += 1
    return None


def probe_size_and_headers(url: str, headers: Optional[Dict[str, str]] = None):
    """用 Range 0-0 探测总大小与可下载性，返回 (total, content_type, err)。"""
    h = {"Range": "bytes=0-0", "User-Agent": UA_MOBILE}
    h.update(headers or {})
    try:
        st, hd, _ = http(url, h, timeout=60, follow=True)
    except Exception as e:  # noqa: BLE001
        return None, None, str(e)
    if st not in (200, 206):
        return None, None, "HTTP %s" % st
    cr = hd.get("Content-Range")
    if cr and "/" in cr:
        try:
            return int(cr.rsplit("/", 1)[1]), hd.get("Content-Type"), None
        except ValueError:
            pass
    cl = hd.get("Content-Length")
    if cl and st == 200:
        return int(cl), hd.get("Content-Type"), None
    return None, hd.get("Content-Type"), "无法确定文件大小"


def fetch_range(url: str, start: int, end: int,
                headers: Optional[Dict[str, str]] = None, retries: int = 8) -> bytes:
    expect = end - start + 1
    last = None
    for attempt in range(1, retries + 1):
        h = {"Range": "bytes=%d-%d" % (start, end), "User-Agent": UA_MOBILE}
        h.update(headers or {})
        try:
            st, _hd, body = http(url, h, timeout=300, follow=True)
            if st in (200, 206) and len(body) == expect:
                return body
            last = "HTTP %s, 返回 %d 字节, 期望 %d" % (st, len(body), expect)
        except Exception as e:  # noqa: BLE001
            last = str(e)
        if attempt < retries:
            time.sleep(min(2 * attempt, 8))
    raise StoreError("偏移 %d 下载失败（重试 %d 次）：%s" % (start, retries, last))


def download(url: str, out_path: str, total: int,
             headers: Optional[Dict[str, str]] = None, chunk_mb: int = 8,
             retries: int = 8, logfn: Callable[[str], None] = _noop,
             progress: Optional[Callable[[int, int], None]] = None,
             should_stop: Optional[Callable[[], bool]] = None) -> int:
    """分块下载，支持断点续传（同一个 out_path 重跑会接着下）。"""
    resume = 0
    if os.path.exists(out_path):
        resume = os.path.getsize(out_path)
        if resume >= total:
            os.remove(out_path)
            resume = 0
        else:
            logfn("    检测到未完成文件，从 {:,} 字节续传".format(resume))
    chunk = chunk_mb * 1024 * 1024
    off = resume
    if progress:
        progress(off, total)
    with open(out_path, "ab" if resume else "wb") as f:
        while off < total:
            if should_stop is not None and should_stop():
                raise StoreCancelled("下载过程中被要求停止")
            end = min(off + chunk, total) - 1
            f.write(fetch_range(url, off, end, headers, retries))
            off = end + 1
            logfn("    {:,} / {:,} bytes  ({:5.1f}%)".format(off, total, off * 100.0 / total))
            if progress:
                progress(off, total)
    return os.path.getsize(out_path)


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def verify_apk(path: str, expect_pkg: Optional[str] = None) -> Dict[str, Any]:
    """结构校验：是不是有效 ZIP、有没有 native 库、包名对不对。

    ★ 为什么必须校验：实测 360 的某条跳转会把目标应用劫持成
      「360手机助手客户端安装包」。下下来一个 45MB 的错包，后续静态分析、
      动态采集全都"正常"跑完，报告测的是别的东西。
    """
    import zipfile

    res: Dict[str, Any] = {"zip_ok": False, "abi": [], "pkg_ok": None}
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:  # noqa: BLE001
        res["err"] = "不是有效的 ZIP/APK: %s" % e
        return res
    res["zip_ok"] = z.testzip() is None
    names = z.namelist()
    res["abi"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/")})
    if expect_pkg and "AndroidManifest.xml" in names:
        raw = z.read("AndroidManifest.xml")
        # AXML 的字符串池可能是 UTF-16 也可能是 UTF-8（aapt/aapt2 版本差异），
        # 两种编码都查一遍，否则会误报「包名不匹配」。
        res["pkg_ok"] = ((expect_pkg.encode("utf-16-le") in raw)
                         or (expect_pkg.encode("utf-8") in raw))
    res["ok"] = res["zip_ok"] and res["pkg_ok"] is not False
    return res


# --------------------------------------------------------------------------
# 各市场适配器：resolve(url) -> dict
#   candidates: [(abi 名, 直链, 额外请求头), ...]
# --------------------------------------------------------------------------

def resolve_yyb(url: str, abi: str = "arm64") -> Dict[str, Any]:
    m = (re.search(r"/appdetail/([A-Za-z0-9_.\-]+)", url)
         or re.search(r"[?&]pkgname=([A-Za-z0-9_.\-]+)", url))
    if not m:
        raise StoreError("无法从应用宝链接解析包名（应形如 …/appdetail/com.xxx.yyy）")
    pkg = m.group(1)
    st, _hd, html = http_text("https://a.app.qq.com/o/simple.jsp?pkgname=" + pkg,
                              {"User-Agent": UA_MOBILE})

    def g(k: str) -> Optional[str]:
        mm = re.search(r'"%s":"([^"]*)"' % k, html)
        return mm.group(1) if mm else None

    apk32, apk64 = g("apkUrl"), g("apkUrl64")
    if not (apk32 or apk64):
        raise StoreError("应用宝详情页未返回直链（应用可能未上线、已下架，或该包名不存在）")
    cands: List[Tuple[str, str, Optional[Dict[str, str]]]] = []
    if abi in ("arm64", "both") and apk64:
        cands.append(("arm64", apk64, None))
    if abi in ("arm32", "both") and apk32:
        cands.append(("arm32", apk32, None))
    if not cands:
        cands = [(("arm64" if apk64 else "arm32"), (apk64 or apk32), None)]
    return {"market": "应用宝", "app_id": pkg, "name": g("appName"),
            "package": g("packageName") or pkg, "version": g("versionName"),
            "candidates": cands}


def resolve_huawei(url: str) -> Dict[str, Any]:
    m = re.search(r"\b(C\d{5,})\b", url)
    if not m:
        raise StoreError("无法从华为链接解析应用 ID（形如 C100404489）")
    cid = m.group(1)
    last_err = None
    for tld in (".com", ".com.cn", ".asia", ".eu"):
        host = "appgallery.cloud.huawei" + tld
        try:
            _st, loc = location_of("https://%s/appdl/%s" % (host, cid),
                                   {"User-Agent": UA_DESKTOP})
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
            continue
        if loc and re.search(r"appdl.*/apk/|/dl/appdl/", loc):
            pkg = None
            mm = re.search(r"/([A-Za-z][A-Za-z0-9_.]*[0-9]{6,})\.apk", loc)
            if mm:
                pkg = re.sub(r"\.\d{6,}$", "", mm.group(1))
            return {"market": "华为应用市场", "app_id": cid, "name": None,
                    "package": pkg, "version": None,
                    "candidates": [("universal", loc, None)],
                    "note": "经 %s 解析（.com 常跳回首页，需回退 TLD）" % host}
        last_err = "%s 未返回 APK（302 -> %s）" % (host, loc)
    raise StoreError("华为该应用网页端不提供下载：%s。"
                     "appdl 仅对开放网页下载的应用生效，其余需 AppGallery 客户端"
                     % last_err)


def resolve_vivo(url: str) -> Dict[str, Any]:
    m = re.search(r"[?&#]app_?[Ii]d=(\d+)", url)
    if not m:
        raise StoreError("无法从 vivo 链接解析 app_id")
    aid = m.group(1)
    st, _hd, body = http("https://h5-api.appstore.vivo.com.cn/detailInfo",
                         {"User-Agent": UA_MOBILE,
                          "Content-Type": "application/x-www-form-urlencoded"},
                         data={"appId": aid})
    try:
        js = json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:  # noqa: BLE001
        raise StoreError("vivo 详情接口返回异常（HTTP %s）" % st)
    if js.get("filter") is True or not js.get("download_url"):
        raise StoreError("vivo 标记该应用当前不可下载（filter=true，无 download_url）")
    jump = js["download_url"]
    _st2, loc = location_of(jump, {"User-Agent": UA_MOBILE})
    if not loc:
        loc = jump
    # cdn3 边缘节点无 DNS，签名不绑定 host，统一规范化到 cdn1
    path = re.sub(r"^https?://[^/]+", "", loc)
    direct = "http://apkverifycdn1-v6dl.vivo.com.cn" + path
    size_kb = js.get("size")
    return {"market": "vivo 应用商店", "app_id": aid, "name": js.get("title_zh"),
            "package": js.get("package_name"), "version": js.get("version_name"),
            "candidates": [("universal", direct, None)],
            "size_hint": int(size_kb) * 1024 if size_kb else None,
            "note": "CDN 对 curl 默认 UA 返回 403；cdn 边缘节点已规范化为 cdn1"}


def resolve_mi(url: str) -> Dict[str, Any]:
    m = re.search(r"[?&]id=([A-Za-z0-9_.]+)", url)
    if not m:
        raise StoreError("无法从小米链接解析包名（应形如 …/details?id=com.xxx.yyy）")
    pkg = m.group(1)
    _st, _hd, html = http_text("https://app.mi.com/details?id=" + pkg,
                               {"User-Agent": UA_DESKTOP})
    anchor = re.search(r'<a[^>]*class="[^"]*allowDownload[^"]*"[^>]*>', html)
    if not anchor:
        if "maintenanceDownloadBtn" in html or "维护中" in html:
            raise StoreError("小米标记该应用「维护中」，网页端不提供直链（服务端策略，无法绕过）")
        raise StoreError("小米详情页未找到下载入口（应用可能已下架）")
    seg = anchor.group(0)
    aid_m = re.search(r"/download/(\d+)", seg)
    if not aid_m:
        raise StoreError("小米详情页下载元素格式异常，未能解析 appId")
    aid = aid_m.group(1)
    st2, loc = location_of("https://app.mi.com/download/%s?id=%s" % (aid, pkg),
                           {"User-Agent": UA_DESKTOP})
    if not loc or ("/download/" not in loc and "AppStore" not in loc):
        raise StoreError("小米下载接口未跳转到 CDN（HTTP %s）" % st2)
    name = re.search(r'<meta name="description" content="([^"]*)"', html)
    ver = re.search(r"版本[：:]\s*</?[^>]*>?\s*([0-9][0-9A-Za-z._\-]{0,30})", html)
    return {"market": "小米应用商店", "app_id": aid,
            "name": name.group(1).strip() if name else None,
            "package": pkg, "version": ver.group(1) if ver else None,
            "candidates": [("universal", loc, None)],
            "note": "签名约 7 天有效，脚本每次实时取"}


def resolve_baidu(url: str) -> Dict[str, Any]:
    m = re.search(r"[?&]docid=(\d+)", url)
    if not m:
        raise StoreError("无法从百度链接解析 docid")
    docid = m.group(1)
    _st, _hd, html = http_text("https://shouji.baidu.com/item?docid=%s" % docid,
                               {"User-Agent": UA_DESKTOP})
    raw = extract_json_object(html, "window.__INITIAL_STATE__=")
    if not raw:
        raise StoreError("百度详情页未找到 __INITIAL_STATE__ 数据（应用可能已下架）")
    stj = json.loads(raw)
    card = None
    try:
        card = stj["appDoc"]["resList"]["d_%s" % docid]["data"]["appDocNew"]["appDoc"]
    except Exception:  # noqa: BLE001
        pass
    if not card or not card.get("downloadUrl"):
        found: List[Dict[str, Any]] = []

        def walk(o: Any) -> None:
            if isinstance(o, dict):
                if o.get("downloadUrl") and str(o.get("docid")) == docid:
                    found.append(o)
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)

        walk(stj)
        card = found[0] if found else None
    if not card:
        raise StoreError("百度未找到该 docid 的下载地址（应用可能已下架）")
    ref = {"Referer": "https://shouji.baidu.com/"}
    return {"market": "百度手机助手", "app_id": docid, "name": card.get("sname"),
            "package": card.get("package"), "version": card.get("versionname"),
            "candidates": [("universal", card["downloadUrl"], ref)],
            "size_hint": card.get("size"),
            "note": "直链必须带 Referer，否则 404；会 302 到 ms2-gdown"}


def resolve_wandoujia(url: str) -> Dict[str, Any]:
    m = re.search(r"/apps/([A-Za-z0-9_.\-]+)", url)
    if not m:
        raise StoreError("无法从豌豆荚链接解析应用标识")
    ident = m.group(1)
    if not ident.isdigit():
        final = None
        try:
            _st, _hd, _b = http("https://www.wandoujia.com/apps/%s" % ident,
                                {"User-Agent": UA_DESKTOP}, follow=True)
            req = urllib.request.Request("https://www.wandoujia.com/apps/%s" % ident,
                                         headers={"User-Agent": UA_DESKTOP})
            with _OPENER_FOLLOW.open(req, timeout=60) as r:
                final = r.url
        except Exception:  # noqa: BLE001
            pass
        mm = re.search(r"/apps/(\d+)", final or "")
        if not mm:
            raise StoreError("豌豆荚未能把包名 %s 反查为数字 ID" % ident)
        ident = mm.group(1)
    _st, _hd, body = http("https://www.wandoujia.com/wdjweb/api/getDownloadAppByAppId",
                          {"User-Agent": UA_DESKTOP,
                           "Content-Type": "application/x-www-form-urlencoded"},
                          data={"appId": ident})
    js = json.loads(body.decode("utf-8", errors="ignore"))
    app = (js or {}).get("app") or {}
    if not app.get("downloadUrl"):
        raise StoreError("豌豆荚接口未返回 downloadUrl（应用可能已下架）")
    return {"market": "豌豆荚", "app_id": ident,
            "name": app.get("name") or app.get("title"),
            "package": app.get("packageName"), "version": app.get("versionName"),
            "candidates": [("universal", app["downloadUrl"], None)],
            # 注意：豌豆荚接口的 size 字段单位是 KB（不是字节），需 ×1024
            "size_hint": (int(app["size"]) * 1024
                          if str(app.get("size", "")).isdigit() else None),
            "note": "直链会 302 到 ucdl.25pp.com，无防盗链"}


def resolve_360(url: str) -> Dict[str, Any]:
    m = re.search(r"soft_id/(\d+)", url) or re.search(r"[?&]id=(\d+)", url)
    if not m:
        raise StoreError("无法从 360 链接解析 soft_id")
    sid = m.group(1)
    _st, _hd, html = http_text("https://zhushou.360.cn/detail?id=%s" % sid,
                               {"User-Agent": UA_DESKTOP})
    mm = re.search(r'<script[^>]*id="__NUXT_DATA__"[^>]*>(.*?)</script>', html, re.S)
    if not mm:
        cand = re.findall(r'https?://[^"\'<>\s]+\.apk[^"\'<>\s|]*', html)
        if not cand:
            raise StoreError("360 详情页未找到下载数据（页面结构可能已改版）")
        return {"market": "360手机助手", "app_id": sid, "name": None, "package": None,
                "version": None, "candidates": [("universal", cand[0], None)],
                "note": "旧版页面路径（兜底）"}
    payload = mm.group(1).strip()
    arr = json.loads(payload)
    schema = None
    for el in arr:
        if isinstance(el, dict) and "down_url" in el and "pname" in el:
            schema = el
            break
    if not schema:
        cand = re.findall(r'https?://[^"\'<>\s]+\.apk[^"\'<>\s|]*', html)
        if cand:
            return {"market": "360手机助手", "app_id": sid, "name": None, "package": None,
                    "version": None, "candidates": [("universal", cand[0], None)],
                    "note": "兜底路径：直接从页面提取 apk 直链"}
        raise StoreError("360 未解析到应用数据（soft_id=%s）。可能该 soft_id 不存在，"
                         "或页面已改版；请确认链接形如 "
                         "https://zhushou.360.cn/detail?id=<数字>" % sid)

    def val(field: str) -> Any:
        i = schema.get(field)
        if isinstance(i, int) and 0 <= i < len(arr) and not isinstance(arr[i], (dict, list)):
            return arr[i]
        return None

    # 优先用 download_urls（带 tok 的官方直链）。
    # pdown_url 里的 shouji.360tpcdn.com 直链是给 PC 客户端用的，会被
    # download.api.sj.360.cn 跳转器劫持成「360手机助手客户端安装包」
    # （实测返回 45MB 的 appstore-*.apk 而非目标应用），故仅作兜底。
    dl = val("download_urls") or val("down_url")
    pdown = val("pdown_url") or ""
    pm = re.search(r"(https?://[^\s|]+\.apk)", pdown)
    if not dl and pm:
        dl = pm.group(1)
    if not dl:
        raise StoreError("360 未解析出下载地址")
    size_hint = val("apk_sizes")
    return {"market": "360手机助手", "app_id": sid, "name": val("soft_name"),
            "package": val("pname"), "version": val("version_name"),
            "candidates": [("universal", dl, None)],
            "size_hint": int(size_hint) if str(size_hint).isdigit() else None,
            "note": "取自 __NUXT_DATA__ 的 devalue 数组（字段名→下标映射）"}


ADAPTERS = [
    ("应用宝", r"sj\.qq\.com", resolve_yyb),
    ("华为应用市场", r"appgallery\.huawei\.com", resolve_huawei),
    ("vivo 应用商店", r"appstore\.vivo\.com\.cn", resolve_vivo),
    ("小米应用商店", r"app\.mi\.com", resolve_mi),
    ("百度手机助手", r"shouji\.baidu\.com", resolve_baidu),
    ("豌豆荚", r"wandoujia\.com", resolve_wandoujia),
    ("360手机助手", r"zhushou\.360\.cn", resolve_360),
]

MARKET_NAMES = [n for n, _p, _f in ADAPTERS]


def pick_adapter(url: str) -> Tuple[str, Callable[..., Dict[str, Any]]]:
    """按链接识别市场。识别不出就抛 StoreError（调用方可以直接把人话写进任务记录）。"""
    for name, pat, fn in ADAPTERS:
        if re.search(pat, url):
            return name, fn
    raise StoreError(
        "不支持的应用商店链接。目前支持：%s。"
        "（若你手上是 APK 直链，请改用「APK 下载链接」）" % "、".join(MARKET_NAMES))


def resolve(url: str, abi: str = "arm64") -> Dict[str, Any]:
    _name, fn = pick_adapter(url)
    return fn(url, abi) if fn is resolve_yyb else fn(url)


# --------------------------------------------------------------------------
# 批量网址输入
# --------------------------------------------------------------------------

def parse_url_list(text: str, limit: int = MAX_BATCH_URLS
                   ) -> Tuple[List[str], List[Dict[str, str]]]:
    """把多行文本切成网址列表，返回 (可用网址, 被跳过的条目)。

    被跳过的每一条都带原因 —— 提交后用户要能一眼看出"我贴了 8 行，为什么只建了 5 个任务"。
    空行不算"跳过"（那不是用户的错误，是排版），直接忽略。
    """
    ok: List[str] = []
    skipped: List[Dict[str, str]] = []
    seen = set()
    for raw in (text or "").splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        if not re.match(r"^https?://", line, re.I):
            skipped.append({"url": line, "reason": "不是 http/https 链接"})
            continue
        key = line.rstrip("/")
        if key in seen:
            skipped.append({"url": line, "reason": "本批次内重复，已合并为一条"})
            continue
        try:
            name, _fn = pick_adapter(line)
        except StoreError:
            # 把"这是直链"单独认出来：用户最常犯的错是把 .apk 直链贴进商店输入框，
            # 泛泛地说"不支持"他还得自己猜该用哪个入口。
            if re.search(r"\.apk($|[?#])", line, re.I):
                skipped.append({"url": line,
                                "reason": "这是 APK 直链，请改用「APK 下载链接」提交"})
            else:
                skipped.append({"url": line, "reason": "不是受支持的应用商店链接"})
            continue
        seen.add(key)
        ok.append(line)
    if len(ok) > limit:
        for url in ok[limit:]:
            skipped.append({"url": url, "reason": "超出单次提交上限 %d 条" % limit})
        ok = ok[:limit]
    return ok, skipped


# --------------------------------------------------------------------------
# 主入口
# --------------------------------------------------------------------------

def fetch(url: str, dest_dir: str | os.PathLike, abi: str = "arm64",
          log: Optional[Callable[[str], None]] = None,
          progress: Optional[Callable[[int, int], None]] = None,
          should_stop: Optional[Callable[[], bool]] = None,
          force: bool = False, chunk_mb: int = 8, retries: int = 8) -> FetchResult:
    """商店链接 → 本地 APK。

    失败不抛异常，返回 `ok=False` 且 `error` 写清原因（与 apkfetch.fetch_url 一致），
    只有调用方明确要中止时才抛 StoreCancelled —— 那属于"用户操作"，不是"失败"。
    """
    logf = log or _noop
    t0 = time.time()
    res = FetchResult(ok=False, source="store", url=url)

    try:
        name, fn = pick_adapter(url)
    except StoreError as e:
        res.error = str(e)
        return res
    logf("[*] 识别市场：%s" % name)

    try:
        logf("[*] 解析直链 ...")
        info = fn(url, abi) if fn is resolve_yyb else fn(url)
    except StoreError as e:
        res.error = str(e)
        return res
    except Exception as e:  # noqa: BLE001
        # 解析器里的解析错误（页面改版导致的 JSON 结构变化）不应该把 worker 带走，
        # 但必须原样报出来 —— 否则会变成"这个 App 测不了"而看不出是解析器坏了。
        res.error = "解析该链接时出错（页面结构可能已改版）：%s: %s" % (type(e).__name__, e)
        return res

    res.market = info.get("market") or name
    res.package = info.get("package") or ""
    res.version = info.get("version") or ""
    res.app_name = info.get("name") or ""
    res.original_name = "%s %s" % (res.app_name or "", res.version or "")
    logf("[*] 市场：%s" % res.market)
    logf("[*] 应用：%s ｜ 包名：%s ｜ 版本：%s"
         % (res.app_name or "(未解析)", res.package or "(未解析)", res.version or "(未解析)"))
    if info.get("note"):
        logf("[*] 说明：%s" % info["note"])

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    last_err = "没有可用的下载直链"

    for abi_name, dl_url, headers in info["candidates"]:
        size, ctype, err = probe_size_and_headers(dl_url, headers)
        if err:
            last_err = "%s 直链不可用：%s" % (abi_name, err)
            logf("[!] %s" % last_err)
            continue
        # 体积上限与直链下载保持一致。没有上限时，一个填错的链接就能把
        # 服务器磁盘写满 —— 而任务只是"看起来在下"。
        if size > MAX_BYTES:
            last_err = ("文件 %.1f MB 超过上限 %.0f MB，已拒绝下载"
                        % (size / 1048576.0, MAX_BYTES / 1048576.0))
            logf("[!] %s" % last_err)
            continue
        # 体积交叉校验：防止某些市场把「客户端引导包/微下载包」当成目标应用返回
        hint = info.get("size_hint")
        if hint and abs(size - hint) > max(2 * 1024 * 1024, hint * 0.01):
            last_err = ("体积校验失败，疑似被劫持为引导包：详情页标注 %s 字节，"
                        "直链实测 %s 字节" % (hint, size))
            logf("[!] %s" % last_err)
            continue
        pkg = info.get("package")
        fname = urllib.parse.urlparse(dl_url).path.rsplit("/", 1)[-1]
        if pkg and fname.lower().endswith(".apk") and pkg.lower() not in fname.lower():
            logf("[!] 提示：直链文件名「%s」中不含包名「%s」，下载后会做包名校验"
                 % (fname, pkg))
        logf("[*] %s：%s  %s 字节（%.1f MB）  %s"
             % (abi_name, dl_url.split("?")[0].rsplit("/", 1)[-1][:60],
                format(size, ","), size / 1048576.0, ctype or ""))

        stem = safe_ascii_filename("%s_%s_%s.apk" % (pkg or info.get("app_id") or "app",
                                                     info.get("version") or "unknown",
                                                     abi_name))
        out_path = str(dest / stem)
        try:
            if os.path.exists(out_path) and os.path.getsize(out_path) == size and not force:
                logf("[*] 已存在完整文件，跳过下载")
            else:
                if force and os.path.exists(out_path):
                    os.remove(out_path)
                logf("[*] 下载 -> %s" % out_path)
                got = download(dl_url, out_path, size, headers, chunk_mb, retries,
                               logfn=logf, progress=progress, should_stop=should_stop)
                if got != size:
                    raise StoreError("大小不符：%d != %d" % (got, size))
        except StoreCancelled:
            raise
        except StoreError as e:
            done = os.path.getsize(out_path) if os.path.exists(out_path) else 0
            last_err = str(e)
            logf("[!] 下载中断：%s（已保存 %s / %s 字节，重跑可续传）"
                 % (e, format(done, ","), format(size, ",")))
            continue

        v = verify_apk(out_path, info.get("package"))
        if not v.get("ok"):
            last_err = ("下载到的文件校验未通过：%s"
                        % (v.get("err") or
                           ("包名不匹配" if v.get("pkg_ok") is False else "ZIP 损坏")))
            logf("[!] %s" % last_err)
            continue
        res.ok = True
        res.path = os.path.abspath(out_path)
        res.filename = os.path.basename(out_path)
        res.size = os.path.getsize(out_path)
        res.sha256 = sha256_of(res.path)
        res.elapsed = time.time() - t0
        logf("[+] 下载完成：%s（%.1f MB，ABI %s，SHA256 %s…）"
             % (res.filename, res.size / 1048576.0,
                "/".join(v.get("abi") or []) or "无 native 库", res.sha256[:12]))
        return res

    res.error = last_err
    res.elapsed = time.time() - t0
    return res
