"""统一加载沙箱客户端提取出的知识库资源（reference/ 目录）。

这些资源是判定引擎与 SDK 识别的基础，由本项目自行维护（见各文件头的说明），
加载结果带进程内缓存，重复调用不会重复解析。
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple

# 项目根：.../piiscan/  （本文件位于 .../piiscan/piiscan/resources.py）
ROOT = Path(__file__).resolve().parent.parent
REF = ROOT / "reference"


def _read_text(p: Path) -> str:
    """读文本，先严格 UTF-8，失败再按 GBK。

    ★ 这里**不能**给 utf-8 加 `errors="replace"`：那会让 UTF-8 解码永不抛异常，
      GBK 文件被整片替换成 `\ufffd` 却当成功返回，下面的 GBK 分支成了死代码。
      早期一份 GBK 编码的行为码表就是这么被整片读成 `�` 的。
      严格解码先行，失败才回落；两者都不行才用替换符兜底（宁可乱码也不抛）。
    """
    for enc in ("utf-8", "gbk"):
        try:
            return p.read_text(encoding=enc)
        except Exception:
            continue
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _read_json(p: Path) -> Any:
    try:
        return json.loads(_read_text(p))
    except Exception:
        return None


# ---------------------------------------------------------------- SDK 库
@lru_cache(maxsize=1)
def sdk_library() -> List[Tuple[str, str, str, str]]:
    """返回 [(包名前缀, SDK名称, SDK类型, 厂商)]，按前缀长度降序。

    数据源：reference/sdk_package/sdk.json（本项目整理的全量表）
          + reference/sdk_package/sdk_alias.json（同 SDK 的其它包名根）。

    ★ 别名表为什么必须并进来（金考典 2026-10-28）：
      sdk.json 只登记了倍孜的 `com.beizi.fusion`，而它运行期的类跑在
      `xyz.adscope.*` / `com.beizi.ad.*` 下。结果静态分析认得出这个 SDK，
      调用栈归因却写"未能归属" —— 同一份报告里两处结论互相打脸，
      而复核员只会看到"你的证据和结论对不上"。别名表是纯数据，
      补一条就同时修好静态识别与运行期归因两条链路。
    """
    data = _read_json(REF / "sdk_package" / "sdk.json") or {}
    models = list(data.get("sdkModels") if isinstance(data, dict) else None) \
        if isinstance(data, dict) else []
    alias = _read_json(REF / "sdk_package" / "sdk_alias.json") or {}
    if isinstance(alias, dict):
        models.extend(alias.get("sdkModels") or [])
    out: List[Tuple[str, str, str, str]] = []
    seen_pkg: set = set()
    for m in (models or []):
        pkg = (m.get("SdkPackage") or "").strip()
        if not pkg or pkg.rstrip(".") in seen_pkg:
            continue
        seen_pkg.add(pkg.rstrip("."))
        # iOS 的 "xxx.framework." 形式对 Android 无意义，但保留成本很低
        out.append((pkg.rstrip("."), (m.get("SdkName") or "").strip(),
                    (m.get("SdkType") or "").strip(), (m.get("author") or "").strip()))
    out.sort(key=lambda t: len(t[0]), reverse=True)
    return out


@lru_cache(maxsize=1)
def sdk_type_words() -> Dict[str, List[str]]:
    """按 SDK 类型归类（广告类 / 推送类 …）。"""
    grouped: Dict[str, List[str]] = {}
    for pkg, name, typ, _author in sdk_library():
        if typ:
            grouped.setdefault(typ, []).append(name or pkg)
    return grouped


# ---------------------------------------------------------------- 加固特征
@lru_cache(maxsize=1)
def jiagu_signatures() -> List[Tuple[str, str, str]]:
    """返回 [(特征文件名/串, 加固名称, 厂商)]。

    数据源：reference/sdk_package/jiagu.txt（本项目整理的全量表）。
    格式：特征;加固名;厂商;官网
    """
    out: List[Tuple[str, str, str]] = []
    for line in _read_text(REF / "sdk_package" / "jiagu.txt").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(";")
        if len(parts) >= 3:
            out.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
    return out


# ---------------------------------------------------------------- 敏感 API 静态表
@lru_cache(maxsize=1)
def sensitive_api_table() -> List[Dict[str, Any]]:
    """静态敏感 API 表。

    数据源：reference/static_word/sensitive-api-static-api.json
    每条含 category / label / behavior_code / required_permissions / signatures。
    """
    data = _read_json(REF / "static_word" / "sensitive-api-static-api.json") or {}
    if isinstance(data, dict):
        return list(data.get("apis") or [])
    return []


@lru_cache(maxsize=1)
def ignore_packages() -> List[str]:
    data = _read_json(REF / "static_word" / "sensitive-api-static-api.json") or {}
    if isinstance(data, dict):
        return list(data.get("ignore_packages") or [])
    return []


# ---------------------------------------------------------------- 行为码 ↔ 政策表述
@lru_cache(maxsize=1)
def policy_words() -> Dict[str, List[str]]:
    """行为码 -> 隐私政策中可能出现的表述词。

    数据源：reference/static_word/privacyconfig.txt
    例：beh.device.imei:IMEI、MEID、设备识别码…
    用途：做「声明 vs 实际」差集判定 —— 实测收集了某类信息，
    但政策文本中找不到任何对应表述，则为「收集了但未声明」。
    """
    out: Dict[str, List[str]] = {}
    for line in _read_text(REF / "static_word" / "privacyconfig.txt").splitlines():
        line = line.strip()
        # 词表带 `#` 注释头，不跳过的话注释里的冒号会被解析成一条行为码
        if not line or line.startswith("#") or ":" not in line:
            continue
        code, _, words = line.partition(":")
        items = [w.strip() for w in re.split(r"[、,，;；]", words) if w.strip()]
        if items:
            out[code.strip()] = items
    return out


# ---------------------------------------------------------------- 权限字典
@lru_cache(maxsize=1)
def permission_table() -> Dict[str, Dict[str, str]]:
    """权限名 -> {name: 中文名, desc: 说明, level: 保护级别}。

    主源：static_word/permission.json（含中文名与说明）
    补充：static_word/permission.txt（含 dangerous / normal / signature 级别）
    """
    out: Dict[str, Dict[str, str]] = {}
    data = _read_json(REF / "static_word" / "permission.json")
    if isinstance(data, list):
        for it in data:
            p = (it.get("permission") or "").strip()
            if not p:
                continue
            out[p] = {
                "name": (it.get("permissionName") or "").strip(),
                "desc": (it.get("permissionDes") or "").strip(),
                "level": "",
            }
    # 级别：permission.txt 每行 `权限;;中文名;;描述;;级别;;`
    # ★ 级别在 parts[3]，不是 parts[4]：行尾那个 `;;` 会切出一个空串，
    #   取 parts[4] 的结果是「每条权限的级别都为空」，报告里永远显示不出危险权限。
    for line in _read_text(REF / "static_word" / "permission.txt").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(";;")
        if len(parts) >= 4:
            p = parts[0].strip()
            if not p:
                continue
            rec = out.setdefault(p, {"name": "", "desc": "", "level": ""})
            rec["level"] = parts[3].strip()
            if not rec["name"]:
                rec["name"] = parts[1].strip()
    return out


def permission_labels() -> Dict[str, str]:
    """权限名 -> 中文标签（兼容旧调用）。"""
    return {k: v["name"] for k, v in permission_table().items() if v.get("name")}


def permission_level(perm: str) -> str:
    rec = permission_table().get(perm)
    return (rec or {}).get("level", "")


# ---------------------------------------------------------------- 域名归属
@lru_cache(maxsize=1)
def web_hosts() -> Dict[str, str]:
    """域名 -> 公司名（WebSiteHost.txt，`=` 分隔）。"""
    out: Dict[str, str] = {}
    for line in _read_text(REF / "static_word" / "WebSiteHost.txt").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        host, _, company = line.partition("=")
        out[host.strip().lower()] = company.strip()
    return out


def host_owner(host: str) -> str:
    """把域名反查到公司：先精确匹配，再按后缀逐级匹配。"""
    hosts = web_hosts()
    host = (host or "").lower().strip()
    if not host:
        return ""
    if host in hosts:
        return hosts[host]
    parts = host.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in hosts:
            return hosts[cand]
    return ""


# ---------------------------------------------------------------- 资源可用性自检
def available() -> Dict[str, int]:
    return {
        "sdk_library": len(sdk_library()),
        "jiagu_signatures": len(jiagu_signatures()),
        "sensitive_api": len(sensitive_api_table()),
        "policy_words": len(policy_words()),
        "permission_table": len(permission_table()),
        "web_hosts": len(web_hosts()),
    }
