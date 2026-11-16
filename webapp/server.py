"""Web 提交平台：HTTP 服务 + 后台任务执行器。

只用 Python 标准库（http.server / sqlite3），零第三方依赖，便于搬到内网。
"""
from __future__ import annotations

import base64
import importlib.util
import io
import json
import mimetypes
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .db import JobDB

ROOT = Path(__file__).resolve().parent.parent          # .../piiscan/
STATIC = Path(__file__).resolve().parent / "static"

# 注意：进度不再按日志关键字推断，而是由 sop_job 的 on_stage 回调直接上报
# 真实阶段。早先那张"阶段→百分比"表在平台改走 SOP 之后就对不上了。

# AI 选项白名单：只接收这些键，避免前端随便塞东西进来。
# 值统一转成字符串/布尔后打包成 JSON 存进任务的 ai_opts 列。
AI_OPT_KEYS = (
    "ai_provider", "ai_base_url", "ai_model", "ai_vision_model", "ai_api_key",
    "ai_policy_vision", "ai_policy_analyze", "ai_ui_agent", "ai_policy_parse",
    # 遍历成本控制与 Agent 中继（留空则沿用 config.yaml）
    "ai_ui_agent_every", "ai_ui_agent_max_calls",
    "ai_relay_dir", "ai_relay_timeout",
)


def _norm_device(raw: Any) -> str:
    """规整"指定测试机"参数。空串 / auto = 不指定。

    只做格式校验，不要求它**此刻**在线：批量提交时用户可能先把一队任务排进
    队列，某台机稍后才插上。真正的"在不在"由开跑前的自检判定（那里会带着
    adb 原文报错），这里拦下的是拼错的序列号。
    """
    s = str(raw or "").strip()
    if s.lower() in ("", "auto", "默认", "自动"):
        return ""
    if not re.fullmatch(r"[A-Za-z0-9._:\-]{1,64}", s):
        raise ValueError("测试机序列号格式不对：%r（应为 adb devices 里显示的那串）" % s[:64])
    return s


def _as_bool(v) -> bool:
    return str(v).strip().lower() not in ("0", "false", "off", "no", "")


# 档位别名（与 piiscan.config._DEPTH_ALIASES 保持一致）。
# 这里不 import 那个私有表：webapp 应当能在没有 piiscan 的场景下单独起，
# 而这份映射只有六个词，重复写一遍比多一条运行期依赖划算。
_DEPTH_ALIAS = {
    "standard": "normal", "quick": "normal", "fast": "normal",
    "1": "pre", "2": "light", "3": "deep", "4": "extreme",
    "shallow": "light", "full": "extreme", "max": "extreme",
}


def resolve_dynamic(requested, device_enabled: bool) -> bool:
    """决定这个任务跑不跑动态采集。

    `requested` 为 None 表示调用方没提交这个字段（老前端、纯 API 客户端），
    此时按**本机能力**给默认值：接了手机就默认跑，没接就不跑。

    为什么"要求动态但没有设备"必须报错而不是降级成静态：静态-only 的报告
    里所有采集类结论都会是"跳过未测"，而提交者以为跑过动态，就会把
    "没测"读成"没问题"。宁可当场 400，让人去接入设备或明确改成静态。
    """
    if requested is None:
        return bool(device_enabled)
    if requested and not device_enabled:
        raise ValueError("本服务未接入检测设备，无法执行动态采集；"
                         "请取消「执行设备动态采集」（run_dynamic=0）后重新提交，"
                         "或在连接了测试机的主机上提交")
    return bool(requested)


def _norm_phone(raw: Any) -> str:
    """规范化测试手机号。空串 = 不做登录辅助。

    为什么要卡这么死：号码填错不会当场报错，而是等到遍历走进登录页、
    App 真发了一条短信、拿不到码才失败 —— 那时人已经离开屏幕，
    整轮采集就白跑了。所以在提交这一刻就把明显不对的号拦下来。
    """
    s = re.sub(r"[\s\-()（）]", "", str(raw or ""))
    if not s:
        return ""
    if not re.fullmatch(r"1[3-9]\d{9}", s):
        raise ValueError("测试手机号格式不对（%s）：需为 11 位大陆手机号，"
                         "不需要登录辅助请留空" % (str(raw or "")[:20]))
    return s


def _local_cfg(cfg_path: Optional[str] = None):
    """读本地 config.yaml（或调用方指定的另一份），读不出来返回 None。

    ★ 为什么允许传路径
      离线自检要能在**没有 config.yaml 的干净发布树**里跑。让用例自己造一份
      临时配置、显式传进来，比"依赖开发机上恰好有一份带真实号码的配置"可靠：
      否则别人 clone 下来第一件事就是看到一片红。
    """
    try:
        from piiscan.config import AppConfig
        p = Path(cfg_path) if cfg_path else (ROOT / "config.yaml")
        return AppConfig.load(p) if p.exists() else AppConfig()
    except Exception:
        return None


def _default_login_phone(cfg_path: Optional[str] = None) -> str:
    """表单**没带** login_phone 字段时用的默认测试号（config.yaml → scan.login_phone）。

    ★ 为什么"缺字段"不能等于"不登录"（2026-11-06 用户口径）：
      这台红米 K30 的测试号已经写进配置，默认就做登录辅助测试；不想登录的人
      在前端把「登录辅助测试」取消勾选，前端会**显式传空串**。
      于是三种情况各有明确含义：
        字段缺失 → 没表态 → 用配置里的默认号
        字段为空串 → 用户主动关 → 不登录
        字段有号 → 用填的号

      反过来做（缺字段即不登录）会让"默认开启"变成一句空话，
      而改成"缺字段就用默认号、空串也当没传"则会让用户关不掉 —— 两种都错。
    """
    try:
        cfg = _local_cfg(cfg_path)
        if cfg is None:
            return ""
        return _norm_phone(getattr(cfg.scan, "login_phone", ""))
    except Exception:
        # 配置读不出来/号码格式写错都不该让任务提交失败：退回"不登录"，
        # 采集侧照样能跑，报告会写明只覆盖游客可见范围。
        return ""


def _registry_db():
    """拿到登记簿所在的库（Handler.db 是类属性，运行时才注入）。

    抽成一个函数而不是到处 `Handler.db`：以后要是把 db 换成多实例/连接池，
    只需要改这一处；而且 `getattr` 兜底让 server 在没有 db 的场景下也能起。
    """
    try:
        return getattr(Handler, "db", None)
    except Exception:
        return None


def _device_phones(cfg_path: Optional[str] = None) -> Dict[str, str]:
    """每台测试机登记的 SIM 号码（serial → 号）。

    ★ 为什么号码要按机器登记，而不是全局一个：
      每台测试机插的是自己的卡。拿 A 机的号去登录 B 机上的 App，验证码根本
      收不到，而现象只是「登录超时」—— 看不出是号码错了，很容易被当成 App
      的问题写进报告。所以"选哪台机就用那台的号"是唯一不会错的默认。

    两个来源，**登记簿优先**：
      · `devices` 表 —— 界面「手机管理」里填的，是主口径；
      · `config.yaml → device.phones` —— 历史部署手写的，保留作兜底。
      同一台机两边都有值时以界面为准：人在界面上改过，说明他刚刚确认过。

    配置读不出来时返回空表（调用方会退回全局默认号），不让整个请求失败。
    """
    out: Dict[str, str] = {}
    cfg = _local_cfg(cfg_path)
    raw = (getattr(getattr(cfg, "device", None), "phones", None) or {}) if cfg else {}
    try:
        for k, v in raw.items():
            s = str(k or "").strip()
            n = _norm_phone(str(v or ""))
            if s and n:
                out[s] = n
    except Exception:
        pass
    db = _registry_db()
    if db is not None:
        try:
            for k, v in (db.device_phones() or {}).items():
                s = str(k or "").strip()
                n = _norm_phone(str(v or ""))
                if s and n:
                    out[s] = n
        except Exception:
            pass
    return out


def _default_login_phone_for(device: str = "", cfg_path: Optional[str] = None) -> str:
    """表单没带 login_phone 时的默认号：**优先用这台测试机登记的号**。

    只在"字段缺失"时才会被调用（前端显式传空串仍表示不登录），所以这条回落
    不会让用户关不掉登录；它只决定"用户没表态时默认用哪个号"。
    """
    if device:
        p = _device_phones(cfg_path).get(device, "")
        if p:
            return p
    return _default_login_phone(cfg_path)


def _norm_depth(raw: Any) -> str:
    """检测深度档位规范化。未知值退回 normal。

    四档口径（2026-10-31）：pre / light / deep / extreme。
    normal 仍接受 —— 历史任务与老调用方写的就是它，直接判非法会让重跑失败。

    为什么不报错：档位是"多花点时间"的旋钮，填错一个词不该让任务提交失败。
    但也不能猜成 deep —— 那会把一份十几分钟的检测当成用户没要求过。
    """
    v = str(raw or "").strip().lower()
    if v in _DEPTH_ALIAS:
        v = _DEPTH_ALIAS[v]
    return v if v in ("pre", "light", "normal", "deep", "extreme") else "normal"


def _file_stem(job: Dict[str, Any], suffix: str) -> str:
    """下载文件名（纯 ASCII）。留给只认 ASCII 的场景 / 老调用方。"""
    pkg = (job.get("package") or "").strip() or (job.get("id") or "job")
    ts = time.strftime("%Y%m%d-%H%M", time.localtime(job.get("created_at") or time.time()))
    tail = ("-" + suffix) if suffix else ""
    return "PII-Report-%s-%s%s" % (pkg, ts, tail)


# ---------------------------------------------------------------- 文件名
# 报告文件名要带 App 名称，但名称的来源很杂：`android:label`、商店页标题、
# APK 文件名。里面可能混着斜杠、冒号、换行（甚至有整句话）——
# 直接拼进文件名，Windows 上创建失败、Linux 上悄悄变成多级目录。必须先清洗。
_BAD_NAME_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def _safe_name(raw: Any, limit: int = 40) -> str:
    """把任意字符串清成可放进文件名的片段。"""
    t = _BAD_NAME_CHARS.sub("_", str(raw or ""))
    t = re.sub(r"\s+", " ", t).strip(" ._-")
    return t[:limit].strip(" ._-")


def _app_label(job: Dict[str, Any]) -> str:
    """App 名称，按可靠性依次退：app_label → APK 文件名 → 包名。

    `app_label` 是装包后从系统里读出的 `android:label`，最接近用户桌面上
    看到的名字。只跑静态分析（未装包）时它可能为空，此时退到 APK 文件名 ——
    用户上传时多半就叫「米兔.apk」，比 com.xiaomi.xxx 好认。
    """
    for raw in (job.get("app_label"), Path(job.get("apk_name") or "").stem,
                job.get("package")):
        s = _safe_name(raw, 30)
        if s:
            return s
    return ""


def _report_filename(job: Dict[str, Any], suffix: str = "", ext: str = ".html") -> str:
    """下载 / 打包时给人看的文件名：`<App名称>_<包名>_<时间>[_后缀]`。

    顺序按「人先看哪个」排：App 名称在前，包名在后，时间最后 ——
    同一个 App 测了多轮，解压到同一个文件夹后按名称排序就能排到一起，
    而不是散落在十几个 PII-Report-… 里靠时间戳去猜。
    """
    parts: List[str] = []
    label = _app_label(job)
    if label:
        parts.append(label)
    pkg = _safe_name(job.get("package") or "", 48)
    if pkg:
        parts.append(pkg)
    if not parts:
        # 名称和包名都取不到（任务刚建、APK 还没解析）时，退到任务号。
        # 不能只剩时间戳 —— 同一分钟提交的几个任务会撞成同一个文件名，
        # 单份下载下来分不清是谁的。
        parts.append(_safe_name(job.get("id") or "", 24) or "report")
    parts.append(time.strftime("%Y%m%d-%H%M",
                               time.localtime(job.get("created_at") or time.time())))
    stem = "_".join(parts)
    return stem + (("_" + suffix) if suffix else "") + ext


def _ascii_fallback(job: Dict[str, Any], suffix: str = "", ext: str = ".html") -> str:
    """Content-Disposition 的 ASCII 兜底名（只认 ASCII 的老客户端用这个）。"""
    pkg = _safe_name(job.get("package") or "", 48) or (job.get("id") or "job")
    ts = time.strftime("%Y%m%d-%H%M", time.localtime(job.get("created_at") or time.time()))
    return "%s-%s%s%s" % (pkg, ts, ("-" + suffix) if suffix else "", ext)


# 简版报告的文件名。与详细报告同目录，靠文件名区分 ——
# 不加数据库字段是刻意的：路径能推导出来，多一个字段就多一处可能写漏的地方。
BRIEF_NAME = "report_brief.html"


def _brief_path(job: Dict[str, Any]) -> Optional[Path]:
    """由详细报告路径推出简版路径；没有详细报告就没有简版。"""
    rp = str(job.get("report_path") or "").strip()
    if not rp:
        return None
    return Path(rp).with_name(BRIEF_NAME)


def _brief_fresh(bp: Path) -> bool:
    """已落盘的那份是不是**当前口径**渲染的。

    口径改过（去掉"简版"字样、补静态档案/加固/签名、补调用栈与截图）之后，
    老任务目录里的 `report_brief.html` 仍然在、仍然能打开，但内容是旧版。
    只判"文件存在"会让用户点下载拿到的还是旧版本，而且看不出哪里不对
    —— 所以文件头写了口径标记，对不上就重渲染。
    """
    try:
        from piiscan.report.sop_brief import BRIEF_MARKER
    except Exception:
        return True                      # 导入不了就按旧行为处理，别把下载打死
    if not bp.exists() or bp.stat().st_size <= 0:
        return False
    try:
        with bp.open("r", encoding="utf-8", errors="ignore") as f:
            head = f.read(400)
    except OSError:
        return False
    return BRIEF_MARKER in head


def _ensure_brief(job: Dict[str, Any]) -> Tuple[Optional[Path], str]:
    """拿到简版报告，没有（或口径过期）就现渲染一份。返回 (路径, 失败原因)。

    为什么允许"现渲染"：这份报告是后加的，之前跑的任务目录里只有
    `report.html` + `flow.json`。要求用户为了拿一份报告重跑整轮检测
    （十几分钟、还要占着手机）显然不合理。而渲染器只吃 `flow.json`
    的 dict（不依赖运行期对象），所以补出来的那份与"当时生成"的完全同源。

    失败只返回原因、不抛异常：调用方要把它变成一条 409 提示，
    而不是让整个请求 500。
    """
    bp = _brief_path(job)
    if bp is None:
        return None, "任务没有详细报告（状态：%s）" % (job.get("status") or "未知")
    if _brief_fresh(bp):
        return bp, ""

    src = str(job.get("result_path") or "").strip()
    if not src or not Path(src).exists():
        # 旧口径但打不开重渲染的条件（flow.json 被清掉了）—— 有就用旧的，
        # 总比让用户彻底下不到强，但要在日志里留痕。
        if bp.exists() and bp.stat().st_size > 0:
            return bp, ""
        return None, ("缺少流程存档（flow.json），无法据此补出这份报告；"
                      "请重新检测，或下载详细报告")
    try:
        from piiscan.report.sop_brief import render_brief
        data = json.loads(Path(src).read_text(encoding="utf-8"))
        html = render_brief(
            data,
            app_name=str(job.get("app_label") or ""),
            version=str(job.get("version_name") or ""),
            date=job.get("created_at") or "",
        )
        bp.parent.mkdir(parents=True, exist_ok=True)
        bp.write_text(html, encoding="utf-8")
        return bp, ""
    except Exception as e:
        return None, "渲染简版失败：%s: %s" % (type(e).__name__, e)


def _disposition(filename: str, fallback: str) -> str:
    """`Content-Disposition`：ASCII 兜底 + RFC 5987 扩展，**两个都给**。

    ★ 早先只用 `filename="…"` 且全是 ASCII，理由写的是"中文名各家支持不一"。
      真正的原因是当时**只写了 filename* 而没给兜底**，部分客户端于是把
      `%E7%B1%B3%E5%85%94...` 原样当文件名显示（看起来像乱码，其实是没解码）。
      正确写法是两个都写：认 `filename*` 的取中文名，不认的退回 ASCII。
    """
    fb = re.sub(r"[^A-Za-z0-9._-]", "_", fallback) or "report"
    return "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (
        fb, urllib.parse.quote(filename, safe=""))


# 批量打包上限。为什么要有：zip 是在内存里拼的（不落临时文件，避免
# 半成品包和清理问题），而报告里有内联截图，单份 0.2~1.5 MB。
# 200 份 × 平均 1 MB ≈ 200 MB 峰值内存 —— 本地平台可接受，再大就该分批。
MAX_ZIP_ITEMS = 200
MAX_ZIP_BYTES = 200 * 1024 * 1024


def apply_ai_profile(db, cfg, log=None) -> str:
    """把「当前启用的 AI 配置档案」覆盖到 cfg.ai 上，返回档案名（未启用返回空串）。

    ★ 为什么放在 apply_ai_opts 之后调用
      任务级的 ai_opts 里可能还留着旧版本的模型地址（加档案表之前提交的老任务）。
      现在模型连接是**平台级**配置：档案说什么就是什么。
      有冲突时写一行日志说明"任务里记的旧地址没有生效"，
      而不是悄悄按旧的跑 —— 否则使用者会以为档案没保存成功。

    ★ 未启用任何档案 = AI 关闭（provider=none）
      这是刻意的：把"没配"和"配了但连不上"分开。前者连请求都不发，
      直接走确定性策略；后者会报错并降级。混在一起就没法回答
      "AI 到底有没有参与"这个报告必须回答的问题。
    """
    if db is None:
        return ""
    try:
        pid = db.ai_active_id()
        if not pid:
            return ""
        p = db.ai_profile(pid)
    except Exception:
        return ""
    if not p:
        return ""
    ai = cfg.ai
    old = (ai.provider, ai.base_url, ai.model)
    ai.provider = (p.get("provider") or "none").strip() or "none"
    ai.base_url = (p.get("base_url") or "").strip()
    ai.model = (p.get("model") or "").strip()
    ai.vision_model = (p.get("vision_model") or "").strip()
    ai.api_key = (p.get("api_key") or "").strip()
    # ollama 的空地址＝本机默认端口。写在这里而不是让 provider 自己猜：
    # 日志与报告里要显示一个真实地址，不能是空串。
    if ai.provider == "ollama" and not ai.base_url:
        ai.base_url = "http://127.0.0.1:11434"
    name = (p.get("name") or pid).strip()
    if log and old[0] and old[0] != ai.provider:
        log("[*] AI 配置「%s」生效：%s（任务里记录的 %s 不再生效）"
            % (name, ai.provider, old[0]))
    return name


def seed_ai_profiles(db, cfg_path: Optional[str] = None) -> str:
    """首次启动时把 config.yaml 里的连接配置迁进档案表，返回新建的 id。

    ★ 为什么要迁而不是"直接删掉 config.yaml 的 ai 段"
      升级之后原来的模型服务必须还能用。迁移做一次、留痕（名字里写明来源），
      使用者就能在界面上看见它、改它、删它 —— 比"读一个看不见的文件"清楚。
      config.yaml 的 ai 段仍然保留，作为**没有档案时的兜底**（命令行裸跑、
      不经过平台服务时仍然能读到配置）。
    """
    try:
        if db.ai_profiles():
            return ""
        # ★ 必须在这里导入：server.py 顶部没有 `AppConfig`（各函数都是局部导入），
        #   写 `AppConfig.load(...)` 会抛 NameError 并被下面那个 except 吞掉，
        #   表现为"迁移没发生、也没有任何提示" —— 这个坑已经踩过一次。
        from piiscan.config import AppConfig
        p = Path(cfg_path) if cfg_path else (ROOT / "config.yaml")
        cfg = AppConfig.load(p) if p.exists() else AppConfig()
    except Exception as e:
        print("[!] AI 配置迁移失败（不影响启动，可在界面上手工添加）：%s: %s"
              % (type(e).__name__, e))
        return ""
    ai = cfg.ai
    if (ai.provider or "none").strip().lower() in ("", "none", "off", "disabled"):
        return ""
    try:
        pid = db.ai_profile_save(
            name="本机配置（升级时从 config.yaml 迁入）",
            provider=ai.provider, base_url=ai.base_url, model=ai.model,
            vision_model=ai.vision_model, api_key=ai.api_key,
            note="平台升级后自动迁移。可以在这里改地址/模型，或直接删除并新建别的。")
        db.ai_set_active(pid)
        return pid
    except Exception:
        return ""


def ai_profile_out(p: Dict[str, Any], active_id: str) -> Dict[str, Any]:
    """给前端的档案视图。**绝不回传 api_key 原文**。"""
    key = str(p.get("api_key") or "")
    prov = (p.get("provider") or "").strip().lower()
    from piiscan.ai.factory import _REGISTRY as _AI_REG
    cls = _AI_REG.get(prov)
    return {
        "id": p.get("id") or "",
        "name": p.get("name") or "",
        "provider": prov,
        "provider_label": getattr(cls, "label", prov) if cls else prov,
        "base_url": p.get("base_url") or "",
        "model": p.get("model") or "",
        "vision_model": p.get("vision_model") or "",
        "note": p.get("note") or "",
        "has_key": bool(key),
        # 只给末四位用于辨认是哪把钥匙。完整密钥不出服务端。
        "key_hint": ("…" + key[-4:]) if len(key) >= 8 else ("已保存" if key else ""),
        "vision": bool(getattr(cls, "vision", False)) if cls else False,
        "active": bool(active_id) and (p.get("id") == active_id),
        "created_at": float(p.get("created_at") or 0),
        "updated_at": float(p.get("updated_at") or 0),
        "last_used_at": float(p.get("last_used_at") or 0),
    }


# 可选的接口类型。`default_base` 用于界面上一键填好，
# 避免"选了 DeepSeek 却还要自己记域名"。
AI_PROVIDER_CATALOG = [
    {"id": "ollama", "label": "Ollama（本机 / 内网）",
     "default_base": "http://127.0.0.1:11434", "needs_key": False, "vision": True,
     "models": "qwen2.5:7b、qwen2.5vl:7b（视觉）",
     "hint": "部署在自己的机器或内网，不需要密钥；视觉模型可看截图。"},
    {"id": "deepseek", "label": "DeepSeek（云端 API）",
     "default_base": "https://api.deepseek.com", "needs_key": True, "vision": True,
     "models": "deepseek-flash（可看图）、deepseek-v4-pro（纯文本，推理更强）",
     "hint": "填 API 密钥即可用，按量计费。图片能力按模型区分："
             "deepseek-flash 支持图片输入（截图定位政策入口、AI 指挥遍历都能用）；"
             "deepseek-v4-pro 只读文本，若把文本模型设成它，视觉模型请单独填 deepseek-flash。"},
    {"id": "openai", "label": "其他 OpenAI 兼容接口（vLLM / LM Studio / 中转）",
     "default_base": "", "needs_key": True, "vision": True,
     "models": "按服务端实际部署填写",
     "hint": "任何暴露 /v1/chat/completions 的服务都能接。是否支持图片由服务端决定。"},
]


def _norm_ai_provider(raw: str) -> str:
    p = (raw or "").strip().lower()
    if p in ("ollama", "deepseek", "openai", "openai_compat", "vllm", "lmstudio", "agent"):
        return "openai" if p in ("openai_compat", "vllm", "lmstudio") else p
    raise ValueError("不支持的接口类型：%r（可选：ollama / deepseek / openai）" % (raw or ""))


def collect_ai_opts(fields: Dict[str, Any]) -> str:
    """从表单字段里收集 AI 选项，打包成 JSON 字符串。

    只有前端**真的提交了**的键才会写进去 —— 没提交的键保持 config.yaml 的配置。
    这点很重要：使用者可以在 config.yaml 里配好一套默认（比如内网模型地址），
    然后在前端只勾一个"本次用 AI 深读"，不必每次重填地址。
    """
    opts: Dict[str, Any] = {}
    for k in AI_OPT_KEYS:
        if k not in fields:
            continue
        v = fields.get(k)
        if isinstance(v, (bytes, bytearray)):
            try:
                v = v.decode("utf-8", "replace")
            except Exception:
                v = ""
        if k.startswith("ai_policy") or k == "ai_ui_agent":
            opts[k] = _as_bool(v)
        else:
            s = str(v or "").strip()
            if s:
                opts[k] = s
    return json.dumps(opts, ensure_ascii=False) if opts else ""


def apply_ai_opts(cfg, job: Dict[str, Any], log=print) -> None:
    """把任务级的 AI 选项应用到配置对象上。

    每个任务都持有自己的一份 AppConfig（_process 里单独 load），
    所以这里可以放心直接改 —— 并行跑两个任务时，一个开 AI 深检、
    另一个走纯规则，互不污染。
    """
    ai = cfg.ai
    # ★ 政策视觉 / 政策深读在任务级**固定启用**，界面上不再给勾选，前端传 0
    #   也无效。理由：这两项直接决定结论质量 ——
    #     · 政策视觉是"入口藏在正文里的可点超链接 / 政策页其实是目录页或登录墙"
    #       时唯一能救回来的手段，而它平时零成本（政策链接能直接取到时一次都不调）；
    #     · 政策深读负责声明范围与第三方共享清单追链，关掉会让"未列明第三方"
    #       这类判定失去依据，且政策换一种说法就会被误报成缺失。
    #   放在 raw 判空**之前**：旧任务、API 直传不带 ai_opts 时同样锁定。
    #   否则"固定启用"只在带参数时成立，又会出现两套口径。
    #   仍保留降级路径：模型不可用 / 中途连续失败时照旧回退确定性策略，
    #   锁定的是"用户能不能关"，不是"必须成功"。
    forced = [f for f in ("policy_vision", "policy_analyze") if not ai.feature(f)]
    ai.features["policy_vision"] = True
    ai.features["policy_analyze"] = True
    if forced:
        log("[*] 已固定启用 AI 环节：%s（任务级不可关闭，原配置为关闭）"
            % "、".join(forced))

    raw = job.get("ai_opts") or ""
    if not raw:
        _log_ai_state(ai, log, source="服务端默认配置")
        return
    try:
        opts = json.loads(raw)
    except Exception:
        _log_ai_state(ai, log, source="服务端默认配置（任务参数无法解析）")
        return
    if not isinstance(opts, dict):
        _log_ai_state(ai, log, source="服务端默认配置（任务参数格式不对）")
        return
    for key, attr in (("ai_provider", "provider"), ("ai_base_url", "base_url"),
                      ("ai_model", "model"), ("ai_vision_model", "vision_model"),
                      ("ai_api_key", "api_key")):
        if opts.get(key):
            setattr(ai, attr, str(opts[key]))
    # 注意不含 policy_vision / policy_analyze：上面已固定为 True，
    # 放在这里会让前端传来的 0 把它们重新关掉。
    for key, feat in (("ai_ui_agent", "ui_agent"),
                      ("ai_policy_parse", "policy_parse")):
        if key in opts:
            ai.features[feat] = bool(opts[key])
    # 数值型选项：转不动就忽略，不要让一个填错的输入框把整轮检测带崩
    for key, attr in (("ai_ui_agent_every", "ui_agent_every"),
                      ("ai_ui_agent_max_calls", "ui_agent_max_calls"),
                      ("ai_relay_timeout", "relay_timeout")):
        raw_v = opts.get(key)
        if raw_v in (None, ""):
            continue
        try:
            setattr(ai, attr, int(str(raw_v).strip()))
        except Exception:
            pass
    if opts.get("ai_relay_dir"):
        ai.relay_dir = str(opts["ai_relay_dir"])
    _log_ai_state(ai, log, source="任务参数")


def _log_ai_state(ai, log, source: str = "") -> None:
    """把本轮**实际生效**的 AI 环节写进日志。

    单独抽出来是为了让"界面显示的"与"实际跑的"能对上：政策视觉与政策深读
    是固定启用的，UI 遍历是可选的，三者状态必须每轮都留一行 —— 否则事后
    只能看到报告结论，看不出结论是模型读出来的还是规则碰巧命中的。
    """
    parts = ["政策视觉", "政策深读"]
    if ai.feature("ui_agent"):
        parts.append("UI 遍历")
    else:
        parts.append("UI 遍历（已关闭）")
    if (ai.provider or "none") == "none":
        log("[!] AI 环节已固定启用（%s），但未配置模型服务（ai.provider=none），"
            "本轮将全部回退到确定性策略" % "、".join(parts))
        return
    who = ("由对话里的 AI 中继作答" if (ai.provider or "").lower() in ("agent", "relay")
           else "模型 %s" % (ai.vision_model or ai.model))
    log("[*] 本任务 AI 环节：%s（%s；%s）" % ("、".join(parts), who, source))


# 视觉模型的名字特征。这不是硬判断，只是给使用者一句提示 ——
# 真正能不能处理图片要看模型本身，但名字里带这些字样的基本都对。
_VISION_NAME_HINT = re.compile(
    r"(^|[^a-z])vl([^a-z]|$)|vision|visual|llava|gpt-4o|gpt-4\.1|claude|gemini"
    r"|glm-4v|internvl|minicpm-v|step-1v|yi-vl|qwen2-vl|qwen2\.5-vl|gemma3",
    re.I)


def _vision_hint(name: str) -> str:
    n = (name or "").strip()
    if not n:
        return "未指定视觉模型"
    if _VISION_NAME_HINT.search(n):
        return "「%s」看起来支持图片输入 ✓" % n
    return ("「%s」可能不支持图片输入 —— 视觉环节（截图定位政策入口、AI 指挥遍历）"
            "会自动回退到规则策略。若要用这些能力，请换成多模态模型"
            "（如 qwen2.5vl:7b / llava）。" % n)


def _ollama_probe(ai, model: str, timeout: float = 6.0) -> Dict[str, Any]:
    """核对「这个模型到底部署了没有」并读出真实 num_ctx / capabilities。

    ★ 唯一实现在 `piiscan/ai/providers.py::OllamaProvider.show()`，
      这里只是给 HTTP 层一个不抛异常的入口（探测失败不该让接口崩）。
      不在两处各写一套，是因为它们将来会各自漂移 —— 那类问题排查起来极费时间。
    """
    try:
        from piiscan.ai.providers import OllamaProvider
        return OllamaProvider(ai).show(model, timeout=timeout)
    except Exception as e:
        return {"ok": False, "exists": False, "num_ctx": 0,
                "capabilities": [], "error": "探测模型失败：%s" % e}


def _ollama_loaded(ai, timeout: float = 3.0) -> Optional[List[str]]:
    """`/api/ps`：已加载进内存的模型；拿不到返回 None（与"空"区分）。唯一实现同上。"""
    try:
        from piiscan.ai.providers import OllamaProvider
        return OllamaProvider(ai).loaded(timeout=timeout)
    except Exception:
        return None


def _list_models(ai) -> list:
    """尽力列出服务端已有的模型名；拿不到就返回空列表，不影响可达性判断。"""
    import urllib.request
    base = (ai.base_url or "").rstrip("/")
    urls = []
    if (ai.provider or "").lower() == "ollama":
        urls.append(base + "/api/tags")
    else:
        urls.append(base + "/models" if base.endswith("/v1") else base + "/v1/models")
    urls.append(base + "/api/tags")
    for u in urls:
        try:
            req = urllib.request.Request(u)
            if getattr(ai, "api_key", ""):
                req.add_header("Authorization", "Bearer " + ai.api_key)
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            continue
        if isinstance(data, dict):
            if isinstance(data.get("models"), list):        # Ollama
                return [str(m.get("name") or m.get("model") or "")
                        for m in data["models"] if isinstance(m, dict)]
            if isinstance(data.get("data"), list):          # OpenAI 兼容
                return [str(m.get("id") or "")
                        for m in data["data"] if isinstance(m, dict)]
    return []


# ============================================================================
#  multipart 流式解析（标准库 cgi 已在 3.13 移除，这里自行实现）
# ============================================================================

class _Body:
    """带缓冲的请求体读取器，支持 readline 与流式 read_until。"""

    def __init__(self, rfile, length: int):
        self.rfile = rfile
        self.left = max(0, int(length))
        self.buf = b""

    def _fill(self, n: int = 262144) -> bool:
        if self.left <= 0:
            return False
        chunk = self.rfile.read(min(n, self.left))
        if not chunk:
            self.left = 0
            return False
        self.left -= len(chunk)
        self.buf += chunk
        return True

    def readline(self) -> bytes:
        while b"\r\n" not in self.buf and self.left > 0:
            if not self._fill(65536):
                break
        i = self.buf.find(b"\r\n")
        if i < 0:
            line, self.buf = self.buf, b""
            return line
        line, self.buf = self.buf[:i], self.buf[i + 2:]
        return line

    @property
    def eof(self) -> bool:
        """readline 返回空串时，用它区分「空行」与「流已结束」。"""
        return not self.buf and self.left <= 0

    def read_until(self, delim: bytes, sink) -> bool:
        while True:
            i = self.buf.find(delim)
            if i >= 0:
                sink(self.buf[:i])
                self.buf = self.buf[i + len(delim):]
                return True
            keep = len(delim) - 1
            if len(self.buf) > keep:
                sink(self.buf[:-keep])
                self.buf = self.buf[-keep:]
            if not self._fill():
                sink(self.buf)
                self.buf = b""
                return False


def parse_multipart(rfile, content_type: str, content_length: int,
                    save_dir: Path, max_bytes: int) -> Dict[str, Any]:
    """返回 {字段名: 值}；文件字段值为 {'filename','path','size'}。"""
    m = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not m:
        raise ValueError("请求缺少 multipart boundary")
    delim = b"--" + m.group(1).encode("latin-1")
    body = _Body(rfile, content_length)
    save_dir.mkdir(parents=True, exist_ok=True)
    fields: Dict[str, Any] = {}

    # 跳过前导内容直到第一个分隔行
    while True:
        line = body.readline()
        if line.startswith(delim):
            break
        if not line and body.eof:
            return fields

    while True:
        # ---- 解析分段头部 ----
        headers: Dict[str, str] = {}
        while True:
            line = body.readline()
            if not line:
                if body.eof:
                    return fields
                break          # 空行：分段头部结束（区分于 EOF）
            if not line.strip():
                break
            k, _, v = line.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()

        disp = headers.get("content-disposition", "")
        name_m = re.search(r'name="([^"]*)"', disp)
        file_m = re.search(r'filename="([^"]*)"', disp)
        field = name_m.group(1) if name_m else ""

        # ---- 读取内容直到下一个 boundary ----
        if file_m:
            fname = os.path.basename(file_m.group(1)) or "upload.apk"
            # 落盘统一用 ASCII 名：中文/空格文件名经命令行传给 adb 时会被编码破坏，
            # 导致 `adb install` 静默失败（stderr 为空）。原始名保留在 filename 字段里给界面展示。
            ext = os.path.splitext(fname)[1].lower()
            if ext not in (".apk", ".apks", ".xapk", ".zip"):
                ext = ".apk"
            dest = save_dir / ("upload_%d%s" % (int(time.time() * 1000), ext))
            written = {"n": 0}
            fh = open(dest, "wb")

            def sink(chunk: bytes, _fh=fh, _w=written):
                if not chunk:
                    return
                _w["n"] += len(chunk)
                if _w["n"] > max_bytes:
                    raise ValueError("上传文件超过大小上限")
                _fh.write(chunk)

            try:
                body.read_until(b"\r\n" + delim, sink)
            finally:
                fh.close()
            fields[field or "file"] = {
                "filename": fname, "path": str(dest), "size": written["n"],
            }
        else:
            chunks: list = []
            body.read_until(b"\r\n" + delim, chunks.append)
            raw = b"".join(chunks)
            try:
                fields[field] = raw.decode("utf-8")
            except UnicodeDecodeError:
                fields[field] = raw.decode("gbk", errors="replace")

        # ---- 判断是否结束 ----
        # read_until 已消费掉 "\r\n" + delim，缓冲区里剩下的是
        #   "\r\n"     → 还有下一个分段
        #   "--\r\n"   → 结束标记
        tail = body.readline()
        if tail.startswith(b"--"):
            break
        if body.eof:
            break

    return fields


# ============================================================================
#  后台执行器
# ============================================================================

class Worker(threading.Thread):
    """单线程顺序执行任务 —— 动态采集需要独占设备，串行更稳。

    ★ "单线程"只保证**一个进程内**串行。跨进程要靠两道锁：
      工作目录锁（`serve()` 里拿）挡住重复启动的服务；
      设备锁（`_lease_device()` 里拿）挡住"不同工作目录 → 同一台手机"。
      起因见 `piiscan/runlock.py` 头部：Windows 上两个服务能同时绑 8760，
      两个 Worker 各自取任务，两个 App 就同时跑在一台手机上了。
    """

    # 一个任务结束后、取下一个之前的冷却时间。卸载/停止 frida 之后
    # adb 通道和 uiautomator 残留还需要一两秒才散干净，紧接着安装下一个
    # App 会偶发 `INSTALL_FAILED_UPDATE_INCOMPATIBLE` 或首屏判重失准。
    SETTLE_S = 3.0
    # 等设备回到 `device` 状态的上限。超过就写警告继续（不把任务判死：
    # 设备偶尔掉线是人为插拔，等下去比直接失败更有价值）。
    SETTLE_TIMEOUT_S = 180.0
    SETTLE_POLL_S = 2.0

    def __init__(self, db: JobDB, workdir: Path, static_root: Optional[Path] = None,
                 device_enabled: bool = False, device_key: str = "auto"):
        super().__init__(daemon=True, name="piiscan-worker")
        self.db = db
        self.workdir = workdir
        self.static_root = static_root or ROOT
        self.stop_flag = threading.Event()
        # 只有真的接了设备才需要设备锁；服务器部署（--no-device）不占锁，
        # 否则会把本机的检测任务无谓地串起来。
        self.device_enabled = bool(device_enabled)
        self.device_key = (device_key or "auto").strip() or "auto"
        # 当前正在跑的任务与所用设备。前端"测试机"下拉框靠这两个字段显示"占用中/空闲"，
        # 也是 `_lease_device` 之外第二处能判断"这台机现在归谁"的地方。
        self.current_job = ""
        self.current_serial = ""
        # 当前任务的包名（`run_job` 静态分析后回填）。看门狗强制停止时要用它
        # 执行 `am force-stop` —— 卡死的进程只能靠杀进程解开。
        self.current_pkg = ""
        self._forced: Dict[str, str] = {}
        self._forced_lock = threading.Lock()

    def stop(self):
        self.stop_flag.set()
        # 关服务时也把正在进行的 AI 请求打断：否则一次 90/180 秒的调用
        # 会让退出流程干等（用户看到的是"关不掉"）。
        try:
            from piiscan.ai import cancel as _ai_cancel
            _ai_cancel.arm("服务正在停止")
        except Exception:
            pass

    # ---------------------------------------------------------- 取消 AI 调用
    def request_cancel(self, job_id: str, reason: str = "用户请求停止") -> bool:
        """把「停止」立刻送到 AI 调用那一层（2026-11-12）。

        ★ 为什么不能只靠 `should_stop()`
          它只在两次 AI 调用之间被检查，而单次调用最长可占 180 秒
          （视觉），分段抽取还会并发 4 路、失败再重试一次。用户点了停止，
          线程却停在 `urlopen` 里 —— 界面上就是"点了没反应"。
          这里直接置位取消令牌，`_post_json` 以 0.25 秒粒度轮询，随即抛错，
          采集线程马上回到检查点。

        ★ 只在该任务确实是"当前任务"时才置位
          否则会误伤：队列里排着 A、B 两条，A 跑完刚要开始 B，
          此时对 A 的迟到取消如果无条件置位，B 一开局就被判为已停止。
        """
        if not job_id or job_id != getattr(self, "current_job", ""):
            return False
        try:
            from piiscan.ai import cancel as _ai_cancel
            _ai_cancel.arm(reason)
            return True
        except Exception:
            return False

    # ---------------------------------------------------------- 强制停止
    def force_stop(self, job_id: str, reason: str) -> None:
        """把"停止"变成真的能停下（看门狗在卡死 / 取消不生效时调用）。

        ★ 为什么还需要这一层（2026-11-11 实测）
          frida 的同步 RPC 在目标进程冻住时**永远不返回**：`kill -STOP` 之后
          `exports_sync.ping()` 12 秒仍在等，`kill -CONT` 才立刻返回。
          于是采集线程回不到任何 `should_stop()` 检查点 —— 用户点了两次停止、
          看板写着"进度停滞"，程序里却什么都没发生（真机事故：95 分钟零日志，
          最后只能关掉服务）。

        ★ 三件事缺一不可
          1. 立标记：线程一旦回到检查点就收工；
          2. 异步 detach：**不能同步调**，冻结状态下 detach 自己也会卡住（实测）；
          3. `am force-stop` 被测应用：实测这是唯一能解开冻结 RPC 的手段
             —— 杀进程后 0.7 秒内抛 `script has been destroyed`。
        """
        with self._forced_lock:
            self._forced[job_id] = reason
        # 强制收工也意味着"这一轮的 AI 结果没用了"：先打断在途请求，
        # 否则 force-stop 之后线程可能还挂在模型调用上，白等一个超时。
        try:
            from piiscan.ai import cancel as _ai_cancel
            _ai_cancel.arm(reason)
        except Exception:
            pass
        pkg = (self.current_pkg or "").strip()
        serial = (self.current_serial or "").strip()
        try:
            self.db.append_log(
                job_id,
                "[!] %s；正在强制收工（停止被测应用、断开注入会话）。"
                "已采到的数据会保留。" % reason, live=False)
        except Exception:
            pass
        if pkg and serial:
            threading.Thread(target=self._force_stop_app,
                             args=(serial, pkg, job_id), daemon=True,
                             name="piiscan-force-stop").start()
        try:
            from piiscan import frida_guard
            n = frida_guard.detach_all_async()
            if n:
                print("[worker] 强制停止：已请求断开 %d 个注入会话" % n)
        except Exception:
            pass

    def _force_stop_app(self, serial: str, pkg: str, job_id: str) -> None:
        try:
            p = subprocess.run(_adb_base(serial)
                               + ["shell", "am", "force-stop", pkg],
                               capture_output=True, timeout=25)
            blob = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
            if p.returncode == 0 and "Error" not in blob:
                self.db.append_log(
                    job_id,
                    "[!] 已强制停止被测应用（%s）：卡住的注入调用会立即报错并解开"
                    % pkg, live=False)
            else:
                self.db.append_log(
                    job_id, "[!] 强制停止被测应用失败（%s）：%s"
                    % (pkg, blob.strip()[:120] or "adb 返回 %s" % p.returncode),
                    live=False)
        except Exception as e:
            try:
                self.db.append_log(job_id, "[!] 强制停止被测应用异常：%s" % e,
                                   live=False)
            except Exception:
                pass

    def is_forced(self, job_id: str) -> bool:
        with self._forced_lock:
            return job_id in self._forced

    def forced_reason(self, job_id: str) -> str:
        with self._forced_lock:
            return self._forced.get(job_id, "")

    def clear_forced(self, job_id: str) -> None:
        with self._forced_lock:
            self._forced.pop(job_id, None)

    def run(self):
        while not self.stop_flag.is_set():
            try:
                job = self.db.next_queued()
            except Exception:
                time.sleep(2)
                continue
            if not job:
                time.sleep(1.0)
                continue
            lease = None
            serial = self._serial_of(job)
            try:
                lease = self._lease_device(job, serial)
                if lease is None and self.device_enabled:
                    # 只会在"等设备的过程中服务被停止"时发生。任务还没开始，
                    # 退回队列而不是留成 running —— 否则下次启动 cleanup_stale
                    # 会把它标成"服务重启导致中断"，白记一次失败。
                    self.db.update(job["id"], status="queued", started_at=None, req="")
                    break
                self.current_job = job["id"]
                self.current_serial = "" if serial in ("", "auto") else serial
                # 新任务开局先复位取消令牌：上一条任务的"停止"不能连坐到这一条。
                try:
                    from piiscan.ai import cancel as _ai_cancel
                    _ai_cancel.disarm()
                except Exception:
                    pass
                self._process(job)
            except Exception as e:
                self.db.update(job["id"], status="failed", finished_at=time.time(),
                               error="%s: %s" % (type(e).__name__, e))
                self.db.append_log(job["id"], "[!] 任务异常终止：%s" % e)
                self.db.append_log(job["id"], traceback.format_exc()[-2000:])
            finally:
                # ★ 先收尾、后放锁。顺序反了（先 release 再 settle）时，
                #   另一个实例会立刻拿到设备锁开始装包，而本实例还在冷却/
                #   等 adb 就绪 —— 两台 App 就会在这几秒里撞上。
                #   "测完一个彻底收尾了再开始下一个"必须包含冷却在内。
                try:
                    self._settle(job["id"], self.current_serial or serial)
                except Exception:
                    pass
                if lease is not None:
                    lease.release()
                self.current_job = ""
                self.current_serial = ""
                # 任务结束（正常/停止/失败）后一定复位：取消令牌是全局的，
                # 残留的置位会让下一个任务连第一次 AI 调用都发不出去。
                try:
                    from piiscan.ai import cancel as _ai_cancel
                    _ai_cancel.disarm()
                except Exception:
                    pass

    # ------------------------------------------------------------ 串行保障
    def _serial_of(self, job: Dict[str, Any]) -> str:
        """这个任务该在哪台机上跑。

        任务行里写了就用它（建任务时用户在界面上选定，写进库）；
        没写就回落到 config.yaml 的 `device.serial`，再没有就是 `auto`
        （只有一台在线时用它，多台时由自检明确拒绝 —— 不替用户猜）。
        """
        s = str(job.get("device") or "").strip()
        return s or self.device_key

    def _lease_device(self, job: Dict[str, Any], serial: str = ""):
        """取得检测设备的独占权，拿不到就一直等（等说明上一位还没收尾完）。

        为什么等而不是排队重投：任务已被 `next_queued` 置为 running，
        退回 queued 会让它在"队列里第几个"这件事上反复跳动，
        日志和报告时间线都会乱。原地等，语义最清楚 ——
        「轮到你之前，别人还没跑完」。
        """
        if not self.device_enabled:
            return None
        from piiscan import runlock

        job_id = job["id"]
        # ★ 锁按**这一台**手机加，不按"配置里的那台"。
        #   接了两台机之后，"device-<序列号>.lock" 才是正确的互斥粒度：
        #   两个任务指定不同的机器本就该能分别排队，而两台服务实例
        #   同时选同一台时才必须互相挡住。
        key = (serial or self.device_key or "auto").strip()
        lock = runlock.FileLock(
            runlock.device_lock_path(key),
            {"pid": os.getpid(), "job": job_id,
             "workdir": str(self.workdir.resolve()),
             # 记下是哪台机，前端"测试机"下拉框要靠它显示"占用中"
             "device": key})

        def on_wait(elapsed: float) -> None:
            # 2 秒轮询一次（设备一放锁就能立刻接上），但日志每 30 秒才写一条：
            # 等 40 分钟的任务如果每 2 秒写一行，日志表会被灌满，真正有用的
            # 采集日志全被挤到看不见。
            if elapsed - last_note["t"] < 30:
                return
            last_note["t"] = elapsed
            holder = runlock.read_holder(lock)
            try:
                self.db.update(job_id, stage="等待设备（另一任务在跑）", progress=1)
                self.db.append_log(
                    job_id,
                    "[=] 检测设备正被另一个任务占用（%s）；本任务已等待 %d 秒。"
                    "一台手机同时只能跑一个 App，等它彻底收尾后再开始。"
                    % (runlock.describe_holder(holder, lock), int(elapsed)))
            except Exception:
                pass

        last_note = {"t": -1e9}
        if not lock.acquire_wait(0, poll_s=2.0, on_wait=on_wait,
                                 should_stop=lambda: self.stop_flag.is_set()):
            return None
        try:
            self.db.append_log(
                job_id,
                "[=] 已取得检测设备独占权（%s；本机同时只跑一个任务）"
                % ("自动选择" if key == "auto" else "设备 " + key))
        except Exception:
            pass
        return lock

    def _adb_state(self, serial: str = "") -> str:
        """`adb get-state` 的原文（device / offline / unknown / 报错）。

        ★ stdout 优先、stderr 只兜底（与 `uiwalk.device_state` 同一口径）。
          adb server 刚被拉起时，stdout 是干净的 `device`，stderr 会多出
          `* daemon not running; starting now at tcp:5037` 两行；两者一拼，
          `"device" != "device\n* daemon…"` —— 设备明明在线，收尾闸门却判定
          "未就绪"并一路等到 180 秒超时。
        """
        serial = "" if (serial or self.device_key) in ("", "auto") else (serial or self.device_key)
        try:
            from piiscan.teardown import _adb_args
            p = subprocess.run(_adb_args(serial) + ["get-state"],
                               capture_output=True, timeout=20)
            txt = (p.stdout or b"").decode("utf-8", "replace").strip()
            if not txt:
                txt = (p.stderr or b"").decode("utf-8", "replace").strip()
            return txt or "(空)"
        except Exception as e:  # noqa: BLE001
            return "adb 调用失败：%s" % e

    def _settle(self, job_id: str, serial: str = "") -> None:
        """一个任务彻底收尾之后再放行下一个。

        收尾卸载在 `sop_job` 内部完成（`teardown.uninstall`），这里补的是
        **卸载之后设备能不能马上接受下一次安装**：
          1. 冷却 `SETTLE_S` 秒，让 frida 会话、uiautomator、adb shell 退出；
          2. 轮询 `adb get-state`，等到 `device` 为止（掉线时等满上限并告警）。
        没有这两步时，队列里连着的两个任务会互相打架，而现象是
        "第二个 App 首屏截图是上一个 App 的界面" —— 看起来像遍历器出错。
        """
        if not self.device_enabled:
            return
        # 不知道是哪台机时就别干等：多台在线时 `adb get-state` 会报
        # "more than one device"，等满 SETTLE_TIMEOUT_S 也等不出结果（2026-11-10）。
        if (serial or "") in ("", "auto"):
            try:
                on = [d for d in list_test_devices(getattr(self, "worker", None))
                      if d["state"] == "device"]
            except Exception:
                on = []
            if len(on) == 1:
                serial = on[0]["serial"]
            elif len(on) > 1:
                try:
                    self.db.append_log(
                        job_id, "[!] 本任务未记录所用序列号，而当前有 %d 台设备在线，"
                                "无法判断该等哪一台，跳过收尾等待；下一轮任务开始前会重新自检"
                        % len(on))
                except Exception:
                    pass
                return
        if self.SETTLE_S > 0:
            time.sleep(self.SETTLE_S)
        t0 = time.time()
        state = self._adb_state(serial)
        # adb 命令本身跑不起来（没装 / 不在 PATH）时等下去毫无意义：
        # 等 180 秒再放行，只会让队列白等。直接告警放行，让下一个任务去暴露真实错误。
        if state.startswith("adb 调用失败"):
            try:
                self.db.append_log(
                    job_id, "[!] 收尾时无法执行 adb（%s）；跳过设备等待，"
                            "直接继续队列。下一轮安装若失败，原因会是同一件事。" % state)
            except Exception:
                pass
            return
        last_note = 0.0
        # 不是 device 时先让 adb 层自己修一次（reconnect / 必要时重启 server），
        # 再进下面的干等循环。只靠 `get-state` 轮询的话，遇到"必须 reconnect
        # 才回来"的情况会白等满 180 秒；而 2026-10-26 实测 USB 偶发重新枚举时
        # 设备是 2 秒左右自愈的 —— 能等到的就不该让它等到超时。
        if state != "device":
            # ★ 等待必须**计入收尾闸门的总预算**，不能另开一份。
            #   否则 SETTLE_TIMEOUT_S 承诺的"到上限就放行"会被这条前置等待
            #   拖长（实测：上限 0.6 秒的用例跑成 30.9 秒）。
            _budget = max(0.0, float(self.SETTLE_TIMEOUT_S) - (time.time() - t0))

            def _say(s: str) -> None:
                try:
                    self.db.append_log(job_id, s)
                except Exception:
                    pass
            if _budget > 0.2:
                try:
                    from piiscan import uiwalk as _UW
                    _sn = "" if (serial or self.device_key) in ("", "auto") else (serial or self.device_key)
                    _okd, _note = _UW.ensure_device(
                        _sn, wait_s=min(30.0, _budget), log=_say)
                    if _okd:
                        state = "device"
                except Exception:
                    pass
        while state != "device" and time.time() - t0 < self.SETTLE_TIMEOUT_S:
            if self.stop_flag.is_set():
                return
            if time.time() - last_note >= 15:
                last_note = time.time()
                try:
                    self.db.append_log(
                        job_id, "[!] 收尾后设备未就绪（adb get-state → %s），"
                                "继续等待（已等 %d 秒）" % (state, int(time.time() - t0)))
                except Exception:
                    pass
            time.sleep(self.SETTLE_POLL_S)
            state = self._adb_state(serial)
        try:
            if state == "device":
                self.db.append_log(
                    job_id, "[=] 收尾完成，设备已就绪（耗时 %.1f 秒）；"
                            "队列继续，开始下一个任务" % (time.time() - t0))
            else:
                self.db.append_log(
                    job_id, "[!] 收尾后等设备超时（%d 秒，最后状态：%s）；"
                            "仍会继续取下一个任务，若下一轮首屏异常请检查设备连接"
                            % (int(time.time() - t0), state))
        except Exception:
            pass

    # ------------------------------------------------------------ 单任务
    def _process(self, job: Dict[str, Any]):
        """执行一个任务。

        ★ 一律走 piiscan.sop_job —— 与命令行同一条链。
          此前这里调的是 piiscan/pipeline.py 的旧流水线：报告模板不同、
          结尾不卸载应用、结论口径也不同。同一个 APK 在平台和命令行
          会得到两份不一样的报告，而使用者只会以为"平台就是这结果"。
        """
        from piiscan.config import AppConfig
        from piiscan.sop_job import JobOptions, run_job

        job_id = job["id"]
        # ★ 重读一次最新行。`next_queued()` 返回的是「发现它的那一刻」的快照，
        #   而上传模式下 create() 先把任务置为 queued、随后才补 apk_path。
        #   worker 若正好在这两步之间醒来，拿到的就是 apk_path 为空的快照 ——
        #   实测撞过一次：APK 明明传上来了，任务却报「取不到目标包名」直接失败。
        #   重新读一行成本可忽略，却能根治这一整类「字段还没写完就被取走」的问题。
        latest = self.db.get(job_id)
        if latest:
            job = latest
        wd = self.workdir / job_id
        wd.mkdir(parents=True, exist_ok=True)
        # 新任务从干净的强制停止状态开始：上一次的 reason 若留在这里，
        # 这一轮会在第一个检查点就"被停止"，看起来像任务自己无故中止。
        self.clear_forced(job_id)
        self.current_pkg = ""
        self.db.update(job_id, status="running", started_at=time.time(),
                       stage="启动中", progress=1, workdir=str(wd))

        def log(line: str):
            self.db.append_log(job_id, line)

        def on_stage(name: str, pct: int):
            self.db.update(job_id, stage=name, progress=max(0, min(99, int(pct))))

        # ---- 取消/暂停：轮询请求信箱 ----
        # 采集循环里会高频调用它，直接查库会把 SQLite 打成热表；
        # 加一层 0.5 秒缓存，既够快又不会漏掉请求。
        _cache = {"at": 0.0, "req": ""}

        def should_stop() -> bool:
            now = time.time()
            if now - _cache["at"] > 0.5:
                try:
                    _cache["req"] = self.db.take_request(job_id)
                except Exception:
                    _cache["req"] = ""
                _cache["at"] = now
            # 看门狗的强制停止与库里的 req 是两回事：前者用于"req 送不进去"
            # 的场景（线程卡在 frida 里，连 0.5 秒一次的读库都轮不到）。
            return bool(_cache["req"]) or self.is_forced(job_id)

        cfg = AppConfig()
        cfg_path = ROOT / "config.yaml"
        if cfg_path.exists():
            try:
                cfg = AppConfig.load(cfg_path)
            except Exception:
                pass

        # ---- 任务级设备选择 ----
        # ★ 必须在 run_job 之前落到 cfg.device.serial：整条链（自检、安装、
        #   frida.get_device、uiautomator、卸载）都只认这一个字段。放到这里
        #   而不是各调用点分别传参，是因为漏传任何一处都会变成"装在这台、
        #   截在那台"—— 而这种错误在报告里看不出来。
        want_dev = str(job.get("device") or "").strip()
        if want_dev:
            if getattr(cfg, "device", None) is None:
                from piiscan.config import DeviceConfig
                cfg.device = DeviceConfig()
            cfg.device.serial = want_dev
            log("[*] 本次指定测试机：%s" % want_dev)
        else:
            # 2026-11-11 起，新提交的动态任务必须在界面上选机（HTTP 入口已强制），
            # 走到这里只可能是**老任务**（那时 device 还没进库）。这条兜底保留，
            # 但日志要说清是"历史任务"，别让人以为是平台又在替人挑。
            log("[*] 这条任务没有记录测试机（多为加字段前的历史任务），"
                "沿用 config.yaml 的 device.serial=%s；新任务请在「测试机」里选一台"
                % ((getattr(getattr(cfg, "device", None), "serial", "") or "auto")))

        # AI 增强：任务级选项覆盖 config.yaml 的默认值。
        # 必须在 run_job 之前应用 —— 采集端的 AI 环节按 cfg.ai 判断要不要启用。
        apply_ai_opts(cfg, job, log)

        # ★ 再套一层「平台级 AI 配置档案」，它优先级最高（2026-11-12）。
        #   模型服务地址/模型名/密钥不再是每个任务各填一份：那不是任务参数，
        #   而是这台机器的环境。放在任务级选项之后，是为了让"界面上改了档案、
        #   老任务却还按旧地址跑"这种事不可能发生。
        _ai_profile = ""
        try:
            _ai_profile = apply_ai_profile(self.db, cfg, log)
            if _ai_profile:
                log("[*] 使用 AI 配置：%s" % _ai_profile)
        except Exception as e:
            log("[!] 应用 AI 配置失败（沿用配置文件的默认值）：%s" % e)

        # AI 实例由这里构造后整条链共用：中继模式下只会产生一个会话目录。
        ai_tasks = None
        ai = None
        try:
            from piiscan.ai import build_tasks_safe
            from piiscan.ai.factory import build_ai_safe
            ai_tasks = build_tasks_safe(cfg.ai, log)
            ai = ai_tasks.ai if ai_tasks is not None else build_ai_safe(cfg.ai)
            log("[*] 模型通道：%s" % ai.describe())
        except Exception as e:
            log("[!] 模型通道初始化失败，改用纯规则策略：%s" % e)

        opts = JobOptions(
            package="",
            apk_path=job.get("apk_path") or "",
            dynamic=bool(job.get("run_dynamic", 1)),
            duration=int(job.get("duration") or 90),
            policy_wait=int(job.get("policy_wait") or 22),
            reset_app=bool(job.get("reset_app", 1)),
            keep_app=False,          # 平台任务一律测完卸载（用户明确要求）
            mode="expert",
            policy_url=job.get("policy_url") or "",
            policy_text=job.get("policy_text") or "",
            # 登录辅助：手机号建任务时就定下来（遍历中途不能再改，
            # 否则报告里"用的是哪个号"会说不清）。
            login_phone=str(job.get("login_phone") or ""),
            login_timeout=int(job.get("login_timeout") or 180),
            # 发现问题后清数据重跑一轮做复现。默认开：不复现就只能给"疑似"，
            # 而平台的主要用途是出可认定的结论。
            do_repro=bool(job.get("repro", 1)),
            depth=str(job.get("depth") or "normal"),
        )

        # ---- 应用商店链接：先解析出直链，再下载 ----
        # 这一步失败时任务标记为「已跳过」而不是「失败」：批量提交时两者的含义
        # 完全不同 —— 失败是"测了，有问题"，跳过是"根本没测"。混在一起，
        # 用户看到"8 个任务 3 个失败"会以为那 3 个 App 有问题。
        if not opts.apk_path and job.get("store_url"):
            if not self._fetch_from_store(job, opts, log, should_stop):
                return

        # ---- 链接模式的 APK 要在开跑前先下下来 ----
        # 下载失败必须让任务失败并写清原因：若放行，静态分析会以"无 APK"跳过，
        # 最后给出一份"跳过未测 22 项"的报告，看起来像检测过了。
        if not opts.apk_path and job.get("apk_url"):
            self.db.update(job_id, stage="下载 APK", progress=2)
            log("[*] 下载 APK：%s" % job["apk_url"])
            try:
                from piiscan import apkfetch, apkstore
                # 下到存储目录的 .incoming：与正式目录同盘，收进去只是改名。
                _incoming = apkstore.incoming_dir(apk_store_root(self.db, self.workdir))
                fr = apkfetch.fetch_url(job["apk_url"], _incoming, log=log)
            except Exception as e:
                fr = None
                log("[!] 下载异常：%s" % e)
            if fr is None or not fr.ok:
                msg = "APK 下载失败：%s" % ((fr.error if fr else "异常") or "未知原因")
                self.db.update(job_id, status="failed", finished_at=time.time(),
                               error=msg, progress=100, stage="失败", req="")
                log("[!] %s" % msg)
                return
            try:
                _apk, _rt = apk_store_adopt(self.db, self.workdir, fr.path, fr.filename, fr.sha256, log=log)
            except Exception as e:
                msg = "APK 归档失败：%s" % e
                self.db.update(job_id, status="failed", finished_at=time.time(),
                               error=msg, progress=100, stage="失败", req="")
                log("[!] %s" % msg)
                return
            opts.apk_path = _apk
            self.db.update(job_id, apk_path=_apk, apk_store=_rt,
                           apk_name=fr.original_name or fr.filename,
                           apk_size=fr.size, md5=fr.md5, sha256=fr.sha256)
            log("[*] 已下载：%s（%.1f MB）" % (fr.filename, fr.size / 1048576.0))

        log("[*] 任务 %s 开始执行" % job_id)
        try:
            res = run_job(job_id, wd, opts, cfg, log=log,
                          on_stage=on_stage, should_stop=should_stop,
                          ai_tasks=ai_tasks, ai=ai,
                          # 包名一早交给看门狗：卡死时它要 `am force-stop` 这个包
                          on_package=lambda p: setattr(self, "current_pkg", p))
            # 把**实际用上的**序列号记下来：收尾/_settle 要按它去查 adb 状态。
            # 任务没指定机器（auto）时，这里才第一次知道究竟是哪一台。
            try:
                if getattr(res, "device_serial", ""):
                    self.current_serial = res.device_serial
                    # 这一轮真的在这台机上跑过（能起 frida-server 并装上 hook），
                    # 这就是"已 root"的实证，记下来让设备卡不必再靠轮询去 su。
                    # ★ 只有"这次真的碰了设备"才算：纯离线重渲染也带着存档里的
                    #   serial，但它没连过任何手机，写成已 root 等于凭空断言。
                    _touched = (bool(getattr(opts, "dynamic", False))
                                and not getattr(opts, "scan_result_path", ""))
                    if getattr(res, "ok", False) and _touched:
                        mark_root_verified(res.device_serial)
            except Exception:
                pass
            # "这套 AI 配置真的被用过"才更新 last_used_at：
            # 只是被选中不算，一次调用都没发生就更不算 —— 否则界面上会写着
            # "上次使用：今天"，而实际上一次都没发出去（比如全走确定性策略）。
            try:
                _prov = getattr(ai, "ai", ai)
                if (_ai_profile and _prov is not None
                        and int((_prov.call_stats() or {}).get("total") or 0) > 0):
                    self.db.ai_touch(self.db.ai_active_id())
            except Exception:
                pass
        except Exception as e:
            # 强制停止引起的异常（典型：杀进程后 frida 抛 script has been destroyed）
            # 不是"检测失败"，必须按"已停止"记账 —— 否则用户点了停止，
            # 任务却显示"失败"，下次看报告会以为这个 App 有问题。
            _fr = self.forced_reason(job_id)
            if _fr:
                self.db.update(job_id, status="canceled", stage="已停止",
                               progress=100, finished_at=time.time(),
                               error="%s（线程被强制收工：%s: %s）"
                                     % (_fr, type(e).__name__, str(e)[:160]), req="")
                log("[!] %s；线程在异常中强制收工：%s: %s"
                    % (_fr, type(e).__name__, str(e)[:200]))
                return
            self.db.update(job_id, status="failed", finished_at=time.time(),
                           error="%s: %s" % (type(e).__name__, e), progress=100,
                           stage="失败")
            log("[!] 任务异常终止：%s" % e)
            log(traceback.format_exc()[-2000:])
            return

        # ---- 落地最终状态 ----
        # 看门狗强制停止过、而这一轮又没跑出可用结果 → 按"已停止"记，
        # 不按"失败"记。用户点的是停止，不是"这个 App 有问题"。
        # 反过来，若结果已经完整（ok=True），强制停止来得太晚了，保留结果。
        _forced = self.forced_reason(job_id)
        if _forced and not res.ok:
            res.canceled = True
            res.error = res.error or _forced
        req = self.db.take_request(job_id) or ""
        base = dict(finished_at=time.time(), progress=100,
                    package=res.package or "",
                    app_label=res.app_name or "",
                    version_name=res.version or "",
                    report_path=res.report_path or "",
                    result_path=res.flow_path or "",
                    scan_path=res.scan_path or "")

        if res.canceled:
            # 被要求停止 → canceled；被要求暂停 → paused（恢复后重跑）
            target = "paused" if req == "pause" else "canceled"
            label = "已暂停" if target == "paused" else "已停止"
            note = ("已暂停（采集过程不可续，恢复后将重新执行本轮）"
                    if target == "paused" else "已停止")
            if res.teardown and res.teardown.get("ok") is False:
                note += "；但卸载被测应用失败：" + (res.teardown.get("note") or "")
            self.db.update(job_id, status=target, stage=label,
                           paused_at=time.time() if target == "paused" else None,
                           error=res.error or note, req="", **base)
            log("[*] 任务%s：%s" % ("暂停" if target == "paused" else "停止", res.error))
            return

        if not res.ok:
            self.db.update(job_id, status="failed", stage="失败",
                           error=res.error or "检测失败", req="", **base)
            return

        # ---- App 压根没跑起来 → 算失败，不算"已完成" ----
        # 用户口径（2026-10-27）：国象联盟、火花思维课堂、学习通、洋葱学园这几轮
        # 22 项全「跳过未测」、截图清一色是手机桌面，却挂在「已完成」里 ——
        # 看报告的人会以为测过了。这类任务的价值只剩"启动崩溃取证"，
        # 状态必须说清楚：报告照留（崩溃原因要能复核），但任务记失败。
        if getattr(res, "run_failed", False):
            _h = getattr(res, "run_health", {}) or {}
            _why = _h.get("why") or "未取得被测应用界面内容"
            _state = str(_h.get("state") or "")
            # ★ 失败要分清是哪一种失败（2026-10-27 用户指出洋葱学园判错）：
            #   no_app        应用确实没起来（启动即崩/一直停桌面）→ 应用的问题
            #   no_ui/no_dump 应用起来了，但我们读不到界面 → 检测手段受限
            #   把后者写成"应用未能正常运行"，等于把我们的限制算到应用头上。
            if _state == "no_app":
                _stage, _head = "失败（应用未能正常运行）", "被测应用未能正常运行"
            elif _state == "no_ui":
                _stage, _head = "失败（界面无法读取）", "被测应用已启动但界面无法读取"
            elif _state == "no_dump":
                _stage, _head = "失败（界面未能导出）", "被测应用已启动但界面结构未能导出"
            else:
                _stage, _head = "失败（应用未能正常运行）", "被测应用未能正常运行"
            _probe = _h.get("app_start_probe") or {}
            if _h.get("hook_blocked"):
                if _state == "no_app" and _probe.get("started") is False:
                    # ★ 注入失败 + 应用自己也起不来（小盒课堂/爱加密）：不许写成
                    #   "注入被拦截"，那会把责任从应用挪到检测工具身上。
                    _stage = "失败（应用在本机无法启动）"
                    _head = "被测应用在本机无法启动（不注入时同样无法稳定存活）"
                else:
                    _stage = "失败（注入被加固拦截）"
                    _head = "动态检测未能开展：加固机制拦截注入"
            _cr = ""
            try:
                _crash = json.loads(Path(res.flow_path).read_text(encoding="utf-8")) \
                    .get("app_crash") or {}
                if _crash.get("found"):
                    _cr = "；崩溃信号 %s（%s）" % (_crash.get("signal") or "—",
                                                  _crash.get("signal_code") or "—")
            except Exception:
                _cr = ""
            self.db.update(
                job_id, status="failed", stage=_stage,
                error="%s：%s%s。本轮未取得可用于判定的运行期数据，"
                      "报告仅保留启动状态与相关取证，不能视为已完成检测" % (_head, _why, _cr),
                findings=0, high=0, mid=0, low=0, checked=0,
                skipped=(res.stats or {}).get("not_tested", 0), req="", **base)
            log("[!] 任务记为失败：%s（%s）" % (_head, _why))
            return

        st = res.stats or {}
        self.db.update(
            job_id, status="done", stage="完成", req="", error="",
            findings=st.get("fail", 0) + st.get("suspect", 0),
            high=st.get("fail", 0), mid=st.get("suspect", 0), low=0,
            checked=st.get("pass", 0) + st.get("fail", 0) + st.get("suspect", 0),
            skipped=st.get("not_tested", 0), **base)
        log("[+] 任务完成：发现问题 %d / 疑似 %d / 未发现问题 %d / 跳过未测 %d"
            % (st.get("fail", 0), st.get("suspect", 0),
               st.get("pass", 0), st.get("not_tested", 0)))

    # ------------------------------------------------------------ 商店链接
    def _skip(self, job_id: str, reason: str) -> None:
        """把任务标记为「已跳过」——这一条没测，且不产出报告。

        ★ 与 failed 的区别是刻意的：批量提交 20 个链接时，用户要能一眼分出
          「这些测了、有结论」和「这些压根没拿到包」。都记成 failed 的话，
          "失败 5 个"会被读成"5 个 App 有问题"。
        """
        self.db.update(job_id, status="skipped", stage="已跳过", progress=100,
                       finished_at=time.time(), error=reason, req="")
        self.db.append_log(job_id, "[!] 已跳过（未执行检测）：%s" % reason)

    def _fetch_from_store(self, job: Dict[str, Any], opts: Any,
                          log, should_stop) -> bool:
        """解析应用商店链接并把 APK 下载到共享存储。成功返回 True。"""
        from piiscan import storefetch

        url = job["store_url"]
        jid = job["id"]
        self.db.update(jid, stage="解析应用商店链接", progress=2)
        log("[*] 应用商店链接：%s" % url)

        # 下载进度映射到 2~12%：报表上的进度条此时还在最前面，
        # 但"在动"这件事必须可见 —— 一个 200MB 的包下 5 分钟，
        # 界面若一直停在"解析中"，就会被当成卡死。
        last = {"pct": -1}

        def on_progress(done: int, total: int) -> None:
            if not total:
                return
            pct = int(done * 100 / total)
            if pct >= last["pct"] + 5 or pct >= 100:
                last["pct"] = pct
                self.db.update(jid, stage="下载 APK %d%%" % pct,
                               progress=max(2, min(12, 2 + pct // 10)))

        try:
            from piiscan import apkstore
            _incoming = apkstore.incoming_dir(apk_store_root(self.db, self.workdir))
            fr = storefetch.fetch(url, _incoming, log=log,
                                  progress=on_progress, should_stop=should_stop)
        except storefetch.StoreCancelled:
            # 下载途中被要求停止：这是"用户操作"，不是失败。
            self.db.update(jid, status="canceled", stage="已停止", progress=100,
                           finished_at=time.time(), req="",
                           error="下载 APK 过程中被停止")
            log("[*] 下载过程中被停止")
            return False
        except Exception as e:  # noqa: BLE001
            log("[!] 下载异常：%s: %s" % (type(e).__name__, e))
            self._skip(jid, "APK 下载异常：%s: %s" % (type(e).__name__, e))
            return False

        if not fr.ok:
            self._skip(jid, "无法从应用商店取得 APK：%s" % (fr.error or "未知原因"))
            return False

        # 商店解析出的包名/版本作为兜底：服务器上没有 aapt 时，
        # 静态分析解析不出显示名，报告头会只剩包名。
        try:
            _apk, _rt = apk_store_adopt(self.db, self.workdir, fr.path, fr.filename, fr.sha256, log=log)
        except Exception as e:  # noqa: BLE001
            self._skip(jid, "APK 归档失败：%s" % e)
            return False
        opts.apk_path = _apk
        opts.package = fr.package or opts.package
        opts.app_name = fr.app_name or opts.app_name
        opts.version = fr.version or opts.version
        self.db.update(jid, apk_path=_apk, apk_store=_rt, apk_name=fr.filename,
                       apk_size=fr.size, sha256=fr.sha256,
                       package=fr.package or "", app_label=fr.app_name or "",
                       version_name=fr.version or "")
        log("[+] 已下载：%s（%.1f MB，来源 %s）"
            % (fr.filename, fr.size / 1048576.0, fr.market or "应用商店"))
        return True


# ============================================================================
#  APK 共享存储（建任务时的上传、worker 里的下载，两条路都走这里）
# ============================================================================
#
# 为什么放到模块级而不是某个类的方法：同一次落盘既要能从 HTTP 处理线程
# （上传）发起，也要能从 worker 线程（直链/商店下载）发起，两边各自实现一遍
# 迟早会分叉 —— 一边记 apk_store、一边忘了记，删除时的护栏就失效了。

def apk_store_root(db: Any, workdir: Path) -> Path:
    """当前生效的 APK 存储根目录（已创建）。

    配置在 `app_meta.apk_store_dir`（系统状态页可改），空则用
    `<工作目录>/apk`。建任务和跑任务都从这里取，保证"任务里记的路径"
    与"文件实际所在"永远是同一个位置。
    """
    from piiscan import apkstore
    rt = apkstore.root(db, workdir)
    try:
        apkstore.ensure(rt)
        apkstore.incoming_dir(rt).mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise ValueError("APK 存储目录不可用（%s）：%s" % (rt, e))
    return rt


def apk_store_adopt(db: Any, workdir: Path, src: str, filename: str,
                    key: str, log=None) -> Tuple[str, str]:
    """把一个刚落地的临时文件收进存储目录，返回 (绝对路径, 存储根)。

    `key` 是内容哈希（sha256 优先）：同一个包不管下几次、传几次，
    最终都落到同一个路径上，多任务共用一份文件。
    """
    from piiscan import apkstore
    rt = apk_store_root(db, workdir)
    r = apkstore.adopt(src, rt, key=key, filename=filename, log=log)
    if not r.get("ok"):
        raise ValueError("APK 归档失败：%s" % r.get("error"))
    return r["path"], str(rt)


# ============================================================================
#  在服务所在机器上弹一个目录选择框
# ============================================================================
#
# 为什么要有多个后端：早先只调 tkinter，结果使用者那台机器的 Python 是精简
# 打包的，**根本没装 tkinter**（`No module named '_tkinter'`），点一下就把
# 一整段 traceback 甩到界面上。这不是故障，是环境差异 —— 应当换条路继续走，
# 走不通就退回手填，而不是让使用者读栈。
#
# 各平台按"装得更普遍、效果更好"排列：
#   Windows  PowerShell + FolderBrowserDialog（系统自带，与 Python 无关）
#   macOS    osascript 的 choose folder（系统自带）
#   Linux    zenity / kdialog（桌面环境一般有其一）
#   兜底     tkinter（有就用，没有就跳过，连子进程都不起）
#
# 每个后端返回 (状态, 值)：状态 ok=选好了、cancel=使用者取消、fail=这条走不通。

_PICK_TIMEOUT = 300          # 对话框等人操作的上限（秒）

# PowerShell 侧的选择框脚本。用 -EncodedCommand（UTF-16LE + base64）传，
# 中文提示语就不经过控制台代码页，避免出现"选择 APK 存储目¼"这类乱码。
# 隐藏的顶层 owner 窗口是为了让对话框落在最前面 —— 从浏览器点一下，
# 弹窗跑到浏览器后面的话，使用者会以为没反应。
_PS_PICK_SCRIPT = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.ShowInTaskbar = $false
$owner.FormBorderStyle = 'None'
$owner.StartPosition = 'Manual'
$owner.Size = New-Object System.Drawing.Size(1, 1)
$owner.Location = New-Object System.Drawing.Point(-2000, -2000)
$owner.Show()
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.Description = '选择 APK 存储目录'
$d.ShowNewFolderButton = $true
$r = $d.ShowDialog($owner)
$owner.Close()
if ($r -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output ('OK=' + $d.SelectedPath) }
else { Write-Output 'CANCEL' }
"""


def _pick_powershell(script: Optional[str] = None,
                     timeout: float = 0) -> Tuple[str, str]:
    """Windows：用 .NET 的文件夹选择框，不依赖 Python 装了什么。

    `script` / `timeout` 只在自检里替换（用一段不弹窗的脚本验编码与解析），
    正常调用保持默认值。
    """
    exe = shutil.which("powershell.exe") or shutil.which("powershell")
    if not exe:
        return "fail", "找不到 powershell.exe"
    script = _PS_PICK_SCRIPT if script is None else script
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    cmd = [exe, "-NoProfile", "-NonInteractive", "-STA", "-EncodedCommand", enc]
    flags = 0
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        p = subprocess.run(cmd, capture_output=True,
                           timeout=(timeout or _PICK_TIMEOUT),
                           encoding="utf-8", errors="replace", creationflags=flags)
    except subprocess.TimeoutExpired:
        return "cancel", ""            # 挂着不选＝当取消，别把线程一直占住
    except OSError as e:
        return "fail", "启动 powershell 失败：%s" % e
    out = (p.stdout or "").strip()
    if out.startswith("OK="):
        return "ok", out[3:].strip()
    if out == "CANCEL":
        return "cancel", ""
    tail = ((p.stderr or "").strip().splitlines() or [""])[-1][:160]
    return "fail", "powershell 退出码 %s %s" % (p.returncode, tail)


def _pick_osascript() -> Tuple[str, str]:
    """macOS：系统自带的 choose folder。"""
    exe = shutil.which("osascript")
    if not exe:
        return "fail", "找不到 osascript"
    cmd = [exe, "-e", 'POSIX path of (choose folder with prompt "选择 APK 存储目录")']
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=_PICK_TIMEOUT,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return "cancel", ""
    except OSError as e:
        return "fail", "启动 osascript 失败：%s" % e
    if p.returncode != 0:
        err = (p.stderr or "")
        # 使用者点取消时 osascript 也返回非零，必须与真失败区分开
        if "User canceled" in err or "-128" in err:
            return "cancel", ""
        return "fail", "osascript 失败：%s" % err.strip()[-160:]
    return "ok", (p.stdout or "").strip()


def _pick_linux_dialog() -> Tuple[str, str]:
    """Linux：zenity 或 kdialog，桌面环境一般至少有一个。"""
    if shutil.which("zenity"):
        cmd = ["zenity", "--file-selection", "--directory",
               "--title=选择 APK 存储目录"]
    elif shutil.which("kdialog"):
        cmd = ["kdialog", "--getexistingdirectory", str(Path.home()),
               "--title", "选择 APK 存储目录"]
    else:
        return "fail", "没有 zenity / kdialog"
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=_PICK_TIMEOUT,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return "cancel", ""
    except OSError as e:
        return "fail", "启动选择框失败：%s" % e
    if p.returncode != 0:
        return "cancel", ""          # zenity 取消返回 1
    return "ok", (p.stdout or "").strip()


def _pick_tkinter() -> Tuple[str, str]:
    """兜底：tkinter 版目录框。没装就立刻返回，不起子进程。"""
    if importlib.util.find_spec("tkinter") is None:
        return "fail", "这个 Python 没有 tkinter"
    code = (
        "import tkinter as tk\n"
        "from tkinter import filedialog\n"
        "r = tk.Tk(); r.withdraw()\n"
        "try: r.attributes('-topmost', True)\n"
        "except Exception: pass\n"
        "print('OK=' + (filedialog.askdirectory(title='选择 APK 存储目录') or ''))\n"
        "r.destroy()\n"
    )
    try:
        p = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           timeout=_PICK_TIMEOUT, encoding="utf-8",
                           errors="replace")
    except subprocess.TimeoutExpired:
        return "cancel", ""
    except OSError as e:
        return "fail", "启动 tkinter 失败：%s" % e
    out = (p.stdout or "").strip()
    if p.returncode != 0:
        return "fail", "tkinter 退出码 %s" % p.returncode
    if out.startswith("OK="):
        path = out[3:].strip()
        return ("ok", path) if path else ("cancel", "")
    return "cancel", ""


def pick_backends() -> List[Tuple[str, Any]]:
    """按当前平台列出可用后端（顺序即尝试顺序，最后一个总是 tkinter）。"""
    out: List[Tuple[str, Any]] = []
    if os.name == "nt":
        out.append(("powershell", _pick_powershell))
    elif sys.platform == "darwin":
        out.append(("osascript", _pick_osascript))
    else:
        out.append(("zenity/kdialog", _pick_linux_dialog))
    out.append(("tkinter", _pick_tkinter))
    return out


def pick_directory(backends: Optional[List[Tuple[str, Any]]] = None) -> Dict[str, Any]:
    """依次尝试各后端，返回给界面用的结果。

    返回值三态：
      ok=True, dir=路径      选好了
      ok=True, dir="", cancelled=True   使用者取消
      ok=False, fallback=True          一条路都走不通，界面改手填
    `error` 永远是一句人话，**不含 traceback**；细节放进 `tried` 供排查。

    `PIISCAN_NO_DIALOG=1` 直接返回 fallback：无头服务器上不必等一个
    永远不会被点的对话框干等 5 分钟，自检也靠它避免真的弹窗。
    """
    if os.environ.get("PIISCAN_NO_DIALOG", "").strip().lower() in ("1", "true", "yes"):
        return {
            "ok": False, "fallback": True,
            "error": "已按 PIISCAN_NO_DIALOG 跳过系统目录选择框。"
                     "请在输入框里直接填绝对路径，例如 D:\\apk。",
            "tried": [],
        }
    tried: List[Dict[str, str]] = []
    for name, fn in (backends if backends is not None else pick_backends()):
        try:
            state, val = fn()
        except Exception as e:                      # 单个后端炸了不该影响别的
            tried.append({"backend": name, "error": "%s: %s" % (type(e).__name__, e)})
            continue
        if state == "ok":
            return {"ok": True, "dir": val, "via": name, "tried": tried}
        if state == "cancel":
            return {"ok": True, "dir": "", "cancelled": True, "via": name,
                    "tried": tried}
        tried.append({"backend": name, "error": val})
    names = "、".join(t["backend"] for t in tried) or "无"
    return {
        "ok": False,
        "fallback": True,
        "error": "这台机器弹不出系统目录选择框（已试：%s）。请在输入框里直接填绝对路径，"
                 "例如 D:\\apk 或 /data/apk。" % names,
        "tried": tried,
    }


# ============================================================================
#  测试机清单
# ============================================================================

# 一次 adb shell 拿全所有属性 + root + frida 状态。
#
# 为什么合并成一条：每台机单查一次要 5~7 次 adb 往返（每次 ~80ms，su 更慢），
# 两台机就是一两秒 —— 而这是**打开页面就要显示**的内容。合成一条后
# 单台约 0.4 秒，前端再叠 6 秒缓存，点击刷新也不会有明显等待。
#
# `su -c id` 失败（未授权 root）时输出为空，不会阻塞 —— 这一点很重要：
# 界面必须能显示"这台机没 root"，而不是整块清单一转圈就没了。
_PROBE_SCRIPT = (
    "echo M=$(getprop ro.product.model);"
    "echo B=$(getprop ro.product.brand);"
    "echo R=$(getprop ro.build.version.release);"
    "echo S=$(getprop ro.build.version.sdk);"
    "echo A=$(getprop ro.product.cpu.abi);"
    # ★ 故意**不执行 su**（2026-11-11 用户报障）：
    #   前端每 10 秒拉一次 /api/devices，旧脚本每次都跑 `su -c id` 与
    #   `su -c ps`。结果是"测 A 机时 B 机每 10 秒被授一次 root"—— 屏幕上
    #   反复弹 Magisk 的「shell 已授予 root 权限」，MIUI 的通知亮屏还会把
    #   睡着的屏幕点亮。探测是只读观察，不该在任何一台机器上产生副作用，
    #   更不该碰没在测的那台。
    #   下面两条都不需要 root：`command -v su` 只查文件存在，
    #   `ps -A` 在 shell 身份下本来就能看到 root 进程（两台真机实测均可用）。
    "echo X=$(command -v su 2>/dev/null);"
    "echo F=$(ps -A 2>/dev/null | grep frida-server | head -1)"
)

# 已**实际提权验证**过的设备（serial → 时间戳）。
# 只在明确动作里写入：环境自检、或任务真正开跑。轮询探测永远不写它 ——
# 否则"显示已 root"就变成了"因为轮询跑过 su"这种没意义的循环论证。
# ★ 刻意只存在内存里（不落盘）：重启服务后重新显示「su 可用（未验证）」，
#   这只是"这次进程还没验过"，是真话；落盘反而会在手机被取消 root 后
#   继续断言"已 root"，那是假话。
_ROOT_VERIFIED: Dict[str, float] = {}
_ROOT_VERIFIED_LOCK = threading.Lock()


def mark_root_verified(serial: str) -> None:
    serial = (serial or "").strip()
    if not serial:
        return
    with _ROOT_VERIFIED_LOCK:
        _ROOT_VERIFIED[serial] = time.time()


def _root_verified(serial: str) -> bool:
    with _ROOT_VERIFIED_LOCK:
        return (serial or "").strip() in _ROOT_VERIFIED


def _adb_base(serial: str = "") -> List[str]:
    # 唯一解析口径在 piiscan/adbtool（环境变量 → SDK 目录 → PATH → 默认安装位置）。
    # 这里若只读 `ADB` 环境变量，用户没配它、但 adb 明明在 PATH 里时，
    # 设备列表就是空的 —— 而界面会把这解释成「没有手机」。
    from piiscan import adbtool as _ADB
    return [_ADB.adb_exe()] + (["-s", serial] if serial else [])


def _probe_one(serial: str, state: str, model: str) -> Dict[str, Any]:
    """读一台机的型号/系统/root/frida。只报实测到的东西，不猜。"""
    info: Dict[str, Any] = {
        "serial": serial, "state": state, "model": model or "",
        "brand": "", "android": "", "sdk": "", "abi": "",
        "root": False, "root_verified": False, "su": "",
        "frida": "", "frida_ok": False,
        "busy": False, "busy_job": "", "note": "",
    }
    if state != "device":
        info["note"] = {"offline": "设备处于 offline（USB 松动或调试授权失效）",
                        "unauthorized": "未授权 USB 调试，请在手机上点「允许」"}.get(
            state, "设备状态异常：%s" % state)
        return info
    try:
        p = subprocess.run(_adb_base(serial) + ["shell", _PROBE_SCRIPT],
                           capture_output=True, timeout=25)
    except Exception as e:                      # noqa: BLE001
        info["note"] = "读取设备信息失败：%s" % e
        return info
    txt = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    kv: Dict[str, str] = {}
    for ln in txt.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            k = k.strip()
            if k in ("M", "B", "R", "S", "A", "X", "F"):
                kv[k] = v.strip()
    info["model"] = kv.get("M") or info["model"]
    info["brand"] = kv.get("B") or ""
    info["android"] = kv.get("R") or ""
    info["sdk"] = kv.get("S") or ""
    info["abi"] = kv.get("A") or ""
    # root 的判据分两层，不能混：
    #   su 存在  —— 能说明"这台机装过 root 方案"，但**不等于**我们的 shell 真能提权
    #                （Magisk 可能设成询问、或只授权特定 UID）。
    #   verified —— 本轮/最近一次自检确实拿到 uid=0。界面据此才敢写"已 root"。
    info["su"] = kv.get("X") or ""
    info["root"] = bool(info["su"])
    info["root_verified"] = _root_verified(serial)
    fr = kv.get("F") or ""
    if fr:
        m = re.search(r"frida-server[-\s]*([0-9]+\.[0-9]+\.[0-9]+)?", fr)
        info["frida"] = (m.group(1) if (m and m.group(1)) else "运行中")
        info["frida_ok"] = True
    if not info["root"]:
        info["note"] = "未找到 su：无法启动 frida-server，动态采集不可用"
    elif not info["root_verified"]:
        info["note"] = ("su 可用（尚未实际提权验证）；开始检测前的自检会验证一次后"
                        "才写「已 root」")
    elif not info["frida_ok"]:
        info["note"] = "frida-server 未运行：开始检测时会自动启动"
    else:
        # 走到这里＝su 存在、真拿到过 uid=0、frida-server 在跑：三件事都是实测的
        info["note"] = "已 root（本机检测时实测提权成功，frida-server 运行中）"
    return info


# `adb` 字段是「为什么一台都没看到」的结论（2026-11-12）。空列表有多种成因：
# 没装 adb / 手机没插 / 没授权 / adb 服务卡住。原来一律渲染成「未检测到测试机」，
# 用户只能猜。这里把 adbtool 的判定结果一并带出去，界面照实转述。
_DEV_CACHE: Dict[str, Any] = {"at": 0.0, "data": [], "adb": {}}
_DEV_CACHE_LOCK = threading.Lock()
_DEV_CACHE_TTL = 6.0


def _device_busy(serial: str, my_pid: Optional[int] = None):
    """这台机现在是不是**真的**被另一个任务占着 → (busy, 占用它的任务号)。

    ★ 判据只认内核文件锁（`runlock.probe_free`），不认 `.info` 里的 PID。
      `.info` 在进程退出后不会删，而 PID 会被系统复用 —— 2026-11-11 实测：
      一条任务早被杀掉，它的 PID 恰好被刚启动的浏览器拿去用了，
      于是界面把一台空闲的机器一直显示成"占用中"，提交时的提示也跟着说
      "要排队"。文件锁在进程退出时由内核释放，不会骗人。
      `.info` 只用来回答"是谁在占"，不参与"是否占用"的判断。
    """
    from piiscan import runlock
    me = os.getpid() if my_pid is None else my_pid
    key = (serial or "auto").strip()
    path = runlock.device_lock_path(key)
    if runlock.probe_free(path) is not False:
        # 空闲，或者探不出来。探不出来时**不猜"占用"** —— 猜错会让人以为
        # 要排队，从而不敢提交；而真实情况由任务日志来说（开跑会立刻写一行）。
        return False, ""
    try:
        h = runlock.read_holder(runlock.FileLock(path))
    except Exception:
        h = {}
    if h.get("pid") == me:
        # 自己进程持有的：由 worker.current_serial 那条路径如实报告，
        # 这里不能重复算成"别人占用"。
        return False, ""
    return True, str(h.get("job") or "")


def list_test_devices(worker: Optional["Worker"] = None,
                      force: bool = False) -> List[Dict[str, Any]]:
    """当前接在机器上的测试机清单（含占用状态）。

    ★ 占用状态有两个来源，缺一不可：
      · 本进程的 Worker —— 它正在跑哪个任务、用的哪台机，最权威；
      · 别的服务实例 —— 通过设备锁的 holder 信息看，PID 还活着才算。
    只看锁文件不行：锁释放后 `.info` 文件不会删，会把"跑完了"一直显示成"占用中"。
    """
    now = time.time()
    with _DEV_CACHE_LOCK:
        if not force and _DEV_CACHE["data"] and now - _DEV_CACHE["at"] < _DEV_CACHE_TTL:
            devs = [dict(d) for d in _DEV_CACHE["data"]]
        else:
            # ★ 异常不能一律当成"没有设备"（2026-11-12 用户换机器部署踩到）：
            #   原来 `except Exception: out = ""` 把 FileNotFoundError（adb 没装）
            #   和"手机没插"压成同一句话，界面显示「未检测到测试机」。
            #   现在分别记下来，交给 adbtool 生成一句能照着做的话。
            from piiscan import adbtool as _ADB
            raw, err, missing = "", "", False
            try:
                p = subprocess.run(_adb_base() + ["devices", "-l"],
                                   capture_output=True, timeout=20)
                raw = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
                if p.returncode != 0:
                    err = raw.strip()[:300] or ("adb devices 返回 %d" % p.returncode)
            except FileNotFoundError:
                missing = True
            except subprocess.TimeoutExpired:
                err = "adb devices 超时（20s）：adb 服务可能卡住，试 `adb kill-server` 后重试"
            except Exception as e:                       # noqa: BLE001
                err = "调用 adb 失败：%s" % e
            devs = []
            for d in _ADB.parse_devices(raw):
                devs.append(_probe_one(d["serial"], d["state"], d["model"]))
            _DEV_CACHE["data"] = [dict(d) for d in devs]
            _DEV_CACHE["at"] = now
            # 结论按**本次**实测重算，不走缓存：插拔手机后点"刷新"要立刻看到变化
            _DEV_CACHE["adb"] = _ADB.snapshot(devs, raw, err, missing=missing)

    # ---- 占用状态（每次都现算，不走缓存：缓存 6 秒会让"刚开跑"看起来还空闲）
    # 登记号码同理现取：改 config.yaml 后点一下刷新就该生效，不该等缓存过期。
    phones = _device_phones()
    # 登记簿（2026-11-11 手机管理）。这里只是**标注**，不负责过滤：
    # 插上来的机器一律返回，"这台是否已登记"由 managed 字段回答。
    # 若在这里直接丢掉未登记的，用户插上一台新机时会以为"平台没认出来"，
    # 而真实原因是他还没在「手机管理」里添加。
    reg: Dict[str, Dict[str, Any]] = {}
    db = _registry_db()
    if db is not None:
        try:
            for e in db.devices_list():
                reg[str(e.get("serial") or "")] = e
        except Exception:
            reg = {}
    for d in devs:
        s = d["serial"]
        d["phone"] = phones.get(s, "")
        if worker is not None and getattr(worker, "current_serial", "") == s:
            d["busy"] = True
            d["busy_job"] = getattr(worker, "current_job", "") or ""
        else:
            try:
                d["busy"], bj = _device_busy(s)
                if d["busy"]:
                    d["busy_job"] = bj
            except Exception:
                pass
        e = reg.get(s) or {}
        d["managed"] = bool(e)
        d["alias"] = str(e.get("alias") or "")
        # 登记时**真的拿到过 uid=0** 才算 root 达标；只记"看到过 su 文件"是不够的
        d["registered_root_ok"] = bool(e.get("root_ok"))
        d["degraded"] = bool(e.get("degraded"))
        d["verified_at"] = float(e.get("verified_at") or 0)
        # ★ 别让界面自相矛盾（2026-11-11 截图里一眼可见）：
        #   `_device_info` 的 note 只按"**本轮**有没有验证过"写，于是登记过的机器会
        #   同时出现"已 root（实测提权成功）"和"su 可用（尚未实际提权验证）"。
        #   登记簿里的 root_ok 是"接入那一刻真拿到过 uid=0"的实测证据，它也作数，
        #   所以这里按证据来源重写这句话，而不是两句都摆着让人自己判。
        if d["registered_root_ok"] and not d.get("root_verified"):
            _when = (time.strftime("%Y-%m-%d %H:%M", time.localtime(d["verified_at"]))
                     if d["verified_at"] else "")
            d["note"] = ("接入时已验证 root%s（当时实测拿到 uid=0）；本轮未复验，"
                         "开跑前自检会再验一次" % (" · " + _when if _when else ""))
        name = d["alias"] or d["model"] or d["serial"]
        d["label"] = "%s（%s / Android %s）" % (
            name, d["serial"], d["android"] or "?")
        # ★「这台现在能不能用」只在一个地方算，别让两个页面各算一遍。
        #   2026-11-11：状态页按"adb 里有几台"统计，手机管理页按登记簿统计，
        #   于是把两台都移除了，状态页仍写着"2 台可用" —— 一处操作、两处不一致。
        #   口径 = 有真实提权证据（接入时验证过 或 本次自检过了）＋ 此刻插着
        #          ＋ 此刻 su 还在 ＋ 没被任务占用。
        try:
            from piiscan.devices import usable as _usable
            _verified = bool(e) and (bool(e.get("root_ok")) or bool(d.get("root_verified")))
            d["usable"] = bool(_verified and _usable(e, d)) and not d.get("busy")
        except Exception:
            d["usable"] = False
        tags = []
        if d["busy"]:
            tags.append("占用中")
        if d["state"] != "device":
            tags.append("不可用")
        elif not d["root"]:
            tags.append("无 root")
        if not d["managed"]:
            # 不是错误，是"还没登记"。措辞要中性：它照样能跑，只是没在平台上管理。
            tags.append("未登记")
        d["tags"] = tags
    return devs


# ============================================================================
#  测试机接入会话（界面上的「添加手机」）
# ============================================================================

# 接入是**长动作**：等 USB 授权可能 90 秒、push frida-server 几十 MB、
# 再启动 + 连一次 + dump 一次界面。同步 HTTP 请求会被浏览器/代理判超时，
# 而用户看不到任何进度 —— 那不是"等待"，是"以为卡死了"。
# 所以做成会话：POST 立刻返回 id，前端每 1 秒拉一次步骤状态。
_ENROLLS: Dict[str, Dict[str, Any]] = {}
_ENROLL_LOCK = threading.Lock()
_ENROLL_KEEP = 3600.0        # 完成后保留一小时（够人截图、够刷新页面再看一眼）
_ENROLL_MAX_KEEP = 20        # 内存里最多留 20 条，防止长时间运行无限增长


def _prune_enrolls() -> None:
    now = time.time()
    with _ENROLL_LOCK:
        dead = [k for k, v in _ENROLLS.items()
                if v.get("finished_at") and now - float(v["finished_at"]) > _ENROLL_KEEP]
        for k in dead:
            _ENROLLS.pop(k, None)
        if len(_ENROLLS) > _ENROLL_MAX_KEEP:
            order = sorted(_ENROLLS.items(),
                           key=lambda kv: float(kv[1].get("started_at") or 0))
            for k, _v in order[:len(_ENROLLS) - _ENROLL_MAX_KEEP]:
                if _ENROLLS[k].get("finished_at"):
                    _ENROLLS.pop(k, None)


def _enroll_snapshot(sess: Dict[str, Any]) -> Dict[str, Any]:
    """给前端的只读快照。steps 里每一项都带 state，界面直接照着画。"""
    out = {
        "id": sess["id"], "serial": sess["serial"],
        "alias": sess.get("alias") or "", "phone": sess.get("phone") or "",
        "state": sess.get("state") or "running",
        # ★ 字段名不能用 `ok`：这一层已经有"请求成功"的 `ok` 了（所有接口都返回
        #   `{"ok": true|false, ...}`）。业务上的"接入成功"必须是另一个名字，
        #   否则"正在跑"这个中间态会被前端当成"请求失败"直接中断
        #   （2026-11-11 实测踩到：点了开始接入，界面上立刻显示"无法开始接入"）。
        "succeeded": (sess.get("state") == "ok"),
        "steps": [dict(s) for s in (sess.get("steps") or [])],
        "info": dict(sess.get("info") or {}),
        "error": sess.get("error") or "",
        "degraded": bool(sess.get("degraded")),
        "started_at": sess.get("started_at"), "finished_at": sess.get("finished_at"),
        "elapsed": round(time.time() - float(sess.get("started_at") or time.time()), 1),
        "saved": bool(sess.get("saved")),
    }
    return out


def start_enroll(db: JobDB, serial: str, *, alias: str = "", phone: str = "",
                 note: str = "", force: bool = False,
                 allow_download: bool = True) -> Dict[str, Any]:
    """创建接入会话并起后台线程。返回初始快照（前端据此立刻画出步骤条）。"""
    from piiscan import devices as _dev

    serial = (serial or "").strip()
    sid = "E" + time.strftime("%Y%m%d%H%M%S") + "-" + uuid_hex(4)
    sess: Dict[str, Any] = {
        "id": sid, "serial": serial, "alias": (alias or "").strip(),
        "phone": (phone or "").strip(), "note": (note or "").strip(),
        "state": "running", "steps": [{"key": k, "title": t, "state": "pending",
                                       "detail": "", "fix": "", "fixed": False,
                                       "fatal": True}
                                      for k, t in _dev.STEP_TITLES],
        "info": {}, "error": "", "degraded": False,
        "started_at": time.time(), "finished_at": None, "saved": False,
        "log": [],
    }
    _prune_enrolls()
    with _ENROLL_LOCK:
        _ENROLLS[sid] = sess

    def on_step(res) -> None:
        with _ENROLL_LOCK:
            sess["steps"] = [s.to_dict() for s in res.steps]
            sess["info"] = dict(res.info)
            sess["degraded"] = bool(res.degraded)
        # 不在这里写库/写日志：这个方法每秒会被调用几十次（等待授权时），
        # 任何 I/O 都会把"实时"变成"卡顿"。

    def work() -> None:
        log_lines: List[str] = []

        def log(msg: str) -> None:
            log_lines.append(str(msg))
            with _ENROLL_LOCK:
                sess["log"] = log_lines[-200:]

        try:
            res = _dev.enroll(serial, log=log, on_step=on_step,
                              allow_download=allow_download, force=force)
        except Exception as e:                     # noqa: BLE001
            with _ENROLL_LOCK:
                sess["state"] = "failed"
                sess["error"] = "接入过程异常：%s: %s" % (type(e).__name__, e)
                sess["finished_at"] = time.time()
            return

        with _ENROLL_LOCK:
            sess["steps"] = [s.to_dict() for s in res.steps]
            sess["info"] = dict(res.info)
            sess["degraded"] = bool(res.degraded)
            sess["error"] = res.error
            sess["log"] = log_lines[-200:]

        if res.ok:
            # 落库放在这里（不在 on_step 里）：只有"整条流程走完"才登记。
            # 半途失败就落库，会留下一台"记录了但从没可用过"的机器。
            steps_brief = json.dumps(
                [{"key": s.key, "state": s.state, "title": s.title} for s in res.steps],
                ensure_ascii=False)
            frida_ver = ""
            try:
                from piiscan import fridabin as _fb
                frida_ver = _fb.local_version()
            except Exception:
                frida_ver = ""
            try:
                db.device_save(serial=serial, alias=alias, phone=phone, note=note,
                               root_ok=not res.degraded, degraded=res.degraded,
                               info=res.info, frida_ver=frida_ver, steps=steps_brief)
                with _ENROLL_LOCK:
                    sess["saved"] = True
            except Exception as e:                 # noqa: BLE001
                with _ENROLL_LOCK:
                    sess["state"] = "failed"
                    sess["error"] = ("设备已就绪，但写入登记簿失败：%s: %s"
                                     % (type(e).__name__, e))
                    sess["finished_at"] = time.time()
                return
            # root 没通过却按用户要求登记了（degraded）：**不标记**已 root ——
            # 那会把"这台机现在跑不了动态采集"说成"已 root"，而后者是任务调度
            # 与报告设备信息都要用到的结论。
            if not res.degraded:
                mark_root_verified(serial)
        with _ENROLL_LOCK:
            sess["state"] = "ok" if res.ok else "failed"
            sess["finished_at"] = time.time()

    t = threading.Thread(target=work, name="enroll:%s" % serial, daemon=True)
    t.start()
    return _enroll_snapshot(sess)


def enroll_get(sid: str) -> Optional[Dict[str, Any]]:
    with _ENROLL_LOCK:
        sess = _ENROLLS.get(sid)
        if not sess:
            return None
        return _enroll_snapshot(sess)


def uuid_hex(n: int = 4) -> str:
    import uuid
    return uuid.uuid4().hex[:n]


# ============================================================================
#  HTTP 处理
# ============================================================================

class Handler(BaseHTTPRequestHandler):
    server_version = "PIIscan/1.0"
    db: JobDB = None
    workdir: Path = None
    max_upload = 800 * 1024 * 1024
    # 本机是否接了检测设备（adb + 已 root 的测试机）。
    # 服务器部署（无 USB、手机不在同一网段）时置 False：默认不跑动态采集，
    # 且**明确拒绝**要求动态采集的请求 —— 静默降级会让报告看起来像
    # "这个 App 很干净"，是最危险的假阴性。
    device_enabled: bool = True
    # 后台执行器实例（由 serve() 注入）。只读用途：让"测试机"清单知道
    # 哪台正在被本进程的任务占用。为 None 时也能工作（只看跨进程锁）。
    worker: Any = None

    # ---- 工具 ----
    def log_message(self, fmt, *args):
        if self.server.quiet:
            return
        print("[web] %s - %s" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8",
              extra: Optional[Dict[str, str]] = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _err(self, code: int, msg: str):
        self._json({"ok": False, "error": msg}, code)

    def _read_body_json(self) -> Dict[str, Any]:
        """读请求体：JSON / 表单 / multipart 三种都认。

        为什么都要认：前端为了上传 APK 用 FormData，设备管理这些纯文本接口
        用 JSON 更省事；而这套服务要能被别的系统（脚本、AI 编排器）调用，
        它们往往就发一个 `application/x-www-form-urlencoded`。三种都接受
        比要求调用方猜"应该发哪种"更省事。
        """
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        cap = min(length, 2 * 1024 * 1024)
        if ctype == "multipart/form-data":
            fields = parse_multipart(self.rfile, self.headers.get("Content-Type", ""),
                                     length, self.workdir / "_uploads", cap)
            return {k: (v.get("path") if isinstance(v, dict) else v)
                    for k, v in fields.items()}
        raw = self.rfile.read(cap)
        txt = raw.decode("utf-8", "replace")
        if ctype == "application/json" or txt.strip().startswith("{"):
            try:
                data = json.loads(txt)
                return data if isinstance(data, dict) else {}
            except Exception:
                raise ValueError("请求体不是合法 JSON")
        q = urllib.parse.parse_qs(txt, keep_blank_values=True)
        return {k: v[0] for k, v in q.items()}

    # ---- 路由 ----
    # ------------------------------------------------------------ APK 存储
    #
    # 为什么把它做成平台级设置而不是任务参数：APK 一次只有一个"当前该放哪"，
    # 而且它取决于这台机器的磁盘布局（C 盘小、D 盘大）。每个任务各填一次
    # 只会让人重复劳动，还会出现"同一台机器上任务分散在三个目录"的局面。
    #
    # 换目录**不搬**已有文件：几百 MB 的包搬起来又慢又容易半路失败，
    # 而老任务里记的是绝对路径，留在原处照样能复现、能删。
    def _storage_get(self):
        from piiscan import apkstore
        cur = apkstore.root(self.db, self.workdir)
        dft = apkstore.default_root(self.workdir)
        info = apkstore.describe(cur)
        try:
            orph = apkstore.orphans(self.db, cur) if info["exists"] else []
        except Exception:
            orph = []
        ob = sum(int(o.get("size") or 0) for o in orph)
        return self._json({
            "ok": True,
            "dir": info["dir"],
            "default_dir": str(dft),
            "is_default": not apkstore.configured(self.db),
            "exists": info["exists"],
            "files": info["files"],
            "bytes": info["bytes"],
            "size_text": apkstore.fmt_size(info["bytes"]),
            # .incoming 里是还没收进去的半截下载，单独报：混进"已占用"会让人误解。
            "incoming_files": info["incoming_files"],
            "incoming_bytes": info["incoming_bytes"],
            "incoming_size_text": apkstore.fmt_size(info["incoming_bytes"]),
            "orphans": len(orph),
            "orphan_bytes": ob,
            "orphan_size_text": apkstore.fmt_size(ob),
        })

    def _storage_set(self):
        from piiscan import apkstore
        data = self._read_body_json()
        raw = str(data.get("dir") or "").strip()
        old = apkstore.root(self.db, self.workdir)
        created = False
        if not raw:
            # 空＝恢复默认位置。这是"取消自定义"，不是"存一个空路径"。
            self.db.meta_set(apkstore.META_KEY, "")
            new = apkstore.default_root(self.workdir)
        else:
            v = apkstore.validate_dir(raw)
            if not v.get("ok"):
                raise ValueError(v.get("error") or "目录不可用")
            self.db.meta_set(apkstore.META_KEY, v["path"])
            new = Path(v["path"])
            created = bool(v.get("created"))
        note = ""
        if str(new) != str(old):
            prev = apkstore.describe(old)
            if prev.get("files"):
                note = ("原目录里的 %d 个包（%s）仍然保留在原处，没有搬移；"
                        "老任务记的是绝对路径，删任务时照各自记录的位置清理。"
                        % (prev["files"], apkstore.fmt_size(prev["bytes"])))
            else:
                note = "之后下载与上传的 APK 都放到新位置。"
        return self._json({"ok": True, "dir": str(new), "previous": str(old),
                           "created": created, "note": note,
                           "default_dir": str(apkstore.default_root(self.workdir))})

    def _storage_sweep(self):
        """清掉没有任务引用的包，以及一天前还没下完的残片。"""
        from piiscan import apkstore
        rt = apkstore.root(self.db, self.workdir)
        r = apkstore.sweep(self.db, rt)
        return self._json({
            "ok": True, "dir": str(rt),
            "count": r.get("count", 0),
            "bytes": r.get("bytes", 0),
            "size_text": apkstore.fmt_size(r.get("bytes", 0)),
            "errors": r.get("errors") or [],
        })

    def _storage_pick(self):
        """在服务所在的这台机器上弹一个目录选择框。

        具体走哪条路由 `pick_directory()` 决定（Windows 用系统自带的
        FolderBrowserDialog，不依赖 Python 有没有装 tkinter）。
        一条路都走不通时**不报错**，返回 fallback 让界面提示手填 ——
        "没装图形库"是环境差异，不是故障，不该朝使用者甩 traceback。
        """
        return self._json(pick_directory())

    # ------------------------------------------------------------ AI 连通性
    def _ai_ping(self):
        """回答"这套 AI 配置现在到底能不能用"，而不是只回答"端口通不通"。

        分三层，一层都不能省（早先只做了第一层，界面上写"✓ 服务可达"，
        模型名写错时照样是绿的，直到跑完一轮才失败）：
          ① 服务可达 —— `/api/tags` 有响应，只证明有进程在听
          ② 模型已部署 —— `/api/show` 精确核对（毫秒级、不加载权重），
             顺带读回真实 `num_ctx` 与 `capabilities`
          ③ 当前是否已加载 —— `/api/ps`。**未加载是正常状态**（Ollama 按需加载、
             空闲自动卸载），必须与"没部署"分开表述，否则使用者会误判成故障。

        真正的推理验证在环境自检 `preflight.check_ai()` 第三层做（要等冷加载，
        不适合点按钮即返回）。查询参数可只填其中一项，其余沿用 config.yaml。
        """
        from piiscan.ai.factory import build_ai
        from piiscan.config import AppConfig

        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        def g(k: str) -> str:
            return (qs.get(k) or [""])[0].strip()

        cfg = AppConfig()
        cfg_path = ROOT / "config.yaml"
        if cfg_path.exists():
            try:
                cfg = AppConfig.load(cfg_path)
            except Exception:
                pass
        # 模型连接配置现在以「系统状态 → AI 模型服务」里启用的那一套为准；
        # config.yaml 只是没有档案时的兜底。查询参数仍可覆盖（用于临时试探）。
        try:
            apply_ai_profile(self.db, cfg)
        except Exception:
            pass
        ai = cfg.ai
        if g("provider"):
            ai.provider = g("provider")
        if g("base_url"):
            ai.base_url = g("base_url")
        if g("model"):
            ai.model = g("model")
        if g("vision_model"):
            ai.vision_model = g("vision_model")

        if (ai.provider or "none") == "none":
            return self._json({"ok": False,
                               "error": "未指定接口类型（provider=none）。"
                                        "请选择 Ollama 或 OpenAI 兼容接口。"})
        # Agent 中继不连任何服务，探测方式也不同：只看中继目录能不能建起来
        if (ai.provider or "").lower() in ("agent", "relay"):
            try:
                provider = build_ai(ai)
            except Exception as e:
                return self._json({"ok": False, "error": "配置无效：%s" % e})
            ok = provider.available()
            return self._json({
                "ok": bool(ok),
                "error": "" if ok else "无法创建中继目录，请检查写权限",
                "models": [],
                "vision_hint": "Agent 中继：由对话里的 AI 亲自看图作答，无需任何模型服务 ✓",
                "relay_dir": str(getattr(provider, "dir", "") or ""),
                "usage": "python tools/ai_relay.py list / show <id> / answer <id> --file a.json",
            })
        try:
            provider = build_ai(ai)
        except Exception as e:
            return self._json({"ok": False, "error": "配置无效：%s" % e})

        reachable = provider.available()
        models = _list_models(ai) if reachable else []
        vm = ai.vision_model or ai.model
        is_ollama = (ai.provider or "").lower() == "ollama"
        probe: Dict[str, Any] = {}
        loaded: Optional[List[str]] = None

        # ---- 第二层：模型到底在不在 ----
        # ★ 只报"服务可达"是不够的：端口开着、模型名写错时它照样是绿的，
        #   使用者会以为配好了，直到 P2 政策深读才失败（或更糟：无声回退关键词）。
        #   这里补一句"这个模型在不在"，才算回答了"能不能用"。
        if reachable and is_ollama:
            probe = _ollama_probe(ai, ai.model)
            loaded = _ollama_loaded(ai)
        if reachable and is_ollama and not probe.get("exists"):
            avail = [n for n in models if n]
            return self._json({
                "ok": False,
                "reachable": True,
                "model": ai.model,
                "model_exists": False,
                "models": avail,
                "vision_hint": _vision_hint(vm),
                "error": "服务可达，但模型「%s」没有部署到服务端（%s）。%s"
                         "请先 `ollama pull %s`，或把模型名改成已有的一个。"
                         % (ai.model, probe.get("error") or "查无此模型",
                            ("服务端现有：%s。" % "、".join(avail[:6])) if avail else "",
                            ai.model),
            })

        # ---- 上下文长度核对：配置写的 vs 模型实际的 ----
        # 两者不一致时，按配置算出来的"可送字数"就是错的：配置写大了会被静默截尾
        # （模型没看完却报告"已分析全文"），写小了只是白砍预算。
        cfg_ctx = int(getattr(ai, "context_tokens", 0) or 0)
        real_ctx = int(probe.get("num_ctx") or 0)
        ctx_note = ""
        if real_ctx and cfg_ctx and real_ctx != cfg_ctx:
            ctx_note = ("⚠ 配置 context_tokens=%d 与模型实际 num_ctx=%d 不一致，"
                        "请改 config.yaml（不一致会导致按错的预算送入正文）"
                        % (cfg_ctx, real_ctx))

        # ---- 加载状态：解释"为什么 ps 里看不到它" ----
        state = ""
        is_loaded = False
        if loaded is not None:
            is_loaded = any(n == ai.model or n.split(":")[0] == ai.model.split(":")[0]
                            for n in loaded)
            if is_loaded:
                state = "当前已加载"
            else:
                state = ("当前未加载（Ollama 按需加载，首次调用会自动载入，"
                         "这属正常状态，不是故障）")

        # 视觉能力优先看模型自报的 capabilities，比按名字猜可靠。
        # 视觉模型与主模型不同名时必须单独问它自己 —— 否则会拿主模型的能力冒充。
        caps = [c.lower() for c in (probe.get("capabilities") or [])]
        v_missing = ""
        if reachable and is_ollama and vm and vm != ai.model:
            vprobe = _ollama_probe(ai, vm)
            if not vprobe.get("exists"):
                v_missing = ("⚠ 视觉模型「%s」没有部署到服务端，视觉环节"
                             "（截图定位政策入口、AI 指挥遍历）会回退到规则策略" % vm)
                caps = []
            else:
                caps = [c.lower() for c in (vprobe.get("capabilities") or [])]
        if v_missing:
            vision_hint = v_missing
        elif caps and "vision" in caps:
            vision_hint = "「%s」支持图片输入（模型能力清单确认 ✓）" % vm
        elif caps and "vision" not in caps:
            vision_hint = ("「%s」的模型能力清单里**没有 vision** —— 视觉环节"
                           "（截图定位政策入口、AI 指挥遍历）会回退到规则策略" % vm)
        else:
            vision_hint = _vision_hint(vm)

        return self._json({
            "ok": bool(reachable),
            "reachable": bool(reachable),
            "model": ai.model,
            "model_exists": bool(probe.get("exists")) if is_ollama else None,
            "loaded": is_loaded if loaded is not None else None,
            "state": state,
            "num_ctx": real_ctx,
            "cfg_ctx": cfg_ctx,
            "ctx_note": ctx_note,
            "capabilities": probe.get("capabilities") or [],
            "error": "" if reachable else
                     "无法连接 %s。请确认服务已启动、地址与端口填写正确。" % ai.base_url,
            "models": models,
            "vision_hint": vision_hint,
        })

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._file(STATIC / "index.html", "text/html; charset=utf-8")
        if path == "/api/jobs":
            return self._json({"ok": True, "jobs": self.db.list(200),
                               "stats": self.db.stats()})
        # AI 配置档案（2026-11-12）：模型地址/模型名/密钥从 config.yaml
        # 搬到平台里，可保存多套、可切换、可删除。
        if path == "/api/ai/profiles":
            return self._ai_profiles_list()
        if path == "/api/health":
            return self._json({"ok": True, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                               "stats": self.db.stats()})
        if path == "/api/env":
            # 前端用它决定「执行设备动态采集」勾选框是否可用。
            # 部署在服务器上（无 USB、手机不在同网段）时这里是 false。
            return self._json({"ok": True, "device_enabled": bool(self.device_enabled),
                               "server": self.server_version,
                               "workdir": str(self.workdir)})
        if path == "/api/devices":
            # 测试机清单：前端下拉框用。带 ?refresh=1 时绕过 6 秒缓存
            # （插拔手机之后马上点"刷新"要能看到变化）。
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            force = (qs.get("refresh") or ["0"])[0].strip() not in ("0", "", "false")
            devs = list_test_devices(getattr(self, "worker", None), force=force)
            cur, pref = "", ""
            try:
                from piiscan.config import AppConfig
                _c = AppConfig.load(ROOT / "config.yaml")
                _d = getattr(_c, "device", None)
                cur = (getattr(_d, "serial", "") or "").strip()
                pref = (getattr(_d, "preferred", "") or "").strip()
            except Exception:
                cur, pref = "", ""
            reg_n = 0
            db = _registry_db()
            if db is not None:
                try:
                    reg_n = db.device_count()
                except Exception:
                    reg_n = 0
            return self._json({"ok": True, "devices": devs,
                               # adb 自身的状态：查不到 adb 与"没有手机"必须能分开
                               "adb": dict(_DEV_CACHE.get("adb") or {}),
                               "device_enabled": bool(self.device_enabled),
                               "default": cur,
                               # 下拉框默认选谁。与 default 分开：default 是
                               # `serial`（"就这一台"的硬指定），preferred 只是
                               # "首选哪台"，两者语义不同，不能合并成一个字段。
                               "preferred": pref,
                               # 登记了几台。前端下拉框**只列登记的**（2026-11-11
                               # 起不再"空了就回落列全部"）—— 回落会让「移除手机」
                               # 这个动作看起来没生效：两台都移除了，下拉框里又冒出两台。
                               "registry_count": reg_n,
                               "auto": not cur})
        if path == "/api/ai/ping":
            return self._ai_ping()
        if path == "/api/storage":
            return self._storage_get()
        if path == "/api/env/preflight":
            return self._preflight()
        if path == "/api/devices/registry":
            return self._devices_registry()
        m = re.match(r"^/api/devices/enroll/([A-Za-z0-9\-]+)$", path)
        if m:
            snap = enroll_get(m.group(1))
            if not snap:
                return self._err(404, "接入会话不存在或已过期：服务重启后进度会丢失，"
                                      "请重新点「添加手机」")
            # 顶层 ok 恒为 True：它回答的是"这次查询成功了吗"。
            # 接入本身成没成看 succeeded —— 两个概念不能共用一个字段名。
            return self._json(dict(snap, ok=True))
        m = re.match(r"^/api/jobs/([^/]+)$", path)
        if m:
            job = self.db.get(m.group(1))
            if not job:
                return self._err(404, "任务不存在")
            # 与列表接口保持同一套可操作项，前端不必自己维护状态→动作的映射
            from .db import ALLOWED_ACTIONS
            job["actions"] = list(ALLOWED_ACTIONS.get(job.get("status"), ()))
            # 与列表接口一致地给出"距上次进度变化多久"，前端详情页也能提示卡死
            hb = job.get("heartbeat_at")
            job["stall"] = int(time.time() - hb) if (job.get("status") == "running" and hb) else 0
            return self._json({"ok": True, "job": job})
        m = re.match(r"^/api/jobs/([^/]+)/log$", path)
        if m:
            job = self.db.get(m.group(1))
            if not job:
                return self._err(404, "任务不存在")
            return self._json({"ok": True, "log": job.get("log") or "",
                               "status": job.get("status"), "stage": job.get("stage")})
        m = re.match(r"^/api/jobs/([^/]+)/report$", path)
        if m:
            return self._report(m.group(1), download=False)
        m = re.match(r"^/api/jobs/([^/]+)/download$", path)
        if m:
            return self._report(m.group(1), download=True)
        # 批量下载（打包 zip）。路径放 /api/reports/ 下与单任务的 /api/jobs/<id>/ 区分，
        # 免得和「某个任务的第 N 个动作」混淆。
        if path.rstrip("/") == "/api/reports/zip":
            return self._report_zip()
        m = re.match(r"^/static/(.+)$", path)
        if m:
            f = (STATIC / m.group(1)).resolve()
            if STATIC.resolve() in f.parents and f.exists():
                ct = mimetypes.guess_type(str(f))[0] or "application/octet-stream"
                return self._file(f, ct)
        self._err(404, "未找到：%s" % path)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        # ---- AI 配置档案（系统状态页的全局配置）----
        if path == "/api/ai/profiles":
            try:
                return self._ai_profile_save()
            except ValueError as e:
                return self._err(400, str(e))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
        if path == "/api/ai/active":
            try:
                return self._ai_active_set()
            except ValueError as e:
                return self._err(400, str(e))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
        # ---- APK 存储位置（系统状态页）----
        if path == "/api/storage":
            try:
                return self._storage_set()
            except ValueError as e:
                return self._err(400, str(e))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
        if path == "/api/storage/sweep":
            try:
                return self._storage_sweep()
            except ValueError as e:
                return self._err(400, str(e))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
        if path == "/api/storage/pick":
            try:
                return self._storage_pick()
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
        m = re.match(r"^/api/ai/profiles/([A-Za-z0-9_\-]+)/(activate|test)$", path)
        if m:
            try:
                if m.group(2) == "activate":
                    return self._ai_profile_activate(m.group(1))
                return self._ai_profile_test(m.group(1))
            except ValueError as e:
                return self._err(400, str(e))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))

        # ---- 手机管理（2026-11-11）----
        # 这两个接口都是 JSON 进、JSON 出，不走 APK 上传那条 multipart 路径。
        if path == "/api/devices/enroll":
            try:
                return self._device_enroll()
            except ValueError as e:
                return self._err(400, str(e))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
        m = re.match(r"^/api/devices/([A-Za-z0-9._:\-]+)/meta$", path)
        if m:
            try:
                return self._device_meta(m.group(1))
            except ValueError as e:
                return self._err(400, str(e))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
        if path == "/api/jobs":
            try:
                return self._create_job()
            except ValueError as e:
                return self._err(400, str(e))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))

        # 短信验证码回填：POST /api/jobs/<id>/sms  {"code": "123456"}
        # 采集线程遇到登录页会点"获取验证码"然后轮询工作目录的 sms.txt。
        # 这里只负责把码写进文件 —— 不碰设备、不碰数据库里的任务状态，
        # 所以采集线程完全不用等这条请求。
        m = re.match(r"^/api/jobs/([^/]+)/sms$", path)
        if m:
            try:
                return self._submit_sms(m.group(1))
            except ValueError as e:
                return self._err(400, str(e))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))

        # 任务操作：暂停 / 恢复 / 停止 / 重试 / 置顶到队头
        m = re.match(r"^/api/jobs/([^/]+)/(pause|resume|cancel|retry|front)$", path)
        if m:
            job_id, action = m.group(1), m.group(2)
            try:
                if action == "front":
                    r = self.db.bump_queue(job_id)
                else:
                    r = self.db.request(job_id, action)
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
            if not r.get("ok"):
                return self._err(409 if r.get("status") else 404,
                                 r.get("error") or "操作失败")
            job = self.db.get(job_id) or {}
            self.db.append_log(job_id, "[*] 用户操作：%s —— %s"
                               % ({"pause": "暂停", "resume": "恢复",
                                   "cancel": "停止", "retry": "重试",
                                   "front": "置顶到队头"}[action],
                                  r.get("note") or ""))
            # ★ 停止请求不要等 worker 下一轮读库（500ms ~ 1s）再被看见 ——
            #   更不要等它从一次 AI 调用里返回。这里立刻置位取消令牌，
            #   在途的网络请求 0.25 秒内被打断（见 piiscan/ai/cancel.py）。
            hit = False
            if action == "cancel":
                try:
                    hit = bool(self.worker.request_cancel(job_id))
                except Exception:
                    hit = False
                if hit:
                    self.db.append_log(
                        job_id, "[*] 已打断正在进行的模型调用（不再等它返回）", live=False)
            return self._json({"ok": True, "job": job, "note": r.get("note") or "",
                               "interrupted_ai": hit})

        return self._err(404, "未找到：%s" % path)

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path

        # 删除一套 AI 配置：DELETE /api/ai/profiles/<id>
        m = re.match(r"^/api/ai/profiles/([A-Za-z0-9_\-]+)$", path)
        if m:
            return self._ai_profile_delete(m.group(1))

        # 移除登记的手机：DELETE /api/devices/<serial>
        # 只删平台记录，不碰设备（见 db.device_delete 的说明）。
        m = re.match(r"^/api/devices/([A-Za-z0-9._:\-]+)$", path)
        if m:
            try:
                return self._device_delete(m.group(1))
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))

        # 批量删除：DELETE /api/jobs?ids=a,b,c&files=0
        # 用 query 而不是请求体：DELETE 带 body 在部分代理/客户端上会被丢掉，
        # 结果是"请求成功但一个都没删"，比报错更难查。
        if path.rstrip("/") == "/api/jobs":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            ids: List[str] = []
            for raw in qs.get("ids", []) + qs.get("id", []):
                ids.extend(x for x in raw.split(",") if x.strip())
            if not ids:
                return self._err(400, "缺少 ids 参数（DELETE /api/jobs?ids=J1,J2）")
            drop_files = str((qs.get("files") or ["1"])[0]).lower() not in ("0", "false", "no")
            try:
                r = self.db.delete_many(ids, drop_files=drop_files)
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
            # 一条都没删掉才算失败（例如全在运行中），部分成功仍返回 200，
            # 由 skipped 说明剩下的为什么没删 —— 界面需要区分
            # "全成功"、"删了一部分" 和 "一个都没动"，否则用户会以为清干净了。
            if not r.get("ok"):
                r["error"] = ("未能删除任何任务：%s"
                              % ("；".join("%s %s" % (x["id"], x["reason"])
                                          for x in (r.get("skipped") or [])[:5])
                                 or "未知原因"))
                return self._json(r, 409)
            return self._json(r)

        m = re.match(r"^/api/jobs/([^/]+)$", path)
        if not m:
            return self._err(404, "未找到：%s" % path)
        try:
            r = self.db.delete(m.group(1))
        except Exception as e:
            return self._err(500, "%s: %s" % (type(e).__name__, e))
        if not r.get("ok"):
            return self._err(409, r.get("error") or "删除失败")
        return self._json({"ok": True, "removed": r.get("removed") or [],
                           # 包还被别的任务用着时文件会留着，这里如实带出去，
                           # 否则界面说"已删除"，磁盘上却还在，等于撒谎。
                           "apk_kept_by": r.get("apk_kept_by") or 0,
                           "apk_note": r.get("apk_note") or ""})

    # ---- 具体动作 ----
    def _file(self, path: Path, ctype: str):
        if not path.exists():
            return self._err(404, "文件不存在")
        self._send(200, path.read_bytes(), ctype)

    def _report(self, job_id: str, download: bool):
        """预览或下载报告。

        `?fmt=json` 取流程存档、`?fmt=scan` 取原始采集存档 ——
        复核时经常要拿这两份原始件去核报告里某一句话的出处，
        只给 HTML 会让"报告说的"和"采到的"之间无法对照。

        `?fmt=brief`（或 `?brief=1`）= **简版报告**。两者取同一个渲染器，
        只是文件不同（`report_brief.html` / `report.html`）。
        """
        job = self.db.get(job_id)
        if not job:
            return self._err(404, "任务不存在")
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        fmt = ((qs.get("fmt") or [""])[0] or "html").lower()

        if fmt in ("json", "scan"):
            p = job.get("result_path" if fmt == "json" else "scan_path") or ""
            if not p or not Path(p).exists():
                return self._err(409, "该格式的产物不存在（任务状态：%s）" % job.get("status"))
            suffix = "流程存档" if fmt == "json" else "采集存档"
            extra = {}
            if download:
                extra["Content-Disposition"] = _disposition(
                    _report_filename(job, suffix, ".json"),
                    _ascii_fallback(job, "flow" if fmt == "json" else "scan", ".json"))
            return self._send(200, Path(p).read_bytes(),
                              "application/json; charset=utf-8", extra)

        rp = job.get("report_path") or ""
        if not rp or not Path(rp).exists():
            return self._err(409, "报告尚未生成（任务状态：%s）"
                             % (job.get("status") or "未知"))

        # ---- 简版 ----
        # 简版是任务跑完时一并落盘的（`report_brief.html`）。
        # 简版上线前跑的历史任务没有这个文件，但 flow.json 还在 ——
        # 现场渲染一份即可，不必让人为了要个简版把整轮检测重跑一遍。
        # （渲染器只吃 flow.json 的 dict，不依赖运行期的 FlowResult，
        #   所以"补一份简版"和"当时生成的那份"是同一段代码、同一份数据。）
        brief = (fmt == "brief") or ((qs.get("brief") or [""])[0] in ("1", "true", "yes"))
        if brief:
            bp, berr = _ensure_brief(job)
            if not bp:
                return self._err(409, "简版报告无法生成：%s"
                                 % (berr or "缺少流程存档或报告"))
            rp = str(bp)
            # 后缀加在**详细版**上、简版不加（2026-10-26 用户指定）：
            # 对外交出去的是不带后缀那一份，文件名本身不该替它声明"我是删节版"。
            suffix = ""
        else:
            suffix = "详细版"

        extra = {}
        if download:
            # 文件名带 App 名称，便于人在下载目录里直接认出是哪个应用。
            # ASCII 兜底名用英文（中文后缀会被过滤成一串下划线）。
            extra["Content-Disposition"] = _disposition(
                _report_filename(job, suffix),
                _ascii_fallback(job, "" if brief else "detail"))
        self._send(200, Path(rp).read_bytes(), "text/html; charset=utf-8", extra)

    def _report_zip(self):
        """批量下载：`GET /api/reports/zip?ids=a,b,c[&fmt=html|brief|json|scan]`。

        `fmt=html` 详细报告、`fmt=brief` 简版报告（缺简版的会按 flow.json 现补）。

        为什么打成 zip 而不是让浏览器连开 N 个下载：浏览器对同源并发下载
        有上限（Chrome 约 6 个），一次勾 50 个任务会有一大半被静默挡掉，
        用户以为都下完了。打成一个包还有个顺带的好处 —— 压缩包里每个文件
        可以放心用中文 App 名称，不必逐个去赌客户端对 header 的解码。

        缺产物 / 体积超限的项**不让整单失败**，而是写进包里的
        `_未打包的项.txt`：批量下载最常见的场景就是"刚测完一批，
        大部分有报告、少数还没跑完"，整单 409 只会逼人一个个去挑。
        """
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        raw_ids: List[str] = []
        for raw in (qs.get("ids") or []) + (qs.get("id") or []):
            raw_ids.extend(x.strip() for x in raw.split(",") if x.strip())
        if not raw_ids:
            return self._err(400, "缺少 ids 参数（GET /api/reports/zip?ids=J1,J2）")

        # 去重但**保序**：调用方给的顺序就是压缩包里的顺序
        seen: set = set()
        ids: List[str] = []
        for x in raw_ids:
            if x not in seen:
                seen.add(x)
                ids.append(x)
        if len(ids) > MAX_ZIP_ITEMS:
            return self._err(400, "一次最多打包 %d 份（收到 %d 份），请分批下载"
                             % (MAX_ZIP_ITEMS, len(ids)))

        fmt = ((qs.get("fmt") or ["html"])[0] or "html").lower()
        # `brief` 不对应数据库字段（路径由 report_path 推导），所以单独一支；
        # 其余三种都是"某个字段指向一个文件"。
        if fmt == "brief":
            # 后缀加在详细版上：包里那份对外交出去的报告不带「简版」字样，
            # 说明文件里仍写「简版报告」—— 那是给我们自己看的对账口径。
            key, suffix, ext, what = "@brief", "", ".html", "简版报告"
        else:
            spec = {"html": ("report_path", "详细版", ".html", "详细报告"),
                    "json": ("result_path", "流程存档", ".json", "流程存档"),
                    "scan": ("scan_path", "采集存档", ".json", "采集存档")}.get(fmt)
            if not spec:
                return self._err(400, "fmt 只支持 html / brief / json / scan")
            key, suffix, ext, what = spec

        # zip 自身的名字跟着"对外那份不加后缀"走：批量下载简版时包名里也不写
        # 「简版」—— 收件人光看压缩包名就知道是删节版，那等于白改了正文。
        # 详细版反之，包名带「详细报告」（与文件后缀「_详细版」对齐）。
        zip_label = {"brief": "报告", "html": "详细报告"}.get(fmt, what)

        picked: List[Tuple[str, Path]] = []
        skipped: List[str] = []
        used: Dict[str, int] = {}
        total = 0
        for jid in ids:
            job = self.db.get(jid)
            if not job:
                skipped.append("%s  任务不存在" % jid)
                continue
            label = _app_label(job) or job.get("id") or jid
            why = "任务状态：%s" % (job.get("status") or "未知")
            if key == "@brief":
                p, berr = _ensure_brief(job)
                if berr:
                    why = berr
            else:
                src = job.get(key) or ""
                p = Path(src) if src else None
            if p is None or not p.exists():
                # 缺什么要说清：是"没跑完"还是"产物被删了"，复核时要能追
                skipped.append("%s（%s）  没有%s（%s）" % (jid, label, what, why))
                continue
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            if total + size > MAX_ZIP_BYTES:
                skipped.append("%s（%s）  未打包：累计体积超过 %d MB 上限"
                               % (jid, label, MAX_ZIP_BYTES // (1024 * 1024)))
                continue
            name = _report_filename(job, suffix, ext)
            if name in used:
                used[name] += 1
                stem, dot, e = name.rpartition(".")
                name = ("%s(%d)%s%s" % (stem, used[name], dot, e)
                        if dot else "%s(%d)" % (name, used[name]))
            else:
                used[name] = 1
            picked.append((name, p))
            total += size

        if not picked:
            return self._json({"ok": False, "skipped": skipped,
                               "error": "所选任务里没有可下载的%s" % what}, 409)

        buf = io.BytesIO()
        # compresslevel=6：报告里大量内联 base64 截图，deflate 大约压到六成；
        # 再往上收益很小而 CPU 明显变慢（上百份要多等好几秒）。
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for name, p in picked:
                try:
                    z.write(str(p), arcname=name)
                except OSError as e:
                    skipped.append("%s  读取失败：%s" % (name, e))
            if skipped:
                z.writestr("_未打包的项.txt", "\n".join(
                    ["打包时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"),
                     "已打包：%d 份%s" % (len(picked), what),
                     "未打包：%d 项" % len(skipped), ""] + skipped) + "\n")

        data = buf.getvalue()
        ts = time.strftime("%Y%m%d-%H%M%S")
        zip_name = "%s_%d份_%s.zip" % (zip_label, len(picked), ts)
        self._send(200, data, "application/zip",
                   {"Content-Disposition": _disposition(
                       zip_name, "PII-Reports-%s.zip" % ts)})

    # ------------------------------------------------------------ 环境自检
    def _preflight(self):
        """把"这台机器现在能不能测"变成一次接口调用。

        为什么平台也需要它：无人值守时最怕的状态是"任务排着队，但设备根本没连"。
        有了这个接口，调度方可以在提交任务前探一下，也可以把它接进监控。
        """
        from piiscan.config import AppConfig
        from piiscan import preflight

        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        _dflt = "1" if self.device_enabled else "0"
        need_dev = ((qs.get("device") or [_dflt])[0]).strip() not in ("0", "false", "")
        auto_fix = ((qs.get("fix") or ["1"])[0]).strip() not in ("0", "false", "")
        # 指定机自检：界面上每台机一个"自检"按钮。多机时不能只探"自动选中的那台" ——
        # 那台恰好是空闲的，而真要用的另一台可能根本没 root。
        want = ((qs.get("serial") or [""])[0]).strip()

        cfg = AppConfig()
        cfg_path = ROOT / "config.yaml"
        if cfg_path.exists():
            try:
                cfg = AppConfig.load(cfg_path)
            except Exception:
                pass
        if want:
            if getattr(cfg, "device", None) is None:
                from piiscan.config import DeviceConfig
                cfg.device = DeviceConfig()
            cfg.device.serial = want
        try:
            rep = preflight.run(cfg, log=lambda *_a: None,
                                auto_fix=auto_fix, need_device=need_dev)
            body = rep.to_dict()
            # 自检是真跑了一次提权（preflight 会验证 su 与 frida-server），
            # 这是"已 root"这个结论的唯一合法来源 —— 轮询探测不再执行 su。
            _s = str(body.get("serial") or want or "").strip()
            if rep.ok and _s:
                mark_root_verified(_s)
            return self._json({"ok": rep.ok, **body})
        except Exception as e:
            return self._json({"ok": False, "error": "%s: %s" % (type(e).__name__, e)})

    # ------------------------------------------------------------ 手机管理
    def _devices_registry(self):
        """已登记测试机 + 当前实时状态。界面「手机管理」页用它。

        ★ 为什么不能只返回登记簿：登记簿是历史记录（"这台机在某时刻接入过"），
          而界面要回答的是"现在能不能用"。拔了线、root 被撤销、被任务占用，
          这三件事在登记簿里都看不出来。
        ★ 也不能只返回实时设备列表：登记过但没插上的机器会整个消失，
          人会以为"我添加的手机不见了"，其实是拔了线。
          两边合并，缺一边都是错的。
        """
        try:
            entries = self.db.devices_list()
        except Exception as e:
            return self._err(500, "读取设备登记簿失败：%s: %s" % (type(e).__name__, e))
        try:
            live = {d["serial"]: d
                    for d in list_test_devices(getattr(self, "worker", None))}
        except Exception:
            live = {}

        out = []
        for e in entries:
            s = str(e.get("serial") or "")
            d = live.get(s) or {}
            online = (d.get("state") == "device")
            busy = bool(d.get("busy"))
            ok_root = bool(e.get("root_ok"))
            # 现在到底能不能用：登记时达标 + 此刻插着 + su 还在 + 没被占用。
            # ★ 直接取 list_test_devices 算好的 usable，不在这里再算一遍 ——
            #   两处各算一遍就是"状态页说可用、管理页说不可用"的来路。
            can = bool(d.get("usable"))
            if not online:
                reason = ("未连接（USB 未插、或 USB 调试未授权）" if not d
                          else "设备状态 %s" % (d.get("state") or "未知"))
            elif not ok_root:
                reason = "接入时 root 未通过（%s）" % (
                    "按你的要求仅登记信息" if e.get("degraded") else "当时无法提权")
            elif not d.get("root"):
                reason = "root 已失效：这台机上现在找不到 su（可能被刷回原厂或撤销了授权）"
            elif busy:
                reason = "被任务 %s 占用中" % (d.get("busy_job") or "其他任务")
            else:
                reason = "可用"
            out.append({
                "serial": s,
                "alias": e.get("alias") or "",
                "phone": e.get("phone") or "",
                "note": e.get("note") or "",
                "model": e.get("model") or d.get("model") or "",
                "brand": e.get("brand") or d.get("brand") or "",
                "android": e.get("android") or d.get("android") or "",
                "sdk": e.get("sdk") or d.get("sdk") or "",
                "abi": e.get("abi") or d.get("abi") or "",
                "frida_ver": e.get("frida_ver") or "",
                "added_at": e.get("added_at"),
                "verified_at": e.get("verified_at"),
                "root_ok": ok_root,
                "degraded": bool(e.get("degraded")),
                "last_steps": e.get("last_steps") or "",
                # ---- 实时 ----
                "online": online,
                "state": d.get("state") or "absent",
                "su": bool(d.get("root")),
                "root_verified": bool(d.get("root_verified")),
                "frida_ok": bool(d.get("frida_ok")),
                "frida": d.get("frida") or "",
                "busy": busy,
                "busy_job": d.get("busy_job") or "",
                "usable": can,
                "reason": reason,
            })
        # 插着但没登记的：给"一键添加"用。不混进上面那张表 ——
        # 那会让"已登记"这个状态失去意义。
        known = {e["serial"] for e in out}
        unmanaged = []
        for s, d in live.items():
            if s in known:
                continue
            unmanaged.append({
                "serial": s, "model": d.get("model") or "", "brand": d.get("brand") or "",
                "android": d.get("android") or "", "sdk": d.get("sdk") or "",
                "abi": d.get("abi") or "", "state": d.get("state") or "",
                "su": bool(d.get("root")), "frida_ok": bool(d.get("frida_ok")),
                "busy": bool(d.get("busy")), "busy_job": d.get("busy_job") or "",
            })
        return self._json({
            "ok": True, "devices": out, "unmanaged": unmanaged,
            # 登记簿为空时，任务下拉框退回"列出全部在线设备"（老行为）。
            # 一旦登记了至少一台，就只列登记的 —— 这是"管理"这件事的意义所在。
            "registry_count": len(out),
            "device_enabled": bool(self.device_enabled),
        })

    def _device_enroll(self):
        """开始接入一台手机。立刻返回会话 id，不等流程跑完。"""
        body = self._read_body_json()
        try:
            serial = _norm_device(body.get("serial"))
        except ValueError as e:
            return self._err(400, str(e))
        if not serial:
            return self._err(400, "请先选择要添加的设备")
        # 正在跑的任务用着它就不许接入：接入会 push 二进制、重启 frida-server、
        # 还会把屏幕点亮解锁 —— 任何一项都会打断正在采集的那一轮。
        try:
            live = {d["serial"]: d for d in
                    list_test_devices(getattr(self, "worker", None))}
        except Exception:
            live = {}
        d = live.get(serial) or {}
        if d.get("busy"):
            return self._err(409, "这台设备正被任务 %s 占用，等它跑完再添加"
                             % (d.get("busy_job") or "其他任务"))
        if (d and d.get("state") != "device"
                and d.get("state") != "unauthorized"):
            # unauthorized 允许继续：流程会等用户在手机上点「允许」。
            # 其它异常状态（offline/absent）也允许进流程 —— 流程里同样会等，
            # 而且能给出针对该状态的具体提示，比在这里一句"设备不可用"有用。
            pass
        alias = str(body.get("alias") or "").strip()[:40]
        phone = str(body.get("phone") or "").strip()
        if phone:
            try:
                phone = _norm_phone(phone)
            except ValueError as e:
                return self._err(400, str(e))
        note = str(body.get("note") or "").strip()[:200]
        # ★ 重新接入一台已登记的机器时，表单里没填的项要沿用旧值。
        #   不沿用的话，"重新接入一次"会把之前填好的号码悄悄清空 ——
        #   而号码是"选这台机跑任务时自动带上的登录号"，清空之后症状只是
        #   "登录超时"，没人会想到是这里丢的。
        try:
            old = self.db.device_get(serial) or {}
        except Exception:
            old = {}
        if not alias:
            alias = str(old.get("alias") or "")
        if not phone:
            phone = str(old.get("phone") or "")
        if not note:
            note = str(old.get("note") or "")
        force = bool(_as_bool(body.get("force")))
        # 是否允许联网下载 frida-server。默认允许，内网部署可以关掉。
        allow_dl = body.get("allow_download")
        allow_download = True if allow_dl is None else _as_bool(allow_dl)
        try:
            snap = start_enroll(self.db, serial, alias=alias, phone=phone, note=note,
                                force=force, allow_download=allow_download)
        except Exception as e:
            return self._err(500, "创建接入会话失败：%s: %s" % (type(e).__name__, e))
        return self._json(dict(snap, ok=True), 202)

    def _device_meta(self, serial: str):
        """改别名 / 号码 / 备注。不动"上次验证"那类事实字段。"""
        body = self._read_body_json()
        phone = body.get("phone")
        if phone:
            try:
                phone = _norm_phone(phone)
            except ValueError as e:
                return self._err(400, str(e))
        try:
            r = self.db.device_meta(
                serial,
                alias=body.get("alias"),
                phone=phone,
                note=body.get("note"))
        except Exception as e:
            return self._err(500, "%s: %s" % (type(e).__name__, e))
        if not r.get("ok"):
            return self._err(404, r.get("error") or "更新失败")
        return self._json({"ok": True, "device": r.get("device")})

    def _device_delete(self, serial: str):
        """从平台移除一台测试机。不动设备本身。"""
        try:
            live = {d["serial"]: d for d in
                    list_test_devices(getattr(self, "worker", None))}
        except Exception:
            live = {}
        d = live.get(serial) or {}
        if d.get("busy"):
            return self._err(409, "这台设备正被任务 %s 占用，等它跑完再移除"
                             % (d.get("busy_job") or "其他任务"))
        try:
            r = self.db.device_delete(serial)
        except Exception as e:
            return self._err(500, "%s: %s" % (type(e).__name__, e))
        if not r.get("ok"):
            return self._err(404, r.get("error") or "移除失败")
        return self._json({
            "ok": True, "serial": serial,
            # 说清"没有动设备"：否则人会以为删掉手机就等于把手机清空了，
            # 下次插上时对着还在跑的 frida-server 一头雾水。
            "note": "已从平台移除。设备本身未做任何改动（frida-server 仍在运行、"
                    "USB 调试授权与设备上的文件都保留）。",
        })

    # ================================================================ AI 配置
    def _ai_profiles_list(self):
        try:
            items = self.db.ai_profiles()
            active = self.db.ai_active_id()
        except Exception as e:
            return self._err(500, "读取 AI 配置失败：%s: %s" % (type(e).__name__, e))
        return self._json({
            "ok": True,
            "profiles": [ai_profile_out(p, active) for p in items],
            "active": active,
            "count": len(items),
            "catalog": AI_PROVIDER_CATALOG,
            # 说明"当前有没有 AI"。前端据此显示"未启用 → 全部走确定性策略"，
            # 而不是让使用者以为保存过就一定会用上。
            "enabled": bool(active),
        })

    def _ai_profile_save(self):
        body = self._read_body_json()
        pid = str(body.get("id") or "").strip()
        name = str(body.get("name") or "").strip()
        if not name:
            raise ValueError("请给这套配置起个名字（列表里靠它区分，例如「本机 Ollama」「DeepSeek」）")
        provider = _norm_ai_provider(body.get("provider"))
        base_url = str(body.get("base_url") or "").strip()
        model = str(body.get("model") or "").strip()
        vision_model = str(body.get("vision_model") or "").strip()
        note = str(body.get("note") or "").strip()

        if base_url and not re.match(r"^https?://", base_url, re.I):
            raise ValueError("服务地址需以 http:// 或 https:// 开头：%r" % base_url[:80])
        if provider in ("ollama", "deepseek", "openai") and not model:
            raise ValueError("请填写模型名（DeepSeek 是 deepseek-flash 或 deepseek-v4-pro，"
                             "Ollama 是 `ollama list` 里显示的那个名字）")
        # DeepSeek 按模型分视觉能力：能看图的是 deepseek-flash。存盘前把名字统一一次，
        # 让列表上写的模型 = 实际会被调用的模型（否则报告里写 deepseek-chat、
        # 网络上打的却是 deepseek-flash，对不上）。
        if provider == "deepseek":
            from piiscan.ai.providers import DeepSeekProvider as _DSP
            from piiscan.config import AIConfig as _AIC
            _probe = _DSP(_AIC(provider="deepseek", base_url=base_url,
                               model=model, vision_model=vision_model))
            model = _probe._model() or model
            vision_model = _probe._model(vision=True)
        # 密钥：字段缺省 = 不改（编辑时不重填就沿用旧值）；显式传空串 = 清掉。
        api_key = body.get("api_key", None) if "api_key" in body else None
        if api_key is not None:
            api_key = str(api_key or "").strip()
        old = self.db.ai_profile(pid) if pid else None
        have_key = bool((api_key if api_key is not None else (old or {}).get("api_key")))
        if provider == "deepseek" and not have_key:
            raise ValueError("DeepSeek 需要 API 密钥（在 deepseek.com 控制台创建后填在这里）。"
                             "没有密钥时请求会直接 401，不如现在就别保存。")
        try:
            pid = self.db.ai_profile_save(
                pid=pid, name=name, provider=provider, base_url=base_url,
                model=model, vision_model=vision_model, note=note, api_key=api_key)
        except ValueError as e:
            raise e
        except Exception as e:
            return self._err(500, "保存 AI 配置失败：%s: %s" % (type(e).__name__, e))

        activate = body.get("activate", True)
        if activate:
            self.db.ai_set_active(pid)
        p = self.db.ai_profile(pid) or {}
        return self._json({
            "ok": True,
            "id": pid,
            "profile": ai_profile_out(p, self.db.ai_active_id()),
            "active": self.db.ai_active_id() == pid,
            "note": ("已保存并启用「%s」。新提交的任务会立刻用它；"
                     "正在运行的任务仍用启动时加载的配置。" % name
                     if activate else "已保存「%s」（未启用）" % name),
        })

    def _ai_profile_activate(self, pid: str):
        try:
            self.db.ai_set_active(pid)
        except ValueError as e:
            return self._err(404, str(e))
        except Exception as e:
            return self._err(500, "%s: %s" % (type(e).__name__, e))
        p = self.db.ai_profile(pid) or {}
        return self._json({
            "ok": True, "id": pid,
            "profile": ai_profile_out(p, pid),
            "note": "已启用「%s」。新提交的任务立即使用；"
                    "正在运行的任务不会中途换模型（那会让一份报告里混两种模型）。"
                    % (p.get("name") or pid),
        })

    def _ai_active_set(self):
        """启用 / 停用。`{"id": ""}` = 停用全部（AI 完全关闭）。"""
        body = self._read_body_json()
        pid = str(body.get("id") or "").strip()
        try:
            self.db.ai_set_active(pid)
        except ValueError as e:
            return self._err(404, str(e))
        except Exception as e:
            return self._err(500, "%s: %s" % (type(e).__name__, e))
        if not pid:
            return self._json({
                "ok": True, "id": "",
                "note": "已停用全部 AI 配置。之后的检测全部走确定性策略"
                        "（关键词 + 结构树），报告照常生成；随时可以再启用一套。",
            })
        p = self.db.ai_profile(pid) or {}
        return self._json({
            "ok": True, "id": pid, "profile": ai_profile_out(p, pid),
            "note": "已启用「%s」。新提交的任务立即使用；正在运行的任务不会中途换模型"
                    "（那会让一份报告里混两种模型）。" % (p.get("name") or pid),
        })

    def _ai_profile_delete(self, pid: str):
        try:
            r = self.db.ai_profile_delete(pid)
        except Exception as e:
            return self._err(500, "%s: %s" % (type(e).__name__, e))
        if not r.get("ok"):
            return self._err(404, r.get("error") or "删除失败")
        note = "已删除「%s」。" % r.get("name")
        if r.get("was_active"):
            # 这条必须说清楚：删掉的正好是正在用的那份，AI 就彻底关了。
            note += ("它正是当前启用的配置，删除后没有启用的 AI 配置 —— "
                     "AI 环节全部回退到确定性策略（关键词 + 结构树），报告照常生成。")
        return self._json({"ok": True, "was_active": bool(r.get("was_active")),
                           "note": note})

    def _ai_profile_test(self, pid: str):
        """探测一套配置现在能不能用。不写 last_used_at（没跑过检测就不算用过）。"""
        p = self.db.ai_profile(pid)
        if not p:
            return self._err(404, "这条 AI 配置不存在（可能已被删除）")
        provider = (p.get("provider") or "").strip().lower()
        base = (p.get("base_url") or "").strip()
        model = (p.get("model") or "").strip()
        key = (p.get("api_key") or "").strip()
        if provider == "ollama" and not base:
            base = "http://127.0.0.1:11434"
        if provider == "deepseek" and not base:
            base = "https://api.deepseek.com"

        # ---- Agent 中继：不连任何服务，只看目录能不能建 ----
        if provider in ("agent", "relay"):
            try:
                from piiscan.ai.factory import build_ai
                from piiscan.config import AIConfig
                ai = AIConfig(provider="agent", base_url=base, model=model)
                prov = build_ai(ai)
                ok = bool(prov.available())
            except Exception as e:
                return self._json({"ok": False, "error": "配置无效：%s" % e})
            return self._json({"ok": ok, "reachable": ok, "relay": True,
                               "vision_hint": "Agent 中继：由对话里的 AI 亲自看图作答",
                               "error": "" if ok else "无法创建中继目录，请检查写权限"})

        # ---- 云端 / OpenAI 兼容：单独探测，才能区分"密钥错"和"连不上" ----
        if provider in ("deepseek", "openai"):
            import urllib.error
            import urllib.request as _ur
            url = base.rstrip("/") + ("/models" if base.rstrip("/").endswith("/v1")
                                      else "/v1/models")
            err, reachable = "", False
            models: List[str] = []
            try:
                req = _ur.Request(url)
                if key:
                    req.add_header("Authorization", "Bearer " + key)
                with _ur.urlopen(req, timeout=8) as resp:
                    reachable = 200 <= resp.status < 300
                    try:
                        data = json.loads(resp.read().decode("utf-8", "replace"))
                        models = [str(m.get("id") or "") for m in (data.get("data") or [])
                                  if isinstance(m, dict)]
                    except Exception:
                        models = []
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode("utf-8", "replace")[:200]
                except Exception:
                    pass
                if e.code in (401, 403):
                    err = ("密钥被拒绝（HTTP %s）。请确认密钥是否有效、是否已过期。%s"
                           % (e.code, (" 服务端返回：" + body) if body else ""))
                else:
                    err = "服务返回 HTTP %s %s%s" % (e.code, e.reason,
                                                     ("：" + body) if body else "")
            except Exception as e:
                err = "连不上 %s：%s: %s" % (base, type(e).__name__, e)
            if reachable:
                if provider == "deepseek":
                    # 视觉能力按模型区分（2026-11-12 按官方文档修正）：
                    # deepseek-flash 能看图，deepseek-v4-pro 不能。别再说"整家不支持"。
                    vm = (p.get("vision_model") or "").strip() or "deepseek-flash"
                    if vm == "deepseek-v4-pro":
                        vh = ("注意：视觉模型填成了 deepseek-v4-pro，它**不接受图片输入**，"
                              "带图调用会报错。视觉环节请改用 deepseek-flash"
                              "（平台会在调用时自动改用它，但界面显示要对得上）。")
                    elif model == "deepseek-v4-pro" and not (p.get("vision_model") or "").strip():
                        vh = ("文本模型 deepseek-v4-pro 只读文本；视觉环节平台会自动改用 "
                              "deepseek-flash，两项看图功能照常可用。")
                    else:
                        vh = ("DeepSeek 支持图片输入（deepseek-flash）："
                              "「看截图识别政策入口」「AI 指挥遍历」都能用；"
                              "deepseek-v4-pro 则只读文本。")
                else:
                    vh = ("是否支持图片由服务端模型决定，平台无法从接口核实；"
                          "若视觉环节回退，请确认该模型是多模态的。")
                hit = model in models if models else None
                return self._json({
                    "ok": True, "reachable": True, "model": model,
                    "model_exists": hit, "models": models[:30],
                    "vision_hint": vh,
                    "note": ("服务可达，模型列表里%s「%s」"
                             % ("有" if hit else "没看到", model) if models and model
                             else "服务可达"),
                })
            return self._json({"ok": False, "reachable": False, "models": [],
                               "error": err or "连接失败"})

        # ---- Ollama：三层（可达 / 模型在不在 / 能力与上下文） ----
        try:
            from piiscan.ai.factory import build_ai
            from piiscan.config import AIConfig
            ai = AIConfig(provider="ollama", base_url=base, model=model,
                          vision_model=(p.get("vision_model") or ""))
            prov = build_ai(ai)
            reachable = bool(prov.available())
        except Exception as e:
            return self._json({"ok": False, "error": "配置无效：%s" % e})
        if not reachable:
            return self._json({
                "ok": False, "reachable": False,
                "error": "无法连接 %s。请确认 Ollama 已启动（`ollama serve`）、"
                         "地址与端口正确。" % base})
        probe = _ollama_probe(ai, model)
        if not probe.get("exists"):
            models = _list_models(ai)
            return self._json({
                "ok": False, "reachable": True, "model": model,
                "model_exists": False, "models": models[:30],
                "error": "服务可达，但模型「%s」没有部署到这台 Ollama（%s）。%s"
                         "先 `ollama pull %s`，或把模型名改成已有的一个。"
                         % (model, probe.get("error") or "查无此模型",
                            ("服务端现有：%s。" % "、".join(models[:6])) if models else "",
                            model)})
        vm = (p.get("vision_model") or "").strip() or model
        caps = [str(c).lower() for c in (probe.get("capabilities") or [])]
        if vm and vm != model:
            vp = _ollama_probe(ai, vm)
            caps = [str(c).lower() for c in (vp.get("capabilities") or [])] if vp.get("exists") else []
            if not vp.get("exists"):
                return self._json({
                    "ok": True, "reachable": True, "model": model,
                    "model_exists": True, "models": [],
                    "vision_hint": "⚠ 视觉模型「%s」没有部署，视觉环节会回退到规则策略" % vm,
                    "note": "文本模型可用；视觉模型需单独 pull"})
        vh = ("「%s」支持图片输入（模型能力清单确认 ✓）" % vm if "vision" in caps
              else "「%s」的模型能力清单里没有 vision —— 视觉环节会回退到规则策略" % vm
              if caps else _vision_hint(vm))
        return self._json({
            "ok": True, "reachable": True, "model": model, "model_exists": True,
            "num_ctx": int(probe.get("num_ctx") or 0),
            "capabilities": probe.get("capabilities") or [],
            "vision_hint": vh, "note": "服务与模型均正常",
        })

    def _create_job(self):
        ctype = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ValueError("请求体为空")

        if ctype.startswith("multipart/form-data"):
            if length > self.max_upload:
                raise ValueError("上传体积超过上限 %.0f MB" % (self.max_upload / 1048576.0))
            # 上传的文件先落到存储目录的 .incoming 下：与正式目录同盘，
            # 收进去时是一次 rename，不再复制第二份几百 MB 的副本。
            # ★ 存储目录在这里就要校验：不可写必须现在失败，
            #   而不是等 worker 跑到下载/归档那一步才报错 —— 那时任务已经排上队了。
            from piiscan import apkstore
            _store = apk_store_root(self.db, self.workdir)
            save_dir = apkstore.incoming_dir(_store)
            fields = parse_multipart(self.rfile, ctype, length, save_dir, self.max_upload)
            # 前端 URL 模式同样走 FormData（只带 apk_url 字段，不带文件），
            # 所以这里必须先判有没有文件，不能无条件要求 apk_file。
            apk = fields.get("apk_file") or fields.get("file")
            _rd = fields.get("run_dynamic")
            store_text = str(fields.get("store_urls") or "").strip()
            # 先解析设备：默认手机号要按"这次跑哪台"来取 —— 不能先生成一个跟
            # 本机无关的号再去跑另一台机的 App，那样验证码永远收不到。
            # ★ 设备解析必须排在 login_phone 之前（2026-11-11）：只有一台时
            #   平台会替你把序列号定死，若号还是按"没选机"取全局默认，
            #   就等于拿另一张卡的号去登录这台机上的 App —— 验证码到不了。
            _run_dyn = resolve_dynamic(
                None if _rd is None else (_as_bool(_rd)), self.device_enabled)
            _dev = self._resolve_device(_norm_device(fields.get("device")), _run_dyn)
            common = dict(
                policy_url=str(fields.get("policy_url") or "").strip(),
                policy_text=str(fields.get("policy_text") or "").strip(),
                run_dynamic=_run_dyn,
                duration=int(str(fields.get("duration") or 90) or 90),
                reset_app=str(fields.get("reset_app", "1")) not in ("0", "false", ""),
                policy_wait=int(str(fields.get("policy_wait") or 22) or 22),
                login_phone=_norm_phone(fields.get("login_phone",
                                                  _default_login_phone_for(_dev))),
                repro=str(fields.get("repro", "1")) not in ("0", "false", "off", "no", ""),
                depth=_norm_depth(fields.get("depth")),
                device=_dev,
                ai_opts=collect_ai_opts(fields),
            )
            if apk and apk.get("path"):
                # 内容哈希决定它落在存储目录的哪个位置：同一个包再传一次
                # 只会复用已有文件，不会多占一份。哈希与 apk_path 一起入库，
                # 仍然是"一条 INSERT 落地"，不留 worker 抢先的空窗。
                from piiscan import apkfetch
                h = apkfetch.hash_file(apk["path"])
                _path, _rt = apk_store_adopt(self.db, self.workdir, apk["path"],
                                             apk["filename"], h["sha256"])
                # 一次性写入，不给 worker 留「字段还没补全就被取走」的窗口
                job_id = self.db.create(
                    source="upload", apk_name=apk["filename"],
                    apk_path=_path, apk_store=_rt,
                    apk_size=int(apk.get("size") or 0),
                    md5=h["md5"], sha256=h["sha256"],
                    **common)
            elif store_text:
                # 批量：一行一个商店链接，按提交顺序逐个排队
                return self._create_store_jobs(store_text, common)
            else:
                url = str(fields.get("apk_url") or "").strip()
                if not url:
                    raise ValueError("未收到 APK 文件，也没有填写下载链接")
                if not re.match(r"^https?://", url, re.I):
                    raise ValueError("下载链接必须以 http:// 或 https:// 开头")
                job_id = self.db.create(
                    source="url", apk_url=url,
                    apk_name=os.path.basename(urllib.parse.urlparse(url).path) or "remote.apk",
                    **common)
        else:
            raw = self.rfile.read(min(length, 4 * 1024 * 1024))
            try:
                data = json.loads(raw.decode("utf-8"))
            except Exception:
                raise ValueError("请求体不是合法 JSON")
            # 与 multipart 分支同序：先定死跑哪台，再按那台取默认号（见上方注释）
            _run_dyn = resolve_dynamic(
                None if "run_dynamic" not in data else bool(data.get("run_dynamic")),
                self.device_enabled)
            _dev = self._resolve_device(_norm_device(data.get("device")), _run_dyn)
            common = dict(
                policy_url=(data.get("policy_url") or "").strip(),
                policy_text=(data.get("policy_text") or "").strip(),
                run_dynamic=_run_dyn,
                duration=int(data.get("duration") or 90),
                reset_app=bool(data.get("reset_app", True)),
                policy_wait=int(data.get("policy_wait") or 22),
                login_phone=_norm_phone(data.get("login_phone",
                                                 _default_login_phone_for(_dev))),
                repro=bool(data.get("repro", True)),
                depth=_norm_depth(data.get("depth")),
                device=_dev,
            )
            store_text = data.get("store_urls")
            if isinstance(store_text, (list, tuple)):
                store_text = "\n".join(str(x) for x in store_text)
            store_text = (store_text or "").strip()
            if store_text:
                return self._create_store_jobs(store_text, common)
            url = (data.get("apk_url") or "").strip()
            if not url:
                raise ValueError("请填写 APK 下载链接")
            if not re.match(r"^https?://", url, re.I):
                raise ValueError("下载链接必须以 http:// 或 https:// 开头")
            job_id = self.db.create(
                source="url", apk_url=url,
                apk_name=os.path.basename(urllib.parse.urlparse(url).path) or "remote.apk",
                **common)
        self.db.append_log(job_id, "[*] 任务已创建，等待执行")
        self._note_device_choice(job_id, common.get("device") or "")
        self._json({"ok": True, "job_id": job_id}, 201)

    def _resolve_device(self, dev: str, run_dynamic: bool) -> str:
        """提交那一刻把"这次用哪台机"定死，并把登记簿当唯一口径。

        三件事，每件都是当场就能确定的事实，不该拖到开跑后才发现：
        ① 指定的序列号没登记（含"刚被移除"）→ 拒绝。否则平台会继续用一台
           用户已经宣布不用的手机跑任务，而报告上看不出来 —— 2026-11-11 的
           "两台都移除了，状态页还写 2 台可用"就是这个洞的界面表现。
        ② 动态采集却没指定 → **一律拒绝**，哪怕此刻只插着一台。
           2026-11-11 用户指定："不要哪个手机是默认，必须自己选。"
           这条不是啰嗦：报告里的设备指纹是证据的一部分，设备由人明确指定
           才叫"这次在这台上测的"；替用户定，等于替他签了个字。
        ③ 一台都没登记/没在线 → 拒绝，并告诉人去哪儿添加。动态采集没有设备
           是跑不了的，与其排队后失败，不如现在说清楚。

        返回最终序列号；不需要设备时返回空串。
        """
        dev = (dev or "").strip()
        try:
            reg = self.db.devices_list() or []
        except Exception:
            reg = []
        reg_serials = {str(e.get("serial") or "") for e in reg}

        if dev:
            if dev not in reg_serials:
                raise ValueError(
                    "设备 %s 没有在平台登记（可能刚被移除）。"
                    "去「手机管理」把它重新添加，或换一台已登记的测试机。" % dev)
            return dev

        if not run_dynamic:
            return ""
        try:
            devs = list_test_devices(getattr(self, "worker", None))
        except Exception:
            devs = []
        # 只看已登记的：未登记的机器仍然插在电脑上，但"平台该不该用它"由登记簿决定。
        online = [d for d in devs if d.get("state") == "device" and d.get("managed")]
        if not online:
            raise ValueError(
                "还没有已登记、且此刻在线的测试机。动态采集必须先有一台测试机："
                "去「手机管理」点「添加手机」，平台会自动识别插在电脑上的设备、"
                "检查调试与 root 并部署 frida-server。")
        raise ValueError(
            "请先在「测试机」里选一台（当前已登记且在线的有 %d 台：%s）。"
            "报告里的设备信息取自你选的那台，程序替你选会让报告与实机对不上，"
            "而这种错误从报告上查不出来。"
            % (len(online), "、".join("%s %s" % (d.get("alias") or d.get("model") or d["serial"],
                                                d["serial"]) for d in online)))

    def _note_device_choice(self, job_id: str, dev: str) -> None:
        """把"这个任务将跑在哪台机上"写进日志。

        只在**确实指定**时写。不指定是一项静默行为（回落 config.yaml / 自动），
        这种"没选"不该在每个任务的日志里都占一行；而一旦选了却没插上，
        必须当场说清楚，否则用户会等到任务失败才发现选错机器。
        """
        if not dev:
            return
        try:
            devs = list_test_devices(getattr(self, "worker", None))
        except Exception:
            devs = []
        hit = next((d for d in devs if d["serial"] == dev), None)
        if hit is None:
            self.db.append_log(
                job_id, "[!] 指定测试机 %s 当前不在 adb 设备列表里；"
                        "任务会照常排队，执行前会重新检查（届时仍不在线则以"
                        "「目标设备在线」一项失败并写明原因）" % dev)
            return
        if hit["state"] != "device":
            self.db.append_log(
                job_id, "[!] 指定测试机 %s 状态为 %s（%s）；执行前会再检查一次"
                        % (dev, hit["state"], hit.get("note") or "不可用"))
            return
        self.db.append_log(
            job_id, "[*] 指定测试机：%s（%s / Android %s / %s）"
                    % (hit["model"] or dev, dev, hit["android"] or "?",
                       "已 root" if hit.get("root_verified")
                       else ("su 可用（开跑前自检会验证提权）" if hit.get("root")
                             else "未 root，动态采集不可用")))

    def _submit_sms(self, job_id: str) -> None:
        """把人工收到的短信验证码交给正在跑的采集线程。

        ★ 为什么是"写文件"而不是"存进任务表让采集线程查"
          采集线程在登录页上要每 2~3 秒问一次"码来了吗"，一次登录能问上百次。
          让它查库，等于把 SQLite 打成热表，还会和任务状态更新抢写锁；
          而验证码本质就是**一次性、只在本次任务内有效**的一个值，
          落在工作目录的 sms.txt 里，采集线程读完即删，代价几乎为零。

        ★ 只接受"检测中"的任务
          任务没跑起来时写进去的文件会在真正登录时被当成刚收到的码用掉，
          而那条码早就过期了 —— 结果是一次注定失败的登录，报告上却写着
          "已尝试用测试号登录"。宁可当场 409，让人等采集跑到登录页再填。
        """
        job = self.db.get(job_id)
        if not job:
            return self._err(404, "任务不存在")

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 64 * 1024)) if length > 0 else b""
        obj: Dict[str, Any] = {}
        if raw:
            try:
                obj = json.loads(raw.decode("utf-8"))
            except Exception:
                qs = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
                obj = {k: v[0] for k, v in qs.items() if v}
        code = re.sub(r"\s", "", str(obj.get("code") or obj.get("sms") or ""))
        if not re.fullmatch(r"\d{4,8}", code):
            raise ValueError("验证码应为 4~8 位数字（收到的是 %r）"
                             % (str(obj.get("code") or "")[:20]))

        st = job.get("status") or ""
        if st != "running":
            from .db import STATUS_LABELS
            return self._err(409, "任务当前状态为「%s」，没有在等待验证码；"
                                  "请等采集跑到登录页、日志出现「需要短信验证码」后再填"
                             % STATUS_LABELS.get(st, st))

        wd = Path(job.get("workdir") or (self.workdir / job_id))
        wd.mkdir(parents=True, exist_ok=True)
        (wd / "sms.txt").write_text(code + "\n", encoding="utf-8")
        self.db.append_log(job_id, "[*] 已收到人工回填的短信验证码（%s 位），"
                                   "采集线程会在下一次轮询时取走" % len(code))
        return self._json({"ok": True, "note": "验证码已送达，采集线程将在数秒内取用"})

    def _create_store_jobs(self, text: str, common: Dict[str, Any]) -> None:
        """把多行应用商店链接拆成多个任务，按提交顺序逐个排队。

        ★ 这里只做本地就能判断的校验（是不是 http 链接、是不是受支持的市场、
          本批次是否重复）。真正的"能不能下到"必须访问市场才知道，放在 worker
          里做 —— 提交接口不能因为某个市场响应慢就把用户卡在那儿，
          而且下不到的原因要落进那一条任务的日志里，而不是一个弹窗里一闪而过。
        """
        from piiscan import storefetch

        urls, skipped = storefetch.parse_url_list(text)
        if not urls:
            detail = "；".join("%s（%s）" % (s["url"][:60], s["reason"])
                               for s in skipped[:3])
            raise ValueError("没有可提交的应用商店链接，每行一个应用商店详情页地址。%s"
                             % ("已跳过：" + detail if detail else ""))

        ids = []
        for u in urls:
            market = storefetch.pick_adapter(u)[0]
            jid = self.db.create(source="store", store_url=u, apk_name=u, **common)
            self.db.append_log(jid, "[*] 已排队（%s）：%s" % (market, u))
            self._note_device_choice(jid, common.get("device") or "")
            ids.append(jid)
        self._json({"ok": True, "job_id": ids[0], "job_ids": ids,
                    "created": len(ids), "skipped": skipped}, 201)


# ============================================================================
#  启动
# ============================================================================

class Watchdog(threading.Thread):
    """盯着「看起来还在跑」的任务：进度不动就写日志、抓线程栈，必要时强制收工。

    ★ 为什么现在必须会"动手"（2026-11-11 真机事故）
      旧版本只会写一句"已 N 分钟没有更新"。可那天的任务不是"慢"，是**卡死**：
      停在「复现采集 89%」后 95 分钟零日志，用户点两次停止都没反应，只能关服务。
      根因是 frida 的同步 RPC 在目标进程冻结时永远不返回（可复现，见
      `piiscan/frida_guard.py` 头部），采集线程连一次 `should_stop()` 都执行不到。
      这种情况下"只提醒不动手"等于把判断责任推给用户，而他连该杀谁都不知道。

    ★ 三层，按时间升级，每一层都留证据
      1. 10 分钟没动静 → 写提醒，并把**工作线程的调用栈**打进任务日志。
         没有栈，下一次还是只能靠猜；有了栈，"卡在哪个函数"一眼可见。
      2. 20 分钟没动静，或已请求停止却 90 秒不退 → 强制停止：置标记、
         异步 detach、`am force-stop` 被测应用（唯一实测能解开冻结 RPC 的手段）。
      3. 强制后 5 分钟仍不退出 → 硬收尾：按「已停止」记账并明确写出
         "设备独占权仍被卡住的线程持有，请重启服务"。

    ★ 仍然不按"慢"判死
      判据只有"多久没有任何日志/进度"，与阶段、百分比无关 ——
      遍历天然是"数字慢慢爬、日志一直在刷"，那种任务不会被误伤。
    """

    POLL_S = 15
    # 超过这个时间**既没有进度变化、也没有任何一行日志**才算异常。
    # 只看百分比是不够的：遍历阶段天然是"数字慢慢爬、日志一直在刷"，
    # 拿百分比当死活判据会把正在干活的任务判成卡死（用户 2026-10-21 提的第二条）。
    STALL_S = 600          # 10 分钟完全没有任何动静 → 提醒 + 抓栈
    FORCE_S = 1200         # 20 分钟仍无动静 → 强制收工
    CANCEL_QUIET_S = 45    # 已请求停止，且 45 秒没有任何日志 → 判定卡死
    HARD_S = 300           # 强制后再等 5 分钟仍无响应 → 硬收尾
    REPEAT_S = 300         # 同一任务最多每 5 分钟提醒一次，避免刷屏

    def __init__(self, db: JobDB, worker: Optional["Worker"] = None):
        super().__init__(daemon=True, name="piiscan-watchdog")
        self.db = db
        self.worker = worker
        self._last: Dict[str, float] = {}
        self._forced_at: Dict[str, float] = {}

    @staticmethod
    def _worker_stack(max_lines: int = 8) -> str:
        """把工作线程当前的调用栈抓出来。

        这是把"神秘卡死"变成"卡在 XXX 函数"的唯一低成本手段。只抓
        `piiscan-worker`，不抓看门狗自己（它永远停在 time.sleep）。
        """
        try:
            frames = sys._current_frames()          # noqa: SLF001  诊断用
        except Exception:
            return ""
        out = []
        for th in threading.enumerate():
            if th.name != "piiscan-worker":
                continue
            fr = frames.get(th.ident)
            if fr is None:
                continue
            lines = traceback.format_stack(fr)[-max_lines:]
            out.append("线程 %s 的调用栈（末 %d 层）：\n%s"
                       % (th.name, max_lines, "".join(lines)))
        return "\n".join(out)

    def _note(self, job_id: str, msg: str) -> None:
        try:
            # live=False：这是提醒本身，不能把自己的提醒算成"还活着"
            self.db.append_log(job_id, msg, live=False)
        except Exception:
            pass
        print("[watchdog] %s %s" % (job_id, msg.splitlines()[0] if msg else ""))

    def _force(self, job: Dict[str, Any], reason: str) -> None:
        jid = job["id"]
        if self.worker is None:
            return
        if not self.worker.is_forced(jid):
            self._forced_at[jid] = time.time()
            try:
                self.worker.force_stop(jid, reason)
            except Exception as e:
                self._note(jid, "[!] 强制停止失败：%s: %s" % (type(e).__name__, e))
            return
        # 已经强制过：还在 running 说明线程没被解开 → 硬收尾
        t0 = self._forced_at.get(jid, time.time())
        if time.time() - t0 < self.HARD_S:
            return
        msg = ("[!] 强制停止后已过 %d 分钟，采集线程仍未退出。任务按「已停止」记账，"
               "但**设备独占权仍被那个卡住的线程持有** —— 后续任务会停在"
               "「等待设备」。请重启服务（重启会释放设备锁，已在跑的证据不会丢）。"
               % int((time.time() - t0) // 60))
        self._note(jid, msg)
        try:
            self.db.update(jid, status="canceled", stage="已停止（线程无响应）",
                           progress=100, finished_at=time.time(),
                           error=msg, req="")
        except Exception:
            pass

    def run(self):
        while True:
            time.sleep(self.POLL_S)
            try:
                self.sweep()
            except Exception as e:                  # 看门狗自己绝不能挂
                print("[watchdog] 本轮检查异常（已忽略）：%s: %s"
                      % (type(e).__name__, e))

    def sweep(self) -> None:
        """走一遍所有在跑的任务，按规则提醒 / 强制收工。"""
        try:
            jobs = self.db.list(30)
        except Exception:
            return
        now = time.time()
        running = {j["id"] for j in jobs if j.get("status") == "running"}
        for k in list(self._forced_at):
            if k not in running:
                self._forced_at.pop(k, None)

        for j in jobs:
            if j.get("status") != "running":
                continue
            jid = j["id"]
            stall = int(j.get("stall") or 0)
            req = (j.get("req") or "").strip()

            # ---- 停止请求送不进去 → 心跳停了才算卡住 ----
            if req == "cancel":
                # 已经强制过还在跑：交给 `_force` 判断是否该硬收尾。
                if self.worker is not None and self.worker.is_forced(jid):
                    self._force(j, "已请求停止，但线程仍未退出")
                    continue
                # ★ 判据用**心跳**，不是"点了停止多久"。
                #   真机实测（2026-11-11）：点停止后线程正常收尾（卸载、写存档），
                #   但走完要 90 秒；拿时间当判据会把它误判成"卡在设备调用里"，
                #   在收尾阶段又去 force-stop 一次。心跳不动才说明真的卡住了。
                if stall >= self.CANCEL_QUIET_S:
                    self._force(
                        j, "已请求停止，但连续 %d 秒没有任何日志"
                           "（线程卡在设备调用里）" % stall)
                continue

            if stall < self.STALL_S:
                continue

            # ---- 长时间零输出 → 强制 ----
            if stall >= self.FORCE_S:
                self._force(j, "已连续 %d 分钟没有任何日志或进度更新"
                               "（疑似应用黑屏/无响应）" % (stall // 60))
                continue

            if now - self._last.get(jid, 0) < self.REPEAT_S:
                continue
            self._last[jid] = now
            msg = ("[!] 已 %d 分钟没有任何日志或进度更新（阶段：%s，%d%%）。"
                   "任务仍在运行状态，若持续无输出请检查设备连接与 uiautomator 进程；"
                   "必要时停止任务后重试。注：遍历阶段百分比变化慢属正常，"
                   "只要日志仍在滚动即代表正在遍历。"
                   % (stall // 60, j.get("stage") or "?", j.get("progress") or 0))
            stack = self._worker_stack()
            if stack:
                msg += ("\n" + stack
                        + "\n（此栈仅用于定位卡在哪一步；持续无输出会自动强制收工）")
            self._note(jid, msg)


def _device_key_from_config() -> str:
    """设备锁的 key：优先用 config.yaml 里写的序列号，没写就用 auto。

    ★ 用配置而不是现查 `adb devices`：服务启动时手机可能还没插上，
      现查会得到"auto"而另一台机器上配置写的就是序列号 —— 两边 key 不同，
      锁就形同虚设。key 必须**稳定**，不能取决于当下插没插手机。
    """
    try:
        from piiscan.config import AppConfig
        cfg = AppConfig.load(ROOT / "config.yaml")
        return (getattr(cfg.device, "serial", "") or "").strip() or "auto"
    except Exception:
        return "auto"


def serve(host: str = "127.0.0.1", port: int = 8760,
          workdir: str | Path = "out/platform",
          db_path: Optional[str] = None, quiet: bool = False,
          device: bool = True):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- 单实例
    # ★ 必须在建库、起 Worker **之前**拿锁。
    #   用户 2026-10-25 的现象：批量提交商店链接后两个 App 同时跑。根因不是
    #   队列写错了，而是 Windows 允许两个进程同时绑 127.0.0.1:8760
    #   （SO_REUSEADDR 的真实语义），第二个 run_platform.py 静默成为
    #   第二个服务，各自一个 Worker 抢同一个 jobs.db。
    #   这里挡的是"同一个工作目录起两次"，设备锁挡的是"不同目录抢同一台机"。
    from piiscan import runlock
    dev_key = _device_key_from_config()
    inst = runlock.FileLock(
        runlock.workdir_lock_path(workdir),
        {"pid": os.getpid(), "port": port, "workdir": str(workdir.resolve()),
         "device": dev_key})
    if not inst.acquire():
        holder = runlock.read_holder(inst)
        print("=" * 66)
        print("  [×] 启动被拒绝：这个工作目录已经有一个检测服务在运行")
        print("=" * 66)
        print("  占用者：%s" % runlock.describe_holder(holder, inst))
        print("  锁文件：%s" % inst.path)
        print("")
        print("  为什么不能同时跑两个：一台手机同时只能测一个 App。两个服务会")
        print("  各自从同一队列取任务，两个 App 同时安装、同时采集，截图与事件流")
        print("  互相污染，而两条任务的状态都会显示\"已完成\"——结论悄悄错掉。")
        print("")
        print("  处理：先结束上面那个进程（或关掉它的终端窗口），再重新启动。")
        print("=" * 66)
        return 3

    try:
        db = JobDB(db_path or (workdir / "jobs.db"))

        stale = db.cleanup_stale()
        if stale:
            print("[*] 已将 %d 个中断任务标记为失败" % stale)

        # AI 连接配置迁移（只在第一次启动、档案表为空时做一次）。
        # 升级后原来的模型服务必须还能用，否则"改个界面"就把 AI 弄没了。
        _seeded = seed_ai_profiles(db)
        if _seeded:
            print("[*] 已将 config.yaml 里的模型服务配置迁入「系统状态 → AI 模型服务」"
                  "（可在界面里修改或删除）")

        worker = Worker(db, workdir, device_enabled=device, device_key=dev_key)
        worker.start()
        Watchdog(db, worker).start()

        Handler.db = db
        Handler.workdir = workdir
        Handler.device_enabled = bool(device)
        Handler.worker = worker
        httpd = ThreadingHTTPServer((host, port), Handler)
        httpd.quiet = quiet
        httpd.daemon_threads = True

        print("=" * 66)
        print("  App 个人信息保护合规检测平台")
        print("=" * 66)
        print("  访问地址：http://%s:%d" % (host if host != "0.0.0.0" else "127.0.0.1", port))
        print("  工作目录：%s" % workdir.resolve())
        print("  数据库：  %s" % (db_path or (workdir / "jobs.db")))
        print("  检测设备：%s" % ("已接入（任务严格串行，同时只跑一个）" if device
                                 else "未接入（仅静态分析 + 政策分析，动态采集请求会被拒绝）"))
        print("  实例锁：  %s" % inst.path)
        print("  按 Ctrl+C 停止服务")
        print("=" * 66)

        # 不同工作目录可以各起一个实例（静态分析不需要设备），但**手机只有一台**。
        # 这里只探测、不占锁：已经把别人的锁抢过来会让对方的任务干等。
        # 探测到被占就说清楚，否则用户会看到任务长时间停在"等待设备"却不知道原因。
        #
        # ★ 用 probe_free 而不是"acquire 一下就 release"：后者会把本次探测的
        #   PID 写进 .info，覆盖掉真正的持有者 —— 留给下一个启动的实例一条
        #   "某个早就退出的进程占着设备"的假信息。探测不该留下任何痕迹。
        if device:
            lp = runlock.device_lock_path(dev_key)
            free = runlock.probe_free(lp)
            if free is False:
                h = runlock.read_holder(runlock.FileLock(lp))
                print("[!] 检测设备当前被另一个实例占用：%s"
                      % runlock.describe_holder(h, runlock.FileLock(lp)))
                print("    本实例不需要设备的任务照常执行；需要动态采集的任务会先排队等待。")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] 正在停止 …")
        finally:
            worker.stop()
            httpd.server_close()
        return 0
    finally:
        inst.release()
