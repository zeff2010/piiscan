"""检测流水线：把「目标接入 → 静态分析 → 政策解析 → 动态采集 → 判定 → 报告」
串成一次完整检测。

对外只暴露一个 run_detection()，平台层（Web 服务）与命令行都调用它。
每一步都会写进度日志，便于前端实时展示；任一步失败都不会让整条流水线崩溃
（除入口获取失败外），而是把缺失环节记入报告并跳过依赖它的检测项。
"""
from __future__ import annotations

import json
import re
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import apkfetch, apkstatic, policy as policy_mod
from .ai import build_tasks_safe
from .config import AppConfig
from .rules import ScanContext, evaluate
from .rules.models import JudgeResult


@dataclass
class DetectionOptions:
    policy_url: str = ""        # 人工指定的隐私政策链接（优先于自动提取）
    policy_text: str = ""       # 人工粘贴的政策全文
    dynamic: bool = True        # 是否执行设备动态采集
    duration: int = 90          # 采集时长（秒）
    device_serial: str = ""
    ui_walk: bool = True
    capture_screenshot: bool = True
    deep_static: bool = True    # 是否做 DEX 深度扫描（大文件可关）
    reset_app: bool = True      # 检测前清除应用数据（首启流程必须）
    policy_wait: int = 22       # 首启观测时长：等隐私政策弹窗（秒）

    @classmethod
    def from_config(cls, cfg: AppConfig) -> "DetectionOptions":
        return cls(duration=cfg.scan.duration, device_serial=cfg.device.serial,
                   ui_walk=cfg.scan.ui_walk, capture_screenshot=cfg.scan.capture_screenshot,
                   reset_app=cfg.scan.reset_app, policy_wait=cfg.scan.policy_wait)


@dataclass
class DetectionResult:
    ok: bool = False
    job_id: str = ""
    error: str = ""
    target: Dict[str, Any] = field(default_factory=dict)
    static: Any = None
    policy: Any = None
    dynamic: Any = None
    judge: Optional[JudgeResult] = None
    report_path: str = ""
    result_path: str = ""
    stages: List[Dict[str, Any]] = field(default_factory=list)
    started_at: float = 0.0
    ended_at: float = 0.0

    @property
    def elapsed(self) -> float:
        return max(0.0, self.ended_at - self.started_at)


class _Stage:
    """阶段计时与日志包装。"""

    def __init__(self, res: DetectionResult, name: str, log: Callable[[str], None]):
        self.res, self.name, self.log = res, name, log
        self.t0 = 0.0

    def __enter__(self):
        self.t0 = time.time()
        self.log("[阶段] %s 开始" % self.name)
        return self

    def __exit__(self, exc_type, exc, tb):
        dur = time.time() - self.t0
        status = "ok" if exc_type is None else "error"
        msg = "" if exc_type is None else ("%s: %s" % (exc_type.__name__, exc))
        self.res.stages.append({"name": self.name, "status": status,
                                "seconds": round(dur, 2), "message": msg})
        if exc_type is None:
            self.log("[阶段] %s 完成（%.1fs）" % (self.name, dur))
        else:
            self.log("[阶段] %s 失败：%s" % (self.name, msg))
        return exc_type is None      # 吞掉异常，保证流水线继续


def run_detection(*, job_id: str, workdir: str | Path,
                  apk_path: str = "", apk_url: str = "",
                  options: Optional[DetectionOptions] = None,
                  cfg: Optional[AppConfig] = None,
                  log: Optional[Callable[[str], None]] = None) -> DetectionResult:
    log = log or (lambda *_: None)
    options = options or DetectionOptions()
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    res = DetectionResult(job_id=job_id)
    res.started_at = time.time()
    log("[*] 检测任务 %s 开始" % job_id)

    # ---- AI 能力（可选）----
    # 整条流水线共用一个实例，好处是调用留痕集中：报告最后能拿出一份
    # 「AI 这一步看了什么、判了什么、我们据此做了什么」的完整记录，
    # 人工复核时可以直接对照，而不是只看到一个结论。
    ai_tasks = build_tasks_safe(cfg.ai, log) if cfg is not None else None

    # ---------------- 1. 目标获取 ----------------
    with _Stage(res, "目标获取", log) as s:
        if apk_path and Path(apk_path).exists():
            fr = apkfetch.fetch_upload(apk_path, workdir / "input", log=log)
        elif apk_url:
            fr = apkfetch.fetch_url(apk_url, workdir / "input", log=log)
        else:
            res.error = "未提供 APK 文件或下载链接"
            raise ValueError(res.error)
        if not fr.ok:
            res.error = fr.error or "APK 获取失败"
            raise RuntimeError(res.error)
        res.target = {
            "source": fr.source,
            "source_label": "本地上传" if fr.source == "upload" else "在线下载（%s）" % fr.url,
            "url": fr.url, "filename": fr.original_name or fr.filename,
            "archived": fr.filename, "size": fr.size,
            "md5": fr.md5, "sha256": fr.sha256, "path": fr.path,
        }
        apk_file = fr.path

    # ---------------- 2. 静态分析 ----------------
    with _Stage(res, "静态分析", log) as s:
        res.static = apkstatic.analyze(apk_file, log=log, deep=options.deep_static)
        res.target.update({
            "package": res.static.package, "app_label": res.static.app_label,
            "version_name": res.static.version_name, "version_code": res.static.version_code,
        })

    # ---------------- 3. 设备动态采集（含首启弹窗与政策捕获） ----------------
    # 顺序说明：政策解析必须排在动态采集之后 —— 隐私政策的真实来源是
    # App 首启弹窗里的链接，只有把 App 跑起来才拿得到。
    if options.dynamic:
        with _Stage(res, "设备动态采集", log) as s:
            res.dynamic = _run_dynamic(res.static, options, cfg, log, apk_file,
                                       ai_tasks=ai_tasks)
    else:
        res.stages.append({"name": "设备动态采集", "status": "skipped",
                           "seconds": 0, "message": "按配置跳过（未执行设备采集）"})
        log("[阶段] 设备动态采集 已跳过")

    # ---------------- 4. 隐私政策解析（运行时捕获优先） ----------------
    with _Stage(res, "隐私政策解析", log) as s:
        res.policy = _resolve_policy(res.static, res.dynamic, options, log)

    # ---------------- 4.5 AI 深读政策（可选） ----------------
    # 为什么单独一个阶段：政策深读会顺链抓取「第三方信息共享清单」等子文档，
    # 属于网络 IO + 多次模型推理，耗时与前面的环节不在一个量级，
    # 单独计时才能让使用者看清时间花在哪、值不值。
    if ai_tasks is not None and cfg is not None and cfg.ai.feature("policy_analyze"):
        with _Stage(res, "AI 政策深读", log) as s:
            _ai_enrich_policy(res.policy, ai_tasks, res.static, log)
    elif ai_tasks is not None:
        log("[阶段] AI 政策深读 已跳过（ai.features.policy_analyze = false）")

    # ---------------- 5. 判定 ----------------
    with _Stage(res, "规则判定", log) as s:
        ctx = ScanContext(static=res.static, policy=res.policy,
                          dynamic=res.dynamic, log=log)
        res.judge = evaluate(ctx, log=log)
    if res.judge is None:      # 判定阶段异常时保证报告仍可生成
        res.judge = JudgeResult()

    # ---------------- 6. 报告 ----------------
    with _Stage(res, "报告生成", log) as s:
        res.report_path, res.result_path = _write_outputs(res, workdir, log)

    res.ended_at = time.time()
    res.ok = bool(res.judge is not None)
    log("[*] 检测任务 %s 结束，耗时 %.1fs" % (job_id, res.elapsed))
    return res


def _resolve_policy(static, dynamic, options: DetectionOptions, log):
    """政策获取优先级（按「离用户实际看到的那一份有多近」排序）：

      1. 人工粘贴全文
      2. **设备运行时**：首启弹窗里直接读到的文本 / 打开政策页后读到的 WebView 正文
         —— 这是用户真正看到的内容，证据效力最高
      3. **APK 内置政策文档**（assets/**/privacy.html 等）
         —— 政务/金融类 App 常随包内置，在线抓链接永远拿不到，但正文就在包里
      4. 人工指定的链接
      5. 运行时捕获到的真实链接 → HTTP 抓取
      6. APK 静态提取的候选链接（可靠性最低，常命中第三方 SDK 内置政策）

    2 与 3 同时存在时取正文更完整的那一份（首启弹窗常只是"告知摘要"，
    完整条款在内置文档或政策页里），并保留另一份作为佐证。
    """
    if options.policy_text and len(options.policy_text.strip()) >= 50:
        log("[*] 使用人工提供的隐私政策全文（%d 字）" % len(options.policy_text))
        r = policy_mod.from_text(options.policy_text)
        r.source = "text"
        return r

    # ---- 收集「设备运行时」与「APK 内置」两类候选 ----
    cap = (getattr(dynamic, "policy_capture", None) or {}) if dynamic is not None else {}
    # 运行时拿到的东西分两种，语义完全不同，绝不能混为一谈：
    #   bestText  = 政策**正文**（点了弹窗里的入口打开的政策页，或是内联全文）
    #   noticeText= 首启弹窗上的**告知摘要**（"请您仔细阅读…"那一段）
    # 把摘要当正文用，会让条款比对凭空多出一堆"未告知"（假阳性）。
    rt_text = (cap.get("bestText") or "").strip()
    rt_notice = (cap.get("noticeText") or "").strip()
    rt_url = (cap.get("bestTextUrl") or "").strip()
    rt_urls = [u.get("url") for u in (cap.get("urls") or []) if u.get("url")]
    if cap.get("entryTexts"):
        log("[*] 首启弹窗观测到的政策入口/文本：%s"
            % "、".join(str(t) for t in cap["entryTexts"][:2])[:100])

    assets = list(getattr(static, "policy_assets", None) or [])
    asset_text = (assets[0]["text"] if assets else "").strip()

    extra_notes: List[str] = []
    if rt_notice:
        log("[*] 首启弹窗告知摘要 %d 字（作为「已向用户告知」的证据，不等同于政策全文）"
            % len(rt_notice))
    if rt_text:
        log("[*] 设备运行时读取到政策正文 %d 字（%s）"
            % (len(rt_text), cap.get("bestTextUrl") or "运行中界面"))
    if asset_text:
        log("[*] APK 内置政策文档 %d 份，最长 %d 字（%s）"
            % (len(assets), len(asset_text), assets[0]["name"]))

    # ---- 2/3 择优（正文只在「运行时正文」与「APK 内置文档」之间比） ----
    if rt_text or asset_text:
        if asset_text and len(asset_text) > len(rt_text) * 1.25:
            chosen, src, note = asset_text, "apk_asset", "APK 内置政策文档"
            if rt_text:
                extra_notes.append("设备运行时读取到政策正文 %d 字（作为佐证）" % len(rt_text))
        else:
            chosen, src, note = (rt_text or asset_text), "runtime_text", "设备运行时读取"
            if src == "runtime_text" and asset_text and len(asset_text) > len(rt_text):
                extra_notes.append("APK 内置政策文档 %d 字（作为全文佐证）" % len(asset_text))
        if len(chosen) >= 300:
            log("[*] 采用%s，正文 %d 字" % (note, len(chosen)))
            r = policy_mod.from_text(chosen)
            r.source = src
            # ★ 政策 URL 只在"确实打开过政策页"时才给出。
            # 早先无条件优先塞 rt_urls[0]，结果滴滴那次把**滑块验证码**的地址
            # （access-web.xiaojukeji.com/captcha）当成了隐私政策地址写进报告。
            url = ""
            if src == "runtime_text":
                likely = [u for u in (cap.get("urls") or [])
                          if u.get("policyLikely") and u.get("url")]
                if likely:
                    url = likely[0]["url"]
                elif cap.get("entryClicked") and rt_urls:
                    url = rt_urls[-1]     # 点了政策入口后新出现的那个 WebView
            r.url = url
            r.final_url = url
            r.assets = assets[:3]
            r.notes = extra_notes + list(cap.get("notes") or [])
            if src == "runtime_text" and rt_url:
                r.notes.append("政策正文取自界面位置：%s" % rt_url)
            r.popup_notice = rt_notice     # 弹窗告知摘要始终单独保留，不混入正文
            return r
        log("[!] 候选政策正文偏短（%d 字），继续尝试其它来源" % len(chosen))

    if options.policy_url:
        r = policy_mod.fetch(options.policy_url, log=log)
        if r.ok:
            r.source = "runtime_url" if options.policy_url in rt_urls else "url"
        r.popup_notice = rt_notice
        return r

    # 运行时捕获的真实链接优先于静态候选
    for url in rt_urls[:6]:
        log("[*] 尝试抓取运行时捕获的政策链接：%s" % url[:90])
        r = policy_mod.fetch(url, log=log)
        if r.ok and len(r.text) >= 300:
            r.source = "runtime_url"
            r.popup_notice = rt_notice
            return r
        if r.error:
            log("    ↳ 该链接不可用：%s" % r.error[:70])

    for url in policy_mod.candidate_urls(static):
        log("[*] 尝试抓取 APK 静态提取的候选链接：%s" % url[:90])
        r = policy_mod.fetch(url, log=log)
        if r.ok and len(r.text) >= 300:
            r.source = "static"
            r.popup_notice = rt_notice
            log("[!] 注意：该链接来自 APK 静态提取，可能是第三方 SDK 内置政策，"
                "不等同于本 App 的隐私政策，请人工确认")
            return r
        if r.error:
            log("    ↳ 该链接不可用：%s" % r.error[:70])

    log("[!] 未能获取隐私政策正文，相关检测项将被标记为未执行")
    r = policy_mod.PolicyResult(source="none")
    r.error = "未能自动定位并抓取隐私政策正文"
    r.popup_notice = rt_notice     # 至少把「首启告知了什么」保留下来
    return r


def _merge_list(base, extra) -> List[str]:
    """合并两个字符串列表，去重去空，保持原有顺序在前。"""
    out: List[str] = []
    for src in (base or [], extra or []):
        for x in src:
            s = str(x).strip()
            if s and s not in out:
                out.append(s)
    return out


_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'）)\]，。；]+")


def _absolutize(url: str, base: str) -> str:
    """把政策里出现的链接补全成可抓取的绝对地址。

    政策正文里的链接写法非常杂：绝对地址、以 / 开头的站内路径、
    以 // 开头的协议相对地址，还有直接写在书名号或括号里的。
    能补全就补全，补不了就返回空串 —— **不猜**：
    猜错的链接抓回来的是无关页面，会污染证据。
    """
    from urllib.parse import urljoin
    u = (url or "").strip().strip("《》<>（）()【】[]，,。；;")
    if not u:
        return ""
    if u.startswith(("http://", "https://")):
        return u
    if u.startswith("//"):
        return "https:" + u
    if u.startswith("/") and base:
        return urljoin(base, u)
    # 有些政策会把完整地址写在没有 <a> 的纯文本里，模型只抄回了标题
    m = _URL_IN_TEXT.search(u)
    if m:
        return m.group(0)
    return ""


def _ai_enrich_policy(policy, ai_tasks, static, log) -> None:
    """用 AI 读透政策全文：结构化抽取 + 追第三方共享清单。

    为什么必须追链：合规检测里最要紧的一条证据就是「有没有第三方共享清单」。
    大量 App 的隐私政策正文只写一句「详见《第三方信息共享清单》」，真正的清单
    在**另一个页面**。不追过去，判定层就只知道"提到了第三方"，
    既核对不了共享了哪些信息、给了哪些公司，也判不准"未列明第三方 SDK"是否成立。

    ★ 一条硬规则：AI 的结论**只用于补强正面证据，不用于制造违规结论**。
      · AI 说"政策里写了注销路径" → 可以据此认定"提供了该路径"（减少假阳性）
      · AI 说"政策里没写注销" → **不**据此判定缺失。漏读会让报告凭空多一条
        违规项，而这正是最需要避免的错误方向。
      所以下面的合并逻辑一律是「AI 有 → 补上」，没有反向删除。
    """
    if policy is None:
        return
    text = (policy.text or "").strip()
    if not text:
        policy.ai_status = "跳过：没有可分析的政策正文"
        log("    ↳ 没有政策正文，AI 深读跳过")
        return

    app_label = getattr(static, "app_label", "") or ""
    log("[*] AI 深读政策正文（%d 字）…" % len(text))
    t0 = time.time()
    ret = ai_tasks.analyze_policy(text, app_label=app_label)
    if ret is None:
        policy.ai_status = "未执行（模型不可用）"
        log("[!] AI 深读未执行，报告将只使用正则提取的结果")
        return
    if not ret.ok:
        policy.ai_status = "失败：%s" % (ret.error or "输出无法解析")
        log("[!] AI 深读失败（%s），已回退到正则提取的结果" % policy.ai_status)
        return

    d = ret.data
    policy.ai_analysis = d
    policy.ai_status = "完成（%.1fs）" % (time.time() - t0)
    log("[*] AI 深读完成：声明信息类型 %d 项、注销路径 %d 条、投诉渠道 %d 条、"
        "指向第三方文档 %d 份"
        % (len(d.get("declared_types") or []), len(d.get("cancel_account") or []),
           len(d.get("complaint") or []), len(d.get("third_party_docs") or [])))

    # ---- 把 AI 的结论合并进规则字段（只补强，不删除）----
    policy.declared_types = _merge_list(policy.declared_types, d.get("declared_types"))
    cancel = [x.get("path") for x in (d.get("cancel_account") or []) if x.get("path")]
    policy.cancel_paths = _merge_list(policy.cancel_paths, cancel)
    if policy.cancel_paths:
        policy.has_cancel_account = True
    cd = [x.get("path") for x in (d.get("correct_delete") or []) if x.get("path")]
    policy.correct_delete_paths = _merge_list(policy.correct_delete_paths, cd)
    if policy.correct_delete_paths:
        policy.has_correct_delete = True
    comp = ["%s：%s" % (x.get("path") or x.get("channel") or "", x.get("detail") or "")
            for x in (d.get("complaint") or []) if (x.get("path") or x.get("detail"))]
    policy.complaint_channels = _merge_list(policy.complaint_channels, comp)
    if policy.complaint_channels:
        policy.has_complaint = True
    if d.get("contact"):
        policy.contact_info = _merge_list(policy.contact_info, [d["contact"]])
    if d.get("minor_rules"):
        policy.children_rule = True
    if d.get("retention"):
        policy.notes.append("AI 读出保存期限：%s" % str(d["retention"])[:120])
    if d.get("cross_border"):
        policy.notes.append("AI 读出数据出境表述：%s" % str(d["cross_border"])[:120])

    # ---- 追链：政策里提到的第三方文档 ----
    base = policy.final_url or policy.url or ""
    docs = list(d.get("third_party_docs") or [])
    if not docs:
        log("    ↳ 政策正文中未发现指向第三方清单/其它文档的链接")
    for doc in docs[:4]:                       # 上限 4 份，避免链式抓取失控
        title = str(doc.get("title") or "").strip()
        raw_url = str(doc.get("url") or "").strip()
        url = _absolutize(raw_url or title, base)
        entry: Dict[str, Any] = {
            "title": title, "url": url or raw_url,
            "where": doc.get("where") or "", "kind": doc.get("kind") or "",
            "fetched": False, "text_len": 0, "summary": "", "error": "",
            "declared_types": [],
        }
        if url:
            log("[*] 追取第三方文档：%s" % title[:40])
            log("    %s" % url[:100])
            fr = policy_mod.fetch(url, log=log)
            if fr.ok and (fr.text or "").strip():
                entry["fetched"] = True
                entry["text_len"] = len(fr.text)
                sub = ai_tasks.analyze_policy(fr.text, app_label=app_label,
                                              is_sub_document=True)
                if sub is not None and sub.ok:
                    entry["summary"] = sub.data.get("summary") or ""
                    entry["declared_types"] = sub.data.get("declared_types") or []
                    # 清单本身也可能再指向明细页，但只跟一层就够 ——
                    # 再深下去收益递减，而每层都要花一次抓取 + 一次推理。
                    entry["inner_docs"] = [x.get("title") or ""
                                           for x in (sub.data.get("third_party_docs") or [])][:5]
                    policy.declared_types = _merge_list(policy.declared_types,
                                                        entry["declared_types"])
            else:
                entry["error"] = fr.error or "抓取后无正文"
                log("    ↳ 抓取失败：%s" % entry["error"][:80])
        else:
            entry["error"] = "政策提到了该文档，但未给出可抓取的链接"
            log("    ↳ 「%s」未提供可抓取的链接" % title[:40])
        policy.third_party_docs.append(entry)

    if policy.third_party_docs:
        got = sum(1 for x in policy.third_party_docs if x.get("fetched"))
        policy.notes.append(
            "AI 深读识别出 %d 份指向第三方的文档，其中 %d 份已成功抓取并二次分析"
            % (len(policy.third_party_docs), got))
    if isinstance(d.get("summary"), str) and d["summary"]:
        policy.notes.append("AI 政策要点：%s" % d["summary"][:200])
    policy.ai_text_len = len(text)


def _run_dynamic(static, options: DetectionOptions, cfg: Optional[AppConfig], log,
                 apk_path: str = "", ai_tasks=None):
    """执行设备采集；设备不可用时返回 None 并记日志。"""
    try:
        from .collector import run_scan
    except Exception as e:
        log("[!] 采集模块不可用（%s），跳过动态采集" % e)
        return None
    if cfg is None:
        cfg = AppConfig()
    cfg.scan.package = static.package
    cfg.scan.duration = options.duration
    cfg.scan.spawn = True
    cfg.scan.ui_walk = options.ui_walk
    cfg.scan.capture_screenshot = options.capture_screenshot
    cfg.scan.reset_app = options.reset_app
    cfg.scan.policy_wait = options.policy_wait
    if options.device_serial:
        cfg.device.serial = options.device_serial
    try:
        return run_scan(cfg, log=log, apk_path=apk_path,
                        reset_app=options.reset_app, policy_wait=options.policy_wait,
                        ai_tasks=ai_tasks)
    except Exception as e:
        log("[!] 动态采集失败：%s" % e)
        log("    （未连接设备或 frida-server 未运行时会如此；静态与政策结论不受影响）")
        import traceback
        log("    " + traceback.format_exc().strip().splitlines()[-1])
        return None


def _write_outputs(res: DetectionResult, workdir: Path, log) -> tuple[str, str]:
    from .report.platform import render_platform_report

    meta = {
        "job_id": res.job_id,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(res.started_at)),
        "finished_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(res.ended_at)),
        "elapsed": "%.1f 秒" % res.elapsed,
    }
    html = render_platform_report(target=res.target, static=res.static, policy=res.policy,
                                  dynamic=res.dynamic, judge=res.judge, meta=meta)
    report_path = workdir / "report.html"
    report_path.write_text(html, encoding="utf-8")

    payload = {
        "job_id": res.job_id,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": {k: v for k, v in res.target.items()},
        "stages": res.stages,
        "static": _static_dict(res.static),
        "policy": _policy_dict(res.policy),
        "dynamic": _dynamic_dict(res.dynamic),
        "judge": {
            "stats": res.judge.stats if res.judge else {},
            "findings": [f.to_dict() for f in res.judge.sorted_findings()] if res.judge else [],
            "checked": res.judge.checked if res.judge else [],
            "skipped": res.judge.skipped if res.judge else [],
        },
    }
    result_path = workdir / "result.json"
    result_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    log("[*] 报告已生成：%s（%.0f KB）" % (report_path.name, report_path.stat().st_size / 1024.0))
    return str(report_path), str(result_path)


# ---------------------------------------------------------------- 结果序列化

def _static_dict(st) -> Dict[str, Any]:
    if st is None:
        return {}
    return {
        "package": st.package, "app_label": st.app_label,
        "version_name": st.version_name, "version_code": st.version_code,
        "min_sdk": st.min_sdk, "target_sdk": st.target_sdk,
        "md5": st.md5, "sha256": st.sha256, "size": st.size,
        "permissions": st.permissions,
        "permission_details": st.permission_details,
        "dangerous_permissions": st.dangerous_permissions,
        "signature": st.signature,
        "sdks": st.sdks,
        "jiagu": st.jiagu,
        "cleartext": st.cleartext,
        "dex_count": st.dex_count,
        "sensitive_hits": st.sensitive_hits,
        "policy_urls": st.policy_urls,
        "policy_assets": [{"path": a.get("path"), "name": a.get("name"),
                           "size": a.get("size"), "text_len": a.get("text_len")}
                          for a in (getattr(st, "policy_assets", None) or [])],
        "domains": st.domains,
        "manifest_source": st.manifest_source,
        "errors": st.errors,
    }


def _policy_dict(p) -> Dict[str, Any]:
    if p is None:
        return {}
    return {
        "url": p.url, "final_url": p.final_url, "ok": p.ok, "source": p.source,
        "source_label": POLICY_SOURCE_LABELS.get(p.source, p.source),
        "title": p.title, "text_len": p.text_len, "error": p.error,
        "has_cancel_account": p.has_cancel_account, "cancel_paths": p.cancel_paths,
        "has_complaint": p.has_complaint, "complaint_channels": p.complaint_channels,
        "processing_days": p.processing_days,
        "has_correct_delete": p.has_correct_delete,
        "correct_delete_paths": p.correct_delete_paths,
        "withdraw_consent": p.withdraw_consent,
        "third_party_mentioned": p.third_party_mentioned,
        "third_party_names": p.third_party_names[:40],
        "children_rule": p.children_rule,
        "declared_behaviors": p.declared_behaviors,
        "declared_types": p.declared_types,
        "assets": [{"path": a.get("path"), "name": a.get("name"),
                    "text_len": a.get("text_len")}
                   for a in (getattr(p, "assets", None) or [])],
        "notes": list(getattr(p, "notes", None) or []),
        "popup_notice": (getattr(p, "popup_notice", "") or "")[:2000],
        "text_excerpt": (p.text or "")[:4000],
        # ---- AI 深读结果 ----
        "ai_status": getattr(p, "ai_status", "") or "",
        "ai_text_len": getattr(p, "ai_text_len", 0) or 0,
        "ai_analysis": getattr(p, "ai_analysis", None) or {},
        "third_party_docs": getattr(p, "third_party_docs", None) or [],
    }


POLICY_SOURCE_LABELS: Dict[str, str] = {
    "runtime_text": "设备运行中读取（首启弹窗/政策页的真实文本）",
    "runtime_url": "首启弹窗捕获的真实链接",
    "apk_asset": "APK 内置政策文档（随包下发的全文）",
    "url": "指定链接抓取",
    "text": "人工提供全文",
    "static": "APK 静态提取的候选链接（可能是第三方 SDK 内置政策）",
    "none": "未获取到",
}


def _dynamic_dict(d) -> Dict[str, Any]:
    if d is None:
        return {}
    return {
        "device_model": d.device_model, "android_version": d.android_version,
        "device_serial": d.device_serial,
        "duration": round(getattr(d, "duration", 0), 1),
        "install": getattr(d, "install", {}),
        "event_count": len(d.events),
        "before_consent_count": len(d.before_consent_events),
        "consent_given": d.consent_given,
        "consent_elapsed_ms": d.consent_elapsed_ms,
        "consent_source": getattr(d, "consent_source", ""),
        "ui_taps": d.ui_taps, "ui_steps": d.ui_steps,
        "hooks_installed": len(d.hooks_installed),
        "hooks_failed": len(d.hooks_failed),
        "hooks_failed_list": list(getattr(d, "hooks_failed", []) or []),
        "errors": d.errors,
        "locked_at_start": getattr(d, "locked_at_start", False),
        "overlays_dismissed": list(getattr(d, "overlays_dismissed", []) or []),
        "captcha_hits": list(getattr(d, "captcha_hits", []) or []),
        # ---- AI 参与过程（可审计）----
        "ai_enabled": bool(getattr(d, "ai_enabled", False)),
        "ai_vision": bool(getattr(d, "ai_vision", False)),
        "ai_stats": dict(getattr(d, "ai_stats", None) or {}),
        "ai_notes": list(getattr(d, "ai_notes", None) or []),
        "ai_errors": list(getattr(d, "ai_errors", None) or []),
        # 每次 AI 判断的完整记录（含模型原始输出），报告里会展示，
        # 让人工复核能回答"这个决策是 AI 做的还是规则做的、依据是什么"
        "ai_trace": [{"stage": t.get("stage"), "ok": t.get("ok"),
                      "action": t.get("action"), "error": t.get("error"),
                      "ts": t.get("ts"),
                      "decision": t.get("decision"), "raw": (t.get("raw") or "")[:1200]}
                     for t in (getattr(d, "ai_trace", []) or [])[-40:]],
        # ---- 新增：政策捕获 / 首启弹窗 / 去向 / SDK / 界面序列 ----
        "first_launch_popup": getattr(d, "first_launch_popup", False),
        "popup_evidence": list(getattr(d, "popup_evidence", []) or []),
        "policy_capture": {
            k: v for k, v in (getattr(d, "policy_capture", {}) or {}).items()
            if k not in ("bestText",)          # 正文单独放进 policy 段，避免重复
        },
        "network_sinks": list(getattr(d, "network_sinks", []) or []),
        "sdks_detected": list(getattr(d, "sdks_detected", []) or []),
        "events_by_level": d.events_by_level,
        "screens": [{"index": s.get("index"), "label": s.get("label"),
                     "activity": s.get("activity"), "fingerprint": s.get("fingerprint"),
                     "screenshot": s.get("screenshot"),
                     "texts": (s.get("texts") or [])[:20]}
                    for s in (getattr(d, "screens", []) or [])[:60]],
        "screenshots": [{"label": s.get("label"), "activity": s.get("activity"),
                         "b64": s.get("b64")} for s in (d.screenshots or [])],
        "events": [{"api": e.api, "category": e.category, "result": str(e.result)[:160],
                    "args": str(e.args)[:160],
                    "elapsed_ms": e.elapsed_ms, "before_consent": e.before_consent,
                    "evidence": e.evidence, "sink": e.sink, "signal": e.signal,
                    "pi": e.pi, "group": e.group,
                    "activity": e.activity, "ui_action": e.ui_action,
                    "screenshot_idx": e.screenshot_idx,
                    "stack": e.stack[:12]} for e in d.events[:600]],
    }
