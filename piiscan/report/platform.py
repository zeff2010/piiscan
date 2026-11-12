"""正式检测报告的 HTML 渲染。

报告结构对齐机构现有的人工检测报告：
    报告头 → 应用软件信息 → 检测环境 → 验证情况（统计）
    → 不符合项（问题 / 问题描述 / 触发过程 / 证据 / 调用栈 / 截图 / 处置建议）
    → 技术附录（权限、SDK、域名、未执行项、方法说明）
"""
from __future__ import annotations

import html
import re
import time
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional

TEMPLATE_PATH = Path(__file__).resolve().parent / "platform_template.html"

FOOTER_NOTE = (
    "本报告由自动化检测平台生成，用于内部复核与工作底稿。"
    "报告中的「疑似」项为规则引擎依据自动化证据给出的初步判断，"
    "需由检测人员结合业务场景复核确认；本报告不构成法律意见。"
)


def _e(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def _pct(a: int, b: int) -> str:
    return "%.0f%%" % (a * 100.0 / b) if b else "—"


# ---------------------------------------------------------------- 报告头

def _header(target: Dict[str, Any], judge, meta: Dict[str, Any]) -> str:
    st = judge.stats
    n = st.get("findings", 0)
    conclusion = "未发现不符合项" if n == 0 else "发现 %d 项不符合或疑似不符合项" % n
    badges = [
        "包名 %s" % _e(target.get("package") or "—"),
        "检测编号 %s" % _e(meta.get("job_id", "—")),
        "检测时间 %s" % _e(meta.get("finished_at", "—")),
        "结论：%s" % _e(conclusion),
    ]
    return (
        '<div class="head">'
        '<h1>App 个人信息保护合规检测报告</h1>'
        '<div class="sub">%s　%s</div>'
        '<div class="badges">%s</div>'
        '</div>'
    ) % (_e(target.get("app_label") or "—"), _e(target.get("version_name") or ""),
         "".join('<span class="badge">%s</span>' % b for b in badges))


# ---------------------------------------------------------------- 验证情况

def _summary(target: Dict[str, Any], static, policy, dynamic, judge, meta: Dict[str, Any]) -> str:
    st = judge.stats
    kpis = "".join([
        _kpi(st.get("findings", 0), "不符合项合计", "danger" if st.get("findings") else ""),
        _kpi(st.get("high", 0), "高风险项", "danger" if st.get("high") else ""),
        _kpi(st.get("confirmed", 0), "证据确证项", "warn" if st.get("confirmed") else ""),
        _kpi(st.get("checked", 0), "已执行检测项"),
        _kpi(st.get("skipped", 0), "未执行检测项"),
    ])

    rows: List[tuple] = [
        ("应用名称", target.get("app_label") or "—"),
        ("应用包名", target.get("package") or "—"),
        ("版本信息", "%s（versionCode %s）" % (target.get("version_name") or "—",
                                            target.get("version_code") or "—")),
        ("来源方式", target.get("source_label") or "—"),
        ("文件名称", target.get("filename") or "—"),
        ("文件大小", "%.1f MB" % (target.get("size", 0) / 1048576.0)
         if target.get("size") else "—"),
        ("MD5", target.get("md5") or "—"),
        ("SHA-256", target.get("sha256") or "—"),
    ]
    if static is not None:
        rows += [
            ("minSdk / targetSdk", "%s / %s" % (static.min_sdk or "—", static.target_sdk or "—")),
            ("签名主体", (static.signature or {}).get("subject") or "—"),
            ("签名校验", (static.signature or {}).get("verified") or "—"),
            ("加固情况", "、".join(j["name"] for j in static.jiagu) if static.jiagu else "未识别"),
            ("声明权限数", "%d 项（其中敏感权限 %d 项）"
             % (len(static.permissions), len(static.dangerous_permissions))),
            ("内嵌 SDK", "%d 个" % len(static.sdks)),
        ]

    env_rows = [
        ("隐私政策", _policy_line(policy)),
        ("动态采集", _dynamic_line(dynamic)),
        ("检测方式", "静态分析 + 隐私政策解析" + (" + 运行时插桩采集" if dynamic else "")),
        ("检测开始", meta.get("started_at", "—")),
        ("检测结束", meta.get("finished_at", "—")),
        ("检测耗时", meta.get("elapsed", "—")),
    ]

    app_tbl = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_e(k), _fmt(v)) for k, v in rows)
    env_tbl = "".join("<tr><th>%s</th><td>%s</td></tr>" % (_e(k), _fmt(v)) for k, v in env_rows)

    conclusion = _conclusion(judge)

    return (
        '<div class="card"><h2>一、验证情况</h2>'
        '<div class="kpis">%s</div>'
        '<div class="label">检测结论</div><div class="desc">%s</div>'
        '<h3>应用软件信息</h3><table>%s</table>'
        '<h3>检测环境与方法</h3><table>%s</table>'
        '</div>'
    ) % (kpis, _e(conclusion), app_tbl, env_tbl)


def _kpi(v, l, tone: str = "") -> str:
    return '<div class="kpi %s"><div class="v">%s</div><div class="l">%s</div></div>' % (
        tone, _e(v), _e(l))


def _fmt(v) -> str:
    return _e(v)


def _policy_line(policy) -> str:
    if policy is None:
        return "未获取"
    if not policy.ok:
        return "获取失败（%s）" % (policy.error or "未知原因")
    return "已获取并解析（%d 字）｜来源：%s" % (policy.text_len, _policy_src(policy))


def _policy_src(policy) -> str:
    """政策来源的中文描述（报告里必须能看出证据是怎么来的）。"""
    try:
        from ..pipeline import POLICY_SOURCE_LABELS
    except Exception:
        POLICY_SOURCE_LABELS = {}
    src = str(getattr(policy, "source", "") or "")
    label = POLICY_SOURCE_LABELS.get(src, src or "未知")
    url = (getattr(policy, "final_url", "") or getattr(policy, "url", "") or "")
    return "%s%s" % (label, ("（%s）" % url[:70]) if str(url).startswith("http") else "")


def _dynamic_line(dynamic) -> str:
    if dynamic is None:
        return "本次未执行（未连接测试设备）"
    parts = [
        "已执行：%s（Android %s）" % (dynamic.device_model or "—",
                                     dynamic.android_version or "—"),
        "插桩 %d 个接口" % len(getattr(dynamic, "hooks_installed", []) or []),
        "采集事件 %d 条" % len(getattr(dynamic, "events", []) or []),
        "UI 操作 %d 次" % getattr(dynamic, "ui_taps", 0),
        "截图 %d 张" % len(getattr(dynamic, "screenshots", []) or []),
    ]
    if getattr(dynamic, "locked_at_start", False):
        parts.append("⚠ 检测开始时设备处于锁屏，UI 遍历未执行")
    return "；".join(parts)


def _conclusion(judge) -> str:
    st = judge.stats
    n, hi = st.get("findings", 0), st.get("high", 0)
    if n == 0:
        return ("本次自动化检测未发现明确的个人信息保护不符合项。"
                "需要说明的是，自动化检测的覆盖范围有限（详见附录「检测范围与局限」），"
                "未命中不代表不存在问题。")
    parts = ["本次自动化检测共发现 %d 项不符合或疑似不符合项" % n]
    if hi:
        parts.append("其中高风险 %d 项" % hi)
    parts.append("涉及 %d 个测评项" % len({f.rule_id for f in judge.findings}))
    return "，".join(parts) + "。各项问题描述、证据链与处置建议见下文。"


# ---------------------------------------------------------------- 不符合项

def _findings(judge) -> str:
    findings = judge.sorted_findings()
    if not findings:
        return ('<div class="card"><h2>二、不符合项</h2>'
                '<p class="muted">本次检测未命中任何不符合项规则。</p></div>')

    # 按一级类别分组，与人工报告的章节编号一致
    groups: Dict[str, List[Any]] = {}
    for f in findings:
        groups.setdefault(f.category_name or "其他", []).append(f)

    out = ['<div class="card"><h2>二、不符合项</h2>',
           '<p class="muted">共 %d 项，按问题类别编排；每项含问题描述、触发过程、'
           '证据链与处置建议。</p>' % len(findings)]
    counter = 0
    for cname, items in groups.items():
        out.append('<h3>（%s）%s　<span class="muted" style="font-weight:400">共 %d 项</span></h3>'
                   % (_e(_cn_num(list(groups).index(cname) + 1)), _e(cname), len(items)))
        for f in items:
            counter += 1
            out.append(_finding_block(counter, f))
    out.append('</div>')
    return "".join(out)


_CN = "一二三四五六七八九十"


def _cn_num(i: int) -> str:
    return _CN[i - 1] if 1 <= i <= 10 else str(i)


def _finding_block(n: int, f) -> str:
    tone = {"高": "high", "中": "mid", "低": "low"}.get(f.level, "low")
    tags = [
        '<span class="tag %s">%s风险</span>' % (tone, _e(f.level)),
        '<span class="tag %s">%s</span>' % ("conf" if f.confidence == "确证" else "susp",
                                            _e(f.confidence)),
        '<span class="tag lv">%s</span>' % _e(f.automation or "—"),
    ]
    if f.unit:
        tags.append('<span class="tag lv">%s</span>' % _e(f.unit))

    parts = [
        '<div class="finding %s">' % tone,
        '<div class="fh">%s<span class="qid">%s</span></div>' % ("".join(tags), _e(f.rule_id)),
        '<div class="ft">%d. 问题：%s</div>' % (n, _e(f.title)),
        '<div class="label">问题描述</div><div class="desc">%s</div>' % _e(f.description),
    ]
    if f.basis:
        parts.append('<div class="label">检测依据</div><div class="note">%s</div>' % _e(f.basis))

    if f.facts:
        parts.append('<div class="label">证据明细</div><table>%s</table>'
                     % "".join("<tr><th>%s</th><td>%s</td></tr>"
                               % (_e(k), _e(v)) for k, v in f.facts))

    if f.steps:
        parts.append('<div class="label">触发过程</div><ol class="steps">%s</ol>'
                     % "".join("<li>%s</li>" % _e(s) for s in f.steps))

    if f.stacks:
        for i, st in enumerate(f.stacks, 1):
            parts.append('<details><summary>调用栈 #%d（%d 层）</summary><pre>%s</pre></details>'
                         % (i, len(st), _e("\n".join(st))))

    if f.shots:
        parts.append('<div class="label">证据截图</div><div class="shots">%s</div>'
                     % "".join('<figure><img src="data:image/png;base64,%s" alt="%s"/>'
                               '<figcaption>%s</figcaption></figure>'
                               % (sh.get("b64", ""), _e(sh.get("label", "")),
                                  _e(sh.get("label", ""))) for sh in f.shots))

    if f.advise:
        parts.append('<div class="label">处置建议</div><div class="advise">%s</div>'
                     % _e(f.advise))

    parts.append('</div>')
    return "".join(parts)


# ---------------------------------------------------------------- 附录

def _appendix(static, policy, dynamic, judge, meta: Dict[str, Any]) -> str:
    out = ['<div class="card"><h2>三、技术附录</h2>']

    # ---- 3.1 隐私政策来源与获取过程（新增：这是本轮改造的重点） ----
    out.append(_policy_provenance(policy))

    # ---- 3.2 首启弹窗与同意过程实测（新增） ----
    out.append(_first_launch_evidence(dynamic))

    # ---- 3.3 运行期数据去向（新增：误报漏斗第 4 级） ----
    out.append(_network_sinks(dynamic))

    if static is not None and static.permission_details:
        rows = "".join(
            "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (_e(p["name"]), _e(p.get("label") or "—"), _e(p.get("level") or "—"),
               _e("个人信息相关" if p.get("pii") == "是" else "—"))
            for p in static.permission_details)
        out.append('<h3>3.4 声明权限清单（%d 项）</h3>'
                   '<table><tr><th style="width:auto">权限</th>'
                   '<th style="width:auto">说明</th><th style="width:auto">保护级别</th>'
                   '<th style="width:auto">备注</th></tr>%s</table>' % (len(static.permission_details), rows))

    if static is not None and static.sdks:
        by_type: Dict[str, List[str]] = {}
        for s in static.sdks:
            by_type.setdefault(s.get("type") or "其他", []).append(
                "%s（%s）" % (s.get("name"), s.get("author") or "未知"))
        rows = "".join("<tr><td>%s</td><td>%s</td></tr>"
                       % (_e(t), _e("；".join(v[:12]) + ("…" if len(v) > 12 else "")))
                       for t, v in sorted(by_type.items()))
        out.append('<h3>3.5 内嵌第三方 SDK（%d 个）</h3>'
                   '<table><tr><th style="width:auto">类型</th>'
                   '<th style="width:auto">SDK</th></tr>%s</table>' % (len(static.sdks), rows))

    if static is not None and static.domains:
        rows = "".join("<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>"
                       % (_e(d["domain"]), _e(d.get("owner") or "—"), _e(d.get("count")))
                       for d in static.domains[:20])
        out.append('<h3>3.6 代码中出现的外发域名（Top %d）</h3>'
                   '<table><tr><th style="width:auto">域名</th>'
                   '<th style="width:auto">归属</th><th style="width:auto">出现次数</th></tr>%s</table>'
                   % (min(20, len(static.domains)), rows))

    if static is not None and static.sensitive_hits:
        rows = "".join("<tr><td>%s</td><td>%s</td><td><code>%s</code></td></tr>"
                       % (_e(h["label"]), _e(h.get("behavior") or "—"),
                          _e("；".join(h["apis"][:2])))
                       for h in static.sensitive_hits[:30])
        out.append('<h3>3.7 静态命中的敏感接口（%d 项，用于确定插桩重点）</h3>'
                   '<table><tr><th style="width:auto">接口</th>'
                   '<th style="width:auto">对应行为</th><th style="width:auto">签名</th></tr>%s</table>'
                   % (len(static.sensitive_hits), rows))

    out.append(_run_quality(dynamic))

    if judge.skipped:
        rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                       % (_e(s["id"]), _e(s["title"]), _e(s["automation"]), _e(s["reason"]))
                       for s in judge.skipped)
        out.append('<h3>3.9 未执行的检测项（%d 项，需人工补齐）</h3>'
                   '<table><tr><th style="width:auto">编号</th><th style="width:auto">测评项</th>'
                   '<th style="width:auto">自动化等级</th><th style="width:auto">未执行原因</th></tr>%s</table>'
                   % (len(judge.skipped), rows))

    out.append(_ai_provenance(dynamic, policy))
    out.append(_method_note(static, policy, dynamic, judge, meta))
    out.append('</div>')
    return "".join(out)


# ---------------------------------------------------------------- 3.10 AI 参与记录

def _ai_provenance(dynamic, policy) -> str:
    """把 AI 的参与过程如实写进报告。

    这一节存在的意义是**可复核**：检测报告要经得起追问「这个结论是怎么来的」。
    如果 AI 参与了判断却只留下一个结论，那它就成了黑盒 —— 人工没法核对，
    出问题时也没法定位是模型看错了还是我们传错了。
    所以这里既给结论，也给模型的原话。
    """
    dyn = dynamic
    stats = dict(getattr(dyn, "ai_stats", None) or {}) if dyn is not None else {}
    trace = list(getattr(dyn, "ai_trace", None) or []) if dyn is not None else []
    errs = list(getattr(dyn, "ai_errors", None) or []) if dyn is not None else []
    notes = list(getattr(dyn, "ai_notes", None) or []) if dyn is not None else []
    pol_status = (getattr(policy, "ai_status", "") or "") if policy is not None else ""
    pol_analysis = (getattr(policy, "ai_analysis", None) or {}) if policy is not None else {}
    tp_docs = list(getattr(policy, "third_party_docs", None) or []) if policy is not None else []

    enabled = bool(getattr(dyn, "ai_enabled", False)) if dyn is not None else False
    if not enabled and not pol_status:
        return ('<h3>3.10 AI 参与情况</h3>'
                '<div class="note">本次检测未启用 AI 环节，全部结论由确定性规则'
                '（关键词匹配 + 界面结构树 + 行为特征）得出。'
                '如需在政策入口识别、政策全文深读、UI 遍历等环节引入大模型，'
                '可在 config.yaml 的 <code>ai.features</code> 中开启，'
                '或在提交任务时勾选「AI 增强」。</div>')

    out = ['<h3>3.10 AI 参与情况</h3>']
    rows = [
        ("AI 服务", stats.get("provider") or "—"),
        ("模型", "%s（视觉模型：%s）"
                 % (stats.get("model") or "—",
                    stats.get("vision_model") or "沿用文本模型")),
        ("调用统计", "共 %s 次（成功 %s / 失败 %s，其中带图片 %s 次）"
                    % (stats.get("total", 0), stats.get("ok", 0),
                       stats.get("failed", 0), stats.get("vision", 0))),
        ("视觉能力", "已启用（模型 %s）" % stats.get("vision_model")
                    if stats.get("vision_enabled") else
                    "未启用（截图识别与 AI 遍历回退到规则策略）"),
        ("政策深读", pol_status or "未执行"),
    ]
    out.append('<table>%s</table>'
               % "".join("<tr><th>%s</th><td>%s</td></tr>" % (_e(k), _e(v))
                         for k, v in rows))

    # ---- 政策深读的结构化结果 ----
    if isinstance(pol_analysis, dict) and pol_analysis:
        bits = []
        dt = pol_analysis.get("declared_types") or []
        if dt:
            bits.append("AI 从政策中读出的个人信息类型：%s"
                        % _e("、".join(str(x) for x in dt[:20])))
        if pol_analysis.get("retention"):
            bits.append("保存期限：%s" % _e(str(pol_analysis["retention"])[:200]))
        if pol_analysis.get("cross_border"):
            bits.append("数据出境：%s" % _e(str(pol_analysis["cross_border"])[:200]))
        if pol_analysis.get("minor_rules"):
            bits.append("未成年人规则：%s" % _e(str(pol_analysis["minor_rules"])[:200]))
        if pol_analysis.get("summary"):
            bits.append("政策要点：%s" % _e(str(pol_analysis["summary"])[:400]))
        if bits:
            out.append('<div class="note">%s</div>'
                       % "<br/>".join("· " + b for b in bits))

    # ---- 第三方共享清单追链结果（本节最有价值的证据）----
    if tp_docs:
        rows_html = []
        for d in tp_docs:
            ok = bool(d.get("fetched"))
            tail = ("已抓取并二次分析（%s 字）" % d.get("text_len")) if ok \
                else _e(d.get("error") or "未抓取")
            rows_html.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                % (_e(d.get("title") or "—"), _e(d.get("kind") or "—"),
                   _e((d.get("url") or "")[:120]) or "—", _e(tail)))
        out.append('<h4>政策中指出的第三方文档（%d 份）</h4>'
                   '<table><tr><th style="width:auto">文档</th><th style="width:auto">类型</th>'
                   '<th style="width:auto">链接</th><th style="width:auto">处理结果</th></tr>%s</table>'
                   % (len(tp_docs), "".join(rows_html)))
        out.append('<div class="note">说明：这些文档由 AI 阅读政策正文后指出，'
                   '平台已顺链抓取并做二次分析。<b>若无任何第三方文档，'
                   '或政策提到了清单但无法访问</b>，本身就是需要人工确认的发现 —— '
                   '《个人信息保护法》要求向第三方提供个人信息时应告知接收方名称、'
                   '联系方式与处理目的。</div>')
    elif pol_analysis:
        out.append('<div class="note">AI 未在该隐私政策正文中发现指向「第三方信息共享清单」'
                   '等独立文档的链接。这可能是政策确实未提供清单，'
                   '也可能是清单藏在需要登录/跳转的页面里 —— 建议人工复核确认。</div>')

    # ---- 视觉/遍历的决策记录 ----
    if trace:
        vis = [t for t in trace if t.get("decision") or t.get("error")]
        if vis:
            out.append('<h4>AI 判断记录（最近 %d 条）</h4>' % len(vis[-24:]))
            items = []
            for t in vis[-24:]:
                ts = ""
                try:
                    ts = time.strftime("%H:%M:%S", time.localtime(float(t.get("ts") or 0)))
                except Exception:
                    pass
                head = "%s %s → %s" % (ts, _e(t.get("stage") or ""),
                                       _e(t.get("action") or ("失败：%s" % t.get("error"))))
                raw = str(t.get("raw") or "")
                dec = t.get("decision")
                body = ""
                if isinstance(dec, dict):
                    keys = ("display_form", "policy_present", "page_kind",
                            "is_policy_content", "confidence", "reason",
                            "goal_progress", "expect")
                    body = "；".join("%s=%s" % (k, _e(str(dec[k])[:120]))
                                     for k in keys if dec.get(k) not in (None, "", []))
                if raw:
                    body += ("<br/><span class=\"opt\">模型原始输出：</span>"
                             "<pre class=\"airaw\">%s</pre>" % _e(raw[:1500]))
                items.append("<li>%s<br/><span class=\"opt\">%s</span></li>" % (head, body))
            out.append('<ul class="ainotes">%s</ul>' % "".join(items))

    if notes:
        out.append('<h4>AI 环节日志</h4><ul class="ainotes">%s</ul>'
                   % "".join("<li>%s</li>" % _e(n) for n in notes[-20:]))
    if errs:
        out.append('<h4>AI 环节异常与降级（%d 条）</h4><ul class="ainotes warnlist">%s</ul>'
                   % (len(errs), "".join("<li>%s</li>" % _e(e) for e in errs[-15:])))
    out.append('<div class="note">说明：AI 只用于<b>补强证据</b>，不作为单独定性的依据。'
               '政策深读的结论只用于补充「政策中确有该条款」这类正面事实；'
               '模型没读到的内容<b>不会</b>被直接判为缺失 —— 避免因漏读而冤枉被测应用。'
               '所有判定项仍以规则引擎的结论为准，AI 的结果可在上方逐条核对。</div>')
    return "".join(out)


# ---------------------------------------------------------------- 3.1 政策来源

def _policy_provenance(policy) -> str:
    notice = (getattr(policy, "popup_notice", "") or "").strip() if policy is not None else ""
    if policy is None or not policy.ok:
        reason = (getattr(policy, "error", "") if policy is not None else "未执行政策解析")
        out = ['<h3>3.1 隐私政策来源与获取过程</h3>',
               '<div class="note">未能获取隐私政策正文：%s。'
               '依赖政策文本的检测项（未公开规则、告知完整性、第三方清单、'
               '儿童规则、实测与声明差集等）本章节留空，需人工补齐。</div>'
               % _e(reason or "未知原因")]
        # 正文没拿到，但首启弹窗上的告知文本往往已经采到了 —— 它本身就是
        # 「是否公开收集使用规则」「是否告知处理目的」的直接证据，不能因为
        # 正文抓取失败就一起丢掉。
        if notice:
            out.append('<div class="label">首启弹窗中的告知文本（%d 字，非政策全文）</div>'
                       '<pre class="excerpt">%s</pre>' % (len(notice), _e(notice[:3000])))
            out.append('<div class="note">政策全文未能自动获取（常见原因：App 把政策放在'
                       '多级目录页、需要登录、或触发了人机验证）。上方的弹窗告知文本是'
                       '<b>设备实测所得</b>，可作为"首启是否向用户提示了处理规则"的证据；'
                       '但条款级判定仍需人工补齐政策全文。</div>')
        return "".join(out)

    rows: List[tuple] = [
        ("政策来源", _policy_src(policy)),
        ("政策标题", getattr(policy, "title", "") or "—"),
        ("正文长度", "%d 字" % policy.text_len),
    ]
    url = getattr(policy, "final_url", "") or getattr(policy, "url", "") or ""
    if url:
        rows.append(("访问地址", url))

    parts = ['<h3>3.1 隐私政策来源与获取过程</h3>']
    if getattr(policy, "notes", None):
        parts.append('<div class="note">获取过程中的观测记录：<ul class="plain">%s</ul></div>'
                     % "".join("<li>%s</li>" % _e(n) for n in policy.notes))
    parts.append('<table>%s</table>'
                 % "".join("<tr><th>%s</th><td>%s</td></tr>" % (_e(k), _fmt(v))
                           for k, v in rows))

    assets = getattr(policy, "assets", None) or []
    if assets:
        arows = "".join("<tr><td><code>%s</code></td><td>%s</td></tr>"
                        % (_e(a.get("path")), _e("%s 字" % a.get("text_len")))
                        for a in assets)
        parts.append('<div class="label">APK 内置政策文档</div>'
                     '<table><tr><th style="width:auto">包内路径</th>'
                     '<th style="width:auto">正文长度</th></tr>%s</table>' % arows)

    notice = (getattr(policy, "popup_notice", "") or "").strip()
    if notice:
        parts.append('<div class="label">首启弹窗中的告知文本（%d 字，与政策全文可能不同）</div>'
                     '<pre class="excerpt">%s</pre>' % (len(notice), _e(notice[:3000])))

    declared = getattr(policy, "declared_behaviors", None) or []
    types = getattr(policy, "declared_types", None) or []
    if declared or types:
        parts.append('<div class="label">政策中已声明的个人信息类型</div>'
                     '<div class="note">共 %d 类。匹配到的表述：%s</div>'
                     % (len(declared), _e("、".join(types[:40]) or "—")))

    if policy.text_len >= 300:
        parts.append('<details><summary>查看政策正文（前 6000 字）</summary>'
                     '<pre class="excerpt">%s</pre></details>'
                     % _e((policy.text or "")[:6000]))

    parts.append(
        '<div class="note"><b>来源说明</b>：'
        '「设备运行中读取」与「APK 内置文档」都强于「链接抓取」，'
        '后者可能命中第三方 SDK 内置的政策页（例如某些 App 会在代码里引用'
        '广告、统计 SDK 自带的隐私政策地址），与 App 自身的政策无关，'
        '使用时务必核对来源。</div>')
    return "".join(parts)


# ---------------------------------------------------------------- 3.2 首启实测

def _consent_line(dynamic) -> str:
    """渲染"同意动作"一行。

    耗时字段做过一次防御：早先脚本侧没回 `startTs`，算出来是 epoch 毫秒，
    报告里出现「冷启动后 1792074259.6 秒同意」这种明显离谱的数字。
    源头已修；这里再加一道合理性闸门，宁可写「耗时未记录」也不写错数。
    """
    if not getattr(dynamic, "consent_given", False):
        return "未捕获到"
    src = re.sub(r"^ui:ui:", "ui:", getattr(dynamic, "consent_source", "") or "—")
    ms = getattr(dynamic, "consent_elapsed_ms", None)
    if not isinstance(ms, (int, float)) or ms < 0 or ms > 30 * 60 * 1000:
        return "已捕获（%s，耗时未记录）" % src
    return "已捕获（%s，冷启动后 %.1f 秒）" % (src, ms / 1000.0)


def _first_launch_evidence(dynamic) -> str:
    if dynamic is None:
        return ('<h3>3.2 首启弹窗与同意过程实测</h3>'
                '<div class="note">本次未执行设备端采集，因此没有首启实测证据。'
                '「未公开收集使用规则」「征得同意前收集」等结论缺少直接证据，'
                '建议连接已 root 的测试机重跑。</div>')

    cap = getattr(dynamic, "policy_capture", None) or {}
    popup = bool(getattr(dynamic, "first_launch_popup", False))
    rows: List[tuple] = [
        ("应用数据重置", "已清除（下次启动即首启流程）"
         if (getattr(dynamic, "install", None) or {}).get("ok", True) else "未执行"),
        ("首启隐私提示", "已观测到" if popup else "未观测到"),
        ("政策入口（弹窗内）",
         "、".join((cap.get("entryTexts") or [])[:2])[:120] or "—"),
        ("实际点击", cap.get("entryClicked") or "—"),
        ("同意动作", _consent_line(dynamic)),
    ]
    # ★ 「政策条款到底拿到没有」必须单独写清楚 —— 这是报告里最容易被误读的一处。
    #   真机实测（赣警办）：弹窗里的《隐私协议》超链接指向 /webchat/#/privacy，
    #   服务端返回 404，WebView 显示的是该站自己的错误页（标题却由 App 设成「隐私协议」）。
    #   如果只写「已获取政策正文 428 字」，读者会以为政策已公开；
    #   而实际情况恰恰相反 —— App 未能提供可查阅的政策条款。
    _urls = [str(d.get("url") or "") for d in (cap.get("urls") or []) if d.get("url")]
    if _urls:
        rows.append(("政策链接（实采）", "、".join(u[:180] for u in _urls[:3])))
    _xy = cap.get("entryTapXY")
    if isinstance(_xy, (list, tuple)) and len(_xy) == 2:
        rows.append(("政策入口点击坐标", "(%s, %s)" % (_xy[0], _xy[1])))
    _best = (cap.get("bestText") or "").strip()
    if cap.get("errorPage"):
        rows.append(("政策条款获取",
                     "失败 — 入口打开的是错误页（命中特征「%s」），未取得政策条款"
                     % cap["errorPage"]))
    elif len(_best) >= 1200:
        rows.append(("政策条款获取", "成功（%d 字）" % len(_best)))
    elif _best:
        rows.append(("政策条款获取",
                     "不完整 — 仅 %d 字，与首启弹窗的告知摘要相当，非政策全文"
                     % len(_best)))
    else:
        rows.append(("政策条款获取", "失败 — 未取得任何政策条款文本"))
    if cap.get("notes"):
        rows.append(("观测说明", "；".join(cap["notes"])))

    parts = ['<h3>3.2 首启弹窗与同意过程实测</h3>',
             '<table>%s</table>' % "".join("<tr><th>%s</th><td>%s</td></tr>"
                                           % (_e(k), _fmt(v)) for k, v in rows)]

    ev = getattr(dynamic, "popup_evidence", None) or []
    if ev:
        parts.append('<div class="label">首启观测记录</div><ul class="plain">%s</ul>'
                     % "".join("<li>%s</li>" % _e(x) for x in ev))

    steps = getattr(dynamic, "ui_steps", None) or []
    if steps:
        parts.append('<div class="label">操作路径（前 25 步）</div><ol class="steps">%s</ol>'
                     % "".join("<li>%s</li>" % _e(s) for s in steps[:25]))

    # 首启相关的截图
    shots: List[Dict[str, Any]] = []
    all_shots = list(getattr(dynamic, "screenshots", None) or [])
    for sc in (getattr(dynamic, "screens", None) or []):
        lab = sc.get("label") or ""
        idx = sc.get("screenshot")
        if idx is not None and 0 <= idx < len(all_shots) and any(
                k in lab for k in ("首启", "隐私政策", "同意")):
            shots.append(all_shots[idx])
    if shots:
        parts.append('<div class="label">首启过程截图</div><div class="shots">%s</div>'
                     % "".join('<figure><img src="data:image/png;base64,%s" alt="%s"/>'
                               '<figcaption>%s</figcaption></figure>'
                               % (sh.get("b64", ""), _e(sh.get("label", "")),
                                  _e(sh.get("label", ""))) for sh in shots[:8]))

    if not popup and not cap.get("entryTexts") and not cap.get("bestText"):
        parts.append('<div class="note"><b>重要发现</b>：设备端首启实测<b>未观测到</b>'
                     '任何隐私政策提示或可点击入口。依据《App违法违规收集使用'
                     '个人信息行为认定方法》第一条，这将直接支撑「未公开收集使用'
                     '规则」的结论；但若 App 对本机环境做了适配导致弹窗未出现，'
                     '请人工复核后使用。</div>')
    return "".join(parts)


# ---------------------------------------------------------------- 3.3 数据去向

def _network_sinks(dynamic) -> str:
    if dynamic is None:
        return ""
    sinks = list(getattr(dynamic, "network_sinks", None) or [])
    header = ('<h3>3.3 运行期数据去向（网络上报）</h3>')
    if not sinks:
        return (header + '<div class="note">本次采集未捕获到网络上报事件。'
                '这<b>不等于</b>数据没有外发：App 可能经 native 层、长连接或'
                '加密通道上报，也可能在采集窗口内没有触发上报动作。'
                '如需确证外发，建议接入网络抓包（mitmproxy）并由人工触发一次'
                '涉及个人信息的功能。</div>')

    rows = "".join(
        "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (_e(s.get("host")), _e(s.get("count")), _e(s.get("before_consent") or 0),
           _e("；".join(s.get("apis") or [])[:80]))
        for s in sinks[:25])
    return (header +
            '<div class="note">下表为运行期被拦截到的对外网络连接（按域名聚合）。'
            '这是误报漏斗的第 4 级「有去向下落」——值有效且确有外发时，'
            '结论可由「疑似」升级为「确证」。</div>'
            '<table><tr><th style="width:auto">域名</th>'
            '<th style="width:auto">次数</th><th style="width:auto">其中同意前</th>'
            '<th style="width:auto">相关接口</th></tr>%s</table>' % rows)


# ---------------------------------------------------------------- 3.8 采集质量

def _run_quality(dynamic) -> str:
    if dynamic is None:
        return ""
    levels = getattr(dynamic, "events_by_level", None) or {}
    rows: List[tuple] = [
        ("采集时长", "%.0f 秒" % (getattr(dynamic, "duration", 0) or 0)),
        ("插桩接口", "%d 个成功 / %d 个未命中"
         % (len(getattr(dynamic, "hooks_installed", []) or []),
            len(getattr(dynamic, "hooks_failed", []) or []))),
        ("采集事件", "%d 条（同意前 %d 条）"
         % (len(getattr(dynamic, "events", []) or []),
            len(getattr(dynamic, "before_consent_events", []) or []))),
        ("证据分级", "；".join("%s 级 %d 条" % (k, v) for k, v in sorted(levels.items())) or "—"),
        ("UI 自动操作", "%d 次" % getattr(dynamic, "ui_taps", 0)),
        ("界面记录 / 截图", "%d 个 / %d 张"
         % (len(getattr(dynamic, "screens", []) or []),
            len(getattr(dynamic, "screenshots", []) or []))),
    ]
    sdks = getattr(dynamic, "sdks_detected", None) or []
    if sdks:
        rows.append(("运行期发现的 SDK",
                     "；".join("%s（%d 类）" % (s.get("sdk"), s.get("classes"))
                               for s in sdks[:8])))
    overlays = list(getattr(dynamic, "overlays_dismissed", None) or [])
    if overlays:
        rows.append(("已清理的系统悬浮窗",
                     "；".join(sorted(set(overlays))) +
                     "（悬浮窗不进入界面结构导出，但会拦截触摸，"
                     "曾导致「同意」按钮点击落空）"))

    parts = ['<h3>3.8 采集质量与证据分级</h3>']
    captchas = list(getattr(dynamic, "captcha_hits", None) or [])
    if captchas:
        # 这一条必须放在表格**之前**：它决定后面所有界面类证据能不能用，
        # 藏在表格里容易被忽略。
        parts.append(
            '<div class="warn"><b>⚠ 检测到反自动化/人机验证界面</b>（%s）。<br>'
            '验证码页会接管整个 App，此后采集到的界面与权限场景证据'
            '<b>不能代表 App 的正常运行表现</b>。本次报告中的动态结论请结合'
            '「人工沙箱复核」使用；若需自动化数据可用，请更换测试设备标识或'
            '降低冷启动频次后重跑。</div>' % _e("；".join(captchas)))
    parts.append('<table>%s</table>' % "".join("<tr><th>%s</th><td>%s</td></tr>"
                                               % (_e(k), _fmt(v)) for k, v in rows))
    parts.append(
        '<div class="note"><b>证据分级说明</b>（对应误报漏斗）：<br>'
        'A 级 = API 被调用<b>且取到有效值</b>，可独立支撑结论；<br>'
        'B 级 = API 被调用但取值需人工确认（返回 null、占位值等）；<br>'
        'C 级 = 纯行为记录（如申请权限），需结合界面上下文判断；<br>'
        'D 级 = 噪声线索，仅作参考。<br>'
        '采集脚本已按「第一条业务帧」规则剔除框架/WebView 自身触发的调用'
        '（对应沙箱的 excludeStack 机制），因此进入本报告的事件均已过堆栈筛选。</div>')

    errs = [e for e in (getattr(dynamic, "errors", None) or [])]
    if errs:
        parts.append('<div class="label">采集过程中的异常与告警</div><ul class="plain">%s</ul>'
                     % "".join("<li>%s</li>" % _e(x) for x in errs[:12]))
    return "".join(parts)


def _method_note(static, policy, dynamic, judge, meta) -> str:
    lines = [
        '<h3>3.11 检测范围与局限</h3><div class="note">',
        '<p>本平台的检测能力覆盖 %d 项测评项，其中已执行 %d 项。'
        '自动化检测的固有局限如下，请在使用结论时一并考虑：</p>'
        % (len(judge.checked) + len(judge.skipped), len(judge.checked)),
        '<ul class="plain">',
        '<li><b>静态分析</b>：基于 APK 内嵌的权限声明、SDK 特征与字符串，'
        '反映「声明了什么」，不反映「实际做了什么」。</li>',
        '<li><b>隐私政策获取</b>：优先级为「人工提供 &gt; 设备运行中读取 &gt; '
        'APK 内置政策文档 &gt; 链接抓取」。其中「链接抓取」若命中第三方 SDK 内置的'
        '政策页（常见于代码里引用的广告、统计 SDK 地址），与本 App 自身的政策无关，'
        '报告中已标注来源，请以标注为准。</li>',
        '<li><b>运行时插桩</b>：仅覆盖 Java 层接口调用，'
        'Native 层（/proc、/sys、ioctl）与 Binder 直连不在覆盖范围内；'
        '同时插桩本身可能被具有反检测能力的应用感知，导致行为失真。</li>',
        '<li><b>UI 自动遍历</b>：以 uiautomator 界面结构为驱动，'
        '对自绘控件、游戏引擎渲染、强反自动化页面覆盖有限；'
        '检测期间若未解锁屏幕，遍历不会执行（报告中会标注）。'
        '界面结构导出只含前台窗口，<b>系统悬浮窗（如屏幕录制控制条）不在导出结果中'
        '却会拦截触摸</b>，平台会在采集前与遍历中自动识别并关闭此类窗口'
        '（判据为窗口类型为覆盖型且当前可见），已清理的窗口见 3.8 节。</li>',
        '<li><b>误报控制</b>：运行时证据经过五级漏斗筛选 —— '
        '① 接口命中 → ② 取到有效值 → ③ 堆栈与包名排除 → ④ 有去向下落 → ⑤ 进报告。'
        '事件按 A/B/C/D 证据分级标注；标为「疑似」的项仍需人工复核。</li>',
        '<li><b>结论性质</b>：本报告为自动化初筛结果，用于确定人工精检的重点方向，'
        '不作为对外出具的检测结论。</li>',
        '</ul></div>',
    ]
    if meta.get("ai_used"):
        lines.append('<p class="note">问题描述由大模型辅助生成（%s），'
                     '关键事实与判定结论均来自规则引擎与采集数据。</p>' % _e(meta["ai_used"]))
    return "".join(lines)


# ---------------------------------------------------------------- 主入口

def render_platform_report(*, target: Dict[str, Any], static=None, policy=None,
                           dynamic=None, judge=None, meta: Optional[Dict[str, Any]] = None,
                           title: str = "App 个人信息保护合规检测报告") -> str:
    meta = dict(meta or {})
    meta.setdefault("finished_at", time.strftime("%Y-%m-%d %H:%M:%S"))
    body = TEMPLATE_PATH.read_text(encoding="utf-8")
    return Template(body).safe_substitute(
        title=_e(title),
        header=_header(target, judge, meta),
        summary=_summary(target, static, policy, dynamic, judge, meta),
        findings=_findings(judge),
        appendix=_appendix(static, policy, dynamic, judge, meta),
        footer=_e(FOOTER_NOTE),
    )
