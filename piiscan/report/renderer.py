"""HTML 报告渲染。

问题描述有两条生成路径：
  1. AI 路径：把事件事实交给配置好的大模型（Ollama / OpenAI 兼容接口）生成；
  2. 模板路径：AI 未启用或调用失败时自动降级，保证报告永远出得来。
两条路径产出的报告结构完全一致，只在每条描述下方标注来源。
"""
from __future__ import annotations

import html
import json
import time
from collections import OrderedDict
from pathlib import Path
from string import Template
from typing import Any, Callable, Dict, List, Tuple

from ..ai.base import AIError, AIProvider
from ..models import CATEGORY_LABELS, SENSITIVE_CATEGORIES, PIIEvent

TEMPLATE_PATH = Path(__file__).resolve().parent / "template.html"

SYSTEM_PROMPT = (
    "你是移动应用个人信息保护合规检测的辅助分析助手。"
    "你会收到一条检测中实际观测到的敏感接口调用记录，"
    "请用一至两句简洁客观的中文描述该行为可能涉及的合规问题。"
    "只依据给出的事实，不要编造未提供的信息，不要给出法律定性意见，不要使用 Markdown 语法。"
)


# ---------------------------------------------------------------- 分组

def group_events(events: List[PIIEvent]) -> List[Tuple[str, List[PIIEvent]]]:
    """按「类别 + 接口」聚合成不符合项条目。

    已标 `noise`（系统/框架自身行为）的事件**不参与分组** —— 它们留在存档里备查，
    但不该出现在问题项明细中，否则人工复核要逐条读文字才能挑出去。
    """
    buckets: "OrderedDict[str, List[PIIEvent]]" = OrderedDict()
    for e in events:
        if getattr(e, "noise", ""):
            continue
        buckets.setdefault(e.group_key, []).append(e)
    # 被采集侧截断主机名的那一组，按前缀并回完整的那一组。
    # 例：URL 太长被截成 `https://license.vod2.myqcl…`，前缀 `license.vod2.myqcl`
    # 能唯一匹配到 `license.vod2.myqcloud.com` —— 本来是同一次连接的两次捕获。
    _merge_truncated_hosts(buckets)
    # 同意前发生的排前面
    ordered = sorted(buckets.items(),
                     key=lambda kv: (not kv[1][0].before_consent, kv[1][0].elapsed_ms))
    return ordered


def _merge_truncated_hosts(buckets: "OrderedDict[str, List[PIIEvent]]") -> None:
    """把 `target:~prefix` 形式的组并进 `target:prefix…` 的完整组（原地修改）。"""
    truncated = [k for k in buckets if "target:~" in k]
    if not truncated:
        return
    full_keys = [k for k in buckets if "target:~" not in k and "target:" in k]
    for tk in truncated:
        pref = tk.split("target:~", 1)[1]
        if not pref:
            continue
        for fk in full_keys:
            host = fk.split("target:", 1)[1]
            if host.startswith(pref):
                buckets[fk].extend(buckets.pop(tk))
                break
    # 没有更完整形式可并的截断组：把标记去掉，免得 `~` 出现在报告标题里
    for tk in [k for k in buckets if "target:~" in k]:
        clean = tk.replace("target:~", "target:")
        if clean in buckets:
            buckets[clean].extend(buckets.pop(tk))
        else:
            buckets[clean] = buckets.pop(tk)


def risk_of(events: List[PIIEvent]) -> Tuple[str, str]:
    e = events[0]
    if e.before_consent:
        return "高", "high"
    if e.category in SENSITIVE_CATEGORIES:
        return "中", "mid"
    return "低", "low"


# 描述里出现这些字样 = 结论倾向"不构成问题"。必须先于 _POS 判断。
_NEG_MARKERS = (
    "不宜单独认定", "不构成", "建议不认定", "不应认定", "不属于个人信息",
    "不含用户个人信息", "不含个人信息", "不涉及用户个人信息",
    "未发现该请求携带用户个人信息", "未发现携带用户个人信息", "未发现携带",
    "属常规", "常规调用", "并非网络外发", "不涉及向外部传输",
    "属于播放能力初始化", "属于应用本地数据库的初始化",
)
_POS_MARKERS = ("构成", "涉嫌", "需核查", "需进一步核查", "建议列为疑似", "疑似")


def ai_verdict(desc: str) -> str:
    """从一条问题描述里读出结论倾向：`neg` 不构成 / `pos` 构成 / `` 中性。

    ★ 为什么需要它（简小知 jxz3 真机）：
      风险等级由规则层机械生成（"发生在同意之前"→ 高风险），描述却由模型按事实写，
      两者会打架。典型是 MIUI 自己读 `persist.sys.spc.whitepkg` 那条 ——
      徽标写着"高风险"，描述却是"不含用户个人信息，建议不认定为违规收集"。
      读者只看徽标就会把它当成问题项；人工复核要从一堆写着"不构成"的条目里挑，
      等于把筛选成本原样还给了人。把倾向显式标在标题行上，复核顺序就一目了然。
    """
    d = desc or ""
    if any(m in d for m in _NEG_MARKERS):
        return "neg"
    if any(m in d for m in _POS_MARKERS):
        return "pos"
    return ""


# ---------------------------------------------------------------- 描述生成

def _facts(events: List[PIIEvent]) -> Dict[str, Any]:
    e = events[0]
    return {
        "个人信息类别": CATEGORY_LABELS.get(e.category, e.category),
        "调用的接口": e.api,
        "调用参数": e.args,
        "返回内容": e.result,
        "是否发生在用户确认隐私政策之前": e.before_consent,
        "本次检测中同类调用累计次数": len(events),
    }


def template_narrative(events: List[PIIEvent]) -> str:
    e = events[0]
    label = CATEGORY_LABELS.get(e.category, e.category)
    suffix = "（本次共 %d 次）" % len(events) if len(events) > 1 else ""
    if e.before_consent:
        return ("在用户确认隐私政策之前，应用即调用 %s 读取%s%s，"
                "涉嫌未征得用户同意收集个人信息。" % (e.api, label, suffix))
    return "应用在运行过程中调用 %s 读取%s%s。" % (e.api, label, suffix)


def ai_narrative(provider: AIProvider, events: List[PIIEvent]) -> str:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(_facts(events), ensure_ascii=False)},
    ]
    return provider.chat(messages)


class NarrativeStats:
    def __init__(self):
        self.ai_calls = 0
        self.ai_ok = 0
        self.ai_fail = 0
        self.template_used = 0
        self.last_error = ""

    @property
    def ai_effective(self) -> bool:
        return self.ai_ok > 0


def make_narrative(provider: AIProvider, use_ai: bool, events: List[PIIEvent],
                   stats: NarrativeStats, log: Callable[[str], None] = print):
    """返回 (描述文本, 来源标记)。"""
    if use_ai:
        stats.ai_calls += 1
        try:
            text = ai_narrative(provider, events)
            if text:
                stats.ai_ok += 1
                return text, "ai"
        except AIError as e:
            stats.ai_fail += 1
            if not stats.last_error:
                stats.last_error = str(e)
                log("[!] 模型调用失败，已降级为模板生成：%s" % e)
        except Exception as e:
            stats.ai_fail += 1
            if not stats.last_error:
                stats.last_error = str(e)
    stats.template_used += 1
    return template_narrative(events), "template"


BATCH_SYSTEM_PROMPT = (
    "你是移动应用个人信息保护合规检测的辅助分析助手。"
    "你会一次收到**多条**检测中实际观测到的敏感接口调用记录，编号从 1 开始。"
    "请为每一条用一至两句简洁客观的中文描述该行为可能涉及的合规问题。"
    "只依据给出的事实，不要编造未提供的信息，不要给出法律定性意见，不要使用 Markdown 语法。"
    "如果某条实际是框架/系统自身行为、或返回值不含用户个人信息（例如 classpath 资源读取、"
    "建表语句、公共存储目录路径、系统属性配置等），请如实说明它不构成个人信息收集。"
    "只输出一个 JSON 对象，键是编号字符串，值是描述文本，不要输出任何其它内容。"
    "形如：{\"1\": \"……\", \"2\": \"……\"}"
)


def batch_narratives(provider: AIProvider, groups: List[Tuple[str, List[PIIEvent]]],
                     stats: NarrativeStats,
                     log: Callable[[str], None] = print) -> Dict[str, str]:
    """一次请求生成所有条目的描述，返回 {group_key: 描述}。

    ★ 为什么要批量（简小知 jxz3 实测）：逐条请求时 15 个条目 = 15 次往返，
      真机上单条模型耗时 40~60 秒，报告阶段凭空多花十几分钟，而且每一条都要
      人工/AI 单独看一次几乎相同的提示词。一次问完，往返从 N 降到 1，
      模型还能横向看到全部条目、避免对本质相同的两条给出互相矛盾的说法。

    解析失败（模型没按 JSON 回话）时返回空 dict —— 调用方会退回逐条生成，
    行为与从前一致，不会因为批量这一步而丢掉任何一条描述。
    """
    if not groups:
        return {}
    items = []
    index_to_key: Dict[str, str] = {}
    for i, (key, events) in enumerate(groups, 1):
        f = _facts(events)
        f = {"编号": i, **f}
        items.append(f)
        index_to_key[str(i)] = key

    # ★ 分批：条目多时（或"返回内容"字段很长时）一次性塞进去会超上下文。
    #   小上下文模型超限是静默截尾，模型只看到前几条却仍会返回一个"看着完整"
    #   的 JSON，后面那些条目就永远拿不到描述了。按预算切批，宁多几次往返。
    budget = 6000
    try:
        budget = max(1200, int(provider.input_budget_chars())
                     - len(BATCH_SYSTEM_PROMPT) - 200)
    except Exception:
        pass

    batches: List[List[dict]] = []
    cur: List[dict] = []
    used = 0
    for it in items:
        n = len(json.dumps(it, ensure_ascii=False)) + 2
        if cur and used + n > budget:
            batches.append(cur)
            cur, used = [], 0
        cur.append(it)
        used += n
    if cur:
        batches.append(cur)

    out: Dict[str, str] = {}
    for bi, batch in enumerate(batches, 1):
        messages = [
            {"role": "system", "content": BATCH_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(batch, ensure_ascii=False)},
        ]
        stats.ai_calls += 1
        try:
            raw = provider.chat(messages)
        except Exception as e:                   # AIError 与解析异常一视同仁
            stats.ai_fail += 1
            stats.last_error = stats.last_error or str(e)
            log("[!] 批量描述生成失败（第 %d/%d 批），回退逐条生成：%s"
                % (bi, len(batches), e))
            return {}
        parsed = _parse_json_object(raw)
        if not parsed:
            stats.ai_fail += 1
            log("[!] 批量描述返回的不是 JSON 对象（第 %d/%d 批），回退逐条生成"
                % (bi, len(batches)))
            return {}
        for k, v in parsed.items():
            key = index_to_key.get(str(k))
            if key and isinstance(v, str) and v.strip():
                out[key] = v.strip()

    if out:
        stats.ai_ok += 1
        log("[*] 批量描述：%d 次请求生成 %d/%d 条问题描述"
            % (len(batches), len(out), len(groups)))
    else:
        stats.ai_fail += 1
    return out


def _parse_json_object(raw: str) -> Dict[str, Any]:
    """从模型回复里抠出 JSON 对象，容忍 ```json 围栏和前后废话。"""
    if not raw:
        return {}
    s = raw.strip()
    if s.startswith("```"):
        s = s.split("```")[1] if "```" in s[3:] else s.strip("`")
        s = s[4:] if s.lower().startswith("json") else s
    try:
        got = json.loads(s)
        return got if isinstance(got, dict) else {}
    except Exception:
        pass
    i, j = s.find("{"), s.rfind("}")
    if 0 <= i < j:
        try:
            got = json.loads(s[i:j + 1])
            return got if isinstance(got, dict) else {}
        except Exception:
            return {}
    return {}


# ---------------------------------------------------------------- HTML 片段

def _esc(s: Any) -> str:
    return html.escape(str(s), quote=True)


def _kpi(value: Any, label: str, tone: str = "") -> str:
    return ('<div class="kpi %s"><div class="kpi-v">%s</div>'
            '<div class="kpi-l">%s</div></div>' % (tone, _esc(value), _esc(label)))


def _finding(events: List[PIIEvent], narrative: str, source: str) -> str:
    e = events[0]
    level, tone = risk_of(events)
    src_label = "模型生成" if source == "ai" else "模板生成"
    badge = '<span class="badge %s">%s风险</span>' % (tone, _esc(level))
    verdict_html = ""
    verdict = ai_verdict(narrative)
    if verdict == "neg":
        # 视觉上必须和真正的"问题项"区分开，否则人工复核又得逐条读文字才知道
        # 哪些其实不构成问题 —— 那等于把筛选成本原样还给了人。
        tone = "low"
        badge = ('<span class="badge low">存疑·非问题项</span>'
                 '<span class="badge low">AI 建议不认定</span>')
        verdict_html = (
            '<p style="margin:.5em 0 0;padding:.5em .7em;background:#eef7ee;'
            'border-left:3px solid #4c9a52;border-radius:4px;color:#245c28;font-size:.92em">'
            '该条命中了「同意之前」等规则条件，但模型依据事实判断其不涉及用户个人信息，'
            '建议人工确认后从问题项中剔除。</p>')
    elif verdict == "pos":
        verdict_html = (
            '<p style="margin:.5em 0 0;padding:.5em .7em;background:#fdecea;'
            'border-left:3px solid #c0392b;border-radius:4px;color:#7b241c;font-size:.92em">'
            '模型判断该行为可能构成不符合项，建议列入复核重点。</p>')
    rows = [
        ("触发过程", "冷启动后第 <b>%.1fs</b> 调用 <code>%s</code>" % (e.elapsed_ms / 1000.0, _esc(e.api))),
        ("调用参数", "<code>%s</code>" % _esc(e.args or "—")),
        ("返回值", "<code>%s</code>" % _esc(e.result or "—")),
        ("发生时机", ("<span class='warn'>用户确认隐私政策之前</span>" if e.before_consent
                     else "用户确认隐私政策之后")),
        ("累计次数", "%d 次（本次检测）" % len(events)),
        ("线程", "<code>%s</code>" % _esc(e.thread or "—")),
    ]
    facts = "".join("<tr><th>%s</th><td>%s</td></tr>" % (k, v) for k, v in rows)
    stack = "\n".join(e.stack) if e.stack else "(未捕获到调用栈)"
    return (
        '<div class="finding %s">'
        '<div class="f-head">'
        '%s'
        '<span class="cat">%s</span>'
        '<span class="api">%s</span>'
        '</div>'
        '<p class="narr">%s<span class="src">%s</span></p>'
        '%s'
        '<table class="facts">%s</table>'
        '<details><summary>调用栈（%d 层）</summary><pre>%s</pre></details>'
        '</div>'
    ) % (tone, badge, _esc(CATEGORY_LABELS.get(e.category, e.category)),
         _esc(e.api), _esc(narrative), _esc(src_label), verdict_html,
         facts, len(e.stack), _esc(stack))


def _shots(shots: List[Dict[str, str]]) -> str:
    if not shots:
        return '<p class="muted">本次检测未抓取截图。</p>'
    out = []
    for s in shots:
        out.append('<figure><img src="data:image/png;base64,%s" alt="%s"/>'
                   '<figcaption>%s</figcaption></figure>' % (s["b64"], _esc(s["label"]), _esc(s["label"])))
    return '<div class="shots">%s</div>' % "".join(out)


def _list(items: List[str], empty: str) -> str:
    if not items:
        return '<p class="muted">%s</p>' % _esc(empty)
    return "<ul class='plain'>%s</ul>" % "".join("<li>%s</li>" % _esc(i) for i in items)


# ------------------------------------------------------- 隐私政策获取情况

# 与 collector.INLINE_POLICY_MIN 保持一致：低于这个长度不算"完整条款"。
# 不直接 import collector —— 那个模块顶层依赖 frida，
# 会让报告层在没装 frida 的环境（如纯离线渲染）直接导入失败。
INLINE_POLICY_MIN = 1200

# 结论 → (中文标题, 色彩档, 一句话解释)
# 色彩档沿用报告既有语义：high = 应当写进问题项；mid = 需要人工核对；""=正常。
POLICY_OUTCOMES: Dict[str, Tuple[str, str, str]] = {
    "full": ("已取得完整政策条款", "", "政策入口可正常打开，且拿到了足够长的条款正文。"),
    "full_inline": ("已取得完整政策条款（应用内直接呈现）", "",
                    "应用未跳转外部页面，而是在弹窗/页面内直接展示了完整条款。"),
    "notice_only": ("未取得完整条款：仅拿到首启弹窗的告知摘要", "mid",
                    "入口点开后累计文本与弹窗告知摘要相当，判断未真正提供可查阅的条款全文。"),
    "error_page": ("未取得条款：政策入口打开的是错误页", "high",
                   "入口本身存在、可以点击，但打开后是错误页 —— 用户实际无法查阅收集使用规则。"),
    # ★ 2026-11-10：测试机自己没网时，任何政策页都会显示"网页无法打开"。
    #   这种轮次必须单独一档 —— 记成 error_page 等于把测试环境的问题写成
    #   应用的缺陷，是这一行里最严重的一类误报（那一批 15 单有 8 单断网）。
    "offline_unverified": ("无法判断：测试机当时没有网络", "mid",
                           "点击政策入口后页面无法加载，但采集当时测试机处于断网状态"
                           "（飞行模式 / 未连接 Wi-Fi 或数据）。此时任何网页都会显示"
                           "「网页无法打开」，因此本轮**不能**据此判断应用的政策链接是否可用；"
                           "需在联网环境下重跑该应用才能得出结论。"),
    "no_text": ("未取得条款：点击入口后没有政策文本", "mid",
                "已尝试点击政策入口，但页面上没有可提取的条款文本，需人工确认是否被反自动化拦截。"),
    "external_app": ("未取得条款：政策页由系统组件/外部应用打开", "mid",
                     "应用内没有政策页，点入口后交给了系统浏览器或其他应用；"
                     "本次未能在其中读到可用的条款正文，需人工核对。"),
    "external_partial": ("已取得部分条款：政策页在系统浏览器内", "mid",
                         "应用内没有政策页，入口由系统浏览器打开；已按屏幕逐屏读取到"
                         "一部分条款正文，可能不足以支撑全部条款比对，需人工补全。"),
    # 2026-11-05 高途：浏览器里确实读出 7815 字，但那 7815 字是浏览器首页/搜索页，
    # 没有通过「像不像隐私政策」的判据。旧代码只看字数就写"已取得全文"——
    # 结论说有、证据是空。单独一档，把"读到了但没认下来"和"根本没读到"分开。
    "external_unverified": ("浏览器内读到文字但未认定为政策正文", "mid",
                            "入口由系统浏览器打开，界面里读到了文字，但内容不像隐私政策"
                            "（多为浏览器首页/搜索结果/跳转提示），未作为条款正文使用；"
                            "该页需人工在浏览器中核对。"),
    "no_entry": ("未定位到政策入口", "mid",
                 "首启观测期内没有定位到可点击的隐私政策入口。"
                 "这不等于应用没提供：WebView／自绘界面里的超链接在界面结构树中"
                 "可能完全不可见（实测过这种），需人工复核屏幕上是否提供了收集使用规则。"),
    "not_run": ("本次未执行首启政策捕获", "", "本次检测未进入首启流程（如应用非首次启动）。"),
}


def _plain_policy_text(txt: str) -> str:
    """把"其实是 HTML 源码"的政策正文转成可读文本。

    ★ 为什么报告层也要做一次（2026-11-09 用户第 5 条：镜像投屏"政策可读性
      非常差"）：采集层已经把这类正文转成纯文本了，但**历史存档**里存的还是
      源码（200001 字全是 `<span style="font-size: 11pt; …">`）。重渲染旧存档、
      以及采集层漏转的情况，都会让报告把一整页 CSS 当正文印出来。
      渲染是最后一道关，在这里兜住，比事后逐份改存档靠谱。
    """
    s = (txt or "").strip()
    if not s or not s.startswith("<"):
        return s
    try:
        from .. import policy as _P          # 延迟导入：避免与 collector 循环依赖
        out, _title = _P.html_to_text(s)
        return (out or "").strip() or s
    except Exception:
        return s


def _policy_block(res) -> str:
    """渲染「隐私政策获取情况」。

    ★ 为什么这段必须单独成节（而不是塞进「不符合项明细」里）：
      政策到底拿没拿到，决定了整份报告里**一半以上判定项**能不能成立 ——
      「同意前收集」「超出必要范围」「未同步告知目的」全都要拿政策文本做比对。
      只报"采集到 N 条事件"而把这件事含糊过去，报告就失去了判断前提。
      真机教训（赣警办）：入口指向的链接 404，弹窗里的 428 字告知摘要
      曾被误当成政策正文，报告于是写「政策已获取」—— 结论与事实完全相反。
    """
    cap = getattr(res, "policy_capture", None) or {}
    if not cap:
        return '<p class="muted">本次未执行首启政策捕获。</p>'

    key = str(cap.get("outcome") or "not_run")
    title, tone, explain = POLICY_OUTCOMES.get(key, POLICY_OUTCOMES["not_run"])

    badge = '<span class="badge %s">%s</span>' % (tone, _esc(title))
    head = '<div class="f-head">%s</div><p class="narr">%s</p>' % (badge, _esc(explain))

    # ---- 关键事实 ----
    urls = [str(u.get("url") or "") for u in (cap.get("urls") or []) if u.get("url")]
    entries = [t for t in (cap.get("entryTexts") or []) if t]
    got = _plain_policy_text(cap.get("bestText") or "")
    notice = (cap.get("noticeText") or "").strip()
    tap_xy = cap.get("entryTapXY") or []

    rows: List[Tuple[str, str]] = []
    rows.append(("政策入口", "、".join(_esc(e) for e in entries[:4]) or "—"))
    if cap.get("entrySource"):
        rows.append(("入口识别方式", _esc(cap["entrySource"])))
    if cap.get("entryClicked"):
        rows.append(("实际点击目标", _esc(cap["entryClicked"])))
    if tap_xy:
        rows.append(("点击坐标", "<code>(%s, %s)</code>" % (_esc(tap_xy[0]), _esc(tap_xy[1]))))
    if urls:
        rows.append(("打开的地址", "　".join("<code>%s</code>" % _esc(u) for u in urls[:4])))
    if cap.get("errorPage"):
        rows.append(("错误页特征", "<span class='warn'>命中「%s」</span>" % _esc(cap["errorPage"])))
    snap = cap.get("openSnapshot") or {}
    if snap.get("focus"):
        # 「点开瞬间的前台页面」是区分「点击没生效」与「打开了但页面是死的」的硬证据；
        # 它必须在点开那一刻就抓，晚了页面已被滚动/回退带离。
        rows.append(("点开后前台页面",
                     "<code title='%s'>%s</code>" % (
                         _esc(str(snap["focus"])),
                         _esc(str(snap["focus"]).split("/")[-1]))))
    rows.append(("条款正文长度", "%d 字%s" % (
        len(got),
        "（不足 %d 字，不视为完整条款）" % INLINE_POLICY_MIN if got and len(got) < INLINE_POLICY_MIN else "")))
    if notice:
        # 弹窗上的那段文字**永远**不是政策全文（它只是首启告知摘要）。
        # 更要紧的是另一种情况：抓到的"政策正文"与弹窗摘要一模一样 ——
        # 说明入口根本没点开、只是停在弹窗上，这是历史上导致结论反转的根因，
        # 必须在报告里点出来，不能只报一个字数。
        #
        # ★ 但"字数相同"有两种成因，不能一律判成"入口没点开"：
        #   · 入口确实没点开（前台没换页）→ 这才是问题所在，要告警；
        #   · 入口点开了，但那一页给不出可读文本（错误页 / 纯 JS 渲染）→
        #     此时两者字数相同是**正常现象**。真机实测（赣警办 e2e12）：
        #     前台已切到 WebAndroidActivity、页面是 404 错误页，
        #     正文抓不到，字数自然与弹窗摘要一致 —— 若照旧告警，
        #     报告会一边说"打开了错误页"、一边说"入口并未真正打开"，自相矛盾。
        #   error_page / no_text 这两个结论本身就意味着"页面打开过"。
        _opened = key in ("error_page", "no_text")
        if got and notice.strip() == got.strip():
            if _opened:
                note_suffix = ("<span class='muted'>（该页未能提供可读条款，此处与"
                               "上方字数相同属正常，并非入口未打开）</span>")
            else:
                note_suffix = ("<span class='warn'>★ 与条款正文完全相同 —— "
                               "说明政策入口并未真正打开，只是停留在首启弹窗上</span>")
        else:
            note_suffix = "（弹窗告知文本，不是政策全文）"
        rows.append(("首启弹窗告知摘要", "%d 字%s" % (len(notice), note_suffix)))
    if cap.get("pageKind"):
        rows.append(("政策页性质（AI 判定）", _esc(cap["pageKind"])))
    if cap.get("webviewCount"):
        rows.append(("WebView 实例", "%s 个" % _esc(cap["webviewCount"])))
    links = [str(x) for x in (cap.get("pageLinks") or []) if x]
    if links:
        rows.append(("政策页上的其它文档", "、".join(_esc(x) for x in links[:6])))

    facts = "".join("<tr><th>%s</th><td>%s</td></tr>" % (k, v) for k, v in rows)

    # ---- 观测备注（采集过程中写下的判断依据）----
    notes = [str(n).replace("**", "") for n in (cap.get("notes") or []) if n]
    notes_html = _list(notes, "无")

    # ---- AI 原话留痕：报告要能回答"这个结论是模型判的还是规则判的" ----
    trace = [t for t in (getattr(res, "ai_trace", None) or [])
             if str(t.get("stage") or "") in ("首启弹窗", "政策页判定")]
    ai_html = ""
    if trace:
        items = []
        for t in trace:
            raw = str(t.get("raw") or "").replace("\n", " ").strip()
            items.append("%s —— 结论 %s%s" % (
                t.get("stage"), t.get("action") or "—",
                ("；模型原话：%s" % raw[:260]) if raw else
                ("；解析失败：%s" % t.get("error")) if t.get("error") else ""))
        ai_html = ("<h3 style='font-size:13.5px;margin:16px 0 8px;font-weight:600;'>"
                   "AI 判断留痕</h3>" + _list(items, "无"))

    return head + "<table class='meta'>%s</table>" % facts + \
        "<h3 style='font-size:13.5px;margin:16px 0 8px;font-weight:600;'>观测说明</h3>" + \
        notes_html + ai_html


# ---------------------------------------------------------------- 主入口

def render(cfg, res, provider: AIProvider, log: Callable[[str], None] = print,
           preset_narratives: Dict[str, Tuple[str, str]] = None
           ) -> Tuple[str, NarrativeStats]:
    """渲染阶段 0 报告。

    `preset_narratives`：{group_key: (描述, 来源)}。用于从 result.json 重渲染时
    复用**当时生成的**描述 —— 否则重渲染只能退回内置模板，同一份样本两次出报告
    文字不一致，AI 写过的话也留不下来。
    """
    stats = NarrativeStats()
    use_ai = cfg.ai.feature("report_narrative") and provider.name != "none"

    if cfg.ai.feature("report_narrative") and provider.name == "none":
        log("[*] 未启用大模型（ai.provider=none），问题描述使用内置模板生成")

    groups = group_events(res.events)
    preset: Dict[str, Tuple[str, str]] = dict(preset_narratives or {})

    # 还没描述的条目 → 一次请求全问完（见 batch_narratives 的说明）。
    missing = [kv for kv in groups if kv[0] not in preset]
    if use_ai and missing:
        got = batch_narratives(provider, missing, stats, log)
        for k, v in got.items():
            preset[k] = (v, "ai")

    findings = []
    saved: List[Dict[str, Any]] = []
    for key, events in groups:
        if key in preset:
            narrative, source = preset[key]
        else:                       # 批量没覆盖到（或 AI 未启用）→ 逐条 / 模板
            narrative, source = make_narrative(provider, use_ai, events, stats, log)
        findings.append(_finding(events, narrative, source))
        saved.append({"group_key": key, "narrative": narrative, "source": source})
    # 落到 ScanResult 上，run_scan 存档 result.json 时会一起写盘
    try:
        res.narratives = saved
    except Exception:
        pass

    # 有效事件 = 剔除系统/框架自身行为之后剩下的事件。
    # 两个数都显示：既让读者知道原始采集量，也让他们看到漏斗排掉了多少噪声。
    noise_n = len([e for e in res.events if getattr(e, "noise", "")])
    effective = [e for e in res.events if not getattr(e, "noise", "")]
    before = [e for e in res.before_consent_events if not getattr(e, "noise", "")]
    cats = {e.category for e in effective}

    cards = "".join([
        _kpi(len(res.events), "采集事件总数"),
        _kpi(len(effective), "有效事件", "" if not noise_n else "ok"),
        _kpi(len(before), "同意前发生", "danger" if before else ""),
        _kpi(len(groups), "涉及接口条目"),
        _kpi(len(cats), "涉及信息类别"),
        _kpi(noise_n, "已排除系统噪声", "" if not noise_n else "ok"),
        _kpi(len(res.hooks_installed), "已生效 hook 点"),
    ])

    if provider.name == "none":
        ai_desc = "未启用（报告由内置模板生成）"
    else:
        ai_desc = "%s · 模型 %s" % (provider.label, cfg.ai.model)

    ai_stats = "模型调用 %d 次，成功 %d 次，降级模板 %d 次" % (
        stats.ai_calls, stats.ai_ok, stats.template_used)
    if stats.last_error:
        ai_stats += "；最近一次错误：%s" % stats.last_error

    consent_line = ("检测到用户同意隐私政策的操作，发生于第 %.1fs"
                    % (res.consent_elapsed_ms / 1000.0)) if res.consent_given else "本次检测未捕获到用户同意操作"

    # 政策获取结论放进基本信息：它是后面所有"政策比对类"判定的前提，
    # 检测人员第一眼就该看到"这次到底有没有拿到政策文本"。
    _cap = getattr(res, "policy_capture", None) or {}
    _pk = str(_cap.get("outcome") or "not_run")
    policy_line = POLICY_OUTCOMES.get(_pk, POLICY_OUTCOMES["not_run"])[0]

    meta_rows = [
        ("被测应用", res.package),
        ("测试设备", "%s（Android %s）" % (res.device_model or "—", res.android_version or "—")),
        ("设备序列号", res.device_serial),
        ("检测开始", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(res.started_at))),
        ("检测结束", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(res.ended_at))),
        ("采集时长", "%.0f 秒" % res.duration),
        ("同意状态", consent_line),
        ("隐私政策", policy_line),
        ("UI 自动遍历", "共点击 %d 次" % res.ui_taps),
        ("AI 配置", ai_desc),
        ("AI 调用情况", ai_stats),
    ]
    meta = "".join("<tr><th>%s</th><td>%s</td></tr>" % (k, _esc(v)) for k, v in meta_rows)

    if res.ui_steps:
        steps_html = "<ol class='steps'>%s</ol>" % "".join(
            "<li>%s</li>" % _esc(s.split(". ", 1)[-1]) for s in res.ui_steps)
    else:
        steps_html = '<p class="muted">本次未执行 UI 自动遍历。</p>'

    body = TEMPLATE_PATH.read_text(encoding="utf-8")
    html_out = Template(body).safe_substitute(
        title=_esc(cfg.report.title),
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        meta_rows=meta,
        policy_block=_policy_block(res),
        cards=cards,
        findings="".join(findings) if findings else '<p class="muted">本次未采集到敏感接口调用。</p>',
        screenshots=_shots(res.screenshots),
        ui_steps=steps_html,
        hooks_installed=_list(res.hooks_installed, "无"),
        hooks_failed=_list(res.hooks_failed, "无"),
        errors=_list(res.errors, "无"),
        event_total=len(res.events),
    )
    return html_out, stats
