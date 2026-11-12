"""四个 AI 任务 —— 用多模态/大模型替换掉「关键词匹配 + 文本长度启发式」。

为什么必须换：这些环节原来的确定性策略都撞到了各自的语义天花板。

  · 政策入口定位   —— 关键词匹配认不出「服务协议及个人信息处理规则」等于隐私政策，
                      也分不清「同意」和「不同意」；标题「隐私政策」常常 clickable=false
  · 政策页分类     —— 靠「正文长度 > 1200 字」判断是否采全，遇到目录页就失效
                      （目录页本身没正文，但它恰好是通往正文的唯一入口）
  · 政策结构化     —— 正则去找「第三方共享清单」链接，遇到图片链、文字链、跳转按钮全失效
  · UI 遍历        —— 「按优先级取第一个可点节点」是盲走，不知道自己在第几步、
                      更不知道离目标（注销入口/权限弹窗）还有多远

AI 在这里不是「加个花哨功能」，而是**补上语义理解这一层**。因此每个任务都遵守
同一条契约：**AI 不可用或返回异常时返回 None，由调用方回退到原有确定性策略**。
绝不允许因为模型没配好就让检测跑不出结果。

坐标系约定（重要）：所有 AI 返回的 bbox 都是**相对所给图片的归一化坐标 0~1**，
由 ai/vision.py 的 norm_to_px 换算回原图。不要让模型输出像素坐标 —— 实测它给不准。
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import chunker
from . import vision
from .base import AIError, AIProvider


@dataclass
class AIReturn:
    """一次 AI 任务的结果。

    除了业务字段，还带两样东西供审计：
      raw         —— 模型原始输出（报告里要能回看它的理由）
      annotated   —— 送进模型的标注图（JPEG 字节），存进证据目录
                    后人工可以核对「模型当时到底看到了什么」
    """

    data: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    annotated: Optional[bytes] = None
    ok: bool = False
    error: str = ""

    def get(self, k: str, default=None):
        return self.data.get(k, default)


# ---------------------------------------------------------------- 预算
# ★ 遍历两处（plan_ui_action / choose）的文字预算**封顶且与 context_tokens 解耦**。
#   上下文从 4096 抬到 8192（2026-10-25 核对 Modelfile）之后，这两处若按比例跟着涨，
#   模型看到的候选与排序会变，点击顺序跟着变、覆盖的界面跟着变 —— 跨轮"同一判据没再现"
#   就分不清是问题消失了还是压根没走到。政策/报告环节可以吃这份红利，遍历这条链路不吃。
UI_TEXT_BUDGET_CAP = 2400      # 图引导决策（带标注框）的界面文字预算
CHOOSE_TEXT_BUDGET_CAP = 1600  # 选项选择（原图）的界面文字预算


# ---------------------------------------------------------------- 提示词

_COMMON_SYSTEM = (
    "你是移动应用个人信息保护合规检测的专家助手，熟悉中国《个人信息保护法》"
    "（PIPL）、《信息安全技术 个人信息安全规范》（GB/T 35273）以及"
    "《App 违法违规收集使用个人信息行为认定方法》。"
    "你只输出 JSON，不输出任何解释性文字、不加 Markdown 代码块。"
    "不确定时如实降低 confidence，不要编造。"
)

# 政策所在区域的通用认知 —— 反复在多个提示词里出现，抽出来保持一致
_POLICY_KNOWLEDGE = (
    "背景知识：隐私政策在不同 App 里有大量不同的叫法 ——「隐私政策」「隐私权政策」"
    "「个人信息保护政策」「个人信息保护指引」「用户隐私政策」「隐私协议」"
    "「个人信息处理规则」「服务协议及个人信息处理规则」「协议与规则」等。"
    "首启界面上它可能表现为：一段很长的告知正文（无需点击，正文直接铺在界面上）、"
    "一个可点击的链接或按钮、勾选框旁的带下划线的文字、或者根本没有任何提示。"
)


def _entry_prompt(package: str, app_label: str, screen_texts: Sequence[str],
                  cand_lines: Sequence[str], has_candidates: bool) -> str:
    lines = [
        "任务：这是 App **首次启动**时的界面截图。请判断界面上哪里是"
        "「隐私政策 / 个人信息保护政策」的入口，或者界面本身是否就是政策内容。",
        _POLICY_KNOWLEDGE,
        "",
        "已检测到的 App 信息：包名 %s，应用名 %s。" % (package or "未知", app_label or "未知"),
    ]
    if screen_texts:
        lines += ["", "界面上的文字（按出现顺序，仅供交叉验证）：",
                  " | ".join([str(t)[:60] for t in list(screen_texts)[:25]])]
    if has_candidates:
        lines += [
            "",
            "⭐ 我在截图上把**可点击的元素**画了红/蓝色矩形框，框左上角有编号。",
            "候选列表（格式：编号. 元素文字，附加线索）：",
        ]
        lines += ["  " + l for l in cand_lines]
    else:
        lines += ["", "（界面上没有导出到可点击元素，请直接依据截图判断。）"]

    lines += [
        "",
        "判断要求：",
        "1. 「不同意 / 拒绝 / 退出」这类**拒绝性**按钮**不是**政策入口，必须排除。",
        "2. 不可点击的**标题**不是入口（例如只是一个大字标题「隐私政策」但没有跳转）。",
        "3. 如果界面上只看到一段简短的提示语（例如「请您仔细阅读并同意…协议」），"
        "且没有任何链接或按钮指向政策全文，判为该 App **只有告知没有提供政策入口**。",
        "4. 如果界面上直接铺着很长的政策正文（能读到条款编号、收集信息清单等），"
        "判为**政策全文直接内联**，此时入口是可选的。",
        "5. ⭐ 特别注意：告知正文里常嵌着**带颜色或下划线的超链接**"
        "（例如「《个人信息保护》」「《隐私协议》」这种书名号包起来的彩色文字）。"
        "这类链接在程序的结构树里**拿不到位置**，只有你能看见。"
        "如果发现了，务必在 entry_bbox 里给出它的位置、entry_text 填链接文字，"
        "并令 display_form = entry_link —— 这是我们能否打开完整政策正文的关键。",
        "",
        "只输出如下 JSON：",
        json.dumps({
            "policy_present": "true/false —— 这一屏上有没有隐私政策相关内容",
            "display_form": "entry_link（有可点入口）/ inline_full（正文直接铺开）/ "
                            "notice_only（只有简短告知、无入口）/ none（完全没有）",
            "entry_index": "整数。政策入口对应的框编号；没有则填 0",
            "entry_text": "该入口在界面上显示的文字，照抄，不要改写；没有则空字符串",
            "entry_bbox": "[x1,y1,x2,y2] 归一化到 0~1。当入口没有编号（框没画到它上面，"
                          "比如是段落里的超链接）时，用它指出位置；否则填 []",
            "longest_text_holder": "如果界面上有长段政策正文，指出它所在的那个框编号，否则 0",
            "confidence": "0~1 的小数",
            "reason": "一句话说明你的判断依据",
        }, ensure_ascii=False, indent=1),
    ]
    return "\n".join(lines)


def _page_prompt(texts: Sequence[str], cand_lines: Sequence[str], has_candidates: bool,
                 opened_from: str) -> str:
    lines = [
        "任务：这是「点击了 %s 之后」打开的页面截图。请判断它的性质。" % (opened_from or "某个入口"),
        "",
        "背景：不少 App 的政策入口点进去**不是政策正文，而是一个目录/索引页**，"
        "列着若干份文档（如「个人信息处理规则」「软件使用协议」「第三方共享清单」"
        "「儿童个人信息保护规则」「历史版本」等），真正要看的内容还要再点一层。"
        "也有 App 点进去先要登录，或者弹出了验证码。",
        "",
        "页面上的文字（供交叉验证）：",
        " | ".join([str(t)[:60] for t in list(texts)[:25]]) or "（无）",
    ]
    if has_candidates:
        lines += ["",
                  "⭐ 我在截图上把**可点击的元素**画了带编号的框："]
        lines += ["  " + l for l in cand_lines]
    lines += [
        "",
        "只输出如下 JSON：",
        json.dumps({
            "page_kind": "full_text（已是政策正文）/ document_index（文档目录，需要再点进去）"
                         "/ login_wall（要求登录）/ captcha（人机或短信验证）/ "
                         "/ other（其它，如首页、错误页）",
            "is_policy_content": "true/false —— 本页内容是不是隐私政策/个人信息处理规则本身",
            "next_targets": "[{index, text, why}] 若需要继续点击，给出**应该点哪一个**（优先"
                            "「个人信息处理规则 / 隐私政策 / 个人信息保护政策」这类主政策，"
                            "而不是「软件使用协议」等次级文档）。按优先级排序，最多 3 个。",
            "links": "[{text, url, bbox}] 页面上出现的、指向其它文档的链接。"
                     "url 若界面上能看到就照抄，看不到填空字符串。",
            "confidence": "0~1",
            "reason": "一句话依据",
        }, ensure_ascii=False, indent=1),
    ]
    return "\n".join(lines)


_ANALYZE_SYSTEM = (
    "你是个人信息保护合规审查专家，负责把一份隐私政策读透并结构化。"
    "要求：严格依据原文，**不要脑补原文没写的内容**；原文没有的项填空数组或空字符串。"
    "只输出 JSON，不加任何解释文字。"
)


def _analyze_prompt(text: str, app_label: str, is_sub_document: bool = False,
                    limit: int = 24000) -> str:
    role = "一份从 App 内获取到的补充文档（可能是第三方共享清单等）" if is_sub_document \
        else "某 App 的隐私政策全文"
    body = text[:limit]      # 调用方按模型上下文预算传入；截断会如实标注
    truncated = len(text) > len(body)
    return "\n".join([
        "任务：仔细阅读下面的%s，抽取结构化信息。%s" % (
            role, "【注意：文本过长已截断，只分析了前面部分】" if truncated else ""),
        "App：%s" % (app_label or "未知"),
        "",
        "重点关注：",
        "1. **有没有指向其它文档的链接或名称** —— 尤其是「第三方信息共享清单」"
        "「第三方 SDK 目录」「个人信息对外提供清单」这类独立文档。"
        "这是合规检测最关键的证据：有清单就必须核对，没有清单本身就是问题。"
        "把它们的标题、可见的 URL、以及文中出现的位置都记下来。",
        "2. 声明收集了哪些**个人信息类型**（设备标识符、位置、通讯录、相册、"
        "应用列表、剪贴板、传感器等）。",
        "3. 收集使用的**目的**（用于什么功能）。",
        "4. 保存期限、是否涉及数据出境。",
        "5. **注销账号 / 更正删除个人信息** 的操作路径，要具体到入口在哪个菜单下。",
        "6. 投诉举报渠道（电话/邮箱/在线表单）。",
        "7. 未成年人（儿童）个人信息处理规则。",
        "8. 个性化推荐/广告的关闭方式。",
        "",
        "只输出如下 JSON（没有的项填空数组 [] 或空字符串）：",
        json.dumps({
            "third_party_docs": [{"title": "文档标题", "url": "可见的链接或空串",
                                  "where": "出现在政策的哪一节", "kind": "shared_list/sdk_list/other"}],
            "declared_types": ["声明收集的个人信息类型，用规范中文表述"],
            "purposes": ["收集使用目的"],
            "retention": "保存期限的原文表述",
            "cross_border": "数据出境的原文表述，没有则空字符串",
            "cancel_account": [{"path": "具体操作路径", "detail": "补充说明"}],
            "correct_delete": [{"path": "具体操作路径", "detail": "补充说明"}],
            "complaint": [{"channel": "邮箱/电话/在线", "detail": "具体值"}],
            "minor_rules": "未成年人保护条款摘要",
            "personalized_ads_off": "个性化推荐关闭方式",
            "contact": "个人信息保护负责人的联系方式",
            "summary": "150 字以内的政策要点概述",
        }, ensure_ascii=False, indent=1),
        "",
        "===== 政策原文开始 =====",
        body,
        "===== 政策原文结束 =====",
    ])


# ============================================================================
#  分段抽取（map）—— 给小上下文模型用的精简提示词
# ============================================================================
# 为什么不能复用 _ANALYZE_SYSTEM 那一套：它自带 12 条详细指令 + 完整 JSON 模板，
# 光指令就占 600 多 token，配上 2500 字正文在 8K 的预算里也偏紧（还要留 1536 给输出）。
# 分段抽取每块只要"这一段里有没有这些东西"，指令人为压到最短，
# 把省下的额度全部让给正文 —— 漏读正文才是真正的损失。
_CHUNK_SYSTEM = (
    "你是个人信息保护合规审查助手。用户给你一份隐私政策的其中一段，"
    "请只抽取**这一段里实际写了**的内容。原文没写的项一律留空，绝不脑补。"
    "只输出 JSON，不要解释。"
)

# 每块抽取的 JSON 骨架。键名与最终结构对齐，reduce 阶段可以直接并集。
_CHUNK_SCHEMA = {
    "declared_types": ["本段声明的个人信息类型，规范中文，如：设备标识符、位置、通讯录"],
    "third_parties": [{"name": "第三方名称", "purpose": "共享目的", "info": "涉及的信息类型"}],
    "docs": [{"title": "指向的其它文档标题", "url": "可见链接或空串"}],
    "cancel_account": [{"path": "注销账号的操作路径", "detail": "补充说明"}],
    "correct_delete": [{"path": "更正/删除个人信息的操作路径", "detail": "补充说明"}],
    "complaint": [{"channel": "邮箱/电话/在线表单/地址", "detail": "具体值"}],
    "minor_rules": "未成年人（儿童）条款要点，没有则空串",
    "personalized_ads_off": "个性化推荐/广告的关闭方式，没有则空串",
    "retention": "保存期限原文，没有则空串",
    "cross_border": "数据出境相关原文，没有则空串",
    "contact": "个人信息保护负责人联系方式，没有则空串",
}


def _chunk_prompt(chunk_text: str, heading: str, idx: int, total: int,
                  app_label: str) -> str:
    head = ("本段所属小节：%s\n" % heading) if heading else ""
    return "\n".join([
        "App：%s" % (app_label or "未知"),
        "这是隐私政策的第 %d/%d 段。%s" % (idx, total, head.strip()),
        "",
        "输出要求（务必遵守，否则结果会被截断而作废）：",
        "· 每个字段只写**本段原文里出现的**内容，没有就留空数组/空串，不要推测；",
        "· declared_types 每项不超过 10 个字，最多 15 项；",
        "· third_parties 最多 12 项，name/purpose/info 各不超过 25 字；",
        "· 字符串字段不超过 60 字；",
        "· 只输出 JSON，不要任何解释、不要 markdown 代码块。",
        "",
        "JSON 骨架：",
        json.dumps({k: (v if isinstance(v, str) else v) for k, v in _CHUNK_SCHEMA.items()},
                   ensure_ascii=False, indent=1),
        "",
        "===== 本段原文开始 =====",
        chunk_text,
        "===== 本段原文结束 =====",
    ])


_AGENT_SYSTEM = (
    "你操控一台安卓手机完成个人信息保护合规检测。你每一步只输出一个 JSON 动作指令，"
    "不加任何解释文字。你的操作必须安全：绝不能点击退出、卸载、支付、"
    "删除账号、拒绝授权这类会导致检测中断或行为失真的按钮。"
)

# 「选择题」模式的系统提示词。
#
# ★ 与 _AGENT_SYSTEM 的区别是本轮改造的核心（UI-KOBE 的做法）：不再要求模型
#   看着截图规划"整条路径该往哪走"，而是把当前界面上**本地已经算好的有限动作集**
#   交给它，让它只回答"选哪个编号"。同一批候选下，自由规划需要模型同时完成
#   「我在哪 / 我做过什么 / 目标在哪 / 先点哪个」四件事，小模型常常在第一步就错；
#   选择题只需要它做"这一个界面上的局部判断"。
_CHOOSE_SYSTEM = (
    "你在手机上做个人信息保护合规检测。每一步只输出一个 JSON，不要解释。\n"
    "规则：\n"
    "1. 只能从给定的动作编号里选一个，不能自己发明动作或坐标。\n"
    "2. 优先选能通向「设置 / 我的 / 账号 / 隐私」这类页面的入口，以及题干里点名"
    "还没找到的权利入口。\n"
    "3. 不要选标记为「死点」「陷阱」的入口，也不要选运营位（活动/领券/会员）。\n"
    "4. 当前界面已经没有可探索入口时，选返回或下滑，不要原地重复点。\n"
    "5. 同时用一句话描述当前界面是什么页面（page 字段），供后续复用。\n"
    '输出：{"choice":"A1","page":"设置页","reason":"20字内"}\n'
)


def _choose_prompt(options: Sequence[Any], memory: str, goal: str,
                   text_budget: int = 1400, screen_texts: Sequence[str] = ()) -> str:
    """「选择题」提示词。

    比 `_agent_prompt` 短得多，这是有意的：材料不再是"25 条屏幕文字 + 24 个候选框 +
    12 条历史"，而是"一张已经压缩好的图记忆 + 不到 10 个选项"。文字预算从 2600
    降到 1400 —— 材料越少，小模型越不会在中段丢东西；这条链路也**不因 num_ctx
    抬到 8192 而放宽**（见 CHOOSE_TEXT_BUDGET_CAP）。
    """
    lines: List[str] = []
    g = (goal or "").strip()
    if g:
        lines.append("【本轮目标】" + g[:300])
    mem = (memory or "").strip()
    if mem:
        lines.append(mem[:max(300, int(text_budget * 0.55))])
    lines.append("【当前界面可以做的事（只能选一个编号）】")
    for o in options or ():
        try:
            lines.append(o.line())
        except Exception:
            continue
    # 屏幕文字只给一小撮：它用来补充"这一屏在说什么"，不参与找按钮
    txts = [str(t)[:24] for t in (screen_texts or ())][:12]
    if txts:
        lines.append("【当前屏幕文字】" + " / ".join(txts)[:400])
    lines.append("只输出 JSON：{\"choice\":\"编号\",\"page\":\"当前页面一句话\","
                 "\"reason\":\"为什么选它\"}")
    return "\n".join(lines)


def _agent_prompt(package: str, app_label: str, goal: str, step: int,
                  history: Sequence[str], screen_texts: Sequence[str],
                  cand_lines: Sequence[str], has_candidates: bool,
                  back_unsafe: bool, text_budget: int = 2600) -> str:
    """UI 决策提示词。

    `text_budget` 是**纯文本部分**的字符预算。为什么要单独算：这个环节每步都带
    一张截图，图片在视觉编码器里要吃掉上千 token（720 宽的全屏截图约 1300~1500），
    8K 上下文的模型留给文字的空间其实只有一半。早先不管这个，把 12 条历史 +
    25 条屏幕文字 + 24 个候选框全塞进去，正文被静默截尾，模型看到的是一个
    残缺的界面 —— 于是点错位置，或者对已经做过的操作重复操作。
    """
    text_budget = max(800, int(text_budget or 2600))

    # 三份材料按比例分配预算，各自从"最近的 / 最靠前的"开始取
    hist_quota = int(text_budget * 0.26)
    chosen_hist, used = [], 0
    for h in reversed(list(history)):
        if len(chosen_hist) >= 10 or used + len(str(h)) > hist_quota:
            break
        chosen_hist.append(str(h))
        used += len(str(h))
    chosen_hist.reverse()

    txt_quota = int(text_budget * 0.44)
    chosen_texts, used = [], 0
    for t in list(screen_texts):
        s = str(t)[:50]
        if len(chosen_texts) >= 25 or used + len(s) > txt_quota:
            break
        chosen_texts.append(s)
        used += len(s)

    cand_quota = int(text_budget * 0.28)
    chosen_cands, used = [], 0
    for l in list(cand_lines):
        s = str(l)[:60]
        if used + len(s) > cand_quota:
            break
        chosen_cands.append(s)
        used += len(s)

    lines = [
        "任务：App「%s」（%s）的合规检测正在自动进行，当前是第 %d 步。"
        % (app_label or package, package, step),
        "本轮目标：%s" % goal,
        "",
        "已经做过的操作（最近的在最后）：",
    ]
    lines += ["  " + h for h in chosen_hist] or ["  （还没有操作）"]
    lines += ["",
              "当前界面上的文字：",
              " | ".join(chosen_texts) or "（无）"]
    if has_candidates and chosen_cands:
        lines += ["",
                  "⭐ 我在截图上把**可点击的元素**画了带编号的框："]
        lines += ["  " + l for l in chosen_cands]
    else:
        lines += ["", "（本页没有导出到可点击元素，你可能需要滑动或返回。）"]

    lines += [
        "",
        "可执行的动作（只选一个）：",
        "  tap    —— 点击某个框编号（index）或某个位置（bbox）",
        "  swipe  —— 滑动：direction = up/down/left/right（上滑=看下面的内容）",
        "  back   —— 返回上一级",
        "  input  —— 在输入框里输入内容（少见，谨慎用）",
        "  wait   —— 等待界面加载",
        "  done   —— 认为本轮目标已达成或无法继续",
        "",
        "安全红线（违反会导致检测失败，必须避免）：",
        "  · 绝不点击「不同意 / 拒绝 / 退出 / 取消 / 卸载 / 注销账号 / 删除账号 / 支付 / 立即购买」",
        "  · 优先探索与目标相关的入口（设置、我的、隐私、权限管理这类入口值得点进去找）",
        "  · 同一屏不要反复点同一个元素；如果最近几步都在原地打转，改为滑动或返回",
    ]
    if back_unsafe:
        lines += ["  · ⚠ 已确认本 App 在入口页按返回键会直接退出，禁止使用 back，"
                  "请改用 swipe 或其它入口"]
    lines += [
        "",
        "只输出如下 JSON：",
        json.dumps({
            "action": "tap/swipe/back/input/wait/done",
            "index": "整数。动作是 tap 且用框编号定位时填编号，否则填 0",
            "bbox": "[x1,y1,x2,y2] 归一化 0~1。动作是 tap 但没有合适编号时用它，否则填 []",
            "direction": "swipe 的方向，其它动作填空字符串",
            "text": "input 要输入的内容，其它填空字符串",
            "expect": "你预期这一步会发生什么（用于判断是否卡住）",
            "goal_progress": "not_found / progressing / achieved",
            "reason": "一句话说明为什么做这个动作",
        }, ensure_ascii=False, indent=1),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------- 任务门面

class AITasks:
    """把 AI 能力包装成业务层好调用的形态。

    每个方法都可能返回 None —— 表示「这次没让 AI 参与」，调用方必须准备好回退。
    设计上宁可回退也不要抛异常向上冒：一段模型的格式抖动不该让整个检测任务失败。
    """

    def __init__(self, provider: AIProvider, cfg, log: Callable[[str], None] = print):
        self.ai = provider
        self.cfg = cfg
        self.log = log
        self.notes: List[str] = []       # AI 参与过程的记录，最终进报告
        self.enabled_vision = False

    # ---- 可用性 ----
    def can_vision(self) -> bool:
        """能否做视觉任务：开关打开 + 配了服务 + provider 支持图片。

        ★ 闸门看**任一视觉环节**，不是只看 `policy_vision`。
          原先只认 `policy_vision`，于是"只开 UI 遍历、不开政策视觉"时
          `plan_ui_action` / `choose_action` 全部返回 None，而调用方把 None
          当"AI 决策失败"计数 → 三步之后打出「AI 遍历决策连续失败，停用 AI」
          并写进 `res.ai_errors`；日志却还写着"参与环节：指挥 UI 遍历"。
          界面显示与实际执行完全相反，而报告里看不出这一点。
        """
        if not (self.cfg.feature("policy_vision") or self.cfg.feature("ui_agent")):
            return False
        if (self.cfg.provider or "none") == "none":
            return False
        return bool(getattr(self.ai, "vision", False))

    def can_text(self) -> bool:
        """能否做纯文本任务（政策结构化等）。"""
        return (self.cfg.provider or "none") != "none"

    # 兼容旧名（自检脚本与早期调用点用过）
    _vision_ok = can_vision
    _text_ok = can_text

    def _note(self, msg: str) -> None:
        self.notes.append(msg)
        self.log("[AI] %s" % msg)

    @staticmethod
    def _prepare(png: bytes, cfg) -> Optional[vision.PreparedImage]:
        try:
            return vision.prepare(png, max_width=int(getattr(cfg, "vision_max_width", 720) or 720),
                                  quality=int(getattr(cfg, "vision_quality", 72) or 72))
        except Exception as e:
            return None

    # ============================================================ T1 政策入口
    def locate_policy_entry(self, png: bytes, candidates: Sequence[Any],
                            screen_texts: Sequence[str], package: str = "",
                            app_label: str = "") -> Optional[AIReturn]:
        """看首启弹窗截图，判断隐私政策入口在哪。

        candidates 是 (label, bounds) 或 uiwalk.UiNode 列表；会被画成编号框。
        返回的 data 里 entry_bounds 已是**原图像素**坐标，业务层直接用。
        """
        if not self._vision_ok():
            return None
        prepped = self._prepare(png, self.cfg)
        if prepped is None:
            self._note("截图预处理失败（缺少 Pillow？），本步回退到关键词策略")
            return None

        boxes = [_as_candidate(i + 1, c) for i, c in enumerate(candidates)]
        boxes = [b for b in boxes if b is not None]
        try:
            annotated, drawn = vision.annotate(png, boxes,
                                               max_width=prepped.sent_w,
                                               quality=int(getattr(self.cfg, "vision_quality", 72) or 72))
        except Exception as e:
            self._note("截图标注失败（%s），改用未标注原图提问" % e)
            annotated, drawn = prepped, []

        prompt = _entry_prompt(package, app_label, screen_texts,
                               [b.to_prompt_line() for b in drawn], bool(drawn))
        try:
            raw = self.ai.chat_vision(prompt, [annotated.jpeg], system=_COMMON_SYSTEM)
        except AIError as e:
            self._note("政策入口识别失败：%s" % e)
            return None

        parsed = vision.parse_json(raw)
        if not parsed:
            self._note("政策入口识别返回内容无法解析为 JSON，已忽略")
            return AIReturn(raw=raw, annotated=annotated.jpeg, error="JSON 解析失败")

        out: Dict[str, Any] = {
            "policy_present": vision.as_bool(parsed.get("policy_present")),
            "display_form": str(parsed.get("display_form") or "").strip().lower() or "none",
            "entry_text": str(parsed.get("entry_text") or "").strip(),
            "confidence": vision.as_float(parsed.get("confidence"), 0.0),
            "reason": str(parsed.get("reason") or "").strip()[:300],
            "annotated_size": (prepped.sent_w, prepped.sent_h),
        }
        idx = int(vision.as_float(parsed.get("entry_index"), 0))
        if 1 <= idx <= len(drawn):
            out["entry_index"] = idx
            out["entry_bounds"] = tuple(drawn[idx - 1].bounds)
            if not out["entry_text"]:
                out["entry_text"] = drawn[idx - 1].label
        bbox = parsed.get("entry_bbox")
        if isinstance(bbox, (list, tuple)) and len(bbox) >= 4:
            px = vision.norm_to_px(bbox, prepped.orig_w, prepped.orig_h)
            # 换算出的框必须过合理性闸门：过小（几个像素，多半是解析噪声）或过大
            # （几乎整屏）都不能照着点。宁可放弃、退回关键词策略。
            if px and vision.plausible_box(px, prepped.orig_w, prepped.orig_h, min_side=16):
                out["entry_bbox_px"] = px
                # 没有编号命中但有可靠坐标时，用坐标当入口
                if "entry_bounds" not in out:
                    out["entry_bounds"] = px
            elif px:
                out["bbox_rejected"] = px
                self._note("模型给出的入口坐标不合理，已忽略（%s），改用编号或回退" % (px,))
        hlt = int(vision.as_float(parsed.get("longest_text_holder"), 0))
        if 1 <= hlt <= len(drawn):
            out["longest_text_bounds"] = tuple(drawn[hlt - 1].bounds)

        self._note("政策入口识别：form=%s present=%s entry=%r conf=%.2f"
                   % (out["display_form"], out["policy_present"],
                      out["entry_text"][:30], out["confidence"]))
        return AIReturn(data=out, raw=raw, annotated=annotated.jpeg, ok=True)

    # ============================================================ T2 页面分类
    def classify_policy_page(self, png: bytes, candidates: Sequence[Any],
                             screen_texts: Sequence[str],
                             opened_from: str = "") -> Optional[AIReturn]:
        """判断政策页是正文、目录页、登录墙还是验证码；给出下钻目标。"""
        if not self._vision_ok():
            return None
        prepped = self._prepare(png, self.cfg)
        if prepped is None:
            return None
        boxes = [b for b in (_as_candidate(i + 1, c) for i, c in enumerate(candidates))
                 if b is not None]
        try:
            annotated, drawn = vision.annotate(png, boxes, max_width=prepped.sent_w,
                                               quality=int(getattr(self.cfg, "vision_quality", 72) or 72))
        except Exception:
            annotated, drawn = prepped, []

        prompt = _page_prompt(screen_texts, [b.to_prompt_line() for b in drawn],
                              bool(drawn), opened_from)
        try:
            raw = self.ai.chat_vision(prompt, [annotated.jpeg], system=_COMMON_SYSTEM)
        except AIError as e:
            self._note("政策页分类失败：%s" % e)
            return None
        parsed = vision.parse_json(raw)
        if not parsed:
            return AIReturn(raw=raw, annotated=annotated.jpeg, error="JSON 解析失败")

        out: Dict[str, Any] = {
            "page_kind": str(parsed.get("page_kind") or "").strip().lower() or "other",
            "is_policy_content": vision.as_bool(parsed.get("is_policy_content")),
            "confidence": vision.as_float(parsed.get("confidence"), 0.0),
            "reason": str(parsed.get("reason") or "").strip()[:300],
        }
        targets: List[Dict[str, Any]] = []
        for t in vision.as_list(parsed.get("next_targets")):
            if not isinstance(t, dict):
                continue
            i = int(vision.as_float(t.get("index"), 0))
            item: Dict[str, Any] = {"text": str(t.get("text") or "").strip(),
                                    "why": str(t.get("why") or "").strip()[:160]}
            if 1 <= i <= len(drawn):
                item["index"] = i
                item["bounds"] = tuple(drawn[i - 1].bounds)
                if not item["text"]:
                    item["text"] = drawn[i - 1].label
            if item.get("bounds") or item["text"]:
                targets.append(item)
        out["next_targets"] = targets

        links: List[Dict[str, Any]] = []
        for l in vision.as_list(parsed.get("links")):
            if not isinstance(l, dict):
                continue
            links.append({"text": str(l.get("text") or "").strip()[:120],
                          "url": str(l.get("url") or "").strip()[:500]})
        out["links"] = links

        self._note("政策页判定：%s（是否正文=%s，下钻目标 %d 个）"
                   % (out["page_kind"], out["is_policy_content"], len(targets)))
        return AIReturn(data=out, raw=raw, annotated=annotated.jpeg, ok=True)

    # ==================================================== T2b 权限弹窗背景说明
    def read_perm_banner(self, png: bytes, perm: str = "") -> Optional[AIReturn]:
        """看一张权限弹窗截图，抄出**弹窗之外**的说明文字（浮窗/横幅）。

        ★ 为什么这件事必须看图（免费手机投屏神器 2026-10-26 实测）：
          App 在权限弹窗出现的同时，在屏幕顶部弹了一条浮窗：
            「相关权限说明：获取位置信息权限 用于获取附近的免费WIFI列表
              若拒绝该功能将无法使用」
          这条浮窗属于 App 的窗口，被系统权限弹窗压在下面、颜色偏暗，
          `uiautomator dump` 只导最顶层窗口，**一个字都读不到**。
          于是 Q026 判成"未同步告知目的"，而截图里写得清清楚楚 ——
          判错的原因不是标准宽严，是证据没采到。
          文本层拿不到的东西，只能从像素里取。
        """
        if not self._vision_ok():
            return None
        prepped = self._prepare(png, self.cfg)
        if prepped is None:
            return None
        prompt = (
            "这是一张安卓手机截图，画面上有一个系统权限申请弹窗（里面有「拒绝」「允许」"
            "这类按钮）。请只做两件事：\n"
            "1) 把**权限弹窗以外**的界面文字逐字抄出来（通常在弹窗上方/背后/"
            "顶部浮窗/横幅里，颜色可能偏暗）。只抄看得清的，看不清就留空。\n"
            "2) 判断这些文字里有没有针对「%s」这个权限的**用途说明**"
            "（例如「用于…」「以便…」「为了…」「查看已连接的 WiFi」这类说明了为什么需要它）。"
            "有就抄出那句话原文，没有就留空。\n"
            "不要推断、不要补全、不要从弹窗里的文字里找（那是系统模板句）。\n"
            '只输出 JSON：{"text":"弹窗外的全部文字","purpose":"针对该权限的用途说明原句",'
            '"confidence":0.0}\n'
            "看不清或没有就返回 {\"text\":\"\",\"purpose\":\"\",\"confidence\":0}"
            % (perm or "该")
        )
        try:
            raw = self.ai.chat_vision(prompt, [prepped.jpeg], system=_COMMON_SYSTEM)
        except AIError as e:
            self._note("权限弹窗背景文字识别失败：%s" % e)
            return None
        parsed = vision.parse_json(raw)
        if not parsed:
            return AIReturn(raw=raw, annotated=prepped.jpeg, error="JSON 解析失败")
        out = {
            "text": str(parsed.get("text") or "").strip()[:400],
            "purpose": str(parsed.get("purpose") or "").strip()[:200],
            "confidence": vision.as_float(parsed.get("confidence"), 0.0),
        }
        if not out["text"] and not out["purpose"]:
            return AIReturn(data=out, raw=raw, annotated=prepped.jpeg,
                            error="图上未读到弹窗外的说明文字")
        self._note("权限弹窗背景文字：%s（用途说明：%s）"
                   % (out["text"][:40] or "—", out["purpose"][:40] or "无"))
        return AIReturn(data=out, raw=raw, annotated=prepped.jpeg, ok=True)

    # ============================================================ T3 政策结构化
    def analyze_policy(self, text: str, app_label: str = "",                       is_sub_document: bool = False) -> Optional[AIReturn]:
        """读透政策全文，抽取结构化信息（含第三方文档链接）。

        ★ 长文本必须分段 —— 本机 qwen3.8-fast（PARAMETER num_ctx 8192）实测：
          正文 16000 字 → prompt_eval_count 8092 完整；20000 字 → **被静默截尾**
          （计数掉到 4098，不报错、不提示）。三万字政策直接丢进去只读了前两成，
          报告却会写"已分析全文"。分段后每块都真被读过，代价只是多几次往返
          （本机 2~3 秒/次）。归并走**本地确定性并集**而不是再问一次模型：
          并集不会漏，而"让模型总结 26 段结果"既要再喂一次长输入，又可能丢条目。
        """
        if not self._text_ok() or not self.cfg.feature("policy_analyze"):
            return None
        text = (text or "").strip()
        if len(text) < 200:
            return None

        budget = self.ai.input_budget_chars()
        # 每段 3600 字：加 ~900 字抽取指令约 2400 token，留 1536 给输出，
        # 离 8192 还有一半余量 —— 但**不往上抬**。块越小，模型越不会在中段丢条目；
        # 决定耗时的是**段数**，而准确率优先于耗时（这条链路不吃上下文的红利）。
        plan = chunker.plan(text, chunk_chars=3600, max_chunks=26)

        if len(plan.chunks) <= 1 and len(text) <= budget:
            # 短文本：一次读完，走原来的完整提示词
            try:
                raw = self.ai.chat(_msgs(_ANALYZE_SYSTEM,
                                         _analyze_prompt(text, app_label,
                                                         is_sub_document,
                                                         limit=budget)))
            except AIError as e:
                self._note("政策结构化分析失败：%s" % e)
                return None
            parsed = vision.parse_json(raw)
            if not parsed:
                self._note("政策结构化返回内容无法解析")
                return AIReturn(raw=raw, error="JSON 解析失败")
            return AIReturn(data=self._normalize(parsed), raw=raw, ok=True)

        # ---- 长文本：逐段抽取（map）→ 本地并集（reduce）----
        total = len(plan.chunks)
        self._note("政策 %d 字超出单次上下文预算（约 %d 字），分 %d 段抽取%s"
                   % (len(text), budget, total,
                      "；%s" % plan.summary() if plan.skipped else ""))
        parts: List[Dict[str, Any]] = []
        failed = 0

        def _one(pair):
            i, ch = pair
            prompt = _chunk_prompt(ch.text, ch.heading, i, total, app_label)
            last_err = ""
            # 抽一段失败就整段丢掉，代价是这段里的证据全部消失。
            # 解析失败多半是输出被截断/带了多余前缀，重试一次比丢弃划算。
            for attempt in (1, 2):
                try:
                    raw = self.ai.chat(_msgs(_CHUNK_SYSTEM, prompt), temperature=0.1)
                except AIError as e:
                    last_err = "第 %d/%d 段抽取失败：%s" % (i, total, e)
                    continue
                parsed = vision.parse_json(raw)
                if isinstance(parsed, dict):
                    return i, parsed, ""
                last_err = ("第 %d/%d 段返回无法解析（%d 字，开头：%s）"
                            % (i, total, len(raw or ""), (raw or "")[:60].replace("\n", " ")))
            return i, None, last_err

        # 并发跑。分段的意义就是用"多次小请求"换"一次读全"，
        # 串行 26 段要 5 分半，4 路并发后约 1 分半（实测 ollama 侧约 2.3 倍吞吐）。
        workers = max(1, int(getattr(self.cfg, "chunk_workers", 4) or 1))
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for i, parsed, err in ex.map(_one, list(enumerate(plan.chunks, 1))):
                done += 1
                if parsed is None:
                    failed += 1
                    if err:
                        self._note(err)
                else:
                    parts.append(parsed)
                if done % 5 == 0 or done == total:
                    self._note("政策分段抽取进度 %d/%d" % (done, total))

        if not parts:
            self._note("政策分段抽取全部失败，本轮不做结构化解析")
            return None

        merged = self._merge_parts(parts)
        merged["_chunks_total"] = total
        merged["_chunks_failed"] = failed
        # 覆盖率按"有效文本"算：原文里混着网页抽取留下的 CSS 残片，
        # 拿原文总长当分母会让一句"覆盖 77%"看起来像漏读了四分之一。
        effective = sum(c.chars for c in plan.chunks) + sum(c.chars for c in plan.skipped)
        merged["_coverage"] = (sum(c.chars for c in plan.chunks) / effective) \
            if effective else 1.0
        self._note("政策结构化完成（分段）：声明信息类型 %d 项、第三方文档 %d 份、"
                   "注销路径 %d 条、失败 %d/%d 段"
                   % (len(merged["declared_types"]),
                      len(merged["third_party_docs"]),
                      len(merged["cancel_account"]), failed, total))
        return AIReturn(data=merged, raw="", ok=True)

    # ------------------------------------------------------------ 归并工具
    @staticmethod
    def _normalize(parsed: Dict[str, Any]) -> Dict[str, Any]:
        """把模型返回整理成固定结构（单段路径与分段路径共用）。"""
        docs = []
        for d in vision.as_list(parsed.get("third_party_docs")):
            if isinstance(d, dict):
                docs.append({"title": str(d.get("title") or "").strip()[:200],
                             "url": str(d.get("url") or "").strip()[:500],
                             "where": str(d.get("where") or "").strip()[:120],
                             "kind": str(d.get("kind") or "").strip()[:40]})
            elif isinstance(d, str) and d.strip():
                docs.append({"title": d.strip()[:200], "url": "", "where": "", "kind": ""})
        return {
            "third_party_docs": docs,
            "declared_types": [str(x).strip()[:80]
                               for x in vision.as_list(parsed.get("declared_types"))
                               if str(x).strip()],
            "purposes": [str(x).strip()[:120]
                         for x in vision.as_list(parsed.get("purposes"))
                         if str(x).strip()][:20],
            "retention": str(parsed.get("retention") or "").strip()[:400],
            "cross_border": str(parsed.get("cross_border") or "").strip()[:400],
            "cancel_account": [_pair(x) for x in vision.as_list(parsed.get("cancel_account"))],
            "correct_delete": [_pair(x) for x in vision.as_list(parsed.get("correct_delete"))],
            "complaint": [_pair(x) for x in vision.as_list(parsed.get("complaint"))],
            "minor_rules": str(parsed.get("minor_rules") or "").strip()[:600],
            "personalized_ads_off": str(parsed.get("personalized_ads_off") or "").strip()[:400],
            "contact": str(parsed.get("contact") or "").strip()[:400],
            "summary": str(parsed.get("summary") or "").strip()[:600],
        }

    @staticmethod
    def _merge_parts(parts: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        """把多段抽取结果并成一份。

        全是确定性并集：文本字段取"最长的那条"（信息量最多），
        列表按内容去重。不做任何取舍 —— 少一条就可能导致"
        "政策里明明写了"被误判成"没写"。
        """
        types: List[str] = []
        docs: List[Dict[str, str]] = []
        cancels: List[Dict[str, str]] = []
        corrects: List[Dict[str, str]] = []
        complaints: List[Dict[str, str]] = []
        third: List[Dict[str, str]] = []

        def _uniq(items: List[str], cap: int = 60) -> List[str]:
            seen, out = set(), []
            for x in items:
                k = x.strip()
                if k and k not in seen:
                    seen.add(k)
                    out.append(k)
                if len(out) >= cap:
                    break
            return out

        def _uniq_pairs(items: List[Dict[str, str]], cap: int = 20) -> List[Dict[str, str]]:
            seen, out = set(), []
            for d in items:
                key = (d.get("path") or d.get("channel") or "").strip()
                if key and key not in seen:
                    seen.add(key)
                    out.append(d)
                if len(out) >= cap:
                    break
            return out

        def _longest(field: str, cap: int) -> str:
            best = ""
            for p in parts:
                v = str(p.get(field) or "").strip()
                if len(v) > len(best):
                    best = v
            return best[:cap]

        for p in parts:
            types += [str(x).strip()[:80] for x in vision.as_list(p.get("declared_types"))
                      if str(x).strip()]
            for d in vision.as_list(p.get("docs")):
                if isinstance(d, dict) and str(d.get("title") or "").strip():
                    docs.append({"title": str(d["title"]).strip()[:200],
                                 "url": str(d.get("url") or "").strip()[:500],
                                 "where": "", "kind": ""})
                elif isinstance(d, str) and d.strip():
                    docs.append({"title": d.strip()[:200], "url": "",
                                 "where": "", "kind": ""})
            for k, bucket in (("cancel_account", cancels),
                              ("correct_delete", corrects),
                              ("complaint", complaints)):
                for x in vision.as_list(p.get(k)):
                    bucket.append(_pair(x))
            for x in vision.as_list(p.get("third_parties")):
                if isinstance(x, dict) and str(x.get("name") or "").strip():
                    third.append({"name": str(x["name"]).strip()[:120],
                                  "purpose": str(x.get("purpose") or "").strip()[:120],
                                  "info": str(x.get("info") or "").strip()[:160]})

        seen_docs, uniq_docs = set(), []
        for d in docs:
            k = d["title"]
            if k not in seen_docs:
                seen_docs.add(k)
                uniq_docs.append(d)

        return {
            "third_party_docs": uniq_docs[:40],
            "third_parties": third[:60],
            "declared_types": _uniq(types, 60),
            "purposes": [],
            "retention": _longest("retention", 400),
            "cross_border": _longest("cross_border", 400),
            "cancel_account": _uniq_pairs(cancels),
            "correct_delete": _uniq_pairs(corrects),
            "complaint": _uniq_pairs(complaints),
            "minor_rules": _longest("minor_rules", 600),
            "personalized_ads_off": _longest("personalized_ads_off", 400),
            "contact": _longest("contact", 400),
            "summary": "",
        }

    # ============================================================ T4 UI agent
    def plan_ui_action(self, png: bytes, candidates: Sequence[Any],
                       screen_texts: Sequence[str], goal: str, step: int,
                       history: Sequence[str], package: str = "",
                       app_label: str = "", back_unsafe: bool = False
                       ) -> Optional[AIReturn]:
        """看当前截图，决定下一步点什么 / 往哪滑。"""
        if not self._vision_ok() or not self.cfg.feature("ui_agent"):
            return None
        prepped = self._prepare(png, self.cfg)
        if prepped is None:
            return None
        boxes = [b for b in (_as_candidate(i + 1, c) for i, c in enumerate(candidates))
                 if b is not None]
        # 遍历时候选可能非常多，全画上去图会糊；只画前 24 个（按调用方给的优先级）
        boxes = boxes[:24]
        try:
            annotated, drawn = vision.annotate(png, boxes, max_width=prepped.sent_w,
                                               quality=int(getattr(self.cfg, "vision_quality", 72) or 72))
        except Exception:
            annotated, drawn = prepped, []

        # 图片占掉大半上下文，留给文字的大约只有预算的一半，但另有硬顶
        # （见 UI_TEXT_BUDGET_CAP 的说明：遍历链路不随上下文放大而变长）。
        try:
            text_budget = int(min(UI_TEXT_BUDGET_CAP,
                                  self.ai.input_budget_chars() * 0.5))
        except Exception:
            text_budget = 2400
        prompt = _agent_prompt(package, app_label, goal, step, history, screen_texts,
                               [b.to_prompt_line() for b in drawn], bool(drawn),
                               back_unsafe, text_budget=text_budget)
        try:
            # temperature=0：这一步决定"接下来点哪个入口"。同一屏、同一目标，
            # 换一次运行就该给同一个答案 —— 否则两轮的点击顺序不同、覆盖的
            # 界面不同，复现时"判据没出现"就分不清是问题消失了还是没走到。
            # 创意从这里拿不到好处，可复现性才是要的。
            raw = self.ai.chat_vision(prompt, [annotated.jpeg], system=_AGENT_SYSTEM,
                                      temperature=0.0)
        except AIError as e:
            self._note("UI 决策失败：%s" % e)
            return None
        parsed = vision.parse_json(raw)
        if not parsed:
            return AIReturn(raw=raw, annotated=annotated.jpeg, error="JSON 解析失败")

        action = str(parsed.get("action") or "").strip().lower()
        if action not in ("tap", "swipe", "back", "input", "wait", "done"):
            self._note("UI 决策返回了未知动作 %r，忽略本步" % action)
            return AIReturn(raw=raw, annotated=annotated.jpeg, error="动作非法")

        out: Dict[str, Any] = {
            "action": action,
            "direction": str(parsed.get("direction") or "").strip().lower(),
            "text": str(parsed.get("text") or "")[:200],
            "expect": str(parsed.get("expect") or "").strip()[:200],
            "goal_progress": str(parsed.get("goal_progress") or "").strip().lower(),
            "reason": str(parsed.get("reason") or "").strip()[:250],
        }
        idx = int(vision.as_float(parsed.get("index"), 0))
        if 1 <= idx <= len(drawn):
            out["index"] = idx
            out["target_text"] = drawn[idx - 1].label
            out["target_bounds"] = tuple(drawn[idx - 1].bounds)
        bbox = parsed.get("bbox")
        if isinstance(bbox, (list, tuple)) and len(bbox) >= 4:
            px = vision.norm_to_px(bbox, prepped.orig_w, prepped.orig_h)
            if px and vision.plausible_box(px, prepped.orig_w, prepped.orig_h, min_side=16):
                out["target_bbox_px"] = px
                out.setdefault("target_bounds", px)
            elif px:
                out["bbox_rejected"] = px
        return AIReturn(data=out, raw=raw, annotated=annotated.jpeg, ok=True)

    # ==================================================== T4b 图引导选择
    def choose_action(self, png: bytes, options: Sequence[Any], memory: str,
                      goal: str, screen_texts: Sequence[str] = (),
                      step: int = 0) -> Optional[AIReturn]:
        """从**本地已算好的有限动作集**里选一个（UI-KOBE 的 graph-guided 选择）。

        与 `plan_ui_action` 的分工（两者都在，不是替代关系）：

          · 本方法用于「结构树里有点得着的东西」—— 选项来自图与结构树，
            身份精确（uid），模型只做局部选择；
          · `plan_ui_action` 用于「结构树里一个可点节点都没有」的自绘界面 /
            WebView —— 那时没有选项可选，只能让模型看着截图给坐标。

        ★ 不画标注框，用原图：选项的身份是 uid，不依赖坐标对齐；而 annotate
          会跳过全屏容器后**重新编号**，历史上正是这一步让"提示词里的 2 号"
          与"本地列表第 2 个"错位，点在了空白处。选项本身带文字，模型按文字
          对号即可，不需要视觉编号。
        """
        if not self._vision_ok() or not self.cfg.feature("ui_agent"):
            return None
        if not options:
            return None
        prepped = self._prepare(png, self.cfg)
        if prepped is None:
            return None
        try:
            text_budget = max(600, int(min(CHOOSE_TEXT_BUDGET_CAP,
                                           self.ai.input_budget_chars() * 0.34)))
        except Exception:
            text_budget = 1400
        prompt = _choose_prompt(options, memory, goal, text_budget=text_budget,
                                screen_texts=screen_texts)
        try:
            raw = self.ai.chat_vision(prompt, [prepped.jpeg], system=_CHOOSE_SYSTEM,
                                      temperature=0.0)
        except AIError as e:
            self._note("图引导选择失败：%s" % e)
            return None
        parsed = vision.parse_json(raw)
        if not parsed:
            return AIReturn(raw=raw, annotated=prepped.jpeg, error="JSON 解析失败")
        choice = str(parsed.get("choice") or "").strip().upper()
        # 宽松解析：模型可能写 "A2（设置）" / "a2." / "选 A2"
        import re as _re
        m = _re.search(r"([ANSPB]\s*\d+)", choice)
        oid = m.group(1).replace(" ", "") if m else ""
        valid = {str(getattr(o, "oid", "")): o for o in options}
        if not oid or oid not in valid:
            return AIReturn(raw=raw, annotated=prepped.jpeg,
                            error="选择不在给定动作集内（%r）" % choice[:20])
        opt = valid[oid]
        out: Dict[str, Any] = {
            "choice": oid,
            "action": str(getattr(opt, "action", "") or ""),
            "label": str(getattr(opt, "label", "") or "")[:40],
            # page：让模型顺带命名当前界面（零额外调用），回写图后
            # 下一轮"我在哪"就不必重新推断。
            "page": str(parsed.get("page") or "").strip()[:40],
            "reason": str(parsed.get("reason") or "").strip()[:200],
            "options": len(list(options)),
        }
        return AIReturn(data=out, raw=raw, annotated=prepped.jpeg, ok=True)


# ---------------------------------------------------------------- 小工具

def _msgs(system: str, user: str) -> List[Dict[str, str]]:
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _as_candidate(index: int, c: Any) -> Optional[vision.CandidateBox]:
    """把调用方给的候选（(label,bounds) 元组 或 uiwalk.UiNode）统一成 CandidateBox。"""
    label = ""
    bounds = None
    tag = ""
    try:
        if isinstance(c, (tuple, list)) and len(c) >= 2:
            label, bounds = str(c[0]), tuple(c[1])
            if len(c) >= 3:
                tag = str(c[2] or "")
        else:
            label = str(getattr(c, "label", "") or "")
            bounds = getattr(c, "bounds", None)
            if getattr(c, "clickable", False):
                tag = "可点击"
        if not bounds or len(bounds) != 4:
            return None
        return vision.CandidateBox(index=index, label=label[:80],
                                   bounds=(int(bounds[0]), int(bounds[1]),
                                           int(bounds[2]), int(bounds[3])), tag=tag)
    except Exception:
        return None


def _pair(v: Any) -> Dict[str, str]:
    if isinstance(v, dict):
        return {"path": str(v.get("path") or v.get("channel") or "").strip()[:200],
                "detail": str(v.get("detail") or "").strip()[:300]}
    return {"path": str(v).strip()[:200], "detail": ""}
