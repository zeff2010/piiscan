"""把长文本切成模型一次读得完的块，并挑出与检测最相关的块。

★ 为什么必须要有这一层（本机实测 qwen3.8-fast, Modelfile 里 PARAMETER num_ctx 8192；
  2026-10-25 用 /api/show 核对 + 三档长文本复测）：

    输入 4000 字  → prompt_eval_count 2037，完整处理
    输入 12000 字 → prompt_eval_count 6073，完整处理
    输入 16000 字 → prompt_eval_count 8092，完整处理（已贴近 8192 顶）
    输入 20000 字 → prompt_eval_count 4098，**被截尾**
    输入 30000 字 → prompt_eval_count 4098，同样被截尾

★ 截尾后的计数会**掉到 4098 附近**，而不是停在 8192。早先把 4098 当成了
"可用上限只有 4096"，白砍掉一半预算 —— 判据要看"计数是否随字数线性增长"，
卡住不动才是被截。

Ollama 超限不报错、不提示，只是把尾部扔掉。一份 31061 字的隐私政策直接丢进去，
模型实际只读了前 26%，而报告里会写着"已分析隐私政策全文"——这是最危险的一类
假阴性：结论看起来有据，其实依据根本没被读过。

分段的代价是多几次调用（本机一次 1~3 秒），收益是"每一个字都真的被模型看过"。
再叠一层本地检索（关键词打分）把「定义」「适用法律」「历史版本」这类与检测
无关的章节排到后面，能在不牺牲召回的前提下把调用次数压下来。

注意：本模块只做切分与挑选，不做任何语义判断——语义交给模型。
挑选是**保守**的：只要预算装得下就全取，只有当块数真的超过预算才做取舍，
并且会把「跳过了哪些」如实返回给上层写进报告。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Sequence, Tuple

# 与 25 个测评项的证据需求一一对应。命中越多的块越可能含有判定依据。
_TOPIC_WORDS: Tuple[Tuple[str, int], ...] = (
    # 收集范围（Q010/Q012 超范围、Q002 同意前收集的对照面）
    ("收集", 2), ("采集", 2), ("获取", 1), ("读取", 1),
    ("设备标识", 3), ("IMEI", 3), ("MAC", 2), ("OAID", 3), ("Android ID", 3),
    ("位置", 2), ("通讯录", 3), ("通话记录", 3), ("短信", 2), ("相册", 2),
    ("摄像头", 2), ("麦克风", 3), ("录音", 2), ("剪贴板", 3), ("应用列表", 3),
    ("传感器", 2), ("身份证", 2), ("人脸", 3), ("指纹", 2), ("银行卡", 2),
    # 第三方与共享（Q005/Q006 未列明接收方、SDK 清单）
    ("第三方", 3), ("共享", 3), ("对外提供", 3), ("委托处理", 3), ("SDK", 3),
    ("接收方", 3), ("合作方", 2), ("供应商", 1),
    # 用户权利（Q018 注销、Q019 更正删除、Q020 投诉举报）
    ("注销", 4), ("删除", 2), ("更正", 3), ("撤回", 2), ("撤回同意", 3),
    ("投诉", 3), ("举报", 3), ("意见反馈", 3), ("客服", 1),
    # 未成年人（Q009）
    ("未成年", 4), ("儿童", 3), ("十四周岁", 4), ("监护人", 3), ("青少年", 2),
    # 个性化推荐与广告（Q024/Q025）
    ("个性化", 3), ("推荐", 2), ("广告", 2), ("画像", 3), ("标签", 1),
    # 数据出境与留存（Q013/Q023）
    ("出境", 3), ("境外", 2), ("跨境", 3), ("保存期限", 3), ("存储期限", 3),
    ("留存", 2), ("安全措施", 2), ("加密", 2), ("去标识化", 3),
    # 联系方式（Q020 渠道证据）
    ("联系方式", 2), ("个人信息保护负责人", 3), ("邮箱", 1), ("电话", 1),
)

# 一眼就知道与检测无关的章节标题——不是删除，只是排到最后
_LOW_VALUE_HEADS = ("定义", "术语", "版本历史", "更新记录", "历史版本", "法律适用",
                    "争议解决", "管辖", "特别声明", "附则", "目录")

_HEAD_RE = re.compile(
    r"^\s*(?:第[一二三四五六七八九十百]+[条章节部分]"
    r"|[一二三四五六七八九十]+[、.．]"
    r"|[（(][一二三四五六七八九十]+[)）]"
    r"|\d+[、.．]\s|\d+(?:\.\d+)+)"
)
_SENT_SPLIT = re.compile(r"(?<=[。！？；\n])")


@dataclass
class Chunk:
    index: int
    text: str
    heading: str = ""
    score: int = 0
    kept: bool = True

    @property
    def chars(self) -> int:
        return len(self.text)


@dataclass
class Plan:
    """一次分段计划：要送去模型的块 + 被跳过的块（含理由）。"""
    chunks: List[Chunk] = field(default_factory=list)
    total_chars: int = 0
    covered_chars: int = 0
    skipped: List[Chunk] = field(default_factory=list)
    split_ok: bool = True

    @property
    def coverage(self) -> float:
        return (self.covered_chars / self.total_chars) if self.total_chars else 1.0

    def summary(self) -> str:
        if not self.skipped:
            return "全文 %d 字，分 %d 段处理完毕" % (self.total_chars, len(self.chunks))
        return ("全文 %d 字，分 %d 段处理；因单次上下文预算限制，跳过 %d 段低相关章节"
                "（%d 字，覆盖率 %.0f%%）"
                % (self.total_chars, len(self.chunks), len(self.skipped),
                   self.total_chars - self.covered_chars, self.coverage * 100))


def _is_heading(line: str) -> bool:
    """只认**强标题**：编号式（第X章/一、/1.）或很短且不像正文的独立行。

    早先这里把"长度 ≤ 24 且无句号"的短行一律当标题，结果网页抽取出来的政策
    每一行都很短，切出 129 个碎片块（大量只有 1~20 字），预算全被碎片吃掉。
    """
    s = line.strip()
    if not s:
        return False
    if len(s) <= 40 and _HEAD_RE.match(s):
        return True
    # 极短且不像句子：多半是「引言」「目录」这类小标题
    return len(s) <= 12 and s.count("。") == 0 and s.count("，") == 0


def _sentences(par: str) -> List[str]:
    return [x for x in _SENT_SPLIT.split(par) if x]


def _pack_paragraphs(paras: List[str], max_chars: int, head: str,
                     start: int) -> List[Chunk]:
    """把若干段落合并成不超过 max_chars 的块；超长段落按句子切。"""
    out: List[Chunk] = []
    buf: List[str] = []

    def flush():
        nonlocal buf
        if buf:
            out.append(Chunk(index=start + len(out), text="\n".join(buf).strip(),
                             heading=head))
            buf = []

    for par in paras:
        if not par:
            continue
        if len(par) > max_chars:
            flush()
            cur = ""
            for s in _sentences(par):
                if len(cur) + len(s) > max_chars and cur:
                    out.append(Chunk(index=start + len(out), text=cur.strip(),
                                     heading=head))
                    cur = s
                else:
                    cur += s
            if cur.strip():
                buf.append(cur.strip())
            continue
        if sum(len(x) + 1 for x in buf) + len(par) > max_chars:
            flush()
        buf.append(par)
    flush()
    return out


def _is_junk(text: str) -> bool:
    """网页抽正文时常会带出 CSS/JS 残片（`.title {`、`}`）。它们不是政策文字，
    留在块里只会白占宝贵的上下文。"""
    s = (text or "").strip()
    if not s:
        return True
    if len(s) > 40:
        return False
    return bool(re.match(r"^[\s\w\{\}\.\#\"':;,\-—()（）]*$", s)) and not re.search(
        r"[\u4e00-\u9fff]", s)


def _merge_small(chunks: List[Chunk], max_chars: int, min_chars: int = 220) -> List[Chunk]:
    """把过短的块并到相邻块。

    真实政策里「一、」「（1）」这类编号行会单独成节，切完得到几十个 1~20 字的
    碎片。分块数量是有预算的（max_chunks），碎片刻度会把预算吃光，
    真正有内容的章节反而被挤掉。
    """
    out: List[Chunk] = []
    for c in chunks:
        if _is_junk(c.text):
            continue
        if out and c.chars < min_chars and out[-1].chars + c.chars + 1 <= max_chars:
            out[-1].text = out[-1].text + "\n" + c.text
            continue
        out.append(c)
    # 第一块如果是碎片、后面还有内容，往前并
    if len(out) > 1 and out[0].chars < min_chars:
        out[1].text = out[0].text + "\n" + out[1].text
        if out[0].heading:
            out[1].heading = out[0].heading
        out.pop(0)
    for i, c in enumerate(out):
        c.index = i
    return out


def split_sections(text: str, max_chars: int = 2200) -> List[Chunk]:
    """先按强标题切「节」，节内再按 max_chars 切「块」。

    切块优先级：节边界 > 段落边界 > 句子边界。**绝不从句子中间切断**——
    半句话喂给模型，比整段不给更容易引出错误的原文引用。
    """
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return []
    max_chars = max(400, int(max_chars))

    # ---- ① 切节 ----
    sections: List[Tuple[str, List[str]]] = []
    head = ""
    cur: List[str] = []
    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            continue
        if _is_heading(line):
            if cur:
                sections.append((head, cur))
                cur = []
            head = line[:40]
            cur = [line]
        else:
            cur.append(line)
    if cur:
        sections.append((head, cur))
    if not sections:
        sections = [("", [text])]

    # ---- ② 节内切块 ----
    chunks: List[Chunk] = []
    for h, paras in sections:
        chunks.extend(_pack_paragraphs(paras, max_chars, h, len(chunks)))
    return _merge_small(chunks, max_chars)


def score_chunk(chunk: Chunk) -> int:
    """关键词打分。只用来排序，不参与任何结论。"""
    body = chunk.text
    low = body.lower()
    total = 0
    for word, weight in _TOPIC_WORDS:
        if word.isascii():
            n = low.count(word.lower())
        else:
            n = body.count(word)
        if n:
            # 同一个词出现很多次只略加分，避免"第三方"堆砌的段落霸榜
            total += weight * (1 + min(n - 1, 3) * 0.3)
    return int(total)


def plan(text: str, chunk_chars: int = 2500, max_chunks: int = 24,
         budget_chars: int = 0, min_keep: int = 1) -> Plan:
    """切块 + 挑选，返回实际要处理的块。

    ★ 默认策略是**全量覆盖**：块数在 max_chunks 以内就一块不落。
      早先按"总字数预算"挑，31061 字的政策在 5300 字预算下只覆盖 17% ——
      等于把"看完全文"悄悄退化成"看了六分之一"，比多调几次模型糟糕得多。
      只有块数真的超过 max_chunks（文本极端长）时才降采样，并把跳过的段与
      覆盖率如实返回，让报告能写清楚"哪些章节没读"。
    """
    chunks = split_sections(text, max_chars=chunk_chars)
    p = Plan(chunks=chunks, total_chars=len(text or ""))
    if not chunks:
        p.covered_chars = 0
        return p

    for c in chunks:
        c.score = score_chunk(c)
        if any(w in (c.heading or "") for w in _LOW_VALUE_HEADS):
            c.score -= 8

    total = sum(c.chars for c in chunks)
    over_budget = budget_chars > 0 and total > budget_chars
    over_count = len(chunks) > max(1, int(max_chunks))
    if not over_budget and not over_count:
        for c in chunks:
            c.kept = True
        p.covered_chars = total
        return p

    limit = max(1, int(max_chunks))
    picked: List[int] = []
    used = 0
    for i in sorted(range(len(chunks)), key=lambda k: (-chunks[k].score, k)):
        if len(picked) >= limit:
            break
        c = chunks[i]
        if budget_chars > 0 and used + c.chars > budget_chars:
            continue
        picked.append(i)
        used += c.chars
    for i, c in enumerate(chunks):
        c.kept = i in picked

    if len(picked) < min_keep:
        i = min(range(len(chunks)), key=lambda k: chunks[k].chars)
        if i not in picked:
            picked.append(i)
            used += chunks[i].chars
            chunks[i].kept = True

    # 按原文顺序放回——保持上下文连贯，模型更容易理解指代
    p.chunks = [chunks[i] for i in sorted(picked)]
    p.skipped = [c for c in chunks if not c.kept]
    p.covered_chars = used
    return p


def pack(results: Sequence[str], budget_chars: int) -> List[List[str]]:
    """把多段结果按预算分组，用于 reduce 阶段（结果本身也可能超预算）。"""
    groups: List[List[str]] = []
    cur: List[str] = []
    used = 0
    for r in results:
        n = len(r) + 1
        if cur and used + n > budget_chars:
            groups.append(cur)
            cur, used = [], 0
        cur.append(r)
        used += n
    if cur:
        groups.append(cur)
    return groups
