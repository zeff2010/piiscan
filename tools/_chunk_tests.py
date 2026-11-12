"""分段 / 上下文预算的离线测试（不连模型、不读设备）。

为什么单独成文件：这一层的正确性直接决定"模型到底有没有读完政策"。
纯函数，容易测，也应该测死 —— 一旦切块出问题，最坏的结果不是报错，
而是**每一段都"成功"了、报告也写满了，但有一段正文从来没被送去模型**。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from piiscan.ai import chunker as C          # noqa: E402
from piiscan.ai.base import AIProvider       # noqa: E402
from piiscan.config import AIConfig          # noqa: E402


def _long_policy(repeat: int = 30) -> str:
    """造一份结构类似真实隐私政策的长文本。"""
    sec = []
    sec.append("第一章 我们如何收集您的个人信息")
    sec.append("一、我们会收集您的设备标识符（包括 IMEI、MAC 地址、Android ID）、"
               "位置信息、通讯录与通话记录，用于账号安全与风控。")
    sec.append("第二章 我们如何共享您的个人信息")
    sec.append("（1）第三方SDK：友盟统计会采集设备信息；极光推送会采集设备标识。"
               "接收方名称与联系方式见《第三方信息共享清单》。")
    sec.append("第三章 您如何管理自己的个人信息")
    sec.append("一、注销账号：您可在「我的-设置-注销账号」中提交申请，我们将在 15 个工作日内处理。")
    sec.append("二、更正与删除：您可通过客服邮箱 privacy@example.com 提出请求。")
    sec.append("第四章 未成年人保护")
    sec.append("我们不允许十四周岁以下儿童在无监护人同意的情况下注册使用本产品。")
    sec.append("第五章 本政策如何更新")
    sec.append("当本政策发生重大变更时，我们会通过弹窗方式通知您。")
    body = "\n".join(sec)
    return "\n".join([body] * max(1, repeat))


def run(check) -> None:
    # ------------------------------------------------------------ 切块
    text = _long_policy()
    check("合成政策足够长", len(text) > 8000, len(text))

    chunks = C.split_sections(text, max_chars=3000)
    check("切块数合理（不是碎片）", 2 <= len(chunks) <= 30, len(chunks))
    check("没有空块", all(c.chars > 0 for c in chunks))
    check("单块不超上限太多",
          all(c.chars <= 3000 * 1.2 for c in chunks),
          max(c.chars for c in chunks))
    # 每一块都必须以标点/换行收尾，不能把句子切一半
    tails = [c.text[-1] for c in chunks if not c.heading == c.text]
    check("块尾不在句子中间",
          all(t in "。！？；）】”\"' \n" or t.isdigit() for t in tails),
          "".join(sorted(set(tails)))[:20])
    check("切块覆盖了正文要素",
          any("注销" in c.text for c in chunks)
          and any("第三方SDK" in c.text for c in chunks),
          "")

    # ------------------------------------------------------------ 残片过滤
    dirty = "隐私政策正文。\n.title {\n  color: red;\n}\n" + ("正式条款内容。" * 200)
    ch2 = C.split_sections(dirty, max_chars=800)
    check("CSS 残片被清掉",
          all(".title {" not in c.text and c.text.strip() != "}" for c in ch2),
          [c.text[:12] for c in ch2])
    check("正文保留", any("正式条款" in c.text for c in ch2))

    # ------------------------------------------------------------ plan 全量
    plan = C.plan(text, chunk_chars=3000, max_chunks=40)
    check("段数在限内时全量覆盖", not plan.skipped, plan.summary())
    check("全量时覆盖率接近 100%", plan.coverage > 0.99, round(plan.coverage, 4))
    check("按原文顺序返回",
          [c.index for c in plan.chunks] == sorted(c.index for c in plan.chunks),
          [c.index for c in plan.chunks])

    # ------------------------------------------------------------ plan 降采样
    small = C.plan(text, chunk_chars=800, max_chunks=3)
    check("段数超限时降采样", len(small.chunks) <= 3, len(small.chunks))
    check("降采样记录被跳过的段", bool(small.skipped) and len(small.skipped) > 0,
          len(small.skipped))
    check("降采样后覆盖率 < 1", small.coverage < 1.0, round(small.coverage, 3))
    check("摘要如实说明跳过", "跳过" in small.summary(), small.summary())
    # 挑出来的应该比扔掉的更相关
    keep_score = sum(c.score for c in small.chunks) / max(1, len(small.chunks))
    drop_score = sum(c.score for c in small.skipped) / max(1, len(small.skipped))
    check("保留的段相关度不低于被丢弃的", keep_score >= drop_score,
          "keep=%.1f drop=%.1f" % (keep_score, drop_score))

    # ------------------------------------------------------------ 预算
    cfg = AIConfig(provider="ollama", context_tokens=4096, max_output_tokens=1536)
    p = AIProvider(cfg)
    budget = p.input_budget_chars()
    check("输入预算按上下文扣除输出额度",
          2000 < budget < 6000, budget)
    long_text = "字" * (budget + 500)
    cut = p.fit(long_text)
    check("fit 把超长正文裁到预算内", len(cut) <= budget, len(cut))
    short = "短文" * 10
    check("fit 不裁剪短正文", p.fit(short) == short)

    # 上下文配大时预算同步变大 —— 换模型不用改代码
    big = AIProvider(AIConfig(provider="ollama", context_tokens=32768,
                              max_output_tokens=2048))
    check("大上下文模型的预算更大", big.input_budget_chars() > budget * 4,
          big.input_budget_chars())

    # ------------------------------------------------------------ 空输入
    check("空文本不炸", C.split_sections("") == [])
    check("空文本 plan 安全", C.plan("", 1000).chunks == [])
