"""AI provider 抽象层。

任何需要调用大模型的地方，都通过这里的 AIProvider 接口调用，
具体走哪个后端（none / ollama / openai 兼容）由 config.yaml 决定。

两类接口：
  chat(...)        —— 纯文本
  chat_vision(...) —— 文本 + 一张或多张图片（多模态）

★ 调用留痕：每次调用都会往 self.calls 里追加一条记录（含提示词摘要、原始返回、
耗时、是否成功）。这是刻意设计的，不是为了调试方便 —— 合规检测报告要能回答
「这个结论是怎么来的」。人工复核时必须能看到模型当时收到的输入和给出的理由，
否则 AI 的参与过程就成了黑盒，报告也就失去了作为工作底稿的价值。
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Sequence

Message = Dict[str, str]


class AIError(RuntimeError):
    """AI 调用失败。调用方应捕获并降级到模板生成，而不是让整个流程挂掉。"""


class AIProvider:
    """大模型调用统一接口。"""

    name = "base"
    label = "基础"
    vision = False          # 是否支持图片输入
    calls: List[Dict] = []  # 调用留痕（实例级；由 __init__ 重置）

    MAX_CALLS_KEPT = 300

    def __init__(self, cfg):
        self.cfg = cfg
        self.calls = []

    # ---- 上下文预算 ----
    # 中文在 qwen 系词表里约 1 字 ≈ 0.51 token（2026-10-25 复测：
    # 16000 字 → prompt_eval_count 8092）。反过来 1 token ≈ 1.96 字。
    # 这里用 1.75 保守折算，宁可多切一段也不要被截尾 ——
    # Ollama 超限是**静默截尾**，模型不会告诉你它没看完，多切一段只是多一次调用，
    # 少切一段就是实打实的漏检。
    CHARS_PER_TOKEN = 1.75

    # 模板 / system 提示本身也要占位（实测 400~700 token）。
    # 不扣这一块，正文按满额送进去，输出那 1536 就把总长顶过 num_ctx，
    # 表现为"prompt 完整、回答却是空的"——比直接截尾更难排查。
    SYSTEM_RESERVE_TOKENS = 256

    def input_budget_chars(self) -> int:
        """一次请求里可以安全放入的正文长度（字符）。"""
        ctx = int(getattr(self.cfg, "context_tokens", 8192) or 8192)
        out = int(getattr(self.cfg, "max_output_tokens", 1024) or 0)
        usable = max(512, ctx - max(0, out) - self.SYSTEM_RESERVE_TOKENS)
        return int(usable * self.CHARS_PER_TOKEN)

    def fit(self, text: str, overhead: int = 0) -> str:
        """把正文裁到本模型的预算内。调用方应优先分段，这里只是兜底。"""
        room = max(200, self.input_budget_chars() - max(0, overhead))
        s = text or ""
        return s if len(s) <= room else s[:room]

    # ---- 子类需要实现 ----
    def _chat(self, messages: List[Message], temperature: float, timeout: int) -> str:
        raise NotImplementedError

    def _chat_vision(self, prompt: str, images: Sequence[bytes], system: str,
                     temperature: float, timeout: int) -> str:
        raise AIError("%s 不支持图片输入" % self.label)

    # ---- 超时：视觉请求更重，给更长的默认值 ----
    def _vision_timeout(self, timeout: Optional[int]) -> int:
        if timeout is not None:
            return timeout
        # 视觉推理明显比纯文本慢（要过视觉编码器），沿用文本超时会导致大批超时失败。
        return max(int(self.cfg.timeout or 90), 180)

    # ---- 对外统一入口 ----
    def chat(self, messages: List[Message], system: str = "",
             temperature: float | None = None,
             timeout: int | None = None) -> str:
        """纯文本提问。

        `system` 与 `chat_vision` 保持一致 —— 早先这里没有这个参数，而
        `flow/compare.py` 的政策差集复核是按 `chat(..., system=...)` 调的，
        真机实测直接抛 `got an unexpected keyword argument 'system'`，
        复核静默降级成"保留原始差集"：报告上看不出任何异常，
        但这一步其实从来没真正跑过。
        """
        temp = self.cfg.temperature if temperature is None else temperature
        to = self.cfg.timeout if timeout is None else timeout
        return self._call("chat", messages, None, temp, to, system=system)

    def chat_vision(self, prompt: str, images: Sequence[bytes],
                    system: str = "", temperature: float | None = None,
                    timeout: int | None = None) -> str:
        """带图提问。images 为图片字节（JPEG/PNG 均可，建议先用 vision.prepare 压缩）。"""
        if not images:
            raise AIError("chat_vision 至少需要一张图片")
        temp = self.cfg.temperature if temperature is None else temperature
        to = self._vision_timeout(timeout)
        msgs = [{"role": "user", "content": prompt}]
        return self._call("vision", msgs, list(images), temp, to, system=system)

    # ---- 内部：统一执行 + 留痕 ----
    def _call(self, kind: str, messages: List[Message], images: Optional[List[bytes]],
              temperature: float, timeout: int, system: str = "") -> str:
        # 已请求停止时连请求都不要发出去：这一轮结果没有意义，
        # 白发一次还可能把「停止」拖到下一个超时点（2026-11-12）。
        # 延迟导入避免 cancel ↔ base 的循环依赖（cancel 需要 AIError）。
        from . import cancel as _cancel
        _cancel.check("AI 调用")
        started = time.time()
        rec: Dict = {"kind": kind, "ts": started, "images": len(images or []),
                     "prompt_chars": sum(len(m.get("content") or "") for m in messages),
                     "ok": False, "error": "", "raw": "", "duration_ms": 0}
        if images:
            rec["image_kb"] = round(sum(len(b) for b in images) / 1024.0, 1)
        try:
            if kind == "vision":
                raw = self._chat_vision(
                    messages[0].get("content") or "", images or [], system,
                    temperature, timeout)
            else:
                raw = self._chat(messages, temperature, timeout)
            rec["ok"] = True
            rec["raw"] = (raw or "")[:4000]
            return raw
        except Exception as e:
            rec["error"] = "%s: %s" % (type(e).__name__, e)
            raise
        finally:
            rec["duration_ms"] = int((time.time() - started) * 1000)
            if messages:
                rec["prompt_head"] = (messages[0].get("content") or "")[:600]
            self.calls.append(rec)
            if len(self.calls) > self.MAX_CALLS_KEPT:
                del self.calls[:len(self.calls) - self.MAX_CALLS_KEPT]

    def available(self) -> bool:
        """服务是否可达。用于报告里标注 AI 的真实状态。"""
        return False

    def supports_vision(self) -> bool:
        """本 provider 在**当前配置下**能否处理图片。"""
        return bool(self.vision) and self.available()

    def describe(self) -> str:
        if self.name == "none":
            return "未启用（报告由内置模板生成）"
        return "%s · %s @ %s" % (self.label, self.cfg.model, self.cfg.base_url)

    def call_stats(self) -> Dict[str, int]:
        """调用统计，写进报告供人工核对 AI 的实际参与程度。"""
        return {
            "total": len(self.calls),
            "ok": sum(1 for c in self.calls if c.get("ok")),
            "failed": sum(1 for c in self.calls if not c.get("ok")),
            "vision": sum(1 for c in self.calls if c.get("kind") == "vision"),
        }
