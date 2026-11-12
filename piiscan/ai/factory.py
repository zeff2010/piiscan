"""按配置构造 provider。"""
from __future__ import annotations

from .base import AIError, AIProvider
from .providers import DeepSeekProvider, NullProvider, OllamaProvider, OpenAICompatProvider
from .relay import AgentRelayProvider

# provider 名称别名，方便不同环境直接写习惯的名字
_REGISTRY = {
    "none": NullProvider,
    "off": NullProvider,
    "disabled": NullProvider,
    "ollama": OllamaProvider,
    "openai": OpenAICompatProvider,
    "openai_compat": OpenAICompatProvider,
    "vllm": OpenAICompatProvider,
    "lmstudio": OpenAICompatProvider,
    # DeepSeek 云端 API。协议同 OpenAI 兼容，但单独一个类而不是别名：
    # 它的模型分成"能看图"（deepseek-flash）和"只能读文本"（deepseek-v4-pro）
    # 两档，得由 provider 自己按 `vision` 参数挑模型，不能照抄一个模型名了事。
    "deepseek": DeepSeekProvider,
    # 本机开发测试用：不连任何模型服务，把请求落盘交给对话里的 AI 回答
    "agent": AgentRelayProvider,
    "relay": AgentRelayProvider,
}


def build_ai(cfg) -> AIProvider:
    key = (cfg.provider or "none").strip().lower()
    cls = _REGISTRY.get(key)
    if cls is None:
        raise ValueError(
            "未知的 ai.provider：%r。可选值：%s" % (cfg.provider, ", ".join(sorted(_REGISTRY)))
        )
    return cls(cfg)


def build_ai_safe(cfg, log=print):
    """构造失败时降级为 NullProvider，保证主流程不中断。"""
    try:
        return build_ai(cfg)
    except Exception as e:
        log("[!] AI 初始化失败，降级为模板生成：%s" % e)
        return NullProvider(cfg)


def build_tasks_safe(ai_cfg, log=print):
    """按配置构造 AITasks（四个 AI 任务的统一门面）；不可用时返回 None。

    ★ 整条流水线（政策获取 → 深读 → 遍历 → 报告）共用同一个实例。
    这不是为了省内存，而是为了**调用留痕集中在一处** —— 报告要能回答
    「AI 在哪些环节参与了、每一步的依据是什么、有没有失败降级」，
    分散成多个实例就拼不出完整的证据链，人工复核时无从追溯。

    返回 None 的含义：AI 完全不可用（没配 / 配错 / 开关全关）。
    调用方一律走原有的确定性策略即可，不需要知道原因。
    """
    from .tasks import AITasks
    try:
        if (getattr(ai_cfg, "provider", "none") or "none") == "none":
            return None
        provider = build_ai_safe(ai_cfg, log)
        if getattr(provider, "name", "none") == "none":
            return None
        tasks = AITasks(provider, ai_cfg, log)

        parts = []
        if ai_cfg.feature("policy_vision"):
            if getattr(provider, "vision", False):
                parts.append("看截图定位政策入口/判断页面")
            else:
                parts.append("看截图定位政策入口（当前 provider 不支持图片，将回退）")
        if ai_cfg.feature("policy_analyze"):
            parts.append("政策全文深读与第三方清单追链")
        if ai_cfg.feature("ui_agent"):
            parts.append("指挥 UI 遍历")
        log("[*] AI 已启用：%s" % provider.describe())
        log("    参与环节：%s" % ("、".join(parts) if parts else "无（未开启任何 AI 环节开关）"))
        if not parts:
            log("    （提示：在 config.yaml 的 ai.features 里打开对应开关才会生效）")
        return tasks
    except Exception as e:
        log("[!] AI 初始化失败，全部 AI 环节回退到确定性策略：%s" % e)
        return None


__all__ = ["AIError", "AIProvider", "build_ai", "build_ai_safe", "build_tasks_safe",
           "NullProvider", "OllamaProvider", "OpenAICompatProvider",
           "DeepSeekProvider", "AgentRelayProvider"]
