"""具体 provider 实现：none / ollama / openai 兼容。

只用标准库 urllib，不引入额外依赖，方便搬到内网或离线环境。

视觉请求的两种报文格式差别较大，这里分别适配：
  · Ollama 原生：把 base64 塞进 message 的 `images` 数组（纯 base64，不带前缀）
  · OpenAI 兼容：content 变成数组，图片走 `image_url` + data URI
两者都支持「一次多张图」，但本项目的用法基本是「一张截图配一段提示词」。
"""
from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence

from . import cancel
from .base import AIError, AIProvider, Message


def _post_json_blocking(url: str, payload: dict, headers: dict | None,
                        timeout: int) -> dict:
    """真正的 HTTP 调用（阻塞）。只由 `_post_json` 在后台线程里调用。"""
    body = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        raise AIError("HTTP %s %s%s" % (e.code, e.reason, (" — " + detail) if detail else ""))
    except Exception as e:  # 连接失败 / 超时
        raise AIError("%s: %s" % (type(e).__name__, e))
    try:
        return json.loads(raw)
    except Exception:
        raise AIError("返回内容不是合法 JSON：%s" % raw[:200])


def _post_json(url: str, payload: dict, headers: dict | None = None, timeout: int = 90) -> dict:
    """可被「停止」立刻打断的 POST（2026-11-12）。

    ★ 为什么套一层线程
      用户点停止时，采集线程可能正阻塞在 `urlopen` 里（模型服务断了、
      请求挂住）。urllib 没有取消接口，同步等待就只能等满 timeout ——
      实测一次文本调用 90 秒、视觉 180 秒，分段抽取还会并发 4 路，
      于是"停止"要等好几分钟才生效，看起来就是按钮没反应。

      现在把阻塞调用放到后台线程，这里按 0.25 秒轮询取消令牌：
      一旦置位立即抛 AIError，采集线程马上回到 `should_stop()`。
      被放弃的那个线程会在自己的 socket 超时后自然结束（daemon，
      不阻止进程退出），不需要也无法强杀 —— 这点写在日志里，
      免得下次看到"还有 AI 线程在跑"以为是泄漏。
    """
    cancel.check("AI 请求")
    started = time.time()
    box: Dict[str, Any] = {}
    done = threading.Event()

    def _run() -> None:
        try:
            box["data"] = _post_json_blocking(url, payload, headers, timeout)
        except BaseException as e:      # noqa: BLE001  原样转交给调用线程
            box["err"] = e
        finally:
            done.set()

    threading.Thread(target=_run, daemon=True,
                     name="piiscan-ai-http").start()
    # 自身也守一个上限：万一底层线程因 DNS/连接卡住不返回，不能让这里无限等。
    deadline = started + max(1, int(timeout)) + 5
    while not done.wait(0.25):
        if cancel.is_set():
            raise AIError(
                "AI 请求已中断（%s）：不再等待服务端返回；原请求最多还会占用 "
                "%.0f 秒后自行超时" % (cancel.ACTIVE.reason(), timeout))
        if time.time() > deadline:
            raise AIError("AI 请求超时（%.0f 秒未返回）" % (time.time() - started))
    if "err" in box:
        raise box["err"]
    # 拿到响应后才置位的取消同样要认：这一轮结果已无意义，
    # 继续往下跑只会让"停止"多花几十秒。
    cancel.check("AI 调用（返回后）")
    return box.get("data") or {}


def _b64(blob: bytes) -> str:
    return base64.b64encode(blob).decode("ascii")


def _parse_num_ctx(params: Any) -> int:
    """从 `/api/show` 的 `parameters` 里取 `num_ctx`，取不到返回 0。

    这个字段的形态随 Ollama 版本变过：老版本是**一段文本**（"num_ctx    8192\\n…"），
    新版本可能给 dict。两种都认，认不出来就返回 0（调用方按"未知"处理，
    不能默认成配置里的值 —— 那等于把"没核实"伪装成"核实过"）。
    """
    if isinstance(params, dict):
        for k, v in params.items():
            if str(k).strip().lower() == "num_ctx":
                try:
                    return int(float(v))
                except Exception:
                    return 0
        return 0
    for line in str(params or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == "num_ctx":
            try:
                return int(float(parts[-1]))
            except Exception:
                return 0
    return 0


class NullProvider(AIProvider):
    """不调用任何模型。报告用内置模板生成，保证零依赖可跑通。"""

    name = "none"
    label = "未启用"
    vision = False

    def _chat(self, messages: List[Message], temperature: float, timeout: int) -> str:
        raise AIError("AI 未启用（config: ai.provider = none）")

    def available(self) -> bool:
        return False


class OllamaProvider(AIProvider):
    """Ollama 原生接口：POST {base_url}/api/chat"""

    name = "ollama"
    label = "Ollama 原生接口"
    vision = True

    def _model(self, vision: bool = False) -> str:
        if vision:
            return (getattr(self.cfg, "vision_model", "") or self.cfg.model)
        return self.cfg.model

    def _options(self, temperature: float) -> dict:
        opts = {"temperature": temperature}
        # 输出上限。不设的话 ollama 会给一个很宽的默认值，而模型一旦"刹不住"
        # 就会把 JSON 写到一半被截断 —— 表现为"返回无法解析"。
        cap = int(getattr(self.cfg, "max_output_tokens", 0) or 0)
        if cap > 0:
            opts["num_predict"] = max(256, cap)
        return opts

    def _no_think(self) -> bool:
        """是否要求模型跳过思考链。

        ★ `think` 是 ollama 请求的**顶层字段**，放进 options 里会被静默忽略。
          我第一版就放错了地方，结果同一轮里既看到"思考链 1916 字"，
          又是 4 次"返回无法解析"——因为 1024 的 num_predict 全被思考吃掉了。
        带思考链的模型（qwen3.8 / QwQ / R1）默认会先写一大段推理，
        而我们这些任务是"照骨架抽取"，不需要长链推理：
        实测开思考 2.0s/次、关思考 0.5s/次。
        """
        return not bool(getattr(self.cfg, "think", False))

    def _chat(self, messages: List[Message], temperature: float, timeout: int) -> str:
        url = self.cfg.base_url.rstrip("/") + "/api/chat"
        payload = {
            "model": self._model(),
            "messages": messages,
            "stream": False,
            "options": self._options(temperature),
        }
        if self._no_think():
            payload["think"] = False
        try:
            data = _post_json(url, payload, timeout=timeout)
        except AIError as e:
            # 老版本 ollama / 不支持 thinking 的模型会直接拒绝这个字段，
            # 去掉再试一次，别让一个可选优化把整条链带死
            if "think" in str(e).lower() and "think" in payload:
                payload.pop("think", None)
                data = _post_json(url, payload, timeout=timeout)
            else:
                raise
        msg = data.get("message") or {}
        content = msg.get("content")
        if not content:
            think = msg.get("thinking") or ""
            raise AIError("Ollama 返回缺少 message.content（思考链 %d 字，"
                          "可能被 num_predict 吃光）：%s"
                          % (len(think), str(data)[:200]))
        return str(content).strip()

    def _chat_vision(self, prompt: str, images: Sequence[bytes], system: str,
                     temperature: float, timeout: int) -> str:
        url = self.cfg.base_url.rstrip("/") + "/api/chat"
        msgs: List[dict] = []
        if system:
            msgs.append({"role": "system", "content": system})
        # Ollama 的 images 是**纯 base64 字符串**数组，不要带 data: 前缀，
        # 带了会被当成非法图片直接报错。
        msgs.append({"role": "user", "content": prompt,
                     "images": [_b64(b) for b in images]})
        payload = {
            "model": self._model(vision=True),
            "messages": msgs,
            "stream": False,
            "options": self._options(temperature),
        }
        if self._no_think():
            payload["think"] = False
        try:
            data = _post_json(url, payload, timeout=timeout)
        except AIError as e:
            if "think" in str(e).lower() and "think" in payload:
                payload.pop("think", None)
                data = _post_json(url, payload, timeout=timeout)
            else:
                raise
        content = (data.get("message") or {}).get("content")
        if not content:
            msg = data.get("message") or {}
            think = msg.get("thinking") or ""
            raise AIError("Ollama 视觉返回缺少 message.content（思考链 %d 字）：%s"
                          % (len(think), str(data)[:300]))
        return str(content).strip()

    def available(self) -> bool:
        try:
            url = self.cfg.base_url.rstrip("/") + "/api/tags"
            with urllib.request.urlopen(url, timeout=3) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def show(self, model: str = "", timeout: float = 6.0) -> Dict[str, Any]:
        """`/api/show`：这个模型到底部署了没有，以及它真实的 num_ctx / capabilities。

        为什么值得单独做一层（`available()` 只证明"有服务在听"）：
          · 端口通、模型名写错时，`available()` 照样是 True —— 要等到真正调用才 404；
          · `num_ctx` 只能从 Modelfile 元数据读到，而它决定"正文送多少字不会被静默截尾"。
            配置里写错（2026-10 就把 8192 误记成 4096）会让整条判定链按错的预算喂正文：
            写大了模型没看完却报告"已分析全文"，是假阴性；写小了只是白砍预算。

        只读元数据、**不加载权重**（本机实测 0.07s），所以可以放在"测试连接"里。

        返回 {"ok","exists","num_ctx","capabilities","error"}，恒返回 dict 不抛异常。
        """
        name = (model or self.cfg.model or "").strip()
        out: Dict[str, Any] = {"ok": True, "exists": False, "num_ctx": 0,
                               "capabilities": [], "error": ""}
        if not name:
            out.update(ok=False, error="未填写模型名")
            return out
        url = self.cfg.base_url.rstrip("/") + "/api/show"
        try:
            data = _post_json(url, {"model": name}, timeout=timeout)
        except AIError as e:
            msg = str(e)
            # 404 才是"查无此模型"；其它错误（超时/5xx）不能一口咬定模型不存在
            out["ok"] = False
            out["error"] = ("服务端没有这个模型" if "404" in msg
                            else "探测模型失败：%s" % msg[:160])
            return out
        except Exception as e:      # 兜底：探测失败不该让调用方崩
            out["ok"] = False
            out["error"] = "探测模型失败：%s" % e
            return out

        out["exists"] = True
        out["capabilities"] = [str(c) for c in (data.get("capabilities") or [])]
        out["num_ctx"] = _parse_num_ctx(data.get("parameters"))
        return out

    def loaded(self, timeout: float = 3.0) -> Optional[List[str]]:
        """`/api/ps`：当前**已加载进内存/显存**的模型名；拿不到返回 None。

        ★ 必须和"没部署"分开说：Ollama 是按需加载的，空闲 `keep_alive`（默认 5 分钟）
          到期就卸载，所以 `ps` 为空是**正常状态**，不是故障。用户看到"模型没在运行"
          很容易判成配错了，界面上得把这两种情况说清楚。
        """
        url = self.cfg.base_url.rstrip("/") + "/api/ps"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            return None
        return [str(m.get("name") or m.get("model") or "")
                for m in (data.get("models") or []) if isinstance(m, dict)]


class OpenAICompatProvider(AIProvider):
    """OpenAI 兼容接口：POST {base_url}/v1/chat/completions

    Ollama 的兼容模式、vLLM、LM Studio、云端 API 均可走这里。
    """

    name = "openai"
    label = "OpenAI 兼容接口"
    vision = True

    def _endpoint(self) -> str:
        base = self.cfg.base_url.rstrip("/")
        return base + "/chat/completions" if base.endswith("/v1") else base + "/v1/chat/completions"

    def _model(self, vision: bool = False) -> str:
        if vision:
            return (getattr(self.cfg, "vision_model", "") or self.cfg.model)
        return self.cfg.model

    def _headers(self) -> dict:
        return {"Authorization": "Bearer " + self.cfg.api_key} if self.cfg.api_key else {}

    def _chat(self, messages: List[Message], temperature: float, timeout: int) -> str:
        payload = {
            "model": self._model(),
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        data = _post_json(self._endpoint(), payload, headers=self._headers(), timeout=timeout)
        choices = data.get("choices") or []
        if not choices:
            raise AIError("OpenAI 兼容接口返回缺少 choices：%s" % str(data)[:200])
        content = (choices[0].get("message") or {}).get("content")
        if not content:
            raise AIError("返回 choices[0].message.content 为空")
        return str(content).strip()

    def _chat_vision(self, prompt: str, images: Sequence[bytes], system: str,
                     temperature: float, timeout: int) -> str:
        content: List[dict] = [{"type": "text", "text": prompt}]
        for b in images:
            content.append({
                "type": "image_url",
                "image_url": {"url": "data:image/jpeg;base64," + _b64(b)},
            })
        msgs: List[dict] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": content})
        payload = {
            "model": self._model(vision=True),
            "messages": msgs,
            "temperature": temperature,
            "stream": False,
        }
        data = _post_json(self._endpoint(), payload, headers=self._headers(), timeout=timeout)
        choices = data.get("choices") or []
        if not choices:
            raise AIError("视觉请求返回缺少 choices：%s" % str(data)[:300])
        msg = choices[0].get("message") or {}
        out = msg.get("content")
        # 少数服务会把内容放在 content 数组里（多模态返回格式），这里一并兜住
        if isinstance(out, list):
            out = "".join(seg.get("text", "") for seg in out if isinstance(seg, dict))
        if not out:
            raise AIError("视觉请求返回内容为空")
        return str(out).strip()

    def available(self) -> bool:
        base = self.cfg.base_url.rstrip("/")
        url = base + "/models" if base.endswith("/v1") else base + "/v1/models"
        try:
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=3) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False


class DeepSeekProvider(OpenAICompatProvider):
    """DeepSeek 云端 API（2026-11-12 按用户要求新增）。

    协议就是 OpenAI 兼容的那一套（`/v1/chat/completions`），所以直接继承，
    只改三件事：

    · `base_url` 允许留空 —— 留空就用官方地址。让使用者只填一个密钥就能用，
      不必先记住 `https://api.deepseek.com` 这个细节。
    · **哪个模型能看图，是按模型区分的，不是按厂商区分的**（见下）。
    · `label` / `name` 用于报告里标注模型来源（"deepseek · deepseek-flash @ …"）。

    ---- 视觉能力（2026-11-12 修正）----
    初版我把 `vision` 写死成 False，理由是"DeepSeek 对话模型不接受图片"。
    **这条已经过时了。** 官方文档（api-docs.deepseek.com/quick_start/pricing
    的 FEATURES 表、以及 /guides/vision）现在写得很清楚：

        deepseek-flash   (DeepSeek-V4.1-Flash-1017)   Vision ✓
        deepseek-v4-pro  (DeepSeek-V4-Pro-0813)       Vision ✗

    所以正确做法不是整家关掉，而是**按模型分流**：
    带图的调用一律走 `deepseek-flash`；文本调用才可能落到 `deepseek-v4-pro`。
    若使用者只填了 v4-pro、没填视觉模型，`_model(vision=True)` 会自动回落到
    `deepseek-flash` —— 否则每一次看图都 400，然后静默回退成规则策略，
    界面上还写着"AI 已启用"。

    官方还说明：`deepseek-v4-flash`、`deepseek-v4-flash-vision-exp` 两个旧名仍被
    接受，请求由 V4.1-Flash 承接。`deepseek-chat` / `deepseek-reasoner` 已不在
    现行价格表里（2026-07-24 起逐步退场），旧配置里若还留着，这里做一次改名，
    免得使用者拿着一个已经不存在的模型名去撞 400。
    """

    name = "deepseek"
    label = "DeepSeek"
    # 厂商整体具备视觉能力；具体能不能看，由 `_model(vision=True)` 选中的模型决定。
    vision = True

    DEFAULT_BASE_URL = "https://api.deepseek.com"
    # 唯一支持图片输入的模型。视觉调用不允许落到别的模型上。
    VISION_MODEL = "deepseek-flash"
    TEXT_MODEL = "deepseek-flash"
    # 旧名 → 现名。官方明确仍在接受的旧名只有前两个；后两个是退场前的老配置。
    _ALIASES = {
        "deepseek-v4-flash": "deepseek-flash",
        "deepseek-v4-flash-vision-exp": "deepseek-flash",
        "deepseek-chat": "deepseek-flash",
        "deepseek-reasoner": "deepseek-flash",
    }

    def _clean_model(self, raw: str) -> str:
        m = (raw or "").strip()
        if not m:
            return ""
        return self._ALIASES.get(m.lower(), m)

    def _model(self, vision: bool = False) -> str:
        """带图 → 只能是 deepseek-flash；纯文本 → 用配置的模型。

        注意这里**不能**照抄父类的"视觉留空沿用文本模型"：文本模型若是
        `deepseek-v4-pro`，沿用它等于给一个不接受图片的模型送图。
        """
        if vision:
            vm = self._clean_model(getattr(self.cfg, "vision_model", "") or "")
            # 视觉模型填成 v4-pro 也是常见误配，拦下来而不是让它 400。
            if vm and vm != "deepseek-v4-pro":
                return vm
            return self.VISION_MODEL
        return self._clean_model(self.cfg.model) or self.TEXT_MODEL

    def _base(self) -> str:
        return (self.cfg.base_url or "").strip().rstrip("/") or self.DEFAULT_BASE_URL

    def _endpoint(self) -> str:
        base = self._base()
        return base + "/chat/completions" if base.endswith("/v1") else base + "/v1/chat/completions"

    def _headers(self) -> dict:
        key = (getattr(self.cfg, "api_key", "") or "").strip()
        if not key:
            # 早报错比等到 401 好：DeepSeek 是要计费的云服务，没密钥时
            # 请求会直接 401，报错信息还不一定看得懂。
            raise AIError("DeepSeek 需要 API 密钥（在「系统状态 → AI 模型服务」里填写）")
        return {"Authorization": "Bearer " + key}

    def available(self) -> bool:
        base = self._base()
        url = base + "/models" if base.endswith("/v1") else base + "/v1/models"
        try:
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=5) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    # 视觉调用不再覆写：父类 `OpenAICompatProvider._chat_vision` 发的就是
    # `image_url` + `data:image/jpeg;base64,...` 的内容块，正是 DeepSeek 官方文档
    # 写的三种图片入参之一（另外两种是外链 URL 与 Files API file_id，本地截图
    # 用 base64 最直接）。图片格式由 DeepSeek 侧按字节判断，不看后缀。
