"""Agent 中继通道 —— 让「对话中的 AI」直接充当检测工具的模型。

## 为什么需要它

本机开发测试阶段的两个现实：没有能跑视觉模型的显卡；为试一次检测就去申请
云端 key 也划不来。而当前对话里的 AI 本身就能看图、懂这套合规语义 ——
提示词本来就是写给「会看图的模型」的，那就不必绕道某个 HTTP 端点。

于是把「模型」换成一次文件投递：工具把请求（截图 + 提示词 + system）落盘，
对话里的 AI 用 Read 看那张图、按提示词的 schema 写好 JSON 答案写回，
工具取到后继续跑。链路是**真实**的 —— 真的看了那张首启截图、真的按
提示词做了判断；只是「推理」发生在对话里，而不是某个服务后面。

将来部署到有模型的环境，把 ai.provider 从 agent 换成 ollama / openai 即可，
上层代码一行都不用改 —— 这正是 provider 抽象层存在的意义。

## 落盘布局

    out/ai_relay/<会话>/
        session.json          会话元信息（创建时间、超时、pid）
        req/0001.json         请求：kind / system / prompt / images / 超时
        img/0001_1.jpg        截图（对话里的 AI 直接看这张）
        resp/0001.json        回答：{"raw": "<模型原样输出>"}
        log.txt               人类可读的往返日志（含超时记录）

## 超时

请求写好后阻塞轮询 resp/<id>.json，超过 relay_timeout（默认 900 秒）抛 AIError，
由调用方回退到确定性策略。**绝不允许把检测卡死**：对话可能中断、人可能走开，
而一次没人回答的等待不该让整个检测任务烂在那里。
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import cancel
from .base import AIError, AIProvider

DEFAULT_TIMEOUT = 900        # 给对话中的 AI 留足看图与思考的时间
POLL_INTERVAL = 0.4


class AgentRelayProvider(AIProvider):
    """把请求投递给「对话中的 AI」并等待回答。"""

    name = "agent"
    label = "Agent 中继（对话中的 AI 亲自看图和回答）"
    vision = True

    def __init__(self, cfg):
        super().__init__(cfg)
        raw = str(getattr(cfg, "relay_dir", "") or "").strip()
        base = Path(raw).expanduser() if raw else (Path.cwd() / "out" / "ai_relay")
        self.session = time.strftime("%Y%m%d-%H%M%S") + "-%d" % os.getpid()
        self.dir = base / self.session
        self.timeout = int(getattr(cfg, "relay_timeout", 0) or DEFAULT_TIMEOUT)
        self.seq = 0                 # 本会话已投递的请求数
        self.answered = 0
        self.timed_out = 0
        self._ready = False

    # ------------------------------------------------------------ 目录

    def _ensure(self) -> None:
        if self._ready:
            return
        for sub in ("req", "resp", "img"):
            (self.dir / sub).mkdir(parents=True, exist_ok=True)
        self._write_json(self.dir / "session.json", {
            "session": self.session,
            "created": time.time(),
            "timeout": self.timeout,
            "pid": os.getpid(),
            "note": "本目录是 Agent 中继通道。对话里的 AI 读 req/*.json 与 img/*.jpg，"
                    "把回答写进 resp/*.json。",
        })
        self._ready = True

    def available(self) -> bool:
        """中继通道可用性 = 目录能建、能写。"""
        try:
            self._ensure()
            probe = self.dir / ".probe"
            probe.write_text("1", encoding="utf-8")
            probe.unlink()
            return True
        except Exception:
            return False

    def describe(self) -> str:
        return "%s · 会话 %s · 待回答目录 %s" % (self.label, self.session, self.dir)

    def stats(self) -> Dict[str, Any]:
        return {"session": self.session, "dir": str(self.dir), "sent": self.seq,
                "answered": self.answered, "timed_out": self.timed_out}

    # ------------------------------------------------------------ 接口实现

    def _chat(self, messages: List[Dict[str, str]], temperature: float, timeout: int) -> str:
        system, user = "", ""
        for m in messages:
            if m.get("role") == "system":
                system = m.get("content") or ""
            else:
                user = m.get("content") or ""
        return self._relay("chat", user, [], system, timeout)

    def _chat_vision(self, prompt: str, images: Sequence[bytes], system: str,
                     temperature: float, timeout: int) -> str:
        return self._relay("vision", prompt, list(images or []), system, timeout)

    # ------------------------------------------------------------ 投递与等待

    def _relay(self, kind: str, prompt: str, images: List[bytes],
               system: str, timeout: int) -> str:
        try:
            self._ensure()
        except Exception as e:
            raise AIError("无法创建中继目录：%s" % e)

        self.seq += 1
        rid = self.seq
        names: List[str] = []
        try:
            for i, blob in enumerate(images):
                name = "%04d_%d.jpg" % (rid, i + 1)
                (self.dir / "img" / name).write_bytes(blob)
                names.append(name)
            # 等待上限只由 relay_timeout 决定。
            # 不能与调用方传入的 timeout 取 max —— 视觉调用默认会传 180 秒
            # （那是给 HTTP 模型的），取 max 会让 relay_timeout 形同虚设，
            # 中继模式下就再也调不短等待时间了。
            wait = self.timeout
            self._write_json(self.dir / "req" / ("%04d.json" % rid), {
                "id": rid, "kind": kind, "system": system, "prompt": prompt,
                "images": names, "ts": time.time(), "timeout": wait,
                "expect": "把回答写进 resp/%04d.json，形如 {\"raw\": \"<你要返回的原始文本>\"}"
                          % rid,
            })
        except Exception as e:
            raise AIError("写入中继请求失败：%s" % e)

        resp = self.dir / "resp" / ("%04d.json" % rid)
        self._log("[%04d] 投递 %s（%d 张图，提示词 %d 字），上限 %ds"
                  % (rid, kind, len(names), len(prompt), wait))
        deadline = time.time() + wait
        while time.time() < deadline:
            # 中继默认等 900 秒。用户点了停止就该立刻退出，而不是"等人工答完"——
            # 否则停止按钮在中继模式下同样是个假动作（2026-11-12）。
            cancel.check("Agent 中继等待")
            if resp.exists():
                raw = self._read_resp(resp)
                if raw is not None:
                    self.answered += 1
                    self._log("[%04d] 收到回答（%d 字）" % (rid, len(raw)))
                    return raw
            time.sleep(POLL_INTERVAL)

        self.timed_out += 1
        self._log("[%04d] 超时未收到回答，交由调用方回退确定性策略" % rid)
        raise AIError("Agent 中继超时：等待 %ds 仍未收到 resp/%04d.json（%s）"
                      % (wait, rid, self.dir))

    # ------------------------------------------------------------ 小工具

    @staticmethod
    def _read_resp(path: Path) -> Optional[str]:
        """读回答。既接受 {"raw": "..."}，也接受整文件就是一段文本。"""
        try:
            text = path.read_text(encoding="utf-8").strip()
        except Exception:
            return None
        if not text:
            return None
        try:
            obj = json.loads(text)
        except Exception:
            return text                       # 直接把文件内容当回答
        if isinstance(obj, dict):
            for key in ("raw", "text", "content", "answer"):
                val = obj.get(key)
                if isinstance(val, str):
                    return val
            return json.dumps(obj, ensure_ascii=False)   # 回退：整个对象序列化
        return text

    @staticmethod
    def _write_json(path: Path, obj: Any) -> None:
        """原子写：先写 .tmp 再替换，避免对话侧读到半截文件。"""
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, path)

    def _log(self, line: str) -> None:
        try:
            with open(self.dir / "log.txt", "a", encoding="utf-8") as f:
                f.write("%s  %s\n" % (time.strftime("%H:%M:%S"), line))
        except Exception:
            pass
