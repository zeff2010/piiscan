"""本地模拟多模态模型服务（Ollama 原生 + OpenAI 兼容两套端点）。

用途：在没有真实模型的机器上，把 AI 链路的**协议层**跑穿 —— 验证
图片确实按对方能吃的格式送出去了、结构化输出被正确解析、归一化坐标
换算成像素之后落在该点的位置上，以及服务端抽风时能干净回退而不是
把整个检测任务带崩。

端点：
  GET  /api/tags              Ollama 模型列表（无需鉴权）
  POST /api/chat              Ollama 原生（图片在 message.images，**纯 base64**）
  GET  /v1/models             OpenAI 兼容模型列表
  POST /v1/chat/completions   OpenAI 兼容（图片在 content[].image_url data URI）
  GET  /__requests            返回收到的所有请求摘要（图片只记字节数，不记内容）
  POST /__reset               清空记录与剧本游标

剧本（--script file.json）：一个 JSON 数组，**按请求顺序**消费。每项：
  {"match": "必须出现在提示词里的关键字", "reply": {...}}     正常返回结构化结果
  {"match": "...", "raw": "不是 JSON 的文本"}                模拟格式抖动
  {"match": "...", "status": 500, "raw": "..."}              模拟服务端错误
match 只是自我校验：用它锁定「第几次请求应该是什么任务」，
一旦接线顺序变了，mock 会把不一致记进 /__requests 的 errors 里。
不给 --script 时按提示词特征返回内置默认剧本。

运行：
  python tools/mock_ollama.py 11499
  python tools/mock_ollama.py 11499 --script tmp/ai_script.json
"""
from __future__ import annotations

import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_REPLY = ("[mock-model] 观测到该接口读取了设备标识类个人信息，"
                 "需结合用户同意时机判断是否涉嫌未授权收集。")

# ---- 内置默认剧本：按提示词特征自动匹配（未给 --script 时生效）----
_AUTO_SCRIPTS: List[Tuple[str, Dict[str, Any]]] = [
    ("display_form", {
        "policy_present": True,
        "display_form": "entry_link",
        "entry_index": 0,
        "entry_text": "《个人信息保护》",
        "entry_bbox": [0.12, 0.86, 0.42, 0.90],
        "longest_text_holder": 0,
        "confidence": 0.88,
        "reason": "告知正文中有一段带下划线的蓝色超链接文字，指向《个人信息保护》",
    }),
    ("page_kind", {
        "page_kind": "document_index",
        "is_policy_content": False,
        "next_targets": [
            {"index": 1, "text": "个人信息处理规则", "why": "主政策，应优先打开"},
            {"index": 2, "text": "第三方共享清单", "why": "合规定性的关键证据"},
        ],
        "links": [{"text": "个人信息处理规则", "url": ""},
                  {"text": "第三方共享清单", "url": "https://example.com/sdk-list"}],
        "confidence": 0.8,
        "reason": "页面只有文档标题列表，没有条款正文",
    }),
    ("third_party_docs", {
        "third_party_docs": [
            {"title": "第三方信息共享清单", "url": "https://example.com/share-list",
             "where": "政策第 5 节", "kind": "shared_list"},
            {"title": "第三方 SDK 目录", "url": "", "where": "政策附录", "kind": "sdk_list"},
        ],
        "declared_types": ["设备标识符（IMEI/IMSI/OAID/AndroidID）", "位置信息", "应用列表"],
        "purposes": ["账号安全", "风险控制", "个性化推荐"],
        "retention": "账号注销后 30 日内删除",
        "cross_border": "",
        "cancel_account": [{"path": "我的-设置-账号与安全-注销账号", "detail": "需短信验证"}],
        "correct_delete": [{"path": "我的-设置-账号与安全-更正个人信息", "detail": ""}],
        "complaint": [{"channel": "邮箱", "detail": "privacy@example.com"}],
        "minor_rules": "不满 14 周岁需监护人同意",
        "personalized_ads_off": "我的-设置-隐私-个性化推荐开关",
        "contact": "个人信息保护负责人 privacy@example.com",
        "summary": "示例政策摘要（由 mock 服务生成，仅用于链路验证）。",
    }),
    ("goal_progress", {
        "action": "tap",
        "index": 2,
        "bbox": [],
        "direction": "",
        "text": "",
        "expect": "进入设置页",
        "goal_progress": "progressing",
        "reason": "「设置」是与当前目标最相关的入口",
    }),
]


def _as_text(v: Any) -> str:
    if isinstance(v, str):
        return v
    return json.dumps(v, ensure_ascii=False)


def _extract(req: Dict[str, Any]) -> Tuple[str, List[int], str]:
    """从请求体里取出 (提示词, [每张图片的字节数], 协议类型)。

    两种格式都要认：
      Ollama  —— message.content 是字符串，图片在同级 message.images（纯 base64）
      OpenAI  —— message.content 是数组，图片在 {type:image_url} 的 data URI 里
    这里同时校验了两件事：图片有没有真的发出来、发送格式对不对。
    """
    msgs = req.get("messages") or []
    prompt = ""
    images: List[int] = []
    kind = "ollama"
    for m in msgs:
        if not isinstance(m, dict):
            continue
        c = m.get("content")
        if isinstance(c, str) and c.strip() and m.get("role") != "system":
            prompt = c
        elif isinstance(c, list):
            kind = "openai"
            for part in c:
                if not isinstance(part, dict):
                    continue
                if part.get("type") == "text":
                    prompt = part.get("text") or ""
                elif part.get("type") == "image_url":
                    url = ((part.get("image_url") or {}).get("url") or "")
                    if url.startswith("data:"):
                        try:
                            images.append(len(base64.b64decode(url.split(",", 1)[-1])))
                        except Exception:
                            images.append(-1)       # 解不开，说明格式发错了
                    else:
                        images.append(-2)           # 不是 data URI，OpenAI 端点会拒
        for im in (m.get("images") or []):
            if isinstance(im, str):
                if im.startswith("data:"):
                    images.append(-3)               # Ollama 不认 data: 前缀
                else:
                    try:
                        images.append(len(base64.b64decode(im)))
                    except Exception:
                        images.append(-1)
    return prompt, images, kind


class Script:
    """按顺序消费剧本；每项带 match 关键字做自我校验。"""

    def __init__(self, items: Optional[List[Dict[str, Any]]] = None):
        self.items: List[Dict[str, Any]] = list(items or [])
        self.cursor = 0
        self.errors: List[str] = []

    def reset(self) -> None:
        self.cursor = 0
        self.errors = []

    def take(self, prompt: str) -> Tuple[Optional[str], int, str]:
        """返回 (响应文本, HTTP 状态, 剧本来源说明)。"""
        if self.items:
            if self.cursor >= len(self.items):
                self.errors.append("剧本已用尽：第 %d 次请求没有对应剧本"
                                   % (self.cursor + 1))
                return None, 500, "exhausted"
            item = self.items[self.cursor]
            self.cursor += 1
            kw = str(item.get("match") or "")
            if kw and kw not in prompt:
                self.errors.append(
                    "第 %d 次请求的提示词里找不到关键词 %r —— 接线顺序可能变了"
                    % (self.cursor, kw))
            if "raw" in item:
                return _as_text(item["raw"]), int(item.get("status") or 200), "raw"
            return (json.dumps(item.get("reply") or {}, ensure_ascii=False),
                    int(item.get("status") or 200), "reply")
        for kw, reply in _AUTO_SCRIPTS:
            if kw in prompt:
                return json.dumps(reply, ensure_ascii=False), 200, "auto:" + kw
        return DEFAULT_REPLY, 200, "default"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):       # 静音访问日志
        pass

    # ---- 基础设施 ----
    def _read(self) -> Dict[str, Any]:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            obj = json.loads(raw or b"{}")
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _send(self, obj: Any, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- 路由 ----
    def do_GET(self):
        srv = self.server
        if self.path.startswith("/api/tags"):
            self._send({"models": [{"name": srv.model, "model": srv.model}]})
        elif self.path.startswith("/v1/models"):
            self._send({"object": "list",
                        "data": [{"id": srv.model, "object": "model"}]})
        elif self.path.startswith("/__requests"):
            self._send({"count": len(srv.records),
                        "records": srv.records,
                        "errors": srv.script.errors})
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self):
        srv = self.server
        if self.path.startswith("/__reset"):
            srv.records = []
            srv.script.reset()
            self._send({"ok": True})
            return

        req = self._read()
        if not self.path.startswith(("/api/chat", "/v1/chat/completions")):
            self._send({"error": "not found"}, 404)
            return

        prompt, images, kind = _extract(req)
        raw, code, how = srv.script.take(prompt)
        srv.records.append({
            "seq": len(srv.records) + 1,
            "path": self.path,
            "kind": kind,
            "model": req.get("model") or srv.model,
            "has_system": any(isinstance(m, dict) and m.get("role") == "system"
                              for m in (req.get("messages") or [])),
            "prompt_chars": len(prompt),
            "prompt_head": prompt[:140],
            "images": images,
            "image_total_kb": round(sum(b for b in images if b > 0) / 1024.0, 1),
            "script": how,
            "status": code,
            "reply_chars": len(raw or ""),
        })
        if raw is None:
            self._send({"error": "script exhausted"}, 500)
            return

        # 真模型不会因为「内容不是 JSON」而报错 —— 它就是把那段文本返回来，
        # 由客户端自己去解析、去容错。所以这里也照原样返回。
        if self.path.startswith("/v1/chat/completions"):
            self._send({
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "model": req.get("model") or srv.model,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": raw}}],
            }, code)
        else:
            self._send({
                "model": req.get("model") or srv.model,
                "created_at": "2026-01-01T00:00:00Z",
                "message": {"role": "assistant", "content": raw},
                "done": True,
            }, code)


def serve(port: int = 11499, model: str = "mock-model",
          script: Optional[List[Dict[str, Any]]] = None) -> HTTPServer:
    srv = HTTPServer(("127.0.0.1", port), Handler)
    srv.model = model                 # type: ignore[attr-defined]
    srv.script = Script(script)       # type: ignore[attr-defined]
    srv.records = []                  # type: ignore[attr-defined]
    return srv


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 11499
    items = None
    if "--script" in sys.argv:
        path = sys.argv[sys.argv.index("--script") + 1]
        with open(path, "r", encoding="utf-8") as f:
            items = json.load(f)
    s = serve(p, script=items)
    print("mock model listening on http://127.0.0.1:%d" % p, flush=True)
    try:
        s.serve_forever()
    except KeyboardInterrupt:
        pass
