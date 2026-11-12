# -*- coding: utf-8 -*-
"""「测试连接」判定口径的回归测试。

背景（用户提问）：ollama 服务在跑，但 `ollama ps` 里看不到模型，
界面上却只写"✓ 服务可达"。要回答的是：这算不算假阳性？

结论是**两个问题混在一起**：
  ① "模型没加载" 是正常状态 —— Ollama 按需加载、空闲自动卸载（`keep_alive`），
     `ps` 为空不代表不能用；
  ② 但"只报可达"确实是口径不足 —— 端口通、模型名写错时同样是绿的，
     使用者要等跑完一轮才发现配错。

所以本文件测的是"**能不能把这两种情况分开说**"：必须有 `/api/show` 这一层
确认模型真的部署了，并用 `/api/ps` 单独描述加载状态。

用本地 ollama 桩（stub）而不是某台内网机器：测试不该依赖外部服务，
否则服务一停机、模型一改版，回归就成了"看运气"。
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiscan.ai.providers import OllamaProvider, _parse_num_ctx   # noqa: E402
from piiscan.config import AppConfig                              # noqa: E402

_ok = 0
_bad = 0


def check(name: str, cond: bool, detail=""):
    global _ok, _bad
    if cond:
        _ok += 1
    else:
        _bad += 1
        print("  [FAIL] %s  %s" % (name, detail))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _get_json(url: str, timeout: float = 60.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# --------------------------------------------------------------- ollama 桩
class _Stub:
    """最小 ollama 桩：只实现 /api/tags、/api/show、/api/ps 三个只读接口。

    故意把 num_ctx 做成可配置，好用同一条路径测出"配置与模型实际不一致"。
    """

    def __init__(self):
        self.tags = ["qwen3.8-fast:latest", "qwen3.5:2b"]
        self.ctx = {"qwen3.8-fast": 8192, "qwen3.5": 2048}
        self.caps = {"qwen3.8-fast": ["completion", "vision", "tools"],
                     "qwen3.5": ["completion"]}
        self.ps = []

    @staticmethod
    def _key(name: str) -> str:
        return (name or "").split(":")[0].strip()


def _serve_stub(stub: _Stub):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code: int, obj):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/tags":
                return self._json(200, {"models": [{"name": n} for n in stub.tags]})
            if path == "/api/ps":
                return self._json(200, {"models": [{"name": n} for n in stub.ps]})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                body = {}
            if path != "/api/show":
                return self._json(404, {"error": "not found"})
            key = stub._key(body.get("model") or "")
            if key not in stub.ctx:
                return self._json(404, {"error": "model not found"})
            # parameters 走文本形态（老版本 ollama 的真实返回就是这个样子）
            return self._json(200, {
                "parameters": "num_ctx                        %d\n"
                              "repeat_penalty                 1\n" % stub.ctx[key],
                "capabilities": stub.caps.get(key, []),
            })

    port = _free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % port


# ------------------------------------------------------------------ 单元层
def test_parse_num_ctx():
    check("解析文本形态的 num_ctx",
          _parse_num_ctx("num_ctx                        8192\nrepeat_penalty 1") == 8192,
          _parse_num_ctx("num_ctx 8192"))
    check("解析 dict 形态的 num_ctx", _parse_num_ctx({"num_ctx": "4096"}) == 4096,
          _parse_num_ctx({"num_ctx": "4096"}))
    check("取不到时返回 0（不拿配置值冒充）",
          _parse_num_ctx(None) == 0 and _parse_num_ctx("top_k 20") == 0)


def test_provider_show_and_loaded(base: str):
    cfg = AppConfig.load(ROOT / "config.yaml")
    ai = cfg.ai
    ai.base_url = base
    p = OllamaProvider(ai)

    info = p.show("qwen3.8-fast")
    check("show：模型存在", info.get("exists") is True, info)
    check("show：读回真实 num_ctx", info.get("num_ctx") == 8192, info.get("num_ctx"))
    check("show：带 capabilities", "vision" in (info.get("capabilities") or []), info)

    info2 = p.show("qwen9-nope")
    check("show：不存在的模型 exists=False", info2.get("exists") is False, info2)
    check("show：不存在的模型给出明确原因",
          "没有这个模型" in (info2.get("error") or ""), info2.get("error"))
    check("show：不抛异常（恒返回 dict）", isinstance(info2, dict), type(info2))

    # loaded() 的三种状态必须能区分：[] 已加载零个 / [名] / None 拿不到
    check("loaded：桩返回空列表（未加载）", p.loaded() == [], p.loaded())
    bad = OllamaProvider(ai)
    bad.cfg.base_url = "http://127.0.0.1:%d" % _free_port()
    check("loaded：连不上返回 None（不是空列表）", bad.loaded() is None, bad.loaded())


# ---------------------------------------------------------------- 接口层
def test_preflight_timeout_scaling(stub: _Stub, stub_base: str):
    """预检的推理超时必须随"是否已加载"变化。

    这是本次最容易踩的坑：模型没加载时，那一次自检调用要先把 16.9GB 权重读进来，
    给 60s 会把"正在加载"误判成"推理失败"，而部署后第一次自检恰好就是这个状态。
    已加载时则不该让用户干等几分钟 —— 那种情况本来就该秒回。
    """
    import piiscan.ai.factory as fac
    from piiscan.preflight import check_ai

    cfg = AppConfig.load(ROOT / "config.yaml")
    cfg.ai.base_url = stub_base
    p = OllamaProvider(cfg.ai)
    seen = {}

    def fake_chat(messages, temperature=0.2, timeout=90, **kw):
        seen["timeout"] = timeout
        return "在线"

    p.chat = fake_chat
    orig = fac.build_ai
    fac.build_ai = lambda ai: p
    try:
        stub.ps = []                       # 未加载 → 要给足加载时间
        r = check_ai(cfg, lambda m: None)
        check("未加载时自检仍通过（加载不算失败）", r.ok is True, r.detail)
        check("未加载时超时放宽到 ≥180s", seen.get("timeout", 0) >= 180, seen)
        check("未加载时说明里点明含加载", "含首次加载" in (r.detail or ""), r.detail)

        stub.ps = ["qwen3.8-fast:latest"]  # 已加载 → 该短超时
        r = check_ai(cfg, lambda m: None)
        check("已加载时超时回到 ≤60s", seen.get("timeout", 999) <= 60, seen)
        check("已加载时不写「含加载」", "含首次加载" not in (r.detail or ""), r.detail)
    finally:
        fac.build_ai = orig
        stub.ps = []


def test_ai_ping(stub: _Stub, stub_base: str, svc: str):
    def ping(**kw) -> dict:
        q = {"provider": "ollama", "base_url": stub_base, "model": "qwen3.8-fast"}
        q.update(kw)
        return _get_json(svc + "/api/ai/ping?" + urllib.parse.urlencode(q))

    # ① 服务可达 + 模型已部署 + 当前未加载 —— 这是用户看到的那种情况
    stub.ps = []
    r = ping()
    check("未加载时 ok 仍为 True（按需加载不是故障）", r.get("ok") is True, r)
    check("明确报 model_exists=True", r.get("model_exists") is True, r)
    check("明确报 loaded=False", r.get("loaded") is False, r)
    check("说明里出现「按需加载」", "按需加载" in (r.get("state") or ""), r.get("state"))
    check("说明里点名「不是故障」", "不是故障" in (r.get("state") or ""), r.get("state"))
    check("带真实 num_ctx", r.get("num_ctx") == 8192, r.get("num_ctx"))

    # ② 已加载 → 状态必须变，不能还写"未加载"
    stub.ps = ["qwen3.8-fast:latest"]
    r = ping()
    check("已加载时 loaded=True", r.get("loaded") is True, r)
    check("已加载时不再说「未加载」", "未加载" not in (r.get("state") or ""), r.get("state"))
    stub.ps = []

    # ③ 模型名写错 —— 这是最要紧的一条：不能再显示"服务可达"就算过
    r = ping(model="qwen9-nope")
    check("模型不存在时 ok=False", r.get("ok") is False, r)
    check("模型不存在时 reachable 仍为 True（把两件事分开）",
          r.get("reachable") is True, r.get("reachable"))
    check("错误信息点明「没有部署」", "没有部署" in (r.get("error") or ""), r.get("error"))
    check("错误信息给出可用模型", "qwen3.8-fast" in (r.get("error") or ""), r.get("error"))

    # ④ 上下文与配置不一致 —— 必须报警，否则预算按错的算
    stub.ctx["qwen3.8-fast"] = 4096
    r = ping()
    check("num_ctx 与配置不一致时给出告警",
          "不一致" in (r.get("ctx_note") or ""), r.get("ctx_note"))
    check("告警里同时给出两个数字",
          "8192" in (r.get("ctx_note") or "") and "4096" in (r.get("ctx_note") or ""),
          r.get("ctx_note"))
    stub.ctx["qwen3.8-fast"] = 8192

    # ⑤ 视觉能力以 capability 为准，不靠名字猜
    stub.caps["qwen3.8-fast"] = ["completion", "vision"]
    r = ping()
    check("有 vision 能力时判定为支持图片",
          "支持图片输入" in (r.get("vision_hint") or ""), r.get("vision_hint"))
    stub.caps["qwen3.8-fast"] = ["completion"]     # 纯文本模型
    r = ping()
    check("没有 vision 能力时明确说不支持",
          "没有 vision" in (r.get("vision_hint") or ""), r.get("vision_hint"))
    stub.caps["qwen3.8-fast"] = ["completion", "vision", "tools"]

    # ⑥ 视觉模型单独配了但服务端没有 → 视觉环节会静默回退，必须说出来
    r = ping(vision_model="qwen-vl-nope")
    check("视觉模型未部署时给出警告",
          "视觉模型" in (r.get("vision_hint") or "")
          and "没有部署" in (r.get("vision_hint") or ""), r.get("vision_hint"))

    # ⑦ 地址不可达
    r = ping(base_url="http://127.0.0.1:%d" % _free_port())
    check("连不上时 ok=False", r.get("ok") is False, r)
    check("连不上时 reachable=False", r.get("reachable") is False, r)
    check("连不上时错误信息带地址", "无法连接" in (r.get("error") or ""), r.get("error"))


def main() -> int:
    stub = _Stub()
    srv, stub_base = _serve_stub(stub)
    work = Path(tempfile.mkdtemp(prefix="aiping-"))
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "run_platform.py"), "--port", str(port),
         "--workdir", str(work), "--no-device", "--quiet"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    svc = "http://127.0.0.1:%d" % port
    try:
        for _ in range(120):
            try:
                if _get_json(svc + "/api/health", timeout=3).get("ok"):
                    break
            except Exception:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("测试服务未能启动：%s"
                               % proc.stderr.read().decode("utf-8", "replace")[:400])

        test_parse_num_ctx()
        test_provider_show_and_loaded(stub_base)
        test_preflight_timeout_scaling(stub, stub_base)
        test_ai_ping(stub, stub_base, svc)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        srv.shutdown()

    total = _ok + _bad
    print("\n  AI 连接探测：%d 项通过 / %d 项失败（共 %d）" % (_ok, _bad, total))
    return 1 if _bad else 0


if __name__ == "__main__":
    sys.exit(main())
