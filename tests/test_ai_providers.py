"""验证 AI provider 的接口兼容性。

不依赖真实 Ollama：本地起一个同时实现 Ollama 原生接口和 OpenAI 兼容接口的模拟服务，
分别用 provider=ollama 与 provider=openai 走一遍完整调用链，确认接口实现对得上。

运行：
  python tests/test_ai_providers.py
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from mock_ollama import DEFAULT_REPLY as MOCK_REPLY, serve   # noqa: E402
from piiscan.ai import AIError, build_ai           # noqa: E402
from piiscan.config import AIConfig                # noqa: E402

PORT = 11499
BASE = "http://127.0.0.1:%d" % PORT
MESSAGES = [{"role": "user", "content": "请描述这条采集行为"}]


def main() -> int:
    srv = serve(PORT, model="mock-model")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.4)

    failures = []

    def check(title, provider, expect_ok=True):
        print("\n--- %s ---" % title)
        print("  provider.name = %s" % provider.name)
        try:
            reachable = provider.available()
        except Exception as e:
            reachable = "异常: %s" % e
        print("  available()   = %s" % reachable)
        try:
            out = provider.chat(MESSAGES)
            print("  chat() 返回   = %s" % out[:90])
            if expect_ok and MOCK_REPLY[:12] not in out:
                failures.append("%s: 返回内容与预期不符" % title)
        except AIError as e:
            print("  chat() 抛错   = %s" % e)
            if expect_ok:
                failures.append("%s: 不应抛错 (%s)" % (title, e))
        except Exception as e:
            failures.append("%s: 意外异常 (%s)" % (title, e))

    check("provider=ollama（Ollama 原生 /api/chat）",
          build_ai(AIConfig(provider="ollama", base_url=BASE, model="mock-model", timeout=10)))

    check("provider=openai（OpenAI 兼容 /v1/chat/completions）",
          build_ai(AIConfig(provider="openai", base_url=BASE, model="mock-model", timeout=10)))

    check("provider=openai + base_url 已带 /v1",
          build_ai(AIConfig(provider="openai", base_url=BASE + "/v1", model="mock-model", timeout=10)))

    # none 必须抛 AIError，让上层降级
    print("\n--- provider=none（应抛 AIError 以便上层降级）---")
    nullp = build_ai(AIConfig(provider="none"))
    try:
        nullp.chat(MESSAGES)
        failures.append("none: 未抛错")
    except AIError as e:
        print("  正确抛出 AIError = %s" % e)

    # 别名解析
    for alias in ["openai_compat", "vllm", "lmstudio"]:
        p = build_ai(AIConfig(provider=alias, base_url=BASE, model="m"))
        print("别名 %-14s -> %s" % (alias, p.name))
        if p.name != "openai":
            failures.append("别名 %s 未解析到 openai" % alias)

    srv.shutdown()

    print("\n" + "=" * 56)
    if failures:
        print("失败 %d 项：" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("全部通过：ollama 与 openai 两种接口调用链均可用")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
