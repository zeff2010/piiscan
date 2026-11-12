#!/usr/bin/env python3
"""阶段 0 入口：采集 -> 事件流 -> HTML 报告。

用法示例：
  python run_scan.py
  python run_scan.py -p com.example.app -t 30 -o out/app.html
  python run_scan.py --ai-provider ollama --ai-base-url http://127.0.0.1:11434 --ai-model qwen2.5:7b
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from piiscan.ai import build_ai_safe                    # noqa: E402
from piiscan.collector import run_scan                  # noqa: E402
from piiscan.config import AppConfig                    # noqa: E402
from piiscan.report import render                       # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="App 个人信息保护合规检测（阶段 0 初筛）")
    ap.add_argument("-c", "--config", default="config.yaml", help="配置文件路径")
    ap.add_argument("-p", "--package", help="覆盖待检测包名")
    # 接了两台以上测试机时必须指定；不指定时自检会直接拒绝（不替人猜）。
    # 与平台的「测试机」下拉框是同一件事，命令行这边也要能选。
    ap.add_argument("-s", "--serial", help="指定测试机（adb devices 里的序列号）")
    ap.add_argument("-t", "--duration", type=int, help="覆盖采集时长（秒）")
    ap.add_argument("--deep", action="store_true",
                    help="深度检测档（约 15 分钟采集：翻深层菜单、事件上限提高 5 倍、截图 60 张）")
    ap.add_argument("-o", "--out", help="覆盖报告输出路径")
    ap.add_argument("--attach", action="store_true", help="附着到已运行进程，而非冷启动")
    ap.add_argument("--ai-provider", help="覆盖 ai.provider：none / ollama / openai / agent")
    ap.add_argument("--ai-base-url", help="覆盖 ai.base_url")
    ap.add_argument("--ai-model", help="覆盖 ai.model")
    ap.add_argument("--ai-vision", action="store_true",
                    help="开启「看截图定位政策入口 / 判断页面类型」")
    ap.add_argument("--ai-analyze", action="store_true",
                    help="开启「政策全文深读 + 第三方共享清单追链」")
    ap.add_argument("--ai-ui-agent", action="store_true", help="开启「AI 指挥 UI 遍历」")
    ap.add_argument("--ai-ui-every", type=int, help="遍历每 N 步问一次 AI（默认 1）")
    ap.add_argument("--ai-ui-max", type=int, help="AI 决策次数上限，0 = 不限")
    ap.add_argument("--ai-vision-model", help="覆盖 ai.vision_model")
    ap.add_argument("--relay-dir", help="Agent 中继目录（provider=agent 时用）")
    ap.add_argument("--relay-timeout", type=int, help="中继等一次回答的上限（秒）")
    ap.add_argument("--ai-narrative", choices=("on", "off"),
                    help="报告问题描述是否由模型生成（off 则用内置模板）")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.is_absolute():
        cfg_path = Path(__file__).resolve().parent / cfg_path
    cfg = AppConfig.load(cfg_path)

    if args.package:
        cfg.scan.package = args.package
    if args.serial:
        cfg.device.serial = args.serial.strip()
        print("[*] 指定测试机：%s" % cfg.device.serial, flush=True)
    # 先套深度档再决定时长：深档下 -t 不生效（由档位统一决定），
    # 常规档才允许 -t 覆盖。这里的顺序与平台/run_flow 完全一致。
    if args.deep:
        cfg.scan.apply_depth("deep")
        print("[*] 检测深度：深度档（采集 %d 秒，最多 %d 张截图）"
              % (cfg.scan.duration, cfg.scan.max_shots), flush=True)
    elif args.duration:
        cfg.scan.duration = args.duration
    if args.out:
        cfg.report.out = args.out
    if args.attach:
        cfg.scan.spawn = False
    if args.ai_provider:
        cfg.ai.provider = args.ai_provider
    if args.ai_base_url:
        cfg.ai.base_url = args.ai_base_url
    if args.ai_model:
        cfg.ai.model = args.ai_model
    if args.ai_vision_model:
        cfg.ai.vision_model = args.ai_vision_model
    for flag, feat in ((args.ai_vision, "policy_vision"),
                       (args.ai_analyze, "policy_analyze"),
                       (args.ai_ui_agent, "ui_agent")):
        if flag:
            cfg.ai.features[feat] = True
    if args.ai_narrative:
        cfg.ai.features["report_narrative"] = (args.ai_narrative == "on")
    if args.ai_ui_every is not None:
        cfg.ai.ui_agent_every = args.ai_ui_every
    if args.ai_ui_max is not None:
        cfg.ai.ui_agent_max_calls = args.ai_ui_max
    if args.relay_dir:
        cfg.ai.relay_dir = args.relay_dir
    if args.relay_timeout is not None:
        cfg.ai.relay_timeout = args.relay_timeout

    print("=" * 64)
    print("  App 个人信息保护合规检测 · 阶段 0")
    print("=" * 64)
    print("[*] 目标应用：%s" % cfg.scan.package)
    print("[*] AI 配置：provider=%s  model=%s  base_url=%s"
          % (cfg.ai.provider, cfg.ai.model, cfg.ai.base_url))
    print("[*] AI 环节：%s"
          % "、".join(k for k in ("policy_vision", "policy_analyze", "ui_agent",
                                  "report_narrative") if cfg.ai.feature(k)) or "（无）")

    # ★ 整条流水线（采集 + 遍历 + 报告叙述）共用同一个 provider 实例。
    # 这不只是省资源：调用留痕集中在一处，报告才能拼出完整的证据链；
    # 中继模式下也才会只产生**一个**会话目录，值守时不必猜该看哪个。
    from piiscan.ai import build_tasks_safe
    ai_tasks = build_tasks_safe(cfg.ai, print)
    provider = ai_tasks.ai if ai_tasks is not None else build_ai_safe(cfg.ai)
    if provider.name == "none":
        print("[*] 未启用大模型，问题描述将由内置模板生成")
    elif provider.name in ("agent", "relay"):
        print("[*] Agent 中继已就绪：%s" % provider.describe())
        print("    值守命令：python tools/ai_relay.py list / show <id> / answer <id> --file a.json")
    else:
        reachable = provider.available()
        print("[*] 模型服务可达：%s" % ("是" if reachable else "否（调用失败会自动降级为模板生成）"))

    res = run_scan(cfg, ai_tasks=ai_tasks)
    html_out, stats = render(cfg, res, provider)

    out_path = cfg.out_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_out, encoding="utf-8")

    # 把原始采集结果一并落盘：报告模板改动后可用
    #   python tools/rerender_report.py <result.json> --stage0 -o x.html
    # 秒级重渲染，不必为了一次排版调整再占用真机跑一遍十几分钟的采集。
    try:
        rj = out_path.with_suffix(".result.json")
        rj.write_text(json.dumps(res.to_dict(), ensure_ascii=False, indent=2),
                      encoding="utf-8")
        print("[*] 采集结果已存档：%s" % rj.name)
    except Exception as e:      # 存档失败不影响报告交付
        print("[!] 采集结果存档失败（不影响报告）：%s" % e)

    groups = {e.group_key for e in res.events}
    print("-" * 64)
    print("[+] 报告已生成：%s" % out_path)
    print("[+] 事件 %d 条 ｜ 同意前 %d 条 ｜ 条目 %d 组"
          % (len(res.events), len(res.before_consent_events), len(groups)))
    if stats.ai_calls:
        print("[+] 模型调用 %d 次，成功 %d 次，降级模板 %d 次"
              % (stats.ai_calls, stats.ai_ok, stats.template_used))
    if res.hooks_failed:
        print("[!] %d 个 hook 点安装失败，详见报告技术附录" % len(res.hooks_failed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
