"""标准作业流程（SOP）入口：按 P0~P7 阶段跑完整检测，输出模板化报告。

两种用法：

  ① 从已有采集存档离线出报告（不占真机，改模板/改措辞时反复用这个）：
       python run_flow.py --from-result out/ai_jxz4.result.json -o out/flow_jxz4.html

  ② 连真机跑全流程（采集 + 判定 + 报告）：
       python run_flow.py -p com.jz.jxz --apk x.apk -o out/flow.html \
              --ai-provider agent --ai-vision --ai-analyze

流程本身定义在 analysis/checkflow.yaml —— 改阶段、改报告项映射都改那里。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="App 个人信息保护合规检测 · 标准作业流程（SOP）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("-p", "--package", default="", help="目标包名")
    ap.add_argument("--apk", default="", help="APK 路径（用于 P0 静态分析）")
    ap.add_argument("-o", "--out", default="out/flow_report.html", help="报告输出路径")
    ap.add_argument("--json-out", default="", help="流程结果 JSON 输出路径（默认与报告同前缀）")

    ap.add_argument("--from-result", default="",
                    help="从已有 *.result.json 采集存档渲染（不连真机）")
    ap.add_argument("--from-static", default="", help="从已有静态分析 JSON 渲染")
    ap.add_argument("--app-name", default="", help="应用软件名称（进报告头）")
    ap.add_argument("--version", default="", help="应用软件版本")
    ap.add_argument("--market", default="", help="来源应用市场")
    ap.add_argument("--operator", default="", help="主办单位")
    ap.add_argument("--published", default="", help="发布日期")

    # 真机模式
    ap.add_argument("-t", "--seconds", type=int, default=180, help="采集时长（秒）")
    ap.add_argument("--ai-provider", default=None, help="模型服务：none/agent/openai…")
    ap.add_argument("--ai-vision", action="store_true", help="启用视觉能力")
    ap.add_argument("--ai-analyze", action="store_true", help="启用政策分析")
    ap.add_argument("--relay-dir", default="", help="agent 中继目录")
    ap.add_argument("--relay-timeout", type=int, default=1800, help="中继等待秒数")
    ap.add_argument("--mode", default="expert", choices=["expert", "checklist"],
                    help="expert=按阶段走；checklist=按报告项逐项走")
    ap.add_argument("--repro", action="store_true", help="跑 P7 复现确认（需额外一轮采集）")
    ap.add_argument("--deep", action="store_true",
                    help="深度检测档（约 60 分钟采集：层级不限、可登录、事件上限 40k、截图 160 张）")
    ap.add_argument("-c", "--config", default="config.yaml", help="配置文件路径")
    ap.add_argument("--ai-ui-agent", action="store_true", help="开启「AI 指挥 UI 遍历」")
    ap.add_argument("--ai-every", type=int, default=0,
                    help="AI 遍历每几步问一次模型（0=用配置值；1=每步都问）")
    ap.add_argument("--ai-max", type=int, default=-1,
                    help="AI 遍历决策次数上限（-1=用配置值；0=不限）")
    ap.add_argument("--ai-per-node", type=int, default=-1,
                    help="同一界面最多问几次模型（-1=用配置值；0=每步都问）")
    ap.add_argument("--crawl-strategy", default="", choices=["", "guided", "rule"],
                    help="遍历策略：guided=图引导（默认）／rule=不用图引导")
    ap.add_argument("--login-phone", default="",
                    help="测试手机号：遇到登录/注册页时自动代填并申请验证码"
                         "（不填=用 config.yaml 里的默认测试号）。"
                         "验证码收到后写入工作目录的 sms.txt")
    ap.add_argument("--no-login", action="store_true",
                    help="本次不做登录辅助（等同于前端取消「登录辅助测试」勾选）；"
                         "与不传 --login-phone 不同——不传表示用配置里的默认号")
    ap.add_argument("--login-timeout", type=int, default=0,
                    help="等验证码回填的秒数（默认取配置里的 login_timeout，通常 180）")
    ap.add_argument("--keep-app", action="store_true",
                    help="收尾时不卸载被测应用（默认采集完成后卸载，保持设备干净）")
    args = ap.parse_args()

    log = lambda m: print(m, flush=True)   # noqa: E731

    # ---------------------------------------------------------------- 载入存档
    scan_result = None
    static_result = None
    pending_teardown: dict = {}     # 真机轮结束后填入，稍后进报告
    if args.from_result:
        p = Path(args.from_result)
        if not p.exists():
            log("[x] 找不到采集存档：%s" % p)
            return 2
        data = json.loads(p.read_text(encoding="utf-8"))
        from piiscan.collector import ScanResult
        scan_result = ScanResult.from_dict(data)
        pending_teardown = data.get("teardown") or {}
        if pending_teardown:
            log("[*] 已载入收尾记录（卸载）：%s"
                % (pending_teardown.get("note") or "已卸载"))
        static_result = data.get("static") or None
        log("[*] 已载入采集存档：%s（事件 %d 条，同意 %s）"
            % (p.name, len(scan_result.events),
               "已同意" if scan_result.consent_given else "未同意"))
        if not args.package:
            args.package = data.get("package", "")
    if args.from_static:
        sp = Path(args.from_static)
        if sp.exists():
            static_result = json.loads(sp.read_text(encoding="utf-8"))
            log("[*] 已载入静态分析：%s" % sp.name)

    # ---------------------------------------------------------------- 模型通道
    # ★ 两条路径都要建 AI，不能只在真机分支里建。
    #   离线重跑（--from-result / --from-static）以前完全不建 AI，结果是
    #   同一份存档重渲出来的报告里：P5 的差集复核退化成「未经模型复核」、
    #   政策深读那 86 秒的成果整段消失 —— 结论强度比原始那份弱，且没有任何提示。
    #   这类"重渲一次结论就变弱"的偏差最难发现，所以统一在这里建，两边共用。
    ai = None
    ai_tasks = None
    cfg = None
    try:
        from piiscan.config import AppConfig

        cfg_path = Path(args.config)
        if not cfg_path.is_absolute():
            cfg_path = ROOT / cfg_path
        cfg = AppConfig.load(cfg_path) if cfg_path.exists() else AppConfig()
        if args.ai_provider:
            cfg.ai.provider = args.ai_provider
        for flag, feat in ((args.ai_vision, "policy_vision"),
                           (args.ai_analyze, "policy_analyze"),
                           (args.ai_ui_agent, "ui_agent")):
            if flag:
                cfg.ai.features[feat] = True
        if args.relay_dir:
            cfg.ai.relay_dir = args.relay_dir
        if args.relay_timeout:
            cfg.ai.relay_timeout = args.relay_timeout
        if getattr(args, "ai_every", 0):
            cfg.ai.ui_agent_every = max(1, int(args.ai_every))
        if getattr(args, "ai_max", -1) >= 0:
            cfg.ai.ui_agent_max_calls = int(args.ai_max)
        if getattr(args, "ai_per_node", -1) >= 0:
            cfg.ai.ui_agent_per_node = int(args.ai_per_node)
        if getattr(args, "crawl_strategy", ""):
            cfg.scan.crawl_strategy = args.crawl_strategy

        from piiscan.ai import build_tasks_safe
        from piiscan.ai.factory import build_ai_safe
        ai_tasks = build_tasks_safe(cfg.ai, log)
        ai = ai_tasks.ai if ai_tasks is not None else build_ai_safe(cfg.ai)
        log("[*] 模型通道：%s" % ai.describe())
    except Exception as e:                       # noqa: BLE001
        log("[!] 模型通道初始化失败（本轮走纯规则）：%s" % e)

    # ---------------------------------------------------------------- 真机采集
    # ★ 真机这条路径统一走 piiscan.sop_job —— 与平台用的是同一条链。
    #   早先这里和 webapp 各写一套（CLI 走 SOP、平台走旧 pipeline），
    #   同一个 APK 会得到两份不同的结论，而且没人会去核对"平台跑的到底是哪套流程"。
    if not scan_result and args.package:
        try:
            from piiscan.sop_job import JobOptions, run_job

            if args.seconds:
                cfg.scan.duration = args.seconds
            cfg.scan.package = args.package
            # ★ 登录辅助原先只有平台那条链能开（JobOptions.login_phone 由平台表单填），
            #   CLI 根本没有入口 —— 于是命令行跑出来的报告永远写"未登录，账号页未覆盖"。
            #   这里补上，并把手机号同时写进 cfg，便于日志与报告追溯。
            #   默认值取 config.yaml（本机测试机号码）：与平台同一条口径 ——
            #   缺省＝默认做登录，明确不要才用 --no-login 关掉。
            _phone = str(args.login_phone or "").strip()
            if not _phone and not args.no_login:
                _phone = str(getattr(cfg.scan, "login_phone", "") or "").strip()
            if args.no_login:
                _phone = ""
                log("[*] 本次不做登录辅助（--no-login）")
            if _phone:
                cfg.scan.login_phone = _phone
            _lt = int(args.login_timeout or 0) or int(getattr(cfg.scan, "login_timeout", 180) or 180)

            out = Path(args.out)
            opts = JobOptions(
                package=args.package, apk_path=args.apk,
                dynamic=True, duration=args.seconds or cfg.scan.duration,
                policy_wait=cfg.scan.policy_wait,
                reset_app=cfg.scan.reset_app, keep_app=args.keep_app,
                mode=args.mode, do_repro=args.repro,
                depth="deep" if args.deep else "normal",
                login_phone=_phone, login_timeout=_lt,
                report_name=out.name or "report.html",
                flow_name=(Path(args.json_out).name if args.json_out
                           else out.with_suffix(".json").name),
                app_name=args.app_name, version=args.version,
                market=args.market, operator=args.operator, published=args.published)
            res = run_job("cli-" + str(int(time.time())), out.parent, opts,
                          cfg, log=log, ai_tasks=ai_tasks, ai=ai)
            if res.canceled:
                log("[*] 任务已取消：%s" % res.error)
                return 4
            if not res.ok:
                log("[x] 检测失败：%s" % res.error)
                return 3
            # 让调用方拿到与离线路径一致的产物路径
            log("[+] 阶段耗时：%s" % "；".join(
                "%s %.1fs" % (p["phase"], p["seconds"]) for p in res.phases))
            return 0
        except Exception as e:
            log("[!] 真机检测失败：%s\n    改用 --from-result 从存档渲染，或先跑 run_scan.py。" % e)
            return 3
    elif args.apk:
        try:
            from piiscan.apkstatic import analyze
            static_result = analyze(args.apk, log=log)
        except Exception as e:
            log("[!] 静态分析失败：%s" % e)

    if scan_result is None and static_result is None:
        log("[x] 既没有采集存档也没有 APK，无法生成报告。"
            "\n    用法见：python run_flow.py --help")
        return 2

    # ---------------------------------------------------------------- 跑流程
    from piiscan.flow import run_flow
    from piiscan.report import sop_report

    fr = run_flow(package=args.package, apk=args.apk,
                  scan_result=scan_result, static_result=static_result,
                  ai=ai, ai_tasks=ai_tasks,
                  mode=args.mode, do_repro=args.repro, log=log,
                  app_name=args.app_name, version=args.version)
    fr.teardown = pending_teardown
    fr.source_market = args.market or fr.source_market
    fr.operator = args.operator or fr.operator
    fr.published_at = args.published or fr.published_at

    html = sop_report.render(fr, app_name=args.app_name, version=args.version,
                             source_market=args.market, operator=args.operator,
                             published_at=args.published)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")

    jout = Path(args.json_out) if args.json_out else out.with_suffix(".json")
    jout.write_text(json.dumps(fr.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8")

    st = fr.stats()
    log("")
    log("[+] 报告：%s（%.0f KB）" % (out, len(html.encode("utf-8")) / 1024.0))
    log("[+] 流程存档：%s" % jout)
    log("[+] 结论：发现问题 %d / 疑似 %d / 未发现问题 %d / 跳过未测 %d"
        % (st["fail"], st["suspect"], st["pass"], st["not_tested"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
