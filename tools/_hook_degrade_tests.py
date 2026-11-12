#!/usr/bin/env python3
"""注入失败降级（仅界面采集）的离线用例。

背景（2026-10-27 小盒课堂/小盒AI学）：加固壳（爱加密）让 frida 的
"暂停 → 注入 → 恢复"走不通，`device.spawn` 干等 30 秒抛 TimedOutError，
整轮任务直接判失败 —— 一张截图、一个字政策正文都没留下。

"注入不了"和"应用跑不起来"是两件事：界面、政策、权限弹窗照样能采。
所以注入失败时降级为"仅界面采集"，用 `_NoScript` 接住下游所有
`script.post(...)` / `exports_sync.xxx()` 调用，并把这件事记进
`res.hook_hostile` → 报告里写"检测手段受限"。

这里守的是三件事：
  ① 替身必须容忍下游**真实**的调用形状（返回 None/{}，绝不抛异常）；
  ② 降级后不能还去 spawn / attach / 注子进程（再赔一次超时，还可能害死应用）；
  ③ 降级不能被误判成"应用未能正常运行"。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def run(check) -> None:
    from piiscan import collector as C
    from piiscan.flow import models as M

    src = (ROOT / "piiscan" / "collector.py").read_text(encoding="utf-8")

    # ---- ① 替身容错 ----
    live = C._Live()
    check("① 新会话默认标记为「未注入」", live.hooked is False, str(live.hooked))
    scr = C._NoScript()
    check("① 替身 post 不抛异常且返回 None",
          scr.post({"type": "event"}) is None, "")
    check("① 替身 on/load/unload 可调用", all(
        f() is None for f in (lambda: scr.on("message", None),
                              scr.load, scr.unload)), "")
    # 下游真实写法：`... or {}` / `... or []` / 直接丢弃返回值的 for 循环
    check("① exports_sync.get_policy() 返回 None（下游用 or {}）",
          (scr.exports_sync.get_policy() or {}) == {}, "")
    check("① exports_sync.current_urls() 返回 None（下游用 or []）",
          (scr.exports_sync.current_urls() or []) == [], "")
    check("① exports_sync.summary() 返回 None（下游用 or {}）",
          (scr.exports_sync.summary() or {}) == {}, "")
    check("① 任意新方法名都不炸（不会因为脚本改版而崩）",
          scr.exports_sync.whatever_new_method(1, 2, k=3) is None, "")
    check("① 替身本身也算 exports_sync 的存在",
          hasattr(scr, "exports_sync"), "")

    # ---- ② 降级路径不许再注入 ----
    check("② spawn 失败被兜住，不再直接判死整轮",
          "冷启动注入失败" in src and "hook_degraded" in src, "")
    check("② 降级后先探测「应用自己能不能起来」，不直接放弃注入",
          re.search(r"if hook_degraded:[\s\S]{0,300}probe_start_without_hook", src)
          is not None, "")
    # 附着改走 `_fguard.attach`（带超时，见 frida_guard 头部），语义不变：
    # 应用能起来时就"先启动、后附着"，而不是反复 spawn。
    check("② 探测到应用能跑时，改用「先启动、后附着」注入",
          re.search(r'if _probe\.get\("started"\):[\s\S]{0,500}live\.session = '
                    r'(?:device\.attach\(|_fguard\.attach\()', src) is not None, "")
    check("② 探测到应用起不来时，不走 attach（省掉必然失败的尝试）",
          re.search(r'res\.attach_after_spawn_fail = "skipped"', src) is not None, "")
    check("② 降级后 respawn 不再 spawn（只 adb 拉起）",
          re.search(r"def respawn[\s\S]{0,900}if not live\.hooked:[\s\S]{0,200}"
                    r"launch_app\(", src) is not None, "")
    check("② 降级后不重附着（rehook 直接返回 False）",
          re.search(r"def rehook[\s\S]{0,700}if not live\.hooked:[\s\S]{0,80}return False",
                    src) is not None, "")
    check("② 降级后不注子进程",
          src.count("if live.hooked:\n                _attach_extra_processes") >= 1
          or src.count("if live.hooked:") >= 2, "")
    # 洋葱学园实测 13 秒才回 hook 回执（加固壳解壳慢），12 秒窗口太紧
    check("② 等 hook 回执给到 20 秒（加固包解壳慢）",
          "hooks_ready.wait(20)" in src, "")

    # ---- ③ 降级不等于"应用没起来" ----
    h = M.assess_run_health(
        [{"activity": "com.demo.app/.SplashActivity",
          "texts": ["隐私政策", "同意并继续"]},
         {"activity": "com.demo.app/.MainActivity", "texts": ["推荐", "我的"]}],
        "com.demo.app", foreground_seen=True, hook_hostile=1)
    check("③ 有界面证据就不算「应用未能正常运行」",
          h["state"] == "ok", str(h))
    check("③ 但要标出「注入被拦截」", h.get("hook_blocked") is True, str(h))
    check("③ 原因里写清「检测手段受限」而非「应用有问题」",
          "加固" in h["why"] and "不代表应用自身无法运行" in h["why"], h["why"])

    fr = M.FlowResult(package="com.demo.app")
    fr.runtime_data = {"run_health": h, "screens": 12, "ui_steps": 40}
    check("③ 降级轮不算「应用未能启动」（任务不该判失败）",
          fr.app_start_failed is False, str(h.get("state")))
    h2 = M.assess_run_health([], "com.demo.app", foreground_seen=False, hook_hostile=0)
    check("③ 真的没起来才判失败", h2["state"] == "no_app", str(h2.get("state")))

    # ---- ④ 两种"注入被杀"必须分开：补救办法相反（2026-10-27 实测） ----
    #   · re-attach 被杀 → 以后别 attach，可以改走 spawn 重建
    #   · spawn 注入被杀 → 这个壳连冷启动都杀，再注入只会反复杀应用
    check("④ 存活检查区分 re-attach 致死与 spawn 致死",
          "_reattach_hit" in src and "_spawn_hit" in src, "")
    check("④ re-attach 致死只禁附着（reattach_banned）",
          "res.reattach_banned = True" in src, "")
    check("④ spawn 致死单独计数（hook_spawn_killed）",
          "res.hook_spawn_killed += 1" in src, "")
    check("④ 只有 spawn 没死过，才允许冷启动重建注入",
          "if respawn is not None and not res.hook_spawn_killed" in src, "")
    check("④ 脚本中途失效时，附着被禁就改走冷启动重建",
          re.search(r"elif res\.reattach_banned:[\s\S]{0,400}respawn\(\)", src)
          is not None, "")

    # ---- ⑤ "应用在本机起不来" ≠ "检测手段受限" ----
    h3 = M.assess_run_health(
        [{"activity": "", "texts": []}] * 3, "cn.knowbox.androidaiclass",
        foreground_seen=False, hook_hostile=1,
        app_start_probe={"started": False,
                         "why": "不注入直接启动时进程反复重建（共出现 5 个不同 pid）",
                         "evidence": "avc: denied { execmod } for /system/lib64/liblog.so"})
    check("⑤ 探测到应用自己起不来，判 no_app（不是 no_ui/no_dump）",
          h3["state"] == "no_app", str(h3.get("state")))
    check("⑤ 原因里带出启动失败现场（SELinux/崩溃原文）",
          "execmod" in h3["why"], h3["why"][:160])
    check("⑤ 这时不许再说「不代表应用自身无法运行」",
          "不代表应用自身无法运行" not in h3["why"], h3["why"][-120:])

    # 应用能跑、只是注入被杀：仍要写"检测手段受限"
    h4 = M.assess_run_health(
        [{"activity": "com.demo.app/.Main", "texts": ["首页", "我的"]}],
        "com.demo.app", foreground_seen=True, hook_hostile=2, hook_spawn_killed=1,
        app_start_probe={"started": True, "why": "不注入时进程稳定存活"})
    check("⑤ 应用能跑时，仍归因为检测手段受限", h4["state"] == "ok"
          and "检测手段受限" in h4["why"], h4["why"][:120])

    # 探到界面就不许被探测结论推翻（启动慢 ≠ 起不来）
    h5 = M.assess_run_health(
        [{"activity": "com.demo.app/.Main", "texts": ["首页", "我的"]}],
        "com.demo.app", app_start_probe={"started": False, "why": "超时"})
    check("⑤ 已取得界面证据时，探测的否定结论不采纳",
          h5["state"] == "ok", str(h5.get("state")))

    _head, _why = M.start_failed_reason(
        type("F", (), {"run_health": h3, "relaunch_count": 5})())
    check("⑤ 失败原因用探测原文，而不是「进程反复退出 5 次」",
          "反复重建" in _why, _why[:160])
    # 这条原因会出现在每一个未测项里，不能把 logcat 原文贴 22 遍
    check("⑤ 逐项原因只给指针，不重复贴现场原文",
          "execmod" not in _why and "目标应用启动状态" in _why, _why[:160])
    check("⑤ 失败标题不再把注入被拦当成主因", "注入被加固机制拦截" not in _head, _head)

    # ---- ⑥ 探测判据本身：崩溃循环不能被判成"能启动" ----
    check("⑥ 要求至少 3 次采样且 pid 全程一致才算能启动",
          re.search(r"len\(seen\) >= 3 and len\(uniq\) == 1", src) is not None, "")
    check("⑥ 进程名带 :xxx 后缀也要能认出来（pidof 认不出）",
          "parts[-1].startswith(package)" in src, "")
