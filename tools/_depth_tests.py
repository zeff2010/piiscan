#!/usr/bin/env python3
"""检测深度档的自测：预算参数是否成套、有没有"只调一半"的情况。

为什么要单独钉住这个：深度档坏掉不会报错，只会表现成
「跑了 15 分钟，采到的事件数和 90 秒那轮一样多」——
因为事件被 `global_event_cap` 截断了，或者遍历压根没走到深层界面。
这种"看起来测得很深"的报告比一份短报告危险得多。

跑法：python tools/_depth_tests.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def run(check) -> None:
    from piiscan.config import DEPTH_PROFILES, ScanConfig
    from piiscan.sop_job import apply_depth_budget

    # ---------------------------------------------------------------- 档位表
    # 四档（2026-10-31 用户定的口径）：1 档仅同意前 / 2 档浅测 / 3 档深度 / 4 档极致。
    # normal 是历史档（约 1.5 分钟），保留只为读得懂旧存档与老调用方。
    check("档位表：四档 + 历史常规档都在",
          set(DEPTH_PROFILES) == {"pre", "light", "normal", "deep", "extreme"},
          sorted(DEPTH_PROFILES))
    keys = set(DEPTH_PROFILES["normal"])
    for _k in ("pre", "light", "deep", "extreme"):
        check("档位表：%s 与常规档参数项完全相同（少一项就会沿用上一档的值）" % _k,
              keys == set(DEPTH_PROFILES[_k]), keys ^ set(DEPTH_PROFILES[_k]))
    must = {"duration", "policy_wait", "ui_tap_interval", "max_shots",
            "max_events_per_hook", "global_event_cap", "repro_duration",
            "max_depth", "login_enabled", "consent_only"}
    check("档位表：关键预算项齐全", must <= keys, must - keys)

    n, d = DEPTH_PROFILES["normal"], DEPTH_PROFILES["deep"]
    for k in ("duration", "policy_wait", "max_shots", "max_events_per_hook",
              "global_event_cap", "repro_duration"):
        check("深度档的 %s 必须大于常规档" % k, d[k] > n[k], "%r vs %r" % (d[k], n[k]))
    # 点得太快容易被判成机器操作，也来不及看加载中的界面
    check("深度档点击间隔不小于常规档", d["ui_tap_interval"] >= n["ui_tap_interval"],
          "%r vs %r" % (d["ui_tap_interval"], n["ui_tap_interval"]))

    # ---- 四档的语义必须写在档位表里，而不是靠调用方记得 ----
    p, l, x = (DEPTH_PROFILES["pre"], DEPTH_PROFILES["light"],
               DEPTH_PROFILES["extreme"])
    check("1 档：只测同意前（不点同意）", p["consent_only"] is True, p["consent_only"])
    check("1 档：不登录", p["login_enabled"] is False, p["login_enabled"])
    check("2 档：同意后测（不点 consent_only）", l["consent_only"] is False)
    check("2 档：不登录", l["login_enabled"] is False, l["login_enabled"])
    check("2 档：只到二级目录", l["max_depth"] == 2, l["max_depth"])
    check("2 档：约 5 分钟", 240 <= l["duration"] <= 360, l["duration"])
    check("3 档：允许登录", d["login_enabled"] is True, d["login_enabled"])
    check("3 档：不限制层级", d["max_depth"] == 0, d["max_depth"])
    check("4 档：约 60 分钟", 3300 <= x["duration"] <= 4200, x["duration"])
    check("4 档：预算全面大于 3 档",
          all(x[k] > d[k] for k in ("duration", "max_shots", "global_event_cap",
                                    "max_events_per_hook", "repro_duration")),
          {k: (x[k], d[k]) for k in ("duration", "max_shots", "global_event_cap")})

    # ---------------------------------------------------------------- 套档
    c = ScanConfig()
    check("默认档位是常规", c.depth == "normal", c.depth)
    check("套深度档返回 deep", c.apply_depth("deep") == "deep", c.depth)
    check("套档后时长生效", c.duration == 900, c.duration)
    check("套档后单 hook 上限生效", c.max_events_per_hook == 40, c.max_events_per_hook)
    check("套档后总事件上限生效", c.global_event_cap == 12000, c.global_event_cap)
    check("套档后截图上限生效", c.max_shots == 60, c.max_shots)
    check("套档后复现轮时长也变长", c.repro_duration == 300, c.repro_duration)
    check("未知档位退回常规而不是抛错", c.apply_depth("ultra") == "normal", c.depth)
    check("未知档位不会静默留在深度", c.duration == 90, c.duration)

    # ---------------------------------------------------------------- 与表单时长的关系
    # 常规档：手填时长覆盖档位（临时想跑 5 分钟）
    c = ScanConfig()
    apply_depth_budget(c, "normal", 300)
    check("常规档：手填时长覆盖档位", c.duration == 300, c.duration)

    # 深度档：手填的 90 秒**不能**把 900 秒盖掉
    c = ScanConfig()
    apply_depth_budget(c, "deep", 90)
    check("深度档：不会被表单里的默认 90 秒盖掉", c.duration == 900, c.duration)
    check("深度档：截图上限仍是档位值", c.max_shots == 60, c.max_shots)

    # 不填时长：用配置文件里的值（而不是 0）
    c = ScanConfig()
    c.duration = 150
    apply_depth_budget(c, "normal", 0)
    check("常规档：不填时长时保留配置值", c.duration == 150, c.duration)

    # 日志要能看出到底按哪个档在跑
    lines = []
    c = ScanConfig()
    apply_depth_budget(c, "deep", 90, lambda m: lines.append(m))
    check("深度档：日志写明档位与关键预算",
          any("3 档" in x and "900" in x for x in lines), lines)
    check("深度档：日志写明可登录", any("登录" in x or "可登录" in x for x in lines)
          or any("3 档" in x for x in lines), lines)
    lines2 = []
    c = ScanConfig()
    apply_depth_budget(c, "normal", 120, lambda m: lines2.append(m))
    check("常规档：日志写明档位与时长",
          any("常规" in x and "120" in x for x in lines2), lines2)
    lines3 = []
    c = ScanConfig()
    apply_depth_budget(c, "light", 0, lambda m: lines3.append(m))
    check("2 档：日志写明不登录", any("不登录" in x or "不做登录" in x for x in lines3), lines3)
    check("2 档：日志写明层级上限", any("只到第 2 层" in x or "2 层" in x for x in lines3), lines3)
    lines4 = []
    c = ScanConfig()
    apply_depth_budget(c, "pre", 0, lambda m: lines4.append(m))
    check("1 档：日志写明不点同意", any("不点同意" in x for x in lines4), lines4)
    check("1 档：套档后 consent_only 生效", c.consent_only is True, c.consent_only)

    # ---------------------------------------------------------------- 平台/命令行入口
    from webapp.server import _norm_depth
    check("平台：合法档位原样通过", _norm_depth("deep") == "deep")
    check("平台：大小写与空格容错", _norm_depth(" DEEP ") == "deep", _norm_depth(" DEEP "))
    check("平台：空值退回常规", _norm_depth("") == "normal" and _norm_depth(None) == "normal")
    check("平台：四档都认", all(_norm_depth(k) == k
                                for k in ("pre", "light", "deep", "extreme")))
    check("平台：数字档位映射到中文档", _norm_depth("4") == "extreme", _norm_depth("4"))
    check("平台：未知值退回常规", _norm_depth("ultra") == "normal")

    src = (ROOT / "run_flow.py").read_text(encoding="utf-8")
    check("命令行：提供 --deep 开关", '"--deep"' in src)
    check("命令行：--deep 映射到深档", 'depth="deep" if args.deep else "normal"' in src)

    # ---------------------------------------------------------------- 截图上限按轮次
    # 模块常量是进程级的：两个任务并发时，后启动的会把前一个的上限改掉。
    from piiscan.collector import ScanResult
    s = ScanResult(package="com.demo.app")
    check("采集结果自带截图上限（默认 14）", s.max_shots == 14, s.max_shots)
    s2 = ScanResult(package="com.demo.app")
    s2.max_shots = 60
    check("两轮的上限互不影响", s.max_shots == 14 and s2.max_shots == 60,
          (s.max_shots, s2.max_shots))
    # 上限必须能进存档：离线重渲染时报告要知道"这一轮留了几张"
    check("截图上限写进存档", s.to_dict().get("max_shots") == 14)


if __name__ == "__main__":
    _ok = 0
    _bad = []

    def _check(name, cond, got=""):
        global _ok
        if cond:
            _ok += 1
        else:
            _bad.append("%s（实际：%r）" % (name, got))

    run(_check)
    print("通过 %d 项，失败 %d 项" % (_ok, len(_bad)))
    for b in _bad:
        print("  FAIL", b)
    sys.exit(1 if _bad else 0)
