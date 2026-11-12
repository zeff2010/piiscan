"""遍历空转熔断（2026-11-01）。

背景：4 档（1 小时）跑完与 15 分钟档没有本质区别。逐条查存档发现原因不在
"时长不够"，而在"时间全花在同一屏的重复动作上"：

  · 看个比赛 com.kgbs.ticket（4526 秒）：387 步里 297 步是「返回上一级」、
    67 步是滑动，真正点击只有 9 次；
  · 冰纷万象（1851 秒）：191 步里 176 步是「向 up 滑动」，点击 4 次。

两条成因：①同一界面上同一个动作反复执行却从不判定"无效"（原来的 stuck
只统计点击，返回与滑动一次都没计入）；②节点级节流只在"上次点了东西"时
才生效，模型连续答 back 就变成每步都问、每步都答 back。

本文件只测纯函数部分（`_note_act_result` / `_act_blocked`），它们的判决
直接决定采集侧封不封动作，判错了等于把遍历锁死或放任它空转。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def run(check) -> None:
    from piiscan import collector as C

    # 源码级守护要用：有些行为（遍历主循环里的处置阶梯）需要真实设备才能跑到，
    # 离线只能确认"这几条分支还在"，防止后续重构把它们整段删掉。
    _src = Path(C.__file__).read_text(encoding="utf-8")

    # ---------------------------------------------------------------- 返回键
    run_, ban = {}, set()
    got = []
    for _ in range(3):
        got.append(C._note_act_result(False, "back", run_, ban))
    check("连续 3 次返回都没换屏 → 第 3 次封禁返回",
          got[:2] == [None, None] and got[2] == "back", got)
    check("封禁后返回被拦", C._act_blocked("back", ban) is True)
    # 封了返回不该连带封滑动：那会让遍历彻底停在原地，比原来的死循环更糟。
    check("封返回不影响滑动", C._act_blocked("swipe:up", ban) is False)

    # 界面一变，之前的"无效"结论只对旧界面成立，必须整体作废。
    C._note_act_result(True, "", run_, ban)
    check("界面变化后解封返回", C._act_blocked("back", ban) is False)
    check("界面变化后计数清零", run_ == {}, run_)

    # ---------------------------------------------------------------- 滑动
    run2, ban2 = {}, set()
    for _ in range(3):
        C._note_act_result(False, "swipe:up", run2, ban2)
    check("滑动 3 次还不封（长列表要滚很多次才到底）",
          C._act_blocked("swipe:up", ban2) is False, sorted(ban2))
    C._note_act_result(False, "swipe:up", run2, ban2)
    check("同向滑动 4 次 → 封该方向", C._act_blocked("swipe:up", ban2) is True)
    check("只封该方向，反方向仍可用", C._act_blocked("swipe:down", ban2) is False)

    # 换方向要重新计数，不能沿用上一个方向的次数
    run3, ban3 = {}, set()
    for _ in range(3):
        C._note_act_result(False, "swipe:up", run3, ban3)
    C._note_act_result(False, "swipe:down", run3, ban3)
    check("换方向后按新方向重新计数",
          run3.get("swipe:down") == 1 and C._act_blocked("swipe:down", ban3) is False,
          run3)

    # ---------------------------------------------------------------- 上拉
    run4, ban4 = {}, set()
    C._note_act_result(False, "pull", run4, ban4)
    check("上拉 1 次不封（可能还在加载）", C._act_blocked("pull", ban4) is False)
    C._note_act_result(False, "pull", run4, ban4)
    check("上拉 2 次仍无新内容 → 封（没有下一页）",
          C._act_blocked("pull", ban4) is True)

    # ---------------------------------------------------------------- 点击
    run5, ban5 = {}, set()
    for _ in range(10):
        C._note_act_result(False, "tap", run5, ban5)
    check("点击不由本函数封禁（另有 stuck 判据要清悬浮窗）",
          C._act_blocked("tap", ban5) is False, sorted(ban5))
    check("点击仍计入本屏空转总量", run5.get("__total__") == 10, run5)

    # ---------------------------------------------------------------- 总量
    run6, ban6 = {}, set()
    for _ in range(C.STUCK_TOTAL_LIMIT):
        C._note_act_result(False, "swipe:left" if _ % 2 else "swipe:right", run6, ban6)
    check("本屏空转总量按动作累加",
          run6.get("__total__") == C.STUCK_TOTAL_LIMIT, run6)

    # 空动作不该污染计数（有些分支只是 sleep 后 continue，没有真实动作）
    run7, ban7 = {}, set()
    C._note_act_result(False, "", run7, ban7)
    check("空动作不计数", run7 == {}, run7)

    # ---------------------------------------------------------------- 阈值自检
    check("返回的容忍度低于滑动（返回有效必换屏）",
          C.STUCK_RUN_LIMIT["back"] < C.STUCK_RUN_LIMIT["swipe:up"],
          (C.STUCK_RUN_LIMIT["back"], C.STUCK_RUN_LIMIT["swipe:up"]))
    check("上拉的容忍度最低（只该触发一次）",
          C.STUCK_RUN_LIMIT["pull"] <= min(C.STUCK_RUN_LIMIT.values()),
          C.STUCK_RUN_LIMIT)
    check("本屏榨干阈值大于任一动作阈值",
          C.STUCK_TOTAL_LIMIT > max(C.STUCK_RUN_LIMIT.values()),
          C.STUCK_TOTAL_LIMIT)
    check("每个被封的动作都有中文名（写进报告时不能出现英文键名）",
          all(k in C.ACT_LABEL for k in C.STUCK_RUN_LIMIT),
          [k for k in C.STUCK_RUN_LIMIT if k not in C.ACT_LABEL])

    # ------------------------------------------- 读不到界面结构时的处置阶梯
    # 2026-11-02 川剧迷：点到搜索页后连续 63 次导不出结构树，每轮 49 秒，
    # 第 51~111 轮烧掉 2954 秒（49 分钟）一个动作没做，最后写成"时间预算耗尽"。
    # 这里钉死三档阈值与顺序：收键盘 → 重启应用 → 判死收工。
    check("自愈阈值是递增的三档",
          C._DUMP_BLUR_AT < C._DUMP_RESET_AT < C._DUMP_GIVEUP,
          (C._DUMP_BLUR_AT, C._DUMP_RESET_AT, C._DUMP_GIVEUP))
    check("三档自愈都要能落到代码里（源码级守护，防止被误删）",
          all(tok in _src for tok in
              ("_DUMP_BLUR_AT", "_DUMP_RESET_AT", "_DUMP_GIVEUP",
               "ui_walk_blur")),
          "缺少自愈分支")
    check("判死时必须写 stop_reason 说明未覆盖原因",
          "不代表应用没有该功能" in _src, "缺少停止原因")
    check("收键盘用 ESC（keyevent 111），不能用 BACK 退栈",
          "input keyevent 111" in _src, "未找到 ESC 键码")

    # ---------------------------------------------------- 事件静默（应用无响应）
    # 川剧迷：点进 SearchActivity 之后 3154 秒 0 条事件、0 次界面变化、
    # 63 次 dump 失败。报告只写"有 63 次导出失败"，读者会以为采集器不行，
    # 实际是被测应用在那之后就没有再响应过。这条判据必须算对。
    import time as _t

    class _R:
        pass

    r = _R()
    r.events = [{"ts": (_t.time() - 120) * 1000}]      # 毫秒时间戳
    gap = C._event_silence(r)
    check("事件静默按毫秒时间戳算", 118 <= gap <= 124, round(gap, 1))
    r.events = [{"ts": _t.time() - 30}]                # 秒级时间戳
    gap = C._event_silence(r)
    check("事件静默也认秒级时间戳", 28 <= gap <= 33, round(gap, 1))
    r.events = []
    check("没有事件时返回 0（不能凭空算出一个巨大的静默期）",
          C._event_silence(r) == 0.0, C._event_silence(r))


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
