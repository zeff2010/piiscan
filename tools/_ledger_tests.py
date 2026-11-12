"""遍历台账与循环判定（2026-11-01）。

背景：两个 1 小时档真机任务（川剧迷 / 冰纷万象）都在做无用功，形态完全一样 ——
**A 屏点一下 → 进 B 屏 → B 屏退回 A → 再点同一个**：

  · 川剧迷 496 步：同一屏「檢舉」206 次、同一屏下滑 204 次，界面数停在 43；
  · 冰纷万象 496 步：同一屏「Layout_area_code」224 次、另一屏返回 225 次，停在 16。

每一步"界面都变了"，所以原来只看"界面指纹没变"的空转熔断一次都没触发。
本文件测的是替代判据：`ActionLedger`（同一元素能点几次）与
`LoopWatch`（动作序列是否周期重复 / 是否还有新界面）。

判错两个方向的代价都不小：
  · 太松 → 又是 1 小时原地打转；
  · 太严 → 正常的多步复查被当成死循环，把还没走的界面提前掐掉。
所以正反两类用例都要有。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def run(check) -> None:
    from piiscan.flow import ledger as L

    # ------------------------------------------------------------ 台账：点击
    led = L.ActionLedger(tap_limit=2)
    led.visit("A")
    check("首次点击前不拦", led.tap_blocked("A", "id:btn") == "")
    led.note_tap("A", "id:btn")          # 第 1 次
    check("点 1 次后仍可再点（复查入口要留一次机会）",
          led.tap_blocked("A", "id:btn") == "")
    led.note_tap("A", "id:btn")          # 第 2 次
    check("★ 同一屏同一元素点满 2 次后拦下",
          "已点过 2 次" in led.tap_blocked("A", "id:btn"), led.tap_blocked("A", "id:btn"))
    check("换个界面同一元素不受影响（不同屏是不同上下文）",
          led.tap_blocked("B", "id:btn") == "")
    check("同屏别的元素不受影响", led.tap_blocked("A", "id:other") == "")

    # 纯查询不能有副作用：同一个判据要问两次（过滤候选 + 执行前再拦），
    # 带副作用会把"拦 1 次"记成"拦 2 次"，报告数字虚高。
    before = dict(led.stats())
    for _ in range(5):
        led.tap_blocked("A", "id:btn")
    check("tap_blocked 是纯查询（不计数）", led.stats() == before,
          (before, led.stats()))

    led.note_blocked("已点过 2 次且无新界面")
    check("note_blocked 计数", led.stats()["blocked_taps"] == 1, led.stats())

    # ------------------------------------------------------------ 台账：冻结
    led2 = L.ActionLedger(tap_limit=2)
    led2.visit("A")
    check("冻结前可点", led2.tap_blocked("A", "id:x") == "")
    led2.freeze("A", ttl=60, now=1000.0)
    check("★ 冻结中的界面一律不点",
          "循环" in led2.tap_blocked("A", "id:x", now=1001.0))
    check("冻结到期后恢复", led2.tap_blocked("A", "id:x", now=1100.0) == "")

    # ------------------------------------------------------------ 台账：返回
    led3 = L.ActionLedger()
    for _ in range(4):
        led3.note_act("A", "back")
    check("★ 同一屏返回 4 次后封禁（冰纷万象同屏返回 225 次的防线）",
          led3.act_blocked("A", "back") != "", led3.act_blocked("A", "back"))
    check("封返回不连带封滑动", led3.act_blocked("A", "swipe:up") == "")
    check("换屏后返回额度重置", led3.act_blocked("B", "back") == "")

    # ------------------------------------------------------------ 循环观测
    # 真机形态：A 屏点「檢舉」↔ B 屏下滑
    w = L.LoopWatch()
    w.note_state("A")
    for i in range(6):
        w.note("A", "tap", "lb:檢舉")
        w.note("B", "swipe:down", "")
        w.note_state("B")               # 同一屏反复到达，不算新进展
        w.note_state("A")
    check("★ 两屏来回 6 轮 → 判定为周期 2 的循环", w.period() == 2, w.period())

    # 反例：正常的"逐个条目进详情再返回"。元素不同 → 不是循环。
    w2 = L.LoopWatch()
    w2.note_state("LIST")
    for i in range(5):
        w2.note("LIST", "tap", "id:item_%d" % i)
        w2.note("DETAIL_%d" % i, "back", "")
        w2.note_state("DETAIL_%d" % i)
        w2.note_state("LIST")
    check("★ 逐个条目进详情（元素不同）不算循环", w2.period() == 0, w2.period())

    # 反例：A→B→C→A 三角也认，但四拍以上不认（那是走走看看）
    w3 = L.LoopWatch()
    for _ in range(3):
        w3.note("A", "tap", "u1")
        w3.note("B", "tap", "u2")
        w3.note("C", "back", "")
    check("★ 三拍循环能识别", w3.period() == 3, w3.period())

    # ------------------------------------------------------------ 饱和判定
    w4 = L.LoopWatch(sat_actions=10, min_actions=5, min_states=2)
    w4.note_state("A")
    w4.note_state("B")
    check("刚起步不判饱和（还没走够动作）", w4.stalled() is False)
    for i in range(11):
        w4.note("A", "tap", "id:unique_%d" % i)   # 元素各不相同，不构成周期循环
    check("★ 11 个动作没有新界面 → 判定饱和", w4.stalled() is True, w4.stats())
    w4.note_state("C")                            # 又走了新界面 → 重新计时
    check("出现新界面后饱和判定解除", w4.stalled() is False, w4.stats())

    # 界面太少时绝不判饱和：那是"应用没起来"，属运行有效性问题，
    # 在这里提前收工会把"没测"写成"测完了"（最严重的一类假结论）。
    w5 = L.LoopWatch(sat_actions=10, min_actions=0, min_states=6)
    w5.note_state("A")
    for i in range(40):
        w5.note("A", "tap", "id:u%d" % i)
    check("★ 只见过 1 个界面时不判饱和", w5.stalled() is False, w5.stats())

    # ------------------------------------------------------------ 结论合并
    check("振荡优先于饱和（还能救，先换路）",
          L.judge_walk(2, True)["verdict"] == "oscillate")
    check("没有振荡才看饱和", L.judge_walk(0, True)["verdict"] == "stalled")
    check("都没有则不介入", L.judge_walk(0, False)["verdict"] == "")

    # ------------------------------------------------------------ 真机路径复盘
    # 用两条真实 `ui_path` 回放：新判据应在**很前面**就识别出循环，
    # 而不是等 496 步走完。这是本改动唯一能离线证明的部分。
    _replay_real_paths(check)

    # ------------------------------------------------------------ AI 目标对齐
    _match_real_node(check)

    # ------------------------------------------------------------ 接线契约
    # 台账要在"真正下手"之前拦，而且 AI 的两条候选来源（图选项、自由规划）
    # 都要过它。这三处任何一处被后来的改动挪走，重复点击就会从这里漏回来 ——
    # 而漏回来的表现只是"又跑满了一小时"，不会报错。
    src = (Path(__file__).resolve().parent.parent
           / "piiscan" / "collector.py").read_text(encoding="utf-8")
    i_gate = src.find("台账闸门：这个元素在这屏已经点过够多次了")
    i_tap = src.rfind("if uiwalk.tap(res.device_serial, x, y):")
    check("★ 台账闸门在点击执行之前", 0 < i_gate < i_tap, (i_gate, i_tap))
    check("★ AI 图选项过了台账", "ledger.tap_blocked(obs.current" in src)
    check("★ AI 自由规划的候选过了台账", "free_cands = [n for n in all_cands" in src)
    check("★ 同一元素的身份由 match_real_node 对齐",
          "uiwalk.match_real_node(clicks_all, node)" in src)


def _replay_real_paths(check) -> None:
    """把真机 ui_path 喂给 LoopWatch，看多久能识别出循环。"""
    import json
    from piiscan.flow import ledger as L
    root = Path(__file__).resolve().parent.parent / "out" / "platform"
    cases = [("川剧迷", "J20261101110114-b45ec3"),
             ("冰纷万象", "J20261101110114-724d13")]
    found = 0
    for name, jid in cases:
        p = root / jid / "scan.result.json"
        if not p.exists():
            continue
        found += 1
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        path = d.get("ui_path") or []
        w = L.LoopWatch()
        seen_states = set()
        hit = 0
        for it in path:
            fp = it.get("fp") or ""
            if fp and fp not in seen_states:
                seen_states.add(fp)
                w.note_state(fp)
            kind = it.get("kind") or ""
            uid = (it.get("label") or "") if kind == "tap" else ""
            w.note(fp, kind, uid)
            if not hit and w.period():
                hit = w.actions
                break
        check("★ 真机路径「%s」第 %d 步就识别出循环（全长 %d 步）"
              % (name, hit or -1, len(path)),
              bool(hit) and hit < len(path) * 0.5, hit)


def _match_real_node(check) -> None:
    """AI 给的目标要能对齐回结构树里的真实节点。"""
    from piiscan import uiwalk

    class N:
        def __init__(self, text, bounds, rid=""):
            self.text = text
            self.content_desc = ""
            self.bounds = bounds
            self.resource_id = rid
            self.cls = "android.widget.Button"
            self.clickable = True

        @property
        def center(self):
            x1, y1, x2, y2 = self.bounds
            return (x1 + x2) // 2, (y1 + y2) // 2

    real = [N("檢舉", (100, 2000, 300, 2080), "com.app:id/report"),
            N("返回", (20, 80, 120, 160), "com.app:id/back")]
    # AI 只给了坐标，本地包出来的对象没有 resource-id
    synth = N("AI 目标", (110, 2010, 290, 2070))
    got = uiwalk.match_real_node(real, synth)
    check("★ AI 的坐标目标对齐回真实节点（拿到正式 uid）",
          got is not None and got.resource_id == "com.app:id/report",
          getattr(got, "resource_id", None))

    # 坐标对不上时退回文字全等
    synth2 = N("返回", (0, 0, 10, 10))
    got2 = uiwalk.match_real_node(real, synth2)
    check("坐标不中时按文字对齐", got2 is not None and got2.resource_id == "com.app:id/back",
          getattr(got2, "resource_id", None))

    # 不能模糊匹配：把「同意」对到「不同意」上会直接点错
    synth3 = N("同意", (0, 0, 10, 10))
    check("不把「同意」模糊匹配成别的按钮",
          uiwalk.match_real_node(real, synth3) is None)
