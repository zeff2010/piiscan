"""遍历台账：谁点了什么，只在这里记一份。

## 为什么需要这个模块

2026-11-01 两个 1 小时档的真机任务，两个应用都出现了同一形态的退化：

    · 川剧迷（`J20261101110114-b45ec3`）496 步里
      同一屏的「檢舉」被点 206 次、同一屏下滑 204 次，界面数停在 43；
    · 冰纷万象（`J20261101110114-724d13`）496 步里
      同一屏的「Layout_area_code」被点 224 次、另一屏返回 225 次，界面数停在 16。

两者的形态完全一样：**A 屏点一下 → 进 B 屏 → B 屏退回 A → 再点同一个**。
每一步"界面都变了"，于是原有的空转熔断（它只看"界面指纹没变"）一次都没触发，
1 小时预算的 90% 花在两屏之间来回。

三个缺口，三处补：

1. **没有跨来源的台账。** 规则调度器自己记着"本屏点过哪些 uid"（
   `PageGraph.states[fp].uids_clicked`），但 AI/图排序那条路不查它 ——
   于是"谁选的"决定了"记不记得"，两边各记一套。本模块把执行层的事实集中
   记成一份账，**不管动作是模型选的、图排序选的还是规则选的**。

2. **熔断判据太窄。** `_note_act_result` 只在"界面指纹没变"时累加，
   对 A↔B 这种每步都换屏的振荡完全失明。`LoopWatch` 改看**动作序列的周期性**
   与**距上一个新界面的动作数**，这两条都与"单步是否变化"无关。

3. **没有完结判断。** 明明 40 分钟没有新界面，仍然跑满预算。`LoopWatch.stalled()`
   给出"再走也不会更多"的判据，采集层据此提前收工进下一阶段。

## 边界

纯逻辑，不碰设备、不读配置、不认识 UiNode。输入是界面指纹与元素 uid（
都来自 `flow/graph.py` 那一套身份），输出是"这个动作还能不能做 / 是不是僵局"。
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

# ---------------------------------------------------------------- 台账

# 同一界面上同一个元素最多执行几次。
#   1 次 = 首次探索；2 次 = 「回到上级后复查」—— 开关点完会不会变、再进一次
#   还弹不弹窗，这是取证重点，不能一刀切掉。
#   第 3 次开始就没有新信息了：同样的屏、同样的元素、同样的落点。
TAP_LIMIT = 2

# 返回/滑动这类"全局动作"在**同一界面**上的容忍度，与 collector 的
# STUCK_RUN_LIMIT 口径一致（那边管"连续无效"，这里管"总次数"）。
ACT_LIMIT = {"back": 4, "swipe:up": 5, "swipe:down": 5,
             "swipe:left": 4, "swipe:right": 4, "pull": 3}

# 振荡时冻结整个界面的时长（秒）。冻结只是"暂时别在这屏点"，不是永久拉黑 ——
# 长跑里过一会儿这屏可能因为别处的操作而出现新入口（例如登录后整页变了）。
FREEZE_SEC = 180.0


class ActionLedger:
    """执行台账：`(界面, 元素)` → 执行次数。

    只记**真的执行了**的动作（点击成功、返回发出、滑动手势发出）。被危险检查
    拦下的、没找到节点的都不记 —— 账目只能反映设备上真发生过的事。
    """

    def __init__(self, tap_limit: int = TAP_LIMIT,
                 freeze_sec: float = FREEZE_SEC) -> None:
        self.tap_limit = max(1, int(tap_limit))
        self.freeze_sec = max(0.0, float(freeze_sec))
        self.taps: Dict[Tuple[str, str], int] = {}
        self.acts: Dict[Tuple[str, str], int] = {}
        self.visits: Dict[str, int] = {}
        self.first_seen: Dict[str, int] = {}
        self.frozen_until: Dict[str, float] = {}
        self.blocked_taps = 0          # 被台账拦下的次数（写进报告）
        self.blocked_frozen = 0
        self.actions = 0

    # -- 观测 ---------------------------------------------------------
    def visit(self, fp: str, now: Optional[float] = None) -> bool:
        """登记"到了这一屏"，返回是否首次见到。"""
        if not fp:
            return False
        first = fp not in self.visits
        self.visits[fp] = self.visits.get(fp, 0) + 1
        if first:
            self.first_seen[fp] = self.actions
        return first

    def note_tap(self, fp: str, uid: str, label: str = "") -> int:
        """记一次**已执行**的点击，返回该元素在本屏的累计次数。"""
        self.actions += 1
        if not fp or not uid:
            return 0
        k = (fp, uid)
        n = self.taps.get(k, 0) + 1
        self.taps[k] = n
        return n

    def note_act(self, fp: str, sig: str) -> int:
        """记一次返回/滑动/上拉。`sig` 形如 `back` / `swipe:up` / `pull`。"""
        self.actions += 1
        if not fp or not sig:
            return 0
        k = (fp, sig)
        n = self.acts.get(k, 0) + 1
        self.acts[k] = n
        return n

    # -- 判据 ---------------------------------------------------------
    def tap_count(self, fp: str, uid: str) -> int:
        return int(self.taps.get((fp or "", uid or ""), 0) or 0)

    def act_count(self, fp: str, sig: str) -> int:
        return int(self.acts.get((fp or "", sig or ""), 0) or 0)

    def frozen(self, fp: str, now: Optional[float] = None) -> bool:
        t = self.frozen_until.get(fp or "", 0.0)
        if not t:
            return False
        return (now if now is not None else time.time()) < t

    def freeze(self, fp: str, ttl: Optional[float] = None,
               now: Optional[float] = None) -> bool:
        """冻结一个界面（振荡时用）。返回是否真的冻上了。"""
        if not fp:
            return False
        self.frozen_until[fp] = ((now if now is not None else time.time())
                                 + (self.freeze_sec if ttl is None else max(0.0, ttl)))
        return True

    def tap_blocked(self, fp: str, uid: str,
                    now: Optional[float] = None) -> str:
        """这个点击还能不能执行。返回原因（空串 = 可以）。

        ★ 纯查询，**不改任何计数**。同一个判据会在两处问：生成候选时过滤、
          执行前再拦一次；带副作用的话一次拦截会被记成两次，报告里的
          "拦下 N 次"就虚高了。要计数请显式调 `note_blocked()`。

        返回值是给人看的短语，会原样进日志与报告 —— 排查时"为什么没点这个"
        必须能回答，否则只能猜。
        """
        if not fp or not uid:
            return ""
        if self.frozen(fp, now):
            return "该界面刚判定为循环，暂停点击"
        n = self.tap_count(fp, uid)
        if n >= self.tap_limit:
            return "已点过 %d 次且无新界面" % n
        return ""

    def note_blocked(self, why: str = "") -> None:
        """记一次"真的被台账拦下"（执行前那道闸），用于报告与日志统计。"""
        if "暂停点击" in (why or ""):
            self.blocked_frozen += 1
        else:
            self.blocked_taps += 1

    def act_blocked(self, fp: str, sig: str) -> str:
        """返回/滑动在上限内吗。与点击分开算：封了返回不该连带封滑动。"""
        lim = ACT_LIMIT.get(sig or "")
        if not lim or not fp:
            return ""
        n = self.act_count(fp, sig)
        if n >= lim:
            return "本屏%s已执行 %d 次" % (sig, n)
        return ""

    # -- 统计 ---------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        repeat = sum(max(0, n - 1) for n in self.taps.values())
        return {
            "screens": len(self.visits),
            "taps": sum(self.taps.values()),
            "repeat_taps": repeat,
            "blocked_taps": self.blocked_taps,
            "blocked_frozen": self.blocked_frozen,
            "frozen_screens": len(self.frozen_until),
            "actions": self.actions,
            "tap_limit": self.tap_limit,
        }

    def summary_line(self) -> str:
        s = self.stats()
        if not s["taps"]:
            return "遍历台账：尚未产生点击"
        return ("遍历台账：界面 %d 个｜点击 %d 次（重复 %d 次）｜"
                "重复拦截 %d 次、循环冻结拦截 %d 次"
                % (s["screens"], s["taps"], s["repeat_taps"],
                   s["blocked_taps"], s["blocked_frozen"]))


# ---------------------------------------------------------------- 振荡

# 判"僵局"要求同时满足三个条件，缺一不可（只看一条会误杀）：
#   · 至少走了 SAT_MIN_ACTIONS 个动作 —— 刚开始的几屏本来就不会有新界面；
#   · 至少见过 SAT_MIN_STATES 个界面 —— 否则是"应用压根没起来"，那是另一个问题
#     （由运行有效性单独判定，不能在这里提前收工把"没测"写成"测完了"）；
#   · 距上一个新界面已经过了 SAT_ACTIONS 个动作。
SAT_ACTIONS = 30
SAT_MIN_ACTIONS = 45
SAT_MIN_STATES = 6

# 振荡检测窗口最多认几拍。2 拍覆盖 A↔B，3 拍覆盖 A→B→C→A 的三角循环，
# 再长就不是循环而是正常的走走看看了。
PERIOD_MAX = 3


class LoopWatch:
    """循环观测：从**动作序列**判断"还在前进"还是"原地打转"。

    与 `ActionLedger` 分工清楚：台账管"这个元素还能不能再点"（局部），
    `LoopWatch` 管"整条路是不是绕回去了"（全局）。两个都要有 ——
    只封单个元素防不住"换个元素继续绕"，只判全局循环又太晚。
    """

    def __init__(self, period_max: int = PERIOD_MAX,
                 sat_actions: int = SAT_ACTIONS,
                 min_actions: int = SAT_MIN_ACTIONS,
                 min_states: int = SAT_MIN_STATES) -> None:
        self.period_max = max(2, int(period_max))
        self.sat_actions = max(4, int(sat_actions))
        self.min_actions = max(0, int(min_actions))
        self.min_states = max(0, int(min_states))
        self.sigs: Deque[Tuple[str, str, str]] = deque(maxlen=64)
        self.actions = 0
        self.last_novel = 0            # 上一个**新界面**出现时的动作序号
        self.states: set = set()
        self.osc_hits = 0
        self.stall_hits = 0

    # -- 观测 ---------------------------------------------------------
    def note_state(self, fp: str) -> bool:
        """登记当前界面，返回是否首次见到（首次见 = 有进展）。"""
        if not fp:
            return False
        if fp in self.states:
            return False
        self.states.add(fp)
        self.last_novel = self.actions
        return True

    def note(self, fp: str, kind: str, uid: str = "") -> None:
        """记一步动作。签名里必须带**界面**：同一个「返回」在不同屏上意义不同。"""
        self.actions += 1
        self.sigs.append((fp or "", kind or "", uid or ""))

    def reset_window(self) -> None:
        """重启/换屏复位后清掉序列窗口。

        只清窗口，不清计数：`last_novel` 要保留 —— 重启本身不算进展，
        否则每次死循环重启都会被当成"又走了新界面"，僵局永远判不出来。
        """
        self.sigs.clear()

    # -- 判据 ---------------------------------------------------------
    def period(self) -> int:
        """当前是否处于周期振荡，返回周期（0 = 没有）。

        判据：最近 2k 步与再往前 k 步**逐项相同**（界面、动作、元素都一样），
        且这 2k 步里出现的界面不超过 k+1 个。
        后一条是关键：`点A→返回→点B→返回` 也满足"步数多"，但 A、B 不同，
        那是正常的逐个复查，不是死循环。
        """
        t = list(self.sigs)
        gap = self.actions - self.last_novel
        for k in range(2, self.period_max + 1):
            if len(t) < 2 * k or gap < 2 * k:
                continue
            if t[-k:] != t[-2 * k:-k]:
                continue
            if len({s[0] for s in t[-2 * k:]}) <= k + 1:
                return k
        return 0

    def stalled(self) -> bool:
        """是否已经"再走也不会更多"（完结判据）。"""
        if self.actions < self.min_actions:
            return False
        if len(self.states) < self.min_states:
            return False
        return (self.actions - self.last_novel) >= self.sat_actions

    def novel_gap(self) -> int:
        return max(0, self.actions - self.last_novel)

    def stats(self) -> Dict[str, Any]:
        return {
            "actions": self.actions,
            "states": len(self.states),
            "novel_gap": self.novel_gap(),
            "osc_hits": self.osc_hits,
            "stall_hits": self.stall_hits,
        }

    def summary_line(self) -> str:
        return ("进度观测：动作 %d 步｜界面 %d 个｜距上一个新界面已 %d 步｜"
                "振荡 %d 次、僵局 %d 次"
                % (self.actions, len(self.states), self.novel_gap(),
                   self.osc_hits, self.stall_hits))


# ---------------------------------------------------------------- 判定入口

def judge_walk(period: int, stalled: bool, sat_hint: str = "") -> Dict[str, Any]:
    """把两条判据合成一个结论，供采集层统一处理。

    顺序不能反：先看振荡（还能救，换条路继续），再看僵局（救不回来了，收工）。
    反过来的话，一个正在振荡的任务会被直接判成"已完结"，把还能跑的预算扔掉。
    """
    if period:
        return {"verdict": "oscillate", "period": period,
                "why": "最近 %d 步与再往前 %d 步完全重复" % (2 * period, period)}
    if stalled:
        return {"verdict": "stalled", "period": 0,
                "why": sat_hint or "连续多个动作没有发现新界面"}
    return {"verdict": "", "period": 0, "why": ""}
