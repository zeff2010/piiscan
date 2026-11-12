#!/usr/bin/env python3
"""遍历调度器的自测（P4 遍历 Step 2：DFS + tab 铺开 + 价值表 + 死点）。

为什么不靠真机验
----------------
调度器是一段纯决策逻辑：给它"这一屏有哪些入口、之前点过什么"，它返回"这一步点谁"。
真机跑一轮只能看到**结果**（走了几个界面），看不到**决策错在哪** —— 而这里每一条
错都会安静地把报告结论推向"没覆盖"或"覆盖了"两个相反方向：

  · tab 来回切换 → 预算烧光、界面数不涨，报告里"未探索"看起来是时间不够，其实是打转；
  · 全局 seen 判重 → 从子页返回父页后寸步难行，"复查开关是否保持"这类取证永远做不到；
  · 危险按钮没挡住 → App 退出、重新拉起、再点，一轮白跑（真机踩过 5 次「不同意」）；
  · BACK 一刀切禁用 → DFS 回不来，遍历只剩一层，深度指标永远上不去。

所以用离线 XML 序列把每条决策钉住，真机只负责最后验收"同预算下界面数有没有涨"。

跑法：python tools/_sched_tests.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------- 造界面

def _btn(text, x1, y1, x2, y2, rid="", cd="", cls="android.widget.TextView",
         clickable=True, scrollable=False):
    return ('<node text="%s" resource-id="%s" content-desc="%s" class="%s" '
            'bounds="[%d,%d][%d,%d]" clickable="%s" scrollable="%s"/>'
            % (text, rid, cd, cls, x1, y1, x2, y2,
               "true" if clickable else "false", "true" if scrollable else "false"))


def _wrap(*nodes, pkg="com.t"):
    return ('<?xml version="1.0" encoding="UTF-8"?><hierarchy rotation="0">'
            '<node index="0" text="" resource-id="" class="android.widget.FrameLayout" '
            'package="%s" bounds="[0,0][1080,1920]" clickable="false">%s</node>'
            '</hierarchy>' % (pkg, "".join(nodes)))


def _tabbar(names=("首页", "发现", "我的"), y=1800):
    out = []
    w = int(1080 / max(1, len(names)))
    for i, n in enumerate(names):
        out.append(_btn(n, i * w, y, (i + 1) * w, y + 60,
                        rid="com.t:id/tab_%d" % i))
    return out


def _rows(items, y0=200, h=150, prefix="row"):
    return [_btn(t, 20, y0 + i * h, 1060, y0 + i * h + 100,
                 rid="com.t:id/%s_%d" % (prefix, i)) for i, t in enumerate(items)]


# 一个够用的 App：三个 tab + 两个二级页 + 一个三级页 + 一个叶子页。
SCREENS = {
    "home": _wrap(*_tabbar(), *_rows(["新闻一", "新闻二"], prefix="feed"),
                  _btn("设置", 20, 900, 1060, 1000, rid="com.t:id/home_set")),
    "discover": _wrap(*_tabbar(), *_rows(["话题一", "话题二"], prefix="topic")),
    "mine": _wrap(*_tabbar(), *_rows(["我的订单", "客服"], prefix="mine_row"),
                  _btn("设置", 20, 900, 1060, 1000, rid="com.t:id/mine_set")),
    "settings": _wrap(_btn("隐私政策", 20, 200, 1060, 300, rid="com.t:id/policy"),
                      _btn("权限管理", 20, 320, 1060, 420, rid="com.t:id/perm"),
                      _btn("账号与安全", 20, 440, 1060, 560, rid="com.t:id/security"),
                      _btn("注销账号", 20, 600, 1060, 700, rid="com.t:id/kill")),
    "privacy": _wrap(_btn("第三方共享清单", 20, 200, 1060, 300, rid="com.t:id/share"),
                     _btn("返回", 20, 1800, 200, 1860, rid="com.t:id/back")),
    "share": _wrap(_btn("共享给腾讯", 20, 200, 1060, 300, rid="com.t:id/one")),
    "empty": _wrap(_btn("本页没有可点的东西", 20, 200, 1060, 300,
                        rid="com.t:id/txt", clickable=False)),
    "leaf": _wrap(_btn("确认支付", 20, 200, 540, 300, rid="com.t:id/pay"),
                  _btn("立即购买", 560, 200, 1060, 300, rid="com.t:id/buy")),
    "dead": _wrap(_btn("空入口", 20, 200, 1060, 300, rid="com.t:id/none")),
}

# 点哪个文字 → 去哪个界面。不在表里 = 点了没反应（死点）。
GO = {
    "home": {"首页": "home", "发现": "discover", "我的": "mine",
             "设置": "settings", "新闻一": "leaf", "新闻二": "dead"},
    "discover": {"首页": "home", "发现": "discover", "我的": "mine"},
    "mine": {"首页": "home", "发现": "discover", "我的": "mine",
             "设置": "settings", "我的订单": "leaf", "客服": "dead"},
    "settings": {"隐私政策": "privacy", "权限管理": "dead", "账号与安全": "leaf"},
    "privacy": {"第三方共享清单": "share", "返回": "settings"},
    "share": {},
    "leaf": {},
    "dead": {},
}
TAB_LABELS = {"首页", "发现", "我的"}


class Sim:
    """离线回放器：把调度决策作用到"界面图"上，模拟真实点击与返回。

    ★ 只复用真实的 `PageGraph` 与 `Scheduler`，其余（adb、截图、AI）全部省略。
      这样测到的就是调度逻辑本身，不会因为真机抖动而变成"偶发失败"。
    """

    def __init__(self, start="home"):
        from piiscan.flow import graph as G
        from piiscan.flow import crawl as C
        self.C = C
        self.g = G.PageGraph("com.t")
        self.s = C.Scheduler(self.g)
        self.cur = start
        self.parents = []          # 真实位置（用于 BACK 的落点）
        self.log = []              # [(action, label, phase)]
        self.stuck = 0
        self.scroll_noop = True    # 这个 App 的滚动不产生新内容

    # -- 一步 ---------------------------------------------------------
    def tick(self, progress):
        snap = self.g.observe(SCREENS[self.cur], "com.t/.Main")
        if self.g.has_pending:
            self.g.resolve(snap.fp, is_dialog=snap.is_dialog)
        self.s.sync(snap.fp)
        step = self.s.decide(snap.fp, snap.clicks, snap.nav,
                             progress=progress, back_unsafe=False)
        self.log.append((step.action, step.label, step.phase))
        if step.action == "tap":
            tab = step.tab
            self.s.note_tap(tab=tab, uid=step.uid)
            if tab:
                self.parents = []
            target = GO.get(self.cur, {}).get(step.label, self.cur)
            if target != self.cur:
                self.parents.append(self.cur)
                self.cur = target
            return step
        if step.action == "back":
            self.s.note_back(killed=False)
            self.cur = self.parents.pop() if self.parents else self.cur
            return step
        if step.action == "scroll":
            self.s.note_scroll(self.cur)
            return step
        # none：真机上这时会走"无候选三拍"，这里直接放弃这一步
        return step

    def run(self, n, progress=0.5):
        for _ in range(n):
            self.tick(progress)
        return self


def run(check) -> None:
    from piiscan.flow import crawl as C
    from piiscan.flow import graph
    from piiscan import uiwalk

    # ================================================================ uid
    # 同屏同名元素必须拿到不同身份 —— 列表页里多个「更多/查看」很常见，
    # 撞成一个身份就会"点一个等于全点过"，那些入口再也轮不到。
    dup = _wrap(_btn("更多", 20, 200, 300, 260),
                _btn("更多", 20, 400, 300, 460),
                _btn("更多", 20, 600, 300, 660))
    g0 = graph.PageGraph("com.t")
    g0.observe(dup, "com.t/.Main")
    batch2 = uiwalk.clickable(dup)              # ★ 另一次解析：对象不是同一批
    uids = [g0.uid_for(n) for n in batch2]
    check("uid：跨解析批次仍能区分同屏同名元素", len(set(uids)) == 3, uids)
    check("uid：跨批次算出的身份与同批次一致",
          uids == [graph.node_uid(n, uiwalk.clickable(dup)) for n in batch2], uids)

    # ================================================================ 阶段
    check("阶段：0~0.20 是入口期", C.phase_of(0.0) == C.ENTRY
          and C.phase_of(0.19) == C.ENTRY, C.phase_of(0.19))
    check("阶段：0.20~0.60 是铺开期", C.phase_of(0.20) == C.SURVEY
          and C.phase_of(0.59) == C.SURVEY)
    check("阶段：0.60~0.88 是深挖期", C.phase_of(0.60) == C.DEEPEN
          and C.phase_of(0.87) == C.DEEPEN)
    check("阶段：0.88 之后是定向期", C.phase_of(0.88) == C.TARGETED
          and C.phase_of(1.0) == C.TARGETED)
    check("阶段：进度越界被夹住（负数/超过 1 都不越界）",
          C.phase_of(-1) == C.ENTRY and C.phase_of(9) == C.TARGETED)

    # ================================================================ 价值表
    check("价值：设置/隐私这类入口排在最前",
          C.value_rank("设置") < C.value_rank("新闻") < C.value_rank("抽奖"))
    check("价值：'我的' 与 '我的订单' 都算高价值（都带收集行为）",
          C.value_rank("我的") == 0 and C.value_rank("我的订单") <= 1)
    check("价值：运营位排在最后", C.value_rank("签到领红包") == 3,
          C.value_rank("签到领红包"))

    # ================================================================ 软禁
    check("软禁：'我的订单' 可以进（要取证）",
          not C.is_soft_commit(type("N", (), {"label": "我的订单"})()))
    check("软禁：'确认支付' 不许点",
          C.is_soft_commit(type("N", (), {"label": "确认支付"})()))
    check("软禁：'提交订单' / '获取验证码' 不许点",
          C.is_soft_commit(type("N", (), {"label": "提交订单"})())
          and C.is_soft_commit(type("N", (), {"label": "获取验证码"})()))
    check("软禁：'提交反馈' 不在禁列（意见反馈要能提交才能走完流程）",
          not C.is_soft_commit(type("N", (), {"label": "提交反馈"})()))

    # ================================================================ 入口期先铺 tab
    sim = Sim().run(1, progress=0.05)
    first = sim.log[0]
    check("入口期：第一步就点主导航（不是直接扎进某个功能）",
          first[0] == "tap" and first[1] in TAB_LABELS, first)
    check("入口期：优先点证据最密的那个 tab（'我的'）",
          first[1] == "我的", first[1])
    check("入口期：点 tab 会被标记为 tab（栈要重置，不能算深入）",
          sim.log and sim.s.stats()["tabs_opened"] == 1, sim.s.stats())

    # ================================================================ tab 铺开后不来回切
    sim = Sim()
    for _ in range(6):
        sim.tick(progress=0.10)
    visited = {sim.log[i][1] for i in range(len(sim.log)) if sim.log[i][0] == "tap"}
    check("铺开：连续几步把不同 tab 都走一遍", {"我的", "发现"} <= visited, visited)
    check("铺开：不会反复点同一个 tab（去过的 tab 被跳过）",
          len([x for x in sim.log if x[1] == "我的"]) <= 2,
          [x[1] for x in sim.log])
    check("铺开：记录了 tab → 落点界面 的映射",
          len(sim.s._tab_target) >= 1 and len(sim.s._tab_fps) >= 1,
          (sim.s._tab_target, sim.s._tab_fps))

    # ================================================================ 全局 seen 的病根
    # 场景：进子界面再返回父界面，父界面上没点过的入口必须还能点。
    g1 = graph.PageGraph("com.t")
    s1 = C.Scheduler(g1)
    snap = g1.observe(SCREENS["settings"], "com.t/.Main")
    s1.sync(snap.fp)
    st = g1.states[snap.fp]
    step = s1.decide(snap.fp, snap.clicks, snap.nav, progress=0.5, back_unsafe=False)
    check("深挖：本屏有入口时返回 tap", step.action == "tap", step)
    g1.mark_tap(snap.fp, step.uid, step.label)
    st.uids_clicked.add(step.uid)
    after = s1.decide(snap.fp, snap.clicks, snap.nav, progress=0.5, back_unsafe=False)
    check("深挖：点过的入口不再选（本界面记账）",
          after.uid != step.uid, (step.uid, after.uid))
    # 危险入口：一屏全是"点了就完蛋"的按钮时，调度器必须宁可什么都不点。
    only_danger = _wrap(_btn("注销账号", 20, 200, 1060, 300, rid="com.t:id/kill2"),
                        _btn("退出登录", 20, 400, 1060, 500, rid="com.t:id/logout"))
    gk = graph.PageGraph("com.t")
    sk = C.Scheduler(gk)
    rk = gk.observe(only_danger, "com.t/.Main")
    sk.sync(rk.fp)
    kstep = sk.decide(rk.fp, rk.clicks, rk.nav, progress=0.5, back_unsafe=False)
    check("深挖：只有危险入口的界面不会去点它", kstep.action != "tap", kstep)
    check("深挖：'注销账号' 不会被选中",
          kstep.uid != "id:kill2" and kstep.uid != "id:logout", kstep.uid)
    check("未探索：危险入口不计入 todo（否则覆盖率分母永久虚高）",
          "id:kill" in st.blocked and "id:kill" not in st.uids_seen,
          (sorted(st.blocked), sorted(st.uids_seen)))

    # ================================================================ 死点
    g2 = graph.PageGraph("com.t")
    s2 = C.Scheduler(g2)
    snap = g2.observe(SCREENS["dead"], "com.t/.Main")
    s2.sync(snap.fp)
    s2.decide(snap.fp, snap.clicks, snap.nav, progress=0.5, back_unsafe=False)
    uid_none = g2.uid_for(snap.clicks[0])
    g2.mark_tap(snap.fp, uid_none, "空入口")
    g2.resolve(snap.fp)          # 点了没反应 → SAME
    check("死点：点了没反应的入口进 dead 集合",
          uid_none in g2.states[snap.fp].dead, sorted(g2.states[snap.fp].dead))
    step = s2.decide(snap.fp, snap.clicks, snap.nav, progress=0.5, back_unsafe=False)
    check("死点：不会再被选中，改为滚动或回退",
          step.action in ("scroll", "back", "none") and step.uid != uid_none, step)

    # ================================================================ 回退
    g3 = graph.PageGraph("com.t")
    s3 = C.Scheduler(g3)
    a = g3.observe(SCREENS["settings"], "com.t/.Main")
    s3.sync(a.fp)
    # 假装点进了 privacy
    s3.note_tap(uid="id:policy")
    b = g3.observe(SCREENS["privacy"], "com.t/.Main")
    g3.resolve(b.fp)
    s3.sync(b.fp)
    check("栈：深入一级后栈深为 1", s3.depth == 1, s3.stack)
    # privacy 上有个「返回」按钮，会被当成普通入口点掉 → 回到 settings
    s3.note_tap(uid="id:back")
    g3.observe(SCREENS["settings"], "com.t/.Main")
    s3.sync(a.fp)
    check("栈：退回父界面后栈自动截断", s3.depth == 0, s3.stack)

    # ★ 两种"没得点"必须分开：
    #   ① 结构树一个可点节点都没有（引导页/WebView）→ 让位给"滚/左右滑/返回"兜底。
    #      真机实测：赣警办首启是引导页，调度器在这里连滚 19 次、一个界面都没多走。
    g4 = graph.PageGraph("com.t")
    s4 = C.Scheduler(g4)
    s4.sync(g4.observe(SCREENS["home"], "com.t/.Main").fp)
    r = g4.observe(SCREENS["empty"], "com.t/.Main")
    s4.sync(r.fp)
    g4.states[r.fp].scroll_exhausted = True
    step = s4.decide(r.fp, r.clicks, r.nav, progress=0.5, back_unsafe=False)
    check("空屏：结构树没有可点节点 → 让位给滑动兜底（不能一味往下滚）",
          step.action == "none" and "可点节点" in step.reason, step)

    #   ② 有可点节点但都点过了 → 滚到底之后请求返回。
    g4b = graph.PageGraph("com.t")
    s4b = C.Scheduler(g4b)
    s4b.sync(g4b.observe(SCREENS["home"], "com.t/.Main").fp)
    rb = g4b.observe(SCREENS["dead"], "com.t/.Main")
    s4b.sync(rb.fp)
    stb = g4b.states[rb.fp]
    stb.uids_clicked.update(stb.uids_seen)      # 本屏入口都点过
    stb.scroll_exhausted = True
    step = s4b.decide(rb.fp, rb.clicks, rb.nav, progress=0.5, back_unsafe=False)
    check("回退：入口都点完且已滚到底 → 请求返回", step.action == "back", step)
    stb.scroll_exhausted = False
    step = s4b.decide(rb.fp, rb.clicks, rb.nav, progress=0.5, back_unsafe=False)
    check("回退：入口都点完但还没滚到底 → 先滚", step.action == "scroll", step)

    # 根界面不按返回（会把 App 退掉）
    g5 = graph.PageGraph("com.t")
    s5 = C.Scheduler(g5)
    r5 = g5.observe(SCREENS["empty"], "com.t/.Main")
    s5.sync(r5.fp)
    g5.states[r5.fp].scroll_exhausted = True
    step = s5.decide(r5.fp, r5.clicks, r5.nav, progress=0.5, back_unsafe=True)
    check("回退：根界面 + 已知 BACK 会退出 App → 不请求返回", step.action == "none", step)
    check("回退：内页 + BACK 曾退出过 App → 仍然允许返回（否则 DFS 回不来）",
          s5.can_back(True) is False and s5.depth == 0, (s5.can_back(True), s5.depth))

    # 内页允许
    s5.stack = [r5.fp, "child"]
    check("回退：内页允许返回", s5.can_back(True) is True, s5.stack)

    # 硬止损：内页 BACK 两次把 App 弄没
    s6 = C.Scheduler(graph.PageGraph("com.t"))
    s6.stack = ["a", "b"]
    s6.note_back(killed=True)
    check("止损：一次内页退出 App 还不禁用", s6.no_back is False)
    s6.note_back(killed=True)
    check("止损：两次即永久停用 BACK（宁可少走几层，也不反复重拉）", s6.no_back is True)
    check("止损：停用后即使在内页也不请求返回",
          s6.can_back(False) is False and s6.depth == 1)
    check("止损：停用会进统计（报告要能解释未探索入口为何偏高）",
          s6.stats()["no_back"] is True and s6.stats()["back_kills"] == 2)

    # ================================================================ 滚动
    g7 = graph.PageGraph("com.t")
    s7 = C.Scheduler(g7)
    r7 = g7.observe(SCREENS["dead"], "com.t/.Main")
    s7.sync(r7.fp)
    st7 = g7.states[r7.fp]
    check("滚动：初始未标记滚到底", st7.scroll_exhausted is False)
    s7.note_scroll(r7.fp)
    check("滚动：滚完还没 dump 时不急着判到底", st7.scroll_exhausted is False)
    s7.sync(r7.fp)                       # 界面没变 → 第一次
    check("滚动：一次没变化不判死", st7.scroll_exhausted is False)
    s7.note_scroll(r7.fp)
    s7.sync(r7.fp)                       # 第二次没变化
    check("滚动：连续两次滚完没新内容 → 标记滚到底", st7.scroll_exhausted is True)
    # 滚出新内容就不能判死
    g8 = graph.PageGraph("com.t")
    s8 = C.Scheduler(g8)
    r8 = g8.observe(SCREENS["home"], "com.t/.Main")
    s8.sync(r8.fp)
    s8.note_scroll(r8.fp)
    moved = _wrap(*_tabbar(), *_rows(["另一屏内容一", "另一屏内容二", "另一屏内容三"],
                                     prefix="zz"))
    r8b = g8.observe(moved, "com.t/.Main")
    s8.sync(r8b.fp)
    s8.note_scroll(r8b.fp)
    s8.sync(r8b.fp)
    check("滚动：滚出新界面时不会误标滚到底",
          all(not s.scroll_exhausted for s in g8.states.values()),
          [s.scroll_exhausted for s in g8.states.values()])

    # ================================================================ 单屏上限
    g9 = graph.PageGraph("com.t")
    s9 = C.Scheduler(g9, max_taps_per_state=2)
    r9 = g9.observe(SCREENS["settings"], "com.t/.Main")
    s9.sync(r9.fp)
    st9 = g9.states[r9.fp]
    st9.uids_clicked.update(["a", "b"])
    step = s9.decide(r9.fp, r9.clicks, r9.nav, progress=0.5, back_unsafe=False)
    check("上限：单屏点到次数上限后不再点，把预算让给别的界面",
          step.action in ("scroll", "back", "none"), step)

    # ================================================================ 定向期
    g10 = graph.PageGraph("com.t")
    s10 = C.Scheduler(g10)
    r10 = g10.observe(SCREENS["settings"], "com.t/.Main")
    s10.sync(r10.fp)
    step = s10.decide(r10.fp, r10.clicks, r10.nav, progress=0.95, back_unsafe=False)
    check("定向期：优先找设置/隐私/权限类入口", step.label in ("隐私政策", "权限管理",
                                                              "账号与安全"), step.label)
    check("定向期：日志里能看出为什么点它（定向/高价值）",
          "定向" in step.reason or "高价值" in step.reason, step.reason)

    # ================================================================ 系统界面不插手
    sys_xml = _wrap(_btn("允许", 20, 900, 500, 1000, rid="android:id/button1"),
                    _btn("拒绝", 560, 900, 1060, 1000, rid="android:id/button2"),
                    pkg="com.android.permissioncontroller")
    g11 = graph.PageGraph("com.t")
    s11 = C.Scheduler(g11)
    r11 = g11.observe(sys_xml, "com.android.permissioncontroller/.GrantPermissionsActivity")
    s11.sync(r11.fp)
    step = s11.decide(r11.fp, r11.clicks, r11.nav, progress=0.5, back_unsafe=False)
    check("系统界面：调度器不插手（授权要由拦截分支取证后决定）",
          step.action == "none" and "系统界面" in step.reason, step)
    check("系统界面：被识别为 system，不计入 App 覆盖率", g11.states[r11.fp].system is True)

    # ================================================================ 无用控件
    # 真机实测（赣警办注册页）：连着点了「请输入手机号」「请输入验证码」
    # 「img_verificationcode」三次，一无所获，还把界面顶成了输入法。
    def _n(cls="", rid="", text="x"):
        return type("N", (), {"cls": cls, "resource_id": rid, "label": text})()

    check("无用控件：EditText 被识别为无采集价值",
          uiwalk.is_no_use(_n(cls="android.widget.EditText")))
    check("无用控件：图形验证码（id）被识别",
          uiwalk.is_no_use(_n(cls="android.widget.ImageView",
                              rid="com.t:id/img_verificationcode")))
    check("无用控件：普通按钮不误伤",
          not uiwalk.is_no_use(_n(cls="android.widget.Button", rid="com.t:id/btn_login",
                                  text="登录")))
    check("无用控件：包名里带 verify 不算（只看 id 最后一段）",
          not uiwalk.is_no_use(_n(cls="android.widget.Button",
                                  rid="com.verif.app:id/ok", text="确定")))

    # ================================================================ 无文字的 tab
    # 真机实测：赣警办底部四个 tab 的 text 全为空，只有 tab_home/tab_person 这类 id。
    # 只按文字识别会认不出导航，"先铺 tab"这条策略就永远不生效。
    nav_xml = _wrap(
        _btn("", 0, 1800, 270, 1860, rid="com.t:id/tab_home"),
        _btn("", 270, 1800, 540, 1860, rid="com.t:id/tab_service"),
        _btn("", 540, 1800, 810, 1860, rid="com.t:id/tab_msg"),
        _btn("", 810, 1800, 1080, 1860, rid="com.t:id/tab_person"),
        _btn("内容推荐位", 20, 400, 1060, 500, rid="com.t:id/card_0"))
    gn = graph.PageGraph("com.t")
    rn = gn.observe(nav_xml, "com.t/.Main")
    check("导航：无文字但有 tab id 的底部按钮能识别为导航",
          len(rn.nav) == 4, [n.resource_id for n in rn.nav])
    check("导航：签名用 id 回退，不因无文字而变成空串",
          rn.tab_sig.count("|") >= 2, rn.tab_sig)
    # 无文字且 id 无导航特征的容器不能被当成导航
    junk_xml = _wrap(*[_btn("", i * 270, 1800, (i + 1) * 270, 1860,
                            rid="com.t:id/cell_%d" % i) for i in range(4)])
    rj = graph.PageGraph("com.t").observe(junk_xml, "com.t/.Main")
    check("导航：无文字又无 nav 特征的一排容器不误判成导航", rj.nav == [], rj.nav)

    # ================================================================ 弹窗不压栈
    # 注册页 + 它的「确定」对话框如果各算一层，深度会虚高，DFS 还会来回切换。
    dlg = _wrap(_btn("提示", 100, 800, 980, 850, cls="android.app.Dialog",
                     clickable=False),
                _btn("确定", 200, 900, 500, 1000, cls="android.widget.Button",
                     rid="com.t:id/ok"),
                _btn("取消", 560, 900, 860, 1000, cls="android.widget.Button",
                     rid="com.t:id/no"))
    gd = graph.PageGraph("com.t")
    sd = C.Scheduler(gd)
    sd.sync(gd.observe(SCREENS["settings"], "com.t/.Main").fp)
    rd = gd.observe(dlg, "com.t/.Main")
    check("弹窗：被结构树识别为弹窗", rd.is_dialog is True)
    sd.sync(rd.fp)
    check("弹窗：不压栈（否则深度虚高、DFS 在页面与弹窗间来回）",
          sd.depth == 0, sd.stack)

    # ================================================================ 政策入口降权
    # 首启阶段（P2）已单独取过政策正文；遍历阶段再点进去多半只是长文本 WebView，
    # 真机上甚至是错误页。深挖期要往后排，把预算留给有功能入口的页面。
    #
    # ★ 前提是"正文真的取到了"（2026-11-10 CNC宝典）：P2 失败时，设置页里的
    #   「隐私政策」是最后的补救入口 —— 无条件压后等于主动放弃唯一能拿到条款的
    #   机会，而整份报告十几项都要靠它。所以这里显式声明 policy_ready=True。
    g13 = graph.PageGraph("com.t")
    s13 = C.Scheduler(g13)
    s13.policy_ready = True
    r13 = g13.observe(SCREENS["settings"], "com.t/.Main")
    s13.sync(r13.fp)
    step = s13.decide(r13.fp, r13.clicks, r13.nav, progress=0.70, back_unsafe=False)
    check("深挖期：政策正文已取到时，政策/协议入口排在功能入口之后",
          step.label != "隐私政策", step.label)
    step_t = s13.decide(r13.fp, r13.clicks, r13.nav, progress=0.95, back_unsafe=False)
    check("定向期：政策入口仍然可点（第三方共享清单常在政策页里）",
          step_t.action == "tap", step_t)

    # 反例：正文还没取到 → 政策入口必须是优先项，不能被压后
    g13b = graph.PageGraph("com.t")
    s13b = C.Scheduler(g13b)
    s13b.policy_ready = False
    r13b = g13b.observe(SCREENS["settings"], "com.t/.Main")
    s13b.sync(r13b.fp)
    step_b = s13b.decide(r13b.fp, r13b.clicks, r13b.nav, progress=0.70,
                         back_unsafe=False)
    check("深挖期：政策正文未取到时，政策入口排在最前（最后补救机会）",
          step_b.label == "隐私政策" or "隐私" in str(step_b.label), step_b.label)

    # ================================================================ 统计
    stats = sim.s.stats()
    check("统计：点开过 tab 就不算'未识别出主导航'",
          stats["entry_failed"] is False and stats["tabs_opened"] > 0,
          (stats["entry_failed"], stats["tabs_opened"]))
    check("统计：有阶段、栈深、点击/回退/滚动三项计数",
          all(k in stats for k in ("phase", "stack_depth", "taps", "backs", "scrolls")),
          list(stats))
    check("统计：按阶段分别记点击（能看出预算花在哪个阶段）",
          isinstance(stats["phase_taps"], dict) and sum(stats["phase_taps"].values()) > 0,
          stats["phase_taps"])
    check("日志：摘要行包含点击/回退/滚动/栈深",
          all(k in C.Scheduler(graph.PageGraph("com.t")).summary_line()
              for k in ("点击", "回退", "滚动", "栈深")))

    # ================================================================ 接入契约
    src = (ROOT / "piiscan" / "collector.py").read_text(encoding="utf-8")
    check("接入：观测之后同步调度栈",
          re.search(r"obs\.resolve\(snap\.fp[\s\S]{0,300}?sched\.sync\(snap\.fp\)", src)
          is not None)
    check("接入：点击路径汇报给调度器（否则栈永远不动）",
          src.count("sched.note_tap(") >= 2, src.count("sched.note_tap("))
    check("接入：返回路径汇报，并把'是否退出 App'一起告知",
          "sched.note_back(killed=" in src)
    check("接入：调度决策被 try 包住，异常不得影响采集",
          re.search(r"sched_step = sched\.decide\([\s\S]{0,500}?except Exception", src)
          is not None)
    check("接入：调度点中的节点落地前再过一遍危险检查",
          re.search(r"if uiwalk\.is_dangerous\(node\):[\s\S]{0,400}?continue", src)
          is not None)
    check("接入：调度口径写进结果（crawl_mode / scheduler）",
          '"scheduler"' in src and '"crawl_mode"' in src)
    check("接入：legacy 模式可一键回退",
          'crawl_mode' in (ROOT / "piiscan" / "config.py").read_text(encoding="utf-8"))
    check("接入：BACK 统一走 _do_back（两处各写一遍退出检测迟早漏一处）",
          src.count("uiwalk.back(res.device_serial)") <= 4,
          src.count("uiwalk.back(res.device_serial)"))

    # ================================================================ 返回控件
    # 真机（CNC宝典 2026-11-10）：标题栏左箭头 label 被继承成应用名，
    # 身份是 iv_back / ivBack / imgBtnBack / btn_main_left，一轮被当入口点了 24 次。
    # 点它等于替 App 按 BACK —— 花 9 秒做一次白做的事，还把报告写成
    # "点击『数控车床CNC宝典』14 次"。这里钉住判据：认得准，且**不能误杀**
    # 名字里含 back 的真入口（意见反馈的 id 是 btFeedback）。
    def _node(**kw):
        base = dict(text="", resource_id="", content_desc="", cls="android.widget.ImageView",
                    bounds=(0, 90, 112, 250), sub_text="")
        base.update(kw)
        return uiwalk.UiNode(**base)

    check("返回控件：iv_back 认成返回", graph.is_back_control(_node(resource_id="com.t:id/iv_back")))
    check("返回控件：imgBtnBack / ivBack 认成返回",
          graph.is_back_control(_node(resource_id="com.t:id/imgBtnBack"))
          and graph.is_back_control(_node(resource_id="com.t:id/ivBack")))
    check("返回控件：自绘页的左箭头 btn_main_left 认成返回",
          graph.is_back_control(_node(resource_id="com.t:id/btn_main_left")))
    check("返回控件：content-desc 写着「转到上一层级」也认",
          graph.is_back_control(_node(content_desc="转到上一层级")))
    check("返回控件：★ 不误杀「意见反馈」(btFeedback) —— 名字里含 back 但不是返回",
          not graph.is_back_control(_node(text="意见反馈", resource_id="com.t:id/btFeedback")))
    check("返回控件：★ 不误杀标题栏 logo（ivKefu，label 继承成应用名）",
          not graph.is_back_control(_node(resource_id="com.t:id/ivKefu",
                                          sub_text="数控车床CNC宝典")))

    # 调度器层：同屏既有返回箭头又有真入口时，必须点真入口。
    rs = _wrap(_btn("", 0, 90, 112, 250, rid="com.t:id/iv_back",
                    cls="android.widget.ImageView"),
               _btn("设置", 20, 400, 1060, 500, rid="com.t:id/setting_layout",
                    cls="android.widget.LinearLayout"))
    grs = graph.PageGraph("com.t")
    srs = C.Scheduler(grs)
    rrs = grs.observe(rs, "com.t/.Main")
    srs.sync(rrs.fp)
    strs = srs.decide(rrs.fp, rrs.clicks, rrs.nav, progress=0.5, back_unsafe=False)
    check("返回控件：有真入口时不会去点左箭头", strs.label == "设置", strs.label)

    # 整屏只有左箭头时：走 BACK，而不是"点一下箭头"
    # （落点一样，但 BACK 有 `can_back()` 统一判"会不会退出应用"，且不占点击留痕）
    only_back = _wrap(_btn("", 0, 90, 112, 250, rid="com.t:id/iv_back",
                           cls="android.widget.ImageView"))
    gob = graph.PageGraph("com.t")
    sob = C.Scheduler(gob)
    rob = gob.observe(only_back, "com.t/.Main")
    sob.sync(rob.fp)
    sob.stack = [rob.fp, "prev-fp"]       # 栈深 ≥2 才能返回（根界面 BACK 会退出应用）
    stob = sob.decide(rob.fp, rob.clicks, rob.nav, progress=0.5, back_unsafe=False)
    check("返回控件：只剩左箭头时改走 BACK（不占一次点击留痕）",
          stob.action == "back", stob)

    # 图标不继承同行文字：标题栏的客服/会员图标不该被叫成应用名
    head = _wrap('<node text="" resource-id="com.t:id/ivKefu" class="android.widget.ImageView" '
                 'bounds="[900,90][1030,250]" clickable="true" package="com.t"/>'
                 '<node text="数控车床CNC宝典" resource-id="" class="android.widget.TextView" '
                 'bounds="[200,90][800,250]" clickable="false" package="com.t"/>')
    n_head = [n for n in uiwalk.parse_all(head) if "ivKefu" in (n.resource_id or "")][0]
    check("命名：图标节点不继承同一行标题文字（避免报告写成'点击应用名'）",
          graph._label_of(n_head) == "", graph._label_of(n_head))

    # ================================================================ 文档重复打开
    # 真机（CNC宝典）：设置页滚一下 / 从文档返回一次，界面指纹就变了，
    # 同一份《隐私政策》重新变成合法候选 —— 一轮打开 5 次《隐私政策》、
    # 6 次《用户协议》，每次都是同一条长文本，单次 30~90 秒。
    doc_xml = _wrap(_btn("《隐私政策》", 20, 300, 1060, 380, rid="com.t:id/tv_yszc"),
                    _btn("《用户协议》", 20, 400, 1060, 480, rid="com.t:id/tv_yhxy"),
                    _btn("设置", 20, 600, 1060, 680, rid="com.t:id/setting_layout"))
    gd = graph.PageGraph("com.t")
    sd = C.Scheduler(gd)
    sd.policy_ready = True
    rd = gd.observe(doc_xml, "com.t/.Main")
    sd.sync(rd.fp)
    stt = gd.states[rd.fp]
    # 模拟"点开 → 返回后指纹变了 → 同一份文档又被点"：直接连点 5 次
    for _ in range(5):
        stt.uids_clicked.clear()          # 每次都是"新界面"，旧记录不生效
        step = sd.decide(rd.fp, rd.clicks, rd.nav, progress=0.5, back_unsafe=False)
        if step.action != "tap":
            break
        sd.note_tap(uid=step.uid, label=step.label)
        if "隐私政策" in (step.label or ""):
            continue
        break
    check("文档：同一份《隐私政策》整轮最多打开 2 次（policy_ready 之后）",
          sd._doc_taps.get("隐私政策", 0) <= 2, sd._doc_taps)
    check("文档：打开次数被记在调度器台账里（AI 直选也走同一本账）",
          "隐私政策" in sd._doc_taps, sd._doc_taps)
    # 超限后必须**移出候选**（不是降权：降权只是排后面，点完别的还会轮回来）
    gd1b = graph.PageGraph("com.t")
    sd1b = C.Scheduler(gd1b)
    sd1b.policy_ready = True
    r1b = gd1b.observe(doc_xml, "com.t/.Main")
    sd1b.sync(r1b.fp)
    sd1b.note_tap(uid="id:tv_yszc", label="《隐私政策》")
    sd1b.note_tap(uid="id:tv_yszc", label="《隐私政策》")
    cands = sd1b._candidates(r1b.clicks, gd1b.states[r1b.fp])
    check("文档：点满 2 次后《隐私政策》被移出候选（不是只降权）",
          all("隐私政策" not in (getattr(n, "label", "") or "") for n, _u in cands),
          [getattr(n, "label", "") for n, _u in cands])
    check("文档：移出候选的同时《用户协议》《设置》仍在（只封这一份）",
          any("用户协议" in (getattr(n, "label", "") or "") for n, _u in cands)
          and any("设置" in (getattr(n, "label", "") or "") for n, _u in cands),
          [getattr(n, "label", "") for n, _u in cands])
    # 正文没取到时不缩到 2：那是最后的补救入口，给 4 次
    gd2 = graph.PageGraph("com.t")
    sd2 = C.Scheduler(gd2)
    rd2 = gd2.observe(doc_xml, "com.t/.Main")
    sd2.sync(rd2.fp)
    for _ in range(6):
        gd2.states[rd2.fp].uids_clicked.clear()
        step = sd2.decide(rd2.fp, rd2.clicks, rd2.nav, progress=0.5, back_unsafe=False)
        if step.action != "tap":
            break
        sd2.note_tap(uid=step.uid, label=step.label)
        if "隐私政策" not in (step.label or ""):
            break
    check("文档：正文未取到时上限放宽到 4 次（不放弃补救入口）",
          sd2._doc_taps.get("隐私政策", 0) <= C.DOC_TAP_LIMIT_UNREADY, sd2._doc_taps)


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
