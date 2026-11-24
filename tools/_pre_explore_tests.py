# -*- coding: utf-8 -*-
"""1 档「未同意状态探索」的回归（不连真机）。

起因（使用者 2026-11-17）：
    「用了十几个 App 跑 1 档，居然一个同意前实锤都没有，比例上说不通。
     1 档本来就是同意前，可以去点点除了『同意』之外的按钮和链接。」

查证：不是判定错，是**这一档从来没点过任何东西** —— 16 轮 1 档的 ui_steps
全部 ≤1，全程静置在隐私弹窗上。整改后的 App 把 SDK 初始化推迟到同意之后，
静置自然一个标识符都读不到。

这里守四件事：
  ① 同意类标签一个都不能点（含弹窗上的「确定/接受/允许」）；
  ② 「不同意/仅浏览/跳过」要能点 —— 它们是进入未同意可用界面的唯一入口；
  ③ 注销账号、真实支付这类不可逆动作不能点；
  ④ 点了「不同意」导致退出要如实记下来，并重新拉起继续试别的路径。
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiscan import collector as C          # noqa: E402
from piiscan import uiwalk                  # noqa: E402
from piiscan.collector import ScanResult    # noqa: E402
from piiscan.flow import sop as SOP         # noqa: E402


# ---------------------------------------------------------------- 假界面


def _node(label, x, y, cls="android.widget.Button"):
    return uiwalk.UiNode(text=label, cls=cls, resource_id="", bounds=(x, y, x + 80, y + 30),
                         clickable=True, enabled=True)


class FakeWalk:
    """按"当前屏"返回节点；点某个标签后切到下一屏（或退出）。"""

    def __init__(self, screens):
        # screens: [{"act":str,"pkg":str,"nodes":[label...],"on_tap":{label: 下一屏序号 或 "exit"}}]
        self.screens = screens
        self.idx = 0
        self.tapped = []
        self.backs = 0
        self.respawns = 0

    def foreground(self, serial):
        s = self.screens[self.idx]
        pkg = s.get("pkg", "com.test.app")
        act = s.get("act", "com.test.app.MainActivity")
        # ★ 必须与真实 `uiwalk.foreground()` 的返回结构一致：键是 focus/pkg/via。
        #   2026-11-17 的教训 —— 假对象当初返回 package/activity（真实函数里
        #   根本没有这两个键），65 项测试全绿，真机上"前台不在被测应用"这条
        #   防线整段失效，探索一路点进了系统相册。假对象与真实结构脱钩，
        #   测试就是在给自己发合格证。
        focus = act if "/" in act else ("%s/%s" % (pkg, act))
        return {"focus": focus, "pkg": pkg, "via": "window"}

    def dump_retry(self, serial, tries=3, wait=0.6):
        xp = self.screens[self.idx].get("xml_pkg")
        if xp:
            # 结构树根节点的 package：前台接口读不到时，只有它能说出
            # "这一屏到底是谁的界面"。
            return '<hierarchy package="%s"></hierarchy>' % xp
        return "XML-%d" % self.idx

    def parse_all(self, xml):
        if "hierarchy" in str(xml):
            return []
        i = int(str(xml).split("-")[1])
        return [_node(lab, 100, 100 + 60 * k)
                for k, lab in enumerate(self.screens[i]["nodes"])]

    def screen_texts(self, xml):
        if "hierarchy" in str(xml):
            return []
        i = int(str(xml).split("-")[1])
        return list(self.screens[i]["nodes"])

    def focus_key(self, act):
        return act or ""

    def tap(self, serial, x, y):
        i = int((y - 100) // 60)
        lab = self.screens[self.idx]["nodes"][i]
        self.tapped.append(lab)
        nxt = (self.screens[self.idx].get("on_tap") or {}).get(lab)
        if nxt == "exit":
            self.idx = self.screens[self.idx]["exit_to"]
        elif isinstance(nxt, int):
            self.idx = nxt
        return True

    def back(self, serial):
        self.backs += 1
        return True


class _Patcher:
    """把 collector 里用到的 uiwalk / observe_screen 换掉，退出时还原。"""

    def __init__(self, fw):
        self.fw = fw
        self.saved = {}

    def __enter__(self):
        for name in ("foreground", "dump_retry", "parse_all", "screen_texts",
                     "focus_key", "tap", "back"):
            self.saved[name] = getattr(C.uiwalk, name)
            setattr(C.uiwalk, name, getattr(self.fw, name))
        self.saved["observe_screen"] = C.observe_screen
        C.observe_screen = lambda *a, **k: None
        return self

    def __exit__(self, *exc):
        for name, fn in self.saved.items():
            setattr(C.uiwalk if name != "observe_screen" else C,
                    name, fn)
        return False


def _run_explore(fw, *, budget=4.0, respawn=None):
    res = ScanResult(package="com.test.app", device_serial="s1")
    cfg = SimpleNamespace(scan=SimpleNamespace(
        package="com.test.app", ui_tap_interval=0.4, max_shots=20,
        max_taps_per_state=20))
    log = []
    with _Patcher(fw):
        out = C._explore_pre_consent(res, cfg, None, time.time() + budget,
                                     log.append, respawn=respawn,
                                     should_stop=lambda: False)
    return res, out, log


def _S_with(ui_steps=None, pe=None, depth="pre", given=False, cms=None):
    """假的 ScanResult：只带判定层要读的字段。"""
    return SimpleNamespace(
        depth=depth, consent_given=given, consent_elapsed_ms=cms,
        consent_source=("ui:同意并继续" if given else ""),
        events=[], ui_steps=list(ui_steps or []),
        errors=[], ui_taps=0, screenshots=[], pre_explore=dict(pe or {}))


# ---------------------------------------------------------------- 用例


def run(check) -> None:
    print("— 1 档未同意状态探索")

    # ---- ① 安全闸门：同意类一个都不能点 ----
    must_block = ["同意并继续", "我同意", "同意", "确定", "接受", "允许",
                  "我知道了", "好的", "继续", "同意并使用", "同  意",
                  "我已阅读并同意《隐私政策》"]
    for lab in must_block:
        check("不点同意类「%s」" % lab, not C._pre_may_tap(lab), lab)

    # ---- ② 拒绝类要能点（进入未同意可用界面的唯一入口）----
    must_allow = ["不同意", "拒绝", "暂不使用", "仅浏览", "游客模式", "跳过",
                  "先逛逛", "取消", "关闭", "设置", "《隐私政策》", "首页",
                  "我的", "搜索", "分类"]
    for lab in must_allow:
        check("可以点「%s」" % lab, C._pre_may_tap(lab), lab)

    # ---- ③ 不可逆 / 花钱的动作不能点 ----
    must_forbid = ["注销账号", "退出登录", "解绑手机号", "立即支付",
                   "提交订单", "立即购买", "确认充值", "开通会员",
                   "拨号", "发送短信", "退出应用", "确认卸载"]
    for lab in must_forbid:
        check("不点不可逆动作「%s」" % lab, not C._pre_may_tap(lab), lab)

    # 「支付设置」不是交易动作，应当放行（短语匹配，不是单词匹配）
    check("「支付设置」不算交易动作", C._pre_may_tap("支付设置"), "支付设置")

    # ---- ④ 退出类排最后：先点无风险入口，绝不点「同意并继续」----
    # ★ 2026-11-18 改了顺序：原来"退出类优先"，理由是"模态弹窗上点背景全是
    #   空转"。真机上驿站助手 / 贝利自动点击器点「不同意」都**直接退回桌面**，
    #   探索第一下就自杀，后面的 respawn 只是重复同一条路。
    fw = FakeWalk([
        {"act": "com.test.app.PrivacyDialog", "nodes": ["《隐私政策》", "同意并继续", "不同意"],
         "on_tap": {"不同意": 1, "《隐私政策》": 0, "同意并继续": 0}},
        {"act": "com.test.app.Home", "nodes": ["首页", "我的", "搜索"],
         "on_tap": {"首页": 1, "我的": 1, "搜索": 1}},
    ])
    res, out, log = _run_explore(fw)
    check("探索确实点了元素", out["taps"] > 0, out)
    check("一次都没点同意", "同意并继续" not in fw.tapped, fw.tapped)
    check("退出类排最后：先点无风险入口",
          fw.tapped and fw.tapped[0] == "《隐私政策》", fw.tapped)
    check("「不同意」不是第一个点的",
          "不同意" in fw.tapped and fw.tapped.index("不同意") > 0, fw.tapped)
    check("跳过了同意类并计数", out["skipped_consent"] >= 1, out)
    check("进入了第二屏", out["screens"] >= 2, out)
    check("探索结果写进了 res.pre_explore", res.pre_explore.get("taps") == out["taps"],
          res.pre_explore)

    # ★ 这一条是"文本切分"那个坑的回归：1 档的步骤文字必然是
    #   「未同意状态：点击「不同意」」—— 本身就含「同意」二字。
    #   旧逻辑靠"遇到含『同意』的步骤就停"来数探索步数，一匹配就把整段
    #   探索截掉，探索反而被判成没做。新逻辑只认 pre_explore 字段。
    check("步骤文字里确实含「同意」二字（这正是旧逻辑会踩的坑）",
          any("同意" in s for s in res.ui_steps), res.ui_steps)
    _r = SOP.FlowRunner(log=lambda *_a: None)
    _r.scan = _S_with(ui_steps=list(res.ui_steps), pe=dict(out))
    _pr = _r.p1_pre_consent()
    check("步骤文字含「同意」也不影响探索判定",
          any("点击 %d 次" % out["taps"] in s for s in _pr.steps), _pr.steps)

    # ---- ⑤ 只有同意按钮时，一下都不点 ----
    fw2 = FakeWalk([{"act": "com.test.app.PrivacyDialog", "nodes": ["同意并继续"]}])
    res2, out2, _ = _run_explore(fw2, budget=3.0)
    check("只有同意按钮时点击数为 0", out2["taps"] == 0, out2)
    check("只有同意按钮时如实记下原因", bool(out2["why"]), out2)

    # ---- ⑥ 点「不同意」导致退出：记下事实并重新拉起 ----
    fw3 = FakeWalk([
        {"act": "com.test.app.PrivacyDialog", "nodes": ["不同意"],
         "on_tap": {"不同意": "exit"}, "exit_to": 1},
        {"act": "com.launcher", "pkg": "com.miui.home", "nodes": []},
    ])
    calls = {"n": 0}

    def _respawn():
        calls["n"] += 1
        fw3.idx = 0          # 重新拉起后回到弹窗
        return calls["n"] >= 2   # 第二次就说拉不回来了，结束循环

    res3, out3, _ = _run_explore(fw3, budget=4.0, respawn=_respawn)
    check("退出被如实记录", bool(out3["refused_exit"]), out3)
    check("记录里带上了点的按钮和落到哪",
          out3["refused_exit"] and out3["refused_exit"][0]["label"] == "不同意"
          and "miui" in out3["refused_exit"][0]["pkg_after"],
          out3["refused_exit"])
    check("尝试过重新拉起", calls["n"] >= 1, calls)
    check("退出也写进操作步骤", any("应用退出" in s for s in res3.ui_steps),
          res3.ui_steps)

    # ---- ⑥b 点进系统图片选择器：绝不能在相册里继续点 ----
    # ★ 2026-11-17 真机回归：前台判定读错了键名，探索在 MIUI 相册里连点了
    #   5 次（含「新建相册」）—— 这是在别人的应用里动手，属副作用。
    #   正确行为：一旦界面不属于被测应用，立刻停手（BACK / 结束），
    #   相册里的元素一个都不许点。
    fw_pick = FakeWalk([
        {"act": "com.test.app.Home", "nodes": ["相册", "同意并继续"],
         "on_tap": {"相册": 1, "同意并继续": 1}},
        {"act": "com.miui.gallery.PickActivity", "pkg": "com.miui.gallery",
         "nodes": ["新建相册", "取消", "照片"]},
    ])
    res_pick, out_pick, _ = _run_explore(fw_pick, budget=4.0)
    check("跳进系统图片选择器后不再点击相册里的元素",
          "新建相册" not in fw_pick.tapped and "取消" not in fw_pick.tapped,
          fw_pick.tapped)
    check("越界次数被记下来", int(out_pick.get("escapes") or 0) >= 1, out_pick)
    check("越界后如实写原因", bool(out_pick.get("why")), out_pick)

    # ---- ⑥c 前台读不到焦点时，用结构树根节点的 package 兜底 ----
    fw_xml = FakeWalk([
        {"act": "com.test.app.Home", "nodes": ["首页", "我的"], "xml_pkg": "com.miui.gallery"},
    ])
    res_xml, out_xml, _ = _run_explore(fw_xml, budget=3.0)
    check("结构树属于别的应用时一个元素都不点", out_xml["taps"] == 0, out_xml)
    check("结构树兜底也会把越界计入", int(out_xml.get("escapes") or 0) >= 1, out_xml)

    # ---- ⑥d 前台返回结构：键名必须与真实 uiwalk.foreground 一致 ----
    # 这条是上面那个坑的"根因断言"：mock 换成真实结构之后，_fg_pkg 必须能
    # 从 pkg / focus 两条路都取到包名。
    check("_fg_pkg 认 pkg 键",
          C._fg_pkg({"pkg": "com.a.b", "focus": "com.a.b/.Main"}) == "com.a.b",
          C._fg_pkg({"pkg": "com.a.b", "focus": "com.a.b/.Main"}))
    check("_fg_pkg 缺 pkg 时从 focus 切",
          C._fg_pkg({"focus": "com.c.d/com.c.d.X"}) == "com.c.d",
          C._fg_pkg({"focus": "com.c.d/com.c.d.X"}))
    check("_fg_pkg 读不到时返回空串", C._fg_pkg({}) == "", C._fg_pkg({}))

    # ---- ⑥e 重新拉起有上限、进新屏会静置 ----
    # 一轮里重启二十多次，会把首启的网络请求重复计成"外发 43 次"。
    check("重新拉起有上限", 1 <= C._PRE_EXPLORE_RESPAWN_CAP <= 5,
          C._PRE_EXPLORE_RESPAWN_CAP)
    check("探索结果里带 respawns 字段", "respawns" in out3, out3)
    check("进入新界面后会静置观察", float(out.get("settle") or 0) > 0, out)

    # ---- ⑥f 退出类只点一次：不许"退出-重拉-再退出"把首启重放三遍 ----
    # ★ 2026-11-18 真机：驿站助手点「不同意并退出」、贝利自动点击器点
    #   「不同意」都直接退回桌面。旧逻辑把退出类排在最前，respawn 三次就等于
    #   把首启流程重放三遍，网络请求跟着重复计数。
    fw_ex = FakeWalk([
        {"act": "com.test.app.PrivacyDialog", "nodes": ["同意并继续", "不同意"],
         "on_tap": {"不同意": "exit", "同意并继续": "exit"}, "exit_to": 1},
        {"act": "com.launcher", "pkg": "com.miui.home", "nodes": []},
    ])
    ex_calls = {"n": 0}

    def _respawn_ex():
        ex_calls["n"] += 1
        fw_ex.idx = 0
        return ex_calls["n"] <= 1        # 只拉回一次

    res_ex, out_ex, _ = _run_explore(fw_ex, budget=6.0, respawn=_respawn_ex)
    check("退出只记了一笔", len(out_ex["refused_exit"]) == 1, out_ex["refused_exit"])
    check("重拉回来不再点退出类",
          int(out_ex.get("skipped_exit") or 0) >= 1
          and fw_ex.tapped.count("不同意") == 1,
          (out_ex.get("skipped_exit"), fw_ex.tapped))

    # ---- ⑥g 政策处理完后静置到窗口结束 ----
    # ★ 2026-11-18 同批 App 的 1 档 / 4 档对照：Android ID 在冷启动后
    #   **23.0s（驿站助手）/ 48.2s（贝利）**被读，而 1 档"拿到政策就收工"，
    #   根本没在弹窗上待够那几十秒。静置这一段不点任何东西，是 1 档最该
    #   拿到、也最干净的同意前观测。
    class _Drift(FakeWalk):
        """每次 dump 就"App 自己换屏"——静置期间我们没动手。"""

        def dump_retry(self, serial, tries=3, wait=0.6):
            if self.idx < len(self.screens) - 1:
                self.idx += 1
            return "XML-%d" % self.idx

    fw_st = _Drift([
        {"act": "com.test.app.Splash", "nodes": ["欢迎使用", "隐私政策"]},
        {"act": "com.test.app.PrivacyDialog", "nodes": ["欢迎使用", "隐私政策", "同意"]},
        {"act": "com.test.app.PrivacyDialog", "nodes": ["欢迎使用", "隐私政策", "同意", "补充"]},
    ])
    res_st = ScanResult(package="com.test.app", device_serial="s1")
    shots = []
    with _Patcher(fw_st):
        C.observe_screen = lambda *a, **k: shots.append(a[1] if len(a) > 1 else "")
        out_st = C._pre_consent_settle(res_st, "s1", time.time() + 1.0,
                                       (lambda *_: None), poll=0.05)
    check("静置拿到秒数", float(out_st.get("seconds") or 0) > 0, out_st)
    check("界面自行变化时补了图", int(out_st.get("screens") or 0) >= 1, out_st)
    check("静置期间一次都没点", fw_st.tapped == [], fw_st.tapped)
    check("ScanResult 有 pre_settle 字段", hasattr(res_st, "pre_settle"), dir(res_st))
    from piiscan.config import DEPTH_PROFILES as _DEPTHS
    check("1 档首启窗口 ≥ 60s（4 档实测采集点在 48.2s）",
          int(_DEPTHS["pre"]["policy_wait"]) >= 60, _DEPTHS["pre"]["policy_wait"])
    check("1 档总预算 ≥ 420s（60s 静置 + 探索）",
          int(_DEPTHS["pre"]["duration"]) >= 420, _DEPTHS["pre"]["duration"])

    # ---- ⑥h 点正文：App 的初始化链由"用户读了政策"带起来 ----
    # ★ 2026-11-18 真机 logcat 定论（驿站助手）：纯等 74 秒 App 一行业务日志
    #   都没有；而 2 档在**启动后 24.6 秒**出现 `View$PerformClick`，
    #   Android ID 的读取（elapsed=23946ms）紧跟着就发生了。
    #   所以静置里必须点一下政策正文 —— 只点正文，绝不点按钮。
    _long = "请您务必审慎阅读、充分理解《隐私政策》和《服务协议》的全部条款，" * 2
    _px = ('<hierarchy><node text="%s" bounds="[40,300][1040,700]"/>'
           '<node text="同意" bounds="[40,1700][500,1760]"/>'
           '<node text="不同意并退出" bounds="[540,1700][1040,1760]"/>'
           '</hierarchy>' % _long)
    class _BodyWalk:
        def __init__(self):
            self.tapped = []
        def foreground(self, serial):
            return {"pkg": "com.test.app", "focus": "com.test.app/.Start", "via": "w"}
        def dump_retry(self, serial, tries=1, wait=0.3):
            return _px
        def parse_all(self, xml):
            return [
                uiwalk.UiNode(text=_long, cls="android.widget.TextView",
                              resource_id="", bounds=(40, 300, 1040, 700),
                              clickable=False),
                uiwalk.UiNode(text="同意", cls="android.widget.Button",
                              resource_id="", bounds=(40, 1700, 500, 1760),
                              clickable=True),
                uiwalk.UiNode(text="不同意并退出", cls="android.widget.Button",
                              resource_id="", bounds=(540, 1700, 1040, 1760),
                              clickable=True),
            ]
        def screen_texts(self, xml):
            return ["正文", "同意", "不同意并退出"]
        def focus_key(self, act):
            return act or ""
        def tap(self, serial, x, y):
            self.tapped.append((x, y))
            return True
        def back(self, serial):
            return True

    _bw = _BodyWalk()
    with _Patcher(_bw):
        C.observe_screen = lambda *a, **k: None
        _o = C._pre_consent_settle(ScanResult(package="com.test.app", device_serial="s1"),
                                   "s1", time.time() + 1.2, (lambda *_: None), poll=0.05)
    check("静置里点了一次正文", len(_bw.tapped) == 1, _bw.tapped)
    _bx, _by = _bw.tapped[0] if _bw.tapped else (0, 0)
    check("点的是正文（y 落在正文区间，不是按钮那一行）",
          300 <= _by <= 700, (_bx, _by))
    check("正文点击记进了结果", bool(_o.get("body_tap")), _o.get("body_tap"))

    # 正文挑选的判据：够长才点，短标签（按钮）一律不选
    _n1 = C._pre_body_node(_px)
    check("_pre_body_node 挑到的是正文", _n1 is not None
          and _n1.text.startswith("请您务必审慎阅读"), _n1.text[:20] if _n1 else None)
    check("_pre_body_node 不会挑到按钮",
          C._pre_body_node(
              '<hierarchy><node text="同意" bounds="[40,900][500,960]"/></hierarchy>'
          ) is None, "只有短按钮时应当返回 None")
    check("覆盖大半屏的容器节点不点",
          C._pre_body_node(
              '<hierarchy><node text="%s" bounds="[0,0][1080,1800]"/></hierarchy>' % _long
          ) is None, "整屏节点中心可能压在按钮上")

    # ---- ⑥i 静默段：一个 adb 命令都不发 ----
    # ★ 2026-11-18 根因：1 档每 5 秒 dump 一次，App 的消息队列一直不空闲，
    #   挂 IdleHandler/postDelayed 上的首启初始化永远排不到 —— 表现就是
    #   "App 什么都没做"。而 2 档同一时刻只 dump 了寥寥几次，第 23.9 秒
    #   就把 Android ID 读出来了。静置的前 30 秒必须真的什么都不碰。
    class _QuietWalk(FakeWalk):
        def __init__(self, screens):
            super().__init__(screens)
            self.calls = {"foreground": 0, "dump": 0}

        def foreground(self, serial):
            self.calls["foreground"] += 1
            return super().foreground(serial)

        def dump_retry(self, serial, tries=3, wait=0.6):
            self.calls["dump"] += 1
            return super().dump_retry(serial, tries, wait)

    fw_q = _QuietWalk([{"act": "com.test.app.S", "nodes": ["正文"]}])
    with _Patcher(fw_q):
        C.observe_screen = lambda *a, **k: None
        out_q = C._pre_consent_settle(
            ScanResult(package="com.test.app", device_serial="s1"),
            "s1", time.time() + 1.0, (lambda *_: None), poll=0.05, quiet=0.9)
    check("静默段内几乎不发 adb 命令",
          fw_q.calls["foreground"] + fw_q.calls["dump"] <= 4, fw_q.calls)
    check("静默段结束后仍会继续工作", out_q.get("seconds") is not None, out_q)

    # ---- ⑦ 判定层：探索过就不再写"仅静置观察" ----
    class _S:
        def __init__(self, pe):
            self.depth = "pre"
            self.consent_given = False
            self.consent_elapsed_ms = None
            self.consent_source = ""
            self.events = []
            self.ui_steps = []
            self.errors = []
            self.ui_taps = 0
            self.screenshots = []
            self.pre_explore = pe

    for pe, want, banned in (
        ({"taps": 7, "screens": 3, "why": "", "refused_exit": []},
         "点击 7 次", "静置观察"),
        ({"taps": 0, "screens": 0, "why": "没点到", "refused_exit": []},
         "静置观察", "点击 7 次"),
    ):
        r = SOP.FlowRunner(log=lambda *_a: None)
        r.scan = _S(pe)
        pr = r.p1_pre_consent()
        blob = " ".join(pr.steps) + " " + " ".join(pr.warnings)
        check("探索=%d 时步骤写「%s」" % (pe["taps"], want), want in blob, blob[:160])
        check("探索=%d 时不出现「%s」" % (pe["taps"], banned), banned not in blob,
              blob[:160])

    # ---- ⑧ 档位：1 档给了足够预算（150 秒时政策观测就占 45 秒）----
    from piiscan.config import DEPTH_PROFILES
    check("1 档总预算 ≥ 300 秒", DEPTH_PROFILES["pre"]["duration"] >= 300,
          DEPTH_PROFILES["pre"]["duration"])
    check("1 档仍然声明 consent_only", DEPTH_PROFILES["pre"]["consent_only"] is True)

    # ---- ⑨ 复现步骤：1 档要列出真正点过的路径 ----
    # 这里有个容易写错的地方：旧代码剥"同意那一步"用的是 `act not in s`，
    # 而 1 档 act 默认是「同意」，探索步骤「未同意状态：点击「不同意」」
    # 里含「同意」二字，于是整段路径被剥光，⑦ 变成空白 ——
    # 报告上看就是"这一档什么都没点"，与事实相反。
    r9 = SOP.FlowRunner(log=lambda *_a: None)
    r9.scan = _S_with(ui_steps=["未同意状态：点击「不同意」",
                               "未同意状态：点击「首页」"],
                      pe={"taps": 2, "screens": 2, "why": "", "refused_exit": []})
    r9.p1_pre_consent()
    r9._build_repro()
    _b9 = " ".join(r9.fr.repro)
    check("1 档复现步骤写「未同意状态下…探索」", "未同意状态下" in _b9, _b9[:200])
    check("1 档复现步骤里能看到点过「不同意」", "点击「不同意」" in _b9, _b9[:200])
    check("1 档复现步骤不写「同意后按本轮实际路径遍历」",
          "同意后按本轮实际路径遍历" not in _b9, _b9[:200])

    # 对照：2 档仍然走"同意后遍历"，不能被改坏
    r10 = SOP.FlowRunner(log=lambda *_a: None)
    r10.scan = _S_with(ui_steps=["同意：点击「同意并继续」", "点击「我的」"],
                       depth="light", given=True, cms=5000)
    r10.p1_pre_consent()
    r10._build_repro()
    _b10 = " ".join(r10.fr.repro)
    check("2 档复现步骤仍写「同意后」", "同意后" in _b10, _b10[:200])
    check("2 档不会误挂 1 档的探索字样", "未同意状态下" not in _b10, _b10[:200])


if __name__ == "__main__":
    OK = FAIL = 0

    def check(name, cond, got=""):
        global OK, FAIL
        if cond:
            OK += 1
            print("  PASS", name)
        else:
            FAIL += 1
            print("  FAIL", name, "实际：%r" % (got,))

    run(check)
    print("结果：%d 项通过，%d 项失败" % (OK, FAIL))
    raise SystemExit(1 if FAIL else 0)
