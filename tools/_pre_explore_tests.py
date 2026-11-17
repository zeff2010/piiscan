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
        return {"package": s.get("pkg", "com.test.app"),
                "activity": s.get("act", "com.test.app.MainActivity")}

    def dump_retry(self, serial, tries=3, wait=0.6):
        return "XML-%d" % self.idx

    def parse_all(self, xml):
        i = int(str(xml).split("-")[1])
        return [_node(lab, 100, 100 + 60 * k)
                for k, lab in enumerate(self.screens[i]["nodes"])]

    def screen_texts(self, xml):
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

    # ---- ④ 弹窗上要优先点「不同意」，绝不点「同意并继续」----
    fw = FakeWalk([
        {"act": "com.test.app.PrivacyDialog", "nodes": ["《隐私政策》", "同意并继续", "不同意"],
         "on_tap": {"不同意": 1, "《隐私政策》": 0, "同意并继续": 0}},
        {"act": "com.test.app.Home", "nodes": ["首页", "我的", "搜索"],
         "on_tap": {"首页": 1, "我的": 1, "搜索": 1}},
    ])
    res, out, log = _run_explore(fw)
    check("探索确实点了元素", out["taps"] > 0, out)
    check("一次都没点同意", "同意并继续" not in fw.tapped, fw.tapped)
    check("优先点了「不同意」", fw.tapped and fw.tapped[0] == "不同意", fw.tapped)
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
