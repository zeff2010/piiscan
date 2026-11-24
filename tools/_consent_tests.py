"""同意动作（分水岭）登记的回归测试（不连真机）。

守的是用户明确提的要求：**「同意」必须登记成事件，作为「同意前 / 同意后」的分水岭**。

真机撞到的问题（以观书法 mbsf6）：
    AI 在政策下钻时顺手点了「同意并继续」，界面确实变了，
    但那条点击走的不是任何一条既有登记路径 → `consent_given` 始终 False、
    50 条事件全标"同意前"、P3 写"未捕获到同意事件"，
    而正文却写着"时序不可分辨" —— 同一份底稿自己跟自己打架。

这里覆盖的正是那条断掉的链：
  ① 任意路径点到同意按钮都要登记（首启 / 下钻 / 遍历 / 脚本观测）；
  ② 分水岭只认**第一条**，后续同意动作留痕但不改边界；
  ③ 中性确认（确定/允许）不算分水岭；
  ④ 点击完全没反应（signal=""）不能算同意；
  ⑤ 脚本同步失败**不能**把"已经同意"这个事实吞掉；
  ⑥ 事件流里必须留下一条 CONSENT 标记，且它不算"收集行为"；
  ⑦ 收尾兜底：老存档只有布尔位时，补齐分水岭并插回时间轴正确位置。
"""
from __future__ import annotations

import base64
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiscan import collector as C                 # noqa: E402
from piiscan.models import PIIEvent                # noqa: E402

OK = 0
BAD: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global OK
    if cond:
        OK += 1
    else:
        BAD.append("%s%s" % (name, ("　→ " + detail) if detail else ""))
        print("  ✗ %s%s" % (name, ("　→ " + detail) if detail else ""))


# 1×1 PNG：只验证"有没有留图"，不验证图像质量
_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")

_real_capture = C.capture_screenshot
_real_top = C.uiwalk.top_activity


def _install_fakes(png: bool = True):
    C.capture_screenshot = lambda serial="": (_PNG if png else b"")
    C.uiwalk.top_activity = lambda serial="": "com.demo/.MainActivity"


def _uninstall_fakes():
    C.capture_screenshot = _real_capture
    C.uiwalk.top_activity = _real_top


def _node(label: str):
    from types import SimpleNamespace
    return SimpleNamespace(label=label, text=label)


def _res(max_shots: int = 14, n_ordinary: int = 0):
    r = C.ScanResult(package="com.demo")
    # 用当前时钟：不传 elapsed_ms 的用例会按 (now - started_at) 反推时刻
    r.started_at = time.time()
    r.max_shots = max_shots
    r.screenshots = [{"label": "UI 遍历第 %d 步" % i, "activity": "a", "b64": "x"}
                     for i in range(n_ordinary)]
    return r


def _marker(res):
    return [e for e in res.events if getattr(e, "signal", "") == "CONSENT"]


# ============================================================ ① 判定强度
def t_kind():
    check("「同意并继续」= explicit",
          C._consent_label_kind("同意并继续")[0] == "explicit")
    check("「我已阅读并同意《隐私政策》」= checkbox",
          C._consent_label_kind("我已阅读并同意《隐私政策》")[0] == "checkbox")
    check("遍历途中「确定」= weak（不计分水岭）",
          C._consent_label_kind("确定")[0] == "weak")
    check("政策告知弹窗上的「确定」= explicit",
          C._consent_label_kind("确定", in_policy_dialog=True)[0] == "explicit")
    check("「不同意并退出」不是同意",
          C._consent_label_kind("不同意并退出")[0] == "")
    check("长正文不是按钮",
          C._consent_label_kind("我们非常重视您的个人信息保护，本政策将向您说明" * 3)[0] == "")


# ============================================================ ② 首启弹窗登记
def t_first_launch():
    _install_fakes()
    try:
        r = _res()
        ok = C._mark_consent(r, "同意并继续", "首启隐私弹窗点击", print,
                             set_consent=lambda l: None, strength="explicit",
                             elapsed_ms=4200)
        check("首启点同意 → 登记成功", ok is True)
        check("consent_given=True", r.consent_given is True)
        check("consent_strength=explicit", r.consent_strength == "explicit")
        check("同意时刻已记（4200ms）", r.consent_elapsed_ms == 4200)
        check("consent_events 有 1 条", len(r.consent_events) == 1)
        check("该条标记为分水岭", r.consent_events[0]["watershed"] is True)
        check("脚本同步标记为 ok", r.consent_events[0]["sync"] == "ok")
        m = _marker(r)
        check("事件流里有 CONSENT 标记", len(m) == 1)
        check("标记事件不属于「同意前」", m[0].before_consent is False)
        check("标记事件带 noise 说明", bool(m[0].noise))
        check("标记事件不计入 before_consent_events",
              len(r.before_consent_events) == 0)
        check("分水岭已留取证图",
              any(s["label"].startswith("同意动作") for s in r.screenshots))
    finally:
        _uninstall_fakes()


# ============================================================ ③ 分界只认第一条
def t_only_first():
    _install_fakes()
    try:
        r = _res()
        C._mark_consent(r, "同意并继续", "首启弹窗", print, strength="explicit",
                        elapsed_ms=3000)
        second = C._mark_consent(r, "我已阅读并同意", "登录页勾选", print,
                                 strength="checkbox", elapsed_ms=90000)
        check("第二次同意不成为分水岭", second is False)
        check("同意时刻未被冲掉（仍 3000ms）", r.consent_elapsed_ms == 3000)
        check("两次动作都留痕", len(r.consent_events) == 2)
        check("第二条写明是重复动作", "重复" in (r.consent_events[1].get("why") or ""))
        check("事件流里仍只有 1 条分水岭标记", len(_marker(r)) == 1)
    finally:
        _uninstall_fakes()


# ============================================================ ④ 下钻路径（mbsf6）
def t_drill_path():
    _install_fakes()
    try:
        r = _res()
        ok = C._mark_consent_after_tap(r, _node("同意并继续"),
                                       "政策下钻点击（AI 指定目标）", print,
                                       signal="ui", screen_label="首启弹窗")
        check("★ 政策下钻点到同意按钮也能登记（mbsf6 漏的就是这条）", ok is True)
        check("登记来源记为下钻",
              (r.consent_events[0].get("via") or "").startswith("政策下钻"))
        check("下钻登记后事件流有分水岭", len(_marker(r)) == 1)
    finally:
        _uninstall_fakes()


# ============================================================ ⑤ 点击落空不算同意
def t_no_signal():
    _install_fakes()
    try:
        r = _res()
        ok = C._mark_consent_after_tap(r, _node("同意并继续"), "政策入口点击",
                                       print, signal="")
        check("★ 框内所有采样点都没反应 → 不认定同意", ok is False)
        check("未同意时 consent_given 保持 False", r.consent_given is False)
        check("仍留一条候选记录（可审计）", len(r.consent_events) == 0,
              "落空连候选都不记：%d 条" % len(r.consent_events))
    finally:
        _uninstall_fakes()


# ============================================================ ⑥ 中性确认不算
def t_weak():
    _install_fakes()
    try:
        r = _res()
        ok = C._mark_consent_after_tap(r, _node("确定"), "遍历·调度器点击",
                                       print, signal="ui")
        check("遍历中「确定」不成为分水岭", ok is False)
        check("中性确认仍留候选记录", len(r.consent_events) == 1)
        check("候选写明不计分水岭",
              "中性确认" in (r.consent_events[0].get("why") or ""))
        check("候选强度=weak", r.consent_events[0].get("strength") == "weak")
    finally:
        _uninstall_fakes()


# ============================================================ ⑦ 同步失败不吞事实
def t_sync_failed():
    _install_fakes()
    try:
        r = _res()

        def _boom(l):
            raise RuntimeError("script has been destroyed")

        ok = C._mark_consent(r, "同意并继续", "首启弹窗", print,
                             set_consent=_boom, strength="explicit")
        check("★ 脚本同步失败仍认定同意（不把「没同步成」写成「没同意」）",
              ok is True and r.consent_given is True)
        check("同步失败写进候选记录",
              str(r.consent_events[0].get("sync") or "").startswith("failed"))
        check("同步失败写进 errors（报告可见）",
              any("同步" in e for e in r.errors))
    finally:
        _uninstall_fakes()


# ============================================================ ⑧ 截图独立配额
def t_shot_quota():
    _install_fakes()
    try:
        r = _res(max_shots=14, n_ordinary=14)     # 普通配额已吃光
        C._mark_consent(r, "同意并继续", "首启弹窗", print, strength="explicit")
        check("★ 普通配额用满时，分水岭仍留取证图",
              any(s["label"].startswith("同意动作") for s in r.screenshots))
    finally:
        _uninstall_fakes()


def t_shot_failed():
    _install_fakes(png=False)
    try:
        r = _res()
        ok = C._mark_consent(r, "同意并继续", "首启弹窗", print, strength="explicit")
        check("截图失败不影响同意事实", ok is True and r.consent_given is True)
        check("截图失败写进备注", "截图失败" in (r.consent_events[0].get("why") or ""))
    finally:
        _uninstall_fakes()


# ============================================================ ⑨ 收尾兜底
def t_ensure_marker():
    _install_fakes()
    try:
        # 老存档形态：只有布尔位 + 时刻，事件流里没有分水岭
        r = _res()
        r.consent_given = True
        r.consent_source = "ui:同意并继续"
        r.consent_elapsed_ms = 8000
        r.events = [
            PIIEvent(hook_id="H", category="device_id", api="getDeviceId",
                     ts=1002000, elapsed_ms=2000, before_consent=True),
            PIIEvent(hook_id="H", category="device_id", api="getDeviceId",
                     ts=1030000, elapsed_ms=30000, before_consent=False),
        ]
        added = C._ensure_consent_marker(r, print)
        check("★ 只有布尔位时能补齐分水岭事件", added is True)
        m = _marker(r)
        check("补齐后事件流有且仅有 1 条分水岭", len(m) == 1)
        check("补齐的分水岭按时刻插回时间轴（不在末尾）",
              r.events.index(m[0]) == 1, "实际位置 %d" % r.events.index(m[0]))
        check("补齐的分水岭带上正确时刻", m[0].elapsed_ms == 8000)
        check("补齐后仍不被算作「同意前」事件",
              len([e for e in r.before_consent_events
                   if getattr(e, "signal", "") == "CONSENT"]) == 0)
        check("重复调用不再插入第二条",
              C._ensure_consent_marker(r, print) is False)
    finally:
        _uninstall_fakes()


def t_ensure_noop():
    _install_fakes()
    try:
        r = _res()
        check("未同意时不补分水岭", C._ensure_consent_marker(r, print) is False)
        check("未同意时事件流保持干净", len(r.events) == 0)
    finally:
        _uninstall_fakes()


# ============================================================ ⑩ 存档往返
def t_roundtrip():
    _install_fakes()
    try:
        r = _res()
        C._mark_consent(r, "同意并继续", "首启弹窗", print, strength="explicit",
                        elapsed_ms=5000)
        d = r.to_dict()
        r2 = C.ScanResult.from_dict(d)
        check("存档往返后 consent_events 保留", len(r2.consent_events) == 1)
        check("存档往返后 consent_strength 保留", r2.consent_strength == "explicit")
        check("存档往返后分水岭标记保留", len(_marker(r2)) == 1)
    finally:
        _uninstall_fakes()


# ============================================================ ⑧ 分水岭=点击那一瞬
def _ev(ts, elapsed, before=True, noise="", api="x"):
    from types import SimpleNamespace
    return SimpleNamespace(ts=ts, elapsed_ms=elapsed,
                           before_consent=before, noise=noise, api=api)


def _res_with_clocks(offset_ms: int = 133, launch_pc: float = 1022.0):
    """造一份"设备时钟比本机快 offset_ms"的采集结果。"""
    r = C.ScanResult(package="com.demo")
    r.started_at = 1000.0                  # 采集开始（本机）
    r.marks["app_launched"] = int((launch_pc - 1000.0) * 1000)
    return r, launch_pc * 1000 + offset_ms  # 返回设备侧的启动时刻（epoch ms）


def t_tap_moment():
    """点击回调里同步发生的事件，不能被算成"同意前"。

    真机（驿站助手 2026-11-18，红米9）：`input tap` 10:57:37.685 →
    应用 `StartActivity$4.onClick` .777 → 读 android_id .792，
    而同意登记要到 10:57:42.7（晚 5 秒）—— 88 条事件里 69 条被标"同意前"，
    照这份标记出报告就会写"未经同意读取 Android ID"。
    """
    r, dev_launch = _res_with_clocks()
    # 启动时的时区读取：点击之前，不能动
    r.events.append(_ev(dev_launch + 924, 924, api="SystemProperties.get"))
    # 点击（本机 1030.0）之后 107ms 读 android_id —— 属于同意动作本身
    tap_pc = 1030.0
    r.consent_tap_at = tap_pc
    r.events.append(_ev(dev_launch + 8107, 8107, api="getStringForUser"))
    # 点击后 2 秒：仍是同意之后，但不算"同一交互"
    r.events.append(_ev(dev_launch + 12000, 12000, api="URL.openConnection"))
    check("时钟偏移按 (ts-elapsed) 中位数还原", C._clock_offset_ms(r) == 133)
    n = C._reclassify_consent_boundary(r, log=lambda *_: None)
    check("点击之后的事件被改判（2 条）", n == 2, str(n))
    check("点击之前的那条仍是同意前",
          r.events[0].before_consent is True)
    check("点击同一交互内的那条不再是同意前",
          r.events[1].before_consent is False)
    check("同一交互计数只含 1.5 秒内的（1 条）",
          r.consent_sync_events == 1, str(r.consent_sync_events))
    check("改判条数已落盘", r.consent_reclassified == 2)


def t_tap_moment_noise():
    """系统噪声事件即使落在点击之后也不改判（它本来就不参与认定）。"""
    r, dev_launch = _res_with_clocks()
    r.consent_tap_at = 1030.0
    r.events.append(_ev(dev_launch + 8200, 8200, noise="系统自身行为"))
    n = C._reclassify_consent_boundary(r, log=lambda *_: None)
    check("噪声事件不改判", n == 0 and r.events[0].before_consent is True)
    check("噪声仍计入同一交互的观察条数", r.consent_sync_events == 1)


def t_clock_offset_bad():
    """时基错乱的一条事件不能把时钟偏移带走（实测吃到过 -22.3 秒）。"""
    r, dev_launch = _res_with_clocks()
    r.events.append(_ev(dev_launch + 1000, 1000))
    r.events.append(_ev(dev_launch + 2000, 2000))
    # 收尾补齐的分水岭事件：ts 按采集开始造，elapsed 却填进程相对值
    r.events.append(_ev(1000 * 1000, 120000))
    check("个别错乱事件不影响偏移估算", C._clock_offset_ms(r) == 133,
          str(C._clock_offset_ms(r)))
    # 全部事件都跨了进程（差 200 秒）→ 估不出来时返回 None，不硬算
    r2, _ = _res_with_clocks()
    r2.events.append(_ev(500 * 1000, 1000))   # 与本机时钟差约 8 分钟
    check("偏移超过合理上限时返回 None", C._clock_offset_ms(r2) is None)


def t_scope_consent_sync():
    """简版「本轮检测范围」要把同意交互与 1 档的观测边界写出来。"""
    from piiscan.report.sop_brief import _scope_line
    d = {"depth": "light", "consent_sync_events": 68}
    line = _scope_line(d)
    check("2 档写明同一交互条数", "68 条事件与「同意」点击属于同一交互" in line, line)
    check("2 档写明不计为同意前收集", "不计为同意前收集" in line, line)
    d2 = {"depth": "pre", "pre_explore": {"taps": 2, "screens": 3}}
    line2 = _scope_line(d2)
    check("1 档写明不执行同意动作", "本轮不执行同意动作" in line2, line2)
    check("1 档写明观测边界", "不在本轮观测范围内" in line2, line2)
    check("1 档不写同意交互条数", "同一交互" not in line2, line2)


def t_flow_carries_consent_sync():
    """同意复核结果必须进 flow.json —— 简版只读 flow.json，不进就等于没算。

    真机踩过：字段只加在 ScanResult 上，_scope_line 从 flow.json 取不到，
    报告那句"47 条与同意点击同一交互"就永远不出现，而且屏幕上看着很正常。
    """
    from piiscan.flow.models import FlowResult
    fr = FlowResult()
    d = fr.to_dict()
    check("flow.json 带 consent_sync_events", "consent_sync_events" in d)
    check("flow.json 带 consent_reclassified", "consent_reclassified" in d)
    check("默认值为 0（旧存档读进来不会炸）",
          d.get("consent_sync_events") == 0 and d.get("consent_reclassified") == 0)


def main() -> int:
    for fn in (t_kind, t_first_launch, t_only_first, t_drill_path, t_no_signal,
               t_weak, t_sync_failed, t_shot_quota, t_shot_failed,
               t_ensure_marker, t_ensure_noop, t_roundtrip,
               t_tap_moment, t_tap_moment_noise, t_clock_offset_bad,
               t_scope_consent_sync, t_flow_carries_consent_sync):
        fn()
    print("\n同意动作（分水岭）回归：%d 项通过，%d 项失败" % (OK, len(BAD)))
    for b in BAD:
        print("  - %s" % b)
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
