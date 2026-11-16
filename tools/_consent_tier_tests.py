# -*- coding: utf-8 -*-
"""1 档「仅同意前」的时序口径回归（不连真机）。

起因（使用者 2026-11-16）：1 档跑出来的报告写
    「本次在同意动作前后 1500 ms 窗口内观测到个人信息的读取」
    「同意时刻：未记录」
可 1 档的口径是**取到政策正文就收工，不点同意、不遍历** —— 整轮根本没有
同意动作，所有读取本来就发生在未同意状态下。那句话等于凭空造了一个窗口，
还把"没有同意动作"写成了"漏记了同意时刻"。

守的三件事：
  ① 没有同意动作的轮次，一律按"确认在同意前"，不许判成"时序不可分辨"；
  ② 措辞里不许出现 1500 ms 窗口 / 同意时刻未记录（那是另一种情形）；
  ③ 真捕获到同意动作的轮次，原来那套边界窗口口径不能被改坏。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiscan.flow import compare as CMP      # noqa: E402
from piiscan.flow import models as M         # noqa: E402
from piiscan.flow import sop as SOP          # noqa: E402
from piiscan.models import PIIEvent          # noqa: E402


def _ev(**kw):
    base = dict(hook_id="h1", category="device", api="Settings.Secure.getString",
                args="name=android_id", result="", thread="main",
                ts=1000, elapsed_ms=3000, before_consent=True,
                stack=[], pi="设备标识符", group="设备标识符")
    base.update(kw)
    return PIIEvent(**base)


class _Scan:                                  # 假 ScanResult
    def __init__(self, depth="pre", given=False, cms=None, events=None,
                 ui_steps=None):
        self.depth = depth
        self.consent_given = given
        self.consent_elapsed_ms = cms
        self.consent_source = "ui:同意并继续" if given else ""
        self.events = events or []
        self.ui_steps = ui_steps or []
        self.errors = []
        self.ui_taps = 0
        self.screenshots = []


def _run_p1(scan):
    r = SOP.FlowRunner(log=lambda *_a: None)
    r.scan = scan
    return r, r.p1_pre_consent()


def run(check) -> None:
    print("— 1 档「仅同意前」的时序口径")

    # ---- ① 分类函数：没有同意动作 ≠ 时序不可分辨 ----
    e_stack = _ev(stack=["com.x.AgreementDialog.onConfirm", "com.x.Boot.onCreate"],
                  elapsed_ms=7000)
    check("没有同意动作时，同意链栈也归入「同意前」",
          CMP.classify_consent(e_stack, None, consent_absent=True) == "before",
          CMP.classify_consent(e_stack, None, consent_absent=True))
    check("没有同意时刻、但确有同意动作时，仍按「不可分辨」保守处理",
          CMP.classify_consent(e_stack, None) == "edge")
    check("离同意很远的读取仍算「同意前」",
          CMP.classify_consent(_ev(elapsed_ms=2000), 9000) == "before")
    check("紧邻同意的读取算「不可分辨」",
          CMP.classify_consent(_ev(elapsed_ms=8900), 9000) == "edge")
    check("晚于同意的读取算「同意后」",
          CMP.classify_consent(_ev(elapsed_ms=9500), 9000) == "after")

    evs = [_ev(elapsed_ms=t) for t in (1000, 3000, 5000)]
    b, e, a = CMP.split_by_consent(evs, None, consent_absent=True)
    check("没有同意动作时全部落在「同意前」，边界事件为 0",
          len(b) == 3 and len(e) == 0 and len(a) == 0, (len(b), len(e), len(a)))

    # ---- ② 档位判定：只有 1 档能断言"没有同意动作" ----
    def _absent(depth, given=False, cms=None):
        r = SOP.FlowRunner(log=lambda *_a: None)
        r.scan = _Scan(depth=depth, given=given, cms=cms)
        return r._consent_absent()

    check("1 档 + 未登记同意 → 确定没有同意动作", _absent("pre") is True)
    check("1 档 + 已登记同意 → 不能再说没有", _absent("pre", given=True, cms=5000) is False)
    check("2 档 + 未捕获同意 → 不能说成「没有同意动作」", _absent("light") is False)
    check("2 档 + 有同意时刻 → 不是「没有同意动作」",
          _absent("light", given=True, cms=5000) is False)

    # ---- ③ 1 档实跑：观测到读取但没取到取值 ----
    scan = _Scan(events=[_ev(elapsed_ms=1000 + i * 700) for i in range(12)])
    r, pr = _run_p1(scan)
    st = r.fr.items.get("Q002")
    reason = (getattr(st, "reason", "") or "")
    check("1 档判「跳过未测」（没取到取值，证据不足以认定）",
          getattr(st, "state", "") == M.NOT_TESTED, getattr(st, "state", ""))
    check("★ 1 档结论里不出现「1500 ms 窗口」", "1500" not in reason, reason)
    check("★ 1 档结论里不出现「同意动作前后」", "同意动作前后" not in reason, reason)
    check("1 档结论写明本轮未执行同意动作", "未执行「同意」动作" in reason, reason)
    facts = dict(getattr(st, "facts", []) or [])
    check("事实表写明「同意动作：本轮未执行」",
          "本轮未执行" in str(facts.get("同意动作", "")), facts)
    check("事实表不再写「同意时刻：未记录」",
          "同意时刻" not in " ".join(facts.keys()), list(facts.keys()))

    q3 = r.fr.items.get("Q003")
    check("Q003 给出本轮自己的结论，而不是「缺少阶段 P3 的证据」",
          "缺少阶段" not in (getattr(q3, "reason", "") or ""),
          getattr(q3, "reason", ""))
    check("Q003 如实写「未取得任何个人信息取值」",
          "未取得任何个人信息取值" in (getattr(q3, "reason", "") or ""),
          getattr(q3, "reason", ""))

    # ---- ④ 1 档取到取值 + 有栈 → 确证"未同意状态下已收集" ----
    scan = _Scan(events=[
        _ev(elapsed_ms=2000, result="260618dfb57fd814",
            stack=["com.x.Boot.onCreate", "com.x.MainActivity$1.run"])])
    r, pr = _run_p1(scan)
    st = r.fr.items.get("Q002")
    desc = getattr(st, "desc", "") or ""
    check("1 档取到取值时判「发现问题」", getattr(st, "state", "") == M.FAIL,
          getattr(st, "state", ""))
    check("★ 1 档的结论措辞是「未执行同意动作、全程未同意状态」",
          "未执行「同意」动作" in desc and "未同意状态" in desc, desc)
    check("1 档的结论不再写「在用户同意隐私政策之前」",
          "同意隐私政策之前" not in desc, desc)

    # ---- ⑤ 回归：真捕获到同意动作的轮次，边界窗口口径不能被改坏 ----
    scan = _Scan(depth="light", given=True, cms=8000,
                 events=[_ev(elapsed_ms=7000),
                         _ev(elapsed_ms=9000, before_consent=False)])
    r, pr = _run_p1(scan)
    st = r.fr.items.get("Q002")
    desc = getattr(st, "desc", "") or ""
    check("捕获到同意时刻时仍按 1500 ms 窗口表述", "1500" in desc, desc)
    check("仍写明「时序不可分辨」", "时序不可分辨" in desc, desc)

    # ---- ⑥ 回归：捕获到同意动作但没时刻 → 不许出现窗口 ----
    scan = _Scan(depth="light", given=True, cms=None,
                 events=[_ev(elapsed_ms=7000)])
    r, pr = _run_p1(scan)
    st = r.fr.items.get("Q002")
    desc = getattr(st, "desc", "") or ""
    check("★ 同意时刻没记录时不许出现 1500 ms 窗口", "1500" not in desc, desc)
    check("并如实写「未记录到同意时刻」", "未记录到同意时刻" in desc, desc)

    # ---- ⑦ 操作步骤与 P3：1 档不许假装点了同意、也不许告警 ----
    src = (ROOT / "piiscan" / "flow" / "sop.py").read_text(encoding="utf-8")
    check("操作步骤里 1 档写明不执行同意动作",
          "本档位不执行「同意」动作" in src)
    check("操作步骤不再无条件写「点击「同意」，随后开始同意后功能遍历」",
          src.count("随后开始同意后功能遍历") <= 2, src.count("随后开始同意后功能遍历"))

    r = SOP.FlowRunner(log=lambda *_a: None)
    r.scan = _Scan(events=[_ev()])
    pr = r.p3_consent() if hasattr(r, "p3_consent") else None
    if pr is not None:
        check("1 档的 P3 判「跳过」而不是「部分完成」",
              pr.status == M.PHASE_SKIPPED, pr.status)
        check("1 档的 P3 不再告警「未捕获到同意动作」",
              not any("未捕获到" in w for w in (pr.warnings or [])), pr.warnings)


if __name__ == "__main__":
    OK = FAIL = 0

    def _check(name, cond, got=""):
        global OK, FAIL
        if cond:
            OK += 1
            print("  PASS", name)
        else:
            FAIL += 1
            print("  FAIL", name, "实际：%r" % (got,))

    run(_check)
    print("结果：%d 项通过，%d 项失败" % (OK, FAIL))
    raise SystemExit(1 if FAIL else 0)
