#!/usr/bin/env python3
"""P7 复现判定的离线自测。

复现这件事最容易出的不是"跑不通"，而是**把三种结果说成两种**：
  · 把"复现轮没采到数据"写成"未复现" → 等于用工具没电去否定一个真实发现；
  · 把"未复现"仍写成确证 → 夸大结论；
  · 把"已复现"错降成疑似 → 真实问题被稀释。
三种都是文字层面的错，跑起来一声不响，只能在离线把口径钉死。

跑法：python tools/_repro_tests.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class E:
    """假事件，字段对齐 PIIEvent（compare.event_pi 只读这几个）。"""

    def __init__(self, api, result="", category="", sink="", before=False,
                 noise="", hook_id="", stack=None):
        self.api, self.result, self.category = api, result, category
        self.sink, self.before_consent, self.noise = sink, before, noise
        self.hook_id, self.stack = hook_id, stack or []
        self.args, self.elapsed_ms = "", 0


def scan(events=(), perms=(), policy=None, package="com.demo.app"):
    return SimpleNamespace(
        package=package, events=list(events), perm_scenes=list(perms),
        policy_capture=policy or {"outcome": "not_found", "bestText": ""},
        aborted=False, device_serial="",
    )


IMEI = E("TelephonyManager.getImei", result="867686023456789", category="api")
LOC = E("LocationManager.getLastKnownLocation", result="39.9,116.3", category="api")
SMS = E("TelephonyManager.getLine1Number", result="+8613800138000", category="api")


def sdk_event(api="TelephonyManager.getImei", result="867686023456789",
              pkg="com.bytedance.sdk.openadsdk"):
    """一条能归因到穿山甲的事件（堆栈落在字节的 SDK 包里）。"""
    e = E(api, result=result, category="api")
    e.stack = ["%s.core.b.j(SourceFile:120)" % pkg,
               "%s.TTAdManager.get(SourceFile:88)" % pkg]
    return e


def item(qid, title, state, ev_kind, detail):
    from piiscan.flow.models import Evidence, ItemState
    it = ItemState(qid=qid, title=title, state=state,
                   evidence=[Evidence(kind=ev_kind, title=title, detail=detail)])
    return it


def run(check) -> None:
    from piiscan.flow import repro as R
    from piiscan.flow.models import FlowResult

    # ---------------------------------------------------------------- 观测集
    o1 = R.observe(scan([IMEI, LOC]))
    check("观测集：认得出设备标识（P01）", "P01" in o1["pis"], sorted(o1["pis"]))
    check("观测集：记下了调用的 API", "TelephonyManager.getImei" in o1["apis"])

    # 未同意阶段的事件不算：那是另一项结论，不能拿来当复现判据
    e_pre = E("TelephonyManager.getImei", result="867686023456789", before=True)
    check("观测集：未同意阶段的事件不计入",
          "P01" not in R.observe(scan([e_pre]))["pis"])
    # 噪声 / 外发去向 / 没取到有效值，都不算"收集"
    check("观测集：噪声事件不计入",
          "P01" not in R.observe(scan([E("TelephonyManager.getImei", result="x",
                                         noise="系统调用")]))["pis"])
    check("观测集：空返回值不计入",
          "P01" not in R.observe(scan([E("TelephonyManager.getImei", result="")]))["pis"])
    check("观测集：sink 不计入",
          "P01" not in R.observe(scan([E("TelephonyManager.getImei",
                                         result="867686023456789",
                                         category="api_sink")]))["pis"])

    # ---------------------------------------------------------------- 事件类
    fr = FlowResult(package="com.demo.app")
    fr.items = {
        "Q008": item("Q008", "超范围收集个人信息", "fail", "frida",
                     "TelephonyManager.getImei 被调用 3 次（P01 设备标识）"),
        "Q001": item("Q001", "隐私政策总体质量", "pass", "policy", "政策完整"),
    }
    s1 = scan([IMEI, LOC])
    s2_same = scan([IMEI, LOC])
    s2_diff = scan([LOC])
    s2_empty = scan([])

    rs = R.judge(fr, s1, s2_same)
    check("待复现项只含 fail/suspect（pass 不进列表）",
          [r["qid"] for r in rs] == ["Q008"], [r["qid"] for r in rs])
    check("事件类：同一调用再现 → 已复现", rs[0]["reproduced"] is True, rs[0])

    rs = R.judge(fr, s1, s2_diff)
    check("事件类：判据未再现 → 未复现", rs[0]["reproduced"] is False, rs[0])
    check("事件类：未复现的说明里写清复现轮采到多少条",
          "1 条" in rs[0]["note"], rs[0]["note"])

    rs = R.judge(fr, s1, s2_empty)
    check("事件类：复现轮一条都没采到 → 未能判定（不是未复现）",
          rs[0]["reproduced"] is None, rs[0])
    check("事件类：未能判定的说明写明原因", "未采到" in rs[0]["note"], rs[0]["note"])

    rs = R.judge(fr, s1, None)
    check("第二轮没跑成 → 全部未能判定", rs[0]["reproduced"] is None, rs[0])
    check("第二轮没跑成 → 说明写未执行", "未执行" in rs[0]["how"], rs[0]["how"])

    # ---------------------------------------------------------------- 降级
    fr2 = FlowResult(package="com.demo.app")
    fr2.items = {
        "Q008": item("Q008", "超范围收集个人信息", "fail", "frida",
                     "TelephonyManager.getImei 被调用 3 次"),
    }
    R.apply(fr2, R.judge(fr2, s1, s2_diff))
    check("未复现：fail 降为 suspect", fr2.items["Q008"].state == "suspect",
          fr2.items["Q008"].state)
    check("未复现：置信度改成疑似", fr2.items["Q008"].confidence == "疑似",
          fr2.items["Q008"].confidence)
    check("未复现：理由里写明为何降级",
          "未再次出现" in fr2.items["Q008"].reason, fr2.items["Q008"].reason)

    fr3 = FlowResult(package="com.demo.app")
    fr3.items = {
        "Q008": item("Q008", "超范围收集个人信息", "fail", "frida",
                     "TelephonyManager.getImei 被调用 3 次"),
    }
    R.apply(fr3, R.judge(fr3, s1, s2_same))
    check("已复现：状态保持 fail（不因复现而改判）",
          fr3.items["Q008"].state == "fail", fr3.items["Q008"].state)

    fr4 = FlowResult(package="com.demo.app")
    fr4.items = {
        "Q008": item("Q008", "超范围收集个人信息", "fail", "frida",
                     "TelephonyManager.getImei 被调用 3 次"),
    }
    R.apply(fr4, R.judge(fr4, s1, s2_empty))
    check("未能判定：状态不变（不许用没跑成去否定发现）",
          fr4.items["Q008"].state == "fail", fr4.items["Q008"].state)

    # ---------------------------------------------------------------- 权限类
    perm_none = {"perm": "位置信息", "purpose": "none", "dialog_text": "允许访问位置信息吗？"}
    perm_ok = {"perm": "位置信息", "purpose": "dialog", "dialog_text": "允许访问位置信息吗？",
               "explain": "用于展示附近门店"}
    frp = FlowResult(package="com.demo.app")
    frp.items = {
        "Q026": item("Q026", "申请权限未同步告知目的", "fail", "ui",
                     "位置信息（未同步告知）"),
    }
    rp = R.judge(frp, scan(perms=[perm_none]), scan(perms=[perm_none]))
    check("权限类：同一权限再次未告知 → 已复现", rp[0]["reproduced"] is True, rp[0])
    rp = R.judge(frp, scan(perms=[perm_none]), scan(perms=[perm_ok]))
    check("权限类：这次说明了目的 → 未复现", rp[0]["reproduced"] is False, rp[0])
    check("权限类：未复现的说明写清是同一权限、且这次看到了用途说明",
          "位置信息" in rp[0]["note"] and "用途说明" in rp[0]["note"],
          rp[0]["note"])

    # 本轮申请了**别的**权限 → 不能拿它给本项减责（旧逻辑会误判"未复现"）
    r_other = R.judge(frp, scan(perms=[perm_none]),
                      scan(perms=[{"perm": "通讯录", "purpose": "dialog",
                                   "dialog_text": "允许访问通讯录吗？"}]))
    check("权限类：只申请了别的权限 → 未能判定（不降级）",
          r_other[0]["reproduced"] is None, r_other[0])

    # 该权限这一轮压根没再申请（系统记住了拒绝） → 也判不了
    r_none = R.judge(frp, scan(perms=[perm_none]), scan(perms=[]))
    check("权限类：本项权限未再申请 → 未能判定",
          r_none[0]["reproduced"] is None, r_none[0])
    check("权限类：未再申请要说清可能是系统记住了拒绝",
          "记住" in r_none[0]["note"], r_none[0]["note"])

    # 同一权限又申请了，但弹窗前那一屏没取到文字 → 证据不足，不能算未复现
    r_blind = R.judge(frp, scan(perms=[perm_none]),
                      scan(perms=[{"perm": "位置信息", "purpose": ""}]))
    check("权限类：同权限再次申请但没读到前屏 → 未能判定",
          r_blind[0]["reproduced"] is None, r_blind[0])

    # ★ 抽不出"该对照哪个权限"时不许判未复现。
    #   证据文字里没有权限名 → crit["perms"] 为空。此时复现轮里**任何**一次
    #   无关的权限申请都会被旧逻辑读成"又申请了但说明了目的"，把 fail 降成
    #   suspect —— 等于拿别的权限给本项减责。
    frp2 = FlowResult(package="com.demo.app")
    frp2.items = {
        "Q026": item("Q026", "申请权限未同步告知目的", "fail", "ui",
                     "申请了敏感权限但弹窗前没有任何用途说明"),
    }
    rp2 = R.judge(frp2, scan(perms=[perm_none]), scan(perms=[perm_ok]))
    check("权限类：抽不出权限名时不予降级", rp2[0]["reproduced"] is None, rp2[0])
    check("权限类：不予降级要说明原因", "没有具体权限名" in rp2[0]["note"],
          rp2[0]["note"])

    # ---------------------------------------------------------------- 政策类
    frd = FlowResult(package="com.demo.app")
    frd.items = {
        "Q005": item("Q005", "隐私政策未公开收集使用规则", "fail", "policy",
                     "政策正文未取得"),
    }
    cap_no = {"outcome": "not_found", "bestText": ""}
    cap_ok = {"outcome": "full", "bestText": "隐私政策 " + "说明" * 80}
    rd = R.judge(frd, scan(policy=cap_no), scan(policy=cap_no))
    check("政策类：两轮都没取得 → 已复现", rd[0]["reproduced"] is True, rd[0])
    rd = R.judge(frd, scan(policy=cap_no), scan(policy=cap_ok))
    check("政策类：这次取得了 → 未复现", rd[0]["reproduced"] is False, rd[0])
    check("政策类：说明里给出两轮结论",
          "not_found" in rd[0]["note"] and "full" in rd[0]["note"], rd[0]["note"])
    rd = R.judge(frd, scan(policy=cap_no), scan(policy={"outcome": "", "bestText": ""}))
    check("政策类：复现轮没记录结论 → 未能判定", rd[0]["reproduced"] is None, rd[0])

    # ---------------------------------------------------------------- 无法复现的项
    fra = FlowResult(package="com.demo.app")
    fra.items = {"Q001": item("Q001", "隐私政策总体质量", "suspect", "text", "表述模糊")}
    ra = R.judge(fra, s1, s2_same)
    check("文本类结论：判为未能判定并说明原因",
          ra[0]["reproduced"] is None and "文本比对" in ra[0]["note"], ra[0])

    # ---------------------------------------------------------------- 报告
    from piiscan.report import sop_report as RP
    frr = FlowResult(package="com.demo.app")
    frr.repro_results = [
        {"qid": "Q008", "title": "超范围收集", "reproduced": True,
         "result_label": "已复现", "how": "清数据重跑", "note": "再次出现"},
        {"qid": "Q009", "title": "超频次", "reproduced": False,
         "result_label": "未复现", "how": "清数据重跑", "note": "未再出现"},
        {"qid": "Q010", "title": "其他", "reproduced": None,
         "result_label": "未能判定", "how": "第二轮采集失败", "note": "未采到数据"},
    ]
    frr.repro_teardown = {"ok": True, "note": "已卸载"}
    h = RP._repro_results(frr)
    check("报告：三种结果都在", all(x in h for x in ("已复现", "未复现", "未能判定")), h[:200])
    check("报告：统计口径写清楚", "已复现 1 项、未复现 1 项、未能判定 1 项" in h, h[-400:])
    check("报告：未能判定不写成问题不存在", "不代表「问题不存在」" in h, h[-300:])
    check("报告：复现轮也卸了应用", "已卸载" in h, h[-200:])
    # 未能判定不能用"问题"色的 chip，否则视觉上与已复现等同
    seg = h.split("Q010", 1)[1].split("</tr>", 1)[0]
    check("报告：未能判定不用问题色标记", "c-high" not in seg, seg[:160])


def run_sdk(check) -> None:
    """Q007（第三方声明缺口）的复现判据：按 SDK 名 + 信息类型比对。

    这一类不能用通用 token 判据：它的问题描述里写的是 SDK 名，
    没有可执行的 API 名 —— 走通用比对必然落到"未能判定"，
    而它恰恰是最该被复现的一类（报告结论直接指向第三方）。
    """
    from piiscan.flow import repro as R
    from piiscan.flow.models import FlowResult, Evidence, ItemState

    def fr_q007():
        fr = FlowResult(package="com.demo.app")
        fr.sdk_matrix = {"gap_sdk": [
            {"name": "穿山甲广告SDK", "missing_pi": [{"pi": "P01", "name": "设备标识"}]}]}
        fr.items = {"Q007": ItemState(
            qid="Q007",
            title="未列明向第三方提供个人信息的种类、目的、方式以及接收方的名称、联系方式",
            state="fail",
            evidence=[Evidence(kind="policy", title="第三方 SDK",
                               detail="穿山甲广告SDK 采集设备标识但清单未列明")])}
        return fr

    s_sdk = scan([sdk_event()])
    rs = R.judge(fr_q007(), s_sdk, s_sdk)
    check("Q007：同一 SDK 仍采同一类信息 → 已复现",
          rs[0]["reproduced"] is True, rs[0])
    check("Q007：说明里点名是哪个 SDK",
          "穿山甲" in rs[0]["note"], rs[0]["note"])

    # 第二轮该 SDK 没再出现（只有本 App 自己的采集）
    app_ev = E("TelephonyManager.getImei", result="867686023456789", category="api")
    app_ev.stack = ["com.demo.app.MainActivity.a(MainActivity.java:60)"]
    rs = R.judge(fr_q007(), s_sdk, scan([app_ev]))
    check("Q007：该 SDK 未再出现 → 未复现", rs[0]["reproduced"] is False, rs[0])
    check("Q007：未复现的说明列出复现轮可归属的 SDK",
          "复现轮可归属 SDK" in rs[0]["note"], rs[0]["note"])

    # 第二轮一条可归属 SDK 的事件都没有 → 不能判"未复现"
    rs = R.judge(fr_q007(), s_sdk, scan([]))
    check("Q007：复现轮无可归属 SDK → 未能判定", rs[0]["reproduced"] is None, rs[0])

    # 没有 SDK 缺口（比如只有 App 自身的问题）→ 回到通用判据
    fr2 = FlowResult(package="com.demo.app")
    fr2.sdk_matrix = {"gap_sdk": []}
    fr2.items = {"Q008": item("Q008", "超范围收集个人信息", "fail", "frida",
                              "TelephonyManager.getImei 被调用 3 次")}
    rs = R.judge(fr2, scan([IMEI]), scan([IMEI]))
    check("无 SDK 缺口时走通用判据", rs[0]["reproduced"] is True, rs[0])

    # 未复现要真的降级
    fr3 = fr_q007()
    R.apply(fr3, R.judge(fr3, s_sdk, scan([app_ev])))
    check("Q007 未复现 → 降为疑似", fr3.items["Q007"].state == "suspect",
          fr3.items["Q007"].state)


def run_p7(check) -> None:
    """P7 阶段的接线：注入/未注入/采集失败三种情况。"""
    from piiscan.flow import sop as SOP
    from piiscan.flow import models as M
    from piiscan.flow.models import FlowResult

    def runner_obj():
        r = SOP.FlowRunner(log=lambda *_a, **_k: None)
        r.scan = scan([IMEI])
        r.fr = FlowResult(package="com.demo.app")
        r.fr.items = {"Q008": item("Q008", "超范围收集个人信息", "fail", "frida",
                                   "TelephonyManager.getImei 被调用 3 次")}
        return r

    # ① 注入了复现能力：真跑第二轮并回写
    r = runner_obj()
    r.repro_runner = lambda: {"scan": scan([IMEI]),
                              "teardown": {"ok": True, "note": "已卸载"}}
    pr = r.p7_repro()
    check("P7：有复现能力时阶段为已完成", pr.status == M.PHASE_DONE, pr.status)
    check("P7：回写了复现结果", len(r.fr.repro_results) == 1, r.fr.repro_results)
    check("P7：复现成功保留原状态", r.fr.items["Q008"].state == "fail",
          r.fr.items["Q008"].state)
    check("P7：记下复现轮的卸载结果", r.fr.repro_teardown.get("note") == "已卸载",
          r.fr.repro_teardown)

    # ② 没注入（离线出报告 / 平台无设备）：不能假装跑过
    r = runner_obj()
    pr = r.p7_repro()
    check("P7：无复现能力时标跳过", pr.status == M.PHASE_SKIPPED, pr.status)
    check("P7：无复现能力时写明待复现项",
          any("Q008" in w for w in pr.warnings), pr.warnings)
    check("P7：无复现能力时不写复现结果", not r.fr.repro_results, r.fr.repro_results)

    # ③ 复现采集抛异常：标跳过 + 每条"未能判定"，状态不动
    r = runner_obj()

    def boom():
        raise RuntimeError("设备掉线")

    r.repro_runner = boom
    pr = r.p7_repro()
    check("P7：采集失败时标跳过", pr.status == M.PHASE_SKIPPED, pr.status)
    check("P7：采集失败时结果写未能判定",
          [x.get("reproduced") for x in r.fr.repro_results] == [None],
          r.fr.repro_results)
    check("P7：采集失败的说明带错误原因",
          "设备掉线" in (r.fr.repro_results[0].get("note") or ""), r.fr.repro_results)
    check("P7：采集失败不改状态", r.fr.items["Q008"].state == "fail",
          r.fr.items["Q008"].state)

    # ④ 没有问题项时直接跳过，不去碰设备
    r = runner_obj()
    r.fr.items = {"Q001": item("Q001", "其它", "pass", "policy", "政策完整")}
    called = {"n": 0}
    r.repro_runner = lambda: called.__setitem__("n", called["n"] + 1)
    pr = r.p7_repro()
    check("P7：没有问题项时不触发采集", called["n"] == 0, called)
    check("P7：没有问题项时标跳过", pr.status == M.PHASE_SKIPPED, pr.status)


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
    run_sdk(_check)
    run_p7(_check)
    print("通过 %d 项，失败 %d 项" % (_ok, len(_bad)))
    for b in _bad:
        print("  FAIL", b)
    sys.exit(1 if _bad else 0)
