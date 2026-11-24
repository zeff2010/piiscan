"""系统权限弹窗识别与「是否同步告知目的」判定的离线自测。

设备无关：用两段真实结构的 uiautomator XML 打桩，覆盖
  ① 系统权限框（带用途说明 / 不带用途说明）；
  ② App 自己的"允许通知"弹窗**不能**被误判成系统权限框；
  ③ 判定分寸：一次未告知 → 疑似；两次且全局都没有说明 → 发现。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from piiscan import uiwalk                               # noqa: E402
from piiscan.flow import models as M                    # noqa: E402
from piiscan.flow import permissions as PERM            # noqa: E402


def _xml(pkg: str, texts, buttons=True) -> str:
    rows = []
    y = 900
    for t in texts:
        rows.append("<node class='android.widget.TextView' package='%s' "
                    "bounds='[80,%d][1000,%d]' text=\"%s\"/>" % (pkg, y, y + 90, t))
        y += 110
    if buttons:
        for t in ("仅在使用该应用时允许", "仅本次允许", "不允许"):
            rows.append("<node class='android.widget.Button' package='%s' clickable='true' "
                        "bounds='[80,%d][1000,%d]' text=\"%s\"/>" % (pkg, y, y + 90, t))
            y += 110
    return ("<?xml version='1.0' encoding='UTF-8'?><hierarchy rotation='0'>"
            "<node class='android.widget.FrameLayout' package='%s' bounds='[0,0][1080,2400]'>"
            "%s</node></hierarchy>" % (pkg, "".join(rows)))


SYS_WITH_PURPOSE = _xml("com.android.permissioncontroller", [
    "允许“演示”访问您的位置信息吗？",
    "用于向您推荐附近的门店与服务",
])

SYS_PLAIN = _xml("com.android.permissioncontroller", [
    "允许“演示”访问您的通讯录吗？",
])

APP_OWN = _xml("com.demo.app", [
    "允许接收通知吗？",
    "开启后可及时收到消息提醒",
], buttons=False)


def _scene(**kw):
    base = {"perm": "位置信息", "dialog_text": "允许“演示”访问您的位置信息吗？",
            "pre_text": "开启定位，为您推荐附近门店", "phase": "P4", "at_ms": 12000}
    base.update(kw)
    return base


def run(check):
    # ---------------------------------------------------------------- 识别
    pd = uiwalk.perm_dialog(SYS_WITH_PURPOSE)
    check("权限弹窗：识别出系统权限框", bool(pd), pd)
    check("权限弹窗：取到权限名", bool(pd) and pd["perm"] == "位置信息",
          pd["perm"] if pd else None)
    check("权限弹窗：取到按钮列表", bool(pd) and len(pd["options"]) >= 2,
          pd["options"] if pd else None)
    check("权限弹窗：优先点「仅在使用时允许」而不是「始终允许」",
          bool(pd) and pd["allow_label"] == "仅在使用该应用时允许",
          pd["allow_label"] if pd else None)
    check("权限弹窗：识别弹窗内自带的用途说明", bool(pd) and pd["has_purpose"],
          pd["purpose_quote"] if pd else None)

    plain = uiwalk.perm_dialog(SYS_PLAIN)
    check("权限弹窗：无说明的弹窗也能识别", bool(plain), plain)
    check("权限弹窗：无说明时不误判为有说明", bool(plain) and not plain["has_purpose"],
          plain["has_purpose"] if plain else None)

    own = uiwalk.perm_dialog(APP_OWN)
    check("权限弹窗：App 自己的通知弹窗不被误判", own is None, own)
    check("权限弹窗：空输入不报错", uiwalk.perm_dialog("") is None)

    # ---------------------------------------------------------------- 用途说明检索
    ok, q = PERM.explained_in_text("开启定位，为您推荐附近门店", "位置信息")
    check("用途说明：同一句里「目的词+功能词」才算", ok, q)
    bad, _ = PERM.explained_in_text("为您提供更好的服务。我们不会读取通讯录", "通讯录")
    check("用途说明：跨句拼接不算", not bad)
    bad2, _ = PERM.explained_in_text("为您提供更好的服务", "位置信息")
    check("用途说明：只有套话、没有功能词不算", not bad2)
    ok2, _ = PERM.explained_in_text("麦克风权限用于语音搜索", "麦克风")
    check("用途说明：另一权限也能命中", ok2, _)

    # ---------------------------------------------------------------- 场景判定
    s_dialog = PERM.judge_scene({"perm": "位置信息", "has_purpose": True,
                                 "purpose_quote": "用于推荐附近门店",
                                 "pre_text": "首页"})
    check("判定：弹窗自带说明 → dialog", s_dialog["purpose"] == "dialog",
          s_dialog["purpose"])

    s_pre = PERM.judge_scene(_scene())
    check("判定：弹窗前界面说明 → pre", s_pre["purpose"] == "pre", s_pre["purpose"])

    s_none = PERM.judge_scene(_scene(pre_text="我的"))
    check("判定：前屏无说明 → none", s_none["purpose"] == "none", s_none["purpose"])

    s_unk = PERM.judge_scene(_scene(pre_text=""))
    check("判定：前屏没抓到文字 → 证据不足（不是 none）", s_unk["purpose"] == "",
          s_unk["purpose"])

    # 一次未告知 → 认定。不设"抓到两次"的门槛：次数取决于本轮点开了几个
    # 会索权的功能，与 App 有没有告知目的无关，用它决定结论会随遍历漂移。
    r1 = PERM.judge([_scene(pre_text="我的")])
    check("汇总：单次未告知即认定（证据完整，无次数门槛）", r1["state"] == M.FAIL, r1["state"])
    check("汇总：结论里写明是哪个权限", "位置信息" in r1["desc"], r1["desc"][:80])
    check("汇总：事实表逐场景一条", len(r1["facts"]) == 1, len(r1["facts"]))

    # 两次未告知、且全局都没有说明 → 发现
    r2 = PERM.judge([_scene(pre_text="我的"),
                     _scene(perm="通讯录", pre_text="添加好友")])
    check("汇总：两次未告知且全局无说明 → 认定为问题", r2["state"] == M.FAIL, r2["state"])
    check("汇总：结论里点名两个场景", "通讯录" in r2["desc"] and "位置信息" in r2["desc"],
          r2["desc"][:120])
    check("汇总：统计数对得上", r2["stats"]["silent"] == 2, r2["stats"])

    # 全局别的界面写过说明 —— 只作线索，不改结论。
    # 这条曾经把 fail 洗成 suspect，导致同一 App 只因"这轮多翻到一屏权限说明页"
    # 就换结论（实测 mbsf15/16/18/19）。
    screens = [{"label": "欢迎页", "texts": ["开启定位以便为您推荐附近门店"]}]
    r3 = PERM.judge([_scene(pre_text="我的"), _scene(perm="通讯录", pre_text="添加好友")],
                    screens)
    check("汇总：别的界面写过说明不改变认定", r3["state"] == M.FAIL, r3["state"])
    check("汇总：该线索记进 stats 而非结论",
          "位置信息" in (r3["stats"].get("elsewhere") or {}), str(r3["stats"].get("elsewhere")))
    check("汇总：desc 明说该线索未参与判断",
          "未据此改变本项结论" in r3["desc"], r3["desc"][:200])

    # 全部有说明 → 未发现问题
    r4 = PERM.judge([_scene(),
                     _scene(perm="通讯录", pre_text="添加好友，需要读取通讯录以便推荐好友")])
    check("汇总：全部有说明 → 未发现问题", r4["state"] == M.PASS, r4["state"])

    # 没有场景 → 未测（交给 checklist 给原因）
    r5 = PERM.judge([])
    check("汇总：无场景 → 未测", r5["state"] == M.NOT_TESTED, r5["state"])
    check("汇总：无场景不编造结论", not r5["desc"])

    # 只有证据不足 → 未测，不能写"未告知"
    r6 = PERM.judge([_scene(pre_text="")])
    check("汇总：证据不足 → 未测而非疑似", r6["state"] == M.NOT_TESTED, r6["state"])

    # -------------------------------------------- 同意前索权（2026-11-18 口径）
    from piiscan.flow import compare as CMP

    # 组名归一必须覆盖 uiwalk 可能返回的**每一个**词。漏一个就是整类漏判，
    # 而且屏幕上看不出异常（报告只是"未发现问题"）—— 这种错最难发现。
    _unmapped = [w for w in uiwalk.PERM_LABELS
                 if CMP.norm_perm_group(w) not in CMP.PII_PERM_GROUPS
                 and CMP.norm_perm_group(w) != "通知"]
    check("索权：PERM_LABELS 每个词都能归到已知组（通知除外）",
          not _unmapped, _unmapped)
    check("索权：通知不在「可采集个人信息」集合里",
          "通知" not in CMP.PII_PERM_GROUPS)
    check("索权：「位置信息」归到位置", CMP.norm_perm_group("位置信息") == "位置")
    check("索权：「照片」归到存储", CMP.norm_perm_group("照片") == "存储")
    check("索权：「拍摄照片和视频」归到相机",
          CMP.norm_perm_group("拍摄照片和视频") == "相机")

    _sc = [
        _scene(perm="位置信息", phase="P1", app_before=True),
        _scene(perm="通知", phase="P1", app_before=True),
        _scene(perm="相机", phase="P4", app_before=True),
        _scene(perm="相机", phase="P1", app_before=False),
        _scene(perm="照片", phase="P1", app_before=None),
    ]
    _hits = CMP.pre_consent_perm_requests(_sc)
    check("索权：只认「同意前 + 可采集个人信息 + 弹窗前在前台」",
          len(_hits) == 2, [(h["perm"], h.get("app_before")) for h in _hits])
    check("索权：通知权限不算问题", all(h["perm"] != "通知" for h in _hits))
    check("索权：同意后的弹窗不算", all(h["phase"] == "P1" for h in _hits))
    check("索权：弹窗前就不在前台的不认",
          all(h.get("app_before") is not False for h in _hits))

    # 弹窗读不到权限名时，用同时段的 requestPermissions 事件补齐
    from types import SimpleNamespace as NS
    _ev = NS(api="ActivityCompat.requestPermissions", hook_id="perm_request",
             args="android.permission.ACCESS_FINE_LOCATION", result="null",
             elapsed_ms=12050, noise="", signal="S069", before_consent=True)
    _blind = [_scene(perm="", phase="P1", app_before=True, at_ms=12000)]
    check("索权：弹窗无权限名时用 hook 事件补齐",
          len(CMP.pre_consent_perm_requests(_blind, [_ev])) == 1)
    check("索权：事件时刻差得远就不配对",
          CMP.pre_consent_perm_requests(_blind, [
              NS(api="ActivityCompat.requestPermissions", hook_id="perm_request",
                 args="android.permission.ACCESS_FINE_LOCATION", result="null",
                 elapsed_ms=60000, noise="", signal="S069")]) == [])

    # ---------------------------------------------------- 尝试获取（未成功）
    check("尝试获取：被系统拒绝要写清原因",
          "调用被拒绝" in CMP._attempt_reason("调用被拒绝：SecurityException",
                                              "TelephonyManager.getDeviceId"))
    check("尝试获取：假 MAC 要写清是系统不给",
          "假值" in CMP._attempt_reason("02:00:00:00:00:00",
                                       "WifiInfo.getMacAddress"))
    check("尝试获取：空值单独说明", CMP._attempt_reason("", "x") == "取值为空")
    # 返回对象/列表不等于"没拿到"：App 很可能已经拿到，只是采集侧展开不了。
    # 写成"未成功"方向正好相反（真机数据里 115/153 条属于这一类）。
    _obj = CMP.attempted_types([
        NS(api="ActivityManager.getRunningAppProcesses", hook_id="", args="",
           result="[object Object]", elapsed_ms=1000, before_consent=True,
           noise="", signal="S054")])
    check("尝试获取：返回对象的不算「未成功」", _obj == {}, list(_obj))

    _att = CMP.attempted_types([
        NS(api="TelephonyManager.getDeviceId", hook_id="", args="",
           result="调用被拒绝：SecurityException", elapsed_ms=5000,
           before_consent=True, noise="", signal="S012"),
        NS(api="TelephonyManager.getDeviceId", hook_id="", args="",
           result="调用被拒绝：SecurityException", elapsed_ms=5100,
           before_consent=True, noise="", signal="S012"),
        NS(api="Settings.Secure.getString", hook_id="", args="android_id",
           result="d85823f5504132c4", elapsed_ms=7000,
           before_consent=True, noise="", signal="S003"),
    ])
    check("尝试获取：只收未取到值的（1 类 2 次）", len(_att) == 1, list(_att))
    _r = list(_att.values())[0]
    check("尝试获取：同一类型合并计数", _r["count"] == 2, _r["count"])
    check("尝试获取：取到值的那条不算尝试",
          "getString" not in "".join(_r.get("apis") or []), _r.get("apis"))
    _desc = CMP.describe_attempted(_att)
    check("尝试获取：描述里带次数与原因",
          "2 次" in _desc and "拒绝" in _desc, _desc)

    # ------------------------------------------ 取证本身：1 档不代点「允许」
    # 这是红线：点「允许」等于替用户授权，之后测到的就不是 App 原本的行为。
    # 用打桩跑一遍真实函数，确认"只取证、不点击"真的成立。
    import time as _time
    from piiscan import collector as COLL
    _tapped = []
    _o_fg, _o_shot = COLL.app_in_foreground, COLL.capture_screenshot
    _o_top, _o_tap = uiwalk.top_activity, uiwalk.tap
    try:
        COLL.app_in_foreground = lambda *a, **k: False
        COLL.capture_screenshot = lambda *a, **k: b""
        uiwalk.top_activity = lambda *a, **k: "com.demo.Main"
        uiwalk.tap = lambda *a, **k: (_tapped.append(a), True)[1]
        _res = COLL.ScanResult(package="com.demo")
        _res.started_at = _time.time()
        _ok = COLL._capture_perm_dialog(
            _res, SYS_WITH_PURPOSE, "SERIAL", lambda *_: None,
            phase="P1", tap_allow=False, app_before=True)
        _sc = _res.perm_scenes[-1] if _res.perm_scenes else {}
    finally:
        COLL.app_in_foreground, COLL.capture_screenshot = _o_fg, _o_shot
        uiwalk.top_activity, uiwalk.tap = _o_top, _o_tap

    check("权限取证：识别为权限弹窗", _ok is True, _ok)
    check("权限取证：1 档不代点「允许」（红线）", not _tapped, _tapped)
    check("权限取证：动作写明未代为作答",
          "未代为作答" in str(_sc.get("action") or ""), _sc.get("action"))
    check("权限取证：记下弹窗前应用在前台",
          _sc.get("app_before") is True, _sc.get("app_before"))
    check("权限取证：app_before=True → 可当证据（焦点在弹窗上不影响）",
          _sc.get("evidable") is True, _sc.get("evidable"))
    check("权限取证：记下权限名", _sc.get("perm") == "位置信息", _sc.get("perm"))

    # ---------------------------- 索权并入 Q003 / 尝试获取写进事实（判定层）
    from piiscan import collector as COLL
    from piiscan.flow import sop as SOP

    def _run_p1(**kw):
        r = SOP.FlowRunner(log=lambda *_: None)
        sc = COLL.ScanResult(depth="pre", package="com.demo")
        sc.started_at = 1000.0
        for k, v in kw.items():
            setattr(sc, k, v)
        r.scan = sc
        r.p1_pre_consent()
        return r.fr, r.fr.items.get("Q003")

    _pos = {"perm": "位置信息", "phase": "P1", "at_ms": 12400,
            "app_before": True, "dialog_text": "允许访问位置信息吗？",
            "action": "未代为作答（本档不点系统权限弹窗）"}
    _, q3 = _run_p1(perm_scenes=[dict(_pos)])
    check("Q003：未同意阶段索权 → 发现问题", q3.state == M.FAIL, q3.state)
    check("Q003：描述写「索要」而不是「已收集」",
          "索要" in q3.desc and "已实际收集" not in q3.desc, q3.desc[:120])
    check("Q003：事实表写下索要的权限",
          any(f[0] == "未同意阶段索要的权限" for f in q3.facts), q3.facts[:3])
    check("Q003：事实表交代没替用户点允许",
          any(f[0] == "是否代为作答" and "否" in f[1] for f in q3.facts), q3.facts[:4])

    _, q3_notice = _run_p1(perm_scenes=[{"perm": "通知", "phase": "P1",
                                         "at_ms": 1000, "app_before": True}])
    check("Q003：通知权限不改判", q3_notice.state != M.FAIL, q3_notice.state)

    _, q3_off = _run_p1(perm_scenes=[{"perm": "相机", "phase": "P1",
                                      "at_ms": 5000, "app_before": False}])
    check("Q003：弹窗前就不在前台的不认", q3_off.state != M.FAIL, q3_off.state)

    _deny = NS(api="TelephonyManager.getDeviceId", hook_id="", args="",
               result="调用被拒绝：SecurityException", elapsed_ms=5000,
               before_consent=True, noise="", signal="S012", ts=0)
    _, q3_att = _run_p1(events=[_deny])
    check("Q003：尝试获取不改状态（仍为未测）",
          q3_att.state == M.NOT_TESTED, q3_att.state)
    check("Q003：尝试获取写进事实表",
          any("尝试获取但未成功" in f[0] for f in q3_att.facts), q3_att.facts[-1:])
    check("Q003：事实里写明不计为违规",
          any("不计为违规" in f[0] for f in q3_att.facts))

    # 只有"非个人信息"的事件（读时区）也算行为事件：PASS 的 facts 必须写真实
    # 条数，写死 0 就是报告与存档对不上（2026-11-18 真机撞到）。
    _tz = NS(api="SystemProperties.get", hook_id="", args="persist.sys.timezone",
             result="Asia/Shanghai", elapsed_ms=900, before_consent=True,
             noise="", signal="S055", ts=0)
    _fr2, _q3b = _run_p1(events=[_tz],
                         pre_explore={"taps": 2, "screens": 3, "perm_dialogs": 0})
    _q2b = _fr2.items.get("Q002")
    check("P1：PASS 时事件数按实际写，不写死 0 条",
          any(f[0] == "同意前事件数" and str(f[1]).startswith("1 条")
              for f in _q2b.facts), _q2b.facts[:2])
    check("P1：Q003 有自己的未测原因（不是『缺少阶段 P3 的证据』）",
          _q3b.state == M.NOT_TESTED and "P3" not in (_q3b.reason or ""),
          (_q3b.state, (_q3b.reason or "")[:60]))

    # ---------------------------------------------------------------- 同一交互采集
    # 2026-11-19 用户口径：点击「同意」后 1.5 秒内的采集"记录但不判违规"。
    # 这一支的真正用途是防"报告看起来什么都没发生"——驿站助手 4 档那一轮
    # 点击前 1 条、点击后 1.5 秒内 74 条（含读 Android ID），旧报告只写
    # "未取得任何取值"，与事实相反。
    _fr3, q3s = _run_p1(
        consent_sync_events=74,
        consent_sync_summary="设备标识 3 条、本地留存 41 条、外发数据 2 条",
        pre_explore={"taps": 2, "screens": 3, "perm_dialogs": 0})
    _q2s = _fr3.items.get("Q002")
    check("Q003：同一交互采集写进事实表",
          any(str(f[0]).startswith("同一交互内采集") for f in q3s.facts), q3s.facts[-2:])
    check("Q002：同一交互采集也写进事实表",
          any(str(f[0]).startswith("同一交互内采集") for f in (_q2s.facts or [])),
          (_q2s.facts or [])[-2:])
    check("同一交互：写明条数",
          any("74 条" in str(f[1]) for f in q3s.facts
              if str(f[0]).startswith("同一交互内采集")), q3s.facts[-1:])
    check("同一交互：写明不计为同意前",
          any("不计为「同意前收集」" in str(f[1]) for f in q3s.facts))
    check("同一交互：带上类型摘要（不能只说条数）",
          any("设备标识" in str(f[1]) for f in q3s.facts), q3s.facts[-1:])
    check("同一交互：不改 Q003 状态", q3s.state == M.NOT_TESTED, q3s.state)

    # 没有同一交互事件时不能凭空多出一行
    _fr4, q3n = _run_p1(events=[_tz],
                        pre_explore={"taps": 2, "screens": 3, "perm_dialogs": 0})
    check("同一交互：0 条时不写事实行",
          not any(str(f[0]).startswith("同一交互内采集") for f in q3n.facts),
          q3n.facts)
