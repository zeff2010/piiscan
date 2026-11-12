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
