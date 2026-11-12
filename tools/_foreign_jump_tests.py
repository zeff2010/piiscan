#!/usr/bin/env python3
"""外跳判定（flow/foreign.py）的自测。

为什么这些用例值得钉住
----------------------
判错一个方向的代价完全不对等：

  · 把**权限弹窗**判成"设置页" → 弹窗不进 `_capture_perm_dialog`，
    原文不记、不代点「允许」，Q026 直接无从判定（一整项作废）；
  · 把**设置页/授权页**判成"无意义跳转" → 报告里永远没有
    "权限管理只跳系统设置""存在微信授权登录"这两条事实；
  · 把**商店/相册**判成"有价值" → 每跳一次多停 1~2 秒还占一张截图配额，
    在 600 秒的遍历预算里能吃掉几十次点击。

所以这里既钉"该留证的留证"，也钉"没有文字时不要瞎猜"（need_text）。

跑法：python tools/_foreign_jump_tests.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from piiscan.flow import foreign as F            # noqa: E402

APP = "com.ltzk.mbsf"


def run(check):
    # ---------------------------------------------------------------- 系统设置页
    v = F.classify("com.android.settings",
                   activity="com.android.settings.applications.AppInfoActivity",
                   entry="权限管理")
    check("系统设置·应用详情 → 留证", v["action"] == "evidence" and v["valuable"], v)
    check("系统设置·应用详情 写明是设置页", v["kind"].startswith("settings"), v["kind"])
    check("系统设置·应用详情 有等待（等页面渲染再截图）", v["wait"] > 0, v["wait"])
    check("系统设置·应用详情 理由写明「交给系统承接」",
          "系统" in v["why"], v["why"])

    v = F.classify("com.android.settings",
                   activity="com.android.settings.SubSettings",
                   entry="权限管理", screen_text="应用权限 相机 存储 麦克风 权限管理")
    check("系统设置·权限页 → 判为权限管理页", v["kind"] == "settings_perm", v)
    check("系统设置·权限页 理由写明「未自建权限开关」", "未自建" in v["why"], v["why"])

    # MIUI：权限管理挂在 securitycenter 上，与权限确认框同宿主
    v = F.classify("com.miui.securitycenter",
                   activity="com.miui.permcenter.permissions.PermissionsEditorActivity",
                   entry="权限管理")
    check("MIUI 权限管理页 → 设置页（不是弹窗）",
          F.is_settings_page("com.miui.securitycenter",
                             "com.miui.permcenter.permissions.PermissionsEditorActivity"),
          v)
    check("MIUI 权限管理页 → 留证", v["action"] == "evidence" and v["valuable"], v)

    # ★ 反向：白名单里的权限弹窗不能被当成"设置页"，否则权限取证整条链路被绕过
    for pkg, act in (
        ("com.android.permissioncontroller",
         "com.android.permissioncontroller.permission.ui.GrantPermissionsActivity"),
        ("com.google.android.permissioncontroller",
         "com.google.android.permissioncontroller.permission.ui.GrantPermissionsActivity"),
        ("com.lbe.security.miui", "com.lbe.security.miui.PermissionActivity"),
    ):
        check("权限弹窗宿主不被判成设置页（%s）" % pkg.split(".")[-1],
              F.is_settings_page(pkg, act) is False, act)
        check("权限弹窗宿主不被判成外跳（%s）" % pkg.split(".")[-1],
              F.is_foreign(pkg, APP) is False, pkg)
        vv = F.classify(pkg, activity=act, entry="允许")
        check("权限弹窗 classify → permission_dialog（%s）" % pkg.split(".")[-1],
              vv["kind"] == "permission_dialog" and vv["action"] == "back", vv)
        check("权限弹窗不留证（%s）" % pkg.split(".")[-1],
              vv["valuable"] is False, vv)

    v = F.classify("com.miui.securitycenter",
                   activity="com.miui.permission.PermissionActivity", entry="允许")
    check("MIUI 权限确认框 → 弹窗（不是设置页）", v["kind"] == "permission_dialog", v)

    # ---------------------------------------------------------------- 浏览器
    v = F.classify("com.android.chrome",
                   activity="com.google.android.apps.chrome.Main",
                   entry="微信登录",
                   screen_text="微信登录 授权 允许 获取你的昵称、头像")
    check("浏览器·授权页 → 留证", v["action"] == "evidence" and v["valuable"], v)
    check("浏览器·授权页 kind=browser_auth", v["kind"] == "browser_auth", v["kind"])
    check("浏览器·授权页 等待更久（oauth 要跳两次）", v["wait"] >= 2.0, v["wait"])

    v = F.classify("com.android.chrome", activity="com.google.android.apps.chrome.Main",
                   entry="广告位", screen_text="今日头条 首页 推荐 视频 热点")
    check("浏览器·普通网页 → 立即返回", v["action"] == "back", v)
    check("浏览器·普通网页 → 不留证", v["valuable"] is False, v)
    check("浏览器·普通网页 → 不等待（及时返回）", v["wait"] == 0, v["wait"])

    v = F.classify("com.android.chrome", entry="隐私政策")
    check("浏览器·无落点文字 → 要求补 dump", v["need_text"] is True, v)
    check("浏览器·无落点文字 先按立即返回处理（不赌）", v["action"] == "back", v)

    # ---------------------------------------------------------------- 社交 / 支付
    v = F.classify("com.tencent.mm", activity="com.tencent.mm.plugin.webview.ui.tools.WebViewUI",
                   entry="微信登录", screen_text="微信登录 授权 允许")
    check("微信授权登录 → 留证", v["action"] == "evidence" and v["valuable"], v)
    check("微信授权登录 点名是第三方账号体系", "第三方" in v["why"], v["why"])
    check("微信授权登录 理由带应用名", "微信" in v["why"], v["why"])

    v = F.classify("com.tencent.mm", entry="分享到微信", screen_text="微信 通讯录 聊天 发现")
    check("微信非授权页 → 立即返回", v["action"] == "back" and not v["valuable"], v)

    v = F.classify("com.eg.android.AlipayGphone", entry="立即支付",
                   screen_text="收银台 确认付款")
    check("支付宝支付 → 留证", v["action"] == "evidence" and v["valuable"], v)
    check("支付宝支付 kind=sns_pay", v["kind"] == "sns_pay", v["kind"])

    # ---------------------------------------------------------------- 无价值跳转
    for pkg, kind in (("com.xiaomi.market", "store"),
                      ("com.android.vending", "store"),
                      ("com.android.documentsui", "picker"),
                      ("com.miui.mediapicker", "picker"),
                      ("com.miui.gallery", "picker")):
        v = F.classify(pkg, entry="上传图片", screen_text="图片 相册")
        check("%s → 立即返回" % kind, v["action"] == "back", v)
        check("%s → 不留证" % kind, v["valuable"] is False, v)
        check("%s → 不等待" % kind, v["wait"] == 0, v["wait"])

    # ---------------------------------------------------------------- 退出与拨号
    v = F.classify("com.miui.home", entry="返回")
    check("桌面 → 不是跳转，要重拉 App", v["action"] == "relaunch", v)
    check("桌面 理由点明「已退出」", "退出" in v["why"], v["why"])

    v = F.classify("com.android.dialer", entry="客服电话",
                   screen_text="拨号 10086 通话")
    check("拨号 → 立即返回", v["action"] == "back", v)
    check("拨号 → 标记要挂断（避免真实外呼）", v["end_call"] is True, v)
    check("拨号 → 理由写明未实际通话", "未实际通话" in v["why"], v["why"])

    # ---------------------------------------------------------------- 其他应用
    v = F.classify("com.some.unknownapp", entry="查看详情",
                   screen_text="欢迎使用 首页")
    check("未知应用 → 立即返回", v["action"] == "back" and not v["valuable"], v)
    v = F.classify("com.some.unknownapp", entry="登录", screen_text="请授权登录")
    check("未知应用·授权页 → 留证", v["action"] == "evidence" and v["valuable"], v)
    v = F.classify("com.some.unknownapp", entry="打开")
    check("未知应用·无文字 → 要求补 dump", v["need_text"] is True, v)
    v = F.classify("", entry="x")
    check("取不到包名 → 按离开处理", v["action"] == "back" and v["kind"] == "unknown", v)

    # ---------------------------------------------------------------- 通用不变量
    samples = [
        F.classify("com.android.settings", screen_text="应用信息"),
        F.classify("com.android.chrome", entry="登录", screen_text="授权"),
        F.classify("com.xiaomi.market"),
        F.classify("com.miui.home"),
        F.classify("com.android.dialer"),
        F.classify("com.tencent.mm", entry="微信登录", screen_text="授权"),
    ]
    check("所有判定都要求「该入口不再点」", all(s["revisit"] is False for s in samples),
          [s.get("revisit") for s in samples])
    check("所有判定都有可读的类别名", all(s["label"] for s in samples),
          [s["label"] for s in samples])
    check("所有判定都写明理由（不进报告的空话不许出现）",
          all(len(s["why"]) >= 8 for s in samples), [s["why"] for s in samples])
    check("动作只有三种（不留'点外部按钮'的口子）",
          all(s["action"] in ("evidence", "back", "relaunch") for s in samples),
          [s["action"] for s in samples])

    # ---------------------------------------------------------------- parse_focus
    check("parse_focus：相对类名补全包名",
          F.parse_focus("com.miui.home/.launcher.Launcher") ==
          ("com.miui.home", "com.miui.home.launcher.Launcher"))
    check("parse_focus：全限定名原样",
          F.parse_focus("com.android.settings/com.android.settings.Settings") ==
          ("com.android.settings", "com.android.settings.Settings"))
    check("parse_focus：空串", F.parse_focus("") == ("", ""))
    check("parse_focus：无斜杠只给包名", F.parse_focus("com.android.settings") ==
          ("com.android.settings", ""))

    # ---------------------------------------------------------------- is_foreign
    check("is_foreign：被测 App 自身 → False", F.is_foreign(APP, APP) is False)
    check("is_foreign：被测 App 子进程 → False",
          F.is_foreign(APP + ":push", APP) is False)
    check("is_foreign：浏览器 → True", F.is_foreign("com.android.chrome", APP) is True)
    check("is_foreign：系统设置 → True", F.is_foreign("com.android.settings", APP) is True)
    check("is_foreign：权限弹窗（白名单）→ False",
          F.is_foreign("com.android.permissioncontroller", APP) is False)
    check("is_foreign：空包名 → False（读不到别乱判）",
          F.is_foreign("", APP) is False)

    # ---------------------------------------------------------------- summarize
    sm = F.summarize([
        {"kind": "settings_perm", "label": "系统设置 · 权限管理", "valuable": True},
        {"kind": "browser_plain", "label": "浏览器", "valuable": False},
        {"kind": "launcher", "label": "系统桌面", "valuable": False},
        {"kind": "browser_plain", "label": "浏览器", "valuable": False},
    ])
    check("汇总：总数", sm["total"] == 4, sm)
    check("汇总：有价值 1", sm["valuable"] == 1, sm)
    check("汇总：无意义 3", sm["meaningless"] == 3, sm)
    check("汇总：落到桌面单列", sm["left_app"] == 1, sm)
    check("汇总：按类别计次", sm["by_kind"]["browser_plain"]["count"] == 2, sm["by_kind"])
    check("汇总：空输入不崩", F.summarize([])["total"] == 0, F.summarize([]))

    # ---------------------------------------------------------------- 报告章节
    from types import SimpleNamespace
    from piiscan.flow.sop import shot_phase
    from piiscan.report.sop_report import _foreign_jumps

    check("截图阶段：外跳图归到 P4（否则整张被丢弃）",
          shot_phase("外跳：系统设置 · 权限管理") == "P4",
          shot_phase("外跳：系统设置 · 权限管理"))

    check("报告：没有外跳记录时不出现空章节",
          _foreign_jumps(SimpleNamespace(external_jumps=[])) == "")

    rows = [
        {"seq": 1, "entry": "权限管理", "pkg": "com.android.settings",
         "activity": "com.android.settings.applications.AppInfoActivity",
         "kind": "settings_perm", "label": "系统设置 · 权限管理", "valuable": True,
         "why": "跳转到系统设置的权限管理页：被测应用未自建权限开关", "shot_index": 3},
        {"seq": 2, "entry": "微信登录", "pkg": "com.tencent.mm", "activity": "x",
         "kind": "sns_auth", "label": "第三方授权登录", "valuable": True,
         "why": "跳转到微信完成授权登录：存在第三方账号体系", "shot_index": None},
        {"seq": 3, "entry": "去评分", "pkg": "com.xiaomi.market", "activity": "y",
         "kind": "store", "label": "应用商店", "valuable": False,
         "why": "跳转到应用商店（评分/更新）", "shot_index": None},
    ]
    html = _foreign_jumps(SimpleNamespace(external_jumps=rows),
                          {3: {"b64": "QUJD", "label": "外跳：系统设置 · 权限管理"}})
    check("报告：含概览（总次数）", "3 次" in html, html[:200])
    check("报告：含概览（有取证价值 2 次）", "2 次" in html, html[:300])
    check("报告：点明「未内置权限开关」", "未内置权限开关" in html, "")
    check("报告：点明「第三方授权登录」", "第三方授权登录" in html, "")
    check("报告：写明未记录传输内容（不臆测外发）",
          "未记录该过程的传输内容" in html, "")
    check("报告：无意义跳转标为「已即时返回」", "已即时返回" in html, "")
    check("报告：明细列出入口名", "权限管理" in html and "去评分" in html, "")
    check("报告：有截图的项内嵌图片",
          "data:image/jpeg;base64,QUJD" in html, "")
    check("报告：截图图注说明「进入…后的界面」", "后的界面" in html, "")
    check("报告：写清边界（外部应用不在采集范围）",
          "不在采集范围" in html, "")
    check("报告：不把授权跳转直接判成违规",
          "违规" not in html, "")
    check("报告：判定理由单独列出", "判定理由" in html, "")
    check("报告：系统设置截图附注（不是 App 自己的页面）",
          "不是被测应用自己的页面" in html, "")

    # 只有无意义跳转时，结论不能写"有价值"
    html2 = _foreign_jumps(SimpleNamespace(external_jumps=[rows[2]]))
    check("报告：全是无意义跳转时说清「没有提供取证价值」",
          "没有跳转提供取证价值" in html2, html2[:300])
    check("报告：无跳转截图时不出现图片标签", "data:image" not in html2, "")


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
