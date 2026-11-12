#!/usr/bin/env python3
"""调用栈归因用例（离线，不需要设备）。

这块判错的代价比"少报一条"大得多：
把 App 自己的代码判成第三方 SDK，等于替 App 脱责；
把 SDK 判成 App，整改方向就指错了（让 App 改代码，而真正该换的是 SDK）。

跑法：python tools/_attribution_tests.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from piiscan.flow import attribution as A

APP = "cn.ixuecheng"


def _stk(*frames: str):
    return list(frames)


# 常见真实形态：栈顶是被 hook 的框架 API，往下才是调用者
SDK_STACK = _stk(
    "android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:740)",
    "android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:668)",
    "com.umeng.commonsdk.statistics.UMConfigure.init(UMConfigure.java:77)",
    "com.umeng.analytics.MobclickAgent.init(MobclickAgent.java:30)",
    "cn.ixuecheng.App.onCreate(App.java:41)",
    "android.app.ActivityThread.performLaunchActivity(ActivityThread.java:3449)",
)
APP_STACK = _stk(
    "android.provider.Settings$Secure.getString(Settings.java:1234)",
    "cn.ixuecheng.utils.DeviceUtil.getAndroidId(DeviceUtil.java:22)",
    "cn.ixuecheng.ui.SplashActivity.onCreate(SplashActivity.java:88)",
    "android.app.Activity.performCreate(Activity.java:8000)",
)
FW_STACK = _stk(
    "android.os.SystemProperties.get(SystemProperties.java:100)",
    "android.app.ActivityThread.handleBindApplication(ActivityThread.java:6230)",
)


def run(check) -> None:
    print("— 调用栈归因")

    # ---- ① 帧解析 ----
    check("去掉 at 前缀取类名",
          A.frame_class("at com.x.Y.z(File.java:1)") == "com.x.Y.z",
          A.frame_class("at com.x.Y.z(File.java:1)"))
    check("Native Method 也能解析",
          A.frame_class("com.x.N.m(Native Method)") == "com.x.N.m")
    check("取栈失败标记不误判为类名",
          A.frame_class("<调用栈获取失败: boom>") == "")
    check("空帧安全", A.frame_class("") == "" and A.frame_class(None) == "")

    # ---- ② 框架帧 ----
    for f in ("android.app.Foo.bar(X.java:1)", "java.lang.Thread.sleep(Y.java:2)",
              "androidx.core.A.b(C.java:3)", "com.android.okhttp.internal.Foo.g(D.java:4)",
              "kotlin.jvm.internal.H.i(E.java:5)"):
        check("框架帧识别：%s" % f.split("(")[0], A.is_framework(A.frame_class(f)))
    check("业务包不是框架", not A.is_framework("cn.ixuecheng.utils.DeviceUtil"))

    # ---- ③ App 自身行为 ----
    a = A.analyze_stack(APP_STACK, APP)
    check("★ App 自身读取判为 app", a["owner"] == "app", a["owner"])
    check("App 栈的发起点是业务代码",
          a["initiator"] == "cn.ixuecheng.utils.DeviceUtil.getAndroidId", a["initiator"])
    check("App 标签里带包名", "cn.ixuecheng" in a["owner_label"], a["owner_label"])
    check("App 栈不计出 SDK", not a["sdk"], a["sdk"])

    # ---- ④ 第三方 SDK 行为 ----
    s = A.analyze_stack(SDK_STACK, APP)
    check("★ 友盟读取判为 sdk", s["owner"] == "sdk", (s["owner"], s["sdk"]))
    check("★ 识别出 SDK 名称", bool(s["sdk"]) and "友盟" in s["sdk"][0]["name"], s["sdk"])
    check("SDK 标签含名称", "友盟" in s["owner_label"], s["owner_label"])
    check("发起点是 SDK 帧",
          s["initiator"].startswith("com.umeng."), s["initiator"])
    check("★ 识别出「App 主动调用 SDK」",
          s["sdk_called_by_app"] is True, s["sdk_called_by_app"])
    check("同一厂商的多条库记录被归并成一个 SDK", len(s["sdk"]) == 1, s["sdk"])

    # SDK 自启动：栈里没有 App 帧
    s2 = A.analyze_stack(_stk(
        "android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:740)",
        "com.umeng.commonsdk.statistics.UMConfigure.init(UMConfigure.java:77)",
        "android.app.ActivityThread.handleBindApplication(ActivityThread.java:6230)",
    ), APP)
    check("SDK 自启动时 sdk_called_by_app=False",
          s2["owner"] == "sdk" and s2["sdk_called_by_app"] is False, s2["sdk_called_by_app"])

    # ---- ⑤ 纯框架栈 ----
    fw = A.analyze_stack(FW_STACK, APP)
    check("纯框架栈判为 framework", fw["owner"] == "framework", fw["owner"])
    check("框架标签写明没读到应用痕迹",
          "未发现" in fw["owner_label"], fw["owner_label"])
    check("框架栈不计入业务主体", A.summarize([FW_STACK], APP)["total"] == 0,
          A.summarize([FW_STACK], APP)["total"])

    # ---- ⑥ 未收录的第三方库 ----
    un = A.analyze_stack(_stk(
        "android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:740)",
        "com.whoisunknown.net.NetUtils.readDevice(NetUtils.java:11)",
    ), APP)
    check("未收录包判为 unknown", un["owner"] == "unknown", un["owner"])
    check("unknown 记录调用点供人工判断",
          "com.whoisunknown.net" in un["initiator"], un["initiator"])

    # ---- ⑦ ★ 护栏：App 自己的包不能被判成同厂商 SDK ----
    # 腾讯系 SDK 大量存在（com.tencent.iot.* 等），若被测 App 就是 com.tencent.*
    # 的自家应用，按根段退化会把 App 自己的类全判给腾讯 SDK。
    own = A.analyze_stack(_stk(
        "android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:740)",
        "com.tencent.mm.plugin.device.DeviceInfo.get(DeviceInfo.java:9)",
    ), "com.tencent.mm")
    check("★ App 自带包名优先于 SDK 库", own["owner"] == "app", (own["owner"], own["sdk"]))
    # App 包是 com.umeng.commonsdk 这种"恰好和库前缀重合"的极端情况
    own2 = A.analyze_stack(_stk(
        "android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:740)",
        "com.umeng.commonsdk.statistics.UMConfigure.init(UMConfigure.java:77)",
    ), "com.umeng.commonsdk")
    check("★ App 包与库前缀完全重合时仍归 App", own2["owner"] == "app", own2["owner"])

    # ---- ⑧ 汇总：混合主体不能被抹成单一主体 ----
    mix = A.summarize([APP_STACK, SDK_STACK], APP)
    check("App + SDK 每条各一 → mixed", mix["owner"] == "mixed", mix["owner"])
    check("mixed 标签两边都点名",
          "应用自身" in mix["owner_label"] and "SDK" in mix["owner_label"], mix["owner_label"])
    check("mixed 说明里给出两边条数", "应用自身 1 条" in mix["text"], mix["text"])

    # 80% 规则：4 条 App + 1 条 SDK 仍判 App
    dom = A.summarize([APP_STACK] * 4 + [SDK_STACK], APP)
    check("★ 80% 以上仍判单一主体", dom["owner"] == "app", (dom["owner"], dom["counts"]))
    check("单一主体时说明里仍列出少数派",
          "另有 1 条调用栈的主体为第三方 SDK" in dom["text"], dom["text"])
    check("★ 少数派不被「均位于」掩盖", "均位于" not in dom["text"], dom["text"])

    # ---- ⑨ 空输入 / 脏输入 ----
    for bad in ([], [[]], [[], []], [["", "   "]]):
        r = A.summarize(bad, APP)
        check("空栈安全（%d 条）" % len(bad), r["total"] == 0 and r["owner"] == "", r)
    check("None 安全", A.summarize(None, APP)["total"] == 0)          # type: ignore[arg-type]
    check("空 app 包名不炸", A.analyze_stack(APP_STACK, "")["owner"] == "unknown",
          A.analyze_stack(APP_STACK, "")["owner"])

    # ---- ⑩ SDK 名单抽取（供政策「未列明」比对用）----
    names = A.sdk_names([SDK_STACK, _stk(
        "android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:740)",
        "cn.jpush.android.api.JPushInterface.init(JPushInterface.java:20)",
        "cn.ixuecheng.App.onCreate(App.java:50)",
    )], APP)
    check("SDK 名单抽到两个不同厂商", len(names) >= 2, names)
    check("SDK 名单去重", len(names) == len(set(names)), names)

    # ---- ⑪ 逐帧标注可读 ----
    lines = A.annotated_frames(s)
    check("逐帧标注条数等于栈深", len(lines) == len(SDK_STACK), len(lines))
    check("标注含 [SDK 名称]", any("[SDK" in x and "友盟" in x for x in lines), lines[:5])
    check("框架帧标 [框架]", lines[0].startswith("[框架]"), lines[0])
    check("App 帧标 [App]", any(x.startswith("[App]") for x in lines), lines[:6])

    # ---- ⑬ ★ 网络栈要穿过传输层 ----
    # 外发类行为的栈顶永远是 OkHttp，不跳过它，结论就变成"外发由 okhttp3 发起"，
    # 等于什么都没回答。实测一条真实栈就是这么来的：
    #   okhttp3.RealCall.enqueue ← cj.mobile.p.f.a ← CJMobileAd.init ← App.registerAD
    net = A.analyze_stack(_stk(
        "okhttp3.RealCall.enqueue(RealCall.java:150)",
        "cj.mobile.p.f.a(CJMobileAd.java:88)",
        "cj.mobile.CJMobileAd.init(CJMobileAd.java:40)",
        "cn.ixuecheng.utils.MyApplication.registerAD(MyApplication.java:66)",
        "android.os.Handler.handleCallback(Handler.java:938)",
    ), APP)
    check("★ 穿过 OkHttp 找到真正的发起方", net["owner"] == "sdk", (net["owner"], net["sdk"]))
    check("★ 发起点是 SDK 而不是 okhttp3",
          net["initiator"].startswith("cj.mobile."), net["initiator"])
    check("传输层帧标为 [通道]",
          any(x.startswith("[通道]") for x in A.annotated_frames(net)),
          A.annotated_frames(net)[:3])
    check("传输层不计入业务主体（仍算 SDK 那条）",
          net["transport_frames"] == 1, net["transport_frames"])

    only_net = A.analyze_stack(_stk(
        "okhttp3.RealCall.enqueue(RealCall.java:150)",
        "okio.RealBufferedSink.flush(RealBufferedSink.java:60)",
    ), APP)
    check("纯传输层栈判为 transport", only_net["owner"] == "transport", only_net["owner"])
    check("纯传输层栈说明里点明「无法判断」",
          "无法判断" in A.summarize([_stk("okhttp3.RealCall.enqueue(R.java:1)")], APP)["text"],
          A.summarize([_stk("okhttp3.RealCall.enqueue(R.java:1)")], APP)["text"])

    # ---- ⑭ SDK 显示名要去掉 @厂商 后缀 ----
    check("SDK 展示名去掉 @ 后缀",
          A.display_name("某广告SDK@某厂商") == "某广告SDK",
          A.display_name("某广告SDK@某厂商"))
    check("无 @ 时原样返回", A.display_name("友盟统计分析") == "友盟统计分析")
    check("说明文字以句号收尾", s and A.summarize([SDK_STACK], APP)["text"].endswith("。"))
    check("SDK 说明写明「SDK 自身发起」",
          "SDK 自身发起" in A.summarize([SDK_STACK], APP)["text"],
          A.summarize([SDK_STACK], APP)["text"])


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
