"""「结论必须与证据同源」的回归测试（不连真机、不读磁盘存档）。

守的是用户 2026-10-27 对 13 份报告的七条意见里最伤可信度的几条：

  ② 结论说的是"同意之前"，配图却是同意之后；
  ③ 结论说"收集了三类"，下面三条栈只有一类对得上；
  ⑤ 描述说"实际收集了存储文件"，栈其实是注册传感器监听器；
  ⑥ 描述点名了 5 个 SDK，栈里一个都对不上，也没说是哪个 SDK；
  ⑦ 截图里明明有"相关权限说明"浮窗，却判成未经同步告知。

共同点：**报告里写的话，与手上那份证据不是一回事**。这类错误不会抛异常，
只会让复核员在第一次对照时就不信整份报告，所以必须逐条守住。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiscan import policy as POL                       # noqa: E402
from piiscan.flow import compare as CMP                 # noqa: E402
from piiscan.flow import declaration as DCL             # noqa: E402
from piiscan.flow import models as M                    # noqa: E402
from piiscan.flow import permissions as PERM            # noqa: E402
from piiscan.flow import sop as SOP                     # noqa: E402
from piiscan.models import PIIEvent                     # noqa: E402


def _ev(sig: str, api: str, args: str = "", result: str = "",
        stack=None, before: bool = True) -> PIIEvent:
    return PIIEvent(hook_id="t", category="c", api=api, args=args,
                    result=result, stack=list(stack or []), signal=sig,
                    before_consent=before)


_ST_AID = ["android.provider.Settings$Secure.getString(Native Method)",
           "com.demo.AppUtils.getAndroidId(AppUtils.java:232)"]
_ST_CLIP = ["android.content.ClipboardManager.getPrimaryClip(Native Method)",
            "com.demo.CopyUtil.read(CopyUtil.java:41)"]
_ST_NET = ["android.net.wifi.WifiManager.getConnectionInfo(Native Method)",
           "com.demo.NetUtil.wifi(NetUtil.java:22)"]
_ST_SENSOR = ["android.hardware.SystemSensorManager.registerListener(Native Method)",
              "com.demo.SensorHelper.start(SensorHelper.java:18)"]


def _events():
    return [
        _ev("S006", "android.provider.Settings$Secure#getString()",
            args='["android_id"]', result="120ddd35c9b21f2e", stack=_ST_AID),
        _ev("S046", "android.content.ClipboardManager#getPrimaryClip()",
            result="[text]", stack=_ST_CLIP),
        _ev("S089", "android.net.wifi.WifiManager#getConnectionInfo()",
            result="WifiInfo", stack=_ST_NET),
    ]


def run(check) -> None:
    # ---- ③ 描述里的每一类，都要有属于它自己的栈 ----
    evs = _events()
    col = CMP.collected_types(evs)
    desc = CMP.describe_collected(col, with_count=True)
    check("③ 描述带每类的次数", "次" in desc, desc)
    check("③ 描述只写有取值的类型（设备标识符在）", "设备标识符" in desc, desc)

    # `collected_types` 只给"取到有效值"的类；没有具体成员（只有接口调用）
    # 的类不进主句，也不该占一条栈 —— 这条口径见 describe_collected。
    check("③ 只有接口调用的类型不进主句",
          "剪贴板" not in desc and "网络标识" not in desc, desc)
    check("③ 它们改列在「另见接口调用」",
          "剪贴板" in CMP.describe_calls_only(col), CMP.describe_calls_only(col))

    # 栈必须**按类型**取：描述里出现的每一类，都要有属于它自己的那条栈。
    _col = {
        "P01": {"name": "设备标识符", "count": 6,
                "members": {"Android ID": {"count": 6,
                                           "values": ["120ddd35c9b21f2e"]}}},
        "P09": {"name": "剪贴板", "count": 1,
                "members": {"剪贴板内容": {"count": 1, "values": ["合同编号"]}}},
    }
    stk, missing = CMP.stacks_by_type(_col, evs, per_type=1, limit=6)
    tops = [s[0] for s in stk]
    check("③ 两类各给一条栈", len(stk) == 2, str(tops))
    check("③ 设备标识符的栈是 getAndroidId 那条", _ST_AID[0] in tops, str(tops))
    check("③ 剪贴板有自己的栈", _ST_CLIP[0] in tops, str(tops))
    check("③ 不会把别的类型的栈挪过来凑数",
          _ST_NET[0] not in tops, str(tops))
    # 有类型但一个栈都没有时，必须报出来（由事实表明写"无可用调用栈"）
    _stk2, _miss2 = CMP.stacks_by_type(
        {"P01": {"name": "设备标识符", "count": 1,
                 "members": {"Android ID": {"count": 1, "values": ["x"]}}}},
        [e for e in evs if "P01" not in e.api and "Secure" not in e.api], limit=4)
    check("③ 无栈的类型要报出来", "设备标识符" in _miss2, str(_miss2))

    # 只有接口调用、没取到值的类型：不得进主句，只进"另见接口调用"
    weak = CMP.collected_types([_ev("S036", "android.hardware.SystemSensorManager#registerListener()",
                                    result="true", stack=_ST_SENSOR)])
    d2 = CMP.describe_collected(weak, with_count=True)
    check("③ 未取到值的类型不进主句", "传感器" not in d2, d2)
    check("③ 未取到值的类型进「另见接口调用」", "传感器" in CMP.describe_calls_only(weak),
          CMP.describe_calls_only(weak))

    # ---- ⑤ 注册传感器 ≠ 收集存储文件 ----
    check("⑤ registerListener 归到传感器信息而不是存储文件",
          all(v.get("name") != "存储文件" for v in weak.values()), str(weak.keys()))

    # ---- ⑥ 清单里的 SDK 名要把行号 / 半截括号清掉 ----
    check("⑥ 去掉前导行号", DCL._clean_name("5 阿里云推送") == "阿里云推送",
          DCL._clean_name("5 阿里云推送"))
    check("⑥ 半截括号截断", DCL._clean_name("11 友盟推送（高级版本") == "友盟推送",
          DCL._clean_name("11 友盟推送（高级版本"))
    check("⑥ 正常名字不被改坏", DCL._clean_name("神策分析 Android SDK") == "神策分析 Android SDK",
          DCL._clean_name("神策分析 Android SDK"))

    # ---- ⑥ SDK 名残留的行号不会再出现在结论里 ----
    rows = [
        {"name": "smsdk", "matched_by": "未列明",
         "missing_pi": [{"pi": "P02", "name": "网络标识与状态"}]},
        {"name": "支付宝设备标识生成库", "matched_by": "同厂商（阿里巴巴）已列明",
         "group": "阿里巴巴", "same_vendor_sdks": ["阿里云推送", "友盟推送", "高德"],
         "missing_pi": []},
    ]
    txt = DCL.describe({"stats": {"observed_sdk": 2, "sdk_same_vendor": 1},
                        "sdk_rows": rows})
    check("⑥ 同厂商放宽要点名是哪个 SDK", "支付宝设备标识生成库" in txt, txt)
    check("⑥ 不再出现裸编号", "5 阿里云推送" not in txt and "11 友盟" not in txt, txt)

    # ---- ⑦ 同屏浮窗里的用途说明算同步告知 ----
    banner = ("相关权限说明：获取存储空间权限 用于获取您手机内的视频,图片,音频文件信息 "
              "若拒绝该功能将无法使用")
    sc = PERM.judge_scene({"perm": "照片", "banner_text": banner, "pre_text": "首页"})
    check("⑦ 浮窗说明了存储权限的用途", sc.get("purpose") == "banner", str(sc.get("purpose")))
    check("⑦ 浮窗说明不会顺带洗白别的权限",
          PERM.judge_scene({"perm": "通讯录", "banner_text": banner,
                            "pre_text": "首页"}).get("purpose") == "none")

    # 弹窗压住浮窗时，结构树只读到弹窗前那一屏 —— 那一屏写了用途也算
    sc2 = PERM.judge_scene({"perm": "定位", "pre_text": "需要开启定位权限，查看已连接的WIFI"})
    check("⑦ 申请前一刻的界面说明也算同步告知", sc2.get("purpose") == "pre",
          str(sc2.get("purpose")))
    # 跨子句拼接不算：空格拼起来的整段文字不能当"同句说明"
    sc3 = PERM.judge_scene({"perm": "照片",
                            "pre_text": "需要开启定位权限 查看已连接的WIFI 投图片 显示 未找到文件"})
    check("⑦ 跨子句拼出的「说明」不算", sc3.get("purpose") == "none", str(sc3.get("purpose")))

    # 没看过浮窗 → 只能说疑似，不能确证"未告知"
    j = PERM.judge([{"perm": "照片", "pre_text": "首页", "banner_unread": True}])
    check("⑦ 浮窗未核过时判疑似（不确证未告知）", j["state"] == M.SUSPECT, j["state"])
    check("⑦ 疑似理由里写明「同屏浮窗」", "浮窗" in j["desc"], j["desc"][:80])
    j2 = PERM.judge([{"perm": "照片", "pre_text": "首页",
                      "banner_text": banner}])
    check("⑦ 读到了浮窗说明就是未发现问题", j2["state"] == M.PASS, j2["state"])

    # ---- ① 政策来源域名闸门：SDK 厂商的政策页不能当 App 的政策 ----
    for u in ("https://www.pangle.cn/privacy/partner",
              "https://sf6-ttcdn-tos.pstatp.com/obj/ad-tetris-site/personal-privacy-page.html",
              "https://www.umeng.com/policy"):
        check("① 第三方 SDK 域名被识别（%s）" % u[:32], bool(POL.policy_host_reason(u)),
              POL.policy_host_reason(u))
    check("① App 自己的政策域名不被误伤",
          not POL.policy_host_reason("https://app.ygsf.com/privacy.html"))

    # ---- ① 标着政策页、其实还是首启弹窗的截图要被认出来 ----
    import base64
    same = base64.b64encode(b"\x89PNG-same-bytes").decode()
    other = base64.b64encode(b"\x89PNG-other-bytes").decode()
    shots = [{"label": "首启界面 1", "b64": same},
             {"label": "隐私政策页面", "b64": same},
             {"label": "政策页滚动第 1 屏", "b64": other}]
    bad, note = SOP._fake_policy_shots(shots)
    check("① 与首启弹窗同字节的政策页图被剔除", bad == ["隐私政策页面"], str(bad))
    check("① 真政策页截图不受影响", "政策页滚动第 1 屏" not in bad, str(bad))
    check("① 剔除时必须留下说明", "逐字节相同" in note, note[:60])

    # ---- ④ 运行有效性：三种状态要分得开 ----
    def _scr(rows):
        return [{"label": "screen %d" % i, "activity": a, "texts": t}
                for i, (a, t) in enumerate(rows, 1)]
    h1 = M.assess_run_health(_scr([("com.miui.home/.Launcher",
                                    ["桌面", "Now Playing"]),
                                   ("com.miui.home/.Launcher", ["桌面", "设置"])]),
                             "com.demo.app")
    check("④ 全程桌面 = 应用没起来", h1["state"] == "no_app", str(h1))
    h2 = M.assess_run_health(_scr([("com.demo.app/.Main", ["", ""]),
                                   ("com.demo.app/.Main", ["", ""])]),
                             "com.demo.app")
    check("④ 进过应用但读不到文字 = no_ui", h2["state"] == "no_ui", str(h2))
    h3 = M.assess_run_health(_scr([("com.demo.app/.Main", ["首页", "我的", "设置"])]),
                             "com.demo.app")
    check("④ 正常拿到界面文字 = ok", h3["state"] == "ok", str(h3))
    check("④ 反复重启不等于没启动（有界面就 ok）",
          M.assess_run_health(_scr([("com.demo.app/.Main", ["首页", "我的"])]),
                              "com.demo.app")["state"] == "ok")


    # ---- ④' 应用起来了但界面导不出来 ≠ 应用没运行（洋葱学园 2026-10-27）----
    h4 = M.assess_run_health(_scr([("com.miui.home/.Launcher", ["桌面"])]),
                             "com.demo.app", foreground_seen=True)
    check("④ 亲眼见前台切到应用、却没留下界面 = no_dump",
          h4["state"] == "no_dump", str(h4))
    check("④ 这种情况不能写成「前台从未切换」",
          "从未切换" not in h4["why"], h4["why"])
    h5 = M.assess_run_health(_scr([("com.demo.app/.Main", ["", ""])]),
                             "com.demo.app", hook_hostile=2)
    check("④ 注入被加固拦截要标记出来", h5.get("hook_blocked") is True, str(h5))
    check("④ 拦截导致的数据缺失要写进原因",
          "加固" in h5["why"] and "不代表应用自身无法运行" in h5["why"], h5["why"])

    # ---- ④'' 录了屏却一屏都归不了类：不许断言"前台从未切换"（2026-10-30）----
    #   真机上 dump 成功但 Activity 取不到时会留一条空壳屏记录。此时我们手上是
    #   "看不清"，不是"看见了没进" —— 写成 no_app 等于替应用下结论。
    h6 = M.assess_run_health([{"label": "s1"}, {"label": "s2"}, {"label": "s3"}],
                             "com.demo.app")
    check("④ 录了屏但都归不了类 → no_dump 而不是 no_app",
          h6["state"] == "no_dump", str(h6))
    check("④ 这种情况也不能写「从未切换」",
          "从未切换" not in h6["why"], h6["why"])
    _head6, _ = M.start_failed_reason(
        type("FR", (), {"run_health": h6, "relaunch_count": 3,
                        "app_crash": {}, "runtime_data": {}})())
    check("④ 未确认前台时不许写「已确认前台切换」",
          "已确认前台" not in _head6, _head6)

    # ---- ①' 政策文本解码：UTF-16 不能解成乱码 ----
    body = "【隐私政策】本政策仅适用于本 App，我们收集设备标识符用于安全风控。"
    u16 = body.encode("utf-16-le")
    check("①' UTF-16LE 带 BOM 能正确解码",
          "隐私政策" in POL._decode(bytes([0xff, 0xfe]) + u16), POL._decode(u16)[:20])
    check("①' 无 BOM 的 UTF-16LE 靠 NUL 密度也能认出来",
          "隐私政策" in POL._decode(u16), POL._decode(u16)[:20])
    _garbage = (chr(0) + "<" + chr(0) + "h" + chr(0) + "t" + chr(0) + "m" + chr(0) + "l") * 60
    # 乱码的坏字符占比接近 50%，离 0.98 的闸门很远 —— 这里量的就是"能不能过闸"，
    # 不是精确比例，所以按闸门断言。
    check("①' 乱码的文本质量分过不了 0.98 的闸",
          POL._text_quality(_garbage) < 0.98, str(POL._text_quality(_garbage)))
    check("①' 乱码过不了内置政策的两道闸",
          not POL.looks_like_privacy_policy(_garbage),
          str(POL.looks_like_privacy_policy(_garbage)))
    # 真实形态：带标签的 HTML（ASCII 多）用 UTF-16LE 存盘，无 BOM。
    # 金考典 assets/privacy.htm 就是这样，被 gb18030 解成 206132 字 `< h t m l`。
    _html = ("<html><head><meta charset='utf-8'><title>隐私政策</title></head>"
             "<body><h1>隐私政策</h1><p>本政策仅适用于本 App。</p>"
             "<p>我们收集设备标识符用于安全风控，不会向第三方提供。</p>"
             "</body></html>") * 4
    _h16 = _html.encode("utf-16-le")
    check("①' UTF-16LE 的 HTML 正文能读回中文（金考典 206132 字乱码）",
          "隐私政策" in POL._decode(_h16) and "< h t" not in POL._decode(_h16),
          repr(POL._decode(_h16)[:40]))
    check("①' 解码结果字数与原文字数一致",
          len(POL._decode(u16)) == len(body), "%d 字" % len(POL._decode(u16)))
    check("①' 正常中文文本质量分为 1",
          POL._text_quality(body) > 0.99, str(POL._text_quality(body)))

    # ---- ⑥' hook 里写死的 signal 编号必须与信号表一致（金考典 2026-10-27）----
    #      getPackagesForUid 曾被标成 S041（通话记录）→「获取应用列表」被报成
    #      敏感个人信息。只要 api 在信号表里登记过，编号就必须与表一致。
    import re as _re
    import yaml as _yaml
    _js = (ROOT / "piiscan" / "hooks" / "collector.js").read_text(encoding="utf-8")
    _sm = _yaml.safe_load((ROOT / "analysis" / "signal_map.yaml")
                          .read_text(encoding="utf-8"))
    _api2sig = {}
    for _sg in (_sm.get("signals") or []):
        for _a in _sg.get("api") or []:
            _api2sig.setdefault(_a.replace("()", ""), []).append(_sg["id"])
    _bad = []
    for _m in _re.finditer(
            r"install\(\s*'[^']+'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,"
            r"\s*'[^']*'\s*,\s*\{([^}]*)\}", _js, _re.S):
        _cls, _meth, _opts = _m.group(1), _m.group(2), _m.group(3)
        _sig = _re.search(r"signal:\s*'([^']+)'", _opts)
        _ids = _api2sig.get(_cls + "#" + _meth) or []
        if _sig and len(_ids) == 1 and _sig.group(1) != _ids[0]:
            _bad.append("%s#%s: %s≠%s" % (_cls, _meth, _sig.group(1), _ids[0]))
    check("⑥' hook 的 signal 编号与信号表一致", not _bad, "；".join(_bad[:4]))

    # ---- ⑥''' sink 类（本地留存）的 signal 号必须对得上（2026-11-10 Android 10 实测）----
    #      这两处是手写的 emit，不走 install()，⑥' 的正则扫不到，于是长期错标：
    #        SQLiteDatabase.insert/execSQL → S093（发送邮件）
    #        SharedPreferences.Editor.*     → S092（改变网络类型）
    #      后果是报告里"本地数据库写入"被写成"发送邮件"，与金考典那次
    #      「获取应用列表被报成通话记录」是同一类张冠李戴。正确项：
    #        S063 SQLite数据库 / S064 SharedPrefs（两者 pi 均为 null，走 sink K2）
    _bad2 = []
    for _hid, _want in (("sink_sqlite", "S063"), ("sink_sp", "S064")):
        _at = _js.find("emit('" + _hid + "_' + m")
        _got = _re.search(r"signal:\s*'(S\d+)'", _js[_at:_at + 600]) if _at >= 0 else None
        if _at < 0:
            _bad2.append("%s 未找到" % _hid)
        elif not _got or _got.group(1) != _want:
            _bad2.append("%s=%s≠%s" % (_hid, _got.group(1) if _got else "?", _want))
    check("⑥''' 本地存储 sink 的 signal 编号正确（SQLite→S063、SharedPrefs→S064）",
          not _bad2, "；".join(_bad2))

    # ---- ⑥'''' 「调用了但被系统拒绝」不能算「取到有效值」（2026-11-10 Android 10）----
    #      Android 10 起 IMEI / 序列号对普通应用一律抛 SecurityException。
    #      采集侧现在把异常也记成事件（"调用了"是确凿事实），但结果写成
    #      "调用被拒绝：…"。判定层若不排除它，尝试读取就会被算成已收集 ——
    #      这是"未经同意收集设备标识"类结论里最危险的一类误报。
    check("⑥'''' 被系统拒绝的调用不算有效取值",
          CMP._valid_value("调用被拒绝：java.lang.SecurityException: getImei") is False,
          CMP._valid_value("调用被拒绝：java.lang.SecurityException: getImei"))
    check("⑥'''' 正常取值仍算有效（不误伤）",
          CMP._valid_value("9893a5aebfd56f37") is True)

    # ---- ⑥'' 栈要按类型存：同一个 SDK 的两种行为各有各的栈 ----
    inv = {
        "vocab": {"P13": {"name": "传感器信息", "class": "一般个人信息"},
                  "P07": {"name": "应用信息", "class": "一般个人信息"}},
        "by_key": {"sdk:腾讯": {
            "kind": "sdk", "name": "腾讯图灵盾", "vendor": "腾讯", "group": "腾讯",
            "count": 2, "before": 0, "apis": ["registerListener", "getPackagesForUid"],
            "stacks": [_ST_SENSOR, ["android.app.ApplicationPackageManager.getPackagesForUid(Native Method)",
                                    "com.tencent.turingfd.sdk.ams.au.Bryony.e(A:12)"]],
            "pi": {
                "P13": {"name": "传感器信息", "class": "", "count": 1, "before": 0,
                        "members": {}, "stacks": [_ST_SENSOR]},
                "P07": {"name": "应用信息", "class": "", "count": 1, "before": 0,
                        "members": {},
                        "stacks": [["android.app.ApplicationPackageManager.getPackagesForUid(Native Method)",
                                    "com.tencent.turingfd.sdk.ams.au.Bryony.e(A:12)"]]},
            }}},
    }
    _rows = DCL.compare(inv, [], set(), [])
    _pi = {p["pi"]: p for p in _rows["sdk_rows"][0]["observed_pi"]}
    check("⑥'' 传感器信息的栈就是 registerListener 那条",
          _pi["P13"]["stacks"][0][0].startswith("android.hardware.SystemSensorManager"),
          str(_pi["P13"]["stacks"])[:60])
    check("⑥'' 应用信息的栈是 getPackagesForUid 那条",
          "getPackagesForUid" in _pi["P07"]["stacks"][0][0],
          str(_pi["P07"]["stacks"])[:60])

    # ---- ⑦' 域名分角色：CDN/静态资源不是「接收方」（金考典 2026-10-27）----
    #      政策正文解码修好之后，Q007 从「1 个 SDK 未列明」翻成
    #      「5 个第三方地址未列明接收方」，而那 5 个全是图片/静态资源域名。
    from piiscan.flow.compare import host_role as _role
    check("⑦' 云存储/CDN 域名判为静态资源",
          _role("amsweb-cdn-gz-1258344696.file.myqcloud.com") == "static",
          _role("amsweb-cdn-gz-1258344696.file.myqcloud.com"))
    check("⑦' 图片域名判为静态资源",
          _role("pic2.iqiyipic.com") == "static" and _role("qzs.gdtimg.com") == "static",
          "")
    check("⑦' 接口域名保持 api（不许把接口洗成 CDN）",
          _role("ad-api.adn-plus.com.cn") == "api"
          and _role("api.example.com") == "api", "")
    check("⑦' 第三方缺口带上 role 字段",
          all("role" in g for g in
              __import__("piiscan.flow.compare", fromlist=["x"])
              .third_party_gaps(["pic2.iqiyipic.com"], ["无关正文"])), "")
    # 静态资源独占时，结论不能被后面的「域名都能检索到」分支覆盖
    _sop_src = (ROOT / "piiscan" / "flow" / "sop.py").read_text(encoding="utf-8")
    check("⑦' 静态资源独占的结论不会被后续分支改写",
          "_q7_set = True" in _sop_src and "elif hthird and not _q7_set" in _sop_src, "")


__all__ = ["run"]
