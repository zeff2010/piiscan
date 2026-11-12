"""首启着陆（landing / 采集侧挂载 / 报告）的离线用例。

为什么这套要用例密集：着陆阶段的每一个误判都不是"少走一步"，而是
**整份报告作废** ——
  · 把广告主体当"可点入口"→ 外跳电商页，后面几十屏全是别人的界面；
  · 把兴趣标签当"跳过"→ 我们替用户写了画像，还影响个性化推荐类判定；
  · 把登录页判成引导页 → 去左滑一个登录页，永远滑不出主页面；
  · 把骨架屏判成主页面 → 在还没有入口的页面上开始遍历。

这些错误在真机上都不报错，只是"结果变差"，所以只能靠离线用例钉住。
八个形态样本全部取自 2026-11-05/06 四台真机的实测界面文字。
"""

import inspect

from piiscan import landing, uiwalk
from piiscan import collector
from piiscan.report import sop_report


def _xml(items):
    """按 (text, cls, clickable, x1, y1, x2, y2) 拼一棵结构树。"""
    body = "".join(
        '<node text="%s" class="%s" clickable="%s" bounds="[%d,%d][%d,%d]"'
        ' package="a" content-desc="" checkable="false" checked="false"'
        ' enabled="true" scrollable="false" resource-id="" />'
        % (t, c, "true" if k else "false", a, b, d, e)
        for (t, c, k, a, b, d, e) in items)
    return '<hierarchy rotation="0">%s</hierarchy>' % body


# ---------------- 八个实测形态 ----------------
# ① 携船网：pages/expand/entry/guide + 「跳过:」+ 拆成两个节点的倒计时（00 / s）
_X_AD = _xml([
    ("pages/expand/entry/guide[1", "android.widget.TextView", 0, 20, 60, 400, 100),
    ("跳过:", "android.widget.TextView", 1, 900, 80, 1000, 130),
    ("00", "android.widget.TextView", 0, 1010, 80, 1050, 130),
    ("s", "android.widget.TextView", 0, 1055, 80, 1070, 130),
    ("95e348f17e6584e79f2b3275f6", "android.widget.ImageView", 1, 0, 300, 1080, 1600),
])
# ② 高途：青少年守护年龄门
_X_AGE = _xml([
    ("青少年守护", "android.widget.TextView", 0, 300, 800, 780, 880),
    ("由于您未满14岁，请确保您已获得监护人的同意，再使用", "android.widget.TextView",
     0, 100, 900, 980, 1050),
    ("退出App", "android.widget.Button", 1, 100, 1700, 500, 1800),
    ("监护人已同意", "android.widget.Button", 1, 580, 1700, 980, 1800),
])
# ③ 春雨诊所：登录页（标题就叫「欢迎使用…」）
_X_LOGIN = _xml([
    ("欢迎使用春雨诊所", "android.widget.TextView", 0, 200, 600, 880, 680),
    ("自由执业，从春雨开始", "android.widget.TextView", 0, 200, 700, 880, 760),
    ("13800000000", "android.widget.EditText", 1, 200, 1100, 880, 1200),
    ("密码", "android.widget.EditText", 1, 200, 1220, 880, 1320),
    ("登录", "android.widget.Button", 1, 200, 1500, 880, 1600),
])
# ③.5 实名认证页（春雨诊所 2026-11-06 登录后真实落在这一屏）
_X_REALNAME = _xml([
    ("实名认证", "android.widget.TextView", 0, 60, 200, 1020, 280),
    ("执业信息", "android.widget.TextView", 0, 60, 360, 300, 420),
    ("执业证件", "android.widget.TextView", 0, 340, 360, 560, 420),
    ("实名信息", "android.widget.TextView", 0, 600, 360, 820, 420),
    ("人脸认证", "android.widget.TextView", 0, 860, 360, 1020, 420),
    ("手写签名", "android.widget.TextView", 0, 60, 450, 300, 510),
    ("请务必填写本人姓名", "android.widget.EditText", 1, 400, 640, 1020, 720),
    ("下一步", "android.widget.Button", 1, 60, 2100, 1020, 2200),
])
# ④ 兴趣收集页（带「跳过」—— 这是最容易被误判成广告页的原因）
_X_INTEREST = _xml([
    ("请选择你感兴趣的内容", "android.widget.TextView", 0, 100, 200, 980, 260),
    ("至少选择 3 个", "android.widget.TextView", 0, 100, 280, 980, 340),
    ("篮球", "android.widget.TextView", 1, 100, 500, 300, 580),
    ("足球", "android.widget.TextView", 1, 340, 500, 540, 580),
    ("音乐", "android.widget.TextView", 1, 580, 500, 780, 580),
    ("跳过", "android.widget.TextView", 1, 900, 120, 1040, 180),
])
# ⑤ 引导页：没有可点节点，只能左滑
_X_GUIDE = _xml([
    ("功能介绍", "android.widget.TextView", 0, 100, 400, 980, 470),
    ("上滑进入下一页", "android.widget.TextView", 0, 100, 1800, 980, 1860),
])
# ⑥ 版本更新弹窗
_X_UPDATE = _xml([
    ("发现新版本 5.9.3", "android.widget.TextView", 0, 200, 900, 880, 980),
    ("稍后再说", "android.widget.Button", 1, 200, 1500, 500, 1600),
    ("立即更新", "android.widget.Button", 1, 580, 1500, 880, 1600),
])
# ⑦ 促销弹窗
_X_PROMO = _xml([
    ("限时红包", "android.widget.TextView", 0, 300, 800, 780, 880),
    ("新人专享礼包等你领取", "android.widget.TextView", 0, 200, 900, 880, 980),
    ("立即领取", "android.widget.Button", 1, 300, 1400, 780, 1500),
    ("关闭", "android.widget.ImageView", 1, 950, 700, 1040, 790),
])
# ⑧ 主页面：底部四个 tab
_X_HOME = _xml([
    ("推荐", "android.widget.TextView", 1, 100, 200, 300, 260),
    ("搜索课程", "android.widget.TextView", 1, 100, 300, 900, 400),
    ("首页", "android.widget.TextView", 1, 30, 2280, 200, 2380),
    ("学习", "android.widget.TextView", 1, 300, 2280, 470, 2380),
    ("消息", "android.widget.TextView", 1, 570, 2280, 740, 2380),
    ("我的", "android.widget.TextView", 1, 840, 2280, 1050, 2380),
])
# ⑨ 高途：首启学段调研页（2026-11-06 用户反馈：被当功能遍历逐个点选项）
_X_SURVEY = _xml([
    ("请选择您的学习阶段", "android.widget.TextView", 0, 100, 300, 980, 380),
    ("小学", "android.widget.TextView", 1, 100, 600, 500, 720),
    ("初中", "android.widget.TextView", 1, 580, 600, 980, 720),
    ("高中", "android.widget.TextView", 1, 100, 800, 500, 920),
    ("大学", "android.widget.TextView", 1, 580, 800, 980, 920),
    ("成人教育", "android.widget.TextView", 1, 100, 1000, 500, 1120),
    ("进入首页", "android.widget.Button", 1, 100, 1900, 980, 2020),
])


def _nodes(x):
    return uiwalk.clickable(x)


def _planned(x):
    c = landing.classify(x)
    p = landing.plan(c["form"], _nodes(x), list(uiwalk.screen_texts(x)))
    return c, p


def _label(n):
    return landing._texts_of(n) if n is not None else ""


def run(check) -> None:
    # ================================================ 形态分类
    forms = [
        ("携船网开屏广告（跳过 + 拆开的倒计时）", _X_AD, "splash_ad"),
        ("高途年龄门（未满14 / 监护人已同意）", _X_AGE, "age_gate"),
        ("春雨登录页（标题是「欢迎使用」）", _X_LOGIN, "login"),
        ("兴趣收集页（带跳过）", _X_INTEREST, "interest_picker"),
        ("欢迎引导页（无可点节点）", _X_GUIDE, "guide_pager"),
        ("版本更新弹窗", _X_UPDATE, "update_dialog"),
        ("促销弹窗", _X_PROMO, "promo_dialog"),
        ("主页面（底部四个 tab）", _X_HOME, "home"),
        ("高途学段调研页（选一项+进入首页）", _X_SURVEY, "survey_gate"),
    ]
    for name, x, want in forms:
        c = landing.classify(x)
        check("★ 形态判对：%s → %s" % (name, want),
              c["form"] == want, "实得 %s（%s）" % (c["form"], c["why"][:40]))

    # 判读必须说清"凭什么"，否则报告里的结论没有依据
    c = landing.classify(_X_LOGIN)
    check("判读文案带依据（不是只给一个名字）", len(c["why"]) >= 8, c["why"])
    check("空界面不抛异常、判 unknown",
          landing.classify("")["form"] == "unknown", "")

    # ============================================ 实名 / 资质认证墙
    # 2026-11-06 春雨诊所实测：登录成功后不是主页面，而是「实名认证」——
    # 要姓名、执业科室、执业证件、人脸认证、手写签名。这一步过不去，
    # **也不该过**（填的是别人的真实身份）。以前没有这一类，它被当成
    # "未识别界面"，模型看截图就建议"填表继续"。
    c_rn = landing.classify(_X_REALNAME)
    check("★ 实名认证页要能识别出来（不能被当成登录页）",
          c_rn["form"] == "realname_gate", c_rn["form"])
    check("实名认证页要说明凭什么这么判", "实名" in c_rn["why"], c_rn["why"])
    check("实名认证属于门禁形态（模型说\"到了\"也不许采信）",
          landing.is_gate("realname_gate"), "")
    _a_rn = landing.plan("realname_gate", landing.uiwalk.parse_all(_X_REALNAME), [])
    check("★ 实名认证页要直接收工，不试任何动作",
          _a_rn["action"] == "give_up" and _a_rn.get("code") == "realname_wall",
          _a_rn.get("action"))
    check("收工理由要写清\"检测方不具备该条件\"，不许写成应用没这功能",
          "不具备" in _a_rn["why"] and "未覆盖" in _a_rn["why"], _a_rn["why"])
    # 政策正文里也会出现"实名认证"这一个词，单个词就判会把政策页认错
    _x_one = _xml([("本平台依据实名认证要求收集您的身份信息",
                    "android.widget.TextView", 0, 60, 200, 1020, 280)])
    check("只有单个\"实名认证\"词时不许判成认证墙（政策正文会误伤）",
          landing.classify(_x_one)["form"] != "realname_gate",
          landing.classify(_x_one)["form"])
    # ★ 春雨诊所的「授权提示」页（2026-11-06 land27 实测原文）：
    #   它把"上传证件照片""人脸识别""证件照"写在权限说明里 —— 三个弱词同时命中，
    #   于是被误判成实名认证墙，着陆 2.9 秒就收工。弱词不算证据，必须有强词。
    _x_perm = _xml([
        ("授权提示", "android.widget.TextView", 0, 60, 380, 1020, 440),
        ("在使用过程中，可能需要您授权我们获取以下权限", "android.widget.TextView",
         0, 60, 460, 1020, 520),
        ("存储权限", "android.widget.TextView", 0, 60, 620, 1020, 680),
        ("注册时上传证件照片；咨询中发送语音、图片、视频", "android.widget.TextView",
         0, 60, 690, 1020, 750),
        ("相机权限", "android.widget.TextView", 0, 60, 780, 1020, 840),
        ("注册时拍摄证件照片；咨询中拍摄并发送图片、视频；人脸识别时需要该权限",
         "android.widget.TextView", 0, 60, 850, 1020, 940),
        ("我知道了", "android.widget.Button", 1, 60, 1900, 1020, 2000),
    ])
    check("★ 权限说明页里出现\"证件照/人脸识别\"不算实名认证墙（必须有强词）",
          landing.classify(_x_perm)["form"] != "realname_gate",
          landing.classify(_x_perm)["form"])
    check("权限说明页要认成权限引导页（不是未识别）",
          landing.classify(_x_perm)["form"] == "perm_guide",
          landing.classify(_x_perm)["form"])

    # ★ 报告正文里不许出现 Markdown 的星号：`plan()` 的 why/expect 是原样
    #   进 HTML 的（高途 land9 实测把「**可关闭的登录弹窗**」连星号印了出来）。
    #   注释和 docstring 里随便写，但**进报告的字段**必须干净。
    _dirty = []
    for name, x, _want in forms:
        _c, _p = _planned(x)
        for _k in ("why", "expect"):
            if "**" in str(_p.get(_k) or ""):
                _dirty.append("%s/%s=%s" % (name, _k, str(_p.get(_k))[:30]))
        if "**" in str(_c.get("why") or ""):
            _dirty.append("%s/判读=%s" % (name, str(_c.get("why"))[:30]))
    check("★ 进报告的判读/理由里不许有 Markdown 星号", not _dirty, "；".join(_dirty[:3]))

    # ================================================ 动作规划
    c, p = _planned(_X_AD)
    check("★ 开屏广告点「跳过」而不是点广告主体",
          p["action"] == "tap" and "跳过" in _label(p["node"]), _label(p["node"]))
    c, p = _planned(_X_AGE)
    check("★ 年龄门点「监护人已同意」，绝不点「退出App」",
          p["action"] == "tap" and "监护人" in _label(p["node"]), _label(p["node"]))
    c, p = _planned(_X_INTEREST)
    check("★ 兴趣页只点「跳过」，不点任何一个标签",
          p["action"] == "tap" and "跳过" in _label(p["node"]), _label(p["node"]))
    c, p = _planned(_X_GUIDE)
    check("★ 引导页没有可点按钮时左滑翻页（不是干等）",
          p["action"] == "swipe" and p.get("direction") == "left", p["action"])
    c, p = _planned(_X_UPDATE)
    check("★ 更新弹窗点「稍后再说」，不点「立即更新」",
          p["action"] == "tap" and "稍后" in _label(p["node"]), _label(p["node"]))
    c, p = _planned(_X_PROMO)
    check("促销弹窗点关闭类按钮",
          p["action"] == "tap" and ("关闭" in _label(p["node"])), _label(p["node"]))
    c, p = _planned(_X_LOGIN)
    check("★ 登录页不代填、直接交棒（give_up 且代号 login_wall）",
          p["action"] == "give_up" and p.get("code") == "login_wall", p["action"])
    c, p = _planned(_X_HOME)
    check("主页面直接 done", p["action"] == "done", p["action"])

    # 每个决定都要带判读与预判 —— 报告里这两列不能空
    for name, x in (("广告", _X_AD), ("引导页", _X_GUIDE), ("兴趣页", _X_INTEREST)):
        _, p = _planned(x)
        check("%s的动作带判读与预判" % name,
              bool(p.get("why")) and bool(p.get("expect")), p.get("code"))

    # ================================================ 禁点清单
    ad = _nodes(_X_AD)
    body = [n for n in ad if "95e3" in _label(n)]
    check("★ 开屏页的广告主体被拦（点它会外跳）",
          bool(body) and "外跳" in landing.forbidden(body[0], "splash_ad"), "")
    interest = _nodes(_X_INTEREST)
    tag = [n for n in interest if _label(n) == "篮球"]
    check("★ 兴趣标签被拦（不代替用户做画像选择）",
          bool(tag) and "画像" in landing.forbidden(tag[0], "interest_picker"), "")
    upd = _nodes(_X_UPDATE)
    up = [n for n in upd if "立即更新" in _label(n)]
    check("★ 「立即更新」被拦（会换掉被测版本）",
          bool(up) and "被测版本" in landing.forbidden(up[0], "update_dialog"), "")
    promo = _nodes(_X_PROMO)
    grab = [n for n in promo if "立即领取" in _label(n)]
    check("「立即领取」被拦（会拉起领取/支付流程）",
          bool(grab) and bool(landing.forbidden(grab[0], "promo_dialog")), "")
    check("普通可点的「跳过」不被拦",
          landing.forbidden([n for n in ad if "跳过" in _label(n)][0], "splash_ad") == "",
          "")

    # ================================================ 主页面判定
    ok, why = landing.is_home(_X_HOME)
    check("★ 底部四个 tab → 判为主页面", ok, why)
    ok2, why2 = landing.is_home(_X_GUIDE)
    check("引导页不判为主页面（否则会在引导页上开始遍历）", not ok2, why2)
    ok3, why3 = landing.is_home(_X_PROMO)
    check("弹窗页不判为主页面", not ok3, why3)
    # 只有两个 tab 的页面不够（很多二级页也有底部两栏）
    two = _xml([("返回", "android.widget.TextView", 1, 30, 2280, 200, 2380),
                ("完成", "android.widget.TextView", 1, 840, 2280, 1050, 2380),
                ("标题", "android.widget.TextView", 0, 100, 300, 900, 400)])
    ok4, why4 = landing.is_home(two)
    check("只有两个底部入口不算主页面", not ok4, why4)

    # confirm_home：单次判是还不够，要连续两次且指纹稳定
    okc, _ = landing.confirm_home([{"is_home": True, "fp": "a"}], 2)
    check("只判到一次首页时不算到（防骨架屏）", not okc, "")
    okc2, _ = landing.confirm_home([{"is_home": True, "fp": "a"},
                                    {"is_home": True, "fp": "a"}], 2)
    check("连续两次同一指纹判为首页", okc2, "")
    okc3, _ = landing.confirm_home([{"is_home": True, "fp": "a"},
                                    {"is_home": True, "fp": "b"}], 2)
    check("两次都像首页但指纹在变 → 还在跳转，不算到", not okc3, "")
    okc4, _ = landing.confirm_home([{"is_home": True, "fp": "a"},
                                    {"is_home": False, "fp": "a"}], 2)
    check("最近一次不是首页形态 → 不算到", not okc4, "")

    # ================================================ 汇总与文案
    s = landing.summary([
        {"form": "splash_ad", "action": "tap", "why": ""},
        {"form": "guide_pager", "action": "swipe", "why": ""},
        {"form": "home", "action": "done", "why": ""},
    ], True, "连续 2 次判为首页且界面稳定", 12.3)
    check("汇总：到达主页面、路径去重成三段",
          s["reached_home"] and s["forms"] == ["splash_ad", "guide_pager", "home"],
          str(s["forms"]))
    check("汇总：滑动与点击分别计数",
          s["taps"] == 1 and s["swipes"] == 1, "%s/%s" % (s["taps"], s["swipes"]))
    txt = landing.describe_path(s)
    check("文案说清经过了哪些环节、用了几次动作",
          "开屏广告页" in txt and "主页面" in txt, txt[:60])
    s2 = landing.summary([{"form": "login", "action": "give_up",
                           "why": "已到登录/注册页"}], False, "登录墙", 8.0)
    txt2 = landing.describe_path(s2)
    check("★ 没进主页面时文案必须写清原因（否则读者误以为工具点不动）",
          "未能进入主页面" in txt2 and "登录墙" in txt2, txt2[:80])
    s3 = landing.summary([{"form": "splash_ad", "action": "wait", "why": ""},
                          {"form": "home", "action": "done", "why": ""}],
                         True, "", 9.0)
    txt3 = landing.describe_path(s3)
    check("★ 0 次动作时文案要解释「为什么是 0」（不是让读者以为程序没动）",
          "没有可点击" in txt3 and "自行跳转" in txt3, txt3[:70])
    check("空汇总不抛异常", landing.describe_path({}) == "", "")

    check("形态名是人话（不是内部键名）",
          landing.form_name("splash_ad") == "开屏广告页"
          and landing.form_name("home") == "主页面", landing.form_name("splash_ad"))

    # ================================================ 启动页 / 文字锚点（真机补）
    # 纯品牌启动页：只有 logo，没有任何可点元素。判成 unknown 会去按返回 →
    # 把应用退到桌面 → 重拉 → 再退，整轮预算烧在"启动页与桌面之间"。
    splash = _xml([("logo", "android.widget.ImageView", 0, 300, 900, 780, 1200)])
    c = landing.classify(splash)
    check("★ 纯启动页判成「启动/加载页」，不是未识别",
          c["form"] == "splash_wait", c["form"])
    p = landing.plan("splash_wait", _nodes(splash), [])
    check("★ 启动页只等待，不按返回（按返回会退出应用）",
          p["action"] == "wait" and p["code"] == "wait_splash", p["action"])
    p = landing.plan("splash_wait", [], [], wait_rounds=3)
    check("启动页等满 3 次仍未跳转就停下并写明原因",
          p["action"] == "give_up" and p["code"] == "stuck_splash", p["code"])

    # 开屏广告的「跳过」在结构树里不可点（uni-app / H5 的常见形态）：
    # 携船网真机实测因此连等 3 轮广告自己结束。按文字位置点它。
    ad_text = _xml([
        ("跳过:", "android.widget.TextView", 0, 900, 80, 1000, 130),
        ("00", "android.widget.TextView", 0, 1010, 80, 1050, 130),
        ("s", "android.widget.TextView", 0, 1055, 80, 1070, 130),
        ("banner", "android.widget.ImageView", 1, 0, 300, 1080, 1600),
    ])
    c = landing.classify(ad_text)
    p = landing.plan(c["form"], uiwalk.parse_all(ad_text), list(uiwalk.screen_texts(ad_text)))
    check("★ 「跳过」不可点击时按文字位置点它（否则只能干等广告结束）",
          p["action"] == "tap" and "跳过" in _label(p["node"])
          and p.get("text_anchor") is True, "%s/%s" % (p["action"], _label(p["node"])))
    check("文字锚点的点击在判读里写明依据（复核员要知道这不是普通点击）",
          "没有点击属性" in p["why"], p["why"][:50])

    # 但**不能**把文字锚点用到兴趣标签上：那等于绕过"不代选"的红线。
    it_text = _xml([
        ("请选择你感兴趣的内容", "android.widget.TextView", 0, 100, 200, 980, 260),
        ("篮球", "android.widget.TextView", 0, 100, 500, 300, 580),
        ("足球", "android.widget.TextView", 0, 340, 500, 540, 580),
        ("跳过", "android.widget.TextView", 0, 900, 120, 1040, 180),
    ])
    c = landing.classify(it_text)
    check("兴趣页（标签全不可点）仍判成画像收集页",
          c["form"] == "interest_picker", c["form"])
    p = landing.plan(c["form"], uiwalk.parse_all(it_text), list(uiwalk.screen_texts(it_text)))
    check("★ 兴趣页只按文字点「跳过」，绝不按文字点标签",
          p["action"] == "tap" and _label(p["node"]).strip() == "跳过",
          _label(p["node"]))

    # 游客入口：登录页上的「随便逛逛」是正当的绕过路径，不是代填账号
    guest = _xml([
        ("欢迎使用春雨诊所", "android.widget.TextView", 0, 200, 600, 880, 680),
        ("手机号", "android.widget.EditText", 1, 200, 1100, 880, 1200),
        ("密码", "android.widget.EditText", 1, 200, 1220, 880, 1320),
        ("登录", "android.widget.Button", 1, 200, 1500, 880, 1600),
        ("随便逛逛", "android.widget.TextView", 1, 200, 1650, 880, 1720),
    ])
    c = landing.classify(guest)
    p = landing.plan(c["form"], _nodes(guest), list(uiwalk.screen_texts(guest)))
    check("★ 登录页有游客入口时点它进主页面（不是直接放弃）",
          p["action"] == "tap" and "逛逛" in _label(p["node"])
          and p["code"] == "guest_login", _label(p["node"]))

    # 高途式登录弹窗：关闭叉只有资源 id（`login_view_close`）、没有中文。
    # 只按中文词表找 → 找不到 → 判"登录墙"直接收工，而底下本来就能用。
    lp = _xml([
        ("登录", "android.widget.TextView", 0, 300, 800, 700, 880),
        ("手机号", "android.widget.EditText", 1, 200, 1100, 880, 1200),
        ("登录", "android.widget.Button", 1, 200, 1500, 880, 1600),
        ("", "android.widget.ImageView", 1, 950, 700, 1040, 790),
    ])
    # 上面那条没有 resource-id，下面单独造一条带 id 的
    lp_id = ('<hierarchy rotation="0">'
             '<node text="登录" class="android.widget.TextView" clickable="false"'
             ' bounds="[300,800][700,880]" package="a" content-desc="" resource-id="tv_title"'
             ' checkable="false" checked="false" enabled="true" scrollable="false" />'
             '<node text="手机号" class="android.widget.EditText" clickable="true"'
             ' bounds="[200,1100][880,1200]" package="a" content-desc="" resource-id="et_phone"'
             ' checkable="false" checked="false" enabled="true" scrollable="false" />'
             '<node text="登录" class="android.widget.Button" clickable="true"'
             ' bounds="[200,1500][880,1600]" package="a" content-desc="" resource-id="btn_login"'
             ' checkable="false" checked="false" enabled="true" scrollable="false" />'
             '<node text="" class="android.widget.ImageView" clickable="true"'
             ' bounds="[950,700][1040,790]" package="a" content-desc="" resource-id="login_view_close"'
             ' checkable="false" checked="false" enabled="true" scrollable="false" />'
             '</hierarchy>')
    c = landing.classify(lp_id)
    p = landing.plan(c["form"], uiwalk.parse_all(lp_id), list(uiwalk.screen_texts(lp_id)))
    check("★ 登录弹窗的关闭叉只有资源 id 时也要认出来并点它（不是判成登录墙）",
          p["action"] == "tap" and p["code"] == "close_login", p["code"])

    # 引导页的按钮文案（高途实测「开启学习探索之旅」）
    gd2 = _xml([("开启学习探索之旅", "android.widget.TextView", 1, 300, 1500, 780, 1600)])
    c = landing.classify(gd2)
    p = landing.plan(c["form"], uiwalk.parse_all(gd2), [])
    check("★ 引导页的新式文案（开启…之旅）要判成引导页并点它，不是去左滑",
          c["form"] == "guide_pager" and p["action"] == "tap"
          and "开启" in _label(p["node"]), "%s/%s" % (c["form"], p["action"]))

    # 含"活动"两个字的普通页面不能判成促销弹窗（高途实测误判）
    plain = _xml([
        ("校园活动", "android.widget.TextView", 0, 100, 300, 900, 380),
        ("查看更多", "android.widget.TextView", 1, 100, 500, 900, 560),
        ("收藏", "android.widget.TextView", 1, 100, 700, 400, 760),
        ("分享", "android.widget.TextView", 1, 600, 700, 900, 760),
    ])
    check("★ 界面里有「活动」两个字不等于促销弹窗（词表要用长词）",
          landing.classify(plain)["form"] != "promo_dialog", landing.classify(plain)["form"])

    # 地区 / 城市选择（外卖、打车、本地服务类首启常见）：与兴趣页同类 ——
    # 选哪个城市都会写进位置偏好，我们不代选，只找「跳过」。
    region = _xml([
        ("请选择你所在的城市", "android.widget.TextView", 0, 100, 200, 980, 260),
        ("北京", "android.widget.TextView", 1, 100, 500, 400, 580),
        ("上海", "android.widget.TextView", 1, 420, 500, 720, 580),
        ("跳过", "android.widget.TextView", 1, 900, 120, 1040, 180),
    ])
    c = landing.classify(region)
    check("★ 城市选择页判成「地区/城市选择」，不混进兴趣页",
          c["form"] == "region_picker", "%s（%s）" % (c["form"], c["why"][:30]))
    p = landing.plan(c["form"], uiwalk.parse_all(region),
                     list(uiwalk.screen_texts(region)))
    check("★ 城市选择页只点「跳过」，不替用户选城市",
          p["action"] == "tap" and _label(p["node"]).strip() == "跳过",
          _label(p["node"]))
    # 兴趣页与城市页不能互相抢（「请选择你」这种半截句会造成混判）
    check("兴趣页不会被城市判据抢走",
          landing.classify(_xml([("请选择你感兴趣的内容", "android.widget.TextView",
                                  0, 100, 200, 980, 260),
                                 ("篮球", "android.widget.TextView", 1, 100, 500, 300, 580)]))["form"]
          == "interest_picker", "")

    # ================================================ 调研 / 选择页
    # ★ 2026-11-06 高途实测（用户反馈）：首启学段选择页被当成功能遍历，
    #   选项（小学→成人教育）被逐个当"入口"点。正确做法是把它当问卷：
    #   选**一个**选项、再点「进入首页」提交 —— 模仿真实用户。
    c, p = _planned(_X_SURVEY)
    check("★ 学段调研页判成 survey_gate（不当功能页）",
          c["form"] == "survey_gate", "%s（%s）" % (c["form"], c["why"][:40]))
    check("★ 调研页第一步：选第一个选项（不是点「进入首页」也不是逐个点）",
          p["action"] == "tap" and p.get("code") == "survey_select"
          and _label(p["node"]).strip() == "小学",
          "%s/%s/%s" % (p["action"], p.get("code"), _label(p["node"])))
    # 选完之后（tried 里有了小学）→ 提交，绝不多选第二个
    _opt = [n for n in uiwalk.parse_all(_X_SURVEY)
            if (n.text or "").strip() == "小学"][0]
    p2 = landing.plan("survey_gate", uiwalk.parse_all(_X_SURVEY),
                      list(uiwalk.screen_texts(_X_SURVEY)),
                      tried=[landing.node_key(_opt)])
    check("★ 调研页第二步：选过一项后点「进入首页」提交（一次只选一个）",
          p2["action"] == "tap" and p2.get("code") == "survey_submit"
          and "进入首页" in _label(p2["node"]),
          "%s/%s/%s" % (p2["action"], p2.get("code"), _label(p2["node"])))
    # 原生单选钮的 checked 态也算"已选"：直接提交
    _sv_rb = _xml([
        ("您是", "android.widget.TextView", 0, 100, 300, 980, 380),
        ("我是学生", "android.widget.RadioButton", 1, 100, 700, 500, 820),
        ("我是家长", "android.widget.RadioButton", 1, 580, 700, 980, 820),
        ("进入首页", "android.widget.Button", 1, 100, 1900, 980, 2020),
    ])
    _rb_nodes = uiwalk.parse_all(_sv_rb)
    for _n in _rb_nodes:
        if (_n.text or "").strip() == "我是学生":
            _n.checked = True
    check("身份调研页（我是学生/我是家长）也判成 survey_gate",
          landing.classify(_sv_rb)["form"] == "survey_gate",
          landing.classify(_sv_rb)["form"])
    p3 = landing.plan("survey_gate", _rb_nodes, list(uiwalk.screen_texts(_sv_rb)))
    check("★ 已勾选的调研页直接点「进入首页」（不再选第二项）",
          p3["action"] == "tap" and p3.get("code") == "survey_submit",
          "%s/%s" % (p3["action"], p3.get("code")))
    # 有「跳过」的调研页：优先跳过（不把选项写进用户画像）
    _sv_skip = _xml([
        ("请选择您的学习阶段", "android.widget.TextView", 0, 100, 300, 980, 380),
        ("小学", "android.widget.TextView", 1, 100, 600, 500, 720),
        ("初中", "android.widget.TextView", 1, 580, 600, 980, 720),
        ("跳过", "android.widget.TextView", 1, 900, 120, 1040, 180),
        ("进入首页", "android.widget.Button", 1, 100, 1900, 980, 2020),
    ])
    c4 = landing.classify(_sv_skip)
    p4 = landing.plan(c4["form"], uiwalk.parse_all(_sv_skip),
                      list(uiwalk.screen_texts(_sv_skip)))
    check("★ 有「跳过」的调研页优先跳过，不代选",
          c4["form"] == "survey_gate" and p4.get("code") == "survey_skip"
          and "跳过" in _label(p4["node"]),
          "%s/%s" % (c4["form"], p4.get("code")))
    # 误判防护①：有输入框的页面是表单（登录/实名/注册），不是问卷
    _sv_edit = _xml([
        ("请选择您的身份信息", "android.widget.TextView", 0, 100, 300, 980, 380),
        ("请输入姓名", "android.widget.EditText", 1, 100, 600, 980, 720),
        ("下一步", "android.widget.Button", 1, 100, 1900, 980, 2020),
    ])
    check("带输入框的表单不判成调研页（问卷没有输入框）",
          landing.classify(_sv_edit)["form"] != "survey_gate",
          landing.classify(_sv_edit)["form"])
    # 误判防护②：实名页有「下一步」也有"身份"字样，绝不能被问卷判据抢走
    check("★ 实名认证页不会被调研判据抢走（那是不能代填的）",
          landing.classify(_X_REALNAME)["form"] == "realname_gate",
          landing.classify(_X_REALNAME)["form"])
    # 误判防护③：主页面上的运营问句不当问卷
    _sv_home = _xml([
        ("首页", "android.widget.TextView", 1, 30, 2280, 200, 2380),
        ("学习", "android.widget.TextView", 1, 300, 2280, 470, 2380),
        ("消息", "android.widget.TextView", 1, 570, 2280, 740, 2380),
        ("我的", "android.widget.TextView", 1, 840, 2280, 1050, 2380),
        ("您是大学生吗", "android.widget.TextView", 0, 100, 500, 700, 580),
        ("查看更多", "android.widget.TextView", 1, 100, 700, 500, 780),
    ])
    check("主页面（带 tab）上的问句不当调研页",
          landing.classify(_sv_home)["form"] == "home",
          landing.classify(_sv_home)["form"])
    # 选项与提交按钮不被禁点清单拦（否则组合操作一步都走不了）
    _sv_nodes = uiwalk.parse_all(_X_SURVEY)
    _opt2 = [n for n in _sv_nodes if (n.text or "").strip() == "高中"][0]
    _sub2 = [n for n in _sv_nodes if "进入首页" in (n.text or "")][0]
    check("调研选项不被禁点清单拦",
          landing.forbidden(_opt2, "survey_gate") == "", landing.forbidden(_opt2, "survey_gate"))
    check("调研提交按钮（进入首页）不被禁点清单拦",
          landing.forbidden(_sub2, "survey_gate") == "", landing.forbidden(_sub2, "survey_gate"))
    # H5 形态：选项全不可点（clickable=false），按文字位置点
    _sv_h5 = _xml([
        ("请选择您的学习阶段", "android.widget.TextView", 0, 100, 300, 980, 380),
        ("小学", "android.widget.TextView", 0, 100, 600, 500, 720),
        ("初中", "android.widget.TextView", 0, 580, 600, 980, 720),
        ("进入首页", "android.widget.Button", 1, 100, 1900, 980, 2020),
    ])
    c5 = landing.classify(_sv_h5)
    p5 = landing.plan(c5["form"], uiwalk.parse_all(_sv_h5),
                      list(uiwalk.screen_texts(_sv_h5)))
    check("H5 调研页（选项不可点）按文字位置选一项",
          c5["form"] == "survey_gate" and p5.get("code") == "survey_select"
          and _label(p5["node"]).strip() == "小学",
          "%s/%s" % (c5["form"], p5.get("code")))

    # ================================================ 门禁形态（视觉不能推翻结构）
    # ★ 春雨诊所 2026-11-06 实测：登录墙上模型连答 5 次「已到主页面」，
    #   本地 give_up 被顶掉，10 步 92 秒全部空烧，最后仍停在登录页。
    #   根子是**两类证据的强弱搞反了**：登录页有手机号/密码框是结构事实，
    #   "截图看起来像首页"是猜测。门禁形态下单凭猜测不许说"到了"。
    check("★ 门禁形态清单存在且覆盖所有环节（漏一类就等于放宽一次）",
          set(landing.GATE_FORMS) == set(landing.FORMS) - {"home", "unknown",
                                                           "splash_wait"},
          "差集 %s" % (set(landing.FORMS) - set(landing.GATE_FORMS)))
    for _f in ("login", "age_gate", "guide_pager", "interest_picker",
               "region_picker", "splash_ad", "promo_dialog", "update_dialog",
               "system_perm", "perm_guide", "realname_gate", "survey_gate"):
        check("「%s」算门禁形态（本地说还没到主页面）" % _f,
              landing.is_gate(_f) is True, "")
    check("未识别界面不算门禁（它正是要交给模型看的那种）",
          landing.is_gate("unknown") is False, "")
    check("主页面不算门禁", landing.is_gate("home") is False, "")
    # 登录墙：本地必须给出 give_up，而不是"再找找" —— 它自己没有出路
    _lp = landing.plan("login", _nodes([("手机号", "android.widget.EditText",
                                        0, 80, 400, 1000, 500),
                                        ("密码", "android.widget.EditText",
                                         0, 80, 600, 1000, 700),
                                        ("登录", "android.widget.TextView",
                                         1, 80, 900, 600, 1000)]),
                       ["手机号", "密码", "登录"])
    check("★ 登录墙本地只能 give_up（没有游客入口、没有可关的弹窗）",
          _lp["action"] == "give_up" and _lp.get("code") == "login_wall",
          "%s / %s" % (_lp["action"], _lp.get("code")))
    check("give_up 的理由要写清「不代填」而不是「测不了」",
          "不代填" in str(_lp.get("why") or ""), str(_lp.get("why"))[:40])

    # ================================================ 采集侧挂载（源码守护）
    src = inspect.getsource(collector)
    check("★ 采集器有独立的着陆阶段", "def _landing(" in src, "")
    i_land = src.find("_land = _landing(")
    i_walk = src.find("_walk_ui(res, cfg, live, deadline, log, respawn=respawn")
    check("★ 着陆在功能遍历之前执行（顺序反了等于没做）",
          0 < i_land < i_walk, "着陆位置 %d / 遍历位置 %d" % (i_land, i_walk))
    check("★ 模型给的着陆动作要过本地黑名单",
          "landing_mod.forbidden" in src, "")
    check("★ 着陆的每次点击也留痕（在 tap 之前取图）",
          src.find("点击留痕") > 0 and "landing_mod.node_key" in src, "")
    check("★ 前台跑出被测应用时不再按返回并重拉",
          "前台已不在被测应用内" in src, "")
    check("★ 着陆用掉的时间要从剩余预算里扣掉",
          "remain = int(max(1, deadline - time.time()))" in src, "")
    check("★ 着陆没进主页面要写进 errors（报告才有话说）",
          "首启着陆未完成" in src, "")
    # ★ 模型说"到了"不能直接算到（2026-11-06 携船网实测）：开屏广告盖在
    #   首页之上时，模型看截图说"底部有导航栏、已到主页面"，而广告还在。
    #   在广告上开始功能遍历，点到的都是广告位。
    check("★ 模型判「已到主页面」仍要回到本地判据再确认一次",
          "ai_done_pending" in src and "按本地判据（连续两次 + 界面稳定）再确认" in src,
          "")
    check("★ 门禁形态上模型没资格说「已到主页面」（必须被驳回）",
          "landing_mod.is_gate(form)" in src
          and "视觉判断不能推翻它" in src, "")
    check("★ 驳回后要改回本地判据（否则会停在模型那个 done 上）",
          src.count("landing_mod.plan(form, all_nodes, texts") >= 2, "")
    check("★ 同一屏问过两次就不再问模型（春雨诊所白烧 5 次模型调用）",
          "ai_done_denied" in src and "答案不变，不再询问" in src, "")
    check("模型的 reason 要落进「为什么这么做」那一列（否则报告里是空的）",
          'act.get("why") or act.get("reason")' in src, "")
    check("等待 / 滑动也要结算「有没有用」（否则结果列全是 —）",
          "pending_step" in src, "")
    check("★ 文字锚点的点击必须写进日志（这类点击没有可点属性作依据）",
          "在结构树里不可点，按文字位置" in src, "")
    check("★ 传给着陆的是全部节点而不是只传可点节点（否则点不到「跳过」）",
          "all_nodes = uiwalk.parse_all(xml)" in src, "")
    # ★ 结构树够不着时的视觉判据（2026-11-06 携船网实测）：uni-app 首页的
    #   底部导航栏渲染在 WebView 里、不进程结构树，本地看"0 个 tab、0 个导航词"，
    #   而截图上有"首页/资讯/消息/我的"。没有这条，会在真主页面上空转 13 步。
    check("★ 结构树判不出主页面时允许采信视觉判据（且要求连续两次）",
          'home_by = "vision"' in src and "ai_home_run >= 2" in src, "")
    check("★ 视觉判据必须排除全屏单图（广告页）并记下判据来源",
          '(form == "unknown" and len(nodes) >= 3) or same_run >= 2' in src
          and "out[\"home_by\"]" in src, "")
    check("★ 结构树里的残留节点（连续两步没换来新界面）也要能走视觉判据",
          "same_run >= 2" in src and "残留着" in src, "")
    check("视觉判据的理由要与实况对得上（不能说成「连点两次没反应」）",
          "连续 %d 步没有换来新界面" in src
          and "连点两次都没有反应" not in src, "")
    check("报告要区分「结构判的」与「看图判的」",
          "不进入 Android 界面结构树" in inspect.getsource(sop_report), "")

    # ★ 登录墙接力（2026-11-06 用户口径：登录测试默认开启）。
    #   着陆遇到登录页时 landing 只会 give_up（它刻意不碰账号代填），
    #   如果不在这里接手，"默认开登录"就只是配置里的一行字：春雨诊所、万步健康
    #   这种同意完就落在登录/注册页的 App 永远进不了主页面。
    check("★ 着陆阶段的登录墙要转交登录辅助（否则默认开登录也进不去）",
          '_code == "login_wall"' in src and "_login_assist(res, xml, serial, log, login_phone" in src,
          "")
    check("★ 登录整轮只接一次（再试只会多刷短信）",
          'not res.login.get("attempted")' in src, "")
    check("★ 登录成功后要清掉上一屏攒的证据（否则会拖住主页面的判定）",
          "ai_done_denied.clear()" in src and "rec[\"result\"] = \"login_ok\"" in src, "")
    check("登录失败不许当成「到了」（结果与原因都要写清）",
          'rec["result"] = "login_fail"' in src and "不重复尝试以免重复发短信" in src, "")
    check("★ 着陆函数的登录参数要从主流程传进来（漏传＝静默不登录）",
          "login_phone=login_phone," in src and "get_sms_code=get_sms_code," in src, "")

    # ★ 调研页（2026-11-06 高途实测，用户反馈）：遍历侧必须按问卷流程处理
    #   （选一项+提交），不能把选项当功能入口逐个点；步数必须封顶，
    #   否则判据误命中时会把整轮预算烧在"问卷"上。
    check("★ 遍历侧识别调研页并按问卷流程处理（不当功能遍历）",
          '"survey_gate"' in src and "survey_tried" in src, "")
    check("★ 调研页处理步数封顶（防误判烧预算）",
          "survey_steps < SURVEY_STEP_CAP" in src, "")
    check("★ AI 着陆目标里教了问卷的答法（先跳过、没跳过选一项再提交）",
          "完成首启调研" in src and "模仿真实用户" in src, "")

    # ================================================ 报告侧
    rsrc = inspect.getsource(sop_report)
    check("报告有「首启着陆」章节渲染", "def _landing_section(" in rsrc, "")
    check("报告里着陆表格与点击留痕分开（不混成一张表）",
          "class='ltable'" in rsrc, "")
    check("★ 视觉判定那一步要有结果名（否则结论行渲染成「—」）",
          "vision_home" in rsrc and "vision_home" in src, "")
    from piiscan.report.sop_report import _TPL
    tpl = _TPL.read_text(encoding="utf-8")
    check("★ 模板有 $landing_section 占位符（漏了报告就静默少一节）",
          "$landing_section" in tpl, "")
    check("模板里着陆排在点击留痕之前（时间顺序）",
          tpl.find("$landing_section") < tpl.find("$click_trail"), "")
    check("模板有 ltable 的换行样式（六列长文本）",
          "table.ltable" in tpl and "word-break" in tpl, "")
