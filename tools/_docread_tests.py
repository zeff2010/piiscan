"""外部界面读文档 + 登录门 + 无进展看门狗（2026-11-03）。

背景（10 单里 4 单栽在三件事上）：

  · **春雨诊所**：点《隐私政策》→ 系统浏览器。那一屏结构树里有 312 条文字、
    826 字长文本，正文就在眼前，旧逻辑却只记一句"由系统组件接管"就放弃 ——
    P2 失败、P5 整段跳过、21 项只能记「跳过未测」。随后反复外跳累计 9 次，
    整轮遍历被停掉（跑了 8 分钟）。
  · **高途**：同样的浏览器政策 + 一个"网络链接有问题"的错误页；
    更糟的是它卡在一个**没能代点的系统权限弹窗**上 —— 每轮都
    「同一弹窗 → 已记过 → continue」，界面没变、动作没发生，
    台账/振荡/僵化三条判据全部失明，3518 秒里 3357 秒在空转。
  · **万步健康 / 携船网**：点哪里都跳登录页。一个在同一屏点了 275 次
    （68 分钟、4 个界面），一个 3 次"循环"直接结束（7 分钟）。

本文件守住四件事：

  ① 错误页认得准：`无法访问此网站 / 网络连接有问题 / 404` 要判成"打不开"，
     但**长政策正文里出现"网络连接""404"不能误判**（误判会让正文整段丢失）。
  ② 浏览器里的政策页要读得回来：拼正文时按行去重，滚动重复不能灌水。
  ③ 登录页认得准：提示写「用户名/昵称/手机」的登录框也算登录页
     （旧词表只认"手机号"，万步健康因此从未被识别）；普通页面不能误判。
  ④ 三个兜底闸门都在：无进展看门狗、粘住弹窗的处置、登录门剔除。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def run(check) -> None:
    from piiscan import uiwalk
    from piiscan.flow import docread as DR
    from piiscan.flow import foreign as FG

    # ---- ① 错误页：判得准，也不能误杀 ----
    check("浏览器错误页「无法访问此网站」判得出",
          DR.error_sign(["无法访问此网站", "www.xx.com 意外终止了连接"]) == "无法访问此网站",
          DR.error_sign(["无法访问此网站"]))
    check("应用自绘错误页「网络连接有问题」判得出",
          bool(DR.error_sign(["网络连接有问题", "请稍后重试"])), DR.error_sign(["网络连接有问题"]))
    check("404 页判得出", bool(DR.error_sign(["您所访问的页面不存在"])),
          DR.error_sign(["您所访问的页面不存在"]))
    check("Chrome 的 net::ERR 判得出",
          bool(DR.error_sign(["net::ERR_CONNECTION_TIMED_OUT"])),
          DR.error_sign(["net::ERR_CONNECTION_TIMED_OUT"]))
    # 关键反例：政策正文里出现"网络连接""404"不能算错误页 —— 那会把正文丢掉。
    _policy_like = (
        "隐私政策 本政策说明我们如何收集、使用、共享您的个人信息。"
        "为保障您在使用网络连接服务时的安全，我们会收集设备标识。"
        "我们不会向第三方共享您的个人信息，除非取得您的单独同意。"
        "未成年人保护：若您为未成年人，请在监护人陪同下阅读本政策。"
        "您可以申请注销账号、更正或删除个人信息。" + "本段为条款正文。" * 60
        + "第 404 条 本政策的解释权归本公司所有。"
    )
    check("长政策正文里的「网络连接 / 第 404 条」不误判为错误页",
          DR.error_sign(_policy_like) == "", DR.error_sign(_policy_like))
    check("正常页面（登录页带一句网络异常提示）不误判",
          DR.error_sign(["密码登录", "短信验证码登录", "网络异常时可用验证码登录"]) == "",
          DR.error_sign(["密码登录", "短信验证码登录"]))

    # ---- ② 正文拼接：滚动重复必须去重 ----
    _a = "隐私政策\n我们收集您的手机号\n用于账号注册与登录"
    _b = "用于账号注册与登录\n我们收集您的位置信息\n用于附近门店推荐"
    _merged = DR.stitch([_a, _b])
    check("滚动后重复的行只保留一次", _merged.count("用于账号注册与登录") == 1, _merged)
    check("新增的行不丢", "用于附近门店推荐" in _merged, _merged)
    check("纯符号/页码行不进正文", "———— 3 ————" not in DR.stitch(["———— 3 ————", "正文"]),
          DR.stitch(["———— 3 ————", "正文"]))
    check("novel_chars 只算新增内容",
          DR.novel_chars("我们收集手机号", "我们收集手机号\n我们收集位置") == len("我们收集位置"),
          DR.novel_chars("我们收集手机号", "我们收集手机号\n我们收集位置"))

    # ---- ③ 政策入口判定 ----
    check("《春雨诊所隐私政策》算政策入口", DR.is_policy_entry("《春雨诊所隐私政策》"))
    check("《服务协议》和《隐私政策》算政策入口",
          DR.is_policy_entry("《服务协议》和《隐私政策》"))
    check("《用户协议》算政策入口", DR.is_policy_entry("用户协议"))
    check("「微信登录」不算政策入口（那是授权流程）",
          not DR.is_policy_entry("微信登录"))
    check("「去评分」不算政策入口", not DR.is_policy_entry("去评分"))

    # ---- ④ 外跳分类：政策入口 → 有取证价值；普通网页 → 立刻返回 ----
    _v = FG.classify("com.android.browser", activity="com.android.browser.BrowserActivity",
                     entry="《春雨诊所隐私政策》", app_package="me.chunyu.ChunyuDoctorClient")
    check("浏览器 + 政策入口 = 有取证价值（不再算无意义外跳）",
          _v.get("valuable") is True and _v.get("kind") == "browser_policy",
          (v := (_v.get("kind"), _v.get("valuable"))))
    _v2 = FG.classify("com.android.browser", activity="com.android.browser.BrowserActivity",
                      entry="去评分", screen_text="搜索 或输入网址", app_package="com.demo")
    check("浏览器 + 普通入口 = 无取证价值（立即返回）",
          _v2.get("valuable") is False, (_v2.get("kind"), _v2.get("valuable")))
    # 这条最关键：外跳政策页不能把遍历预算当"无效跳转"烧掉 ——
    # 旧逻辑里累计 9 次就把整轮停掉，春雨诊所正是这样只跑了 8 分钟。
    check("政策外跳不会被算作「无意义外跳」", _v.get("action") == "evidence", _v.get("action"))
    check("外跳分类暴露了宿主类别（采集侧据此决定读不读）",
          FG.host_kind("com.android.browser", "com.android.browser.BrowserActivity") == "browser",
          FG.host_kind("com.android.browser"))
    # 高途 2026-11-05：前台只有类名（`.BrowserActivity`），parse_focus 拿不到
    # 包名 → 旧 `_host_kind` 一路走到 unknown → 判"不是浏览器，不读取"。
    check("只有类名时按类名判成浏览器",
          FG.host_kind(*FG.parse_focus(".BrowserActivity")) == "browser",
          str(FG.parse_focus(".BrowserActivity")))
    check("只有类名的选择器判成 picker",
          FG.host_kind(*FG.parse_focus(".MiuiChooserActivity")) == "picker",
          str(FG.parse_focus(".MiuiChooserActivity")))

    # ---- ⑤ 登录页识别：结构判据 ----
    def _xml(nodes):
        rows = ["<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>",
                "<hierarchy rotation='0'>"]
        for t, cls, rid, b in nodes:
            rows.append(
                "<node index='0' text='%s' resource-id='%s' class='%s' "
                "package='com.demo' content-desc='' clickable='true' enabled='true' "
                "focusable='true' scrollable='false' bounds='[%d,%d][%d,%d]' />"
                % (t, rid, cls, b[0], b[1], b[2], b[3]))
        rows.append("</hierarchy>")
        return "\n".join(rows)

    # 万步健康那一屏：提示是「用户名/昵称/手机」，一个"手机号"都没有。
    _wb = _xml([
        ("同意", "android.widget.CheckBox", "rb_easy", (40, 380, 120, 440)),
        ("用户名/昵称/手机", "android.widget.EditText", "et_user", (40, 520, 1040, 620)),
        ("密码", "android.widget.EditText", "et_pwd", (40, 640, 1040, 740)),
        ("登  录", "android.widget.Button", "btn_login", (40, 800, 1040, 900)),
        ("注册", "android.widget.TextView", "tv_reg", (40, 940, 300, 1000)),
    ])
    _info = uiwalk.login_screen(_wb)
    check("提示写「用户名/昵称/手机」的登录页也能认出来（万步健康）",
          _info is not None, _info)
    check("按钮文字带字间距「登  录」也算（旧代码 `\"登录\" in blob` 匹配不上）",
          _info is not None and _info.get("submit") is not None,
          _info.get("submit") if _info else None)
    check("认出后能拿到提交按钮", _info is not None and (_info.get("submit") is not None),
          _info.get("submit") if _info else None)

    # 反例：普通文章页 + 底部"登录"tab，不能当登录页
    _normal = _xml([
        ("资讯详情", "android.widget.TextView", "tv_title", (40, 200, 1040, 280)),
        ("正文内容正文内容正文内容", "android.widget.TextView", "tv_body", (40, 300, 1040, 900)),
        ("搜索", "android.widget.EditText", "et_search", (40, 940, 900, 1020)),
        ("登录", "android.widget.TextView", "tab_login", (40, 2100, 300, 2200)),
    ])
    check("普通页面不会被误判成登录页", uiwalk.login_screen(_normal) is None,
          uiwalk.login_screen(_normal))

    # ---- ⑥ 三个兜底闸门都在代码里 ----
    import inspect
    from piiscan import collector as C
    _walk = inspect.getsource(C._walk_ui)
    check("有「无进展看门狗」（界面与动作都不动就重启/收工）",
          "_IDLE_RESPAWN_AT" in _walk and "idle_rounds" in _walk, "缺少看门狗")
    check("看门狗会写 stop_reason（不能把空转写成时间耗尽）",
          "idle_rounds >= _IDLE_GIVEUP" in _walk and "stop_reason" in _walk, "缺少停止原因")
    check("有「登录门」处置：入口记成需登录并退回",
          "login_gate_uids" in _walk and "登录门退回" in _walk, "缺少登录门")
    check("登录门按元素身份记（携船网首页入口全是「FrameLayout」，按文字会误剔整屏）",
          "_led_uid(n) not in login_gate_uids" in _walk, "未按身份过滤")
    check("登录门入口会从候选剔除（规则/AI 共用同一份候选）",
          "clicks_all = [n for n in clicks_all" in _walk, "未剔除")
    check("遍历中遇到打不开的页面会跳过并留证",
          "docread.error_sign" in _walk and "错误页跳过" in _walk, "缺少错误页处置")
    _perm = inspect.getsource(C._capture_perm_dialog)
    check("粘住的权限弹窗会被关掉（不再每轮 return True 空转）",
          "_PERM_STICKY" in _perm and "按返回键关闭" in _perm, "缺少粘窗处置")
    check("粘窗处置写进报告（这是事实，不能吞掉）",
          "未能代点" in _perm and "res.errors.append" in _perm, "未记录")
    check("图上排序不再拿到已点满的元素（传的是过滤后的候选）",
          "kg.options(\n                        obs.current, free_cands" in _walk
          or "obs.current, free_cands" in _walk, "仍在传 all_cands")
    check("台账过滤同时查 option.uid 与节点真实身份",
          "_blk_o" in _walk and "_blk_n" in _walk, "只查了一个 key")
