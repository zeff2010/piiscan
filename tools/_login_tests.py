#!/usr/bin/env python3
"""登录辅助链路自测：验证码回填、手机号校验、报告口径。

这条链路的特点是**失败很安静**：
  · 验证码文件没被删掉 → 下一次登录读到过期码 → 报告写"登录失败"
  · 手机号填错 → 真发了一条短信才发现 → 那一轮采集白跑
  · 报告漏写账号 → 复核员不知道结论出自游客态还是登录态
三样都不会抛异常，只会在几天后的报告里表现成"这个 App 登录功能有问题"。
所以必须离线钉住。

跑法：python tools/_login_tests.py
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _getter(tmp: Path, stop=None):
    from piiscan.sop_job import _sms_getter
    return _sms_getter(tmp, stop, lambda *_a: None)


def run(check) -> None:
    from piiscan.sop_job import _parse_sms, _sms_getter

    # ---------------------------------------------------------------- 解析
    check("验证码：只贴一串数字", _parse_sms("382910") == "382910")
    check("验证码：贴整条短信", _parse_sms("【某某】您的验证码是 382910，5分钟内有效") == "382910",
          _parse_sms("【某某】您的验证码是 382910，5分钟内有效"))
    check("验证码：英文 code", _parse_sms("Your code: 7411") == "7411",
          _parse_sms("Your code: 7411"))
    check("验证码：带空格也能认", _parse_sms("  3829 10 \n") == "382910",
          _parse_sms("  3829 10 \n"))
    # 11 位手机号绝不能被当成验证码 —— 否则会拿着号码去登录，必然失败，
    # 而失败原因看起来像"App 校验码不认"。
    check("验证码：11 位手机号不误认", _parse_sms("13800138000") == "",
          _parse_sms("13800138000"))
    check("验证码：空内容", _parse_sms("") == "" and _parse_sms("   ") == "")
    check("验证码：只有无关文字", _parse_sms("已发送") == "", _parse_sms("已发送"))

    # ---------------------------------------------------------------- 取用
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        g = _getter(tmp)
        check("取码：文件不存在返回空串", g() == "")

        (tmp / "sms.txt").write_text("382910", encoding="utf-8")
        check("取码：读到内容", g() == "382910")

        # 用过即删：留着会让下一次登录读到同一条已失效的码
        check("取码：用过即删", not (tmp / "sms.txt").exists())

        check("取码：删掉之后再取为空", g() == "")

        # 整条短信原文
        (tmp / "sms.txt").write_text("【某App】验证码 7411，切勿告知他人", encoding="utf-8")
        check("取码：整条短信取到码", g() == "7411")
        check("取码：整条短信也删掉", not (tmp / "sms.txt").exists())

        # 写进去的是无效内容：不返回东西，但也**不能删** ——
        # 删了检测人员会以为"没收到"，然后重发一条，白花钱还多一次风控。
        (tmp / "sms.txt").write_text("还没收到", encoding="utf-8")
        check("取码：无效内容返回空串", g() == "")
        check("取码：无效内容不删除（留给人自己看）", (tmp / "sms.txt").exists())

        # 取消：不应把码取走
        (tmp / "sms.txt").write_text("889900", encoding="utf-8")
        g2 = _getter(tmp, stop=lambda: True)
        check("取码：任务已停止时不取码", g2() == "")
        check("取码：停止时文件仍在", (tmp / "sms.txt").exists())

    # ---------------------------------------------------------------- 手机号
    from webapp.server import _norm_phone

    check("手机号：原样通过", _norm_phone("13800000000") == "13800000000")
    check("手机号：去空格与连字符", _norm_phone("138 0000-0000") == "13800000000")
    check("手机号：空值表示不做登录辅助", _norm_phone("") == "" and _norm_phone(None) == "")
    for bad in ("12345", "1380000000", "138000000001", "23800000000", "abcdefghijk"):
        try:
            _norm_phone(bad)
            check("手机号：%s 应被拒绝" % bad, False, "未抛错")
        except ValueError:
            check("手机号：%s 应被拒绝" % bad, True)

    # ---------------------------------------------------------------- 入库
    from webapp.db import JobDB

    with tempfile.TemporaryDirectory() as td:
        db = JobDB(Path(td) / "jobs.db")
        jid = db.create(source="upload", apk_name="x.apk", apk_path="D:/tmp/x.apk",
                        login_phone="13800000000")
        check("建任务即带 login_phone", db.get(jid)["login_phone"] == "13800000000",
              db.get(jid)["login_phone"])
        jid2 = db.create(source="upload", apk_name="y.apk")
        check("不填手机号时为空串", (db.get(jid2)["login_phone"] or "") == "",
              db.get(jid2)["login_phone"])

    # ---------------------------------------------------------------- 报告
    from piiscan.flow.models import FlowResult
    from piiscan.report import sop_report as R

    fr = FlowResult(package="com.demo.app")
    fr.login = {
        "attempted": True, "phone": "133****0822", "phone_full": "13800000000",
        "method": "短信验证码注册/登录", "ok": True,
        "note": "已用测试手机号 133****0822 完成登录，登录态下继续遍历",
        "title": "手机号快捷登录", "code_requested": True, "at_ms": 96000, "shot": 12,
    }
    html = R._login_account(fr)
    # 章标题由 _review_materials 统一编排（编号不能写死在各自小节里，
    # 否则条件渲染时会跳号），所以"章节存在"要在整节里查、细节在正文里查。
    whole = R._review_materials(fr)
    check("报告：写明测试账号章节", "本次检测使用的测试账号" in whole)
    check("报告：章节按顺序编号（无跳号）",
          re.search(r"<h3>[一二三四五六七八九十]、本次检测使用的测试账号</h3>", whole),
          whole[:200])
    check("报告：手机号脱敏显示", "133****0822" in html)
    # 报告是底稿，会被传阅/打印 —— 完整号码没有技术必要性
    check("报告：不出现完整手机号", "13800000000" not in html)
    check("报告：写明登录结果", "已登录" in html)
    check("报告：写明验证码不留存", "用完即删" in html)
    # 「验证码登录即注册」的账号确实产生了，必须说清，不能让复核员以为没建号
    check("报告：提示可能已产生账号", "产生了一个以该号码为凭据的账号" in html)
    check("报告：引用登录后截图", "附图 12" in html)

    # 未启用登录辅助：不能只说"未登录"，必须说清因此哪些东西没覆盖
    fr2 = FlowResult(package="com.demo.app")
    html2 = R._login_account(fr2)
    check("报告（未启用）：说明未启用登录辅助", "未启用登录辅助" in html2)
    check("报告（未启用）：说明登录后才能到的功能未覆盖",
          "未覆盖" in html2, html2[:120])
    # 没登录就绝不能暗示"登录态也干净"：必须明确写"不据此认定未发现问题"
    check("报告（未启用）：明确不据此认定未发现问题",
          "不据此认定未发现问题" in html2, html2[-120:])

    # 登录失败：必须写明"登录后才可见的功能未被覆盖"
    fr3 = FlowResult(package="com.demo.app")
    fr3.login = {
        "attempted": True, "phone": "133****0822", "ok": False,
        "method": "短信验证码注册/登录", "code_requested": True,
        "note": "已申请验证码，但 180 秒内未收到检测人员回填的验证码，登录未完成；登录态后的功能未覆盖",
    }
    html3 = R._login_account(fr3)
    check("报告（登录失败）：如实写未完成登录", "未完成登录" in html3)
    check("报告（登录失败）：说明不构成「功能不存在」", "不构成" in html3, html3[-200:])

    # ------------------------------------------------- 登录页的两道前置
    # 实测背景（以观书法 5.4.2）：点「我的 → 登录/注册」先出一屏三选一
    # （微信 / 手机验证码 / 用户名密码），底部一个没勾的「我已阅读并同意」。
    # ① 不勾就点「手机验证码登录」→ 弹个 toast，界面纹丝不动；
    # ② 进到短信表单后那屏**又有一个**同意框，不勾点「获取短信验证码」同样无效。
    # 原先的实现只会"找输入框"，于是直接放弃，报告写"登录未完成"。
    t_login_prepare(check)


def _login_xml(rows, footer=""):
    return ('<?xml version="1.0" encoding="UTF-8"?><hierarchy rotation="0">'
            '<node index="0" text="" class="android.widget.FrameLayout" package="com.t" '
            'bounds="[0,0][1080,2340]" clickable="false">%s%s</node></hierarchy>'
            % ("".join(rows), footer))


def _n(text, y, cls="android.widget.TextView", clickable=True, checked=None,
       checkable=None, rid=""):
    attrs = ''
    if checked is not None:
        attrs += ' checkable="true" checked="%s"' % ("true" if checked else "false")
    return ('<node text="%s" resource-id="%s" class="%s" bounds="[0,%d][1080,%d]" '
            'clickable="%s"%s />'
            % (text, rid, cls, y, y + 90, "true" if clickable else "false", attrs))


def t_login_prepare(check) -> None:
    """登录页：认得出"要先勾同意"和"要先切到验证码登录"，且不重复点已勾的框。"""
    import piiscan.uiwalk as U

    # 屏 1：登录方式三选一 + 未勾的同意框
    p1 = _login_xml([
        _n("用户登录", 100, clickable=False),
        _n("通过微信登录", 900),
        _n("手机验证码登录", 1100, rid="com.t:id/login_phone"),
        _n("用户名密码登录", 1300),
    ], _n("我已阅读并同意", 2000, cls="android.widget.CheckBox", checked=False))
    info = U.login_screen(p1)
    check("登录页：三选一页也认得出（有登录字样+手机）", bool(info), info)
    if info:
        check("登录页：认不出输入框", info["phone_field"] is None)
        check("登录页：找到「手机验证码登录」入口",
              info["switch_btn"] is not None
              and "手机验证码登录" in (info["switch_btn"].text or ""), info["switch_btn"])
        check("登录页：找到未勾的同意框",
              info["agree_cb"] is not None and "同意" in (info["agree_cb"].text or ""),
              info["agree_cb"])

    # 屏 2：短信表单（自己又带一个未勾的同意框）
    p2 = _login_xml([
        _n("短信验证码登录", 100, clickable=False),
        _n("手机号", 300, clickable=False),
        _n("请输入11位手机号", 300, cls="android.widget.EditText", clickable=True,
           rid="com.t:id/et_phone"),
        _n("请输入验证码", 430, cls="android.widget.EditText", clickable=True,
           rid="com.t:id/et_code"),
        _n("获取短信验证码", 450),
        _n("登录", 700, rid="com.t:id/tv_btn"),
    ], _n("我已阅读并同意", 800, cls="android.widget.CheckBox", checked=False))
    info2 = U.login_screen(p2)
    check("短信表单：认出手机号/验证码/获取码/登录四个元素",
          bool(info2) and info2["phone_field"] is not None
          and info2["code_field"] is not None
          and info2["code_btn"] is not None and info2["submit"] is not None, info2)

    # 已勾选的框不再返回 —— 否则每轮都点一次，把用户的勾选点掉
    p3 = _login_xml([
        _n("短信验证码登录", 100, clickable=False),
        _n("请输入11位手机号", 300, cls="android.widget.EditText"),
        _n("获取短信验证码", 450),
        _n("登录", 700),
    ], _n("我已阅读并同意", 800, cls="android.widget.CheckBox", checked=True))
    check("已勾选的同意框不再返回", U.login_screen(p3)["agree_cb"] is None)

    # 只有密码登录时不该被当成"切换到验证码表单"（没有密码就走不通）
    p4 = _login_xml([_n("用户登录", 100, clickable=False),
                     _n("用户名密码登录", 1300)])
    info4 = U.login_screen(p4)
    check("密码登录不当成验证码入口",
          info4 is None or info4["switch_btn"] is None,
          info4 and info4["switch_btn"])

    # ★ 真机形态（春雨诊所 2026-11-06）：手机号 + 密码 + 登录，没有验证码入口。
    #   第二个输入框必须认出是**密码框**。认不出来就会以为"有验证码路径"，
    #   于是在没申请到码的情况下点一次「登录」（密码为空），再把失败写成
    #   "校验码错误或被风控" —— 而一次登录请求都没成功发出过。
    p6 = _login_xml([
        _n("欢迎使用春雨诊所", 100, clickable=False),
        _n("13800000000", 300, cls="android.widget.EditText", rid="com.t:id/phone"),
        _n("密码", 430, cls="android.widget.EditText", rid="com.t:id/pwd"),
        _n("登录", 700),
    ])
    info6 = U.login_screen(p6)
    check("★ 手机号+密码的登录页要认出「密码框」，不能当成验证码框",
          bool(info6) and info6.get("pwd_field") is not None
          and info6.get("code_field") is None, info6)
    check("★ 没有「获取验证码」按钮就不算有验证码路径",
          bool(info6) and info6.get("code_btn") is None, "")

    # ★ 真机形态（春雨诊所 SignInActivity 2026-11-06）：**同时**有
    #   「手机号 / 密码」两个输入框，底部还有一行小字「短信验证码登录」。
    #   旧代码只在"这一屏没有输入框"时才找切换入口，于是永远看不到那行小字 ——
    #   一个明明支持验证码登录的应用被判成"只有密码登录"然后放弃。
    p7 = _login_xml([
        _n("欢迎使用春雨诊所", 100, clickable=False),
        _n("手机号", 300, cls="android.widget.EditText", rid="com.t:id/phone"),
        _n("密码", 430, cls="android.widget.EditText", rid="com.t:id/pwd"),
        _n("登录", 700),
        _n("忘记密码", 800),
        _n("短信验证码登录", 900, clickable=False),
        _n("注册", 60, clickable=True),
    ])
    info7 = U.login_screen(p7)
    check("★ 有输入框的登录页上也要能找到「短信验证码登录」入口",
          bool(info7) and info7.get("switch_btn") is not None
          and "短信验证码" in (info7["switch_btn"].text or ""), info7)
    check("春雨形态：仍然认出密码框（不是验证码框）",
          bool(info7) and info7.get("pwd_field") is not None
          and info7.get("code_field") is None, "")

    # 注册入口：能认出「注册」，但不许把「登录/注册」当成它
    _reg = U.find_register_entry(p7)
    check("★ 登录页上找得到「注册」入口",
          _reg is not None and "注册" in (_reg.text or ""), _reg)
    _lr = _login_xml([_n("手机号", 300, cls="android.widget.EditText"),
                      _n("登录/注册", 700)])
    check("「登录/注册」是提交按钮，不能当注册入口",
          U.find_register_entry(_lr) is None, U.find_register_entry(_lr))

    # 账号台账：密码规则固定且够强、落盘能读回、同一账号不重复建条目
    from piiscan import accounts as A
    _p = A.make_password("13800000000")
    check("★ 台账密码规则固定（台账丢了也能重算）",
          _p == A.make_password("13800000000") and len(_p) >= 8, _p)
    check("台账密码满足常见强度（字母 + 数字 + 符号）",
          any(c.isalpha() for c in _p) and any(c.isdigit() for c in _p)
          and any(not c.isalnum() for c in _p), _p)
    _tmp = Path(tempfile.mkdtemp()) / "accounts.json"
    A.upsert("com.demo.app", "13800000000", password=_p, app="示例",
             ok=True, path=_tmp)
    A.upsert("com.demo.app", "13800000000", password=_p, ok=False,
             note="重登失败", path=_tmp)
    _rows = A.load(_tmp)["accounts"]
    check("★ 同一包名+号码只留一条台账（否则会重复注册）",
          len(_rows) == 1, _rows)
    check("台账：登录失败不清掉密码与首次注册时间",
          _rows[0].get("password") == _p and bool(_rows[0].get("created_at")),
          _rows[0])
    check("台账：按包名找得到", A.find("com.demo.app", path=_tmp) is not None)
    check("台账：别的包名查不到", A.find("com.other", path=_tmp) is None)

    # ★ 真机形态：文字不可点、监听挂在父容器上（以观书法 login_phone）
    #   只按"可点且有文字"找按钮，永远找不到「手机验证码登录」——
    #   登录辅助会停在"未找到手机号输入框"，一条短信都不发。
    p5 = ('<?xml version="1.0" encoding="UTF-8"?><hierarchy rotation="0">'
          '<node index="0" text="" class="android.widget.FrameLayout" '
          'package="com.t" bounds="[0,0][1080,2340]" clickable="false">'
          '<node text="用户登录" class="android.widget.TextView" '
          'bounds="[400,100][700,180]" clickable="false" />'
          '<node text="" resource-id="com.t:id/login_phone" '
          'class="android.widget.RelativeLayout" bounds="[265,1129][815,1322]" '
          'clickable="true">'
          '<node text="手机验证码登录" class="android.widget.TextView" '
          'bounds="[431,1199][704,1251]" clickable="false" />'
          '</node></node></hierarchy>')
    info5 = U.login_screen(p5)
    check("文字不可点时仍能找到登录方式入口",
          bool(info5) and info5["switch_btn"] is not None, info5)
    if info5 and info5["switch_btn"] is not None:
        check("沿父容器取可点节点（而不是硬点文字）",
              info5["switch_btn"].resource_id.endswith("login_phone"),
              info5["switch_btn"].to_dict())

    # ---- login_prepare：动作顺序 勾同意 → 切表单 → 勾第二屏的同意 ----
    taps, dumps = [], [p2, p3]

    def _fake_tap(_serial, node, root=True):
        taps.append((node.text or "").strip())
        return True

    o_tap, o_dump = U.tap_node, U.dump_retry
    U.tap_node, U.dump_retry = _fake_tap, lambda *_a, **_k: dumps.pop(0) if dumps else p3
    try:
        xml_out, acts = U.login_prepare("fake-serial", p1)
    finally:
        U.tap_node, U.dump_retry = o_tap, o_dump
    check("prepare：先勾同意再点登录方式",
          taps[:2] == ["我已阅读并同意", "手机验证码登录"], taps)
    check("prepare：进表单后又勾了第二个同意框",
          len(taps) == 3 and taps[2] == "我已阅读并同意", taps)
    check("prepare：动作有记录供报告引用",
          len(acts) == 3 and all(isinstance(a, str) and a for a in acts), acts)
    check("prepare：返回的是准备后的界面（已能填手机号）",
          U.login_screen(xml_out)["phone_field"] is not None)

    # 已经准备好的页面：一个动作都不做，原样返回
    taps.clear()
    o_tap = U.tap_node
    U.tap_node = _fake_tap
    try:
        xml_out2, acts2 = U.login_prepare("fake-serial", p3)
    finally:
        U.tap_node = o_tap
    check("prepare：已就绪时不动手", taps == [] and acts2 == [] and xml_out2 == p3)

    # ------------------------------------------------- 采集侧：能力边界不许说假话
    # 春雨诊所 2026-11-06 实测：登录页是「手机号 + 密码」，没有验证码入口。
    # 旧代码照样点了一次「登录」（密码为空），失败后写
    # "已提交，但界面仍停留在登录页（可能校验码错误或被风控）"——
    # 一次登录请求都没成功发出过。复核员会去查短信记录，而那里什么都没有。
    import inspect
    from piiscan import collector as C
    from piiscan import uiwalk as uiwalk_mod
    csrc = inspect.getsource(C)
    check("★ 只有账号密码登录时不提交登录请求（不许假装试过）",
          'res.login["password_only"] = True' in csrc
          and "只提供账号密码登录" in csrc, "")
    check("★ 登录失败原因要按「是否真的提交过验证码」分开写",
          "_submitted_code" in csrc
          and "已填入验证码并提交登录，但界面仍停留在登录页" in csrc, "")
    check("只密码登录时要留一张截图（复核员看得到那一屏长什么样）",
          "登录页·仅账号密码登录（未提交）" in csrc, "")

    # ---- 验证码从哪来：设备收件箱（2026-11-06 春雨诊所 600 秒白等） ----
    # 那一单点了「获取短信验证码」就干等人工回填，600 秒没等到，报告写
    # "已申请验证码，但未收到回填"。事后翻设备收件箱：当天一条短信都没有 ——
    # 协议没勾，请求根本没发出去。报告替应用编了个理由。
    from piiscan import smsbox
    check("★ 验证码解析：带关键词的 4~6 位数字取得出",
          smsbox.extract_code("【春雨诊所】您的验证码是483920，5分钟内有效。") == "483920"
          and smsbox.extract_code("验证码1234，请勿泄露") == "1234", "")
    check("★ 验证码解析：银行短信的尾号/金额不许当成验证码",
          smsbox.extract_code("您尾号5697账户存入36.30元") == ""
          and smsbox.extract_code("手机号13800000000已验证") == "", "")
    check("★ 验证码解析：取不出就返回空（宁可空也不填错，填错会写成\"验证码错误\"）",
          smsbox.extract_code("") == "" and smsbox.extract_code("测试") == "", "")
    check("★ 等待验证码优先读设备收件箱（不再只等人工回填）",
          "code_source" in csrc and "设备收件箱" in csrc
          and "smsbox.wait_code" in csrc, "")
    check("★ 必须区分「没发出」与「发了没到」",
          "code_sent" in csrc and "_sms_arrived" in csrc
          and "可判定**发码请求没有真正发出**" in csrc, "")
    check("读不到收件箱时不许写成\"没发出\"（那是不知道）",
          'res.login["code_sent"] = None' in csrc, "")
    check("★ 发码前先勾「我已阅读并同意」（认那个空勾选框，不是那行字）",
          "_tap_agree_by_text" in csrc
          and "find_agree_target" in csrc
          and "find_agree_target" in inspect.getsource(uiwalk_mod), "")
    check("勾选框要点它自己的包围盒（点文字等于没点）",
          "uiwalk.tap_node(serial, target)" in csrc, "")

    # 春雨诊所登录页的真实结构（2026-11-06 dump 片段）：
    # 勾选框是空文字的 CheckBox，标签是紧挨它右边的不可点 TextView。
    _x_cy = ('<hierarchy><node class="android.widget.FrameLayout" '
             'bounds="[0,0][1080,2340]">'
             '<node class="android.widget.CheckBox" text="" checkable="true" '
             'checked="false" clickable="true" bounds="[41,872][136,980]" />'
             '<node class="android.widget.TextView" '
             'text="我已阅读并同意《春雨诊所协议》《隐私政策》" clickable="false" '
             'bounds="[136,872][955,952]" />'
             '</node></hierarchy>')
    _t = uiwalk_mod.find_agree_target(uiwalk_mod.parse_all(_x_cy))
    check("★ 标签在右、空勾选框在左时，认的是左边那个勾选框",
          _t is not None and _t.bounds[0] == 41, _t.bounds if _t else None)
    _x_no = ('<hierarchy><node class="android.widget.FrameLayout" '
             'bounds="[0,0][1080,2340]">'
             '<node class="android.widget.TextView" '
             'text="我已阅读并同意《用户协议》" clickable="false" '
             'bounds="[136,872][955,952]" />'
             '</node></hierarchy>')
    check("页面上没有勾选框时不许瞎点（返回 None，交给下一层兜底）",
          uiwalk_mod.find_agree_target(uiwalk_mod.parse_all(_x_no)) is None, "")
    _x_lab = ('<hierarchy><node class="android.widget.FrameLayout" '
              'bounds="[0,0][1080,2340]">'
              '<node class="android.widget.CheckBox" '
              'text="我已阅读并同意《用户协议》" checkable="true" '
              'checked="true" clickable="true" bounds="[40,870][960,950]" />'
              '</node></hierarchy>')
    _t2 = uiwalk_mod.find_agree_target(uiwalk_mod.parse_all(_x_lab))
    check("勾选框自带文字时也要认得（不要只认空文字那一种）",
          _t2 is not None and _t2.checked, _t2.bounds if _t2 else None)
    check("勾选时点到链接要退回来（别把外跳当成勾上了）",
          "勾选协议时意外跳到了" in csrc and "uiwalk.back(serial)" in csrc, "")
    check("★ 点发码后要认「您还未注册，请先注册」并转注册（别干等到超时）",
          "_need_register_dialog" in csrc and "请先注册" in csrc
          and "on_register_page" in csrc, "")
    check("只看正文里的 4 位数字会误伤银行短信（这条锁死词表顺序）",
          "没有关键词时**不认 4 位数字**" in (
              Path(__file__).resolve().parent.parent
              / "piiscan" / "smsbox.py").read_text(encoding="utf-8"), "")


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
