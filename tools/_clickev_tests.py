"""逐次点击留痕（clickev / 采集侧 / 报告侧）的离线用例。

为什么单独一套：这套改动的每一环都"看起来对、真机上却不生效"——
采集点在 `_walk_ui` 深处、报告走模板占位符、截图要在点击**之前**取。
只要有一环漏掉，报告里就静默少一节（或图全糊），而离线跑一遍就能发现。

守护项（`inspect.getsource`）不是形式主义：这些机制都是"删掉不会报错、
只是结果变差"的类型。2026-11-03 那批改动就差点在重构时被冲掉。
"""

import inspect
import io

from PIL import Image

from piiscan import clickev, collector
from piiscan.flow import replay as replaymod
from piiscan.report import sop_report


def _png(w=1080, h=2400, color=(30, 34, 40)):
    im = Image.new("RGB", (w, h), color)
    b = io.BytesIO()
    im.save(b, format="PNG")
    return b.getvalue()


def run(check) -> None:
    # ---------------- 标注 ----------------
    raw = _png()
    ann = clickev.annotate(raw, 540, 1200, "12 隐私政策")
    check("标注后仍是合法 PNG 且尺寸不变",
          Image.open(io.BytesIO(ann)).size == (1080, 2400), str(len(ann)))
    im = Image.open(io.BytesIO(ann)).convert("RGB")
    # 点击点附近必须出现红色像素；远处必须**没有**被涂改。
    near = [im.getpixel((540 + dx, 1200 + dy))
            for dx in range(-40, 41, 8) for dy in range(-40, 41, 8)]
    check("点击位置画出了红色标记",
          any(r > 150 and g < 90 and b < 100 for r, g, b in near), str(near[:3]))
    far = im.getpixel((60, 60))
    check("标注不影响画面其它区域", far == (30, 34, 40), str(far))

    # 贴边点击：标牌必须被夹进画面内（否则图上什么都看不到）。
    edge = Image.open(io.BytesIO(clickev.annotate(raw, 10, 60, "999 关闭"))).convert("RGB")
    check("贴边点击的标牌没有被裁出画面",
          any(sum(edge.getpixel((x, y))) > 600
              for x in range(0, 260, 6) for y in range(0, 140, 6)), "")

    check("空截图/坏字节不抛异常，返回原样",
          clickev.annotate(b"", 1, 1) == b"" and clickev.annotate(b"notpng", 1, 1) == b"notpng", "")
    check("缩略图是 JPEG base64 且体积可控",
          clickev.thumb(ann).startswith("/9j/") and len(clickev.thumb(ann)) < 60000,
          str(len(clickev.thumb(ann))))

    # ---------------- 预判 ----------------
    check("政策入口判得准", clickev.predict("《春雨诊所隐私政策》")["kind"] == "policy", "")
    check("登录入口判得准", clickev.predict("登  录")["kind"] == "login", "")
    check("权利入口判得准", clickev.predict("注销账号")["kind"] == "logout", "")
    check("无文字容器不瞎猜（label=类名时按无文字处理）",
          clickev.predict("FrameLayout", "android.widget.FrameLayout")["kind"] == "unknown", "")
    check("输入框按控件类型判", clickev.predict("", "android.widget.EditText")["kind"] == "widget", "")
    check("预判带'预期'说明而不是只给类型",
          "预期：" in clickev.predict("设置")["expect"], "")

    # ---------------- 判读 ----------------
    check("AI 决策的判读带上模型理由",
          "模型决策" in clickev.describe("ai", "政策入口优先"), "")
    check("规则兜底不乱写成 AI",
          "规则兜底" in clickev.describe("rule", ""), "")
    check("重复点击次数写进判读",
          "已点过 2 次" in clickev.describe("sched", "", taps_before=2), "")

    # ---------------- 汇总 ----------------
    s = clickev.summarize([
        {"result": "new", "kind": "policy"}, {"result": "new", "kind": "policy"},
        {"result": "same", "kind": "login", "label": "登录"},
        {"result": "", "kind": "unknown"},
    ])
    check("换屏率按条数算", s["new_rate"] == 50.0, str(s["new_rate"]))
    check("未判定单独计数（不是算成无变化）", s["unknown"] == 1, str(s))
    check("空点清单记下是哪个入口", s["dead"] == ["登录"], str(s["dead"]))

    # ---------------- 采集侧接线 ----------------
    src = inspect.getsource(collector)
    check("★ 点击之前取图（annotate 在 tap 之前）",
          src.find("clickev.annotate(") < src.find("if uiwalk.tap(res.device_serial, x, y):"),
          "")
    check("★ 每次点击都带判读与留痕编号进 ui_path",
          "why=_why_txt, shot=_shot_no" in src, "")
    check("★ 点击结果要等下一屏才结算（pending_click）",
          "pending_click" in src and "res.click_shots[pending_click - 1]" in src, "")
    check("★ 榨干过的界面不再重复探测（exhausted_fps）",
          "exhausted_fps.add(_cur_fp)" in src and "_cur_fp in exhausted_fps" in src, "")
    check("★ 注入反复失效有次数上限，转仅界面采集",
          "HOOK_TRY_CAP" in src and "hook_tries >= HOOK_TRY_CAP" in src, "")
    check("★ 人机验证界面不参与遍历", "该屏是人机验证界面" in src, "")
    check("★ 单信号限流要如实交代（不假装只调了几次）",
          "signalSkipped" in src, "")

    # ---------------- 登录门 / 登录墙（2026-11-05 携船网实测） ----------------
    # 现场：300 秒里只点了 1 次，按了 51 次返回，界面一次没换。
    # 三条机制缺一条，这一整轮预算就等于白烧，所以逐条卡住。
    check("★ 登录页返回无效要能认出来（否则整轮只剩'返回'）",
          "gate_back_run" in src and "登录页不响应返回键" in src, "")
    check("★ 认出来之后重拉应用，而不是继续按返回",
          src.find("登录页不响应返回键") < src.find("respawn()", src.find("登录页不响应返回键")),
          "")
    check("★ 被登录门挡住的入口要记名字（报告文案不能出现空顿号）",
          "login_gate_labels.append(" in src and "无文字入口" in src, "")
    check("★ 登录墙早停有阈值常量，且只在没登录成功时生效",
          "_LOGIN_GATE_STOP = 5" in src and "_LOGIN_GATE_STOP)" in src, "")
    check("★ 已判需登录的入口从候选里剔除（三条决策路径都看不到它）",
          "if _led_uid(n) not in login_gate_uids" in src, "")
    check("★ 只剩登录门入口的首页要收工，不能靠按返回空转",
          "剔除这些入口后本屏已无可遍历的候选" in src, "")
    check("★ 重拉后仍落在登录页要收工（冷启动恢复路由栈的那种墙）",
          "gate_respawns >= 2 and not _gate_new_entry" in src
          # 文案里不许出现 Markdown 的 ** —— 这段会原样进 HTML 报告，
          # 星号会跟着显示出来（2026-11-06 在携船网报告里看到了）。
          and "重拉应用后仍然直接落在登录页" in src, "")
    check("★ 流程推进按钮（同意/已满14岁）不得记成「需要登录的入口」",
          "_GATE_FLOW_WORDS" in src and "_gate_is_flow" in src, "")
    check("★ 上一屏已是登录页时，登录页内的跳转不算「进登录页」",
          "_was_login_prev" in src and "_login_prev_round" in src, "")
    check("★ 登录页上按返回会退掉 App 时要换招（否则来回退出重拉）",
          "login_back_unsafe" in src and "登录页上按返回把 App 退出了" in src, "")
    # 高途 2026-11-05：确认按钮只有 resource-id（tvConfirm），被写成
    # "入口「tvConfirm」需要登录才能使用" —— 我们其实分不清它是什么入口。
    check("资源 id 当名字时不断言「该入口需要登录」（改成陈述事实）",
          "无中文文字的可点控件" in src, "")
    check("unreadable：资源 id / 类名认得出来，中文按钮不算",
          all(clickev.unreadable(x) for x in ("tvConfirm", "iv_back", "rb_easy", "FrameLayout"))
          and not any(clickev.unreadable(x) for x in ("同意", "登录", "我已经年满14周岁")), "")
    # 高途 2026-11-05：浏览器里读到 7815 字，但这 7815 字没通过「像隐私政策」判据，
    # bestText 仍是 0 —— 旧代码只看字数就把 outcome 写成 full，报告变成
    # "已取得政策全文"而正文一个字没有。这类"结论说有、证据是空"最致命。
    _i_erc = src.find("elif _erc >= INLINE_POLICY_MIN:")
    _i_next = src.find("elif _erc > 0", _i_erc) if _i_erc > 0 else -1
    _seg_erc = src[_i_erc:_i_next] if (_i_erc > 0 and _i_next > _i_erc) else ""
    check("★ 浏览器内读到字数不足以为凭：要过判据（bestText）才算取得政策",
          bool(_seg_erc) and 'external_unverified' in _seg_erc
          and 'len((cap.get("bestText") or "").strip()) >= INLINE_POLICY_MIN' in _seg_erc,
          "分支长度 %d" % len(_seg_erc))
    check("★ 浏览器内正文被拒时不能写成「未达长度」（那是另一回事）",
          "但没有通过「像隐私政策」判据" in src, "")
    check("入口名是类名时不写进报告（写「无文字入口」）",
          clickev.plain_label("FrameLayout", "android.widget.FrameLayout") == ""
          and clickev.plain_label("封航信息", "android.widget.TextView") == "封航信息", "")

    # ---------------- 重放记账 ----------------
    it = replaymod.norm("tap", label="隐私政策", at=[1, 2], why="规则兜底：x", shot=3)
    check("动作记录里带判读与留痕编号",
          it.get("why") == "规则兜底：x" and it.get("shot") == 3, str(it))
    check("留痕编号非正数不写（0 表示没截到图）",
          "shot" not in replaymod.norm("tap", label="a", shot=0), "")

    # ---------------- 报告侧 ----------------
    h = sop_report.render(_fr_with_clicks())
    check("报告里有「点击留痕（逐次）」一节", "点击留痕（逐次）" in h, "")
    check("留痕条目带判读与预判两栏", "判读：" in h and "预判：" in h, "")
    check("空点那一条被单独标色（citem same）", "citem same" in h, "")
    check("没有留痕时如实说明，不留空白",
          "未取得逐次点击留痕" in sop_report._click_trail(_fr_with_clicks(bare=True)), "")
    tpl = open(sop_report._TPL, encoding="utf-8").read()
    check("模板里有 $click_trail 占位符", "$click_trail" in tpl, "")

    # ---------------- 登录页弱判据（H5 / 自绘登录页） ----------------
    from piiscan import uiwalk as UW

    def _xml(items):
        body = "".join(
            '<node text="%s" class="android.widget.TextView" clickable="%s" '
            'bounds="[0,%d][200,%d]" package="a" content-desc="" checkable="false" '
            'checked="false" enabled="true" />' % (t, c, i * 10, i * 10 + 9)
            for i, (t, c) in enumerate(items))
        return '<hierarchy rotation="0">%s</hierarchy>' % body

    _h5_login = [("欢迎登录", False), ("手机号", False), ("请输入验证码", False),
                 ("获取验证码", True), ("登录", True), ("注册", True),
                 ("忘记密码", True), ("密码登录", True), ("用户协议", True)]
    check("H5 登录页（无 EditText）能被弱判据认出来",
          (UW.login_screen_weak(_xml(_h5_login)) or {}).get("weak") is True, "")
    _home = [("首页", True), ("推荐", True), ("消息", True), ("我的", True),
             ("搜索", True), ("更多", True), ("分类", True), ("购物车", True),
             ("订单", True), ("客服", True), ("设置", True), ("关于", True)]
    check("首页有十几个入口时不会被误判成登录页",
          UW.login_screen_weak(_xml(_home)) is None, "")
    check("首启隐私弹窗不会被误判成登录页",
          UW.login_screen_weak(_xml([("隐私政策", False), ("同意", True),
                                     ("不同意", True)])) is None, "")

    # ---------------- 注入脚本 ----------------
    js = open(str(clickev.__file__).replace("clickev.py", "hooks/collector.js"),
              encoding="utf-8").read()
    check("★ hook 脚本按信号限流（防止一个高频接口吃光额度）",
          "PER_SIGNAL_CAP" in js and "shouldReport(hookId, opts.signal" in js, "")
    check("限流丢掉的条数可从 summary 取到", "signalSkipped" in js, "")


def _fr_with_clicks(bare: bool = False):
    from piiscan.flow.models import FlowResult
    fr = FlowResult(package="com.demo.app", app_name="演示", version="1.0")
    if bare:
        return fr
    ann = clickev.annotate(_png(), 540, 1200, "1 隐私政策")
    tb = clickev.thumb(ann)
    fr.click_shots = [
        {"i": 1, "t": 12.0, "label": "隐私政策", "cls": "TextView", "at": [540, 1200],
         "why": "规则兜底：本屏第一个未点过的可点元素", "kind": "policy",
         "kind_label": "政策/协议入口", "expect": clickev.predict("隐私政策")["expect"],
         "result": "new", "b64": tb},
        {"i": 2, "t": 30.0, "label": "登录", "cls": "Button", "at": [500, 900],
         "why": "模型决策：需要登录才能看订单", "kind": "login",
         "kind_label": "登录/注册入口", "expect": clickev.predict("登录")["expect"],
         "result": "same", "b64": tb},
    ]
    fr.click_stats = clickev.summarize(fr.click_shots)
    return fr
