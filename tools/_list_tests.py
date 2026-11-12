#!/usr/bin/env python3
"""P4 遍历 Step 3 的自测：列表遍历 / 上拉加载 / 定向权利入口 / 覆盖报告。

为什么这几条必须离线钉死
------------------------
Step 3 加的全是"**判断**"而不是"动作"：这一屏算不算列表、滚到底了要不要再拉一下、
找到了注销入口算什么结论、没找到的入口在报告里怎么写。每一条判错的方向都很糟：

  · 不认列表 → 只滚一屏就走，列表后半截的功能页永远到不了；
  · 滚到底就回退 → 上拉才加载的列表被整段判成"没有该功能"；
  · 找到了注销入口却写成"未提供" / 没走到却写成"未提供" → 报告失实（最严重）；
  · 覆盖明细把系统弹窗算进分母 → 覆盖率虚低，"还有一堆没测"变成结论。

跑法：python tools/_list_tests.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------- 造界面

def _node(text, x1, y1, x2, y2, rid="", cls="android.widget.TextView",
          clickable=True, scrollable=False):
    return ('<node text="%s" resource-id="%s" content-desc="" class="%s" '
            'bounds="[%d,%d][%d,%d]" clickable="%s" scrollable="%s"/>'
            % (text, rid, cls, x1, y1, x2, y2,
               "true" if clickable else "false", "true" if scrollable else "false"))


def _wrap(*nodes, pkg="com.t"):
    return ('<?xml version="1.0" encoding="UTF-8"?><hierarchy rotation="0">'
            '<node index="0" text="" resource-id="" class="android.widget.FrameLayout" '
            'package="%s" bounds="[0,0][1080,1920]" clickable="false">%s</node>'
            '</hierarchy>' % (pkg, "".join(nodes)))


def _list_screen(rows, y0=200, container=(0, 150, 1080, 1700)):
    """一个"列表页"：可滚动容器 + 若干可点行。"""
    x1, y1, x2, y2 = container
    kids = "".join(_node(t, 20, y0 + i * 150, 1060, y0 + i * 150 + 110,
                         rid="com.t:id/row_%d" % (i + 1)) for i, t in enumerate(rows))
    box = ('<node text="" resource-id="com.t:id/recycler" class="androidx.recyclerview'
           '.widget.RecyclerView" bounds="[%d,%d][%d,%d]" clickable="false" '
           'scrollable="true">%s</node>' % (x1, y1, x2, y2, kids))
    return _wrap(box)


def _tabbar(names=("首页", "发现", "我的"), y=1800):
    out = []
    w = int(1080 / max(1, len(names)))
    for i, n in enumerate(names):
        out.append(_node(n, i * w, y, (i + 1) * w, y + 60, rid="com.t:id/tab_%d" % i))
    return out


SETTINGS = _wrap(
    _node("账号与安全", 20, 200, 1060, 300, rid="com.t:id/security"),
    _node("权限管理", 20, 320, 1060, 420, rid="com.t:id/perm"),
    _node("个性化推荐", 20, 440, 1060, 540, rid="com.t:id/rec"),
    _node("注销账号", 20, 560, 1060, 660, rid="com.t:id/kill"),
    _node("意见反馈", 20, 680, 1060, 780, rid="com.t:id/feedback"),
)


def run(check) -> None:
    from piiscan import uiwalk
    from piiscan.flow import crawl as C
    from piiscan.flow import graph as G
    from piiscan.flow import checklist as CL
    from piiscan.flow.models import FlowResult

    # ================================================================ 列表识别
    g = G.PageGraph("com.t")
    lst = g.observe(_list_screen(["订单 1", "订单 2", "订单 3", "订单 4", "订单 5"]),
                    "com.t/.ListActivity")
    st_list = g.states[lst.fp]
    check("列表：可滚动容器里 ≥4 行 → 识别为列表界面",
          st_list.list_like is True and st_list.list_children >= 4,
          (st_list.list_like, st_list.list_children))
    st_set = g.states[g.observe(SETTINGS, "com.t/.SettingsActivity").fp]
    check("列表：普通设置页不算列表（否则会对着设置页做上拉加载，纯浪费预算）",
          st_set.list_like is False, (st_set.list_like, st_set.list_children))
    check("统计：列表界面数与已加载页数进 stats",
          g.stats()["list_states"] == 1 and g.stats()["pages_loaded"] == 0,
          (g.stats()["list_states"], g.stats()["pages_loaded"]))

    # ================================================================ 上拉加载
    # 场景：这一屏的入口都点完了、也滚到底了，但它是个列表 —— 不能直接回退。
    s = C.Scheduler(g)
    s.sync(lst.fp)
    st_list.uids_clicked.update(st_list.uids_seen)     # 本屏入口都点过
    st_list.scroll_exhausted = True
    step = s.decide(lst.fp, lst.clicks, lst.nav, progress=0.5, back_unsafe=False)
    check("上拉：列表滚到底后先请求上拉（不是立刻回退）", step.action == "pull", step)

    # 拉了一次没加载出新内容 → 还能再拉一次（有的 App 要拉两下）
    s.note_scroll(lst.fp, kind="pull")
    s.sync(lst.fp)
    check("上拉：空拉一次后仍可再拉（不急着判死）", st_list.pulls == 1, st_list.pulls)
    step = s.decide(lst.fp, lst.clicks, lst.nav, progress=0.5, back_unsafe=False)
    check("上拉：第二次仍请求上拉", step.action == "pull", step)

    # 拉到第二次还没有内容 → 认了，回退
    s.note_scroll(lst.fp, kind="pull")
    s.sync(lst.fp)
    s.stack = [lst.fp, "child"]          # 假装来自上一级，允许 BACK
    s.sync(lst.fp)
    step = s.decide(lst.fp, lst.clicks, lst.nav, progress=0.5, back_unsafe=False)
    check("上拉：两次都拉不出新内容后回退（不在列表页上空转）",
          step.action in ("back", "none"), step)

    # 拉出了新内容 → 立刻恢复"可以继续滚"
    g2 = G.PageGraph("com.t")
    s2 = C.Scheduler(g2)
    a = g2.observe(_list_screen(["A1", "A2", "A3", "A4"]), "com.t/.L")
    s2.sync(a.fp)
    st_a = g2.states[a.fp]
    st_a.uids_clicked.update(st_a.uids_seen)
    st_a.scroll_exhausted = True
    s2.note_scroll(a.fp, kind="pull")
    b = g2.observe(_list_screen(["B1", "B2", "B3", "B4", "B5", "B6"]), "com.t/.L")
    s2.sync(b.fp)
    check("上拉：加载出新一页后清掉「已到底」并记一页",
          st_a.scroll_exhausted is False and st_a.pages == 1 and st_a.pulls == 0,
          (st_a.scroll_exhausted, st_a.pages, st_a.pulls))

    # ================================================================ 定向权利入口
    g3 = G.PageGraph("com.t")
    s3 = C.Scheduler(g3)
    r3 = g3.observe(SETTINGS, "com.t/.SettingsActivity")
    s3.sync(r3.fp)
    tg = {t["name"]: t for t in s3.target_report()}
    check("定向：目标清单覆盖 PIPL 的注销/撤回/更正/副本/清单/权限/推荐/投诉",
          len(tg) >= 8 and all(k in tg for k in ("注销账号入口", "撤回同意入口",
                                                "更正/删除个人信息", "权限管理",
                                                "个性化推荐开关")), sorted(tg))
    check("定向：界面上的「注销账号」被定位（记下位置，不点击）",
          tg["注销账号入口"]["found"] is True
          and "SettingsActivity" in tg["注销账号入口"]["where"],
          tg["注销账号入口"])
    check("定向：注销入口被标记为「安全规则拦截」（报告要写清未点击的原因）",
          tg["注销账号入口"]["blocked"] is True, tg["注销账号入口"])
    check("定向：个性化推荐入口被定位", tg["个性化推荐开关"]["found"] is True,
          tg["个性化推荐开关"])
    check("定向：投诉/反馈入口被定位（但「客服/联系我们」不算，避免拨号）",
          tg["投诉举报/意见反馈入口"]["found"] is True
          and "客服" not in C.TARGETS[-1][1], C.TARGETS[-1])
    check("定向：没找到的目标如实标 found=False（不猜）",
          tg["个人信息副本/导出"]["found"] is False, tg["个人信息副本/导出"])

    # 定向期排序：路由词优先于普通内容入口
    s3.phase = C.TARGETED
    route = uiwalk.UiNode(text="设置", cls="android.widget.TextView",
                          resource_id="com.t:id/s", bounds=(0, 0, 10, 10))
    content = uiwalk.UiNode(text="热门推荐", cls="android.widget.TextView",
                            resource_id="com.t:id/h", bounds=(0, 0, 10, 10))
    rr = s3._rank(route, "id:s", set())
    rc = s3._rank(content, "id:h", set())
    check("定向：路由入口（设置）排序优先于运营位（热门推荐）", rr < rc, (rr, rc))
    hit = uiwalk.UiNode(text="注销账号", cls="android.widget.TextView",
                        resource_id="com.t:id/kill", bounds=(0, 0, 10, 10))
    check("定向：命中目标词的入口排在最前",
          s3._rank(hit, "id:kill", set()) < rr,
          (s3._rank(hit, "id:kill", set()), rr))

    # ================================================================ tab 根与子树
    g4 = G.PageGraph("com.t")
    s4 = C.Scheduler(g4)
    home = g4.observe(_wrap(*_tabbar()), "com.t/.Main")
    s4.sync(home.fp)
    s4.note_tap(tab=True, uid="id:tab_2", label="我的")
    mine = g4.observe(_wrap(*_tabbar(), _node("设置", 20, 300, 1060, 400,
                                              rid="com.t:id/set")), "com.t/.Main")
    s4.sync(mine.fp)
    check("tab：点过的 tab 会登记「标签 → 落点界面」（各 tab 覆盖表的数据源）",
          g4.tab_roots.get("我的") == mine.fp, g4.tab_roots)
    # 真实链路里"点了哪个元素"由 `mark_tap` 记账（collector 的 `_obs_tap`），
    # 父边与深度都从它推出来，测试必须走同一条路。
    g4.mark_tap(mine.fp, "id:set", "设置")
    sub = g4.observe(SETTINGS, "com.t/.SettingsActivity")
    s4.sync(sub.fp)
    det = g4.coverage_detail()
    tabrow = {t["tab"]: t for t in det["tabs"]}
    check("覆盖：各 tab 的子树界面数与深度按父边归集",
          tabrow.get("我的", {}).get("states") == 2
          and tabrow.get("我的", {}).get("depth") == 1, det["tabs"])
    check("覆盖：探索比例按「已点 / (已点+未点)」算，且不超 100%",
          0 <= det["explore_ratio"] <= 1, det["explore_ratio"])

    # ================================================================ 未探索入口 & 死点
    g5 = G.PageGraph("com.t")
    s5 = C.Scheduler(g5)
    r5 = g5.observe(SETTINGS, "com.t/.SettingsActivity")
    s5.sync(r5.fp)
    step = s5.decide(r5.fp, r5.clicks, r5.nav, progress=0.5, back_unsafe=False)
    g5.mark_tap(r5.fp, step.uid, step.label)
    g5.resolve(r5.fp)                     # 点了没反应 → 死点
    det5 = g5.coverage_detail()
    check("覆盖：死点带可读标签（报告能写清是哪个入口没反应）",
          det5["dead_points"] and det5["dead_points"][0]["label"], det5["dead_points"])
    check("覆盖：未探索入口给出「哪个界面的哪些入口」",
          det5["gaps"] and det5["gaps"][0]["examples"],
          det5["gaps"])
    labels5 = det5["gaps"][0]["examples"]
    check("覆盖：未探索入口的示例是界面文字而不是 uid（复核员要读得懂）",
          all(not str(x).startswith(("id:", "lb:", "cl:")) for x in labels5), labels5)
    check("覆盖：被安全规则挡住的入口单列（注销/退出不混进未探索）",
          any("注销" in (b.get("label") or "") for b in det5["blocked_points"]),
          det5["blocked_points"])
    check("覆盖：未探索里不含被挡住的注销入口",
          all("注销" not in (x or "") for x in labels5), labels5)

    # 登录页实测（赣警办）：报告「被安全规则挡住的入口」一列里全是
    # 「请输入手机号」「请输入密码」「请输入6位验证码」—— 那是输入框，不是
    # 不许点的按钮。混进来的后果是复核员看不到真正该注意的「取消/退出」。
    login_xml = _wrap(
        _node("请输入手机号", 20, 300, 1060, 400, rid="com.t:id/phone",
              cls="android.widget.EditText"),
        _node("请输入密码", 20, 420, 1060, 520, rid="com.t:id/pwd",
              cls="android.widget.EditText"),
        _node("登录", 20, 560, 1060, 660, rid="com.t:id/login"))
    g7 = G.PageGraph("com.t")
    r7 = g7.observe(login_xml, "com.t/.LoginActivity")
    st7 = g7.states[r7.fp]
    check("覆盖：输入框既不算未探索、也不进「被挡住的入口」",
          "id:phone" in st7.ignored and "id:phone" not in st7.blocked
          and "id:phone" not in st7.uids_seen,
          (sorted(st7.ignored), sorted(st7.blocked)))
    check("覆盖：输入框不会出现在报告的「被挡住入口」里",
          all("请输入" not in (b.get("label") or "")
              for b in g7.coverage_detail()["blocked_points"]),
          g7.coverage_detail()["blocked_points"])

    # ================================================================ 漂移纠偏
    g6 = G.PageGraph("com.t")
    s6 = C.Scheduler(g6)
    s6.stack = ["a", "b", "c"]
    s6.note_back()                        # 预期回到 b
    s6.stack = ["a", "b", "c"]            # 落点不是 b（模拟拦截页插队）
    s6.sync("drift1")
    s6.note_back()
    s6.sync("drift2")
    s6.note_back()
    s6.sync("drift3")
    check("漂移：连续三次没回到预期界面就累计漂移", s6.drift >= 3, s6.drift)
    check("漂移：达到阈值后请求重拉 App 复位", s6.take_respawn_request() is True)
    check("漂移：重拉请求只发一次（不能反复重拉，每次都要重新注入 hook）",
          s6.take_respawn_request() is False)
    check("漂移：重拉前清空栈（旧栈已经不可信）", s6.stack == [], s6.stack)

    # ================================================================ 报告措辞
    fr = FlowResult(package="com.t", app_name="测试")
    fr.coverage = {
        "app_states": 12, "system_states": 3, "edges": 15, "taps": 20,
        "repeat_taps": 0,
        "detail": {
            "explored": 30, "unexplored": 10, "explore_ratio": 0.75,
            "max_depth": 3, "list_states": 2, "pages_loaded": 2, "dead": 1,
            "dialogs": 1, "tabs": [{"tab": "我的", "states": 5, "depth": 2,
                                    "clicked": 12, "todo": 3}],
            "gaps": [{"activity": "ui.SettingsActivity", "count": 4,
                      "examples": ["账号与安全", "消息通知"]}],
            "dead_points": [{"activity": "ui.HomeActivity", "label": "空入口"}],
            "blocked_points": [{"activity": "ui.SettingsActivity", "label": "注销账号"}],
        },
        "targets": [
            {"name": "注销账号入口", "found": True, "where": "ui.SettingsActivity",
             "label": "注销账号", "blocked": True},
            {"name": "个人信息副本/导出", "found": False, "where": "", "label": "",
             "blocked": False},
        ],
        "interrupt": "时间预算耗尽",
        "scheduler": {"drift": 1},
    }
    html_ = __import__("piiscan.report.sop_report", fromlist=["_ui_coverage"]) \
        ._ui_coverage(fr)
    check("报告：有覆盖数据时输出「界面覆盖情况」正文", "入口探索比例" in html_,
          html_[:120])
    check("报告：写清中断原因（否则「未覆盖」会被读成「App 没有」）",
          "时间预算耗尽" in html_)
    check("报告：找到的权利入口写出所在界面",
          "ui.SettingsActivity" in html_ and "注销账号" in html_)
    check("报告：找到但被拦的入口注明「未点击」", "未点击" in html_)
    check("报告：没找到的入口写「未覆盖」而不是「未提供」",
          "未覆盖" in html_ and "未提供" not in html_.replace("不代表 App 未提供", ""))
    check("报告：口径说明明确「未覆盖不代表 App 不存在该行为」",
          "不代表被测应用不存在该行为" in html_, html_[-160:])
    check("报告：没有覆盖数据时不输出这一节（不硬凑）",
          __import__("piiscan.report.sop_report", fromlist=["_ui_coverage"])
          ._ui_coverage(FlowResult(package="com.t")) == "")

    # 登录墙：没登进去时，账号类界面的"未覆盖"必须归因到"没登录"，
    # 否则会被读成"App 没有注销/设置功能"。
    fr3 = FlowResult(package="com.t", app_name="测试")
    fr3.coverage = {"app_states": 3, "detail": {"explored": 3, "unexplored": 5}}
    fr3.login = {"attempted": True, "ok": False, "note": "未收到检测人员回填的验证码"}
    h3 = __import__("piiscan.report.sop_report", fromlist=["_ui_coverage"])._ui_coverage(fr3)
    check("报告：未登录时写明「账号类界面未覆盖」及其原因",
          "未完成登录" in h3 and "账号类界面" in h3, h3[:200])

    # ---- 未测原因 ----
    r1 = CL._coverage_reason("Q013", fr)
    check("未测原因：已定位注销入口且未点击 → 说明「仅记录位置、需人工判断」",
          "仅记录" in r1 and "ui.SettingsActivity" in r1, r1)
    r2 = CL._coverage_reason("Q022", fr)
    check("未测原因：没找到个性化推荐入口 → 写「未覆盖」且说明不能据此认为不存在",
          "未覆盖" in r2 and "不能据此认为不存在" in r2, r2)
    check("未测原因：无覆盖数据时不出这种句子（不能用编的覆盖面凑）",
          CL._coverage_reason("Q013", FlowResult(package="com.t")) == "")

    # ================================================================ 第三方政策归属
    # 真机实测（赣警办 P4 深挖）：点进「意见反馈」的腾讯兔小巢页面，它的
    # 《隐私保护指引》14902 字，比 App 自己的政策长 → 旧逻辑"谁长用谁"把它当成了
    # App 政策，于是未成年人规则、个性化推荐、SDK 列明全是对着别人的文件下的结论。
    from piiscan import policy as POL
    from piiscan import collector as COL
    txc = ("腾讯兔小巢隐私保护指引\n更新时间：2022年7月12日\n"
           "鉴于我们在传递自定义参数功能进行了升级，" + "我们收集您使用服务时的必要信息。" * 80)
    check("政策归属：第三方 SDK 的政策被识别出来（含品牌且开头未出现被测 App 名）",
          bool(POL.third_party_reason(txc, "赣警办", "com.oceansoft.jxpolice")),
          POL.third_party_reason(txc, "赣警办", "com.oceansoft.jxpolice"))
    own = ("赣警办隐私政策\n本政策适用于赣警办App。" + "我们收集您使用服务时的必要信息。" * 80)
    check("政策归属：App 自己的政策不会被误判",
          POL.third_party_reason(own, "赣警办", "com.oceansoft.jxpolice") == "")
    check("政策归属：App 名里自带品牌词时也不误判（腾讯新闻）",
          POL.third_party_reason("腾讯新闻隐私政策\n本政策适用于腾讯新闻客户端。"
                                 + "条款正文。" * 100,
                                 "腾讯新闻", "com.tencent.news") == "")
    # 反例：App 自己的政策也会在正文里写"接收方包括友盟等合作伙伴"。
    # 若拿全文命中品牌就当第三方，会把 App 的政策整份排掉（SOP 自测撞到过）。
    own2 = ("本隐私政策说明我们收集、使用个人信息的目的、方式和范围。"
            "我们可能向第三方共享必要信息，接收方包括友盟等合作伙伴。"
            "本政策适用于赣警办App。")
    check("政策归属：正文提到合作方品牌不算第三方政策（只在标题区判品牌）",
          POL.third_party_reason(own2, "赣警办", "com.oceansoft.jxpolice") == "",
          POL.third_party_reason(own2, "赣警办", "com.oceansoft.jxpolice"))

    cap = {"bestText": own, "bestTextUrl": "https://wmfw.gat.jiangxi.gov.cn/webchat/#/privacy"}
    ok = COL._keep_policy_text(cap, txc, "https://txc.qq.com/xy/privacy.html")
    check("政策归属：不同站点的更长文本不覆盖已取得的 App 政策",
          ok is False and cap["bestText"] == own, (ok, len(cap["bestText"])))
    check("政策归属：被拒绝的文本留档（报告要能说清看过了哪一份）",
          cap.get("otherPolicyTexts") and "txc.qq.com" in cap["otherPolicyTexts"][0]["url"],
          cap.get("otherPolicyTexts"))
    cap2 = {"bestText": own, "bestTextUrl": "https://x.gov.cn/p.html"}
    ok2 = COL._keep_policy_text(cap2, own + "补充条款。" * 300, "https://x.gov.cn/p2.html")
    check("政策归属：同站点的更完整版本可以更新（同一份政策的续页）",
          ok2 is True and len(cap2["bestText"]) > len(own), ok2)
    cap3 = {"bestText": "非常抱歉您访问的页面不存在!", "bestTextUrl": "https://x.gov.cn/p.html"}
    ok3 = COL._keep_policy_text(cap3, txc, "https://txc.qq.com/xy/privacy.html")
    check("政策归属：手上只有错误页(<1200 字)时允许被候选正文替换",
          ok3 is True and "兔小巢" in cap3["bestText"], ok3)

    # 报告里要写明"看过但不用"以及理由 —— 否则复核员会以为我们没拿到政策。
    fr2 = FlowResult(package="com.t", app_name="测试")
    fr2.policy_rejected = {"reason": "该政策正文的出具方是第三方（腾讯兔小巢）",
                           "chars": 14902, "url": "https://txc.qq.com/xy/privacy.html"}
    rm = __import__("piiscan.report.sop_report", fromlist=["_review_materials"]) \
        ._review_materials(fr2)
    check("报告：政策章节写明已排除的第三方政策与理由",
          "已排除的政策正文" in rm and "腾讯兔小巢" in rm and "14902" in rm, rm[:200])

    print("（Step 3 自测完成）")


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
