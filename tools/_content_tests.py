"""内容型列表识别（2026-11-03）。

背景：川剧迷 1 小时档 3683 秒里 2948 秒（80%）耗在 `web.WebActivity` 上 ——
`图片墙` 信息流的卡片点开是 `mp.weixin.qq.com` 公众号文章，页面里只有
「兼容模式 / 分享」，与合规检测无关；89 次点击里 50 多次点的是这些卡片。

本文件守住三件事：

  ① **判得准**：资讯/商品列表要判成内容、设置页（2~4 字短标签）绝不能误判；
     判错的代价是整整一类合规入口被漏点，比"多点几屏"严重得多。
  ② **判得稳**：政策页哪怕挂在公众号文章里也不能被跳过（它是整份报告的依据），
     注销/权限这类权利入口即使落在内容列表里也必须照常点。
  ③ **真省时间**：内容页只抽 1 条、最多滚 1 屏、整轮有点击上限；
     短标题列表（戏曲名/商品名）靠"点一条发现是内容页"回溯把同组标掉。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


SCREEN_H = 2340


def _node(text="", cls="android.widget.FrameLayout", rid="", bounds=(0, 0, 1080, 300)):
    from piiscan import uiwalk
    return uiwalk.UiNode(text=text, cls=cls, resource_id=rid, bounds=bounds,
                         clickable=True)


def _cards(n, *, h=380, top=300, text="", cls="android.widget.FrameLayout",
           x=(0, 1080), gap=20):
    """n 张竖向排列的同尺寸卡片（模拟信息流/商品列表）。"""
    return [_node(text=text, cls=cls,
                  bounds=(x[0], top + i * (h + gap), x[1], top + i * (h + gap) + h))
            for i in range(n)]


def _xml(nodes) -> str:
    """把 (text, cls, rid, bounds) 拼成 uiautomator 风格 XML。"""
    rows = ["<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>",
            "<hierarchy rotation='0'>"]
    for n in nodes:
        x1, y1, x2, y2 = n["bounds"]
        rows.append(
            "<node index='0' text='%s' resource-id='%s' class='%s' "
            "package='com.demo' content-desc='' clickable='%s' enabled='true' "
            "focusable='true' scrollable='%s' bounds='[%d,%d][%d,%d]' />"
            % (n.get("text", ""), n.get("rid", ""), n.get("cls", "android.widget.FrameLayout"),
               "true" if n.get("clickable", True) else "false",
               "true" if n.get("scrollable") else "false", x1, y1, x2, y2))
    rows.append("</hierarchy>")
    return "\n".join(rows)


def run(check) -> None:
    from piiscan.flow import content as CT
    from piiscan.flow import crawl as CR
    from piiscan.flow import graph as G

    # ------------------------------------------------------------ ① 判得准
    # 公众号文章列表：卡片没有任何文字（WebView 里的 FrameLayout），页面里只有域名。
    v = CT.classify("com.demo.web.WebActivity", _cards(8),
                    ["mp.weixin.qq.com/s/AbCdEf", "兼容模式", "分享"], SCREEN_H)
    check("公众号文章列表判为内容型", v.kind == "content", v.reason)
    check("同模板 8 条全部识别", v.total == 8, v.total)
    check("抽样取最上面一条", v.sample is not None and v.sample.bounds[1] == 300,
          getattr(v.sample, "bounds", None))
    check("跳过的是其余 7 条", len(v.skipped) == 7, len(v.skipped))

    # 设置页：2~4 字短标签 + 行高只有 130（屏高 5%）。这是**绝不能**误判的一屏，
    # 里面每一行都是一条不同的合规事实（隐私设置/账号与安全/权限管理）。
    _set_rows = []
    for i, lab in enumerate(["隐私设置", "账号与安全", "权限管理", "清除缓存",
                             "关于我们", "检查更新"]):
        _set_rows.append(_node(lab, "android.widget.TextView", "com.demo:id/ll_%d" % i,
                               (0, 200 + i * 140, 1080, 200 + i * 140 + 130)))
    v = CT.classify("com.demo.ui.SettingsActivity", _set_rows,
                    ["隐私设置", "账号与安全", "权限管理", "清除缓存"], SCREEN_H)
    check("设置页不判为内容型（短标签+矮行）", v.kind == "", (v.kind, v.reason))

    # 原生资讯列表：标题长、卡片高、页面有阅读/评论 -> 判内容。
    _news = [_node("深度解读川剧《白蛇传》的唱腔流变", "android.widget.TextView",
                   "", (0, 300 + i * 340, 1080, 300 + i * 340 + 300))
             for i in range(5)]
    v = CT.classify("com.demo.ui.NewsActivity", _news, ["阅读 1234", "评论 56"], SCREEN_H)
    check("原生长标题资讯列表判为内容型", v.kind == "content", (v.kind, v.reason))

    # 两列网格（图片墙/商品墙）：同一行两张卡片 y 相同、x 不同。
    _grid = []
    for r in range(3):
        for c in range(2):
            _grid.append(_node("", "android.widget.FrameLayout", "",
                               (c * 540, 300 + r * 420, c * 540 + 520, 300 + r * 420 + 400)))
    v = CT.classify("com.demo.web.WebActivity", _grid, ["兼容模式", "mp.weixin.qq.com"], SCREEN_H)
    check("两列内容网格能按列识别", v.kind == "content" and v.total >= 3,
          (v.kind, v.total))

    # 底部导航条：5 个等宽无文字按钮，同一 y —— 不是内容条目（横向排列）。
    _nav = [_node("", "android.widget.ImageButton", "",
                  (i * 216, 2160, i * 216 + 216, 2260)) for i in range(5)]
    v = CT.classify("com.demo.ui.HomeActivity", _nav, ["首页", "我的"], SCREEN_H)
    check("底部导航条不判为内容型", v.kind == "", (v.kind, v.reason))

    # 短标题列表（三祭江/拷紅/曉艇）：静态判据**故意**不认 —— 放宽会把设置页一起卷进来。
    # 这类列表由"点一条发现是内容页"的回溯兜住（见 ③）。
    _opera = [_node(t, "android.widget.TextView", "",
                    (0, 300 + i * 320, 1080, 300 + i * 320 + 280))
              for i, t in enumerate(["三祭江", "拷紅", "曉艇", "沈鐵梅", "成都市川剧院"])]
    v = CT.classify("com.demo.ui.opera.OperasActivity", _opera, ["戏曲", "精选"], SCREEN_H)
    check("2~4 字短标题列表保守地不判内容（留给回溯）", v.kind == "", (v.kind, v.reason))

    # ------------------------------------------------------------ ② 护栏
    check("政策页不因像内容被跳过",
          CT.classify("com.demo.web.WebPureActivity", _cards(6),
                      ["《隐私政策》", "mp.weixin.qq.com", "兼容模式"], SCREEN_H).kind == "",
          "政策页被误判为内容")

    # 权利入口混在内容列表里：不能跟着同构跳过（否则"注销入口"永远点不到）。
    _mixed = [n for n in _cards(6)]
    _mixed[2] = _node("注销账号", "android.widget.TextView", "",
                      (0, 300 + 2 * 400, 1080, 300 + 2 * 400 + 380))
    v = CT.classify("com.demo.web.WebActivity", _mixed,
                    ["mp.weixin.qq.com", "兼容模式"], SCREEN_H)
    _labels = [getattr(n, "text", "") for n in v.skipped]
    check("内容列表里的「注销账号」不参与同构跳过",
          v.kind == "content" and "注销账号" not in _labels, _labels)

    # 词表超集守护：两处词表必须同源，否则以后改一处、漏一处就会漏点。
    # 政策这边只要求覆盖"文档名"——crawl.POLICY_DOC 里还混着「隐私设置」「隐私与安全」
    # 这类**设置入口**（不是政策正文），要求逐一覆盖会把内容判别卡得太死。
    _doc_words = ["隐私政策", "隐私协议", "用户协议", "服务协议", "个人信息保护", "隐私权"]
    check("内容模块的政策词表覆盖全部政策文档名",
          all(k in CT.POLICY_GUARD for k in _doc_words),
          [k for k in _doc_words if k not in CT.POLICY_GUARD])
    _tgt_kw = [k for _n, kws in CR.TARGETS for k in kws]
    check("内容模块的权利词表覆盖 crawl.TARGETS 全部关键词",
          all(any(g in k for g in CT.TARGET_GUARD) for k in _tgt_kw),
          [k for k in _tgt_kw if not any(g in k for g in CT.TARGET_GUARD)])

    # ------------------------------------------------------------ ③ 省时间
    from piiscan import uiwalk
    _logs = []
    clicks = _cards(8)
    g = G.PageGraph(package="com.demo")
    g._last_clicks = list(clicks)
    uids = [g.uid_for(n) for n in clicks]
    root = G.State(fp="ROOT", activity="com.demo.ui.HomeActivity")
    root.clickable = 1
    list_st = G.State(fp="LIST", activity="com.demo.web.WebActivity")
    list_st.clickable = len(clicks)
    list_st.list_like = True
    list_st.uids_seen = set(uids)
    list_st.content = True
    list_st.content_reason = "内容平台（mp.weixin.qq.com）"
    list_st.content_sample = uids[0]
    list_st.content_items = set(uids[1:])
    g.states["ROOT"] = root
    g.states["LIST"] = list_st
    g.current = "LIST"
    sched = CR.Scheduler(g, log=_logs.append)
    sched.stack = ["ROOT", "LIST"]

    _cands = sched._candidates(clicks, list_st)
    check("同模板条目只留 1 条候选（8 条里 7 条被拿掉）", len(_cands) == 1, len(_cands))
    step = sched.decide("LIST", clicks, [], progress=0.5, back_unsafe=False)
    check("内容页第一步：抽样点开 1 条", step.action == "tap", step.action)
    check("抽样点的是保留的那一条", step.uid == uids[0], (step.uid, uids[0]))
    check("内容页不再走常规价值排序（原因是内容型）", "内容型" in step.reason, step.reason)

    list_st.uids_clicked.add(uids[0])
    step = sched.decide("LIST", clicks, [], progress=0.5, back_unsafe=False)
    check("点完 1 条后改为滚一屏（不再点第 2 条）", step.action == "scroll", step.action)
    sched.note_scroll("LIST")
    step = sched.decide("LIST", clicks, [], progress=0.5, back_unsafe=False)
    check("滚过 1 屏就离开（不追信息流下一页）", step.action == "back", step.action)
    check("离开原因写明是内容型页面", "内容型" in step.reason, step.reason)

    # 整轮上限：内容页点击到 CONTENT_TAP_LIMIT 后就不再点任何入口。
    _st2 = G.State(fp="LIST2", activity="com.demo.web.WebActivity")
    _st2.clickable = len(clicks)
    _st2.uids_seen = set(uids)
    _st2.content = True
    g.states["LIST2"] = _st2
    sched.stack = ["ROOT", "LIST2"]
    sched.content_taps = CR.CONTENT_TAP_LIMIT
    step = sched.decide("LIST2", clicks, [], progress=0.5, back_unsafe=False)
    check("内容页点击预算用尽后不再点（直接退）", step.action != "tap", step.action)

    # 内容页里挂着「隐私政策」：抽样上限也不能把它挡掉 —— 政策正文是整份报告的依据。
    _with_policy = _cards(8) + [_node("隐私政策", "android.widget.TextView", "",
                                      (0, 2100, 1080, 2180))]
    g._last_clicks = list(_with_policy)
    _puids = [g.uid_for(n) for n in _with_policy]
    _st3 = G.State(fp="LIST3", activity="com.demo.web.WebActivity")
    _st3.clickable = len(_with_policy)
    _st3.uids_seen = set(_puids)
    _st3.content = True
    _st3.content_reason = "内容平台（mp.weixin.qq.com）"
    _st3.content_sample = _puids[0]
    _st3.content_items = set(_puids[1:8])
    _st3.uids_clicked.add(_puids[0])          # 抽样那一条已经点过
    g.states["LIST3"] = _st3
    sched.stack = ["ROOT", "LIST3"]
    sched.content_taps = 0
    step = sched.decide("LIST3", _with_policy, [], progress=0.5, back_unsafe=False)
    check("内容页里的「隐私政策」不受抽样上限限制",
          step.action == "tap" and step.uid == _puids[-1], (step.action, step.uid))

    # 内容页上的底部主导航：不能被抽样上限挡住（否则首页是信息流的 App 会被困死在这一屏）。
    _tab = _node("我的", "android.widget.TextView", "", (0, 2200, 300, 2300))
    _clicks4 = _cards(8) + [_tab]
    g._last_clicks = list(_clicks4)
    _t4 = [g.uid_for(n) for n in _clicks4]
    _st4 = G.State(fp="FEED", activity="com.demo.ui.HomeActivity")
    _st4.clickable = len(_clicks4)
    _st4.tab_sig = "川剧迷|图片墙|我的"
    _st4.uids_seen = set(_t4)
    _st4.content = True
    _st4.content_reason = "内容平台（mp.weixin.qq.com）"
    _st4.content_sample = _t4[0]
    _st4.content_items = set(_t4[1:8])
    _st4.uids_clicked.add(_t4[0])
    g.states["FEED"] = _st4
    sched.stack = ["FEED"]
    step = sched.decide("FEED", _clicks4, [_tab], progress=0.5, back_unsafe=False)
    check("内容页上的主导航照常可点", step.action == "tap" and step.tab is True,
          (step.action, step.tab, step.reason))

    # ---- 回溯：短标题列表也靠"点一条发现是内容页"兜住 ----
    g2 = G.PageGraph(package="com.demo")
    _p_clicks = [_node(t, "android.widget.TextView", "",
                       (0, 300 + i * 320, 1080, 300 + i * 320 + 280))
                 for i, t in enumerate(["三祭江", "拷紅", "曉艇", "沈鐵梅", "成都市川剧院"])]
    g2._last_clicks = list(_p_clicks)
    _p_uids = [g2.uid_for(n) for n in _p_clicks]
    parent = G.State(fp="OPERA", activity="com.demo.ui.opera.OperasActivity")
    parent.clickable = len(_p_clicks)
    parent.uids_seen = set(_p_uids)
    child = G.State(fp="DETAIL", activity="com.demo.web.WebActivity")
    child.content = True
    child.content_reason = "内容平台（mp.weixin.qq.com）"
    child.content_host = "mp.weixin.qq.com"
    child.parent_fp = "OPERA"
    child.enter_uid = _p_uids[0]
    g2.states["OPERA"] = parent
    g2.states["DETAIL"] = child
    _s2 = CR.Scheduler(g2, log=_logs.append)
    _s2.stack = ["OPERA"]
    _s2._templates["OPERA"] = list(_p_uids)     # decide 时算好、点击前落账
    _s2.sync("DETAIL")
    check("点一条发现是内容页 → 父界面被标为内容型", parent.content is True, parent.content)
    check("同模板其余 4 条一次性标掉", len(parent.content_items) == 4,
          len(parent.content_items))
    check("回溯保留进入时那一条为样本", parent.content_sample == _p_uids[0],
          parent.content_sample)
    _s2.stack = ["OPERA", "DETAIL"]
    _c2 = _s2._candidates(_p_clicks, parent)
    check("回溯后父界面只剩 1 条可点", len(_c2) == 1, len(_c2))

    # 反例：落点只是"看起来像内容页"（公司介绍/帮助中心，没有站外域名）时不能回溯 ——
    # 否则「关于我们」打开一个官网页面，会把整个设置页标成"同构内容"、整类漏测。
    g2b = G.PageGraph(package="com.demo")
    g2b._last_clicks = list(_p_clicks)
    _p2 = G.State(fp="SETTINGS", activity="com.demo.ui.SettingsActivity")
    _p2.clickable = len(_p_clicks)
    _p2.uids_seen = set(_p_uids)
    _kid = G.State(fp="ABOUT", activity="com.demo.web.WebPureActivity")
    _kid.content = True
    _kid.content_reason = "内嵌网页内容页"
    _kid.parent_fp = "SETTINGS"
    _kid.enter_uid = _p_uids[0]
    g2b.states["SETTINGS"] = _p2
    g2b.states["ABOUT"] = _kid
    _s2b = CR.Scheduler(g2b, log=lambda _m: None)
    _s2b.stack = ["SETTINGS"]
    _s2b._templates["SETTINGS"] = list(_p_uids)
    _s2b.sync("ABOUT")
    check("没有站外域名的内容页不回溯（设置页不会被误标）",
          _p2.content is False and not _p2.content_items,
          (getattr(_p2, "content", None), len(getattr(_p2, "content_items", set()))))

    # ---- 观测层：真的 XML 走一遍，确认 State 上留了痕 ----
    _xml_nodes = [{"text": "mp.weixin.qq.com/s/AbCdEf", "cls": "android.widget.TextView",
                   "bounds": (0, 80, 1080, 180)},
                  {"text": "兼容模式", "cls": "android.widget.TextView",
                   "bounds": (700, 2200, 880, 2260)},
                  {"text": "分享", "cls": "android.widget.TextView",
                   "bounds": (900, 2200, 1020, 2260)}]
    for i in range(6):
        _xml_nodes.append({"text": "", "cls": "android.widget.FrameLayout",
                           "bounds": (0, 300 + i * 300, 1080, 300 + i * 300 + 280)})
    _doc = _xml(_xml_nodes)
    g3 = G.PageGraph(package="com.demo")
    snap = g3.observe(_doc, "com.demo.web.WebActivity")
    check("观测层能解析这屏", snap is not None, "解析失败")
    _st = g3.states.get(snap.fp) if snap is not None else None
    check("观测层把内容页标在状态上", _st is not None and _st.content is True,
          getattr(_st, "content", None))
    check("观测层记录了 5 条可跳过条目",
          _st is not None and len(_st.content_items) == 5,
          len(_st.content_items) if _st is not None else None)
    _stats = g3.stats()
    check("统计里有内容型页面计数", _stats.get("content_states") == 1,
          _stats.get("content_states"))
    _detail = g3.coverage_detail()
    check("覆盖明细把内容条目单列（不算功能缺口）",
          _detail.get("unexplored_content") == 5 and _detail.get("content_lists"),
          (_detail.get("unexplored_content"), len(_detail.get("content_lists") or [])))
    check("缺口举例里不出现被跳过的内容条目",
          all("FrameLayout" not in e for x in _detail.get("gaps") or []
              for e in x.get("examples") or []),
          _detail.get("gaps"))
