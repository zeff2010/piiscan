#!/usr/bin/env python3
"""页面图观测的自测（P4 遍历 Step 1：只观测，不参与决策）。

为什么这些用例值得钉住
----------------------
观测层坏掉**不会报错**，只会安静地给出一张错的图：

  · 指纹太细（把列表滚动当成新界面）→ 状态数虚高，覆盖率看起来"很全"，
    实际每个列表页被拆成几十个状态，全是假的；
  · 指纹太粗（只看 activity）→ uni-app / Flutter 三个 tab 合并成一个，
    状态数虚低，深挖漏掉也不报警；
  · uid 用坐标 → 滚动后同一元素换身份，被反复点击（重复率指标失去意义）；
  · 落点判定错 → 把"崩溃"记成"界面没变"，把"跑出 App"记成死点。

这几种错都会直接推动后续 Step 2 的决策做错，所以每一条都单独钉。

跑法：python tools/_crawl_tests.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------- 造界面

def _btn(text, x1, y1, x2, y2, rid="", cd="", cls="android.widget.TextView",
         clickable=True, scrollable=False):
    return ('<node text="%s" resource-id="%s" content-desc="%s" class="%s" '
            'bounds="[%d,%d][%d,%d]" clickable="%s" scrollable="%s"/>'
            % (text, rid, cd, cls, x1, y1, x2, y2,
               "true" if clickable else "false", "true" if scrollable else "false"))


def _wrap(*nodes):
    return ('<?xml version="1.0" encoding="UTF-8"?><hierarchy rotation="0">'
            '<node index="0" text="" resource-id="" class="android.widget.FrameLayout" '
            'bounds="[0,0][1080,1920]" clickable="false">%s</node></hierarchy>'
            % "".join(nodes))


def _tabs(names=("首页", "发现", "我的"), y=1800):
    out = []
    w = int(1080 / max(1, len(names)))
    for i, n in enumerate(names):
        out.append(_btn(n, i * w, y, (i + 1) * w, y + 60,
                        rid="com.t:id/tab_%d" % i))
    return out


def _feed(texts, y0=200, h=150):
    return [_btn(t, 20, y0 + i * h, 1060, y0 + i * h + 100,
                 rid="com.t:id/feed_%d" % i) for i, t in enumerate(texts)]


def run(check) -> None:
    from piiscan.flow import graph
    from piiscan import uiwalk

    # ================================================================ 指纹
    base = _wrap(*_tabs(), *_feed(["新闻一", "新闻二", "新闻三"]))
    same = _wrap(*_tabs(), *_feed(["广告位", "另一个标题", "第三个"]))
    check("指纹：同样的结构、不同的列表文字 → 同一个界面",
          graph.fingerprint(base, "A") == graph.fingerprint(same, "A"),
          (graph.fingerprint(base, "A"), graph.fingerprint(same, "A")))
    check("指纹：null/空 XML 不抛异常，返回空串", graph.fingerprint("") == "", "")

    more = _wrap(*_tabs(), *_feed(["a", "b", "c", "d"]))
    check("指纹：列表多一行仍在同一分桶内 → 不分裂",
          graph.fingerprint(base, "A") == graph.fingerprint(more, "A"),
          (graph.fingerprint(base, "A"), graph.fingerprint(more, "A")))

    check("指纹：换了 Activity → 不同界面",
          graph.fingerprint(base, "A") != graph.fingerprint(base, "B"))

    # 单 Activity 多 tab：这是 uni-app / Flutter 的常态，必须区分开
    tab_b = _wrap(*_tabs(("首页", "发现", "我的")), *_feed(["新闻一"]))
    tab_sel = _wrap(*_tabs(("推荐", "同城", "我的")), *_feed(["新闻一"]))
    check("指纹：同一 Activity 下不同 tab 名 → 不同界面（否则多 tab 会被合并）",
          graph.fingerprint(tab_b, "Main") != graph.fingerprint(tab_sel, "Main"))

    # 无 id 的按钮，靠数量分桶
    def _plain(n, y0=200):
        return _wrap(*[_btn("按钮%d" % i, 20, y0 + i * 160, 400, y0 + i * 160 + 80)
                       for i in range(n)])

    check("指纹：可点数量跨桶（4 → 8）→ 判为不同界面",
          graph.fingerprint(_plain(4), "A") != graph.fingerprint(_plain(8), "A"))
    check("指纹：可点数量同桶（5 → 8，//5 都是 1）→ 不因多一个按钮就分裂",
          graph.fingerprint(_plain(5), "A") == graph.fingerprint(_plain(8), "A"),
          (graph.fingerprint(_plain(5), "A"), graph.fingerprint(_plain(8), "A")))

    # 尾部数字归一化（作为结构签名合并，但 uid 不能合并）
    check("指纹：list_item_1 与 list_item_2 视为同构结构",
          graph._id_sig(uiwalk.parse_all(_wrap(
              _btn("x", 0, 0, 100, 100, rid="com.t:id/list_item_1")))) ==
          graph._id_sig(uiwalk.parse_all(_wrap(
              _btn("x", 0, 0, 100, 100, rid="com.t:id/list_item_2")))))

    # ================================================================ 导航条
    check("导航条：底部三等宽同带按钮 → 识别为 tab 并进指纹",
          graph._tab_sig([n for n in uiwalk.parse_all(_wrap(*_tabs())) if n.clickable],
                         1920) == "首页|发现|我的")
    check("导航条：只有两个按钮不算导航（避免把所有界面并成一个）",
          graph._tab_sig([n for n in uiwalk.parse_all(_wrap(
              _btn("是", 0, 1800, 300, 1860), _btn("否", 400, 1800, 700, 1860)))
              if n.clickable], 1920) == "")
    check("导航条：七个按钮也不算（超出 3~6 的常见形态）",
          graph._tab_sig([n for n in uiwalk.parse_all(_wrap(
              *[_btn("t%d" % i, i * 150, 1800, i * 150 + 140, 1860)
                for i in range(7)])) if n.clickable], 1920) == "")

    # ================================================================ uid
    nodes = uiwalk.parse_all(_wrap(*_tabs(), *_feed(["甲"])))
    clicks = [n for n in nodes if n.clickable]
    check("uid：有 resource-id 时优先用它",
          graph.node_uid(clicks[0], clicks) == "id:tab_0", graph.node_uid(clicks[0], clicks))
    cd_node = uiwalk.parse_all(_wrap(_btn("", 0, 0, 100, 100, cd="设置")))
    check("uid：无 id 时用 content-desc",
          graph.node_uid(cd_node[0], cd_node) == "lb:设置", graph.node_uid(cd_node[0], cd_node))

    # ★ 真机踩到的坑：同一个按钮，有的 dump 带 content-desc、有的只有 text
    a_cd = uiwalk.parse_all(_wrap(_btn("", 0, 0, 200, 100, cd="转到上一层级",
                                       cls="android.widget.ImageButton")))
    a_tx = uiwalk.parse_all(_wrap(_btn("转到上一层级", 0, 0, 200, 100,
                                       cls="android.widget.ImageButton")))
    check("uid：同一元素「有 content-desc / 只有 text」两种形态身份一致",
          graph.node_uid(a_cd[0], a_cd) == graph.node_uid(a_tx[0], a_tx),
          (graph.node_uid(a_cd[0], a_cd), graph.node_uid(a_tx[0], a_tx)))

    two_same = uiwalk.parse_all(_wrap(_btn("更多", 0, 100, 200, 160),
                                      _btn("更多", 0, 400, 200, 460)))
    uids = [graph.node_uid(n, two_same) for n in two_same]
    check("uid：同屏同名的两个元素用序号区分",
          len(set(uids)) == 2 and all(u.startswith("lb:更多#") for u in uids), uids)

    bare = uiwalk.parse_all(_wrap(_btn("", 0, 0, 300, 200, cls="android.widget.LinearLayout")))
    check("uid：连标签都没有的容器退到 class（这类元素被点到本身是覆盖差的证据）",
          graph.node_uid(bare[0], bare) == "cl:LinearLayout", graph.node_uid(bare[0], bare))

    # ★ 这条是核心回归：滚动后坐标全变，uid 必须不变
    before = uiwalk.parse_all(_wrap(_btn("行一", 0, 200, 500, 260),
                                    _btn("行二", 0, 400, 500, 460)))
    after = uiwalk.parse_all(_wrap(_btn("行一", 0, 40, 500, 100),
                                   _btn("行二", 0, 240, 500, 300)))
    check("uid：滚动导致坐标变化后，同一元素仍是同一个身份",
          [graph.node_uid(n, before) for n in before] ==
          [graph.node_uid(n, after) for n in after],
          ([graph.node_uid(n, before) for n in before],
           [graph.node_uid(n, after) for n in after]))

    # ================================================================ 落点
    check("落点：界面变了 → NEW", graph.judge_tap("a", "b") == "NEW")
    check("落点：界面没变 → SAME", graph.judge_tap("a", "a") == "SAME")
    check("落点：新界面是弹窗 → DIALOG", graph.judge_tap("a", "b", is_dialog=True) == "DIALOG")
    check("落点：跑到别的 App → LEFT", graph.judge_tap("a", "", foreign=True) == "LEFT")
    check("落点：进程没了 → CRASH（优先级高于 LEFT）",
          graph.judge_tap("a", "", alive=False, foreign=True) == "CRASH")
    check("落点：拿不到新界面指纹 → UNKNOWN", graph.judge_tap("a", "") == "UNKNOWN")

    # ================================================================ 建图
    g = graph.PageGraph("com.t")
    s1 = g.observe(base, "A", ts=1.0)
    check("建图：首次观测登记一个状态", s1 is not None and len(g.states) == 1, len(g.states))
    g.observe(base, "A", ts=2.0)
    check("建图：同界面再来一次仍是同一个状态（visits 累加）",
          len(g.states) == 1 and list(g.states.values())[0].visits == 2)

    s2 = _wrap(*_tabs(("设置", "隐私", "关于")), *_feed(["开关"]))
    g.mark_tap(s1.fp, "id:tab_0", "首页", 1)
    snap2 = g.observe(s2, "A", ts=3.0)
    g.resolve(snap2.fp, is_dialog=False)
    check("建图：点击后进入的新界面成为第二个状态", len(g.states) == 2, len(g.states))
    check("建图：新状态的深度 = 来源状态 + 1",
          g.states[snap2.fp].depth == g.states[s1.fp].depth + 1,
          (g.states[snap2.fp].depth, g.states[s1.fp].depth))
    check("建图：父子关系被记下来（用于回退与深度统计）",
          g.states[snap2.fp].parent_fp == s1.fp and g.states[snap2.fp].enter_uid == "id:tab_0")
    check("建图：边记录了 from / uid / to",
          g.edges and g.edges[0].from_fp == s1.fp and g.edges[0].uid == "id:tab_0"
          and g.edges[0].to_fp == snap2.fp and g.edges[0].kind == "NEW",
          g.edges[0].to_dict() if g.edges else None)

    # 点了没反应 → 死点；同一元素再点 → 重复
    g.mark_tap(snap2.fp, "id:tab_1", "隐私", 2)
    g.observe(s2, "A", ts=4.0)
    g.resolve(snap2.fp)
    st2 = g.states[snap2.fp]
    check("建图：点了界面没变 → 该元素进死点集", "id:tab_1" in st2.dead, sorted(st2.dead))
    g.mark_tap(snap2.fp, "id:tab_1", "隐私", 3)
    g.observe(s2, "A", ts=5.0)
    g.resolve(snap2.fp)
    check("统计：同一元素第二次点击算一次重复", g.repeat_taps == 1, g.repeat_taps)
    g.mark_tap(snap2.fp, "id:tab_1", "隐私", 4)
    g.observe(s2, "A", ts=6.0)
    g.resolve(snap2.fp)
    check("统计：第三次点击再计一次重复（口径是次数不是元素个数）",
          g.repeat_taps == 2, g.repeat_taps)

    chk = g.stats()
    check("统计：重复率 = 重复次数 / 总点击", abs(chk["repeat_rate"] - 2 / 4.0) < 1e-6,
          chk["repeat_rate"])
    check("统计：未探索入口 = 各状态已知未点元素之和", chk["unexplored"] > 0, chk["unexplored"])
    check("统计：死点个数被汇总", chk["dead"] >= 1, chk["dead"])
    check("统计：访问次数被汇总（两个状态分别看了 2 次与 4 次）", chk["visits"] == 6,
          chk["visits"])

    line = g.summary_line()
    check("日志：摘要行包含四项指标（界面/边/重复/未探索）",
          all(k in line for k in ("界面", "边", "重复", "未探索")), line)

    # ================================================================ 系统界面
    # 真机实测：一轮 10 个状态里 3 个是系统权限弹窗（GrantPermissionsActivity）。
    # 它们被算进"未探索入口"会让覆盖率分母虚高三十多，结论就变成"还有很多没测"。
    perm_xml = _wrap(*[_btn("仅在使用中允许", 100, 700 + i * 90, 980, 780 + i * 90)
                       for i in range(3)])
    perm_xml = perm_xml.replace('content-desc=""',
                                'content-desc="" package="com.android.permissioncontroller"')
    g3 = graph.PageGraph("com.oceansoft.jxpolice")
    sp = g3.observe(perm_xml, "com.android.permissioncontroller/.permission.ui.GrantPermissionsActivity")
    stp = g3.states[sp.fp]
    check("系统界面：权限弹窗被标为系统界面（不混进 App 覆盖率）", stp.system is True,
          stp.to_dict())
    s3 = g3.stats()
    check("系统界面：不计入 App 界面数与未探索入口",
          s3["app_states"] == 0 and s3["unexplored"] == 0 and s3["system_states"] == 1,
          s3)
    check("系统界面：未探索入口另有一份不计入的分项",
          s3["unexplored_system"] == stp.to_dict()["todo"], s3["unexplored_system"])
    check("系统界面：摘要行会说明有几个系统界面被排除", "系统界面" in g3.summary_line(),
          g3.summary_line())

    # 目标 App 自己的界面不能被误判成系统界面
    g4 = graph.PageGraph("com.t")
    s4 = g4.observe(base, "com.t/.ui.MainActivity")
    check("系统界面：目标 App 的界面不算系统界面", g4.states[s4.fp].system is False)

    # 系统弹窗盖在 App 界面上：activity 缓存仍是 App 的（会造成"App 自己在索权"的误读）
    g5 = graph.PageGraph("com.t")
    s5 = g5.observe(perm_xml, "com.t/.ui.MainActivity")
    row5 = g5.top_states(1)[0]
    check("系统界面：弹窗覆盖时以结构树包名为准（不读成 App 界面）",
          g5.states[s5.fp].system is True
          and row5["activity"].startswith("com.android.permissioncontroller"), row5)

    # ================================================================ 存档
    d = g.to_dict()
    try:
        blob = json.dumps(d, ensure_ascii=False)
        ok = True
    except Exception as e:               # pragma: no cover
        blob, ok = str(e), False
    check("存档：页面图可 JSON 序列化（要写进 result.json）", ok, blob[:200])
    check("存档：含 stats / states / edges 三段",
          set(d) >= {"stats", "states", "edges"}, sorted(d))
    check("存档：状态里带 todo/clicked/depth（报告层要用）",
          all(k in d["states"][0] for k in ("todo", "clicked", "depth", "parent")))

    # 上限保护：异常 App 可能产生成千上万个状态，不能把 result.json 撑爆
    g2 = graph.PageGraph("com.t", max_states=2, max_edges=1)
    for i in range(6):
        g2.observe(_wrap(*_tabs(("t%d" % i, "b", "c"))), "A", ts=float(i))
    check("上限：状态数超过上限后停止增长并打标记",
          len(g2.states) <= 2 and g2.stats()["truncated"], len(g2.states))

    # ================================================================ 接入契约
    src = (ROOT / "piiscan" / "collector.py").read_text(encoding="utf-8")
    check("接入：collector 里有观测开关（可一键回到旧行为）",
          "crawl_observe" in (ROOT / "piiscan" / "config.py").read_text(encoding="utf-8")
          and "pagegraph.enabled" in src)
    check("接入：观测包在 try/except 里（记轨迹失败不许拖垮采集）",
          re.search(r"obs = pagegraph\.PageGraph\(package\)[\s\S]{0,120}?except Exception",
                    src) is not None)
    check("接入：主循环里的观测块自带异常保护",
          re.search(r"snap = obs\.observe\([\s\S]{0,600}?except Exception", src) is not None)
    check("接入：收尾统计也包了异常保护",
          re.search(r"res\.graph = obs\.to_dict\(\)[\s\S]{0,800}?except Exception", src)
          is not None)
    check("接入：崩溃与离开 App 的落点会被单独结算",
          "_obs_resolve(\"\", alive=False)" in src and "_obs_resolve(\"\", foreign=True)" in src)
    check("接入：两处点击都登记了上下文",
          src.count("_obs_tap(") >= 3, src.count("_obs_tap("))

    # 开关本身：旧配置对象（没有这个字段）也要能跑
    class _Old:
        class scan:               # noqa: N801
            pass
    check("开关：旧配置对象缺字段时默认开启（不因升级而静默停掉观测）",
          graph.enabled(_Old()) is True)

    class _Off:
        class scan:               # noqa: N801
            crawl_observe = False
    check("开关：显式关闭时观测不启用", graph.enabled(_Off()) is False)


    # ================================================================ 同构列表项抽样
    # 用户 2026-10-31：「遍历还是有点傻」。最典型的一种傻是：一屏 20 个商品卡片，
    # 逐个点进去，每个都是同一个详情页模板 —— 预算烧完，深层菜单一个没摸到。
    from piiscan.flow import crawl as crawlsched
    from types import SimpleNamespace as _NS

    pg = graph.PageGraph(package="com.t")
    _items = _wrap(*[_btn("今日特价好物九块九包邮 第%d件" % i, 20, 200 + i * 150,
                          1060, 200 + i * 150 + 100, rid="com.t:id/feed_%d" % i)
                     for i in range(8)])
    pg.observe(_items, "MainActivity", ts=1.0)
    _fp = graph.fingerprint(_items, "MainActivity")
    _clicks = uiwalk.clickable(_items)
    sch = crawlsched.Scheduler(pg, max_taps_per_state=30)
    _picks = []
    for _ in range(10):
        try:
            _step = sch.decide(_fp, _clicks, [], progress=0.5, back_unsafe=True)
        except Exception as e:      # noqa: BLE001
            _picks.append("ERR:%s" % e)
            break
        if _step is None or _step.action != "tap":
            break
        _picks.append(_step.label)
        # 模拟"点成功了"：这一项进已点集合，否则下一轮还会选中它
        pg.states[_fp].uids_clicked.add(_step.uid)
    check("同构列表项抽样：一屏 8 个同模板卡片只点前 3 个",
          len(_picks) == 3, _picks)

    # 反例：「设置」页的短标签**不能**被合并 —— 每一条都是不同的合规事实
    check("短标签入口不参与同构合并（设置页）",
          crawlsched._same_shape(_NS(resource_id="com.t:id/btn_privacy",
                                     label="隐私设置",
                                     cls="android.widget.TextView")) is None)
    check("索引型 id 判定为同构",
          crawlsched._same_shape(_NS(resource_id="com.t:id/item_7", label="",
                                     cls="android.widget.TextView")) == "id:item")
    check("长文本同类控件判定为同构",
          crawlsched._same_shape(_NS(resource_id="", label="春日限定好物推荐清单",
                                     cls="android.widget.TextView")) == "cls:TextView")

    # ---- 登录 / 注册页的提交动作必须软禁（2 档不登录，点了只会触发风控）----
    check("登录页「立即登录」属于提交动作",
          crawlsched.is_soft_commit(_NS(label="立即登录")))
    check("登录页「注册/登录」属于提交动作",
          crawlsched.is_soft_commit(_NS(label="注册/登录")))
    check("进入登录页的入口仍然可点（「点击登录」不是提交）",
          not crawlsched.is_soft_commit(_NS(label="点击登录")))
    check("「登录后查看订单」这类文案不被误判成提交动作",
          not crawlsched.is_soft_commit(_NS(label="登录后查看订单")))

    # ---- 层级上限（2 档「只点二级目录」）----
    # 到了上限就不再往里点，但**先滚完本屏**（长列表的后半截仍属本层内容）。
    sch2 = crawlsched.Scheduler(pg, max_taps_per_state=30, max_depth=2)
    pg.states[_fp].depth = 2
    pg.states[_fp].uids_clicked.clear()
    step2 = sch2.decide(_fp, _clicks, [], progress=0.5, back_unsafe=True)
    check("2 档到层级上限后不再深点（先滚本屏）",
          step2.action in ("scroll", "back", "pull", "none"), step2.action)
    pg.states[_fp].scroll_exhausted = True
    step3 = sch2.decide(_fp, _clicks, [], progress=0.5, back_unsafe=True)
    check("2 档滚完仍在上限层 → 回退而不是继续点",
          step3.action in ("back", "none"), step3.action)
    # 层级没到上限时照常点
    pg.states[_fp].depth = 1
    sch2b = crawlsched.Scheduler(pg, max_taps_per_state=30, max_depth=2)
    step4 = sch2b.decide(_fp, _clicks, [], progress=0.5, back_unsafe=True)
    check("2 档未到上限时照常点击入口", step4.action == "tap", step4.action)


    # ================================================================ 政策入口优先
    # 2026-11-01：政策/协议入口必须是遍历的第一优先级。
    # 依据是实测丢证据：看个比赛 4 档 1 小时只点了 9 次、全在搜索页，
    # 政策页一次没进 → 报告里政策全文为空（前一晚同一个包拿到 16411 字）。
    _r_pol = crawlsched.value_rank("隐私政策")
    _r_perm = crawlsched.value_rank("拍照上传")
    _r_set = crawlsched.value_rank("设置")
    _r_noise = crawlsched.value_rank("签到")
    check("政策入口排在权限触发之前", _r_pol < _r_perm, (_r_pol, _r_perm))
    check("政策入口排在设置之前", _r_pol < _r_set, (_r_pol, _r_set))
    check("政策入口排在运营位之前", _r_pol < _r_noise, (_r_pol, _r_noise))
    for _w in ("用户协议", "个人信息保护指引", "隐私权政策", "服务协议"):
        check("「%s」也按政策入口提级" % _w,
              crawlsched.value_rank(_w) == _r_pol, crawlsched.value_rank(_w))
    # 反例：普通内容入口不能被误提级，否则整屏都成"政策入口"，提级等于没提。
    check("普通内容入口不被当成政策入口",
          crawlsched.value_rank("热门推荐") > _r_pol,
          crawlsched.value_rank("热门推荐"))


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
