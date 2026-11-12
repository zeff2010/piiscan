"""App 知识图谱（kgraph）离线回归。

覆盖三块，对应 UI-KOBE 与 AutoDroid 的两个关键机制：

  A. 图构建：语义节点、节点合并（graph auditing）、动作分类、目标识别
  B. 局部选项：危险/提交/输入框必须**不生成选项**；权利入口一票优先；
     编号稳定；导航类动作永远给
  C. 图上导航：最短路径、到目标的路径提示、记忆表长度预算

全部用构造的 PageGraph，不碰真机。
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")

from piiscan import uiwalk                      # noqa: E402
from piiscan.flow import graph as G             # noqa: E402
from piiscan.flow import kgraph as K            # noqa: E402

PASS = 0
FAIL = 0
FAILS = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILS.append("%s%s" % (name, (" | " + str(detail)) if detail else ""))
        print("  [x] %s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "got=%r want=%r" % (got, want))


class N:
    """最小 UiNode 替身（kgraph 只用 label/bounds/clickable 等少数属性）。"""

    def __init__(self, text, bounds, rid="", clickable=True, cls="android.widget.TextView"):
        self.text = text
        self.content_desc = ""
        self.bounds = bounds
        self.clickable = clickable
        self.resource_id = rid
        self.cls = cls
        self.scrollable = False
        self.package = "com.demo"
        self.enabled = True

    @property
    def label(self):
        return self.text

    @property
    def center(self):
        return ((self.bounds[0] + self.bounds[2]) // 2,
                (self.bounds[1] + self.bounds[3]) // 2)

    @property
    def key(self):
        return "%s|%s" % (self.text, self.bounds)


def state(fp, *, activity=".MainActivity", labels=None, seen=(), clicked=(),
          dead=(), blocked=(), depth=0, tab="", list_like=False, dialog=False,
          system=False, visits=1, first_ts=0.0, parent="", enter_uid="",
          pkg="com.demo"):
    labels = dict(labels or {})
    st = G.State(fp=fp, activity=activity, first_ts=first_ts, last_ts=first_ts,
                 visits=visits, clickable=len(seen), texts=len(seen) + 3,
                 tab_sig=tab, list_children=(6 if list_like else 0),
                 list_like=list_like, is_dialog=dialog, depth=depth,
                 parent_fp=parent, enter_uid=enter_uid, system=system,
                 screen_pkg=pkg)
    st.labels = labels
    st.uids_seen = set(seen) | set(clicked) | set(dead) | set(blocked)
    st.uids_clicked = set(clicked)
    st.dead = set(dead)
    st.blocked = set(blocked)
    return st


def edge(src, uid, label, to, kind):
    return G.Edge(from_fp=src, uid=uid, label=label, to_fp=to, kind=kind)


def build(*states, edges=()):
    pg = G.PageGraph("com.demo")
    for st in states:
        pg.states[st.fp] = st
        pg.order.append(st.fp)
    pg.edges = list(edges)
    return pg


# ============================================================ A. 建图

def test_build():
    print("\n[A] 图构建")
    home = state("f_home", seen=("id:tab_home", "id:tab_find", "id:tab_me"),
                 labels={"id:tab_home": "首页", "id:tab_find": "发现",
                         "id:tab_me": "我的"},
                 tab="首页|发现|我的")
    me = state("f_me", depth=1, parent="f_home", enter_uid="id:tab_me",
               seen=("id:btn_set", "id:btn_order"),
               labels={"id:tab_me": "我的", "id:btn_set": "设置",
                       "id:btn_order": "我的订单"},
               tab="首页|发现|我的",
               clicked=("id:btn_order",))
    pg = build(home, me,
               edges=[edge("f_home", "id:tab_me", "我的", "f_me", "NEW"),
                      edge("f_me", "id:btn_order", "我的订单", "f_order", "NEW")])
    kg = K.AppKG("com.demo")
    kg.sync(pg)
    s = kg.stats()
    eq("两个界面 → 两个节点", s["nodes"], 2)
    eq("已知边只算落点在图内的", s["edges"], 1)     # f_order 未观测到，不入图
    n_home = kg.node_of("f_home")
    n_me = kg.node_of("f_me")
    eq("首页角色", n_home.role, K.ROLE_HOME)
    check("我的页角色是账号类", n_me.role in (K.ROLE_ACCOUNT, K.ROLE_SETTINGS),
          n_me.role)
    check("未探索动作数正确", len(n_me.todo) == 1, [a.label for a in n_me.todo])
    eq("点过的算 known/已试", n_me.acts["id:btn_order"].kind, "known")
    eq("known 边记下落点", n_me.acts["id:btn_order"].to_nid, "")

    # 系统界面不进图
    perm = state("f_perm", activity="GrantPermissionsActivity", system=True,
                 seen=("id:allow",), labels={"id:allow": "允许"})
    kg2 = K.AppKG("com.demo")
    kg2.sync(build(home, perm))
    eq("系统弹窗不入图", kg2.stats()["nodes"], 1)

    # 空图不炸
    kg3 = K.AppKG("com.demo")
    kg3.sync(G.PageGraph("com.demo"))
    eq("空图 stats", kg3.stats()["nodes"], 0)
    eq("空图 options", kg3.options("", []), [])
    check("空图 memory 不抛", isinstance(kg3.memory_text(""), str))


def test_merge():
    print("\n[A2] 节点合并（graph auditing）")
    # 同一列表页滚了一屏：可点元素 id 相同、只是列表行号不同 → 应合并
    a = state("f_list_a", activity=".ListActivity", list_like=True, depth=2,
              seen=("id:item_1", "id:item_2", "id:item_3", "id:item_4"),
              labels={"id:item_1": "第一行", "id:item_2": "第二行",
                      "id:item_3": "第三行", "id:item_4": "第四行"},
              first_ts=10.0)
    b = state("f_list_b", activity=".ListActivity", list_like=True, depth=2,
              seen=("id:item_3", "id:item_4", "id:item_5", "id:item_6"),
              labels={"id:item_3": "第三行", "id:item_4": "第四行",
                      "id:item_5": "第五行", "id:item_6": "第六行"},
              first_ts=20.0)
    kg = K.AppKG("com.demo")
    kg.sync(build(a, b))
    eq("滚动分裂的两个指纹合并成一个节点", kg.stats()["nodes"], 1)
    eq("合并留痕", len(kg.nodes["N1"].fps), 2)

    # 同一 activity、同样 4 个可点，但文字完全不同 → 不合并
    c = state("f_set", activity=".MainActivity", depth=2,
              seen=("id:row_1", "id:row_2", "id:row_3", "id:row_4"),
              labels={"id:row_1": "账号与安全", "id:row_2": "隐私设置",
                      "id:row_3": "清除缓存", "id:row_4": "关于我们"},
              first_ts=10.0)
    d = state("f_addr", activity=".MainActivity", depth=2,
              seen=("id:row_1", "id:row_2", "id:row_3", "id:row_4"),
              labels={"id:row_1": "收货人", "id:row_2": "手机号",
                      "id:row_3": "所在地区", "id:row_4": "详细地址"},
              first_ts=20.0)
    kg2 = K.AppKG("com.demo")
    kg2.sync(build(c, d))
    eq("文字完全不同的两屏不合并", kg2.stats()["nodes"], 2)

    # 不同 activity 永不合并（哪怕结构一样）
    e = state("f_x", activity=".A", depth=1,
              seen=("id:r_1", "id:r_2"), labels={"id:r_1": "甲", "id:r_2": "乙"})
    f = state("f_y", activity=".B", depth=1,
              seen=("id:r_1", "id:r_2"), labels={"id:r_1": "甲", "id:r_2": "乙"})
    kg3 = K.AppKG("com.demo")
    kg3.sync(build(e, f))
    # activity 串台：真机（以观书法 mbsf11）同一张「我的」页同时挂着
    # MainActivity / ZiLibMyActivity / SettingsActivity / GrantPermissionsActivity。
    # 结构与文字几乎一致时按同一屏合并，否则一屏变 4 个节点、同一批入口被反复重算。
    eq("activity 串台且结构文字一致 → 合并", kg3.stats()["nodes"], 1)

    # 但结构一致、文字不同 → 仍是两个页面（设置 / 关于我们都可能只有一个返回键）
    h1 = state("f_p", activity=".A", depth=1, seen=("id:r_1", "id:r_2"),
               labels={"id:r_1": "设置", "id:r_2": "退出登录"})
    h2 = state("f_q", activity=".B", depth=1, seen=("id:r_1", "id:r_2"),
               labels={"id:r_1": "关于我们", "id:r_2": "版本号"})
    kg3b = K.AppKG("com.demo")
    kg3b.sync(build(h1, h2))
    eq("activity 不同且文字不同 → 不合并", kg3b.stats()["nodes"], 2)

    # 换了个包的界面一定不合并（系统设置 / 权限弹窗）
    k1 = state("f_s", activity=".A", depth=1, seen=("id:r_1",))
    k2 = state("f_t", activity=".B", depth=1, seen=("id:r_1",),
               pkg="com.android.settings")
    kg3c = K.AppKG("com.demo")
    kg3c.sync(build(k1, k2))
    eq("跨包不合并", kg3c.stats()["nodes"], 2)

    # 深度差 >1 不合并（同 activity 下的不同层级）
    g1 = state("f_d1", activity=".M", depth=1, seen=("id:k",),
               labels={"id:k": "设置"})
    g2 = state("f_d4", activity=".M", depth=4, seen=("id:k",),
               labels={"id:k": "设置"})
    kg4 = K.AppKG("com.demo")
    kg4.sync(build(g1, g2))
    eq("深度差过大不合并", kg4.stats()["nodes"], 2)


def test_action_kinds():
    print("\n[A3] 动作分类")
    st = state("f1", seen=("id:a", "id:b", "id:c", "id:d", "id:e"),
               labels={"id:a": "隐私设置", "id:b": "领券中心", "id:c": "个性化推荐开关",
                       "id:d": "立即支付", "id:e": "搜索框"},
               clicked=("id:b", "id:c"), dead=("id:b",), blocked=("id:logout",))
    st.labels["id:logout"] = "退出登录"
    pg = build(st, edges=[edge("f1", "id:c", "个性化推荐开关", "f1", "SAME")])
    kg = K.AppKG("com.demo")
    kg.sync(pg)
    n = kg.node_of("f1")
    eq("点过没反应的判死点", n.acts["id:b"].kind, "dead")
    eq("同屏开关判自环", n.acts["id:c"].kind, "selfloop")
    eq("危险入口判 danger", n.acts["id:logout"].kind, "danger")
    eq("没点过的是探索", n.acts["id:a"].kind, "explore")

    # 陷阱边
    pg2 = build(st, edges=[edge("f1", "id:a", "隐私设置", "f9", "LEFT")])
    kg2 = K.AppKG("com.demo")
    kg2.sync(pg2)
    eq("跳出 App 的边判陷阱", kg2.node_of("f1").acts["id:a"].kind, "trap")
    eq("陷阱会让节点被记下", len(kg2.node_of("f1").traps), 1)


def test_targets():
    print("\n[A4] 权利入口识别")
    st = state("f_set", depth=2,
               seen=("id:z", "id:c", "id:k"),
               labels={"id:z": "注销账号", "id:c": "撤回同意",
                       "id:k": "已收集个人信息清单"})
    kg = K.AppKG("com.demo")
    kg.sync(build(st))
    m = {r["name"]: r for r in kg.target_matrix()}
    check("注销账号被识别", m["注销账号入口"]["found"])
    check("撤回同意被识别", m["撤回同意入口"]["found"])
    check("已收集清单被识别", m["已收集个人信息清单"]["found"])
    check("未出现的目标记未找到", not m["第三方共享清单"]["found"])
    eq("matrix 覆盖全部 9 类", len(kg.target_matrix()), 9)
    check("missing_targets 非空", len(kg.missing_targets()) >= 6)

    # 危险入口出现在矩阵里要标 blocked（看见了但不许点）
    st2 = state("f2", seen=(), blocked=("id:del",), labels={"id:del": "注销账号"})
    kg2 = K.AppKG("com.demo")
    kg2.sync(build(st2))
    row = [r for r in kg2.target_matrix() if r["name"] == "注销账号入口"][0]
    check("注销入口标 blocked", row["blocked"], row)


# ============================================================ B. 选项

def test_options():
    print("\n[B] 局部选项生成")
    st = state("f_me", depth=1,
               seen=("id:set", "id:del", "id:pay", "id:srch", "id:ad",
                     "id:order", "id:privacy"),
               labels={"id:set": "设置", "id:del": "注销账号",
                       "id:pay": "立即支付", "id:srch": "搜索框",
                       "id:ad": "限时活动", "id:order": "我的订单",
                       "id:privacy": "隐私政策"},
               clicked=("id:order",))
    kg = K.AppKG("com.demo")
    kg.sync(build(st))
    clicks = [N("设置", (0, 0, 100, 50), "a:id/set"),
              N("注销账号", (0, 60, 100, 110), "a:id/del"),
              N("立即支付", (0, 120, 100, 170), "a:id/pay"),
              N("搜索框", (0, 180, 100, 230), "a:id/et_search",
                cls="android.widget.EditText"),
              N("限时活动", (0, 240, 100, 290), "a:id/ad"),
              N("我的订单", (0, 300, 100, 350), "a:id/order"),
              N("隐私政策", (0, 360, 100, 410), "a:id/privacy")]
    opts = kg.options("f_me", clicks)
    texts = [o.label for o in opts if o.action == "tap"]
    check("危险入口不进选项", "注销账号" not in texts, texts)
    check("提交类动作不进选项", "立即支付" not in texts, texts)
    check("输入框不进选项", "搜索框" not in texts, texts)
    check("普通入口进选项", "设置" in texts, texts)
    check("导航动作永远给（滚动）", any(o.action == "scroll" for o in opts),
          [(o.oid, o.action) for o in opts])
    check("不可返回时不给 back", not any(o.action == "back" for o in opts))
    opt_ids = [o.oid for o in opts]
    eq("编号不重复", len(opt_ids), len(set(opt_ids)))
    check("编号形态合法", all(o.oid[:1] in ("A", "S", "P", "B") for o in opts),
          opt_ids)
    # 「隐私政策」属政策类，价值不高但仍是未探索 → 应在选项里但排后面
    if "隐私政策" in texts:
        check("政策入口排在设置之后",
              texts.index("隐私政策") > texts.index("设置"), texts)

    # 已到底 + 列表页 → 给上拉
    st2 = state("f_l", list_like=True, seen=("id:x",), labels={"id:x": "行"},
                clicked=("id:x",))
    st2.scroll_exhausted = True
    kg2 = K.AppKG("com.demo")
    kg2.sync(build(st2))
    o2 = kg2.options("f_l", [N("行", (0, 0, 100, 50), "a:id/x")],
                     scroll_exhausted=True, list_like=True, can_back=True,
                     back_target="N1 首页")
    acts = [o.action for o in o2]
    check("到底的列表页给上拉", "pull" in acts, acts)
    check("可返回时给 back", "back" in acts, acts)
    check("back 带目标名字", any(o.label == "N1 首页" for o in o2 if o.action == "back"))
    check("已到底不再给 scroll", "scroll" not in acts, acts)

    # 确认型销毁按钮也不能出现在选项里（真机 mbsf13 点「确定注销」把账号注销了）。
    # 入口「注销账号」被拦只说明"不点入口"，真正执行销毁的是确认弹窗上那个按钮，
    # 措辞是「确定注销」，不完全等于「注销账号」。
    st_d = state("f_del", depth=1, seen=("id:c1", "id:c2", "id:c3"),
                 labels={"id:c1": "确定注销", "id:c2": "确认删除", "id:c3": "返回"})
    kg_d = K.AppKG("com.demo")
    kg_d.sync(build(st_d, edges=[edge("f_del", "id:c1", "确定注销", "f_del", "SAME")]))
    o_d = kg_d.options("f_del", [N("确定注销", (0, 0, 100, 50), "a:id/c1"),
                                 N("确认删除", (0, 60, 100, 110), "a:id/c2"),
                                 N("返回", (0, 120, 100, 170), "a:id/c3")])
    labs_d = [o.label for o in o_d if o.action == "tap"]
    check("确认型销毁（确定注销）不进选项", "确定注销" not in labs_d, labs_d)
    check("确认型销毁（确认删除）不进选项", "确认删除" not in labs_d, labs_d)
    check("普通入口照常给", "返回" in labs_d, labs_d)

    # ---- 回头路：刚从那屏回来，通往它的入口不能排第一 ----
    # ★ 真机 mbsf12：图上有一条记错的边 `我的页 --查看历史--> 设置页`，而
    #   `path_to_target` 按标签加权，于是每回到我的页「查看历史」都被顶到第一位，
    #   44 次动作里 26 次是「查看历史↔返回」死循环。
    me = state("f_me2", depth=1, seen=("id:his", "id:set2", "id:safe"),
               labels={"id:his": "查看历史", "id:set2": "设置", "id:safe": "账号安全"})
    his = state("f_his", depth=2, seen=("id:back",), labels={"id:back": "返回"})
    stg = state("f_set", depth=2, seen=("id:x",), labels={"id:x": "行"})
    pg3 = build(me, his, stg, edges=[
        edge("f_me2", "id:his", "查看历史", "f_his", "NEW"),
        edge("f_his", "id:back", "返回", "f_me2", "NEW"),
        edge("f_me2", "id:set2", "设置", "f_set", "NEW")])
    kg3 = K.AppKG("com.demo")
    kg3.sync(pg3)
    me_nid = kg3.node_of("f_me2").nid
    his_nid = kg3.node_of("f_his").nid
    clicks3 = [N("查看历史", (0, 0, 100, 50), "a:id/his"),
               N("设置", (0, 60, 100, 110), "a:id/set2"),
               N("账号安全", (0, 120, 100, 170), "a:id/safe")]
    o3 = kg3.options("f_me2", clicks3, avoid_nid=his_nid)
    tap3 = [o for o in o3 if o.action == "tap"]
    check("刚从那屏回来 → 不把它排第一",
          not (tap3 and tap3[0].label == "查看历史"),
          [(o.label, o.why[:16]) for o in tap3])
    check("回头路仍留在选项里（否则这屏没别的就卡死）",
          any(o.label == "查看历史" for o in tap3),
          [o.label for o in tap3])
    check("回头路写明理由",
          any(o.label == "查看历史" and "不回头" in o.why for o in tap3),
          [(o.label, o.why) for o in tap3])
    # 不给 avoid 时按原逻辑（不误伤正常路径规划）：已知边回访按"已知通往"排序
    o4 = kg3.options("f_me2", clicks3)
    _his4 = [o for o in o4 if o.action == "tap" and o.label == "查看历史"]
    check("不给 avoid 时不打回头路标记",
          bool(_his4) and all("不回头" not in o.why for o in _his4),
          [(o.label, o.why) for o in o4 if o.action == "tap"])
    check("know 边回访也标回头路",
          all("不回头" in o.why for o in o3
              if o.action == "tap" and o.to_nid == his_nid),
          [(o.label, o.why) for o in o3 if o.action == "tap"])
    eq("节点身份没被 avoid 改掉", kg3.node_of("f_me2").nid, me_nid)


def test_option_priority():
    print("\n[B2] 选项排序（权利入口一票优先）")
    st = state("f_home",
               seen=("id:ad", "id:set", "id:del"),
               labels={"id:ad": "限时活动", "id:set": "设置",
                       "id:del": "注销账号"})
    kg = K.AppKG("com.demo")
    kg.sync(build(st))
    clicks = [N("限时活动", (0, 0, 100, 50), "a:id/ad"),
              N("设置", (0, 60, 100, 110), "a:id/set"),
              N("注销账号", (0, 120, 100, 170), "a:id/del")]
    opts = kg.options("f_home", clicks)
    taps = [o for o in opts if o.action == "tap"]
    check("有候选", bool(taps))
    eq("设置排第一（运营位押后）", taps[0].label, "设置")
    eq("设置被标成高价值", taps[0].score, 1)
    # 权利入口（未被 blocked 的）应排最前
    st2 = state("f2", seen=("id:ad", "id:undo"),
                labels={"id:ad": "限时活动", "id:undo": "撤回同意"})
    kg2 = K.AppKG("com.demo")
    kg2.sync(build(st2))
    o2 = kg2.options("f2", [N("限时活动", (0, 0, 100, 50), "a:id/ad"),
                            N("撤回同意", (0, 60, 100, 110), "a:id/undo")])
    t2 = [o for o in o2 if o.action == "tap"]
    eq("权利入口排最前", t2[0].label, "撤回同意")
    eq("权利入口 score=0", t2[0].score, 0)
    check("理由点名目标", "权利入口" in t2[0].why, t2[0].why)

    # 元素已滚走（clicks 里没有它）→ 不能当选项
    st3 = state("f3", seen=("id:gone",), labels={"id:gone": "设置"})
    kg3 = K.AppKG("com.demo")
    kg3.sync(build(st3))
    o3 = kg3.options("f3", [])
    check("元素不在本屏时不给它选项",
          not any(o.action == "tap" for o in o3),
          [(o.oid, o.label) for o in o3])


# ============================================================ C. 导航

def test_nav():
    print("\n[C] 图上导航")
    home = state("f_home", seen=("id:tab_me", "id:tab_find"),
                 labels={"id:tab_me": "我的", "id:tab_find": "发现"},
                 tab="首页|发现|我的", depth=0)
    me = state("f_me", depth=1, parent="f_home", seen=("id:set",),
               labels={"id:set": "设置"}, tab="首页|发现|我的")
    setting = state("f_set", depth=2, parent="f_me",
                    seen=("id:priv", "id:about"),
                    labels={"id:priv": "隐私设置", "id:about": "关于"})
    about = state("f_about", depth=3, parent="f_set", seen=(),
                  labels={})
    pg = build(home, me, setting, about,
               edges=[edge("f_home", "id:tab_me", "我的", "f_me", "NEW"),
                      edge("f_me", "id:set", "设置", "f_set", "NEW"),
                      edge("f_set", "id:about", "关于", "f_about", "NEW")])
    kg = K.AppKG("com.demo")
    kg.sync(pg)
    n_home = kg.node_of("f_home").nid
    n_set = kg.node_of("f_set").nid
    p = kg.shortest(n_home, n_set)
    check("算得出两跳路径", p is not None and len(p["labels"]) == 2, p)
    eq("路径文字按顺序", (p or {}).get("labels"), ["我的", "设置"])
    eq("不可达返回 None", kg.shortest(n_set, n_home), None)

    hint = kg.path_to_target(n_home)
    check("到目标的路径提示存在", hint is not None, hint)
    if hint:
        eq("第一步是「我的」", hint["first_label"], "我的")
        eq("目标落在设置页", hint["nid"], n_set)
        eq("步数正确", hint["steps"], 2)
        # 图里还没有任何"权利入口"字样 → 只能按角色推断，必须标明是方向
        eq("无已见目标时走角色推断", hint["kind"], "role")

    # 已见目标（设置页里有「权限管理」）→ 走硬事实，不再按角色猜
    setting2 = state("f_set2", depth=2, parent="f_me",
                     seen=("id:perm",), labels={"id:perm": "权限管理"})
    kg3 = K.AppKG("com.demo")
    kg3.sync(build(home, me, setting2,
                   edges=[edge("f_home", "id:tab_me", "我的", "f_me", "NEW"),
                          edge("f_me", "id:set", "设置", "f_set2", "NEW")]))
    h3 = kg3.path_to_target(kg3.node_of("f_home").nid)
    check("已见目标时给出硬事实路径", h3 is not None, h3)
    if h3:
        eq("路径类型是 target", h3["kind"], "target")
        eq("目标落在含权限管理的界面", h3["nid"], kg3.node_of("f_set2").nid)

    # 当前节点已经在目标节点上 → 不需要路径（就地探索）
    check("已在目标节点上不给路径", kg.path_to_target(n_set) is None,
          kg.path_to_target(n_set))

    # 陷阱边不参与路径
    kg2 = K.AppKG("com.demo")
    pg2 = build(home, setting,
                edges=[edge("f_home", "id:tab_me", "我的", "f_set", "LEFT")])
    kg2.sync(pg2)
    check("陷阱边不参与路径",
          kg2.shortest(kg2.node_of("f_home").nid,
                       kg2.node_of("f_set").nid) is None)


def test_memory():
    print("\n[C2] 记忆表")
    home = state("f_home", seen=("id:me",), labels={"id:me": "我的"},
                 tab="首页|发现|我的", depth=0)
    me = state("f_me", depth=1, parent="f_home",
               seen=("id:set", "id:order", "id:del"),
               labels={"id:set": "设置", "id:order": "我的订单",
                       "id:del": "注销账号"},
               clicked=("id:order",))
    kg = K.AppKG("com.demo")
    kg.sync(build(home, me,
                  edges=[edge("f_home", "id:me", "我的", "f_me", "NEW")]))
    txt = kg.memory_text("f_me")
    check("记忆表非空", len(txt) > 30, txt)
    check("含当前节点", "当前：" in txt)
    check("含未找到的权利入口", "尚未找到的权利入口" in txt)
    check("含节点标题", "N2" in txt or "N1" in txt)
    # 预算硬控：超长图也不能超
    kg.budget = 120
    short = kg.memory_text("f_me")
    check("预算 120 时不超长", len(short) <= 120, len(short))
    kg.budget = 900
    check("默认预算内", len(kg.memory_text("f_me")) <= 900)

    # AI 命名：只认第一次
    nid = kg.node_of("f_me").nid
    check("首次命名成功", kg.note_desc("f_me", "我的页面（含订单与设置入口）"))
    eq("描述已写入", kg.nodes[nid].desc, "我的页面（含订单与设置入口）")
    check("二次命名被拒", not kg.note_desc("f_me", "另一个说法"))
    eq("描述未被覆盖", kg.nodes[nid].desc, "我的页面（含订单与设置入口）")
    eq("named 标记", kg.nodes[nid].named, True)

    # ★ 命名要能熬过 `sync()` 的重建。真机 mbsf11：22 个界面都让模型命名过，
    #   图里只剩 1 个 desc —— 因为 `_rebuild()` 重建了 Node 对象，命名写在
    #   node.desc 上就被抹回空。后果是报告一边写"AI 命名 22 个"、一边语义表
    #   几乎全空，记忆表也退化成"当前在不认识的一屏"。
    new_st = state("f_new", activity=".MainActivity", depth=1,
                   seen=("id:zz",), labels={"id:zz": "新界面"})
    kg2 = K.AppKG("com.demo")
    first = state("f_me", activity=".MainActivity", depth=1,
                  seen=("id:a", "id:b"),
                  labels={"id:a": "我的订单", "id:b": "设置"})
    kg2.sync(build(first))
    kg2.note_desc("f_me", "我的页面（含订单与设置入口）")
    eq("命名后 desc 就位", kg2.node_of("f_me").desc, "我的页面（含订单与设置入口）")
    # 再加一屏 → 触发全量重建
    kg2.sync(build(first, new_st))
    eq("重建后命名仍在", kg2.node_of("f_me").desc, "我的页面（含订单与设置入口）")
    eq("重建后 named 仍为真", kg2.node_of("f_me").named, True)
    eq("重建后 stats 计入命名", kg2.stats()["named"], 1)
    # 合并进来的 fp 不能把已有命名冲掉，也不能各说各话
    kg2.note_desc("f_me", "我的页面（含订单与设置入口）")
    eq("重复命名幂等", kg2.node_of("f_me").desc, "我的页面（含订单与设置入口）")


def test_merge_content_pages():
    print("")
    print("[A2b] 内容会变的界面合并（首页/列表）")
    # 首页：可点元素 id 归一化后完全一致，只有推荐文字不同 → 必须合并。
    # 真机 mbsf9 实测首页被算成 3 个节点（N1/N3/N8），覆盖率分母虚高 3 倍。
    a = state("h1", depth=0, tab="首页|发现|我的",
              seen=("id:t1", "id:t2", "id:t3", "id:feed_item_1", "id:feed_item_2"),
              labels={"id:t1": "首页", "id:t2": "发现", "id:t3": "我的",
                      "id:feed_item_1": "推荐A", "id:feed_item_2": "推荐B"},
              first_ts=1.0)
    b = state("h2", depth=0, tab="首页|发现|我的",
              seen=("id:t1", "id:t2", "id:t3", "id:feed_item_3", "id:feed_item_4"),
              labels={"id:t1": "首页", "id:t2": "发现", "id:t3": "我的",
                      "id:feed_item_3": "推荐C", "id:feed_item_4": "推荐D"},
              first_ts=2.0)
    kg = K.AppKG("com.demo")
    kg.sync(build(a, b))
    eq("首页内容变化仍合并成一个节点", kg.stats()["nodes"], 1)
    eq("合并留痕", len(kg.merges), 1)
    check("合并理由写明只比结构", "只比可点元素" in (kg.merges[0]["why"] if kg.merges else ""),
          kg.merges[:1])

    # 但结构不同的两屏（id 集合差很多）仍不合并
    c = state("h3", depth=0, tab="首页|发现|我的",
              seen=("id:z1", "id:z2", "id:z3", "id:z4", "id:z5"),
              labels={"id:z1": "一", "id:z2": "二", "id:z3": "三",
                      "id:z4": "四", "id:z5": "五"}, first_ts=3.0)
    kg2 = K.AppKG("com.demo")
    kg2.sync(build(a, c))
    eq("结构不同的顶层界面不合并", kg2.stats()["nodes"], 2)


def test_policy_deprioritize():
    print("")
    print("[B3] 协议/政策入口降权")
    st = state("f1", seen=("id:pp", "id:set", "id:ad"),
               labels={"id:pp": "《隐私政策》", "id:set": "设置",
                       "id:ad": "限时活动"})
    kg = K.AppKG("com.demo")
    kg.sync(build(st))
    clicks = [N("《隐私政策》", (0, 0, 100, 50), "a:id/pp"),
              N("设置", (0, 60, 100, 110), "a:id/set"),
              N("限时活动", (0, 120, 100, 170), "a:id/ad")]
    opts = kg.options("f1", clicks)
    taps = [o for o in opts if o.action == "tap"]
    pp = [o for o in taps if "隐私政策" in o.label]
    check("政策入口仍在选项里（不是排除，只是排后）", bool(pp),
          [o.label for o in taps])
    if pp:
        eq("政策入口 score=5", pp[0].score, 5)
        check("理由说明正文已取得", "P2" in pp[0].why, pp[0].why)
    eq("设置仍排第一", taps[0].label, "设置")
    # 真机依据：mbsf9 的 26 步里有 5 步在《隐私政策》上进进出出，一次新界面都没多到


def test_step_mapping():
    print("")
    print("[B4] 选项 → 执行动作映射")
    import piiscan.collector as C
    from piiscan.flow.kgraph import Option
    tap = Option(oid="A1", action="tap", label="设置",
                 node=N("设置", (0, 0, 10, 10), "a:id/s"))
    st = C._option_to_step(tap)
    eq("tap 带上节点", st.get("action"), "tap")
    check("tap 的 node 是同一个对象", st.get("node") is tap.node)
    sc = C._option_to_step(Option(oid="S1", action="scroll", why="向下找"))
    eq("scroll 映射成 swipe", sc.get("action"), "swipe")
    eq("swipe 方向是 up（看下面的内容）", sc.get("direction"), "up")
    pu = C._option_to_step(Option(oid="P1", action="pull"))
    eq("pull 保持原动作", pu.get("action"), "pull")
    bk = C._option_to_step(Option(oid="B1", action="back", label="N1 首页"))
    eq("back 保持原动作", bk.get("action"), "back")
    check("back 不误带 node", bk.get("node") is None)


def test_archive():
    print("\n[C3] 存档")
    home = state("f_home", seen=("id:me", "id:ad"), labels={"id:me": "我的",
                                                            "id:ad": "活动"})
    kg = K.AppKG("com.demo")
    kg.sync(build(home))
    d = kg.to_dict()
    check("stats 在存档里", "stats" in d)
    check("nodes 在存档里", len(d["nodes"]) == 1)
    check("targets 覆盖 9 类", len(d["targets"]) == 9)
    check("未探索动作带标签", any(t["label"] == "我的" for t in d["nodes"][0]["todo"]),
          d["nodes"][0]["todo"])
    import json
    json.dumps(d, ensure_ascii=False)      # 必须可 json 序列化（要进 result.json）
    check("可 json 序列化", True)


def main():
    test_build()
    test_merge()
    test_action_kinds()
    test_targets()
    test_merge_content_pages()
    test_options()
    test_option_priority()
    test_policy_deprioritize()
    test_step_mapping()
    test_nav()
    test_memory()
    test_archive()
    print("\n结果：%d 通过 / %d 失败" % (PASS, FAIL))
    if FAILS:
        print("失败项：")
        for f in FAILS:
            print("  -", f)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
