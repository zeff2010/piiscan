"""点击路径记录与重放的离线回归。

覆盖两块：

  A. `flow/replay.py`：动作规整（哪些字段该存、类名不能当文字）、四级匹配
     （文字+类型 → 文字 → 控件 id → 坐标包含）、预检、结果摘要
  B. `flow/repro.py` 的 `_replay_gap`：重放没走完时**不许**判"未复现"
     —— 否则等于用"工具没走到"给被测应用减责

全部用构造的节点，不碰真机。
"""
from __future__ import annotations

import sys
from types import SimpleNamespace

sys.path.insert(0, ".")

from piiscan.flow import replay as R            # noqa: E402
from piiscan.flow import repro as RP           # noqa: E402

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


def node(label="", cls="android.widget.TextView", uid="", bounds=(0, 0, 100, 100),
         enabled=True):
    """造一个 UiNode 形状的对象：匹配只看 label/cls/resource_id/bounds/enabled。"""
    return SimpleNamespace(label=label, cls=cls, resource_id=uid, bounds=bounds,
                           enabled=enabled, text=label, content_desc="")


# ================================================================ A. 规整
def t_norm():
    print("[A1] 动作规整")
    s = R.norm("tap", label="  我 的 ", cls="android.widget.RadioButton",
               uid="id/tab_4", at=(540, 2100), bounds=(0, 2000, 1080, 2200),
               src="ai", fp="abc123", elapsed=12.34)
    eq("tap 的 kind", s["kind"], "tap")
    eq("label 去空白", s["label"], "我的")
    eq("cls 原样保留", s["cls"], "android.widget.RadioButton")
    eq("uid 保留", s["uid"], "id/tab_4")
    eq("at 转 list", s["at"], [540, 2100])
    eq("bounds 转 list", s["bounds"], [0, 2000, 1080, 2200])
    eq("src 保留", s["src"], "ai")
    eq("t 四舍五入到 0.1", s["t"], 12.3)

    # ★ 结构树里大量空 View 的 label 会退化成类名。把它当文字存下来，
    #   匹配时第一个空 View 就会命中，复现直接走到别处。
    s2 = R.norm("tap", label="android.view.ViewGroup",
                cls="android.view.ViewGroup", bounds=(0, 0, 1080, 100))
    check("label 是类名时不存", "label" not in s2, s2)

    s3 = R.norm("tap", label="id/btn_ok", cls="android.widget.Button")
    eq("resource_id 形态的 label 保留", s3.get("label"), "id/btn_ok")

    eq("未知 kind 返回空", R.norm("longclick", label="x"), {})
    eq("空 kind 返回空", R.norm("", label="x"), {})

    sw = R.norm("swipe", dir="left")
    eq("swipe 左右不算 scroll", sw.get("scroll"), False)
    sw2 = R.norm("swipe", dir="down")
    eq("swipe 上下默认 scroll", sw2.get("scroll"), True)
    sw3 = R.norm("swipe", dir="bogus")
    eq("非法方向归为 down", sw3.get("dir"), "down")

    eq("back 只有 kind", R.norm("back"), {"kind": "back"})
    eq("pull 只有 kind", R.norm("pull"), {"kind": "pull"})

    # 登录是路径里的一步：只记"这里登录过"，手机号/验证码不进存档
    lg = R.norm("login", label="133****0822", at=(1, 2))
    eq("login 只记 kind", lg, {"kind": "login"})

    c = R.norm("tap", label="播放", at=(10, 20), coord=True)
    eq("结构树外坐标标记", c.get("coord"), True)


# ================================================================ B. 匹配
def t_match():
    print("[A2] 四级匹配")
    # ① 文字 + 类型：同屏两个「设置」，一个是底部 tab（RadioButton），
    #    一个是列表项（TextView）。只按文字会挑错。
    tab = node("设置", "android.widget.RadioButton", bounds=(810, 2000, 1080, 2200))
    item = node("设置", "android.widget.TextView", bounds=(0, 300, 1080, 420))
    step = R.norm("tap", label="设置", cls="android.widget.RadioButton",
                  bounds=(810, 2000, 1080, 2200))
    got, how = R.match([item, tab], step)
    check("文字+类型挑中 tab 而不是列表项", got is tab, how)
    eq("命中方式写明", how, "文字+类型")

    # ② 只有文字且唯一
    got, how = R.match([item], R.norm("tap", label="设置"))
    check("按文字命中", got is item, how)
    eq("命中方式=文字", how, "文字")

    # ③ 文字多个时用记录位置挑
    got, how = R.match([tab, item],
                       R.norm("tap", label="设置", bounds=(0, 300, 1080, 420)))
    check("同名多个按位置挑", got is item, how)

    # ④ 文字全对不上时按控件 id
    got, how = R.match([node("甲", uid="id/a"), node("乙", uid="id/b")],
                       R.norm("tap", label="丙", uid="id/b"))
    check("按控件 id 命中", got.label == "乙", how)
    eq("命中方式=控件id", how, "控件id")

    # ⑤ 坐标包含：没有文字也没有 id 的自绘界面
    hit = node("", "android.view.View", bounds=(100, 200, 300, 400))
    got, how = R.match([hit], R.norm("tap", bounds=(150, 250, 250, 350)))
    check("按记录位置包含命中", got is hit, how)
    eq("命中方式=坐标位置", how, "坐标位置")

    # 父子容器都包含中心点：取面积最小（最内层）
    parent = node("", "android.view.ViewGroup", bounds=(0, 0, 1080, 2000))
    child = node("", "android.widget.Button", bounds=(400, 900, 700, 1000))
    got, _how = R.match([parent, child], R.norm("tap", bounds=(450, 920, 650, 980)))
    check("父子都命中时取最内层", got is child,
          (getattr(got, "cls", ""), _how))

    # ⑥ 前三级全落空但有 coord 标记 → 用记录坐标
    got, how = R.match([], R.norm("tap", label="播放", at=(500, 800), coord=True))
    check("结构树外点击退到记录坐标", got is not None, how)
    eq("坐标命中方式", how, "记录坐标")
    eq("占位对象带中心点", got.center, (500, 800))

    # ⑦ 什么都没有 → 不猜
    got, how = R.match([node("别的")], R.norm("tap", label="找不到", uid="id/x"))
    check("全落空返回 None", got is None, (got, how))
    eq("全落空 how 为空", how, "")

    # ⑧ 禁用元素不参与匹配（首轮能点的元素，重放时被置灰说明状态变了）
    got, _how = R.match([node("提交", enabled=False)], R.norm("tap", label="提交"))
    check("禁用元素不参与匹配", got is None, got)

    # ⑨ 非 tap 动作不匹配
    got, how = R.match([node("返回")], R.norm("back"))
    check("back 不做元素匹配", got is None and how == "", (got, how))


def t_plan():
    print("[A3] 起步预检")
    steps = [R.norm("tap", label="我的"), R.norm("tap", label="设置")]
    p = R.plan(steps, [node("我的")])
    eq("总步数", p["total"], 2)
    eq("首步能找到", p["first_ok"], True)
    eq("首步命中方式", p["first_how"], "文字")

    p2 = R.plan(steps, [node("别的")])
    eq("首步找不到", p2["first_ok"], False)
    eq("首步文字回填", p2["first_label"], "我的")

    p3 = R.plan([R.norm("back")], [])
    eq("非 tap 首步视为可起步", p3["first_ok"], True)
    eq("空路径不可起步", R.plan([], [node("x")])["first_ok"], False)


def t_summary():
    print("[A4] 结果摘要与措辞")
    steps = [R.norm("tap", label=str(i)) for i in range(5)]
    s = R.summarize(steps, 5, [])
    eq("走完时 complete", s["complete"], True)
    check("走完的说明不含停手原因", "停止" not in R.describe(s), R.describe(s))

    s2 = R.summarize(steps, 3, [2], drift=True)
    eq("漂移时 complete=False", s2["complete"], False)
    check("漂移写进说明", "漂移" in R.describe(s2), R.describe(s2))

    s3 = R.summarize(steps, 2, [0, 1], not_replayable=[3], timed_out=True)
    eq("超时 complete=False", s3["complete"], False)
    check("超时写进说明", "上限" in R.describe(s3), R.describe(s3))
    check("跳过数合并统计", "跳过 3 步" in R.describe(s3), R.describe(s3))

    s4 = R.summarize(steps, 0, [])
    eq("一步没走不算 complete", s4["complete"], False)
    eq("空路径不算 complete", R.summarize([], 0, [])["complete"], False)

    # 登录失败中止：原因要写进说明，不能只说"其余步骤未能重放"
    s5 = R.summarize(steps, 2, [], stopped="第 3 步登录未完成，登录之后的步骤无法重放")
    eq("登录中止不算 complete", s5["complete"], False)
    check("登录中止原因进说明", "登录未完成" in R.describe(s5), R.describe(s5))

    # 跳过的步要能说出"哪一步、点的什么"：只记下标，复核员无法判断
    # 判据会不会正由被跳过的那一步触发（mbsf19 跳的是「my_vip_open」与
    # 「拍照识字」，光看 [33, 52] 完全看不出这两步是否有关系）。
    s6 = R.summarize(steps, 4, [2],
                     skip_notes=["第 3 步「my_vip_open」在当前界面找不到"])
    eq("跳过说明进摘要", s6["skip_notes"],
       ["第 3 步「my_vip_open」在当前界面找不到"])
    eq("跳过后仍算走完", s6["complete"], True)
    eq("无跳过说明时是空列表", R.summarize(steps, 5, [])["skip_notes"], [])
    check("跳过说明过长时截断",
          all(len(x) <= 60 for x in R.summarize(
              steps, 0, [0], skip_notes=["x" * 200])["skip_notes"]))


# ================================================================ C. 判定闸门
def _scan(replay=None, events=None):
    return SimpleNamespace(events=events or [], perm_scenes=[],
                           ui_replay=replay or {},
                           policy_capture={})


def t_gap():
    print("[B1] 重放没走完不能判未复现")
    eq("未启用重放时不报缺口", RP._replay_gap({}), "")
    ok = {"total": 10, "done": 10, "complete": True, "skipped": []}
    eq("走完不报缺口", RP._replay_gap(RP.observe(_scan(ok))), "")
    bad = {"total": 10, "done": 4, "complete": False, "drift": True}
    g = RP._replay_gap(RP.observe(_scan(bad)))
    check("漂移时报缺口", "路径漂移" in g and "4/10" in g, g)
    bad2 = {"total": 10, "done": 6, "complete": False, "timed_out": True}
    g2 = RP._replay_gap(RP.observe(_scan(bad2)))
    check("超时时报缺口", "时长上限" in g2, g2)

    # complete 缺失（老存档只有 total/done）时按"没走完"处理：
    # 无法证明走完就不能当走完用。
    g3 = RP._replay_gap({"replay": {"total": 8, "done": 8}})
    check("缺 complete 字段按时未走完处理", g3 != "", g3)


def t_path_gap():
    print("[B2] 压根没进入重放也要挡住")
    p1 = [{"kind": "tap"} for _ in range(7)]
    s1 = _scan({"total": 7, "done": 7, "complete": True})
    s1.ui_path = p1

    # 首轮有路径、复现轮一次都没点：首启把时长用完了（mbsf15 的真实形态）
    s2 = _scan()                      # ui_replay 空
    s2.ui_taps = 0
    g = RP.path_gap(s1, s2, RP.observe(s2))
    check("没进重放时报缺口", "未进入路径重放" in g and "7 步" in g, g)

    # 首轮有路径、复现轮走了别的遍历（老版本行为）：不报缺口，
    # 那是"整轮重新遍历"，不是"没走"，口径不同不能混。
    s3 = _scan()
    s3.ui_taps = 12
    eq("整轮重新遍历不算缺口", RP.path_gap(s1, s3, RP.observe(s3)), "")

    # 首轮本来就没路径（旧存档）：无从要求重放，不报缺口
    s4 = _scan()
    s4.ui_path = []
    s4b = _scan()
    s4b.ui_taps = 0
    eq("首轮无路径时不报缺口", RP.path_gap(s4, s4b, RP.observe(s4b)), "")

    # 重放走了但没走完：走 _replay_gap 的口径
    s5 = _scan({"total": 7, "done": 3, "complete": False, "timed_out": True})
    s5.ui_taps = 3
    g5 = RP.path_gap(s1, s5, RP.observe(s5))
    check("走了一半报的是重放缺口", "时长上限" in g5, g5)


def main():
    t_norm()
    t_match()
    t_plan()
    t_summary()
    t_gap()
    t_path_gap()
    print("")
    print("=" * 56)
    print("点击路径重放回归：通过 %d 项，失败 %d 项" % (PASS, FAIL))
    if FAILS:
        print("失败项：")
        for f in FAILS:
            print("  -", f)
    print("=" * 56)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
