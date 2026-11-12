"""点击路径的记录规整与重放匹配：把首轮的"点了什么"变成复现轮的"按原路再点一遍"。

**为什么要有这一层**

    改造前 P7 的做法是"清数据后整轮重跑"：复现轮和首轮一样走首启 → 政策 →
    同意 → 登录，然后交给同一套遍历器（AI 指挥 / 调度规则）重新探一遍。
    两个后果：
      · **贵**：首轮 420 秒里约 60 秒花在等模型回答上，复现轮照样要等；
      · **不可比**：每轮走的界面不同，某个判据没出现时无法区分
        "问题不再复现"和"这轮根本没走到那屏"。后者会被判成"未复现"、
        进而把 fail 降成 suspect —— 这是**假降级**，比不复现更危险。

    改成"按首轮点击路径重放"之后，复现轮不再决策：照着首轮记下的
    tap / back / swipe / pull 顺序执行，一步一个动作，不调模型。
    路径能走完 = 走到了同一批界面，此时"判据未再出现"才是真的未复现。

**分工**

    本模块只做纯逻辑（能离线单测）：
      · `norm()`   把一条动作规整成可存档、可跨轮比较的形态；
      · `match()`  给定当前屏的元素列表，找出这条记录该点哪个元素；
      · `plan()`   预检整条路径能不能在当前屏起步（判断是否需要先回退）；
      · `summarize()` 走到第几步、哪几步跳过、是否漂移。
    真正 `adb tap` 由 collector 做 —— flow 层碰设备，离线重渲染（--from-result）
    就废了，同一份存档在服务器上会得出和采集端不一样的结论。

**匹配为什么要四级**

    首轮的坐标不能直接复用：状态栏高度、软键盘、字体缩放、内容长度变化都会
    让同一个入口落到不同位置。所以先认文字（最稳，但列表内容会变），
    再认 resource-id（很稳，但 WebView/自绘界面没有），
    最后才退到坐标包含（只在标签全对不上时用，且要求唯一命中）。
    四级都落空就算"这一步重放不了" —— 如实记账，不硬点一个位置相近的元素。
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# 支持的四种动作，外加一个"登录"标记。`tap` 需要定位元素；其余按方向/按键执行。
# ★ 为什么要记 `login`：首轮很多路径**跨越登录**——先以游客身份走几屏，
#   走到登录页时代填登录，然后继续走登录后的界面。复现轮如果一上来就登录
#   或者完全不登录，界面栈都与首轮对不上，从登录点往后每一步都找不到目标
#   （真机实测 mbsf16：前 8 步全部命中，第 10 步起连续落空）。把登录当成
#   路径里的一步记下来，回放时才真正"照着原路走"。
KINDS = ("tap", "back", "swipe", "pull", "login")

# 连续多少步找不到目标就判定路径漂移并停止。
# 单步找不到是常态（元素被弹窗盖住、列表滚出屏幕），连续三步找不到说明
# 已经不在首轮那条路径上了 —— 此时继续按记录点下去只会在错误界面上乱点，
# 产生一批与问题项无关的事件，反过来污染复现判定。
DRIFT_LIMIT = 3

_WORD = re.compile(r"[\s\u3000]+")

# 结构树里大量 View 节点的 text 为空，`UiNode.label` 会退化成类名
# （"android.view.ViewGroup"）。把这种当"文字判据"用，第一次匹配就会命中所
# 有同类型空节点，把复现带到完全无关的位置。
_CLSNAME = re.compile(r"^[a-zA-Z_][\w]*(\.[a-zA-Z_][\w]*)+$")


def _looks_like_cls(s: str) -> bool:
    return bool(_CLSNAME.match(s or ""))


def _clean_label(s: Any) -> str:
    """文字归一：去首尾与中间的分隔空白。

    首轮记的是结构树里的原文，复现轮读的是同一棵树，理论上完全一致；
    归一化只为吃掉"多条空白/换行"这类不改变语义的差异。
    """
    return _WORD.sub("", str(s or "")).strip()


def norm(kind: str, **kw: Any) -> Dict[str, Any]:
    """把一条动作规整成可存档形态。

    `kind` 不在 KINDS 里返回空字典（调用方据此跳过记录）：宁可少记一条，
    也不要往路径里塞一种回放时无法执行的动作 —— 那会让复现轮在跑到一半时
    才发现"这一步不知道怎么做"。
    """
    k = str(kind or "").strip()
    if k not in KINDS:
        return {}
    it: Dict[str, Any] = {"kind": k}

    if k == "tap":
        lab = _clean_label(kw.get("label"))
        cls = str(kw.get("cls") or "").strip()
        uid = str(kw.get("uid") or "").strip()
        # label 退化成类名时不存：那不是"文字"，是个类型标签。
        if lab and _looks_like_cls(lab):
            lab = ""
        if lab:
            it["label"] = lab[:40]
        if cls:
            it["cls"] = cls[:80]
        if uid:
            it["uid"] = uid[:120]
        at = kw.get("at")
        if isinstance(at, (list, tuple)) and len(at) == 2:
            try:
                it["at"] = [int(at[0]), int(at[1])]
            except Exception:
                pass
        bounds = kw.get("bounds")
        if isinstance(bounds, (list, tuple)) and len(bounds) == 4:
            try:
                it["bounds"] = [int(x) for x in bounds]
            except Exception:
                pass
        # 结构树外坐标点击（WebView/Canvas）：没有 uid，只能靠坐标。
        # 标出来是为了让回放知道"这条本来就不该在树里找到元素"。
        if kw.get("coord"):
            it["coord"] = True
    elif k == "swipe":
        d = str(kw.get("dir") or "down").strip()
        it["dir"] = d if d in ("up", "down", "left", "right") else "down"
        # scroll=True 表示"纵向滚动看内容"，对应 uiwalk.scroll；
        # 否则是 swipe_side（左右切换/轮播）。两者物理动作不同，不能混。
        it["scroll"] = bool(kw.get("scroll", it["dir"] in ("up", "down")))
    elif k == "login":
        # 只记"这里登录过"这个事实。手机号/验证码不进路径：路径会落盘进报告
        # 存档，敏感信息留在里面既没必要也不该带出去。
        pass

    src = str(kw.get("src") or "").strip()
    if src:
        it["src"] = src[:12]          # ai / sched / rule
    # ---- 判读与留痕（2026-11-05）----
    # 这两项**不参与重放**（重放照抄动作，不需要理由），但必须跟着动作一起存：
    # 报告要按同一次点击把"图 + 判读 + 结果"摆在一起，分开存就对不上号了。
    why = str(kw.get("why") or "").strip()
    if why:
        it["why"] = why[:200]
    shot = kw.get("shot")
    if isinstance(shot, int) and shot > 0:
        it["shot"] = shot             # 指向 res.click_shots 的 1 基编号
    fp = str(kw.get("fp") or "").strip()
    if fp:
        it["fp"] = fp[:24]            # 执行前所在界面指纹，用于事后核查
    el = kw.get("elapsed")
    if isinstance(el, (int, float)):
        it["t"] = round(float(el), 1)
    return it


def _uniq(nodes: Sequence[Any], pred) -> List[Any]:
    return [n for n in nodes if pred(n)]


def match(nodes: Sequence[Any], step: Dict[str, Any]) -> Tuple[Optional[Any], str]:
    """在当前屏的元素里找这条记录对应的元素。

    返回 `(node, how)`，`how` 是命中的一级（写进日志与报告，便于复核
    "这一步是按文字找到的，还是按坐标蒙的"）。找不到返回 `(None, "")`。
    """
    if not step or step.get("kind") != "tap":
        return None, ""
    usable = [n for n in nodes if getattr(n, "enabled", True)]
    lab = _clean_label(step.get("label"))
    cls = str(step.get("cls") or "")
    uid = str(step.get("uid") or "")

    # ① 文字 + 控件类型：最稳的一级。同屏常有多个「设置」（tab 上的与列表项里的），
    #    加上 cls 能把 RadioButton（底部 tab）和 TextView（列表项）分开。
    if lab and cls:
        hit = _uniq(usable, lambda n: (_clean_label(getattr(n, "label", "")) == lab
                                       and str(getattr(n, "cls", "")) == cls))
        if len(hit) == 1:
            return hit[0], "文字+类型"

    # ② 只按文字，且必须唯一。多个同名元素时不敢猜 —— 猜错就是走上了另一条路径。
    if lab:
        hit = _uniq(usable, lambda n: _clean_label(getattr(n, "label", "")) == lab)
        if len(hit) == 1:
            return hit[0], "文字"
        if len(hit) > 1 and step.get("bounds"):
            same = _pick_by_bounds(hit, step["bounds"])
            if same is not None:
                return same, "文字+位置"

    # ③ resource-id：文字为空或同名多个时的第二抓手（列表项、图标按钮）。
    if uid:
        hit = _uniq(usable, lambda n: str(getattr(n, "resource_id", "")) == uid)
        if len(hit) == 1:
            return hit[0], "控件id"

    # ④ 坐标包含：只在前三级全落空时用。要求"首轮的中心点落在该元素范围内"，
    #    而不是"离得最近" —— 后者在半屏布局变化时会点到一个完全无关的元素。
    if step.get("bounds"):
        same = _pick_by_bounds(usable, step["bounds"])
        if same is not None:
            return same, "坐标位置"
    if step.get("coord") and step.get("at"):
        return _CoordHit(tuple(step["at"])), "记录坐标"

    return None, ""


def _pick_by_bounds(nodes: Iterable[Any], bounds: Sequence[int]) -> Optional[Any]:
    """按"记录里的中心点落在哪个元素内"来选，且要求唯一命中。"""
    try:
        x1, y1, x2, y2 = [int(v) for v in bounds]
    except Exception:
        return None
    cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
    hit = []
    for n in nodes:
        try:
            b = getattr(n, "bounds", None) or (0, 0, 0, 0)
            nx1, ny1, nx2, ny2 = [int(v) for v in b]
        except Exception:
            continue
        if nx1 <= cx <= nx2 and ny1 <= cy <= ny2:
            hit.append(n)
    if len(hit) == 1:
        return hit[0]
    # 多个元素都包含该点时，取面积最小的那个（最内层）：父子容器会同时命中，
    # 而真正被点的是最里面那个。
    if len(hit) > 1:
        def area(n):
            b = getattr(n, "bounds", (0, 0, 0, 0))
            return max(0, (int(b[2]) - int(b[0]))) * max(0, (int(b[3]) - int(b[1])))
        hit.sort(key=area)
        # 面积并列说明两个元素几乎重合，分不清 → 不猜
        if area(hit[0]) < area(hit[1]):
            return hit[0]
    return None


class _CoordHit:
    """按记录坐标点击时的占位对象：只需要 center 与 label。"""

    __slots__ = ("_c", "label", "cls", "resource_id", "bounds")

    def __init__(self, c: Tuple[int, int]):
        self._c = c
        self.label = "（记录坐标）"
        self.cls = ""
        self.resource_id = ""
        self.bounds = (c[0], c[1], c[0], c[1])

    @property
    def center(self) -> Tuple[int, int]:
        return self._c


def plan(steps: Sequence[Dict[str, Any]], nodes: Sequence[Any]) -> Dict[str, Any]:
    """预检：这条路能否从当前屏起步。

    只回答一个问题 —— 第一步（如果是 tap）现在找不找得到。用于回放开始前
    打一行日志，让"起点就对不上"这件事在日志里显式出现，而不是等到
    连续漂移三次才发现。
    """
    out = {"total": len(steps), "first_ok": True, "first_how": "", "first_label": ""}
    if not steps:
        out["first_ok"] = False
        return out
    s0 = steps[0]
    if s0.get("kind") != "tap":
        return out
    out["first_label"] = s0.get("label") or ""
    n, how = match(nodes, s0)
    out["first_ok"] = n is not None
    out["first_how"] = how
    return out


def summarize(steps: Sequence[Dict[str, Any]], done: int, skipped: Sequence[int],
              *, drift: bool = False, timed_out: bool = False,
              by_kind: Optional[Dict[str, int]] = None,
              not_replayable: Sequence[int] = (),
              stopped: str = "",
              skip_notes: Sequence[str] = ()) -> Dict[str, Any]:
    """回放结果的可存档摘要。

    `done` 是"执行成功的步数"，不是"下标"——报告里要回答的是
    "这段路径重放了多少"，而不是"停在了第几条"。
    `stopped` 是停手原因的自然语言（登录失败、应用退出…）。它和
    `drift`/`timed_out` 分开：那两个是判定出来的，这个是执行时撞上的事实，
    混在一起写会让报告读者分不清"路径变了"还是"这一步就没做成"。
    `skip_notes` 是"哪一步因为什么被跳过"的人话（如「第 33 步「my_vip_open」」）。
    只记下标不够用：复核员要判断"判据会不会正由被跳过的那一步触发"，
    必须看到是哪一步、点的什么。
    """
    total = len(steps)
    return {
        "total": total,
        "done": int(done),
        "skipped": sorted(int(i) for i in skipped),
        "not_replayable": sorted(int(i) for i in not_replayable),
        "drift": bool(drift),
        "timed_out": bool(timed_out),
        "stopped": str(stopped or ""),
        "complete": bool(total and not drift and not timed_out and not stopped
                         and int(done) + len(skipped) + len(not_replayable) >= total),
        "by_kind": dict(by_kind or {}),
        # 只留前 8 条：存档与报告都不是日志，超过这个数量复核员也不会逐条看
        "skip_notes": [str(x)[:60] for x in (skip_notes or ())][:8],
    }


def describe(res: Dict[str, Any]) -> str:
    """一句话说明回放结果，给日志和报告用（口径只在这里写一次）。"""
    total = int(res.get("total") or 0)
    done = int(res.get("done") or 0)
    skip = len(res.get("skipped") or [])
    bad = len(res.get("not_replayable") or [])
    tail = ""
    if res.get("stopped"):
        tail = "；%s" % res["stopped"]
    elif res.get("drift"):
        tail = "；中途路径漂移（连续 %d 步找不到目标）后停止" % DRIFT_LIMIT
    elif res.get("timed_out"):
        tail = "；到采集时长上限时仍未走完"
    seg = "共 %d 步，已重放 %d 步" % (total, done)
    if skip or bad:
        seg += "，跳过 %d 步" % (skip + bad)
    return seg + tail
