"""P4 遍历的页面图观测（Step 1：只记录，不参与决策）。

为什么单独一个模块
------------------
现有遍历（`collector._walk_ui`）每轮 dump 一屏、点一个没点过的元素，**不保存
"我从哪来、这屏是哪一屏、这一下点到了哪"**。于是三个问题无法回答：

  · 还有哪些界面/入口没去过（覆盖率无从度量，报告只能写"界面记录 25 个"）；
  · 哪些元素点了没反应（现在只能靠 stuck 计数整体后退，粒度太粗）；
  · 同一个入口被点了多少次（预算被重复消耗，日志里看不出来）。

本模块只做一件事：把遍历**实际走过的轨迹**记成一张图 ——
状态是界面（结构指纹），边是"在哪个界面点了哪个元素、跳到了哪"。

★ 本阶段（Step 1）纯粹是**观测**：`PageGraph` 不参与任何决策，遍历行为与
  改动前逐字节一致。所有调用点都在 collector 里用 try/except 包住，
  观测代码出任何异常都不允许影响采集。

指纹为什么不沿用现有的 `uiwalk.screen_fingerprint`
--------------------------------------------------
现有指纹是「activity + 全量可见文字的 md5」，用于"这次点击界面有没有变"是够的，
但用来建图会碎：列表滚动一屏、未读数加一、时间戳跳一秒，都会分裂成新状态；
反过来，uni-app / Flutter / 小程序容器是**单 Activity**，底部 tab 切换根本不改
activity，只看 activity 又会把三个 tab 合并成一个节点。

所以这里用结构特征组合：

    fp = h( activity
          + 关键 resource-id 集合（尾部数字归一化）
          + 可点节点数分桶（//5）
          + 主导航条签名（同一水平带、等宽、3~6 个短文字）
          + 最大可滚动容器内的子节点数分桶（//10） )

文字**不进**指纹（列表内容会变），但导航条文字进（tab 名是界面身份的一部分）。
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .. import uiwalk
from . import content

# 图规模上限：result.json 要能长期存档，不能因为异常 App 产生几万个状态而爆掉。
MAX_STATES = 600
MAX_EDGES = 2000

# 列表页判据：最大可滚动容器里至少有这么多可点行。
# 3 太少（分区标题 + 两个入口的普通页面会被当成列表，然后对它做上拉加载），
# 5 太多（真机上不少列表一屏只露 4 行）。
LIST_MIN_CHILDREN = 4

_TAIL_DIGITS = re.compile(r"\d+$")


# --------------------------------------------------------------------- 指纹

def _short_id(rid: str) -> str:
    """`com.foo:id/list_item_1` → `list_item_1`（保留数字，供 uid 用）。"""
    rid = (rid or "").strip()
    if not rid:
        return ""
    if ":id/" in rid:
        return rid.split(":id/", 1)[1]
    return rid.split("/")[-1]


def _id_sig(nodes: Sequence[uiwalk.UiNode]) -> str:
    """关键 resource-id 集合。

    ★ 尾部数字归一化：`list_item_1` / `list_item_2` 是同一列表的不同行，
    作为**界面身份**应当视为同构（否则列表每滚一行就是一个新状态）。
    注意这与 uid 相反 —— uid 必须保留完整 id，否则两行会被当成同一个元素。
    """
    ids: Set[str] = set()
    for n in nodes:
        s = _short_id(n.resource_id)
        if not s:
            continue
        ids.add(_TAIL_DIGITS.sub("#", s))
        if len(ids) >= 60:
            break
    return "|".join(sorted(ids)[:40])


def _screen_size(nodes: Sequence[uiwalk.UiNode]) -> Tuple[int, int]:
    w = h = 0
    for n in nodes:
        w = max(w, n.bounds[2])
        h = max(h, n.bounds[3])
    return w or 1080, h or 1920


# 底部/顶部导航按钮的 resource-id 特征。很多 App 的 tab 只有 id 没有 text
# （真机实测赣警办：底部四个 tab 的 text 全为空，只有 `tab_home`/`tab_person` 这类 id），
# 只按文字识别会认不出导航，"先铺 tab"这条策略就永远不生效。
_NAV_ID_HINT = ("tab", "nav", "menu", "bottom", "indicator")


def _nav_label(n: uiwalk.UiNode) -> str:
    """导航节点的标识：文字优先，没有文字用它在底栏里的位置。

    ★ 无文字底栏必须能命名（2026-11-10 CNC宝典）：自绘底栏四个 tab 的
      text / content-desc 全空、id 又都是 `layoutRoot`，若用 id 当标识，
      四个 tab 会得到完全相同的名字 —— `_tab_done` 点一个就把其余三个
      记成"已去过"，"铺一遍底栏"永远做不到。
    """
    t = (n.text or "").strip() or (n.content_desc or "").strip()
    if t:
        return t
    slot = int(getattr(n, "nav_slot", 0) or 0)
    if slot:
        total = int(getattr(n, "nav_total", 0) or 0)
        return ("底部导航第%d/%d项" % (slot, total)) if total else ("底部导航第%d项" % slot)
    return _short_id(n.resource_id)


def _stamp_bar(bar: Sequence[uiwalk.UiNode]) -> List[uiwalk.UiNode]:
    """给导航条上的节点打上位置标记（供命名与排序用）。"""
    out = sorted(bar, key=lambda n: n.bounds[0])
    for i, n in enumerate(out):
        n.nav_slot = i + 1
        n.nav_total = len(out)
    return out


def bottom_bar(nodes: Sequence[uiwalk.UiNode],
               screen_h: int) -> List[uiwalk.UiNode]:
    """按**几何形态**认底部导航条（完全不依赖文字）。识别不出来返回空列表。

    ★ 为什么需要这条判据（2026-11-10 CNC宝典 真机实测）：
      该 App 的底栏是自绘的（`PageNavigationView` → `CustomItemLayout`），
      结构树里四个 tab 的 `text` 与 `content-desc` **全部为空**，
      `resource-id` 统一是 `layoutRoot`。因此任何"看文字 / 看 id"的判据
      都不可能命中 —— 真机实测时 `nav_nodes` 一直返回空，调度器以为
      "这屏没有导航可铺"，于是扎进首页的内容网格，标题栏被反复点。
      底栏四个 tab 实际是「首页 / 数控 / 视频 / 我的」（截图可证）。

      唯一稳定的特征是几何：四个 RelativeLayout 各 270px，等分 1080 屏宽、
      首尾无缝相接、贴在最底部。这也是绝大多数 App 底栏的共性。

    判据（宁缺勿滥 —— 误判一条"导航"会把不同界面错并成一屏）：
      · 全部 clickable，位于屏幕最后 14%
      · 高度 ≤ 13% 屏高（排除整块内容区）
      · 2~6 个，落在同一水平带
      · 宽度相近（最大最小差 ≤ 30%）
      · **左右顶满屏宽**（首项左边 ≤ 3% 屏宽、末项右边 ≥ 97% 屏宽）
      · 相邻首尾相接（间隙 ≤ 6% 屏宽、且不重叠）

    ★ "顶满屏宽"这条是关键区分：CNC 首页的内容网格最后一行
      （车工/铣工/数控工艺…，y 2139~2191）同样等宽、同样在屏幕底部 14%，
      但它左右各留 44px 边距（44/1080 = 4%）→ 被这条排除。
      少了它，内容网格会被当成底栏，四个功能入口被当成 tab 点。
    """
    if screen_h <= 0:
        return []
    cands = [n for n in nodes
             if n.clickable
             and n.bounds[3] - n.bounds[1] > 0
             and n.bounds[1] >= screen_h * 0.86
             and (n.bounds[3] - n.bounds[1]) <= screen_h * 0.13]
    if len(cands) < 2:
        return []
    screen_w = max((n.bounds[2] for n in nodes), default=0)
    if screen_w <= 0:
        return []
    buckets: Dict[int, List[uiwalk.UiNode]] = {}
    for n in cands:
        # ★ 按**上边缘**分桶，不用中心点（2026-11-10 CNC宝典 实测）：
        #   首页最底部一行内容入口（车工/铣工/…，y 2139~2191）与底栏
        #   （y 2150~2261）中心点只差 40px，按 3% 屏高（72px）分桶会落进
        #   同一组变成 8 个候选，超过上限 6 → 整组被丢，底栏识别失败。
        #   同一行的控件 y1 在 dump 里逐像素相同，按 y1 分组才不会把
        #   "被底栏压住的内容行"和底栏搅在一起。
        buckets.setdefault(n.bounds[1] // 8, []).append(n)
    best: List[uiwalk.UiNode] = []
    best_cy = -1.0
    for grp in buckets.values():
        if not (2 <= len(grp) <= 6):
            continue
        ws = [n.bounds[2] - n.bounds[0] for n in grp]
        if min(ws) <= 0 or (max(ws) - min(ws)) > max(ws) * 0.3:
            continue
        grp = sorted(grp, key=lambda n: n.bounds[0])
        # 至少一半的项要带图标。真底栏的 tab 几乎都配图标；而"底部一排等宽
        # 文字格子"（列表最后一行、按钮组）没有 —— 两者几何形态一样，
        # 只能靠这一条分开（对照组见 _sched_tests 的 `cell_0..3` 用例）。
        if sum(1 for n in grp if getattr(n, "has_icon", False)) < max(2, len(grp) // 2):
            continue
        if grp[0].bounds[0] > screen_w * 0.03:
            continue
        if grp[-1].bounds[2] < screen_w * 0.97:
            continue
        _overlap = any(a.bounds[2] > b.bounds[0] + 1
                       for a, b in zip(grp, grp[1:]))
        if _overlap:
            continue
        if any((b.bounds[0] - a.bounds[2]) > screen_w * 0.06
               for a, b in zip(grp, grp[1:])):
            continue
        cy = sum((n.bounds[1] + n.bounds[3]) / 2.0 for n in grp) / len(grp)
        if cy > best_cy:
            best, best_cy = grp, cy
    return _stamp_bar(best) if best else []



# 主流 App 底部导航的标准叫法（兜底判据用，见 nav_nodes 末尾）。
# 刻意只收这些"几乎只作全局导航"的词：内容页的标签（如「热门」「精选」）
# 不收，否则会把一屏内容列表误判成导航条。
_NAV_WORDS = ("首页", "我的", "个人中心", "发现", "消息", "分类", "购物车",
              "订单", "学习", "课程", "题库", "社区", "打卡", "票夹",
              "工作台", "通讯录", "设置", "会员")


def nav_nodes(nodes: Sequence[uiwalk.UiNode],
              screen_h: int) -> List[uiwalk.UiNode]:
    """主导航条上的节点（按从左到右排序）。识别不出来返回空列表。

    判据全部来自真机上见过的形态，宁缺勿滥 —— 误判一条"导航"会让所有界面
    共用同一个签名，反而把不同界面错并成一个：

      · 同一水平带（中心 y 相差 ≤ 4% 屏高）
      · 3~6 个元素（1 个是标题、2 个是左右按钮，都不算）
      · 宽度相近（最大最小差 ≤ 50%）
      · 标签都很短（≤ 8 字；无文字的必须 id 带 tab/nav/menu 特征）
      · 位于屏幕下 1/3 或上 1/4

    ★ Step 2 起这个列表不只用来说明"这屏有没有导航"，调度器要**按它来铺 tab**：
      先把每个 tab 各点一次建一级结构，再逐支深挖，避免一头扎进某个 tab 出不来。
    """
    # ---- ① 几何底栏：不依赖任何文字，优先 ----
    _bar = bottom_bar(nodes, screen_h)
    if _bar:
        return _bar
    cands = []
    for n in nodes:
        if not n.clickable:
            continue
        lab = (n.text or "").strip()
        if 0 < len(lab) <= 8:
            cands.append(n)
        elif not lab:
            # 无文字的可点容器太多（卡片、遮罩、列表项），必须靠 id 收窄，
            # 否则一张列表页会被误判成"有导航"，tab 铺开策略立刻失效。
            sid = _short_id(n.resource_id).lower()
            if sid and any(h in sid for h in _NAV_ID_HINT):
                cands.append(n)
    buckets: Dict[int, List[uiwalk.UiNode]] = {}
    # ★ 不足 3 个就**不再直接返回**空（2026-11-10 CNC宝典）：底栏可能只有
    #   「首页 / 我的」两个标签（自绘/异形底栏在真机上很常见），
    #   直接 return 会让下面的词表兜底永远走不到。
    if len(cands) >= 3:
        for n in cands:
            cy = (n.bounds[1] + n.bounds[3]) / 2.0
            buckets.setdefault(int(cy / max(1.0, screen_h * 0.04)), []).append(n)
    best: List[uiwalk.UiNode] = []
    for _k, grp in buckets.items():
        if not (3 <= len(grp) <= 6):
            continue
        ws = [n.bounds[2] - n.bounds[0] for n in grp]
        if min(ws) <= 0 or (max(ws) - min(ws)) > max(ws) * 0.5:
            continue
        cy = (grp[0].bounds[1] + grp[0].bounds[3]) / 2.0
        if not (cy < screen_h * 0.25 or cy > screen_h * 0.70):
            continue
        if len(grp) > len(best):
            best = grp
    if best:
        return _stamp_bar(best)
    # ---- 兜底：几何判据落空时按「导航词表」认（2026-11-10 CNC宝典）----
    #   为什么要这一步：上面那套判据要求「3~6 个、宽度相近、同一水平带」。
    #   CNC宝典 的底栏是自绘的，结构树里只有「首页 / 我的」两个短标签
    #   （不足 3 个 → 恒返回空），于是调度器认为"这屏没有导航可铺"，
    #   只能在本屏残存的几个入口里反复挑，标题栏就被点了 4 次。
    #   用户明确要求：先把「首页 / 我的」这类大入口走一遍，再逐页深入。
    #   没有导航识别，这条策略根本无从执行。
    #
    #   兜底判据刻意保守：**只认词表里的标准叫法**，且必须在屏幕下半部，
    #   至少 2 个、标签互不相同。宁可少认（退回原行为），也不要把
    #   内容页的「推荐 / 关注」误当成全局导航 —— 那会把不同界面错并成一屏。
    _low: List[uiwalk.UiNode] = []
    _seen_lab: set = set()
    for n in nodes:
        if not n.clickable:
            continue
        lab = (n.text or "").strip()
        if lab not in _NAV_WORDS or lab in _seen_lab:
            continue
        cy = (n.bounds[1] + n.bounds[3]) / 2.0
        if cy < screen_h * 0.55:
            continue
        _seen_lab.add(lab)
        _low.append(n)
    if len(_seen_lab) >= 2:
        return _stamp_bar(_low[:6])
    return []


def _tab_sig(nodes: Sequence[uiwalk.UiNode], screen_h: int) -> str:
    """主导航条签名（底部或顶部 tab 的标签用 | 连接）。"""
    grp = nav_nodes(nodes, screen_h)
    return "|".join(_nav_label(n) for n in grp) if grp else ""


def _list_children(nodes: Sequence[uiwalk.UiNode]) -> int:
    """最大可滚动容器里包含的**可点**节点数（列表可见行数的近似）。

    `parse_all` 不保留父子关系，所以用**几何包含**判定：完全落在某个
    scrollable 节点 bounds 内的节点视为它的子节点。

    ★ 只数可点节点：一行列表往往由"标题 + 副标题 + 时间"三个节点组成，
      连不可点的文字一起数，4 行的列表会被算成 12，`//10` 分桶后仍能容忍，
      但"有没有列表"的阈值（≥4）会被 2 行的普通页面顶穿。
    """
    best = 0
    for c in nodes:
        if not c.scrollable:
            continue
        x1, y1, x2, y2 = c.bounds
        n = 0
        for o in nodes:
            if o is c or not o.clickable:
                continue
            ox1, oy1, ox2, oy2 = o.bounds
            if ox1 >= x1 and oy1 >= y1 and ox2 <= x2 and oy2 <= y2:
                n += 1
        best = max(best, n)
    return best


def fingerprint(xml: str, activity: str = "") -> str:
    """结构指纹（12 位）。同一界面在滚动/文字变化后应当保持不变。"""
    nodes = uiwalk.parse_all(xml)
    if not nodes:
        return ""
    _w, h = _screen_size(nodes)
    clicks = [n for n in nodes if n.clickable]
    h_ = hashlib.md5()
    h_.update((activity or "").encode("utf-8", "replace"))
    h_.update(b"|" + _id_sig(nodes).encode("utf-8", "replace"))
    h_.update(b"|" + str(min(40, len(clicks) // 5)).encode())
    h_.update(b"|" + _tab_sig(clicks, h).encode("utf-8", "replace"))
    h_.update(b"|" + str(min(40, _list_children(nodes) // 10)).encode())
    return h_.hexdigest()[:12]


# --------------------------------------------------------------------- uid

def _label_of(node: uiwalk.UiNode) -> str:
    """元素的可读标签：文字优先，没有文字用 content-desc。

    ★ 必须合并成一个概念。真机实测（赣警办）：同一个「转到上一层级」按钮，
    有的 dump 里带 content-desc、有的没有（系统渲染差异），于是同一元素拿到
    `cd:转到上一层级` 与 `tx:转到上一层级` 两个身份 —— 图上的边被拆成两条，
    重复点击统计也跟着失真。

    ★ 第三顺位用 `sub_text`（后代文字，2026-11-10 CNC宝典）：
      空壳可点容器（clickable 的 LinearLayout，自身无文字）原来只能落到
      `cl:LinearLayout`，一屏 18 个入口全同名。继承子文字后 identity 变成
      「数控基础 / 数控工艺」，既稳定（每个入口名字唯一，滚动不漂移）又可读。

    ★ 但**图标不继承**（同上，2026-11-10 第二轮实测）：标题栏是一行
      返回箭头 + 标题文字 + 两个图标按钮，图标节点（ImageView）自己没有文字，
      继承到的是同一行里的标题「数控车床CNC宝典」—— 于是报告里出现
      "点击『数控车床CNC宝典』14 次"，读起来像在点标题，实际点的是返回箭头
      和客服/会员图标。图标的名字本来就该由 id 表达（`id:ivKefu`），
      硬给它安一个别人的文字，比留空更糟。
    """
    own = (node.text or "").strip() or (node.content_desc or "").strip()
    if own:
        return own
    cls = (node.cls or "")
    if "ImageView" in cls or "ImageButton" in cls:
        return ""            # 图标不继承同行文字（见上）
    return (getattr(node, "sub_text", "") or "").strip()


# ---- 返回控件识别（2026-11-10 CNC宝典）--------------------------------
# 真机实测：标题栏左侧那个返回箭头，结构树身份是 `id:iv_back` / `id:ivBack` /
# `id:imgBtnBack` / `id:btn_main_left`，而它的 label 往往继承成**应用名**
# （「数控车床CNC宝典」）。调度器把它当普通入口，一轮点了 24 次 ——
# 每次都是"回到上一级"，等于花 9 秒做一次 BACK 键本来就白做的事，
# 而且让报告写"点击『数控车床CNC宝典』14 次"，读起来像在点标题。
#
# 判据只认"准的"，宁可漏也不误杀：把 id 归一成纯字母后，
#   · 以 back 结尾且前缀是图标类词（iv/img/btn/icon/nav/…）→ 返回键
#   · 少数固定写法（btnmainleft / ivback / imgbtnback）
#   · 文字或 content-desc 明确写「返回 / 上一级 / 转到上一层级」
# ★ 不能用"包含 back"：`btFeedback`（意见反馈）归一后是 `btfeedback`，
#   包含了 back 三个字母 —— 那是 App 里真实存在的功能入口，误杀就少测一项。
_BACK_WORDS = ("返回", "上一级", "上一页", "转到上一层级", "回退", "返回上一页")
_BACK_PREFIX = ("", "iv", "img", "icon", "btn", "button", "nav", "toolbar",
                "top", "title", "go", "main", "left", "imgbtn", "ivbtn", "tl")
_BACK_FIXED = ("btnmainleft", "ivback", "imgbtnback", "btnback", "navback",
               "topback", "titleback", "iconback")


def _norm_id(sid: str) -> str:
    return re.sub(r"[^a-z]", "", (sid or "").lower())


def is_back_control(node: Any) -> bool:
    """这个元素是不是"返回上一级"控件（点它等价于按 BACK，不该算探索入口）。"""
    sid = _short_id(getattr(node, "resource_id", "") or "")
    n = _norm_id(sid)
    if n:
        if n in _BACK_FIXED:
            return True
        if n.endswith("back") and n[:-4] in _BACK_PREFIX:
            return True
    txt = ((getattr(node, "text", "") or "").strip()
           or (getattr(node, "content_desc", "") or "").strip())
    if txt and any(w in txt for w in _BACK_WORDS):
        return True
    return False


def node_uid(node: uiwalk.UiNode, peers: Sequence[uiwalk.UiNode] = ()) -> str:
    """元素身份（跨屏可比、滚动稳定）。

    优先级与理由：

      1. `resource-id` —— 最稳。保留尾部数字，列表第 3 行与第 4 行是不同元素。
      2. `文字 / content-desc`（合并成 label）—— 图标按钮常只有后一个。
      3. `class + 同屏序号` —— 连标签都没有的容器（真机上确实存在，遍历器
         有时就在点这些 `LinearLayout`，这本身是"覆盖差"的证据）。

    ★ 位置**不进** uid：网格法在长列表滚动时会跨格，同一个元素换了 uid
      就被当成新元素重复点击。改用"同屏同标签的第几个"（按位置排序），
      滚动不改变同屏相对次序，比网格稳。
    """
    sid = _short_id(node.resource_id)
    if sid:
        base = "id:" + sid
        # ★ 同屏多个节点共用同一个 id 时必须消歧（2026-11-10 CNC宝典）：
        #   底部导航四个 tab 的 resource-id 全是 `layoutRoot`，
        #   原来这里直接 return "id:layoutRoot"，四个 tab 在调度器眼里
        #   是**同一个元素** —— 点了「首页」，其余三个立刻被判成"已去过"，
        #   「先把底栏铺一遍」这条策略根本没有执行机会。
        #   真机实测该 App：首页/数控/视频/我的 四个 tab 全部 270px 等分，
        #   text 与 content-desc 都是空，只有 id 能用，所以只能靠同屏序号区分。
        if not peers:
            return base
        same = [p for p in peers
                if _short_id(p.resource_id) == sid]
        if len(same) <= 1:
            return base
        same = sorted(same, key=lambda p: (p.bounds[1], p.bounds[0]))
        return "%s#%d" % (base, _index_in(same, node))
    lab = _label_of(node)
    cls = (node.cls or "").split(".")[-1]
    base = ("lb:" + lab[:40]) if lab else ("cl:" + cls)
    if not peers:
        return base
    same = [p for p in peers if _label_of(p) == lab and (p.cls or "").split(".")[-1] == cls]
    if len(same) <= 1:
        return base
    same = sorted(same, key=lambda p: (p.bounds[1], p.bounds[0]))
    return "%s#%d" % (base, _index_in(same, node))


def _index_in(peers: Sequence[uiwalk.UiNode], node: uiwalk.UiNode) -> int:
    """`node` 在 `peers` 里的次序。

    ★ 不能只用 `id()`：`observe()` 内部会重新 `parse_all(xml)`，而调用方
      （collector）手里的节点来自**另一次**解析 —— 两个 UiNode 是不同对象，
      `id()` 永远对不上，同屏同名元素就全部退化成 `#0`，互相覆盖成同一个身份。
      真机上列表页里多个「更多」会因此被当成同一个，点一个就把它们全标记为已点。

      所以先按对象身份找（同一批次时最快），再按 **bounds** 找（跨批次可用，
      同一屏的同一元素坐标必然一致），都找不到才退回 0。
    """
    for i, p in enumerate(peers):
        if p is node:
            return i
    b = tuple(getattr(node, "bounds", ()) or ())
    if b:
        for i, p in enumerate(peers):
            if tuple(p.bounds) == b:
                return i
    return 0


# --------------------------------------------------------------------- 数据

def _is_system(activity: str, package: str, xml_pkg: str = "") -> bool:
    """判断这一屏是不是系统界面（权限弹窗、系统设置）而不是被测 App。

    判据优先级（**保守优先**）：

      1. `xml_pkg`：结构树里节点自带的 package 属性 —— 它反映此刻真正在画这一屏
         的进程，是唯一可靠的来源。权限弹窗这里是 `com.android.permissioncontroller`。
      2. Activity 名里出现 `GrantPermissionsActivity` —— 各版本 Android 的系统
         权限控制器都用这个类名，是很窄的一条白名单。
      3. 其余一律判为**被测 App 的界面**。

    ★ 为什么默认判成 App 界面：两个方向的错代价不对等。把 App 界面误判成系统界面，
      会让覆盖率的分子分母一起变小，报告读起来"已经走遍了"，属于**偏乐观的假象**；
      把系统弹窗误判成 App 界面，只是未探索入口数虚高几项，不误导结论。
      所以拿不准时一律算 App 界面。
    """
    if not package:
        return False
    if xml_pkg:
        return package not in xml_pkg
    return "GrantPermissionsActivity" in (activity or "")


def _is_opaque(label: str) -> bool:
    """标签是不是"说了等于没说"（裸类名 / 空）。

    真机实测：未探索入口的样例列出来是 `FrameLayout、LinearLayout、View`——
    那是结构树里没有文字的可点容器（自绘界面、引导页蒙层、卡片外框）。
    这种入口本身是**证据的一部分**（说明这一屏的结构树质量差、点它也不知道会去哪），
    但直接把类名印进报告的"示例"列，复核员读不出任何东西。
    """
    lab = (label or "").strip()
    if not lab:
        return True
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,24}", lab))


def _readable_label(label: str, uid: str = "") -> str:
    """把 uid/裸类名换成可读的说明。"""
    lab = (label or "").strip()
    if not _is_opaque(lab):
        return lab[:40]
    if not lab:
        lab = (uid or "").split(":", 1)[-1]
    return "无文字可点容器"


@dataclass
class State:
    """一个界面（由结构指纹标识）。"""

    fp: str
    activity: str = ""
    first_ts: float = 0.0
    last_ts: float = 0.0
    visits: int = 0
    clickable: int = 0
    texts: int = 0
    tab_sig: str = ""
    list_children: int = 0
    # 这一屏是不是"列表页"（最大可滚动容器里有 ≥4 个可点行）。
    # ★ 与 `list_children` 分开存一个布尔：报告里要按"列表界面 N 个"统计，
    #   而下拉加载的判据也要用它，两处各算一遍迟早不一致。
    list_like: bool = False
    # 已加载的页数 / 上拉尝试次数。有些 App 列表必须"拉到顶再拉一下"才加载下一页，
    # 光靠 scroll + 指纹不变 会把它判成"到底了"，整页后面的行全都不点。
    pages: int = 0
    pulls: int = 0
    # uid → 元素标签。报告要能回答"还有哪些入口没点"，只有 uid 是读不出来的。
    labels: Dict[str, str] = field(default_factory=dict)
    uids_seen: Set[str] = field(default_factory=set)
    uids_clicked: Set[str] = field(default_factory=set)
    dead: Set[str] = field(default_factory=set)      # 点了没反应的
    # 结构上可点、但**不许点**的入口（不同意 / 注销账号 / 退出登录 / 拒绝…）。
    # ★ 必须与 `uids_seen` 分开：把它们算进"未探索入口"，覆盖率分母会虚高一大截，
    #   报告读起来像"还有一堆没测"，其实那些入口本来就不该点。
    blocked: Set[str] = field(default_factory=set)
    # 点了没有采集价值的控件（输入框 / 图形验证码）。**既不点、也不算未探索**：
    # 它们既不是"该去没去"，也不是"不许点"，混进任何一个集合都会让报告口径失真。
    ignored: Set[str] = field(default_factory=set)
    # 本屏是否已滚到底（连续两次滚动后界面没变）。
    scroll_exhausted: bool = False
    parent_fp: str = ""                              # 第一次进入时的来源界面
    enter_uid: str = ""                              # 从哪个元素进来的
    depth: int = 0
    # 是否为**系统界面**（权限弹窗、系统设置页）而不是被测 App 的界面。
    # ★ 必须分开统计：真机实测（赣警办）一轮 10 个状态里有 3 个是
    #   `…permission.ui.GrantPermissionsActivity`，把它们算进"未探索入口"，
    #   会让覆盖率分母虚高 30 多，结论就成了"还有很多没测"——而那是系统弹窗，
    #   本来就不该去遍历。
    system: bool = False
    # 这一屏结构树自报的进程包名。系统弹窗覆盖在 App 界面上时，activity 缓存
    # 还是 App 的（显示成 MainActivity），只有这个字段能说明"屏幕上是系统弹窗"。
    screen_pkg: str = ""
    # 这一屏是不是弹窗（对话框/浮层）。★ 弹窗不算"深入一层"：它是当前界面上的
    # 临时层，关掉之后还回原界面。把它压栈会让深度虚高 —— 真机实测：注册页与它的
    # 「确定」对话框被算成两层，深度冲到 6 而 App 界面只有 9 个，DFS 还在两者间来回。
    is_dialog: bool = False
    # ---- 内容型页面（资讯/文章/视频/商品）----
    # ★ 与 `blocked` / `ignored` 刻意分开：这些条目**不是不该点**，也不是"点了没用"，
    #   而是**同模板重复**——看一条就等于看了全部（详见 flow/content.py 的模块注释）。
    #   单列一批 uid 而不是直接从 `uids_seen` 里摘掉，是为了报告能同时说清
    #   "还有 N 个没点，其中 M 个是同模板内容条目"——少报比多报更糟。
    content: bool = False
    content_items: Set[str] = field(default_factory=set)   # 可按同构跳过的条目
    content_sample: str = ""                              # 保留抽样的一条
    content_reason: str = ""                              # 判定的理由（中文）
    # 命中的站外内容平台域名（mp.weixin.qq.com 等）。这是**最高精度**的一条证据：
    # 只有它成立时才允许"回头把父界面的同模板条目也标掉"—— 否则「关于我们」
    # 打开的公司介绍页会把整个设置页误标成内容（那是灾难性的漏测）。
    content_host: str = ""

    @property
    def todo(self) -> Set[str]:
        return self.uids_seen - self.uids_clicked

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fp": self.fp,
            "activity": self.activity,
            "screen_pkg": self.screen_pkg,
            "visits": self.visits,
            "clickable": self.clickable,
            "texts": self.texts,
            "tab": self.tab_sig,
            "list_children": self.list_children,
            "list_like": self.list_like,
            "pages": self.pages,
            "pulls": self.pulls,
            "parent": self.parent_fp,
            "enter_uid": self.enter_uid,
            "depth": self.depth,
            "seen": len(self.uids_seen),
            "clicked": len(self.uids_clicked),
            "dead": sorted(self.dead)[:20],
            "blocked": len(self.blocked),
            "todo": len(self.todo),
            "scroll_exhausted": self.scroll_exhausted,
            "system": self.system,
            "content": self.content,
            "content_items": len(self.content_items),
            "content_reason": self.content_reason,
            "content_host": self.content_host,
        }


@dataclass
class Edge:
    """一次点击：从哪个界面、点了哪个元素、到了哪、结果如何。"""

    from_fp: str
    uid: str
    label: str
    to_fp: str
    kind: str          # NEW / SAME / DIALOG / LEFT / CRASH / UNKNOWN
    ts: float = 0.0
    ui_step: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"from": self.from_fp, "uid": self.uid, "label": self.label[:40],
                "to": self.to_fp, "kind": self.kind, "step": self.ui_step}


@dataclass
class Snapshot:
    """一次界面观测的结果（供调用方立刻使用，不入档）。"""

    fp: str
    activity: str
    clickable: int
    tab_sig: str
    is_dialog: bool
    nodes: List[uiwalk.UiNode] = field(default_factory=list)
    # 主导航节点（已按从左到右排好）。调度器用它来铺 tab。
    nav: List[uiwalk.UiNode] = field(default_factory=list)
    # 本屏全部可点节点。★ 排除"不能点"的两类之后仍保留在原位，
    # 让调用方与 `clickable` 的过滤口径分开，避免两处各算一套。
    clicks: List[uiwalk.UiNode] = field(default_factory=list)


class PageGraph:
    """页面图：状态 + 边 + 统计。只记录，不决策。"""

    def __init__(self, package: str = "", max_states: int = MAX_STATES,
                 max_edges: int = MAX_EDGES) -> None:
        self.package = package
        self.max_states = max_states
        self.max_edges = max_edges
        self.states: Dict[str, State] = {}
        self.order: List[str] = []
        self.edges: List[Edge] = []
        self.taps = 0
        self.repeat_taps = 0
        self.truncated = False
        self._click_count: Dict[Tuple[str, str], int] = {}
        self.current: str = ""
        # 待判定的点击上下文：点下去时记下"在哪个界面点了谁"，下一屏观测到后落账。
        self._pending_from: str = ""
        self._pending_uid: str = ""
        self._pending_label: str = ""
        self._pending_step: int = 0
        self._last_clicks: List[uiwalk.UiNode] = []
        # 主导航（tab）标签 → 它落到的界面 fp。由调度器回填：
        # 图的职责是"记账"，但"哪个界面是一级 tab 的根"这件事只有点过 tab 的人知道。
        # 报告里的「各 tab 覆盖表」就是按这些根做子树统计的。
        self.tab_roots: Dict[str, str] = {}

    # -- 观测 ---------------------------------------------------------
    def observe(self, xml: str, activity: str = "", ts: Optional[float] = None,
                ui_step: int = 0) -> Optional[Snapshot]:
        """登记一屏。返回快照；解析失败返回 None（不抛异常）。"""
        if not xml:
            return None
        fp = fingerprint(xml, activity)
        if not fp:
            return None
        nodes = uiwalk.parse_all(xml)
        clicks = [n for n in nodes if n.clickable]
        _w, h = _screen_size(nodes)
        # 结构树里自带的 package：这一屏此刻真正是哪个进程在画。
        xml_pkg = next((n.package for n in nodes if n.package), "")
        now = ts if ts is not None else time.time()
        nav = nav_nodes(clicks, h)
        # 只算一次：`_list_children` 是 O(n²) 的几何包含判断，同一屏算两遍
        # 在长列表上会明显拖慢每一轮 dump（真机一屏两三百个节点）。
        lc = _list_children(nodes)
        snap = Snapshot(fp=fp, activity=activity, clickable=len(clicks),
                        # 签名必须与 `_tab_sig` 用同一套取标签的规则（无文字时退回 id），
                        # 否则只有 id 的 tab 会拼出 `||` 这种空签名，"这屏有没有导航"
                        # 就变成了"有三个空名字"，后续文案与统计全对不上。
                        tab_sig="|".join(_nav_label(n) for n in nav) if nav else "",
                        is_dialog=uiwalk.is_dialog_present(xml), nodes=nodes,
                        nav=nav, clicks=clicks)
        st = self.states.get(fp)
        if st is None:
            if len(self.states) >= self.max_states:
                self.truncated = True
                self.current = fp
                return snap
            _lc = lc
            st = State(fp=fp, activity=activity, first_ts=now, tab_sig=snap.tab_sig,
                       list_children=_lc, list_like=_lc >= LIST_MIN_CHILDREN,                       screen_pkg=xml_pkg,
                       is_dialog=snap.is_dialog,
                       system=_is_system(activity, self.package, xml_pkg))
            # 深度：从"点击前所在界面"推。没有父边（冷启动/被重拉回来）就是 0。
            prev = self.states.get(self._pending_from) if self._pending_from else None
            if prev is not None:
                st.parent_fp = prev.fp
                st.enter_uid = self._pending_uid
                st.depth = prev.depth + 1
            self.states[fp] = st
            self.order.append(fp)
        st.visits += 1
        st.last_ts = now
        # 列表页的行数会随翻页变多：只增不减，避免"加载更多后又变回 0 行"导致判据翻转。
        st.list_children = max(st.list_children, lc)
        st.list_like = st.list_like or st.list_children >= LIST_MIN_CHILDREN
        st.clickable = len(clicks)
        st.texts = len(nodes)
        # 新建状态时 activity 可能还没取到（缓存为空）。后续补上，且**只补不改**：
        # activity 参与指纹计算，事后修改会让同一界面算出第二个 fp。
        if not st.system and xml_pkg and self.package and self.package not in xml_pkg:
            st.system = True          # 结构树自己说了它不是被测 App，纠正安全（不动 fp）
        if not st.activity and activity:
            st.activity = activity
        if not st.screen_pkg and xml_pkg:
            st.screen_pkg = xml_pkg
        # 本屏出现的所有可点元素都算"已知入口"，未点过的自然成为 todo。
        # ★ 危险入口单独记：它们永远不会被点，若混进 todo 会让"未探索入口"
        #   永久虚高（真机一轮就有十几个"不同意/取消"）。
        for n in clicks:
            u = node_uid(n, clicks)
            # 标签要留下：报告里「还有哪些入口没点」只能靠它来读；
            # 只存 uid（`id:btn_12`）复核员看不出这是"设置"还是"广告位"。
            # 上限 400 条/屏：异常 App 可能一屏上千个可点节点，这里不能无界增长。
            if u not in st.labels and len(st.labels) < 400:
                st.labels[u] = (n.label or "")[:40]
            # 危险入口（不同意/注销账号）与"点了没用"的控件（输入框/图形验证码）
            # 都不进 todo：它们永远不会被点，混进去会让"未探索入口"永久虚高。
            # ★ 但两者要**分开记**：报告里「被安全规则挡住的入口」一栏
            #   只应出现注销/退出这类"该看见、不许点"的，不能混进"请输入密码"
            #   和「取消」——真机实测那样一列里全是输入框，复核员读不出任何结论。
            if uiwalk.is_dangerous(n):
                st.blocked.add(u)
            elif uiwalk.is_no_use(n):
                st.ignored.add(u)
            else:
                st.uids_seen.add(u)
        # ---- 内容型页面判别（2026-11-03）----
        # 这里只**标注**，不在观测层决定点不点：点不点由调度器按预算与阶段决定。
        # 危险入口与"点了没用"的控件先摘掉 —— 它们本来就不进候选，混进同模板分组
        # 会让"条目数"虚高，也可能把设置页的输入框当成一条内容。
        try:
            _clicks_for_kind = [n for n in clicks
                                if not uiwalk.is_dangerous(n)
                                and not uiwalk.is_no_use(n)]
            _v = content.classify(
                activity=activity or st.activity,
                clicks=_clicks_for_kind,
                texts=[n.text for n in nodes if n.text],
                screen_h=h)
        except Exception:
            _v = None
        if _v is not None and _v.kind == "content":
            st.content = True
            st.content_reason = _v.reason
            st.content_host = _v.host or st.content_host
            _sample = node_uid(_v.sample, clicks) if _v.sample is not None else ""
            st.content_sample = _sample
            for _it in _v.items:
                _u = node_uid(_it, clicks)
                if _u and _u != _sample:
                    st.content_items.add(_u)
        self._last_clicks = clicks
        self.current = fp
        return snap

    def uid_for(self, node: Any) -> str:
        """按最近一次观测到的同屏元素算 uid（保证"点击"与"登记"用同一套身份）。"""
        return node_uid(node, self._last_clicks)

    def mark_tab_root(self, label: str, fp: str) -> None:
        """登记「这个 tab 通到哪个界面」。同标签只认第一次落点（tab 根固定不变）。"""
        if label and fp and label not in self.tab_roots:
            self.tab_roots[label] = fp

    # -- 记账 ---------------------------------------------------------
    def mark_tap(self, fp: str, uid: str, label: str = "", ui_step: int = 0) -> None:
        """点击发生时登记"待判定"的上下文（落点要等下一屏才知道）。"""
        self._pending_from = fp or ""
        self._pending_uid = uid or ""
        self.taps += 1
        k = (self._pending_from, self._pending_uid)
        n = self._click_count.get(k, 0) + 1
        self._click_count[k] = n
        if n > 1:
            # 重复 = 同一个界面上的同一个元素被点了第二次及以上。
            # 统计口径按"重复发生的次数"而不是"重复的元素个数"，
            # 因为要衡量的是**被浪费的点击预算**有多少。
            self.repeat_taps += 1
        st = self.states.get(self._pending_from)
        if st is not None and self._pending_uid:
            st.uids_clicked.add(self._pending_uid)
        self._pending_label = (label or "")[:40]
        self._pending_step = ui_step

    def resolve_tap(self, to_fp: str, kind: str, ts: Optional[float] = None) -> None:
        """下一屏观测到后落账：这次点击到了哪、结果是什么。"""
        if not self._pending_from:
            return
        src = self.states.get(self._pending_from)
        if src is not None and kind == "SAME" and self._pending_uid:
            src.dead.add(self._pending_uid)
        if len(self.edges) < self.max_edges:
            self.edges.append(Edge(from_fp=self._pending_from, uid=self._pending_uid,
                                   label=getattr(self, "_pending_label", ""),
                                   to_fp=to_fp or "", kind=kind,
                                   ts=ts if ts is not None else time.time(),
                                   ui_step=getattr(self, "_pending_step", 0)))
        elif not self.truncated:
            self.truncated = True
        self._pending_from = ""
        self._pending_uid = ""

    @property
    def has_pending(self) -> bool:
        return bool(self._pending_from)

    def resolve(self, to_fp: str, *, alive: bool = True, foreign: bool = False,
                is_dialog: bool = False) -> str:
        """结算上一次点击：判定落点并落账，返回落点类型。

        调用方只需把"下一屏"的事实交给它（进程是否还在、是否跑到别的 App、
        新界面是不是弹窗），判定规则集中在 `judge_tap`，不在调用处各写一遍。
        """
        prev = self._pending_from
        kind = judge_tap(prev, to_fp, alive=alive, foreign=foreign, is_dialog=is_dialog)
        if prev:
            self.resolve_tap(to_fp, kind)
        return kind

    # -- 统计 ---------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        states = list(self.states.values())
        app_states = [s for s in states if not s.system]
        sys_states = [s for s in states if s.system]
        max_depth = max([s.depth for s in states] or [0])
        kinds: Dict[str, int] = {}
        for e in self.edges:
            kinds[e.kind] = kinds.get(e.kind, 0) + 1
        # 「已探索入口 / (已探索 + 未探索)」—— 衡量"测完了没有"要用这个比例，
        # 不能用未探索的绝对值：走到的界面越多，发现的入口就越多，
        # 绝对值反而会上升（Step 2 真机就是这样：界面 8→12，未探索 69→102）。
        explored = sum(len(s.uids_clicked) for s in app_states)
        todo_app = sum(len(s.todo) for s in app_states)
        return {
            "states": len(states),
            "app_states": len(app_states),
            "system_states": len(sys_states),
            "edges": len(self.edges),
            "visits": sum(s.visits for s in states),
            "max_depth": max_depth,
            "taps": self.taps,
            "repeat_taps": self.repeat_taps,
            "repeat_rate": (round(self.repeat_taps / float(self.taps), 3)
                            if self.taps else 0.0),
            "dead": sum(len(s.dead) for s in states),
            # 结构上可点、但按合规要求不许点掉的入口（不同意 / 注销账号 / 退出登录…）。
            # 单列出来，让"未探索入口"只反映"该去但没去"的部分。
            "blocked": sum(len(s.blocked) for s in states),
            # 「未探索入口」只算**被测 App 的界面**：系统权限弹窗上的按钮
            # 本来就不该去遍历，混进来会让覆盖率分母虚高。
            "unexplored": todo_app,
            "unexplored_system": sum(len(s.todo) for s in sys_states),
            "explored": explored,
            "explore_ratio": (round(explored / float(explored + todo_app), 3)
                              if (explored + todo_app) else 0.0),
            "nav_states": sum(1 for s in app_states if s.tab_sig),
            "scroll_exhausted": sum(1 for s in app_states if s.scroll_exhausted),
            "list_states": sum(1 for s in app_states if s.list_like),
            # 内容型列表（资讯/文章/视频/商品）：条目按同模板抽样，只展开一条。
            # 与 `list_states` 并列而不合并：一个是"结构像列表"，一个是"列表里
            # 装的是站外内容"，报告要分开说（前者照样逐条点，后者按同构跳过）。
            "content_states": sum(1 for s in app_states if s.content),
            "content_items": sum(len(s.content_items) for s in app_states),
            "pages_loaded": sum(s.pages for s in app_states),
            "dialogs": kinds.get("DIALOG", 0),
            "edge_kinds": kinds,
            "truncated": self.truncated,
        }

    def summary_line(self) -> str:
        s = self.stats()
        tail = ""
        if s["system_states"]:
            tail = "（另有 %d 个系统界面未计入）" % s["system_states"]
        lists = ""
        if s["list_states"]:
            lists = "｜ 列表界面 %d 个（已加载 %d 页）" % (s["list_states"],
                                                         s["pages_loaded"])
        return ("页面图：App 界面 %d 个%s / 边 %d 条 / 最大深度 %d ｜ 点击 %d 次，"
                "其中重复 %d 次（%.0f%%）｜ 死点 %d 个 ｜ 未探索入口 %d 个"
                "（入口已探索 %d/%d，%.0f%%）%s"
                % (s["app_states"], tail, s["edges"], s["max_depth"], s["taps"],
                   s["repeat_taps"], s["repeat_rate"] * 100,
                   s["dead"], s["unexplored"], s["explored"],
                   s["explored"] + s["unexplored"], s["explore_ratio"] * 100, lists))

    def top_states(self, n: int = 8) -> List[Dict[str, Any]]:
        """访问最多的几个界面（用于日志里快速看出遍历卡在哪）。"""
        out = sorted(self.states.values(), key=lambda s: (-s.visits, s.depth))
        rows = []
        for s in out[:n]:
            # 系统弹窗盖在 App 界面上时，activity 是 App 的（显示成 MainActivity），
            # 会造成"这是 App 自己在索权"的误读 —— 用结构树自报的包名更正它。
            name = s.activity or s.fp
            if s.system and s.screen_pkg and s.screen_pkg not in name:
                name = s.screen_pkg
            rows.append({"fp": s.fp, "activity": name[-44:], "visits": s.visits,
                         "depth": s.depth, "clicked": len(s.uids_clicked),
                         "todo": len(s.todo), "tab": s.tab_sig[:24],
                         "system": s.system})
        return rows

    def _name_of(self, st: State) -> str:
        """界面的可读名字。系统弹窗盖在 App 上时 activity 是 App 的，用自报包名更正。"""
        name = st.activity or st.fp
        if st.system and st.screen_pkg and st.screen_pkg not in name:
            name = st.screen_pkg
        # 只留最后两段：`com.oceansoft.jxpolice/.ui.MainActivity` → `ui.MainActivity`。
        # 报告里一整列全限定名会撑爆表格宽度，而区分度全在尾部。
        parts = [p for p in name.replace("/", ".").split(".") if p]
        return ".".join(parts[-2:]) if len(parts) > 2 else name

    def _subtree(self, root_fp: str) -> List[State]:
        """以某个界面为根的子树（含根）。按 parent_fp 链展开。

        `parent_fp` 记的是"第一次进入时的来源界面"，所以同一界面被两个地方
        指过来时只会挂在一个父下 —— 会少算，不会重复算。覆盖率报告宁可少报
        （说"这个 tab 只有 3 个界面"）也不能重复计数（说"深度 9"其实是全 App 的深度）。
        """
        kids: Dict[str, List[State]] = {}
        for s in self.states.values():
            if s.parent_fp:
                kids.setdefault(s.parent_fp, []).append(s)
        out: List[State] = []
        seen: Set[str] = set()
        stack = [root_fp]
        while stack:
            f = stack.pop()
            if f in seen:
                continue
            seen.add(f)
            st = self.states.get(f)
            if st is None:
                continue
            out.append(st)
            stack.extend(k.fp for k in kids.get(f, []))
        return out

    def coverage_detail(self) -> Dict[str, Any]:
        """覆盖明细（进报告「界面覆盖情况」章节）。

        ★ 这一节的用途只有一个：让复核员看出**结论覆盖了哪些界面、还漏了什么**。
          所以这里给的是"分母"和"缺口"，不是又一份漂亮的总数 ——
          「界面记录 25 个」回答不了"设置页走到底了吗"。
        """
        s = self.stats()
        app = [x for x in self.states.values() if not x.system]

        tabs = []
        for label, fp in sorted(self.tab_roots.items()):
            sub = self._subtree(fp) if fp else []
            base = self.states[fp].depth if fp in self.states else 0
            tabs.append({
                "tab": label[:12],
                "states": len(sub),
                "depth": max([x.depth - base for x in sub] or [0]),
                "clicked": sum(len(x.uids_clicked) for x in sub),
                "todo": sum(len(x.todo) for x in sub),
            })

        dead_points = []
        for x in app:
            for u in sorted(x.dead):
                dead_points.append({"activity": self._name_of(x),
                                    "label": _readable_label(x.labels.get(u) or "", u)[:26]})
        # 被规则挡住、但**应该出现在报告里**的入口：注销/退出/删除账号这类
        # 我们永不点击的按钮。它们不进"未探索"（不该点），但"找没找到注销入口"
        # 恰恰是合规结论要回答的事实，所以要单独列出来。
        blocked_points = []
        for x in app:
            for u in sorted(x.blocked):
                blocked_points.append({"activity": self._name_of(x),
                                       "label": _readable_label(x.labels.get(u) or "", u)[:26]})

        gaps = []
        for x in sorted(app, key=lambda y: -len(y.todo))[:6]:
            # 内容条目不算"缺口"：它们不是"该去没去"，而是同模板重复（看一条即全部）。
            # ★ 只在**举例**这一层剔掉，`count` 仍然如实给出功能入口的条数，
            #   内容条目另用 `content` 字段标出来 —— 少报比多报更糟。
            _func_todo = [u for u in x.todo if u not in x.content_items]
            if not _func_todo:
                continue
            ex: List[str] = []
            for u in sorted(_func_todo):
                lab = _readable_label(x.labels.get(u) or "", u)
                if lab not in ex:          # 同一屏一堆"无文字可点容器"只留一条
                    ex.append(lab)
                if len(ex) >= 5:
                    break
            gaps.append({"activity": self._name_of(x), "count": len(_func_todo),
                         "examples": ex,
                         "content": len(x.todo) - len(_func_todo)})

        # 「未探索入口」里有多少是**无文字可点容器**：这类入口既点不出结论、
        # 也不代表用户可见的功能，但会把分母撑大。单列出来，复核员才不会被
        # 「还有 105 个入口没点」吓到 —— 真机上其中大半是这种容器。
        opaque = 0
        for x in app:
            for u in x.todo:
                if u in x.content_items:
                    continue               # 内容条目单独统计，不重复计入
                if _is_opaque(x.labels.get(u) or ""):
                    opaque += 1
        # 内容型列表的明细：报告要能回答"这几十个没点的入口是什么"。
        content_todo = sum(1 for x in app for u in x.todo if u in x.content_items)
        content_lists = [{"activity": self._name_of(x), "reason": x.content_reason,
                          "skipped": len(x.content_items & x.todo),
                          "total": len(x.content_items) + (1 if x.content_sample else 0)}
                         for x in app if x.content][:8]

        deepest = [{"activity": self._name_of(x), "depth": x.depth}
                   for x in sorted(app, key=lambda y: -y.depth)[:5] if x.depth]

        return {
            "explored": s["explored"],
            "unexplored": s["unexplored"],
            "explore_ratio": s["explore_ratio"],
            "blocked": s["blocked"],
            "unexplored_opaque": opaque,
            "dead": s["dead"],
            "dialogs": s["dialogs"],
            "list_states": s["list_states"],
            "pages_loaded": s["pages_loaded"],
            # 内容型列表（资讯/文章/商品）：这些没点的入口**不是漏测**，
            # 而是同模板重复 —— 报告必须把这两笔数分开写，否则复核员会把
            # "还有 200 个入口没点"读成"测得很浅"。
            "content_states": s["content_states"],
            "unexplored_content": content_todo,
            "content_lists": content_lists,
            "system_states": s["system_states"],
            "max_depth": s["max_depth"],
            "tabs": tabs,
            "dead_points": dead_points[:12],
            "blocked_points": blocked_points[:16],
            "gaps": gaps,
            "deepest": deepest,
            "truncated": self.truncated,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.stats(),
            "tab_roots": dict(self.tab_roots),
            "states": [s.to_dict() for s in self.states.values()],
            "order": self.order[:self.max_states],
            "edges": [e.to_dict() for e in self.edges],
        }


# --------------------------------------------------------------------- 落点

def judge_tap(prev_fp: str, to_fp: str, *, alive: bool = True,
              foreign: bool = False, is_dialog: bool = False) -> str:
    """判定一次点击的落点。

    顺序很重要：进程没了 → 崩溃；跑到别的 App → 离开；否则看界面变没变。
    """
    if not alive:
        return "CRASH"
    if foreign:
        return "LEFT"
    if not to_fp:
        return "UNKNOWN"
    if to_fp == prev_fp:
        return "SAME"
    if is_dialog:
        return "DIALOG"
    return "NEW"


# --------------------------------------------------------------------- 开关

def enabled(cfg: Any) -> bool:
    """观测开关（`scan.crawl_observe`，缺省开）。

    留开关的理由：观测本身极轻（每屏多一次 XML 解析），但**任何**新增代码都有
    风险；出问题时应当能在不改代码的前提下关掉，而不是回滚版本。
    """
    try:
        return bool(getattr(getattr(cfg, "scan", cfg), "crawl_observe", True))
    except Exception:
        return True
