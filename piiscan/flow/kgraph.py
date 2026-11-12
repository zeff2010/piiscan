"""App 知识图谱：把「走到过哪里」变成「下一步该去哪」的可查询知识。

## 为什么要这一层

`graph.PageGraph` 记的是**事实**（哪一屏、点了谁、落到哪），报告读它算覆盖率。
但遍历决策读不到它：`collector` 里的 AI 每一步拿到的是「当前可点元素全量 +
最近 14 条操作文字 + 一句按时间派生的阶段目标」，等于**每一步都从零规划整条路径**。

这正是 UI-KOBE（arXiv 2605.29534）指出的失效模式：轻量模型单独靠截图做长时程
规划不可靠，而把"应用知识"外化成一张图、让模型只在**当前节点的有限动作集**里
做选择，同一个 4B 模型在 AndroidWorld 上的成功率从 58.6 提到 70.7。
AutoDroid（MobiCom'24）走的是同一条路：离线探索产出 UTG，再用它合成一张
「模拟任务 → 状态 → 元素」的 App Memory 表，在线时把表注入提示词。

本地这套工具做的是**合规检测**而不是"完成任务"，所以照搬会有两处必须改：

  · 目标不是某个任务，而是「9 类权利入口 + 触发收集行为」→ 图的查询要按
    **目标可达性**加权，而不是按"任务是否需要"；
  · 交付物是报告，所以图不只是给模型的素材，还要能直接回答复核员的
    「凭什么说没找到注销入口」→ 图要能导出成表（`to_report()`）。

## 与 PageGraph 的关系

**不重复记账**。本模块是 PageGraph 的只读视图 + 三样新东西：

  1. **语义层**：节点角色（首页/列表/设置/账号/表单…）与一句话描述。
     UI-KOBE 用页面描述的 embedding 做节点识别；这里没有 embedding 模型
     （本地 ollama 只有对话模型，未部署 embed），改用
     「规则判定 + AI 决策时顺手命名」，见 `note_desc()` 的说明。
  2. **节点合并**：同一界面因列表滚动、未读数变化而分裂出的多个结构指纹，
     合并成一个语义节点（UI-KOBE 的 graph auditing）。合并**刻意保守** ——
     误合并会让覆盖率虚高（把"没走遍"说成"走遍了"），比不合并更糟。
  3. **图上的查询**：从前沿（还有未探索动作的最近节点）、到目标的已知路径、
     当前节点的局部动作集。这三样是喂给模型的"局部选择器"。

## 代价模型

边权不是 1，因为"同屏动作"和"跨屏动作"的成本差一个数量级：

    self-loop（开关/勾选）  0.3   不用导航过去，点完还在原屏
    普通跳转              1.0
    返回                 1.2   有退出 App 的风险，真机上已实测过
    陷阱边（崩溃/离开）      ∞     永不使用

路径规划用 Dijkstra（图规模 ≤600 节点 / 2000 边，每次重算都够快）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .. import uiwalk
from . import crawl

# ---------------------------------------------------------------- 角色
ROLE_HOME = "首页"
ROLE_LIST = "列表页"
ROLE_SETTINGS = "设置页"
ROLE_ACCOUNT = "账号/我的"
ROLE_FORM = "表单页"
ROLE_WEB = "网页/长文"
ROLE_DIALOG = "弹窗"
ROLE_DETAIL = "详情页"
ROLE_OTHER = "其他"

_SETTING_KW = ("设置", "隐私", "权限", "安全", "关于", "版本", "清理", "缓存")
_ACCOUNT_KW = ("账号", "账户", "我的", "个人中心", "会员", "资料", "实名", "认证")
_FORM_KW = ("登录", "注册", "验证码", "密码", "获取验证码", "手机号")
_WEB_KW = ("webview", "h5", "富文本", "协议", "政策")

# 边权（见模块注释的代价模型）
W_SELFLOOP = 0.3
W_EDGE = 1.0
W_BACK = 1.2
W_TRAP = 1e9

# 合并阈值。刻意偏高：宁可两个节点分着放，也不能把"根本不同的两屏"并成一个。
MERGE_JACCARD_LIST = 0.75      # 列表页：只比结构 id（内容本来就会变）
MERGE_JACCARD_UID = 0.70       # 普通页：结构 id
MERGE_JACCARD_LABEL = 0.50     # 普通页：还要比文字集合
# 跨组补救（activity 串台）：判据必须比组内更严。组内已经确认了 activity /
# tab / 列表 / 弹窗四项一致，跨组这四项里至少有一项不同，只能靠"结构+文字
# 几乎一模一样"来认，稍微放松就会把同结构不同功能的页（设置 / 关于我们）并掉。
MERGE_JACCARD_CROSS = 0.88
MERGE_JACCARD_CROSS_LABEL = 0.60

# 权利入口的"落点角色"：还没见过任何一个目标入口时，往这两类页面走。
# 依据是 PIPL 第 15/17/45/47 条对应的功能在 App 里的实际分布 ——
# 注销、撤回同意、更正删除、副本导出、已收集清单、权限管理、个性化推荐开关，
# 真机上几乎全部挂在「设置」或「我的/账号」下面。这是**经验判据**，
# 不是从被测 App 观测到的事实，所以报告与提示词里必须写成"方向"而不是"位置"。
ROLE_AFFINITY = (ROLE_SETTINGS, ROLE_ACCOUNT)

# 记忆表预算（字符）。★ 它和截图、候选列表挤在同一个请求里，遍历链路刻意
# 不随 num_ctx（8192）放大；超限是**静默截尾**，
# 截掉尾巴等于把最关键的"当前节点与路径"喂丢，是最危险的假阴性来源。
MEMORY_BUDGET = 900

# 动作在提示词里的编号前缀。短、稳定、模型好复述（"选 A3"）。
OID_TAP = "A"
OID_NAV = "N"
OID_SCROLL = "S"
OID_PULL = "P"
OID_BACK = "B"

_DIGITS = re.compile(r"\d+")


# ---------------------------------------------------------------- 数据结构

@dataclass
class Act:
    """节点上的一个动作（点某个元素）。"""

    uid: str
    label: str
    # explore（没点过）/ known（点过，跳到别处）/ selfloop（点过，同屏状态变）
    # / dead（点过没反应）/ trap（崩溃或跳到别的 App）/ danger（不许点）
    kind: str = "explore"
    to_nid: str = ""
    tries: int = 0
    # 命中的定向目标名（空 = 不是权利入口）
    targets: List[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        """这个动作能不能作为候选项（探索 / 回访 / 自环）。"""
        return self.kind in ("explore", "known", "selfloop")


@dataclass
class Node:
    """一个语义界面。同一语义可能对应多个结构指纹（合并后的 `fps`）。"""

    nid: str
    role: str = ROLE_OTHER
    desc: str = ""
    activity: str = ""
    depth: int = 0
    visits: int = 0
    list_like: bool = False
    is_dialog: bool = False
    tab_sig: str = ""
    # 这个节点上出现过的全部动作（uid → Act）
    acts: Dict[str, Act] = field(default_factory=dict)
    fps: Set[str] = field(default_factory=set)
    # 首次到达它的入边（起点 nid, 动作 label），用于"我是怎么到这的"
    parent_nid: str = ""
    enter_label: str = ""
    # 是否被 AI 命名过（规则角色一旦被 AI 纠正，不再覆盖）
    named: bool = False

    # -- 视图 --------------------------------------------------------
    @property
    def todo(self) -> List[Act]:
        return [a for a in self.acts.values() if a.kind == "explore"]

    @property
    def dead(self) -> List[Act]:
        return [a for a in self.acts.values() if a.kind == "dead"]

    @property
    def traps(self) -> List[Act]:
        return [a for a in self.acts.values() if a.kind == "trap"]

    def title(self) -> str:
        """提示词与报告里的短名字：`N7 设置页·设置`（40 字内）。"""
        tail = (self.desc or "").strip()
        if tail:
            return "%s %s·%s" % (self.nid, self.role, tail[:18])
        return "%s %s" % (self.nid, self.role)


@dataclass
class Option:
    """给模型的一个局部选项。`oid` 就是提示词里的编号。"""

    oid: str
    action: str            # tap / back / scroll / pull
    label: str = ""
    uid: str = ""
    node: Any = None       # uiwalk.UiNode（tap 用）
    to_nid: str = ""
    # 0 = 命中尚未找到的权利入口；1 = 通向北价值的设置类页面；
    # 2 = 普通未探索；3 = 已知边回访；4 = 自环（开关类）；5 = 低价值运营位
    score: int = 3
    why: str = ""

    def line(self) -> str:
        """提示词里的一行（控制长度：遍历 prompt 的文字预算有硬顶，见 tasks.py）。"""
        lab = ("「%s」" % self.label[:20]) if self.label else ""
        extra = ("→ %s" % self.to_nid) if self.to_nid else ""
        # 动作名与理由重复时只印一次（"下滑（下滑）"这种会白占预算）
        why = "" if (self.why or "") == _act_cn(self.action) else (self.why or "")
        tail = ("（%s）" % why) if why else ""
        return "%s %s%s%s%s" % (self.oid, _act_cn(self.action), lab, extra, tail)


def _act_cn(action: str) -> str:
    return {"tap": "点", "back": "返回", "scroll": "下滑",
            "pull": "上拉加载", "wait": "等待"}.get(action, action)


# ---------------------------------------------------------------- 工具

def _norm_uid(uid: str) -> str:
    """uid 归一化：`id:list_item_3` → `id:list_item_#`。

    ★ 只在**比较节点结构**时用。动作身份必须保留数字（第 3 行和第 4 行是两个
      可点元素），这条与 `graph.node_uid` 的约定一致，不要混用。
    """
    return _DIGITS.sub("#", (uid or "").strip())


def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / float(len(sa | sb))


def _role_of(st: Any, labels: Sequence[str]) -> str:
    """规则判定界面角色。拿不准就返回「其他」，不硬猜。

    role 只用于两件事：提示词里让模型一眼看出"这是设置页"，
    以及选项排序时给"设置/账号"类页面加权。判错的代价是排序差一点，
    不影响任何结论，所以这里可以粗。
    """
    if getattr(st, "is_dialog", False):
        return ROLE_DIALOG
    act = (getattr(st, "activity", "") or "").lower()
    txt = " ".join(labels)
    low = txt.lower()
    if any(k in act or k in low for k in _WEB_KW):
        return ROLE_WEB
    # 首页优先判：底部 tab 里几乎一定有「我的」，按关键词判会把首页认成账号页。
    # role 只进提示词与排序，判错的代价很小，但"我站在首页"这句话本身
    # 对模型定位很重要，所以位置在最前。
    if getattr(st, "depth", 0) <= 0:
        return ROLE_HOME
    if any(k in txt for k in _SETTING_KW):
        return ROLE_SETTINGS
    if any(k in txt for k in _ACCOUNT_KW):
        return ROLE_ACCOUNT
    if any(k in txt for k in _FORM_KW):
        return ROLE_FORM
    if getattr(st, "list_like", False):
        return ROLE_LIST
    if len(getattr(st, "uids_seen", ()) or ()) <= 4:
        return ROLE_DETAIL
    return ROLE_OTHER


def _targets_of(label: str) -> List[str]:
    """入口文字命中了哪几个定向目标（9 类权利入口）。"""
    lab = (label or "").strip()
    if not lab or len(lab) > 20:
        return []
    return [name for name, kws in crawl.TARGETS if any(k in lab for k in kws)]


def _is_policy_label(label: str) -> bool:
    """是不是协议/政策类长文入口（点进去通常只是一个 WebView）。"""
    lab = (label or "").strip()
    return bool(lab) and any(k in lab for k in crawl.POLICY_LABEL)


# ---------------------------------------------------------------- 图谱

class AppKG:
    """App 知识图谱。由 `sync()` 从 PageGraph 增量重算，查询都很快。"""

    def __init__(self, package: str = "", budget: int = MEMORY_BUDGET) -> None:
        self.package = package
        self.budget = max(300, int(budget))
        self.nodes: Dict[str, Node] = {}
        self.fp2nid: Dict[str, str] = {}
        self.order: List[str] = []
        # (from_nid, oid_uid) → (to_nid, kind)
        self.edges: Dict[Tuple[str, str], Tuple[str, str, str]] = {}
        self.merges: List[Dict[str, Any]] = []
        # AI 给的界面命名，按 **fp** 存，不挂在 Node 对象上。
        # ★ 真机实测（以观书法 mbsf11）：`_rebuild()` 每次都重建 Node 对象，
        #   命名写在 node 上会在下一次 sync 时被抹回空 —— 22 个界面全都让模型
        #   命名过，图里却只剩 1 个 desc，报告一边写"AI 命名 22 个"、一边的
        #   语义表几乎是空的，自相矛盾；记忆表也因此退化成"当前在不知道哪一屏"。
        #   存在 fp 上就与重建、合并都无关：只要这个 fp 还在，命名就还在。
        self._ai_desc: Dict[str, str] = {}
        self._sig = ("", 0, 0)          # 上次同步的 (fp 数, 边数, 合并数)
        self._seq = 0
        self.sync_calls = 0

    # -- 同步 ---------------------------------------------------------
    def sync(self, pg: Any) -> None:
        """从 PageGraph 重算图。

        增量：PageGraph 的 states 数、edges 数与合并结果都没变就直接返回 ——
        遍历里每一步都会调它，全量重算虽然只几十毫秒，但一轮几百步就白烧几秒。
        """
        if pg is None:
            return
        states = getattr(pg, "states", None) or {}
        edges = getattr(pg, "edges", None) or []
        sig = (len(states), len(edges), len(self.merges))
        if sig == self._sig:
            return
        self._sig = sig
        self.sync_calls += 1
        self._rebuild(pg, states, edges)

    def _rebuild(self, pg: Any, states: Dict[str, Any],
                 edges: Sequence[Any]) -> None:
        # ① 先按"语义同构"分组，再决定合并。分组键里放 activity / tab 签名 /
        #    是否列表 / 是否弹窗 —— 这四样不同，就一定不是同一屏。
        groups: Dict[Tuple[str, str, bool, bool], List[Any]] = {}
        for fp, st in states.items():
            if getattr(st, "system", False):
                continue          # 系统弹窗不进图：不该被遍历，也不该占选项
            tab = getattr(st, "tab_sig", "") or ""
            # ★ activity 会"串台"，不能当硬分组键（以观书法 mbsf11 实测）：
            #   同一张「我的」页在存档里同时挂着 MainActivity / ZiLibMyActivity /
            #   SettingsActivity / GrantPermissionsActivity —— 后两个是权限弹窗与
            #   页面切换途中抓到的**前台 Activity**，并不是这一屏的主人。按 activity
            #   分组的结果是一屏变成 4 个节点，每个节点各有一份"未探索入口"，
            #   于是同一批入口被反复当成新入口点（实测同一屏被到访 15 次）。
            #   有底部导航条（tab_sig 非空）时，导航条本身就是这一屏的身份，
            #   activity 一律不参与分组。
            eff_act = "" if tab else (getattr(st, "activity", "") or "")
            key = (eff_act, tab,
                   bool(getattr(st, "list_like", False)),
                   bool(getattr(st, "is_dialog", False)))
            groups.setdefault(key, []).append(st)

        old_fp2nid = dict(self.fp2nid)
        self.nodes = {}
        self.fp2nid = {}
        self.order = []
        self.edges = {}
        self.merges = []
        self._seq = 0
        # 跨组补救用的代表节点池（跨组 = activity 串台被拆到不同分组）
        cross_reps: List[Tuple[Node, Any]] = []

        for key, group in groups.items():
            # 组内按首次出现时间排，最早的那个当代表节点（它的 nid 最小）
            group.sort(key=lambda s: getattr(s, "first_ts", 0.0) or 0.0)
            # 这一组要不要**只比结构、不比文字**。
            #
            # ★ 真机实测（以观书法 mbsf9）：首页被算成 3 个节点（N1/N3/N8，
            #   到访次数 1/4/7），因为推荐流、轮播、未读数让文字集合每次都不同，
            #   而结构（可点元素 id）其实一样。后果是覆盖率分母虚高 3 倍，
            #   而且 AI 每次"回到首页"都像到了一个没来过的地方，重复点同一批入口。
            #   判据：有主导航条（tab_sig 非空）、是列表页、或处于最顶层 ——
            #   这三类界面的**内容本来就会变**，文字不能当身份。
            structural_only = bool(key[1]) or key[2]
            for st in group:
                if (getattr(st, "depth", 0) or 0) <= 0:
                    structural_only = True
                    break
            reps: List[Tuple[Node, Any]] = []
            for st in group:
                uids = {_norm_uid(u) for u in (getattr(st, "uids_seen", ()) or ())}
                uids |= {_norm_uid(u) for u in (getattr(st, "uids_clicked", ()) or ())}
                labels = {lab for lab in ((getattr(st, "labels", {}) or {}).values())
                          if lab}
                hit: Optional[Node] = None
                hit_cross = False
                for node, rep_st in reps:
                    rep_uids = {_norm_uid(u) for u in
                                (getattr(rep_st, "uids_seen", ()) or ())}
                    rep_uids |= {_norm_uid(u) for u in
                                 (getattr(rep_st, "uids_clicked", ()) or ())}
                    # 深度差太多的一定是不同层级（哪怕同 activity）。
                    # 有 tab 的界面不比深度：同一张 tab 页会被从不同路径进到
                    # 深度 0/1/2（实测 我的页同屏分别是 0/1/2），深度是**爬取栈**
                    # 的深度，不是界面的层级，拿它当身份会白白拆出好几个节点。
                    if not key[1] and abs((getattr(st, "depth", 0) or 0)
                                          - (getattr(rep_st, "depth", 0) or 0)) > 1:
                        continue
                    if _jaccard(uids, rep_uids) < (MERGE_JACCARD_LIST
                                                   if structural_only
                                                   else MERGE_JACCARD_UID):
                        continue
                    # 内容会变的界面（有 tab / 列表 / 顶层）只比结构；其余还要比文字，
                    # 否则"设置"和"地址管理"这种同结构不同功能的页会被并成一个。
                    if not structural_only:
                        rep_labels = {lab for lab in
                                      ((getattr(rep_st, "labels", {}) or {}).values())
                                      if lab}
                        if _jaccard(labels, rep_labels) < MERGE_JACCARD_LABEL:
                            continue
                    hit = node
                    break
                # ---- 跨组补救：同一屏被 activity 串台拆到不同组 ----
                # ★ 以观书法 mbsf11 实测：「设置」页同一屏分别记在 MainActivity 与
                #   SettingsActivity 下（可点数 10/文字数 19 完全相同），因为抓屏时
                #   前台 Activity 是切换途中那个。这类只能靠"结构几乎一模一样
                #   + 文字几乎一模一样 + 同一个包"来认，判据必须比组内更严，
                #   否则同结构不同功能的页（设置 / 关于我们）会被误并成一个。
                if hit is None and cross_reps:
                    for node, rep_st in cross_reps:
                        if (getattr(st, "screen_pkg", "") or "") != (
                                getattr(rep_st, "screen_pkg", "") or ""):
                            continue
                        if abs((getattr(st, "depth", 0) or 0)
                               - (getattr(rep_st, "depth", 0) or 0)) > 2:
                            continue
                        rep_uids = {_norm_uid(u) for u in
                                    (getattr(rep_st, "uids_seen", ()) or ())}
                        rep_uids |= {_norm_uid(u) for u in
                                     (getattr(rep_st, "uids_clicked", ()) or ())}
                        if _jaccard(uids, rep_uids) < MERGE_JACCARD_CROSS:
                            continue
                        rep_labels = {lab for lab in
                                      ((getattr(rep_st, "labels", {}) or {}).values())
                                      if lab}
                        if _jaccard(labels, rep_labels) < MERGE_JACCARD_CROSS_LABEL:
                            continue
                        hit = node
                        hit_cross = True
                        break
                if hit is None:
                    self._seq += 1
                    nid = "N%d" % self._seq
                    node = Node(nid=nid, activity=getattr(st, "activity", "") or "",
                                depth=int(getattr(st, "depth", 0) or 0),
                                list_like=bool(getattr(st, "list_like", False)),
                                is_dialog=bool(getattr(st, "is_dialog", False)),
                                tab_sig=getattr(st, "tab_sig", "") or "")
                    node.role = _role_of(st, list(labels)[:30])
                    reps.append((node, st))
                    cross_reps.append((node, st))
                    self.nodes[nid] = node
                    self.order.append(nid)
                else:
                    node = hit
                    if node.fps:        # 只有真的合并过才留痕
                        self.merges.append({
                            "into": node.nid, "fp": st.fp,
                            "activity": getattr(st, "activity", "") or "",
                            "why": ("activity 串台（结构与文字几乎一致，只是抓屏时"
                                    "前台 Activity 不是这一屏的主人）"
                                    if hit_cross else
                                    ("结构同构（内容会变的界面，只比可点元素 id 集合）"
                                     if structural_only else
                                     "结构同构（id 集合与文字集合重合度高）")),
                        })
                node.fps.add(st.fp)
                node.visits += int(getattr(st, "visits", 1) or 1)
                node.depth = min(node.depth, int(getattr(st, "depth", 0) or 0))
                self.fp2nid[st.fp] = node.nid
                # 节点描述：首次进入时用的入口文字，后面 AI 命名会覆盖
                if not node.desc:
                    node.enter_label = (getattr(st, "labels", {}) or {}).get(
                        getattr(st, "enter_uid", ""), "") or ""
                    node.desc = node.enter_label
                node.parent_nid = self.fp2nid.get(
                    getattr(st, "parent_fp", "") or "", node.parent_nid)

        # ---- ①-b 把 AI 命名贴回去 ----
        # 上一步只给了"从哪个入口进来的"当描述，那是权宜；模型真的看过截图并
        # 命名过的界面，描述要用模型的。命名按 fp 存在 `_ai_desc` 里，这里逐个
        # 节点找自己名下（可能合并了多个 fp）的第一个命名。
        for node in self.nodes.values():
            for fp in node.fps:
                d = self._ai_desc.get(fp)
                if d:
                    node.desc = d
                    node.named = True
                    break

        # ② 节点上的动作账
        for fp, st in states.items():
            nid = self.fp2nid.get(fp)
            if not nid:
                continue
            node = self.nodes[nid]
            labels = getattr(st, "labels", {}) or {}
            seen = getattr(st, "uids_seen", ()) or ()
            clicked = getattr(st, "uids_clicked", ()) or ()
            dead = getattr(st, "dead", ()) or ()
            blocked = getattr(st, "blocked", ()) or ()
            for u in set(seen) | set(clicked) | set(dead) | set(blocked):
                lab = (labels.get(u) or "")
                act = node.acts.get(u)
                if act is None:
                    act = Act(uid=u, label=lab, targets=_targets_of(lab))
                    node.acts[u] = act
                elif not act.label and lab:
                    act.label = lab
                    act.targets = _targets_of(lab)
                # 状态优先级：danger > trap > dead > selfloop > known > explore
                if u in blocked:
                    act.kind = "danger"
                elif u in dead:
                    if act.kind not in ("danger",):
                        act.kind = "dead"

        # ③ 边
        for e in edges:
            src = self.fp2nid.get(getattr(e, "from_fp", "") or "")
            if not src:
                continue
            dst = self.fp2nid.get(getattr(e, "to_fp", "") or "")
            kind = str(getattr(e, "kind", "") or "")
            uid = getattr(e, "uid", "") or ""
            act = self.nodes[src].acts.get(uid)
            if act is None:
                act = Act(uid=uid, label=getattr(e, "label", "") or "")
                act.targets = _targets_of(act.label)
                self.nodes[src].acts[uid] = act
            act.tries += 1
            if kind == "SAME":
                # 同屏没变：可能是"点了没反应"，也可能是开关/勾选这类自环。
                # ★ 两者在合规上意义完全不同 —— 自环是**有价值**的（个性化推荐
                #   开关、权限开关），死点是纯浪费。用文字判，判错只会让一个
                #   开关少点一次，不会把死点当成果。
                act.kind = "selfloop" if _looks_toggle(act.label) else "dead"
            elif kind in ("LEFT", "CRASH"):
                act.kind = "trap"
            elif kind in ("NEW", "DIALOG"):
                act.kind = "known"
                act.to_nid = dst or ""
                if dst:
                    self.edges[(src, uid)] = (dst, kind, act.label)
            # UNKNOWN 保底保持原状态（探索 → 还是探索）

        self._drop_self_ref()

    def _drop_self_ref(self) -> None:
        """去掉"到自己的已知边"：图上没意义，但会误导路径规划（自环代价 0.3）。"""
        for (src, uid), (dst, kind, lab) in list(self.edges.items()):
            if src == dst and kind != "DIALOG":
                self.edges.pop((src, uid), None)
                act = self.nodes.get(src)
                if act is not None:
                    a = act.acts.get(uid)
                    if a is not None and a.kind == "known":
                        a.kind = "selfloop" if _looks_toggle(a.label) else "dead"

    # -- 语义命名 -----------------------------------------------------
    def note_desc(self, fp: str, desc: str, role: str = "") -> bool:
        """记下 AI 对这个界面的语义描述（零额外成本：它本来就在看这一屏）。

        ★ 为什么不在新界面出现时**单独**调一次模型命名：一轮遍历可能有几十个
          新界面，逐个命名就是几十次视觉调用（中继模式下等于几十次人工往返）。
          而 AI 决策时本来就要输出对当前屏的判断，让它顺带说一句"这是什么页"
          是零成本的。规则侧用 activity/tab/文字先兜一个 role，保证没有 AI
          时图里的语义也不为空 —— 这一层是**增强**，去掉它图仍然可用。
        """
        nid = self.fp2nid.get(fp or "")
        if not nid:
            return False
        node = self.nodes[nid]
        d = (desc or "").strip()[:40]
        if not d:
            return False
        # 已经用 AI 命名过就不再覆盖：同一节点后续的描述往往是"我在这做什么"，
        # 会把节点身份说法冲乱（"我的页面"→"正在点击设置按钮"）。
        if node.named and node.desc != d:
            return False
        # ★ 命名必须同时落到 **fp 级存档**：`_rebuild()` 会重建 Node 对象，
        #   只写在 node 上，下一次 sync 就被抹回空（mbsf11 实测 22 条命名只剩 1 条）。
        #   节点合并了多个 fp 时只认第一个名字，后面的不记 —— 否则重建时
        #   按 set 顺序挑一个，同一份存档两次渲染能出两个名字。
        self._ai_desc[fp] = d
        node.desc = d
        node.named = True
        if role:
            node.role = role[:8]
        return True

    def node_of(self, fp: str) -> Optional[Node]:
        return self.nodes.get(self.fp2nid.get(fp or ""))

    # -- 统计 ---------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        app_nodes = list(self.nodes.values())
        explore = sum(len(n.todo) for n in app_nodes)
        known = sum(1 for n in app_nodes for a in n.acts.values() if a.kind == "known")
        dead = sum(len(n.dead) for n in app_nodes)
        traps = sum(len(n.traps) for n in app_nodes)
        roles: Dict[str, int] = {}
        for n in app_nodes:
            roles[n.role] = roles.get(n.role, 0) + 1
        return {
            "nodes": len(app_nodes),
            "edges": len(self.edges),
            "actions": sum(len(n.acts) for n in app_nodes),
            "known_edges": known,
            "explore": explore,
            "dead": dead,
            "traps": traps,
            "merges": len(self.merges),
            "named": sum(1 for n in app_nodes if n.named),
            "roles": roles,
        }

    # -- 目标 ---------------------------------------------------------
    def target_matrix(self, sched_targets: Optional[Dict[str, Any]] = None
                      ) -> List[Dict[str, Any]]:
        """9 类权利入口的**图上**可达性。

        与 `Scheduler.target_report()` 的区别：那个只回答"看没看见"，
        这个还要回答"在哪一屏、距当前位置几步、路上有没有断"。报告里
        这两个口径都要给 —— 看见但走不到，本身就是一条事实。
        """
        found: Dict[str, Dict[str, Any]] = {}
        for n in self.nodes.values():
            for a in n.acts.values():
                for t in a.targets:
                    if t in found:
                        continue
                    found[t] = {
                        "name": t, "where": n.title(), "label": a.label,
                        "nid": n.nid,
                        "blocked": a.kind == "danger",
                        "tried": a.kind in ("known", "selfloop", "dead", "trap"),
                    }
        out = []
        for name, _kws in crawl.TARGETS:
            got = found.get(name) or {}
            out.append({
                "name": name,
                "found": bool(got),
                "where": got.get("where") or "",
                "label": got.get("label") or "",
                "nid": got.get("nid") or "",
                "blocked": bool(got.get("blocked")),
                "tried": bool(got.get("tried")),
            })
        return out

    def missing_targets(self) -> List[str]:
        return [r["name"] for r in self.target_matrix() if not r["found"]]

    # -- 路径 ---------------------------------------------------------
    def _adj(self) -> Dict[str, List[Tuple[str, str, float, str]]]:
        """邻接表：src → [(dst_nid, uid, 权重, 边上的文字)]。"""
        adj: Dict[str, List[Tuple[str, str, float, str]]] = {}
        for (src, uid), (dst, kind, lab) in self.edges.items():
            if not dst or dst not in self.nodes:
                continue
            w = W_SELFLOOP if kind == "DIALOG" else W_EDGE
            adj.setdefault(src, []).append((dst, uid, w, lab))
        return adj

    def shortest(self, src: str, dst: str) -> Optional[Dict[str, Any]]:
        """图上最短路径（Dijkstra）。返回 {"nids":[...], "labels":[...], "cost":x}。"""
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            return {"nids": [src], "labels": [], "cost": 0.0}
        adj = self._adj()
        dist: Dict[str, float] = {src: 0.0}
        prev: Dict[str, Tuple[str, str]] = {}
        done: Set[str] = set()
        import heapq
        pq: List[Tuple[float, str]] = [(0.0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if u in done:
                continue
            done.add(u)
            if u == dst:
                break
            for v, _uid, w, lab in adj.get(u, ()):
                nd = d + w
                if nd < dist.get(v, 1e18):
                    dist[v] = nd
                    prev[v] = (u, lab)
                    heapq.heappush(pq, (nd, v))
        if dst not in dist:
            return None
        nids = [dst]
        labels: List[str] = []
        cur = dst
        while cur != src:
            p, lab = prev[cur]
            labels.append(lab)
            nids.append(p)
            cur = p
        nids.reverse()
        labels.reverse()
        return {"nids": nids, "labels": labels, "cost": dist[dst]}

    def path_to_target(self, cur: str) -> Optional[Dict[str, Any]]:
        """从当前节点出发，「往哪走一步」最可能找到还没找到的权利入口。

        这就是 UI-KOBE 的 graph-guided navigation：模型不需要知道整条路径，
        只需要知道"沿哪条边迈第一步"。

        两级判据（顺序不能反）：

          ① **已见目标**：图里已经出现过某类权利入口（哪怕还没点），
             直接算到那个节点的最短路径 —— 这是硬事实。
          ② **角色推断**：一条都还没见过时，图里没有任何"目标节点"可算路径。
             此时按 PIPL 权利入口的实际分布，往最近的「设置页 / 账号页」
             且还有未探索动作的节点走 —— 注销、撤回同意、权限管理、
             个性化推荐开关几乎都挂在这两类页面下。

        ★ 必须两级都写。只做 ①：目标一次都没露过面时路径永远是 None，
          「定向期」就退化成按关键词瞎猜（这正是改造前的状态，也是 9 类权利
          入口 0 命中的直接原因之一）。只做 ②：已经看见入口却不走最短路径，
          白绕一圈。
        """
        if cur not in self.nodes:
            return None
        missing = set(self.missing_targets())
        if not missing:
            return None
        # ① 已见但**还没点过**的目标入口：这是最硬的导航目标。
        #    ★ 判据用 kind=="explore" 而不是"目标是否已 found"：found 只说明
        #      这一屏上出现过这个入口（`target_matrix` 靠它回答"有没有提供"），
        #      但"看见"和"点进去了"是两件事 —— 只按 found 排除，会把
        #      「看见了但还没点」的入口也一起排除，等于放着最短路径不走。
        dests: List[Tuple[str, str]] = []
        for n in self.nodes.values():
            for a in n.acts.values():
                if a.kind != "explore" or not a.targets:
                    continue
                if n.nid == cur:
                    continue
                dests.append((n.nid, a.label))
        best = None
        for nid, lab in dests:
            p = self.shortest(cur, nid)
            if not p:
                continue
            if best is None or p["cost"] < best["path"]["cost"]:
                best = {"nid": nid, "label": lab, "path": p, "kind": "target"}
        if best is None:
            # ② 角色推断：去找设置页 / 账号页（还留着未探索动作的那种）
            for n in self.nodes.values():
                if n.nid == cur or n.role not in ROLE_AFFINITY:
                    continue
                if not n.todo:
                    continue
                p = self.shortest(cur, n.nid)
                if not p:
                    continue
                if best is None or p["cost"] < best["path"]["cost"]:
                    best = {"nid": n.nid, "label": n.role + "方向",
                            "path": p, "kind": "role"}
        if best is None:
            return None
        nid, lab, p = best["nid"], best["label"], best["path"]
        first = p["labels"][0] if p["labels"] else ""
        return {
            "nid": nid,
            "target": lab,
            "kind": best["kind"],
            "steps": len(p["labels"]),
            "cost": round(p["cost"], 2),
            "first_label": first,
            "node": self.nodes[nid].title(),
        }

    def frontier(self, cur: str, limit: int = 5) -> List[Dict[str, Any]]:
        """最近的"还有未探索动作"的节点（含当前节点）。"""
        out: List[Dict[str, Any]] = []
        if cur in self.nodes and self.nodes[cur].todo:
            out.append({"nid": cur, "node": self.nodes[cur].title(),
                        "todo": len(self.nodes[cur].todo), "steps": 0})
        for n in self.nodes.values():
            if n.nid == cur or not n.todo:
                continue
            p = self.shortest(cur, n.nid)
            if not p:
                continue
            out.append({"nid": n.nid, "node": n.title(),
                        "todo": len(n.todo), "steps": len(p["labels"]),
                        "cost": round(p["cost"], 2)})
        out.sort(key=lambda r: (r["steps"], -r["todo"]))
        return out[:limit]

    # -- 局部选项（UI-KOBE 的核心：把规划降级成选择）--------------------
    def options(self, fp: str, clicks: Sequence[Any], *,
                can_back: bool = False, back_target: str = "",
                scroll_exhausted: bool = False, list_like: bool = False,
                phase: str = "", limit: int = 9,
                avoid_nid: str = "") -> List[Option]:
        """当前节点的**有限动作集**。模型只在这个集合里选，不自由发挥。

        集合构成（顺序即提示词里的编号顺序）：

          ① 未探索且命中"尚未找到的权利入口" —— 一票优先
          ② 通向东价值页面（设置/账号/隐私）的未探索入口
          ③ 普通未探索入口
          ④ 图上路径的第一步（已知边，用于走向目标所在节点）
          ⑤ 自环动作（开关/勾选，同屏状态变化）
          ⑥ 已知边回访
          ⑦ 滚动 / 上拉 / 返回

        `clicks` 是当前屏的可点节点（UiNode）。危险入口、提交类动作、
        输入框在这里**就不生成选项** —— 比"执行时拦截"更早，模型根本看不到。
        """
        node = self.node_of(fp)
        out: List[Option] = []
        if node is None:
            return out
        from .graph import node_uid       # 与 PageGraph 用同一套身份
        by_uid = {}
        dom: Dict[str, int] = {}
        for i, n in enumerate(clicks or ()):
            u = node_uid(n, clicks)
            by_uid[u] = n
            dom.setdefault(u, i)

        hint = self.path_to_target(node.nid)
        hint_label = (hint or {}).get("first_label") or ""

        # ---- 回头路：刚刚才从那一屏回来，就别再把通往它的入口排前面 ----
        # ★ 真机实测（以观书法 mbsf12，节点级节流生效后）：44 次动作里有 26 次是
        #   「查看历史 → 返回 → 查看历史 → 返回」的**两节点死循环**。原因是图上
        #   有一条记错的边 `我的页 --查看历史--> 设置页`（点击落点晚一拍被抓成
        #   下一页），于是"去设置页的最短路径第一步"永远是「查看历史」，
        #   而 `hint_label` 是按**标签**加权的，每回到我的页它又被顶到第一位。
        #   节流之前模型有发言权，会自己避开；节流之后全靠这张排序表，就死循环了。
        #   判据：本屏通往"上一步所在节点"的入口，一律降到最后（不是删掉 ——
        #   如果这屏真的没别的可做，还得允许它走回头路，否则卡死）。
        avoid_labels: Dict[str, str] = {}
        if avoid_nid and avoid_nid != node.nid:
            for (src, _u), (dst, _k, lab) in self.edges.items():
                if src == node.nid and dst == avoid_nid and (lab or "").strip():
                    avoid_labels[lab.strip()] = dst

        # 四元组排序：分数 → 类别 → **DOM 次序** → uid。
        # ★ DOM 次序必须进 key：`node.acts` 是按集合迭代建的，同分项的顺序
        #   每一轮都可能不同 —— 日志里"这屏先点了设置、下一轮先点了隐私"
        #   看着像策略变了，其实只是 dict 顺序变了，事后根本没法核对。
        #   界面上排在前面的先点，这个次序对人也最好解释。
        cand: List[Tuple[int, int, int, str, Option]] = []
        for uid, act in node.acts.items():
            n = by_uid.get(uid)
            if act.kind in ("danger", "trap", "dead"):
                continue
            # 危险 / 提交类 / 输入框：**任何类别都不生成选项**。
            # 执行层还有一道同样的闸门（`_walk_ui` 里对 ai_step 的复查），但闸门
            # 只保证"点了不执行"，模型仍会为一个不可执行的动作白花一次决策；
            # 而且 known/selfloop 这两个分支原先没过滤，等于把「确定注销」这类
            # 确认型销毁按钮摆到模型面前（mbsf13 真机就是照它点下去的）。
            if n is not None and (uiwalk.is_dangerous(n) or uiwalk.is_no_use(n)
                                  or crawl.is_soft_commit(n)):
                continue
            if act.kind == "explore":
                if n is None:
                    # 元素在这一屏已经不存在（滚走了 / 弹窗盖住）→ 不能当选项，
                    # 否则模型选了它、本地按 uid 找不到节点，白跑一次决策。
                    continue
                score = 2
                why = "未探索"
                if act.targets:
                    score = 0
                    why = "权利入口·" + act.targets[0]
                elif _is_policy_label(act.label):
                    # 协议/政策类长文：P2 已经单独取过正文，这里再进去只是又一个
                    # WebView，没有功能入口。真机实测（以观书法 mbsf9）：
                    # 26 步图引导里有 5 步花在「《隐私政策》」上来回进出，
                    # 一次新的账号页都没多走到 —— 排到最后。
                    score = 5
                    why = "协议/政策长文（正文已在 P2 取得，排最后）"
                elif crawl.value_rank(act.label) == 0:
                    score = 1
                    why = "通往设置/账号类页面"
                elif crawl.value_rank(act.label) == 3:
                    score = 5
                    why = "运营位"
                if act.label and act.label.strip() in avoid_labels:
                    score = 7
                    why = "刚从那回来，先不回头"
                elif hint_label and act.label and hint_label in act.label:
                    score = min(score, 1)
                    why += "；图上路径第一步"
                cand.append((score, 0, dom.get(uid, 999), uid, Option(
                    oid="", action="tap", label=act.label, uid=uid, node=n,
                    to_nid=act.to_nid, score=score, why=why)))
            elif act.kind == "selfloop":
                if n is None:
                    continue
                _sl_score = 4
                _sl_why = "同屏开关/勾选，可再操作一次"
                # ★ 同意类自环一律排最后（2026-11-10 CNC宝典连点 4 次
                #   「我已阅读并同意」）：同意在 P3 已单独做过，遍历期再点等于
                #   把勾选框取消又勾上 —— 既没有新界面，还会让"同意前/同意后"
                #   的时间划分变得可疑。
                if any(w in (act.label or "") for w in crawl._CONSENTY):
                    _sl_score = 8
                    _sl_why = "同意类控件，遍历期不再重复点击"
                cand.append((_sl_score, 1, dom.get(uid, 999), uid, Option(
                    oid="", action="tap", label=act.label, uid=uid, node=n,
                    to_nid=act.to_nid, score=_sl_score, why=_sl_why)))
            elif act.kind == "known":
                # 已知边主要用于"沿图走向目标"，单独排一档，且只在有路径提示时
                # 优先 —— 否则回访已知边纯属重复劳动（报告里的重复点击率就是这么来的）。
                if n is None:
                    continue
                score = 3
                why = "已知通往 %s" % (self.nodes[act.to_nid].role
                                       if act.to_nid in self.nodes else "其他界面")
                # ★ 回头路：目标界面比当前界面**更浅**，说明这个入口只是"回首页 /
                #   回上一级"的快捷方式（典型是标题栏里的 App 名称、logo）。
                #   它每屏都在、DOM 序还靠前，不压下去就会把遍历一直拉回根界面 ——
                #   CNC宝典 269 步里有 20 多次点在「数控车床CNC宝典」上，
                #   全程在首页↔详情之间弹跳，一个大功能都没走完。
                _tn = self.nodes.get(act.to_nid)
                if (_tn is not None and _tn.depth < node.depth
                        and not (hint and act.to_nid == hint.get("nid"))):
                    score = 7
                    why = "回头路：通往更浅的界面（%s），往回走交给返回键" % _tn.role
                elif avoid_nid and act.to_nid == avoid_nid:
                    score = 7
                    why = "刚从那回来，先不回头"
                elif hint and act.to_nid and act.to_nid == hint.get("nid"):
                    score = 1
                    why = "图上路径：去 %s（%d 步）" % (hint["node"], hint["steps"])
                cand.append((score, 2, dom.get(uid, 999), uid, Option(
                    oid="", action="tap", label=act.label, uid=uid, node=n,
                    to_nid=act.to_nid, score=score, why=why)))

        cand.sort(key=lambda c: (c[0], c[1], c[2], c[3]))
        picked = [c[4] for c in cand[:limit]]

        # ⑦ 导航类动作永远给（否则模型在"这屏没得点"时只能瞎猜）
        if not scroll_exhausted:
            picked.append(Option(oid="", action="scroll", score=6,
                                 why="向下找本屏下文"))
        elif list_like:
            picked.append(Option(oid="", action="pull", score=6,
                                 why="列表已到底，上拉加载下一页"))
        if can_back:
            picked.append(Option(oid="", action="back", score=7,
                                 label=back_target,
                                 why=("回到上层" if not back_target
                                      else "回到 %s" % back_target)))

        # 编号：tap 用 A/C，导航用 S/P/B
        for i, o in enumerate(picked):
            if o.action == "tap":
                o.oid = "%s%d" % (OID_TAP, sum(1 for x in picked[:i + 1]
                                               if x.action == "tap"))
            elif o.action == "scroll":
                o.oid = OID_SCROLL + "1"
            elif o.action == "pull":
                o.oid = OID_PULL + "1"
            else:
                o.oid = OID_BACK + "1"
        return picked

    # -- 记忆表（AutoDroid 的 App Memory）----------------------------
    def memory_text(self, fp: str, *, budget: Optional[int] = None) -> str:
        """当前图的"探索记忆"，注入提示词。

        AutoDroid 的做法：把离线探索得到的「模拟任务 → 状态 → 元素」表注入
        提示词，让模型不必从零推断"怎么走到那个页面"。这里对应的是
        「节点 → 已试/未试动作 → 到目标的路径 → 死路」。

        ★ 长度预算按字符硬控（默认 900 字），且**不随 num_ctx 放大**：
          这段是和截图、候选列表挤在同一个请求里的，遍历链路刻意保持
          与历史轮次同规模的输入（见 tasks.py 的 UI_TEXT_BUDGET_CAP 说明）。
          超出是**静默截尾**，尾巴被砍掉时最关键的"当前节点与路径"会一起丢。
          所以优先级从高到低排列，截断只可能砍掉最不重要的部分。
        """
        b = int(budget or self.budget)
        cur = self.node_of(fp)
        lines: List[str] = []
        s = self.stats()
        lines.append("【本轮已探索出的界面图谱（实测，不是先验知识）】")
        lines.append("共 %d 个界面 / %d 条已知跳转 / %d 个未探索入口 / %d 个死点 / %d 个陷阱"
                     % (s["nodes"], s["edges"], s["explore"], s["dead"], s["traps"]))

        if cur is not None:
            lines.append("当前：%s（第 %d 层，本节点已试 %d 个动作，剩 %d 个未试）"
                         % (cur.title(), cur.depth,
                            sum(1 for a in cur.acts.values() if a.kind != "explore"),
                            len(cur.todo)))
            if cur.dead:
                lines.append("本节点死点（点过没反应，别再点）：%s"
                             % "、".join(a.label[:10] for a in cur.dead[:4]))
            if cur.traps:
                lines.append("本节点陷阱（点了崩溃/跳出 App，禁止再点）：%s"
                             % "、".join(a.label[:10] for a in cur.traps[:3]))

        # 未找到的权利入口 + 路径
        miss = self.missing_targets()
        if miss:
            lines.append("尚未找到的权利入口：%s" % "、".join(miss[:6]))
        hint = self.path_to_target(cur.nid) if cur is not None else None
        if hint and hint.get("kind") == "target":
            lines.append("最近的可达目标：「%s」在 %s，约 %d 步；下一步先点「%s」"
                         % (hint["target"], hint["node"], hint["steps"],
                            hint["first_label"]))
        elif hint:
            # 角色推断必须写明是"方向"：这不是观测到的事实，写成"在设置页"
            # 会让模型（和复核员）误以为已经看见入口了。
            lines.append("图上还没出现过任何权利入口；最近的「%s」是 %s（%d 步），"
                         "往那边走更可能找到，下一步先点「%s」"
                         % (hint["target"], hint["node"], hint["steps"],
                            hint["first_label"]))

        # 最近的前沿（还有未探索动作的节点）
        fr = [r for r in (self.frontier(cur.nid, 4) if cur is not None else [])
              if r["steps"] > 0]
        if fr:
            lines.append("其他还有入口未试的界面：" + "；".join(
                "%s（%d 步 / 剩 %d 个）" % (r["node"], r["steps"], r["todo"])
                for r in fr[:3]))

        # 按预算截断：逐行加入，超了就停（宁少不超）
        out: List[str] = []
        used = 0
        for ln in lines:
            if used + len(ln) + 1 > b:
                break
            out.append(ln)
            used += len(ln) + 1
        return "\n".join(out)

    # -- 存档 / 报告 -------------------------------------------------
    def summary_line(self) -> str:
        """一行日志摘要（收尾时打出来，事后能从日志核对图长什么样）。"""
        s = self.stats()
        tail = "｜合并 %d 次" % s["merges"] if s["merges"] else ""
        if s["named"]:
            tail += "｜AI 命名 %d 个界面" % s["named"]
        return ("知识图谱：语义界面 %d 个 / 已探明跳转 %d 条 / 未探索动作 %d 个"
                " / 死点 %d 个 / 陷阱 %d 个%s"
                % (s["nodes"], s["edges"], s["explore"], s["dead"], s["traps"], tail))

    def to_dict(self) -> Dict[str, Any]:
        """进 scan.result.json：报告要能用**存档里的图**重渲染，不重算。"""
        return {
            "stats": self.stats(),
            "nodes": [{
                "nid": n.nid, "role": n.role, "desc": n.desc[:40],
                "named": bool(n.named),
                "activity": n.activity, "depth": n.depth, "visits": n.visits,
                "list_like": n.list_like, "dialog": n.is_dialog,
                "fps": len(n.fps), "parent": n.parent_nid,
                "todo": [{"label": a.label[:24], "targets": a.targets}
                         for a in n.todo[:12]],
                "dead": [a.label[:20] for a in n.dead[:8]],
                "traps": [a.label[:20] for a in n.traps[:6]],
            } for n in self.nodes.values()],
            "edges": [{"from": s, "uid": u, "to": d, "kind": k, "label": lab[:24]}
                      for (s, u), (d, k, lab) in list(self.edges.items())[:400]],
            "targets": self.target_matrix(),
            "merges": self.merges[:30],
        }


def _looks_toggle(label: str) -> bool:
    """这个"点了同屏不变"的元素更像开关，还是更像死点。

    ★ 必须分开：个性化推荐开关、权限开关、自动续费开关点完本来就不换屏，
      它们是**有价值**的动作；而"领券中心"点完没反应是纯浪费预算。
      判错一个开关的代价是少点一次，判错一个死点的代价是多烧几秒。
    """
    lab = (label or "").strip()
    if not lab:
        return False
    kw = ("开关", "切换", "开启", "关闭", "启用", "停用", "允许", "禁止",
          "同意", "勾选", "选中", "取消选中", "推荐", "通知", "自动")
    return any(k in lab for k in kw)
