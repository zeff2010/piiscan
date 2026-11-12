"""P4 遍历调度器：决定「这一步该做什么」。

## 为什么单独一层

Step 1 的结论是：旧的遍历是**逐屏贪心**——每停一屏就重新枚举可点元素、取排序第一个，
走进去就忘了怎么回来，也没有"这一屏还剩几个没试"的账。覆盖率上限被这个结构锁死了：
真机实测 8 次点击里有 3 次点在无文字容器上，重复点击 12%，未探索入口 69 个。

所以这一层只回答一个问题：**点哪个 / 返回 / 滚动 / 等**。它刻意不碰 adb、不碰采集
通道、不碰日志格式 —— 执行与护栏留在 `collector._walk_ui`，这样：

  · 调度逻辑可以**离线回放 XML 序列**完整验证，不需要真机；
  · 真机上护栏出问题时，可以判断是"决策错"还是"执行错"；
  · 想退回旧逻辑时只换一个分支，不用把护栏重写一遍。

## 四态

预算按时间进度推进，而不是按点击次数 —— 因为穷举一个巨大的列表页可能几百次点击，
按次数分配会让后面的阶段永远轮不到。

    ENTRY     确认站在主界面：优先铺主导航（tab）
    SURVEY    一级结构铺开：tab 与一级入口
    DEEPEN    DFS 深挖：非导航入口优先，点完逐层回退
    TARGETED  定向找注销 / 撤回同意 / 更正 / 个人信息副本

★ ENTRY 的判据不是"看起来像首页"，而是**实际上有没有铺到 tab**：铺到就提前结束，
  铺不到（单页应用、WebView 壳）就按时间硬切到 SURVEY。不能永远卡在入口策略，
  否则一个没有底部导航的 App 会整轮都在等"主界面出现"。

## 三条硬规矩

1. **候选按"本界面"过滤，不用全局 seen**。旧逻辑的 `seen` 是全局的，A 屏点完进 B 屏、
   再 BACK 回 A，A 的元素仍算"已点过"→ 什么都点不到 → 触发"无候选三拍"→ 又离开 A。
   回到上一级后复查（开关点完会不会变、再进一次还弹不弹窗）恰恰是合规取证的重点。
2. **危险入口不进候选，也不进"未探索"**。拦截在执行层（`uiwalk.is_dangerous`）已经做了，
   这里再挡一次是纵深防御；同时把它从 todo 里摘掉，否则"未探索入口"永远虚高十几项。
3. **BACK 要能按需使用**。`back_unsafe` 在旧逻辑里是"一旦发现退出 App 就永久禁用"，
   那会让 DFS 根本回不来。这里的判据是"根界面禁用、内页放行"，并留一道硬止损：
   内页 BACK 也导致 App 消失 ≥2 次，就彻底不再请求 BACK（降级为就地遍历，并如实记录）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .. import uiwalk
from . import content
from . import graph as graphmod

# --------------------------------------------------------------------- 阶段

ENTRY = "entry"
SURVEY = "survey"
DEEPEN = "deepen"
TARGETED = "targeted"

# (进度上限, 阶段)。进度是**真实采集进度**（已扣掉等模型的时间）。
PHASE_SPLIT: Tuple[Tuple[float, str], ...] = (
    (0.20, ENTRY),
    (0.60, SURVEY),
    (0.88, DEEPEN),
    (1.01, TARGETED),
)

# 单屏最多尝试点击几次。超过就回退，把预算让给别的界面。
# 真机依据：赣警办主界面一屏有 21 个入口，点完约 25 秒；给到 30 既能走完
# 一屏的主要入口，又不会让某个巨型列表页吃掉整轮预算。
MAX_TAPS_PER_STATE = 30
MAX_STACK = 20

# 滚到底之后还要"上拉"几次。
# ★ 为什么需要这一步：很多列表（微博式信息流、订单列表、消息列表）不是滚到底
#   就结束，而是**拉到边界再拉一下**才请求下一页。只按"滚两次界面没变"判到底，
#   会把这类列表的后半截整段判成"已走完"—— 报告里就成了"这个功能没有收集行为"。
#   给 2 次是实测够用的值：第 1 次触发加载，第 2 次兜住"加载慢/需要再拉一次"。
MAX_PULLS = 2

# 定向目标（PIPL 第 15/17/45/47 条对应的权利入口）。
# 每一项：(名称, 命中关键词)。命中即可，不需要精确匹配 —— App 的措辞五花八门
# （"注销账号""账号注销""申请注销""永久注销账号"）。
#
# ★ 这里**只找不点**：注销账号、删除账号在 `uiwalk.DANGEROUS_LABELS` 里，
#   点了就真把账号删了（不可逆），而且会打断后续采集。
#   记录"在哪个界面的哪个入口"本身就是结论：有没有提供注销入口、藏得多深。
TARGETS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("注销账号入口", ("注销",)),
    ("撤回同意入口", ("撤回", "撤销授权", "授权管理")),
    ("更正/删除个人信息", ("更正", "修改个人信息", "个人信息管理", "删除个人信息")),
    ("个人信息副本/导出", ("副本", "导出", "复制个人信息", "下载个人信息")),
    ("已收集个人信息清单", ("已收集", "收集清单", "个人信息清单")),
    ("第三方共享清单", ("共享清单", "第三方共享", "第三方信息")),
    ("权限管理", ("权限管理", "系统权限")),
    ("个性化推荐开关", ("个性化推荐", "个性化广告", "定向推送", "猜你喜欢")),
    # ★ 刻意不含「客服」「联系我们」：这两个入口在真机上常是**直接拨号**，
    #   拨出去就是真实外呼（有社会成本，也不是检测该做的事）。投诉/反馈类是页面跳转，安全。
    ("投诉举报/意见反馈入口", ("投诉", "举报", "意见反馈", "问题反馈", "投诉建议")),
)

# --------------------------------------------------------------------- 价值表

# 合规证据密度最高的入口。设置/隐私/权限/个人信息这几类页面里才有
# 「隐私政策入口」「权限管理」「注销账号」「撤回同意」这些东西。
HIGH_VALUE = ("我的", "个人", "设置", "账号", "隐私", "权限", "信息", "安全",
              "授权", "认证", "实名")
# 会收集个人信息的功能：注册资料、地址、发票、客服会话、意见反馈。
MID_VALUE = ("注册", "登录", "地址", "发票", "客服", "反馈", "资料", "绑定",
             "编辑", "管理", "收藏", "消息", "通知")
# 纯装饰 / 运营位：点进去基本没有个人信息行为，排在最后。
NOISE = ("广告", "抽奖", "活动", "升级", "评分", "签到", "分享", "邀请",
         "红包", "领券", "直播", "会员", "推荐", "热门")

# 会触发系统权限申请的功能入口，优先点。
#
# ★ 为什么它比"我的/设置"还优先
#   不是为了多找问题，而是为了**可复现**：Q026「申请权限未同步告知目的」
#   的前提是这一轮真的抓到过权限弹窗，而弹窗只在点到这类功能时才出现。
#   靠碰巧走到，同一个包同一版本会一轮"认定"、一轮"跳过未测"——
#   mbsf17 实测：登录失败导致覆盖缩到 40 屏，一次弹窗都没碰到，
#   Q026 只能记未测，而其余四轮（覆盖 58~69 屏）都判认定。
#   这类入口在界面上的位置是固定的，优先进去就能把"能不能测"变成确定的。
#
# ★ 只认动作词，不认泛词
#   "图片""通讯录"这类泛词在内容页到处都是（"上传图片"按钮、"通讯录"文案），
#   用泛词会把预算吸到无关页面。所以写成"上传/选择 + 图片"这种组合。
PERM_TRIGGER = ("拍照", "拍摄", "相机", "相册", "上传图片", "上传照片",
                "选择图片", "扫一扫", "扫码", "扫描", "语音输入", "录音",
                "按住说话", "定位", "附近", "通讯录好友", "读取通讯录")

# 政策/协议类入口：遍历的第一优先级（见 value_rank）。
#
# ★ 为什么单列一张表，而不是塞进 HIGH_VALUE
#   HIGH_VALUE 里的"隐私"只是泛词，命中后与"设置/账号"同级；而政策入口
#   必须**先于一切**被打开：它是后续条款比对的唯一依据。
#
#   实测丢失路径（2026-10-31，看个比赛 com.kgbs.ticket）：1 小时档只完成 9 次
#   点击，全部落在搜索页与刷新按钮上，政策页一次没进去 → 报告里政策全文为空
#   （前一晚同一台机拿到 16411 字）。遍历按价值排序时，"搜索/推荐"这类入口
#   更容易被点到，政策入口藏在「我的 → 设置」最深处，不专门提级就永远轮不到。
#
# ★ 点开这类入口没有副作用：政策页是只读页面，不产生业务后果，
#   所以不需要走"软禁"那套（SOFT_ENTRY 才需要）。
POLICY_DOC = ("隐私政策", "隐私协议", "隐私权", "隐私条款", "个人信息保护",
              "个人信息处理", "用户协议", "服务协议", "用户服务协议",
              "协议与规则", "隐私与安全", "数据保护", "隐私设置")

# 定向期关键词（PIPL 第 15/17/45/47 条对应的权利入口）。
TARGET_KW = ("注销", "撤回", "更正", "删除", "副本", "导出", "第三方共享",
             "共享清单", "权限管理", "已收集", "个性化推荐", "授权管理",
             "隐私设置", "账号与安全", "个人信息")
# 定向期的"路由词"：目标入口通常挂在这类页面下。当前屏一个目标词都没有时，
# 先往这些入口走，比在同一屏上按价值表瞎猜有效得多。
TARGET_ROUTE = ("我的", "个人中心", "设置", "账号", "隐私", "安全", "中心", "更多服务")

# 「展开型」入口：点了会把一屏内容变全（完整列表、全部评论、更多设置）。
# ★ 它们值得排在内容浏览之前，但不是最高优先级：这些入口本身不产生个人信息行为，
#   价值在于**把没露出来的入口露出来**。真机上很多「隐私设置」「账号与安全」
#   就藏在「更多」后面，只按价值表点的话永远打不开。
EXPAND_ENTRY = ("查看更多", "查看全部", "全部", "更多", "展开", "更多设置",
                "显示全部", "更多功能", "全部分类")

# 顶部/底部主导航里"先看哪个"（2026-11-10 数控车床CNC宝典）。
#
# ★ 用户要求：先把最下面那几个大入口铺开、把 App 的骨架搞清楚，再逐个小节
#   往里挖；「我的」「设置」这类小节要优先深入。
#   骨架本身由 `_tab_done` 保证"每个 tab 只点一次"，这张表决定顺序：
#   个人信息类小节排最前（合规事实密度最高），首页/信息流排后（点进去主要是内容）。
_TAB_FIRST = ("我的", "个人中心", "我的主页", "我", "账号", "账户", "设置",
              "会员中心", "个人")
_TAB_LAST = ("首页", "推荐", "发现", "关注", "热门", "精选")

# 同意类控件（「我已阅读并同意」「同意并继续」）。
# ★ 遍历阶段一律排最后（2026-11-10 数控车床CNC宝典连点 4 次「我已阅读并同意」）：
#   同意在 P3 已经单独做过一次，遍历期再点是空动作 —— 勾选框点第二下等于取消，
#   既拿不到新界面，还会让"同意前/同意后"的划分变得可疑。
_CONSENTY = ("阅读并同意", "已阅读并同意", "我已同意", "同意并继续", "勾选")


_NAV_SLOT = re.compile(r"底部导航第(\d+)/(\d+)项")


def tab_rank(label: str) -> int:
    """导航入口的次序：个人信息类小节 0 < 其它 1 < 首页/信息流 2。

    ★ 无文字底栏只能靠位置判（2026-11-10 CNC宝典）：自绘底栏的四个 tab
      在结构树里没有任何文字，命名成「底部导航第3/4项」。位置同样能表达
      用户要的那套章法 —— 最后一个 tab 绝大多数 App 是「我的」（个人信息
      最密集：登录态、订单、设置、隐私政策都挂在它下面），第一项多是
      首页/信息流（内容多、与个人信息关系弱）。中间项按原序即可。
    """
    lab = (label or "").strip()
    if not lab:
        return 1
    m = _NAV_SLOT.search(lab)
    if m:
        i, n = int(m.group(1)), int(m.group(2))
        if n >= 2 and i == n:
            return 0        # 最右一个：通常是「我的」
        if i == 1:
            return 2        # 最左一个：通常是「首页」
        return 1
    if any(w in lab for w in _TAB_FIRST):
        return 0
    if any(w in lab for w in _TAB_LAST):
        return 2
    return 1

# 软禁：这类字样的入口**可以进页面取证**（记字段、记索权），
# 但提交动作不许点。整类拉黑会漏掉"付款前强制收集身份证/银行卡/人脸"——
# 那正是高价值发现。
SOFT_ENTRY = ("支付", "购买", "订单", "结算", "购物车", "银行卡", "免密",
              "实名", "认证", "预约", "申领")
SOFT_COMMIT = ("确认支付", "立即支付", "去支付", "提交订单", "确认下单",
               "立即购买", "确认实名", "提交认证", "确认绑定", "立即开通",
               "开通免密", "确认授权", "获取验证码", "发送验证码", "确认注销",
               # ---- 登录/注册页的**提交**动作（2026-10-31）----
               # 只收组合词，刻意**不收**「登录」两个字：首页/我的页上的
               # 「点击登录」「登录后查看」是进入登录页的入口，本身是取证对象
               # （"不登录能用多少"要靠它才能看到）。拦掉它等于把登录页关在门外。
               # 这里要挡的是"在登录页上真的把账号登进去"那个动作 ——
               # 不登录的档位（1、2 档）反复点它只会触发风控，一条有效证据也换不来。
               "立即登录", "登录/注册", "注册/登录", "手机号登录", "密码登录",
               "验证码登录", "一键登录", "同意并登录", "注册账号", "忘记密码",
               "切换登录", "其他方式登录")

# 同构列表项抽样：一屏里 N 个同模板卡片（商品/文章/房源）点进去都是同一个
# 详情页模板，逐个点等于把预算烧在"同一件事"上。同类最多点这么多个。
# ★ 只在能确认"同构"时才合并，判据见 `_same_shape`：
#   要么 resource_id 只差数字后缀，要么标签都是长文本且同类控件。
#   「设置」页那种 2~4 字的短标签**不会**被合并 —— 那里每一项都是不同的合规事实。
MAX_SAME_SHAPE = 3

# ---- 内容型页面（资讯/文章/视频/商品）的预算（2026-11-03）----
# 真机依据（川剧迷 2026-11-02，1 小时档）：3683 秒里 2948 秒（80%）在
# `web.WebActivity` 一篇篇公众号文章上，89 次点击有 50 多次点的是信息流卡片。
# 同一模板的卡片点进去必然是同一套页面 —— 看一条就够，其余不看。
#
# ★ 为什么是"1 条"而不是"3 条"（`MAX_SAME_SHAPE` 是 3）：
#   后者防的是"漏掉同列表里不同的条目"（一屏 3 种商品），前者面对的是
#   **同一次渲染出来的同一模板**（同一篇文章的 20 个入口）。两回事。
CONTENT_ITEM_SAMPLE = 1     # 每个内容型页面最多点开几条
CONTENT_SCROLL_MAX = 1      # 内容页最多滚几次（够确认结构，不追信息流下一页）
CONTENT_TAP_LIMIT = 12      # 整轮在内容型页面上的点击总预算（到量就只退不进）


def phase_of(progress: float) -> str:
    """时间进度 → 阶段。"""
    p = min(1.0, max(0.0, float(progress or 0.0)))
    for limit, name in PHASE_SPLIT:
        if p < limit:
            return name
    return TARGETED


def is_soft_commit(node: Any) -> bool:
    """是不是"提交类"动作（软禁的第二段：能进去看，不能提交）。

    只认组合词（"确认支付"而不是"支付"），否则"提交反馈""我的订单"会被误拦。
    """
    lab = (getattr(node, "label", "") or "")
    if not lab:
        return False
    return any(k in lab for k in SOFT_COMMIT)


# 政策/协议类入口。首启阶段（P2）已经单独获取过政策正文，遍历阶段再点进去
# 通常只有一个长文本 WebView，没有功能入口 —— 真机实测（赣警办）在注册页与
# 政策错误页之间来回两趟，一次新入口都没多到。深挖期把它们排到最后。
POLICY_LABEL = ("隐私政策", "隐私协议", "用户协议", "服务协议", "隐私权",
                "个人信息保护", "个人信息处理规则", "儿童个人信息")

# 同一份文档入口整轮最多打开几次（2026-11-10 CNC宝典）。
#
# ★ 为什么要有这条上限：`_candidates` 判"点过没有"用的是**本界面**记录
#   （`st.uids_clicked`），而指纹里含可见文字与可见入口数 —— 设置页滚一下、
#   或者"个人信息收集清单"里按了返回，落点就被算成**另一个界面**，于是同一个
#   「隐私政策」重新变成合法候选。真机实测一轮里「隐私政策」被打开 5 次、
#   「用户协议」6 次，每次都只是同一条长文本 WebView：点开 → 滚 4 屏 → 返回，
#   单次 30~90 秒；光这 11 次就烧掉约 8 分钟，而正文在 P2 早就有 11378 字了。
#   `ledger` 的 `walk_tap_limit` 管不住它，因为那是按 (界面, 入口) 记的账。
# ★ 上限给 2 而不是 1：第一次可能正好撞上 WebView 还没渲染完（取不到正文），
#   留一次重试机会；第二次之后仍取不到的，再点也取不到（本轮实测 6 次全空）。
DOC_TAP_LIMIT_READY = 2      # 政策正文已取到：同一文档入口最多点 2 次
DOC_TAP_LIMIT_UNREADY = 4    # 正文还没取到：放宽到 4 次，别放弃最后的补救入口


def _doc_key(label: str) -> str:
    """文档入口的归一化身份（`《隐私政策》`/`隐私政策 ` → `隐私政策`）。"""
    s = re.sub(r"[《》〈〉「」『』【】\[\]（）()\s]", "", label or "")
    return s


def _hit(text: str, words: Sequence[str]) -> bool:
    return bool(text) and any(w in text for w in words)


# resource_id 末尾的数字索引：`item_0` / `row12` / `cell_3`。
# 去掉数字后同名的，几乎可以肯定是同一个模板渲染出来的一批条目。
_ID_TAIL = re.compile(r"^(.*?)[_\-]?(\d+)$")


def _is_evidence_entry(node: Any) -> bool:
    """这一条是不是"取证入口"（政策正文 / 权利入口）。

    内容型页面的抽样上限对它无效：同模板卡片可以只看一条，但「隐私政策」
    「注销账号」「权限管理」这类入口本身就是证据，不能因为"这页是内容页"被跳过。

    ★ 词表刻意比 `content.TARGET_GUARD` 窄：那个表是"不许算同构跳过"，
      所以宁宽勿窄；这里会**真的多花点击**去点，混进「删除」「举报」这种泛词，
      一条笔记列表就会被逐行点一遍（每行都有「删除」）。
    """
    lab = (getattr(node, "label", "") or "").strip()
    if not lab:
        return False
    return _hit(lab, _EVIDENCE_KW)


# 值得为它单独花一次点击的入口（政策正文 + PIPL 权利入口）。
_EVIDENCE_KW = ("隐私政策", "隐私协议", "用户协议", "服务协议", "隐私权",
                "个人信息保护", "个人信息", "注销", "撤回", "撤销授权", "更正",
                "副本", "导出", "共享清单", "第三方共享", "权限管理", "已收集",
                "个性化推荐", "授权管理")


def _same_shape(node: Any) -> Optional[str]:
    """这个入口属于哪种"同构模板"；判断不出来返回 None（= 不可合并）。

    ★ 判据必须保守 —— 合并错的代价是**整整一类入口被漏点**，而这份报告的价值
      全靠"该测的都测到了"。所以只认两种铁证：

        ① resource_id 只差末尾数字（`item_0` 与 `item_1`）；
        ② 标签是长文本（≥8 字）且控件类相同 —— 商品标题/文章标题/房源名这类。

      「设置」页上的「隐私设置」「账号与安全」「清除缓存」都是 3~5 字短标签，
       每条都是不同的合规事实，**绝不能**被当成同构合并掉。
    """
    sid = (getattr(node, "resource_id", "") or "").split("/")[-1]
    if sid:
        m = _ID_TAIL.match(sid.lower())
        if m and len(m.group(1)) >= 3:
            return "id:" + m.group(1)
    lab = (getattr(node, "label", "") or "").strip()
    cls = (getattr(node, "cls", "") or "").split(".")[-1]
    if len(lab) >= 8 and cls:
        return "cls:" + cls
    return None


def value_rank(label: str) -> int:
    """入口的价值等级，越小越优先。

    顺序刻意让"我的/设置/隐私"压过"首页/推荐"：首页 feed 点进去只是内容浏览，
    而设置里的每一个开关都是一条合规事实。
    """
    lab = label or ""
    if _hit(lab, POLICY_DOC):
        # ★ 排在所有入口之前，包括权限触发类。
        #   这不是"多找问题"，而是**整份报告的依据**：条款比对、目的正当性、
        #   权限与功能对应，全都要读政策正文。正文没拿到，22 项里十几项只能记
        #   "跳过未测"。真机教训（2026-10-31）：看个比赛 1 小时只点了 9 次、
        #   全在搜索页打转，政策页一次没进 —— 报告里连政策全文都没有，
        #   而前一晚同一台机、同一个包拿到过 16411 字。
        return -2
    if _hit(lab, PERM_TRIGGER):
        # 比 HIGH_VALUE 更前：理由见 PERM_TRIGGER 处的注释（关系到本项能不能测）。
        return -1
    if _hit(lab, HIGH_VALUE):
        return 0
    if _hit(lab, EXPAND_ENTRY):
        # 展开型入口（更多/全部）排在设置类之后、内容浏览之前：
        # 它的价值是把藏起来的入口露出来，本身不产生行为证据。
        return 1
    if _hit(lab, SOFT_ENTRY):
        # 支付/订单/实名这类页面正是"是否强制收集"的高发地：能进去看，但要排在
        # 内容浏览之前。提交动作由 `is_soft_commit` 单独拦，不在这里排除整类。
        return 1
    if _hit(lab, MID_VALUE):
        return 1
    if _hit(lab, NOISE):
        return 3
    return 2


def priority_rank(label: str) -> int:
    """弹窗类按钮的次序（同意/允许/确定…在前）。"""
    for i, kw in enumerate(uiwalk.PRIORITY_KEYWORDS):
        if kw in (label or ""):
            return i
    return len(uiwalk.PRIORITY_KEYWORDS)


# --------------------------------------------------------------------- 结果

@dataclass
class Step:
    """一次调度决策。

    `action` 只有五种：

      tap     点某个入口
      back    回上一级
      scroll  向下滚动（找本屏下文）
      pull    已滚到底后上拉加载下一页（只对列表页）
      none    这一屏没得做，交回调用方的兜底序列（滚动/左右滑/返回）
    """

    action: str
    node: Any = None
    uid: str = ""
    reason: str = ""
    phase: str = ""
    tab: bool = False          # 这一步点的是主导航（用于栈同步）
    label: str = ""

    def __bool__(self) -> bool:
        return self.action != "none"


# --------------------------------------------------------------------- 调度器

class Scheduler:
    """DFS 栈 + 价值表 + 死点 + 滚动记账。"""

    def __init__(self, graph: Any, *, max_taps_per_state: int = MAX_TAPS_PER_STATE,
                 max_pulls: int = MAX_PULLS, max_depth: int = 0,
                 log: Optional[Any] = None) -> None:
        self.g = graph
        self.max_taps_per_state = max(1, int(max_taps_per_state))
        # 0 = 关掉上拉（退回 Step 2 的行为）。
        self.max_pulls = max(0, int(max_pulls))
        # 最深能点到第几层（0 = 不限）。2 档「只点二级目录」用 2：
        # 到了第 2 层的界面就不再往里点，只滚一滚、然后回退。
        # ★ 层级用页面图的"从入口点了几跳"记，不是猜 Activity 名 ——
        #   同一个 MainActivity 承载五层菜单的 App 很常见。
        self.max_depth = max(0, int(max_depth or 0))
        self.log = log
        # 从入口到当前界面的路径。栈底永远是入口界面（通常是主界面/首页）。
        self.stack: List[str] = []
        self.phase = ENTRY
        self.tabs_opened = 0
        self.taps = 0
        self.backs = 0
        self.scrolls = 0
        self.back_kills = 0            # 内页 BACK 导致 App 消失的次数
        self.no_back = False           # 彻底不再用 BACK（硬止损）
        self.entry_failed = False      # 一直没识别出主导航
        self._tabs_seen: Set[str] = set()
        # tab 节点 uid → 它通向的界面 fp。同一个 App 的 tab bar 是固定的，
        # 「发现」永远通向同一个根界面，所以这个映射可以跨界面复用。
        self._tab_target: Dict[str, str] = {}
        # 已经去过的 tab 落点界面。用来避免"从 A tab 点去 B tab、到了 B 又点回 A"——
        # 旧逻辑里 tab 之间的来回切换能吃掉一半预算，却一个新界面都没多到。
        self._tab_fps: Set[str] = set()
        self._pending = ""             # 上一次点击的性质：tab / deep / ""
        # ---- 同构列表项抽样（2026-10-31）----
        # fp → {同构签名: 已安排点击数}；fp → 本屏被"抽样"跳过的 uid。
        # ★ 为什么要在**候选层**记账，而不是在排序里压低权重：
        #   排序只决定"先点谁"，一屏 20 个同构卡片最后还是会被逐个点完 ——
        #   预算照烧，行为照旧。要真的少点，必须让它们**离开候选**。
        self._shape_count: Dict[str, Dict[str, int]] = {}
        self._shape_skipped: Dict[str, Set[str]] = {}
        # ---- 内容型页面（2026-11-03）----
        # fp → 本屏同模板条目的 uid 列表（点之前先算好，落点结算时要用它反推父界面）
        self._templates: Dict[str, List[str]] = {}
        self._content_learned: Set[str] = set()   # 已经做过"父界面回溯"的落点
        self._content_scrolls: Dict[str, int] = {}
        self.content_taps = 0                     # 整轮在内容页上的点击总数
        self.content_logged: Set[str] = set()
        self._pending_tab_uid = ""
        self._pending_tab_label = ""   # tab 的文字，用来登记"这个 tab 通到哪个界面"
        # 「点了它、界面纹丝不动」的入口记账（uid → 次数）。
        # 2026-11-10 CNC宝典真机：标题栏「数控车床CNC宝典」（ImageView）一整轮被点了
        # 3 次。它不是"回头路"（点它不换屏，压根没有边），也不是"同意类"，
        # 于是每次回到根界面它都重新变得"合法可点"，一路吃预算。
        # 判据来自结果：点完落点还是同一屏 → 记为无效入口，本屏排到最后。
        self._noop_uids: Dict[str, int] = {}
        # 文档类入口（隐私政策/用户协议…）整轮被打开的次数，按归一化标签记。
        # 判"点过没有"用的是本界面记录，滚一下或返回一次就算新界面，
        # 同一份文档会被反复打开 —— 详见 DOC_TAP_LIMIT_READY 的说明。
        self._doc_taps: Dict[str, int] = {}
        # 已经因为"超限被移出候选"而提示过的文档（只提一次，避免刷屏）
        self._doc_skipped: Set[str] = set()
        # 政策正文是否已取到（由采集侧每步同步）。决定 DEEPEN 里政策入口
        # 要不要往后压 —— 没取到时它是最后的补救入口，必须优先。
        self.policy_ready: bool = False
        self._pending_tap_uid = ""
        self._scroll_fp = ""           # 最近一次滚动所在的界面
        self._scroll_from = ""         # 本次滚动之前停在哪一屏（等下一屏结算）
        self._scroll_pending = False
        self._scroll_kind = ""         # scroll / pull
        self._scroll_same = 0
        self.phase_taps: Dict[str, int] = {}
        # ---- 定向目标 ----
        # 目标名 → {"found": bool, "where": 界面, "label": 入口文字, "blocked": 是否被拦}
        self.targets: Dict[str, Dict[str, Any]] = {}
        self._target_scanned: Set[str] = set()   # 已扫描过的界面（每屏只扫一次）
        # ---- 状态漂移 ----
        # BACK 之后落到哪一屏是可以预期的（栈的上一级）。落点不对说明 App 有
        # 拦截页/登录页/广告页插了队，此时继续按旧栈走会一路错下去。
        self._back_expect = ""
        self.drift = 0
        self.drift_giveup = False
        self._respawn_asked = False
        # uid → 它上一次点到的界面。`_rank` 用来识别"回首页/回上一级"这类
        # 快捷入口（点它只是往回走，不该占探索预算）。
        self._tmap: Dict[str, str] = {}

    # -- 栈 -----------------------------------------------------------
    def sync(self, fp: str) -> None:
        """界面变了之后同步栈。

        四种情况必须分开处理，混在一起会让栈逐渐和真实位置脱节：

          · 点的是主导航 → 栈**重置为这一屏**。tab 之间是平级切换，不是"深入"；
            若当成深入，从 tab2 里点进三级页再返回，栈会以为还在 tab1 的子树里。
          · 回到栈内某处 → 截断到那里。这是 DFS 的正常回退。
          · 全新界面 → 压栈。
          · 同一屏 → 不动。
        """
        if not fp:
            return
        # 内容页回溯（见 `_learn_content_parent`）：点进去才发现是站外内容时，
        # 回父界面把同一模板的其余条目一次性标掉。放在最前面，不依赖本次落点
        # 是"新界面"还是"回到旧界面"。异常不外溢 —— 它只是优化，不能影响遍历。
        try:
            self._learn_content_parent(fp)
        except Exception:
            pass
        # 滚动/上拉结算放在最前面：滚完之后界面有没有变，只有到了这一屏才知道。
        if self._scroll_pending:
            self._scroll_pending = False
            kind, self._scroll_kind = self._scroll_kind, ""
            changed = bool(self._scroll_from) and fp != self._scroll_from
            st_prev = self.g.states.get(self._scroll_from) if self.g is not None else None
            if kind == "pull" and st_prev is not None:
                # 上拉：加载出下一页 → 清掉"到底"标记，重新允许滚动；
                # 拉完还是老样子 → 记一次空拉，拉到 MAX_PULLS 次就认了。
                if changed:
                    st_prev.scroll_exhausted = False
                    st_prev.pages += 1
                    st_prev.pulls = 0
                    self._scroll_same = 0     # 新一页：滚动计数从头来
                else:
                    st_prev.pulls += 1
            elif changed:
                self._scroll_same = 0          # 滚出了新内容
            else:
                self._scroll_same += 1         # 滚了等于没滚
            self._scroll_fp = fp
            if self._scroll_same >= 2 and kind != "pull":
                st_prev2 = self.g.states.get(fp) if self.g is not None else None
                if st_prev2 is not None:
                    st_prev2.scroll_exhausted = True
        # 漂移判定：BACK 之前记下了"应该回到哪一屏"，落点不是它 → 记一次漂移。
        # ★ 只统计不立即纠偏：纠偏动作（再按一次 BACK）由 `decide` 在下一轮请求，
        #   这样"要不要按返回"的判据仍然只有 `can_back` 一处。
        if self._back_expect:
            expect, self._back_expect = self._back_expect, ""
            if fp != expect and fp not in self.stack:
                self.drift += 1
                if self.drift >= 3 and not self.drift_giveup:
                    self.drift_giveup = True
        kind, self._pending = self._pending, ""
        tap_uid, self._pending_tap_uid = self._pending_tap_uid, ""
        tab_uid, self._pending_tab_uid = self._pending_tab_uid, ""
        tab_label, self._pending_tab_label = self._pending_tab_label, ""
        # ★ 「点了它、界面纹丝不动」→ 记一次无效入口（2026-11-10 CNC宝典）。
        #   放在栈判定之前：无效点击的特征正好是"落点还是本屏"，
        #   而下面的 `fp == stack[-1]` 分支会直接 return，错过就记不上了。
        if tap_uid and kind == "deep" and self.stack and fp == self.stack[-1]:
            self._noop_uids[tap_uid] = self._noop_uids.get(tap_uid, 0) + 1
        # 定向目标扫描：每屏只扫一次（标签集合在页内基本不变，重复扫纯浪费）。
        if fp not in self._target_scanned:
            self._target_scanned.add(fp)
            self._scan_targets(fp)
        if not self.stack:
            if kind == "tab" and tab_uid:
                self._tab_target[tab_uid] = fp
                self._tab_fps.add(fp)
                if self.g is not None and tab_label:
                    self.g.mark_tab_root(tab_label, fp)
            self.stack = [fp]
            return
        if kind == "tab":
            if tab_uid:
                self._tab_target[tab_uid] = fp
            self._tab_fps.add(fp)
            if self.g is not None and tab_label:
                self.g.mark_tab_root(tab_label, fp)
            self.stack = [fp]
            return
        if fp == self.stack[-1]:
            return
        if fp in self.stack:
            del self.stack[self.stack.index(fp) + 1:]
            return
        st = self.g.states.get(fp) if self.g is not None else None
        if st is not None and st.is_dialog:
            # 弹窗是当前界面上的临时层，关掉就回原界面 —— 不压栈。
            # 压了会让深度虚高，DFS 还会在"页面 ↔ 弹窗"之间反复来回。
            return
        self.stack.append(fp)
        if len(self.stack) > MAX_STACK:
            # 栈过深说明一直在往下钻。截掉最老的中间层，保留入口与最近几层 ——
            # 直接截断尾部会丢掉"我现在在哪"，而归位只依赖栈尾。
            del self.stack[1:len(self.stack) - MAX_STACK + 1]

    def _learn_content_parent(self, fp: str) -> None:
        """落点是内容页 → 回头把父界面上**同一模板的其余条目**一次性标掉。

        ★ 为什么需要这一步（光靠静态判据不够）：
          静态判据（`content.classify`）认得出"长标题 + 站外域名"的资讯列表，
          但认不出「三祭江 / 拷紅 / 曉艇」这种 2~4 字短标题的戏曲/商品列表 ——
          要是放宽到"短标题也算内容"，设置页的「隐私设置」「账号与安全」就会被
          一起跳过，那是把整类合规事实漏掉。

          所以改用**结果反推**：从同模板的其中一条点进去，落点是不是内容页是
          客观事实。是 → 其余几条点进去必然是同一套模板（同一次渲染出来的）。
          这一步恰好实现了用户要的"看一个就够"，而且不会误伤设置页 ——
          设置项点进去是原生功能页，不会被判成内容页，因此父界面不会被标。

        保守条件：父界面的同模板组至少 4 条，且落点确实被判成内容页。
        """
        if self.g is None or fp in self._content_learned:
            return
        st = self.g.states.get(fp)
        if st is None or not st.content:
            return
        self._content_learned.add(fp)
        # ★ 只认"站外内容平台域名"这一条铁证才回溯。
        #   理由：这一步会把父界面上**一整组**入口标成同构跳过，判错等于整类漏测。
        #   而"关于我们→公司介绍页""帮助中心→官网"这类页面也长得很像内容页，
        #   只有 `mp.weixin.qq.com` 这种域名能说明"这是他人生产的内容"。
        if not getattr(st, "content_host", ""):
            return
        parent = self.g.states.get(st.parent_fp) if st.parent_fp else None
        if parent is None or parent.system or parent.content:
            return
        _tpl = list(self._templates.get(parent.fp) or [])
        if len(_tpl) < 4:
            return
        items = set(_tpl)
        items.discard(st.enter_uid or "")
        if len(items) < 3:
            return
        parent.content = True
        parent.content_reason = ("同模板条目点开后为内容页（%s）"
                                 % (st.content_reason or "站外内容"))
        parent.content_items |= items
        parent.content_sample = st.enter_uid or ""
        try:
            if self.log:
                self.log("[*] 内容型列表回溯：从「%s」点进去是%s，同模板其余 %d 条"
                         "按同构跳过（同一次渲染，点开是同一套页面）"
                         % ((parent.labels.get(st.enter_uid or "") or "同模板条目")[:18],
                            st.content_reason or "站外内容", len(items)))
        except Exception:
            pass

    @property
    def depth(self) -> int:
        return max(0, len(self.stack) - 1)

    # -- 反馈 ---------------------------------------------------------
    def note_tap(self, *, tab: bool = False, uid: str = "", label: str = "") -> None:
        self.taps += 1
        self._pending = "tab" if tab else "deep"
        self._pending_tap_uid = uid or ""
        self._pending_tab_uid = uid if tab else ""
        self._pending_tab_label = label if tab else ""
        self.phase_taps[self.phase] = self.phase_taps.get(self.phase, 0) + 1
        if tab:
            self.tabs_opened += 1
        # 文档入口的整轮上限（见 DOC_TAP_LIMIT_READY）：在这里记而不是在
        # `_rank` 里记，是因为 AI 也可能直接选中这些入口 —— 记账必须只有一份，
        # 否则"模型选的"绕过了上限，等于没有上限。
        _dk = _doc_key(label)
        if _dk and _hit(_dk, POLICY_LABEL):
            self._doc_taps[_dk] = self._doc_taps.get(_dk, 0) + 1

    def note_back(self, *, killed: bool = False) -> None:
        self.backs += 1
        # 栈在下一屏 `sync` 时按实际落点修正，这里不预先弹栈 ——
        # 猜错了会让"BACK 没生效"被当成"已经在父界面"。
        self._pending = ""
        # 但要**记下预期落点**：下一屏如果不是它，说明有页面插队（登录/广告/拦截页），
        # 这时栈已经不可信了，必须纠偏。
        self._back_expect = self.stack[-2] if len(self.stack) >= 2 else ""
        if killed:
            self.back_kills += 1
            if self.back_kills >= 2:
                self.no_back = True

    def note_scroll(self, fp: str = "", kind: str = "scroll") -> None:
        """记一次滚动（kind="pull" 表示"已到底后再上拉加载"，语义不同）。

        ★ 只记"从哪一屏滚的"，**不在这里判结果**：`input swipe` 之后并没有立刻
          重新 dump，此刻根本不知道界面上多了内容没有。硬判"没变化"会让每滚两次
          就误标"已滚到底"，把还有下文的列表页整页跳过。结果由下一次 `sync` 结算。
        """
        self.scrolls += 1
        self._pending = ""
        self._scroll_from = fp or self._scroll_fp or ""
        self._scroll_kind = "pull" if str(kind).lower() == "pull" else "scroll"
        self._scroll_pending = True
        # 内容页的滚动单独记账：这类页面最多滚 `CONTENT_SCROLL_MAX` 次，
        # 之后必须离开 —— 信息流是无限长的，"滚到底"这个判据在这里永远不成立。
        _st = self.g.states.get(self._scroll_from) if self.g is not None else None
        if _st is not None and getattr(_st, "content", False):
            self._content_scrolls[_st.fp] = self._content_scrolls.get(_st.fp, 0) + 1

    # -- 定向目标 -----------------------------------------------------
    def _scan_targets(self, fp: str) -> None:
        """把这一屏上出现的"权利入口"记下来（**只看不点**）。

        记录三件事：在哪个界面、入口写的是什么、是不是被安全规则挡住了。
        这三样合起来才是结论 —— "提供了注销入口，位于'设置-账号与安全'，
        入口本身可点，但按检测规范不实际注销"。
        """
        g = self.g
        st = g.states.get(fp) if g is not None else None
        if st is None:
            return
        uids = set(st.uids_seen) | set(st.blocked)
        for name, kws in TARGETS:
            got = self.targets.get(name)
            if got and got.get("found"):
                continue
            for u in uids:
                lab = st.labels.get(u) or ""
                if not lab or len(lab) > 20:
                    continue
                if not any(k in lab for k in kws):
                    continue
                self.targets[name] = {
                    "found": True,
                    "where": g._name_of(st) if hasattr(g, "_name_of") else (st.activity or fp),
                    "label": lab[:30],
                    "blocked": u in st.blocked,
                }
                break

    def target_report(self) -> List[Dict[str, Any]]:
        """定向目标的查找结果（按 TARGETS 顺序，没找到的也列出来）。"""
        out = []
        for name, _kws in TARGETS:
            got = self.targets.get(name) or {}
            out.append({
                "name": name,
                "found": bool(got.get("found")),
                "where": got.get("where") or "",
                "label": got.get("label") or "",
                "blocked": bool(got.get("blocked")),
            })
        return out

    # -- 漂移 ---------------------------------------------------------
    def take_respawn_request(self) -> bool:
        """要不要重拉一次 App（漂移纠偏的最后手段）。取一次就复位。

        ★ 只在**连续三次** BACK 都没回到预期界面时才置位：App 有拦截页插队是常见的，
          一次不对就重拉会把好好的遍历打断（重拉要重新注入 hook，代价很高）。
        """
        if self._respawn_asked or not self.drift_giveup:
            return False
        self._respawn_asked = True
        self.stack = []
        return True

    # -- 决策 ---------------------------------------------------------
    def decide(self, fp: str, clicks: Sequence[Any], nav: Sequence[Any], *,
               progress: float, back_unsafe: bool, system: bool = False) -> Step:
        """给出这一步该做什么。任何异常都由调用方兜住（这里不吞异常）。"""
        self.phase = phase_of(progress)
        st = self.g.states.get(fp) if (self.g is not None and fp) else None
        if st is None:
            return Step("none", phase=self.phase, reason="界面未登记")
        if system or st.system:
            # 系统界面（权限弹窗）由采集层的拦截分支取证并代点，调度器不插手 ——
            # 在这里点按钮会把"申请权限"变成"替用户授权"，证据就没了。
            return Step("none", phase=self.phase, reason="系统界面，交给拦截分支")

        # ENTRY 结束条件：已经铺到过主导航。铺不到就等时间硬切。
        # （`entry_failed` 在 `stats()` 里按"实际点开过几个 tab"动态算 ——
        #  在这里按时间点置位会误报：tab 往往是在 SURVEY 阶段才点到的。）

        nav_uids = {self.g.uid_for(n) for n in (nav or [])}
        # 「这个入口上次点到了哪儿」。`_rank` 用它把"回头路"排到最后。
        # 每步重算一次：边数最多几百，比起多走一步 7 秒，这点开销可以忽略。
        try:
            self._tmap = {}
            for _e in (getattr(self.g, "edges", None) or []):
                _u, _t = getattr(_e, "uid", ""), getattr(_e, "to_fp", "")
                if _u and _t:
                    self._tmap[_u] = _t
        except Exception:
            self._tmap = {}
        cands = self._candidates(clicks, st)
        # 记下本屏的同模板条目 uid：落点结算时要用它反推"父界面上还有哪些同构条目"
        # （`_learn_content_parent`）。这一步必须发生在点击之前。
        # 用 loose（不等高也算同模板）：那条路是"点进去已经确认是站外内容"之后才走的，
        # 有证据支撑，可以放宽 —— 真机图片墙就是两列不等高瀑布流。
        self._templates[getattr(st, "fp", "") or ""] = [
            self.g.uid_for(n) for n in content.template_items(clicks, loose=True)]
        if nav_uids:
            # 去过的 tab 不再点：从「我的」点「发现」到发现页，发现页上又点回「我的」，
            # 这种来回切换在旧逻辑里很常见，一次新界面都没多到却吃掉大量预算。
            # 判据是"这个 tab 之前通到过哪个界面，那个界面已经去过了"。
            cands = [c for c in cands if not self._tab_done(c[1], nav_uids)]
        # ---- 内容型页面：不按常规 DFS 铺，只抽样一条就退（2026-11-03）----
        # 放在层级上限之前：内容页无论在第几层都按"低成本"走，否则 4 档（不限层）
        # 会把它当普通页面一路点下去 —— 那正是 80% 预算被烧掉的地方。
        if getattr(st, "content", False):
            return self._content_step(st, cands, clicks, nav_uids, back_unsafe)
        # ---- 层级上限（2 档「只点二级目录」）----
        # ★ 到顶之后**不是**立刻收工：本屏仍要滚一滚（列表后半截的条目也算本层内容），
        #   滚完再回退。直接返回 back 会让长列表页只看到第一屏。
        if self.max_depth and cands:
            _here = int(getattr(st, "depth", 0) or 0)
            if _here >= self.max_depth and not any(c[1] in nav_uids for c in cands):
                if not st.scroll_exhausted:
                    return Step("scroll", phase=self.phase,
                                reason="%s｜已达本档层级上限（第 %d 层），先滚完本屏"
                                       % (self.phase, _here))
                return self._fallback(st, back_unsafe)
        if not cands:
            return self._fallback(st, back_unsafe)

        best = min(cands, key=lambda c: (self._rank(c[0], c[1], nav_uids),
                                         _dom_index(clicks, c[0])))
        node, uid = best
        # 只剩返回控件时，直接走「返回上一级」，不要"点一下那个箭头"（2026-11-10）：
        #   两者落点一样，但按 BACK 这件事有 `can_back()` 统一判"会不会退出应用"，
        #   而点箭头绕过了它；报告里也会把这次点击写成"点击『xx返回』"，
        #   白白占掉一次点击留痕与一张截图。真机实测这一轮 32 次点击里有 7 次
        #   是这么来的（文档页/设置子页上唯一可点的就是左箭头）。
        try:
            if graphmod.is_back_control(node) and self.can_back(back_unsafe):
                return Step("back", phase=self.phase,
                            reason="%s｜本屏只剩返回控件，交给 BACK（返回键口径统一）"
                                   % self.phase)
        except Exception:
            pass
        self._note_shape(st, node, clicks)
        is_nav = uid in nav_uids
        if is_nav:
            self._tabs_seen.add(uid)
        return Step("tap", node=node, uid=uid, label=(node.label or "")[:40],
                    phase=self.phase, tab=is_nav,
                    reason="%s｜%s%s" % (self.phase, _why(node.label, self.phase),
                                         "｜主导航" if is_nav else ""))

    def _candidates(self, clicks: Sequence[Any], st: Any) -> List[Tuple[Any, str]]:
        """本屏真正还能点的入口：危险的不算、提交类的不算、点过的/死点/超额的不算。

        ★ 判"点过没有"用**本界面**的记录（`st.uids_clicked`），不用旧逻辑那个全局
          `seen`：从子界面返回父界面后，父界面上没点过的入口仍然是可点的。
        """
        if len(st.uids_clicked) >= self.max_taps_per_state:
            # 这一屏已经点够多了，把预算让给别的界面。
            return []
        out: List[Tuple[Any, str]] = []
        _fp = getattr(st, "fp", "") or ""
        _skip = self._shape_skipped.get(_fp, set())
        # 内容型页面上"同模板的其余条目"直接从候选里拿掉（不是降权）：
        # 排序只决定先点谁，一屏 20 张卡片最后还是会逐个点完 —— 预算照烧。
        _content_skip = getattr(st, "content_items", None) or set()
        for n in clicks or ():
            if uiwalk.is_dangerous(n) or is_soft_commit(n) or uiwalk.is_no_use(n):
                continue
            u = self.g.uid_for(n)
            if u in st.uids_clicked or u in st.dead or u in _skip or u in _content_skip:
                continue
            # 文档类入口整轮最多打开 N 次（2026-11-10 CNC宝典）：
            # 判"点过没有"用的是本界面记录，而指纹含可见文字/入口数 ——
            # 滚一下或从文档返回一次就变成"另一个界面"，同一份《隐私政策》
            # 会被反复点开。真机实测一轮 5 次《隐私政策》+6 次《用户协议》，
            # 每次都是同一条长文本 WebView，单次 30~90 秒。
            #
            # ★ 超限后**移出候选**而不是降权：降权只是排后面，一屏点完
            #   还是要轮回来，预算照烧（和 `_shape_skipped` 同理）。
            #   也不剔除 `_is_evidence_entry` 的其它入口 —— 只认这份文档本身。
            _dk = _doc_key(getattr(n, "label", "") or "")
            if _dk and _hit(_dk, POLICY_LABEL):
                _lim = (DOC_TAP_LIMIT_READY if self.policy_ready
                        else DOC_TAP_LIMIT_UNREADY)
                if self._doc_taps.get(_dk, 0) >= _lim:
                    if _dk not in self._doc_skipped:
                        self._doc_skipped.add(_dk)
                        if self.log:
                            self.log("[*] 「%s」整轮已打开 %d 次，未取到新内容，"
                                     "后续不再点开（省下的预算给未走过的界面）"
                                     % (_dk[:18], self._doc_taps.get(_dk, 0)))
                    continue
            out.append((n, u))
        return out

    def _content_step(self, st: Any, cands: Sequence[Tuple[Any, str]],
                      clicks: Sequence[Any], nav_uids: Set[str],
                      back_unsafe: bool) -> Step:
        """内容型页面上的处置：抽 1 条 → 滚 1 屏 → 离开。

        ★ 三类动作各自的上限都不是"拍脑袋的省时间"，而是**边际收益已经为零**：
          · 同模板条目的第 2 条起，点开必然是同一套页面（同一次渲染出来的）；
          · 滚第 2 屏起，进来的只会是信息流的下一页（内容更远，结构一样）；
          · 整轮内容页点击到 `CONTENT_TAP_LIMIT` 后，再进= 纯烧预算。
        留 1 条 1 屏是为了一种情况：内容页里可能挂着「分享/收藏」这类会触发
        权限的动作，点一下能取到"是否索权"的事实 —— 这也是一条合规证据。

        两类例外不受上述上限约束（它们不是"内容条目"）：
          · 主导航 tab —— App 的结构骨架，限掉会把遍历困在这一屏；
          · 政策/权利入口 —— 它们本身就是证据，见 `_is_evidence_entry`。
        """
        _fp = getattr(st, "fp", "") or ""
        items = getattr(st, "content_items", None) or set()
        limit = CONTENT_ITEM_SAMPLE if items else 1
        used = len(getattr(st, "uids_clicked", ()) or ())
        # ★ 主导航（底部 tab）永远照常点：它是 App 的结构骨架，不是"内容条目"。
        #   真机上不少 App 的首页/「图片墙」就是信息流 —— 若在这里把 tab 也限掉，
        #   整个遍历会被困在这一屏，连「我的」都进不去。
        _nav = [c for c in cands if c[1] in nav_uids]
        if _nav and used < self.max_taps_per_state:
            best = min(_nav, key=lambda c: (self._rank(c[0], c[1], nav_uids),
                                            _dom_index(clicks, c[0])))
            node, uid = best
            self._tabs_seen.add(uid)
            return Step("tap", node=node, uid=uid, label=(node.label or "")[:40],
                        phase=self.phase, tab=True,
                        reason="%s｜内容型页面上的主导航，照常切换" % self.phase)
        # ★ 抽样上限之上留一道放行：内容页里可能挂着「隐私政策」「注销账号」
        #   「权限管理」这类入口 —— 它们不是同模板内容，是**证据本身**。
        #   抽样逻辑再省也不能把它们一起挡掉（真机上政策入口常藏在文章页底部）。
        _ev = [c for c in cands if _is_evidence_entry(c[0])]
        # ★ 连"整轮内容页点击总预算"也不挡它：政策正文与权利入口是整份报告的依据，
        #   省时间的规则不能省到证据头上（只受单屏点击上限 `max_taps_per_state` 约束）。
        if cands and used < limit and self.content_taps < CONTENT_TAP_LIMIT:
            best = min(cands, key=lambda c: (self._rank(c[0], c[1], nav_uids),
                                             _dom_index(clicks, c[0])))
            node, uid = best
            self._note_shape(st, node, clicks)
            self.content_taps += 1
            if _fp not in self.content_logged:
                self.content_logged.add(_fp)
                try:
                    if self.log:
                        self.log("[*] 内容型页面（%s）：本屏 %d 条同模板条目，"
                                 "只展开 1 条、最多滚 1 屏，其余按同构跳过"
                                 % (st.content_reason or "同模板",
                                    len(items) + (1 if st.content_sample else 0)))
                except Exception:
                    pass
            return Step("tap", node=node, uid=uid, label=(node.label or "")[:40],
                        phase=self.phase, tab=uid in nav_uids,
                        reason="%s｜内容型页面：只抽样 1 条（%s）"
                               % (self.phase, st.content_reason or "同模板"))
        if _ev and used < self.max_taps_per_state:
            best = min(_ev, key=lambda c: (self._rank(c[0], c[1], nav_uids),
                                           _dom_index(clicks, c[0])))
            node, uid = best
            self.content_taps += 1
            return Step("tap", node=node, uid=uid, label=(node.label or "")[:40],
                        phase=self.phase, tab=False,
                        reason="%s｜内容型页面但命中政策/权利入口，照常取证"
                               % self.phase)
        if self._content_scrolls.get(_fp, 0) < CONTENT_SCROLL_MAX:
            return Step("scroll", phase=self.phase,
                        reason="%s｜内容型页面：滚一屏确认结构后离开" % self.phase)
        if self.can_back(back_unsafe):
            return Step("back", phase=self.phase,
                        reason="%s｜内容型页面已取样（%s），不再逐条展开"
                               % (self.phase, st.content_reason or "同模板"))
        return Step("none", phase=self.phase,
                    reason="%s｜内容型页面已取样且无法回退" % self.phase)

    def _note_shape(self, st: Any, node: Any, peers: Sequence[Any]) -> None:
        """记一次"同构项已安排"，并在达到上限时把同组的其余项移出候选。

        ★ 抽样上限到了就把**同组剩下的一次性全部**标掉，而不是每轮标一个：
          逐轮标会让"下一个同构项"始终排在候选第一位（它们排名相同、DOM 序最小），
          于是一屏 20 个卡片还是被点了 20 次 —— 抽样等于没做。
        """
        sig = _same_shape(node)
        if not sig:
            return
        fp = getattr(st, "fp", "") or ""
        cnt = self._shape_count.setdefault(fp, {})
        c = cnt.get(sig, 0) + 1
        cnt[sig] = c
        if c < MAX_SAME_SHAPE:
            return
        skip = self._shape_skipped.setdefault(fp, set())
        _me = self.g.uid_for(node)
        for p in peers or ():
            if _same_shape(p) == sig:
                u = self.g.uid_for(p)
                if u != _me:
                    skip.add(u)
        if c == MAX_SAME_SHAPE:
            try:
                if self.log:
                    self.log("[*] 同构列表项抽样：本屏同类入口「%s」已点 %d 个，"
                             "其余 %d 个按同模板跳过（点进去是同一类页面）"
                             % ((getattr(node, "label", "") or "")[:18], c,
                                max(0, len(skip))))
            except Exception:
                pass

    def _rank(self, node: Any, uid: str, nav_uids: Set[str]) -> Tuple[int, int, int]:
        """排序键：阶段策略 → 价值 → 弹窗按钮次序。越小越先点。"""
        lab = getattr(node, "label", "") or ""
        is_nav = uid in nav_uids
        # ---- ① 回头路：已知落点就在当前路径上（2026-11-10 CNC宝典）----
        #   标题栏里的 App 名称/logo 点一下就回首页。它每屏都在、DOM 序还靠前，
        #   于是调度器一深挖就"顺手"点它，一屏一屏地被拉回根界面 ——
        #   CNC宝典 269 步里有 20 多次点在「数控车床CNC宝典」上，全程在
        #   首页↔详情之间弹跳，一个大功能都没走完。
        #   已知落点已经在栈里 = 这一步只是往回走，而"往回"由 BACK 负责，
        #   不该占用探索预算。排在最后，除非本屏别无他物。
        _tgt = self._tmap.get(uid) if uid else ""
        if _tgt and len(self.stack) > 1 and _tgt in self.stack:
            return (9, value_rank(lab), priority_rank(lab))
        # ---- ② 同意类控件：遍历期一律最后（见 `_CONSENTY` 的说明）----
        if any(w in lab for w in _CONSENTY):
            return (8, value_rank(lab), priority_rank(lab))
        # ---- ③ 点了没反应的入口：也排到最后（2026-11-10 CNC宝典）----
        #   标题栏里的 App 名称/logo 点下去多半只是"回首页"或干脆没反应，
        #   它既没有出边（不是回头路），也不含关键词，于是每回到根界面就重新
        #   变成合法候选。判据用**结果**：上一次点它，落点还是同一屏。
        #   只降权不剔除 —— 它可能是个开关（点第二下才生效）。
        if uid and self._noop_uids.get(uid, 0) >= 1:
            return (9, value_rank(lab), priority_rank(lab))
        # ---- ③' 返回控件：左箭头 / "返回上一级"（2026-11-10 CNC宝典）----
        #   它每屏都在、身份稳定，于是被当成普通入口反复点：一轮 24 次。
        #   点它等于替 App 按 BACK —— 该由 `can_back()` 决定，不该占探索预算。
        #   排在最后而不是剔除：某些页面的唯一出口就是这个箭头，
        #   剔除会让 `_fallback` 以为"本屏无入口"而去按 BACK，反而退出应用。
        try:
            if graphmod.is_back_control(node):
                return (9, value_rank(lab), priority_rank(lab))
        except Exception:
            pass
        if self.phase == ENTRY:
            # 先把导航铺开，同时别漏掉首启弹窗里的"同意/继续"。
            return (0 if is_nav else 1, tab_rank(lab) if is_nav else priority_rank(lab),
                    value_rank(lab))
        if self.phase == SURVEY:
            if is_nav:
                return (0, tab_rank(lab), value_rank(lab))
            return (1, value_rank(lab), priority_rank(lab))
        if self.phase == DEEPEN:
            # ★ 骨架没铺完就不许深挖（2026-11-10）：去过的 tab 已被 `_tab_done`
            #   从候选里滤掉，所以这里还能看到的导航**都是没去过的** ——
            #   它们必须排在所有页内入口之前，否则 4 档（不限层）会一头扎进
            #   第一个 tab 的子树，剩下几个大入口一次都不点。
            if is_nav:
                return (0, tab_rank(lab), value_rank(lab))
            # 政策/协议入口再往后放一层：P2 已单独取过政策正文，这里点进去多半
            # 只是长文本 WebView（真机上甚至是错误页），把预算扔进去不划算。
            #
            # ★ 前提是"正文已经取到"（2026-11-10 CNC宝典）。P2 失败时，
            #   设置页里的「隐私政策」是**最后的补救入口** —— 无条件往后压等于
            #   主动放弃唯一能拿到条款的机会，而整份报告十几项都要靠它。
            #   真机实测该 App：设置页的隐私政策/用户协议/隐私权限设置
            #   三项目前会被压到 rank=2（排在"检查更新"之后）。
            if _hit(lab, POLICY_LABEL) and self.policy_ready:
                return (2, value_rank(lab), priority_rank(lab))
            return (1, value_rank(lab), priority_rank(lab))
        # TARGETED：定向关键词一票优先，其次往"设置/账号/隐私"这类页面走。
        # ★ 只按关键词排是不够的：定向期的起点往往在首页 feed 上，这屏上一个目标词
        #   都没有，排序退化成"按价值猜"，跟深挖期没区别。加一层"路由词"，
        #   让调度器主动往目标所在的那类页面（我的/设置/账号/隐私）靠，
        #   否则定向期 12% 的预算全花在内容浏览页上。
        if _hit(lab, TARGET_KW):
            return (0, 0, value_rank(lab))
        if _hit(lab, TARGET_ROUTE):
            return (1, 0 if is_nav else 1, value_rank(lab))
        return (2, 0 if is_nav else 1, value_rank(lab))

    def _fallback(self, st: Any, back_unsafe: bool) -> Step:
        """本屏没有可点入口时的处置。

        ★ "没得点"有两种完全不同的成因，混在一起会让整轮卡死：

          ① **结构树里一个可点节点都没有**（引导页轮播 / WebView / 加载页）——
             这不是"入口都点完了"，是"屏幕上没有结构可点的东西"。此时纵向滚动
             基本无效（轮播要左右滑才翻页），必须交给调用方的兜底序列
             （滚 → 左右滑 → 返回）。真机实测：赣警办首启是 `GuideActivity`
             的引导页，调度器在这里连滚 19 次，一个界面都没多走。
          ② **有可点节点但全都点过了** —— 这才是"滚动找下文，滚完就回退"。
        """
        if not st.clickable:
            return Step("none", phase=self.phase,
                        reason="%s｜本屏无结构可点节点，交给滑动/返回兜底" % self.phase)
        if not st.scroll_exhausted:
            return Step("scroll", phase=self.phase,
                        reason="%s｜本屏入口已点完，向下找" % self.phase)
        # 已滚到底，但这是列表页 → 再上拉两次。
        # 很多列表（信息流 / 订单 / 消息）要"拉到边界再拉一下"才请求下一页；
        # 只按"滚两次界面没变"收工，后半截列表项永远不会被点到，
        # 而报告会把它读成"这个功能没走完"甚至"没有收集行为"。
        if st.list_like and st.pulls < self.max_pulls:
            return Step("pull", phase=self.phase,
                        reason="%s｜已滚到底，上拉加载下一页（第 %d/%d 次）"
                               % (self.phase, st.pulls + 1, self.max_pulls))
        if self.can_back(back_unsafe):
            return Step("back", phase=self.phase,
                        reason="%s｜本屏已到底，回上一级" % self.phase)
        return Step("none", phase=self.phase,
                    reason="%s｜本屏已到底且无法回退" % self.phase)

    def _tab_done(self, uid: str, nav_uids: Set[str]) -> bool:
        """这个 tab 是不是已经去过了（点它只会回到一个已经访问过的根界面）。"""
        if uid not in nav_uids:
            return False
        target = self._tab_target.get(uid)
        return bool(target) and target in self._tab_fps

    def can_back(self, back_unsafe: bool) -> bool:
        """现在能不能按返回。

        ★ 公开出来是给调用方的兜底序列用的：真机实测第一轮，引导页上"无候选三拍"
          走到第三拍就按了 BACK，App 直接退出、白重启一次。判据必须只有一份，
          否则调度器和三拍会各按各的来 —— 一个说"根界面别按"，一个照样按。
        """
        if self.no_back:
            return False
        if len(self.stack) <= 1:
            # 栈里只剩入口界面：再 BACK 就是退出 App。
            return False
        if back_unsafe:
            # 已知这台设备上 BACK 会把 App 退掉 —— 但那只在**入口界面**成立，
            # 内页 BACK 通常正常。内页也出问题的情形由 `note_back(killed=True)`
            # 的硬止损兜住（两次即彻底禁用）。
            return self.depth > 0
        return True

    # -- 统计 ---------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        found = [n for n, v in self.targets.items() if (v or {}).get("found")]
        _cs = ([s for s in self.g.states.values() if getattr(s, "content", False)]
               if self.g is not None else [])
        return {
            "phase": self.phase,
            "stack_depth": self.depth,
            "taps": self.taps,
            "backs": self.backs,
            "scrolls": self.scrolls,
            "tabs_opened": self.tabs_opened,
            "unique_tabs": len(self._tabs_seen),
            "back_kills": self.back_kills,
            "no_back": self.no_back,
            # 定向期找到了几个权利入口（全部 8 个都找到说明 App 的权利入口做得比较规范；
            # 一个都没有说明要么藏得深、要么本轮预算没走到，报告要分开说）。
            "targets_found": len(found),
            "targets_total": len(TARGETS),
            "drift": self.drift,
            # 动态判：只有"一个 tab 都没点开过"才算没识别出主导航。
            # 用时间来置位会误报 —— tab 常常在 SURVEY 阶段才点到。
            "entry_failed": (self.tabs_opened == 0 and self.taps >= 5),
            # 内容型页面（资讯/文章/商品）的账：识别出几个、跳过了多少同模板条目、
            # 在它们身上花了多少次点击。报告要能回答"为什么这些入口没点"。
            "content_pages": len(_cs),
            "content_items_skipped": sum(len(getattr(s, "content_items", ()) or ())
                                         for s in _cs),
            "content_taps": self.content_taps,
            "phase_taps": dict(self.phase_taps),
        }

    def summary_line(self) -> str:
        s = self.stats()
        tabs = ("，其中主导航 %d" % s["tabs_opened"]) if s["tabs_opened"] else ""
        tail = ""
        if s["no_back"]:
            tail = "｜BACK 已停用，遍历深度受限"
        elif s["entry_failed"]:
            tail = "｜未识别出主导航，按时间推进"
        if s["drift"]:
            tail += "｜界面漂移 %d 次（有拦截页插队）" % s["drift"]
        tgt = ""
        if s["targets_found"] or s["phase"] == TARGETED:
            tgt = "｜权利入口找到 %d/%d" % (s["targets_found"], s["targets_total"])
        ct = ""
        if s.get("content_pages"):
            ct = ("｜内容型页面 %d 个（同构跳过 %d 条）"
                  % (s["content_pages"], s.get("content_items_skipped") or 0))
        return ("遍历调度：点击 %d 次%s ｜ 回退 %d 次 ｜ 滚动 %d 次 ｜ 最大栈深 %d%s%s%s"
                % (s["taps"], tabs, s["backs"], s["scrolls"], s["stack_depth"],
                   tgt, ct, tail))


def _dom_index(clicks: Sequence[Any], node: Any) -> int:
    """同分时按 DOM 顺序 —— 界面上排在前面的先点，这个次序对用户是可解释的。"""
    for i, n in enumerate(clicks or ()):
        if n is node:
            return i
    b = tuple(getattr(node, "bounds", ()) or ())
    for i, n in enumerate(clicks or ()):
        if b and tuple(n.bounds) == b:
            return i
    return 1 << 20


def _why(label: str, phase: str) -> str:
    """一句话说明为什么点它（进日志，事后能核对决策而不是只能看到结果）。"""
    lab = label or ""
    if phase == TARGETED and _hit(lab, TARGET_KW):
        return "定向命中"
    if phase == TARGETED and _hit(lab, TARGET_ROUTE):
        return "定向路由"
    if _hit(lab, HIGH_VALUE):
        return "高价值入口"
    if _hit(lab, MID_VALUE):
        return "收集类功能"
    if _hit(lab, NOISE):
        return "运营位（排后）"
    return "普通入口"
