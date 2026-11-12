"""内容型列表 / 内容页识别：资讯、文章、视频、商品这类「同模板重复」的浏览型页面。

## 为什么需要单独一层判别

真机实测（2026-11-02 川剧迷 `com.couplower.chuan`，1 小时档）：整轮 3683 秒里
**2948 秒（80%）**花在 `web.WebActivity` 上。`图片墙` 信息流的卡片点开就是
`mp.weixin.qq.com` 的公众号文章，页面里除了正文只有「兼容模式 / 分享」两个按钮，
和合规检测毫无关系；89 次点击里有 50 多次落在这些文章的 `FrameLayout` 上。

`crawl._same_shape` 抓不住这种情况：它只认两种铁证（resource_id 数字后缀、
≥8 字长文本）。WebView 里的卡片 `<FrameLayout>` **既没有 text 也没有 id**，
label 退化成类名，同构签名恒为 `cls:FrameLayout`；而且点进下一个列表时已经是
**另一个 fp**，按 fp 记账的抽样计数重新归零 —— 于是"抽样"形同不存在。

所以判别必须放在**页面级**，并且允许两个来源：

  ① 静态判据（本模块 `classify`）：页面结构 + 文字 + 容器，当场判；
  ② 反馈判据（`crawl` 的父界面回溯）：点进去一条，发现是内容页，就回来把
     **同一模板的其余条目**一次性标掉 —— 这正是"看一个就够"的实现方式，
     也能覆盖「戏曲名 / 商品名」这种 2~4 字短标题的列表（静态判据刻意不认它们）。

## 判据为什么这么保守

判错的代价是**整整一类入口被漏点**，而这份报告的价值全靠"该测的都测到了"。
所以只判"内容"需要同时满足：同模板重复（≥3 条、纵向堆叠、尺寸一致）、
条目里没有功能词（设置/账号/隐私/权限/注销…）、以及内容侧的旁证
（第三方内容平台域名 / 内容页外壳字样 / 长标题 / 卡片高度像文章卡）。

「设置」页那种 2~4 字短标签、行高只有 100 多像素的列表**不会**被判成内容 ——
那里每一项都是一条不同的合规事实。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ------------------------------------------------------------------ 词表

# 第三方内容平台域名。页面上出现这些字样，基本可以认定"当前读的是站外内容"。
# ★ 为什么不只认 weixin：真机上资讯/商品页的主机五花八门，但**壳**是同一套。
#   反过来，App 自己的政策页极少挂在内容平台上 —— 所以这条信号精度很高。
CONTENT_HOSTS: Tuple[str, ...] = (
    "mp.weixin.qq.com", "weixin.qq.com", "toutiao.com", "baijiahao.baidu.com",
    "weibo.com", "weibo.cn", "xiaohongshu.com", "zhihu.com", "bilibili.com",
    "douyin.com", "kuaishou.com", "taobao.com", "tmall.com", "jd.com",
    "pinduoduo.com", "yangkeduo.com", "meituan.com", "dianping.com",
    "sohu.com", "163.com/news", "sina.com.cn", "qq.com/news", "ifeng.com",
)

# 内容页的"外壳"字样：这些是阅读器/内嵌浏览器的 chrome，业务页面不会有。
CONTENT_CHROME: Tuple[str, ...] = (
    "兼容模式", "阅读原文", "网页由", "复制链接", "在浏览器打开",
    "上一篇", "下一篇", "字号", "夜间模式", "回到顶部",
)

# 内容侧文字。刻意收窄到"阅读/购买行为"才出现的词，避免"信息""管理"这类泛词。
CONTENT_KW: Tuple[str, ...] = (
    "阅读", "评论", "点赞", "在看", "转发", "收藏", "发布于", "来源", "作者",
    "编辑", "责编", "资讯", "新闻", "推荐", "热门", "排行", "榜单", "专题",
    "直播", "播放", "时长", "粉丝", "关注", "¥", "￥", "价格", "销量", "已售",
    "加入购物车", "立即购买", "包邮", "库存", "规格", "优惠券", "原价",
)

# 功能侧文字：出现两个以上就**不是**内容列表（那是设置/账号/权限页）。
FUNC_KW: Tuple[str, ...] = (
    "设置", "账号与安全", "隐私", "权限管理", "注销", "退出登录", "修改密码",
    "清除缓存", "清理缓存", "关于我们", "意见反馈", "消息通知", "个性化推荐",
    "实名认证", "授权管理", "免密支付", "地址管理", "检查更新", "帮助中心",
    "用户协议", "服务协议", "隐私政策", "绑定手机", "切换账号", "充值",
)

# 政策/协议页的护栏：**政策正文可能就挂在公众号文章里**（不少 App 这么干），
# 这类页面绝不能因为"看起来像内容"被跳过 —— 它是整份报告的依据。
# 与 `crawl.POLICY_DOC` 保持超集关系（有离线用例卡这条）。
POLICY_GUARD: Tuple[str, ...] = (
    "隐私政策", "隐私协议", "隐私权", "隐私条款", "个人信息保护", "个人信息处理",
    "用户协议", "服务协议", "用户服务协议", "儿童个人信息", "协议与规则",
)

# 权利入口护栏：这些条目哪怕落在内容列表里也必须照常点（不能算同构跳过）。
# ★ 与 `crawl.TARGETS` 的关键词保持超集关系（有离线用例卡这条）：定向期要找的
#   8 类权利入口一个都不能被"同构"顺手抹掉。
TARGET_GUARD: Tuple[str, ...] = (
    "注销", "撤回", "撤销授权", "更正", "删除", "副本", "导出",
    "第三方共享", "共享清单", "第三方信息", "收集清单", "已收集",
    "权限管理", "系统权限", "授权管理", "个人信息", "个性化推荐",
    "个性化广告", "定向推送", "猜你喜欢",
    "投诉", "举报", "意见反馈", "问题反馈", "投诉建议",
)

# 同模板判定参数
MIN_GROUP = 3          # 一列里至少几条同模板条目才算"列表"
TALL_RATIO = 0.09      # 条目高度 / 屏高：资讯卡通常 ≥0.12，设置行约 0.05
_X_TOL = 48            # 同一列的 x1 容差（两列网格的列间距远大于它）
_OVERLAP_TOL = 12      # 纵向相邻两条允许的微小重叠（阴影/分割线）


@dataclass
class Verdict:
    """一次判别结果。`kind=""` 表示"不是内容型页面"。"""

    kind: str = ""                     # "content" | ""
    reason: str = ""                   # 中文原因（进日志与报告）
    items: List[Any] = field(default_factory=list)   # 同模板条目（含 sample）
    sample: Any = None                 # 建议保留抽样的一条
    web: bool = False                  # 是否内嵌网页
    host: str = ""                     # 命中的内容平台域名

    @property
    def total(self) -> int:
        return len(self.items)

    @property
    def skipped(self) -> List[Any]:
        """除抽样样本外、可以按同构跳过的条目。"""
        return [n for n in self.items if n is not self.sample]


# ------------------------------------------------------------------ 工具

def _label(n: Any) -> str:
    """节点的可见文字（text 优先，其次 content-desc）—— 不看 id。

    ★ 不能直接用 `UiNode.label`：它在没有文字时会退回 resource-id 甚至类名，
      而这里正是要区分"有没有文字"（`FrameLayout` 这种占位 label 必须当成空）。
    """
    return ((getattr(n, "text", "") or "").strip()
            or (getattr(n, "content_desc", "") or "").strip())


def _cls(n: Any) -> str:
    return (getattr(n, "cls", "") or "").split(".")[-1]


def _bounds(n: Any) -> Tuple[int, int, int, int]:
    b = getattr(n, "bounds", None) or (0, 0, 0, 0)
    try:
        return int(b[0]), int(b[1]), int(b[2]), int(b[3])
    except Exception:
        return 0, 0, 0, 0


def _w(n: Any) -> int:
    x1, _, x2, _ = _bounds(n)
    return max(0, x2 - x1)


def _h(n: Any) -> int:
    _, y1, _, y2 = _bounds(n)
    return max(0, y2 - y1)


def _hit(text: str, words: Sequence[str]) -> bool:
    return bool(text) and any(w in text for w in words)


def is_web_container(activity: str, clicks: Sequence[Any] = ()) -> bool:
    """这一屏是不是内嵌网页（WebView / H5 容器）。

    ★ 只说明"是网页"，**不能**据此判内容：隐私政策也常挂在 WebPureActivity 里。
      川剧迷首启的政策页正是 `web.WebPureActivity`。
    """
    act = (activity or "").lower()
    if any(k in act for k in ("webactivity", "webview", "webpure", "browseractivity",
                              "h5", "appbrandui", "tbsactivity")):
        return True
    return any("webview" in _cls(n).lower() for n in clicks or ())


def _columns(nodes: Sequence[Any]) -> List[List[Any]]:
    """把同模板节点切成"竖向列"。

    ★ 必须先分列再判重复：两列网格（图片墙、商品网格）里同一行的两张卡片
      x1 不同、y 相同，直接按 DOM 序当一列会被"y 不递增"否掉，
      于是一个真实的内容网格被拆成一堆 len=2 的碎片、永远判不出来。
    """
    out: List[List[Any]] = []
    used: set = set()
    ordered = sorted(nodes, key=lambda n: (_bounds(n)[1], _bounds(n)[0]))
    for i, n in enumerate(ordered):
        if i in used:
            continue
        x1 = _bounds(n)[0]
        col = [n]
        used.add(i)
        for j in range(i + 1, len(ordered)):
            if j in used:
                continue
            m = ordered[j]
            if abs(_bounds(m)[0] - x1) > _X_TOL:
                continue
            prev = col[-1]
            if _bounds(m)[1] < _bounds(prev)[3] - _OVERLAP_TOL:
                continue          # 纵向重叠 → 是同一卡片里的子元素，不是下一条
            col.append(m)
            used.add(j)
        out.append(col)
    return out


def _groups(clicks: Sequence[Any], loose: bool = False) -> List[List[Any]]:
    """找出"同模板重复"的条目列（每组 ≥ MIN_GROUP 条）。

    `loose=True` 时只按 (类名, 宽) 分桶、不要求等高 —— 用于**已有证据**的场景
    （点进去确认是站外内容页了，回头看父界面还有哪些同模板条目）。真机实测
    图片墙是两列不等高的瀑布流：等高分桶会把每张卡片都切成独立的 1~2 条组，
    永远凑不出 3 条，抽样就完全失效。
    """
    buckets: Dict[Tuple[str, int, int], List[Any]] = {}
    for n in clicks or ():
        w, h = _w(n), _h(n)
        # 24px 以下的小控件（图标按钮、勾选框）不参与"同模板条目"：
        # 一列同尺寸的小图标（点赞/评论/分享）会被误当成内容条目。
        if w < 24 or h < 24:
            continue
        # 宽高按 12px 分桶：同一模板渲染出的卡片偶尔差几像素（阴影/边框）。
        key = (_cls(n), w // 12) if loose else (_cls(n), w // 12, h // 12)
        buckets.setdefault(key, []).append(n)
    out: List[List[Any]] = []
    for _key, members in buckets.items():
        if len(members) < MIN_GROUP:
            continue
        if loose:
            # 宽松模式把同一模板的各列合起来算一组（瀑布流通常两列）。
            cols = [c for c in _columns(members) if len(c) >= 2]
            merged = [n for c in cols for n in c]
            if len(merged) >= MIN_GROUP:
                out.append(merged)
            continue
        for col in _columns(members):
            if len(col) >= MIN_GROUP:
                out.append(col)
    # 条目多的组先判：真列表通常 5~20 条，碎片组只有 3 条。
    out.sort(key=len, reverse=True)
    return out


def _host_of(text: str) -> str:
    for h in CONTENT_HOSTS:
        if h in (text or "").lower():
            return h
    return ""


def _median(xs: Sequence[int]) -> int:
    if not xs:
        return 0
    s = sorted(xs)
    return s[len(s) // 2]


def _judge_group(col: Sequence[Any], *, web: bool, host: str, chrome: int,
                 kw: int, screen_h: int) -> Optional[Verdict]:
    """判一列同模板条目是不是"内容条目"。判不出返回 None。"""
    labels = [_label(n) for n in col]
    # 功能词过多 → 这是设置/账号页，不是内容列表。
    func = sum(1 for lab in labels if lab and _hit(lab, FUNC_KW))
    if func >= max(2, len(labels) // 3):
        return None
    # "像标题"的比例：空文字（纯图片卡）或 ≥8 字（文章/商品标题）。
    rich = sum(1 for lab in labels if len(lab) < 2 or len(lab) >= 8) / float(len(labels))
    med_h = _median([_h(n) for n in col])
    tall = (med_h / float(screen_h) >= TALL_RATIO) if screen_h else med_h >= 150
    confident = bool(host) or (web and chrome >= 2)
    if confident:
        ok = rich >= 0.5 or tall
    elif web:
        ok = rich >= 0.6 and (tall or kw >= 2)
    else:
        # 原生列表：要求更严 —— 标题要长、卡片要像文章卡、条目至少 4 条。
        ok = rich >= 0.7 and tall and len(col) >= 4
    if not ok:
        return None
    items = [n for n in col if not _never_skip(_label(n))]
    if len(items) < MIN_GROUP:
        return None
    why = ("内容平台（%s）" % host) if host else ("内嵌网页内容页" if web else "同模板内容列表")
    return Verdict(kind="content", reason=why, items=items,
                   sample=items[0], web=web, host=host)


def _never_skip(label: str) -> bool:
    """这条即使落在内容列表里也必须照常点（政策/权利入口）。"""
    return _hit(label, POLICY_GUARD) or _hit(label, TARGET_GUARD)


# ------------------------------------------------------------------ 判据

def classify(activity: str = "", clicks: Sequence[Any] = (),
             texts: Sequence[str] = (), screen_h: int = 0) -> Verdict:
    """判这一屏是不是内容型页面。

    返回 `Verdict.kind == "content"` 时：
      · `items` 是同模板条目（可能为空：文章详情页没有条目）；
      · `sample` 是唯一建议点开的那一条，其余由调度器直接跳过。
    """
    nodes = [n for n in clicks or () if _cls(n)]
    if not nodes:
        return Verdict()
    txt = " ".join(t for t in (texts or ()) if t)
    if not txt:
        txt = " ".join(_label(n) for n in nodes)
    # 政策页护栏：宁可把它当普通页面继续走，也不能误判成内容跳过。
    if _hit(txt, POLICY_GUARD):
        return Verdict(reason="政策/协议页（不按内容跳过）")

    web = is_web_container(activity, nodes)
    host = _host_of(txt)
    chrome = sum(1 for c in CONTENT_CHROME if c in txt)
    kw = sum(1 for c in CONTENT_KW if c in txt)

    for col in _groups(nodes):
        v = _judge_group(col, web=web, host=host, chrome=chrome, kw=kw,
                         screen_h=screen_h)
        if v is not None:
            return v

    # 整页式内容页（文章详情 / 商品详情）：没有重复条目，但壳与文字都在说"这是内容"。
    if (host or (web and chrome >= 2)) and kw >= 1:
        return Verdict(kind="content",
                       reason=("内容平台（%s）" % host) if host else "内嵌网页内容页",
                       items=[], sample=None, web=web, host=host)
    return Verdict(web=web, host=host)


def template_items(clicks: Sequence[Any], loose: bool = False) -> List[Any]:
    """本屏最大的那组"同模板条目"（没有就返回空）。

    给调度器在点击**之前**记一份：落点结算时用它反推父界面上还有哪些同构条目
    （见 `crawl.Scheduler._learn_content_parent`）。那条路是"已经有证据"的，
    所以用 `loose=True`（不等高也算同模板，覆盖瀑布流）。
    """
    for col in _groups([n for n in clicks or ()], loose=loose):
        return list(col)
    return []


def content_texts(texts: Sequence[str]) -> bool:
    """页面文字里有没有内容侧旁证（给调用方在"父界面回溯"时用）。"""
    return _hit(" ".join(t for t in texts or () if t), CONTENT_KW)
