"""首启着陆（P3.5）：从「点了同意」到「站在主页面」之间那一段。

## 为什么必须单独有一个阶段

同意之后的界面**不是功能界面**，而是应用自己的首启流程。2026-11-05 在四台单子上
实测到的形态（同一个采集器、同一批 APK）：

| App | 同意后立刻落到 | 形态 |
|---|---|---|
| 携船网 | `pages/expand/entry/guide` + 「跳过:」+ `00 s` 倒计时 | 开屏广告 |
| 高途 | 「由于您未满14岁…」+「退出App / 监护人已同意」 | 年龄门 |
| 春雨诊所 | 「欢迎使用春雨诊所」+ 手机号 / 密码 | 登录页 |
| 万步健康 | 「用户名/昵称/手机 / 密码 / 注册」 | 登录页 |

拿通用遍历去"闯"这一段，代价不是多花几步，而是**整份报告作废**：
  · 点中开屏广告主体 → 跳到电商页/应用商店，后面几十屏全是别人的界面；
  · 兴趣选择页被逐个点标签 → 等于我们替用户做了个人信息处理决定，
    而且写进了画像，后续"个性化推荐"类判定全部失真；
  · 版本更新弹窗点「立即更新」→ 被测对象被换掉了，本轮结论不可比。

所以这一段的目标只有一个：**把 App 稳稳带到主页面**，不探索、不取证功能。
进了主页面再交给 `_walk_ui` 去做功能遍历。

## 三条硬规矩

1. **能点什么由「敢点清单」决定，不是「除了禁点都能点」。**
   遍历阶段错了只浪费一步；着陆阶段错了，后面全部白跑。两个阶段的安全
   等级不同，不能用同一套候选逻辑。

2. **广告主体、兴趣标签、更新按钮一律不点。** 见 `forbidden()`。这不是保守，
   是这三类动作的**副作用不可逆**（外跳 / 写画像 / 换被测对象）。

3. **AI 只给建议，不给决定。** 模型选的任何目标都要再过一遍 `forbidden()`；
   本地判据（形态分类）与模型冲突时，**以本地为准**，把分歧写进日志给人看。

## 与其它模块的分工

  · `uiwalk` 负责"这一屏有哪些可点节点、怎么点、怎么 dumpxml"（执行层）；
  · 本模块只做**判读与决策**（纯函数，无 IO），所以能离线全量回归；
  · `collector._landing()` 负责按本模块的决定去执行、结算、留痕。

纯函数的好处很实际：形态分类写错了，离线用例能立刻抓住，不必上真机跑 8 分钟
才发现"把登录页当成促销弹窗关掉了"。
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import uiwalk

# ============================================================ 形态定义
# 键是给代码看的，值里的 name 是给报告读者看的（不许出现内部黑话）。
FORMS: Dict[str, Dict[str, str]] = {
    "system_perm": {
        "name": "系统权限弹窗",
        "desc": "Android 系统弹出的权限申请框，不是应用自己的界面。",
    },
    "age_gate": {
        "name": "年龄门 / 青少年模式",
        "desc": "要求确认年龄或监护人同意后才能继续，通常带「退出App」。",
    },
    "update_dialog": {
        "name": "版本更新弹窗",
        "desc": "提示有新版本，带「立即更新 / 稍后再说」。",
    },
    "promo_dialog": {
        "name": "促销 / 活动弹窗",
        "desc": "浮在页面之上的运营弹窗（红包、会员、优惠券、活动）。",
    },
    "splash_ad": {
        "name": "开屏广告页",
        "desc": "全屏广告，角上有「跳过」和倒计时；点广告主体会外跳。",
    },
    # ★ 纯品牌启动页（2026-11-06 补）：SplashActivity 只放 logo / 动画，
    #   没有任何可点元素，也没有「跳过」。这是 Android 应用最常见的启动形态
    #   （官方文档也建议 SplashActivity 只做"读本地 token"这一件事）。
    #   没有这一类的话，它会被判成 unknown → 走"按返回找上一级" →
    #   **直接把应用退到桌面**，然后重拉、再退，整轮预算烧在"启动页与桌面之间"。
    "splash_wait": {
        "name": "启动 / 加载页",
        "desc": "只有品牌标识或加载动画，没有可点元素；应当等它自己跳转。",
    },
    "interest_picker": {
        "name": "兴趣 / 偏好选择页",
        "desc": "让用户勾选感兴趣的内容，用来建立画像。",
    },
    # ★ 地区/城市选择（2026-11-06 补）：外卖、打车、资讯、本地服务类首次启动
    #   常要先选城市，不选就进不去。它和兴趣选择在**处置上同类**：选哪个都是在
    #   替用户做个人信息处理决定（位置偏好），所以只找「跳过/暂不」，没有就停。
    "region_picker": {
        "name": "地区 / 城市选择页",
        "desc": "要求先选城市或地区才能继续；选择结果会写入位置偏好。",
    },
    # ★ 调研 / 问卷页（2026-11-06 高途实测，用户反馈）：首启向用户发问卷
    #   —— 选学段（小学→成人教育）/ 身份角色 / 使用目的，底部「进入首页」。
    #   它与兴趣标签页的**业务设计不同**：兴趣页是"可跳过的多选画像云"，
    #   调研页是"必答的单选门槛"，不选就进不了主页面。以前没有这一类，
    #   它被当成普通功能页遍历：选项被逐个当"入口"点过去，「进入首页」
    #   倒是碰巧点到了，但整页问卷的证据（首启即收集画像）被打散在
    #   遍历轨迹里，读者看不出这是一道问卷。处置改为**模仿真实用户**：
    #   选一个选项、再点提交 —— 两次点击各留一条痕。
    "survey_gate": {
        "name": "调研 / 选择页",
        "desc": "首启问卷（学段 / 身份 / 使用目的等），选一项后提交即可继续。",
    },
    "guide_pager": {
        "name": "欢迎引导页",
        "desc": "一屏一屏的功能介绍，要靠左滑或「跳过 / 开始使用」走出去。",
    },
    "perm_guide": {
        "name": "权限引导页",
        "desc": "应用自绘的权限说明页，带「去开启 / 暂不开启」。",
    },
    "login": {
        "name": "登录 / 注册页",
        "desc": "要手机号或账号密码；没有测试账号时只能到此为止。",
    },
    # ★ 实名 / 资质认证（2026-11-06 春雨诊所实测）：登录成功后不是主页面，
    #   而是一屏「实名认证」——要姓名、执业科室、职称、医院、执业证件照、
    #   人脸认证、手写签名。医疗、金融、招聘、网约车这类应用普遍如此。
    #   这一步**过不去**，也**不该过**：往里填的是别人的真实身份信息，
    #   做出来的人脸/证件/签名也不是检测该碰的东西。
    #   所以它和 login 一样属于"结构上确定没到主页面"，而且要一次说清原因，
    #   不能像"未识别界面"那样被模型带着到处点。
    "realname_gate": {
        "name": "实名 / 资质认证页",
        "desc": "要求实名信息、证件照或人脸认证；检测方不具备该条件，只能到此为止。",
    },
    "home": {
        "name": "主页面",
        "desc": "已进入应用的常规界面，可以开始功能遍历。",
    },
    "unknown": {
        "name": "未识别的界面",
        "desc": "形态判据都没命中，交给 AI 看一眼再决定。",
    },
}
FORM_ORDER = tuple(FORMS.keys())

# 门禁形态（gate）：这些形态**本身就是"还没到主页面"的结构证据**。
#
# ★ 为什么需要这一份（2026-11-06 春雨诊所实测）：
#   在登录墙上，本地判据给出的是 `give_up / login_wall`（"没账号，到此为止"），
#   而模型看截图说"我已经到底部了"——于是模型答案把 `give_up` 顶掉，改成
#   `done`；本地又不肯把登录页认成首页，于是一轮轮"再确认"，同一屏问了模型
#   5 次、白烧 10 步、92 秒，最后仍停在登录页。
#   根子上是**两类证据的强弱搞反了**：
#     · "这一屏有手机号输入框 + 密码框 + 注册/登录按钮" —— 结构事实，确定；
#     · "截图看起来像首页" —— 视觉猜测，在有门禁形态时必然采信错误的那一类。
#   所以：门禁形态下模型**没有资格**说 done，本地 give_up 必须生效。
#   只有 `unknown`（本地什么都没认出来）/ `home` 才允许视觉判断推翻本地。
GATE_FORMS: Tuple[str, ...] = (
    "system_perm", "age_gate", "update_dialog", "promo_dialog", "splash_ad",
    "interest_picker", "region_picker", "guide_pager", "perm_guide", "login",
    "realname_gate", "survey_gate",
)


def is_gate(form: str) -> bool:
    """这个形态是否属于"结构上确定还没到主页面"。"""
    return form in GATE_FORMS


def form_name(form: str) -> str:
    return (FORMS.get(form) or FORMS["unknown"])["name"]


# ============================================================ 词表
# 关闭类：这些词点下去是"把这一层收掉"，副作用最小，所以排在最前面。
# 顺序即优先级：「跳过」比「取消」好（取消有时会退掉整个流程）。
_CLOSE_WORDS: Tuple[str, ...] = (
    "跳过广告", "跳过", "关闭广告", "关闭", "我知道了", "知道了", "知道啦",
    "以后再说", "下次再说", "暂不需要", "暂不", "稍后", "残忍拒绝",
    "不再提示", "放弃", "取消", "返回",
)

# 推进类：把这些步骤走完才能进主页面（引导页的「开始使用」、年龄门的
# 「监护人已同意」）。**注意不含「立即领取」「立即购买」**，那类在禁点表里。
_ADVANCE_WORDS: Tuple[str, ...] = (
    "开始使用", "立即体验", "开始体验", "进入应用", "立即进入", "进入首页",
    "开始探索", "已满14", "已满 14", "我已满", "监护人已同意", "已完成",
    "完成", "下一步", "进入",
    # 与 `_GUIDE_WORDS` 对齐：引导页上那两个词既是"这屏是引导页"的证据，
    # 也常常就是那个按钮本身（高途的「开启学习探索之旅」）。词表不对齐的
    # 后果很实际：判成引导页却找不到按钮，只能去左滑。
    "开启学习", "探索之旅", "开启个性化", "开启旅程",
)

# 单个符号形态的关闭按钮。lower() 之后比较，只认这些确定含义的字符。
_CLOSE_GLYPHS = frozenset(("x", "×", "✕", "╳", "✖", "close", "关闭"))

# ------------------------------------------------------------------ 禁点
# ① **副作用不可逆**：外跳 / 开始下载 / 换掉被测对象。
#    高途 2026-11-05 实测：开屏页的广告主体点下去直接进应用商店下载页，
#    之后的界面与"被检测应用"毫无关系，报告里那几十屏全是噪声。
_FORBIDDEN_IRREVERSIBLE: Tuple[str, ...] = (
    "下载", "安装", "立即更新", "马上升级", "去更新", "升级版本",
    "立即购买", "立即领取", "马上抢", "领红包", "开通会员", "去开通",
    "打开看看", "去看看", "了解更多", "查看详情", "了解详情",
    # 发短信/打电话这类"点一下就到外面去"的动作：着陆阶段一律不做。
    # 2026-11-06 春雨诊所实测：登录成功后又绕回登录页，着陆把「获取短信验证码」
    # 当成出路点了一次 —— 真发了一条短信出去（设备收件箱能查到）。
    # 验证码该由登录辅助（`_login_assist`）负责，它知道什么时候发、发几次；
    # 着陆只负责"走过去"，不该有任何对外副作用。
    "获取短信验证码", "获取验证码", "重新获取", "发送验证码", "获取动态码",
    "拨打", "呼叫",
)

# ② 兴趣 / 偏好标签：点了就是把偏好写进画像。我们不是真实用户，
#    代选等于伪造证据 —— 而且会影响"个性化推荐是否默认开启"这类判定。
#    这类只在 interest_picker 形态下拦截（见 forbidden），因为"兴趣"两个字
#    在普通页面上也可能出现。
# 游客 / 跳过登录入口：这类按钮是**正当的绕过路径**，不是"代填账号"。
# 很多 App 的登录页右下角写着「随便逛逛」「暂不登录」，点了就能以未登录状态
# 进主页面 —— 这正是我们要的落地效果。以前 landing 在登录页一律 give_up，
# 等于把这条最省事的路径白白丢掉，然后报告写"登录墙"。
_GUEST_WORDS: Tuple[str, ...] = (
    "暂不登录", "先不登录", "不登录", "随便逛逛", "先逛逛", "逛逛再说",
    "游客模式", "以游客", "游客登录", "先体验", "稍后登录", "跳过登录",
    "以后再说", "暂不", "跳过", "先看看",
)
_INTEREST_ONLY_CLOSE: Tuple[str, ...] = _CLOSE_WORDS + ("暂不设置", "不感兴趣", "随便看看")


def _texts_of(node: Any) -> str:
    """节点的可读文字（含 resource id 的尾巴，因为很多按钮只有 id）。"""
    return " ".join(x for x in (
        str(getattr(node, "text", "") or ""),
        str(getattr(node, "content_desc", "") or ""),
        str(getattr(node, "resource_id", "") or "").split("/")[-1],
    ) if x).strip()


def _hit(label: str, words: Sequence[str]) -> str:
    """在 label 里找命中词，返回命中的那个（长词优先，避免「关闭」抢先于「关闭广告」）。"""
    low = (label or "").strip().lower()
    if not low:
        return ""
    for w in sorted(words, key=len, reverse=True):
        if w.lower() in low:
            return w
    return ""


def _is_close_glyph(label: str) -> bool:
    low = (label or "").strip().lower()
    return bool(low) and low in _CLOSE_GLYPHS


# ============================================================ 形态分类
# 分类顺序：
#   1. 系统权限框 —— 它不是应用页面，别的一概不谈；
#   2. 年龄门 —— 必须先判，因为它带「退出App」，误当促销弹窗会点错；
#   3. 更新 / 促销弹窗 —— 弹窗浮在页面之上，先判它才看得清底下是什么；
#   4. 开屏广告 —— 带跳过与倒计时；
#   5. 兴趣选择 → 登录 → 引导页；
#   6. 主页面。
# 顺序本身就是判据的一部分：把 login 提到 guide 前面，才不会因为标题
# 写着「欢迎使用」就把登录页当引导页（反之则不会漏）。

_AGE_WORDS = ("未满14", "未满 14", "已满14", "已满 14", "青少年", "监护人",
              "家长同意", "未成年人")
# 实名 / 资质认证（2026-11-06 春雨诊所）。判据要求**两个词同现**：
# 政策正文里也常出现"实名认证"，单个词就判会把政策页认成认证墙。
_REALNAME_WORDS = ("实名认证", "实名信息", "人脸识别", "人脸认证", "身份认证",
                   "执业证", "执业信息", "证件照", "身份证", "手写签名",
                   "资质认证", "上传证件")
# 只有"强词"出现才算认证墙。弱词（人脸识别/证件照/上传证件…）在**权限说明页**
# 里到处都是：春雨诊所的「授权提示」写着"注册时上传证件照片……人脸识别时需要该权限"，
# 三个弱词同时命中，于是被误判成实名认证墙，着陆在 2.9 秒就收工了
# （2026-11-06 land27 实测，还是靠人看截图才发现的）。
_REALNAME_STRONG = ("实名认证", "实名信息", "身份认证", "资质认证",
                    "执业资格", "执业信息")
_UPDATE_WORDS = ("新版本", "发现新版本", "立即更新", "版本更新", "马上升级",
                 "升级到最新", "有新版本")
# ★ 这里刻意用**具体组合**而不是"活动""会员"这类单字词（2026-11-06 高途实测）：
#   高途第 3 步只因界面上有"活动"两个字就被判成促销弹窗（实际是剪切板授权框）。
#   判形态比判结论更容易被单个常用词带偏，所以宁可用长词、多词。
_PROMO_WORDS = ("限时活动", "活动期间", "活动仅剩", "红包", "优惠券", "开通会员",
                "会员专享", "礼包", "抽奖", "签到领", "首单立减", "特惠",
                "折扣", "立即领取", "福利", "新人专享", "免费领取")
_SPLASH_WORDS = ("跳过", "跳过广告", "广告")
# ★ 「欢迎使用」不在引导页词表里（2026-11-06 离线用例抓到）：
#   春雨诊所的**登录页**标题就是「欢迎使用春雨诊所 / 自由执业，从春雨开始」，
#   拿它当引导页证据，会把登录页判成引导页 → 然后去左滑一个登录页，
#   永远滑不出主页面。引导页的硬证据是"跳过/开始使用/上滑左滑"，不是"欢迎"。
_GUIDE_WORDS = ("开始使用", "立即体验", "开始体验", "新手引导", "功能介绍",
                "上滑", "左滑", "下一步",
                # 高途 2026-11-06 实测：引导页的按钮是「开启学习探索之旅」，
                # 不在上面任何一个词里，于是整屏被判成「未识别」交给模型。
                # 模型猜对了，但这类文案很常见，本地就该认得。
                "开启学习", "探索之旅", "开始探索", "进入首页", "开启个性化")
# ★ 不用「请选择你 / 请选择您」这种半截句（2026-11-06）：城市选择页的
#   「请选择你所在的城市」会先被它抢走，然后按"兴趣页"处置 —— 结论碰巧一样，
#   但报告会把"选城市"写成"选兴趣"，是事实错误。
_INTEREST_WORDS = ("选择你感兴趣", "选择您感兴趣",
                   "选择你的兴趣", "选择您的兴趣", "你想看什么", "您想看什么",
                   "至少选择", "兴趣标签", "定制你的", "定制您的", "选择感兴趣")
_PERM_WORDS = ("权限", "允许", "开启定位", "开启通知", "去开启", "暂不开启")
# 地区选择：同样用"半句祈使"的写法，避免把普通页面上的"城市"当成它
_REGION_WORDS = ("选择城市", "选择地区", "请选择城市", "请选择地区", "定位城市",
                 "当前城市", "手动选择城市", "切换城市", "所在城市",
                 "选择你所在", "选择您所在", "所在地区", "选择收货地址")
# ============================================================ 调研 / 问卷页
# 2026-11-06 高途实测（用户反馈）：首启学段选择页（小学→成人教育 + 「进入首页」）。
# 业务上这是一道**必答门槛**：不选就进不了主页面，和"可跳过的兴趣云"不是一种设计。
# 常见的问法（调研自 196 份报告与主流 App 首启流程）：
#   · 教育类：学段 / 年级 / 学习阶段（高途、作业帮）
#   · 双角色类：您是——我是学生 / 我是家长 / 我是老师（家长端 App）
#   · 工具/内容类：使用目的 / 为什么使用我们
#   · 垂直行业：您的身份——货主 / 司机 / 船员（携船网类）
# 主题词必须是"问用户是什么/要什么"的词；"请选择城市"归 region_picker，
# "选择你感兴趣的"归 interest_picker，都不在这里。
_SURVEY_TOPIC_WORDS: Tuple[str, ...] = (
    "学段", "学习阶段", "年级", "您是", "你是", "您的身份", "你的身份",
    "身份是", "选择身份", "选择角色", "使用目的", "为什么使用", "想学",
    "您的孩子", "就读", "年龄段", "处在哪个",
)
# 提交词：调研页底部的"完成问卷"按钮。注意与登录提交（登录/注册）区分开 ——
# 那些词不在这个表里，所以登录页不会被当成调研页。
_SURVEY_SUBMIT_WORDS: Tuple[str, ...] = (
    "进入首页", "进入APP", "进入App", "进入应用", "开始使用", "开始体验",
    "立即体验", "开始学习", "选好了", "下一步", "完成", "提交", "确认",
)
_TAB_WORDS = ("首页", "我的", "消息", "发现", "分类", "购物车", "工作台",
              "学习", "社区", "圈子", "订单", "课程", "推荐", "关注", "精选",
              "服务", "首页 ", "个人中心", "设置")


def _screen_h(xml: str) -> int:
    """从 bounds 里推屏高（不额外 dump，省一次设备往返）。"""
    hi = 0
    for n in uiwalk.parse_all(xml):
        try:
            hi = max(hi, int(n.bounds[3]))
        except Exception:
            continue
    return hi or 0


def bottom_tabs(xml: str, nodes: Optional[Sequence[Any]] = None) -> List[Any]:
    """底部导航栏的候选节点：屏幕最下方、不高的一块、文字互不相同。

    为什么用它判主页面：这是"到了应用中枢"最稳的结构特征 —— 引导页、广告、
    弹窗都不会同时具备「贴底 + ≥3 个 + 文字各异」。春泥/高途那种纯 H5 首页
    有 tab 但没有原生节点，所以另有导航词兜底（见 `is_home`）。
    """
    h = _screen_h(xml)
    if h <= 0:
        return []
    pool = list(nodes) if nodes is not None else uiwalk.clickable(xml)
    y0 = h * 0.80
    out: List[Any] = []
    seen = set()
    for n in pool:
        try:
            x1, y1, x2, y2 = n.bounds
        except Exception:
            continue
        if y1 < y0:
            continue
        if (y2 - y1) > h * 0.18:          # 贴底但很高的不是 tab，是整块内容区
            continue
        lab = ((getattr(n, "text", "") or "").strip()
               or (getattr(n, "content_desc", "") or "").strip())
        if not lab or lab in seen:
            continue
        seen.add(lab)
        out.append(n)
    return out


def is_home(xml: str, nodes: Optional[Sequence[Any]] = None) -> Tuple[bool, str]:
    """是不是"可以开始功能遍历了"的界面。

    宁可判否，不可判是：误判成首页的代价是拿引导页/弹窗去遍历（一轮全废），
    漏判的代价只是多走一步（下一步还会再判）。

    两条独立判据，任一成立即算：
      ① 底部有 ≥3 个文字各异的 tab；
      ② 导航词命中 ≥3 个，且可点元素 ≥5（排除"活动页恰好写了首页、我的"）。
    """
    if not (xml or "").strip():
        return False, "界面结构为空，无法判断"
    pool = list(nodes) if nodes is not None else uiwalk.clickable(xml)
    tabs = bottom_tabs(xml, pool)
    if len(tabs) >= 3:
        return True, ("底部导航栏有 %d 个入口（%s）"
                      % (len(tabs), "、".join(
                          ((getattr(n, "text", "") or getattr(n, "content_desc", "") or "")
                           .strip()[:6]) for n in tabs[:4])))
    texts = " ".join(uiwalk.screen_texts(xml))
    hits = [w for w in _TAB_WORDS if w.strip() and w.strip() in texts]
    if len(hits) >= 3 and len(pool) >= 5:
        return True, ("界面含 %d 个导航类文字（%s），可点元素 %d 个"
                      % (len(hits), "、".join(hits[:5]), len(pool)))
    return False, ("底部无导航栏（%d 个），导航词 %d 个 / 可点 %d 个"
                   % (len(tabs), len(hits), len(pool)))


def classify(xml: str, package: str = "",
             nodes: Optional[Sequence[Any]] = None) -> Dict[str, Any]:
    """判这一屏属于首启流程的哪一种形态。

    返回 {"form","name","why","evidence","n_click","is_home"}。
    `why` 是给报告读者看的一句话判读，必须说清"凭什么这么判"。

    判据一律"结构 + 文字"两路合看：只靠文字会把「首页」上写着"限时活动"的
    运营位判成促销弹窗；只靠结构会把登录页（无 tab、可点少）判成弹窗。
    """
    if not (xml or "").strip():
        return {"form": "unknown", "name": form_name("unknown"),
                "why": "界面结构为空（dump 失败或界面未稳定）",
                "evidence": [], "n_click": 0, "is_home": False}
    pool = list(nodes) if nodes is not None else uiwalk.clickable(xml)
    texts_seq = list(uiwalk.screen_texts(xml))
    texts = " ".join(texts_seq)
    n = len(pool)

    def out(form: str, why: str, ev: Sequence[str] = ()) -> Dict[str, Any]:
        return {"form": form, "name": form_name(form), "why": why,
                "evidence": list(ev)[:6], "n_click": n, "is_home": False}

    # ① 系统权限框：包名是系统的、且带"允许/拒绝"。它不是应用界面，
    #    但也必须认出来 —— 否则会被当成"未识别界面"去乱点。
    lowpkg = (package or "").lower()
    if ("com.android.permissioncontroller" in lowpkg
            or "com.lbe.security" in lowpkg or "com.miui.securitycenter" in lowpkg):
        return out("system_perm", "系统权限弹窗（宿主包名 %s）" % (package or "?"),
                   ["包名命中系统权限组件"])

    # ② 年龄门：必须排在促销之前。它的按钮里有「退出App」，
    #    当成促销弹窗去"找关闭按钮"，容易顺手点到退出。
    age = _hit(texts, _AGE_WORDS)
    if age and n <= 8:
        return out("age_gate", "出现年龄/监护人相关表述（「%s」），可点元素仅 %d 个，"
                               "判断为年龄门" % (age, n), [age])

    # ③ 更新弹窗（先于促销：文案里常同时含"活动""升级"）
    upd = _hit(texts, _UPDATE_WORDS)
    if upd and n <= 8:
        return out("update_dialog", "出现版本更新表述（「%s」），可点元素仅 %d 个"
                                    % (upd, n), [upd])

    # ④ 促销弹窗：要"弹窗样"（可点少）才算，否则首页的运营位会被误判。
    promo = _hit(texts, _PROMO_WORDS)
    if promo and n <= 8 and not _hit(texts, ("跳过",)):
        return out("promo_dialog", "出现运营类表述（「%s」）且可点元素仅 %d 个，"
                                   "判断为弹窗" % (promo, n), [promo])

    # ⑤ 地区 / 城市选择：**排在兴趣之前**，因为"请选择你所在的城市"同时
    #    像半个兴趣句式，先判具体的那一个。
    rg = _hit(texts, _REGION_WORDS)
    if rg:
        return out("region_picker",
                   "出现地区/城市选择句式（「%s」），判断为地区选择页" % rg, [rg])

    # ⑤b 调研 / 问卷页：主题问句 + 提交入口 + ≥2 个选项，且**没有输入框**。
    #   排在兴趣之前：两者句式相近（"请选择…"），但业务设计不同 ——
    #   兴趣页是可跳过的多选画像云（只跳过），调研页是必答的单选门槛
    #   （选一个 + 提交，模仿真实用户）。
    #   ★ 必须排除实名强词：春雨实名页有「下一步」，也有"身份认证"字样，
    #     不排除会把认证墙当成可填的问卷 —— 那是绝不能代填的东西。
    #   ★ 必须排除输入框：有 EditText 的页面是表单（登录/实名/注册），
    #     问卷只有选项没有输入框。
    #   ★ 政策 / 协议正文一律不判问卷（2026-11-10 CNC宝典 真机实测）：
    #     该 App 设置页的「隐私政策」点进去是政策全文，正文里「使用目的」
    #     「您是」「确认」必然出现 —— `_SURVEY_TOPIC_WORDS` 与
    #     `_SURVEY_SUBMIT_WORDS` 同时命中，于是被判成首启调研问卷。
    #     采集侧随后把正文里的书名号与「（一）（二）」编号当成"选项"逐个点，
    #     一轮里 7 次"调研页"动作全是假的，报告会因此写上
    #     「首启出现调研问卷（选身份/使用目的）」这种**不存在的事实**。
    #     判据：问卷页只有几十~几百字，政策正文动辄上千；再叠一层政策正文
    #     识别，短一点的用户协议也能拦住。
    _sv_blob = " ".join(texts)
    _sv_is_doc = len(_sv_blob) >= 900
    if not _sv_is_doc:
        try:
            from . import policy as _polmod
            _sv_is_doc = bool(_polmod.looks_like_privacy_policy(_sv_blob))
        except Exception:
            _sv_is_doc = False
    sv = None if _sv_is_doc else _hit(texts, _SURVEY_TOPIC_WORDS)
    if (sv and "EditText" not in xml
            and not _hit(texts, _REALNAME_STRONG)
            and _hit(texts, _SURVEY_SUBMIT_WORDS)):
        # 选项统计用**全量节点**而不是可点池：uni-app / H5 的选项常常
        # `clickable=false`（高途的学段卡片就是），只数可点会漏掉整页问卷，
        # 然后被后面的引导页判据（「进入首页」≈"开始使用"类文案）抢走。
        # 先严格（可点/单选钮），不够再宽松（不可点短文字也算）。
        _sv_all = uiwalk.parse_all(xml)
        _sv_opts = survey_options(_sv_all)
        if len(_sv_opts) < 2:
            _sv_opts = survey_options(_sv_all, include_text=True)
        if len(_sv_opts) >= 2:
            return out("survey_gate",
                       "出现调研问句（「%s」）与提交入口（「%s」），且有 %d 个可选项，"
                       "判断为首启调研/选择页（必答门槛，模仿真实用户作答）"
                       % (sv, _hit(texts, _SURVEY_SUBMIT_WORDS), len(_sv_opts)),
                       [sv, _hit(texts, _SURVEY_SUBMIT_WORDS)])

    # ⑤ 兴趣 / 偏好选择：**必须排在开屏广告之前**。
    #    兴趣页通常也带「跳过」，而开屏广告的判据就是"有跳过" —— 排在后面
    #    会把一个要选 12 个标签的画像页当成广告页，然后只点一下"跳过"就走，
    #    看着没事，实际是**漏掉了"应用在首次启动就建立用户画像"这个事实**。
    #    判据用具体句式（"请选择你感兴趣"）而不是"兴趣"两个字。
    itr = _hit(texts, _INTEREST_WORDS)
    if itr:
        # 不再要求"可点元素 ≥3"：自绘/H5 的兴趣页里标签常常全不可点
        # （2026-11-06 用例抓到：全不可点时会被后面"有跳过 + 可点少"的
        # 开屏广告判据抢走）。`_INTEREST_WORDS` 用的都是祈使句式
        # （"请选择你感兴趣…"），普通页面上不会出现，不需要再拿数量兜底。
        return out("interest_picker",
                   "出现兴趣/偏好选择句式（「%s」），判断为画像收集页" % itr, [itr])

    # ⑥ 开屏广告：有「跳过」+（倒计时 或 可点元素极少）。
    #    `n <= 4` 是收紧过的：广告页的可点元素是「跳过」加广告主体，一般 2~3 个；
    #    放到 6 会把兴趣选择页、带跳过的小弹窗都吸进来。
    skip = _hit(texts, ("跳过广告", "跳过"))
    if skip:
        has_count = bool(re.search(r"\d{1,2}\s*[s秒]", texts))
        # 携船网的形态：`跳过:` 后面跟 `00` 和 `s` —— 倒计时被拆成两个节点，
        # 所以除了"3s/5秒"这种连写，还要认"纯数字节点"和"单独的 s"。
        count_hint = any(len(t.strip()) <= 3 and t.strip().rstrip("sS").isdigit()
                         for t in texts_seq) or ("s" in [t.strip().lower()
                                                         for t in texts_seq])
        if has_count or count_hint or n <= 4:
            return out("splash_ad",
                       "界面有「%s」，%s，判断为开屏广告页"
                       % (skip, "并带倒计时" if (has_count or count_hint)
                          else "可点元素仅 %d 个" % n),
                       [skip, "倒计时" if (has_count or count_hint) else ""])

    # ⑦ 实名 / 资质认证：**必须排在登录页之前**。
    #    这一屏有「姓名」这类输入框，登录判据（有输入框 + 提交按钮）会把它
    #    认成登录页，然后交给登录辅助去"代填手机号/验证码"——填不进去，
    #    还会被记成"登录失败"（2026-11-06 春雨诊所实测：登录成功后落在
    #    「实名认证」页，要执业信息/执业证件/人脸认证/手写签名）。
    #    判据要求**至少一个强词 + 至少两个具体词**：政策正文和权限说明页里
    #    也会出现"人脸识别""证件照"这类词，只按弱词判会把它们认成认证墙
    #    （2026-11-06 land27 实测：春雨的「授权提示」页被误判，着陆 2.9 秒就收工）。
    _rn_hits = [w for w in _REALNAME_WORDS if w in texts]
    _rn_strong = [w for w in _REALNAME_STRONG if w in texts]
    if _rn_strong and len(_rn_hits) >= 2:
        return out("realname_gate",
                   "出现实名/资质认证表述（%s 等 %d 处），判断为实名或资质认证页，"
                   "检测方不具备该条件" % ("、".join(_rn_hits[:3]), len(_rn_hits)),
                   _rn_hits[:4])

    # ⑧ 登录页：**必须排在引导页之前**。
    #    登录页最常用的标题就是「欢迎使用 XX」，排在引导页后面会先被
    #    「欢迎」抢走（春雨诊所实测），然后去左滑一个登录页 —— 滑到天荒地老。
    #    判据本身已有输入框/账号词/可点数量三重约束，误判概率低于纯词表。
    try:
        lg = uiwalk.login_screen(xml)
    except Exception:
        lg = None
    if lg is None:
        try:
            lg = uiwalk.login_screen_weak(xml)
        except Exception:
            lg = None
    if lg is not None:
        return out("login", "识别为登录/注册页（%s）"
                   % (str(lg.get("title") or lg.get("why") or "登录类字样齐全")[:40]), [])

    # ⑧ 引导页：有"开始使用/上滑左滑"等，且底部无 tab
    tabs = bottom_tabs(xml, pool)
    gd = _hit(texts, _GUIDE_WORDS)
    if gd and len(tabs) < 3:
        return out("guide_pager", "出现引导类表述（「%s」）且底部无导航栏，"
                                  "判断为欢迎引导页" % gd, [gd])

    # ⑨ 权限引导（应用自绘，不是系统框）
    pm = _hit(texts, _PERM_WORDS)
    # 只看"开启/允许"不够：春雨诊所的「授权提示」通篇用的是"授权""您有权拒绝"
    # 和一句「我知道了」，一个"开启"都没有，于是被判成 unknown
    # （2026-11-06 land27 实测）。这种页面的动作就是点「我知道了」，必须认得。
    if pm and _hit(texts, ("开启", "允许", "去设置", "去开启", "暂不",
                           "授权", "我知道了")):
        return out("perm_guide", "出现权限引导表述（「%s」），判断为权限说明页" % pm, [pm])

    # ⑩ 主页面
    ok, why = is_home(xml, pool)
    if ok:
        d = out("home", "已到主页面：%s" % why)
        d["is_home"] = True
        return d

    # ⑪ 启动 / 加载页：几乎没内容、也没有可点的东西。
    #    ★ 必须排在 unknown 之前。它和 unknown 的区别不是"看起来像什么"，
    #      而是**该做什么**：unknown 会去按返回，而在这个界面上按返回
    #      就是把应用退掉。可点元素 ≤1、文字 ≤2 条，就只可能是启动页或
    #      加载占位页，等它自己跳转是唯一正确的动作。
    if n <= 1 and len(texts.strip()) <= 40:
        return out("splash_wait",
                   "界面上几乎没有内容（可点元素 %d 个、文字 %d 条），"
                   "判断为启动/加载页，等待自动跳转" % (n, len(texts_seq)), [])

    return out("unknown", "形态判据未命中：%s" % why)


# ============================================================ 禁点判定
def forbidden(node: Any, form: str) -> str:
    """这一屏、这个节点**为什么不能点**。空串表示可以点。

    注意返回的是"理由"，不是布尔 —— 理由要进日志和报告，否则复核员只能看到
    "程序没点它"，看不出是漏了还是有意不点。这在检验检测里是两回事。
    """
    label = _texts_of(node)
    low = label.lower()

    # ① 不可逆副作用：外跳 / 下载 / 换掉被测对象
    hit = _hit(label, _FORBIDDEN_IRREVERSIBLE)
    if hit:
        return "「%s」会带来不可逆副作用（外跳、下载或改变被测版本），着陆阶段不点" % hit

    # ② 广告主体：开屏页上除了「跳过/关闭」，其余区域都是广告位。
    #    这里不能靠"是不是就一个节点"来判 —— 广告主体常被切成好几块。
    if form == "splash_ad":
        if not (_hit(label, _CLOSE_WORDS) or _is_close_glyph(label)
                or label.strip() == ""):
            if not _hit(label, _ADVANCE_WORDS):
                return "开屏广告的广告位：点它会外跳，着陆阶段只允许点「跳过/关闭」"

    # ③ 兴趣标签：只允许"跳过/暂不"这一类，标签本身一个都不点。
    if form == "interest_picker":
        if not (_hit(label, _INTEREST_ONLY_CLOSE) or _is_close_glyph(label)):
            return "兴趣标签会把偏好写进用户画像，本工具不代替用户做这项选择"

    # ④ 兜底的通用危险词（退出App / 不同意 / 注销 等）
    try:
        if uiwalk.is_dangerous(node):
            return "属通用危险操作（退出/注销/不同意类），任何阶段都不点"
    except Exception:
        pass
    if not low:
        # 完全无文字的容器：点了不知道会发生什么，着陆阶段不冒这个险。
        return "无可读文字的可点容器，点了无法预判去向"
    return ""


# ============================================================ 调研页选项
def survey_options(nodes: Sequence[Any], include_text: bool = False) -> List[Any]:
    """调研页的候选项节点：单选/复选控件，或 2~10 字的可点短文字。

    提交按钮与「跳过/关闭」**不算选项** —— 否则「进入首页」本身会被当成
    第一个选项选了，等于跳过"选"这一步、只点提交。

    `include_text=True` 时把不可点的短文字也算进来（uni-app / H5 的选项
    常常 `clickable=false`，只能按文字位置点）。**只**在 plan 已经确定
    这一屏是 survey_gate 之后用它做兜底，分类判据仍用严格版 ——
    普通页面上短文字遍地都是，宽松版会把任何带「下一步」的页面认成问卷。
    """
    out: List[Any] = []
    for n in nodes:
        cls = (getattr(n, "cls", "") or "")
        if "EditText" in cls:
            continue
        label = _texts_of(n)
        if _hit(label, _CLOSE_WORDS) or _hit(label, _SURVEY_SUBMIT_WORDS):
            continue
        if "RadioButton" in cls or "CheckBox" in cls:
            out.append(n)
            continue
        t = label.strip()
        if include_text and (_hit(t, _SURVEY_TOPIC_WORDS) or t.startswith("请选择")
                             or "至少" in t or len(t) > 6 and "选择" in t):
            # 宽松模式下问句标题/提示语不算选项：它们也是 ≤10 字的短文字，
            # 不排除的话"选"这一步会点到标题上。
            continue
        if 2 <= len(t) <= 10 and (getattr(n, "clickable", False) or include_text):
            out.append(n)
    return out


# ============================================================ 动作规划
def node_key(node: Any) -> str:
    """节点的稳定身份：文字 + 坐标。

    不用 `obs.uid_for()` 那个 uid：它需要观察器对象，而本模块要能脱离采集器
    单独跑（离线用例全靠这一点）。同一屏里"文字+坐标"已经够唯一；跨屏坐标
    会变，那正好 —— 换了屏本来就该重新允许点。
    """
    try:
        x1, y1, x2, y2 = node.bounds
    except Exception:
        x1 = y1 = x2 = y2 = 0
    return "%s|%d,%d,%d,%d" % (_texts_of(node)[:40], x1, y1, x2, y2)


def plan(form: str, nodes: Sequence[Any], texts: Sequence[str],
         tried: Optional[Sequence[str]] = None,
         back_unsafe: bool = False,
         swipe_rounds: int = 0, max_swipes: int = 6,
         wait_rounds: int = 0, max_waits: int = 3) -> Dict[str, Any]:
    """给这一屏定一个动作。**纯决策**，不执行、不碰设备。

    返回 {"action","node","direction","why","expect","code"}：
      action ∈ tap / swipe / wait / back / give_up / done
      why    = 判读（为什么做这个动作）
      expect = 预判（做完应该看到什么）
      code   = 稳定代号，供日志聚合与用例断言

    `tried` 是已经点过的 `node_key()`，用来避免"同一个「跳过」点五次"。
    """
    tried = set(tried or [])
    pool = [n for n in nodes]
    free = [n for n in pool if node_key(n) not in tried]

    def _is_click(n: Any) -> bool:
        return bool(getattr(n, "clickable", False))

    # ★ 「文字锚点」兜底（2026-11-06 携船网真机踩出来的）：
    #   开屏广告的「跳过」在结构树里是 text 节点、`clickable=false`
    #   （uni-app / H5 与自绘控件都这样），真正的点击区是它自己那块文字。
    #   只认 clickable 的话，`close_target()` 一律返回 None，程序就只能
    #   干等倒计时走完 —— 广告 3~5 秒，遇到 15 秒的就白烧预算。
    #   所以允许按"文字节点自身的坐标中心"点一下。
    #   风险控制三条：只对关闭类词、文字长度 ≤12、且只在弹窗/广告这类
    #   "必须收掉才能继续"的形态下启用。不做通用兜底 —— 在功能页面上
    #   按文字位置乱点，等于绕过所有危险按钮检查。
    #   `interest_picker` 也在内：它的 `close_target` 只找关闭词，
    #   而 `forbidden()` 会拦掉所有非关闭词的节点，所以不会点到标签上。
    _TEXT_ANCHOR_FORMS = ("splash_ad", "promo_dialog", "update_dialog",
                          "age_gate", "interest_picker", "region_picker",
                          "guide_pager", "survey_gate")

    def find(words: Sequence[str], pool2: Sequence[Any],
             allow_text: bool = False) -> Optional[Any]:
        """在允许点的节点里，按词表顺序找第一个命中的（可点优先）。"""
        for w in sorted(words, key=len, reverse=True):
            for n in pool2:
                if not _is_click(n):
                    continue
                if forbidden(n, form):
                    continue
                if _hit(_texts_of(n), (w,)) or (w == "关闭" and _is_close_glyph(_texts_of(n))):
                    return n
        if not (allow_text and form in _TEXT_ANCHOR_FORMS):
            return None
        for w in sorted(words, key=len, reverse=True):
            for n in pool2:
                if _is_click(n):
                    continue
                lab = (getattr(n, "text", "") or "").strip()
                if not lab or len(lab) > 12:
                    continue
                if forbidden(n, form):
                    continue
                if _hit(lab, (w,)) or _is_close_glyph(lab):
                    return n
        return None

    def close_target(pool2: Sequence[Any], allow_text: bool = True) -> Optional[Any]:
        n = find(_CLOSE_WORDS, pool2, allow_text=allow_text)
        if n is None and allow_text:
            for c in pool2:
                if forbidden(c, form):
                    continue
                if _is_close_glyph(_texts_of(c)):
                    return c
        return n

    def tap(n: Any, why: str, expect: str, code: str) -> Dict[str, Any]:
        d = {"action": "tap", "node": n, "why": why, "expect": expect, "code": code}
        if not _is_click(n):
            d["text_anchor"] = True
            d["why"] = why + "（该按钮在结构树里没有点击属性，按文字所在位置点击）"
        return d

    # ---- 启动 / 加载页：唯一正确的动作是等
    if form == "splash_wait":
        if wait_rounds >= max_waits:
            return {"action": "give_up", "node": None,
                    "why": "启动/加载页已等待 %d 次仍未跳转（累计约 %d 秒），"
                           "可能卡在启动流程" % (wait_rounds, wait_rounds * 2),
                    "expect": "需人工确认应用能否正常启动", "code": "stuck_splash"}
        return {"action": "wait", "node": None,
                "why": "启动/加载页没有可点元素，按常规等它自己跳转"
                       "（第 %d 次等待）" % (wait_rounds + 1),
                "expect": "自动进入下一步（首启弹窗或主页面）", "code": "wait_splash"}

    # ---- 已到主页面：直接交棒
    if form == "home":
        return {"action": "done", "node": None,
                "why": "当前已处于主页面，无需再处理首启环节",
                "expect": "交给功能遍历", "code": "home"}

    # ---- 实名 / 资质认证：这是**过不去**的一道门，而且不该过去
    #   ★ 2026-11-06 春雨诊所实测：登录成功后不是主页面，而是「实名认证」——
    #     要姓名、执业科室、职称、医院、执业证件照、人脸认证、手写签名。
    #     往里填的是别人的真实身份信息；人脸、证件、签名更不是检测该碰的东西。
    #     所以这里**只认、不试**：说清原因就收工，交给遍历去走登录前可见的功能。
    #     以前没有这一类，它会被当成"未识别界面"，模型看截图说"填表继续"，
    #     于是它在表单上反复点「下一步」——每一步都在替被测应用索要真实身份信息。
    if form == "realname_gate":
        _blob = " ".join(texts)
        _rn = [w for w in _REALNAME_WORDS if w in _blob]
        return {"action": "give_up", "node": None,
                "why": ("该应用登录后要求实名/资质认证（%s），检测方不具备"
                        "真实身份与执业资质，认证后的功能未覆盖"
                        % ("、".join(_rn[:3]) or "实名认证")),
                "expect": "不处理：这类动作需要真实身份信息与证件/人脸，不在检测范围内",
                "code": "realname_wall"}

    # ---- 登录页：先看有没有「暂不登录 / 随便逛逛」
    #   ★ 这一步不能省（2026-11-06 自查）：以前在登录页一律 give_up，
    #     于是把"点一下就能以游客身份进主页面"这条路白白扔掉，报告里
    #     还写成"登录墙"。而游客入口是应用自己提供的正当路径，点它
    #     既不是代填账号、也不是伪造身份，没有任何副作用。
    #   登录本身仍属功能遍历（有测试账号才走），landing 不代填。
    if form == "login":
        g = find(_GUEST_WORDS, free, allow_text=True)
        if g is not None:
            return tap(g, "登录页上有「%s」入口，先以未登录状态进入主页面；"
                          "这一步不涉及账号代填" % _texts_of(g)[:12],
                       "以游客/未登录状态进入主页面", "guest_login")
        # ★ 可关闭的登录**弹窗** ≠ 登录墙（2026-11-06 高途实测）：
        #   高途的登录是以弹窗形式盖在首页上的，右上角有个关闭叉，但那个控件
        #   只有资源 id（`login_view_close`）、没有中文文字，本地只按词表找
        #   就找不到，于是被判成"登录墙"直接收工 —— 而底下本来就能用。
        #   判据：资源 id 里带 close/dismiss/skip，且不带头部含 exit/quit 的字样。
        for nd in free:
            if not _is_click(nd):
                continue
            rid = (getattr(nd, "resource_id", "") or "").lower()
            if not rid or forbidden(nd, form):
                continue
            if any(h in rid for h in ("close", "dismiss", "skip")) and not any(
                    x in rid for x in ("exit", "quit", "app")):
                return tap(nd, "登录界面上有一个关闭控件（资源 id 含「%s」），"
                               "说明这是可关闭的登录弹窗、不是必须登录的墙；"
                               "关掉它继续往主页面走"
                          % next(h for h in ("close", "dismiss", "skip") if h in rid),
                       "登录弹窗被关闭，露出下面的主页面", "close_login")
        return {"action": "give_up", "node": None,
                "why": "已到登录/注册页且没有游客入口、也没有可关闭的弹窗控件，"
                       "着陆阶段不代填（代填属功能遍历的登录流程）",
                "expect": "交由登录流程或登录墙判定", "code": "login_wall"}

    # ---- 系统权限框：交给调用方的权限处理，不在这里点
    if form == "system_perm":
        return {"action": "give_up", "node": None,
                "why": "系统权限弹窗由权限场景逻辑处理，着陆阶段不点",
                "expect": "交由权限弹窗处理", "code": "system_perm"}

    # ---- 年龄门 / 弹窗类 / 广告：先关，再推进
    if form in ("age_gate", "update_dialog", "promo_dialog", "splash_ad", "perm_guide"):
        n = close_target(free)
        if n is not None:
            return tap(n, "当前是%s，先收起这一层再看底下的界面" % form_name(form),
                       {
                           "splash_ad": "回到应用界面（广告结束或跳过）",
                           "age_gate": "年龄确认通过，进入下一步",
                       }.get(form, "弹窗消失，露出下面的页面"),
                       "close_" + form)
        # 广告没有跳过按钮时，只能等（很多开屏广告 3~5 秒自动结束）。
        if form == "splash_ad":
            return {"action": "wait", "node": None,
                    "why": "开屏广告上没有可点的关闭/跳过，按常见做法等它自动结束",
                    "expect": "倒计时结束后自动进入应用", "code": "ad_wait"}
        # 年龄门 / 权限引导：推进类按钮（监护人已同意 / 去开启 不行，暂不开启 算关闭）
        n = find(_ADVANCE_WORDS, free, allow_text=True)
        if n is not None:
            return tap(n, "%s上没有明显的关闭入口，改点流程推进按钮" % form_name(form),
                       "该步骤被确认，进入下一步", "advance_" + form)
        return {"action": "give_up", "node": None,
                "why": "%s上既没有可点的关闭按钮，也没有可推进的按钮" % form_name(form),
                "expect": "需要人工确认", "code": "stuck_" + form}

    # ---- 调研 / 选择页：模仿真实用户「选一项 + 提交」的组合操作
    #   ★ 2026-11-06 高途实测（用户反馈）：首启学段选择页（小学→成人教育，
    #     底部「进入首页」）被当成功能遍历，选项被逐个当"入口"点过去。
    #     正确做法是把它当问卷：选**一个**选项、再点提交 —— 就像一个真实
    #     用户那样。两次点击各留一条痕，报告里能看出"应用在首启就收集
    #     学段/身份画像"这件事。
    #   ★ 顺序有讲究：
    #     ① 已选过（勾上/已点过）→ 提交，不再选第二个（真实用户也只选一个）；
    #     ② 有「跳过」→ 优先跳过：不代替用户把选项写进画像，最保守；
    #     ③ 没跳过 → 选第一个未试过的选项（H5 选项不可点时按文字位置点）；
    #     ④ 只有提交没有选项 → 直接提交；
    #     ⑤ 什么都没有 → 按返回，如实收工。
    if form == "survey_gate":
        _all_opts = [n for n in survey_options(pool, include_text=True)
                     if not forbidden(n, form)]
        _fresh_opts = [n for n in _all_opts if node_key(n) not in tried]
        # 可点的排前面：宽松版把标题/说明这类不可点短文字也收进来了，
        # 它们也是候选（H5 选项常 clickable=false），但只有真按钮优先。
        _fresh_opts.sort(key=lambda n: 0 if getattr(n, "clickable", False) else 1)
        _picked = (any(bool(getattr(n, "checked", False)) for n in _all_opts)
                   or len(_fresh_opts) < len(_all_opts))   # 已点过某个选项
        _sub = find(_SURVEY_SUBMIT_WORDS, free, allow_text=True)
        if _picked and _sub is not None:
            return tap(_sub, "调研页已选定选项，点「%s」提交（模仿真实用户完成问卷）"
                          % _texts_of(_sub)[:12],
                       "问卷提交，进入主页面或下一题", "survey_submit")
        _skip = close_target(free)
        if not _picked and _skip is not None:
            return tap(_skip, "调研页上有「%s」入口，优先跳过 —— 不代替用户"
                           "把选项写进画像" % _texts_of(_skip)[:10],
                       "跳过调研，进入下一环节", "survey_skip")
        if _fresh_opts:
            _pick = _fresh_opts[0]
            return tap(_pick, "调研页没有跳过入口；模仿真实用户选择「%s」"
                           "（该选择由检测工具代选，会在留痕与报告里写明）"
                           % _texts_of(_pick)[:12],
                       "该选项被选中；下一步点「进入首页/下一步」提交",
                       "survey_select")
        if _sub is not None:
            return tap(_sub, "调研页没有可辨识的选项、只有提交入口，直接点它继续",
                       "进入下一环节或主页面", "survey_submit")
        if not back_unsafe:
            return {"action": "back", "node": None,
                    "why": "调研页上既找不到选项也找不到提交入口，按返回退出这一页",
                    "expect": "回到上一级界面", "code": "survey_back"}
        return {"action": "give_up", "node": None,
                "why": "调研页上找不到选项与提交入口，返回键在该界面也不安全",
                "expect": "需人工确认该页的作答方式", "code": "stuck_survey"}

    # ---- 兴趣选择 / 地区选择：只找"跳过/暂不"，没有就退
    #   ★ 两类合在一处处理，是因为**处置原则相同**：勾兴趣、选城市都会写进
    #     用户画像/位置偏好，我们不是真实用户，代选等于伪造证据。
    if form in ("interest_picker", "region_picker"):
        n = close_target(free)
        _what = "兴趣/偏好" if form == "interest_picker" else "地区/城市"
        if n is not None:
            return tap(n, "当前是%s收集页；本工具不代替用户做出该项选择，"
                          "只找「跳过/暂不」类入口" % _what, "跳过本页，进入下一环节",
                       "skip_interest")
        if not back_unsafe:
            return {"action": "back", "node": None,
                    "why": "%s收集页没有「跳过」入口；代选会写入用户画像/位置偏好，"
                           "所以按返回退出这一页" % _what,
                    "expect": "回到上一级界面", "code": "back_interest"}
        return {"action": "give_up", "node": None,
                "why": "%s收集页没有跳过入口，且返回键在该界面不安全" % _what,
                "expect": "需人工确认是否必须做出该项选择才能继续",
                "code": "stuck_interest"}

    # ---- 引导页：先跳过/开始使用，都没有就左滑
    if form == "guide_pager":
        n = find(_ADVANCE_WORDS, free, allow_text=True) or close_target(free)
        if n is not None:
            return tap(n, "当前是欢迎引导页，找「跳过 / 开始使用」类入口走出引导",
                       "结束引导，进入主页面", "exit_guide")
        if swipe_rounds >= max_swipes:
            return {"action": "give_up", "node": None,
                    "why": "引导页已连续左滑 %d 次仍未出现「开始使用」，"
                           "可能停在最后一屏或滑动方向不对" % swipe_rounds,
                    "expect": "需人工确认", "code": "stuck_guide"}
        return {"action": "swipe", "node": None, "direction": "left",
                "why": "引导页没有可点的跳过/开始按钮，按引导页的通用交互左滑翻到下一屏"
                       "（第 %d 次）" % (swipe_rounds + 1),
                "expect": "翻到下一页引导图或出现「开始使用」", "code": "swipe_guide"}

    # ---- 未识别：只点很确定的关闭类，其余交 AI
    n = close_target(free)
    if n is not None:
        return tap(n, "界面形态未识别，但存在明确的关闭类按钮，先收掉这一层",
                   "这一层消失，露出真实界面", "close_unknown")
    if not back_unsafe:
        return {"action": "back", "node": None,
                "why": "界面形态未识别且没有可点的关闭类按钮，先按返回看能否回到上一级",
                "expect": "回到上一级界面", "code": "back_unknown"}
    return {"action": "give_up", "node": None,
            "why": "界面形态未识别，没有可点的关闭按钮，返回键也不可用",
            "expect": "需人工确认", "code": "stuck_unknown"}


# ============================================================ 主页面确认
def confirm_home(history: Sequence[Dict[str, Any]], need: int = 2) -> Tuple[bool, str]:
    """连续 N 次都是"新增界面 + 判为 home"才算真的到了主页面。

    为什么要连续：转场动画、加载占位页常常一瞬就带 tab（首页骨架屏），
    单次判定的假阳性会在骨架屏上开始遍历，点到的都是还不存在的入口。
    `history` 每项 {"is_home": bool, "fp": str}，按时间顺序。
    """
    if not history:
        return False, "还没有界面记录"
    tail = list(history)[-need:]
    if len(tail) < need:
        return False, "刚判为首页 %d 次，还需再确认 %d 次" % (len(tail), need - len(tail))
    if not all(bool(h.get("is_home")) for h in tail):
        return False, "最近 %d 次里有一次不是首页形态" % need
    fps = [str(h.get("fp") or "") for h in tail]
    if len(set(fps)) > 1 and all(fps):
        # 指纹不同说明还在跳转中，不是"稳定停在首页"。
        return False, "连续判为首页但界面指纹在变（还在跳转）"
    return True, "连续 %d 次判为首页且界面稳定" % need


# ============================================================ 报告口径
def summary(steps: Sequence[Dict[str, Any]], reached: bool,
            why: str = "", secs: float = 0.0) -> Dict[str, Any]:
    """把着陆过程压成报告要用的一小段事实。

    只陈述发生过什么，不给"是否合规"的判断 —— 那是 P4/P5 的事。
    但有两个事实必须留下：**是否真的进了主页面**、以及**没进去的原因**。
    少了后一条，报告里的"未覆盖"就成了无主语的句子。
    """
    forms: List[str] = []
    for s in steps:
        f = str(s.get("form") or "")
        if f and (not forms or forms[-1] != f):
            forms.append(f)
    taps = sum(1 for s in steps if str(s.get("action") or "") == "tap")
    swipes = sum(1 for s in steps if str(s.get("action") or "") == "swipe")
    blocked = [str(s.get("why") or "") for s in steps
               if str(s.get("action") or "") == "give_up"]
    return {
        "reached_home": bool(reached),
        "why": why,
        "secs": round(float(secs), 1),
        "steps": len(steps),
        "taps": taps,
        "swipes": swipes,
        "forms": forms,
        "form_names": [form_name(f) for f in forms],
        "blocked_why": blocked[-1] if blocked else "",
    }


def describe_path(summary_d: Dict[str, Any]) -> str:
    """一句话说清"这一轮是怎么走进主页面的"。报告用。"""
    if not summary_d:
        return ""
    names = summary_d.get("form_names") or []
    taps = int(summary_d.get("taps") or 0)
    swipes = int(summary_d.get("swipes") or 0)
    if summary_d.get("reached_home"):
        if not names or names == [form_name("home")]:
            return "点击同意后直接进入主页面，中间没有额外环节。"
        if taps + swipes == 0:
            # ★ 0 次要写清"为什么是 0"（2026-11-06 携船网实测）：
            #   开屏广告的「跳过」在结构树里是不可点节点（uni-app 的 H5 文本），
            #   程序只能等倒计时走完。这时写"用 0 次点击完成着陆"读起来像
            #   程序没动过，实际是"这一屏没有可点的东西，等它自己走"。
            return ("点击同意后依次经过：%s；这些界面没有可点击的关闭/跳过入口，"
                    "等待应用自行跳转后进入主页面（未执行点击或滑动）。"
                    % " → ".join(names))
        return ("点击同意后依次经过：%s；用 %d 次点击、%d 次滑动完成着陆，进入主页面。"
                % (" → ".join(names), taps, swipes))
    return ("点击同意后依次经过：%s；未能进入主页面（%s）。"
            % (" → ".join(names) or "无可记录界面", summary_d.get("why") or "原因未记录"))
