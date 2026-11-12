"""外跳判定：这一屏跑到别的应用 / 系统页面去了，值不值得留证。

## 为什么必须单独判

遍历时，一次点击把界面带出被测 App，有三种性质完全不同的情况：

  ① **跳转本身就是证据**
     点「权限管理」跳到系统设置的权限页 —— 说明 App 没有自建权限开关，
     用户只能去系统里关；点「微信登录」跳到微信授权页 —— 说明存在第三方
     账号体系，授权后设备标识 / 昵称头像会流向微信。这两件事都要进报告，
     落点界面要截图留证。
  ② **跳转毫无取证价值**
     点「去评分」开应用商店、点广告位开浏览器首页、点「上传头像」弹系统相册。
     这些界面里没有被测 App 的任何行为，停在上面只是烧预算。
  ③ **App 被退出了**
     落到桌面 / 拨号盘。那不是"跳转"，是崩溃或误触，要按退出处理。

旧逻辑对三种一视同仁：一律按返回键 + 把入口拉黑。后果是 ① 被当成废点击丢掉，
报告里永远看不到"权限管理只跳系统设置"这条事实；而 ② 的返回又发生在
**下一轮循环**（中间已经过去一两秒，有时还多跳了一屏），退得太晚。

## 判定口径

先看**宿主包名**（此刻谁在前台），再看**落点文字**与**入口标签**：

  · 设置类宿主      → ①（系统设置的落地页本身就是"开关交给系统"的证据）
  · 浏览器/社交宿主  → 落点像授权流程（授权 / 登录 / oauth / callback），
                       或入口写了"登录 / 授权 / 绑定"时才算 ①；否则 ②
  · 商店 / 选择器 / 桌面 / 拨号 → ② / ③

落点文字要 dump 一次外部界面才有（2~3 秒）。为了让这段时间只花在必要处，
`classify()` 返回 `need_text=True` 表示"光看包名定不了性"，调用方补 dump 后再判一次。

## 一条硬规矩

**永远不在外部应用里点任何按钮。** 外部界面对我们是不透明的（hook 装在被测
App 进程里，拿到的数据不代表那个界面），而且微信 / 支付宝里的一次点击操作的
是真实用户账号。所以动作只有三种：留证后返回、立刻返回、重拉 App。
"""
from __future__ import annotations

from typing import Any, Dict, Tuple
import re

from .docread import is_policy_entry

# ---------------------------------------------------------------- 宿主分类表
#
# 表里全是**包名前缀**。用前缀而不是全等：同一个应用常有 `.module` / `:push`
# 这类子包（`com.android.settings.intelligence`、`com.miui.home:recents`），
# 全等匹配会把它们全漏成 "unknown"。

SETTINGS_PKGS: Tuple[str, ...] = (
    "com.android.settings",
    "com.android.settings.intelligence",
    "com.miui.securitycenter",           # MIUI：权限管理在安全中心里
    "com.miui.securityadd",
    "com.coloros.safecenter",
    "com.oppo.safecenter",
    "com.vivo.settings",
    "com.vivo.permissionmanager",
    "com.huawei.systemmanager",
    "com.hihonor.systemmanager",
    "com.samsung.android.settings",
    "com.meizu.safe",
    "com.iqoo.secure",
    "com.oneplus.security",
    "com.lenovo.security",
    "com.oplus.safecenter",
)

BROWSER_PKGS: Tuple[str, ...] = (
    "com.android.chrome",
    "com.android.browser",
    "com.miui.browser",
    "com.heytap.browser",
    "com.oppo.browser",
    "com.vivo.browser",
    "com.huawei.browser",
    "com.tencent.mtt",                   # QQ 浏览器
    "com.UCMobile",
    "com.baidu.browser",
    "com.baidu.searchbox",
    "com.quark.browser",
    "com.journeyapps.barcodescanner",    # 二维码库自带的浏览器
    "org.mozilla.firefox",
    "com.microsoft.emmx",
    "com.sec.android.app.sbrowser",
)

SNS_PKGS: Tuple[str, ...] = (
    "com.tencent.mm",                     # 微信
    "com.tencent.mobileqq",               # QQ
    "com.tencent.tim",
    "com.sina.weibo",
    "com.eg.android.AlipayGphone",        # 支付宝
    "com.alipay.mobile",
    "com.alibaba.android.rimet",          # 钉钉
    "com.ss.android.ugc.aweme",           # 抖音
    "com.xingin.xhs",
    "com.jingdong.app.mall",
    "com.taobao.taobao",
    "com.smile.gifmaker",
)

STORE_PKGS: Tuple[str, ...] = (
    "com.xiaomi.market",
    "com.android.vending",
    "com.oppo.market",
    "com.heytap.market",
    "com.huawei.appmarket",
    "com.hihonor.appmarket",
    "com.tencent.android.qqdownloader",
    "com.bbk.appstore",
    "com.sec.android.app.samsungapps",
)

PICKER_PKGS: Tuple[str, ...] = (
    "com.android.documentsui",
    "com.google.android.documentsui",
    "com.miui.mediapicker",
    "com.miui.gallery",
    "com.android.gallery3d",
    "com.google.android.providers.media.module",
    "com.android.providers.media.module",
    "com.coloros.gallery3d",
    "com.oppo.gallery3d",
    "com.vivo.gallery",
    "com.huawei.photos",
    "com.android.camera",
    "com.miui.camera",
)

DIALER_PKGS: Tuple[str, ...] = (
    "com.android.dialer",
    "com.google.android.dialer",
    "com.miui.dialer",
    "com.android.incallui",
    "com.android.server.telecom",
    "com.samsung.android.dialer",
)

LAUNCHER_PKGS: Tuple[str, ...] = (
    "com.miui.home",
    "com.android.launcher3",
    "com.google.android.apps.nexuslauncher",
    "com.oppo.launcher",
    "com.coloros.launcher",
    "com.huawei.android.launcher",
    "com.hihonor.android.launcher",
    "com.bbk.launcher2",
    "com.sec.android.app.launcher",
    "com.android.launcher",
)

# 「这一页像是在走授权流程」的措辞。只认**动作与流程**词，不认"安全""隐私"
# 这种到处都有的泛词 —— 授权页、隐私政策页、客服页里都有"安全"。
AUTH_WORDS: Tuple[str, ...] = (
    "授权", "登录", "登陆", "一键登录", "扫码登录", "统一认证", "允许", "同意并授权",
    "oauth", "authorize", "authorization", "signin", "sign in", "callback", "sso",
    "第三方登录", "绑定账号",
)
# 入口标签里出现就说明这个入口**本来就打算**去别的应用完成某件事。
AUTH_ENTRY: Tuple[str, ...] = ("登录", "登陆", "授权", "绑定", "关联", "一键", "第三方")
PAY_ENTRY: Tuple[str, ...] = ("支付", "付款", "收银台", "结算", "购买", "充值")
PERM_WORDS: Tuple[str, ...] = ("权限", "授权管理", "应用权限", "permission", "permcenter",
                               "应用信息", "应用详情", "自启动", "通知管理")

# 系统权限弹窗的宿主。★ 必须在设置类判定**之前**排除：
#   这些包名里都带 permission / settings 字样，若只靠"包名含 settings/permission"
#   兜底，会把权限弹窗判成"设置页"→ 走外跳分支 → **跳过权限取证链路**，
#   弹窗原文没记、代点也没做，Q026 直接无从判定。
PERM_DIALOG_HOSTS: Tuple[str, ...] = (
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
    "com.lbe.security.miui",
    "android",
)

# 系统权限弹窗的 Activity 类名。它挂在白名单里，**不是外跳**，走各自链路。
PERM_DIALOG_ACT = ("GrantPermissionsActivity", "PermissionDialog", "grantpermissions",
                   "PermissionActivity", "AppOpsDialog")


def _host_kind(pkg: str, activity: str = "") -> str:
    """宿主包名 → 类别。`settings` 还要看 activity 才能分清弹窗与页面。"""
    p = (pkg or "").strip()
    if not p:
        return "unknown"
    for pre in PERM_DIALOG_HOSTS:
        if p == pre or p.startswith(pre + ".") or p.startswith(pre + ":"):
            return "permission"
    for table, kind in ((LAUNCHER_PKGS, "launcher"), (DIALER_PKGS, "dialer"),
                        (STORE_PKGS, "store"), (PICKER_PKGS, "picker"),
                        (BROWSER_PKGS, "browser"), (SNS_PKGS, "sns"),
                        (SETTINGS_PKGS, "settings")):
        for pre in table:
            if p == pre or p.startswith(pre + ".") or p.startswith(pre + ":"):
                return kind
    # 没进表但自带 settings/permission 字样的系统包（各家 ROM 的命名很杂）。
    # 只认"以 settings 结尾"或含 securitycenter/permission 的，不认包名里
    # 随便出现 settings 字样的第三方应用（那会把普通 App 判成系统页）。
    low = p.lower()
    if (low.endswith(".settings") or low.startswith("com.android.settings")
            or "securitycenter" in low or "safecenter" in low
            or "permissionmanager" in low):
        return "settings"
    # ★ 只有类名、没有包名的兜底（高途 2026-11-05 实测）：
    #   点「《高途隐私政策》」后 `dumpsys` 只给出 `.BrowserActivity`，
    #   parse_focus 拿不到包名，于是这里一路走到 unknown ——
    #   采集侧判"不是浏览器，只记事实、不读取"，浏览器里那几千字政策正文
    #   一个字都没读，报告写成"政策正文需人工在浏览器中核对"。
    #   能拿到类名就够了：浏览器/选择器这几个类的名字是稳定的系统约定。
    _a = (activity or p or "").lower()
    for mark, kind in (("browseractivity", "browser"), ("browser", "browser"),
                       ("chooseractivity", "picker"), ("resolveractivity", "picker")):
        if mark in _a:
            return kind
    return "unknown"


def host_kind(package: str, activity: str = "") -> str:
    """前台宿主类别（browser / settings / store / picker / sns / launcher /
    dialer / permission / unknown）。`_host_kind` 的公开入口 ——
    采集侧要按类别决定"这一屏值不值得读"，不该自己去猜包名。"""
    return _host_kind(package, activity)


def is_permission_dialog(package: str, activity: str = "") -> bool:
    """这一屏是不是**系统权限弹窗**（而不是设置页）。

    ★ 两者都归在设置类宿主下，处置却完全相反：弹窗要取证并代点「允许」
      （Q026 的证据全在那一段），设置页要留证后立刻返回。
      `com.miui.securitycenter` 既承载权限弹窗也承载权限管理页，只能靠 activity 分辨。
    """
    act = (activity or "").strip()
    for key in PERM_DIALOG_ACT:
        if key in act:
            return True
    return False


def is_settings_page(package: str, activity: str = "") -> bool:
    """前台是不是「系统设置类页面」（权限管理 / 应用详情），而不是权限弹窗。

    只判"是不是设置页"，不判"值不值得留证" —— 后者交给 `classify()`。
    collector 用它补一道判据：`com.miui.securitycenter` 在白名单里，
    `is_foreign_screen()` 对它返回 False，于是"跳到 MIUI 权限管理页"这条
    根本进不了外跳分支，被当成普通界面继续遍历（真机上那一屏几乎全是系统
    ROM 的开关，点了既改设备设置、又拿不到 App 的任何行为）。
    """
    if _host_kind(package, activity) != "settings":
        return False
    return not is_permission_dialog(package, activity)


def is_foreign(package: str, app_package: str) -> bool:
    """前台包名是否已经不在被测 App（白名单内的系统确认框不算）。"""
    p = (package or "").strip()
    if not p or not app_package:
        return False
    if p == app_package or p.startswith(app_package + ":"):
        return False
    try:
        from ..uiwalk import FOREIGN_ALLOWED
    except Exception:                                     # pragma: no cover
        FOREIGN_ALLOWED = ()                              # type: ignore
    for allow in FOREIGN_ALLOWED:
        if p == allow or p.startswith(allow + ".") or p.startswith(allow + ":"):
            return False
    return True


def _has(text: str, words: Tuple[str, ...]) -> bool:
    t = (text or "").lower()
    return bool(t) and any(w.lower() in t for w in words)


# ---------------------------------------------------------------- 广告落地页
#
# 为什么单列（2026-11-09 Q船 4.4.2）：
#   广告不是"跳到别的 App"，而是**开在被测应用自己的 WebView 里**的落地页
#   （`chengzijianzhan.com` / `apps.bytesfield.com`）。前台包名依旧是被测应用，
#   于是它被当成一个普通功能页继续遍历：点「立即下载」→ 真的下载了 APK，
#   点「打开App」→ 又跳去夸克/小红书。报告里那一整段既不是应用的功能、
#   也不是它的外发行为，却占着截图与步数，还可能触发真实下载。
#
# 判定要**多路证据**才落锤，宁可漏也不要把正常页面误判成广告：
#   · 域名落在广告投放/应用分发域名表里（最强，单独成立）
#   · 屏上有「跳过 3 / 跳过广告」（开屏插屏，单独成立）
#   · 下载动词 + 另一个 App 的名字（"夸克""小红书"…）——广告的典型形态
#   · 下载动词 + 应用商店式字段（版本/大小/开发者/应用介绍）
AD_HOSTS: Tuple[str, ...] = (
    "chengzijianzhan.com",       # 巨量引擎橙子建站（Q船实测）
    "bytesfield.com",            # 字节应用分发（Q船实测，package_name=com.xingin.xhs）
    "pstatp.com",                # 头条静态资源，含 ad-tetris-site
    "gdt.qq.com",                # 广点通
    "tanx.com",                  # 阿里妈妈
    "alimama.com",
    "doubleclick.net",
    "googlesyndication.com",
    "admaster.com.cn",
    "miaozhen.com",
    "irs01.com",
)

_AD_DOWNLOAD = ("立即下载", "马上下载", "下载安装", "一键安装", "立即安装",
                "免费下载", "点击下载", "下载应用", "获取应用", "安装应用")
_AD_STORE_FIELDS = ("版本", "大小", "开发者", "更新时间", "应用介绍",
                    "应用权限", "安全检测", "官方", "应用截图")
# 常见被推广的 App：出现"下载"动词 + 这些名字 = 在给别的应用导流
_AD_PROMO_APPS: Tuple[str, ...] = (
    "夸克", "小红书", "抖音", "快手", "拼多多", "淘宝", "京东", "美团",
    "soul", "得物", "闲鱼", "番茄小说", "今日头条", "西瓜视频",
    "QQ浏览器", "爱奇艺", "腾讯视频",
)


def _host_of(url: str) -> str:
    u = (url or "").strip().lower()
    if not u:
        return ""
    if "://" in u:
        u = u.split("://", 1)[1]
    return u.split("/", 1)[0].split("?", 1)[0]


def is_ad_url(url: str) -> bool:
    """这个地址是不是广告投放 / 应用分发域名。

    ★ 为什么要单独给一个判据（2026-11-09 Q船）：那轮的 `policy_capture.urls`
      里 10 条地址有 9 条是广告 —— `p3-app-package-sign.byteimg.com/ad-app-package/…`
      （来自 `Intent.extra:dialog_icon_url`）和 `apps.bytesfield.com/…?package_name=
      com.xingin.xhs`（WebView.loadUrl）。报告里「打开的地址」一栏会把第一个地址
      印出来，读者看到的就是"隐私政策在 apps.bytesfield.com" —— 这比"没有链接"
      更糟：它把一条广告写成了取证依据。
      所以凡是往"政策地址"里塞 URL 的地方，都要先过这一道。
    """
    host = _host_of(url)
    if not host:
        return False
    if any(host == h or host.endswith("." + h) for h in AD_HOSTS):
        return True
    # 域名本身是中性的 CDN，但**路径**写在脸上：字节的
    # `p3-app-package-sign.byteimg.com/ad-app-package/…` 是推广 APK 的下载包，
    # Q船的 `Intent.extra:dialog_icon_url` 里全是这种地址（2026-11-09）。
    _u = (url or "").lower()
    return ("ad-app-package" in _u) or ("/ad_app_" in _u)


def looks_like_ad_landing(text: str, *, url: str = "", app_name: str = "") -> str:
    """这一屏是不是广告落地页/应用下载页。返回命中原因，空串表示不是。

    纯函数，离线可测。调用方拿到非空原因后应当：截图留证 → 立刻返回 →
    把这个入口本会话拉黑。**绝不在这种页面上点任何东西**（点下载会真的下载）。
    """
    t = text or ""
    # 政策页/长正文页绝不判成广告：政策里出现"下载""版本"这类词很正常，
    # 一旦误判就会把整页政策跳过（比漏一个广告代价大得多）。
    if len(t) > 800 and ("隐私政策" in t or "隐私协议" in t or "个人信息保护" in t):
        return ""
    host = _host_of(url)
    if host:
        for h in AD_HOSTS:
            if host == h or host.endswith("." + h):
                return "落地页域名属广告投放/应用分发（%s）" % host

    # 开屏/插屏广告：出现「跳过 3」「3s 跳过」「跳过广告」即可单独成立
    if "跳过广告" in t:
        return "屏上有「跳过广告」（开屏/插屏广告）"
    if re.search(r"跳过\s*\d", t) or re.search(r"\d+\s*s?\s*跳过", t, re.I):
        return "屏上有广告倒计时跳过控件"

    if not _has(t, _AD_DOWNLOAD):
        return ""

    _self = (app_name or "").strip()
    promo = [n for n in _AD_PROMO_APPS if n in t and n not in _self]
    if promo:
        return "下载页在推广其它应用（%s）" % "、".join(promo[:3])

    store_hits = [w for w in _AD_STORE_FIELDS if w in t]
    if len(store_hits) >= 3:
        return "屏上同时出现下载按钮与应用商店式字段（%s）" % "、".join(store_hits[:4])

    if _has(t, ("广告", "推广", "赞助")):
        return "屏上有下载按钮且标注为广告/推广"
    return ""


def _verdict(kind: str, label: str, action: str, why: str, *,
             valuable: bool = False, wait: float = 0.0,
             need_text: bool = False, end_call: bool = False,
             pkg: str = "", activity: str = "", entry: str = "") -> Dict[str, Any]:
    return {
        "kind": kind,
        "label": label,
        # action：`evidence` 留证后返回 / `back` 立刻返回 / `relaunch` App 已退出
        "action": action,
        "valuable": bool(valuable),
        "why": why,
        # 落地页多半还要加载一会儿，等一等再截图，否则截到白屏
        "wait": float(wait),
        # 光看包名定不了性 → 调用方补 dump 一次落点文字再判
        "need_text": bool(need_text),
        # 拨号类：真的接通了要挂断（外呼有社会成本，也不该占着线路）
        "end_call": bool(end_call),
        # 该入口本会话不再点：落点类型已经拿到了，再点一次不会有新事实
        "revisit": False,
        "pkg": pkg,
        "activity": activity,
        "entry": (entry or "")[:40],
    }


def classify(pkg: str, *, activity: str = "", entry: str = "",
             screen_text: str = "", app_package: str = "") -> Dict[str, Any]:
    """判定这次外跳的性质与处置。

    纯函数（只看包名 / Activity / 入口文字 / 落点文字），离线可测 ——
    真机上每跳一次都是几十秒，靠真机试参数既慢又不可复现。

    `screen_text` 为空且返回 `need_text=True` 时，调用方应 dump 一次外部界面
    再调一次；本函数对同一输入永远是同一结论。
    """
    p = (pkg or "").strip()
    act = (activity or "").strip()
    ent = (entry or "").strip()
    txt = (screen_text or "")
    host = _host_kind(p, act)
    kw = dict(pkg=p, activity=act, entry=ent)

    if not p:
        return _verdict("unknown", "未知界面", "back",
                        "取不到前台包名，按离开被测应用处理", **kw)

    # ---- ⓪ 系统权限弹窗：**不是外跳**，交给权限取证链路（这里只做自洽的兜底）----
    # ★ 正常情况下根本走不到这一支：`is_foreign()` 对白名单宿主返回 False、
    #   `is_settings_page()` 也返回 False，collector 不会把它送进外跳分支。
    #   但这个函数是纯判定器，将来若有别的调用方直接用它，这里必须给出正确结论 ——
    #   返回 "其他应用/需要补 dump" 会让人以为权限弹窗是个陌生跳转。
    if host == "permission":
        return _verdict("permission_dialog", "系统权限弹窗", "back",
                        "系统权限弹窗，交由权限取证链路处理，此处不动", **kw)

    # ---- ① 系统设置类：一律留证（它是"开关交给系统"的唯一证据）----
    if host == "settings":
        if is_permission_dialog(p, act):
            # 不该走到这里：权限弹窗在白名单里、有专门的取证链路。
            # 万一进来了，也不许当设置页处理（那会把「允许」当成普通界面点掉）。
            return _verdict("permission_dialog", "系统权限弹窗", "back",
                            "系统权限弹窗，交由权限取证链路处理，此处不动",
                            pkg=p, activity=act, entry=ent)
        perm = _has(act + " " + txt, PERM_WORDS)
        if perm:
            return _verdict(
                "settings_perm", "系统设置 · 权限管理", "evidence",
                "跳转到系统设置的权限管理页：被测应用未自建权限开关，"
                "用户只能到系统设置里关闭授权",
                valuable=True, wait=1.2, **kw)
        if not txt:
            # 设置页的具体一页要靠文字区分（"应用信息" / "通知管理" / "存储"）。
            # 没有文字就先按"应用详情页"记，但不要凭猜写理由。
            return _verdict("settings_plain", "系统设置", "evidence",
                            "跳转到系统设置页：被测应用把该配置项交给系统承接",
                            valuable=True, wait=1.2, need_text=True, **kw)
        return _verdict("settings_plain", "系统设置", "evidence",
                        "跳转到系统设置页：被测应用把该配置项交给系统承接",
                        valuable=True, wait=1.2, **kw)

    # ---- ③ 桌面 / 拨号：不是跳转 ----
    if host == "launcher":
        return _verdict("launcher", "系统桌面", "relaunch",
                        "落在系统桌面：被测应用已退出（不是跳转），需重新拉起", **kw)
    if host == "dialer":
        return _verdict("dialer", "拨号界面", "back",
                        "跳到系统拨号界面（该入口实为客服电话），未实际通话",
                        wait=0.4, end_call=True, **kw)

    # ---- ② 商店 / 选择器：无取证价值，立刻走 ----
    if host == "store":
        return _verdict("store", "应用商店", "back",
                        "跳转到应用商店（评分/更新），界面内无被测应用行为", **kw)
    if host == "picker":
        return _verdict("picker", "系统选择器", "back",
                        "弹出系统选择器（相册/文件），选择动作不产生收集证据", **kw)

    # ---- 浏览器：授权流程 / 政策正文才留证 ----
    if host == "browser":
        # ★ 政策/协议类入口点开的浏览器页是**证据本身**（2026-11-03，春雨诊所/高途）：
        #   这两家的隐私政策都不在应用内，点一下就交给系统浏览器。
        #   旧逻辑把它判成"普通网页，与被测应用的行为无关，立即返回"，
        #   于是 P2 永远拿不到正文，二十几项只能记「跳过未测」；
        #   而且退出次数累计到 9 次就把整轮遍历停掉了 —— 罪魁是"读政策"。
        #   判据只看**入口文字**：点开的是《隐私政策》《用户协议》这类文档，
        #   落到浏览器也只能是去读它（浏览器里的正文由采集侧逐屏读回来）。
        if is_policy_entry(ent):
            return _verdict("browser_policy", "浏览器 · 政策正文页", "evidence",
                            "应用内政策入口由系统浏览器打开（应用未内置政策页），"
                            "浏览器内为政策正文，需在此读取后返回",
                            valuable=True, wait=2.0, **kw)
        if _has(txt, AUTH_WORDS) or _has(ent, AUTH_ENTRY):
            return _verdict("browser_auth", "浏览器授权页", "evidence",
                            "跳转到浏览器完成授权登录：存在第三方账号/统一认证流程",
                            valuable=True, wait=2.0, **kw)
        if not txt:
            return _verdict("browser_plain", "浏览器", "back",
                            "跳转到浏览器，落点是否为授权页待确认", need_text=True, **kw)
        return _verdict("browser_plain", "浏览器", "back",
                        "跳转到浏览器打开普通网页（落点无授权/登录字样），"
                        "与被测应用的行为无关，立即返回", **kw)

    # ---- 社交 / 支付类：授权与支付留证，其余立刻走 ----
    # ★ label 写成"微信授权页"而不是"第三方授权登录"：报告的句子是
    #   「…存在第三方授权登录路径（去向：…）」，用类别名当去向会读成
    #   "去向：第三方授权登录"，同义反复；写应用名才回答了"去了哪"。
    if host == "sns":
        _who = _app_name(p) or "其他应用"
        pay = _has(ent, PAY_ENTRY)
        auth = _has(txt, AUTH_WORDS) or _has(ent, AUTH_ENTRY)
        if pay:
            return _verdict("sns_pay", "%s收银台" % _who, "evidence",
                            "跳转到外部支付应用：该功能需第三方收银台结算",
                            valuable=True, wait=1.5, **kw)
        if auth:
            return _verdict("sns_auth", "%s授权页" % _who, "evidence",
                            "跳转到%s完成授权登录：存在第三方账号体系，"
                            "授权后设备标识/头像昵称会流向该应用" % _who,
                            valuable=True, wait=1.8, **kw)
        if not txt:
            return _verdict("sns_plain", _app_name(p) or "其他应用", "back",
                            "跳转到%s，落点是否为授权页待确认" % (_app_name(p) or "其他应用"),
                            need_text=True, **kw)
        return _verdict("sns_plain", _app_name(p) or "其他应用", "back",
                        "跳转到%s但落点不是授权页（本机未登录该应用），无法取证"
                        % (_app_name(p) or "其他应用"), **kw)

    # ---- 其他应用（含未知包名）----
    if _has(txt, AUTH_WORDS):
        return _verdict("unknown_auth", "其他应用 · 授权页", "evidence",
                        "跳转到其他应用完成授权：存在第三方账号流程",
                        valuable=True, wait=1.8, **kw)
    if not txt:
        return _verdict("unknown", "其他应用", "back",
                        "跳转到其他应用，落点待确认", need_text=True, **kw)
    return _verdict("unknown", "其他应用", "back",
                    "跳转到其他应用，界面内容与被测应用的行为无关，立即返回", **kw)


# 报告里读得懂的应用名。表里没写就退回包名末段 —— 不许编一个"某应用"。
_APP_NAMES: Dict[str, str] = {
    "com.tencent.mm": "微信",
    "com.tencent.mobileqq": "QQ",
    "com.tencent.tim": "TIM",
    "com.sina.weibo": "微博",
    "com.eg.android.AlipayGphone": "支付宝",
    "com.alibaba.android.rimet": "钉钉",
    "com.ss.android.ugc.aweme": "抖音",
    "com.xingin.xhs": "小红书",
    "com.jingdong.app.mall": "京东",
    "com.taobao.taobao": "淘宝",
    "com.smile.gifmaker": "快手",
    "com.miui.securitycenter": "系统安全中心",
    "com.android.settings": "系统设置",
}


def _app_name(pkg: str) -> str:
    p = (pkg or "").strip()
    if p in _APP_NAMES:
        return _APP_NAMES[p]
    for k, v in _APP_NAMES.items():
        if p.startswith(k + ".") or p.startswith(k + ":"):
            return v
    # 未知包：写包名末段（`com.foo.bar` → `bar`），比"另一个应用"更有信息量，
    # 也明确告诉复核员"这是从包名推的，不是识别出来的应用名"。
    return ("（%s）" % p.split(".")[-1]) if p else ""


def parse_focus(focus: str) -> Tuple[str, str]:
    """`包名/Activity` → (包名, Activity 全限定名)。取不到返回 ("", "")。

    两处采集路径写法不同（`pkg/.ui.X` 与 `pkg/pkg.ui.X`），这里统一成全限定名，
    与 `uiwalk.focus_key` 同口径 —— 否则同一个设置页会被判成两个页面。
    """
    f = (focus or "").strip()
    if not f:
        return "", ""
    if "/" not in f:
        return f, ""
    pkg, _, act = f.partition("/")
    pkg, act = pkg.strip(), act.strip()
    if act.startswith("."):
        act = pkg + act
    return pkg, act


def summarize(jumps: Any) -> Dict[str, Any]:
    """把一批外跳记录汇总成报告要用的几个数。"""
    rows = [j for j in (jumps or []) if isinstance(j, dict)]
    out = {
        "total": len(rows),
        "valuable": sum(1 for j in rows if j.get("valuable")),
        "meaningless": sum(1 for j in rows if not j.get("valuable")),
        "left_app": sum(1 for j in rows if j.get("kind") == "launcher"),
        "by_kind": {},
        "kinds": [],
    }
    by: Dict[str, Dict[str, Any]] = {}
    for j in rows:
        k = str(j.get("kind") or "unknown")
        rec = by.setdefault(k, {"kind": k, "label": j.get("label") or k,
                                "count": 0, "valuable": bool(j.get("valuable"))})
        rec["count"] += 1
    out["by_kind"] = by
    out["kinds"] = sorted(by.values(), key=lambda r: -r["count"])
    return out
