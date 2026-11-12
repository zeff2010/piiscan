"""权限申请场景的判定：申请了什么、申请时有没有说明目的。

对应报告模板第 7 项（Q026）：「在申请打开可收集个人信息的权限或申请收集用户
个人敏感信息时，未同步告知用户其目的」。

## 判定口径

人工看的是三件事，按可靠度排：

  ① **系统弹窗内**是否带 App 提供的说明文字（定制 ROM 常见，标准 Android 少见）；
  ② 弹窗出现**之前** App 是否弹出过说明浮窗 / 说明页（"开启定位以推荐附近门店"）；
  ③ 弹窗所在功能界面的文字是否说明了用途（弱证据，单独不成立）。

三者都没有，才记「未同步告知」。

## 为什么不直接判 fail（以及为什么现在改成一次即认定）

"没看到说明"不等于"没有说明"：说明可能以 Toast、引导页、图片出现，结构树读不到。
所以 `purpose` 为空（**弹窗前那一屏没取到文字**）时只记「证据不足」，不判违规。

早期版本更保守：要在同一会话里抓到**两次以上**未告知、且在**全部界面文字**里
都找不到该权限的用途说明，才判 fail。这条规则在真机上被证明是不可复现的 ——
两次还是一次取决于本轮点开了几个功能，而"全部界面文字"取决于本轮遍历翻到了
哪些页。同一个包、同一版本连跑五轮，Q026 会在「认定」与「疑似」之间来回跳
（mbsf16 第 36 步、mbsf18 第 24 步翻到设置里的「相机权限使用说明：用于拍照图片」，
这句静态说明把两条未告知洗成疑似；mbsf15/mbsf19 没翻到，同样的两条就判认定）。

现在的口径：**证据只取这一次申请**（弹窗内 + 弹窗前那一屏），取到即为有效值，
一次即认定；跨界面翻到的静态说明页只写进 `stats["elsewhere"]` 供人工复核，
不参与结论。
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import models as M

# 各个权限对应的"功能词"：说明文字里出现这些词，才认为这条说明与本次申请相关。
# 不写功能词的话，"为了保障您的账号安全"这种套话会被当成用途说明。
PERM_FUNCS: Dict[str, Tuple[str, ...]] = {
    "位置": ("定位", "导航", "附近", "地图", "门店", "城市", "天气", "周边",
             "距离", "打卡", "路线"),
    "通讯录": ("好友", "邀请", "联系人", "通讯录", "推荐好友", "找人"),
    "相机": ("拍照", "拍摄", "扫一扫", "扫码", "头像", "视频通话", "上传照片"),
    "照片": ("相册", "上传", "图片", "照片", "头像", "保存"),
    "麦克风": ("语音", "录音", "说话", "语音搜索", "语音输入", "听写"),
    "存储": ("上传", "下载", "保存", "缓存", "文件", "导出"),
    "电话": ("拨打", "客服", "电话", "通话"),
    "通话记录": ("拨打", "客服", "通话记录"),
    "短信": ("验证码", "短信", "登录"),
    "日历": ("日程", "提醒", "行程"),
    "通知": ("提醒", "推送", "消息"),
    "蓝牙": ("连接设备", "蓝牙", "手环", "耳机"),
    "附近设备": ("连接设备", "投屏", "附近"),
    "身体": ("步数", "运动", "健康", "心率"),
}

# 表示"目的"的词。缺了它们就不算说明，只是描述。
PURPOSE_WORDS = ("用于", "以便", "为了", "方便", "目的", "以提供", "以为您",
                 "以向您", "以帮助", "帮助您", "便于", "为您")

# 权限名的别名：系统弹窗写法五花八门（"获取设备的定位信息""读写设备上的照片"），
# 归类时要落到 PERM_FUNCS 的键上，否则逐条判据找不到功能词 —— 免费手机投屏神器
# 那轮第二个场景 perm 是空的（弹窗写"获取设备的定位信息"），判成了"未知权限"。
_PERM_ALIAS = (
    ("定位", "位置"), ("位置", "位置"), ("地理位置", "位置"),
    ("照片", "照片"), ("图片", "照片"), ("媒体", "照片"),
    ("存储", "存储"), ("文件", "存储"),
    ("通话", "电话"), ("电话", "电话"),
    ("麦克风", "麦克风"), ("录音", "麦克风"),
    ("相机", "相机"), ("摄像", "相机"),
)

# 「同步告知」的强提示词：App 用浮窗/横幅专门说明权限用途时，
# 几乎都会带上这类抬头（"相关权限说明："）。截图 OCR 读到它就基本能定案。
PURPOSE_BANNER_WORDS = ("权限说明", "权限用途", "权限提示", "申请说明",
                        "使用说明", "权限申请说明")

_SENT_SPLIT = re.compile(r"[。！？；\n|]")

# 子句切分：逗号、分号、空格、斜杠都算分隔。
# 界面 dump 出来的文字是**空格拼接**的（"需要开启定位权限 查看已连接的WIFI"），
# 不按空格切就分不清"同一句话里的说明"和"隔着十几屏文案的两个词"。
_CLAUSE_SPLIT = re.compile(r"[，,。；;！!？?、\s/]+")

# 用途说明的「出处」。事实表里必须写清依据在哪，否则"有（……整段原文……）"
# 读不出重点：是弹窗里自带的一句，还是弹窗上方的浮窗，还是申请前那一屏。
_PURPOSE_SRC_LABEL = {
    "dialog": "系统弹窗内",
    "banner": "同屏浮窗/横幅",
    "pre": "权限弹窗前一刻的界面",
}


def _norm_perm(perm: str) -> str:
    p = (perm or "").strip()
    for k, v in _PERM_ALIAS:
        if k in p:
            return v
    return p


def _funcs_for(perm: str) -> Tuple[str, ...]:
    p = _norm_perm(perm)
    for k, v in PERM_FUNCS.items():
        if k in p:
            return v
    return ()


def explained_in_text(text: str, perm: str) -> Tuple[bool, str]:
    """这段界面文字里，有没有针对该权限说明用途。返回 (是否, 原文摘录)。

    判据要求**同句**成立：目的词与该权限的功能词出现在同一句。
    跨句组合会把"为您提供更好服务。我们不会读取通讯录"拼成一句用途说明。

    ★ 第二条通路（2026-10-27，免费手机投屏神器实测）：
      浮窗原文是「相关权限说明：获取位置信息权限 用于获取附近的免费WIFI列表
      若拒绝该功能将无法使用」—— 有"用于"，能过第一条。
      但很多 App 的写法是「需要开启定位权限，查看已连接的 WiFi」：
      没有"用于/以便"，语义却是明确的目的说明。
      这类句子只要同时满足「权限名/功能词」+「场景描述」+「申请语气」，
      同样算同步告知 —— 否则会把已经告知的判成未告知（错判方向更糟）。
      反例保护：单纯的按钮文案「开启定位」没有申请语气也没有场景描述，不算。
    """
    t = text or ""
    if not t.strip():
        return False, ""
    funcs = _funcs_for(perm)
    pnorm = _norm_perm(perm)
    for sent in _SENT_SPLIT.split(t):
        s = sent.strip()
        if not s or len(s) < 6:
            continue
        # ① 目的词 + 功能词（强判据）
        if any(w in s for w in PURPOSE_WORDS):
            if funcs and not any(f in s for f in funcs) and (perm or "") not in s:
                continue
            if not funcs and (perm or "") not in s:
                continue
            return True, s[:120]
        # ② 「申请某权限，用来做某事」的口语写法（弱一点，但仍是同步告知）。
        #    ★ 必须按**子句**匹配：界面文本是空格拼起来的，整段当一句判会让
        #      "需要开启定位权限 … 投图片" 这种跨十几个词的组合被当成
        #      "照片权限的用途说明"（免费手机投屏神器就差点这样误判）。
        #      只认相邻两个子句：权限词在一句、场景描述紧挨着另一句。
        parts = [x.strip() for x in _CLAUSE_SPLIT.split(s) if x.strip()]
        for i, cl in enumerate(parts):
            if not any(w in cl for w in ("需要", "需开启", "请开启", "请允许", "申请")):
                continue
            if not any(w in cl for w in ("权限", pnorm) if w):
                continue
            if funcs and not any(f in cl for f in funcs) and pnorm not in cl:
                continue
            # 场景描述在同一个子句里，或紧跟其后的一个子句里
            nxt = parts[i + 1] if i + 1 < len(parts) else ""
            scene = cl + ("，" + nxt if nxt else "")
            rest = scene
            for f in (funcs or ()) + (pnorm, "权限", "需要", "开启", "请"):
                rest = rest.replace(f, "")
            if len(rest.strip(" ，,。:：、*")) < 6:
                continue
            return True, scene[:120]
    return False, ""


def judge_scene(scene: Dict[str, Any]) -> Dict[str, Any]:
    """给一条权限场景补 `purpose`（dialog/banner/pre/none/空）与 `explain`。

    `purpose` 为空表示**证据不足**：弹窗前那一屏没抓到文字（结构树读不出），
    此时不能算"未告知"，只能说"没看出来"。

    banner：截图里读到的浮窗/横幅说明（`banner_text`）。它与权限弹窗**同屏**出现，
    是真正意义上的"同步告知"，优先级仅次于弹窗自带说明。
    """
    s = dict(scene or {})
    perm = str(s.get("perm") or s.get("perm_raw") or "")
    if not str(s.get("perm") or "").strip():
        # 旧存档里弹窗写的是"获取设备的定位信息"这类长句，`perm` 字段是空的，
        # 于是报告的事实表里整列都是"获取设备的定位信息 免费手机投屏神器 拒绝
        # 本次运行允许 仅在使用中允许"—— 复核员看不出这是哪个权限。
        # 用别名表压成短名（定位/位置），原文仍留在 perm_raw 与 dialog_text 里。
        _short = _norm_perm(str(s.get("perm_raw") or ""))
        if _short and _short != (s.get("perm_raw") or ""):
            s["perm"] = _short
    if s.get("has_purpose"):
        s["purpose"] = "dialog"
        s["explain"] = str(s.get("purpose_quote") or "").strip()[:160] or "（弹窗内含有用途说明）"
        return s
    banner = str(s.get("banner_text") or "")
    bq = str(s.get("banner_purpose") or "").strip()
    if bq:
        s["purpose"] = "banner"
        s["explain"] = bq[:160]
        return s
    if banner.strip():
        ok, quote = explained_in_text(banner, perm)
        if ok:
            s["purpose"] = "banner"
            s["explain"] = quote
            return s
    pre = str(s.get("pre_text") or "")
    ok, quote = explained_in_text(pre, perm)
    if ok:
        s["purpose"] = "pre"
        s["explain"] = quote
        return s
    if not pre.strip():
        s["purpose"] = ""
        s["explain"] = ""
        return s
    s["purpose"] = "none"
    s["explain"] = ""
    return s


def _session_explains(screens: Iterable[Any], perm: str) -> Tuple[bool, str]:
    """整个会话的所有界面文字里，有没有针对该权限的用途说明。

    ★ 只作人工复核线索，**不参与 Q026 的结论**。
      命中与否取决于本轮遍历有没有翻到那一屏（常见于设置里的"权限使用说明"
      静态页），拿它否定"申请时未同步告知"会让结论随遍历范围漂移。
      判状态请看 `judge()` 里 `purpose` 的取值。
    """
    for sc in screens or []:
        texts = sc.get("texts") if isinstance(sc, dict) else None
        if not texts:
            continue
        ok, quote = explained_in_text(" ".join(str(x) for x in texts), perm)
        if ok:
            where = (sc.get("label") or "") if isinstance(sc, dict) else ""
            return True, ("%s：%s" % (where, quote)) if where else quote
    return False, ""


def judge(scenes: Sequence[Dict[str, Any]],
          screens: Sequence[Any] = ()) -> Dict[str, Any]:
    """汇总全部权限场景，给出 Q026 的状态、结论与事实表。"""
    # ★ 只在"确认应用在前台"的场景上下结论（2026-11-10 铁路火车票真机实测）：
    #   采集侧已经写进 errors："该弹窗出现时应用不在前台（截图背景为系统桌面）……
    #   此场景只记录弹窗原文，不作为「应用在运行中申请该权限」的证据"，
    #   而判定层照旧拿它判了 pass —— 同一份报告两头自相矛盾，签字的人只会
    #   看到「每次都能看到用途说明」，看不到那句否定。
    #   闸门放在入口而不是逐分支打补丁：只要有场景不可用，它就不许参与
    #   silent/explained/unclear 的任何统计。
    _all = [s for s in (scenes or []) if isinstance(s, dict)]
    _usable = [s for s in _all if s.get("evidable") is not False]
    _unusable = len(_all) - len(_usable)
    if _all and not _usable:
        return {"scenes": [judge_scene(s) for s in _all], "state": M.NOT_TESTED,
                "desc": "",
                "reason": ("本次捕获到 %d 次系统权限申请，但每一次都无法确认弹窗出现时"
                           "被测应用是否在前台（应用当时多半已被退出、或正在重新拉起），"
                           "按取证规矩这类场景只能记录弹窗原文、不能作为「应用在运行时"
                           "申请该权限」的证据，故本项不下结论；需在应用稳定运行的轮次"
                           "复测该场景" % len(_all)),
                "facts": [], "stats": {"total": len(_all), "unusable": _unusable}}
    judged = [judge_scene(s) for s in _usable]
    if not judged:
        return {"scenes": [], "state": M.NOT_TESTED, "desc": "", "reason": "",
                "facts": [], "stats": {}}

    silent = [s for s in judged if s.get("purpose") == "none"]
    explained = [s for s in judged if s.get("purpose") in ("dialog", "banner", "pre")]
    unclear = [s for s in judged
               if s.get("purpose") not in ("dialog", "banner", "pre", "none")]

    facts: List[List[str]] = []
    for s in judged:
        _at = s.get("at_ms")
        _src = _PURPOSE_SRC_LABEL.get(s.get("purpose") or "", "")
        # 「无」和「没核」是两件事：浮窗这一路没看过图，就不能写"无浮窗"。
        if s.get("banner_text"):
            _ban = str(s.get("banner_text"))[:60]
        elif s.get("banner_unread"):
            _ban = "未核对（本轮未读该弹窗截图）"
        else:
            _ban = "无"
        facts.append([
            "%s（第 %s 阶段%s）" % (
                s.get("perm") or s.get("perm_raw") or "权限",
                s.get("phase") or "—",
                "，冷启动第 %.1f 秒" % (float(_at) / 1000.0) if _at else ""),
            "弹窗前界面：%s；同屏浮窗说明：%s；系统弹窗：%s；用途说明：%s" % (
                (s.get("pre_text") or "未记录")[:60],
                _ban,
                (s.get("dialog_text") or "未记录")[:60],
                ("有（%s：%s）" % (_src, s.get("explain"))) if s.get("explain") else "无")])

    perms = []
    for s in judged:
        p = s.get("perm") or s.get("perm_raw") or ""
        if p and p not in perms:
            perms.append(p)

    stats = {"total": len(judged), "explained": len(explained),
             "silent": len(silent), "unclear": len(unclear), "perms": perms,
             # 被排除掉的不可用场景数：报告要能解释"为什么只算了这几次"，
             # 否则复核员会以为本轮只弹过这么几次权限框。
             "unusable": _unusable}
    _unusable_note = ("；另有 %d 次权限弹窗因无法确认应用当时在前台（应用被退出/"
                      "正在重新拉起）未计入本次判定" % _unusable) if _unusable else ""

    if not silent:
        if explained and not unclear:
            _srcs = []
            for _k in ("dialog", "banner", "pre"):
                if any(s.get("purpose") == _k for s in explained):
                    _srcs.append(_PURPOSE_SRC_LABEL[_k])
            return {"scenes": judged, "state": M.PASS,
                    "desc": "本次共捕获 %d 次系统权限申请（%s），"
                            "每次都能看到针对该权限的用途说明（依据：%s）%s"
                            % (len(judged), "、".join(perms),
                               "、".join(_srcs) or "弹窗内或申请前界面",
                               _unusable_note),
                    "reason": "", "facts": facts, "stats": stats}
        return {"scenes": judged, "state": M.NOT_TESTED,
                "reason": "本次捕获到 %d 次权限申请，但弹窗出现前的界面文字未能取得"
                          "（结构树读取不到该屏），无法判断是否同步告知目的" % len(judged),
                "facts": facts, "stats": stats}

    # ★ 认定与否，只由「这一次申请」自带的证据决定：弹窗内文字 + 弹窗前那一屏。
    #
    #   这里曾经有一道「全会话兜底」：只要本轮遍历中**任何一屏**出现过该权限的
    #   用途说明，就把未告知的场景从认定里剔除。它在真机上极不稳定 ——
    #   以观书法同一个包、同一个版本连跑五轮，Q026 在「认定」与「疑似」之间
    #   来回跳：mbsf16 第 36 步、mbsf18 第 24 步恰好翻到设置里的
    #   「相机权限使用说明：用于拍照图片」，这句静态说明就把两条「弹窗无说明」
    #   洗成了疑似；mbsf15、mbsf19 没翻到那一屏，同样的两条就判为认定。
    #   题面问的是「申请权限时是否同步告知」，一张事后才被翻到的说明页
    #   不构成同步告知 —— 它可以是人工复核的线索，但不应参与结论。
    #
    #   同理，「同一会话抓到两次以上才认定」这个次数门槛也去掉了：
    #   一次还是两次，取决于本轮点开了几个会索权的功能，与 App 有没有告知目的
    #   无关。证据完整的一次（弹窗原文与弹窗前界面都取到）就足够认定；
    #   读不到弹窗前界面的场景 purpose 为空，本来就不进 silent。
    elsewhere: Dict[str, str] = {}
    for s in silent:
        ok, q = _session_explains(screens, str(s.get("perm") or ""))
        if ok:
            elsewhere[s.get("perm") or ""] = q
    # 线索进 stats，不进 desc 主句：主句必须每轮一致，否则读报告的人
    # 会以为结论变了，其实只是这次多翻到一屏。
    stats["elsewhere"] = dict(elsewhere)

    # ★ 「没读到浮窗」不等于「没有浮窗」（免费手机投屏神器 2026-10-26 实测）：
    #   那一轮 App 在屏幕顶部弹了「相关权限说明：获取存储空间权限 用于获取您
    #   手机内的视频,图片,音频文件信息」，与系统弹窗**同时**出现、被压暗；
    #   uiautomator dump 只导最顶层窗口，这句一个字都读不到。
    #   于是"文本层看不到 = 没告知"，直接写成确证「未同步告知目的」——
    #   用户一看截图就知道判错了。
    #   所以：浮窗这一路证据**没核过**（没视觉能力 / 没截图 / 预算用完），
    #   就只能判"疑似、需人工看图复核"，不能判确证。
    unread = [s for s in silent if s.get("banner_unread")]
    stats["banner_unread"] = len(unread)
    stats["banner_read"] = sum(1 for s in judged if s.get("banner_source"))

    names = "、".join("「%s」（第 %s 阶段%s）" % (
        s.get("perm") or "权限", s.get("phase") or "—",
        "，弹窗前界面为「%s」" % (s.get("pre_text") or "")[:24] if s.get("pre_text") else "")
        for s in silent[:6])

    _desc = ("本次在 %d 个场景中申请了可收集个人信息的权限，系统弹窗内没有用途说明，"
             "申请前的界面中也没有说明目的，属于未同步告知用户其目的：%s"
             % (len(silent), names))
    if elsewhere:
        _desc += ("。另：本次遍历在其他界面翻到过该权限的用途说明（%s），"
                  "但那是事后的说明页，不是申请时的同步告知，未据此改变本项结论"
                  % "、".join(sorted(elsewhere)))
    if unread:
        # 有场景的同屏浮窗没核过 —— 结论只能到"疑似"。
        _un = "、".join("「%s」" % (s.get("perm") or "权限") for s in unread[:4])
        _why = ("本轮未启用视觉能力或读取失败，没有看过这些弹窗的截图"
                if not stats.get("banner_read") else "部分场景的截图未能覆盖")
        return {"scenes": judged, "state": M.SUSPECT,
                "desc": ("疑似：%d 个权限申请场景中，%s 的弹窗内文字与申请前界面都没有"
                         "读到用途说明；但同屏浮窗/横幅这一路证据没有核对"
                         "（%s），而这类说明在与弹窗同时出现时常常被压在下方、"
                         "系统结构树读不到。现有证据不足以确证「未同步告知目的」，"
                         "需人工查看该项附图确认。"
                         % (len(silent), _un, _why)),
                "reason": "", "facts": facts, "stats": stats}
    return {"scenes": judged, "state": M.FAIL,
            "desc": _desc, "reason": "", "facts": facts, "stats": stats}


__all__ = ["PERM_FUNCS", "PURPOSE_WORDS", "explained_in_text", "judge_scene",
           "judge"]
