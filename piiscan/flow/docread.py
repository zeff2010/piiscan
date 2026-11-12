"""在「别人的界面」里读文档：应用把政策链接交给系统浏览器 / 系统组件时用。

## 为什么需要单独一个模块

2026-11-03 的 10 单里有 4 单栽在同一件事上：**隐私政策不在应用里**。

    · 春雨诊所：点《春雨诊所隐私政策》→ `com.android.browser/.BrowserActivity`，
      那一屏的结构树里有 312 条文字、826 字长文本 —— 政策正文就在眼前；
    · 高途：点《高途隐私政策》→ 同样是 `.BrowserActivity`；
    · 携船网：点《服务协议》和《隐私政策》→ 自带的 WebviewActivity，
      首屏还在加载（3 条文字 / 0 字），第 2 屏才有正文。

旧逻辑在这三处都只做了一件事：判成"由系统组件/外部应用接管"，
记一条 error 就放弃 —— 于是 P2 一律"未能取得政策正文"，
下游 P5 政策对照整段跳过，二十几项只能记「跳过未测」。
**正文明明就在屏幕上，只是不在我们自己的 WebView 里。**

## 边界（必须写清，否则会读完整个互联网）

  · 只读**当前这一屏及其后续滚动**，不点任何按钮 —— 外部应用里的点击会操作
    真实账号（浏览器里有登录态、有书签、有历史），这条与 `flow/foreign.py` 一致；
  · 有硬上限：最多滚 `max_scrolls` 屏、单次调用不超过 `budget` 秒；
  · 连续两屏没读到新内容就停（到底了 / 触发了懒加载的"再试一次"）；
  · 命中错误页特征立刻停 —— 高途那一屏就是"网络链接有问题"，
    在上面滚一百屏也滚不出政策。

纯函数（`error_sign` / `stitch` / `page_text`）与设备侧读取（`read_page`）分开：
前者可离线测，后者只做"dump → 收割 → 滑一屏 → 再 dump"这一件事。
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

# ---------------------------------------------------------------- 错误页

# 「这一页打不开」的特征词。真机上这几类页面长得都很像，但文案差别很大：
#   · Chrome / 系统浏览器：无法访问此网站、ERR_CONNECTION_TIMED_OUT、DNSPod
#   · 各家 App 自绘的错误页：网络连接失败、请检查网络设置、加载失败，点击重试
#   · 404 页：访问的页面不存在、404 Not Found
# 只认**整句**，不认"网络""失败"这种到处都有的词 —— 登录页上也写着
# "网络异常时可用验证码登录"，那是正常页面。
ERROR_HINTS: tuple = (
    "无法访问此网站", "网页无法打开", "无法打开网页", "网页打不开",
    "网络连接错误", "网络连接失败", "网络连接有问题", "网络连接不可用",
    "网络未连接", "请检查网络", "请检查网络设置", "网络异常，请稍后",
    "加载失败", "页面加载失败", "加载出错", "内容加载失败",
    "暂时无法打开", "暂时无法访问", "服务暂时不可用", "找不到网页",
    "访问的页面不存在", "您所访问的页面不存在", "页面不存在", "页面已失效",
    # ★ 不认裸 "404"：政策正文里"第 404 条"、金额"1,404 元"都会命中，
    #   而它命中后的处置是"跳过这一页"—— 正文会被整段丢掉，代价远大于收益。
    #   中文 404 页面基本都带"页面不存在 / 找不到页面"，靠它们就够。
    "404 not found", "404 错误", "404错误", "找不到页面",
    "err_connection", "err_name_not_resolved",
    "err_internet_disconnected", "err_timed_out", "err_proxy_connection",
    "err_empty_response", "err_ssl", "net::err_",
)

# 错误页上一定不会出现的词。命中就**不判**错误页 —— 这条是防误杀的：
# Chrome 的"无法访问此网站"页底部常常带一句"请检查网络连接"，而正常的
# 政策页里也会出现"网络连接"字样（"为保障您在使用网络连接服务时的…"）。
# 所以只要页面上有政策/正文特征，就不能当错误页跳过。
DOC_HINTS: tuple = (
    "隐私政策", "隐私权", "个人信息保护", "用户协议", "服务协议",
    "收集", "使用目的", "共享", "第三方", "未成年人", "注销",
)


def error_sign(texts: Any) -> str:
    """这一屏像不像"打不开"的错误页。返回命中的特征词（空串 = 不像）。

    `texts` 可以是字符串，也可以是若干条文字组成的序列。
    """
    if isinstance(texts, str):
        blob = texts
    else:
        blob = " ".join(str(t) for t in (texts or ()) if t)
    low = blob.lower()
    if not low.strip():
        return ""
    # 页面上已经有大量正文特征 → 不是错误页（防止把"网络连接"这类
    # 政策条款里的词当成错误提示）。
    doc_hits = sum(1 for w in DOC_HINTS if w in blob)
    for w in ERROR_HINTS:
        if w.lower() in low:
            if doc_hits >= 4 and len(blob) > 1200 and w not in (
                    "404 not found", "无法访问此网站", "网页无法打开"):
                # 正文够长且政策特征密集 → 宁可不判错误页（读错比跳过更糟）
                continue
            return w
    return ""


# ---------------------------------------------------------------- 文本拼接

_LINE_NOISE = re.compile(r"^[\s\d:：/|·.\-—]+$")


def page_text(xml: str) -> str:
    """把一屏结构树里的**全部**文字按 DOM 顺序拼起来。

    与 `collector._harvest_ui_text` 的区别：那个只取 ≥120 字的**单个**长文本
    （政策常是一个大 TextView），而浏览器渲染出来的正文是**几十个短块**
    —— 每段一个节点，单看谁都不够 120 字。这里不设长度门槛，改用行级去重，
    拼出来才是一篇能读的正文。
    """
    if not xml:
        return ""
    try:
        from .. import uiwalk
        texts = uiwalk.screen_texts(xml)
    except Exception:
        return ""
    return stitch(texts)


def stitch(texts: Sequence[str]) -> str:
    """把多段文字拼成正文，按行去重且保持顺序。

    浏览器的可访问性树会把**同一段文字拆成多行**（`<p>` 换行、CSS 折行），
    滚动之后上一屏的尾部还会重复出现 —— 不去重的话 6 屏能滚出 3 倍的重复，
    长度看着漂亮，实际全是同一段话。
    """
    out: List[str] = []
    seen: set = set()
    for t in texts or ():
        for raw in str(t or "").splitlines():
            line = raw.strip()
            if not line or len(line) < 2:
                continue
            if _LINE_NOISE.match(line):
                continue
            if line in seen:
                continue
            seen.add(line)
            out.append(line)
    return "\n".join(out)


def novel_chars(old: str, new: str) -> int:
    """`new` 里有多少字是 `old` 没有的（用于判"还在往下读"还是"到底了"）。"""
    if not new:
        return 0
    if not old:
        return len(new)
    add = 0
    tail = old[-400:]          # 只比尾部：新一屏的前半段本就是上一屏的尾巴
    for line in new.splitlines():
        if line and line not in tail:
            add += len(line)
    return add


# ---------------------------------------------------------------- 设备侧读取

def read_page(serial: str,
              log: Optional[Callable[[str], None]] = None,
              *,
              max_scrolls: int = 6,
              budget: float = 90.0,
              min_chars: int = 1500,
              stop_if: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
    """把**当前这一屏**（通常是系统浏览器）的正文读下来。

    返回 `{"text", "chars", "screens", "err", "scrolled", "why"}`：
      · `err` 非空表示命中错误页特征，调用方应当直接放弃、别再等；
      · `text` 是逐屏拼接去重后的正文；
      · `why` 是给日志/报告看的一句话结论。

    停止条件（任一满足即停）：
      1. 命中错误页特征；
      2. 已读到 `min_chars` 且本屏没新增（正文够长）；
      3. 连续 2 屏没有新增内容（到底 / 懒加载没触发）；
      4. 滚满 `max_scrolls` 屏 / 超过 `budget` 秒。
    """
    from .. import uiwalk

    def _say(msg: str) -> None:
        if log:
            log(msg)

    t0 = time.time()
    chunks: List[str] = []
    text = ""
    err = ""
    screens = 0
    scrolled = 0
    xml = uiwalk.dump_retry(serial, tries=2, wait=0.6)
    if not xml:
        return {"text": "", "chars": 0, "screens": 0, "err": "",
                "scrolled": 0, "why": "读不到界面结构（该页可能还在加载）"}

    stall = 0
    while True:
        screens += 1
        piece = page_text(xml)
        _err = error_sign(piece)
        if _err:
            err = _err
            if piece:
                chunks.append(piece)
            break
        if piece:
            add = novel_chars(text, piece)
            chunks.append(piece)
            text = stitch(chunks)
            if add < 40:
                stall += 1
            else:
                stall = 0
        else:
            stall += 1
        if len(text) >= min_chars and stall:
            break
        if stall >= 2:
            break
        if scrolled >= max(0, int(max_scrolls)) or (time.time() - t0) >= budget:
            break
        if stop_if is not None:
            try:
                if stop_if():
                    _say("[.] 读页面期间收到停止信号，提前收手")
                    break
            except Exception:
                pass
        uiwalk.scroll(serial, "down")
        scrolled += 1
        time.sleep(0.9)
        xml = uiwalk.dump_retry(serial, tries=1, wait=0.4)
        if not xml:
            stall += 1
            if stall >= 2:
                break
            continue

    if err:
        why = "页面打不开（命中「%s」）" % err
    elif len(text) >= min_chars:
        why = "读到 %d 字（%d 屏）" % (len(text), screens)
    elif text:
        why = "只读到 %d 字（%d 屏），不足以作为正文" % (len(text), screens)
    else:
        why = "这一页没有可读文字"
    return {"text": text, "chars": len(text), "screens": screens,
            "err": err, "scrolled": scrolled, "why": why}


# ---------------------------------------------------------------- 政策入口判定

# 入口文字里出现这些，说明**这一下点开的就是一份文档**，落点即使跑到浏览器
# 也是"去读政策"，不是"跳去玩别的"。
POLICY_ENTRY_WORDS: tuple = (
    "隐私", "隐私政策", "隐私协议", "个人信息保护", "个人信息", "用户协议",
    "服务协议", "使用协议", "协议", "条款", "声明", "授权书", "儿童",
)


def is_policy_entry(label: str) -> bool:
    """这个入口点开的是一份政策/协议文档吗。

    ★ 只认**文档型**措辞，不认"登录""授权"：点"微信登录"也会开浏览器，
      那是第三方授权流程（由 `foreign.classify` 单独判 ① 级证据），
      与"读政策正文"是两件事。
    """
    s = (label or "").strip()
    if not s:
        return False
    return any(w in s for w in POLICY_ENTRY_WORDS)
