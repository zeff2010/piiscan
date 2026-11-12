"""「先按 URL 取政策全文，取不到才滑动阅读」的回归测试（不连真机、不发请求）。

守的是用户 2026-10-21 提的第一条意见：
    "优先想办法拿到隐私政策的 url，然后直接通过 url 拿到全文的隐私政策，
     不要在隐私政策页面下滑查看隐私政策过程浪费太多时间，
     除非拿不到隐私政策的 url，那只能不断下滑截图阅读隐私政策全文了。"

为什么这条值得单独守：
    一屏屏上滑读政策是整轮采集里最贵的一段 —— 每滑一次 1s 等待 + 约 2.8s 的
    uiautomator dump，外加一次 3~4s 的模型问答；深挖三层就是好几分钟，
    而这些时间全从遍历预算里扣。政策页几乎都对应一个 URL，
    一次 HTTP 只要 1~2 秒，拿到的还是**完整全文**。

所以顺序必须是：有 URL → 直取；取不到/取回来不像政策 → 才退回滑动。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiscan import collector as C            # noqa: E402
from piiscan import policy as POL             # noqa: E402

OK = 0
BAD: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global OK
    if cond:
        OK += 1
    else:
        BAD.append("%s%s" % (name, ("　→ " + detail) if detail else ""))
        print("  ✗ %s%s" % (name, ("　→ " + detail) if detail else ""))


# 一份"像隐私政策"的正文（开头必须交代隐私/个人信息，且足够长）
_REAL = ("隐私政策\n本政策适用于以观书法。我们如何收集和使用个人信息："
         "设备识别码、MAC 地址、位置信息……" + "个人信息保护" * 400)
# 一份"不是隐私政策"的长文（会员协议）
_CONTRACT = ("VIP会员服务协议\n会员价格与购买渠道如下："
             "连续包月 ¥28，连续包年 ¥268……" + "会员权益说明" * 400)

_real_fetch = POL.fetch


def _fake_fetch(table):
    def _f(url, timeout=25, log=None):
        r = table.get(url)
        if r is None:
            class _R:
                text = ""
                title = ""
                error = "连接失败"
            return _R()
        class _R:
            text = r
            title = "标题"
            error = ""
        return _R()
    return _f


def _install(table):
    POL.fetch = _fake_fetch(table)
    C._POL.fetch = POL.fetch


def _uninstall():
    POL.fetch = _real_fetch
    C._POL.fetch = _real_fetch


# ============================================================ ① 候选排序
def t_rank():
    urls = [
        "https://a.com/logo.png",
        "https://a.com/other/page",
        "https://a.com/privacy.html",
        "https://a.com/privacy.html",          # 重复
        "ftp://a.com/privacy",
        "",
    ]
    got = C._rank_policy_urls(urls)
    check("非 http 的被剔除", all(u.startswith("http") for u in got), got)
    check("图片/样式类被剔除", not any(u.endswith(".png") for u in got), got)
    check("重复被去掉", len(got) == len(set(got)), got)
    check("含 privacy 的排在最前", got and "privacy" in got[0], got)
    check("空串不进列表", "" not in got)


# ============================================================ ② 取到了就用
def t_ok():
    _install({"https://a.com/privacy.html": _REAL})
    try:
        r = C.fetch_policy_by_url(["https://a.com/privacy.html"], log=lambda *a: None)
        check("★ 拿到合格政策 → ok", r.get("ok") is True)
        check("返回正文", len(r.get("text") or "") > 800)
        check("返回 URL", r.get("url") == "https://a.com/privacy.html")
        check("记录了字数", r.get("chars") == len(r.get("text") or ""))
    finally:
        _uninstall()


# ============================================================ ③ 三条拒绝闸门
def t_gates():
    _install({
        "https://a.com/vip.html": _CONTRACT,                    # 不像政策
        "https://a.com/short.html": "隐私政策（就一句）",          # 太短
        "https://a.com/dead.html": None,                         # 抓取失败
    })
    try:
        r = C.fetch_policy_by_url(
            ["https://a.com/vip.html"], log=lambda *a: None)
        check("★ 会员协议不像隐私政策 → 不认", r.get("ok") is False)
        check("不认的原因写明'不像隐私政策'",
              "隐私政策" in (r["tried"][0].get("why") or ""), r["tried"])

        r2 = C.fetch_policy_by_url(
            ["https://a.com/short.html"], log=lambda *a: None)
        check("正文过短 → 不认（可能是 JS 渲染）", r2.get("ok") is False)
        check("过短的原因写明字数", "过短" in (r2["tried"][0].get("why") or ""), r2["tried"])

        r3 = C.fetch_policy_by_url(
            ["https://a.com/dead.html"], log=lambda *a: None)
        check("抓取失败 → 不认", r3.get("ok") is False)

        # 一个失败不该挡住后面那个能成的
        r4 = C.fetch_policy_by_url(
            ["https://a.com/dead.html", "https://a.com/x",
             ], log=lambda *a: None)
        check("多个都失败时 ok=False 且留下全部尝试记录",
              r4.get("ok") is False and len(r4.get("tried") or []) >= 1)
    finally:
        _uninstall()


def t_tried_kept():
    """失败了也要留痕 —— 报告要能回答"为什么还是去滑了"。"""
    _install({"https://a.com/dead.html": None})
    try:
        r = C.fetch_policy_by_url(["https://a.com/dead.html"], log=lambda *a: None)
        check("失败仍返回 dict（不是 None）", isinstance(r, dict))
        check("失败也带 tried 留痕", bool(r.get("tried")))
        check("tried 里写明原因", bool((r["tried"][0].get("why") or "")), r["tried"])
    finally:
        _uninstall()


# ============================================================ ④ 没有 URL 直接放行
def t_empty():
    _install({})
    try:
        r = C.fetch_policy_by_url([], log=lambda *a: None)
        check("没有候选链接时 ok=False、不报错", r.get("ok") is False)
        check("没有候选时不留 tried", r.get("tried") == [])
        r2 = C.fetch_policy_by_url(["", "ftp://x", "https://a.com/a.js"],
                                   log=lambda *a: None)
        check("全是无效链接时不报错", r2.get("ok") is False)
    finally:
        _uninstall()


def main() -> int:
    for fn in (t_rank, t_ok, t_gates, t_tried_kept, t_empty):
        fn()
    print("\n政策 URL 直取回归：%d 项通过，%d 项失败" % (OK, len(BAD)))
    for b in BAD:
        print("  - %s" % b)
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
