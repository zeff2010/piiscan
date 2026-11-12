"""遮挡剔除（uiwalk.occluded_map）的离线用例。

起因（2026-11-01 人工接管实测，川剧迷）：设置页「关于」与底部固定导航栏
「图片墙」的 bounds 几乎重合，点「关于」实际切到了图片墙 tab。
这类点击白花一步还带偏后续所有判断，所以从候选里剔除；剔除后必须
在日志/报告里留一句，否则"这屏怎么少点了几个"没法回答。

这里守两条边界：
  · 内部子元素（图标、文字）**不能**被当成遮挡，否则整页的可点元素会被误杀；
  · 真正重叠的兄弟才判，相邻但不重叠的不许判。
"""

from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_HEAD = '<hierarchy rotation="0"><node text="" class="android.widget.FrameLayout" ' \
        'clickable="false" enabled="true" bounds="[0,0][1080,2400]">'
_TAIL = "</node></hierarchy>"


def _n(text="", rid="", cls="android.widget.TextView", click="true", bounds="[0,0][10,10]"):
    return ('<node text="%s" resource-id="%s" class="%s" clickable="%s" '
            'enabled="true" bounds="%s"/>' % (text, rid, cls, click, bounds))


def run(check) -> None:
    from piiscan import uiwalk

    # -------------------------------------------------- 真实场景：关于 vs 图片墙
    xml = _HEAD + (
        _n("关于", "id:ll_about", "android.widget.LinearLayout",
           "true", "[14,2195][1066,2261]")
        + '<node text="" class="android.widget.LinearLayout" clickable="false" '
          'enabled="true" bounds="[0,2150][1080,2400]">'
        + _n("图片墙", "lb:tu", "android.widget.TextView", "true", "[14,2195][1066,2261]")
        + "</node>"
    ) + _TAIL
    occ = uiwalk.occluded_map(xml)
    hit = {n.label: occ.get(uiwalk.node_key(n), "") for n in uiwalk.clickable(xml)}
    check("★ 被底部固定导航压住的「关于」判为遮挡", hit.get("关于") == "图片墙", hit)
    check("★ 遮挡物自身不算被遮挡", hit.get("图片墙") == "", hit)

    # -------------------------------------------------- 不重叠：一个都不许判
    xml2 = _HEAD + (
        _n("设置", "id:a", "", "true", "[14,100][1066,200]")
        + _n("退出", "id:b", "", "true", "[14,300][1066,400]")
        + _n("帮助", "id:c", "", "true", "[14,500][1066,600]")
    ) + _TAIL
    check("★ 不重叠的兄弟零误报", uiwalk.occluded_map(xml2) == {},
          uiwalk.occluded_map(xml2))

    # -------------------------------------------------- 内部子元素：不算遮挡
    xml3 = _HEAD + (
        '<node text="设置" resource-id="id:row" class="android.widget.LinearLayout" '
        'clickable="true" enabled="true" bounds="[14,100][1066,200]">'
        + _n("", "id:icon", "android.widget.ImageView", "false", "[30,110][90,170]")
        + _n("设置", "id:txt", "android.widget.TextView", "false", "[110,110][400,170]")
        + "</node>"
    ) + _TAIL
    check("★ 行内的图标/文字不算遮挡（否则整页候选会被误杀）",
          uiwalk.occluded_map(xml3) == {}, uiwalk.occluded_map(xml3))

    # -------------------------------------------------- 压住中心点才算，压边角不算
    # 点击是打在**中心点**上的：浮层只盖住右半边时，点中心照样能点到按钮，
    # 这时判遮挡会把本来能用的入口误杀。
    xml4 = _HEAD + (
        _n("立即领取", "id:cta", "android.widget.Button", "true", "[100,1000][900,1100]")
        + _n("关闭广告", "id:x", "android.widget.ImageView", "true", "[400,980][700,1120]")
    ) + _TAIL
    occ4 = uiwalk.occluded_map(xml4)
    hit4 = {n.label: occ4.get(uiwalk.node_key(n), "") for n in uiwalk.clickable(xml4)}
    check("★ 盖住中心点的浮层按钮判遮挡", hit4.get("立即领取") == "关闭广告", hit4)

    xml5 = _HEAD + (
        _n("立即领取", "id:cta", "android.widget.Button", "true", "[100,1000][900,1100]")
        + _n("关闭广告", "id:x2", "android.widget.ImageView", "true", "[820,980][1000,1120]")
    ) + _TAIL
    check("★ 只压住边角不判遮挡（中心点仍可点）",
          uiwalk.occluded_map(xml5) == {}, uiwalk.occluded_map(xml5))

    # -------------------------------------------------- 空/坏 XML 不许抛
    for bad in ("", "<hierarchy></hierarchy>", "not xml"):
        try:
            r = uiwalk.occluded_map(bad)
            ok = r == {}
        except Exception:
            ok = False
        check("坏输入不抛异常且返回空（%r）" % (bad[:12],), ok)
