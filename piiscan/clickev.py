"""逐次点击的界面留痕：截图 + 点击位置标注 + 这一步的判读与预判。

为什么要有这个模块（2026-11-05 用户意见）
--------------------------------------
报告里原来只有"UI 点击 124 次、界面 234 个"这种**合计数字**，复核员没法回答
最基本的三问：这一次点的是屏幕上哪一块？点之前那屏长什么样？凭什么点它？
于是"测得不充分"只能靠猜 —— 是没点够、点错了、还是点了没反应，全看不出来。

这个模块只做三件互不耦合的事，且都是纯函数（可离线测）：

  1. `annotate()`  —— 在**点击那一刻的截图**上画出点击位置（双色圆环 + 十字
                     + 序号标牌）。必须用点击**前**的照片：点完之后界面已经
                     换了，拿后面的图当"点之前的图"就是造假。
  2. `predict()`   —— 按入口文字/控件类型预判"这一下点下去应该发生什么"。
                     有了预判，才能事后对照"实际发生了什么"；预期与结果不一致
                     的地方，正是遍历策略该改的地方（这也是用户提的
                     "工具要知道自己点的按钮是什么意思"）。
  3. `describe()`  —— 把决策来源（AI 图引导 / 调度器 / 规则兜底）翻成一句人话，
                     写进报告的"判读"列。

边界：本模块**不读设备、不做决策**，只处理字节与文字。截图失败、字体缺失、
图片损坏都要能吞掉并返回可用结果（一份报告不能因为一张缩略图崩掉）。
"""

from __future__ import annotations

import base64
import io
import os
import re
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["annotate", "predict", "describe", "thumb", "RESULT_LABELS"]

# 点击结果的口径。空串表示"这一击之后没等到下一屏"（采集被中断/超时），
# 不能写成"无变化"——没观测到不等于没发生。
RESULT_LABELS = {
    "new": "切换到新界面",
    "same": "界面无变化",
    "external": "前台切到了别的应用",
    "": "未判定（未观测到下一屏）",
}

# ---- 入口文字的预判表 ----
# 顺序即优先级：同一段文字命中多条时取靠前的。
# 这些预期不是"结论"，是**用于事后对照的假设**，报告里要写清是预判。
_RULES: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    ("policy", ("隐私政策", "隐私保护", "个人信息保护", "用户协议", "服务协议",
                "隐私权", "政策", "协议", "条款", "声明"),
     "预期：打开政策/协议正文页（正文可能在应用内 WebView，也可能拉起系统浏览器）",
     "高"),
    ("logout", ("注销", "注销账号", "删除账号", "撤回授权", "撤回同意",
                "个人信息收集清单", "个人信息副本", "账号安全"),
     "预期：进入权利入口（注销/撤回/查阅），是取证重点但可能有二次确认",
     "高"),
    ("consent", ("同意并", "同意", "接受", "允许并", "我知道了", "开始使用"),
     "预期：表示同意，构成「同意前/同意后」的分水岭，点击后事件要按同意后计",
     "高"),
    ("disagree", ("不同意", "拒绝", "暂不同意", "仅浏览", "以后再说"),
     "预期：不同意会退出或降级，之后无法再取证（本工具默认不点）",
     "高"),
    ("login", ("登录", "登陆", "注册", "验证码", "密码", "一键登录", "微信登录"),
     "预期：进入登录/注册流程；未配账号时该功能整片不可达",
     "中"),
    ("perm", ("允许", "始终允许", "仅在使用中允许", "禁止", "权限"),
     "预期：系统权限弹窗（点了才算「申请了权限」的现场证据）",
     "高"),
    ("setting", ("设置", "偏好", "通用", "隐私", "关于我们", "帮助", "客服"),
     "预期：进入设置/说明页，常含权利入口与第三方清单",
     "中"),
    ("close", ("关闭", "取消", "返回", "跳过", "×", "以后", "暂不"),
     "预期：关闭当前层或放弃当前流程",
     "低"),
    ("form", ("搜索", "筛选", "排序", "全部", "更多", "查看全部"),
     "预期：展开列表/筛选条件，通常不产生新的采集行为",
     "低"),
)

# 控件类型兜底：没有文字时，按类名猜这一下是干什么的。
_CLS_RULES: Tuple[Tuple[str, str, str], ...] = (
    ("EditText", "输入框：点击只是获得焦点，真正触发采集要等输入内容", "低"),
    ("CheckBox", "勾选框：用于勾选协议，本身不跳转", "中"),
    ("Switch", "开关：切换一个设置项的状态，不跳转", "中"),
    ("Button", "按钮：触发一次业务动作", "中"),
    ("ImageButton", "图标按钮：按图标语义执行动作", "中"),
    ("ImageView", "图片/图标：可能是入口，也可能只是装饰", "低"),
    ("WebView", "网页区域：点击坐标由网页自己解释，结构树看不到落点", "低"),
)


def _font(size: int):
    """优先用系统中文字体（标牌要写"点击「登录」"这种中文）。

    找不到就退回 PIL 默认位图字体 —— 字小但不会崩，标牌退化成纯序号。
    """
    try:
        from PIL import ImageFont
    except Exception:
        return None
    for p in ("C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/msyhbd.ttc",
              "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
              "/System/Library/Fonts/PingFang.ttc"):
        try:
            if os.path.exists(p):
                return ImageFont.truetype(p, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default()
    except Exception:
        return None


def annotate(png: bytes, x: int, y: int, caption: str = "",
             *, radius: int = 0) -> bytes:
    """在截图上标出点击位置，返回新的 PNG 字节。

    画法用**双色环 + 十字**：单色环在浅色/深色界面上总有一种看不清，
    白环打底再压红环，两种背景都能看清。标牌放在点的上方（上方没地方就放下方），
    并夹在画面内 —— 贴边点击时标牌被裁掉，图就白留了。
    """
    if not png:
        return b""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return png
    try:
        img = Image.open(io.BytesIO(png)).convert("RGB")
    except Exception:
        return png
    try:
        w, h = img.size
        r = int(radius or max(28.0, min(w, h) * 0.07))
        cx, cy = int(x), int(y)
        d = ImageDraw.Draw(img)
        box = [cx - r, cy - r, cx + r, cy + r]
        # 白环（外）→ 红环（内）：任何底色上都有一个对比度够的边。
        d.ellipse(box, outline=(255, 255, 255), width=max(6, r // 5))
        d.ellipse([cx - r + 3, cy - r + 3, cx + r - 3, cy + r - 3],
                  outline=(230, 30, 45), width=max(4, r // 8))
        # 十字：中心点被手指盖住时也看得出落点。
        d.line([cx - int(r * 1.5), cy, cx + int(r * 1.5), cy],
               fill=(255, 255, 255), width=max(4, r // 9))
        d.line([cx, cy - int(r * 1.5), cx, cy + int(r * 1.5)],
               fill=(255, 255, 255), width=max(4, r // 9))
        d.line([cx - int(r * 1.5), cy, cx + int(r * 1.5), cy],
               fill=(230, 30, 45), width=max(2, r // 18))
        d.line([cx, cy - int(r * 1.5), cx, cy + int(r * 1.5)],
               fill=(230, 30, 45), width=max(2, r // 18))
        # 标牌：黑底白字，紧贴圆环外侧。
        cap = (caption or "").strip()
        if cap:
            fs = max(20, int(r * 0.62))
            font = _font(fs)
            tw = th = 0
            try:
                l, t, rt, b = d.textbbox((0, 0), cap, font=font)
                tw, th = rt - l, b - t
            except Exception:
                tw, th = len(cap) * fs // 2, fs
            pad = max(8, fs // 3)
            bx0 = min(max(0, cx - tw // 2 - pad), max(0, w - tw - pad * 2))
            by0 = cy - r - th - pad * 3
            if by0 < 0:
                by0 = min(h - th - pad * 2, cy + r + pad)
            bx1, by1 = bx0 + tw + pad * 2, by0 + th + pad * 2
            d.rectangle([bx0, by0, bx1, by1], fill=(0, 0, 0))
            d.rectangle([bx0, by0, bx1, by1], outline=(230, 30, 45),
                        width=max(2, fs // 8))
            d.text((bx0 + pad, by0 + pad - max(2, fs // 8)), cap,
                   fill=(255, 255, 255), font=font)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return png


def thumb(raw: bytes, *, max_width: int = 360, quality: int = 66) -> str:
    """压成可内嵌的 JPEG base64。

    逐次点击动辄上百张，单张整屏 PNG 有 1~2MB —— 直接内嵌会让报告膨胀到
    几百 MB。360px 宽、q66 在页面上以 300px 显示，点击位置（红圈）与页面
    标题仍然清楚，而体积只有 ~20KB。
    """
    if not raw:
        return ""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(raw)).convert("RGB")
        w, h = img.size
        sc = min(1.0, float(max_width) / float(w or 1))
        if sc < 1.0:
            img = img.resize((int(w * sc), int(h * sc)), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=int(quality), optimize=True)
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        return ""


def predict(label: str = "", cls: str = "", *, uid: str = "") -> Dict[str, str]:
    """按入口文字/控件类型给出"点了应该发生什么"的预判。

    返回 {kind, kind_label, expect, risk}。**这是假设不是结论**：
    报告里写在"预判"栏，与"实际结果"并排，两者不一致才是有价值的信息。
    """
    lab = (label or "").strip()
    flat = lab.replace(" ", "").replace("\u3000", "")
    # 结构树里"没有文字"的节点，其 label 常常直接是类名（FrameLayout / ViewGroup）。
    # 那种"文字"不是文字，按无文字处理 —— 否则会给出"按文字语义进入功能页"
    # 这种明显不对的预判。
    _cs = (cls or "").split(".")[-1]
    if flat and (flat in _CONTAINER_NAMES or (bool(_cs) and flat.lower() == _cs.lower())):
        lab, flat = "", ""
    for kind, words, expect, risk in _RULES:
        for wd in words:
            if wd and wd in flat:
                return {"kind": kind, "kind_label": _KIND_LABELS.get(kind, kind),
                        "expect": expect, "risk": risk}
    # 文字认不出（"FrameLayout""ViewGroup"这类）时看控件类型。
    c = (cls or "").split(".")[-1]
    for cn, expect, risk in _CLS_RULES:
        if c and c.lower() == cn.lower():
            return {"kind": "widget", "kind_label": c, "expect": expect, "risk": risk}
    if not flat:
        return {"kind": "unknown", "kind_label": "无文字的容器",
                "expect": "预期：这是一个无文字的布局容器，点它多半是进入卡片对应的详情页",
                "risk": "低"}
    return {"kind": "text", "kind_label": "文字入口",
            "expect": "预期：按文字语义进入对应功能页", "risk": "低"}


# 这些"文字"其实是控件类名，不算入口文字。
_CONTAINER_NAMES = frozenset((
    "framelayout", "linearlayout", "relativelayout", "constraintlayout",
    "viewgroup", "view", "imageview", "textview", "button", "webview",
    "scrollview", "recyclerview", "listview", "gridlayout", "cardview",
))


def plain_label(label: str = "", cls: str = "") -> str:
    """把"文字其实是类名"的入口还原成空串。

    用于写报告文案：携船网首页那些入口的 label 就是 `FrameLayout`，
    直接写进"入口「FrameLayout」需要登录"里，读起来像在说界面结构，
    读者拿不到任何信息。这类一律写"无文字入口"更有用。
    """
    lab = (label or "").strip()
    flat = lab.replace(" ", "").replace("\u3000", "")
    cs = (cls or "").split(".")[-1]
    if flat and (flat.lower() in _CONTAINER_NAMES
                 or (bool(cs) and flat.lower() == cs.lower())):
        return ""
    return lab


_CJK = re.compile(r"[\u4e00-\u9fff]")
_ASCII_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]*$")


def unreadable(label: str = "") -> bool:
    """这个入口名是不是**资源 id / 类名**（而不是人看得懂的文字）。

    高途 2026-11-05：首屏那个「我已年满14周岁」确认按钮，节点上没有 text，
    只有 `resource-id=tvConfirm`，于是被记成"入口「tvConfirm」需要登录才能使用"，
    并从候选里剔除 —— 整轮只点了 1 次。
    判据：整串没有中文、且长成标识符的样子。中文 App 的真实按钮文字几乎总有中文，
    所以这条不会误伤"同意""登录"这类真文字。
    """
    lab = (label or "").strip().replace(" ", "")
    if not lab or _CJK.search(lab):
        return False
    if lab.lower() in _CONTAINER_NAMES:
        return True
    return bool(_ASCII_ID.match(lab)) and len(lab) >= 3

_KIND_LABELS = {    "policy": "政策/协议入口", "logout": "权利入口（注销/撤回/查阅）",
    "consent": "同意类按钮", "disagree": "拒绝类按钮", "login": "登录/注册入口",
    "perm": "系统权限弹窗按钮", "setting": "设置/说明入口", "close": "关闭/返回",
    "form": "列表/筛选控件", "widget": "控件", "unknown": "容器", "text": "文字入口",
}


def describe(src: str = "", reason: str = "", *, label: str = "",
             taps_before: int = 0, tags: Optional[List[str]] = None) -> str:
    """把"这一步是谁选的、凭什么"翻成报告里那句判读。

    `src` 的取值来自采集侧的 `ui_path[].src`（ai / sched / rule / ai_free）。
    必须区分来源：同样是"点了隐私政策"，规则命中与模型看图看出来的，
    在证据强度上不是一回事。
    """
    s = (src or "").strip()
    why = (reason or "").strip()
    if s == "ai" or s == "ai_free":
        head = "模型决策：" + (why or "（模型未给理由）")
    elif s == "landing":
        # 首启着陆阶段（P3.5）的动作：它不探索功能，只把应用带到主页面。
        # 报告里必须与功能遍历的点击分开，否则读者会以为这一击是在测功能。
        head = "首启着陆：" + (why or "首启过渡界面上的关闭/推进动作")
    elif s == "sched":
        head = "调度器：" + (why or "本屏按图谱价值排序选中该入口")
    elif s == "oracle":
        head = "外部接管：" + (why or "由外部决策通道指定")
    else:
        head = "规则兜底：" + (why or "本屏第一个未点过的可点元素")
    if taps_before > 0:
        head += "；本屏该元素此前已点过 %d 次" % int(taps_before)
    for t in (tags or []):
        if t and t not in head:
            head += "；%s" % t
    return head


def summarize(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """统计一批点击留痕：换到新界面的比例、各类预判的命中情况。

    "命中"指预判种类与实际结果对得上（政策入口→进新界面）。这个数字是
    遍历质量的直接指标：如果大量点击都"界面无变化"，说明候选生成有问题，
    而不是"这个 App 没什么可点的"。
    """
    n = len(items)
    out: Dict[str, Any] = {"total": n, "new": 0, "same": 0, "external": 0,
                           "unknown": 0, "by_kind": {}, "dead": []}
    for it in items or []:
        r = str(it.get("result") or "")
        if r in ("new", "same", "external"):
            out[r] += 1
        else:
            out["unknown"] += 1
        k = str(it.get("kind") or "unknown")
        b = out["by_kind"].setdefault(k, {"n": 0, "new": 0})
        b["n"] += 1
        if r == "new":
            b["new"] += 1
        if r == "same":
            out["dead"].append(it.get("label") or it.get("at") or "?")
    out["new_rate"] = round(100.0 * out["new"] / n, 1) if n else 0.0
    return out
