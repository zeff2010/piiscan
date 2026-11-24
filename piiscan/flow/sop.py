"""流程编排器：按 checkflow.yaml 的定义逐阶段执行检测。

设计上的一条硬规矩：**阶段之间只通过证据传递，不通过隐式状态传递**。
每个阶段把自己的产出写进 FlowResult.phases[i].evidence，
后面的阶段只从这里读。这样任何一个阶段单独重跑都不会影响别的阶段，
也方便把某个阶段的结果换成人工填的（比如政策正文人工粘贴）。

另一点：任何一个阶段失败都不中断整个流程。
检测报告最怕的不是"某项没测"，而是"因为某一步崩了导致后面全没测"——
前者可以补，后者连补什么都不知道。所以阶段失败只标记，不抛出。
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import attribution as ATTR
from . import checklist as CL
from . import compare as CMP
from . import declaration as DCL
from . import models as M
from . import permissions as PERM
from . import repro as REPRO
# 政策正文的归属核验（第三方 SDK 政策排除）用，避免把别人的政策当 App 的。
from .. import policy as _POL
from ..device_ids import IDENTITY_LABELS as _DIDS_LABELS
from .models import (FAIL, NOT_TESTED, PASS, SUSPECT, Evidence, FlowResult,
                     ItemState, PhaseResult, ReportRow)

Log = Callable[[str], None]
_NOP: Log = lambda *_a, **_k: None

# 政策文本类结论的边界说明。
# ★ 只靠政策文本能证的是"它声称这么做了"，证不了"它真的这么做了"。
#   凡结论只到文本为止的测评项，一律在报告里带上这句限定 ——
#   复核员不会把"政策里写了"读成"App 真的做了"，也不会据此免掉自己的核对。
_P6_SCOPE: Dict[str, str] = {
    "Q009": "本结论仅及于政策文本是否载有上述规则；该 App 是否实际处理不满十四周岁"
            "未成年人个人信息、注册流程中是否真的取得监护人同意，属功能与流程范畴，"
            "需人工在真实使用场景中核实",
}

# 功能存在性项的「入口关键词」。
#
# ★ 为什么需要这张表：这类项（注销 / 投诉举报 / 更正删除 / 个性化推荐关闭）此前
#   统一写"本轮遍历未走通该路径"。但"没走通完整流程"和"压根没碰到入口"是两件
#   完全不同的事 —— 实测里「问题与反馈」入口不仅打开过、还取到了第三方提交页
#   的证据，报告却写"未走通"，复核员照着去补测，等于白跑一趟。
#   所以措辞必须**从本轮存档里现查**，不能写死一个句子。
#
# 关键词只写"入口在界面上长什么样"，不写政策措辞 ——
# 政策正文里必然出现"注销/投诉/更正"等字眼，拿政策页去匹配会 100% 假阳性。
_FUNCTIONAL_ENTRY: Dict[str, Tuple[str, ...]] = {
    "Q013": ("注销",),
    "Q014": ("问题与反馈", "意见反馈", "投诉", "举报", "客服"),
    "Q015": ("更正", "修改资料", "个人资料", "删除"),
    # 只写"标签"：实测里「画像」二字命中了作品详情页的日文作者说明
    # （"クラシックメーカーでつくった画像と…"），那是正文不是入口。
    "Q016": ("标签",),
    "Q022": ("个性化", "推荐", "隐私设置", "权限管理"),
    "Q023": ("个性化", "推荐", "隐私设置", "权限管理"),
}

# AI 轨迹里表示"这个页面真的打开并看清了"的措辞。
# 只认这些显式确认词，不做模糊相似度匹配 ——
# **宁可漏判成"入口已见未打开"，也不能把"想点开"说成"已打开"**。
_OPENED_MARKS: Tuple[str, ...] = (
    "已确认", "已打开", "打开了", "已经打开", "进入该页", "已取证", "证据已到手",
)

# AI 轨迹里表示"逐屏找过了、这个入口确实没有"的措辞。
# 这是**第三种状态**：既不是"打开并取证"，也不是"没碰到"，
# 而是"认真找过、确认没有"。三者对人工的后续动作完全不同 ——
# 前者该看证据，中者该补测，后者基本可以直接收口。
_ABSENT_MARKS: Tuple[str, ...] = (
    "确不存在", "均无", "未找到", "没有找到", "不存在该", "均已看清",
)

# 「入口见到了，但差在哪一步」—— 每项各不相同，写清楚人工才知道补什么。
# 笼统一句"未走通完整流程"等于没说：补测的人不知道是要登录、还是要真的提交一次。
_FUNCTIONAL_TAIL: Dict[str, str] = {
    "Q013": "；但仅到入口为止，未实际执行账号注销操作",
    "Q014": "；但未实际提交投诉/举报内容，该渠道是否真正受理未经验证",
    "Q015": "；但仅到入口为止，未实际执行更正/删除操作",
    "Q016": "；但仅到入口为止，未实际执行特征标签删除操作",
    "Q022": "；因未找到开关，无法验证关闭选项是否真实可用",
}

# 这几项在本轮实测中明确受阻于登录态，把原因一起写上。
# 只列实测确有此事（界面显示「未登录」）时才拼，否则不写 —— 不推测。
_LOGIN_SENSITIVE: Tuple[str, ...] = ("Q013", "Q015")


# ---------------------------------------------------------------- 证据截图挂载
#
# 采集侧本来就存了界面截图（`ScanResult.screenshots`，含 base64 PNG），但此前
# 没有任何一处把它们挂到报告项上 —— 每个问题块都印着"本次自动化未采集到该项的
# 界面截图，需人工补充"。人工复核的核心诉求正是"看当时界面长什么样"，
# 这一栏空着等于把最直观的那份证据丢掉了。
#
# 挂载规则故意做得**机械可核**：每张截图产生在哪个阶段，是截图标签本身写明的
# （首启界面→P1、隐私政策页面/政策页滚动→P2、同意后界面→P3、UI 遍历第 N 步→P4），
# 而每个报告项也声明了它由哪些阶段参与判定（`ReportRow.phases`，来自
# checkitems.yaml）。两者一交，就是"支撑这一项的截图"。
# 不做关键词猜测式的关联 —— **挂错图比不挂更容易误导复核**。
_SHOT_PHASE_RULES: Tuple[Tuple[str, str], ...] = (
    ("首启界面", "P1"),
    ("启动后界面", "P1"),
    ("权限申请·P1", "P1"),
    ("隐私政策页面", "P2"),
    ("政策页滚动", "P2"),
    ("政策正文页", "P2"),
    ("政策页", "P2"),
    # 「点了入口但没跳走」这一屏：它恰恰是"入口点不开"的证据，
    # 必须进图集，否则报告里写"点击无响应"却拿不出一张图。
    ("政策入口点击后", "P2"),
    ("同意后界面", "P3"),
    ("权限申请·P4", "P4"),
    ("UI 遍历第", "P4"),
    ("采集结束界面", "P4"),
    # 外跳取证图（系统设置权限页 / 第三方授权页）都产生在遍历途中。
    # ★ 必须在这里登记：`shot_phase` 判不出阶段的图会被**整张丢掉**
    #   （`_attach_shots` 里 `if not ph: continue`），报告那一节就只剩文字。
    ("外跳", "P4"),
)


# 每个问题块内嵌几张截图。
# 用户要求"图就放在对应问题项的位置"——同一张图被多个项引用就重复内嵌，
# 不再集中到文末。为控制体积：普通项 3 张，权限项 4 张（弹窗常常不止一次，
# 每次弹的权限和文案都可能不同，少挂一张就可能漏掉"哪次没写用途"）。
ITEM_SHOTS_MAX = 3
ITEM_SHOTS_PERM = 4

# 「逐次点击留痕」内嵌多少条。
# 单条约 20KB（360px JPEG），200 条约 4MB —— 这是详细版报告能接受的量级：
# 再多就会让浏览器打开时卡顿，而超过 200 条之后的点击大多是同类重复
# （同一屏换着点卡片），信息量已经很低。被丢掉的条数会在报告里写明。
CLICK_SHOTS_MAX = 200

# 「这段正文够不够当政策全文」的下限。与采集侧 `collector.INLINE_POLICY_MIN`
# 保持同值（1200）—— 采集侧用它决定要不要继续滚动，这里用它解释
# "为什么内置文档取代了 UI 正文"。两处不同值会让报告里的理由与实际切换条件对不上。
POLICY_MIN_CHARS = 1200

# 与权限申请直接相关的报告项（Q010 超范围 / Q011 频率 / Q012 提前索权 /
# Q026 未同步告知目的）。这几项的截图必须是**权限弹窗本身**。
PERM_QIDS: Tuple[str, ...] = ("Q010", "Q011", "Q012", "Q026")

# 「同意之前」这个时段才成立的报告项。它们配的图必须也发生在同意之前：
# 结论写"在用户同意隐私政策之前，App 已收集…"，配图却是同意后的首页，
# 复核员会直接认定证据与结论对不上（Hi投屏 2026-10-26 那轮就是这样）。
PRE_CONSENT_QIDS: Tuple[str, ...] = ("Q002", "Q003")


def _is_post_consent_shot(item: Dict[str, Any]) -> bool:
    """这张图是否一定产生在用户同意之后（P3 同意环节 / P4 遍历）。"""
    if (item.get("phase") or "") in ("P3", "P4"):
        return True
    return "同意后" in str(item.get("label") or "")


_POLICY_SHOT_PREFIXES: Tuple[str, ...] = ("隐私政策页面", "政策页滚动", "政策页",
                                          "政策正文页")


def _shot_md5(b64: str) -> str:
    """截图字节的指纹。用来判"这两张图是不是同一张"，比看标签可靠。"""
    try:
        return hashlib.md5(_b64_to_bytes(b64 or "")).hexdigest()
    except Exception:
        return ""


def _desktop_labels(screens: Sequence[Any]) -> List[str]:
    """采集期哪些"界面"其实是系统桌面（按 activity 判）。

    为什么要在报告层再判一次（金考典 2026-10-26 用户意见）：
      那三轮的「首启界面 1/2/3」三张截图全是手机桌面 —— 冷启动还没等到
      App 到前台就先截了图。采集侧已改成等前台再截（`await_app_foreground`），
      但旧存档重渲染不会重新采集，只能在这里按 activity 把这批图剔掉：
      拿桌面当"首启界面"，等于给"App 首启时展示了什么"编证据。
    """
    out: List[str] = []
    for s in (screens or []):
        if not isinstance(s, dict):
            continue
        act = str(s.get("activity") or "").lower()
        if act and any(h in act for h in M._DESKTOP_ACTIVITIES):
            lab = str(s.get("label") or "").strip()
            if lab and lab not in out:
                out.append(lab)
    return out


def _fake_policy_shots(screenshots: Sequence[Any]) -> Tuple[List[str], str]:
    """找出「标着政策页、其实是首启弹窗」的截图。

    为什么必须查这一层（Hi投屏 2026-10-26 用户意见）：
      报告里三张图的标签分别是「首启界面 1」「隐私政策页面」「政策页滚动第 1 屏」，
      但三者字节完全相同 —— 当时那一次点击根本没跳转，采集器却按脚本往下
      "滚动阅读政策"继续截了图。报告于是拿着一张开屏弹窗当"政策页正文"的配图，
      复核员只会得出一个结论：政策页根本没打开，报告在编。
      标签是**采集脚本自己写的**，不能当证据；字节指纹才是。

    返回 (被剔除的标签列表, 给报告用的一句话说明)。
    """
    raw = [s for s in (screenshots or []) if isinstance(s, dict)]
    if not raw:
        return [], ""
    launch = set()
    for s in raw:
        lab = str(s.get("label") or "")
        if lab.startswith(("首启界面", "启动后界面")):
            h = _shot_md5(s.get("b64") or "")
            if h:
                launch.add(h)
    if not launch:
        return [], ""
    bad: List[str] = []
    hashes: List[str] = []
    for s in raw:
        lab = str(s.get("label") or "").strip()
        if not lab.startswith(_POLICY_SHOT_PREFIXES):
            continue
        h = _shot_md5(s.get("b64") or "")
        if h and h in launch:
            bad.append(lab)
            if h not in hashes:
                hashes.append(h)
    if not bad:
        return [], ""
    note = ("存档中 %d 张标注为「政策页」的截图与首启弹窗**逐字节相同**"
            "（md5 %s），说明点击入口后并未真正进入政策页，采集脚本在弹窗上"
            "继续截了图。这些图已从报告图集剔除，不作为政策页证据。"
            % (len(bad), "、".join(hashes)))
    return bad, note


def shot_phase(label: str) -> str:
    """由截图标签判断它产生在哪个阶段；判断不了就返回空串（宁可不挂）。

    权限弹窗的标签形如 `权限申请·P4·照片`，阶段直接写在标签里 —— 先按这个
    前缀解析，避免"只在 P1/P4 两个阶段枚举"把别处出现的权限弹窗整张丢掉
    （P3 同意环节、登录后首次拍照等都可能弹权限）。
    """
    lab = (label or "").strip()
    if lab.startswith("权限申请·"):
        m = re.match(r"^权限申请·(P\d)", lab)
        if m:
            return m.group(1)
    for kw, ph in _SHOT_PHASE_RULES:
        if lab.startswith(kw):
            return ph
    return ""


def _thumb(label: str, png_bytes: bytes) -> str:
    """把整屏截图（1080×2400 PNG，动辄 1~2MB）压成可内嵌的缩略图。

    为什么压到 320px：截图现在**逐项内嵌**（同一张图被多个报告项引用就重复
    出现几次），体积是首要约束。320px 宽在页面上以 200~230px 显示，
    复核员要看的"哪一页、标题写了什么、有什么入口"仍然清楚；
    而原图直接内嵌会让一份报告膨胀到几十 MB、浏览器打开就卡死。
    压缩失败就返回空串 —— 宁可少一张图，也不要把一份打不开的报告交出去。
    """
    try:
        from .. import ai as _ai_pkg  # noqa: F401
        from ..ai.vision import prepare
        return _b64_of(prepare(png_bytes, max_width=320, quality=70).jpeg)
    except Exception:
        pass
    try:
        import base64
        import io as _io

        from PIL import Image
        img = Image.open(_io.BytesIO(png_bytes)).convert("RGB")
        w, h = img.size
        scale = min(1.0, 320.0 / float(w or 1))
        if scale < 1.0:
            img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
        buf = _io.BytesIO()
        img.save(buf, format="JPEG", quality=70, optimize=True)
        return _b64_of(buf.getvalue())
    except Exception:
        return ""


def _b64_of(raw: bytes) -> str:
    import base64
    return base64.b64encode(raw).decode("ascii")


def _is_privacy_policy_text(text: str) -> bool:
    """粗略判断拿到手的正文是不是隐私政策（而不是用户协议 / 服务条款）。

    为什么必须判：「未列明第三方 SDK」这类结论只能对着**隐私政策或第三方
    共享清单**下。拿一份《用户协议》去搜 SDK 名称，必然一个都搜不到，
    于是报出"15 个 SDK 未列明"—— 这不是发现了问题，是拿错了文件。
    实测撞过一次：P2 点进去的入口文字是「用户协议」，全文 5381 字，
    里面一个 SDK 名称都没有，按字面判定就是全部未列明。
    """
    head = (text or "")[:500]
    if not head.strip():
        return False
    # 标题级判据：开头出现"用户协议/服务协议"且没有"隐私"字样
    if any(w in head for w in ("用户协议", "服务协议", "服务条款", "使用条款", "会员协议")) \
            and "隐私" not in head:
        return False
    return True


def _fix_link(u: str) -> str:
    """把模型从政策正文里抄出来的链接修成能点开的形状。

    真机实测（学丞政策）：30 条第三方 SDK 隐私政策链接里，有 9 条写成
    `https:/opendocs.alipay.com/...`（少一个斜杠），另有几条路径中间
    夹着软换行留下的空格（`.../mmsuppo rtacct...`）。这类链接留在清单里
    比不写还糟：复核员点不开，会以为是采集侧没抓到。

    只做两件确定性的事：补回 `//`、去掉 URL 内空白。判断不了的（没有协议头、
    看着就不像 URL）原样返回，由调用方按"非 http"过滤掉。
    """
    s = re.sub(r"\s+", "", (u or "").strip())
    m = re.match(r"^(https?):(/*)(.+)$", s, re.I)
    if not m:
        return s
    return "%s://%s" % (m.group(1).lower(), m.group(3))


def _b64_to_bytes(txt: str) -> bytes:
    """存档里的截图是 base64 字符串；解不开就返回空串（调用方会跳过这张图）。"""
    import base64
    try:
        return base64.b64decode(txt or "")
    except Exception:
        return b""



class FlowRunner:
    """一次完整检测的执行器。"""

    def __init__(self, cfg=None, log: Log = print, ai=None, ai_tasks=None):
        self.cfg = cfg
        self.log = log
        self.ai = ai                    # 底层 provider（compare 用）
        self.ai_tasks = ai_tasks        # 业务封装（视觉/遍历决策用）
        self.flow = CL.load_checkflow()
        self.items_idx = CL.items_index()
        self.fr = FlowResult()
        self.scan = None                # 采集结果（ScanResult）
        # 复现采集能力（由 run() 注入）：None = 不做复现，P7 会如实标"未执行"。
        self.repro_runner: Any = None
        self.policy_text = ""
        self.policy_url = ""
        self.sdk_texts: List[str] = []
        self.policy_docs: List[Dict[str, str]] = []
        # 采集期拿到的正文被判定"不是隐私政策"时，若它其实是另一类声明文档
        # （共享清单 / 用户协议 / 收集清单），正文留在这里、后面并入文档表。
        # ★ 用户 2026-10-28：「三方共享清单…这些都是有用的，要展示出来」。
        #   Hi投屏那轮唯一的 WebView 正文就是 `/protocol/share`，
        #   旧逻辑把它排除后正文直接丢掉，报告只剩一句"已排除"——
        #   复核员看不到清单内容，也没法核接收方。
        self._declined_docs: List[Dict[str, str]] = []
        # 政策正文的来源标注：UI 抓取 vs APK 内置文档。
        # 报告必须写清"这份正文是从哪来的"，复核员才能判断它是否等于用户看到的那一份。
        self.policy_builtin: Dict[str, Any] = {}
        self.ui_policy_chars = 0
        # 提交时直接给的政策正文/链接（平台表单、服务器部署的主要来源）
        self.user_policy_text = ""
        self.user_policy_url = ""
        self.policy_source = ""
        # P2 阶段模型深读政策的结果（分段抽取，见 ai/tasks.analyze_policy）。
        # P5 的差集要用它 —— 关键词法漏掉的声明写法，靠这一份补上。
        self.ai_policy: Dict[str, Any] = {}
        # P5 的第二支：按 SDK 的「声明 vs 实测」对照（flow/declaration.py）。
        self.sdk_matrix: Dict[str, Any] = {}
        # 「标着政策页、其实是首启弹窗」的截图（按字节指纹判，见 _fake_policy_shots）。
        # 采集器旧版本在入口没跳转时也会继续截"政策页"，这些图必须整批剔除。
        self.fake_policy_shots: List[str] = []
        self.policy_shot_note = ""
        # 本轮「有没有真的跑起来」（assess_run_health 的结果），截图与结论都要看它
        self._run_health: Dict[str, Any] = {}

    # ------------------------------------------------------------------ 工具
    def _builtin_policy(self) -> Tuple[str, str]:
        """取 APK 内置的政策正文，返回 (包内路径, 正文)。

        为什么需要：在线/UI 抓取并非总能成功。自设捏脸（uni-app）的政策入口是
        弹窗告知语里的内联链接，UI 上点了 5 处坐标都没反应，
        而政策全文（23064 字）就躺在安装包里 —— App 弹窗读的正是这份文件。
        跳过它就等于主动放弃已经到手的证据。
        """
        assets = (self.fr.static or {}).get("policy_assets") or []
        best: Tuple[str, str] = ("", "")
        for a in assets:
            if not isinstance(a, dict):
                continue
            # 弹窗配置（androidPrivacy.json 之类）不是政策正文，不能拿来比对条款
            if a.get("role") == "prompt_config":
                continue
            t = str(a.get("text") or "").strip()
            if len(t) < 300:
                continue
            # ★ 乱码不算政策正文（金考典 2026-10-27）：那份 assets/privacy.htm
            #   是 UTF-16LE，被当成 GBK 解出 20 万字的「< h t m l」，长度检查
            #   一路绿灯，报告最后写"已自安装包提取核查、政策文本确证"——
            #   等于宣称核对过一份没人能读的文件。两道闸：可读性 + 政策特征。
            if _POL._text_quality(t) < 0.98:
                self.log("[流程]    跳过内置文档 %s：解码结果不可读（疑似编码识别错误）"
                         % a.get("path"))
                continue
            if not _POL.looks_like_privacy_policy(t):
                self.log("[流程]    跳过内置文档 %s：正文不含隐私政策特征，"
                         "不作为政策全文" % a.get("path"))
                continue
            if len(t) > len(best[1]):
                best = (str(a.get("path") or ""), t)
        return best

    def _fetch_policy_from_url(self, url: str, pr: PhaseResult) -> str:
        """按提交时给的链接抓政策正文（服务器部署的主要来源）。

        为什么不让调用方自己抓：抓取要处理编码（GBK/UTF-8 混用）、
        Content-Type 缺失、重定向、正文提取（去导航/去脚本），这套逻辑
        已经在 `piiscan.policy.fetch` 里了，重复实现只会得到两份不一样的结果。
        抓失败不是异常：如实记进 notes，让 P2 走"未能取得正文"的正常分支。
        """
        try:
            from .. import policy as POLICY
            res = POLICY.fetch(url, log=self.log)
        except Exception as e:
            pr.notes.append("按提交的链接抓取政策失败：%s: %s" % (type(e).__name__, e))
            return ""
        if not getattr(res, "ok", False) or not (getattr(res, "text", "") or "").strip():
            pr.notes.append("按提交的链接抓取政策失败：%s"
                            % (getattr(res, "error", "") or "未取到正文"))
            return ""
        t = res.text.strip()
        pr.notes.append("政策正文按提交的链接抓取：%s（%d 字）"
                        % (getattr(res, "final_url", "") or url, len(t)))
        return t

    # URL 里出现这些词，基本可判定是隐私政策页；出现后一组的则多是协议/条款/版权页
    _URL_GOOD = ("privacy", "yinsi", "private", "policy")
    _URL_BAD = ("agreement", "protocol", "vip", "terms", "copyright", "user")

    @classmethod
    def _policy_url_score(cls, url: str) -> int:
        low = (url or "").lower()
        s = 0
        if any(k in low for k in cls._URL_GOOD):
            s += 2
        if any(k in low for k in cls._URL_BAD):
            s -= 3
        return s

    def _fetch_policy_from_apk_links(self, pr: PhaseResult) -> None:
        """界面入口打不开时，按 APK 里登记的政策链接直接抓正文。

        ★ 为什么需要（以观书法 5.4.2 真机，2026-10-20）：
          首启弹窗的《以观书法隐私政策》是带 ClickableSpan 的 TextView，
          这轮 5 个采样点都没能打开（上一轮打开过，属点击命中不稳定）。
          而 APK 里明明白白登记着 `https://app.ygsf.com/privacy.html`，
          网络可达 —— 正文就躺在那里，却因为"只在界面上找"而判成未取得。
          结果 22 项里有 20 项只能"跳过未测"，报告可用性大打折扣。

        两条纪律：
          · 只把**通过类型闸门**的正文当政策（`vipagreement.html` 2674 字
            曾被当成政策，见 `policy.looks_like_privacy_policy`）；
          · 抓到了也必须写明来源是"按 APK 链接抓取"，不能冒充"政策页打开"。
        """
        from .. import policy as POLICY
        cands: List[str] = []
        for u in ((self.fr.static or {}).get("policy_urls") or []):
            if isinstance(u, str) and u.startswith("http"):
                cands.append(u)
        cap = (getattr(self.scan, "policy_capture", None) or {}) if self.scan else {}
        for u in (cap.get("urls") or []):
            if not isinstance(u, dict):
                continue
            _u = str(u.get("url") or "")
            if _u.startswith("http") and (u.get("policyLikely")
                                          or self._policy_url_score(_u) > 0):
                cands.append(_u)
        # 去重并按"像不像政策页"排序，负分的（协议/条款/版权）直接不试
        _seen: List[str] = []
        for u in sorted(set(cands), key=self._policy_url_score, reverse=True):
            if self._policy_url_score(u) <= 0:
                continue
            if u not in _seen:
                _seen.append(u)
        for u in _seen:
            # ★ 域名就是 SDK 厂商的政策站 → 不抓、更不能用（免费投屏神器实测：
            #   APK 里第一顺位是 www.pangle.cn，抓回来的是《穿山甲广告SDK隐私政策》，
            #   比 App 自己的政策还长，一路当成了 App 的政策）。
            if POLICY.policy_host_reason(u):
                cap.setdefault("otherPolicyTexts", []).append({
                    "url": u, "chars": 0,
                    "why": POLICY.policy_host_reason(u) + "，未抓取",
                })
                continue
            try:
                res = POLICY.fetch(u, log=self.log)
            except Exception:
                continue
            t = (getattr(res, "text", "") or "").strip()
            if not getattr(res, "ok", False) or not t:
                continue
            if not _POL.looks_like_privacy_policy(t):
                cap.setdefault("otherPolicyTexts", []).append({
                    "url": u, "chars": len(t),
                    "why": "按 APK 内链接抓到的正文不是隐私政策，未采用",
                })
                continue
            _tp2 = POLICY.third_party_reason(t, self.fr.app_name or "",
                                             self.fr.package or "", url=u)
            if _tp2:
                cap.setdefault("otherPolicyTexts", []).append({
                    "url": u, "chars": len(t), "why": _tp2 + "，未采用",
                })
                continue
            self.policy_text = t
            self.policy_url = u
            self.policy_source = "按 APK 内政策链接抓取"
            pr.notes.append(
                "界面入口未能打开，改按 APK 内登记的政策链接抓取正文："
                "%s（%d 字）" % (u, len(t)))
            return
        pr.notes.append("界面入口未能打开，APK 内登记的政策链接也未能取到隐私政策正文")

    def _phase_spec(self, pid: str) -> Dict[str, Any]:
        for p in self.flow.get("phases") or []:
            if p.get("id") == pid:
                return p
        return {}

    def _begin(self, pid: str) -> PhaseResult:
        spec = self._phase_spec(pid)
        pr = PhaseResult(phase_id=pid, num=spec.get("num", ""), name=spec.get("name", pid))
        pr.started_at = time.time()
        self.fr.phases.append(pr)
        self.log("[流程] ── %s、%s（%s）" % (spec.get("num", ""), spec.get("name", pid), pid))
        return pr

    def _end(self, pr: PhaseResult, status: str, note: str = "") -> PhaseResult:
        pr.ended_at = time.time()
        pr.status = status
        if note:
            pr.notes.append(note)
        self._fill_real_timing(pr)
        _d = ("真实耗时 %.1fs" % pr.real_seconds) if pr.real_ms > 0 else \
             ("分析耗时 %.1fs" % pr.duration)
        self.log("[流程]    %s 结束：%s（%s）%s"
                 % (pr.phase_id, M.PHASE_LABELS.get(status, status), _d,
                    ("｜" + note) if note else ""))
        return pr

    # 各阶段在采集侧的锚点区间：(起点锚点, 终点锚点, 起点兜底, 终点兜底)
    # 锚点由 collector.mark() 在真机采集时打下，见 collector.ScanResult.marks。
    _REAL_SPANS = {
        "P1": ("app_launched", "consent", "scan_start", "scan_end"),
        "P2": ("policy_tap", "policy_text", "observe_start", "consent"),
        "P4": ("consent", "scan_end", "walk_start", "scan_end"),
    }

    def _fill_real_timing(self, pr: PhaseResult) -> None:
        """把采集侧的真实耗时填进阶段结果。

        编排器的墙钟（duration）只覆盖"读存档 + 算判定"，P1/P2/P4 的真实耗时
        发生在采集阶段、在编排之前，不回填就会显示成 0.2 秒 —— 那不是真的快，
        是根本没记。没有锚点可依时保持 -1（报告写"不适用"），绝不猜一个数。
        """
        scan = self.scan
        if scan is None:
            return
        marks = getattr(scan, "marks", None) or {}
        if not marks:
            # 旧存档没有 marks 字段：能推多少推多少，推不出就不写
            marks = self._legacy_marks()

        if pr.phase_id == "P3":
            # 同意是一个瞬时边界，不占时长，但要说清它发生在冷启动后第几秒
            c = marks.get("consent")
            if c is not None:
                pr.real_ms = 0
                pr.timing = "边界点：同意发生在冷启动后 %.1fs，不单独占用时长" % (c / 1000.0)
            elif getattr(scan, "consent_given", False):
                # 认到了同意动作，但没能定出它发生在第几秒 —— 这两件事必须分开说。
                # 合成一句"未捕获到同意事件"会让报告自相矛盾：
                # P3 明明写了"已同意"，同一页的耗时表却说"没捕获到"。
                pr.timing = ("已捕获同意动作，但未记录到同意时刻"
                             "（分水岭有效、时序数值不可用）")
            else:
                pr.timing = ("本档位不执行同意动作（仅同意前），无同意时刻"
                             if self._consent_absent()
                             else "未捕获到同意事件，无法定位同意时刻")
            return

        # ---- P2 特殊：政策采集与首启观测在时间上本来就重叠 ----
        # 真机实测（flow_live3）：policy_text 打在 64.6s、policy_tap 打在 67.7s ——
        # 正文比"点击入口"还早 3 秒。原因是 App 在弹窗出现时就把政策 WebView
        # 预加载好了，点不点入口都能读到正文。硬套"点击→取得"的区间会算出负数，
        # 与其编一个数，不如如实说明这段与 P1 重叠、政策在第几秒取得。
        if pr.phase_id == "P2":
            pt = marks.get("policy_text")
            tap = marks.get("policy_tap")
            if pt is None:
                pr.real_ms = -1
                pr.timing = "本次未记录到取得政策正文的时刻，真实耗时未记录"
            else:
                pr.real_ms = -1
                extra = ""
                if tap is not None and pt < tap:
                    extra = ("；正文比点击入口（%.1fs）还早 %.1fs 取得，"
                             "说明 App 在弹窗阶段已预加载政策页面，"
                             "该阶段与 P1 首启观测在时间上重叠，不单独计时"
                             % (tap / 1000.0, (tap - pt) / 1000.0))
                elif tap is not None:
                    extra = "；点击入口于 %.1fs" % (tap / 1000.0)
                pr.timing = ("政策正文于冷启动后 %.1fs 取得%s"
                             % (pt / 1000.0, extra))
            return

        span = self._REAL_SPANS.get(pr.phase_id)
        if not span:
            # P0/P5/P6 是纯分析阶段，墙钟就是真实耗时
            pr.real_ms = int(pr.duration * 1000)
            if pr.phase_id == "P0" and getattr(self, "_static_reused", False):
                pr.real_ms = -1
                pr.timing = "本次静态档案由外部存档提供，未重新执行静态分析，耗时未记录"
            else:
                pr.timing = "本阶段为离线分析，耗时即实际计算时间"
            return

        s1, e1, s2, e2 = span
        a = marks.get(s1, marks.get(s2))
        b = marks.get(e1, marks.get(e2))
        if a is None or b is None or b < a:
            pr.real_ms = -1
            pr.timing = "缺少可用锚点（%s→%s），真实耗时未记录" % (s1, e1)
            return
        pr.real_ms = int(b - a)
        pr.timing = "冷启动后 %.1fs → %.1fs（锚点 %s → %s）" % (
            a / 1000.0, b / 1000.0, s1 if s1 in marks else s2,
            e1 if e1 in marks else e2)
        # 这段里有多少是在等模型回答 —— 设备只是在原地等，不是"操作"
        #
        # ★ 必须分阶段切（2026-11-10 CNC宝典）：`ai_wait_seconds` 是**整轮**累计，
        #   P1 只覆盖"冷启动 → 同意"，P4 只覆盖"同意 → 采集结束"。拿整轮的数
        #   往 P1 上贴，同一份样本会写出"P1 等待模型 118s"——而日志里 P1 只等了
        #   4 秒，那 118 秒有 115 秒发生在遍历阶段。这种数字读起来很具体，
        #   实际是把另一个阶段的时间记到这一阶段头上，属于口径错误。
        wait_total = float(getattr(scan, "ai_wait_seconds", 0) or 0)
        wait_pre = float(getattr(scan, "ai_wait_pre_walk", 0) or 0)
        if pr.phase_id == "P1":
            wait = wait_pre          # 旧存档没有这个字段 → 0，宁可不写也不猜
        elif pr.phase_id == "P4":
            wait = wait_total - wait_pre if wait_pre > 0 else wait_total
        else:
            wait = 0.0
        if wait > 1:
            pr.timing += "；其中等待模型判断累计 %.0fs（设备静止未操作）" % wait

    def _legacy_marks(self) -> Dict[str, int]:
        """旧存档没有 marks 时，用能拿到的字段尽量还原锚点。"""
        scan = self.scan
        out: Dict[str, int] = {}
        if scan is None:
            return out
        c = getattr(scan, "consent_elapsed_ms", None)
        if c:
            out["consent"] = int(c)
        try:
            total = int((float(getattr(scan, "ended_at", 0) or 0)
                         - float(getattr(scan, "started_at", 0) or 0)) * 1000)
            if total > 0:
                out["scan_start"] = 0
                out["scan_end"] = total
        except Exception:
            pass
        return out

    def _item(self, qid: str) -> ItemState:
        """取（或造）一个测评项状态。"""
        st = self.fr.items.get(qid)
        if st is None:
            st = CL.new_item(qid, self.items_idx)
            self.fr.items[qid] = st
        return st

    def _collect_incomplete(self) -> str:
        """本轮采集是否明显不完整（注入脚本脱钩）。返回原因；完整则返回空串。

        ★ 判据来源（2026-11-10 CNC宝典 真机两轮对照，同一包/同机/同版本）：
            第一轮 102 条事件，界面 66 个（其中 53 个来自 hook 事件）
                    → Q002/Q003 认定「同意前已取 Android ID」；
            第二轮 4 条事件，界面 17 个（其中只有 3 个来自 hook 事件）
                    → 只能全部记 not_tested。
          差别不在应用：第二轮的政策入口被**系统浏览器**接管，应用切到后台，
          Frida 脚本静默脱钩。`ui_activity` 本来是每换一次 Activity 一条，
          界面数与 hook 界面数严重失配就是脱钩的硬证据。

        ★ 为什么必须在结论层拦：事件少不等于没收集。用"没收到事件"去支撑
          「未观测到收集行为」，是拿失灵仪器替应用背书 —— 反向假话。
        """
        sc = [s for s in (getattr(self.scan, "screens", None) or [])
              if isinstance(s, dict)]
        if len(sc) < 8:
            return ""
        hook_n = sum(1 for s in sc if s.get("source") == "hook")
        if hook_n >= max(2, len(sc) * 0.2):
            return ""
        ev_n = len(getattr(self.scan, "events", None) or [])
        return ("本轮共记录 %d 个界面，其中只有 %d 个来自 hook 事件（正常应占多数，"
                "界面每切换一次就该有一条），全程事件总数仅 %d 条 —— 注入脚本在"
                "采集过程中已脱钩（常见原因：政策页被系统浏览器接管、应用退到后台"
                "后被系统冻结）。此种轮次既不能认定「同意前发生过收集」，也不能认定"
                "「未观测到收集」，需在注入可全程存活的环境下重跑"
                % (len(sc), hook_n, ev_n))

    def _set(self, qid: str, state: str, desc: str = "", reason: str = "",
             level: str = "中", confidence: str = "", phase: str = "",
             evidence: Optional[Sequence[Evidence]] = None,
             facts: Optional[Sequence[Sequence[str]]] = None,
             stacks: Optional[Sequence[Sequence[str]]] = None,
             links: Optional[Sequence[str]] = None) -> ItemState:
        st = self._item(qid)
        st.state = state
        st.desc = desc or st.desc
        if reason:
            st.reason = reason
        elif state != NOT_TESTED and st.reason == CL.PLACEHOLDER_REASON:
            # ★ 状态已经不是「未测」了，那句「本次流程未取得判定所需的证据」
            #   就变成了反话 —— 存档里会出现「发现问题 / 未取得判定所需的证据」
            #   这种自相矛盾的组合（学丞 cn.ixuecheng 实测撞到：Q002、Q003
            #   结论与证据链都齐，唯独 reason 还留着 new_item 的占位数）。
            #   报告正文走的是 desc，所以纸面上看不出问题；但只要有人（或下游
            #   AI）去读 flow.json 的 reason，就会以为这条结论是没证据硬判的。
            st.reason = ""
        st.level = level or st.level
        st.confidence = confidence or st.confidence
        st.source_phase = phase or st.source_phase
        if evidence:
            st.evidence.extend(evidence)
        if facts:
            st.facts.extend([list(x) for x in facts])
        if stacks:
            st.stacks.extend([list(x) for x in stacks])
            # 挂栈就顺手归因（谁发起的：App / SDK / 框架）。放在这里而不是
            # 每个调用点手写，是因为"漏算归因"的后果是报告里那条问题
            # 无法回答"App 还是 SDK"—— 而这是复核时的必答题。
            try:
                st.attribution = ATTR.summarize(st.stacks, self.fr.package or "")
            except Exception:
                pass        # 归因失败不影响判定本身
        if links:
            for u in links:
                if u and u not in st.links:
                    st.links.append(u)
        return st

    # ================================================================== 主入口
    def run(self, *, package: str = "", apk: str = "",
            scan_result: Any = None, static_result: Any = None,
            mode: str = "expert", do_repro: bool = False,
            app_name: str = "", version: str = "",
            policy_text: str = "", policy_url: str = "",
            repro_runner: Any = None) -> FlowResult:
        # 复现采集能力由调用方注入；没有就跳过 P7 并如实标注（不假装跑过）。
        self.repro_runner = repro_runner
        self.user_policy_text = (policy_text or "").strip()
        self.user_policy_url = (policy_url or "").strip()
        self.fr.package = package
        self.fr.apk_path = apk or ""
        self.fr.app_name = app_name
        self.fr.version = version
        self.fr.mode = mode
        self.fr.started_at = time.time()
        if scan_result is not None:
            self.scan = scan_result
            # 测试机真实标识：设备标识符取值的比对基准。带进 flow.json，
            # 离线重渲染时也能据此复核"这个值到底是不是 IMEI"。
            self.fr.device_identities = dict(
                getattr(scan_result, "device_identities", None) or {})
            # 本轮档位 / 预算 / 实际耗时：报告"界面覆盖情况"里要写明。
            # 三项分开存：预算（配置给的）与实际耗时（真跑了多久）经常不等 ——
            # 提前终止、AI 等待补偿都会让两者差出几十分钟，
            # 合成一个数就分不清"没给足时间"和"给了没跑满"。
            self.fr.depth = str(getattr(scan_result, "depth", "") or "")
            self.fr.budget_seconds = int(
                getattr(scan_result, "budget_seconds", 0) or 0)
            try:
                _s0 = float(getattr(scan_result, "started_at", 0) or 0)
                _s1 = float(getattr(scan_result, "ended_at", 0) or 0)
                self.fr.scan_elapsed = int(_s1 - _s0) if _s1 > _s0 > 0 else 0
            except Exception:
                self.fr.scan_elapsed = 0
            # 旁路取证：注入被壳拦死时的系统侧证据（appops / 运行时权限）。
            self.fr.bypass = dict(getattr(scan_result, "bypass", None) or {})
            # 「目标应用没能启动」不是某一项的问题，而是整轮检测的前提是否成立，
            # 必须一路带到报告头与每个未测项，否则报告只剩一句"跳过未测"。
            self.fr.app_crash = dict(getattr(scan_result, "app_crash", None) or {})
            self.fr.relaunch_count = int(getattr(scan_result, "relaunch_count", 0) or 0)
            # ★ 「反复重启」与「压根没启动」是两件事。判后者还要看本轮到底有没有
            #   跑起来的痕迹：真机实测（以观书法 mbsf6）遍历中退出 4 次被重启，
            #   同时完成了 45 次点击、102 个界面 —— 只看 relaunch_count 会把它
            #   误判成"未能启动"，报告头就会写"未取得任何运行期数据"。
            _rh = M.assess_run_health(
                getattr(scan_result, "screens", None) or [],
                package or getattr(scan_result, "package", "") or "",
                foreground_seen=bool(getattr(scan_result, "app_foreground_seen", False)),
                hook_hostile=int(getattr(scan_result, "hook_hostile", 0) or 0),
                # 注入不可用时"不注入启动"的观察结果：它决定证据缺失能不能
                # 算在检测手段头上（小盒课堂实测：应用自己就起不来）。
                app_start_probe=dict(getattr(scan_result, "app_start_probe", None) or {}),
                hook_spawn_killed=int(getattr(scan_result, "hook_spawn_killed", 0) or 0))
            self.fr.runtime_data = {
                "ui_steps": len(getattr(scan_result, "ui_steps", None) or []),
                "screens": len(getattr(scan_result, "screens", None) or []),
                "events": len(getattr(scan_result, "events", None) or []),
                # 「屏幕上到底有没有被测应用的界面」——判"跑起来了没有"用它，
                # 不用点击次数（有朋公社点击 4 次、事件 45 条，界面却全是空的）。
                "run_health": _rh,
            }
            # 调用栈要能配回"那次调用的参数与取值"（用户 2026-10-28 意见）。
            # 事件流是唯一同时握着 stacks 与 args/result 的地方，先留一份引用，
            # 最后由 `_attach_stack_meta()` 一次性贴到各测评项的栈上。
            self._events = list(getattr(scan_result, "events", None) or [])
            self._run_health = dict(_rh)
            # 注入被加固拦截时，即便界面采集成功也要说清楚（否则复核员会以为
            # "事件少"等于"应用真的只做了这些"）。
            if _rh.get("hook_blocked"):
                _probe_rh = _rh.get("app_start_probe") or {}
                if _rh.get("state") == "no_app" and _probe_rh.get("started") is False:
                    # ★ 不许把"应用自己起不来"说成"检测手段受限"（小盒课堂 2026-10-27：
                    #   旧报告写的是后者，实测它 60 ms 就死）。
                    self.fr.notes.append(
                        "本轮注入不可用，而且**不注入直接启动时应用也无法稳定存活**"
                        "（%s）。因此本报告的证据缺失不能归因于检测手段，"
                        "而是该应用在本次检测设备上未能正常运行；"
                        "启动失败现场见「目标应用启动状态」章节。"
                        % (_probe_rh.get("why") or "进程未能稳定存活"))
                elif int(_rh.get("hook_hostile") or 0):
                    self.fr.notes.append(
                        "本轮 hook 注入被应用自带的加固机制拦截：重新附着/冷启动注入"
                        "后有 %d 次进程立即退出。已改为不注入、只做界面采集，因此行为"
                        "事件（尤其接口级证据）明显少于正常轮次；涉及「是否收集某类信息」"
                        "的判断以界面与静态分析为准，不等同于应用的真实行为全集。"
                        % int(_rh.get("hook_hostile") or 0))
            # 登录辅助的结果要一路带到报告：「这次结论是在登录态还是游客态下得出的」
            # 是复核员判断结论适用范围的前提。离线重渲染（--from-result）走同一份
            # 存档，因此这里读一次就够，不需要各阶段重复。
            self.fr.login = dict(getattr(scan_result, "login", None) or {})
            # ★ 同意动作要整段带上（不只一个布尔位）。它是整份报告的时间分水岭，
            #   复核员必须能自己验"凭什么认定用户在这儿同意了"，而不是信一个开关。
            self.fr.consent = {
                "given": bool(getattr(scan_result, "consent_given", False)),
                "source": getattr(scan_result, "consent_source", "") or "",
                "strength": getattr(scan_result, "consent_strength", "") or "",
                "elapsed_ms": getattr(scan_result, "consent_elapsed_ms", None),
                "events": list(getattr(scan_result, "consent_events", None) or []),
                # 事件流里的分水岭标记数（正常为 1；为 0 说明登记链断了一半）
                "markers": sum(1 for e in (getattr(scan_result, "events", None) or [])
                               if getattr(e, "signal", "") == "CONSENT"),
            }
            # 界面覆盖情况：报告要能回答"这个结论覆盖了哪些界面、还有哪些没走到"。
            # 离线重渲染（--from-result）也读同一份存档，口径不会变。
            self.fr.coverage = dict(getattr(scan_result, "coverage", None) or {})
            # 外跳去向：跳到系统设置/浏览器/别的 App 时去了哪、算不算证据。
            # ★ 要一路带到报告：「权限管理」入口是自建开关还是只能跳系统设置、
            #   有没有第三方授权登录 —— 这两条事实只有这里记着。
            self.fr.external_jumps = [dict(x) for x in
                                      (getattr(scan_result, "external_jumps", None) or [])
                                      if isinstance(x, dict)]
            # 知识图谱：与 coverage 同源不同口径（一个是"走到哪"，
            # 一个是"界面之间怎么连、还剩什么、到权利入口几步"）。
            self.fr.kgraph = dict(getattr(scan_result, "kgraph", None) or {})
            self.fr.ai_guided = int(getattr(scan_result, "ai_guided", 0) or 0)
            self.fr.ai_free = int(getattr(scan_result, "ai_free", 0) or 0)
            # AI 参与的**原始事实**先整段搬过来（开关、可用的视觉模型、调用统计、
            # 采集侧自己记的说明）。P2 政策深读的状态在这里还没有，稍后补进去。
            self.fr.ai_used = {
                "enabled": bool(getattr(scan_result, "ai_enabled", False)),
                "vision": bool(getattr(scan_result, "ai_vision", False)),
                "stats": dict(getattr(scan_result, "ai_stats", None) or {}),
                "wait_seconds": float(getattr(scan_result, "ai_wait_seconds", 0)
                                      or 0),
                "errors": [str(x) for x in (getattr(scan_result, "ai_errors", None)
                                            or [])][:6],
                "notes": [str(x) for x in (getattr(scan_result, "ai_notes", None)
                                           or [])][:6],
            }
            self._heal_consent()
            self.fr.scan_errors = [str(x) for x in (getattr(scan_result, "errors", None) or [])]
            # ★ 先把"假政策页截图"揪出来：报告里挂着三张一模一样的图、
            #   两张标着"政策页"，是用户一眼就看出来的硬伤。这一步只依赖
            #   存档里的字节，所以旧存档重渲染也能纠正（2026-10-27）。
            self.fake_policy_shots, self.policy_shot_note = _fake_policy_shots(
                getattr(scan_result, "screenshots", None) or [])
            if self.policy_shot_note:
                self.fr.notes.append(self.policy_shot_note)

        self.p0_static(apk, static_result)
        self.p1_pre_consent()
        self.p2_policy()
        self.p3_consent()
        self.p4_post_consent()
        self.p5_compare()
        if do_repro:
            self.p7_repro()
        self.p6_checklist()

        self.fr.ended_at = time.time()
        self._note_ai_usage()
        self._build_repro()
        self._attach_stack_meta()
        CL.finalize(self.fr, self.flow)
        self._attach_shots()
        self._attach_click_shots()
        self._attach_landing()
        st = self.fr.stats()
        self.log("[流程] 完成：共 %d 项报告项 → 发现问题 %d / 疑似 %d / 未发现问题 %d / 跳过未测 %d"
                 % (st["total"], st["fail"], st["suspect"], st["pass"], st["not_tested"]))
        return self.fr

    def _attach_stack_meta(self) -> None:
        """给每条调用栈配上「那次调用的接口参数 / 取到的值 / 时刻」。

        ★ 为什么必须补（用户 2026-10-28 意见，金考典）：
          报告写「App 已收集设备标识符 2 次（Android ID，取值 04080c7d80e2b2c5）」，
          而下面的调用栈只有一行 `android.provider.Settings$Secure.getString`——
          复核员看不出这条栈读的是 **android_id** 还是别的东西，
          更看不出取到的值就是结论里那个。栈回答"谁读的"，
          参数回答"读了什么、读到什么"，缺一半就得回头翻原始 JSON。

        数据来源：事件流是全流程唯一同时握着 stack 与 args/result 的地方。
        同一段栈可能被多次命中（同一接口轮询），取**最早**那次：
        与「同意前第几秒」的口径一致，也最接近"第一次收集"这一认定基础。
        """
        evs = getattr(self, "_events", None) or []
        if not evs:
            return
        index: Dict[tuple, Dict[str, Any]] = {}
        for e in evs:
            st = tuple(getattr(e, "stack", None) or ())
            if not st:
                continue
            meta = {
                "api": getattr(e, "api", "") or "",
                "args": getattr(e, "args", "") or "",
                "result": getattr(e, "result", "") or "",
                "before": bool(getattr(e, "before_consent", False)),
                "elapsed_ms": getattr(e, "elapsed_ms", None),
                "thread": getattr(e, "thread", "") or "",
            }
            prev = index.get(st)
            if prev is None or (meta.get("elapsed_ms") or 0) < (prev.get("elapsed_ms") or 0):
                index[st] = meta
        for st_item in (self.fr.items or {}).values():
            st_item.stack_meta = [index.get(tuple(st)) or {}
                                  for st in (st_item.stacks or [])]

    def _note_ai_usage(self) -> None:
        """把「本轮 AI 到底参与了哪些环节」整成一段可复核的事实，交给报告。

        ★ 为什么要单独立这一段
          报告里的 22 项结论在纸面上长得一样，但来源不同：有的来自关键词与
          结构树（确定性规则），有的是模型读完政策正文后补上的（"为保障账号
          安全，我们可能获取您设备的唯一硬件编号"这类写法关键词配不上）。
          复核员追问"这条凭什么这么说"，只给结论就是黑盒。

        ★ 三种状态必须分开写
          完成 / 没跑 / 跑了但失败。一句"AI 已参与"会把后两种盖住 ——
          "没跑"说明这次结论只来自关键词，适用性要打折；"失败"说明有一份
          模型输出没拿到，同样的结论可信度更低。
        """
        ai = getattr(self.cfg, "ai", None) if self.cfg is not None else None

        def _flag(name: str) -> bool:
            try:
                return bool(ai.feature(name)) if ai is not None else False
            except Exception:
                return False

        au = dict(self.fr.ai_used) if isinstance(self.fr.ai_used, dict) else {}
        # 缺存档（纯离线构造的 FlowResult）时也不编运行期数字，只写开关。
        au.setdefault("enabled", False)
        au.setdefault("vision", False)
        au.setdefault("stats", {})
        au["flags"] = {
            "policy_vision": _flag("policy_vision"),
            "policy_analyze": _flag("policy_analyze"),
            "ui_agent": _flag("ui_agent"),
        }

        pol = dict(self.ai_policy or {})
        if pol:
            au["policy_deep"] = {
                "status": "完成",
                "declared_types": len(pol.get("declared_types") or []),
                "coverage": round(float(pol.get("_coverage", 1.0) or 1.0), 3),
                "chunks_total": int(pol.get("_chunks_total") or 1),
                "chunks_failed": int(pol.get("_chunks_failed") or 0),
            }
        else:
            # 没产出结果：把 P2 自己记的原因原样带出来（"未成功：xxx"/"异常"），
            # 没有原因就按"没开开关 / 无通道"分开说，不留空泛的"未执行"。
            detail = ""
            for ph in (self.fr.phases or []):
                if getattr(ph, "phase_id", "") != "P2":
                    continue
                for n in (ph.notes or []):
                    if "深读" in str(n):
                        detail = str(n)
            if detail:
                au["policy_deep"] = {"status": "未完成", "detail": detail}
            else:
                au["policy_deep"] = {
                    "status": "未执行",
                    "detail": ("未开启「政策深读」" if not _flag("policy_analyze")
                               else "已开启，但没有可深读的政策正文或模型通道未就绪"),
                }
        self.fr.ai_used = au

    def _heal_consent(self) -> None:
        """「同意时刻」被污染时先自愈，再进各阶段判定。

        采集侧（collector）已经修过一次；离线重渲染（--from-result）不经过
        采集侧，所以这里必须再做一遍 —— 同一份存档两条路都要能得出同样结论。
        """
        sc = self.scan
        if sc is None or not getattr(sc, "consent_given", False):
            return
        fixed, note = CMP.heal_consent_ms(
            getattr(sc, "events", None) or [], getattr(sc, "consent_elapsed_ms", None))
        if not note:
            return
        try:
            sc.consent_elapsed_ms = fixed
        except Exception:
            return
        errs = list(getattr(sc, "errors", None) or [])
        if note not in errs:
            errs.append(note)
            try:
                sc.errors = errs
            except Exception:
                pass
        self.log("[流程] 同意时刻自愈：%s" % note)

    # ================================================================== 复现步骤
    def _attach_shots(self) -> None:
        """把采集到的界面截图按阶段挂到报告项上，并整份只留一份缩略图。

        数据形态：
          · `fr.shots` —— 图集，每条 `{index, label, phase, b64}`，整份报告一份；
          · `row.shots` —— 只放 `{index, label, phase, kind}`（**不带 b64**），
            渲染时按 index 回查 b64 直接内嵌到问题项里。

        为什么 row 不带 b64：同一张图会被多个报告项引用（首启界面既支撑
        "未公开规则"也支撑"未经同意收集"），若每项都存一份 base64，
        JSON 存档会从几百 KB 涨到几 MB。**引用编号 + 渲染时回查**既能满足
        "图就放在问题项下面"，又不让存档膨胀。

        ★ 权限项（Q010/Q011/Q012/Q026）单独走一条规则：优先挂**权限弹窗本身**
          的截图，而不是"该项所处阶段的任意一屏"。原因很直接 —— 复核员要看的
          是弹窗上写了什么、弹的是哪个权限；给他一张同阶段的首页截图等于没给。
          若本轮确实没抓到权限弹窗截图（旧存档 / 截图失败），退回阶段图但把
          kind 标成 `phase`，报告里会明说"这不是权限弹窗截图"。
        """
        raw = list(getattr(self.scan, "screenshots", None) or []) if self.scan else []
        # ★ App 根本没到前台（no_app）时，采到的"界面"全是系统桌面。
        #   把这些图当"首启界面"挂进报告，等于拿桌面给 App 的行为作证
        #   （国象联盟 / 火花思维课堂 2026-10-26 就是这样，用户一眼看出"截图全是桌面"）。
        #   新采集侧已经不再截这种图（observe_screen(require_app=True)），
        #   旧存档在这里整批剔除，并在「证据取舍说明」里写清。
        if raw and (getattr(self, "_run_health", {}) or {}).get("state") == "no_app":
            self.fr.notes.append(
                "本轮采集到的 %d 张界面截图全部是系统桌面（被测应用从未切到前台），"
                "已整批剔除，不作为任何检测项的配图。" % len(raw))
            self.fr.shots = []
            return
        if not raw:
            return
        gal: List[Dict[str, Any]] = []
        by_phase: Dict[str, List[Dict[str, Any]]] = {}
        perm_shots: List[Dict[str, Any]] = []
        # 外跳取证图单独一池：它们是「外跳去向」章节的配图，
        # ★ 不能混进 by_phase —— 否则会被"P4 阶段"的普通检测项顺手挂走，
        #   报告里就出现"某问题项的附图是一张系统设置页"这种对不上的证据。
        jump_shots: List[Dict[str, Any]] = []
        _launch_md5 = {_shot_md5(x.get("b64") or "") for x in raw
                       if isinstance(x, dict)
                       and str(x.get("label") or "").startswith(("首启界面", "启动后界面"))}
        _launch_md5.discard("")
        # 采集期标成"首启界面"、实际是系统桌面的那几张：不进图集。
        _desk = set(_desktop_labels(getattr(self.scan, "screens", None) or []))
        _desk_hit: List[str] = []
        for sh in raw:
            if not isinstance(sh, dict):
                continue
            label = str(sh.get("label") or "").strip()
            b64 = sh.get("b64") or ""
            if not label or not b64:
                continue
            # 与首启弹窗逐字节相同的"政策页"截图不进图集：它不是政策页，
            # 挂上去等于拿开屏弹窗给"政策正文"作证（Hi投屏 2026-10-26）。
            # ★ 更进一步：只要这一轮**已经证明没进政策页**（`policy_shot_note`），
            #   所有标着"政策页/隐私政策页面/政策正文页"的图都不算数 ——
            #   有一张 md5 不同，也是弹窗换个时刻/被裁过的样子，不是政策页。
            if label.startswith(_POLICY_SHOT_PREFIXES) and (
                    self.policy_shot_note or _shot_md5(b64) in _launch_md5):
                continue
            if label in _desk:
                if label not in _desk_hit:
                    _desk_hit.append(label)
                continue
            ph = shot_phase(label)
            if not ph:
                continue      # 归不到阶段的图不进报告项，但仍留在采集存档里可审计
            item = {"index": len(gal) + 1, "label": label, "phase": ph,
                    "b64": _thumb(label, _b64_to_bytes(b64))}
            if not item["b64"]:
                continue      # 压缩失败就不挂，避免出一张打不开的图
            gal.append(item)
            if label.startswith("权限申请"):
                perm_shots.append(item)
            elif label.startswith("外跳"):
                jump_shots.append(item)
            else:
                by_phase.setdefault(ph, []).append(item)
        if _desk_hit:
            self.fr.notes.append(
                "%d 张标注为「%s」的截图实际是系统桌面（采集时应用还没切到前台），"
                "已剔除，不作为 App 首启界面的证据。"
                % (len(_desk_hit), "」「".join(_desk_hit)))
        if not gal:
            return
        self.fr.shots = gal

        perm_qids = set(PERM_QIDS)
        for row in self.fr.rows:
            qids = {str(s.get("qid") or "") for s in (row.sub or [])}
            is_perm = bool(qids & perm_qids)
            got: List[Dict[str, Any]] = []
            seen: set = set()

            def _add(it: Dict[str, Any], cap: int) -> None:
                if len(got) >= cap or it["index"] in seen:
                    return
                seen.add(it["index"])
                got.append(it)

            if is_perm and perm_shots:
                # 权限项：全部弹窗截图优先（一次检测通常 1~5 次）
                for it in perm_shots:
                    _add(it, ITEM_SHOTS_PERM)
                kind = "perm"
            elif qids and qids <= set(PRE_CONSENT_QIDS):
                # ★ 「同意前收集」类项只配同意之前的图（2026-10-27 用户意见：
                #   Hi投屏 第 3 项的正文说的是同意之前，配图却是同意后的界面）。
                #   同意后 / 遍历阶段的图一律不挂 —— 宁可这一项没有配图
                #   （渲染时会写"本项未取得同意前的界面截图"），
                #   也不能拿一张时间对不上的图去支撑结论。
                for it in by_phase.get("P1", []):
                    if _is_post_consent_shot(it):
                        continue
                    _add(it, ITEM_SHOTS_MAX)
                kind = "phase"
            else:
                for ph in (row.phases or []):
                    for it in by_phase.get(ph, []):
                        _add(it, ITEM_SHOTS_MAX)
                kind = "phase"
            # 每个问题块最多列 ITEM_SHOTS_MAX 张：够说明"当时在哪一屏、有什么入口"，
            # 又不至于让一个问题块撑成好几屏。
            if (not got and self.policy_shot_note
                    and "P2" in (row.phases or [])):
                # 政策页截图被证伪剔除后，靠政策页作证的那几项就成了"无图"。
                # 此时补首启弹窗那一屏：它正是政策入口所在的地方 ——
                # 报告写"入口在弹窗上、但点了没进去"，配图就该是那个弹窗。
                # 只在这一种情形下补，别的时候不拿 P1 的图去凑 P2 的项。
                for it in by_phase.get("P1", []):
                    _add(it, 2)
                kind = "phase"
            if not got and "Q001" in qids and by_phase.get("P1"):
                # 政策项（Q001）没图时，配首启那一屏（金考典 2026-10-27）：
                # 「首启弹窗里有没有政策入口、有没有同意按钮」就长在这一屏上。
                # Q001 的阶段是 P0/P2/P5，按阶段取图永远取不到 P1，
                # 于是正文在讲首启弹窗、配图却是空的。
                for it in by_phase.get("P1", []):
                    _add(it, 2)
                kind = "phase"
            row.shots = [{"index": it["index"], "label": it["label"],
                          "phase": it["phase"], "kind": kind}
                         for it in got[:ITEM_SHOTS_MAX]]

        used = {s["index"] for r in self.fr.rows for s in (r.shots or [])}
        # 外跳取证图已经挂在「外跳去向」章节，不能再出现在文末的
        # "未挂到具体检测项的界面截图"里（同一张图出现两次，读起来像两件事）。
        used |= {it["index"] for it in jump_shots}
        # 把报告里的 1 基编号回填到外跳记录（采集期存的是 res.screenshots 的
        # 下标，两套编号不通，直接用会把图挂错）。按 label 配对，按出现顺序取。
        _pool: Dict[str, List[int]] = {}
        for it in jump_shots:
            _pool.setdefault(str(it.get("label") or ""), []).append(it["index"])
        _rest = [it["index"] for it in jump_shots]
        for j in (self.fr.external_jumps or []):
            if j.get("screenshot") is None:
                continue
            lab = "外跳：%s" % (j.get("label") or "其他应用")
            lst = _pool.get(lab) or []
            if lst:
                idx = lst.pop(0)
                j["shot_index"] = idx
                if idx in _rest:
                    _rest.remove(idx)
        # 兜底：按 label 配不上时按顺序补。★ 不能就这样放弃 —— 否则盘上明明
        # 有一张外跳图，章节里却写"未留证"，复核员对着两张清单对不上账。
        # 只给"采集期确实截过图"（screenshot 非 None）的条目补，不凭空的发图。
        for j in (self.fr.external_jumps or []):
            if j.get("screenshot") is None or j.get("shot_index"):
                continue
            if _rest:
                j["shot_index"] = _rest.pop(0)
        self.fr.shots_unused = [it for it in gal if it["index"] not in used]

    def _attach_click_shots(self) -> None:
        """把采集侧的逐次点击留痕搬到报告对象上（图 + 判读 + 预判 + 结果）。

        ★ 为什么需要这一节（用户 2026-11-05 意见）：
          报告原来只有"UI 点击 124 次、界面 234 个"这种合计数字。复核员没法
          回答"这 124 次点在哪、凭什么点、点了有没有用"，也就无从判断"测得
          充分不充分"。逐次留痕把这三问一次答完 —— 而且它同时是**自查工具**：
          换屏率低、空点集中在某类入口，说明候选生成有问题，不是 App 没东西。

        采集侧已压成 360px JPEG（约 20KB/条），这里不再压第二次：二次压缩只会
        让点击标记变糊，而体积已不是问题。超上限的部分如实写明丢了多少条 ——
        不能让报告假装"每一次都留了痕"。
        """
        raw = list(getattr(self.scan, "click_shots", None) or []) if self.scan else []
        if not raw:
            return
        keep: List[Dict[str, Any]] = []
        for it in raw:
            if not isinstance(it, dict) or not it.get("b64"):
                continue
            keep.append({
                "i": it.get("i"), "t": it.get("t"),
                "label": it.get("label") or "", "cls": it.get("cls") or "",
                "at": list(it.get("at") or []), "bounds": list(it.get("bounds") or []),
                "src": it.get("src") or "", "why": it.get("why") or "",
                "kind": it.get("kind") or "unknown",
                "kind_label": it.get("kind_label") or "",
                "expect": it.get("expect") or "", "risk": it.get("risk") or "",
                "result": it.get("result") or "",
                "b64": it.get("b64") or "",
            })
        dropped = max(0, len(keep) - CLICK_SHOTS_MAX)
        self.fr.click_shots = keep[:CLICK_SHOTS_MAX]
        try:
            from .. import clickev
            self.fr.click_stats = clickev.summarize(self.fr.click_shots)
        except Exception:
            self.fr.click_stats = {}
        self.fr.click_stats["dropped"] = dropped
        self.fr.click_stats["total_recorded"] = len(keep)
        if dropped:
            self.fr.notes.append(
                "逐次点击留痕共 %d 条，报告只内嵌前 %d 条（其余 %d 条的界面截图"
                "已按上限丢弃，动作本身仍完整记录在点击路径里）。"
                % (len(keep), CLICK_SHOTS_MAX, dropped))

    def _attach_landing(self) -> None:
        """搬「首启着陆」记录（P3.5）：同意之后怎么走到主页面的。

        ★ 为什么报告必须有这一节（用户 2026-11-06 意见）：
          以前报告里只有"UI 点击 5 次"，读者无从判断这是工具不行还是应用
          把流程卡住了。而"同意后落在开屏广告 / 年龄门 / 登录墙"这件事本身，
          就是**首启流程的设计事实**，属于检测结论的一部分，不是采集内部的
          技术细节 —— 用户有权知道"这个 App 一装好就要先过几道门"。

        没有这一段（旧存档、1 档、应用起不来）时保持空字典，报告渲染成
        "本轮未记录"，而不是编一段出来。
        """
        d = dict(getattr(self.scan, "landing", None) or {}) if self.scan else {}
        if not d:
            return
        steps: List[Dict[str, Any]] = []
        for it in (d.get("steps_detail") or []):
            if not isinstance(it, dict):
                continue
            steps.append({
                "n": it.get("n"),
                "form": it.get("form") or "",
                "form_name": it.get("form_name") or "",
                "read": it.get("read") or "",
                "action": it.get("action") or "",
                "target": it.get("target") or "",
                "why": it.get("why") or "",
                "expect": it.get("expect") or "",
                "ai": it.get("ai") or "",
                "result": it.get("result") or "",
            })
        self.fr.landing = {
            "reached_home": bool(d.get("reached_home")),
            "why": d.get("why") or "",
            "secs": float(d.get("secs") or 0),
            "steps": int(d.get("steps") or len(steps)),
            "taps": int(d.get("taps") or 0),
            "swipes": int(d.get("swipes") or 0),
            "forms": list(d.get("forms") or []),
            "form_names": list(d.get("form_names") or []),
            "blocked_why": d.get("blocked_why") or "",
            "home_by": d.get("home_by") or "",
            "budget": d.get("budget"),
            "detail": steps[:40],
        }

    @staticmethod
    def _plain(title: str) -> str:
        """去掉重复的书名号。

        entryClicked 从界面抓来时本身常带书名号（《用户隐私政策》），
        外面再套一层就成了「《《用户隐私政策》》」—— 报告里很显眼。
        """
        t = (title or "").strip()
        while t.startswith("《") and t.endswith("》"):
            t = t[1:-1].strip()
            if not t:
                return ""
        return t

    def _builtin_path_note(self) -> str:
        """正文取自安装包时，把包内路径补在复现步骤里。

        用户 2026-10-28 的意见：复现步骤 ④ 只写「正文取自 APK 内置文档」，
        复核员拿着这句话没法自己去看那份文件 —— 加一句包内路径，
        解包后 `assets/vivo_private.html` 双击就能打开对照。
        """
        path = str((self.policy_builtin or {}).get("path") or "").strip()
        return "（包内路径：%s）" % path if path else ""

    @staticmethod
    def _excerpt(text: str, n: int = 200) -> str:
        """取一段**像正文**的开头。

        WebView 抓下来的 innerText 开头常是一堆 H5 残留（"添加图片"、
        "Created with Sketch."、"编组 15"），直接截前 200 字会让复核员
        以为我们拿到的是垃圾。这里跳过过短的行和明显的 UI 残留词。
        """
        junk = ("created with", "sketch", "添加图片", "编组", "图层", "svg",
                "placeholder", "loading")
        buf = []
        for line in (text or "").splitlines():
            s = line.strip()
            if len(s) < 12:
                continue
            low = s.lower()
            if any(j in low for j in junk):
                continue
            buf.append(s)
            if sum(len(x) for x in buf) >= n:
                break
        out = " ".join(buf)[:n]
        return out or (text or "")[:n]

    def _build_repro(self) -> None:
        """把这次检测实际走过的路，写成人工可照着重走一遍的步骤。

        为什么必须有这一段：自动检测的价值是「人工能快速验出我测的对不对」。
        最好的情况是证据链本身足够准，复核员看描述就知道对不对；
        次一等、但同样可接受的情况，是复现步骤写得足够清楚，
        复核员能自己重走一遍验出来。两者都要求**每一个数字都是真的** ——
        这里所有时刻、坐标、次数都取自本次采集记录，取不到就写"未记录"，
        不填任何推测出来的值。
        """
        fr = self.fr
        sc = self.scan
        steps: List[str] = []
        pkg = fr.package or (getattr(sc, "package", "") if sc else "")

        # ★ 目标应用没跑起来时，"重走检测流程"没有意义 —— 走到第三步就会
        #   卡在同一个问题上。此时对复核员真正有用的是**复现这个现象本身**：
        #   自己眼前看到一次，就能确认"不是检测工具的问题"。
        # ★★ 但"现象"分三种，措辞不能混（2026-10-27 洋葱学园）：那一轮应用
        #   明明在前台待了 7 分钟，复现步骤却写"应用启动后立即退回桌面，
        #   进程存活不足 1 秒" —— 复现步骤编造了没发生的事，比没写更糟。
        if getattr(fr, "app_start_failed", False):
            cr = fr.app_crash or {}
            reg = cr.get("fault_region") or {}
            _rh = fr.run_health or {}
            _st = str(_rh.get("state") or "")
            _weak_read = _st in ("no_ui", "no_dump")
            _NUM = "①②③④⑤⑥⑦⑧"

            def _add(txt: str) -> None:
                """按当前条数自动编号 —— 手写数字会在跳过某一步时留下空号。"""
                steps.append("%s %s" % (_NUM[len(steps)], txt))

            # ★ repro 是纯文本：写 <b> 会被渲染层转义成 &lt;b&gt;（已踩）。
            steps = []
            _add("连接设备后执行：%s"
                 % (cr.get("repro_cmd") or "adb shell am start -n <包名>/<主 Activity>"))
            if _weak_read:
                _add("观察设备：应用能正常打开并停在前台"
                     "（本次实测进入应用 %d 屏，没有崩溃记录）——"
                     "打不开的不是应用，是界面结构"
                     % int(_rh.get("app_any") or 0))
                _add("在应用停在前台的状态下导出界面结构："
                     "adb shell uiautomator dump /sdcard/ui.xml && "
                     "adb shell cat /sdcard/ui.xml")
                _add("与本次记录逐项对照：本次导出 %d 屏，其中可读文字节点 0 屏"
                     "（结构树为空 / 只有 WebView 容器 / 加固壳自绘）"
                     % int(_rh.get("app_any") or 0))
                if cr.get("signal"):
                    _add("另：本次取到了崩溃记录（信号 %s），但它不是"
                         "「应用打不开」的证据" % cr.get("signal"))
                _add("若你那边同样读不到文字节点，即可确认本次 22 项「跳过未测」"
                     "源于界面无法读取，而非应用没有相应行为；"
                     "改用人工沙箱（截图+录屏）方式复核即可取得结论")
            else:
                _add("观察设备：应用启动后立即退回桌面，进程存活不足 1 秒"
                     "（本次实测：采集器在第 %d 次探测到进程已不存在后中止遍历）"
                     % int(fr.relaunch_count or 0))
                _add("取崩溃日志（无需 root）：adb logcat -d | grep -A 30 \"Fatal signal\"")
                if cr.get("tombstone"):
                    _add("取系统崩溃转储（需 root）：su -c \"cat %s\"" % cr["tombstone"])
                _add("与本次记录逐项对照：信号 %s（%s）／出错地址 %s%s"
                     % (cr.get("signal") or "未取到",
                        cr.get("signal_code") or "—",
                        cr.get("fault_addr") or "未取到",
                        ("／该地址所属内存段 %s（权限 %s）"
                         % (reg.get("path"), reg.get("perms"))) if reg.get("path") else ""))
                if cr.get("signal"):
                    _add("若能复现同一崩溃，即可确认本次 22 项「跳过未测」"
                         "源于该应用在本设备上无法启动，而非检测流程未执行；"
                         "换到该应用可正常启动的设备后重跑本流程即可取得结论")
                else:
                    _add("本次未取到崩溃记录，所以不能声称「崩溃可复现」；"
                         "请按上述命令自行观察启动过程，"
                         "以判断这台设备上该应用能否进入前台")
            fr.repro = steps
            return

        # ① 复原到新装状态 —— 首启弹窗只在清数据后的第一次启动出现
        if pkg:
            steps.append("① 复原到新安装状态（首启弹窗只在此状态下出现）："
                         "adb shell su -c \"pm clear %s\"" % pkg)
        if getattr(fr, "apk_path", ""):
            steps.append("② 安装本次检测的同一份包：adb install \"%s\"" % fr.apk_path)
        elif pkg:
            inst = (getattr(sc, "install", None) or {}) if sc else {}
            if inst.get("apk"):
                steps.append("② 安装本次检测的同一份包：adb install \"%s\"" % inst["apk"])
            else:
                steps.append("② 安装与本次检测相同的包（本次记录的 APK 路径：未记录）")

        # ③ 冷启动 —— 政策入口与同意前行为都在这个窗口里
        steps.append("③ 冷启动 App 并注入采集脚本（不要预先启动、不要手动同意）："
                     "python run_flow.py -p %s --ai-provider agent --ai-vision --ai-analyze" % pkg)

        # ④ 政策入口：坐标与入口文案都是本次实测值
        #
        # ★ 这一步原先有两个"想当然"，真机一跑就露：
        #   (a) 不管有没有点成入口，一律写"点《隐私政策》入口…政策页打开并取得正文 N 字"。
        #       赣警办这轮首启弹窗里入口文字不在可点击节点内，`entryClicked` 是空的，
        #       正文其实来自 APK 内置文档 —— 复核员照着做会发现"点了没反应"。
        #   (b) 页面地址取的是 `cap["bestTextUrl"]`，而那份正文正是被归属核验**排除**
        #       的第三方（腾讯兔小巢）政策。于是 1847 字的 App 政策被标成了
        #       txc.qq.com 的地址，证据与结论对不上。
        #   现在按"正文到底出自哪儿"分三支写，取不到就写取不到。
        cap = (getattr(sc, "policy_capture", None) or {}) if sc else {}
        xy = cap.get("entryTapXY") or []
        clicked = str(cap.get("entryClicked") or "").strip()
        entry = self._plain(clicked or "隐私政策")
        chars = len(self.policy_text or "")
        # 正文来源标签：与「隐私政策获取情况」一节用同一套判定
        src = (self.policy_source
               or ("APK 内置文档" if self.policy_builtin else "设备侧页面"))
        from_page = not self.policy_source and not self.policy_builtin
        # policy_url 在被排除时已清空；不能再用 cap["bestTextUrl"]（那是排除掉的那份）
        url = self.policy_url or ""
        if not url:
            # 正文来自安装包、但入口**确实打开过**时，页面地址仍然值得写 ——
            # 复核员要复现"政策页长什么样"。只取**像政策**的那一个地址：
            # 同一批 URL 里常混着第三方共享清单（Hi投屏 /protocol/share），
            # 把它当"政策页面地址"写进来，正是用户 2026-10-28 指出的那个错。
            for _u in [d.get("url") for d in (cap.get("urls") or [])
                       if isinstance(d, dict)]:
                if not _u:
                    continue
                _lu = str(_u).lower()
                if _lu.startswith("file:///android_asset"):
                    url = _u
                    break
                if _lu.startswith("http") and _POL.classify_doc("", "", _u) == "privacy":
                    url = _u
                    break
        if not clicked:
            if cap.get("policyUrlFetched"):
                # ★ 没点 ≠ 点不动。按链接取得全文后，采集端是**主动跳过**了
                #   「点开政策页并滑动阅读」这一段（省下的时间还给遍历），
                #   不是试了几次没点开。写成"未能点开（点击无响应）"是编了个没做过的动作。
                s4 = ("④ 首启弹窗出现后，**先不要点同意**。本轮已**按链接直接取得政策全文**，"
                      "因此未在弹窗上点开政策入口（该入口的可点性本轮未实测）")
            else:
                s4 = ("④ 首启弹窗出现后，**先不要点同意**。本次在弹窗上**未能点开政策入口**"
                      "（弹窗只给出 %d 字告知摘要，入口文字不在可点击节点内或点击无响应）"
                      % len(cap.get("noticeText") or ""))
            if chars:
                s4 += ("；本报告使用的 %d 字正文取自**%s**%s，核对方式见本节表格"
                       % (chars, src, self._builtin_path_note()))
            # 正文若是按 APK 链接在线抓的，必须把地址写出来（复核员可直接打开核对）
            if url and not from_page:
                s4 += "，地址：%s" % url
            steps.append(s4)
        else:
            if xy:
                s4 = ("④ 首启弹窗出现后，**先不要点同意**。点《%s》入口"
                      "（屏幕坐标 %d, %d）" % (entry, xy[0], xy[1]))
            else:
                s4 = ("④ 首启弹窗出现后，**先不要点同意**。点《%s》入口（本次未记录坐标）"
                      % entry)
            if chars and from_page:
                s4 += "，政策页打开并取得正文 %d 字" % chars
            elif chars:
                s4 += ("，但未取到页面正文，本报告使用的 %d 字正文取自**%s**%s"
                       % (chars, src, self._builtin_path_note()))
            # ★ 链接被系统选择器/外部浏览器接管时，必须当场说清（作业帮 2026-10-30）：
            #   复核员按"点开就应当看到政策页"去复现，得到的却是浏览器搜索页，
            #   会以为是我们点错了。真实情况是这个链接根本不走应用内 WebView。
            _ext = str(cap.get("externalOpen") or "").strip()
            if _ext:
                s4 += ("，但点击后由**系统组件/外部应用**接管（前台：%s），"
                       "政策内容不在被测应用内展示，本轮无法在应用内读取其正文，"
                       "需在浏览器中人工核对" % _ext.split("/")[-1][:40])
            elif not chars:
                s4 += "，未取到政策正文"
            if url:
                s4 += "，页面地址：%s" % url
            steps.append(s4)

        # ⑤ 同意前观察窗口 —— 这是"未经同意收集"的取证窗口
        cms = getattr(sc, "consent_elapsed_ms", None) if sc else None
        _no_consent = self._consent_absent()
        if _no_consent:
            # 1 档：没有同意动作，也就不存在"窗口终点"，整轮都在未同意状态下
            steps.append("⑤ 冷启动后保持未同意状态静置观察（本档位不执行「同意」动作、"
                         "不做界面遍历），共记录未同意状态行为 %d 条"
                         % self._pre_count())
        elif cms:
            steps.append("⑤ 保持未同意状态观察至第 %.1f 秒（本轮确证在此窗口内的行为 %d 条；"
                         "另有发生在同意前后 %.1f 秒内、时序不可分辨的事件不计入）；"
                         "判定口径：只把**明确早于同意**时间戳的个人信息读取"
                         "认定为未经同意收集"
                         % (cms / 1000.0, self._pre_count(),
                            CMP.CONSENT_EDGE_MS / 1000.0))
        else:
            steps.append("⑤ 保持未同意状态观察（%s）"
                         % ("已捕获同意动作但未记录到同意时刻，窗口终点未记录"
                            if getattr(sc, "consent_given", False)
                            else "本轮未捕获到同意事件，窗口终点未记录"))

        # ⑥ 同意动作
        src = getattr(sc, "consent_source", "") if sc else ""
        act = (src.split(":", 1)[1] if ":" in (src or "") else "") or "同意"
        if _no_consent:
            steps.append("⑥ 本档位不执行「同意」动作（1 档「仅同意前」：全程保持未同意状态），"
                         "因此本轮没有「同意后」阶段")
        elif cms:
            steps.append("⑥ 点击「%s」（本轮在第 %.1f 秒捕获到该事件），"
                         "随后开始同意后功能遍历" % (act, cms / 1000.0))
        else:
            steps.append("⑥ 点击「%s」，随后开始同意后功能遍历" % act)

        # ⑦ 遍历路径 —— 逐条照抄本次实际点击
        ui_steps = [s for s in (getattr(sc, "ui_steps", None) or []) if sc]
        if _no_consent:
            # 1 档没有"同意"那一步可剥，反而**不能**按同意字样过滤：
            # 探索步骤是「未同意状态：点击「不同意」」，一过滤就整段消失，
            # ⑦ 会变成空白，等于把这一档实际点过的路径全部隐去。
            walked = [s for s in ui_steps if not str(s).startswith("AI ")]
        else:
            # 同意那一步已在 ⑥ 里单独写了，留在遍历列表里会让人以为要点两次
            walked = [s for s in ui_steps
                      if not str(s).startswith("AI ") and act not in str(s)]
        if walked:
            # ★ ui_steps 里带的序号是采集时的原始序号。这里剥掉了「点击同意」
            #   那一步（它已单列在⑥），于是序号跳号（…1. 3. 4.…），而
            #   "共 N 步"又是剥完之后的计数 —— 复核员照着重走会对不上。
            #   统一重排序号，并写明剥掉了哪一条、有没有省略未列出的。
            items = [re.sub(r"^\s*\d+\s*[.、)]\s*", "", str(x)).strip() for x in walked]
            shown = items[:20]
            seq = "；".join("%d. %s" % (i + 1, t) for i, t in enumerate(shown))
            tail = ("；另有 %d 步未列出" % (len(items) - len(shown))
                    if len(items) > len(shown) else "")
            note = ("（「点击同意」那一步已单列在⑥，此处不重复）"
                    if len(walked) != len(ui_steps) else "")
            steps.append(("⑦ 未同意状态下按本轮实际路径探索（共 %d 步）%s：%s%s"
                          if _no_consent else
                          "⑦ 同意后按本轮实际路径遍历（共 %d 步）%s：%s%s")
                         % (len(walked), note, seq, tail))

        # ⑧ 各问题项的复现要点 —— 只写本次真有证据的
        for r in fr.rows:
            if r.state not in (M.FAIL, M.SUSPECT):
                continue
            key = self._repro_key(r)
            if key:
                steps.append("⑧ 【第 %s 项 %s】复现要点：%s" % (r.num, r.title, key))
        fr.repro = steps

    def _consent_absent(self) -> bool:
        """本轮是否**确定没有同意动作**（不是"没捕获到"，而是根本没做这一动作）。

        为什么要区分（使用者 2026-11-16 指出）：1 档「仅同意前」的口径是
        **取到政策正文就收工，不点同意、不遍历**。整轮所有读取本来就发生在
        未同意状态下，不存在"同意动作前后 1500 ms 窗口"这件事。
        早先 `consent_ms is None` 一律判"时序不可分辨"，于是 1 档的报告写成
        "本次在同意动作前后 1500 ms 窗口内观测到…""同意时刻：未记录" ——
        说了一个根本不存在的窗口，属于结论与事实不符。

        判据只用两样可核对的事实：档位声明了 consent_only，且本轮没有登记到
        任何同意动作。2、3 档即使没捕获到同意动作，也不能断言"没有同意" ——
        可能是登记链断了（以观书法 mbsf6 就是这么误判的），那种情形仍按
        "无法分辨先后"保守处理。
        """
        sc = self.scan
        if sc is None:
            return False
        if getattr(sc, "consent_given", False):
            return False
        if getattr(sc, "consent_elapsed_ms", None) is not None:
            return False
        try:
            from ..config import DEPTH_PROFILES
            prof = DEPTH_PROFILES.get(getattr(sc, "depth", "") or "") or {}
            return bool(prof.get("consent_only"))
        except Exception:
            return False

    def _pre_count(self) -> int:
        """确证发生在同意之前的事件数（不含时序不可分辨的边界事件）。"""
        if self.scan is None:
            return 0
        raw = [e for e in (getattr(self.scan, "events", []) or [])
               if getattr(e, "before_consent", False)
               and not getattr(e, "noise", "")]
        b, _e, _a = CMP.split_by_consent(
            raw, getattr(self.scan, "consent_elapsed_ms", None),
            consent_absent=self._consent_absent())
        return len(b)

    def _repro_key(self, r) -> str:
        """给一个问题项写"怎么复现出来"，只用本次实测到的元素。"""
        sc = self.scan
        if sc is None:
            return ""
        st = self.fr.items.get((r.checks or [None])[0]) if r.checks else None
        if st is None:
            return ""
        # 优先用事实表里已经整理好的「调用点与时刻」
        for k, v in (st.facts or []):
            if "调用点" in k or "时刻" in k:
                return str(v)
        # 退而用证据里的接口与取值
        for ev in (st.evidence or []):
            if ev.detail:
                return "%s｜%s" % (ev.detail, ev.title)
        return ""

    # ================================================================== P0
    def p0_static(self, apk: str = "", static_result: Any = None) -> PhaseResult:
        pr = self._begin("P0")
        if static_result is None and not apk:
            self._end(pr, M.PHASE_SKIPPED, "未提供 APK，跳过静态分析")
            return pr
        # 用离线存档复跑时静态分析并没有真的执行 —— 不能把 0 秒写成"耗时 0.0s"，
        # 那看起来像"静态分析瞬间完成"，复核员会以为没做。
        self._static_reused = static_result is not None
        try:
            if static_result is None:
                from ..apkstatic import analyze
                static_result = analyze(apk, log=self.log)
        except Exception as e:
            self._end(pr, M.PHASE_FAILED, "静态分析异常：%s" % e)
            return pr

        import dataclasses
        if dataclasses.is_dataclass(static_result):
            d = dataclasses.asdict(static_result)
        elif hasattr(static_result, "to_dict"):
            d = static_result.to_dict()
        else:
            d = dict(static_result or {})
        self.fr.static = d
        # StaticResult 是扁平结构（min_sdk / target_sdk / permissions …），
        # 早期这里当成 {"manifest": {...}} 嵌套去取，结果 minSdk 永远是 None。
        mf = d.get("manifest") or {}
        perms = d.get("permissions") or []
        sdks = d.get("sdks") or []
        pr.evidence = {
            "package": d.get("package", ""),
            "app_label": d.get("app_label", ""),
            "version_name": d.get("version_name", ""),
            "min_sdk": mf.get("minSdkVersion") or d.get("min_sdk") or "",
            "target_sdk": mf.get("targetSdkVersion") or d.get("target_sdk") or "",
            "permissions": perms,
            "components": d.get("components") or d.get("exported") or [],
            "sdks": sdks,
            "jiagu": d.get("jiagu") or [],
            "debuggable": d.get("debuggable", ""),
            "cleartext": d.get("cleartext", ""),
            "allow_backup": d.get("allow_backup", ""),
            "signature": d.get("signature") or {},
            "policy_urls": d.get("policy_urls") or [],
            "domains": d.get("domains") or [],
            "dex_count": d.get("dex_count", ""),
        }
        pr.steps = ["解析 AndroidManifest", "提取权限声明", "识别 SDK", "抽取内嵌政策 URL"]
        self.log("[流程]    minSdk=%s targetSdk=%s 权限 %d 项 SDK %d 个 加固=%s"
                 % (pr.evidence["min_sdk"], pr.evidence["target_sdk"],
                    len(perms), len(sdks), (d.get("jiagu") or ["未识别"])[:1]))
        if not self.fr.app_name:
            self.fr.app_name = d.get("app_label") or ""
        if not self.fr.version:
            self.fr.version = d.get("version_name") or ""

        # ---------- 静态能给的两条事实，且两条不能互相错位 ----------
        # ★ 早先这里把「危险权限声明」写进了 Q007，于是报告第 5 项
        #   （未列明向第三方提供个人信息的种类、目的、方式以及接收方名称、联系方式）
        #   的结论成了「静态分析发现 App 声明了 11 项危险权限（精确位置、录音、
        #   相机…），需核对是否已在政策中列明接收方与共享目的」——
        #   题面问的是"有没有向第三方提供、列没列接收方"，证据给的却是
        #   "声明了哪些权限"，两者没有因果关系。复核员一眼就能看出证据撑不住题面，
        #   这类"看着像结论、其实是错位"的句子比留白更糟：它会让人以为该项已验过。
        #   正确归口：
        #     危险权限声明 → Q010（超出必要范围收集使用个人信息，报告第 11 项）
        #     第三方 SDK   → Q007（需核对是否为政策第三方清单逐一列明，报告第 5 项）
        # permissions 是字符串列表（不是 dict）—— 早先按 p.get("dangerous") 取，
        # 条件恒为 False，报告把 49 项权限里的危险权限算成 0 项。
        risky = CMP.dangerous_permissions(perms)
        if risky:
            rnames = [str(p.get("name")) for p in risky]
            # ★「声明了敏感权限」本身不是违规：是否超范围取决于该权限是不是
            #   该 App 核心功能所必需（属业务归类裁量，自动化判不了）。
            #   所以只固化事实、标"未测" —— 不能凭一句声明就写"疑似超范围"，
            #   那会把复核员的注意力引到一条站不住的线索上。
            self._set("Q010", NOT_TESTED, phase="P0",
                      reason="静态分析记录 App 声明了 %d 项危险权限（%s）。权限声明本身"
                             "不等于超范围，是否为实现核心功能所必需须结合 App 业务类型"
                             "逐项判断；本轮界面遍历也未在无关场景观测到对应的实际收集，"
                             "故不对该项作合规性认定，留给人工结合业务场景复核"
                             % (len(risky), "、".join(rnames[:8])),
                      evidence=[Evidence("manifest", "危险权限声明 %d 项" % len(risky),
                                         "、".join(rnames[:12]), "P0")],
                      facts=[["危险权限声明", "%d 项（共声明 %d 项权限）"
                              % (len(risky), len(perms))],
                             ["危险权限清单", "、".join(rnames)]])

        # Q007 在静态阶段能拿到的唯一证据是**内嵌第三方 SDK 清单** ——
        # 政策需逐一列明接收方名称、联系方式、共享目的与所涉信息种类，
        # 而"要不要列、列了没列"要先有一份待核对的 SDK 对象清单。
        # 这里只把清单摆出来、不做判定；判定等 P5 与政策文本对照后再定。
        sdks = [s for s in (sdks or []) if (s.get("name") or s.get("package"))]
        if sdks:
            # 框架工具类（Support Library / OkHttp / Glide 之流）不处理个人信息，
            # 不是"接收方"。分开计数，避免把 30 多个 SDK 一股脑说成共享对象。
            fw = [s for s in sdks
                  if any(t in (s.get("type") or "") for t in ("框架", "工具"))]
            pii = [s for s in sdks if s not in fw]
            shown = []
            for s in pii[:40]:
                nm = (s.get("name") or s.get("package") or "").strip()
                au = (s.get("author") or "").strip()
                if nm:
                    shown.append("%s%s" % (nm, "（%s）" % au if au else ""))
            self._set("Q007", NOT_TESTED, phase="P0",
                      reason="静态分析从 APK 中识别出 %d 个第三方 SDK 组件，"
                             "其中 %d 个属可能处理个人信息的类型（%s…），另有 %d 个"
                             "为框架/工具类（不处理个人信息，通常不作为共享接收方）。"
                             "各 SDK 是否为政策第三方清单逐一列明了名称、联系方式、"
                             "共享目的与所涉信息种类，需与政策文本逐条比对（结论见 P5）"
                             % (len(sdks), len(pii), "、".join(shown[:5]), len(fw)),
                      evidence=[Evidence("manifest", "内嵌第三方 SDK %d 个"
                                         % len(sdks), "、".join(shown[:12]), "P0")],
                      facts=[["内嵌 SDK 总数", "%d 个" % len(sdks)],
                             ["可能处理个人信息的 SDK", "%d 个" % len(pii)],
                             ["框架/工具类 SDK", "%d 个" % len(fw)],
                             ["SDK 清单", "、".join(shown) or "（无可疑项）"]])
        self._end(pr, M.PHASE_DONE)
        return pr

    # ---------------------------------------------------------------- P1 辅助
    def _merge_pre_consent_perms(self) -> int:
        """把「未同意阶段索要可采集个人信息的权限」并入 Q003。

        ★ 用户 2026-11-18 口径（第 1 条）：同意前申请这类权限的行为，合并到
          「3. 未经用户同意收集使用个人信息」。不改 Q012 —— 它判的是"这个
          权限与当前功能是否匹配"，是另一回事，两者混一起会互相稀释。

        状态怎么定（两种情形，措辞必须分开，否则就是假话）：
          · 本轮另有取到值的收集 → Q003 已是「发现问题」，这里只追加事实；
          · 只有索权、没取到值 → 也判「发现问题」，但描述写的是"索要权限"，
            并注明本轮未观测到该权限对应的取值 —— 不写"已收集"。

        只认系统弹窗（`perm_scenes` 的来源）。写剪贴板之类的 API 既不弹窗
        也不采集个人信息，按用户口径不算问题。
        """
        scenes = getattr(self.scan, "perm_scenes", None) or []
        hits = CMP.pre_consent_perm_requests(
            scenes, getattr(self.scan, "events", None))
        if not hits:
            return 0
        # 同一权限弹多次只写一条事实（次数另计）：报告要的是"要过哪些权限"，
        # 而不是"这个弹窗出现了 7 次"——后者对复核没有增量信息。
        seen: Dict[str, Dict[str, Any]] = {}
        for s in hits:
            g = CMP.norm_perm_group(str(s.get("perm") or ""))
            if g and g not in seen:
                seen[g] = s
        _parts = []
        for g, s in seen.items():
            _t = "冷启动后 %.1f 秒" % (float(s.get("at_ms") or 0) / 1000.0)
            _parts.append("%s（%s）" % (g, _t))
        names = "、".join(_parts)
        _raw = " ｜ ".join(
            (str(s.get("dialog_text") or s.get("perm_raw") or "")).strip()[:80]
            for s in list(seen.values())[:3]
            if (s.get("dialog_text") or s.get("perm_raw")))
        facts = [["未同意阶段索要的权限", names]]
        if _raw:
            facts.append(["弹窗文字", _raw])
        # 有没有真的替用户点了「允许」——这是"我们改没改变被测状态"的交代
        _tapped = [g for g, s in seen.items() if "代点" in str(s.get("action") or "")]
        facts.append(["是否代为作答",
                      ("是（%s；已注明为本轮采集动作，不代表用户授权）"
                       % "、".join(_tapped)) if _tapped else
                      "否（仅取证，弹窗未由采集脚本作答）"])
        # 证据是否够硬：app_before 明确为 True 才算"确认应用在弹窗之前还在前台"
        _soft = [g for g, s in seen.items() if s.get("app_before") is not True]
        if _soft:
            facts.append(["证据待补",
                          "、".join(_soft) + "：弹窗出现前未能确认被测应用在前台，"
                          "该条只记为线索，不足以单独认定"])
        facts.append(["本项认定依据",
                      "系统权限弹窗本身（索权行为）；是否已实际取到该权限对应的"
                      "个人信息，见本项「采集类事件」部分"])
        _state = SUSPECT if _soft else FAIL
        _absent = self._consent_absent()
        _when = ("本轮未执行「同意」动作、全程处于未同意状态" if _absent
                 else "在用户同意隐私政策之前")
        cur = self._item("Q003")
        if cur.state == FAIL:
            # 已经因"实际取到取值"认定过：这句只是把索权行为补进同一条结论，
            # 不另起一条 —— 否则同一时段的行为会被记成两件事。
            if "索要" not in (cur.desc or ""):
                cur.desc = (cur.desc or "").rstrip("。") + \
                    "；同一期间还向用户索要了%s权限" % "、".join(seen.keys())
            cur.facts.extend(facts)
            return len(seen)
        self._set(
            "Q003", _state, phase="P1",
            level=("高" if _state == FAIL else "中"),
            confidence=("确证" if _state == FAIL else "疑似"),
            desc=("%s，App 即向用户索要了%s权限；"
                  "本轮未观测到这些权限对应的实际取值%s"
                  % (_when, "、".join(seen.keys()),
                     "，该索权行为本身已构成「未经同意收集」的前置动作"
                     if _state == FAIL else
                     "；且弹窗出现前未能确认应用在前台，需人工复核")),
            evidence=[Evidence("ui", "未同意阶段索要权限", names, "P1")],
            facts=facts)
        self.log("[流程]    未同意阶段索要权限：%s（%s）→ Q003"
                 % ("、".join(seen.keys()),
                    "已认定" if _state == FAIL else "疑似"))
        return len(seen)

    def _append_p1_attempts(self, pre: Sequence[Any]) -> None:
        """把「尝试获取但未成功」写进事实表 —— 写明、标注未成功、**不计违规**。

        ★ 用户 2026-11-18 口径（第 4 条）。这类事件原先被四级漏斗第②级
          （取值有效性）整批挡掉，报告里一个字都没有：复核员看到"没收集过
          IMEI"，而 App 其实试过、只是被系统拒绝。
          反过来若据此认定违规，又是假话（Android 10 起读 IMEI 必然失败）。
          所以单独成一行事实，状态一律不动。
        """
        try:
            att = CMP.attempted_types(pre, device_ids=self.fr.device_identities)
        except Exception as e:
            self.log("[!] 尝试获取统计失败（不影响结论）：%s" % str(e)[:100])
            return
        if not att:
            return
        _desc = CMP.describe_attempted(att)
        _n = sum(int(r.get("count") or 0) for r in att.values())
        # 落进 flow.json：简版的「本轮检测范围」要据此写一句，否则"未收集"
        # 会被读成"压根没试过"（见 sop_brief._scope_line）。
        self.fr.p1_attempted = {"count": _n, "text": _desc, "types": len(att)}
        for qid in ("Q002", "Q003"):
            st = self.fr.items.get(qid)
            if st is None:
                continue
            st.facts.append([
                "尝试获取但未成功（不计为违规）",
                "%s；共 %d 次接口调用未取到有效值。"
                "该行为只说明 App 发起过读取，不构成「已收集」，"
                "也不作为违规认定依据" % (_desc, _n)])
        self.log("[流程]    尝试获取未成功 %d 次（%d 类），已写入事实表、不计违规"
                 % (_n, len(att)))

    def _append_consent_sync(self) -> None:
        """把「点击同意后 1.5 秒内」的采集写进事实表 —— 写明、**不计为同意前**。

        ★ 用户 2026-11-19 口径：同一交互内的采集"记录但不判违规"。
          这一支不是可选项，而是修正一种**报告失真**：驿站助手 4 档那一轮
          887 条事件里，点击前只有 1 条（读时区），点击后 1.5 秒内却有 74 条
          （其中 400 毫秒就读了 Android ID 并外发）。旧报告只写"本轮未取得
          任何个人信息取值"，读者看到的是"什么都没发生"—— 与事实相反。
          判定可以是不违规，但**不能让人以为没采**。

        为什么只追加事实、不动状态：Q003 问的是"同意前有没有实际取得"，
        这些事件发生在点击之后，按分水岭口径不属于该项；挪进事实表既不改变
        结论，也把"间隔极短"这个可复核的现象留在了纸面上。
        """
        n = int(getattr(self.fr, "consent_sync_events", 0) or 0)
        if n <= 0:
            return
        _sum = str(getattr(self.fr, "consent_sync_summary", "") or "")
        _ms = int(CMP.CONSENT_EDGE_MS)
        _txt = ("%d 条（点击「同意」后 %d 毫秒内%s）。与同意动作属于同一交互，"
                "按本轮口径不计为「同意前收集」；但它说明收集与同意的间隔极短："
                "用户点下同意后 1.5 秒内，上述读取就已经完成"
                % (n, _ms, ("：" + _sum) if _sum else ""))
        for qid in ("Q002", "Q003"):
            st = self.fr.items.get(qid)
            if st is None:
                continue
            st.facts.append(["同一交互内采集（不计为同意前）", _txt])
        self.log("[流程]    同一交互内采集 %d 条（点击后 %d ms 内），"
                 "已写入事实表、不计为同意前收集%s"
                 % (n, _ms, ("：" + _sum) if _sum else ""))

    # ================================================================== P1
    def p1_pre_consent(self) -> PhaseResult:
        """未同意阶段：凡同意前采集到个人信息，一律算未经同意收集。

        这是全流程最确定的一条规则 —— 时间戳早于同意事件即可判定，
        不需要裁量，所以直接定 fail 而不是 suspect。
        """
        pr = self._begin("P1")
        if self.scan is None:
            self._end(pr, M.PHASE_SKIPPED, "本次未执行设备动态采集")
            return pr

        # ★ 先确认前提是否成立：目标应用本次到底有没有运行起来。
        #   三一卡车 2026-10-16 实测：包内带阿里 AShield 加固壳（libashield.so），
        #   冷启动即 SIGSEGV（进程存活 0 秒），采集期间反复退出 4 次，
        #   整轮只留下 5 条事件、0 次 UI 点击、未捕获同意。
        #   这种数据下「同意前事件 0 条」的真实含义是**App 没运行过**，
        #   而不是「App 没有在同意前收集」。写成后者就是拿"没测"冒充"没问题"。
        if self.fr.app_start_failed:
            _rn = int(self.fr.relaunch_count or 0)
            # ★ 三种失败不能混成一句话（2026-10-27 洋葱学园）：用户站在手机前
            #   看着 App 明明开着，报告却写"前台从未切换"——因为界面结构读不出来
            #   被当成了"没起来"。措辞统一由 `start_failed_reason()` 生成。
            _head, _why = M.start_failed_reason(self.fr)
            self._end(pr, M.PHASE_FAILED, "%s，本阶段无有效数据" % _head)
            pr.warnings.append(
                "本阶段未取得任何可支撑结论的数据：%s"
                "是否重测，取决于该 App 能否在检测设备上被读取 —— "
                "取证与复现命令见报告「目标应用启动状态」章节。" % _why)
            for qid, what in (("Q002", "同意前是否存在收集行为"),
                              ("Q003", "同意前是否实际取得个人信息取值")):
                self._set(qid, NOT_TESTED, phase="P1",
                          reason="%s，无法观测%s；本项未取得任何证据，非「未发现问题」"
                                 % (_head, what))
            self.log("[流程]    ⚠ %s，本阶段无有效数据" % _head)
            return pr

        evs = [e for e in getattr(self.scan, "events", []) or []]
        raw_pre = [e for e in evs if getattr(e, "before_consent", False)
                   and not getattr(e, "noise", "")]
        # ★ 光看 before_consent 布尔位会误判（简小知实测）：
        #   android_id 的读取只比同意早 9ms，且调用栈是 AgreementDialog.onConfirm
        #   —— 那是「点了同意之后」的回调链，不是未征得同意就收集。
        #   误判一旦写进报告，复核员照着签字的是一条不成立的结论。
        #   这里按「与同意时刻的距离 + 调用栈」重新切一遍，时序不可分辨的
        #   单独放一边，不参与"未经同意收集"的认定。
        _cms = getattr(self.scan, "consent_elapsed_ms", None)
        # 1 档「仅同意前」不点同意：整轮都在未同意状态下，不存在"同意前后"窗口。
        # 这类轮次的事件必须全部算作"确认在同意前"，否则报告会写出一个
        # 不存在的 1500 ms 窗口（见 _consent_absent 的注释）。
        _absent = self._consent_absent()
        pre, edge_pre, _post = CMP.split_by_consent(raw_pre, _cms,
                                                   consent_absent=_absent)
        # 结论句的时态前提：1 档没有同意动作，不能写"在同意之前"（那暗示
        # 后面有个同意），要写"本轮未执行同意动作、全程处于未同意状态"。
        _p1_pre = ("首次打开 App，本轮未执行「同意」动作，App 全程处于未同意状态，"
                   if _absent else "首次打开 App，在用户同意隐私政策之前，")
        # 采集（取到值的）与外发（数据离开设备）分开统计 —— 外发只能证"送出去"，
        # 不能证"收集了什么"，混在一起会把联网次数当成收集次数。
        collected = CMP.collected_types(pre, device_ids=self.fr.device_identities)
        collected_edge = CMP.collected_types(edge_pre, device_ids=self.fr.device_identities)
        sinks = CMP.sink_summary(pre)
        pr.evidence = {"pre_events": len(pre), "total_events": len(evs),
                       "collected_types": list(collected.keys()),
                       "sink_before": sinks["before_consent"],
                       "sink_hosts_before": sinks["before_hosts"]}
        # 人工流程要求「先停一会儿，在不同意的前提下尽量多点各种按钮和链接」。
        # 采集侧从 2026-11-17 起真的会点了（见 collector._explore_pre_consent），
        # 但"点了几屏"必须如实写出来：没点到的话，同意前结论仍属"静置观察"，
        # 报告不能让复核的人以为行为已被充分触发。
        #
        # ★ 判据用结构化字段 `pre_explore`，不再从 `ui_steps` 文本里切：
        #   原文写法是"遇到含『同意』的步骤就停"，而探索的步骤文字是
        #   「未同意状态：点击「不同意」」—— 本身就含「同意」二字，
        #   一匹配就把整段探索当成同意动作截掉了，探索反而被判成没做。
        _pe = getattr(self.scan, "pre_explore", None) or {}
        if _pe:
            # 存档与简版报告都要能看到"这一轮点了几次、经过几屏、卡在哪"
            self.fr.pre_explore = dict(_pe)
        # 静置观测单独存档：1 档的采集多半发生在"我们没动手"的那段时间里
        # （真机实测 Android ID 在冷启动后 23~48 秒被读，而那几个 App 一点
        #  「不同意」就退出）。只写"点了几下"会让读者以为采集只在点击后发生。
        _ps = getattr(self.scan, "pre_settle", None) or {}
        if _ps:
            self.fr.pre_settle = dict(_ps)
        # 同意分水岭复核的条数：简版「本轮检测范围」要用它交代
        # "有多少条其实是点「同意」那一下带出来的"（见 sop_brief._scope_line）。
        self.fr.consent_reclassified = int(
            getattr(self.scan, "consent_reclassified", 0) or 0)
        self.fr.consent_sync_events = int(
            getattr(self.scan, "consent_sync_events", 0) or 0)
        self.fr.consent_sync_summary = str(
            getattr(self.scan, "consent_sync_summary", "") or "")
        _pe_taps = int(_pe.get("taps") or 0)
        _pe_screens = int(_pe.get("screens") or 0)
        if _pe:
            # 1 档：探索有没有真发生，以采集侧记的结构化结果为准
            explored = _pe_taps > 0
            _explore_desc = (("未同意状态下交互探索（点击 %d 次、经过 %d 屏）"
                              % (_pe_taps, _pe_screens)) if explored
                             else "未同意状态下静置观察（未点到界面元素：%s）"
                                  % (_pe.get("why") or "原因未记录"))
        else:
            # 2、3 档没有"未同意探索"这个阶段，沿用原判定：同意之前的遍历步数。
            # （这一支不能删：2、3 档的 PASS/NOT_TESTED 全靠它。）
            pre_steps = []
            for s in (getattr(self.scan, "ui_steps", None) or []):
                if "同意" in str(s):
                    break
                pre_steps.append(s)
            explored = len(pre_steps) >= 2
            _explore_desc = ("%d 步" % len(pre_steps)) if explored else ""
        pr.steps = ["冷启动并注入",
                    _explore_desc or "未同意状态下静置观察（未做交互探索）",
                    "记录同意前行为"]
        if not explored:
            pr.warnings.append(
                "本次未在未同意状态下执行主动交互探索（%s），"
                "同意前的收集行为可能未被充分触发，结论偏保守"
                % (_pe.get("why") or "采集器未进入探索阶段"))
            self.log("[流程]    ⚠ 未执行未同意状态下的交互探索，同意前结论基于静置观察")
        else:
            _rx = _pe.get("refused_exit") or []
            if _rx:
                pr.warnings.append(
                    "未同意状态下点击「%s」后应用退出，此后无法在未同意状态继续操作；"
                    "该行为本身已计入事实表（未同意即不可用）"
                    % "、".join(str(r.get("label") or "") for r in _rx[:3]))
            # 探索跑出被测应用：这一条必须写在报告里。它说明"点了很多次"里
            # 有一部分是在系统应用（相册/桌面/浏览器）里点的 —— 既不能算作
            # 对被测应用的触发，也是不该发生的动作。
            _esc = int(_pe.get("escapes") or 0) if isinstance(_pe, dict) else 0
            if _esc:
                pr.warnings.append(
                    "未同意探索期间有 %d 次界面已不属于被测应用（按 BACK 返回）；"
                    "这些界面上的点击不计入对被测应用的触发" % _esc)
            # 重启会把首启流程重放一遍：网络请求跟着重复计数。不说明的话，
            # 报告里"向某地址发起连接 43 次"会被读成高频外发，其实是同一段
            # 首启代码被跑了 20 遍。
            _rs = int(_pe.get("respawns") or 0) if isinstance(_pe, dict) else 0
            if _rs:
                pr.warnings.append(
                    "探索期间因点击后应用退出，重新拉起过 %d 次；"
                    "每次重启都会重放首启流程，期间的外发计数含重复" % _rs)
            self.log("[流程]    未同意探索：点击 %d 次、经过 %d 屏（%s）"
                     % (_pe_taps, _pe_screens, _pe.get("why") or ""))

        self.log("[流程]    同意前事件 %d 条：采集类 %d 种类型，外发 %d 次（%d 个地址）"
                 % (len(pre), len(collected), sinks["before_consent"],
                    len(sinks["before_hosts"])))

        # 栈要取**与结论相关的那批事件**的，不能取 pre 的前几条 ——
        # 否则"同意前外发"这条结论下面挂的是建表的栈（SQLiteDatabase.execSQL），
        # 人工一看就对不上，等于证据作废。
        # 「收集了哪几类」这条结论的栈改由 CMP.stacks_by_type() 逐类取
        # （见下），sink 那条结论（"向外发起连接"）另按 K1 事件取。
        # 结论是「向外部发起网络连接」，栈就必须取网络外发（K1）那批的。
        # sink 还有 K2 持久化（写库/写文件）、K3 日志，它们的栈挂在这里
        # 会让人看不懂——"说联网，怎么给的是建表的堆栈"。
        pre_sink = [e for e in pre if CMP._is_sink(e)
                    and (getattr(e, "sink", "") == "K1"
                         or "network" in (getattr(e, "category", "") or ""))]
        stacks_of = lambda evs: [s for s in                       # noqa: E731
                                 (list(getattr(x, "stack", []) or []) for x in evs[:6]) if s]

        # ---- 只有「取到了有效值」的类型才能进结论主句 ----
        # ★ 久趣课堂 2026-10-30 实测：collected 里有「传感器信息」（2 次接口
        #   调用），但一个取值都没取到。describe_collected(only_with_value=True)
        #   会把这类整条跳过，于是主句变成「App 已收集。」——宾语是空的，
        #   却照样判了"发现问题·确证"。没有取值就没有"收集了什么"这回事，
        #   这类只能进事实表的"另见接口调用"，不能进认定。
        _valued = {k: v for k, v in collected.items()
                   if any((m.get("values") or [])
                          for m in (v.get("members") or {}).values())}
        _stk, _no_stack = (CMP.stacks_by_type(_valued, pre, limit=4,
                                             device_ids=self.fr.device_identities)
                           if _valued else ([], []))
        _has_stack = any(bool(s) for s in _stk)
        if _valued:
            # 取到了有效值 = 可作为认定依据。这是全流程最硬的一条结论。
            # ★ 必须写清「到底是哪一个标识符、取到的值是什么、哪个接口取的、
            #   发生在同意之前第几秒」。只写「收集了设备标识符」没法复核 ——
            #   人工拿到报告第一件事就是问「是 IMEI 还是 Android ID」。
            #
            # ★ 口径（2026-10-27 用户意见）：不要再写「本次共记录到同意前行为
            #   68 次」——这个数把联网、写库、读配置都混在一起，看不出严重程度。
            #   要的是「每一类采集行为各发生多少次」，所以次数挂在类型上（with_count）。
            names = CMP.describe_collected(_valued, with_count=True)
            calls_only = CMP.describe_calls_only(collected)
            _cms = getattr(self.scan, "consent_elapsed_ms", None)
            _n_ev = sum(int(v.get("count") or 0) for v in collected.values())
            facts = [["采集类事件合计",
                      "%d 次（%d 类，各类次数见上）" % (_n_ev, len(collected))],
                     ["证据等级",
                      "已取到有效值（确证）" if names else "仅见接口调用，未取得取值"]]
            # 取值类型不是靠方法名猜的：开测前已记录本机真实标识，逐条比对过。
            # 这一行是给复核员看的"标尺从哪来"，否则「凭什么说它不是 IMEI」没法答。
            _div = (self.fr.device_identities or {}).get("values") or {}
            if _div:
                facts.append([
                    "机器标识比对基准",
                    "本次检测已记录测试机真实 %s；表中每一类标识符均与该基准逐值比对，"
                    "名称后标注「与测试机真实值一致」的才是比对命中，"
                    "取不到真实值的标识符（如 OAID）只按取值形态推断"
                    % "、".join(_DIDS_LABELS.get(k, k) for k in _div)])
            for row in CMP.collected_facts(collected, _cms):
                facts.append([row[0], "%s：%s" % (row[1], row[2])])
                if row[3]:
                    facts.append(["　调用点与时刻", row[3]])
            if calls_only:
                # 只有接口调用、没取到取值的类型：写明它，但不进主句、不进认定。
                facts.append(["另见接口调用（未取得取值）", calls_only])
            # ★ 栈按"描述里出现的类型"逐类取，不能按事件顺序取前三条 ——
            #   西五街那轮描述了三类，栈却是两个 getRunningAppProcesses
            #   加一个 getAndroidId，两类根本没有对应证据。
            if _no_stack:
                facts.append(["无可用调用栈的类型",
                              "、".join(_no_stack) + "（仅见接口调用，未取得取值）"])
            # ★ 有取值但一条栈都没有 → 不能认定（久趣课堂 2026-10-30 用户第 5 条）。
            #   取证逻辑上「谁读的」与「读了什么」缺一不可：只有取值，无法排除
            #   是系统/预装组件或采集侧自身读到的。这种情形降为疑似并写明缺口。
            if not _has_stack:
                facts.append(["本项未认定的原因",
                              "取到了取值，但本轮未捕获到任何调用栈，"
                              "无法确认该读取由被测应用（或其内嵌 SDK）发起；"
                              "按证据不足降为疑似，需人工结合沙箱精检复核"])
                self._set(
                    "Q002", SUSPECT, phase="P1", level="中", confidence="疑似",
                    desc=_p1_pre + "观测到%s的读取，"
                         "但未捕获到调用栈，无法确认由被测应用发起，"
                         "未认定为「未经用户同意收集」，需人工复核" % names,
                    evidence=[Evidence("frida", "同意前收集 %d 次" % len(pre), names, "P1")],
                    facts=facts, stacks=[])
                self._set(
                    "Q003", SUSPECT, phase="P1", level="中", confidence="疑似",
                    desc="观测到%s的读取且发生在同意之前，但缺少调用栈，"
                         "无法认定「未经同意收集」，需人工复核" % names,
                    evidence=[Evidence("frida", "同意前收集", names, "P1")],
                    facts=facts, stacks=[])
            else:
                self._set(
                    "Q002", FAIL, phase="P1", level="高", confidence="确证",
                    desc=_p1_pre + "App 已收集%s" % names,
                    evidence=[Evidence("frida", "同意前收集 %d 次" % len(pre), names, "P1",
                                       {"types": {k: v["count"] for k, v in collected.items()},
                                        "members": {k: v.get("members", {})
                                                    for k, v in collected.items()}})],
                    facts=facts,
                    stacks=_stk,
                )
                self._set("Q003", FAIL, phase="P1", level="高", confidence="确证",
                          desc="用户在未同意隐私政策的情况下，App 已实际收集%s" % names,
                          evidence=[Evidence("frida", "同意前收集", names, "P1")],
                          facts=facts,
                          stacks=_stk[:2])
        elif collected_edge or edge_pre:
            # ★ 只在「同意动作前后」观测到收集，时序不可分辨 —— 不能定罪。
            #   简小知实测：android_id 读取比同意早 9ms，调用栈还是
            #   AgreementDialog.onConfirm（点同意之后的回调链）。
            #   这种情形下写"未经用户同意收集"，结论就是错的。
            #   如实写成"发生在同意动作前后、时序不可分辨"，交人工决定。
            _ename = CMP.describe_collected(collected_edge, with_count=True) or "个人信息"
            _n_edge = len(edge_pre)
            _n_strict = len(pre)
            facts = [["时序不可分辨的事件", "%d 条" % _n_edge],
                     ["确证在同意前的事件", "%d 条" % _n_strict],
                     ["同意时刻", ("冷启动后 %.1f ms" % _cms) if _cms
                      else "未记录（本轮捕获到同意动作，但未能定位到时刻）"]]
            for row in CMP.collected_facts(collected_edge, _cms):
                facts.append([row[0], "%s：%s" % (row[1], row[2])])
                facts.append(["　调用点与时刻", row[3]])
            # 栈里能看到"同意回调链"这条线索时，要把它作为判定依据写出来，
            # 否则复核员不理解为什么这次不判违规。
            if any(CMP.looks_like_consent_action(e) for e in edge_pre):
                facts.append(["判定依据",
                             "调用栈显示该读取位于用户点击「同意」后的回调链中"
                             "（如 AgreementDialog.onConfirm），"
                             "与同意时刻相差 %d ms 以内，无法认定为未经同意收集"
                             % (CMP.CONSENT_EDGE_MS)])
            # ★ 没有同意时刻时**不能**说"1500 ms 窗口内"（会凭空造出一个窗口）。
            #   只有"捕获到同意动作但没定位到时刻"这一种情形会走到这里。
            if _cms:
                _edge_desc = ("首次打开 App，本次在同意动作前后 %d ms 窗口内观测到%s的读取"
                              "（时序不可分辨：读取与同意事件的上报通道存在延迟差，"
                              "且调用栈显示位于同意回调链中）；"
                              "确证发生在同意之前的事件为 %d 条，未取得有效个人信息取值。"
                              "该项需人工结合录屏或加大同意前静置时长复核"
                              % (CMP.CONSENT_EDGE_MS, _ename, _n_strict))
                _edge_ev = "边界窗口内收集（时序不可分辨）"
            else:
                _edge_desc = ("首次打开 App，本轮捕获到「同意」动作，但未记录到同意时刻，"
                              "因此无法判断这些%s的读取发生在同意之前还是之后"
                              "（时序不可分辨）；确证发生在同意之前的事件为 %d 条，"
                              "未取得有效个人信息取值。该项需人工结合录屏复核"
                              % (_ename, _n_strict))
                _edge_ev = "同意动作前后收集（时刻未记录，时序不可分辨）"
            self._set(
                "Q002", SUSPECT, phase="P1", level="中", confidence="疑似",
                desc=_edge_desc,
                evidence=[Evidence("frida", _edge_ev,
                                   "%d 条" % _n_edge, "P1")],
                facts=facts,
                stacks=CMP.stacks_by_type(collected_edge, edge_pre, limit=3,
                                          device_ids=self.fr.device_identities)[0],
            )
            self._set("Q003", SUSPECT, phase="P1", level="中", confidence="疑似",
                      desc=(("同意动作前后存在%s的读取，但时序不可分辨，"
                             "无法认定为「未经用户同意收集」，需人工复核" % _ename)
                            if _cms else
                            ("存在%s的读取，但同意时刻未记录、无法分辨先后，"
                             "未认定为「未经用户同意收集」，需人工复核" % _ename)),
                      evidence=[Evidence("frida", "边界窗口内收集", _ename, "P1")],
                      facts=facts)
        elif sinks["before_consent"]:
            # ★ 只观测到"同意前发起了网络连接"，**没有抓包**。
            #   用户明确要求：监测不到对外发了什么，就不要拿外发行为当关注点。
            #   所以这里不再判「疑似」——「发起连接」推不出「传了个人信息」，
            #   凭空出一条疑似就是编造。连接地址与次数照实留给人工，
            #   结论标"跳过未测"并写明缺的是哪一步（抓包）。
            hosts = "、".join(list(sinks["before_hosts"])[:6])
            self._set(
                "Q002", NOT_TESTED, phase="P1",
                reason=_p1_pre + "观测到向 %s 等 %d 个地址"
                       "发起网络连接共 %d 次；本轮未部署流量监测，未取得传输内容，"
                       "无法判断是否上传了个人信息，因此不对「同意前已开始收集」下结论。"
                       "如需认定，应以抓包或沙箱精检方式复核"
                       % (hosts, len(sinks["before_hosts"]), sinks["before_consent"]),
                evidence=[Evidence("traffic", "同意前发起网络连接 %d 次"
                                   % sinks["before_consent"],
                                   hosts, "P1", {"hosts": sinks["before_hosts"]})],
                facts=[["同意前发起网络连接", "%d 次" % sinks["before_consent"]],
                       ["涉及地址", hosts],
                       ["本项观测范围", "仅记录连接目标地址，未记录传输内容"
                                        "（未部署流量监测，不判断是否传输个人信息）"]],
                stacks=stacks_of(pre_sink)[:2],
            )
            # Q003（是否已实际取得取值）也要在这里给出结论：否则它会落到
            # 检查表兜底的"缺少阶段 P3 的证据"上 —— 而真相是"只有连接、没有取值"，
            # 与同意后遍历跑没跑无关。
            self._set(
                "Q003", NOT_TESTED, phase="P1",
                reason="本轮仅在未同意状态下观测到向 %s 等 %d 个地址发起网络连接 %d 次，"
                       "未取得任何个人信息取值；且未部署流量监测，无法判断连接中"
                       "是否携带个人信息，因此不对「已实际取得取值」下结论"
                       % (hosts, len(sinks["before_hosts"]), sinks["before_consent"]),
                facts=[["同意前发起网络连接", "%d 次" % sinks["before_consent"]],
                       # ★ 必须限定「同意前」（2026-11-19 贝利实测）：
                       #   同一张事实表里还会出现「同一交互内采集：设备标识 4 条」，
                       #   只写"个人信息取值 未取得"会读成整轮都没取到值。
                       ["同意前个人信息取值", "未取得"],
                       ["本项观测范围", "仅记录连接目标地址与次数，未记录传输内容"]])
        else:
            # ★「没观测到」不等于「没问题」（简小知实测）：
            #   采集器目前只做静置观察，不会去点按钮、翻页面。如果这轮压根没
            #   主动触发过，判 pass 就是在说"这个 App 干净"—— 而真相是
            #   "我们没有去看"。这两件事在报告里必须分开写，否则复核员
            #   会照着"未发现问题"的结论签字。做了主动探索的轮次才判 pass。
            if explored:
                # ★ 数字必须现算，不能写死 0（2026-11-18 真机撞到）：
                #   1 档驿站助手同意前有 2 条事件（读时区），被 `_SYS_SETTING_PI`
                #   判为"不是个人信息"—— 这个结论没错，但报告写"同意前事件数
                #   0 条"就与存档对不上了，复核员一对数就发现报告在说假话。
                #   口径：写**行为事件**的真实条数，再说明"均未取到有效取值"。
                _n_pre_all = len(pre) + len(edge_pre)
                self._set("Q002", PASS, phase="P1", confidence="确证",
                          desc="冷启动至用户同意隐私政策期间，在已执行的%s中，"
                               "均未观测到个人信息收集行为" % _explore_desc,
                          evidence=[Evidence("frida",
                                             "同意前事件 %d 条，均未取到有效个人信息取值（%s）"
                                             % (_n_pre_all, _explore_desc), "", "P1")],
                          facts=[["同意前事件数",
                                  ("%d 条（均未取到有效个人信息取值）" % _n_pre_all)
                                  if _n_pre_all else "0 条"],
                                 ["未同意状态交互探索", _explore_desc],
                                 ["结论边界", "仅覆盖本轮已触发的界面，未触发的路径不在结论范围内"]])
                # ★ Q003 必须给出自己的结论（2026-11-18）：它问的是"有没有
                #   实际取得取值"，与 Q002（有没有收集行为）不是一回事。
                #   不 set 的话会落到兜底的"缺少阶段 P3 的证据"—— 而 P3 在
                #   1 档本来就不执行，等于用一句错的原因掩盖了"没取到值"。
                #   顺序上它在 `_merge_pre_consent_perms()` 之前，后者若有
                #   同意前索权，会把这个「未测」改成「发现问题」。
                self._set(
                    "Q003", NOT_TESTED, phase="P1",
                    reason=("本轮在未同意状态下共观测到 %d 条行为事件，"
                            "但没有一条取到有效个人信息取值；证据等级不足以认定"
                            "「已实际取得」，同样不足以认定「未取得」%s"
                            % (_n_pre_all,
                               "；本档位不执行同意动作与界面遍历，"
                               "未触发的路径不在结论范围内" if _absent else "")),
                    facts=[["未同意状态事件数", "%d 条" % _n_pre_all]])
            else:
                # ★ 措辞必须和存档对得上（自设捏脸第 4 轮教训）：
                #   这一支的真实语义是"观测到了行为，但没取到有效取值"，
                #   不是"什么都没看到"。早先写死"同意前事件 0 条""本轮未触发过"，
                #   而存档里其实有 44 条同意前事件 —— 复核员一对数就会看到
                #   报告与证据自相矛盾。数字一律从本轮事件里现算，不写死的句子。
                _n_all = len(pre) + len(edge_pre)
                if _absent:
                    # 1 档：本轮没有同意动作，谈不上"同意之前/之后"，只有"未同意状态"。
                    if explored:
                        _nt_reason = ("本轮未执行「同意」动作（全程处于未同意状态），"
                                      "在%s的过程中共观测到 %d 条行为事件，"
                                      "但没有一条取到有效个人信息取值，也未观测到外发，"
                                      "证据等级不足以认定「已收集」，"
                                      "同样不足以认定「未收集」；"
                                      "未触发的界面路径不在结论范围内。"
                                      "如需认定，应扩大未同意状态下的探索范围后复测"
                                      % (_explore_desc, _n_all))
                        _nt_scope = _explore_desc
                    else:
                        _nt_reason = ("本轮未执行「同意」动作（全程处于未同意状态），"
                                      "共观测到 %d 条行为事件，但没有一条取到有效个人信息取值，"
                                      "也未观测到外发，证据等级不足以认定「已收集」，"
                                      "同样不足以认定「未收集」；此外本轮未能在未同意状态下"
                                      "点击界面（%s），未触发的界面路径不在结论范围内。"
                                      "如需认定，应在未同意状态下主动遍历后复测"
                                      % (_n_all, _pe.get("why") or "未进入探索阶段"))
                        _nt_scope = "0 步（未能点到界面元素）"
                    _nt_facts = [["未同意状态事件数", "%d 条" % _n_all],
                                 ["同意动作", "本轮未执行（1 档「仅同意前」口径）"]]
                elif _cms:
                    _nt_reason = ("本轮在同意之前共观测到 %d 条行为事件（时序可分辨 %d 条、"
                                  "落在同意动作前后 %d ms 内因而无法分辨先后的 %d 条），"
                                  "但没有一条取到有效个人信息取值，也未观测到同意前外发，"
                                  "证据等级不足以认定「已收集」同样不足以认定「未收集」；"
                                  "此外本轮未在未同意状态下执行主动交互探索，"
                                  "未触发的界面路径不在结论范围内。需在未同意状态下主动遍历后复测"
                                  % (_n_all, len(pre), CMP.CONSENT_EDGE_MS, len(edge_pre)))
                    _nt_scope = "0 步（本轮仅静置观察）"
                    _nt_facts = [["同意前事件数", "%d 条（时序可分辨 %d 条 / 不可分辨 %d 条）"
                                  % (_n_all, len(pre), len(edge_pre))]]
                else:
                    _nt_reason = ("本轮捕获到「同意」动作，但未记录到同意时刻，"
                                  "共观测到 %d 条行为事件而无法分辨先后，"
                                  "且没有一条取到有效个人信息取值、未观测到外发，"
                                  "证据等级不足以认定「已收集」同样不足以认定「未收集」；"
                                  "此外本轮未在未同意状态下执行主动交互探索，"
                                  "未触发的界面路径不在结论范围内。需人工结合录屏复核"
                                  % _n_all)
                    _nt_scope = "0 步（本轮仅静置观察）"
                    _nt_facts = [["行为事件数", "%d 条（同意时刻未记录，先后不可分辨）"
                                  % _n_all]]
                self._set("Q002", NOT_TESTED, phase="P1",
                          reason=_nt_reason,
                          evidence=[Evidence("frida", "同意前事件 %d 条，均未取到有效取值"
                                             % _n_all, "", "P1")],
                          facts=_nt_facts + [
                                 ["证据等级", "仅命中调用，未取到有效取值（不足以认定）"],
                                 ["未同意状态交互探索", _nt_scope]])
                # Q003 同理：不写的话会落到"缺少阶段 P3 的证据"，
                # 而 P3 在 1 档本来就是不执行的阶段。
                # ★ 措辞必须限定「同意之前」（2026-11-19）：点击同意后 1.5 秒内
                #   往往就有读 Android ID 之类的事件，只写"本轮未取得任何取值"
                #   会被读成整轮什么都没采到 —— 与同一交互事实行自相矛盾。
                self._set("Q003", NOT_TESTED, phase="P1",
                          reason=("本轮在同意之前未取得任何个人信息取值，"
                                  "无法认定「已实际取得个人信息」，也无法认定「未取得」%s"
                                  % ("；本档位不执行同意动作与界面遍历，"
                                     "未触发的路径不在结论范围内" if _absent else "")),
                          facts=_nt_facts)
        # ★ 三条用户口径的收尾（2026-11-18 / 11-19），顺序不能反：
        #   ① 先合并"同意前索权"：它可能把 Q003 从 PASS / 未测 改成"发现问题"；
        #   ② 再补"尝试获取未成功"：只往事实表加一行，绝不改状态；
        #   ③ 最后补"同一交互内采集"：同样只加事实行，绝不改状态。
        self._merge_pre_consent_perms()
        self._append_p1_attempts(pre)
        # ③ 最后补"同意点击后同一交互内的采集"：只往事实表加一行，绝不改状态。
        #    放在最后是因为前两步可能把 Q003 改成"发现问题"，而这一行无论如何
        #    都要出现 —— 报告不能因为"已经判了违规"就把其余现象省略掉。
        self._append_consent_sync()
        self._end(pr, M.PHASE_DONE)
        return pr

    # ================================================================== P2
    def _first_launch_no_notice(self, cap: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """首启全程观测到"应用压根没有任何隐私政策提示"吗？是则返回证据，否则 None。

        ★ 为什么单独判（用户 2026-11-09 第 4 条，船务通）：
          「这个 app 是不是压根就没有首启弹窗让用户同意隐私政策的过程啊？我觉得
           如果判断压根就没有隐私政策，应该指出来，并且在「1. 未公开收集使用规则」
           的检测项进行判定。」
          属实：船务通 7 冷启动后 18s~90s 连续 5 屏都是同一个网页首页（60 条文字、
          2015 字，可读），没有任何弹窗，也没有任何政策字样，直接可用。

        ★ 这类结论最容易变成假话，所以判据全部是**可核对的硬条件**：
          · 亲眼确认过前台切到了被测应用（`app_foreground_seen`）；
          · 首启阶段**没有**出现过政策弹窗、没有同意动作、没有入口文本；
          · 首启界面确实读到了文字（而不是一片空白/读不出来）—— 且这些文字里
            **没有任何**政策关键词；
          · 观测窗口 ≥20 秒且至少 2 屏；
          · 首启着陆确实到了主页面（说明应用已经可用，不是卡在启动页）；
          · 遍历阶段跑过（这样"应用内也没有入口"才是查过的）。
        任一条不满足就返回 None，退回"跳过未测"并写清原因 —— 宁可写"没测到"，
          也绝不能把"我们没看见"写成"应用没有"。
        """
        sc = self.scan
        if sc is None:
            return None
        if not getattr(sc, "app_foreground_seen", False):
            return None
        if getattr(sc, "first_launch_popup", False) or getattr(sc, "consent_given", False):
            return None
        if (cap.get("bestText") or "").strip() or cap.get("entryClicked"):
            return None
        if (cap.get("entryTexts") or []):
            return None
        landing = getattr(sc, "landing", None)
        if not (isinstance(landing, dict) and landing.get("reached_home")):
            return None
        marks = getattr(sc, "marks", None) or {}
        if not isinstance(marks, dict) or not marks.get("walk_start"):
            return None
        t0 = marks.get("app_launched")
        t1 = marks.get("landing_start") or marks.get("walk_start")
        if t0 is None or t1 is None:
            return None
        try:
            # marks 的单位是**毫秒**（与 P1/P3 的耗时换算一致，见 _REAL_SPANS）
            secs = (float(t1) - float(t0)) / 1000.0
        except Exception:
            return None
        if secs < 20:
            return None
        screens = [s for s in (getattr(sc, "screens", None) or [])
                   if isinstance(s, dict)
                   and str(s.get("label") or "").startswith("首启界面")
                   and "未到前台" not in str(s.get("label") or "")]
        if len(screens) < 2:
            return None
        readable = [s for s in screens if (s.get("texts") or [])]
        if not readable:
            return None
        words = ("隐私政策", "隐私协议", "隐私权政策", "个人信息保护",
                 "用户协议", "服务协议", "收集使用规则", "同意")
        for s in readable:
            blob = " ".join(str(x) for x in (s.get("texts") or []))
            for w in words:
                if w in blob:
                    return None
        seq = " → ".join(str(s.get("label") or "") for s in screens[:8])
        return {"secs": secs, "screens": len(screens), "seq": seq,
                "chars": sum(len(" ".join(str(x) for x in (s.get("texts") or [])))
                             for s in readable)}

    def _coverage_caveat(self) -> str:
        """本轮采集是否自己承认过"没走完、不代表应用没有"？有则返回那句话。

        ★ 为什么单拎出来（2026-11-13，对着 40 份人工检测报告复核发现）：
          84 轮里只有两轮判了「未公开收集使用规则（发现问题）」—— 船务通与
          健康深圳。两轮的 `scan_errors` 里都明明白白写着
          "未覆盖部分按「跳过未测」计，不代表应用没有该功能"，
          而人工报告里船务通**是有隐私政策的**（还引用了其中"更正 30 天"的承诺）。

          也就是说，问题不在采集：采集已经诚实地说"我没走完"。问题在判据层
          把"没走完"读成了"不存在" —— 结论比证据强了一档。

          这不是那两单的特例，而是一条普适边界：**否定性结论（"应用没有"）
          必须有充分的探索支撑**。所以本轮只要存在这种自述，就不许判"未公开"，
          降级为"疑似"并把观测到什么、缺什么写清楚。
        """
        for e in (getattr(self.fr, "scan_errors", None) or []):
            s = str(e or "")
            if "不代表应用没有" in s:
                return s
        return ""

    def p2_policy(self) -> PhaseResult:
        pr = self._begin("P2")
        # 政策正文挂在 ScanResult.policy_capture 里（bestText / urls / pageLinks / outcome）。
        # 早先这里写成 getattr(self.scan, "policy", None) —— 字段名不对，
        # 结果明明拿到了 31955 字正文却判「未能取得」，P5 对照整体被跳过。
        cap = getattr(self.scan, "policy_capture", None) if self.scan else None
        cap = cap if isinstance(cap, dict) else {}
        # ★ 旧存档没有 externalOpen 字段（作业帮 2026-10-30 那轮就是）：
        #   但 openSnapshot.focus 里已经存着 `MiuiChooserActivity` —— 那就是
        #   "系统在问用哪个浏览器打开"的铁证。这里补判一次，离线重渲染也能写对。
        if not cap.get("externalOpen"):
            _of = str((cap.get("openSnapshot") or {}).get("focus") or "")
            if _of and _POL.is_external_app_focus(
                    _of, getattr(self.fr, "package", "") or
                    getattr(self.scan, "package", "") or ""):
                cap["externalOpen"] = _of
        text = cap.get("bestText") or cap.get("best_text") or cap.get("text") or ""
        # ★ 结论必须与"手上到底有没有正文"自洽（镜像投屏 2026-11-09）：
        #   首启阶段判了 no_entry，遍历阶段才读到 28879 字，两边都没回头改。
        #   这里统一结算一次，覆盖"正文是后面才补上的"这条路径。
        _POL.settle_outcome(cap)
        urls = cap.get("urls") or []
        page_links = cap.get("pageLinks") or []
        outcome = cap.get("outcome", "")
        # ★ 旧存档里的 "not_run" 多半是假的（2026-11-01 修正的采集侧 bug）：
        #   采集侧曾把 outcome 预置成 not_run，导致末尾的结算永远不执行 ——
        #   只要没走到某个显式赋值分支，最终都记成"本次未执行首启政策捕获"。
        #   看个比赛 2026-10-31 那轮首启观测了 156 秒、还取到了弹窗告知语，
        #   报告却写"未执行首启政策捕获"，等于把"我们没找到"说成"我们没测"。
        #   这里按已有证据补算一次：有 marks.observe_start = 首启真的跑过。
        if str(outcome or "") == "not_run" or not outcome:
            _marks = getattr(self.scan, "marks", None) or {}
            _ran = ("observe_start" in _marks) if isinstance(_marks, dict) else False
            if _ran:
                _bt = len(str(text or "").strip())
                if cap.get("externalOpen") and _bt < 1200:
                    outcome = "external_app"
                elif cap.get("errorPage"):
                    outcome = "error_page"
                elif _bt >= 1200:
                    outcome = "full_inline"
                elif _bt or urls or cap.get("entryClicked") or (
                        cap.get("entryTexts") or []):
                    outcome = "no_text" if cap.get("entryClicked") else "no_entry"
                else:
                    outcome = "no_entry"
                cap["outcome"] = outcome
                if outcome != "not_run":
                    self.fr.notes.append(
                        "政策获取结论已按采集证据复核修正：原记录为「未执行首启"
                        "政策捕获」，但本轮首启观测确实执行过（取到入口文本 %d 条、"
                        "候选链接 %d 个），实际结论为「%s」"
                        % (len(cap.get("entryTexts") or []), len(urls),
                           {"no_entry": "未定位到政策入口",
                            "no_text": "点了入口但未取到条款文本",
                            "full_inline": "取到条款正文",
                            "error_page": "入口打开的是错误页",
                            "external_app": "入口交给系统组件/外部应用",
                            "external_partial": "浏览器内读到部分条款",
                            "external_unverified": "浏览器内读到文字但未认定为政策正文",
                            }.get(outcome, outcome)))
        self.policy_text = text or ""
        self.policy_url = cap.get("bestTextUrl") or ""
        # ★ 采集端按 URL 直取到全文时，来源必须写"按政策链接抓取"，
        #   不能沿用默认的"设备侧页面"。
        #   否则复现步骤④会写成"点《隐私政策》入口，政策页打开并取得正文 N 字"——
        #   而这一轮压根没打开页面，复核员照着做会发现对不上（文档拿错比没测更糟）。
        if cap.get("policyUrlFetched") and self.policy_text:
            self.policy_source = "按政策链接抓取"
        # ★ 类型闸门（以观书法 5.4.2 实测，2026-10-20）：
        #   采集侧已经堵了"非政策文本写进 bestText"，这里再堵一次"采信"——
        #   旧存档、离线重渲染（--from-result）都会绕过采集侧走到这里。
        #   实测那份"政策正文"是 App 自己的课程 H5（1652 字课程列表，全文没有
        #   「隐私」「个人信息」），报告据此判「实际收集设备属性但政策未列明」= 认定。
        #   依据一份连主题都不对的文档下结论，比"没测"更糟：它看起来有证据。
        # ★ 告知语闸门（春雨诊所 359 字 / 高途 279 字，2026-10-30）：
        #   采集侧已经拦了，但旧存档与离线重渲染会绕过采集侧 —— 这里再拦一次。
        #   这两轮报告都写着"已取得政策正文"，实际是首启弹窗那段"请您务必仔细
        #   阅读…"的阅读提示，一条条款都没有。拿它做条款比对，结论全是空的。
        if self.policy_text and _POL.is_notice_summary(self.policy_text):
            _nt = self.policy_text
            # ★ 短文本里也有"自称是什么"的区别（2026-10-30）：
            #   102 字的残页开头就是「用户协议」，把它统一说成"告知语"会误导复核员
            #   —— 报告该说"拿到的是《用户协议》，不是隐私政策"，这样才指得出
            #   取证环节错在哪。只有确实没有其他自称时，才按告知语/阅读提示处理。
            _kind = _POL.classify_doc(_nt, "", self.policy_url)
            if _kind in ("user_agreement", "collection_list", "third_party_list",
                         "permission_list"):
                self.policy_reject_note = (
                    "本轮取得的「政策正文」实为 %d 字的《%s》，不是隐私政策"
                    % (len(_nt), _POL.doc_kind_label(_kind)))
                pr.notes.append("取得的是 %d 字《%s》，不是隐私政策，已排除，"
                                "不作政策依据" % (len(_nt), _POL.doc_kind_label(_kind)))
                cap.setdefault("otherPolicyTexts", []).insert(0, {
                    "url": self.policy_url, "chars": len(_nt),
                    "why": "该正文不是隐私政策（开头为「%s」），未作为政策依据"
                           % _nt.strip()[:20].replace("\n", " "),
                })
                if not self.fr.policy_rejected:
                    self.fr.policy_rejected = {
                        "reason": "该正文是《%s》，不是隐私政策"
                                  % _POL.doc_kind_label(_kind),
                        "chars": len(_nt), "url": self.policy_url,
                    }
                self.policy_text = ""
                self.policy_url = ""
            else:
                if len(_nt) > len((cap.get("noticeText") or "")):
                    cap["noticeText"] = _nt
                self.policy_reject_note = (
                    "本轮取得的「政策正文」实为 %d 字的告知语（首启弹窗上的阅读提示），"
                    "不是政策条款正文" % len(_nt))
                pr.notes.append("取得的是 %d 字告知语，不是政策条款正文，已排除，"
                                "不作政策依据" % len(_nt))
                if not self.fr.policy_rejected:
                    self.fr.policy_rejected = {
                        "reason": "该正文是弹窗告知语（阅读提示），不是政策条款正文",
                        "chars": len(_nt), "url": self.policy_url,
                    }
                self.policy_text = ""
                self.policy_url = ""
        if self.policy_text and not _POL.looks_like_privacy_policy(self.policy_text):
            _bad = self.policy_text
            # 记下"拿错了文件"这件事：报告里必须写清是《用户协议》一类的文本，
            # 而不是含糊的"未能取得政策正文"—— 复核员要能看出问题出在取证环节。
            self.policy_reject_note = ("本轮取得的正文为「%s」一类文本，不是隐私政策"
                                       % _bad.strip()[:20].replace("\n", " "))
            cap.setdefault("otherPolicyTexts", []).insert(0, {
                "url": self.policy_url, "chars": len(_bad),
                "why": "该正文不是隐私政策（开头为「%s」），未作为政策依据"
                       % _bad.strip()[:20].replace("\n", " "),
            })
            if not self.fr.policy_rejected:
                self.fr.policy_rejected = {
                    "reason": "该正文不是隐私政策（开头为「%s」）"
                              % _bad.strip()[:20].replace("\n", " "),
                    "chars": len(_bad), "url": self.policy_url,
                }
            pr.notes.append(
                "设备侧取得的 %d 字正文不是隐私政策，已排除，不作政策依据"
                % len(_bad))
            # 不是政策 ≠ 没用：判得出类型的，正文另存进文档表（共享清单/协议/清单
            # 都是检测要用的直接证据）。判不出类型的仍只在"已排除"里交代一句。
            _dk = _POL.classify_doc(_bad, "", self.policy_url or "")
            if _dk in ("user_agreement", "minor_policy", "collection_list",
                       "third_party_list", "permission_list"):
                self._declined_docs.append({
                    "title": "设备侧读取的《%s》" % _POL.doc_kind_label(_dk),
                    "kind": _POL.doc_kind_label(_dk),
                    "url": self.policy_url or "",
                    "text": _bad,
                    "how": ("按链接抓取：%s —— 该文本**不是隐私政策**，"
                            "仅作该类文档留档核对" % (self.policy_url or "未记录地址")),
                })
            self.policy_text = ""
            self.policy_url = ""
        # 采集期被拒收 / 被顶替的候选正文，带进报告供复核（"看过但不是它"也是结论）
        # ★ 已经作为文档入档的（共享清单那类）不在这张表里重复出现：
        #   一张表写"看过但没用"、另一张表全文摆着，读的人会以为前者没抓到。
        _archived = {(d.get("url") or "") for d in self._declined_docs if d.get("url")}
        _side: List[Dict[str, Any]] = []
        for it in (cap.get("otherPolicyTexts") or []):
            if isinstance(it, dict):
                if (it.get("url") or "") in _archived:
                    continue
                _side.append({"kind": "拒收", "url": it.get("url") or "",
                              "chars": int(it.get("chars") or 0),
                              "why": it.get("why") or ""})
        for it in (cap.get("replacedPolicyTexts") or []):
            if isinstance(it, dict):
                _side.append({"kind": "被顶替", "url": it.get("url") or "",
                              "chars": int(it.get("chars") or 0),
                              "why": "同站点更完整的正文（开头为「%s」）已取代它"
                                     % (it.get("head") or "")})
        self.fr.policy_side_texts = _side

        # ---- 归属核验：这份正文是不是**被测 App 自己**的政策 ----
        # ★ 真机实测（赣警办 P4 深挖）：点进「意见反馈」的腾讯兔小巢页面，
        #   它的《隐私保护指引》14902 字，比 App 自己的政策长得多，于是被当成
        #   App 政策 —— 未成年人专门规则、个性化推荐、SDK 列明这几项的结论
        #   全部变成对第三方 SDK 政策的核查结果。文档拿错，结论必错。
        #   采集侧已经堵了覆盖（见 collector._keep_policy_text），这里是第二道：
        #   离线重渲染 / 旧存档也会走到这里。
        _tp = _POL.third_party_reason(self.policy_text, self.fr.app_name or "",
                                      self.fr.package or "",
                                      url=self.policy_url or "")
        if _tp:
            self.fr.policy_rejected = {
                "reason": _tp,
                "chars": len(self.policy_text),
                "url": self.policy_url,
                "head": self.policy_text[:80],
            }
            pr.warnings.append("设备侧取得的政策正文已排除：%s" % _tp)
            # ★ 排除原因必须一路带到 Q001 的"未测理由"里（用户 2026-10-27 第 1 条）：
            #   否则报告只写"未能取得隐私政策正文"，读的人不知道是"没抓到"
            #   还是"抓错了"，更不知道抓到的其实是谁的政策。
            self.policy_reject_note = "已排除本轮取得的正文：%s" % _tp
            self.policy_text = ""
            self.policy_url = ""

        # ---- 第二个来源：本次提交时给的政策正文 / 链接 ----
        # 平台表单里「隐私政策全文」写着"优先级最高"，但这条链路此前根本没接通
        # （JobOptions 连字段都没有）：用户粘了一整篇政策，走的还是空正文，
        # 报告最后写成"未能取得隐私政策正文"。
        # 服务器部署（没有设备、抓不到首启弹窗）时这是**唯一**的政策来源，
        # 所以这里必须显式、优先，并且把"以哪一份为准"写进备注。
        _provided = self.user_policy_text
        if _provided:
            if self.policy_text and self.policy_text.strip() != _provided:
                pr.notes.append(
                    "设备侧另取得正文 %d 字；按提交时提供的正文（%d 字）为准"
                    % (len(self.policy_text), len(_provided)))
            self.policy_text = _provided
            self.policy_source = "提交时提供的正文"
        elif not self.policy_text and self.user_policy_url:
            _t = self._fetch_policy_from_url(self.user_policy_url, pr)
            if _t:
                self.policy_text = _t
                self.policy_url = self.user_policy_url
                self.policy_source = "按提交的链接抓取"

        # ---- 政策正文的第二个来源：APK 内置文档 ----
        # 真机实测（自设捏脸 / uni-app）：政策入口是弹窗告知语里的内联链接
        # （「你可阅读《服务协议》和《隐私政策》了解详细信息」），
        # UI 上连点 5 个采样点都没反应，最终只拿到 322 字的弹窗告知摘要 ——
        # 而 APK 里 assets/apps/__UNI__CA2D8BF/www/hybrid/html/private.html
        # 就是 **23064 字**的政策全文，正是 App 弹窗要展示的那一份。
        # 只认在线抓取会把这类 App 全判成"未取得政策"，
        # 于是政策类检测项集体"跳过未测"—— 明明证据在手上。
        #
        # 取舍：UI 正文足够长（≥1200 字）时以 UI 为准（那是用户当场看到的内容，
        # 也可能是最新版本）；否则回退到内置文档，并如实标注来源与提取路径。
        bpath, btext = self._builtin_policy()
        self.policy_builtin = {}
        # 提交时给了正文就以它为准：那是使用者明确指定的那一份，
        # 不该被 APK 里可能过期的内置副本顶掉。
        if btext and not _provided and len(btext) > len(self.policy_text):
            if self.policy_text:
                pr.notes.append(
                    "UI 侧仅取得 %d 字的弹窗告知摘要；政策正文改由 APK 内置文档提供"
                    "（%s，%d 字）" % (len(self.policy_text), bpath, len(btext)))
                self.ui_policy_chars = len(self.policy_text)
            self.policy_text = btext
            self.policy_builtin = {"path": bpath, "chars": len(btext)}

        # ---- 第三个来源：APK 里登记的政策链接（界面入口打不开时）----
        # 只有在"使用者没主动提供、内置文档也没有"时才走这里。
        # 实测（以观书法 5.4.2）：弹窗入口点击命中不稳定，这轮 5 个采样点全部落空；
        # 而 APK 里登记的 https://app.ygsf.com/privacy.html 是可访问的真政策。
        if not _provided and not self.policy_text:
            self._fetch_policy_from_apk_links(pr)
        docs: List[Dict[str, str]] = []
        for d in (page_links or []):
            if isinstance(d, dict):
                docs.append(d)
                if d.get("text"):
                    self.sdk_texts.append(d["text"])
            elif isinstance(d, str):
                docs.append({"url": d})
        self.policy_docs = docs
        pr.evidence = {
            "policy_chars": len(self.policy_text),
            "docs": len(self.policy_docs),
            "urls": urls,
            "page_links": len(page_links),
            "outcome": outcome,
            "entry_source": cap.get("entrySource", ""),
            # 正文到底来自哪儿：设备抓取 / 提交时提供 / 按提交链接抓 / APK 内置。
            # 复核员必须能一眼判断"这份是不是用户当时看到的那一份"。
            "policy_source": self.policy_source or ("APK 内置文档" if self.policy_builtin
                                                    else ("设备抓取" if self.policy_text else "")),
        }
        # 采信的那份政策的网址，单独落进存档：对外版报告只有这一句"政策在哪"，
        # 它此前一直取不到（FlowResult 没有这个字段，渲染器只能去 rows.links 里猜，
        # 猜到的常是界面来源标签）。只认 http(s)，内置文档没有网址就留空。
        if str(self.policy_url or "").lower().startswith("http"):
            self.fr.policy_url = self.policy_url
        pr.steps = ["定位政策入口", "读取政策正文", "追查共享清单链接"]
        for u in (urls or []):
            if isinstance(u, dict):
                self.fr.link_inventory.append({
                    "url": u.get("url", ""),
                    "title": u.get("title", "") or u.get("from", ""),
                    "kind": "隐私政策候选链接",
                })
            elif isinstance(u, str):
                self.fr.link_inventory.append({"url": u, "title": "", "kind": "隐私政策候选链接"})
        for d in docs:
            self.fr.link_inventory.append({
                "url": d.get("url", ""),
                "title": d.get("title", "") or d.get("kind", ""),
                "kind": "政策内下钻链接",
            })

        if not self.policy_text:
            _why = "未能取得隐私政策正文"
            _note = getattr(self, "policy_reject_note", "")
            if _note:
                _why += "（%s）" % _note
            # ★ 「压根没有首启告知」必须判成**发现问题**，不能只写"跳过未测"
            #   （用户 2026-11-09 第 4 条，船务通）。两者的区别很大：
            #   "跳过未测"读起来是"我们没测到"，而事实是"应用启动后直接进主界面，
            #   从头到尾没有任何隐私政策提示" —— 这正是《认定方法》第一条
            #   「未通过弹窗等明显方式提示用户阅读隐私政策」的情形。
            #   但也不能反向冤枉：只有在**亲眼看着应用起来、看到了界面、走到了
            #   主页面，且全程没有任何政策字样**时才认定。任何一环不确定
            #   （没到前台/界面读不出来/遍历没跑）都退回"跳过未测"并写清原因。
            _nonotice = self._first_launch_no_notice(cap)
            if _nonotice:
                # ★ 结论强度不能超过证据强度（2026-11-13 复核 40 份人工报告后补）：
                #   船务通、健康深圳两轮都判了"未公开"，但这两轮的 scan_errors 里
                #   明明写着"未探索部分……不代表应用没有该功能"。人工报告复核：
                #   船务通是有隐私政策的（报告里还引用了其中 30 天的更正时限）。
                #   采集侧已经诚实地说"没走完"，判据层不能把"没走完"读成"不存在"。
                _caveat = self._coverage_caveat()
                if _caveat:
                    self._end(pr, M.PHASE_DONE,
                              "首启未见政策提示，但本轮覆盖不全，按疑似处理")
                    _cov = getattr(self.fr, "coverage", None) or {}
                    self._set(
                        "Q001", SUSPECT, phase="P2",
                        confidence="首启观测成立，遍历覆盖不足",
                        desc=("冷启动后连续观测 %.0f 秒、%d 个界面，未出现任何弹窗或"
                              "首屏提示要求用户阅读隐私政策，直接进入主界面。但本轮"
                              "遍历没有走完（已进入 %d 个界面、点击 %d 次，尚有 %d 个"
                              "入口未探索），因此不足以认定应用「未公开收集使用规则」"
                              "—— 政策入口可能就在未探索到的路径里。按疑似处理，"
                              "需人工复核应用内是否存在政策入口。"
                              % (_nonotice["secs"], _nonotice["screens"],
                                 int(_cov.get("app_states") or 0),
                                 int(_cov.get("taps") or 0),
                                 int(_cov.get("unexplored") or 0))),
                        evidence=[Evidence("ui", "首启观测界面序列",
                                           _nonotice["seq"], "P1"),
                                  Evidence("note", "覆盖不足的原始记录",
                                           _caveat[:300], "P4")],
                        facts=[["首启观测时长", "%.0f 秒" % _nonotice["secs"]],
                               ["观测到的界面数", "%d 屏" % _nonotice["screens"]],
                               ["是否出现隐私政策字样", "未出现（含「隐私」「协议」相关字样）"],
                               ["遍历覆盖", "已进入 %d 个界面、点击 %d 次，未探索入口 %d 个"
                                % (int(_cov.get("app_states") or 0),
                                   int(_cov.get("taps") or 0),
                                   int(_cov.get("unexplored") or 0))],
                               ["为何不定为发现问题", "覆盖不全：%s" % _caveat[:160]],
                               ["结论依据", "否定性结论需要充分探索；本轮未走完，不能据此认定"]])
                    return pr
                self._end(pr, M.PHASE_DONE,
                          "首启未见任何隐私政策提示（已观测 %.0fs，%d 屏）"
                          % (_nonotice["secs"], _nonotice["screens"]))
                self._set(
                    "Q001", FAIL, phase="P2", confidence="首启全程观测，未见任何提示",
                    desc=("冷启动后连续观测 %.0f 秒、%d 个界面，应用未以任何弹窗或"
                          "首屏提示的方式提示用户阅读隐私政策，直接进入主界面；"
                          "遍历阶段也未在应用内找到隐私政策入口。据《App违法违规"
                          "收集使用个人信息行为认定方法》第一条，属于「未公开收集"
                          "使用规则」"
                          % (_nonotice["secs"], _nonotice["screens"])),
                    evidence=[Evidence("ui", "首启观测界面序列",
                                       _nonotice["seq"], "P1")],
                    facts=[["首启观测时长", "%.0f 秒" % _nonotice["secs"]],
                           ["观测到的界面数", "%d 屏" % _nonotice["screens"]],
                           ["是否出现隐私政策字样", "未出现（含「隐私」「协议」相关字样）"],
                           ["是否出现同意动作", "未出现（应用未要求同意即进入主界面）"],
                           ["遍历覆盖", "已进入 %d 个界面、点击 %d 次，未探索入口 %d 个"
                            % (int((getattr(self.fr, "coverage", None) or {}).get("app_states") or 0),
                               int((getattr(self.fr, "coverage", None) or {}).get("taps") or 0),
                               int((getattr(self.fr, "coverage", None) or {}).get("unexplored") or 0))],
                           ["遍历阶段是否找到政策入口", "未找到"],
                           ["结论依据", "首启全程无人为遮挡，界面结构树可正常读取"]])
                for qid in ("Q005", "Q006", "Q007", "Q008", "Q009",
                            "Q013", "Q014", "Q015", "Q016"):
                    st = self._item(qid)
                    if st.state == NOT_TESTED:
                        st.reason = "应用未公开收集使用规则（未见隐私政策），无政策文本可比对"
                return pr
            self._end(pr, M.PHASE_FAILED, _why)
            # ---- ★ 「有入口、点了、页面打不开」→ 疑似（用户 2026-11-10 第 1 条）----
            #   这四单（EV投屏/电视投屏/易投屏/中医针灸）的共同特征：首启弹窗里
            #   确实有《隐私政策》链接，点下去也确实跳转了，但页面显示"网页无法打开"。
            #   它既不是"没有入口"（不能记跳过未测），也不足以直接认定（可能是
            #   网络波动、服务器临时故障），按"疑似"处理并写清可复核的现场。
            #
            #   ★ 但**测试机断网时绝不能走到这里**：那样 4 条结论都会变成对应用的
            #     指控，而真实原因是测试环境。采集侧已把这种情形单列成
            #     `offline_unverified`，这里再守一道。
            _oc_now = str(cap.get("outcome") or "")
            _off = bool(cap.get("deviceOffline")) or _oc_now == "offline_unverified"
            if not _off:
                # 旧存档里没有 `deviceOffline` 这个字段，但错误清单写着"测试机无网络" ——
                # 不认这一条，历史存档重渲染时会把断网轮次判成"应用的链接坏了"。
                try:
                    _errs = " ".join(str(e) for e in (getattr(self.scan, "errors", None) or []))
                except Exception:
                    _errs = ""
                if ("无网络" in _errs or "没有网络" in _errs) and not cap.get("bestText"):
                    _off = True
            _page_err = str(cap.get("errorPage") or cap.get("pageErrorRaw") or "")
            # ★ 「点了、但不知道点中哪个」必须写明（2026-11-10 铁路火车票真机）：
            #   入口文案是「已阅读并同意\n《用户协议》及《隐私政策》」——
            #   同意表述与协议链接压在同一行，点击后应用直接进了主界面
            #   （定格观测：ScreenAct → MainActivity，界面 0 字）。这一击很可能是
            #   点中了"同意"而不是协议链接。
            #   这种情形两头都不能写：不能写"应用未提供政策"（它提供了），
            #   也不能写"政策页打不开"（我们从未真正打开过它）。
            _ent_txt = str(cap.get("entryClicked") or "")
            if "《" in _ent_txt and "同意" in _ent_txt:
                _why += ("；首启弹窗中的入口文案「%s」把同意表述与协议链接放在同一行，"
                         "点击后应用直接进入主界面，无法确认这一击是否落在协议链接上"
                         "（既不能据此认定应用未提供政策，也不能认定政策页不可访问）"
                         % " ".join(_ent_txt.split())[:48])
            if _off:
                self._set(
                    "Q001", NOT_TESTED, phase="P2",
                    reason=("测试机在采集期间无网络，政策页无法加载，**这不是应用的问题**，"
                            "本轮无法判断其隐私政策是否可正常查阅；需在联网环境下重跑"))
                for qid in ("Q005", "Q006", "Q007", "Q008", "Q009",
                            "Q013", "Q014", "Q015", "Q016"):
                    st = self._item(qid)
                    if st.state == NOT_TESTED:
                        st.reason = ("测试机无网络，未取得政策正文，无法比对；"
                                     "该轮涉网结论需联网重跑后才能给出")
                return pr
            if _oc_now == "error_page" or (_page_err and cap.get("entryClicked")):
                _entry_txt = (cap.get("entryLabel")
                              or (cap.get("entryTexts") or [""])[0]
                              or "隐私政策")
                _url = ""
                for _u in (urls or []):
                    _uu = _u.get("url") if isinstance(_u, dict) else str(_u)
                    if str(_uu or "").startswith("http"):
                        _url = str(_uu)
                        break
                self._end(pr, M.PHASE_DONE,
                          "政策入口存在且可点击，但打开的是错误页（%s）"
                          % (_page_err or "页面无法显示"))
                self._set(
                    "Q001", SUSPECT, phase="P2",
                    confidence="入口可点、页面不可访问（未取得条款正文）",
                    desc=("首启弹窗中提供了隐私政策入口「%s」，点击后确实发生了页面"
                          "跳转，但打开的页面显示「%s」，未能取得任何条款正文。"
                          "应用提供了政策链接这一点是明确的，用户能否实际查阅到"
                          "收集使用规则仍存疑；按《App违法违规收集使用个人信息行为"
                          "认定方法》第一条，疑似「未公开收集使用规则」，"
                          "需人工在联网环境下复核该链接是否长期不可用"
                          % (str(_entry_txt)[:30], (_page_err or "网页无法打开"))),
                    evidence=[Evidence("ui", "政策入口点击后的页面",
                                       "入口「%s」→ 页面提示「%s」"
                                       % (str(_entry_txt)[:30], _page_err or "无法显示"),
                                       "P2")],
                    facts=[["首启弹窗中的政策入口", str(_entry_txt)[:40]],
                           ["入口是否可点击", "是（点击后前台页面已切换）"],
                           ["点击后页面显示", _page_err or "网页无法打开"],
                           ["取得的条款正文", "0 字"],
                           ["实际加载地址", _url or "未捕获（页面未完成加载）"],
                           ["测试机网络", "在线（已排除断网导致）"],
                           ["认定为「疑似」而非「发现问题」的原因",
                            "链接客观存在且可点，页面打不开也可能是服务端临时故障；"
                            "需人工复核该地址是否长期不可用后再认定"]])
                for qid in ("Q005", "Q006", "Q007", "Q008", "Q009",
                            "Q013", "Q014", "Q015", "Q016"):
                    st = self._item(qid)
                    if st.state == NOT_TESTED:
                        st.reason = ("未取得政策条款正文（入口打开的是错误页），"
                                     "无法比对；该页需人工复核")
                return pr
            self._set("Q001", NOT_TESTED, phase="P2",
                      reason=_why + "，无法判断是否公开收集使用规则")
            for qid in ("Q005", "Q006", "Q007", "Q008", "Q009",
                        "Q013", "Q014", "Q015", "Q016"):
                st = self._item(qid)
                if st.state == NOT_TESTED:
                    st.reason = _why
            # ★ Q007 不能因为"没拿到政策"就什么也不交。
            #   实测到的第三方外发地址是**独立于政策文本**的证据，
            #   复核员拿它照样能去人工核对接收方，丢掉等于白采一趟。
            _hosts: List[str] = []
            for s in (getattr(self.scan, "network_sinks", None) or []):
                h = (s.get("host") if isinstance(s, dict) else str(s)) or ""
                if h and h not in _hosts:
                    _hosts.append(h)
            if _hosts:
                _st7 = self._item("Q007")
                _st7.reason = (_why + "，无法在政策中检索接收方名称、联系方式与共享目的；"
                               "但本轮实测到应用运行期连接到 %d 个第三方地址"
                               "（仅记录目标地址，未记录传输内容），可据此人工核对"
                               % len(_hosts))
                _st7.facts = [["运行期连接到的第三方地址", "、".join(_hosts[:10])],
                              ["本项观测范围", "仅记录连接目标地址，未记录传输内容"
                                               "（未部署流量监测，不判断传输内容）"],
                              ["本项未下结论的原因",
                               _note or "未取得政策正文/SDK 清单，无处检索接收方信息"]]
                _st7.evidence = [Evidence("traffic", "运行期连接到的第三方地址",
                                          "、".join(_hosts[:10]), "P5")]
            return pr

        # ---- 模型深读政策正文（分段抽取）----
        # 为什么要有这一步：P5 的「声明范围」原本只靠关键词匹配，
        # "我们会收集设备识别码"能配上，但"为保障账号安全，我们可能获取
        # 您设备的唯一硬件编号"就配不上 → 真声明被判成未声明 → Q006 误报。
        # 分段抽取让长政策每一段都真被读过（小上下文模型不会静默截尾），
        # 结果在 P5 与关键词结果取并集。
        # 失败不影响流程：AI 是能力增强，不是运行前提。
        self.ai_policy = {}
        if self.ai_tasks is not None:
            t0 = time.time()
            data: Optional[Dict[str, Any]] = None
            try:
                ret = self.ai_tasks.analyze_policy(
                    self.policy_text, app_label=self.fr.app_name or "")
                if ret is not None and getattr(ret, "ok", False):
                    data = ret.data or None
                    if not data:
                        pr.notes.append("政策深读返回空结果，P5 只用关键词口径")
                elif ret is not None and getattr(ret, "error", ""):
                    pr.notes.append("政策深读未成功：%s" % ret.error)
            except Exception as e:                       # noqa: BLE001
                pr.notes.append("政策深读异常：%s" % e)
            if data:
                self.ai_policy = data
                cost = time.time() - t0
                cov = float(data.get("_coverage", 1.0) or 1.0)
                n_types = len(data.get("declared_types") or [])
                n_docs = len(data.get("third_party_docs") or [])
                n_cancel = len(data.get("cancel_account") or [])
                pr.notes.append(
                    "AI 深读政策：声明类型 %d 项、第三方文档 %d 份、注销路径 %d 条；"
                    "覆盖 %.0f%%（共 %d 段，失败 %d 段），耗时 %.0fs"
                    % (n_types, n_docs, n_cancel, cov * 100,
                       int(data.get("_chunks_total") or 1),
                       int(data.get("_chunks_failed") or 0), cost))
                pr.evidence["ai_declared_types"] = n_types
                pr.evidence["ai_coverage"] = round(cov, 3)
                pr.evidence["ai_third_party_docs"] = n_docs
                pr.evidence["ai_cancel_paths"] = n_cancel
                pr.steps.append("AI 深读政策正文")
                # 模型在政策正文里找到的关联文档/共享清单：UI 侧往往一个都没
                # 下钻到（本机实测 0 份），但有链接的那些是复核员能直接点开的
                # 一手材料，全部留在链接清单里，别让 86 秒白跑。
                seen_links = {x.get("url") for x in self.fr.link_inventory}
                for d in (data.get("third_party_docs") or []):
                    u = _fix_link(str(d.get("url") or ""))
                    if not u.lower().startswith("http") or u in seen_links:
                        continue
                    seen_links.add(u)
                    self.fr.link_inventory.append({
                        "url": u,
                        "title": str(d.get("title") or "")[:120],
                        "kind": "政策正文中的第三方/关联文档（模型读出）",
                    })
                self.log("[流程]    AI 深读政策：声明类型 %d 项，覆盖 %.0f%%，耗时 %.0fs"
                         % (n_types, cov * 100, cost))

        self.log("[流程]    政策正文 %d 字，下钻文档 %d 份"
                 % (len(self.policy_text), len(self.policy_docs)))

        # ---- 留给人工复核员的政策材料 ----
        # 报告里最该留的是「能直接点开核对的链接」。判据说"政策未列明 XX"，
        # 复核员必须能自己打开那份政策看一眼 —— 只给结论不给链接，
        # 这条结论就没法验，等于白测。
        # 界面侧正文的地址：只认真地址，标签（"政策页面文本（滚动后）"）不算。
        _ui_url = str(cap.get("bestTextUrl") or "")
        if not _ui_url.lower().startswith("http"):
            _ui_url = ""
        if self.policy_builtin:
            self.fr.policy_refs.append({
                "title": "隐私政策（APK 内置文档）",
                "kind": _POL.doc_kind_label(_POL.classify_doc(self.policy_text)),
                # 安装包内路径不是网址，不能放进 url（渲染时会被当成可点链接）。
                # 路径在 how 与 facts 里写清楚，复核员解包即可对照。
                "url": "",
                "path": self.policy_builtin.get("path", ""),
                "chars": len(self.policy_text),
                "text": self.policy_text[:200000],
                "how": "自安装包内提取：%s —— App 首启弹窗展示的政策即读取该文件，"
                       "解包后可直接打开核对（无需联网、无需登录）"
                       % self.policy_builtin.get("path", ""),
                "excerpt": self._excerpt(self.policy_text),
            })
            if self.ui_policy_chars:
                # ★ 标题必须与采集事实一致（金考典 2026-10-28）：
                #   844 字是**政策页**读到的文本（入口已打开），不是弹窗上那段
                #   128 字告知语。旧标题把两者混成一个"告知摘要"，
                #   复核员会以为 App 弹窗写了 844 字 —— 与截图对不上。
                _entered_ui = bool((cap.get("openSnapshot") or {}).get("entered"))
                self.fr.policy_refs.append({
                    "title": ("政策页界面读到的文本（UI 运行时抓取，不完整）"
                              if _entered_ui else "首启弹窗告知摘要（UI 运行时抓取）"),
                    "kind": ("政策页界面文本" if _entered_ui else "首启弹窗告知摘要"),
                    # ★ 只放真地址（金考典 2026-10-28）：这里原来放的是
                    #   cap["bestTextUrl"]，而它可能是界面收割的来源标签
                    #   （"政策页面文本（滚动后）"），渲染出来就是一条
                    #   `file:///…/政策页面文本（滚动后）` 的死链。
                    "url": _ui_url,
                    "chars": self.ui_policy_chars,
                    "text": (cap.get("bestText") or "")[:20000],
                    "how": (("入口已打开（前台页面已切换），界面侧只渲染出 %d 字；"
                             "完整正文取自安装包内同一份文档，两者开头一致，"
                             "可逐段对照") % self.ui_policy_chars) if _entered_ui
                           else ("首启弹窗内直接读取，仅 %d 字告知语，非政策条款全文；"
                                 "两相对照可确认弹窗展示的政策与内置文档是同一份"
                                 % self.ui_policy_chars),
                    "excerpt": "",
                })
        else:
            # 没有 http 地址时把**为什么没有**一并带给报告层（2026-11-09 Q船）。
            # 否则简版只能写"本次未记录到可访问地址"，读的人会以为采集器漏了；
            # 实际最常见的原因是应用把 HTML 直接交给 WebView（about:blank），
            # 或者读本地资源文件 —— 那种情况链本来就不存在。
            _url_why = _POL.no_url_reason(cap) if not _ui_url else ""
            self.fr.policy_refs.append({
                "title": "隐私政策（正文）",
                "kind": _POL.doc_kind_label(_POL.classify_doc(self.policy_text)),
                "url": _ui_url,
                "url_note": _url_why,
                "chars": len(self.policy_text),
                "text": self.policy_text[:200000],
                "how": "App 首启弹窗内《%s》入口点开后，从 WebView 渲染完成的正文中读取"
                       % self._plain(cap.get("entryClicked") or "隐私政策"),
                "excerpt": self._excerpt(self.policy_text),
            })
        # ---- 把「本轮读到的所有声明文档」逐份列出来（用户 2026-10-28 意见）----
        # 隐私政策 / 用户协议 / 未成年人规则 / 收集清单 / 共享清单，四类都有用：
        #   · 「是否逐一列明接收方」要看共享清单，不是看隐私政策；
        #   · 「未成年人专门规则」要看未成年人政策；
        #   · 用户协议常是 App 把收集规则写错地方的去处。
        # 旧做法只列"政策正文 + 弹窗摘要"，其余文档要么不显示、要么混在
        # 「采集期看到的其他长文本（均未用作政策依据）」里 —— 复核员会以为没抓到。
        def _add_ref(title: str, kind: str, url: str, text: str, how: str,
                     path: str = "") -> None:
            body = (text or "").strip()
            if not body:
                return
            key = (kind, re.sub(r"\s+", "", body)[:60])
            for r in self.fr.policy_refs:
                if (r.get("kind"), re.sub(r"\s+", "", (r.get("text") or "") or
                                          (r.get("excerpt") or ""))[:60]) == key:
                    return
            self.fr.policy_refs.append({
                "title": title, "kind": kind,
                "url": url if str(url or "").lower().startswith("http") else "",
                "path": path, "chars": len(body), "text": body[:200000],
                "how": how, "excerpt": self._excerpt(body),
            })

        # ① 安装包内置的各类文档（金考典：assets/privacy.htm + assets/agreement.htm）
        # ★ 同一类只留最长那一份：Hi投屏 有 vivo/lenovo/tengxun/ali/huawei/oppo/url
        #   七份内容几乎相同的厂商定制政策副本，全列出来会把这张表灌满，
        #   复核员反而找不到该看哪一份。份数另用一句话交代。
        _by_kind: Dict[str, List[Dict[str, Any]]] = {}
        for a in ((self.fr.static or {}).get("policy_assets") or []):
            if not isinstance(a, dict) or a.get("role") == "prompt_config":
                continue
            _t = str(a.get("text") or "").strip()
            if len(_t) < 300 or _POL._text_quality(_t) < 0.98:
                continue
            _by_kind.setdefault(_POL.classify_doc(_t, ""), []).append(a)
        for _k, _items in _by_kind.items():
            _items.sort(key=lambda a: -(len(str(a.get("text") or ""))))
            _a = _items[0]
            _t = str(_a.get("text") or "").strip()
            _extra = ("" if len(_items) <= 1 else
                      "；安装包内另有 %d 份同类文档（内容相近的厂商定制副本），已省略"
                      % (len(_items) - 1))
            _add_ref("内置文档：%s" % _POL.doc_kind_label(_k), _POL.doc_kind_label(_k),
                     "", _t,
                     "自安装包内提取：%s —— 解包后可直接打开核对（无需联网、无需登录）%s"
                     % (_a.get("path") or "", _extra), path=str(_a.get("path") or ""))
        # ② 运行期按链接 / 界面取到的文档
        for d in (cap.get("documents") or []):
            if not isinstance(d, dict):
                continue
            _add_ref(d.get("title") or _POL.doc_kind_label(d.get("kind") or ""),
                     d.get("kind_label") or _POL.doc_kind_label(d.get("kind") or ""),
                     (d.get("urls") or [d.get("url") or ""])[0] if d.get("urls")
                     else (d.get("url") or ""),
                     d.get("text") or "", d.get("how") or "界面读取")
        # ②' 判得出类型、但被排除在"政策正文"之外的那份（Hi投屏 /protocol/share）
        for d in self._declined_docs:
            _add_ref(d.get("title") or d.get("kind") or "设备侧文档",
                     d.get("kind") or "文档", d.get("url") or "",
                     d.get("text") or "", d.get("how") or "按链接抓取")
        # ③ 政策正文里下钻到的关联文档
        for d in (self.policy_docs or []):
            _t = d.get("text") or ""
            _add_ref(d.get("title") or d.get("kind") or "政策内链接",
                     _POL.doc_kind_label(_POL.classify_doc(_t, d.get("title") or "",
                                                           d.get("url") or "")),
                     d.get("url", ""), _t, "政策正文内嵌链接，运行时下钻读取")

        # 政策拿到了，说明「公开了收集使用规则」—— 但完整性和准确性要等 P5
        if self.policy_builtin:
            # 政策全文来自安装包而非 UI —— 入口点不开这件事本身就是事实，
            # 不能因为"正文在手"就把它抹掉：用户侧的观感是"点不动"。
            #
            # ★ 措辞必须与采集期实测一致（Hi投屏 2026-10-26 用户意见）：
            #   旧文案硬编码"点击 5 处采样点均未触发页面跳转"，而那一轮
            #   报告里同时还挂着一张标题为「政策页滚动第 1 屏」的截图 ——
            #   其实那是开屏弹窗，三张图字节完全相同。没进政策页就是没进，
            #   既不能写成"政策页打开并取得正文"，也不该留一张假的政策页图。
            _snap = (cap.get("openSnapshot") or {}) if isinstance(cap, dict) else {}
            _entered = bool(_snap.get("entered"))
            _sig = str(_snap.get("tapSignal") or "")
            if _entered:
                _try_txt = ("已进入政策页（前台页面已切换），但 UI 侧取得的正文"
                            "仅 %d 字，不足 %d 字，改以安装包内置文档为准"
                            % (self.ui_policy_chars, POLICY_MIN_CHARS))
            elif self.policy_shot_note:
                # 这一轮的字节指纹已经证明"没进政策页"——比任何信号都硬。
                _try_txt = ("点击入口后并未进入政策页（采集存档中标注为「政策页」的"
                            "截图与首启弹窗逐字节相同，说明当时仍停留在弹窗上），"
                            "未取得政策页正文")
            elif _sig == "ui":
                _try_txt = ("点击入口后前台页面未切换，仅界面内容有变化"
                            "（可能是在同一弹窗内展开或滚动），未取得政策页正文")
            elif _snap and "tapSignal" in _snap:
                _try_txt = ("点击入口后前台页面未切换、界面也无变化"
                            "（框内各采样点均无响应），未取得政策页正文")
            elif _snap:
                # 旧存档：只有 focus/textLen，没有点击信号 —— 那就如实写"没记录"，
                # 不能替它编一句"各采样点均无响应"（没记过的事不能说）。
                _try_txt = ("采集存档只记录了点击后的前台页面（%s）与文字长度，"
                            "未记录点击信号，无法据存档判断入口是否响应该次点击，"
                            "也未取得政策页正文" % (_snap.get("focus") or "未记录"))
            else:
                _try_txt = "本次未在弹窗上点开政策入口，未取得政策页正文"
            # ★ 不能无条件写"首启弹窗虽展示《隐私政策》入口文字"（金考典 2026-10-27）：
            #   那一轮首启观测根本没取到界面（加固包冷启动 70s 才到前台），
            #   弹窗、入口文案、可点性全都没观测过，却印了这句话，
            #   读报告的人会以为我们看见过入口。
            _entry_txt = str(cap.get("entryClicked") or "").strip()
            if not _entry_txt:
                _et = [str(x).strip() for x in (cap.get("entryTexts") or []) if str(x).strip()]
                _entry_txt = _et[0] if _et else ""
            _popup_seen = bool(getattr(self.scan, "first_launch_popup", False)) \
                if self.scan is not None else False
            if _popup_seen:
                _popup_txt = ("首启弹窗%s，%s"
                              % (("展示了隐私政策入口「%s」" % _entry_txt) if _entry_txt
                                 else "未读到隐私政策入口文字", _try_txt))
            else:
                _popup_txt = ("本轮首启观测没有取到首启界面（详见「目标应用启动状态」与"
                              "界面覆盖表），因此「首启弹窗里有没有隐私政策入口、入口能不能"
                              "点开」本次<b>未核实</b>；正文仅来自安装包内文档")
            src = ("App 随包提供隐私政策全文（%d 字），已自安装包提取核查；%s。"
                   % (len(self.policy_text), _popup_txt))
            self._set("Q001", PASS, phase="P2", confidence="政策文本确证",
                      desc=src,
                      evidence=[Evidence("policy", "APK 内置政策全文 %d 字" % len(self.policy_text),
                                         (self.policy_text[:120] + "…"), "P2")],
                      facts=[["政策正文", "%d 字（APK 内置：%s）"
                              % (len(self.policy_text), self.policy_builtin.get("path", ""))],
                             ["首启弹窗入口文案", str(cap.get("entryClicked") or "—")],
                             ["弹窗入口可点性", _try_txt],
                             ["UI 侧另取得", "%d 字弹窗告知摘要" % self.ui_policy_chars
                              if self.ui_policy_chars else "—"]],
                      # 内置路径不是网址，不能进 links：渲染成 <a href> 会让人
                      # 以为"政策 URL 抓错了"。路径已在上面的 facts 里写明。
                      links=[])
            self.log("[流程]    ★ 政策正文来源：APK 内置文档 %s（%d 字）"
                     % (self.policy_builtin.get("path", ""), len(self.policy_text)))
        elif self.scan is None or self.policy_source:
            # 正文来自「提交时提供 / 按链接抓取」，或本轮根本没有设备观测：
            # 不能写"App 在首启弹窗中提供了隐私政策入口" —— 入口可点性没验过。
            # 这句话一旦印进报告，复核员会以为入口可点性已经验过。
            # 只认定手上真有的那一半：正文存在，且其中对收集使用规则作了说明。
            #
            # ★ 但"做了设备观测"与"没做设备观测"必须分开写。
            #   按 URL 直取正文之后（用户 2026-10-21 第一条），采集端跳过的是
            #   「点开政策页并滑动阅读」这一整段，首启观测**照常执行**
            #   （弹窗、同意动作、界面序列都采到了）。此前一律写
            #   "本轮未执行设备侧首启观测"，与同一份报告里的同意分水岭、
            #   界面覆盖表直接打架 —— 复核员不知道该信哪一句。
            _cap = (getattr(self.scan, "policy_capture", None) or {}) if self.scan else {}
            _screens = list(getattr(self.scan, "screens", None) or []) if self.scan else []
            _dev_obs = bool(
                (self.scan is not None)
                and (getattr(self.scan, "first_launch_popup", False)
                     or getattr(self.scan, "consent_given", False)
                     or str(_cap.get("entryClicked") or "").strip()
                     or any(str(s.get("label") or "").startswith("首启界面")
                            and "未到前台" not in str(s.get("label") or "")
                            for s in _screens if isinstance(s, dict))))
            if _dev_obs:
                _tail = ("；本轮执行了设备侧首启观测（同意动作与界面序列已采集），"
                         "但政策正文是按链接直接取得的，未在弹窗上点开政策页，"
                         "故该入口在 App 内的可点性未实测，需人工在真机确认")
            else:
                _tail = ("；但本轮未执行设备侧首启观测，该入口在 App 内的"
                         "展示位置与可点性未核实，需人工在真机确认后再作最终结论")
            self._set("Q001", PASS, phase="P2", confidence="政策文本确证",
                      desc="本轮取得隐私政策正文 %d 字（来源：%s），其中对收集使用规则"
                           "作了公开说明%s"
                           % (len(self.policy_text),
                              self.policy_source or "提交时提供的正文", _tail),
                      evidence=[Evidence("policy", "隐私政策正文 %d 字" % len(self.policy_text),
                                         (self.policy_text[:120] + "…"), "P2")],
                      facts=[["政策正文", "%d 字" % len(self.policy_text)],
                             ["正文来源", self.policy_source or "提交时提供的正文"],
                             ["访问链接", self.policy_url or "（未记录）"],
                             ["入口可点性",
                              "未实测（本轮未在弹窗上点开政策页，正文按链接取得）"
                              if _dev_obs else "未核实（本轮未做设备侧首启观测）"],
                             # 只有 0 份时说明为什么是 0：正文由链接直接抓取，
                             # 没有展开页内的"共享清单/子政策"链接。不写这句，
                             # 复核员会以为追过但一份都没追到（两件事差很远）。
                             ["下钻文档", ("%d 份" % len(self.policy_docs)) if self.policy_docs
                              else "0 份（本轮只取正文，未展开政策页内的共享清单/子政策链接）"]],
                      links=[self.policy_url or ""])
        else:
            self._set("Q001", PASS, phase="P2", confidence="确证",
                      desc="App 在首启弹窗中提供了隐私政策入口，且可正常访问（取得正文 %d 字）"
                           % len(self.policy_text),
                      evidence=[Evidence("policy", "隐私政策正文 %d 字" % len(self.policy_text),
                                         (self.policy_text[:120] + "…"), "P2")],
                      facts=[["政策正文", "%d 字" % len(self.policy_text)],
                             ["访问链接", cap.get("bestTextUrl")
                              or (_POL.no_url_reason(cap) or "（未记录）")],
                             ["入口文案", str(cap.get("entryClicked") or "—")],
                             ["下钻文档", "%d 份" % len(self.policy_docs)]],
                      links=[cap.get("bestTextUrl") or ""])
        self._end(pr, M.PHASE_DONE)
        return pr

    # ================================================================== P3
    def p3_consent(self) -> PhaseResult:
        pr = self._begin("P3")
        if self.scan is None:
            self._end(pr, M.PHASE_SKIPPED, "本次未执行设备动态采集")
            return pr
        given = bool(getattr(self.scan, "consent_given", False))
        src = getattr(self.scan, "consent_source", "") or ""
        at = getattr(self.scan, "consent_elapsed_ms", None)
        recs = list(getattr(self.scan, "consent_events", None) or [])
        strength = getattr(self.scan, "consent_strength", "") or ""
        ws = next((r for r in recs if r.get("watershed")), None)
        # 事件流里的分水岭标记（与 consent_events 互为佐证，缺一个就是登记断了）
        marker = [e for e in (getattr(self.scan, "events", None) or [])
                  if getattr(e, "signal", "") == "CONSENT"]
        pr.evidence = {"consent_given": given, "source": src, "elapsed_ms": at,
                       "strength": strength, "candidates": len(recs),
                       "watershed": ws or {}, "marker_events": len(marker)}
        pr.steps = [
            "点击同意（登记点：首启弹窗 / 政策下钻 / 遍历调度 / 脚本观测，命中即记）",
            "同意时刻写入事件流作为「同意前 / 同意后」分水岭",
            "开始记录同意后行为",
        ]
        if not given:
            if self._consent_absent():
                # 1 档：不点同意是**设计如此**，不是"没测到"。写成告警会让
                # 复核员以为漏采了一次同意动作，进而怀疑同意前的时序结论。
                pr.steps = ["本档位（1 档·仅同意前）：取到政策正文后结束，"
                            "不执行「同意」动作"]
                self._end(pr, M.PHASE_SKIPPED,
                          "本档位不执行同意动作，无「同意后」阶段")
                return pr
            pr.warnings.append("本次未捕获到「同意」动作，同意前/后的时间边界不确定")
            self._end(pr, M.PHASE_PARTIAL, "未捕获到同意事件")
            return pr

        if ws:
            pr.steps.append(
                "分水岭：冷启动后 %.1fs 点击「%s」（%s，强度：%s%s）"
                % ((ws.get("elapsed_ms") or 0) / 1000.0, ws.get("label") or "",
                   ws.get("via") or "", ws.get("strength_label") or strength,
                   "" if ws.get("verified", True) else "，界面变化未确证"))
        if len(recs) > 1:
            others = [r for r in recs if not r.get("watershed")]
            pr.steps.append("另有 %d 次同意类点击未改分水岭（分界只认第一条）：%s"
                            % (len(others),
                               "、".join("「%s」" % (r.get("label") or "?")
                                        for r in others[:3])))
        if not marker:
            # given=True 却没有分水岭事件 = 登记链断了一半，时间线会缺一个锚点。
            # 不静默：这是可以自查出来的内部不一致，写出来比糊过去强。
            pr.warnings.append(
                "已认定用户同意，但事件流中缺少分水岭标记，时间线的同意边界不可定位")
        if ws and ws.get("sync") not in ("ok", "not_applicable"):
            pr.warnings.append(
                "同意状态未同步到采集脚本（%s），脚本侧上报的事件其「同意前/后」"
                "标记可能与实际不符，本报告的时序结论需人工复核" % ws.get("sync"))
        self.log("[流程]    同意事件：%s（第 %.1fs，强度=%s，候选 %d 条）"
                 % (src, (at or 0) / 1000.0, strength or "未记录", len(recs)))
        self._end(pr, M.PHASE_DONE)
        return pr

    # ================================================================== P4
    def p4_post_consent(self) -> PhaseResult:
        pr = self._begin("P4")
        if self.scan is None:
            self._end(pr, M.PHASE_SKIPPED, "本次未执行设备动态采集")
            for qid in ("Q012", "Q013", "Q014", "Q015", "Q016", "Q020",
                        "Q022", "Q023", "Q011", "Q017", "Q019", "Q026"):
                st = self._item(qid)
                if st.state == NOT_TESTED:
                    st.reason = "本次未执行设备动态采集与界面遍历"
            return pr
        evs = [e for e in getattr(self.scan, "events", []) or []]
        post = [e for e in evs if not getattr(e, "before_consent", False)
                and not getattr(e, "noise", "")]
        sinks = getattr(self.scan, "network_sinks", None) or []
        pr.evidence = {"post_events": len(post), "sinks": len(sinks)}
        pr.steps = ["同意后功能遍历", "记录权限申请与信息填报场景", "截图备用"]
        self.log("[流程]    同意后有效事件 %d 条，外发去向 %d 个" % (len(post), len(sinks)))

        # 同意后仍在收集 → 是否超出授权范围，要等 P5 对照政策才知道，这里只记事实
        collected = CMP.collected_types(post, device_ids=self.fr.device_identities)
        if collected:
            names = "、".join(v["name"] for v in collected.values())
            self.fr.notes.append(
                "同意后仍观测到收集行为：%s（是否超出政策声明范围见 P5 对照结论）" % names)
        # 超频次：同一接口单位时间内触发次数异常
        # ★ 只能数**个人信息读取类**事件（自设捏脸第 4 轮实测）：
        #   早先把同意后事件按接口名一股脑计数，Top1 出来是
        #   SQLiteDatabase.insert×24 —— 那是**本地留存**，属"数据去向"，
        #   不是"读取个人信息的权限调用"。拿它支撑
        #   「超出最低必要频率调用个人信息权限」，复核员一查就知道不对题。
        #   sink（本地留存 / 外发数据）是去向下落，永远不能当"收集频次"用。
        freq: Dict[str, int] = {}
        for e in post:
            cat = (getattr(e, "category", "") or "").lower()
            if cat.endswith("_sink"):
                continue
            k = getattr(e, "api", "") or getattr(e, "hook_id", "")
            freq[k] = freq.get(k, 0) + 1
        hot = sorted(freq.items(), key=lambda kv: -kv[1])[:5]
        if hot and hot[0][1] >= 20:
            # 「高频调用」这条同样是采集行为，必须回答是谁在反复调用 ——
            # 自研代码轮询 vs SDK 心跳，整改手段完全不同。
            _hot_api = hot[0][0]
            _hot_evs = [e for e in post
                        if (_hot_api in ((getattr(e, "api", "") or ""),
                                         (getattr(e, "hook_id", "") or "")))]
            self._set("Q011", SUSPECT, phase="P4", level="中",
                      desc="同意后「%s」在本次检测中被调用 %d 次，是否超出实现功能所需的最低必要频率需人工结合业务场景复核"
                           % (hot[0][0], hot[0][1]),
                      evidence=[Evidence("frida", "高频调用", "%s×%d" % (hot[0][0], hot[0][1]), "P4")],
                      facts=[["调用频次 Top5", "；".join("%s×%d" % kv for kv in hot)]],
                      stacks=[s for s in (list(getattr(e, "stack", []) or [])
                                          for e in _hot_evs[:3]) if s])
        else:
            # 「没命中」也要把观测数据写出来。只留一句"未取得充分证据"，
            # 复核员分不清是"没超频"还是"压根没测"。
            top = "；".join("%s×%d" % kv for kv in hot) or "无有效调用记录"
            # 1 档没有"同意后"阶段，不能写成"同意后未达阈值"——那是把没观测说成观测过。
            _scope = ("本轮未执行「同意」动作（无同意后阶段），未同意状态下观测到的"
                      if self._consent_absent() else "本轮同意后")
            self._item("Q011").reason = (
                "%s各接口调用次数均未达高频阈值（Top5：%s），"
                "未出现单位时间内异常高频调用。如需更严格的结论（例如后台静默高频采集），"
                "应延长采集时段或提高采样密度" % (_scope, top))
        # ---- 权限申请场景 → Q026（申请权限/收集敏感信息时是否同步告知目的）----
        # 这一项此前从未真正判过，报告里恒为"未捕获到权限弹窗"。
        # 采集侧现在逐次记录：申请了哪个权限、弹窗原文、弹窗**之前**那一屏写了什么。
        scenes = list(getattr(self.scan, "perm_scenes", None) or [])
        if scenes:
            # ★ 旧存档没有 `evidable` 字段（2026-11-10 铁路火车票那轮就是这样）：
            #   采集侧在 errors 里写了"权限弹窗「定位信息」出现时被测应用已不在前台…
            #   不作为证据"，但场景里没留标记，判定层照旧拿它判了 pass。
            #   这里按**权限名**把那条否定对回场景 —— 不按顺序、不猜，只认同名。
            _errs_txt = " ".join(str(e) for e in (getattr(self.scan, "errors", None) or []))
            for _sc in scenes:
                if "evidable" in _sc:
                    continue
                _pn = str(_sc.get("perm") or "").strip()
                if _pn and ("权限弹窗「%s」出现时" % _pn) in _errs_txt:
                    _sc["evidable"] = False
            # 文本层读不到"同屏浮窗"（系统弹窗是独立窗口，dump 只导最顶层），
            # 所以在落判**之前**用截图视觉补一次证：读到了就当 banner 证据用。
            # 视觉不可用（没配模型/没开开关）时原样返回，判定退回文本判据。
            scenes = self._enrich_perm_scenes(scenes)
            j = PERM.judge(scenes, getattr(self.scan, "screens", None) or [])
            self.fr.perm_scenes = j.get("scenes") or []
            _st26 = self._set(
                "Q026", j["state"], phase="P4", level="中",
                desc=j.get("desc") or "", reason=j.get("reason") or "",
                confidence=("确证" if j["state"] == M.FAIL else
                            ("疑似" if j["state"] == M.SUSPECT else "")),
                facts=j.get("facts") or [],
                evidence=[Evidence("ui", "权限申请场景",
                                   "、".join("%s(%s)" % (s.get("perm") or "未知",
                                                         s.get("purpose") or "证据不足")
                                            for s in self.fr.perm_scenes[:8]), "P4")])
            # 未同意阶段就申请权限：按用户 2026-11-18 口径并入 Q003 认定，
            # 这里只留一行指引。不能再把同一行为写成 Q012 的一行事实 ——
            # Q012 判的是"权限与当前功能是否匹配"，把时间维度塞进去会让
            # 同一件事在两个问题项下各出现一次，复核员无法判断以哪个为准。
            _pre = CMP.pre_consent_perm_requests(
                self.fr.perm_scenes or [],
                getattr(self.scan, "events", None))
            if _pre:
                self._item("Q012").facts.append([
                    "未同意阶段的权限申请",
                    "已并入 Q003「未经用户同意收集使用个人信息」认定，"
                    "本项不重复判定（本项只判权限与当前功能是否匹配）"])
            self.log("[流程]    权限申请场景 %d 个（已说明目的 %d、未说明 %d、证据不足 %d）→ %s"
                     % (len(self.fr.perm_scenes), j["stats"].get("explained", 0),
                        j["stats"].get("silent", 0), j["stats"].get("unclear", 0),
                        M.STATE_LABELS.get(j["state"], j["state"])))
        self._end(pr, M.PHASE_DONE)
        return pr

    # ================================================================== P5
    def p5_compare(self) -> PhaseResult:
        pr = self._begin("P5")
        if not self.policy_text:
            self._end(pr, M.PHASE_SKIPPED, "无政策正文，无法做对照")
            return pr
        evs = [e for e in getattr(self.scan, "events", []) or []] if self.scan else []
        hosts = []
        for s in (getattr(self.scan, "network_sinks", None) or []):
            h = ((s or {}).get("host") or (s or {}).get("target") or "").strip()
            # 采集侧解析不出主机名时会填占位串，直接拿去比对会在报告里
            # 写出「检测到向 (未解析) 等 1 个第三方地址外发数据」这种句子。
            if not h or h in ("(未解析)", "?", "-", "unknown", "N/A"):
                continue
            if "." not in h and not h.replace(".", "").isdigit():
                continue            # 既不是域名也不是 IP，不要
            hosts.append(h)
        try:
            # 栈里识别出的第三方 SDK 作为**第二条证据链**送进对照：
            # 域名法只能抓到"往哪儿发"，抓不到"用了谁的 SDK"；
            # 而「未列明第三方 SDK」这一项的判定对象恰恰是后者。
            _obs_sdk = ATTR.sdk_specs(
                [list(getattr(e, "stack", []) or []) for e in evs],
                self.fr.package or "")
            res = CMP.analyze(evs, [self.policy_text], self.sdk_texts, hosts,
                              ai=self.ai, log=self.log,
                              ai_policy=self.ai_policy or None,
                              observed_sdks=_obs_sdk,
                              device_ids=self.fr.device_identities)
        except Exception as e:
            self._end(pr, M.PHASE_FAILED, "对照分析异常：%s" % e)
            return pr
        self.fr.gaps = res
        pr.evidence = res.get("stats", {})
        pr.steps = ["行为映射为个人信息类型", "解析政策声明范围", "求差集", "AI 复核同义表述"]
        if self.ai_policy:
            pr.steps.insert(2, "并入模型深读的声明类型")
        self.log("[流程]    收集类型 %d / 声明类型 %d（关键词 %d + 模型补充 %d）/ "
                 "差集 %d（复核后 %d）"
                 % (res["stats"]["collected_types"], res["stats"]["declared_types"],
                    res["stats"].get("declared_types_kw", 0),
                    res["stats"].get("declared_ai_extra", 0),
                    res["stats"]["gap_raw"], res["stats"]["gap_real"]))

        # ---- 第二支：按 SDK 逐条对照「声明 vs 实测」----
        # 上一步的差集是「类型 → 类型」，回答不了"哪个 SDK 多采了什么"。
        # 人工报告里最常被追问的恰恰是后一句，所以单独再算一遍：
        #   · 清单/政策里逐条抽出 SDK（名称、厂商、声明类型）
        #   · 调用栈归因把实测事件按 SDK 聚合
        #   · 两边比对，同厂商按集团放宽（腾讯系列一个就算，见 declaration 模块注释）
        try:
            docs: List[Dict[str, str]] = []
            if self.policy_text:
                docs.append({"title": "隐私政策正文", "text": self.policy_text,
                             "url": (self.scan.policy_capture.get("bestTextUrl") or "")
                             if self.scan else ""})
            for d in (self.policy_docs or []):
                if isinstance(d, dict) and (d.get("text") or "").strip():
                    docs.append({"title": d.get("title") or d.get("kind") or "政策内文档",
                                 "text": d["text"], "url": d.get("url") or ""})
            self.sdk_matrix = DCL.analyze(
                evs, docs, list((res.get("declared") or {}).keys()),
                package=self.fr.package or "", ai=self.ai, log=self.log)
            self.fr.sdk_matrix = self.sdk_matrix
            _ms = self.sdk_matrix.get("stats") or {}
            pr.evidence["sdk_declared"] = _ms.get("declared_sdk", 0)
            pr.evidence["sdk_observed"] = _ms.get("observed_sdk", 0)
            pr.evidence["sdk_gap"] = _ms.get("sdk_gap", 0)
            pr.steps.append("按 SDK 逐条对照声明与实测")
            self.log("[流程]    SDK 对照：清单声明 %d 个 / 实测 %d 个 / 未列明或范围不足 %d 个"
                     % (_ms.get("declared_sdk", 0), _ms.get("observed_sdk", 0),
                        _ms.get("sdk_gap", 0)))
        except Exception as e:                      # noqa: BLE001
            pr.warnings.append("按 SDK 对照失败（不影响类型级差集）：%s" % e)
            self.log("[!] 按 SDK 对照失败：%s" % e)

        def _sink_stacks(target_hosts: Sequence[str]) -> List[List[str]]:
            """按域名反查 K1 事件的调用栈。

            「检测到向 X 外发数据」这条结论同样要回答"谁发的" ——
            是 App 主动上报，还是某个 SDK 在自己的线程里上报。
            后者对应"未列明第三方 SDK/接收方"，整改对象完全不同。
            """
            out: List[List[str]] = []
            for e in evs:
                if getattr(e, "sink", "") != "K1" or getattr(e, "noise", ""):
                    continue
                blob = getattr(e, "args", "") or ""
                if not any(h and h in blob for h in target_hosts):
                    continue
                st = list(getattr(e, "stack", []) or [])
                if st:
                    out.append(st)
                if len(out) >= 3:
                    break
            return out

        real = res.get("real_gaps") or []
        if real:
            names = "、".join("%s（%s）" % (g["name"], g.get("class", "")) for g in real)
            detail = []
            for g in real[:8]:
                s = g.get("samples") or []
                where = ""
                if s:
                    where = "，如调用 %s%s" % (s[0].get("api", ""),
                                              "（发生在同意前）" if s[0].get("before") else "")
                detail.append("%s%s" % (g["name"], where))
            stacks = [list(g["samples"][0].get("stack") or [])
                      for g in real if (g.get("samples") or [])]
            # ★ 强度分级（用户 2026-10-27 意见）：只有"注册传感器监听器"这类
            #   **接口调用**、没取到任何具体取值的，不足以认定"实际收集了 XX"，
            #   应记疑似；取到了具体成员（Android ID=…）才算认定。
            #   旧写法一律 FAIL，于是"注册监听器"被写成"实际收集了存储文件"，
            #   既夸大了事实，也和下面那条栈对不上。
            strong = [g for g in real if (g.get("members") or {})]
            _state = FAIL if strong else SUSPECT
            _conf = "确证" if strong else "疑似"
            _desc = ("实际收集了%s，但隐私政策中未列明相应内容，"
                     "告知的收集范围与实际情况不一致" % names)
            if not strong:
                _desc = ("观测到%s的接口调用，但本次未取得具体取值（如仅注册传感器监听、"
                         "未取到传感器数据），尚不足以认定「实际收集」。"
                         "政策中未见对应声明，是否构成告知不一致需人工结合业务场景复核"
                         % names)
            self._set("Q006", _state, phase="P5", level="中", confidence=_conf,
                      desc=_desc,
                      evidence=[Evidence("policy", "政策未列明的收集类型", "；".join(detail), "P5")],
                      facts=[["实际收集类型数", str(res["stats"]["collected_types"])],
                             ["政策声明类型数", str(res["stats"]["declared_types"])],
                             ["声明类型来源", "关键词匹配 %d 项 + 模型深读补充 %d 项"
                              % (res["stats"].get("declared_types_kw", 0),
                                 res["stats"].get("declared_ai_extra", 0))],
                             ["未列明", names],
                             ["证据强度", ("已取得具体取值（%s）"
                                           % "、".join(g["name"] for g in strong))
                              if strong else
                              "仅见接口调用、未取得具体取值（%s）"
                              % "、".join(g["name"] for g in real)]],
                      stacks=[s for s in stacks if s][:3])
            self._set("Q005", SUSPECT, phase="P5", level="中",
                      desc="隐私政策未逐一列明 App 实际收集的个人信息的%s" % names,
                      evidence=[Evidence("policy", "未逐一列出", names, "P5")])
        else:
            # ★ 「未发现不一致」必须写清是**在多大观测面上**未发现。
            #   本轮只收集到 1 种类型（设备标识符）时写一句光秃秃的
            #   "实际收集到的信息均能在政策中找到对应声明"，复核员会读成
            #   "全部收集行为都被政策覆盖了"——而遍历根本没走完。
            #   把观测面写进结论，结论才站得住。
            obs = [v.get("name") for v in (res.get("collected") or {}).values()]
            obs = [x for x in obs if x]
            # ★ 采集完整性闸门（2026-11-10 CNC宝典 真机两轮对照）：
            #   同一个包、同一台机、同一版本连跑两轮：
            #     第一轮 102 条事件 → Q002/Q003 认定「同意前已取 Android ID」；
            #     第二轮只有 4 条事件 → 两项都只能记 not_tested。
            #   差别不在应用，而在第二轮**政策入口被系统浏览器接管**：应用切到后台，
            #   Frida 脚本静默脱钩（17 个界面里只有 3 个来自 hook —— 正常每换一次
            #   Activity 都该有一条）。在这种轮次上写「本轮未观测到任何个人信息
            #   收集行为」是**反向假话**：拿一台已经失灵的仪器替应用背书。
            _inc = self._collect_incomplete() if not obs else ""
            if _inc:
                self._set("Q006", NOT_TESTED, phase="P5",
                          reason=_inc,
                          evidence=[Evidence("runtime", "注入脚本已脱钩", _inc, "P4")])
            else:
                if obs:
                    head = ("本轮实际观测到 %d 种个人信息类型的收集行为（%s），"
                            "均已能在隐私政策中找到对应声明"
                            % (res["stats"]["collected_types"], "、".join(obs)))
                else:
                    head = "本轮未观测到任何个人信息收集行为，故无可比对的实际收集项"
                # Q005（是否逐一列明目的/方式/范围）**故意不在这里判**：
                # 「实际收集的类型都能在政策里找到」与「政策对目的/方式/范围作了列明」
                # 是两个问题。前者成立推不出后者，在这里顺手写一句
                # "隐私政策对收集的目的、方式、范围作了列明"，等于把没做过的事
                # 说成做过了。Q005 由 P6 的政策文本核查按「目的/方式/范围」
                # 三要素逐项检索后给结论，那里才有真凭据。
                self._set("Q006", PASS, phase="P5", confidence="确证",
                          desc="%s。收集行为的覆盖范围受本轮界面遍历深度限制，"
                               "未遍历到的场景是否存在政策未声明的收集，不在本结论范围内"
                               % head,
                          facts=[["实际观测到的收集类型", "%d 种：%s"
                                  % (res["stats"]["collected_types"],
                                     "、".join(obs) or "（无）")],
                                 ["政策声明的信息类型", "%d 种"
                                  % res["stats"]["declared_types"]],
                                 ["未达成一致的差集", "%d 项" % res["stats"]["gap_real"]],
                                 ["本结论观测面", "仅覆盖本轮界面遍历到的场景，"
                                                  "受遍历深度限制"]])

        tp = res.get("third_party_gaps") or []
        sdk_gaps = res.get("sdk_gaps") or []
        obs_sdk = res.get("observed_sdks") or []
        hthird = res.get("hosts_third") or []
        # ★ 域名分角色（2026-10-27 金考典）：CDN / 图片 / 静态资源域名不是
        #   "接收方"。把 myqcloud、gdtimg 这类地址算成"未列明的接收方"，
        #   复核员一眼推翻 —— 结论要么落在真正的接口域名上，要么老老实实
        #   写"本次只观测到静态资源加载，是否构成提供个人信息需人工确认"。
        _tp_api = [t for t in tp if (t.get("role") or "api") != "static"]
        _tp_static = [t for t in tp if (t.get("role") or "api") == "static"]
        _q7_set = False
        if tp and not _tp_api and _tp_static:
            _sh = "、".join(t["host"] for t in _tp_static[:10])
            _rf = [["运行期连接到的域名（均为内容分发/静态资源）", _sh],
                   ["本项观测范围", "仅记录连接目标地址，未记录传输内容"],
                   ["为什么不算「未列明的接收方」",
                    "这些域名用于图片/页面等资源加载，通常不作为个人信息接收方"
                    "在政策里逐一列明；是否构成「向第三方提供个人信息」"
                    "取决于传输内容，本轮未部署流量监测，无法判定"]]
            if sdk_gaps:
                _rf.append(["调用栈中识别出的第三方 SDK",
                            "、".join("%s（%s）" % (g.get("display") or g["name"],
                                                     g["vendor"] or g["prefix"])
                                     for g in sdk_gaps[:6])])
            if _is_privacy_policy_text(self.policy_text):
                self._set("Q007", NOT_TESTED, phase="P5",
                          reason="本轮运行期只连接到 %s 等 %d 个内容分发/静态资源域名，"
                                 "未观测到向第三方接口地址发起连接；"
                                 "这类域名通常不作为个人信息接收方列明，"
                                 "是否构成「向第三方提供个人信息」需结合流量内容判定，"
                                 "本轮未部署流量监测，故不下结论" % (_sh, len(_tp_static)),
                          evidence=[Evidence("traffic", "运行期连接到的静态资源域名",
                                             _sh, "P5")],
                          facts=_rf,
                          stacks=_sink_stacks([t["host"] for t in _tp_static]))
            else:
                self._set("Q007", NOT_TESTED, phase="P5",
                          reason="本轮运行期连接到 %s 等 %d 个内容分发/静态资源域名，"
                                 "且取得的正文不是隐私政策，无法据此判断接收方是否列明"
                                 % (_sh, len(_tp_static)),
                          evidence=[Evidence("traffic", "运行期连接到的静态资源域名",
                                             _sh, "P5")],
                          facts=_rf,
                          stacks=_sink_stacks([t["host"] for t in _tp_static]))
            _q7_set = True   # 走完这一支，下面的分支不许再覆盖结论
        if tp and not _q7_set:
            hostnames = "、".join(t["host"] for t in _tp_api[:10])
            tp = _tp_api
            # ★ 措辞铁律：我们只 hook 到了"向哪个地址发起了连接"，
            #   **没有抓包**，看不到请求体里有没有个人信息、传了哪些字段。
            #   写成"检测到外发数据"会让复核员以为内容被监测过 —— 那是另一件事，
            #   而且本报告不具备该能力（用户明确要求：不能监测内容就不谈外发行为）。
            #   所以只说"运行期连接到该地址"，结论落在"接收方是否列明"上。
            _f = [["运行期连接到的第三方地址", hostnames],
                  ["本项观测范围", "仅记录连接目标地址，未记录传输内容"
                                   "（本轮未部署流量监测，不对传输内容作判断）"]]
            if sdk_gaps:
                _f.append(["调用栈中识别出的第三方 SDK",
                           "、".join("%s（%s）" % (g.get("display") or g["name"],
                                                    g["vendor"] or g["prefix"])
                                    for g in sdk_gaps[:6])])
            if _tp_static:
                # 静态资源域名不算接收方，但也不能悄悄吞掉 —— 报告里要能看到
                # "本轮还连了这些 CDN"，否则读者会以为抓到的地址只有这几个接口。
                _f.append(["另：内容分发/静态资源域名（不作为接收方列明判断对象）",
                           "、".join(t["host"] for t in _tp_static[:10])])
            if _is_privacy_policy_text(self.policy_text):
                self._set("Q007", SUSPECT, phase="P5", level="中",
                          desc="应用运行期连接到 %s 等 %d 个第三方地址，"
                               "在隐私政策及第三方共享清单中未查到对应的接收方名称、"
                               "联系方式与共享目的（仅记录连接目标地址，未记录传输内容）"
                               % (hostnames, len(tp)),
                          evidence=[Evidence("traffic", "未在政策中列明的第三方连接地址",
                                             hostnames, "P5")],
                          facts=_f,
                          stacks=_sink_stacks([t["host"] for t in tp]))
            else:
                # 正文不是隐私政策时，"政策里查不到这个域名"不构成任何证据 ——
                # 拿一份《用户协议》去搜接收方，本来就一个都搜不到。
                # 连接地址与调用栈都是本轮实测到的硬事实，照实交出去；
                # 判定留给人工取到隐私政策后做。
                self._set("Q007", NOT_TESTED, phase="P5",
                          reason="本轮实测观测到应用运行期连接到 %s 等 %d 个第三方地址，"
                                 "但取得的正文为《用户协议》一类文本而非隐私政策/第三方共享清单，"
                                 "无法据此判断这些接收方是否已列明名称、联系方式与共享目的；"
                                 "需人工取得隐私政策后逐条核对" % (hostnames, len(tp)),
                          evidence=[Evidence("traffic", "运行期连接到的第三方地址",
                                             hostnames, "P5")],
                          facts=_f + [["本项未下结论的原因",
                                       "取得的正文为《用户协议》类文本，"
                                       "在其检索接收方信息不具判定意义"]],
                          stacks=_sink_stacks([t["host"] for t in tp]))
        elif sdk_gaps and _is_privacy_policy_text(self.policy_text):
            # 域名都对得上、但栈里的 SDK 名一个都没在政策里检索到。
            # 这一支是纯"栈贡献"的结论：没有调用栈就永远发现不了
            # （SDK 走的是自家域名，域名法看着像 App 自有服务）。
            _names = "、".join("%s（%s）" % (g.get("display") or g["name"],
                                            g["vendor"] or g["prefix"])
                              for g in sdk_gaps[:6])
            # ★ 换结论就必须换栈（金考典 2026-10-28）：`_set` 是 extend，
            #   上一条分支（按连接地址下的结论）挂过的栈会留下来，
            #   于是"描述说优推广告未列明、下面挂着 3 条七巧板的外发栈"，
            #   复核员一比对就整条作废。先清空，再只挂这些 SDK 自己的栈。
            _st7 = self._item("Q007")
            _st7.stacks = []
            _own = [s for s in ATTR.stacks_with_sdks(
                [list(getattr(e, "stack", []) or []) for e in evs],
                self.fr.package or "", {g["name"] for g in sdk_gaps}) if s][:3]
            self._set("Q007", SUSPECT, phase="P5", level="中",
                      desc="调用栈显示本轮实际调用了 %s 等 %d 个第三方 SDK，"
                           "这些 SDK 的名称/厂商/包名在隐私政策与第三方共享清单中均未检索到，"
                           "存在未逐一列出第三方 SDK 的可能，需人工核对政策原文确认"
                           % (_names, len(sdk_gaps)),
                      evidence=[Evidence("frida", "调用栈识别出的第三方 SDK",
                                         _names, "P5")],
                      facts=[["调用栈中识别出的第三方 SDK",
                              "、".join(g.get("display") or g["name"] for g in sdk_gaps)],
                             ["政策文本检索用的键", "、".join(g["keys"] for g in sdk_gaps[:6])],
                             ["检索结果", "上述名称、厂商与包名根在政策正文中均未命中"],
                             # 两个数口径不同，必须当场说清（金考典 2026-10-28 用户质疑）：
                             #   「按行为主体归属」只算**发起那次调用**的 SDK；
                             #   「按调用栈实测」还算在栈里出现、但只在更外层
                             #   调用聚合 SDK 的那些 —— 优推就是这种（它初始化了倍孜）。
                             #   不解释的话，报告里"未列明 1 个"与
                             #   对照表里"未列明 0 个"会互相打脸。
                             ["本项计数口径",
                              "按调用栈实测（栈内出现即计入，含只在更外层调用了"
                              "聚合 SDK 的那些）；下方「第三方 SDK 对照」按行为主体"
                              "归属计数，两者口径不同，数字可不相等"]],
                      stacks=_own)
        elif sdk_gaps:
            # 正文不是隐私政策（用户协议 / 服务条款）时，拿它搜 SDK 名称
            # 必然一个都搜不到 —— 不给结论，只把识别结果交出去。
            self._set("Q007", NOT_TESTED, phase="P5",
                      reason="本轮取得的正文不是隐私政策（开头为《用户协议》一类文本），"
                             "不能据此判断第三方 SDK 是否已列明；调用栈中已识别出 %d 个 SDK，"
                             "需人工取得隐私政策或第三方共享清单后逐条核对" % len(sdk_gaps),
                      evidence=[Evidence("frida", "调用栈识别出的第三方 SDK",
                                         "、".join(g["name"] for g in sdk_gaps[:6]), "P5")],
                      facts=[["调用栈中识别出的第三方 SDK",
                              "、".join(g.get("display") or g["name"] for g in sdk_gaps)],
                             ["本项未下结论的原因",
                              "取得的正文为《用户协议》类文本，不是隐私政策/共享清单，"
                              "在其中的检索结果不具判定意义"]])
        elif hthird and not _q7_set:
            # ★ 「政策里能检索到这些域名/厂商名」**不等于**「五要素已列明」。
            #   本次实现的检索只能回答"接收方名称出现过没有"，
            #   回答不了"每个接收方的联系方式、共享目的、所涉信息种类是否都写了"。
            #   所以这里既不判 pass（会把"没写全"洗成"没问题"），
            #   也不判 suspect（本次没有任何指向违规的证据，凭空出一条疑似
            #   就是编造），如实标"未测"并把已取得的清单交出去供人工逐条核对。
            self._set("Q007", NOT_TESTED, phase="P5",
                      reason="本轮观测到应用运行期连接到 %d 个第三方地址（%s），"
                             "这些域名或其对应厂商名称均能在隐私政策/SDK 清单文本中检索到"
                             "对应表述；但「各接收方的名称、联系方式、共享目的与所涉"
                             "个人信息种类」是否逐项列明（五要素）本次未做逐条核对，"
                             "故既不认定已列明、也不认定未列明，留给人工按下方清单逐条比对"
                             % (len(hthird), "、".join(hthird[:10])),
                      evidence=[Evidence("traffic", "运行期连接到的第三方地址",
                                         "、".join(hthird[:10]), "P5")],
                      facts=[["运行期连接到的第三方地址", "、".join(hthird)],
                             ["本项观测范围", "仅记录连接目标地址，未记录传输内容"],
                             ["政策文本检索结果", "上述域名/厂商名均检出对应表述"]])

        # ---- ③ SDK 粒度的逐条结论（补强的第二路证据）----
        # 前面几支都是"有没有列明"的整体判断；这一支回答的是
        # 「哪个 SDK 实际采的比清单声明多」。结论只在有 SDK 缺口时升级状态，
        # 没有缺口时**不动状态**，只把对照事实挂上去 —— 五要素是否列全
        # 仍要人工逐条核，这里不能凭空给出"未发现问题"。
        _m = self.sdk_matrix or {}
        if _m:
            _st7 = self._item("Q007")
            _facts = self._matrix_facts(_m)
            _ev = Evidence("policy", "第三方 SDK 逐条比对",
                           DCL.describe(_m), "P5")
            if (_m.get("gap_sdk") or []) and _st7.state != M.FAIL \
                    and _is_privacy_policy_text(self.policy_text):
                # ★ 每个缺口 SDK 都要有自己的栈（用户 2026-10-27 意见）：
                #   旧写法只取前 3 个缺口 SDK 的栈再截 3 条，结果是"描述里点了 5 个
                #   SDK 未列明，下面只有 2~3 个 SDK 的栈"，还有"已列明但声明范围
                #   小于实际采集"那一条完全没有栈 —— 复核员没法据此核对任何一个 SDK。
                #   顺序与描述一致：先未列明，其次范围不足。
                _gaps = [g for g in (_m.get("gap_sdk") or [])
                         if g.get("matched_by") == "未列明"]
                _gaps += [g for g in (_m.get("gap_sdk") or [])
                          if g.get("matched_by") != "未列明"]
                _stk: List[List[str]] = []
                _nostk: List[str] = []
                _pair: List[str] = []          # 「类型 ← API」对照，写进事实表
                for _g in _gaps:
                    _by_pi = {p.get("pi"): p for p in (_g.get("observed_pi") or [])}
                    _types = list(_g.get("missing_pi") or [])
                    if not _types:
                        # 未列明但没细到类型：退回该 SDK 自己的栈（这是它自己的行为）
                        _own = [s for s in (_g.get("stacks") or [])
                                if s and s not in _stk]
                        if not _own:
                            _nostk.append(_g.get("name") or "")
                            continue
                        _stk.extend(_own[:2])
                        continue
                    for _p in _types:
                        _pid = _p.get("pi")
                        _obs = _by_pi.get(_pid) or {}
                        # ★ 只取**产出该类型**的那条栈（金考典 2026-10-27）：
                        #   旧写法拿 SDK 的前两条栈了事，于是"未列明：传感器信息、
                        #   通信记录"下面挂的是两条 getPackagesForUid（应用列表），
                        #   类型与栈对不上，复核员没法据此核对任何一条。
                        _own = [s for s in (_obs.get("stacks") or [])
                                if s and s not in _stk]
                        if _own:
                            _stk.append(_own[0])
                            _pair.append("%s「%s」← %s"
                                         % (_g.get("name") or "", _p.get("name") or "",
                                            str(_own[0][0] if _own[0] else "")))
                        else:
                            _nostk.append("%s·%s" % (_g.get("name") or "",
                                                     _p.get("name") or ""))
                    if len(_stk) >= 8:
                        break
                _facts2 = [[a, b] for a, b in _facts]
                # ★ 「栈里出现过、但不承担这次调用」的 SDK 必须单独交代
                #   （金考典 2026-10-28 用户问"为什么描述说优推、栈里全是七巧板/倍孜"）：
                #   优推（com.alliance.ssp.ad）只在栈的**最外层**出现一层 ——
                #   它初始化并调用倍孜（xyz.adscope / com.beizi.ad）去真正读设备信息，
                #   于是行为主体归到倍孜，栈里前 8 层全是倍孜的类。
                #   政策里两家都没写，整改时是两家都要做的事，不能因为
                #   归因只算"发起方"就把优推从报告里抹掉。
                _gap_names = {str(r.get("name") or "") for r in (_m.get("gap_sdk") or [])}
                _outer = [g for g in sdk_gaps
                          if (g.get("display") or g.get("name") or "") not in _gap_names
                          and not any(_gap_names & {(g.get("display") or "")})]
                if _outer:
                    _facts2.append([
                        "调用栈中出现、但未承担该次调用的 SDK",
                        "、".join("%s（%s）" % (g.get("display") or g["name"],
                                               g.get("vendor") or g.get("prefix") or "")
                                 for g in _outer[:6])
                        + "：这些 SDK 的代码参与了调用链（典型情形是聚合广告 SDK "
                        "在自己的线程里初始化/调用另一个 SDK），本次采集行为由上面的 SDK 发起；"
                        "它们在政策与共享清单中同样未检索到，整改时建议一并列出"])
                if _pair:
                    _facts2.append(["栈与类型的对应",
                                    "；".join(_pair[:8]) + "（每条栈都取自实测产出该类型的"
                                    "那次调用，不是同 SDK 的任意一条）"])
                if _nostk:
                    # 没有栈的 SDK 不能只靠描述带过 —— 明写缺的是什么。
                    _facts2.append(["无可用调用栈的类型",
                                    "、".join(_nostk) + "（实测采集已归属到该 SDK，"
                                    "但本次未捕获到该类型对应的调用栈，需加大采样深度复核）"])
                # ★ 结论文本换了，栈也必须换（不能累加）：
                #   上面那一段按"连到哪个地址"挂过 2 条栈（神策、信通院），
                #   现在结论改成"哪几个 SDK 未列明"，再留着那两条，
                #   复核员数一遍就发现"描述里只有 smsdk，栈里却有别人的"——
                #   西五街 2026-10-27 那轮就是这样。`_set` 是 extend，
                #   所以这里先清空，让栈与描述一一对应。
                _st7.stacks = []
                # ★ 事实表也要跟着换（金考典 2026-10-28）：上一条分支挂过
                #   「调用栈中识别出的第三方 SDK＝优推」「检索结果＝未命中」，
                #   而这一支的结论是「AdScope 未列明设备标识符」——
                #   两套事实并列，复核员读到的是一份自相矛盾的证据表。
                #   只删那几行结论性事实，静态/域名类事实（同一项的证据面）保留。
                _drop = {"调用栈中识别出的第三方 SDK", "政策文本检索用的键",
                         "检索结果", "本项计数口径", "本项未下结论的原因"}
                _st7.facts = [f for f in (_st7.facts or [])
                              if str(f[0] if f else "") not in _drop]
                self._set("Q007", SUSPECT, phase="P5", level="中",
                          desc="按第三方 SDK 逐条比对实测采集与声明清单：%s"
                               % DCL.describe(_m),
                          evidence=[_ev], facts=_facts2, stacks=_stk)
            else:
                _st7.evidence.append(_ev)
                _st7.facts.extend([[a, b] for a, b in _facts])
            # App 自身超范围的那部分挂到 Q006（告知与实际情况不一致）上
            for _r in (_m.get("gap_app") or [])[:2]:
                self._item("Q006").facts.append([
                    "App 自身超出声明",
                    "实际采集 %s，政策与收集清单中未见对应声明"
                    % "、".join(p.get("name", "") for p in _r.get("missing_pi") or [])])

        miss = res.get("missing_elements") or []
        # ★ 同样要有政策类型护栏：拿《用户协议》去查"有没有第三方共享章节"
        #   必然查不到，据此出「政策未说明向第三方提供」的疑似项，是把
        #   拿错文件当成 App 的过错。
        if "第三方共享" in miss and self._item("Q007").state == NOT_TESTED \
                and _is_privacy_policy_text(self.policy_text):
            self._set("Q007", SUSPECT, phase="P5", level="中",
                      desc="隐私政策中未发现关于向第三方提供个人信息的说明")
        self._end(pr, M.PHASE_DONE)
        return pr

    # ------------------------------------------------- SDK 对照事实表
    @staticmethod
    def _matrix_facts(m: Dict[str, Any]) -> List[List[str]]:
        """把 SDK 对照压成「键 → 值」两列，塞进报告的事实表。

        完整的多列表格由报告层单独渲染（`fr.sdk_matrix`），这里只放
        复核员一眼要看的那几行：总数、每个缺口 SDK 的缺项、同厂商放宽了哪些。
        """
        st = m.get("stats") or {}
        out: List[List[str]] = [[
            # 标明口径：这个数只算「发起那次调用的 SDK」，与「栈里出现过」不同 ——
            # 两个口径并列时数字对不上是正常的，不标就会看起来像自相矛盾。
            "第三方 SDK 对照（按行为主体归属）",
            "清单/政策中识别到 %d 个 · 实测采集到 %d 个 · 未列明 %d 个 · 已列明但声明范围不足 %d 个"
            % (st.get("declared_sdk", 0), st.get("observed_sdk", 0),
               st.get("sdk_unlisted", 0),
               max(0, st.get("sdk_gap", 0) - st.get("sdk_unlisted", 0)))]]
        for r in (m.get("gap_sdk") or [])[:8]:
            obs = "、".join(p.get("name", "") for p in r.get("observed_pi") or []) or "—"
            decl = "、".join(p.get("name", "") for p in r.get("declared_pi") or []) or "—"
            miss = "、".join(p.get("name", "") for p in r.get("missing_pi") or [])
            tail = ("；未列明：%s" % miss) if miss else ""
            out.append(["SDK「%s」" % (r.get("name") or ""),
                        "实际采集 %s；清单声明 %s（%s）%s"
                        % (obs, decl, r.get("matched_by") or "未列明", tail)])
        for r in (m.get("sdk_rows") or []):
            if r.get("matched_by", "").startswith("同厂商") and not r.get("missing_pi"):
                out.append(["同厂商放宽「%s」" % (r.get("name") or ""),
                            "清单中未逐字出现该 SDK，但同一厂商（%s）已列明 %s，"
                            "按厂商口径视为已声明"
                            % (r.get("group") or "",
                               "、".join((r.get("same_vendor_sdks") or [])[:3])
                               or "旗下其他 SDK")])
        for r in (m.get("gap_app") or [])[:2]:
            out.append(["App 自身超出声明",
                        "实际采集 %s，政策与收集清单中未见对应声明"
                        % "、".join(p.get("name", "") for p in r.get("missing_pi") or [])])
        if m.get("unknown_row"):
            u = m["unknown_row"]
            out.append(["未能归属的采集行为",
                        "%d 次，调用点 %s（不在 App 包内、也不在已收录 SDK 名单内，"
                        "未计入任何一方的差集）"
                        % (u.get("count", 0), u.get("name", ""))])
        if m.get("covered_by_ai"):
            out.append(["经模型复核视为已列明",
                        "、".join(m["covered_by_ai"][:8])])
        return out

    # ------------------------------------------------- 功能存在性项：入口实测情况
    def _functional_probe(self, qid: str) -> Dict[str, Any]:
        """从本轮存档里查出「这个功能入口到底碰没碰到」，供措辞使用。

        返回 dict（全部字段都来自存档，查不到就是空，绝不推测）：
          listed  界面（非政策页）上出现过该入口的文字
          where   出现在哪个界面
          opened  AI 轨迹里显式确认过"这个页面已打开并看清了"
          quote   确认时的原话节选（带 AI 轨迹步号，可追溯）
          login   None / "未登录" —— 本轮界面是否显示未登录态

        ★ 只查两处硬证据：设备端抓到的界面文字，和 AI 决策时留下的原话。
          政策页（WebviewActivity）一律排除：政策正文里必然出现"注销/投诉"等字眼，
          拿它当入口证据会把"政策写了"当成"App 有"。
        """
        out: Dict[str, Any] = {"listed": False, "where": "", "opened": False,
                               "absent": False, "seen": False,
                               "quote": "", "login": None,
                               "blocked": False, "blocked_label": ""}
        keys = _FUNCTIONAL_ENTRY.get(qid) or ()
        if not keys or not self.scan:
            return out

        # ---- ① 界面文字：排除政策页，只看 App 自身界面 ----
        for s in (getattr(self.scan, "screens", None) or []):
            act = str(s.get("activity") or "")
            if "Webview" in act or "webview" in act:
                continue
            # 只认**短标签**（≤12 字）。界面上还有大段正文，
            # 拿正文去匹配会命中无关字词（实测："画像"命中的是日文作品说明）。
            texts = [str(t) for t in (s.get("texts") or []) if len(str(t)) <= 12]
            blob = " ".join(texts)
            if not out["listed"] and any(k in blob for k in keys):
                out["listed"] = True
                out["where"] = str(s.get("label") or act or "未知界面")
            if out["login"] is None and "未登录" in blob:
                out["login"] = "未登录"

        # ---- ② AI 轨迹：只取决策原话（decision.reason）----
        #   不能把 raw/expect 混进来：那是 JSON，塞进报告会变成
        #   「AI 轨迹第 9 步：tap  {"action": "tap", "index": 4…」这种废话。
        #   而且**必须引"含关键词的那一句"** —— 否则会引到同一步里另一句
        #   无关的话，看着像证据，实际风马牛不相及。
        for i, t in enumerate(getattr(self.scan, "ai_trace", None) or []):
            blob = str((t.get("decision") or {}).get("reason") or "")
            if not blob:
                continue
            seg = [x.strip() for x in re.split(r"[。；;]", blob) if x.strip()]
            # 取**命中关键词最多**的那一句：同一步里往往既有一句"覆盖清单"
            # 也有一句"为什么没走通"，取命中多的那句才是对得上题的实证。
            cand = [x for x in seg if any(k in x for k in keys)]
            if not cand:
                continue
            sent = max(cand, key=lambda x: sum(1 for k in keys if k in x))
            # 判定强度：确认词与关键词**同句**才算"确证"；
            # 只在同一步别处出现，说明只是"进过相关页面"，不能说"已打开该入口"。
            if any(m in sent for m in _OPENED_MARKS):
                out["opened"] = True
            elif any(m in sent for m in _ABSENT_MARKS):
                out["absent"] = True
            elif any(m in blob for m in _OPENED_MARKS):
                out["seen"] = True
            elif any(m in blob for m in _ABSENT_MARKS):
                out["absent"] = True
            else:
                continue
            q = sent if len(sent) <= 90 else sent[:90] + "…"
            m = re.search(r"(\d+)", str(t.get("stage") or ""))
            out["quote"] = "AI 轨迹第 %s 步原话：%s" % (
                m.group(1) if m else str(i + 1), q)
            break

        # ---- ③ 遍历图：定向期记下的入口位置 ----
        # ★ 比 ①② 更硬：它记的是"这个入口此刻确实在这一屏上、是可点节点"，
        #   而不是"某段文字里出现过这个词"。而且能区分"看到了但按规范不点"
        #   （注销/退出类）与"根本没走到"—— 这两者在报告里必须分开写。
        cov = getattr(self.fr, "coverage", None) or {}
        tname = CL.QID_TARGET.get(qid)
        if tname:
            for t in (cov.get("targets") or []):
                if str(t.get("name") or "") != tname or not t.get("found"):
                    continue
                out["listed"] = True
                out["where"] = out["where"] or str(t.get("where") or "")
                out["blocked"] = bool(t.get("blocked"))
                out["blocked_label"] = str(t.get("label") or "")
                break
        return out

    def _functional_reason(self, qid: str, hits: Sequence[str]) -> Tuple[str, List[List[str]]]:
        """拼「功能存在性」项的未测理由 —— 每一句都要能在存档里对得上。"""
        p = self._functional_probe(qid)
        hits_txt = "、".join(hits) if hits else "见政策原文"

        if p["blocked"]:
            # 「看到了但按规范不点」必须写清楚，否则复核员会以为我们漏点了，
            # 或者反过来以为已经修好了。
            obs = ("本轮遍历在界面「%s」上定位到该入口（「%s」，为可点节点），"
                   "因属注销/退出类不可逆操作，按检测规范仅记录位置、未实际执行"
                   % (p["where"] or "—", p["blocked_label"] or "该入口"))
        elif p["opened"]:
            obs = "本轮遍历已打开该入口页面并取证（%s）" % p["quote"]
        elif p["absent"]:
            obs = "本轮遍历已逐屏排查过相关入口，未找到该入口（%s）" % p["quote"]
        elif p["seen"]:
            obs = "本轮遍历进入过相关页面（%s）" % p["quote"]
        elif p["listed"]:
            obs = "本轮界面（%s）中出现该入口文字" % p["where"]
        else:
            obs = "本轮遍历未触及该入口"

        # 入口见到了 ≠ 功能走通了。差别必须说清楚，否则复核员会以为验过了。
        # 且要说到"差在哪一步"（_FUNCTIONAL_TAIL）—— 补测的人才知道该登录还是该提交一次。
        if p["opened"] or p["listed"] or p["seen"]:
            tail = _FUNCTIONAL_TAIL.get(qid, "；但仅到入口为止，未走通完整功能流程")
            if p["login"] and qid in _LOGIN_SENSITIVE:
                tail += "（本轮界面显示「%s」，账号类功能需登录后才能实际操作）" % p["login"]
        else:
            tail = "，因此功能是否真实存在、是否可用均未经验证"

        reason = ("隐私政策文本已载有相关表述（检索到关键词：%s），"
                  "但该项目属「功能存在性」检测，仅凭政策文本不能认定功能真实存在，"
                  "须在 App 内实际走通对应功能路径方可判定。%s%s，留给人工补测"
                  % (hits_txt, obs, tail))

        facts: List[List[str]] = [["政策文本核查", "政策文本载有相关表述（检索到：%s）" % hits_txt]]
        facts.append(["功能入口实测", obs])
        facts.append(["功能实测", ("未走通完整流程" + ("（界面显示未登录）" if p["login"] else ""))])
        return reason, facts

    # ================================================================== P6
    def _enrich_perm_scenes(self, scenes: Sequence[Dict[str, Any]]
                            ) -> List[Dict[str, Any]]:
        """对"看不到用途说明"的权限场景，用**截图视觉**补一次证（同屏浮窗）。

        为什么必须看图（免费手机投屏神器 2026-10-26，用户指出判错了）：
          截图里 App 在屏幕顶部弹了一条浮窗 ——
            「相关权限说明：获取位置信息权限 用于获取附近的免费WIFI列表」
          它和系统权限弹窗**同时**出现，只是被弹窗压住、颜色偏暗。
          `uiautomator dump` 只导最顶层窗口，这句一个字都读不到，
          于是判成"未同步告知目的"。判错不是因为尺度太严，是证据没采到。
        约束：
          · 只在视觉可用时做；不可用就用文本判据，不假装看过图；
          · 每次检测最多补 4 个场景（模型调用是秒级开销，不能把预算吃光）；
          · 读到的原文照样写进事实表，复核员能看到凭据。
        """
        if not scenes:
            return []
        try:
            ok_vis = bool(self.ai_tasks is not None and self.ai_tasks.can_vision())
        except Exception:
            ok_vis = False
        if not ok_vis:
            # 视觉不可用 ≠ 没有浮窗。把"没检查过同屏浮窗"这件事记在场景上，
            # 判定层据此不会把"未告知"写成确证（见 PERM.judge 的 unread 分支）。
            out0: List[Dict[str, Any]] = []
            for s in scenes:
                sc = dict(s or {})
                if PERM.judge_scene(sc).get("purpose") not in ("dialog", "banner", "pre"):
                    sc["banner_unread"] = True
                out0.append(sc)
            return out0
        shots = list(getattr(self.scan, "screenshots", None) or []) if self.scan else []
        out: List[Dict[str, Any]] = []
        used = 0
        for s in scenes:
            sc = dict(s or {})
            pre = PERM.judge_scene(sc)
            if pre.get("purpose") in ("dialog", "banner", "pre"):
                out.append(sc)
                continue
            if used >= 4:
                sc["banner_unread"] = True    # 预算用完，这个场景没看过图
                out.append(sc)
                continue
            idx = sc.get("shot")
            b64 = ""
            if isinstance(idx, int) and 0 <= idx < len(shots):
                b64 = str((shots[idx] or {}).get("b64") or "")
            if not b64:
                sc["banner_unread"] = True    # 连截图都没有，浮窗更无从核起
                out.append(sc)
                continue
            if used >= 4:
                sc["banner_unread"] = True    # 预算用完，这个场景没看过图
                out.append(sc)
                continue
            used += 1
            try:
                ret = self.ai_tasks.read_perm_banner(
                    base64.b64decode(b64),
                    str(sc.get("perm") or sc.get("perm_raw") or ""))
            except Exception as e:                      # noqa: BLE001
                self.log("[流程]    权限弹窗同屏说明识别失败（不影响判定）：%s" % e)
                sc["banner_unread"] = True
                out.append(sc)
                continue
            data = (getattr(ret, "data", None) or {}) if ret is not None else {}
            txt = str(data.get("text") or "").strip()
            pur = str(data.get("purpose") or "").strip()
            if txt or pur:
                sc["banner_text"] = txt[:400]
                sc["banner_purpose"] = pur[:200]
                sc["banner_source"] = "截图视觉识别"
                self.log("[流程]    权限弹窗同屏说明（截图识别）：%s"
                         % ((pur or txt)[:60]))
            out.append(sc)
        return out

    def p6_checklist(self) -> PhaseResult:
        """逐项检测：把还没被任何阶段喂到的测评项显式标为「跳过未测」。

        人工流程里这一步叫「对于没有测到的项目，再做逐项的检测」。
        自动化做不到逐项，所以诚实标注并写清原因 ——
        这比留白或者硬凑一个结论都强。
        """
        pr = self._begin("P6")

        # ---- ① 政策文本逐项检测（不需要设备，最省事的一段）----
        if self.policy_text:
            from . import policy_checks as PC
            pres = PC.run(self.policy_text, log=self.log)
            applied = []
            for qid, r in pres.items():
                if qid.startswith("_"):
                    continue
                st = self.fr.items.get(qid)
                if st is not None and st.state != NOT_TESTED:
                    continue        # 已被 P1~P5 判定的不覆盖（前面的证据更硬）
                if r["state"] == "pass":
                    # ★ 政策里写了 ≠ App 里真有（简小知实测发现的最严重误判）：
                    #   注销账号、投诉举报渠道、更正删除途径、关闭个性化推荐
                    #   这些都是**功能存在性**问题。政策写了只能说明"它声称有"，
                    #   而本次根本没登录，「我的→设置→账号设置」这条路径压根没走到，
                    #   拿政策文本去判「未发现问题」就是拿声称当事实 ——
                    #   复核员照着报告以为验过了，实际一处都没看。
                    #   这类项政策命中时只能记"政策载有表述"，功能是否可用
                    #   必须标未测，把最后一步留给人工。
                    if r.get("functional"):
                        # ★ 措辞从本轮存档现查（见 _functional_reason）：
                        #   「入口打开并取证」/「入口已见未打开」/「未触及入口」
                        #   三种情况说法不同，写死一句"未走通该路径"会把
                        #   已经取到的证据说成没取到 —— 复核员照着补测就白跑了。
                        _reason, _facts = self._functional_reason(
                            qid, r.get("hits") or [])
                        self._set(
                            qid, NOT_TESTED, phase="P6", reason=_reason,
                            evidence=[Evidence("policy", "政策文本载有表述（未做功能实测）",
                                               r["desc"][:200], "P6")],
                            facts=_facts,
                            links=[self.policy_url] if self.policy_url else None)
                    else:
                        # ★ 政策文本能证明的边界要写在结论里：否则复核员会把
                        #   「政策里写了」读成「App 真的做了」。凡结论只到政策
                        #   文本为止的项，都把限定句一并带出来。
                        _scope = _P6_SCOPE.get(qid, "")
                        self._set(qid, PASS, phase="P6",
                                  confidence="政策文本确证" if _scope else "确证",
                                  desc="经隐私政策文本核查：%s%s"
                                       % (r["desc"], "。%s" % _scope if _scope else ""),
                                  evidence=[Evidence("policy", "政策文本核查",
                                                     r["desc"][:200], "P6")],
                                  facts=[["政策文本核查", r["desc"]]]
                                        + ([["本结论边界", _scope]] if _scope else []),
                                  links=[self.policy_url] if self.policy_url else None)
                elif r["state"] == "suspect":
                    self._set(qid, SUSPECT, phase="P6", level=r.get("level", "中"),
                              desc="经隐私政策文本核查：%s" % r["desc"],
                              evidence=[Evidence("policy", "政策文本核查未见",
                                                 r["desc"][:200], "P6")])
                applied.append(qid)
            # ---- ② 「承诺处理时间 > 15 个工作日」是硬标准，直接定问题 ----
            over = pres.get("_time_limit", {}).get("items") or []
            if over:
                ctx = over[0]
                for qid in ("Q013", "Q014", "Q015"):
                    st = self.fr.items.get(qid)
                    if st is None or st.state == FAIL:
                        continue
                    self._set(qid, FAIL, phase="P6", level="高", confidence="确证",
                              desc="隐私政策中承诺的处理时间为 %d 个工作日，超过 15 个工作日的要求"
                                   "（原文：…%s…）" % (ctx["days"], ctx["context"][-70:]),
                              evidence=[Evidence("policy", "超期承诺 %d 个工作日" % ctx["days"],
                                                 ctx["context"], "P6")])
            pr.steps.append("政策文本逐项核查（%d 项）" % len(applied))
            self.log("[流程]    政策文本核查 %d 项，超期承诺 %d 处"
                     % (len(applied), len(over)))

        # ---- ②' Q023 的缺口描述改为「从本轮实测现查」----
        #   原来写死"（相关入口需登录）"，这是**推测**：本轮实际看到的是
        #   「设置」页只有 4 项、根本没有推荐开关。把推测当原因写进报告，
        #   复核员会按"登录后就有"去补测，方向直接错了。
        # 注意用 _item 而不是 fr.items.get：Q023 此前从未被任何阶段写过，
        # 这一刻它还没有条目，get 回来是 None，判断就整段跳过了。
        _q23 = self._item("Q023")
        if _q23.state == NOT_TESTED:
            _p23 = self._functional_probe("Q023")
            if _p23["opened"]:
                _obs23 = "本轮遍历已打开该入口（%s）" % _p23["quote"]
            elif _p23["absent"]:
                _obs23 = "本轮遍历已逐屏排查过相关入口，未找到该入口（%s）" % _p23["quote"]
            elif _p23["listed"]:
                _obs23 = "本轮界面（%s）中见到相关入口" % _p23["where"]
            else:
                _obs23 = "本轮遍历未触及该入口"
            self._set(
                "Q023", NOT_TESTED, phase="P6",
                reason="该项要求先执行「关闭个性化推荐」，再观测关闭后是否仍在收集，"
                       "两个要件必须成对取得。%s，因此无法执行「关闭后观测」这一步，"
                       "缺少关闭后的观测窗口。本轮未覆盖到的路径中是否仍有该入口，"
                       "本次未排除，留给人工确认" % _obs23,
                evidence=[Evidence("ui", "个性化推荐入口实测情况", _obs23, "P6")],
                facts=[["功能入口实测", _obs23],
                       ["功能实测", "未执行「关闭后观测」，缺少关闭后的观测窗口"]])

        done, skipped = [], []
        for qid in sorted(self.items_idx.keys()):
            st = self.fr.items.get(qid)
            if st is None:
                st = self._item(qid)
            if st.state == NOT_TESTED:
                if not st.reason:
                    st.reason = CL.not_tested_reason(qid, self.fr, self.flow)
                skipped.append(qid)
            else:
                done.append(qid)
        pr.evidence = {"executed": done, "skipped": skipped}
        pr.steps = ["汇总已覆盖项", "标注未覆盖项及原因"]
        self.log("[流程]    已判定 %d 项，跳过未测 %d 项" % (len(done), len(skipped)))
        self._end(pr, M.PHASE_DONE)
        return pr

    # ================================================================== P7
    def p7_repro(self) -> PhaseResult:
        """复现确认：清数据复原后逐个复现问题项。

        ★ 为什么不在这里直接清数据重跑
          "清数据重跑"要动设备（卸载/重装/pm clear），那是采集层的事。
          流层一旦去碰 adb，离线重渲染（--from-result）就废了 ——
          同一份存档在服务器上会得出和采集端不一样的结论。
          所以第二轮采集由调用方通过 `repro_runner` 注入：
          默认没有 = 不执行 = 如实写"本轮未执行复现"，绝不假装跑过。

        ★ 三种结论
          已复现（状态不变）/ 未复现（fail→suspect）/ 未能判定（状态不变）。
          详见 flow/repro.py 模块头。
        """
        pr = self._begin("P7")
        need = [qid for qid, st in self.fr.items.items() if st.state in (FAIL, SUSPECT)]
        pr.evidence = {"to_repro": need}
        pr.steps = ["清除 App 数据复原到初始安装状态",
                    "按首轮记录的点击路径逐步重放（不调用模型）",
                    "逐项对照判据"]
        if not need:
            self._end(pr, M.PHASE_SKIPPED, "没有问题项需要复现")
            return pr

        runner = getattr(self, "repro_runner", None)
        if runner is None:
            # 没注入采集能力（离线出报告 / 平台无设备）：如实说没复现，
            # 并把待复现项列出来，人工可以照着做。
            pr.warnings.append(
                "本轮未执行自动复现（未连接采集设备或未启用复现）：待复现项 %s"
                % "、".join(sorted(need)))
            pr.to_repro = sorted(need)
            self._end(pr, M.PHASE_SKIPPED,
                      "未执行自动复现（无采集能力），待复现项 %d 条" % len(need))
            return pr

        self.log("[复现] 开始第二轮采集：清除应用数据后按首轮路径重放，待复现 %d 项"
                 % len(need))
        scan2 = None
        td2: Dict[str, Any] = {}
        err = ""
        try:
            got = runner()
            if isinstance(got, dict):
                scan2 = got.get("scan")
                td2 = dict(got.get("teardown") or {})
                if got.get("error"):
                    err = str(got["error"])
            else:
                scan2 = got
        except Exception as e:
            err = "%s: %s" % (type(e).__name__, e)
            self.log("[!] 复现采集失败：%s" % err)

        if scan2 is None:
            pr.warnings.append("复现采集未取得数据%s，结论状态保持不变"
                               % ("（%s）" % err if err else ""))
            self.fr.repro_results = [
                {"qid": q, "title": self.fr.items[q].title, "reproduced": None,
                 "result_label": "未能判定", "how": "第二轮采集失败",
                 "note": "本轮未能完成复现采集%s，结论状态保持不变；"
                         "需人工按复现步骤重跑" % (("（%s）" % err) if err else "")}
                for q in sorted(need)]
            self._end(pr, M.PHASE_SKIPPED,
                      "复现采集未取得数据%s" % ("：" + err if err else ""))
            return pr

        results = REPRO.judge(self.fr, self.scan, scan2, log=self.log)
        REPRO.apply(self.fr, results, log=self.log)
        # 回放结果进存档：报告要能说清"这次复现走的是首轮同一条路径、
        # 走完了没有"。没走完的步对应的问题项已在 judge 里改判"未能判定"。
        _rp = dict(getattr(scan2, "ui_replay", None) or {})
        if _rp:
            self.fr.repro_replay = _rp
        if getattr(scan2, "aborted", False):
            pr.warnings.append("复现轮采集被中断，部分判据可能不完整")
        if td2:
            self.fr.repro_teardown = td2
        n_ok = sum(1 for r in results if r.get("reproduced") is True)
        n_no = sum(1 for r in results if r.get("reproduced") is False)
        n_mid = len(results) - n_ok - n_no
        pr.evidence = {"to_repro": need, "reproduced": n_ok,
                       "not_reproduced": n_no, "inconclusive": n_mid,
                       "events_round2": len(getattr(scan2, "events", None) or []),
                       "replay": {k: _rp.get(k) for k in
                                  ("total", "done", "complete", "drift", "timed_out")
                                  if k in _rp}}
        self.log("[复现] 结果：已复现 %d / 未复现 %d / 未能判定 %d" % (n_ok, n_no, n_mid))
        self._end(pr, M.PHASE_DONE,
                  "已复现 %d 项，未复现 %d 项，未能判定 %d 项" % (n_ok, n_no, n_mid))
        return pr
        self._end(pr, M.PHASE_SKIPPED, "本次未执行自动复现（需额外一轮真机采集）")
        return pr


def run_flow(*, package: str = "", apk: str = "", scan_result: Any = None,
             static_result: Any = None, cfg=None, ai=None, ai_tasks=None,
             mode: str = "expert", do_repro: bool = False,
             policy_text: str = "", policy_url: str = "",
             log: Log = print, app_name: str = "", version: str = "",
             repro_runner: Any = None) -> FlowResult:
    """一站式入口。

    `repro_runner` 由调用方注入：一个无参可调用对象，执行"清数据重跑一轮采集"，
    返回 ScanResult 或 {"scan":…, "teardown":…}。不传 = 不做复现。
    这样复现能力留在采集层（要动设备），判定留在流层（不碰设备）。
    """
    r = FlowRunner(cfg=cfg, log=log, ai=ai, ai_tasks=ai_tasks)
    return r.run(package=package, apk=apk, scan_result=scan_result,
                 static_result=static_result, mode=mode, do_repro=do_repro,
                 policy_text=policy_text, policy_url=policy_url,
                 app_name=app_name, version=version, repro_runner=repro_runner)


__all__ = ["FlowRunner", "run_flow"]
