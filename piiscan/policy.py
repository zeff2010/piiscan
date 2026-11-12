"""隐私政策抓取与结构化解析。

流程：
  1. 抓取：urllib 拉取政策页面（多编码兜底），或直接接收用户粘贴/上传的政策全文；
  2. 清洗：去掉 script/style，HTML 转纯文本；
  3. 结构化：用沙箱 privacyconfig.txt 的「行为码 → 政策常见表述词」词典做匹配，
     同时用规则正则抽取注销路径、投诉渠道、处理时限、第三方清单、儿童规则等要素。

结构化结果直接喂给判定引擎做两类判定：
  · 纯文本类（未公开规则 / 注销 / 投诉渠道 / 更正删除 / 处理时限）
  · 声明与实际的差集（实测收集了 X，但政策通篇未提 X）
"""
from __future__ import annotations

import html as _html
import json as _json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional

from . import resources

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

MAX_HTML_BYTES = 8 * 1024 * 1024


# ---------------------------------------------------------------- HTML 转文本

class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.skip_depth = 0
        self.title = ""
        self._in_title = False
        self.headings: List[str] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.SKIP:
            self.skip_depth += 1
        elif tag == "title":
            self._in_title = True
        elif tag in ("p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "section"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.SKIP and self.skip_depth:
            self.skip_depth -= 1
        elif tag == "title":
            self._in_title = False
        elif tag in ("p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5"):
            self.parts.append("\n")

    def handle_data(self, data):
        if self.skip_depth:
            return
        if self._in_title:
            self.title += data.strip()
        self.parts.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        raw = raw.replace("\u00a0", " ").replace("\u3000", " ")
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n\s*\n\s*\n+", "\n\n", raw)
        return raw.strip()


def html_to_text(raw: str) -> tuple[str, str]:
    p = _TextExtractor()
    try:
        p.feed(raw)
    except Exception:
        pass
    return p.text(), p.title.strip()


def _text_quality(s: str) -> float:
    """粗略判断一段解码结果"像不像正常文本"。

    为什么要打分：`gb18030` 几乎能解码**任意**字节序列，所以"解码没抛异常"
    不等于解码正确。金考典（2026-10-27）的 assets/privacy.htm 是 UTF-16LE，
    utf-8 解码失败后落到 gb18030，成功解出一整篇 `< h t m l` 的乱码，
    还被当成"206132 字政策正文"写进了报告并判"政策文本确证" ——
    比没测更糟：看报告的人会以为政策原文核对过了。
    """
    if not s:
        return -1.0
    head = s[:4000]
    bad = sum(1 for ch in head
              if ch == "\ufffd" or (ord(ch) < 32 and ch not in "\r\n\t"))
    return 1.0 - bad / max(1, len(head))


def _decode(raw: bytes, ctype: str = "") -> str:
    """多编码兜底：BOM/UTF-16 特征 → Content-Type → meta charset → utf-8 → gbk。"""
    if not raw:
        return ""
    # ① BOM 最确定，直接按它解
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", errors="replace")
    if raw[:2] == b"\xff\xfe":
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", errors="replace")
    cands: List[str] = []
    # ② 无 BOM 的 UTF-16：靠 NUL 字节密度判断（ASCII 字符在 UTF-16 里
    #    每隔一个字节就是 0x00，这种形态绝不可能是单字节编码的正常文本）
    head_b = raw[:400]
    #    纯中文的 UTF-16 里几乎没有 0x00（只有夹在中间的少量 ASCII 才有），
    #    所以阈值不能定太高，否则"通篇汉字、无 BOM"的文件会漏判。
    if head_b.count(b"\x00") > max(3, len(head_b) // 12):
        even_nul = sum(1 for i in range(0, len(head_b) - 1, 2)
                       if head_b[i:i + 1] == b"\x00")
        odd_nul = sum(1 for i in range(1, len(head_b), 2)
                      if head_b[i:i + 1] == b"\x00")
        cands.append("utf-16-be" if even_nul >= odd_nul else "utf-16-le")
    m = re.search(r"charset=([\w\-]+)", ctype or "", re.I)
    if m:
        cands.append(m.group(1))
    head = raw[:4096].decode("latin-1", errors="ignore")
    for pat in (r'charset=["\']?([\w\-]+)', r'encoding=["\']?([\w\-]+)'):
        m = re.search(pat, head, re.I)
        if m:
            cands.append(m.group(1))
    #    单字节编码放在前面：正常 GBK/UTF-8 文本会在这里就 q=1.0 返回，
    #    UTF-16 只是"所有单字节解码都脏"时的最后兜底，不会反抢正常文本。
    cands += ["utf-8", "gb18030", "gbk", "big5", "utf-16-le", "utf-16-be"]
    seen = set()
    best: tuple = (-1.0, "")
    for enc in cands:
        enc = (enc or "").lower().strip()
        if not enc or enc in seen or enc in ("none", "text/html"):
            continue
        seen.add(enc)
        try:
            s = raw.decode(enc)
        except Exception:
            continue
        q = _text_quality(s)
        # 干净就直接用；都不干净就挑最好的那个（乱码至少还能救回一部分）
        if q >= 0.995:
            return s
        if q > best[0]:
            best = (q, s)
    if best[1]:
        return best[1]
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------- 结果模型

@dataclass
class PolicyResult:
    url: str = ""
    final_url: str = ""
    ok: bool = False
    source: str = "url"          # url | text | none
    title: str = ""
    text: str = ""
    error: str = ""

    # ---- 纯文本类要素 ----
    has_cancel_account: bool = False
    cancel_paths: List[str] = field(default_factory=list)
    has_complaint: bool = False
    complaint_channels: List[str] = field(default_factory=list)
    processing_days: Optional[int] = None
    has_correct_delete: bool = False
    correct_delete_paths: List[str] = field(default_factory=list)
    withdraw_consent: bool = False
    third_party_mentioned: bool = False
    third_party_names: List[str] = field(default_factory=list)
    children_rule: bool = False
    has_policy_text: bool = False      # 是否成功取到完整政策正文
    contact_info: List[str] = field(default_factory=list)

    # ---- 声明的个人信息类型（行为码维度）----
    declared_behaviors: List[str] = field(default_factory=list)
    declared_types: List[str] = field(default_factory=list)

    # ---- 溯源信息：这份正文到底是怎么来的（报告里必须写清楚）----
    assets: List[Dict[str, Any]] = field(default_factory=list)   # APK 内置政策文档
    notes: List[str] = field(default_factory=list)               # 捕获过程说明
    popup_notice: str = ""        # 首启弹窗里的"告知摘要"（与政策全文可能不同）

    # ---- AI 深读结果（启用 ai.features.policy_analyze 时）----
    # ai_analysis 是模型的原始结构化输出（含它给出的理由），供人工复核；
    # 其中可用的部分会被合并进上面的规则字段，让判定层无需感知 AI 的存在。
    ai_analysis: Dict[str, Any] = field(default_factory=dict)
    # 追链得到的第三方文档：政策正文里提到「第三方信息共享清单」等，
    # 顺着链接抓下来并二次分析的结果。没有清单本身就是一条重要发现。
    third_party_docs: List[Dict[str, Any]] = field(default_factory=list)
    ai_status: str = ""           # AI 深读的实际状态（完成/跳过/失败原因）
    ai_text_len: int = 0          # 实际送去深读的正文长度

    @property
    def text_len(self) -> int:
        return len(self.text)


# ---------------------------------------------------------------- 正则规则

_R = {
    "cancel": re.compile(r"注销|删除账[号户]|账号注销|cancel\s*account|delete\s*account|"
                         r"注销流程|注销方式|申请注销", re.I),
    "complaint": re.compile(r"投诉|举报|申诉|反馈渠道|客服(电话|邮箱|中心)?|"
                            r"联系(我们|方式|电话|邮箱)|意见反馈|投诉举报", re.I),
    "correct_delete": re.compile(r"更正|纠正|修正|修改(您的)?个人信息|"
                                 r"删除(您的)?个人信息|删除权|更正权|擦除", re.I),
    "withdraw": re.compile(r"撤回(同意|授权|您的同意)|撤销(同意|授权)|"
                           r"关闭(授权|权限)|改变(授权|同意)|注销账号以撤回", re.I),
    "third_party": re.compile(r"第三方|合作(方|伙伴)|共享|转让|公开披露|SDK|"
                              r"接入(的)?第?三方|委托处理", re.I),
    "children": re.compile(r"未成年人|不满十四周岁|儿童个人信息|监护人|父母|"
                           r"青少年模式|儿童保护", re.I),
    "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"(?:400|800)[\-\s]?\d{3}[\-\s]?\d{4}|"
                        r"1[3-9]\d{9}|0\d{2,3}[\-\s]?\d{7,8}"),
    "days": re.compile(r"(\d{1,3}|[一二三四五六七八九十]{1,3})\s*个?\s*工作日"),
}

_CN_NUM = {"一": 1, "二": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7,
           "八": 8, "九": 9, "十": 10}


def _cn_to_int(s: str) -> Optional[int]:
    s = s.strip()
    if s.isdigit():
        return int(s)
    if not s:
        return None
    if s == "十":
        return 10
    if len(s) == 1:
        return _CN_NUM.get(s)
    if s.startswith("十"):
        return 10 + _CN_NUM.get(s[1], 0)
    if s.endswith("十"):
        return _CN_NUM.get(s[0], 0) * 10
    if "十" in s:
        a, _, b = s.partition("十")
        return _CN_NUM.get(a, 0) * 10 + _CN_NUM.get(b, 0)
    return None


# 从政策文本中提取「注销路径」之类的操作性描述
_PATH_PATTERNS = [
    re.compile(r"(?:进入|打开|点击|前往|通过)[^。；\n]{0,60}?(?:设置|我的|个人中心|账号|安全)[^。；\n]{0,80}"),
    re.compile(r"(?:【[^】]{1,20}】[\-—>→]{0,2}){2,}"),          # 【我的】-【设置】-【注销】
    re.compile(r"(?:我的|个人中心|设置)[^\n。；]{0,10}(?:[-—>→]{1,2}|→)[^\n。；]{0,60}"),
]


def _extract_paths(text: str, anchor: int, window: int = 220) -> List[str]:
    seg = text[max(0, anchor - 60): anchor + window]
    out: List[str] = []
    for pat in _PATH_PATTERNS:
        for m in pat.finditer(seg):
            s = m.group(0).strip(" -—>→·、")
            if 4 <= len(s) <= 90 and s not in out:
                out.append(s)
    return out[:4]


# ---------------------------------------------------------------- 抓取

def fetch(url: str, timeout: int = 25,
          log: Optional[Callable[[str], None]] = None) -> PolicyResult:
    log = log or (lambda *_: None)
    res = PolicyResult(url=url, source="url")
    if not url:
        res.error = "未提供隐私政策链接"
        return res
    if not re.match(r"^https?://", url, re.I):
        res.error = "隐私政策链接不是 http/https：%s" % url
        return res

    log("[*] 抓取隐私政策：%s" % url)
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            res.final_url = resp.geturl()
            ctype = resp.headers.get("Content-Type", "")
            raw = resp.read(MAX_HTML_BYTES)
    except urllib.error.HTTPError as e:
        res.error = "HTTP %s %s" % (e.code, e.reason)
        return res
    except Exception as e:
        res.error = "%s: %s" % (type(e).__name__, e)
        return res

    body = _decode(raw, ctype)
    if "html" in ctype.lower() or re.search(r"<html|<div|<p\b", body[:2000], re.I):
        text, title = html_to_text(body)
    else:
        text, title = body.strip(), ""

    res.text = text
    res.title = title
    _structure(res)
    res.ok = bool(text)
    if len(text) < 300:
        res.error = (res.error or "") + (
            "抓取到的正文过短（%d 字），该页面可能是 JS 动态渲染，"
            "需要人工把政策全文粘贴进来" % len(text))
    log("[*] 政策正文 %d 字，标题：%s" % (len(text), title or "（无）"))
    return res


def from_text(text: str, title: str = "") -> PolicyResult:
    """直接接收粘贴/上传的政策全文。"""
    res = PolicyResult(source="text", text=(text or "").strip(), title=title)
    _structure(res)
    res.ok = bool(res.text)
    return res


# ---------------------------------------------------------------- 结构化

def _structure(res: PolicyResult) -> None:
    t = res.text or ""
    if not t:
        return
    res.has_policy_text = len(t) >= 300

    # --- 纯文本要素 ---
    if _R["cancel"].search(t):
        res.has_cancel_account = True
        m = _R["cancel"].search(t)
        res.cancel_paths = _extract_paths(t, m.start()) if m else []

    if _R["complaint"].search(t):
        res.has_complaint = True

    if _R["correct_delete"].search(t):
        res.has_correct_delete = True
        m = _R["correct_delete"].search(t)
        res.correct_delete_paths = _extract_paths(t, m.start()) if m else []

    res.withdraw_consent = bool(_R["withdraw"].search(t))
    res.third_party_mentioned = bool(_R["third_party"].search(t))
    res.children_rule = bool(_R["children"].search(t))

    # --- 联系方式 ---
    res.contact_info = list(dict.fromkeys(_R["email"].findall(t)))[:5]
    phones = list(dict.fromkeys(_R["phone"].findall(t)))[:5]
    res.contact_info += phones

    # --- 投诉渠道 = 明确的联系方式 + 投诉关键词 ---
    if res.has_complaint:
        res.complaint_channels = list(res.contact_info)
        for kw in ("在线客服", "意见反馈", "在线投诉", "投诉入口", "反馈入口", "举报入口"):
            if kw in t:
                res.complaint_channels.append(kw)
        res.complaint_channels = list(dict.fromkeys(res.complaint_channels))[:8]

    # --- 处理时限：取全部命中里的最大值（保守，避免漏报超期）---
    days: List[int] = []
    for m in _R["days"].finditer(t):
        v = _cn_to_int(m.group(1))
        if v:
            days.append(v)
    res.processing_days = max(days) if days else None

    # --- 第三方名称 ---
    if res.third_party_mentioned:
        names: List[str] = []
        # APK 内嵌 SDK 库里的名字若出现在政策文本里，说明政策有列明
        for pkg, name, typ, _a in resources.sdk_library():
            if name and len(name) >= 4 and name in t:
                names.append(name)
        # 常见第三方公司名
        for m in re.finditer(r"([\u4e00-\u9fa5]{2,20}(?:有限公司|股份公司|科技公司))", t):
            n = m.group(1)
            if n not in names:
                names.append(n)
        res.third_party_names = names[:40]

    # --- 声明收集的个人信息类型（行为码维度 + 个人信息类型维度）---
    declared: List[str] = []
    types: List[str] = []
    for code, words in resources.policy_words().items():
        hit = [w for w in words if w and w in t]
        if hit:
            declared.append(code)
            types.extend(hit)
    # 补充：用 signal_map 的个人信息类型词表再扫一遍。
    # 只靠沙箱的 privacyconfig.txt（24 条，偏设备类）覆盖面不够，
    # 会把"政策其实写了但词典没收录"的项误判为未声明 —— 这是误报的主要来源。
    try:
        from .rules.rulebase import signal_map
        for pid, pv in (signal_map().pi or {}).items():
            terms = [x for x in (pv.get("policy_terms") or []) if x]
            hit = [x for x in terms if x in t]
            if hit:
                declared.append(pid)
                types.extend(hit)
    except Exception:
        pass
    res.declared_behaviors = list(dict.fromkeys(declared))
    res.declared_types = list(dict.fromkeys(types))[:80]


# ---------------------------------------------------------------- 政策定位辅助

_POLICY_LINK = re.compile(
    r"(隐私|协议|政策|条款|privacy|policy|agreement|statement|protocol|terms)", re.I)


def candidate_urls(static_result) -> List[str]:
    """从静态分析结果里挑出最可能是「隐私政策」的链接，用于自动抓取。"""
    out: List[str] = []
    for u in (static_result.policy_urls or []):
        if u not in out:
            out.append(u)
    return out[:10]


# --------------------------------------------------------------------- 归属核验
# 第三方 SDK 自带的隐私政策品牌名。真机实测（赣警办 P4 深挖）：遍历点进了
# 「意见反馈」里的腾讯兔小巢页面，它的《隐私保护指引》比 App 自己的政策还长，
# 于是把 App 政策正文覆盖掉了 —— 报告里"未成年人专门规则已载明""个性化推荐
# 已说明"这类结论，全是对着**第三方 SDK 的政策**下的。文档拿错了，结论必然错。
_THIRD_PARTY_BRANDS = (
    "腾讯", "兔小巢", "友盟", "极光", "个推", "阿里云", "百度", "新浪", "微博",
    "支付宝", "微信", "穿山甲", "字节跳动", "今日头条", "华为", "小米", "OPPO",
    "vivo", "神策", "GrowingIO", "TalkingData", "Sensors", "Bugly", "Firebase",
    "Facebook", "Google", "AppsFlyer", "Adjust", "Umeng", "JPush",
)

# 政策文本开头的自我指称。第三方 SDK 的政策往往在这里自报家门
# （"腾讯兔小巢隐私保护指引"），而 App 自己的政策会写"本政策适用于 XXX"。
_SELF_REF_HEAD = 220

# 「这像不像隐私政策」的正向判据词。
# 真隐私政策开头必然交代"隐私 / 个人信息"，这是文本类型本身的特征，
# 不依赖具体 App 的措辞。
_PRIVACY_WORDS = ("隐私", "个人信息")

# 反过来，"协议 / 条款 / 购买须知"这类文本常常也很长、也是同一站点，
# 混进来会把隐私政策顶掉（实测：以观书法《VIP会员服务协议》2674 字）。
_CONTRACT_WORDS = ("用户协议", "服务协议", "服务条款", "使用条款", "会员协议",
                   "会员服务协议", "购买渠道", "会员价格", "退订")


# ---------------------------------------------------------------- 文档类型
# 为什么要把「一份文档是什么」单独成一层（Hi投屏 2026-10-28 用户意见）：
#   该 App 首启弹窗里同时开着《隐私政策》《用户协议》《第三方共享数据清单》。
#   采集侧把 WebView 加载到的 `/protocol/share`（第三方共享数据清单）当成了
#   政策正文 —— 因为它也通篇在谈"个人信息"，`looks_like_privacy_policy`
#   一路绿灯。报告于是把共享清单摆成"隐私政策"，链接也指向了共享清单。
#   文档类型判错，后面每一条政策类结论都会对着错的文档下。
#
# 这四类文档对检测都**有用**（用户明确要求全部展示），所以不是简单"拒收"，
# 而是先分类、再按类各归各位：
#   · 隐私政策        → 条款比对的主依据
#   · 用户协议        → 只作旁证（很多 App 把收集规则写在协议里）
#   · 未成年人规则    → 「专门规则是否载明」类判定的直接依据
#   · 收集清单/共享清单 → 「是否逐一列明接收方」类判定的直接依据
DOC_KINDS: Dict[str, str] = {
    "privacy": "隐私政策",
    "user_agreement": "用户协议/服务协议",
    "minor_policy": "未成年人（儿童）个人信息保护规则",
    "collection_list": "收集个人信息清单",
    "third_party_list": "第三方共享（SDK）清单",
    "permission_list": "权限使用说明",
    "other": "其它文档",
}

# 判定顺序即优先级：越靠前的越具体，避免"隐私政策里提到共享清单"被误判成清单。
_DOC_RULES: List[tuple] = [
    # ★ 未成年人规则要求"自称"（高途 2026-10-30）：
    #   原来只要正文出现"未成年"三个字就判 minor_policy —— 而几乎每份用户协议
    #   都会写一句"未成年人应在监护人陪同下阅读"，告知语里也会提《儿童隐私保护规则》。
    #   结果高途的《用户服务协议》（3180 字）被判成未成年人规则，首启告知语
    #   （279 字）也被判成未成年人规则，真正的隐私政策反而没找到。
    #   改为只认**完整文档名**：文档在开头自称是什么，才算什么。
    ("minor_policy", ("未成年人个人信息保护规则", "未成年人个人信息保护政策",
                      "未成年人隐私政策", "未成年人保护规则", "未成年人个人信息保护指引",
                      "儿童个人信息保护规则", "儿童个人信息保护政策", "儿童隐私政策",
                      "儿童个人信息保护指引", "青少年模式", "children's privacy")),
    ("third_party_list", ("第三方共享", "共享清单", "共享数据清单", "第三方信息共享",
                          "第三方sdk清单", "sdk清单", "接入第三方", "第三方目录",
                          "共享个人信息", "对外提供清单")),
    ("collection_list", ("收集个人信息清单", "个人信息收集清单", "已收集个人信息清单",
                         "收集清单", "个人信息清单", "权限与个人信息")),
    ("permission_list", ("权限说明", "权限列表", "权限使用说明", "权限申请与使用")),
    ("privacy", ("隐私政策", "隐私协议", "隐私权政策", "隐私保护指引", "隐私保护政策",
                 "个人信息保护政策", "privacy", "yinsi")),
    ("user_agreement", ("用户协议", "服务协议", "服务条款", "使用条款", "用户注册协议",
                        "会员服务协议", "购买须知", "agreement", "terms")),
]


def _doc_sig(text: str, lines: int = 3, limit: int = 160) -> str:
    """取"自我指称区"：标题行 + 开头几行。类型判定只看这一小段。

    为什么不看全文：隐私政策里必然会用大段篇幅谈"第三方共享清单"「收集个人
    信息清单」，按全文统计永远会被更具体的词抢走；而一份文档**自称**是什么，
    只会出现在标题与开头。

    `lines`/`limit` 可放宽 —— 有些 App 的政策页开头是一大段欢迎语，
    真正的自指语句要读到第 4~6 行才出现（携船网 2026-10-30）。
    """
    body = (text or "").strip()
    got = [x.strip() for x in body.splitlines() if x.strip()][:max(1, lines)]
    return "\n".join(got)[:max(20, limit)].lower()


# 协议类"强自称"：开头就写这句，基本可以断定是协议而不是政策。
_SELF_AGREEMENT = ("本协议由您", "本协议由你", "本协议是您", "本协议是用户",
                   "本协议乃", "共同缔结")


def classify_doc(text: str, title: str = "", url: str = "") -> str:
    """判断一份文档属于哪一类（返回 `DOC_KINDS` 的键）。

    判据优先级：标题 → 正文自我指称区 → 链接路径 → 全文兜底。
    都判不出来时返回 `other`（**不**默认成隐私政策 —— 猜成政策就等于
    拿错文档去做条款比对，比不判更糟）。
    """
    # ★ 结构化数据不是文档（看个比赛 2026-10-29）：
    #   `https://cgi.connect.qq.com/qqconnectopen/openapi/policy_conf` 返回的是
    #   QQ 互联的 SDK 配置 JSON（`{"Agent_ReportBatchCount":5,…}`），URL 里的
    #   "policy" 让下面的路径规则把它判成隐私政策 —— 1470 字配置被当成第二份
    #   政策正文留在报告里，复核员点开全是花括号。
    #   整段能被 json 解析是硬证据，排在标题之前判：标题写着"隐私政策"也不算，
    #   因为那多半是采集侧按入口名称给的默认标题，不是文档自称。
    if (text or "").strip()[:1] in ("{", "["):
        try:
            _json.loads((text or "").strip())
            return "other"
        except Exception:
            pass
    name = (title or "").strip().lower()
    if name:
        for kind, words in _DOC_RULES:
            if any(w in name for w in words):
                return kind
    sig = _doc_sig(text)
    body = (text or "").strip()
    # ---- 自称区判定（2026-10-30 携船网 / 高途实测后重排）----
    # ★ 原实现把六类塞进同一个 160 字窗口按顺序匹配，两个反例：
    #   ① 携船网的《隐私政策》开头是「欢迎您使用携船网！在使用携船网前，您应当
    #      阅读并遵守《携船网用户服务协议》…」，160 字里只截到"用户协议"，
    #      8271 字的政策原文被拒收，报告写"未取得政策正文"；
    #   ② 高途的《用户服务协议》因为末句"未成年人应在监护人陪同下阅读"被判成
    #      未成年人规则（已通过要求"完整文档名"修掉）。
    #   现在分三步：具体文档类型（清单/权限/未成年人）→ 协议强自称 →
    #   放宽到 400 字找"隐私政策"且全文确实在谈个人信息 → 其余协议关键词。
    for kind, words in _DOC_RULES:
        if kind in ("user_agreement", "privacy"):
            continue                    # 这两类留到后面按强度判
        if sig and any(w in sig for w in words):
            return kind
    if sig and any(w in sig for w in _SELF_AGREEMENT):
        return "user_agreement"
    _wide = _doc_sig(text, lines=8, limit=400)
    if ("隐私政策" in _wide or "隐私协议" in _wide) and body.count("个人信息") >= 5:
        return "privacy"
    if sig:
        for kind, words in _DOC_RULES:
            if kind == "user_agreement" and any(w in sig for w in words):
                return kind
            if kind == "privacy" and any(w in sig for w in words):
                return kind
    u = (url or "").lower()
    if u:
        # 路径是最弱的证据，但比"什么都不看"强：/protocol/share 一眼就是清单。
        for kind, words in (
            ("third_party_list", ("/share", "shared", "third")),
            ("collection_list", ("/collect", "collection", "/list")),
            ("minor_policy", ("minor", "child", "teen")),
            ("user_agreement", ("agreement", "protocol/user", "terms")),
            ("privacy", ("privacy", "private", "yinsi", "policy")),
        ):
            if any(w in u for w in words):
                return kind
    body = (text or "").strip()
    if len(body) >= 200:
        head = body[:400]
        if any(w in head for w in _PRIVACY_WORDS):
            return "privacy"
    return "other"


def doc_kind_label(kind: str) -> str:
    return DOC_KINDS.get(kind or "", DOC_KINDS["other"])


def is_policy_kind(kind: str) -> bool:
    """这类文档能不能当"隐私政策"用于条款比对。

    未成年人规则是隐私政策的**专门分册**，可以当政策看；
    用户协议 / 各类清单 / 权限说明都不能 —— 它们回答的是别的问题。
    """
    return kind in ("privacy", "minor_policy")


# 系统"把这个链接交给谁"时插进来的界面，以及常见外部浏览器。
# 命中即说明政策**没有在被测应用内打开** —— 既不能截"政策页"，也不能读正文。
_EXTERNAL_APP_MARKS = (
    "chooseractivity", "resolveractivity", "intentresolver",
    "com.android.internal.app", "android/com.android.internal.app",
    "com.android.browser", "com.android.chrome", "com.sec.android.app.sbrowser",
    "com.miui.securitycenter", "com.android.packageinstaller",
)


def is_external_app_focus(focus: str, package: str = "") -> bool:
    """这个前台页面是不是"系统组件/外部应用"，而不是被测应用自己。

    作业帮 2026-10-30：点「《作业帮用户隐私政策》」后前台变成
    `android/com.android.internal.app.MiuiChooserActivity` —— 系统在问
    "用哪个浏览器打开"。只看"前台变了"就判"已进入政策页"，等于把系统选择器
    当成政策页留证，后面的浏览器搜索页也被当成了"政策正文页"。
    """
    f = (focus or "").strip().lower()
    if not f:
        return False
    if package and f.startswith(package.strip().lower() + "/"):
        return False
    if any(m in f for m in _EXTERNAL_APP_MARKS):
        return True
    # 只有类名、没有包名（`dumpsys` 偶尔只给出 `.BrowserActivity`，高途 2026-11-05）：
    # 没有包名就没法做"是不是被测应用"的前缀比较，只能按类名认。
    # 只认这三个系统约定名，不把它扩成"任何带 browser 字样的东西"。
    return "/" not in f and any(
        m in f for m in ("browseractivity", "chooseractivity", "resolveractivity"))


# 首启弹窗告知语的特征句。这类文字谈的是"我们要收集什么、请你阅读政策"，
# 不是条款本身 —— 拿它当政策正文，后面所有"政策写没写 XX"的结论都作废。
_NOTICE_HINTS = (
    "请您务必", "请务必仔细阅读", "特向您说明", "作出授权与否", "请您认真阅读",
    "请您仔细阅读", "感谢您下载", "感谢您使用", "感谢您的下载",
    "我们非常重视您的个人信息", "点击同意", "阅读并同意",
    # 2026-11-05 万步健康实测：它的首启弹窗写的是「请你务必审慎阅读」
    # （"你"不是"您"），上面那一串一条都命中不了，于是这块弹窗被当成
    # 可代填的登录页处理，55 分钟后报告只写"未找到手机号输入框"。
    "请你务必", "审慎阅读",
)
# 政策条款极少短于 700 字；短于此且带告知语特征的，一律按告知摘要处理。
NOTICE_MAX_CHARS = 700


def has_notice_phrase(text: str) -> bool:
    """正文里有没有**告知语特征句**（不看长度）。

    与 `is_notice_summary` 的分工：那个要回答"这段文字够不够格当政策正文"，
    所以把"短"也算成一种证据；这个只回答"这屏是不是隐私弹窗"，
    不能拿长度说事 —— 登录方式选择页（"微信登录/验证码登录/账号密码登录"）
    也只有几十个字，按长度判会把登录页判成弹窗。

    ★ 刻意**用窄表**，不收"阅读并同意""点击同意"：那是登录页勾选框上的字
      （"我已阅读并同意《用户协议》"），收进来会把三选一登录页判成弹窗，
      登录代填那条路就断了。这里只收弹窗正文里才会出现的句子。
    """
    body = (text or "").strip()
    return bool(body) and any(w in body for w in _NOTICE_BODY_HINTS)


# 只出现在**弹窗正文**里的句子（勾选框上不会这么写）。
_NOTICE_BODY_HINTS = ("请您务必", "请你务必", "审慎阅读", "特向您说明",
                      "作出授权与否", "感谢您下载", "感谢您使用",
                      "我们非常重视您的个人信息")


def is_notice_summary(text: str) -> bool:
    """这段文字是不是**首启弹窗的告知摘要**（而不是政策条款正文）。

    ★ 为什么必须单独判（春雨诊所 / 高途 2026-10-30）：
      春雨诊所报告里的"隐私政策全文"是 359 字，开头「感谢您使用春雨诊所！
      为了便于您详细了解您的权利和义务，请您务必仔细阅读…特向您说明如下」——
      那是弹窗上那段告知语。高途更短：279 字，还因为末尾提到
      《儿童隐私保护规则》被判成了"未成年人个人信息保护规则"。
      两轮的报告都写着"已取得政策正文"，实际一个字条款都没有。

    判据（任一成立即为告知摘要）：
      · 短于 300 字 —— 任何一份完整政策都不可能这么短；
      · 300~700 字之间，且开头出现告知语特征句（"请您务必""特向您说明"…）。
    长于 700 字的一律不判（宁可放过，也不要把简短政策误杀）。
    """
    body = (text or "").strip()
    if not body:
        return True
    if len(body) >= NOTICE_MAX_CHARS:
        return False
    if len(body) < 300:
        return True
    head = body[:600]
    return any(w in head for w in _NOTICE_HINTS)


def looks_like_privacy_policy(text: str, title: str = "") -> bool:
    """这份正文像不像**隐私政策**（而不是会员/用户协议、活动规则）。

    为什么需要（以观书法 5.4.2 实测，代价很大）
    -------------------------------------------
    首启阶段拿到了真正的《以观书法隐私政策》（1652 字），P4 遍历时又点开了
    《VIP会员服务协议》（2674 字）——**同站点、更长**，于是按"同站点取更长"
    把它覆盖了。接下来整份报告的政策类结论都是对着会员协议做的：
    「实际收集了设备属性、政策未列明」直接判成**认定**（fail），
    而真政策里写没写设备信息，根本没人看。文档拿错，结论必错。

    判据（都要求"正向证据"，避免把好的政策误杀）
    --------------------------------------------
      ① 开头 400 字出现「隐私」或「个人信息」→ 是；
      ② 开头是合同类词（协议/条款/购买渠道…）且全篇几乎不谈个人信息 → 不是；
      ③ 兜底：正文里「个人信息」反复出现（≥5 次）且出现「隐私」→ 是。
    其余情况一律判"不是"——宁可让 P2 走"未取得正文"的保守分支，
    也不要拿一份协议去当隐私政策下结论。
    """
    body = (text or "").strip()
    if len(body) < 200:
        return False
    # ---- 先过"文档类型"闸门 ----
    # ★ 这一步不能省（Hi投屏 2026-10-28）：《第三方共享数据清单》同样满篇
    #   "个人信息 / 隐私"，走下面三条判据会一路通过，被当成政策正文。
    #   类型判成"用户协议 / 清单 / 权限说明"的，一律不算隐私政策。
    kind = classify_doc(body, title or "")
    if kind in ("user_agreement", "collection_list", "third_party_list",
                "permission_list"):
        return False
    head = body[:400]
    if any(w in head for w in _PRIVACY_WORDS):
        return True
    scan = body[:6000]
    # ★ 判据②原实现与注释不一致（携船网 2026-10-30）：注释写的是"合同类词
    #   **且全篇几乎不谈个人信息**"，代码却只判了前半句 —— 于是政策页开头
    #   那句「在使用携船网前，您应当阅读并遵守《携船网用户服务协议》…」
    #   直接把 8271 字的真政策否掉了，报告写"未取得政策条款"。
    #   现在按注释的本意：开头有合同词、且正文确实不谈个人信息，才否。
    if any(w in head for w in _CONTRACT_WORDS):
        if scan.count("个人信息") < 5:
            return False
    return scan.count("个人信息") >= 5 and "隐私" in scan


# 已知第三方 SDK 厂商的政策站域名。命中即判"这份不是被测 App 的政策"，
# 不必等正文写完 —— 实测（免费手机投屏神器 2026-10-26）：
#   该 App 的 APK 里同时登记了自家政策链接和穿山甲、QQ互联等的 SDK 政策链接，
#   `fetch_policy_by_url` 按"最长正文"选中了 www.pangle.cn（9971 字），
#   报告据此把一份《穿山甲广告SDK隐私政策》当成了 App 自己的政策。
_SDK_POLICY_HOSTS = (
    "pangle.cn", "csjplatform.com", "pangolin-sdk-toutiao.com",
    # 字节系 CDN / 落地页：穿山甲的政策常常托管在这些域名上，
    # 只认 pangle.cn 会漏掉「sf6-ttcdn-tos.pstatp.com/obj/ad-tetris-site/…」
    # 这种同内容不同域名的落地页（免费手机投屏神器 2026-10-26 实测）。
    # 只收 CDN 类域名 —— 不写 bytedance.com / toutiao.com：
    # 被测应用本身可能就是字节系产品，那两处可能就是它自己的政策页。
    "pstatp.com", "snssdk.com", "bytesmanager.com",
    "umeng.com", "jpush.cn", "getui.com", "igexin.com",
    "growingio.com", "talkingdata.com", "sensorsdata.cn", "bugly.qq.com",
    "appsflyer.com", "adjust.com", "mintegral.com", "mtgspan.com",
    "baidu.com/union", "tanx.com", "alipay.com/privacy", "unionpay.com",
    "kuaishou.com", "kwai.com", "oppomobile.com", "vivo.com.cn",
)


POLICY_MIN_CHARS = 1200


def settle_outcome(cap: Dict[str, Any]) -> str:
    """结论必须与"手上到底有没有正文"自洽，返回（可能被修正后的）outcome。

    ★ 镜像投屏 4.0（2026-11-09）实测：首启阶段没找到入口，结论定成 `no_entry`；
      之后的**遍历阶段**才把政策打开、读到 28879 字。同一份报告里于是出现
      "未观测到政策入口"＋"政策正文 28879 字"，读者只能怀疑整份报告。
      采集侧已经在首启收尾时自洽过一次，但"正文是遍历阶段才补上的"这条路径
      到不了那里 —— 所以在 SOP 层（P2 开头）再结算一次，覆盖全部路径，
      顺带也把历史存档重渲染时的这个矛盾修掉。

    只在"确实拿到了足量正文、结论却说没拿到"这个方向上修：反向
    （有结论没正文）不在这里动 —— 那需要重新取证，不是改字段能解决的。
    """
    cap = cap or {}
    oc = str(cap.get("outcome") or "")
    n = len((cap.get("bestText") or "").strip())
    if n < POLICY_MIN_CHARS:
        return oc
    if oc in ("", "not_run", "no_entry", "no_text", "notice_only",
              "external_unverified", "error_page"):
        cap["outcome"] = "full_inline"
        cap.setdefault("notes", []).append(
            "结论修正：入口判定原记为「%s」，但本轮实际取得政策正文 %d 字"
            "（取得方式：%s），按实证改为「已取得条款正文」"
            % (oc or "（空）", n, cap.get("bestTextFrom") or "界面读取"))
        return "full_inline"
    return oc


def no_url_reason(cap: Dict[str, Any]) -> str:
    """正文拿到了、却没有可访问链接时，**说清楚为什么没有**。

    ★ 用户 2026-11-09 第 1 条（Q船）：「隐私政策页面确实点开了，正文确实也记录了，
      但仍说本次未记录到可访问地址，为什么？既然能通过页面侧获取，为什么会没有
      拿到页面的链接？」—— 答案是这类应用的政策**根本不通过网络地址加载**：
      它把 HTML 直接塞给 WebView（`loadDataWithBaseURL`，URL 恒为 about:blank），
      或者读 APK 里的本地资源文件。链不存在，不是我们漏记。
      报告必须写清是哪一种，否则复核员只能读成"采集器又漏了"。
    """
    cap = cap or {}
    kind = str(cap.get("bestTextSourceKind") or "")
    # ★ 两个键名都认：采集侧写的是 bestTextRawForm，早期版本写 bestTextSourceRaw。
    #   只认其中一个，历史存档就一律落到最后那个笼统说法上。
    raw = str(cap.get("bestTextRawForm") or cap.get("bestTextSourceRaw") or "")
    # ★ 老存档没有 bestTextSourceKind（那个字段是 2026-11-09 才加的）。
    #   直接看正文开头就能判：以 `<` 开头且带标签的，就是 HTML 源码兜底。
    if not kind:
        _body = (cap.get("bestText") or "").lstrip()
        if _body.startswith("<"):
            kind = "inline_html"
            raw = raw or "HTML 源码（%d 字）" % len(_body)
    if kind == "inline_html":
        return ("政策正文由应用直接把 HTML 内容交给内嵌浏览器渲染"
                "（WebView.loadDataWithBaseURL，页面地址恒为 about:blank），"
                "应用未通过任何网络地址加载该政策，因此**客观上不存在可访问链接**"
                "（不是漏记）。已按页面实际显示的文字记录全文")
    if kind == "local_file":
        return ("政策正文取自应用本地资源文件（%s），未通过网络地址加载，"
                "因此无可访问链接（不是漏记）；该文件随安装包分发，"
                "版本更新时内容可能变化" % (raw or "file:///…"))
    if kind == "other" and raw:
        return ("政策正文取自应用内页面（来源标识：%s），该来源不是 http(s) 地址，"
                "因此无可访问链接（不是漏记）" % raw[:60])
    if cap.get("_notInjected"):
        return ("本轮注入受限（应用带加固保护，注入后无法留存会话），"
                "WebView 地址通道不可用，因此未取得页面地址；"
                "正文已按页面实际显示的文字记录，链接需人工在真机确认")
    return ""


def policy_host_reason(url: str) -> str:
    """政策链接的域名本身就能说明"这是谁的政策"时，直接给一句理由。

    与 `third_party_reason` 的分工：那条靠**正文**判，这条靠**来源**判。
    正文有空导航栏、有改版，来源域名不会变，所以先判来源更稳。
    """
    u = (url or "").strip().lower()
    if not u.startswith("http"):
        return ""
    host_path = u.split("://", 1)[-1]
    for pat in _SDK_POLICY_HOSTS:
        if pat in host_path:
            return ("该政策正文取自第三方 SDK 厂商的政策页（%s），"
                    "不是被测应用自身的隐私政策" % host_path.split("?")[0][:80])
    return ""


def third_party_reason(text: str, app_name: str = "", package: str = "",
                       url: str = "") -> str:
    """判断这份政策正文是不是**第三方 SDK 的**（而不是被测 App 的）。

    返回 "" 表示没发现问题（**不是"确证是 App 的"**，只是没有第三方特征）；
    返回非空字符串时，那是一句可以直接写进报告的理由。

    判据（命中任一条即成立，都带反误杀保护）：
      ⓪ 来源域名属于已知 SDK 厂商（`policy_host_reason`）；
      ① 文中出现第三方品牌名，且
      ② 开头（自我指称区）**没有**出现被测 App 的名字或包名里的可辨识词。
    反例保护：App 本身叫「腾讯新闻」时，① 命中「腾讯」但 ② 也命中（开头就写了），
    不会误判成第三方。
    """
    _h = policy_host_reason(url)
    if _h:
        return _h
    body = (text or "").strip()
    if not body:
        return ""
    head = body[:_SELF_REF_HEAD]
    # App 的可辨识词：名称（去掉"App/客户端"这类后缀）+ 包名里长度≥4 的段。
    tokens: List[str] = []
    nm = (app_name or "").strip()
    for junk in ("App", "APP", "客户端", "手机版", "官方版"):
        nm = nm.replace(junk, "")
    if len(nm) >= 2:
        tokens.append(nm)
    for seg in (package or "").split("."):
        if len(seg) >= 4 and seg.isascii() and seg.isalpha():
            tokens.append(seg)
    if any(t and t in head for t in tokens):
        return ""
    # ★ 品牌名只在**标题区**里找，不在正文里找：
    #   App 自己的政策也常在开头提"接收方包括友盟等合作伙伴"，
    #   拿正文命中当"这是友盟的政策"，会把 App 的政策误排掉（测试里就撞到过）。
    #   第三方 SDK 的政策必然在标题里自报家门（"腾讯兔小巢隐私保护指引"）。
    #
    # ★ 标题区不能再取"第一行"（2026-10-27 实测）：
    #   pangle.cn 那份抓下来开头是网页导航 ——
    #     "首页 / 产品中心 / 解决方案 / 登录立即注册 / 首页/协议条款 /
    #      隐私政策 / 穿山甲广告SDK隐私政策"
    #   第一行是「首页」，品牌一个都不在里面，于是漏判、拿 SDK 政策当 App 政策。
    #   改为在自我指称区里找**像标题的短行**（≤40 字，且含"隐私/政策/协议/指引"）。
    title_zone = _policy_title_line(head) or (head.splitlines()[0][:40]
                                              if head.splitlines() else head[:40])
    hit = next((b for b in _THIRD_PARTY_BRANDS if b in title_zone), "")
    if not hit:
        return ""
    title = title_zone.strip("\"'“”「」 	")
    return ("该政策正文的出具方是第三方（开头为「%s」，出现品牌「%s」），"
            "不是被测应用自身的隐私政策" % (title, hit))


def _policy_title_line(head: str) -> str:
    """在自我指称区里挑一行"最像标题"的文本（用于认第三方品牌）。

    不做文本理解，只按形态挑：短、含标题词、不含导航符号。
    挑不出来就返回空串，由调用方退回"第一行"。
    """
    best = ""
    # ★ 先丢掉空行再取前 N 行：网页正文的换行经常是双换行（一个空行一断），
    #   不过滤的话 head 里只能看到前 6 个导航词，标题还在十几行之外 ——
    #   pangle 那份《穿山甲广告SDK隐私政策》就是这么漏掉的。
    lines = [ln.strip() for ln in (head or "").splitlines() if ln.strip()]
    for ln in lines[:14]:
        if not ln or len(ln) > 40:
            continue
        if not any(w in ln for w in ("隐私", "政策", "协议", "指引", "条款")):
            continue
        # 导航条式的一行塞很多项（"首页/协议条款/隐私政策"）不当标题
        if ln.count("/") >= 3:
            continue
        if len(ln) > len(best):
            best = ln
    return best


__all__ = ["PolicyResult", "fetch", "from_text", "html_to_text",
           "candidate_urls", "third_party_reason", "policy_host_reason"]
