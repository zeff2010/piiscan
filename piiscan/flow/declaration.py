"""声明清单的结构化解析，以及「按 SDK」的实测/声明对照。

## 为什么需要单独一层

`compare.py` 的差集是**类型 → 类型**：实际收集了 P01（设备标识符），政策里
有没有提过设备标识符。这能回答"政策写没写"，但回答不了人工报告里真正要写的话：

  · App 自己声明采集哪些个人信息（按功能场景）
  · 每个 SDK 声明采集哪些个人信息
  · **某个 SDK 实际采了 A/B，但清单里只写了 A**

这三件事都需要把清单拆成一条条 SDK 记录，而不是当成一大段文本做关键词匹配。

## 解析分两层：先规则，后模型

· 规则层：把清单切成 SDK 块（空行分块、序号分块、一行一条表格都见过），
  块内抽 名称 / 厂商 / 声明类型 / 目的 / 链接。可重复、可回指原文。
· 模型层：只在规则层抽不出内容（清单是图片、表格错行、只写"设备相关信息"这类
  笼统词）时介入。模型结果**只做加法**，且每一条都要能回到某一块原文。

## 厂商归组：不做"同名才算"

同一家大厂常常在同一份清单里列好几个 SDK（腾讯 Bugly / 腾讯云 / 优量汇），
而 App 里实际跑起来的可能是同厂商的另一个产品线。按 SDK 名字逐字比对，
会把"腾讯系已列明"判成"未列明"——这是高召回变成全量误报的典型。

所以对照时按**厂商集团**放宽：
  · 清单里列了这个厂商的任一 SDK → 同厂商的其他 SDK 记为「同厂商已列明」，
    不算未列明；但仍会在明细里写明"清单列的是 A，实际运行的是 B"，
    供复核员判断要不要按 SDK 粒度整改。
  · 整个厂商集团都没出现 → 才是真正的「未列明」。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import attribution as ATTR
from . import compare as CMP

Log = Callable[[str], None]
_NOP: Log = lambda *_a, **_k: None


# ---------------------------------------------------------------------------
# 厂商集团
# ---------------------------------------------------------------------------
# 只收"一家公司有多个 SDK 产品线、且政策里通常写品牌不写产品名"的厂商。
# 别名尽量宽（中文品牌 + 英文 + 常见包名根），因为清单里的写法五花八门：
# 有的写"腾讯云计算（北京）有限责任公司"，有的写"腾讯 Bugly"，有的只写"bugly"。
VENDOR_GROUPS: Dict[str, Tuple[str, ...]] = {
    "腾讯": ("腾讯", "tencent", "qq", "wechat", "微信", "广点通", "优量汇", "gdt",
             "bugly", "腾讯云", "tbs", "x5", "mmkv", "乐固", "灯塔", "beacon",
             "腾讯地图", "腾讯广告", "tinker", "weishi"),
    "字节跳动": ("字节", "bytedance", "穿山甲", "巨量", "pangle", "toutiao",
                 "今日头条", "抖音", "csj", "字节跳动", "轻量引擎", "自动化营销"),
    "阿里巴巴": ("阿里", "alibaba", "友盟", "umeng", "高德", "amap", "阿里云",
                 "aliyun", "uc", "夸克", "钉钉", "淘宝", "支付宝", "alipay",
                 "mtop", "阿里妈妈", "tanx", "mmstat", "emas", "神马"),
    "百度": ("百度", "baidu", "百青藤", "aiqiyi"),   # aiqiyi 是爱奇艺，单独成组更准确，见下
    "华为": ("华为", "huawei", "hms", "agconnect", "hicloud", "荣耀", "honor"),
    "小米": ("小米", "xiaomi", "mipush", "miui", "米聊"),
    "OPPO": ("oppo", "欧珀", "heytap", "coloros"),
    "vivo": ("vivo", "维沃"),
    "快手": ("快手", "kuaishou", "kwai"),
    "网易": ("网易", "netease", "易盾", "云信", "有态度"),
    "新浪": ("新浪", "sina", "weibo", "微博"),
    "360": ("360", "奇虎", "qihoo", "加固保", "jiagu"),
    "搜狐": ("搜狐", "sohu"),
    "美团": ("美团", "meituan", "大众点评"),
    "京东": ("京东", "jd", "jingdong"),
    "拼多多": ("拼多多", "pinduoduo"),
    "携程": ("携程", "ctrip", "trip"),
    "科大讯飞": ("讯飞", "iflytek", "xunfei"),
    "极光": ("极光", "jpush", "jiguang"),
    "个推": ("个推", "getui", "igexin"),
    "神策": ("神策", "sensorsdata", "sensors"),
    "TalkingData": ("talkingdata",),
    "Mob": ("mob", "sharesdk", "mobtech"),
    "声网": ("声网", "agora"),
    "融云": ("融云", "rongcloud"),
    "环信": ("环信", "easemob"),
}


def _has_cjk(s: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fa5]", s or ""))


def vendor_group(*names: str) -> str:
    """从若干写法（SDK 名 / 厂商名 / 包前缀）判断属于哪个厂商集团。

    取不到返回空串 —— 调用方按"单家厂商"处理，不做跨厂商放宽。
    """
    blob = " ".join(str(x or "") for x in names).lower()
    if not blob.strip():
        return ""
    for group, aliases in VENDOR_GROUPS.items():
        for a in aliases:
            a = (a or "").lower().strip()
            if not a:
                continue
            if _has_cjk(a):
                if a in blob:
                    return group
            else:
                # 拉丁别名要卡边界：`qq` 不能命中 `qqpinyin`，`uc` 不能命中 `include`
                if re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(a), blob):
                    return group
    return ""


# ---------------------------------------------------------------------------
# 文本切块
# ---------------------------------------------------------------------------

_NUM_PREFIX = re.compile(
    r"^\s*(?:\d{1,2}\s*[.、)）]|[（(]\s*\d{1,2}\s*[)）]|[一二三四五六七八九十]{1,2}\s*[、.])\s*")
_SDK_WORD = re.compile(r"sd[kK]", re.I)
_URL = re.compile(r"https?://[^\s）)】\]\"'，,；;]+")
_COMPANY = re.compile(
    r"[\u4e00-\u9fa5A-Za-z0-9（）()·\-]{2,40}?"
    r"(?:股份有限公司|有限责任公司|有限公司|集团有限公司|集团|科技公司|网络公司)")
_PI_HINT = re.compile(
    r"信息|标识|号码|位置|通讯录|通讯记录|短信|照片|相机|麦克风|录音|设备|"
    r"IMEI|IMSI|MAC|OAID|Android\s*ID|IP|地址|账号|账户|日志|剪贴板|应用列表",
    re.I)

# 表头行：命中的字段名足够多，就认定这行不是数据
_HEADER_FIELDS = ("名称", "提供方", "提供者", "收集", "目的", "方式", "链接",
                  "共享", "接收方", "类型", "场景", "功能", "用途", "隐私政策")


def _is_header(line: str) -> bool:
    hits = sum(1 for f in _HEADER_FIELDS if f in line)
    # 表头通常一行里有 3 个以上字段名；只有一两个的可能是正常句子
    return hits >= 3 and len(line) <= 120


def _clean(line: str) -> str:
    return re.sub(r"\s+", " ", (line or "")).strip()


def blocks(text: str) -> List[str]:
    """把清单/政策正文切成「一条记录的块」。

    三种版式都见过：
      · 每行一条（表格被 innerText 拍平）：行内有 SDK 名 + 公司 + 信息 + 目的；
      · 空行分段：一段讲一个 SDK；
      · 序号分段：1. 友盟SDK …  2. 腾讯Bugly …
    """
    lines = [_clean(x) for x in (text or "").splitlines()]
    lines = [x for x in lines if x and not _is_header(x)]
    if not lines:
        return []
    out: List[str] = []
    cur: List[str] = []
    cur_has_sdk = False

    def flush():
        nonlocal cur, cur_has_sdk
        if cur:
            out.append("\n".join(cur))
        cur, cur_has_sdk = [], False

    for ln in lines:
        numbered = bool(_NUM_PREFIX.match(ln)) and len(ln) > 6
        has_sdk = bool(_SDK_WORD.search(ln))
        new = False
        if numbered:
            new = True
        elif has_sdk and cur_has_sdk and (_PI_HINT.search(ln) or len(ln) > 60):
            # 两行都带 SDK：第二行是下一条记录（表格一行一条）
            new = True
        elif (not has_sdk) and _COMPANY.search(ln) and cur \
                and _PI_HINT.search(cur[-1]):
            # 表格被拍平后，第二条往往以公司名开头、行内没有 SDK 字样
            # （「Bugly Android 深圳市腾讯… 设备标识符…」）。
            # 判据：上一行已经出现了个人信息类型 → 这一行是新记录。
            new = True
        if new:
            flush()
        cur.append(_NUM_PREFIX.sub("", ln, count=1) if numbered else ln)
        cur_has_sdk = cur_has_sdk or has_sdk
    flush()
    return [b for b in out if len(b) >= 4]


def _clean_name(nm: str) -> str:
    """把清单里带出来的行号、半截括号去掉。

    第三方共享清单是一张表，被 innerText 拍平后行号会粘在名称前面：
      「5 阿里云推送」「11 友盟推送（高级版本」「16 神策」
    这些名字一旦进了报告正文（"按其所属厂商的已有声明视为已列明："），
    复核员读到的是一串看不懂的编号，等于没点名（西五街 2026-10-27 实测）。
    """
    s = (nm or "").strip()
    s = re.sub(r"^\d{1,2}[.、)）]?\s+", "", s)      # 去掉前导行号（1~99）
    s = re.sub(r"^[\s•·\-—]+", "", s)
    # 半截括号：截到左括号之前，避免 "友盟推送（高级版本" 这种断句
    if s.count("（") > s.count("）"):
        s = s.split("（")[0].strip()
    if s.count("(") > s.count(")"):
        s = s.split("(")[0].strip()
    return s.strip(" ：:、-—")[:40]


def _sdk_name(block: str) -> str:
    """块内取 SDK 名称；统一过一遍 `_clean_name`（行号、半截括号都在那里去掉）。"""
    return _clean_name(_sdk_name_raw(block))


def _sdk_name_raw(block: str) -> str:
    """块内取 SDK 名称。取不到返回空串（不编）。"""
    first = (block or "").splitlines()[0] if block else ""
    # 「友盟+移动统计SDK：...」「XxxSDK」这类，优先带 SDK 字样的那个短语
    m = re.search(r"([\u4e00-\u9fa5A-Za-z0-9+·\-（）() ]{2,40}?)\s*SDK", block, re.I)
    if m:
        nm = m.group(1).strip(" ：:、-—")
        if len(nm) >= 2:
            return nm[:40]
    # 「第三方名称：友盟同欣（北京）科技有限公司」
    m = re.search(r"(?:名称|提供方|提供者|接收方)[：:]\s*([^\n，,；;]{2,40})", block)
    if m:
        return m.group(1).strip()
    # 首行冒号前
    head = re.split(r"[：:]", first, 1)[0].strip()
    if 2 <= len(head) <= 40 and not _COMPANY.search(head):
        return head
    m = _COMPANY.search(block)
    if m:
        return m.group(0)[:40]
    return first[:40].strip()


def _company(block: str) -> str:
    m = _COMPANY.search(block or "")
    return m.group(0)[:60] if m else ""


def _purpose(block: str) -> str:
    m = re.search(r"(?:使用)?目的[：:为是]?\s*([^\n。；;]{2,60})", block)
    if m:
        return m.group(1).strip()
    m = re.search(r"用于([^\n。；;]{2,50})", block)
    if m:
        return ("用于" + m.group(1)).strip()
    # 表格被 innerText 拍平后没有「目的：」这种字段名，只剩一串按空格排的格子：
    #   「友盟统计SDK 友盟同欣… 设备标识符、位置信息 统计分析 https://…」
    # 此时取链接前最后一个短片段（通常就是"使用目的"那一格）。
    # 只接受 2~20 字、且本身不像个人信息类型的片段 —— 否则会把"设备标识符"当目的。
    u = _URL.search(block or "")
    if u:
        seg = block[:u.start()].strip()
        tok = re.split(r"[\s，,；;、]", seg)[-1].strip() if seg else ""
        if 2 <= len(tok) <= 20 and not _PI_HINT.search(tok):
            return tok
    return ""


# ---------------------------------------------------------------------------
# 声明记录
# ---------------------------------------------------------------------------

@dataclass
class DeclaredSdk:
    """清单里的一条 SDK 声明。"""
    name: str = ""
    vendor: str = ""                 # 公司全称（清单原文）
    group: str = ""                  # 厂商集团（腾讯/字节跳动…），可空
    pi_ids: List[str] = field(default_factory=list)
    pi_terms: List[str] = field(default_factory=list)   # 原文里的写法，可回指
    purpose: str = ""
    link: str = ""
    source: str = ""                 # 来自哪份文档（标题/URL）
    raw: str = ""                    # 原文块，供人工核对与模型复核

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "vendor": self.vendor, "group": self.group,
            "pi_ids": list(self.pi_ids), "pi_terms": list(self.pi_terms),
            "purpose": self.purpose, "link": self.link, "source": self.source,
            "raw": self.raw[:600],
        }


def parse_declared_sdks(docs: Sequence[Dict[str, str]],
                        sm: Optional[Dict[str, Any]] = None,
                        min_types: int = 1) -> List[DeclaredSdk]:
    """从若干份文档（政策正文 / 第三方共享清单 / SDK 清单）里抽出 SDK 声明。

    `docs` 每项形如 `{"title": …, "text": …, "url": …}`。
    只保留"有名称且至少声明了一类信息"的块 —— 一份正文里到处都是
    "本政策不适用于第三方 SDK"这种句子，不设门槛会把整篇文章都当成 SDK。
    """
    sm = sm or CMP._signal_map()             # noqa: SLF001  与既有口径共用同一份词表
    out: List[DeclaredSdk] = []
    seen: Dict[str, int] = {}

    for d in docs or []:
        text = (d or {}).get("text") or ""
        title = (d or {}).get("title") or (d or {}).get("url") or ""
        if not text.strip():
            continue
        for blk in blocks(text):
            name = _sdk_name(blk)
            if not name or len(name) < 2:
                continue
            types = CMP.declared_types([blk], sm)
            if len(types) < min_types:
                continue
            vendor = _company(blk)
            rec = DeclaredSdk(
                name=name, vendor=vendor,
                group=vendor_group(name, vendor),
                pi_ids=sorted(types),
                pi_terms=sorted({t for v in types.values() for t in v})[:12],
                purpose=_purpose(blk),
                link=(_URL.search(blk).group(0) if _URL.search(blk) else
                      ((d or {}).get("url") or "")),
                source=title,
                raw=blk,
            )
            key = _norm(rec.name)
            if key in seen:
                # 同一 SDK 在多份文档里出现：合并类型，保留更长的原文
                old = out[seen[key]]
                old.pi_ids = sorted(set(old.pi_ids) | set(rec.pi_ids))
                old.pi_terms = sorted(set(old.pi_terms) | set(rec.pi_terms))[:16]
                old.purpose = old.purpose or rec.purpose
                old.link = old.link or rec.link
                old.vendor = old.vendor or rec.vendor
                if len(rec.raw) > len(old.raw):
                    old.raw = rec.raw
                continue
            seen[key] = len(out)
            out.append(rec)
    return out


def parse_collect_lists(docs: Sequence[Dict[str, str]],
                        sm: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """解析「个人信息收集清单」：App 自己在哪个功能场景收集哪些信息。

    与 `parse_declared_sdks` 的区别：清单的主语是**功能场景**（注册登录、
    附近门店、发布内容），不是第三方。人工报告第 4 项要的正是这层
    "目的—场景—信息类型"的对应关系。
    """
    sm = sm or CMP._signal_map()             # noqa: SLF001
    out: List[Dict[str, Any]] = []
    for d in docs or []:
        text = (d or {}).get("text") or ""
        if not text.strip():
            continue
        for blk in blocks(text):
            if not _PI_HINT.search(blk):
                continue
            # 含有"SDK / 第三方"的块属于共享清单，不是 App 自身清单
            if re.search(r"SDK|第三方|合作方|接收方", blk, re.I):
                continue
            types = CMP.declared_types([blk], sm)
            if not types:
                continue
            scene = _scene_name(blk)
            if not scene:
                continue
            out.append({
                "scene": scene,
                "pi_ids": sorted(types),
                "pi_terms": sorted({t for v in types.values() for t in v})[:10],
                "source": (d or {}).get("title") or "",
                "raw": blk[:400],
            })
    # 同一场景合并
    merged: Dict[str, Dict[str, Any]] = {}
    for r in out:
        k = _norm(r["scene"])
        if k in merged:
            merged[k]["pi_ids"] = sorted(set(merged[k]["pi_ids"]) | set(r["pi_ids"]))
            merged[k]["pi_terms"] = sorted(
                set(merged[k]["pi_terms"]) | set(r["pi_terms"]))[:12]
        else:
            merged[k] = r
    return list(merged.values())[:60]


def _scene_name(block: str) -> str:
    first = (block or "").splitlines()[0] if block else ""
    head = re.split(r"[：:]", first, 1)[0].strip()
    head = re.sub(r"^(?:功能|场景|业务功能|使用场景)[：:]?", "", head).strip()
    if 2 <= len(head) <= 30 and not _COMPANY.search(head):
        return head
    m = re.search(r"(?:功能|场景|业务)[：:]\s*([^\n，,；;]{2,30})", block)
    return m.group(1).strip() if m else ""


def _norm(s: str) -> str:
    """归一化写法：去掉空格与标点、统一小写。"""
    return re.sub(r"[\s\u3000（）()【】\[\]《》〈〉、，,。.;；:：/|｜\\\-_~·\"'“”‘’+]",
                  "", str(s or "")).lower()


# ---------------------------------------------------------------------------
# 实测侧：按 SDK / App 自身聚合
# ---------------------------------------------------------------------------

APP_KEY = "__app__"
UNKNOWN_KEY = "__unknown__"


def observed_inventory(events: Iterable[Any], package: str = "",
                       sm: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """把采集事件按「谁采的」聚合：每个 SDK 采了哪些类型、哪些具体标识符。

    与 `CMP.collected_types()` 共用 `event_pi()` 的判定口径，只在**分组维度**上
    不同：这里按调用栈的归因结果分组，那边按类型分组。两处口径一致，
    报告里才不会出现"总量说 5 类、按 SDK 明细只列出 3 类"。
    """
    sm = sm or CMP._signal_map()             # noqa: SLF001
    idx = CMP.build_signal_index(sm)
    vocab = {v["id"]: v for v in CMP.pi_vocab(sm)}

    def _bucket(kind: str, name: str, vendor: str, prefix: str) -> Dict[str, Any]:
        return {"kind": kind, "name": name, "vendor": vendor,
                "group": vendor_group(name, vendor, prefix),
                "prefix": prefix, "count": 0, "before": 0,
                "pi": {}, "apis": set(), "stacks": []}

    out: Dict[str, Dict[str, Any]] = {}
    for e in events or []:
        pid, mem, _sg = CMP.event_pi(e, idx, vocab, sm)
        if not pid:
            continue
        stack = list(getattr(e, "stack", []) or [])
        if not stack:
            key, rec = UNKNOWN_KEY, _bucket("unknown", "未能归属", "", "")
        else:
            info = ATTR.analyze_stack(stack, package)
            k = info.get("owner")
            if k == "sdk":
                s0 = (info.get("sdk") or [{}])[0]
                name = ATTR.display_name(s0.get("name") or s0.get("prefix") or "未命名 SDK")
                # ★ 分组键不能只用厂商（金考典 2026-10-28）：腾讯一家有
                #   七巧板 / 图灵盾 / 优量汇 / 微信 OpenSDK 等好几个 SDK，
                #   按厂商聚合会把它们并成一条，报告于是写"实测采集到 1 个"——
                #   而栈里明明有 3 家不同的 SDK 在各自读信息。
                #   也**不能**只用全名：同一 SDK 在库里的多条登记名不同
                #   （友盟统计 / 友盟+ 移动统计），那样又会把一条拆成两条。
                #   厂商 + 包名根是这两者的中间粒度。
                key = "sdk:%s#%s" % (s0.get("vendor") or name,
                                     ATTR.frame_class(s0.get("prefix") or "")
                                     or (s0.get("prefix") or name))
                rec = _bucket("sdk", name, s0.get("vendor") or "", s0.get("prefix") or "")
                # 同厂商不同入口名时保留先到的名字
                old = out.get(key)
                if old and old.get("name") and old["name"] != name:
                    rec["name"] = old["name"] if len(old["name"]) <= len(name) else name
            elif k == "app":
                key, rec = APP_KEY, _bucket("app", "应用自身", package, package)
            elif k in ("framework", "transport"):
                # 系统框架 / 纯传输层栈：不是"谁决定要读"，不计入任何一方。
                # 这与 compare 的口径一致 —— 框架栈不能拿来给 App 定责。
                continue
            else:
                # framework / transport 之外的"未能归属"：既可能是混淆后的自研代码，
                # 也可能是没收录进 SDK 库的第三方库。**不能算到 App 头上**（会冤枉 App），
                # **也不能算成第三方 SDK 未列明**（会冤枉第三方）—— 单独归类，
                # 报告里如实写"未能归属"，把判断留给人工。
                root = (info.get("initiator") or "").rsplit(".", 1)[0] or "未归属"
                key = UNKNOWN_KEY + ":" + root
                rec = _bucket("unknown", "未能归属（%s）" % root, "", root)
        rec = out.setdefault(key, rec)
        rec["count"] += 1
        if getattr(e, "before_consent", False):
            rec["before"] += 1
        rec["apis"].add(getattr(e, "api", ""))
        p = rec["pi"].setdefault(pid, {
            "pi": pid, "name": vocab[pid]["name"], "class": vocab[pid].get("class", ""),
            "count": 0, "before": 0, "members": {}, "stacks": [],
        })
        p["count"] += 1
        if getattr(e, "before_consent", False):
            p["before"] += 1
        if mem:
            m = p["members"].setdefault(mem, {"count": 0, "values": []})
            m["count"] += 1
            val = (getattr(e, "result", "") or "").strip()
            if val and len(m["values"]) < 2 and val not in m["values"]:
                m["values"].append(val)
        if stack and len(rec["stacks"]) < 3:
            rec["stacks"].append(stack)
        # ★ 栈要按**类型**存一份（金考典 2026-10-27）：
        #   报告写"该 SDK 采集了传感器信息、通信记录"，下面却挂了两条
        #   `getPackagesForUid`（应用列表）的栈 —— 说明取栈时根本没看类型。
        #   复核员拿这种报告去核对，只会得出"你的证据和结论对不上"。
        if stack and len(p["stacks"]) < 2 and stack not in p["stacks"]:
            p["stacks"].append(stack)

    for rec in out.values():
        rec["apis"] = sorted(x for x in rec["apis"] if x)
        rec["pi"] = dict(sorted(rec["pi"].items(), key=lambda kv: -kv[1]["count"]))
    return {"by_key": out, "vocab": vocab}


# ---------------------------------------------------------------------------
# 对照
# ---------------------------------------------------------------------------

def _match_declared(obs: Dict[str, Any],
                    declared: Sequence[DeclaredSdk]) -> Tuple[Optional[DeclaredSdk],
                                                              str, List[DeclaredSdk]]:
    """实测的 SDK 在声明清单里对上了没有。

    返回 (最匹配的那条, 命中方式, 同厂商的全部记录)。
    命中方式：`本 SDK 名称` / `同厂商（腾讯）已列明` / `` （未命中）
    """
    name = obs.get("name") or ""
    vendor = obs.get("vendor") or ""
    n = _norm(name)
    if not n:
        return None, "", []
    # ① 名称归一化后相同
    for d in declared:
        if _norm(d.name) == n:
            return d, "本 SDK 名称", [d]
    # ② 互相包含（"友盟+移动统计" vs "友盟统计"），要求足够长以免误配
    for d in declared:
        dn = _norm(d.name)
        if len(dn) >= 4 and len(n) >= 4 and (dn in n or n in dn):
            return d, "本 SDK 名称", [d]
    # ③ 品牌词相同（compare 里已有那套 SDK 名归一逻辑，直接复用）
    b_obs = CMP._sdk_brand(name, vendor)     # noqa: SLF001
    if b_obs:
        for d in declared:
            if CMP._sdk_brand(d.name, d.vendor) == b_obs:   # noqa: SLF001
                return d, "本 SDK 名称", [d]
    # ④ 厂商集团相同 —— 用户口径：同一个大厂的 SDK 有声明到就算
    g = obs.get("group") or vendor_group(name, vendor)
    if g:
        same = [d for d in declared if (d.group or vendor_group(d.name, d.vendor)) == g]
        if same:
            return same[0], "同厂商（%s）已列明" % g, same
    return None, "", []


def _pi_names(ids: Iterable[str], vocab: Dict[str, Dict[str, Any]]) -> List[str]:
    out = []
    for pid in ids:
        v = vocab.get(pid) or {}
        if v.get("name"):
            out.append(v["name"])
    return out


def compare(inv: Dict[str, Any], declared: Sequence[DeclaredSdk],
            declared_pi_ids: Iterable[str],
            collect_list: Sequence[Dict[str, Any]] = ()) -> Dict[str, Any]:
    """逐 SDK 求"实际采集 − 声明"，并给出 App 自身口径的同一组数字。

    `declared_pi_ids` 是政策正文关键词 + 模型深读得到的**整体**声明类型，
    用于 App 自身那一支（App 自己采的东西不必要求在 SDK 清单里逐条出现）。
    """
    vocab = inv.get("vocab") or {}
    by_key = inv.get("by_key") or {}
    app_declared_ids = set(declared_pi_ids or ())

    sdk_rows: List[Dict[str, Any]] = []
    app_row: Optional[Dict[str, Any]] = None
    unknown_row: Optional[Dict[str, Any]] = None
    unk_pi: Dict[str, Dict[str, Any]] = {}
    unk_count = unk_before = 0
    unk_roots: List[str] = []

    for key, rec in by_key.items():
        pi_ids = list(rec["pi"].keys())
        base = {
            "key": key, "kind": rec["kind"], "name": rec["name"],
            "vendor": rec["vendor"], "group": rec["group"],
            "count": rec["count"], "before": rec["before"],
            "observed_pi": [{"pi": pid, "name": rec["pi"][pid]["name"],
                             "class": rec["pi"][pid].get("class", ""),
                             "count": rec["pi"][pid]["count"],
                             "stacks": [list(x) for x in
                                        (rec["pi"][pid].get("stacks") or [])],
                             "members": [
                                 {"name": mn, "values": mv.get("values") or [],
                                  "count": mv.get("count", 0)}
                                 for mn, mv in (rec["pi"][pid].get("members") or {}).items()
                             ]}
                            for pid in pi_ids],
            "apis": rec["apis"],
            "stacks": rec["stacks"],
        }
        if rec["kind"] == "unknown":
            unk_count += rec["count"]
            unk_before += rec["before"]
            if rec["prefix"] and rec["prefix"] not in unk_roots:
                unk_roots.append(rec["prefix"])
            for pid in pi_ids:
                cur = unk_pi.setdefault(pid, {"pi": pid,
                                              "name": rec["pi"][pid]["name"],
                                              "count": 0, "members": {}})
                cur["count"] += rec["pi"][pid]["count"]
                for mn, mv in (rec["pi"][pid].get("members") or {}).items():
                    cur["members"].setdefault(mn, mv.get("count", 0))
            continue
        if key == APP_KEY:
            missing = [p for p in pi_ids if p not in app_declared_ids]
            base.update({
                "declared_pi": [{"pi": p, "name": (vocab.get(p) or {}).get("name", p)}
                                for p in pi_ids if p in app_declared_ids],
                "missing_pi": [{"pi": p, "name": (vocab.get(p) or {}).get("name", p)}
                               for p in missing],
                "matched_by": "政策正文/收集清单",
            })
            app_row = base
            continue

        hit, how, same = _match_declared(rec, declared)
        d_ids = set()
        for d in (same if how.startswith("同厂商") else ([hit] if hit else [])):
            d_ids |= set(d.pi_ids or [])
        missing = [p for p in pi_ids if p not in d_ids]
        base.update({
            "declared_pi": [{"pi": p, "name": (vocab.get(p) or {}).get("name", p)}
                            for p in sorted(d_ids)],
            "missing_pi": [{"pi": p, "name": (vocab.get(p) or {}).get("name", p)}
                           for p in missing],
            "matched_by": how or "未列明",
            "declared_name": (hit.name if hit else ""),
            "declared_vendor": (hit.vendor if hit else ""),
            "declared_source": (hit.source if hit else ""),
            "declared_link": (hit.link if hit else ""),
            "same_vendor_sdks": [d.name for d in same][:6] if how.startswith("同厂商") else [],
        })
        sdk_rows.append(base)

    # 「未能归属」单独汇总成一行：既不算 App 的行为，也不算某个 SDK 未列明，
    # 但必须在报告里可见 —— 藏起来会让"实际采集了却没人认领"从此消失。
    if unk_count:
        unknown_row = {
            "key": UNKNOWN_KEY, "kind": "unknown",
            "name": ("未能归属（%s）" % "、".join(unk_roots[:3])) if unk_roots else "未能归属",
            "vendor": "", "group": "", "count": unk_count, "before": unk_before,
            "observed_pi": [{"pi": p["pi"], "name": p["name"], "class": "",
                             "count": p["count"],
                             "members": [{"name": k2, "values": [], "count": v2}
                                         for k2, v2 in p["members"].items()]}
                            for p in unk_pi.values()],
            "apis": [], "stacks": [],
            "note": "调用栈的调用点不在 App 包内、也不在已收录的 SDK 名单内"
                    "（可能为混淆后的自研代码，或未收录的第三方库），"
                    "未计入 App 与任何 SDK 的差集，需人工确认归属",
        }

    # 排序：未列明在最前（人工先看），其次有缺项的，最后是已完全覆盖的
    def _rank(r: Dict[str, Any]) -> Tuple[int, int, int]:
        if r["matched_by"] == "未列明":
            return (0, 0, -r["count"])
        if r["missing_pi"]:
            return (1, 0, -r["count"])
        return (2, 0 if r["matched_by"].startswith("同厂商") else 1, -r["count"])
    sdk_rows.sort(key=_rank)

    gap_sdk = [r for r in sdk_rows if r["matched_by"] == "未列明" or r["missing_pi"]]
    gap_app = ([{"name": app_row["name"], "missing_pi": app_row["missing_pi"],
                 "count": app_row["count"]}] if app_row and app_row["missing_pi"] else [])

    # 声明了但本次没观测到的 SDK：不算问题（可能只是没触发），但值得列出来，
    # 供人工判断"清单是不是照抄的模板"。
    obs_names = {_norm(r["name"]) for r in sdk_rows}
    declared_unobserved = [d.to_dict() for d in declared
                           if _norm(d.name) not in obs_names][:20]

    return {
        "declared_sdks": [d.to_dict() for d in declared],
        "collect_list": [dict(x, pi_names=_pi_names(x.get("pi_ids") or [], vocab))
                         for x in (collect_list or [])],
        "sdk_rows": sdk_rows,
        "app_row": app_row,
        "unknown_row": unknown_row,
        "gap_sdk": gap_sdk,
        "gap_app": gap_app,
        "declared_unobserved": declared_unobserved,
        "stats": {
            "declared_sdk": len(declared),
            "observed_sdk": len(sdk_rows),
            "sdk_gap": len(gap_sdk),
            "sdk_missing_types": sum(len(r["missing_pi"]) for r in gap_sdk),
            "sdk_unlisted": sum(1 for r in sdk_rows if r["matched_by"] == "未列明"),
            "sdk_same_vendor": sum(1 for r in sdk_rows
                                   if r["matched_by"].startswith("同厂商")),
            "app_gap_types": len(gap_app[0]["missing_pi"]) if gap_app else 0,
        },
    }


# ---------------------------------------------------------------------------
# 模型层：只做加法 / 只做许可
# ---------------------------------------------------------------------------

_EXTRACT_SYS = (
    "你是个人信息保护合规检测的数据整理员。下面是一段隐私政策或第三方共享清单原文。"
    "请只抽取其中**明确写到的第三方 SDK**，输出 JSON 数组，每项形如：\n"
    '  {"name":"SDK 名称","vendor":"提供方公司全称（原文没有就留空）",'
    '"types":["该 SDK 声明收集的个人信息类型，用原文措辞"],'
    '"purpose":"声明用途（原文没有就留空）"}\n'
    "要求：只输出原文里确实出现的 SDK，不要补充常识；原文没有第三方 SDK 就输出 []。"
    "不要输出 JSON 之外的内容。"
)

_VERIFY_SYS = (
    "你是个人信息保护合规检测的复核员。下面列出若干「实际采集到、但在隐私政策/共享清单里"
    "没检索到对应声明」的第三方 SDK。请逐条判断它是否其实已被列明。\n"
    "只输出 JSON 数组，每项形如：\n"
    '  {"idx":0,"verdict":"covered|gap","reason":"…（covered 时给出原文里的名称）"}\n'
    "判断时可参考：同一厂商只要列明了旗下任一 SDK 或品牌，即算 covered；"
    "SDK 名称写法不同（如「友盟+移动统计」与「友盟统计」）也算 covered。"
    "不要输出 JSON 之外的内容。"
)


def ai_extract(docs: Sequence[Dict[str, str]], ai: Any, log: Log = _NOP,
               budget: int = 6000) -> List[DeclaredSdk]:
    """模型补充解析：规则层一个 SDK 都没抽出来时才调用。"""
    if ai is None or getattr(ai, "name", "none") == "none":
        return []
    text = "\n\n".join(((d or {}).get("text") or "") for d in docs or [])[:budget]
    if not text.strip():
        return []
    try:
        raw = ai.chat([{"role": "user", "content": "原文：\n" + text}],
                      system=_EXTRACT_SYS)
    except Exception as e:                      # noqa: BLE001
        log("[P5] SDK 清单结构化（模型）失败：%s" % e)
        return []
    arr = _json_array(raw)
    if not arr:
        return []
    out: List[DeclaredSdk] = []
    for it in arr[:60]:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name") or "").strip()
        types = [str(x).strip() for x in (it.get("types") or []) if str(x).strip()]
        if len(name) < 2 or not types:
            continue
        # 模型给的是类型名，映射回词表 id 才能参与差集；映射不上就只留原文
        ids = sorted(CMP.ai_declared_types({"declared_types": types}).keys())
        out.append(DeclaredSdk(
            name=name[:60], vendor=str(it.get("vendor") or "")[:60],
            group=vendor_group(name, str(it.get("vendor") or "")),
            pi_ids=ids, pi_terms=types[:10],
            purpose=str(it.get("purpose") or "")[:80],
            source="模型抽取", raw=text[:600]))
    if out:
        log("[P5] 模型补充识别出 %d 个第三方 SDK（规则层未识别到）" % len(out))
    return out


def ai_verify_gaps(rows: Sequence[Dict[str, Any]], policy_blob: str, ai: Any,
                   log: Log = _NOP, budget: int = 6000) -> None:
    """让模型复核「SDK 未列明」的判定，就地修改 `matched_by` / `verdict`。

    为什么必须复核：清单写法千变万化（品牌简称、英文名、公司全称），
    规则层的名称匹配一定会有漏网。宁可让模型多看一遍，也不要让报告
    把"其实写了"的 SDK 报成未列明 —— 那会直接毁掉这一栏的可信度。
    """
    if not rows:
        return
    if ai is None or getattr(ai, "name", "none") == "none":
        for r in rows:
            r["verdict"] = "gap"
            r["verdict_reason"] = "未经模型复核"
        return
    lines = []
    for i, r in enumerate(rows):
        miss = "、".join(p.get("name", "") for p in r.get("missing_pi") or []) or "—"
        lines.append("%d. %s（厂商：%s；实际采集：%s；清单内未匹配到）"
                     % (i, r.get("name"), r.get("vendor") or "未识别", miss))
    fixed = len("\n".join(lines)) + 200
    room = max(600, budget - fixed)
    prompt = ("待复核的 SDK（共 %d 个）：\n%s\n\n隐私政策/共享清单正文（摘录）：\n%s"
              % (len(rows), "\n".join(lines), (policy_blob or "")[:room]))
    try:
        raw = ai.chat([{"role": "user", "content": prompt}], system=_VERIFY_SYS)
    except Exception as e:                      # noqa: BLE001
        log("[P5] SDK 未列明复核失败（%s），保留规则判定" % e)
        for r in rows:
            r["verdict"] = "gap"
            r["verdict_reason"] = "模型复核失败"
        return
    arr = _json_array(raw) or []
    verdicts = {}
    for it in arr:
        if isinstance(it, dict) and it.get("idx") is not None:
            try:
                verdicts[int(it["idx"])] = (str(it.get("verdict") or "gap"),
                                            str(it.get("reason") or ""))
            except Exception:
                continue
    absorbed = 0
    for i, r in enumerate(rows):
        v, why = verdicts.get(i, ("gap", "模型未覆盖该条"))
        r["verdict"] = v
        r["verdict_reason"] = why
        if v != "gap":
            absorbed += 1
    if absorbed:
        log("[P5] 模型复核后，%d 个 SDK 改判为已列明（同义/同厂商写法）" % absorbed)


def _json_array(raw: str) -> Optional[List[Any]]:
    import json
    txt = (raw or "").strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```[a-zA-Z]*\s*", "", txt)
        txt = re.sub(r"```\s*$", "", txt)
    i, j = txt.find("["), txt.rfind("]")
    if i < 0 or j <= i:
        return None
    try:
        arr = json.loads(txt[i:j + 1])
    except Exception:
        return None
    return arr if isinstance(arr, list) else None


# ---------------------------------------------------------------------------
# 一站式入口
# ---------------------------------------------------------------------------

def analyze(events: Sequence[Any], docs: Sequence[Dict[str, str]],
            declared_pi_ids: Iterable[str], package: str = "",
            ai: Any = None, log: Log = _NOP) -> Dict[str, Any]:
    """P5 的第二支对照：按 SDK 的「声明 vs 实测」。

    `docs` 应是**已取得的全部文本**（政策正文 + 下钻的共享清单 + 收集清单），
    因为清单可能被放在任何一份文档里，事先分不清哪份是清单。
    """
    sm = CMP._signal_map()                   # noqa: SLF001
    declared = parse_declared_sdks(docs, sm)
    if not declared and ai is not None:
        declared = ai_extract(docs, ai, log)
    collect = parse_collect_lists(docs, sm)
    inv = observed_inventory(events, package, sm)
    res = compare(inv, declared, declared_pi_ids, collect)

    # 模型复核：只对"未列明"与"有缺项"的行做，已完全覆盖的不打扰模型
    gap_rows = [r for r in res["sdk_rows"] if r["matched_by"] == "未列明"]
    if gap_rows:
        blob = "\n".join(((d or {}).get("text") or "") for d in docs or [])[:12000]
        ai_verify_gaps(gap_rows, blob, ai, log)
        covered = [r for r in gap_rows if r.get("verdict") == "covered"]
        if covered:
            # 改判后不再计入差集，但保留在明细里（复核员要能看到"为什么消失了"）
            res["gap_sdk"] = [r for r in res["sdk_rows"]
                              if (r["matched_by"] == "未列明" and r.get("verdict") != "covered")
                              or r["missing_pi"]]
            res["covered_by_ai"] = [r["name"] for r in covered]
            res["stats"]["sdk_unlisted"] = sum(
                1 for r in res["sdk_rows"]
                if r["matched_by"] == "未列明" and r.get("verdict") != "covered")
            res["stats"]["sdk_gap"] = len(res["gap_sdk"])
            log("[P5] 其中 %d 个 SDK 经模型复核后视为已列明：%s"
                % (len(covered), "、".join(res["covered_by_ai"][:6])))
    for r in res["sdk_rows"]:
        r.setdefault("verdict", "covered" if not r["missing_pi"] else "gap")
    return res


def matrix_rows(res: Dict[str, Any]) -> List[List[str]]:
    """把对照结果压成报告用的表格行（每行一个 SDK）。"""
    rows: List[List[str]] = []
    for r in (res.get("sdk_rows") or []):
        obs = "、".join(p.get("name", "") for p in r.get("observed_pi") or []) or "—"
        mem = []
        for p in r.get("observed_pi") or []:
            for m in p.get("members") or []:
                nm = m.get("name") or ""
                if nm and nm not in mem:
                    mem.append(nm)
        if mem:
            obs += "（%s）" % "、".join(mem[:4])
        decl = ("、".join(p.get("name", "") for p in r.get("declared_pi") or [])
                or "—")
        miss = "、".join(p.get("name", "") for p in r.get("missing_pi") or []) or "—"
        rows.append([r.get("name") or "", r.get("group") or r.get("vendor") or "—",
                     obs, decl, miss,
                     r.get("matched_by") or "",
                     "已列明" if not r.get("missing_pi") and
                     r.get("matched_by") != "未列明" else
                     ("未列明" if r.get("matched_by") == "未列明" else "部分未列明")])
    return rows


def describe(res: Dict[str, Any], limit: int = 6) -> str:
    """一句话结论，进 Q007 正文。"""
    st = res.get("stats") or {}
    if not st.get("observed_sdk"):
        return "本次未从调用栈中识别出可归属的第三方 SDK 采集行为"
    parts = []
    unlisted = [r for r in (res.get("sdk_rows") or []) if r["matched_by"] == "未列明"]
    partial = [r for r in (res.get("sdk_rows") or [])
               if r["matched_by"] != "未列明" and r["missing_pi"]]
    if unlisted:
        parts.append("%d 个 SDK 未在政策或共享清单中列明（%s）"
                     % (len(unlisted),
                        "、".join("%s：%s" % (r["name"],
                                             "、".join(p.get("name", "") for p in r["missing_pi"]))
                                 for r in unlisted[:limit])))
    if partial:
        parts.append("%d 个 SDK 已列明但声明范围小于实际采集（%s）"
                     % (len(partial),
                        "、".join("%s 实际采集 %s 未列明" % (
                            r["name"],
                            "、".join(p.get("name", "") for p in r["missing_pi"]))
                            for r in partial[:limit])))
    if not parts:
        parts.append("实际观测到的 %d 个第三方 SDK 采集行为均能在政策或共享清单中找到对应声明"
                     % st.get("observed_sdk", 0))
    if st.get("sdk_same_vendor"):
        # ★ 必须点名是哪个 SDK（用户 2026-10-27 意见）：旧文案只写
        #   "其中 1 个按其所属厂商（字节跳动）的已有声明视为已列明"，
        #   看报告的人根本不知道说的是哪一个 —— 而这正是最容易被质疑的一条
        #   （"凭什么它算已列明"），不点名等于没交代。
        _same = [r for r in (res.get("sdk_rows") or [])
                 if r.get("matched_by", "").startswith("同厂商")]
        _same_txt = "、".join(
            "「%s」（按 %s 已列明的 %s 放宽）"
            % (r.get("name") or "",
               r.get("group") or r.get("declared_vendor") or "同一厂商",
               "、".join((r.get("same_vendor_sdks") or [])[:3]) or "旗下其他 SDK")
            for r in _same[:limit])
        parts.append("另有 %d 个 SDK 未逐字出现在清单中，按其所属厂商的已有声明"
                     "视为已列明：%s" % (st["sdk_same_vendor"], _same_txt))
    return "；".join(parts)


def repro_signature(res: Dict[str, Any], limit: int = 6) -> List[Dict[str, str]]:
    """给复现环节用：把问题 SDK 的「API + 具体标识符」列成可重放的判据。

    复现只认这组判据：同一个 SDK 在清数据重启后又取了同一类信息，
    才叫"复现出来"。只看到"App 又启动了"不算。
    """
    out: List[Dict[str, str]] = []
    for r in (res.get("gap_sdk") or [])[:limit]:
        for p in r.get("missing_pi") or []:
            for m in (p.get("members") or []):
                out.append({"kind": "sdk", "who": r.get("name") or "",
                            "pi": p.get("pi") or "", "member": m.get("name") or ""})
            if not (p.get("members") or []):
                out.append({"kind": "sdk", "who": r.get("name") or "",
                            "pi": p.get("pi") or "", "member": ""})
    for r in (res.get("gap_app") or [])[:2]:
        for p in r.get("missing_pi") or []:
            out.append({"kind": "app", "who": "应用自身",
                        "pi": p.get("pi") or "", "member": ""})
    return out


__all__ = ["VENDOR_GROUPS", "vendor_group", "DeclaredSdk", "blocks",
           "parse_declared_sdks", "parse_collect_lists", "observed_inventory",
           "compare", "analyze", "matrix_rows", "describe", "repro_signature",
           "ai_extract", "ai_verify_gaps", "APP_KEY", "UNKNOWN_KEY"]
