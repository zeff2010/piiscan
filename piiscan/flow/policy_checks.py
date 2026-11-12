"""从隐私政策正文里逐项检测合规项。

对应人工流程里最耗时的一段：「对照合规要求，逐项看政策里写没写」。
这一段不需要设备、不需要抓包，只靠文本，所以是自动化性价比最高的部分。

判定的分寸：
  政策里**写了**       → pass（有说明）
  政策里**没写**       → suspect，而不是 fail
      因为 App 内的功能入口（设置页里的注销按钮）也可能提供该渠道，
      政策没写 ≠ 没有。直接判 fail 会误报，判 pass 会漏报，
      所以出「疑似」+ 明确写清"政策中未见…需人工确认 App 内是否有入口"，
      把最后一步留给人工 —— 这正是「AI 出疑似清单、人工做判定」的分工。
  政策里写了**超期承诺**（>15 个工作日）→ fail，这条是硬标准，没有裁量空间。
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# 超过这个天数即违反「15 个工作日」的承诺要求
WORKDAY_LIMIT = 15

_WORKDAY_RE = re.compile(r"(?:(\d+)|([一二三四五六七八九十]+))\s*个?\s*工作日")

_CN_NUM = {"一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5,
           "六": 6, "七": 7, "八": 8, "九": 9, "十": 10, "十五": 15}


def _cn_to_int(s: str) -> Optional[int]:
    s = (s or "").strip()
    if s.isdigit():
        return int(s)
    if s in _CN_NUM:
        return _CN_NUM[s]
    if s.startswith("十") and len(s) == 2:
        return 10 + _CN_NUM.get(s[1], 0)
    if "十" in s:
        a, _, b = s.partition("十")
        return (_CN_NUM.get(a, 1) * 10) + (_CN_NUM.get(b, 0) if b else 0)
    return None


def find_workday_promises(text: str) -> List[Tuple[int, str]]:
    """找出政策里所有「N 个工作日」的承诺，返回 (天数, 上下文)。"""
    out = []
    for m in _WORKDAY_RE.finditer(text or ""):
        n = _cn_to_int(m.group(1) or "") or _cn_to_int(m.group(2) or "")
        if n is None:
            continue
        a = max(0, m.start() - 60)
        out.append((n, (text[a:m.end() + 30]).replace("\n", " ")))
    return out


def _over_limit(text: str) -> List[Tuple[int, str]]:
    return [(n, ctx) for n, ctx in find_workday_promises(text) if n > WORKDAY_LIMIT]


def _hits(text: str, words: Sequence[str]) -> List[str]:
    low = (text or "").lower()
    return [w for w in words if w.lower() in low]


# ---------------------------------------------------------------------------
# 规则表
#   每条：测评项 → 政策里该出现什么 → 命中/未命中分别怎么判
# ---------------------------------------------------------------------------
RULES: List[Dict[str, Any]] = [
    {
        "qid": "Q005",
        "name": "逐一列出目的、方式、范围",
        "need_all": None,
        # 必须同时具备「目的 / 方式 / 范围」三要素，缺一项即为疑似
        "need_each": {
            "目的": ["目的", "用途", "用于", "为了", "以便"],
            "方式": ["方式", "如何收集", "收集方式", "通过", "收集手段"],
            "范围": ["范围", "种类", "类型", "清单", "包括"],
        },
        "ok": "隐私政策中对收集、使用个人信息的目的、方式和范围作了列明（检索到：{hits}）",
        "miss": "隐私政策中未逐一列明收集、使用个人信息的{missing}，"
                "需人工对照政策全文确认",
        "level": "中",
    },
    {
        "qid": "Q008",
        "name": "明确用于广告、用户画像",
        "need_each": {
            "广告用途说明": ["广告", "推广", "营销"],
            "画像用途说明": ["画像", "用户画像", "个性化", "推荐"],
        },
        "ok": "隐私政策中明确提及收集的信息用于{hits}",
        "miss": "隐私政策中未明确收集到的个人信息用于广告、用户画像等功能（未见{missing}相关表述），"
                "需人工确认是否存在广告/画像场景",
        "level": "中",
        # 只有同时涉及广告或画像 SDK 才有意义；政策完全没提广告时出疑似即可
        "soft": True,
    },
    {
        "qid": "Q009",
        "name": "未成年人专门规则",
        # ★ 原先是 need_all：命中「儿童/未成年人/监护人」中**任何一个**即判 pass。
        #   这个判法太宽 —— 政策里写一句"本政策不适用于未成年人"也会命中，
        #   报告第 2 项于是显示"未发现问题"，而复核员会以为未成年人保护
        #   这一整块都验过了。现在拆成两组、必须同时命中：
        #     ① 载有专门规则（儿童隐私政策 / 未成年人专章）
        #     ② 载有监护人同意要求
        #   两组齐了才说"政策文本载有"。缺一组出疑似，交给人工。
        #   注：实际是否真的取得监护人同意属功能/流程范畴，政策文本证明不了，
        #   由 sop 层在结论后追加限定说明。
        "need_each": {
            "专门处理规则": ["儿童隐私政策", "儿童个人信息保护", "未成年人个人信息保护",
                            "未成年人保护", "专门的个人信息处理规则", "儿童个人信息",
                            "不满十四周岁", "未满十四周岁", "十四周岁以下"],
            "监护人同意要求": ["监护人", "父母", "家长同意"],
        },
        "ok": "隐私政策中载有面向未成年人的专门处理规则与监护人同意要求（检索到：{hits}）",
        "miss": "隐私政策中未见{missing}的有关说明，需人工确认该 App 是否处理未成年人个人信息",
        "level": "中",
    },
    {
        "qid": "Q013",
        "name": "注销账号途径",
        "need_all": ["注销", "销户", "删除账号", "注销账号"],
        "ok": "隐私政策中提供了注销账号的途径说明（检索到：{hits}）",
        "miss": "隐私政策中未检索到注销账号的途径和方式，"
                "需人工确认 App 功能界面中是否提供注销入口",
        "level": "中",
        "functional": True,
    },
    {
        "qid": "Q014",
        "name": "投诉举报渠道",
        "need_all": ["投诉", "举报", "反馈渠道", "意见反馈"],
        "ok": "隐私政策中公布了投诉举报渠道（检索到：{hits}）",
        "miss": "隐私政策中未检索到个人信息安全投诉举报渠道，"
                "需人工确认 App 功能界面中是否提供投诉举报入口",
        "level": "中",
        "functional": True,
    },
    {
        "qid": "Q015",
        "name": "更正、删除、拒绝处理渠道",
        "need_each": {
            "更正": ["更正", "补充", "修改个人信息"],
            # 实测（以观书法 5.4.2 政策原文）：「保证您可以访问、更新和更正自己的
            # 注册信息…在访问、更新、更正和删除前述信息时…」—— 写的是"删除前述信息"，
            # 原先只认「删除个人信息」，于是把"政策写了删除"报成"未见删除的有关说明"。
            # 结论方向没错（确实没给具体渠道），但给出的理由与原文不符，
            # 复核员一核对就会发现报告在说假话。
            "删除": ["删除个人信息", "删除您的信息", "删除权", "删除前述信息", "更正和删除"],
            "撤回同意": ["撤回同意", "撤回授权", "拒绝处理"],
        },
        "ok": "隐私政策中提供了{hits}的行使途径说明",
        "miss": "隐私政策中未见{missing}的具体途径说明，需人工确认 App 内是否提供相应功能",
        "level": "中",
        "functional": True,
    },
    {
        "qid": "Q016",
        "name": "删除个人特征标签",
        "need_all": ["标签", "特征标签", "用户画像", "个性化推荐"],
        "ok": "隐私政策中提及个人特征标签/画像相关说明（检索到：{hits}）",
        "miss": "隐私政策中未检索到删除用户个人特征标签的相关说明，"
                "若存在广告 SDK 的个性化推荐功能则需人工确认是否提供删除途径",
        "level": "低",
        "soft": True,
        "functional": True,
    },
    {
        "qid": "Q022",
        "name": "个性化推荐关闭选项",
        "need_all": ["个性化推荐", "个性化展示", "个性化内容", "推荐算法", "个性化"],
        "ok": "隐私政策中提及个性化推荐（检索到：{hits}）",
        "miss": "隐私政策中未检索到个性化推荐相关的说明与关闭选项，"
                "需人工确认 App 内是否提供关闭入口",
        "level": "中",
        "soft": True,
        "functional": True,
    },
]


def check_one(rule: Dict[str, Any], text: str) -> Dict[str, Any]:
    """对一条规则做判定。返回 {state, desc, hits, missing}。"""
    if not (text or "").strip():
        return {"state": "not_tested", "desc": "", "hits": [], "missing": [],
                "reason": "无隐私政策正文"}
    need_each: Optional[Dict[str, Sequence[str]]] = rule.get("need_each")
    if need_each:
        got, miss, allhits = [], [], []
        for label, words in need_each.items():
            h = _hits(text, words)
            if h:
                got.append(label)
                allhits.extend(h[:2])
            else:
                miss.append(label)
        if not miss:
            return {"state": "pass", "hits": got, "missing": [],
                    "desc": rule["ok"].format(hits="、".join(got))}
        return {"state": "suspect", "hits": got, "missing": miss,
                "desc": rule["miss"].format(missing="、".join(miss), hits="、".join(allhits))}
    h = _hits(text, rule.get("need_all") or [])
    if h:
        return {"state": "pass", "hits": h, "missing": [],
                "desc": rule["ok"].format(hits="、".join(h[:4]))}
    return {"state": "suspect", "hits": [], "missing": list(rule.get("need_all") or [])[:3],
            "desc": rule["miss"]}


def check_time_limit(text: str) -> List[Dict[str, Any]]:
    """「承诺处理时间大于 15 个工作日」—— 硬违规，直接定 fail。"""
    out = []
    for n, ctx in _over_limit(text):
        out.append({"days": n, "context": ctx})
    return out


def run(policy_text: str,
        log: Callable[[str], None] = print) -> Dict[str, Dict[str, Any]]:
    """对政策正文跑全部文本规则。"""
    res: Dict[str, Dict[str, Any]] = {}
    for rule in RULES:
        r = check_one(rule, policy_text)
        r["name"] = rule["name"]
        r["level"] = rule.get("level", "中")
        r["soft"] = bool(rule.get("soft"))
        # ★ 必须把 functional 一路带到调用方：漏了这一行，P6 里
        #   r.get("functional") 恒为 False，「政策写了就判未发现问题」
        #   的误判会原封不动地留在报告里（简小知实测踩到过）。
        r["functional"] = bool(rule.get("functional"))
        res[rule["qid"]] = r
    res["_time_limit"] = {"items": check_time_limit(policy_text), "limit": WORKDAY_LIMIT}
    return res


__all__ = ["run", "check_one", "check_time_limit", "find_workday_promises",
           "RULES", "WORKDAY_LIMIT"]
