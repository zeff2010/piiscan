#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""P5 声明侧自检 —— 「模型深读政策」到底有没有进判定链。

为什么单独测这一块：P2 花 90 秒把三万字政策分 24 段读完，抽出 60 个声明类型，
如果这些结果只进了日志、没进 P5 的差集计算，那 90 秒就是白花的，
而报告照样写着"已分析政策全文"—— 是最难发现的一类空转。

这里全部离线跑，用一个假模型把「政策原文写法古怪、关键词配不上、
但模型读得出标准类型名」这种最常见的情况复现出来。
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from piiscan.flow import compare as CMP                            # noqa: E402

# 关键词法一定配不上、模型一定能读出来的政策写法。
# 「设备的唯一硬件编号」不是任何 policy_term／member，但人一看就知道是设备标识符。
POLICY_HARD = (
    "本政策适用于本产品。为保障您的账号与交易安全，我们可能获取您设备的唯一硬件编号，"
    "用于识别设备与风险控制。我们还会记录您访问时所用的网络地址，用于故障排查。"
    "我们仅在实现上述目的所必需的期间内保留相关信息。"
)
POLICY_AI = {
    "declared_types": ["设备标识符", "IP地址"],
    "purposes": ["账号与交易安全", "风险控制", "故障排查"],
    "retention": "仅在实现上述目的所必需的期间内保留",
    "cancel_account": [{"path": "我的-设置-注销账户", "channel": "App 内"}],
    "complaint": [{"path": "我的-帮助中心-投诉", "channel": "App 内"}],
}


def _ev(api: str, result: str, **kw: Any) -> Any:
    d = {"api": api, "result": result, "noise": "", "hook_id": "",
         "signal": "", "ts": 0.0, "stack": [], "thread": "main",
         "before_consent": False}
    d.update(kw)
    return SimpleNamespace(**d)


def run(check: Callable[..., bool]) -> None:
    sm = CMP._signal_map()

    print("— 声明侧：模型抽出的类型")

    # ---- ① 映射表本身 ----
    got = CMP.ai_declared_types(POLICY_AI, sm)
    check("标准类型名映射到 pi_vocab",
          got.get("P01") and got.get("P02"),
          "P01=%s P02=%s" % (got.get("P01"), got.get("P02")))
    check("命中值带 AI: 前缀（可追溯）",
          all(t.startswith("AI:") for v in got.values() for t in v),
          got.get("P01"))
    check("None / 空输入安全",
          CMP.ai_declared_types(None, sm) == {}
          and CMP.ai_declared_types({}, sm) == {}
          and CMP.ai_declared_types({"declared_types": []}, sm) == {})

    # 万能词一律不收：放宽一格就会把整片真差集"声明掉"
    generic = CMP.ai_declared_types(
        {"declared_types": ["设备信息", "个人信息", "信息", "数据", "用户信息"]}, sm)
    check("万能词不引入任何类型", generic == {}, generic)

    # 反向包含会出硬伤：「位置信息」是 P11 policy_term「图片位置信息」的子串，
    # 一旦反向匹配，一条普通位置声明就被算成"声明了媒体文件采集"。
    pos = CMP.ai_declared_types({"declared_types": ["位置信息"]}, sm)
    check("不因反向包含误判媒体文件", "P11" not in pos and "P04" in pos, pos)

    # 短词靠"完全相同"命中
    check("短词精确匹配（日历→P10）",
          "P10" in CMP.ai_declared_types({"declared_types": ["日历"]}, sm))
    check("子串匹配（剪贴板信息→P09）",
          "P09" in CMP.ai_declared_types({"declared_types": ["剪贴板信息"]}, sm))

    # ---- ② 必备要素：模型给的原文摘录也要算数 ----
    plain = CMP._ai_policy_text({"declared_types": ["设备标识符"]})
    check("未给要素时拼不出文本（不硬凑）", plain == "", plain[:40])
    rich = CMP._ai_policy_text(POLICY_AI)
    check("要素原文能被拼出来", "注销账户" in rich and "投诉" in rich, rich[:60])

    # ---- ③ 差集并集：关键词配不上的声明，靠模型补上 ----
    evs = [_ev("android.telephony.TelephonyManager#getImei()",
               "861234567890123", before_consent=True),
           _ev("java.net.NetworkInterface#getHardwareAddress", "3c:5a:b4:11:22:33")]

    base = CMP.analyze(evs, [POLICY_HARD], [], [], ai=None, log=lambda *_a: None)
    with_ai = CMP.analyze(evs, [POLICY_HARD], [], [], ai=None, log=lambda *_a: None,
                          ai_policy=POLICY_AI)
    check("观测到被收集的类型（前置条件）",
          base["stats"]["collected_types"] >= 1,
          base["stats"]["collected_types"])
    check("不传模型结果时，声明类型 = 关键词口径",
          base["stats"]["declared_types"] == base["stats"]["declared_types_kw"]
          and base["stats"]["declared_ai_extra"] == 0, base["stats"])
    check("模型结果并入了声明类型",
          with_ai["stats"]["declared_types"] > base["stats"]["declared_types"],
          "%s → %s" % (base["stats"]["declared_types"],
                       with_ai["stats"]["declared_types"]))
    check("并集只增不减（声明范围不会被缩小）",
          set(with_ai["declared"]) >= set(base["declared"]))
    check("新增的来源记在 declared_ai_extra 里",
          with_ai["stats"]["declared_ai_extra"] == len(with_ai["declared_ai_extra"])
          and with_ai["stats"]["declared_ai_extra"] >= 1,
          with_ai["declared_ai_extra"])
    check("差集数量因模型深读而下降",
          with_ai["stats"]["gap_raw"] <= base["stats"]["gap_raw"],
          "%d → %d" % (base["stats"]["gap_raw"], with_ai["stats"]["gap_raw"]))
    check("被模型吸收的差集有独立计数（可审计）",
          with_ai["stats"]["gap_absorbed_by_ai"]
          == base["stats"]["gap_raw"] - with_ai["stats"]["gap_raw"],
          with_ai["stats"]["gap_absorbed_by_ai"])
    check("差集条目里不再出现已声明类型",
          all(g["pi"] not in with_ai["declared_ai_extra"]
              for g in with_ai["real_gaps"]),
          [g["pi"] for g in with_ai["real_gaps"]])

    # ---- ④ 要素检查：模型读到的注销/投诉途径不能算"没写" ----
    elems_ai = with_ai.get("elements") or {}
    check("模型读到的注销途径被算作政策载有",
          bool(elems_ai.get("注销")), elems_ai.get("注销"))
    # POLICY_HARD 里没有任何「注销」字样，关键词法必然判缺 —— 这两条一起
    # 说明"要素变齐"确实来自模型摘录，不是文本里本来就有。
    base_elems = base.get("elements") or {}
    check("原文确实没写注销（对照成立）", not base_elems.get("注销"), base_elems.get("注销"))

    # ---- ⑤ 统计口径健全性：报告要用的键一个都不能少 ----
    need = ("collected_types", "declared_types", "declared_types_kw",
            "declared_ai_extra", "gap_raw", "gap_real",
            "gap_absorbed_by_ai", "third_party_gap")
    missing = [k for k in need if k not in with_ai["stats"]]
    check("stats 键齐全（报告/日志直接用）", not missing, missing)
    check("空政策文本也不炸（只做防御）",
          isinstance(CMP.analyze([], [""], [], [], ai=None, log=lambda *_a: None,
                                 ai_policy=POLICY_AI).get("stats"), dict))

    # ---- ⑥ 模型抄回来的链接要能点开 ----
    # 真机实测：30 条第三方 SDK 隐私政策链接里 9 条写成 `https:/xxx`（少一个斜杠），
    # 几条路径中间带软换行空格。留着就是"复核员点不开 → 以为没抓到"。
    from piiscan.flow.sop import _fix_link
    check("补回缺失的斜杠", _fix_link("https:/a.com/x") == "https://a.com/x",
          _fix_link("https:/a.com/x"))
    check("去掉 URL 内空白",
          _fix_link("https://a.com/mm suppo rt") == "https://a.com/mmsupport",
          _fix_link("https://a.com/mm suppo rt"))
    check("正常链接不被改动",
          _fix_link("https://a.com/x?y=1&z=2") == "https://a.com/x?y=1&z=2")
    check("非 http 原样返回（交给调用方过滤）",
          _fix_link("ftp://a.com") == "ftp://a.com" and _fix_link("") == "")

    # ---- ⑦ 调用栈识别出的 SDK → 政策「未列明」比对 ----
    # 这条是"栈进判定链"的核心：域名法只能抓到往哪儿发，
    # 抓不到"用了谁的 SDK"；而政策里该不该列 SDK 是另一回事。
    SPEC_UMENG = "友盟统计分析|友盟同欣（北京）科技有限公司|com.umeng.commonsdk.statistics"
    SPEC_VIVO = "vivo推送SDK@维沃移动通信|维沃移动通信有限公司|com.vivo.push"
    SPEC_MI = "小米推送|北京小米移动软件有限公司|com.xiaomi.push"

    pol_full = "我们接入了友盟统计分析SDK用于统计。第三方SDK：小米推送（用于消息通知）。"
    gaps = CMP.observed_sdk_gaps([SPEC_UMENG, SPEC_VIVO, SPEC_MI], [pol_full])
    check("★ 政策写了友盟→不再列为未列明",
          all("友盟" not in g["name"] for g in gaps), gaps)
    check("★ 政策写了小米推送→不再列为未列明",
          all("小米" not in g["name"] for g in gaps), gaps)
    check("★ 政策没写的 vivo 仍列为未列明",
          any("vivo" in g["name"] for g in gaps), gaps)
    check("未列明项带回检索用的键（可复核）",
          all(g.get("keys") for g in gaps), gaps)

    # 只写品牌、不写全称 —— 政策里最常见
    gaps2 = CMP.observed_sdk_gaps([SPEC_UMENG], ["第三方SDK：友盟（统计）"])
    check("★ 只写品牌「友盟」也算已列明", not gaps2, gaps2)

    # 品牌词出现在与 SDK 无关的句子里，不能算已声明（"小米手机" 是最典型的坑）
    gaps3 = CMP.observed_sdk_gaps([SPEC_MI], ["本应用在小米手机上显示可能存在差异。"])
    check("★ 无关句子里的品牌词不算已列明", len(gaps3) == 1, gaps3)

    # 包名根命中也算（政策里直接贴了 umeng）
    gaps4 = CMP.observed_sdk_gaps([SPEC_UMENG], ["信息共享给 umeng.com 所属公司"])
    check("包名根命中算已列明", not gaps4, gaps4)

    # 空输入安全
    check("未列明比对：空观测 → 空结果", CMP.observed_sdk_gaps([], ["x"]) == [])
    check("未列明比对：空文本 → 全部未列明",
          len(CMP.observed_sdk_gaps([SPEC_UMENG], [])) == 1)

    # analyze() 要把这条接上（不是只测工具函数）
    res = CMP.analyze([], [pol_full], [], [], ai=None, log=lambda *_a: None,
                      observed_sdks=[SPEC_UMENG, SPEC_VIVO])
    check("analyze 回传 observed_sdks / sdk_gaps",
          res.get("stats", {}).get("observed_sdk") == 2
          and res.get("stats", {}).get("sdk_gap") == 1, res.get("stats"))
    check("sdk_gaps 里是拿不到声明的那一个",
          [g["name"] for g in (res.get("sdk_gaps") or [])] == [SPEC_VIVO.split("|")[0]],
          res.get("sdk_gaps"))

    # ---- ⑧ 「未列明 SDK」只能对着隐私政策判 ----
    # 实测：P2 点进去的是《用户协议》，全文没有一个 SDK 名称，
    # 按字面判定就是"15 个 SDK 全部未列明"—— 这不是发现问题，是拿错了文件。
    from piiscan.flow.sop import _is_privacy_policy_text as is_priv
    check("★《用户协议》不当作隐私政策",
          not is_priv('" Pofi无限人偶「用户协议」一、用户协议的接受1.1本用户协议（简称"协议"）'))
    check("★《服务协议》不当作隐私政策", not is_priv("软件许可及服务协议 首部 本协议是您与…"))
    check("隐私政策判为可用", is_priv("Pofi 隐私政策 我们如何收集和使用您的个人信息…"))
    check("空文本判为不可用", not is_priv(""))
