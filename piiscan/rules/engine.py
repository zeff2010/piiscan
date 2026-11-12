"""判定引擎：编排全部检测器，产出不符合项清单。"""
from __future__ import annotations

from typing import Callable, List

from . import detectors
from .detectors import ScanContext
from .models import Finding, JudgeResult
from .rulebase import checkitems

# 需要设备才能执行的测评项（缺失动态证据时标记为「未执行」）
NEEDS_DEVICE = {"Q002", "Q003", "Q004", "Q011", "Q012", "Q016", "Q017",
                "Q018", "Q019", "Q020", "Q021", "Q022", "Q023", "Q024", "Q025"}
# 需要隐私政策文本的测评项
NEEDS_POLICY = {"Q001", "Q005", "Q006", "Q007", "Q008", "Q009", "Q013", "Q014", "Q015"}


def evaluate(ctx: ScanContext, log: Callable[[str], None] = print) -> JudgeResult:
    res = JudgeResult()
    executed: List[str] = []

    for qid, fn, requires in detectors.registry():
        if requires == "policy" and not ctx.has_policy():
            continue
        if requires == "dynamic" and not ctx.has_dynamic():
            continue
        try:
            finding = fn(ctx)
        except Exception as e:
            log("[!] 检测项 %s 执行异常：%s" % (qid, e))
            continue
        executed.append(qid)
        if finding is not None:
            res.findings.append(finding)

    res.checked = executed

    # 未执行的项：说明原因，便于人工补齐
    executed_set = set(executed)
    for qid in checkitems().all_ids():
        if qid in executed_set:
            continue
        reason = []
        if qid in NEEDS_DEVICE and not ctx.has_dynamic():
            reason.append("本次未执行设备动态采集")
        if qid in NEEDS_POLICY and not ctx.has_policy():
            reason.append("未能获取隐私政策正文")
        if not reason:
            reason.append("该检测项需人工参与或当前版本尚未实现")
        ci = checkitems()
        res.skipped.append({
            "id": qid,
            "title": ci.title(qid),
            "automation": ci.automation(qid),
            "reason": "；".join(reason),
        })

    res.stats = {
        "findings": len(res.findings),
        "high": sum(1 for f in res.findings if f.level == "高"),
        "mid": sum(1 for f in res.findings if f.level == "中"),
        "low": sum(1 for f in res.findings if f.level == "低"),
        "confirmed": sum(1 for f in res.findings if f.confidence == "确证"),
        "suspect": sum(1 for f in res.findings if f.confidence == "疑似"),
        "checked": len(executed),
        "skipped": len(res.skipped),
    }
    log("[*] 判定完成：命中 %d 项（高 %d / 中 %d / 低 %d），已执行 %d 项，未执行 %d 项"
        % (res.stats["findings"], res.stats["high"], res.stats["mid"],
           res.stats["low"], res.stats["checked"], res.stats["skipped"]))
    return res


__all__ = ["evaluate", "ScanContext", "Finding", "JudgeResult", "detectors"]
