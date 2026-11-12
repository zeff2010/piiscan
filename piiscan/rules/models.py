"""判定结果的数据模型。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

LEVEL_ORDER = {"高": 0, "中": 1, "低": 2}


@dataclass
class Evidence:
    """一条证据。kind 表示证据类型，对应 checkitems.yaml 的 evidence 字段。"""
    kind: str            # frida / policy / manifest / ui / traffic / code
    title: str
    detail: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """一个不符合项（对应人工报告里的一个「问题」）。"""
    rule_id: str
    title: str
    category_id: str = ""
    category_name: str = ""
    basis: str = ""
    unit: str = ""
    level: str = "中"                 # 高 / 中 / 低
    confidence: str = "疑似"           # 确证 / 疑似
    automation: str = ""              # L1 / L2 / L3 / L4
    description: str = ""
    facts: List[Tuple[str, str]] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    stacks: List[List[str]] = field(default_factory=list)
    shots: List[Dict[str, str]] = field(default_factory=list)
    advise: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)   # 涉及的信号 ID
    freq: int = 0
    pain: str = ""
    source: str = ""                  # static / policy / dynamic

    @property
    def sort_key(self):
        return (LEVEL_ORDER.get(self.level, 9), 0 if self.confidence == "确证" else 1,
                -self.freq, self.rule_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "title": self.title,
            "category_id": self.category_id, "category_name": self.category_name,
            "basis": self.basis, "unit": self.unit,
            "level": self.level, "confidence": self.confidence,
            "automation": self.automation, "description": self.description,
            "facts": [list(x) for x in self.facts], "steps": self.steps,
            "stacks": self.stacks, "advise": self.advise,
            "signals": self.signals, "freq": self.freq, "source": self.source,
            "evidence": [{"kind": e.kind, "title": e.title, "detail": e.detail}
                         for e in self.evidence],
        }


@dataclass
class JudgeResult:
    findings: List[Finding] = field(default_factory=list)
    checked: List[str] = field(default_factory=list)      # 已执行的检测项
    skipped: List[Dict[str, str]] = field(default_factory=list)  # 因缺证据未执行
    stats: Dict[str, Any] = field(default_factory=dict)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key)
