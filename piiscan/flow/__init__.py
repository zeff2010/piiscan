"""标准作业流程（SOP）编排层。

把「人工检测员怎么测」固化成 P0~P8 九个阶段，
AI 接管其中的查看、比对、判定三环，人工只做复核与取证。

    from piiscan.flow import run_flow
    fr = run_flow(package="com.xxx", scan_result=res, static_result=st)

流程定义在 analysis/checkflow.yaml，改流程改那里，不用动代码。
"""
from .models import (FAIL, NOT_TESTED, PASS, SUSPECT, STATE_LABELS,
                     Evidence, FlowResult, ItemState, PhaseResult, ReportRow)
from . import checklist as _CL
from . import compare as _CMP
from .sop import FlowRunner, run_flow

checklist = _CL
compare = _CMP

__all__ = ["run_flow", "FlowRunner", "FlowResult", "ItemState", "PhaseResult",
           "ReportRow", "Evidence", "checklist", "compare",
           "FAIL", "PASS", "SUSPECT", "NOT_TESTED", "STATE_LABELS"]
