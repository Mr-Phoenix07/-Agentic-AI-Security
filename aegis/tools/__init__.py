"""Controlled external-tool integration layer.

This package is the bridge between AEGIS's agentic orchestration and external
security tooling (Nmap, Nuclei, httpx, ffuf, Semgrep, Trivy, …). It exists to
make that bridge *safe by construction*:

* :mod:`aegis.tools.spec`      — the standardized tool-adapter contract.
* :mod:`aegis.tools.catalog`   — built-in adapter specs (executable + docs-only).
* :mod:`aegis.tools.registry`  — the tool registry + intelligent test selection.
* :mod:`aegis.tools.execution` — the single controlled execution choke point
  (scope-gated, no-shell, dry-run-by-default, approval-gated, fully audited).

Nothing outside this package should call :mod:`subprocess`; route every external
tool through :class:`~aegis.tools.execution.ToolExecutor`.
"""

from __future__ import annotations

from .catalog import default_catalog
from .execution import (
    ApprovalCallback,
    ToolExecutionError,
    ToolExecutor,
    ToolResult,
    ToolRunRecord,
    deny_all_approvals,
)
from .pipeline import (
    PipelineBudget,
    PipelineResult,
    RecursiveScanner,
    ScanNode,
    TargetExpander,
)
from .registry import SelectedTool, SelectionPlan, TargetProfile, ToolRegistry
from .runner import RunOutput, ToolRunner, ToolRunnerLike
from .spec import (
    ParsedObservation,
    RiskLevel,
    ToolCategory,
    ToolInvocation,
    ToolSpec,
)
from .validation import (
    ValidationRequest,
    ValidationResult,
    ValidationStatus,
    Validator,
)

__all__ = [
    "default_catalog",
    "ToolRegistry", "TargetProfile", "SelectionPlan", "SelectedTool",
    "ToolExecutor", "ToolResult", "ToolRunRecord", "ToolExecutionError",
    "ApprovalCallback", "deny_all_approvals",
    "ToolSpec", "ToolInvocation", "ToolCategory", "RiskLevel", "ParsedObservation",
    # runner + recursive scanning
    "ToolRunner", "ToolRunnerLike", "RunOutput",
    "RecursiveScanner", "PipelineBudget", "PipelineResult", "ScanNode",
    "TargetExpander",
    # approval-gated validation
    "Validator", "ValidationRequest", "ValidationResult", "ValidationStatus",
]
