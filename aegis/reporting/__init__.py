"""Reporting: framework mappings, report model/builder, and renderers."""

from __future__ import annotations

from .frameworks import (
    frameworks_for,
    mitigations_for,
    regression_tests_for,
)
from .models import Report, ReportBuilder
from .renderer import render_html, render_json, render_markdown

__all__ = [
    "Report", "ReportBuilder", "render_html", "render_json", "render_markdown",
    "frameworks_for", "mitigations_for", "regression_tests_for",
]
