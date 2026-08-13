"""Structured scan completeness diagnostics."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class DiagnosticSeverity(StrEnum):
    WARNING = "warning"
    ERROR = "error"


class ScanDiagnostic(BaseModel):
    stage: str
    component: str
    severity: DiagnosticSeverity = DiagnosticSeverity.WARNING
    message: str
    recoverable: bool = True
