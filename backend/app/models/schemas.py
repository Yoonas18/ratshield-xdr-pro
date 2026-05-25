from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    key: str
    value: str


class TimelineEvent(BaseModel):
    time: str
    title: str
    details: str
    severity: str = "info"


class Finding(BaseModel):
    id: str
    title: str
    description: str
    platform: str
    category: str
    severity: str = "info"
    risk_score: int = 0
    confidence: int = 50
    evidence: List[Evidence] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    mitre: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    explanation: str = ""


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    persistence: int = 0
    network: int = 0
    process: int = 0
    file: int = 0
    android: int = 0


class ScanResult(BaseModel):
    scan_id: str
    target: str
    platform: str
    started_at: str
    completed_at: str
    total_findings: int
    highest_risk: int
    verdict: str
    summary: ScanSummary
    findings: List[Finding]
    timeline: List[TimelineEvent] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
