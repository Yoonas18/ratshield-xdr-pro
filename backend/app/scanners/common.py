from __future__ import annotations

import platform
import socket
import uuid

from backend.app.core.risk_engine import finalize_scan
from backend.app.models.schemas import Evidence, Finding, ScanResult, ScanSummary, TimelineEvent, utc_now


def host_target() -> str:
    return f"{socket.gethostname()} ({platform.system()} {platform.release()})"


def new_result(target: str, platform_name: str) -> ScanResult:
    now = utc_now()
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        target=target,
        platform=platform_name,
        started_at=now,
        completed_at=now,
        total_findings=0,
        highest_risk=0,
        verdict="Pending",
        summary=ScanSummary(),
        findings=[],
        timeline=[],
        metadata={},
    )


def finding(
    title: str,
    description: str,
    platform_name: str,
    category: str,
    score: int,
    evidence: dict[str, str],
    recommendations: list[str],
    mitre: list[str] | None = None,
    tags: list[str] | None = None,
    confidence: int = 60,
    explanation: str = "",
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        title=title,
        description=description,
        platform=platform_name,
        category=category,
        risk_score=score,
        confidence=confidence,
        evidence=[Evidence(key=k, value=str(v)) for k, v in evidence.items()],
        recommendations=recommendations,
        mitre=mitre or [],
        tags=tags or [],
        explanation=explanation,
    )


def event(title: str, details: str, severity: str = "info") -> TimelineEvent:
    return TimelineEvent(time=utc_now(), title=title, details=details, severity=severity)


REVIEW_RECS = [
    "Validate the file/process with the system owner before removal.",
    "Collect hash, path, command line, parent process and network destination as evidence.",
    "If confirmed malicious, isolate the endpoint and perform full incident response.",
]
