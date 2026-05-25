from __future__ import annotations

from collections import Counter

from backend.app.models.schemas import Finding, ScanResult, ScanSummary


def severity_from_score(score: int) -> str:
    if score >= 86:
        return "critical"
    if score >= 61:
        return "high"
    if score >= 31:
        return "medium"
    if score >= 1:
        return "low"
    return "info"


def verdict_from_score(score: int) -> str:
    if score >= 86:
        return "Probable RAT behavior detected"
    if score >= 61:
        return "High-risk suspicious behavior detected"
    if score >= 31:
        return "Suspicious indicators detected"
    return "No major RAT-like behavior detected by current rules"


def finalize_finding(f: Finding) -> Finding:
    f.risk_score = max(0, min(100, int(f.risk_score)))
    f.confidence = max(1, min(100, int(f.confidence)))
    f.severity = severity_from_score(f.risk_score)
    if not f.explanation:
        f.explanation = "This item matched one or more RAT-like indicators. Review the evidence before taking action."
    return f


def build_summary(findings: list[Finding]) -> ScanSummary:
    sev = Counter(f.severity for f in findings)
    cat = Counter(f.category for f in findings)
    return ScanSummary(
        critical=sev.get("critical", 0),
        high=sev.get("high", 0),
        medium=sev.get("medium", 0),
        low=sev.get("low", 0),
        info=sev.get("info", 0),
        persistence=cat.get("persistence", 0),
        network=cat.get("network", 0),
        process=cat.get("process", 0),
        file=cat.get("file", 0),
        android=cat.get("android", 0),
    )


def finalize_scan(result: ScanResult) -> ScanResult:
    result.findings = sorted([finalize_finding(f) for f in result.findings], key=lambda x: x.risk_score, reverse=True)
    result.total_findings = len(result.findings)
    result.highest_risk = max([f.risk_score for f in result.findings], default=0)
    result.summary = build_summary(result.findings)
    result.verdict = verdict_from_score(result.highest_risk)
    return result
