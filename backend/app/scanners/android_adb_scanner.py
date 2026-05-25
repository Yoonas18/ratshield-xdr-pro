from __future__ import annotations

import re
import subprocess

from backend.app.core.rules import ANDROID_DANGEROUS_PERMISSIONS, MITRE_MAP
from backend.app.core.risk_engine import finalize_scan
from backend.app.models.schemas import utc_now
from backend.app.scanners.common import new_result, finding, event


def adb(cmd: list[str], timeout: int = 8) -> str:
    try:
        return subprocess.check_output(["adb"] + cmd, text=True, stderr=subprocess.STDOUT, timeout=timeout)
    except FileNotFoundError:
        return "ADB_NOT_FOUND"
    except subprocess.CalledProcessError as e:
        return e.output or "ADB_ERROR"
    except Exception as e:
        return f"ADB_ERROR: {e}"


def list_packages() -> list[str]:
    out = adb(["shell", "pm", "list", "packages"])
    return [line.replace("package:", "").strip() for line in out.splitlines() if line.startswith("package:")]


def package_dump(pkg: str) -> str:
    return adb(["shell", "dumpsys", "package", pkg], timeout=10)


def scan_android_adb():
    r = new_result("Android device via ADB", "android")
    r.timeline.append(event("Android ADB scan started", "Checking packages, permissions and running services."))
    state = adb(["get-state"])
    if "ADB_NOT_FOUND" in state:
        r.findings.append(finding("ADB not installed", "Android scan requires adb in PATH.", "android", "android", 5, {"Error": state}, ["Install Android platform-tools and retry."], [], ["setup"], 95))
        r.completed_at = utc_now(); return finalize_scan(r)
    if "device" not in state:
        r.findings.append(finding("No Android device connected", "ADB did not find an authorized device.", "android", "android", 5, {"ADB state": state.strip()}, ["Enable USB debugging and accept the RSA prompt on the device."], [], ["setup"], 95))
        r.completed_at = utc_now(); return finalize_scan(r)
    pkgs = list_packages()[:400]
    risky_count = 0
    for pkg in pkgs:
        dump = package_dump(pkg)
        perms = [p for p in ANDROID_DANGEROUS_PERMISSIONS if p in dump]
        score = sum(ANDROID_DANGEROUS_PERMISSIONS[p] for p in perms)
        flags = []
        lower = dump.lower()
        if "receiver" in lower and "boot_completed" in lower:
            score += 20; flags.append("BOOT_COMPLETED receiver")
        if "accessibility" in lower:
            score += 25; flags.append("accessibility reference")
        if "deviceadminreceiver" in lower or "device_admin" in lower:
            score += 25; flags.append("device admin reference")
        if "com.android" not in pkg and score >= 35:
            risky_count += 1
            r.findings.append(finding("Risky Android app permission cluster", "Application requests privacy-sensitive permissions or persistence-style capabilities.", "android", "android", min(95, score),
                {"Package": pkg, "Dangerous permissions": ", ".join(perms) or "none", "Extra flags": ", ".join(flags) or "none"},
                ["Verify whether the app is trusted and required.", "Review Accessibility, Device Admin, Notification Access and Overlay settings.", "Uninstall or disable if not business-approved."],
                MITRE_MAP["android"], ["android", "permissions", "privacy-risk"], 70,
                "Android RATs commonly combine permissions for SMS, camera, microphone, overlay, accessibility or boot persistence."))
    services = adb(["shell", "dumpsys", "activity", "services"], timeout=10)
    for line in services.splitlines()[:3000]:
        if re.search(r"accessibility|notification|overlay|record|camera|sms", line, re.I):
            r.findings.append(finding("Interesting Android background service", "A running service references sensitive capability keywords.", "android", "android", 35,
                {"Service line": line.strip()[:300]}, ["Correlate this service with package permissions and user approval."], MITRE_MAP["android"], ["service"], 45,
                "This is an indicator for triage only; many legitimate apps use background services."))
    r.timeline.append(event("Android ADB scan completed", f"Checked {len(pkgs)} packages and found {risky_count} risky package clusters.", "medium" if risky_count else "info"))
    r.completed_at = utc_now()
    return finalize_scan(r)
