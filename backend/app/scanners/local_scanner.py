from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

try:
    import psutil
except ModuleNotFoundError:
    psutil = None

from backend.app.core.rules import (
    SUSPICIOUS_PORTS,
    SUSPICIOUS_WINDOWS_PATHS,
    SUSPICIOUS_LINUX_PATHS,
    SYSTEM_NAME_MIMICS,
    SUSPICIOUS_SCRIPT_NAMES,
    MITRE_MAP,
)
from backend.app.core.static_analyzer import sha256_file, entropy_file, lightweight_yara_match
from backend.app.core.risk_engine import finalize_scan
from backend.app.models.schemas import utc_now
from backend.app.scanners.common import new_result, finding, event, host_target, REVIEW_RECS

YARA_TERMS = {
    "generic_rat_strings": ["keylogger", "screenshot", "webcam", "persistence", "connect", "download", "upload", "shell"],
    "c2_client_terms": ["beacon", "command", "control", "client", "mutex", "reconnect", "socket"],
}
SCRIPT_EXTENSIONS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
SCRIPT_SCAN_LIMIT = 180
SCRIPT_SIZE_LIMIT = 300_000
TEXT_RULES = [
    {
        "title": "Suspicious PowerShell loader",
        "category": "process",
        "score": 48,
        "confidence": 82,
        "tags": ["powershell", "obfuscation", "loader"],
        "mitre": MITRE_MAP["process"] + MITRE_MAP["defense_evasion"],
        "terms": ["powershell", "pwsh", "-enc", "-encodedcommand", "frombase64string", "invoke-expression", "iex ", "downloadstring", "invoke-webrequest", "new-object net.webclient", "windowstyle hidden", "noprofile"],
        "min_hits": 3,
        "explanation": "Encoded commands, IEX, WebClient and hidden-window execution are common malware launch traits.",
        "description": "PowerShell content or command line uses loader-style or obfuscated execution patterns.",
    },
    {
        "title": "Suspicious scheduled task masquerade",
        "category": "persistence",
        "score": 58,
        "confidence": 86,
        "tags": ["schtasks", "masquerading", "persistence"],
        "mitre": MITRE_MAP["persistence"] + MITRE_MAP["defense_evasion"],
        "terms": ["schtasks", "/create", "register-scheduledtask", "microsoftantiviruscriticalupdates", "criticalupdatescore", "criticalupdatesua", "criticalupdatesdf", "windowsdefender", "securityupdate", "securityhealth"],
        "min_hits": 2,
        "explanation": "Masqueraded task names are a common persistence and disguise technique used by RATs and trojans.",
        "description": "Task scheduler output or script text references a fake update or antivirus-looking task name.",
    },
    {
        "title": "Screen capture with mail exfil markers",
        "category": "file",
        "score": 62,
        "confidence": 88,
        "tags": ["screen-capture", "exfiltration", "email"],
        "mitre": MITRE_MAP["collection"] + MITRE_MAP["exfiltration"],
        "terms": ["copyfromscreen", "screenshot", "screen capture", "bitmap", "send-mailmessage", "smtpclient", "attachment", "gmail", "smtp."],
        "min_hits": 3,
        "explanation": "The combination of screenshots and email attachments closely matches the repo's exfiltration workflow.",
        "description": "Script content shows screenshot collection and email attachment delivery behavior.",
    },
    {
        "title": "Suspicious defense evasion",
        "category": "process",
        "score": 40,
        "confidence": 80,
        "tags": ["defense-evasion", "pua", "tampering"],
        "mitre": MITRE_MAP["defense_evasion"],
        "terms": ["set-executionpolicy", "unrestricted", "bypass", "windowstyle hidden", "add-mppreference", "set-mppreference", "exclusionpath", "excludepath", "hidden"],
        "min_hits": 2,
        "explanation": "Attackers commonly lower PowerShell or Defender restrictions before launching the payload.",
        "description": "Command line or script text attempts to weaken PowerShell or Defender safeguards.",
    },
    {
        "title": "Living-off-the-land binary usage",
        "category": "process",
        "score": 44,
        "confidence": 78,
        "tags": ["lolbin", "delivery", "proxy-exec"],
        "mitre": MITRE_MAP["process"] + MITRE_MAP["defense_evasion"],
        "terms": ["mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "wscript", "cscript", "installutil"],
        "min_hits": 2,
        "explanation": "Proxy execution binaries are frequently abused to stage payloads and hide the true execution chain.",
        "description": "Command line or script uses common proxy execution binaries associated with malware delivery.",
    },
]


def _text_hits(text: str, terms: list[str]) -> list[str]:
    low = (text or "").lower()
    return [term for term in terms if term.lower() in low]


def _emit_text_rule_findings(r, platform_name: str, source_label: str, source_value: str, text: str):
    for rule in TEXT_RULES:
        hits = _text_hits(text, rule["terms"])
        if len(hits) < rule["min_hits"]:
            continue
        score = min(95, rule["score"] + max(0, len(hits) - rule["min_hits"]) * 4)
        ev = {source_label: source_value[:350], "Matched indicators": ", ".join(hits[:10])}
        if "gmail" in (text or "").lower() or "smtp" in (text or "").lower():
            ev["Delivery channel"] = "Email / SMTP"
        r.findings.append(
            finding(
                rule["title"],
                rule["description"],
                platform_name,
                rule["category"],
                score,
                ev,
                REVIEW_RECS + ["Correlate this indicator with parent process, file hash and any network destinations."],
                rule["mitre"],
                rule["tags"],
                rule["confidence"],
                rule["explanation"],
            )
        )


def _script_roots(system: str) -> list[Path]:
    roots: list[Path] = []
    if system == "Windows":
        for raw in [os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", ""), os.environ.get("TEMP", ""), os.environ.get("TMP", ""), os.environ.get("PROGRAMDATA", "")]:
            if raw:
                roots.append(Path(raw))
        for raw in [os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")]:
            if "%" not in raw:
                roots.append(Path(raw))
    else:
        roots.extend([Path.home() / ".config", Path.home() / ".local" / "share", Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")])
    seen = []
    for root in roots:
        if root and root.exists() and root not in seen:
            seen.append(root)
    return seen


def _is_suspicious_path(path: str, system: str) -> bool:
    low = (path or "").lower()
    paths = SUSPICIOUS_WINDOWS_PATHS if system == "Windows" else SUSPICIOUS_LINUX_PATHS
    return any(p in low for p in paths)


def scan_processes(r, system: str):
    checked_files = set()
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or [])[:500]
            score, reasons, tags = 0, [], ["process"]
            if any(m in name for m in SYSTEM_NAME_MIMICS):
                score += 25; reasons.append("process name mimics trusted system/update component"); tags.append("masquerading")
            if _is_suspicious_path(exe, system):
                score += 25; reasons.append("executable runs from user-writable or temporary path"); tags.append("suspicious-path")
            if any(s in name or s in cmdline.lower() for s in SUSPICIOUS_SCRIPT_NAMES):
                score += 15; reasons.append("command line/name contains suspicious remote-control wording")
            if any(term in cmdline.lower() for term in ["-enc", "-encodedcommand", "frombase64string", "invoke-expression", "downloadstring", "new-object net.webclient", "windowstyle hidden", "set-executionpolicy unrestricted", "bypass"]):
                score += 25; reasons.append("command line shows PowerShell obfuscation or defense-evasion patterns"); tags.extend(["powershell", "obfuscation"])
            if any(term in cmdline.lower() for term in ["schtasks", "register-scheduledtask", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "wscript", "cscript"]):
                score += 20; reasons.append("command line uses a living-off-the-land binary or scheduler"); tags.extend(["lolbin", "persistence"])
            _emit_text_rule_findings(r, system.lower(), "Command line", f"PID {info.get('pid')} / {info.get('name') or 'unknown'}", cmdline)
            if score:
                ev = {"PID": str(info.get("pid")), "Name": info.get("name") or "", "Path": exe or "unknown", "User": info.get("username") or "unknown", "Command line": cmdline}
                r.findings.append(finding("Suspicious process indicator", "; ".join(reasons), system.lower(), "process", min(80, score + 10), ev, REVIEW_RECS, MITRE_MAP["process"], tags, 65, "RATs often disguise process names and run from user-writable locations to avoid attention."))
            if exe and exe not in checked_files and Path(exe).exists():
                checked_files.add(exe)
                ent = entropy_file(exe)
                yara = lightweight_yara_match(exe, YARA_TERMS)
                if ent >= 7.5 or yara:
                    ev = {"Path": exe, "SHA256": sha256_file(exe) or "unavailable", "Entropy": str(ent), "Rule hits": ", ".join(yara) or "none"}
                    r.findings.append(finding("Suspicious executable content", "Executable has packed-like entropy or matched lightweight RAT string rules.", system.lower(), "file", 50 + (20 if yara else 0) + (10 if ent >= 7.5 else 0), ev, REVIEW_RECS, MITRE_MAP["file"], ["static-analysis", "file"], 55, "This is a lightweight static check. Treat it as triage and verify with full YARA/AV sandbox analysis."))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def scan_network(r, system: str):
    for c in psutil.net_connections(kind="inet"):
        if not c.raddr:
            continue
        try:
            remote_ip, remote_port = c.raddr.ip, int(c.raddr.port)
            pid = c.pid
            pname = psutil.Process(pid).name() if pid else "unknown"
        except Exception:
            continue
        if remote_port in SUSPICIOUS_PORTS:
            r.findings.append(finding("Suspicious outbound connection", "Process is connected to an uncommon port often seen in labs/backdoors/RAT tooling.", system.lower(), "network", 66, {"Process": pname, "PID": str(pid), "Remote": f"{remote_ip}:{remote_port}", "Status": str(c.status)}, ["Verify whether this destination is business-approved.", "Check firewall/proxy/DNS logs for repeated beacons."] + REVIEW_RECS, MITRE_MAP["network"], ["network", "c2-candidate"], 62, "Outbound connections are normal, but rare ports tied to suspicious processes increase RAT risk."))


def scan_windows_persistence(r):
    try:
        import winreg
        keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"), (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")]
        for hive, subkey in keys:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        low = str(value).lower()
                        if any(p in low for p in SUSPICIOUS_WINDOWS_PATHS) or any(m in low for m in SYSTEM_NAME_MIMICS):
                            r.findings.append(finding("Suspicious Windows autostart entry", "Startup entry points to a suspicious location or masqueraded file name.", "windows", "persistence", 74, {"Registry": subkey, "Name": name, "Value": str(value)}, REVIEW_RECS, MITRE_MAP["persistence"], ["registry", "startup"], 72, "Registry Run keys are commonly abused by RATs for persistence."))
                        if "powershell" in low or any(term in low for term in ["-enc", "-encodedcommand", "invoke-expression", "downloadstring", "windowstyle hidden"]):
                            _emit_text_rule_findings(r, "windows", "Registry value", f"{subkey}\\{name}", low)
            except Exception:
                pass
    except Exception:
        pass
    tasks = subprocess.check_output(["schtasks", "/query", "/fo", "LIST", "/v"], text=True, stderr=subprocess.DEVNULL, timeout=10) if system == "Windows" else ""
    for line in tasks.splitlines():
        low = line.lower()
        if any(p in low for p in SUSPICIOUS_WINDOWS_PATHS) or any(m in low for m in SYSTEM_NAME_MIMICS):
            r.findings.append(finding("Suspicious scheduled task reference", "Scheduled task output references suspicious path or masqueraded name.", "windows", "persistence", 61, {"Task line": line[:300]}, REVIEW_RECS, MITRE_MAP["persistence"], ["scheduled-task"], 55, "Scheduled tasks are a common persistence technique."))
        _emit_text_rule_findings(r, "windows", "Task output", "Scheduled tasks", low)


def scan_linux_persistence(r):
    files = ["/etc/crontab", "/etc/rc.local"] + [str(p) for p in Path("/etc/cron.d").glob("*") if p.is_file()]
    for f in files:
        try:
            text = Path(f).read_text(errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            low = line.lower()
            if any(p in low for p in SUSPICIOUS_LINUX_PATHS) or "curl" in low and "|" in low or "wget" in low and "|" in low:
                r.findings.append(finding("Suspicious Linux persistence entry", "Cron/boot script contains user-writable path or download-and-execute pattern.", "linux", "persistence", 70, {"File": f, "Line": line[:300]}, REVIEW_RECS, MITRE_MAP["persistence"], ["cron", "startup"], 67, "Cron and boot scripts are frequently abused for Linux RAT persistence."))
            _emit_text_rule_findings(r, "linux", "Persistence file", f, low)
    for svc in Path("/etc/systemd/system").glob("*.service"):
        try:
            text = svc.read_text(errors="ignore").lower()
        except Exception:
            continue
        if any(p in text for p in SUSPICIOUS_LINUX_PATHS) or any(m in text for m in SYSTEM_NAME_MIMICS):
            r.findings.append(finding("Suspicious systemd service", "Service references a suspicious path or masqueraded update/system name.", "linux", "persistence", 68, {"Service": str(svc)}, REVIEW_RECS, MITRE_MAP["persistence"], ["systemd"], 64, "Systemd services can make malware restart automatically after reboot."))
        _emit_text_rule_findings(r, "linux", "Service file", str(svc), text)


def scan_script_files(r, system: str):
    roots = _script_roots(system)
    seen_files = 0
    for root in roots:
        try:
            for path in root.rglob("*"):
                if seen_files >= SCRIPT_SCAN_LIMIT:
                    return
                if not path.is_file() or path.suffix.lower() not in SCRIPT_EXTENSIONS:
                    continue
                try:
                    if path.stat().st_size > SCRIPT_SIZE_LIMIT:
                        continue
                    text = path.read_text(errors="ignore")
                except Exception:
                    continue
                seen_files += 1
                _emit_text_rule_findings(r, system.lower(), "Script file", str(path), text)
        except Exception:
            continue


def scan_local():
    system = platform.system() or "unknown"
    r = new_result(host_target(), system.lower())
    r.timeline.append(event("Local scan started", "Collecting process, network, persistence and lightweight static indicators."))
    if psutil is None:
        r.findings.append(finding("psutil dependency missing", "Local scanning requires the psutil package, but it is not installed in this environment.", system.lower(), "process", 10, {"Missing dependency": "psutil"}, ["Install the project requirements and rerun the local scan."], [], ["setup"], 95, "The app can still load and run demo or Android scans, but local host inspection needs psutil."))
        r.timeline.append(event("Local scan completed", "psutil was unavailable, so only a dependency warning was generated.", "low"))
        r.completed_at = utc_now()
        return finalize_scan(r)
    scan_processes(r, system)
    scan_network(r, system)
    if system == "Windows":
        scan_windows_persistence(r)
    elif system == "Linux":
        scan_linux_persistence(r)
    scan_script_files(r, system)
    r.timeline.append(event("Local scan completed", f"Collected {len(r.findings)} findings.", "medium" if r.findings else "info"))
    r.completed_at = utc_now()
    return finalize_scan(r)
