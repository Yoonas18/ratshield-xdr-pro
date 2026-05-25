from backend.app.scanners.common import new_result, finding, event, REVIEW_RECS
from backend.app.core.risk_engine import finalize_scan
from backend.app.models.schemas import utc_now


def scan_demo():
    r = new_result("Safe Classroom Demo Endpoint", "demo")
    r.timeline.append(event("Demo scan started", "Generated safe RAT-like indicators. No malware is included."))
    r.findings.extend([
        finding("Probable RAT-style persistence", "A fake system-like executable is configured to auto-start from a user profile path.", "windows", "persistence", 92,
                {"Registry key": r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Image": r"C:\\Users\\Public\\svhost.exe", "Why suspicious": "Name mimics svchost.exe but path is not System32"},
                ["Disable the startup entry only after evidence collection.", "Investigate the binary hash and parent process."] + REVIEW_RECS,
                ["T1547 Boot or Logon Autostart Execution", "T1036 Masquerading"], ["startup", "masquerading", "windows"], 92,
                "Real Windows svchost.exe normally runs from System32. A similarly named binary in a user-writable path is a strong RAT indicator."),
        finding("Suspicious C2-like beacon", "Repeated outbound connection to an uncommon remote service port.", "linux", "network", 78,
                {"Process": "chrome_update", "Remote": "198.51.100.23:4444", "Pattern": "Periodic connection every 30 seconds"},
                ["Block the destination temporarily.", "Review DNS/proxy logs for the same host."] + REVIEW_RECS,
                ["T1071 Application Layer Protocol", "T1105 Ingress Tool Transfer"], ["c2", "beacon", "network"], 82,
                "RATs commonly maintain outbound command channels. Rare ports plus a fake updater name increase risk."),
        finding("Android spyware permission cluster", "Demo APK requests SMS, camera, microphone, overlay and accessibility-like permissions.", "android", "android", 88,
                {"Package": "com.update.security", "Permissions": "READ_SMS, CAMERA, RECORD_AUDIO, SYSTEM_ALERT_WINDOW, Accessibility service"},
                ["Revoke dangerous permissions.", "Uninstall if the app is not business-approved.", "Check device admin/accessibility settings."],
                ["Mobile T1626 Abuse Elevation Control Mechanism", "Mobile T1418 Software Discovery"], ["android", "permissions", "spyware"], 86,
                "A single app with privacy-sensitive permissions and overlay/accessibility access is consistent with Android RAT/spyware behavior."),
        finding("High entropy executable in temporary directory", "A suspicious binary-like file appears packed or encrypted based on entropy.", "windows", "file", 67,
                {"Path": r"C:\\Windows\\Temp\\agent_update.exe", "Entropy": "7.82", "Hash": "demo-hash-only"},
                ["Submit hash to internal reputation tools.", "Scan with YARA and AV in an isolated environment."],
                ["T1027 Obfuscated Files or Information"], ["packed", "file-analysis"], 70,
                "Packed malware often has high entropy. This does not prove malware, but it deserves deeper analysis."),
    ])
    r.timeline.append(event("Risk scoring completed", "4 demo findings generated and sorted by severity.", "high"))
    r.completed_at = utc_now()
    return finalize_scan(r)
