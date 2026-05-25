SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6666, 8080, 9001, 9999, 12345, 54321}

SUSPICIOUS_WINDOWS_PATHS = [
    "\\appdata\\", "\\temp\\", "\\programdata\\", "\\users\\public\\", "\\windows\\temp\\", "\\recycle.bin\\"
]
SUSPICIOUS_LINUX_PATHS = [
    "/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/.config/", "/.local/", "/run/user/"
]
SYSTEM_NAME_MIMICS = [
    "svhost", "svchosts", "explorer32", "winlogon32", "system32", "lsasss", "lsas", "csrsss",
    "update_service", "chrome_update", "security_update", "kworkerx", "systemd-update", "dbus-update"
]
SUSPICIOUS_SCRIPT_NAMES = ["payload", "shell", "reverse", "rat", "client", "backdoor", "agent_update"]
SUSPICIOUS_POWERSHELL_TERMS = [
    "powershell", "pwsh", "-enc", "-encodedcommand", "frombase64string", "invoke-expression",
    "iex ", "downloadstring", "invoke-webrequest", "new-object net.webclient", "windowstyle hidden",
    "noprofile", "bypass", "unrestricted",
]
SUSPICIOUS_LOLBIN_TERMS = [
    "schtasks", "set-executionpolicy", "send-mailmessage", "smtpclient", "attachment", "gmail",
    "copyfromscreen", "screenshot", "bitmap", "mshta", "rundll32", "regsvr32", "certutil",
    "bitsadmin", "wscript", "cscript", "installutil",
]
TASK_MASQUERADE_TERMS = [
    "microsoftantiviruscriticalupdates", "criticalupdatescore", "criticalupdatesua", "criticalupdatesdf",
    "windowsdefender", "securityupdate", "securityhealth", "antivirus",
]
SCREEN_CAPTURE_TERMS = ["copyfromscreen", "screenshot", "screen capture", "graphics", "bitmap"]
MAIL_EXFIL_TERMS = ["send-mailmessage", "smtpclient", "attachment", "gmail", "smtp.", "mail from"]
DEFENSE_EVASION_TERMS = [
    "set-executionpolicy unrestricted", "set-executionpolicy bypass", "windowstyle hidden", "hidden",
    "noprofile", "bypass", "add-mppreference", "set-mppreference", "exclusionpath", "excludepath",
]
ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": 15,
    "android.permission.SEND_SMS": 20,
    "android.permission.RECEIVE_SMS": 15,
    "android.permission.READ_CONTACTS": 10,
    "android.permission.RECORD_AUDIO": 20,
    "android.permission.CAMERA": 20,
    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.READ_CALL_LOG": 15,
    "android.permission.WRITE_CALL_LOG": 15,
    "android.permission.READ_EXTERNAL_STORAGE": 10,
    "android.permission.MANAGE_EXTERNAL_STORAGE": 25,
    "android.permission.SYSTEM_ALERT_WINDOW": 25,
    "android.permission.REQUEST_INSTALL_PACKAGES": 15,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 40,
    "android.permission.BIND_DEVICE_ADMIN": 35,
    "android.permission.PACKAGE_USAGE_STATS": 25,
}
MITRE_MAP = {
    "persistence": ["T1547 Boot or Logon Autostart Execution", "T1053 Scheduled Task/Job"],
    "network": ["T1071 Application Layer Protocol", "T1105 Ingress Tool Transfer"],
    "process": ["T1036 Masquerading", "T1059 Command and Scripting Interpreter"],
    "file": ["T1027 Obfuscated Files or Information"],
    "android": ["Mobile T1626 Abuse Elevation Control Mechanism", "Mobile T1418 Software Discovery"],
    "defense_evasion": ["T1562 Impair Defenses", "T1027 Obfuscated Files or Information"],
    "collection": ["T1113 Screen Capture", "T1114 Email Collection"],
    "exfiltration": ["T1041 Exfiltration Over C2 Channel", "T1020 Data Exfiltration"],
}
