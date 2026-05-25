import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.scanners.local_scanner import scan_local
from backend.app.scanners.demo_scanner import scan_demo
from backend.app.scanners.android_adb_scanner import scan_android_adb
from backend.app.core.reporting import save_reports


def main():
    parser = argparse.ArgumentParser(description="RATShield XDR Pro CLI")
    parser.add_argument("--target", choices=["local", "demo", "android"], required=True)
    args = parser.parse_args()
    result = scan_local() if args.target == "local" else scan_android_adb() if args.target == "android" else scan_demo()
    save_reports(result)
    print(result.model_dump_json(indent=2))
    print("\nReports saved: reports/latest_scan.json and reports/latest_scan.html")


if __name__ == "__main__":
    main()
