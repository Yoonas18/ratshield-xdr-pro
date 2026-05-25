from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(prefix="/api")


@router.post("/scan/local")
def api_scan_local():
    from backend.app.core.reporting import save_reports
    from backend.app.scanners.local_scanner import scan_local

    result = scan_local()
    save_reports(result)
    return result


@router.post("/scan/demo")
def api_scan_demo():
    from backend.app.core.reporting import save_reports
    from backend.app.scanners.demo_scanner import scan_demo

    result = scan_demo()
    save_reports(result)
    return result


@router.post("/scan/android")
def api_scan_android():
    from backend.app.core.reporting import save_reports
    from backend.app.scanners.android_adb_scanner import scan_android_adb

    result = scan_android_adb()
    save_reports(result)
    return result


@router.get("/reports/latest-json")
def latest_json():
    from backend.app.core.reporting import LATEST_JSON, save_reports
    from backend.app.scanners.demo_scanner import scan_demo

    if not LATEST_JSON.exists():
        result = scan_demo()
        save_reports(result)
    return FileResponse(LATEST_JSON, filename="ratshield_latest_scan.json", media_type="application/json")


@router.get("/reports/latest-html")
def latest_html():
    from backend.app.core.reporting import LATEST_HTML, save_reports
    from backend.app.scanners.demo_scanner import scan_demo

    if not LATEST_HTML.exists():
        result = scan_demo()
        save_reports(result)
    return FileResponse(LATEST_HTML, filename="ratshield_investigation_report.html", media_type="text/html")
