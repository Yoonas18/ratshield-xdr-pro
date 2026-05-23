from fastapi import APIRouter
from backend.app.scanners.demo_scanner import scan_demo

router = APIRouter(prefix='/api')

@router.post('/scan/demo')
def api_scan_demo():
    return scan_demo()

@router.get('/status')
def status():
    return {'service':'online'}
