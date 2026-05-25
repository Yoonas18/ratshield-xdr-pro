from pathlib import Path

from fastapi import FastAPI, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api.routes import router

app = FastAPI(title="RATShield XDR Pro", version="0.2.0")
app.include_router(router)
ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
ASSETS = ROOT / "assets"
app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
app.mount("/assets", StaticFiles(directory=str(ASSETS)), name="assets")


@app.get("/")
def dashboard():
    return FileResponse(FRONTEND / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "name": "RATShield XDR Pro", "version": "0.2.0"}


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)
