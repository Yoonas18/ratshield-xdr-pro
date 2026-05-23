from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from backend.app.api.routes import router

app = FastAPI(title='RATShield XDR Pro', version='0.3.0')
app.include_router(router)
ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / 'frontend'
app.mount('/static', StaticFiles(directory=str(FRONTEND)), name='static')

@app.get('/')
def dashboard():
    return FileResponse(FRONTEND / 'index.html')

@app.get('/health')
def health():
    return {'status':'ok','name':'RATShield XDR Pro','version':'0.3.0'}
