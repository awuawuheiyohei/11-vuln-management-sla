"""Vulnerability Management + SLA Tracking - FastAPI 入口（端口 5038）"""

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from . import init_db
from .api.routes import router as api_router

ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "static"

app = FastAPI(
    title="Vulnerability Management + SLA Tracking",
    version="0.1.0",
    description="全生命周期漏洞管理 — CVSS+EPSS+KEV 加权 + SLA 追踪 + 风险例外",
)


@app.on_event("startup")
def _startup():
    init_db()


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vuln-mgmt", "version": "0.1.0"}


app.include_router(api_router, prefix="/api")


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    async def index():
        idx = STATIC_DIR / "index.html"
        if idx.exists():
            return FileResponse(str(idx))
        return {"msg": "static/index.html not found"}
else:
    @app.get("/")
    async def index():
        return {"msg": "static dir not built", "docs": "/docs"}


def run():
    import uvicorn
    port = int(os.environ.get("WEB_PORT", "5038"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()
