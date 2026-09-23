"""Vulnerability Management + SLA - FastAPI 入口（端口 5038）"""

from fastapi import FastAPI

app = FastAPI(title="Vulnerability Management + SLA", version="0.1.0")


@app.on_event("startup")
def _startup():
    from . import init_db
    init_db()


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vuln-management", "version": "0.1.0"}


def run():
    import uvicorn
    import os
    port = int(os.environ.get("WEB_PORT", "5038"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()
