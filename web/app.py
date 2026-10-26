from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from config.loader import load_config
from analyzers.dispatcher import scan_target
from output.enricher import enrich_sarif
from storage.db import init_db, create_scan, save_findings, list_scans, get_findings


app = FastAPI(title="secure-scan")
templates = Jinja2Templates(directory="web/templates")
SessionLocal = init_db()


class ScanRequest(BaseModel):
    target_path: str


def _finding_to_dict(f):
    return {
        "rule_id": f.rule_id,
        "file_path": f.file_path,
        "line": f.line,
        "severity": f.severity,
        "cwe": f.cwe,
        "message": f.message,
        "remediation": f.remediation,
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    session = SessionLocal()
    try:
        scans = list_scans(session)
        findings = get_findings(session, scans[0].id) if scans else []
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "scans": scans, "findings": findings},
        )
    finally:
        session.close()


@app.get("/findings")
def get_findings_api(scan_id: str | None = None):
    session = SessionLocal()
    try:
        if not scan_id:
            scans = list_scans(session)
            if not scans:
                return JSONResponse({"scan_id": None, "findings": []})
            scan_id = scans[0].id
        findings = get_findings(session, scan_id)
        return JSONResponse({
            "scan_id": scan_id,
            "findings": [_finding_to_dict(f) for f in findings],
        })
    finally:
        session.close()


@app.post("/scan")
async def post_scan(req: ScanRequest):
    session = SessionLocal()
    try:
        cfg = load_config()
        raw_results = await run_in_threadpool(scan_target, req.target_path, cfg)
        sarif = enrich_sarif(raw_results)
        scan = create_scan(session, req.target_path)
        save_findings(session, scan.id, sarif)
        return JSONResponse({"scan_id": scan.id})
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@app.get("/scans")
def get_scans_api():
    session = SessionLocal()
    try:
        scans = list_scans(session)
        return JSONResponse([
            {
                "id": s.id,
                "target_path": s.target_path,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "total_findings": s.total_findings,
            }
            for s in scans
        ])
    finally:
        session.close()


@app.get("/health")
def health():
    return {"status": "ok"}
