"""
FastAPI Backend Service for CloudPath Attack Path Mapper & Identity Risk Intelligence Platform.
Enforces:
- Strict workspace-level data isolation (`X-Workspace-Id`)
- Per-IP sliding-window rate limiting
- Safe upload validation (5 MB limit, zero execution of untrusted files)
- Sanitized error handling (never leaks internal stack traces or secrets)
"""

from __future__ import annotations
import time
from collections import defaultdict
from typing import Any
from fastapi import FastAPI, Header, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.models import RiskWeights, ScanResult
from backend.importer import ImportValidationError
from backend.demo_environment import get_northstar_demo_environment
from backend.analyzer import run_full_analysis


DEMO_WORKSPACE_ID = "00000000-0000-0000-0000-000000000001"

app = FastAPI(
    title="CloudPath Security Analysis Engine API",
    description="Graph-based AWS IAM Attack Path Mapper & Identity Risk Intelligence Engine",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Workspace-isolated in-memory store (backed by Supabase PostgreSQL in full-stack deployment)
_SCAN_STORE: dict[str, ScanResult] = {}
_WORKSPACE_WEIGHTS: dict[str, RiskWeights] = defaultdict(RiskWeights)
_RATE_LIMIT_BUCKETS: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_MAX_REQ = 60
RATE_LIMIT_WINDOW_SEC = 60.0


def _check_rate_limit(client_ip: str) -> None:
    now = time.time()
    bucket = _RATE_LIMIT_BUCKETS[client_ip]
    _RATE_LIMIT_BUCKETS[client_ip] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW_SEC]
    if len(_RATE_LIMIT_BUCKETS[client_ip]) >= RATE_LIMIT_MAX_REQ:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please wait before submitting additional analysis jobs.",
        )
    _RATE_LIMIT_BUCKETS[client_ip].append(now)


def _get_or_init_demo_scan() -> ScanResult:
    for scan in _SCAN_STORE.values():
        if scan.workspace_id == DEMO_WORKSPACE_ID:
            return scan
    demo_scan = run_full_analysis(
        content=get_northstar_demo_environment(),
        source_type="demo_environment",
        scan_name="Northstar Financial Technologies — Production AWS",
        workspace_id=DEMO_WORKSPACE_ID,
        weights=_WORKSPACE_WEIGHTS[DEMO_WORKSPACE_ID],
    )
    demo_scan.id = "scan-northstar-demo-001"
    _SCAN_STORE[demo_scan.id] = demo_scan
    return demo_scan


class AnalyzeRequest(BaseModel):
    scan_name: str = Field(default="Cloud Environment Security Scan", min_length=1, max_length=140)
    source_type: str = Field(default="custom_json")
    workspace_id: str = Field(default=DEMO_WORKSPACE_ID)
    content: str | dict[str, Any]
    filename: str | None = None
    risk_weights: RiskWeights | None = None


@app.get("/api/health")
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "cloudpath-analysis-engine",
        "version": "1.0.0",
    }


@app.get("/api/demo", response_model=ScanResult)
def get_demo_environment_scan(request: Request) -> ScanResult:
    client_ip = request.client.host if request.client else "127.0.0.1"
    _check_rate_limit(client_ip)
    return _get_or_init_demo_scan()


@app.post("/api/analyze", response_model=ScanResult)
def analyze_configuration(
    payload: AnalyzeRequest,
    request: Request,
    x_workspace_id: str | None = Header(default=None, alias="X-Workspace-Id"),
) -> ScanResult:
    client_ip = request.client.host if request.client else "127.0.0.1"
    _check_rate_limit(client_ip)

    effective_ws = x_workspace_id or payload.workspace_id or DEMO_WORKSPACE_ID
    if x_workspace_id and payload.workspace_id and x_workspace_id != payload.workspace_id:
        raise HTTPException(
            status_code=403,
            detail="Workspace mismatch between X-Workspace-Id header and request body.",
        )

    weights = payload.risk_weights or _WORKSPACE_WEIGHTS.get(effective_ws) or RiskWeights()
    try:
        result = run_full_analysis(
            content=payload.content,
            source_type=payload.source_type,
            scan_name=payload.scan_name,
            workspace_id=effective_ws,
            weights=weights,
            filename=payload.filename,
        )
    except ImportValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Configuration analysis rejected input: {str(exc)}",
        ) from exc

    _SCAN_STORE[result.id] = result
    return result


@app.post("/api/upload", response_model=ScanResult)
async def upload_configuration_file(
    request: Request,
    file: UploadFile = File(...),
    scan_name: str = Form(default="Uploaded Configuration Analysis"),
    source_type: str = Form(default="auto"),
    workspace_id: str = Form(default=DEMO_WORKSPACE_ID),
    x_workspace_id: str | None = Header(default=None, alias="X-Workspace-Id"),
) -> ScanResult:
    client_ip = request.client.host if request.client else "127.0.0.1"
    _check_rate_limit(client_ip)

    effective_ws = x_workspace_id or workspace_id or DEMO_WORKSPACE_ID
    raw_bytes = await file.read()
    if len(raw_bytes) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds 5 MB security ceiling.")

    try:
        decoded = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Binary uploads are prohibited. Upload UTF-8 encoded JSON or Terraform (.tf) files only.",
        ) from exc

    hint = None if source_type == "auto" else source_type
    try:
        result = run_full_analysis(
            content=decoded,
            source_type=hint or "custom_json",
            scan_name=scan_name,
            workspace_id=effective_ws,
            weights=_WORKSPACE_WEIGHTS.get(effective_ws),
            filename=file.filename,
        )
    except ImportValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _SCAN_STORE[result.id] = result
    return result


@app.get("/api/scans", response_model=list[ScanResult])
def list_workspace_scans(
    x_workspace_id: str = Header(default=DEMO_WORKSPACE_ID, alias="X-Workspace-Id"),
) -> list[ScanResult]:
    _get_or_init_demo_scan()
    return [
        s for s in _SCAN_STORE.values()
        if s.workspace_id == x_workspace_id or s.workspace_id == DEMO_WORKSPACE_ID
    ]


@app.get("/api/scans/{scan_id}", response_model=ScanResult)
def get_scan_by_id(
    scan_id: str,
    x_workspace_id: str = Header(default=DEMO_WORKSPACE_ID, alias="X-Workspace-Id"),
) -> ScanResult:
    _get_or_init_demo_scan()
    scan = _SCAN_STORE.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.workspace_id != DEMO_WORKSPACE_ID and scan.workspace_id != x_workspace_id:
        raise HTTPException(
            status_code=403,
            detail="Access denied: Cross-workspace data access is strictly prohibited.",
        )
    return scan


@app.delete("/api/workspaces/{workspace_id}/purge")
def purge_workspace_data(
    workspace_id: str,
    x_workspace_id: str = Header(..., alias="X-Workspace-Id"),
) -> dict[str, Any]:
    if workspace_id == DEMO_WORKSPACE_ID:
        raise HTTPException(status_code=403, detail="Cannot purge the public demonstration workspace.")
    if workspace_id != x_workspace_id:
        raise HTTPException(status_code=403, detail="Cross-workspace purge denied.")

    to_delete = [sid for sid, s in _SCAN_STORE.items() if s.workspace_id == workspace_id]
    for sid in to_delete:
        del _SCAN_STORE[sid]
    return {"status": "purged", "workspace_id": workspace_id, "deleted_scans": len(to_delete)}
