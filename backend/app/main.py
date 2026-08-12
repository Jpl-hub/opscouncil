from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from starlette.middleware.gzip import GZipMiddleware

from backend.app.api.routes import build_router
from backend.app.collaboration.manifest import AGENT_TOOL_SCOPES
from backend.app.core.config import ensure_runtime_dirs, settings
from backend.app.core.database import SessionLocal, init_db
from backend.app.mcp.protocol import build_mcp_router
from backend.app.runtime.tool_registry import build_runtime_tool_registry


ensure_runtime_dirs()
init_db()

registry = build_runtime_tool_registry(SessionLocal)

app = FastAPI(title=settings.app_name, version="0.1.0")
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=6)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(build_mcp_router(registry))
for agent_name, allowed_tools in AGENT_TOOL_SCOPES.items():
    app.include_router(
        build_mcp_router(
            registry.scoped(allowed_tools),
            path=f"/mcp/agents/{agent_name}",
            server_name=f"opscouncil-{agent_name}",
            server_title=f"OpsCouncil {agent_name}",
            identity_subject=f"agent:{agent_name}",
        )
    )
app.include_router(build_router(registry))


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


frontend_dist_dir = settings.frontend_dist_dir.resolve()
index_file = frontend_dist_dir / "index.html"

if index_file.exists():

    @app.get("/", include_in_schema=False)
    def serve_frontend_index() -> FileResponse:
        return FileResponse(index_file)

    @app.get("/{path:path}", include_in_schema=False)
    def serve_frontend(path: str) -> FileResponse:
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="not found")
        target = (frontend_dist_dir / path).resolve()
        if frontend_dist_dir in target.parents and target.is_file():
            return FileResponse(target)
        return FileResponse(index_file)
