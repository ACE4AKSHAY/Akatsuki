"""
FastAPI Main Application for ECDAT Module M7 (Backend API & Orchestration).
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database import init_db
from backend.api.scans import router as scans_router
from backend.api.assets import router as assets_router
from backend.api.cbom import router as cbom_router
from backend.api.reports import router as reports_router
from backend.api.config_routes import router as config_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database schema
    init_db()
    yield
    # Shutdown: cleanup if needed


app = FastAPI(
    title="ECDAT Backend API (Module M7)",
    description=(
        "Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) Backend API.\n"
        "Coordinates discovery scanning, Mosca quantum risk assessment, PQC recommendations, "
        "and CycloneDX 1.6 Cryptography Bill of Materials (CBOM) export."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Enable CORS for Frontend (M8)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(scans_router)
app.include_router(assets_router)
app.include_router(cbom_router)
app.include_router(reports_router)
app.include_router(config_router)


@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "ECDAT Backend API (M7)", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
