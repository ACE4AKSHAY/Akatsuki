"""ECDAT Backend API Application (M7).

Enterprise Cryptographic Discovery & Analysis Tool
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import router
from backend.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    init_db()
    yield


app = FastAPI(
    title="ECDAT — Enterprise Cryptographic Discovery & Analysis Tool",
    description="Backend API and Orchestration Engine (M4, M5, M6, M7)",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS for M8 React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount core routers
app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
