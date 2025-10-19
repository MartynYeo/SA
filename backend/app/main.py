from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base
from app.routers.uploads import router as uploads_router
from app.routers.iam_data import router as iam_data_router
from app.routers.llm import router as llm_router

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AWS IAM Viewer API",
    description="Backend API for Permeo",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Next.js dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(uploads_router, prefix="/api/uploads", tags=["uploads"])
app.include_router(iam_data_router, prefix="/api/iam", tags=["iam-data"])
app.include_router(llm_router, prefix="/api/llm", tags=["llm"])

@app.get("/")
async def root():
    return {"message": "AWS IAM Viewer API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/api/config")
async def runtime_config():
    return {"llm_disabled": settings.llm_disabled}