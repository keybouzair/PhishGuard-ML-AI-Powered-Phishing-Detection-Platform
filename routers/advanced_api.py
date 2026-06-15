"""
FastAPI Advanced Phishing Detection Router

This module defines the new async API endpoints for the extended features:
1. Visual Brand Impersonation Scanning
2. QR Code Phishing Scanning (Quishing)
3. Email Intelligence Parsing (.eml)

It interacts with the existing ML pipeline where appropriate.
"""

import os
import logging
from typing import Dict, Any, List

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

# Import our new services
from services.visual_analysis import VisualAnalysisService
from services.qr_scanner import QRScannerService

from routes.soc_routes import soc_router
from agents.response_orchestrator import response_orchestrator
from agents.threat_hunter import threat_hunter

# Attempt to import existing threat intel for integration
try:
    import threat_intelligence as ti
    from integrations import defense_agent, notify_phishing_detection
    INTEGRATION_AVAILABLE = True
except ImportError:
    INTEGRATION_AVAILABLE = False
    print("Warning: Could not import existing legacy integrations. Running FastAPI in standalone mode.")

# Configure Security Logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("security")

# Initialize FastAPI App
app = FastAPI(
    title="Phishing Detection Advanced API & AI SOC",
    description="Extended enterprise-grade AI detection endpoints and autonomous SOC components.",
    version="2.0.0"
)

# Start/Stop background agent loops
@app.on_event("startup")
async def startup_event():
    import asyncio
    asyncio.create_task(threat_hunter.start_hunting_loop())
    asyncio.create_task(response_orchestrator.start_orchestrator())
    logger.info("AI SOC Autonomous background agents started.")

@app.on_event("shutdown")
def shutdown_event():
    threat_hunter.stop_hunting_loop()
    response_orchestrator.stop_orchestrator()
    logger.info("AI SOC Autonomous background agents stopped.")

# Include the AI SOC features
app.include_router(soc_router)

# Zero Trust: Restrict CORS (In production, replace '*' with specific domains)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Services
visual_service = VisualAnalysisService()
qr_service = QRScannerService(max_file_size_mb=10)

# --- Schemas ---

class VisualScanRequest(BaseModel):
    url: HttpUrl
    client_ip: str | None = None

class ScanResponse(BaseModel):
    status: str
    message: str | None = None
    data: Dict[str, Any]

# --- Helper Functions ---

def _process_extracted_urls(urls: List[str], source: str, background_tasks: BackgroundTasks):
    """
    Queue extracted URLs into the existing threat pipeline via background tasks.
    """
    if not INTEGRATION_AVAILABLE:
        logger.warning("Pipeline integrations unavailable. Processing skipped.")
        return

    logger.info(f"Queuing {len(urls)} URLs extracted from {source} for analysis.")
    
    for url in urls:
        # We run the existing threat_intel synchronously in the background task
        background_tasks.add_task(_analyze_and_respond, url, source)

def _analyze_and_respond(url: str, source: str):
    """Execute the legacy threat intel and active defense."""
    try:
        # 1. Run legacy threat intel
        threat_result = ti.check_url(url)
        threat_score = threat_result.get('threat_score', 0)
        
        # 2. Trigger active defense if critical
        if threat_score > 50:
             notify_phishing_detection(
                 url=url, 
                 threat_score=threat_score, 
                 details={"source": source, "intel": threat_result},
                 user="system_auto_scanner"
             )
    except Exception as e:
        logger.error(f"Background analysis failed for {url}: {e}")

# --- API Routes ---

@app.post("/api/visual-scan", response_model=ScanResponse)
async def visual_scan(request: VisualScanRequest, background_tasks: BackgroundTasks):
    """
    Endpoint for Visual Brand Impersonation Scanning.
    Takes a screenshot of the URL and uses Vision LLM to detect spoofing.
    """
    logger.info(f"Visual scan requested for: {request.url}")
    url_str = str(request.url)
    
    try:
        result = await visual_service.analyze_url(url_str)
        
        # If impersonation is high, queue defense actions
        if result.get("status") == "success" and result.get("impersonation_score", 0) > 80:
             background_tasks.add_task(
                 _analyze_and_respond, 
                 url_str, 
                 "visual_impersonation_engine"
             )
             
        return ScanResponse(status="success", data=result)
        
    except Exception as e:
        logger.error(f"Visual scan failed: {e}")
        raise HTTPException(status_code=500, detail="Visual analysis failed")

@app.post("/api/upload-scan", response_model=ScanResponse)
async def upload_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Endpoint for Quishing Detection.
    Accepts an Image or PDF and extracts QR code URLs.
    """
    logger.info(f"QR/Quishing scan requested for file: {file.filename}")
    
    # Zero Trust: MIME validation
    allowed_types = ["image/jpeg", "image/png", "image/webp", "application/pdf"]
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="Invalid file type. Must be image or PDF.")
        
    try:
        file_bytes = await file.read()
        result = await qr_service.extract_urls_from_file(file_bytes, file.filename)
        
        if result.get("urls_found"):
             _process_extracted_urls(
                 result["urls_found"], 
                 f"qr_upload_{file.filename}", 
                 background_tasks
             )
             
        return ScanResponse(status="success", data=result)
        
    except Exception as e:
        logger.error(f"Upload scan failed: {e}")
        raise HTTPException(status_code=500, detail="File processing failed")

@app.post("/api/email-scan", response_model=ScanResponse)
async def email_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Endpoint for Email Intelligence Parsing.
    Accepts raw .eml files, extracts URLs, and runs NLP risk scoring.
    """
    logger.info(f"Email scan requested for file: {file.filename}")
    
    if not file.filename.lower().endswith(".eml"):
         raise HTTPException(status_code=400, detail="Invalid file type. Must be .eml.")
         
    try:
        # Email parsing service removed
        raise HTTPException(status_code=503, detail="Email parsing service not available")
        
    except Exception as e:
        logger.error(f"Email scan failed: {e}")
        raise HTTPException(status_code=500, detail="Email processing failed")

# --- Startup/Health ---

@app.get("/api/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "services": {
            "visual_analysis": "ready",
            "qr_scanner": "ready",
            "email_parser": "removed",
            "ai_soc_agents": "ready"
        }
    }

# Entry point for running the server standalone
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("routers.advanced_api:app", host="0.0.0.0", port=8000, reload=True)
