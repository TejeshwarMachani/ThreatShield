from fastapi import FastAPI, APIRouter, File, UploadFile, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any
import uuid
from datetime import datetime, timezone
import hashlib
import filetype
import re

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Known malicious file signatures (MD5 hashes)
KNOWN_MALWARE_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File",
    "275a021bbfb6489e54d471899f7db9d1": "Generic Malware Sample",
}

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.pif', 
    '.vbs', '.js', '.jar', '.ps1', '.sh', '.app', '.deb', '.rpm'
]

# Suspicious patterns in file content
SUSPICIOUS_PATTERNS = [
    rb'eval\(',
    rb'exec\(',
    rb'system\(',
    rb'shell_exec',
    rb'passthru',
    rb'base64_decode',
    rb'\$_GET',
    rb'\$_POST',
    rb'cmd\.exe',
    rb'powershell',
    rb'<script>',
]

class ScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    file_size: int
    file_type: str
    md5_hash: str
    sha256_hash: str
    threat_level: str  # safe, suspicious, malicious
    threats_detected: List[str]
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    heuristic_score: int

class ScanHistory(BaseModel):
    model_config = ConfigDict(extra="ignore")
    scans: List[ScanResult]

def calculate_file_hashes(content: bytes) -> Dict[str, str]:
    """Calculate MD5 and SHA256 hashes of file content"""
    md5_hash = hashlib.md5(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    return {"md5": md5_hash, "sha256": sha256_hash}

def detect_file_type(content: bytes, filename: str) -> str:
    """Detect file type using magic numbers"""
    kind = filetype.guess(content)
    if kind is None:
        return f"Unknown ({Path(filename).suffix})"
    return f"{kind.mime} ({kind.extension})"

def heuristic_scan(content: bytes, filename: str, file_size: int) -> Dict[str, Any]:
    """Perform heuristic analysis on the file"""
    threats = []
    score = 0
    
    # Check file extension
    file_ext = Path(filename).suffix.lower()
    if file_ext in SUSPICIOUS_EXTENSIONS:
        threats.append(f"Suspicious file extension: {file_ext}")
        score += 30
    
    # Check file size (files > 100MB or < 10 bytes can be suspicious)
    if file_size > 100 * 1024 * 1024:
        threats.append("Unusually large file size")
        score += 10
    elif file_size < 10:
        threats.append("Unusually small file size")
        score += 5
    
    # Check for suspicious patterns in content (first 10MB only)
    scan_content = content[:10 * 1024 * 1024]
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, scan_content, re.IGNORECASE):
            threats.append(f"Suspicious code pattern detected")
            score += 20
            break  # Only count once
    
    # Check for null bytes in text files (possible binary disguised as text)
    if file_ext in ['.txt', '.log', '.csv', '.json', '.xml']:
        if b'\x00' in scan_content:
            threats.append("Binary content in text file")
            score += 25
    
    # Check for PE header in executables
    if file_ext in ['.exe', '.dll', '.sys']:
        if content[:2] == b'MZ':  # DOS header
            # This is normal for Windows executables, but we flag it as requiring caution
            threats.append("Windows executable detected - exercise caution")
            score += 15
    
    return {
        "threats": threats,
        "score": min(score, 100)  # Cap at 100
    }

def analyze_threat_level(heuristic_score: int, hash_matched: bool, threats: List[str]) -> str:
    """Determine overall threat level"""
    if hash_matched:
        return "malicious"
    elif heuristic_score >= 50 or len(threats) >= 3:
        return "suspicious"
    elif heuristic_score > 0 or len(threats) > 0:
        return "caution"
    else:
        return "safe"

@api_router.post("/scan", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    """Scan uploaded file for malware"""
    try:
        # Read file content
        content = await file.read()
        file_size = len(content)
        
        # Calculate hashes
        hashes = calculate_file_hashes(content)
        
        # Detect file type
        file_type = detect_file_type(content, file.filename)
        
        # Check against known malware hashes
        hash_matched = False
        threats = []
        
        if hashes["md5"] in KNOWN_MALWARE_HASHES:
            hash_matched = True
            threats.append(f"Known malware: {KNOWN_MALWARE_HASHES[hashes['md5']]}")
        
        # Perform heuristic scan
        heuristic_result = heuristic_scan(content, file.filename, file_size)
        threats.extend(heuristic_result["threats"])
        heuristic_score = heuristic_result["score"]
        
        # Determine threat level
        threat_level = analyze_threat_level(heuristic_score, hash_matched, threats)
        
        # Create scan result
        scan_result = ScanResult(
            filename=file.filename,
            file_size=file_size,
            file_type=file_type,
            md5_hash=hashes["md5"],
            sha256_hash=hashes["sha256"],
            threat_level=threat_level,
            threats_detected=threats if threats else ["No threats detected"],
            heuristic_score=heuristic_score
        )
        
        # Save to database
        doc = scan_result.model_dump()
        doc['scan_timestamp'] = doc['scan_timestamp'].isoformat()
        await db.scan_results.insert_one(doc)
        
        return scan_result
        
    except Exception as e:
        logger.error(f"Error scanning file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error scanning file: {str(e)}")

@api_router.get("/scan-history", response_model=List[ScanResult])
async def get_scan_history():
    """Get scan history"""
    scans = await db.scan_results.find({}, {"_id": 0}).sort("scan_timestamp", -1).limit(50).to_list(50)
    
    # Convert ISO string timestamps back to datetime objects
    for scan in scans:
        if isinstance(scan['scan_timestamp'], str):
            scan['scan_timestamp'] = datetime.fromisoformat(scan['scan_timestamp'])
    
    return scans

@api_router.get("/")
async def root():
    return {"message": "ThreatShield API - Malware Scanner"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()