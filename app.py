import os
from typing import Optional
import uvicorn
from fastapi import Depends, FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
import security_core as sc
from model import ActivityLog, Base
from schemas import (
    BruteForceRequest,
    DecryptRequest,
    EncryptTextRequest,
    GeneratePasswordRequest,
    HashCrackRequest,
    HashIdentifyRequest,
    LogEntry,
    PasswordAuditRequest,
)

if "DATABASE_URL" not in os.environ and os.path.exists(".env"):
    with open(".env", encoding="utf-8") as f:
        for line in f:
            if line.startswith("DATABASE_URL="):
                os.environ["DATABASE_URL"] = line.split("=", 1)[1].strip().strip("\"'")
                break

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@localhost:5432/crypca",
)

engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base.metadata.create_all(bind=engine)          # auto-create tables on startup


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _log(db: Session, action: str, inp: str, result: str) -> None:
    db.add(ActivityLog(
        action=action,
        input_summary=inp[:500],
        result_summary=result[:2000],
    ))
    db.commit()
    

app = FastAPI(
    title="Crypca",
    description="Password & Cryptography Security Suite",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/", include_in_schema=False)
def index():
    return FileResponse("index.html")

#Password Auditor
@app.post("/api/audit-password", tags=["Password"])
def audit_password(req: PasswordAuditRequest, db: Session = Depends(get_db)):
    result = sc.audit_password(req.password)
    _log(db,
         "Password Audit",
         f"length={len(req.password)}",
         f"strength={result['strength']}, score={result['score']}, entropy={result['entropy_bits']} bits")
    return result

#Hash Identifier
@app.post("/api/identify-hash", tags=["Hashing"])
def identify_hash(req: HashIdentifyRequest, db: Session = Depends(get_db)):
    result = sc.identify_hash(req.hash_str)
    types  = [t["type"] for t in result["possible_types"]]
    _log(db,
         "Hash Identify",
         f"hash={req.hash_str[:32]}… (len={len(req.hash_str)})",
         f"possible={types}")
    return result

#Hash Cracker
@app.post("/api/crack-hash", tags=["Hashing"])
def crack_hash(req: HashCrackRequest, db: Session = Depends(get_db)):
    result  = sc.crack_hash(req.hash_str, req.hash_type, req.custom_words)
    status  = f"Cracked → '{result['plaintext']}'" if result.get("cracked") else f"Not found after {result.get('attempts', 0)} attempts"
    _log(db,
         "Hash Crack",
         f"hash={req.hash_str[:32]}…, type={req.hash_type}, custom_words={len(req.custom_words or [])}",
         status)
    return result

#Encrypt text 

@app.post("/api/encrypt", tags=["Encryption"])
def encrypt_text(req: EncryptTextRequest, db: Session = Depends(get_db)):
    key    = req.key or sc.generate_fernet_key()
    result = sc.encrypt_data(req.text.encode(), key)
    result["key"] = key
    _log(db,
         "Encrypt Text",
         f"text_length={len(req.text)} chars, key_provided={req.key is not None}",
         "success" if result["success"] else f"failed: {result.get('error')}")
    return result

#Encrypt file

@app.post("/api/encrypt-file", tags=["Encryption"])
async def encrypt_file(
    file: UploadFile = File(...),
    key: Optional[str] = Form(default=None),
    db: Session = Depends(get_db),
):
    data   = await file.read()
    key    = key or sc.generate_fernet_key()
    result = sc.encrypt_data(data, key)
    result["key"]      = key
    result["filename"] = file.filename
    _log(db,
         "Encrypt File",
         f"file={file.filename}, size={len(data)} bytes",
         "success" if result["success"] else f"failed: {result.get('error')}")
    return result

#Decrypt
@app.post("/api/decrypt", tags=["Encryption"])
def decrypt(req: DecryptRequest, db: Session = Depends(get_db)):
    result = sc.decrypt_data(req.token, req.key)
    _log(db,
         "Decrypt",
         f"token_length={len(req.token)} chars",
         "success" if result["success"] else f"failed: {result.get('error')}")
    return result

#Brute Force Simulation
@app.post("/api/brute-force", tags=["Simulation"])
def brute_force(req: BruteForceRequest, db: Session = Depends(get_db)):
    result = sc.brute_force_simulate(
        req.hash_str, req.hash_type, req.max_length, req.charset
    )
    status = (
        f"Cracked → '{result['plaintext']}' in {result.get('attempts_made', 0)} attempts"
        if result.get("cracked")
        else f"Not found in {result.get('attempts_made', 0)} attempts. ETA: {result.get('estimated_full_crack_time')}"
    )
    _log(db,
         "Brute Force Sim",
         f"type={req.hash_type}, max_len={req.max_length}, charset={req.charset}",
         status)
    return result

#Password Generator
@app.post("/api/generate-password", tags=["Password"])
def generate_password(req: GeneratePasswordRequest, db: Session = Depends(get_db)):
    result = sc.generate_password(
        req.length, req.require_upper, req.require_lower,
        req.require_digits, req.require_special,
        req.exclude_ambiguous, req.custom_special,
    )
    _log(db,
         "Generate Password",
         f"length={req.length}, upper={req.require_upper}, lower={req.require_lower}, "
         f"digits={req.require_digits}, special={req.require_special}, ambiguous_excluded={req.exclude_ambiguous}",
         f"strength={result.get('strength')}, score={result.get('score')}")
    return result


# Activity Logs
@app.get("/api/logs", response_model=list[LogEntry], tags=["Logs"])
def get_logs(limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(ActivityLog)
        .order_by(ActivityLog.created_at.desc())
        .limit(limit)
        .all()
    )

@app.delete("/api/logs", tags=["Logs"])
def clear_logs(db: Session = Depends(get_db)):
    deleted = db.query(ActivityLog).delete()
    db.commit()
    return {"deleted": deleted}


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
