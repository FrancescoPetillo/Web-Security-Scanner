from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner.engine import run_scan

app = FastAPI()

# 🔥 CORS APERTO (DEBUG)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 🔥 temporaneo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🔹 MODEL REQUEST
class ScanRequest(BaseModel):
    url: str


def validate_url(url: str) -> str:
    if not url or not url.strip():
        raise HTTPException(status_code=400, detail="URL vuoto")

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(status_code=400, detail="Protocollo non valido")

    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Host non valido")

    return url


@app.get("/")
def root():
    return {"message": "API working"}


@app.post("/scan")
def start_scan(req: ScanRequest):
    safe_url = validate_url(req.url)

    result = run_scan(safe_url)

    return {
        "url": safe_url,
        **result
    }