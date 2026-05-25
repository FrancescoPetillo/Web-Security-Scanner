from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from scanner.engine import run_scan

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
def start_scan(url: str):
    safe_url = validate_url(url)

    result = run_scan(safe_url)

    return {
        "url": safe_url,
        **result
    }