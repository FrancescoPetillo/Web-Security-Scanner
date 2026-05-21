from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from scanner.engine import run_scan

app = FastAPI()

# 🔥 CORS (fondamentale per React)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🔹 Test endpoint
@app.get("/")
def root():
    return {"message": "API working"}

# 🔹 Scan endpoint
@app.post("/scan")
def start_scan(url: str):
    result = run_scan(url)

    return {
        "url": url,
        **result
    }
