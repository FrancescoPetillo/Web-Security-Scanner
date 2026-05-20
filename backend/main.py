from fastapi import FastAPI
from scanner.engine import run_scan

app = FastAPI()

@app.get("/")
def root():
    return {"message": "API working"}

@app.post("/scan")
def start_scan(url: str):
    result = run_scan(url)

    return {
        "url": url,
        **result
    }
