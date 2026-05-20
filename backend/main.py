import requests
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"message": "API working"}
@app.post("/scan")
def start_scan(url: str):
    findings = []

    try:
        response = requests.get(url)
        headers = response.headers

        # Check CSP
        if "Content-Security-Policy" not in headers:
            findings.append({
                "title": "Missing CSP",
                "severity": "Medium"
            })

        # Check HSTS
        if "Strict-Transport-Security" not in headers:
            findings.append({
                "title": "Missing HSTS",
                "severity": "Medium"
            })

        # Server disclosure
        if "Server" in headers:
            findings.append({
                "title": f"Server exposed: {headers['Server']}",
                "severity": "Low"
            })

        return {
            "url": url,
            "status": "done",
            "findings": findings
        }

    except Exception as e:
        return {
            "url": url,
            "status": "error",
            "error": str(e)
        }
