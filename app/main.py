from fastapi import FastAPI
import os

app = FastAPI(title="secure-supply-chain-app")

APP_VERSION = "1.1.0"
BUILD_COMMIT = os.getenv("BUILD_COMMIT", "unknown")
BUILD_DATE = os.getenv("BUILD_DATE", "unknown")


@app.get("/health")
def health():
    return {"status": "healthy1"}


@app.get("/info")
def info():
    return {
        "version": APP_VERSION,
        "build_commit": BUILD_COMMIT,
        "build_date": BUILD_DATE,
    }
