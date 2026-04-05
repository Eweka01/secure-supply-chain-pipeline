import json
import os
import boto3
from fastapi import FastAPI, Query, HTTPException
from typing import Optional

app = FastAPI(title="SBOM Vulnerability Correlation Engine")

S3_BUCKET = os.getenv("SBOM_BUCKET", "supply-chain-sboms-120430500058")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

s3 = boto3.client("s3", region_name=AWS_REGION)


def list_sboms() -> list[dict]:
    """Return all SBOMs stored in S3 as {image, digest, sbom} dicts."""
    sboms = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix="sboms/"):
        for obj in page.get("Contents", []):
            # Key format: sboms/<image>/<digest>/sbom.cyclonedx.json
            parts = obj["Key"].split("/")
            if len(parts) == 4 and parts[3] == "sbom.cyclonedx.json":
                body = s3.get_object(Bucket=S3_BUCKET, Key=obj["Key"])["Body"].read()
                sboms.append({
                    "image": parts[1],
                    "digest": f"sha256:{parts[2]}",
                    "sbom": json.loads(body),
                })
    return sboms


def search_package(sbom: dict, package: str) -> Optional[dict]:
    """Return component details if package name matches any component."""
    for component in sbom.get("components", []):
        if package.lower() in component.get("name", "").lower():
            return {
                "name": component.get("name"),
                "version": component.get("version"),
                "type": component.get("type"),
                "purl": component.get("purl"),
            }
    return None


def search_cve(sbom: dict, cve: str) -> list[dict]:
    """Return components that reference the given CVE in their vulnerabilities."""
    hits = []
    for vuln in sbom.get("vulnerabilities", []):
        if cve.lower() in vuln.get("id", "").lower():
            for affect in vuln.get("affects", []):
                hits.append({
                    "cve": vuln.get("id"),
                    "severity": vuln.get("ratings", [{}])[0].get("severity"),
                    "affects": affect.get("ref"),
                })
    return hits


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/query")
def query(
    package: Optional[str] = Query(None, description="Package name to search for"),
    cve: Optional[str] = Query(None, description="CVE ID to search for"),
):
    """
    Query all stored SBOMs for a package name or CVE ID.
    Returns which images contain the match and what version is installed.
    """
    if not package and not cve:
        raise HTTPException(status_code=400, detail="Provide ?package=<name> or ?cve=<CVE-ID>")

    results = []
    for entry in list_sboms():
        if package:
            match = search_package(entry["sbom"], package)
            if match:
                results.append({
                    "image": entry["image"],
                    "digest": entry["digest"],
                    "match": match,
                })
        elif cve:
            matches = search_cve(entry["sbom"], cve)
            if matches:
                results.append({
                    "image": entry["image"],
                    "digest": entry["digest"],
                    "matches": matches,
                })

    return {
        "query": {"package": package, "cve": cve},
        "total_images_scanned": len(list_sboms()),
        "affected_images": len(results),
        "results": results,
    }


@app.get("/sboms")
def list_all_sboms():
    """List all stored SBOMs with their image and digest."""
    sboms = list_sboms()
    return {
        "total": len(sboms),
        "sboms": [{"image": s["image"], "digest": s["digest"]} for s in sboms],
    }
