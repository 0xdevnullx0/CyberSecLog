"""NIST NVD API v2 collector.

Fetches CVEs published/modified within the last NVD_DAYS_BACK days.
Filters by MIN_CVSS_SCORE and enriches each item with EPSS exploit probability.

Rate limits (no API key): 5 req / 30 s  → we sleep between pages.
Docs: https://nvd.nist.gov/developers/vulnerabilities
"""
import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone

import requests

import config

log = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE = "https://api.first.org/data/v1/epss"


def _nvd_headers() -> dict:
    """Include the API key if configured (raises rate limit from 5→50 req/30 s)."""
    h = {"User-Agent": "CyberSecLog/1.0 (security-briefing-tool)"}
    api_key = getattr(config, "NVD_API_KEY", "")
    if api_key:
        h["apiKey"] = api_key
    return h


def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a list of CVE IDs.  Returns {cve_id: score}."""
    if not cve_ids:
        return {}
    try:
        resp = requests.get(
            EPSS_BASE,
            params={"cve": ",".join(cve_ids), "fields": "cve,epss"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        return {entry["cve"]: float(entry["epss"]) for entry in data}
    except Exception as exc:
        log.warning("EPSS fetch failed: %s", exc)
        return {}


def _parse_cve(vuln: dict) -> dict:
    """Parse a single NVD vulnerability object into our canonical schema."""
    cve_data = vuln.get("cve", {})
    cve_id = cve_data.get("id", "UNKNOWN")

    # Description (prefer English)
    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    # CVSS score – prefer v3.1, fall back to v3.0, then v2
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    severity = "UNKNOWN"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            primary = next(
                (m for m in metric_list if m.get("type") == "Primary"),
                metric_list[0],
            )
            cvss_data = primary.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", primary.get("baseSeverity", "UNKNOWN"))
            break

    # Published date
    published = cve_data.get("published", "")

    # References
    refs = cve_data.get("references", [])
    urls = [r.get("url", "") for r in refs[:3]]

    # CWE tags
    weaknesses = cve_data.get("weaknesses", [])
    cwes: list[str] = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("lang") == "en":
                cwes.append(d["value"])

    # Affected CPEs (vendors/products)
    configs = cve_data.get("configurations", [])
    affected_products: list[str] = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    affected_products.append(f"{parts[3]} {parts[4]}")

    # Build canonical item
    tags = list(set(cwes + affected_products[:5]))
    return {
        "id": cve_id,
        "source": "NVD",
        "category": "cve",
        "title": cve_id,
        "description": description,
        "url": urls[0] if urls else f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "published": published,
        "severity": severity.upper(),
        "cvss_score": cvss_score,
        "epss_score": None,  # filled later
        "tags": tags,
        "raw_data": {
            "cve_id": cve_id,
            "affected_products": affected_products[:10],
            "references": urls,
            "cwes": cwes,
        },
    }


def collect(days_back: int | None = None) -> list[dict]:
    """Collect recent CVEs from NVD.  Returns a list of canonical items."""
    days_back = days_back or config.NVD_DAYS_BACK
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_back)

    # NVD uses ISO 8601 with milliseconds in UTC
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate": start.strftime(fmt),
        "pubEndDate": now.strftime(fmt),
        "resultsPerPage": 2000,
    }

    items: list[dict] = []
    start_index = 0
    total_results = None

    while True:
        params["startIndex"] = start_index
        try:
            resp = requests.get(
                NVD_BASE, params=params, headers=_nvd_headers(), timeout=30
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception as exc:
            log.error("NVD request failed (startIndex=%s): %s", start_index, exc)
            break

        if total_results is None:
            total_results = payload.get("totalResults", 0)
            log.info("NVD: %d CVEs in window (%s → %s)", total_results,
                     start.date(), now.date())

        for vuln in payload.get("vulnerabilities", []):
            item = _parse_cve(vuln)
            # Apply minimum CVSS filter
            if item["cvss_score"] is None or item["cvss_score"] >= config.MIN_CVSS_SCORE:
                items.append(item)

        start_index += len(payload.get("vulnerabilities", []))
        if start_index >= (total_results or 0):
            break

        # Respect NVD rate limit
        time.sleep(6)

    # Enrich with EPSS scores in batches of 100
    cve_ids = [i["id"] for i in items]
    epss_map: dict[str, float] = {}
    for batch_start in range(0, len(cve_ids), 100):
        epss_map.update(_fetch_epss(cve_ids[batch_start: batch_start + 100]))

    for item in items:
        item["epss_score"] = epss_map.get(item["id"])

    log.info("NVD: collected %d CVEs (CVSS >= %.1f)", len(items), config.MIN_CVSS_SCORE)
    return items
