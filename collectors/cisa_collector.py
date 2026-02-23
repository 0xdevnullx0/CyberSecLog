"""CISA Known Exploited Vulnerabilities (KEV) catalog collector.

Downloads the full JSON catalog and returns entries added within the last
NVD_DAYS_BACK days.  No authentication required.

Catalog URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
import logging
from datetime import datetime, timedelta, timezone

import requests

import config

log = logging.getLogger(__name__)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def collect(days_back: int | None = None) -> list[dict]:
    """Return recently-added CISA KEV entries as canonical intelligence items."""
    days_back = days_back or config.NVD_DAYS_BACK
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)

    try:
        resp = requests.get(
            KEV_URL,
            headers={"User-Agent": "CyberSecLog/1.0"},
            timeout=30,
        )
        resp.raise_for_status()
        catalog = resp.json()
    except Exception as exc:
        log.error("CISA KEV download failed: %s", exc)
        return []

    vulnerabilities = catalog.get("vulnerabilities", [])
    items: list[dict] = []

    for vuln in vulnerabilities:
        # dateAdded is YYYY-MM-DD
        date_added_str = vuln.get("dateAdded", "")
        try:
            date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue

        if date_added < cutoff:
            continue

        cve_id = vuln.get("cveID", "UNKNOWN")
        product = vuln.get("product", "")
        vendor = vuln.get("vendorProject", "")
        vuln_name = vuln.get("vulnerabilityName", "")
        description = vuln.get("shortDescription", "")
        due_date = vuln.get("dueDate", "")
        ransomware_use = vuln.get("knownRansomwareCampaignUse", "Unknown")

        title = f"{cve_id}: {vuln_name}" if vuln_name else cve_id

        tags = [vendor, product, "CISA-KEV", "actively-exploited"]
        if ransomware_use.lower() == "known":
            tags.append("ransomware")

        items.append({
            "id": f"CISA-KEV-{cve_id}",
            "source": "CISA-KEV",
            "category": "cve",
            "title": title,
            "description": (
                f"{description}\n\nCISA required remediation by: {due_date}. "
                f"Known ransomware use: {ransomware_use}."
            ),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published": date_added_str,
            "severity": "CRITICAL",  # All KEV entries are exploited in the wild
            "cvss_score": None,      # Will be enriched by risk ranker if available
            "tags": tags,
            "raw_data": vuln,
        })

    log.info("CISA KEV: %d new entries in last %d day(s)", len(items), days_back)
    return items


def get_full_catalog() -> list[dict]:
    """Return the complete KEV catalog (all-time), used for CVE enrichment."""
    try:
        resp = requests.get(
            KEV_URL,
            headers={"User-Agent": "CyberSecLog/1.0"},
            timeout=30,
        )
        resp.raise_for_status()
        return {
            v["cveID"]: v
            for v in resp.json().get("vulnerabilities", [])
        }
    except Exception as exc:
        log.warning("CISA KEV full catalog fetch failed: %s", exc)
        return {}
