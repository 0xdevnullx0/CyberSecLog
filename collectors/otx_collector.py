"""AlienVault OTX (Open Threat Exchange) collector.

Collects recent threat intelligence pulses covering:
- Active threat actors / APT groups
- Indicators of Compromise (IoCs)
- Malware campaigns
- Industry-targeted attacks

API docs: https://otx.alienvault.com/api
Free API key: https://otx.alienvault.com/accounts/signup
"""
import logging
from datetime import datetime, timedelta, timezone

import requests

import config

log = logging.getLogger(__name__)

OTX_BASE = "https://otx.alienvault.com/api/v1"


def _otx_headers() -> dict:
    return {
        "X-OTX-API-KEY": config.OTX_API_KEY,
        "User-Agent": "CyberSecLog/1.0",
    }


def _collect_subscribed_pulses(days_back: int) -> list[dict]:
    """Fetch pulses from the subscribed feed (requires OTX API key)."""
    modified_since = (
        datetime.now(timezone.utc) - timedelta(days=days_back)
    ).strftime("%Y-%m-%dT%H:%M:%S")

    items: list[dict] = []
    url = f"{OTX_BASE}/pulses/subscribed"
    params = {"modified_since": modified_since, "limit": 50}

    while url:
        try:
            resp = requests.get(
                url, params=params, headers=_otx_headers(), timeout=20
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.warning("OTX subscribed pulses failed: %s", exc)
            break

        for pulse in data.get("results", []):
            items.append(_parse_pulse(pulse))

        url = data.get("next")  # pagination
        params = {}  # next URL includes all params

    return items


def _collect_search_pulses(days_back: int) -> list[dict]:
    """Search for security-relevant pulses (works without API key too)."""
    queries = [
        "financial sector attack",
        "banking trojan",
        "ransomware",
        "zero day",
        "supply chain",
        "APT",
        "critical infrastructure",
    ]
    modified_since = (
        datetime.now(timezone.utc) - timedelta(days=days_back)
    ).strftime("%Y-%m-%dT%H:%M:%S")

    items: list[dict] = []
    seen_ids: set[str] = set()

    for query in queries:
        try:
            resp = requests.get(
                f"{OTX_BASE}/search/pulses",
                params={
                    "q": query,
                    "sort": "modified",
                    "limit": 10,
                    "modified_since": modified_since,
                },
                headers=_otx_headers(),
                timeout=20,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except Exception as exc:
            log.warning("OTX search failed for '%s': %s", query, exc)
            continue

        for pulse in results:
            pulse_id = pulse.get("id", "")
            if pulse_id and pulse_id not in seen_ids:
                seen_ids.add(pulse_id)
                items.append(_parse_pulse(pulse))

    return items


def _parse_pulse(pulse: dict) -> dict:
    pulse_id = pulse.get("id", "")
    name = pulse.get("name", "Unknown Pulse")
    description = pulse.get("description", "")[:1500]
    created = pulse.get("created", "")
    modified = pulse.get("modified", "")
    author = pulse.get("author_name", "")
    tlp = pulse.get("tlp", "white")

    # Tags and industries
    tags: list[str] = pulse.get("tags", [])
    industries: list[str] = pulse.get("industries", [])
    malware_families: list[str] = pulse.get("malware_families", [])
    attack_ids: list[str] = [a.get("id", "") for a in pulse.get("attack_ids", [])]
    references: list[str] = pulse.get("references", [])

    combined_tags = tags + industries + malware_families + attack_ids
    combined_tags = [t for t in combined_tags if t][:20]

    # Count IoCs
    indicators = pulse.get("indicators", [])
    ioc_summary = f"{len(indicators)} IoCs" if indicators else "no IoCs"

    description_full = (
        f"{description}\n\nAuthor: {author} | TLP: {tlp.upper()} | {ioc_summary}"
    )
    if references:
        description_full += f"\nReferences: {'; '.join(references[:3])}"

    # Determine category: threat_actor vs advisory
    category = "threat_actor" if any(
        kw in name.lower() for kw in ["apt", "lazarus", "fin", "ta", "group", "actor"]
    ) else "advisory"

    return {
        "id": f"OTX-{pulse_id}",
        "source": "AlienVault-OTX",
        "category": category,
        "title": name,
        "description": description_full,
        "url": f"https://otx.alienvault.com/pulse/{pulse_id}",
        "published": created or modified,
        "severity": "",
        "cvss_score": None,
        "tags": combined_tags,
        "raw_data": {
            "pulse_id": pulse_id,
            "author": author,
            "tlp": tlp,
            "ioc_count": len(indicators),
            "attack_ids": attack_ids,
            "industries": industries,
            "malware_families": malware_families,
        },
    }


def collect(days_back: int | None = None) -> list[dict]:
    """Collect OTX pulses.  Falls back to search if no API key configured."""
    days_back = days_back or config.OTX_DAYS_BACK
    items: list[dict] = []

    if config.OTX_API_KEY:
        items.extend(_collect_subscribed_pulses(days_back))
        log.info("OTX subscribed: %d pulses", len(items))
    else:
        log.info("OTX: no API key configured – using public search only")

    # Always run search (supplements subscription with targeted queries)
    search_items = _collect_search_pulses(days_back)
    # Deduplicate by ID
    existing_ids = {i["id"] for i in items}
    for item in search_items:
        if item["id"] not in existing_ids:
            items.append(item)
            existing_ids.add(item["id"])

    log.info("OTX: total %d pulses collected", len(items))
    return items
