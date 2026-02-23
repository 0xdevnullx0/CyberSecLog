"""Risk ranking engine.

Assigns a composite risk score (0–100) to each intelligence item based on:

  Base score (from CVSS / severity)
  × financial sector relevance multiplier
  × exploit maturity multiplier  (KEV, RCE, zero-day, EPSS)
  × supply chain multiplier
  × critical vendor multiplier

Items are then sorted descending by risk score and categorised for the briefing.
"""
import logging
import re
from typing import Any

import config

log = logging.getLogger(__name__)

# ── Scoring weights ────────────────────────────────────────────────────────────

CVSS_BASE_WEIGHT = 10.0          # CVSS 10 → 100 base points (before multipliers)

MULTIPLIERS = {
    "cisa_kev":        2.5,  # actively exploited per CISA
    "zero_day":        2.0,  # no patch available
    "rce":             1.8,  # remote code execution
    "supply_chain":    1.7,  # supply-chain compromise
    "financial":       1.6,  # financial sector relevance
    "critical_vendor": 1.4,  # from a high-impact vendor
    "ransomware":      1.4,  # ransomware family involved
    "epss_high":       1.3,  # EPSS exploit probability >= 0.5
    "epss_medium":     1.15, # EPSS >= 0.1
    "threat_actor":    1.2,  # associated with known APT/TA
}

# Severity → base score when CVSS is not available
SEVERITY_BASE: dict[str, float] = {
    "CRITICAL": 90.0,
    "HIGH":     70.0,
    "MEDIUM":   45.0,
    "LOW":      20.0,
    "UNKNOWN":  30.0,
    "":         30.0,
}


# ── Text-matching helpers ──────────────────────────────────────────────────────

def _contains(text: str, keywords: list[str]) -> bool:
    t = text.lower()
    return any(kw.lower() in t for kw in keywords)


def _combined_text(item: dict) -> str:
    return " ".join(filter(None, [
        item.get("title", ""),
        item.get("description", ""),
        " ".join(item.get("tags", [])),
    ])).lower()


# ── Risk scoring ───────────────────────────────────────────────────────────────

def score_item(item: dict, kev_catalog: dict | None = None) -> dict:
    """Compute and attach `risk_score` and `risk_factors` to *item*.

    Returns the modified item (also mutates in place).
    """
    text = _combined_text(item)
    tags = [t.lower() for t in item.get("tags", [])]
    source = item.get("source", "").lower()

    # ── Base score ─────────────────────────────────────────────────────────────
    cvss = item.get("cvss_score")
    if cvss is not None:
        base = float(cvss) * CVSS_BASE_WEIGHT
    else:
        base = SEVERITY_BASE.get(item.get("severity", "").upper(), 30.0)

    # News items have a lower base than CVEs
    if item.get("category") == "news":
        base = min(base, 50.0)

    # ── Identify risk factors ──────────────────────────────────────────────────
    factors: list[str] = []
    multiplier = 1.0

    def apply(key: str, condition: bool) -> None:
        if condition:
            nonlocal multiplier
            multiplier *= MULTIPLIERS[key]
            factors.append(key)

    # CISA KEV
    is_kev = (
        source == "cisa-kev"
        or "cisa-kev" in tags
        or "actively-exploited" in tags
        or (
            kev_catalog
            and item.get("raw_data", {}).get("cve_id") in kev_catalog
        )
    )
    apply("cisa_kev", is_kev)

    # Zero-day
    apply("zero_day", _contains(text, config.ZERO_DAY_KEYWORDS))

    # RCE
    apply("rce", _contains(text, config.RCE_KEYWORDS))

    # Supply chain
    apply("supply_chain", _contains(text, config.SUPPLY_CHAIN_KEYWORDS))

    # Financial sector
    apply("financial", _contains(text, config.FINANCIAL_SECTOR_KEYWORDS))

    # Critical vendor
    apply("critical_vendor", _contains(text, config.CRITICAL_VENDOR_KEYWORDS))

    # Ransomware
    apply("ransomware", "ransomware" in text or "ransomware" in tags)

    # EPSS
    epss = item.get("epss_score")
    if epss is not None:
        apply("epss_high", epss >= 0.5)
        if "epss_high" not in factors:
            apply("epss_medium", epss >= 0.1)

    # Threat actor involvement
    apply("threat_actor", item.get("category") == "threat_actor")

    risk_score = min(round(base * multiplier, 1), 100.0)

    item["risk_score"] = risk_score
    item["risk_factors"] = factors
    return item


def rank_items(items: list[dict], kev_catalog: dict | None = None) -> list[dict]:
    """Score and sort all items by risk (highest first)."""
    for item in items:
        score_item(item, kev_catalog)
    return sorted(items, key=lambda x: x.get("risk_score", 0), reverse=True)


# ── Categorisation ─────────────────────────────────────────────────────────────

def categorize(items: list[dict]) -> dict[str, list[dict]]:
    """Group ranked items into briefing sections."""
    cats: dict[str, list[dict]] = {
        "critical_cves":       [],
        "threat_actors":       [],
        "financial_threats":   [],
        "supply_chain":        [],
        "mitre_activity":      [],
        "news_advisories":     [],
    }

    for item in items:
        category = item.get("category", "")
        factors = item.get("risk_factors", [])
        score = item.get("risk_score", 0)

        if category == "mitre":
            cats["mitre_activity"].append(item)
            continue

        if category == "threat_actor":
            cats["threat_actors"].append(item)
            if "financial" in factors:
                cats["financial_threats"].append(item)
            continue

        if category == "cve":
            if score >= 40:
                cats["critical_cves"].append(item)
            if "financial" in factors:
                cats["financial_threats"].append(item)
            if "supply_chain" in factors:
                cats["supply_chain"].append(item)
            continue

        # news / advisory
        if "financial" in factors:
            cats["financial_threats"].append(item)
        elif "supply_chain" in factors:
            cats["supply_chain"].append(item)
        else:
            cats["news_advisories"].append(item)

    # Trim each section to keep the briefing focused
    limits = {
        "critical_cves":    20,
        "threat_actors":    10,
        "financial_threats": 15,
        "supply_chain":     10,
        "mitre_activity":   10,
        "news_advisories":  15,
    }
    for key, limit in limits.items():
        cats[key] = cats[key][:limit]

    return cats


def get_top_items(items: list[dict], n: int = 5) -> list[dict]:
    """Return the top-N highest-risk items across all categories."""
    return sorted(items, key=lambda x: x.get("risk_score", 0), reverse=True)[:n]
