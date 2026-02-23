"""MITRE ATT&CK collector.

Downloads the MITRE ATT&CK Enterprise JSON (STIX 2.1 format) from GitHub
and provides lookup utilities used by the risk ranker and briefing generator.

The full STIX bundle is ~20 MB and changes slowly, so we cache it locally.
"""
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import requests

import config

log = logging.getLogger(__name__)

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CACHE_FILE = "mitre_attack_cache.json"
CACHE_TTL_HOURS = 24


# ── Cache management ───────────────────────────────────────────────────────────

def _cache_valid() -> bool:
    if not os.path.exists(CACHE_FILE):
        return False
    mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_FILE), tz=timezone.utc)
    return (datetime.now(timezone.utc) - mtime) < timedelta(hours=CACHE_TTL_HOURS)


def _load_stix() -> dict:
    if _cache_valid():
        with open(CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    try:
        resp = requests.get(
            ATTACK_URL,
            headers={"User-Agent": "CyberSecLog/1.0"},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
        log.info("MITRE ATT&CK: downloaded and cached enterprise bundle")
        return data
    except Exception as exc:
        log.error("MITRE ATT&CK download failed: %s", exc)
        return {}


# ── Index builders ─────────────────────────────────────────────────────────────

class AttackIndex:
    """In-memory index of MITRE ATT&CK techniques and groups."""

    def __init__(self) -> None:
        self._techniques: dict[str, dict] = {}    # technique_id → object
        self._groups: dict[str, dict] = {}         # group_id → object
        self._software: dict[str, dict] = {}       # software_id → object
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        stix = _load_stix()
        if not stix:
            return
        for obj in stix.get("objects", []):
            obj_type = obj.get("type", "")
            ext = obj.get("external_references", [])
            att_id = next(
                (r.get("external_id", "") for r in ext if r.get("source_name") == "mitre-attack"),
                "",
            )
            if obj_type == "attack-pattern" and att_id.startswith("T"):
                self._techniques[att_id] = obj
            elif obj_type == "intrusion-set":
                self._groups[att_id] = obj
            elif obj_type in ("malware", "tool"):
                self._software[att_id] = obj
        self._loaded = True
        log.info(
            "MITRE ATT&CK index: %d techniques, %d groups, %d software",
            len(self._techniques), len(self._groups), len(self._software),
        )

    def lookup_technique(self, technique_id: str) -> dict | None:
        self._ensure_loaded()
        return self._techniques.get(technique_id.upper())

    def lookup_group(self, group_id: str) -> dict | None:
        self._ensure_loaded()
        return self._groups.get(group_id.upper())

    def search_techniques(self, text: str) -> list[dict]:
        """Find techniques whose name or description mentions `text`."""
        self._ensure_loaded()
        text_lower = text.lower()
        return [
            t for t in self._techniques.values()
            if text_lower in t.get("name", "").lower()
            or text_lower in t.get("description", "").lower()
        ]

    def get_recent_groups(self) -> list[dict]:
        """Return all known threat groups for use in briefing context."""
        self._ensure_loaded()
        return list(self._groups.values())

    def technique_summary(self, technique_id: str) -> str:
        """Return a concise one-liner for a technique."""
        t = self.lookup_technique(technique_id)
        if not t:
            return technique_id
        name = t.get("name", technique_id)
        desc = t.get("description", "")[:200]
        return f"{technique_id}: {name} – {desc}"

    def map_tags_to_techniques(self, tags: list[str]) -> list[str]:
        """Given a list of tags/keywords, find matching ATT&CK technique IDs."""
        self._ensure_loaded()
        matched: set[str] = set()
        for tag in tags:
            for tid, tobj in self._techniques.items():
                if tag.lower() in tobj.get("name", "").lower():
                    matched.add(tid)
        return sorted(matched)

    def top_techniques_for_briefing(self, limit: int = 10) -> list[dict]:
        """Return a curated set of high-visibility techniques for briefing context."""
        self._ensure_loaded()
        # Priority techniques commonly abused in recent campaigns
        priority_ids = [
            "T1566",  # Phishing
            "T1190",  # Exploit Public-Facing Application
            "T1133",  # External Remote Services
            "T1486",  # Data Encrypted for Impact (ransomware)
            "T1489",  # Service Stop
            "T1071",  # Application Layer Protocol (C2)
            "T1059",  # Command and Scripting Interpreter
            "T1078",  # Valid Accounts
            "T1082",  # System Information Discovery
            "T1105",  # Ingress Tool Transfer
        ]
        result = []
        for tid in priority_ids[:limit]:
            t = self._techniques.get(tid)
            if t:
                result.append({"id": tid, "name": t.get("name", ""), "description": t.get("description", "")[:300]})
        return result


# Global singleton index
ATTACK_INDEX = AttackIndex()


def collect() -> list[dict]:
    """Return MITRE ATT&CK context items for the briefing.

    These are not time-windowed intelligence items but reference data
    provided to Claude for enrichment context.
    """
    ATTACK_INDEX._ensure_loaded()
    techniques = ATTACK_INDEX.top_techniques_for_briefing(limit=15)
    items = []
    for t in techniques:
        items.append({
            "id": f"MITRE-{t['id']}",
            "source": "MITRE-ATT&CK",
            "category": "mitre",
            "title": f"{t['id']}: {t['name']}",
            "description": t["description"],
            "url": f"https://attack.mitre.org/techniques/{t['id']}/",
            "published": "",
            "severity": "",
            "cvss_score": None,
            "tags": ["mitre", "attack", t["id"]],
            "raw_data": t,
        })
    return items
