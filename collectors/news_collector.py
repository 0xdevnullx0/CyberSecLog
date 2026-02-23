"""News and blog collector.

Sources:
  - RSS/Atom feeds: BleepingComputer, TheHackersNews, DarkReading, SecurityWeek,
                    KrebsOnSecurity, CISA Alerts, Rapid7, Recorded Future, etc.
  - HackerNews Algolia API (cybersecurity-tagged stories)
  - GitHub Security Advisories API (public, no auth needed but benefits from token)

All items are returned in the canonical schema.
Uses stdlib xml.etree.ElementTree to parse RSS/Atom — no feedparser dependency.
"""
import hashlib
import logging
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import requests

import config

log = logging.getLogger(__name__)

HACKERNEWS_API = "https://hn.algolia.com/api/v1/search"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"

# Atom namespace
_ATOM_NS = "http://www.w3.org/2005/Atom"


# ── RSS / Atom (stdlib parser) ─────────────────────────────────────────────────

def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text or "").strip()


def _parse_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    # Try RFC 2822 (used by RSS)
    try:
        return parsedate_to_datetime(date_str).astimezone(timezone.utc)
    except Exception:
        pass
    # Try ISO 8601 (used by Atom)
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str[:25], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass
    return None


def _parse_feed_xml(feed_name: str, xml_text: str, cutoff: datetime) -> list[dict]:
    """Parse RSS or Atom XML and return canonical items published after cutoff."""
    items: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        log.warning("XML parse error for %s: %s", feed_name, exc)
        return []

    # Detect RSS vs Atom
    tag = root.tag.lower()
    is_atom = "atom" in tag or tag.startswith(f"{{{_ATOM_NS}}}")

    if is_atom or root.tag == f"{{{_ATOM_NS}}}feed":
        entries = root.findall(f"{{{_ATOM_NS}}}entry") or root.findall("entry")
    else:
        # RSS — entries are under channel/item
        channel = root.find("channel") or root
        entries = channel.findall("item")

    def _text(el, *tags: str) -> str:
        for t in tags:
            child = el.find(t)
            if child is not None and child.text:
                return child.text.strip()
            # Try with atom namespace
            child = el.find(f"{{{_ATOM_NS}}}{t}")
            if child is not None and child.text:
                return child.text.strip()
        return ""

    for entry in entries:
        title = _text(entry, "title")
        # Link: RSS uses <link>, Atom uses <link href="...">
        url = _text(entry, "link")
        if not url:
            link_el = entry.find(f"{{{_ATOM_NS}}}link")
            if link_el is None:
                link_el = entry.find("link")
            if link_el is not None:
                url = link_el.get("href", "") or (link_el.text or "").strip()

        pub_str = _text(entry, "pubDate", "published", "updated", "dc:date")
        pub_date = _parse_date(pub_str)

        if pub_date and pub_date < cutoff:
            continue

        summary = _text(entry, "description", "summary", "content")
        summary = _strip_html(summary)[:1500]

        if not title or not url:
            continue

        item_id = hashlib.md5(f"{feed_name}::{url}".encode()).hexdigest()
        items.append({
            "id": item_id,
            "source": feed_name,
            "category": "news",
            "title": title,
            "description": summary,
            "url": url,
            "published": pub_date.isoformat() if pub_date else "",
            "severity": "",
            "cvss_score": None,
            "tags": [feed_name],
            "raw_data": {"feed": feed_name, "url": url},
        })
    return items


def _make_item_id(source: str, url: str) -> str:
    return hashlib.md5(f"{source}::{url}".encode()).hexdigest()


def collect_rss(days_back: int | None = None) -> list[dict]:
    """Collect articles from all configured RSS feeds."""
    days_back = days_back or config.NEWS_DAYS_BACK
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)

    items: list[dict] = []
    headers = {"User-Agent": "CyberSecLog/1.0 (security-briefing-tool)"}

    for feed_name, feed_url in config.RSS_FEEDS.items():
        try:
            resp = requests.get(feed_url, headers=headers, timeout=15)
            resp.raise_for_status()
            feed_items = _parse_feed_xml(feed_name, resp.text, cutoff)
            items.extend(feed_items)
        except Exception as exc:
            log.warning("RSS fetch/parse failed for %s: %s", feed_name, exc)

    log.info("RSS: collected %d articles from %d feeds", len(items), len(config.RSS_FEEDS))
    return items


# ── HackerNews ─────────────────────────────────────────────────────────────────

_HN_QUERIES = [
    "cybersecurity vulnerability",
    "zero day exploit",
    "ransomware attack",
    "data breach",
    "APT threat actor",
    "CISA advisory",
    "supply chain attack",
    "critical vulnerability patch",
]


def collect_hackernews(days_back: int | None = None) -> list[dict]:
    """Collect security-relevant HN stories via Algolia search API."""
    days_back = days_back or config.NEWS_DAYS_BACK
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=days_back)).timestamp())

    items: list[dict] = []
    seen_ids: set[str] = set()

    for query in _HN_QUERIES:
        try:
            resp = requests.get(
                HACKERNEWS_API,
                params={
                    "query": query,
                    "tags": "story",
                    "numericFilters": f"created_at_i>{cutoff}",
                    "hitsPerPage": 20,
                },
                timeout=15,
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", [])
        except Exception as exc:
            log.warning("HackerNews API failed for query '%s': %s", query, exc)
            continue

        for hit in hits:
            hn_id = str(hit.get("objectID", ""))
            if not hn_id or hn_id in seen_ids:
                continue
            seen_ids.add(hn_id)

            title = hit.get("title", "")
            url = hit.get("url") or f"https://news.ycombinator.com/item?id={hn_id}"
            points = hit.get("points", 0)
            comments = hit.get("num_comments", 0)
            created = hit.get("created_at", "")

            items.append({
                "id": f"HN-{hn_id}",
                "source": "HackerNews",
                "category": "news",
                "title": title,
                "description": (
                    f"HackerNews story with {points} points and {comments} comments. "
                    f"Query match: {query}."
                ),
                "url": url,
                "published": created,
                "severity": "",
                "cvss_score": None,
                "tags": ["hackernews", query.split()[0]],
                "raw_data": {"hn_id": hn_id, "points": points, "query": query},
            })

        time.sleep(0.5)

    log.info("HackerNews: collected %d stories", len(items))
    return items


# ── GitHub Security Advisories ─────────────────────────────────────────────────

def collect_github_advisories(days_back: int | None = None) -> list[dict]:
    """Collect recent GitHub Security Advisories (public, curated CVEs)."""
    days_back = days_back or config.NVD_DAYS_BACK
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()

    headers = {"User-Agent": "CyberSecLog/1.0", "Accept": "application/vnd.github+json"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"

    items: list[dict] = []
    page = 1

    while True:
        try:
            resp = requests.get(
                GITHUB_ADVISORY_API,
                params={
                    "per_page": 100,
                    "page": page,
                    "published": f">{cutoff}",
                    "type": "reviewed",
                },
                headers=headers,
                timeout=20,
            )
            if resp.status_code == 403:
                log.warning("GitHub advisory rate limit hit")
                break
            resp.raise_for_status()
            advisories = resp.json()
        except Exception as exc:
            log.warning("GitHub advisory fetch failed: %s", exc)
            break

        if not advisories:
            break

        for advisory in advisories:
            ghsa_id = advisory.get("ghsa_id", "")
            cve_id = advisory.get("cve_id", "")
            item_id = cve_id or ghsa_id
            if not item_id:
                continue

            severity = advisory.get("severity", "").upper()
            cvss_score = None
            cvss_info = advisory.get("cvss", {})
            if cvss_info:
                cvss_score = cvss_info.get("score")

            ecosystem = advisory.get("vulnerabilities", [{}])[0].get("package", {}).get("ecosystem", "")
            pkg_name = advisory.get("vulnerabilities", [{}])[0].get("package", {}).get("name", "")

            items.append({
                "id": f"GHSA-{item_id}",
                "source": "GitHub-GHSA",
                "category": "cve",
                "title": advisory.get("summary", item_id),
                "description": advisory.get("description", "")[:1500],
                "url": advisory.get("html_url", ""),
                "published": advisory.get("published_at", ""),
                "severity": severity,
                "cvss_score": cvss_score,
                "tags": [ecosystem, pkg_name, "ghsa"] if ecosystem else ["ghsa"],
                "raw_data": {
                    "ghsa_id": ghsa_id,
                    "cve_id": cve_id,
                    "ecosystem": ecosystem,
                    "package": pkg_name,
                },
            })

        page += 1
        if len(advisories) < 100:
            break
        time.sleep(1)

    log.info("GitHub GHSA: collected %d advisories", len(items))
    return items


def collect(days_back: int | None = None) -> list[dict]:
    """Collect from all news sources."""
    all_items: list[dict] = []
    all_items.extend(collect_rss(days_back))
    all_items.extend(collect_hackernews(days_back))
    all_items.extend(collect_github_advisories(days_back))
    return all_items
