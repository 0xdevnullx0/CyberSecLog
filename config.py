"""Central configuration — loaded once at import time from environment / .env."""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Claude / Anthropic ─────────────────────────────────────────────────────────
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")

# ── AlienVault OTX ─────────────────────────────────────────────────────────────
OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")

# ── Email ──────────────────────────────────────────────────────────────────────
EMAIL_SMTP_HOST: str = os.getenv("EMAIL_SMTP_HOST", "smtp-relay.brevo.com")
EMAIL_SMTP_PORT: int = int(os.getenv("EMAIL_SMTP_PORT", "587"))
EMAIL_FROM: str = os.getenv("EMAIL_FROM", "no-reply@cyberseclog.app")
# LOGIN user for SMTP auth — defaults to EMAIL_FROM if not set separately
# (Brevo requires the account login email, which differs from the FROM address)
EMAIL_SMTP_USER: str = os.getenv("EMAIL_SMTP_USER", "") or os.getenv("EMAIL_FROM", "")
EMAIL_PASSWORD: str = os.getenv("EMAIL_PASSWORD", "")
EMAIL_TO: list[str] = [
    addr.strip()
    for addr in os.getenv("EMAIL_TO", "").split(",")
    if addr.strip()
]
EMAIL_SUBJECT_PREFIX: str = os.getenv(
    "EMAIL_SUBJECT_PREFIX", "[CyberThreat Briefing]"
)

# ── Schedule ───────────────────────────────────────────────────────────────────
BRIEFING_HOUR: int = int(os.getenv("BRIEFING_HOUR", "7"))
BRIEFING_MINUTE: int = int(os.getenv("BRIEFING_MINUTE", "0"))
BRIEFING_TIMEZONE: str = os.getenv("BRIEFING_TIMEZONE", "UTC")

# ── Collection windows ─────────────────────────────────────────────────────────
NVD_DAYS_BACK: int = int(os.getenv("NVD_DAYS_BACK", "1"))
NEWS_DAYS_BACK: int = int(os.getenv("NEWS_DAYS_BACK", "1"))
OTX_DAYS_BACK: int = int(os.getenv("OTX_DAYS_BACK", "1"))
MIN_CVSS_SCORE: float = float(os.getenv("MIN_CVSS_SCORE", "7.0"))

# ── Storage ────────────────────────────────────────────────────────────────────
DB_PATH: str = os.getenv("DB_PATH", "cyberthreat.db")

# ── Optional: Telegram ─────────────────────────────────────────────────────────
TELEGRAM_API_ID: str = os.getenv("TELEGRAM_API_ID", "")
TELEGRAM_API_HASH: str = os.getenv("TELEGRAM_API_HASH", "")
TELEGRAM_CHANNELS: list[str] = [
    ch.strip()
    for ch in os.getenv("TELEGRAM_CHANNELS", "").split(",")
    if ch.strip()
]

# ── Optional: GitHub ───────────────────────────────────────────────────────────
GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")

# ── Risk ranking constants ─────────────────────────────────────────────────────
FINANCIAL_SECTOR_KEYWORDS: list[str] = [
    "bank", "banking", "financial", "fintech", "payment", "swift", "sepa",
    "trading", "forex", "cryptocurrency", "crypto exchange", "exchange",
    "insurance", "investment", "broker", "wealth management", "federal reserve",
    "central bank", "regulatory", "sec ", " fca", " mas", "credit card",
    "atm", "wire transfer", "money laundering", "aml", "kyc",
]

SUPPLY_CHAIN_KEYWORDS: list[str] = [
    "supply chain", "dependency", "npm", "pypi", "maven", "nuget", "rubygems",
    "open source", "third party", "vendor", "upstream", "package", "library",
    "software bill of materials", "sbom", "typosquat", "malicious package",
]

RCE_KEYWORDS: list[str] = [
    "remote code execution", "rce", "arbitrary code", "code execution",
    "unauthenticated rce", "pre-auth rce",
]

ZERO_DAY_KEYWORDS: list[str] = [
    "zero-day", "zero day", "0day", "0-day", "unpatched", "no patch",
    "actively exploited", "in the wild", "itw",
]

CRITICAL_VENDOR_KEYWORDS: list[str] = [
    "microsoft", "oracle", "openssl", "cisco", "vmware", "fortinet",
    "palo alto", "juniper", "sap", "adobe", "google chrome", "firefox",
    "apache", "nginx", "linux kernel", "windows", "exchange", "sharepoint",
    "confluence", "jira", "gitlab", "github actions",
]

# RSS feeds to monitor
RSS_FEEDS: dict[str, str] = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "TheHackersNews": "https://feeds.feedburner.com/TheHackersNews",
    "DarkReading": "https://www.darkreading.com/rss.xml",
    "SecurityWeek": "https://feeds.feedburner.com/securityweek",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
    "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Rapid7 Blog": "https://blog.rapid7.com/rss/",
    "Recorded Future": "https://www.recordedfuture.com/feed",
}
