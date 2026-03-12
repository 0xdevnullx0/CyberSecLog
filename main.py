#!/usr/bin/env python3
"""CyberSecLog — Daily Cyber Threat Intelligence Briefing

Entry point supporting two modes:
  1. Daemon mode: runs the daily briefing on the configured schedule.
  2. One-shot CLI mode: run immediately for testing / ad-hoc briefings.

Usage:
  python main.py              # Start scheduler (daemon)
  python main.py --now        # Generate and send briefing immediately
  python main.py --dry-run    # Collect only; print summary without email
  python main.py --status     # Show last briefing info from DB
"""
import argparse
import logging
import sys
from datetime import datetime, timezone

# ── Logging setup (do this before any imports that log at module level) ────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("cyberseclog.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("main")

# ── Application imports ────────────────────────────────────────────────────────
import config
from storage import database as db
from collectors import (
    nvd_collector,
    cisa_collector,
    news_collector,
    otx_collector,
    mitre_collector,
)
from analyzers import risk_ranker
from briefing import generator, email_sender


# ── Core pipeline ──────────────────────────────────────────────────────────────

def run_collection() -> list[dict]:
    """Collect intelligence from all sources.  Returns deduplicated list."""
    log.info("=== Intelligence Collection Started ===")
    all_raw: list[dict] = []

    # NVD CVEs
    try:
        nvd_items = nvd_collector.collect()
        all_raw.extend(nvd_items)
        log.info("NVD: +%d items", len(nvd_items))
    except Exception as exc:
        log.error("NVD collection failed: %s", exc)

    # CISA KEV
    try:
        cisa_items = cisa_collector.collect()
        all_raw.extend(cisa_items)
        log.info("CISA KEV: +%d items", len(cisa_items))
    except Exception as exc:
        log.error("CISA KEV collection failed: %s", exc)

    # News / RSS / HackerNews / GitHub GHSA
    try:
        news_items = news_collector.collect()
        all_raw.extend(news_items)
        log.info("News/RSS/HN: +%d items", len(news_items))
    except Exception as exc:
        log.error("News collection failed: %s", exc)

    # AlienVault OTX
    try:
        otx_items = otx_collector.collect()
        all_raw.extend(otx_items)
        log.info("OTX: +%d items", len(otx_items))
    except Exception as exc:
        log.error("OTX collection failed: %s", exc)

    # MITRE ATT&CK reference (always included for context)
    try:
        mitre_items = mitre_collector.collect()
        all_raw.extend(mitre_items)
        log.info("MITRE ATT&CK: +%d context items", len(mitre_items))
    except Exception as exc:
        log.error("MITRE collection failed: %s", exc)

    log.info("=== Collection complete: %d raw items ===", len(all_raw))

    # Deduplicate by item ID
    seen: set[str] = set()
    unique_items: list[dict] = []
    for item in all_raw:
        item_id = item.get("id", "")
        if item_id and item_id not in seen:
            seen.add(item_id)
            unique_items.append(item)
    log.info("After deduplication: %d unique items", len(unique_items))
    return unique_items


def run_risk_ranking(items: list[dict]) -> tuple[list[dict], dict]:
    """Score, rank, and categorise all items."""
    log.info("=== Risk Ranking ===")

    # Fetch full CISA KEV catalog for CVE enrichment
    kev_catalog = {}
    try:
        kev_catalog = cisa_collector.get_full_catalog()
        log.info("KEV catalog loaded: %d entries", len(kev_catalog))
    except Exception as exc:
        log.warning("Could not load full KEV catalog: %s", exc)

    ranked = risk_ranker.rank_items(items, kev_catalog=kev_catalog)
    categorized = risk_ranker.categorize(ranked)

    # Log top 5
    top = risk_ranker.get_top_items(ranked, n=5)
    log.info("Top 5 risks:")
    for i, item in enumerate(top, 1):
        log.info(
            "  %d. [%.1f] %s (%s)",
            i, item.get("risk_score", 0), item.get("title", "")[:80], item.get("source", ""),
        )
    return ranked, categorized


def run_briefing(ranked: list[dict], categorized: dict, dry_run: bool = False) -> str:
    """Generate the briefing and optionally send it."""
    log.info("=== Generating Briefing ===")

    if dry_run:
        log.info("[DRY RUN] Skipping Claude API call and email.")
        _print_dry_run_summary(ranked, categorized)
        return ""

    html = generator.generate_briefing(categorized, ranked)
    log.info("Briefing generated: %d chars", len(html))

    # Persist to DB
    briefing_id = db.save_briefing(html, items_count=len(ranked))
    log.info("Briefing saved to DB (id=%d)", briefing_id)

    # Persist items
    for item in ranked:
        try:
            db.upsert_item(item)
        except Exception as exc:
            log.warning("DB upsert failed for %s: %s", item.get("id"), exc)

    return html


def run_pipeline(dry_run: bool = False) -> None:
    """Full pipeline: collect → rank → brief → email."""
    db.init_db()

    items = run_collection()
    if not items:
        log.warning("No items collected – aborting briefing.")
        return

    ranked, categorized = run_risk_ranking(items)
    html = run_briefing(ranked, categorized, dry_run=dry_run)

    if not dry_run and html:
        log.info("=== Sending Email ===")
        sent = email_sender.send_briefing(html, items_count=len(ranked))
        if sent:
            log.info("Email delivered successfully.")
        else:
            log.warning("Email delivery failed – check logs above.")

    log.info("=== Pipeline Complete ===")


# ── Dry-run summary ────────────────────────────────────────────────────────────

def _print_dry_run_summary(ranked: list[dict], categorized: dict) -> None:
    print("\n" + "=" * 70)
    print("DRY RUN SUMMARY")
    print("=" * 70)
    print(f"Total items collected & ranked: {len(ranked)}")
    print()

    section_labels = {
        "critical_cves":       "Critical CVEs",
        "threat_actors":       "Threat Actors",
        "financial_threats":   "Financial Sector Threats",
        "supply_chain":        "Supply Chain Risks",
        "mitre_activity":      "MITRE ATT&CK Context",
        "news_advisories":     "News & Advisories",
    }
    for key, label in section_labels.items():
        items = categorized.get(key, [])
        print(f"{label}: {len(items)} items")

    print("\nTop 10 Risks:")
    print("-" * 70)
    for i, item in enumerate(ranked[:10], 1):
        factors = ", ".join(item.get("risk_factors", []))
        print(
            f"  {i:2}. [{item.get('risk_score', 0):5.1f}] {item.get('title', '')[:65]}"
        )
        print(f"       Source: {item.get('source', ''):<20} Factors: {factors}")
    print("=" * 70 + "\n")


# ── Status command ─────────────────────────────────────────────────────────────

def show_status() -> None:
    db.init_db()
    briefing = db.get_latest_briefing()
    items = db.get_recent_items(hours=48)

    print("\n── CyberSecLog Status ─────────────────────────────────────────")
    if briefing:
        print(f"Last briefing:  {briefing['date_label']} (DB id={briefing['id']})")
        print(f"  Created:      {briefing['created_at']}")
        print(f"  Items count:  {briefing['items_count']}")
        print(f"  HTML size:    {len(briefing['content']):,} bytes")
    else:
        print("Last briefing: None yet")

    print(f"\nItems in DB (last 48 h): {len(items)}")
    if items:
        print(f"  Highest risk: {items[0].get('title', '')[:70]}")
        print(f"    Score={items[0].get('risk_score', 0):.1f}, Source={items[0].get('source', '')}")
    print("─" * 65 + "\n")


# ── Test email ────────────────────────────────────────────────────────────────

def send_test_email() -> None:
    """Send a minimal test message to verify SMTP relay credentials."""
    from briefing.email_sender import _is_configured
    import smtplib
    from email.mime.text import MIMEText
    import config as cfg

    if not _is_configured():
        print("\nEmail not fully configured. Set these values in .env:\n")
        print("── Option A: Brevo free relay (recommended) ──────────────────────────────")
        print("  Allows no-reply@cyberseclog.app as FROM, 300 emails/day, no credit card")
        print("  1. Sign up free at https://app.brevo.com")
        print("  2. SMTP & API → Generate SMTP Key")
        print("  3. Add to .env:")
        print("       EMAIL_SMTP_HOST=smtp-relay.brevo.com")
        print("       EMAIL_SMTP_PORT=587")
        print("       EMAIL_FROM=no-reply@cyberseclog.app")
        print("       EMAIL_SMTP_USER=your-brevo-login@email.com")
        print("       EMAIL_PASSWORD=<brevo-smtp-key>")
        print()
        print("── Option B: Gmail App Password ──────────────────────────────────────────")
        print("  1. Enable 2FA at myaccount.google.com/security")
        print("  2. App Passwords → Mail → generate 16-char code")
        print("  3. Add to .env:")
        print("       EMAIL_SMTP_HOST=smtp.gmail.com")
        print("       EMAIL_SMTP_PORT=587")
        print("       EMAIL_FROM=youraddress@gmail.com")
        print("       EMAIL_PASSWORD=<16-char-app-password>")
        print()
        print("  EMAIL_TO=Sharath.rt@gmail.com  ← already set")
        return

    smtp_user = cfg.EMAIL_SMTP_USER or cfg.EMAIL_FROM
    subject = "[CyberSecLog] Test email — SMTP configuration verified"
    body = (
        f"This is a test message from CyberSecLog.\n\n"
        f"SMTP relay: {cfg.EMAIL_SMTP_HOST}:{cfg.EMAIL_SMTP_PORT}\n"
        f"From: {cfg.EMAIL_FROM}\n"
        f"Auth user: {smtp_user}\n\n"
        "Your SMTP configuration is working. Daily threat briefings will be\n"
        "delivered to this address from no-reply@cyberseclog.app.\n\n"
        "-- CyberSecLog"
    )
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = cfg.EMAIL_FROM
    msg["To"] = ", ".join(cfg.EMAIL_TO)

    try:
        with smtplib.SMTP(cfg.EMAIL_SMTP_HOST, cfg.EMAIL_SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_user, cfg.EMAIL_PASSWORD)
            server.sendmail(cfg.EMAIL_FROM, cfg.EMAIL_TO, msg.as_string())
        print(f"\nTest email sent successfully to: {', '.join(cfg.EMAIL_TO)}")
        log.info("Test email delivered to %s", ", ".join(cfg.EMAIL_TO))
    except smtplib.SMTPAuthenticationError:
        print("\nAuthentication failed.")
        print(f"  SMTP host:  {cfg.EMAIL_SMTP_HOST}")
        print(f"  Auth user:  {smtp_user}")
        print("  For Brevo: ensure EMAIL_SMTP_USER is your Brevo account login email")
        print("             and EMAIL_PASSWORD is the SMTP key (not your account password).")
        log.error("SMTP auth failed during test email")
    except Exception as exc:
        print(f"\nFailed to send test email: {exc}")
        log.error("Test email failed: %s", exc)


# ── Scheduler ─────────────────────────────────────────────────────────────────

def start_scheduler() -> None:
    try:
        from apscheduler.schedulers.blocking import BlockingScheduler
    except ImportError:
        log.error("apscheduler not installed.  Run: pip install apscheduler")
        sys.exit(1)

    scheduler = BlockingScheduler(timezone=config.BRIEFING_TIMEZONE)
    scheduler.add_job(
        run_pipeline,
        trigger="cron",
        hour=config.BRIEFING_HOUR,
        minute=config.BRIEFING_MINUTE,
        id="daily_briefing",
        name="Daily Cyber Threat Briefing",
        misfire_grace_time=3600,  # Allow up to 1 h late start
    )

    next_run = scheduler.get_jobs()[0].next_run_time
    log.info("Scheduler started.")
    log.info(
        "Daily briefing scheduled at %02d:%02d %s",
        config.BRIEFING_HOUR, config.BRIEFING_MINUTE, config.BRIEFING_TIMEZONE,
    )
    log.info("Next run: %s", next_run)
    log.info("Press Ctrl+C to stop.")

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopped.")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberSecLog – Daily Cyber Threat Intelligence Briefing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py               # Start daily scheduler (daemon mode)
  python main.py --now         # Run pipeline immediately
  python main.py --dry-run     # Collect & rank without generating/emailing
  python main.py --status      # Show DB status
  python main.py --test-email  # Verify Gmail SMTP credentials
        """,
    )
    parser.add_argument(
        "--now", action="store_true",
        help="Run the full pipeline immediately instead of waiting for schedule."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Collect and rank intelligence; print summary without Claude call or email."
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Show the status of the last briefing and recent DB items."
    )
    parser.add_argument(
        "--test-email", action="store_true",
        help="Send a short test email to verify Gmail SMTP configuration."
    )
    args = parser.parse_args()

    print("CyberSecLog — Cyber Threat Intelligence Briefing System")
    print(f"  Schedule: {config.BRIEFING_HOUR:02d}:{config.BRIEFING_MINUTE:02d} {config.BRIEFING_TIMEZONE}")
    print(f"  DB:       {config.DB_PATH}")
    print(f"  Email to: {', '.join(config.EMAIL_TO) or '(not configured)'}")
    print()

    if args.status:
        show_status()
        return

    if args.test_email:
        send_test_email()
        return

    if args.dry_run:
        run_pipeline(dry_run=True)
        return

    if args.now:
        run_pipeline(dry_run=False)
        return

    # Default: daemon scheduler
    start_scheduler()


if __name__ == "__main__":
    main()
