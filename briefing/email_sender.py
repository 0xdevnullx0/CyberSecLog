"""Email delivery module.

Sends the daily HTML briefing via SMTP (TLS/STARTTLS).
Falls back to printing to stdout if email is not configured.

Supports Gmail App Passwords, Office 365, and any SMTP relay.
"""
import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import config

log = logging.getLogger(__name__)


def _build_plaintext_fallback(html: str) -> str:
    """Very basic HTML → plain-text strip for MIME multipart alternative."""
    import re
    text = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def send_briefing(html_content: str, items_count: int = 0) -> bool:
    """Send the briefing email.

    Returns True on success, False on failure.
    If email is not configured, writes the HTML to a local file instead.
    """
    if not _is_configured():
        log.warning("Email not configured – saving briefing to file instead.")
        _save_to_file(html_content)
        return False

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    subject = f"{config.EMAIL_SUBJECT_PREFIX} {today} — {_threat_level_from_html(html_content)}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = config.EMAIL_FROM
    msg["To"] = ", ".join(config.EMAIL_TO)
    msg["X-Mailer"] = "CyberSecLog/1.0"

    plain = _build_plaintext_fallback(html_content)
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    try:
        with smtplib.SMTP(config.EMAIL_SMTP_HOST, config.EMAIL_SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(config.EMAIL_FROM, config.EMAIL_PASSWORD)
            server.sendmail(config.EMAIL_FROM, config.EMAIL_TO, msg.as_string())
        log.info("Briefing email sent to: %s", ", ".join(config.EMAIL_TO))
        return True
    except smtplib.SMTPAuthenticationError:
        log.error("SMTP authentication failed – check EMAIL_FROM / EMAIL_PASSWORD")
    except smtplib.SMTPException as exc:
        log.error("SMTP error: %s", exc)
    except OSError as exc:
        log.error("Network error sending email: %s", exc)

    # Fallback: save to file so the briefing is not lost
    _save_to_file(html_content)
    return False


def _is_configured() -> bool:
    return bool(
        config.EMAIL_FROM
        and config.EMAIL_PASSWORD
        and config.EMAIL_TO
        and config.EMAIL_SMTP_HOST
    )


def _save_to_file(html_content: str) -> None:
    """Save briefing HTML to a timestamped file in the current directory."""
    filename = "briefing_{}.html".format(
        datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    )
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    log.info("Briefing saved to file: %s", filename)
    print(f"\nBriefing saved to: {filename}")


def _threat_level_from_html(html: str) -> str:
    """Extract the threat level badge text from the generated HTML."""
    import re
    for level in ("CRITICAL", "HIGH", "ELEVATED", "MODERATE"):
        if f"badge-{level.lower()}" in html.lower():
            return f"Threat Level: {level}"
    return "Threat Level: UNKNOWN"
