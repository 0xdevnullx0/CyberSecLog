"""Claude-powered daily executive briefing generator.

Uses claude-opus-4-6 with adaptive thinking and streaming to produce
a structured threat intelligence briefing from all collected, ranked items.

Output is full HTML suitable for email delivery.
"""
import json
import logging
from datetime import datetime, timezone

import anthropic

import config

log = logging.getLogger(__name__)

_CLIENT: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
    return _CLIENT


# ── Prompt construction ────────────────────────────────────────────────────────

def _format_item_for_prompt(item: dict) -> str:
    lines = [
        f"  ID: {item.get('id', 'N/A')}",
        f"  Title: {item.get('title', 'N/A')}",
        f"  Source: {item.get('source', 'N/A')}",
        f"  Risk Score: {item.get('risk_score', 0):.1f}/100",
        f"  Risk Factors: {', '.join(item.get('risk_factors', []))}",
    ]
    if item.get("cvss_score") is not None:
        lines.append(f"  CVSS: {item['cvss_score']}")
    if item.get("severity"):
        lines.append(f"  Severity: {item['severity']}")
    if item.get("epss_score") is not None:
        lines.append(f"  EPSS Exploit Probability: {item['epss_score']:.1%}")
    desc = item.get("description", "")[:600]
    if desc:
        lines.append(f"  Description: {desc}")
    url = item.get("url", "")
    if url:
        lines.append(f"  Reference: {url}")
    return "\n".join(lines)


def _build_system_prompt() -> str:
    today = datetime.now(timezone.utc).strftime("%A, %d %B %Y")
    return f"""You are a senior threat intelligence analyst producing the daily executive cyber threat briefing for {today}.

Your audience is the CISO, CTO, and executive leadership team of a financial services organisation.

Your briefing must:
1. Be written in clear, authoritative, executive-friendly prose – no jargon without explanation.
2. Prioritise threats most relevant to the FINANCIAL SECTOR: banks, payment systems, trading platforms, crypto exchanges, insurance firms.
3. Highlight CRITICAL risks first: zero-days, actively exploited CVEs (CISA KEV), CVSS 10 from major vendors, remote code execution, supply chain compromises.
4. Map threats to the MITRE ATT&CK framework and kill-chain stages where relevant.
5. Categorise by: Threat Actors, Vulnerabilities/CVEs, MITRE ATT&CK Activity, Financial Sector Threats, Supply Chain Risks, General Advisories.
6. Include a concise Executive Summary with a threat level (CRITICAL / HIGH / ELEVATED / MODERATE).
7. End with concrete, prioritised Recommended Actions.
8. Format the output as clean HTML (without <html>/<head>/<body> wrapper tags – just the inner content sections) ready for email embedding.

Use these HTML conventions:
- <h2> for section headings
- <h3> for subsections
- <div class="risk-critical"> / <div class="risk-high"> / <div class="risk-medium"> for severity-coloured blocks
- <table> for CVE lists
- <ul>/<li> for bullet lists
- <strong> for emphasis
- Include a risk-level badge at the top: <span class="badge-critical">CRITICAL</span> etc.

Be thorough but keep each section scannable. Executives read this briefing in under 10 minutes."""


def _build_user_prompt(categorized: dict, all_items: list[dict]) -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    top_items = sorted(all_items, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]

    sections: list[str] = [
        f"# Cyber Threat Intelligence Data — {today}",
        f"Total intelligence items collected: {len(all_items)}",
        "",
        "## TOP 5 HIGHEST-RISK ITEMS (Executive Priority)",
    ]

    for i, item in enumerate(top_items, 1):
        sections.append(f"\n### {i}. {item.get('title', 'Unknown')}")
        sections.append(_format_item_for_prompt(item))

    section_labels = {
        "critical_cves":       "CRITICAL VULNERABILITIES & CVEs",
        "threat_actors":       "ACTIVE THREAT ACTORS & CAMPAIGNS",
        "financial_threats":   "FINANCIAL SECTOR THREATS",
        "supply_chain":        "SUPPLY CHAIN RISKS",
        "mitre_activity":      "MITRE ATT&CK TECHNIQUES IN USE",
        "news_advisories":     "ADVISORIES & INDUSTRY NEWS",
    }

    for key, label in section_labels.items():
        items_in_section = categorized.get(key, [])
        if not items_in_section:
            continue
        sections.append(f"\n## {label} ({len(items_in_section)} items)")
        for item in items_in_section[:15]:  # Limit per section for prompt size
            sections.append(f"\n### {item.get('title', 'Unknown')}")
            sections.append(_format_item_for_prompt(item))

    sections.append("\n---")
    sections.append(
        "Based on ALL of the above intelligence, produce the complete executive briefing HTML."
    )
    sections.append(
        "Synthesise, cross-reference, and add your expert analysis. "
        "Do NOT simply re-list items – provide context, business impact, and actionable insight."
    )

    return "\n".join(sections)


# ── HTML wrapping ──────────────────────────────────────────────────────────────

_HTML_WRAPPER = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Daily Cyber Threat Briefing — {date}</title>
<style>
  body {{ font-family: Arial, Helvetica, sans-serif; max-width: 900px; margin: 0 auto;
         padding: 20px; color: #1a1a2e; background: #f4f4f9; }}
  .header {{ background: linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
             color:#fff; padding:30px; border-radius:8px; margin-bottom:24px; }}
  .header h1 {{ margin:0 0 8px 0; font-size:1.8em; }}
  .header .subtitle {{ opacity:.8; font-size:.95em; }}
  .badge-critical {{ background:#c0392b; color:#fff; padding:4px 12px; border-radius:12px;
                     font-weight:bold; font-size:.85em; letter-spacing:.5px; }}
  .badge-high     {{ background:#e67e22; color:#fff; padding:4px 12px; border-radius:12px;
                     font-weight:bold; font-size:.85em; }}
  .badge-elevated {{ background:#f39c12; color:#fff; padding:4px 12px; border-radius:12px;
                     font-weight:bold; font-size:.85em; }}
  .badge-moderate {{ background:#27ae60; color:#fff; padding:4px 12px; border-radius:12px;
                     font-weight:bold; font-size:.85em; }}
  h2 {{ color:#16213e; border-left:4px solid #e94560; padding-left:12px; margin-top:32px; }}
  h3 {{ color:#0f3460; margin-top:18px; }}
  .risk-critical {{ border-left:4px solid #c0392b; background:#fdf2f2; padding:12px 16px;
                    margin:8px 0; border-radius:4px; }}
  .risk-high     {{ border-left:4px solid #e67e22; background:#fef9f0; padding:12px 16px;
                    margin:8px 0; border-radius:4px; }}
  .risk-medium   {{ border-left:4px solid #f39c12; background:#fffdf0; padding:12px 16px;
                    margin:8px 0; border-radius:4px; }}
  table {{ width:100%; border-collapse:collapse; margin:12px 0; font-size:.9em; }}
  th {{ background:#16213e; color:#fff; padding:10px 12px; text-align:left; }}
  td {{ padding:8px 12px; border-bottom:1px solid #ddd; }}
  tr:nth-child(even) {{ background:#f9f9f9; }}
  .cvss-10  {{ color:#c0392b; font-weight:bold; }}
  .cvss-9   {{ color:#e67e22; font-weight:bold; }}
  .cvss-8   {{ color:#f39c12; font-weight:bold; }}
  ul {{ padding-left:20px; }}
  li {{ margin:6px 0; }}
  .action-item {{ background:#eaf4fb; border-left:4px solid #2980b9; padding:10px 14px;
                  margin:6px 0; border-radius:4px; }}
  .footer {{ text-align:center; font-size:.8em; color:#888; margin-top:40px;
             padding-top:20px; border-top:1px solid #ddd; }}
  a {{ color:#0f3460; }}
</style>
</head>
<body>
<div class="header">
  <h1>&#128737; Daily Cyber Threat Intelligence Briefing</h1>
  <div class="subtitle">Generated: {date} UTC &nbsp;|&nbsp; Items analysed: {items_count} &nbsp;|&nbsp; Powered by Claude AI</div>
</div>

{content}

<div class="footer">
  <p>This briefing is generated automatically from NVD, CISA KEV, AlienVault OTX, MITRE ATT&amp;CK,
  BleepingComputer, TheHackersNews, DarkReading, SecurityWeek, KrebsOnSecurity and HackerNews.</p>
  <p>For questions contact your Security Operations Centre.</p>
</div>
</body>
</html>
"""


# ── Main generation function ───────────────────────────────────────────────────

def generate_briefing(categorized: dict, all_items: list[dict]) -> str:
    """Generate the full HTML briefing using Claude claude-opus-4-6.

    Uses streaming to handle the large output without timeout issues.
    Returns the complete HTML string.
    """
    client = _get_client()
    system_prompt = _build_system_prompt()
    user_prompt = _build_user_prompt(categorized, all_items)

    log.info("Generating briefing with Claude (input ~%d chars)…", len(user_prompt))

    # Streaming with adaptive thinking
    inner_html_parts: list[str] = []

    with client.messages.stream(
        model="claude-opus-4-6",
        max_tokens=8000,
        thinking={"type": "adaptive"},
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    ) as stream:
        for event in stream:
            if event.type == "content_block_delta":
                delta = event.delta
                if hasattr(delta, "type") and delta.type == "text_delta":
                    inner_html_parts.append(delta.text)

        # Ensure we have the final message (also flushes the stream)
        final_msg = stream.get_final_message()
        log.info(
            "Claude usage — input: %d tokens, output: %d tokens",
            final_msg.usage.input_tokens,
            final_msg.usage.output_tokens,
        )

    inner_html = "".join(inner_html_parts).strip()

    # Wrap with full HTML template
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    full_html = _HTML_WRAPPER.format(
        date=today_str,
        items_count=len(all_items),
        content=inner_html,
    )

    return full_html
