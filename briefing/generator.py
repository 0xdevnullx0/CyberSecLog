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


# ── Template-based fallback briefing ─────────────────────────────────────────

def _risk_div_class(score: float) -> str:
    if score >= 80:
        return "risk-critical"
    if score >= 50:
        return "risk-high"
    return "risk-medium"


def _threat_badge(score: float) -> tuple[str, str]:
    """Return (level_text, badge_class) based on top risk score."""
    if score >= 80:
        return "CRITICAL", "badge-critical"
    if score >= 60:
        return "HIGH", "badge-high"
    if score >= 40:
        return "ELEVATED", "badge-elevated"
    return "MODERATE", "badge-moderate"


def _render_item_card(item: dict) -> str:
    title = item.get("title", "Unknown")
    source = item.get("source", "")
    score = item.get("risk_score", 0)
    factors = ", ".join(item.get("risk_factors", [])) or "—"
    desc = (item.get("description") or "")[:400]
    url = item.get("url", "")
    cvss = item.get("cvss_score")
    epss = item.get("epss_score")
    div_cls = _risk_div_class(score)

    cvss_str = ""
    if cvss is not None:
        cls = "cvss-10" if cvss >= 10 else ("cvss-9" if cvss >= 9 else "cvss-8" if cvss >= 8 else "")
        cvss_str = f' &nbsp;<span class="{cls}">CVSS {cvss}</span>' if cls else f" &nbsp;CVSS {cvss}"

    epss_str = f" &nbsp;EPSS {epss:.0%}" if epss is not None else ""

    ref_str = f'&nbsp;<a href="{url}" target="_blank">[ref]</a>' if url else ""

    return (
        f'<div class="{div_cls}">'
        f"<strong>{title}</strong>{cvss_str}{epss_str}{ref_str}<br>"
        f"<small>Source: {source} &nbsp;|&nbsp; Risk Score: <strong>{score:.1f}</strong>"
        f" &nbsp;|&nbsp; Factors: {factors}</small>"
        + (f"<p style='margin:6px 0 0;font-size:.9em;'>{desc}</p>" if desc else "")
        + "</div>"
    )


def _render_section(title: str, icon: str, items: list[dict], limit: int = 10) -> str:
    if not items:
        return ""
    cards = "\n".join(_render_item_card(i) for i in items[:limit])
    more = f"<p><em>…and {len(items) - limit} more items.</em></p>" if len(items) > limit else ""
    return f"<h2>{icon} {title}</h2>\n{cards}\n{more}\n"


def _generate_template_briefing(categorized: dict, all_items: list[dict]) -> str:
    """Build a complete professional HTML briefing without the Claude API."""
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    today_label = datetime.now(timezone.utc).strftime("%A, %d %B %Y")

    top_score = max((i.get("risk_score", 0) for i in all_items), default=0)
    threat_level, badge_class = _threat_badge(top_score)

    top5 = sorted(all_items, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]

    # ── Executive summary ────────────────────────────────────────────────────
    crit_count = sum(1 for i in all_items if i.get("risk_score", 0) >= 80)
    high_count = sum(1 for i in all_items if 60 <= i.get("risk_score", 0) < 80)
    kev_count = sum(1 for i in all_items if "CISA KEV" in i.get("risk_factors", []))
    zd_count = sum(1 for i in all_items if "zero-day" in i.get("risk_factors", []))
    rce_count = sum(1 for i in all_items if "RCE" in i.get("risk_factors", []))

    exec_summary = f"""
<h2>&#128203; Executive Summary</h2>
<p>Threat Level for <strong>{today_label}</strong>: <span class="{badge_class}">{threat_level}</span></p>
<p>CyberSecLog analysed <strong>{len(all_items)}</strong> threat intelligence items across all monitored
sources today. Key statistics:</p>
<ul>
  <li><strong>{crit_count}</strong> items rated <em>Critical</em> (risk score ≥ 80)</li>
  <li><strong>{high_count}</strong> items rated <em>High</em> (risk score 60–79)</li>
  <li><strong>{kev_count}</strong> items in the <em>CISA Known Exploited Vulnerabilities</em> catalog</li>
  <li><strong>{zd_count}</strong> potential zero-day or unpatched vulnerabilities identified</li>
  <li><strong>{rce_count}</strong> Remote Code Execution (RCE) vulnerabilities flagged</li>
</ul>
<p>Financial-sector teams should review Critical and High items immediately. Prioritise patching
of any CISA KEV entries within 24–48 hours per CISA Binding Operational Directive 22-01.</p>
"""

    # ── Top 5 priority items ─────────────────────────────────────────────────
    top5_html = "<h2>&#128680; Top Priority Items</h2>\n"
    for rank, item in enumerate(top5, 1):
        top5_html += f"<h3>#{rank} — {item.get('title', 'Unknown')}</h3>\n"
        top5_html += _render_item_card(item) + "\n"

    # ── Category sections ────────────────────────────────────────────────────
    section_cfg = [
        ("critical_cves",     "Critical Vulnerabilities & CVEs",          "&#128165;", 12),
        ("threat_actors",     "Active Threat Actors & Campaigns",          "&#128373;", 10),
        ("financial_threats", "Financial Sector Threats",                  "&#127981;", 10),
        ("supply_chain",      "Supply Chain Risks",                        "&#9937;",   8),
        ("mitre_activity",    "MITRE ATT&amp;CK Techniques",               "&#127919;", 10),
        ("news_advisories",   "Advisories &amp; Industry News",            "&#128240;", 12),
    ]

    sections_html = ""
    for key, label, icon, limit in section_cfg:
        sections_html += _render_section(label, icon, categorized.get(key, []), limit)

    # ── Recommended actions ──────────────────────────────────────────────────
    actions = []
    if kev_count:
        actions.append(f"Patch <strong>{kev_count} CISA KEV</strong> vulnerability/ies immediately (BOD 22-01 deadline applies).")
    if zd_count:
        actions.append(f"Assess exposure to <strong>{zd_count} zero-day</strong> vulnerability/ies; apply vendor mitigations or workarounds.")
    if rce_count:
        actions.append(f"Prioritise remediation of <strong>{rce_count} RCE</strong> vulnerability/ies — these enable full system compromise.")
    fin_items = categorized.get("financial_threats", [])
    if fin_items:
        actions.append("Review financial-sector threat indicators with your fraud and payment security teams.")
    sc_items = categorized.get("supply_chain", [])
    if sc_items:
        actions.append("Audit third-party dependencies and software supply chain for listed compromised packages.")
    actions.append("Ensure endpoint detection rules are updated to cover newly observed MITRE ATT&amp;CK techniques.")
    actions.append("Review and rotate credentials for any systems affected by listed vulnerabilities.")
    actions.append("Share critical IoCs with your SIEM/SOAR and threat intelligence platform.")

    actions_html = "<h2>&#9989; Recommended Actions</h2>\n"
    for action in actions:
        actions_html += f'<div class="action-item">&#8226; {action}</div>\n'

    inner_html = exec_summary + top5_html + sections_html + actions_html

    return _HTML_WRAPPER.format(
        date=today_str,
        items_count=len(all_items),
        content=inner_html,
    )


# ── Main generation function ───────────────────────────────────────────────────

def generate_briefing(categorized: dict, all_items: list[dict]) -> str:
    """Generate the full HTML briefing.

    Uses Claude claude-opus-4-6 with adaptive thinking when ANTHROPIC_API_KEY is set.
    Falls back to a Jinja2-style template briefing when no API key is available.
    Returns the complete HTML string.
    """
    if not config.ANTHROPIC_API_KEY:
        log.info("ANTHROPIC_API_KEY not set — using built-in template briefing (no Claude call).")
        return _generate_template_briefing(categorized, all_items)

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
