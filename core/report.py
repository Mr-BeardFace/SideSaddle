"""Report agent — reads DB state, calls LLM to write the narrative, renders HTML."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.store import EngagementStore
    from core.engagement_state import EngagementState

# ── System prompt ─────────────────────────────────────────────────────────────

_REPORT_SYSTEM = """You are a senior penetration test report writer. You have been given the complete findings, \
operational facts, activity log, and context from a live red team engagement run through SideSaddle. \
Your job is to produce a professional, client-ready deliverable.

You work through tool calls:
1. Enrich every finding — call `annotate_finding` for each finding_id to set its polished `description`, \
`impact`, `cvss` vector + scores, and `remediation` bullets. One call per finding.
2. Submit the narrative — call `write_report` once with the `executive_summary` and `technical_overview`.

Do not speculate about findings not supported by the evidence. Do not invent tool output.

## Voice

- Never first person ("I", "we", "my"). Never second person ("you should"). Never "the team".
- In findings, stay impersonal and passive. In the technical_overview, the acting subject is the operator or "the tool".
- No weasel words — never "appears to", "might be", "could potentially". If confirmed, state it plainly.
- Descriptions and impact are paragraph prose; remediation is condensed bullets.

## annotate_finding — one call per finding_id

- description — broad class summary (first paragraph) then specifics of THIS engagement (subsequent paragraphs). \
Reference evidence; do not rewrite raw evidence into prose.
- impact — what a successful attack achieves. Paragraph form.
- cvss — a complete CVSS 3.1 vector (reason through AV/AC/PR/UI/S, C/I/A, E/RL/RC) plus three scores. \
Skip for pure recon / info severity findings.
- remediation — condensed bullets, multiple options where possible.

## write_report — call once after all findings are enriched

executive_summary — for a decision-maker, three labelled parts (## Overview, ## Key Findings, ## Conclusion):
- Overview: one paragraph — what was tested and the objective, in business terms.
- Key Findings: 2-3 paragraphs — exposed surfaces, foothold, what it chained into, the worst findings. Impact first.
- Conclusion: one paragraph — what this means and whether the objective was met.

technical_overview — REQUIRED — the full attack path start to finish as a chronological cause-and-effect story:
- Open with ## Summary, then sections by phase (## Recon, ## Foothold, ## Lateral Movement, etc.).
- Every move is "X was done because Y, which yielded Z".
- Show exact commands in fenced code blocks where they prove the step.
- Include failures that shaped the path.
- Cover from initial recon through the deepest access reached.
- This section is never omitted — even a short engagement must have one.

Finish once you have enriched every finding and called write_report. Final message is one line only.
"""

# ── Tool schemas ──────────────────────────────────────────────────────────────

_ANNOTATE_FINDING_TOOL = {
    "name": "annotate_finding",
    "description": "Enrich one finding with polished description, impact, CVSS scores, and remediation.",
    "input_schema": {
        "type": "object",
        "properties": {
            "finding_id": {"type": "string", "description": "The finding's id field"},
            "description": {"type": "string"},
            "impact":      {"type": "string"},
            "remediation": {"type": "array", "items": {"type": "string"}},
            "cvss": {
                "type": "object",
                "properties": {
                    "vector":              {"type": "string"},
                    "base_score":          {"type": "number"},
                    "temporal_score":      {"type": "number"},
                    "environmental_score": {"type": "number"},
                },
                "required": ["vector", "base_score"],
            },
        },
        "required": ["finding_id"],
    },
}

_WRITE_REPORT_TOOL = {
    "name": "write_report",
    "description": (
        "Submit the report narrative — executive summary and technical overview. "
        "Call this once, after annotate_finding has been called for every finding."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "executive_summary":  {"type": "string"},
            "technical_overview": {"type": "string"},
        },
        "required": ["executive_summary", "technical_overview"],
    },
}

# ── Jinja2 filter: narrative_blocks ──────────────────────────────────────────

def _narrative_blocks(text: str) -> list[dict]:
    """Split narrative into [{kind, content, lang}] — code | heading | text."""
    if not text or not isinstance(text, str):
        return []
    blocks: list[dict] = []
    parts = text.split("```")
    last = len(parts) - 1
    for i, part in enumerate(parts):
        if i % 2 == 1 and i != last:
            first, _, rest = part.partition("\n")
            lang = first.strip() if first.strip() and " " not in first.strip() else ""
            code = (rest if lang or first.strip() == "" else part).strip("\n")
            blocks.append({"kind": "code", "lang": lang, "content": code})
        else:
            for para in re.split(r"\n\s*\n", part):
                p = para.strip()
                if not p:
                    continue
                if p.startswith("## ") and "\n" not in p:
                    blocks.append({"kind": "heading", "lang": "", "content": p[3:].strip()})
                else:
                    blocks.append({"kind": "text", "lang": "", "content": p})
    return blocks


# ── HTML renderer ─────────────────────────────────────────────────────────────

def _render_html(
    op_name: str,
    op_start: str,
    op_end: str | None,
    findings: list,
    persistence: list,
    activities: list,
    op_picture: str,
    executive_summary: str,
    technical_overview: str,
    ioc_name: str | None = None,
) -> str:
    from jinja2 import Environment, FileSystemLoader
    from urllib.parse import quote as _urlquote

    tmpl_dir = Path(__file__).parent.parent / "reporting" / "templates"
    env = Environment(loader=FileSystemLoader(str(tmpl_dir)), autoescape=True)
    env.filters["narrative_blocks"] = _narrative_blocks
    env.filters["nist_cvss_url"] = lambda v: f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector={_urlquote(v)}"

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = getattr(f, "severity", f.get("severity", "info") if isinstance(f, dict) else "info")
        if sev in sev_counts:
            sev_counts[sev] += 1

    tmpl = env.get_template("report.html.j2")
    return tmpl.render(
        op_name=op_name,
        op_start=op_start,
        op_end=op_end,
        findings=findings,
        persistence=persistence,
        activities=activities,
        op_picture=op_picture,
        executive_summary=executive_summary,
        technical_overview=technical_overview,
        ioc_name=ioc_name,
        severity_counts=sev_counts,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )


# ── State context builder ─────────────────────────────────────────────────────

def _build_context(store: "EngagementStore", state: "EngagementState") -> str:
    """Build a text summary of all DB state for the LLM."""
    lines = [
        f"Op: {state.op_name}  |  Frontier: {state.frontier}",
        f"Op picture: {state.op_picture or 'Not established'}",
        "",
    ]

    lines.append(f"Beacons ({len(state.beacons)}):")
    for b in state.beacons:
        lines.append(f"  {b.id}  host={b.host}  ip={b.ip}  user={b.user}  os={b.os}")

    lines.append(f"\nHosts ({len(state.hosts)}):")
    for h in state.hosts:
        lines.append(f"  {h.ip}  hostname={h.hostname}  os={h.os}  ports={','.join(h.open_ports[:12])}")

    lines.append(f"\nFindings ({len(state.findings)}):")
    for f in state.findings:
        lines.append(f"  [{f.id}] [{f.severity.upper()}] {f.title}  target={f.target}  technique={f.technique}")
        if f.description:
            lines.append(f"    description: {f.description[:300]}")
        if f.evidence:
            lines.append(f"    evidence: {f.evidence[:300]}")

    lines.append(f"\nCredentials found ({len(state.credentials)}):")
    for c in state.credentials:
        masked = (c.secret[:2] + "***") if c.secret else "(none)"
        lines.append(f"  username={c.username}  type={c.type}  format={c.format}  location={c.location or c.source_host}  secret={masked}")

    lines.append(f"\nPersistence ({len(state.persistence)}):")
    for p in state.persistence:
        lines.append(f"  [{p.kind}] {p.host}: {p.detail}  cleanup: {p.cleanup or '(none)' }")

    lines.append(f"\nOperational facts ({len(state.facts)}):")
    for f in state.facts:
        lines.append(f"  {f.statement}  [{f.scope or 'global'}]")

    op_activities = [a for a in state.activities if a.ioc_type == "op"]
    lines.append(f"\nOp-tagged activities ({len(op_activities)}):")
    for a in op_activities[:60]:
        lines.append(
            f"  [{a.activity_id}] {a.timestamp}  ctx={a.execution_context}  "
            f"host={a.execution_host}  user={a.user_context}"
        )
        lines.append(f"    cmd: {a.command_action[:200]}")
        if a.result:
            lines.append(f"    result: {a.result[:150]}")
        if a.observable_artifacts:
            lines.append(f"    artifacts: {a.observable_artifacts[:200]}")

    # Last few analyst cycles for advisory context
    try:
        cycles = store.get_last_cycles(3)
        if cycles:
            lines.append("\nRecent analyst advisories:")
            for c in cycles:
                if c.get("advisory"):
                    lines.append(f"  {c.get('ts', '')}:  {c['advisory'][:400]}")
    except Exception:
        pass

    return "\n".join(lines)


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_report(
    store: "EngagementStore",
    state: "EngagementState",
    op_dir: Path,
) -> Path:
    """Run the LLM report agent, render HTML, return the report path."""
    from core import llm_client, config
    from core.engagement_state import Finding

    context = _build_context(store, state)
    findings_by_id = {f.id: f for f in state.findings}

    # Mutable enrichment overlay — the LLM fills these via annotate_finding calls
    enrichments: dict[str, dict] = {}

    messages = [
        {
            "role": "user",
            "content": (
                f"Engagement state:\n{context}\n\n"
                "Write the penetration test report. "
                "Call annotate_finding for every finding, then call write_report once."
            ),
        }
    ]

    executive_summary = ""
    technical_overview = ""
    client = llm_client.LLMClient()

    # Agentic loop — handle annotate_finding calls until write_report is called
    max_turns = 40
    for _ in range(max_turns):
        response = client.run(
            model=llm_client._model(),
            system=_REPORT_SYSTEM,
            messages=messages,
            tools=[_ANNOTATE_FINDING_TOOL, _WRITE_REPORT_TOOL],
            max_tokens=8192,
        )

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue

            if block.name == "annotate_finding":
                fid = block.input.get("finding_id", "")
                enrichments[fid] = {
                    "description": block.input.get("description", ""),
                    "impact":      block.input.get("impact", ""),
                    "remediation": block.input.get("remediation", []),
                    "cvss":        block.input.get("cvss"),
                }
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": f"Finding {fid} enriched.",
                })

            elif block.name == "write_report":
                executive_summary  = block.input.get("executive_summary", "")
                technical_overview = block.input.get("technical_overview", "")
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": "Report written.",
                })

        if response.stop_reason != "tool_use":
            break

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

        if executive_summary and technical_overview:
            break

    def _cvss_severity(score: float) -> str:
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score > 0:    return "low"
        return "info"

    _SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    # Merge enrichments onto findings (build plain objects for the template)
    enriched_findings = []
    for f in state.findings:
        e = enrichments.get(f.id, {})
        cvss_obj = None
        if e.get("cvss"):
            cvss_obj = type("CVSS", (), e["cvss"])()
        sev = _cvss_severity(cvss_obj.base_score) if (cvss_obj and cvss_obj.base_score) else f.severity
        enriched_findings.append(type("F", (), {
            "id":          f.id,
            "severity":    sev,
            "title":       f.title,
            "description": e.get("description") or f.description,
            "impact":      e.get("impact", ""),
            "target":      f.target,
            "evidence":    f.evidence,
            "technique":   f.technique,
            "verified":    f.verified,
            "timestamp":   f.timestamp,
            "remediation": e.get("remediation", []),
            "cvss":        cvss_obj,
        })())

    # Sort highest CVSS first; fall back to severity order for findings without CVSS
    enriched_findings.sort(
        key=lambda f: (-(f.cvss.base_score if (f.cvss and f.cvss.base_score) else 0),
                       -_SEV_ORDER.get(f.severity, 0))
    )

    op_start = state.created.strftime("%Y-%m-%d %H:%M UTC")
    op_end   = store.get_op_ended()

    ioc_files = sorted(op_dir.glob("ioc_*.xlsx"))
    ioc_name  = ioc_files[-1].name if ioc_files else None

    html = _render_html(
        op_name=state.op_name,
        op_start=op_start,
        op_end=op_end,
        findings=enriched_findings,
        persistence=state.persistence,
        activities=[a for a in state.activities if a.ioc_type == "op"],
        op_picture=state.op_picture,
        executive_summary=executive_summary,
        technical_overview=technical_overview,
        ioc_name=ioc_name,
    )

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_path = op_dir / f"report_{ts}.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path
