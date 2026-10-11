from __future__ import annotations
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from core import config, llm_client, preprocessor
from core.engagement_state import EngagementState
from core.store import EngagementStore

_ANALYSIS_SYSTEM = """You are an expert red team analyst embedded in a live penetration test operation.
You have access to terminal logs, C2 console output, and the current engagement state.
Your job is to maintain a precise, accurate tactical picture of the operation.

CORE RULES:
- ONLY record facts that are directly evidenced in the logs. No speculation.
- Tag each command as: op (directly related to the engagement), local (local admin/noise), or unknown.
  op: anything through proxychains, targeting discovered hosts/IPs, C2 interaction, credential use against targets, AWS commands tied to target accounts.
  local: ls/cat/grep of local files, local pip/apt installs, tool setup, navigation.
- verified is ALWAYS false — the operator sets verified, never you.
- lead status is ALWAYS "open" — the operator changes status, never you.

CREDENTIALS — critical:
- Extract credentials from ALL command output regardless of op/local/unknown tag.
  A grep, cat, or find command may be tagged local, but if its output contains passwords, hashes, tokens, or keys — those MUST go into the credentials array.
- Any line matching: password=, passwd=, pass=, secret=, token=, key=, hash=, NTLM, :$, ::: → add to credentials.
- secret: the actual value verbatim (do NOT redact — this is the secure analyst record).
- output_summary: redact the secret (first 2 chars + ***).
- type: "password" | "hash" | "token" | "key" | "certificate"
- format: e.g. "cleartext", "NTLM", "bcrypt", "AWS_ACCESS_KEY", "RSA_KEY"
- location: where the credential was FOUND (file path, service URL, or host it was extracted from)
- source_host: the host the credential was extracted from
- service: what protocol it's used with (ssh, smb, http, winrm…) if known

FINDINGS — security observations:
- findings are vulnerabilities, misconfigurations, or exploitable conditions discovered in logs.
- severity: "info" | "low" | "medium" | "high" | "critical"
- evidence: a verbatim snippet from the log that proves the finding — not a paraphrase.
- technique: short label e.g. "default-creds", "path-traversal", "kerberoasting", "pass-the-hash"
- verified: always false — operator marks verified manually.

LEADS — next attack actions on the kill chain:
- leads are concrete next steps ranked by their potential kill-chain advancement.
- reach_level: what level the lead REACHES if successful — "recon"|"service"|"vuln"|"exploited"|"foothold"|"user"|"privesc"|"root"
- prior: 0.0–1.0 estimated likelihood this advances (0.3 = unlikely, 0.5 = plausible, 0.8 = strong)
- cost: "cheap" (< 5 min, no tooling) | "medium" | "expensive" (requires setup, risk, or time)
- status: always "open" — operator marks confirmed/refuted/exhausted.
- Only emit leads that are directly suggested by evidence in the current logs.

AUTH ATTEMPTS — credential testing log:
- Emit an auth_attempt any time logs show a credential was tested against a service.
- secret_masked: first 2 chars of the secret + "***" — never the real value.
- result: "success" | "fail" | "error"

OPERATIONAL FACTS — scaffolding, not findings:
- facts are confirmed environmental truths: "domain is corp.local", "DC IP is 10.0.0.1", "OS is Windows Server 2019 21H2"
- Do not repeat facts already listed in the state.
- evidence: short snippet that proved it.

SURFACES — attack surface map:
- A surface is a (host, service, port) unit. Emit one when a new service/port is discovered.
- fingerprint: product/version banner if visible in logs.
- status: always "pending" — operator updates to active/exhausted.

PERSISTENCE — changes made to targets:
- Only emit if the logs show a file dropped, user added, key planted, service installed, or scheduled task created on a target.
- cleanup: exact command/steps to revert the change.

- frontier: only emit when logs contain hard evidence of a new kill-chain level being reached.
  Examples: open port found → "service"; code exec confirmed → "exploited"; stable C2 session → "foothold";
  user creds proven working → "user"; root/SYSTEM shell confirmed (uid=0 or whoami=system) → "root".
  Omit the field entirely if unsure — never guess.
- advisory: one or two sentences on the most important thing to focus on. Empty string if nothing new.
- op_picture: a current paragraph summarizing what you have, where you are, what access exists.

Scope hints from config (not exhaustive):
{scope_hints}
"""

_ANALYZE_TOOL = {
    "name": "update_engagement_state",
    "description": "Update the engagement state with findings from new log content",
    "input_schema": {
        "type": "object",
        "properties": {
            "beacons": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "host": {"type": "string"},
                        "ip": {"type": "string"},
                        "user": {"type": "string"},
                        "arch": {"type": "string"},
                        "os": {"type": "string"},
                        "notes": {"type": "string"},
                    },
                    "required": ["id", "host"],
                },
            },
            "hosts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "hostname": {"type": "string"},
                        "os": {"type": "string"},
                        "open_ports": {"type": "array", "items": {"type": "string"}},
                        "notes": {"type": "string"},
                    },
                    "required": ["ip"],
                },
            },
            "surfaces": {
                "type": "array",
                "description": "New (host, service, port) attack surfaces discovered in these logs",
                "items": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "service": {"type": "string"},
                        "port": {"type": "integer"},
                        "fingerprint": {"type": "string"},
                        "notes": {"type": "string"},
                    },
                    "required": ["host"],
                },
            },
            "credentials": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": ["password", "hash", "token", "key", "certificate"]},
                        "username": {"type": "string"},
                        "secret": {"type": "string"},
                        "format": {"type": "string"},
                        "location": {"type": "string", "description": "where found: file path, URL, or host"},
                        "service": {"type": "string", "description": "protocol: ssh|smb|http|winrm…"},
                        "source_host": {"type": "string"},
                        "notes": {"type": "string"},
                    },
                    "required": ["type"],
                },
            },
            "findings": {
                "type": "array",
                "description": "Security findings: vulnerabilities, misconfigs, exploitable conditions",
                "items": {
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "target": {"type": "string"},
                        "evidence": {"type": "string", "description": "verbatim log snippet proving the finding"},
                        "technique": {"type": "string"},
                    },
                    "required": ["severity", "title", "description", "target"],
                },
            },
            "leads": {
                "type": "array",
                "description": "Concrete next attack actions suggested by current evidence",
                "items": {
                    "type": "object",
                    "properties": {
                        "description": {"type": "string"},
                        "target": {"type": "string"},
                        "technique": {"type": "string"},
                        "reach_level": {
                            "type": "string",
                            "enum": ["recon", "service", "vuln", "exploited", "foothold", "user", "privesc", "root"],
                        },
                        "prior": {"type": "number", "minimum": 0, "maximum": 1},
                        "cost": {"type": "string", "enum": ["cheap", "medium", "expensive"]},
                        "notes": {"type": "string"},
                    },
                    "required": ["description", "reach_level"],
                },
            },
            "auth_attempts": {
                "type": "array",
                "description": "Credential testing events seen in logs",
                "items": {
                    "type": "object",
                    "properties": {
                        "service": {"type": "string"},
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "username": {"type": "string"},
                        "secret_masked": {"type": "string", "description": "first 2 chars + ***"},
                        "result": {"type": "string", "enum": ["success", "fail", "error"]},
                    },
                    "required": ["service", "host", "result"],
                },
            },
            "facts": {
                "type": "array",
                "description": "Confirmed operational facts: domain, OS version, DC IP, etc.",
                "items": {
                    "type": "object",
                    "properties": {
                        "statement": {"type": "string"},
                        "evidence": {"type": "string"},
                        "scope": {"type": "string", "description": "host this applies to, empty if global"},
                    },
                    "required": ["statement"],
                },
            },
            "persistence": {
                "type": "array",
                "description": "Changes made to target systems (files, users, services, keys)",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": ["file", "authorized_key", "user", "service", "cron", "webshell", "other"],
                        },
                        "host": {"type": "string"},
                        "detail": {"type": "string"},
                        "cleanup": {"type": "string", "description": "exact command/steps to revert"},
                    },
                    "required": ["kind", "host", "detail"],
                },
            },
            "activities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "timestamp": {"type": "string"},
                        "command": {"type": "string"},
                        "host": {"type": "string"},
                        "ioc_type": {"type": "string", "enum": ["op", "local", "unknown"]},
                        "execution_context": {"type": "string"},
                        "output_summary": {"type": "string"},
                    },
                    "required": ["timestamp", "command", "ioc_type"],
                },
            },
            "op_picture": {"type": "string"},
            "advisory": {"type": "string"},
            "frontier": {
                "type": "string",
                "description": "Current kill-chain position — only emit when evidence in the logs confirms a new level has been reached",
                "enum": ["recon", "service", "vuln", "exploited", "foothold", "user", "privesc", "root"],
            },
        },
        "required": ["op_picture", "activities", "credentials"],
    },
}

_CHAT_TOOLS = [
    {
        "name": "list_directory",
        "description": "List files in a directory",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "read_file",
        "description": "Read the contents of a file",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "find_files",
        "description": "Find files matching a pattern",
        "input_schema": {
            "type": "object",
            "properties": {
                "directory": {"type": "string"},
                "pattern": {"type": "string"},
            },
            "required": ["directory", "pattern"],
        },
    },
    {
        "name": "grep_file",
        "description": "Search for a pattern in a file",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "pattern": {"type": "string"},
            },
            "required": ["path", "pattern"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file in the AI workspace directory",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Filename only, no path"},
                "content": {"type": "string"},
            },
            "required": ["filename", "content"],
        },
    },
    {
        "name": "web_search",
        "description": "Search the web for information about a topic",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
]

# Phase hints injected into _ANALYSIS_SYSTEM based on state.frontier.
# Frontier drives the hint — it's already confirmed and reliable, no log pattern inference needed.
_PHASE_HINTS: dict[str, str] = {
    "recon": (
        "CURRENT PHASE — RECON: Focus on infrastructure mapping. Flag new hosts, ports, services, "
        "and version banners. Watch for identity systems (ADFS, Okta, VPN portals, LDAP). "
        "Credential exposure signals (error messages revealing usernames, job postings, public repos) "
        "are findings even if not yet exploitable. Leads at this stage should have detection_risk=low."
    ),
    "service": (
        "CURRENT PHASE — SERVICE FINGERPRINTING: Services are identified but not yet exploited. "
        "Watch for default credential attempts, unauthenticated access (anonymous FTP, null SMB sessions, "
        "unauth Redis/Mongo), and version banners that match CVE families. Flag CVE matches as findings "
        "with verified=false. Leads that involve active exploitation have detection_risk=medium or higher."
    ),
    "vuln": (
        "CURRENT PHASE — VULNERABILITY ANALYSIS: Known weaknesses exist but exploitation hasn't been "
        "confirmed. Watch for exploit attempts and their outcomes — exact error messages matter. "
        "Flag whether a technique requires a compiled payload (detection_risk=high) vs. a LOLBin "
        "(detection_risk=low/medium). Password spray attempts: note the rate — slow spray is medium, "
        "fast spray is certain."
    ),
    "exploited": (
        "CURRENT PHASE — EXPLOITATION CONFIRMED: Code execution or access has been proven. "
        "Watch for stabilization attempts (reverse shell, SSH key drop, C2 beacon). "
        "Every command the operator runs is now generating SOC-visible events — note what EDR/logging "
        "is present. Flag the access primitive as a finding with the exact evidence. "
        "Leads should prioritize credential extraction and foothold stability."
    ),
    "foothold": (
        "CURRENT PHASE — POST-EXPLOITATION: Stable access exists. Aggressively extract credentials "
        "from every source: /etc/shadow, LSASS, SAM/SYSTEM, browser stores, config files, shell history, "
        "environment variables. Every credential found is a potential lateral movement path. "
        "Flag detection gaps: LSASS dump with no EDR alert → HIGH finding. "
        "Leads for escalation and lateral movement should note detection_risk explicitly."
    ),
    "user": (
        "CURRENT PHASE — PRIVILEGE ESCALATION: User-level access exists, root/SYSTEM is the target. "
        "Watch for sudo enumeration, SUID/SGID binaries, writable service paths, token privileges "
        "(SeImpersonatePrivilege → Potato family), and AD paths (Kerberoasting, ADCS, ACL abuse). "
        "Rank escalation leads by detection_risk first — a low-detection path to SYSTEM beats a "
        "noisy kernel exploit every time. Flag each path found with its detection profile."
    ),
    "privesc": (
        "CURRENT PHASE — LATERAL MOVEMENT: Escalation path identified or achieved. Focus on "
        "credential reuse across all known services — cross-reference every credential against every "
        "surface. Prefer LOLBin-based movement: WMI, scheduled tasks, DCOM over PsExec/service creation. "
        "New hosts reached are surfaces to register. Every technique used without triggering an alert "
        "is a detection gap finding. Note which credentials succeeded on which hosts."
    ),
    "root": (
        "CURRENT PHASE — ROOT/SYSTEM ACCESS: Full control achieved on at least one host. "
        "Focus on persistence documentation — every change to target systems must have a cleanup entry. "
        "Flag detection gaps for any persistence that wasn't caught. Document the full access chain "
        "from initial access to root as evidence. Leads should focus on scope expansion or "
        "demonstrating impact on additional targets."
    ),
}

_CHAT_SYSTEM = """You are an expert red team advisor embedded in a live penetration test.
You have full context of the current operation. Answer concisely and tactically.
You have access to tools to read files and search the web.

CRITICAL: Never use web_search with target IPs, hostnames, discovered credentials, or anything
that could reveal the operation to external services. Public CVEs, tool usage, general techniques only.
"""


class Analyst:
    def __init__(
        self,
        state: EngagementState,
        on_activity: Callable[[str], None],
        on_state_update: Callable[[EngagementState], None],
        store: EngagementStore | None = None,
    ) -> None:
        self._state = state
        self._on_activity = on_activity
        self._on_state_update = on_state_update
        self._store = store
        self._pending: list[list[dict]] = []
        self._pending_lock = threading.Lock()
        self._last_new_content = 0.0
        self._running = False
        self._thread: threading.Thread | None = None
        self._chat_history: list[dict] = []
        self._debounce = config.get("analyst.debounce", 8)

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def queue_new_content(self, path: Path, data: bytes) -> None:
        chunks = preprocessor.parse_chunks(data)
        if self._store is not None and chunks:
            try:
                self._store.add_chunks(chunks)
            except Exception as e:
                self._on_activity(f"[bold red]DB write error:[/bold red] {e}")
        with self._pending_lock:
            self._pending.append(chunks)
        self._last_new_content = time.time()

    def _run(self) -> None:
        while self._running:
            time.sleep(2)
            if not self._pending:
                continue
            # wait for debounce: no new content for N seconds
            if time.time() - self._last_new_content < self._debounce:
                continue
            with self._pending_lock:
                batch = self._pending[:]
                self._pending.clear()
            self._analyze(batch)

    def _analyze(self, batch: list[list[dict]]) -> None:
        try:
            all_chunks: list[dict] = [c for chunk_list in batch for c in chunk_list]
            if not all_chunks:
                return

            log_text = preprocessor.chunks_to_text(all_chunks)
            scope_hints = self._build_scope_hints()
            state_summary = self._state_summary()
            phase_hint = _PHASE_HINTS.get(self._state.frontier, _PHASE_HINTS["recon"])

            messages = [
                {
                    "role": "user",
                    "content": (
                        f"Current engagement state:\n{state_summary}\n\n"
                        f"New log content to analyze:\n{log_text}\n\n"
                        "Update the engagement state. Rules:\n"
                        "- activities: ALL commands from the new log content, tagged op/local/unknown.\n"
                        "- beacons/hosts/surfaces: only add entries NOT already listed above.\n"
                        "- credentials: only add credentials whose secret is NOT already listed above. Same username+hash = skip.\n"
                        "- findings: only add findings NOT already listed above (match on title+target).\n"
                        "- leads: only add leads NOT already listed above. status is always 'open'.\n"
                        "- auth_attempts: add every auth event seen in the new logs.\n"
                        "- facts: only add facts NOT already listed above.\n"
                        "- persistence: add any new changes made to target systems.\n"
                        "- op_picture: update to reflect the full current state."
                    ),
                }
            ]

            system = _ANALYSIS_SYSTEM.format(scope_hints=scope_hints) + f"\n\n{phase_hint}"
            response = llm_client.call(
                system=system,
                messages=messages,
                tools=[_ANALYZE_TOOL],
                max_tokens=8192,
            )

            for block in response.content:
                if block.type == "tool_use" and block.name == "update_engagement_state":
                    update = block.input
                    new_items = self._state.merge_update(update)
                    self._save_state()
                    self._on_state_update(self._state)

                    if self._store is not None:
                        self._push_update_to_db(update)

                    advisory = update.get("advisory", "")
                    if advisory:
                        self._on_activity(f"[bold yellow]Analyst:[/bold yellow] {advisory}")

                    for item in new_items:
                        self._on_activity(f"[bold green]>>>[/bold green] {item}")

        except Exception as e:
            self._on_activity(f"[bold red]Analyst error:[/bold red] {e}")

    def _push_update_to_db(self, update: dict) -> None:
        """Write one LLM update dict into every relevant DB table. Fire-and-forget."""
        s = self._store
        try:
            for h in update.get("hosts", []):
                s.upsert_host(
                    ip=h["ip"],
                    hostname=h.get("hostname", ""),
                    os=h.get("os", ""),
                    notes=h.get("notes", ""),
                    open_ports=h.get("open_ports"),
                )
            for b in update.get("beacons", []):
                s.upsert_beacon(
                    beacon_id=b["id"],
                    host=b.get("host", ""),
                    ip=b.get("ip", ""),
                    user=b.get("user", ""),
                    arch=b.get("arch", ""),
                    os=b.get("os", ""),
                    notes=b.get("notes", ""),
                )
            for sv in update.get("surfaces", []):
                s.add_surface(
                    host=sv["host"],
                    service=sv.get("service", ""),
                    port=sv.get("port"),
                    fingerprint=sv.get("fingerprint", ""),
                    notes=sv.get("notes", ""),
                )
            for c in update.get("credentials", []):
                if c.get("secret"):
                    s.add_credential(
                        username=c.get("username", ""),
                        secret=c["secret"],
                        cred_type=c.get("type", "password"),
                        cred_format=c.get("format", ""),
                        location=c.get("location", ""),
                        service=c.get("service", ""),
                        source_host=c.get("source_host", ""),
                        added_by="analyst",
                    )
            for f in update.get("findings", []):
                s.add_finding(
                    severity=f.get("severity", "info"),
                    title=f["title"],
                    description=f.get("description", ""),
                    target=f.get("target", ""),
                    evidence=f.get("evidence", ""),
                    technique=f.get("technique", ""),
                )
            for l in update.get("leads", []):
                s.add_lead(
                    description=l["description"],
                    reach_level=l.get("reach_level", "vuln"),
                    prior=float(l.get("prior", 0.5)),
                    cost=l.get("cost", "medium"),
                    target=l.get("target", ""),
                    technique=l.get("technique", ""),
                    created_by="analyst",
                    notes=l.get("notes", ""),
                )
            for f in update.get("facts", []):
                s.add_fact(
                    statement=f["statement"],
                    evidence=f.get("evidence", ""),
                    scope=f.get("scope", ""),
                )
            for p in update.get("persistence", []):
                s.add_persistence(
                    kind=p.get("kind", "other"),
                    host=p.get("host", ""),
                    detail=p.get("detail", ""),
                    cleanup=p.get("cleanup", ""),
                )
            for a in update.get("auth_attempts", []):
                s.add_auth_attempt(
                    service=a["service"],
                    host=a["host"],
                    result=a["result"],
                    port=a.get("port"),
                    username=a.get("username", ""),
                    secret_masked=a.get("secret_masked", ""),
                )
            # Analyst cycle — one row per analysis run
            s.add_analyst_cycle(
                frontier_level=self._state.frontier,
                summary=update.get("op_picture", ""),
                hypothesis="",   # LLM doesn't emit hypothesis in this tool call
                next_steps=[l["description"] for l in update.get("leads", [])[:5]],
                op_picture=update.get("op_picture", ""),
                advisory=update.get("advisory", ""),
            )
        except Exception as e:
            self._on_activity(f"[bold red]DB push error:[/bold red] {e}")

    def _state_summary(self) -> str:
        s = self._state
        lines = [
            f"Op: {s.op_name}  |  Frontier: {s.frontier}",
            f"Op directory: {config.op_dir()}",
            f"Log directory: {config.log_dir()}",
            f"AI workspace: {config.op_dir() / 'ai_workspace'}",
            f"Op picture: {s.op_picture or 'Not yet established'}",
        ]

        lines.append(f"\nBeacons ({len(s.beacons)}):")
        for b in s.beacons:
            lines.append(f"  {b.id}  host={b.host}  ip={b.ip}  user={b.user}  os={b.os}")
        if not s.beacons:
            lines.append("  none")

        lines.append(f"\nHosts ({len(s.hosts)}):")
        for h in s.hosts:
            lines.append(f"  {h.ip}  hostname={h.hostname}  os={h.os}  ports={','.join(h.open_ports[:8])}")
        if not s.hosts:
            lines.append("  none")

        lines.append(f"\nSurfaces ({len(s.surfaces)}):")
        for sv in s.surfaces:
            lines.append(f"  {sv.host}:{sv.port or '?'}/{sv.service}  {sv.fingerprint}  [{sv.status}]")
        if not s.surfaces:
            lines.append("  none")

        lines.append(f"\nCredentials ({len(s.credentials)}) — DO NOT RE-ADD THESE:")
        for c in s.credentials:
            masked = (c.secret[:2] + "***") if c.secret else "(none)"
            lines.append(f"  username={c.username}  type={c.type}  format={c.format}  "
                         f"location={c.location or c.source_host}  secret={masked}")
        if not s.credentials:
            lines.append("  none")

        lines.append(f"\nFindings ({len(s.findings)}) — DO NOT RE-ADD THESE:")
        for f in s.findings:
            lines.append(f"  [{f.severity.upper()}] {f.title}  target={f.target}")
        if not s.findings:
            lines.append("  none")

        lines.append(f"\nLeads ({len(s.leads)}) — DO NOT RE-ADD THESE:")
        for l in s.leads:
            lines.append(f"  [{l.status}] {l.description[:80]}  target={l.target}  reach={l.reach_level}")
        if not s.leads:
            lines.append("  none")

        lines.append(f"\nOperational facts ({len(s.facts)}) — DO NOT RE-ADD THESE:")
        for f in s.facts:
            lines.append(f"  {f.statement}  [{f.scope or 'global'}]")
        if not s.facts:
            lines.append("  none")

        lines.append(f"\nPersistence ({len(s.persistence)}):")
        for p in s.persistence:
            lines.append(f"  [{p.kind}] {p.host}: {p.detail[:60]}")
        if not s.persistence:
            lines.append("  none")

        return "\n".join(lines)

    def _build_scope_hints(self) -> str:
        targets = config.get("scope.targets", [])
        exclusions = config.get("scope.exclusions", [])
        if not targets and not exclusions:
            return "No explicit scope defined. Use context clues (proxychains, target IPs in commands, C2 activity) to determine what is op-related."
        parts = []
        if targets:
            parts.append(f"Known targets: {', '.join(targets)}")
        if exclusions:
            parts.append(f"Exclusions (never op-related): {', '.join(exclusions)}")
        return ". ".join(parts)

    def _save_state(self) -> None:
        if self._store is not None:
            self._store.save_cursors(self._state.log_cursors)
            return
        state_path = config.op_dir() / "session_state.json"
        self._state.save(state_path)

    # --- Chat ---

    def chat(self, message: str) -> str:
        """Synchronous chat call (called from UI thread via thread pool)."""
        self._chat_history.append({"role": "user", "content": message})

        # inject current state into system context
        system = _CHAT_SYSTEM + f"\n\nCurrent engagement state:\n{self._state_summary()}"

        messages = list(self._chat_history[-20:])  # keep last 20 turns

        try:
            response = llm_client.call(
                system=system,
                messages=messages,
                tools=_CHAT_TOOLS,
                max_tokens=4096,
            )
            reply = self._handle_chat_response(response)
            self._chat_history.append({"role": "assistant", "content": reply})
            return reply
        except Exception as e:
            return f"Error: {e}"

    def _handle_chat_response(self, response) -> str:
        """Run tool loop for chat responses."""
        messages = list(self._chat_history[-20:])

        while response.stop_reason == "tool_use":
            tool_results = []
            text_parts = []

            for block in response.content:
                if block.type == "text":
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    result = self._run_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

            system = _CHAT_SYSTEM + f"\n\nCurrent engagement state:\n{self._state_summary()}"
            response = llm_client.call(
                system=system,
                messages=messages[-20:],
                tools=_CHAT_TOOLS,
                max_tokens=4096,
            )

        return "\n".join(
            block.text for block in response.content if hasattr(block, "text")
        )

    def _run_tool(self, name: str, inputs: dict) -> str:
        import glob as _glob
        import re

        if name == "list_directory":
            try:
                p = Path(inputs["path"]).expanduser()
                return "\n".join(str(f) for f in sorted(p.iterdir()))
            except Exception as e:
                return f"Error: {e}"

        if name == "read_file":
            try:
                return Path(inputs["path"]).expanduser().read_text(errors="replace")
            except Exception as e:
                return f"Error: {e}"

        if name == "find_files":
            try:
                pattern = str(Path(inputs["directory"]).expanduser() / inputs["pattern"])
                return "\n".join(_glob.glob(pattern, recursive=True)[:100])
            except Exception as e:
                return f"Error: {e}"

        if name == "grep_file":
            try:
                content = Path(inputs["path"]).expanduser().read_text(errors="replace")
                pattern = inputs["pattern"]
                matches = [line for line in content.splitlines()
                           if re.search(pattern, line, re.IGNORECASE)]
                return "\n".join(matches[:200])
            except Exception as e:
                return f"Error: {e}"

        if name == "write_file":
            try:
                workspace = config.op_dir() / "ai_workspace"
                workspace.mkdir(exist_ok=True)
                # strip any path components — filename only
                filename = Path(inputs["filename"]).name
                target = workspace / filename
                target.write_text(inputs["content"])
                return f"Written to {target}"
            except Exception as e:
                return f"Error: {e}"

        if name == "web_search":
            return self._web_search(inputs["query"])

        return f"Unknown tool: {name}"

    def _web_search(self, query: str) -> str:
        # guard: block queries containing engagement-specific data
        s = self._state
        sensitive = (
            [b.host for b in s.beacons]
            + [h.ip for h in s.hosts]
            + [h.hostname for h in s.hosts if h.hostname]
            + [c.username for c in s.credentials]
            + config.get("scope.targets", [])
        )
        q_lower = query.lower()
        for term in sensitive:
            if term and term.lower() in q_lower:
                return f"Blocked: query contains engagement-specific term '{term}'. Keep web searches generic."

        import httpx

        brave_key = config.get_api_key("brave")
        if brave_key:
            try:
                r = httpx.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    params={"q": query, "count": 5},
                    headers={"Accept": "application/json", "X-Subscription-Token": brave_key},
                    timeout=10,
                )
                r.raise_for_status()
                results = r.json().get("web", {}).get("results", [])
                if results:
                    return "\n\n".join(
                        f"{res['title']}\n{res['url']}\n{res.get('description', '')}"
                        for res in results
                    )
            except Exception:
                pass  # fall through to DDG

        # ponytail: DuckDuckGo instant answers — no key, limited to definitions/abstracts
        try:
            r = httpx.get(
                "https://api.duckduckgo.com/",
                params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
                timeout=10,
            )
            r.raise_for_status()
            d = r.json()
            parts = []
            if d.get("AbstractText"):
                parts.append(f"{d['AbstractText']}\n{d.get('AbstractURL', '')}")
            for t in d.get("RelatedTopics", [])[:4]:
                if isinstance(t, dict) and t.get("Text"):
                    parts.append(f"{t['Text']}\n{t.get('FirstURL', '')}")
            if parts:
                note = "" if brave_key else " [DuckDuckGo instant answers — set /key set brave <key> for full results]"
                return note + "\n\n" + "\n\n".join(parts)
            return "No results found."
        except Exception as e:
            return f"Search error: {e}"

    # --- IOC Export ---

    def export_ioc(self) -> Path:
        """Export op-tagged activities + beacons to CSV/xlsx in op_dir."""
        import csv
        import openpyxl
        from datetime import datetime as dt

        op = config.op_dir()
        ts = dt.utcnow().strftime("%Y%m%d_%H%M%S")

        activities_path = op / f"ioc_activities_{ts}.csv"
        beacons_path = op / f"ioc_beacons_{ts}.csv"
        xlsx_path = op / f"ioc_{ts}.xlsx"

        op_activities = [a for a in self._state.activities if a.ioc_type == "op"]

        with open(activities_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["timestamp", "command", "host", "execution_context", "output_summary"])
            w.writeheader()
            for a in op_activities:
                w.writerow({
                    "timestamp": a.timestamp,
                    "command": a.command,
                    "host": a.host,
                    "execution_context": a.execution_context,
                    "output_summary": a.output_summary,
                })

        with open(beacons_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["id", "host", "ip", "user", "pid", "arch", "os", "last_seen", "notes"], extrasaction="ignore")
            w.writeheader()
            for b in self._state.beacons:
                w.writerow(b.model_dump())

        wb = openpyxl.Workbook()
        ws_act = wb.active
        ws_act.title = "Activities"
        ws_act.append(["Timestamp", "Command", "Host", "Execution Context", "Output Summary"])
        for a in op_activities:
            ws_act.append([a.timestamp, a.command, a.host, a.execution_context, a.output_summary])

        ws_beac = wb.create_sheet("Beacons")
        ws_beac.append(["ID", "Host", "IP", "User", "Arch", "OS", "Last Seen", "Notes"])
        for b in self._state.beacons:
            ws_beac.append([b.id, b.host, b.ip, b.user, b.arch, b.os,
                            str(b.last_seen) if b.last_seen else "", b.notes])

        ws_creds = wb.create_sheet("Credentials")
        ws_creds.append(["Type", "Username", "Format", "Location", "Service", "Source Host", "Verified", "Notes"])
        for c in self._state.credentials:
            ws_creds.append([c.type, c.username, c.format, c.location, c.service, c.source_host, c.verified, c.notes])

        ws_findings = wb.create_sheet("Findings")
        ws_findings.append(["Severity", "Title", "Target", "Technique", "Description", "Evidence", "Verified"])
        for f in self._state.findings:
            ws_findings.append([f.severity, f.title, f.target, f.technique, f.description, f.evidence, f.verified])

        ws_leads = wb.create_sheet("Leads")
        ws_leads.append(["Status", "Reach Level", "Prior", "Cost", "Target", "Technique", "Description"])
        for l in self._state.leads:
            ws_leads.append([l.status, l.reach_level, l.prior, l.cost, l.target, l.technique, l.description])

        ws_persist = wb.create_sheet("Persistence")
        ws_persist.append(["Kind", "Host", "Detail", "Cleanup"])
        for p in self._state.persistence:
            ws_persist.append([p.kind, p.host, p.detail, p.cleanup])

        wb.save(xlsx_path)

        return xlsx_path
