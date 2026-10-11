from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional
from pathlib import Path
from pydantic import BaseModel, Field


# ── Kill-chain ladder ─────────────────────────────────────────────────────────

FRONTIER_LEVELS: dict[str, int] = {
    "recon":      0,   # ports/hosts discovered
    "service":    1,   # service fingerprinted
    "vuln":       2,   # vulnerability identified (not yet exploited)
    "exploited":  3,   # code-exec / access primitive proven
    "foothold":   4,   # stable session held
    "user":       5,   # user-level creds / user flag
    "privesc":    6,   # concrete privilege-escalation path identified
    "root":       7,   # root / administrator / root flag
}

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_OPEN_LEAD_STATES  = ("open", "active")
_DEAD_LEAD_STATES  = ("refuted", "exhausted")


def level_of(name: str) -> int:
    return FRONTIER_LEVELS.get((name or "").lower(), 0)


# ── Core models ───────────────────────────────────────────────────────────────

class Beacon(BaseModel):
    id: str
    host: str
    ip: str = ""
    user: str = ""
    pid: str = ""
    arch: str = ""
    os: str = ""
    last_seen: Optional[datetime] = None
    notes: str = ""


class Host(BaseModel):
    ip: str
    hostname: str = ""
    os: str = ""
    open_ports: list[str] = Field(default_factory=list)
    notes: str = ""


class Credential(BaseModel):
    type: str                    # password | hash | token | key | certificate
    username: str = ""
    secret: str = ""
    format: str = ""             # NTLM | cleartext | bcrypt | JWT | AWS_ACCESS_KEY …
    location: str = ""           # where the credential was FOUND (file path, service, host)
    used_at: list[str] = Field(default_factory=list)  # services/hosts where confirmed to work
    service: str = ""            # protocol context: ssh | smb | http | winrm …
    source_host: str = ""        # host it was extracted from
    verified: bool = False       # operator confirmed it works — LLM never sets this True
    notes: str = ""


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    severity: str                # info | low | medium | high | critical
    title: str
    description: str             # what it is, why it exists, how exploited
    target: str                  # host/service/path this applies to
    evidence: str = ""           # key output snippet proving the finding
    technique: str = ""          # e.g. "default-creds", "path-traversal", "kerberoasting"
    verified: bool = False       # operator-only — LLM never sets True
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Lead(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str             # the concrete next action to attempt
    target: str = ""             # host/surface/service this pertains to
    technique: str = ""          # category label (e.g. "SMB relay", "AS-REP roasting")
    reach_level: str = "vuln"    # kill-chain rung this reaches IF it succeeds
    prior: float = 0.5           # 0..1 estimated likelihood it advances
    cost: str = "medium"         # cheap | medium | expensive
    status: str = "open"         # open | active | confirmed | refuted | exhausted
    notes: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @property
    def is_open(self) -> bool:
        return self.status in _OPEN_LEAD_STATES


class AuthAttempt(BaseModel):
    service: str                 # ssh | smb | http | winrm | mssql | ftp …
    host: str
    port: Optional[int] = None
    username: str = ""
    secret_masked: str = ""      # first 2 chars + *** — never the real secret
    result: str = "unknown"      # success | fail | error
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PersistenceItem(BaseModel):
    """A change made to a target system — tracked for cleanup and reporting."""
    kind: str                    # file | authorized_key | user | service | cron | webshell | other
    host: str
    detail: str                  # what was planted/changed
    cleanup: str = ""            # exact command/steps to revert
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class OperationalFact(BaseModel):
    """Confirmed scaffolding facts — don't re-derive, don't report, just know."""
    statement: str               # one-line fact: "domain is corp.local"
    evidence: str = ""           # output snippet that proved it
    scope: str = ""              # host or principal it applies to (empty = global)
    status: str = "confirmed"    # confirmed | invalidated


class Surface(BaseModel):
    """An attack surface — the (host, service, port) unit of assessment."""
    host: str
    service: str = ""
    port: Optional[int] = None
    fingerprint: str = ""        # product/version banner
    status: str = "pending"      # pending | active | exhausted
    notes: str = ""

    def key(self) -> str:
        return f"{self.host}:{self.port or ''}/{self.service}".lower()


class Activity(BaseModel):
    timestamp: str
    command: str
    host: str = ""
    ioc_type: str = "unknown"    # op | local | unknown
    execution_context: str = ""
    output_summary: str = ""


# ── Engagement state ──────────────────────────────────────────────────────────

class EngagementState(BaseModel):
    op_name: str
    created: datetime = Field(default_factory=datetime.utcnow)
    last_analysis: Optional[datetime] = None

    # Tactical picture
    op_picture: str = ""
    frontier: str = "recon"      # current kill-chain position (highest confirmed lead level)

    # Discovered infrastructure
    beacons:      list[Beacon]        = Field(default_factory=list)
    hosts:        list[Host]          = Field(default_factory=list)
    surfaces:     list[Surface]       = Field(default_factory=list)

    # Findings and leads
    findings:     list[Finding]       = Field(default_factory=list)
    leads:        list[Lead]          = Field(default_factory=list)

    # Credentials and auth
    credentials:  list[Credential]   = Field(default_factory=list)
    auth_attempts:list[AuthAttempt]  = Field(default_factory=list)

    # Operator actions / changes
    persistence:  list[PersistenceItem] = Field(default_factory=list)

    # Confirmed facts (scaffolding — never re-derive)
    facts:        list[OperationalFact] = Field(default_factory=list)

    # Activity tracking
    activities:   list[Activity]     = Field(default_factory=list)

    # Log byte-offset cursors — persisted so analysis resumes from correct offset
    log_cursors: dict[str, int] = Field(default_factory=dict)

    def save(self, path: Path) -> None:
        path.write_text(self.model_dump_json(indent=2))

    @classmethod
    def load(cls, path: Path) -> "EngagementState":
        return cls.model_validate_json(path.read_text())

    def current_frontier(self) -> int:
        confirmed = [level_of(l.reach_level) for l in self.leads if l.status == "confirmed"]
        return max(confirmed) if confirmed else 0

    def frontier_name(self) -> str:
        lvl = self.current_frontier()
        return next((n for n, v in FRONTIER_LEVELS.items() if v == lvl), "recon")

    def open_leads(self) -> list[Lead]:
        return [l for l in self.leads if l.is_open]

    def merge_update(self, update: dict) -> list[str]:
        """Merge analyst LLM update into state. Returns list of notable new items."""
        new_items: list[str] = []

        # ── Beacons ───────────────────────────────────────────────────────────
        for b in update.get("beacons", []):
            if not any(x.id == b["id"] for x in self.beacons):
                self.beacons.append(Beacon(**b))
                new_items.append(f"New beacon: {b['id']} on {b.get('host', '?')}")
            else:
                existing = next(x for x in self.beacons if x.id == b["id"])
                for field in ("ip", "user", "os", "arch", "notes"):
                    if b.get(field) and not getattr(existing, field):
                        setattr(existing, field, b[field])

        # ── Hosts ─────────────────────────────────────────────────────────────
        for h in update.get("hosts", []):
            if not any(x.ip == h["ip"] for x in self.hosts):
                self.hosts.append(Host(**h))
                new_items.append(f"New host: {h['ip']}")
            else:
                existing = next(x for x in self.hosts if x.ip == h["ip"])
                for field in ("hostname", "os", "notes"):
                    if h.get(field) and not getattr(existing, field):
                        setattr(existing, field, h[field])
                if h.get("open_ports"):
                    existing.open_ports = list(dict.fromkeys(existing.open_ports + h["open_ports"]))

        # ── Surfaces ──────────────────────────────────────────────────────────
        for sv in update.get("surfaces", []):
            s = Surface(**sv)
            if not any(x.key() == s.key() for x in self.surfaces):
                self.surfaces.append(s)

        # ── Credentials ───────────────────────────────────────────────────────
        for c in update.get("credentials", []):
            u = c.get("username", "").strip()
            s = c.get("secret", "").strip()
            s_norm = s.lower()
            if s and not any(x.secret.strip().lower() == s_norm for x in self.credentials):
                self.credentials.append(Credential(**{**c, "username": u, "secret": s}))
                new_items.append(f"New credential: {u or '?'} ({c.get('type', '?')})")
            elif not s and u and not any(x.username.strip() == u and not x.secret for x in self.credentials):
                self.credentials.append(Credential(**{**c, "username": u}))
                new_items.append(f"New credential: {u or '?'} ({c.get('type', '?')})")

        # ── Findings ──────────────────────────────────────────────────────────
        for f in update.get("findings", []):
            title_norm = f.get("title", "").lower().strip()
            target = f.get("target", "")
            if not any(x.title.lower().strip() == title_norm and x.target == target
                       for x in self.findings):
                finding = Finding(**f)
                finding.verified = False  # LLM never marks verified
                self.findings.append(finding)
                sev = f.get("severity", "?")
                new_items.append(f"[{sev.upper()}] Finding: {f.get('title', '?')}")

        # ── Leads ─────────────────────────────────────────────────────────────
        for l in update.get("leads", []):
            desc_norm = " ".join(l.get("description", "").lower().split())[:80]
            target = l.get("target", "")
            if not any(
                " ".join(x.description.lower().split())[:80] == desc_norm and x.target == target
                for x in self.leads
            ):
                lead = Lead(**l)
                lead.status = "open"  # LLM never sets status; operator does
                self.leads.append(lead)

        # ── Auth attempts ─────────────────────────────────────────────────────
        for a in update.get("auth_attempts", []):
            self.auth_attempts.append(AuthAttempt(**a))

        # ── Persistence ───────────────────────────────────────────────────────
        for p in update.get("persistence", []):
            self.persistence.append(PersistenceItem(**p))
            new_items.append(f"Persistence: {p.get('kind', '?')} on {p.get('host', '?')}")

        # ── Operational facts ─────────────────────────────────────────────────
        for f in update.get("facts", []):
            stmt_norm = f.get("statement", "").lower().strip()
            if not any(x.statement.lower().strip() == stmt_norm for x in self.facts):
                self.facts.append(OperationalFact(**f))

        # ── Activities ────────────────────────────────────────────────────────
        for a in update.get("activities", []):
            if not any(x.command == a["command"] and x.timestamp == a["timestamp"]
                       for x in self.activities):
                self.activities.append(Activity(**a))

        if update.get("op_picture"):
            self.op_picture = update["op_picture"]

        # Advance frontier — analyst sets it directly from log evidence
        suggested = update.get("frontier", "")
        if suggested and level_of(suggested) > level_of(self.frontier):
            self.frontier = suggested
            new_items.append(f"Frontier advanced to: {suggested}")

        self.last_analysis = datetime.utcnow()
        return new_items
