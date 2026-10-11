from __future__ import annotations
import json
import os
import re
import sqlite3
from datetime import datetime
from hashlib import pbkdf2_hmac
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PBKDF2_ITERS = 390_000
_VERIFY_PAYLOAD = b"sidesaddle-verify-1"

# Parses "user@host$ → user@host#" from session-event output field
_SE_PATTERN = re.compile(
    r"([\w\-\.]+)@([\w\-\.]+)([$#])\s*[→>-]+\s*([\w\-\.]+)@([\w\-\.]+)([$#])"
)


class BadPassphrase(Exception):
    pass


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return pbkdf2_hmac("sha256", passphrase.encode(), salt, _PBKDF2_ITERS)


class EngagementStore:
    """
    One SQLite DB per engagement. Passphrase-protected: PBKDF2+AES-GCM verifies
    the key on open; credential secrets are the only field-level encrypted data.
    """

    def __init__(self, db_path: Path, passphrase: str) -> None:
        self._path = db_path
        is_new = not db_path.exists()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

        if is_new:
            salt = os.urandom(32)
            key = _derive_key(passphrase, salt)
            nonce = os.urandom(12)
            verify_blob = nonce + AESGCM(key).encrypt(nonce, _VERIFY_PAYLOAD, None)
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('salt', ?), ('verify_blob', ?)",
                (salt.hex(), verify_blob.hex()),
            )
            self._conn.commit()
            self._key = key
        else:
            rows = {r[0]: r[1] for r in self._conn.execute(
                "SELECT key, value FROM meta WHERE key IN ('salt', 'verify_blob')"
            ).fetchall()}
            if "salt" not in rows or "verify_blob" not in rows:
                self._conn.close()
                raise RuntimeError("DB missing auth metadata — corrupt or wrong file")
            salt = bytes.fromhex(rows["salt"])
            verify_blob = bytes.fromhex(rows["verify_blob"])
            key = _derive_key(passphrase, salt)
            nonce, ct = verify_blob[:12], verify_blob[12:]
            try:
                AESGCM(key).decrypt(nonce, ct, None)
            except Exception:
                self._conn.close()
                raise BadPassphrase("incorrect passphrase")
            self._key = key

    def close(self) -> None:
        self._conn.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    # ── schema ────────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS log_chunks (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT    NOT NULL,
                command      TEXT    NOT NULL,
                output       TEXT,
                context      TEXT,
                remote_user  TEXT,
                remote_host  TEXT,
                remote_privs TEXT,
                annotation   TEXT,
                created_at   TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_chunks_host ON log_chunks(remote_host, ts);
            CREATE INDEX IF NOT EXISTS idx_chunks_ts   ON log_chunks(ts);

            CREATE TABLE IF NOT EXISTS session_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                event_type TEXT NOT NULL,
                from_user  TEXT,
                from_host  TEXT,
                from_privs TEXT,
                to_user    TEXT,
                to_host    TEXT,
                to_privs   TEXT
            );

            CREATE TABLE IF NOT EXISTS hosts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT    NOT NULL UNIQUE,
                hostname   TEXT,
                os         TEXT,
                open_ports TEXT,
                notes      TEXT,
                first_seen TEXT DEFAULT (datetime('now')),
                last_seen  TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id      INTEGER REFERENCES hosts(id),
                username     TEXT,
                secret_enc   BLOB,
                secret_nonce BLOB,
                cred_type    TEXT,
                cred_format  TEXT,
                location     TEXT,
                service      TEXT,
                source_host  TEXT,
                chunk_id     INTEGER REFERENCES log_chunks(id),
                added_by     TEXT DEFAULT 'analyst',
                created_at   TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                severity    TEXT,
                title       TEXT NOT NULL,
                description TEXT,
                target      TEXT,
                evidence    TEXT,
                technique   TEXT,
                verified    INTEGER DEFAULT 0,
                ts          TEXT DEFAULT (datetime('now')),
                UNIQUE(title, target)
            );

            CREATE TABLE IF NOT EXISTS beacons (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                beacon_id   TEXT NOT NULL UNIQUE,
                host        TEXT,
                ip          TEXT,
                user        TEXT,
                pid         TEXT,
                arch        TEXT,
                os          TEXT,
                last_seen   TEXT,
                notes       TEXT,
                updated_at  TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS surfaces (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                host        TEXT NOT NULL,
                service     TEXT DEFAULT '',
                port        INTEGER,
                fingerprint TEXT,
                status      TEXT DEFAULT 'pending',
                notes       TEXT,
                ts          TEXT DEFAULT (datetime('now'))
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_surfaces_with_port
                ON surfaces(host, port, service) WHERE port IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_surfaces_no_port
                ON surfaces(host, service) WHERE port IS NULL;

            CREATE TABLE IF NOT EXISTS facts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                statement TEXT NOT NULL UNIQUE,
                evidence  TEXT,
                scope     TEXT,
                status    TEXT DEFAULT 'confirmed',
                ts        TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS persistence (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                kind    TEXT,
                host    TEXT,
                detail  TEXT,
                cleanup TEXT,
                ts      TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS auth_attempts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                service       TEXT,
                host          TEXT,
                port          INTEGER,
                username      TEXT,
                secret_masked TEXT,
                result        TEXT,
                ts            TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS analyst_cycles (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                ts             TEXT NOT NULL,
                frontier_level TEXT,
                summary        TEXT,
                hypothesis     TEXT,
                next_steps     TEXT,
                op_picture     TEXT,
                advisory       TEXT
            );

            CREATE TABLE IF NOT EXISTS leads (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                kind        TEXT,
                description TEXT    NOT NULL,
                target      TEXT,
                technique   TEXT,
                reach_level TEXT    DEFAULT 'vuln',
                prior       REAL    DEFAULT 0.5,
                cost        TEXT    DEFAULT 'medium',
                status      TEXT    DEFAULT 'open',
                origin_id   INTEGER,
                created_by  TEXT    DEFAULT 'analyst',
                notes       TEXT,
                ts          TEXT    DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS attack_paths (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                phase       TEXT,
                description TEXT,
                evidence    TEXT,
                ts          TEXT DEFAULT (datetime('now'))
            );
        """)
        self._conn.commit()
        self._migrate_schema()

    def _migrate_schema(self) -> None:
        """Add columns introduced after a DB was first created. Safe to re-run."""
        migrations = [
            ("hosts",           "open_ports TEXT"),
            ("credentials",     "cred_format TEXT"),
            ("credentials",     "location TEXT"),
            ("credentials",     "service TEXT"),
            ("credentials",     "source_host TEXT"),
            ("analyst_cycles",  "op_picture TEXT"),
            ("analyst_cycles",  "advisory TEXT"),
            ("leads",           "target TEXT"),
            ("leads",           "technique TEXT"),
        ]
        for table, col_def in migrations:
            col_name = col_def.split()[0]
            try:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
                self._conn.commit()
            except Exception:
                pass  # column already exists

    # ── log chunks ────────────────────────────────────────────────────────────

    def add_chunk(self, chunk: dict) -> int:
        """Insert one dict from parse_chunks. Session-events route to session_events table."""
        if chunk.get("context") == "session-event":
            return self._add_session_event(chunk)
        cur = self._conn.execute(
            """INSERT INTO log_chunks
               (ts, command, output, context, remote_user, remote_host, remote_privs)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (chunk["timestamp"], chunk["command"], chunk.get("output", ""),
             chunk.get("context"), chunk.get("remote_user"),
             chunk.get("remote_host"), chunk.get("remote_privs")),
        )
        self._conn.commit()
        return cur.lastrowid

    def add_chunks(self, chunks: list[dict]) -> int:
        """Bulk insert list from parse_chunks. Returns total rows written."""
        normal = [c for c in chunks if c.get("context") != "session-event"]
        events = [c for c in chunks if c.get("context") == "session-event"]
        self._conn.executemany(
            """INSERT INTO log_chunks
               (ts, command, output, context, remote_user, remote_host, remote_privs)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(c["timestamp"], c["command"], c.get("output", ""),
              c.get("context"), c.get("remote_user"),
              c.get("remote_host"), c.get("remote_privs")) for c in normal],
        )
        for e in events:
            self._add_session_event(e)
        self._conn.commit()
        return len(chunks)

    def annotate_chunk(self, chunk_id: int, note: str) -> None:
        self._conn.execute(
            "UPDATE log_chunks SET annotation = ? WHERE id = ?", (note, chunk_id)
        )
        self._conn.commit()

    def get_chunks(
        self,
        remote_host: str | None = None,
        context: str | None = None,
        limit: int = 500,
    ) -> list[dict]:
        q = "SELECT * FROM log_chunks WHERE 1=1"
        params: list = []
        if remote_host:
            q += " AND remote_host = ?"
            params.append(remote_host)
        if context:
            q += " AND context = ?"
            params.append(context)
        q += " ORDER BY ts LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self._conn.execute(q, params).fetchall()]

    # ── session events ────────────────────────────────────────────────────────

    def _add_session_event(self, chunk: dict) -> int:
        cmd = chunk.get("command", "")
        event_type = (
            cmd[16:-1] if cmd.startswith("(session event: ") and cmd.endswith(")")
            else cmd
        )
        fu = fh = fp = tu = th = tp = None
        m = _SE_PATTERN.search(chunk.get("output", ""))
        if m:
            fu, fh, fp, tu, th, tp = (
                m.group(1), m.group(2), m.group(3),
                m.group(4), m.group(5), m.group(6),
            )
        cur = self._conn.execute(
            """INSERT INTO session_events
               (ts, event_type, from_user, from_host, from_privs,
                to_user, to_host, to_privs)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (chunk["timestamp"], event_type, fu, fh, fp, tu, th, tp),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_session_events(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM session_events ORDER BY ts"
        ).fetchall()]

    # ── hosts ─────────────────────────────────────────────────────────────────

    def upsert_host(
        self, ip: str, hostname: str = "", os: str = "", notes: str = "",
        open_ports: list[str] | None = None,
    ) -> int:
        existing = self._conn.execute(
            "SELECT id FROM hosts WHERE ip = ?", (ip,)
        ).fetchone()
        ports_str = json.dumps(open_ports) if open_ports else None
        if existing:
            self._conn.execute(
                """UPDATE hosts
                   SET hostname   = COALESCE(NULLIF(?, ''), hostname),
                       os         = COALESCE(NULLIF(?, ''), os),
                       notes      = COALESCE(NULLIF(?, ''), notes),
                       open_ports = CASE WHEN ? IS NOT NULL THEN ? ELSE open_ports END,
                       last_seen  = datetime('now')
                   WHERE ip = ?""",
                (hostname, os, notes, ports_str, ports_str, ip),
            )
            self._conn.commit()
            return existing[0]
        cur = self._conn.execute(
            "INSERT INTO hosts (ip, hostname, os, notes, open_ports) VALUES (?, ?, ?, ?, ?)",
            (ip, hostname, os, notes, ports_str),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_hosts(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM hosts ORDER BY first_seen"
        ).fetchall()]

    # ── credentials ───────────────────────────────────────────────────────────

    def add_credential(
        self,
        username: str,
        secret: str,
        cred_type: str = "password",
        cred_format: str = "",
        location: str = "",
        service: str = "",
        source_host: str = "",
        host_id: int | None = None,
        chunk_id: int | None = None,
        added_by: str = "analyst",
    ) -> int:
        ct, nonce = self._encrypt(secret)
        cur = self._conn.execute(
            """INSERT INTO credentials
               (host_id, username, secret_enc, secret_nonce, cred_type,
                cred_format, location, service, source_host, chunk_id, added_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, username, ct, nonce, cred_type,
             cred_format, location, service, source_host, chunk_id, added_by),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_credentials(self, decrypt: bool = False) -> list[dict]:
        rows = [dict(r) for r in self._conn.execute(
            "SELECT * FROM credentials ORDER BY created_at"
        ).fetchall()]
        if decrypt:
            for r in rows:
                enc, nonce = r.get("secret_enc"), r.get("secret_nonce")
                if enc and nonce:
                    try:
                        r["secret"] = self._decrypt(enc, nonce)
                    except Exception:
                        r["secret"] = "(decrypt failed)"
        return rows

    def _encrypt(self, plaintext: str) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        return AESGCM(self._key).encrypt(nonce, plaintext.encode(), None), nonce

    def _decrypt(self, ct: bytes, nonce: bytes) -> str:
        return AESGCM(self._key).decrypt(nonce, ct, None).decode()

    # ── findings ──────────────────────────────────────────────────────────────

    def add_finding(
        self, severity: str, title: str, description: str = "",
        target: str = "", evidence: str = "", technique: str = "",
    ) -> int:
        cur = self._conn.execute(
            """INSERT OR IGNORE INTO findings
               (severity, title, description, target, evidence, technique)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (severity, title, description, target, evidence, technique),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_findings(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM findings ORDER BY ts"
        ).fetchall()]

    # ── beacons ───────────────────────────────────────────────────────────────

    def upsert_beacon(
        self, beacon_id: str, host: str = "", ip: str = "", user: str = "",
        pid: str = "", arch: str = "", os: str = "", last_seen: str = "", notes: str = "",
    ) -> int:
        self._conn.execute(
            """INSERT INTO beacons
               (beacon_id, host, ip, user, pid, arch, os, last_seen, notes, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(beacon_id) DO UPDATE SET
                   host      = COALESCE(NULLIF(excluded.host, ''), beacons.host),
                   ip        = COALESCE(NULLIF(excluded.ip, ''), beacons.ip),
                   user      = COALESCE(NULLIF(excluded.user, ''), beacons.user),
                   os        = COALESCE(NULLIF(excluded.os, ''), beacons.os),
                   last_seen = COALESCE(NULLIF(excluded.last_seen, ''), beacons.last_seen),
                   updated_at = datetime('now')""",
            (beacon_id, host, ip, user, pid, arch, os, last_seen, notes),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM beacons WHERE beacon_id = ?", (beacon_id,)
        ).fetchone()
        return row[0] if row else -1

    def get_beacons(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM beacons ORDER BY updated_at"
        ).fetchall()]

    # ── surfaces ──────────────────────────────────────────────────────────────

    def add_surface(
        self, host: str, service: str = "", port: int | None = None,
        fingerprint: str = "", notes: str = "",
    ) -> int:
        cur = self._conn.execute(
            """INSERT OR IGNORE INTO surfaces
               (host, service, port, fingerprint, notes)
               VALUES (?, ?, ?, ?, ?)""",
            (host, service, port, fingerprint, notes),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_surfaces(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM surfaces ORDER BY ts"
        ).fetchall()]

    # ── facts ─────────────────────────────────────────────────────────────────

    def add_fact(self, statement: str, evidence: str = "", scope: str = "") -> int:
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO facts (statement, evidence, scope) VALUES (?, ?, ?)",
            (statement, evidence, scope),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_facts(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM facts WHERE status = 'confirmed' ORDER BY ts"
        ).fetchall()]

    # ── persistence ───────────────────────────────────────────────────────────

    def add_persistence(
        self, kind: str, host: str, detail: str, cleanup: str = "",
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO persistence (kind, host, detail, cleanup) VALUES (?, ?, ?, ?)",
            (kind, host, detail, cleanup),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_persistence(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM persistence ORDER BY ts"
        ).fetchall()]

    # ── auth attempts ─────────────────────────────────────────────────────────

    def add_auth_attempt(
        self, service: str, host: str, result: str,
        port: int | None = None, username: str = "", secret_masked: str = "",
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO auth_attempts
               (service, host, port, username, secret_masked, result)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (service, host, port, username, secret_masked, result),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_auth_attempts(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM auth_attempts ORDER BY ts"
        ).fetchall()]

    # ── analyst cycles ────────────────────────────────────────────────────────

    def add_analyst_cycle(
        self,
        frontier_level: str,
        summary: str,
        hypothesis: str,
        next_steps: list[str],
        op_picture: str = "",
        advisory: str = "",
        ts: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO analyst_cycles
               (ts, frontier_level, summary, hypothesis, next_steps, op_picture, advisory)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ts or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
             frontier_level, summary, hypothesis, json.dumps(next_steps),
             op_picture, advisory),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_last_cycles(self, n: int = 5) -> list[dict]:
        rows = [dict(r) for r in self._conn.execute(
            "SELECT * FROM analyst_cycles ORDER BY ts DESC LIMIT ?", (n,)
        ).fetchall()]
        for r in rows:
            if r.get("next_steps"):
                try:
                    r["next_steps"] = json.loads(r["next_steps"])
                except (json.JSONDecodeError, TypeError):
                    pass
        return list(reversed(rows))  # return in chronological order

    # ── leads ─────────────────────────────────────────────────────────────────

    def add_lead(
        self,
        description: str,
        reach_level: str = "vuln",
        prior: float = 0.5,
        cost: str = "medium",
        kind: str = "",
        target: str = "",
        technique: str = "",
        origin_id: int | None = None,
        created_by: str = "analyst",
        notes: str = "",
        ts: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO leads
               (kind, description, target, technique, reach_level, prior, cost,
                origin_id, created_by, notes, ts)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (kind, description, target, technique, reach_level, prior, cost,
             origin_id, created_by, notes,
             ts or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        )
        self._conn.commit()
        return cur.lastrowid

    def update_lead_status(self, lead_id: int, status: str) -> None:
        self._conn.execute(
            "UPDATE leads SET status = ? WHERE id = ?", (status, lead_id)
        )
        self._conn.commit()

    def get_leads(self, status: str | None = None) -> list[dict]:
        q = "SELECT * FROM leads"
        params: list = []
        if status:
            q += " WHERE status = ?"
            params.append(status)
        q += " ORDER BY ts"
        return [dict(r) for r in self._conn.execute(q, params).fetchall()]

    # ── attack paths ──────────────────────────────────────────────────────────

    def add_attack_path(
        self, phase: str, description: str, evidence: str = "",
        ts: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO attack_paths (phase, description, evidence, ts) VALUES (?, ?, ?, ?)",
            (phase, description, evidence,
             ts or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_attack_paths(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM attack_paths ORDER BY ts"
        ).fetchall()]

    # ── summary ───────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        c = self._conn
        return {
            "chunks":       c.execute("SELECT COUNT(*) FROM log_chunks").fetchone()[0],
            "events":       c.execute("SELECT COUNT(*) FROM session_events").fetchone()[0],
            "hosts":        c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0],
            "creds":        c.execute("SELECT COUNT(*) FROM credentials").fetchone()[0],
            "findings":     c.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "beacons":      c.execute("SELECT COUNT(*) FROM beacons").fetchone()[0],
            "surfaces":     c.execute("SELECT COUNT(*) FROM surfaces").fetchone()[0],
            "facts":        c.execute("SELECT COUNT(*) FROM facts").fetchone()[0],
            "persistence":  c.execute("SELECT COUNT(*) FROM persistence").fetchone()[0],
            "leads":        c.execute("SELECT COUNT(*) FROM leads").fetchone()[0],
            "cycles":       c.execute("SELECT COUNT(*) FROM analyst_cycles").fetchone()[0],
            "paths":        c.execute("SELECT COUNT(*) FROM attack_paths").fetchone()[0],
        }
