#!/usr/bin/env python3
"""EvidenceGate - an evidence-first ledger and release gate for security findings.

A security finding is only as good as the proof behind it. EvidenceGate keeps every
finding and its evidence in a small SQLite ledger, and enforces one rule at the
database level: **you cannot mark a finding "confirmed" unless it has a hashed
evidence record.** A separate, deterministic gate then re-verifies the whole package -
evidence integrity, CVSS scoring, and HTTP capture structure - and prints a single
READY / NOT READY verdict for the configured checks. Analyst approval of the
vulnerability, impact, authorization and redaction remains necessary.

Standard library only. No network, no AI, no telemetry.

    evidencegate init report.db
    evidencegate add-finding report.db --id F-01 --title "Reflected XSS" \
        --severity HIGH --cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    evidencegate add-evidence report.db --finding F-01 --file proof/xss.txt --kind http
    evidencegate confirm report.db --id F-01      # refused if F-01 has no evidence
    evidencegate gate report.db --evidence-root . # deterministic READY/NOT READY
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import math
import re
import sqlite3
import sys
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    severity      TEXT,
    cvss_vector   TEXT,
    status        TEXT NOT NULL DEFAULT 'draft'
                  CHECK (status IN ('draft', 'confirmed', 'dropped')),
    created_utc   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    path          TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    kind          TEXT,
    added_utc     TEXT NOT NULL,
    UNIQUE (finding_id, path)
);
-- The gate, enforced by the database itself: a finding cannot become
-- "confirmed" while it has zero evidence rows. This is the core guarantee -
-- it assumes an intact schema, not a hostile database administrator.
CREATE TRIGGER IF NOT EXISTS no_confirm_without_evidence
BEFORE UPDATE OF status ON findings
WHEN NEW.status = 'confirmed'
     AND (SELECT COUNT(*) FROM evidence WHERE finding_id = NEW.id) = 0
BEGIN
    SELECT RAISE(ABORT, 'cannot confirm a finding with no evidence');
END;
CREATE TRIGGER IF NOT EXISTS no_confirm_on_insert
BEFORE INSERT ON findings
WHEN NEW.status = 'confirmed'
BEGIN
    SELECT RAISE(ABORT, 'a finding cannot be created already confirmed; add evidence then confirm');
END;
CREATE TRIGGER IF NOT EXISTS valid_hash_insert
BEFORE INSERT ON evidence
WHEN length(NEW.sha256) != 64 OR NEW.sha256 GLOB '*[^0-9a-fA-F]*'
BEGIN
    SELECT RAISE(ABORT, 'evidence requires a 64-character SHA-256 digest');
END;
CREATE TRIGGER IF NOT EXISTS valid_hash_update
BEFORE UPDATE OF sha256 ON evidence
WHEN length(NEW.sha256) != 64 OR NEW.sha256 GLOB '*[^0-9a-fA-F]*'
BEGIN
    SELECT RAISE(ABORT, 'evidence requires a 64-character SHA-256 digest');
END;
CREATE TRIGGER IF NOT EXISTS retain_confirmed_evidence_delete
BEFORE DELETE ON evidence
WHEN EXISTS (SELECT 1 FROM findings WHERE id=OLD.finding_id AND status='confirmed')
 AND (SELECT count(*) FROM evidence WHERE finding_id=OLD.finding_id) <= 1
BEGIN
    SELECT RAISE(ABORT, 'return finding to draft before removing its last evidence');
END;
CREATE TRIGGER IF NOT EXISTS retain_confirmed_evidence_move
BEFORE UPDATE OF finding_id ON evidence
WHEN NEW.finding_id != OLD.finding_id
 AND EXISTS (SELECT 1 FROM findings WHERE id=OLD.finding_id AND status='confirmed')
 AND (SELECT count(*) FROM evidence WHERE finding_id=OLD.finding_id) <= 1
BEGIN
    SELECT RAISE(ABORT, 'return finding to draft before moving its last evidence');
END;
"""

# ------------------------------------------------------------------ CVSS 3.1
_CVSS_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def cvss31(vector: str) -> float:
    """Return the CVSS 3.1 base score for a base vector, by the published spec."""
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError("not a CVSS:3.1 base vector")
    m: dict[str, str] = {}
    for tok in vector.split("/")[1:]:
        k, _, v = tok.partition(":")
        if k in m:
            raise ValueError(f"duplicate metric {k}")
        m[k] = v
    if sorted(m) != sorted(_CVSS_METRICS):
        raise ValueError("base metric set incorrect")
    w = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
         "UI": {"N": .85, "R": .62}, "C": {"H": .56, "L": .22, "N": 0.0},
         "I": {"H": .56, "L": .22, "N": 0.0}, "A": {"H": .56, "L": .22, "N": 0.0}}
    pr = {"U": {"N": .85, "L": .62, "H": .27}, "C": {"N": .85, "L": .68, "H": .5}}
    s = m["S"]
    if s not in ("U", "C"):
        raise ValueError("scope must be U or C")
    for key, values in w.items():
        if m[key] not in values:
            raise ValueError(f"invalid {key} metric")
    if m['PR'] not in pr[s]:
        raise ValueError("invalid PR metric")
    iss = 1 - ((1 - w["C"][m["C"]]) * (1 - w["I"][m["I"]]) * (1 - w["A"][m["A"]]))
    imp = 6.42 * iss if s == "U" else 7.52 * (iss - .029) - 3.25 * ((iss - .02) ** 15)
    if imp <= 0:
        return 0.0
    exp = 8.22 * w["AV"][m["AV"]] * w["AC"][m["AC"]] * pr[s][m["PR"]] * w["UI"][m["UI"]]
    raw = min(imp + exp, 10.0) if s == "U" else min(1.08 * (imp + exp), 10.0)
    return math.ceil((raw * 10) - 1e-10) / 10.0


def band(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


# ------------------------------------------------------------------ helpers
def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def connect(db: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


@contextlib.contextmanager
def ledger(db: str):
    """Open the ledger, commit on clean exit, and always close the handle."""
    conn = connect(db)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# Capture structure is not proof of vulnerability or authenticity.
RE_REQUEST = re.compile(rb"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+", re.M)
RE_RESPONSE = re.compile(rb"HTTP/[0-9.]+\s+\d{3}")
RE_HOST = re.compile(rb"^\s*Host:\s*(\S+)", re.M | re.I)
SECRETS = {
    "raw JWT": re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "Authorization: Bearer": re.compile(rb"[Aa]uthorization:\s*Bearer\s+\S{12,}"),
    "AWS access key id": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "private key block": re.compile(rb"BEGIN (?:RSA |EC )?PRIVATE KEY"),
}


def evidence_path(root: Path, value: str) -> Path:
    """Resolve only regular evidence files contained by the declared root."""
    root = root.resolve(strict=True)
    path = (root / value).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("evidence path is outside root or not a regular file")
    return path


def hostname(value: str) -> str:
    """Normalize a Host authority, rejecting credentials, paths and invalid ports."""
    if not value or any(c.isspace() for c in value) or any(c in value for c in '/\\?#@'):
        raise ValueError("invalid host authority")
    parsed = urlsplit('//' + value)
    host = parsed.hostname
    if not host or parsed.username or parsed.password:
        raise ValueError("missing host")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid port")
    host = host.rstrip('.').encode('idna').decode('ascii').lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                                    for part in host.split('.')):
            raise ValueError("invalid hostname")
        return host


def scope_errors(data: bytes, allowed: str, subdomains: bool) -> list[str]:
    """Check each HTTP/1 request header block; fail closed on unknown authority."""
    errors = []
    requests = list(re.finditer(rb'(?m)^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^\r\n ]+) HTTP/1\.[01]\r?$', data))
    if not requests:
        return ['no supported HTTP/1 request headers']
    for match in requests:
        tail = data[match.end():]
        end = re.search(rb'\r?\n\r?\n', tail)
        if end is None:
            errors.append('unterminated request headers'); continue
        values = re.findall(rb'(?im)^Host:[ \t]*([^\r\n]+)', tail[:end.start()])
        if len(values) != 1:
            errors.append('missing or duplicate Host header'); continue
        try:
            host = hostname(values[0].decode('ascii').strip())
            target = match.group(1).decode('ascii')
            if not target.startswith('/') and target != '*':
                url = urlsplit(target)
                if url.scheme not in ('http', 'https') or hostname(url.netloc) != host:
                    raise ValueError('request target and Host disagree')
            if host != allowed and not (subdomains and host.endswith('.' + allowed)):
                errors.append('host outside declared scope')
        except (ValueError, UnicodeError):
            errors.append('invalid or conflicting request authority')
    return errors


# ------------------------------------------------------------------ commands
def _done(msg: str) -> int:
    print(msg)
    return 0


def cmd_init(args) -> int:
    with ledger(args.db) as conn:
        conn.executescript(SCHEMA)
    return _done(f"initialized ledger: {args.db}")


def cmd_add_finding(args) -> int:
    if args.cvss:
        cvss31(args.cvss)  # validate now; raises on a bad vector
    with ledger(args.db) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO findings (id, title, severity, cvss_vector, status, created_utc) "
            "VALUES (?, ?, ?, ?, 'draft', ?)",
            (args.id, args.title, args.severity, args.cvss, now()))
    return _done(f"added finding {args.id} (status: draft)")


def cmd_add_evidence(args) -> int:
    p = Path(args.file)
    if not p.is_file():
        print(f"error: evidence file not found: {p}", file=sys.stderr)
        return 2
    digest = sha256_file(p)
    with ledger(args.db) as conn:
        if conn.execute("SELECT 1 FROM findings WHERE id = ?", (args.finding,)).fetchone() is None:
            print(f"error: no such finding: {args.finding}", file=sys.stderr)
            return 2
        conn.execute(
            "INSERT INTO evidence (finding_id, path, sha256, kind, added_utc) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(finding_id,path) DO UPDATE SET "
            "sha256=excluded.sha256, kind=excluded.kind, added_utc=excluded.added_utc",
            (args.finding, str(args.file), digest, args.kind, now()))
    return _done(f"attached evidence {args.file} to {args.finding}  sha256={digest[:16]}...")


def cmd_confirm(args) -> int:
    with ledger(args.db) as conn:
        try:
            cur = conn.execute("UPDATE findings SET status = 'confirmed' WHERE id = ?", (args.id,))
        except sqlite3.IntegrityError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 1
        if cur.rowcount == 0:
            print(f"error: no such finding: {args.id}", file=sys.stderr)
            return 2
    return _done(f"confirmed {args.id}")


def cmd_gate(args) -> int:
    root = Path(args.evidence_root).resolve()
    conn = connect(args.db)
    try:
        return _gate(args, root, conn)
    finally:
        conn.close()


def _gate(args, root: Path, conn: sqlite3.Connection) -> int:
    findings = conn.execute("SELECT * FROM findings").fetchall()
    blockers: list[str] = []
    lines: list[str] = [f"# EvidenceGate report - {Path(args.db).name}\n"]

    confirmed = [f for f in findings if f["status"] == "confirmed"]
    if not confirmed:
        blockers.append("no confirmed findings to evaluate")
    lines.append(f"## Findings\n- total: {len(findings)}\n- confirmed: {len(confirmed)}\n")

    # G1 - evidence integrity: every stored hash must still match the file on disk.
    missing = bad = ok = 0
    for f in confirmed:
        for e in conn.execute("SELECT * FROM evidence WHERE finding_id = ?", (f["id"],)):
            try:
                fp = evidence_path(root, e["path"])
            except (OSError, ValueError, RuntimeError):
                missing += 1
                continue
            if sha256_file(fp).lower() != e["sha256"].lower():
                bad += 1
            else:
                ok += 1
    lines.append(f"\n## G1 evidence integrity\n- verified: {ok}\n- missing: {missing}\n- hash mismatches: {bad}\n")
    if missing or bad:
        blockers.append(f"G1 evidence integrity: {missing} missing, {bad} tampered")

    # G2 - CVSS recomputation: a declared severity must match the vector's real score.
    cvss_bad = []
    for f in confirmed:
        if not f["cvss_vector"]:
            continue
        try:
            score = cvss31(f["cvss_vector"])
        except ValueError as exc:
            cvss_bad.append((f["id"], str(exc))); continue
        if f["severity"] and f["severity"].upper() != band(score):
            cvss_bad.append((f["id"], f"severity {f['severity']} but {score} is {band(score)}"))
    lines.append(f"\n## G2 CVSS recomputation\n- defects: {len(cvss_bad)}\n")
    lines += [f"  - {i} - {r}\n" for i, r in cvss_bad]
    if cvss_bad:
        blockers.append(f"G2 CVSS defects: {len(cvss_bad)}")

    # G3 - capture structure; not confirmation of a vulnerability.
    no_proof, oos = [], []
    want = hostname(args.in_scope) if args.in_scope else None
    for f in confirmed:
        has_proof = False
        for e in conn.execute("SELECT * FROM evidence WHERE finding_id = ?", (f["id"],)):
            try:
                fp = evidence_path(root, e["path"])
                b = fp.read_bytes()
            except (OSError, ValueError, RuntimeError):
                continue
            if want:
                for error in scope_errors(b, want, args.include_subdomains):
                    oos.append((f['id'], error))
            if RE_REQUEST.search(b) and RE_RESPONSE.search(b):
                has_proof = True
        if not has_proof:
            no_proof.append(f["id"])
    lines.append(f"\n## G3 HTTP capture structure\n- matched: {len(confirmed) - len(no_proof)}/{len(confirmed)}\n")
    if no_proof:
        lines.append(f"  - no supported capture: {', '.join(no_proof)}\n")
        blockers.append(f"G3 confirmed findings without request/response structure: {len(no_proof)}")

    # G4 - scope (optional): confirmed findings must not rest on out-of-scope hosts.
    if want:
        lines.append(f"\n## G4 scope (in-scope: {args.in_scope})\n- out-of-scope evidence hosts: {len(set(oos))}\n")
        for i, h in sorted(set(oos)):
            lines.append(f"  - {i} -> {h}\n")
        if oos:
            blockers.append(f"G4 out-of-scope evidence: {sorted({i for i, _ in oos})}")

    # G5 - secrets: raw proof often carries live tokens; flag them before release.
    sec_total = 0
    files = []
    for candidate in root.rglob('*'):
        if candidate.is_file():
            try:
                files.append(evidence_path(root, str(candidate)))
            except (OSError, ValueError, RuntimeError):
                blockers.append('G5 path outside evidence root or unreadable')
    lines.append("\n## G5 secret material in evidence\n")
    for label, rx in SECRETS.items():
        hits = [str(p.relative_to(root)) for p in files if rx.search(p.read_bytes())]
        sec_total += len(hits)
        lines.append(f"- {label}: {len(hits)} file(s)\n")
        lines += [f"    - {h}\n" for h in hits[:5]]
    if sec_total:
        blockers.append(f"G5 secret material in {sec_total} file(s) - redact before sharing")

    ready = not blockers
    lines.append("\n## VERDICT\n")
    lines.append("READY\n" if ready else "NOT READY\n")
    lines += [f"- BLOCKER: {b}\n" for b in blockers]
    lines.append("\nREADY means configured checks passed, not analyst approval or proof of vulnerability.\n")
    report = "".join(lines)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    print(report)
    return 0 if ready else 1


def cmd_list(args) -> int:
    with ledger(args.db) as conn:
        for f in conn.execute("SELECT * FROM findings ORDER BY id"):
            n = conn.execute("SELECT COUNT(*) c FROM evidence WHERE finding_id = ?",
                             (f["id"],)).fetchone()["c"]
            print(f"  {f['id']:<10} {f['status']:<10} {f['severity'] or '-':<8} evidence={n}  {f['title']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evidencegate", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create a new ledger database")
    s.add_argument("db"); s.set_defaults(func=cmd_init)

    s = sub.add_parser("add-finding", help="add a finding (starts as draft)")
    s.add_argument("db"); s.add_argument("--id", required=True); s.add_argument("--title", required=True)
    s.add_argument("--severity"); s.add_argument("--cvss"); s.set_defaults(func=cmd_add_finding)

    s = sub.add_parser("add-evidence", help="attach and hash an evidence file")
    s.add_argument("db"); s.add_argument("--finding", required=True); s.add_argument("--file", required=True)
    s.add_argument("--kind"); s.set_defaults(func=cmd_add_evidence)

    s = sub.add_parser("confirm", help="mark a finding confirmed (refused without evidence)")
    s.add_argument("db"); s.add_argument("--id", required=True); s.set_defaults(func=cmd_confirm)

    s = sub.add_parser("gate", help="run the deterministic release gate")
    s.add_argument("db"); s.add_argument("--evidence-root", default="."); s.add_argument("--in-scope")
    s.add_argument("--include-subdomains", action="store_true", help="explicitly allow subdomains of --in-scope")
    s.add_argument("--out"); s.set_defaults(func=cmd_gate)

    s = sub.add_parser("list", help="list findings")
    s.add_argument("db"); s.set_defaults(func=cmd_list)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
