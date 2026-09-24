#!/usr/bin/env python3
"""A 60-second tour of EvidenceGate. Run from the repo root:

    python examples/quickstart.py

It builds a throwaway ledger, shows the database refusing a finding with no
evidence, then attaches a synthetic capture and runs the configured checks.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "evidencegate.py"
EVID = ROOT / "examples" / "evidence"

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"  # scores 6.5 (MEDIUM)


def run(*args, expect=None):
    print(f"\n$ evidencegate {' '.join(args)}")
    rc = subprocess.call([sys.executable, str(TOOL), *args])
    if expect is not None and rc != expect:
        raise SystemExit(f"unexpected exit code {rc} (wanted {expect})")
    return rc


def demonstrate(DB):
    run("init", str(DB))
    run("add-finding", str(DB), "--id", "F-01", "--title", "IDOR on /account",
        "--severity", "MEDIUM", "--cvss", VECTOR)

    print("\n# The database will not let a finding be confirmed with no evidence:")
    run("confirm", str(DB), "--id", "F-01", expect=1)

    print("\n# Attach the synthetic request/response capture, then confirm succeeds:")
    run("add-evidence", str(DB), "--finding", "F-01",
        "--file", str(EVID / "idor-account.txt"), "--kind", "http", expect=0)
    run("confirm", str(DB), "--id", "F-01", expect=0)
    run("list", str(DB))

    print("\n# Run the configured deterministic checks:")
    run("gate", str(DB), "--evidence-root", str(EVID), "--in-scope", "example.test", "--include-subdomains", expect=0)
    print("\nDone.")


def main():
    with tempfile.TemporaryDirectory(prefix="evidencegate-demo-") as directory:
        demonstrate(Path(directory) / "quickstart.db")


if __name__ == "__main__":
    main()
