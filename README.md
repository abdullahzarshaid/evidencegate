# EvidenceGate

**Repeatable evidence-package checks for security assessments.**

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)
![License MIT](https://img.shields.io/badge/License-MIT-green)

EvidenceGate keeps findings and evidence references in SQLite, then checks hashes, supplied CVSS
vectors, HTTP capture structure, optional hostname scope and selected secret patterns. It uses only
Python's standard library and makes no network requests.

**READY means configured checks passed. It does not establish vulnerability, authenticity,
authorization, complete redaction or analyst approval.**

![EvidenceGate architecture](docs/architecture.png)

## Try it with synthetic evidence

```bash
git clone https://github.com/abdullahzarshaid/evidencegate.git
cd evidencegate
python examples/quickstart.py
```

The demonstration rejects confirmation without evidence, attaches a synthetic HTTP capture and runs
the gate. No assessment target is contacted. See `python evidencegate.py --help` for commands.

## Assessment workflow

```bash
python evidencegate.py init assessment.db
python evidencegate.py add-finding assessment.db --id F-01 --title "Candidate IDOR" --severity MEDIUM --cvss "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
python evidencegate.py add-evidence assessment.db --finding F-01 --file proof/idor.txt --kind http
python evidencegate.py confirm assessment.db --id F-01
python evidencegate.py gate assessment.db --evidence-root . --in-scope example.test
```

Use your own authorized, reviewed evidence in `proof/idor.txt`. The `confirmed` status is a recorded
analyst decision; the tool enforces supporting evidence presence, not the truth of that decision.

| Check | What it establishes |
|---|---|
| G1 — integrity | Referenced evidence for confirmed findings matches its recorded hash and remains inside the evidence root |
| G2 — CVSS | Supplied CVSS 3.1 base vectors are valid and agree with supplied severity |
| G3 — HTTP structure | A request line and response status occur in supporting evidence |
| G4 — scope | Supported HTTP/1 request hosts match the optional declared hostname policy |
| G5 — secret patterns | Selected JWT, bearer-token, AWS-key and private-key patterns were checked |

Missing CVSS vectors are not inferred. No `--in-scope` means scope was **not checked**.
An empty confirmed set does not pass. Exit codes: `0` checks passed, `1` checks failed, `2` invalid input.

## Scope and evidence boundaries

`--in-scope example.test` permits that hostname, normalizing case and an optional port. Add
`--include-subdomains` only if authorization covers subdomains too. Substring lookalikes do not match.
Missing, duplicate or conflicting request authorities fail. This is not a port/path/CIDR policy engine;
HTTP/2 binary captures and non-HTTP proof formats are outside the HTTP checks.

Relative evidence paths resolve from `--evidence-root`; absolute paths must still resolve inside it.
Keep the ledger and trusted hash reference protected separately. Hashes are not signatures: a writer
who changes both evidence and ledger can defeat an integrity comparison. Avoid concurrent writes.
Secret detection is heuristic; review cookies, personal information and other credentials manually.

SQLite triggers require evidence before confirmation, validate hash format and prevent deleting or
moving the final evidence row of a confirmed finding. They assume an intact schema and trusted writer.
For an existing ledger, back it up and run `init` to install the added non-destructive triggers, then run
the gate. Existing labels and hashes are not automatically changed.

## Tests and contributions

```bash
python -m unittest discover -v
```

The suite includes normal operations, malformed vectors, scope tricks, missing/duplicate hosts,
path traversal and ledger-lifecycle cases. The symlink test skips when the operating system does not
permit symlink creation. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Contributions and bug reports should use synthetic examples, never private evidence.
