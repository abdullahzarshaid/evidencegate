# Changelog

All notable changes to EvidenceGate. The ledger schema is unchanged across the entries below.

## 1.0.0, 17 October 2026

First tagged release. The tool itself is unchanged in behaviour from the version published in September 2026; this release adds the packaging a user needs to depend on it.

- `--version` flag and a `__version__` constant in `evidencegate.py`.
- Continuous tests on GitHub Actions: Linux, Windows and macOS on Python 3.10 and 3.12, running the unit suite, the synthetic quickstart and the version flag.
- `CITATION.cff` so the repository can be cited from the GitHub "Cite this repository" button.
- A project page at https://abdullahzarshaid.github.io/evidencegate/ with the demonstration and the five checks explained.
- `docs/demo.gif`: the quickstart typeset as a short terminal recording. Paths are normalised and the gate report is condensed to one line per check; the figures are from a verified run.

What the release contains: the single-file tool (`evidencegate.py`, standard library only), the unit suite (`test_evidencegate.py`, `test_regressions.py`; 21 tests, one skipped where symlinks cannot be created), the synthetic quickstart and its invented capture, the architecture diagram, and the contribution and security guidance.
