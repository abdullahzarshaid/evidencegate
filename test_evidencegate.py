"""Tests for EvidenceGate. Run: python -m pytest -q   (or: python test_evidencegate.py)"""
import os
import sqlite3
import unittest
from pathlib import Path
import tempfile

import evidencegate as eg


def status_of(db, fid):
    with eg.ledger(db) as conn:
        return conn.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()["status"]

PROOF = (
    b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\n"
    b"Host: app.example.test\r\n\r\n"
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n\r\n"
    b"<html>...<script>alert(1)</script>...</html>\r\n"
)


class CvssTests(unittest.TestCase):
    def test_known_vectors(self):
        # Reference scores from the FIRST CVSS 3.1 specification examples.
        self.assertEqual(eg.cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(eg.cvss31("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"), 3.1)
        self.assertEqual(eg.cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(eg.cvss31("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"), 0.0)

    def test_bands(self):
        self.assertEqual(eg.band(0.0), "NONE")
        self.assertEqual(eg.band(3.9), "LOW")
        self.assertEqual(eg.band(6.9), "MEDIUM")
        self.assertEqual(eg.band(8.9), "HIGH")
        self.assertEqual(eg.band(9.8), "CRITICAL")

    def test_bad_vector_rejected(self):
        with self.assertRaises(ValueError):
            eg.cvss31("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        with self.assertRaises(ValueError):
            eg.cvss31("CVSS:3.1/AV:N/AC:L")  # incomplete


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "r.db")
        self._cwd = os.getcwd()
        os.chdir(self.root)          # run everything from the evidence root
        eg.main(["init", self.db])

    def tearDown(self):
        os.chdir(self._cwd)
        self.tmp.cleanup()

    def _finding(self, cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", sev="MEDIUM"):
        eg.main(["add-finding", self.db, "--id", "F-01", "--title", "Reflected XSS",
                 "--severity", sev, "--cvss", cvss])

    def test_confirm_refused_without_evidence(self):
        self._finding()
        rc = eg.main(["confirm", self.db, "--id", "F-01"])
        self.assertEqual(rc, 1)  # the DB trigger blocks it
        self.assertEqual(status_of(self.db, "F-01"), "draft")

    def test_confirm_succeeds_with_evidence(self):
        self._finding()
        Path("xss.txt").write_bytes(PROOF)
        eg.main(["add-evidence", self.db, "--finding", "F-01", "--file", "xss.txt", "--kind", "http"])
        rc = eg.main(["confirm", self.db, "--id", "F-01"])
        self.assertEqual(rc, 0)
        self.assertEqual(status_of(self.db, "F-01"), "confirmed")

    def test_insert_confirmed_blocked(self):
        with eg.ledger(self.db) as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO findings (id,title,status,created_utc) VALUES "
                             "('X','t','confirmed','now')")

    def test_gate_ready_and_tamper_detected(self):
        self._finding()
        p = self.root / "xss.txt"
        p.write_bytes(PROOF)
        eg.main(["add-evidence", self.db, "--finding", "F-01", "--file", "xss.txt", "--kind", "http"])
        eg.main(["confirm", self.db, "--id", "F-01"])

        rc = eg.main(["gate", self.db, "--evidence-root", str(self.root)])
        self.assertEqual(rc, 0)  # READY

        p.write_bytes(PROOF + b"tampered")  # change the file after hashing
        rc = eg.main(["gate", self.db, "--evidence-root", str(self.root)])
        self.assertEqual(rc, 1)  # G1 integrity fails -> NOT READY

    def test_gate_blocks_cvss_mismatch(self):
        # declare CRITICAL but give a LOW vector
        self._finding(cvss="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", sev="CRITICAL")
        p = self.root / "xss.txt"; p.write_bytes(PROOF)
        eg.main(["add-evidence", self.db, "--finding", "F-01", "--file", "xss.txt"])
        eg.main(["confirm", self.db, "--id", "F-01"])
        rc = eg.main(["gate", self.db, "--evidence-root", str(self.root)])
        self.assertEqual(rc, 1)  # G2 fails

    def test_gate_blocks_without_raw_proof(self):
        self._finding()
        p = self.root / "note.txt"; p.write_bytes(b"I think this is vulnerable, saw an error once.")
        eg.main(["add-evidence", self.db, "--finding", "F-01", "--file", "note.txt"])
        eg.main(["confirm", self.db, "--id", "F-01"])
        rc = eg.main(["gate", self.db, "--evidence-root", str(self.root)])
        self.assertEqual(rc, 1)  # G3 fails - no request/response

    def test_gate_flags_secret(self):
        self._finding()
        leak = PROOF + b"\nAuthorization: Bearer eyJabc123.def456ghijklmnop\n"
        p = self.root / "leak.txt"; p.write_bytes(leak)
        eg.main(["add-evidence", self.db, "--finding", "F-01", "--file", "leak.txt"])
        eg.main(["confirm", self.db, "--id", "F-01"])
        rc = eg.main(["gate", self.db, "--evidence-root", str(self.root)])
        self.assertEqual(rc, 1)  # G5 flags the token


if __name__ == "__main__":
    unittest.main(verbosity=2)
