"""Synthetic boundary checks. No network targets are contacted."""
import contextlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
import evidencegate as eg


def capture(host='example.test', target='/'):
    return f'GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\nHTTP/1.1 200 OK\r\n\r\n'.encode()


class ScopeTests(unittest.TestCase):
    def test_exact_case_and_port(self):
        self.assertEqual(eg.scope_errors(capture('EXAMPLE.TEST:443'), 'example.test', False), [])

    def test_subdomain_requires_opt_in(self):
        self.assertTrue(eg.scope_errors(capture('app.example.test'), 'example.test', False))
        self.assertEqual(eg.scope_errors(capture('app.example.test'), 'example.test', True), [])

    def test_suffix_and_prefix_tricks(self):
        for host in ('example.test.attacker.invalid', 'notexample.test'):
            self.assertTrue(eg.scope_errors(capture(host), 'example.test', True))

    def test_missing_duplicate_and_conflicting(self):
        for data in (capture().replace(b'Host: example.test\r\n', b''),
                     capture().replace(b'Host:', b'Host: other.test\r\nHost:'),
                     capture(target='https://other.test/path')):
            self.assertTrue(eg.scope_errors(data, 'example.test', False))

    def test_multiple_requests_all_checked(self):
        self.assertTrue(eg.scope_errors(capture() + capture('other.test'), 'example.test', False))

    def test_malformed_authority(self):
        for host in ('example.test:bad', 'user@example.test', 'example.test/path'):
            self.assertTrue(eg.scope_errors(capture(host), 'example.test', False))


class IntegrityTests(unittest.TestCase):
    def test_bad_metric_is_value_error(self):
        with self.assertRaises(ValueError):
            eg.cvss31('CVSS:3.1/AV:BAD/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')

    def test_containment(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); root = base / 'evidence'; root.mkdir()
            (base / 'outside').write_text('synthetic')
            with self.assertRaises(ValueError):
                eg.evidence_path(root, '../outside')
            with self.assertRaises(ValueError):
                eg.evidence_path(root, str(base / 'outside'))

    def test_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); root = base / 'evidence'; root.mkdir()
            target = base / 'outside'; target.write_text('synthetic')
            try:
                (root / 'link').symlink_to(target)
            except OSError:
                self.skipTest('OS does not permit unprivileged symlinks')
            with self.assertRaises(ValueError):
                eg.evidence_path(root, 'link')

    def test_hash_and_lifecycle_constraints(self):
        conn = sqlite3.connect(':memory:'); conn.executescript(eg.SCHEMA)
        conn.execute("INSERT INTO findings(id,title,created_utc) VALUES ('F','test','now')")
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO evidence(finding_id,path,sha256,added_utc) VALUES ('F','proof','bad','now')")
        conn.execute("INSERT INTO evidence(finding_id,path,sha256,added_utc) VALUES ('F','proof',?,'now')", ('a'*64,))
        conn.execute("UPDATE findings SET status='confirmed' WHERE id='F'")
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM evidence WHERE finding_id='F'")
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE evidence SET finding_id='G' WHERE finding_id='F'")
        conn.execute("UPDATE findings SET status='draft' WHERE id='F'")
        conn.execute("DELETE FROM evidence WHERE finding_id='F'")
        conn.close()

    def test_empty_gate_fails(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            db = str(Path(temp) / 'test.db')
            self.assertEqual(eg.main(['init', db]), 0)
            self.assertEqual(eg.main(['gate', db, '--evidence-root', temp]), 1)


if __name__ == '__main__':
    unittest.main()
