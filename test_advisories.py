#!/usr/bin/env python3
"""Tests for rustlock-scan/advisories.py. Stdlib only (unittest)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import advisories as adv


class VersionTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(adv.parse_version("0.4.16"), ((0, 4, 16), (1,)))
        self.assertEqual(adv.parse_version("1.2"), ((1, 2, 0), (1,)))
        self.assertEqual(adv.parse_version("1"), ((1, 0, 0), (1,)))
        self.assertEqual(adv.parse_version("0"), ((0, 0, 0), (1,)))
        self.assertEqual(adv.parse_version("0.0.0-0"), ((0, 0, 0), (0, (0, 0))))
        self.assertLess(adv.parse_version("1.0.0-alpha"), adv.parse_version("1.0.0"))

    def test_in_range(self):
        ev = [{"introduced": "0"}, {"fixed": "0.4.16"}]
        self.assertTrue(adv._in_range(adv.parse_version("0.4.15"), ev))
        self.assertFalse(adv._in_range(adv.parse_version("0.4.16"), ev))
        self.assertTrue(adv._in_range(adv.parse_version("0.1.0"), ev))

    def test_in_range_last_affected(self):
        ev = [{"introduced": "2.0.0"}, {"last_affected": "2.3.1"}]
        self.assertTrue(adv._in_range(adv.parse_version("2.3.1"), ev))
        self.assertFalse(adv._in_range(adv.parse_version("2.3.2"), ev))
        self.assertFalse(adv._in_range(adv.parse_version("1.9.9"), ev))

    def test_affected_multi_range(self):
        affected = [{"package": {"ecosystem": "crates.io"},
                     "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.0"}]},
                                {"events": [{"introduced": "2.0.0"}, {"fixed": "2.5.0"}]}]}]
        self.assertTrue(adv.version_is_affected("0.9.0", affected))
        self.assertFalse(adv.version_is_affected("1.5.0", affected))
        self.assertTrue(adv.version_is_affected("2.4.9", affected))
        self.assertFalse(adv.version_is_affected("2.5.0", affected))

    def test_affected_explicit_versions(self):
        affected = [{"package": {"ecosystem": "crates.io"},
                     "versions": ["0.3.10", "0.3.9"]}]
        self.assertTrue(adv.version_is_affected("0.3.10", affected))
        self.assertFalse(adv.version_is_affected("0.3.8", affected))

    def test_affected_other_ecosystem_ignored(self):
        affected = [{"package": {"ecosystem": "npm"},
                     "ranges": [{"events": [{"introduced": "0"}]}]}]
        self.assertFalse(adv.version_is_affected("1.0.0", affected))

    def test_fixed_version(self):
        affected = [{"package": {"ecosystem": "crates.io"},
                     "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.4.16"}]}]}]
        self.assertEqual(adv.fixed_version(affected), "0.4.16")


class LockfileTests(unittest.TestCase):
    def test_crates_in_lockfile(self):
        lock = '''version = 3

[[package]]
name = "h2"
version = "0.4.15"

[[package]]
name = "serde"
version = "1.0.200"
'''
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Cargo.lock"
            p.write_text(lock)
            crates = adv.crates_in_lockfile(p)
        self.assertEqual(crates, {"h2": "0.4.15", "serde": "1.0.200"})


class IntegrationTests(unittest.TestCase):
    """End-to-end via a pre-seeded cache (offline path)."""

    H2_VULN = {
        "id": "RUSTSEC-2026-0258",
        "summary": "h2 unbounded empty DATA frames",
        "database_specific": {"severity": "LOW"},
        "affected": [{"package": {"ecosystem": "crates.io"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.4.16"}]}]}],
    }

    def _lockfile(self, version):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "Cargo.lock"
        p.write_text(f'''version = 3\n\n[[package]]\nname = "h2"\nversion = "{version}"\n''')
        return p

    def test_vulnerable_hit(self):
        cache = {"h2": {"vulns": [self.H2_VULN]}}
        p = self._lockfile("0.4.15")
        hits, unchecked = adv.check_lockfile(p, cache, offline=True)
        self.assertEqual(unchecked, [])
        self.assertEqual(len(hits), 1)
        name, version, vid, sev, summary, fixed = hits[0]
        self.assertEqual((name, version, vid, sev, fixed),
                         ("h2", "0.4.15", "RUSTSEC-2026-0258", "LOW", "0.4.16"))

    def test_patched_clean(self):
        cache = {"h2": {"vulns": [self.H2_VULN]}}
        p = self._lockfile("0.4.16")
        hits, unchecked = adv.check_lockfile(p, cache, offline=True)
        self.assertEqual(hits, [])

    def test_offline_unchecked(self):
        p = self._lockfile("0.4.15")
        hits, unchecked = adv.check_lockfile(p, {}, offline=True)
        self.assertEqual(hits, [])
        self.assertEqual(len(unchecked), 1)
        self.assertIn("offline", unchecked[0])

    def test_cache_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "cache.json"
            cache = {"h2": {"vulns": [self.H2_VULN]}}
            adv.save_cache(db, cache)
            self.assertEqual(adv.load_cache(db), cache)


if __name__ == "__main__":
    unittest.main(verbosity=2)
