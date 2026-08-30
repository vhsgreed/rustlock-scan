#!/usr/bin/env python3
"""Tests for typosquat.py — the scoring engine must catch real typosquats
while NOT flagging legitimate ecosystem derivatives."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from typosquat import (
    DERIVATIVES,
    POPULAR,
    flagged_names,
    levenshtein,
    score_name,
)


class TestLevenshtein(unittest.TestCase):
    def test_equal(self):
        self.assertEqual(levenshtein("tokio", "tokio"), 0)

    def test_substitution(self):
        self.assertEqual(levenshtein("tokio", "toklo"), 1)

    def test_insertion(self):
        self.assertEqual(levenshtein("tokio", "tokios"), 1)

    def test_deletion(self):
        self.assertEqual(levenshtein("tokiox", "tokio"), 1)

    def test_unrelated(self):
        self.assertGreater(levenshtein("serde", "axum"), 2)


class TestDigitSuffix(unittest.TestCase):
    def test_proc_macro1_is_caught(self):
        """The exact 2026-08-20 incident pattern."""
        hits = flagged_names("proc-macro1")
        self.assertTrue(hits)
        best = max(s for s, _, _ in hits)
        self.assertGreaterEqual(best, 4, "digit-suffix clone should score 4")

    def test_serde1_is_caught(self):
        hits = flagged_names("serde1")
        self.assertTrue(any(s >= 4 for s, _, _ in hits))

    def test_tokio2_is_caught(self):
        hits = flagged_names("tokio2")
        self.assertTrue(any(s >= 4 for s, _, _ in hits))

    def test_no_digit_flag_on_real(self):
        """serde_json is a real crate, not a digit-suffix of anything."""
        self.assertEqual(flagged_names("serde_json"), [])


class TestDerivatives(unittest.TestCase):
    def test_tokio_util_not_flagged(self):
        self.assertIn("tokio-util", DERIVATIVES)
        self.assertEqual(flagged_names("tokio-util"), [])

    def test_serde_derive_not_flagged(self):
        self.assertEqual(flagged_names("serde_derive"), [])

    def test_axum_core_not_flagged(self):
        self.assertEqual(flagged_names("axum-core"), [])

    def test_sqlx_postgres_not_flagged(self):
        self.assertEqual(flagged_names("sqlx-postgres"), [])


class TestNearMiss(unittest.TestCase):
    def test_edit_distance_1_caught(self):
        hits = flagged_names("serdee")  # serde + extra e
        self.assertTrue(hits)
        self.assertGreaterEqual(max(s for s, _, _ in hits), 3)

    def test_edit_distance_2_caught(self):
        hits = flagged_names("sarde")   # serde with two substitutions
        self.assertTrue(hits)
        self.assertGreaterEqual(max(s for s, _, _ in hits), 2)

    def test_reqest_caught(self):
        """Common misspelling of reqwest."""
        hits = flagged_names("reqest")
        self.assertTrue(hits)

    def test_unrelated_not_flagged(self):
        self.assertEqual(flagged_names("bevy"), [])
        self.assertEqual(flagged_names("rocket"), [])
        self.assertEqual(flagged_names("mysql"), [])


class TestInterface(unittest.TestCase):
    def test_score_name_returns_tuples(self):
        results = score_name("proc-macro1")
        self.assertTrue(all(len(r) == 3 for r in results))

    def test_score_sorted_desc(self):
        results = score_name("serdee")
        scores = [s for s, _, _ in results]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_threshold_filters(self):
        # tokio-whatever is a weak prefix signal (score 1): below threshold.
        self.assertEqual(flagged_names("tokio-whatever"), [])
        # ...but visible in raw score_name output.
        self.assertTrue(score_name("tokio-whatever"))

    def test_popular_not_self_flagged(self):
        for name in list(POPULAR)[:5]:
            self.assertEqual(flagged_names(name), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)