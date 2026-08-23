"""
Unit tests for the new core (response_differ, web_findings confidence
model, injection_checker's error-signature matcher). These use fixed
strings/objects as fixtures -- no live target required.

Run with:
    python3 -m unittest discover -s tests -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.modules.web_security.response_differ import ResponseDiffer, HttpResponse
from engine.modules.web_security.web_findings import compute_confidence, confidence_band
from engine.modules.web_security.injection_checker import InjectionChecker


class TestResponseDiffer(unittest.TestCase):
    def setUp(self):
        self.differ = ResponseDiffer()

    def test_identical_responses_show_no_change(self):
        r1 = HttpResponse(status=200, headers={}, body="hello world", elapsed=0.1)
        r2 = HttpResponse(status=200, headers={}, body="hello world", elapsed=0.1)
        diff = self.differ.diff(r1, r2)
        self.assertFalse(diff.status_changed)
        self.assertFalse(diff.body_changed)
        self.assertEqual(diff.similarity_score, 1.0)

    def test_status_change_detected(self):
        r1 = HttpResponse(status=401, headers={}, body="Unauthorized", elapsed=0.1)
        r2 = HttpResponse(status=200, headers={}, body="Welcome back", elapsed=0.1)
        diff = self.differ.diff(r1, r2)
        self.assertTrue(diff.status_changed)

    def test_json_structure_change_detected_independent_of_values(self):
        r1 = HttpResponse(status=200, headers={}, body='{"error": "bad"}', elapsed=0.1)
        r2 = HttpResponse(status=200, headers={}, body='{"token": "abc", "user": {"id": 1}}', elapsed=0.1)
        diff = self.differ.diff(r1, r2)
        self.assertTrue(diff.json_structure_changed)

    def test_json_structure_unchanged_for_same_shape_different_values(self):
        r1 = HttpResponse(status=200, headers={}, body='{"id": 1, "name": "a"}', elapsed=0.1)
        r2 = HttpResponse(status=200, headers={}, body='{"id": 2, "name": "b"}', elapsed=0.1)
        diff = self.differ.diff(r1, r2)
        self.assertFalse(diff.json_structure_changed)

    def test_timing_change_requires_threshold(self):
        r1 = HttpResponse(status=200, headers={}, body="x", elapsed=0.2)
        r2_small = HttpResponse(status=200, headers={}, body="x", elapsed=0.5)
        r2_big = HttpResponse(status=200, headers={}, body="x", elapsed=5.0)
        self.assertFalse(self.differ.diff(r1, r2_small).timing_changed)
        self.assertTrue(self.differ.diff(r1, r2_big).timing_changed)


class TestConfidenceModel(unittest.TestCase):
    def test_no_evidence_is_low(self):
        self.assertEqual(confidence_band(compute_confidence()), "LOW")

    def test_error_plus_repeatable_is_high_or_above(self):
        c = compute_confidence(error_evidence=True, behavioral_evidence=True, repeatable=True, validated=True)
        self.assertGreaterEqual(c, 0.90)
        self.assertEqual(confidence_band(c), "VERY_HIGH")

    def test_single_observation_capped_below_confirmed_tier(self):
        c = compute_confidence(error_evidence=True, behavioral_evidence=False, repeatable=None, validated=False)
        self.assertLess(c, 0.90)

    def test_contradicted_on_retest_is_penalized_hard(self):
        c_first = compute_confidence(error_evidence=True, behavioral_evidence=True)
        c_after_fail = compute_confidence(error_evidence=True, behavioral_evidence=True, repeatable=False)
        self.assertLess(c_after_fail, c_first)


class TestSQLErrorSignatureMatching(unittest.TestCase):
    def setUp(self):
        self.checker = InjectionChecker("http://lab.invalid")

    def test_sqlite_error_detected(self):
        body = "Error: SQLITE_ERROR: near \"'\": syntax error"
        self.assertTrue(self.checker._has_sql_error(body))

    def test_mysql_error_detected(self):
        body = "Warning: mysql_fetch_array() expects parameter 1 to be resource"
        self.assertTrue(self.checker._has_sql_error(body))

    def test_postgres_error_detected(self):
        body = "PG::SyntaxError: ERROR: syntax error at or near"
        self.assertTrue(self.checker._has_sql_error(body))

    def test_sequelize_wrapped_error_detected(self):
        body = "SequelizeDatabaseError: SQLITE_ERROR: near \"nonexistent\""
        self.assertTrue(self.checker._has_sql_error(body))

    def test_plain_word_error_is_not_a_false_positive_trigger(self):
        body = "<title>Error</title><body>404 - page not found</body>"
        self.assertFalse(self.checker._has_sql_error(body))

    def test_generic_app_error_message_is_not_a_false_positive(self):
        body = '{"error": "Invalid email or password."}'
        self.assertFalse(self.checker._has_sql_error(body))


if __name__ == "__main__":
    unittest.main()
