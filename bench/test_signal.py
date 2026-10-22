"""Signal quality must measure guidance and completion, not severity inflation."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("oxtf_signal", Path(__file__).with_name("signal.py"))
signal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signal)


class SignalQualityTests(unittest.TestCase):
    def record(self):
        return {
            "schema": 3, "status": "complete", "rule_errors": [], "diagnostics": [],
            "stats": {"occurrences": 2},
            "rules": {"reviewed": {"rationale": "Impact is limited by scope.",
                                   "remediation": "Restrict the permitted resources.",
                                   "guideline": "https://docs.example.test/policy"},
                      "unreviewed": {"guideline": "https://github.com/example/check.py"}},
            "findings": [dict(rule=rule, attribute="policy", fix_hint=None, level="medium")
                         for rule in ("reviewed", "unreviewed")],
        }

    def test_source_link_alone_is_not_remediation(self):
        record = self.record()
        measured = signal.measure(record, 1000, 500)
        self.assertEqual(measured["with_rationale_pct"], 50.0)
        self.assertEqual(measured["with_remediation_pct"], 50.0)
        record["rules"]["reviewed"]["remediation"] = " "
        self.assertEqual(signal.measure(record, 1000, 500)["with_remediation_pct"], 0.0)

    def test_severity_distribution_is_not_a_quality_gate(self):
        measured = signal.measure(self.record(), 1000, 500)
        measured["default_profile"] = measured.copy()
        baseline = copy.deepcopy(measured)
        baseline["not_medium_pct"] = 100.0
        self.assertEqual(signal.regressions(measured, baseline), [])

    def test_missing_guidance_or_incomplete_analysis_fails_the_gate(self):
        baseline = signal.measure(self.record(), 1000, 500)
        baseline["default_profile"] = baseline.copy()
        current = copy.deepcopy(baseline)
        current["with_remediation_pct"] = 0.0
        current["default_profile"]["status"] = "incomplete"
        problems = signal.regressions(current, baseline)
        self.assertTrue(any("with_remediation_pct" in p for p in problems))
        self.assertTrue(any("default: analysis incomplete" in p for p in problems))

    def test_byte_inventory_keeps_error_and_guidance_costs_visible(self):
        rows = [{"type": "finding", "rule": "a"},
                {"type": "diagnostic", "message": "missing module"},
                {"type": "rule_error", "rule": "b", "message": "execution failed"},
                {"type": "summary", "rules": {"a": {"remediation": "Réduire les droits."}}}]
        raw = b"".join((json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for r in rows)
        parts = signal.ndjson_breakdown(raw)
        self.assertEqual(sum(parts.values()), len(raw))
        self.assertGreater(parts["rule_metadata"], 0)
        self.assertGreater(parts["diagnostic"], 0)
        self.assertGreater(parts["rule_error"], 0)

    def test_backlog_is_ranked_by_findings_not_severity(self):
        record = self.record()
        record["findings"].append(record["findings"][1].copy())
        backlog = signal.inventory(record)["guidance_backlog"]
        self.assertEqual([(r["rule"], r["findings"]) for r in backlog], [("unreviewed", 2)])

    def test_partial_observations_cannot_replace_the_baseline(self):
        current = signal.measure(self.record(), 1000, 500)
        current["status"] = "failed"
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            baseline.write_text("trusted baseline\n")
            for arguments in (["--write"], ["--output", str(baseline)]):
                with mock.patch.object(signal, "RESULTS", baseline), \
                        mock.patch.object(signal, "metrics", side_effect=lambda *a, **kw: current.copy()), \
                        mock.patch.object(signal.sys, "argv", ["signal.py", *arguments]), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as result:
                        signal.main()
                    self.assertNotEqual(result.exception.code, 0)
                self.assertEqual(baseline.read_text(), "trusted baseline\n")


if __name__ == "__main__":
    unittest.main()
