import json
import sys
import unittest

import compare


VERSION = "3.2.328"
RULE = "CKV_AWS_16"
NATIVE = "aws-rds-unencrypted"
ADDRESS = 'module.database["prod"].aws_db_instance.db["a"]'


def run(doc, code=0):
    return {"stdout": json.dumps(doc), "stderr": "", "exit_code": code, "error": None}


def checkov_doc(state="FAILED", address=ADDRESS):
    groups = {"PASSED": "passed", "FAILED": "failed", "SKIPPED": "skipped"}
    group = groups[state]
    result = {"passed_checks": [], "failed_checks": [], "skipped_checks": [], "parsing_errors": []}
    result[group + "_checks"] = [{"check_id": RULE, "resource": "fallback", "resource_address": address,
                                    "check_result": {"result": state}}]
    summary = {"checkov_version": VERSION, "passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0}
    summary[group] = 1
    return {"check_type": "terraform", "results": result, "summary": summary}


def finding(severity="definite", address=ADDRESS):
    return {"rule": NATIVE, "address": address, "severity": severity}


class NormalizationTests(unittest.TestCase):
    def test_checkov_exit_one_is_valid_for_failed_checks(self):
        records = compare.checkov_records(run(checkov_doc(), 1), RULE, VERSION)
        self.assertEqual(list(records), [ADDRESS])
        self.assertEqual(records[ADDRESS][0]["status"], "failed")

    def test_empty_summary_is_missing_coverage_not_pass(self):
        doc = {"checkov_version": VERSION, "passed": 0, "failed": 0, "skipped": 0,
               "parsing_errors": 0, "resource_count": 0}
        self.assertEqual(compare.checkov_records(run(doc), RULE, VERSION), {})
        doc["failed"] = 1
        with self.assertRaises(ValueError):
            compare.checkov_records(run(doc, 1), RULE, VERSION)

    def test_quiet_and_truncated_reports_are_rejected(self):
        doc = checkov_doc()
        del doc["results"]["skipped_checks"]
        with self.assertRaises(KeyError):
            compare.checkov_records(run(doc, 1), RULE, VERSION)
        doc = checkov_doc()
        doc["summary"]["failed"] = 2
        with self.assertRaises(ValueError):
            compare.checkov_records(run(doc, 1), RULE, VERSION)

    def test_parse_errors_and_failed_execution_are_not_empty_success(self):
        doc = checkov_doc()
        doc["results"]["parsing_errors"] = ["broken.tf"]
        with self.assertRaises(ValueError):
            compare.checkov_records(run(doc, 1), RULE, VERSION)
        for bad in [run({}, 2), {**run({}), "stdout": "not JSON"}, {**run({}), "error": "timeout"}]:
            with self.assertRaises(ValueError):
                compare.checkov_records(bad, RULE, VERSION)
        with self.assertRaises(ValueError):
            compare.checkov_records(run(checkov_doc("PASSED"), 1), RULE, VERSION)

    def test_version_and_check_ids_are_validated(self):
        with self.assertRaises(ValueError):
            compare.checkov_records(run(checkov_doc(), 1), RULE, "other-version")
        with self.assertRaises(ValueError):
            compare.checkov_records(run(checkov_doc(), 1), "CKV_WRONG", VERSION)

    def test_native_diagnostics_are_not_clean_results(self):
        with self.assertRaises(ValueError):
            compare.native_records(run({"findings": [], "diagnostics": [{"severity": "error"}]}), NATIVE)

    def test_native_certainty_and_full_instance_address_survive(self):
        records = compare.native_records(run({"findings": [finding("conditional")], "diagnostics": []}), NATIVE)
        self.assertEqual(list(records), [ADDRESS])
        self.assertEqual(records[ADDRESS][0]["severity"], "conditional")


class ComparisonTests(unittest.TestCase):
    def row(self, native, checkov, errors=None, root="case-a"):
        return compare.compare({"root": root, "resources": [ADDRESS]}, RULE, native, checkov, errors or {})[0]

    def test_finding_agreement_matrix(self):
        for has_native, foreign, expected in [(True, "failed", "both_reported"), (True, "passed", "native_only"),
                                               (False, "failed", "checkov_only"), (False, "passed", "neither_reported")]:
            with self.subTest(expected=expected):
                row = self.row({ADDRESS: [finding()]} if has_native else {}, {ADDRESS: [{"status": foreign}]})
                self.assertEqual(row["outcome"], expected)
                if not has_native:
                    self.assertEqual(row["native"], "no_finding")

    def test_skips_unknowns_absence_and_errors_are_excluded(self):
        for status, expected in [("skipped", "skipped"), ("unknown", "unsupported")]:
            row = self.row({ADDRESS: [finding()]}, {ADDRESS: [{"status": status}]})
            self.assertEqual(row["outcome"], expected)
        self.assertEqual(self.row({}, {})["outcome"], "unsupported")
        self.assertEqual(self.row({}, {}, {"native": "timeout"})["outcome"], "error")

    def test_duplicates_are_not_silently_collapsed(self):
        for native, foreign in [({ADDRESS: [finding(), finding()]}, {}), ({}, {ADDRESS: [{"status": "failed"}] * 2})]:
            self.assertEqual(self.row(native, foreign)["outcome"], "unsupported")

    def test_roots_and_instance_keys_stay_distinct(self):
        self.assertNotEqual(self.row({}, {}, root="a")["root"], self.row({}, {}, root="b")["root"])
        sibling = ADDRESS.replace('["a"]', '["b"]')
        rows = compare.compare({"root": "a", "resources": [ADDRESS]}, RULE,
                               {sibling: [finding(address=sibling)]}, {}, {})
        self.assertEqual({r["address"] for r in rows}, {ADDRESS, sibling})
        self.assertTrue(all(r["outcome"] == "unsupported" for r in rows))

    def test_conditional_is_not_promoted_to_definite(self):
        row = self.row({ADDRESS: [finding("conditional")]}, {ADDRESS: [{"status": "failed"}]})
        self.assertEqual(row["outcome"], "both_reported")
        self.assertEqual(row["native"], "conditional")


class ExecutionTests(unittest.TestCase):
    def test_timeout_and_launch_errors_are_explicit(self):
        result = compare.execute([sys.executable, "-c", "import time; time.sleep(5)"], 0.02)
        self.assertEqual(result["error"], "timeout")
        self.assertIsNone(result["exit_code"])
        self.assertEqual(compare.execute(["/no/such/oxtf-command"], 1)["error"], "launch_error")


if __name__ == "__main__":
    unittest.main()
