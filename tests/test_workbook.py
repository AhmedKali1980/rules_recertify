import json
import unittest

from rules_recertify.reporting.workbook import _expand_side


class WorkbookExpansionTest(unittest.TestCase):
    def setUp(self):
        self.workloads = [
            {
                "hostname": "payment-01.example.net",
                "name": "payment-01",
                "app": "APM_PAYMENT",
                "env": "PRD",
                "addresses_json": json.dumps(["10.10.1.10"]),
            },
            {
                "hostname": "payment-02.example.net",
                "name": "payment-02",
                "app": "APM_PAYMENT",
                "env": "PRD",
                "addresses_json": json.dumps(["10.10.1.11"]),
            },
            {
                "hostname": "payment-uat.example.net",
                "name": "payment-uat",
                "app": "APM_PAYMENT",
                "env": "UAT",
                "addresses_json": json.dumps(["10.20.1.10"]),
            },
            {
                "hostname": "other.example.net",
                "name": "other",
                "app": "OTHER_APP",
                "env": "PRD",
                "addresses_json": json.dumps(["10.30.1.10"]),
            },
        ]

    def test_all_workloads_expands_app_and_environment_scope(self):
        expanded = _expand_side(
            {
                "ruleset_scope": "app:APM_PAYMENT;env:PRD",
                "src_all_workloads": "true",
            },
            "src",
            self.workloads,
            "PRD",
        )

        self.assertEqual(
            expanded.splitlines(),
            [
                "payment-01.example.net (10.10.1.10)",
                "payment-02.example.net (10.10.1.11)",
            ],
        )

    def test_all_workloads_expansion_accepts_reversed_scope_order(self):
        expanded = _expand_side(
            {
                "ruleset_scope": "env:PRD;app:APM_PAYMENT",
                "dst_all_workloads": "TRUE",
            },
            "dst",
            self.workloads,
            "PRD",
        )

        self.assertNotIn("payment-uat", expanded)
        self.assertNotIn("other.example.net", expanded)
        self.assertIn("payment-01.example.net (10.10.1.10)", expanded)

    def test_null_scope_environment_uses_requested_report_environment(self):
        expanded = _expand_side(
            {
                "ruleset_scope": "app:APM_PAYMENT;env:NULL",
                "src_all_workloads": "true",
            },
            "src",
            self.workloads,
            "UAT",
        )

        self.assertEqual(expanded, "payment-uat.example.net (10.20.1.10)")

