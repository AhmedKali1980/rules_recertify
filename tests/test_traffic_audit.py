import unittest

from rules_recertify.reporting.traffic_audit import (
    build_traffic_audit_rows,
    classify_traffic_outcome,
)


class TrafficAuditTest(unittest.TestCase):
    def test_unknown_and_invalid_are_documented_non_blocking_exceptions(self):
        status, blocking, exceptions = classify_traffic_outcome({
            "total": 8353,
            "completed": 8325,
            "pending": 0,
            "expired": 0,
            "unknown": 28,
            "invalid_query_body_count": 1,
        })
        self.assertEqual(status, "SUCCESS_WITH_EXCEPTIONS")
        self.assertEqual(blocking, [])
        self.assertEqual(
            exceptions, ["ASYNC_STATUS_UNKNOWN_OR_EMPTY", "INVALID_QUERY_BODY"],
        )

    def test_only_pending_and_expired_block_other_gaps_are_documented(self):
        status, blocking, exceptions = classify_traffic_outcome({
            "total": 10,
            "pending": 1,
            "expired": 2,
            "skipped_oversized_ruleset_count": 1,
            "runtime_oversized_ruleset_count": 1,
            "missing_result_count": 3,
        })
        self.assertEqual(status, "WARNING")
        self.assertEqual(blocking, [
            "ASYNC_QUERIES_PENDING", "ASYNC_QUERIES_EXPIRED",
        ])
        self.assertEqual(exceptions, [
            "RULESETS_SKIPPED_OVERSIZED", "RULESETS_SKIPPED_RUNTIME_OVERSIZED",
            "RULES_WITHOUT_RESULT",
        ])

    def test_missing_results_alone_advance_as_documented_exception(self):
        status, blocking, exceptions = classify_traffic_outcome({
            "total": 0,
            "missing_result_count": 2,
        })
        self.assertEqual(status, "SUCCESS_WITH_EXCEPTIONS")
        self.assertEqual(blocking, [])
        self.assertEqual(exceptions, ["RULES_WITHOUT_RESULT"])

    def test_oversized_ruleset_alone_advances_as_documented_exception(self):
        status, blocking, exceptions = classify_traffic_outcome({
            "total": 10,
            "skipped_oversized_ruleset_count": 1,
        })
        self.assertEqual(status, "SUCCESS_WITH_EXCEPTIONS")
        self.assertEqual(blocking, [])
        self.assertEqual(exceptions, ["RULESETS_SKIPPED_OVERSIZED"])

    def test_all_eligible_rulesets_oversized_is_still_non_blocking(self):
        status, blocking, exceptions = classify_traffic_outcome({
            "total": 0,
            "skipped_oversized_ruleset_count": 2,
        })
        self.assertEqual(status, "SUCCESS_WITH_EXCEPTIONS")
        self.assertEqual(blocking, [])
        self.assertEqual(exceptions, ["RULESETS_SKIPPED_OVERSIZED"])

    def test_audit_separates_processed_filtered_exception_and_blocking_rules(self):
        inventory = [
            {"rule_href": "/r/ok", "ruleset_href": "/rs/ok", "ruleset_name": "OK"},
            {"rule_href": "/r/out", "ruleset_href": "/rs/out", "ruleset_name": "OUT"},
            {"rule_href": "/r/unknown", "ruleset_href": "/rs/unknown", "ruleset_name": "UNKNOWN"},
            {"rule_href": "/r/missing", "ruleset_href": "/rs/missing", "ruleset_name": "MISSING"},
        ]
        usage = {
            "/r/ok": {"async_query_status": "completed", "flows": "2", "_batch": 1},
            "/r/unknown": {"async_query_status": "", "flows": "", "_batch": 2},
        }
        rows, counts = build_traffic_audit_rows(
            inventory, usage, {"/rs/out": "ENVIRONMENT_FILTER_MISMATCH"}, {}, [], [],
        )
        self.assertEqual(
            [row["outcome"] for row in rows],
            ["PROCESSED", "NOT_IN_SCOPE", "DOCUMENTED_EXCEPTION", "DOCUMENTED_EXCEPTION"],
        )
        self.assertEqual(counts["missing_result_count"], 1)

    def test_invalid_rows_without_inventory_identity_are_listed_as_problematic(self):
        inventory = [
            {"rule_href": "/r/ok", "ruleset_href": "/rs/ok", "ruleset_name": "OK"},
        ]
        usage = {
            "/r/ok": {"async_query_status": "completed", "flows": "2", "_batch": 1},
        }
        malformed = [
            {
                "rule_href": "rule_href",
                "ruleset_href": "ruleset_href",
                "query_body": "query_body",
                "async_query_status": "async_query_status",
                "_batch": 48,
            },
            {
                "rule_href": "",
                "query_body": "not-json",
                "async_query_status": "completed",
                "_batch": 49,
            },
        ]

        rows, counts = build_traffic_audit_rows(
            inventory, usage, {}, {}, malformed, [],
        )

        problematic = [row for row in rows if row["outcome"] == "DOCUMENTED_EXCEPTION"]
        self.assertEqual(len(problematic), 2)
        self.assertEqual(
            [row["reason"] for row in problematic],
            ["INVALID_QUERY_BODY", "INVALID_QUERY_BODY"],
        )
        self.assertEqual([row["batch"] for row in problematic], [48, 49])
        self.assertEqual(problematic[0]["query_body"], "query_body")
        self.assertEqual(counts["documented_exception_rule_count"], 2)


if __name__ == "__main__":
    unittest.main()
