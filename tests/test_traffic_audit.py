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

    def test_pending_expired_oversized_and_missing_results_are_blocking(self):
        status, blocking, exceptions = classify_traffic_outcome({
            "total": 10,
            "pending": 1,
            "expired": 2,
            "skipped_oversized_ruleset_count": 1,
            "runtime_oversized_ruleset_count": 1,
            "missing_result_count": 3,
        })
        self.assertEqual(status, "WARNING")
        self.assertEqual(exceptions, [])
        self.assertEqual(len(blocking), 5)

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
            ["PROCESSED", "NOT_IN_SCOPE", "DOCUMENTED_EXCEPTION", "BLOCKING_PROBLEM"],
        )
        self.assertEqual(counts["missing_result_count"], 1)


if __name__ == "__main__":
    unittest.main()
