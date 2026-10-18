import tempfile
import unittest
from pathlib import Path

from rules_recertify.reporting.compliance import (
    _contains_user_iplist, _factor_side, _has_intra_zone_iplist,
    _load_scope_input, _programs_for_app, _rule_matches_scope,
)


class ComplianceTest(unittest.TestCase):
    def test_rule_scope_matching_is_anchored_and_environment_is_optional(self):
        rule = {
            "ruleset_scope": "env:PRD;app:PAYMENTS",
            "src_labels": "app:OTHER;env:UAT",
            "dst_labels": "",
        }
        self.assertTrue(_rule_matches_scope(rule, "PAYMENTS", "PRD"))
        self.assertTrue(_rule_matches_scope(rule, "PAYMENTS", ""))
        self.assertFalse(_rule_matches_scope(rule, "PAY", "PRD"))
        self.assertFalse(_rule_matches_scope(rule, "PAYMENTS", "UAT"))

    def test_source_destination_factorization_uses_required_priority(self):
        all_workloads = {
            "src_all_workloads": "true", "src_iplists": "U_USERS", "src_labels": "app:A",
        }
        iplist = {
            "dst_all_workloads": "false", "dst_iplists": "NZ3_APP", "dst_labels": "app:A",
        }
        labels = {
            "src_all_workloads": "false", "src_iplists": "", "src_labels": "app:A;env:PRD",
        }
        self.assertEqual(_factor_side(all_workloads, "src"), ("All workloads", "all_workloads"))
        self.assertEqual(_factor_side(iplist, "dst"), ("NZ3_APP", "iplist"))
        self.assertEqual(_factor_side(labels, "src"), ("app:A;env:PRD", "labels"))

    def test_user_and_intra_zone_iplist_detection_is_prefix_based(self):
        self.assertTrue(_contains_user_iplist("NETWORK;USR_ADMINS"))
        self.assertTrue(_contains_user_iplist("U_USERS (/orgs/1/sec_policy/draft/ip_lists/1)"))
        self.assertFalse(_contains_user_iplist("BUSR_ADMINS"))
        self.assertTrue(_has_intra_zone_iplist("NZ3_PARIS;OTHER"))
        self.assertTrue(_has_intra_zone_iplist("ZNOT_NZ3_APP"))
        self.assertFalse(_has_intra_zone_iplist("NOT_NZ3_APP"))

    def test_program_membership_uses_only_kpi_program_groups(self):
        groups = [
            {"name": "KPI_PROGRAM_ONE", "member_labels": "app:APP_A",
             "fully_expanded_members": "app:APP_A"},
            {"name": "OTHER_GROUP", "member_labels": "app:APP_A",
             "fully_expanded_members": "app:APP_A"},
            {"name": "KPI_PROGRAM_TWO", "member_labels": "",
             "fully_expanded_members": "app:APP_A;env:PRD"},
        ]
        self.assertEqual(_programs_for_app("APP_A", groups), "KPI_PROGRAM_ONE;KPI_PROGRAM_TWO")

    def test_csv_input_preserves_columns_and_env_is_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.csv"
            source.write_text("Owner,app,Ticket\nAlice,APP_A,INC1\n", encoding="utf-8")
            rows, columns = _load_scope_input(source, root / "unused.csv")
        self.assertEqual(columns, ["Owner", "app", "Ticket"])
        self.assertEqual(rows, [{"Owner": "Alice", "app": "APP_A", "Ticket": "INC1"}])

    def test_default_input_uses_all_application_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            labels = Path(directory) / "labels.csv"
            labels.write_text(
                "key,value\napp,APP_A\nenv,PRD\napp,APP_A\napp,APP_B\n", encoding="utf-8",
            )
            rows, columns = _load_scope_input(None, labels)
        self.assertEqual(columns, ["app"])
        self.assertEqual(rows, [{"app": "APP_A"}, {"app": "APP_B"}])


if __name__ == "__main__":
    unittest.main()
