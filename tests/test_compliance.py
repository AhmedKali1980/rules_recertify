import importlib.util
import tempfile
import unittest
from pathlib import Path

from rules_recertify.reporting.compliance import (
    _contains_user_iplist, _extrascope_warning, _factor_side, _global_consumer_in_use,
    _has_intra_zone_iplist, _is_microcosmos_headers,
    _load_scope_input, _module_from_app, _prepare_microcosmos_input,
    _programs_for_app, _rule_matches_scope, _ruleset_scope_context,
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
            "ruleset_scope": "env:PRD; app:APP_A",
        }
        iplist = {
            "dst_all_workloads": "false", "dst_iplists": "NZ3_APP", "dst_labels": "app:A",
        }
        labels = {
            "src_all_workloads": "false", "src_iplists": "", "src_labels": "app:A;env:PRD",
        }
        self.assertEqual(
            _factor_side(all_workloads, "src"),
            ("All workloads (app:APP_A; env:PRD)", "all_workloads"),
        )
        self.assertEqual(_factor_side(iplist, "dst"), ("NZ3_APP", "iplist"))
        self.assertEqual(_factor_side(labels, "src"), ("app:A;env:PRD", "labels"))

    def test_all_workloads_scope_context_is_ordered_and_deduplicated(self):
        self.assertEqual(
            _ruleset_scope_context("env:PRD;app:APP_A;app:APP_A"),
            "app:APP_A; env:PRD",
        )
        self.assertEqual(_ruleset_scope_context(""), "")

    def test_extrascope_all_workloads_source_is_a_global_consumer_warning(self):
        warning = _extrascope_warning({
            "unscoped_consumers": "TRUE", "src_all_workloads": "TRUE",
        })
        self.assertEqual(
            warning,
            "WARNING: Global Consumer applies the rule to all managed workloads in the PCE",
        )
        self.assertTrue(_global_consumer_in_use({
            "unscoped_consumers": "TRUE", "src_all_workloads": "TRUE",
        }))
        for rule in (
            {"unscoped_consumers": "FALSE", "src_all_workloads": "TRUE"},
            {"unscoped_consumers": "TRUE", "src_all_workloads": "FALSE"},
            {"unscoped_consumers": "TRUE", "dst_all_workloads": "TRUE"},
        ):
            self.assertFalse(_global_consumer_in_use(rule))
            self.assertEqual(_extrascope_warning(rule), "")

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

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl is not installed")
    def test_microcosmos_xlsx_resolves_module_to_full_application_label(self):
        from openpyxl import Workbook
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            labels = root / "labels.csv"
            labels.write_text(
                "key,value\napp,APM_L3.GBTO.EUR_X232223\nenv,PRD\n", encoding="utf-8",
            )
            source = root / "microcosmos.xlsx"
            workbook = Workbook()
            sheet = workbook.active
            sheet.append([
                "Kear Id", "Application Name", "Module", "Account", "Account Leader",
                "Microsegmentation Solution", "Environment", "Entity", "Program", "",
            ])
            sheet.append(["", "", "", "", "", "", "", "", "", "Sub-header"])
            sheet.append([
                "K123", "Payments", "X232223", "GBTO", "Alice", "Illumio", "prd",
                "Server", "MIO_ONE", "Bob",
            ])
            workbook.save(source)

            rows, columns = _load_scope_input(source, labels)

        self.assertEqual(columns[:9], [
            "Kear Id", "Application Name", "Module", "Account", "Account Leader",
            "Microsegmentation Solution", "Environment", "Entity", "Program (MIO)",
        ])
        self.assertEqual(columns[9:], ["app"])
        self.assertEqual(rows[0]["app"], "APM_L3.GBTO.EUR_X232223")
        self.assertEqual(rows[0]["__compliance_env"], "PRD")
        self.assertEqual(rows[0]["Program (MIO)"], "MIO_ONE")

    def test_microcosmos_module_is_the_suffix_after_second_underscore(self):
        self.assertEqual(_module_from_app("APM_L3.GBTO.EUR_X232223"), "X232223")
        self.assertEqual(_module_from_app("APP_WITH_MORE_UNDERSCORES"), "MORE_UNDERSCORES")
        self.assertEqual(_module_from_app("APP_ONLY"), "")

    def test_microcosmos_preparation_ignores_unwanted_columns_and_resolves_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            labels = Path(directory) / "labels.csv"
            labels.write_text(
                "key,value\napp,APM_L3.GBTO.EUR_X232223\nenv,PRD\n", encoding="utf-8",
            )
            headers = [
                "Kear Id", "Application Name", "Module", "Account", "Account Leader",
                "Microsegmentation Solution", "Environment", "Entity", "Owner",
            ]
            rows, columns = _prepare_microcosmos_input([{
                "Kear Id": "K123", "Application Name": "Payments", "Module": "X232223",
                "Account": "GBTO", "Account Leader": "Alice",
                "Microsegmentation Solution": "Illumio", "Environment": "prd",
                "Entity": "Server", "Owner": "Bob",
            }], headers, labels)
        self.assertEqual(columns[:10], [
            "Kear Id", "Application Name", "Module", "Account", "Account Leader",
            "Microsegmentation Solution", "Environment", "Entity", "Program (MIO)", "app",
        ])
        self.assertEqual(columns[-1], "app")
        self.assertEqual(rows[0]["app"], "APM_L3.GBTO.EUR_X232223")
        self.assertEqual(rows[0]["__compliance_env"], "PRD")
        self.assertEqual(rows[0]["Program (MIO)"], "")

    def test_microcosmos_header_detection_tolerates_empty_merged_headers(self):
        self.assertTrue(_is_microcosmos_headers([
            "Kear Id", "Application Name", "Module", "Account", "Account Leader",
            "Microsegmentation Solution", "Environment", "Entity", "", "",
        ]))
        self.assertFalse(_is_microcosmos_headers(["app", "env", "Owner"]))


if __name__ == "__main__":
    unittest.main()
