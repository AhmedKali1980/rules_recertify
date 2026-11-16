import csv
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import closing
from datetime import date
from pathlib import Path

from rules_recertify.reporting.compliance import (
    KEAR_NOT_ONBOARDED, RULE_FIELDS, LABEL_GROUP_FIELDS, generate_compliance_workbook,
    _contains_user_iplist, _extrascope_warning, _factor_side, _global_consumer_in_use,
    _format_ruleset_scope, _label_group_index,
    _has_intra_zone_iplist, _is_microcosmos_headers,
    _load_scope_input, _module_from_app, _prepare_microcosmos_input,
    _microcosmos_kear_lookup, _programs_for_app, _resolve_remote_kear,
    _rule_category, _rule_matches_scope, _rule_relationship, _ruleset_scope_context,
    _side_relationship,
    _partition_compliance_rows, _usage_columns, _with_rule_enrichment_columns,
    _write_compliance_sheet,
    _write_summary_sheet,
)


class ComplianceTest(unittest.TestCase):
    def test_empty_remote_kear_has_explicit_microcosmos_status(self):
        enriched = _with_rule_enrichment_columns(
            {"Kear Id": "K-LOCAL", "app": "APP"}, {"kear_remote": ""},
        )
        self.assertEqual(enriched["Kear Remote"], KEAR_NOT_ONBOARDED)

    def test_usage_columns_include_last_hit_and_dangerous_port_hits(self):
        usage = {
            "observed_windows": 3, "total_flows": 21,
            "first_observed": "2026-10-01", "last_observed": "2026-10-22",
            "last_hit": "2026-10-22T00:00:00Z", "incomplete_windows": 1,
            "ports": [
                {"protocol": "TCP", "port": 22, "flows": 7, "last_hit": "2026-10-22"},
                {"protocol": "TCP", "port": 23, "flows": 5, "last_hit": "2026-10-15"},
                {"protocol": "TCP", "port": 443, "flows": 9, "last_hit": "2026-10-22"},
            ],
        }
        columns = _usage_columns(
            usage, ("PORTS_TO_CONTROL", "PORTS_TO_ERADICATE", "PORTS_ADMIN"),
            as_of=date(2026, 11, 1),
        )
        self.assertEqual(columns["Usage Status"], "HIT")
        self.assertEqual(columns["Days Since Last Hit"], 10)
        self.assertEqual(columns["PORTS_TO_CONTROL Hit Flows"], 7)
        self.assertEqual(columns["PORTS_TO_ERADICATE Hit Flows"], 5)
        self.assertEqual(columns["PORTS_ADMIN Hit Flows"], 7)
        self.assertEqual(columns["Port Breakdown Complete"], "FALSE")
        self.assertIn("TCP/22 (7 flows)", columns["PORTS_TO_CONTROL Hit Ports"])

    def test_usage_timestamp_with_utc_z_suffix_does_not_break_days_since_last_hit(self):
        columns = _usage_columns({
            "observed_windows": 1, "total_flows": 1,
            "first_observed": "2026-10-18T00:00:00Z",
            "last_observed": "2026-10-25T00:00:00Z",
            "last_hit": "2026-10-25T00:00:00Z",
            "incomplete_windows": 0, "ports": [],
        }, ("PORTS_TO_CONTROL",), as_of=date(2026, 11, 6))
        self.assertEqual(columns["Last Hit"], "2026-10-25T00:00:00Z")
        self.assertEqual(columns["Days Since Last Hit"], 12)

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl is not installed")
    def test_professional_workbook_sheets_have_dashboard_table_and_navigation(self):
        from openpyxl import Workbook
        workbook = Workbook()
        workbook.remove(workbook.active)
        rows = [{
            "Kear Id": "K-LOCAL", "Kear Remote": KEAR_NOT_ONBOARDED,
            "Direction": "undetermined", "Rule Category": "strategic_rule",
            "Match status": "MATCHED", "Usage Status": "NO_DATA",
            "Port Breakdown Complete": "NO_DATA", "Global Consumer in use": "FALSE",
        }]
        _write_summary_sheet(workbook, rows, ("PORTS_TO_CONTROL",))
        business, infra, quality = _partition_compliance_rows(rows)
        headers = list(rows[0])
        _write_compliance_sheet(workbook, business, "Business Rules", "BusinessRules", headers)
        _write_compliance_sheet(workbook, infra, "Infra Rules", "InfraRules", headers)
        _write_compliance_sheet(workbook, quality, "Data Quality", "DataQuality", headers)
        self.assertEqual(workbook.sheetnames, [
            "Summary", "Business Rules", "Infra Rules", "Data Quality",
        ])
        self.assertEqual(workbook["Business Rules"].freeze_panes, "C2")
        self.assertFalse(workbook["Summary"].sheet_view.showGridLines)
        self.assertFalse(workbook["Business Rules"].sheet_view.showGridLines)
        self.assertIn("BusinessRules", workbook["Business Rules"].tables)
        self.assertEqual(workbook["Business Rules"]["A1"].border.left.style, "thin")
        self.assertEqual(workbook["Business Rules"]["A2"].border.right.style, "thin")
        explanations = {
            row[0]: row[3] for row in workbook["Summary"].iter_rows(
                min_row=15, max_row=24, max_col=4, values_only=True,
            )
        }
        self.assertIn("LUIGI_*", explanations["Rule Category"])
        self.assertIn("exclusion-only EXCEPT", explanations["Direction"])
        self.assertIn("OUTBOUND2APA_DESTINATION_MANAGED", explanations["OUTBOUND2APA validation"])

    def test_compliance_rows_are_partitioned_into_three_exclusive_tabs(self):
        rows = [
            {"id": "business", "Match status": "MATCHED", "Rule Category": "business_rule"},
            {"id": "strategic", "Match status": "MATCHED", "Rule Category": "strategic_rule"},
            {"id": "infra", "Match status": "MATCHED", "Rule Category": "infra_rule"},
            {"id": "missing-app", "Match status": "APP_NOT_FOUND", "Rule Category": ""},
            {"id": "no-match", "Match status": "NO_MATCH", "Rule Category": "infra_rule"},
        ]
        business, infra, quality = _partition_compliance_rows(rows)
        self.assertEqual([row["id"] for row in business], ["business", "strategic"])
        self.assertEqual([row["id"] for row in infra], ["infra"])
        self.assertEqual([row["id"] for row in quality], ["missing-app", "no-match"])

    def test_rule_description_is_part_of_compliance_inventory_contract(self):
        self.assertIn("rule_description", RULE_FIELDS)
        self.assertLess(RULE_FIELDS.index("rule_description"), RULE_FIELDS.index("rule_enabled"))
        for field in (
            "src_labels_exclusions", "src_label_groups", "src_label_groups_exclusions",
            "dst_labels_exclusions", "dst_label_groups", "dst_label_groups_exclusions",
        ):
            self.assertIn(field, RULE_FIELDS)

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
            ("All workloads (app:APP_A; env:PRD); U_USERS; app:A", "all_workloads"),
        )
        self.assertEqual(_factor_side(iplist, "dst"), ("NZ3_APP; app:A", "iplist"))
        self.assertEqual(_factor_side(labels, "src"), ("app:A; env:PRD", "labels"))

    def test_factorization_renders_verified_groups_and_all_except_selectors(self):
        groups = _label_group_index([
            {"name": "APP_BUNDLE", "key": "app", "member_labels": "app:APP_A"},
            {"name": "ROLE_BUNDLE", "key": "role", "member_labels": "role:WEB"},
        ])
        rule = {
            "src_all_workloads": "false", "src_iplists": "",
            "src_labels": "env:PRD", "src_label_groups": "APP_BUNDLE",
            "src_labels_exclusions": "role:LEGACY",
            "src_label_groups_exclusions": "ROLE_BUNDLE",
        }
        self.assertEqual(_factor_side(rule, "src", groups), (
            "EXCEPT(role:LEGACY); EXCEPT(rolegroup:ROLE_BUNDLE); appgroup:APP_BUNDLE; env:PRD",
            "labels",
        ))

    def test_both_sides_keep_all_selector_columns_and_canonical_groups(self):
        groups = _label_group_index([
            {"name": "APPS", "key": "app", "member_labels": "app:A;app:B"},
        ])
        for prefix in ("src", "dst"):
            rule = {
                "ruleset_scope": "app:A;env:PRD",
                f"{prefix}_all_workloads": "true",
                f"{prefix}_iplists": "NETWORK",
                f"{prefix}_labels": "app:APPS;role:WEB",
                f"{prefix}_label_groups": "appgroup:APPS",
                f"{prefix}_labels_exclusions": "role:OLD",
                f"{prefix}_label_groups_exclusions": "app:APPS",
            }
            display, kind = _factor_side(rule, prefix, groups)
            self.assertIn("NETWORK", display)
            self.assertLess(display.index("role:WEB"), display.index("appgroup:APPS"))
            self.assertIn("EXCEPT(role:OLD)", display)
            self.assertIn("EXCEPT(appgroup:APPS)", display)
            self.assertNotIn("app:APPS", display)
            self.assertEqual(kind, "all_workloads")

    def test_exclusions_only_sides_remain_local_to_scope(self):
        for prefix in ("src", "dst"):
            rule = {"ruleset_scope": "app:A;env:PRD",
                    "src_labels_exclusions": "role:OLD",
                    "dst_label_groups_exclusions": "RETIRED"}
            self.assertTrue(_factor_side(rule, prefix)[0])
            result = _rule_relationship(rule, {"app": "A", "Kear Id": "K-A"}, None)
            self.assertEqual(result["direction"], "intra-app")

    def test_iplist_with_exclusions_has_ambiguous_relationship_on_either_side(self):
        for prefix in ("src", "dst"):
            for field in ("labels_exclusions", "label_groups_exclusions"):
                for value in ("", " ;\n ", "role:OLD"):
                    with self.subTest(prefix=prefix, field=field, value=value):
                        rule = {f"{prefix}_iplists": "EXT_NET", f"{prefix}_{field}": value}
                        expected = "ambiguous" if value == "role:OLD" else "iplist"
                        self.assertEqual(
                            _side_relationship(rule, prefix, "A"), (expected, set()),
                        )

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_deployed_compliance_cli_generates_microcosmos_workbook_with_exclusions(self):
        from openpyxl import Workbook, load_workbook
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "raw" / "snapshot"
            snapshot.mkdir(parents=True)
            base = dict.fromkeys(RULE_FIELDS, "")
            base.update(ruleset_name="APP", ruleset_scope="app:APM_REGION_LOCAL;env:PRD",
                        rule_type="allow", rule_enabled="true", services="443 TCP")
            rules = [
                dict(base, rule_href="/rules/remote", src_labels="app:APM_REGION_LOCAL",
                     dst_labels="app:APM_REGION_REMOTE;env:PRD"),
                dict(base, rule_href="/rules/labels", src_labels="role:WEB",
                     src_labels_exclusions="role:OLD", dst_labels="role:DB",
                     dst_labels_exclusions="role:OLD"),
                dict(base, rule_href="/rules/groups", src_label_groups_exclusions="OLD_ROLES",
                     dst_all_workloads="true"),
                dict(base, rule_href="/rules/ambiguous", src_iplists="EXT_NET",
                     src_labels_exclusions="role:OLD", dst_labels="role:DB"),
            ]
            for name, fields, rows in (
                ("rules_inventory.csv", RULE_FIELDS, rules),
                ("export_labelgroups.csv", LABEL_GROUP_FIELDS, [
                    {"name": "OLD_ROLES", "key": "role", "member_labels": "role:OLD"},
                ]),
                ("labels.csv", ("key", "value"), [
                    {"key": "app", "value": "APM_REGION_LOCAL"},
                    {"key": "app", "value": "APM_REGION_REMOTE"},
                    {"key": "env", "value": "PRD"},
                ]),
            ):
                with (snapshot / name).open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(rows)
            source = root / "microcosmos.xlsx"
            book = Workbook()
            sheet = book.active
            sheet.append(["Kear Id", "Application Name", "Module", "Account", "Account Leader",
                          "Microsegmentation Solution", "Environment", "Entity", "Program"])
            sheet.append([""] * 9)
            for module in ("LOCAL", "REMOTE"):
                sheet.append([f"K-{module}", module, module, "Account", "Owner",
                              "Illumio", "PRD", "Server", "MIO"])
            book.save(source)
            book.close()
            config = root / "config.json"
            config.write_text(json.dumps({
                "pce": "offline-test", "raw_dir": str(root / "raw"),
                "state_db": str(root / "state.sqlite"), "log_dir": str(root / "logs"),
                "output_dir": str(root), "smtp_enabled": False,
            }), encoding="utf-8")
            env_file = root / ".env"
            env_file.touch(mode=0o600)
            environment = dict(os.environ)
            for name in ("PCE", "STATE_DB", "WORKLOADER_DIR", "WORKLOADER_CONFIG_FILE"):
                environment.pop(name, None)
            target = root / "deployment"
            environment.update({
                "RULES_RECERTIFY_HOME": str(target),
                "RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME": "1",
            })
            installed = subprocess.run([
                "bash", str(Path("scripts/install-prod.sh").resolve()),
            ], cwd=root, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            launcher = target / "scripts" / "rules-recertify"
            output = root / "compliance.xlsx"
            result = subprocess.run([
                str(launcher), "--config", str(config), "--env-file", str(env_file),
                "compliance-report", "--input", str(source), "--out", str(output),
            ], cwd=root, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(str(output), result.stdout)
            with closing(load_workbook(output, read_only=True)) as report:
                self.assertEqual(report.sheetnames, [
                    "Summary", "Business Rules", "Infra Rules", "Data Quality",
                ])
                values = list(report["Business Rules"].values)
                rows = [dict(zip(values[0], row)) for row in values[1:]]
                local = {row["rule_href"]: row for row in rows if row["Kear Id"] == "K-LOCAL"}
                self.assertEqual(set(local), {rule["rule_href"] for rule in rules})
                self.assertEqual(local["/rules/remote"]["Kear Remote"], "K-REMOTE")
                self.assertEqual(local["/rules/remote"]["Direction"], "outgoing")
                for name in ("labels", "groups"):
                    self.assertEqual(local[f"/rules/{name}"]["Direction"], "intra-app")
                    self.assertEqual(local[f"/rules/{name}"]["Kear Remote"], "K-LOCAL")
                self.assertIn("EXCEPT(role:OLD)", local["/rules/labels"]["Source"])
                self.assertIn("EXCEPT(rolegroup:OLD_ROLES)", local["/rules/groups"]["Source"])
                self.assertEqual(local["/rules/ambiguous"]["Direction"], "undetermined")
                self.assertIn("DIRECTION_UNDETERMINED", local["/rules/ambiguous"]["Warning"])

    def test_group_name_is_not_treated_as_a_remote_application(self):
        groups = _label_group_index([
            {"name": "APPS", "key": "app", "member_labels": "app:A;app:B"},
        ])
        rule = {"ruleset_scope": "app:A;env:PRD",
                "src_labels": "app:APPS", "src_labels_exclusions": "app:B",
                "dst_labels": "app:A"}
        self.assertEqual(_rule_relationship(
            rule, {"app": "A", "Kear Id": "K-A"}, None, groups,
        )["direction"], "intra-app")
        self.assertFalse(_rule_matches_scope(rule, "APPS", "PRD", groups))

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_generated_workbook_preserves_both_sides_and_exclusions(self):
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            rule = dict.fromkeys(RULE_FIELDS, "")
            rule.update(ruleset_name="APP", ruleset_scope="app:A;env:PRD",
                        rule_type="allow", rule_href="/rules/1",
                        src_labels="role:WEB", src_labels_exclusions="role:OLD",
                        src_label_groups="APPS", src_label_groups_exclusions="OLD_APPS",
                        dst_labels="env:PRD", dst_labels_exclusions="role:RETIRED",
                        dst_label_groups="APPS", dst_label_groups_exclusions="OLD_APPS",
                        services="TCP/443")
            for name, fields, rows in (
                ("rules_inventory.csv", RULE_FIELDS, [rule]),
                ("export_labelgroups.csv", LABEL_GROUP_FIELDS, [
                    {"name": "APPS", "key": "app", "member_labels": "app:A"},
                    {"name": "OLD_APPS", "key": "app", "member_labels": "app:B"},
                ]),
                ("labels.csv", ("key", "value"), [{"key": "app", "value": "A"}]),
            ):
                with (snapshot / name).open("w", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(rows)
            output = generate_compliance_workbook(root, root / "compliance.xlsx", ())
            book = load_workbook(output)
            sheet = book["Business Rules"]
            values = dict(zip(next(sheet.values), list(sheet.values)[1]))
            for side in ("Source", "Destination"):
                self.assertIn("appgroup:APPS", values[side])
                self.assertIn("EXCEPT(appgroup:OLD_APPS)", values[side])
                self.assertNotIn("app:APPS", values[side])
            self.assertIn("EXCEPT(role:OLD)", values["Source"])
            self.assertIn("EXCEPT(role:RETIRED)", values["Destination"])
            book.close()

    def test_scope_label_group_is_rendered_and_matches_expanded_members(self):
        groups = _label_group_index([{
            "name": "PAYMENTS_APPS", "key": "app",
            "member_labels": "PAYMENTS;app:PAYMENTS_BATCH",
            "fully_expanded_members": "PAYMENTS;PAYMENTS_BATCH",
        }])
        rule = {
            "ruleset_scope": "app:PAYMENTS_APPS;env:PRD",
            "src_labels": "role:WEB", "src_label_groups": "",
            "dst_labels": "", "dst_label_groups": "",
        }
        self.assertEqual(
            _format_ruleset_scope(rule["ruleset_scope"], groups),
            "appgroup:PAYMENTS_APPS; env:PRD",
        )
        self.assertTrue(_rule_matches_scope(rule, "PAYMENTS", "PRD", groups))
        self.assertFalse(_rule_matches_scope(rule, "OTHER", "PRD", groups))
        canonical = dict(rule, ruleset_scope="appgroup:PAYMENTS_APPS;env:PRD")
        self.assertTrue(_rule_matches_scope(canonical, "PAYMENTS_BATCH", "PRD", groups))

    def test_appgroup_scope_all_workloads_is_remote_from_explicit_matched_source(self):
        groups = _label_group_index([{
            "name": "LUIGI_SGEF.PL-LGA", "key": "app",
            "member_labels": "app:LUIGI_APP",
            "fully_expanded_members": "app:LUIGI_APP;app:CSM_BCK_FRA.TSM.RBDF",
        }])
        rule = {
            "ruleset_name": "LUIGI_INFRA_SGEF.PL-IN-RS", "rule_type": "allow",
            "ruleset_scope": "appgroup:LUIGI_SGEF.PL-LGA",
            "src_all_workloads": "false", "src_iplists": "",
            "src_labels": (
                "env:PRD;app:CSM_BCK_FRA.TSM.RBDF "
                "(/orgs/1/sec_policy/draft/labels/42)"
            ),
            "src_label_groups": "", "dst_all_workloads": "true",
            "dst_iplists": "", "dst_labels": "", "dst_label_groups": "",
        }
        self.assertTrue(_rule_matches_scope(
            rule, "CSM_BCK_FRA.TSM.RBDF", "PRD", groups,
        ))
        self.assertEqual(
            _factor_side(rule, "dst", groups),
            ("All workloads (appgroup:LUIGI_SGEF.PL-LGA)", "all_workloads"),
        )
        self.assertEqual(_rule_relationship(
            rule,
            {"app": "CSM_BCK_FRA.TSM.RBDF", "Kear Id": "K-CSM"},
            {}, groups,
        ), {
            "kear_remote": "", "direction": "outgoing",
            "rule_category": "infra_rule", "warning": "",
        })

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

    def test_remote_kear_prefers_environment_then_unique_cross_environment_kear(self):
        rows = [
            {"Module": "CG.MUREX.IAAS", "Environment": "PRD", "Kear Id": "K-ONE"},
            {"Module": "CG.MUREX.IAAS", "Environment": "DEV", "Kear Id": "K-ONE"},
            {"Module": "SHARED", "Environment": "PRD", "Kear Id": "K-PRD"},
            {"Module": "SHARED", "Environment": "DEV", "Kear Id": "K-DEV"},
        ]
        lookup = _microcosmos_kear_lookup(rows)
        self.assertEqual(
            _resolve_remote_kear("APM_L3.GBTO.EUR_CG.MUREX.IAAS", "DEV", lookup),
            ("K-ONE", ""),
        )
        self.assertEqual(
            _resolve_remote_kear("APM_L3.GBTO.EUR_CG.MUREX.IAAS", "UAT", lookup),
            ("K-ONE", ""),
        )
        self.assertEqual(
            _resolve_remote_kear("APM_L3.GBTO.EUR_SHARED", "UAT", lookup),
            ("", "REMOTE_KEAR_AMBIGUOUS"),
        )

    def test_relationship_detects_incoming_remote_app_and_same_kear_intra_app(self):
        rule = {
            "ruleset_name": "APP_RULESET", "rule_type": "allow",
            "ruleset_scope": "app:APM_L3.GBTO.EUR_CG.MUREX;env:DEV",
            "src_all_workloads": "false", "src_iplists": "",
            "src_labels": "role:DB.OCP;app:APM_L3.GBTO.EUR_CG.MUREX.IAAS;env:DEV",
            "dst_all_workloads": "false", "dst_iplists": "", "dst_labels": "role:DB.OCP",
        }
        input_row = {"Kear Id": "K-LOCAL"}
        remote = {"cg.murex.iaas": {"dev": {"K-REMOTE"}}}
        self.assertEqual(_rule_relationship(rule, input_row, remote), {
            "kear_remote": "K-REMOTE", "direction": "incoming",
            "rule_category": "business_rule", "warning": "",
        })
        same_kear = {"cg.murex.iaas": {"dev": {"K-LOCAL"}}}
        self.assertEqual(_rule_relationship(rule, input_row, same_kear)["direction"], "intra-app")

    def test_relationship_handles_local_roles_all_workloads_iplists_and_ambiguity(self):
        base = {
            "ruleset_name": "APP_RULESET", "rule_type": "allow",
            "ruleset_scope": "app:APM_L3.GBTO.EUR_LOCAL;env:PRD",
            "src_all_workloads": "false", "src_iplists": "", "src_labels": "role:WEB",
            "dst_all_workloads": "false", "dst_iplists": "", "dst_labels": "role:DB",
        }
        local = _rule_relationship(base, {"Kear Id": "K-LOCAL"}, {})
        self.assertEqual((local["kear_remote"], local["direction"]), ("K-LOCAL", "intra-app"))

        exclusions_only = dict(
            base, src_labels="", dst_labels="",
            src_labels_exclusions="role:FRONTEND",
            dst_labels_exclusions="role:FRONTEND",
        )
        exclusions_result = _rule_relationship(
            exclusions_only, {"Kear Id": "K-LOCAL"}, {},
        )
        self.assertEqual(
            (exclusions_result["kear_remote"], exclusions_result["direction"]),
            ("K-LOCAL", "intra-app"),
        )
        self.assertEqual(
            _factor_side(exclusions_only, "src"),
            ("EXCEPT(role:FRONTEND)", "labels"),
        )

        incoming = dict(base, src_labels="", src_iplists="EXT_NET")
        self.assertEqual(_rule_relationship(incoming, {"Kear Id": "K-LOCAL"}, {})["direction"], "incoming")
        outgoing = dict(base, dst_labels="", dst_all_workloads="true", src_iplists="")
        self.assertEqual(_rule_relationship(outgoing, {"Kear Id": "K-LOCAL"}, {})["direction"], "intra-app")
        outgoing = dict(base, dst_labels="", dst_iplists="EXT_NET")
        self.assertEqual(_rule_relationship(outgoing, {"Kear Id": "K-LOCAL"}, {})["direction"], "outgoing")
        ambiguous = dict(base, src_labels="", src_iplists="EXT_A", dst_labels="", dst_iplists="EXT_B")
        result = _rule_relationship(ambiguous, {"Kear Id": "K-LOCAL"}, {})
        self.assertEqual(result["direction"], "undetermined")
        self.assertEqual(result["warning"], "DIRECTION_UNDETERMINED")

    def test_rule_category_precedence(self):
        self.assertEqual(_rule_category({
            "ruleset_name": "GLOBAL_BASE", "rule_type": "deny",
            "src_iplists": "ZNOT_ADMIN", "dst_iplists": "",
        }), "infra_rule")
        self.assertEqual(_rule_category({
            "ruleset_name": "luigi_application_rules", "rule_type": "allow",
            "src_iplists": "", "dst_iplists": "",
        }), "infra_rule")
        self.assertEqual(_rule_category({
            "ruleset_name": "APP_RULESET", "rule_type": "deny",
            "src_iplists": "", "dst_iplists": "",
        }), "strategic_rule")
        self.assertEqual(_rule_category({
            "ruleset_name": "APP_RULESET", "rule_type": "allow",
            "src_iplists": "", "dst_iplists": "ZNOT_REMOTE",
        }), "strategic_rule")
        self.assertEqual(_rule_category({
            "ruleset_name": "APP_RULESET", "rule_type": "allow",
            "src_iplists": "NOT_ZNOT_REMOTE", "dst_iplists": "",
        }), "business_rule")
        for marker in ("[+srule]", "[+drule]"):
            self.assertEqual(_rule_category({
                "ruleset_name": "APP_RULESET", "rule_type": "allow",
                "rule_description": f"{marker} governed exception",
                "src_iplists": "", "dst_iplists": "",
            }), "strategic_rule")
        self.assertEqual(_rule_category({
            "ruleset_name": "APP_RULESET", "rule_type": "allow",
            "rule_description": "ordinary text [+srule] later",
            "src_iplists": "", "dst_iplists": "",
        }), "business_rule")

    def test_unscoped_outbound2apa_rule_is_outgoing_from_matched_source_app(self):
        rule = {
            "ruleset_name": "TACTICAL_OUTBOUND2APA_UNMANAGED", "rule_type": "allow",
            "ruleset_scope": "", "src_all_workloads": "false",
            "src_iplists": "", "src_labels": "app:LOCAL_APP;env:PRD;role:WEB",
            "dst_all_workloads": "false", "dst_iplists": "UNMANAGED_REMOTE",
            "dst_labels": "",
        }
        result = _rule_relationship(
            rule, {"app": "LOCAL_APP", "Kear Id": "K-LOCAL"}, {},
        )
        self.assertEqual(result, {
            "kear_remote": "", "direction": "outgoing",
            "rule_category": "business_rule", "warning": "",
        })

        unrelated = _rule_relationship(
            rule, {"app": "OTHER_APP", "Kear Id": "K-OTHER"}, {},
        )
        self.assertEqual(unrelated["direction"], "undetermined")

    def test_outbound2apa_managed_destination_has_its_own_incoming_perspective(self):
        rule = {
            "ruleset_name": "APM_GBTO_CG.NG.OIB-OUTBOUND2APA-PROD-RS",
            "rule_type": "allow", "ruleset_scope": "",
            "src_all_workloads": "false", "src_iplists": "",
            "src_labels": "role:BATCH;app:APM_GBTO_CG.NG.OIB;env:PRD",
            "src_label_groups": "", "dst_all_workloads": "false",
            "dst_iplists": "", "dst_labels": "app:APM_GCR_PTF;env:PRD",
            "dst_label_groups": "",
        }
        source = {
            "app": "APM_GBTO_CG.NG.OIB", "Kear Id": "K-SOURCE",
            "Environment": "PRD", "__compliance_env": "PRD",
        }
        destination = {
            "app": "APM_GCR_PTF", "Kear Id": "K-DESTINATION",
            "Environment": "PRD", "__compliance_env": "PRD",
        }
        lookup = _microcosmos_kear_lookup([
            {**source, "Module": "CG.NG.OIB"},
            {**destination, "Module": "PTF"},
        ])

        result = _rule_relationship(rule, source, lookup)
        self.assertEqual(result, {
            "kear_remote": "K-DESTINATION", "direction": "outgoing",
            "rule_category": "business_rule",
            "warning": "OUTBOUND2APA_DESTINATION_MANAGED",
        })
        self.assertEqual(_rule_relationship(rule, destination, lookup), {
            "kear_remote": "K-SOURCE", "direction": "incoming",
            "rule_category": "business_rule",
            "warning": "OUTBOUND2APA_DESTINATION_MANAGED",
        })


if __name__ == "__main__":
    unittest.main()
