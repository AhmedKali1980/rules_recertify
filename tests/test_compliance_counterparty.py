import csv
import importlib.util
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from rules_recertify.reporting.compliance import (
    LABEL_GROUP_FIELDS, MICROCOSMOS_COLUMNS, RULE_FIELDS,
    _label_group_index, _microcosmos_kear_lookup, _rule_matches_scope,
    _rule_relationship, generate_compliance_workbook,
)


class ComplianceCounterpartyTest(unittest.TestCase):
    def setUp(self):
        self.taskit = {
            "app": "APM_IBFS_SGEF.IT.TASKIT.TAT", "Module": "SGEF.IT.TASKIT.TAT",
            "Kear Id": "1624a08f-6a17-4293-9d94-5819f41f9ecb",
            "Application Name": "SGEF Italy - TASC-IT", "Account": "TSA_A6347_PRD",
            "Environment": "PRD",
        }
        self.arcos = {
            "app": "APM_IBFS_SGEF.IT.ARCOS.AOS", "Module": "SGEF.IT.ARCOS.AOS",
            "Kear Id": "a9eda1f5-07d8-46a6-a580-cdbe7151db6a",
            "Application Name": "SGEF ITA - ARCOS", "Account": "AKA_A6332_PRD",
            "Environment": "PRD",
        }
        self.group = {
            "name": "LUIGI_SGEF.IT-LGA", "key": "app",
            "member_labels": f"app:{self.taskit['app']};app:{self.arcos['app']}",
        }
        self.groups = _label_group_index([self.group])
        self.lookup = _microcosmos_kear_lookup([self.taskit, self.arcos])
        self.rule = {
            **dict.fromkeys(RULE_FIELDS, ""),
            "ruleset_name": "APM_LUIGI_SGEF.IT_TAT-PROD-RS",
            "ruleset_scope": f"app:{self.taskit['app']};env:PRD",
            "ruleset_enabled": "TRUE", "rule_type": "allow", "rule_enabled": "TRUE",
            "unscoped_consumers": "TRUE", "src_all_workloads": "FALSE",
            "src_labels": "env:PRD", "src_label_groups": self.group["name"],
            "dst_all_workloads": "FALSE", "dst_labels": "role:MANAGEMENT",
            "services": "445 TCP;139 TCP",
            "rule_href": "/orgs/1/sec_policy/draft/rule_sets/3051/sec_rules/68804",
        }

    def test_extrascope_consumer_points_to_scoped_provider_kear(self):
        for members in (self.group["member_labels"], f"app:{self.arcos['app']}"):
            with self.subTest(members=members):
                groups = _label_group_index([{**self.group, "member_labels": members}])
                self.assertTrue(_rule_matches_scope(self.rule, self.arcos["app"], "PRD", groups))
                self.assertEqual(_rule_relationship(self.rule, self.arcos, self.lookup, groups), {
                    "kear_remote": self.taskit["Kear Id"], "direction": "outgoing",
                    "rule_category": "business_rule", "warning": "",
                })
                if members == f"app:{self.arcos['app']}":
                    self.assertEqual(_rule_relationship(self.rule, self.taskit, self.lookup, groups), {
                        "kear_remote": self.arcos["Kear Id"], "direction": "incoming",
                        "rule_category": "business_rule", "warning": "",
                    })

    def test_intrascope_consumer_group_does_not_select_application_outside_scope(self):
        rule = {**self.rule, "unscoped_consumers": "FALSE"}
        self.assertFalse(_rule_matches_scope(rule, self.arcos["app"], "PRD", self.groups))
        self.assertTrue(_rule_matches_scope(rule, self.taskit["app"], "PRD", self.groups))
        self.assertEqual(_rule_relationship(rule, self.taskit, self.lookup, self.groups), {
            "kear_remote": self.taskit["Kear Id"], "direction": "intra-app",
            "rule_category": "business_rule", "warning": "",
        })
        self.assertEqual(
            _rule_relationship(rule, self.arcos, self.lookup, self.groups)["direction"],
            "undetermined",
        )

    def test_excluded_consumer_is_not_selected_or_reported_as_outgoing(self):
        excluded_group = {"name": "EXCLUDED", "key": "app",
                          "member_labels": f"app:{self.arcos['app']}"}
        groups = _label_group_index([self.group, excluded_group])
        for field, value in (
            ("src_labels_exclusions", f"app:{self.arcos['app']}"),
            ("src_label_groups_exclusions", "EXCLUDED"),
        ):
            with self.subTest(field=field):
                rule = {**self.rule, field: value}
                self.assertFalse(_rule_matches_scope(rule, self.arcos["app"], "PRD", groups))
                self.assertEqual(
                    _rule_relationship(rule, self.arcos, self.lookup, groups)["direction"],
                    "undetermined",
                )

    def test_provider_kear_missing_or_ambiguous_is_not_guessed(self):
        for lookup, warning in (
            (None, "REMOTE_KEAR_UNAVAILABLE"),
            ({}, "REMOTE_KEAR_NOT_FOUND"),
            ({"sgef.it.taskit.tat": {"prd": {"K-ONE", "K-TWO"}}}, "REMOTE_KEAR_AMBIGUOUS"),
        ):
            with self.subTest(warning=warning):
                self.assertEqual(_rule_relationship(self.rule, self.arcos, lookup, self.groups), {
                    "kear_remote": "", "direction": "outgoing",
                    "rule_category": "business_rule", "warning": warning,
                })

    def test_equal_kears_are_intra_app_and_provider_uses_scope_environment(self):
        rule = {**self.rule, "src_labels": "env:DEV"}
        arcos = {**self.arcos, "Environment": "DEV"}
        lookup = {"sgef.it.taskit.tat": {
            "prd": {self.taskit["Kear Id"]}, "dev": {"WRONG-ENVIRONMENT"},
        }}
        result = _rule_relationship(rule, arcos, lookup, self.groups)
        self.assertEqual((result["direction"], result["kear_remote"]),
                         ("outgoing", self.taskit["Kear Id"]))
        lookup["sgef.it.taskit.tat"]["prd"] = {arcos["Kear Id"]}
        self.assertEqual(
            _rule_relationship(rule, arcos, lookup, self.groups)["direction"], "intra-app",
        )

    def test_external_destination_is_incoming_from_scope_application(self):
        rule = {**self.rule, "src_labels": "role:MANAGEMENT", "src_label_groups": "",
                "dst_labels": f"app:{self.arcos['app']};env:PRD"}
        self.assertEqual(_rule_relationship(rule, self.arcos, self.lookup, self.groups), {
            "kear_remote": self.taskit["Kear Id"], "direction": "incoming",
            "rule_category": "business_rule", "warning": "",
        })

    def test_multiple_scope_applications_do_not_pick_arbitrary_remote_kear(self):
        rule = {**self.rule, "ruleset_scope": self.rule["ruleset_scope"] + ";app:APM_IBFS_OTHER"}
        result = _rule_relationship(rule, self.arcos, self.lookup, self.groups)
        self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                         ("outgoing", "", "REMOTE_KEAR_AMBIGUOUS"))

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_microcosmos_report_keeps_taskit_and_arcos_identities_in_both_input_orders(self):
        from openpyxl import Workbook, load_workbook
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            for name, fields, rows in (
                ("rules_inventory.csv", RULE_FIELDS, [self.rule]),
                ("export_labelgroups.csv", LABEL_GROUP_FIELDS, [self.group]),
                ("labels.csv", ("key", "value"), [
                    {"key": "app", "value": row["app"]} for row in (self.taskit, self.arcos)
                ] + [{"key": "env", "value": "PRD"}]),
            ):
                with (snapshot / name).open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(rows)
            for inputs in ((self.taskit, self.arcos), (self.arcos, self.taskit)):
                with self.subTest(first=inputs[0]["Module"]):
                    source = root / "microcosmos.xlsx"
                    book = Workbook()
                    book.active.append(list(MICROCOSMOS_COLUMNS))
                    book.active.append([""] * len(MICROCOSMOS_COLUMNS))
                    for row in inputs:
                        book.active.append([row.get(column, "") for column in MICROCOSMOS_COLUMNS])
                    book.save(source)
                    book.close()
                    output = generate_compliance_workbook(root, root / "compliance.xlsx", (), source)
                    with closing(load_workbook(output, read_only=True)) as report:
                        values = list(report["Business Rules"].values)
                        rows = [dict(zip(values[0], row)) for row in values[1:]]
                        self.assertEqual(len(rows), 2)
                        by_module = {row["Module"]: row for row in rows}
                        for original in inputs:
                            actual = by_module[original["Module"]]
                            for field in ("Kear Id", "Application Name", "Account", "app"):
                                self.assertEqual(actual[field], original[field])
                            self.assertEqual(actual["rule_href"], self.rule["rule_href"])
                        arcos = by_module[self.arcos["Module"]]
                        self.assertEqual(arcos["Direction"], "outgoing")
                        self.assertEqual(arcos["Kear Remote"], self.taskit["Kear Id"])
                        self.assertEqual(arcos["ruleset_scope"], self.rule["ruleset_scope"])
                        self.assertEqual(arcos["Global Consumer in use"], "FALSE")
                        self.assertIsNone(arcos["Warning"])
