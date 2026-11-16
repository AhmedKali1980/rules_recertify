import csv
import importlib.util
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from rules_recertify.reporting.compliance import (
    KEAR_NOT_ONBOARDED, LABEL_GROUP_FIELDS, MICROCOSMOS_COLUMNS, RULE_FIELDS,
    _rule_relationship, generate_compliance_workbook,
)


class ComplianceManagedFallbackTest(unittest.TestCase):
    def setUp(self):
        self.kear = "dd14fbac-80d8-47fc-9c21-0c656fa92fca"
        self.scope_app = "APU_L3.SGRF.EUR_CG.SAFIR.CREDIT.RISK.AGENTLESS"
        self.source_app = "APM_L3.SGRF.EUR_CG.SAFIR.CREDIT.RISK.IAAS"
        self.row = {"app": self.scope_app, "Kear Id": self.kear, "Environment": "PRD"}
        self.lookup = {"cg.safir.credit.risk.agentless": {"prd": {self.kear}}}
        self.rule = {
            **dict.fromkeys(RULE_FIELDS, ""), "ruleset_name": self.scope_app + "-PRD-RS",
            "ruleset_scope": f"app:{self.scope_app};env:PRD", "rule_type": "allow",
            "unscoped_consumers": "TRUE", "rule_enabled": "TRUE",
            "src_labels": f"role:DB.OCP;app:{self.source_app};env:PRD",
            "dst_labels": "app:APA_RFG_A2389;env:PRD", "services": "10000 TCP",
            "rule_href": "/orgs/1/sec_policy/draft/rule_sets/9385/sec_rules/106271",
        }

    def test_missing_iaas_module_does_not_hide_managed_source_direction(self):
        result = _rule_relationship(self.rule, self.row, self.lookup)
        self.assertEqual(result, {
            "direction": "outgoing", "kear_remote": "", "rule_category": "business_rule",
            "warning": "DIRECTION_FROM_MANAGED_APP_LABEL; REMOTE_KEAR_NOT_FOUND",
        })

    def test_missing_managed_destination_is_incoming(self):
        rule = {**self.rule, "src_labels": self.rule["dst_labels"],
                "dst_labels": self.rule["src_labels"]}
        result = _rule_relationship(rule, self.row, self.lookup)
        self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                         ("incoming", "", "DIRECTION_FROM_MANAGED_APP_LABEL; REMOTE_KEAR_NOT_FOUND"))

    def test_registered_peer_kears_are_not_overridden_by_label_convention(self):
        for kears in ({"OTHER"}, {self.kear, "OTHER"}):
            with self.subTest(kears=kears):
                lookup = {**self.lookup, "cg.safir.credit.risk.iaas": {"prd": kears}}
                result = _rule_relationship(self.rule, self.row, lookup)
                self.assertEqual(result["direction"], "undetermined")
                self.assertNotIn("DIRECTION_FROM_MANAGED_APP_LABEL", result["warning"])
        lookup = {**self.lookup, "cg.safir.credit.risk.iaas": {"prd": {self.kear}}}
        result = _rule_relationship(self.rule, self.row, lookup)
        self.assertEqual(result["direction"], "outgoing")
        self.assertEqual(result["warning"], "REMOTE_KEAR_NOT_FOUND")

    def test_two_or_no_managed_sides_do_not_choose_arbitrary_direction(self):
        for source, destination in (
            (self.rule["src_labels"], "app:APM_REGION_OTHER;env:PRD"),
            ("app:APA_REGION_OTHER;env:PRD", self.rule["dst_labels"]),
        ):
            with self.subTest(source=source, destination=destination):
                rule = {**self.rule, "src_labels": source, "dst_labels": destination}
                self.assertEqual(_rule_relationship(rule, self.row, self.lookup)["direction"],
                                 "undetermined")

    def test_unverified_row_identity_and_managed_scope_do_not_use_fallback(self):
        for lookup in (None, {}, {"cg.safir.credit.risk.agentless": {"prd": {"OTHER"}}}):
            with self.subTest(lookup=lookup):
                result = _rule_relationship(self.rule, self.row, lookup)
                self.assertEqual(result["direction"], "undetermined")
        # The current input row already identifies its Kear: other records for
        # the same scope module must not force a choice or replace that ID.
        lookup = {"cg.safir.credit.risk.agentless": {"prd": {self.kear, "OTHER"}}}
        self.assertEqual(_rule_relationship(self.rule, self.row, lookup)["direction"], "outgoing")
        managed_scope = "APM_REGION_OWNER"
        rule = {**self.rule, "ruleset_scope": f"app:{managed_scope};env:PRD"}
        row = {**self.row, "app": managed_scope}
        self.assertEqual(_rule_relationship(rule, row, {"owner": {"prd": {self.kear}}})["direction"],
                         "undetermined")

    def test_mixed_or_multiple_managed_selectors_are_not_used_as_fallback(self):
        for field, value in (
            ("src_iplists", "Any (0.0.0.0/0)"), ("src_workloads", "host"),
            ("src_all_workloads", "TRUE"),
            ("src_labels", self.rule["src_labels"] + ";app:APM_REGION_OTHER"),
            ("src_labels", self.rule["src_labels"] + ";env:DEV"),
        ):
            with self.subTest(field=field, value=value):
                result = _rule_relationship({**self.rule, field: value}, self.row, self.lookup)
                self.assertEqual(result["direction"], "undetermined")

    def test_registered_destination_kear_precedes_label_inference(self):
        lookup = {**self.lookup, "a2389": {"prd": {self.kear}}}
        result = _rule_relationship(self.rule, self.row, lookup)
        self.assertEqual(result, {
            "direction": "incoming", "kear_remote": "", "rule_category": "business_rule",
            "warning": "REMOTE_KEAR_NOT_FOUND",
        })
        lookup["a2389"]["prd"] = {"K-DESTINATION"}
        self.assertEqual(_rule_relationship(self.rule, self.row, lookup), {
            "direction": "outgoing", "kear_remote": "K-DESTINATION", "rule_category": "business_rule",
            "warning": "DIRECTION_FROM_MANAGED_APP_LABEL",
        })

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_workbook_with_only_agentless_microcosmos_row_still_reports_outgoing(self):
        from openpyxl import Workbook, load_workbook
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            for name, fields, rows in (
                ("rules_inventory.csv", RULE_FIELDS, [self.rule]),
                ("export_labelgroups.csv", LABEL_GROUP_FIELDS, []),
                ("labels.csv", ("key", "value"), [
                    {"key": "app", "value": app} for app in (self.scope_app, self.source_app)
                ] + [{"key": "env", "value": "PRD"}]),
            ):
                with (snapshot / name).open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(rows)
            source = root / "microcosmos.xlsx"
            book = Workbook()
            book.active.append(list(MICROCOSMOS_COLUMNS))
            book.active.append([""] * len(MICROCOSMOS_COLUMNS))
            original = {**self.row, "Module": "CG.SAFIR.CREDIT.RISK.AGENTLESS",
                        "Application Name": "Safir - Credit Risk", "Account": "RFG_A2389_PRD"}
            book.active.append([original.get(field, "") for field in MICROCOSMOS_COLUMNS])
            book.save(source)
            book.close()
            target = generate_compliance_workbook(root, root / "compliance.xlsx", (), source)
            with closing(load_workbook(target, read_only=True)) as report:
                values = list(report["Business Rules"].values)
                self.assertEqual(len(values), 2)
                row = dict(zip(values[0], values[1]))
                for field in ("Kear Id", "Module", "Application Name", "Account", "app"):
                    self.assertEqual(row[field], original[field])
                self.assertEqual(row["Direction"], "outgoing")
                self.assertEqual(row["Kear Remote"], KEAR_NOT_ONBOARDED)
                self.assertEqual(row["Warning"],
                                 "DIRECTION_FROM_MANAGED_APP_LABEL; REMOTE_KEAR_NOT_FOUND")
