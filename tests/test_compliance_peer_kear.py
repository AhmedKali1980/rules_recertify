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


class CompliancePeerKearTest(unittest.TestCase):
    def setUp(self):
        self.kear = "dd14fbac-80d8-47fc-9c21-0c656fa92fca"
        self.scope_app = "APU_L3.SGRF.EUR_CG.SAFIR.CREDIT.RISK.AGENTLESS"
        self.source_app = "APM_L3.SGRF.EUR_CG.SAFIR.CREDIT.RISK.IAAS"
        self.row = {"app": self.scope_app, "Kear Id": self.kear, "Environment": "PRD"}
        self.rule = {
            **dict.fromkeys(RULE_FIELDS, ""),
            "ruleset_name": self.scope_app + "-PRD-RS",
            "ruleset_scope": f"app:{self.scope_app};env:PRD",
            "rule_type": "allow", "rule_enabled": "TRUE", "unscoped_consumers": "TRUE",
            "src_labels": f"role:DB.OCP;app:{self.source_app};env:PRD",
            "dst_labels": "app:APA_RFG_A2389;env:PRD", "services": "10000 TCP",
            "rule_href": "/orgs/1/sec_policy/draft/rule_sets/9385/sec_rules/106271",
        }
        self.lookup = {"cg.safir.credit.risk.iaas": {"prd": {self.kear}}}

    def test_source_peer_with_row_kear_is_outgoing_even_if_app_label_differs(self):
        self.assertEqual(_rule_relationship(self.rule, self.row, self.lookup), {
            "kear_remote": "", "direction": "outgoing", "rule_category": "business_rule",
            "warning": "REMOTE_KEAR_NOT_FOUND",
        })
        lookup = {**self.lookup, "a2389": {"prd": {"K-REMOTE"}}}
        self.assertEqual(_rule_relationship(self.rule, self.row, lookup), {
            "kear_remote": "K-REMOTE", "direction": "outgoing",
            "rule_category": "business_rule", "warning": "",
        })

    def test_destination_peer_with_row_kear_is_incoming(self):
        rule = {**self.rule, "src_labels": self.rule["dst_labels"],
                "dst_labels": self.rule["src_labels"]}
        result = _rule_relationship(rule, self.row, self.lookup)
        self.assertEqual((result["direction"], result["warning"]),
                         ("incoming", "REMOTE_KEAR_NOT_FOUND"))

    def test_missing_different_or_ambiguous_peer_kear_does_not_anchor_direction(self):
        for lookup in (None, {}, {"cg.safir.credit.risk.iaas": {"prd": {"OTHER"}}},
                       {"cg.safir.credit.risk.iaas": {"prd": {self.kear, "OTHER"}}}):
            with self.subTest(lookup=lookup):
                result = _rule_relationship(self.rule, self.row, lookup)
                self.assertEqual((result["direction"], result["warning"]),
                                 ("undetermined", "DIRECTION_UNDETERMINED"))
        result = _rule_relationship(self.rule, {**self.row, "Kear Id": ""}, self.lookup)
        self.assertEqual(result["direction"], "undetermined")

    def test_peer_environment_and_mixed_selectors_do_not_create_false_local_anchor(self):
        lookup = {"cg.safir.credit.risk.iaas": {"prd": {"OTHER"}, "dev": {self.kear}}}
        self.assertEqual(_rule_relationship(self.rule, self.row, lookup)["direction"], "undetermined")
        multiple_environments = {**self.rule,
                                 "src_labels": self.rule["src_labels"] + ";env:DEV"}
        self.assertEqual(_rule_relationship(multiple_environments, self.row, self.lookup)["direction"],
                         "undetermined")
        for field, value in (("src_iplists", "Any (0.0.0.0/0)"),
                             ("src_workloads", "unresolved-host"), ("src_all_workloads", "TRUE")):
            with self.subTest(field=field):
                result = _rule_relationship({**self.rule, field: value}, self.row, self.lookup)
                self.assertEqual(result["direction"], "undetermined")

    def test_both_peers_with_same_row_kear_are_intra_app(self):
        lookup = {**self.lookup, "a2389": {"prd": {self.kear}}}
        result = _rule_relationship(self.rule, self.row, lookup)
        self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                         ("intra-app", self.kear, ""))

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_generated_report_keeps_scope_identity_and_uses_source_peer_kear(self):
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
            for app in (self.scope_app, self.source_app):
                row = {"Kear Id": self.kear, "Module": app.split("_", 2)[2],
                       "Application Name": "Safir - Credit Risk", "Environment": "PRD"}
                book.active.append([row.get(field, "") for field in MICROCOSMOS_COLUMNS])
            book.save(source)
            book.close()
            target = generate_compliance_workbook(root, root / "compliance.xlsx", (), source, debug=True)
            with closing(load_workbook(target, read_only=True)) as report:
                values = list(report["Business Rules"].values)
                rows = {row[values[0].index("illumio label app (Scope)")]: dict(zip(values[0], row)) for row in values[1:]}
                self.assertEqual(set(rows), {self.scope_app, self.source_app})
                actual = rows[self.scope_app]
                self.assertEqual(actual["Kear Id (Scope)"], self.kear)
                self.assertEqual(actual["Module (Scope)"], "CG.SAFIR.CREDIT.RISK.AGENTLESS")
                self.assertEqual(actual["Direction"], "outgoing")
                self.assertEqual(actual["Kear Remote"], KEAR_NOT_ONBOARDED)
                self.assertEqual(actual["Warning"], "REMOTE_KEAR_NOT_FOUND")
                self.assertIn(self.source_app, actual["Source"])
                self.assertIn("APA_RFG_A2389", actual["Destination"])
