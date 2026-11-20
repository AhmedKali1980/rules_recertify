import csv
import importlib.util
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from rules_recertify.reporting.compliance import (
    LABEL_GROUP_FIELDS, RULE_FIELDS, _factor_side, _label_group_index,
    _rule_relationship, generate_compliance_workbook,
)


class ComplianceEndpointTest(unittest.TestCase):
    def setUp(self):
        self.dhcp = "CSM_NET_FRA.PEPSY.ROUGE.DHCP"
        self.safir = "APM_L3.SGRF.EUR_CG.SAFIR.CREDIT.RISK"
        self.dhcp_rule = {
            **dict.fromkeys(RULE_FIELDS, ""), "ruleset_name": "INFRA.RULES_CSM_NET_DHCP",
            "ruleset_scope": f"app:{self.dhcp};env:PRD", "rule_type": "allow",
            "rule_enabled": "FALSE",
            "src_iplists": "Any (0.0.0.0/0 and ::/0)", "src_label_groups": "WORKLOADS.GCR-LGA",
            "dst_all_workloads": "TRUE", "rule_href": "/rule_sets/3204/sec_rules/52300",
        }
        self.safir_rule = {
            **dict.fromkeys(RULE_FIELDS, ""), "ruleset_name": "APU_CG.SAFIR.AGENTLESS-PRD-RS",
            "ruleset_scope": "app:APU_L3.SGRF.EUR_CG.SAFIR.CREDIT.RISK.AGENTLESS;env:PRD",
            "rule_type": "allow", "unscoped_consumers": "TRUE",
            "src_labels": f"role:DB.OCP;app:{self.safir};env:PRD",
            "dst_labels": "role:DB.OCP;app:APA_RFG_A2389;env:PRD",
            "rule_href": "/rule_sets/9385/sec_rules/91304",
        }

    def test_any_and_group_into_scoped_all_workloads_is_incoming(self):
        for members in (f"app:{self.dhcp};app:APM_REGION_REMOTE", ""):
            with self.subTest(members=members):
                groups = _label_group_index([{
                    "name": "WORKLOADS.GCR-LGA", "key": "app", "member_labels": members,
                }])
                result = _rule_relationship(self.dhcp_rule, {"app": self.dhcp, "Kear Id": "K-DHCP"},
                                            {"remote": {"prd": {"K-REMOTE"}}}, groups)
                self.assertEqual(result["direction"], "incoming")
                self.assertEqual(result["kear_remote"], "")
                self.assertNotIn("DIRECTION_UNDETERMINED", result["warning"])

    def test_explicit_endpoints_take_precedence_over_different_scope(self):
        lookup = {"a2389": {"prd": {"K-DESTINATION"}},
                  "cg.safir.credit.risk": {"prd": {"K-SAFIR"}}}
        for row, direction, remote in (
            ({"app": self.safir, "Kear Id": "K-SAFIR"}, "outgoing", "K-DESTINATION"),
            ({"app": "APA_RFG_A2389", "Kear Id": "K-DESTINATION"}, "incoming", "K-SAFIR"),
        ):
            with self.subTest(direction=direction):
                self.assertEqual(_rule_relationship(self.safir_rule, row, lookup), {
                    "kear_remote": remote, "direction": direction,
                    "rule_category": "business_rule", "warning": "",
                })
        cross_environment = {**self.safir_rule,
                             "dst_labels": "role:DB.OCP;app:APA_RFG_A2389;env:UAT"}
        lookup["a2389"]["uat"] = {"K-UAT"}
        result = _rule_relationship(cross_environment, {"app": self.safir, "Kear Id": "K-SAFIR"}, lookup)
        self.assertEqual((result["direction"], result["kear_remote"]), ("outgoing", "K-UAT"))

    def test_scope_alone_does_not_choose_between_two_unrelated_explicit_sides(self):
        scope_app = "APU_L3.SGRF.EUR_CG.SAFIR.CREDIT.RISK.AGENTLESS"
        result = _rule_relationship(self.safir_rule, {"app": scope_app, "Kear Id": "K-SCOPE"}, {})
        self.assertEqual(result["direction"], "undetermined")

    def test_explicit_workload_names_are_preserved_on_both_sides(self):
        for prefix in ("src", "dst"):
            with self.subTest(prefix=prefix):
                rule = {f"{prefix}_workloads": "host-a (/orgs/1/workloads/abc);host-b"}
                self.assertEqual(_factor_side(rule, prefix), (
                    "workload:host-a (/orgs/1/workloads/abc); workload:host-b", "workload",
                ))
                rule[f"{prefix}_labels"] = "env:PRD;role:DB"
                text, _ = _factor_side(rule, prefix)
                self.assertIn("role:DB; env:PRD", text)
                self.assertIn("workload:host-a (/orgs/1/workloads/abc)", text)
                self.assertIn("workload:host-b", text)

    def test_workload_peer_keeps_direction_without_inventing_application_kear(self):
        for remote_side, direction in (("src", "incoming"), ("dst", "outgoing")):
            with self.subTest(remote_side=remote_side):
                local_side = "dst" if remote_side == "src" else "src"
                rule = {**self.dhcp_rule, "src_iplists": "", "src_label_groups": "",
                        "dst_all_workloads": "FALSE", f"{local_side}_labels": "role:DB",
                        f"{remote_side}_workloads": "server-name"}
                result = _rule_relationship(rule, {"app": self.dhcp, "Kear Id": "K-DHCP"}, {})
                self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                                 (direction, "", "REMOTE_KEAR_UNAVAILABLE"))

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_report_keeps_workloads_in_source_destination_and_accepts_older_exports(self):
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            source = root / "input.csv"
            source.write_text(f"app,env,Kear Id\nNO_MATCH,PRD,K-MISSING\n{self.dhcp},PRD,K-DHCP\n"
                              f"{self.safir},PRD,K-SAFIR\n", encoding="utf-8")
            group = {"name": "WORKLOADS.GCR-LGA", "key": "app", "member_labels": "app:REMOTE"}
            with (snapshot / "export_labelgroups.csv").open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=LABEL_GROUP_FIELDS)
                writer.writeheader()
                writer.writerow(group)
            workload_rule = {**self.safir_rule, "ruleset_scope": f"app:{self.safir};env:PRD",
                             "dst_labels": "", "src_workloads": "source-host",
                             "dst_workloads": "destination-host", "rule_href": "/rules/workload"}
            for include_workloads in (True, False):
                with self.subTest(include_workloads=include_workloads):
                    fields = list(dict.fromkeys((*RULE_FIELDS, "src_workloads", "dst_workloads")))
                    if not include_workloads:
                        fields = [field for field in fields if field not in ("src_workloads", "dst_workloads")]
                    with (snapshot / "rules_inventory.csv").open("w", newline="") as handle:
                        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
                        writer.writeheader()
                        writer.writerows([self.dhcp_rule, self.safir_rule, workload_rule])
                    output = generate_compliance_workbook(root, root / "compliance.xlsx", (), source)
                    with closing(load_workbook(output, read_only=True)) as report:
                        values = list(report["Business Rules"].values)
                        rows = {row[values[0].index("rule_href")]: dict(zip(values[0], row)) for row in values[1:]}
                        self.assertEqual(rows[self.dhcp_rule["rule_href"]]["Direction"], "incoming")
                        self.assertEqual(rows[self.safir_rule["rule_href"]]["Direction"], "outgoing")
                        workload = rows["/rules/workload"]
                        self.assertNotIn("src_workloads", values[0])
                        self.assertNotIn("dst_workloads", values[0])
                        self.assertIn(f"role:DB.OCP; app:{self.safir}; env:PRD", workload["Source"])
                        if include_workloads:
                            self.assertIn("workload:source-host", workload["Source"])
                            self.assertEqual(workload["Destination"], "workload:destination-host")
                        else:
                            self.assertNotIn("workload:", workload["Source"])
                            self.assertIsNone(workload["Destination"])
