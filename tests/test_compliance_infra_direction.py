import csv
import importlib.util
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

if importlib.util.find_spec("openpyxl"):
    from openpyxl import load_workbook

from rules_recertify.reporting.compliance import (
    KEAR_NOT_ONBOARDED, LABEL_GROUP_FIELDS, RULE_FIELDS, _label_group_index,
    _rule_relationship, generate_compliance_workbook,
)


class InfraAppgroupDirectionTest(unittest.TestCase):
    def setUp(self):
        self.row = {"app": "APM_REGION_LOCAL", "Kear Id": "K-LOCAL", "Environment": "PRD"}
        self.group_rows = [
            {"name": "LOCAL_APPS", "key": "app",
             "member_labels": "app:APM_REGION_LOCAL;app:APM_REGION_OTHER"},
            {"name": "LOCAL_ROLES", "key": "role", "member_labels": "role:DB"},
        ]
        self.groups = _label_group_index(self.group_rows)
        self.base = {**dict.fromkeys(RULE_FIELDS, ""), "ruleset_name": "BOUQUETS_TEST",
                     "ruleset_scope": "app:APM_REGION_LOCAL;env:PRD", "unscoped_consumers": "TRUE",
                     "rule_type": "allow", "rule_enabled": "true", "services": "SSH"}

    def test_single_explicit_appgroup_sets_direction_across_infrastructure_families(self):
        references = (("labels", "appgroup:UNKNOWN"), ("labels", "app:LOCAL_APPS"),
                      ("label_groups", "LOCAL_APPS"), ("label_groups", "appgroup:UNKNOWN"),
                      ("label_groups", "app:UNKNOWN"))
        for family in ("BOUQUETS_TEST", "GLOBAL_TEST", "LUIGI_TEST"):
            for prefix, direction in (("src", "outgoing"), ("dst", "incoming")):
                for field, reference in references:
                    for scope in ("", "env:PRD", "app:APM_REGION_LOCAL;env:PRD"):
                        with self.subTest(family=family, prefix=prefix, field=field, scope=scope):
                            remote = "dst" if prefix == "src" else "src"
                            rule = {**self.base, "ruleset_name": family, "ruleset_scope": scope,
                                    f"{prefix}_{field}": reference, f"{remote}_iplists": "EXTERNAL"}
                            result = _rule_relationship(rule, self.row, None, self.groups)
                            self.assertEqual(result["direction"], direction)
                            self.assertEqual(result["rule_category"], "infra_rule")
                            self.assertNotIn("DIRECTION_UNDETERMINED", result["warning"])
                            self.assertNotIn("LOCAL_SCOPE_UNDETERMINED", result["warning"])

    def test_opposite_peer_kear_uses_its_explicit_environment(self):
        lookup = {"remote": {"prd": {"K-PRD"}, "uat": {"K-UAT"}}}
        for prefix, direction in (("src", "outgoing"), ("dst", "incoming")):
            remote = "dst" if prefix == "src" else "src"
            rule = {**self.base, f"{prefix}_label_groups": "LOCAL_APPS",
                    f"{remote}_labels": "app:APM_REGION_REMOTE;env:UAT"}
            self.assertEqual(_rule_relationship(rule, self.row, lookup, self.groups), {
                "kear_remote": "K-UAT", "direction": direction,
                "rule_category": "infra_rule", "warning": "",
            })

    def test_convention_keeps_direction_when_remote_kear_is_missing_ambiguous_or_equal(self):
        rule = {**self.base, "src_labels": "appgroup:UNKNOWN",
                "dst_labels": "app:APM_REGION_REMOTE"}
        for lookup, expected_kear, warning in (
            (None, "", "REMOTE_KEAR_UNAVAILABLE"),
            ({}, "", "REMOTE_KEAR_NOT_FOUND"),
            ({"remote": {"prd": {"K-ONE", "K-TWO"}}}, "", "REMOTE_KEAR_AMBIGUOUS"),
            ({"remote": {"prd": {"K-LOCAL"}}}, "K-LOCAL", ""),
        ):
            with self.subTest(lookup=lookup):
                result = _rule_relationship(rule, self.row, lookup, self.groups)
                self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                                 ("outgoing", expected_kear, warning))

    def test_remote_environment_is_not_guessed_and_csv_env_is_used_without_scope(self):
        lookup = {"remote": {"prd": {"K-PRD"}, "uat": {"K-UAT"}}}
        rule = {**self.base, "src_labels": "appgroup:UNKNOWN",
                "dst_labels": "app:APM_REGION_REMOTE;env:PRD;env:UAT"}
        result = _rule_relationship(rule, self.row, lookup, self.groups)
        self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                         ("outgoing", "", "REMOTE_KEAR_AMBIGUOUS"))
        rule.update(ruleset_scope="", dst_labels="app:APM_REGION_REMOTE")
        row = {"app": self.row["app"], "Kear Id": "K-LOCAL", "env": "PRD"}
        result = _rule_relationship(rule, row, lookup, self.groups)
        self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                         ("outgoing", "K-PRD", ""))

    def test_mixed_local_selectors_keep_group_direction_and_mixed_remote_is_ambiguous(self):
        rule = {**self.base, "src_label_groups": "LOCAL_APPS", "src_iplists": "LOCAL_NET",
                "src_labels": "role:WEB", "dst_labels": "app:APM_REGION_REMOTE",
                "dst_workloads": "unresolved-host"}
        result = _rule_relationship(rule, self.row, {"remote": {"prd": {"K-REMOTE"}}}, self.groups)
        self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                         ("outgoing", "", "REMOTE_KEAR_AMBIGUOUS"))

    def test_two_appgroups_keep_existing_resolution(self):
        rule = {**self.base, "src_labels": "appgroup:UNKNOWN_SRC", "dst_labels": "appgroup:UNKNOWN_DST"}
        self.assertEqual(_rule_relationship(rule, self.row, {}, self.groups)["direction"], "undetermined")
        groups = _label_group_index([{"name": "ONE_APP", "key": "app", "member_labels": self.row["app"]}])
        rule.update(src_labels="appgroup:ONE_APP", dst_labels="appgroup:ONE_APP")
        result = _rule_relationship(rule, self.row, {}, groups)
        self.assertEqual((result["direction"], result["kear_remote"]), ("intra-app", "K-LOCAL"))

    def test_infra_outbound2apa_retains_managed_destination_warning(self):
        rule = {**self.base, "ruleset_scope": "", "ruleset_name": "GLOBAL_OUTBOUND2APA",
                "src_label_groups": "LOCAL_APPS", "dst_labels": "app:APM_REGION_REMOTE"}
        result = _rule_relationship(rule, self.row, {"remote": {"prd": {"K-REMOTE"}}}, self.groups)
        self.assertEqual(result, {
            "direction": "outgoing", "kear_remote": "K-REMOTE", "rule_category": "infra_rule",
            "warning": "OUTBOUND2APA_DESTINATION_MANAGED",
        })

    def test_business_and_strategic_rules_keep_application_based_direction(self):
        for rule_type in ("allow", "deny"):
            rule = {**self.base, "ruleset_name": "APPLICATION", "rule_type": rule_type,
                    "src_labels": "appgroup:UNKNOWN", "dst_labels": "role:DB"}
            result = _rule_relationship(rule, self.row, {}, self.groups)
            self.assertEqual(result["direction"], "incoming")
            self.assertNotEqual(result["rule_category"], "infra_rule")

    def test_scope_exclusions_and_non_application_groups_do_not_trigger_convention(self):
        rule = {**self.base, "ruleset_scope": "appgroup:UNKNOWN", "src_iplists": "EXTERNAL",
                "dst_labels": "role:DB"}
        self.assertEqual(_rule_relationship(rule, self.row, {}, self.groups)["direction"], "undetermined")
        rule = {**self.base, "src_labels": "role:WEB", "dst_iplists": "EXTERNAL",
                "dst_label_groups_exclusions": "LOCAL_APPS"}
        self.assertEqual(_rule_relationship(rule, self.row, {}, self.groups)["direction"], "outgoing")
        rule = {**self.base, "ruleset_scope": "", "src_label_groups": "LOCAL_ROLES", "dst_iplists": "EXTERNAL"}
        self.assertEqual(_rule_relationship(rule, self.row, {}, self.groups)["direction"], "undetermined")

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_infra_workbook_preserves_identity_services_and_custom_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            rules = [
                {**self.base, "rule_href": "/rules/outgoing", "src_labels": "appgroup:UNKNOWN",
                 "dst_labels": "app:APM_REGION_REMOTE"},
                {**self.base, "rule_href": "/rules/incoming", "src_labels": "app:APM_REGION_REMOTE",
                 "dst_label_groups": "LOCAL_APPS", "services": "All Services"},
            ]
            for name, fields, rows in (
                ("rules_inventory.csv", RULE_FIELDS, rules),
                ("export_labelgroups.csv", LABEL_GROUP_FIELDS, self.group_rows),
                ("export_services.csv", ("name", "service_ports"), [{"name": "SSH", "service_ports": "22 TCP"}]),
            ):
                with (snapshot / name).open("w", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(rows)
            source = root / "applications.csv"
            source.write_text("app,env,Kear Id\nAPM_REGION_LOCAL,PRD,K-LOCAL\n")
            profile = root / "headers.conf"
            profile.write_text("[Kear Id]\nvisibility=true\n[Direction]\nvisibility=true\n"
                               "[services]\nvisibility=true\n")
            output = root / "report.xlsx"
            for custom in (None, profile):
                with self.subTest(profile=custom):
                    generate_compliance_workbook(root, output, (), source, custom_headers_path=custom, debug=custom is None)
                    with closing(load_workbook(output)) as report:
                        values = list(report["Infra Rules"].values)
                        rows = [dict(zip(values[0], row)) for row in values[1:]]
                        self.assertEqual([row["Direction"] for row in rows], ["outgoing", "incoming"])
                        self.assertEqual([row["Kear Id (Scope)"] for row in rows], ["K-LOCAL", "K-LOCAL"])
                        self.assertEqual([row["services"] for row in rows], ["SSH (22 TCP)", "All Services"])
                        self.assertEqual(report["Summary"]["D10"].value, 0)
                        if custom is None:
                            for row in rows:
                                self.assertEqual(row["Kear Remote"], KEAR_NOT_ONBOARDED)
                                self.assertNotIn("DIRECTION_UNDETERMINED", row["Warning"] or "")
