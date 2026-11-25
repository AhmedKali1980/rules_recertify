import csv
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

if importlib.util.find_spec("openpyxl"):
    from openpyxl import load_workbook

from rules_recertify.reporting.app_server_scope import (
    IMPACTED_APP_SERVERS, RoleSelection, load_app_server_scope_index,
)
from rules_recertify.reporting.compliance import (
    LABEL_GROUP_FIELDS, RULE_FIELDS, _impacted_app_server_count,
    _label_group_index, generate_compliance_workbook,
)


class AppServerScopeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir()
        self.workloads = self.snapshot / "export_wklds.csv"
        rows = [
            ("A", "PRD", "WEB", "true"), ("A", "PRD", "OLD", "TRUE"),
            ("A", "PRD", "DB", "true"), ("A", "PRD", "DB", "true"),
            ("A", "PRD", "OLD", "true"), ("A", "PRD", "", "true"),
            ("A", "PRD", "WEB", "false"), ("A", "PRD", "WEB", ""),
            ("A", "UAT", "WEB", "true"), ("AX", "PRD", "WEB", "true"),
            ("B", "PRD", "DB", "true"),
        ]
        self.write_csv(self.workloads, ("app", "env", "role", "managed"), [
            dict(zip(("app", "env", "role", "managed"), row)) for row in rows
        ])
        self.index = load_app_server_scope_index(self.snapshot)
        self.group_rows = [
            {"name": "ROLES", "key": "role", "member_labels": "role:WEB (/orgs/1/labels/10)",
             "fully_expanded_members": "role:WEB;role:DB"},
            {"name": "OLD_ROLES", "key": "role", "member_labels": "role:OLD"},
            {"name": "EMPTY_ROLES", "key": "role"},
            {"name": "PARTIAL_ROLES", "key": "role", "member_labels": "role:WEB",
             "member_label_groups": "UNKNOWN_CHILD"},
            {"name": "NESTED_ROLES", "key": "role", "member_labels": "role:OLD",
             "member_label_groups": "ROLES"},
            {"name": "CYCLIC_ROLES", "key": "role", "member_label_groups": "CYCLIC_ROLES"},
            {"name": "APPS", "key": "app", "member_labels": "app:A;app:B"},
        ]
        self.groups = _label_group_index(self.group_rows)
        self.rule = {**dict.fromkeys(RULE_FIELDS, ""), "ruleset_name": "APPLICATION",
                     "ruleset_scope": "app:A;env:PRD", "src_labels": "role:WEB", "dst_labels": "role:DB",
                     "rule_type": "allow", "rule_enabled": "true", "services": "22 TCP"}

    def write_csv(self, path, fields, rows):
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def count(self, direction, category="business_rule", **changes):
        return _impacted_app_server_count({**self.rule, **changes},
                                          {"direction": direction, "rule_category": category}, self.index, self.groups)

    def test_direction_selects_local_roles_and_intra_app_uses_union(self):
        self.assertEqual(self.count("incoming"), 2)
        self.assertEqual(self.count("outgoing"), 1)
        self.assertEqual(self.count("intra-app"), 3)
        self.assertEqual(self.count("intra-app", dst_labels="role:WEB"), 1)
        self.assertEqual(self.count("outgoing", src_labels="role:WEB;role:DB"), 3)
        self.assertEqual(self.count("incoming", dst_labels="role:MISSING"), 0)
        # The metric uses scope A/PRD, not another app/env on the peer.
        self.assertEqual(self.count("outgoing", src_labels="role:WEB;app:B;env:UAT"), 1)

    def test_all_workloads_and_absent_roles_cover_the_managed_scope(self):
        for direction, prefix in (("incoming", "dst"), ("outgoing", "src")):
            with self.subTest(direction=direction):
                self.assertEqual(self.count(direction, **{f"{prefix}_labels": "app:A"}), 6)
                self.assertEqual(self.count(direction, **{f"{prefix}_all_workloads": "true"}), 6)
        self.assertEqual(self.count("intra-app", src_all_workloads="true"), 6)
        self.assertEqual(self.count("intra-app", dst_all_workloads="true"), 6)
        self.assertEqual(self.count("intra-app", src_labels=""), 6)
        self.assertEqual(self.count("intra-app", src_labels="rolegroup:UNKNOWN", dst_all_workloads="true"), 6)

    def test_role_exclusions_apply_per_side_before_union(self):
        self.assertEqual(self.count("outgoing", src_labels="role:WEB;role:DB", src_labels_exclusions="role:DB"), 1)
        self.assertEqual(self.count("incoming", dst_labels="", dst_labels_exclusions="role:OLD"), 4)
        self.assertEqual(self.count("incoming", dst_labels_exclusions="role:DB"), 0)
        self.assertEqual(self.count("intra-app", src_labels_exclusions="role:WEB", dst_labels="role:WEB"), 1)
        self.assertEqual(self.count("intra-app", src_all_workloads="true", src_labels_exclusions="role:OLD"), 4)
        self.assertEqual(self.count("intra-app", src_all_workloads="true", src_labels_exclusions="role:OLD",
                                    dst_labels="role:OLD"), 6)

    def test_verified_groups_are_resolved_and_unresolved_groups_are_not_wildcards(self):
        self.assertEqual(self.count("incoming", dst_labels="rolegroup:ROLES"), 3)
        self.assertEqual(self.count("incoming", dst_labels="", dst_label_groups="ROLES"), 3)
        self.assertEqual(self.count("incoming", dst_labels="", dst_label_groups_exclusions="OLD_ROLES"), 4)
        self.assertEqual(self.count("incoming", dst_labels="rolegroup:EMPTY_ROLES"), 0)
        self.assertEqual(self.count("incoming", dst_labels="rolegroup:NESTED_ROLES"), 5)
        self.assertEqual(self.count("incoming", ruleset_scope="appgroup:APPS;env:PRD"), 3)
        for reference in ("rolegroup:UNKNOWN", "rolegroup:PARTIAL_ROLES", "rolegroup:CYCLIC_ROLES"):
            self.assertIsNone(self.count("incoming", dst_labels=reference))
        self.assertIsNone(self.count("incoming", dst_labels="", dst_label_groups="UNKNOWN_GROUP"))
        self.assertIsNone(self.count("incoming", dst_label_groups_exclusions="role:UNKNOWN"))

    def test_unavailable_scope_direction_and_infra_are_blank_while_no_matches_are_zero(self):
        self.assertIsNone(self.count("undetermined"))
        self.assertIsNone(self.count("incoming", category="infra_rule"))
        self.assertEqual(self.count("incoming", category="strategic_rule"), 2)
        for scope in ("", "app:A", "env:PRD", "appgroup:UNKNOWN;env:PRD", "app:A;env:null"):
            self.assertIsNone(self.count("incoming", ruleset_scope=scope))
        self.assertEqual(self.count("incoming", ruleset_scope="app:Z;env:PRD"), 0)
        self.assertEqual(self.count("incoming", ruleset_scope="app:A;env:DEV"), 0)

    def test_reference_alias_priority_normalization_and_unavailable_inputs(self):
        singular = self.snapshot / "export_wkld.csv"
        self.write_csv(singular, ("app", "env", "role", "managed"), [])
        self.assertEqual(load_app_server_scope_index(self.snapshot).count({"a"}, {"prd"}, [RoleSelection()]), 6)
        self.workloads.unlink()
        self.assertEqual(load_app_server_scope_index(self.snapshot).count({"a"}, {"prd"}, [RoleSelection()]), 0)
        self.write_csv(singular, ("app", "env", "role", "managed"), [{
            "app": "app:A (/orgs/1/labels/1)", "env": "env:PrD", "role": "role:WeB", "managed": "true",
        }])
        index = load_app_server_scope_index(self.snapshot)
        self.assertEqual(index.count({"a"}, {"prd"}, [RoleSelection(frozenset({"web"}))]), 1)
        self.write_csv(self.workloads, ("app", "env", "managed"), [])
        self.assertIsNone(load_app_server_scope_index(self.snapshot))
        self.workloads.write_text("app,env,role,managed\nA,PRD,WEB,true\nA,PRD,DB,invalid\n")
        self.assertIsNone(load_app_server_scope_index(self.snapshot))
        with patch("rules_recertify.reporting.app_server_scope.read_rows", side_effect=PermissionError("unreadable")):
            self.assertIsNone(load_app_server_scope_index(self.snapshot))
        with patch("rules_recertify.reporting.app_server_scope.read_rows", side_effect=csv.Error("malformed CSV")):
            self.assertIsNone(load_app_server_scope_index(self.snapshot))
        self.workloads.unlink()
        singular.unlink()
        self.assertIsNone(load_app_server_scope_index(self.snapshot))

    def prepare_report(self):
        base = self.rule
        rules = [
            dict(base, rule_href="outgoing", dst_labels="", dst_iplists="EXTERNAL"),
            dict(base, rule_href="incoming", src_labels="", src_iplists="EXTERNAL"),
            dict(base, rule_href="intra"),
            dict(base, rule_href="all", src_all_workloads="true"),
            dict(base, rule_href="no-role", src_labels="app:A", dst_labels="", dst_iplists="EXTERNAL"),
            dict(base, rule_href="excluded", src_labels="role:WEB;role:DB", src_labels_exclusions="role:DB",
                 dst_labels="", dst_iplists="EXTERNAL"),
            dict(base, rule_href="zero", src_labels="", src_iplists="EXTERNAL", dst_labels="role:MISSING"),
            dict(base, rule_href="strategic", rule_type="deny", dst_labels="", dst_iplists="EXTERNAL"),
            dict(base, rule_href="unknown", src_labels="app:B", dst_labels="app:C"),
            dict(base, rule_href="infra", ruleset_name="GLOBAL_TEST", dst_labels="", dst_iplists="EXTERNAL"),
        ]
        self.write_csv(self.snapshot / "rules_inventory.csv", RULE_FIELDS, rules)
        self.write_csv(self.snapshot / "export_labelgroups.csv", LABEL_GROUP_FIELDS, self.group_rows)
        self.write_csv(self.snapshot / "export_services.csv", ("name", "service_ports"), [])
        source = self.root / "apps.csv"
        source.write_text("app,env,Kear Id,Entity\nA,PRD,K-A,E1\nNO_MATCH,PRD,K-MISSING,E1\n")
        return source

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_standard_custom_hidden_and_split_outputs_keep_numeric_counts(self):
        source = self.prepare_report()
        output = self.root / "standard.xlsx"
        generate_compliance_workbook(self.root, output, (), source)
        expected = {"outgoing": 1, "incoming": 2, "intra": 3, "all": 6, "no-role": 6,
                    "excluded": 1, "zero": 0, "strategic": 1, "unknown": None}
        with closing(load_workbook(output)) as report:
            values = list(report["Business Rules"].values)
            rows = {row[values[0].index("rule_href")]: dict(zip(values[0], row)) for row in values[1:]}
            self.assertEqual({name: row[IMPACTED_APP_SERVERS] for name, row in rows.items()}, expected)
            self.assertIsInstance(rows["zero"][IMPACTED_APP_SERVERS], int)
            for name in ("Infra Rules", "Data Quality"):
                values = list(report[name].values)
                self.assertTrue(all(row[values[0].index(IMPACTED_APP_SERVERS)] is None for row in values[1:]))
        profile = self.root / "headers.conf"
        profile.write_text(f"[{IMPACTED_APP_SERVERS}]\nvisibility=true\n[rule_href]\nvisibility=true\n")
        generate_compliance_workbook(self.root, output, (), source, custom_headers_path=profile)
        with closing(load_workbook(output)) as report:
            values = list(report["Business Rules"].values)
            self.assertEqual(values[0], ("rule_href", IMPACTED_APP_SERVERS))
            self.assertEqual(dict(values[1:]), expected)
            audit = list(report["Report Configuration"].values)
            self.assertTrue(next(dict(zip(audit[0], row))["Displayed"]
                                 for row in audit[1:] if row[0] == "Column" and row[1] == IMPACTED_APP_SERVERS))
        archive_path = self.root / "split.zip"
        generate_compliance_workbook(self.root, archive_path, (), source, custom_headers_path=profile,
                                     split_by_kear_id=True, timestamp="20261125T120000Z")
        with ZipFile(archive_path) as archive:
            data = archive.read("E1/compliance_K-A_20261125T120000Z.xlsx")
            with closing(load_workbook(io.BytesIO(data))) as report:
                self.assertEqual(dict(list(report["Business Rules"].values)[1:]), expected)
        profile.write_text(f"[{IMPACTED_APP_SERVERS}]\nvisibility=false\n[rule_href]\nvisibility=true\n")
        generate_compliance_workbook(self.root, output, (), source, custom_headers_path=profile)
        with closing(load_workbook(output)) as report:
            self.assertNotIn(IMPACTED_APP_SERVERS, next(report["Business Rules"].values))

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_missing_reference_leaves_counts_blank_and_installed_cli_loads_the_feature(self):
        source = self.prepare_report()
        target = self.root / "deployment"
        environment = dict(os.environ)
        environment.pop("RULES_RECERTIFY_SHARED_GROUP", None)
        for name in ("STATE_DB", "PCE", "WORKLOADER_DIR", "WORKLOADER_CONFIG_FILE"):
            environment.pop(name, None)
        environment.update({"RULES_RECERTIFY_HOME": str(target), "RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME": "1"})
        subprocess.run(["bash", "scripts/install-prod.sh"], env=environment, check=True,
                       capture_output=True, text=True, timeout=30)
        settings = self.root / "settings.json"
        settings.write_text(json.dumps({"pce": "offline", "raw_dir": str(self.root),
                                        "state_db": str(self.root / "state.sqlite"),
                                        "log_dir": str(self.root / "logs"), "output_dir": str(self.root / "out")}))
        output = self.root / "cli.xlsx"
        result = subprocess.run([str(target / "scripts/rules-recertify"), "--config", str(settings),
                                 "--env-file", str(target / ".env"), "compliance-report", "--input", str(source),
                                 "--out", str(output), "--custom-headers", str(target / "config/headers.conf")],
                                cwd=target, env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with closing(load_workbook(output)) as report:
            values = list(report["Business Rules"].values)
            self.assertEqual(values[1][values[0].index(IMPACTED_APP_SERVERS)], 1)
        source.write_text(f"app,env,Kear Id,Entity,{IMPACTED_APP_SERVERS}\nA,PRD,K-A,E1,999\n")
        generate_compliance_workbook(self.root, output, (), source)
        with closing(load_workbook(output)) as report:
            values = list(report["Business Rules"].values)
            self.assertEqual(values[1][values[0].index(IMPACTED_APP_SERVERS)], 1)
        self.workloads.unlink()
        generate_compliance_workbook(self.root, output, (), source)
        with closing(load_workbook(output)) as report:
            values = list(report["Business Rules"].values)
            self.assertTrue(all(row[values[0].index(IMPACTED_APP_SERVERS)] is None for row in values[1:]))
