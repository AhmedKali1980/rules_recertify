import csv
import importlib.util
import io
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

if importlib.util.find_spec("openpyxl"):
    from openpyxl import load_workbook

from rules_recertify.cli import parser
from rules_recertify.reporting.compliance import LABEL_GROUP_FIELDS, RULE_FIELDS, generate_compliance_workbook
from rules_recertify.reporting.compliance_schema import ALL_HEADERS, DEFAULT_HEADERS, REFERENCE_HEADERS, RULE_ID, RULE_STATUS


@unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
class ComplianceModesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir()
        base = {**dict.fromkeys(RULE_FIELDS, ""), "ruleset_name": "APP", "ruleset_scope": "app:A;env:PRD",
                "ruleset_enabled": "true", "rule_enabled": "true", "rule_type": "allow",
                "unscoped_consumers": "false", "services": "22 TCP"}
        self.rules = [
            dict(base, rule_href="/orgs/1/sec_policy/draft/rule_sets/11155/sec_rules/101899",
                 src_labels="role:WEB;loc:LON", dst_iplists="EDGE; IP List: DOMAIN"),
            dict(base, rule_href="/orgs/1/sec_policy/draft/rule_sets/11155/sec_rules/101900",
                 ruleset_enabled="false", src_iplists="EDGE", dst_labels="role:DB"),
            dict(base, rule_href="/orgs/1/sec_policy/draft/rule_sets/00002/sec_rules/00003",
                 ruleset_scope="app:B;env:PRD", rule_enabled="false", src_iplists="ONLY_B",
                 dst_labels="role:DB", dst_workloads="explicit-01"),
        ]
        self.write("rules_inventory.csv", RULE_FIELDS, self.rules)
        self.write("export_labelgroups.csv", LABEL_GROUP_FIELDS, [])
        self.write("export_services.csv", ("name", "service_ports"), [])
        self.write("export_iplists.csv", ("name", "include", "exclude", "fqdns"), [
            {"name": name, "include": include, "exclude": "10.0.0.7", "fqdns": "example.test"}
            for name, include in (("EDGE", "10.0.0.0/24; 192.0.2.0/24 # office"),
                                  ("DOMAIN", ""), ("ONLY_B", "203.0.113.1"), ("UNUSED", "0.0.0.0/0"))
        ])
        self.workloads = [
            {"app": app, "env": env, "role": role, "loc": loc, "managed": managed,
             "name": name, "hostname": name + ".example", "os_id": "linux", "enforcement": "full",
             "created_at": "2026-01-01T00:00:00Z", "ip_with_default_gw": "10.0.0.1",
             "external_data_reference": "ref-" + name}
            for app, env, role, loc, name, managed in (
                ("A", "PRD", "WEB", "LON", "a-web", "true"),
                ("A", "PRD", "WEB", "PAR", "a-par", "true"),
                ("A", "PRD", "DB", "LON", "a-db", "true"),
                ("A", "UAT", "WEB", "LON", "a-uat", "true"),
                ("B", "PRD", "DB", "LON", "b-db", "true"),
                ("C", "UAT", "OTHER", "PAR", "explicit-01", "true"),
                ("A", "PRD", "WEB", "LON", "unmanaged", "false"),
                ("C", "PRD", "DB", "LON", "unrelated", "true"),
            )
        ]
        self.write("export_wkld.csv", tuple(self.workloads[0]), self.workloads)
        self.source = self.root / "input.csv"
        self.source.write_text("app,env,Kear Id,Application Name,Module,Entity,Owner\n"
                               "A,PRD,K-A,App A,M-A,E1,Team A\nB,PRD,K-B,App B,M-B,E2,Team B\n")
        self.output = self.root / "report.xlsx"

    def write(self, name, fields, rows):
        with (self.snapshot / name).open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def generate(self, **options):
        return generate_compliance_workbook(self.root, self.output, (), self.source, **options)

    def rows(self, book, sheet):
        values = list(book[sheet].values)
        return [dict(zip(values[0], row)) for row in values[1:]]

    def test_default_column_order_renames_status_and_text_rule_id(self):
        self.generate()
        with closing(load_workbook(self.output)) as book:
            self.assertEqual(book.sheetnames, ["Summary", "Business Rules", "Infra Rules", "Data Quality", "iplists", "workloads"])
            headers = tuple(cell.value for cell in book["Business Rules"][1])
            self.assertEqual(headers, DEFAULT_HEADERS)
            self.assertEqual(headers[:9], ("Kear Id (Scope)", "Application Name (Scope)", "Entity", "Module (Scope)",
                                          "illumio label app (Scope)", "illumio label env (Scope)",
                                          "Number of impacted App servers (Scope)", RULE_STATUS, RULE_ID))
            self.assertNotIn("Owner", headers)
            self.assertNotIn("rule_href", headers)
            rows = self.rows(book, "Business Rules")
            self.assertEqual([row[RULE_STATUS] for row in rows], ["Enabled", "Disabled", "Disabled"])
            self.assertEqual([row[RULE_ID] for row in rows], ["11155-101899", "11155-101900", "00002-00003"])
            self.assertEqual(rows[0]["Kear Id (Scope)"], "K-A")
            self.assertEqual(rows[0]["Application Name (Scope)"], "App A")
            self.assertEqual(rows[0]["illumio label env (Scope)"], "PRD")
            for row in book["Business Rules"].iter_rows(min_row=2):
                cell = row[headers.index(RULE_ID)]
                self.assertEqual((cell.data_type, cell.number_format, cell.alignment.horizontal), ("s", "@", "right"))

    def test_debug_shows_all_columns_and_ignores_the_unrequested_profile(self):
        (self.root / "headers.conf").write_text("invalid profile")
        self.generate(debug=True)
        with closing(load_workbook(self.output)) as book:
            headers = next(book["Business Rules"].values)
            self.assertEqual(set(headers), {*ALL_HEADERS, "Owner"})
            self.assertEqual(len(headers), len(set(headers)))
            self.assertNotIn("app", headers)
            self.assertNotIn("Environment", headers)
            for sheet in book:
                self.assertEqual(sheet.sheet_state, "visible")
                self.assertTrue(all(not dimension.hidden for dimension in sheet.column_dimensions.values()))
            self.assertEqual(self.rows(book, "Business Rules")[0]["Owner"], "Team A")

    def test_references_include_only_used_ip_lists_and_matching_managed_workloads(self):
        self.generate()
        with closing(load_workbook(self.output)) as book:
            ip_rows = {row["name"]: row for row in self.rows(book, "iplists")}
            self.assertEqual(set(ip_rows), {"EDGE", "DOMAIN", "ONLY_B"})
            self.assertEqual(ip_rows["EDGE"]["include"], "10.0.0.0/24\n192.0.2.0/24 # office")
            self.assertEqual(ip_rows["EDGE"]["exclude"], "10.0.0.7")
            self.assertEqual(ip_rows["DOMAIN"]["fqdns"], "example.test")
            rows = {row["name"]: row for row in self.rows(book, "workloads")}
            self.assertEqual(set(rows), {"a-web", "a-db", "b-db", "explicit-01"})
            self.assertEqual(rows["a-web"]["OS"], "linux")
            self.assertEqual(tuple(book["workloads"].values)[0], REFERENCE_HEADERS["workloads"])
            self.assertTrue(all(row["managed"] == "true" for row in rows.values()))

    def test_custom_profile_controls_reference_columns_sheets_and_audit_and_accepts_old_aliases(self):
        profile = self.root / "custom.conf"
        profile.write_text("[Kear Id]\nvisibility=true\n[app]\nvisibility=true\n[rule-id]\nvisibility=true\n"
                           "[sheet:Infra Rules]\nvisibility=false\n[sheet:iplists]\nvisibility=true\n"
                           "[column:iplists:name]\nvisibility=true\n[sheet:workloads]\nvisibility=true\n"
                           "[column:workloads:hostname]\nvisibility=true\n")
        self.generate(custom_headers_path=profile)
        with closing(load_workbook(self.output)) as book:
            self.assertNotIn("Infra Rules", book.sheetnames)
            self.assertEqual(next(book["Business Rules"].values), ("Kear Id (Scope)", "illumio label app (Scope)", RULE_ID))
            self.assertEqual(next(book["iplists"].values), ("name",))
            self.assertEqual(next(book["workloads"].values), ("hostname",))
            audit = {(row["Type"], row["Name"]): row for row in self.rows(book, "Report Configuration")}
            self.assertTrue(audit[("Column", "workloads.hostname")]["Displayed"])
            self.assertFalse(audit[("Column", "workloads.app")]["Displayed"])
            self.assertFalse(audit[("Sheet", "Infra Rules")]["Displayed"])
        original = self.output.read_bytes()
        for text in ("[app]\nvisibility=true\n[illumio label app (Scope)]\nvisibility=false\n",
                     "[rule-id]\nvisibility=true\n[sheet:workloads]\nvisibility=true\n",
                     "[rule-id]\nvisibility=true\n[column:workloads:typo]\nvisibility=true\n"):
            profile.write_text(text)
            with self.assertRaises(ValueError):
                self.generate(custom_headers_path=profile)
            self.assertEqual(self.output.read_bytes(), original)

        profile.write_text("[Environment]\nvisibility=true\n[env]\nvisibility=true\n"
                           "[Number of impacted App servers (scope)]\nvisibility=true\n")
        self.generate(custom_headers_path=profile)
        with closing(load_workbook(self.output)) as book:
            self.assertEqual(next(book["Business Rules"].values),
                             ("illumio label env (Scope)", "Number of impacted App servers (Scope)"))

    def test_workload_reference_resolves_groups_scope_exclusions_and_all_workloads(self):
        self.write("export_labelgroups.csv", LABEL_GROUP_FIELDS,
                   [{"name": "WEB_ROLES", "key": "role", "member_labels": "role:WEB"},
                    {"name": "APPS", "key": "app", "member_labels": "app:A;app:B"}])
        rule = dict(self.rules[0], src_labels="rolegroup:WEB_ROLES", src_labels_exclusions="loc:PAR")
        self.write("rules_inventory.csv", RULE_FIELDS, [rule])
        self.generate()
        with closing(load_workbook(self.output)) as book:
            self.assertEqual({row["name"] for row in self.rows(book, "workloads")}, {"a-web"})
        rule.update(src_labels="role:WEB;loc:LON", src_labels_exclusions="", src_all_workloads="true")
        self.write("rules_inventory.csv", RULE_FIELDS, [rule])
        self.generate()
        with closing(load_workbook(self.output)) as book:
            self.assertEqual({row["name"] for row in self.rows(book, "workloads")}, {"a-web", "a-par", "a-db"})
        rule.update(src_labels="", src_labels_exclusions="", dst_labels_exclusions="role:WEB",
                    src_all_workloads="false", dst_all_workloads="true")
        self.write("rules_inventory.csv", RULE_FIELDS, [rule])
        self.generate()
        with closing(load_workbook(self.output)) as book:
            self.assertEqual({row["name"] for row in self.rows(book, "workloads")}, {"a-db"})
        rule.update(src_labels="role:DB", unscoped_consumers="true", dst_all_workloads="false",
                    dst_labels_exclusions="")
        self.write("rules_inventory.csv", RULE_FIELDS, [rule])
        self.generate()
        with closing(load_workbook(self.output)) as book:
            self.assertEqual({row["name"] for row in self.rows(book, "workloads")}, {"a-db", "b-db", "unrelated"})
        rule.update(src_labels="appgroup:APPS;env:PRD;role:DB", unscoped_consumers="false")
        self.write("rules_inventory.csv", RULE_FIELDS, [rule])
        self.generate()
        with closing(load_workbook(self.output)) as book:
            self.assertEqual({row["name"] for row in self.rows(book, "workloads")}, {"a-db"})

    def test_unreadable_references_do_not_block_reports_and_disabled_references_are_not_loaded(self):
        with patch("rules_recertify.reporting.compliance_references.read_rows", side_effect=PermissionError("unreadable")):
            self.generate()
        with closing(load_workbook(self.output)) as book:
            self.assertEqual(len(self.rows(book, "Business Rules")), 3)
            self.assertEqual(self.rows(book, "workloads"), [])
            self.assertEqual({row["name"] for row in self.rows(book, "iplists")}, {"EDGE", "DOMAIN", "ONLY_B"})
        profile = self.root / "detail-only.conf"
        profile.write_text("[rule-id]\nvisibility=true\n")
        with patch("rules_recertify.reporting.compliance_references.read_rows") as read:
            self.generate(custom_headers_path=profile)
        read.assert_not_called()

    def test_status_truth_table_and_unmatched_rows(self):
        variants = [("true", "true", "Enabled"), ("false", "true", "Disabled"),
                    ("true", "false", "Disabled"), ("false", "false", "Disabled"), ("", "", "Enabled"),
                    ("FALSE", "true", "Disabled"), ("unknown", "true", "Enabled")]
        self.write("rules_inventory.csv", RULE_FIELDS, [
            dict(self.rules[0], rule_href=f"/rule_sets/1/sec_rules/{number}", ruleset_enabled=ruleset,
                 rule_enabled=rule) for number, (ruleset, rule, _) in enumerate(variants)
        ])
        self.generate()
        with closing(load_workbook(self.output)) as book:
            self.assertEqual([row[RULE_STATUS] for row in self.rows(book, "Business Rules")],
                             [status for _, _, status in variants])
            rows = self.rows(book, "Data Quality")
            self.assertEqual(len(rows), 1)
            self.assertIsNone(rows[0][RULE_STATUS])
            self.assertIsNone(rows[0][RULE_ID])

    def test_split_reference_dictionaries_are_limited_to_each_entity_kear(self):
        self.output = self.root / "reports.zip"
        self.generate(split_by_kear_id=True, timestamp="20261125T120000Z")
        with ZipFile(self.output) as archive:
            for entity, kear, ip_names, workload_names in (
                ("E1", "K-A", {"EDGE", "DOMAIN"}, {"a-web", "a-db"}),
                ("E2", "K-B", {"ONLY_B"}, {"b-db", "explicit-01"}),
            ):
                with closing(load_workbook(io.BytesIO(archive.read(f"{entity}/compliance_{kear}_20261125T120000Z.xlsx")))) as book:
                    self.assertEqual({row["name"] for row in self.rows(book, "iplists")}, ip_names)
                    self.assertEqual({row["name"] for row in self.rows(book, "workloads")}, workload_names)

    def test_modes_are_exclusive_and_shipped_template_covers_all_public_columns(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            parser().parse_args(["compliance-report", "--debug", "--custom-headers", "headers.conf"])
        self.assertEqual(failure.exception.code, 2)
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            self.generate(debug=True, custom_headers_path=Path("config/headers.conf"))
        self.generate(custom_headers_path=Path("config/headers.conf"))
        with closing(load_workbook(self.output)) as book:
            self.assertEqual(next(book["Business Rules"].values), ALL_HEADERS)
            for sheet, headers in REFERENCE_HEADERS.items():
                self.assertEqual(next(book[sheet].values), headers)
            self.assertIn("Report Configuration", book.sheetnames)
