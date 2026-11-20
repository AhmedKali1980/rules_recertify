import csv
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from xml.etree.ElementTree import tostring

if importlib.util.find_spec("openpyxl"):
    from openpyxl import Workbook, load_workbook

from rules_recertify.reporting.compliance import (
    LABEL_GROUP_FIELDS, MICROCOSMOS_COLUMNS, RULE_FIELDS, generate_compliance_workbook,
)


@unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
class ComplianceHeadersTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.raw = self.root / "raw"
        self.snapshot = self.raw / "snapshot"
        self.snapshot.mkdir(parents=True)
        base = dict.fromkeys(RULE_FIELDS, "")
        base.update(ruleset_name="APP", ruleset_scope="app:APM_REGION_LOCAL;env:PRD",
                    rule_type="allow", rule_enabled="true", services="443 TCP")
        self.rules = [
            dict(base, rule_href="/rules/outgoing", src_labels="role:WEB", dst_workloads="database-01"),
            dict(base, rule_href="/rules/incoming", ruleset_name="BOUQUETS_LOCAL",
                 src_workloads="client-01", dst_labels="role:DB"),
        ]
        self.write_csv("rules_inventory.csv", RULE_FIELDS, self.rules)
        self.write_csv("export_labelgroups.csv", LABEL_GROUP_FIELDS, [])
        self.write_csv("labels.csv", ("key", "value"), [
            {"key": "app", "value": "APM_REGION_LOCAL"}, {"key": "env", "value": "PRD"},
        ])
        self.source = self.root / "applications.csv"
        self.source.write_text("app,env,Owner\nAPM_REGION_LOCAL,PRD,Team A\nUNKNOWN,PRD,Team B\n")
        self.output = self.root / "compliance.xlsx"

    def write_csv(self, name, fields, rows):
        with (self.snapshot / name).open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def generate(self, profile=None, output=None, source=None):
        return generate_compliance_workbook(
            self.raw, output or self.output, (), source or self.source,
            custom_headers_path=profile,
        )

    def test_visibility_projects_all_detail_sheets_without_changing_data_or_summary(self):
        baseline = self.generate(output=self.root / "full.xlsx")
        profile = self.root / "headers.conf"
        profile.write_text("[Destination]\nvisibility=true\n[Source]\nvisibility=true\n"
                           "[Direction]\nvisibility=false\n[Owner]\nvisibility=true\n")
        filtered = self.generate(profile)
        with closing(load_workbook(baseline)) as full, closing(load_workbook(filtered)) as report:
            self.assertEqual(report.sheetnames, full.sheetnames)
            self.assertEqual(list(report["Summary"].values), list(full["Summary"].values))
            self.assertEqual(report["Summary"]["A6"].value, 3)
            self.assertEqual(report["Summary"]["D6"].value, 2)
            self.assertEqual(tostring(report["Summary"]._charts[0].to_tree()),
                             tostring(full["Summary"]._charts[0].to_tree()))
            for name in ("Business Rules", "Infra Rules", "Data Quality"):
                original = list(full[name].values)
                values = list(report[name].values)
                self.assertEqual(values[0], ("Owner", "Source", "Destination"))
                indexes = [original[0].index(header) for header in values[0]]
                self.assertEqual(values[1:], [tuple(row[index] for index in indexes) for row in original[1:]])
                self.assertEqual(report[name].max_column, 3)
                table = next(iter(report[name].tables.values()))
                self.assertEqual(table.ref, "A1:C2")
            self.assertEqual(report["Business Rules"]["C2"].value, "workload:database-01")
            self.assertEqual(report["Infra Rules"]["B2"].value, "workload:client-01")

    def test_shipped_all_visible_profile_matches_defaults_for_snapshot_and_microcosmos(self):
        source = self.root / "microcosmos.xlsx"
        workbook = Workbook()
        workbook.active.append(list(MICROCOSMOS_COLUMNS))
        workbook.active.append([""] * len(MICROCOSMOS_COLUMNS))
        row = {"Kear Id": "K-LOCAL", "Application Name": "Local", "Module": "LOCAL",
               "Environment": "PRD", "Microsegmentation Solution": "Illumio"}
        workbook.active.append([row.get(header, "") for header in MICROCOSMOS_COLUMNS])
        workbook.save(source)
        workbook.close()
        for input_path in (None, source):
            with self.subTest(input_path=input_path):
                baseline = self.root / "all.xlsx"
                generate_compliance_workbook(self.raw, baseline, (), input_path)
                generate_compliance_workbook(self.raw, self.output, (), input_path,
                                             custom_headers_path=Path("config/headers.conf"))
                with closing(load_workbook(baseline)) as full, closing(load_workbook(self.output)) as report:
                    self.assertEqual(report.sheetnames, full.sheetnames)
                    for name in full.sheetnames:
                        self.assertEqual(list(report[name].values), list(full[name].values))

    def test_one_visible_column_and_empty_sheets_work_with_windows_profile(self):
        self.write_csv("rules_inventory.csv", RULE_FIELDS, self.rules[:1])
        self.source.write_text("app,env\nAPM_REGION_LOCAL,PRD\n")
        profile = self.root / "headers2.conf"
        profile.write_bytes(b"\xef\xbb\xbf[Source]\r\nvisibility=TRUE\r\n[Direction]\r\nvisibility=FALSE\r\n")
        self.generate(profile)
        with closing(load_workbook(self.output)) as report:
            self.assertEqual(list(report["Business Rules"].values), [("Source",), ("role:WEB",)])
            for name in ("Infra Rules", "Data Quality"):
                self.assertEqual(list(report[name].values), [("Source",)])
                self.assertEqual(report[name].auto_filter.ref, "A1:A1")
                self.assertEqual(report[name].max_column, 1)

    def test_conditional_formatting_follows_selected_column_positions(self):
        profile = self.root / "headers.conf"
        profile.write_text("[Direction]\nvisibility=true\n[Source]\nvisibility=true\n")
        self.generate(profile)
        with closing(load_workbook(self.output)) as report:
            for name, direction in (("Business Rules", "outgoing"), ("Infra Rules", "incoming")):
                sheet = report[name]
                self.assertEqual(tuple(cell.value for cell in sheet[1]), ("Direction", "Source"))
                self.assertEqual(sheet["A2"].value, direction)
                ranges = [str(item.sqref) for item in sheet.conditional_formatting]
                self.assertEqual(ranges, ["A2"])

    def test_invalid_profiles_fail_without_overwriting_an_existing_report(self):
        profiles = (
            ("", "No visible columns"),
            ("[Source]\nvisibility=false\n", "No visible columns"),
            ("[Srouce]\nvisibility=true\n", "Unknown report column"),
            ("[Source]\nvisibility=yes\n", "expected true or false"),
            ("[Source]\nvisible=true\n", "requires only visibility"),
            ("[Source]\nvisibility=true\nextra=1\n", "requires only visibility"),
            ("[Source]\nvisibility=true\n[Source]\nvisibility=false\n", "Cannot read"),
            ("[Source]\nvisibility=true\nvisibility=false\n", "Cannot read"),
            ("[DEFAULT]\nvisibility=true\n[Source]\n", "must not contain DEFAULT"),
            ("visibility=true\n", "Cannot read"),
            ("[Application Name]\nvisibility=true\n", "No visible columns"),
        )
        profile = self.root / "invalid.conf"
        for contents, message in profiles:
            with self.subTest(contents=contents):
                profile.write_text(contents)
                self.output.write_bytes(b"existing report")
                with self.assertRaisesRegex(ValueError, message):
                    self.generate(profile)
                self.assertEqual(self.output.read_bytes(), b"existing report")
                self.assertFalse(self.output.with_suffix(".xlsx.tmp").exists())
        with self.assertRaisesRegex(ValueError, "Cannot read custom headers file"):
            self.generate(self.root / "missing.conf")

    def test_installed_cli_reads_only_the_explicitly_requested_profile(self):
        target = self.root / "deployment"
        environment = dict(os.environ)
        environment.pop("RULES_RECERTIFY_SHARED_GROUP", None)
        for key in ("STATE_DB", "PCE", "WORKLOADER_DIR", "WORKLOADER_CONFIG_FILE"):
            environment.pop(key, None)
        environment.update({"RULES_RECERTIFY_HOME": str(target), "RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME": "1"})
        subprocess.run(["bash", "scripts/install-prod.sh"], env=environment, check=True,
                       capture_output=True, text=True, timeout=30)
        settings = self.root / "settings.json"
        settings.write_text(json.dumps({
            "pce": "offline", "raw_dir": str(self.raw), "log_dir": str(self.root / "logs"),
            "state_db": str(self.root / "state.sqlite"), "output_dir": str(self.root / "output"),
        }))
        command = [str(target / "scripts/rules-recertify"), "--config", str(settings),
                   "--env-file", str(target / "missing.env"), "compliance-report",
                   "--input", str(self.source), "--out", str(self.output)]
        (target / "config/headers.conf").write_text("invalid default profile")
        result = subprocess.run(command, cwd=target, env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with closing(load_workbook(self.output)) as full:
            self.assertIn("Owner", next(full["Business Rules"].values))
        for name, header in (("headers.conf", "Source"), ("custom profiles/headers2.conf", "Direction")):
            with self.subTest(profile=name):
                profile = self.root / name
                profile.parent.mkdir(parents=True, exist_ok=True)
                profile.write_text(f"[{header}]\nvisibility=true\n")
                result = subprocess.run(command + ["--custom-headers", str(profile)], cwd=target,
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                with closing(load_workbook(self.output)) as report:
                    for sheet in ("Business Rules", "Infra Rules", "Data Quality"):
                        self.assertEqual(next(report[sheet].values), (header,))
        original = self.output.read_bytes()
        result = subprocess.run(command + ["--custom-headers", "config/headers.conf"], cwd=target,
                                env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Cannot read custom headers file", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.output.read_bytes(), original)
