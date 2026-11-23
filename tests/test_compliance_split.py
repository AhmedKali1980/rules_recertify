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
    from openpyxl import Workbook, load_workbook

from rules_recertify.reporting.compliance import (
    LABEL_GROUP_FIELDS, MICROCOSMOS_COLUMNS, RULE_FIELDS, generate_compliance_workbook,
)


@unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
class ComplianceSplitTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.raw = self.root / "raw"
        snapshot = self.raw / "snapshot"
        snapshot.mkdir(parents=True)
        base = dict.fromkeys(RULE_FIELDS, "")
        base.update(ruleset_name="APP", rule_type="allow", rule_enabled="true",
                    unscoped_consumers="true", services="22 TCP")
        rules = [
            dict(base, rule_href="/rules/a", ruleset_scope="app:APM_REGION_APP_A;env:PRD",
                 src_labels="app:APM_REGION_APP_A", dst_labels="app:APM_REGION_APP_B;env:PRD"),
            dict(base, rule_href="/rules/a2", ruleset_scope="app:APM_REGION_APP_A2;env:UAT",
                 src_labels="role:WEB", dst_iplists="EXTERNAL"),
            dict(base, rule_href="/rules/b", ruleset_scope="app:APM_REGION_APP_B;env:PRD",
                 src_iplists="EXTERNAL", dst_labels="role:DB"),
        ]
        for name, fields, rows in (
            ("rules_inventory.csv", RULE_FIELDS, rules),
            ("export_labelgroups.csv", LABEL_GROUP_FIELDS, []),
            ("export_services.csv", ("name", "service_ports"), []),
            ("labels.csv", ("key", "value"), [
                {"key": "app", "value": f"APM_REGION_{module}"} for module in ("APP_A", "APP_A2", "APP_B")
            ] + [{"key": "env", "value": value} for value in ("PRD", "UAT")]),
        ):
            with (snapshot / name).open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
        self.source = self.root / "microcosmos.xlsx"
        book = Workbook()
        book.active.append(list(MICROCOSMOS_COLUMNS))
        book.active.append([""] * len(MICROCOSMOS_COLUMNS))
        for kear, module, env, entity in (
            ("K-A", "APP_A", "PRD", "E1"), ("K-A", "APP_A2", "UAT", "E1"),
            ("K-B", "APP_B", "PRD", "E2"), ("K-A", "APP_A", "PRD", "E3"),
            ("", "APP_A", "PRD", "E1"), ("K-UNKNOWN", "MISSING", "PRD", ""),
        ):
            row = {"Kear Id": kear, "Application Name": module, "Module": module,
                   "Environment": env, "Entity": entity, "Microsegmentation Solution": "Illumio"}
            book.active.append([row.get(header, "") for header in MICROCOSMOS_COLUMNS])
        book.save(self.source)
        book.close()
        self.stamp = "20261120T120000Z"
        self.output = self.root / "output" / f"compliance_{self.stamp}.zip"

    def generate(self, source=None, profile=None):
        return generate_compliance_workbook(
            self.raw, self.output, (), source or self.source,
            custom_headers_path=profile, split_by_kear_id=True, timestamp=self.stamp,
        )

    def data_rows(self, book):
        rows = []
        for name in ("Business Rules", "Infra Rules", "Data Quality"):
            if name in book.sheetnames:
                values = list(book[name].values)
                rows.extend(dict(zip(values[0], row)) for row in values[1:])
        return rows

    def test_zip_groups_by_entity_and_kear_and_preserves_global_kear_resolution(self):
        full_path = self.root / "full.xlsx"
        generate_compliance_workbook(self.raw, full_path, (), self.source)
        with closing(load_workbook(full_path)) as book:
            full_rows = self.data_rows(book)
        self.assertEqual(self.generate(), self.output)
        with ZipFile(self.output) as archive:
            self.assertIsNone(archive.testzip())
            expected = {(entity, kear) for entity, kear in
                        (("E1", "K-A"), ("E2", "K-B"), ("E3", "K-A"), ("UNSPECIFIED", "K-UNKNOWN"))}
            self.assertEqual(set(archive.namelist()),
                             {f"{entity}/compliance_{kear}_{self.stamp}.xlsx" for entity, kear in expected})
            for entity, kear in expected:
                name = f"{entity}/compliance_{kear}_{self.stamp}.xlsx"
                with closing(load_workbook(io.BytesIO(archive.read(name)))) as book:
                    self.assertEqual(book.sheetnames, ["Summary", "Business Rules", "Infra Rules", "Data Quality"])
                    expected_rows = [row for row in full_rows if row["Kear Id"] == kear
                                     and (row["Entity"] or "UNSPECIFIED") == entity]
                    self.assertEqual(self.data_rows(book), expected_rows)
                    self.assertEqual(book["Summary"]["A6"].value, len(expected_rows))
                    if (entity, kear) == ("E1", "K-A"):
                        self.assertEqual({row["Environment"] for row in expected_rows}, {"PRD", "UAT"})
                        row = next(row for row in self.data_rows(book) if row["rule_href"] == "/rules/a")
                        self.assertEqual(row["Kear Remote"], "K-B")
        self.assertEqual(list(self.output.parent.iterdir()), [self.output])

    def test_split_works_when_identity_columns_and_sheets_are_filtered(self):
        profile = self.root / "headers.conf"
        profile.write_text("[Module]\nvisibility=true\n[Direction]\nvisibility=true\n"
                           "[Kear Id]\nvisibility=false\n[Entity]\nvisibility=false\n"
                           "[sheet:Summary]\nvisibility=false\n[sheet:Infra Rules]\nvisibility=false\n")
        self.generate(profile=profile)
        with ZipFile(self.output) as archive:
            self.assertEqual(len(archive.namelist()), 4)
            for member in archive.namelist():
                with closing(load_workbook(io.BytesIO(archive.read(member)))) as book:
                    self.assertEqual(book.sheetnames, ["Business Rules", "Data Quality", "Report Configuration"])
                    for name in ("Business Rules", "Data Quality"):
                        self.assertEqual(next(book[name].values), ("Direction", "Module"))
                    values = list(book["Report Configuration"].values)
                    audit = {(row[0], row[1]): dict(zip(values[0], row)) for row in values[1:]}
                    self.assertFalse(audit[("Column", "Kear Id")]["Displayed"])
                    self.assertFalse(audit[("Sheet", "Summary")]["Displayed"])

    def test_missing_identity_all_empty_ids_and_invalid_output_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "requires --input"):
            generate_compliance_workbook(self.raw, self.output, (), split_by_kear_id=True)
        with self.assertRaisesRegex(ValueError, r"requires a \.zip"):
            generate_compliance_workbook(self.raw, self.root / "wrong.xlsx", (), self.source, split_by_kear_id=True)
        source = self.root / "input.csv"
        source.write_text("app,env\nAPM_REGION_APP_A,PRD\n")
        with self.assertRaisesRegex(ValueError, "requires input with a Kear Id"):
            self.generate(source=source)
        source.write_text("app,env,Kear Id\nAPM_REGION_APP_A,PRD,\n")
        with self.assertRaisesRegex(ValueError, "No non-empty Kear Id"):
            self.generate(source=source)
        self.assertFalse(self.output.exists())

    def test_safe_member_names_and_collision_detection_preserve_existing_archive(self):
        source = self.root / "input.csv"
        source.write_text("app,env,Kear Id,Entity\nAPM_REGION_APP_A,PRD,../../K-A,../E1\n")
        self.generate(source=source)
        with ZipFile(self.output) as archive:
            self.assertEqual(archive.namelist(), [f"E1/compliance_K-A_{self.stamp}.xlsx"])
        for entity in ("reports.zip", "workbooks"):
            source.write_text(f"app,env,Kear Id,Entity\nAPM_REGION_APP_A,PRD,K-A,{entity}\n")
            self.generate(source=source)
            with ZipFile(self.output) as archive:
                self.assertEqual(archive.namelist(), [f"{entity}/compliance_K-A_{self.stamp}.xlsx"])
        original = self.output.read_bytes()
        for first, second in (("E/A", "E?A"), ("E1", "e1")):
            source.write_text("app,env,Kear Id,Entity\n" + "".join(
                f"APM_REGION_APP_A,PRD,K-A,{entity}\n" for entity in (first, second)
            ))
            with self.assertRaisesRegex(ValueError, "filenames collide"):
                self.generate(source=source)
            self.assertEqual(self.output.read_bytes(), original)

    def test_generation_failure_does_not_publish_partial_archive_or_leave_staging(self):
        from rules_recertify.reporting.compliance import _write_compliance_workbook
        self.output.parent.mkdir()
        self.output.write_bytes(b"existing archive")
        calls = []

        def write_or_fail(*args, **kwargs):
            calls.append(args)
            if len(calls) == 2:
                raise RuntimeError("injected generation failure")
            return _write_compliance_workbook(*args, **kwargs)

        with patch("rules_recertify.reporting.compliance._write_compliance_workbook", side_effect=write_or_fail):
            with self.assertRaisesRegex(RuntimeError, "injected generation failure"):
                self.generate()
        self.assertEqual(self.output.read_bytes(), b"existing archive")
        self.assertEqual(list(self.output.parent.iterdir()), [self.output])

    def test_installed_cli_defaults_to_archive_in_configured_output_directory(self):
        target = self.root / "deployment"
        environment = dict(os.environ)
        environment.pop("RULES_RECERTIFY_SHARED_GROUP", None)
        for key in ("STATE_DB", "PCE", "WORKLOADER_DIR", "WORKLOADER_CONFIG_FILE"):
            environment.pop(key, None)
        environment.update({"RULES_RECERTIFY_HOME": str(target), "RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME": "1"})
        subprocess.run(["bash", "scripts/install-prod.sh"], env=environment, check=True,
                       capture_output=True, text=True, timeout=30)
        settings = self.root / "settings.json"
        output_dir = self.root / "var/output"
        settings.write_text(json.dumps({"pce": "offline", "raw_dir": str(self.raw),
                                        "state_db": str(self.root / "state.sqlite"),
                                        "output_dir": str(output_dir), "log_dir": str(self.root / "logs")}))
        result = subprocess.run([
            str(target / "scripts/rules-recertify"), "--config", str(settings), "--env-file", str(target / ".env"),
            "compliance-report", "--input", str(self.source), "--split-by-kear-id",
            "--custom-headers", str(target / "config/headers.conf"),
        ], cwd=target, env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        path = Path(result.stdout.strip())
        self.assertEqual(path.parent, output_dir)
        self.assertRegex(path.name, r"^compliance_\d{8}T\d{6}Z\.zip$")
        stamp = path.stem[len("compliance_"):]
        with ZipFile(path) as archive:
            self.assertEqual(len(archive.namelist()), 4)
            self.assertTrue(all(member.endswith(f"_{stamp}.xlsx") for member in archive.namelist()))
