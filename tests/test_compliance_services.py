import csv
import importlib.util
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

if importlib.util.find_spec("openpyxl"):
    from openpyxl import load_workbook

from rules_recertify.reporting.compliance import (
    LABEL_GROUP_FIELDS, RULE_FIELDS, generate_compliance_workbook,
)


@unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
class ComplianceServicesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.raw = Path(self.directory.name)
        self.snapshot = self.raw / "snapshot"
        self.snapshot.mkdir()
        self.definition = "22 TCP;135 UDP;5900-5902 TCP"
        self.write_csv(self.snapshot / "export_services.csv", ("name", "service_ports"), [
            {"name": "ALL-BUT-ERADICATE", "service_ports": self.definition},
            {"name": "EMPTY-SVC", "service_ports": ""},
        ])
        # The published snapshot must take precedence over other raw runs.
        run = self.raw / "20990101T000000Z-AAAAAAAA"
        run.mkdir()
        self.alternate = run / "export_services.csv"
        self.write_csv(self.alternate, ("name", "service_ports"), [
            {"name": "ALL-BUT-ERADICATE", "service_ports": "80 TCP"},
        ])
        base = dict.fromkeys(RULE_FIELDS, "")
        base.update(ruleset_name="APP", ruleset_scope="app:A;env:PRD", rule_type="allow",
                    rule_enabled="true", src_labels="role:WEB", dst_labels="role:DB")
        rules = [
            dict(base, rule_href="named", services="all-but-eradicate"),
            dict(base, rule_href="all", ruleset_name="GLOBAL_TEST", services="All Services"),
            dict(base, rule_href="mixed", services="ALL-BUT-ERADICATE;All Services;53 UDP;UNKNOWN;EMPTY-SVC"),
            dict(base, rule_href="explicit", services="443 TCP;53 UDP"),
            dict(base, rule_href="unknown", services="UNREFERENCED"),
            dict(base, rule_href="empty", services=""),
        ]
        self.write_csv(self.snapshot / "rules_inventory.csv", RULE_FIELDS, rules)
        self.write_csv(self.snapshot / "export_labelgroups.csv", LABEL_GROUP_FIELDS, [])
        self.write_csv(self.snapshot / "labels.csv", ("key", "value"), [{"key": "app", "value": "A"}])
        self.output = self.raw / "compliance.xlsx"

    def write_csv(self, path, fields, rows):
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def test_named_service_display_uses_snapshot_without_changing_all_service_exposure(self):
        generate_compliance_workbook(self.raw, self.output, (), debug=True)
        with closing(load_workbook(self.output)) as report:
            rows = {}
            expected_by_sheet = {}
            for name in ("Business Rules", "Infra Rules", "Data Quality"):
                values = list(report[name].values)
                data = [dict(zip(values[0], row)) for row in values[1:]]
                rows.update((row["rule_href"], row) for row in data)
                expected_by_sheet[name] = [("services",), *((row["services"],) for row in data)]
            self.assertEqual(rows["named"]["services"], f"ALL-BUT-ERADICATE ({self.definition})")
            self.assertEqual(rows["named"]["PORTS_TO_CONTROL"], "TCP/22")
            self.assertEqual(rows["named"]["PORTS_TO_ERADICATE"], "TCP/5900-5902")
            self.assertEqual(rows["all"]["services"], "All Services")
            self.assertIn("TCP/22", rows["all"]["PORTS_TO_CONTROL"])
            self.assertIn("UDP/161", rows["all"]["PORTS_TO_CONTROL"])
            self.assertIn("TCP/139", rows["all"]["PORTS_TO_ERADICATE"])
            self.assertEqual(rows["mixed"]["services"],
                             f"ALL-BUT-ERADICATE ({self.definition});All Services;53 UDP;UNKNOWN;EMPTY-SVC")
            self.assertEqual(rows["explicit"]["services"], "443 TCP;53 UDP")
            self.assertEqual(rows["unknown"]["services"], "UNREFERENCED")
            self.assertIsNone(rows["empty"]["services"])
            self.assertEqual(report["Summary"]["A6"].value, 6)
            self.assertEqual(report["Summary"]["D6"].value, 6)
        profile = self.raw / "headers.conf"
        profile.write_text("[services]\nvisibility=true\n")
        generate_compliance_workbook(self.raw, self.output, (), custom_headers_path=profile)
        with closing(load_workbook(self.output)) as report:
            for name, values in expected_by_sheet.items():
                self.assertEqual(list(report[name].values), values)
            self.assertEqual(report["Summary"]["A6"].value, 6)

    def test_unavailable_catalog_preserves_names_and_all_services(self):
        (self.snapshot / "export_services.csv").unlink()
        self.alternate.unlink()
        generate_compliance_workbook(self.raw, self.output, (), debug=True)
        with closing(load_workbook(self.output)) as report:
            rows = {}
            for name in ("Business Rules", "Infra Rules"):
                values = list(report[name].values)
                rows.update((row[values[0].index("rule_href")], dict(zip(values[0], row)))
                            for row in values[1:])
            self.assertEqual(rows["named"]["services"], "all-but-eradicate")
            self.assertEqual(rows["all"]["services"], "All Services")
            self.assertEqual(rows["explicit"]["services"], "443 TCP;53 UDP")
