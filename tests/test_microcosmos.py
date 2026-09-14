import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from rules_recertify.history.database import Database
from rules_recertify.reporting.microcosmos import (
    _known_application_labels,
    _labels_for_module,
    generate_microcosmos_reports,
)


class MicrocosmosReportTest(unittest.TestCase):
    def test_known_labels_include_latest_raw_label_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); db = Database(root / "state.sqlite"); db.initialize()
            run = root / "raw" / "20260914T120000Z-aabbccdd"; run.mkdir(parents=True)
            (run / "labels.csv").write_text(
                "key,value\napp,APM_GBTO_CHR_FLEXCUBE_IAAS\nenv,PRD\n", encoding="utf-8",
            )
            self.assertIn("APM_GBTO_CHR_FLEXCUBE_IAAS", _known_application_labels(db, root / "raw"))

    def test_module_matches_only_label_suffix_after_second_underscore(self):
        labels = ["APM_RBS_FACTOBOT", "APM_OTHER_FACTOBOT", "APM_RBS_OTHER", "FACTOBOT"]
        self.assertEqual(
            _labels_for_module(" factobot ", labels),
            ["APM_RBS_FACTOBOT", "APM_OTHER_FACTOBOT"],
        )

    @patch("rules_recertify.reporting.microcosmos.generate_workbook")
    @patch("rules_recertify.reporting.microcosmos._write_audit_workbook")
    @patch("rules_recertify.reporting.microcosmos._rule_rows")
    @patch("rules_recertify.reporting.microcosmos._known_application_labels")
    @patch("rules_recertify.reporting.microcosmos._read_microcosmos")
    def test_batch_groups_kear_by_prd_nonprd_and_entity(
        self, read_rows, known_labels, rule_rows, write_audit, generate,
    ):
        read_rows.return_value = [
            {"Kear Id": "K1", "Application Name": "Factobot", "Module": "FACTOBOT",
             "Environment": "PRD", "Entity": "Retail France"},
            {"Kear Id": "K1", "Application Name": "Factobot", "Module": "FACTOBOT",
             "Environment": "UAT", "Entity": "Retail France"},
            {"Kear Id": "", "Application Name": "Ignored", "Module": "OTHER",
             "Environment": "PRD", "Entity": "Retail France"},
        ]
        known_labels.return_value = ["APM_RBS_FACTOBOT"]
        rule_rows.return_value = [
            {"raw_json": '{"ruleset_scope":"app:APM_RBS_FACTOBOT;env:PRD"}'},
            {"raw_json": '{"ruleset_scope":"app:APM_RBS_FACTOBOT;env:UAT"}'},
        ]
        write_audit.return_value = Path("audit.xlsx")
        generate.side_effect = lambda _db, output, *_args, **kwargs: output / (kwargs["filename_environment"] + ".xlsx")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); db = Database(root / "state.sqlite"); db.initialize()
            targets = generate_microcosmos_reports(
                db, root / "input.xlsx", root / "output", root / "raw", 180,
                date(2026, 9, 10), timestamp="20260914T120000Z",
            )
        self.assertEqual(len(targets), 3)
        self.assertEqual(targets[0], Path("audit.xlsx"))
        self.assertEqual(
            {str(path.relative_to(root / "output")) for path in targets[1:]},
            {
                "20260914T120000Z/PRD/Retail_France/PRD.xlsx",
                "20260914T120000Z/NONPRD/Retail_France/NONPRD.xlsx",
            },
        )
        calls = {call.kwargs["filename_environment"]: call for call in generate.call_args_list}
        self.assertEqual(calls["PRD"].args[4:6], (["APM_RBS_FACTOBOT"], ["PRD"]))
        self.assertEqual(calls["NONPRD"].args[4:6], (["APM_RBS_FACTOBOT"], ["UAT"]))
        statuses = write_audit.call_args.args[2]
        self.assertIn("PROCESSED", statuses[2])
        self.assertIn("PROCESSED", statuses[3])
        self.assertEqual(statuses[4], "SKIPPED: empty Kear Id")

    @patch("rules_recertify.reporting.microcosmos._write_audit_workbook", return_value=Path("audit.xlsx"))
    @patch("rules_recertify.reporting.microcosmos._rule_rows", return_value=[])
    @patch("rules_recertify.reporting.microcosmos._known_application_labels", return_value=[])
    @patch("rules_recertify.reporting.microcosmos._read_microcosmos")
    def test_unknown_module_is_skipped_and_audited(self, read_rows, _known, _rules, write_audit):
        read_rows.return_value = [
            {"Kear Id": "K1", "Application Name": "App", "Module": "UNKNOWN",
             "Environment": "PRD", "Entity": "Entity"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); db = Database(root / "state.sqlite"); db.initialize()
            targets = generate_microcosmos_reports(
                db, root / "input.xlsx", root / "output", root / "raw", 180,
                date(2026, 9, 10), timestamp="run",
            )
        self.assertEqual(targets, [Path("audit.xlsx")])
        self.assertIn("no application label", write_audit.call_args.args[2][2])

    @patch("rules_recertify.reporting.microcosmos._write_audit_workbook", return_value=Path("audit.xlsx"))
    @patch("rules_recertify.reporting.microcosmos._rule_rows", return_value=[])
    @patch("rules_recertify.reporting.microcosmos._known_application_labels", return_value=["APM_RBS_FACTOBOT"])
    @patch("rules_recertify.reporting.microcosmos._read_microcosmos")
    def test_label_without_matching_rule_is_skipped(self, read_rows, _known, _rules, write_audit):
        read_rows.return_value = [
            {"Kear Id": "K1", "Application Name": "App", "Module": "FACTOBOT",
             "Environment": "PRD", "Entity": "Entity"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); db = Database(root / "state.sqlite"); db.initialize()
            targets = generate_microcosmos_reports(
                db, root / "input.xlsx", root / "output", root / "raw", 180,
                date(2026, 9, 10), timestamp="run",
            )
        self.assertEqual(targets, [Path("audit.xlsx")])
        self.assertEqual(write_audit.call_args.args[2][2], "SKIPPED: no matching ruleset/rule in SQLite")
