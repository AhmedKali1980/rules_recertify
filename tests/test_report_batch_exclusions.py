import csv
import importlib.util
import ipaddress
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import date
from pathlib import Path

if importlib.util.find_spec("openpyxl"):
    from openpyxl import Workbook, load_workbook

from rules_recertify.history.database import Database
from rules_recertify.reporting.microcosmos import REQUIRED_COLUMNS, generate_microcosmos_reports
from rules_recertify.reporting.workbook import (
    _count_addresses, _effective_ip_list_members, _effective_nz3_members,
    _expand_side_details, _load_report_ip_lists, _zones_for_addresses,
)
from rules_recertify.resolution.workloads import prepare_nz3_members


class IPListExclusionsTest(unittest.TestCase):
    def test_include_exclude_display_comments_and_ipv4_only_filter(self):
        reference = [{"name": "SUBNET-GLOBAL-IPL", "include": "0.0.0.0/0#all IPv4;::/0#all IPv6",
                      "exclude": "193.79.20.0/24#SUBNET FRANCE;2001:db8::/32 #IPv6;#empty comment"}]
        rule = {"src_iplists": "SUBNET-GLOBAL-IPL", "dst_iplists": "SUBNET-GLOBAL-IPL"}
        for side in ("src", "dst"):
            full, addresses = _expand_side_details(rule, side, [], [("APP", "PRD")], reference)
            self.assertEqual(full, "IP List: SUBNET-GLOBAL-IPL (0.0.0.0/0;::/0; !193.79.20.0/24; !2001:db8::/32)")
            self.assertNotIn("#", full)
            self.assertEqual(_count_addresses(addresses), 2 ** 32 - 256)
            octoflow, addresses = _expand_side_details(rule, side, [], [("APP", "PRD")], reference, ipv4_only=True)
            self.assertEqual(octoflow, "IP List: SUBNET-GLOBAL-IPL (0.0.0.0/0; !193.79.20.0/24)")
            self.assertEqual(_count_addresses(addresses), 2 ** 32 - 256)

    def test_exclusions_apply_per_list_before_union_and_zone_membership(self):
        reference = [{"name": "NZ3_LAN", "include": "10.0.0.0/24", "exclude": "10.0.0.7#host"},
                     {"name": "HOST", "member": "10.0.0.7"}]
        single = {"src_iplists": "NZ3_LAN"}
        _, addresses = _expand_side_details(single, "src", [], [("APP", "PRD")], reference)
        self.assertEqual(_count_addresses(addresses), 255)
        _, addresses = _expand_side_details({"src_iplists": "NZ3_LAN;HOST"}, "src", [], [("APP", "PRD")], reference)
        self.assertEqual(_count_addresses(addresses), 256)
        prepared = prepare_nz3_members(_effective_nz3_members(reference))
        self.assertEqual(_zones_for_addresses(["10.0.0.7"], prepared), "Any")
        self.assertEqual(_zones_for_addresses(["10.0.0.8"], prepared), "NZ3_LAN")
        self.assertEqual(_zones_for_addresses(["10.0.0.0/24"], prepared), "Any")

    def test_interval_subtraction_handles_overlap_spanning_gaps_and_both_families(self):
        self.assertEqual(_effective_ip_list_members([], ["10.0.0.0/8"]), [])
        self.assertEqual(_effective_ip_list_members(["10.0.0.0/24"], ["10.0.0.0/8"]), [])
        self.assertEqual(_effective_ip_list_members(["::/126"], ["::/127"]), ["::2-::3"])
        for included, excluded, expected in (
            (["10.0.0.0/24", "10.0.0.0/25"], ["10.0.0.0/25", "10.0.0.7"], 128),
            (["10.0.0.0-10.0.0.9", "10.0.0.20-10.0.0.29"], ["10.0.0.5-10.0.0.24"], 10),
            (["10.0.0.0/24"], ["192.0.2.0/24", "::/0"], 256),
            (["0.0.0.0/0", "::/0"], ["193.79.20.0/24", "2001:db8::/32"], 2 ** 32 - 256),
        ):
            self.assertEqual(_count_addresses(_effective_ip_list_members(included, excluded)), expected)

    def test_interval_subtraction_matches_independent_small_address_sets(self):
        generator = random.Random(20261126)
        for _ in range(40):
            include_ranges = [tuple(sorted(generator.sample(range(32), 2))) for _ in range(4)]
            exclude_ranges = [tuple(sorted(generator.sample(range(32), 2))) for _ in range(4)]
            included = [f"10.0.0.{start}-10.0.0.{end}" for start, end in include_ranges]
            excluded = [f"10.0.0.{start}-10.0.0.{end}" for start, end in exclude_ranges]
            expected = {value for start, end in include_ranges for value in range(start, end + 1)}
            expected -= {value for start, end in exclude_ranges for value in range(start, end + 1)}
            actual = set()
            for expression in _effective_ip_list_members(included, excluded):
                first, separator, last = expression.partition("-")
                start = int(ipaddress.ip_address(first))
                end = int(ipaddress.ip_address(last)) if separator else start
                actual.update(value & 255 for value in range(start, end + 1))
            self.assertEqual(actual, expected)


@unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
class ReportBatchExclusionsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.raw = self.root / "raw"
        self.snapshot = self.raw / "snapshot"
        self.snapshot.mkdir(parents=True)
        self.database = Database(self.root / "state.sqlite")
        self.database.initialize()
        base = {"ruleset_name": "APP", "ruleset_href": "/orgs/1/sec_policy/draft/rule_sets/11155",
                "ruleset_enabled": "true", "rule_enabled": "true",
                "rule_type": "allow", "src_iplists": "SUBNET-GLOBAL-IPL", "dst_iplists": "LAN",
                "services": "80 TCP"}
        rules = [dict(base, ruleset_scope=f"app:APM_RBS_TEST;env:{env}",
                      rule_href=f"/orgs/1/sec_policy/draft/rule_sets/11155/sec_rules/{number}")
                 for number, env in enumerate(("PRD", "UAT", "DEV"), 1)]
        rules += [dict(rules[0], rule_href="/rule_sets/11155/sec_rules/4", src_iplists="LAN;HOST"),
                  dict(rules[0], rule_href="/rule_sets/11155/sec_rules/5", src_iplists="LAN", dst_iplists="HOST")]
        self.database.upsert_rules(rules, "2026-11-25T00:00:00+00:00")
        with self.database.connect() as connection:
            connection.execute("INSERT INTO ip_lists VALUES(?,?,?)", ("SUBNET-GLOBAL-IPL", "192.0.2.1", "old"))
        self.references = [
            {"name": "SUBNET-GLOBAL-IPL", "include": "0.0.0.0/0#global;::/0#IPv6",
             "exclude": "193.79.20.0/24#SUBNET FRANCE;2001:db8::/32#IPv6"},
            {"name": "LAN", "include": "10.0.0.0/24#LAN", "exclude": "10.0.0.7#server;10.0.0.7#duplicate"},
            {"name": "HOST", "include": "10.0.0.7#server", "exclude": ""},
        ]
        self.write_references(self.snapshot / "export_iplists.csv", self.references)
        newer = self.raw / "20990101T000000Z-aabbccdd"
        newer.mkdir()
        self.write_references(newer / "export_iplists.csv", [{"name": "SUBNET-GLOBAL-IPL", "include": "203.0.113.1"}])
        self.source = self.root / "microcosmos.xlsx"
        book = Workbook()
        book.active.append(list(REQUIRED_COLUMNS))
        for env in ("PRD", "UAT", "DEV"):
            row = {"Kear Id": "K-1", "Application Name": "Application", "Module": "TEST",
                   "Environment": env, "Entity": "E", "Microsegmentation Solution": "Illumio"}
            book.active.append([row.get(name, "") for name in REQUIRED_COLUMNS])
        book.save(self.source)
        book.close()

    def write_references(self, path, rows):
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=("name", "include", "exclude"))
            writer.writeheader()
            writer.writerows(rows)

    def rows(self, book, sheet):
        values = list(book[sheet].values)
        return [dict(zip(values[0], row)) for row in values[1:]]

    def test_reference_loading_keeps_signed_exclusions_without_comments(self):
        with self.database.connect() as connection:
            rows, source = _load_report_ip_lists(connection, self.raw)
        self.assertEqual(source, str(self.snapshot / "export_iplists.csv"))
        self.assertIn({"name": "SUBNET-GLOBAL-IPL", "member": "!193.79.20.0/24"}, rows)
        self.assertIn({"name": "SUBNET-GLOBAL-IPL", "member": "!2001:db8::/32"}, rows)
        self.assertTrue(all("#" not in row["member"] for row in rows))

    def test_all_batch_layouts_prd_nonprd_sides_counts_and_raw_rule_retention(self):
        baseline = {}
        for thin in (False, True):
            reports = generate_microcosmos_reports(
                self.database, self.source, self.root / "output", self.raw, 120, date(2026, 11, 26),
                timestamp="reduced" if thin else "standard", octoflow_only=thin,
            )
            self.assertEqual(len(reports), 3)
            with closing(load_workbook(reports[0])) as audit:
                statuses = [row[-1] for row in list(audit.active.values)[1:]]
                self.assertTrue(all(str(status).startswith("PROCESSED:") for status in statuses))
            for report in reports[1:]:
                category = report.parent.parent.name
                with closing(load_workbook(report)) as book:
                    expected_sheets = ["Raw Rules", "Octoflow"] if thin else [
                        "Presentation", "Raw Rules", "Expanded Rules", "Octoflow", "Rule Usage", "Data Quality"]
                    self.assertEqual(book.sheetnames, expected_sheets)
                    rows = {row["rule_id"]: row for row in self.rows(book, "Octoflow")}
                    self.assertEqual(set(rows), {"1", "4", "5"} if category == "PRD" else {"2", "3"})
                    for identifier in ({"1"} if category == "PRD" else {"2", "3"}):
                        row = rows[identifier]
                        self.assertEqual(row["sources"], "IP List: SUBNET-GLOBAL-IPL (0.0.0.0/0; !193.79.20.0/24)")
                        self.assertEqual(row["destinations"], "IP List: LAN (10.0.0.0/24; !10.0.0.7)")
                        self.assertEqual(row["nb_src_ips"], 2 ** 32 - 256)
                        self.assertEqual(row["nb_dst_ips"], 255)
                    if category == "PRD":
                        self.assertEqual(rows["4"]["nb_src_ips"], 256)
                        self.assertEqual(rows["4"]["permissive_rule"], "YES")
                        self.assertEqual(rows["5"]["nb_src_ips"], 255)
                        self.assertEqual(rows["5"]["permissive_rule"], "NO")
                    self.assertTrue(all("#" not in row["sources"] + row["destinations"] for row in rows.values()))
                    raw_rows = self.rows(book, "Raw Rules")
                    self.assertEqual(len(raw_rows), len(rows))
                    self.assertTrue(any("SUBNET-GLOBAL-IPL" in str(row["Source"]) for row in raw_rows))
                    if thin:
                        self.assertEqual(rows, baseline[category])
                    else:
                        baseline[category] = rows
                        expanded = self.rows(book, "Expanded Rules")
                        self.assertTrue(any("!2001:db8::/32" in row["Expanded Sources"] for row in expanded))
                        self.assertTrue(all("#" not in row["Expanded Sources"] + row["Expanded Destinations"] for row in expanded))

    def test_cli_batch_and_single_report_support_the_two_sheet_octoflow_layout(self):
        repository = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        for name in ("STATE_DB", "PCE", "WORKLOADER_DIR", "WORKLOADER_CONFIG_FILE"):
            environment.pop(name, None)
        environment["PYTHONPATH"] = str(repository / "src")
        settings = self.root / "settings.json"
        command = [sys.executable, "-m", "rules_recertify.cli", "--config", str(settings),
                   "--env-file", str(self.root / "missing.env")]
        for thin in (False, True):
            settings.write_text(json.dumps({"pce": "offline", "state_db": str(self.root / "state.sqlite"),
                                            "raw_dir": str(self.raw), "log_dir": str(self.root / "logs"),
                                            "output_dir": str(self.root / ("cli-reduced" if thin else "cli-standard"))}))
            args = command + ["report-batch", "--microcosmos-xlsx", str(self.source),
                              "--lookback-days", "120", "--as-of", "2026-11-26"]
            result = subprocess.run(args + (["--octoflow"] if thin else []), env=environment,
                                    cwd=repository, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            paths = [Path(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(paths), 3)
            for path in paths[1:]:
                with closing(load_workbook(path)) as book:
                    if thin:
                        self.assertEqual(book.sheetnames, ["Raw Rules", "Octoflow"])
                    else:
                        self.assertIn("Expanded Rules", book.sheetnames)
                    row = self.rows(book, "Octoflow")[0]
                    self.assertEqual(row["sources"], "IP List: SUBNET-GLOBAL-IPL (0.0.0.0/0; !193.79.20.0/24)")
        result = subprocess.run(command + ["report", "--kear-id", "K-1", "--logical-application-name", "Application",
                                          "--application-label", "APM_RBS_TEST", "--environment", "PRD",
                                          "--as-of", "2026-11-26", "--octoflow"],
                                env=environment, cwd=repository, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with closing(load_workbook(Path(result.stdout.strip()))) as book:
            self.assertEqual(book.sheetnames, ["Raw Rules", "Octoflow"])
