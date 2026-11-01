import tempfile
import unittest
from pathlib import Path

from rules_recertify.reporting.iplist_search import (
    _input_value, _is_any_span, _load_ip_lists, _load_search_input,
    _matching_ip_lists, _member_span, _parse_query,
    generate_iplist_search_workbook,
)


class IpListSearchTest(unittest.TestCase):
    def test_csv_input_preserves_columns_and_accepts_supported_header(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.csv"
            source.write_text(
                "Owner,ip/subnet,Ticket\nAlice,10.0.0.12,INC1\n", encoding="utf-8",
            )
            rows, columns = _load_search_input(source)
        self.assertEqual(columns, ["Owner", "ip/subnet", "Ticket"])
        self.assertEqual(_input_value(rows[0]), "10.0.0.12")
        self.assertEqual(rows[0]["Owner"], "Alice")

    def test_network_matching_requires_full_containment(self):
        ip_lists = [{
            "name": "NETWORKS",
            "members": [
                ("10.0.0.0/24", _member_span("10.0.0.0/24")),
                ("192.0.2.10-192.0.2.20", _member_span("192.0.2.10-192.0.2.20")),
            ],
            "references": ["export_iplists.csv"],
        }]
        self.assertEqual(_matching_ip_lists(_parse_query("10.0.0.12"), ip_lists)[0]["name"],
                         "NETWORKS")
        self.assertEqual(_matching_ip_lists(_parse_query("10.0.0.0/25"), ip_lists)[0]["members"],
                         ["10.0.0.0/24"])
        self.assertEqual(_matching_ip_lists(_parse_query("10.0.0.0/23"), ip_lists), [])
        self.assertEqual(_matching_ip_lists(_parse_query("192.0.2.15"), ip_lists)[0]["members"],
                         ["192.0.2.10-192.0.2.20"])

    def test_any_members_are_removed_and_exports_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            full = root / "export_iplists.csv"
            derived = root / "export_iplists.derived.csv"
            full.write_text(
                'name,include\nANY,"0.0.0.0/0;::/0"\nAPP,10.20.0.0/16# prod\n',
                encoding="utf-8",
            )
            derived.write_text("name,include\nAPP,10.20.0.0/16\n", encoding="utf-8")
            rows = _load_ip_lists([full, derived])
        by_name = {row["name"]: row for row in rows}
        self.assertEqual(by_name["ANY"]["members"], [])
        self.assertEqual(len(by_name["APP"]["members"]), 1)
        self.assertEqual(
            by_name["APP"]["references"],
            ["export_iplists.csv", "export_iplists.derived.csv"],
        )
        self.assertTrue(_is_any_span(_member_span("0.0.0.0/0")))

    def test_invalid_query_is_rejected(self):
        with self.assertRaises(ValueError):
            _parse_query("not-an-address")

    def test_workbook_preserves_input_and_reports_match_statuses(self):
        try:
            from openpyxl import load_workbook
        except ImportError:
            self.skipTest("openpyxl is not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "raw" / "snapshot"
            snapshot.mkdir(parents=True)
            (snapshot / "export_iplists.csv").write_text(
                "name,include\nAPP_NET,10.20.0.0/16\nANY,0.0.0.0/0\n",
                encoding="utf-8",
            )
            source = root / "input.csv"
            source.write_text(
                "Owner,ip\nAlice,10.20.30.40\nBob,192.0.2.1\nEve,invalid\n",
                encoding="utf-8",
            )
            output = root / "result.xlsx"
            generate_iplist_search_workbook(root / "raw", source, output)
            workbook = load_workbook(output, read_only=True)
            sheet = workbook["IP List Matches"]
            rows = list(sheet.iter_rows(values_only=True))
            headers = list(rows[0])
            records = [dict(zip(headers, row)) for row in rows[1:]]
            workbook.close()
        self.assertEqual(records[0]["Owner"], "Alice")
        self.assertEqual(records[0]["iplist_name"], "APP_NET")
        self.assertEqual(records[0]["match_status"], "MATCHED")
        self.assertEqual(records[1]["match_status"], "NO_MATCH")
        self.assertEqual(records[2]["match_status"], "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
