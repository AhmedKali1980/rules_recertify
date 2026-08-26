import csv
import tempfile
import unittest
from pathlib import Path

from rules_recertify.workloader.csvio import CsvContractError, parse_bool, parse_flows_by_port, read_rows


class CsvIoTest(unittest.TestCase):
    def test_large_workloader_query_body(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usage.csv"
            query_body = "x" * 200_000
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["rule_href", "query_body"])
                writer.writerow(["/rules/1", query_body])

            rows = list(read_rows(path, ("rule_href", "query_body")))

        self.assertEqual(rows[0]["query_body"], query_body)

    def test_semicolon_and_quoted_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.csv"
            path.write_text('a;b\n1;"x;y"\n', encoding="utf-8")
            self.assertEqual(list(read_rows(path, ("a", "b")))[0]["b"], "x;y")

    def test_flows_by_port_and_more(self):
        rows, complete, omitted = parse_flows_by_port("5353 UDP (2); 0 ICMP (9); + 13 more")
        self.assertEqual(rows, [{"port": 5353, "protocol": "UDP", "flows": 2}, {"port": None, "protocol": "ICMP", "flows": 9}])
        self.assertFalse(complete); self.assertEqual(omitted, 13)

    def test_boolean_spellings(self):
        self.assertTrue(parse_bool("TRUE")); self.assertFalse(parse_bool("false")); self.assertIsNone(parse_bool(""))
        with self.assertRaises(CsvContractError): parse_bool("maybe")
