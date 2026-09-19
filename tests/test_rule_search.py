import json
import tempfile
import unittest
from pathlib import Path

from rules_recertify.history.database import Database
from rules_recertify.reporting.rule_search import (
    latest_rules, load_search_items, search_latest_rules,
)


class RuleSearchTest(unittest.TestCase):
    def test_items_file_supports_header_deduplication_and_blanks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "items.csv"
            path.write_text("item\nAPP_A\n\nAPP_A\nTCP/22\n", encoding="utf-8")
            self.assertEqual(load_search_items(path), ["APP_A", "TCP/22"])

    def test_partial_upsert_does_not_mark_older_rules_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "state.sqlite"); db.initialize()
            db.upsert_rules([{
                "rule_href": "/rules/old", "ruleset_href": "/rulesets/old",
                "ruleset_name": "OLD", "services": "80 TCP",
            }], "2026-09-14T00:00:00+00:00")
            db.upsert_rules([{
                "rule_href": "/rules/new", "ruleset_href": "/rulesets/new",
                "ruleset_name": "NEW", "services": "443 TCP",
            }], "2026-09-15T00:00:00+00:00")
            rules, snapshot = latest_rules(db)
            self.assertEqual(snapshot, "2026-09-15T00:00:00+00:00")
            self.assertEqual([row["rule_href"] for row in rules], ["/rules/new", "/rules/old"])

    def test_latest_rules_uses_explicit_current_state(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "state.sqlite"); db.initialize()
            old={"rule_href":"/rules/old","ruleset_href":"/rulesets/1"}
            current={"rule_href":"/rules/current","ruleset_href":"/rulesets/1"}
            db.complete_policy_snapshot("one", "run-1", [old, current], "2026-01-01")
            db.complete_policy_snapshot("two", "run-2", [current], "2026-01-02")
            rules, snapshot = latest_rules(db)
            self.assertEqual(snapshot, "2026-01-02")
            self.assertEqual([row["rule_href"] for row in rules], ["/rules/current"])

    def test_text_items_find_labels_groups_ip_lists_and_named_services(self):
        raw = {
            "rule_href": "/rules/1", "ruleset_href": "/rulesets/1",
            "ruleset_name": "APP RULES", "ruleset_scope": "app:APP_A;env:PRD",
            "src_labels": "role:WEB", "src_label_groups": "PRODUCTION-WEB",
            "dst_iplists": "DATABASE-NET", "services": "DATABASE-SVC",
        }
        rule = {**raw, "raw_json": json.dumps(raw), "snapshot_at": "now"}
        results, summary = search_latest_rules(
            [rule], ["APP_A", "PRODUCTION-WEB", "DATABASE-NET", "DATABASE-SVC", "MISSING"], {},
        )
        found = {(row["searched item"], row["found as"]) for row in results if row["status"] == "FOUND"}
        self.assertIn(("APP_A", "ruleset_scope"), found)
        self.assertIn(("PRODUCTION-WEB", "src_label_groups"), found)
        self.assertIn(("DATABASE-NET", "dst_iplists"), found)
        self.assertIn(("DATABASE-SVC", "services"), found)
        self.assertEqual(summary[-1], {
            "searched item": "MISSING", "status": "NOT_USED_IN_ANY_RULE", "matching rules": 0,
        })

    def test_port_and_range_queries_intersect_explicit_and_named_services(self):
        rows = []
        for href, services in (("/rules/1", "20-25 TCP"), ("/rules/2", "ADMIN-SVC")):
            raw = {"rule_href": href, "ruleset_href": "/rulesets/1", "services": services}
            rows.append({**raw, "raw_json": json.dumps(raw), "snapshot_at": "now"})
        catalog = {"admin-svc": ("ADMIN-SVC", "3389 TCP;161 UDP")}
        all_raw = {"rule_href": "/rules/3", "ruleset_href": "/rulesets/1", "services": "All Services"}
        rows.append({**all_raw, "raw_json": json.dumps(all_raw), "snapshot_at": "now"})
        results, _ = search_latest_rules(rows, ["TCP/22", "3389", "UDP/160-162"], catalog)
        matched = {(row["searched item"], row["rule_href"], row["match details"]) for row in results}
        self.assertIn(("TCP/22", "/rules/1", "TCP/22"), matched)
        self.assertIn(("3389", "/rules/2", "TCP/3389"), matched)
        self.assertIn(("UDP/160-162", "/rules/2", "UDP/161"), matched)
        self.assertIn(("TCP/22", "/rules/3", "TCP/22"), matched)

    def test_case_sensitive_text_search_is_optional(self):
        raw = {"rule_href": "/r", "ruleset_href": "/rs", "src_labels": "app:APP_A"}
        rule = {**raw, "raw_json": json.dumps(raw), "snapshot_at": "now"}
        insensitive, _ = search_latest_rules([rule], ["app_a"], {}, False)
        sensitive, _ = search_latest_rules([rule], ["app_a"], {}, True)
        self.assertEqual(insensitive[0]["status"], "FOUND")
        self.assertEqual(sensitive[0]["status"], "NOT_USED_IN_ANY_RULE")


if __name__ == "__main__":
    unittest.main()
