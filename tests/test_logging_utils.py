import json
import logging
import unittest

from rules_recertify.logging_utils import JsonFormatter


class LoggingUtilsTest(unittest.TestCase):
    def test_ruleset_selection_fields_are_serialized(self):
        record = logging.LogRecord(
            "rules_recertify.collection",
            logging.INFO,
            __file__,
            1,
            "Traffic ruleset selected",
            (),
            None,
        )
        record.selection = "SELECTED"
        record.batch = 2
        record.ruleset_href = "/orgs/1/rule_sets/42"
        record.ruleset_name = "APP-RS"
        record.ruleset_scope = "app:APP;env:PRD"
        record.rule_count = 12

        payload = json.loads(JsonFormatter().format(record))

        self.assertEqual(payload["selection"], "SELECTED")
        self.assertEqual(payload["batch"], 2)
        self.assertEqual(payload["ruleset_name"], "APP-RS")
        self.assertEqual(payload["rule_count"], 12)
