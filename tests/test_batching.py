import unittest
from rules_recertify.workloader.batching import (
    ExcludedRuleset,
    RulesetCount,
    OversizedRulesetError,
    bin_pack_rulesets,
    partition_and_pack_rulesets,
    select_application_scoped_rulesets,
)

class BatchingTest(unittest.TestCase):
    def test_batches_never_exceed_limit(self):
        batches = bin_pack_rulesets([RulesetCount("a", 300), RulesetCount("b", 200), RulesetCount("c", 200)], 500)
        self.assertTrue(all(sum(x.count for x in batch) <= 500 for batch in batches))
        self.assertEqual(sum(len(x) for x in batches), 3)
    def test_oversized_ruleset_fails(self):
        with self.assertRaises(OversizedRulesetError): bin_pack_rulesets([RulesetCount("a", 501)], 500)

    def test_partition_skips_only_rulesets_above_limit(self):
        batches, skipped = partition_and_pack_rulesets(
            [
                RulesetCount("exact", 100),
                RulesetCount("small-a", 60),
                RulesetCount("small-b", 40),
                RulesetCount("too-large", 101),
            ],
            100,
        )
        self.assertEqual(skipped, [RulesetCount("too-large", 101)])
        self.assertTrue(
            all(sum(item.count for item in batch) <= 100 for batch in batches)
        )
        self.assertEqual(
            {item.href for batch in batches for item in batch},
            {"exact", "small-a", "small-b"},
        )

    def test_only_known_application_scopes_are_selected(self):
        eligible, excluded = select_application_scoped_rulesets(
            [
                {"ruleset_href": "/valid", "ruleset_scope": "app:APP_A;env:PRD"},
                {"ruleset_href": "/empty", "ruleset_scope": ""},
                {"ruleset_href": "/group", "ruleset_scope": "label_group:1"},
                {"ruleset_href": "/unknown", "ruleset_scope": "app:APP_X;env:PRD"},
            ],
            ["APP_A"],
        )
        self.assertEqual(eligible, [RulesetCount("/valid", 1)])
        self.assertEqual(
            excluded,
            [
                ExcludedRuleset("/empty", 1, "", "EMPTY_SCOPE"),
                ExcludedRuleset("/group", 1, "label_group:1", "INVALID_SCOPE_FORMAT"),
                ExcludedRuleset(
                    "/unknown", 1, "app:APP_X;env:PRD", "UNKNOWN_APPLICATION_LABEL"
                ),
            ],
        )

    def test_scope_dimension_order_does_not_affect_selection(self):
        eligible, excluded = select_application_scoped_rulesets(
            [
                {
                    "ruleset_href": "/env-first",
                    "ruleset_scope": "env:PRD;app:APP_A",
                },
                {
                    "ruleset_href": "/app-first",
                    "ruleset_scope": "app:APP_A;env:PRD",
                },
            ],
            ["APP_A"],
        )
        self.assertEqual(
            eligible,
            [RulesetCount("/app-first", 1), RulesetCount("/env-first", 1)],
        )
        self.assertEqual(excluded, [])

    def test_scope_still_requires_exactly_application_and_environment(self):
        eligible, excluded = select_application_scoped_rulesets(
            [
                {"ruleset_href": "/app-only", "ruleset_scope": "app:APP_A"},
                {
                    "ruleset_href": "/extra",
                    "ruleset_scope": "env:PRD;app:APP_A;loc:PAR",
                },
            ],
            ["APP_A"],
        )
        self.assertEqual(eligible, [])
        self.assertEqual(
            excluded,
            [
                ExcludedRuleset("/app-only", 1, "app:APP_A", "INVALID_SCOPE_FORMAT"),
                ExcludedRuleset(
                    "/extra", 1, "env:PRD;app:APP_A;loc:PAR", "INVALID_SCOPE_FORMAT"
                ),
            ],
        )
