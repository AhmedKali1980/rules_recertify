import unittest
from rules_recertify.workloader.batching import RulesetCount, OversizedRulesetError, bin_pack_rulesets

class BatchingTest(unittest.TestCase):
    def test_batches_never_exceed_limit(self):
        batches = bin_pack_rulesets([RulesetCount("a", 300), RulesetCount("b", 200), RulesetCount("c", 200)], 500)
        self.assertTrue(all(sum(x.count for x in batch) <= 500 for batch in batches))
        self.assertEqual(sum(len(x) for x in batches), 3)
    def test_oversized_ruleset_fails(self):
        with self.assertRaises(OversizedRulesetError): bin_pack_rulesets([RulesetCount("a", 501)], 500)
