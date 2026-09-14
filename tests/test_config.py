import json, os, tempfile, unittest
from pathlib import Path
from rules_recertify.config import ConfigurationError, load_dotenv, load_settings

class ConfigTest(unittest.TestCase):
    def test_minimum_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"c.json"; p.write_text(json.dumps({"pce":"p","retention_days":199}))
            with self.assertRaises(ConfigurationError): load_settings(p)
    def test_dotenv_does_not_execute_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/".env"; p.write_text("SAFE=$(touch /tmp/must-not-exist)\n"); p.chmod(0o600)
            loaded=load_dotenv(p)
            self.assertEqual(loaded["SAFE"], "$(touch /tmp/must-not-exist)")
    def test_rate_limit_retry_delay_is_at_least_ten_minutes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"c.json"
            path.write_text(json.dumps({"pce":"p","rate_limit_retry_delay_minutes":9}))
            with self.assertRaises(ConfigurationError): load_settings(path)
    def test_empty_scope_patterns_must_be_non_empty_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"c.json"
            path.write_text(json.dumps({"pce":"p","empty_scope_ruleset_name_patterns":[""]}))
            with self.assertRaises(ConfigurationError): load_settings(path)
    def test_dangerous_port_lists_accept_comma_separated_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"c.json"
            path.write_text(json.dumps({"pce":"p","dangerous_port_lists":"PORTS_TO_CONTROL,PORTS_ADMIN"}))
            settings=load_settings(path)
            self.assertEqual(settings.dangerous_port_lists, ("PORTS_TO_CONTROL", "PORTS_ADMIN"))
    def test_unknown_dangerous_port_list_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"c.json"
            path.write_text(json.dumps({"pce":"p","dangerous_port_lists":["UNKNOWN"]}))
            with self.assertRaisesRegex(ConfigurationError, "unknown dangerous_port_lists"):
                load_settings(path)
