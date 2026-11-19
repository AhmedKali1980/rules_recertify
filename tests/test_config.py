import json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from rules_recertify.config import ConfigurationError, load_dotenv, load_settings

class ConfigTest(unittest.TestCase):
    def test_traffic_window_is_exactly_seven_days(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"c.json"
            path.write_text(json.dumps({"pce":"p","traffic_window_days":6}))
            with self.assertRaisesRegex(ConfigurationError,"must be 7"):
                load_settings(path,Path(directory)/"missing.env")

    def test_minimum_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"c.json"; p.write_text(json.dumps({"pce":"p","retention_days":549}))
            with self.assertRaises(ConfigurationError): load_settings(p)
    def test_production_retention_and_weekly_window_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"c.json"; path.write_text(json.dumps({"pce":"p"}))
            settings=load_settings(path)
            self.assertEqual(settings.traffic_window_days, 7)
            self.assertEqual(settings.retention_days, 550)
            self.assertEqual(settings.default_lookback_days, 548)
    def test_dotenv_does_not_execute_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/".env"; p.write_text("SAFE=$(touch /tmp/must-not-exist)\n"); p.chmod(0o600)
            loaded=load_dotenv(p)
            self.assertEqual(loaded["SAFE"], "$(touch /tmp/must-not-exist)")
    def test_dotenv_accepts_readable_modes_and_preserves_permissions_and_environment(self):
        key = "RULES_RECERTIFY_DOTENV_PERMISSION_TEST"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(f"{key}=from-file\n", encoding="utf-8")
            with patch.dict(os.environ, {key: "already-set"}):
                for mode in (0o600, 0o640, 0o660, 0o644):
                    with self.subTest(mode=oct(mode)):
                        path.chmod(mode)
                        self.assertEqual(load_dotenv(path), {key: "from-file"})
                        self.assertEqual(path.stat().st_mode & 0o777, mode)
                        self.assertEqual(os.environ[key], "already-set")

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0,
                     "requires unprivileged POSIX file access")
    def test_dotenv_keeps_os_read_access_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("EXAMPLE=not-a-secret\n", encoding="utf-8")
            path.chmod(0o000)
            try:
                with self.assertRaises(PermissionError):
                    load_dotenv(path)
            finally:
                path.chmod(0o600)
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
    def test_permissive_rule_threshold_must_be_positive(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"c.json"
            path.write_text(json.dumps({"pce":"p","permissive_rule_max_ips":0}))
            with self.assertRaisesRegex(ConfigurationError, "permissive_rule_max_ips"):
                load_settings(path)
    def test_traffic_environments_accept_list_or_comma_separated_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            list_path=root/"list.json"
            list_path.write_text(json.dumps({"pce":"p","traffic_environments":["PRD","BCK"]}))
            self.assertEqual(load_settings(list_path).traffic_environments, ("PRD", "BCK"))
            text_path=root/"text.json"
            text_path.write_text(json.dumps({"pce":"p","traffic_environments":"PRD, DRP"}))
            self.assertEqual(load_settings(text_path).traffic_environments, ("PRD", "DRP"))
    def test_traffic_environments_reject_blank_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"c.json"
            path.write_text(json.dumps({"pce":"p","traffic_environments":["PRD",""]}))
            with self.assertRaisesRegex(ConfigurationError,"traffic_environments"):
                load_settings(path)
