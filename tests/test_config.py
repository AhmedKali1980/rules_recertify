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
