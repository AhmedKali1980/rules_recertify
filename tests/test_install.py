import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class ProductionInstallerTest(unittest.TestCase):
    def test_install_and_upgrade_preserve_local_state(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "rules_recertify"
            environment = dict(os.environ)
            environment.update({
                "RULES_RECERTIFY_HOME": str(target),
                "RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME": "1",
            })
            subprocess.run(["bash", "scripts/install-prod.sh"], check=True, env=environment,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertTrue((target / "src/rules_recertify/cli.py").is_file())
            self.assertTrue((target / "setup.py").is_file())
            self.assertEqual((target / ".env").stat().st_mode & 0o777, 0o600)
            (target / ".env").write_text("PCE=preserved\n", encoding="utf-8")
            (target / "config/local.json").write_text('{"preserved": true}\n', encoding="utf-8")
            (target / "var/state/sentinel").write_text("state", encoding="utf-8")
            subprocess.run(["bash", "scripts/install-prod.sh"], check=True, env=environment,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual((target / ".env").read_text(encoding="utf-8"), "PCE=preserved\n")
            self.assertIn("preserved", (target / "config/local.json").read_text(encoding="utf-8"))
            self.assertEqual((target / "var/state/sentinel").read_text(encoding="utf-8"), "state")
