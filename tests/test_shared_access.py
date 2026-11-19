import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

if os.name == "posix":
    import grp
    import pwd


PROBE = r'''
import json, os
from pathlib import Path
from rules_recertify.history.database import Database
root = Path(os.environ["RULES_RECERTIFY_PROBE_ROOT"])
mask = os.umask(0)
os.umask(mask)
path = root / "var/state/probe.sqlite"
database = Database(path)
database.initialize()
database.upsert_rules([{
    "rule_href": "/rules/shared", "ruleset_href": "/rulesets/shared", "ruleset_name": "SHARED",
    "ruleset_scope": "app:APM_TEST_SHARED;env:PRD", "rule_type": "allow", "rule_enabled": "true",
    "src_labels": "app:APM_TEST_SHARED;env:PRD", "dst_iplists": "EXTERNAL", "services": "443 TCP",
}], "2026-01-01T00:00:00Z")
connection = database.connect()
connection.execute("CREATE TABLE IF NOT EXISTS group_probe(value TEXT)")
connection.execute("INSERT INTO group_probe VALUES('example')")
connection.commit()
output = root / "var/output/new/report.txt"
output.parent.mkdir()
output.write_text("example")
log = root / "var/logs/probe.jsonl"
log.write_text("{}\n")
paths = [path, Path(str(path)+"-wal"), Path(str(path)+"-shm"), output, log]
print(json.dumps({"umask": mask, "modes": [p.stat().st_mode & 0o777 for p in paths],
                  "groups": [p.stat().st_gid for p in paths],
                  "output_directory_mode": output.parent.stat().st_mode & 0o7777}))
connection.close()
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux group permissions")
class SharedAccessTest(unittest.TestCase):
    def install(self, target, shared=False):
        environment = dict(os.environ)
        environment.pop("RULES_RECERTIFY_SHARED_GROUP", None)
        environment.update({
            "RULES_RECERTIFY_HOME": str(target), "RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME": "1",
            "RULES_RECERTIFY_OWNER": pwd.getpwuid(os.getuid()).pw_name,
            "RULES_RECERTIFY_GROUP": grp.getgrgid(os.getgid()).gr_name,
        })
        if shared:
            environment["RULES_RECERTIFY_SHARED_GROUP"] = grp.getgrgid(os.getgid()).gr_name
        subprocess.run(["bash", "scripts/install-prod.sh"], env=environment, check=True,
                       capture_output=True, text=True, timeout=30)

    def probe(self, root, target):
        fake = root / "probe-bin"
        fake.mkdir()
        executable = fake / "python3"
        executable.write_text(f"#!{sys.executable}\n" + PROBE)
        executable.chmod(0o755)
        environment = dict(os.environ)
        environment["PATH"] = str(fake) + os.pathsep + environment.get("PATH", "")
        environment["RULES_RECERTIFY_PROBE_ROOT"] = str(target)
        result = subprocess.run([
            "bash", "-c", 'umask 077\nexec "$1"', "probe", str(target / "scripts/rules-recertify"),
        ], cwd=target, env=environment, check=True, capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout)

    def test_shared_upgrade_repairs_runtime_modes_and_remembers_group(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment"
            self.install(target)
            env_file = target / ".env"
            env_file.write_text("# preserved\n")
            env_file.chmod(0o660)
            paths = [target / "var/state/test.sqlite", target / "var/state/test.sqlite-wal",
                     target / "var/state/test.sqlite-shm", target / "var/logs/old.jsonl",
                     target / "var/output/old.txt"]
            for path in paths:
                path.write_text("preserved")
                path.chmod(0o600)
            snapshot = target / "var/raw/snapshot"
            snapshot.mkdir(mode=0o750)
            reference = snapshot / "reference.csv"
            reference.write_text("preserved")
            reference.chmod(0o600)
            self.install(target, shared=True)
            for relative in ("var/state", "var/output", "var/logs", "var/raw", "var/raw/archives"):
                self.assertEqual((target / relative).stat().st_mode & 0o7777, 0o2770)
            for path in paths:
                self.assertEqual(path.stat().st_mode & 0o060, 0o060)
                self.assertEqual(path.read_text(), "preserved")
                self.assertEqual(path.stat().st_gid, os.getgid())
            self.assertEqual(reference.stat().st_mode & 0o060, 0o040)
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o660)
            self.assertEqual(env_file.read_text(), "# preserved\n")
            marker = target / "var/.shared-group"
            self.assertEqual(marker.read_text().strip(), grp.getgrgid(os.getgid()).gr_name)
            self.install(target)
            self.assertTrue(marker.is_file())
            self.assertEqual((target / "var/state").stat().st_mode & 0o7777, 0o2770)

    def test_shared_launcher_creates_group_writable_sqlite_auxiliary_and_output_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "deployment"
            self.install(target, shared=True)
            self.assertEqual((target / ".env").stat().st_mode & 0o777, 0o640)
            result = self.probe(root, target)
            self.assertEqual(result["umask"], 0o007)
            self.assertEqual(result["modes"], [0o660] * 5)
            self.assertEqual(result["groups"], [os.getgid()] * 5)
            self.assertEqual(result["output_directory_mode"], 0o2770)
            config = target / "config/local.json"
            config.write_text(json.dumps({
                "pce": "offline", "state_db": str(target / "var/state/probe.sqlite"),
                "log_dir": str(target / "var/logs"), "raw_dir": str(target / "var/raw"),
                "output_dir": str(target / "var/output"),
            }))
            environment = dict(os.environ)
            for key in ("STATE_DB", "PCE", "WORKLOADER_DIR", "WORKLOADER_CONFIG_FILE"):
                environment.pop(key, None)
            subprocess.run([str(target / "scripts/rules-recertify"), "--config", str(config),
                            "--env-file", str(target / ".env"), "init-db"], cwd=target,
                           env=environment, check=True, capture_output=True, text=True, timeout=30)
            self.assertEqual((target / "var/state/probe.sqlite").stat().st_mode & 0o777, 0o660)
            from openpyxl import Workbook, load_workbook
            from rules_recertify.reporting.microcosmos import REQUIRED_COLUMNS
            workbook = Workbook()
            workbook.active.append(list(REQUIRED_COLUMNS))
            row = {"Kear Id": "K-SHARED", "Application Name": "Shared test", "Module": "SHARED",
                   "Environment": "PRD", "Entity": "TEST"}
            workbook.active.append([row.get(field, "") for field in REQUIRED_COLUMNS])
            microcosmos = target / "input.xlsx"
            workbook.save(microcosmos)
            workbook.close()
            result = subprocess.run([
                str(target / "scripts/rules-recertify"), "--config", str(config),
                "--env-file", str(target / ".env"), "report-batch",
                "--microcosmos-xlsx", str(microcosmos), "--lookback-days", "120",
            ], cwd=target, env=environment, check=True, capture_output=True, text=True, timeout=30)
            outputs = [Path(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(outputs), 2, result.stdout + result.stderr)
            report_count = 0
            for output in outputs:
                self.assertEqual(output.stat().st_mode & 0o777, 0o660)
                self.assertEqual(output.stat().st_gid, os.getgid())
                report = load_workbook(output, read_only=True)
                try:
                    if "Raw Rules" in report.sheetnames:
                        self.assertEqual(report["Raw Rules"].max_row, 2)
                        report_count += 1
                finally:
                    report.close()
            self.assertEqual(report_count, 1)
            for log in (target / "var/logs").glob("rules-recertify-*.jsonl"):
                self.assertEqual(log.stat().st_mode & 0o777, 0o660)

    def test_private_launcher_keeps_callers_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "deployment"
            self.install(target)
            result = self.probe(root, target)
            self.assertEqual(result["umask"], 0o077)
            self.assertEqual(result["modes"], [0o600] * 5)

    def test_collection_wrappers_create_locks_with_shared_group_write_access(self):
        for shared in (False, True):
            with self.subTest(shared=shared), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "deployment"
                self.install(target, shared=shared)
                fake_bin = root / "fake-bin"
                fake_bin.mkdir()
                fake_cli = fake_bin / "python3"
                fake_cli.write_text("#!/usr/bin/env bash\nexit 0\n")
                fake_cli.chmod(0o755)
                environment = dict(os.environ)
                environment.update({
                    "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                    "RULES_RECERTIFY_CLI": str(fake_cli),
                    "RULES_RECERTIFY_VENV": str(target / ".venv"),
                })
                for name in ("daily-policy-collect.sh", "check-collection.sh", "daily-collect.sh"):
                    lock = target / "var/state" / (name + ".lock")
                    environment["RULES_RECERTIFY_LOCK"] = str(lock)
                    subprocess.run([
                        "bash", "-c", 'umask 077\nexec "$1"', "probe", str(target / "scripts" / name),
                    ], cwd=target, env=environment, check=True, capture_output=True, text=True, timeout=30)
                    self.assertEqual(lock.stat().st_mode & 0o777, 0o660 if shared else 0o600, name)
                    self.assertEqual(lock.stat().st_gid, os.getgid())

    def test_unknown_shared_group_is_rejected_before_deployment(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deployment"
            environment = dict(os.environ)
            environment.update({
                "RULES_RECERTIFY_HOME": str(target), "RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME": "1",
                "RULES_RECERTIFY_SHARED_GROUP": f"rules-recertify-absent-{os.getpid()}",
            })
            result = subprocess.run(["bash", "scripts/install-prod.sh"], env=environment,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 64)
            self.assertIn("Unknown shared runtime group", result.stderr)
            self.assertFalse(target.exists())
