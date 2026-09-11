import csv
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from rules_recertify.pce_import import import_pce_exports
from rules_recertify.workloader.reference_exports import (
    ExportContractError, derive_exports, first_ip_list_match, merge_workloads,
    ocs_name_from_ip, parse_ipv4_interfaces, parse_subnets, prepare_ip_lists,
    short_hostname,
)


HEADER = ["href", "hostname", "interfaces", "ip_with_default_gw", "os_id", "managed", "external_data_set"]
WORKLOADER_HEADERS = "href,hostname,name,external_data_set,created_at,interfaces,public_ip,ip_with_default_gw,app,env,loc,role,managed,enforcement,external_data_reference,OS,os_id"


def write_csv(path, header, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=header); writer.writeheader(); writer.writerows(rows)


class ReferenceExportsTest(unittest.TestCase):
    def test_pure_enrichment_rules(self):
        self.assertEqual(short_hostname("my-server.example.net"), "MY-SERVER")
        self.assertEqual(short_hostname(""), "")
        linux = {"managed": " TRUE ", "ip_with_default_gw": "10.20.30.40", "os_id": "linux"}
        windows = {**linux, "os_id": "Windows Server"}
        self.assertEqual(ocs_name_from_ip(linux), "IP-10-20-30-40")
        self.assertEqual(ocs_name_from_ip(windows), "10-20-30-40")
        gen2 = {"managed": "false", "external_data_set": " automation gen2 ", "interfaces": "eth0:192.163.231.75/24"}
        self.assertEqual(ocs_name_from_ip(gen2), "IP-192-163-231-75")
        self.assertEqual(ocs_name_from_ip({"managed": "false", "external_data_set": "other"}), "")

    def test_interfaces_invalid_multiple_and_stable_deduplication(self):
        self.assertEqual(parse_ipv4_interfaces("bad:999.1.2.3; eth0:10.0.0.2/24, rich[10.0.0.3],again=10.0.0.2; ::1"),
                         ["10.0.0.2", "10.0.0.3"])
        self.assertEqual(parse_ipv4_interfaces("invalid"), [])

    def test_subnet_filter_comments_invalid_and_source_priority(self):
        rows = [
            {"name": "OTHER", "include": "10.0.0.0/8"},
            {"name": "NZ3_FIRST", "include": "bad; 10.0.0.7/24 # office;2001:db8::/32"},
            {"name": "NZ3_SECOND", "include": "10.0.0.0/25"},
        ]
        prepared = prepare_ip_lists(rows)
        self.assertEqual([str(x) for x in parse_subnets(rows[1]["include"])], ["10.0.0.0/24"])
        self.assertEqual(first_ip_list_match(["10.0.0.8"], prepared), ("NZ3_FIRST", "10.0.0.0/24"))

    def test_derive_contract_legacy_and_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = HEADER[:-1]
            write_csv(root / "export_wkld.csv", legacy, [{"href": "/1", "hostname": "a.example", "interfaces": "e:10.1.2.3", "ip_with_default_gw": "", "os_id": "", "managed": "false"}])
            write_csv(root / "export_iplists.csv", ["name", "include"], [{"name": "NZ3_A", "include": "10.1.0.0/16"}, {"name": "OTHER", "include": "0.0.0.0/0"}])
            derive_exports(root)
            with (root / "export_wkld.derived.csv").open(newline="") as handle:
                reader = csv.DictReader(handle); row = next(reader)
                self.assertEqual(reader.fieldnames[2], "short_hostname")
                self.assertEqual(reader.fieldnames[-3:], ["ocs_name_from_IP", "IPLIST", "SUBNET"])
                self.assertEqual((row["IPLIST"], row["SUBNET"]), ("NZ3_A", "10.1.0.0/16"))
            with (root / "export_iplists.derived.csv").open(newline="") as handle:
                self.assertEqual(list(csv.DictReader(handle))[0]["name"], "NZ3_A")

    def test_missing_required_workload_column_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_csv(root / "export_wkld.csv", ["hostname"], [])
            write_csv(root / "export_iplists.csv", ["name", "include"], [])
            with self.assertRaisesRegex(ExportContractError, "interfaces"):
                derive_exports(root)

    def test_merge_once_and_reject_mismatched_header(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); one = root / "one.csv"; two = root / "two.csv"
            write_csv(one, ["a", "b"], [{"a": "quoted, value", "b": "1"}])
            write_csv(two, ["a", "b"], [{"a": "next", "b": "2"}, {"a": "", "b": ""}])
            self.assertEqual(merge_workloads(one, two), 1)
            with one.open(newline="") as handle: self.assertEqual(len(list(csv.reader(handle))), 3)
            write_csv(two, ["b", "a"], [])
            with self.assertRaisesRegex(ExportContractError, "strictly identical"):
                merge_workloads(one, two)

    def test_stub_end_to_end_with_spaces_and_no_workloader(self):
        with tempfile.TemporaryDirectory(prefix="reference space ") as directory:
            root = Path(directory); stub = root / "stub files"; raw = root / "raw files"; stub.mkdir()
            row = {"href": "/1", "hostname": "host.example", "interfaces": "e:10.0.0.1", "ip_with_default_gw": "", "os_id": "linux", "managed": "false", "external_data_set": "Automation GEN2"}
            write_csv(stub / "export_wkld.csv", HEADER, [row])
            write_csv(stub / "export_wkld.l3sm.m.csv", HEADER, [{**row, "href": "/2", "managed": "TRUE", "ip_with_default_gw": "10.0.0.2"}])
            write_csv(stub / "export_iplists.csv", ["name", "include"], [{"name": "NZ3_A", "include": "10.0.0.0/24"}])
            import_pce_exports(raw, stub)
            self.assertTrue(all((raw / name).stat().st_size for name in ("export_wkld.csv", "export_iplists.csv", "export_wkld.derived.csv", "export_iplists.derived.csv")))


class WorkloaderShellTest(unittest.TestCase):
    def _run(self, script, env, output):
        return subprocess.run([str(Path("scripts") / script), str(output)], text=True, capture_output=True, env=env)

    def test_profiles_quoting_and_output_retry(self):
        with tempfile.TemporaryDirectory(prefix="shell space ") as directory:
            root = Path(directory); calls = root / "calls"; executable = root / "fake workloader"
            executable.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >> \"$CALLS\"\nout=''\nwhile (($#)); do [[ $1 == --output-file ]] && { shift; out=$1; }; shift || :; done\n[[ ${NO_OUTPUT:-0} == 1 ]] || printf 'h\\n' > \"$out\"\n", encoding="utf-8")
            executable.chmod(executable.stat().st_mode | stat.S_IEXEC)
            cfg = root / "pce config.yaml"; cfg.write_text("l1-profile:\n  fqdn: l1.example.net\nl3-profile:\n  fqdn: l3.example.net\n")
            env = {**os.environ, "EXECUTABLE": str(executable), "CFG": str(cfg), "CALLS": str(calls), "PCE_L1_FQDN": "l1.example.net", "PCE_L3SM_FQDN": "l3.example.net", "MAX_ATTEMPTS": "2", "BASE_SLEEP": "0", "POST_SUCCESS_PAUSE_SEC": "0", "POST_FAILURE_PAUSE_SEC": "0"}
            result = self._run("workloader-wkld-export.sh", env, root / "out file.csv")
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = calls.read_text().splitlines()
            self.assertIn("l1-profile", arguments)
            self.assertEqual(arguments[arguments.index("--headers") + 1], WORKLOADER_HEADERS)
            self.assertNotIn("--columns", arguments)
            calls.write_text(""); result = self._run("workloader-wkld-l3sm-managed-export.sh", env, root / "managed file.csv")
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = calls.read_text().splitlines()
            self.assertIn("l3-profile", arguments)
            self.assertIn("-m", arguments)
            self.assertEqual(arguments[arguments.index("--headers") + 1], WORKLOADER_HEADERS)
            self.assertNotIn("--columns", arguments)
            env.update({"NO_OUTPUT": "1"}); calls.write_text("")
            result = self._run("workloader-ipl-export.sh", env, root / "empty.csv")
            self.assertNotEqual(result.returncode, 0); self.assertEqual(calls.read_text().count("--config-file\n"), 2)

    def test_profiles_are_read_from_workloader_yaml_without_env_duplication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); calls = root / "calls"; executable = root / "workloader"
            executable.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >> \"$CALLS\"\n"
                "while (($#)); do [[ $1 == --output-file ]] && { shift; printf 'header\\n' > \"$1\"; }; shift || :; done\n"
            )
            executable.chmod(0o755)
            cfg = root / "pce.yaml"
            cfg.write_text(
                "default_pce_name: pce-prod-l2\n"
                "pce-l3-sm:\n  fqdn: l3sm.example.invalid\n"
                "pce-prod-l3:\n  fqdn: l3.example.invalid\n  wr:\n    fqdn: l1.example.invalid\n"
                "pce-prod-l2:\n  fqdn: l2.example.invalid\n"
                "target_pce: pce-prod-l3.wr\n"
            )
            env = {**os.environ, "EXECUTABLE": str(executable), "CFG": str(cfg), "CALLS": str(calls),
                   "POST_SUCCESS_PAUSE_SEC": "0"}
            for key in ("PCE_L1_NAME", "PCE_L3SM_NAME", "PCE_L1_FQDN", "PCE_L3SM_FQDN"):
                env.pop(key, None)
            l1 = self._run("workloader-wkld-export.sh", env, root / "l1.csv")
            l3sm = self._run("workloader-wkld-l3sm-managed-export.sh", env, root / "l3sm.csv")
            self.assertEqual((l1.returncode, l3sm.returncode), (0, 0), l1.stderr + l3sm.stderr)
            arguments = calls.read_text().splitlines()
            self.assertIn("pce-prod-l2", arguments)
            self.assertIn("pce-l3-sm", arguments)

    def test_l3sm_without_resolvable_profile_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); executable = root / "never"
            executable.write_text("#!/bin/sh\nexit 99\n"); executable.chmod(0o755)
            cfg = root / "pce.yaml"; cfg.write_text("default:\n  fqdn: l1.example\n")
            env = {**os.environ, "EXECUTABLE": str(executable), "CFG": str(cfg), "POST_FAILURE_PAUSE_SEC": "0"}
            result = self._run("workloader-wkld-l3sm-managed-export.sh", env, root / "out.csv")
            self.assertEqual(result.returncode, 64)

    def test_ambiguous_l3sm_profiles_fail_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); executable = root / "never"
            executable.write_text("#!/bin/sh\nexit 99\n"); executable.chmod(0o755)
            cfg = root / "pce.yaml"; cfg.write_text("pce-l3-sm:\n  fqdn: one.invalid\nbackup-l3sm:\n  fqdn: two.invalid\n")
            env = {**os.environ, "EXECUTABLE": str(executable), "CFG": str(cfg)}
            for key in ("PCE_L3SM_NAME", "PCE_L3SM_FQDN"):
                env.pop(key, None)
            result = self._run("workloader-wkld-l3sm-managed-export.sh", env, root / "out.csv")
            self.assertEqual(result.returncode, 64)
            self.assertIn("Several L3SM profiles", result.stderr)


if __name__ == "__main__": unittest.main()
