import importlib.util
import io
import unittest
from contextlib import closing
from pathlib import Path
from zipfile import ZipFile

if importlib.util.find_spec("openpyxl"):
    from openpyxl import load_workbook

import test_compliance_modes as fixtures
from rules_recertify.reporting.compliance import RULE_FIELDS, _iplist_names
from rules_recertify.reporting.compliance_schema import RULE_ID, RULE_STATUS
from rules_recertify.workloader.csvio import read_rows


@unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
class ComplianceFormattingTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ComplianceModesTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def profiles(self):
        profile = self.fixture.root / "formatting.conf"
        profile.write_text("[rule-id]\nvisibility=true\n[Usage Status]\nvisibility=true\n"
                           "[sheet:iplists]\nvisibility=true\n[column:iplists:name]\nvisibility=true\n"
                           "[column:iplists:include]\nvisibility=true\n[column:iplists:exclude]\nvisibility=true\n"
                           "[column:iplists:fqdns]\nvisibility=true\n"
                           "[sheet:workloads]\nvisibility=true\n[column:workloads:name]\nvisibility=true\n")
        return ({}, {"debug": True}, {"custom_headers_path": profile})

    def test_names_keep_literal_parentheses_and_remove_only_trailing_iplist_hrefs(self):
        name = "SUB_SGCIB Development 2 Network (VRF SGCIB)"
        suffix = " (/orgs/1/sec_policy/draft/ip_lists/2672)"
        self.assertEqual(_iplist_names(f"IP List: {name}{suffix};Alpha (corp) (VRF 2)\nZulu (test)"),
                         [name, "Alpha (corp) (VRF 2)", "Zulu (test)"])
        self.assertEqual(_iplist_names(name), [name])
        self.assertEqual(_iplist_names("Name (/orgs/1/ip_lists/2)"), ["Name"])

    def test_iplist_exact_lookup_sorted_names_multiline_entries_and_row_height_in_all_modes(self):
        fx = self.fixture
        name = "SUB_SGCIB Development 2 Network (VRF SGCIB)"
        fx.rules[0]["dst_iplists"] = f"Zulu;IP List: {name} (/orgs/1/sec_policy/draft/ip_lists/2672);Alpha (corp)"
        for rule in fx.rules:
            rule["src_iplists"] = ""
        fx.write("rules_inventory.csv", RULE_FIELDS, fx.rules)
        include = "192.16.0.0/16#SUBNET FRANCE;192.160.79.136#MONSERVEUR;2001:db8::/64 # IPv6;10.0.0.0/24 # corp, Paris;"
        exclude = "10.0.0.7#server;\r\n10.0.0.8 # other;#comment-only;"
        fx.write("export_iplists.csv", ("name", "include", "exclude", "fqdns"), [
            {"name": "Zulu", "include": "203.0.113.1"},
            {"name": name, "include": include, "exclude": exclude, "fqdns": "example.test;other.test"},
            {"name": "SUB_SGCIB Development 2 Network", "include": "WRONG PREFIX CONTENT"},
            {"name": "Alpha (corp)", "include": "198.51.100.1"},
        ])
        for options in self.profiles():
            with self.subTest(options=options):
                fx.generate(**options)
                with closing(load_workbook(fx.output)) as book:
                    rows = fx.rows(book, "iplists")
                    self.assertEqual([row["name"] for row in rows], ["Alpha (corp)", name, "Zulu"])
                    row = rows[1]
                    self.assertEqual(row["include"], "192.16.0.0/16\n192.160.79.136\n2001:db8::/64\n10.0.0.0/24")
                    self.assertEqual(row["exclude"], "10.0.0.7\n10.0.0.8")
                    if "fqdns" in row:
                        self.assertEqual(row["fqdns"], "example.test\nother.test")
                    self.assertGreater(book["iplists"].row_dimensions[3].height, 30)
                    self.assertTrue(all(cell.alignment.wrap_text for cell in book["iplists"][3]))

    def sorted_data(self):
        fx = self.fixture
        records = (("A", "PRD", "K-Z", "M-Z", 4), ("B", "UAT", "K-A", "M-B", 3),
                   ("D", "PRD", "K-A", "M-A", 2), ("C", "DEV", "K-A", "M-A", 1))
        fx.source.write_text("app,env,Kear Id,Module,Entity\n" + "".join(
            f"{app},{env},{kear},{module},E\n" for app, env, kear, module, _ in records
        ))
        rules = []
        for app, env, _, _, number in records:
            for infra in (True, False):
                rules.append(dict(fx.rules[0], ruleset_name="GLOBAL_APP" if infra else "APP",
                                  ruleset_scope=f"app:{app};env:{env}", src_labels="role:WEB", dst_iplists="EDGE",
                                  src_all_workloads="true" if app == "A" else "false",
                                  unscoped_consumers="true" if app == "A" else "false",
                                  rule_enabled="false" if app in ("B", "C") else "true",
                                  rule_href=f"/rule_sets/7/sec_rules/{number + (100 if infra else 0)}"))
        fx.write("rules_inventory.csv", RULE_FIELDS, rules)
        workloads = []
        for app, env, loc, os_name, hostname, created, name in (
            ("D", "PRD", "LON", "linux", "d", "2026-01-01", "d"),
            ("A", "UAT", "LON", "linux", "h1", "2026-01-01", "a-uat"),
            ("A", "PRD", "PAR", "linux", "h1", "2026-01-01", "a-par"),
            ("A", "PRD", "LON", "windows", "h1", "2026-01-01", "a-windows"),
            ("A", "PRD", "LON", "linux", "h2", "2026-01-01", "a-linux-host2"),
            ("A", "PRD", "LON", "linux", "h1", "2026-02-01", "a-linux-late"),
            ("A", "PRD", "LON", "linux", "h1", "2026-01-01", "a-linux-early"),
            ("A", "DEV", "LON", "linux", "h1", "2026-01-01", "a-dev"),
        ):
            workloads.append(dict(fx.workloads[0], app=app, env=env, loc=loc, os_id=os_name,
                                  hostname=hostname, created_at=created, name=name))
        fx.write("export_wkld.csv", tuple(workloads[0]), workloads)

    def test_rule_and_workload_sorts_and_disabled_grey_survive_hidden_keys_and_status(self):
        fx = self.fixture
        self.sorted_data()
        for options in self.profiles():
            with self.subTest(options=options):
                fx.generate(**options)
                with closing(load_workbook(fx.output)) as book:
                    for name, offset in (("Business Rules", 0), ("Infra Rules", 100)):
                        rows = fx.rows(book, name)
                        self.assertEqual([row[RULE_ID] for row in rows], [f"7-{i + offset}" for i in (1, 2, 3, 4)])
                        sheet = book[name]
                        for index in (2, 4):
                            self.assertTrue(all(cell.fill.fgColor.rgb == "00ECECEC" for cell in sheet[index]))
                        grey_rule = next(rule for item in sheet.conditional_formatting for rule in sheet.conditional_formatting[item]
                                         if rule.type == "expression" and rule.stopIfTrue)
                        self.assertEqual(grey_rule.priority, 1)
                        self.assertEqual(grey_rule.dxf.fill.fgColor.rgb, "00ECECEC")
                        if "custom_headers_path" in options:
                            self.assertNotIn(RULE_STATUS, next(sheet.values))
                            self.assertEqual(grey_rule.formula, ["TRUE"])
                            self.assertEqual(sheet.max_column, 2)
                    self.assertEqual([row["name"] for row in fx.rows(book, "workloads")],
                                     ["a-dev", "a-linux-early", "a-linux-late", "a-linux-host2",
                                      "a-windows", "a-par", "a-uat", "d"])

    def test_two_blue_header_shades_alternate_groups_with_striped_rows_and_disabled_grey(self):
        fx = self.fixture
        anchors = ("Kear Id (Scope)", RULE_ID, "Usage Status", "PORTS_TO_CONTROL Hit Ports",
                   "PORTS_TO_ERADICATE Hit Ports", "PORTS_ADMIN Hit Ports")
        profile = fx.root / "groups.conf"
        profile.write_text("".join(f"[{name}]\nvisibility=true\n" for name in anchors))
        expected = None
        for options in ({}, {"debug": True}, {"custom_headers_path": profile}):
            fx.generate(**options)
            with closing(load_workbook(fx.output)) as book:
                sheet = book["Business Rules"]
                headers = next(sheet.values)
                colors = [sheet.cell(1, headers.index(name) + 1).fill.fgColor.rgb for name in anchors]
                self.assertEqual(len(set(colors)), 2)
                self.assertEqual(colors[::2], [colors[0]] * 3)
                self.assertEqual(colors[1::2], [colors[1]] * 3)
                table = next(iter(sheet.tables.values()))
                self.assertEqual(table.tableStyleInfo.name, "TableStyleMedium2")
                self.assertTrue(table.tableStyleInfo.showRowStripes)
                self.assertFalse(table.tableStyleInfo.showColumnStripes)
                self.assertTrue(all(sheet.cell(2, headers.index(name) + 1).fill.patternType is None for name in anchors))
                if expected is None:
                    expected = colors
                self.assertEqual(colors, expected)
                self.assertTrue(all(cell.fill.fgColor.rgb == "00ECECEC" for cell in sheet[3]))
                if RULE_ID in headers:
                    cell = sheet.cell(3, headers.index(RULE_ID) + 1)
                    self.assertEqual((cell.number_format, cell.alignment.horizontal), ("@", "right"))

    def test_reference_widths_fit_long_entries_from_every_row_and_fqdns_are_multiline(self):
        fx = self.fixture
        self.sorted_data()
        workloads = list(read_rows(fx.snapshot / "export_wkld.csv"))
        base = workloads[0]
        workloads.extend(dict(base, app="A", name=f"filler-{i:03}", hostname=f"filler-{i:03}") for i in range(260))
        long_values = dict(base, app="ZZZ_" + "APPLICATION_" * 8, hostname="hostname-" + "long-name-" * 12,
                           os_id="EnterpriseOperatingSystem_" * 3, external_data_reference="asset:" + "R" * 100,
                           name="last-long-record")
        workloads.append(long_values)
        fx.write("export_wkld.csv", tuple(workloads[0]), workloads)
        ip_name = "NETWORK (VRF " + "FRANCE_" * 12 + ")"
        rules = list(read_rows(fx.snapshot / "rules_inventory.csv"))
        for rule in rules:
            rule["dst_iplists"] = ip_name
        fx.write("rules_inventory.csv", RULE_FIELDS, rules)
        fqdn = "service-" + "x" * 60 + ".example.test"
        include = "192.168.10.2#MONSERVEUR;192.18.10.0/24#SUBNET FRANCE;"
        fx.write("export_iplists.csv", ("name", "include", "exclude", "fqdns"), [
            {"name": ip_name, "include": include, "exclude": "# no exclusion",
             "fqdns": fqdn + ";*.example.test;second.example.test;"},
        ])
        for options in ({}, {"debug": True}, {"custom_headers_path": Path("config/headers.conf")}):
            fx.generate(**options)
            with closing(load_workbook(fx.output)) as book:
                ip_sheet = book["iplists"]
                ip_headers = next(ip_sheet.values)
                row = fx.rows(book, "iplists")[0]
                self.assertEqual(row["include"], "192.168.10.2\n192.18.10.0/24")
                self.assertIsNone(row["exclude"])
                self.assertEqual(row["fqdns"], fqdn + "\n*.example.test\nsecond.example.test")
                for name, value in (("name", ip_name), ("fqdns", fqdn)):
                    letter = ip_sheet.cell(1, ip_headers.index(name) + 1).column_letter
                    self.assertGreaterEqual(ip_sheet.column_dimensions[letter].width, len(value) + 2)
                    self.assertTrue(ip_sheet.column_dimensions[letter].bestFit)
                self.assertGreaterEqual(ip_sheet.row_dimensions[2].height, 42)
                wkld_sheet = book["workloads"]
                wkld_headers = next(wkld_sheet.values)
                self.assertGreater(wkld_sheet.max_row, 250)
                self.assertEqual(fx.rows(book, "workloads")[-1]["name"], "last-long-record")
                for name in ("app", "hostname", "OS", "external_data_reference"):
                    value = long_values["os_id" if name == "OS" else name]
                    letter = wkld_sheet.cell(1, wkld_headers.index(name) + 1).column_letter
                    self.assertGreaterEqual(wkld_sheet.column_dimensions[letter].width, len(value) + 2)
                    self.assertTrue(wkld_sheet.column_dimensions[letter].bestFit)
        self.assertEqual(list(read_rows(fx.snapshot / "export_iplists.csv"))[0]["include"], include)

    def test_default_user_flags_follow_rule_type_and_keep_existing_calculations(self):
        fx = self.fixture
        fx.rules[0]["dst_iplists"] = "U_USER_NETWORK"
        fx.rules[1]["src_iplists"] = "USR_STAFF_NETWORK"
        fx.write("rules_inventory.csv", RULE_FIELDS, fx.rules)
        fx.generate()
        with closing(load_workbook(fx.output)) as book:
            headers = next(book["Business Rules"].values)
            index = headers.index("rule_type")
            self.assertEqual(headers[index + 1:index + 3], ("Source contains User", "Destination contains User"))
            rows = {row[RULE_ID]: row for row in fx.rows(book, "Business Rules")}
            self.assertEqual((rows["11155-101899"]["Source contains User"], rows["11155-101899"]["Destination contains User"]),
                             ("FALSE", "TRUE"))
            self.assertEqual((rows["11155-101900"]["Source contains User"], rows["11155-101900"]["Destination contains User"]),
                             ("TRUE", "FALSE"))
            self.assertEqual(book["Business Rules"].cell(1, index + 1).fill.fgColor.rgb,
                             book["Business Rules"].cell(1, index + 2).fill.fgColor.rgb)

    def test_previous_counter_header_remains_a_profile_alias(self):
        fx = self.fixture
        profile = fx.root / "old-counter.conf"
        profile.write_text("[Number impacted App servers (Scope)]\nvisibility=true\n")
        fx.generate(custom_headers_path=profile)
        with closing(load_workbook(fx.output)) as book:
            self.assertEqual(next(book["Business Rules"].values), ("Number of impacted App servers (Scope)",))

    def test_split_workbooks_preserve_sort_styles_and_text_ids(self):
        fx = self.fixture
        self.sorted_data()
        fx.write("export_iplists.csv", ("name", "include", "exclude", "fqdns"), [
            {"name": "EDGE", "include": "192.0.2.1#SERVER;192.0.2.0/24#SUBNET",
             "exclude": "192.0.2.7#EXCLUDED", "fqdns": "a.example.test;b.example.test"},
        ])
        fx.output = fx.root / "sorted.zip"
        fx.generate(split_by_kear_id=True, timestamp="20261125T120000Z")
        with ZipFile(fx.output) as archive:
            for kear, ids in (("K-A", (1, 2, 3)), ("K-Z", (4,))):
                with closing(load_workbook(io.BytesIO(archive.read(f"E/compliance_{kear}_20261125T120000Z.xlsx")))) as book:
                    self.assertEqual([row[RULE_ID] for row in fx.rows(book, "Business Rules")], [f"7-{i}" for i in ids])
                    headers = next(book["Business Rules"].values)
                    cell = book["Business Rules"].cell(2, headers.index(RULE_ID) + 1)
                    self.assertEqual((cell.data_type, cell.alignment.horizontal), ("s", "right"))
                    if kear == "K-A":
                        self.assertEqual(cell.fill.fgColor.rgb, "00ECECEC")
                    ip_row = fx.rows(book, "iplists")[0]
                    self.assertEqual(ip_row["include"], "192.0.2.1\n192.0.2.0/24")
                    self.assertEqual(ip_row["exclude"], "192.0.2.7")
                    self.assertEqual(ip_row["fqdns"], "a.example.test\nb.example.test")
