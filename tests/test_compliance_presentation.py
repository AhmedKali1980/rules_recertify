import csv
import importlib.util
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from rules_recertify.reporting.compliance import (
    KEAR_NOT_ONBOARDED, LABEL_GROUP_FIELDS, MICROCOSMOS_COLUMNS, RULE_FIELDS,
    _factor_side, _format_ruleset_scope, _label_group_index,
    _rule_relationship, _ruleset_scope_context, generate_compliance_workbook,
)


class CompliancePresentationTest(unittest.TestCase):
    def setUp(self):
        self.local = {"app": "APM_REGION_LOCAL", "Kear Id": "K-LOCAL", "Environment": "PRD"}
        self.remote = {"app": "APM_REGION_REMOTE", "Kear Id": "K-REMOTE", "Environment": "PRD"}
        self.lookup = {"local": {"prd": {"K-LOCAL"}}, "remote": {"prd": {"K-REMOTE"}}}
        self.rule = {**dict.fromkeys(RULE_FIELDS, ""),
                     "ruleset_name": "APP", "ruleset_scope": "env:PRD;app:APM_REGION_LOCAL",
                     "rule_type": "allow", "unscoped_consumers": "TRUE"}

    def test_scope_order_preserves_values_and_other_dimensions(self):
        scope = "env:PRD;loc:PARIS;app:PAYMENTS;role:WEB;role:DB;custom:VALUE"
        self.assertEqual(_format_ruleset_scope(scope, {}),
                         "role:WEB; role:DB; app:PAYMENTS; env:PRD; loc:PARIS; custom:VALUE")
        self.assertEqual(_ruleset_scope_context(scope),
                         "role:WEB, DB; app:PAYMENTS; env:PRD; loc:PARIS")

    def test_side_order_includes_groups_and_exclusions(self):
        groups = _label_group_index([
            {"name": "APPS", "key": "app"}, {"name": "ROLES", "key": "role"},
            {"name": "ENVS", "key": "env"},
        ])
        for prefix in ("src", "dst"):
            with self.subTest(prefix=prefix):
                rule = {f"{prefix}_labels": "env:PRD;app:PAYMENTS;role:WEB",
                        f"{prefix}_label_groups": "APPS;ROLES;ENVS",
                        f"{prefix}_labels_exclusions": "env:DEV;app:OLD;role:RETIRED"}
                self.assertEqual(_factor_side(rule, prefix, groups), (
                    "role:WEB; rolegroup:ROLES; EXCEPT(role:RETIRED); "
                    "app:PAYMENTS; appgroup:APPS; EXCEPT(app:OLD); "
                    "env:PRD; envgroup:ENVS; EXCEPT(env:DEV)", "labels",
                ))

    def test_mixed_remote_group_uses_identified_local_side_for_direction(self):
        groups = _label_group_index([{
            "name": "APPS", "key": "app",
            "member_labels": "app:APM_REGION_LOCAL;app:APM_REGION_REMOTE",
        }])
        for local_side, direction in (("src", "outgoing"), ("dst", "incoming")):
            with self.subTest(local_side=local_side):
                remote_side = "dst" if local_side == "src" else "src"
                rule = {**self.rule, f"{local_side}_labels": "role:WEB",
                        f"{remote_side}_label_groups": "APPS"}
                self.assertEqual(_rule_relationship(rule, self.local, self.lookup, groups), {
                    "kear_remote": "K-REMOTE", "direction": direction,
                    "rule_category": "business_rule", "warning": "",
                })

    def test_unresolved_remote_group_does_not_hide_known_direction(self):
        groups = _label_group_index([{"name": "APPS", "key": "app"}])
        for remote_side, direction in (("dst", "outgoing"), ("src", "incoming")):
            for reference in ("APPS", "appgroup:UNKNOWN"):
                with self.subTest(remote_side=remote_side, reference=reference):
                    local_side = "src" if remote_side == "dst" else "dst"
                    rule = {**self.rule, f"{local_side}_labels": "role:WEB",
                            f"{remote_side}_label_groups": reference}
                    result = _rule_relationship(rule, self.local, self.lookup, groups)
                    self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                                     (direction, "", "REMOTE_KEAR_UNAVAILABLE"))

    def test_multiple_remote_group_members_keep_direction_with_ambiguous_kear(self):
        groups = _label_group_index([{
            "name": "APPS", "key": "app",
            "member_labels": "app:APM_REGION_LOCAL;app:APM_REGION_REMOTE;app:APM_REGION_OTHER",
        }])
        rule = {**self.rule, "src_labels": "role:WEB", "dst_label_groups": "APPS"}
        result = _rule_relationship(rule, self.local, self.lookup, groups)
        self.assertEqual((result["direction"], result["kear_remote"], result["warning"]),
                         ("outgoing", "", "REMOTE_KEAR_AMBIGUOUS"))

    def test_two_unresolved_groups_remain_undetermined(self):
        rule = {**self.rule, "src_labels": "appgroup:UNKNOWN_SRC",
                "dst_labels": "appgroup:UNKNOWN_DST"}
        self.assertEqual(_rule_relationship(rule, self.local, self.lookup)["direction"],
                         "undetermined")

    def test_reversed_outbound2apa_keeps_incoming_and_reports_convention_violation(self):
        rule = {**self.rule, "ruleset_name": "APP_OUTBOUND2APA_PRD", "ruleset_scope": "",
                "src_iplists": "UNMANAGED_NETWORK",
                "dst_labels": "env:PRD;app:APM_REGION_LOCAL;role:WEB"}
        self.assertEqual(_rule_relationship(rule, self.local, self.lookup), {
            "kear_remote": "", "direction": "incoming", "rule_category": "business_rule",
            "warning": "OUTBOUND2APA_DESTINATION_MANAGED",
        })
        same_app = {**rule, "src_iplists": "", "src_labels": "app:APM_REGION_LOCAL;env:PRD"}
        self.assertEqual(_rule_relationship(same_app, self.local, self.lookup), {
            "kear_remote": "K-LOCAL", "direction": "intra-app", "rule_category": "business_rule",
            "warning": "OUTBOUND2APA_DESTINATION_MANAGED",
        })
        unknown_source = {**rule, "src_iplists": "", "src_labels": "appgroup:UNKNOWN"}
        self.assertEqual(_rule_relationship(unknown_source, self.local, self.lookup), {
            "kear_remote": "", "direction": "incoming", "rule_category": "business_rule",
            "warning": "OUTBOUND2APA_DESTINATION_MANAGED; REMOTE_KEAR_UNAVAILABLE",
        })

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl required")
    def test_workbook_orders_labels_and_preserves_both_managed_outbound_perspectives(self):
        from openpyxl import Workbook, load_workbook
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            rules = [
                {**self.rule, "rule_href": "/rules/group",
                 "ruleset_scope": "env:PRD;app:APM_REGION_LOCAL;role:WEB",
                 "src_labels": "env:PRD;app:APM_REGION_LOCAL;role:WEB",
                 "dst_labels": "env:PRD;appgroup:APPS;role:DB"},
                {**self.rule, "rule_href": "/rules/both", "ruleset_scope": "",
                 "ruleset_name": "APP_OUTBOUND2APA_PRD",
                 "src_labels": "env:PRD;app:APM_REGION_LOCAL;role:WEB",
                 "dst_labels": "env:PRD;app:APM_REGION_REMOTE;role:DB"},
                {**self.rule, "rule_href": "/rules/reversed", "ruleset_scope": "",
                 "ruleset_name": "APP_OUTBOUND2APA_PRD", "src_iplists": "UNMANAGED_NETWORK",
                 "dst_labels": "env:PRD;app:APM_REGION_LOCAL;role:WEB"},
            ]
            for name, fields, rows in (
                ("rules_inventory.csv", RULE_FIELDS, rules),
                ("export_labelgroups.csv", LABEL_GROUP_FIELDS, [{
                    "name": "APPS", "key": "app",
                    "member_labels": "app:APM_REGION_LOCAL;app:APM_REGION_REMOTE",
                }]),
                ("labels.csv", ("key", "value"), [
                    {"key": "app", "value": row["app"]} for row in (self.local, self.remote)
                ] + [{"key": "env", "value": "PRD"}]),
            ):
                with (snapshot / name).open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(rows)
            source = root / "microcosmos.xlsx"
            book = Workbook()
            book.active.append(list(MICROCOSMOS_COLUMNS))
            book.active.append([""] * len(MICROCOSMOS_COLUMNS))
            for row, module in ((self.local, "LOCAL"), (self.remote, "REMOTE")):
                data = {**row, "Module": module, "Application Name": module}
                book.active.append([data.get(column, "") for column in MICROCOSMOS_COLUMNS])
            book.save(source)
            book.close()
            output = generate_compliance_workbook(root, root / "compliance.xlsx", (), source, debug=True)
            with closing(load_workbook(output, read_only=True)) as report:
                values = list(report["Business Rules"].values)
                rows = [dict(zip(values[0], row)) for row in values[1:]]
                keyed = {(row["Kear Id (Scope)"], row["rule_href"]): row for row in rows}
                self.assertEqual(len(keyed), len(rows))
                group = keyed[("K-LOCAL", "/rules/group")]
                self.assertEqual(group["ruleset_scope"], "role:WEB; app:APM_REGION_LOCAL; env:PRD")
                self.assertEqual(group["Source"], "role:WEB; app:APM_REGION_LOCAL; env:PRD")
                self.assertEqual(group["Destination"], "role:DB; appgroup:APPS; env:PRD")
                self.assertEqual(group["Direction"], "outgoing")
                for kear, direction, peer in (("K-LOCAL", "outgoing", "K-REMOTE"),
                                               ("K-REMOTE", "incoming", "K-LOCAL")):
                    actual = keyed[(kear, "/rules/both")]
                    self.assertEqual((actual["Direction"], actual["Kear Remote"]), (direction, peer))
                    self.assertEqual(actual["Warning"], "OUTBOUND2APA_DESTINATION_MANAGED")
                reversed_row = keyed[("K-LOCAL", "/rules/reversed")]
                self.assertEqual(reversed_row["Direction"], "incoming")
                self.assertEqual(reversed_row["Kear Remote"], KEAR_NOT_ONBOARDED)
                self.assertEqual(reversed_row["Warning"], "OUTBOUND2APA_DESTINATION_MANAGED")
