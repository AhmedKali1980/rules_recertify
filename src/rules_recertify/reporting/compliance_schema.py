"""Public compliance columns and their stable default presentation order."""
from __future__ import annotations

from typing import Mapping, Sequence

from .app_server_scope import IMPACTED_APP_SERVERS


RULE_STATUS = "rule_status (Enabled/Disabled)"
RULE_ID = "rule-id"
ALIASES = {
    "Kear Id": "Kear Id (Scope)", "Application Name": "Application Name (Scope)",
    "Module": "Module (Scope)", "app": "illumio label app (Scope)",
    "Environment": "illumio label env (Scope)", "env": "illumio label env (Scope)",
    "Number of impacted App servers (scope)": IMPACTED_APP_SERVERS,
    "Number impacted App servers (Scope)": IMPACTED_APP_SERVERS,
}
DEFAULT_HEADERS = (
    "Kear Id (Scope)", "Application Name (Scope)", "Entity", "Module (Scope)",
    "illumio label app (Scope)", "illumio label env (Scope)", IMPACTED_APP_SERVERS,
    RULE_STATUS, RULE_ID, "Direction", "Rule Category", "rule_type",
    "Source contains User", "Destination contains User", "rule_description",
    "Source", "Destination", "services", "PORTS_TO_CONTROL", "PORTS_TO_ERADICATE", "PORTS_ADMIN",
    "Usage Status", "Last Hit", "Days Since Last Hit", "Total Hit Flows", "Observed Windows",
    "First Observed", "Last Observed", "Port Breakdown Complete",
    "PORTS_TO_CONTROL Hit Ports", "PORTS_TO_CONTROL Hit Flows", "PORTS_TO_CONTROL Last Hit",
    "PORTS_TO_ERADICATE Hit Ports", "PORTS_TO_ERADICATE Hit Flows", "PORTS_TO_ERADICATE Last Hit",
    "PORTS_ADMIN Hit Ports", "PORTS_ADMIN Hit Flows", "PORTS_ADMIN Last Hit",
)
ALL_HEADERS = (*DEFAULT_HEADERS, "Kear Remote", "Account", "Account Leader",
               "Microsegmentation Solution", "Program (MIO)", "Program (KPI)",
               "Match status", "Warning", "Global Consumer in use", "ruleset_name",
               "ruleset_scope", "ruleset_enabled", "rule_enabled", "rule_href", "Protection type")
COLUMN_GROUPS = (
    DEFAULT_HEADERS[:7],
    DEFAULT_HEADERS[7:DEFAULT_HEADERS.index("PORTS_TO_CONTROL")],
    DEFAULT_HEADERS[DEFAULT_HEADERS.index("PORTS_TO_CONTROL"):DEFAULT_HEADERS.index("PORTS_TO_CONTROL Hit Ports")],
    DEFAULT_HEADERS[-9:-6], DEFAULT_HEADERS[-6:-3], DEFAULT_HEADERS[-3:],
)
REFERENCE_HEADERS = {
    "iplists": ("name", "include", "exclude", "fqdns"),
    "workloads": ("app", "env", "role", "loc", "OS", "hostname", "name", "managed", "enforcement",
                  "created_at", "ip_with_default_gw", "external_data_reference"),
}
_NAMES = {name.casefold(): name for name in ALL_HEADERS}
_NAMES.update({old.casefold(): new for old, new in ALIASES.items()})


def canonical_header(name: str) -> str:
    return _NAMES.get(name.casefold(), name)


def available_headers(raw: Sequence[str]) -> list[str]:
    return list(dict.fromkeys((*ALL_HEADERS, *(canonical_header(name) for name in raw))))


def output_row(row: Mapping[str, object]) -> dict[str, object]:
    result = {canonical_header(name): value for name, value in row.items()}
    # CSV env and Microcosmos Environment represent the same public column.
    environment = next((value for name, value in row.items() if name.casefold() == "env" and value), None)
    if environment is None:
        environment = next((value for name, value in row.items() if name.casefold() == "environment" and value), None)
    if environment is not None:
        result["illumio label env (Scope)"] = environment
    return result
