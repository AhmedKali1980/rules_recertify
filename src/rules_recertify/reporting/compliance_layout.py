"""Optional column/sheet visibility and the report's configuration audit."""
from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Sequence

from .compliance_schema import REFERENCE_HEADERS, canonical_header


DETAIL_SHEETS = ("Business Rules", "Infra Rules", "Data Quality")
CONFIGURATION_SHEET = "Report Configuration"
REPORT_SHEETS = ("Summary", *DETAIL_SHEETS, *REFERENCE_HEADERS, CONFIGURATION_SHEET)


@dataclass(frozen=True)
class ComplianceLayout:
    available_headers: Sequence[str]
    headers: Sequence[str]
    columns: Mapping[str, bool]
    sheets: Mapping[str, bool]
    reference_columns: Mapping[str, Mapping[str, bool]] = field(default_factory=dict)

    def sheet_visible(self, name: str) -> bool:
        # Keep historical tabs visible for existing column-only profiles.
        return self.sheets.get(name, name not in REFERENCE_HEADERS)

    def reference_headers(self, sheet: str) -> List[str]:
        return [name for name in REFERENCE_HEADERS[sheet]
                if self.reference_columns.get(sheet, {}).get(name, False)]

    def configuration_rows(self) -> List[Dict[str, object]]:
        displayed_columns = set(self.headers) if any(self.sheet_visible(s) for s in DETAIL_SHEETS) else set()
        rows: List[Dict[str, object]] = []
        for name in dict.fromkeys((*self.available_headers, *self.columns)):
            available = name in self.available_headers
            enabled = self.columns.get(name, False)
            displayed = name in displayed_columns
            reason = (
                "Unavailable for this input" if not available else
                "Not configured" if name not in self.columns else
                "Disabled" if not enabled else
                "No detail sheet enabled" if not displayed else "Enabled"
            )
            rows.append({"Type": "Column", "Name": name, "Configured visibility": enabled,
                         "Available": available, "Displayed": displayed, "Reason": reason})
        for sheet, headers in REFERENCE_HEADERS.items():
            for name in headers:
                enabled = self.reference_columns.get(sheet, {}).get(name, False)
                displayed = enabled and self.sheet_visible(sheet)
                rows.append({"Type": "Column", "Name": f"{sheet}.{name}",
                             "Configured visibility": enabled, "Available": True, "Displayed": displayed,
                             "Reason": "Enabled" if displayed else "Disabled" if not enabled else "Sheet disabled"})
        for name in REPORT_SHEETS:
            enabled = self.sheet_visible(name)
            rows.append({"Type": "Sheet", "Name": name, "Configured visibility": enabled,
                         "Available": True, "Displayed": enabled,
                         "Reason": "Default visibility" if name not in self.sheets else
                         "Enabled" if enabled else "Disabled"})
        return rows


def load_compliance_layout(
    path: Path, available: Sequence[str], optional_columns: Sequence[str],
) -> ComplianceLayout:
    configuration = configparser.ConfigParser(interpolation=None)
    try:
        with path.open(encoding="utf-8-sig") as handle:
            configuration.read_file(handle)
    except (OSError, UnicodeError, configparser.Error) as exc:
        raise ValueError(f"Cannot read custom headers file {path}: {exc}") from exc
    if configuration.defaults():
        raise ValueError(f"Custom headers file {path} must not contain DEFAULT settings")

    known_columns = set(available) | {canonical_header(name) for name in optional_columns}
    columns: Dict[str, bool] = {}
    sheets: Dict[str, bool] = {}
    reference_columns: Dict[str, Dict[str, bool]] = {}
    for section in configuration.sections():
        is_sheet = section.startswith("sheet:")
        is_reference = section.startswith("column:")
        name = section[len("sheet:"):] if is_sheet else canonical_header(section)
        if is_reference:
            parts = section.split(":", 2)
            if len(parts) != 3 or parts[1] not in REFERENCE_HEADERS or parts[2] not in REFERENCE_HEADERS[parts[1]]:
                raise ValueError(f"Unknown reference column [{section}] in custom headers file {path}")
        if is_sheet and name not in REPORT_SHEETS:
            raise ValueError(f"Unknown report sheet [{section}] in custom headers file {path}")
        if not is_sheet and not is_reference and name not in known_columns:
            raise ValueError(f"Unknown report column [{section}] in custom headers file {path}")
        if set(configuration[section]) != {"visibility"}:
            raise ValueError(f"Section [{section}] in {path} requires only visibility = true or false")
        value = configuration[section]["visibility"].strip().casefold()
        if value not in {"true", "false"}:
            raise ValueError(f"Invalid visibility for [{section}] in {path}: expected true or false")
        if is_reference:
            reference_columns.setdefault(parts[1], {})[parts[2]] = value == "true"
        else:
            target = sheets if is_sheet else columns
            if name in target and target[name] != (value == "true"):
                raise ValueError(f"Conflicting alias [{section}] in custom headers file {path}")
            target[name] = value == "true"

    selected = [name for name in available if columns.get(name, False)]
    layout = ComplianceLayout(tuple(available), tuple(selected), columns, sheets, reference_columns)
    if not any(layout.sheet_visible(name) for name in REPORT_SHEETS):
        raise ValueError(f"No visible sheets in custom headers file {path}")
    if not selected and any(layout.sheet_visible(name) for name in DETAIL_SHEETS):
        raise ValueError(f"No visible columns are available for this report in custom headers file {path}")
    for name in REFERENCE_HEADERS:
        if layout.sheet_visible(name) and not layout.reference_headers(name):
            raise ValueError(f"No visible columns for sheet {name} in custom headers file {path}")
    return layout
