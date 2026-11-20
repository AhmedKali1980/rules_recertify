"""Optional column/sheet visibility and the report's configuration audit."""
from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Sequence


DETAIL_SHEETS = ("Business Rules", "Infra Rules", "Data Quality")
CONFIGURATION_SHEET = "Report Configuration"
REPORT_SHEETS = ("Summary", *DETAIL_SHEETS, CONFIGURATION_SHEET)


@dataclass(frozen=True)
class ComplianceLayout:
    available_headers: Sequence[str]
    headers: Sequence[str]
    columns: Mapping[str, bool]
    sheets: Mapping[str, bool]

    def sheet_visible(self, name: str) -> bool:
        # Existing profiles contain only column sections: keep all tabs visible.
        return self.sheets.get(name, True)

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

    known_columns = set(available) | set(optional_columns)
    columns: Dict[str, bool] = {}
    sheets: Dict[str, bool] = {}
    for section in configuration.sections():
        is_sheet = section.startswith("sheet:")
        name = section[len("sheet:"):] if is_sheet else section
        if is_sheet and name not in REPORT_SHEETS:
            raise ValueError(f"Unknown report sheet [{section}] in custom headers file {path}")
        if not is_sheet and name not in known_columns:
            raise ValueError(f"Unknown report column [{section}] in custom headers file {path}")
        if set(configuration[section]) != {"visibility"}:
            raise ValueError(f"Section [{section}] in {path} requires only visibility = true or false")
        value = configuration[section]["visibility"].strip().casefold()
        if value not in {"true", "false"}:
            raise ValueError(f"Invalid visibility for [{section}] in {path}: expected true or false")
        (sheets if is_sheet else columns)[name] = value == "true"

    selected = [name for name in available if columns.get(name, False)]
    layout = ComplianceLayout(tuple(available), tuple(selected), columns, sheets)
    if not any(layout.sheet_visible(name) for name in REPORT_SHEETS):
        raise ValueError(f"No visible sheets in custom headers file {path}")
    if not selected and any(layout.sheet_visible(name) for name in DETAIL_SHEETS):
        raise ValueError(f"No visible columns are available for this report in custom headers file {path}")
    return layout
