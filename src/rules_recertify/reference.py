from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .history.database import Database
from .resolution.workloads import matching_nz3, normalize_ip_list_member, ocs_name_from_ip, select_addresses, short_hostname
from .workloader.csvio import parse_bool, read_rows


def ingest_reference(db: Database, workloads_file: Path, ip_lists_file: Path, run_id: str) -> Dict[str, int]:
    timestamp = datetime.now(timezone.utc).isoformat()
    raw_ip_rows = list(read_rows(ip_lists_file, ("name", "include")))
    ip_rows = []
    for row in raw_ip_rows:
        normalized = normalize_ip_list_member(row["include"])
        if normalized:
            ip_rows.append({**row, "include": normalized})
    workload_rows = list(read_rows(workloads_file, ("href", "hostname", "interfaces", "ip_with_default_gw", "app", "env", "managed")))
    quality = []
    with db.connect() as connection:
        connection.execute("DELETE FROM ip_lists")
        for row in ip_rows:
            if row["name"] and row["include"]:
                connection.execute("INSERT OR IGNORE INTO ip_lists VALUES(?,?,?)", (row["name"], row["include"], timestamp))
        connection.execute("DELETE FROM workloads")
        inserted = 0
        for row in workload_rows:
            addresses, warnings = select_addresses(row)
            if not addresses:
                quality.append(("WORKLOAD_WITHOUT_IP", row["href"], "; ".join(warnings) or "No usable IP"))
                continue
            enriched = dict(row)
            enriched["short_hostname"] = short_hostname(row["hostname"])
            enriched["address_details"] = []
            for address in addresses:
                matches = matching_nz3(address, ip_rows)
                enriched["address_details"].append({"ip": address, "ocs_name_from_IP": ocs_name_from_ip(address),
                                                     "IPLIST": [m[0] for m in matches], "SUBNET": [m[1] for m in matches]})
            connection.execute("""INSERT INTO workloads VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (
                row["href"], row.get("hostname", ""), enriched["short_hostname"], row.get("name", ""),
                row.get("app", ""), row.get("env", ""), row.get("loc", ""), row.get("role", ""),
                int(parse_bool(row.get("managed", "")) or False), json.dumps(addresses), json.dumps(enriched, sort_keys=True), timestamp))
            for warning in warnings:
                quality.append(("WORKLOAD_INTERFACE", row["href"], warning))
            inserted += 1
    for category, object_id, message in quality:
        db.add_quality(run_id, category, object_id, message)
    return {"workloads": inserted, "ip_list_members": len(ip_rows)}
