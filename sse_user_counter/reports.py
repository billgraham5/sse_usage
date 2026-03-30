from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .collectors import SWG, VPN, ZTNA
from .models import Product, ServiceReport, ServiceRow


def write_service_logs(output_dir: Path, reports: dict[str, ServiceReport]) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for service_name, report in reports.items():
        path = output_dir / f"{service_name.lower()}_log.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "user_name",
                    "computer_name",
                    "service_type",
                    "source_product",
                    "device_id",
                    "first_seen",
                    "last_seen",
                    "event_count",
                    "notes",
                ],
            )
            writer.writeheader()
            for row in report.rows:
                writer.writerow(asdict(row))
        paths[service_name] = path
    return paths


def build_correlated_rows(reports: dict[str, ServiceReport]) -> list[dict[str, str]]:
    correlated: dict[str, dict[str, object]] = defaultdict(
        lambda: {
            "swg": False,
            "vpn": False,
            "ztna": False,
            "swg_computers": set(),
            "ztna_devices": set(),
            "vpn_last_seen": "",
        }
    )

    for service_name, report in reports.items():
        for row in report.rows:
            if not row.user_name:
                continue
            entry = correlated[row.user_name]
            if service_name == SWG:
                entry["swg"] = True
                if row.computer_name:
                    entry["swg_computers"].add(row.computer_name)
            elif service_name == VPN:
                entry["vpn"] = True
                if row.last_seen:
                    entry["vpn_last_seen"] = max(str(entry["vpn_last_seen"]), row.last_seen)
            elif service_name == ZTNA:
                entry["ztna"] = True
                if row.device_id:
                    entry["ztna_devices"].add(row.device_id)

    rows: list[dict[str, str]] = []
    for user_name, details in sorted(correlated.items(), key=lambda item: item[0].casefold()):
        services = [label for label, enabled in ((SWG, details["swg"]), (VPN, details["vpn"]), (ZTNA, details["ztna"])) if enabled]
        rows.append(
            {
                "user_name": user_name,
                "services": ", ".join(services),
                "swg": "yes" if details["swg"] else "no",
                "vpn": "yes" if details["vpn"] else "no",
                "ztna": "yes" if details["ztna"] else "no",
                "swg_computers": "; ".join(sorted(details["swg_computers"])),
                "vpn_last_seen": str(details["vpn_last_seen"]),
                "ztna_device_ids": "; ".join(sorted(details["ztna_devices"])),
            }
        )
    return rows


def write_correlated_log(output_dir: Path, reports: dict[str, ServiceReport]) -> Path:
    path = output_dir / "correlated_log.csv"
    rows = build_correlated_rows(reports)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "user_name",
                "services",
                "swg",
                "vpn",
                "ztna",
                "swg_computers",
                "vpn_last_seen",
                "ztna_device_ids",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


def write_summary_json(output_dir: Path, product: Product, reports: dict[str, ServiceReport]) -> Path:
    path = output_dir / "summary.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "product": product.value,
        "services": {
            name: {
                "supported": report.supported,
                "primary_count": report.primary_count,
                "unique_users": report.unique_users,
                "notes": report.notes,
            }
            for name, report in reports.items()
        },
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def format_console_summary(reports: dict[str, ServiceReport]) -> str:
    lines = []
    for service_name in (SWG, VPN, ZTNA):
        report = reports[service_name]
        if not report.supported:
            lines.append(f"{service_name}: unsupported for the selected product")
            continue
        if service_name == SWG:
            lines.append(
                f"{service_name}: {report.primary_count} registered computers, {report.unique_users} correlated users"
            )
        elif service_name == ZTNA:
            lines.append(
                f"{service_name}: {report.primary_count} active registered devices, {report.unique_users} unique users"
            )
        else:
            lines.append(f"{service_name}: {report.primary_count} unique users")
    correlated_user_count = len(build_correlated_rows(reports))
    lines.append(f"Correlated users across supported services: {correlated_user_count}")
    return "\n".join(lines)
