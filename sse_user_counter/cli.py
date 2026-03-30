from __future__ import annotations

import argparse
import getpass
import sys
from datetime import datetime
from pathlib import Path

from .collectors import UsageCollector
from .http import ApiError, CiscoApiClient
from .models import Credentials, Product, RunConfig
from .reports import (
    format_console_summary,
    write_correlated_log,
    write_service_logs,
    write_summary_json,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Count Cisco Umbrella or Cisco Secure Access users for SWG, VPN, and ZTNA.",
    )
    parser.add_argument("--product", choices=[product.value for product in Product], help="Target product.")
    parser.add_argument("--api-key", help="Cisco API key.")
    parser.add_argument("--api-secret", help="Cisco API secret.")
    parser.add_argument("--org-id", default="", help="Cisco organization ID. Leave blank if your tenant does not require it.")
    parser.add_argument(
        "--swg-correlate-identities",
        choices=["yes", "no"],
        help="Whether to attempt SWG roaming-computer to SAML-user correlation.",
    )
    parser.add_argument(
        "--reporting-region",
        choices=["auto", "us", "eu"],
        default="auto",
        help="Reporting API region hint. Use auto unless redirects are a problem.",
    )
    parser.add_argument(
        "--swg-correlation-days",
        type=int,
        default=30,
        help="Days of proxy activity to use for SWG user-to-computer correlation. Cisco limits this to 30 days.",
    )
    parser.add_argument(
        "--vpn-days",
        type=int,
        default=60,
        help="Days of remote access VPN history to evaluate.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("output"),
        help="Directory where logs and summary files will be written.",
    )
    return parser.parse_args(argv)


def prompt_if_missing(args: argparse.Namespace) -> argparse.Namespace:
    if not args.product:
        args.product = _prompt_choice(
            "Select product",
            {"umbrella": Product.UMBRELLA.value, "secure-access": Product.SECURE_ACCESS.value},
        )
    if not args.api_key:
        args.api_key = input("API key: ").strip()
    if not args.api_secret:
        args.api_secret = getpass.getpass("API secret: ").strip()
    if not args.org_id:
        args.org_id = input("Org ID (press Enter to leave blank if not required): ").strip()
    if not args.swg_correlate_identities:
        args.swg_correlate_identities = _prompt_yes_no(
            "Do you want to attempt correlation of Roaming Computer identities with SAML identities? "
            "(Warning: may take over an hour for large organizations. This will build a permanent cache to support faster subsequent runs.) [yes/no]: "
        )
    return args


def _prompt_choice(prompt: str, choices: dict[str, str]) -> str:
    labels = "/".join(choices.keys())
    while True:
        response = input(f"{prompt} [{labels}]: ").strip().casefold()
        if response in choices:
            return choices[response]
        print(f"Please choose one of: {', '.join(choices.keys())}")


def _prompt_yes_no(prompt: str) -> str:
    while True:
        response = input(prompt).strip().casefold()
        if response in {"yes", "y"}:
            return "yes"
        if response in {"no", "n"}:
            return "no"
        print("Please answer yes or no.")


def build_config(args: argparse.Namespace) -> tuple[Credentials, RunConfig]:
    product = Product(args.product)
    credentials = Credentials(
        api_key=args.api_key.strip(),
        api_secret=args.api_secret.strip(),
        org_id=args.org_id.strip(),
    )
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_root / f"{product.value}_{timestamp}"
    config = RunConfig(
        product=product,
        output_dir=output_dir,
        reporting_region=args.reporting_region,
        swg_correlate_identities=args.swg_correlate_identities == "yes",
        swg_correlation_days=max(1, args.swg_correlation_days),
        vpn_days=max(1, args.vpn_days),
    )
    return credentials, config


def _make_progress_printer():
    def emit(message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}", flush=True)

    return emit


def main(argv: list[str] | None = None) -> int:
    args = prompt_if_missing(parse_args(argv))
    credentials, config = build_config(args)
    progress = _make_progress_printer()

    client = CiscoApiClient(
        product=config.product,
        credentials=credentials,
        reporting_region=config.reporting_region,
        progress_callback=progress,
    )
    collector = UsageCollector(client, config, progress_callback=progress)

    try:
        organization_id = client.get_organization_id()
        reports = collector.collect()
    except ApiError as error:
        print(f"API error: {error}", file=sys.stderr)
        return 1
    except Exception as error:  # pragma: no cover - defensive CLI handling
        print(f"Unexpected error: {error}", file=sys.stderr)
        return 1

    progress("Writing CSV and summary output files...")
    log_paths = write_service_logs(config.output_dir, reports)
    correlated_path = write_correlated_log(config.output_dir, reports)
    summary_path = write_summary_json(config.output_dir, config.product, reports)
    progress("Run complete.")

    print(f"\nProduct: {config.product.display_name}")
    print(f"Organization ID: {organization_id or 'Unavailable from API'}")
    print(format_console_summary(reports))
    print("\nGenerated files:")
    for service_name, path in log_paths.items():
        print(f"- {service_name}: {path}")
    print(f"- Correlated log: {correlated_path}")
    print(f"- Summary JSON: {summary_path}")
    return 0
