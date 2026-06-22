"""Command-line interface for AlertBot."""

import argparse
import getpass
import json
import logging
import os
import sys
from pathlib import Path
from typing import Iterable, Optional

import requests

from .bhe_client import (
    BHEClient,
    ENTERPRISE_PRODUCT_EDITION,
    UnsupportedProductEditionError,
    validate_enterprise_version,
)
from .config import (
    ConfigError,
    DEFAULT_CONFIG_PATH,
    load_config,
    resolve_state_path,
    write_config,
)
from .models import (
    AlertBotConfig,
    AssetGroupTagConfig,
    AssetGroupTagSelection,
    BHEConfig,
    Credentials,
    DomainSelection,
    WebhookConfig,
)
from .runner import run_alertbot
from .state import AlertState, StateError, save_state


def _write_json_output(path: Path, result: object) -> None:
    """Write a run result to a local JSON file for payload validation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(result.to_dict(), file, indent=2)
        file.write("\n")


def _configure_logging(level: str) -> None:
    """Configure process-wide logging from a config log level string."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def _prompt(prompt: str, default: Optional[str] = None) -> str:
    """Prompt for a value and return the default when the user submits blank input."""
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def _prompt_choice(prompt: str, choices: Iterable[str], default: str) -> str:
    """Prompt until the user selects one of the allowed choices."""
    choices = list(choices)
    while True:
        value = _prompt(f"{prompt} ({'/'.join(choices)})", default)
        if value in choices:
            return value
        print(f"Choose one of: {', '.join(choices)}")


def _version_display_value(version: dict, key: str) -> str:
    """Return a printable version field with a stable fallback."""
    value = version.get(key)
    return str(value) if value else "unknown"


def _format_api_connection_status(version: dict) -> str:
    """Build the setup status line for the BHE version pre-check."""
    server_version = _version_display_value(version, "server_version")
    product_edition = _version_display_value(version, "product_edition")
    can_proceed = product_edition.strip().lower() == ENTERPRISE_PRODUCT_EDITION
    if can_proceed:
        return f"API connection successful: {server_version}, {product_edition}. Proceed."

    next_step = "AlertBot requires product_edition 'enterprise'; setup cannot proceed."
    status = "unsuccessful"
    return (
        f"API connection {status}: "
        f"server_version={server_version}, product_edition={product_edition}. "
        f"{next_step}"
    )


def _setup_credential_input(value: str, default_env: str) -> tuple[str, Optional[str]]:
    """Return the config env var and optional setup-only credential from a prompt value."""
    if value == default_env or os.environ.get(value):
        return value, None
    return default_env, value


def _temporary_credentials(
    bhe: BHEConfig,
    token_id: Optional[str] = None,
    token_key: Optional[str] = None,
) -> Credentials:
    """Collect setup-only credentials without writing secrets to config."""
    token_id = token_id or os.environ.get(bhe.token_id_env) or _prompt("BHE token ID for setup session")
    token_key = token_key or os.environ.get(bhe.token_key_env) or getpass.getpass("BHE token key for setup session: ")
    if not token_id or not token_key:
        raise ConfigError("Setup requires BHE credentials to retrieve available domains")
    return Credentials(token_id=token_id, token_key=token_key, tenant=bhe.tenant)


def _asset_group_tag_label(tag: dict) -> str:
    """Format an asset group tag for setup prompts."""
    tag_id = tag.get("id")
    tag_name = tag.get("name") or tag_id
    return f"{tag_name} ({tag_id})"


def _resolve_asset_group_tag_selection(raw_selection: str, tags: list[dict]) -> list[AssetGroupTagConfig]:
    """Resolve comma-separated tag prompt input to configured tag objects."""
    selected_tags = []
    for item in raw_selection.split(","):
        item = item.strip()
        if not item:
            continue
        if item.isdigit():
            selected_number = int(item)
            if selected_number == 0:
                selected_tags.append(AssetGroupTagConfig(id=0, name="Default / Hygiene"))
            elif 1 <= selected_number <= len(tags):
                tag = tags[selected_number - 1]
                selected_tags.append(AssetGroupTagConfig(id=int(tag["id"]), name=tag.get("name")))
            else:
                selected_tags.append(AssetGroupTagConfig(id=selected_number))
            continue

        matched_tag = next(
            (tag for tag in tags if str(tag.get("name", "")).lower() == item.lower()),
            None,
        )
        if matched_tag:
            selected_tags.append(AssetGroupTagConfig(id=int(matched_tag["id"]), name=matched_tag.get("name")))
            continue
        raise ConfigError("Asset group tag selection must be listed numbers, numeric IDs, or tag names")

    return selected_tags


def _prompt_asset_group_tags(client: BHEClient) -> AssetGroupTagSelection:
    """Prompt for all or selected asset group tags using live BHE tag data."""
    tags = client.fetch_asset_group_tags()

    print("\nAvailable asset group tags:")
    print("0. Default / Hygiene (0) - only used when explicitly selected")
    for index, tag in enumerate(tags, start=1):
        print(f"{index}. {_asset_group_tag_label(tag)}")

    tag_mode = _prompt_choice("Monitor asset group tags", ["selected", "all"], "selected")
    if tag_mode == "all":
        return AssetGroupTagSelection(mode="all", selected_tags=[])

    raw_selection = _prompt("Asset group tag numbers, IDs, or names separated by commas", "1")
    selected_tags = _resolve_asset_group_tag_selection(raw_selection, tags)
    if not selected_tags:
        raise ConfigError("At least one asset group tag must be selected")
    return AssetGroupTagSelection(mode="selected", selected_tags=selected_tags)


def _run_setup(args: argparse.Namespace) -> int:
    """Run the interactive setup flow and write initial config/state files."""
    config_path = Path(args.config)
    tenant = _prompt("BHE tenant host", "example.bloodhoundenterprise.io")
    token_id_input = _prompt("BHE token ID environment variable or setup token ID", "BHE_ID")
    token_key_input = _prompt("BHE token key environment variable or setup token key", "BHE_KEY")
    token_id_env, setup_token_id = _setup_credential_input(token_id_input, "BHE_ID")
    token_key_env, setup_token_key = _setup_credential_input(token_key_input, "BHE_KEY")
    bhe = BHEConfig(tenant=tenant, token_id_env=token_id_env, token_key_env=token_key_env)
    credentials = _temporary_credentials(bhe, token_id=setup_token_id, token_key=setup_token_key)
    client = BHEClient.from_config(
        AlertBotConfig(
            bhe=bhe,
            domains=DomainSelection(),
            webhook=WebhookConfig(url="https://example.invalid/webhook"),
        ),
        credentials,
    )

    try:
        version = client.fetch_version()
    except (requests.RequestException, ValueError) as exc:
        print(_format_api_connection_status({}))
        raise ConfigError(f"Unable to connect to BHE API version endpoint: {exc}") from exc
    api_connection_status = _format_api_connection_status(version)
    try:
        validate_enterprise_version(version)
    except UnsupportedProductEditionError as exc:
        print(api_connection_status)
        raise ConfigError(str(exc)) from exc

    domains = client.fetch_all_available_domains()
    if not domains:
        raise ConfigError("No available domains returned by BHE")

    print("\nAvailable domains:")
    for index, domain in enumerate(domains, start=1):
        domain_id = domain.get("id") or domain.get("objectid") or domain.get("objectId") or domain.get("sid")
        print(f"{index}. {domain.get('name', domain_id)} ({domain_id})")

    domain_mode = _prompt_choice("Monitor domains", ["all", "selected"], "all")
    selected_domains = []
    if domain_mode == "selected":
        raw_selection = _prompt("Enter domain numbers, names, or IDs separated by commas")
        for item in raw_selection.split(","):
            item = item.strip()
            if not item:
                continue
            if item.isdigit() and 1 <= int(item) <= len(domains):
                domain = domains[int(item) - 1]
                selected_domains.append(str(domain.get("id") or domain.get("objectid") or domain.get("objectId") or domain.get("sid")))
            else:
                selected_domains.append(item)

    webhook_url = _prompt("Webhook URL")
    state_path = _prompt("State file path", "alertbot.state.json")
    first_run_behavior = _prompt_choice("First run behavior", ["baseline", "alert"], "baseline")
    dedupe_mode = _prompt_choice("Deduplication mode", ["group", "finding"], "group")
    asset_group_tags = _prompt_asset_group_tags(client)

    config = AlertBotConfig(
        bhe=bhe,
        domains=DomainSelection(mode=domain_mode, selected_domains=selected_domains),
        webhook=WebhookConfig(url=webhook_url),
        asset_group_tags=asset_group_tags,
        state_path=state_path,
        first_run_behavior=first_run_behavior,
        dedupe_mode=dedupe_mode,
    )
    write_config(config, config_path)

    resolved_state_path = resolve_state_path(config_path, state_path)
    if not resolved_state_path.exists():
        save_state(AlertState(), resolved_state_path)

    print(f"Wrote config to {config_path}")
    print(f"Initialized state at {resolved_state_path}")
    print(api_connection_status)
    print("Run 'alertbot run --dry-run' next to preview grouped webhook payloads.")
    return 0


def _run_alerts(args: argparse.Namespace) -> int:
    """Run one AlertBot execution from config and optional dry-run/output flags."""
    config_path = Path(args.config)
    config = load_config(config_path)
    _configure_logging(config.log_level)
    result = run_alertbot(config=config, config_path=config_path, dry_run=args.dry_run)
    if args.output_json:
        output_path = Path(args.output_json)
        _write_json_output(output_path, result)
        print(f"Wrote alert payload preview to {output_path}")
    if args.dry_run:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(
            "AlertBot run complete: "
            f"{result.delivered_count} delivered, "
            f"{result.failed_count} failed, "
            f"{result.baseline_count} baselined, "
            f"{result.total_attack_paths} total."
        )
    return 2 if result.failed_count else 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level AlertBot argument parser."""
    parser = argparse.ArgumentParser(description="BloodHound Enterprise AlertBot")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to AlertBot config JSON. Default: alertbot.config.json",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("setup", help="Interactively create AlertBot config and state files")

    run = subparsers.add_parser("run", help="Run AlertBot once")
    run.add_argument("--dry-run", action="store_true", help="Build payloads without POSTing or mutating state")
    run.add_argument(
        "--output-json",
        default=None,
        help="Write generated alert payloads and run summary to a local JSON file",
    )

    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    """CLI entrypoint used by the console script and `python -m alertbot`."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "setup":
            return _run_setup(args)
        if args.command == "run":
            return _run_alerts(args)
    except (ConfigError, StateError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1
