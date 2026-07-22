"""Configuration loading and validation."""

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .models import (
    AlertBotConfig,
    AssetGroupTagConfig,
    AssetGroupTagSelection,
    BHEConfig,
    Credentials,
    DomainSelection,
    WebhookConfig,
)
from .providers import PROVIDER_NAMES


DEFAULT_CONFIG_PATH = Path("alertbot.config.json")
DEFAULT_STATE_PATH = "alertbot.state.json"
FIRST_RUN_BEHAVIORS = {"baseline", "alert"}
DEDUPE_MODES = {"group", "finding"}
PRINCIPAL_DISPLAY_MODES = {"object_id", "display_name"}
DOMAIN_MODES = {"all", "selected"}
ASSET_GROUP_TAG_MODES = {"all", "selected"}
WEBHOOK_PROVIDERS = set(PROVIDER_NAMES) | {"auto"}


class ConfigError(ValueError):
    """Raised when AlertBot configuration is invalid."""


def _coerce_mapping(value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a mapping for optional config sections."""
    return value or {}


def _asset_group_tag_from_dict(data: Dict[str, Any]) -> AssetGroupTagConfig:
    """Parse one configured asset group tag object."""
    return AssetGroupTagConfig(
        id=int(data.get("id", 0)),
        name=data.get("name") or None,
    )


def _asset_group_tags_from_config(data: Dict[str, Any]) -> AssetGroupTagSelection:
    """Parse current and legacy asset group tag config shapes."""
    asset_group_tags_data = data.get("asset_group_tags")
    if isinstance(asset_group_tags_data, dict):
        mode = str(asset_group_tags_data.get("mode", "selected")).strip() or "selected"
        selected_tags = [
            _asset_group_tag_from_dict(tag)
            for tag in asset_group_tags_data.get("selected_tags", [])
            if isinstance(tag, dict)
        ]
        selected_tags.extend(
            AssetGroupTagConfig(id=int(tag_id))
            for tag_id in asset_group_tags_data.get("selected_ids", [])
        )
        return AssetGroupTagSelection(mode=mode, selected_tags=selected_tags)

    asset_group_tag_data = _coerce_mapping(data.get("asset_group_tag"))
    return AssetGroupTagSelection(
        mode="selected",
        selected_tags=[
            AssetGroupTagConfig(
                id=int(asset_group_tag_data.get("id", data.get("asset_group_tag_id", 0))),
                name=asset_group_tag_data.get("name") or None,
            )
        ],
    )


def config_from_dict(data: Dict[str, Any]) -> AlertBotConfig:
    """Parse raw JSON config data into typed AlertBot configuration."""
    bhe_data = _coerce_mapping(data.get("bhe"))
    domain_data = _coerce_mapping(data.get("domains"))
    webhook_data = _coerce_mapping(data.get("webhook"))

    try:
        config = AlertBotConfig(
            bhe=BHEConfig(
                tenant=str(bhe_data.get("tenant", "")).strip(),
                scheme=str(bhe_data.get("scheme", "https")).strip() or "https",
                port=int(bhe_data.get("port", 443)),
                token_id_env=str(bhe_data.get("token_id_env", "BHE_ID")).strip() or "BHE_ID",
                token_key_env=str(bhe_data.get("token_key_env", "BHE_KEY")).strip() or "BHE_KEY",
                token_id=bhe_data.get("token_id"),
                token_key=bhe_data.get("token_key"),
            ),
            domains=DomainSelection(
                mode=str(domain_data.get("mode", "all")).strip() or "all",
                selected_domains=[str(item).strip() for item in domain_data.get("selected_domains", [])],
            ),
            webhook=WebhookConfig(
                url=str(webhook_data.get("url", "")).strip(),
                timeout_seconds=float(webhook_data.get("timeout_seconds", 10.0)),
                provider=str(webhook_data.get("provider", "auto")).strip().lower() or "auto",
            ),
            asset_group_tags=_asset_group_tags_from_config(data),
            state_path=str(data.get("state_path", DEFAULT_STATE_PATH)).strip() or DEFAULT_STATE_PATH,
            first_run_behavior=str(data.get("first_run_behavior", "baseline")).strip() or "baseline",
            dedupe_mode=str(data.get("dedupe_mode", "finding")).strip() or "finding",
            principal_display=str(data.get("principal_display", "display_name")).strip() or "display_name",
            page_size=int(data.get("page_size", 500)),
            log_level=str(data.get("log_level", "INFO")).strip() or "INFO",
        )
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Invalid configuration value: {exc}") from exc

    validate_config(config)
    return config


def config_to_dict(config: AlertBotConfig) -> Dict[str, Any]:
    """Convert typed config back to JSON-serializable data."""
    return asdict(config)


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> AlertBotConfig:
    """Load and validate AlertBot configuration from a JSON file."""
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Config file is not valid JSON: {path}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Config file must contain a JSON object")

    return config_from_dict(data)


def write_config(config: AlertBotConfig, path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Write AlertBot configuration to disk as formatted JSON."""
    validate_config(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(config_to_dict(config), file, indent=2)
        file.write("\n")


def validate_config(config: AlertBotConfig) -> None:
    """Validate required config fields and supported selection modes."""
    if not config.bhe.tenant:
        raise ConfigError("bhe.tenant is required")
    if config.bhe.port < 1:
        raise ConfigError("bhe.port must be greater than 0")
    if config.domains.mode not in DOMAIN_MODES:
        raise ConfigError("domains.mode must be 'all' or 'selected'")
    if config.domains.mode == "selected" and not config.domains.selected_domains:
        raise ConfigError("domains.selected_domains is required when domains.mode is 'selected'")
    if not config.webhook.url:
        raise ConfigError("webhook.url is required")
    if config.webhook.timeout_seconds <= 0:
        raise ConfigError("webhook.timeout_seconds must be greater than 0")
    if config.webhook.provider not in WEBHOOK_PROVIDERS:
        raise ConfigError("webhook.provider must be 'auto', 'generic', or 'slack'")
    if config.asset_group_tags.mode not in ASSET_GROUP_TAG_MODES:
        raise ConfigError("asset_group_tags.mode must be 'all' or 'selected'")
    if config.asset_group_tags.mode == "selected" and not config.asset_group_tags.selected_tags:
        raise ConfigError("asset_group_tags.selected_tags is required when asset_group_tags.mode is 'selected'")
    for tag in config.asset_group_tags.selected_tags:
        if tag.id < 0:
            raise ConfigError("asset_group_tags.selected_tags IDs must be 0 or greater")
    if config.page_size < 1:
        raise ConfigError("page_size must be greater than 0")
    if config.first_run_behavior not in FIRST_RUN_BEHAVIORS:
        raise ConfigError("first_run_behavior must be 'baseline' or 'alert'")
    if config.dedupe_mode not in DEDUPE_MODES:
        raise ConfigError("dedupe_mode must be 'group' or 'finding'")
    if config.principal_display not in PRINCIPAL_DISPLAY_MODES:
        raise ConfigError("principal_display must be 'object_id' or 'display_name'")


def resolve_credentials(
    config: AlertBotConfig,
    env: Optional[Mapping[str, str]] = None,
) -> Credentials:
    """Resolve BHE credentials from environment variables or config fallback fields."""
    env = env or os.environ
    token_id = env.get(config.bhe.token_id_env) or config.bhe.token_id
    token_key = env.get(config.bhe.token_key_env) or config.bhe.token_key

    if not token_id:
        raise ConfigError(
            f"BHE token ID is required. Set {config.bhe.token_id_env} or configure bhe.token_id."
        )
    if not token_key:
        raise ConfigError(
            f"BHE token key is required. Set {config.bhe.token_key_env} or configure bhe.token_key."
        )

    return Credentials(token_id=token_id, token_key=token_key, tenant=config.bhe.tenant)


def resolve_state_path(config_path: Path, state_path: str) -> Path:
    """Resolve a state path relative to the config file when needed."""
    path = Path(state_path)
    if path.is_absolute():
        return path
    return config_path.parent / path
