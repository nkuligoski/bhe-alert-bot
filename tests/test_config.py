from pathlib import Path

import pytest

from alertbot.config import ConfigError, config_from_dict, resolve_credentials, resolve_state_path


def test_resolve_credentials_prefers_environment(monkeypatch):
    config = config_from_dict(
        {
            "bhe": {
                "tenant": "tenant.example",
                "token_id": "config-id",
                "token_key": "config-key",
            },
            "webhook": {"url": "https://webhook.example"},
        }
    )
    monkeypatch.setenv("BHE_ID", "env-id")
    monkeypatch.setenv("BHE_KEY", "env-key")

    credentials = resolve_credentials(config)

    assert credentials.token_id == "env-id"
    assert credentials.token_key == "env-key"
    assert credentials.tenant == "tenant.example"


def test_unrecognized_config_sections_are_ignored():
    config = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
            "unused": {"value": "ignored"},
        }
    )

    assert config.bhe.tenant == "tenant.example"


def test_relative_state_path_resolves_from_config_directory(tmp_path: Path):
    config_path = tmp_path / "nested" / "alertbot.config.json"

    assert resolve_state_path(config_path, "alertbot.state.json") == tmp_path / "nested" / "alertbot.state.json"


def test_asset_group_tag_config_supports_current_and_legacy_shapes():
    current = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
            "asset_group_tags": {
                "mode": "selected",
                "selected_tags": [{"id": 3, "name": "Server Tier"}],
            },
        }
    )
    legacy = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
            "asset_group_tag_id": 2,
        }
    )

    assert current.asset_group_tags.mode == "selected"
    assert current.asset_group_tags.selected_tags[0].id == 3
    assert current.asset_group_tags.selected_tags[0].name == "Server Tier"
    assert legacy.asset_group_tags.selected_tags[0].id == 2


def test_asset_group_tags_all_mode_does_not_require_selected_tags():
    config = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
            "asset_group_tags": {"mode": "all"},
        }
    )

    assert config.asset_group_tags.mode == "all"
    assert config.asset_group_tags.selected_tags == []


def test_dedupe_mode_defaults_to_finding_and_accepts_group():
    default = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
        }
    )
    group = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
            "dedupe_mode": "group",
        }
    )

    assert default.dedupe_mode == "finding"
    assert group.dedupe_mode == "group"


def test_principal_display_defaults_to_display_name_and_accepts_object_id():
    default = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
        }
    )
    object_id = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
            "principal_display": "object_id",
        }
    )

    assert default.principal_display == "display_name"
    assert object_id.principal_display == "object_id"


def test_invalid_principal_display_is_rejected():
    with pytest.raises(ConfigError):
        config_from_dict(
            {
                "bhe": {"tenant": "tenant.example"},
                "webhook": {"url": "https://webhook.example"},
                "principal_display": "both",
            }
        )


def test_webhook_provider_defaults_to_auto_and_accepts_slack():
    default = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
        }
    )
    slack = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example", "provider": "slack"},
        }
    )

    assert default.webhook.provider == "auto"
    assert slack.webhook.provider == "slack"


def test_invalid_webhook_provider_is_rejected():
    with pytest.raises(ConfigError):
        config_from_dict(
            {
                "bhe": {"tenant": "tenant.example"},
                "webhook": {"url": "https://webhook.example", "provider": "pager"},
            }
        )


def test_invalid_dedupe_mode_is_rejected():
    with pytest.raises(ConfigError):
        config_from_dict(
            {
                "bhe": {"tenant": "tenant.example"},
                "webhook": {"url": "https://webhook.example"},
                "dedupe_mode": "unsupported",
            }
        )
