import json

from alertbot.cli import main
from alertbot.cli import _format_api_connection_status
from alertbot.cli import _write_json_output
from alertbot.models import RunResult


def test_run_missing_config_returns_error(tmp_path):
    missing = tmp_path / "missing.json"

    assert main(["--config", str(missing), "run"]) == 1


def test_help_returns_success(capsys):
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0


def test_write_json_output(tmp_path):
    output_path = tmp_path / "nested" / "alerts.json"
    result = RunResult(
        total_attack_paths=1,
        candidate_attack_paths=1,
        dry_run=True,
        payloads=[{"event_type": "new_attack_path"}],
    )

    _write_json_output(output_path, result)

    assert '"event_type": "new_attack_path"' in output_path.read_text(encoding="utf-8")


def test_format_api_connection_status_success():
    message = _format_api_connection_status(
        {"server_version": "1.2.3", "product_edition": "enterprise"}
    )

    assert message == "API connection successful: 1.2.3, enterprise. Proceed."


def test_format_api_connection_status_unsuccessful():
    message = _format_api_connection_status(
        {"server_version": "1.2.3", "product_edition": "community"}
    )

    assert message == (
        "API connection unsuccessful: server_version=1.2.3, "
        "product_edition=community. "
        "AlertBot requires product_edition 'enterprise'; setup cannot proceed."
    )


def test_setup_prints_api_connection_status_before_dry_run_guidance(tmp_path, monkeypatch, capsys):
    class FakeSetupClient:
        def fetch_version(self):
            return {"server_version": "1.2.3", "product_edition": "enterprise"}

        def fetch_all_available_domains(self):
            return [{"id": "S-1", "name": "example.local"}]

        def fetch_asset_group_tags(self):
            return [{"id": 1, "name": "Tier Zero"}]

    responses = iter(
        [
            "tenant.example",
            "BHE_ID",
            "BHE_KEY",
            "",
            "https://webhook.example",
            "",
            "",
            "",
            "",
            "",
        ]
    )

    monkeypatch.setenv("BHE_ID", "id")
    monkeypatch.setenv("BHE_KEY", "key")
    monkeypatch.setattr("builtins.input", lambda prompt: next(responses))
    monkeypatch.setattr(
        "alertbot.cli.BHEClient.from_config",
        lambda config, credentials: FakeSetupClient(),
    )

    config_path = tmp_path / "alertbot.config.json"
    result = main(["--config", str(config_path), "setup"])
    output = capsys.readouterr().out
    config_data = json.loads(config_path.read_text(encoding="utf-8"))

    status = "API connection successful: 1.2.3, enterprise. Proceed."
    guidance = "Run 'alertbot run --dry-run' next to preview grouped webhook payloads."
    assert result == 0
    assert status in output
    assert output.index(status) < output.index(guidance)
    assert config_data["bhe"]["token_id"] is None
    assert config_data["bhe"]["token_key"] is None


def test_setup_accepts_inline_credentials_from_initial_prompts(tmp_path, monkeypatch):
    captured = {}

    class FakeSetupClient:
        def fetch_version(self):
            return {"server_version": "1.2.3", "product_edition": "enterprise"}

        def fetch_all_available_domains(self):
            return [{"id": "S-1", "name": "example.local"}]

        def fetch_asset_group_tags(self):
            return [{"id": 1, "name": "Tier Zero"}]

    def fake_from_config(config, credentials):
        captured["credentials"] = credentials
        captured["bhe"] = config.bhe
        return FakeSetupClient()

    responses = iter(
        [
            "tenant.example",
            "inline-token-id",
            "inline-token-key",
            "",
            "https://webhook.example",
            "",
            "",
            "",
            "",
            "",
        ]
    )
    config_path = tmp_path / "alertbot.config.json"

    monkeypatch.delenv("BHE_ID", raising=False)
    monkeypatch.delenv("BHE_KEY", raising=False)
    monkeypatch.setattr("builtins.input", lambda prompt: next(responses))
    monkeypatch.setattr("alertbot.cli.BHEClient.from_config", fake_from_config)

    result = main(["--config", str(config_path), "setup"])
    config_data = json.loads(config_path.read_text(encoding="utf-8"))

    assert result == 0
    assert captured["credentials"].token_id == "inline-token-id"
    assert captured["credentials"].token_key == "inline-token-key"
    assert captured["bhe"].token_id_env == "BHE_ID"
    assert captured["bhe"].token_key_env == "BHE_KEY"
    assert config_data["bhe"]["token_id"] == "inline-token-id"
    assert config_data["bhe"]["token_key"] == "inline-token-key"


def test_setup_accepts_number_lists_for_domain_and_asset_group_tag_selection(
    tmp_path,
    monkeypatch,
):
    class FakeSetupClient:
        def fetch_version(self):
            return {"server_version": "1.2.3", "product_edition": "enterprise"}

        def fetch_all_available_domains(self):
            return [
                {"id": "S-1", "name": "example.local"},
                {"id": "S-2", "name": "child.example.local"},
            ]

        def fetch_asset_group_tags(self):
            return [
                {"id": 1, "name": "Tier Zero"},
                {"id": 3, "name": "Server Tier"},
            ]

    responses = iter(
        [
            "tenant.example",
            "BHE_ID",
            "BHE_KEY",
            "1,2",
            "https://webhook.example",
            "",
            "",
            "",
            "",
            "1,2",
        ]
    )
    config_path = tmp_path / "alertbot.config.json"

    monkeypatch.setenv("BHE_ID", "id")
    monkeypatch.setenv("BHE_KEY", "key")
    monkeypatch.setattr("builtins.input", lambda prompt: next(responses))
    monkeypatch.setattr(
        "alertbot.cli.BHEClient.from_config",
        lambda config, credentials: FakeSetupClient(),
    )

    result = main(["--config", str(config_path), "setup"])
    config_data = json.loads(config_path.read_text(encoding="utf-8"))

    assert result == 0
    assert config_data["domains"] == {
        "mode": "selected",
        "selected_domains": ["S-1", "S-2"],
    }
    assert config_data["asset_group_tags"] == {
        "mode": "selected",
        "selected_tags": [
            {"id": 1, "name": "Tier Zero"},
            {"id": 3, "name": "Server Tier"},
        ],
    }
    assert config_data["dedupe_mode"] == "finding"
    assert config_data["principal_display"] == "display_name"


def test_setup_prints_unsuccessful_api_connection_status_for_non_enterprise(
    tmp_path,
    monkeypatch,
    capsys,
):
    class FakeSetupClient:
        def fetch_version(self):
            return {"server_version": "1.2.3", "product_edition": "community"}

        def fetch_all_available_domains(self):
            raise AssertionError("setup should stop before domain discovery")

    responses = iter(["tenant.example", "BHE_ID", "BHE_KEY"])
    config_path = tmp_path / "alertbot.config.json"

    monkeypatch.setenv("BHE_ID", "id")
    monkeypatch.setenv("BHE_KEY", "key")
    monkeypatch.setattr("builtins.input", lambda prompt: next(responses))
    monkeypatch.setattr(
        "alertbot.cli.BHEClient.from_config",
        lambda config, credentials: FakeSetupClient(),
    )

    result = main(["--config", str(config_path), "setup"])
    captured = capsys.readouterr()

    assert result == 1
    assert (
        "API connection unsuccessful: server_version=1.2.3, "
        "product_edition=community. "
        "AlertBot requires product_edition 'enterprise'; setup cannot proceed."
    ) in captured.out
    assert "product_edition must be 'enterprise'" in captured.err
    assert not config_path.exists()
