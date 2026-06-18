from pathlib import Path

from alertbot.config import config_from_dict, write_config
from alertbot.runner import run_alertbot
from alertbot.state import load_state


class FakeClient:
    def fetch_all_available_domains(self):
        return [{"id": "domain", "name": "example.local"}]

    def fetch_available_types_for_each_domain(self, domain_id, params=None):
        return ["Type A"]

    def fetch_attack_path_finding_details(self, domain_sid, finding, page_size, params=None):
        return [{"attack_path_id": "ap-1", "finding_id": "f-1"}]


def _config(tmp_path: Path, first_run_behavior="baseline"):
    return config_from_dict(
        {
            "bhe": {"tenant": "tenant.example", "token_id": "id", "token_key": "key"},
            "webhook": {"url": "https://webhook.example"},
            "state_path": "state.json",
            "first_run_behavior": first_run_behavior,
        }
    )


def test_first_run_baseline_marks_without_payloads(tmp_path):
    config = _config(tmp_path, first_run_behavior="baseline")
    config_path = tmp_path / "alertbot.config.json"
    write_config(config, config_path)

    result = run_alertbot(
        config=config,
        config_path=config_path,
        dry_run=False,
        client=FakeClient(),
        now_fn=lambda: "2026-06-17T00:00:00Z",
    )
    state = load_state(tmp_path / "state.json")

    assert result.baseline_count == 1
    assert result.delivered_count == 0
    assert state.has_attack_path("domain:0:Type A")


def test_dry_run_does_not_mutate_state(tmp_path):
    config = _config(tmp_path, first_run_behavior="alert")
    config_path = tmp_path / "alertbot.config.json"
    write_config(config, config_path)

    result = run_alertbot(
        config=config,
        config_path=config_path,
        dry_run=True,
        client=FakeClient(),
        now_fn=lambda: "2026-06-17T00:00:00Z",
    )

    assert len(result.payloads) == 1
    assert not (tmp_path / "state.json").exists()


def test_baseline_dry_run_still_builds_preview_payloads(tmp_path):
    config = _config(tmp_path, first_run_behavior="baseline")
    config_path = tmp_path / "alertbot.config.json"
    write_config(config, config_path)

    result = run_alertbot(
        config=config,
        config_path=config_path,
        dry_run=True,
        client=FakeClient(),
        now_fn=lambda: "2026-06-17T00:00:00Z",
    )

    assert result.baseline_count == 1
    assert len(result.payloads) == 1
    assert result.payloads[0]["attack_path"]["id"] == "Type A"
    assert not (tmp_path / "state.json").exists()
