from pathlib import Path

import pytest

from alertbot.bhe_client import UnsupportedProductEditionError
from alertbot.config import config_from_dict, write_config
from alertbot.models import DeliveryResult
from alertbot.runner import run_alertbot
from alertbot.state import load_state


class FakeClient:
    def __init__(self, rows=None):
        self.rows = rows or [{"attack_path_id": "ap-1", "finding_id": "f-1"}]
        self.checked_edition = False

    def ensure_enterprise_edition(self):
        self.checked_edition = True

    def fetch_all_available_domains(self):
        assert self.checked_edition
        return [{"id": "domain", "name": "example.local"}]

    def fetch_available_types_for_each_domain(self, domain_id, params=None):
        return ["Type A"]

    def fetch_attack_path_finding_details(self, domain_sid, finding, page_size, params=None):
        return self.rows


def _config(tmp_path: Path, first_run_behavior="baseline", dedupe_mode="group"):
    return config_from_dict(
        {
            "bhe": {"tenant": "tenant.example", "token_id": "id", "token_key": "key"},
            "webhook": {"url": "https://webhook.example"},
            "state_path": "state.json",
            "first_run_behavior": first_run_behavior,
            "dedupe_mode": dedupe_mode,
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


def test_run_checks_product_edition_before_collecting_data(tmp_path):
    class UnsupportedClient(FakeClient):
        def ensure_enterprise_edition(self):
            raise UnsupportedProductEditionError(
                "BloodHound product_edition must be 'enterprise'; received 'community'."
            )

        def fetch_all_available_domains(self):
            raise AssertionError("domain collection should not run after failed edition check")

    config = _config(tmp_path, first_run_behavior="alert")
    config_path = tmp_path / "alertbot.config.json"
    write_config(config, config_path)

    with pytest.raises(UnsupportedProductEditionError):
        run_alertbot(
            config=config,
            config_path=config_path,
            dry_run=False,
            client=UnsupportedClient(),
            now_fn=lambda: "2026-06-17T00:00:00Z",
        )


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


def test_finding_dedupe_dry_run_only_returns_unseen_findings(tmp_path):
    config = _config(tmp_path, first_run_behavior="baseline", dedupe_mode="finding")
    config_path = tmp_path / "alertbot.config.json"
    write_config(config, config_path)

    run_alertbot(
        config=config,
        config_path=config_path,
        dry_run=False,
        client=FakeClient(rows=[{"attack_path_id": "ap-1", "finding_id": "f-1"}]),
        now_fn=lambda: "2026-06-17T00:00:00Z",
    )

    result = run_alertbot(
        config=config,
        config_path=config_path,
        dry_run=True,
        client=FakeClient(
            rows=[
                {"attack_path_id": "ap-1", "finding_id": "f-1"},
                {"attack_path_id": "ap-1", "finding_id": "f-2"},
            ]
        ),
        now_fn=lambda: "2026-06-17T00:01:00Z",
    )

    assert result.candidate_attack_paths == 1
    assert len(result.payloads) == 1
    assert result.payloads[0]["counts"]["findings"] == 1
    assert result.payloads[0]["findings"][0]["id"] == "f-2"


def test_finding_dedupe_marks_only_delivered_findings(tmp_path, monkeypatch):
    captured_payloads = []

    def fake_post_webhook(url, payload, timeout_seconds):
        captured_payloads.append(payload)
        return DeliveryResult(success=True, status_code=204)

    monkeypatch.setattr("alertbot.runner.post_webhook", fake_post_webhook)
    config = _config(tmp_path, first_run_behavior="alert", dedupe_mode="finding")
    config_path = tmp_path / "alertbot.config.json"
    write_config(config, config_path)

    result = run_alertbot(
        config=config,
        config_path=config_path,
        dry_run=False,
        client=FakeClient(
            rows=[
                {"attack_path_id": "ap-1", "finding_id": "f-1"},
                {"attack_path_id": "ap-1", "finding_id": "f-2"},
            ]
        ),
        now_fn=lambda: "2026-06-17T00:00:00Z",
    )
    state = load_state(tmp_path / "state.json")

    assert result.delivered_count == 1
    assert captured_payloads[0]["counts"]["findings"] == 2
    assert state.recorded_finding_keys("domain:0:Type A") == {"id:f-1", "id:f-2"}


def test_group_dedupe_still_suppresses_new_findings_in_seen_group(tmp_path):
    config = _config(tmp_path, first_run_behavior="baseline", dedupe_mode="group")
    config_path = tmp_path / "alertbot.config.json"
    write_config(config, config_path)

    run_alertbot(
        config=config,
        config_path=config_path,
        dry_run=False,
        client=FakeClient(rows=[{"attack_path_id": "ap-1", "finding_id": "f-1"}]),
        now_fn=lambda: "2026-06-17T00:00:00Z",
    )

    result = run_alertbot(
        config=config,
        config_path=config_path,
        dry_run=True,
        client=FakeClient(
            rows=[
                {"attack_path_id": "ap-1", "finding_id": "f-1"},
                {"attack_path_id": "ap-1", "finding_id": "f-2"},
            ]
        ),
        now_fn=lambda: "2026-06-17T00:01:00Z",
    )

    assert result.candidate_attack_paths == 0
    assert result.payloads == []


def test_switching_group_state_to_finding_dedupe_baselines_existing_group(tmp_path):
    group_config = _config(tmp_path, first_run_behavior="baseline", dedupe_mode="group")
    finding_config = _config(tmp_path, first_run_behavior="baseline", dedupe_mode="finding")
    config_path = tmp_path / "alertbot.config.json"
    write_config(group_config, config_path)

    run_alertbot(
        config=group_config,
        config_path=config_path,
        dry_run=False,
        client=FakeClient(
            rows=[
                {"attack_path_id": "ap-1", "finding_id": "f-1"},
                {"attack_path_id": "ap-1", "finding_id": "f-2"},
            ]
        ),
        now_fn=lambda: "2026-06-17T00:00:00Z",
    )

    run_alertbot(
        config=finding_config,
        config_path=config_path,
        dry_run=False,
        client=FakeClient(
            rows=[
                {"attack_path_id": "ap-1", "finding_id": "f-1"},
                {"attack_path_id": "ap-1", "finding_id": "f-2"},
            ]
        ),
        now_fn=lambda: "2026-06-17T00:01:00Z",
    )

    result = run_alertbot(
        config=finding_config,
        config_path=config_path,
        dry_run=True,
        client=FakeClient(
            rows=[
                {"attack_path_id": "ap-1", "finding_id": "f-1"},
                {"attack_path_id": "ap-1", "finding_id": "f-2"},
                {"attack_path_id": "ap-1", "finding_id": "f-3"},
            ]
        ),
        now_fn=lambda: "2026-06-17T00:02:00Z",
    )

    state = load_state(tmp_path / "state.json")

    assert state.recorded_finding_keys("domain:0:Type A") == {"id:f-1", "id:f-2"}
    assert len(result.payloads) == 1
    assert result.payloads[0]["findings"][0]["id"] == "f-3"
