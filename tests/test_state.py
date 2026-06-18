from alertbot.models import AttackPathGroup, DomainInfo
from alertbot.state import AlertState, finding_state_key, load_state, save_state


def test_state_round_trip(tmp_path):
    state_path = tmp_path / "state.json"
    group = AttackPathGroup(
        state_key="domain:ap-1",
        attack_path_id="ap-1",
        domain=DomainInfo(id="domain", name="example.local"),
        attack_path_type="test-path",
    )
    state = AlertState()
    state.mark_attack_path(group, recorded_at="2026-06-17T00:00:00Z", delivery_status_code=200)
    state.last_successful_run_at = "2026-06-17T00:00:00Z"

    save_state(state, state_path)
    loaded = load_state(state_path)

    assert loaded.has_attack_path("domain:ap-1")
    assert loaded.last_successful_run_at == "2026-06-17T00:00:00Z"


def test_finding_level_state_merges_finding_keys(tmp_path):
    state_path = tmp_path / "state.json"
    group = AttackPathGroup(
        state_key="domain:ap-1",
        attack_path_id="ap-1",
        domain=DomainInfo(id="domain", name="example.local"),
        attack_path_type="test-path",
        findings=[{"finding_id": "f-1"}],
    )
    state = AlertState()
    state.mark_attack_path(
        group,
        recorded_at="2026-06-17T00:00:00Z",
        dedupe_mode="finding",
    )
    group.findings = [{"finding_id": "f-2"}]
    state.mark_attack_path(
        group,
        recorded_at="2026-06-17T00:01:00Z",
        dedupe_mode="finding",
    )

    save_state(state, state_path)
    loaded = load_state(state_path)

    assert loaded.recorded_finding_keys("domain:ap-1") == {"id:f-1", "id:f-2"}


def test_finding_state_key_falls_back_to_content_hash():
    first = finding_state_key({"ObjectName": "server01", "Finding": "Type A"})
    second = finding_state_key({"Finding": "Type A", "ObjectName": "server01"})

    assert first == second
    assert first.startswith("sha256:")


def test_unrecorded_findings_deduplicates_current_rows():
    group = AttackPathGroup(
        state_key="domain:ap-1",
        attack_path_id="ap-1",
        domain=DomainInfo(id="domain", name="example.local"),
        attack_path_type="test-path",
        findings=[
            {"finding_id": "f-1"},
            {"finding_id": "f-1"},
            {"finding_id": "f-2"},
        ],
    )

    assert AlertState().unrecorded_findings(group) == [
        {"finding_id": "f-1"},
        {"finding_id": "f-2"},
    ]
