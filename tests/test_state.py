from alertbot.models import AttackPathGroup, DomainInfo
from alertbot.state import AlertState, load_state, save_state


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
