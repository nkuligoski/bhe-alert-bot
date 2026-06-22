from alertbot.alert_builder import build_alert_payload
from alertbot.config import config_from_dict
from alertbot.models import AttackPathGroup, DomainInfo


def _config():
    return config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
            "asset_group_tag": {"id": 0, "name": "Default / Hygiene"},
        }
    )


def test_build_alert_payload_includes_grouped_findings():
    group = AttackPathGroup(
        state_key="domain:Path Type",
        attack_path_id="Path Type",
        domain=DomainInfo(id="domain", name="example.local"),
        attack_path_type="Path Type",
        findings=[
            {"attack_path_id": "ap-1", "finding_id": "f-1", "title": "Finding", "severity": "high"}
        ],
    )

    payload = build_alert_payload(group, _config(), alerted_at="2026-06-17T00:00:00Z")

    assert payload["event_type"] == "new_attack_path"
    assert payload["attack_path"]["id"] == "Path Type"
    assert payload["attack_path"]["url"] == (
        "https://tenant.example/ui/graphview?"
        "environmentId=domain&assetGroupTagId=0&findingName=Path+Type"
    )
    assert payload["counts"]["findings"] == 1
    assert payload["additional_findings"] is False
    assert "examples" not in payload
    assert payload["findings"][0]["id"] == "f-1"
    assert "raw" not in payload["findings"][0]


def test_build_alert_payload_uses_details_endpoint_fields():
    group = AttackPathGroup(
        state_key="domain:Path Type",
        attack_path_id="Path Type",
        domain=DomainInfo(id="domain", name="example.local"),
        attack_path_type="Path Type",
        findings=[
            {
                "id": 1,
                "created_at": "2024-08-28T21:21:40.845Z",
                "updated_at": "2024-08-28T21:21:40.845Z",
                "FromPrincipal": "alice@example.local",
                "ToPrincipal": "server01.example.local",
                "Finding": "Path Type",
                "Severity": "high",
            }
        ],
    )

    payload = build_alert_payload(group, _config(), alerted_at="2026-06-18T00:00:00Z")

    assert payload["attack_path"]["severity"] == "high"
    assert payload["attack_path"]["summary"] == "alice@example.local -> Path Type -> server01.example.local"
    assert payload["attack_path"]["url"] == (
        "https://tenant.example/ui/graphview?"
        "environmentId=domain&assetGroupTagId=0&findingName=Path+Type"
    )
    assert payload["observed_at"] == "2024-08-28T21:21:40.845Z"
    assert payload["findings"][0]["id"] == 1
    assert payload["findings"][0]["title"] == "Path Type"
    assert payload["findings"][0]["from"] == "alice@example.local"
    assert payload["findings"][0]["to"] == "server01.example.local"
    assert payload["findings"][0]["summary"] == "alice@example.local -> Path Type -> server01.example.local"


def test_build_alert_payload_summarizes_multiple_findings():
    group = AttackPathGroup(
        state_key="domain:Path Type",
        attack_path_id="Path Type",
        domain=DomainInfo(id="domain", name="example.local"),
        attack_path_type="Path Type",
        asset_group_tag_id=1,
        asset_group_tag_name="Tier Zero",
        findings=[
            {
                "id": 1,
                "FromPrincipal": "alice@example.local",
                "ToPrincipal": "server01.example.local",
                "Finding": "Path Type",
                "Severity": "high",
            },
            {
                "id": 2,
                "FromPrincipal": "bob@example.local",
                "ToPrincipal": "server01.example.local",
                "Finding": "Path Type",
                "Severity": "high",
            },
            {
                "id": 3,
                "FromPrincipal": "alice@example.local",
                "ToPrincipal": "server02.example.local",
                "Finding": "Path Type",
                "Severity": "high",
            },
        ],
    )

    payload = build_alert_payload(group, _config(), alerted_at="2026-06-18T00:00:00Z")

    assert payload["attack_path"]["summary"] == (
        "3 findings for Path Type in example.local for Tier Zero "
        "from 2 source principals to 2 target principals."
    )
    assert payload["counts"] == {
        "findings": 3,
        "source_principals": 2,
        "target_principals": 2,
        "objects": 0,
    }
    assert len(payload["findings"]) == 3
    assert payload["additional_findings"] is False
    assert payload["findings"][0]["summary"] == "alice@example.local -> Path Type -> server01.example.local"


def test_build_alert_payload_limits_findings_and_flags_additional_findings():
    group = AttackPathGroup(
        state_key="domain:Path Type",
        attack_path_id="Path Type",
        domain=DomainInfo(id="domain", name="example.local"),
        attack_path_type="Path Type",
        findings=[
            {
                "id": index,
                "FromPrincipal": f"user{index}@example.local",
                "ToPrincipal": "server01.example.local",
                "Finding": "Path Type",
                "Severity": "high",
            }
            for index in range(1, 6)
        ],
    )

    payload = build_alert_payload(group, _config(), alerted_at="2026-06-18T00:00:00Z")

    assert payload["counts"]["findings"] == 5
    assert len(payload["findings"]) == 3
    assert payload["findings"][-1]["id"] == 3
    assert payload["additional_findings"] is True


def test_build_alert_payload_summarizes_object_only_findings():
    group = AttackPathGroup(
        state_key="domain:T0MarkSensitive",
        attack_path_id="T0MarkSensitive",
        domain=DomainInfo(id="domain", name="example.local"),
        attack_path_type="T0MarkSensitive",
        asset_group_tag_id=1,
        asset_group_tag_name="Tier Zero",
        findings=[
            {
                "id": 7,
                "Finding": "T0MarkSensitive",
                "PrincipalHash": "ADMINISTRATOR@EXAMPLE.LOCAL",
                "Severity": "critical",
            },
            {
                "id": 8,
                "Finding": "T0MarkSensitive",
                "PrincipalHash": "HELPDESK@EXAMPLE.LOCAL",
                "Severity": "critical",
            },
            {
                "id": 9,
                "Finding": "T0MarkSensitive",
                "PrincipalHash": "ADMINISTRATOR@EXAMPLE.LOCAL",
                "Severity": "critical",
            },
        ],
    )

    payload = build_alert_payload(group, _config(), alerted_at="2026-06-18T00:00:00Z")

    assert payload["attack_path"]["summary"] == (
        "3 findings for T0MarkSensitive in example.local for Tier Zero affecting 2 objects."
    )
    assert payload["counts"] == {
        "findings": 3,
        "source_principals": 0,
        "target_principals": 0,
        "objects": 2,
    }
    assert payload["findings"][0]["object"] == "ADMINISTRATOR@EXAMPLE.LOCAL"
    assert payload["findings"][0]["summary"] == "ADMINISTRATOR@EXAMPLE.LOCAL has finding T0MarkSensitive"
