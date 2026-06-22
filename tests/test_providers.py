from alertbot.alert_builder import build_alert_payload
from alertbot.config import config_from_dict
from alertbot.models import AttackPathGroup, DomainInfo
from alertbot.providers import build_delivery_payload, resolve_webhook_provider


def _group():
    return AttackPathGroup(
        state_key="domain:0:Path Type",
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
            }
        ],
    )


def test_resolve_webhook_provider_auto_detects_slack():
    slack = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://hooks.slack.com/services/T000/B000/secret"},
        }
    )
    generic = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example"},
        }
    )

    assert resolve_webhook_provider(slack.webhook).name == "slack"
    assert resolve_webhook_provider(generic.webhook).name == "generic"


def test_generic_delivery_payload_keeps_canonical_alert_shape():
    config = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {"url": "https://webhook.example", "provider": "generic"},
        }
    )
    alert_payload = build_alert_payload(_group(), config, alerted_at="2026-06-18T00:00:00Z")

    delivery_payload = build_delivery_payload(alert_payload, config.webhook)

    assert delivery_payload is alert_payload
    assert delivery_payload["event_type"] == "new_attack_path"


def test_slack_delivery_payload_formats_incoming_webhook_message():
    config = config_from_dict(
        {
            "bhe": {"tenant": "tenant.example"},
            "webhook": {
                "url": "https://hooks.slack.com/services/T000/B000/secret",
                "provider": "slack",
            },
        }
    )
    alert_payload = build_alert_payload(_group(), config, alerted_at="2026-06-18T00:00:00Z")

    delivery_payload = build_delivery_payload(alert_payload, config.webhook)

    assert delivery_payload["text"] == "[HIGH] New BloodHound Attack Path: Path Type in example.local"
    assert "event_type" not in delivery_payload
    assert delivery_payload["blocks"][0]["type"] == "header"
    assert delivery_payload["blocks"][1]["text"]["type"] == "mrkdwn"
    assert "Open in BloodHound" in delivery_payload["blocks"][1]["text"]["text"]
    assert "*Domain*\nexample.local" in [
        field["text"] for field in delivery_payload["blocks"][2]["fields"]
    ]
    assert (
        "alice@example.local -&gt; Path Type -&gt; server01.example.local"
        in delivery_payload["blocks"][3]["text"]["text"]
    )
