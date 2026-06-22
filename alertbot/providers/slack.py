"""Slack incoming webhook provider."""

import urllib.parse
from typing import Any, Dict, Optional

from .base import AlertPayload


SLACK_WEBHOOK_HOSTS = {"hooks.slack.com", "hooks.slack-gov.com"}


def _slack_escape(value: Any) -> str:
    """Escape text for Slack mrkdwn fields."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _slack_value(value: Any, fallback: str = "unknown") -> str:
    """Return a display-safe Slack value with a stable fallback."""
    if value is None or value == "":
        return fallback
    return _slack_escape(value)


def _truncate(value: Any, limit: int) -> str:
    """Trim Slack text fields to known Block Kit limits."""
    text = str(value)
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3].rstrip() + "..."


def _slack_link(url: Any, label: str) -> Optional[str]:
    """Build a Slack mrkdwn link when a URL is available."""
    if not url:
        return None
    safe_url = str(url).replace("|", "%7C").replace(" ", "%20")
    return f"<{safe_url}|{_slack_escape(label)}>"


def _slack_field(label: str, value: Any) -> Dict[str, str]:
    """Build one Slack section field."""
    return {
        "type": "mrkdwn",
        "text": _truncate(f"*{label}*\n{_slack_value(value)}", 2000),
    }


class SlackProvider:
    """Format alerts for Slack incoming webhooks."""

    name = "slack"

    def matches_url(self, url: str) -> bool:
        """Return whether a URL is a Slack incoming webhook endpoint."""
        hostname = urllib.parse.urlparse(url).hostname or ""
        return hostname.lower() in SLACK_WEBHOOK_HOSTS

    def build_payload(self, alert_payload: AlertPayload) -> AlertPayload:
        """Convert a canonical AlertBot payload into a Slack message payload."""
        attack_path = alert_payload.get("attack_path", {})
        domain = alert_payload.get("domain", {})
        asset_group_tag = alert_payload.get("asset_group_tag", {})
        counts = alert_payload.get("counts", {})

        title = attack_path.get("name") or attack_path.get("type") or "Attack Path"
        severity = attack_path.get("severity")
        summary = attack_path.get("summary") or "New BloodHound Enterprise Attack Path detected."
        domain_name = domain.get("name") or domain.get("id") or "unknown domain"
        tag_name = asset_group_tag.get("name") or asset_group_tag.get("id") or "unknown"
        severity_prefix = f"[{str(severity).upper()}] " if severity else ""
        fallback_text = f"{severity_prefix}New BloodHound Attack Path: {title} in {domain_name}"

        body_lines = [
            f"*{_slack_escape(title)}*",
            _slack_escape(summary),
        ]
        graph_link = _slack_link(attack_path.get("url"), "Open in BloodHound")
        if graph_link:
            body_lines.append(graph_link)

        fields = [
            _slack_field("Domain", domain_name),
            _slack_field("Asset group tag", tag_name),
            _slack_field("Severity", severity or "unknown"),
            _slack_field("Findings", counts.get("findings", 0)),
        ]
        if counts.get("source_principals"):
            fields.append(_slack_field("Source principals", counts["source_principals"]))
        if counts.get("target_principals"):
            fields.append(_slack_field("Target principals", counts["target_principals"]))
        if counts.get("objects"):
            fields.append(_slack_field("Objects", counts["objects"]))

        blocks: list[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": _truncate(f"New Attack Path: {title}", 150),
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": _truncate("\n".join(body_lines), 3000),
                },
            },
            {
                "type": "section",
                "fields": fields[:10],
            },
        ]

        finding_lines = []
        for finding in alert_payload.get("findings", []):
            finding_summary = (
                finding.get("summary")
                or finding.get("title")
                or finding.get("object")
                or finding.get("id")
            )
            if finding_summary:
                finding_lines.append(f"- {_slack_value(finding_summary)}")
        if alert_payload.get("additional_findings"):
            finding_lines.append("- Additional findings are available in BloodHound.")
        if finding_lines:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": _truncate("*Findings*\n" + "\n".join(finding_lines), 3000),
                    },
                }
            )

        return {
            "text": _truncate(_slack_escape(fallback_text), 3000),
            "blocks": blocks,
        }
