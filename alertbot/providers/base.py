"""Shared provider interfaces for webhook payload formatting."""

from typing import Any, Dict, Protocol


AlertPayload = Dict[str, Any]


class WebhookProvider(Protocol):
    """Format a canonical AlertBot payload for one destination type."""

    name: str

    def matches_url(self, url: str) -> bool:
        """Return whether this provider should handle a URL in auto mode."""
        ...

    def build_payload(self, alert_payload: AlertPayload) -> AlertPayload:
        """Convert a canonical AlertBot payload into the provider-specific payload."""
        ...
