"""Generic webhook provider."""

from .base import AlertPayload


class GenericProvider:
    """Send AlertBot's canonical JSON payload unchanged."""

    name = "generic"

    def matches_url(self, url: str) -> bool:
        """Generic webhooks are the fallback, never an auto-detected provider."""
        return False

    def build_payload(self, alert_payload: AlertPayload) -> AlertPayload:
        """Return the canonical alert payload unchanged."""
        return alert_payload
