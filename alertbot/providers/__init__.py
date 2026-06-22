"""Webhook provider registry."""

from typing import Dict

from ..models import WebhookConfig
from .base import AlertPayload, WebhookProvider
from .generic import GenericProvider
from .slack import SlackProvider


GENERIC_PROVIDER = GenericProvider()
SLACK_PROVIDER = SlackProvider()

PROVIDERS_BY_NAME: Dict[str, WebhookProvider] = {
    GENERIC_PROVIDER.name: GENERIC_PROVIDER,
    SLACK_PROVIDER.name: SLACK_PROVIDER,
}
PROVIDER_NAMES = frozenset(PROVIDERS_BY_NAME)
AUTO_DETECT_PROVIDERS = (SLACK_PROVIDER,)


def provider_for_name(name: str) -> WebhookProvider:
    """Return a configured provider by name."""
    try:
        return PROVIDERS_BY_NAME[name]
    except KeyError as exc:
        raise ValueError(f"Unsupported webhook provider: {name}") from exc


def resolve_webhook_provider(webhook: WebhookConfig) -> WebhookProvider:
    """Resolve the provider configured for a webhook."""
    if webhook.provider != "auto":
        return provider_for_name(webhook.provider)

    for provider in AUTO_DETECT_PROVIDERS:
        if provider.matches_url(webhook.url):
            return provider
    return GENERIC_PROVIDER


def build_delivery_payload(
    alert_payload: AlertPayload,
    webhook: WebhookConfig,
) -> AlertPayload:
    """Format a canonical alert payload for the configured webhook provider."""
    provider = resolve_webhook_provider(webhook)
    return provider.build_payload(alert_payload)
