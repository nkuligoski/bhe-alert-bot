"""Webhook delivery."""

from typing import Any, Dict

import requests

from .models import DeliveryResult


def post_webhook(url: str, payload: Dict[str, Any], timeout_seconds: float = 10.0) -> DeliveryResult:
    """POST one compact alert payload and normalize success or failure details."""
    try:
        response = requests.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        return DeliveryResult(success=False, error=str(exc))

    return DeliveryResult(
        success=200 <= response.status_code < 300,
        status_code=response.status_code,
    )
