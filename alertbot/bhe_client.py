"""BloodHound Enterprise API client."""

import base64
import datetime
import hashlib
import hmac
import logging
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from .models import AlertBotConfig, Credentials

LOGGER = logging.getLogger(__name__)
ENTERPRISE_PRODUCT_EDITION = "enterprise"


class UnsupportedProductEditionError(ValueError):
    """Raised when the connected BloodHound tenant is not Enterprise edition."""


def validate_enterprise_version(version: Dict[str, Any]) -> None:
    """Validate that version metadata identifies an Enterprise tenant."""
    product_edition = version.get("product_edition")
    normalized_edition = str(product_edition or "").strip().lower()
    if normalized_edition != ENTERPRISE_PRODUCT_EDITION:
        received = product_edition if product_edition else "unknown"
        raise UnsupportedProductEditionError(
            "BloodHound product_edition must be 'enterprise'; "
            f"received '{received}'."
        )


class BHEClient:
    """Client object to perform signed requests to the BloodHound Enterprise API."""

    def __init__(
        self,
        scheme: str,
        host: str,
        port: int,
        credentials: Credentials,
        timeout_seconds: float = 10.0,
    ) -> None:
        """Create a signed BHE API client for one tenant and credential pair."""
        self._scheme = scheme
        self._host = host
        self._port = port
        self._credentials = credentials
        self._timeout_seconds = timeout_seconds

    @classmethod
    def from_config(cls, config: AlertBotConfig, credentials: Credentials) -> "BHEClient":
        """Create a client from AlertBot config and resolved credentials."""
        return cls(
            scheme=config.bhe.scheme,
            host=config.bhe.tenant,
            port=config.bhe.port,
            credentials=credentials,
            timeout_seconds=config.webhook.timeout_seconds,
        )

    def _format_url(self, uri: str, params: Optional[dict] = None) -> str:
        """Build an absolute API URL and encode optional query parameters."""
        formatted_uri = uri[1:] if uri.startswith("/") else uri
        base_url = f"{self._scheme}://{self._host}:{self._port}/{formatted_uri}"
        if params:
            return f"{base_url}?{urllib.parse.urlencode(params)}"
        return base_url

    def _request(
        self,
        method: str,
        uri: str,
        options: Optional[Dict[str, Any]] = None,
        content_type: str = "application/json",
    ) -> requests.Response:
        """Send a signed BHE API request using the HMAC signature chain."""
        options = options or {}
        params = options.get("params")
        body = options.get("body")
        prefer = options.get("prefer")

        url = self._format_url(uri, params=params)
        LOGGER.info("%s %s", method, url)

        digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)

        full_uri = uri
        if params:
            full_uri = f"{uri}?{urllib.parse.urlencode(params)}"
        digester.update(f"{method}{full_uri}".encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
        digester.update(datetime_formatted[:13].encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        if body is not None:
            digester.update(body)

        headers = {
            "User-Agent": "bhe-alertbot 001",
            "Authorization": f"bhesignature {self._credentials.token_id}",
            "RequestDate": datetime_formatted,
            "Signature": base64.b64encode(digester.digest()).decode(),
            "Accept": content_type,
            "Content-Type": content_type,
        }
        if prefer is not None:
            headers["Prefer"] = f"{prefer}"

        return requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            timeout=self._timeout_seconds,
        )

    def _fetch_data(self, uri: str, params: Optional[Dict[str, Any]] = None) -> List[Any]:
        """Fetch a JSON endpoint and normalize its `data` field to a list."""
        response = self._request("GET", uri, options={"params": params or {}})
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict):
            data = payload.get("data", [])
            return data if isinstance(data, list) else [data]
        return payload if isinstance(payload, list) else []

    def fetch_all_available_domains(self, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Return BHE domains that can be monitored for Attack Paths."""
        data = self._fetch_data("/api/v2/available-domains", params)
        return [item for item in data if isinstance(item, dict)]

    def fetch_version(self) -> Dict[str, Any]:
        """Return BloodHound version metadata from the API version endpoint."""
        response = self._request("GET", "/api/version")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return {}
        data = payload.get("data", {})
        return data if isinstance(data, dict) else {}

    def ensure_enterprise_edition(self) -> Dict[str, Any]:
        """Validate that the connected BloodHound tenant is Enterprise edition."""
        version = self.fetch_version()
        validate_enterprise_version(version)
        return version

    def fetch_asset_group_tags(self) -> List[Dict[str, Any]]:
        """Return asset group tags from the nested asset-group-tags response."""
        response = self._request("GET", "/api/v2/asset-group-tags")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return []
        data = payload.get("data", {})
        if not isinstance(data, dict):
            return []
        tags = data.get("tags", [])
        return [tag for tag in tags if isinstance(tag, dict)]

    def fetch_available_types_for_each_domain(
        self,
        domain_sid: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Any]:
        """Return available Attack Path types for a domain and optional tag filter."""
        return self._fetch_data(f"/api/v2/domains/{domain_sid}/available-types", params)

    def fetch_attack_path_finding_details_page(
        self,
        domain_sid: str,
        finding: str,
        skip: int = 0,
        limit: int = 500,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch one JSON page of detail rows for a domain and Attack Path type."""
        uri = f"/api/v2/domains/{domain_sid}/details"
        page_params = params.copy() if params else {}
        page_params.update(
            {
                "finding": finding,
                "skip": skip,
                "limit": limit,
            }
        )
        rows = self._fetch_data(uri, page_params)
        return [row for row in rows if isinstance(row, dict)]

    def fetch_attack_path_finding_details(
        self,
        domain_sid: str,
        finding: str,
        page_size: int = 500,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch all detail rows for a domain and Attack Path type."""
        all_rows: List[Dict[str, Any]] = []
        skip = 0

        while True:
            page_rows = self.fetch_attack_path_finding_details_page(
                domain_sid=domain_sid,
                finding=finding,
                skip=skip,
                limit=page_size,
                params=params,
            )
            if not page_rows:
                break
            all_rows.extend(page_rows)
            if len(page_rows) < page_size:
                break
            skip += page_size

        return all_rows


def normalize_attack_path_type(value: Any) -> str:
    """Normalize BHE Attack Path type responses to the finding name string."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("finding", "name", "type", "id"):
            if value.get(key):
                return str(value[key])
    return str(value)
