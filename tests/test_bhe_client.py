import pytest

from alertbot.bhe_client import BHEClient, UnsupportedProductEditionError
from alertbot.models import Credentials


class JsonResponse:
    text = ""

    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_details_endpoint_reads_json_data(monkeypatch):
    captured = {}

    def fake_request(method, url, headers, data, timeout):
        captured["url"] = url
        captured["headers"] = headers
        return JsonResponse(
            {
                "count": 1,
                "skip": 0,
                "limit": 500,
                "data": [
                    {
                        "id": 1,
                        "created_at": "2024-08-28T21:21:40.845Z",
                        "Finding": "Path Type",
                        "Severity": "high",
                    }
                ],
            }
        )

    monkeypatch.setattr("alertbot.bhe_client.requests.request", fake_request)
    client = BHEClient(
        scheme="https",
        host="tenant.example",
        port=443,
        credentials=Credentials(token_id="id", token_key="key", tenant="tenant.example"),
    )

    rows = client.fetch_attack_path_finding_details_page("S-1", "Path Type", skip=0, limit=500)

    assert rows == [
        {
            "id": 1,
            "created_at": "2024-08-28T21:21:40.845Z",
            "Finding": "Path Type",
            "Severity": "high",
        }
    ]
    assert "Accept=text%2Fcsv" not in captured["url"]
    assert captured["headers"]["Accept"] == "application/json"


def test_fetch_asset_group_tags_reads_nested_tags(monkeypatch):
    def fake_request(method, url, headers, data, timeout):
        assert url == "https://tenant.example:443/api/v2/asset-group-tags"
        return JsonResponse(
            {
                "data": {
                    "tags": [
                        {"id": 1, "name": "Tier Zero"},
                        {"id": 3, "name": "Server Tier"},
                    ]
                }
            }
        )

    monkeypatch.setattr("alertbot.bhe_client.requests.request", fake_request)
    client = BHEClient(
        scheme="https",
        host="tenant.example",
        port=443,
        credentials=Credentials(token_id="id", token_key="key", tenant="tenant.example"),
    )

    assert client.fetch_asset_group_tags() == [
        {"id": 1, "name": "Tier Zero"},
        {"id": 3, "name": "Server Tier"},
    ]


def test_fetch_version_returns_nested_version_data(monkeypatch):
    def fake_request(method, url, headers, data, timeout):
        assert method == "GET"
        assert url == "https://tenant.example:443/api/version"
        return JsonResponse(
            {
                "data": {
                    "API": {
                        "current_version": "v2",
                        "deprecated_version": "v1",
                    },
                    "server_version": "1.0.0",
                    "product_edition": "enterprise",
                }
            }
        )

    monkeypatch.setattr("alertbot.bhe_client.requests.request", fake_request)
    client = BHEClient(
        scheme="https",
        host="tenant.example",
        port=443,
        credentials=Credentials(token_id="id", token_key="key", tenant="tenant.example"),
    )

    assert client.fetch_version()["product_edition"] == "enterprise"


def test_ensure_enterprise_edition_rejects_other_editions(monkeypatch):
    def fake_request(method, url, headers, data, timeout):
        return JsonResponse({"data": {"product_edition": "community"}})

    monkeypatch.setattr("alertbot.bhe_client.requests.request", fake_request)
    client = BHEClient(
        scheme="https",
        host="tenant.example",
        port=443,
        credentials=Credentials(token_id="id", token_key="key", tenant="tenant.example"),
    )

    with pytest.raises(UnsupportedProductEditionError, match="product_edition"):
        client.ensure_enterprise_edition()
