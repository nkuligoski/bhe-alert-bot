import requests

from alertbot.webhook import post_webhook


class Response:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


def test_post_webhook_success(monkeypatch):
    def fake_post(url, **kwargs):
        assert url == "https://webhook.example"
        assert kwargs["json"] == {"hello": "world"}
        return Response(204)

    monkeypatch.setattr("alertbot.webhook.requests.post", fake_post)

    result = post_webhook("https://webhook.example", {"hello": "world"})

    assert result.success
    assert result.status_code == 204


def test_post_webhook_failure_status(monkeypatch):
    monkeypatch.setattr("alertbot.webhook.requests.post", lambda url, **kwargs: Response(500, "nope"))

    result = post_webhook("https://webhook.example", {})

    assert not result.success
    assert result.status_code == 500


def test_post_webhook_request_exception(monkeypatch):
    def fake_post(url, **kwargs):
        raise requests.Timeout("timed out")

    monkeypatch.setattr("alertbot.webhook.requests.post", fake_post)

    result = post_webhook("https://webhook.example", {})

    assert not result.success
    assert "timed out" in result.error
