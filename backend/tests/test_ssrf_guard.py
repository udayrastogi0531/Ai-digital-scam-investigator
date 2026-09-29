"""The no-SSRF property, asserted rather than assumed.

The application must never dereference a URL a user submitted. URLs are
analysed structurally and sent to reputation providers **as values**; the
only hosts the backend is allowed to contact are the configured third-party
services.

Until now this was established by reading the code. This test proves it
behaviourally: every outbound request made while investigating a submission
containing an internal-looking address is captured, and none of them may
target that address.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from app.core.config import get_settings
from app.intelligence.manager import get_manager

# Hosts the backend is permitted to contact for reputation lookups.
_ALLOWED_HOSTS = {
    "safebrowsing.googleapis.com",
    "www.virustotal.com",
    "virustotal.com",
}

# Addresses a user might submit hoping the server will fetch them for us.
_INTERNAL_URLS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://internal.example.local/admin",
    "http://localhost:8000/api/health",
]


def test_pipeline_never_fetches_submitted_urls(client, monkeypatch):
    """Outbound requests may only go to configured reputation providers."""
    calls: list[str] = []

    async def _recording_send(self, request, **kwargs):  # noqa: ANN001, ANN003
        calls.append(str(request.url))
        target = str(request.url)
        if "safebrowsing" in target:
            # Empty match set: a clean, informative verdict.
            return httpx.Response(200, json={}, request=request)
        if "virustotal" in target:
            # 404 -> "not seen", which must not read as clean.
            return httpx.Response(404, json={}, request=request)
        return httpx.Response(200, json={}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", _recording_send)
    # Dummy keys so the real (non-mock) providers are constructed and attempt
    # a lookup; with no keys configured nothing would call out at all.
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "dummy-not-a-real-key")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy-not-a-real-key")
    get_settings.cache_clear()
    get_manager.cache_clear()
    try:
        resp = client.post(
            "/api/investigations",
            data={
                "text": "Urgent: your account is locked. Verify now or it will be closed.",
                "urls": _INTERNAL_URLS,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "completed"
    finally:
        # Never leak live providers into the rest of the suite.
        get_settings.cache_clear()
        get_manager.cache_clear()

    # The providers must actually have run, otherwise this test proves nothing.
    assert calls, "no outbound request was made — the guard was not exercised"

    for called in calls:
        host = urlsplit(called).hostname or ""
        assert host in _ALLOWED_HOSTS, f"unexpected outbound host contacted: {called}"

    # The decisive assertion: the addresses the user submitted were sent as
    # values, never requested.
    for internal in _INTERNAL_URLS:
        internal_host = urlsplit(internal).hostname or ""
        assert not any(urlsplit(c).hostname == internal_host for c in calls), (
            f"the server fetched a user-submitted host: {internal_host}"
        )


def test_provider_payload_carries_the_url_as_data(monkeypatch):
    """A lookup transmits the URL inside the payload, not as a request target.

    The Safe Browsing provider posts to a fixed endpoint; the URL under
    investigation appears only in the request body.
    """
    captured: dict = {}

    async def _capture_send(self, request, **kwargs):  # noqa: ANN001, ANN003
        captured["url"] = str(request.url)
        captured["body"] = request.content.decode("utf-8", errors="replace")
        return httpx.Response(200, json={}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", _capture_send)

    from app.intelligence.google_safe_browsing import GoogleSafeBrowsingProvider

    import asyncio

    target = "http://169.254.169.254/latest/meta-data/"
    result = asyncio.run(GoogleSafeBrowsingProvider(api_key="dummy").check(target))

    assert result.provider == "google_safe_browsing"
    assert captured["url"] == "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    assert "169.254.169.254" in captured["body"]
    assert "169.254.169.254" not in captured["url"]
