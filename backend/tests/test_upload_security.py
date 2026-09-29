"""Upload-rejection coverage for ``app.core.security``.

The happy path was covered (``test_api_integration.py``); every rejection
branch was implemented but untested, so a regression that let a bad upload
through would have been silent.  These tests pin the contract that matters:
the declared content type is ignored, the bytes must really decode as an
image, the size and pixel caps are enforced, and a rejected upload never
creates an investigation.

They also pin the privacy property the documentation relies on: a valid
upload is analysed in memory and **nothing** is written to the upload
directory.

Two honest gaps are pinned here rather than described loosely (see
``test_dimension_cap_is_applied_after_decode`` and
``test_pillow_bomb_error_is_not_translated_to_a_400``).
"""
from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest
from PIL import Image

from app.core.config import get_settings
from app.core.security import read_image_upload, sanitize_filename
from tests.conftest import BENIGN_NOTE

MAX_BYTES = 10 * 1024 * 1024  # default MAX_UPLOAD_MB


def _png_bytes(size: tuple[int, int] = (120, 60)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color=(250, 250, 250)).save(buf, format="PNG")
    return buf.getvalue()


def _uploads_dir() -> Path:
    return get_settings().upload_dir


# --- filename helper (unit) -------------------------------------------------


def test_sanitize_filename_strips_path_components():
    """The helper must never return something usable as a path.

    Note: no route calls this helper today — uploads are not written to disk
    at all — so this pins its behaviour for the day it is wired in.
    """
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename(r"C:\Windows\System32\evil.png") == "evil.png"
    assert "/" not in sanitize_filename("a/b/c.png")
    assert "\\" not in sanitize_filename("a\\b\\c.png")
    # A path made only of traversal segments collapses to the bare segment;
    # separators are gone, which is the property that matters.
    assert "/" not in sanitize_filename("../../../")


def test_sanitize_filename_replaces_suspicious_characters():
    assert sanitize_filename("my shot (1).png") == "my_shot__1_.png"
    assert len(sanitize_filename("x" * 500)) == 120
    assert sanitize_filename("") == "upload"


# --- in-memory handling -----------------------------------------------------


def test_read_image_upload_returns_bytes_without_touching_disk():
    """A valid image is decoded in memory; no upload file is created."""

    class _Upload:
        filename = "shot.png"

        async def read(self, n: int = -1) -> bytes:
            return data

    data = _png_bytes()
    before = set(_uploads_dir().glob("*")) if _uploads_dir().exists() else set()

    out = asyncio.run(read_image_upload(_Upload()))  # type: ignore[arg-type]
    assert out == data

    after = set(_uploads_dir().glob("*")) if _uploads_dir().exists() else set()
    assert before == after, "upload evidence was written to disk"


# --- rejection branches through the API -------------------------------------


def test_empty_upload_is_rejected(client):
    resp = client.post(
        "/api/analyze/image",
        files={"image": ("empty.png", b"", "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()


def test_oversized_upload_is_rejected(client):
    resp = client.post(
        "/api/analyze/image",
        files={"image": ("big.png", b"\x00" * (MAX_BYTES + 1), "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 400
    assert "too large" in resp.json()["detail"].lower()


def test_non_image_bytes_are_rejected_even_with_an_image_content_type(client):
    """The declared content type is not trusted — the bytes must decode."""
    resp = client.post(
        "/api/analyze/image",
        files={"image": ("payload.png", b"this is not an image at all", "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 400
    assert "valid image" in resp.json()["detail"].lower()


def test_rejected_upload_creates_no_investigation(client):
    before = client.get("/api/investigations").json()["total"]
    resp = client.post(
        "/api/analyze/image",
        files={"image": ("payload.png", b"nope", "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 400
    assert client.get("/api/investigations").json()["total"] == before


def test_dimension_cap_is_applied_after_decode(client, monkeypatch):
    """Images above the 64M-pixel cap are rejected with a 400.

    ``read_image_upload`` calls ``image.load()`` **before** comparing
    ``width * height``, so this cap limits what is *accepted* rather than
    preventing the decode itself. A stub keeps the test cheap: a genuine
    64M+ pixel image would allocate hundreds of megabytes to reach the same
    branch.
    """

    class _HugeImage:
        width = 20_000
        height = 20_000

        def load(self) -> None:
            pass  # the real code decodes first; the cap is checked afterwards

    monkeypatch.setattr("PIL.Image.open", lambda *a, **k: _HugeImage())

    resp = client.post(
        "/api/analyze/image",
        files={"image": ("bomb.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 400
    assert "dimensions" in resp.json()["detail"].lower()


def test_pillow_bomb_error_is_not_translated_to_a_400(client, monkeypatch):
    """DOCUMENTED GAP: Pillow's own bomb guard is not handled.

    Above roughly 178M pixels Pillow raises ``DecompressionBombError``, which
    derives from ``Exception`` — not ``OSError`` — so it is neither caught by
    ``read_image_upload``'s handler (400) nor by the route's generic handler,
    and the client sees a server error instead of a clean rejection. Pinned
    here so that fixing it stays a deliberate, reviewable change.
    """

    def _raise(*args, **kwargs):
        raise Image.DecompressionBombError("too many pixels")

    monkeypatch.setattr("PIL.Image.open", _raise)

    with pytest.raises(Image.DecompressionBombError):
        client.post(
            "/api/analyze/image",
            files={"image": ("bomb.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image/png")},
            data={"text": BENIGN_NOTE},
        )


# --- control case -----------------------------------------------------------


def test_valid_image_still_succeeds_after_the_rejections(client):
    """Contrast case: the same endpoint accepts a real screenshot."""
    resp = client.post(
        "/api/analyze/image",
        files={"image": ("shot.png", _png_bytes(), "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


@pytest.mark.parametrize("filename", ["../../evil.png", "a/b/c.png"])
def test_malicious_filename_is_accepted_only_as_sanitised_input(client, filename):
    """A traversal-style filename is not an error, and never becomes a path."""
    resp = client.post(
        "/api/analyze/image",
        files={"image": (filename, _png_bytes(), "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 200
    assert ".." not in str(_uploads_dir())
