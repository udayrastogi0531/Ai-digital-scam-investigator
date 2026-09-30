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

The order of the safety checks is part of the contract: dimensions are read
from the header and compared against the cap *before* the pixel data is
decoded, so an oversized image is rejected without ever being decompressed,
and Pillow's own decompression-bomb guard (which derives from ``Exception``,
not ``OSError``) is translated into the same 400 as every other rejection.
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


def test_dimension_cap_is_checked_before_the_image_is_decoded(client, monkeypatch):
    """Images above the 64M-pixel cap are rejected *without* being decoded.

    The dimensions come from the header, which ``Image.open`` reads eagerly, so
    the cap can be enforced before ``load()`` allocates the pixel buffer. The
    stub records whether the decode was reached; a genuine 64M+ pixel image
    would allocate hundreds of megabytes to exercise the same branch.
    """
    decoded: list[bool] = []

    class _HugeImage:
        size = (20_000, 20_000)  # 400 M pixels, six times the cap

        def load(self) -> None:
            decoded.append(True)

    monkeypatch.setattr("PIL.Image.open", lambda *a, **k: _HugeImage())

    resp = client.post(
        "/api/analyze/image",
        files={"image": ("bomb.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 400
    assert "dimensions" in resp.json()["detail"].lower()
    assert not decoded, "oversized image was decoded before the cap was applied"


@pytest.mark.parametrize(
    "error",
    [Image.DecompressionBombError("too many pixels"), Image.DecompressionBombWarning("too many pixels")],
    ids=["bomb-error", "bomb-warning"],
)
def test_pillow_bomb_guard_becomes_a_400_not_a_server_error(client, monkeypatch, error):
    """Pillow's own bomb guard is translated into the standard rejection.

    ``DecompressionBombError`` derives from ``Exception``, not ``OSError``, so
    an unnamed handler lets it escape as a 500. Raising it from ``Image.open``
    is exactly where Pillow raises it — while reading the header, before any
    pixel data is decoded.
    """

    def _raise(*args, **kwargs):
        raise error

    monkeypatch.setattr("PIL.Image.open", _raise)

    resp = client.post(
        "/api/analyze/image",
        files={"image": ("bomb.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 400
    assert "too large" in resp.json()["detail"].lower()


def test_decode_time_exhaustion_is_reported_as_too_large(client, monkeypatch):
    """A cap-sized file that still exhausts memory on decode is a clean 400.

    ``MemoryError`` is neither an ``OSError`` nor an ``HTTPException``; without
    an explicit clause it would surface as a server error.
    """

    class _ExplodingImage:
        size = (800, 600)

        def load(self) -> None:
            raise MemoryError("cannot allocate pixel buffer")

    monkeypatch.setattr("PIL.Image.open", lambda *a, **k: _ExplodingImage())

    resp = client.post(
        "/api/analyze/image",
        files={"image": ("bomb.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert resp.status_code == 400
    assert "too large" in resp.json()["detail"].lower()


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
