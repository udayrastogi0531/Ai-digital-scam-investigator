"""Security helpers: safe, in-memory upload handling.

All user-supplied content is treated as untrusted:

* size limits (a bounded read, so an oversized body is never fully buffered)
* real decoding via Pillow — the declared content-type is ignored
* a pixel cap enforced from the image header *before* the pixels are decoded
* nothing is ever written to disk

``sanitize_filename`` is retained as a defensive helper for any future code
that might handle a filename, but **no route writes an upload to disk**, so it
is not on a live code path today.
"""
from __future__ import annotations

import asyncio
import io
import re

from fastapi import HTTPException, UploadFile

from app.core.config import get_settings

_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
# Our own pixel cap.  Deliberately below Pillow's default ``MAX_IMAGE_PIXELS``
# (~89 M), so an oversized image is rejected on the application's terms rather
# than Pillow's.
_MAX_PIXELS = 64_000_000


class UnsafeUploadError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=400, detail=detail)


def sanitize_filename(name: str) -> str:
    """Strip path components and suspicious characters.

    Currently unused by any route — uploads are never persisted — but kept as a
    small, tested guard in case a filename ever needs to be handled.

    Both POSIX (``/``) and Windows (``\\``) separators are reduced explicitly
    rather than through :class:`pathlib.Path`: ``Path`` splits only on the
    *host* OS separator, so ``Path(r"C:\\x\\evil.png").name`` is ``"evil.png"``
    on Windows but the whole string on POSIX.  A filename that crossed an OS
    boundary (or a body produced on a different platform than the one running
    this code) would keep its separators and then be rewritten to ``_`` by the
    character filter — turning an intended basename into a path-shaped string.
    Normalising both separators keeps the guard identical on every platform.
    """
    name = name or "upload"
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    # "." and ".." survive basename extraction but are themselves traversal
    # tokens, so they map to the same neutral fallback as an empty name.
    if name in (".", "..") or not name.strip():
        return "upload"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:120] or "upload"


def _validate_image_bytes(data: bytes) -> None:
    """Decode and validate raw image bytes.  **Blocking** — run off the loop.

    Raises :class:`UnsafeUploadError` for every rejected input.  ``Image.open``
    reads only the header, so ``image.size`` is known without allocating the
    pixel buffer that ``load()`` would create; an oversized image is therefore
    rejected before it is ever decompressed.
    """
    from PIL import Image, UnidentifiedImageError

    # ``DecompressionBombError`` derives from ``Exception`` — *not* from
    # ``OSError`` — so it is invisible to a handler that only names ``OSError``.
    # Left uncaught it escapes this function entirely and the client sees a 500
    # instead of a validation error.  Pillow raises it while reading the header
    # (above ``Image.MAX_IMAGE_PIXELS`` it warns above ~89 M pixels, above twice
    # that it raises), i.e. before any pixels are decoded.
    _BOMB = (Image.DecompressionBombError, Image.DecompressionBombWarning)

    try:
        image = Image.open(io.BytesIO(data))
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise UnsafeUploadError("Uploaded file is not a valid image") from exc
    except (*_BOMB, MemoryError) as exc:
        raise UnsafeUploadError("Image is too large to process safely") from exc

    # Decompression-bomb protection, checked *before* the decode.
    if image.size[0] * image.size[1] > _MAX_PIXELS:
        raise UnsafeUploadError("Image dimensions are too large")

    try:
        image.load()
    except (*_BOMB, MemoryError) as exc:
        # A cap-sized image can still blow up on decode (a truncated file that
        # declares large dimensions, or a format that expands at load time).
        raise UnsafeUploadError("Image is too large to process safely") from exc
    except (OSError, ValueError) as exc:
        raise UnsafeUploadError("Uploaded file is not a valid image") from exc


async def read_image_upload(upload: UploadFile) -> bytes:
    """Read an upload, enforcing size and validating that it is a real image.

    Returns the raw image bytes (validated).  The declared content-type is not
    trusted; Pillow must be able to decode the bytes.  The decode is CPU- and
    memory-bound, so it runs in a worker thread and does not block the event
    loop while it allocates the pixel buffer.
    """
    settings = get_settings()
    max_bytes = settings.max_upload_mb * 1024 * 1024
    data = await upload.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UnsafeUploadError(f"File too large (max {settings.max_upload_mb} MB)")
    if not data:
        raise UnsafeUploadError("Empty file")

    # ``run_in_executor`` returns/raises exactly what the callable did, so an
    # ``UnsafeUploadError`` still reaches the client as a ``400``.
    await asyncio.get_running_loop().run_in_executor(None, _validate_image_bytes, data)
    return data
