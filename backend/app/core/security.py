"""Security helpers: safe upload handling and filename sanitization.

All user-supplied content is treated as untrusted:
* size limits
* MIME sniffing via Pillow (the declared content-type is not trusted)
* filenames are never used as-is on disk
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path

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
    """Strip path components and suspicious characters."""
    name = name or "upload"
    name = Path(name).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:120] or "upload"


async def read_image_upload(upload: UploadFile) -> bytes:
    """Read an upload, enforcing size and validating that it is a real image.

    Returns raw image bytes (validated).  Does NOT trust the content-type
    header; Pillow must be able to decode the image.
    """
    settings = get_settings()
    max_bytes = settings.max_upload_mb * 1024 * 1024
    data = await upload.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UnsafeUploadError(f"File too large (max {settings.max_upload_mb} MB)")
    if not data:
        raise UnsafeUploadError("Empty file")

    import io

    from PIL import Image, UnidentifiedImageError

    # ``DecompressionBombError`` derives from ``Exception`` — *not* from
    # ``OSError`` — so it is invisible to the handler below unless it is named
    # explicitly.  Left uncaught it escapes this function entirely and the
    # client sees a 500 instead of a validation error.  Pillow raises it while
    # reading the header (above ``Image.MAX_IMAGE_PIXELS`` it warns above
    # ~89 M pixels, above twice that it raises), i.e. before any pixels are
    # decoded.
    _BOMB = (Image.DecompressionBombError, Image.DecompressionBombWarning)

    try:
        image = Image.open(io.BytesIO(data))
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise UnsafeUploadError("Uploaded file is not a valid image") from exc
    except (*_BOMB, MemoryError) as exc:
        raise UnsafeUploadError("Image is too large to process safely") from exc

    # Decompression-bomb protection, checked *before* the decode.
    # ``Image.open`` reads only the header, so ``image.size`` is known without
    # allocating the pixel buffer that ``load()`` would create; an oversized
    # image is therefore rejected without ever being decompressed.
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
    return data


async def persist_upload(upload: UploadFile) -> Path:
    """Validate + store an uploaded image; returns the stored path."""
    settings = get_settings()
    data = await read_image_upload(upload)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    ext = Path(upload.filename or "image").suffix.lower() if upload.filename else ".png"
    if ext not in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}:
        ext = ".png"
    target = settings.upload_dir / f"{uuid.uuid4().hex}{ext}"
    target.write_bytes(data)
    return target