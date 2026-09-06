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

    from PIL import Image, UnidentifiedImageError

    try:
        import io

        image = Image.open(io.BytesIO(data))
        image.load()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise UnsafeUploadError("Uploaded file is not a valid image") from exc

    # decompression-bomb protection
    if image.width * image.height > 64_000_000:
        raise UnsafeUploadError("Image dimensions are too large")
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