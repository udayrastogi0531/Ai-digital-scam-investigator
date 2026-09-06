"""OCR provider abstraction.

Tesseract is used when the binary is available; otherwise an honest mock
provider is used that reports ``is_mock=True`` and extracts nothing —
so screenshot investigations still run end-to-end with a clear warning
instead of pretending OCR happened.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from PIL import Image

from app.core.config import get_settings

logger = logging.getLogger("scaminvestigator.ocr")

MAX_IMAGE_PIXELS = 16_000_000  # ~ 4000x4000


class OCRResult:
    __slots__ = ("text", "confidence", "is_mock", "provider", "error")

    def __init__(
        self,
        text: str,
        confidence: float = 0.0,
        is_mock: bool = False,
        provider: str = "unknown",
        error: str | None = None,
    ):
        self.text = text
        self.confidence = confidence
        self.is_mock = is_mock
        self.provider = provider
        self.error = error


class OCRProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def extract(self, image_bytes: bytes) -> OCRResult:
        """Extract text from raw image bytes."""


class TesseractOCRProvider(OCRProvider):
    name = "tesseract"
    is_mock = False

    def __init__(self, binary: str = "tesseract"):
        self.binary = binary

    async def extract(self, image_bytes: bytes) -> OCRResult:
        try:
            image = Image.open(__import__("io").BytesIO(image_bytes))
        except Exception as exc:  # noqa: BLE001
            return OCRResult(text="", provider=self.name, error=f"unreadable image: {exc}")
        # decode to RGB (handles PNG palette, CMYK JPEG, etc.)
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")
        if image.width * image.height > MAX_IMAGE_PIXELS:
            scale = (MAX_IMAGE_PIXELS / (image.width * image.height)) ** 0.5
            image = image.resize((int(image.width * scale), int(image.height * scale)))

        with tempfile.TemporaryDirectory() as tmp:
            img_path = Path(tmp) / "input.png"
            image.save(img_path, "PNG")
            try:
                proc = await _run_async(
                    [self.binary, str(img_path), "stdout", "--psm", "3", "-l", "eng"]
                )
            except FileNotFoundError:
                return OCRResult(
                    text="", provider=self.name, error="tesseract binary not found"
                )
        if proc.returncode != 0:
            return OCRResult(
                text="",
                provider=self.name,
                error=f"tesseract exited {proc.returncode}",
            )
        text = proc.stdout.decode("utf-8", errors="replace").strip()
        # Tesseract's per-word confidence requires TSV output; we report a
        # conservative estimate and let the caller treat it as indicative.
        confidence = 0.8 if text else 0.0
        return OCRResult(text=text, confidence=confidence, provider=self.name)


class MockOCRProvider(OCRProvider):
    """Honest fallback: extracts nothing and says so.

    The screenshot is still validated and stored; the investigation
    continues with a visible warning that OCR was unavailable.
    """

    name = "mock"
    is_mock = True

    async def extract(self, image_bytes: bytes) -> OCRResult:
        return OCRResult(
            text="",
            confidence=0.0,
            is_mock=True,
            provider=self.name,
            error="OCR unavailable (no tesseract binary); demo mode — no text extracted",
        )


async def _run_async(argv: list[str]) -> subprocess.CompletedProcess:
    import asyncio

    return await asyncio.get_event_loop().run_in_executor(
        None, lambda: subprocess.run(argv, capture_output=True, timeout=60)
    )


def get_ocr_provider() -> OCRProvider:
    """Factory honoring ``OCR_PROVIDER`` setting: auto/tesseract/mock."""
    settings = get_settings()
    if settings.ocr_provider == "tesseract":
        return TesseractOCRProvider(settings.tesseract_binary)
    if settings.ocr_provider == "mock":
        return MockOCRProvider()
    # auto
    if shutil.which(settings.tesseract_binary):
        return TesseractOCRProvider(settings.tesseract_binary)
    return MockOCRProvider()