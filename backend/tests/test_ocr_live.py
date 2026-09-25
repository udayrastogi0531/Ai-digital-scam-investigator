"""OPT-IN live OCR integration tests (system Tesseract required).

Excluded from the offline suite (which pins ``OCR_PROVIDER=mock`` in
conftest) because they need the real ``tesseract`` binary.  Enable with::

    set RUN_LIVE_OCR_TESTS=1
    pytest tests/test_ocr_live.py -q

Fixtures are *generated at runtime* into ``tmp_path`` — no screenshots are
committed to the repository, and none of the sample text is real user data.

What they assert (the OCR contract, not Tesseract's accuracy):
* the real provider is selected (``is_mock is False``) when tesseract exists;
* extracted text is non-empty for a legible screenshot and is passed through
  to the investigation pipeline (pattern/URL analysis → risk → report);
* an unreadable image yields a *truthful* failure — empty text and an error,
  never a fabricated success;
* the pipeline never silently pretends OCR ran when it did not.
"""
from __future__ import annotations

import asyncio
import io
import os
import shutil
import textwrap

import pytest
from PIL import Image, ImageDraw, ImageFont

from app.extraction.ocr import MockOCRProvider, TesseractOCRProvider, get_ocr_provider
from app.schemas.evidence import InputPayload
from app.services.investigation_service import prepare_state

pytestmark = pytest.mark.skipif(
    not (os.environ.get("RUN_LIVE_OCR_TESTS") == "1" and shutil.which("tesseract")),
    reason="live OCR tests require RUN_LIVE_OCR_TESTS=1 and a system tesseract binary",
)

# Safe synthetic fixtures.  ``*.example`` / fake numbers only — never real
# organizations, real links or real personal data.
FIXTURES: dict[str, str] = {
    "banking_phishing": (
        "URGENT: Your bank account has been suspended.\n"
        "Verify your identity within 24 hours or it will be closed.\n"
        "Click http://nationaltrust-bank-secure.example/login\n"
        "and enter your password and the OTP code sent to your phone."
    ),
    "delivery_payment": (
        "Your parcel could not be delivered.\n"
        "A customs fee of 2.99 must be paid within 12 hours.\n"
        "Pay now at http://delivery-redelivery.example/pay"
    ),
    "job_scam": (
        "Congratulations! You have been selected for a work from home job.\n"
        "Pay a registration fee of 50 to confirm your position.\n"
        "WhatsApp the recruiter on +1 555 0100 today."
    ),
    "legitimate_notification": (
        "Your appointment is confirmed for Tuesday at 10:30.\n"
        "Reply STOP to cancel. Thank you."
    ),
}


def _font(size: int = 30):
    for name in ("arial.ttf", "DejaVuSans.ttf", "LiberationSans-Regular.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=size)  # Pillow >= 10.1
    except TypeError:  # pragma: no cover - very old Pillow
        return ImageFont.load_default()


def _render(text: str, *, size=(1000, 620), scale: float = 1.0, width: int = 58) -> bytes:
    """Render text to PNG bytes, optionally downscaled to simulate low quality.

    Lines are wrapped so nothing is clipped at the canvas edge (a clipped
    word would make the OCR assertion fail for a rendering reason rather
    than an OCR reason).
    """
    image = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(image)
    y = 20
    for source_line in text.splitlines():
        for line in textwrap.wrap(source_line, width=width) or [""]:
            draw.text((20, y), line, fill="black", font=_font())
            y += 42
    if scale != 1.0:
        image = image.resize((max(1, int(size[0] * scale)), max(1, int(size[1] * scale))))
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


@pytest.fixture
def live_ocr(monkeypatch):
    """Force the real tesseract provider and drop the cached settings."""
    from app.core.config import get_settings

    monkeypatch.setenv("OCR_PROVIDER", "tesseract")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_real_provider_is_selected_and_not_a_mock(monkeypatch):
    """With OCR_PROVIDER=auto and tesseract on PATH, the real provider wins."""
    from app.core.config import get_settings

    monkeypatch.setenv("OCR_PROVIDER", "auto")
    get_settings.cache_clear()
    provider = get_ocr_provider()
    get_settings.cache_clear()
    assert isinstance(provider, TesseractOCRProvider)
    assert provider.is_mock is False
    assert not isinstance(provider, MockOCRProvider)


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_live_ocr_extracts_expected_terms(live_ocr, name):
    provider = get_ocr_provider()
    assert isinstance(provider, TesseractOCRProvider)
    result = asyncio.run(provider.extract(_render(FIXTURES[name])))

    assert result.error is None, result.error
    assert result.is_mock is False
    assert result.provider == "tesseract"
    assert result.confidence > 0
    text = result.text.lower()
    assert text.strip(), f"OCR produced no text for {name}"
    # a few stable, fixture-specific anchors (lenient about OCR noise)
    anchors = {
        "banking_phishing": ["urgent", "account", "http"],
        "delivery_payment": ["parcel", "fee", "http"],
        "job_scam": ["job", "registration", "fee"],
        "legitimate_notification": ["appointment", "confirmed"],
    }[name]
    for anchor in anchors:
        assert anchor in text, f"{anchor!r} missing from OCR text for {name}: {text[:200]!r}"


def test_ocr_text_reaches_the_investigation_pipeline(live_ocr):
    """IMAGE → OCR → text → patterns/URL → risk → report, end to end."""
    from app.graph import run_investigation

    payload = InputPayload()
    state = prepare_state("ocr-live-1", payload, image_bytes=_render(FIXTURES["banking_phishing"]))
    result = asyncio.run(run_investigation(state))

    assert result["status"] == "completed"
    assert result["ocr_provider"] == "tesseract"
    assert result["ocr_mock"] is False
    assert result["ocr_text"].strip(), "OCR text never reached the graph state"
    # the OCR'd text produced real downstream evidence, not a stub
    assert result["scam_patterns"], "no scam pattern matched the OCR'd text"
    assert result["urls"], "the URL in the screenshot was not analyzed"
    assert result["risk"] is not None
    assert result["risk"].level in ("MEDIUM", "HIGH", "CRITICAL"), result["risk"].level
    assert result["report"] is not None


def test_unreadable_image_is_a_truthful_failure(live_ocr):
    """A blank/noise image must not report success or fabricated text."""
    provider = get_ocr_provider()
    blank = Image.new("RGB", (400, 200), "white")
    buffer = io.BytesIO()
    blank.save(buffer, "PNG")
    result = asyncio.run(provider.extract(buffer.getvalue()))

    # non-image bytes must fail loudly, not silently succeed
    bad = asyncio.run(provider.extract(b"this is definitely not an image"))

    assert result.is_mock is False
    assert result.text.strip() == ""  # nothing invented from a blank page
    assert result.confidence == 0.0
    assert bad.text == ""
    assert bad.error and "unreadable image" in bad.error
