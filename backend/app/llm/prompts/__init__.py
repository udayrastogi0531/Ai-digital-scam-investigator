"""Dedicated prompt builders for classification, explanation and reports."""

# Submodules must be importable as attributes (``prompts.classification``)
# for the OpenAI-compatible provider; import them eagerly here.
from . import classification, common, explanation, report  # noqa: F401,E402