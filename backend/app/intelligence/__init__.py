"""Threat-intelligence provider abstraction."""
from .base import ThreatIntelProvider  # noqa: F401
from .manager import ThreatIntelManager, get_manager  # noqa: F401