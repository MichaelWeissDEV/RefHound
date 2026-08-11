"""Generic / binary credential container detector.

Pruned expression list - keep this module dependency-light; the heavy lifting
is done in cloud.py, github.py, etc. This detector handles remaining
well-known vendor token prefixes.
"""

from __future__ import annotations

from refhound.detectors.base import PatternDetector
from refhound.models.finding import Confidence, Severity

_PATTERNS = [
    # Slack webhook/API tokens
    rb"\bxox[baprs]-[0-9A-Za-z\-]{10,255}\b",
    # Stripe
    rb"\bsk_live_[0-9A-Za-z]{24,255}\b",
    # Twilio
    rb"\bSK[0-9a-fA-F]{32}\b",
    # SendGrid
    rb"\bSG\.[0-9A-Za-z_\-]{22,255}\b",
    # Slack xapp / xoxe tokenish
    rb"\bxoxe-xapp-[0-9A-Za-z\-]+",
    # Mailgun
    rb"\bkey-[0-9a-f]{32}\b",
    # Square
    rb"\bEAAA[0-9A-Za-z_\-]{40,255}\b",
    # Doppler / common env-run style service tokens are handled via keyword rules.
]


class GenericProviderTokenDetector(PatternDetector):
    id = "generic-token"
    name = "Well-known SaaS token"
    description = (
        "Detects common third-party service token prefixes (Slack, Stripe, Twilio, SendGrid, ...)."
    )
    category = "credential"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM

    patterns = _PATTERNS
