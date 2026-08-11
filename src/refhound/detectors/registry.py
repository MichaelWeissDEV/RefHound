"""Secret detector registry.

Detectors are resolved by id, filtered by configuration ignore rules, and
available for future plugin entry-point discovery.
"""

from __future__ import annotations

from collections.abc import Iterable

from refhound.detectors.base import SecretDetector
from refhound.detectors.cloud import AWSDetector, GCPDetector
from refhound.detectors.database import DatabaseURIDetector
from refhound.detectors.entropy import EntropyDetector
from refhound.detectors.generic import GenericProviderTokenDetector
from refhound.detectors.github import GitHubDetector
from refhound.detectors.gitlab import GitLabDetector
from refhound.detectors.jwt import JWTDetector
from refhound.detectors.passwords import GenericPasswordDetector
from refhound.detectors.private_keys import PrivateKeyDetector

_DEFAULT_DETECTORS: tuple[SecretDetector, ...] = (
    PrivateKeyDetector(),
    GitHubDetector(),
    GitLabDetector(),
    AWSDetector(),
    GCPDetector(),
    JWTDetector(),
    DatabaseURIDetector(),
    GenericPasswordDetector(),
    GenericProviderTokenDetector(),
    EntropyDetector(),
)


def default_detectors() -> list[SecretDetector]:
    return list(_DEFAULT_DETECTORS)


def resolve_detectors(
    detectors: Iterable[SecretDetector] | None = None,
    *,
    disabled: Iterable[str] = (),
) -> list[SecretDetector]:
    """Filter a detector set by ids in ``disabled``."""
    disabled_set = set(disabled)
    return [d for d in (detectors or _DEFAULT_DETECTORS) if d.id not in disabled_set]


def detector_by_id(detector_id: str) -> SecretDetector | None:
    for detector in _DEFAULT_DETECTORS:
        if detector.id == detector_id:
            return detector
    return None
