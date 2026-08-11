"""Generic git provider: no API access, git-only facts."""

from __future__ import annotations

from refhound.providers.base import Provider, ProviderMetadata


class GenericGitProvider(Provider):
    """Fallback provider for cases where no provider API is configured.

    Uses nothing beyond what the local git client already exposes.
    """

    name = "generic"

    def __init__(self, base_url: str = "") -> None:
        self.base_url = base_url

    def describe(self) -> ProviderMetadata:
        return ProviderMetadata()
