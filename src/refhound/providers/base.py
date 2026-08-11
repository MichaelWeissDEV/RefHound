"""Provider abstraction.

Providers supplement git-local data only with metadata the configured user
is authorized to access. Provider integration is strictly optional; a normal
repository scan never requires a provider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from refhound.errors import ProviderError


@dataclass(slots=True)
class ProviderMetadata:
    """Metadata collected from a provider API (authorized access only)."""

    open_pull_requests: int = 0
    branches: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    protected_branches: list[str] = field(default_factory=list)
    collaborators: list[str] = field(default_factory=list)
    default_branch: str = ""
    archived: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


class Provider(ABC):
    """Base class for repository providers."""

    name: str = "provider"

    @abstractmethod
    def describe(self) -> ProviderMetadata:
        """Fetch provider metadata (must respect configured permissions)."""
        raise NotImplementedError


class NoProvider(Provider):
    """A provider that returns no metadata (used when none is configured)."""

    name = "none"

    def describe(self) -> ProviderMetadata:
        return ProviderMetadata()


def make_provider(kind: str, base_url: str, token: str | None) -> Provider:
    """Construct a provider adapter by name; raises ProviderError on unknown."""
    from collections.abc import Callable

    from refhound.providers.generic import GenericGitProvider
    from refhound.providers.github import GitHubProvider
    from refhound.providers.gitlab import GitLabProvider

    adapted: dict[str, Callable[[], Provider]] = {
        "generic": lambda: GenericGitProvider(base_url),
        "github": lambda: (
            GitHubProvider(base_url, token) if token else GenericGitProvider(base_url)
        ),
        "gitlab": lambda: (
            GitLabProvider(base_url, token) if token else GenericGitProvider(base_url)
        ),
    }
    factory = adapted.get(kind)
    if factory is None:
        raise ProviderError(f"unknown provider kind: {kind}")
    return factory()
