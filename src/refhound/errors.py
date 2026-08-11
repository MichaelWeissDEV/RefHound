"""Exception hierarchy for RefHound.

Stable exit-code mapping lives in :mod:`refhound.cli`.
"""

from __future__ import annotations


class RefHoundError(Exception):
    """Base class for all RefHound errors."""


class UsageError(RefHoundError):
    """Invalid command line or configuration usage (exit code 2)."""


class ConfigError(UsageError):
    """Configuration could not be parsed or is invalid."""


class GitError(RefHoundError):
    """A git invocation failed (exit code 3)."""

    def __init__(self, message: str, *, command: str | None = None, stderr: str = "") -> None:
        self.command = command
        self.stderr = stderr
        super().__init__(message)


class GitNotFoundError(GitError):
    """The git executable could not be found."""


class RepositoryError(GitError):
    """The repository could not be opened or is invalid."""


class RepositoryNotFoundError(RepositoryError):
    """No repository exists at the given location."""


class RemoteError(GitError):
    """A remote operation failed (network, auth, unavailable)."""


class ShallowRepositoryError(RepositoryError):
    """The repository is shallow; historical analysis is incomplete."""


class CorruptRepositoryError(RepositoryError):
    """The repository object database appears corrupt."""


class ProviderError(RefHoundError):
    """A provider API call failed."""


class ProviderRateLimitError(ProviderError):
    """The provider API rate limit was exceeded."""


class InternalError(RefHoundError):
    """Unexpected internal failure (exit code 4)."""
