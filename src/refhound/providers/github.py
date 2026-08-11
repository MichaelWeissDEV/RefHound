"""GitHub API adapter (optional).

Only uses data the configured token is authorized to access. The token is
never written to disk, logs, or reports. No access-control bypass.
"""

from __future__ import annotations

import logging

import httpx

from refhound.errors import ProviderError, ProviderRateLimitError
from refhound.providers.base import Provider, ProviderMetadata

logger = logging.getLogger("refhound.providers.github")

_API = "https://api.github.com"


class GitHubProvider(Provider):
    name = "github"

    def __init__(self, base_url: str, token: str | None) -> None:
        self.base_url = base_url.rstrip("/") or _API
        self.token = token

    def describe(self) -> ProviderMetadata:
        """Fetch repository-level metadata (read-only)."""
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        with httpx.Client(headers=headers, timeout=20.0) as client:
            meta = ProviderMetadata()
            try:
                response = client.get(f"{self.base_url}/repos/{self._slice()}")
            except httpx.HTTPError as exc:
                raise ProviderError(f"github api request failed: {exc}") from exc
            if response.status_code == 403 and "rate limit" in response.text.lower():
                raise ProviderRateLimitError("GitHub API rate limit exceeded")
            if response.status_code in (401, 404):
                raise ProviderError(
                    f"github api returned {response.status_code}; check token/permissions"
                )
            if response.status_code != 200:
                raise ProviderError(f"github api returned {response.status_code}")
            data = response.json()
            meta.default_branch = data.get("default_branch", "")
            meta.archived = bool(data.get("archived", False))
            meta.raw.update(data)
            return meta

    def _slice(self) -> str:
        # Only ever used for metadata of the repository the user scanned.
        path = self.base_url.split("github.com")[-1].strip("/")
        return path or "api/v3"
