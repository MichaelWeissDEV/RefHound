"""GitLab API adapter (optional).

Uses only data the configured token is authorized to access. The token is
never persisted, logged, or reported.
"""

from __future__ import annotations

import logging

import httpx

from refhound.errors import ProviderError, ProviderRateLimitError
from refhound.providers.base import Provider, ProviderMetadata

logger = logging.getLogger("refhound.providers.gitlab")

_API = "https://gitlab.com/api/v4"


class GitLabProvider(Provider):
    name = "gitlab"

    def __init__(self, base_url: str, token: str | None) -> None:
        self.base_url = base_url.rstrip("/") or _API
        self.token = token

    def describe(self) -> ProviderMetadata:
        headers = {"PRIVATE-TOKEN": self.token} if self.token else {}
        with httpx.Client(headers=headers, timeout=20.0) as client:
            meta = ProviderMetadata()
            project = self._project()
            try:
                response = client.get(f"{self.base_url}/projects/{project}")
            except httpx.HTTPError as exc:
                raise ProviderError(f"gitlab api request failed: {exc}") from exc
            if response.status_code == 429:
                raise ProviderRateLimitError("GitLab API rate limit exceeded")
            if response.status_code in (401, 404):
                raise ProviderError(
                    f"gitlab api returned {response.status_code}; check token/permissions"
                )
            if response.status_code != 200:
                raise ProviderError(f"gitlab api returned {response.status_code}")
            data = response.json()
            meta.default_branch = data.get("default_branch", "")
            meta.archived = bool(data.get("archived", False))
            meta.raw.update(data)
            return meta

    def _project(self) -> str:
        path = self.base_url.split("/")[-2:] if self.base_url != _API else []
        import urllib.parse

        return urllib.parse.quote("/".join(path), safe="") if path else ""
