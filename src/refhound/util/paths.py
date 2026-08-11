"""Path helpers for safe handling of git-controlled paths.

Important: historical git paths are treated as *data*, never used to write
files to the filesystem. See docs/architecture.md (path safety).
"""

from __future__ import annotations

import re
from pathlib import Path


def normalize_git_path(path: str) -> str:
    """Normalize a path as git would report it (POSIX separators)."""
    return path.replace("\\", "/").lstrip("/")


def is_interesting_path(path: str) -> bool:
    """Heuristic: does this path look security relevant?"""
    lowered = path.lower()
    interesting_dirs = (
        ".github",
        ".gitlab",
        ".circleci",
        "ci",
        "deploy",
        "deployment",
        "infrastructure",
        "infra",
        "terraform",
        "ansible",
        "kubernetes",
        "k8s",
        "secrets",
        "config",
        "auth",
        "security",
    )
    segments = lowered.split("/")
    return any(segment in interesting_dirs for segment in segments)


#: Well-known credential/secret file names.
CREDENTIAL_FILE_NAMES: frozenset[str] = frozenset(
    {
        ".env",
        ".env.production",
        ".env.local",
        ".env.development",
        ".env.test",
        "credentials",
        "credentials.json",
        "secrets.yml",
        "secrets.yaml",
        "config.json",
        "settings.py",
        "id_rsa",
        "id_ed25519",
        "kubeconfig",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".npmrc",
        ".pypirc",
        ".netrc",
        "terraform.tfvars",
        "terraform.tfstate",
        "inventory.ini",
    }
)

#: Extensions that indicate key/certificate/binary-credential material.
CREDENTIAL_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".kdbx",
        ".sqlite",
        ".db",
    }
)


def classify_path_category(path: str) -> str | None:
    """Return a coarse category for a path or ``None``.

    Categories: ``credential``, ``configuration``, ``deployment``,
    ``infrastructure``, ``ci``, ``certificate``, ``database``.
    """
    lowered = path.lower().lstrip("./")
    name = lowered.rsplit("/", 1)[-1]

    if name in CREDENTIAL_FILE_NAMES or (
        name.startswith("id_") and name.split(".")[0].startswith("id_rsa")
    ):
        return "credential"
    if Path(name).suffix in CREDENTIAL_EXTENSIONS:
        return (
            "certificate"
            if Path(name).suffix in {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
            else "database"
        )
    if any(seg in lowered.split("/") for seg in (".github", ".gitlab", ".circleci")) or name in {
        "jenkinsfile",
        "gitlab-ci.yml",
        ".gitlab-ci.yml",
        ".travis.yml",
    }:
        return "ci"
    if any(
        seg in lowered.split("/")
        for seg in (
            "deploy",
            "deployment",
            "infra",
            "infrastructure",
            "terraform",
            "ansible",
            "kubernetes",
            "k8s",
        )
    ):
        return "infrastructure"
    if lowered.endswith((".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".cfg")):
        return "configuration"
    return None


#: Path segments that always indicate ignored/derived content.
IGNORED_SEGMENTS: tuple[str, ...] = (
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    "__pycache__",
)


def looks_ignorable(path: str) -> bool:
    """Heuristic pre-filter used to skip obviously derived blobs.

    Never a hard ignore: users can opt into vendor scanning. This only feeds
    low-confidence entropy candidates, not exact-pattern detectors.
    """
    parts = path.lower().split("/")
    return any(part in IGNORED_SEGMENTS for part in parts)


def is_vendored(path: str) -> bool:
    """Whether the path lives in a vendored/derived location."""
    return looks_ignorable(path)


_BINARY_CHARSET = {0x00, 0x01, 0x02, 0xFF, 0xFE}


def looks_binary(data: bytes) -> bool:
    """Cheap heuristic for binary content (NUL / control bytes in sample)."""
    sample = data[:8192]
    if not sample:
        return False
    return any(byte in _BINARY_CHARSET for byte in sample[:4096])


_MIME_HINT_RE = {
    "image": re.compile(rb"^\x89PNG|^\xff\xd8|^GIF8|^BM"),
    "zip": re.compile(rb"^PK\x03\x04"),
    "gzip": re.compile(rb"^\x1f\x8b"),
    "sqlite": re.compile(rb"^SQLite format 3"),
    "pdf": re.compile(rb"^%PDF"),
}


def mime_hint(data: bytes) -> str | None:
    """Coarse MIME-style hint from magic bytes (best effort)."""
    for name, pattern in _MIME_HINT_RE.items():
        if pattern.match(data):
            return f"{name}"
    return None


def safe_display_path(path: str) -> str:
    """Sanitize a path for terminal display (no control characters)."""
    return "".join(ch if ch.isprintable() else "?" for ch in path)


def path_is_ignored(path: str, ignored: list[str]) -> bool:
    """Whether a path matches any ignore prefix (directory or file prefix)."""
    normalized = path.replace("\\", "/").lstrip("/")
    for rule in ignored:
        rule = rule.replace("\\", "/").strip("/")
        if not rule:
            continue
        if normalized == rule or normalized.startswith(f"{rule}/"):
            return True
    return False
