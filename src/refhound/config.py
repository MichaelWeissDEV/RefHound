"""Configuration loading and scan profiles.

Configuration precedence (highest first):

1. command line options
2. ``.refhound.yml`` / ``.refhound.yaml`` in the repository root
3. built-in defaults

Secrets are never stored in configuration files.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from refhound.errors import ConfigError


@dataclass(slots=True)
class ScanProfile:
    name: str
    reachable_history: bool = True
    unreachable_objects: bool = False
    reflogs: bool = False
    provider_metadata: bool = False
    secret_scan: bool = True
    entropy_scan: bool = True
    binary_scan: bool = False
    stash: bool = False
    notes: bool = False
    lfs: bool = False
    submodules: bool = False

    def with_overrides(self, **kwargs: bool) -> ScanProfile:
        merged = ScanProfile(
            name=self.name,
            reachable_history=self.reachable_history,
            unreachable_objects=self.unreachable_objects,
            reflogs=self.reflogs,
            provider_metadata=self.provider_metadata,
            secret_scan=self.secret_scan,
            entropy_scan=self.entropy_scan,
            binary_scan=self.binary_scan,
            stash=self.stash,
            notes=self.notes,
            lfs=self.lfs,
            submodules=self.submodules,
        )
        for key, value in kwargs.items():
            if hasattr(merged, key):
                setattr(merged, key, value)
        return merged


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(name="quick", unreachable_objects=False, reflogs=False, entropy_scan=True),
    "standard": ScanProfile(name="standard"),
    "deep": ScanProfile(
        name="deep",
        unreachable_objects=True,
        reflogs=True,
        stash=True,
        notes=True,
        lfs=True,
        submodules=True,
        binary_scan=True,
    ),
    "forensic": ScanProfile(
        name="forensic",
        unreachable_objects=True,
        reflogs=True,
        stash=True,
        notes=True,
        lfs=True,
        submodules=True,
        binary_scan=True,
        provider_metadata=True,
    ),
}


@dataclass(slots=True)
class IgnoreRules:
    paths: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanOptions:
    profile: ScanProfile = field(default_factory=lambda: PROFILES["standard"])
    max_blob_size: int = 5 * 1024 * 1024
    jobs: int | None = None
    fail_on: str | None = None
    baseline_path: str | None = None
    fetch_lfs: bool = False
    unshallow: bool = False
    include_vendor: bool = False
    json_output: bool = False
    debug: bool = False
    ignore: IgnoreRules = field(default_factory=IgnoreRules)

    def hash(self) -> str:
        """Stable configuration fingerprint for report reproducibility."""
        payload = json.dumps(
            {
                "profile": asdict(self.profile),
                "max_blob_size": self.max_blob_size,
                "jobs": self.jobs,
                "fetch_lfs": self.fetch_lfs,
                "unshallow": self.unshallow,
                "include_vendor": self.include_vendor,
                "ignore": asdict(self.ignore),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def cache_hash(self) -> str:
        """Fingerprint result-affecting settings shared across compatible profiles."""
        payload = json.dumps(
            {
                "max_blob_size": self.max_blob_size,
                "fetch_lfs": self.fetch_lfs,
                "unshallow": self.unshallow,
                "include_vendor": self.include_vendor,
                "ignore": asdict(self.ignore),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def load_config_file(path: str | Path) -> dict[str, Any]:
    """Load ``.refhound.yml`` from a repository directory if present."""
    config_path = Path(path) / ".refhound.yml"
    if not config_path.exists():
        config_path = Path(path) / ".refhound.yaml"
    if not config_path.exists():
        return {}
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid .refhound.yml: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(".refhound.yml must contain a mapping")
    return data


def options_from_config(data: dict[str, Any], options: ScanOptions) -> ScanOptions:
    """Apply repository configuration onto CLI-provided options."""
    scan = data.get("scan", {})
    if isinstance(scan, dict):
        if "max_blob_size" in scan:
            value = scan["max_blob_size"]
            if not isinstance(value, int) or value <= 0:
                raise ConfigError("scan.max_blob_size must be a positive integer")
            options.max_blob_size = value
        if "jobs" in scan:
            options.jobs = int(scan["jobs"])
    ignore = data.get("ignore", {})
    if isinstance(ignore, dict):
        options.ignore.paths = list(ignore.get("paths", []))
        options.ignore.detectors = list(ignore.get("detectors", []))
        options.ignore.findings = list(ignore.get("findings", []))
    return options
