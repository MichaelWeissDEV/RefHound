"""Secret scanning scanner.

Runs detectors over deduplicated blobs (unique by content address), groups
results into unique-secret records, and resolves introduction/removal windows
for lifetime reporting.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import datetime

from refhound.analysis import deletion_analysis
from refhound.analysis.data import AnalysisData
from refhound.detectors.base import SecretDetector
from refhound.git.command import GitRunner, is_valid_oid
from refhound.models.diagnostic import DiagnosticSeverity, ScanDiagnostic
from refhound.models.finding import SecretOccurrence, SecretRecord, SourceState
from refhound.models.object import BlobRecord
from refhound.models.secret import DetectorResult
from refhound.util.paths import looks_binary, mime_hint, path_is_excluded

logger = logging.getLogger("refhound.scanners.secrets")


def _classify_state(record: BlobRecord, path: str, tip_trees: dict[str, dict[str, str]]) -> str:
    if not record.reachable:
        return "unreachable"
    for tree in tip_trees.values():
        if tree.get(path) == record.oid:
            return "current"
    return "historical"


def scan_secrets(
    git: GitRunner,
    cwd: str,
    data: AnalysisData,
    *,
    detectors: Sequence[SecretDetector],
    max_blob_size: int,
    binary_scan: bool,
    include_vendor: bool,
    ignored_paths: list[str] | None = None,
) -> None:
    """Scan all unique blobs once and build secret records."""
    ignored = ignored_paths or []
    logger.info("secret scanning (%d blobs)", len(data.blobs))
    results_by_blob: dict[str, list[DetectorResult]] = {}
    to_scan = sorted(
        oid for oid, r in data.blobs.items() if is_valid_oid(oid) and r.size <= max_blob_size
    )
    for offset in range(0, len(to_scan), 500):
        chunk = to_scan[offset : offset + 500]
        contents = git.batch_cat_file(chunk, cwd=cwd, content=True)
        for oid, raw in contents.items():
            record = data.blobs.get(oid)
            if record is None or len(raw) > max_blob_size:
                continue
            if record.paths and all(
                path_is_excluded(path, ignored, include_vendor=include_vendor)
                for path in record.paths
            ):
                continue
            import hashlib

            record.content_hash = hashlib.sha256(raw).hexdigest()
            record.binary = looks_binary(raw)
            record.mime = mime_hint(raw)
            record.scanned = True
            if record.binary and not binary_scan:
                continue
            found: list[DetectorResult] = []
            for detector in detectors:
                try:
                    found.extend(
                        detector.detect(raw, path=record.paths[0] if record.paths else None)
                    )
                except Exception:
                    logger.debug("detector %s failed on blob %s", detector.id, oid, exc_info=True)
                    data.complete = False
                    data.failed_detectors[detector.id] = (
                        data.failed_detectors.get(detector.id, 0) + 1
                    )
                    if not any(d.component == detector.id for d in data.diagnostics):
                        message = f"Detector {detector.id} failed; secret scan is incomplete."
                        data.diagnostics.append(
                            ScanDiagnostic(
                                stage="secret-scan",
                                component=detector.id,
                                severity=DiagnosticSeverity.ERROR,
                                message=message,
                            )
                        )
                        data.scan_warnings.append(message)
            if found:
                results_by_blob[oid] = found

    secret_map: dict[str, SecretRecord] = {}
    for blob_oid, results in results_by_blob.items():
        record = data.blobs.get(blob_oid)
        if record is None:
            continue
        for result in results:
            secret = secret_map.setdefault(
                result.secret_fingerprint,
                SecretRecord(
                    fingerprint=result.secret_fingerprint,
                    detector=result.detector_id,
                    prefix=result.prefix,
                    suffix=result.suffix,
                    categories=[result.category],
                ),
            )
            for path in record.paths:
                state = _classify_state(record, path, data.tip_trees)
                commits = sorted(data.blob_commits.get(blob_oid, ()))
                source_state = SourceState(state)
                if state == "unreachable" and commits:
                    source_state = SourceState.UNREACHABLE
                secret.occurrences.append(
                    SecretOccurrence(
                        commit_sha=commits[0] if commits else "",
                        path=path,
                        line=result.line,
                        source_state=source_state,
                        blob_oid=blob_oid,
                        char_offset=result.char_offset,
                    )
                )
                if state == "current":
                    secret.current = True
                elif state == "unreachable":
                    secret.unreachable = True
                else:
                    secret.historical = True

    _resolve_secret_history(git, cwd, data, secret_map)
    data.secrets = list(secret_map.values())


def _resolve_secret_history(
    git: GitRunner, cwd: str, data: AnalysisData, secret_map: dict[str, SecretRecord]
) -> None:
    for record in secret_map.values():
        if not record.occurrences:
            continue
        wanted_blobs = {occ.blob_oid for occ in record.occurrences}
        for path in sorted({occ.path for occ in record.occurrences})[:20]:
            events = deletion_analysis.path_history(git, cwd, path)
            if not events:
                continue
            timeline: list[tuple[str, str | None, str]] = []
            for event in events:
                timeline.append((event.commit, _blob_at(git, cwd, event.commit, path), event.date))
            for added, removed, _added_ts, _removed_ts in _presence_windows(timeline, wanted_blobs):
                if record.introduced_commit is None:
                    record.introduced_commit = added
                    record.first_seen = _commit_date(data, added)
                if removed:
                    record.removed_commit = removed
                    record.last_seen = _commit_date(data, removed)
            if record.first_seen and record.last_seen and record.last_seen >= record.first_seen:
                record.lifetime_seconds = (record.last_seen - record.first_seen).total_seconds()


def _blob_at(git: GitRunner, cwd: str, commit: str, path: str) -> str | None:
    try:
        from refhound.git.command import validate_oid

        validate_oid(commit)
    except ValueError:
        return None
    out = git.run("rev-parse", f"{commit}:{path}", cwd=cwd, check=False)
    if out.returncode != 0:
        return None
    value = out.stdout.strip()
    return value if is_valid_oid(value) else None


def _presence_windows(
    events: list[tuple[str, str | None, str]], wanted: set[str]
) -> list[tuple[str, str | None, str, str]]:
    windows: list[tuple[str, str | None, str, str]] = []
    present: str | None = None
    present_ts = ""
    for commit, blob, ts in events:
        if blob in wanted and present is None:
            present = commit
            present_ts = ts
        elif blob not in wanted and present is not None:
            windows.append((present, commit, present_ts, ts))
            present = None
    if present is not None:
        windows.append((present, None, present_ts, ""))
    return windows


def _commit_date(data: AnalysisData, sha: str) -> datetime | None:
    info = data.commit_graph.get(sha)
    return info.committer_date if info else None
