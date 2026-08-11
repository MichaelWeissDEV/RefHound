"""Scan orchestration.

The pipeline walks:

    acquisition -> validation -> ref inventory -> object inventory ->
    commit graph -> reachability -> blob inventory -> secret scanning ->
    file/history analysis -> timeline -> anomaly detection -> correlation ->
    scoring -> persistence -> reporting

Each stage mutates a shared :class:`AnalysisData`. Per-domain logic lives in
the ``scanners.*`` modules; the engine only coordinates them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from refhound.analysis import correlations, deletion_analysis
from refhound.analysis.commit_anomalies import score_commit
from refhound.analysis.data import AnalysisData
from refhound.analysis.scoring import apply_score
from refhound.config import ScanOptions
from refhound.errors import GitError, RepositoryError
from refhound.git import commits as commit_api
from refhound.git import fsck, objects
from refhound.git.command import GitRunner, validate_oid
from refhound.git.repository import open_repository, prepare_remote
from refhound.models.anomaly import InterestingCommit
from refhound.models.finding import (
    Confidence,
    Finding,
    FindingCategory,
    SecretRecord,
    Severity,
    SourceState,
)
from refhound.models.object import BlobRecord, LostCommitChain
from refhound.models.repository import RepoRef, RepositoryInfo
from refhound.scanners import ci, files, history, identity, refs, secrets, timeline, unreachable
from refhound.scanners.base import FindingCollector, RepositoryContext
from refhound.util.dates import utc_now
from refhound.util.paths import (
    classify_path_category,
    is_interesting_path,
)

logger = logging.getLogger("refhound.engine")


@dataclass(slots=True)
class ScanResult:
    data: AnalysisData
    options: ScanOptions
    started: datetime
    duration_seconds: float = 0.0
    repository: str = ""

    @property
    def findings_sorted(self) -> list[Finding]:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(self.data.findings, key=lambda f: (order.get(f.severity, 9), -f.score, f.id))


def _repo_display(repo: RepositoryInfo) -> str:
    return repo.remote_url or repo.path


def _tip_trees(git: GitRunner, cwd: str, refs: list[RepoRef]) -> dict[str, dict[str, str]]:
    """Map ref -> {path: blob_oid} for commit-tip refs (limited)."""
    trees: dict[str, dict[str, str]] = {}
    for ref in refs:
        if not ref.ref_name.startswith(("refs/heads/", "refs/remotes/")):
            continue
        oid = ref.peeled or ref.target_oid
        try:
            validate_oid(oid)
        except ValueError:
            continue
        try:
            trees[ref.ref_name] = dict(fsck.list_tree_blobs(git, cwd, oid))
        except GitError:
            continue
    return trees


def _blob_inventory(git: GitRunner, cwd: str) -> dict[str, BlobRecord]:
    """Blob records from ``git rev-list --objects --all`` (reachable blobs).

    ``rev-list --objects`` also lists trees; we filter to blobs via a single
    ``cat-file --batch-check`` pass so directories are never treated as files.
    """
    out = git.run("rev-list", "--objects", "--all", cwd=cwd, timeout=900.0).stdout
    oid_paths: dict[str, list[str]] = {}
    for line in out.splitlines():
        parts = line.split(" ", 1)
        if not parts or len(parts[0]) != 40:
            continue
        oid = parts[0]
        path = parts[1].strip() if len(parts) > 1 else ""
        if path:
            oid_paths.setdefault(oid, []).append(path)

    if not oid_paths:
        return {}
    check = git.run(
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname) %(objecttype)",
        cwd=cwd,
        timeout=900.0,
    ).stdout
    blob_types = {line.split(" ", 1)[0] for line in check.splitlines() if line.endswith(" blob")}
    records: dict[str, BlobRecord] = {}
    for oid, paths in oid_paths.items():
        if oid not in blob_types:
            continue
        size = 0
        try:
            size = int(git.run("cat-file", "-s", oid, cwd=cwd).stdout.strip())
        except Exception:
            size = 0
        records[oid] = BlobRecord(oid=oid, size=size, reachable=True, scanned=False, paths=paths)
    return records


class Engine:
    """Runs a full scan for one repository."""

    def __init__(self, options: ScanOptions) -> None:
        self.options = options
        self.git = GitRunner()
        self.collector = FindingCollector()

    def run(self, target: str) -> ScanResult:
        started = utc_now()
        logger.info("acquiring %s", target)
        info = self._acquire(target)

        cwd = info.git_dir or info.path
        context = RepositoryContext(repo=info, git=self.git, options=self.options, cwd=cwd)
        data = AnalysisData(repo=info)
        data.scan_id = context.scan_id
        data.scan_timestamp = started.isoformat()

        try:
            self._inventory(context, data, cwd)
            self._graph_and_reachability(context, data, cwd)
            self._blobs(context, data, cwd)
            self._secrets(context, data, cwd)
            self._unreachable(context, data, cwd)
            self._history_and_files(context, data, cwd)
            self._timeline_and_anomalies(context, data)
            self._identities(context, data, cwd)
            self._correlate(context, data, cwd)
            self._score(context, data)
        except GitError as exc:
            raise RepositoryError(f"scan failed: {exc}") from exc

        data.findings = self.collector.all()
        result = ScanResult(
            data=data,
            options=self.options,
            started=started,
            repository=_repo_display(info),
        )
        result.duration_seconds = (utc_now() - started).total_seconds()
        return result

    # ---------------------------------------------------------- acquisition
    def _acquire(self, target: str) -> RepositoryInfo:
        if target.startswith(("http://", "https://", "git@", "ssh://")):
            mirror = prepare_remote(target, git=self.git)
            return self._open(str(mirror))
        return self._open(target)

    def _open(self, path: str) -> RepositoryInfo:
        info = open_repository(path, git=self.git, unshallow=self.options.unshallow)
        if info.shallow:
            logger.warning("repository is shallow; historical analysis is incomplete")
        if info.partial:
            logger.warning("repository is a partial/promisor clone; some objects may be missing")
        return info

    # ------------------------------------------------------------- inventory
    def _inventory(self, context: RepositoryContext, data: AnalysisData, cwd: str) -> None:
        logger.info("ref inventory")
        refs.scan_refs(self.git, cwd, data)

        try:
            inv = objects.count_objects(self.git, cwd)
            data.object_stats.commits = inv.commits
            data.object_stats.trees = inv.trees
            data.object_stats.blobs = inv.blobs
            data.object_stats.tags = inv.tags
        except GitError:
            logger.debug("count-objects unavailable", exc_info=True)

        logger.info("fsck")
        dangling, unreachable_count = objects.fsck_objects(self.git, cwd)
        data.dangling = dangling
        data.object_stats.unreachable = unreachable_count
        data.object_stats.dangling = len(dangling)

    def _graph_and_reachability(
        self, context: RepositoryContext, data: AnalysisData, cwd: str
    ) -> None:
        logger.info("commit graph")
        graph = commit_api.load_all_reachable(self.git, cwd)
        data.commit_graph = graph
        data.reachable_oids = set(graph)

        all_oids = objects.list_all_commits_oids(self.git, cwd)
        data.all_commit_oids = all_oids
        unreachable_oids = [o for o in all_oids if o not in graph]
        data.unreachable_oids = set(unreachable_oids)
        logger.info("unreachable commit oids: %d", len(unreachable_oids))

        if self.options.profile.unreachable_objects and unreachable_oids:
            for i in range(0, len(unreachable_oids), 2000):
                chunk = unreachable_oids[i : i + 2000]
                extra = commit_api.load_specific(self.git, cwd, chunk)
                for oid, info in extra.items():
                    if oid not in data.commit_graph:
                        info.reachable = False
                        data.commit_graph[oid] = info
        data.object_stats.unreachable_commits = len(data.unreachable_oids)

        signed = unsigned = 0
        for info in data.commit_graph.values():
            if info.signed is True:
                signed += 1
            elif info.signed is False:
                unsigned += 1
        data.signed_count = signed
        data.unsigned_count = unsigned
        data.merge_commit_count = sum(1 for info in data.commit_graph.values() if info.is_merge)

        dates = [c.committer_date for c in data.commit_graph.values() if c.committer_date]
        if dates and data.repo is not None:
            data.repo.first_commit_date = min(dates)
            data.repo.last_commit_date = max(dates)

    def _blobs(self, context: RepositoryContext, data: AnalysisData, cwd: str) -> None:
        logger.info("blob inventory")
        data.blobs = _blob_inventory(self.git, cwd)
        logger.info("tip trees")
        data.tip_trees = _tip_trees(self.git, cwd, data.refs)

        logger.info("unreachable blobs")
        for oid, info in data.commit_graph.items():
            if info.reachable:
                continue
            try:
                blobs = dict(fsck.list_tree_blobs(self.git, cwd, oid))
            except GitError:
                continue
            for path, blob_oid in blobs.items():
                record = data.blobs.get(blob_oid)
                if record is None:
                    # Only truly-unreachable-only blobs are tagged unreachable.
                    # A blob already known from reachable history keeps its
                    # reachable status (state is contextual per path/commit).
                    data.blobs[blob_oid] = BlobRecord(
                        oid=blob_oid, size=0, reachable=False, scanned=False, paths=[path]
                    )
                elif path not in record.paths:
                    record.paths.append(path)
                data.blob_commits.setdefault(blob_oid, set()).add(oid)

    # ---------------------------------------------------------------- secrets
    def _secrets(self, context: RepositoryContext, data: AnalysisData, cwd: str) -> None:
        from refhound.detectors.registry import resolve_detectors

        detectors = resolve_detectors(disabled=self.options.ignore.detectors)
        secrets.scan_secrets(
            self.git,
            cwd,
            data,
            detectors=detectors,
            max_blob_size=self.options.max_blob_size,
            binary_scan=self.options.profile.binary_scan,
            ignored_paths=self.options.ignore.paths,
        )

    def _unreachable(self, context: RepositoryContext, data: AnalysisData, cwd: str) -> None:
        unreachable.scan_unreachable(self.git, cwd, data)

    def _history_and_files(self, context: RepositoryContext, data: AnalysisData, cwd: str) -> None:
        repo_display = _repo_display(data.repo) if data.repo else ""
        self.collector.extend(history.scan_history(self.git, cwd, data, repo_display))
        self.collector.extend(ci.scan_ci(self.git, cwd, data, repo_display))
        files.scan_files(
            self.git,
            cwd,
            data,
            include_vendor=self.options.include_vendor,
            ignored_paths=self.options.ignore.paths,
        )

    def _timeline_and_anomalies(self, context: RepositoryContext, data: AnalysisData) -> None:
        timeline.scan_timeline(data)
        repo_display = _repo_display(data.repo) if data.repo else ""
        self.collector.extend(timeline.scan_anomalies(data, repo_display))
        timeline.count_history_components(data)

    def _identities(self, context: RepositoryContext, data: AnalysisData, cwd: str) -> None:
        repo_display = _repo_display(data.repo) if data.repo else ""
        self.collector.extend(identity.scan_identities(data, repo_display))

    def _correlate(self, context: RepositoryContext, data: AnalysisData, cwd: str) -> None:
        logger.info("correlation")
        interesting_lookup: set[str] = set()
        for record in data.blobs.values():
            for p in record.paths:
                if is_interesting_path(p) or classify_path_category(p) is not None:
                    interesting_lookup.add(p)
        repo_display = _repo_display(data.repo) if data.repo else ""

        self.collector.extend(
            correlations.cluster_secrets_into_findings(
                data.secrets, repo_display, interesting_lookup
            )
        )

        for chain in data.lost_chains:
            chain_secrets = [s for s in data.secrets if _chain_contains_secret(chain, s)]
            merged = correlations.merge_chain_into_finding(chain, chain_secrets, repo_display)
            if merged:
                self.collector.add(merged)

        for dangling in data.dangling:
            self.collector.add(
                Finding(
                    id=f"RH-dng-{dangling.oid[:8]}",
                    category=FindingCategory.DANGLING_OBJECT,
                    title=f"Dangling {dangling.object_type} object",
                    description=f"{dangling.oid} is not referenced by any reachable object.",
                    severity=Severity.INFO,
                    score=0,
                    repository=repo_display,
                    source_state=SourceState.DANGLING,
                    confidence=Confidence.HIGH,
                    provenance=["git-fsck"],
                )
            )

        for path in data.deleted_files[:50]:
            self.collector.add(
                Finding(
                    id=f"RH-del-{path[:96]}",
                    category=FindingCategory.INTERESTING_FILE,
                    title="Deleted interesting file",
                    description=f"{path} exists in history but is absent from the current tree.",
                    severity=Severity.MEDIUM,
                    score=0,
                    repository=repo_display,
                    path=path,
                    source_state=SourceState.HISTORICAL,
                    confidence=Confidence.MEDIUM,
                    provenance=["git-object-db"],
                    metadata={"interesting_path": "yes"},
                )
            )

        self.collector.extend(correlations.churn_to_findings(data.churn, repo_display))

        for sha in sorted(data.unreachable_oids)[:200]:
            self.collector.add(
                Finding(
                    id=f"RH-unr-{sha[:8]}",
                    category=FindingCategory.UNREACHABLE_COMMIT,
                    title="Unreachable commit",
                    description=f"{sha} exists in the object database but is not reachable from any known ref.",
                    severity=Severity.INFO,
                    score=0,
                    repository=repo_display,
                    commit_sha=sha,
                    source_state=SourceState.UNREACHABLE,
                    confidence=Confidence.HIGH,
                    provenance=["git-object-db"],
                )
            )

    def _score(self, context: RepositoryContext, data: AnalysisData) -> None:
        logger.info("scoring")
        scored: list[Finding] = []
        for finding in self.collector.all():
            current = _finding_is_current(finding, data.tip_trees)
            lifetime = _lifetime_seconds(finding)
            apply_score(finding, current=current, lifetime_seconds=lifetime)
            scored.append(finding)

        new_collector = FindingCollector()
        for finding in scored:
            new_collector.add(finding)
        self.collector = new_collector

        data.interesting = self._interesting_commits(data)

    def _interesting_commits(self, data: AnalysisData) -> dict[str, InterestingCommit]:
        has_secret_added: set[str] = set()
        has_secret_removed: set[str] = set()
        for secret in data.secrets:
            if secret.introduced_commit:
                has_secret_added.add(secret.introduced_commit)
            if secret.removed_commit:
                has_secret_removed.add(secret.removed_commit)

        chain_of: dict[str, str] = {}
        for chain in data.lost_chains:
            for sha in chain.commits:
                chain_of[sha] = chain.chain_id

        added_map, removed_map = _changed_maps(
            self.git, (data.repo.git_dir or data.repo.path) if data.repo else ""
        )

        result: dict[str, InterestingCommit] = {}
        for sha, info in data.commit_graph.items():
            result[sha] = score_commit(
                info,
                has_secret_added=sha in has_secret_added,
                has_secret_removed=sha in has_secret_removed,
                added_paths=added_map.get(sha, []),
                removed_paths=removed_map.get(sha, []),
                unreachable=sha in data.unreachable_oids,
                chain_id=chain_of.get(sha),
            )
        return result


def _changed_maps(git: GitRunner, cwd: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Added/removed interesting paths per commit (bounded buffer)."""
    added_map: dict[str, list[str]] = {}
    removed_map: dict[str, list[str]] = {}
    for count, change in enumerate(deletion_analysis.changed_file_status_iter(git, cwd)):
        if count > 30_000:
            break
        interesting_added = [
            p for p in change.added if is_interesting_path(p) or classify_path_category(p)
        ]
        interesting_removed = [
            p for p in change.removed if is_interesting_path(p) or classify_path_category(p)
        ]
        if interesting_added:
            added_map[change.commit] = interesting_added
        if interesting_removed:
            removed_map[change.commit] = interesting_removed
    return added_map, removed_map


def _finding_is_current(finding: Finding, tip_trees: dict[str, dict[str, str]]) -> bool:
    if not finding.path:
        return False
    return any(tree.get(finding.path) for tree in tip_trees.values())


def _lifetime_seconds(finding: Finding) -> float | None:
    value = finding.metadata.get("lifetime_seconds")
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _chain_contains_secret(chain: LostCommitChain, secret: SecretRecord) -> bool:
    return any(o.commit_sha in chain.commits for o in secret.occurrences)
