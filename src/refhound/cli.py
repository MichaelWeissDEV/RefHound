"""RefHound command line interface.

Exit codes (stable):
    0  scan successful, no threshold exceeded
    1  findings exceeded the configured threshold (--fail-on)
    2  usage / configuration error
    3  git / repository error
    4  internal error
"""

from __future__ import annotations

import json
import logging
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer

from refhound import __version__
from refhound.analysis import force_push_analysis
from refhound.analysis.data import AnalysisData
from refhound.analysis.force_push_analysis import RefTransition
from refhound.baseline import create_baseline, load_baseline, suppress_with_baseline
from refhound.cli_cache import register_cache_commands
from refhound.config import PROFILES, ScanOptions, load_config_file, options_from_config
from refhound.errors import (
    ConfigError,
    GitError,
    ProviderError,
    RefHoundError,
    RepositoryError,
    UsageError,
)
from refhound.models.anomaly import ChurnFinding, InterestingCommit, TimelineRow
from refhound.models.commit import CommitInfo, IdentitySet
from refhound.models.finding import Finding, FindingCategory, SecretRecord, Severity, SourceState
from refhound.models.object import DanglingObject, LostCommitChain
from refhound.models.repository import RepoRef, RepositoryInfo
from refhound.models.statistics import ObjectStats, RepositoryStatistics
from refhound.reporting import console as console_ui
from refhound.reporting import json as json_ui
from refhound.reporting import markdown as markdown_ui
from refhound.reporting import sarif as sarif_ui
from refhound.reporting.statistics import compute_statistics
from refhound.scanners.engine import Engine, ScanResult
from refhound.storage.database import Database, default_db_path
from refhound.util.hashing import redacted_label
from refhound.util.output import secure_write_text

app = typer.Typer(help="RefHound - Git repository security and forensic analysis tool.")
analyze_app = typer.Typer(help="Focused analyses.")
cache_app = typer.Typer(help="Inspect and maintain remote mirror cache.")
app.add_typer(analyze_app, name="analyze")
app.add_typer(cache_app, name="cache")

console = console_ui.make_console()

_logger = logging.getLogger("refhound")


def _print_serialized(value: str) -> None:
    """Write machine-readable output without Rich markup or line wrapping."""
    console.print(value, markup=False, highlight=False, soft_wrap=True)


def _detail_json(result: ScanResult, key: str, value: object) -> str:
    """Versioned envelope shared by detail-command JSON outputs."""
    return json.dumps(
        {
            "schema_version": "1",
            "refhound_version": __version__,
            "repository": result.repository,
            key: value,
        },
        indent=2,
    )


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"RefHound {__version__}")
        raise typer.Exit()


@app.callback(no_args_is_help=True)
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the version and exit.",
        is_eager=True,
        callback=_version_callback,
    ),
) -> None:
    """RefHound - Git repository security and forensic analysis tool."""


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity >= 3:
        level = logging.DEBUG
    elif verbosity == 2:
        level = logging.INFO
    elif verbosity == 1:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _ensure(path: str) -> None:
    if not Path(path).exists():
        raise UsageError(f"path does not exist: {path}")


def _resolve_options(
    path: str,
    *,
    profile: str | None,
    max_blob_size: int | None,
    fail_on: str | None,
    baseline: str | None,
    unshallow: bool = False,
    include_vendor: bool = False,
    refresh_remote: bool = False,
    offline: bool = False,
    debug: bool = False,
) -> ScanOptions:
    profile = profile or "standard"
    if profile in PROFILES:
        scan_profile = PROFILES[profile]
    else:
        raise UsageError(f"unknown profile '{profile}'; choose from {', '.join(sorted(PROFILES))}")
    options = ScanOptions(
        profile=scan_profile,
        max_blob_size=max_blob_size or 5 * 1024 * 1024,
        fail_on=fail_on,
        baseline_path=baseline,
        unshallow=unshallow,
        include_vendor=include_vendor,
        refresh_remote=refresh_remote,
        offline=offline,
        debug=debug,
    )
    try:
        config = load_config_file(path)
        options = options_from_config(config, options)
    except ConfigError:
        raise
    except OSError:
        pass
    return options


def _load_previous_ref_transitions(
    db: Database | None, repository: str, data: AnalysisData
) -> list[RefTransition]:
    if db is None:
        return []
    previous = db.latest_ref_snapshot(repository)
    if not previous:
        return []
    current = {r.ref_name: r.target_oid for r in data.refs}
    return force_push_analysis.compare_snapshots(previous, current, data.commit_graph)


def _ref_change_findings(transitions: list[RefTransition], repo_display: str) -> list[Finding]:
    findings: list[Finding] = []
    for t in transitions:
        if t.kind in {
            force_push_analysis.RefTransitionKind.NON_FAST_FORWARD,
            force_push_analysis.RefTransitionKind.DELETED,
        }:
            description = (
                f"Ref {t.ref} moved from {t.old_oid[:8]} to {t.new_oid[:8]}; "
                f"new tip is not a descendant of the previous tip ({t.evidence})."
            )
        else:
            continue
        findings.append(
            Finding(
                id=f"RH-ref-{t.ref[:96]}-{t.old_oid[:8]}-{t.new_oid[:8] or 'deleted'}",
                category=FindingCategory.REF_CHANGE,
                title="Possible non-fast-forward ref transition",
                description=description,
                severity=Severity.MEDIUM,
                score=0,
                repository=repo_display,
                source_state=SourceState.SNAPSHOT,
                confidence=(
                    "high"
                    if t.kind == force_push_analysis.RefTransitionKind.DELETED
                    else t.confidence
                ),
                metadata={"ref": t.ref, "previous": t.old_oid, "current": t.new_oid},
                provenance=["previous-refhound-snapshot"],
                remediation=(
                    "Compare the previous and current tip commits manually. "
                    "A non-fast-forward transition can be legitimate history "
                    "rewriting; it is not proof of an incident."
                ),
            )
        )
    return findings


def _apply_baseline(
    findings: list[Finding], baseline_path: str | None, *, repository: str | None = None
) -> list[Finding]:
    if not baseline_path:
        return findings
    baseline = load_baseline(baseline_path, repository=repository)
    return suppress_with_baseline(findings, baseline)


def _store_scan(db: Database | None, repository: str, result: ScanResult) -> None:
    if db is None:
        return
    # Reflog pseudo-refs are forensic evidence, not stable ref tips used for
    # cache invalidation. Their selectors change independently of ref state.
    refs = [r.model_dump(mode="json") for r in result.data.refs if r.source != "reflog"]
    findings = [f.model_dump(mode="json") for f in result.data.findings]
    secrets = [s.model_dump(mode="json") for s in result.data.secrets]
    statistics = compute_statistics(result.data).model_dump(mode="json")
    commit_graph = [
        commit.model_dump(mode="json", exclude={"body", "message"})
        for commit in result.data.commit_graph.values()
    ]
    db.store_scan(
        repository=repository,
        scan_id=result.data.scan_id,
        refs=refs,
        commits=len(result.data.commit_graph),
        findings=findings,
        snapshot=_snapshot(result, statistics),
        secrets=secrets,
        commit_graph=commit_graph,
        statistics=statistics,
        profile=result.options.profile.name,
    )


def _snapshot(result: ScanResult, statistics: dict[str, Any]) -> dict[str, Any]:
    """Build the redacted, report-ready representation stored in SQLite."""
    data = result.data
    return {
        "schema_version": 2,
        "scan_id": data.scan_id,
        "scan_timestamp": data.scan_timestamp,
        "profile": result.options.profile.name,
        "configuration_hash": result.options.hash(),
        "cache_hash": result.options.cache_hash(),
        "repository": result.repository,
        "repo": data.repo.model_dump(mode="json") if data.repo else None,
        "findings": [f.model_dump(mode="json") for f in data.findings],
        "secrets": [s.model_dump(mode="json") for s in data.secrets],
        "lost_chains": [c.model_dump(mode="json") for c in data.lost_chains],
        "dangling": [d.model_dump(mode="json") for d in data.dangling],
        "unreachable_oids": sorted(data.unreachable_oids),
        "reachable_oids": sorted(data.reachable_oids),
        "refs": [r.model_dump(mode="json") for r in data.refs],
        "object_stats": data.object_stats.model_dump(mode="json"),
        "statistics": statistics,
        "deleted_files": list(data.deleted_files),
        "scan_warnings": list(data.scan_warnings),
        "duration_seconds": result.duration_seconds,
        "commit_graph": {
            sha: commit.model_dump(mode="json", exclude={"body", "message"})
            for sha, commit in data.commit_graph.items()
        },
        "timeline": [row.model_dump(mode="json") for row in data.timeline],
        "interesting": {
            sha: entry.model_dump(mode="json") for sha, entry in data.interesting.items()
        },
        "churn": [entry.model_dump(mode="json") for entry in data.churn],
        "identities": [identity.model_dump(mode="json") for identity in data.identities],
        "renamed_files": list(data.renamed_files),
        "merge_commit_count": data.merge_commit_count,
        "signed_count": data.signed_count,
        "unsigned_count": data.unsigned_count,
        "history_components": data.history_components,
        "notes_count": len(data.notes),
    }


def _result_from_snapshot(snapshot: dict[str, Any], options: ScanOptions) -> ScanResult:
    """Validate and reconstruct report-ready analysis data from a DB snapshot."""
    if snapshot.get("schema_version") != 2:
        raise ValueError("unsupported snapshot schema")
    data = AnalysisData(
        repo=(RepositoryInfo.model_validate(snapshot["repo"]) if snapshot.get("repo") else None),
        refs=[RepoRef.model_validate(value) for value in snapshot.get("refs", [])],
        commit_graph={
            sha: CommitInfo.model_validate(value)
            for sha, value in snapshot.get("commit_graph", {}).items()
        },
        reachable_oids=set(snapshot.get("reachable_oids", [])),
        unreachable_oids=set(snapshot.get("unreachable_oids", [])),
        dangling=[DanglingObject.model_validate(value) for value in snapshot.get("dangling", [])],
        object_stats=ObjectStats.model_validate(snapshot.get("object_stats", {})),
        secrets=[SecretRecord.model_validate(value) for value in snapshot.get("secrets", [])],
        lost_chains=[
            LostCommitChain.model_validate(value) for value in snapshot.get("lost_chains", [])
        ],
        deleted_files=list(snapshot.get("deleted_files", [])),
        renamed_files=list(snapshot.get("renamed_files", [])),
        timeline=[TimelineRow.model_validate(value) for value in snapshot.get("timeline", [])],
        interesting={
            sha: InterestingCommit.model_validate(value)
            for sha, value in snapshot.get("interesting", {}).items()
        },
        churn=[ChurnFinding.model_validate(value) for value in snapshot.get("churn", [])],
        identities=[IdentitySet.model_validate(value) for value in snapshot.get("identities", [])],
        merge_commit_count=int(snapshot.get("merge_commit_count", 0)),
        signed_count=int(snapshot.get("signed_count", 0)),
        unsigned_count=int(snapshot.get("unsigned_count", 0)),
        history_components=int(snapshot.get("history_components", 0)),
        notes={str(index): b"" for index in range(int(snapshot.get("notes_count", 0)))},
        findings=[Finding.model_validate(value) for value in snapshot.get("findings", [])],
        scan_warnings=list(snapshot.get("scan_warnings", [])),
        scan_id=str(snapshot["scan_id"]),
        scan_timestamp=str(snapshot["scan_timestamp"]),
        cached_statistics=RepositoryStatistics.model_validate(snapshot["statistics"]),
    )
    started = datetime.fromisoformat(data.scan_timestamp)
    return ScanResult(
        data=data,
        options=options,
        started=started,
        duration_seconds=float(snapshot.get("duration_seconds", 0.0)),
        repository=str(snapshot.get("repository", "")),
    )


def _exit_code_for(result: ScanResult, fail_on: str | None) -> int:
    if not getattr(result.data, "complete", True):
        return 5
    if not fail_on:
        return 0
    try:
        threshold = Severity(fail_on.lower())
    except ValueError:
        raise UsageError(f"invalid threshold severity: {fail_on}") from None
    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    threshold_rank = order[threshold]
    for finding in result.data.findings:
        if order.get(finding.severity, 0) >= threshold_rank:
            return 1
    return 0


def _is_remote(target: str) -> bool:
    return target.startswith(("http://", "https://", "git@", "ssh://"))


def _repository_key(target: str) -> str:
    if _is_remote(target):
        return target
    from refhound.git.command import GitRunner

    path = Path(target).expanduser().resolve()
    git = GitRunner()
    try:
        root = git.run("rev-parse", "--show-toplevel", cwd=path).stdout.strip()
        if root:
            return str(Path(root).resolve())
    except RefHoundError:
        pass
    try:
        git_dir = git.run("rev-parse", "--absolute-git-dir", cwd=path).stdout.strip()
        if git_dir:
            return str(Path(git_dir).resolve())
    except RefHoundError:
        pass
    return str(path)


def _current_ref_snapshot(target: str) -> dict[str, str] | None:
    """Read refs without running the expensive scan pipeline or using the network."""
    from refhound.git import refs as ref_api
    from refhound.git.command import GitRunner
    from refhound.git.repository import cache_root, remote_slug

    if _is_remote(target):
        cwd = cache_root() / "mirrors" / remote_slug(target)
        if not (cwd / "HEAD").exists():
            return None
    else:
        cwd = Path(target).expanduser().resolve()
    git = GitRunner()
    refs = ref_api.list_refs(git, cwd)
    refs.extend(ref_api.stash_refs(git, cwd))
    return {ref.ref_name: ref.target_oid for ref in refs}


def _profile_covers(stored: object, requested: str) -> bool:
    ranks = {"quick": 0, "standard": 1, "deep": 2, "forensic": 3}
    return isinstance(stored, str) and ranks.get(stored, -1) >= ranks.get(requested, 99)


def _load_or_run(path: str, options: ScanOptions, *, fresh: bool = False) -> ScanResult:
    """Load a compatible complete snapshot, otherwise scan and persist one."""
    if not _is_remote(path):
        _ensure(path)
    if options.debug:
        return Engine(options).run(path)
    repository = _repository_key(path)
    db = Database(default_db_path())
    try:
        if not fresh:
            snapshot = db.latest_snapshot(repository)
            if (
                snapshot is not None
                and _profile_covers(snapshot.get("profile"), options.profile.name)
                and snapshot.get("cache_hash") == options.cache_hash()
            ):
                try:
                    current_refs = _current_ref_snapshot(path)
                    stored_refs = db.latest_ref_snapshot(repository)
                    if current_refs is not None and current_refs == stored_refs:
                        _logger.info("using cached scan %s", snapshot.get("scan_id", ""))
                        stored_profile = snapshot.get("profile")
                        if isinstance(stored_profile, str) and stored_profile in PROFILES:
                            options.profile = PROFILES[stored_profile]
                        return _result_from_snapshot(snapshot, options)
                except (AttributeError, KeyError, RefHoundError, OSError, TypeError, ValueError):
                    _logger.debug("cached scan could not be loaded", exc_info=True)

        result = Engine(options).run(path)
        try:
            transitions = _load_previous_ref_transitions(db, repository, result.data)
        except RefHoundError:
            transitions = []
        result.data.findings.extend(_ref_change_findings(transitions, result.repository))
        _store_scan(db, repository, result)
        return result
    finally:
        db.close()


def _load_or_scan(path: str, *, fresh: bool = False, profile: str = "deep") -> ScanResult:
    options = _resolve_options(
        path,
        profile=profile,
        max_blob_size=None,
        fail_on=None,
        baseline=None,
        debug=False,
    )
    return _load_or_run(path, options, fresh=fresh)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    path: str = typer.Argument(..., help="Repository directory, local path or remote URL"),
    quick: bool = typer.Option(False, "--quick", help="Quick scan: refs + simple secrets only"),
    profile: str = typer.Option(
        None, "--profile", help="Scan profile: quick|standard|deep|forensic"
    ),
    max_blob_size: int = typer.Option(
        None, "--max-blob-size", help="Skip blobs larger than N bytes"
    ),
    fail_on: str = typer.Option(
        None, "--fail-on", help="Exit 1 if any finding reaches this severity"
    ),
    baseline: str = typer.Option(
        None, "--baseline", help="Suppress findings listed in a baseline file"
    ),
    format_option: str = typer.Option(
        "table", "--format", help="Output: table | json | sarif | markdown"
    ),
    output: str = typer.Option(None, "--output", "-o", help="Write output to a file"),
    deep: bool = typer.Option(False, "--deep", help="Shorthand for --profile deep"),
    forensic: bool = typer.Option(False, "--forensic", help="Shorthand for --profile forensic"),
    unshallow: bool = typer.Option(
        False, "--unshallow", help="Fetch full history if the repository is shallow"
    ),
    include_vendor: bool = typer.Option(
        False, "--include-vendor", help="Also scan vendored/dependency content"
    ),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore cached scan results"),
    refresh_remote: bool = typer.Option(
        False, "--refresh-remote", help="Fetch updates into an existing remote mirror"
    ),
    offline: bool = typer.Option(False, "--offline", help="Never access the network"),
    debug: bool = typer.Option(False, "--debug", help="Show full stack traces"),
    verbose: int = typer.Option(0, "-v", count=True, help="Increase verbosity (-v, -vv, -vvv)"),
) -> None:
    """Scan a repository (local or remote) for security findings."""
    _setup_logging(3 if debug else verbose)
    if quick:
        effective_profile = "quick"
    elif profile:
        effective_profile = profile
    elif forensic:
        effective_profile = "forensic"
    elif deep:
        effective_profile = "deep"
    else:
        effective_profile = "standard"
    options = _resolve_options(
        path,
        profile=effective_profile,
        max_blob_size=max_blob_size,
        fail_on=fail_on,
        baseline=baseline,
        unshallow=unshallow,
        include_vendor=include_vendor,
        refresh_remote=refresh_remote,
        offline=offline,
        debug=debug,
    )

    try:
        result = _load_or_run(path, options, fresh=fresh or refresh_remote)
    except RefHoundError as exc:
        _fail(exc, debug)
        return

    result.data.findings = _apply_baseline(
        result.data.findings, baseline, repository=result.repository
    )

    if format_option == "json":
        output_text = json_ui.scan_json(result.data, options, include_secrets=True)
    elif format_option == "sarif":
        output_text = sarif_ui.sarif_document(result.data, options)
    elif format_option == "markdown":
        output_text = markdown_ui.markdown_report(result.data, options)
    else:
        _render_scan_console(result)
        output_text = None

    if output_text is not None:
        if output:
            secure_write_text(output, output_text)
        else:
            _print_serialized(output_text)

    _report_warnings(result)
    exit_code = _exit_code_for(result, options.fail_on)
    if options.fail_on:
        _logger.info("fail-on=%s -> exit %d", options.fail_on, exit_code)
    _exit(exit_code)


def _report_warnings(result: ScanResult) -> None:
    for warning in result.data.scan_warnings:
        console.print(f"[yellow]WARNING[/] {warning}")


def _render_scan_console(result: ScanResult) -> None:
    data = result.data
    stats = compute_statistics(data)
    console.print(f"[bold]RefHound[/] {__version__}")
    console.print("Repository Security & Git Forensics")
    console.print()
    head = []
    repo = data.repo
    if repo:
        head.append(("URL", repo.remote_url or repo.path))
        head.append(("Path", repo.path))
        if repo.head_sha:
            head.append(("HEAD", repo.head_sha[:8]))
    head.append(("Commits", f"{data.object_stats.commits or len(data.commit_graph)}"))
    head.append(("Branches", str(stats.branches)))
    head.append(("Tags", str(stats.tags)))
    head.append(("Authors", str(stats.authors)))
    console_ui.render_summary(console, head)
    console.print()

    console.print("[bold]Git archaeology[/]")
    console_ui.render_summary(
        console,
        [
            ("Reachable commits", f"{len(data.reachable_oids)}"),
            ("Unreachable commits", f"{len(data.unreachable_oids)}"),
            ("Lost chains", str(len(data.lost_chains))),
            ("Dangling objects", str(len(data.dangling))),
        ],
    )
    console.print()

    console.print("[bold]Secret exposure[/]")
    console_ui.render_summary(
        console,
        [
            ("Current", f"{stats.secrets.current}"),
            ("Historical", f"{stats.secrets.historical}"),
            ("Unreachable", f"{stats.secrets.unreachable}"),
        ],
    )
    console.print()

    console.print("[bold]Findings[/]")
    console_ui.render_findings_table(console, result.findings_sorted, limit=10)
    console.print()

    console.print("Run:")
    console.print("  refhound findings <path>")
    console.print("  refhound lost <path>")
    console.print("  refhound secrets <path>")


# ---------------------------------------------------------------------------
# detail commands
# ---------------------------------------------------------------------------


@app.command()
def findings(
    path: str = typer.Argument(...),
    severity: str = typer.Option(None, "--severity", help="Filter by severity"),
    category: str = typer.Option(None, "--category", help="Filter by category"),
    score_min: int = typer.Option(None, "--score-min", help="Minimum score"),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore cached scan results"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show findings for a repository."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path, fresh=fresh)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    filtered = _filter_findings(result.data.findings, severity, category, score_min)
    if as_json:
        _print_serialized(
            json_ui.findings_json(
                result.data,
                filtered,
                severity=severity,
                category=category,
                score_min=score_min,
            )
        )
        return
    console_ui.render_findings_table(console, filtered)


def _filter_findings(
    findings_list: list[Finding], severity: str | None, category: str | None, score_min: int | None
) -> list[Finding]:
    result = findings_list
    if severity:
        result = [f for f in result if f.severity.value == severity.lower()]
    if category:
        result = [f for f in result if f.category.value == category.lower()]
    if score_min is not None:
        result = [f for f in result if f.score >= score_min]
    from refhound.util.sorting import finding_sort_key

    return sorted(result, key=finding_sort_key)


@app.command()
def secrets(
    path: str = typer.Argument(...),
    historical: bool = typer.Option(False, "--historical"),
    unreachable: bool = typer.Option(False, "--unreachable"),
    current: bool = typer.Option(False, "--current"),
    as_json: bool = typer.Option(False, "--json"),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore cached scan results"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show grouped secret records (always redacted)."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path, fresh=fresh)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    selected = result.data.secrets
    if current:
        selected = [s for s in selected if s.current]
    if historical:
        selected = [s for s in selected if s.historical]
    if unreachable:
        selected = [s for s in selected if s.unreachable]
    if as_json:
        payload = {
            "schema_version": "1",
            "refhound_version": __version__,
            "repository": result.repository,
            "secrets": [
                {
                    "fingerprint": s.fingerprint,
                    "detector": s.detector,
                    "prefix": s.prefix,
                    "suffix": s.suffix,
                    "occurrences": s.occurrence_count,
                    "current": s.current,
                    "historical": s.historical,
                    "unreachable": s.unreachable,
                    "introduced_commit": s.introduced_commit,
                    "removed_commit": s.removed_commit,
                    "lifetime_seconds": s.lifetime_seconds,
                }
                for s in selected
            ],
        }
        _print_serialized(json.dumps(payload, indent=2))
        return
    for secret in selected:
        state = (
            "current" if secret.current else ("historical" if secret.historical else "unreachable")
        )
        lifetime = ""
        if secret.lifetime_seconds is not None:
            lifetime = f" (lifetime {int(secret.lifetime_seconds)}s)"
        console.print(
            f"[yellow]{redacted_label(secret.prefix, secret.suffix, secret.fingerprint)}[/]  "
            f"{secret.detector}  "
            f"state={state}  occurrences={secret.occurrence_count}{lifetime}"
        )
        if secret.introduced_commit:
            console.print(f"      introduced: {secret.introduced_commit}")
        if secret.removed_commit:
            console.print(f"      removed: {secret.removed_commit}")
        for occ in secret.occurrences[:3]:
            console.print(f"      @ {occ.path}:{occ.line} [{occ.source_state.value}]")
        console.print()


@app.command()
def refs(
    path: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """List refs with resolved types."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    if as_json:
        payload = [
            {
                "ref_name": r.ref_name,
                "target_oid": r.target_oid,
                "object_type": r.object_type,
                "source": r.source,
                "annotated": r.annotated,
                "signed": r.signed,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            }
            for r in result.data.refs
        ]
        _print_serialized(_detail_json(result, "refs", payload))
        return
    for ref in result.data.refs:
        console.print(f"{ref.ref_name:<64} {ref.target_oid[:12]}  {ref.object_type or '-'}")


@app.command()
def commits(
    path: str = typer.Argument(...),
    author: str = typer.Option(None, "--author", help="Filter by author email"),
    as_json: bool = typer.Option(False, "--json"),
    limit: int = typer.Option(50, "--limit", help="Maximum number of commits"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """List commits (most recent first)."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    items = sorted(
        result.data.commit_graph.values(),
        key=lambda c: (c.committer_date or datetime.min.replace(tzinfo=UTC), c.sha),
        reverse=True,
    )
    if author:
        items = [c for c in items if (author.lower() in c.author_email.lower())]
    items = items[:limit]
    if as_json:
        payload = [
            {
                "sha": c.sha,
                "author": c.author_email,
                "committer": c.committer_email,
                "date": c.committer_date.isoformat() if c.committer_date else None,
                "subject": c.subject,
                "reachable": c.reachable,
                "parents": c.parents,
            }
            for c in items
        ]
        _print_serialized(_detail_json(result, "commits", payload))
        return
    for c in items:
        mark = "" if c.reachable else " [red](unreachable)[/]"
        console.print(f"{c.sha[:8]}  {c.subject[:70]}{mark}")


@app.command()
def objects(
    path: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show object database statistics."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    stats = result.data.object_stats
    if as_json:
        _print_serialized(_detail_json(result, "objects", stats.model_dump(mode="json")))
        return
    console_ui.render_summary(
        console,
        [
            ("Commits", str(stats.commits)),
            ("Trees", str(stats.trees)),
            ("Blobs", str(stats.blobs)),
            ("Tags", str(stats.tags)),
            ("Unreachable objects", str(stats.unreachable)),
            ("Dangling objects", str(stats.dangling)),
        ],
    )


@app.command()
def dangling(
    path: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show dangling git objects."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    if as_json:
        _print_serialized(
            _detail_json(result, "dangling", [d.model_dump() for d in result.data.dangling])
        )
        return
    for d in result.data.dangling:
        console.print(f"{d.oid[:12]}  {d.object_type}")


@app.command()
def unreachable(
    path: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show unreachable commits."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    uncommits = sorted(result.data.unreachable_oids, key=lambda o: int(o, 16))
    if as_json:
        _print_serialized(_detail_json(result, "unreachable_commits", uncommits))
        return
    for sha in uncommits:
        console.print(sha)


@app.command()
def lost(
    path: str = typer.Argument(...),
    contains_secret: bool = typer.Option(False, "--contains-secret"),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show reconstructed lost commit chains."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    chains = result.data.lost_chains
    if contains_secret:
        chains = [c for c in chains if _chain_has_secret(c, result.data.secrets)]
    if as_json:
        _print_serialized(
            json.dumps(
                [
                    {
                        "chain_id": c.chain_id,
                        "root": c.root,
                        "tip": c.tip,
                        "commits": c.commits,
                        "commit_count": c.commit_count,
                        "common_ancestor": c.common_ancestor,
                        "hint_branch": c.hint_branch,
                        "authors": c.authors,
                    }
                    for c in chains
                ],
                indent=2,
            )
        )
        return
    for chain in chains:
        console_ui.render_lost_chain(console, chain)


def _chain_has_secret(chain: LostCommitChain, secrets: list[SecretRecord]) -> bool:
    return any(o.commit_sha in chain.commits for s in secrets for o in s.occurrences)


@app.command()
def timeline(
    path: str = typer.Argument(...),
    since: str = typer.Option(None, "--from", help="Start date (ISO)"),
    until: str = typer.Option(None, "--to", help="End date (ISO)"),
    author: str = typer.Option(None, "--author", help="Author filter"),
    path_filter: str = typer.Option(None, "--path", help="Path filter"),
    severity: str = typer.Option(None, "--severity", help="Severity filter"),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show the commit timeline."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    rows = result.data.timeline
    if since:
        start = datetime.fromisoformat(since)
        rows = [r for r in rows if r.timestamp and _at_or_after(r.timestamp, start)]
    if until:
        end = datetime.fromisoformat(until)
        rows = [r for r in rows if r.timestamp and _leq(r.timestamp, end)]
    if author:
        rows = [r for r in rows if author.lower() in r.author.lower()]
    if as_json:
        _print_serialized(
            json.dumps(
                [
                    {
                        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                        "commit": r.commit,
                        "author": r.author,
                        "subject": r.subject,
                        "reachable": r.reachable,
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return
    for r in rows:
        ts = r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "-"
        mark = "" if r.reachable else " [red](unreachable)[/]"
        console.print(f"{ts}  {r.commit[:8]}  {r.author[:24]:<24}  {r.subject[:60]}{mark}")


def _leq(timestamp: datetime, end: datetime) -> bool:
    if timestamp.tzinfo is not None and end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    if timestamp.tzinfo is None and end.tzinfo is not None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp <= end


def _at_or_after(timestamp: datetime, start: datetime) -> bool:
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    return timestamp >= start


@app.command()
def authors(
    path: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show author statistics."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    identities = result.data.identities
    if as_json:
        _print_serialized(
            json.dumps(
                [
                    {
                        "email": i.email,
                        "name": i.name,
                        "commit_count": i.commit_count,
                        "insertions": i.insertions,
                        "deletions": i.deletions,
                        "first_commit": i.first_commit.isoformat() if i.first_commit else None,
                        "last_commit": i.last_commit.isoformat() if i.last_commit else None,
                    }
                    for i in identities
                ],
                indent=2,
            )
        )
        return
    print("Author                          Commits")
    print("---------------------------------------------------------")
    for identity in identities[:50]:
        print(f"{identity.email[:30]:<30}   {identity.commit_count:>7}")


@app.command()
def stats(
    path: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show repository statistics."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    stats = compute_statistics(result.data)
    if as_json:
        _print_serialized(json.dumps(stats.model_dump(mode="json"), indent=2))
        return
    console.print("[bold]History[/]")
    console_ui.render_summary(
        console,
        [
            ("First commit", str(stats.first_commit or "-")),
            ("Last commit", str(stats.last_commit or "-")),
            ("Total commits", str(stats.total_commits)),
            ("Time span (days)", f"{stats.time_span_days:.1f}" if stats.time_span_days else "-"),
        ],
    )
    console.print()
    console.print("[bold]Contributors[/]")
    console_ui.render_summary(
        console, [("Authors", str(stats.authors)), ("Committers", str(stats.committers))]
    )
    console.print()
    console.print("[bold]Objects[/]")
    console_ui.render_summary(
        console,
        [
            ("Commits", str(stats.objects.commits)),
            ("Trees", str(stats.objects.trees)),
            ("Blobs", str(stats.objects.blobs)),
        ],
    )
    console.print()
    console.print("[bold]Git archaeology[/]")
    console_ui.render_summary(
        console,
        [
            ("Unreachable", str(stats.objects.unreachable_commits)),
            ("Lost chains", str(stats.objects.lost_chains)),
            ("Dangling objects", str(stats.objects.dangling)),
            ("Deleted interesting files", str(len(result.data.deleted_files))),
        ],
    )
    console.print()
    console.print("[bold]Secrets[/]")
    console_ui.render_summary(
        console,
        [
            ("Unique", str(stats.secrets.unique_secrets)),
            ("Current", str(stats.secrets.current)),
            ("Historical", str(stats.secrets.historical)),
            ("Unreachable", str(stats.secrets.unreachable)),
        ],
    )


@app.command()
def history(
    path: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show annotations about the repository history structure."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    data = result.data
    components = _history_components(data)
    if as_json:
        _print_serialized(
            json.dumps(
                {
                    "components": components,
                    "roots": sorted(_root_commits(data)),
                    "merge_count": data.merge_commit_count,
                    "signed_count": data.signed_count,
                    "unsigned_count": data.unsigned_count,
                },
                indent=2,
            )
        )
        return
    console.print(f"History components (disconnected roots): {components}")
    console.print(f"Merge commits: {data.merge_commit_count}")
    console.print(f"Commits with signature present: {data.signed_count}")
    console.print(f"Commits without signature: {data.unsigned_count}")
    console.print("Notes:", len(data.notes))


@app.command()
def interesting(
    path: str = typer.Argument(...),
    limit: int = typer.Option(15, "--limit"),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Show the most interesting commits by score."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    entries = sorted(
        result.data.interesting.values(),
        key=lambda e: (-e.score, e.sha),
    )
    if as_json:
        _print_serialized(
            json.dumps(
                [
                    {
                        "score": e.score,
                        "sha": e.sha,
                        "date": e.date.isoformat() if e.date else None,
                        "subject": e.subject,
                        "reasons": e.reasons,
                    }
                    for e in entries[:limit]
                ],
                indent=2,
            )
        )
        return
    rows = [
        (e.score, e.sha[:7], e.date.strftime("%Y-%m-%d") if e.date else "-", e.subject)
        for e in entries[:limit]
    ]
    console_ui.render_interesting(console, rows)


@app.command()
def explain(
    path: str = typer.Argument(...),
    commit: str = typer.Argument(...),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Explain why a specific commit is interesting."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    info = result.data.commit_graph.get(commit) or _lookup_short(result.data.commit_graph, commit)
    if info is None:
        raise UsageError(f"commit not found: {commit}")
    entry = result.data.interesting.get(info.sha)
    console.print(f"[bold]Commit {info.sha[:12]}[/]")
    console.print()
    console.print(
        f"Interest score: {entry.score if entry else 0}/100" if entry else "Interest score: n/a"
    )
    if entry and entry.reasons:
        console.print()
        console.print("Reasons:")
        for score, reason in entry.reasons:
            console.print(f"  +{score:>2} {reason}")
    else:
        console.print("No notable reasons recorded for this commit.")
    console.print()
    console.print(f"Subject: {info.subject}")
    console.print(f"Author: {info.author_name} <{info.author_email}>")
    console.print(f"Committer: {info.committer_name} <{info.committer_email}>")
    console.print(f"Reachable: {info.reachable}")


def _lookup_short(graph: dict[str, CommitInfo], short: str) -> CommitInfo | None:
    short = short.lower()
    for sha, info in graph.items():
        if sha.startswith(short):
            return info
    return None


@app.command()
def explain_lost(
    path: str = typer.Argument(...),
    chain_id: str = typer.Argument(...),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Explain a lost commit chain in detail."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    chain = next((c for c in result.data.lost_chains if c.chain_id == chain_id), None)
    if chain is None:
        raise UsageError(f"lost chain not found: {chain_id}")
    console.print(f"[bold]{chain.chain_id}[/]")
    console.print(f"  Root: {chain.root}")
    console.print(f"  Tip:  {chain.tip}")
    console.print(f"  Commits: {chain.commit_count}")
    console.print(f"  Span: {chain.start} .. {chain.end}")
    console.print(f"  Common reachable ancestor: {chain.common_ancestor or '-'}")
    if chain.hint_branch:
        console.print(f"  Branch hint (heuristic): {chain.hint_branch}")
    console.print("  Chain:")
    for sha in chain.commits:
        console.print(f"    {sha[:12]}")
    if chain.authors:
        console.print(f"  Authors: {', '.join(chain.authors)}")
    console.print()
    console.print("These commits are currently unreachable from any known ref.")
    console.print("Reasoning is limited to local object availability; no intent is asserted.")


@app.command()
def doctor(
    path: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Check repository health and tool prerequisites."""
    _setup_logging(verbose)
    from refhound.git.command import GitRunner
    from refhound.git.repository import open_repository

    git = GitRunner()
    try:
        version = git.run("--version").stdout.strip()
        console.print(f"[green]git[/] {version}")
    except Exception as exc:
        console.print(f"[red]git unavailable[/] {exc}")
        return
    try:
        info = open_repository(path, git=git)
    except Exception as exc:
        console.print(f"[red]repository error[/] {exc}")
        return
    from refhound.git.lfs import lfs_installed
    from refhound.git.repository import cache_root

    details = {
        "schema_version": "1",
        "refhound_version": __version__,
        "git_version": version,
        "python_version": sys.version.split()[0],
        "repository": info.path,
        "object_format": info.object_format,
        "bare": info.bare,
        "shallow": info.shallow,
        "partial": info.partial,
        "work_tree": info.work_tree,
        "head": info.head_sha,
        "head_ref": info.head_ref,
        "remote": info.remote_url,
        "lfs_available": lfs_installed(git, info.git_dir or info.path),
        "database_path": str(default_db_path()),
        "cache_path": str(cache_root()),
        "providers_enabled": False,
        "profiles": sorted(PROFILES),
    }
    if as_json:
        _print_serialized(json.dumps(details, indent=2))
        return
    console.print(f"- bare: {info.bare}")
    console.print(f"- shallow: {info.shallow}")
    console.print(f"- partial clone: {info.partial}")
    console.print(f"- object format: {info.object_format}")
    console.print(f"- work tree: {info.work_tree or '-'}")
    console.print(f"- HEAD: {(info.head_sha or '-')[:12]} on {info.head_ref or '-'}")
    if info.remote_url:
        console.print(f"- remote origin: {info.remote_url}")
    else:
        console.print("- remote origin: none")
    console.print(f"- git-lfs available: {details['lfs_available']}")
    console.print(f"- database: {details['database_path']}")
    console.print(f"- cache: {details['cache_path']}")


@app.command()
def report(
    path: str = typer.Argument(...),
    format_option: str = typer.Option("markdown", "--format", help="markdown | json | sarif"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path"),
    deep: bool = typer.Option(False, "--deep"),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore cached scan results"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Generate a report (Markdown, JSON or SARIF)."""
    _setup_logging(verbose)
    profile = "deep" if deep else "standard"
    try:
        result = _load_or_scan(path, fresh=fresh, profile=profile)
        options = result.options
    except RefHoundError as exc:
        _fail(exc, False)
        return
    if format_option == "json":
        text = json_ui.scan_json(result.data, options, include_secrets=True)
    elif format_option == "sarif":
        text = sarif_ui.sarif_document(result.data, options)
    else:
        text = markdown_ui.markdown_report(result.data, options)
    if output:
        secure_write_text(output, text)
        console.print(f"Report written to {output}")
    else:
        _print_serialized(text)


@app.command()
def diff_scan(
    old: str = typer.Argument(...),
    new: str = typer.Argument(...),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Compare two scan results (by scan id)."""
    _setup_logging(verbose)
    db = Database(default_db_path())
    scans = {scan_id: _resolve_scan_refs(db, scan_id) for _, scan_id in db.list_all_scan_ids()}
    old_refs = scans.get(old)
    new_refs = scans.get(new)
    if old_refs is None:
        raise UsageError(f"scan id not found: {old}")
    if new_refs is None:
        raise UsageError(f"scan id not found: {new}")
    old_set, new_set = set(old_refs), set(new_refs)
    added_refs = sorted(new_set - old_set)
    removed_refs = sorted(old_set - new_set)
    for ref in added_refs:
        console.print(f"+ {ref} ({new_refs[ref][:8]})")
    for ref in removed_refs:
        console.print(f"- {ref} ({old_refs[ref][:8]})")
    for ref in sorted(old_set & new_set):
        if old_refs[ref] != new_refs[ref]:
            console.print(f"~ {ref} {old_refs[ref][:8]} -> {new_refs[ref][:8]}")


def _resolve_scan_refs(db: Database, scan_id: str) -> dict[str, str]:
    refs = db.scan_refs_by_id(scan_id)
    if not refs:
        raise UsageError(f"scan id not found: {scan_id}")
    return refs


@app.command()
def baseline(
    path: str = typer.Argument(...),
    output: str = typer.Option("baseline.json", "--output", "-o"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Create a baseline from the current findings."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    text = create_baseline(result.data.findings, repository=result.repository)
    secure_write_text(output, text)
    console.print(f"Baseline written to {output} ({len(result.data.findings)} findings)")


# --------------------------------------------------------------- analyze app


@analyze_app.command("churn")
def analyze_churn(
    path: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
    verbose: int = typer.Option(0, "-v", count=True),
) -> None:
    """Find files/secrets added and removed within a short window."""
    _setup_logging(verbose)
    try:
        result = _load_or_scan(path)
    except RefHoundError as exc:
        _fail(exc, False)
        return
    if as_json:
        _print_serialized(
            json.dumps(
                [
                    {
                        "path": c.path,
                        "added_commit": c.added_commit,
                        "removed_commit": c.removed_commit,
                        "lifetime_seconds": c.lifetime_seconds,
                        "added_at": c.added_at.isoformat() if c.added_at else None,
                        "removed_at": c.removed_at.isoformat() if c.removed_at else None,
                        "secret_found": c.secret_found,
                    }
                    for c in result.data.churn
                ],
                indent=2,
            )
        )
        return
    for item in result.data.churn:
        lifetime = f"{int(item.lifetime_seconds)}s" if item.lifetime_seconds else "?"
        console.print(
            f"[yellow]{item.path}[/]  added {item.added_commit[:8]} -> removed {item.removed_commit[:8]}  lifetime {lifetime}"
        )


# ------------------------------------------------------------------ helpers


def _history_components(data: AnalysisData) -> int:
    from refhound.git.graph import components

    return len(components(data.commit_graph))


def _root_commits(data: AnalysisData) -> list[str]:
    from refhound.git.graph import find_roots

    return find_roots(data.commit_graph)


def _fail(exc: RefHoundError, debug: bool) -> None:
    if debug:
        traceback.print_exc()
    console.print(f"[red]error[/] {exc}")
    _exit(_exit_code(exc))


def _exit_code(exc: Exception) -> int:
    if isinstance(exc, (UsageError, ConfigError)):
        return 2
    if isinstance(exc, (GitError, RepositoryError, ProviderError)):
        return 3
    return 4


class _ExitError(Exception):
    """Internal control-flow exception carrying the process exit code."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def _exit(code: int) -> None:
    raise _ExitError(code)


register_cache_commands(cache_app, console, _print_serialized, _fail)


def main() -> None:
    """Entry point used by the console script; controls exit codes."""
    try:
        app(standalone_mode=False)
    except _ExitError as exc:
        raise SystemExit(exc.code) from exc
    except typer.Exit as exc:
        raise SystemExit(exc.exit_code) from exc
    except UsageError as exc:
        console.print(f"[red]usage error[/] {exc}")
        raise SystemExit(2) from exc
    except RefHoundError as exc:
        console.print(f"[red]error[/] {exc}")
        raise SystemExit(_exit_code(exc)) from exc
    except Exception as exc:  # pragma: no cover - last-resort guard
        console.print(f"[red]internal error[/] {exc}")
        raise SystemExit(4) from exc


if __name__ == "__main__":
    main()
