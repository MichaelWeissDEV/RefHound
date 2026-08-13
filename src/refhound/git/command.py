"""Central git invocation layer.

Every ``git`` call in RefHound goes through :class:`GitRunner`. This gives us:

* a single place to apply timeouts and environment overrides
* structured errors that map to the public exit-code scheme
* optional streaming output
* validation that user-supplied object IDs are well-formed before they are
  interpolated into revision expressions
* command logging that intentionally never receives secret material

``shell=True`` is never used. Arguments are passed as a list.
"""

from __future__ import annotations

import logging
import os
import queue
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from refhound.errors import GitError, GitNotFoundError
from refhound.util.sanitize import sanitize_command_args, sanitize_text

logger = logging.getLogger("refhound.git")

_HEX_OID_RE = re.compile(r"^(?:[0-9a-fA-F]{4,40}|[0-9a-fA-F]{64})$")

#: Commands whose stdout may be arbitrarily large; used for streaming callers.
_BINARY_SAFE = ("cat-file",)


def validate_oid(value: str) -> str:
    """Validate an object ID (short or full) before using it with git.

    Raises ``ValueError`` if the value is not a plausible hex OID.
    """
    if not isinstance(value, str) or not _HEX_OID_RE.match(value):
        raise ValueError(f"Invalid git object ID: {value!r}")
    return value.lower()


def is_valid_oid(value: str) -> bool:
    """Return whether *value* is an accepted SHA-1/SHA-256 object id."""
    try:
        validate_oid(value)
    except ValueError:
        return False
    return True


def find_git() -> str:
    """Locate the git executable."""
    exe = shutil.which("git")
    if not exe:
        raise GitNotFoundError(
            "git executable not found on PATH. RefHound requires a local "
            "git client; see docs/git-model.md."
        )
    return exe


@dataclass(slots=True)
class GitResult:
    """Result of a successful ``git`` invocation."""

    command: str
    args: list[str]
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0

    @property
    def lines(self) -> Iterator[str]:
        yield from self.stdout.splitlines()


@dataclass(slots=True)
class GitRunner:
    """Thin wrapper around subprocess for git invocations."""

    git: str = field(default_factory=find_git)
    default_timeout: float = 300.0
    _env: dict[str, str] | None = None

    def environment(self, **overrides: str) -> GitRunner:
        """Return a copy with extra environment variables applied."""
        merged = dict(self._env or os.environ.copy())
        merged.update(overrides)
        return GitRunner(git=self.git, default_timeout=self.default_timeout, _env=merged)

    def run(
        self,
        *args: str,
        cwd: str | Path | None = None,
        timeout: float | None = None,
        check: bool = True,
        input_data: bytes | None = None,
    ) -> GitResult:
        """Run git with ``args`` and return structured output."""
        command = self.git
        env = self._env or os.environ.copy()
        # Deterministic, locale-independent output.
        env.setdefault("LC_ALL", "C")
        try:
            proc = subprocess.run(
                [command, *args],
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                input=input_data,
                env=env,
                timeout=self.default_timeout if timeout is None else timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitError(
                f"git command timed out after {timeout or self.default_timeout}s: "
                f"{self._describe(args)}",
                command=self._describe(args),
            ) from exc
        except OSError as exc:
            raise GitError(f"failed to execute git: {exc}", command=self._describe(args)) from exc

        result = GitResult(
            command=command,
            args=list(args),
            stdout=proc.stdout.decode("utf-8", errors="replace"),
            stderr=sanitize_text(proc.stderr.decode("utf-8", errors="replace")),
            returncode=proc.returncode,
        )
        if check and proc.returncode != 0:
            raise GitError(
                f"git {self._describe(args)} failed (exit {proc.returncode}): "
                f"{result.stderr.strip()[:500]}",
                command=self._describe(args),
                stderr=result.stderr,
            )
        logger.debug("git %s -> exit %s", self._describe(args), proc.returncode)
        return result

    def stream(
        self,
        *args: str,
        cwd: str | Path | None = None,
        timeout: float | None = None,
    ) -> Iterator[bytes]:
        """Stream stdout of a git command line-by-line as bytes."""
        env = self._env or os.environ.copy()
        env.setdefault("LC_ALL", "C")
        proc = subprocess.Popen(
            [self.git, *args],
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        limit = self.default_timeout if timeout is None else timeout
        started = time.monotonic()
        output: queue.Queue[bytes | None] = queue.Queue(maxsize=128)
        stderr_chunks: list[bytes] = []
        assert proc.stdout is not None
        assert proc.stderr is not None
        stdout_pipe = proc.stdout
        stderr_pipe = proc.stderr

        def _read_stdout() -> None:
            try:
                for line in stdout_pipe:
                    output.put(line)
            finally:
                output.put(None)

        def _read_stderr() -> None:
            for chunk in iter(lambda: stderr_pipe.read(65536), b""):
                stderr_chunks.append(chunk)

        stdout_thread = threading.Thread(target=_read_stdout, daemon=True)
        stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        try:
            while True:
                remaining = limit - (time.monotonic() - started)
                if remaining <= 0:
                    raise GitError(
                        f"git command timed out after {limit}s: {self._describe(args)}",
                        command=self._describe(args),
                    )
                try:
                    item = output.get(timeout=min(remaining, 0.1))
                except queue.Empty:
                    if proc.poll() is not None and not stdout_thread.is_alive():
                        break
                    continue
                if item is None:
                    break
                yield item
            remaining = max(0.0, limit - (time.monotonic() - started))
            try:
                returncode = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise GitError(
                    f"git command timed out after {limit}s: {self._describe(args)}",
                    command=self._describe(args),
                ) from exc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            stdout_pipe.close()
            stderr_pipe.close()
            stdout_thread.join(timeout=1.0)
            stderr_thread.join(timeout=1.0)
        stderr = sanitize_text(b"".join(stderr_chunks).decode("utf-8", errors="replace"))
        if returncode != 0:
            raise GitError(
                f"git {self._describe(args)} failed (exit {returncode}): {stderr.strip()[:500]}",
                command=self._describe(args),
                stderr=stderr,
            )

    def batch_cat_file(
        self,
        oids: Sequence[str],
        *,
        cwd: str | Path | None = None,
        content: bool = True,
    ) -> dict[str, bytes]:
        """Fetch many blobs efficiently via ``git cat-file --batch``.

        Returns a mapping oid -> raw bytes. Invalid/missing blobs are skipped.
        """
        if not oids:
            return {}
        flag = "--batch" if content else "--batch-check"
        validated = [validate_oid(oid) for oid in oids]
        request = "\n".join(validated)
        if not request.endswith("\n"):
            request += "\n"
        env = self._env or os.environ.copy()
        env.setdefault("LC_ALL", "C")
        proc = subprocess.run(
            [self.git, "cat-file", flag],
            cwd=str(cwd) if cwd else None,
            input=request.encode("utf-8"),
            capture_output=True,
            env=env,
            timeout=self.default_timeout,
            check=False,
        )
        if proc.returncode != 0:
            raise GitError(
                f"git cat-file {flag} failed",
                stderr=sanitize_text(proc.stderr.decode("utf-8", errors="replace")),
            )
        out = proc.stdout
        results: dict[str, bytes] = {}
        pos = 0
        while pos < len(out):
            nl = out.find(b"\n", pos)
            if nl == -1:
                break
            header = out[pos:nl].decode("utf-8", errors="replace")
            fields = header.split(" ")
            if len(fields) >= 2 and fields[1] == "missing":
                pos = nl + 1
                continue
            if len(fields) < 3:
                break
            oid, _kind, size = fields[0], fields[1], int(fields[2])
            body = out[nl + 1 : nl + 1 + size]
            results[oid] = body
            pos = nl + 1 + size + 1  # trailing newline after blob data
        return results

    @staticmethod
    def _describe(args: Sequence[str]) -> str:
        return " ".join(sanitize_command_args(args))
