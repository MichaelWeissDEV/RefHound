"""Safe writes for security-sensitive report artifacts."""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from pathlib import Path

from refhound.errors import ConfigError


def secure_write_text(path: str | Path, content: str) -> None:
    """Atomically write UTF-8 text with user-only POSIX permissions."""
    destination = Path(path).expanduser()
    parent = destination.parent
    if not parent.exists() or not parent.is_dir():
        raise ConfigError(f"output parent directory does not exist: {parent}")
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    except OSError as exc:
        raise ConfigError(f"cannot write output file {destination}: {exc}") from exc
    finally:
        if temporary is not None:
            with suppress(OSError):
                os.unlink(temporary)
