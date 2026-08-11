"""Git notes inventory (refs/notes/*)."""

from __future__ import annotations

import logging
from pathlib import Path

from refhound.git.command import GitRunner, validate_oid

logger = logging.getLogger(__name__)


def list_notes(git: GitRunner, cwd: str | Path) -> dict[str, bytes]:
    """Return mapping {object_sha: note_bytes} for all notes.

    Notes content is only read in memory; it is never written to disk.
    Superseded notes are skipped (we read the current refs only).
    """
    out = git.run("notes", "list", cwd=cwd, check=False)
    if out.returncode != 0:
        return {}
    notes: dict[str, bytes] = {}
    for line in out.stdout.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        note_oid, target = fields[0], fields[1]
        if not note_oid or len(note_oid) < 4:
            continue
        try:
            blob = git.batch_cat_file([validate_oid(note_oid)], cwd=cwd, content=True)
        except Exception as exc:
            logger.debug("failed to read note %s: %s", note_oid, exc)
            continue
        if note_oid in blob:
            notes[target] = blob[note_oid]
    return notes
