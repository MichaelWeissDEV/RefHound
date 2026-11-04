"""Sphinx configuration for the RefHound documentation.

This file intentionally contains only ASCII characters so the build
is fully portable across platforms and CI environments.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path


def _read_version() -> str:
    """Read the single version source without importing the package."""
    source = Path(__file__).resolve().parent.parent / "src" / "refhound" / "_version.py"
    module = ast.parse(source.read_text(encoding="utf-8"))
    for node in module.body:
        if isinstance(node, ast.Assign) and any(
            getattr(target, "id", "") == "__version__" for target in node.targets
        ):
            return str(ast.literal_eval(node.value))
    raise RuntimeError(f"could not read __version__ from {source}")


project = "RefHound"
author = "Michael Weiss"
copyright = "2026, Michael Weiss"
version = os.environ.get("REFHOUND_DOC_VERSION", _read_version())
release = version

extensions: list[str] = []

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

source_suffix = ".rst"
master_doc = "index"

language = "en"

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "prev_next_buttons_location": "bottom",
    "style_external_links": True,
}
html_static_path: list[str] = []
