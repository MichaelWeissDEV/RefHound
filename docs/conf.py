"""Sphinx configuration for the RefHound documentation.

This file intentionally contains only ASCII characters so the build
is fully portable across platforms and CI environments.
"""

from __future__ import annotations

import os

project = "RefHound"
author = "Michael Weiss"
copyright = "2026, Michael Weiss"
version = os.environ.get("REFHOUND_DOC_VERSION", "0.1.0")
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
