Release and Compatibility
=========================

The supported public interface for v0.1 is the CLI and its versioned JSON,
baseline, and SARIF documents. Internal Python modules may change without a
deprecation period. Supported Python versions are 3.12 and 3.13. CI exercises
Linux, macOS, and Windows. Git SHA-1 is required; SHA-256 is supported where
the installed Git supports ``git init --object-format=sha256``.

Release artifacts are a wheel and source distribution. CI installs the wheel
in isolation and executes version/help commands. PyPI publication and tags
remain maintainer-controlled external release actions.
