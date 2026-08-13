# Security

RefHound is a defensive analysis tool. Its core security model is:

## Secret handling

* **Secrets are redacted at the source.** Detectors return only a prefix,
  a suffix, a category and a content-derived fingerprint (`sec_…`). The full
  value never leaves the detection layer.
* **Full secret values are never persisted.** RefHound does persist scan
  metadata, repository/ref information, commit metadata, findings, author
  identities, fingerprints, and safe redacted fragments in SQLite and
  reports. Treat those artifacts as security-sensitive forensic data.
* **Short secrets** (at or below `MIN_SECRET_LENGTH = 8`) are shown only as
  `<redacted:sec_…>` to avoid trivial reconstruction from a short mask.

### Fingerprint privacy tradeoff

Version 0.1 uses a stable, unsalted SHA-256 fingerprint. This enables stable
finding IDs and cross-scan baselines, but a party holding a report can test
low-entropy password guesses offline. Fingerprints must therefore be treated
as sensitive data. A future schema may introduce installation-keyed HMAC
fingerprints; that requires an explicit migration and is not silently mixed
with version-0.1 fingerprints.

### Remote authentication

HTTP/SSH URL userinfo and credential-like query parameters are removed by one
central sanitizer before URLs enter reports, models, logs, or exceptions.
Prefer Git Credential Manager or SSH configuration over credentials embedded
in a command-line URL, because process listings and shell history are outside
RefHound's control.

## What RefHound will never do

* Never validates, logs in with, or reuses a discovered credential.
* Never brute-forces object IDs, commit dates or anything else.
* Never attempts to bypass an access-control boundary. Analysis is limited
  to objects the client can already read through the git protocol, reflogs,
  stashes and authorized provider metadata.
* Never modifies the scanned repository (read-only analysis). Remote targets
  are cloned into a private mirror cache under the user's data directory.

## Operating safety

* Git subprocesses are invoked without a shell (`shell=False`) and object
  IDs are validated before interpolation into commands.
* Output is deterministic and stable; scans of the same repository and
  configuration produce identical fingerprints and finding IDs.
* Heuristic conclusions (lost-chain branch hints, force-push inference,
  identity grouping) are explicitly labeled as such and carry confidence
  values. RefHound reports observations; it does not accuse actors.

## Reporting a vulnerability

If you believe you have found a security issue in RefHound itself (e.g. a
way to leak a full secret, an injection through git arguments, or a
misleading report), please do **not** open a public issue. Report it
privately by contacting the maintainers via the repository's security
advisory workflow. Include a minimal reproduction and, if possible, a
suggested fix.
