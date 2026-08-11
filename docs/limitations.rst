Limitations
===========

RefHound is a *client-side* forensic tool. What it can report is bounded by
what the git protocol and the local object database make visible.

Inherent limits
---------------

* **Purged objects are unrecoverable.** If objects have been removed by
  ``git gc --prune`` or a server-side purge, no client can read them. Lost
  history analysis is best-effort over whatever objects remain.
* **Server-side "lost" data** (for example a commit that was force-pushed
  away and garbage-collected on the server) is invisible to a clone. A
  mirror clone only contains what the server still serves.
* **Validation is out of scope.** RefHound reports token shapes; it never
  contacts a provider to check whether a token is live. A found string may
  be a revoked, expired, fake or example value.
* **Shallow / partial clones** miss history by definition. Use
  ``--unshallow`` when authorized to fetch full history.
* **LFS pointers** are detected as pointers, not content, unless LFS
  objects are fetched explicitly.

Heuristics are labeled
----------------------

Branch hints for lost chains, force-push inference, identity grouping and
"interesting" rankings are derived conclusions. They are always presented
with an explicit confidence value and labelled as heuristics. They are
observations that may be explained by benign workflows; they are not
accusations.

False positives
---------------

Secret scanning intentionally favours recall over precision. Generic
password and entropy detectors can flag placeholder values, example files
or test fixtures. Use baselines (``refhound baseline -o FILE`` and
``--baseline FILE``) to suppress known-good findings, and use
``.refhound.yml`` to tune ignored paths and detectors.
