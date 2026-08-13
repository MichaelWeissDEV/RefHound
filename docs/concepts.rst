Core Concepts
=============

Reachability
------------

A reachable object is referenced by a branch, tag, remote-tracking ref, or
another reachable object. An unreachable object still exists locally but has
no path from current refs. A dangling object is not referenced by another
object. Reflog-reachable commits can survive after branch deletion but remain
subject to expiry and garbage collection.

Lost history is RefHound's reconstruction of connected unreachable commits;
it is not proof that a named branch existed. Historical means an object is in
reachable history but absent from current ref-tip trees. Purged local or
server-side objects cannot be recovered by RefHound.

Facts and heuristics
--------------------

Object IDs, parents, refs, paths, and timestamps are facts read from Git.
Branch hints, force-push inference, identity grouping, confidence, and scores
are heuristics for reviewer prioritization. ``refhound explain`` exposes the
named score contributions and final bounded score.

Secret lifecycle
----------------

Detectors discard full values at their boundary. RefHound groups occurrences
using a stable fingerprint and classifies each occurrence as current,
historical, or unreachable. Introduction/removal windows are best effort over
the history visible to the local object database.
