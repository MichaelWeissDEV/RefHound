Git Forensics Methodology
=========================

RefHound inventories refs and objects, loads reachable commits in bulk, asks
``git fsck`` for object-database observations, and parses unreachable commits
through ``cat-file --batch``. Connected unreachable commit components become
lost-chain candidates. Reflogs and stash refs are additional local evidence
in deep/forensic profiles; Git notes are read only in forensic mode.

Force-push findings compare stored ref snapshots. They show observable ref
transitions and never attribute intent. Deleted-branch and branch-name hints
are heuristics. Garbage-collected objects and server-side objects not served
to the client are unavailable.
