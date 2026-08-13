Performance
===========

RefHound deduplicates blobs by object ID, batches content through
``cat-file --batch``, uses bulk ref/log commands, and bounds history buffers.
The quick profile disables entropy, binary, reflog, stash, notes, and
unreachable analysis. Standard adds entropy; deep adds local archaeology and
binary scanning; forensic adds notes.

The repository includes ``benchmarks/README.md`` and a synthetic benchmark
driver for 100/1,000/10,000 commits and 1k/10k/100k blobs. Benchmark results
are environment-specific and are not represented as release guarantees.
