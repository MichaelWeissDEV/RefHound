# RefHound synthetic benchmarks

Run `uv run python benchmarks/run.py`. The driver measures detector throughput
over 1k, 10k, and 100k unique synthetic blobs and Git commit-graph loading over
repositories containing 100, 1,000, and 10,000 commits. It records wall time,
peak Python allocation, Git subprocess count where instrumented, and workload
size as JSON. Fixtures contain no real credentials.

Results are machine-specific and should be compared only on the same host and
Git/Python versions. The benchmark does not access the network.
