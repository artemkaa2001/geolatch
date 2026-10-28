# Reproducible management-plane benchmarks

Install the project into a Python 3.10+ environment, then run:

```sh
.venv/bin/python benchmarks/performance.py --prefixes 50000
```

The synthetic input consists of nonadjacent public IPv4 `/24` networks. The JSON output records Python/kernel versions, input and normalized prefix counts, parsing/normalization time, rules preparation time, rules bytes and peak Python allocations measured with `tracemalloc`. Results describe this process and synthetic input, not actual packet throughput or the RAM consumed by kernel sets.

A recorded 50,000-prefix run on Python 3.12.14 and kernel 6.18.55 measured parsing/normalization at 6.992 seconds with 40,960,491 peak Python bytes, and rules preparation at 1.834 seconds with 43,630,247 peak Python bytes. Rules were 751,330 bytes. These measured times include allocation-tracing overhead; see [verification](../docs/verification.md). No nftables load or packet throughput was measured locally.

For an optional nftables load measurement:

```sh
sudo .venv/bin/python benchmarks/performance.py --prefixes 50000 --kernel
```

`--kernel` re-executes the benchmark in a newly created network namespace before any nftables mutation. The inner process independently checks its parent's namespace through `/proc` and refuses a matching current namespace or a forged parent argument. It requires Linux namespace permissions, `unshare` and nftables. It never loads the benchmark table in the caller's network namespace. If isolation is unavailable, the command fails and no load performance is claimed.

Use `--cidr-file /path/to/public-ipv4.txt` for your own representative CIDR input; the same production validation applies. No upstream datasets are bundled with this benchmark. Record the complete output and hardware/environment when comparing results. Different country aggregation, nftables/kernel versions and memory pressure affect results. No fixed packets-per-second performance is asserted.
