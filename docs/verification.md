# Verification status and release checklist

The repository supplies unit, Textual and opt-in isolated kernel integration tests, plus GitHub Actions for Python compatibility, Ruff, packaging and ShellCheck. A CI workflow definition is not itself a successful CI run.

The initial development environment is an unprivileged Linux workspace with Python 3.12 and preinstalled Python test tools. It does not provide nftables, sudo or usable user/network namespace creation. Kernel packet-filter tests therefore cannot be claimed as passed there. No Ubuntu/Debian host install, real systemd boot, ARM64 run, UFW/Docker deployment or production-throughput test is implied by unit results. The final implementation report records actual local test counts and skips.

Run non-kernel checks in an isolated Python environment:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pytest -m 'not integration'
.venv/bin/python -m build
shellcheck install.sh uninstall.sh
```

Run kernel tests on a disposable Linux VM/CI runner with nftables and iproute2:

```sh
sudo env GEOLATCH_REQUIRE_INTEGRATION=1 "$PWD/.venv/bin/python" -m pytest tests/test_integration.py -m integration -v
```

Tests must create their own network namespaces before rule mutation and clean up on failure. Normally, a missing capability/tool is a skip with a reason, not a successful packet test. `GEOLATCH_REQUIRE_INTEGRATION=1` makes unavailable prerequisites fail the CI job rather than silently skipping it. These tests require nftables, iproute2, util-linux, procps and enabled IPv6. Do not run ad hoc firewall mutations on a real server's primary namespace.

Version 0.1.3 adds isolated scenarios for unique dropped-source accounting. They check repeated source addresses across protocols, ports and destinations, IPv4/IPv6 totals, allowlist and unselected-destination exclusions, snapshot restoration and reset after replacement. A separate scenario reduces each tracking set to two addresses and verifies that further sources still hit DROP after the set fills. Synthetic container/transit links use permanent IPv6 neighbors from their actual veth MACs; the source/server link retains dynamic Neighbor Discovery. These scenarios require the kernel job above; cardinality unit tests do not replace packet evidence. In the local development environment, the two harness-isolation guards pass and all ten packet scenarios skip because kernel prerequisites are unavailable.

Before calling a release suitable for your deployment, verify IPv4/IPv6 TCP and UDP, selected versus unselected destinations, allowed versus blocked sources, preserved established traffic and administrative allowlist. Check pre-DNAT behavior, unrelated table preservation, atomic failed replacement, repeated apply, timeout after parent process death, explicit rollback, disable, offline restore and source failure. Repeat with the UFW/Docker/VPN topology actually used. Test a real reboot with wait-online and actual addresses available.

No packets-per-second or memory guarantee is made. [Benchmarks](../benchmarks/README.md) provide reproducible management-plane measurements and an optional isolated nftables load measurement; packet-path throughput needs a separate workload and target hardware.

## Recorded management benchmark

An actual local run before the 0.1.3 tracking changes, on Python 3.12.14, Linux kernel 6.18.55, used 50,000 synthetic nonadjacent IPv4 `/24` prefixes, all retained after normalization:

| Work | Elapsed time | Peak Python allocations |
| --- | --- | --- |
| CIDR parsing and normalization | 6.992 s | 40,960,491 bytes |
| Rules preparation | 1.834 s | 43,630,247 bytes |

Generated rules were 751,330 bytes. Timings include `tracemalloc` instrumentation overhead and describe this synthetic management workload only. Kernel set memory, nftables load time and packet throughput were not measured in this environment. Reproduce with `.venv/bin/python benchmarks/performance.py --prefixes 50000` after installing the project.
