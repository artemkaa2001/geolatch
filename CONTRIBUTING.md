# Contributing

Use Python 3.10+ on Linux. Create a development environment and install the project:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pytest -m 'not integration'
.venv/bin/python -m build
shellcheck install.sh uninstall.sh
```

Keep CLI and TUI behavior in the shared controller. Add translated user messages to both catalogs, and test their keys and interpolation arguments. Preserve Python 3.10 syntax compatibility. Do not bundle upstream GeoIP datasets or add a paid source as a runtime requirement.

Firewall tests must use isolated network namespaces. Never test a rule mutation in your workstation or CI host's primary network namespace. Kernel tests need Linux, nftables, iproute2 and sufficient namespace capabilities:

```sh
sudo env GEOLATCH_REQUIRE_INTEGRATION=1 "$PWD/.venv/bin/python" -m pytest tests/test_integration.py -m integration -v
```

An unsupported namespace environment must report skipped tests explicitly. Mock-based tests are useful for failures and rollback state machines, but do not establish packet filtering correctness. See [verification](docs/verification.md) for limits and additional manual scenarios.

Before a pull request, describe the concrete behavior change, its safety implications and checks actually run. Include both successful and skipped checks. Keep unrelated refactors out of the change. Follow [SECURITY.md](SECURITY.md) for vulnerabilities.
