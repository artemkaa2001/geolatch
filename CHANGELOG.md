# Changelog

## 0.1.1 — nftables compatibility and interrupted-apply recovery

- Verify ownership and chain revisions through text when older nftables versions omit comments from JSON; explicit foreign markers are still rejected.
- Allow explicit `install.sh --repair` to recover a pending apply using the staged, fixed backend before switching releases.
- Preserve the interrupted policy as `/etc/geolatch/recovered-draft.yaml` and reopen it as an unapplied TUI draft. Automatic updates and enable/disable/rollback do not discard it.
- Fix nft syntax and alternate-interface routes in four isolated integration-test fixtures.
- Add compatibility and repair regressions. Local verification: 302 passed, 8 kernel scenarios skipped; kernel CI is rerun separately.

## 0.1.0 — initial implementation

- Modular Python configuration, provider, nftables and management layers.
- English/Russian Textual setup and management interface.
- Per-destination IPv4/IPv6 country policies with interval sets and GeoLatch-only allowlist.
- Validated GeoIP cache, atomic rules replacement, local confirmed snapshots and timed rollback.
- Isolated installation, systemd update/restore units, CLI, tests and documentation.

Version numbers do not establish verified production readiness. See [verification status](docs/verification.md).
