# Changelog

## 0.1.3 — unique dropped-source IP statistics

- Show the number of unique dropped source IPs in the main menu and a compact Statistics screen, refreshed every 10 seconds while either screen is open.
- Deduplicate actual IPv4/IPv6 source addresses in bounded kernel sets; repeated packets, ports and destinations do not inflate the IP count. Packet and byte counters remain separately labelled.
- Limit tracking to 65,536 addresses per family and show a lower bound when full or after any failed insertion. A fallback DROP continues blocking traffic and counts missed observations, preserving the warning after temporary allocation failures.
- Explain unavailable legacy tracking and counter resets. Updating software preserves live rules; apply the current rules once to enable tracking on an older installation.
- Add cardinality and isolated packet scenarios, including full-set blocking, and stabilize IPv6 neighbors on synthetic forwarding links. Actual kernel verification depends on the integration-test environment; see [verification status](docs/verification.md).

## 0.1.2 — wait for a running rollback during repair

- Explicit repair waits up to 120 seconds for the existing operation lock, allowing a retrying old watchdog to finish its current attempt.
- Preserve the same lock inode and pending journal; do not terminate the watchdog or run concurrent firewall mutations. Ordinary commands still fail fast on contention.
- Close the waiting file descriptor on timeout or interruption. Cover contention with real separate-process flock tests.

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
