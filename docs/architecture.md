# Architecture

GeoLatch has a management plane in Python and a packet path entirely in Linux nftables. CLI and Textual TUI call the same controller.

| Component | Responsibility |
| --- | --- |
| `config`, `networks` | Strict schema/address validation and actual interface discovery. |
| `i18n`, locale catalogs | Stable translation keys, interpolation, date/plural formatting and localized country names. |
| `providers`, `geoip` | Fixed upstream paths, bounded HTTPS downloads, validated immutable cache objects and anomaly detection. |
| `firewall`, `nftables` | Deterministic set/rule generation and ownership-checked atomic kernel transactions. |
| `controller` and persistence helpers | Serialize mutations, manage confirmed snapshots, pending apply and rollback, status, update and restore. |
| `cli`, `tui` | Human/machine command output, full-screen navigation and safe confirmations. |
| `systemd` units | Short daily update and offline boot restore; no permanent Python packet daemon. |

Default storage is `/etc/geolatch` for configuration, `/var/lib/geolatch` for confirmed/pending state and `events.jsonl` history, and `/var/cache/geolatch` for provider cache. systemd captures service output in the journal; the installer also reserves `/var/log/geolatch`. Files are atomically replaced with restrictive permissions. A process lock serializes apply/update/rollback; cached content is hashed and pending state is durable.

Manual apply validates the entire candidate, checks nftables, records a recovery state, arms an independent watchdog, replaces the table as one transaction, and verifies the result. Explicit confirmation promotes the new state; timeout or failure restores the previous state. On installed systemd hosts the watchdog is a dedicated transient service in its own control group, with restart-on-failure and bounded lifetime. A detached-session process is the fallback on nonsystemd systems; this has weaker service-group survival guarantees. Recovery never relies only on the TUI's `finally` block. A watchdog is temporary safety machinery, not a packet-processing daemon.

Unattended updates retain the previous working data on a source or validation failure and do not ask an absent operator to confirm a download. Offline restore uses last confirmed local data, re-resolving `all` destinations from current interfaces, without contacting GitHub. The restore path is distinct from a real boot sequence, which also depends on network-manager ordering and other firewall services.

Versioned Python virtual environments are installed under `/opt/geolatch/releases`; the root-owned launcher selects `/opt/geolatch/current` in isolated Python mode. Runtime state is independent of both source checkout and software release.
