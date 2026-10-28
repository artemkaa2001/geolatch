# Security design and recovery

Perform the first deployment from a server console or with provider console access available. Keep a second administrative session, add a deliberate trusted source CIDR, and test from both an allowed and blocked test source to each destination. Never assume a country lookup proves physical location or trustworthiness.

## Safe apply

The manual path uses a durable previous-state record and an independent timeout watchdog. On a systemd host, rollback runs in a dedicated transient service with its own control group, restart-on-failure behavior and a bounded lifetime; it survives termination of the invoking SSH/TUI service group. The nonsystemd fallback is a detached session process and has weaker protection against service managers that kill an entire parent control group. Confirmation is explicit; a process merely staying alive does not count. The default confirmation deadline is 90 seconds. A TUI crash or disconnected SSH must not be the sole mechanism that controls rollback.

```sh
sudo geolatch apply
# Only after verifying access:
sudo geolatch confirm TOKEN
```

Unattended `apply --yes --confirm` opts out of the extra manual confirmation. An allowlist exception affects only GeoLatch; earlier drops and later firewall chains remain effective. GeoLatch cannot recover from a broken provider route, unrelated firewall rules, a stopped kernel, lost disk or a powered-off server.

From an independent console, inspect the actual state before recovery:

```sh
sudo geolatch status --json
sudo geolatch rollback
# To remove only GeoLatch filtering instead:
sudo geolatch disable --yes
```

Do not use a global nftables flush. If software is damaged, use `install.sh --repair` after resolving a pending apply, then run an ownership-checked disable. Preserve state files for diagnosis. File hashes detect accidental local corruption but are not tamper protection against a root attacker.

## Input and privilege boundaries

Configuration and provider data are untrusted inputs. YAML is safely parsed and schema-validated; ISO codes, interface names, CIDRs and destinations are checked before rule generation. Downloads use fixed HTTPS sources, bounded sizes, timeouts and retries. HTML, malformed/wrong-family/default/service ranges, empty data and suspicious changes are rejected. A full candidate is checked before active rules change.

Privileged subprocesses receive argument arrays, not interpolated shell commands. The installed launcher uses a fixed root-owned interpreter in Python isolated mode, so `PYTHONPATH` and the caller's working directory cannot redirect privileged application imports. Root-owned state is not world-writable. Installation and runtime mutations have separate concurrency locks.

User preferences, raw CIDR data, current cache and confirmed recovery data have distinct roles. A provider/cache update is not permission to discard last-known-good. Uninstall disables jobs and removes only the managed table before removing the executable.
