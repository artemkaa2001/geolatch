# Configuration

The default file is `/etc/geolatch/config.yaml`. It is root-owned and locally readable so an ordinary user can open the menu; configured administrative CIDRs and destinations are therefore visible to local users. It contains no credentials. Confirmed/pending snapshots and provider cache remain private. [The complete example](../examples/config.yaml) uses documentation addresses. TUI edits are drafts until confirmed apply; changing the display language may be saved separately. Unknown keys, unsupported schema versions, malformed YAML, incorrect types, countries, interfaces, addresses or CIDRs are rejected.

| Field | Meaning |
| --- | --- |
| `version` | Schema version; currently `1`. Unsupported versions are rejected rather than guessed. |
| `language` | `en` or `ru`; kept during upgrades. |
| `enabled` | Whether GeoLatch filtering is enabled. |
| `source` | `ipverse-geo` or `ipverse-rir`; no silent failover. |
| `updates.enabled` | Whether the systemd update timer should run. |
| `updates.interval` | `daily`, `hourly` or `weekly`; daily is the default. |
| `network.ipv4`, `network.ipv6` | Families to use for GeoIP filtering. |
| `network.interfaces` | Explicit ingress interface names; required for active blocking policies. |
| `firewall.action` | `drop` in this release. |
| `firewall.preserve_established` | Preserve established/related traffic by default. |
| `allowlist.ipv4`, `allowlist.ipv6` | Trusted source CIDRs excluded only from GeoLatch. |
| `policies` | Named policies with `enabled`, `destinations`, `block_countries`. |

Explicit `destinations` are exact unicast addresses, not arbitrary network prefixes. Private destination addresses are useful when the provider applies external NAT; they must match what this host sees. A manually entered address needs careful review because discovery may not list it. Country codes are ISO 3166-1 alpha-2; country names are display labels only.

`destinations: all` resolves suitable public local addresses on selected interfaces. It does not include arbitrary forwarded destinations, every bridge, loopback or tunnel. Resolution occurs during apply/update/restore. No event-driven address watcher runs in this release, so reapply after changing addresses. At reboot ensure your network manager's wait-online service waits for the addresses you require.

Two active policies that match the same destination block the union of their countries. Empty or disabled policies add nothing; they cannot grant an exception to another policy. Allowlist is global to GeoLatch and does not override UFW or another firewall.

Changing a provider or required country/family can require a new download. Boot restore uses confirmed local data rather than newly edited unconfirmed YAML. To inspect a different config without changing the default use `geolatch --config /path/to/config.yaml plan`.
