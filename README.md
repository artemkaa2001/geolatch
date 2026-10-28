[English](README.md) | [Русский](README.ru.md)

# GeoLatch

Lightweight Linux GeoIP firewall manager with per-IP country blocking, automatic updates, bilingual terminal UI and safe rollback.

GeoLatch filters incoming traffic in the Linux kernel using nftables country CIDR sets. Choose the server interfaces and destination IPs you want to protect, then block different countries for different addresses. Python manages configuration and updates; it does not process packets. There is no web service, account, paid API, database server or permanent Python packet daemon.

Developer: [@artemkaa_2001](https://t.me/artemkaa_2001). Application license: [MIT](LICENSE).

## Requirements and installation

The automatic installer targets Ubuntu 22.04/24.04/26.04 LTS and current Debian on x86_64 or ARM64, with Python 3.10+, nftables and systemd. These are compatibility targets; see [verification status](docs/verification.md) for what has actually been tested. Administrative access and outbound HTTPS to the selected upstream GeoIP repository are required.

```sh
git clone https://github.com/artemkaa2001/geolatch.git && cd geolatch && sudo ./install.sh
```

The installer installs distribution dependencies, creates an isolated Python environment, registers `/usr/local/bin/geolatch` and systemd units, then opens the full-screen setup wizard automatically. It does not change the server's firewall until you review and apply a policy. The first full screen lets you choose English or Russian; a system locale only affects the initially suggested language.

If already installed, the installer offers Open, Upgrade, Repair or Cancel. Updates preserve `/etc/geolatch/config.yaml`, local data and existing rules. For unattended software installation use `sudo ./install.sh --no-setup`; an existing installation additionally requires `--upgrade` or `--repair`. That explicit automation mode does not configure a firewall for you.

For an interrupted apply caused by an older installation, use current source and `sudo bash install.sh --repair`. Repair preserves the desired policy as a recovered draft, restores the preceding rules with the fixed backend, and reopens the draft for review. See [recovery instructions](docs/troubleshooting.md).

## First setup and daily use

The wizard discovers actual interfaces and IPv4/IPv6 addresses, lets you select destinations and countries, choose an upstream provider, add trusted administrative CIDRs, and review the result. Docker bridges, loopback and tunnel interfaces require particular care. Confirm that the selected destination is the address seen **before DNAT**, especially on a VPS behind a provider NAT.

Use arrow keys to navigate, Space to toggle checkboxes, Enter to choose, Tab to move focus, and Esc to go back. Q exits where applicable; Ctrl+C exits cleanly. Country selection supports search by localized country name or ISO code. Changes are drafts until reviewed and applied. Language can be changed under Settings → Language without restarting; `--lang` temporarily overrides it for a CLI invocation.

Run this whenever you need the menu:

```sh
geolatch
```

Changing firewall state requires root. The application uses `sudo` for privileged operations; no setuid Python or persistent root control daemon is installed. Reading kernel nftables state may also require privileges, so an ordinary user's status can report that live state is unavailable rather than inventing an active status.

## Per-IP policies

For example, block Iran and Pakistan on `203.0.113.10`, and China on `203.0.113.20`. In the wizard create a policy for each destination; leave other IPs out of all policies. Policies sharing a destination add their blocked country lists together. A policy with no countries contributes no blocks and does not override another policy.

[examples/config.yaml](examples/config.yaml) shows the equivalent YAML. Its interface, trusted source and destination addresses are documentation examples: replace them with your real values before use. No manual YAML editing is needed for the interactive workflow.

`destinations: all` means suitable public local addresses on the selected interfaces, resolved again during apply, update and offline restore. It never means every forwarded destination. Address changes are not watched continuously; reapply after an address change. See [configuration](docs/configuration.md).

## CLI and safe apply

```sh
geolatch --help
geolatch --lang ru status
geolatch addresses --json
geolatch countries
geolatch plan
sudo geolatch apply
sudo geolatch confirm TOKEN
sudo geolatch update --dry-run
sudo geolatch update
sudo geolatch rollback
sudo geolatch disable --yes
sudo geolatch enable
geolatch check-ip 1.2.3.4 --destination 203.0.113.10
sudo geolatch doctor
geolatch logs
geolatch version
```

`setup` explicitly opens the wizard and requires a terminal. `plan` is a read-only preview. The global `--config FILE`, `--state-dir DIR`, `--cache-dir DIR`, `--lang en|ru` and `--json` options precede the subcommand; diagnostic subcommands also accept `--json`. JSON field names remain stable across languages. `check-ip` predicts GeoLatch policy matching from available data; it is not an end-to-end connectivity test.

Manual apply starts a separate rollback watchdog and returns a confirmation token. Confirm within 90 seconds, or the previous confirmed state is restored. In the TUI use its confirmation screen. `apply --timeout 180` changes the deadline within the supported range. Keep an independent SSH session and a provider console open for your first deployment. An allowlisted source bypasses only GeoLatch; it does not bypass other firewall rules. Do not assume that `SSH_CONNECTION` identifies your real administrative public IP when using a proxy or jump host.

For deliberate automation, `sudo geolatch apply --yes --confirm` acknowledges the change and commits it without a further connectivity confirmation. This explicitly gives up the interactive safety window. `update --force` never disables CIDR validation or anomaly checks. Emergency recovery commands are documented in [security](docs/security.md).

## Updates and reboot

Confirmed configuration and validated local data survive software updates. The daily `geolatch-update.timer` uses a persistent systemd schedule and randomized delay. The short-lived update service downloads all required country/family datasets, validates them, checks changes in prefix counts and address coverage, and applies a complete atomic nftables transaction. A failed download does not clear active sets. An unchanged dataset does not cause an unnecessary rules replacement. See `systemctl list-timers geolatch-update.timer` and `journalctl -u geolatch-update.service`.

`geolatch-restore.service` restores the last confirmed configuration using local data, without a network download. Restore runs after nftables/UFW and after network-online, before Docker. Your network manager must implement a suitable wait-online service for `destinations: all`. A later third-party firewall reload can still remove or change rules; GeoLatch does not take control of other firewall services. The offline restore workflow is tested separately from a real machine reboot.

## Firewall compatibility and limitations

GeoLatch owns only `table inet geolatch`. Its prerouting chain at priority `-150` observes the destination after conntrack and before the usual DNAT priority `-100`; this is intended to include published Docker ports. Rules match selected ingress interfaces and destination addresses. Trusted sources and preserved established/related connections return from GeoLatch's chain; there is no GeoLatch global accept rule. IPv6 Neighbor Discovery is preserved.

UFW, Docker, iptables-nft, Nginx, HAProxy, Xray and VPNs may coexist, but compatibility depends on actual hook ordering, ingress interfaces, NAT placement and conntrack behavior. Traffic already DNATed before reaching this host has a different destination. Custom earlier NAT hooks, notrack, flowtable/hardware offload, proxies and tunnel ingress require separate validation. See [firewall behavior](docs/firewall.md). Do not enable GeoLatch on bridges or tunnels blindly.

GeoIP is an approximate IP classification, not proof of a user's physical location. VPNs, proxies, roaming and database mistakes can change results. Do not use geographic filtering as a replacement for authentication or normal service hardening.

## GeoIP sources and licensing

The default `ipverse-geo` source uses [ipverse/geo-ip-blocks](https://github.com/ipverse/geo-ip-blocks). The compact `ipverse-rir` alternative uses [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) based on registry allocations; its coverage and country attribution differ. GeoLatch never switches source silently after a failure. Downloads use HTTPS with timeouts, bounded retries and size limits. Cached content is hashed; a SHA-256 checksum checks local integrity, not independent upstream authenticity.

Application MIT licensing does not relicense GeoIP data. See [source and license notes](docs/sources.md) for verified upstream terms and links. No upstream CIDR datasets are bundled. Country display names are derived from Debian `iso-codes` and distributed under LGPL-2.1-or-later with their separate [notice](geolatch/locales/COUNTRIES-LICENSE.txt).

## Troubleshooting, verification and removal

Use `sudo geolatch doctor`, `geolatch logs` and the relevant systemd journal. Errors and unavailable checks must be resolved before treating the firewall as active. See [troubleshooting](docs/troubleshooting.md), [architecture](docs/architecture.md), [localization](docs/localization.md) and [verification](docs/verification.md). Unit tests and mocked nftables execution alone do not establish that kernel filtering works on your server.

```sh
sudo ./uninstall.sh
# Or use the installed copy while the checkout is unavailable:
sudo /opt/geolatch/current/uninstall.sh
```

Removal stops GeoLatch jobs, deletes only its owned rules and program, and asks whether to retain configuration, snapshots and cache. `--yes` skips the removal confirmation and preserves data; add `--purge` to explicitly remove that data too. It does not uninstall system nftables, disable UFW, change routes or flush another application's rules.

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). Security reporting: [SECURITY.md](SECURITY.md).
