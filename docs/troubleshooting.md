# Troubleshooting

Start with:

```sh
sudo geolatch doctor
sudo geolatch status --json
geolatch logs
systemctl status geolatch-restore.service geolatch-update.timer geolatch-update.service
journalctl -u geolatch-update.service -u geolatch-restore.service --since today
```

**Permission denied while reading rules:** nftables requires `CAP_NET_ADMIN` on many systems, including root in a restricted container. A missing privilege is not evidence that the firewall is inactive or healthy. Use the supported host privileges; installation is intended for Linux servers with systemd, not an unprivileged application container.

**Wizard requires a terminal:** run `geolatch` through an interactive SSH session with a usable terminal. `setup` does not fall back to a stream of unanswered prompts in a pipe. `install.sh --no-setup` is an explicit software-only automation mode.

**No matching destination/interface:** inspect `geolatch addresses`. Select actual ingress and the destination visible before host DNAT. Private addresses may be correct behind provider NAT. Bridges and tunnels may not be appropriate public ingress. `all` only includes suitable public local addresses, so use explicit addresses where your network requires private targets.

**Upstream download failed or a country is unavailable:** check source, network access, HTTPS certificates and upstream structure. GeoLatch does not replace a missing/empty file with an empty blocklist. Previous active rules should remain. A country with no data for a selected family may require choosing the appropriate families/source. Do not disable validation to force an empty or HTML response through.

**Update rejected as anomalous:** compare source changes and known-good coverage. `--force` intentionally keeps fundamental validation and anomaly safeguards. Investigate rather than clearing the working state. Checksums detect local corruption; they are not independent signatures of upstream correctness.

**Rules disappeared after a firewall reload:** check whether another service flushes the whole ruleset. GeoLatch does not modify UFW/nftables/Docker configuration. Coordinate ordering and rerun an approved apply/restore, then test actual packets. Do not flush other tables to repair GeoLatch.

**Reboot restoration has no `all` addresses:** check the active network manager's wait-online service and selected interfaces. Boot restore needs the addresses to be ready. An offline `restore` unit test does not reproduce your actual boot timing.

**Lost connectivity after apply:** the timed watchdog should restore the preceding state unless you already confirmed. Use the provider console if necessary; see [security and recovery](security.md). If an installation/update failed, keep the error visible, repair the software installation, and verify `geolatch version` and `doctor` before applying.

**“The table is not owned by GeoLatch” after applying with an older nftables version:** nftables 1.0.x releases can retain table/chain comments in text while omitting them from JSON. GeoLatch 0.1.0 then falsely rejects its table; a pending rollback can fail for the same reason. GeoLatch 0.1.1 checks missing JSON comments through the validated textual listing, preserving both ownership and revision checks. A genuinely foreign table still causes refusal.

Download a current checkout/archive and run `sudo bash install.sh --repair` from that directory. Unlike a normal upgrade, explicit repair can handle a pending journal. It stages the new software, saves the candidate to `/etc/geolatch/recovered-draft.yaml`, and uses the fixed backend to restore the preceding firewall before switching releases. If validation or ownership fails, it preserves the journal and aborts. Do not delete the table or pending journal manually.

The reopened TUI loads your saved candidate as a draft. Review it through “Review and apply draft”, apply with rollback protection, test a new SSH connection, and confirm within the deadline. The recovery backup is removed after a successful explicit apply confirmation, and survives unattended updates. An older already-running TUI still has the old code in memory; close that session only after repair succeeds and use the newly launched program.
