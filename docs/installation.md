# Installation and software updates

The supported automatic install path is a checkout plus `sudo ./install.sh`. Ubuntu/Debian distribution packages supply Python, venv, nftables, iproute2, CA certificates and sudo. Python dependencies live under a versioned `/opt/geolatch/releases/…/venv`; system Python is never modified with pip.

The installer validates Linux, distribution, architecture, root rights, systemd and Python 3.10+. It builds a new release before switching `/opt/geolatch/current` atomically, and uses a root-owned `/usr/local/bin/geolatch` launcher with Python isolated mode. The installed application is not imported from the caller's current working directory or `PYTHONPATH`.

An installation lock prevents concurrent installs/removals. The previous release remains available if dependency installation fails. Old successful releases are kept for inspection; they can consume disk space and are removed by the uninstaller. Config, cache and confirmed state remain outside the release tree. A normal software update requires an unconfirmed apply to be resolved first. Explicit `--repair` can recover an interrupted apply with the newly staged backend, saving its candidate as `recovered-draft.yaml` before ownership-checked rollback; see [troubleshooting](troubleshooting.md).

```sh
git pull --ff-only
sudo ./install.sh
```

Review the fetched code before root installation. For automation use `--no-setup --upgrade` or `--no-setup --repair`. These options do not approve or apply firewall configuration. The interactive install opens the first-run wizard automatically, or the existing menu when a saved config is present. Use `--lang en|ru` for installer messages; the wizard still offers its language choice.

Installed units are registered and restore is enabled for boot without immediately applying firewall rules. The update timer is activated according to confirmed configuration. Existing unrelated nftables, UFW, Docker, routes, sysctls and interface settings are untouched.

Uninstall with `sudo ./uninstall.sh` or `sudo /opt/geolatch/current/uninstall.sh`. It stops GeoLatch work, removes only its own rules and program, then optionally deletes local data. `--yes` retains data; `--yes --purge` deletes it explicitly. If the installed command is broken or missing, repair before uninstalling so ownership-checked rule removal can run. Do not substitute a global firewall flush.
