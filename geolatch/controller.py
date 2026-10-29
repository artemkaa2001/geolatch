"""Shared application operations for the CLI and TUI.

The pending journal is durable *before* any kernel mutation. A separate session
waits for confirmation and restores the exact previous GeoLatch table on expiry.
Only confirmed snapshots are used for offline boot recovery.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .config import default_config, load_config, save_config, validate_config
from .firewall import generate_rules
from .geoip import GeoIPStore
from .networks import discover_addresses, resolve_destinations
from .nftables import Nftables
from .paths import Paths
from .statistics import aggregate_stats
from .utils import (
    atomic_write,
    durable_unlink,
    operation_lock,
    read_json,
    secure_directory,
    utc_now,
    write_json,
)


class OperationError(RuntimeError):
    def __init__(self, detail: str, key: str = "error.operation") -> None:
        super().__init__(detail)
        self.detail = detail
        self.key = key


def _digest(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _unavailable_traffic_stats() -> dict:
    # A failed read is unknown, never evidence that no source was blocked.
    # Keep raw nft output out of the public summary (it can contain source IPs).
    return {
        "unique_ips": None,
        "unique_limit_reached": False,
        "tracking_available": False,
        "dropped_packets": None,
        "dropped_bytes": None,
        "counter_error": "unavailable",
    }


def _write_snapshot(path: Path, data: dict) -> None:
    write_json(path, {"schema": 1, "sha256": _digest(data), "data": data})


def _read_snapshot(path: Path) -> dict | None:
    if not path.exists():
        return None
    value = read_json(path)
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise OperationError(f"Unsupported snapshot: {path}")
    data = value.get("data")
    if not isinstance(data, dict) or value.get("sha256") != _digest(data):
        raise OperationError(f"Snapshot integrity check failed: {path}")
    _validate_snapshot(data)
    return data


def _validate_snapshot(data: dict) -> None:
    data["config"] = validate_config(data.get("config"))
    if not isinstance(data.get("databases"), dict) or not isinstance(
        data.get("rules"), (str, type(None))
    ):
        raise OperationError("Invalid local firewall snapshot")
    for key, values in data["databases"].items():
        if (
            not isinstance(key, str)
            or re.fullmatch(r"[A-Z]{2}:[46]", key) is None
            or not isinstance(values, list)
        ):
            raise OperationError("Invalid local database snapshot")
        for value in values:
            network = ipaddress.ip_network(value, strict=True)
            if network.version != int(key[-1]) or network.prefixlen == 0:
                raise OperationError("Invalid local database network")


def _write_pending(path: Path, pending: dict) -> None:
    content = {key: value for key, value in pending.items() if key != "sha256"}
    write_json(path, {**content, "sha256": _digest(content)})


class Controller:
    def __init__(
        self,
        paths: Paths | None = None,
        *,
        nft: Any = None,
        store: Any = None,
        enforce_privileges: bool = True,
        arm_watchdog: Callable[[str], None] | None = None,
    ) -> None:
        self.paths = paths or Paths()
        self.nft = nft if nft is not None else Nftables()
        self.store = store if store is not None else GeoIPStore(self.paths.cache_dir)
        self.enforce_privileges = enforce_privileges
        self._watchdog_hook = arm_watchdog

    @property
    def needs_privileges(self) -> bool:
        return self.enforce_privileges and os.geteuid() != 0

    def _require_root(self) -> None:
        if self.needs_privileges:
            raise OperationError("Run this operation with sudo", "error.root_required")

    def config(self) -> dict:
        return load_config(self.paths.config_file)

    def recovered_draft(self) -> dict | None:
        if self.paths.recovered_draft.exists():
            return load_config(self.paths.recovered_draft)
        return None

    def repair_pending(self, lock_timeout: float = 120.0) -> dict:
        """Use the newly installed backend to undo an interrupted old apply.

        Preserve the user's candidate before journal removal. The next TUI
        session loads it as an unapplied draft, requiring a new safe apply.
        A foreign table or corrupt journal still aborts recovery without deletion.
        """
        self._require_root()
        with operation_lock(self.paths.state_dir, timeout=lock_timeout):
            if not self.paths.pending.exists():
                return {"recovered": False}
            pending = self._pending()
            save_config(pending["candidate"]["config"], self.paths.recovered_draft)
            result = self._recover_pending(pending)
            return {**result, "recovered": True, "draft_path": str(self.paths.recovered_draft)}

    def addresses(self) -> list[dict]:
        return discover_addresses()

    def _address_rows(self, config: dict) -> list[dict]:
        if config["enabled"] and any(
            policy["enabled"] and policy["destinations"] == "all" for policy in config["policies"]
        ):
            return self.addresses()
        return []

    def _event(self, action: str, **fields: Any) -> None:
        secure_directory(self.paths.state_dir, 0o755)
        path = self.paths.events
        if path.exists() and path.stat().st_size > 2 * 1024 * 1024:
            os.replace(path, path.with_suffix(".jsonl.1"))
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
            stream.write(
                json.dumps({"time": utc_now(), "event": action, **fields}, ensure_ascii=False)
                + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())

    def logs(self, limit: int = 100) -> list[dict]:
        try:
            with self.paths.events.open(encoding="utf-8") as stream:
                lines = stream.readlines()
            return [json.loads(line) for line in lines[-limit:]]
        except FileNotFoundError:
            return []

    def save_preferences(self, language: str) -> None:
        self._require_root()
        if language not in ("en", "ru"):
            raise OperationError("Unsupported language")
        with operation_lock(self.paths.state_dir):
            config = self.config()
            config["language"] = language
            save_config(config, self.paths.config_file)
            # Language is a display preference, including during a pending apply.
            # Keep both rollback candidates consistent with the chosen language.
            for path in (self.paths.confirmed, self.paths.previous):
                snapshot = _read_snapshot(path)
                if snapshot:
                    snapshot["config"]["language"] = language
                    _write_snapshot(path, snapshot)
            if self.paths.pending.exists():
                pending = self._pending()
                for key in ("before", "candidate"):
                    pending[key]["config"]["language"] = language
                _write_pending(self.paths.pending, pending)

    def plan(self, config: dict | None = None) -> dict:
        candidate = validate_config(config if config is not None else self.config())
        addresses = self._address_rows(candidate)
        destinations = resolve_destinations(candidate, addresses)
        result = {"config": candidate, "destinations": destinations, "dry_run": True}
        try:
            prepared = self.store.load(candidate)
            result["rules"] = (
                generate_rules(candidate, prepared["databases"], addresses)
                if candidate["enabled"]
                else None
            )
            result["needs_download"] = False
        except (ValueError, OSError, RuntimeError) as exc:
            result["needs_download"] = True
            result["cache_detail"] = str(exc)
        return result

    def _before(self) -> dict:
        previous = _read_snapshot(self.paths.confirmed)
        config = previous["config"] if previous else self.config()
        rules = self.nft.snapshot()
        return {
            "config": {**config, "enabled": rules is not None},
            "rules": rules,
            "databases": previous.get("databases", {}) if previous else {},
            "metadata": previous.get("metadata", {}) if previous else {},
            "destinations": previous.get("destinations", {}) if previous else {},
            "applied_at": previous.get("applied_at") if previous else None,
        }

    def _pending(self) -> dict:
        value = read_json(self.paths.pending)
        if (
            not isinstance(value, dict)
            or value.get("schema") != 1
            or not isinstance(value.get("token"), str)
            or re.fullmatch(r"[0-9a-f]{32}", value["token"]) is None
            or type(value.get("deadline")) not in (int, float)
            or not math.isfinite(value["deadline"])
            or not isinstance(value.get("before"), dict)
            or not isinstance(value.get("candidate"), dict)
        ):
            raise OperationError("Invalid pending rollback journal; inspect before continuing")
        content = {key: item for key, item in value.items() if key != "sha256"}
        if value.get("sha256") != _digest(content):
            raise OperationError("Pending rollback journal integrity check failed")
        _validate_snapshot(value["before"])
        _validate_snapshot(value["candidate"])
        return value

    def _assert_no_pending(self) -> None:
        if self.paths.pending.exists():
            pending = self._pending()
            if pending["deadline"] <= time.time():
                self._recover_pending(pending)
            else:
                raise OperationError("An apply awaits confirmation; confirm or rollback first")

    def _arm(self, token: str) -> None:
        if self._watchdog_hook is not None:
            self._watchdog_hook(token)
            return
        ready = self.paths.state_dir / f"watchdog-{token}.ready"
        args = [
            sys.executable,
            "-I",
            "-m",
            "geolatch",
            "--config",
            str(self.paths.config_file),
            "--state-dir",
            str(self.paths.state_dir),
            "--cache-dir",
            str(self.paths.cache_dir),
            "_watchdog",
            token,
        ]
        process = None
        unit = None
        if Path("/run/systemd/system").exists() and shutil.which("systemd-run"):
            # A separate unit survives the initiating service's cgroup teardown
            # and SSH session cleanup. setsid alone cannot provide that property.
            unit = f"geolatch-rollback-{token}"
            try:
                subprocess.run(
                    [
                        "systemd-run",
                        "--quiet",
                        "--collect",
                        f"--unit={unit}",
                        "--property=Type=exec",
                        "--property=Restart=on-failure",
                        "--property=RestartSec=1s",
                        "--property=RuntimeMaxSec=900",
                        *args,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=True,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise OperationError(
                    "Could not arm the independent systemd rollback service"
                ) from exc
        else:
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                cwd="/",
            )
        until = time.monotonic() + 8
        while time.monotonic() < until:
            if ready.exists():
                if self._pending()["token"] != token:
                    if process is not None:
                        process.terminate()
                    raise OperationError("Rollback journal changed before the watchdog was ready")
                durable_unlink(ready)
                return
            if process is not None and process.poll() is not None:
                break
            time.sleep(0.025)
        if process is not None:
            process.terminate()
        elif unit is not None:
            subprocess.run(
                ["systemctl", "stop", unit], capture_output=True, timeout=15, check=False
            )
        raise OperationError("Independent rollback watchdog failed to start; no rules were applied")

    def _verify(self, snapshot: dict) -> None:
        actual = self.nft.inspect()
        if (actual is not None) != (snapshot["rules"] is not None):
            raise OperationError("Kernel state does not match requested firewall state")
        if actual is not None and snapshot["rules"] is not None:
            revision = re.search(
                r'\bcomment\s+"(geolatch-revision:[0-9a-f]{64})"', snapshot["rules"]
            )
            if revision:
                chains = [
                    item.get("chain", {})
                    for item in actual.get("nftables", [])
                    if isinstance(item, dict)
                ]
                if not any(
                    chain.get("name") == "prerouting" and chain.get("comment") == revision[1]
                    for chain in chains
                ):
                    raise OperationError(
                        "The kernel firewall revision differs from the expected confirmed state"
                    )

    def _publish_status(self, snapshot: dict) -> None:
        write_json(
            self.paths.state_dir / "status.json",
            {
                "configured": True,
                "source": snapshot["config"]["source"],
                "policies": snapshot["config"]["policies"],
                "destinations": snapshot.get("destinations", {}),
                "metadata": snapshot.get("metadata", {}),
                "last_applied": snapshot.get("applied_at"),
                "cidr_count": sum(len(values) for values in snapshot["databases"].values()),
            },
            0o644,
        )

    def _commit(self, pending: dict) -> dict:
        self._verify(pending["candidate"])
        _write_snapshot(self.paths.previous, pending["before"])
        _write_snapshot(self.paths.confirmed, pending["candidate"])
        save_config(pending["candidate"]["config"], self.paths.config_file)
        self._publish_status(pending["candidate"])
        # Journal removal is the commit point. A crash before this point is
        # deliberately treated as unconfirmed, even if a snapshot was written.
        self._event("confirmed", source=pending["candidate"]["config"]["source"])
        durable_unlink(self.paths.pending)
        if pending.get("clear_recovered_draft", False):
            durable_unlink(self.paths.recovered_draft)
        warnings = self._sync_timer(pending["candidate"]["config"])
        return {"pending": False, "confirmed": True, "warnings": warnings}

    def _recover_pending(self, pending: dict) -> dict:
        before = pending["before"]
        self.nft.apply(before["rules"])
        self._verify(before)
        _write_snapshot(self.paths.confirmed, before)
        save_config(before["config"], self.paths.config_file)
        self._publish_status(before)
        self._event("rollback", reason="unconfirmed")
        durable_unlink(self.paths.pending)
        warnings = self._sync_timer(before["config"])
        return {"pending": False, "rolled_back": True, "warnings": warnings}

    def _transaction(
        self, candidate: dict, *, safe: bool, timeout: int = 90, clear_recovered_draft: bool = False
    ) -> dict:
        self._assert_no_pending()
        if not 30 <= timeout <= 600:
            raise OperationError("Rollback timeout must be between 30 and 600 seconds")
        if candidate["rules"] is not None:
            self.nft.check(candidate["rules"])
        before = self._before()
        token = secrets.token_hex(16)
        pending = {
            "schema": 1,
            "token": token,
            "deadline": time.time() + timeout,
            "before": before,
            "candidate": candidate,
            "clear_recovered_draft": clear_recovered_draft,
        }
        _write_pending(self.paths.pending, pending)
        try:
            self._arm(token)
        except BaseException:
            durable_unlink(self.paths.pending)
            raise
        try:
            self.nft.apply(candidate["rules"])
            self._verify(candidate)
            self._event("applied", pending=safe)
            if not safe:
                return self._commit(pending)
        except BaseException:
            # Keep the journal if restoration itself fails: the independent
            # watchdog keeps retrying and the next boot takes the same path.
            self._recover_pending(pending)
            raise
        return {
            "pending": True,
            "token": token,
            "deadline": pending["deadline"],
            "timeout": timeout,
        }

    def apply(
        self,
        config: dict | None = None,
        safe: bool = True,
        force: bool = False,
        timeout: int = 90,
        clear_recovered_draft: bool = True,
    ) -> dict:
        self._require_root()
        with operation_lock(self.paths.state_dir):
            self._assert_no_pending()
            candidate = validate_config(config if config is not None else self.config())
            try:
                prepared = (
                    self.store.prepare(candidate, force=force)
                    if candidate["enabled"]
                    else {"databases": {}, "metadata": {}, "changed": False}
                )
                addresses = self._address_rows(candidate)
                snapshot = {
                    "config": candidate,
                    "databases": prepared["databases"],
                    "metadata": prepared["metadata"],
                    "rules": generate_rules(candidate, prepared["databases"], addresses)
                    if candidate["enabled"]
                    else None,
                    "destinations": resolve_destinations(candidate, addresses),
                    "applied_at": utc_now(),
                }
                return self._transaction(
                    snapshot,
                    safe=safe,
                    timeout=timeout,
                    clear_recovered_draft=clear_recovered_draft,
                )
            except (ValueError, OSError, RuntimeError) as exc:
                self._event("apply_failed", detail=str(exc)[:2000])
                raise

    def confirm(self, token: str) -> dict:
        self._require_root()
        with operation_lock(self.paths.state_dir):
            if not self.paths.pending.exists():
                raise OperationError("No change is awaiting confirmation")
            pending = self._pending()
            if not secrets.compare_digest(pending["token"], token):
                raise OperationError("Confirmation token does not match")
            if time.time() >= pending["deadline"]:
                self._recover_pending(pending)
                raise OperationError("Confirmation expired; previous firewall restored")
            return self._commit(pending)

    def rollback(self) -> dict:
        self._require_root()
        with operation_lock(self.paths.state_dir):
            if self.paths.pending.exists():
                return self._recover_pending(self._pending())
            previous = _read_snapshot(self.paths.previous)
            if previous is None:
                raise OperationError("No previous confirmed snapshot is available")
            return self._transaction(previous, safe=False)

    def disable(self) -> dict:
        self._require_root()
        confirmed = _read_snapshot(self.paths.confirmed)
        if confirmed:
            candidate = confirmed["config"]
        else:
            try:
                candidate = self.config()
            except ValueError:
                candidate = default_config()
        candidate["enabled"] = False
        return self.apply(candidate, safe=False, clear_recovered_draft=False)

    def enable(self, safe: bool = True) -> dict:
        candidate = self.config()
        candidate["enabled"] = True
        return self.apply(candidate, safe=safe, clear_recovered_draft=False)

    def update(self, dry_run: bool = False, force: bool = False) -> dict:
        if dry_run:
            # A true dry run does not fetch or mutate the validated cache.
            return self.plan()
        self._require_root()
        with operation_lock(self.paths.state_dir):
            self._assert_no_pending()
            # Editing YAML is not an implicit unattended policy deployment.
            confirmed = _read_snapshot(self.paths.confirmed)
            if confirmed is None:
                raise OperationError("Apply and confirm a configuration before updating")
            config = confirmed["config"]
            if not config["enabled"]:
                return {"changed": False, "disabled": True}
            try:
                prepared = self.store.prepare(config, force=force)
                addresses = self._address_rows(config)
                rules = generate_rules(config, prepared["databases"], addresses)
                snapshot = {
                    "config": config,
                    "rules": rules,
                    "databases": prepared["databases"],
                    "metadata": prepared["metadata"],
                    "destinations": resolve_destinations(config, addresses),
                    "applied_at": utc_now(),
                }
                current_matches = False
                if rules == confirmed["rules"] and not force:
                    try:
                        self._verify(confirmed)
                        current_matches = True
                    except (ValueError, RuntimeError):
                        pass
                if current_matches:
                    # Preserve counters when upstream data has not changed.
                    confirmed["metadata"] = prepared["metadata"]
                    _write_snapshot(self.paths.confirmed, confirmed)
                    self._publish_status(confirmed)
                    self._event("update_unchanged")
                    return {"changed": False}
                result = self._transaction(snapshot, safe=False, timeout=180)
                self._event("updated", source=config["source"])
                return {**result, "changed": True}
            except (ValueError, OSError, RuntimeError) as exc:
                self._event("update_failed", detail=str(exc)[:2000])
                raise

    def restore(self) -> dict:
        self._require_root()
        with operation_lock(self.paths.state_dir):
            # Any unconfirmed transaction, including one interrupted by reboot,
            # is first restored to its before image without consulting upstream.
            rolled_back = False
            if self.paths.pending.exists():
                self._recover_pending(self._pending())
                rolled_back = True
            snapshot = _read_snapshot(self.paths.confirmed)
            if snapshot is None:
                return {"restored": False, "reason": "not_configured"}
            config = snapshot["config"]
            addresses = self._address_rows(config)
            rules = (
                generate_rules(config, snapshot["databases"], addresses)
                if config["enabled"]
                else None
            )
            if rules is not None:
                self.nft.check(rules)
            self.nft.apply(rules)
            snapshot["rules"] = rules
            snapshot["destinations"] = resolve_destinations(config, addresses)
            self._verify(snapshot)
            _write_snapshot(self.paths.confirmed, snapshot)
            self._publish_status(snapshot)
            self._event("restored")
            result = {"restored": True}
            if rolled_back:
                result["rolled_back"] = True
            return result

    def traffic_stats(self) -> dict:
        """Read live traffic totals without privilege prompts or state writes."""
        return self._traffic_stats()

    def _traffic_stats(self, actual: Any = ...) -> dict:
        try:
            reader = getattr(self.nft, "traffic_stats", None)
            if callable(reader):
                return reader() if actual is ... else reader(table=actual)
            # Injected backends can provide only the normal inspection boundary.
            return aggregate_stats(self.nft.inspect() if actual is ... else actual)
        except (ValueError, OSError, RuntimeError):
            return _unavailable_traffic_stats()

    def status(self) -> dict:
        config = self.config()
        actual = None
        query_error = None
        try:
            actual = self.nft.inspect()
            active: bool | None = actual is not None
        except (ValueError, OSError, RuntimeError) as exc:
            active = None
            query_error = str(exc)
        traffic_stats = (
            _unavailable_traffic_stats() if active is None else self._traffic_stats(actual)
        )
        snapshot = None
        cached = {}
        snapshot_invalid = False
        try:
            snapshot = _read_snapshot(self.paths.confirmed)
        except (PermissionError, ValueError, RuntimeError) as exc:
            if isinstance(exc, PermissionError):
                with contextlib.suppress(OSError, ValueError):
                    cached = read_json(self.paths.state_dir / "status.json", limit=2 * 1024 * 1024)
            else:
                query_error = query_error or str(exc)
                snapshot_invalid = True
        counters = []
        if active:
            with contextlib.suppress(ValueError, OSError, RuntimeError):
                counters = self.nft.counters()
        timer = self._timer_state()
        return {
            "active": active,
            "kernel_query_error": query_error,
            "configured": snapshot is not None or cached.get("configured", False),
            "source": snapshot["config"]["source"]
            if snapshot
            else cached.get("source", config["source"]),
            "policies": snapshot["config"]["policies"]
            if snapshot
            else cached.get("policies", config["policies"]),
            "destinations": snapshot.get("destinations", {})
            if snapshot
            else cached.get("destinations", {}),
            "metadata": snapshot.get("metadata", {}) if snapshot else cached.get("metadata", {}),
            "cidr_count": sum(len(v) for v in snapshot["databases"].values())
            if snapshot
            else cached.get("cidr_count", 0),
            "last_applied": snapshot.get("applied_at") if snapshot else cached.get("last_applied"),
            "cached_summary": bool(cached),
            "geoip_health": "healthy"
            if snapshot
            else "cached"
            if cached
            else "invalid"
            if snapshot_invalid
            else "unconfigured",
            "pending": self.paths.pending.exists(),
            "timer": timer,
            "counters": counters,
            "traffic_stats": traffic_stats,
        }

    def _timer_state(self) -> str:
        if not shutil.which("systemctl") or not Path("/run/systemd/system").exists():
            return "unavailable"
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "geolatch-update.timer"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return "unknown"
        return result.stdout.strip() or "unknown"

    def _sync_timer(self, config: dict) -> list[str]:
        if self.paths != Paths() or not Path("/run/systemd/system").exists():
            return ["systemd_unavailable"]
        if not shutil.which("systemctl"):
            return ["systemd_unavailable"]
        try:
            override = Path("/etc/systemd/system/geolatch-update.timer.d/schedule.conf")
            interval = config["updates"]["interval"]
            schedule = f"[Timer]\nOnCalendar=\nOnCalendar={interval}\n"
            if not override.exists() or override.read_text(encoding="utf-8") != schedule:
                atomic_write(override, schedule, 0o644)
            subprocess.run(
                ["systemctl", "daemon-reload"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            action = "enable" if config["enabled"] and config["updates"]["enabled"] else "disable"
            subprocess.run(
                ["systemctl", action, "--now", "geolatch-update.timer"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            return []
        except (OSError, subprocess.SubprocessError) as exc:
            self._event("timer_failed", detail=str(exc)[:1000])
            return ["systemd_timer_failed"]

    def doctor(self) -> dict:
        import platform

        checks = {
            "kernel": platform.release(),
            "platform": platform.system(),
            "root": os.geteuid() == 0,
            "nft": shutil.which("nft"),
            "ip": shutil.which("ip"),
            "systemd": Path("/run/systemd/system").exists(),
        }
        try:
            with Path("/proc/self/status").open(encoding="ascii") as stream:
                effective = next(line.split()[1] for line in stream if line.startswith("CapEff:"))
            checks["cap_net_admin"] = bool(int(effective, 16) & (1 << 12))
        except (OSError, ValueError, StopIteration):
            checks["cap_net_admin"] = None
        checks["ipv6"] = Path("/proc/net/if_inet6").exists()
        if checks["nft"]:
            try:
                result = subprocess.run(
                    [checks["nft"], "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                checks["nft_version"] = result.stdout.strip() if result.returncode == 0 else None
            except (OSError, subprocess.SubprocessError):
                checks["nft_version"] = None
        try:
            config = self.config()
            checks["config"] = "valid"
            checks["addresses"] = self.addresses()
            checks["destinations"] = resolve_destinations(config)
            try:
                cached = self.store.load(config)
                checks["cache"] = {"healthy": True, "metadata": cached["metadata"]}
            except (OSError, ValueError, RuntimeError) as exc:
                checks["cache"] = {"healthy": False, "detail": str(exc)}
        except (OSError, ValueError, RuntimeError) as exc:
            checks["config"] = str(exc)
        try:
            checks["status"] = self.status()
        except (OSError, ValueError, RuntimeError) as exc:
            checks["status"] = {"active": None, "kernel_query_error": str(exc)}
        checks["warnings"] = [
            "notrack_requires_review",
            "nonstandard_hook_priorities_require_review",
            "firewall_reload_can_remove_geolatch_table",
        ]
        return checks

    def check_ip(self, source: str, destination: str, interface: str | None = None) -> dict:
        src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
        if src.version != dst.version:
            raise OperationError("Source and destination address families differ")
        try:
            snapshot = _read_snapshot(self.paths.confirmed)
        except PermissionError as exc:
            raise OperationError(
                "Run check-ip with sudo to read the private confirmed database",
                "error.root_required",
            ) from exc
        if snapshot is None:
            raise OperationError("No confirmed configuration")
        config = snapshot["config"]
        allowed = any(
            src in ipaddress.ip_network(network)
            for network in config["allowlist"][f"ipv{src.version}"]
        )
        hits: set[str] = set()
        for policy in config["policies"]:
            destinations = snapshot.get("destinations", {}).get(policy["name"], [])
            if not policy["enabled"] or str(dst) not in destinations:
                continue
            for country in policy["block_countries"]:
                if any(
                    src in ipaddress.ip_network(net)
                    for net in snapshot["databases"].get(f"{country}:{src.version}", [])
                ):
                    hits.add(country)
        interface_match = interface is None or interface in config["network"]["interfaces"]
        return {
            "source": str(src),
            "destination": str(dst),
            "countries": sorted(hits),
            "allowlisted": allowed,
            "blocked": config["enabled"] and interface_match and bool(hits) and not allowed,
            "prediction_only": True,
            "assumes_new_original_direction": True,
            "interfaces": config["network"]["interfaces"],
            "actual_status": self.status()["active"],
        }

    def run_privileged(self, operation: str, payload: dict | None = None) -> dict:
        """TUI calls this while Textual's terminal is suspended for sudo."""
        allowed = {
            "apply",
            "confirm",
            "rollback",
            "update",
            "disable",
            "enable",
            "preferences",
            "restore",
        }
        if operation not in allowed:
            raise OperationError("Unsupported privileged operation")
        if not self.needs_privileges:
            return self.operate(operation, payload or {})
        executable = Path("/usr/local/bin/geolatch")
        info = executable.stat()
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise OperationError(
                "GeoLatch launcher must be owned by root and not writable by other users"
            )
        descriptor, name = tempfile.mkstemp(prefix="geolatch-draft-", suffix=".json")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload or {}, stream)
            result = subprocess.run(
                [
                    "sudo",
                    "--",
                    str(executable),
                    "--config",
                    str(self.paths.config_file),
                    "--state-dir",
                    str(self.paths.state_dir),
                    "--cache-dir",
                    str(self.paths.cache_dir),
                    "--json",
                    "_operate",
                    operation,
                    "--payload",
                    name,
                ],
                stdout=subprocess.PIPE,
                text=True,
                check=False,
            )
            if result.returncode:
                try:
                    detail = json.loads(result.stdout).get("detail", "Privileged operation failed")
                except ValueError:
                    detail = "Privileged operation failed"
                raise OperationError(detail)
            return json.loads(result.stdout)
        finally:
            Path(name).unlink(missing_ok=True)

    def operate(self, operation: str, payload: dict) -> dict:
        if operation == "apply":
            config = payload.get("config", payload)
            return self.apply(config=config, safe=True)
        if operation == "confirm":
            return self.confirm(payload["token"])
        if operation == "preferences":
            self.save_preferences(payload["language"])
            return {"language": payload["language"]}
        if operation == "update":
            return self.update(
                dry_run=bool(payload.get("dry_run", False)), force=bool(payload.get("force", False))
            )
        if operation in {"rollback", "disable", "enable", "restore"}:
            return getattr(self, operation)()
        raise OperationError("Unsupported privileged operation")
