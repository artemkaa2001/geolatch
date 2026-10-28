"""Offline transaction tests with real journals and injected kernel/download IO.

These exercise crash/confirmation state handling, not netfilter semantics. Every
path is beneath pytest's temporary directory; no host firewall is touched.
"""

from __future__ import annotations

import copy
import json
import re

import pytest

from geolatch.config import default_config, load_config, save_config
from geolatch.controller import Controller, OperationError, _read_snapshot, _write_pending
from geolatch.firewall import generate_rules
from geolatch.nftables import OWNER, NftError
from geolatch.paths import Paths
from geolatch.utils import operation_lock


class Kernel:
    """Injected stateful IO boundary. This never invokes an nft executable."""

    def __init__(self):
        self.rules = None
        self.checked = []
        self.applied = []
        self.fail_check = False
        self.fail_next_apply = False
        self.fail_next_query = False

    def inspect(self):
        if self.fail_next_query:
            self.fail_next_query = False
            raise NftError("kernel query failed")
        if self.rules is None:
            return None
        revision = re.search(r'comment "(geolatch-revision:[0-9a-f]{64})"', self.rules)
        entries = [{"table": {"family": "inet", "name": "geolatch", "comment": OWNER}}]
        if revision:
            entries.append({"chain": {"name": "prerouting", "comment": revision[1]}})
        return {"nftables": entries}

    def check(self, rules):
        self.checked.append(rules)
        if self.fail_check:
            raise NftError("candidate rules rejected")

    def apply(self, rules):
        self.applied.append(rules)
        if self.fail_next_apply:
            self.fail_next_apply = False
            raise NftError("atomic transaction rejected")
        self.rules = rules

    def snapshot(self):
        return self.rules

    def counters(self):
        return []


class Store:
    def __init__(self):
        self.databases = {"IR:4": ["198.51.100.0/24"], "CN:4": ["192.0.2.0/24"]}
        self.prepared = []
        self.loaded = []
        self.fail_prepare = False

    def _result(self, config):
        countries = {
            code
            for policy in config["policies"]
            if policy["enabled"]
            for code in policy["block_countries"]
        }
        return {
            "databases": {
                key: copy.deepcopy(value)
                for key, value in self.databases.items()
                if key.split(":")[0] in countries
            },
            "metadata": {"source": config["source"], "updated_at": "2026-10-28T00:00:00Z"},
            "changed": True,
        }

    def prepare(self, config, force=False):
        self.prepared.append(copy.deepcopy(config))
        if self.fail_prepare:
            raise ValueError("download rejected")
        return self._result(config)

    def load(self, config):
        self.loaded.append(copy.deepcopy(config))
        return self._result(config)


@pytest.fixture
def candidate():
    config = default_config()
    config["network"].update({"interfaces": ["eth0"], "ipv6": False})
    config["policies"] = [
        {
            "name": "primary",
            "enabled": True,
            "destinations": ["203.0.113.10"],
            "block_countries": ["IR"],
        }
    ]
    return config


@pytest.fixture
def controller(tmp_path):
    paths = Paths(tmp_path / "etc" / "config.yaml", tmp_path / "state", tmp_path / "cache")
    save_config(default_config(), paths.config_file)
    kernel, store = Kernel(), Store()
    ctl = Controller(
        paths, nft=kernel, store=store, enforce_privileges=False, arm_watchdog=lambda token: None
    )
    ctl._sync_timer = lambda config: []
    ctl._timer_state = lambda: "inactive"
    return ctl


def test_manual_apply_requires_explicit_confirmation(controller, candidate):
    original = controller.paths.config_file.read_bytes()
    staged = controller.apply(candidate)
    assert staged["pending"] and len(staged["token"]) == 32
    assert controller.paths.pending.exists()
    assert controller.nft.rules == generate_rules(candidate, {"IR:4": ["198.51.100.0/24"]})
    assert controller.paths.config_file.read_bytes() == original
    assert not controller.paths.confirmed.exists()
    assert not controller.paths.previous.exists()
    result = controller.confirm(staged["token"])
    assert result["confirmed"] and not result["pending"]
    assert not controller.paths.pending.exists()
    assert load_config(controller.paths.config_file) == candidate
    assert _read_snapshot(controller.paths.confirmed)["config"] == candidate
    assert _read_snapshot(controller.paths.previous)["rules"] is None


def test_journal_is_durable_before_watchdog_or_kernel_mutation(controller, candidate):
    def arm(token):
        assert controller.paths.pending.is_file()
        pending = controller._pending()
        assert pending["token"] == token
        assert pending["before"]["rules"] is None
        assert pending["candidate"]["config"] == candidate
        assert not controller.nft.applied

    controller._watchdog_hook = arm
    controller.apply(candidate)


def test_wrong_token_never_commits_or_disarms_pending_change(controller, candidate):
    staged = controller.apply(candidate)
    rules = controller.nft.rules
    with pytest.raises(OperationError, match="token"):
        controller.confirm("0" * 32)
    assert controller.paths.pending.exists() and controller.nft.rules == rules
    assert not controller.paths.confirmed.exists()
    controller.confirm(staged["token"])


def test_expired_confirmation_restores_previous_state(controller, candidate, monkeypatch):
    staged = controller.apply(candidate)
    monkeypatch.setattr("geolatch.controller.time.time", lambda: staged["deadline"] + 1)
    with pytest.raises(OperationError, match="expired"):
        controller.confirm(staged["token"])
    assert controller.nft.rules is None
    assert not controller.paths.pending.exists()
    assert load_config(controller.paths.config_file)["enabled"] is False
    assert _read_snapshot(controller.paths.confirmed)["rules"] is None


def test_failed_watchdog_start_prevents_any_kernel_change(controller, candidate):
    def fail(token):
        raise OperationError("watchdog unavailable")

    controller._watchdog_hook = fail
    original = controller.paths.config_file.read_bytes()
    with pytest.raises(OperationError, match="watchdog"):
        controller.apply(candidate)
    assert not controller.nft.applied
    assert not controller.paths.pending.exists()
    assert not controller.paths.confirmed.exists()
    assert controller.paths.config_file.read_bytes() == original


def test_failed_nft_check_never_creates_a_pending_transaction(controller, candidate):
    controller.nft.fail_check = True
    with pytest.raises(NftError, match="rejected"):
        controller.apply(candidate)
    assert not controller.nft.applied
    assert not controller.paths.pending.exists()
    assert not controller.paths.confirmed.exists()


def test_rejected_atomic_apply_restores_before_image(controller, candidate):
    controller.apply(candidate, safe=False)
    before_rules = controller.nft.rules
    before_config = controller.config()
    candidate["policies"][0]["block_countries"] = ["CN"]
    controller.nft.fail_next_apply = True
    with pytest.raises(NftError, match="rejected"):
        controller.apply(candidate)
    assert controller.nft.rules == before_rules
    assert controller.config() == before_config
    assert _read_snapshot(controller.paths.confirmed)["config"] == before_config
    assert not controller.paths.pending.exists()


def test_failed_download_preserves_confirmed_snapshot_and_live_rules(controller, candidate):
    controller.apply(candidate, safe=False)
    confirmed = controller.paths.confirmed.read_bytes()
    previous = controller.paths.previous.read_bytes()
    config = controller.paths.config_file.read_bytes()
    rules = controller.nft.rules
    writes = len(controller.nft.applied)
    controller.store.fail_prepare = True
    with pytest.raises(ValueError, match="download"):
        controller.update()
    assert controller.paths.confirmed.read_bytes() == confirmed
    assert controller.paths.previous.read_bytes() == previous
    assert controller.paths.config_file.read_bytes() == config
    assert controller.nft.rules == rules and len(controller.nft.applied) == writes
    assert not controller.paths.pending.exists()


def test_concurrent_mutation_is_rejected_before_download(controller, candidate):
    with operation_lock(controller.paths.state_dir):
        with pytest.raises(RuntimeError, match="Another GeoLatch"):
            controller.apply(candidate)
    assert not controller.store.prepared and not controller.nft.applied


def test_another_apply_cannot_replace_an_unconfirmed_transaction(controller, candidate):
    first = controller.apply(candidate)
    candidate["policies"][0]["block_countries"] = ["CN"]
    with pytest.raises(OperationError, match="awaits confirmation"):
        controller.apply(candidate)
    assert controller._pending()["token"] == first["token"]
    assert len(controller.store.prepared) == 1


def test_manual_rollback_of_pending_change_restores_previous_state(controller, candidate):
    controller.apply(candidate, safe=False)
    rules = controller.nft.rules
    candidate["policies"][0]["block_countries"] = ["CN"]
    controller.apply(candidate)
    result = controller.rollback()
    assert result["rolled_back"]
    assert controller.nft.rules == rules
    assert controller.config()["policies"][0]["block_countries"] == ["IR"]
    assert not controller.paths.pending.exists()


def test_rollback_can_switch_between_previous_confirmed_configurations(controller, candidate):
    controller.apply(candidate, safe=False)
    first = controller.nft.rules
    candidate["policies"][0]["block_countries"] = ["CN"]
    controller.apply(candidate, safe=False)
    second = controller.nft.rules
    controller.rollback()
    assert controller.nft.rules == first
    controller.rollback()
    assert controller.nft.rules == second


def test_restore_uses_only_confirmed_local_database(controller, candidate):
    controller.apply(candidate, safe=False)
    before = controller.nft.rules
    candidate["policies"][0]["block_countries"] = ["CN"]
    save_config(candidate, controller.paths.config_file)
    controller.nft.rules = None
    controller.store.fail_prepare = True
    prepared_count = len(controller.store.prepared)
    assert controller.restore()["restored"]
    assert controller.nft.rules == before
    assert len(controller.store.prepared) == prepared_count


def test_restore_after_interrupted_transaction_uses_before_image(controller, candidate):
    controller.apply(candidate, safe=False)
    before = controller.nft.rules
    candidate["policies"][0]["block_countries"] = ["CN"]
    controller.apply(candidate)
    controller.nft.rules = None  # Simulate the empty firewall after reboot.
    controller.store.fail_prepare = True
    assert controller.restore()["rolled_back"]
    assert controller.nft.rules == before
    assert controller.config()["policies"][0]["block_countries"] == ["IR"]


def test_restore_of_unconfigured_system_does_not_create_rules(controller):
    assert controller.restore() == {"restored": False, "reason": "not_configured"}
    assert not controller.nft.applied


def test_snapshot_integrity_failure_is_rejected_without_kernel_changes(controller, candidate):
    controller.apply(candidate, safe=False)
    writes = len(controller.nft.applied)
    value = json.loads(controller.paths.confirmed.read_text())
    value["data"]["config"]["language"] = "ru"
    controller.paths.confirmed.write_text(json.dumps(value))
    with pytest.raises(OperationError, match="integrity"):
        controller.restore()
    assert len(controller.nft.applied) == writes


def test_disable_and_enable_persist_state_and_disabled_update_does_not_download(
    controller, candidate
):
    controller.apply(candidate, safe=False)
    controller.disable()
    assert controller.nft.rules is None and controller.config()["enabled"] is False
    count = len(controller.store.prepared)
    assert controller.update()["disabled"]
    assert len(controller.store.prepared) == count
    staged = controller.enable()
    assert staged["pending"]
    controller.confirm(staged["token"])
    assert controller.config()["enabled"] and controller.nft.rules is not None


def test_update_uses_confirmed_policy_instead_of_unapplied_yaml_edits(controller, candidate):
    controller.apply(candidate, safe=False)
    candidate["policies"][0]["block_countries"] = ["CN"]
    save_config(candidate, controller.paths.config_file)
    controller.update()
    assert controller.store.prepared[-1]["policies"][0]["block_countries"] == ["IR"]
    assert _read_snapshot(controller.paths.confirmed)["config"]["policies"][0][
        "block_countries"
    ] == ["IR"]


def test_unchanged_update_preserves_counters_by_skipping_kernel_reload(controller, candidate):
    controller.apply(candidate, safe=False)
    writes = len(controller.nft.applied)
    assert controller.update()["changed"] is False
    assert len(controller.nft.applied) == writes


def test_changed_database_is_applied_as_confirmed_update(controller, candidate):
    controller.apply(candidate, safe=False)
    old = controller.nft.rules
    controller.store.databases["IR:4"] = ["198.51.100.0/25"]
    assert controller.update()["changed"]
    assert controller.nft.rules != old
    assert _read_snapshot(controller.paths.previous)["rules"] == old
    assert not controller.paths.pending.exists()


def test_dry_run_does_not_download_create_journals_or_change_kernel(controller, candidate):
    save_config(candidate, controller.paths.config_file)
    original = controller.paths.config_file.read_bytes()
    result = controller.update(dry_run=True)
    assert result["dry_run"]
    assert not controller.store.prepared and not controller.nft.applied
    assert not controller.paths.state_dir.exists()
    assert controller.paths.config_file.read_bytes() == original


def test_language_change_keeps_pending_and_rollback_preferences_consistent(controller, candidate):
    staged = controller.apply(candidate)
    rules = controller.nft.rules
    controller.save_preferences("ru")
    pending = controller._pending()
    assert pending["before"]["config"]["language"] == "ru"
    assert pending["candidate"]["config"]["language"] == "ru"
    assert controller.nft.rules == rules
    controller.confirm(staged["token"])
    assert controller.config()["language"] == "ru"
    controller.rollback()
    assert controller.config()["language"] == "ru"


def test_confirm_rejects_external_owned_table_revision_change(controller, candidate):
    staged = controller.apply(candidate)
    changed = copy.deepcopy(candidate)
    changed["policies"][0]["block_countries"] = ["CN"]
    controller.nft.rules = generate_rules(changed, {"CN:4": ["192.0.2.0/24"]})
    with pytest.raises(OperationError, match="revision|match"):
        controller.confirm(staged["token"])
    assert controller.paths.pending.exists()
    assert not controller.paths.confirmed.exists()


def test_unchanged_database_still_repairs_external_ruleset_drift(controller, candidate):
    controller.apply(candidate, safe=False)
    expected = controller.nft.rules
    changed = copy.deepcopy(candidate)
    changed["policies"][0]["block_countries"] = ["CN"]
    controller.nft.rules = generate_rules(changed, {"CN:4": ["192.0.2.0/24"]})
    assert controller.update()["changed"]
    assert controller.nft.rules == expected


def test_corrupt_pending_journal_is_never_used_for_restoration(controller, candidate):
    controller.apply(candidate)
    writes = len(controller.nft.applied)
    pending = json.loads(controller.paths.pending.read_text())
    pending["before"]["rules"] = 'table inet geolatch { comment "modified" }'
    controller.paths.pending.write_text(json.dumps(pending))
    with pytest.raises(OperationError, match="integrity"):
        controller.restore()
    assert len(controller.nft.applied) == writes
    assert controller.paths.pending.exists()


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), True])
def test_nonfinite_or_boolean_deadline_cannot_disable_watchdog(controller, candidate, deadline):
    controller.apply(candidate)
    pending = controller._pending()
    pending["deadline"] = deadline
    _write_pending(controller.paths.pending, pending)
    writes = len(controller.nft.applied)
    with pytest.raises(OperationError, match="Invalid pending"):
        controller.restore()
    assert len(controller.nft.applied) == writes


def test_watchdog_expiry_restores_without_parent_confirmation(controller, candidate, monkeypatch):
    from geolatch import rollback

    staged = controller.apply(candidate)
    clock = [staged["deadline"] - 1]
    monkeypatch.setattr(rollback.signal, "signal", lambda *args: None)
    monkeypatch.setattr(rollback.time, "time", lambda: clock[0])
    monkeypatch.setattr(
        rollback.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds)
    )
    assert rollback.watchdog(controller, staged["token"]) == 0
    assert controller.nft.rules is None
    assert not controller.paths.pending.exists()


def test_watchdog_retries_recovery_failure_without_erasing_journal(
    controller, candidate, monkeypatch
):
    from geolatch import rollback

    staged = controller.apply(candidate)
    clock = [staged["deadline"] + 1]
    controller.nft.fail_next_apply = True
    monkeypatch.setattr(rollback.signal, "signal", lambda *args: None)
    monkeypatch.setattr(rollback.time, "time", lambda: clock[0])

    def advance(seconds):
        # The first failed kernel transaction must leave a retriable journal.
        assert controller.paths.pending.exists()
        clock[0] += seconds

    monkeypatch.setattr(rollback.time, "sleep", advance)
    assert rollback.watchdog(controller, staged["token"]) == 0
    assert controller.nft.rules is None and not controller.paths.pending.exists()
    assert controller.nft.applied[-2:] == [None, None]


def test_watchdog_for_an_old_token_never_reverts_a_new_transaction(
    controller, candidate, monkeypatch
):
    from geolatch import rollback

    staged = controller.apply(candidate)
    monkeypatch.setattr(rollback.signal, "signal", lambda *args: None)
    assert rollback.watchdog(controller, "0" * 32) == 1
    assert controller._pending()["token"] == staged["token"]
    assert len(controller.nft.applied) == 1
