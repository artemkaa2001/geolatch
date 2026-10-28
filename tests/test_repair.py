"""Recover a pending transaction without discarding the user's proposed policy.

The kernel/download boundaries are explicit filesystem-independent test doubles.
Every persisted file lives in pytest's temporary directory; these tests never
invoke nftables, sudo, systemd or a real watchdog.
"""

from __future__ import annotations

import copy
import json
import threading
from types import SimpleNamespace

import pytest
from test_controller import Kernel, Store

from geolatch.config import default_config, load_config, save_config
from geolatch.controller import Controller, OperationError, _read_snapshot, _write_pending
from geolatch.nftables import NftError
from geolatch.paths import Paths
from geolatch.utils import operation_lock


@pytest.fixture
def interrupted(tmp_path):
    paths = Paths(tmp_path / "etc" / "config.yaml", tmp_path / "state", tmp_path / "cache")
    save_config(default_config(), paths.config_file)
    controller = Controller(
        paths,
        nft=Kernel(),
        store=Store(),
        enforce_privileges=False,
        arm_watchdog=lambda token: None,
    )
    controller._sync_timer = lambda config: []
    controller._timer_state = lambda: "inactive"
    confirmed = default_config()
    confirmed["network"].update({"interfaces": ["eth0"], "ipv6": False})
    confirmed["policies"] = [
        {
            "name": "primary",
            "enabled": True,
            "destinations": ["203.0.113.10"],
            "block_countries": ["IR"],
        }
    ]
    controller.apply(confirmed, safe=False)
    before_rules = controller.nft.rules
    desired = copy.deepcopy(confirmed)
    desired["language"] = "ru"
    desired["source"] = "ipverse-rir"
    desired["updates"] = {"enabled": True, "interval": "weekly"}
    desired["allowlist"]["ipv4"] = ["198.51.100.100/32"]
    desired["policies"][0]["block_countries"] = ["CN"]
    desired["policies"].append(
        {
            "name": "secondary",
            "enabled": True,
            "destinations": ["203.0.113.20"],
            "block_countries": ["IR"],
        }
    )
    staged = controller.apply(desired)
    return SimpleNamespace(
        controller=controller,
        paths=paths,
        confirmed=confirmed,
        desired=desired,
        before_rules=before_rules,
        staged=staged,
    )


def test_pending_repair_preserves_all_candidate_settings_before_rollback(interrupted):
    controller = interrupted.controller
    original_recover = controller._recover_pending

    def recover(pending):
        assert interrupted.paths.pending.exists()
        assert load_config(interrupted.paths.recovered_draft) == interrupted.desired
        return original_recover(pending)

    controller._recover_pending = recover
    result = controller.repair_pending()
    assert result["recovered"] is True and result["rolled_back"] is True
    assert result["draft_path"] == str(interrupted.paths.recovered_draft)
    assert not interrupted.paths.pending.exists()
    assert controller.nft.rules == interrupted.before_rules
    assert load_config(interrupted.paths.config_file) == interrupted.confirmed
    assert _read_snapshot(interrupted.paths.confirmed)["config"] == interrupted.confirmed
    assert controller.recovered_draft() == interrupted.desired


def test_repair_of_an_expired_journal_preserves_the_candidate(interrupted):
    pending = interrupted.controller._pending()
    pending["deadline"] = 0
    _write_pending(interrupted.paths.pending, pending)
    assert interrupted.controller.repair_pending()["recovered"] is True
    assert interrupted.controller.recovered_draft() == interrupted.desired
    assert interrupted.controller.nft.rules == interrupted.before_rules


def test_corrupt_pending_never_changes_firewall_or_existing_recovered_draft(interrupted):
    controller = interrupted.controller
    save_config(interrupted.confirmed, interrupted.paths.recovered_draft)
    backup = interrupted.paths.recovered_draft.read_bytes()
    value = json.loads(interrupted.paths.pending.read_text())
    value["candidate"]["config"]["language"] = "en"
    interrupted.paths.pending.write_text(json.dumps(value))
    journal = interrupted.paths.pending.read_bytes()
    rules = controller.nft.rules
    mutations = len(controller.nft.applied)
    with pytest.raises(OperationError, match="integrity"):
        controller.repair_pending()
    assert controller.nft.rules == rules
    assert len(controller.nft.applied) == mutations
    assert interrupted.paths.pending.read_bytes() == journal
    assert interrupted.paths.recovered_draft.read_bytes() == backup


def test_foreign_table_refusal_retains_pending_and_a_recoverable_candidate(interrupted):
    controller = interrupted.controller
    journal = interrupted.paths.pending.read_bytes()
    confirmed = interrupted.paths.confirmed.read_bytes()
    rules = controller.nft.rules

    def refuse(_rules):
        raise NftError("Refusing to modify inet geolatch: the table is not owned by GeoLatch")

    controller.nft.apply = refuse
    with pytest.raises(NftError, match="not owned"):
        controller.repair_pending()
    assert interrupted.paths.pending.read_bytes() == journal
    assert interrupted.paths.confirmed.read_bytes() == confirmed
    assert controller.nft.rules == rules
    assert controller.recovered_draft() == interrupted.desired


def test_failure_to_save_candidate_does_not_start_rollback(interrupted, monkeypatch):
    import geolatch.controller as controller_module

    controller = interrupted.controller
    journal = interrupted.paths.pending.read_bytes()
    rules = controller.nft.rules
    mutations = len(controller.nft.applied)
    real_save = controller_module.save_config

    def save(config, path):
        if path == interrupted.paths.recovered_draft:
            raise PermissionError("recovered draft storage unavailable")
        real_save(config, path)

    monkeypatch.setattr(controller_module, "save_config", save)
    with pytest.raises(PermissionError, match="storage unavailable"):
        controller.repair_pending()
    assert interrupted.paths.pending.read_bytes() == journal
    assert controller.nft.rules == rules and len(controller.nft.applied) == mutations


def test_no_pending_repair_does_not_overwrite_an_existing_candidate(interrupted):
    controller = interrupted.controller
    controller.repair_pending()
    candidate = interrupted.paths.recovered_draft.read_bytes()
    confirmed = interrupted.paths.confirmed.read_bytes()
    mutations = len(controller.nft.applied)
    result = controller.repair_pending()
    assert result["recovered"] is False
    assert interrupted.paths.recovered_draft.read_bytes() == candidate
    assert interrupted.paths.confirmed.read_bytes() == confirmed
    assert len(controller.nft.applied) == mutations


def test_recovered_draft_read_is_read_only_when_nothing_was_recovered(tmp_path):
    controller = Controller(
        Paths(tmp_path / "etc" / "config.yaml", tmp_path / "state", tmp_path / "cache"),
        nft=Kernel(),
        store=Store(),
        enforce_privileges=False,
    )
    assert controller.recovered_draft() is None
    assert list(tmp_path.iterdir()) == []


def test_repair_requires_privileges_before_any_persistent_change(interrupted, monkeypatch):
    controller = interrupted.controller
    journal = interrupted.paths.pending.read_bytes()
    mutations = len(controller.nft.applied)
    monkeypatch.setattr(Controller, "needs_privileges", property(lambda self: True))
    with pytest.raises(OperationError) as error:
        controller.repair_pending()
    assert error.value.key == "error.root_required"
    assert interrupted.paths.pending.read_bytes() == journal
    assert not interrupted.paths.recovered_draft.exists()
    assert len(controller.nft.applied) == mutations


def test_repair_does_not_race_another_mutation(interrupted):
    controller = interrupted.controller
    mutations = len(controller.nft.applied)
    with operation_lock(interrupted.paths.state_dir):
        with pytest.raises(RuntimeError, match="Another GeoLatch"):
            controller.repair_pending(lock_timeout=0)
    assert interrupted.paths.pending.exists()
    assert not interrupted.paths.recovered_draft.exists()
    assert len(controller.nft.applied) == mutations


def test_repair_waits_for_existing_mutation_before_reading_or_modifying_state(interrupted):
    from test_operation_lock import held_by_child, release_holder

    controller = interrupted.controller
    original_journal = interrupted.paths.pending.read_bytes()
    original_config = interrupted.paths.config_file.read_bytes()
    mutations = len(controller.nft.applied)
    finished = threading.Event()
    result = {}
    errors = []

    def repair():
        try:
            result.update(controller.repair_pending(lock_timeout=2))
        except BaseException as error:
            errors.append(error)
        finally:
            finished.set()

    with held_by_child(interrupted.paths.state_dir) as holder:
        thread = threading.Thread(target=repair)
        thread.start()
        try:
            assert not finished.wait(0.1)
            assert interrupted.paths.pending.read_bytes() == original_journal
            assert interrupted.paths.config_file.read_bytes() == original_config
            assert not interrupted.paths.recovered_draft.exists()
            assert len(controller.nft.applied) == mutations
            release_holder(holder)
            thread.join(timeout=3)
            assert not thread.is_alive()
            assert errors == []
            assert result["recovered"] is True
            assert controller.recovered_draft() == interrupted.desired
            assert not interrupted.paths.pending.exists()
            assert controller.nft.rules == interrupted.before_rules
        finally:
            if holder.poll() is None:
                release_holder(holder)
            thread.join(timeout=3)


def test_recovered_candidate_is_removed_only_after_explicit_successful_confirmation(interrupted):
    controller = interrupted.controller
    controller.repair_pending()
    backup = interrupted.paths.recovered_draft.read_bytes()
    staged = controller.apply(controller.recovered_draft())
    assert interrupted.paths.recovered_draft.read_bytes() == backup
    assert load_config(interrupted.paths.config_file) == interrupted.confirmed
    controller.confirm(staged["token"])
    assert not interrupted.paths.recovered_draft.exists()
    assert load_config(interrupted.paths.config_file) == interrupted.desired
    assert _read_snapshot(interrupted.paths.confirmed)["config"] == interrupted.desired


def test_a_failed_apply_does_not_discard_the_recovered_candidate(interrupted):
    controller = interrupted.controller
    controller.repair_pending()
    backup = interrupted.paths.recovered_draft.read_bytes()
    controller.nft.fail_next_apply = True
    with pytest.raises(NftError, match="atomic transaction"):
        controller.apply(controller.recovered_draft())
    assert interrupted.paths.recovered_draft.read_bytes() == backup
    assert load_config(interrupted.paths.config_file) == interrupted.confirmed
    assert controller.nft.rules == interrupted.before_rules


def test_unattended_database_update_cannot_discard_an_unapplied_recovered_candidate(interrupted):
    controller = interrupted.controller
    controller.repair_pending()
    backup = interrupted.paths.recovered_draft.read_bytes()
    controller.store.databases["IR:4"] = ["198.51.100.0/25"]
    result = controller.update()
    assert result["changed"] is True
    assert interrupted.paths.recovered_draft.read_bytes() == backup
    assert controller.recovered_draft() == interrupted.desired
    assert load_config(interrupted.paths.config_file) == interrupted.confirmed


@pytest.mark.parametrize("operation", ["disable", "enable", "rollback"])
def test_firewall_state_commands_do_not_discard_the_recovered_candidate(interrupted, operation):
    controller = interrupted.controller
    controller.repair_pending()
    backup = interrupted.paths.recovered_draft.read_bytes()
    result = getattr(controller, operation)()
    if result.get("pending"):
        controller.confirm(result["token"])
    assert interrupted.paths.recovered_draft.read_bytes() == backup
    assert controller.recovered_draft() == interrupted.desired


def test_tui_reopens_the_recovered_candidate_without_applying_it(interrupted):
    from geolatch.tui.app import GeoLatchApp

    controller = interrupted.controller
    controller.repair_pending()
    mutations = len(controller.nft.applied)
    app = GeoLatchApp(controller)
    try:
        assert app.original == interrupted.confirmed
        assert app.draft == interrupted.desired
        assert app.dirty
        assert controller.nft.rules == interrupted.before_rules
        assert len(controller.nft.applied) == mutations
    finally:
        app._controller_pool.shutdown(wait=False)
