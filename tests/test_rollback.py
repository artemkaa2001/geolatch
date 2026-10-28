"""Real watchdog process/signal tests with filesystem-emulated nft IO.

These prove journal recovery and process independence, not netfilter behavior.
The fake nft executable below only reads/writes files beneath pytest's temporary
directory. No test in this module invokes the real nft executable or requires
root, a network namespace, network sockets, or downloaded data.
"""

from __future__ import annotations

import copy
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from geolatch.config import default_config, load_config, save_config
from geolatch.controller import Controller, _read_snapshot, _write_pending, _write_snapshot
from geolatch.firewall import generate_rules
from geolatch.nftables import Nftables
from geolatch.paths import Paths
from geolatch.rollback import watchdog
from geolatch.utils import write_json

WATCHDOG_DRIVER = """
import json
import sys
from pathlib import Path
from geolatch.controller import Controller
from geolatch.nftables import Nftables
from geolatch.paths import Paths
from geolatch.rollback import watchdog

data = json.loads(sys.argv[1])
paths = Paths(Path(data['config']), Path(data['state']), Path(data['cache']))
controller = Controller(paths, nft=Nftables(binary=data['nft']), store=object(), enforce_privileges=False)
raise SystemExit(watchdog(controller, data['token']))
"""

PARENT_DRIVER = """
import json
import os
import signal
import subprocess
import sys

data = json.loads(sys.argv[2])
with open(data['child_log'], 'w', encoding='utf-8') as errors:
    child = subprocess.Popen(
        [sys.executable, '-I', '-c', sys.argv[1], sys.argv[2]],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors,
        start_new_session=True, close_fds=True, cwd='/',
    )
print(json.dumps({'child_pid': child.pid, 'parent_pid': os.getpid(), 'parent_session': os.getsid(0)}), flush=True)
while True:
    signal.pause()
"""


def wait_until(condition, *, timeout: float = 8.0, detail: str = "") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    pytest.fail("Watchdog condition timed out. " + detail)


def stopped(pid: int) -> bool:
    """Containers without a reaping PID1 can leave a terminated child zombie."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z"
    except FileNotFoundError:
        return True


def fake_nft(path: Path, state: Path) -> None:
    """Implement only the bounded nft CLI protocol used by recovery.

    The script never imports an OS network library and never executes another
    program. Real Nftables still performs ownership and revision verification.
    """
    source = """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import sys

state = Path(STATE_PATH)
value = json.loads(state.read_text())
rules = value['rules']
args = sys.argv[1:]
table = {'family': 'inet', 'name': 'geolatch', 'comment': 'GeoLatch managed table v1'}
if args == ['--json', 'list', 'tables']:
    print(json.dumps({'nftables': [{'table': table}] if rules is not None else []}))
elif args == ['--json', 'list', 'table', 'inet', 'geolatch']:
    entries = [{'table': table}]
    revision = re.search(r'comment "(geolatch-revision:[0-9a-f]{64})"', rules or '')
    if revision:
        entries.append({'chain': {'name': 'prerouting', 'comment': revision[1]}})
    print(json.dumps({'nftables': entries}))
elif args == ['list', 'table', 'inet', 'geolatch']:
    print(rules, end='')
elif args in (['--file', '-'], ['--check', '--file', '-']):
    batch = sys.stdin.read()
    if '--check' not in args:
        start = batch.find('table inet geolatch {')
        value['rules'] = batch[start:] if start >= 0 else None
        value['applier_parent'] = os.getppid()
        value['applications'] = value.get('applications', 0) + 1
        temporary = state.with_suffix('.tmp')
        temporary.write_text(json.dumps(value))
        temporary.replace(state)
else:
    raise SystemExit('Unexpected fake nft operation: ' + repr(args))
""".replace("STATE_PATH", repr(str(state)))
    path.write_text(source, encoding="utf-8")
    path.chmod(0o700)


@pytest.fixture
def journal(tmp_path: Path):
    paths = Paths(tmp_path / "etc" / "config.yaml", tmp_path / "state", tmp_path / "cache")
    before_config = default_config()
    before_config["network"].update({"interfaces": ["eth0"], "ipv6": False})
    before_config["policies"] = [
        {
            "name": "primary",
            "enabled": True,
            "destinations": ["203.0.113.10"],
            "block_countries": ["IR"],
        }
    ]
    candidate_config = copy.deepcopy(before_config)
    candidate_config["policies"][0]["block_countries"] = ["CN"]

    def snapshot(config, databases):
        return {
            "config": config,
            "databases": databases,
            "rules": generate_rules(config, databases),
            "metadata": {"source": "ipverse-geo"},
            "destinations": {"primary": ["203.0.113.10"]},
            "applied_at": "2026-10-28T00:00:00Z",
        }

    before = snapshot(before_config, {"IR:4": ["8.8.8.0/24"]})
    candidate = snapshot(candidate_config, {"CN:4": ["9.9.9.0/24"]})
    save_config(before_config, paths.config_file)
    _write_snapshot(paths.confirmed, before)
    pending = {
        "schema": 1,
        "token": "b" * 32,
        "deadline": time.time() + 60,
        "before": before,
        "candidate": candidate,
    }
    _write_pending(paths.pending, pending)
    state = tmp_path / "fake-kernel.json"
    write_json(state, {"rules": candidate["rules"], "applications": 0})
    executable = tmp_path / "nft-filesystem-emulator"
    fake_nft(executable, state)
    controller = Controller(
        paths, nft=Nftables(binary=str(executable)), store=object(), enforce_privileges=False
    )
    return SimpleNamespace(
        paths=paths,
        before=before,
        candidate=candidate,
        pending=pending,
        state=state,
        executable=executable,
        controller=controller,
    )


def test_detached_watchdog_restores_after_launching_parent_is_killed(
    journal, tmp_path: Path
) -> None:
    """Actually SIGKILL the parent, then expire its independently running guard."""
    data = {
        "config": str(journal.paths.config_file),
        "state": str(journal.paths.state_dir),
        "cache": str(journal.paths.cache_dir),
        "nft": str(journal.executable),
        "token": journal.pending["token"],
        "child_log": str(tmp_path / "watchdog.log"),
    }
    parent = subprocess.Popen(
        [sys.executable, "-I", "-c", PARENT_DRIVER, WATCHDOG_DRIVER, json.dumps(data)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    child_pid = None
    try:
        report = json.loads(parent.stdout.readline())
        child_pid = report["child_pid"]
        ready = journal.paths.state_dir / f"watchdog-{journal.pending['token']}.ready"
        wait_until(ready.exists, detail=f"Inspect {data['child_log']}")
        assert os.getsid(child_pid) == child_pid
        assert os.getsid(child_pid) != report["parent_session"]
        assert json.loads(journal.state.read_text())["rules"] == journal.candidate["rules"]

        parent.kill()
        assert parent.wait(timeout=5) == -signal.SIGKILL
        assert not stopped(child_pid), "Watchdog died with the initiating process"

        # Shorten the durable deadline after killing the parent. The actual
        # watchdog re-reads it; no production minimum timeout is weakened.
        expired = {**journal.pending, "deadline": time.time() - 1}
        _write_pending(journal.paths.pending, expired)
        wait_until(lambda: not journal.paths.pending.exists())
        wait_until(lambda: stopped(child_pid))
        emulated = json.loads(journal.state.read_text())
        assert emulated["rules"] == journal.before["rules"]
        assert emulated["applier_parent"] == child_pid
        assert emulated["applications"] == 1
        assert load_config(journal.paths.config_file) == journal.before["config"]
        assert _read_snapshot(journal.paths.confirmed) == journal.before
        assert not ready.exists()
        events = [json.loads(line) for line in journal.paths.events.read_text().splitlines()]
        assert events[-1]["event"] == "rollback"
        assert events[-1]["reason"] == "unconfirmed"
    finally:
        if parent.poll() is None:
            parent.kill()
        parent.communicate(timeout=5)
        if child_pid is not None and not stopped(child_pid):
            os.kill(child_pid, signal.SIGTERM)
            wait_until(lambda: stopped(child_pid), timeout=3)


def test_production_fallback_launches_a_separate_isolated_python_session(
    journal, monkeypatch
) -> None:
    calls = []

    class Process:
        def poll(self):
            return None

        def terminate(self):
            pytest.fail("Ready watchdog must not be terminated")

    def launch(args, **kwargs):
        calls.append((args, kwargs))
        ready = journal.paths.state_dir / f"watchdog-{journal.pending['token']}.ready"
        write_json(ready, {"ready": True})
        return Process()

    monkeypatch.setattr("geolatch.controller.shutil.which", lambda executable: None)
    monkeypatch.setattr("geolatch.controller.subprocess.Popen", launch)
    journal.controller._arm(journal.pending["token"])
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[:4] == [sys.executable, "-I", "-m", "geolatch"]
    assert args[-2:] == ["_watchdog", journal.pending["token"]]
    assert kwargs["start_new_session"] is True
    assert kwargs["close_fds"] is True
    assert kwargs["cwd"] == "/"
    assert all(kwargs[key] == subprocess.DEVNULL for key in ("stdin", "stdout", "stderr"))


def test_backward_wall_clock_cannot_postpone_rollback(journal, monkeypatch) -> None:
    import geolatch.rollback as module

    recovered = []
    pending = {"token": journal.pending["token"], "deadline": 1002}
    controller = SimpleNamespace(paths=journal.paths, _pending=lambda: pending)

    def recover(value):
        recovered.append(value)
        journal.paths.pending.unlink()

    controller._recover_pending = recover
    wall_times = iter((1000, -1_000_000))
    monotonic_times = iter((100, 103))
    monkeypatch.setattr(module.time, "time", lambda: next(wall_times))
    monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic_times))
    monkeypatch.setattr(module.signal, "signal", lambda *args: None)
    monkeypatch.setattr(
        module.time, "sleep", lambda seconds: pytest.fail("Expired safety clock must not sleep")
    )
    assert watchdog(controller, pending["token"]) == 0
    assert recovered == [pending]
