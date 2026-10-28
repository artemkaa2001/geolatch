"""Exercise real flock contention without touching firewall or system state."""

from __future__ import annotations

import contextlib
import errno
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from geolatch.utils import operation_lock

HOLDER = """
import fcntl
import select
import sys

with open(sys.argv[1], 'a', encoding='utf-8') as stream:
    fcntl.flock(stream, fcntl.LOCK_EX)
    print('locked', flush=True)
    if not select.select([sys.stdin], [], [], 10)[0]:
        raise SystemExit('test lock holder lease expired')
    sys.stdin.read(1)
    fcntl.flock(stream, fcntl.LOCK_UN)
"""


@contextlib.contextmanager
def held_by_child(directory: Path):
    """Keep one independent open-file description locked until explicit release."""
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", HOLDER, str(directory / "operation.lock")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout.readline().strip() == "locked", process.stderr.read()
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def release_holder(process):
    process.stdin.write("x")
    process.stdin.flush()
    assert process.wait(timeout=3) == 0


def test_default_operation_lock_still_fails_immediately_without_changing_lock_file(tmp_path):
    path = tmp_path / "operation.lock"
    path.write_text("preserved lock inode", encoding="utf-8")
    inode = path.stat().st_ino
    with held_by_child(tmp_path):
        entered = False
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="Another GeoLatch"):
            with operation_lock(tmp_path):
                entered = True
        assert time.monotonic() - started < 0.5
        assert not entered
        assert path.stat().st_ino == inode
        assert path.read_text() == "preserved lock inode"


def test_bounded_wait_acquires_only_after_independent_holder_releases(tmp_path):
    acquired = threading.Event()
    started = threading.Event()
    errors = []

    def waiter():
        started.set()
        try:
            with operation_lock(tmp_path, timeout=2):
                acquired.set()
        except BaseException as error:
            errors.append(error)

    with held_by_child(tmp_path) as holder:
        thread = threading.Thread(target=waiter)
        thread.start()
        try:
            assert started.wait(1)
            assert not acquired.wait(0.1)
            release_holder(holder)
            thread.join(timeout=3)
            assert not thread.is_alive()
            assert errors == []
            assert acquired.is_set()
        finally:
            if holder.poll() is None:
                release_holder(holder)
            thread.join(timeout=3)


def test_timeout_preserves_active_holder_and_does_not_enter_critical_section(tmp_path):
    path = tmp_path / "operation.lock"
    path.write_text("same inode, same owner", encoding="utf-8")
    inode = path.stat().st_ino
    with held_by_child(tmp_path) as holder:
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="Another GeoLatch"):
            with operation_lock(tmp_path, timeout=0.15):
                pytest.fail("Timeout must not admit a competing mutation")
        elapsed = time.monotonic() - started
        assert 0.1 <= elapsed < 1
        assert holder.poll() is None
        assert path.stat().st_ino == inode
        assert path.read_text() == "same inode, same owner"
        release_holder(holder)
    with operation_lock(tmp_path):
        pass


def test_interruption_during_wait_closes_the_waiter_descriptor(tmp_path, monkeypatch):
    import geolatch.utils as utils

    descriptors = []
    real_open = os.open

    def record_open(path, flags, mode=0o777):
        descriptor = real_open(path, flags, mode)
        if Path(path).name == "operation.lock":
            descriptors.append(descriptor)
        return descriptor

    def interrupt(_seconds):
        raise KeyboardInterrupt

    with held_by_child(tmp_path) as holder:
        with monkeypatch.context() as patch:
            patch.setattr(utils.os, "open", record_open)
            patch.setattr(utils, "time", SimpleNamespace(monotonic=time.monotonic, sleep=interrupt))
            with pytest.raises(KeyboardInterrupt):
                with operation_lock(tmp_path, timeout=2):
                    pytest.fail("Interrupted waiter cannot enter the critical section")
        assert len(descriptors) == 1
        with pytest.raises(OSError) as error:
            os.fstat(descriptors[0])
        assert error.value.errno == errno.EBADF
        assert holder.poll() is None
        release_holder(holder)
    with operation_lock(tmp_path):
        pass
