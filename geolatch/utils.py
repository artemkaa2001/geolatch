"""Small, durable local storage primitives; no subprocess shell interpolation."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def secure_directory(path: Path, mode: int = 0o700) -> None:
    created = not path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise PermissionError(f"Unsafe directory: {path}")
    if info.st_mode & 0o022:
        raise PermissionError(f"Directory writable by another user: {path}")
    if created:
        path.chmod(mode)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
    secure_directory(path.parent, 0o755 if mode == 0o644 else 0o700)
    descriptor, filename = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, path)
        fsync_directory(path.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(filename)


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n", mode)


def read_json(path: Path, *, limit: int = 256 * 1024 * 1024) -> Any:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError(f"Expected a regular JSON file: {path}")
    with os.fdopen(descriptor, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"File exceeds size limit: {path}")
    return json.loads(raw)


@contextlib.contextmanager
def operation_lock(directory: Path) -> Iterator[None]:
    secure_directory(directory, 0o755)
    descriptor = os.open(
        directory / "operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise RuntimeError("Another GeoLatch operation is running") from exc
    try:
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def durable_unlink(path: Path) -> None:
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
        fsync_directory(path.parent)
