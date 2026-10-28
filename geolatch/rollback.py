"""Independent, bounded-lifetime watchdog for unconfirmed kernel changes."""

from __future__ import annotations

import contextlib
import signal
import time

from .controller import Controller
from .utils import durable_unlink, operation_lock, write_json


def watchdog(controller: Controller, token: str) -> int:
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    pending = controller._pending()
    if pending["token"] != token:
        return 1
    # Wall time is persisted for recovery across boots; elapsed safety time uses
    # a monotonic clock so NTP or a manual clock correction cannot defer rollback.
    monotonic_deadline = time.monotonic() + min(600, max(0, pending["deadline"] - time.time()))
    ready = controller.paths.state_dir / f"watchdog-{token}.ready"
    write_json(ready, {"ready": True})
    try:
        while controller.paths.pending.exists():
            pending = controller._pending()
            if pending["token"] != token:
                return 0
            remaining = min(
                pending["deadline"] - time.time(), monotonic_deadline - time.monotonic()
            )
            if remaining > 0:
                time.sleep(min(1.0, max(0.01, remaining)))
                continue
            try:
                with operation_lock(controller.paths.state_dir):
                    if not controller.paths.pending.exists():
                        return 0
                    current = controller._pending()
                    if current["token"] != token:
                        return 0
                    controller._recover_pending(current)
                    return 0
            except (OSError, RuntimeError, ValueError):
                # Failed recovery never erases its durable journal. Keep trying
                # after temporary netlink/lock contention, including parent death.
                time.sleep(1)
    except FileNotFoundError:
        return 0
    finally:
        with contextlib.suppress(OSError):
            durable_unlink(ready)
    return 0
