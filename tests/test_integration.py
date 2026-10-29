"""Kernel packet tests, each in a disposable network namespace.

These tests never run nft against the caller's network namespace. They require
``ip``, ``nft``, ``unshare`` and ``nsenter`` plus permission to create nested
network namespaces. Run as root on a disposable Linux VM or enable unprivileged
user namespaces. ``GEOLATCH_REQUIRE_INTEGRATION=1`` turns unavailable prerequisites
into a failure, which prevents a CI integration job from silently passing skips.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
HELPER = Path(__file__).with_name("integration_helper.py")


@pytest.mark.parametrize("parent", [None, "net:[invalid-test-namespace]"])
def test_harness_refuses_the_callers_network_namespace(parent: str | None) -> None:
    """The safety guard executes before any attempt to configure networking."""
    if not Path("/proc/self/ns/net").exists():
        pytest.skip("Linux network namespace identifiers are unavailable")
    result = subprocess.run(
        [
            sys.executable,
            str(HELPER),
            "run",
            "ipv4_tcp_udp_policies",
            parent or os.readlink("/proc/self/ns/net"),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "Refusing kernel tests outside a fresh privileged network namespace" in result.stderr


def unavailable(reason: str) -> None:
    if os.environ.get("GEOLATCH_REQUIRE_INTEGRATION") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture(scope="module")
def namespace_command() -> list[str]:
    missing = [
        binary for binary in ("ip", "nft", "unshare", "nsenter") if shutil.which(binary) is None
    ]
    if missing:
        unavailable("Kernel integration prerequisites missing: " + ", ".join(missing))
    if not sys.platform.startswith("linux"):
        unavailable("Kernel integration tests require Linux")
    prefix = ["unshare"]
    if os.geteuid() != 0:
        prefix += ["--user", "--map-root-user"]
    prefix += ["--net", "--"]
    # The probe only creates a namespace. It does not change the caller's network.
    probe = subprocess.run(
        [*prefix, "true"], capture_output=True, text=True, timeout=10, check=False
    )
    if probe.returncode:
        unavailable("Network namespace isolation unavailable: " + probe.stderr.strip())
    return prefix


@pytest.mark.parametrize(
    "scenario",
    [
        "ipv4_tcp_udp_policies",
        "ipv6_tcp_udp_policies",
        "merged_and_disabled_policies",
        "allowlist_and_foreign_firewall",
        "atomic_replace_disable_restore",
        "established_and_reply_direction",
        "unique_dropped_sources",
        "unique_source_capacity_still_drops",
        "dnat_before_forwarding",
        "interface_and_transit_scope",
    ],
)
def test_kernel_filtering(namespace_command: list[str], scenario: str) -> None:
    parent_namespace = os.readlink("/proc/self/ns/net")
    result = subprocess.run(
        [*namespace_command, sys.executable, str(HELPER), "run", scenario, parent_namespace],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["scenario"] == scenario
    assert report["kernel_verified"] is True
    assert report["network_namespace"] != parent_namespace
