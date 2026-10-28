"""Measure real management work; optional kernel work always gets a new netns."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

from geolatch.config import default_config
from geolatch.firewall import generate_rules
from geolatch.geoip import parse_cidrs
from geolatch.nftables import Nftables


def measure(callable_):
    tracemalloc.start()
    started = time.perf_counter()
    result = callable_()
    duration = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, {"seconds": duration, "peak_python_bytes": peak}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefixes", type=int, default=50000)
    parser.add_argument("--cidr-file", type=Path)
    parser.add_argument("--kernel", action="store_true")
    parser.add_argument("--parent-netns", type=int, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if not 1 <= arguments.prefixes <= 100000:
        parser.error("--prefixes must be between 1 and 100000")

    if arguments.kernel and arguments.parent_netns is None:
        unshare = shutil.which("unshare")
        if not unshare:
            parser.error("unshare is required for isolated kernel measurement")
        command = [unshare]
        if os.geteuid() != 0:
            command += ["--user", "--map-root-user"]
        command += [
            "--net",
            "--",
            sys.executable,
            str(Path(__file__).resolve()),
            "--prefixes",
            str(arguments.prefixes),
            "--kernel",
            "--parent-netns",
            str(os.stat("/proc/self/ns/net").st_ino),
        ]
        if arguments.cidr_file:
            command += ["--cidr-file", str(arguments.cidr_file.resolve())]
        return subprocess.run(command, check=False).returncode

    if arguments.kernel:
        # Derive the parent's namespace independently. A caller-supplied
        # --parent-netns value alone must never authorize a host mutation.
        parent_namespace = os.stat(f"/proc/{os.getppid()}/ns/net").st_ino
        current_namespace = os.stat("/proc/self/ns/net").st_ino
        if arguments.parent_netns != parent_namespace or current_namespace == parent_namespace:
            parser.error("refusing kernel measurement in the caller's network namespace")
        if not shutil.which("nft"):
            parser.error("nftables is required for kernel measurement")

    if arguments.cidr_file:
        contents = arguments.cidr_file.read_text(encoding="utf-8")
    else:
        base = int(ipaddress.IPv4Address("8.0.0.0"))
        private_start = int(ipaddress.IPv4Address("10.0.0.0"))
        synthetic = (base + index * 512 for index in range(arguments.prefixes))
        contents = "\n".join(
            f"{ipaddress.IPv4Address(value + (2**24 if value >= private_start else 0))}/24"
            for value in synthetic
        )
    networks, parsing = measure(lambda: parse_cidrs(contents, 4))
    config = default_config()
    config["network"] = {"ipv4": True, "ipv6": False, "interfaces": ["eth0"]}
    config["policies"] = [
        {
            "name": "benchmark",
            "enabled": True,
            "destinations": ["203.0.113.10"],
            "block_countries": ["IR"],
        }
    ]
    rules, generation = measure(lambda: generate_rules(config, {"IR:4": networks}))
    result = {
        "python": platform.python_version(),
        "kernel": platform.release(),
        "input_prefixes": len(contents.splitlines()),
        "normalized_prefixes": len(networks),
        "parse_and_normalize": parsing,
        "prepare_rules": generation,
        "rules_bytes": len(rules.encode("utf-8")),
    }
    if arguments.kernel:
        nft = Nftables()
        _, checking = measure(lambda: nft.check(rules))
        _, applying = measure(lambda: nft.apply(rules))
        result["nft_check"] = checking
        result["nft_apply"] = applying
        result["network_namespace_isolated"] = True
        nft.apply(None)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
