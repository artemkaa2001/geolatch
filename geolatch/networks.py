"""Inspect local Linux addresses without changing interfaces, routes or sysctls."""

from __future__ import annotations

import ipaddress
import json
import subprocess
from typing import Any


class NetworkError(RuntimeError):
    key = "error.network_discovery"


def _kind(item: dict) -> str:
    interface = item.get("ifname", "")
    kind = item.get("linkinfo", {}).get("info_kind", "")
    if item.get("link_type") == "loopback" or interface == "lo":
        return "loopback"
    if kind in {"tun", "wireguard", "gre", "gretap", "ipip", "sit", "vti", "vxlan"}:
        return "tunnel"
    if interface.startswith(("tun", "tap", "wg", "tailscale", "zt")):
        return "tunnel"
    if kind in {"bridge", "veth"} or interface.startswith(("docker", "br-", "veth", "virbr")):
        return "bridge"
    return "network"


def discover_addresses() -> list[dict[str, Any]]:
    """Return real addresses using iproute2's machine interface.

    Tentative, DAD-failed and expired addresses are excluded. Interface category
    is a hint, never evidence that an address is public or safe to select.
    """
    try:
        result = subprocess.run(
            ["ip", "-j", "-details", "address", "show"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise NetworkError(str(error)) from error
    if result.returncode:
        raise NetworkError(result.stderr.strip() or "ip address failed")
    try:
        interfaces = json.loads(result.stdout)
        if not isinstance(interfaces, list):
            raise ValueError("expected a list")
        addresses = []
        seen = set()
        for item in interfaces:
            for address in item.get("addr_info", []):
                if address.get("family") not in {"inet", "inet6"}:
                    continue
                flags = address.get("flags", [])
                if (
                    address.get("tentative")
                    or address.get("dadfailed")
                    or "tentative" in flags
                    or "dadfailed" in flags
                    or address.get("valid_life_time") == 0
                ):
                    continue
                parsed = ipaddress.ip_address(address["local"])
                ifname = item["ifname"]
                identity = (ifname, str(parsed))
                if identity in seen:
                    continue
                seen.add(identity)
                addresses.append(
                    {
                        "interface": ifname,
                        "address": str(parsed),
                        "family": parsed.version,
                        "public": (
                            parsed.is_global
                            and not parsed.is_multicast
                            and not parsed.is_unspecified
                            and not parsed.is_reserved
                        ),
                        "kind": _kind(item),
                    }
                )
        return sorted(
            addresses,
            key=lambda item: (
                item["interface"],
                item["family"],
                int(ipaddress.ip_address(item["address"])),
            ),
        )
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise NetworkError(f"invalid iproute2 JSON: {error}") from error


def resolve_destinations(
    config: dict[str, Any],
    addresses: list[dict[str, Any]] | None = None,
) -> dict[str, list[str]]:
    """Resolve each enabled policy, restricting all to selected public local IPs.

    Explicit destinations are retained even when absent locally to permit an
    upstream public address translated to a private server address. Their use is
    still constrained by the incoming interface and exact destination rule.
    """
    policies = [policy for policy in config["policies"] if policy["enabled"]]
    needs_discovery = any(policy["destinations"] == "all" for policy in policies)
    if needs_discovery and addresses is None:
        addresses = discover_addresses()
    selected = set(config["network"]["interfaces"])
    families = {family for family in (4, 6) if config["network"][f"ipv{family}"]}
    public = sorted(
        {
            item["address"]
            for item in addresses or []
            if item["interface"] in selected
            and item["family"] in families
            and item["public"]
            and item.get("kind") != "loopback"
        },
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )
    result = {}
    for policy in policies:
        if policy["destinations"] == "all":
            if not public and policy["block_countries"] and config.get("enabled", True):
                raise NetworkError(
                    f"{policy['name']}: no public local destination on selected interfaces"
                )
            result[policy["name"]] = public.copy()
        else:
            result[policy["name"]] = [
                address
                for address in policy["destinations"]
                if ipaddress.ip_address(address).version in families
            ]
            if (
                not result[policy["name"]]
                and policy["block_countries"]
                and config.get("enabled", True)
            ):
                raise NetworkError(
                    f"{policy['name']}: destinations do not match enabled IP families"
                )
    return result
