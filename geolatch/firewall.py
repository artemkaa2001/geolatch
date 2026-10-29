"""Deterministic country/destination rules; Python is never on the packet path."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import defaultdict
from typing import Any

from .nftables import OWNER, NftError
from .statistics import DROP_CHAINS, TRACKING_SETS, UNIQUE_IP_CAPACITY


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _networks(values: list[str], family: int) -> list[str]:
    if not isinstance(values, list) or not values:
        raise NftError(f"Required IPv{family} GeoIP database is empty")
    try:
        parsed = [ipaddress.ip_network(value, strict=True) for value in values]
    except (ValueError, TypeError) as exc:
        raise NftError(f"Invalid GeoIP CIDR: {exc}") from exc
    if any(network.version != family or network.prefixlen == 0 for network in parsed):
        raise NftError("GeoIP database contains a wrong address family or a default route")
    return [str(network) for network in ipaddress.collapse_addresses(parsed)]


def _set(name: str, datatype: str, elements: list[str], interval: bool = False) -> list[str]:
    lines = [f"    set {name} {{", f"        type {datatype}"]
    if interval:
        lines.append("        flags interval")
    lines.extend(["        elements = { " + ", ".join(elements) + " }", "    }"])
    return lines


def generate_rules(
    config: dict[str, Any],
    databases: dict[str, list[str]],
    addresses: list[dict[str, Any]] | None = None,
) -> str:
    """Build one owned inet table, with union semantics for overlapping policies.

    Source sets are shared per country/family. The destinations for each country
    are unioned across enabled policies; no source database is copied per IP.
    Only named ingress interfaces and exact selected destination addresses match.
    ``destinations: all`` is resolved to local public addresses before generation.
    """
    from .config import validate_config
    from .networks import resolve_destinations

    config = validate_config(config)
    resolved = resolve_destinations(config, addresses)
    destinations: dict[tuple[str, int], set[str]] = defaultdict(set)
    if config.get("enabled", True):
        for policy in config["policies"]:
            if not policy["enabled"]:
                continue
            for destination in resolved.get(policy["name"], []):
                family = ipaddress.ip_address(destination).version
                if not config["network"][f"ipv{family}"]:
                    continue
                for country in policy["block_countries"]:
                    destinations[country, family].add(destination)
    interfaces = config["network"]["interfaces"]
    if destinations and not interfaces:
        raise NftError("Select ingress network interfaces before applying geographic restrictions")

    lines = ["table inet geolatch {", f"    comment {_quote(OWNER)}"]
    if destinations:
        lines.extend(_set("ingress", "ifname", [_quote(name) for name in sorted(set(interfaces))]))
    for family in (4, 6):
        allowlist = config["allowlist"][f"ipv{family}"]
        if allowlist:
            values = [
                str(network)
                for network in ipaddress.collapse_addresses(
                    ipaddress.ip_network(x) for x in allowlist
                )
            ]
            lines.extend(_set(f"allow_v{family}", f"ipv{family}_addr", values, interval=True))

    destination_sets: dict[tuple[int, tuple[str, ...]], str] = {}
    rule_destinations: dict[tuple[str, int], str] = {}
    for (country, family), values in sorted(destinations.items()):
        key = f"{country}:{family}"
        if key not in databases:
            raise NftError(f"Required GeoIP database is unavailable: {key}")
        networks = _networks(databases[key], family)
        lines.extend(
            _set(f"geo_{country.lower()}_v{family}", f"ipv{family}_addr", networks, interval=True)
        )
        addresses_key = (family, tuple(sorted(values, key=ipaddress.ip_address)))
        if addresses_key not in destination_sets:
            digest = hashlib.sha256("\n".join(addresses_key[1]).encode()).hexdigest()[:16]
            name = f"dst_v{family}_{digest}"
            destination_sets[addresses_key] = name
            lines.extend(_set(name, f"ipv{family}_addr", list(addresses_key[1])))
        rule_destinations[country, family] = destination_sets[addresses_key]

    if rule_destinations:
        lines.extend(["    chain geolatch_drop {", "        drop", "    }"])
    for family in sorted({family for _, family in rule_destinations}):
        protocol = "ip" if family == 4 else "ip6"
        lines.extend(
            [
                f"    set {TRACKING_SETS[family]} {{",
                f"        type ipv{family}_addr",
                "        flags dynamic",
                f"        size {UNIQUE_IP_CAPACITY}",
                "    }",
                f"    chain {DROP_CHAINS[family]} {{",
                f"        update @{TRACKING_SETS[family]} {{ {protocol} saddr }} goto geolatch_drop",
                # Successful insertion jumps directly to DROP. A full set/OOM
                # breaks this rule and reaches the fallback DROP instead. Its
                # counter records missed observations even below the capacity,
                # so the UI never claims an exact count after allocation loss.
                f"        counter drop comment {_quote(f'GeoLatch tracking failure family={family}')}",
                "    }",
            ]
        )

    lines.extend(
        [
            "    chain prerouting {",
            "        type filter hook prerouting priority -150; policy accept;",
            "        ct direction reply return",
            # Related ICMPv6 error/control traffic must not break ND or PMTU.
            "        meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } return",
        ]
    )
    if config["firewall"]["preserve_established"]:
        lines.append("        ct state { established, related } return")
    for family in (4, 6):
        if config["allowlist"][f"ipv{family}"]:
            protocol = "ip" if family == 4 else "ip6"
            lines.append(f"        {protocol} saddr @allow_v{family} return")
    for (country, family), destination_set in sorted(rule_destinations.items()):
        protocol = "ip" if family == 4 else "ip6"
        state = "ct state new " if config["firewall"]["preserve_established"] else ""
        lines.append(
            f"        iifname @ingress ct direction original {state}"
            f"{protocol} daddr @{destination_set} {protocol} saddr @geo_{country.lower()}_v{family} "
            f"counter jump {DROP_CHAINS[family]} comment {_quote(f'GeoLatch country={country} family={family}')}"
        )
    lines.extend(["    }", "}"])
    revision = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    chain_start = lines.index("    chain prerouting {")
    lines.insert(chain_start + 1, f'        comment "geolatch-revision:{revision}"')
    return "\n".join(lines) + "\n"
