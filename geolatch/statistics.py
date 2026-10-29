"""Summaries of actual nftables counters and exact, bounded source-IP sets.

Source addresses remain local to this module: summaries never expose them.
Cardinality comes from set elements, never from packet counters. Sets have no
expiry, so a source is counted once for the lifetime of the current ruleset.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

UNIQUE_IP_CAPACITY = 65536
TRACKING_SETS = {4: "dropped_sources_v4", 6: "dropped_sources_v6"}
DROP_CHAINS = {4: "geolatch_drop_v4", 6: "geolatch_drop_v6"}
_COUNTRY_COMMENT = re.compile(r"GeoLatch country=[A-Z]{2} family=([46])\Z")


class StatisticsError(ValueError):
    """Malformed kernel output cannot be represented as an exact zero."""


def _entries(table: dict[str, Any]) -> list[dict]:
    if not isinstance(table, dict) or not isinstance(table.get("nftables"), list):
        raise StatisticsError("Invalid nftables statistics schema")
    if any(not isinstance(entry, dict) for entry in table["nftables"]):
        raise StatisticsError("Invalid nftables statistics entry")
    return table["nftables"]


def _nonnegative_integer(value: Any, description: str) -> int:
    if type(value) is not int or value < 0:
        raise StatisticsError(f"Invalid {description} in nftables statistics")
    return value


def _country_counters(table: dict[str, Any]) -> tuple[int, int, set[int], set[int]]:
    packets = byte_count = 0
    families = set()
    untracked = set()
    for entry in _entries(table):
        rule = entry.get("rule")
        if not isinstance(rule, dict) or rule.get("chain") != "prerouting":
            continue
        if rule.get("family", "inet") != "inet" or rule.get("table", "geolatch") != "geolatch":
            continue
        comment = rule.get("comment", "")
        match = _COUNTRY_COMMENT.fullmatch(comment) if isinstance(comment, str) else None
        if match is None:
            continue
        family = int(match[1])
        expressions = rule.get("expr")
        if not isinstance(expressions, list):
            raise StatisticsError("Invalid country-rule expressions")
        # Both legacy direct drops and the instrumented family drop chains are
        # supported. A similarly labelled accept/log rule is not a DROP count.
        direct_drop = any(
            isinstance(expression, dict) and "drop" in expression for expression in expressions
        )
        tracked_drop = any(
            isinstance(expression, dict)
            and expression.get("jump") == {"target": DROP_CHAINS[family]}
            for expression in expressions
        )
        if not direct_drop and not tracked_drop:
            continue
        counters = [
            expression["counter"]
            for expression in expressions
            if isinstance(expression, dict) and "counter" in expression
        ]
        if len(counters) != 1 or not isinstance(counters[0], dict):
            raise StatisticsError("Missing or malformed country-rule counter")
        packets += _nonnegative_integer(counters[0].get("packets"), "packet counter")
        byte_count += _nonnegative_integer(counters[0].get("bytes"), "byte counter")
        families.add(family)
        # Legacy direct DROP rules never populate the source sets. The mere
        # presence of a similarly named set cannot turn them into unique-IP
        # history, including a mixture of legacy and instrumented rules.
        if direct_drop:
            untracked.add(family)
    return packets, byte_count, families, untracked


def tracking_families(table: dict[str, Any]) -> set[int]:
    """Families with actual GeoLatch drop rules, not merely enabled IP flags."""
    return _country_counters(table)[2]


def tracking_definitions(table: dict[str, Any]) -> dict[int, dict]:
    result = {}
    for entry in _entries(table):
        definition = entry.get("set")
        if not isinstance(definition, dict):
            continue
        for family, name in TRACKING_SETS.items():
            if definition.get("name") != name:
                continue
            if (
                definition.get("family", "inet") != "inet"
                or definition.get("table", "geolatch") != "geolatch"
            ):
                continue
            if family in result:
                raise StatisticsError("Duplicate unique-source tracking set")
            result[family] = definition
    return result


def _source_address(element: Any, family: int) -> tuple[int, int]:
    # nft 1.0.x normally uses bare address strings. Element metadata can wrap
    # the value in {"elem":{"val":...}} on other JSON-schema versions.
    if isinstance(element, dict) and set(element) == {"elem"}:
        metadata = element["elem"]
        if not isinstance(metadata, dict) or "timeout" in metadata or "expires" in metadata:
            raise StatisticsError("Unexpected expiring unique-source element")
        element = metadata.get("val")
    if isinstance(element, dict) and set(element) == {"prefix"}:
        prefix = element["prefix"]
        if not isinstance(prefix, dict) or prefix.get("len") != (32 if family == 4 else 128):
            raise StatisticsError("A unique-source set contains a range instead of an address")
        element = prefix.get("addr")
    if not isinstance(element, str) or "%" in element:
        raise StatisticsError("Invalid unique-source address element")
    try:
        address = ipaddress.ip_address(element)
    except ValueError:
        # ipaddress's exception embeds its input; source addresses must not
        # appear in a diagnostic traceback for an unavailable counter either.
        raise StatisticsError("Invalid unique-source address element") from None
    if address.version != family:
        raise StatisticsError("Wrong address family in unique-source set")
    return address.version, int(address)


def _cardinality(definition: dict, family: int) -> tuple[int, bool]:
    if definition.get("type") != f"ipv{family}_addr":
        raise StatisticsError("Wrong unique-source set datatype")
    flags = definition.get("flags", [])
    if (
        not isinstance(flags, list)
        or not all(isinstance(flag, str) for flag in flags)
        or "interval" in flags
        or "timeout" in flags
        or definition.get("timeout")
    ):
        raise StatisticsError("Unique-source tracking must contain nonexpiring exact addresses")
    capacity = _nonnegative_integer(
        definition.get("size", UNIQUE_IP_CAPACITY), "source-set capacity"
    )
    if not 0 < capacity <= UNIQUE_IP_CAPACITY:
        raise StatisticsError("Unique-source tracking capacity is outside the supported bound")
    elements = definition.get("elem", [])
    if not isinstance(elements, list):
        raise StatisticsError("Invalid unique-source element list")
    addresses = {_source_address(element, family) for element in elements}
    if len(addresses) > capacity:
        raise StatisticsError("Unique-source tracking exceeds its declared capacity")
    return len(addresses), len(addresses) == capacity


def _tracking_missed_sources(table: dict[str, Any], families: set[int]) -> bool:
    """A failed insertion makes cardinality a lower bound until replacement.

    A temporary allocation failure can happen before the set reaches capacity.
    The dedicated fallback DROP rule records that event in a sticky kernel
    counter, so a later successful insertion must not restore false precision.
    """
    missed = False
    for entry in _entries(table):
        rule = entry.get("rule")
        if not isinstance(rule, dict):
            continue
        if rule.get("family", "inet") != "inet" or rule.get("table", "geolatch") != "geolatch":
            continue
        for family in families:
            if (
                rule.get("chain") != DROP_CHAINS[family]
                or rule.get("comment") != f"GeoLatch tracking failure family={family}"
            ):
                continue
            expressions = rule.get("expr")
            if not isinstance(expressions, list) or not any(
                isinstance(expression, dict) and "drop" in expression for expression in expressions
            ):
                raise StatisticsError("Missing or malformed tracking-failure DROP rule")
            counters = [
                expression["counter"]
                for expression in expressions
                if isinstance(expression, dict) and "counter" in expression
            ]
            if len(counters) != 1 or not isinstance(counters[0], dict):
                raise StatisticsError("Missing or malformed tracking-failure counter")
            failures = _nonnegative_integer(counters[0].get("packets"), "tracking-failure counter")
            _nonnegative_integer(counters[0].get("bytes"), "tracking-failure byte counter")
            missed |= failures > 0
    return missed


def aggregate_stats(table: dict[str, Any] | None) -> dict[str, Any]:
    """Summarize an owned full kernel table, without leaking source addresses.

    None denotes positively verified table absence, not a failed read. Missing
    tracking sets on a legacy ruleset cannot reconstruct historical unique IPs.
    At capacity or after any failed insertion the result remains a lower bound:
    packet drops continue independently of whether their source was recorded.
    """
    if table is None:
        return {
            "unique_ips": 0,
            "unique_limit_reached": False,
            "tracking_available": True,
            "dropped_packets": 0,
            "dropped_bytes": 0,
            "counter_error": None,
        }
    packets, byte_count, families, untracked = _country_counters(table)
    definitions = tracking_definitions(table)
    if untracked or not families <= definitions.keys():
        return {
            "unique_ips": None,
            "unique_limit_reached": False,
            "tracking_available": False,
            "dropped_packets": packets,
            "dropped_bytes": byte_count,
            "counter_error": "tracking_not_enabled",
        }
    unique = 0
    limited = _tracking_missed_sources(table, families)
    for family in families:
        count, reached = _cardinality(definitions[family], family)
        unique += count
        limited |= reached
    return {
        "unique_ips": unique,
        "unique_limit_reached": limited,
        "tracking_available": True,
        "dropped_packets": packets,
        "dropped_bytes": byte_count,
        "counter_error": None,
    }
