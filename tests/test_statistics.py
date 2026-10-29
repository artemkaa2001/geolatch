"""Actual source-set cardinality stays distinct from cumulative packet totals."""

from __future__ import annotations

import copy
import json

import pytest

from geolatch.statistics import (
    DROP_CHAINS,
    TRACKING_SETS,
    UNIQUE_IP_CAPACITY,
    StatisticsError,
    aggregate_stats,
    tracking_definitions,
    tracking_families,
)


def country_rule(family=4, *, packets=100, byte_count=6000, direct=False):
    return {
        "rule": {
            "family": "inet",
            "table": "geolatch",
            "chain": "prerouting",
            "comment": f"GeoLatch country=IR family={family}",
            "expr": [
                {"counter": {"packets": packets, "bytes": byte_count}},
                {"drop": None} if direct else {"jump": {"target": DROP_CHAINS[family]}},
            ],
        }
    }


def source_set(family=4, elements=None, *, size=UNIQUE_IP_CAPACITY):
    return {
        "set": {
            "family": "inet",
            "table": "geolatch",
            "name": TRACKING_SETS[family],
            "type": f"ipv{family}_addr",
            "flags": ["dynamic"],
            "size": size,
            "elem": [] if elements is None else elements,
        }
    }


def tracking_failure_rule(family=4, *, packets=0, byte_count=0):
    return {
        "rule": {
            "family": "inet",
            "table": "geolatch",
            "chain": DROP_CHAINS[family],
            "comment": f"GeoLatch tracking failure family={family}",
            "expr": [{"counter": {"packets": packets, "bytes": byte_count}}, {"drop": None}],
        }
    }


def table(*entries):
    return {"nftables": list(entries)}


def test_packets_are_never_reported_as_unique_ips_and_addresses_stay_private():
    actual = table(
        country_rule(packets=9042, byte_count=701042),
        source_set(elements=["198.51.100.8", "198.51.100.9"]),
    )
    summary = aggregate_stats(actual)
    assert summary == {
        "unique_ips": 2,
        "unique_limit_reached": False,
        "tracking_available": True,
        "dropped_packets": 9042,
        "dropped_bytes": 701042,
        "counter_error": None,
    }
    assert "198.51.100" not in json.dumps(summary)
    actual["nftables"][0]["rule"]["expr"][0]["counter"]["packets"] += 100
    assert aggregate_stats(actual)["unique_ips"] == 2


def test_deduplicates_source_across_country_destination_and_ipv6_spelling():
    actual = table(
        country_rule(packets=3),
        country_rule(packets=5),
        country_rule(6, packets=7),
        source_set(elements=["198.51.100.8"]),
        source_set(6, ["2001:db8::1", "2001:0db8:0:0::1", "2001:db8::2"]),
    )
    summary = aggregate_stats(actual)
    assert summary["unique_ips"] == 3
    assert summary["dropped_packets"] == 15
    assert tracking_families(actual) == {4, 6}
    assert set(tracking_definitions(actual)) == {4, 6}


@pytest.mark.parametrize(
    "element",
    [
        "198.51.100.8",
        {"elem": {"val": "198.51.100.8"}},
        {"prefix": {"addr": "198.51.100.8", "len": 32}},
        {"elem": {"val": {"prefix": {"addr": "198.51.100.8", "len": 32}}}},
    ],
)
def test_historical_json_shapes_count_exact_source_elements(element):
    assert aggregate_stats(table(country_rule(), source_set(elements=[element])))["unique_ips"] == 1


@pytest.mark.parametrize("with_sets", [False, True])
def test_legacy_direct_drop_has_no_unique_history_even_if_named_sets_exist(with_sets):
    entries = [country_rule(direct=True, packets=28)]
    if with_sets:
        entries.append(source_set(elements=["198.51.100.8"]))
    summary = aggregate_stats(table(*entries))
    assert summary["unique_ips"] is None
    assert summary["tracking_available"] is False
    assert summary["counter_error"] == "tracking_not_enabled"
    assert summary["dropped_packets"] == 28


def test_partial_family_tracking_does_not_report_incomplete_total_as_exact():
    summary = aggregate_stats(table(country_rule(), country_rule(6), source_set()))
    assert summary["unique_ips"] is None
    assert summary["dropped_packets"] == 200


def test_no_table_or_no_drop_rules_are_verified_zero():
    for actual in (None, table(), table(source_set())):
        summary = aggregate_stats(actual)
        assert summary["unique_ips"] == summary["dropped_packets"] == summary["dropped_bytes"] == 0
        assert summary["tracking_available"] is True


def test_counter_totals_ignore_foreign_accept_and_non_country_rules():
    ignored = []
    for change in (
        {"chain": "another"},
        {"family": "ip"},
        {"table": "another"},
        {"comment": "not a country drop"},
        {"expr": [{"counter": {"packets": 999, "bytes": 999}}, {"accept": None}]},
    ):
        entry = country_rule(packets=999)
        entry["rule"].update(change)
        ignored.append(entry)
    actual = table(country_rule(packets=4), source_set(), *ignored)
    assert aggregate_stats(actual)["dropped_packets"] == 4


@pytest.mark.parametrize("bad", [{}, [], {"nftables": {}}, {"nftables": [None]}])
def test_malformed_schema_never_returns_a_false_zero(bad):
    with pytest.raises(StatisticsError):
        aggregate_stats(bad)


@pytest.mark.parametrize("value", [-1, 1.5, True, "17", None])
@pytest.mark.parametrize("field", ["packets", "bytes"])
def test_invalid_kernel_counter_is_unavailable(value, field):
    rule = country_rule()
    rule["rule"]["expr"][0]["counter"][field] = value
    with pytest.raises(StatisticsError):
        aggregate_stats(table(rule, source_set()))


@pytest.mark.parametrize(
    "element",
    [
        "198.51.100.8/24",
        "2001:db8::1",
        "198.51.100.8%eth0",
        123,
        {"range": ["198.51.100.8", "198.51.100.9"]},
        {"prefix": {"addr": "198.51.100.8", "len": 24}},
        {"elem": {"val": "198.51.100.8", "expires": 2}},
        {"elem": {"val": "198.51.100.8", "timeout": 5}},
        {"elem": None},
    ],
)
def test_malformed_ranged_or_expiring_elements_cannot_be_miscounted(element):
    with pytest.raises(StatisticsError) as error:
        aggregate_stats(table(country_rule(), source_set(elements=[element])))
    assert "198.51.100.8" not in str(error.value)


@pytest.mark.parametrize(
    "change",
    [
        {"type": "ipv6_addr"},
        {"flags": ["interval"]},
        {"flags": ["timeout"]},
        {"flags": "dynamic"},
        {"flags": [123]},
        {"timeout": 5},
        {"size": 0},
        {"size": -1},
        {"size": True},
        {"size": UNIQUE_IP_CAPACITY + 1},
        {"elem": {}},
    ],
)
def test_malformed_set_definition_is_unavailable(change):
    definition = source_set()
    definition["set"].update(change)
    with pytest.raises(StatisticsError):
        aggregate_stats(table(country_rule(), definition))


def test_capacity_is_a_lower_bound_and_overfull_schema_is_an_error():
    definition = source_set(elements=["198.51.100.8", "198.51.100.9"], size=2)
    summary = aggregate_stats(table(country_rule(), definition))
    assert summary["unique_ips"] == 2
    assert summary["unique_limit_reached"] is True
    definition["set"]["elem"].append("198.51.100.10")
    with pytest.raises(StatisticsError):
        aggregate_stats(table(country_rule(), definition))


def test_duplicate_set_definition_is_an_error():
    definition = source_set()
    with pytest.raises(StatisticsError):
        aggregate_stats(table(country_rule(), definition, copy.deepcopy(definition)))


@pytest.mark.parametrize("family, source", [(4, "198.51.100.8"), (6, "2001:db8::8")])
def test_failed_insertion_below_capacity_remains_a_lower_bound(family, source):
    failure = tracking_failure_rule(family, packets=1, byte_count=60)
    definition = source_set(family, [source])
    actual = table(country_rule(family, packets=2), definition, failure)
    summary = aggregate_stats(actual)
    assert summary["unique_ips"] == 1
    assert summary["unique_limit_reached"] is True
    assert summary["dropped_packets"] == 2  # The fallback is not counted a second time.
    # Later successful insertions do not erase the failure already observed.
    definition["set"]["elem"].append("198.51.100.9" if family == 4 else "2001:db8::9")
    assert aggregate_stats(actual)["unique_ips"] == 2
    assert aggregate_stats(actual)["unique_limit_reached"] is True


def test_unused_failure_counter_preserves_exact_cardinality():
    summary = aggregate_stats(table(country_rule(), source_set(), tracking_failure_rule()))
    assert summary["unique_ips"] == 0
    assert summary["unique_limit_reached"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"family": "ip"},
        {"table": "other"},
        {"chain": "other"},
        {"comment": "not a tracking-failure rule"},
    ],
)
def test_unrelated_failure_like_rules_do_not_mark_lower_bound(change):
    failure = tracking_failure_rule(packets=99)
    failure["rule"].update(change)
    assert not aggregate_stats(table(country_rule(), source_set(), failure))["unique_limit_reached"]


def test_inactive_family_failures_do_not_mark_another_family_lower_bound():
    summary = aggregate_stats(
        table(country_rule(), source_set(), tracking_failure_rule(6, packets=1))
    )
    assert summary["unique_limit_reached"] is False


@pytest.mark.parametrize("value", [-1, True, None, "1"])
@pytest.mark.parametrize("field", ["packets", "bytes"])
def test_malformed_tracking_failure_counter_never_claims_exact(value, field):
    failure = tracking_failure_rule()
    failure["rule"]["expr"][0]["counter"][field] = value
    with pytest.raises(StatisticsError):
        aggregate_stats(table(country_rule(), source_set(), failure))


@pytest.mark.parametrize(
    "expressions", [None, [{"drop": None}], [{"counter": None}, {"drop": None}]]
)
def test_malformed_tracking_failure_rule_is_unavailable(expressions):
    failure = tracking_failure_rule()
    failure["rule"]["expr"] = expressions
    with pytest.raises(StatisticsError):
        aggregate_stats(table(country_rule(), source_set(), failure))
