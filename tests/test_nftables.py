"""Security and transaction invariants; real packet tests live in integration."""

from __future__ import annotations

import json
import subprocess

import pytest

from geolatch.config import ConfigError, default_config
from geolatch.firewall import generate_rules
from geolatch.nftables import OWNER, Nftables, NftError, _validate_table


@pytest.fixture
def configuration():
    config = default_config()
    config["network"]["interfaces"] = ["eth0"]
    config["policies"] = [
        {
            "name": "first",
            "enabled": True,
            "destinations": ["203.0.113.10", "2001:db8::10"],
            "block_countries": ["IR"],
        },
        {
            "name": "second",
            "enabled": True,
            "destinations": ["203.0.113.20"],
            "block_countries": ["IR", "CN"],
        },
    ]
    return config


@pytest.fixture
def databases():
    return {
        "IR:4": ["198.51.100.0/25", "198.51.100.128/25"],
        "IR:6": ["2001:db8:1::/48"],
        "CN:4": ["192.0.2.0/24"],
    }


def test_rules_limit_scope_and_share_country_sets(configuration, databases):
    rules = generate_rules(configuration, databases)
    assert rules.startswith("table inet geolatch {")
    assert 'comment "GeoLatch managed table v1"' in rules
    assert "hook prerouting priority -150" in rules
    assert "198.51.100.0/24" in rules  # Adjacent CIDRs are collapsed.
    assert rules.count("set geo_ir_v4") == 1
    assert rules.count("saddr @geo_ir_v4") == 1  # Union across overlapping policies.
    assert "203.0.113.10, 203.0.113.20" in rules
    assert "203.0.113.30" not in rules
    drops = [line for line in rules.splitlines() if "counter jump geolatch_drop" in line]
    assert len(drops) == 3
    assert all("iifname @ingress" in line and "daddr @dst_" in line for line in drops)
    assert all("ct direction original ct state new" in line for line in drops)
    assert "flush ruleset" not in rules and " accept\n" not in rules


def test_established_and_ipv6_control_traffic_are_preserved(configuration, databases):
    rules = generate_rules(configuration, databases)
    assert "ct state { established, related } return" in rules
    assert "ct direction reply return" in rules
    for vital_type in (
        "packet-too-big",
        "nd-router-solicit",
        "nd-neighbor-solicit",
        "nd-neighbor-advert",
    ):
        assert vital_type in rules
    configuration["firewall"]["preserve_established"] = False
    rules = generate_rules(configuration, databases)
    assert "ct state new" not in rules
    assert "ct direction reply return" in rules
    assert all(
        "ct direction original" in line
        for line in rules.splitlines()
        if "counter jump geolatch_drop" in line
    )


def test_allowlist_only_returns_from_owned_chain(configuration, databases):
    configuration["allowlist"]["ipv4"] = ["198.51.100.8/32"]
    configuration["allowlist"]["ipv6"] = ["2001:db8:1::8/128"]
    rules = generate_rules(configuration, databases)
    assert "ip saddr @allow_v4 return" in rules
    assert "ip6 saddr @allow_v6 return" in rules
    assert "saddr @allow_v4 accept" not in rules
    assert rules.index("saddr @allow_v4 return") < rules.index("counter jump geolatch_drop")


def test_disabled_policies_and_families_require_no_unused_database(configuration, databases):
    configuration["network"]["ipv6"] = False
    configuration["policies"][1]["enabled"] = False
    rules = generate_rules(configuration, {"IR:4": databases["IR:4"]})
    assert "geo_ir_v4" in rules
    assert "geo_ir_v6" not in rules and "geo_cn_v4" not in rules
    configuration["enabled"] = False
    assert "counter jump geolatch_drop" not in generate_rules(configuration, {})


def test_unique_source_sets_are_bounded_and_a_failed_update_still_reaches_drop(
    configuration, databases
):
    from geolatch.statistics import UNIQUE_IP_CAPACITY

    rules = generate_rules(configuration, databases)
    for family, protocol in ((4, "ip"), (6, "ip6")):
        assert (
            f"    set dropped_sources_v{family} {{\n"
            f"        type ipv{family}_addr\n"
            "        flags dynamic\n"
            f"        size {UNIQUE_IP_CAPACITY}\n"
            "    }"
        ) in rules
        # Set insertion can return NFT_BREAK on a full set or allocation
        # failure. The next rule drops and remembers the failed observation;
        # successful tracking goes straight to the shared final DROP chain.
        assert (
            f"    chain geolatch_drop_v{family} {{\n"
            f"        update @dropped_sources_v{family} {{ {protocol} saddr }} goto geolatch_drop\n"
            f'        counter drop comment "GeoLatch tracking failure family={family}"\n'
            "    }"
        ) in rules
    assert "    chain geolatch_drop {\n        drop\n    }" in rules
    assert "timeout" not in rules


def test_all_destinations_only_selects_public_local_chosen_interface(configuration, databases):
    configuration["policies"] = [configuration["policies"][0]]
    configuration["policies"][0]["destinations"] = "all"
    addresses = [
        {"interface": "eth0", "address": "8.8.8.8", "family": 4, "public": True, "kind": "network"},
        {
            "interface": "eth0",
            "address": "10.0.0.1",
            "family": 4,
            "public": False,
            "kind": "network",
        },
        {
            "interface": "docker0",
            "address": "1.1.1.1",
            "family": 4,
            "public": True,
            "kind": "bridge",
        },
    ]
    rules = generate_rules(configuration, databases, addresses)
    assert "8.8.8.8" in rules
    assert "10.0.0.1" not in rules and "1.1.1.1" not in rules


@pytest.mark.parametrize("values", [[], ["0.0.0.0/0"], ["::/0"], ["not-a-cidr"], ["::1/128"]])
def test_missing_corrupt_default_route_or_wrong_family_rejected(configuration, databases, values):
    databases["IR:4"] = values
    with pytest.raises(NftError):
        generate_rules(configuration, databases)


def test_missing_country_data_never_silently_skips_block(configuration, databases):
    databases.pop("IR:6")
    with pytest.raises(NftError, match="IR:6"):
        generate_rules(configuration, databases)


def test_untrusted_interface_and_country_cannot_inject_nft(configuration, databases):
    configuration["network"]["interfaces"] = ['eth0"; delete table inet other; "']
    with pytest.raises(ConfigError):
        generate_rules(configuration, databases)


def test_generation_is_deterministic_and_revision_changes(configuration, databases):
    first = generate_rules(configuration, databases)
    assert first == generate_rules(configuration, databases)
    configuration["policies"][0]["block_countries"] = ["CN"]
    databases["CN:6"] = ["2001:db8:2::/48"]
    second = generate_rules(configuration, databases)

    def revision(rules):
        return next(line for line in rules.splitlines() if "geolatch-revision:" in line)

    assert revision(first) != revision(second)


class FakeNft(Nftables):
    """Model CLI outputs only; this makes no claim about kernel filtering."""

    def __init__(self, table=None):
        super().__init__()
        self.table = table
        self.calls = []
        self.failure = None
        self.bad_revision = False

    def _run(self, arguments, source=None):
        self.calls.append((arguments, source))
        if self.failure:
            raise NftError(self.failure)
        if arguments == ["--json", "list", "tables"]:
            entries = (
                [] if self.table is None else [{"table": {"family": "inet", "name": "geolatch"}}]
            )
            return json.dumps({"nftables": entries})
        if arguments == ["--json", "list", "table", "inet", "geolatch"]:
            return json.dumps(self.table)
        if arguments == ["--file", "-"]:
            if "table inet geolatch {" in source:
                import re

                revision = re.search(r'comment "(geolatch-revision:[0-9a-f]{64})"', source)
                self.table = owned_table()
                if revision:
                    self.table["nftables"].append(
                        {
                            "chain": {
                                "name": "prerouting",
                                "comment": "bad" if self.bad_revision else revision[1],
                            }
                        }
                    )
            else:
                self.table = None
        return ""


def owned_table():
    return {"nftables": [{"table": {"family": "inet", "name": "geolatch", "comment": OWNER}}]}


def test_missing_table_requires_successful_kernel_read():
    backend = FakeNft()
    assert backend.inspect() is None
    backend.failure = "Operation not permitted"
    with pytest.raises(NftError, match="not permitted"):
        backend.inspect()


def test_foreign_name_collision_is_not_owned_and_cannot_be_deleted():
    backend = FakeNft({"nftables": [{"table": {"family": "inet", "name": "geolatch"}}]})
    with pytest.raises(NftError, match="not owned"):
        backend.apply(None)
    assert not any(arguments == ["--file", "-"] for arguments, _ in backend.calls)


def test_replacement_is_one_batch_and_check_never_applies(configuration, databases):
    backend = FakeNft(owned_table())
    rules = generate_rules(configuration, databases)
    backend.check(rules)
    assert not any(arguments == ["--file", "-"] for arguments, _ in backend.calls)
    backend.apply(rules)
    writes = [source for arguments, source in backend.calls if arguments == ["--file", "-"]]
    assert writes == ["delete table inet geolatch\n" + rules]
    assert "flush ruleset" not in writes[0]


def test_new_table_is_applied_without_delete(configuration, databases):
    backend = FakeNft()
    rules = generate_rules(configuration, databases)
    backend.apply(rules)
    writes = [source for arguments, source in backend.calls if arguments == ["--file", "-"]]
    assert writes == [rules]


def test_disable_only_removes_owned_table_and_is_idempotent():
    backend = FakeNft(owned_table())
    backend.apply(None)
    backend.apply(None)
    assert [source for arguments, source in backend.calls if arguments == ["--file", "-"]] == [
        "delete table inet geolatch\n"
    ]


def test_actual_revision_is_checked(configuration, databases):
    backend = FakeNft()
    backend.bad_revision = True
    with pytest.raises(NftError, match="revision"):
        backend.apply(generate_rules(configuration, databases))


@pytest.mark.parametrize(
    "source",
    [
        "flush ruleset",
        'table ip geolatch { comment "GeoLatch managed table v1" }',
        'table inet geolatch { comment "GeoLatch managed table v1" }\ndelete table inet other',
        'table inet geolatch { comment "GeoLatch managed table v1"\n include "/etc/nftables.conf"\n}',
        'table inet geolatch { comment "GeoLatch managed table v1"',
        'table inet geolatch { chain x { comment "GeoLatch managed table v1" } }',
    ],
)
def test_snapshot_cannot_escape_owned_table(source):
    with pytest.raises(NftError):
        _validate_table(source)


def test_counters_come_from_kernel_json():
    table = owned_table()
    table["nftables"].append(
        {
            "rule": {
                "chain": "prerouting",
                "handle": 17,
                "comment": "GeoLatch country=IR family=4",
                "expr": [{"counter": {"packets": 13, "bytes": 1007}}, {"drop": None}],
            }
        }
    )
    assert FakeNft(table).counters() == [
        {
            "chain": "prerouting",
            "handle": 17,
            "comment": "GeoLatch country=IR family=4",
            "packets": 13,
            "bytes": 1007,
        }
    ]


def test_subprocess_is_bounded_and_uses_no_shell(monkeypatch):
    def run(arguments, **kwargs):
        assert arguments == ["/usr/sbin/nft", "--json", "list", "tables"]
        assert "shell" not in kwargs
        assert kwargs["timeout"] == 7 and kwargs["env"]["LC_ALL"] == "C"
        return subprocess.CompletedProcess(arguments, 0, '{"nftables": []}', "")

    monkeypatch.setattr(subprocess, "run", run)
    assert Nftables("/usr/sbin/nft", timeout=7).inspect() is None


@pytest.mark.parametrize("output", ["[]", '{"nftables": {}}', "garbage"])
def test_malformed_kernel_output_is_an_error(monkeypatch, output):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda arguments, **kwargs: subprocess.CompletedProcess(arguments, 0, output, ""),
    )
    with pytest.raises(NftError, match="JSON"):
        Nftables().inspect()


@pytest.mark.parametrize("entries", [[None], [{"table": {}}], [{"unknown": {}}]])
def test_corrupt_table_listing_is_not_evidence_of_absence(monkeypatch, entries):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda arguments, **kwargs: subprocess.CompletedProcess(
            arguments, 0, json.dumps({"nftables": entries}), ""
        ),
    )
    with pytest.raises(NftError, match="invalid table listing"):
        Nftables().inspect()


def statistics_table():
    """CLI schema fixture; packet traversal is exercised in namespace tests."""
    from geolatch.statistics import TRACKING_SETS

    result = owned_table()
    result["nftables"][0]["table"]["handle"] = 10
    result["nftables"].append(
        {
            "chain": {
                "family": "inet",
                "table": "geolatch",
                "name": "prerouting",
                "handle": 20,
                "comment": "geolatch-revision:" + "a" * 64,
            }
        }
    )
    for family, address in ((4, "198.51.100.1"), (6, "2001:db8:1::1")):
        result["nftables"].extend(
            [
                {
                    "set": {
                        "family": "inet",
                        "table": "geolatch",
                        "name": TRACKING_SETS[family],
                        "handle": 30 + family,
                        "type": f"ipv{family}_addr",
                        "flags": ["dynamic"],
                        "size": 65536,
                        "elem": [address],
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "geolatch",
                        "chain": "prerouting",
                        "comment": f"GeoLatch country=IR family={family}",
                        "expr": [
                            {"counter": {"packets": family * 10, "bytes": family * 100}},
                            {"jump": {"target": f"geolatch_drop_v{family}"}},
                        ],
                    }
                },
            ]
        )
    return result


class StatisticsNft(Nftables):
    def __init__(self):
        super().__init__()
        self.table = statistics_table()
        self.calls = []
        self.terse_reads = 0
        self.replace = False
        self.disappear = False
        self.legacy = False
        self.wrong_set = False
        self.bad_set = False
        self.omit_comments = False

    def _run(self, arguments, source=None):
        import copy

        self.calls.append(arguments)
        if arguments == ["--json", "list", "tables"]:
            return json.dumps({"nftables": [{"table": {"family": "inet", "name": "geolatch"}}]})
        if arguments == ["--json", "--terse", "list", "table", "inet", "geolatch"]:
            self.terse_reads += 1
            result = copy.deepcopy(self.table)
            if self.disappear and self.terse_reads > 1:
                raise NftError("No such file or directory")
            if self.replace and self.terse_reads > 1:
                result["nftables"][0]["table"]["handle"] += 1
            for entry in result["nftables"]:
                if "set" in entry:
                    entry["set"].pop("elem", None)
                if self.omit_comments:
                    for kind in ("table", "chain"):
                        if kind in entry:
                            entry[kind].pop("comment", None)
                if "rule" in entry:
                    if self.legacy:
                        entry["rule"]["expr"][-1] = {"drop": None}
                    if self.terse_reads > 1:
                        entry["rule"]["expr"][0]["counter"]["packets"] += 1
            if self.legacy:
                result["nftables"] = [entry for entry in result["nftables"] if "set" not in entry]
            return json.dumps(result)
        if arguments[:5] == ["--json", "list", "set", "inet", "geolatch"]:
            name = arguments[-1]
            result = {
                "nftables": [
                    copy.deepcopy(entry)
                    for entry in self.table["nftables"]
                    if entry.get("set", {}).get("name") == name
                ]
            }
            if self.wrong_set:
                result["nftables"][0]["set"]["name"] = "unrelated"
            if self.bad_set:
                result["nftables"][0]["set"]["elem"] = ["sensitive-invalid-address"]
            return json.dumps(result)
        if arguments == ["--terse", "list", "table", "inet", "geolatch"]:
            return (
                f'table inet geolatch {{\n comment "{OWNER}"\n'
                f' chain prerouting {{\n comment "geolatch-revision:{"a" * 64}"\n }}\n}}\n'
            )
        raise AssertionError(f"Unexpected statistics command: {arguments}")


def test_unique_traffic_stats_query_only_tracking_sets_and_use_final_counters():
    backend = StatisticsNft()
    result = backend.traffic_stats()
    assert result == {
        "unique_ips": 2,
        "unique_limit_reached": False,
        "tracking_available": True,
        "dropped_packets": 102,
        "dropped_bytes": 1000,
        "counter_error": None,
    }
    assert backend.terse_reads == 2
    assert [call[-1] for call in backend.calls if call[:3] == ["--json", "list", "set"]] == [
        "dropped_sources_v4",
        "dropped_sources_v6",
    ]
    assert not any(
        call == ["--json", "list", "table", "inet", "geolatch"] or "geo_ir" in " ".join(call)
        for call in backend.calls
    )
    assert "198.51.100.1" not in json.dumps(result)
    assert "2001:db8" not in json.dumps(result)


def test_existing_full_inspection_is_reused_without_any_command():
    backend = StatisticsNft()
    result = backend.traffic_stats(backend.table)
    assert result["unique_ips"] == 2 and result["dropped_packets"] == 100
    assert backend.traffic_stats(None)["unique_ips"] == 0
    assert backend.calls == []


def test_unique_stats_use_terse_text_for_legacy_comment_ownership():
    backend = StatisticsNft()
    backend.omit_comments = True
    assert backend.traffic_stats()["unique_ips"] == 2
    assert backend.calls.count(["--terse", "list", "table", "inet", "geolatch"]) == 2


def test_legacy_rules_do_not_turn_packet_count_into_unique_ip_count():
    backend = StatisticsNft()
    backend.legacy = True
    result = backend.traffic_stats()
    assert result["unique_ips"] is None and result["dropped_packets"] == 100
    assert result["counter_error"] == "tracking_not_enabled"
    assert backend.terse_reads == 1
    assert not any(call[:3] == ["--json", "list", "set"] for call in backend.calls)


def test_identical_rules_replacement_during_polling_is_not_one_epoch():
    backend = StatisticsNft()
    backend.replace = True
    with pytest.raises(NftError, match="epoch changed"):
        backend.traffic_stats()


def test_table_disappearing_during_polling_is_not_a_false_zero():
    backend = StatisticsNft()
    backend.disappear = True
    with pytest.raises(NftError):
        backend.traffic_stats()


def test_tracking_set_must_be_the_requested_unchanged_set():
    backend = StatisticsNft()
    backend.wrong_set = True
    with pytest.raises(NftError, match="statistics set changed"):
        backend.traffic_stats()


def test_malformed_source_stats_raise_an_error_without_leaking_address():
    backend = StatisticsNft()
    backend.bad_set = True
    with pytest.raises(NftError, match="source address") as caught:
        backend.traffic_stats()
    assert "sensitive-invalid-address" not in str(caught.value)


def test_polling_requires_successful_absence_read_and_never_masks_permissions():
    backend = FakeNft()
    assert backend.traffic_stats()["unique_ips"] == 0
    backend.failure = "Operation not permitted"
    with pytest.raises(NftError, match="not permitted"):
        backend.traffic_stats()
