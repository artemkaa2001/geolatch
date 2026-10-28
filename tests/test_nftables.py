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
    drops = [line for line in rules.splitlines() if "counter drop" in line]
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
        "ct direction original" in line for line in rules.splitlines() if "counter drop" in line
    )


def test_allowlist_only_returns_from_owned_chain(configuration, databases):
    configuration["allowlist"]["ipv4"] = ["198.51.100.8/32"]
    configuration["allowlist"]["ipv6"] = ["2001:db8:1::8/128"]
    rules = generate_rules(configuration, databases)
    assert "ip saddr @allow_v4 return" in rules
    assert "ip6 saddr @allow_v6 return" in rules
    assert "saddr @allow_v4 accept" not in rules
    assert rules.index("saddr @allow_v4 return") < rules.index("counter drop")


def test_disabled_policies_and_families_require_no_unused_database(configuration, databases):
    configuration["network"]["ipv6"] = False
    configuration["policies"][1]["enabled"] = False
    rules = generate_rules(configuration, {"IR:4": databases["IR:4"]})
    assert "geo_ir_v4" in rules
    assert "geo_ir_v6" not in rules and "geo_cn_v4" not in rules
    configuration["enabled"] = False
    assert "counter drop" not in generate_rules(configuration, {})


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
