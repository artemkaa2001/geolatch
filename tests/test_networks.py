import json
import subprocess
from types import SimpleNamespace

import pytest

from geolatch.config import default_config
from geolatch.networks import NetworkError, discover_addresses, resolve_destinations


def test_discovery_supports_real_addresses_and_risk_categories(monkeypatch):
    payload = [
        {
            "ifname": "ens3",
            "addr_info": [
                {"family": "inet", "local": "8.8.8.8"},
                {"family": "inet6", "local": "2001:4860::1"},
                {"family": "inet6", "local": "2001:4860::2", "tentative": True},
                {"family": "inet6", "local": "2001:4860::3", "flags": ["dadfailed"]},
                {"family": "inet", "local": "8.8.4.4", "valid_life_time": 0},
            ],
        },
        {
            "ifname": "lo",
            "link_type": "loopback",
            "addr_info": [{"family": "inet", "local": "127.0.0.1"}],
        },
        {
            "ifname": "docker0",
            "linkinfo": {"info_kind": "bridge"},
            "addr_info": [{"family": "inet", "local": "172.17.0.1"}],
        },
        {"ifname": "wg0", "addr_info": [{"family": "inet", "local": "10.0.0.1"}]},
    ]
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    result = discover_addresses()
    assert len(result) == 5
    public = [item for item in result if item["public"]]
    assert {item["address"] for item in public} == {"8.8.8.8", "2001:4860::1"}
    assert {item["kind"] for item in result} == {"network", "loopback", "tunnel", "bridge"}
    assert calls[0][0] == ["ip", "-j", "-details", "address", "show"]
    assert calls[0][1]["timeout"] == 10


@pytest.mark.parametrize("stdout,code", [("invalid", 0), ("{}", 0), ("[]", 1)])
def test_discovery_failure_is_explicit(monkeypatch, stdout, code):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=code, stdout=stdout, stderr="failure"),
    )
    with pytest.raises(NetworkError):
        discover_addresses()


def test_discovery_missing_iproute2(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("ip")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(NetworkError):
        discover_addresses()


def all_config():
    config = default_config()
    config["network"]["interfaces"] = ["ens3"]
    config["policies"] = [
        {"name": "primary", "enabled": True, "destinations": "all", "block_countries": ["IR"]}
    ]
    return config


def test_all_only_selected_public_local_unicast_destinations():
    addresses = [
        {"interface": "ens3", "address": "8.8.8.8", "family": 4, "public": True},
        {"interface": "ens3", "address": "2001:4860::1", "family": 6, "public": True},
        {"interface": "ens3", "address": "10.0.0.1", "family": 4, "public": False},
        {"interface": "ens4", "address": "1.1.1.1", "family": 4, "public": True},
    ]
    config = all_config()
    assert resolve_destinations(config, addresses) == {"primary": ["8.8.8.8", "2001:4860::1"]}
    config["network"]["ipv6"] = False
    assert resolve_destinations(config, addresses) == {"primary": ["8.8.8.8"]}


def test_no_resolved_address_is_error_instead_of_silent_disable():
    with pytest.raises(NetworkError):
        resolve_destinations(all_config(), [])


def test_explicit_destinations_work_without_discovery(monkeypatch):
    def forbidden_discovery():
        pytest.fail("explicit mode must not depend on discovery")

    monkeypatch.setattr("geolatch.networks.discover_addresses", forbidden_discovery)
    config = all_config()
    config["policies"][0]["destinations"] = ["203.0.113.1", "2001:db8::1"]
    assert resolve_destinations(config) == {"primary": ["203.0.113.1", "2001:db8::1"]}


def test_disabled_policy_does_not_require_discovery():
    config = all_config()
    config["policies"][0]["enabled"] = False
    assert resolve_destinations(config, []) == {}


def test_family_mismatch_does_not_silently_disable_protection():
    config = all_config()
    config["network"]["ipv4"] = False
    config["policies"][0]["destinations"] = ["203.0.113.1"]
    with pytest.raises(NetworkError):
        resolve_destinations(config)
