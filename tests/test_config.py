"""Configuration must fail closed without silently coercing operator input."""

import copy
import os

import pytest

from geolatch.config import ConfigError, default_config, load_config, save_config, validate_config


def policy_config():
    config = default_config()
    config["network"]["interfaces"] = ["ens3"]
    config["policies"] = [
        {
            "name": "primary",
            "enabled": True,
            "destinations": ["203.0.113.10", "2001:db8::10"],
            "block_countries": ["IR", "PK"],
        }
    ]
    return config


def test_default_has_no_active_policies_and_is_fresh():
    config = default_config()
    config["network"]["interfaces"].append("ens3")
    assert default_config()["network"]["interfaces"] == []
    assert validate_config(default_config()) == default_config()


def test_roundtrip_is_atomic_and_readable_but_not_writable_by_others(tmp_path):
    path = tmp_path / "config.yaml"
    config = policy_config()
    save_config(config, path)
    assert load_config(path) == config
    assert path.stat().st_mode & 0o777 == 0o644
    assert list(tmp_path.iterdir()) == [path]
    assert load_config(tmp_path / "missing.yaml") == default_config()


def test_new_config_directory_is_readable_but_not_writable_by_others(tmp_path):
    path = tmp_path / "etc-geolatch" / "config.yaml"
    save_config(default_config(), path)
    assert path.parent.stat().st_mode & 0o777 == 0o755
    assert path.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("mode", [0o777, 0o775, 0o707])
def test_save_rejects_parent_writable_by_another_user(tmp_path, mode):
    parent = tmp_path / "unsafe"
    parent.mkdir(mode=0o755)
    parent.chmod(mode)
    with pytest.raises(PermissionError):
        save_config(default_config(), parent / "config.yaml")
    assert not (parent / "config.yaml").exists()


def test_save_rejects_parent_symbolic_link(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "link"
    link.symlink_to(actual, target_is_directory=True)
    with pytest.raises(PermissionError):
        save_config(default_config(), link / "config.yaml")
    assert not (actual / "config.yaml").exists()


def test_save_does_not_change_existing_private_directory(tmp_path):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    save_config(default_config(), parent / "config.yaml")
    assert parent.stat().st_mode & 0o777 == 0o700


def test_privileged_save_rejects_parent_not_owned_by_caller(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: tmp_path.stat().st_uid + 1)
    with pytest.raises(PermissionError):
        save_config(default_config(), tmp_path / "config.yaml")


def test_load_rejects_group_writable_configuration(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("version: 1")
    path.chmod(0o664)
    with pytest.raises(ConfigError, match="writable"):
        load_config(path)


def test_privileged_load_requires_root_owned_configuration(tmp_path, monkeypatch):
    if tmp_path.stat().st_uid == 0:
        pytest.skip("requires an unprivileged-owned fixture directory")
    path = tmp_path / "config.yaml"
    path.write_text("version: 1")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(ConfigError, match="root-owned"):
        load_config(path)


def test_allowlist_cannot_hide_default_route_in_two_halves():
    config = default_config()
    config["allowlist"]["ipv4"] = ["0.0.0.0/1", "128.0.0.0/1"]
    with pytest.raises(ConfigError):
        validate_config(config)


def test_save_does_not_replace_valid_config_on_validation_error(tmp_path):
    path = tmp_path / "config.yaml"
    config = policy_config()
    save_config(config, path)
    original = path.read_bytes()
    config["policies"][0]["destinations"] = ["0.0.0.0/0"]
    with pytest.raises(ConfigError):
        save_config(config, path)
    assert path.read_bytes() == original


def test_symlink_save_is_rejected(tmp_path):
    actual = tmp_path / "actual"
    actual.write_text("preserve")
    link = tmp_path / "config.yaml"
    link.symlink_to(actual)
    with pytest.raises(ConfigError):
        save_config(default_config(), link)
    assert actual.read_text() == "preserve"


@pytest.mark.parametrize(
    "value", [None, [], "text", {"version": 2}, {"version": True}, {"unexpected": 1}]
)
def test_invalid_top_level_rejected(value):
    with pytest.raises(ConfigError):
        validate_config(value)


@pytest.mark.parametrize(
    "section,field,value",
    [
        (None, "enabled", "true"),
        (None, "language", "fr"),
        (None, "source", "unknown"),
        ("network", "ipv4", 1),
        ("network", "ipv6", "false"),
        ("updates", "enabled", "yes"),
        ("updates", "interval", "minutely"),
        ("firewall", "action", "accept"),
        ("firewall", "preserve_established", 0),
        ("network", "interfaces", "ens3"),
        ("network", "interfaces", ['ens3"; drop']),
        ("network", "interfaces", ["x" * 16]),
        ("allowlist", "ipv4", ["::1"]),
        ("allowlist", "ipv6", ["0.0.0.0/0"]),
        ("allowlist", "ipv4", ["0.0.0.0/0"]),
        ("allowlist", "ipv6", ["::/0"]),
        ("allowlist", "ipv4", [True]),
    ],
)
def test_invalid_fields_rejected(section, field, value):
    config = policy_config()
    if section:
        config[section][field] = value
    else:
        config[field] = value
    with pytest.raises(ConfigError):
        validate_config(config)


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "invalid name"),
        ("name", "x; delete table"),
        ("name", "-bad"),
        ("enabled", 1),
        ("destinations", []),
        ("destinations", "any"),
        ("destinations", ["1.2.3.0/24"]),
        ("destinations", ["::"]),
        ("destinations", ["127.0.0.1"]),
        ("destinations", ["ff02::1"]),
        ("destinations", ["fe80::1%ens3"]),
        ("destinations", ["169.254.1.1"]),
        ("block_countries", ["XX"]),
        ("block_countries", ["IR; drop"]),
        ("block_countries", [False]),
        ("unknown", "value"),
    ],
)
def test_invalid_policies_rejected(field, value):
    config = policy_config()
    config["policies"][0][field] = value
    with pytest.raises(ConfigError):
        validate_config(config)


def test_disabled_family_selection_cannot_disable_everything():
    config = policy_config()
    config["network"].update(ipv4=False, ipv6=False)
    with pytest.raises(ConfigError):
        validate_config(config)


def test_normalize_deduplicates_without_mutating_caller():
    config = policy_config()
    config["network"]["interfaces"] += ["ens3"]
    config["policies"][0]["block_countries"] = ["ir", "PK", "IR"]
    config["policies"][0]["destinations"] += ["203.0.113.10"]
    config["allowlist"]["ipv4"] = ["198.51.100.128/25", "198.51.100.0/25", "198.51.100.8"]
    before = copy.deepcopy(config)
    result = validate_config(config)
    assert config == before
    assert result["network"]["interfaces"] == ["ens3"]
    assert result["policies"][0]["block_countries"] == ["IR", "PK"]
    assert result["policies"][0]["destinations"] == ["203.0.113.10", "2001:db8::10"]
    assert result["allowlist"]["ipv4"] == ["198.51.100.0/24"]


def test_overlapping_policies_allowed_and_duplicate_names_rejected():
    config = policy_config()
    other = copy.deepcopy(config["policies"][0])
    other.update(name="secondary", block_countries=["CN"])
    config["policies"].append(other)
    assert len(validate_config(config)["policies"]) == 2
    config["policies"][1]["name"] = "primary"
    with pytest.raises(ConfigError):
        validate_config(config)


def test_all_requires_explicit_incoming_interface():
    config = policy_config()
    config["policies"][0]["destinations"] = "all"
    assert validate_config(config)["policies"][0]["destinations"] == "all"
    config["network"]["interfaces"] = []
    with pytest.raises(ConfigError):
        validate_config(config)


@pytest.mark.parametrize(
    "payload",
    [
        "version: 1\nversion: 1\n",
        "language: en\nnetwork:\n  ipv4: true\n  ipv4: false\n",
        "network: &network {ipv4: true}\npolicies: [*network]",
        "!!python/object/apply:os.system ['id']",
        "{invalid",
        "[true]",
        "",
        "version: 999",
        "null",
        "1: foo",
    ],
)
def test_yaml_unsafe_and_ambiguous_documents_rejected(tmp_path, payload):
    path = tmp_path / "config.yaml"
    path.write_text(payload)
    with pytest.raises(ConfigError):
        load_config(path)


def test_yaml_country_no_remains_string(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "version: 1\nnetwork: {interfaces: [ens3]}\npolicies:\n"
        "  - name: primary\n    destinations: [203.0.113.1]\n    block_countries: [NO, IR]\n"
    )
    assert load_config(path)["policies"][0]["block_countries"] == ["NO", "IR"]


def test_file_size_limit(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_bytes(b"#" * (1024 * 1024 + 1))
    with pytest.raises(ConfigError, match="size limit"):
        load_config(path)


def test_yaml_boolean_words_do_not_silently_coerce(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("enabled: yes")
    with pytest.raises(ConfigError):
        load_config(path)


def test_atomic_failure_keeps_original(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    save_config(default_config(), path)
    original = path.read_bytes()

    def fail_replace(*args):
        raise OSError("simulated filesystem failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError):
        save_config(policy_config(), path)
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]
