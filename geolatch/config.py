"""Strict versioned YAML configuration with durable, atomic persistence."""

from __future__ import annotations

import copy
import ipaddress
import os
import re
import stat
from pathlib import Path
from typing import Any

import yaml

from geolatch.i18n import COUNTRY_CODES
from geolatch.utils import atomic_write

CONFIG_PATH = Path("/etc/geolatch/config.yaml")
MAX_CONFIG_BYTES = 1024 * 1024
INTERFACE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,15}\Z")
POLICY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class ConfigError(ValueError):
    """A field-qualified error suitable for localized presentation."""

    key = "error.invalid_config"

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


def default_config() -> dict[str, Any]:
    """Return a fresh, safe configuration without any active filtering policy."""
    return {
        "version": 1,
        "enabled": True,
        "language": "en",
        "source": "ipverse-geo",
        "updates": {"enabled": True, "interval": "daily"},
        "network": {"ipv4": True, "ipv6": True, "interfaces": []},
        "firewall": {"action": "drop", "preserve_established": True},
        "allowlist": {"ipv4": [], "ipv6": []},
        "policies": [],
    }


def _mapping(value: Any, allowed: set[str], field: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{field}: expected a mapping")
    for key in value:
        if not isinstance(key, str) or key not in allowed:
            raise ConfigError(f"{field}: unknown field {key!r}")
    return value


def _boolean(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{field}: expected true or false")
    return value


def _list(value: Any, field: str, maximum: int) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        raise ConfigError(f"{field}: expected a list of at most {maximum} items")
    return value


def _choice(value: Any, choices: tuple[str, ...], field: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ConfigError(f"{field}: expected one of {', '.join(choices)}")
    return value


def _strings(value: Any, field: str, maximum: int) -> list[str]:
    result = _list(value, field, maximum)
    if any(not isinstance(item, str) for item in result):
        raise ConfigError(f"{field}: every item must be a string")
    return result


def validate_config(data: Any) -> dict[str, Any]:
    """Validate and normalize; never change the supplied configuration.

    Overlapping policies are intentionally legal. Their country sets are united
    per destination by the firewall compiler. Explicit unicast destinations can
    be private/documentation addresses, which is useful on NATed servers. The
    caller must warn when an explicit address is not discovered locally.
    """
    defaults = default_config()
    raw = _mapping(data, set(defaults), "config")
    cfg = copy.deepcopy(defaults)
    if type(raw.get("version", 1)) is not int or raw.get("version", 1) != 1:
        raise ConfigError("version: unsupported configuration version (expected 1)")
    cfg["enabled"] = _boolean(raw.get("enabled", True), "enabled")
    cfg["language"] = _choice(raw.get("language", "en"), ("en", "ru"), "language")
    cfg["source"] = _choice(
        raw.get("source", "ipverse-geo"), ("ipverse-geo", "ipverse-rir"), "source"
    )
    updates = _mapping(raw.get("updates", {}), {"enabled", "interval"}, "updates")
    cfg["updates"]["enabled"] = _boolean(updates.get("enabled", True), "updates.enabled")
    cfg["updates"]["interval"] = _choice(
        updates.get("interval", "daily"), ("hourly", "daily", "weekly"), "updates.interval"
    )
    network = _mapping(raw.get("network", {}), {"ipv4", "ipv6", "interfaces"}, "network")
    for family in ("ipv4", "ipv6"):
        cfg["network"][family] = _boolean(network.get(family, True), f"network.{family}")
    if not cfg["network"]["ipv4"] and not cfg["network"]["ipv6"]:
        raise ConfigError("network: at least one IP family must be enabled")
    interfaces = _strings(network.get("interfaces", []), "network.interfaces", 256)
    if any(not INTERFACE_RE.fullmatch(name) or name in {".", ".."} for name in interfaces):
        raise ConfigError("network.interfaces: invalid Linux interface name")
    cfg["network"]["interfaces"] = list(dict.fromkeys(interfaces))
    firewall = _mapping(raw.get("firewall", {}), {"action", "preserve_established"}, "firewall")
    cfg["firewall"]["action"] = _choice(
        firewall.get("action", "drop"), ("drop",), "firewall.action"
    )
    cfg["firewall"]["preserve_established"] = _boolean(
        firewall.get("preserve_established", True), "firewall.preserve_established"
    )
    allowlist = _mapping(raw.get("allowlist", {}), {"ipv4", "ipv6"}, "allowlist")
    for version in (4, 6):
        field = f"allowlist.ipv{version}"
        parsed = []
        for entry in _strings(allowlist.get(f"ipv{version}", []), field, 10000):
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError as error:
                raise ConfigError(f"{field}: invalid source network {entry!r}") from error
            if net.version != version:
                raise ConfigError(f"{field}: wrong IP family for {entry!r}")
            # An allowlist /0 would silently bypass every geographic restriction.
            if net.prefixlen == 0 or net.is_multicast or net.is_unspecified:
                raise ConfigError(f"{field}: unsafe source network {entry!r}")
            parsed.append(net)
        collapsed = list(ipaddress.collapse_addresses(parsed))
        if any(net.prefixlen == 0 for net in collapsed):
            raise ConfigError(f"{field}: combined source networks cover the entire address family")
        cfg["allowlist"][f"ipv{version}"] = [str(net) for net in collapsed]
    names: set[str] = set()
    for index, policy in enumerate(_list(raw.get("policies", []), "policies", 128)):
        field = f"policies[{index}]"
        item = _mapping(policy, {"name", "enabled", "destinations", "block_countries"}, field)
        name = item.get("name")
        if not isinstance(name, str) or not POLICY_RE.fullmatch(name):
            raise ConfigError(f"{field}.name: expected a unique 1–64 character identifier")
        if name in names:
            raise ConfigError(f"{field}.name: duplicate policy {name!r}")
        names.add(name)
        enabled = _boolean(item.get("enabled", True), f"{field}.enabled")
        destinations = item.get("destinations", [])
        if destinations != "all":
            addresses = []
            for entry in _strings(destinations, f"{field}.destinations", 1024):
                try:
                    addr = ipaddress.ip_address(entry)
                except ValueError as error:
                    raise ConfigError(
                        f"{field}.destinations: invalid exact IP {entry!r}"
                    ) from error
                if (
                    addr.is_multicast
                    or addr.is_unspecified
                    or addr.is_loopback
                    or addr.is_link_local
                    or "%" in entry
                ):
                    raise ConfigError(f"{field}.destinations: unsafe destination {entry!r}")
                addresses.append(str(addr))
            destinations = list(dict.fromkeys(addresses))
            if not destinations:
                raise ConfigError(f"{field}.destinations: select at least one destination or all")
        codes = _strings(item.get("block_countries", []), f"{field}.block_countries", 249)
        codes = list(dict.fromkeys(code.upper() for code in codes))
        for code in codes:
            if code not in COUNTRY_CODES:
                raise ConfigError(f"{field}.block_countries: invalid ISO 3166-1 code {code!r}")
        if destinations == "all" and not cfg["network"]["interfaces"]:
            raise ConfigError(f"{field}.destinations: all requires selected network interfaces")
        if cfg["enabled"] and enabled and codes and not cfg["network"]["interfaces"]:
            raise ConfigError(f"{field}: select at least one incoming network interface")
        cfg["policies"].append(
            {
                "name": name,
                "enabled": enabled,
                "destinations": destinations,
                "block_countries": codes,
            }
        )
    return cfg


class _ConfigLoader(yaml.SafeLoader):
    """YAML 1.2-style booleans preserve country codes such as NO."""


_ConfigLoader.yaml_implicit_resolvers = {
    key: [(tag, regex) for tag, regex in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_ConfigLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def _construct_mapping(loader: _ConfigLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ConfigError("config: mapping keys must be strings")
        if key in result:
            raise ConfigError(f"config: duplicate YAML field {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_ConfigLoader.add_constructor("tag:yaml.org,2002:map", _construct_mapping)


def load_config(path: str | Path = CONFIG_PATH) -> dict[str, Any]:
    """Load bounded safe YAML. Missing configuration starts the setup workflow."""
    target = Path(path)
    try:
        descriptor = os.open(target, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ConfigError("config: expected a regular file")
            if info.st_mode & 0o022:
                raise ConfigError("config: file is writable by another user")
            if os.geteuid() == 0 and info.st_uid != 0:
                raise ConfigError(
                    "config: privileged operations require a root-owned configuration file"
                )
            payload = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return default_config()
    if len(payload) > MAX_CONFIG_BYTES:
        raise ConfigError("config: file exceeds the 1 MiB size limit")
    try:
        text = payload.decode("utf-8")
        if any(isinstance(token, yaml.tokens.AliasToken) for token in yaml.scan(text)):
            raise ConfigError("config: YAML aliases are not supported")
        data = yaml.load(text, Loader=_ConfigLoader)
    except (UnicodeError, yaml.YAMLError, RecursionError) as error:
        raise ConfigError(f"config: invalid YAML ({error})") from error
    return validate_config(data)


def save_config(config: dict[str, Any], path: str | Path = CONFIG_PATH) -> None:
    """Persist readable, administrator-writable YAML with durable atomic writes.

    The configuration contains no credentials. Mode 0644 lets ordinary users
    open the menu and inspect policy settings, including administrative source
    addresses. Private rollback snapshots and GeoIP caches use separate paths.
    An existing parent must be owned by the caller and not writable by others;
    an existing private directory is never made public without user intent.
    """
    normalized = validate_config(config)
    target = Path(path)
    if target.is_symlink():
        raise ConfigError("config: refusing to replace a symbolic link")
    try:
        target.parent.mkdir(parents=True, mode=0o755)
    except FileExistsError:
        pass
    else:
        # A restrictive installer umask must not make a new public directory
        # inaccessible. Never widen permissions on a pre-existing directory.
        descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if os.fstat(descriptor).st_uid != os.geteuid():
                raise PermissionError(f"Unsafe directory: {target.parent}")
            os.fchmod(descriptor, 0o755)
        finally:
            os.close(descriptor)
    payload = yaml.safe_dump(normalized, allow_unicode=True, sort_keys=False)
    atomic_write(target, payload, mode=0o644)
