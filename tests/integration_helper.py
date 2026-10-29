"""Disposable namespace packet harness used by test_integration.py.

The ``run`` mode verifies network namespace isolation before its first network
mutation. Namespace names are never registered under /run/netns, so tests do not
need to change host mount propagation or share named namespaces with other jobs.
"""

from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import threading
from contextlib import ExitStack
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve()
PAYLOAD = b"GeoLatch kernel packet test"
TIMEOUT = 0.45


def command(*args: str, source: str | None = None, timeout: float = 15) -> str:
    result = subprocess.run(
        args, input=source, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr}")
    return result.stdout


class NetworkNamespace:
    """An anonymous child netns kept alive by a pipe, automatically reaped."""

    def __init__(self) -> None:
        self.process = subprocess.Popen(
            ["unshare", "--net", "--", sys.executable, str(HERE), "hold"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = self.process.stdout.readline()
        if not line:
            _, stderr = self.process.communicate(timeout=5)
            raise RuntimeError("Nested network namespace failed: " + stderr)
        namespace = json.loads(line)["network_namespace"]
        if namespace == os.readlink("/proc/self/ns/net"):
            raise RuntimeError("Child did not enter an isolated network namespace")
        self.pid = str(self.process.pid)

    def args(self, *args: str) -> list[str]:
        return ["nsenter", "--target", self.pid, "--net", "--", *args]

    def run(self, *args: str) -> str:
        return command(*self.args(*args))

    def spawn(self, mode: str, payload: dict[str, Any]) -> subprocess.Popen[str]:
        return subprocess.Popen(
            self.args(sys.executable, str(HERE), mode, json.dumps(payload)),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def __enter__(self) -> NetworkNamespace:
        return self

    def __exit__(self, *_: Any) -> None:
        stop(self.process)


def stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=3)


class EchoServers:
    def __init__(
        self,
        hosts: tuple[str, ...] = (
            "198.51.100.10",
            "198.51.100.20",
            "198.51.100.30",
            "2001:db8::10",
            "2001:db8::20",
            "2001:db8::30",
        ),
    ) -> None:
        self.sockets: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self.done = threading.Event()
        self.ports: dict[str, int] = {}
        for host in hosts:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            for protocol, kind in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
                listener = socket.socket(family, kind)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Exact binds preserve the requested destination as the reply
                # source for UDP. A wildcard recvfrom/sendto server would reply
                # from the interface's primary IP, breaking secondary-IP and
                # alternate-ingress probes even without a firewall.
                key = f"{protocol}{6 if family == socket.AF_INET6 else 4}"
                listener.bind((host, self.ports.get(key, 0)))
                listener.settimeout(0.1)
                if protocol == "tcp":
                    listener.listen(32)
                self.sockets.append(listener)
                self.ports[key] = listener.getsockname()[1]
                thread = threading.Thread(target=self.serve, args=(listener, protocol), daemon=True)
                thread.start()
                self.threads.append(thread)

    def serve(self, listener: socket.socket, protocol: str) -> None:
        while not self.done.is_set():
            try:
                if protocol == "udp":
                    data, remote = listener.recvfrom(4096)
                    listener.sendto(data, remote)
                else:
                    connection, _ = listener.accept()
                    threading.Thread(
                        target=self.connection, args=(connection,), daemon=True
                    ).start()
            except TimeoutError:
                continue
            except OSError:
                if not self.done.is_set():
                    raise

    def connection(self, connection: socket.socket) -> None:
        with connection:
            connection.settimeout(0.2)
            while not self.done.is_set():
                try:
                    data = connection.recv(4096)
                    if not data:
                        return
                    connection.sendall(data)
                except TimeoutError:
                    continue
                except OSError:
                    return

    def __enter__(self) -> EchoServers:
        return self

    def __exit__(self, *_: Any) -> None:
        self.done.set()
        for listener in self.sockets:
            listener.close()
        for thread in self.threads:
            thread.join(timeout=1)


def request(payload: dict[str, Any]) -> bool:
    return request_result(payload)["received"]


def request_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Retain the failed socket phase so a topology failure is diagnosable."""
    family = socket.AF_INET6 if ":" in payload["destination"] else socket.AF_INET
    kind = socket.SOCK_STREAM if payload["protocol"] == "tcp" else socket.SOCK_DGRAM
    phase = "create"
    try:
        with socket.socket(family, kind) as connection:
            connection.settimeout(payload.get("timeout", TIMEOUT))
            phase = "bind"
            connection.bind((payload["source"], 0))
            phase = "connect"
            connection.connect((payload["destination"], payload["port"]))
            phase = "send"
            connection.sendall(PAYLOAD)
            phase = "receive"
            received = connection.recv(len(PAYLOAD)) == PAYLOAD
            return {"received": received, "phase": phase}
    except OSError as error:
        return {"received": False, "phase": phase, "error": str(error), "errno": error.errno}


def network_diagnostics(
    peer: NetworkNamespace, destination_peer: NetworkNamespace | None = None
) -> dict[str, Any]:
    """Bounded read-only evidence from the already isolated test topology."""
    namespaces = [("router", []), ("source", peer.args())]
    if destination_peer is not None:
        namespaces.append(("destination", destination_peer.args()))
    diagnostics: dict[str, Any] = {}
    commands = [
        ("addresses", ["ip", "-j", "address", "show"]),
        ("ipv4_routes", ["ip", "-j", "route", "show", "table", "all"]),
        ("ipv6_routes", ["ip", "-j", "-6", "route", "show", "table", "all"]),
        ("neighbors", ["ip", "-j", "neighbor", "show"]),
        ("forwarding4", ["sysctl", "-n", "net.ipv4.ip_forward"]),
        ("forwarding6", ["sysctl", "-n", "net.ipv6.conf.all.forwarding"]),
        ("rp_filter", ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"]),
    ]
    for name, prefix in namespaces:
        evidence = {}
        for label, args in commands:
            try:
                evidence[label] = command(*prefix, *args, timeout=2)[:12000]
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                evidence[label] = str(error)[:2000]
        diagnostics[name] = evidence
    try:
        diagnostics["router_nft"] = command("nft", "--list", "ruleset", timeout=2)[:16000]
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        diagnostics["router_nft"] = str(error)[:2000]
    return diagnostics


def probe(
    peer: NetworkNamespace,
    source: str,
    destination: str,
    protocol: str,
    port: int,
    *,
    context: str | None = None,
    destination_peer: NetworkNamespace | None = None,
    timeout: float = TIMEOUT,
) -> bool:
    payload = {
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "port": port,
        "timeout": timeout,
    }
    result = json.loads(peer.run(sys.executable, str(HERE), "request", json.dumps(payload)))
    if not result["received"] and context:
        raise AssertionError(
            json.dumps(
                {
                    "context": context,
                    "probe": payload,
                    "result": result,
                    "network": network_diagnostics(peer, destination_peer),
                },
                indent=2,
            )
        )
    return result["received"]


def link(peer: NetworkNamespace, local: str, remote: str, ipv4: str, ipv6: str) -> None:
    command("ip", "link", "add", local, "type", "veth", "peer", "name", remote)
    command("ip", "link", "set", remote, "netns", peer.pid)
    command("ip", "link", "set", local, "up")
    command("ip", "address", "add", ipv4, "dev", local)
    command("ip", "-6", "address", "add", ipv6, "dev", local, "nodad")
    peer.run("ip", "link", "set", "lo", "up")
    peer.run("ip", "link", "set", remote, "up")


def setup_peer(peer: NetworkNamespace) -> None:
    command("ip", "link", "set", "lo", "up")
    link(peer, "server0", "peer0", "198.51.100.10/24", "2001:db8::10/64")
    for suffix in ("20", "30"):
        command("ip", "address", "add", f"198.51.100.{suffix}/24", "dev", "server0")
        command("ip", "-6", "address", "add", f"2001:db8::{suffix}/64", "dev", "server0", "nodad")
    for suffix in ("2", "3"):
        peer.run("ip", "address", "add", f"198.51.100.{suffix}/24", "dev", "peer0")
        peer.run("ip", "-6", "address", "add", f"2001:db8::{suffix}/64", "dev", "peer0", "nodad")


def permanent_ipv6_neighbors(
    peer: NetworkNamespace, local: str, remote: str, local_address: str, remote_address: str
) -> None:
    """Make synthetic container links independent of unrelated ND timing.

    The source/server link deliberately keeps dynamic Neighbor Discovery, which
    the regular IPv6 packet tests exercise. CI showed unresolved neighbors on
    these separate ULA forwarding links before GeoLatch was installed. Pin only
    their known veth endpoints using the MACs assigned by the actual test kernel.
    """
    local_mac = json.loads(command("ip", "-j", "link", "show", "dev", local))[0]["address"]
    remote_mac = json.loads(peer.run("ip", "-j", "link", "show", "dev", remote))[0]["address"]
    command(
        "ip",
        "-6",
        "neighbor",
        "replace",
        remote_address,
        "lladdr",
        remote_mac,
        "nud",
        "permanent",
        "dev",
        local,
    )
    peer.run(
        "ip",
        "-6",
        "neighbor",
        "replace",
        local_address,
        "lladdr",
        local_mac,
        "nud",
        "permanent",
        "dev",
        remote,
    )


def config() -> dict[str, Any]:
    from geolatch.config import default_config

    result = default_config()
    result["network"].update({"ipv4": True, "ipv6": True, "interfaces": ["server0"]})
    result["policies"] = [
        {
            "name": "primary",
            "enabled": True,
            "destinations": ["198.51.100.10", "2001:db8::10"],
            "block_countries": ["IR"],
        },
        {
            "name": "secondary",
            "enabled": True,
            "destinations": ["198.51.100.20", "2001:db8::20"],
            "block_countries": ["CN"],
        },
        {
            "name": "open",
            "enabled": True,
            "destinations": ["198.51.100.30", "2001:db8::30"],
            "block_countries": [],
        },
    ]
    return result


DATABASES = {
    "IR:4": ["198.51.100.2/32"],
    "IR:6": ["2001:db8::2/128"],
    "CN:4": ["198.51.100.3/32"],
    "CN:6": ["2001:db8::3/128"],
}


def install(
    cfg: dict[str, Any] | None = None,
    databases: dict[str, list[str]] | None = None,
) -> Any:
    from geolatch.firewall import generate_rules
    from geolatch.nftables import Nftables

    nft = Nftables()
    rules = generate_rules(cfg or config(), DATABASES if databases is None else databases)
    nft.check(rules)
    nft.apply(rules)
    return nft


def add_source(peer: NetworkNamespace, suffix: str) -> None:
    peer.run("ip", "address", "add", f"198.51.100.{suffix}/24", "dev", "peer0")
    peer.run("ip", "-6", "address", "add", f"2001:db8::{suffix}/64", "dev", "peer0", "nodad")


def tracking_failures(nft: Any) -> int:
    counters = [
        counter
        for counter in nft.counters()
        if counter["comment"].startswith("GeoLatch tracking failure family=")
    ]
    assert len(counters) == 2, counters
    return sum(counter["packets"] for counter in counters)


def unique_sources(peer: NetworkNamespace, servers: EchoServers) -> None:
    """Count actual dropped source addresses, not packets, countries or policies."""
    from geolatch.firewall import generate_rules

    for suffix in ("4", "5"):
        add_source(peer, suffix)
    cfg = config()
    primary = copy.deepcopy(cfg["policies"][0])
    primary["destinations"] += ["198.51.100.20", "2001:db8::20"]
    overlap = copy.deepcopy(primary)
    overlap["name"] = "same-sources-second-policy"
    cfg["policies"] = [primary, overlap, cfg["policies"][2]]
    cfg["allowlist"] = {"ipv4": ["198.51.100.3/32"], "ipv6": ["2001:db8::3/128"]}
    databases = {
        "IR:4": [f"198.51.100.{suffix}/32" for suffix in ("2", "3", "4")],
        "IR:6": [f"2001:db8::{suffix}/128" for suffix in ("2", "3", "4")],
    }
    nft = install(cfg, databases)
    statistics = nft.traffic_stats()
    assert statistics["tracking_available"] and statistics["unique_ips"] == 0, statistics
    assert not statistics["unique_limit_reached"], statistics
    for family, prefix in ((4, "198.51.100."), (6, "2001:db8::")):
        for protocol in ("tcp", "udp"):
            port = servers.ports[f"{protocol}{family}"]
            # Allowlisted, unselected destination, and a non-country source.
            assert probe(peer, prefix + "3", prefix + "10", protocol, port)
            assert probe(peer, prefix + "2", prefix + "30", protocol, port)
            assert probe(peer, prefix + "5", prefix + "10", protocol, port)
    assert nft.traffic_stats()["unique_ips"] == 0
    expected = 0
    # A second set of destination ports also proves that the key is just source
    # address; source port, destination, protocol and overlapping policy differ.
    with EchoServers(("198.51.100.10", "2001:db8::10")) as extra_servers:
        for family, prefix in ((4, "198.51.100."), (6, "2001:db8::")):
            for suffix in ("2", "4"):
                expected += 1
                for _ in range(2):
                    for protocol in ("tcp", "udp"):
                        port = servers.ports[f"{protocol}{family}"]
                        for destination in ("10", "20"):
                            assert not probe(
                                peer, prefix + suffix, prefix + destination, protocol, port
                            )
                        assert not probe(
                            peer,
                            prefix + suffix,
                            prefix + "10",
                            protocol,
                            extra_servers.ports[f"{protocol}{family}"],
                        )
                        statistics = nft.traffic_stats()
                        assert statistics["unique_ips"] == expected, statistics
                        assert not statistics["unique_limit_reached"], statistics
    assert expected == 4
    statistics = nft.traffic_stats()
    assert statistics["dropped_packets"] >= 48, statistics
    assert statistics["dropped_bytes"] > 0, statistics
    assert tracking_failures(nft) == 0
    snapshot = nft.snapshot()
    assert snapshot is not None
    nft.apply(None)
    assert nft.traffic_stats()["unique_ips"] == 0
    nft.apply(snapshot)
    assert nft.traffic_stats()["unique_ips"] == 4
    nft.apply(generate_rules(cfg, databases))
    assert nft.traffic_stats()["unique_ips"] == 0


def unique_source_capacity(peer: NetworkNamespace, servers: EchoServers) -> None:
    """A full observation set must never let a country-blocked packet through."""
    import geolatch.firewall as firewall

    firewall.UNIQUE_IP_CAPACITY = 2
    for suffix in ("4", "5"):
        add_source(peer, suffix)
    cfg = config()
    cfg["policies"] = [cfg["policies"][0]]
    databases = {
        "IR:4": [f"198.51.100.{suffix}/32" for suffix in ("2", "3", "4")],
        "IR:6": [f"2001:db8::{suffix}/128" for suffix in ("2", "3", "4")],
    }
    nft = install(cfg, databases)
    for family, prefix in ((4, "198.51.100."), (6, "2001:db8::")):
        for suffix in ("2", "3"):
            assert not probe(
                peer, prefix + suffix, prefix + "10", "udp", servers.ports[f"udp{family}"]
            )
    full = nft.traffic_stats()
    assert full["tracking_available"] and full["unique_ips"] == 4, full
    assert full["unique_limit_reached"], full
    assert tracking_failures(nft) == 0
    for family, prefix in ((4, "198.51.100."), (6, "2001:db8::")):
        for protocol in ("tcp", "udp"):
            port = servers.ports[f"{protocol}{family}"]
            # Neither source has room for insertion. Both still have to hit the
            # unconditional DROP after the failed dynamic-set update statement.
            for _ in range(2):
                assert not probe(peer, prefix + "4", prefix + "10", protocol, port), (
                    family,
                    protocol,
                )
            assert probe(peer, prefix + "5", prefix + "10", protocol, port)
            assert probe(peer, prefix + "4", prefix + "20", protocol, port)
    after = nft.traffic_stats()
    assert after["unique_ips"] == 4 and after["unique_limit_reached"], after
    assert after["dropped_packets"] >= full["dropped_packets"] + 8, after
    assert tracking_failures(nft) >= 8


def packet_matrix(peer: NetworkNamespace, servers: EchoServers, family: int) -> None:
    nft = install()
    prefix = "198.51.100." if family == 4 else "2001:db8::"
    for protocol in ("tcp", "udp"):
        port = servers.ports[f"{protocol}{family}"]
        for source_suffix in ("2", "3"):
            for destination_suffix in ("10", "20", "30"):
                blocked = (source_suffix, destination_suffix) in (("2", "10"), ("3", "20"))
                result = probe(
                    peer, prefix + source_suffix, prefix + destination_suffix, protocol, port
                )
                assert result is not blocked, (
                    family,
                    protocol,
                    source_suffix,
                    destination_suffix,
                    result,
                )
    assert sum(counter["packets"] for counter in nft.counters()) >= 4


def foreign_table() -> dict[str, Any]:
    return json.loads(command("nft", "--json", "list", "table", "inet", "foreign"))


def merged_policies(peer: NetworkNamespace, servers: EchoServers) -> None:
    cfg = config()
    overlapping = copy.deepcopy(cfg["policies"][0])
    overlapping.update({"name": "overlap", "block_countries": ["CN"]})
    disabled = copy.deepcopy(cfg["policies"][2])
    disabled.update({"name": "disabled", "enabled": False, "block_countries": ["IR", "CN"]})
    cfg["policies"].extend([overlapping, disabled])
    install(cfg)
    for family, prefix in ((4, "198.51.100."), (6, "2001:db8::")):
        for protocol in ("tcp", "udp"):
            for source in ("2", "3"):
                assert not probe(
                    peer,
                    prefix + source,
                    prefix + "10",
                    protocol,
                    servers.ports[f"{protocol}{family}"],
                )
                assert probe(
                    peer,
                    prefix + source,
                    prefix + "30",
                    protocol,
                    servers.ports[f"{protocol}{family}"],
                )


def allowlist(peer: NetworkNamespace, servers: EchoServers) -> None:
    install()
    assert not probe(peer, "198.51.100.2", "198.51.100.10", "tcp", servers.ports["tcp4"])
    cfg = config()
    cfg["allowlist"] = {"ipv4": ["198.51.100.2/32"], "ipv6": ["2001:db8::2/128"]}
    install(cfg)
    for family, source, destination in (
        (4, "198.51.100.2", "198.51.100.10"),
        (6, "2001:db8::2", "2001:db8::10"),
    ):
        for protocol in ("tcp", "udp"):
            assert probe(peer, source, destination, protocol, servers.ports[f"{protocol}{family}"])
    command(
        "nft",
        "--file",
        "-",
        source="table inet foreign {\n"
        "    chain incoming {\n"
        "        type filter hook input priority 0; policy accept;\n"
        f"        ip saddr 198.51.100.2 tcp dport {servers.ports['tcp4']} drop\n"
        f"        ip6 saddr 2001:db8::2 tcp dport {servers.ports['tcp6']} drop\n"
        "    }\n"
        "}\n",
    )
    before = foreign_table()
    install(cfg)
    assert not probe(peer, "198.51.100.2", "198.51.100.10", "tcp", servers.ports["tcp4"])
    assert not probe(peer, "2001:db8::2", "2001:db8::10", "tcp", servers.ports["tcp6"])
    assert probe(peer, "198.51.100.2", "198.51.100.10", "udp", servers.ports["udp4"])
    assert foreign_table() == before


def transactions(peer: NetworkNamespace, servers: EchoServers) -> None:
    from geolatch.firewall import generate_rules
    from geolatch.nftables import NftError

    command(
        "nft",
        "--file",
        "-",
        source="table inet foreign {\n"
        "    set retained {\n"
        "        type ipv4_addr\n"
        "        elements = { 192.0.2.1 }\n"
        "    }\n"
        "}\n",
    )
    foreign = foreign_table()
    nft = install()
    snapshot = nft.snapshot()
    assert snapshot is not None
    # An invalid new rule must not remove the committed table in the same batch.
    invalid = snapshot.replace(
        "chain prerouting {", "chain prerouting { invalid_nft_expression;", 1
    )
    try:
        nft.apply(invalid)
    except NftError:
        pass
    else:
        raise AssertionError("The kernel accepted an invalid nft rule")
    assert nft.snapshot() == snapshot
    assert not probe(peer, "198.51.100.2", "198.51.100.10", "tcp", servers.ports["tcp4"])
    original = generate_rules(config(), DATABASES)
    before_check = nft.snapshot()
    nft.check(original)
    assert nft.snapshot() == before_check
    nft.apply(original)
    nft.apply(original)
    assert foreign_table() == foreign
    cfg = config()
    cfg["policies"][0]["block_countries"] = ["CN"]
    nft.apply(generate_rules(cfg, DATABASES))
    assert probe(peer, "198.51.100.2", "198.51.100.10", "udp", servers.ports["udp4"])
    assert not probe(peer, "198.51.100.3", "198.51.100.10", "udp", servers.ports["udp4"])
    # Restoration uses a local snapshot, not a network download.
    nft.apply(snapshot)
    assert not probe(peer, "198.51.100.2", "198.51.100.10", "udp", servers.ports["udp4"])
    assert probe(peer, "198.51.100.3", "198.51.100.10", "udp", servers.ports["udp4"])
    nft.apply(None)
    assert nft.inspect() is None
    assert probe(peer, "198.51.100.2", "198.51.100.10", "tcp", servers.ports["tcp4"])
    assert foreign_table() == foreign
    nft.apply(snapshot)
    assert nft.inspect() is not None
    assert foreign_table() == foreign


def established(peer: NetworkNamespace, servers: EchoServers) -> None:
    # Activate conntrack in this fresh netns before creating the flow. Merely
    # creating TCP sockets need not register conntrack hooks until nft uses ct.
    initial = config()
    initial["policies"] = []
    install(initial)
    payload = {
        "source": "198.51.100.2",
        "destination": "198.51.100.10",
        "port": servers.ports["tcp4"],
    }
    persistent = peer.spawn("persistent", payload)
    try:
        assert json.loads(persistent.stdout.readline())["received"]
        install()
        persistent.stdin.write("probe\n")
        persistent.stdin.flush()
        assert json.loads(persistent.stdout.readline())["received"]
        assert not probe(peer, "198.51.100.2", "198.51.100.10", "tcp", servers.ports["tcp4"])
        cfg = config()
        cfg["firewall"]["preserve_established"] = False
        install(cfg)
        persistent.stdin.write("probe\n")
        persistent.stdin.flush()
        assert not json.loads(persistent.stdout.readline())["received"]
    finally:
        stop(persistent)
    remote = peer.spawn("serve", {"hosts": ["198.51.100.2", "2001:db8::2"]})
    try:
        ports = json.loads(remote.stdout.readline())["ports"]
        for family, source, destination in (
            (4, "198.51.100.10", "198.51.100.2"),
            (6, "2001:db8::10", "2001:db8::2"),
        ):
            for protocol in ("tcp", "udp"):
                # Return packets from an outbound connection have ct direction
                # reply, even when preserving inbound established flows is off.
                assert request(
                    {
                        "source": source,
                        "destination": destination,
                        "protocol": protocol,
                        "port": ports[f"{protocol}{family}"],
                    }
                )
    finally:
        stop(remote)


def dnat(peer: NetworkNamespace, servers: EchoServers) -> None:
    with NetworkNamespace() as container:
        link(container, "docker0", "container0", "172.18.0.1/24", "fd00:18::1/64")
        container.run("ip", "address", "add", "172.18.0.2/24", "dev", "container0")
        container.run("ip", "-6", "address", "add", "fd00:18::2/64", "dev", "container0", "nodad")
        permanent_ipv6_neighbors(container, "docker0", "container0", "fd00:18::1", "fd00:18::2")
        container.run("ip", "route", "add", "default", "via", "172.18.0.1")
        container.run("ip", "-6", "route", "add", "default", "via", "fd00:18::1")
        command("sysctl", "-w", "net.ipv4.ip_forward=1")
        command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
        remote = container.spawn("serve", {"hosts": ["172.18.0.2", "fd00:18::2"]})
        try:
            ports = json.loads(remote.stdout.readline())["ports"]
            lines = [
                "table inet container_nat {",
                "    chain published {",
                "        type nat hook prerouting priority -100; policy accept;",
            ]
            for protocol in ("tcp", "udp"):
                lines += [
                    f"iifname server0 ip daddr 198.51.100.10 {protocol} dport {ports[f'{protocol}4']} dnat ip to 172.18.0.2",
                    f"iifname server0 ip6 daddr 2001:db8::10 {protocol} dport {ports[f'{protocol}6']} dnat ip6 to fd00:18::2",
                ]
            lines += ["    }", "}"]
            command("nft", "--file", "-", source="\n".join(lines) + "\n")
            for family, prefix in ((4, "198.51.100."), (6, "2001:db8::")):
                for protocol in ("tcp", "udp"):
                    assert probe(
                        peer,
                        prefix + "2",
                        prefix + "10",
                        protocol,
                        ports[f"{protocol}{family}"],
                        context="pre-GeoLatch DNAT connectivity baseline",
                        destination_peer=container,
                        timeout=2.0,
                    )
            install()
            for family, prefix in ((4, "198.51.100."), (6, "2001:db8::")):
                for protocol in ("tcp", "udp"):
                    assert not probe(
                        peer,
                        prefix + "2",
                        prefix + "10",
                        protocol,
                        ports[f"{protocol}{family}"],
                        timeout=2.0,
                    ), (
                        "GeoLatch blocks selected pre-DNAT destination",
                        family,
                        protocol,
                        prefix + "2",
                        prefix + "10",
                    )
                    assert probe(
                        peer,
                        prefix + "3",
                        prefix + "10",
                        protocol,
                        ports[f"{protocol}{family}"],
                        context="allowed source reaches selected pre-DNAT destination",
                        destination_peer=container,
                        timeout=2.0,
                    )
                    assert probe(
                        peer,
                        prefix + "2",
                        prefix + "20",
                        protocol,
                        servers.ports[f"{protocol}{family}"],
                        context="unselected local destination remains reachable with DNAT enabled",
                        destination_peer=container,
                        timeout=2.0,
                    )
        finally:
            stop(remote)


def scope(peer: NetworkNamespace, servers: EchoServers) -> None:
    from geolatch.firewall import generate_rules

    # A source inside the same GeoIP range on an unselected ingress interface
    # is excluded. Source routing is explicit to avoid an ambiguous second link.
    with NetworkNamespace() as alternate:
        link(alternate, "tunnel0", "vpn0", "192.0.2.1/24", "fd00:19::1/64")
        alternate.run("ip", "address", "add", "198.51.100.2/32", "dev", "vpn0")
        alternate.run("ip", "-6", "address", "add", "2001:db8::2/128", "dev", "vpn0", "nodad")
        alternate.run(
            "ip", "route", "add", "198.51.100.10/32", "via", "192.0.2.1", "dev", "vpn0", "onlink"
        )
        alternate.run(
            "ip",
            "-6",
            "route",
            "add",
            "2001:db8::10/128",
            "via",
            "fd00:19::1",
            "dev",
            "vpn0",
            "onlink",
        )
        command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
        command("sysctl", "-w", "net.ipv4.conf.tunnel0.rp_filter=0")
        nft = install()
        # Force local return routes to the alternate source only during probes.
        command("ip", "route", "add", "198.51.100.2/32", "dev", "tunnel0")
        command("ip", "-6", "route", "add", "2001:db8::2/128", "dev", "tunnel0")
        for family, source, destination in (
            (4, "198.51.100.2", "198.51.100.10"),
            (6, "2001:db8::2", "2001:db8::10"),
        ):
            for protocol in ("tcp", "udp"):
                assert probe(
                    alternate, source, destination, protocol, servers.ports[f"{protocol}{family}"]
                )
        command("ip", "route", "del", "198.51.100.2/32", "dev", "tunnel0")
        command("ip", "-6", "route", "del", "2001:db8::2/128", "dev", "tunnel0")
        cfg = config()
        cfg["policies"] = [copy.deepcopy(cfg["policies"][0])]
        cfg["policies"][0]["destinations"] = ["198.51.100.10", "2001:db8::10"]
        nft.apply(generate_rules(cfg, DATABASES))
        assert not probe(peer, "198.51.100.2", "198.51.100.10", "tcp", servers.ports["tcp4"])
        assert probe(peer, "198.51.100.2", "198.51.100.30", "tcp", servers.ports["tcp4"])
    # Unrelated forwarded traffic is not geographically restricted just because
    # it entered a selected interface from a source in a blocked country.
    with NetworkNamespace() as transit:
        link(transit, "transit0", "destination0", "172.19.0.1/24", "fd00:20::1/64")
        transit.run("ip", "address", "add", "172.19.0.2/24", "dev", "destination0")
        transit.run("ip", "-6", "address", "add", "fd00:20::2/64", "dev", "destination0", "nodad")
        permanent_ipv6_neighbors(transit, "transit0", "destination0", "fd00:20::1", "fd00:20::2")
        transit.run("ip", "route", "add", "default", "via", "172.19.0.1")
        transit.run("ip", "-6", "route", "add", "default", "via", "fd00:20::1")
        peer.run("ip", "route", "add", "172.19.0.0/24", "via", "198.51.100.10")
        peer.run("ip", "-6", "route", "add", "fd00:20::/64", "via", "2001:db8::10")
        command("sysctl", "-w", "net.ipv4.ip_forward=1")
        command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
        remote = transit.spawn("serve", {"hosts": ["172.19.0.2", "fd00:20::2"]})
        try:
            ports = json.loads(remote.stdout.readline())["ports"]
            for family, source, destination in (
                (4, "198.51.100.2", "172.19.0.2"),
                (6, "2001:db8::2", "fd00:20::2"),
            ):
                for protocol in ("tcp", "udp"):
                    assert probe(
                        peer,
                        source,
                        destination,
                        protocol,
                        ports[f"{protocol}{family}"],
                        context="unrelated forwarded destination remains reachable",
                        destination_peer=transit,
                        timeout=2.0,
                    )
        finally:
            stop(remote)


def run(scenario: str, parent_namespace: str) -> None:
    current = os.readlink("/proc/self/ns/net")
    # Do not trust a command-line inode alone: a mistaken direct invocation with
    # a bogus value must never turn this harness into a host firewall writer.
    actual_parent = os.readlink(f"/proc/{os.getppid()}/ns/net")
    if parent_namespace != actual_parent or current == actual_parent or os.geteuid() != 0:
        raise RuntimeError("Refusing kernel tests outside a fresh privileged network namespace")
    # All mutations below happen only after the isolation guard above.
    with ExitStack() as stack:
        peer = stack.enter_context(NetworkNamespace())
        setup_peer(peer)
        servers = stack.enter_context(EchoServers())
        if scenario == "ipv4_tcp_udp_policies":
            packet_matrix(peer, servers, 4)
        elif scenario == "ipv6_tcp_udp_policies":
            packet_matrix(peer, servers, 6)
        elif scenario == "merged_and_disabled_policies":
            merged_policies(peer, servers)
        elif scenario == "allowlist_and_foreign_firewall":
            allowlist(peer, servers)
        elif scenario == "atomic_replace_disable_restore":
            transactions(peer, servers)
        elif scenario == "established_and_reply_direction":
            established(peer, servers)
        elif scenario == "unique_dropped_sources":
            unique_sources(peer, servers)
        elif scenario == "unique_source_capacity_still_drops":
            unique_source_capacity(peer, servers)
        elif scenario == "dnat_before_forwarding":
            dnat(peer, servers)
        elif scenario == "interface_and_transit_scope":
            scope(peer, servers)
        else:
            raise ValueError("Unknown integration scenario: " + scenario)
    print(json.dumps({"scenario": scenario, "kernel_verified": True, "network_namespace": current}))


def main() -> None:
    mode = sys.argv[1]
    if mode == "hold":
        print(json.dumps({"network_namespace": os.readlink("/proc/self/ns/net")}), flush=True)
        sys.stdin.read()
    elif mode == "request":
        print(json.dumps(request_result(json.loads(sys.argv[2]))))
    elif mode == "serve":
        with EchoServers(tuple(json.loads(sys.argv[2])["hosts"])) as servers:
            print(json.dumps({"ports": servers.ports}), flush=True)
            sys.stdin.read()
    elif mode == "persistent":
        payload = json.loads(sys.argv[2])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(TIMEOUT)
            connection.bind((payload["source"], 0))
            connection.connect((payload["destination"], payload["port"]))
            while True:
                try:
                    connection.sendall(PAYLOAD)
                    received = connection.recv(len(PAYLOAD)) == PAYLOAD
                except OSError:
                    received = False
                print(json.dumps({"received": received}), flush=True)
                if not sys.stdin.readline():
                    break
    elif mode == "run":
        # The repository path makes direct helper invocation independent of an
        # editable install. Child request modes do not import application code.
        sys.path.insert(0, str(HERE.parents[1]))
        run(sys.argv[2], sys.argv[3])
    else:
        raise ValueError("Unknown helper mode")


if __name__ == "__main__":
    main()
