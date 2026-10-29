"""Read-only controller summaries over injected kernel boundaries."""

from __future__ import annotations

import json

import pytest

from geolatch.config import default_config, save_config
from geolatch.controller import Controller
from geolatch.nftables import NftError
from geolatch.paths import Paths
from geolatch.statistics import aggregate_stats


def kernel_table(*, tracking=True):
    entries = [
        {"table": {"family": "inet", "name": "geolatch"}},
        {
            "rule": {
                "family": "inet",
                "table": "geolatch",
                "chain": "prerouting",
                "comment": "GeoLatch country=IR family=4",
                "expr": [
                    {"counter": {"packets": 900, "bytes": 54000}},
                    {"jump": {"target": "geolatch_drop_v4"}} if tracking else {"drop": None},
                ],
            }
        },
    ]
    if tracking:
        entries.append(
            {
                "set": {
                    "family": "inet",
                    "table": "geolatch",
                    "name": "dropped_sources_v4",
                    "type": "ipv4_addr",
                    "flags": ["dynamic"],
                    "size": 65536,
                    "elem": ["198.51.100.1", "198.51.100.2"],
                }
            }
        )
    return {"nftables": entries}


class Kernel:
    def __init__(self, table):
        self.table = table
        self.inspections = 0

    def inspect(self):
        self.inspections += 1
        if isinstance(self.table, Exception):
            raise self.table
        return self.table

    def counters(self):
        return []


class StatisticsKernel(Kernel):
    def __init__(self, table):
        super().__init__(table)
        self.received = []

    def traffic_stats(self, table=...):
        self.received.append(table)
        return aggregate_stats(self.inspect() if table is ... else table)


@pytest.fixture
def make_controller(tmp_path):
    paths = Paths(tmp_path / "etc" / "config.yaml", tmp_path / "state", tmp_path / "cache")
    save_config(default_config(), paths.config_file)

    def create(kernel):
        controller = Controller(paths, nft=kernel)
        controller._timer_state = lambda: "inactive"
        controller._require_root = lambda: pytest.fail(
            "Statistics requested a privileged operation"
        )
        return controller

    return create


@pytest.mark.parametrize("backend", [Kernel, StatisticsKernel])
def test_confirmed_table_absence_means_zero(make_controller, backend):
    stats = make_controller(backend(None)).traffic_stats()
    assert stats["unique_ips"] == 0
    assert stats["dropped_packets"] == 0
    assert stats["dropped_bytes"] == 0
    assert stats["tracking_available"] is True
    assert stats["counter_error"] is None


@pytest.mark.parametrize("backend", [Kernel, StatisticsKernel])
def test_legacy_rules_do_not_relabel_packet_totals_as_unique_ips(make_controller, backend):
    stats = make_controller(backend(kernel_table(tracking=False))).traffic_stats()
    assert stats["unique_ips"] is None
    assert stats["tracking_available"] is False
    assert stats["dropped_packets"] == 900
    assert stats["counter_error"] == "tracking_not_enabled"


@pytest.mark.parametrize("backend", [Kernel, StatisticsKernel])
@pytest.mark.parametrize(
    "error", [PermissionError("denied"), NftError("failed"), ValueError("bad")]
)
def test_failed_reads_remain_unknown(make_controller, backend, error):
    controller = make_controller(backend(error))
    stats = controller.traffic_stats()
    assert stats["unique_ips"] is None
    assert stats["dropped_packets"] is None
    assert stats["dropped_bytes"] is None
    assert stats["tracking_available"] is False
    assert stats["counter_error"] == "unavailable"
    status = controller.status()
    assert status["active"] is None
    assert status["traffic_stats"] == stats


def test_status_reuses_the_owned_table_inspection(make_controller):
    table = kernel_table()
    kernel = StatisticsKernel(table)
    status = make_controller(kernel).status()
    assert kernel.inspections == 1
    assert kernel.received == [table]
    assert kernel.received[0] is table
    assert status["traffic_stats"]["unique_ips"] == 2
    assert status["traffic_stats"]["dropped_packets"] == 900


def test_injected_kernel_fallback_reuses_status_table(make_controller):
    kernel = Kernel(kernel_table())
    status = make_controller(kernel).status()
    assert kernel.inspections == 1
    assert status["traffic_stats"]["unique_ips"] == 2


def test_traffic_statistics_never_publish_source_addresses_or_write_state(
    make_controller, tmp_path
):
    controller = make_controller(StatisticsKernel(kernel_table()))
    before = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    stats = controller.traffic_stats()
    status = controller.status()
    after = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert before == after
    rendered = json.dumps([stats, status])
    assert "198.51.100.1" not in rendered
    assert "198.51.100.2" not in rendered


def test_failed_counter_read_does_not_publish_raw_kernel_error(make_controller):
    class FailedStats(Kernel):
        def traffic_stats(self):
            raise NftError("invalid source 198.51.100.1")

    stats = make_controller(FailedStats(None)).traffic_stats()
    assert "198.51.100.1" not in json.dumps(stats)
    assert stats["unique_ips"] is None
