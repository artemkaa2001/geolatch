"""Live unique-IP summaries retain focus and never invent counts on read errors."""

import copy
import threading

import pytest
from textual.widgets import OptionList, Static

from geolatch.config import default_config
from geolatch.tui.app import GeoLatchApp, MainScreen, SettingsScreen, StatisticsScreen


class TrafficController:
    needs_privileges = True

    def __init__(self):
        self.saved = default_config()
        self.saved["policies"] = [
            {
                "name": "primary",
                "enabled": True,
                "destinations": ["203.0.113.10"],
                "block_countries": ["IR"],
            }
        ]
        self.traffic = {
            "unique_ips": 12,
            "unique_limit_reached": False,
            "tracking_available": True,
            "dropped_packets": 9000,
            "dropped_bytes": 720000,
            "counter_error": None,
        }
        self.calls = 0
        self.error = False
        self.gate = None
        self.started = threading.Event()

    def config(self):
        return copy.deepcopy(self.saved)

    def addresses(self):
        return []

    def status(self):
        return {"active": True, "traffic_stats": copy.deepcopy(self.traffic)}

    def traffic_stats(self):
        self.calls += 1
        self.started.set()
        if self.gate is not None:
            assert self.gate.wait(5)
        if self.error:
            raise PermissionError("unavailable")
        return copy.deepcopy(self.traffic)

    def run_privileged(self, *args, **kwargs):
        raise AssertionError("Polling must not invoke sudo")


def rendered(widget):
    return str(widget.render())


@pytest.mark.asyncio
async def test_main_unique_count_refresh_preserves_menu_and_focus():
    controller = TrafficController()
    app = GeoLatchApp(controller, language="ru")
    async with app.run_test(size=(60, 30)) as pilot:
        await app.workers.wait_for_complete()
        menu = app.screen.query_one("#menu", OptionList)
        menu.highlighted = 4
        menu.focus()
        summary = app.screen.query_one("#status-summary", Static)
        assert "Отброшено: 12 IP" in rendered(summary)
        assert "9000 IP" not in rendered(summary)
        controller.traffic["unique_ips"] = 13
        app.refresh_traffic_stats()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert "Отброшено: 13 IP" in rendered(summary)
        assert app.screen.query_one("#menu") is menu
        assert menu.highlighted == 4 and app.focused is menu
        assert controller.calls == 1


@pytest.mark.asyncio
async def test_statistics_has_lower_bound_details_and_legacy_hint():
    controller = TrafficController()
    controller.traffic.update(unique_ips=65536, unique_limit_reached=True)
    app = GeoLatchApp(controller, language="ru")
    async with app.run_test(size=(60, 35)) as pilot:
        await app.workers.wait_for_complete()
        app.screen.chosen("stats")
        await pilot.pause()
        await app.workers.wait_for_complete()
        assert isinstance(app.screen, StatisticsScreen)
        summary = app.screen.query_one("#traffic-summary", Static)
        text = rendered(summary)
        assert "≥ 65\u202f536 IP" in text
        assert "9\u202f000" in text and "720\u202f000" in text
        assert "блокировка продолжается" in text
        controller.traffic.update(
            unique_ips=None,
            tracking_available=False,
            unique_limit_reached=False,
            counter_error="tracking_not_enabled",
        )
        app.refresh_traffic_stats()
        await app.workers.wait_for_complete()
        assert "Отброшено: нет данных" in rendered(summary)
        assert "один раз просмотрите и примените" in rendered(summary)
        assert "Отброшено: 0 IP" not in rendered(summary)
        await pilot.press("escape")
        assert isinstance(app.screen, MainScreen)


@pytest.mark.asyncio
async def test_poll_errors_clear_stale_count_and_edit_screens_do_not_poll():
    controller = TrafficController()
    app = GeoLatchApp(controller, language="en")
    async with app.run_test() as pilot:
        await app.workers.wait_for_complete()
        controller.error = True
        app.refresh_traffic_stats()
        await app.workers.wait_for_complete()
        assert "Dropped: no data" in rendered(app.screen.query_one("#status-summary", Static))
        app.push_screen(SettingsScreen())
        await pilot.pause()
        app.refresh_traffic_stats()
        await app.workers.wait_for_complete()
        assert controller.calls == 1


@pytest.mark.asyncio
async def test_overlapping_refreshes_share_one_pending_read():
    controller = TrafficController()
    controller.gate = threading.Event()
    app = GeoLatchApp(controller, language="en")
    async with app.run_test() as pilot:
        await app.workers.wait_for_complete()
        try:
            app.refresh_traffic_stats()
            app.refresh_traffic_stats()
            await pilot.pause()
            assert controller.started.is_set()
            app.refresh_traffic_stats()
            assert controller.calls == 1
        finally:
            controller.gate.set()
        await app.workers.wait_for_complete()
        assert not app._traffic_loading
