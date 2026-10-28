"""Pilot tests exercise real Textual focus, screens and draft transactions."""

import copy
import json
from pathlib import Path

import pytest
from textual.widgets import Input, SelectionList, Static

from geolatch.config import default_config
from geolatch.tui.app import (
    ConfirmApplyScreen,
    EditScreen,
    GeoLatchApp,
    LanguageScreen,
    MainScreen,
    MessageDialog,
    PolicyHubScreen,
    ReviewScreen,
    SettingsScreen,
    WelcomeScreen,
)


class FakeController:
    needs_privileges = False

    def __init__(self, configured=False):
        self.saved = default_config()
        self.saved["network"]["interfaces"] = ["eth0"]
        self.saved["network"]["ipv6"] = False
        if configured:
            self.saved["policies"] = [
                {
                    "name": "primary",
                    "enabled": True,
                    "destinations": ["203.0.113.10"],
                    "block_countries": ["IR"],
                }
            ]
        self.applied = []
        self.confirmed = []
        self.preference_calls = []

    def config(self):
        return copy.deepcopy(self.saved)

    def addresses(self):
        return [
            {
                "interface": "eth0",
                "address": "203.0.113.10",
                "family": 4,
                "public": True,
                "kind": "network",
            },
            {
                "interface": "eth0",
                "address": "203.0.113.20",
                "family": 4,
                "public": True,
                "kind": "network",
            },
            {
                "interface": "lo",
                "address": "127.0.0.1",
                "family": 4,
                "public": False,
                "kind": "loopback",
            },
        ]

    def status(self):
        return {"active": bool(self.confirmed), "policies": len(self.saved["policies"])}

    def save_preferences(self, language):
        self.saved["language"] = language
        self.preference_calls.append(language)

    def apply(self, config=None, safe=True, force=False):
        self.applied.append(copy.deepcopy(config))
        return {"pending": True, "token": "safe-test", "timeout": 90}

    def confirm(self, token):
        self.confirmed.append(token)
        self.saved = copy.deepcopy(self.applied[-1])
        return {"pending": False, "active": True}

    def rollback(self):
        return {"active": False}

    def doctor(self):
        return {"kernel": "test", "nftables": {"available": False}}

    def logs(self):
        return []

    def update(self, dry_run=False, force=False):
        return {"changed": False, "dry_run": dry_run}


@pytest.mark.asyncio
async def test_setup_starts_with_bilingual_language_choice_and_persists_russian():
    controller = FakeController()
    app = GeoLatchApp(controller)
    async with app.run_test(size=(90, 30)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, LanguageScreen)
        assert "Выберите язык" in str(app.screen.query_one(".title", Static).content)
        await pilot.press("down", "enter")
        await pilot.pause()
        assert isinstance(app.screen, WelcomeScreen)
        assert app.language == "ru"
        assert controller.preference_calls == ["ru"]
        assert "Разработчик: @artemkaa_2001" in str(app.screen.query_one("#brand", Static).content)
        assert "Добро пожаловать" in str(app.screen.query_one(".title", Static).content)


@pytest.mark.asyncio
async def test_language_switch_repaints_settings_without_restart():
    controller = FakeController(configured=True)
    app = GeoLatchApp(controller)
    async with app.run_test(size=(90, 30)) as pilot:
        await pilot.pause()
        app.push_screen(SettingsScreen())
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, LanguageScreen)
        await pilot.press("down", "enter")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)
        assert app.language == "ru"
        assert "Настройки" in str(app.screen.query_one(".title", Static).content)
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, MainScreen)
        assert "Главное меню" in str(app.screen.query_one(".title", Static).content)


@pytest.mark.asyncio
async def test_country_search_checkbox_selection_survives_filter_and_back():
    app = GeoLatchApp(FakeController(configured=True))
    async with app.run_test(size=(90, 35)) as pilot:
        await pilot.pause()
        app.push_screen(PolicyHubScreen())
        app.push_screen(EditScreen("countries"))
        await pilot.pause()
        search = app.screen.query_one("#search", Input)
        search.value = "PK"
        await pilot.pause()
        choices = app.screen.query_one("#choices", SelectionList)
        assert choices.option_count == 1
        choices.focus()
        await pilot.press("space")
        await pilot.pause()
        assert set(app.policy["block_countries"]) == {"IR", "PK"}
        search.value = "CN"
        await pilot.pause()
        assert set(app.policy["block_countries"]) == {"IR", "PK"}
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, PolicyHubScreen)
        app.push_screen(EditScreen("countries"))
        await pilot.pause()
        assert set(app.screen.query_one("#choices", SelectionList).selected) == {"IR", "PK"}
        assert app.controller.applied == []


@pytest.mark.asyncio
async def test_enter_advances_interface_step_and_escape_preserves_selection():
    app = GeoLatchApp(FakeController())
    async with app.run_test(size=(95, 35)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.click("#start")
        await pilot.pause()
        assert isinstance(app.screen, EditScreen)
        assert app.screen.step == "interfaces"
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen.step == "destinations"
        choices = app.screen.query_one("#choices", SelectionList)
        choices.highlighted = 1
        await pilot.press("space")
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen.step == "countries"
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen.step == "destinations"
        assert "203.0.113.10" in app.screen.query_one("#choices", SelectionList).selected


@pytest.mark.asyncio
async def test_apply_is_staged_until_explicit_access_confirmation():
    controller = FakeController(configured=True)
    app = GeoLatchApp(controller)
    async with app.run_test(size=(100, 45)) as pilot:
        await pilot.pause()
        app.push_screen(ReviewScreen())
        await pilot.pause()
        await pilot.click("#apply")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmApplyScreen)
        assert len(controller.applied) == 1
        assert not controller.confirmed
        assert app.focused.id == "revert"
        await pilot.click("#confirm")
        await pilot.pause()
        assert controller.confirmed == ["safe-test"]
        await pilot.click("#menu")
        await pilot.pause()
        assert isinstance(app.screen, MainScreen)
        assert len(app.screen_stack) == 2
        assert not app.dirty


@pytest.mark.asyncio
async def test_unsaved_exit_can_be_cancelled_without_applying():
    controller = FakeController(configured=True)
    app = GeoLatchApp(controller)
    async with app.run_test(size=(90, 30)) as pilot:
        await pilot.pause()
        app.policy["block_countries"].append("PK")
        await pilot.press("q")
        await pilot.pause()
        assert isinstance(app.screen, MessageDialog)
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, MainScreen)
        assert app.dirty
        assert controller.applied == []


@pytest.mark.asyncio
async def test_errors_show_localized_dialog_and_preserve_draft():
    class BrokenController(FakeController):
        def apply(self, *args, **kwargs):
            raise RuntimeError("nft check failed")

    controller = BrokenController(configured=True)
    app = GeoLatchApp(controller, language="ru")
    async with app.run_test(size=(100, 45)) as pilot:
        await pilot.pause()
        app.push_screen(ReviewScreen())
        await pilot.pause()
        await pilot.click("#apply")
        await pilot.pause()
        assert isinstance(app.screen, MessageDialog)
        assert "Ошибка операции" in str(app.screen.query_one(".title", Static).content)
        assert app.policy["block_countries"] == ["IR"]


@pytest.mark.asyncio
async def test_small_terminal_has_clear_resize_guidance():
    app = GeoLatchApp(FakeController())
    async with app.run_test(size=(35, 10)) as pilot:
        await pilot.pause()
        assert app.screen.query_one("#small-terminal").display
        assert not app.screen.query_one("#body").display
        await pilot.resize_terminal(90, 30)
        await pilot.pause()
        assert app.screen.query_one("#body").display


def test_tui_translation_catalogs_are_complete_and_have_matching_interpolations():
    root = Path(__file__).parents[1] / "geolatch" / "tui" / "locales"
    english = json.loads((root / "en.json").read_text())
    russian = json.loads((root / "ru.json").read_text())
    from string import Formatter

    formatter = Formatter()
    assert english.keys() == russian.keys()
    for key in english:
        fields_en = {name for _, name, _, _ in formatter.parse(english[key]) if name}
        fields_ru = {name for _, name, _, _ in formatter.parse(russian[key]) if name}
        assert fields_en == fields_ru, key


def test_arbitrary_diagnostic_values_preserve_literal_braces():
    app = GeoLatchApp(FakeController(configured=True), language="ru")
    try:
        assert "unexpected {payload}" in app.format_data({"detail": "unexpected {payload}"})
        assert "table inet geolatch {" in app.format_data("table inet geolatch {")
    finally:
        app._controller_pool.shutdown(wait=False)


@pytest.mark.asyncio
async def test_main_summary_shows_live_unknown_and_cached_geoip_state():
    controller = FakeController(configured=True)
    controller.status = lambda: {
        "active": None,
        "policies": controller.saved["policies"],
        "source": "ipverse-geo",
        "geoip_health": "cached",
        "timer": "unavailable",
    }
    app = GeoLatchApp(controller, language="ru")
    async with app.run_test(size=(100, 35)) as pilot:
        await pilot.pause()
        summary = app.status_summary()
        assert "НЕИЗВЕСТНО" in summary
        assert "Сохранённые сведения" in summary
        assert "Автообновление" in summary


@pytest.mark.asyncio
async def test_complete_setup_adds_second_policy_without_restarting_wizard():
    controller = FakeController()
    app = GeoLatchApp(controller)
    async with app.run_test(size=(105, 45)) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # English
        await pilot.click("#start")
        await pilot.pause()
        await pilot.press("enter")  # interfaces
        await pilot.pause()
        destinations = app.screen.query_one("#choices", SelectionList)
        destinations.highlighted = 1
        await pilot.press("space", "enter")
        await pilot.pause()
        app.screen.query_one("#search", Input).value = "IR"
        await pilot.pause()
        app.screen.query_one("#choices").focus()
        await pilot.press("space", "enter")
        await pilot.pause()
        assert app.screen.step == "families"
        await pilot.press("enter")  # IPv4
        await pilot.pause()
        assert app.screen.step == "provider"
        await pilot.press("enter")  # recommended source
        await pilot.pause()
        assert app.screen.step == "allowlist"
        app.screen.query_one("#allowlist", Input).value = "198.51.100.50/32"
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, PolicyHubScreen)
        await pilot.press("down", "enter")  # add another policy
        await pilot.pause()
        assert app.screen.step == "destinations"
        destinations = app.screen.query_one("#choices", SelectionList)
        destinations.highlighted = 2
        await pilot.press("space", "enter")
        await pilot.pause()
        app.screen.query_one("#search", Input).value = "CN"
        await pilot.pause()
        app.screen.query_one("#choices").focus()
        await pilot.press("space", "enter")
        await pilot.pause()
        assert isinstance(app.screen, PolicyHubScreen)
        assert len(app.draft["policies"]) == 2
        assert app.draft["policies"][0]["block_countries"] == ["IR"]
        assert app.draft["policies"][1]["block_countries"] == ["CN"]
        assert app.draft["allowlist"]["ipv4"] == ["198.51.100.50/32"]
        assert controller.applied == []


@pytest.mark.parametrize("quit_key", [b"q", b"\x03"])
@pytest.mark.parametrize("privileged", [False, True])
def test_real_terminal_restores_alternate_screen_cursor_and_termios(tmp_path, quit_key, privileged):
    """Exercise the actual Textual driver, without touching host firewall state."""
    import fcntl
    import os
    import pty
    import select
    import struct
    import subprocess
    import sys
    import termios
    import time

    if sys.platform != "linux":
        pytest.skip("Linux terminal lifecycle test")
    script = tmp_path / "terminal_app.py"
    marker = tmp_path / "privileged.json"
    script.write_text(
        "from types import SimpleNamespace\n"
        "from contextlib import contextmanager\n"
        "import json, sys, termios, threading\n"
        "from pathlib import Path\n"
        "from geolatch.config import default_config\n"
        "from geolatch.tui import GeoLatchApp\n"
        "main_thread = threading.get_ident()\n"
        "class Controller(SimpleNamespace):\n"
        f"    needs_privileges = {privileged!r}\n"
        "    def run_privileged(self, operation, payload):\n"
        "        result = {'worker': threading.get_ident(), 'main': main_thread, "
        "'flags': termios.tcgetattr(sys.stdin.fileno())[3]}\n"
        f"        Path({str(marker)!r}).write_text(json.dumps(result))\n"
        "        return {}\n"
        "class AuditedApp(GeoLatchApp):\n"
        f"    CSS_PATH = {str(Path(__file__).parents[1] / 'geolatch' / 'tui' / 'styles.tcss')!r}\n"
        "    @contextmanager\n"
        "    def suspend(self):\n"
        "        assert threading.get_ident() == main_thread\n"
        "        with super().suspend():\n"
        "            yield\n"
        "controller = Controller(config=default_config, addresses=lambda: [], "
        "status=lambda: {'active': False})\n"
        "AuditedApp(controller=controller).run()\n"
    )
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 90, 0, 0))
    process = subprocess.Popen(
        [sys.executable, "-c", script.read_text()],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env={**os.environ, "TERM": "xterm-256color"},
        cwd=Path(__file__).parents[1],
    )
    output = bytearray()
    deadline = time.monotonic() + 10
    quit_sent = False
    selection_sent = False
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                output.extend(os.read(master, 65536))
            if privileged and not selection_sent and b"Select your language" in output:
                os.write(master, b"\r")
                selection_sent = True
            ready_to_quit = b"Welcome to GeoLatch" if privileged else b"Select your language"
            if not quit_sent and ready_to_quit in output:
                os.write(master, quit_key)
                quit_sent = True
            if process.poll() is not None:
                while select.select([master], [], [], 0)[0]:
                    output.extend(os.read(master, 65536))
                break
        assert process.poll() == 0, output.decode(errors="replace")[-2000:]
        assert quit_sent
        assert b"\x1b[?1049h" in output
        assert b"\x1b[?1049l" in output
        assert b"\x1b[?25h" in output
        restored = termios.tcgetattr(slave)
        flags = termios.ECHO | termios.ICANON | termios.ISIG
        assert restored[3] & flags == original[3] & flags
        if privileged:
            suspended = json.loads(marker.read_text())
            assert suspended["worker"] != suspended["main"]
            assert suspended["flags"] & flags == original[3] & flags
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)
        os.close(slave)


@pytest.mark.asyncio
async def test_real_controller_persists_language_then_commits_only_after_tui_confirmation(tmp_path):
    """Use real configuration, journals and commit logic with isolated IO boundaries."""
    from test_controller import Kernel, Store

    from geolatch.config import load_config
    from geolatch.controller import Controller, _read_snapshot
    from geolatch.paths import Paths
    from geolatch.tui.app import CompletedScreen

    paths = Paths(tmp_path / "etc" / "config.yaml", tmp_path / "state", tmp_path / "cache")
    kernel = Kernel()
    controller = Controller(
        paths,
        nft=kernel,
        store=Store(),
        enforce_privileges=False,
        arm_watchdog=lambda token: None,
    )
    controller.addresses = lambda: FakeController().addresses()
    controller._timer_state = lambda: "inactive"
    controller._sync_timer = lambda config: []
    app = GeoLatchApp(controller, setup=True)
    async with app.run_test(size=(105, 45)) as pilot:
        await pilot.pause()
        await pilot.press("down", "enter")
        await pilot.pause()
        saved_preferences = load_config(paths.config_file)
        assert saved_preferences["language"] == "ru"
        assert saved_preferences["policies"] == []
        assert kernel.applied == []
        assert not paths.pending.exists()
        candidate = FakeController(configured=True).config()
        candidate["language"] = "ru"
        app.draft = copy.deepcopy(candidate)
        app.push_screen(ReviewScreen())
        await pilot.pause()
        await pilot.click("#apply")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmApplyScreen)
        assert paths.pending.exists()
        assert kernel.rules is not None
        assert load_config(paths.config_file)["policies"] == []
        assert not paths.confirmed.exists()
        assert not any(isinstance(screen, CompletedScreen) for screen in app.screen_stack)
        await pilot.click("#confirm")
        await pilot.pause()
        assert isinstance(app.screen, CompletedScreen)
        assert not paths.pending.exists()
        assert load_config(paths.config_file) == candidate
        assert _read_snapshot(paths.confirmed)["config"] == candidate
        assert not any(isinstance(screen, ConfirmApplyScreen) for screen in app.screen_stack)
    # A language preference file left by interrupted setup still resumes setup.
    interrupted = Controller(
        Paths(
            tmp_path / "interrupted" / "config.yaml",
            tmp_path / "interrupted-state",
            tmp_path / "interrupted-cache",
        ),
        nft=Kernel(),
        store=Store(),
        enforce_privileges=False,
    )
    interrupted.save_preferences("ru")
    restarted = GeoLatchApp(interrupted)
    assert restarted.setup_mode
    restarted._controller_pool.shutdown(wait=False)
