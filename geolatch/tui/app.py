"""Textual screens for shared GeoLatch operations.

All configuration edits stay in a draft until the shared controller commits a
safe transaction. Textual owns the alternate screen and terminal restoration.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import os
import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any

from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Input, LoadingIndicator, OptionList, SelectionList, Static
from textual.widgets.option_list import Option

from geolatch.config import validate_config
from geolatch.i18n import countries, country_name
from geolatch.metadata import DEVELOPER, NAME, VERSION

from .translations import translate

Config = dict[str, Any]


class ContinueList(SelectionList[str]):
    """Space toggles a choice; Enter advances a wizard page."""

    BINDINGS = [Binding("enter", "continue", show=False)]

    class Continue(Message):
        pass

    def action_continue(self) -> None:
        self.post_message(self.Continue())


class BaseScreen(Screen[None]):
    BINDINGS = [
        Binding("escape", "back", show=False),
        Binding("q", "leave", show=False),
    ]

    @property
    def geo(self) -> GeoLatchApp:
        return self.app  # type: ignore[return-value]

    def tr(self, key: str, **values: object) -> str:
        return self.geo.tr(key, **values)

    def compose_body(self) -> ComposeResult:
        return
        yield

    def compose(self) -> ComposeResult:
        yield Static(self.geo.brand(), id="brand", markup=False)
        yield Static(self.tr("small"), id="small-terminal", markup=False)
        with VerticalScroll(id="body"):
            yield from self.compose_body()
        yield Static(self.tr("hint"), id="hint", markup=False)

    def on_resize(self, event: events.Resize) -> None:
        small = event.size.width < 42 or event.size.height < 12
        self.query_one("#small-terminal").display = small
        self.query_one("#body").display = not small

    def action_back(self) -> None:
        if len(self.geo.screen_stack) > 2:
            self.geo.pop_screen()
        else:
            self.geo.request_exit()

    def action_leave(self) -> None:
        self.geo.request_exit()

    def title_widget(self, key: str, **values: object) -> Static:
        return Static(self.tr(key, **values), classes="title", markup=False)

    def text_widget(self, key: str, **values: object) -> Static:
        return Static(self.tr(key, **values), classes="explanation", markup=False)

    def show_error(self, exc: object) -> None:
        self.geo.push_screen(MessageDialog("error", self.tr("error.detail", detail=str(exc))))


class MessageDialog(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", show=False)]

    def __init__(self, title: str, message: str, *, confirm: bool = False) -> None:
        super().__init__()
        self.title_key = title
        self.message = message
        self.confirm = confirm

    @property
    def geo(self) -> GeoLatchApp:
        return self.app  # type: ignore[return-value]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(self.geo.tr(self.title_key), classes="title", markup=False)
            yield Static(self.message, markup=False)
            with Horizontal(classes="actions"):
                yield Button(self.geo.tr("no" if self.confirm else "close"), id="cancel")
                if self.confirm:
                    yield Button(self.geo.tr("yes"), id="yes", variant="warning")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_cancel(self) -> None:
        self.dismiss(False)


class LanguageScreen(BaseScreen):
    """The first complete screen is always bilingual on initial setup."""

    def __init__(self, initial: bool = True) -> None:
        super().__init__()
        self.initial = initial

    def compose_body(self) -> ComposeResult:
        yield self.title_widget("language.title")
        yield OptionList(Option("English", id="en"), Option("Русский", id="ru"), id="language")

    def on_mount(self) -> None:
        choices = self.query_one("#language", OptionList)
        choices.highlighted = 1 if self.geo.language == "ru" else 0
        choices.focus()

    async def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        language = event.option.id or "en"
        try:
            await self.geo.operation("preferences", {"language": language})
        except Exception as exc:
            self.show_error(exc)
            return
        self.geo.language = language
        self.geo.draft["language"] = language
        self.geo.original["language"] = language
        if self.initial:
            self.geo.switch_screen(WelcomeScreen())
        else:
            # Inactive screens are recomposed when resumed, so all visible text
            # changes immediately while drafts and navigation state survive.
            self.geo.pop_screen()

    def action_back(self) -> None:
        if self.initial:
            self.geo.request_exit()
        else:
            super().action_back()


class WelcomeScreen(BaseScreen):
    def compose_body(self) -> ComposeResult:
        yield self.title_widget("welcome.title")
        yield self.text_widget("welcome.text")
        yield Button(self.tr("welcome.start"), id="start", variant="primary")

    def on_mount(self) -> None:
        self.query_one(Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            self.geo.ensure_policy()
            self.geo.push_screen(EditScreen("interfaces", flow="setup"))


class MenuScreen(BaseScreen):
    """OptionList menus support arrows and Enter, including compact terminals."""

    title_key = "main"

    def __init__(self) -> None:
        super().__init__()
        self._mounted_once = False

    def menu_options(self) -> list[tuple[str, str]]:
        return []

    def compose_body(self) -> ComposeResult:
        yield self.title_widget(self.title_key)
        yield OptionList(
            *(Option(self.tr(label), id=action) for action, label in self.menu_options()), id="menu"
        )

    def on_mount(self) -> None:
        self._mounted_once = True
        self.query_one("#menu", OptionList).focus()

    async def on_screen_resume(self) -> None:
        if self._mounted_once:
            await self.repaint_menu()

    async def repaint_menu(self) -> None:
        await self.recompose()
        if self.is_current:
            self.query_one("#menu", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.chosen(event.option.id)

    def chosen(self, action: str) -> None:
        raise NotImplementedError


class MainScreen(MenuScreen):
    title_key = "main"

    def status_summary(self) -> str:
        return self.geo.status_summary()

    def compose_body(self) -> ComposeResult:
        yield self.title_widget("main")
        yield Static(self.status_summary(), id="status-summary", classes="summary", markup=False)
        if self.geo.dirty:
            yield self.text_widget("main.pending")
        yield OptionList(
            *(Option(self.tr(label), id=action) for action, label in self.menu_options()), id="menu"
        )

    def update_status(self) -> None:
        if not self.query("#status-summary"):
            return
        self.query_one("#status-summary", Static).update(self.status_summary())
        menu = self.query_one("#menu", OptionList)
        highlighted = menu.highlighted
        menu.clear_options()
        menu.add_options(Option(self.tr(label), id=action) for action, label in self.menu_options())
        menu.highlighted = highlighted if highlighted is not None else 0

    def menu_options(self) -> list[tuple[str, str]]:
        return [
            ("blocks", "main.blocks"),
            ("addresses", "main.addresses"),
            ("policies", "main.policies"),
            ("update", "main.update"),
            ("stats", "main.stats"),
            ("settings", "main.settings"),
            ("doctor", "main.doctor"),
            ("review", "main.review"),
            ("rollback", "main.rollback"),
            ("disable", "main.disable")
            if self.geo.last_status.get("active")
            else ("enable", "main.enable"),
            ("exit", "exit"),
        ]

    def chosen(self, action: str) -> None:
        if action in {"blocks", "addresses", "policies"}:
            self.geo.push_screen(PolicyHubScreen())
        elif action == "settings":
            self.geo.push_screen(SettingsScreen())
        elif action == "update":
            self.geo.push_screen(UpdateScreen())
        elif action == "stats":
            self.geo.push_screen(DataScreen("stats.title", "status"))
        elif action == "doctor":
            self.geo.push_screen(DataScreen("doctor.title", "doctor"))
        elif action == "review":
            self.geo.push_screen(ReviewScreen())
        elif action in {"disable", "rollback"}:
            self.geo.push_screen(
                MessageDialog(f"{action}.title", self.tr(f"{action}.text"), confirm=True),
                lambda yes: self.geo.push_screen(OperationScreen(action)) if yes else None,
            )
        elif action == "enable":
            self.geo.draft["enabled"] = True
            self.geo.push_screen(ReviewScreen())
        elif action == "exit":
            self.geo.request_exit()


class EditScreen(BaseScreen):
    """A separate screen per wizard step, with all choices retained in a draft."""

    BINDINGS = [Binding("enter", "next", show=False)]
    STEPS = ("interfaces", "destinations", "countries", "families", "provider", "allowlist")

    def __init__(self, step: str, *, flow: str = "edit") -> None:
        super().__init__()
        self.step = step
        self.flow = flow
        self.country_selection: set[str] = set()
        self.manual_addresses: set[str] = set()
        self._rebuilding = False

    def compose_body(self) -> ComposeResult:
        yield self.title_widget(f"{self.step}.title")
        yield self.text_widget(f"{self.step}.text")
        draft = self.geo.draft
        if self.step == "interfaces":
            rows: dict[str, list[dict[str, Any]]] = {}
            for row in self.geo.address_rows:
                rows.setdefault(row["interface"], []).append(row)
            if not rows:
                yield self.text_widget("interfaces.empty")
            selected = set(draft["network"]["interfaces"])
            if not selected and self.flow == "setup":
                selected = {
                    row["interface"]
                    for row in self.geo.address_rows
                    if row.get("public")
                    and row.get("kind") not in {"loopback", "bridge", "tunnel", "vpn"}
                }
            options = []
            for name, addresses in rows.items():
                kind = addresses[0].get("kind", "network")
                description = self.tr(f"kind.{kind}")
                address_text = ", ".join(row["address"] for row in addresses)
                options.append(
                    (Text(f"{name}  [{description}]  {address_text}"), name, name in selected)
                )
            yield ContinueList(*options, id="choices")
        elif self.step == "destinations":
            selected = self.geo.policy["destinations"]
            explicit = set() if selected == "all" else set(selected)
            options = [(Text(self.tr("destinations.all")), "all", selected == "all")]
            seen: set[str] = set()
            for row in self.geo.address_rows:
                if row["interface"] not in draft["network"]["interfaces"]:
                    continue
                address = row["address"]
                if address in seen:
                    continue
                seen.add(address)
                options.append(
                    (Text(f"{address}  {row['interface']}"), address, address in explicit)
                )
            for address in sorted(explicit | self.manual_addresses):
                if address not in seen:
                    options.append((Text(f"{address}  ⚠"), address, True))
            yield ContinueList(*options, id="choices")
            yield Static(
                self.tr("countries.selected", count=len(explicit)),
                id="destination-count",
                classes="counter",
                markup=False,
            )
            yield Input(placeholder=self.tr("destinations.manual"), id="manual-ip")
            yield self.text_widget("destinations.warning")
            yield Button(self.tr("destinations.add"), id="add-ip")
        elif self.step == "countries":
            self.country_selection = set(self.geo.policy["block_countries"])
            yield Input(placeholder=self.tr("countries.search"), id="search")
            yield ContinueList(*self.country_options(), id="choices")
            yield Static(
                self.tr("countries.selected", count=len(self.country_selection)),
                id="selected-count",
                classes="counter",
                markup=False,
            )
            yield Button(self.tr("countries.clear"), id="clear")
        elif self.step == "families":
            yield OptionList(
                Option(self.tr("families.v4"), id="v4"),
                Option(self.tr("families.v6"), id="v6"),
                Option(self.tr("families.both"), id="both"),
                id="single-choice",
            )
        elif self.step == "provider":
            yield OptionList(
                Option(self.tr("provider.geo"), id="ipverse-geo"),
                Option(self.tr("provider.rir"), id="ipverse-rir"),
                id="single-choice",
            )
        elif self.step == "allowlist":
            peer = os.environ.get("SSH_CONNECTION", "").split()
            if peer:
                yield self.text_widget("allowlist.peer", peer=peer[0])
            values = draft["allowlist"]["ipv4"] + draft["allowlist"]["ipv6"]
            yield Input(
                ", ".join(values), placeholder=self.tr("allowlist.placeholder"), id="allowlist"
            )
        with Horizontal(classes="actions"):
            yield Button(self.tr("continue"), id="continue", variant="primary")
            yield Button(self.tr("back"), id="back")
        yield Static("", id="validation", classes="error-text", markup=False)

    def country_options(self, query: str = "") -> list[tuple[Text, str, bool]]:
        query = query.strip().casefold()
        matches = [
            (Text(f"{name}  {code}"), code, code in self.country_selection)
            for code, name in countries(self.geo.language)
            if not query or query in name.casefold() or query in code.casefold()
        ]
        # ISO searches should put their exact country first (IR otherwise also
        # matches Bonaire and Ireland). Name matches keep localized ordering.
        return sorted(matches, key=lambda option: option[1].casefold() != query)

    def on_mount(self) -> None:
        if self.step == "countries":
            self.query_one("#search", Input).focus()
        elif self.query("#choices"):
            self.query_one("#choices").focus()
        elif self.query("#single-choice"):
            choices = self.query_one("#single-choice", OptionList)
            if self.step == "provider":
                choices.highlighted = 1 if self.geo.draft["source"] == "ipverse-rir" else 0
            else:
                network = self.geo.draft["network"]
                choices.highlighted = (
                    2 if network["ipv4"] and network["ipv6"] else 0 if network["ipv4"] else 1
                )
            choices.focus()
        else:
            self.query_one(Input).focus()

    def on_continue_list_continue(self, event: ContinueList.Continue) -> None:
        self.action_next()

    def on_selection_list_selection_toggled(self, event: SelectionList.SelectionToggled) -> None:
        if self.step != "destinations":
            return
        choices = self.query_one("#choices", SelectionList)
        value = event.selection.value
        if value not in choices.selected:
            return
        if value == "all":
            for selected in list(choices.selected):
                if selected != "all":
                    choices.deselect(selected)
        else:
            choices.deselect("all")

    def on_selection_list_selected_changed(self, event: SelectionList.SelectedChanged) -> None:
        if self.step == "destinations":
            selected = self.query_one("#choices", SelectionList).selected
            count = self.tr("all") if "all" in selected else len(selected)
            self.query_one("#destination-count", Static).update(
                self.tr("countries.selected", count=count)
            )
            return
        if self.step == "countries" and not self._rebuilding:
            choices = self.query_one("#choices", SelectionList)
            visible = {choices.get_option_at_index(i).value for i in range(choices.option_count)}
            self.country_selection.difference_update(visible)
            self.country_selection.update(choices.selected)
            self.geo.policy["block_countries"] = sorted(self.country_selection)
            self.query_one("#selected-count", Static).update(
                self.tr("countries.selected", count=len(self.country_selection))
            )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            choices = self.query_one("#choices", SelectionList)
            self._rebuilding = True
            choices.clear_options()
            choices.add_options(self.country_options(event.value))
            choices.highlighted = 0 if choices.option_count else None
            self._rebuilding = False

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "manual-ip":
            self.add_address()
        elif event.input.id == "search":
            self.query_one("#choices").focus()
        else:
            self.action_next()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "single-choice":
            return
        if self.step == "provider":
            self.geo.draft["source"] = event.option.id
        elif self.step == "families":
            family = event.option.id
            network = self.geo.draft["network"]
            network["ipv4"] = family in {"v4", "both"}
            network["ipv6"] = family in {"v6", "both"}
            available = {
                row["family"]
                for row in self.geo.address_rows
                if row["interface"] in network["interfaces"]
            }
            if (network["ipv4"] and 4 not in available) or (network["ipv6"] and 6 not in available):
                self.geo.push_screen(
                    MessageDialog("families.title", self.tr("families.unavailable")),
                    lambda _: self.advance(),
                )
                return
        self.advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "continue":
            self.action_next()
        elif event.button.id == "back":
            self.action_back()
        elif event.button.id == "add-ip":
            self.add_address()
        elif event.button.id == "clear":
            self.country_selection.clear()
            self.geo.policy["block_countries"] = []
            self.query_one("#choices", SelectionList).deselect_all()

    def add_address(self) -> None:
        input_widget = self.query_one("#manual-ip", Input)
        try:
            address = ipaddress.ip_address(input_widget.value.strip())
            if (
                address.is_unspecified
                or address.is_multicast
                or address.is_loopback
                or address.is_link_local
            ):
                raise ValueError
        except ValueError:
            self.query_one("#validation", Static).update(self.tr("destinations.invalid"))
            return
        value = str(address)
        choices = self.query_one("#choices", SelectionList)
        choices.deselect("all")
        present = {choices.get_option_at_index(i).value for i in range(choices.option_count)}
        if value not in present:
            choices.add_option((Text(f"{value}  ⚠"), value, True))
            self.manual_addresses.add(value)
        else:
            choices.select(value)
        input_widget.value = ""
        self.query_one("#validation", Static).update("")

    def save(self) -> bool:
        draft = self.geo.draft
        if self.step == "interfaces":
            selected = self.query_one("#choices", SelectionList).selected
            if not selected:
                self.query_one("#validation", Static).update(self.tr("interfaces.required"))
                return False
            draft["network"]["interfaces"] = list(selected)
        elif self.step == "destinations":
            selected = self.query_one("#choices", SelectionList).selected
            if not selected:
                self.query_one("#validation", Static).update(self.tr("destinations.required"))
                return False
            self.geo.policy["destinations"] = "all" if "all" in selected else list(selected)
        elif self.step == "countries":
            self.geo.policy["block_countries"] = sorted(self.country_selection)
        elif self.step == "allowlist":
            values = re.split(r"[\s,;]+", self.query_one("#allowlist", Input).value.strip())
            allowlist: dict[str, list[str]] = {"ipv4": [], "ipv6": []}
            for value in filter(None, values):
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    if network.prefixlen == 0 or network.is_multicast or network.is_unspecified:
                        raise ValueError
                except ValueError:
                    self.query_one("#validation", Static).update(
                        self.tr("allowlist.invalid", value=value)
                    )
                    return False
                allowlist[f"ipv{network.version}"].append(str(network))
            draft["allowlist"] = allowlist
        return True

    def action_next(self) -> None:
        if self.step in {"families", "provider"}:
            choices = self.query_one("#single-choice", OptionList)
            if choices.highlighted is not None:
                choices.action_select()
            return
        if (
            self.focused
            and isinstance(self.focused, Input)
            and self.focused.id == "manual-ip"
            and self.focused.value
        ):
            self.add_address()
            return
        if self.save():
            self.advance()

    def action_back(self) -> None:
        # Invalid or incomplete drafts are retained as widget state on the stack;
        # valid values are also copied into the shared draft for sibling editors.
        self.save()
        super().action_back()

    def advance(self) -> None:
        if self.flow == "setup":
            index = self.STEPS.index(self.step)
            if index + 1 < len(self.STEPS):
                self.geo.push_screen(EditScreen(self.STEPS[index + 1], flow=self.flow))
            else:
                self.geo.push_screen(PolicyHubScreen(setup=True))
        elif self.flow == "new":
            if self.step == "destinations":
                self.geo.push_screen(EditScreen("countries", flow="new"))
            else:
                self.geo.push_screen(PolicyHubScreen(setup=self.geo.setup_mode))
        else:
            self.geo.pop_screen()


class PolicyHubScreen(MenuScreen):
    title_key = "policies.title"

    def __init__(self, setup: bool = False) -> None:
        super().__init__()
        self.setup = setup

    def compose_body(self) -> ComposeResult:
        yield self.title_widget(self.title_key)
        yield self.text_widget("policies.text")
        if not self.geo.draft["policies"]:
            yield self.text_widget("policies.none")
        options = []
        for index, policy in enumerate(self.geo.draft["policies"]):
            state = self.tr("state.enabled" if policy["enabled"] else "state.disabled")
            destinations = (
                self.tr("all")
                if policy["destinations"] == "all"
                else ", ".join(policy["destinations"])
            )
            options.append(
                Option(Text(f"{policy['name']} · {state} · {destinations}"), id=f"policy-{index}")
            )
        options.extend(
            [
                Option(self.tr("policies.new"), id="new"),
                Option(self.tr("policies.review"), id="review"),
            ]
        )
        yield OptionList(*options, id="menu")

    def chosen(self, action: str) -> None:
        if action.startswith("policy-"):
            self.geo.active_policy = int(action.split("-", 1)[1])
            self.geo.push_screen(PolicyScreen())
        elif action == "new":
            self.geo.new_policy()
            self.geo.push_screen(EditScreen("destinations", flow="new"))
        elif action == "review":
            self.geo.push_screen(ReviewScreen())


class PolicyScreen(MenuScreen):
    def compose_body(self) -> ComposeResult:
        yield self.title_widget("policy.title", name=self.geo.policy["name"])
        yield Static(self.geo.policy_summary(self.geo.policy), classes="summary", markup=False)
        yield OptionList(
            *(Option(self.tr(label), id=action) for action, label in self.menu_options()), id="menu"
        )

    def menu_options(self) -> list[tuple[str, str]]:
        return [
            ("destinations", "policy.destinations"),
            ("countries", "policy.countries"),
            ("rename", "policy.rename"),
            ("toggle", "policy.toggle"),
            ("delete", "policy.delete"),
        ]

    def chosen(self, action: str) -> None:
        if action in {"destinations", "countries"}:
            self.geo.push_screen(EditScreen(action))
        elif action == "rename":
            self.geo.push_screen(RenameScreen())
        elif action == "toggle":
            self.geo.policy["enabled"] = not self.geo.policy["enabled"]
            self.run_worker(self.repaint_menu())
        elif action == "delete":
            self.geo.push_screen(
                MessageDialog("policy.delete.title", self.tr("policy.delete.text"), confirm=True),
                self.delete_policy,
            )

    def delete_policy(self, confirmed: bool) -> None:
        if confirmed:
            self.geo.draft["policies"].pop(self.geo.active_policy)
            self.geo.active_policy = 0
            self.geo.pop_screen()


class RenameScreen(BaseScreen):
    BINDINGS = [Binding("enter", "save", show=False)]

    def compose_body(self) -> ComposeResult:
        yield self.title_widget("policy.name")
        yield Input(self.geo.policy["name"], id="name")
        yield Button(self.tr("continue"), id="save", variant="primary")
        yield Static("", id="validation", classes="error-text", markup=False)

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.action_save()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.action_save()

    def action_save(self) -> None:
        name = self.query_one(Input).value.strip()
        duplicate = any(
            policy["name"] == name
            for index, policy in enumerate(self.geo.draft["policies"])
            if index != self.geo.active_policy
        )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) or duplicate:
            self.query_one("#validation", Static).update(self.tr("policy.name.invalid"))
            return
        self.geo.policy["name"] = name
        self.geo.pop_screen()


class SettingsScreen(MenuScreen):
    title_key = "settings.title"

    def menu_options(self) -> list[tuple[str, str]]:
        return [
            ("language", "language"),
            ("provider", "provider.title"),
            ("updates", "settings.updates"),
            ("families", "families.title"),
            ("interfaces", "interfaces.title"),
            ("allowlist", "allowlist.title"),
            ("established", "settings.established"),
            ("review", "main.review"),
        ]

    def chosen(self, action: str) -> None:
        if action == "language":
            self.geo.push_screen(LanguageScreen(initial=False))
        elif action in EditScreen.STEPS:
            self.geo.push_screen(EditScreen(action))
        elif action in {"updates", "established"}:
            self.geo.push_screen(SettingChoiceScreen(action))
        elif action == "review":
            self.geo.push_screen(ReviewScreen())


class SettingChoiceScreen(MenuScreen):
    def __init__(self, kind: str) -> None:
        super().__init__()
        self.kind = kind
        self.title_key = f"{kind}.title"

    def compose_body(self) -> ComposeResult:
        if self.kind == "established":
            yield self.text_widget("established.text")
        yield from super().compose_body()

    def menu_options(self) -> list[tuple[str, str]]:
        if self.kind == "updates":
            return [
                ("daily", "updates.daily"),
                ("hourly", "updates.hourly"),
                ("weekly", "updates.weekly"),
                ("off", "updates.off"),
            ]
        return [("on", "established.on"), ("off", "established.off")]

    def chosen(self, action: str) -> None:
        if self.kind == "updates":
            self.geo.draft["updates"]["enabled"] = action != "off"
            if action != "off":
                self.geo.draft["updates"]["interval"] = action
        else:
            self.geo.draft["firewall"]["preserve_established"] = action == "on"
        self.geo.pop_screen()


class ReviewScreen(BaseScreen):
    def compose_body(self) -> ComposeResult:
        yield self.title_widget("review.title")
        yield self.text_widget("review.text")
        draft = self.geo.draft
        network = draft["network"]
        families = "+".join(f"IPv{family}" for family in (4, 6) if network[f"ipv{family}"])
        updates = (
            self.tr(f"updates.{draft['updates']['interval']}")
            if draft["updates"]["enabled"]
            else self.tr("state.disabled")
        )
        yield Static(
            self.tr(
                "review.config",
                interfaces=", ".join(network["interfaces"]) or self.tr("none"),
                families=families,
                source=draft["source"],
                updates=updates,
                established=self.geo.bool_text(draft["firewall"]["preserve_established"]),
                allowlist=", ".join(draft["allowlist"]["ipv4"] + draft["allowlist"]["ipv6"])
                or self.tr("none"),
            ),
            classes="summary",
            markup=False,
        )
        for policy in draft["policies"]:
            yield Static(self.geo.policy_summary(policy), classes="summary", markup=False)
        yield Button(self.tr("review.apply"), id="apply", variant="warning")
        yield Button(self.tr("review.edit"), id="edit")
        yield Button(self.tr("review.cancel"), id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply":
            try:
                validate_config(self.geo.draft)
            except Exception as exc:
                self.show_error(exc)
                return
            self.geo.push_screen(
                OperationScreen("apply", {"config": copy.deepcopy(self.geo.draft), "safe": True})
            )
        elif event.button.id == "edit":
            self.geo.push_screen(PolicyHubScreen(setup=self.geo.setup_mode))
        elif event.button.id == "cancel":
            self.geo.push_screen(
                MessageDialog("cancel.title", self.tr("cancel.text"), confirm=True), self.discard
            )

    def discard(self, yes: bool) -> None:
        if yes:
            self.geo.draft = copy.deepcopy(self.geo.original)
            self.geo.show_main()


class OperationScreen(BaseScreen):
    """A worker keeps rendering responsive during network and nft operations."""

    BINDINGS: list[Binding] = []

    def __init__(self, operation: str, payload: dict[str, Any] | None = None) -> None:
        super().__init__()
        self.operation_name = operation
        self.payload = payload or {}

    def compose_body(self) -> ComposeResult:
        yield self.title_widget(
            "progress.title" if self.operation_name == "apply" else "progress.generic"
        )
        yield self.text_widget(
            "progress.text" if self.operation_name == "apply" else "progress.generic"
        )
        yield LoadingIndicator()

    def on_mount(self) -> None:
        self.execute()

    @work(exclusive=True)
    async def execute(self) -> None:
        try:
            result = await self.geo.operation(self.operation_name, self.payload)
        except Exception as exc:
            self.geo.pop_screen()
            self.geo.push_screen(MessageDialog("error", self.tr("error.detail", detail=str(exc))))
            return
        if result.get("pending") and result.get("token"):
            self.geo.switch_screen(ConfirmApplyScreen(result))
            return
        if self.operation_name in {"apply", "confirm"}:
            self.geo.mark_confirmed()
            self.geo.show_completed(result)
        else:
            if self.operation_name in {"disable", "rollback"}:
                self.geo.reload_config()
            self.geo.switch_screen(ResultScreen(result))

    def action_back(self) -> None:
        pass

    def action_leave(self) -> None:
        pass


class ConfirmApplyScreen(BaseScreen):
    def __init__(self, result: dict[str, Any]) -> None:
        super().__init__()
        self.token = str(result["token"])
        deadline = result.get("deadline") or result.get("expires_at")
        try:
            remaining = (
                max(0, float(deadline) - time.time())
                if deadline
                else float(result.get("timeout", 90))
            )
        except (ValueError, TypeError):
            remaining = 90
        self.deadline = time.monotonic() + remaining
        self._expired = False

    def compose_body(self) -> ComposeResult:
        yield self.title_widget("confirm.title")
        yield self.text_widget("confirm.text")
        yield Static("", id="countdown", classes="summary", markup=False)
        yield Button(self.tr("confirm.keep"), id="confirm", variant="warning")
        yield Button(self.tr("confirm.revert"), id="revert")

    def on_mount(self) -> None:
        # Default focus is rollback, so an accidental Enter cannot confirm access.
        self.query_one("#revert").focus()
        self.tick()
        self.set_interval(1, self.tick)

    def tick(self) -> None:
        if not self.is_current:
            return
        seconds = max(0, int(self.deadline - time.monotonic()))
        self.query_one("#countdown", Static).update(self.tr("confirm.countdown", seconds=seconds))
        if seconds <= 0 and not self._expired:
            self._expired = True
            self.query_one("#confirm", Button).disabled = True
            self.geo.push_screen(
                MessageDialog("confirm.title", self.tr("confirm.expired")),
                lambda _: self.geo.show_main(),
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm" and not self._expired:
            self.geo.push_screen(OperationScreen("confirm", {"token": self.token}))
        elif event.button.id == "revert":
            self.geo.push_screen(OperationScreen("rollback"))

    def action_back(self) -> None:
        self.geo.push_screen(OperationScreen("rollback"))


class CompletedScreen(BaseScreen):
    def __init__(self, result: dict[str, Any] | None = None) -> None:
        super().__init__()
        self.result = result or {}

    def compose_body(self) -> ComposeResult:
        yield self.title_widget("completed.title")
        yield self.text_widget("completed.text")
        yield Static(
            self.geo.status_summary(), id="completed-status", classes="summary", markup=False
        )
        if self.result.get("warnings"):
            yield Static(
                self.geo.format_data({"warnings": self.result["warnings"]}),
                classes="summary",
                markup=False,
            )
        yield Button(self.tr("completed.menu"), id="menu", variant="primary")
        yield Button(self.tr("exit"), id="exit")

    def on_mount(self) -> None:
        self.load_status()

    @work(exclusive=True)
    async def load_status(self) -> None:
        try:
            self.geo.last_status = await self.geo.call_controller(self.geo.controller.status)
        except Exception:
            self.geo.last_status = {"active": None}
        self.query_one("#completed-status", Static).update(self.geo.status_summary())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "menu":
            self.geo.show_main()
        elif event.button.id == "exit":
            self.geo.exit()

    def action_back(self) -> None:
        self.geo.show_main()


class UpdateScreen(MenuScreen):
    title_key = "update.title"

    def compose_body(self) -> ComposeResult:
        yield self.text_widget("update.text")
        status = self.geo.last_status
        yield Static(
            self.geo.format_data(
                {
                    "source": status.get("source", self.geo.draft["source"]),
                    "fetched_at": status.get("metadata", {}).get("fetched_at"),
                    "cidr_count": status.get("cidr_count"),
                    "geoip_health": status.get("geoip_health", "unknown"),
                    "timer": status.get("timer", "unknown"),
                }
            ),
            classes="summary",
            markup=False,
        )
        yield from super().compose_body()

    def menu_options(self) -> list[tuple[str, str]]:
        return [("check", "update.check"), ("update", "update.now"), ("history", "update.history")]

    def chosen(self, action: str) -> None:
        if action == "history":
            self.geo.push_screen(DataScreen("logs.title", "logs"))
        else:
            self.geo.push_screen(OperationScreen("update", {"dry_run": action == "check"}))


class DataScreen(BaseScreen):
    def __init__(self, title: str, operation: str) -> None:
        super().__init__()
        self.title_key = title
        self.operation_name = operation

    def compose_body(self) -> ComposeResult:
        yield self.title_widget(self.title_key)
        yield Static(self.tr("progress.generic"), id="data", markup=False)
        yield Button(self.tr("back"), id="back")

    def on_mount(self) -> None:
        self.load_data()

    @work(exclusive=True)
    async def load_data(self) -> None:
        try:
            method = getattr(self.geo.controller, self.operation_name)
            result = await self.geo.call_controller(method)
            self.query_one("#data", Static).update(self.geo.format_data(result))
            if self.operation_name == "status":
                self.geo.last_status = result
        except Exception as exc:
            self.query_one("#data", Static).update(self.tr("error.detail", detail=str(exc)))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.action_back()


class ResultScreen(BaseScreen):
    def __init__(self, result: Any) -> None:
        super().__init__()
        if isinstance(result, dict) and result.get("dry_run") and "config" in result:
            config = result["config"]
            self.result = {
                "dry_run": True,
                "source": config["source"],
                "policies": config["policies"],
                "destinations": result.get("destinations", {}),
                "needs_download": result.get("needs_download", False),
            }
            if result.get("cache_detail"):
                self.result["cache_detail"] = result["cache_detail"]
        else:
            self.result = result

    def compose_body(self) -> ComposeResult:
        yield self.title_widget("operation.done")
        yield Static(self.geo.format_data(self.result), markup=False)
        yield Button(self.tr("completed.menu"), id="menu", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.geo.show_main()

    def action_back(self) -> None:
        self.geo.show_main()


class GeoLatchApp(App[None]):
    """Bilingual setup and management UI backed by one shared controller."""

    CSS_PATH = "styles.tcss"
    TITLE = NAME
    BINDINGS = [Binding("ctrl+c", "safe_exit", show=False, priority=True)]

    def __init__(
        self, controller: Any = None, setup: bool = False, language: str | None = None
    ) -> None:
        super().__init__()
        if controller is None:
            from geolatch.controller import Controller

            controller = Controller()
        self.controller = controller
        self._controller_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="geolatch-ui")
        self.original = copy.deepcopy(controller.config())
        recovered = controller.recovered_draft() if hasattr(controller, "recovered_draft") else None
        self.draft = copy.deepcopy(recovered if recovered is not None else self.original)
        self.language = language or self.draft.get("language", "en")
        self.setup_mode = setup or not bool(self.draft.get("policies"))
        self.active_policy = 0
        self.address_rows: list[dict[str, Any]] = []
        self.last_status: dict[str, Any] = {}
        self._exit_pending = False

    @property
    def dirty(self) -> bool:
        return self.draft != self.original

    @property
    def policy(self) -> dict[str, Any]:
        self.ensure_policy()
        self.active_policy = min(self.active_policy, len(self.draft["policies"]) - 1)
        return self.draft["policies"][self.active_policy]

    def ensure_policy(self) -> None:
        if not self.draft["policies"]:
            self.new_policy()

    def new_policy(self) -> None:
        existing = {policy["name"] for policy in self.draft["policies"]}
        number = 1
        while f"policy-{number}" in existing:
            number += 1
        self.draft["policies"].append(
            {"name": f"policy-{number}", "enabled": True, "destinations": [], "block_countries": []}
        )
        self.active_policy = len(self.draft["policies"]) - 1

    def tr(self, key: str, **values: object) -> str:
        return translate(self.language, key, **values)

    def bool_text(self, value: bool) -> str:
        return self.tr("state.true" if value else "state.false")

    def status_summary(self) -> str:
        state = self.last_status.get("active")
        key = "state.unknown" if state is None else "state.active" if state else "state.inactive"
        policies = self.last_status.get("policies", [])
        count = len(policies) if isinstance(policies, list) else policies
        return self.tr(
            "main.status",
            state=self.tr(key),
            count=count,
            source=self.last_status.get("source", self.draft["source"]),
            geoip=self.format_data(self.last_status.get("geoip_health", "unknown")),
            timer=self.format_data(self.last_status.get("timer", "unknown")),
        )

    def brand(self) -> str:
        return f"{NAME} v{VERSION}  ·  {self.tr('brand.subtitle')}\n{self.tr('brand.developer', developer=DEVELOPER)}"

    def policy_summary(self, policy: dict[str, Any]) -> str:
        destinations = (
            self.tr("all")
            if policy["destinations"] == "all"
            else ", ".join(policy["destinations"]) or self.tr("none")
        )
        return self.tr(
            "policy.summary",
            name=policy["name"],
            state=self.tr("state.enabled" if policy["enabled"] else "state.disabled"),
            destinations=destinations,
            countries=", ".join(
                f"{country_name(code, self.language)} ({code})"
                for code in policy["block_countries"]
            )
            or self.tr("none"),
        )

    def format_data(self, data: Any, indent: int = 0) -> str:
        prefix = "  " * indent
        if isinstance(data, dict):
            lines = []
            for key, value in data.items():
                label = self.tr(f"label.{key}")
                if label == f"label.{key}":
                    label = str(key).replace("_", " ")
                if isinstance(value, (dict, list)):
                    lines.append(f"{prefix}{label}:\n{self.format_data(value, indent + 1)}")
                else:
                    lines.append(f"{prefix}{label}: {self.format_data(value)}")
            return "\n".join(lines) or prefix + self.tr("none")
        if isinstance(data, list):
            return "\n".join(self.format_data(value, indent) for value in data) or prefix + self.tr(
                "none"
            )
        if isinstance(data, bool):
            return prefix + self.bool_text(data)
        if data is None:
            return prefix + self.tr("none")
        if isinstance(data, str) and data in {
            "active",
            "inactive",
            "enabled",
            "disabled",
            "unknown",
        }:
            return prefix + self.tr(f"state.{data}")
        if isinstance(data, str):
            translated = self.tr(f"value.{data}")
            if translated != f"value.{data}":
                return prefix + translated
        return prefix + str(data)

    def on_mount(self) -> None:
        self.push_screen(LanguageScreen() if self.setup_mode else MainScreen())
        if (
            hasattr(self.controller, "recovered_draft")
            and self.controller.recovered_draft() is not None
        ):
            self.notify(self.tr("recovery.draft_restored"), timeout=12)
        self.load_environment()

    @work(exclusive=True)
    async def load_environment(self) -> None:
        try:
            self.address_rows = await self.call_controller(self.controller.addresses)
        except Exception as exc:
            self.notify(self.tr("error.detail", detail=str(exc)), severity="warning")
        try:
            self.last_status = await self.call_controller(self.controller.status)
        except Exception:
            self.last_status = {"active": None}
        if isinstance(self.screen, MainScreen):
            self.screen.update_status()

    async def call_controller(self, method: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run blocking work in a bounded pool owned by the application."""
        return await asyncio.get_running_loop().run_in_executor(
            self._controller_pool, partial(method, *args, **kwargs)
        )

    def on_unmount(self) -> None:
        self._controller_pool.shutdown(wait=False, cancel_futures=True)

    async def operation(self, name: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = payload or {}
        if getattr(self.controller, "needs_privileges", False):
            # Textual restores cooked mode before sudo prompts and re-enters
            # the alternate screen afterwards. Never capture an admin password.
            with self.suspend():
                result = await self.call_controller(self.controller.run_privileged, name, payload)
            return result or {}
        if name == "preferences":
            result = await self.call_controller(
                self.controller.save_preferences, payload["language"]
            )
        elif name == "apply":
            result = await self.call_controller(
                self.controller.apply,
                payload.get("config"),
                safe=payload.get("safe", True),
                force=payload.get("force", False),
            )
        elif name == "confirm":
            result = await self.call_controller(self.controller.confirm, payload["token"])
        elif name == "update":
            result = await self.call_controller(
                self.controller.update,
                dry_run=payload.get("dry_run", False),
                force=payload.get("force", False),
            )
        else:
            method: Callable[..., Any] = getattr(self.controller, name)
            result = await self.call_controller(method)
        return result or {}

    def reload_config(self) -> None:
        self.original = copy.deepcopy(self.controller.config())
        self.draft = copy.deepcopy(self.original)
        self.language = self.draft["language"]

    def mark_confirmed(self) -> None:
        self.original = copy.deepcopy(self.draft)
        self.setup_mode = False

    def show_completed(self, result: dict[str, Any]) -> None:
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(CompletedScreen(result))

    def show_main(self) -> None:
        # Drop wizard screens so back never returns to an applied transaction.
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(MainScreen())
        self.load_environment()

    def request_exit(self) -> None:
        if self._exit_pending:
            return
        if self.dirty:
            self._exit_pending = True
            self.push_screen(
                MessageDialog("quit.title", self.tr("quit.text"), confirm=True), self._finish_exit
            )
        else:
            self.exit()

    def _finish_exit(self, yes: bool) -> None:
        self._exit_pending = False
        if yes:
            self.exit()

    def action_safe_exit(self) -> None:
        if not isinstance(self.screen, OperationScreen):
            self.request_exit()


def launch(*, setup: bool = False, language: str | None = None, controller: Any = None) -> None:
    """Launch the alternate-screen application; CLI checks terminal support."""
    GeoLatchApp(controller=controller, setup=setup, language=language).run()
