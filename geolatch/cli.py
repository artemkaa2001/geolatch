"""Bilingual terminal entry point and stable JSON automation interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .config import load_config
from .controller import Controller, OperationError
from .i18n import Translator, countries, system_language
from .metadata import DEVELOPER, NAME, TELEGRAM, VERSION
from .paths import Paths
from .utils import read_json


class Parser(argparse.ArgumentParser):
    translator: Translator

    def error(self, message: str) -> None:
        if self.translator.language == "ru":

            def localize_detail(detail: str) -> str:
                for prefix, key in (
                    ("invalid int value: ", "cli.error.invalid_integer"),
                    ("invalid float value: ", "cli.error.invalid_number"),
                    ("the following arguments are required: ", "cli.error.required"),
                    ("unrecognized arguments: ", "cli.error.unrecognized"),
                    ("ignored explicit argument ", "cli.error.unexpected_value"),
                ):
                    if detail.startswith(prefix):
                        return self.translator(key, value=detail[len(prefix) :])
                if detail.startswith("invalid choice: "):
                    value, separator, choices = detail[len("invalid choice: ") :].rpartition(
                        " (choose from "
                    )
                    if separator and choices.endswith(")"):
                        return self.translator(
                            "cli.error.invalid_choice", value=value, choices=choices[:-1]
                        )
                if detail.startswith("ambiguous option: "):
                    option, separator, choices = detail[len("ambiguous option: ") :].partition(
                        " could match "
                    )
                    if separator:
                        return self.translator("cli.error.ambiguous", value=option, choices=choices)
                for source, key in (
                    ("expected one argument", "cli.error.expected_one"),
                    ("expected at least one argument", "cli.error.expected_at_least_one"),
                    ("expected at most one argument", "cli.error.expected_at_most_one"),
                    ("Unknown command", "cli.error.unknown_command"),
                ):
                    if detail == source:
                        return self.translator(key)
                return detail

            if message.startswith("argument "):
                argument, separator, detail = message[len("argument ") :].partition(": ")
                if separator:
                    message = self.translator(
                        "cli.error.argument", argument=argument, detail=localize_detail(detail)
                    )
                else:
                    message = localize_detail(message)
            else:
                message = localize_detail(message)
        self.print_usage(sys.stderr)
        self.exit(2, self.translator("cli.argument_error", detail=message) + "\n")

    def format_usage(self) -> str:
        text = super().format_usage()
        if text.startswith("usage:"):
            text = self.translator("cli.usage") + text[len("usage:") :]
        return text

    def format_help(self) -> str:
        text = super().format_help()
        if self.translator.language == "ru":
            for source, key in (
                ("usage:", "cli.usage"),
                ("options:", "cli.options"),
                ("positional arguments:", "cli.arguments"),
            ):
                text = text.replace(source, self.translator(key))
        return text


def _parser(t: Translator) -> Parser:
    class LocalizedParser(Parser):
        translator = t

    parser = LocalizedParser(prog="geolatch", description=t("app.subtitle"), add_help=False)
    parser.add_argument("-h", "--help", action="help", help=t("cli.help"))
    parser.add_argument("--lang", choices=("en", "ru"), help=t("cli.lang"))
    parser.add_argument("--json", action="store_true", help=t("cli.json"))
    parser.add_argument("--config", type=Path, default=Paths().config_file, help=t("cli.config"))
    parser.add_argument(
        "--state-dir", type=Path, default=Paths().state_dir, help=t("cli.state_dir")
    )
    parser.add_argument(
        "--cache-dir", type=Path, default=Paths().cache_dir, help=t("cli.cache_dir")
    )
    commands = parser.add_subparsers(
        dest="command", title=t("cli.commands"), parser_class=LocalizedParser, metavar="COMMAND"
    )
    for command in (
        "setup",
        "status",
        "addresses",
        "countries",
        "plan",
        "apply",
        "confirm",
        "update",
        "rollback",
        "enable",
        "disable",
        "check-ip",
        "doctor",
        "logs",
        "version",
        "restore",
    ):
        child = commands.add_parser(
            command,
            help=t(f"cli.command.{command}"),
            description=t(f"cli.command.{command}"),
            add_help=False,
        )
        child.add_argument("-h", "--help", action="help", help=t("cli.help"))
        child.add_argument(
            "--json", action="store_true", default=argparse.SUPPRESS, help=t("cli.json")
        )
        child.add_argument(
            "--lang", choices=("en", "ru"), default=argparse.SUPPRESS, help=t("cli.lang")
        )
        if command in ("apply", "enable", "disable", "rollback"):
            child.add_argument("--yes", action="store_true", help=t("cli.yes"))
        if command in ("apply", "enable"):
            child.add_argument("--confirm", action="store_true", help=t("cli.confirm_immediately"))
        if command == "apply":
            child.add_argument("--timeout", type=int, default=90, help=t("cli.timeout"))
        if command == "confirm":
            child.add_argument("token", help=t("cli.token"))
        if command == "update":
            child.add_argument("--dry-run", action="store_true", help=t("cli.dry_run"))
            child.add_argument("--force", action="store_true", help=t("cli.force"))
            child.add_argument("--unattended", action="store_true", help=t("cli.unattended"))
        if command == "check-ip":
            child.add_argument("source", help=t("cli.source_ip"))
            child.add_argument("--destination", required=True, help=t("cli.destination_ip"))
            child.add_argument("--interface", help=t("cli.interface"))
        if command == "logs":
            child.add_argument("--limit", type=int, default=100, help=t("cli.limit"))
    # Internal entry points accept only data, never Python or shell code.
    internal = commands.add_parser("_operate", add_help=False, help=argparse.SUPPRESS)
    internal.add_argument(
        "operation",
        choices=(
            "apply",
            "confirm",
            "rollback",
            "update",
            "disable",
            "enable",
            "preferences",
            "restore",
        ),
    )
    internal.add_argument("--payload", required=True, type=Path)
    guard = commands.add_parser("_watchdog", add_help=False, help=argparse.SUPPRESS)
    guard.add_argument("token")
    commands.add_parser("_repair_pending", add_help=False, help=argparse.SUPPRESS)
    commands._choices_actions[:] = [
        action
        for action in commands._choices_actions
        if action.dest not in ("_operate", "_watchdog", "_repair_pending")
    ]
    return parser


def _human(value: Any, t: Translator, *, depth: int = 0) -> str:
    if value is None:
        return t("common.unknown")
    if isinstance(value, bool):
        return t("common.yes" if value else "common.no")
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            label = t(f"field.{key}")
            if label == f"field.{key}":
                label = key
            formatted = _human(item, t, depth=depth + 1)
            if isinstance(item, (dict, list)) and item:
                lines.append(
                    f"{label}:\n" + "\n".join("  " + line for line in formatted.splitlines())
                )
            else:
                lines.append(f"{label}: {formatted}")
        return "\n".join(lines)
    if isinstance(value, list):
        return "\n".join(_human(item, t, depth=depth + 1) for item in value) or "—"
    if isinstance(value, (int, float)):
        return t.number(value)
    text = str(value)
    translated = t(f"value.{text}")
    return text if translated == f"value.{text}" else translated


def _emit(result: Any, args: argparse.Namespace, t: Translator) -> None:
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(_human(result, t))
        if isinstance(result, dict) and result.get("pending") and result.get("token"):
            print(
                t(
                    "cli.pending_instruction",
                    token=result["token"],
                    seconds=result.get("timeout", 90),
                )
            )


def _consent(args: argparse.Namespace, t: Translator) -> None:
    if args.yes:
        return
    if not sys.stdin.isatty():
        raise OperationError(t("cli.yes_required"))
    answer = input(t("cli.confirm_prompt") + " ")
    if answer.strip().casefold() not in ("y", "yes", "д", "да"):
        raise OperationError(t("cli.cancelled"))


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    bootstrap = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    bootstrap.add_argument("--lang")
    bootstrap.add_argument("--config", type=Path, default=Paths().config_file)
    bootstrap.add_argument("--json", action="store_true")
    # Bootstrap parsing does not reject invalid choices: the fully localized
    # parser below owns diagnostics. Only inspect known flags for language.
    try:
        preliminary, _ = bootstrap.parse_known_args(arguments)
    except argparse.ArgumentError:
        recovered_language = None
        for index, argument in enumerate(arguments):
            if argument.startswith("--lang="):
                recovered_language = argument.split("=", 1)[1]
            elif argument == "--lang" and index + 1 < len(arguments):
                recovered_language = arguments[index + 1]
        preliminary = argparse.Namespace(
            lang=recovered_language, config=Paths().config_file, json="--json" in arguments
        )
    language = preliminary.lang or system_language()
    if preliminary.lang is None:
        try:
            language = (
                load_config(preliminary.config)["language"]
                if preliminary.config.exists()
                else language
            )
        except (OSError, ValueError):
            pass
    t = Translator(language)
    parser = _parser(t)
    args = parser.parse_args(arguments)
    t = Translator(args.lang or language)
    controller = Controller(Paths(args.config, args.state_dir, args.cache_dir))
    try:
        command = args.command
        if command is None or command == "setup":
            if not (sys.stdin.isatty() and sys.stdout.isatty()) or os.environ.get("TERM") == "dumb":
                raise OperationError(t("error.tty_required"), "error.tty_required")
            from .tui.app import launch

            launch(
                setup=command == "setup" or not args.config.exists(),
                language=args.lang,
                controller=controller,
            )
            return 0
        if command == "version":
            result = {
                "name": NAME,
                "version": VERSION,
                "developer": DEVELOPER,
                "telegram": TELEGRAM,
            }
        elif command == "countries":
            result = [{"code": code, "name": name} for code, name in countries(t.language)]
        elif command == "status":
            result = controller.status()
        elif command == "addresses":
            result = controller.addresses()
        elif command == "plan":
            result = controller.plan()
        elif command == "apply":
            _consent(args, t)
            result = controller.apply(safe=not args.confirm, timeout=args.timeout)
        elif command == "confirm":
            result = controller.confirm(args.token)
        elif command == "update":
            result = controller.update(dry_run=args.dry_run, force=args.force)
        elif command in ("rollback", "disable"):
            _consent(args, t)
            result = getattr(controller, command)()
        elif command == "enable":
            _consent(args, t)
            result = controller.enable(safe=not args.confirm)
        elif command == "restore":
            result = controller.restore()
        elif command == "check-ip":
            result = controller.check_ip(args.source, args.destination, args.interface)
        elif command == "doctor":
            result = controller.doctor()
        elif command == "logs":
            if not 1 <= args.limit <= 1000:
                raise OperationError("Log limit must be between 1 and 1000")
            result = controller.logs(args.limit)
        elif command == "_operate":
            controller._require_root()
            payload = read_json(args.payload, limit=1024 * 1024)
            if not isinstance(payload, dict):
                raise OperationError("Operation payload must be an object")
            result = controller.operate(args.operation, payload)
        elif command == "_repair_pending":
            result = controller.repair_pending()
        elif command == "_watchdog":
            controller._require_root()
            from .rollback import watchdog

            return watchdog(controller, args.token)
        else:
            parser.error("Unknown command")
        _emit(result, args, t)
        return 0
    except KeyboardInterrupt:
        if args.json:
            print(json.dumps({"error": "interrupted", "detail": t("cli.interrupted")}))
        else:
            print(t("cli.interrupted"), file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        key = getattr(exc, "key", "error.operation")
        detail = getattr(exc, "detail", str(exc))
        if args.json:
            print(json.dumps({"error": key, "detail": detail}, ensure_ascii=False))
        else:
            print(t(key, detail=detail), file=sys.stderr)
        return 3 if key == "error.root_required" else 1


if __name__ == "__main__":
    raise SystemExit(main())
