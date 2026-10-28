import ast
import json
import string
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

import pytest

from geolatch.i18n import (
    COUNTRY_CODES,
    Translator,
    countries,
    country_name,
    plural_form,
    system_language,
    translation_keys,
)


def test_translation_completeness_and_interpolation_parity():
    def placeholders(message):
        if isinstance(message, dict):
            return set().union(*(placeholders(value) for value in message.values()))
        return {field for _, field, _, _ in string.Formatter().parse(message) if field}

    en = json.loads(files("geolatch").joinpath("locales/en.json").read_text())
    ru = json.loads(files("geolatch").joinpath("locales/ru.json").read_text())
    assert translation_keys("en") == translation_keys("ru")
    for key in en:
        assert placeholders(en[key]) == placeholders(ru[key]), key
        assert bool(en[key]) and bool(ru[key]), key


def test_cli_translation_keys_are_present_in_both_languages():
    path = Path(__file__).parents[1] / "geolatch" / "cli.py"
    tree = ast.parse(path.read_text())
    keys = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("cli.")
        and not node.value.endswith(".")
    }
    keys.update(
        f"cli.command.{command}"
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
        )
    )
    for language in ("en", "ru"):
        assert keys <= translation_keys(language), keys - translation_keys(language)


def test_controller_human_output_field_labels_are_localized():
    path = Path(__file__).parents[1] / "geolatch" / "controller.py"
    tree = ast.parse(path.read_text())
    fields = {
        key.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    for language in ("en", "ru"):
        assert {f"field.{field}" for field in fields} <= translation_keys(language)


@pytest.mark.parametrize(
    "arguments,expected,untranslated",
    [
        (["apply", "--timeout", "not-a-number"], "ожидается целое число", "invalid int value"),
        (["--lang", "fr"], "недопустимое значение: 'fr'", "choose from"),
        (
            ["check-ip", "1.1.1.1"],
            "необходимо указать следующие аргументы: --destination",
            "are required",
        ),
        (["status", "--unknown"], "неизвестные аргументы: --unknown", "unrecognized arguments"),
        (["--config"], "необходимо указать одно значение", "expected one argument"),
        (["apply", "--yes=true"], "этот параметр не принимает значение 'true'", "ignored explicit"),
        (["--c", "cache"], "неоднозначный параметр: --c", "ambiguous option"),
    ],
)
def test_russian_argparse_errors_localize_boilerplate(arguments, expected, untranslated, capsys):
    from geolatch.cli import _parser

    with pytest.raises(SystemExit) as error:
        _parser(Translator("ru")).parse_args(arguments)
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("использование:")
    assert "Некорректные аргументы команды:" in captured.err
    assert expected in captured.err
    assert untranslated not in captured.err
    assert "usage:" not in captured.err


def test_english_argparse_errors_keep_original_wording(capsys):
    from geolatch.cli import _parser

    with pytest.raises(SystemExit) as error:
        _parser(Translator("en")).parse_args(["apply", "--timeout", "bad"])
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("usage:")
    assert "argument --timeout: invalid int value: 'bad'" in captured.err


def test_argparse_localization_preserves_user_supplied_values(capsys):
    from geolatch.cli import _parser

    # User data can contain English words from argparse's own templates. Only
    # structurally recognized message prefixes may be translated.
    supplied = "unrecognized arguments: choose from {literal}"
    with pytest.raises(SystemExit):
        _parser(Translator("ru")).parse_args(["apply", "--timeout", supplied])
    assert repr(supplied) in capsys.readouterr().err


def test_all_iso_countries_have_translated_names():
    assert len(COUNTRY_CODES) == 249
    assert {code for code, name in countries("ru")} == COUNTRY_CODES
    assert all(country_name(code, "ru") != code for code in COUNTRY_CODES)
    assert country_name("IR", "ru") == "Иран"
    assert country_name("ir", "en") == "Iran"
    assert country_name("XX", "ru") == "XX"
    assert country_name("CN", "xx") == "China"


@pytest.mark.parametrize(
    "number,form",
    [
        (0, "many"),
        (1, "one"),
        (2, "few"),
        (4, "few"),
        (5, "many"),
        (11, "many"),
        (12, "many"),
        (14, "many"),
        (21, "one"),
        (22, "few"),
        (101, "one"),
        (111, "many"),
        (-1, "one"),
        (1.5, "other"),
    ],
)
def test_russian_plurals(number, form):
    assert plural_form(number, "ru") == form


def test_translation_switching_and_formatting():
    translator = Translator("en")
    assert translator("selection.countries", count=1) == "1 country selected"
    assert translator("selection.countries", count=2) == "2 countries selected"
    translator.language = "ru"
    assert translator("selection.countries", count=2) == "Выбраны 2 страны"
    assert translator("selection.countries", count=11) == "Выбрано 11 стран"
    assert translator("selection.countries", count=21) == "Выбрана 21 страна"
    assert translator.t("common.save") == "Сохранить"
    assert translator.number(10000) == "10\u202f000"


def test_missing_translations_fall_back_to_english(monkeypatch):
    import geolatch.i18n as i18n

    original = i18n._load_catalog
    monkeypatch.setattr(
        i18n, "_load_catalog", lambda language: {} if language == "ru" else original(language)
    )
    assert Translator("ru")("common.save") == "Save"
    assert Translator("fr")("common.save") == "Save"
    assert Translator("ru")("unknown.key") == "unknown.key"
    assert (
        Translator("ru")("value.table inet geolatch { example }")
        == "value.table inet geolatch { example }"
    )


def test_date_formats_without_system_locale():
    value = datetime(2026, 10, 28, 14, 30, tzinfo=timezone.utc)
    assert Translator("ru").date(value) == "28.10.2026 14:30:00 UTC"
    assert Translator("en").date(value) == "2026-10-28 14:30:00 UTC"
    assert Translator("ru").date(None) == "Никогда"
    assert Translator("en").date(value.isoformat()) == "2026-10-28 14:30:00 UTC"


def test_system_locale_precedence(monkeypatch):
    monkeypatch.setenv("LANG", "ru_RU.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LC_MESSAGES", raising=False)
    assert system_language() == "ru"
    monkeypatch.setenv("LC_MESSAGES", "en_US.UTF-8")
    assert system_language() == "en"
    monkeypatch.setenv("LC_ALL", "ru_RU.UTF-8")
    assert system_language() == "ru"
