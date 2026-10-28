"""Small centralized translation catalog with English fallback and plural forms."""

from __future__ import annotations

import json
import os
from datetime import datetime
from functools import lru_cache
from importlib.resources import files
from typing import Any


@lru_cache(maxsize=3)
def _load_catalog(name: str) -> dict[str, Any]:
    return json.loads(
        files("geolatch").joinpath("locales", f"{name}.json").read_text(encoding="utf-8")
    )


COUNTRY_CODES = frozenset(_load_catalog("countries"))


def system_language() -> str:
    """Use POSIX locale precedence without changing the process locale."""
    locale = next(
        (os.environ[key] for key in ("LC_ALL", "LC_MESSAGES", "LANG") if os.environ.get(key)), "en"
    )
    return "ru" if locale.lower().startswith("ru") else "en"


def country_name(code: str, language: str = "en") -> str:
    country = _load_catalog("countries").get(code.upper())
    if country is None:
        return code.upper()
    return country.get(language, country["en"])


def countries(language: str = "en") -> list[tuple[str, str]]:
    """Sorted localized country names, with stable ISO codes as identifiers."""
    return sorted(
        ((code, country_name(code, language)) for code in COUNTRY_CODES),
        key=lambda item: (item[1].casefold(), item[0]),
    )


def plural_form(number: int | float, language: str) -> str:
    if language == "ru" and number == int(number):
        integer = abs(int(number))
        if integer % 10 == 1 and integer % 100 != 11:
            return "one"
        if integer % 10 in (2, 3, 4) and integer % 100 not in (12, 13, 14):
            return "few"
        return "many"
    return "one" if number == 1 else "other"


class Translator:
    def __init__(self, language: str = "en") -> None:
        self.language = language if language in ("en", "ru") else "en"

    def __call__(self, key: str, **kwargs: Any) -> str:
        english = _load_catalog("en")
        localized = _load_catalog(self.language)
        if key not in localized and key not in english:
            # Callers may probe dynamic technical labels (including nft rules
            # containing literal braces). Unknown keys are data, not templates.
            return key
        message = localized.get(key, english.get(key))
        if isinstance(message, dict):
            count = kwargs.get("count", 0)
            form = plural_form(count, self.language)
            message = message.get(form, message.get("other", english.get(key, key)))
        return str(message).format_map(kwargs)

    def t(self, key: str, **kwargs: Any) -> str:
        return self(key, **kwargs)

    def date(self, value: str | datetime | None) -> str:
        """Format timezone-aware dates without relying on installed locales."""
        if value is None:
            return self("common.never")
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return value
        pattern = "%d.%m.%Y %H:%M:%S %Z" if self.language == "ru" else "%Y-%m-%d %H:%M:%S %Z"
        return value.strftime(pattern).rstrip()

    def number(self, value: int | float) -> str:
        text = f"{value:,}"
        return text.replace(",", "\u202f").replace(".", ",") if self.language == "ru" else text


def translation_keys(language: str) -> frozenset[str]:
    """Expose keys for catalog validation without exposing mutable cache data."""
    return frozenset(_load_catalog(language))
