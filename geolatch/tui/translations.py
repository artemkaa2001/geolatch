"""Centralized translations for terminal screens."""

import json
from importlib.resources import files

_CATALOGS = {
    language: json.loads(
        files("geolatch.tui").joinpath("locales", f"{language}.json").read_text("utf-8")
    )
    for language in ("en", "ru")
}


def translate(language: str, key: str, **values: object) -> str:
    """Translate with a complete English fallback and literal Unicode."""
    if key not in _CATALOGS["en"] and key not in _CATALOGS.get(language, {}):
        return key
    message = _CATALOGS.get(language, _CATALOGS["en"]).get(key, _CATALOGS["en"].get(key, key))
    return message.format(**values)
