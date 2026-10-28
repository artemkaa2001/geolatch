"""Small, explicit HTTPS-only provider definitions; no fallback between sources."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    name: str
    repository: str
    filename: str
    license: str = "CC0-1.0"

    def url(self, country: str, family: int) -> str:
        if re.fullmatch(r"[A-Z]{2}", country) is None or family not in (4, 6):
            raise ValueError("Invalid provider country or IP family")
        code = country.lower()
        filename = self.filename.format(country=code, family=family)
        return (
            f"https://raw.githubusercontent.com/ipverse/{self.repository}/master/"
            f"country/{code}/{filename}"
        )
