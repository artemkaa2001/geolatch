"""ipverse's compact RIR delegation feed (verified October 2026)."""

from .base import Provider

PROVIDER = Provider("ipverse-rir", "country-ip-blocks", "ipv{family}-aggregated.txt")
