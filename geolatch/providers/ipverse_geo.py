"""ipverse's more granular geolocation feed (verified October 2026)."""

from .base import Provider

PROVIDER = Provider("ipverse-geo", "geo-ip-blocks", "{country}-ipv{family}.txt")
