"""Audited source registry; selecting another source is always explicit."""

from .base import Provider
from .ipverse_geo import PROVIDER as GEO
from .ipverse_rir import PROVIDER as RIR

PROVIDERS: dict[str, Provider] = {provider.name: provider for provider in (GEO, RIR)}


def get_provider(name: str) -> Provider:
    try:
        return PROVIDERS[name]
    except KeyError as error:
        raise ValueError(f"Unsupported GeoIP source: {name}") from error
