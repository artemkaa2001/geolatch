"""Explicit paths make isolated tests possible without touching host state."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    config_file: Path = Path("/etc/geolatch/config.yaml")
    state_dir: Path = Path("/var/lib/geolatch")
    cache_dir: Path = Path("/var/cache/geolatch")

    @property
    def confirmed(self) -> Path:
        return self.state_dir / "confirmed.json"

    @property
    def previous(self) -> Path:
        return self.state_dir / "previous.json"

    @property
    def pending(self) -> Path:
        return self.state_dir / "pending.json"

    @property
    def recovered_draft(self) -> Path:
        return self.config_file.parent / "recovered-draft.yaml"

    @property
    def events(self) -> Path:
        return self.state_dir / "events.jsonl"
