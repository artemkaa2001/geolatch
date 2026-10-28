"""nftables 1.0.2 omits table/chain comments from JSON, but prints them as text.

Fixtures model that historical serialization difference, not kernel filtering.
The owned marker must still be positively checked before every mutation.
"""

from __future__ import annotations

import json

import pytest

from geolatch.nftables import OWNER, Nftables, NftError

REVISION = "geolatch-revision:" + "a" * 64
OWNED_TEXT = f'''table inet geolatch {{
\tcomment "{OWNER}"
\tchain prerouting {{
\t\tcomment "{REVISION}"
\t\ttype filter hook prerouting priority mangle; policy accept;
\t\tct state established,related return
\t}}
}}
'''


class LegacyNft(Nftables):
    """Read a stateful textual table through a legacy-shaped JSON view."""

    def __init__(self, text: str = OWNED_TEXT):
        super().__init__()
        self.text = text
        self.present = True
        self.table_comment = None
        self.chain_comment = None
        self.calls: list[tuple[list[str], str | None]] = []
        self.text_error = None

    def _run(self, arguments, source=None):
        self.calls.append((arguments, source))
        table = {"family": "inet", "name": "geolatch", "handle": 7}
        if self.table_comment is not None:
            table["comment"] = self.table_comment
        chain = {
            "family": "inet",
            "table": "geolatch",
            "name": "prerouting",
            "handle": 8,
            "type": "filter",
            "hook": "prerouting",
            "prio": -150,
            "policy": "accept",
        }
        if self.chain_comment is not None:
            chain["comment"] = self.chain_comment
        if arguments == ["--json", "list", "tables"]:
            return json.dumps({"nftables": [{"table": table}] if self.present else []})
        if arguments == ["--json", "list", "table", "inet", "geolatch"]:
            return json.dumps({"nftables": [{"table": table}, {"chain": chain}]})
        if arguments == ["list", "table", "inet", "geolatch"]:
            if self.text_error:
                raise NftError(self.text_error)
            return self.text
        if arguments == ["--check", "--file", "-"]:
            return ""
        if arguments == ["--file", "-"]:
            self.present = "table inet geolatch {" in source
            if self.present:
                self.text = source[source.index("table inet geolatch {") :]
            return ""
        raise AssertionError(f"Unexpected nft command {arguments!r}")


def test_legacy_json_uses_positively_verified_table_and_chain_text_comments():
    backend = LegacyNft()
    result = backend.inspect()
    assert result["nftables"][0]["table"]["comment"] == OWNER
    assert result["nftables"][1]["chain"]["comment"] == REVISION
    assert not any(arguments == ["--file", "-"] for arguments, _ in backend.calls)


def test_missing_chain_comment_is_recovered_when_json_already_has_table_owner():
    backend = LegacyNft()
    backend.table_comment = OWNER
    result = backend.inspect()
    assert result["nftables"][1]["chain"]["comment"] == REVISION


def test_explicit_wrong_json_chain_revision_is_never_overridden_by_text():
    backend = LegacyNft()
    backend.table_comment = OWNER
    backend.chain_comment = "geolatch-revision:" + "b" * 64
    with pytest.raises(NftError, match="revision"):
        backend.apply(OWNED_TEXT)


def test_legacy_owned_table_can_be_snapshotted_checked_replaced_and_disabled():
    backend = LegacyNft()
    assert backend.snapshot() == OWNED_TEXT
    backend.check(OWNED_TEXT)
    backend.apply(OWNED_TEXT)
    backend.apply(None)
    assert not backend.present
    batches = [source for args, source in backend.calls if args == ["--file", "-"]]
    assert batches == ["delete table inet geolatch\n" + OWNED_TEXT, "delete table inet geolatch\n"]


@pytest.mark.parametrize(
    "text",
    [
        'table inet geolatch {\n chain prerouting {\n counter comment "GeoLatch managed table v1"\n }\n}\n',
        'table inet geolatch {\n comment "another application"\n}\n',
        'table ip geolatch {\n comment "GeoLatch managed table v1"\n}\n',
        'table inet geolatch {\n chain x {\n comment "GeoLatch managed table v1"\n }\n}\n',
        OWNED_TEXT + "delete table inet foreign\n",
    ],
)
def test_legacy_foreign_or_structurally_unsafe_table_is_never_adopted(text):
    backend = LegacyNft(text)
    with pytest.raises(NftError):
        backend.apply(None)
    assert not any(arguments == ["--file", "-"] for arguments, _ in backend.calls)


def test_explicit_nonmatching_json_owner_cannot_be_overridden_by_text():
    backend = LegacyNft()
    backend.table_comment = "Foreign application"
    with pytest.raises(NftError, match="owned|owner"):
        backend.apply(None)
    assert not any(arguments == ["--file", "-"] for arguments, _ in backend.calls)


def test_text_read_failure_is_never_treated_as_owned_or_missing():
    backend = LegacyNft()
    backend.text_error = "Operation not permitted"
    with pytest.raises(NftError, match="not permitted"):
        backend.apply(None)
    assert backend.present
    assert not any(arguments == ["--file", "-"] for arguments, _ in backend.calls)


def test_rule_comment_cannot_spoof_missing_chain_revision():
    text = OWNED_TEXT.replace(f'\t\tcomment "{REVISION}"\n', "")
    text = text.replace("ct state established,related return", f'counter comment "{REVISION}"')
    backend = LegacyNft(text)
    result = backend.inspect()
    chain = result["nftables"][1]["chain"]
    assert chain.get("comment") != REVISION
