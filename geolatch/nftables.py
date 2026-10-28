"""Small, ownership-aware interface to the nftables transactional CLI.

Only the ``inet geolatch`` table is ever read back for restoration or changed.
An existing table with that name must have our ownership comment; otherwise
GeoLatch refuses to touch it. All replacement commands go through one nft batch.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any

TABLE = "geolatch"
FAMILY = "inet"
OWNER = "GeoLatch managed table v1"


class NftError(RuntimeError):
    """An nftables command, ownership check, or ruleset validation failed."""


def _validate_table(source: str) -> str:
    """Require exactly one owned table declaration, never an arbitrary script.

    This is deliberately a structural guard rather than an nft language parser.
    The kernel/nft check does the semantic validation. Strings and comments are
    removed before checking braces, so a quoted brace cannot hide a command.
    """
    if not isinstance(source, str) or not source.strip():
        raise NftError("The GeoLatch table declaration is empty")
    try:
        clean = re.sub(
            r'"(?:[^"\\]|\\.)*"|#[^\n]*', lambda m: '""' if m[0][0] == '"' else "", source
        )
        match = re.match(r"\s*table\s+inet\s+geolatch\s*\{", clean)
        if match is None:
            raise ValueError("expected one table inet geolatch declaration")
        depth = 1
        for index in range(match.end(), len(clean)):
            if clean[index] == "{":
                depth += 1
            elif clean[index] == "}":
                depth -= 1
                if depth == 0:
                    if clean[index + 1 :].strip():
                        raise ValueError("commands outside the owned table")
                    break
        if depth != 0:
            raise ValueError("unbalanced table braces")
        if re.search(
            r"\b(include|define|flush|delete|destroy|add|insert|replace|create|table)\b",
            clean[match.end() :],
        ):
            raise ValueError("commands are not allowed in a table snapshot")
        # Our own snapshots and generated tables put the ownership declaration
        # first. A matching rule comment must not count as table ownership.
        uncommented = re.sub(r"#[^\n]*", "", source)
        if (
            re.match(
                r'\s*table\s+inet\s+geolatch\s*\{\s*comment\s+"' + re.escape(OWNER) + r'"\s*;?',
                uncommented,
            )
            is None
        ):
            raise ValueError("missing GeoLatch ownership marker")
    except ValueError as exc:
        raise NftError(f"Unsafe GeoLatch table declaration: {exc}") from exc
    return source.strip() + "\n"


class Nftables:
    """Execute bounded nft commands without a shell or localized diagnostics."""

    def __init__(self, binary: str = "nft", timeout: float = 30) -> None:
        self.binary = binary
        self.timeout = timeout

    def _run(self, arguments: list[str], source: str | None = None) -> str:
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        try:
            result = subprocess.run(
                [self.binary, *arguments],
                input=source,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
                env=environment,
            )
        except FileNotFoundError as exc:
            raise NftError("nftables executable is unavailable; install nftables") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NftError(f"nftables could not complete the operation: {exc}") from exc
        if result.returncode:
            detail = (result.stderr or result.stdout or f"exit {result.returncode}").strip()
            raise NftError(f"nftables: {detail[:8000]}")
        return result.stdout

    def _json(self, arguments: list[str]) -> dict[str, Any]:
        try:
            result = json.loads(self._run(["--json", *arguments]))
        except (ValueError, TypeError) as exc:
            raise NftError("nftables returned malformed JSON") from exc
        if not isinstance(result, dict) or not isinstance(result.get("nftables"), list):
            raise NftError("nftables returned an unexpected JSON schema")
        return result

    def inspect(self) -> dict[str, Any] | None:
        """Return the actual owned table, None only after a successful absence check.

        Listing tables first avoids confusing permission denied, missing kernel
        support, or translated error messages with a table which does not exist.
        """
        listing = self._json(["list", "tables"])
        found = False
        for entry in listing["nftables"]:
            if not isinstance(entry, dict):
                raise NftError("nftables returned an invalid table listing")
            if "metainfo" in entry:
                continue
            table = entry.get("table")
            if (
                not isinstance(table, dict)
                or not isinstance(table.get("family"), str)
                or not isinstance(table.get("name"), str)
            ):
                raise NftError("nftables returned an invalid table listing")
            if table["family"] == FAMILY and table["name"] == TABLE:
                found = True
        if not found:
            return None
        result = self._json(["list", "table", FAMILY, TABLE])
        tables = [
            entry["table"]
            for entry in result["nftables"]
            if isinstance(entry, dict) and "table" in entry
        ]
        if len(tables) != 1 or not isinstance(tables[0], dict):
            raise NftError("nftables did not return the requested table")
        table = tables[0]
        if (
            table.get("family") != FAMILY
            or table.get("name") != TABLE
            or table.get("comment") != OWNER
        ):
            raise NftError("Refusing to modify inet geolatch: the table is not owned by GeoLatch")
        return result

    def snapshot(self) -> str | None:
        """Read a restorable snapshot of the owned table, including counters."""
        if self.inspect() is None:
            return None
        return _validate_table(self._run(["list", "table", FAMILY, TABLE]))

    def _transaction(self, rules: str | None, exists: bool) -> str:
        declaration = "" if rules is None else _validate_table(rules)
        return (f"delete table {FAMILY} {TABLE}\n" if exists else "") + declaration

    def check(self, rules: str) -> None:
        """Validate the exact replacement transaction without changing the kernel."""
        transaction = self._transaction(rules, self.inspect() is not None)
        self._run(["--check", "--file", "-"], transaction)

    def apply(self, rules: str | None) -> None:
        """Atomically replace or remove only our table and verify its presence.

        An nft batch is a kernel transaction. A parse, allocation, or semantic
        failure leaves the previously committed table intact.
        """
        transaction = self._transaction(rules, self.inspect() is not None)
        if transaction:
            self._run(["--file", "-"], transaction)
        actual = self.inspect()
        if (actual is None) != (rules is None):
            raise NftError("The actual nftables state does not match the requested state")
        if rules is not None and actual is not None:
            revision = re.search(r'\bcomment\s+"(geolatch-revision:[0-9a-f]{64})"', rules)
            if revision:
                chains = [
                    item.get("chain", {}) for item in actual["nftables"] if isinstance(item, dict)
                ]
                if not any(
                    chain.get("name") == "prerouting" and chain.get("comment") == revision[1]
                    for chain in chains
                ):
                    raise NftError(
                        "The actual nftables table revision differs from the applied transaction"
                    )

    def counters(self) -> list[dict[str, Any]]:
        """Read actual packet/byte counters; a missing table has no counters."""
        table = self.inspect()
        if table is None:
            return []
        counters: list[dict[str, Any]] = []
        for entry in table["nftables"]:
            rule = entry.get("rule") if isinstance(entry, dict) else None
            if not isinstance(rule, dict):
                continue
            for expression in rule.get("expr", []):
                counter = expression.get("counter") if isinstance(expression, dict) else None
                if isinstance(counter, dict):
                    counters.append(
                        {
                            "chain": rule.get("chain"),
                            "comment": rule.get("comment", ""),
                            "handle": rule.get("handle"),
                            "packets": int(counter.get("packets", 0)),
                            "bytes": int(counter.get("bytes", 0)),
                        }
                    )
        return counters
