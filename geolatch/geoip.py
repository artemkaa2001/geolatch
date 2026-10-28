"""Bounded HTTPS downloads, strict CIDR validation and content-addressed cache.

Constructing a store and loading it never writes. A complete candidate is checked
before replacing the manifest; a failed country leaves the old manifest intact.
The controller serializes writes with its operation lock and stores independent
confirmed firewall snapshots, so cache freshness never implies applied rules.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import ssl
import stat
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .config import validate_config
from .providers import get_provider
from .utils import atomic_write, read_json, utc_now, write_json

MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
MAX_PREFIXES = 1_000_000
MAX_CANDIDATE_BYTES = 256 * 1024 * 1024
MAX_LINE_LENGTH = 256
DOWNLOAD_TIMEOUT = 25
DOWNLOAD_ATTEMPTS = 3

_FORBIDDEN = {
    4: tuple(
        ipaddress.ip_network(value)
        for value in (
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        )
    ),
    6: tuple(
        ipaddress.ip_network(value)
        for value in (
            "2001::/32",
            "2001:2::/48",
            "2001:10::/28",
            "2001:20::/28",
            "2001:db8::/32",
        )
    ),
}
_V6_GLOBAL = ipaddress.ip_network("2000::/3")


class GeoIPError(ValueError):
    key = "error.operation"

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _manifest_digest(manifest: dict) -> str:
    content = {key: value for key, value in manifest.items() if key != "sha256"}
    return _sha256(json.dumps(content, sort_keys=True, ensure_ascii=True).encode("ascii"))


def _canonical(networks: list[str]) -> str:
    return "".join(f"{network}\n" for network in networks)


def parse_cidrs(text: str, family: int) -> list[str]:
    """Parse commented plaintext strictly and collapse overlap/adjacent ranges.

    Default routes and every overlap with reserved/service ranges are rejected,
    including a broad public-looking prefix that contains a reserved subrange.
    """
    if family not in (4, 6) or not isinstance(text, str):
        raise GeoIPError("Invalid CIDR input family or encoding")
    if len(text.encode("utf-8")) > MAX_DOWNLOAD_BYTES:
        raise GeoIPError("GeoIP dataset exceeds the size limit")
    networks = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) > MAX_LINE_LENGTH or "/" not in line:
            raise GeoIPError(f"Invalid CIDR record on line {number}")
        try:
            network = ipaddress.ip_network(line, strict=True)
        except ValueError as error:
            raise GeoIPError(f"Invalid CIDR record on line {number}: {line[:80]}") from error
        if network.version != family or network.prefixlen == 0:
            raise GeoIPError(f"Unexpected family or default route on line {number}")
        if (
            any(network.overlaps(excluded) for excluded in _FORBIDDEN[family])
            or (family == 6 and not network.subnet_of(_V6_GLOBAL))
            or not network.network_address.is_global
            or not network.broadcast_address.is_global
        ):
            raise GeoIPError(f"Reserved or service network on line {number}: {network}")
        networks.append(network)
        if len(networks) > MAX_PREFIXES:
            raise GeoIPError("GeoIP dataset has too many prefixes")
    if not networks:
        raise GeoIPError("GeoIP dataset is empty; existing protection is retained")
    collapsed = list(ipaddress.collapse_addresses(networks))
    if any(network.prefixlen == 0 for network in collapsed):
        raise GeoIPError("Combined GeoIP networks cover the entire address family")
    return [str(network) for network in collapsed]


def _overlap_coverage(old: list, new: list) -> int:
    """Count common addresses in linear time for sorted, collapsed networks."""
    i = j = coverage = 0
    while i < len(old) and j < len(new):
        left, right = old[i], new[j]
        start = max(int(left.network_address), int(right.network_address))
        end = min(int(left.broadcast_address), int(right.broadcast_address))
        coverage += max(0, end - start + 1)
        if left.broadcast_address < right.broadcast_address:
            i += 1
        else:
            j += 1
    return coverage


def check_anomalies(
    old: list[str], new: list[str], *, old_size: int | None = None, new_size: int | None = None
) -> None:
    """Compare coverage, turnover, size and prefix counts without aggregation bias.

    Small countries get an absolute change allowance of 4096 IPv4 addresses or
    one IPv6 /64. Large feeds reject >50% loss, >100% growth or >50% turnover.
    Count/size changes alone are advisory unless address coverage also changes.
    No command-line force option disables these checks.
    """
    if not new:
        raise GeoIPError("GeoIP dataset disappeared or became empty")
    if not old:
        return
    try:
        old_nets = list(ipaddress.collapse_addresses(ipaddress.ip_network(x) for x in old))
        new_nets = list(ipaddress.collapse_addresses(ipaddress.ip_network(x) for x in new))
    except (TypeError, ValueError) as error:
        raise GeoIPError("Cannot compare invalid GeoIP datasets") from error
    if old_nets[0].version != new_nets[0].version:
        raise GeoIPError("GeoIP dataset changed its IP family")
    old_coverage = sum(n.num_addresses for n in old_nets)
    new_coverage = sum(n.num_addresses for n in new_nets)
    allowance = 4096 if old_nets[0].version == 4 else 2**64
    if old_coverage - new_coverage > max(old_coverage // 2, allowance):
        raise GeoIPError("GeoIP anomaly: address coverage fell by more than 50%")
    if new_coverage - old_coverage > max(old_coverage, allowance):
        raise GeoIPError("GeoIP anomaly: address coverage more than doubled")
    common = _overlap_coverage(old_nets, new_nets)
    if old_coverage - common > max(old_coverage // 2, allowance):
        raise GeoIPError("GeoIP anomaly: more than 50% of addresses were replaced")
    count_ratio = len(new_nets) / len(old_nets)
    size_ratio = (new_size / old_size) if old_size and new_size is not None else 1.0
    coverage_change = abs(new_coverage - old_coverage)
    if count_ratio < 0.1 or count_ratio > 10 or size_ratio < 0.1 or size_ratio > 10:
        if coverage_change > max(old_coverage // 4, allowance):
            raise GeoIPError("GeoIP anomaly: unexpected prefix count or download size change")


class _HTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://raw.githubusercontent.com/"):
            raise GeoIPError("GeoIP redirect left the trusted HTTPS source")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str) -> bytes:
    """Fetch bounded bytes with certificate validation, retries and timeouts."""
    if not url.startswith("https://raw.githubusercontent.com/ipverse/"):
        raise GeoIPError("Unsupported GeoIP download URL")
    opener = urllib.request.build_opener(
        _HTTPSRedirectHandler(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    request = urllib.request.Request(
        url, headers={"User-Agent": "GeoLatch/0.1.0", "Accept": "text/plain"}
    )
    last_error: Exception | None = None
    for attempt in range(DOWNLOAD_ATTEMPTS):
        try:
            with opener.open(request, timeout=DOWNLOAD_TIMEOUT) as response:
                if response.status != 200 or not response.url.startswith(
                    "https://raw.githubusercontent.com/"
                ):
                    raise GeoIPError("Unexpected GeoIP HTTP response")
                if "html" in response.headers.get("Content-Type", "").lower():
                    raise GeoIPError("GeoIP source returned HTML instead of CIDRs")
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        if not 0 < int(content_length) <= MAX_DOWNLOAD_BYTES:
                            raise GeoIPError("GeoIP download has an unsafe size")
                    except ValueError as error:
                        raise GeoIPError("Invalid GeoIP HTTP content length") from error
                chunks = []
                length = 0
                started = time.monotonic()
                # HTTPResponse.read(n) can wait for n bytes across many socket
                # reads. read1 returns after one transport read, allowing the
                # overall deadline to be checked even for a trickling source.
                reader = getattr(response, "read1", response.read)
                while length <= MAX_DOWNLOAD_BYTES:
                    if time.monotonic() - started > 90:
                        raise GeoIPError("GeoIP download exceeded its total time limit")
                    chunk = reader(min(65536, MAX_DOWNLOAD_BYTES + 1 - length))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    length += len(chunk)
                raw = b"".join(chunks)
                if not raw or len(raw) > MAX_DOWNLOAD_BYTES:
                    raise GeoIPError("GeoIP download is empty or exceeds its size limit")
                return raw
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code not in (408, 429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
        if attempt + 1 < DOWNLOAD_ATTEMPTS:
            time.sleep(0.5 * 2**attempt)
    raise GeoIPError(f"Unable to download GeoIP source: {last_error}") from last_error


class GeoIPStore:
    """Immutable objects plus one atomic manifest, serialized by the controller."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = Path(cache_dir)

    def _manifest_path(self, source: str) -> Path:
        get_provider(source)
        return self.cache_dir / f"{source}.json"

    def _manifest(self, source: str) -> dict[str, Any]:
        try:
            manifest = read_json(self._manifest_path(source), limit=2 * 1024 * 1024)
        except FileNotFoundError:
            return {"schema": 1, "source": source, "entries": {}}
        except (ValueError, OSError) as error:
            raise GeoIPError(f"Invalid GeoIP cache manifest: {error}") from error
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema") != 1
            or manifest.get("source") != source
            or not isinstance(manifest.get("entries"), dict)
        ):
            raise GeoIPError("Invalid GeoIP cache manifest schema")
        if manifest.get("sha256") != _manifest_digest(manifest):
            raise GeoIPError("GeoIP cache manifest integrity check failed")
        return manifest

    def _object_path(self, digest: str) -> Path:
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise GeoIPError("Invalid GeoIP cache object hash")
        return self.cache_dir / "objects" / f"{digest}.txt"

    def _read_entry(self, entry: Any, family: int) -> list[str]:
        if not isinstance(entry, dict):
            raise GeoIPError("Invalid GeoIP cache entry")
        if (
            entry.get("family") != family
            or type(entry.get("byte_size")) is not int
            or not 0 < entry["byte_size"] <= MAX_DOWNLOAD_BYTES
            or not isinstance(entry.get("raw_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["raw_sha256"]) is None
        ):
            raise GeoIPError("Invalid GeoIP cache entry metadata")
        digest = entry.get("cidr_sha256")
        path = self._object_path(digest)
        # Read as text through an O_NOFOLLOW bounded descriptor, not Path.read_text.
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                os.close(descriptor)
                raise GeoIPError("GeoIP cache object is not a regular file")
            with os.fdopen(descriptor, "rb") as stream:
                raw = stream.read(MAX_DOWNLOAD_BYTES + 1)
            if _sha256(raw) != digest:
                raise GeoIPError("GeoIP cache integrity check failed")
            networks = parse_cidrs(raw.decode("ascii"), family)
        except (OSError, UnicodeError) as error:
            raise GeoIPError(f"Cannot read verified GeoIP cache: {error}") from error
        if (
            len(raw) > MAX_DOWNLOAD_BYTES
            or entry.get("count") != len(networks)
            or entry.get("address_coverage")
            != sum(ipaddress.ip_network(x).num_addresses for x in networks)
            or raw != _canonical(networks).encode("ascii")
        ):
            raise GeoIPError("GeoIP cache metadata or normalization mismatch")
        return networks

    def prepare(self, config: dict, force: bool = False, offline: bool = False) -> dict:
        config = validate_config(config)
        provider = get_provider(config["source"])
        needed = set()
        for policy in config["policies"]:
            if not config["enabled"] or not policy["enabled"]:
                continue
            families = (
                {4, 6}
                if policy["destinations"] == "all"
                else {
                    ipaddress.ip_address(destination).version
                    for destination in policy["destinations"]
                }
            )
            needed.update(
                (country, family)
                for country in policy["block_countries"]
                for family in families
                if config["network"][f"ipv{family}"]
            )
        required = sorted(needed)
        if not required:
            return {
                "databases": {},
                "metadata": {"source": provider.name, "entries": {}},
                "changed": False,
            }
        manifest = self._manifest(provider.name)
        entries = dict(manifest["entries"])
        databases: dict[str, list[str]] = {}
        selected: dict[str, dict] = {}
        candidates: dict[str, str] = {}
        changed = False
        candidate_bytes = 0
        fetched_at = utc_now()
        for country, family in required:
            key = f"{country}:{family}"
            old_entry = entries.get(key)
            old_networks = self._read_entry(old_entry, family) if old_entry is not None else []
            if offline:
                if old_entry is None:
                    raise GeoIPError(f"No validated local GeoIP cache for {key}")
                databases[key] = old_networks
                selected[key] = old_entry
                continue
            raw = download(provider.url(country, family))
            candidate_bytes += len(raw)
            if candidate_bytes > MAX_CANDIDATE_BYTES:
                raise GeoIPError("Combined GeoIP candidate exceeds its size limit")
            try:
                networks = parse_cidrs(raw.decode("ascii"), family)
            except UnicodeError as error:
                raise GeoIPError(f"GeoIP source is not ASCII CIDR text: {key}") from error
            check_anomalies(
                old_networks,
                networks,
                old_size=old_entry.get("byte_size") if old_entry else None,
                new_size=len(raw),
            )
            normalized = _canonical(networks)
            digest = _sha256(normalized.encode("ascii"))
            entry = {
                "url": provider.url(country, family),
                "country": country,
                "family": family,
                "raw_sha256": _sha256(raw),
                "cidr_sha256": digest,
                "count": len(networks),
                "address_coverage": sum(ipaddress.ip_network(x).num_addresses for x in networks),
                "byte_size": len(raw),
                "fetched_at": fetched_at,
            }
            changed |= old_entry is None or old_entry.get("cidr_sha256") != digest
            entries[key] = selected[key] = entry
            databases[key] = networks
            candidates[digest] = normalized
        if not offline:
            # All requested countries passed. Partial immutable objects cannot be
            # observed until the manifest commits; an interrupted write is safe.
            for digest, normalized in candidates.items():
                path = self._object_path(digest)
                # Replace even pre-existing objects to avoid committing a digest
                # whose old on-disk content was corrupted or truncated.
                atomic_write(path, normalized)
            manifest = {
                "schema": 1,
                "source": provider.name,
                "fetched_at": fetched_at,
                "entries": entries,
            }
            manifest["sha256"] = _manifest_digest(manifest)
            write_json(self._manifest_path(provider.name), manifest)
        metadata = {
            "source": provider.name,
            "fetched_at": manifest.get("fetched_at"),
            "entries": selected,
            "cidr_count": sum(len(values) for values in databases.values()),
            "license": provider.license,
        }
        return {"databases": databases, "metadata": metadata, "changed": changed}

    def load(self, config: dict) -> dict:
        """Strictly read-only cache loading for plans and offline diagnostics."""
        return self.prepare(config, offline=True)
