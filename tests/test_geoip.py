"""Network-independent tests of hostile input and atomic cache publication."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import urllib.error

import pytest

from geolatch.config import default_config
from geolatch.geoip import GeoIPError, GeoIPStore, check_anomalies, download, parse_cidrs
from geolatch.providers import get_provider


def configuration(countries=("IR",), destinations=None):
    config = default_config()
    config["network"]["interfaces"] = ["eth0"]
    config["policies"] = [
        {
            "name": "primary",
            "enabled": True,
            "destinations": destinations or ["203.0.113.10"],
            "block_countries": list(countries),
        }
    ]
    return config


def test_normalize_comments_duplicates_adjacent_overlapping():
    assert parse_cidrs("# Header\n1.1.1.128/25\n1.1.1.0/25\n1.1.1.0/24\n", 4) == ["1.1.1.0/24"]
    assert parse_cidrs("2606:4700::/33\n2606:4700:8000::/33\n", 6) == ["2606:4700::/32"]


@pytest.mark.parametrize(
    "text,family",
    [
        ("", 4),
        ("# Comment only\n", 4),
        ("<html>Error</html>", 4),
        ("1.1.1.1", 4),
        ("1.1.1.1/24", 4),
        ("0.0.0.0/0", 4),
        ("::/0", 6),
        ("1.1.1.0/24", 6),
        ("2606:4700::/32", 4),
        ("10.0.0.0/8", 4),
        ("127.0.0.0/8", 4),
        ("224.0.0.0/4", 4),
        ("192.0.2.0/24", 4),
        ("100.64.0.0/10", 4),
        ("192.0.0.0/8", 4),
        ("2000::/3", 6),
        ("2001:db8::/32", 6),
        ("fc00::/7", 6),
        ("ff00::/8", 6),
        ("1.1.1.0/24\nINVALID", 4),
        ("1.1.1.0/24; drop table", 4),
    ],
)
def test_reject_bad_dangerous_empty_and_wrong_family(text, family):
    with pytest.raises(GeoIPError):
        parse_cidrs(text, family)


def test_anomaly_coverage_growth_shrink_and_turnover():
    with pytest.raises(GeoIPError, match="doubled"):
        check_anomalies(["5.1.0.0/16"], ["5.0.0.0/8"])
    with pytest.raises(GeoIPError, match="fell"):
        check_anomalies(["5.0.0.0/8"], ["5.1.0.0/16"])
    with pytest.raises(GeoIPError, match="replaced"):
        check_anomalies(["5.1.0.0/16"], ["8.1.0.0/16"])
    with pytest.raises(GeoIPError, match="empty"):
        check_anomalies(["1.1.1.0/24"], [])


def test_small_country_growth_and_aggregation_not_false_positive():
    check_anomalies(["1.1.1.0/24"], ["1.1.0.0/22"])
    check_anomalies(["1.1.1.0/25", "1.1.1.128/25"], ["1.1.1.0/24"], old_size=1000, new_size=15)


def test_provider_urls_verified_upstream_structure():
    assert (
        get_provider("ipverse-geo")
        .url("IR", 4)
        .endswith("geo-ip-blocks/master/country/ir/ir-ipv4.txt")
    )
    assert (
        get_provider("ipverse-rir")
        .url("IR", 6)
        .endswith("country-ip-blocks/master/country/ir/ipv6-aggregated.txt")
    )
    with pytest.raises(ValueError):
        get_provider("ipverse-geo").url("../etc", 4)
    with pytest.raises(ValueError):
        get_provider("unknown")


def test_constructor_and_offline_missing_are_read_only(tmp_path):
    location = tmp_path / "not-created"
    store = GeoIPStore(location)
    assert not location.exists()
    with pytest.raises(GeoIPError, match="No validated"):
        store.load(configuration())
    assert not location.exists()
    assert store.load(default_config())["databases"] == {}
    assert not location.exists()


def test_prepare_hashes_only_needed_family_and_offline_roundtrip(tmp_path, monkeypatch):
    calls = []

    def fetch(url):
        calls.append(url)
        return b"# Upstream data\n1.1.1.0/24\n"

    monkeypatch.setattr("geolatch.geoip.download", fetch)
    store = GeoIPStore(tmp_path / "cache")
    result = store.prepare(configuration())
    assert len(calls) == 1 and calls[0].endswith("ir-ipv4.txt")
    assert result["databases"] == {"IR:4": ["1.1.1.0/24"]}
    assert result["changed"] is True
    entry = result["metadata"]["entries"]["IR:4"]
    assert entry["raw_sha256"] == hashlib.sha256(b"# Upstream data\n1.1.1.0/24\n").hexdigest()
    monkeypatch.setattr("geolatch.geoip.download", lambda _: pytest.fail("offline network access"))
    files_before = {p: p.stat().st_mtime_ns for p in store.cache_dir.rglob("*")}
    assert store.load(configuration())["databases"] == result["databases"]
    assert {p: p.stat().st_mtime_ns for p in store.cache_dir.rglob("*")} == files_before


def test_multiple_country_failure_does_not_publish_partial_cache(tmp_path, monkeypatch):
    store = GeoIPStore(tmp_path / "cache")
    monkeypatch.setattr("geolatch.geoip.download", lambda _: b"1.1.1.0/24\n")
    store.prepare(configuration(("IR", "PK")))
    manifest_path = store.cache_dir / "ipverse-geo.json"
    before = manifest_path.read_bytes()

    def fetch(url):
        return b"1.1.1.0/25\n" if "/ir/" in url else b"<html>upstream error</html>"

    monkeypatch.setattr("geolatch.geoip.download", fetch)
    with pytest.raises(GeoIPError):
        store.prepare(configuration(("IR", "PK")))
    assert manifest_path.read_bytes() == before
    assert store.load(configuration(("IR", "PK")))["databases"]["IR:4"] == ["1.1.1.0/24"]


def test_cache_object_corruption_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr("geolatch.geoip.download", lambda _: b"1.1.1.0/24\n")
    store = GeoIPStore(tmp_path / "cache")
    result = store.prepare(configuration())
    digest = result["metadata"]["entries"]["IR:4"]["cidr_sha256"]
    object_path = store.cache_dir / "objects" / f"{digest}.txt"
    object_path.write_text("1.1.1.0/25\n")
    with pytest.raises(GeoIPError, match="integrity"):
        store.load(configuration())


def test_corrupt_baseline_blocks_network_replacement_and_retains_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr("geolatch.geoip.download", lambda _: b"1.1.1.0/24\n")
    store = GeoIPStore(tmp_path / "cache")
    result = store.prepare(configuration())
    manifest_path = store.cache_dir / "ipverse-geo.json"
    before = manifest_path.read_bytes()
    digest = result["metadata"]["entries"]["IR:4"]["cidr_sha256"]
    (store.cache_dir / "objects" / f"{digest}.txt").write_text("CORRUPTED\n")
    monkeypatch.setattr(
        "geolatch.geoip.download", lambda _: pytest.fail("do not trust corrupt baseline")
    )
    with pytest.raises(GeoIPError, match="integrity"):
        store.prepare(configuration(), force=True)
    assert manifest_path.read_bytes() == before


def test_manifest_corruption_rejected_before_reading_object_paths(tmp_path, monkeypatch):
    monkeypatch.setattr("geolatch.geoip.download", lambda _: b"1.1.1.0/24\n")
    store = GeoIPStore(tmp_path / "cache")
    store.prepare(configuration())
    manifest_path = store.cache_dir / "ipverse-geo.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["entries"]["IR:4"]["cidr_sha256"] = "../../etc/passwd"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(GeoIPError, match="integrity"):
        store.load(configuration())


def test_force_never_bypasses_safety_checks(tmp_path, monkeypatch):
    store = GeoIPStore(tmp_path / "cache")
    monkeypatch.setattr("geolatch.geoip.download", lambda _: b"5.1.0.0/16\n")
    store.prepare(configuration())
    monkeypatch.setattr("geolatch.geoip.download", lambda _: b"5.0.0.0/8\n")
    with pytest.raises(GeoIPError, match="anomaly"):
        store.prepare(configuration(), force=True)
    monkeypatch.setattr("geolatch.geoip.download", lambda _: b"0.0.0.0/0\n")
    with pytest.raises(GeoIPError):
        store.prepare(configuration(), force=True)


def test_disabled_configuration_does_not_touch_cache_or_network(tmp_path, monkeypatch):
    config = configuration()
    config["enabled"] = False
    monkeypatch.setattr("geolatch.geoip.download", lambda _: pytest.fail("disabled network access"))
    store = GeoIPStore(tmp_path / "cache")
    assert store.prepare(config)["databases"] == {}
    assert not store.cache_dir.exists()


def test_no_automatic_source_fallback_and_no_cross_source_reuse(tmp_path, monkeypatch):
    store = GeoIPStore(tmp_path / "cache")
    monkeypatch.setattr("geolatch.geoip.download", lambda _: b"1.1.1.0/24\n")
    config = configuration()
    store.prepare(config)
    alternative = copy.deepcopy(config)
    alternative["source"] = "ipverse-rir"
    with pytest.raises(GeoIPError, match="No validated"):
        store.load(alternative)
    assert store.prepare(alternative)["metadata"]["source"] == "ipverse-rir"
    assert (store.cache_dir / "ipverse-geo.json").exists()
    assert (store.cache_dir / "ipverse-rir.json").exists()


def test_unchanged_dataset_reports_changed_false(tmp_path, monkeypatch):
    monkeypatch.setattr("geolatch.geoip.download", lambda _: b"1.1.1.0/24\n")
    store = GeoIPStore(tmp_path / "cache")
    assert store.prepare(configuration())["changed"]
    assert not store.prepare(configuration())["changed"]


class Response(io.BytesIO):
    status = 200
    url = "https://raw.githubusercontent.com/ipverse/geo-ip-blocks/master/country/ir/ir-ipv4.txt"

    def __init__(self, data=b"1.1.1.0/24\n", headers=None):
        super().__init__(data)
        self.headers = headers or {"Content-Type": "text/plain"}


def test_https_timeout_and_retry_then_success(monkeypatch):
    class Opener:
        calls = 0

        def open(self, request, timeout):
            assert timeout == 25
            self.calls += 1
            if self.calls < 3:
                raise urllib.error.URLError("temporary upstream failure")
            return Response()

    opener = Opener()
    delays = []
    monkeypatch.setattr("geolatch.geoip.urllib.request.build_opener", lambda *args: opener)
    monkeypatch.setattr("geolatch.geoip.time.sleep", delays.append)
    assert download(Response.url) == b"1.1.1.0/24\n"
    assert opener.calls == 3
    assert delays == [0.5, 1.0]


@pytest.mark.parametrize(
    "headers,data",
    [
        ({"Content-Type": "text/html"}, b"<html>error</html>"),
        ({"Content-Length": "0"}, b""),
        ({"Content-Length": "33554433"}, b"1.1.1.0/24\n"),
        ({"Content-Length": "nonsense"}, b"1.1.1.0/24\n"),
        ({"Content-Type": "text/plain"}, b""),
    ],
)
def test_download_validates_content_type_and_bounded_size(monkeypatch, headers, data):
    class Opener:
        def open(self, request, timeout):
            return Response(data, headers)

    monkeypatch.setattr("geolatch.geoip.urllib.request.build_opener", lambda *args: Opener())
    with pytest.raises(GeoIPError):
        download(Response.url)


def test_download_stream_exceeding_size_limit_is_rejected(monkeypatch):
    class Opener:
        def open(self, request, timeout):
            return Response(b"x" * 65)

    monkeypatch.setattr("geolatch.geoip.MAX_DOWNLOAD_BYTES", 64)
    monkeypatch.setattr("geolatch.geoip.urllib.request.build_opener", lambda *args: Opener())
    with pytest.raises(GeoIPError, match="size limit"):
        download(Response.url)


def test_404_does_not_retry_or_switch_source(monkeypatch):
    class Opener:
        calls = 0

        def open(self, request, timeout):
            self.calls += 1
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

    opener = Opener()
    monkeypatch.setattr("geolatch.geoip.urllib.request.build_opener", lambda *args: opener)
    monkeypatch.setattr("geolatch.geoip.time.sleep", lambda _: pytest.fail("404 must not retry"))
    with pytest.raises(GeoIPError, match="404"):
        download(Response.url)
    assert opener.calls == 1


def test_untrusted_url_rejected_before_network(monkeypatch):
    monkeypatch.setattr(
        "geolatch.geoip.urllib.request.build_opener", lambda *args: pytest.fail("network")
    )
    with pytest.raises(GeoIPError, match="Unsupported"):
        download("http://raw.githubusercontent.com/ipverse/data")
    with pytest.raises(GeoIPError):
        download("https://raw.githubusercontent.com.evil.test/ipverse/data")
