"""Exercise the installed module entry point as a real, non-TTY subprocess.

All writable application paths point into pytest's temporary directory. These
tests invoke only read operations or failures which occur before privileges and
kernel mutation; the actual firewall packet tests live in test_integration.py.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from geolatch.config import default_config, save_config
from geolatch.metadata import VERSION

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def cli(tmp_path: Path):
    def run(*args: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb"})
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "geolatch",
                "--config",
                str(tmp_path / "config.yaml"),
                "--state-dir",
                str(tmp_path / "state"),
                "--cache-dir",
                str(tmp_path / "cache"),
                *args,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
            cwd=ROOT,
            timeout=20,
            check=False,
        )

    return run


def output(result: subprocess.CompletedProcess[str], code: int = 0) -> Any:
    assert result.returncode == code, result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("args", [("--json", "version"), ("version", "--json")])
def test_version_supports_json_before_or_after_command(cli, args: tuple[str, ...]) -> None:
    value = output(cli(*args))
    assert value == {
        "name": "GeoLatch",
        "version": VERSION,
        "developer": "@artemkaa_2001",
        "telegram": "https://t.me/artemkaa_2001",
    }


@pytest.mark.parametrize("language, expected", [("en", "usage:"), ("ru", "Использование:")])
def test_help_is_localized_and_lists_public_commands(cli, language: str, expected: str) -> None:
    result = cli("--lang", language, "--help")
    assert result.returncode == 0, result.stderr
    assert expected.casefold() in result.stdout.casefold()
    for command in (
        "setup",
        "status",
        "countries",
        "plan",
        "apply",
        "rollback",
        "check-ip",
        "doctor",
    ):
        assert command in result.stdout
    assert "cli.command." not in result.stdout


@pytest.mark.parametrize("command", [(), ("setup",)])
def test_non_tty_launch_reports_error_without_entering_tui(cli, command: tuple[str, ...]) -> None:
    result = cli("--lang", "en", "--json", *command)
    value = output(result, 1)
    assert value["error"] == "error.tty_required"
    assert "\x1b[" not in result.stdout + result.stderr


def test_country_catalog_has_identical_iso_codes_and_localized_names(cli) -> None:
    english = output(cli("countries", "--lang", "en", "--json"))
    russian = output(cli("countries", "--lang", "ru", "--json"))
    en = {item["code"]: item["name"] for item in english}
    ru = {item["code"]: item["name"] for item in russian}
    assert len(en) == len(ru) == 249
    assert en.keys() == ru.keys()
    assert en["RU"] == "Russian Federation"
    assert ru["RU"] == "Россия"
    assert en["IR"] != ru["IR"]
    assert all(len(code) == 2 and code.isupper() for code in en)


def test_saved_language_is_used_and_override_does_not_change_config(cli, tmp_path: Path) -> None:
    config = default_config()
    config["language"] = "ru"
    path = tmp_path / "config.yaml"
    save_config(config, path)
    before = path.read_bytes()
    saved = {row["code"]: row["name"] for row in output(cli("countries", "--json"))}
    overridden = {
        row["code"]: row["name"] for row in output(cli("--lang", "en", "countries", "--json"))
    }
    assert saved["RU"] == "Россия"
    assert overridden["RU"] == "Russian Federation"
    assert path.read_bytes() == before


def test_read_only_commands_do_not_initialize_writable_state(cli, tmp_path: Path) -> None:
    output(cli("version", "--json"))
    output(cli("countries", "--json"))
    assert output(cli("logs", "--json")) == []
    plan = output(cli("plan", "--json"))
    assert plan["dry_run"] is True
    assert plan["config"]["policies"] == []
    assert not (tmp_path / "config.yaml").exists()
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "cache").exists()


def test_human_plan_prints_nft_rule_braces_without_formatting_them(cli) -> None:
    result = cli("--lang", "en", "plan")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert "Preview without changes" in result.stdout


def test_human_output_preserves_literal_braces_in_rule_text() -> None:
    from geolatch.cli import _human
    from geolatch.i18n import Translator

    rules = 'table inet geolatch {\n    comment "GeoLatch managed table v1"\n}\n'
    rendered = _human({"rules": rules}, Translator("ru"))
    assert "table inet geolatch {" in rendered
    assert 'comment "GeoLatch managed table v1"' in rendered


def test_status_reports_unknown_when_actual_kernel_query_fails(cli) -> None:
    status = output(cli("status", "--json"))
    assert status["active"] in (True, False, None)
    assert status["configured"] is False
    if status["kernel_query_error"]:
        assert status["active"] is None
    assert isinstance(status["counters"], list)
    assert status["cidr_count"] == 0


def test_doctor_uses_json_without_tui_or_mutation(cli, tmp_path: Path) -> None:
    value = output(cli("doctor", "--json"))
    assert value["platform"] == "Linux"
    assert value["kernel"]
    assert isinstance(value["root"], bool)
    assert "status" in value
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "cache").exists()


def test_addresses_returns_real_valid_machine_records(cli) -> None:
    result = cli("addresses", "--json")
    if result.returncode == 1:
        # Restricted workers may forbid even read-only NETLINK sockets. That
        # must remain an explicit discovery error, not a fabricated empty list.
        error = output(result, 1)
        assert error["error"] == "error.network_discovery"
        assert error["detail"]
        return
    value = output(result)
    assert isinstance(value, list)
    for address in value:
        assert address["interface"]
        assert address["family"] in (4, 6)
        assert isinstance(address["public"], bool)


def test_invalid_config_is_a_structured_error(cli, tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("version: 999\nlanguage: en\n", encoding="utf-8")
    value = output(cli("status", "--json"), 1)
    assert value["error"] == "error.invalid_config"
    assert "version" in value["detail"]


def test_named_pipe_configuration_is_rejected_without_waiting_for_a_writer(cli, tmp_path):
    os.mkfifo(tmp_path / "config.yaml", 0o600)
    value = output(cli("status", "--json"), 1)
    assert value["error"] == "error.invalid_config"
    assert "regular file" in value["detail"]


@pytest.mark.parametrize("command", ["apply", "enable", "disable", "rollback"])
def test_noninteractive_mutations_require_explicit_consent(
    cli, command: str, tmp_path: Path
) -> None:
    value = output(cli("--lang", "en", command, "--json"), 1)
    assert "--yes" in value["detail"]
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "cache").exists()


@pytest.mark.parametrize("command", ["apply", "enable", "disable", "rollback"])
@pytest.mark.skipif(os.geteuid() == 0, reason="This test verifies unprivileged refusal")
def test_unprivileged_mutations_are_refused_before_any_writes(
    cli, command: str, tmp_path: Path
) -> None:
    value = output(cli(command, "--yes", "--json"), 3)
    assert value["error"] == "error.root_required"
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "cache").exists()


def test_check_ip_requires_destination_and_valid_addresses(cli) -> None:
    missing = cli("check-ip", "198.51.100.2", "--json")
    assert missing.returncode == 2
    assert "--destination" in missing.stderr
    assert "Traceback" not in missing.stderr
    invalid = output(cli("check-ip", "invalid", "--destination", "198.51.100.10", "--json"), 1)
    assert invalid["error"] == "error.operation"


@pytest.mark.parametrize("arguments", [("--lang", "xx", "version"), ("--config",), ("--lang",)])
def test_invalid_arguments_have_one_diagnostic(cli, arguments: tuple[str, ...]) -> None:
    result = cli(*arguments)
    assert result.returncode == 2
    assert result.stderr.casefold().count("usage:") == 1
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("limit", ["0", "1001", "-1"])
def test_logs_rejects_out_of_range_limits(cli, limit: str) -> None:
    value = output(cli("logs", "--limit", limit, "--json"), 1)
    assert "limit" in value["detail"].casefold()


def test_dry_run_update_remains_read_only_without_root(cli, tmp_path: Path) -> None:
    value = output(cli("update", "--dry-run", "--json"))
    assert value["dry_run"] is True
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "cache").exists()
