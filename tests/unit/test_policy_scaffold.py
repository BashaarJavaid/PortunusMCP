"""Focused item-52 policy scaffold and CLI checks."""

import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from services import cli
from services.gateway.audit_verification import AuditRecord
from services.gateway.policy_engine import load_bytes
from services.gateway.policy_scaffold import (
    ScaffoldConflict,
    ScaffoldRequest,
    _candidate_data,
    _grant,
    _render,
    _window,
)


def _base() -> Any:
    raw = yaml.safe_dump(
        {
            "version": 4,
            "servers": {
                "second": {"image": "second@sha256:abc", "command": ["second"]},
                "first": {"image": "first@sha256:def", "command": ["first"]},
            },
            "identities": [
                {
                    "id": "observed",
                    "api_key_hash": "sha256:observed",
                    "attributes": {"team": "eng"},
                    "allowed_servers": [{"server_id": "first", "allowed_tools": ["old", "*"]}],
                },
                {
                    "id": "unobserved",
                    "api_key_hash": "sha256:unobserved",
                    "allowed_servers": [{"server_id": "first", "allowed_tools": ["old"]}],
                },
                {
                    "id": "admin",
                    "api_key_hash": "sha256:admin",
                    "admin": True,
                    "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
                },
            ],
            "risk": {
                "tool_sensitivity": {"old": "critical"},
                "protected_repos": ["acme/prod-*"],
            },
        },
        sort_keys=False,
    ).encode()
    return load_bytes(raw)


def _record(
    event: str = "ALLOW",
    *,
    mode: str | None = "observe",
    identity: str = "observed",
    server: str | None = "first",
    tool: str | None = "echo",
) -> AuditRecord:
    payload = {"mode": mode} if mode is not None else {}
    return AuditRecord(
        seq=7,
        prev_hash="0" * 64,
        curr_hash="1" * 64,
        signature=b"",
        key_id="sha256:key",
        timestamp=datetime.now(UTC),
        identity_id=identity,
        server_id=server,
        tool_name=tool,
        policy_version=4,
        event_type=event,
        risk_score=None,
        payload=payload,
        latency_ms=None,
    )


def test_request_window_and_exact_observe_filtering() -> None:
    today = datetime.now(UTC).date().isoformat()
    start, end = _window(f"{today}..{today}")
    assert end - start == timedelta(days=1)
    assert _grant(_record()) == ("observed", "first", "echo")
    assert _grant(_record(event="DENY_RBAC")) == ("observed", "first", "echo")
    assert _grant(_record(event="APPROVED")) is None
    assert _grant(_record(mode="enforce")) is None
    assert _grant(_record(mode=None)) is None
    with pytest.raises(ValueError, match="future"):
        future = (datetime.now(UTC).date() + timedelta(days=1)).isoformat()
        _window(f"{today}..{future}")
    with pytest.raises(ValidationError):
        ScaffoldRequest.model_validate(
            {"source": "audit", "window": f"{today}..{today}", "extra": True}
        )


def test_observe_terminal_requires_exact_scope() -> None:
    for record in (
        _record(identity=""),
        _record(server=None),
        _record(tool=None),
        _record(tool="*"),
    ):
        with pytest.raises(ScaffoldConflict):
            _grant(record)


def test_candidate_preserves_auth_servers_and_risk_but_replaces_grants() -> None:
    base = _base()
    observed = {"observed": {"first": {"zeta", "alpha"}, "second": {"beta"}}}
    data, grants, server_tools = _candidate_data(base, 9, observed)
    assert data["version"] == 10
    assert list(data["servers"]) == ["second", "first"]
    assert [identity["id"] for identity in data["identities"]] == ["observed", "admin"]
    observed_identity, admin = data["identities"]
    assert observed_identity["api_key_hash"] == "sha256:observed"
    assert observed_identity["attributes"] == {"team": "eng"}
    assert observed_identity["allowed_servers"] == [
        {"server_id": "second", "allowed_tools": ["beta"], "conditions": []},
        {
            "server_id": "first",
            "allowed_tools": ["alpha", "zeta"],
            "conditions": [],
        },
    ]
    assert admin["allowed_servers"] == []
    assert data["risk"] == {
        "tool_sensitivity": {},
        "protected_repos": ["acme/prod-*"],
    }
    assert (grants, server_tools) == (2, 3)


def test_render_is_deterministic_commented_and_structurally_valid() -> None:
    base = _base()
    data, _, _ = _candidate_data(base, 4, {"observed": {"first": {"echo"}}})
    kwargs = {
        "base": base,
        "window": "2026-07-01..2026-07-07",
        "start_seq": 2,
        "end_seq": 8,
        "genesis_anchored": False,
    }
    first = _render(data, **kwargs)
    assert first == _render(data, **kwargs)
    text = first.decode()
    assert text.startswith("# GENERATED SCAFFOLD — NOT FULLY VALIDATED OR APPLIED\n")
    assert "Review every TODO before rollout." in text
    assert "observed-tool sensitivity" in text
    assert "contextual restrictions" in text
    assert "prefix_attested=false" in text
    candidate = load_bytes(first)
    assert candidate.version == 5
    assert candidate.content_hash == hashlib.sha256(first).hexdigest()


def _response(policy: str, *, content_hash: str | None = None) -> dict[str, Any]:
    digest = content_hash or hashlib.sha256(policy.encode()).hexdigest()
    return {
        "policy": policy,
        "metadata": {
            "candidate": {
                "version": 5,
                "content_hash": digest,
                "identity_count": 2,
                "grant_count": 1,
                "server_tool_count": 1,
            }
        },
    }


def _cli_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORTUNUSMCP_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("PORTUNUSMCP_ADMIN_KEY", "admin-key")


def test_cli_scaffold_atomic_private_output_and_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _cli_env(monkeypatch)
    policy = "version: 5\nservers: {}\nidentities: []\nrisk: {}\n"
    monkeypatch.setattr(cli.Client, "request", lambda *_args, **_kwargs: _response(policy))
    output_arg = str(tmp_path / "missing" / "candidate.yaml")
    assert (
        cli.main(
            [
                "--json",
                "policy",
                "scaffold",
                "--from-audit",
                "--window",
                "2026-07-01..2026-07-07",
                "--output",
                output_arg,
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result == {"output": output_arg, "metadata": _response(policy)["metadata"]}
    output = Path(output_arg)
    assert output.read_text() == policy
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert not list(output.parent.glob(".candidate.yaml.*"))


def test_cli_scaffold_refuses_early_force_replaces_and_checks_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _cli_env(monkeypatch)
    output = tmp_path / "candidate.yaml"
    output.write_text("old")
    calls = 0

    def request(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return _response("version: 5\n")

    monkeypatch.setattr(cli.Client, "request", request)
    args = [
        "policy",
        "scaffold",
        "--from-audit",
        "--window",
        "2026-07-01..2026-07-07",
        "--output",
        str(output),
    ]
    assert cli.main(args) == 1
    assert calls == 0
    assert cli.main([*args, "--force"]) == 0
    assert calls == 1
    assert output.read_text() == "version: 5\n"

    bad = tmp_path / "bad.yaml"
    monkeypatch.setattr(
        cli.Client,
        "request",
        lambda *_args, **_kwargs: _response("version: 6\n", content_hash="0" * 64),
    )
    assert cli.main([*args[:-1], str(bad)]) == 1
    assert not bad.exists()


def test_cli_human_output_shell_quotes_validate_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _cli_env(monkeypatch)
    policy = "version: 5\n"
    monkeypatch.setattr(cli.Client, "request", lambda *_args, **_kwargs: _response(policy))
    output = tmp_path / "candidate policy.yaml"
    assert (
        cli.main(
            [
                "policy",
                "scaffold",
                "--from-audit",
                "--window",
                "2026-07-01..2026-07-07",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    rendered = capsys.readouterr().out
    assert "Identities: 2; grants: 1; server-tools: 1" in rendered
    assert f"portunusmcp policy validate '{output}'" in rendered
