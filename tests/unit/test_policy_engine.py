"""ARCHITECTURE.md §11 unit criterion: policy resolution logic (RBAC + ABAC load)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from services.gateway import policy_engine
from services.gateway.policy_engine import PolicyEngine, PolicyFile

SERVER = {"image": "example/upstream:test", "command": ["unused-command"]}
SERVERS = {"github": SERVER, "filesystem": SERVER}


def make_engine(identities: list[dict]) -> PolicyEngine:
    return PolicyEngine(
        PolicyFile.model_validate({"version": 3, "servers": SERVERS, "identities": identities})
    )


READONLY = {
    "id": "agent-readonly",
    "api_key_hash": "sha256:0",
    "allowed_servers": [{"server_id": "github", "allowed_tools": ["list_issues", "get_pr"]}],
}


def test_allowed_tool_on_matching_server() -> None:
    assert make_engine([READONLY]).is_allowed("agent-readonly", "github", "list_issues")


def test_unlisted_tool_is_denied() -> None:
    assert not make_engine([READONLY]).is_allowed("agent-readonly", "github", "merge_pr")


def test_other_server_is_denied() -> None:
    assert not make_engine([READONLY]).is_allowed("agent-readonly", "filesystem", "list_issues")


def test_unknown_identity_is_denied() -> None:
    assert not make_engine([READONLY]).is_allowed("nobody", "github", "list_issues")


def test_missing_identity_is_denied() -> None:
    assert not make_engine([READONLY]).is_allowed(None, "github", "list_issues")


def test_denied_tools_overrides_wildcard_allow() -> None:
    engine = make_engine(
        [
            {
                "id": "ops",
                "api_key_hash": "sha256:1",
                "allowed_servers": [
                    {
                        "server_id": "*",
                        "allowed_tools": ["*"],
                        "denied_tools": ["delete_repo"],
                    }
                ],
            }
        ]
    )
    assert engine.is_allowed("ops", "github", "merge_pr")
    assert not engine.is_allowed("ops", "github", "delete_repo")


def test_conditions_are_compiled_at_load(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
version: 1
identities:
  - id: "ops"
    api_key_hash: "sha256:1"
    attributes:
      team: "engineering"
    allowed_servers:
      - server_id: "*"
        allowed_tools: ["*"]
        conditions:
          - "identity.team == 'engineering' and context.hour < 20"
          - "risk.score < 60"
"""
    )
    engine = policy_engine.load(policy)
    grant = engine.matching_grant("ops", "github", "merge_pr")
    assert grant is not None
    compiled = grant.compiled_conditions
    assert [c.source for c in compiled] == [
        "identity.team == 'engineering' and context.hour < 20",
        "risk.score < 60",
    ]
    assert [c.references_risk for c in compiled] == [False, True]
    assert engine.identity("ops") is not None
    assert engine.identity("ops").attributes == {"team": "engineering"}  # type: ignore[union-attr]


def test_malformed_condition_fails_load(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
version: 1
identities:
  - id: "ops"
    api_key_hash: "sha256:1"
    allowed_servers:
      - server_id: "*"
        allowed_tools: ["*"]
        conditions:
          - "__import__('os').system('id')"
"""
    )
    with pytest.raises(ValidationError):
        policy_engine.load(policy)


# --- server registry validation (item 35) ---


def test_grant_naming_unregistered_server_fails_load() -> None:
    with pytest.raises(ValidationError, match="unregistered server"):
        PolicyFile.model_validate({"version": 1, "servers": {}, "identities": [READONLY]})


def test_wildcard_is_not_a_registrable_server_id() -> None:
    with pytest.raises(ValidationError, match="not a registrable"):
        PolicyFile.model_validate({"version": 1, "servers": {"*": SERVER}, "identities": []})


def test_server_config_resolves_registered_servers() -> None:
    engine = make_engine([READONLY])
    assert engine.server_config("github") is not None
    assert engine.server_config("github").command == ["unused-command"]  # type: ignore[union-attr]
    assert engine.server_config("nope") is None


def test_legacy_string_server_is_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyFile.model_validate(
            {"version": 1, "servers": {"github": "unused-command"}, "identities": []}
        )


def test_upstream_environment_is_explicit_and_secret_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PORTUNUSMCP_UPSTREAM_TOKEN", "upstream-only")
    policy = PolicyFile.model_validate(
        {
            "version": 1,
            "servers": {
                "github": {
                    **SERVER,
                    "env": {"TOKEN": "PORTUNUSMCP_UPSTREAM_TOKEN"},
                }
            },
        }
    )
    assert policy.servers["github"].resolved_environment == {"TOKEN": "upstream-only"}
    assert "upstream-only" not in policy.model_dump_json()


def test_upstream_environment_rejects_gateway_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "secret")
    with pytest.raises(ValidationError, match="must start"):
        PolicyFile.model_validate(
            {
                "version": 1,
                "servers": {
                    "github": {
                        **SERVER,
                        "env": {"DATABASE_URL": "DATABASE_URL"},
                    }
                },
            }
        )


@pytest.mark.parametrize(
    "target",
    ["/app/secrets", "/app/secrets/key", "/var/run/docker.sock", "/safe/../app/secrets"],
)
def test_upstream_mount_rejects_reserved_targets(target: str) -> None:
    with pytest.raises(ValidationError, match="reserved|must not contain"):
        PolicyFile.model_validate(
            {
                "version": 1,
                "servers": {
                    "github": {
                        **SERVER,
                        "volumes": [
                            {
                                "source": "portunusmcp-upstream-test-data",
                                "target": target,
                            }
                        ],
                    }
                },
            }
        )


def test_matching_grant_none_when_rbac_denies() -> None:
    engine = make_engine([READONLY])
    assert engine.matching_grant("agent-readonly", "github", "merge_pr") is None
    assert engine.matching_grant("nobody", "github", "list_issues") is None


def test_missing_policy_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        policy_engine.load(tmp_path / "nope.yaml")


def test_policy_store_reload_swaps_engine(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nidentities: []\n")
    store = policy_engine.PolicyStore(path)
    assert store.engine.version == 1

    path.write_text("version: 2\nidentities: []\n")
    assert store.reload() is True
    assert store.engine.version == 2
    assert store.engine.content_hash  # recorded for the POLICY_ACTIVATED payload


def test_policy_store_keeps_last_known_good_on_broken_reload(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nidentities: []\n")
    store = policy_engine.PolicyStore(path)

    path.write_text("version: [broken\n")
    assert store.reload() is False
    assert store.engine.version == 1  # old policy stays active


def test_policy_store_keeps_last_known_good_on_bad_condition(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nidentities: []\n")
    store = policy_engine.PolicyStore(path)

    path.write_text(
        """
version: 2
identities:
  - id: "ops"
    api_key_hash: "sha256:1"
    allowed_servers:
      - server_id: "*"
        allowed_tools: ["*"]
        conditions:
          - "open('/etc/passwd')"
"""
    )
    assert store.reload() is False
    assert store.engine.version == 1


# --- auth_mode field matrix (item 34) ---


def signed_identity(**overrides: object) -> dict:
    identity: dict = {
        "id": "ci-agent",
        "auth_mode": "signed",
        "key_id": "kid_test",
        "signing_secret_env": "POLICY_TEST_SECRET",
        "allowed_servers": [],
    }
    identity.update(overrides)
    return identity


def test_signed_identity_loads_and_resolves_by_key_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICY_TEST_SECRET", "s3cret")
    engine = make_engine([signed_identity()])
    assert engine.identity_for_key_id("kid_test") == "ci-agent"
    identity = engine.identity("ci-agent")
    assert identity is not None and identity.signing_secret == b"s3cret"


def test_signed_identity_fails_load_without_its_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("POLICY_TEST_SECRET", raising=False)
    with pytest.raises(ValidationError, match="fail closed"):
        make_engine([signed_identity()])


def test_signed_identity_forbids_api_key_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICY_TEST_SECRET", "s3cret")
    with pytest.raises(ValidationError, match="forbids api_key_hash"):
        make_engine([signed_identity(api_key_hash="sha256:2")])


def test_signed_identity_cannot_be_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    # The /admin API authenticates by bearer key only; an unusable admin flag is a
    # misconfiguration, rejected at load rather than left silently dead.
    monkeypatch.setenv("POLICY_TEST_SECRET", "s3cret")
    with pytest.raises(ValidationError, match="admin requires bearer"):
        make_engine([signed_identity(admin=True)])


def test_signed_identity_requires_key_id_and_env() -> None:
    with pytest.raises(ValidationError, match="requires key_id"):
        make_engine([signed_identity(key_id=None)])
    with pytest.raises(ValidationError, match="requires key_id"):
        make_engine([signed_identity(signing_secret_env=None)])


def test_bearer_identity_requires_api_key_hash_and_forbids_signed_fields() -> None:
    with pytest.raises(ValidationError, match="requires api_key_hash"):
        make_engine([{"id": "a", "allowed_servers": []}])
    with pytest.raises(ValidationError, match="signed-mode fields"):
        make_engine([{"id": "a", "api_key_hash": "sha256:0", "key_id": "kid_x"}])


def test_existing_bearer_yaml_shape_still_loads() -> None:
    # No auth_mode key at all — the pre-item-34 shape must stay valid (default bearer).
    engine = make_engine([READONLY])
    identity = engine.identity("agent-readonly")
    assert identity is not None and identity.auth_mode == "bearer"


# --- identity index collision validation (item 43) ---


def test_duplicate_identity_id_fails_with_positions() -> None:
    with pytest.raises(
        ValidationError,
        match=r"duplicate identity id 'same' at identities\[0\] and identities\[1\]",
    ):
        make_engine(
            [
                {"id": "same", "api_key_hash": "sha256:first"},
                {"id": "same", "api_key_hash": "sha256:second"},
            ]
        )


def test_duplicate_api_key_hash_names_both_identities() -> None:
    with pytest.raises(
        ValidationError,
        match=r"duplicate api_key_hash 'sha256:same' for identities 'first' and 'second'",
    ):
        make_engine(
            [
                {"id": "first", "api_key_hash": "sha256:same"},
                {"id": "second", "api_key_hash": "sha256:same"},
            ]
        )


def test_duplicate_signed_key_id_names_both_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("POLICY_TEST_SECRET_A", "secret-a")
    monkeypatch.setenv("POLICY_TEST_SECRET_B", "secret-b")
    with pytest.raises(
        ValidationError,
        match=r"duplicate key_id 'kid_same' for identities 'first' and 'second'",
    ):
        make_engine(
            [
                {
                    "id": "first",
                    "auth_mode": "signed",
                    "key_id": "kid_same",
                    "signing_secret_env": "POLICY_TEST_SECRET_A",
                },
                {
                    "id": "second",
                    "auth_mode": "signed",
                    "key_id": "kid_same",
                    "signing_secret_env": "POLICY_TEST_SECRET_B",
                },
            ]
        )


def test_policy_store_keeps_last_known_good_on_duplicate_identity(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nidentities: []\n")
    store = policy_engine.PolicyStore(path)
    path.write_text(
        """
version: 2
identities:
  - {id: duplicate, api_key_hash: "sha256:first"}
  - {id: duplicate, api_key_hash: "sha256:second"}
"""
    )
    assert store.reload() is False
    assert store.engine.version == 1
