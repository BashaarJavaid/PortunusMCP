import secrets
import shlex
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import yaml

from services.gateway import risk_engine
from services.gateway.main import app
from tests.integration.conftest import (  # noqa: F401  (fixtures re-exported)
    Gateway,
    _key_hash,
    clean_audit,
    gateway,
    running_gateway,
    signed_gateway,
)
from tests.integration.test_step_up import step_up_gateway  # noqa: F401  (re-exported)

MUTABLE_SERVER = Path(__file__).parent / "fixtures" / "mutable_server.py"


def upstream_command(mutation: str) -> str:
    return f"env MUTATION={mutation} {sys.executable} {MUTABLE_SERVER}"


def set_mutation(mutation: str) -> None:
    """Later sessions spawn the mutated upstream — the rug pull, operator-triggered.
    Rewrites the live registry entry (item 35); tests run the app in-process."""
    app.state.policy_store.engine.policy.servers["default"].command = shlex.split(
        upstream_command(mutation)
    )


@pytest.fixture
async def drift_gateway(
    clean_audit: None,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[Gateway]:
    # These tests assert drift *classification* behavior; drop the clock-dependent
    # business-hours risk factor so an off-hours run doesn't push an unresolved
    # Low/Medium drift (drift_in_review, +15) over the challenge threshold.
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )
    keys = {"dev": secrets.token_urlsafe(32), "admin": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "dev",
                "api_key_hash": _key_hash(keys["dev"]),
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
            {
                "id": "admin",
                "api_key_hash": _key_hash(keys["admin"]),
                "admin": True,
                "allowed_servers": [],
            },
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, upstream_command("none"), keys) as gw:
        yield gw
