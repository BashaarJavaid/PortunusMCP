"""ROADMAP item 42 operator API: durable policy and audit-key lifecycle."""

from datetime import UTC, datetime
from pathlib import Path

import httpx
import yaml
from sqlalchemy import select

from services.gateway.audit_export import verify_file
from services.gateway.db import AuditLog, async_session
from services.gateway.main import app
from tests.integration.conftest import Gateway, policy_dict
from tests.integration.test_policy_scoping import connect


async def test_policy_validate_rollout_revisions_and_durable_rollback(
    gateway: Gateway,
) -> None:
    headers = {"X-PortunusMCP-Key": gateway.keys["agent-full"]}
    candidate = yaml.safe_dump(policy_dict(gateway.keys, version=2)).encode()
    async with httpx.AsyncClient() as client:
        assert (
            await client.post(
                f"{gateway.url}/admin/policy/validate",
                content=b"not: [yaml",
                headers={"Content-Type": "application/yaml"},
            )
        ).status_code == 401
        validated = await client.post(
            f"{gateway.url}/admin/policy/validate",
            content=candidate,
            headers={**headers, "Content-Type": "application/yaml"},
        )
        assert validated.status_code == 200
        assert validated.json()["version"] == 2

        window = datetime.now(UTC).strftime("%Y-%m-%d..%Y-%m-%d")
        simulated = await client.post(
            f"{gateway.url}/admin/policy/simulate-candidate",
            params={"replay_window": window},
            content=candidate,
            headers={**headers, "Content-Type": "application/yaml"},
        )
        assert simulated.status_code == 200

        rolled_out = await client.post(
            f"{gateway.url}/admin/policy/rollout",
            content=candidate,
            headers={**headers, "Content-Type": "application/yaml"},
        )
        assert rolled_out.status_code == 200
        assert rolled_out.json()["decision"]["policy_version"] == 2
        assert yaml.safe_load(gateway.policy_path.read_text())["version"] == 2

        revisions = await client.get(f"{gateway.url}/admin/policy/revisions", headers=headers)
        assert [item["state"] for item in revisions.json()["items"][:2]] == [
            "active",
            "inactive",
        ]

        rollback = await client.post(f"{gateway.url}/admin/policy/rollback/1", headers=headers)
        assert rollback.status_code == 200
        assert rollback.json()["decision"]["policy_version"] == 1
        assert yaml.safe_load(gateway.policy_path.read_text())["version"] == 1


async def test_rotation_handoff_and_export_verify(gateway: Gateway, tmp_path: Path) -> None:
    headers = {"X-PortunusMCP-Key": gateway.keys["agent-full"]}
    old_key_id = app.state.audit_writer.key_id
    async with httpx.AsyncClient() as client:
        denied = await client.post(
            f"{gateway.url}/admin/keys/audit/rotate",
            headers={"X-PortunusMCP-Key": gateway.keys["agent-readonly"]},
        )
        assert denied.status_code == 403
        rotated = await client.post(f"{gateway.url}/admin/keys/audit/rotate", headers=headers)
        assert rotated.status_code == 200
        result = rotated.json()
        new_key_id = result["metadata"]["new_key_id"]
        assert result["metadata"]["old_key_id"] == old_key_id
        assert new_key_id != old_key_id

        async with connect(gateway.url, gateway.keys["agent-full"]) as session:
            await session.list_tools()

        response = await client.get(f"{gateway.url}/admin/audit/export", headers=headers)
        assert response.status_code == 200
    export = tmp_path / "audit.ndjson"
    export.write_bytes(response.content)
    count, anchored = verify_file(export)
    assert count > 0 and anchored

    async with async_session() as session:
        rows = list((await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars())
    rotation = next(row for row in rows if row.event_type == "AUDIT_KEY_ROTATED")
    assert rotation.key_id == old_key_id
    assert rows[-1].key_id == new_key_id
    async with httpx.AsyncClient() as client:
        assert (await client.get(f"{gateway.url}/ready")).status_code == 200
