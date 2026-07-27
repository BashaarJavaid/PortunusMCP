from pathlib import Path

from services.gateway import signing
from services.gateway.audit_keys import AuditKeyStore
from services.gateway.policy_operations import PolicyOperationStore


class _Result:
    def __init__(self, value: int | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> int | None:
        return self.value


class _Session:
    def __init__(self, value: int | None) -> None:
        self.value = value

    async def __aenter__(self) -> "_Session":
        return self

    async def __aexit__(self, *_args: object) -> None:
        pass

    async def execute(self, _statement: object) -> _Result:
        return _Result(self.value)


class _SessionFactory:
    def __init__(self, value: int | None) -> None:
        self.value = value

    def __call__(self) -> _Session:
        return _Session(self.value)


async def test_policy_journal_discards_before_and_completes_after_handoff(
    tmp_path: Path,
) -> None:
    active = tmp_path / "policy.yaml"
    active.write_bytes(b"version: 1\n")
    store = PolicyOperationStore(str(active))
    store.initialize()
    operation = store.prepare(
        b"version: 2\n",
        kind="api",
        activated_by="admin",
        old_version=1,
        new_version=2,
    )
    await store.recover(_SessionFactory(None))  # type: ignore[arg-type]
    assert active.read_bytes() == b"version: 1\n"
    assert store.read_journal() is None

    operation = store.prepare(
        b"version: 2\n",
        kind="api",
        activated_by="admin",
        old_version=1,
        new_version=2,
    )
    store.mark_handoff(operation, 7)
    await store.recover(_SessionFactory(7))  # type: ignore[arg-type]
    assert active.read_bytes() == b"version: 2\n"
    assert store.read_journal() is None


async def test_key_journal_discards_before_and_completes_after_handoff(
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "audit_signing_key.pem"
    private_path.write_bytes(signing.private_pem(signing.generate_private_key()))
    store = AuditKeyStore(str(private_path), str(tmp_path / "public"))
    _, original_id = store.initialize()

    rotation, _ = store.prepare("admin")
    unused_id = rotation.new_key_id
    await store.recover(_SessionFactory(None))  # type: ignore[arg-type]
    _, active_id = store.initialize()
    assert active_id == original_id
    assert store.public_path(unused_id).exists()

    rotation, _ = store.prepare("admin")
    store.mark_handoff(rotation, 8)
    _, active_id = await store.recover(_SessionFactory(8))  # type: ignore[arg-type]
    assert active_id == rotation.new_key_id
    assert store.public_count() == 3
    assert store.read_journal() is None
