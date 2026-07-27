import hashlib
import json
import tarfile
from pathlib import Path

import pytest

from scripts.build_release_bundle import IMAGES, build_bundle


def test_release_bundle_is_deterministic_and_self_verifying(tmp_path: Path) -> None:
    artifact = tmp_path / "portunusmcp-0.1.0-py3-none-any.whl"
    artifact.write_bytes(b"wheel")
    digests = {name: f"sha256:{index:064x}" for index, name in enumerate(IMAGES, 1)}
    arguments = {
        "version": "0.1.0",
        "tag": "v0.1.0",
        "commit": "a" * 40,
        "alembic_head": "0007",
        "digests": digests,
        "python_artifacts": [artifact],
    }
    first = build_bundle(output_dir=tmp_path / "one", **arguments)
    second = build_bundle(output_dir=tmp_path / "two", **arguments)
    assert first.read_bytes() == second.read_bytes()

    extracted = tmp_path / "extracted"
    with tarfile.open(first) as archive:
        members = archive.getmembers()
        assert all(member.uid == member.gid == member.mtime == 0 for member in members)
        assert all(member.mode == (0o755 if member.isdir() else 0o644) for member in members)
        archive.extractall(extracted, filter="data")

    root = extracted / "portunusmcp-v0.1.0"
    manifest = json.loads((root / "release.json").read_text())
    assert manifest["manifest_version"] == 1
    assert manifest["alembic_head"] == "0007"
    assert manifest["images"]["gateway"]["digest"] == digests["gateway"]
    assert manifest["python_artifacts"][artifact.name] == (
        f"sha256:{hashlib.sha256(b'wheel').hexdigest()}"
    )
    env = (root / ".env.prod.example").read_text()
    assert "REPLACE_WITH_64_HEX_CHARACTERS" not in env
    assert "monitoring/prometheus.yml" in manifest["files"]

    for line in (root / "SHA256SUMS").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected

    with pytest.raises(ValueError, match="gateway digest"):
        build_bundle(
            output_dir=tmp_path / "invalid",
            **{**arguments, "digests": {**digests, "gateway": "latest"}},
        )
