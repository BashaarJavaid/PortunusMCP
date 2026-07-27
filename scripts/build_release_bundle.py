"""Build the deterministic v0.1.0 production release bundle."""

import argparse
import gzip
import hashlib
import json
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
PAYLOAD = (
    "compose.prod.yml",
    ".env.prod.gateway.example",
    "README.md",
    "LICENSE",
    "COMPATIBILITY.md",
    "UPGRADING.md",
)
IMAGES = {
    "gateway": "ghcr.io/bashaarjavaid/portunusmcp",
    "postgres": "postgres:16",
    "redis": "redis:7",
    "prometheus": "prom/prometheus:v3.4.1",
    "grafana": "grafana/grafana:12.0.2",
}
PLATFORMS = ["linux/amd64", "linux/arm64"]
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate(version: str, tag: str, commit: str, digests: dict[str, str]) -> None:
    if not VERSION_RE.fullmatch(version) or tag != f"v{version}":
        raise ValueError("version must be X.Y.Z and tag must be vX.Y.Z")
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("commit must be a 40-character lowercase Git SHA")
    for name, digest in digests.items():
        if not DIGEST_RE.fullmatch(digest):
            raise ValueError(f"{name} digest must be sha256 followed by 64 lowercase hex digits")


def _write_payload(destination: Path, digests: dict[str, str]) -> list[Path]:
    paths: list[Path] = []
    for relative in PAYLOAD:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
        paths.append(target)
    env = (ROOT / ".env.prod.example").read_text()
    for name in IMAGES:
        placeholder = f"{name.upper()}_IMAGE_DIGEST=sha256:REPLACE_WITH_64_HEX_CHARACTERS"
        replacement = f"{name.upper()}_IMAGE_DIGEST={digests[name]}"
        if env.count(placeholder) != 1:
            raise ValueError(f"expected one {placeholder} placeholder")
        env = env.replace(placeholder, replacement)
    env_path = destination / ".env.prod.example"
    env_path.write_text(env)
    paths.append(env_path)
    for source in sorted((ROOT / "monitoring").rglob("*")):
        if source.is_file():
            target = destination / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            paths.append(target)
    return sorted(paths)


def _manifest(
    *,
    version: str,
    tag: str,
    commit: str,
    alembic_head: str,
    digests: dict[str, str],
    payload: list[Path],
    root: Path,
    python_artifacts: list[Path],
) -> dict[str, Any]:
    return {
        "manifest_version": 1,
        "version": version,
        "tag": tag,
        "commit": commit,
        "alembic_head": alembic_head,
        "images": {
            name: {
                "reference": f"{reference}@{digests[name]}",
                "digest": digests[name],
                "platforms": PLATFORMS,
            }
            for name, reference in IMAGES.items()
        },
        "python_artifacts": {
            artifact.name: f"sha256:{_hash(artifact)}" for artifact in sorted(python_artifacts)
        },
        "compatibility": {
            "python": ">=3.12,<3.13",
            "docker_engine": "29.x",
            "docker_compose": "5.x",
            "postgresql": "16.x",
            "redis": "7.x",
            "mcp_sdk": "1.28.1",
            "mcp_protocol": "2025-11-25",
            "platforms": PLATFORMS,
        },
        "files": {str(path.relative_to(root)): f"sha256:{_hash(path)}" for path in sorted(payload)},
    }


def _archive(source: Path, output: Path, root_name: str) -> None:
    with output.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                directories = [source, *(path for path in source.rglob("*") if path.is_dir())]
                files = [path for path in source.rglob("*") if path.is_file()]
                for path in sorted([*directories, *files]):
                    relative = path.relative_to(source)
                    name = root_name if relative == Path(".") else f"{root_name}/{relative}"
                    info = archive.gettarinfo(str(path), arcname=name)
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    info.mode = 0o755 if path.is_dir() else 0o644
                    if path.is_file():
                        with path.open("rb") as stream:
                            archive.addfile(info, stream)
                    else:
                        archive.addfile(info)


def build_bundle(
    *,
    version: str,
    tag: str,
    commit: str,
    alembic_head: str,
    digests: dict[str, str],
    python_artifacts: list[Path],
    output_dir: Path,
) -> Path:
    _validate(version, tag, commit, digests)
    if set(digests) != set(IMAGES):
        raise ValueError(f"digests must name exactly: {', '.join(IMAGES)}")
    if not python_artifacts or any(not path.is_file() for path in python_artifacts):
        raise ValueError("python artifacts must be existing files")
    root_name = f"portunusmcp-v{version}"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{root_name}-production.tar.gz"
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / root_name
        root.mkdir()
        payload = _write_payload(root, digests)
        manifest_path = root / "release.json"
        manifest_path.write_text(
            json.dumps(
                _manifest(
                    version=version,
                    tag=tag,
                    commit=commit,
                    alembic_head=alembic_head,
                    digests=digests,
                    payload=payload,
                    root=root,
                    python_artifacts=python_artifacts,
                ),
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        checksums = root / "SHA256SUMS"
        checksum_paths = sorted([*payload, manifest_path])
        checksums.write_text(
            "".join(f"{_hash(path)}  {path.relative_to(root)}\n" for path in checksum_paths)
        )
        _archive(root, output, root_name)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--alembic-head", required=True)
    for name in IMAGES:
        parser.add_argument(f"--{name}-digest", required=True)
    parser.add_argument("--python-artifact", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()
    digests = {name: getattr(args, f"{name}_digest") for name in IMAGES}
    print(
        build_bundle(
            version=args.version,
            tag=args.tag,
            commit=args.commit,
            alembic_head=args.alembic_head,
            digests=digests,
            python_artifacts=args.python_artifact,
            output_dir=args.output_dir,
        )
    )


if __name__ == "__main__":
    main()
