import argparse
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from services import cli, doctor, quickstart
from services.gateway import signing

IMAGE_ID = f"sha256:{'a' * 64}"


def _args(root: Path, **overrides: object) -> argparse.Namespace:
    values = {
        "deployment_dir": str(root),
        "fix": False,
        "yes": False,
        "json": False,
        "timeout": 10.0,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _quickstart(tmp_path: Path) -> quickstart.Generated:
    return quickstart._generate(
        tmp_path / "quickstart",
        IMAGE_ID,
        "echo",
        ["python", "-m", "server"],
        8765,
        "42",
    )


def test_discovers_only_explicit_production_or_quickstart(tmp_path: Path) -> None:
    generated = _quickstart(tmp_path)
    assert doctor._discover(str(generated.root)).kind == "quickstart"

    production = tmp_path / "production"
    production.mkdir()
    (production / "compose.prod.yml").touch()
    assert doctor._discover(str(production)).kind == "production"

    (production / "compose.quickstart.yml").touch()
    with pytest.raises(doctor.DoctorError, match="both production and quickstart"):
        doctor._discover(str(production))

    demo = tmp_path / "demo"
    demo.mkdir()
    (demo / "compose.demo.yml").touch()
    with pytest.raises(doctor.DoctorError, match="not demo"):
        doctor._discover(str(demo))


def test_env_parser_rejects_duplicates_and_atomic_update_preserves_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".env"
    path.write_text("# retained\nDOCKER_GID='41'\nNAME=value\n")
    path.chmod(0o600)
    values, duplicates = doctor._env_file(path)
    assert values == {"DOCKER_GID": "41", "NAME": "value"}
    assert duplicates == set()

    doctor._atomic_env_update(path, "DOCKER_GID", "42")
    assert path.read_text() == "# retained\nDOCKER_GID=42\nNAME=value\n"
    assert _mode(path) == 0o600

    path.write_text("DOCKER_GID=41\nDOCKER_GID=42\n")
    _, duplicates = doctor._env_file(path)
    assert duplicates == {"DOCKER_GID"}
    with pytest.raises(doctor.DoctorError, match="duplicate"):
        doctor._atomic_env_update(path, "DOCKER_GID", "43")


def test_cli_parser_and_exit_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    parsed = cli._parser().parse_args(["--json", "--yes", "doctor", str(tmp_path), "--fix"])
    assert parsed.group == "doctor"
    assert parsed.deployment_dir == str(tmp_path)
    assert parsed.fix is True

    result = {
        "deployment": {"kind": "quickstart", "root": str(tmp_path)},
        "findings": [],
        "summary": {
            "PASS": 0,
            "INFO": 0,
            "WARN": 0,
            "ERROR": 1,
            "FIXED": 0,
            "healthy": False,
            "restart_required": False,
        },
        "commands": {"recreate": ""},
    }
    monkeypatch.setattr(doctor, "run", lambda _args: result)
    assert cli.main(["--json", "doctor", str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().out)["summary"]["healthy"] is False


def test_fix_keeps_history_and_requires_recreate_for_existing_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    generated = _quickstart(tmp_path)
    applied: list[str] = []

    def fake_scan(
        self: doctor._Scan,
    ) -> tuple[list[dict[str, object]], list[doctor.Repair], bool]:
        self.values = {"QUICKSTART_NAMESPACE": "quick-test"}
        if self.offer_repairs:
            return (
                [
                    doctor._finding(
                        "docker.socket_gid",
                        "ERROR",
                        "wrong",
                        fixable=True,
                        action="repair",
                    )
                ],
                [
                    doctor.Repair(
                        "docker.socket_gid",
                        "write the detected GID",
                        lambda: applied.append("gid"),
                        True,
                    )
                ],
                True,
            )
        return [doctor._finding("docker.socket_gid", "PASS", "correct")], [], True

    monkeypatch.setattr(doctor._Scan, "run", fake_scan)
    result = doctor.run(_args(generated.root, fix=True, yes=True, json=True))
    assert applied == ["gid"]
    assert [item["status"] for item in result["findings"]] == ["FIXED", "PASS", "ERROR"]
    assert result["summary"]["healthy"] is False
    assert result["summary"]["restart_required"] is True
    assert "--pull never" in result["commands"]["recreate"]
    assert "--force-recreate gateway verifier" in result["commands"]["recreate"]


def test_json_fix_requires_yes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    generated = _quickstart(tmp_path)

    def fake_scan(
        self: doctor._Scan,
    ) -> tuple[list[dict[str, object]], list[doctor.Repair], bool]:
        return (
            [doctor._finding("filesystem.policy", "ERROR", "wrong")],
            [doctor.Repair("filesystem.policy", "chmod", lambda: None)],
            False,
        )

    monkeypatch.setattr(doctor._Scan, "run", fake_scan)
    with pytest.raises(doctor.DoctorError, match="requires --yes"):
        doctor.run(_args(generated.root, fix=True, json=True))


def test_audit_key_repairs_are_safe_and_complete(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    root.mkdir(mode=0o700)
    layout = doctor.Layout("quickstart", root, root / ".env.quickstart", root / "compose.yml")
    audit_dir = root / "secrets"
    public_dir = audit_dir / "public"
    audit_dir.mkdir(mode=0o700)
    public_dir.mkdir(mode=0o700)
    owner = (os.getuid(), os.getgid())

    pristine = doctor._Scan(layout, 10, repairs=True)
    pristine.audit_keys(audit_dir, public_dir, owner)
    assert [repair.finding_id for repair in pristine.repairs] == ["audit.private_key"]
    pristine.repairs[0].apply()
    private_path = audit_dir / "audit_signing_key.pem"
    assert _mode(private_path) == 0o600
    assert len(list(public_dir.glob("*.pub.pem"))) == 1

    active = next(public_dir.glob("*.pub.pem"))
    active.unlink()
    missing_archive = doctor._Scan(layout, 10, repairs=True)
    missing_archive.audit_keys(audit_dir, public_dir, owner)
    repair = next(
        item for item in missing_archive.repairs if item.finding_id == "audit.public_key.active"
    )
    repair.apply()
    assert active.exists()

    private_path.unlink()
    lost = doctor._Scan(layout, 10, repairs=True)
    lost.audit_keys(audit_dir, public_dir, owner)
    assert not lost.repairs
    assert any(
        item["id"] == "audit.private_key" and "historical public keys" in item["message"]
        for item in lost.findings
    )


def test_audit_keyring_rejects_wrong_fingerprint_and_symlink(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    root.mkdir(mode=0o700)
    audit_dir = root / "secrets"
    public_dir = audit_dir / "public"
    audit_dir.mkdir(mode=0o700)
    public_dir.mkdir(mode=0o700)
    private_key = signing.generate_private_key()
    private_path = audit_dir / "audit_signing_key.pem"
    private_path.write_bytes(signing.private_pem(private_key))
    private_path.chmod(0o600)
    wrong = public_dir / f"{'0' * 64}.pub.pem"
    wrong.write_bytes(signing.public_pem(private_key.public_key()))
    wrong.chmod(0o444)
    symlink = public_dir / f"{'1' * 64}.pub.pem"
    symlink.symlink_to(wrong)
    layout = doctor.Layout("quickstart", root, root / ".env", root / "compose.yml")

    scan = doctor._Scan(layout, 10, repairs=True)
    scan.audit_keys(audit_dir, public_dir, (os.getuid(), os.getgid()))
    errors = [item["message"] for item in scan.findings if item["status"] == "ERROR"]
    assert any("filename does not match" in message for message in errors)
    assert any("is a symlink" in message for message in errors)
    assert any(repair.finding_id == "audit.public_key.active" for repair in scan.repairs)


def test_policy_uses_rendered_gateway_environment_and_redacts_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    generated = _quickstart(tmp_path)
    policy_path = generated.root / "config" / "policy.yaml"
    policy = yaml.safe_load(policy_path.read_text())
    policy["servers"]["default"]["env"] = {"TOKEN": "PORTUNUSMCP_UPSTREAM_TOKEN"}
    policy["identities"][1].update(
        auth_mode="signed",
        api_key_hash=None,
        key_id="kid_test",
        signing_secret_env="PORTUNUSMCP_SIGNING_SECRET",
    )
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False))
    policy_path.chmod(0o600)
    secret = "do-not-print-this"
    scan = doctor._Scan(
        doctor.Layout(
            "quickstart",
            generated.root,
            generated.env_file,
            generated.compose_file,
        ),
        10,
        repairs=False,
    )
    scan.namespace = generated.namespace
    scan.rendered = {
        "services": {
            "gateway": {
                "environment": {
                    "PORTUNUSMCP_UPSTREAM_TOKEN": secret,
                    "PORTUNUSMCP_SIGNING_SECRET": secret,
                }
            }
        }
    }
    monkeypatch.setattr(
        doctor,
        "_command",
        lambda command, _timeout, check=True: subprocess.CompletedProcess(command, 0, "[]", ""),
    )
    scan.policy_and_runtime(
        generated.root / "config",
        generated.env_file,
        (os.getuid(), os.getgid()),
    )
    assert any(
        item["id"] == "policy.validation" and item["status"] == "PASS" for item in scan.findings
    )
    assert secret not in json.dumps(scan.findings)

    del scan.rendered["services"]["gateway"]["environment"]["PORTUNUSMCP_SIGNING_SECRET"]
    missing = doctor._Scan(scan.layout, 10, repairs=False)
    missing.namespace = generated.namespace
    missing.rendered = scan.rendered
    missing.policy_and_runtime(
        generated.root / "config",
        generated.env_file,
        (os.getuid(), os.getgid()),
    )
    output = json.dumps(missing.findings)
    assert "PORTUNUSMCP_SIGNING_SECRET" in output
    assert secret not in output


def test_namespace_gid_image_volume_and_network_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    generated = _quickstart(tmp_path)
    scan = doctor._Scan(
        doctor.Layout(
            "quickstart",
            generated.root,
            generated.env_file,
            generated.compose_file,
        ),
        10,
        repairs=True,
    )
    scan.values, _ = doctor._env_file(generated.env_file)
    scan.values["DOCKER_GID"] = "41"

    def fake_command(
        command: list[str], _timeout: float, *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        output = "42\n" if command[1] == "run" else "[]"
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(doctor, "_command", fake_command)
    scan.namespace_and_gid(True)
    assert any(repair.finding_id == "docker.socket_gid" for repair in scan.repairs)

    class AvailablePort:
        def __enter__(self) -> "AvailablePort":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def bind(self, _address: object) -> None:
            return None

    monkeypatch.setattr(doctor.socket, "socket", lambda *_args: AvailablePort())
    port = 8765
    scan.rendered = {
        "services": {"gateway": {"ports": [{"host_ip": "127.0.0.1", "published": str(port)}]}}
    }
    scan.values["FORWARDED_ALLOW_IPS"] = "*"
    scan.network()
    assert any(
        item["id"] == "network.forwarded_allow_ips" and item["status"] == "PASS"
        for item in scan.findings
    )
    assert any(
        item["id"] == "runtime.readiness" and item["status"] == "INFO" for item in scan.findings
    )

    scan.values["FORWARDED_ALLOW_IPS"] = "not-an-ip"
    scan.network()
    assert any(
        item["id"] == "network.forwarded_allow_ips" and item["status"] == "ERROR"
        for item in scan.findings
    )


def test_docker_subprocess_environment_does_not_inherit_deployment_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_CONTEXT", "test")
    monkeypatch.setenv("PORTUNUSMCP_SIGNING_SECRET", "must-not-leak")
    environment = doctor._docker_environment()
    assert environment["DOCKER_CONTEXT"] == "test"
    assert "PORTUNUSMCP_SIGNING_SECRET" not in environment
