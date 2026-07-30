"""PortunusMCP operator CLI (ROADMAP item 42)."""

import argparse
import base64
import difflib
import hashlib
import json
import os
import secrets
import shlex
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO

from services import doctor, quickstart
from services.gateway.audit_export import verify_file

VERSION = "0.1.0"
JSON_LIMIT = 10 * 1024 * 1024
ERROR_LIMIT = 64 * 1024
MUTATIONS = {
    ("approvals", "approve"),
    ("baselines", "approve"),
    ("policy", "rollout"),
    ("policy", "rollback"),
    ("keys", "rotate-audit"),
}


class CLIError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class Client:
    def __init__(self, base_url: str, api_key: str, ca_file: str | None, timeout: float) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise CLIError("--url must not contain userinfo, a query, or a fragment")
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise CLIError("HTTPS is required except for loopback HTTP")
        if not parsed.netloc:
            raise CLIError("--url must include a host")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        context = ssl.create_default_context(cafile=ca_file)
        self.opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=context)
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        content_type: str | None = None,
        stream_to: Any = None,
    ) -> Any:
        headers = {"X-PortunusMCP-Key": self.api_key, "Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers, method=method
        )
        try:
            response = self.opener.open(request, timeout=self.timeout)
            if stream_to is not None:
                while chunk := response.read(64 * 1024):
                    stream_to.write(chunk)
                return None
            data = response.read(JSON_LIMIT + 1)
            if len(data) > JSON_LIMIT:
                raise CLIError("response exceeds 10 MiB")
            return json.loads(data) if data else {}
        except urllib.error.HTTPError as exc:
            data = exc.read(ERROR_LIMIT + 1)
            suffix = "…" if len(data) > ERROR_LIMIT else ""
            detail = data[:ERROR_LIMIT].decode("utf-8", "replace") + suffix
            try:
                parsed = json.loads(detail)
                detail = str(parsed.get("detail", parsed))
            except json.JSONDecodeError:
                pass
            raise CLIError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise CLIError(str(exc)) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="portunusmcp")
    parser.add_argument("--url", default=os.environ.get("PORTUNUSMCP_URL"))
    parser.add_argument("--ca-file", default=os.environ.get("PORTUNUSMCP_CA_FILE"))
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=os.environ.get("PORTUNUSMCP_TIMEOUT", "300"),
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    groups = parser.add_subparsers(dest="group", required=True)

    approvals = groups.add_parser("approvals").add_subparsers(dest="action", required=True)
    approvals.add_parser("list")
    show = approvals.add_parser("show")
    show.add_argument("id")
    approve = approvals.add_parser("approve")
    approve.add_argument("id")

    baselines = groups.add_parser("baselines").add_subparsers(dest="action", required=True)
    listing = baselines.add_parser("list")
    listing.add_argument("--kind", choices=("all", "drift", "suspicious"), default="all")
    show = baselines.add_parser("show")
    show.add_argument("server")
    show.add_argument("tool")
    approve = baselines.add_parser("approve")
    approve.add_argument("server")
    approve.add_argument("tool")

    decisions = groups.add_parser("decisions").add_subparsers(dest="action", required=True)
    get = decisions.add_parser("get")
    get.add_argument("seq", type=_positive_int)
    explain = decisions.add_parser("explain")
    explain.add_argument("request_file")

    policy = groups.add_parser("policy").add_subparsers(dest="action", required=True)
    policy.add_parser("status")
    policy.add_parser("revisions")
    validate = policy.add_parser("validate")
    validate.add_argument("file")
    simulate = policy.add_parser("simulate")
    simulate.add_argument("file")
    simulate.add_argument("--window", required=True)
    scaffold = policy.add_parser("scaffold")
    scaffold.add_argument("--from-audit", action="store_true", required=True)
    scaffold.add_argument("--window", required=True)
    scaffold.add_argument("--output", required=True)
    scaffold.add_argument("--force", action="store_true")
    compare = policy.add_parser("compare")
    compare.add_argument("old", type=_positive_int)
    compare.add_argument("new", type=_positive_int)
    compare.add_argument("--window", required=True)
    rollout = policy.add_parser("rollout")
    rollout.add_argument("file")
    rollback = policy.add_parser("rollback")
    rollback.add_argument("version", type=_positive_int)

    keys = groups.add_parser("keys").add_subparsers(dest="action", required=True)
    generate = keys.add_parser("generate")
    generate.add_argument("mode", choices=("bearer", "signed"))
    generate.add_argument("--totp", action="store_true")
    keys.add_parser("audit-status")
    keys.add_parser("rotate-audit")

    audit = groups.add_parser("audit").add_subparsers(dest="action", required=True)
    export = audit.add_parser("export")
    export.add_argument("--from-seq", type=_positive_int)
    export.add_argument("--to-seq", type=_positive_int)
    export.add_argument("--output", required=True)
    export.add_argument("--force", action="store_true")

    start = groups.add_parser("quickstart")
    start.add_argument("--upstream-image", required=True)
    start.add_argument("--allow-tool", required=True)
    start.add_argument("--arguments", required=True, type=quickstart.json_object)
    start.add_argument("--port", type=quickstart.port_number, default=8000)
    start.add_argument("--output-dir", default="./portunusmcp-quickstart")
    start.add_argument(
        "--command",
        nargs=argparse.REMAINDER,
        required=True,
        help="upstream argv; must be the final option",
    )
    diagnose = groups.add_parser("doctor")
    diagnose.add_argument("deployment_dir")
    diagnose.add_argument("--fix", action="store_true")
    return parser


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _read(path: str) -> bytes:
    return sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()


def _confirm(args: argparse.Namespace) -> None:
    if (args.group, args.action) not in MUTATIONS or args.yes:
        return
    if args.json:
        raise CLIError("mutating commands require --yes with --json")
    if input("Proceed? [y/N] ").strip().lower() not in {"y", "yes"}:
        raise CLIError("cancelled")


def _generate(args: argparse.Namespace) -> dict[str, Any]:
    if args.json:
        raise CLIError("keys generate does not support --json")
    result: dict[str, Any] = {"mode": args.mode}
    if args.mode == "bearer":
        key = base64.b64encode(secrets.token_bytes(32)).decode()
        result.update(
            api_key=key,
            api_key_hash=f"sha256:{hashlib.sha256(key.encode()).hexdigest()}",
        )
    else:
        result.update(
            key_id=f"kid_{secrets.token_hex(8)}",
            signing_secret=base64.b64encode(secrets.token_bytes(32)).decode(),
            signing_secret_env=f"PORTUNUSMCP_SIGNING_SECRET_{secrets.token_hex(4).upper()}",
        )
    if args.totp:
        result.update(
            totp_secret=base64.b32encode(secrets.token_bytes(20)).decode(),
            totp_secret_env=f"PORTUNUSMCP_TOTP_SECRET_{secrets.token_hex(4).upper()}",
        )
    return result


def _call(args: argparse.Namespace, client: Client) -> Any:
    group, action = args.group, args.action
    if group == "approvals":
        path = "/admin/approvals" + (f"/{_quote(args.id)}" if action != "list" else "")
        if action == "approve":
            path += "/approve"
        return client.request("POST" if action == "approve" else "GET", path)
    if group == "baselines":
        if action == "list":
            return client.request("GET", f"/admin/baselines/flagged?kind={args.kind}")
        path = f"/admin/baselines/{_quote(args.server)}/{_quote(args.tool)}"
        if action == "approve":
            path = f"/admin/tools/{_quote(args.server)}/{_quote(args.tool)}/approve"
        return client.request("POST" if action == "approve" else "GET", path)
    if group == "decisions":
        if action == "get":
            return client.request("GET", f"/admin/decisions/{args.seq}")
        return client.request(
            "POST",
            "/admin/decisions/explain",
            body=_read(args.request_file),
            content_type="application/json",
        )
    if group == "policy":
        if action == "status":
            return client.request("GET", "/admin/policy")
        if action == "revisions":
            return client.request("GET", "/admin/policy/revisions")
        if action in {"validate", "simulate", "rollout"}:
            path = {
                "validate": "/admin/policy/validate",
                "simulate": "/admin/policy/simulate-candidate",
                "rollout": "/admin/policy/rollout",
            }[action]
            if action == "simulate":
                path += "?" + urllib.parse.urlencode({"replay_window": args.window})
            return client.request(
                "POST", path, body=_read(args.file), content_type="application/yaml"
            )
        if action == "compare":
            body = json.dumps(
                {"compare_versions": [args.old, args.new], "replay_window": args.window}
            ).encode()
            return client.request(
                "POST", "/admin/policy/simulate", body=body, content_type="application/json"
            )
        return client.request("POST", f"/admin/policy/rollback/{args.version}")
    if group == "keys":
        if action == "audit-status":
            return client.request("GET", "/admin/keys/audit")
        return client.request("POST", "/admin/keys/audit/rotate")
    raise AssertionError


def _export(args: argparse.Namespace, client: Client) -> dict[str, Any]:
    query = {
        key: value
        for key, value in (("from_seq", args.from_seq), ("to_seq", args.to_seq))
        if value is not None
    }
    path = "/admin/audit/export"
    if query:
        path += "?" + urllib.parse.urlencode(query)

    def write(stream: BinaryIO) -> None:
        client.request("GET", path, stream_to=stream)

    count, anchored = _atomic_output(args.output, args.force, write, verify_file)
    return {"output": args.output, "rows": count, "genesis_anchored": anchored}


def _atomic_output(
    output_name: str,
    force: bool,
    write: Callable[[BinaryIO], Any],
    validate: Callable[[Path], Any] | None = None,
) -> Any:
    output = Path(output_name)
    if output.exists() and not force:
        raise CLIError(f"{output} already exists; pass --force to replace it")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            write(stream)
            stream.flush()
            os.fsync(stream.fileno())
        result = validate(temporary) if validate is not None else None
        temporary.chmod(0o600)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return result


def _scaffold(args: argparse.Namespace, client: Client) -> dict[str, Any]:
    output = Path(args.output)
    if output.exists() and not args.force:
        raise CLIError(f"{output} already exists; pass --force to replace it")
    response = client.request(
        "POST",
        "/admin/policy/scaffold",
        body=json.dumps({"source": "audit", "window": args.window}).encode(),
        content_type="application/json",
    )
    try:
        policy = response["policy"]
        metadata = response["metadata"]
        expected_hash = metadata["candidate"]["content_hash"]
        if not isinstance(policy, str) or not isinstance(metadata, dict):
            raise TypeError
    except (KeyError, TypeError):
        raise CLIError("gateway returned an invalid scaffold response") from None
    raw = policy.encode()
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise CLIError("generated policy hash does not match gateway metadata")

    def write(stream: BinaryIO) -> None:
        stream.write(raw)

    _atomic_output(args.output, args.force, write)
    return {"output": args.output, "metadata": metadata}


def _human(result: Any, args: argparse.Namespace) -> str:
    if args.group == "doctor":
        return doctor.human(result)
    if args.group == "quickstart":
        return quickstart.human(result)
    if args.group == "keys" and args.action == "generate":
        return "\n".join(f"{key}: {value}" for key, value in result.items())
    if args.group == "policy" and args.action == "scaffold":
        candidate = result["metadata"]["candidate"]
        return "\n".join(
            (
                f"Policy scaffold written to {result['output']}",
                (
                    f"Identities: {candidate['identity_count']}; "
                    f"grants: {candidate['grant_count']}; "
                    f"server-tools: {candidate['server_tool_count']}"
                ),
                f"SHA-256: {candidate['content_hash']}",
                f"Next: {shlex.join(['portunusmcp', 'policy', 'validate', result['output']])}",
            )
        )
    if args.group == "baselines" and args.action == "show":
        old = json.dumps(result["approved_schema"], indent=2, sort_keys=True).splitlines(True)
        if result["removed"]:
            new = ["<removed>\n"]
        else:
            new = json.dumps(
                result["observed_schema"] or result["approved_schema"], indent=2, sort_keys=True
            ).splitlines(True)
        diff = "".join(difflib.unified_diff(old, new, "approved", "observed"))
        metadata = json.dumps(
            {key: value for key, value in result.items() if "schema" not in key}, indent=2
        )
        return metadata + ("\n" + diff if diff else "\n(no schema difference)")
    return json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args: argparse.Namespace | None = None
    try:
        args = parser.parse_args(argv)
        if args.group == "doctor":
            result = doctor.run(args)
        elif args.group == "quickstart":
            result = quickstart.run(args)
        elif args.group == "keys" and args.action == "generate":
            result = _generate(args)
        else:
            if not args.url:
                raise CLIError("--url or PORTUNUSMCP_URL is required")
            api_key = os.environ.get("PORTUNUSMCP_ADMIN_KEY")
            if not api_key:
                raise CLIError("PORTUNUSMCP_ADMIN_KEY is required")
            client = Client(args.url, api_key, args.ca_file, args.timeout)
            _confirm(args)
            result = (
                _export(args, client)
                if args.group == "audit" and args.action == "export"
                else _scaffold(args, client)
                if args.group == "policy" and args.action == "scaffold"
                else _call(args, client)
            )
        print(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
            if args.json
            else _human(result, args)
        )
        if args.group == "doctor":
            return 0 if result["summary"]["healthy"] else 1
        return 0
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except quickstart.QuickstartUsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (CLIError, doctor.DoctorError, quickstart.QuickstartError, OSError, ValueError) as exc:
        if args is not None and args.json and args.group != "quickstart":
            print(json.dumps({"error": str(exc)}, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
