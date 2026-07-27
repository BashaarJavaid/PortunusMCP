"""Walk and verify the audit hash chain (full-scan operator tool).

Recomputes H_t = SHA256(H_(t-1) || canonical_json(payload_t)) for every row in seq
order, checking both linkage (prev_hash) and content (curr_hash), plus each row's
ECDSA signature when the public key file exists (item 11). Exits 1 at the first
break. The scheduled incremental verifier is scripts/audit_verifier_daemon.py.

Also the home of the policy revision diff tooling (§4.8, item 19): --diff-policy
compares two snapshots from policies/revisions/ (not the live POLICY_FILE) as a
terminal unified diff, or with --html as a standalone side-by-side page via stdlib
difflib.HtmlDiff. Chain verification remains the default when no flags are given.

Usage: [DATABASE_URL=...] python scripts/verify_audit_chain.py
       python scripts/verify_audit_chain.py --diff-policy v3 v4 [--html]
"""

import argparse
import asyncio
import difflib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select  # noqa: E402

from services.gateway.audit_export import verify_file  # noqa: E402
from services.gateway.audit_keys import AuditKeyStore  # noqa: E402
from services.gateway.audit_log import GENESIS_HASH  # noqa: E402
from services.gateway.audit_verification import AuditRecord, verify_record  # noqa: E402
from services.gateway.config import settings  # noqa: E402
from services.gateway.db import AuditLog, async_session, engine  # noqa: E402
from services.gateway.policy_versions import snapshot_path  # noqa: E402


async def verify() -> int:
    key_store = AuditKeyStore(settings.signing_key_file, settings.signing_public_keys_dir)
    prev_hash = GENESIS_HASH
    count = 0
    async with async_session() as session:
        rows = await session.stream_scalars(select(AuditLog).order_by(AuditLog.seq))
        async for row in rows:
            try:
                prev_hash = verify_record(
                    AuditRecord.from_row(row), prev_hash, key_store.load_public
                )
            except ValueError as exc:
                print(exc)
                return 1
            count += 1
    print(f"chain OK ({count} rows)")
    return 0


def diff_policy(old: str, new: str, html: bool) -> int:
    """Diff two revision snapshots ("v3" or bare "3"); no database needed."""
    labels, lines = [], []
    for arg in (old, new):
        version = arg.removeprefix("v")
        if not version.isdigit():
            print(f"not a policy version: {arg!r} (expected e.g. v3)")
            return 1
        path = snapshot_path(int(version))
        if not path.exists():
            print(f"no revision snapshot at {path}")
            return 1
        labels.append(f"v{version}")
        lines.append(path.read_text().splitlines(keepends=True))
    if html:
        out = Path(f"policy-diff-{labels[0]}-{labels[1]}.html")
        out.write_text(
            difflib.HtmlDiff().make_file(lines[0], lines[1], labels[0], labels[1], context=True)
        )
        print(f"wrote {out}")
    else:
        sys.stdout.writelines(difflib.unified_diff(lines[0], lines[1], labels[0], labels[1]))
    return 0


async def main() -> int:
    try:
        return await verify()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diff-policy", nargs=2, metavar=("OLD", "NEW"))
    parser.add_argument("--html", action="store_true", help="side-by-side HTML diff page")
    parser.add_argument("--export", metavar="FILE", help="verify an exported NDJSON chain")
    args = parser.parse_args()
    if args.export:
        if args.diff_policy or args.html:
            parser.error("--export cannot be combined with policy diff flags")
        try:
            count, anchored = verify_file(args.export)
        except ValueError as exc:
            print(exc)
            sys.exit(1)
        qualifier = "genesis anchored" if anchored else "prefix omitted/unattested"
        print(f"export OK ({count} rows, {qualifier})")
        sys.exit(0)
    if args.diff_policy:
        sys.exit(diff_policy(*args.diff_policy, html=args.html))
    if args.html:
        parser.error("--html requires --diff-policy")
    sys.exit(asyncio.run(main()))
