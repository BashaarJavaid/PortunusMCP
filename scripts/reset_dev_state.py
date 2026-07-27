"""Reset local dev/demo state (ROADMAP item 38). Dev-only and destructive: wipes
the audit chain, drift baselines, approvals, policy version history, the Redis
schema/risk/challenge/rate keys, and (from the CLI) the policy revision snapshots.

This exists because item 19's fail-closed activation checks are *supposed* to
refuse a policy version that was already recorded with different content — which
is exactly what leftover demo state looks like to a fresh demo-stack startup.
The gateway's startup error names this script; running it is the remedy. Nothing
here weakens the checks themselves.

The demo (scripts/run_demo.py), the benchmarks (tests/benchmarks/run.py), and the
integration suite's clean_audit fixture all call reset_dev_state() rather than
re-implementing it; the test callers pass clear_snapshots=False because their
revisions dir is patched to a tmp path only *after* the reset runs.

Run:
    python scripts/reset_dev_state.py          # confirms interactively
    python scripts/reset_dev_state.py --yes    # no prompt (scripts, docker)
    docker compose --env-file .env.demo -f compose.demo.yml run --rm gateway \
      python scripts/reset_dev_state.py --yes
"""

import asyncio
import sys
from pathlib import Path

import redis.asyncio as aioredis
from sqlalchemy import text

from services.gateway.audit_log import POINTER_KEY
from services.gateway.config import settings
from services.gateway.db import Base, engine


class ResetError(Exception):
    """A reset that could not run; the message carries the remedy."""


async def reset_dev_state(clear_snapshots: bool = True) -> None:
    """Wipe dev state in Redis and Postgres (and, when clear_snapshots, the
    policy revision snapshots). Raises ResetError when a service is unreachable."""
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    try:
        await redis_client.ping()
        await redis_client.delete(POINTER_KEY)
        for pattern in ("schema:*", "risk:*", "challenge:*", "rate:*"):
            keys = await redis_client.keys(pattern)
            if keys:
                await redis_client.delete(*keys)
    except Exception as exc:
        raise ResetError(
            "redis not reachable — run: docker compose --env-file .env.demo"
            " -f compose.demo.yml up -d redis"
        ) from exc
    finally:
        await redis_client.aclose()
    try:
        async with engine.begin() as conn:
            # Idempotent on an existing schema; makes a brand-new dev DB work too.
            await conn.run_sync(Base.metadata.create_all)
            await conn.execute(text("TRUNCATE audit_log RESTART IDENTITY"))
            await conn.execute(text("TRUNCATE tool_baselines"))
            await conn.execute(text("TRUNCATE audit_verifier_checkpoint"))
            await conn.execute(text("TRUNCATE approvals"))
            await conn.execute(text("TRUNCATE policy_versions"))
    except Exception as exc:
        raise ResetError(
            "postgres not reachable — run: docker compose --env-file .env.demo"
            " -f compose.demo.yml up -d postgres"
        ) from exc
    if clear_snapshots:
        # Leftover snapshots trip item 19's append-only check even after the
        # policy_versions truncate; the glob leaves .gitkeep alone.
        for snapshot in Path(settings.policy_revisions_dir).glob("v*.yaml"):
            snapshot.unlink()


def main() -> None:
    print("This wipes the LOCAL DEV audit chain, baselines, approvals, policy history,")
    print(f"and revision snapshots under {settings.policy_revisions_dir!r}.")
    print(f"  postgres: {settings.database_url}")
    print(f"  redis:    {settings.redis_url}")
    if "--yes" not in sys.argv[1:]:
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            sys.exit("aborted; nothing was changed")
    try:
        asyncio.run(reset_dev_state())
    except ResetError as exc:
        sys.exit(str(exc))
    print("dev state reset — the gateway will start fresh on the next demo-stack startup")


if __name__ == "__main__":
    main()
