"""Audit verifier daemon (ARCHITECTURE.md §4.8, ROADMAP item 11): incremental
chain + signature verification on a schedule, resuming from last_verified_seq.

Runs as a sidecar container (see the Compose files) or under cron with a single
pass via --once. Needs only the PUBLIC key — the private key stays with the gateway.

Usage:
    [DATABASE_URL=...] [VERIFY_INTERVAL_SECONDS=60] python scripts/audit_verifier_daemon.py [--once]
"""

import asyncio
import os
import sys
from pathlib import Path

import structlog
from prometheus_client import start_http_server

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.gateway import logging_config  # noqa: E402
from services.gateway.audit_keys import AuditKeyStore  # noqa: E402
from services.gateway.audit_verifier import verify_increment  # noqa: E402
from services.gateway.config import settings  # noqa: E402
from services.gateway.db import async_session, engine  # noqa: E402

logger = structlog.get_logger("audit_verifier_daemon")


async def main() -> int:
    key_store = AuditKeyStore(settings.signing_key_file, settings.signing_public_keys_dir)
    interval = int(os.environ.get("VERIFY_INTERVAL_SECONDS", "60"))
    once = "--once" in sys.argv
    if not once:
        # §7 failure counter scrape point (item 25); internal-only, like the gateway's.
        start_http_server(settings.metrics_port, settings.metrics_host)
    try:
        while True:
            verified, failure = await verify_increment(async_session, key_store)
            # Heartbeat: a silent daemon is indistinguishable from a dead one (§5 table).
            logger.info("pass_complete", verified_rows=verified, failure=failure)
            if once:
                return 1 if failure is not None else 0
            await asyncio.sleep(interval)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    logging_config.configure()
    sys.exit(asyncio.run(main()))
