"""Performance benchmark harness (ROADMAP items 12 + 39, ARCHITECTURE.md §9).

Measures tools/call latency directly against sample_target/benchmark_server.py (stdio)
vs. through the full gateway pipeline and a per-session Docker container, plus
container initialization, concurrent-session p95/memory, and tools/list payload-size
reduction. The Risk Engine runs in the pipeline but is neutralized (see main()):
§9 measures pipeline latency, not risk verdicts.

Documented choices (the §9 method leaves these open):
- timing is time.perf_counter() around MCP client SDK calls, identical on both paths;
- one in-process gateway (tests/integration/conftest.running_gateway) serves every
  scenario; its upstream sessions use the real Docker runtime;
- "cold schema cache" = Redis DEL of the schema key before each timed call, forcing
  the interceptor's transparent upstream tools/list re-fetch + drift check per call.

Run (postgres + redis must be reachable; wipes the dev audit chain like the tests do):
    docker compose up -d postgres redis
    docker build -t portunusmcp:dev .
    export UPSTREAM_RUNTIME_NAMESPACE=portunusmcp-benchmark
    .venv/bin/python -m tests.benchmarks.run [N]   # N = calls per scenario, default 1000
"""

import asyncio
import functools
import json
import logging
import os
import platform
import re
import resource
import secrets
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx
import redis.asyncio as aioredis
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import ListToolsResult

from scripts.reset_dev_state import ResetError, reset_dev_state
from services.gateway.config import settings
from services.gateway.schema_cache import SchemaCache
from tests.integration.conftest import (
    Gateway,
    _key_hash,
    running_gateway,
)

BENCHMARK_SERVER = Path(__file__).parents[2] / "sample_target" / "benchmark_server.py"
REPORTS_DIR = Path(__file__).parent / "reports"
CONCURRENCY_LEVELS = (10, 50, 100)
CALLS_PER_SESSION = 20
WARMUP_CALLS = 20
WARM_CONTAINER_LAUNCHES = 20
UPSTREAM_IMAGE = "portunusmcp:dev"


def bench_policy(keys: dict[str, str]) -> dict:
    """Same shape as the item-8 demo: pruned developer, unpruned admin."""
    return {
        "version": 1,
        "servers": {
            "default": {
                "image": UPSTREAM_IMAGE,
                "command": ["python", "sample_target/benchmark_server.py"],
            }
        },
        "identities": [
            {
                "id": "developer",
                "api_key_hash": _key_hash(keys["developer"]),
                "allowed_servers": [
                    {"server_id": "default", "allowed_tools": ["read_file", "list_issues"]}
                ],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }


async def preflight_clean() -> None:
    """Same reset as the integration suite's clean_audit fixture (the shared
    item-38 function), but exit with a remedy instead of pytest.skip. Snapshots
    stay untouched — running_gateway patches the revisions dir to a tmp path."""
    try:
        await reset_dev_state(clear_snapshots=False)
    except ResetError as exc:
        sys.exit(str(exc))


@asynccontextmanager
async def gateway_session(gw: Gateway, identity: str) -> AsyncIterator[ClientSession]:
    """The integration suite's connect(), but with a long timeout: 100 concurrent
    initializes each launch an upstream container and exceed httpx's 5s default."""
    async with httpx.AsyncClient(
        headers={"X-PortunusMCP-Key": gw.keys[identity]},
        follow_redirects=True,
        timeout=httpx.Timeout(300.0),
    ) as http_client:
        async with streamable_http_client(f"{gw.url}/mcp/default", http_client=http_client) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


@asynccontextmanager
async def direct_session() -> AsyncIterator[ClientSession]:
    """Baseline: MCP client straight at the benchmark server, no gateway."""
    params = StdioServerParameters(command=sys.executable, args=[str(BENCHMARK_SERVER)])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def timed_calls(
    call: Callable[[], Awaitable[object]],
    n: int,
    before_each: Callable[[], Awaitable[object]] | None = None,
) -> list[float]:
    """n sequential round trips; per-call latency in ms. before_each runs untimed."""
    latencies = []
    for _ in range(n):
        if before_each is not None:
            await before_each()
        start = time.perf_counter()
        await call()
        latencies.append((time.perf_counter() - start) * 1000)
    return latencies


def dist(samples: list[float]) -> dict[str, float]:
    cuts = statistics.quantiles(samples, n=100)
    return {
        "mean": statistics.fmean(samples),
        "p50": cuts[49],
        "p95": cuts[94],
        "p99": cuts[98],
    }


def fmt_dist(d: dict[str, float]) -> str:
    return " / ".join(f"{d[k]:.2f}" for k in ("mean", "p50", "p95", "p99")) + " ms"


async def bench_single_call(gw: Gateway, n: int) -> dict[str, dict[str, float]]:
    """Scenarios 1+2: N sequential tools/call round trips, direct vs gateway, then
    gateway again with the schema cache blown away before every call."""
    async with direct_session() as session:
        call = functools.partial(session.call_tool, "read_file", {"path": "bench.txt"})
        await timed_calls(call, WARMUP_CALLS)
        direct = dist(await timed_calls(call, n))

    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    cache = SchemaCache(redis_client)
    try:
        async with gateway_session(gw, "developer") as session:
            call = functools.partial(session.call_tool, "read_file", {"path": "bench.txt"})
            await timed_calls(call, WARMUP_CALLS)
            gateway = dist(await timed_calls(call, n))
            cold = dist(await timed_calls(call, n, before_each=lambda: cache.invalidate("default")))
    finally:
        await redis_client.aclose()
    return {"direct": direct, "gateway_cached": gateway, "gateway_cold": cold}


async def bench_container_initialization(gw: Gateway) -> dict[str, object]:
    async def once() -> float:
        start = time.perf_counter()
        async with gateway_session(gw, "developer"):
            elapsed = (time.perf_counter() - start) * 1000
            await asyncio.sleep(0.05)  # let initialized notification settle before DELETE
            return elapsed

    first = await once()
    warm = [await once() for _ in range(WARM_CONTAINER_LAUNCHES)]
    return {"first_ms": first, "warm": dist(warm)}


def _memory_mib(value: str) -> float:
    match = re.fullmatch(r"\s*([\d.]+)(B|KiB|MiB|GiB)\s*", value)
    if match is None:
        raise ValueError(f"unexpected docker memory value: {value!r}")
    number, unit = match.groups()
    scale = {
        "B": 1 / 2**20,
        "KiB": 1 / 2**10,
        "MiB": 1,
        "GiB": 2**10,
    }
    return float(number) * scale[unit]


def aggregate_upstream_memory_mib(namespace: str) -> float:
    containers = subprocess.run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            "label=io.portunusmcp.managed=true",
            "--filter",
            f"label=io.portunusmcp.namespace={namespace}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    if not containers:
        return 0
    rows = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", *containers],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return sum(_memory_mib(row.split("/", 1)[0]) for row in rows)


async def bench_concurrent(
    gw: Gateway, namespace: str
) -> tuple[dict[int, dict[str, float]], float]:
    """Scenario 3: p95 across all calls at each concurrency level, one gateway process,
    each session owning its own upstream stdio subprocess."""

    async def worker(barrier: asyncio.Barrier) -> list[float]:
        try:
            async with gateway_session(gw, "developer") as session:
                await barrier.wait()  # every session initialized before anyone is timed
                await barrier.wait()  # benchmark process samples live container memory
                call = functools.partial(session.call_tool, "read_file", {"path": "bench.txt"})
                await timed_calls(call, 2)
                return await timed_calls(call, CALLS_PER_SESSION)
        except BaseException:
            await barrier.abort()  # don't strand the other workers at the barrier
            raise

    results: dict[int, dict[str, float]] = {}
    upstream_memory_mib = 0.0
    for level in CONCURRENCY_LEVELS:
        barrier = asyncio.Barrier(level + 1)
        # return_exceptions so every worker has fully unwound before we re-raise —
        # otherwise leaked workers keep hitting the gateway during teardown.
        workers = [asyncio.create_task(worker(barrier)) for _ in range(level)]
        await barrier.wait()
        if level == CONCURRENCY_LEVELS[-1]:
            upstream_memory_mib = aggregate_upstream_memory_mib(namespace)
        await barrier.wait()
        per_session = await asyncio.gather(*workers, return_exceptions=True)
        failures = [r for r in per_session if isinstance(r, BaseException)]
        if failures:
            raise failures[0]
        results[level] = dist([lat for session_lats in per_session for lat in session_lats])
    return results, upstream_memory_mib


async def bench_payload_size(gw: Gateway) -> dict[str, float]:
    """Scenario 4: serialized tools/list size, unpruned direct baseline vs the pruned
    developer identity through the gateway. One serializer for both sides."""

    def size(result: ListToolsResult) -> int:
        return len(result.model_dump_json(by_alias=True, exclude_none=True).encode())

    async with direct_session() as session:
        direct_bytes = size(await session.list_tools())
    async with gateway_session(gw, "developer") as session:
        pruned_bytes = size(await session.list_tools())
    return {
        "direct_bytes": direct_bytes,
        "pruned_bytes": pruned_bytes,
        "reduction_pct": (1 - pruned_bytes / direct_bytes) * 100,
    }


def max_rss_mib() -> float:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / (2**20 if sys.platform == "darwin" else 2**10)  # bytes on macOS, KiB on Linux


def render(report: dict) -> str:
    single, conc, payload = report["single_call"], report["concurrent"], report["payload_size"]
    initialization = report["container_initialization"]
    overhead = {k: single["gateway_cached"][k] - single["direct"][k] for k in single["direct"]}
    lines = [
        "# PortunusMCP benchmark report",
        "",
        f"- commit: {report['commit']}  |  date: {report['date']}",
        f"- host: {report['host']}  |  python: {report['python']}",
        f"- N={report['n']} sequential calls/scenario; {CALLS_PER_SESSION} calls/session "
        "at each concurrency level; latencies as mean / p50 / p95 / p99",
        "- one in-process gateway; cold cache = Redis DEL of the schema key before each "
        "timed call; gateway upstreams are real Docker containers",
        "",
        "| Scenario | Direct call | Through gateway | Overhead (gateway − direct) |",
        "|---|---|---|---|",
        f"| Single call, cached schema | {fmt_dist(single['direct'])} "
        f"| {fmt_dist(single['gateway_cached'])} | {fmt_dist(overhead)} |",
        f"| Single call, cold schema cache | {fmt_dist(single['direct'])} "
        f"| {fmt_dist(single['gateway_cold'])} | — |",
    ]
    for level in CONCURRENCY_LEVELS:
        lines.append(f"| {level} concurrent sessions (p95) | — | {conc[level]['p95']:.2f} ms | — |")
    lines += [
        f"| tools/list payload size | {payload['direct_bytes']:.0f} B (unpruned) "
        f"| {payload['pruned_bytes']:.0f} B (pruned developer) "
        f"| {payload['reduction_pct']:.1f}% reduction |",
        "",
        f"Container initialization: first {initialization['first_ms']:.2f} ms; "
        f"next {WARM_CONTAINER_LAUNCHES} p50 {initialization['warm']['p50']:.2f} ms / "
        f"p95 {initialization['warm']['p95']:.2f} ms.",
        f"Peak RSS after the {CONCURRENCY_LEVELS[-1]}-session run: "
        f"{report['max_rss_mib']:.0f} MiB (gateway + harness share the process); "
        f"aggregate upstream container memory while initialized: "
        f"{report['upstream_memory_mib']:.0f} MiB.",
    ]
    return "\n".join(lines)


async def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(4096, hard), hard))  # 100 stdio sessions

    # The in-process gateway shares this settings object: keep off-hours pushes and
    # the deliberate read_file hammering out of the CHALLENGE band (score 45 aborts
    # the run with McpError otherwise).
    settings.business_hours_start_utc = 0
    settings.business_hours_end_utc = 24
    settings.risk_freq_threshold = 10**9
    settings.max_sessions_per_identity = max(CONCURRENCY_LEVELS)
    settings.max_inflight_calls_per_identity = max(CONCURRENCY_LEVELS)
    settings.tool_call_rate_limit = (
        WARMUP_CALLS + 2 * n + sum(level * (2 + CALLS_PER_SESSION) for level in CONCURRENCY_LEVELS)
    )
    for logger_name in (
        "httpx",
        "mcp.client.streamable_http",
        "mcp.server.streamable_http",
        "services.gateway.jsonrpc_interceptor",
    ):
        logging.getLogger(logger_name).setLevel(logging.WARNING)
    namespace = os.environ.get("UPSTREAM_RUNTIME_NAMESPACE", "")
    if not namespace:
        sys.exit("UPSTREAM_RUNTIME_NAMESPACE is required (for example: portunusmcp-benchmark)")

    await preflight_clean()
    keys = {"developer": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    with tempfile.TemporaryDirectory() as tmp:
        policy_path = Path(tmp) / "bench-policy.yaml"
        policy_path.write_text(yaml.safe_dump(bench_policy(keys)))
        async with running_gateway(policy_path, "", keys, isolate_upstreams=True) as gw:
            print("measuring per-session container initialization ...")
            initialization = await bench_container_initialization(gw)
            print(f"gateway up at {gw.url}; running single-call scenarios (N={n}) ...")
            single = await bench_single_call(gw, n)
            print("running concurrent-session scenarios ...")
            concurrent, upstream_memory_mib = await bench_concurrent(gw, namespace)
            payload = await bench_payload_size(gw)

    report = {
        "commit": subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "host": f"{platform.system()} {platform.release()} {platform.machine()}",
        "python": platform.python_version(),
        "n": n,
        "container_initialization": initialization,
        "single_call": single,
        "concurrent": concurrent,
        "payload_size": payload,
        "max_rss_mib": max_rss_mib(),
        "upstream_memory_mib": upstream_memory_mib,
    }
    rendered = render(report)
    print("\n" + rendered)

    REPORTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    (REPORTS_DIR / f"{stamp}.md").write_text(rendered + "\n")
    (REPORTS_DIR / f"{stamp}.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nreport written to {REPORTS_DIR / stamp}.{{md,json}}")


if __name__ == "__main__":
    asyncio.run(main())
