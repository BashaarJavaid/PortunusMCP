"""Focused checks for complete benchmark latency comparisons."""

from typing import Any

import pytest

from tests.benchmarks import run


def _distribution(mean: float, p50: float, p95: float, p99: float) -> dict[str, float]:
    return {"mean": mean, "p50": p50, "p95": p95, "p99": p99}


def test_distribution_subtraction_covers_every_statistic() -> None:
    assert run.subtract_dist(
        _distribution(11, 22, 33, 44), _distribution(1, 2, 3, 4)
    ) == _distribution(10, 20, 30, 40)


@pytest.mark.asyncio
async def test_concurrent_results_are_additive_and_keep_gateway_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    async def fake_level(
        session_factory: Any, level: int, on_ready: Any = None
    ) -> tuple[dict[str, float], float]:
        kind = "direct" if session_factory is run.direct_session else "gateway"
        calls.append((kind, level))
        value = float(level + (5 if kind == "gateway" else 0))
        return _distribution(value, value, value, value), 123.0 if on_ready else 0.0

    monkeypatch.setattr(run, "_bench_concurrent_level", fake_level)
    gateway, direct, overhead, memory = await run.bench_concurrent(object(), "namespace")

    expected_gateway = {
        level: _distribution(level + 5, level + 5, level + 5, level + 5)
        for level in run.CONCURRENCY_LEVELS
    }
    assert gateway == expected_gateway
    assert direct == {
        level: _distribution(level, level, level, level) for level in run.CONCURRENCY_LEVELS
    }
    assert overhead == {level: _distribution(5, 5, 5, 5) for level in run.CONCURRENCY_LEVELS}
    assert memory == 123.0
    assert calls == [
        (kind, level) for level in run.CONCURRENCY_LEVELS for kind in ("direct", "gateway")
    ]


def test_render_has_complete_cached_cold_and_concurrent_distributions() -> None:
    concurrent_direct = {
        level: _distribution(level, level + 1, level + 2, level + 3)
        for level in run.CONCURRENCY_LEVELS
    }
    concurrent = {
        level: _distribution(level + 10, level + 21, level + 32, level + 43)
        for level in run.CONCURRENCY_LEVELS
    }
    report = {
        "commit": "abc1234",
        "date": "2026-07-30",
        "host": "TestOS arm64",
        "python": "3.12.13",
        "n": 1000,
        "single_call": {
            "direct": _distribution(1, 2, 3, 4),
            "gateway_cached": _distribution(11, 22, 33, 44),
            "gateway_cold": _distribution(21, 32, 43, 54),
        },
        "concurrent": concurrent,
        "concurrent_direct": concurrent_direct,
        "concurrent_overhead": {
            level: run.subtract_dist(concurrent[level], concurrent_direct[level])
            for level in run.CONCURRENCY_LEVELS
        },
        "container_initialization": {
            "first_ms": 100.0,
            "warm": _distribution(90, 91, 92, 93),
        },
        "payload_size": {
            "direct_bytes": 744,
            "pruned_bytes": 425,
            "reduction_pct": 42.9,
        },
        "max_rss_mib": 100,
        "upstream_memory_mib": 1000,
    }

    rendered = run.render(report)
    assert (
        "| Single call, cached schema | 1.00 / 2.00 / 3.00 / 4.00 ms "
        "| 11.00 / 22.00 / 33.00 / 44.00 ms | 10.00 / 20.00 / 30.00 / 40.00 ms |"
    ) in rendered
    assert (
        "| Single call, cold schema cache | 1.00 / 2.00 / 3.00 / 4.00 ms "
        "| 21.00 / 32.00 / 43.00 / 54.00 ms | 20.00 / 30.00 / 40.00 / 50.00 ms |"
    ) in rendered
    for level in run.CONCURRENCY_LEVELS:
        row = next(
            line for line in rendered.splitlines() if line.startswith(f"| {level} concurrent")
        )
        assert run.fmt_dist(concurrent_direct[level]) in row
        assert run.fmt_dist(concurrent[level]) in row
        assert run.fmt_dist(report["concurrent_overhead"][level]) in row
        assert "—" not in row
    latency_rows = [
        line
        for line in rendered.splitlines()
        if line.startswith("| Single call") or "concurrent sessions |" in line
    ]
    assert latency_rows
    assert all("—" not in row for row in latency_rows)
