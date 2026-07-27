import pytest
from pydantic import ValidationError

from services.gateway.config import Settings


@pytest.mark.parametrize(
    "name",
    [
        "max_mcp_body_bytes",
        "max_json_depth",
        "max_sessions_per_identity",
        "max_inflight_calls_per_identity",
        "tool_call_rate_limit",
        "tool_call_rate_window_seconds",
        "auth_failure_rate_limit",
        "auth_failure_rate_window_seconds",
        "tool_call_deadline_seconds",
        "readiness_timeout_seconds",
    ],
)
def test_item_40_numeric_settings_are_strictly_positive(name: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**{name: 0})  # type: ignore[arg-type]


def test_edge_allowlists_parse_json_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOWED_HOSTS", '["gateway.example"]')
    monkeypatch.setenv("ALLOWED_ORIGINS", '["https://client.example"]')
    configured = Settings()
    assert configured.allowed_hosts == ["gateway.example"]
    assert configured.allowed_origins == ["https://client.example"]
