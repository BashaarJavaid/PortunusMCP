from services.gateway.policy_engine import PolicyEngine, PolicyFile
from services.gateway.schema_pruner import prune

ENGINE = PolicyEngine(
    PolicyFile.model_validate(
        {
            "version": 1,
            "servers": {
                "default": {"image": "example/upstream:test", "command": ["unused-command"]}
            },
            "identities": [
                {
                    "id": "agent-readonly",
                    "api_key_hash": "sha256:0",
                    "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
                }
            ],
        }
    )
)

TOOLS = [
    {"name": "echo", "description": "echoes", "inputSchema": {"type": "object"}},
    {"name": "delete_repo", "description": "dangerous", "inputSchema": {"type": "object"}},
]


def test_unauthorized_tools_are_absent_authorized_untouched() -> None:
    pruned = prune(TOOLS, "agent-readonly", "default", ENGINE)
    assert pruned == [TOOLS[0]]  # echo untouched, delete_repo gone entirely


def test_unknown_identity_gets_nothing() -> None:
    assert prune(TOOLS, None, "default", ENGINE) == []
