"""Small stdlib MCP stdio target for the 100-container benchmark."""

import json
import sys
from typing import Any

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from the repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "list_issues",
        "description": "List open issues for a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        },
    },
    {
        "name": "delete_repo",
        "description": "Permanently delete a repository. No confirmation. No undo.",
        "inputSchema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        },
    },
    {
        "name": "merge_pr",
        "description": "Merge a pull request to the default branch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "pr_number": {"type": "integer"},
            },
            "required": ["repo", "pr_number"],
        },
    },
]


def result(request: dict[str, Any]) -> dict[str, Any] | None:
    request_id = request.get("id")
    if request_id is None:
        return None
    method = request.get("method")
    if method == "initialize":
        payload = {
            "protocolVersion": request["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "benchmark-server", "version": "1"},
        }
    elif method == "tools/list":
        payload = {"tools": TOOLS}
    elif method == "tools/call":
        arguments = request["params"].get("arguments", {})
        payload = {
            "content": [{"type": "text", "text": f"<contents of {arguments.get('path')}>"}],
            "isError": False,
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"unknown method {method!r}"},
        }
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


if __name__ == "__main__":
    for line in sys.stdin.buffer:
        if response := result(json.loads(line)):
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
