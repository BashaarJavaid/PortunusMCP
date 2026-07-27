"""Tiny async MCP server for deadline and in-flight lifecycle tests."""

import asyncio

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sleep-upstream")


@mcp.tool()
async def sleep(seconds: float) -> str:
    await asyncio.sleep(seconds)
    return "done"


if __name__ == "__main__":
    mcp.run()
