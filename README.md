# Unraid Community Apps – Paul Meier

This repository contains Unraid Community Applications templates maintained by Paul Meier.

## Templates

- **Actual Budget MCP Server (`actual-mcp`)**
  - Docker image: `sstefanov/actual-mcp:latest`
  - Project: https://github.com/s-stefanov/actual-mcp
  - Description: Exposes your Actual Budget data through the Model Context Protocol (MCP) so AI tools
    like Claude and other MCP clients can query your finances via an HTTP SSE endpoint.

## Security / Privacy

- Templates here do not inject additional shell commands into the Unraid docker run command.
- The `actual-mcp` container works with your self-hosted Actual Budget instance or local data directory.
- No telemetry or tracking is added by these templates; all financial data stays within your environment,
  and only flows between your Actual Budget instance and your MCP clients, according to how you configure them.
