# Hecate architecture

Everything in this repository runs on your machine: no Hecate servers, no telemetry.

- **`packages/core`** (`@hecate-mcp/core`, bundled into both published packages): the detection
  engine. Pure and browser-safe: no Node APIs and no runtime dependencies. Each rule
  (MCP001–MCP008) checks one server's tools and config, or every server one agent can reach.
- **`packages/cli`** (`hecate-mcp`): reads tool definitions and MCP client configs, lists live
  servers' tools with `--connect`, runs core, and prints pretty, JSON or SARIF output with CI
  exit codes.
- **`packages/sdk`** (`@hecate-mcp/sdk`): the runtime guard, embedded in the agent's own process.
  It wraps MCP clients (or any MCP transport) and vets every `tools/list` and `tools/call`.
- **`benchmarks`**: reproducible performance and detection benchmarks.
- **`fixtures`**: example tool definitions and client configs used by the tests and CI.

Hecate Cloud, the hosted product for teams, is developed separately. This repository stays
Apache-2.0.
