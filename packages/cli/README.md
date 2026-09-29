# hecate-mcp

> **Beta.** Rules, output formats and the policy file may still change before 1.0.

Security scanner for MCP (Model Context Protocol) servers and the AI agents
that use them. It runs on your machine; nothing is sent anywhere.

```bash
npx hecate-mcp@beta scan ./tools.json
```

Needs Node.js 20 or later. The installed command is `hecate`.

## What it checks

| Rule | Finds |
|---|---|
| MCP001 | Tool poisoning: injected instructions, invisible Unicode or hidden HTML comments in tool descriptions |
| MCP002 | Rug pulls: tools that changed or appeared since you approved them (`hecate pin` / `hecate check`) |
| MCP003 | Tool shadowing: a tool that tells the model how another server's tools should behave; one tool name on several servers |
| MCP004 | Excessive scope: tools that run commands or code, file writes that untrusted content can steer, servers given `/` or a home directory |
| MCP005 | The lethal trifecta: one agent that can read untrusted content, reach private data and send data out |
| MCP006 | Secrets in plain text in client configs and tool definitions (reported by type and length, never the value) |
| MCP007 | Known-malicious or known-vulnerable server packages, and your policy's server allow and deny lists |
| MCP008 | Server packages and images not pinned to a version, remote servers over plain HTTP |

MCP003, MCP004 and MCP005 classify tools heuristically from their names,
parameters and descriptions, and show the evidence behind each classification.

## Commands

```bash
hecate scan <files...>    # findings for everything one agent uses
hecate graph <files...>   # the lethal-trifecta attack graph: --format mermaid (default) or json
hecate pin <file>         # approve: write tool-definition hashes to hecate.lock.json
hecate check <file>       # fail if a tool changed or appeared since it was pinned
```

Each file is a `tools/list` result (`[...]`, `{ "tools": [...] }` or a raw
JSON-RPC response) or an MCP client config:

- `mcpServers`: Claude Desktop, Claude Code (`.mcp.json`), Cursor, Windsurf
- `servers`: VS Code (`.vscode/mcp.json`), or `mcp.servers` in its `settings.json`

A config only says how to start or reach each server. `scan` checks the config
itself (secrets, supply chain, broad filesystem grants) and says which
tool-level rules it skipped. Add `--connect` to start the configured stdio
servers and connect to the remote ones (streamable HTTP or SSE, with the
configured headers) to list their tools; **this runs the commands in the
config**, as your MCP client would. `pin`, `check` and `graph` need
`--connect` for configs. Any server that can't be reached fails the run
(`--timeout <seconds>`, default 60).

Exit codes: `0` no critical or high findings, `1` critical or high findings,
`2` unreadable input or bad usage.

Output: `--format pretty` (default), `json` or `sarif`; `--json` is short for
`--format json`.

## In CI

Commit `hecate.lock.json` from `hecate pin`, then:

```yaml
- run: npx hecate-mcp@beta check .mcp.json --connect
- run: npx hecate-mcp@beta scan .mcp.json --connect --format sarif > hecate.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always() # hecate exits 1 on critical or high findings
  with:
    sarif_file: hecate.sarif
```

SARIF results point at the tool's line in a tools file, or at the server's
entry (down to the offending key) in a config.

## Reviewed exceptions: `hecate.policy.json`

Picked up from the working directory, or pass `--policy <path>`. Every entry
needs a `reason`; unknown keys and rule IDs are errors.

```json
{
  "version": 1,
  "capabilities": [
    {
      "server": "fetch",
      "tool": "fetch",
      "external-comms": false,
      "reason": "Egress proxy only allows api.weather.gov"
    }
  ],
  "ignore": [
    {
      "rule": "MCP005",
      "reason": "Sandboxed agent, no credentials; reviewed by @alice",
      "expires": "2026-12-31"
    }
  ],
  "servers": {
    "allow": [{ "package": "@modelcontextprotocol/*", "reason": "Official reference servers" }]
  }
}
```

- `capabilities` corrects the trifecta classification of a tool (or, without
  `tool`, a whole server): `true` adds a leg, `false` removes it.
- `ignore` accepts findings of a rule, optionally narrowed by `server` and
  `tool`. Accepted findings are still listed but don't fail the run; after
  `expires` (UTC) they count again.
- `servers.allow` / `servers.deny` decide which servers may run, matching
  `package`, `image`, `url` or `command` with `*` wildcards.

At runtime, [`@hecate-mcp/sdk`](https://www.npmjs.com/package/@hecate-mcp/sdk)
reads the same file and enforces its `guard` section inside your agent.

## License

Apache-2.0. Copyright (c) 2026 Protyoya Datta.
