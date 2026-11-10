# @hecate-mcp/sdk

> **Beta.** Rules, output formats and the policy file may still change before 1.0.

Runtime guard for MCP clients, inside your agent's own process. The
[`hecate-mcp`](https://www.npmjs.com/package/hecate-mcp) scanner finds risks
before you connect; the guard enforces while the agent runs.

```bash
npm install @hecate-mcp/sdk@beta @modelcontextprotocol/sdk
```

Needs Node.js 20 or later; ESM only. It wraps clients from the official
TypeScript MCP SDK, or any MCP transport.

## Usage

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { createGuard } from "@hecate-mcp/sdk";

const hecate = createGuard({
  policy: "hecate.policy.json", // its "guard" section, below
  lockfile: "hecate.lock.json", // from `hecate pin`
  approve: async ({ server, tool, reasons }) => askUser(`${server}/${tool}?`, reasons),
  audit: "hecate-audit.jsonl",
});

// Wrap every server the agent uses with the same guard, before connect().
const github = hecate.wrap(new Client({ name: "agent", version: "1.0.0" }), { server: "github" });
const web = hecate.wrap(new Client({ name: "agent", version: "1.0.0" }), { server: "fetch" });
await github.connect(githubTransport);
await web.connect(webTransport);
// listTools, callTool and raw requests now go through the guard.
```

For a single server, `guard(client, { server, ...options })` is shorthand. For
frameworks that manage their own transports, `hecate.wrapTransport(transport,
{ server })`. `server` names the server in policy patterns and the lockfile.
Without it, the name the server reports in `initialize` is used, but only when
the policy and lockfile don't name servers: otherwise `connect()` fails, since a
server could claim another's name and, with it, that server's exceptions, pins
and allow rules.

## What it does

**On `tools/list`**, it hides tools the model shouldn't see, so their
descriptions never reach it, and blocks calls to them:

- definitions that differ from the lockfile or, for servers not in it, from the
  first `tools/list` of the session (rug pulls, trust on first use)
- poisoned definitions, and definitions containing secrets
- tools outside `guard.tools.allow`, or matching `guard.tools.deny`

A listing that spans several pages (`nextCursor`) is vetted as one list.

**On `tools/call`**, it blocks calls to tools it hasn't vetted and URLs to hosts
outside `guard.egress.allow`, and asks your `approve` callback first for:

- tools matching `guard.approve`
- tools that run commands or code (`approveExec`)
- once any tool has returned untrusted content (a web page, an email, an
  issue), tools that can send data out, on any server wrapped by the same guard
  (`approveEgressAfterUntrusted`): the lethal trifecta, broken at runtime

Without an `approve` callback those calls are blocked. A blocked or denied call
returns an `isError` tool result saying why, so agent loops carry on.
`mode: "monitor"` records what the guard would do without hiding or blocking
anything.

## Options

| Option | |
|---|---|
| `policy` | Path to `hecate.policy.json`, or a policy object |
| `lockfile` | Path to `hecate.lock.json`, or a lockfile object |
| `mode` | `"enforce"` (default) or `"monitor"` |
| `approve` | `(request) => boolean \| Promise<boolean>`; `request` has `server`, `tool`, `arguments` and `reasons` |
| `audit` | JSONL file path, or a callback receiving each event |
| `auditArguments` | Record call arguments in the audit log (default: their SHA-256 only) |
| `onViolation` | Called for every hidden tool and blocked or denied call |
| `onError` | Audit-log write errors; defaults to `console.error` |

The guard also has `clearTaint()`, to forget untrusted content when a new
conversation starts, and `flush()`, to wait for audit-log writes before exit.
An unreadable policy or lockfile fails `connect()`.

## Policy

```json
{
  "version": 1,
  "guard": {
    "tools": { "allow": [], "deny": ["github/delete_*"] },
    "approve": ["*/send_*"],
    "approveExec": true,
    "approveEgressAfterUntrusted": true,
    "egress": { "allow": ["*.github.com"] }
  }
}
```

Tool patterns are `server/tool` globs. Without a `guard` section the defaults
apply: nothing denied, no egress host limit, and approval for command execution
and for egress after untrusted content. The rest of the policy file
(`capabilities` corrections, `ignore` entries) is shared with the scanner.

## Audit log

One JSON object per line, with `time` and `server` on each:

- `tools/list`: `listed`, and the `hidden` tools with their reasons
- `tools/call`: `tool`, `decision` (`allowed`, `approved`, `denied` or `blocked`),
  `reasons`, `argumentsSha256`, and `enforced` (false in monitor mode)
- `tools/result`: `tool`, `isError`, `durationMs`, and `taints` when the result
  counts as untrusted content

## Limits

- Tool classification (commands, untrusted content, egress) is heuristic, as in
  the scanner; correct it with `capabilities` entries in the policy.
- Untrusted content is tracked per session, not per value: after any untrusted
  read, every egress call needs approval until `clearTaint()`.
- The audit log is a local file, not tamper-evident.
- `guard.egress` sees URLs in any argument (any scheme, or `//host`) and bare
  host names in URL-like fields (`url`, `host`, `endpoint`, `webhook`, ...). A
  host spelled any other way (split across fields, encoded, an email recipient)
  isn't seen: treat it as a tripwire, and put tools that send data out under
  `guard.approve`.

## License

Apache-2.0. Copyright (c) 2026 Protyoya Datta.
