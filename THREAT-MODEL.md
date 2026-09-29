# Hecate Threat Model

- MCP001 Tool poisoning — hidden/injected instructions in tool descriptions. [implemented]
- MCP002 Rug pull — tool definitions change after approval (no pin/hash). [implemented: `hecate pin` / `hecate check`]
- MCP003 Tool shadowing — a tool redefines how other tools behave. [implemented: a tool (or parameter) description that mentions another server's tool, high with directive language; the same tool name on several servers, medium]
- MCP004 Excessive scope — exec / file-write / network-egress combinations. [implemented: command/code execution tools, high, critical when the agent also reads untrusted content; file writes steerable by untrusted content, medium; stdio servers given the filesystem root (high) or a home directory (medium)]
- MCP005 Lethal trifecta — private data + untrusted content + external comms. [implemented: heuristic, from tool names, parameters and descriptions; evaluated across all servers passed to `hecate scan`; `hecate graph`]
- MCP006 Secrets exposure — secrets in configs/env. [implemented: known token formats (high) anywhere in configs and tool definitions; literal values of secret-named keys/flags, URL passwords and query secrets in configs (medium); values are never printed]
- MCP007 Known-bad / supply chain — allow/deny list of malicious servers. [implemented: built-in list of known-malicious and known-vulnerable packages (packages/core/src/known-bad.ts, sourced entries only); policy servers.allow / servers.deny by package, image, URL or command]
- MCP008 Unpinned or insecure server source — packages without an exact version, images without a digest or tag, remote servers over plain HTTP. [implemented; separate from MCP007 so accepting unpinned versions can't hide a known-bad package]

## Runtime mitigations (@hecate-mcp/sdk guard)

- MCP001 / MCP006: poisoned definitions, and definitions containing secrets, are hidden from the model.
- MCP002: tools whose definitions differ from the lockfile, or from the first tools/list of the session, are hidden and blocked.
- MCP004: tools that run commands or code need human approval.
- MCP005: once a tool has returned untrusted content, tools that can send data out need approval; guard.egress.allow limits the hosts URLs in call arguments may reach.
- Least privilege: guard.tools.allow / deny; every decision goes to a JSONL audit log.
