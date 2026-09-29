#!/usr/bin/env bash
# Packs the CLI and SDK exactly as they would be published, installs each
# tarball into an empty project, and runs it. Catches packaging mistakes the
# workspace build can't: missing files, unbundled workspace code, a broken bin.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$root/packages/cli" && pnpm pack --pack-destination "$work/cli" >/dev/null)
(cd "$root/packages/sdk" && pnpm pack --pack-destination "$work/sdk" >/dev/null)
# Read each listing in full first: `tar | grep -q` fails under pipefail when grep
# exits before tar has finished writing (GNU tar: "stdout: write error").
for tarball in "$work"/cli/*.tgz "$work"/sdk/*.tgz; do
  contents="$(tar -tzf "$tarball")"
  for file in LICENSE README.md; do
    if ! grep -qx "package/$file" <<<"$contents"; then
      echo "$(basename "$tarball") is missing $file" >&2
      exit 1
    fi
  done
done

mkdir "$work/app"
cd "$work/app"
npm init -y >/dev/null
npm pkg set type=module >/dev/null
npm install --no-audit --no-fund --loglevel=error \
  "$work"/cli/*.tgz "$work"/sdk/*.tgz @modelcontextprotocol/sdk >/dev/null

# CLI: the installed bin runs and finds tool poisoning.
npx hecate --version
code=0
npx hecate scan "$root/fixtures/poisoned-trivia-server.json" >/dev/null || code=$?
test "$code" -eq 1

# SDK: imports from the tarball and blocks a command tool when nobody approves it.
cat > guard.mjs <<'JS'
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { guard } from "@hecate-mcp/sdk";

const fixtures = process.argv[2];
const client = guard(new Client({ name: "smoke", version: "1.0.0" }), { server: "shell" });
await client.connect(
  new StdioClientTransport({
    command: "node",
    args: [`${fixtures}/servers/serve-tools.mjs`, `${fixtures}/shell-server.json`],
  }),
);
await client.listTools();
const result = await client.callTool({ name: "run_command", arguments: { command: "id" } });
await client.close();
if (!result.isError) throw new Error("expected the guard to block run_command");
console.log("sdk: blocked run_command without an approver");
JS
node guard.mjs "$root/fixtures"
echo "package smoke test passed"
