// Downloads the MCPTox benchmark (Wang et al., AAAI 2026, https://arxiv.org/abs/2508.14925) and
// writes two tool lists for the MCP001 evaluation (packages/core/src/detectors/tool-poisoning.eval.test.ts):
//   benign.json:  the real tool definitions of MCPTox's 45 MCP servers, parameters included
//   attacks.json: its poisoned tool definitions, with their risk category and template
// MCPTox has no license file, so its data is fetched here and never committed.
//   node scripts/fetch-mcptox.mjs [dir]      # default: ./.cache/mcptox (gitignored)
//   MCPTOX_DIR=.cache/mcptox pnpm --filter @hecate-mcp/core test
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const REPO = "https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark";
const COMMIT = "main";
const dir = resolve(process.argv[2] ?? ".cache/mcptox");
mkdirSync(dir, { recursive: true });

const get = async (file) => {
  const res = await fetch(`${REPO}/${COMMIT}/${file}`);
  if (!res.ok) throw new Error(`${file}: HTTP ${res.status}`);
  return res.json();
};

// The servers' clean system prompts list each real tool as:
//   Tool: name\nDescription: ...\nArguments:\n- param: description (required)
const TOOL = /Tool: (.+?)\nDescription: ([\s\S]*?)\nArguments:\n([\s\S]*?)(?=\n\s*\nTool: |$)/g;
const responses = await get("response_all.json");
const benign = [];
for (const [server, entry] of Object.entries(responses.servers)) {
  for (const [, name, description, args] of entry.clean_system_promot.matchAll(TOOL)) {
    const properties = {};
    for (const line of args.trim().split("\n")) {
      const m = line.trim().match(/^- ([^:]+): ([\s\S]*)$/);
      if (!m) continue;
      const text = m[2].replace(/ \(required\)$/, "").trim();
      properties[m[1].trim()] = text.startsWith("No description") ? {} : { description: text };
    }
    benign.push({
      server,
      tool: {
        name: name.trim(),
        ...(description.trim() !== "None" && { description: description.trim() }),
        inputSchema: { type: "object", properties },
      },
    });
  }
}

const attacks = [];
for (const group of await get("pure_tool.json")) {
  for (const [id, t] of Object.entries(group)) {
    attacks.push({
      id,
      server: t.server_name,
      risk: t["security risk"],
      template: t.paradigm,
      // Some entries carry the prompt's "Arguments:" tail; the description is what precedes it.
      tool: {
        name: t.tool_name,
        description: t.tool_content.split(/\\n\s*Arguments:|\nArguments:/)[0].trim(),
      },
    });
  }
}

writeFileSync(join(dir, "benign.json"), JSON.stringify(benign, null, 1));
writeFileSync(join(dir, "attacks.json"), JSON.stringify(attacks, null, 1));
console.log(`${benign.length} real tools and ${attacks.length} poisoned tools written to ${dir}`);
