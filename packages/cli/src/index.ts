#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  CAPABILITIES,
  CAPABILITY_LABELS,
  EMPTY_POLICY,
  type Finding,
  type Lockfile,
  type MCPServerSurface,
  type Policy,
  applyIgnores,
  attackGraph,
  attackGraphToMermaid,
  checkPins,
  definitionFindings,
  expiredIgnores,
  parseLockfile,
  parsePolicy,
  pinSurface,
  printable,
  scan,
  surfacesFromJson,
  toSarif,
  updateLockfile,
} from "@hecate-mcp/core";
import { Command, CommanderError, InvalidArgumentError, Option } from "commander";
import pc from "picocolors";
import { listTools } from "./connect.js";
import { locator } from "./locate.js";
import { VERSION } from "./version.js";

// Node 20+: tool hashing needs Web Crypto as a global, and it's what CI tests.
if (Number(process.versions.node.split(".")[0]) < 20) {
  console.error(`hecate needs Node.js 20 or later; this is ${process.version}.`);
  process.exit(2);
}

const DEFAULT_LOCKFILE = "hecate.lock.json";
const DEFAULT_POLICY = "hecate.policy.json";
const POLICY_HELP = `policy file of reviewed exceptions (default: ${DEFAULT_POLICY} if present)`;

/** Unreadable or invalid input: reported without a stack trace, exit code 2. */
class InputError extends Error {}

interface ConnectOptions {
  connect?: boolean;
  /** Milliseconds, from --timeout <seconds>. */
  timeout: number;
  /** Without --connect, check configs without their tools instead of failing (scan only). */
  configOnly?: boolean;
}

interface FormatOptions {
  format: "pretty" | "json" | "sarif";
  json?: boolean;
}

interface PinOptions extends ConnectOptions {
  lockfile: string;
  server?: string;
  force?: boolean;
  policy?: string;
}

const CONNECT_HINT =
  "Pass --connect to start them and list their tools (this runs the commands in the config).";
const FILES_HELP =
  "tools/list JSON or MCP client config (Claude Desktop, Claude Code, Cursor, VS Code, ...)";

/** Adds --format and its --json shorthand (the original flag). */
function withFormat(command: Command): Command {
  return command
    .addOption(
      new Option("--format <format>", "output format; sarif is for code scanning")
        .choices(["pretty", "json", "sarif"])
        .default("pretty"),
    )
    .addOption(new Option("--json", "same as --format json").conflicts("format"));
}

/** Adds --connect/--timeout: configs name servers, but their tools are only known once they run. */
function withConnect(command: Command): Command {
  return command
    .option(
      "--connect",
      "start the config's stdio servers and connect to its remote ones to list their tools " +
        "(runs the commands in the config)",
    )
    .option("--timeout <seconds>", "per-server time limit with --connect", seconds, 60_000);
}

const program = new Command();
program
  .name("hecate")
  .description("Security scanner and runtime guard for MCP servers and AI agents")
  .version(VERSION)
  // Throw instead of exiting, so usage errors map to exit code 2 (see below).
  .exitOverride();

withFormat(withConnect(program.command("scan")))
  .argument(
    "<files...>",
    `${FILES_HELP}; pass everything one agent uses to catch cross-server risks`,
  )
  .option("--policy <path>", POLICY_HELP)
  .action(async (files: string[], opts: ConnectOptions & FormatOptions & { policy?: string }) => {
    const policy = readPolicy(opts.policy);
    const surfaces = await connect(files.flatMap(readSurfaces), { ...opts, configOnly: true });
    report(scan(surfaces, { policy }), opts, surfaces);
  });

withConnect(program.command("pin"))
  .description("approve servers' tools: write their definition hashes to the lockfile")
  .argument("<file>", FILES_HELP)
  .option("--lockfile <path>", "lockfile to update", DEFAULT_LOCKFILE)
  .option("--server <name>", "server name to pin under (default: serverName in <file>)")
  .option("--force", "pin even if the tools have critical/high findings")
  .option("--policy <path>", POLICY_HELP)
  .action(async (file: string, opts: PinOptions) => {
    const policy = readPolicy(opts.policy);
    const surfaces = await connect(nameServers(readSurfaces(file), file, opts.server), opts);
    // Only findings about the definitions being approved block pinning.
    const findings = definitionFindings(surfaces, { policy });
    if (isBlocking(findings) && !opts.force) {
      printReport(findings);
      console.error(pc.red("Refusing to pin: that would approve the findings above."));
      console.error("Fix them, or pass --force if you have reviewed them.");
      process.exitCode = 1;
      return;
    }

    // Hash everything before writing, so a failure leaves the lockfile untouched.
    let lock = readLockfile(opts.lockfile);
    const pinned: string[] = [];
    for (const surface of surfaces) {
      let pins: Awaited<ReturnType<typeof pinSurface>>;
      try {
        pins = await pinSurface(surface);
      } catch (err) {
        throw new InputError(printable((err as Error).message));
      }
      lock = updateLockfile(lock, surface.serverName, pins);
      pinned.push(
        `${Object.keys(pins.tools).length} tool(s) for "${printable(surface.serverName)}"`,
      );
    }
    writeFileSync(opts.lockfile, `${JSON.stringify(lock, null, 2)}\n`);
    console.log(pc.green(`✔ Pinned ${pinned.join(", ")} in ${opts.lockfile}.`));
  });

withFormat(withConnect(program.command("check")))
  .description("diff tool definitions against the pinned snapshot (rug-pull detection)")
  .argument("<file>", FILES_HELP)
  .option("--lockfile <path>", "lockfile to check against", DEFAULT_LOCKFILE)
  .option("--server <name>", "server name to check under (default: serverName in <file>)")
  .option("--policy <path>", POLICY_HELP)
  .action(async (file: string, opts: Omit<PinOptions, "force"> & FormatOptions) => {
    const policy = readPolicy(opts.policy);
    // Before connecting: don't start servers just to fail on a missing lockfile.
    const lock = readLockfile(opts.lockfile);
    if (!lock) {
      throw new InputError(`No lockfile at ${opts.lockfile}. Run \`hecate pin ${file}\` first.`);
    }
    const { servers } = lock;
    const surfaces = await connect(nameServers(readSurfaces(file), file, opts.server), opts);
    const findings = await Promise.all(
      surfaces.map((s) =>
        checkPins(s, Object.hasOwn(servers, s.serverName) ? servers[s.serverName] : undefined),
      ),
    );
    report(applyIgnores(findings.flat(), policy), opts, surfaces);
  });

withConnect(program.command("graph"))
  .description("print the lethal-trifecta attack graph (MCP005) for one agent's servers")
  .argument("<files...>", `${FILES_HELP}; everything one agent uses`)
  .addOption(
    new Option("--format <format>", "output format")
      .choices(["mermaid", "json"])
      .default("mermaid"),
  )
  .option("--policy <path>", POLICY_HELP)
  .action(
    async (
      files: string[],
      opts: ConnectOptions & { format: "mermaid" | "json"; policy?: string },
    ) => {
      const policy = readPolicy(opts.policy);
      const surfaces = await connect(files.flatMap(readSurfaces), opts);
      const graph = attackGraph(surfaces, policy.capabilities);
      console.log(
        opts.format === "json" ? JSON.stringify(graph, null, 2) : attackGraphToMermaid(graph),
      );
    },
  );

program.parseAsync().catch((err: unknown) => {
  if (err instanceof CommanderError) {
    // Commander already printed the message; --help and --version exit 0.
    process.exitCode = err.exitCode === 0 ? 0 : 2;
    return;
  }
  if (!(err instanceof InputError)) throw err;
  // The parts that come from scanned files and servers are escaped where the message is built;
  // this keeps any that slipped through from acting on the terminal.
  console.error(pc.red(printable(err.message, { newlines: true })));
  process.exitCode = 2;
});

function readSurfaces(file: string): MCPServerSurface[] {
  try {
    return surfacesFromJson(JSON.parse(readFileSync(file, "utf8")), file);
  } catch (err) {
    // JSON.parse quotes the file in its errors, and the parser quotes tool names.
    throw new InputError(`Could not read ${file}: ${printable((err as Error).message)}`);
  }
}

/**
 * Lists the tools of servers that came from client configs. Without --connect
 * a config is an input error rather than a scan of nothing, and any server
 * that can't be listed fails the run: a partial picture could hide a
 * cross-server risk.
 */
async function connect(
  surfaces: MCPServerSurface[],
  opts: ConnectOptions,
): Promise<MCPServerSurface[]> {
  const configured = surfaces.filter((s) => s.launch);
  if (configured.length === 0) return surfaces;
  const names = configured.map((s) => printable(s.serverName)).join(", ");
  if (!opts.connect) {
    if (opts.configOnly) {
      console.error(
        pc.yellow(
          `Only the config was checked for ${configured.length} server(s) (${names}): their tools are known once they run, so tool rules (MCP001, MCP003, MCP004, MCP005) did not see them. ${CONNECT_HINT}`,
        ),
      );
      return surfaces;
    }
    throw new InputError(
      `The client config lists ${configured.length} server(s) (${names}); their tools are only known once they run. ${CONNECT_HINT}`,
    );
  }

  console.error(pc.dim(`Listing tools from ${configured.length} server(s): ${names}`));
  const results = await Promise.allSettled(configured.map((s) => listTools(s, opts.timeout)));
  const failures = results.flatMap((result, i) =>
    result.status === "rejected"
      ? // connect.ts escapes the server's own text (errors, stderr) and adds the line breaks
        [`  ${printable(configured[i].serverName)}: ${(result.reason as Error).message}`]
      : [],
  );
  if (failures.length > 0) {
    throw new InputError(
      `Could not list tools from ${failures.length} of ${configured.length} server(s):\n${failures.join("\n")}`,
    );
  }
  const listed = new Map(
    configured.map((s, i) => [
      s,
      (results[i] as PromiseFulfilledResult<MCPServerSurface["tools"]>).value,
    ]),
  );
  return surfaces.map((s) => {
    const tools = listed.get(s);
    return tools ? { ...s, tools } : s;
  });
}

/** Pins are keyed by server name: --server renames a lone server, and every server needs a name. */
function nameServers(
  surfaces: MCPServerSurface[],
  file: string,
  server: string | undefined,
): MCPServerSurface[] {
  if (surfaces.length === 0) throw new InputError(`${file} lists no servers.`);
  if (server !== undefined) {
    if (surfaces.length > 1) {
      throw new InputError(
        `--server needs a file with one server; ${file} has ${surfaces.length}.`,
      );
    }
    return [{ ...surfaces[0], serverName: server }];
  }
  if (surfaces.some((s) => s.serverName === "unknown")) {
    throw new InputError(`${file} does not name its server ("serverName"); pass --server <name>.`);
  }
  return surfaces;
}

function seconds(value: string): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0)
    throw new InvalidArgumentError("expected a positive number of seconds.");
  return n * 1000;
}

function readLockfile(path: string): Lockfile | undefined {
  if (!existsSync(path)) return undefined;
  try {
    return parseLockfile(JSON.parse(readFileSync(path, "utf8")));
  } catch (err) {
    throw new InputError(`Could not read lockfile ${path}: ${printable((err as Error).message)}`);
  }
}

/** An explicit --policy must exist; the default one is optional. */
function readPolicy(path: string | undefined): Policy {
  if (path === undefined && !existsSync(DEFAULT_POLICY)) return EMPTY_POLICY;
  const file = path ?? DEFAULT_POLICY;
  let policy: Policy;
  try {
    policy = parsePolicy(JSON.parse(readFileSync(file, "utf8")));
  } catch (err) {
    throw new InputError(`Could not read policy ${file}: ${printable((err as Error).message)}`);
  }
  for (const entry of expiredIgnores(policy)) {
    const scope = printable([entry.rule, entry.server, entry.tool].filter(Boolean).join(" "));
    console.error(
      pc.yellow(
        `warning: ${file}: ignore for ${scope} expired on ${entry.expires}; it no longer applies.`,
      ),
    );
  }
  return policy;
}

/** Suppressed findings never block. */
function isBlocking(findings: Finding[]): boolean {
  return findings.some(
    (f) => !f.suppressed && (f.severity === "critical" || f.severity === "high"),
  );
}

function report(findings: Finding[], opts: FormatOptions, surfaces: MCPServerSurface[]): void {
  const format = opts.json ? "json" : opts.format;
  if (format === "sarif") {
    const log = toSarif(findings, { toolVersion: VERSION, locate: locator(surfaces) });
    console.log(JSON.stringify(log, null, 2));
  } else if (format === "json") {
    // The findings that count; suppressed ones appear in the pretty and SARIF output.
    const active = findings.filter((f) => !f.suppressed);
    console.log(JSON.stringify(active, null, 2));
  } else {
    printReport(findings);
  }
  // exitCode, not process.exit(): stdout to a pipe is async on macOS, and
  // exiting early truncates large --json output.
  process.exitCode = isBlocking(findings) ? 1 : 0;
}

function printReport(findings: Finding[]): void {
  const active = findings.filter((f) => !f.suppressed);
  const suppressed = findings.filter((f) => f.suppressed);
  if (active.length === 0) console.log(pc.green("✔ No issues found."));
  else printFindings(active);
  if (suppressed.length > 0) {
    console.log(pc.dim(`${suppressed.length} finding(s) accepted by policy:`));
    for (const f of suppressed) {
      const at = where(f) ? ` ${where(f)}` : "";
      const until = f.suppressed?.expires ? ` (until ${f.suppressed.expires})` : "";
      console.log(pc.dim(`  ${f.ruleId}${at}: ${printable(f.suppressed?.reason ?? "")}${until}`));
    }
  }
}

/**
 * Findings quote tool names, server names and descriptions from the scanned servers: every value
 * goes through printable(), so a hostile server can't rewrite the report (see core text.ts).
 */
function printFindings(findings: Finding[]): void {
  const color = (s: Finding["severity"]) =>
    s === "critical" || s === "high" ? pc.red : s === "medium" ? pc.yellow : pc.dim;
  console.log(pc.bold(`\nFound ${findings.length} issue(s):\n`));
  for (const f of findings) {
    console.log(
      `${color(f.severity)(`[${f.severity.toUpperCase()}]`)} ${pc.bold(f.ruleId)} ${printable(f.title)}`,
    );
    if (where(f)) console.log(`  at: ${where(f)}`);
    console.log(`  ${printable(f.detail)}`);
    if (f.attackGraph) printAttackPath(f.attackGraph);
    console.log(`  ${pc.cyan("fix:")} ${printable(f.remediation)}\n`);
  }
}

/** "server/tool", or "server", then the field if any: "github › env.GITHUB_TOKEN". */
function where(f: Finding): string {
  const subject = f.toolName ? `${f.serverName ?? "?"}/${f.toolName}` : f.serverName;
  return printable([subject, f.field].filter(Boolean).join(" › "));
}

function printAttackPath(graph: NonNullable<Finding["attackGraph"]>): void {
  for (const [i, capability] of CAPABILITIES.entries()) {
    const tools = graph[capability].map((t) => printable(`${t.serverName}/${t.toolName}`));
    const shown = tools.length > 4 ? [...tools.slice(0, 3), `+${tools.length - 3} more`] : tools;
    console.log(`  ${i + 1}. ${CAPABILITY_LABELS[capability].padEnd(23)} ${shown.join(", ")}`);
  }
}
