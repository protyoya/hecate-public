import {
  DEFAULT_GUARD_POLICY,
  EMPTY_POLICY,
  type GuardPolicy,
  type Lockfile,
  type Policy,
  attackGraph,
  classifyScope,
  definitionFindings,
  globMatch,
  hashJson,
  hashTool,
  parseLockfile,
  parsePolicy,
  surfaceFromToolsJson,
} from "@hecate-mcp/core";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { type AuditTarget, type AuditWriter, auditWriter } from "./audit.js";
import { GuardedTransport } from "./transport.js";

export interface GuardOptions {
  /** hecate.policy.json path, or a policy object. Its `guard` section holds the runtime rules. */
  policy?: string | Policy;
  /** hecate.lock.json path, or a lockfile object: tool definitions approved with `hecate pin`. */
  lockfile?: string | Lockfile;
  /** "enforce" (default) hides and blocks; "monitor" only reports what it would do. */
  mode?: "enforce" | "monitor";
  /** Asked before high-risk calls. Without it those calls are blocked. */
  approve?: (request: ApprovalRequest) => boolean | Promise<boolean>;
  /** A JSONL file path or a callback for audit events. */
  audit?: AuditTarget;
  /** Put call arguments in audit events; by default only their SHA-256 is recorded. */
  auditArguments?: boolean;
  /** Called for every hidden tool and every blocked or denied call. */
  onViolation?: (violation: Violation) => void;
  /** Audit-log write errors and the like; defaults to console.error. */
  onError?: (error: Error) => void;
}

export interface ApprovalRequest {
  server: string;
  tool: string;
  arguments: Record<string, unknown>;
  /** Why approval is needed, e.g. "runs commands or code". */
  reasons: string[];
}

export interface Violation {
  server: string;
  tool: string;
  kind: "hidden" | "blocked" | "denied";
  reasons: string[];
}

export interface Decision {
  /** Whether the call goes to the server (always true in monitor mode). */
  forward: boolean;
  outcome: "allowed" | "approved" | "denied" | "blocked";
  reasons: string[];
}

/** Anything with the MCP SDK Client's connect(transport, ...). */
export interface Connectable {
  connect(transport: Transport, ...rest: never[]): Promise<void>;
  readonly transport?: Transport;
}

export interface Guard {
  /** Guards a client; call before connect(). `server` names it in policy patterns and the lockfile. */
  wrap<C extends Connectable>(client: C, options?: { server?: string }): C;
  /** Guards a transport directly, for frameworks that manage their own. */
  wrapTransport(transport: Transport, options?: { server?: string }): Transport;
  /** Forgets that untrusted content was read, e.g. when a new conversation starts. */
  clearTaint(): void;
  /** Waits for pending audit-log writes, e.g. before the process exits. */
  flush(): Promise<void>;
}

interface ToolInfo {
  exec: boolean;
  untrusted: boolean;
  egress: boolean;
}

interface ServerState {
  visible: Map<string, ToolInfo>;
  hidden: Map<string, string[]>;
}

interface Config {
  policy: Policy;
  guard: GuardPolicy;
  lockfile?: Lockfile;
}

/** scheme://host in any scheme (https, wss, ftp, ...), or //host at the start of a word. */
const URL_IN_TEXT =
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+|(?<![^\s"'(=])\/\/[^\s"'<>/]+\.[^\s"'<>]+/gi;
/** Argument names whose value is a host or URL even without a scheme, e.g. { webhook: "evil.com/x" }. */
const URL_KEY = /url|uri|href|link|host|domain|endpoint|origin|webhook|callback|server/i;
const BARE_HOST = /^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:[/?#].*)?$/i;

/**
 * One guard per agent: servers wrapped by the same guard share state, so
 * untrusted content read through one server makes egress through another
 * need approval.
 */
export function createGuard(options: GuardOptions = {}): Guard {
  return new GuardSession(options);
}

/** Shorthand for one server: createGuard(options).wrap(client, options). */
export function guard<C extends Connectable>(
  client: C,
  options: GuardOptions & { server?: string } = {},
): C {
  return createGuard(options).wrap(client, { server: options.server });
}

export class GuardSession implements Guard {
  readonly mode: "enforce" | "monitor";
  #options: GuardOptions;
  #config?: Promise<Config>;
  /**
   * Trust on first use, for servers without pins: the definitions from the first tools/list of
   * the session, every page of it (`complete` once the last page is in).
   */
  #baselines = new Map<string, { hashes: Map<string, string>; complete: boolean }>();
  #servers = new Map<string, ServerState>();
  #taint?: { server: string; tool: string };
  #audit: AuditWriter;

  constructor(options: GuardOptions) {
    this.#options = options;
    this.mode = options.mode ?? "enforce";
    const onError = options.onError ?? ((error: Error) => console.error(error.message));
    this.#audit = auditWriter(options.audit, onError);
  }

  wrap<C extends Connectable>(client: C, options: { server?: string } = {}): C {
    if (client.transport !== undefined) {
      throw new Error("Hecate guard: wrap the client before calling connect().");
    }
    const connect = client.connect.bind(client);
    client.connect = (transport: Transport, ...rest: never[]) =>
      connect(this.wrapTransport(transport, options), ...rest);
    return client;
  }

  wrapTransport(transport: Transport, options: { server?: string } = {}): Transport {
    return new GuardedTransport(transport, this, options.server);
  }

  clearTaint(): void {
    this.#taint = undefined;
  }

  flush(): Promise<void> {
    return this.#audit.flush();
  }

  /** Loads the policy and lockfile once; a failure fails connect(). */
  ready(): Promise<Config> {
    this.#config ??= load(this.#options);
    return this.#config;
  }

  /**
   * Without `server`, a server is known by the name it gives itself in `initialize`. It could
   * give another server's name, and with it that server's policy exceptions, capability
   * corrections, allow rules and pins: so a policy or lockfile that names servers needs `server`.
   */
  async checkUnnamed(server: string | undefined): Promise<void> {
    const config = await this.ready();
    if (server === undefined && namesServers(config)) {
      throw new Error(
        "Hecate guard: pass { server } to wrap(): the policy or lockfile has rules for named " +
          "servers, and a server's name for itself can't choose which rules apply to it.",
      );
    }
  }

  /**
   * Vets a tools/list result: returns the tools the model may see. A listing can span pages:
   * `continued` for a page fetched with a cursor, `more` when the server has another page.
   */
  async vetTools(
    server: string,
    tools: unknown[],
    page: { continued?: boolean; more?: boolean } = {},
  ): Promise<unknown[]> {
    const { policy, guard: rulesOf, lockfile } = await this.ready();
    const hidden = new Map<string, string[]>();
    const hide = (tool: string, reason: string) =>
      hidden.set(tool, [...(hidden.get(tool) ?? []), reason]);

    let surface: ReturnType<typeof surfaceFromToolsJson>;
    try {
      surface = { ...surfaceFromToolsJson({ tools }, server), serverName: server };
    } catch (error) {
      // Malformed definitions can't be vetted: hide them all.
      const reason = `invalid tools/list: ${(error as Error).message}`;
      this.#servers.set(server, { visible: new Map(), hidden: new Map([["*", [reason]]]) });
      this.#report(server, tools.length, [{ tool: "*", reasons: [reason] }]);
      return this.mode === "enforce" ? [] : tools;
    }

    // 1. Pinned definitions (lockfile), else the first list this session (trust on first use).
    const pins =
      lockfile && Object.hasOwn(lockfile.servers, server)
        ? lockfile.servers[server].tools
        : undefined;
    let first = this.#baselines.get(server);
    // A new listing (no cursor) while the first was unfinished: the first one is what it got.
    if (first && !first.complete && !page.continued) first.complete = true;
    // Still collecting the first listing's pages: new tools join the baseline.
    const collecting = !pins && !first?.complete;
    const baseline = pins ? new Map(Object.entries(pins)) : first?.hashes;
    const hashes = new Map<string, string>();
    for (const tool of surface.tools) {
      const hash = await hashTool(tool);
      hashes.set(tool.name, hash);
      if (!baseline) continue;
      const approved = baseline.get(tool.name);
      if (approved === undefined && collecting) continue;
      if (approved === undefined) {
        hide(
          tool.name,
          pins
            ? "not in the pinned snapshot"
            : "appeared after the first tools/list of this session",
        );
      } else if (approved !== hash) {
        hide(tool.name, "definition changed since it was approved (possible rug pull)");
      }
    }
    if (collecting) {
      first ??= { hashes: new Map(), complete: false };
      for (const [name, hash] of hashes) if (!first.hashes.has(name)) first.hashes.set(name, hash);
      first.complete = !page.more;
      this.#baselines.set(server, first);
    }

    // 2. Findings about the definitions themselves (MCP001 poisoning, MCP006 secrets).
    for (const finding of definitionFindings(surface, { policy })) {
      const blocking = finding.severity === "critical" || finding.severity === "high";
      if (finding.toolName !== undefined && blocking && !finding.suppressed) {
        hide(finding.toolName, `${finding.ruleId}: ${finding.title}`);
      }
    }

    // 3. Least privilege.
    for (const tool of surface.tools) {
      const id = `${server}/${tool.name}`;
      if (rulesOf.tools.deny.some((p) => globMatch(p, id)))
        hide(tool.name, "denied by guard.tools.deny");
      if (rulesOf.tools.allow.length > 0 && !rulesOf.tools.allow.some((p) => globMatch(p, id))) {
        hide(tool.name, "not in guard.tools.allow");
      }
    }

    const graph = attackGraph([surface], policy.capabilities);
    const inLeg = (leg: keyof typeof graph, name: string) =>
      graph[leg].some((t) => t.toolName === name);
    // A later page adds to what the listing's earlier pages showed; a new listing starts over.
    const prior = page.continued ? this.#servers.get(server) : undefined;
    const visible = new Map<string, ToolInfo>(prior?.visible);
    for (const tool of surface.tools) {
      if (hidden.has(tool.name) && this.mode === "enforce") continue;
      visible.set(tool.name, {
        exec: classifyScope(tool).exec !== undefined,
        untrusted: inLeg("untrusted-content", tool.name),
        egress: inLeg("external-comms", tool.name),
      });
    }
    this.#servers.set(server, { visible, hidden: new Map([...(prior?.hidden ?? []), ...hidden]) });
    this.#report(
      server,
      tools.length,
      [...hidden].map(([tool, reasons]) => ({ tool, reasons })),
    );

    if (this.mode === "monitor") return tools;
    return tools.filter((tool) => !hidden.has((tool as { name: string }).name));
  }

  /** Decides a tools/call: may wait for the approver. */
  async decide(server: string, tool: string, args: Record<string, unknown>): Promise<Decision> {
    const { guard: rulesOf } = await this.ready();
    const state = this.#servers.get(server);
    const enforce = this.mode === "enforce";
    const decided = async (decision: Decision): Promise<Decision> => {
      const final = enforce ? decision : { ...decision, forward: true };
      await this.#auditCall(server, tool, args, decision);
      if (decision.outcome === "blocked" || decision.outcome === "denied") {
        this.#options.onViolation?.({
          server,
          tool,
          kind: decision.outcome,
          reasons: decision.reasons,
        });
      }
      return final;
    };
    const block = (reasons: string[]) => decided({ forward: false, outcome: "blocked", reasons });

    const hiddenReasons = state?.hidden.get(tool) ?? state?.hidden.get("*");
    if (hiddenReasons && enforce) return block(hiddenReasons);
    const info = state?.visible.get(tool);
    if (!info) return block(["not in a vetted tools/list for this server"]);

    if (rulesOf.egress) {
      const allowed = rulesOf.egress.allow;
      const hosts = urlHosts(args).filter((host) => !allowed.some((p) => globMatch(p, host)));
      if (hosts.length > 0)
        return block([`sends to ${hosts.join(", ")}, which guard.egress.allow doesn't list`]);
    }

    const needs: string[] = [];
    if (rulesOf.approve.some((p) => globMatch(p, `${server}/${tool}`)))
      needs.push("matches guard.approve");
    if (rulesOf.approveExec && info.exec) needs.push("runs commands or code");
    if (rulesOf.approveEgressAfterUntrusted && info.egress && this.#taint) {
      const { server: s, tool: t } = this.#taint;
      needs.push(`can send data out, and this session read untrusted content from ${s}/${t}`);
    }
    if (needs.length === 0) return decided({ forward: true, outcome: "allowed", reasons: [] });
    if (!enforce) return block([...needs, "needs approval (not asked in monitor mode)"]);
    if (!this.#options.approve)
      return block([...needs, "needs approval, and no approver is configured"]);
    const approved = await this.#options.approve({ server, tool, arguments: args, reasons: needs });
    return approved
      ? decided({ forward: true, outcome: "approved", reasons: needs })
      : decided({ forward: false, outcome: "denied", reasons: needs });
  }

  /** Records a call's result; a successful untrusted-content read taints the session. */
  onResult(server: string, tool: string, isError: boolean, durationMs: number): void {
    const taints = !isError && this.#servers.get(server)?.visible.get(tool)?.untrusted === true;
    if (taints) this.#taint = { server, tool };
    this.#audit.write({
      type: "tools/result",
      time: now(),
      server,
      tool,
      isError,
      durationMs,
      taints,
    });
  }

  #report(server: string, listed: number, hidden: { tool: string; reasons: string[] }[]): void {
    const enforced = this.mode === "enforce";
    this.#audit.write({ type: "tools/list", time: now(), server, listed, hidden, enforced });
    for (const { tool, reasons } of hidden)
      this.#options.onViolation?.({ server, tool, kind: "hidden", reasons });
  }

  async #auditCall(
    server: string,
    tool: string,
    args: Record<string, unknown>,
    decision: Decision,
  ): Promise<void> {
    this.#audit.write({
      type: "tools/call",
      time: now(),
      server,
      tool,
      decision: decision.outcome,
      reasons: decision.reasons,
      enforced: this.mode === "enforce",
      argumentsSha256: (await hashJson(args)).slice("sha256:".length),
      ...(this.#options.auditArguments && { arguments: args }),
    });
  }
}

async function load(options: GuardOptions): Promise<Config> {
  if (!(globalThis as { crypto?: { subtle?: unknown } }).crypto?.subtle) {
    throw new Error("Hecate guard needs the Web Crypto API (Node.js 20 or later).");
  }
  const policy =
    options.policy === undefined ? EMPTY_POLICY : parsePolicy(await json(options.policy, "policy"));
  const lockfile =
    options.lockfile === undefined
      ? undefined
      : parseLockfile(await json(options.lockfile, "lockfile"));
  return { policy, guard: policy.guard ?? DEFAULT_GUARD_POLICY, lockfile };
}

async function json(source: unknown, what: string): Promise<unknown> {
  if (typeof source !== "string") return source;
  try {
    const { readFile } = await import("node:fs/promises");
    return JSON.parse(await readFile(source, "utf8"));
  } catch (error) {
    throw new Error(`Hecate guard: could not read ${what} ${source}: ${(error as Error).message}`);
  }
}

/** Whether any rule in the policy or lockfile applies to servers by name (see checkUnnamed). */
function namesServers({ policy, guard: rules, lockfile }: Config): boolean {
  return (
    Object.keys(lockfile?.servers ?? {}).length > 0 ||
    policy.capabilities.length > 0 ||
    policy.ignore.some((entry) => entry.server !== undefined || entry.tool !== undefined) ||
    rules.tools.allow.length > 0 ||
    rules.tools.deny.length > 0 ||
    rules.approve.length > 0
  );
}

/**
 * The hosts a call's arguments point to: URLs anywhere in them, and bare host names in
 * URL-like fields. Best effort: a host spelled any other way (split across fields, encoded,
 * an email address) isn't seen; see the README's limits.
 */
function urlHosts(value: unknown, key = "", hosts = new Set<string>()): string[] {
  if (typeof value === "string") {
    const found: string[] = [...(value.match(URL_IN_TEXT) ?? [])];
    if (found.length === 0 && URL_KEY.test(key) && BARE_HOST.test(value.trim())) {
      found.push(`//${value.trim()}`);
    }
    for (const text of found) {
      try {
        const host = new URL(text.startsWith("//") ? `https:${text}` : text).hostname;
        if (host) hosts.add(host.toLowerCase());
      } catch {
        // not a URL after all
      }
    }
  } else if (Array.isArray(value)) {
    for (const item of value) urlHosts(item, key, hosts);
  } else if (value !== null && typeof value === "object") {
    for (const [name, item] of Object.entries(value)) urlHosts(item, name, hosts);
  }
  return [...hosts];
}

const now = () => new Date().toISOString();
