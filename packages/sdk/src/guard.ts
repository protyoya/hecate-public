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

const URL_IN_TEXT = /\bhttps?:\/\/[^\s"'<>]+/gi;

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
  /** Trust on first use: first tools/list per server, for servers without pins. */
  #baselines = new Map<string, Map<string, string>>();
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

  /** Vets a tools/list result: returns the tools the model may see. */
  async vetTools(server: string, tools: unknown[]): Promise<unknown[]> {
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
    const baseline = pins ? new Map(Object.entries(pins)) : this.#baselines.get(server);
    const hashes = new Map<string, string>();
    for (const tool of surface.tools) {
      const hash = await hashTool(tool);
      hashes.set(tool.name, hash);
      if (!baseline) continue;
      const approved = baseline.get(tool.name);
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
    if (!baseline) this.#baselines.set(server, hashes);

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
    const visible = new Map<string, ToolInfo>();
    for (const tool of surface.tools) {
      if (hidden.has(tool.name) && this.mode === "enforce") continue;
      visible.set(tool.name, {
        exec: classifyScope(tool).exec !== undefined,
        untrusted: inLeg("untrusted-content", tool.name),
        egress: inLeg("external-comms", tool.name),
      });
    }
    this.#servers.set(server, { visible, hidden });
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

function urlHosts(value: unknown, hosts = new Set<string>()): string[] {
  if (typeof value === "string") {
    for (const text of value.match(URL_IN_TEXT) ?? []) {
      try {
        hosts.add(new URL(text).hostname.toLowerCase());
      } catch {
        // not a URL after all
      }
    }
  } else if (Array.isArray(value)) {
    for (const item of value) urlHosts(item, hosts);
  } else if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) urlHosts(item, hosts);
  }
  return [...hosts];
}

const now = () => new Date().toISOString();
