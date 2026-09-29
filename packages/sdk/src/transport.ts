import type {
  Transport,
  TransportSendOptions,
} from "@modelcontextprotocol/sdk/shared/transport.js";
import type {
  JSONRPCMessage,
  MessageExtraInfo,
  RequestId,
} from "@modelcontextprotocol/sdk/types.js";
import type { GuardSession } from "./guard.js";

type Message = JSONRPCMessage & {
  id?: RequestId;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
};

/**
 * Sits between an MCP client and its transport: vets tools/list results on
 * the way in and decides tools/call requests on the way out, so every client
 * API (listTools, callTool, request) goes through the guard.
 */
export class GuardedTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void;

  #inner: Transport;
  #session: GuardSession;
  #server?: string;
  #initialize?: RequestId;
  #lists = new Set<RequestId>();
  #calls = new Map<RequestId, { tool: string; started: number }>();
  /** Incoming messages are processed in order, even when vetting is async. */
  #queue: Promise<void> = Promise.resolve();

  constructor(inner: Transport, session: GuardSession, server?: string) {
    this.#inner = inner;
    this.#session = session;
    this.#server = server;
  }

  get sessionId(): string | undefined {
    return this.#inner.sessionId;
  }

  setProtocolVersion(version: string): void {
    this.#inner.setProtocolVersion?.(version);
  }

  async start(): Promise<void> {
    await this.#session.ready(); // an unreadable policy or lockfile fails connect()
    this.#inner.onmessage = (message, extra) => this.#enqueue(() => this.#receive(message, extra));
    this.#inner.onclose = () => this.onclose?.();
    this.#inner.onerror = (error) => this.onerror?.(error);
    await this.#inner.start();
  }

  close(): Promise<void> {
    return this.#inner.close();
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    const m = message as Message;
    if (m.id !== undefined && m.method === "initialize") this.#initialize = m.id;
    if (m.id !== undefined && m.method === "tools/list") this.#lists.add(m.id);
    if (m.id !== undefined && m.method === "tools/call") {
      const id = m.id;
      const tool = String(m.params?.name ?? "");
      const args = (m.params?.arguments ?? {}) as Record<string, unknown>;
      const decision = await this.#session.decide(this.#name, tool, args);
      if (!decision.forward) {
        const text = `Hecate blocked this call to ${this.#name}/${tool}: ${decision.reasons.join("; ")}.`;
        const reply = {
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text }], isError: true },
        };
        this.#enqueue(() => this.onmessage?.(reply as JSONRPCMessage));
        return;
      }
      this.#calls.set(id, { tool, started: Date.now() });
    }
    await this.#inner.send(message, options);
  }

  get #name(): string {
    return this.#server ?? "unknown";
  }

  async #receive(message: JSONRPCMessage, extra?: MessageExtraInfo): Promise<void> {
    let m = message as Message;
    const id = m.id;
    if (id !== undefined && m.method === undefined) {
      if (id === this.#initialize && this.#server === undefined) {
        const info = m.result?.serverInfo as { name?: unknown } | undefined;
        if (typeof info?.name === "string") this.#server = info.name;
      }
      if (this.#lists.delete(id) && Array.isArray(m.result?.tools)) {
        const tools = await this.#session.vetTools(this.#name, m.result.tools);
        m = { ...m, result: { ...m.result, tools } } as Message;
      }
      const call = this.#calls.get(id);
      if (call) {
        this.#calls.delete(id);
        const isError = m.result === undefined || m.result.isError === true;
        this.#session.onResult(this.#name, call.tool, isError, Date.now() - call.started);
      }
    }
    this.onmessage?.(m as JSONRPCMessage, extra);
  }

  #enqueue(task: () => unknown): void {
    this.#queue = this.#queue
      .then(async () => {
        await task();
      })
      .catch((error: Error) => this.onerror?.(error));
  }
}
