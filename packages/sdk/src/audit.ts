/** One JSON line per event in the audit log. */
export type AuditEvent =
  | {
      type: "tools/list";
      time: string;
      server: string;
      listed: number;
      hidden: { tool: string; reasons: string[] }[];
      /** False in monitor mode: nothing was actually hidden. */
      enforced: boolean;
    }
  | {
      type: "tools/call";
      time: string;
      server: string;
      tool: string;
      decision: "allowed" | "approved" | "denied" | "blocked";
      reasons: string[];
      enforced: boolean;
      /** SHA-256 of the canonical arguments; the arguments themselves only with auditArguments. */
      argumentsSha256: string;
      arguments?: Record<string, unknown>;
    }
  | {
      type: "tools/result";
      time: string;
      server: string;
      tool: string;
      isError: boolean;
      durationMs: number;
      /** The result counts as untrusted content: egress now needs approval. */
      taints: boolean;
    };

export type AuditTarget = string | ((event: AuditEvent) => void);

export interface AuditWriter {
  write(event: AuditEvent): void;
  /** Resolves once every event written so far has reached the file. */
  flush(): Promise<void>;
}

/**
 * Writes events in order. A path appends JSON lines (Node only, loaded on first
 * use); a function receives each event.
 */
export function auditWriter(
  target: AuditTarget | undefined,
  onError: (error: Error) => void,
): AuditWriter {
  if (target === undefined) return { write: () => {}, flush: async () => {} };
  if (typeof target === "function") {
    return {
      write(event) {
        try {
          target(event);
        } catch (error) {
          onError(error as Error);
        }
      },
      flush: async () => {},
    };
  }
  let queue: Promise<void> = Promise.resolve();
  return {
    write(event) {
      const line = `${JSON.stringify(event)}\n`;
      queue = queue
        .then(async () => {
          const { appendFile } = await import("node:fs/promises");
          await appendFile(target, line, "utf8");
        })
        .catch((error: Error) =>
          onError(new Error(`Hecate audit log ${target}: ${error.message}`)),
        );
    },
    flush: () => queue,
  };
}
