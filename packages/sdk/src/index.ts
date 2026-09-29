// Runtime guard for MCP clients, embedded in the agent's own process:
// (1) hides tools whose definitions changed since they were approved (rug pull),
//     are poisoned, or aren't allowed; (2) enforces a least-privilege policy;
// (3) asks a human before high-risk calls; (4) writes an audit log.
export { createGuard, guard } from "./guard.js";
export type {
  ApprovalRequest,
  Connectable,
  Decision,
  Guard,
  GuardOptions,
  Violation,
} from "./guard.js";
export type { AuditEvent, AuditTarget } from "./audit.js";
export type { GuardPolicy, Lockfile, Policy } from "@hecate-mcp/core";
