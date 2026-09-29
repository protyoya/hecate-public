import { attackGraph } from "../capabilities.js";
import { classifyScope } from "../scope.js";
import type { Finding, MCPServerSurface, Rule, RuleContext } from "../types.js";

const ID = "MCP004";
const BROAD_WHY =
  "which includes SSH keys, cloud credentials and browser profiles. A hijacked agent can " +
  "reach all of it.";
const EXEC_WHY = "A hijacked agent can do anything the user running it can.";
const PLANT_WHY = "Injected text can plant files such as shell profiles, git hooks or CI config.";

/** The filesystem root, or a home directory, as a whole argument (trailing slash ignored). */
const ROOT = /^(?:\/|[A-Za-z]:[\\/]?)$/;
const HOME =
  /^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\/Users\/[^/]+|\/home\/[^/]+|\/root|[A-Za-z]:[\\/]Users[\\/][^\\/]+)$/;

export const excessiveScope: Rule = {
  id: ID,
  severity: "critical",
  title: "Excessive scope: command execution, file writes or broad filesystem access",

  /** Config: a server launched with the whole filesystem or home directory. */
  detect(surface: MCPServerSurface): Finding[] {
    if (surface.launch?.transport !== "stdio") return [];
    const findings: Finding[] = [];
    for (const [i, arg] of surface.launch.args.entries()) {
      const value = (arg.match(/^--?[\w-]+=(.*)$/)?.[1] ?? arg).replace(/(.)[\\/]+$/, "$1");
      const kind = ROOT.test(value) ? "root" : HOME.test(value) ? "home" : undefined;
      if (!kind) continue;
      findings.push({
        ruleId: ID,
        severity: kind === "root" ? "high" : "medium",
        title:
          kind === "root"
            ? "Server is given the whole filesystem"
            : "Server is given the whole home directory",
        detail: `Server "${surface.serverName}" is started with ${kind === "root" ? "the filesystem root" : "a home directory"} (args[${i}]), ${BROAD_WHY}`,
        serverName: surface.serverName,
        field: `args[${i}]`,
        remediation: "Grant only the directories the agent needs, e.g. one project folder.",
      });
    }
    return findings;
  },

  /** Tools: command execution, and file writes where untrusted content can steer them. */
  detectAgent(surfaces: MCPServerSurface[], ctx: RuleContext): Finding[] {
    const untrusted = attackGraph(surfaces, ctx.policy.capabilities)["untrusted-content"];
    const sources = untrusted.slice(0, 3).map((t) => `${t.serverName}/${t.toolName}`);
    const via =
      untrusted.length > 0
        ? `untrusted content (${sources.join(", ")}${untrusted.length > 3 ? ", …" : ""})`
        : undefined;
    const findings: Finding[] = [];

    for (const surface of surfaces) {
      const writers: string[] = [];
      for (const tool of surface.tools) {
        const scope = classifyScope(tool);
        if (scope["file-write"]) writers.push(tool.name);
        if (!scope.exec) continue;
        findings.push({
          ruleId: ID,
          severity: via ? "critical" : "high",
          title: via
            ? "Prompt injection can reach command execution"
            : "Tool can run arbitrary commands or code",
          detail: `Tool "${tool.name}" runs commands or code (${scope.exec.join("; ")}). ${
            via
              ? `The same agent reads ${via}, so injected text can run code on this machine.`
              : EXEC_WHY
          }`,
          serverName: surface.serverName,
          toolName: tool.name,
          remediation:
            "Remove the tool, run the server in a sandbox or container without credentials, or " +
            "require human approval for every call.",
        });
      }
      if (via && writers.length > 0) {
        findings.push({
          ruleId: ID,
          severity: "medium",
          title: "Untrusted content can steer file writes",
          detail: `Server "${surface.serverName}" can write files (${writers.join(", ")}) and the same agent reads ${via}. ${PLANT_WHY}`,
          serverName: surface.serverName,
          remediation:
            "Limit the server to a scratch directory, or require approval for writes outside it.",
        });
      }
    }
    return findings;
  },
};
