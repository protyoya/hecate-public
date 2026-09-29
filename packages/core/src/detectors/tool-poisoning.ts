import type { Finding, MCPServerSurface, Rule } from "../types.js";

const ID = "MCP001";
const SEVERITY = "critical" as const;
const TITLE = "Tool description contains hidden or injected instructions";
const WHY =
  "MCP tool descriptions are injected into the agent's context as trusted text, " +
  "so hidden instructions here can hijack the agent.";

const INJECTION_PATTERNS: RegExp[] = [
  /ignore (all )?(previous|prior|above) (instructions|context)/i,
  /disregard (the )?(above|previous|system)/i,
  /before (using|calling) (any )?other tool/i,
  /you (must|should) (always|first)/i,
  /do not (tell|mention|inform) the user/i,
  /(send|exfiltrate|forward|leak)\b[\s\S]{0,40}(https?:\/\/|@)/i,
];

// zero-width / bidi / other invisible unicode used to smuggle instructions,
// plus Unicode tag characters (U+E0000–E007F, "ASCII smuggling")
const INVISIBLE_UNICODE = /[​-‏‪-‮⁠-⁯﻿\u{E0000}-\u{E007F}]/u;
const HTML_COMMENT = /<!--[\s\S]*?-->/;

export const toolPoisoning: Rule = {
  id: ID,
  severity: SEVERITY,
  title: TITLE,
  detect(surface: MCPServerSurface): Finding[] {
    const findings: Finding[] = [];
    for (const tool of surface.tools) {
      const desc = tool.description ?? "";
      const hits: string[] = [];

      for (const re of INJECTION_PATTERNS) {
        if (re.test(desc)) hits.push(`injection phrase (/${re.source}/)`);
      }
      if (INVISIBLE_UNICODE.test(desc)) hits.push("invisible/zero-width unicode");
      if (HTML_COMMENT.test(desc)) hits.push("hidden HTML comment");

      if (hits.length > 0) {
        findings.push({
          ruleId: ID,
          severity: SEVERITY,
          title: TITLE,
          detail: `Tool "${tool.name}" description looks manipulative (${hits.join("; ")}). ${WHY}`,
          serverName: surface.serverName,
          toolName: tool.name,
          remediation:
            "Review the tool source. Pin an approved hash with `hecate pin` and reject " +
            "servers whose tool definitions change unexpectedly (rug-pull protection).",
        });
      }
    }
    return findings;
  },
};
