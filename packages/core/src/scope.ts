import { inDescription, inName, inParam, toolText, words } from "./signals.js";
import type { MCPTool } from "./types.js";

/** What a tool can do to the machine it runs on (MCP004). */
export type Scope = "exec" | "file-write";

const RUN_VERB = words("run|exec|execute|evaluate|spawn|invoke|launch");
const EXEC_NOUN = words(
  "commands?|cmds?|scripts?|code|shell|process(?:es)?|programs?|python|javascript|js|node|ruby|terminal|binar(?:y|ies)",
);
const EXEC_NAME = words("shell|bash|zsh|sh|powershell|pwsh|cmd|terminal|repl|subprocess|eval");
const EXEC_PARAM = /^(?:command|commands|cmd|shell command|script)$/;
const EXEC_DESC =
  /\b(?:execut(?:e|es|ing)|runs?|running|evaluat(?:e|es|ing))\s+(?:an?\s+|any\s+|arbitrary\s+|the\s+given\s+)?(?:(?:shell|terminal|bash|system|os|python|javascript)\s+)?(?:commands?|scripts?|code)\b|\barbitrary code\b/;

const WRITE_VERB = words(
  "write|create|edit|update|delete|remove|move|rename|append|save|overwrite|patch|modify|put|mkdir|touch|chmod",
);
const FILE_NOUN = words("files?|director(?:y|ies)|dirs?|folders?|paths?");
const FILE_WRITE_NAME = words("mkdir|rmdir|rm|touch|chmod|chown");
const PATH_PARAM =
  /^(?:path|file path|filepath|filename|file|file name|destination|dest|target path)$/;
const CONTENT_PARAM = /^(?:content|contents|text|data|body|patch|diff|edits?)$/;

const SIGNALS: Record<Scope, ((tool: ReturnType<typeof toolText>) => string | undefined)[]> = {
  exec: [
    (t) => inName(t, EXEC_NAME),
    (t) => inName(t, RUN_VERB, EXEC_NOUN),
    (t) => inParam(t, EXEC_PARAM),
    (t) => inDescription(t, EXEC_DESC),
  ],
  "file-write": [
    (t) => inName(t, WRITE_VERB, FILE_NOUN),
    (t) => inName(t, FILE_WRITE_NAME),
    (t) => {
      const path = t.params.find((p) => PATH_PARAM.test(p.words));
      const content = t.params.find((p) => CONTENT_PARAM.test(p.words));
      return path && content ? `parameters: ${path.raw} + ${content.raw}` : undefined;
    },
  ],
};

/** Which scopes a tool has, with the evidence for each (as classifyTool does for MCP005). */
export function classifyScope(tool: MCPTool): Partial<Record<Scope, string[]>> {
  const text = toolText(tool);
  const result: Partial<Record<Scope, string[]>> = {};
  for (const scope of ["exec", "file-write"] as const) {
    const evidence = SIGNALS[scope].map((signal) => signal(text)).filter((e) => e !== undefined);
    if (evidence.length > 0) result[scope] = evidence;
  }
  return result;
}
