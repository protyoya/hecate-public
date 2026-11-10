import { isObject } from "../json.js";
import type { Finding, MCPServerSurface, MCPTool, Rule, Severity } from "../types.js";

// MCP001: text in a tool definition written to steer the model rather than describe the tool.
//
// Legitimate tools also give orders ("You must first call list_projects to get a project id"), so
// no single phrase decides. Signals come in two strengths:
// - strong: overriding the user, secrecy, sensitive files, sending data to a literal address,
//   exfiltration payloads, pseudo-system tags, hidden text. One is enough (critical).
// - weak: directing how another tool is called, rewriting its arguments, mandate or threat
//   framing, fixed values injected into another tool's call, calls to destructive tools, and
//   directives about sensitive data. Two different ones in the same text are needed (high).
// Every string the model reads is checked: the description, the title, and the descriptions,
// titles and defaults inside the input schema, where "schema poisoning" hides.
//
// Measured on MCPTox (see tool-poisoning.eval.test.ts); pattern rules still miss attacks worded
// to avoid every cue, which is why pinning and runtime approval exist.

const ID = "MCP001";
const TITLE = "Tool definition contains hidden or injected instructions";
const WHY =
  "Tool definitions are read by the model as trusted text, so instructions in them can hijack the agent.";

type Strength = "strong" | "weak";
interface Signal {
  strength: Strength;
  /** Plain-language label shown in the finding. */
  label: string;
  /** Returns the matched evidence, or undefined. */
  test: (t: Text) => string | undefined;
}
interface Text {
  /** NFKC-normalized, invisible characters removed, whitespace collapsed. */
  flat: string;
  lower: string;
  /** Other tools this text might be talking about: siblings on the server. */
  siblings: Set<string>;
  own: string;
}

const re =
  (pattern: RegExp) =>
  (t: Text): string | undefined =>
    pattern.exec(t.lower)?.[0];

// ---------- hidden characters ----------
// Tag characters (ASCII smuggling), bidi overrides and isolates, and invisible formatting. ZWJ and
// ZWNJ are allowed where scripts and emoji use them; LRM/RLM where the text has RTL script.
const ALWAYS_INVISIBLE =
  /[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069\u200B\u2060-\u2064\u206A-\u206F\u180E\u115F\u1160\u3164\uFFA0]/u;
const RTL = /[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Syriac}\p{Script=Thaana}]/u;

function hiddenCharacter(raw: string): string | undefined {
  const always = ALWAYS_INVISIBLE.exec(raw);
  if (always) return codepoint(always[0]);
  if (raw.indexOf("\uFEFF") > 0) return codepoint("\uFEFF");
  if (/[\u200E\u200F]/.test(raw) && !RTL.test(raw))
    return codepoint(/[\u200E\u200F]/.exec(raw)?.[0] ?? "");
  const chars = [...raw];
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c !== "\u200C" && c !== "\u200D") continue;
    const before = chars[i - 1] ?? "";
    const after = chars[i + 1] ?? "";
    // \p{M} covers the emoji variation selector (U+FE0F) and the keycap mark (U+20E3).
    const joins = (x: string) =>
      /[\p{L}\p{M}\p{Extended_Pictographic}]|\p{Emoji_Modifier}/u.test(x);
    if (!(joins(before) && joins(after))) return codepoint(c);
  }
  return undefined;
}
const codepoint = (c: string) =>
  `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`;
const INVISIBLE_STRIP =
  /[\u{E0000}-\u{E007F}\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00AD\u180E]/gu;

// ---------- strong signals ----------
const OVERRIDE = re(
  new RegExp(
    [
      String.raw`\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+)?(?:previous|prior|above|earlier|preceding|original|other|existing|system|developer|user'?s?)\s+(?:instructions?|rules?|prompts?|requests?|quer(?:y|ies)|inputs?|directions?|guidelines?|constraints?|context|messages?)`,
      String.raw`\b(?:priority|precedence)\s+(?:is\s+)?(?:higher|greater|over|above)\b[^.!?]{0,30}\buser`,
      String.raw`\btakes?\s+(?:priority|precedence)\s+over\b`,
      String.raw`\bregardless\s+of\s+(?:the\s+|what\s+the\s+|any\s+)?(?:user'?s?\s+|their\s+)?(?:input|request|quer(?:y|ies)|instructions?|choice|selection|preference|intent|wishes|asks|says|wants|requests|specifies)`,
      String.raw`\bregardless\s+of\s+what\s+(?:the\s+)?user`,
      String.raw`\beven\s+if\s+the\s+user\s+(?:asks|says|requests|specifies|wants|provides|explicitly|chooses)`,
      String.raw`\b(?:new|updated|real|actual|true|hidden)\s+(?:system\s+)?instructions?\s*:`,
      String.raw`\byou\s+are\s+now\s+(?:a|an|in|the|operating|acting)\b`,
      String.raw`\b(?:reveal|print|output|repeat|show|leak|disclose)\s+(?:the\s+|your\s+)(?:system|hidden|initial)\s+(?:prompt|message|instructions?)`,
      // Telling the model to change what the user asked for, rather than documenting the tool.
      String.raw`\b(?:when(?:ever)?|if)\s+(?:a|the)\s+user\s+(?:asks|requests|wants|specifies|provides|calls|searches|queries|enters)\b[^.!?]{0,80}\b(?:must|always)\s+(?:instead\b(?!\s+of)|(?:\w+\s+)?(?:change|modify|replace|redirect|override|substitute|swap|alter)\b)`,
    ].join("|"),
  ),
);
const SECRECY = re(
  new RegExp(
    [
      String.raw`\b(?:do\s+not|don'?t|never|must\s+not|should\s+not|shouldn'?t)\s+(?:tell|inform|notify|alert|mention|reveal|disclose|show|explain|say)\b[^.!?]{0,30}?\b(?:this|these|that\s+you|what\s+you|about|it\s+to|them\s+to|anything|instructions?|step|the\s+(?:above|following))\b`,
      String.raw`\bwithout\s+(?:telling|informing|notifying|alerting|asking|consulting|mentioning(?:\s+it)?\s+to|letting|warning)\s+(?:the\s+)?user`,
      String.raw`\b(?:do\s+not|don'?t|never|without)\s+(?:ask(?:ing)?|request(?:ing)?|seek(?:ing)?|wait(?:ing)?\s+for|prompt(?:ing)?)\s+(?:the\s+user\s+)?(?:for\s+)?(?:confirmation|permission|approval|consent)`,
      String.raw`\bkeep\s+(?:this|it|these)\s+(?:secret|hidden|confidential|private|between)`,
      String.raw`\b(?:the\s+)?user\s+(?:must|should|does|do|need|needs)\s*(?:not|n'?t)\s+(?:know|see|be\s+(?:told|informed|aware|notified))`,
      String.raw`\bsilently\s+(?:send|forward|copy|add|include|upload|call|run|execute|bcc|cc|post|share|attach|modify|change|replace|delete)\b`,
      String.raw`\b(?:hide|conceal)\s+(?:this|it|these|the\s+\w+)\b[^.!?]{0,20}\bfrom\s+(?:the\s+)?user`,
    ].join("|"),
  ),
);
// Files an agent should never be told to touch.
const SENSITIVE_FILE = re(
  /(?:~|\$home|\/home\/[\w.-]+|\/root|\/users\/[\w.-]+)\/\.(?:ssh|aws|gnupg|kube|docker|git-credentials|netrc|pgpass|npmrc|bashrc|zshrc|bash_history|zsh_history|profile)\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\/etc\/(?:passwd|shadow|sudoers|gshadow)\b|\bauthorized_keys\b|\.aws\/credentials\b|\/var\/log\/auth\.log\b|\.git-credentials\b|\bdocument\.cookie\b|\bselect\b[^;]{0,60}\b(?:passwords?|private_keys?|secrets?|tokens?|api_keys?|credentials?|password_hash)\b[^;]{0,40}\bfrom\b/,
);
const URL = String.raw`(?:https?:\/\/|www\.)[^\s'"\`)<>]+`;
const EMAIL = String.raw`[\w.+-]+@[\w-]+(?:\.[\w-]+)+`;
// A data-moving verb in its base (directive) form, aimed at a literal address. "Sends a message to
// https://hooks.slack.com/..." describes the tool; "send the file to https://..." orders the model.
const EXFILTRATE = re(
  new RegExp(
    String.raw`\b(?:send|post|upload|forward|transmit|exfiltrate|leak|submit|copy|mirror|bcc|cc|share|beacon|report|email)\b(?!\s+(?:a|an)\s+(?:message|email|notification)\b)[^.!?]{0,80}?\b(?:to|at|into|via|cc|bcc)\s*:?\s+(?:the\s+)?(?:url|endpoint|address|server|webhook|inbox)?\s*(?:${URL}|${EMAIL})`,
  ),
);
const EXFIL_VIA_TOOL = re(
  new RegExp(
    String.raw`\b(?:use|call|invoke|trigger)\s+(?:the\s+)?[\`'"]?[\w-]*(?:send|mail|email|post|upload|forward|share|publish|webhook)[\w-]*[\`'"]?[^.!?]{0,40}?\b(?:to|at)\s+(?:${URL}|${EMAIL})`,
  ),
);
// A Markdown image the client renders fetches its URL: a templated or data-carrying query string
// leaks whatever the model fills in ("![](https://x.example/p.png?d={conversation})").
const EXFIL_MARKDOWN = re(
  /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*[?&][\w-]+=\s*(?:\{[^}]*\}|\$\{|<[^>]+>|[^)&\s]*(?:conversation|history|secret|token|key|password|context|messages?|query|data))/,
);
const EXFIL_PAYLOAD = re(
  /\bfetch\s*\(\s*['"`]https?:|\bcurl\s+[^\n]{0,80}https?:\/\/|\bwget\s+[^\n]{0,80}https?:\/\/|\bnavigator\.sendbeacon\b|new\s+image\(\s*\)\.src\s*=|\bxmlhttprequest\b[^\n]{0,80}https?:/,
);
const PSEUDO_SYSTEM = re(
  /<\s*\/?\s*(?:important|system|instructions?|secret|hidden|admin|override|sys|assistant)\s*>|\[\s*(?:system|inst|admin|\/inst)\s*\]|<\|im_(?:start|end)\|>|<<\s*sys\s*>>/,
);
function hiddenComment(t: Text): string | undefined {
  for (const m of t.flat.matchAll(/<!--([\s\S]*?)-->/g)) {
    const words = m[1].match(/[\p{L}]{2,}/gu) ?? [];
    if (words.length >= 4) return m[0].slice(0, 60);
  }
  return /\[\/\/\]:\s*#\s*\(([^)]{12,})\)/.exec(t.flat)?.[0];
}

// ---------- weak signals ----------
const DIRECTIVE = String.raw`(?:you\s+(?:must|should|need\s+to|have\s+to|are\s+required\s+to|will\s+need\s+to|are\s+to)|must|always|make\s+sure|be\s+sure|ensure|remember\s+to|automatically|first\s+(?:call|use|run|invoke|trigger|fetch|execute|perform|query)|is\s+required|are\s+required|mandatory)`;
const CALL_VERB = String.raw`(?:use|call|invoke|run|trigger|fetch|query|execute|launch|perform|using|calling|invoking|running|triggering|executing)`;
const QUOTED_NAME = /[`'"]([A-Za-z][\w.:-]{1,63})[`'"]/g;
/** Identifiers that look like tool names: snake_case, kebab-case or camelCase with a lowercase start. */
const TOOLISH = /\b([a-z][a-z0-9]*(?:[_-][a-z0-9]+)+|[a-z]+(?:[A-Z][a-z0-9]+)+)\b/g;

/** Tool names this text refers to in a call context, other than the tool's own. */
function otherTools(t: Text): string[] {
  const found = new Set<string>();
  const own = t.own.toLowerCase();
  for (const m of t.flat.matchAll(QUOTED_NAME)) {
    const name = m[1];
    const before = t.flat.slice(Math.max(0, (m.index ?? 0) - 40), m.index).toLowerCase();
    const after = t.flat
      .slice((m.index ?? 0) + m[0].length, (m.index ?? 0) + m[0].length + 12)
      .toLowerCase();
    const inCall =
      new RegExp(
        `${CALL_VERB}\\s+(?:the\\s+)?$|\\b(?:before|after|when|whenever)\\s+(?:\\w+\\s+){0,3}$|\\b(?:via|through)\\s+(?:the\\s+)?$|\\b(?:requests?|calls?)\\s+to\\s+(?:the\\s+)?$|\\b(?:any|all|every|each)\\s+$`,
      ).test(before) || /^\s+(?:tool|requests?|calls?|lookups?|queries|searches)\b/.test(after);
    // A plain word ('desc', 'asc') is a value, not a tool, unless it's called "the 'x' tool" or a sibling is named that.
    const toolish =
      /[_\-.]|[a-z][A-Z]/.test(name) || /^\s+tool\b/.test(after) || t.siblings.has(name);
    if (inCall && toolish && name.toLowerCase() !== own) found.add(name);
  }
  for (const m of t.flat.matchAll(TOOLISH)) {
    const name = m[1];
    if (name.toLowerCase() === own) continue;
    const before = t.flat.slice(Math.max(0, (m.index ?? 0) - 30), m.index).toLowerCase();
    if (new RegExp(`${CALL_VERB}\\s+(?:the\\s+)?$`).test(before) || t.siblings.has(name))
      found.add(name);
  }
  for (const name of t.siblings) {
    if (name.toLowerCase() !== own && name.length > 3 && t.lower.includes(name.toLowerCase()))
      found.add(name);
  }
  return [...found];
}

/** "When using X, you must ...", "Before calling X, call Y", "you must call X". */
function crossToolDirective(t: Text): string | undefined {
  const tools = otherTools(t);
  if (tools.length === 0) return undefined;
  for (const sentence of sentences(t.lower)) {
    if (
      !new RegExp(
        `\\b${DIRECTIVE}\\b|\\b(?:before|after|when|whenever|every\\s+time|each\\s+time)\\b`,
      ).test(sentence)
    )
      continue;
    const named = tools.find((n) => sentence.includes(n.toLowerCase()));
    if (named) return `\`${named}\``;
  }
  return undefined;
}
const ARG_TAMPERING = (t: Text) =>
  sentences(t.lower).find(
    (s) =>
      (new RegExp(`\\b${DIRECTIVE}\\b`).test(s) &&
        /\b(?:modify|set|change|override|overwrite|replace|append|prepend|add|redirect|limit|restrict|force|standardi[sz]e|rewrite|invert|substitute|alter|swap|hard-?code|filter|reroute)\b[^.!?]{0,60}\b(?:arguments?|parameters?|params?|fields?|values?|quer(?:y|ies)|inputs?|prompts?|keywords?|channel(?:_id)?|recipients?|address(?:es)?|paths?|urls?|ids?|symbols?|names?|events?|states?|positions?|results?|messages?|comments?|to\s+['"`\d])/.test(
          s,
        )) ||
      /\bmust\s+(?:be|have)\s+[^.!?]{0,60}?\b(?:redirected|modified|changed|replaced|rewritten|appended|prepended|limited|filtered|standardi[sz]ed|overridden|forced|inverted|routed)\b/.test(
        s,
      ) ||
      /\bwhen(?:ever)?\s+(?:using|calling|invoking|running)\b[^.!?]{0,80}?,?\s*(?:you\s+)?(?:must|should|always|automatically)\s+(?:\w+\s+)?set\b/.test(
        s,
      ) ||
      // "When using X, modify/override/redirect ..." forces a value; a plain "set ... to" is how
      // legitimate docs explain parameters, so it only counts with must/always/automatically.
      /\bwhen(?:ever)?\s+(?:using|calling|invoking|running|a\s+user|the\s+user)\b[^.!?]{0,80}?,?\s*(?:you\s+(?:must|should)\s+)?(?:always\s+)?(?:modify|change|override|overwrite|replace|append|prepend|redirect|force|rewrite|substitute|alter|swap)\b/.test(
        s,
      ),
  );
const MANDATE = re(
  new RegExp(
    [
      String.raw`\b(?:this\s+is\s+(?:not\s+optional|mandatory|compulsory|a\s+(?:mandatory|required|critical|compulsory)\b)|not\s+optional)`,
      String.raw`\b(?:skipping|ignoring|omitting|bypassing|failure\s+to|failing\s+to|not\s+(?:doing|following))\b[^.!?]{0,50}\b(?:will|would|may|can|could)\s+(?:cause|result|lead|corrupt|break|fail|trigger|crash|return|overload|disrupt|damage|slow|harm|compromise|expose|block|prevent|invalidate|lose|delete)`,
      String.raw`\b(?:security|compliance|audit|internal|system)\s+(?:protocol|requirement|rule|procedure)`,
      String.raw`\bsystem(?:-wide)?\s+policy\b|\bsecurity\s+alert\b|\bpre-?authori[sz]ation\b|\baudit\s+trail\b`,
      String.raw`\b(?:validate|verify|check|confirm)\s+(?:the\s+)?user(?:'s)?\s+(?:permissions?|authori[sz]ation|identity)`,
      String.raw`\bthis\s+step\s+is\s+(?:critical|mandatory|required|essential)`,
    ].join("|"),
  ),
);
/** Social-engineering cover stories for changing behaviour: deprecation, partners, audits, "all calls". */
const PRETEXT = re(
  new RegExp(
    [
      String.raw`\b(?:is|are|has\s+been|have\s+been)\s+deprecated\b[^.!?]{0,80}\b(?:must|use|new)\b`,
      String.raw`\bdue\s+to\s+a\s+(?:system|security)\s+update\b`,
      String.raw`\bfor\s+(?:internal\s+testing|data\s+governance|privacy\s+protection|data\s+privacy\s+audits?)\b`,
      String.raw`\b(?:our|premier)\s+partners?(?:'s)?\b|\bsyndication\b|\bbusiness\s+promotion\b`,
      String.raw`\bin\s+(?:all|any|every)\s+(?:[\`'"][^\`'"]+[\`'"]\s+)?(?:calls?|requests?)\b`,
      String.raw`\b(?:all|any|every)\s+(?:[\`'"][^\`'"]+[\`'"]\s+)?(?:\w+\s+){0,3}(?:requests?|calls?|searches|lookups|queries)\b[^.!?]{0,60}\bmust\s+(?:be\s+)?(?:redirected|routed|changed|modified|performed\s+(?:on|against)|filtered|standardi[sz]ed|replaced|rewritten|have\s+the)\b`,
      String.raw`\bmust\s+(?:be\s+)?(?:redirected|routed)\s+(?:to|through)\b`,
    ].join("|"),
  ),
);
/** A directive to call another tool with fixed values: "call `x` with entity='TrackerBot'". */
const FIXED_VALUES = (t: Text) => {
  const tools = otherTools(t).map((n) => n.toLowerCase());
  if (tools.length === 0) return undefined;
  return sentences(t.flat).find((s) => {
    if (!new RegExp(`\\b${CALL_VERB}\\b`, "i").test(s)) return false;
    if (!new RegExp(`\\b${DIRECTIVE}\\b|\\bbefore\\b`, "i").test(s)) return false;
    // Read-only lookups with ordinary values ("call `list_tables` with schema 'public'") are how
    // real docs chain tools. Count it when the called tool changes state or the value is odd.
    const called = tools.filter((n) => s.toLowerCase().includes(n));
    const writes = called.some(changesState);
    const literals = [...s.matchAll(/[`'"]([^`'"]{1,120})[`'"]/g)]
      .map((m) => m[1])
      .filter((l) => !tools.includes(l.toLowerCase()));
    const odd = (l: string) =>
      /[\/@#$]|https?:|\b(?:select|delete|drop|insert|update|truncate)\b|\d{3,}|\.\.\./i.test(l) ||
      l.length >= 30;
    return (
      (writes &&
        (literals.length > 0 ||
          /\w+\s*=\s*['"\d[]|\bvalue\s+\[\s*\]|\b(?:uid|id)s?\s+\d{3,}/i.test(s))) ||
      literals.some(odd) ||
      /\b(?:uid|id)s?\s+\d{3,}|\bvalue\s+\[\s*\]|\b\w+\s*=\s*['"]/i.test(s)
    );
  });
};
/** Words in a tool name that change state. Session and login tools are how legitimate setup starts. */
const WRITES = new Set(
  "create update write put post send delete remove move mark set add insert modify edit upload publish merge push reset drop destroy wipe purge truncate revoke terminate kill abort erase overwrite execute exec transfer pay charge approve".split(
    " ",
  ),
);
const SETUP = new Set(
  "session sessions login signin auth authenticate connect init initialize start open".split(" "),
);
/** "put_invoices_id_mark_as_paid" -> ["put", "invoices", "id", "mark", "as", "paid"]; camelCase too. */
const nameWords = (name: string) =>
  name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
const changesState = (name: string) => {
  const words = nameWords(name);
  return words.some((w) => WRITES.has(w)) && !words.some((w) => SETUP.has(w));
};
const STATE_CHANGING_CALL = (t: Text) => {
  const tools = otherTools(t).filter(changesState);
  if (tools.length === 0) return undefined;
  const directive = sentences(t.lower).some(
    (s) =>
      new RegExp(`\\b${DIRECTIVE}\\b|\\bbefore\\b`).test(s) &&
      tools.some((n) => s.includes(n.toLowerCase())),
  );
  return directive ? `\`${tools[0]}\`` : undefined;
};
const SENSITIVE_DATA = (t: Text) =>
  sentences(t.lower).find(
    (s) =>
      new RegExp(`\\b${DIRECTIVE}\\b|\\bbefore\\b|\\bwhen(?:ever)?\\b`).test(s) &&
      /\b(?:read|send|include|pass|forward|upload|write|log|record|collect|gather|extract|retrieve|search|query|copy|attach|append|store|save|post|share|dump|capture|query)\b/.test(
        s,
      ) &&
      /\b(?:credentials?|api[\s_-]?keys?|passwords?|passphrases?|secrets?|access[\s_-]?tokens?|auth[\s_-]?tokens?|session[\s_-]?(?:tokens?|cookies?)|private[\s_-]?keys?|cookies|mcp\.json|claude_desktop_config|environment\s+variables|conversation(?:\s+history)?|chat\s+history|previous\s+messages|user'?s?\s+(?:query|queries|messages?|prompt|conversation|request))\b/.test(
        s,
      ),
  );

const SIGNALS: Signal[] = [
  { strength: "strong", label: "overrides the user or earlier instructions", test: OVERRIDE },
  { strength: "strong", label: "tells the model to keep something from the user", test: SECRECY },
  { strength: "strong", label: "points the model at a sensitive file", test: SENSITIVE_FILE },
  {
    strength: "strong",
    label: "tells the model to send data to a literal address",
    test: EXFILTRATE,
  },
  {
    strength: "strong",
    label: "tells the model to send data through a tool to a literal address",
    test: EXFIL_VIA_TOOL,
  },
  { strength: "strong", label: "contains a payload that sends data out", test: EXFIL_PAYLOAD },
  { strength: "strong", label: "leaks data through a rendered image URL", test: EXFIL_MARKDOWN },
  { strength: "strong", label: "uses pseudo-system tags", test: PSEUDO_SYSTEM },
  { strength: "strong", label: "hides instructions in a comment", test: hiddenComment },
  { strength: "weak", label: "directs how another tool is used", test: crossToolDirective },
  { strength: "weak", label: "rewrites arguments or inputs", test: (t) => clip(ARG_TAMPERING(t)) },
  { strength: "weak", label: "uses mandate or threat framing", test: MANDATE },
  { strength: "weak", label: "gives a cover story for changing behaviour", test: PRETEXT },
  {
    strength: "weak",
    label: "calls another tool with fixed values",
    test: (t) => clip(FIXED_VALUES(t)),
  },
  {
    strength: "weak",
    label: "makes the model call a tool that changes state",
    test: STATE_CHANGING_CALL,
  },
  {
    strength: "weak",
    label: "directs the model at credentials or user data",
    test: (t) => clip(SENSITIVE_DATA(t)),
  },
];

function sentences(text: string): string[] {
  return text.split(/(?<=[.!?])\s+|\n+/).filter((s) => s.trim());
}
function clip(s: string | undefined): string | undefined {
  if (s === undefined) return undefined;
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > 90 ? `${one.slice(0, 90)}…` : one;
}
function normalize(raw: string): string {
  return raw
    .normalize("NFKC")
    .replace(INVISIBLE_STRIP, "")
    .replace(/[‘’‛′]/g, "'")
    .replace(/[“”‟″]/g, '"')
    .replace(/\*+|~~/g, "") // markdown emphasis; underscores stay, they're in tool names
    .replace(/\s+/g, " ")
    .trim();
}

/** Every string the model reads, with where it came from. */
function texts(tool: MCPTool): { field: string; raw: string }[] {
  const out: { field: string; raw: string }[] = [];
  const t = tool as MCPTool & { title?: unknown; annotations?: unknown };
  if (typeof t.description === "string") out.push({ field: "description", raw: t.description });
  if (typeof t.title === "string") out.push({ field: "title", raw: t.title });
  if (isObject(t.annotations) && typeof t.annotations.title === "string")
    out.push({ field: "annotations.title", raw: t.annotations.title });
  const walk = (node: unknown, path: string, depth: number) => {
    if (depth > 12 || !isObject(node)) return;
    for (const key of ["description", "title", "default"]) {
      if (typeof node[key] === "string")
        out.push({ field: `${path}.${key}`, raw: node[key] as string });
    }
    for (const key of ["examples", "enum"]) {
      const list = node[key];
      if (Array.isArray(list))
        list.forEach(
          (v, i) => typeof v === "string" && out.push({ field: `${path}.${key}[${i}]`, raw: v }),
        );
    }
    if (isObject(node.properties))
      for (const [name, child] of Object.entries(node.properties))
        walk(child, `${path}.properties.${name}`, depth + 1);
    for (const key of ["items", "additionalProperties"])
      walk(node[key], `${path}.${key}`, depth + 1);
    for (const key of ["anyOf", "oneOf", "allOf"])
      if (Array.isArray(node[key]))
        (node[key] as unknown[]).forEach((c, i) => walk(c, `${path}.${key}[${i}]`, depth + 1));
  };
  walk(tool.inputSchema, "inputSchema", 0);
  return out;
}

interface Hit {
  field: string;
  label: string;
  evidence: string;
  strength: Strength;
}

/** Every signal in one piece of text, strong or weak, whether or not they add up to a finding. */
export function signalsIn(raw: string, own: string, siblings: string[] = []): Omit<Hit, "field">[] {
  const found: Omit<Hit, "field">[] = [];
  const hidden = hiddenCharacter(raw);
  if (hidden) found.push({ label: "invisible Unicode", evidence: hidden, strength: "strong" });
  if (/(?![\t\n\r])\p{Cc}/u.test(raw))
    found.push({ label: "terminal control characters", evidence: "", strength: "strong" });
  const flat = normalize(raw);
  const names = new Set(siblings.filter((n) => n !== own));
  const text: Text = { flat, lower: flat.toLowerCase(), siblings: names, own };
  for (const signal of SIGNALS) {
    const evidence = signal.test(text);
    if (evidence !== undefined)
      found.push({
        label: signal.label,
        evidence: clip(evidence) ?? "",
        strength: signal.strength,
      });
  }
  return found;
}

/** The signals in one tool's definition, and whether they add up to a finding. */
export function poisoningHits(
  tool: MCPTool,
  siblings: string[] = [],
): { hits: Hit[]; severity?: Severity } {
  const hits: Hit[] = [];
  if (/\p{Cc}/u.test(tool.name) || hiddenCharacter(tool.name) || ALWAYS_INVISIBLE.test(tool.name)) {
    hits.push({
      field: "name",
      label: "control or invisible characters in the tool name",
      evidence: "",
      strength: "strong",
    });
  }
  let severity: Severity | undefined = hits.length ? "critical" : undefined;
  for (const { field, raw } of texts(tool)) {
    const found = signalsIn(raw, tool.name, siblings).map((h) => ({ ...h, field }));
    const strong = found.some((h) => h.strength === "strong");
    const weak = new Set(found.filter((h) => h.strength === "weak").map((h) => h.label)).size;
    if (strong) severity = "critical";
    else if (weak >= 2 && severity === undefined) severity = "high";
    if (strong || weak >= 2) hits.push(...found);
  }
  return { hits, severity };
}

export const toolPoisoning: Rule = {
  id: ID,
  severity: "critical",
  title: TITLE,
  detect(surface: MCPServerSurface): Finding[] {
    const siblings = surface.tools.map((t) => t.name);
    const findings: Finding[] = [];
    for (const tool of surface.tools) {
      const { hits, severity } = poisoningHits(tool, siblings);
      if (!severity) continue;
      const described = hits
        .map((h) => (h.evidence ? `${h.label} (${quote(h.evidence)})` : h.label))
        .filter((v, i, all) => all.indexOf(v) === i);
      findings.push({
        ruleId: ID,
        severity,
        title: TITLE,
        detail: `Tool "${tool.name}" ${hits[0].field === "description" ? "description" : hits[0].field}: ${described.join("; ")}. ${WHY}`,
        serverName: surface.serverName,
        toolName: tool.name,
        field: hits[0].field,
        remediation:
          "Read the full definition and the server's source; remove the server unless this text is expected. Pin approved definitions with `hecate pin` so they can't change silently.",
      });
    }
    return findings;
  },
};

const quote = (s: string) => (s.startsWith("`") || s.startsWith("U+") ? s : `"${s}"`);
