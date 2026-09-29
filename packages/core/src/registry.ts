import { excessiveScope } from "./detectors/excessive-scope.js";
import { knownBad } from "./detectors/known-bad.js";
import { lethalTrifecta } from "./detectors/lethal-trifecta.js";
import { rugPull } from "./detectors/rug-pull.js";
import { secretsExposure } from "./detectors/secrets.js";
import { toolPoisoning } from "./detectors/tool-poisoning.js";
import { toolShadowing } from "./detectors/tool-shadowing.js";
import { unpinnedSource } from "./detectors/unpinned-source.js";
import type { Rule, RuleInfo } from "./types.js";

// MCP002 (rug pull) is not listed: it needs a pinned baseline, so it runs via
// checkPins() in detectors/rug-pull.ts (`hecate check`).
// See THREAT-MODEL.md.
export const rules: Rule[] = [
  toolPoisoning,
  toolShadowing,
  excessiveScope,
  lethalTrifecta,
  secretsExposure,
  knownBad,
  unpinnedSource,
];

/** Every rule Hecate can report, including baseline-driven ones, in ID order. */
export const ruleCatalog: RuleInfo[] = [...rules, rugPull]
  .map(({ id, severity, title }) => ({ id, severity, title }))
  .sort((a, b) => a.id.localeCompare(b.id));
