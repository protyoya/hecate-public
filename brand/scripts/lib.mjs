// Shared helpers for the Hecate logo generators.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export const D2R = Math.PI / 180;
/** The brand/ folder: every file is written relative to it. */
export const OUT = new URL("../", import.meta.url).pathname;

export const f = (n) => {
  const r = Math.round(n * 100) / 100;
  return (Object.is(r, -0) ? 0 : r).toString();
};
export const P = (x, y) => `${f(x)} ${f(y)}`;

// Brand palette
export const C = {
  obsidian: "#07070C",
  graphite: "#14151D",
  moonHi: "#E6E9F2",
  moonLo: "#8D96AD",
  violet: "#7B61FF",
  ember: "#FF7A3D",
  cyan: "#46D9FF",
  paper: "#F6F5F2",
  // Paper-tuned ends of the Threshold gradient (clear 3:1 on #F6F5F2)
  emberDeep: "#E8581C",
  cyanDeep: "#1391C4",
};

// sRGB <-> OKLab, so gradient midpoints stay vivid instead of going muddy.
const toLin = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const toSrgb = (c) => (c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055);
export function hexToOklab(hex) {
  const h = hex.replace("#", "");
  const [r, g, b] = [0, 2, 4].map((i) => toLin(Number.parseInt(h.slice(i, i + 2), 16) / 255));
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ];
}
export function oklabToHex([L, A, B]) {
  const l = (L + 0.3963377774 * A + 0.2158037573 * B) ** 3;
  const m = (L - 0.1055613458 * A - 0.0638541728 * B) ** 3;
  const s = (L - 0.0894841775 * A - 1.291485548 * B) ** 3;
  const rgb = [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ];
  const hex = rgb.map((v) =>
    Math.round(Math.max(0, Math.min(1, toSrgb(v))) * 255)
      .toString(16)
      .padStart(2, "0"),
  );
  return `#${hex.join("")}`;
}
/** Colour at t in [0,1] along evenly spaced hex stops, mixed in OKLab. */
export function ramp(stops, at) {
  const t = Math.max(0, Math.min(1, at));
  const n = stops.length - 1;
  const i = Math.min(n - 1, Math.floor(t * n));
  const u = t * n - i;
  const a = hexToOklab(stops[i]);
  const b = hexToOklab(stops[i + 1]);
  return oklabToHex(a.map((v, k) => v + (b[k] - v) * u));
}
export const THRESHOLD = [C.ember, C.violet, C.cyan];
export const THRESHOLD_PAPER = [C.emberDeep, C.violet, C.cyanDeep];

export function svg(body, { vb = "-256 -256 512 512", w = 512, h = 512, defs = "" } = {}) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vb}" width="${w}" height="${h}">${defs ? `<defs>${defs}</defs>` : ""}${body}</svg>\n`;
}
export function save(name, content) {
  mkdirSync(dirname(OUT + name), { recursive: true });
  writeFileSync(OUT + name, content);
  return name;
}
