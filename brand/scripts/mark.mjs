// Hecate's Wheel. One strand woven twice around a guarded centre,
// a (2,3) torus knot seen from above: two lanes that swap at three crossings.
import { C, D2R, P, THRESHOLD, f, ramp } from "./lib.mjs";

/** Lane sign along the strand: +1 outer lane, -1 inner lane, cosine S-bends at crossings. */
function laneSign(u, delta) {
  const v = (((u - 60) % 720) + 720) % 720;
  const sign = Math.floor(v / 120) % 2 === 0 ? 1 : -1;
  const p = v % 120;
  const half = delta / 2;
  if (p < half) return -sign * Math.cos((Math.PI * (p + half)) / delta);
  if (p > 120 - half) return sign * Math.cos((Math.PI * (p - (120 - half))) / delta);
  return sign;
}

export function geometry({ Ro, Ri, w, delta, gap, gem, cut = true }) {
  const Rm = (Ro + Ri) / 2;
  const a = (Ro - Ri) / 2;
  const rho = (u) => Rm + a * laneSign(u, delta);
  // Slope at a crossing, and how much of the under strand to cut away there.
  const k = (a * Math.PI) / (delta * D2R);
  const psi = Math.atan(k / Rm);
  const chi = 2 * psi;
  const L = ((w / 2) * (1 + Math.cos(chi)) + gap) / Math.sin(chi) + 2;
  const du = (L * Math.cos(psi)) / Rm / D2R;
  // Crossings at u = 60, 180, 300, 420, 540, 660; over/under alternate, the
  // strand is cut at its under-visits (180, 420, 660): three identical paths.
  const segs = cut ? [180, 420, 660].map((u0) => [u0 + du, u0 + 240 - du]) : [[0, 721]];
  return { Ro, Ri, w, gem, rho, segs, chiDeg: chi / D2R, du };
}

const xy = (u, r) => [r * Math.sin(u * D2R), -r * Math.cos(u * D2R)];

/** Path for u in [u0,u1]: exact arcs on the lanes, 1-degree polyline in the S-bends. */
export function pathU(g, u0, u1, off = 0, step = 1) {
  const n = Math.max(2, Math.ceil((u1 - u0) / step) + 1);
  const pts = [];
  for (let i = 0; i < n; i++) {
    const u = u0 + ((u1 - u0) * i) / (n - 1);
    pts.push([u, g.rho(u) + off]);
  }
  let d = `M${P(...xy(...pts[0]))}`;
  let i = 1;
  while (i < pts.length) {
    if (Math.abs(pts[i][1] - pts[i - 1][1]) < 1e-6) {
      let j = i;
      while (j + 1 < pts.length && Math.abs(pts[j + 1][1] - pts[j][1]) < 1e-6) j++;
      const r = pts[j][1];
      const span = pts[j][0] - pts[i - 1][0];
      d += `A${f(r)} ${f(r)} 0 ${span > 180 ? 1 : 0} 1 ${P(...xy(pts[j][0], r))}`;
      i = j + 1;
    } else {
      d += `L${P(...xy(...pts[i]))}`;
      i++;
    }
  }
  return d;
}

const gemPts = ({ gh, gw }) => [
  [0, -gh],
  [gw, 0],
  [0, gh],
  [-gw, 0],
];
const poly = (pts) => pts.map((p) => P(...p)).join(" ");

export function gemFlat(g, fill) {
  return `<polygon points="${poly(gemPts(g.gem))}" fill="${fill}"/>`;
}
/** Four facets split on both diagonals: a small cut jewel. */
export function gemFacets(g, [tl, tr, bl, br]) {
  const [t, r, b, l] = gemPts(g.gem);
  const o = [0, 0];
  return (
    `<polygon points="${poly([t, o, l])}" fill="${tl}"/>` +
    `<polygon points="${poly([t, r, o])}" fill="${tr}"/>` +
    `<polygon points="${poly([l, o, b])}" fill="${bl}"/>` +
    `<polygon points="${poly([o, r, b])}" fill="${br}"/>`
  );
}

export function strandsFlat(g, stroke, extra = "") {
  const paths = g.segs.map(([a, b]) => `<path d="${pathU(g, a, b)}"/>`).join("");
  return `<g fill="none" stroke="${stroke}" stroke-width="${g.w}" stroke-linecap="butt" stroke-linejoin="round"${extra}>${paths}</g>`;
}

/** Strands split into short pieces, each coloured by colorAt(phiDeg, u). Emulates a conic sweep. */
export function strandsPieces(g, colorAt, { off = 0, width = g.w, bucket = 3, attrs = "" } = {}) {
  let out = "";
  for (const [a, b] of g.segs) {
    let u = a;
    while (u < b - 1e-6) {
      const next = Math.min(b, (Math.floor(u / bucket) + 1) * bucket);
      const end = Math.min(b, next + 0.7); // overlap the next piece: no hairline seams
      const mid = (u + next) / 2;
      const phi = ((mid % 360) + 360) % 360;
      out += `<path d="${pathU(g, u, end, off, 1)}" stroke="${colorAt(phi, mid)}"/>`;
      u = next;
    }
  }
  return `<g fill="none" stroke-width="${f(width)}" stroke-linecap="butt" stroke-linejoin="round"${attrs}>${out}</g>`;
}

// Mirrored conic sweep: Ember at the upper left (315deg), Cyan at the lower right (135deg),
// Violet on the flanks; matches the 135deg linear gradient used elsewhere.
export function sweepT(phi) {
  const d = Math.abs(((((phi - 315) % 360) + 540) % 360) - 180); // 0 at 315deg, 180 at 135deg
  const x = d / 180;
  return 0.5 * x + 0.25 * (1 - Math.cos(Math.PI * x));
}
export const thresholdAt =
  (stops = THRESHOLD) =>
  (phi) =>
    ramp(stops, sweepT(phi));

export function chromeAt(g) {
  return (phi, u) => {
    const s = (g.rho(u) - (g.Ro + g.Ri) / 2) / ((g.Ro - g.Ri) / 2);
    const L =
      0.64 +
      0.22 * Math.cos(2 * (phi - 320) * D2R) +
      0.1 * Math.cos((4 * phi + 40) * D2R) +
      0.06 * s;
    return ramp(["#353A48", "#6E778C", "#B7BFD0", "#EEF1F7", "#FFFFFF"], L);
  };
}

// ---------- full renders ----------
export const GEM_COOL = ["#F7F9FF", "#BFEFFF", "#A996FF", "#6A50F0"];
export const GEM_CHROME = ["#FFFFFF", "#CDD3E0", "#9CA5B9", "#5A6276"];

export function renderFlat(g, color) {
  return strandsFlat(g, color) + gemFlat(g, color);
}
export function renderThreshold(g, stops = THRESHOLD, gem = GEM_COOL) {
  return strandsPieces(g, thresholdAt(stops)) + gemFacets(g, gem);
}
/** Points along the strand, offset `off` units along its true normal (positive = away from the centre). */
function offsetPoints(g, u0, u1, off, step = 0.5) {
  const at = (u) => {
    const r = g.rho(u);
    return [r * Math.sin(u * D2R), -r * Math.cos(u * D2R)];
  };
  const n = Math.max(2, Math.ceil((u1 - u0) / step) + 1);
  const pts = [];
  for (let i = 0; i < n; i++) {
    const u = u0 + ((u1 - u0) * i) / (n - 1);
    const p = at(u);
    const a = at(u - 0.05);
    const b = at(u + 0.05);
    const tl = Math.hypot(b[0] - a[0], b[1] - a[1]);
    let nx = -(b[1] - a[1]) / tl;
    let ny = (b[0] - a[0]) / tl;
    if (nx * p[0] + ny * p[1] < 0) {
      nx = -nx;
      ny = -ny;
    }
    pts.push([p[0] + nx * off, p[1] + ny * off]);
  }
  return pts;
}
/** A line that runs inside each strand, parallel to its edges. */
export function strandsOffset(g, off, width, color, opacity) {
  const d = g.segs
    .map(
      ([a, b]) =>
        `M${offsetPoints(g, a, b, off)
          .map((p) => P(...p))
          .join("L")}`,
    )
    .join("");
  return `<path d="${d}" fill="none" stroke="${color}" stroke-width="${f(width)}" stroke-opacity="${opacity}" stroke-linecap="butt" stroke-linejoin="round"/>`;
}
/** The strands themselves as a mask, inset a little: whatever is drawn under it stays inside the strands. */
export function bandMask(g, id, inset = 1.5) {
  return `<mask id="${id}" maskUnits="userSpaceOnUse" x="-320" y="-320" width="640" height="640">${strandsFlat({ ...g, w: g.w - 2 * inset }, "#FFFFFF")}</mask>`;
}

export function chromeDefs(g) {
  return bandMask(g, "band");
}
export function renderChrome(g) {
  const w = g.w;
  const highlight = strandsOffset(g, w * 0.2, w * 0.12, "#FFFFFF", 0.5);
  const shadow = strandsOffset(g, -w * 0.3, w * 0.16, "#1A1D27", 0.35);
  // Highlight and shadow sit under the strand mask, so they end exactly where each strand is cut.
  return `${strandsPieces(g, chromeAt(g))}<g mask="url(#band)">${highlight}${shadow}</g>${gemFacets(g, GEM_CHROME)}`;
}
// The glass mark needs room for its glow: draw it on a 576 box instead of 512.
export const GLASS_VIEW = { vb: "-288 -288 576 576", w: 576, h: 576 };
export function glassDefs(g) {
  return [
    `<filter id="glow" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="13"/></filter>`,
    `<filter id="soft" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="22"/></filter>`,
    `<radialGradient id="gemglow" cx="0" cy="0" r="120" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#BFEFFF" stop-opacity="0.9"/><stop offset="1" stop-color="#7B61FF" stop-opacity="0"/></radialGradient>`,
    `<linearGradient id="frost" x1="0" y1="-240" x2="0" y2="240" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#FFFFFF" stop-opacity="0.22"/><stop offset="0.5" stop-color="#FFFFFF" stop-opacity="0.08"/><stop offset="1" stop-color="#FFFFFF" stop-opacity="0.14"/></linearGradient>`,
    bandMask(g, "band"),
  ].join("");
}
export function renderGlass(g) {
  const w = g.w;
  const tint = thresholdAt();
  const highlights = [
    strandsOffset(g, w * 0.24, 10, "#FFFFFF", 0.1),
    strandsOffset(g, w * 0.24, 2.5, "#FFFFFF", 0.85),
    strandsOffset(g, -w * 0.3, 1.75, "#FFFFFF", 0.3),
  ].join("");
  return [
    `<g filter="url(#glow)" opacity="0.7">${strandsPieces(g, tint)}</g>`,
    `<circle r="118" fill="url(#gemglow)" filter="url(#soft)"/>`,
    strandsPieces(g, tint, { attrs: ' opacity="0.62"' }),
    strandsFlat(g, "url(#frost)"),
    // Highlights sit under the strand mask, so they end exactly where each strand is cut.
    `<g mask="url(#band)">${highlights}</g>`,
    gemFacets(g, ["#FFFFFF", "#DDF7FF", "#C7BCFF", "#9C88FF"]),
  ].join("");
}

export const FULL = { Ro: 221, Ri: 157, w: 38, delta: 40, gap: 22, gem: { gh: 64, gw: 46 } };
export const SMALL = {
  Ro: 212,
  Ri: 116,
  w: 56,
  delta: 50,
  gap: 0,
  gem: { gh: 52, gw: 40 },
  cut: false,
};
