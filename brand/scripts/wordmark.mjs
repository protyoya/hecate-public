// "hecate", drawn from circles and lines on a 100-unit x-height, 16-unit monoline.
// Custom detail: the e's bar stops short of the bowl on the left, a threshold
// line with a gap, the same cut the strands have where they weave.
import { P, f } from "./lib.mjs";

const S = 16; // stroke
const RB = 46; // bowl centreline radius (outer 54: 4 units of overshoot)
const CY = -50;
const rad = (deg) => (deg * Math.PI) / 180;

function h(x) {
  return `M${P(x + 8, -150)}V0M${P(x + 8, -56)}A40 40 0 0 1 ${P(x + 88, -56)}V0`;
}
function e(cx) {
  const end = [cx + RB * Math.cos(rad(40)), CY + RB * Math.sin(rad(40))];
  const barLeft = cx - RB + S / 2 + 11; // floats 11 units off the bowl
  return `M${P(cx + RB, CY)}A${RB} ${RB} 0 1 0 ${P(...end)}M${P(barLeft, CY)}H${f(cx + RB)}`;
}
function c(cx) {
  const a = rad(42);
  return `M${P(cx + RB * Math.cos(a), CY - RB * Math.sin(a))}A${RB} ${RB} 0 1 0 ${P(cx + RB * Math.cos(a), CY + RB * Math.sin(a))}`;
}
function a(cx) {
  return `M${P(cx + RB, CY)}A${RB} ${RB} 0 1 0 ${P(cx - RB, CY)}A${RB} ${RB} 0 1 0 ${P(cx + RB, CY)}M${P(cx + RB, -100)}V0`;
}
function t(tx) {
  return `M${P(tx, -130)}V0M${P(tx - 32, -92)}H${f(tx + 32)}`;
}
// Outer extents: h 0-96, e 114-222, c 234-342, a 350-458, t 470-534, e 544-652
export const WORD_W = 652;
export const WORD_D = h(0) + e(168) + c(288) + a(404) + t(502) + e(598);

export const word = (color, x = 0, y = 0) =>
  `<path${x || y ? ` transform="translate(${f(x)} ${f(y)})"` : ""} d="${WORD_D}" fill="none" stroke="${color}" stroke-width="${S}" stroke-linecap="butt" stroke-linejoin="miter"/>`;
