// Writes every SVG in brand/. Run: node brand/scripts/build.mjs
import { C, THRESHOLD, THRESHOLD_PAPER, f, save, svg } from "./lib.mjs";
import * as M from "./mark.mjs";
import { word } from "./wordmark.mjs";

const full = M.geometry(M.FULL);
const small = M.geometry(M.SMALL);
const GEM_PAPER = ["#A08FFF", "#3AA7D6", "#6A50F0", "#4630C4"];
const written = [];
const put = (name, body, opts) => written.push(save(name, svg(body, opts)));
const box = (vb, w, h, body, defs = "") =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vb}" width="${w}" height="${h}">${defs ? `<defs>${defs}</defs>` : ""}${body}</svg>\n`;
const placed = (body, x, y, scale) =>
  `<g transform="translate(${f(x)} ${f(y)}) scale(${f(scale)})">${body}</g>`;
const markDark = (g = full) => M.renderThreshold(g, THRESHOLD);
const markLight = (g = full) => M.renderThreshold(g, THRESHOLD_PAPER, GEM_PAPER);

// ---------- mark ----------
put("mark/hecate-mark.svg", markDark());
put("mark/hecate-mark-paper.svg", markLight());
put("mark/hecate-mark-chrome.svg", M.renderChrome(full), { defs: M.chromeDefs(full) });
// Glass sits on a 576 box so its glow fades out before the edge.
put("mark/hecate-mark-glass.svg", M.renderGlass(full), {
  ...M.GLASS_VIEW,
  defs: M.glassDefs(full),
});
put("mark/hecate-mark-violet.svg", M.renderFlat(full, C.violet));
put("mark/hecate-mark-moonstone.svg", M.renderFlat(full, C.moonHi));
put("mark/hecate-mark-obsidian.svg", M.renderFlat(full, C.obsidian));
put("mark/hecate-mark-black.svg", M.renderFlat(full, "#000000"));
put("mark/hecate-mark-white.svg", M.renderFlat(full, "#FFFFFF"));
put("mark/small/hecate-mark-small.svg", markDark(small));
put("mark/small/hecate-mark-small-paper.svg", markLight(small));
put("mark/small/hecate-mark-small-violet.svg", M.renderFlat(small, C.violet));
put("mark/small/hecate-mark-small-obsidian.svg", M.renderFlat(small, C.obsidian));
put("mark/small/hecate-mark-small-white.svg", M.renderFlat(small, "#FFFFFF"));

// ---------- favicon ----------
put("favicon/favicon.svg", M.renderFlat(small, C.violet), { w: 32, h: 32 });
const tileDark = `<linearGradient id="tile" x1="0" y1="-256" x2="0" y2="256" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#1F202C"/><stop offset="1" stop-color="#101119"/></linearGradient><radialGradient id="glow" cx="0" cy="-20" r="300" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="${C.violet}" stop-opacity="0.26"/><stop offset="1" stop-color="${C.violet}" stop-opacity="0"/></radialGradient>`;
put(
  "favicon/favicon-tile.svg",
  `<rect x="-256" y="-256" width="512" height="512" rx="116" fill="url(#tile)"/>${placed(markDark(small), 0, 0, 0.74)}`,
  { defs: tileDark, w: 32, h: 32 },
);

// ---------- app icon ----------
put(
  "app-icon/app-icon-dark.svg",
  `<rect x="-256" y="-256" width="512" height="512" rx="115" fill="url(#tile)"/><rect x="-256" y="-256" width="512" height="512" rx="115" fill="url(#glow)"/><rect x="-255.5" y="-255.5" width="511" height="511" rx="114.5" fill="none" stroke="#FFFFFF" stroke-opacity="0.06"/>${placed(markDark(), 0, 0, 0.64)}`,
  { defs: tileDark },
);
put(
  "app-icon/app-icon-light.svg",
  `<rect x="-256" y="-256" width="512" height="512" rx="115" fill="url(#tile)"/><rect x="-255.5" y="-255.5" width="511" height="511" rx="114.5" fill="none" stroke="${C.obsidian}" stroke-opacity="0.06"/>${placed(markLight(), 0, 0, 0.64)}`,
  {
    defs: `<linearGradient id="tile" x1="0" y1="-256" x2="0" y2="256" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#FFFFFF"/><stop offset="1" stop-color="#EFEDE8"/></linearGradient>`,
  },
);

// ---------- wordmark and lockups ----------
// Word: x-height 100, ascender 150, 652 wide. Horizontal lockup: mark 180 across, 48 from the h.
const wm = (ink) => box("-8 -158 668 170", 668, 170, word(ink));
written.push(save("wordmark/hecate-wordmark-moonstone.svg", wm(C.moonHi)));
written.push(save("wordmark/hecate-wordmark-obsidian.svg", wm(C.obsidian)));
written.push(save("wordmark/hecate-wordmark-white.svg", wm("#FFFFFF")));
const horizontal = (mark, ink) => placed(mark, 90, -66, 90 / 240) + word(ink, 228, 0);
const stacked = (mark, ink) => placed(mark, 326, -356, 150 / 240) + word(ink);
const H = (body) => box("-8 -164 896 196", 896, 196, body);
const V = (body) => box("-8 -514 668 526", 668, 526, body);
written.push(save("lockup/hecate-lockup-horizontal-dark.svg", H(horizontal(markDark(), C.moonHi))));
written.push(
  save("lockup/hecate-lockup-horizontal-light.svg", H(horizontal(markLight(), C.obsidian))),
);
written.push(
  save(
    "lockup/hecate-lockup-horizontal-obsidian.svg",
    H(horizontal(M.renderFlat(full, C.obsidian), C.obsidian)),
  ),
);
written.push(
  save(
    "lockup/hecate-lockup-horizontal-white.svg",
    H(horizontal(M.renderFlat(full, "#FFFFFF"), "#FFFFFF")),
  ),
);
written.push(save("lockup/hecate-lockup-stacked-dark.svg", V(stacked(markDark(), C.moonHi))));
written.push(save("lockup/hecate-lockup-stacked-light.svg", V(stacked(markLight(), C.obsidian))));

// ---------- avatar and README banners ----------
const grain = `<filter id="grain" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="3" stitchTiles="stitch"/><feColorMatrix type="matrix" values="0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 1.4 0 0 0 -0.55"/></filter>`;
const violetGlow = (id, a0, a1) =>
  `<radialGradient id="${id}"><stop offset="0" stop-color="${C.violet}" stop-opacity="${a0}"/><stop offset="0.58" stop-color="${C.violet}" stop-opacity="${a1}"/><stop offset="1" stop-color="${C.violet}" stop-opacity="0"/></radialGradient>`;
written.push(
  save(
    "social/avatar-460.svg",
    box(
      "0 0 460 460",
      460,
      460,
      `<rect width="460" height="460" fill="${C.obsidian}"/><circle cx="230" cy="230" r="305" fill="url(#glow)"/><rect width="460" height="460" filter="url(#grain)" opacity="0.12"/>${placed(markDark(), 230, 230, 284 / 512)}`,
      violetGlow("glow", 0.28, 0.06) + grain,
    ),
  ),
);
function banner(dark) {
  const ink = dark ? "#F2F4F8" : C.obsidian;
  const s = 540 / 896; // lockup at 540 wide, centred on y 200
  const back = dark
    ? `<rect width="1280" height="400" fill="${C.obsidian}"/><circle cx="250" cy="170" r="410" fill="url(#glow)"/><rect width="1280" height="400" filter="url(#grain)" opacity="0.12"/>`
    : `<rect width="1280" height="400" fill="${C.paper}"/>`;
  const lockup = dark ? horizontal(markDark(), C.moonHi) : horizontal(markLight(), C.obsidian);
  const serif = "'Instrument Serif', 'Iowan Old Style', Georgia, serif";
  const mono = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
  const text =
    `<text x="714" y="152" font-family="${serif}" font-size="34" fill="${ink}">Security scanner and runtime guard</text>` +
    `<text x="714" y="192" font-family="${serif}" font-size="34" fill="${ink}">for MCP servers and AI agents.</text>` +
    `<rect x="714" y="218" width="336" height="42" rx="10" fill="${dark ? C.graphite : "#ECEAE4"}" stroke="${dark ? "#FFFFFF" : C.obsidian}" stroke-opacity="${dark ? 0.08 : 0.06}"/>` +
    `<text x="728" y="245" font-family="${mono}" font-size="15" fill="${dark ? C.moonHi : C.graphite}">npx hecate-mcp@beta scan .mcp.json</text>`;
  return box(
    "0 0 1280 400",
    1280,
    400,
    back + placed(lockup, 96 + 8 * s, 200 - 59 + 164 * s, s) + text,
    dark ? violetGlow("glow", 0.2, 0.05) + grain : "",
  );
}
written.push(save("social/readme-banner-dark.svg", banner(true)));
written.push(save("social/readme-banner-light.svg", banner(false)));

// ---------- guardian emote ----------
const RING = [
  "...####...",
  ".##....##.",
  ".#......#.",
  "#........#",
  "#........#",
  "#........#",
  "#........#",
  ".#......#.",
  ".##....##.",
  "...####...",
];
const FACES = {
  watching: {
    ring: C.moonHi,
    face: C.violet,
    cells: [
      [3, 4],
      [3, 5],
      [4, 3],
      [4, 4],
      [4, 5],
      [4, 6],
      [5, 3],
      [5, 4],
      [5, 5],
      [5, 6],
      [6, 4],
      [6, 5],
    ],
  },
  clear: {
    ring: C.cyan,
    face: C.cyan,
    cells: [
      [4, 2],
      [5, 1],
      [5, 3],
      [4, 7],
      [5, 6],
      [5, 8],
      [7, 4],
      [7, 5],
    ],
  },
  alert: {
    ring: C.ember,
    face: C.ember,
    cells: [
      [2, 4],
      [2, 5],
      [3, 4],
      [3, 5],
      [4, 4],
      [4, 5],
      [5, 4],
      [5, 5],
      [7, 4],
      [7, 5],
    ],
  },
};
for (const [state, { ring, face, cells }] of Object.entries(FACES)) {
  let rects = "";
  RING.forEach((row, y) => {
    [...row].forEach((ch, x) => {
      if (ch === "#") rects += `<rect x="${x}" y="${y}" width="1" height="1" fill="${ring}"/>`;
    });
  });
  for (const [y, x] of cells)
    rects += `<rect x="${x}" y="${y}" width="1" height="1" fill="${face}"/>`;
  written.push(
    save(
      `guardian/guardian-${state}.svg`,
      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" width="120" height="120" shape-rendering="crispEdges">${rects}</svg>\n`,
    ),
  );
}

console.log(`${written.length} files`);
