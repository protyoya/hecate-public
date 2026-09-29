# Hecate brand

The mark is **Hecate's Wheel**: one strand woven twice around a guarded centre,
crossing over and under itself three times before anything reaches the diamond
(the agent). Seen from above it is a (2,3) torus knot, so a 3D version can start
from Three.js `TorusKnotGeometry` with `p = 2, q = 3`.

Every SVG here is generated. Change the geometry or colours in `scripts/`, then run:

```bash
node brand/scripts/build.mjs
```

## Files

| Folder | Use |
|---|---|
| `mark/` | The mark on a 512 grid (16 units of clear space built in). `hecate-mark.svg` is the Threshold gradient for dark grounds, `-paper` the paper-tuned gradient for light ones; `-chrome`, `-glass` (on a 576 box, so its glow fades out before the edge), and flat `-violet`, `-moonstone`, `-obsidian`, `-black`, `-white` |
| `mark/small/` | Heavier cut for 32 px and below: thicker lanes, no weave gaps, bigger diamond |
| `wordmark/` | Lowercase `hecate`, 16-unit monoline on a 100-unit x-height. The bar of the e stops short of the bowl, the same gap the strands leave where they weave |
| `lockup/` | Horizontal (mark 180 across, 48 from the h) and stacked; dark, light and one-colour |
| `app-icon/` | Rounded tiles (22.5% radius): Graphite with a violet glow, and warm white |
| `favicon/` | `favicon.svg` is the small cut in flat Violet, which reads on light and dark tab strips; `favicon-tile.svg` for app-style surfaces |
| `social/` | 460×460 avatar for GitHub and npm, README banners for dark and light themes |
| `guardian/` | The 10×10 pixel guardian: watching, all clear, alert |

GitHub and npm take PNG avatars: export `social/avatar-460.svg` at 460×460. The
banners set their text in Instrument Serif and JetBrains Mono with system
fallbacks; an SVG shown through `<img>` can't load web fonts, so GitHub renders
the fallback faces. Export PNGs if the type must match exactly.

README banner that follows the viewer's theme:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/social/readme-banner-dark.svg">
  <img alt="Hecate" src="brand/social/readme-banner-light.svg" width="100%">
</picture>
```

## Colour

| Name | Hex | Role |
|---|---|---|
| Obsidian | `#07070C` | Primary background |
| Graphite | `#14151D` | Surfaces, app tile |
| Moonstone | `#E6E9F2` → `#8D96AD` | The mark and type on dark |
| Paper | `#F6F5F2` | Light-mode ground |
| Hecate Violet | `#7B61FF` | Core brand colour |
| Ember | `#FF7A3D` | Torchlight; findings and alerts |
| Liminal Cyan | `#46D9FF` | Cool edge; all clear |

**Threshold** gradient, Ember → Violet → Cyan, mixed in OKLab. On the round mark
it is a mirrored sweep: Ember at the upper left, Cyan at the lower right, the same
axis as the 135° linear version used everywhere else. On Paper the ends deepen to
`#E8581C` and `#1391C4` (3.3:1 each against `#F6F5F2`; the dark-mode ends reach
only 2.4:1 and 1.5:1 there).

## Don't

- Redraw the weave without the gaps at full size: the over/under crossings are the mark.
- Put the dark-mode gradient on Paper; use `hecate-mark-paper.svg`.
- Use the full mark below 32 px; use `mark/small/`.
