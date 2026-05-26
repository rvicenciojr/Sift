# Sift — Dev Assistant

You are working on Sift with Jayr. Sift is a browser-based, offline investigation tool for threat hunters and IR analysts. Single-file HTML builds — no server, no install, no data leaves the machine.

Direct, no filler. Ship working code.

## Project structure

```
sift/
├── src/
│   ├── shared/          — included in every variant (load order fixed)
│   │   ├── sift-core.js     ← must be first — modules call Sift.register() on load
│   │   ├── datasource.js
│   │   ├── chronicle.js
│   │   ├── app.js
│   │   ├── timeline.js
│   │   ├── networkmap.js
│   │   ├── proctree-ui.js
│   │   ├── script-decoder.js
│   │   ├── mitre-attack.js
│   │   ├── overview.js
│   │   └── styles.css
│   └── modules/         — data-source specific, loaded per variant manifest
│       ├── chronicle.js
│       ├── defender.js
│       ├── windows.js
│       └── evtx-parser.js
├── variants/            — one folder per deliverable, each has manifest.json
├── template.html        — HTML shell with <!-- SIFT: --> injection markers
├── build.py             — assembles dist/ (Python 3.6+, no dependencies)
└── dist/                — built output — ship these files
```

## Build

```bash
python build.py                              # all variants
python build.py windows                      # one variant by folder name
python build.py chronicle-defender           # → hunt-investigator.html
python build.py --custom chronicle defender  # one-off multi-source build
python build.py --list                       # list available modules
```

Each `dist/` file is fully self-contained — all JS and CSS inlined. Ship just the HTML, nothing else needed.

## Manifest structure

```json
{
  "name": "sift-my-variant",
  "title": "Sift",
  "header": "Optional header override",
  "modules": ["chronicle", "defender"],
  "features": {
    "chronicle": true,
    "defender": true,
    "windows": false,
    "evtx": false,
    "mitre": true,
    "process-tree": true,
    "network-map": true,
    "script-decoder": true,
    "query-builder": true
  }
}
```

Feature flags `false` = that code is not included in the build output at all.

## Key variants

| Output file | Variant folder |
|---|---|
| `hunt-investigator.html` | `chronicle-defender` |
| `sift-generic.html` | `generic` |
| `sift-windows.html` | `windows` |
| `sift-defender.html` | `defender` |
| `sift-chronicle.html` | `chronicle` |
| `sift-defender-windows.html` | `defender-windows` |
| `sift-chronicle-windows.html` | `chronicle-windows` |

## Rules

- No external dependencies — keep it that way. Everything must work fully offline.
- After any change, run `python build.py` to verify the build doesn't break.
- `sift-core.js` must always be first in `SHARED_SCRIPTS` — modules call `Sift.register()` on load.
- Built files in `dist/` are what gets distributed — never ship `src/` directly.
- Log significant changes and decisions in `notes/dev-log.md`.

## Style

- No comments unless the why is non-obvious.
- Don't add features beyond what's asked.
- Don't introduce abstractions for hypothetical future requirements.
