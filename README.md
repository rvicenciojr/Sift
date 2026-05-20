# Sift

Browser-based threat hunting and incident response investigation tool. Works completely offline — no install, no server, no dependencies. Drop a log file in, start hunting.

## For analysts (using the tool)

1. Get the right HTML file for your log source (see table below)
2. Open it in **Chrome** or **Edge**
3. Drag and drop your log file onto the page

That's it. One file, nothing else needed.

### Which file do I use?

| File | Use when you have |
|---|---|
| `sift-chronicle-defender.html` | Google Chronicle exports or Microsoft Defender for Endpoint CSVs |
| `sift-windows.html` | Windows Security Event Log CSVs or `.evtx` files |
| `sift-chronicle.html` | Google Chronicle / UDM exports only |
| `sift-defender.html` | Microsoft Defender for Endpoint only |
| `sift-defender-windows.html` | Defender CSVs **and** Windows Event Logs in the same investigation |
| `sift-chronicle-windows.html` | Chronicle CSVs **and** Windows Event Logs in the same investigation |

### Supported file formats

- `.csv` — exported from Chronicle, Defender, or a Windows Security Event Log query
- `.evtx` — Windows Event Log binary format (Windows variants only)

---

## Features

- **Overview dashboard** — auto-detects log source and builds a triage view: event frequency timeline, top offenders, attack chain sequence, MITRE ATT&CK coverage
- **Process Tree** — visualizes parent/child process relationships across the dataset
- **Network Map** — plots remote IPs and connection patterns
- **Script Decoder** — decodes and syntax-highlights encoded PowerShell, base64, and obfuscated commands
- **Query Builder** — builds Chronicle, KQL (Defender/Sentinel), or multi-IOC search queries from selected values
- **Timeline** — drag-to-zoom time range filter with event density chart
- **MITRE ATT&CK** — automatic technique mapping with TTP selector and investigation profiles
- **Filters** — column filters, text/regex search, TTP filters, time range, all live-update the dashboard

---

## For developers (building and modifying)

### Requirements

- Python 3.6+
- No other dependencies

### Project structure

```
sift/
├── src/
│   ├── shared/          # code included in every variant
│   │   ├── app.js
│   │   ├── overview.js
│   │   ├── datasource.js
│   │   ├── styles.css
│   │   ├── mitre-attack.js
│   │   ├── proctree-ui.js
│   │   ├── script-decoder.js
│   │   ├── timeline.js
│   │   ├── networkmap.js
│   │   └── chronicle.js
│   └── modules/         # data-source specific, loaded per variant
│       ├── chronicle.js
│       ├── defender.js
│       ├── windows.js
│       └── evtx-parser.js
├── variants/            # one folder per deliverable
│   ├── chronicle/manifest.json
│   ├── defender/manifest.json
│   ├── windows/manifest.json
│   ├── chronicle-defender/manifest.json
│   ├── defender-windows/manifest.json
│   └── chronicle-windows/manifest.json
├── template.html        # HTML shell (do not edit directly)
├── build.py             # assembles dist/ files
└── dist/                # built output — these are the files you distribute
```

### Building

```bash
# Build all variants
python build.py

# Build a single variant
python build.py windows
python build.py chronicle-defender
```

Output goes to `dist/`. Each file is fully self-contained — all JS and CSS is inlined. Send just the HTML file, nothing else is needed.

### Adding a new variant

1. Create a folder under `variants/` with a `manifest.json`:

```json
{
  "name": "sift-splunk",
  "title": "Sift — Splunk",
  "description": "Splunk export investigation",
  "modules": ["splunk"],
  "features": {
    "chronicle": false,
    "defender": false,
    "windows": false,
    "evtx": false
  }
}
```

2. Create `src/modules/splunk.js` with the data-source specific detection and UI code
3. Run `python build.py splunk`

### Adding a feature to all variants

Edit any file in `src/shared/` and run `python build.py`. All variants rebuild automatically.

### Adding a Windows-only feature

Edit `src/modules/windows.js` and run `python build.py`. Only Windows-enabled variants get the change.

---

## How the build works

`build.py` reads each `manifest.json`, takes `template.html` as the shell, and inlines every source file directly into the HTML as `<script>` and `<style>` blocks. The result is a single HTML file that contains everything — no external dependencies, works offline, open in any modern browser.

```
src/shared/*.js  ──┐
src/shared/*.css ──┤
src/modules/*.js ──┤── build.py ──► dist/sift-{variant}.html
template.html    ──┘                (self-contained, ~650 KB)
```
