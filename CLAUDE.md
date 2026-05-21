# Sift — CLAUDE.md

You are working inside the sift development repo. Read this before executing any task.

## What sift is

A browser-based, offline investigation tool for threat hunters and IR analysts. No install, no server, no data leaves the machine. One HTML file per variant — drag a log file in, get a MITRE ATT&CK dashboard, process tree, network map, script decoder, and SIEM query builder.

**Supported data sources:** Microsoft Defender XDR (Advanced Hunting CSV exports), Google Chronicle / UDM CSV exports, Windows Security Event Logs (CSV or .evtx). Any combination of these can be loaded in a single session via the multi-source variants.

**Who uses it:** Built by and for Jayr's threat hunting workflow. Stack: Chronicle SIEM, Defender XDR, Defender for Identity, large enterprise (10k+ endpoints).

## Architecture

```
src/shared/      — code included in every variant (app, overview, timeline, network map, etc.)
src/modules/     — data-source specific parsers (chronicle.js, defender.js, windows.js, evtx-parser.js)
variants/        — one folder per deliverable, each with a manifest.json
template.html    — HTML shell; build.py inlines everything into it
build.py         — assembles dist/ files; python build.py [variant-name]
dist/            — built output, fully self-contained HTML files
notes/           — dev log, ideas, decisions
notes/dev-log.md — running record of changes and ideas; update on commit or when Jayr drops an idea
```

Each `dist/` file is ~650 KB and entirely self-contained. To build all variants: `python build.py`. To build one: `python build.py chronicle-defender`.

## Location

This repo lives inside Jayr's Framework vault:
`/Users/jayr/Framework/01 - ACTIVE/career/side-project/sift/`

## Operating standards

All operating standards (voice, format, logging) come from Framework:
`/Users/jayr/Framework/03 - SYSTEM/CLAUDE.md`

Queue and research tasks go through Framework's queue (`/Users/jayr/Framework/05 - QUEUE/`). Outputs related to sift land in Framework's generated folders or in `notes/` here.

## Dev log workflow

When Jayr commits or mentions a change or idea:
- Add an entry to `notes/dev-log.md` with the date and a plain-language summary
- For commits: pull from `git log` — what changed and why
- For ideas: record as-stated with a `[IDEA]` prefix so they're easy to scan later
