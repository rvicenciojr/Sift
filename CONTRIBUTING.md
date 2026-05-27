# Contributing to Sift

Thanks for taking the time. This project is a solo side project — issues and small PRs welcome, but turnaround may be slow.

## Reporting bugs

[Open an issue](https://github.com/rvicenciojr/Sift-ThreatHuntingInvestigator/issues) with:

- What you tried to do
- What happened
- What you expected
- Browser + version
- A sanitised CSV sample if the bug is data-shaped (small, no real data, just enough to reproduce)

Do not paste real log data, hostnames, usernames, or customer IOCs into issues.

## Requesting features

Open an issue first to discuss before sending a PR. Sift is intentionally focused — not every idea fits. Things that aren't a fit:

- External network calls of any kind at runtime
- Server-side anything
- Dependencies beyond inlineable JS/CSS
- Features specific to one organisation's quirks (write a fork)

Good fits:

- New data sources (write a module in `src/modules/` and a manifest)
- Additional MITRE ATT&CK technique signatures
- Performance improvements
- UX polish for the Overview / Process Tree / Network Map

## Development setup

Requirements:

- Python 3.6+ (for the build script)
- A modern browser
- No other dependencies

Build all variants:

```bash
python3 build.py
```

Build one variant:

```bash
python3 build.py chronicle-defender    # → dist/hunt-investigator.html
python3 build.py windows               # → dist/sift-windows.html
```

Each `dist/*.html` is fully self-contained. To test locally, just open the file in Chrome or Edge.

## Project structure

See the [project structure section](README.md#project-structure) in the README.

## Code style

- No external runtime dependencies. Everything inlines into a single HTML file.
- No comments unless the why is non-obvious.
- Match the existing voice — direct, no filler.
- Run `python3 build.py` before submitting a PR — if the build fails, the PR fails.

## Where to log changes

User-facing changes go in `CHANGELOG.md`. Internal dev notes go in `notes/dev-log.md`.
