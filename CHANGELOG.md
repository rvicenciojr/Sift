# Changelog

User-facing changes. Detailed dev notes live in [`notes/dev-log.md`](notes/dev-log.md).

## [Unreleased]

## [1.2.0] — 2026-05-27

Documentation, tooling, and sample data release. No `src/` changes since v1.0.0 — dist HTML files are byte-equivalent. The value of this release is everything *around* the tool.

### Added
- `examples/sample-chronicle.csv` — fabricated UDM-format attack chain (process launch, network connection, file creation, registry value set) with `security_result.severity` populated so severity auto-highlights kick in
- `examples/sample-windows-security.csv` — 53-event Windows Security log exercising every Windows Security card (Logon Analysis, Spray/Brute Force, Account Changes, Auth Events, Network Logons, RDP Sessions, Attack Chain)
- 6 new screenshots: `windows-security-overview.png`, `attack-chain.png`, `timeline.png` (standalone), `bytes-chart.png` (standalone), `table-highlighted.png`, replaced `ttp-selector.png` with full expanded view
- GitHub Actions `build.yml` workflow — runs `python3 build.py` on every push/PR, build badge in README
- GitHub Actions `release.yml` workflow — pushing a `vX.Y.Z` tag auto-builds dist and opens a draft release
- Issue templates: `bug.yml`, `feature.yml`, `config.yml` (routes security reports to advisory flow)
- Repo description, homepage, and 15 topics on GitHub for discoverability

### Changed
- **README restructure** — log viewer features (Table / Filter / Context Menu / Keyboard) moved above the threat-hunting dashboard. Reframes Sift as a CSV viewer with hunt features layered on top (which is what most users come for)
- README TOC now grouped: **Core log viewer** / **Threat hunting layer** / **Reference**
- Technique profiles section: the 57-technique dot-separated wall replaced with a clean tactic-grouped table
- CONTRIBUTING.md: documented release process under "Cutting a release"

## [1.0.0] — 2026-05-27

First production-ready release. [GitHub release](https://github.com/rvicenciojr/Sift-ThreatHuntingInvestigator/releases/tag/v1.0.0).

### Added
- Pre-loaded threat-hunting highlight terms (powershell, mimikatz, rundll32, certutil, mshta, encoded, base64)
- Chronicle severity auto-highlights on first load
- Card settings menu (···) with size and chart-mode controls
- Drag-to-reorder and edge-resize for Overview cards
- Custom Profile builder for tailoring the Overview to specific investigations
- Custom Field cards (pin any CSV column as a frequency card)
- HEARTH-style competing hypothesis prompts in `/hunt` workflows (via separate MCP server)
- Chronicle UDM Process Tree support with action type categories
- Sample CSVs for Defender and Windows Security event logs (in `examples/`)
- LICENSE (MIT), CHANGELOG, CONTRIBUTING, SECURITY companion files
- Full README documentation: TOC, Quick Start, Privacy, Performance, FAQ, screenshots for all major features

### Fixed
- Overview chart-area lists now cap at 100 rows with "…and N more" footer (previously could render 8000+ DOM nodes)
- Pagination bar hidden during Overview mode (no longer reappears on filter changes)
- KQL join `on` clauses use `and` not commas (T1574.001 playbook queries)
- Chronicle `actionCategories` returns Chronicle UDM categories, not Defender's
- Process tree no longer self-links when `InitiatingProcessId` is absent from Defender exports
- MITRE technique double-counting (T1003.003 dcsync, T1027 -enc, T1562 narrowed)
- Memory leaks from accumulating event listeners on Overview re-renders
- Donut chart click-to-filter now uses the correct column instead of always `action`

### Changed
- README reorganized — Overview and Analysis Tools moved to the top, log sources to the bottom
