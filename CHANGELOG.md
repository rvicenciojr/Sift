# Changelog

User-facing changes. Detailed dev notes live in [`notes/dev-log.md`](notes/dev-log.md).

## [Unreleased]

### Added
- Pre-loaded threat-hunting highlight terms (powershell, mimikatz, rundll32, certutil, mshta, encoded, base64)
- Chronicle severity auto-highlights on first load
- Card settings menu (···) with size and chart-mode controls
- Drag-to-reorder and edge-resize for Overview cards
- Custom Profile builder for tailoring the Overview to specific investigations
- Custom Field cards (pin any CSV column as a frequency card)
- HEARTH-style competing hypothesis prompts in `/hunt` workflows (via separate MCP server)
- Chronicle UDM Process Tree support with action type categories

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
