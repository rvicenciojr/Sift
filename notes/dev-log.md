# Sift — Dev Log

Running record of changes, decisions, and ideas. Updated on commit or when Jayr drops an idea in conversation.

---

**2026-05-23** — Full code review pass. Six bugs fixed, two dead-code blocks removed.

**Bugs fixed**
- `_updateResizeBtn` undefined: width-resize `onmouseup` called a function that no longer existed after the settings dropdown refactor. Replaced with `_refreshSettingsBtn()` (the correct function already in scope).
- `_buildDonutChart` hardcoded `'action'` column: function ignored its second `colName` parameter, so clicking pie/donut slices on Hosts, Processes, and Network cards always filtered by the `action` column instead of the correct one. Fixed signature + click handlers.
- Event listener memory leak (profile dropdown): `renderFromData` added a new `document.addEventListener` on every re-render with `once: false`, never cleaning up old listeners. Added module-level `_ovListenersAC` AbortController reset each render cycle, scoped the listener to its signal.
- Event listener memory leak (card settings dropdown): same accumulation pattern — one leaking listener per card per render. Same `_ovListenersAC` signal fix.
- `settingsBtn` lost yellow state on mouseout: `onmouseout` unconditionally reset color to muted regardless of whether a non-normal size was active. Now calls `_refreshSettingsBtn()` to restore the correct state.
- `tlQuickPick` used deprecated implicit `event` global: updated function signature to accept `e` parameter; all 6 template call sites updated to pass `event` explicitly.

**Dead code removed**
- `_addChartToggle`: leftover from before the settings dropdown refactor, no longer called anywhere. Had its own toggle button that would have conflicted if called.
- `buildActiveFiltersCard` + `addFilterChip`: superseded by the filter strip in the overview header, never rendered. Removed both.

**2026-05-22** — Pushed `dd4a547`. Major overview UX overhaul.

**Card settings dropdown (··· button)**
- Every overview card now has a small `···` button on the far right of the title bar
- Opens a fixed-position context-menu style dropdown with two sections:
  - **Size**: Small / Medium / Large / Full (maps to compact/normal/wide/full flex widths)
  - **View as**: List / Chart (on cards that support chart toggle: Activity, Processes, Hosts, Network IPs)
- Dropdown is portalled to `document.body` so it's never clipped by the overview panel's scroll overflow
- Replaces the old in-body `◉ Chart` toggle buttons which were scattered and inconsistent

**Drag to reorder (fixed)**
- Ghost element now correctly tracks card origin (was snapping to cursor due to `e.offsetX` being relative to the handle span not the card)
- Order rebuild reads placeholder position directly from DOM
- Placeholder falls back to grid end when only one other card exists
- `window.blur` cleanup prevents stuck drag state if user alt-tabs mid-drag

**Height resize (new)**
- Bottom-edge horizontal grip on each card — drag down to make taller, up to shrink
- Shows px tooltip during drag
- Stores in `_ovCardHeights`, restored on re-render
- Fixed snap-back bug: was comparing `curH` vs `scrollHeight` (always equal after setting min-height), now compares vs `startH`
- `querySelectorAll` so multi-section cards (SHA256/SHA1/MD5 hashes) all expand together

**Width resize (improved)**
- Snap zones now computed from grid width at drag start using pixel midpoints, replacing unstable percentage-based calculation

**Bug fixes**
- `filterFromOverview` with undefined col: now falls back to all-columns search instead of silently adding a broken filter
- Top-N Offenders card no longer hidden in custom profile mode
- Dropdown memory leak fixed: all portalled `dd` elements cleaned from `document.body` before each re-render
- `resetOvProfile` now also resets `_ovChartModes` and `_ovCardHeights` on new file load

