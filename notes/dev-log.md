# Sift — Dev Log

Running record of changes, decisions, and ideas. Updated on commit or when Jayr drops an idea in conversation.

---

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

