#!/usr/bin/env python3
"""
Sift build script
-----------------
Assembles self-contained single-file HTML builds from:
  src/shared/   — code included in every variant
  src/modules/  — data-source-specific code, loaded per-variant manifest
  template.html — the HTML shell with <!-- SIFT:* --> markers

Usage:
  python build.py              # build all variants
  python build.py windows      # build one variant by folder name
"""

import json, os, sys, re
from pathlib import Path

ROOT      = Path(__file__).parent
SHARED    = ROOT / 'src' / 'shared'
MODULES   = ROOT / 'src' / 'modules'
VARIANTS  = ROOT / 'variants'
DIST      = ROOT / 'dist'
TEMPLATE  = ROOT / 'template.html'

# Ordered list of shared scripts (load order matters)
SHARED_SCRIPTS = [
    'sift-core.js',    # must be first — modules call Sift.register() on load
    'datasource.js',
    'chronicle.js',
    'app.js',
    'timeline.js',
    'networkmap.js',
    'proctree-ui.js',
    'script-decoder.js',
    'mitre-attack.js',
    'overview.js',
]

def inline_css(path: Path) -> str:
    return f'<style>\n{path.read_text(encoding="utf-8")}\n</style>'

def inline_js(path: Path, comment: str = '') -> str:
    tag = f'<!-- {comment} -->\n' if comment else ''
    return f'{tag}<script>\n{path.read_text(encoding="utf-8")}\n</script>'

def build_variant(variant_dir: Path) -> None:
    manifest_path = variant_dir / 'manifest.json'
    if not manifest_path.exists():
        return

    manifest = json.loads(manifest_path.read_text())
    name     = manifest['name']
    title    = manifest['title']
    features = manifest.get('features', {})
    modules  = manifest.get('modules', [])

    print(f'Building {name}...')

    html = TEMPLATE.read_text(encoding='utf-8')

    # ── 1. Title + optional header name override ────────────────────────────────
    html = html.replace('<!-- SIFT:title -->', title)
    header_name = manifest.get('header', 'Sift')
    html = html.replace('<h1>Sift</h1>', f'<h1>{header_name}</h1>')

    # ── 2. Config (feature flags injected before any other script) ────────────
    config_js = f'var SIFT_FEATURES = {json.dumps(features, separators=(",", ":"))};'
    config_block = f'<script>/* Sift build: {name} */\n{config_js}\n</script>'
    html = html.replace('<!-- SIFT:config -->', config_block)

    # ── 3. CSS ───────────────────────────────────────────────────────────────
    css_path = SHARED / 'styles.css'
    html = html.replace('<!-- SIFT:css -->', inline_css(css_path))

    # ── 4. Shared scripts ────────────────────────────────────────────────────
    shared_parts = []
    for fname in SHARED_SCRIPTS:
        p = SHARED / fname
        if p.exists():
            shared_parts.append(inline_js(p, f'shared: {fname}'))
        else:
            print(f'  WARNING: shared/{fname} not found, skipping')
    html = html.replace('<!-- SIFT:shared-scripts -->', '\n'.join(shared_parts))

    # ── 5. Modules ───────────────────────────────────────────────────────────
    module_parts = []
    for mod in modules:
        p = MODULES / f'{mod}.js'
        if p.exists():
            module_parts.append(inline_js(p, f'module: {mod}'))
        else:
            print(f'  WARNING: modules/{mod}.js not found, skipping')
    html = html.replace('<!-- SIFT:modules -->', '\n'.join(module_parts))

    # ── 6. Patch HTML based on feature flags ────────────────────────────────
    if not features.get('evtx'):
        html = html.replace('accept=".csv,.evtx"', 'accept=".csv"')
        html = html.replace('Drop a CSV or EVTX file here', 'Drop a CSV file here')
        html = html.replace('or click to browse · supports .csv and .evtx', 'or click to browse · supports .csv')
        html = html.replace('📂 Open CSV</button>', '📂 Open CSV</button>')  # no-op: stays as Open CSV
    else:
        html = html.replace('📂 Open CSV</button>', '📂 Open File</button>')

    if not features.get('windows'):
        # Rename Open CSV button label — stays as "Open CSV" which is correct
        pass  # no further changes needed; windows cards are gated by isWindowsSecurityLog at runtime

    # ── Write output ─────────────────────────────────────────────────────────
    DIST.mkdir(exist_ok=True)
    out = DIST / f'{name}.html'
    out.write_text(html, encoding='utf-8')
    size_kb = out.stat().st_size // 1024
    print(f'  → {out}  ({size_kb} KB)')

def main():
    targets = sys.argv[1:]  # optional: specific variant folder names

    built = 0
    for variant_dir in sorted(VARIANTS.iterdir()):
        if not variant_dir.is_dir():
            continue
        if targets and variant_dir.name not in targets:
            continue
        build_variant(variant_dir)
        built += 1

    if built == 0:
        print('No variants found.' + (' (check folder names)' if targets else ''))
    else:
        print(f'\nDone — {built} variant(s) built in dist/')

if __name__ == '__main__':
    main()
