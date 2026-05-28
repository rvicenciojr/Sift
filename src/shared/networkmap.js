// networkmap.js — Network Map (canvas force-directed graph)
/* globals allRows, headers, escapeHtml */

// NETWORK MAP
  // ════════════════════════════════════════════════════════════════

  var nmNodes = [], nmEdges = [];
  var nmSelectedNode = null, nmHoveredNode = null;
  var nmEdgeFilter = new Set(); // active port-color types; empty = no filter (blank)
  var nmTransform = { x: 0, y: 0, scale: 1 };
  var nmCanvasInited = false;
  var nmTableVisible = false;
  // Density gate — above this many nodes the force graph is unreadable AND slow
  var NM_MAX_NODES        = 300;
  var NM_TABLE_RENDER_CAP = 500;
  var NM_EDGE_TS_CAP      = 200; // cap timestamps stored per edge for jitter calc
  // Palette for tinting internal endpoint nodes by /24 subnet — borders only, fill stays teal-ish
  var NM_SUBNET_PALETTE = ['#2dd4bf', '#7ee8c4', '#88b3b1', '#5da39d', '#9cd4c0', '#6dbfa8', '#a8dad0', '#4fa893'];
  // Table state
  var nmTableRows    = [];
  var nmTableSearch  = '';
  var nmTableSortCol = 'count';
  var nmTableSortDir = -1;       // -1 = desc, 1 = asc
  var nmTableExtFilter = null;   // null = all, true = external only, false = internal only

  function nmHasNetworkData() {
    if (!allRows.length) return false;
    ptResolveColumns(headers);
    return allRows.some(r => (ptGet(r,'remoteIp') || ptGet(r,'remoteUrl')));
  }

  function nmActiveRows() {
    return (typeof filteredSorted !== 'undefined' && filteredSorted.length) ? filteredSorted : allRows;
  }

  function openNetworkMap() {
    ptResolveColumns(headers);
    document.getElementById('networkMapModal').style.display = 'flex';
    // Populate host filter
    const hosts = [...new Set(nmActiveRows().map(r => ptGet(r,'device')).filter(Boolean))].sort();
    const sel = document.getElementById('nmHostFilter');
    const prev = sel.value;
    sel.innerHTML = '<option value="">All Hosts</option>' +
      hosts.map(h => `<option value="${escapeHtml(h)}"${h===prev?' selected':''}>${escapeHtml(h)}</option>`).join('');
    nmCanvasInited = false;
    nmEdgeFilter = new Set();
    nmNodes = []; nmEdges = [];
    const counts = nmQuickCount();
    nmBuildLegendUI(counts);
    nmDrawBlank();
  }

  // Fast scan: count connections by port-color type (no force layout)
  function nmQuickCount() {
    const hostF   = document.getElementById('nmHostFilter').value;
    const procF   = (document.getElementById('nmProcFilter').value || '').toLowerCase().trim();
    const extOnly = document.getElementById('nmExtOnlyCheck').checked;
    const edgeMap = new Map();
    nmActiveRows().forEach(function(row) {
      const remoteIp   = ptGet(row, 'remoteIp');
      const remoteUrl  = ptGet(row, 'remoteUrl');
      const remotePort = ptGet(row, 'remotePort');
      const device     = ptGet(row, 'device');
      if (!remoteIp && !remoteUrl) return;
      if (hostF && device.toLowerCase() !== hostF.toLowerCase()) return;
      const initFname = ptGet(row,'initFile') || ptGet(row,'fileName');
      const initPid   = ptGet(row,'initPid')  || ptGet(row,'pid');
      const initCmd   = ptGet(row,'initCmd')  || ptGet(row,'cmdline');
      if (!initFname && !initPid) return;
      if (procF && !(initFname||'').toLowerCase().includes(procF) && !(initCmd||'').toLowerCase().includes(procF)) return;
      const isExt = !nmIsPrivate(remoteIp);
      if (extOnly && !isExt) return;
      const epLabel = (remoteUrl && remoteUrl.trim() && remoteUrl !== remoteIp) ? remoteUrl.trim() : (remoteIp || '').trim();
      if (!epLabel) return;
      const key = (device||'').toLowerCase() + '|' + initPid + '|' + (initFname||'').toLowerCase() + '||' + epLabel.toLowerCase();
      if (!edgeMap.has(key)) edgeMap.set(key, { ports: new Set(), count: 0 });
      const e = edgeMap.get(key);
      if (remotePort && remotePort !== '0') e.ports.add(remotePort);
      e.count++;
    });
    const counts = {};
    edgeMap.forEach(function(e) {
      const col = nmPortColor(e.ports);
      counts[col] = (counts[col] || 0) + e.count;
    });
    return counts;
  }

  // Called when host/proc/external filters change — reset and go back to blank
  function nmOnFilterChange() {
    nmEdgeFilter = new Set();
    nmNodes = []; nmEdges = [];
    nmCanvasInited = false;
    nmBuildLegendUI(nmQuickCount());
    nmDrawBlank();
    if (nmTableVisible) nmBuildTable();
  }

  // Render a blank canvas with a hint message
  function nmDrawBlank() {
    const canvas = document.getElementById('nmCanvas');
    if (!canvas) return;
    const container = canvas.parentElement;
    const W = Math.max(300, container.clientWidth - 16);
    const H = 420;
    const dpr = window.devicePixelRatio || 1;
    canvas.width  = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    canvas._nmW = W; canvas._nmH = H; canvas._dpr = dpr;
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = '#537173';
    ctx.font = '13px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Click a connection type above to render that map', W / 2, H / 2);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    nmUpdateDetail(null);
    nmSetStats('Select a connection type to render');
  }

  // Connection-type legend categories
  var NM_EDGE_CATS = [
    { label: 'HTTPS·443',    color: '#3a9fd6' },
    { label: 'HTTP·80',      color: '#26c6da' },
    { label: 'Kerberos·88',  color: '#9575cd' },
    { label: 'LDAP·389/636', color: '#ff7043' },
    { label: 'SMB·445',      color: '#e05c3a' },
    { label: 'SSH·22',       color: '#c45ab3' },
    { label: 'WinRM·5985',   color: '#26a69a' },
    { label: 'DNS·53',       color: '#4caf80' },
    { label: 'RDP·3389',     color: '#f0a500' },
    { label: 'High port ⚠',  color: '#e83e3e' },
    { label: 'Other',        color: '#778F8D' },
  ];

  function nmBuildLegendUI(counts) {
    const el = document.getElementById('nmLegendEdges');
    if (!el) return;
    el.innerHTML = '';
    NM_EDGE_CATS.forEach(cat => {
      const cnt = counts ? (counts[cat.color] || 0) : null;
      // Before render: show all types. After render: hide types with 0 connections.
      if (counts !== null && cnt === 0) return;
      const isActive = nmEdgeFilter.has(cat.color);
      const span = document.createElement('span');
      span.style.cssText =
        'cursor:pointer;display:inline-flex;align-items:center;gap:5px;' +
        'padding:2px 7px;border-radius:4px;transition:all .15s;border:1px solid transparent;';
      span.style.color = cat.color;
      if (isActive) { span.style.background = cat.color + '28'; span.style.borderColor = cat.color + '88'; }
      span.appendChild(document.createTextNode(cat.label));
      if (cnt !== null) {
        const badge = document.createElement('span');
        badge.textContent = cnt.toLocaleString();
        badge.style.cssText = 'font-size:9px;font-weight:700;padding:0 5px;border-radius:10px;margin-left:3px;' +
          'background:' + cat.color + '22;border:1px solid ' + cat.color + '55;';
        span.appendChild(badge);
      }
      span.title = isActive ? 'Click to deselect ' + cat.label : 'Click to show ' + cat.label + ' connections';
      span.onmouseover = function() { if (!nmEdgeFilter.has(cat.color)) { span.style.background = cat.color + '18'; span.style.borderColor = cat.color + '44'; } };
      span.onmouseout  = function() { if (!nmEdgeFilter.has(cat.color)) { span.style.background = ''; span.style.borderColor = 'transparent'; } };
      span.onclick = function() {
        // Toggle this type in/out of the active set
        if (nmEdgeFilter.has(cat.color)) nmEdgeFilter.delete(cat.color);
        else nmEdgeFilter.add(cat.color);

        if (nmEdgeFilter.size === 0) {
          // All deselected — clear map and hide table
          nmNodes = []; nmEdges = [];
          nmCanvasInited = false;
          nmTableVisible = false;
          const tp = document.getElementById('nmTablePanel');
          const tb = document.getElementById('nmTableBtn');
          if (tp) tp.style.display = 'none';
          if (tb) tb.style.background = 'rgba(0,0,0,0.25)';
          nmBuildLegendUI(nmQuickCount());
          nmDrawBlank();
        } else if (!nmNodes.length) {
          // Map not built yet — show "Rendering…" then build
          nmCanvasInited = false;
          nmTableVisible = true;
          const tp = document.getElementById('nmTablePanel');
          const tb = document.getElementById('nmTableBtn');
          if (tp) tp.style.display = 'flex';
          if (tb) tb.style.background = 'rgba(45,212,191,0.2)';
          nmSetStats('Rendering…');
          setTimeout(buildNetworkMap, 20); // brief delay so "Rendering…" paints first
        } else {
          // Rebuild with new filter set (force sim runs on filtered nodes = fast)
          nmCanvasInited = false;
          nmSetStats('Rendering…');
          setTimeout(buildNetworkMap, 20);
        }
      };
      el.appendChild(span);
    });
  }

  // Called after buildNetworkMap completes or filter changes — refresh legend
  function nmUpdateLegendCounts() {
    const counts = {};
    nmEdges.forEach(e => { const col = nmPortColor(e.ports); counts[col] = (counts[col] || 0) + e.count; });
    nmBuildLegendUI(counts); // nmBuildLegendUI uses nmEdgeFilter.has() for active state
  }

  // Update nmStats text
  function nmSetStats(text) {
    const el = document.getElementById('nmStats');
    if (el) el.textContent = text;
  }

  // Toggle the connection list table panel
  function nmToggleTableView() {
    nmTableVisible = !nmTableVisible;
    const panel = document.getElementById('nmTablePanel');
    const btn   = document.getElementById('nmTableBtn');
    if (panel) panel.style.display = nmTableVisible ? 'flex' : 'none';
    if (btn)   btn.style.background = nmTableVisible ? 'rgba(45,212,191,0.2)' : 'rgba(0,0,0,0.25)';
    if (nmTableVisible) nmBuildTable();
  }

  // Build connection table with search, filters, and sortable columns
  function nmBuildTable() {
    const panel = document.getElementById('nmTablePanel');
    if (!panel) return;
    panel.style.flexDirection = 'column';

    if (!nmEdges.length) {
      panel.innerHTML = '<div style="padding:20px;text-align:center;color:var(--cb-os3);font-size:12px;flex:1">Click a connection type above to load data</div>';
      return;
    }

    const colorToLabel = {};
    NM_EDGE_CATS.forEach(function(c) { colorToLabel[c.color] = c.label; });

    // Build master rows array — only include edges matching the active type filter
    nmTableRows = [];
    nmEdges.forEach(function(e) {
      const proc = e.sourceNode, ep = e.targetNode;
      if (!proc || !ep) return;
      const col = nmPortColor(e.ports);
      if (nmEdgeFilter.size > 0 && !nmEdgeFilter.has(col)) return; // skip unselected types
      const portStr = [...e.ports].sort(function(a,b){return +a-+b;}).join(', ');
      nmTableRows.push({
        procNode: proc, epNode: ep,
        process: proc.fname, pid: proc.pid, device: proc.device,
        endpoint: ep.label, external: ep.isExternal,
        typeColor: col,
        type: colorToLabel[col] || 'Other',
        ports: portStr, count: e.count,
        _s: (proc.fname + ' ' + (proc.pid||'') + ' ' + (proc.device||'') + ' ' + ep.label + ' ' + portStr + ' ' + (colorToLabel[col]||'')).toLowerCase(),
      });
    });

    // Reset filters on fresh build
    nmTableSearch = ''; nmTableSortCol = 'count'; nmTableSortDir = -1; nmTableExtFilter = null;

    panel.innerHTML = '';

    // ── Controls bar ──
    const ctrl = document.createElement('div');
    ctrl.style.cssText = 'display:flex;align-items:center;gap:6px;padding:5px 10px;background:var(--cb-dark);border-bottom:1px solid var(--cb-os1);flex-shrink:0;flex-wrap:wrap';

    const searchEl = document.createElement('input');
    searchEl.type = 'text';
    searchEl.placeholder = '🔍 Search process, endpoint, port…';
    searchEl.style.cssText = 'flex:1;min-width:160px;font-size:11px;padding:3px 8px;background:rgba(0,0,0,0.25);border:1px solid var(--cb-os1);border-radius:4px;color:var(--cb-text-inverse);outline:none';
    searchEl.oninput = function() { nmTableSearch = searchEl.value.toLowerCase().trim(); nmRefreshTableBody(tbody); };
    ctrl.appendChild(searchEl);

    function mkFilterBtn(label, checkFn, activeCss) {
      const btn = document.createElement('button');
      btn.textContent = label;
      btn.style.cssText = 'font-size:10px;padding:2px 9px;border-radius:4px;cursor:pointer;white-space:nowrap;background:rgba(0,0,0,0.2);border:1px solid var(--cb-os1);color:var(--cb-os3);transition:all .15s';
      btn.onclick = function() {
        checkFn(btn);
        nmRefreshTableBody(tbody);
      };
      return btn;
    }

    const extBtn = mkFilterBtn('🔴 External', function(btn) {
      nmTableExtFilter = (nmTableExtFilter === true) ? null : true;
      intBtn.style.cssText = 'font-size:10px;padding:2px 9px;border-radius:4px;cursor:pointer;white-space:nowrap;background:rgba(0,0,0,0.2);border:1px solid var(--cb-os1);color:var(--cb-os3);transition:all .15s';
      btn.style.background = nmTableExtFilter === true ? 'rgba(240,128,128,0.2)' : 'rgba(0,0,0,0.2)';
      btn.style.borderColor = nmTableExtFilter === true ? '#f08080' : 'var(--cb-os1)';
      btn.style.color       = nmTableExtFilter === true ? '#f08080' : 'var(--cb-os3)';
    });
    var intBtn = mkFilterBtn('🟢 Internal', function(btn) {
      nmTableExtFilter = (nmTableExtFilter === false) ? null : false;
      extBtn.style.cssText = 'font-size:10px;padding:2px 9px;border-radius:4px;cursor:pointer;white-space:nowrap;background:rgba(0,0,0,0.2);border:1px solid var(--cb-os1);color:var(--cb-os3);transition:all .15s';
      btn.style.background = nmTableExtFilter === false ? 'rgba(45,212,191,0.2)' : 'rgba(0,0,0,0.2)';
      btn.style.borderColor = nmTableExtFilter === false ? '#2dd4bf' : 'var(--cb-os1)';
      btn.style.color       = nmTableExtFilter === false ? '#2dd4bf' : 'var(--cb-os3)';
    });
    ctrl.appendChild(extBtn);
    ctrl.appendChild(intBtn);

    const countBadge = document.createElement('span');
    countBadge.id = 'nmTableCount';
    countBadge.style.cssText = 'font-size:10px;color:var(--cb-os3);white-space:nowrap;margin-left:4px';
    ctrl.appendChild(countBadge);
    panel.appendChild(ctrl);

    // ── Table ──
    const wrap = document.createElement('div');
    wrap.style.cssText = 'flex:1;overflow-y:auto;min-height:0';

    const table = document.createElement('table');
    table.style.cssText = 'width:100%;border-collapse:collapse;font-size:11px';

    // Sortable header helper
    function mkTh(label, col, align) {
      const th = document.createElement('th');
      th.style.cssText = 'padding:6px 10px;text-align:' + (align||'left') + ';color:var(--cb-text-inverse);white-space:nowrap;border-right:1px solid var(--cb-os1);background:var(--cb-dark);position:sticky;top:0;z-index:1;cursor:pointer;user-select:none';
      th.onclick = function() {
        nmTableSortDir = (nmTableSortCol === col) ? -nmTableSortDir : -1;
        nmTableSortCol = col;
        table.querySelectorAll('th').forEach(function(t) { t.style.color = 'var(--cb-text-inverse)'; });
        th.style.color = 'var(--cb-yellow)';
        nmRefreshTableBody(tbody);
      };
      const arrow = nmTableSortCol === col ? (nmTableSortDir === -1 ? ' ↓' : ' ↑') : '';
      th.innerHTML = label + '<span style="color:var(--cb-yellow);font-size:10px">' + arrow + '</span>';
      return th;
    }

    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    hr.appendChild(mkTh('Process',  'process'));
    hr.appendChild(mkTh('Endpoint', 'endpoint'));
    hr.appendChild(mkTh('Type',     'type'));
    hr.appendChild(mkTh('Ports',    'ports'));
    hr.appendChild(mkTh('Count',    'count', 'right'));
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    table.appendChild(tbody);
    wrap.appendChild(table);
    panel.appendChild(wrap);

    nmRefreshTableBody(tbody);
  }

  // Re-render tbody based on current search/sort/filter state
  function nmRefreshTableBody(tbody) {
    var rows = nmTableRows.filter(function(r) {
      // Type filter already applied when nmTableRows was built
      if (nmTableExtFilter === true  && !r.external) return false;
      if (nmTableExtFilter === false &&  r.external) return false;
      if (nmTableSearch && !r._s.includes(nmTableSearch)) return false;
      return true;
    });

    rows.sort(function(a, b) {
      var av = a[nmTableSortCol], bv = b[nmTableSortCol];
      if (nmTableSortCol === 'count') return (bv - av) * nmTableSortDir;
      return String(av||'').localeCompare(String(bv||'')) * nmTableSortDir;
    });

    var totalRows = rows.length;
    var truncated = totalRows > NM_TABLE_RENDER_CAP;
    if (truncated) rows = rows.slice(0, NM_TABLE_RENDER_CAP);

    var badge = document.getElementById('nmTableCount');
    if (badge) {
      if (truncated) {
        badge.innerHTML = '<span style="color:#f0a500">showing ' +
          NM_TABLE_RENDER_CAP.toLocaleString() + ' of ' + totalRows.toLocaleString() +
          ' rows — refine search/filter to narrow</span>';
      } else {
        badge.textContent = totalRows.toLocaleString() + ' rows';
      }
    }

    tbody.innerHTML = '';
    rows.forEach(function(r, i) {
      const tr = document.createElement('tr');
      tr.style.cssText = 'border-bottom:1px solid var(--cb-border);cursor:pointer;transition:background .1s';
      if (i % 2) tr.style.background = 'var(--modal-section)';
      tr.onmouseover = function() { tr.style.background = 'rgba(255,215,0,0.08)'; };
      tr.onmouseout  = function() { tr.style.background = i % 2 ? 'var(--modal-section)' : ''; };
      tr.onclick = function() {
        nmSelectedNode = r.epNode;
        nmUpdateDetail(r.epNode);
        const canvas = document.getElementById('nmCanvas');
        if (canvas && nmNodes.length) nmDraw(canvas);
        const dp = document.getElementById('nmDetailPanel');
        if (dp) dp.scrollTop = 0;
      };
      tr.addEventListener('contextmenu', function(e) { nmTableRowMenu(e, r); });
      tr.innerHTML =
        '<td style="padding:5px 10px;border-right:1px solid var(--cb-border)">'
          + '<span style="font-weight:700;font-family:monospace">' + escapeHtml(r.process) + '</span>'
          + (r.pid ? '<span style="color:var(--cb-muted);font-size:10px;margin-left:5px">PID:' + escapeHtml(r.pid) + '</span>' : '')
          + (r.device ? '<br><span style="color:var(--cb-muted);font-size:10px">' + escapeHtml(r.device) + '</span>' : '')
        + '</td>'
        + '<td style="padding:5px 10px;border-right:1px solid var(--cb-border);font-family:monospace;font-size:11px;word-break:break-all">'
          + '<span style="color:' + (r.external ? '#f08080' : '#2dd4bf') + '">' + escapeHtml(r.endpoint) + '</span>'
        + '</td>'
        + '<td style="padding:5px 10px;border-right:1px solid var(--cb-border);white-space:nowrap">'
          + '<span style="color:' + r.typeColor + ';font-weight:700;font-size:10px">' + r.type + '</span>'
        + '</td>'
        + '<td style="padding:5px 10px;border-right:1px solid var(--cb-border);color:var(--cb-muted);font-size:10px;white-space:nowrap">' + escapeHtml(r.ports) + '</td>'
        + '<td style="padding:5px 10px;text-align:right;font-weight:700;color:var(--cb-text)">' + r.count.toLocaleString() + '</td>';
      tbody.appendChild(tr);
    });
  }

  // ── Network Map context menu helpers ─────────────────────────────────────

  // Build IOC pivot items for a network endpoint (IP + optional domain).
  function nmEndpointPivots(ip, domain, label) {
    const pivot = ip || label || '';
    const items = [];
    if (pivot) {
      items.push({ type:'item', icon:'🦠', text:'VirusTotal', url:'https://www.virustotal.com/gui/search/' + encodeURIComponent(pivot) });
    }
    if (ip) {
      items.push({ type:'item', icon:'🔭', text:'Shodan  '  + ip, url:'https://www.shodan.io/host/' + encodeURIComponent(ip) });
      items.push({ type:'item', icon:'🚨', text:'AbuseIPDB  '+ ip, url:'https://www.abuseipdb.com/check/' + encodeURIComponent(ip) });
      items.push({ type:'item', icon:'🌫️', text:'GreyNoise  '+ ip, url:'https://viz.greynoise.io/ip/' + encodeURIComponent(ip) });
      items.push({ type:'item', icon:'🔎', text:'Censys  '  + ip, url:'https://search.censys.io/hosts/' + encodeURIComponent(ip) });
    }
    if (domain) {
      items.push({ type:'item', icon:'🌐', text:'URLScan  ' + (domain.length > 30 ? domain.slice(0,27)+'…' : domain), url:'https://urlscan.io/search/#' + encodeURIComponent(domain) });
      if (!ip) items.push({ type:'item', icon:'🦠', text:'VirusTotal  (domain)', url:'https://www.virustotal.com/gui/domain/' + encodeURIComponent(domain) });
    }
    if (typeof chroniclePivot === 'function') {
      const cp = chroniclePivot('target.ip', pivot);
      if (cp) items.push({ type:'item', icon: cp.icon, text: cp.label, url: cp.url });
    }
    return items;
  }

  // Context menu for the connection list table rows.
  function nmTableRowMenu(e, r) {
    function clip(t) { navigator.clipboard.writeText(t||'').catch(function(){}); }
    function addTableFilter(val) {
      const id = ++filterRowCounter;
      filterRows.push({ id, col:'', mode:'contains', value: val, connector:'AND' });
      renderFilterRows();
      document.getElementById('filterBar').classList.remove('hidden');
      applyFilter();
    }

    const ip     = (r.epNode && r.epNode.ip    ) || '';
    const domain = (r.epNode && r.epNode.domain) || '';
    const connPair = r.process + '  →  ' + r.endpoint + (r.ports ? ':' + r.ports.split(',')[0].trim() : '') + '  (' + r.type + ', ×' + r.count + ')';

    const items = [
      { type:'label',   text: r.process + '  →  ' + r.endpoint },
      { type:'preview', text: r.type + (r.ports ? '  ·  ports ' + r.ports : '') + '  ·  ' + r.count + ' events' },
      { type:'sep' },
      { type:'item', icon:'📋', text:'Copy process name',       fn: function(){ clip(r.process); } },
      { type:'item', icon:'📋', text:'Copy endpoint',           fn: function(){ clip(r.endpoint); } },
    ];
    if (ip)         items.push({ type:'item', icon:'📋', text:'Copy IP  '     + ip,     fn: function(){ clip(ip); } });
    if (domain)     items.push({ type:'item', icon:'📋', text:'Copy domain  ' + domain, fn: function(){ clip(domain); } });
    if (r.ports)    items.push({ type:'item', icon:'📋', text:'Copy ports  '  + r.ports,fn: function(){ clip(r.ports); } });
    items.push(       { type:'item', icon:'📄', text:'Copy connection pair',   fn: function(){ clip(connPair); } });

    // Copy all endpoints this process connects to
    const allEps = nmTableRows
      .filter(function(x){ return x.process === r.process && x.device === r.device; })
      .map(function(x){ return x.endpoint + (x.ports ? ':'+x.ports : ''); });
    if (allEps.length > 1) {
      items.push({ type:'item', icon:'📋', text:'Copy all endpoints for this process  (' + allEps.length + ')', fn: function(){ clip(allEps.join('\n')); } });
    }

    items.push({ type:'sep' });
    items.push({ type:'item', icon:'🔍', text:'Filter table by process',      fn: function(){ addTableFilter(r.process); } });
    items.push({ type:'item', icon:'🔍', text:'Filter table by endpoint',     fn: function(){ addTableFilter(r.endpoint); } });
    if (r.type !== 'Other') {
      items.push({ type:'item', icon:'🔍', text:'Filter table by  ' + r.type, fn: function(){ addTableFilter(r.type); } });
    }

    // Isolate this process in the network map proc filter
    items.push({ type:'item', icon:'🗺', text:'Isolate in network map', fn: function(){
      const pf = document.getElementById('nmProcFilter');
      if (pf) { pf.value = r.process; nmOnFilterChange(); }
    }});

    const pivots = nmEndpointPivots(ip, domain, r.endpoint);
    if (pivots.length) { items.push({ type:'sep' }); pivots.forEach(function(p){ items.push(p); }); }

    if (typeof ctxQueryItems === 'function') {
      var _nq = ip ? ctxQueryItems('remote ip', ip, ip)
                   : domain ? ctxQueryItems('remote url', domain, domain) : [];
      if (_nq.length) { items.push({ type:'sep' }); _nq.forEach(function(q){ items.push(q); }); }
    }
    if (typeof qbAddCondition === 'function' && (ip || domain)) {
      var _nqv = ip || domain, _nqc = ip ? 'remote ip' : 'remote url';
      items.push({ type:'item', icon:'➕', text:'Add to query builder',
        fn: (function(c,v){ return function(){ qbAddCondition(c,v,v); }; })(_nqc,_nqv) });
    }

    showCtxMenu(e, items);
  }

  function closeNetworkMap() {
    document.getElementById('networkMapModal').style.display = 'none';
  }

  function nmIsPrivate(ip) {
    return !ip || /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1|fc|fd)/i.test(ip.trim());
  }

  // Classification is by destination port only — DoH (DNS over 443) reads as HTTPS,
  // SMB tunneled over a non-standard port reads as High port / Other. Mixed-protocol
  // environments will miss the long tail. Use the log view if you need exact protocol.
  function nmPortColor(ports) {
    const ps = [...ports].map(Number);
    if (ps.some(p => p===443||p===8443))                        return '#3a9fd6'; // HTTPS
    if (ps.some(p => p===80||p===8080||p===8000||p===8888))     return '#26c6da'; // HTTP
    if (ps.some(p => p===88))                                   return '#9575cd'; // Kerberos
    if (ps.some(p => p===389||p===636||p===3268||p===3269))     return '#ff7043'; // LDAP/LDAPS/GC
    if (ps.some(p => p===445||p===139||p===135))                return '#e05c3a'; // SMB/NetBIOS
    if (ps.some(p => p===22))                                   return '#c45ab3'; // SSH
    if (ps.some(p => p===5985||p===5986||p===47001))            return '#26a69a'; // WinRM
    if (ps.some(p => p===53||p===5353||p===5355))               return '#4caf80'; // DNS/mDNS/LLMNR
    if (ps.some(p => p===3389))                                 return '#f0a500'; // RDP
    if (ps.some(p => p>49151))                                  return '#e83e3e'; // High/ephemeral
    return '#778F8D'; // Other
  }

  // Stable subnet-tint pick from the /24 of an IPv4 — gives same colour to all hosts in the subnet
  function nmSubnetTint(ip) {
    if (!ip) return NM_SUBNET_PALETTE[0];
    const m = ip.match(/^(\d+\.\d+\.\d+)\./);
    if (!m) return NM_SUBNET_PALETTE[0];
    const subnet = m[1];
    let h = 0;
    for (let i = 0; i < subnet.length; i++) h = (h * 31 + subnet.charCodeAt(i)) | 0;
    return NM_SUBNET_PALETTE[Math.abs(h) % NM_SUBNET_PALETTE.length];
  }

  // Compute "HH:MM:SS → HH:MM:SS (duration)" from edge first/last timestamps
  function nmTimeRangeStr() {
    let minTs = null, maxTs = null;
    for (const e of nmEdges) {
      if (e.firstTs && (!minTs || e.firstTs < minTs)) minTs = e.firstTs;
      if (e.lastTs  && (!maxTs || e.lastTs  > maxTs)) maxTs = e.lastTs;
    }
    if (!minTs || !maxTs) return '';
    const t1 = Date.parse(minTs), t2 = Date.parse(maxTs);
    if (isNaN(t1) || isNaN(t2)) return '';
    const start = new Date(t1).toISOString().slice(11, 19);
    const end   = new Date(t2).toISOString().slice(11, 19);
    const diff  = t2 - t1;
    let dur;
    if (diff < 1000)         dur = '<1s';
    else if (diff < 60000)   dur = Math.round(diff / 1000) + 's';
    else if (diff < 3600000) dur = Math.round(diff / 60000) + 'm';
    else                     dur = (diff / 3600000).toFixed(1) + 'h';
    return start + ' → ' + end + ' · ' + dur;
  }

  // Flag edges that look like beacons: ≥5 events, low jitter (coefficient of variation < 0.25)
  function nmDetectBeacons() {
    nmEdges.forEach(e => {
      e.isBeacon = false;
      e.beaconInterval = null;
      if (!e.timestamps || e.timestamps.length < 5) return;
      const sorted = e.timestamps.map(t => Date.parse(t)).filter(t => !isNaN(t)).sort((a, b) => a - b);
      if (sorted.length < 5) return;
      const gaps = [];
      for (let i = 1; i < sorted.length; i++) gaps.push(sorted[i] - sorted[i-1]);
      const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length;
      if (mean < 5000) return; // <5s avg interval — too tight to be meaningful
      let varSum = 0;
      for (const g of gaps) varSum += (g - mean) * (g - mean);
      const cv = Math.sqrt(varSum / gaps.length) / mean;
      if (cv < 0.25) { e.isBeacon = true; e.beaconInterval = mean; }
    });
  }

  // Build process suggestions for the too-dense panel.
  // For OS-level generic processes (svchost, lsass), filename alone narrows nothing.
  // Expand svchost into '-k <ServiceGroup>' variants so each row scopes meaningfully.
  function nmTopProcessSuggestions(processMap, max) {
    const fnameAgg = new Map();
    processMap.forEach(p => {
      if (!fnameAgg.has(p.fname)) fnameAgg.set(p.fname, { total: 0, processes: [] });
      const slot = fnameAgg.get(p.fname);
      slot.total += p.connCount;
      slot.processes.push(p);
    });
    const ranked = [...fnameAgg.entries()].sort((a, b) => b[1].total - a[1].total);
    const out = [];
    for (const [fname, slot] of ranked) {
      if (out.length >= max) break;
      const isSvchost = (fname || '').toLowerCase() === 'svchost.exe';
      const distinctCmd = new Set(slot.processes.map(p => (p.cmdline || '').trim()));
      if (isSvchost && distinctCmd.size > 1) {
        const groupAgg = new Map();
        slot.processes.forEach(p => {
          const cmd = p.cmdline || '';
          const m = cmd.match(/-k\s+(\S+)/i);
          const grp = m ? m[1] : '(no -k)';
          groupAgg.set(grp, (groupAgg.get(grp) || 0) + p.connCount);
        });
        const topGroups = [...groupAgg.entries()].sort((a, b) => b[1] - a[1]);
        for (const [grp, n] of topGroups) {
          if (out.length >= max) break;
          out.push({
            label: fname + (grp !== '(no -k)' ? ' -k ' + grp : ''),
            filterVal: grp !== '(no -k)' ? grp : fname,
            count: n
          });
        }
      } else {
        out.push({ label: fname, filterVal: fname, count: slot.total });
      }
    }
    return out;
  }

  // When result set is too dense for the force graph, draw a clear message on the canvas
  // and populate the detail panel with click-to-apply scoping suggestions.
  function nmRenderTooDenseHint(processMap, endpointMap, edgeMap, extCount, canvas, W, H) {
    const dpr = window.devicePixelRatio || 1;
    canvas.width  = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    canvas._nmW = W; canvas._nmH = H; canvas._dpr = dpr;
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    ctx.fillStyle = '#f0a500';
    ctx.font = 'bold 14px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('⚠ Too dense to render meaningfully', W / 2, H / 2 - 36);

    ctx.fillStyle = '#A0AEAC';
    ctx.font = '12px system-ui, sans-serif';
    ctx.fillText(processMap.size.toLocaleString() + ' processes · ' +
                 endpointMap.size.toLocaleString() + ' endpoints · ' +
                 edgeMap.size.toLocaleString() + ' unique flows',
                 W / 2, H / 2 - 12);

    ctx.fillStyle = '#778F8D';
    ctx.font = '11px system-ui, sans-serif';
    ctx.fillText('The network map shows visual patterns up to ~' + NM_MAX_NODES + ' nodes.',
                 W / 2, H / 2 + 14);
    ctx.fillText('Narrow with filters above, or close this and use the log view.',
                 W / 2, H / 2 + 30);
    ctx.fillText('Suggested filters in the right panel →', W / 2, H / 2 + 54);

    ctx.setTransform(1, 0, 0, 1, 0, 0);

    const rangeStr = nmTimeRangeStr();
    document.getElementById('nmStats').innerHTML =
      `<span style="color:#f0a500">⚠</span> ` +
      `<strong style="color:var(--cb-yellow)">${processMap.size}</strong> processes · ` +
      `<strong>${endpointMap.size}</strong> endpoints ` +
      `(<strong style="color:#f08080">${extCount}</strong> external) · ` +
      `<strong>${edgeMap.size}</strong> unique flows · ` +
      `<span style="color:#f0a500">too dense to render</span>` +
      (rangeStr ? ` · <span style="color:var(--cb-os3);font-size:10px">${rangeStr}</span>` : '');

    // Build scoping suggestions into the detail panel
    const eps  = [...endpointMap.values()].sort((a, b) => b.totalConns - a.totalConns).slice(0, 8);
    const hostAgg = {};
    processMap.forEach(p => { const d = p.device || '(none)'; hostAgg[d] = (hostAgg[d] || 0) + p.connCount; });
    const hostList = Object.entries(hostAgg).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const procSuggestions = nmTopProcessSuggestions(processMap, 8);

    // Subnet rollup — group internal endpoints by /24
    const subnetAgg = new Map();
    endpointMap.forEach(ep => {
      if (ep.isExternal) return;
      const m = (ep.ip || '').match(/^(\d+\.\d+\.\d+)\./);
      if (!m) return;
      const prefix = m[1] + '.';
      if (!subnetAgg.has(prefix)) subnetAgg.set(prefix, { events: 0, endpoints: 0, label: m[1] + '.0/24' });
      const slot = subnetAgg.get(prefix);
      slot.events    += ep.totalConns;
      slot.endpoints += 1;
    });
    const subnetList = [...subnetAgg.entries()]
      .map(([prefix, slot]) => ({ prefix, ...slot }))
      .filter(s => s.endpoints >= 2)
      .sort((a, b) => b.events - a.events)
      .slice(0, 6);

    // Port rollup — sum event count per port across edges
    const portAgg = new Map();
    edgeMap.forEach(e => {
      e.ports.forEach(p => { portAgg.set(p, (portAgg.get(p) || 0) + e.count); });
    });
    const portList = [...portAgg.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);

    // Event count behind the external-only toggle
    let extEventCount = 0;
    endpointMap.forEach(ep => { if (ep.isExternal) extEventCount += ep.totalConns; });
    const extOnlyAlready = document.getElementById('nmExtOnlyCheck').checked;

    const hdr = (txt) => `<div style="font-size:9px;font-weight:700;color:var(--modal-muted);text-transform:uppercase;margin:12px 0 5px">${txt}</div>`;
    const row = (act, val, label, count, color) => {
      const c = color || 'var(--modal-text)';
      return `<div class="nm-hint-row" data-act="${act}" data-val="${escapeHtml(val)}" style="padding:5px 7px;border-radius:4px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;font-size:11px;border-bottom:1px solid var(--modal-border)">
        <span style="font-family:monospace;color:${c};flex:1;word-break:break-all">${escapeHtml(label)}</span>
        <span style="color:var(--cb-yellow);font-weight:700;margin-left:8px">${count.toLocaleString()}</span>
      </div>`;
    };

    let html = '<div style="font-size:10px;font-weight:700;color:#f0a500;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Scope down to render</div>' +
               '<div style="font-size:11px;color:var(--modal-text);margin-bottom:10px;line-height:1.4">Click a suggestion to apply it as a filter and rebuild the map. Active connection-type filters are preserved.</div>';

    if (hostList.length > 1) {
      html += hdr('Top Hosts');
      hostList.forEach(([h, n]) => { html += row('host', h, h, n); });
    }

    if (subnetList.length > 1) {
      html += hdr('Top Subnets (internal)');
      subnetList.forEach(s => {
        const lbl = s.label + ' · ' + s.endpoints + ' host' + (s.endpoints === 1 ? '' : 's');
        html += row('subnet', s.prefix, lbl, s.events, '#7fffd4');
      });
    }

    html += hdr('Top Processes');
    procSuggestions.forEach(p => { html += row('proc', p.filterVal, p.label, p.count); });

    html += hdr('Top Destinations');
    eps.forEach(ep => {
      const c = ep.isExternal ? '#f08080' : '#7fffd4';
      html += row('dest', ep.label, ep.label, ep.totalConns, c);
    });

    if (portList.length >= 3) {
      html += hdr('Top Ports');
      portList.forEach(([p, n]) => { html += row('port', p, 'Port ' + p, n); });
    }

    if (extCount && !extOnlyAlready) {
      html += `<div class="nm-hint-row" data-act="ext" style="margin-top:12px;padding:7px 9px;border-radius:4px;cursor:pointer;background:rgba(240,128,128,0.08);border:1px solid rgba(240,128,128,0.3);text-align:center;font-size:11px;color:#f08080;font-weight:700">
        🔴 Show external only · ${extCount} endpoint${extCount === 1 ? '' : 's'} · ${extEventCount.toLocaleString()} event${extEventCount === 1 ? '' : 's'}
      </div>`;
    }

    const panel = document.getElementById('nmDetailPanel');
    panel.innerHTML = html;

    // Wire up click → apply filter, preserve active legend types, rebuild
    panel.querySelectorAll('.nm-hint-row').forEach(el => {
      const isExt = el.dataset.act === 'ext';
      el.onmouseover = function() { el.style.background = 'rgba(255,215,0,0.08)'; };
      el.onmouseout  = function() { el.style.background = isExt ? 'rgba(240,128,128,0.08)' : ''; };
      el.onclick = function() {
        const act = el.dataset.act, val = el.dataset.val;
        const preserveTypes = new Set(nmEdgeFilter);
        let needsApplyFilter = false;
        if (act === 'host') {
          const sel = document.getElementById('nmHostFilter');
          if (sel) sel.value = val;
        } else if (act === 'proc') {
          const pf = document.getElementById('nmProcFilter');
          if (pf) pf.value = val;
        } else if (act === 'ext') {
          const cb = document.getElementById('nmExtOnlyCheck');
          if (cb) cb.checked = true;
        } else if (act === 'dest' || act === 'subnet' || act === 'port') {
          // Add a table-row filter against the underlying data — applyFilter() updates
          // filteredSorted, which nmActiveRows() picks up on the next buildNetworkMap.
          const id = ++filterRowCounter;
          filterRows.push({ id, col: '', mode: 'contains', value: val, connector: 'AND' });
          renderFilterRows();
          document.getElementById('filterBar').classList.remove('hidden');
          needsApplyFilter = true;
        }
        if (needsApplyFilter) applyFilter();
        nmEdgeFilter = preserveTypes;
        nmNodes = []; nmEdges = [];
        nmCanvasInited = false;
        nmBuildLegendUI(nmQuickCount());
        if (nmEdgeFilter.size > 0) {
          nmSetStats('Rendering…');
          setTimeout(buildNetworkMap, 20);
        } else {
          nmDrawBlank();
        }
        if (nmTableVisible) nmBuildTable();
      };
    });
  }

  function buildNetworkMap() {
    ptResolveColumns(headers);
    const hostF   = document.getElementById('nmHostFilter').value;
    const procF   = (document.getElementById('nmProcFilter').value || '').toLowerCase().trim();
    const extOnly = document.getElementById('nmExtOnlyCheck').checked;

    const processMap  = new Map();
    const endpointMap = new Map();
    const edgeMap     = new Map();

    nmActiveRows().forEach(row => {
      const remoteIp   = ptGet(row, 'remoteIp');
      const remoteUrl  = ptGet(row, 'remoteUrl');
      const remotePort = ptGet(row, 'remotePort');
      const device     = ptGet(row, 'device');
      if (!remoteIp && !remoteUrl) return;
      if (hostF && device.toLowerCase() !== hostF.toLowerCase()) return;

      const initFname = ptGet(row,'initFile') || ptGet(row,'fileName');
      const initPid   = ptGet(row,'initPid')  || ptGet(row,'pid');
      const initCmd   = ptGet(row,'initCmd')  || ptGet(row,'cmdline');
      const initPath  = ptGet(row,'initPath') || ptGet(row,'filePath');
      const user      = ptGet(row,'user');
      const ts        = ptGet(row,'ts');
      if (!initFname && !initPid) return;
      if (procF && !(initFname||'').toLowerCase().includes(procF) && !(initCmd||'').toLowerCase().includes(procF)) return;

      const procKey = `p|${(device||'').toLowerCase()}|${initPid}|${(initFname||'').toLowerCase()}`;
      if (!processMap.has(procKey)) {
        processMap.set(procKey, {
          id: procKey, type: 'process',
          fname: initFname || `PID:${initPid}`, pid: initPid,
          device, cmdline: initCmd, fpath: initPath, user,
          firstSeen: ts, lastSeen: ts, connCount: 0
        });
      } else {
        const p = processMap.get(procKey);
        if (ts && (!p.firstSeen || ts < p.firstSeen)) p.firstSeen = ts;
        if (ts && (!p.lastSeen  || ts > p.lastSeen))  p.lastSeen  = ts;
        if (!p.cmdline && initCmd) p.cmdline = initCmd;
      }

      const epLabel = (remoteUrl && remoteUrl.trim() && remoteUrl !== remoteIp)
        ? remoteUrl.trim() : (remoteIp || '').trim();
      if (!epLabel) return;
      const isExt = !nmIsPrivate(remoteIp);
      if (extOnly && !isExt) return;

      const epKey = `e|${epLabel.toLowerCase()}`;
      if (!endpointMap.has(epKey)) {
        endpointMap.set(epKey, {
          id: epKey, type: 'endpoint',
          label: epLabel, ip: remoteIp || '',
          domain: (remoteUrl && remoteUrl !== remoteIp) ? remoteUrl : '',
          isExternal: isExt, ports: new Set(),
          subnetTint: isExt ? null : nmSubnetTint(remoteIp),
          firstSeen: ts, lastSeen: ts, totalConns: 0
        });
      }
      const ep = endpointMap.get(epKey);
      if (remotePort && remotePort !== '0') ep.ports.add(remotePort);
      ep.totalConns++;
      if (ts && (!ep.firstSeen || ts < ep.firstSeen)) ep.firstSeen = ts;
      if (ts && (!ep.lastSeen  || ts > ep.lastSeen))  ep.lastSeen  = ts;

      const edgeKey = `${procKey}||${epKey}`;
      if (!edgeMap.has(edgeKey)) {
        edgeMap.set(edgeKey, { source: procKey, target: epKey, count: 0, ports: new Set(), timestamps: [] });
      }
      const edge = edgeMap.get(edgeKey);
      edge.count++;
      if (remotePort && remotePort !== '0') edge.ports.add(remotePort);
      if (ts) {
        if (!edge.firstTs || ts < edge.firstTs) edge.firstTs = ts;
        if (!edge.lastTs  || ts > edge.lastTs)  edge.lastTs  = ts;
        if (edge.timestamps.length < NM_EDGE_TS_CAP) edge.timestamps.push(ts);
      }
      processMap.get(procKey).connCount++;
    });

    // Filter to only the active connection types before running force layout
    if (nmEdgeFilter.size > 0) {
      for (const [key, edge] of edgeMap) {
        if (!nmEdgeFilter.has(nmPortColor(edge.ports))) edgeMap.delete(key);
      }
      const usedProcs = new Set([...edgeMap.values()].map(e => e.source));
      const usedEps   = new Set([...edgeMap.values()].map(e => e.target));
      for (const [key] of processMap)  { if (!usedProcs.has(key)) processMap.delete(key); }
      for (const [key] of endpointMap) { if (!usedEps.has(key))   endpointMap.delete(key); }
    }

    nmNodes = [...processMap.values(), ...endpointMap.values()];
    nmEdges = [...edgeMap.values()];

    // Wire node refs upfront — table needs them even when graph won't render
    const nodeById = new Map(nmNodes.map(n => [n.id, n]));
    nmEdges.forEach(e => { e.sourceNode = nodeById.get(e.source); e.targetNode = nodeById.get(e.target); });

    const canvas = document.getElementById('nmCanvas');
    const container = canvas.parentElement;
    const W = Math.max(300, container.clientWidth - 16);
    const H = Math.max(360, Math.min(580, Math.max(processMap.size, endpointMap.size) * 55 + 80));

    if (!nmNodes.length) {
      document.getElementById('nmStats').textContent = 'No network connection data in current filter.';
      nmSetupCanvas(canvas, W, H);
      nmUpdateDetail(null);
      return;
    }

    const extCount = [...endpointMap.values()].filter(e => e.isExternal).length;

    // Density gate — past the threshold the force graph is unreadable AND locks the page.
    // Refuse to render, surface scoping suggestions in the detail panel instead.
    if (nmNodes.length > NM_MAX_NODES) {
      nmRenderTooDenseHint(processMap, endpointMap, edgeMap, extCount, canvas, W, H);
      nmUpdateLegendCounts();
      if (nmTableVisible) nmBuildTable();
      return;
    }

    // Initial positions: processes left, endpoints right
    const procs = nmNodes.filter(n => n.type === 'process');
    const eps   = nmNodes.filter(n => n.type === 'endpoint');
    procs.forEach((n, i) => {
      n.x = W * 0.22 + (Math.random()-.5)*50; n.y = H*(i+1)/(procs.length+1);
      n.vx=0; n.vy=0; n.r=15; n.pinned=false;
    });
    eps.forEach((n, i) => {
      n.x = W * 0.72 + (Math.random()-.5)*80; n.y = H*(i+1)/(eps.length+1);
      n.vx=0; n.vy=0; n.r=12; n.pinned=false;
    });

    nmTransform = { x:0, y:0, scale:1 };
    nmSelectedNode = null; nmHoveredNode = null;
    nmRunForce(W, H);
    nmDetectBeacons();
    nmSetupCanvas(canvas, W, H);

    const rangeStr = nmTimeRangeStr();
    document.getElementById('nmStats').innerHTML =
      `<strong style="color:var(--cb-yellow)">${processMap.size}</strong> processes · ` +
      `<strong>${endpointMap.size}</strong> endpoints ` +
      `(<strong style="color:#f08080">${extCount}</strong> external) · ` +
      `<strong>${edgeMap.size}</strong> unique flows` +
      (rangeStr ? ` · <span style="color:var(--cb-os3);font-size:10px">${rangeStr}</span>` : '');
    nmUpdateLegendCounts();
    if (nmTableVisible) nmBuildTable();
  }

  function nmRunForce(W, H) {
    const iters = Math.min(450, 200 + nmNodes.length * 6);
    for (let iter = 0; iter < iters; iter++) {
      const a = Math.max(0.003, 1 - iter/iters);
      // Repulsion
      for (let i = 0; i < nmNodes.length; i++) {
        if (nmNodes[i].pinned) continue;
        for (let j = i+1; j < nmNodes.length; j++) {
          const na=nmNodes[i], nb=nmNodes[j];
          const dx=nb.x-na.x, dy=nb.y-na.y, d2=dx*dx+dy*dy||0.01, d=Math.sqrt(d2);
          const f = a * (d < na.r+nb.r+25 ? 3500 : 900) / d2;
          na.vx-=(dx/d)*f; na.vy-=(dy/d)*f;
          if (!nb.pinned) { nb.vx+=(dx/d)*f; nb.vy+=(dy/d)*f; }
        }
      }
      // Edge springs
      nmEdges.forEach(e => {
        const s=e.sourceNode, t=e.targetNode;
        if (!s||!t) return;
        const dx=t.x-s.x, dy=t.y-s.y, d=Math.sqrt(dx*dx+dy*dy)||1;
        const f=(d-140)*a*0.12;
        if (!s.pinned) { s.vx+=dx/d*f; s.vy+=dy/d*f; }
        if (!t.pinned) { t.vx-=dx/d*f; t.vy-=dy/d*f; }
      });
      // Weak centre gravity
      nmNodes.forEach(n => {
        if (n.pinned) return;
        n.vx+=(W/2-n.x)*a*0.008; n.vy+=(H/2-n.y)*a*0.008;
        n.vx*=0.82; n.vy*=0.82;
        n.x=Math.max(n.r+2,Math.min(W-n.r-2, n.x+n.vx));
        n.y=Math.max(n.r+2,Math.min(H-n.r-2, n.y+n.vy));
      });
    }
  }

  function nmDraw(canvas) {
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas._nmW || 600, H = canvas._nmH || 400;
    const ctx = canvas.getContext('2d');
    // Clear with identity
    ctx.setTransform(1,0,0,1,0,0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (!nmNodes.length) return;
    // Apply pan+zoom+DPR
    ctx.setTransform(
      nmTransform.scale*dpr, 0, 0, nmTransform.scale*dpr,
      nmTransform.x*dpr, nmTransform.y*dpr
    );

    const maxCnt = Math.max(...nmEdges.map(e=>e.count), 1);

    // All edges in nmEdges already match the active filter (filtered at build time)
    nmEdges.forEach(e => {
      const s=e.sourceNode, t=e.targetNode;
      if (!s||!t) return;
      const col = nmPortColor(e.ports);
      const lw  = 0.6 + 2.8*(e.count/maxCnt);
      const alp = 0.18 + 0.5*(e.count/maxCnt);
      // Beacon glow underlay — regular-interval edges get a halo so C2/beacons pop
      if (e.isBeacon) {
        ctx.beginPath(); ctx.moveTo(s.x,s.y); ctx.lineTo(t.x,t.y);
        ctx.strokeStyle = col; ctx.globalAlpha = 0.35; ctx.lineWidth = lw + 5;
        ctx.shadowColor = col; ctx.shadowBlur = 10; ctx.stroke();
        ctx.shadowBlur = 0;
      }
      ctx.beginPath(); ctx.moveTo(s.x,s.y); ctx.lineTo(t.x,t.y);
      ctx.strokeStyle=col; ctx.globalAlpha=alp; ctx.lineWidth=lw; ctx.stroke();
      // Arrow at midpoint
      const mx=(s.x+t.x)/2, my=(s.y+t.y)/2;
      const dx=t.x-s.x, dy=t.y-s.y, len=Math.sqrt(dx*dx+dy*dy)||1;
      const ax=dx/len, ay=dy/len, as=4.5;
      ctx.beginPath();
      ctx.moveTo(mx+ax*as, my+ay*as);
      ctx.lineTo(mx-ax*as+ay*as*0.6, my-ay*as-ax*as*0.6);
      ctx.lineTo(mx-ax*as-ay*as*0.6, my-ay*as+ax*as*0.6);
      ctx.closePath(); ctx.fillStyle=col; ctx.fill();
      ctx.globalAlpha=1;
      // Count badge
      if (e.count>1 && nmTransform.scale>0.55) {
        ctx.font='9px system-ui'; ctx.fillStyle='#A0AEAC'; ctx.globalAlpha=0.75;
        ctx.textAlign='center'; ctx.fillText(e.count, mx+ay*9, my-ax*9+3); ctx.globalAlpha=1;
      }
      // Beacon marker at midpoint
      if (e.isBeacon && nmTransform.scale>0.55) {
        ctx.font='10px system-ui'; ctx.fillStyle=col; ctx.globalAlpha=1;
        ctx.textAlign='center'; ctx.fillText('⏱', mx-ay*9, my+ax*9+3);
      }
    });

    // All nodes in nmNodes already match the active filter (filtered at build time)
    nmNodes.forEach(n => {
      const isSel = nmSelectedNode===n, isHov = nmHoveredNode===n;
      const sc = isHov ? 1.22 : 1;
      let fill, stroke;
      if (n.type==='process') {
        fill   = isSel ? '#FFD700' : 'rgba(255,215,0,0.18)';
        stroke = '#FFD700';
      } else if (n.isExternal) {
        fill   = isSel ? '#e83e3e' : 'rgba(232,62,62,0.18)';
        stroke = '#e83e3e';
      } else {
        // Internal endpoint — tint border by /24 subnet so cross-VLAN traffic pops
        const tint = n.subnetTint || '#2dd4bf';
        fill   = isSel ? tint : tint + '2d';
        stroke = tint;
      }
      if (isSel||isHov) { ctx.shadowColor=stroke; ctx.shadowBlur=isSel?14:7; }
      ctx.beginPath(); ctx.arc(n.x,n.y,n.r*sc,0,Math.PI*2);
      ctx.fillStyle=fill; ctx.strokeStyle=stroke; ctx.lineWidth=isSel?2.5:1.5;
      ctx.fill(); ctx.stroke(); ctx.shadowBlur=0;
      // Label
      if (nmTransform.scale>0.35) {
        const raw = n.type==='process' ? n.fname : n.label;
        const lbl = raw.length>22 ? raw.slice(0,19)+'…' : raw;
        const fs  = Math.max(8, Math.round(9.5*Math.min(nmTransform.scale,1)));
        ctx.font = `${n.type==='process'?'bold ':''}${fs}px 'Consolas',monospace`;
        ctx.fillStyle   = n.type==='process' ? '#FFD700' : (n.isExternal?'#f08080':'#7fffd4');
        ctx.textAlign   = 'center';
        ctx.textBaseline= 'top';
        ctx.fillText(lbl, n.x, n.y+n.r*sc+3);
        ctx.textBaseline= 'alphabetic';
      }
    });
    ctx.setTransform(1,0,0,1,0,0);
  }

  function nmSetupCanvas(canvas, W, H) {
    const dpr = window.devicePixelRatio || 1;
    canvas.width  = Math.round(W*dpr);
    canvas.height = Math.round(H*dpr);
    canvas.style.width  = W+'px';
    canvas.style.height = H+'px';
    canvas._nmW = W; canvas._nmH = H; canvas._dpr = dpr;
    nmDraw(canvas);
    if (nmCanvasInited) return;
    nmCanvasInited = true;

    let dragNode=null, panning=false, panSX=0, panSY=0, mdX=0, mdY=0, moved=false;

    const cssPt = e => {
      const r=canvas.getBoundingClientRect();
      return { x: e.clientX-r.left, y: e.clientY-r.top };
    };
    const toWorld = (lx,ly) => ({
      x: (lx-nmTransform.x)/nmTransform.scale,
      y: (ly-nmTransform.y)/nmTransform.scale
    });
    const nodeAt = (wx,wy) => {
      for (let i=nmNodes.length-1;i>=0;i--) {
        const n=nmNodes[i], dx=wx-n.x, dy=wy-n.y;
        if (dx*dx+dy*dy <= n.r*n.r*1.8) return n;
      }
      return null;
    };

    canvas.addEventListener('mousedown', e => {
      const {x,y}=cssPt(e); mdX=x; mdY=y; moved=false;
      const w=toWorld(x,y); dragNode=nodeAt(w.x,w.y);
      if (dragNode) { dragNode.pinned=true; }
      else { panning=true; panSX=x-nmTransform.x; panSY=y-nmTransform.y; }
    });

    canvas.addEventListener('mousemove', e => {
      const {x,y}=cssPt(e);
      if (Math.abs(x-mdX)>3||Math.abs(y-mdY)>3) moved=true;
      if (dragNode) {
        const w=toWorld(x,y); dragNode.x=w.x; dragNode.y=w.y; dragNode.vx=0; dragNode.vy=0;
        nmDraw(canvas);
      } else if (panning) {
        nmTransform.x=x-panSX; nmTransform.y=y-panSY;
        canvas.style.cursor='grabbing'; nmDraw(canvas);
      } else {
        const w=toWorld(x,y), h=nodeAt(w.x,w.y);
        if (h!==nmHoveredNode) { nmHoveredNode=h; canvas.style.cursor=h?'pointer':'grab'; nmDraw(canvas); }
        // Tooltip
        const tip=document.getElementById('nmTooltip');
        if (!h) { tip.style.display='none'; return; }
        let html='';
        if (h.type==='process') {
          html=`<strong style="color:var(--cb-yellow)">${escapeHtml(h.fname)}</strong>`+
            (h.pid?` <span style="color:#537173">PID:${h.pid}</span>`:'')+
            (h.device?`<br><span style="color:#778F8D">${escapeHtml(h.device)}</span>`:'')+
            `<br><span style="color:#A0AEAC">${h.connCount} connection(s)</span>`;
        } else {
          const col=h.isExternal?'#f08080':'#7fffd4';
          html=`<strong style="color:${col}">${escapeHtml(h.label)}</strong>`+
            (h.ip&&h.ip!==h.label?`<br><span style="color:#778F8D">${escapeHtml(h.ip)}</span>`:'')+
            (h.ports.size?`<br>Ports: ${[...h.ports].sort((a,b)=>+a-+b).join(', ')}`:'')+
            `<br>${h.isExternal?'🔴 External':'🟢 Internal'} · ${h.totalConns} events`;
        }
        tip.innerHTML=html;
        tip.style.display='block';
        tip.style.left=Math.min(e.clientX+14,window.innerWidth-220)+'px';
        tip.style.top=(e.clientY-8)+'px';
      }
    });

    canvas.addEventListener('mouseup', e => {
      if (dragNode) {
        dragNode.pinned = moved;
        if (!moved) nmSelectNode(dragNode, canvas);
        dragNode=null;
      } else if (panning) {
        panning=false; canvas.style.cursor='grab';
        if (!moved) { nmSelectedNode=null; nmUpdateDetail(null); nmDraw(canvas); }
      }
    });

    canvas.addEventListener('mouseleave', () => {
      nmHoveredNode=null; nmDraw(canvas);
      document.getElementById('nmTooltip').style.display='none';
    });

    canvas.addEventListener('wheel', e => {
      e.preventDefault();
      const {x,y}=cssPt(e);
      const zf=e.deltaY<0?1.13:1/1.13;
      const ns=Math.max(0.18,Math.min(5, nmTransform.scale*zf));
      nmTransform.x=x-(x-nmTransform.x)*(ns/nmTransform.scale);
      nmTransform.y=y-(y-nmTransform.y)*(ns/nmTransform.scale);
      nmTransform.scale=ns; nmDraw(canvas);
    },{passive:false});

    canvas.addEventListener('dblclick', () => {
      nmTransform={x:0,y:0,scale:1}; nmDraw(canvas);
    });

    canvas.addEventListener('contextmenu', e => {
      const {x,y} = cssPt(e);
      const w = toWorld(x,y);
      const node = nodeAt(w.x, w.y);
      if (!node) return;
      function clip(text) { navigator.clipboard.writeText(text||'').catch(function(){}); }
      const items = [];
      if (node.type === 'process') {
        items.push({ type: 'label',   text: node.fname + (node.pid ? '  ·  PID ' + node.pid : '') });
        items.push({ type: 'preview', text: node.cmdline || node.device || '' });
        items.push({ type: 'sep' });
        items.push({ type: 'item', icon: '📋', text: 'Copy process name',  fn: function(){ clip(node.fname); } });
        if (node.cmdline) items.push({ type: 'item', icon: '📋', text: 'Copy command line', fn: function(){ clip(node.cmdline); } });
        if (node.pid)     items.push({ type: 'item', icon: '📋', text: 'Copy PID',          fn: function(){ clip(node.pid); } });
        if (node.device)  items.push({ type: 'item', icon: '📋', text: 'Copy device',       fn: function(){ clip(node.device); } });
        items.push({ type: 'sep' });
        items.push({ type: 'item', icon: '🔍', text: 'Filter table by process name', fn: function(){
          const id = ++filterRowCounter;
          filterRows.push({ id, col: '', mode: 'contains', value: node.fname, connector: 'AND' });
          renderFilterRows();
          document.getElementById('filterBar').classList.remove('hidden');
          applyFilter();
        }});
        if (node.pid) items.push({ type: 'item', icon: '🔍', text: 'Filter table by PID', fn: function(){
          const id = ++filterRowCounter;
          filterRows.push({ id, col: '', mode: 'contains', value: node.pid, connector: 'AND' });
          renderFilterRows();
          document.getElementById('filterBar').classList.remove('hidden');
          applyFilter();
        }});
      } else {
        // Endpoint node
        const label = node.label || '';
        const ip    = node.ip && node.ip !== label ? node.ip : '';
        items.push({ type: 'label',   text: (node.isExternal ? '🔴 External' : '🟢 Internal') + '  Endpoint' });
        items.push({ type: 'preview', text: label });
        items.push({ type: 'sep' });
        items.push({ type: 'item', icon: '📋', text: 'Copy endpoint',     fn: function(){ clip(label); } });
        if (ip)          items.push({ type: 'item', icon: '📋', text: 'Copy IP  '     + ip,         fn: function(){ clip(ip); } });
        if (node.domain) items.push({ type: 'item', icon: '📋', text: 'Copy domain  ' + node.domain,fn: function(){ clip(node.domain); } });
        const ports = [...node.ports].sort((a,b)=>+a-+b).join(', ');
        if (ports) items.push({ type: 'item', icon: '📋', text: 'Copy ports  ' + ports, fn: function(){ clip(ports); } });
        const connectedProcs = nmEdges.filter(function(e){ return e.targetNode === node; }).map(function(e){ return e.sourceNode.fname; });
        const summary = [
          label,
          ip ? 'IP: ' + ip : '',
          node.domain ? 'Domain: ' + node.domain : '',
          ports ? 'Ports: ' + ports : '',
          connectedProcs.length ? 'Connected from: ' + connectedProcs.join(', ') : '',
          'Events: ' + node.totalConns,
          node.firstSeen ? 'First seen: ' + node.firstSeen.slice(0,19).replace('T',' ') : '',
        ].filter(Boolean).join('\n');
        items.push({ type: 'item', icon: '📄', text: 'Copy full summary', fn: function(){ clip(summary); } });
        items.push({ type: 'sep' });
        items.push({ type: 'item', icon: '🔍', text: 'Filter table by this endpoint', fn: function(){
          const id = ++filterRowCounter;
          filterRows.push({ id, col: '', mode: 'contains', value: label, connector: 'AND' });
          renderFilterRows();
          document.getElementById('filterBar').classList.remove('hidden');
          applyFilter();
        }});
        // IOC pivots — full network-aware set
        const pivots = nmEndpointPivots(ip, node.domain || '', label);
        if (pivots.length) { items.push({ type:'sep' }); pivots.forEach(function(p){ items.push(p); }); }
        if (typeof ctxQueryItems === 'function') {
          var _cq = ip ? ctxQueryItems('remote ip', ip, ip)
                       : node.domain ? ctxQueryItems('remote url', node.domain, node.domain) : [];
          if (_cq.length) { items.push({ type:'sep' }); _cq.forEach(function(q){ items.push(q); }); }
        }
        if (typeof qbAddCondition === 'function' && (ip || node.domain)) {
          var _cqv = ip || node.domain, _cqc = ip ? 'remote ip' : 'remote url';
          items.push({ type:'item', icon:'➕', text:'Add to query builder',
            fn: (function(c,v){ return function(){ qbAddCondition(c,v,v); }; })(_cqc,_cqv) });
        }
      }
      showCtxMenu(e, items);
    });
  }

  function nmSelectNode(node, canvas) {
    nmSelectedNode = nmSelectedNode===node ? null : node;
    nmUpdateDetail(nmSelectedNode);
    nmDraw(canvas);
  }

  function nmCalcInterval(ts) {
    if (!ts||ts.length<2) return null;
    const sorted=ts.map(t=>Date.parse(t)).filter(t=>!isNaN(t)).sort((a,b)=>a-b);
    if (sorted.length<2) return null;
    const gaps=[]; for(let i=1;i<sorted.length;i++) gaps.push(sorted[i]-sorted[i-1]);
    const avg=gaps.reduce((a,b)=>a+b,0)/gaps.length;
    if(avg<1000) return `${Math.round(avg)}ms`;
    if(avg<60000) return `${Math.round(avg/1000)}s`;
    if(avg<3600000) return `${Math.round(avg/60000)}m`;
    return `${Math.round(avg/3600000)}h`;
  }

  function nmUpdateDetail(node) {
    const panel = document.getElementById('nmDetailPanel');
    if (!node) {
      panel.innerHTML='<div style="color:var(--modal-muted);font-size:12px;text-align:center;padding:40px 12px;line-height:1.6">Click a process or endpoint node to see details and connection info</div>';
      return;
    }
    let html='';
    const R = (k,v) => v?`<div class="nm-dp-row"><span>${k}</span><span>${escapeHtml(String(v))}</span></div>`:'';
    if (node.type==='process') {
      html=`<div style="font-size:10px;font-weight:700;color:var(--cb-yellow);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Process</div>
        <div style="font-size:14px;font-weight:700;color:var(--modal-text);margin-bottom:6px;font-family:monospace">${escapeHtml(node.fname)}</div>`+
        R('PID',node.pid)+R('Host',node.device)+R('User',node.user)+R('Path',node.fpath)+
        R('First seen',node.firstSeen?node.firstSeen.slice(0,19).replace('T',' '):'')+
        R('Last seen',node.lastSeen?node.lastSeen.slice(0,19).replace('T',' '):'')+
        `<div class="nm-dp-row"><span>Connections</span><span style="color:var(--cb-yellow);font-weight:700">${node.connCount}</span></div>`;
      const out=nmEdges.filter(e=>e.sourceNode===node).sort((a,b)=>b.count-a.count);
      if (out.length) {
        html+=`<div style="font-size:9px;font-weight:700;color:var(--modal-muted);text-transform:uppercase;margin:12px 0 5px">Connected to (${out.length})</div>`;
        out.forEach(e => {
          const ep=e.targetNode; if(!ep) return;
          const col=ep.isExternal?'#f08080':'#2dd4bf';
          const pts=[...e.ports].sort((a,b)=>+a-+b).join(',');
          const intv=nmCalcInterval(e.timestamps);
          html+=`<div style="padding:5px 0;border-bottom:1px solid var(--modal-border)">
            <div style="display:flex;gap:5px;align-items:flex-start">
              <span style="color:${col};font-family:monospace;font-size:11px;flex:1;word-break:break-all">${escapeHtml(ep.label)}</span>
              <span style="color:var(--modal-muted);white-space:nowrap;font-size:10px">×${e.count}${pts?' :'+pts:''}</span>
            </div>${intv?`<div style="color:#f0a500;font-size:10px;margin-top:2px">⏱ ~${intv} interval</div>`:''}
          </div>`;
        });
      }
      if (node.cmdline) html+=`<div style="font-size:9px;font-weight:700;color:var(--modal-muted);text-transform:uppercase;margin:12px 0 4px">Command Line</div>
        <div style="font-size:10px;font-family:monospace;color:var(--modal-text);word-break:break-all;background:var(--modal-code-bg);padding:6px 8px;border-radius:4px;border:1px solid var(--modal-border);line-height:1.5">${escapeHtml(node.cmdline)}</div>`;
    } else {
      const col=node.isExternal?'#f08080':'#2dd4bf';
      html=`<div style="font-size:10px;font-weight:700;color:${col};text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">${node.isExternal?'🔴 External':'🟢 Internal'} Endpoint</div>
        <div style="font-size:13px;font-weight:700;color:var(--modal-text);margin-bottom:6px;word-break:break-all;font-family:monospace">${escapeHtml(node.label)}</div>`+
        R('IP',node.ip&&node.ip!==node.label?node.ip:'')+
        R('Domain',node.domain)+
        (node.ports.size?`<div class="nm-dp-row"><span>Ports</span><span>${[...node.ports].sort((a,b)=>+a-+b).join(', ')}</span></div>`:'')+
        `<div class="nm-dp-row"><span>Events</span><span style="color:${col};font-weight:700">${node.totalConns}</span></div>`+
        R('First seen',node.firstSeen?node.firstSeen.slice(0,19).replace('T',' '):'')+
        R('Last seen',node.lastSeen?node.lastSeen.slice(0,19).replace('T',' '):'');
      const inc=nmEdges.filter(e=>e.targetNode===node).sort((a,b)=>b.count-a.count);
      if (inc.length) {
        html+=`<div style="font-size:9px;font-weight:700;color:var(--modal-muted);text-transform:uppercase;margin:12px 0 5px">Connected from (${inc.length})</div>`;
        inc.forEach(e => {
          const p=e.sourceNode; if(!p) return;
          const pts=[...e.ports].sort((a,b)=>+a-+b).join(',');
          const intv=nmCalcInterval(e.timestamps);
          html+=`<div style="padding:5px 0;border-bottom:1px solid var(--modal-border)">
            <div style="display:flex;gap:5px;align-items:center">
              <span style="color:var(--cb-yellow);font-family:monospace;font-size:11px;flex:1">${escapeHtml(p.fname)}</span>
              <span style="color:var(--modal-muted);white-space:nowrap;font-size:10px">×${e.count}${pts?' :'+pts:''}</span>
            </div>${intv?`<div style="color:#f0a500;font-size:10px;margin-top:2px">⏱ ~${intv} avg interval${e.count>=3?' — possible beaconing':''}</div>`:''}
          </div>`;
        });
      }
    }
    panel.innerHTML=html;
  }

  // ── Network Map: maximize / restore ──
  var nmMaximized = false;
  function nmToggleMaximize() {
    const modal   = document.getElementById('networkMapModal');
    const box     = document.getElementById('nmModalBox');
    const btn     = document.getElementById('nmMaximizeBtn');
    nmMaximized   = !nmMaximized;
    if (nmMaximized) {
      modal.style.padding = '0';
      box.style.maxWidth  = '100%';
      box.style.maxHeight = '100vh';
      box.style.borderRadius = '0';
      box.style.width  = '100%';
      box.style.height = '100vh';
      btn.textContent  = '⛶';
      btn.title = 'Restore';
    } else {
      modal.style.padding = '24px';
      box.style.maxWidth  = '1200px';
      box.style.maxHeight = 'calc(100vh - 48px)';
      box.style.borderRadius = '10px';
      box.style.width  = '100%';
      box.style.height = '';
      btn.textContent  = '⛶';
      btn.title = 'Maximize';
    }
    // Re-fit canvas to new size
    setTimeout(() => { nmCanvasInited = false; buildNetworkMap(); }, 60);
  }

  // ── Network Map detail panel resize ──
  (function () {
    const handle = document.getElementById('nmPanelResizeHandle');
    const wrap   = document.getElementById('nmDetailPanelWrap');
    if (!handle || !wrap) return;
    let dragging = false, startX = 0, startW = 0;
    handle.addEventListener('mousedown', e => {
      dragging = true;
      startX   = e.clientX;
      startW   = wrap.offsetWidth;
      document.body.style.userSelect = 'none';
      document.body.style.cursor = 'ew-resize';
      e.preventDefault();
    });
    document.addEventListener('mousemove', e => {
      if (!dragging) return;
      const delta = startX - e.clientX;
      const newW  = Math.max(160, Math.min(600, startW + delta));
      wrap.style.width = newW + 'px';
    });
    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
    });
  })();
