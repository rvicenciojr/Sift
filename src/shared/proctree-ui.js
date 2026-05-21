// proctree-ui.js — Process Tree UI + Web Worker bridge
// Column mapping, detection, and shared helpers live in datasource.js
/* globals allRows, headers, escapeHtml, showLoading, hideLoading, ptColMap, ptResolveColumns, ptGet, ptHasDefenderCols, udmEventColor */

// PROCESS TREE — Defender / Chronicle CSV
  // ═══════════════════════════════════════════════════

  // Show/hide analysis buttons based on loaded data
  function updateProcTreeBtn() {
    if (headers.length) ptResolveColumns(headers);

    const btn   = document.getElementById('procTreeBtn');
    const nmBtn = document.getElementById('networkMapBtn');
    const amsiB = document.getElementById('amsiBtn');
    const isWinSec = typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog;

    // Use Sift module feature flags if available, otherwise fall back to legacy logic
    const moduleNetworkOk = (typeof Sift === 'undefined') ? true : Sift.hasFeature('network-map');
    const moduleTreeOk    = (typeof Sift === 'undefined') ? true : Sift.hasFeature('process-tree');
    const moduleScriptOk  = (typeof Sift === 'undefined') ? true : Sift.hasFeature('script-decoder');

    const hasTree = moduleTreeOk && (isWinSec
      ? allRows.some(r => (ptGet(r,'action')||'').trim() === '4688' && (ptGet(r,'fileName') || ptGet(r,'initFile')))
      : ptHasDefenderCols());

    const hasNetwork = moduleNetworkOk && nmHasNetworkData();
    const hasAmsi    = moduleScriptOk  && amsiHasEventData();

    if (btn)   btn.style.display   = hasTree    ? 'inline-flex' : 'none';
    if (nmBtn) nmBtn.style.display = hasNetwork ? 'inline-flex' : 'none';
    if (amsiB) amsiB.style.display = hasAmsi    ? 'inline-flex' : 'none';
    const anySpecial = hasTree || hasNetwork || hasAmsi;
    const div1 = document.getElementById('atbDivider1');
    const div2 = document.getElementById('atbDivider2');
    if (div1) div1.style.display = anySpecial ? '' : 'none';
    if (div2) div2.style.display = anySpecial ? '' : 'none';
  }

  // ── Render ──
  var ptTree = null;
  var ptExpandState = new Map();
  var ptCurrentPage = 1;
  var ptFlatFiltered = []; // flat list of root nodes after filtering, for pagination
  var ptActionFilter = null; // action-color string to filter by, null = show all

  // Action type legend categories — switches based on data source
  var PT_ACTION_CATS_DEFENDER = [
    { label: 'ProcessCreated',   color: '#e05c3a' },
    { label: 'NetworkConnection',color: '#3a9fd6' },
    { label: 'FileCreated',      color: '#c45ab3' },
    { label: 'RegistryValueSet', color: '#f0a500' },
    { label: 'Other',            color: '#4caf80' },
  ];

  var PT_ACTION_CATS_WINSEC = [
    { label: 'Process (4688)',        color: '#e05c3a' },  // process creation
    { label: 'Logon / Auth',          color: '#3a9fd6' },  // 4624, 4634, 4648, 4776
    { label: 'Auth Failure',          color: '#e83e3e' },  // 4625, 4740 lockout
    { label: 'Kerberos',              color: '#26c6da' },  // 4768, 4769, 4770, 4771
    { label: 'Script / PS',           color: '#f0a500' },  // 4103, 4104 + persistence 4697/4698/7045
    { label: 'Account Changes',       color: '#c45ab3' },  // 4720/4722/4725/4726 user changes
    { label: 'Group Changes',         color: '#9c6ade' },  // 4728/4732/4756 group membership
    { label: 'Log / Policy',          color: '#f06292' },  // 1100/1102 log clear, 4719 audit policy
    { label: 'Other',                 color: '#4caf80' },
  ];

  var PT_ACTION_CATS = PT_ACTION_CATS_DEFENDER; // set on open

  // Cache for ptNodeHasAction — separate from match cache
  var _ptActionCache = Object.create(null);
  var _ptActionColor = '';

  // Returns true if node or any descendant has an event matching actionColor
  function ptNodeHasAction(node, actionColor) {
    if (actionColor !== _ptActionColor) { _ptActionCache = Object.create(null); _ptActionColor = actionColor; }
    if (node.key in _ptActionCache) return _ptActionCache[node.key];
    const result = node.events.some(function(e) { return getActionColor(e.action) === actionColor; }) ||
      node.children.some(function(c) { return ptNodeHasAction(c, actionColor); });
    _ptActionCache[node.key] = result;
    return result;
  }

  // Wire up clickable action-type legend.
  // Works on existing .pt-legend-item spans — no wrapper ID required.
  function ptBuildLegendUI() {
    const modal = document.getElementById('procTreeModal');
    if (!modal) return;

    PT_ACTION_CATS.forEach(function(cat) {
      // Find the matching span.
      // Can't use span.style.color — browsers normalize hex to rgb().
      // Match by data attribute (set on first call) or by text content.
      var allSpans = modal.querySelectorAll('.pt-legend-item');
      var span = null;
      for (var i = 0; i < allSpans.length; i++) {
        var s = allSpans[i];
        if (s.dataset.ptcat === cat.label) { span = s; break; }
        var txt = (s.textContent || '').replace('●', '').trim();
        if (txt === cat.label) { span = s; break; }
      }
      if (!span) return;
      span.dataset.ptcat = cat.label; // tag so future calls skip the search

      const isActive = ptActionFilter === cat.color;
      span.style.cursor = 'pointer';
      span.style.padding = '2px 7px';
      span.style.borderRadius = '4px';
      span.style.transition = 'all .15s';
      span.style.border = '1px solid ' + (isActive ? cat.color + '88' : 'transparent');
      span.style.background = isActive ? cat.color + '28' : '';
      span.title = isActive ? 'Click to show all' : 'Click to show only ' + cat.label;

      span.onmouseover = function() {
        if (ptActionFilter !== cat.color) {
          span.style.background = cat.color + '18';
          span.style.border = '1px solid ' + cat.color + '44';
        }
      };
      span.onmouseout = function() {
        if (ptActionFilter !== cat.color) {
          span.style.background = '';
          span.style.border = '1px solid transparent';
        }
      };
      span.onclick = function() {
        ptActionFilter = (ptActionFilter === cat.color) ? null : cat.color;
        _ptActionCache = Object.create(null);
        ptClearMatchCache();
        ptBuildLegendUI();
        renderProcTree();
      };
    });
  }

  // ── Web Worker bridge ─────────────────────────────────────────────────────
  var _ptWorker = null;

  function openProcTree() {
    const isWinSec = typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog;

    // Use module action categories if available, otherwise fall back to legacy arrays
    const moduleCats = (typeof Sift !== 'undefined') ? Sift.getActionCategories() : null;
    PT_ACTION_CATS = moduleCats || (isWinSec ? PT_ACTION_CATS_WINSEC : PT_ACTION_CATS_DEFENDER);

    // Source badge — use module badge config if available
    const badge = document.getElementById('ptSourceBadge');
    if (badge) {
      const moduleBadge = (typeof Sift !== 'undefined') ? Sift.getBadge() : null;
      if (moduleBadge) {
        badge.textContent       = moduleBadge.text.toUpperCase();
        badge.style.background  = moduleBadge.bg;
        badge.style.borderColor = moduleBadge.border.replace('1px solid ','');
        badge.style.color       = moduleBadge.color;
      } else {
        badge.textContent = isWinSec ? 'WINDOWS SECURITY' : 'DEFENDER CSV';
        badge.style.background  = isWinSec ? 'rgba(0,188,102,0.15)' : 'rgba(255,215,0,0.15)';
        badge.style.borderColor = isWinSec ? '#00bc66' : 'var(--cb-yellow)';
        badge.style.color       = isWinSec ? '#00bc66' : 'var(--cb-yellow)';
      }
    }

    // Render legend from active action categories
    const legendEl = document.getElementById('ptLegendActions');
    if (legendEl) {
      legendEl.innerHTML = PT_ACTION_CATS.map(c =>
        `<span class="pt-legend-item" style="color:${c.color}">● ${c.label}</span>`
      ).join('');
    }
    document.getElementById('procTreeModal').style.display = 'flex';
    buildAndRender();
  }

  function closeProcTree() {
    document.getElementById('procTreeModal').style.display = 'none';
  }

  function buildAndRender() {
    ptClearMatchCache();
    ptActionFilter = null;
    _ptActionCache = Object.create(null);
    ptResolveColumns(headers);

    const activeRows = (typeof filteredSorted !== 'undefined' && filteredSorted.length) ? filteredSorted : allRows;
    // Populate host filter immediately (doesn't need the tree)
    const hosts = [...new Set(activeRows.map(r => ptGet(r,'device')).filter(Boolean))].sort();
    const hostSel = document.getElementById('ptHostFilter');
    const curHost = hostSel.value;
    hostSel.innerHTML = '<option value="">All Hosts</option>' +
      hosts.map(h => `<option value="${escapeHtml(h)}" ${h===curHost?'selected':''}>${escapeHtml(h)}</option>`).join('');

    // Show loading state in tree body
    const body = document.getElementById('procTreeBody');
    body.innerHTML = '<div class="pt-empty" style="padding:60px">Building process tree…</div>';

    // Terminate any previous worker run
    if (_ptWorker) _ptWorker.terminate();
    _ptWorker = createBlobWorker('proctree-worker-src');

    _ptWorker.onmessage = function (e) {
      if (e.data.type === 'progress') {
        body.innerHTML = `<div class="pt-empty" style="padding:60px">${e.data.msg}</div>`;
        return;
      }
      if (e.data.type === 'done') {
        // Reconstruct nodeMap from entries array
        const nodeMap = new Map(e.data.nodeMapEntries);
        ptTree = { roots: e.data.roots, nodeMap };
        ptCurrentPage = 1;
        ptBuildLegendUI(); // make legend clickable now that tree is ready
        renderProcTree();
        _ptWorker.terminate();
        _ptWorker = null;
      }
    };

    _ptWorker.onerror = function (err) {
      console.error('Process tree worker error:', err);
      body.innerHTML = '<div class="pt-empty" style="color:#e83e3e">Error building process tree. Check console.</div>';
    };

    _ptWorker.postMessage({ rows: activeRows, ptColMap });
  }

  // Build a searchable text blob for a node (all fields concatenated)
  function ptNodeSearchText(node) {
    const evText = node.events.map(e =>
      [e.action, e.remoteIp, e.remoteUrl, e.remotePort, e.regKey, e.regVal, e.regData].filter(Boolean).join(' ')
    ).join(' ');
    return [
      node.fname, node.cmdline, node.pid, node.fpath,
      node.device, node.user, node.sha256, node.sha1, node.md5,
      node.initFname, node.initCmd, node.initPath,
      evText
    ].filter(Boolean).join(' ').toLowerCase();
  }

  // Match cache — keyed by filter context, auto-clears when search changes
  var _ptMatchCache = Object.create(null);
  var _ptMatchCtx   = '';

  function ptClearMatchCache() { _ptMatchCache = Object.create(null); _ptMatchCtx = ''; }

  // Returns true if node OR any descendant matches all active filters (memoised)
  function ptNodeMatches(node, hostF, terms) {
    const ctx = hostF + '\x00' + terms.join('\x01') + '\x02' + (ptActionFilter || '');
    if (ctx !== _ptMatchCtx) { _ptMatchCache = Object.create(null); _ptMatchCtx = ctx; }
    if (node.key in _ptMatchCache) return _ptMatchCache[node.key];

    const hostOk = !hostF || (node.device||'').toLowerCase() === hostF;
    let result = false;
    if (hostOk) {
      const actionOk = !ptActionFilter || ptNodeHasAction(node, ptActionFilter);
      if (actionOk) {
        if (!terms.length) {
          result = true;
        } else {
          const text = ptNodeSearchText(node);
          result = terms.every(t => text.includes(t)) || node.children.some(c => ptNodeMatches(c, hostF, terms));
        }
      }
    }
    _ptMatchCache[node.key] = result;
    return result;
  }

  function ptGoPage(page) {
    ptCurrentPage = page;
    renderProcTree();
  }

  function renderProcTree() {
    if (!ptTree) return;

    const body    = document.getElementById('procTreeBody');
    const hostF   = document.getElementById('ptHostFilter').value.toLowerCase();
    const rawQ    = (document.getElementById('ptSearch').value || '').toLowerCase().trim();
    const terms   = rawQ ? rawQ.split(/\s+/).filter(Boolean) : [];
    const pgSize  = parseInt(document.getElementById('ptPageSize').value) || 0;

    // Filter roots
    const visibleRoots = ptTree.roots.filter(n => ptNodeMatches(n, hostF, terms));

    const totalNodes = visibleRoots.length;

    // Pagination on roots
    const totalPages = pgSize > 0 ? Math.ceil(totalNodes / pgSize) : 1;
    if (ptCurrentPage < 1) ptCurrentPage = 1;
    if (ptCurrentPage > totalPages) ptCurrentPage = totalPages || 1;

    const start = pgSize > 0 ? (ptCurrentPage - 1) * pgSize : 0;
    const end   = pgSize > 0 ? start + pgSize : totalNodes;
    const pageRoots = visibleRoots.slice(start, end);

    // Update pagination UI
    const prevBtn  = document.getElementById('ptPrevBtn');
    const nextBtn  = document.getElementById('ptNextBtn');
    const pageInfo = document.getElementById('ptPageInfo');

    if (pgSize > 0 && totalPages > 1) {
      prevBtn.disabled = ptCurrentPage <= 1;
      nextBtn.disabled = ptCurrentPage >= totalPages;
      prevBtn.style.opacity = ptCurrentPage <= 1 ? '0.35' : '1';
      nextBtn.style.opacity = ptCurrentPage >= totalPages ? '0.35' : '1';
      pageInfo.textContent = `Page ${ptCurrentPage} of ${totalPages}`;
    } else {
      prevBtn.disabled = true; nextBtn.disabled = true;
      prevBtn.style.opacity = '0.35'; nextBtn.style.opacity = '0.35';
      pageInfo.textContent = '';
    }

    // Show active action filter in node count
    var filterLabel = '';
    if (ptActionFilter) {
      var fcat = PT_ACTION_CATS.find(function(c) { return c.color === ptActionFilter; });
      filterLabel = fcat ? ' · filtered by <span style="color:' + fcat.color + ';font-weight:700">' + fcat.label + '</span>' : '';
    }
    document.getElementById('ptNodeCount').innerHTML =
      totalNodes + ' root processes matched · showing ' + pageRoots.length + filterLabel;

    // Count total events across visible
    let totalEvents = 0;
    visibleRoots.forEach(function countEv(n) { totalEvents += n.events.length; n.children.forEach(countEv); });
    updatePTStats(totalNodes, totalEvents);

    // Render using DocumentFragment for performance
    body.innerHTML = '';
    if (!pageRoots.length) {
      var emptyMsg = ptActionFilter
        ? '<div class="pt-empty">No processes with <strong>' +
          (PT_ACTION_CATS.find(function(c){return c.color===ptActionFilter;})||{label:'that action'}).label +
          '</strong> events found.<br><span style="font-size:11px;opacity:0.7">Click the active filter again to clear it.</span></div>'
        : '<div class="pt-empty">No processes match. Try a different search term.</div>';
      body.innerHTML = emptyMsg;
      return;
    }

    const frag = document.createDocumentFragment();

    pageRoots.forEach((root, idx) => {
      const isLast = idx === pageRoots.length - 1;
      renderNode(root, 0, isLast, [], frag, hostF, terms);
    });

    body.appendChild(frag);
  }

  function renderNode(node, depth, isLast, ancestorHasMore, container, hostF, terms) {
    if (!ptNodeMatches(node, hostF, terms)) return;

    const key = node.key;
    if (!ptExpandState.has(key)) ptExpandState.set(key, depth < 2);

    const wrap = document.createElement('div');
    wrap.className = 'pt-node-wrap';

    const rowEl = document.createElement('div');
    rowEl.className = 'pt-row';

    // Indent
    const indentEl = document.createElement('div');
    indentEl.className = 'pt-indent';
    for (let i = 0; i < depth; i++) {
      const seg = document.createElement('div');
      seg.className = i === depth - 1 ? 'pt-corner' : 'pt-pipe';
      if (i !== depth - 1 && !ancestorHasMore[i]) seg.style.opacity = '0';
      indentEl.appendChild(seg);
    }
    rowEl.appendChild(indentEl);

    // Expand toggle
    const filteredChildren = node.children.filter(c => ptNodeMatches(c, hostF, terms));
    if (filteredChildren.length) {
      const tog = document.createElement('div');
      tog.className = 'pt-children-toggle';
      tog.textContent = ptExpandState.get(key) ? '−' : '+';
      tog.onclick = e => {
        e.stopPropagation();
        ptExpandState.set(key, !ptExpandState.get(key));
        renderProcTree();
      };
      rowEl.appendChild(tog);
    } else {
      const sp = document.createElement('div');
      sp.style.cssText = 'width:18px;flex-shrink:0';
      rowEl.appendChild(sp);
    }

    // Card
    const card = document.createElement('div');
    card.className = 'pt-card';
    card.style.borderLeftColor = getActionColor(node.events[0]?.action || '');

    // Top row
    const top = document.createElement('div');
    top.className = 'pt-top';

    const icon = document.createElement('span');
    icon.className = 'pt-icon';
    icon.textContent = getPTIcon(node.fname);
    top.appendChild(icon);

    const name = document.createElement('span');
    name.className = 'pt-name';
    // Highlight search terms in name
    name.innerHTML = ptHighlightTerms(escapeHtml(node.fname || 'unknown'), terms);
    top.appendChild(name);

    if (node.pid) {
      const pid = document.createElement('span');
      pid.className = 'pt-pid';
      pid.textContent = `PID:${node.pid}`;
      top.appendChild(pid);
    }

    // Action counts badge
    const actionCounts = {};
    node.events.forEach(e => { actionCounts[e.action] = (actionCounts[e.action]||0)+1; });
    const topAction = Object.entries(actionCounts).sort((a,b)=>b[1]-a[1])[0]?.[0] || '';
    if (topAction) {
      const ab = document.createElement('span');
      ab.className = 'pt-action-badge';
      ab.style.color = getActionColor(topAction);
      ab.style.borderColor = getActionColor(topAction);
      // Windows Security EventID short labels
      const WIN_SHORT = {
        '4688':'Process','4689':'ProcEnd',
        '4624':'Logon','4625':'Failed','4634':'Logoff','4648':'ExplicitLogon',
        '4740':'Lockout','4776':'NTLM',
        '4768':'Kerb-TGT','4769':'Kerb-SVC','4770':'Kerb-Renew','4771':'Kerb-Fail',
        '4103':'PS-Module','4104':'PS-Script',
        '4697':'Service','7045':'NewService','7036':'SvcState',
        '4698':'SchedTask','4699':'TaskDel','4702':'TaskMod',
        '4720':'AcctCreate','4722':'AcctEnable','4725':'AcctDisable','4726':'AcctDelete',
        '4738':'AcctChange','4781':'AcctRename','4740':'Lockout',
        '4728':'GroupAdd','4729':'GroupRem','4732':'LocalGrpAdd','4733':'LocalGrpRem',
        '4756':'UniGrpAdd','4757':'UniGrpRem',
        '4672':'SpecPriv','4673':'PrivUse',
        '1102':'LogCleared','1100':'EvtStop','4719':'PolicyChg',
      };
      ab.textContent = WIN_SHORT[topAction.trim()]
        || topAction.replace(/ProcessCreated?/i,'Proc').replace(/Connection/i,'Conn').replace(/Created$/i,'');
      top.appendChild(ab);
    }

    if (node.events.length > 1) {
      const ec = document.createElement('span');
      ec.style.cssText = 'font-size:9px;background:rgba(255,255,255,.07);border:1px solid #304D4A;border-radius:10px;padding:1px 7px;color:#778F8D;flex-shrink:0';
      ec.textContent = `${node.events.length} events`;
      top.appendChild(ec);
    }

    if (node.firstSeen) {
      const ts = document.createElement('span');
      ts.className = 'pt-ts';
      ts.textContent = node.firstSeen.slice(0,19).replace('T',' ');
      top.appendChild(ts);
    }

    card.appendChild(top);

    // Cmdline with search highlight
    if (node.cmdline) {
      const cmd = document.createElement('div');
      cmd.className = 'pt-cmd';
      let cmdHtml = highlightPTCmd(node.cmdline);
      if (terms.length) cmdHtml = ptHighlightTerms(cmdHtml, terms);
      cmd.innerHTML = cmdHtml;
      card.appendChild(cmd);
    }

    // Detail panel (click to toggle)
    const detail = document.createElement('div');
    detail.className = 'pt-detail';

    const detailFields = [
      ['Device',      node.device],
      ['User',        node.user],
      ['PID',         node.pid],
      ['Path',        node.fpath],
      ['SHA256',      node.sha256],
      ['SHA1',        node.sha1],
      ['MD5',         node.md5],
      ['First seen',  node.firstSeen],
      ['Last seen',   node.lastSeen],
      ['Parent',      node.initFname ? `${node.initFname} (PID:${node.initPid})` : ''],
      ['Parent CMD',  node.initCmd],
      ['Integrity',   node.integrity],
    ];

    detailFields.forEach(([k, v]) => {
      if (!v) return;
      const dr = document.createElement('div');
      dr.className = 'pt-detail-row';
      dr.innerHTML = `<span class="pt-detail-key">${k}</span><span class="pt-detail-val">${ptHighlightTerms(escapeHtml(v), terms)}</span>`;
      detail.appendChild(dr);
    });

    if (node.events.length) {
      const evHdr = document.createElement('div');
      evHdr.className = 'pt-detail-row';
      evHdr.innerHTML = `<span class="pt-detail-key" style="color:var(--cb-yellow)">Events (${node.events.length})</span>`;
      detail.appendChild(evHdr);

      node.events.slice(0, 30).forEach(ev => {
        const evR = document.createElement('div');
        evR.className = 'pt-detail-row';
        let evDesc = ev.action || '';
        if (ev.remoteIp)   evDesc += ` → ${ev.remoteIp}`;
        if (ev.remoteUrl)  evDesc += ` (${ev.remoteUrl})`;
        if (ev.remotePort) evDesc += `:${ev.remotePort}`;
        if (ev.regKey)     evDesc += ` ${ev.regKey}`;
        if (ev.regVal)     evDesc += `\\${ev.regVal}`;
        evR.innerHTML = `<span class="pt-detail-key">${(ev.ts||'').slice(0,19).replace('T',' ')}</span><span class="pt-detail-val" style="color:${getActionColor(ev.action)}">${ptHighlightTerms(escapeHtml(evDesc), terms)}</span>`;
        detail.appendChild(evR);
      });
      if (node.events.length > 30) {
        const more = document.createElement('div');
        more.className = 'pt-detail-row';
        more.innerHTML = `<span class="pt-detail-key"></span><span class="pt-detail-val" style="color:#537173">…and ${node.events.length - 30} more events</span>`;
        detail.appendChild(more);
      }
    }

    card.appendChild(detail);
    card.addEventListener('click', () => detail.classList.toggle('open'));
    card.addEventListener('contextmenu', function(e) { openPtMenu(e, node); });

    rowEl.appendChild(card);
    wrap.appendChild(rowEl);

    // Children
    if (ptExpandState.get(key) && filteredChildren.length) {
      filteredChildren.forEach((child, idx) => {
        const childIsLast = idx === filteredChildren.length - 1;
        renderNode(child, depth + 1, childIsLast, [...ancestorHasMore, !isLast], wrap, hostF, terms);
      });
    }

    container.appendChild(wrap);
  }

  // Highlight search terms in already-escaped HTML
  function ptHighlightTerms(html, terms) {
    if (!terms.length) return html;
    terms.forEach(term => {
      const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      html = html.replace(new RegExp(`(${escaped})`, 'gi'),
        '<mark style="background:rgba(255,215,0,0.35);color:inherit;border-radius:2px;padding:0 1px">$1</mark>');
    });
    return html;
  }

  function updatePTStats(nodes, events) {
    const el = document.getElementById('ptStats');
    el.innerHTML = `
      <div class="pt-stat-pill"><strong>${nodes}</strong> Processes</div>
      <div class="pt-stat-pill"><strong>${events}</strong> Events</div>
    `;
  }

  function expandAllPT() {
    if (!ptTree) return;
    ptTree.nodeMap.forEach((_, key) => ptExpandState.set(key, true));
    renderProcTree();
  }

  function collapseAllPT() {
    if (!ptTree) return;
    ptTree.nodeMap.forEach((_, key) => ptExpandState.set(key, false));
    renderProcTree();
  }

  function getActionColor(action) {
    const id = (action || '').trim();

    // Windows Security EventIDs — grouped by investigation category
    // Process events
    if (id === '4688' || id === '4689') return '#e05c3a';
    // Logon / successful auth
    if (['4624','4634','4647','4648','4649','4776','4778','4779'].includes(id)) return '#3a9fd6';
    // Auth failures / lockouts
    if (['4625','4740','4771','4777'].includes(id)) return '#e83e3e';
    // Kerberos
    if (['4768','4769','4770','4771'].includes(id)) return '#26c6da';
    // Script / PowerShell / Persistence (scheduled tasks, services)
    if (['4103','4104','4105','4106','4697','4698','4699','4700','4701','4702','7034','7035','7036','7040','7045'].includes(id)) return '#f0a500';
    // Account changes (user create/modify/delete/enable/disable/rename)
    if (['4720','4722','4723','4724','4725','4726','4738','4767','4781'].includes(id)) return '#c45ab3';
    // Group membership changes
    if (['4727','4728','4729','4730','4731','4732','4733','4734','4735','4737','4756','4757'].includes(id)) return '#9c6ade';
    // Log cleared / audit policy / defense evasion
    if (['1100','1102','4719','4946','4947','4948'].includes(id)) return '#f06292';
    // Privilege use
    if (['4672','4673','4674'].includes(id)) return '#3a9fd6';
    // Object access / file events
    if (['4656','4657','4658','4660','4663','4670'].includes(id)) return '#c45ab3';
    // Other numeric EventIDs — green
    if (/^\d+$/.test(id)) return '#4caf80';

    // Chronicle UDM event types
    if (typeof udmEventColor === 'function') {
      const c = udmEventColor(action);
      if (c) return c;
    }

    // Defender action type strings
    const a = (action || '').toLowerCase();
    if (a.includes('processcreated') || a.includes('process_created')) return '#e05c3a';
    if (a.includes('network') || a.includes('connection'))             return '#3a9fd6';
    if (a.includes('file'))                                            return '#c45ab3';
    if (a.includes('registry'))                                        return '#f0a500';
    if (a.includes('logon') || a.includes('auth'))                     return '#f06292';
    if (a.includes('dns'))                                             return '#26c6da';
    if (a.includes('image') || a.includes('module'))                   return '#9c6ade';
    return '#4caf80';
  }

  function getPTIcon(name) {
    // Extract basename from full paths (Windows or Linux)
    const n = (name || '').replace(/.*[/\\]/, '').toLowerCase();
    if (/powershell|pwsh/.test(n))               return '⚡';
    if (/cmd\.exe/.test(n))                      return '⬛';
    if (/explorer/.test(n))                      return '📁';
    if (/chrome|firefox|edge|iexplore/.test(n))  return '🌐';
    if (/word|excel|outlook|winword/.test(n))    return '📄';
    if (/wscript|cscript|mshta/.test(n))         return '📜';
    if (/svchost/.test(n))                       return '⚙️';
    if (/lsass/.test(n))                         return '🔑';
    if (/rundll32|regsvr32/.test(n))             return '🔄';
    if (/^net(\.exe|1)?$/.test(n))               return '🌐';
    if (/reg\.exe/.test(n))                      return '🗂️';
    if (/mimikatz|procdump/.test(n))             return '🚨';
    if (/python|pip/.test(n))                    return '🐍';
    if (/java/.test(n))                          return '☕';
    if (/curl|wget/.test(n))                     return '📡';
    if (/bash|sh|zsh|dash/.test(n))              return '🐚';
    if (/sudo|su$/.test(n))                      return '🔐';
    return '▸';
  }

  function highlightPTCmd(cmd) {
    let s = escapeHtml(cmd);
    s = s.replace(/((?:^|\s)-[\w]+)/g,                    '<span class="hl-flag">$1</span>');
    s = s.replace(/([A-Za-z]:\\[^\s&lt;&gt;"]+)/g,        '<span class="hl-path">$1</span>');
    s = s.replace(/\b((?:\d{1,3}\.){3}\d{1,3})\b/g,      '<span class="hl-ip">$1</span>');
    s = s.replace(/\b([A-Fa-f0-9]{64}|[A-Fa-f0-9]{32})\b/g,'<span class="hl-hash">$1</span>');
    s = s.replace(/(-enc\s+[A-Za-z0-9+\/=]{8,})/gi,      '<span class="hl-enc">$1</span>');
    return s;
  }

  // ── Process Tree Right-Click Menu ─────────────────────────────────────────
  function openPtMenu(e, node) {
    // Unique remote IPs across all events on this node
    const remoteIps = [...new Set(node.events.map(function(ev) { return ev.remoteIp; }).filter(Boolean))];
    const remoteUrls = [...new Set(node.events.map(function(ev) { return ev.remoteUrl; }).filter(Boolean))];
    const hasEncoded = /-enc(?:odedCommand)?\s+[A-Za-z0-9+\/=]{16,}/i.test(node.cmdline || '');

    function clip(text) { navigator.clipboard.writeText(text || '').catch(function(){}); }

    function ptAddTableFilter(col, val) {
      const id = ++filterRowCounter;
      filterRows.push({ id, col: col, mode: 'contains', value: val, connector: 'AND' });
      renderFilterRows();
      document.getElementById('filterBar').classList.remove('hidden');
      applyFilter();
    }

    function buildSummary() {
      const lines = [
        'Process:  ' + (node.fname || '') + (node.pid ? '  (PID: ' + node.pid + ')' : ''),
      ];
      if (node.cmdline)    lines.push('Command:  ' + node.cmdline);
      if (node.fpath)      lines.push('Path:     ' + node.fpath);
      if (node.user)       lines.push('User:     ' + node.user);
      if (node.device)     lines.push('Device:   ' + node.device);
      if (node.integrity)  lines.push('Integrity:' + node.integrity);
      if (node.sha256)     lines.push('SHA256:   ' + node.sha256);
      if (node.sha1)       lines.push('SHA1:     ' + node.sha1);
      if (node.md5)        lines.push('MD5:      ' + node.md5);
      if (node.firstSeen)  lines.push('First:    ' + node.firstSeen.slice(0,19).replace('T',' '));
      if (node.lastSeen && node.lastSeen !== node.firstSeen)
                           lines.push('Last:     ' + node.lastSeen.slice(0,19).replace('T',' '));
      if (node.initFname)  lines.push('Parent:   ' + node.initFname + (node.initPid ? ' (PID: ' + node.initPid + ')' : ''));
      if (node.initCmd)    lines.push('ParentCmd:' + node.initCmd);
      if (remoteIps.length)  lines.push('Remote IPs:  ' + remoteIps.join(', '));
      if (remoteUrls.length) lines.push('Remote URLs: ' + remoteUrls.join(', '));
      // Event summary
      const counts = {};
      node.events.forEach(function(ev) { counts[ev.action] = (counts[ev.action]||0)+1; });
      const evSummary = Object.entries(counts).map(function(kv){ return kv[0] + ' ×' + kv[1]; }).join(', ');
      if (evSummary) lines.push('Events:   ' + node.events.length + '  (' + evSummary + ')');
      return lines.join('\n');
    }

    const items = [
      { type: 'label',   text: (node.fname || 'Process') + (node.pid ? '  ·  PID ' + node.pid : '') },
      { type: 'preview', text: node.cmdline || node.fpath || '' },
      { type: 'sep' },
      { type: 'item', icon: '📋', text: 'Copy process name',    fn: function() { clip(node.fname); } },
    ];

    if (node.cmdline)  items.push({ type: 'item', icon: '📋', text: 'Copy command line',  fn: function() { clip(node.cmdline); } });
    if (node.fpath)    items.push({ type: 'item', icon: '📋', text: 'Copy file path',     fn: function() { clip(node.fpath); } });
    if (node.pid)      items.push({ type: 'item', icon: '📋', text: 'Copy PID',           fn: function() { clip(node.pid); } });
    if (node.sha256)   items.push({ type: 'item', icon: '📋', text: 'Copy SHA256',        fn: function() { clip(node.sha256); } });
    if (node.md5)      items.push({ type: 'item', icon: '📋', text: 'Copy MD5',           fn: function() { clip(node.md5); } });
    remoteIps.slice(0, 3).forEach(function(ip) {
      items.push({ type: 'item', icon: '📋', text: 'Copy IP  ' + ip, fn: function() { clip(ip); } });
    });
    items.push({ type: 'item', icon: '📄', text: 'Copy full summary', fn: function() { clip(buildSummary()); } });

    items.push({ type: 'sep' });
    if (node.fname) items.push({ type: 'item', icon: '🔍', text: 'Filter table by process name', fn: function() { ptAddTableFilter('', node.fname); } });
    if (node.pid)   items.push({ type: 'item', icon: '🔍', text: 'Filter table by PID',          fn: function() { ptAddTableFilter('', node.pid); } });
    if (node.user)  items.push({ type: 'item', icon: '🔍', text: 'Filter table by user',         fn: function() { ptAddTableFilter('', node.user); } });

    // IOC pivots
    const pivotItems = [];
    if (node.sha256) pivotItems.push({ type: 'item', icon: '🦠', text: 'VirusTotal  (SHA256)', url: 'https://www.virustotal.com/gui/file/' + node.sha256 });
    if (node.md5)    pivotItems.push({ type: 'item', icon: '🦠', text: 'VirusTotal  (MD5)',    url: 'https://www.virustotal.com/gui/file/' + node.md5 });
    remoteIps.slice(0, 3).forEach(function(ip) {
      pivotItems.push({ type: 'item', icon: '🦠', text: 'VirusTotal  ' + ip, url: 'https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip) });
      pivotItems.push({ type: 'item', icon: '🔭', text: 'Shodan  ' + ip,     url: 'https://www.shodan.io/host/' + encodeURIComponent(ip) });
    });
    remoteUrls.slice(0, 2).forEach(function(url) {
      pivotItems.push({ type: 'item', icon: '🦠', text: 'VirusTotal  ' + (url.length > 30 ? url.slice(0,27)+'…' : url), url: 'https://www.virustotal.com/gui/search/' + encodeURIComponent(url) });
    });
    if (hasEncoded) {
      const m = (node.cmdline || '').match(/-enc(?:odedCommand)?\s+([A-Za-z0-9+\/=]+)/i);
      if (m) pivotItems.push({ type: 'item', icon: '⚗️', text: 'CyberChef  (decode -enc)', url: 'https://cyberchef.org/#input=' + encodeURIComponent(btoa(m[1])) });
    }
    if (pivotItems.length) {
      items.push({ type: 'sep' });
      pivotItems.forEach(function(p) { items.push(p); });
    }

    // Add to query builder — individual item per IOC
    if (typeof qbAddCondition === 'function') {
      var _qbItems = [];
      if (node.sha256) _qbItems.push({ col:'sha256', val:node.sha256, label:'SHA256: '+node.sha256.slice(0,12)+'…' });
      if (node.md5)    _qbItems.push({ col:'md5',    val:node.md5,    label:'MD5: '   +node.md5 });
      if (node.sha1)   _qbItems.push({ col:'sha1',   val:node.sha1,   label:'SHA1: '  +node.sha1.slice(0,12)+'…' });
      if (node.cmdline) _qbItems.push({ col:'process command line', val:node.cmdline, label:'cmdline: '+(node.cmdline.length>20?node.cmdline.slice(0,17)+'…':node.cmdline) });
      if (node.fname)  _qbItems.push({ col:'file name', val:node.fname, label:'process: '+node.fname });
      remoteIps.slice(0, 3).forEach(function(ip) { _qbItems.push({ col:'remote ip', val:ip, label:'IP: '+ip }); });
      remoteUrls.slice(0, 2).forEach(function(u) { _qbItems.push({ col:'remote url', val:u, label:'URL: '+(u.length>25?u.slice(0,22)+'…':u) }); });
      if (_qbItems.length) {
        items.push({ type:'sep' });
        _qbItems.forEach(function(b) {
          items.push({ type:'item', icon:'➕', text:'Add to QB: '+b.label,
            fn: (function(c,v,l){ return function(){ qbAddCondition(c,v,l); }; })(b.col,b.val,b.label) });
        });
      }
    }

    // Query builders — one block per available IOC
    if (typeof ctxQueryItems === 'function') {
      var qBlocks = [];
      if (node.sha256) qBlocks.push({ col: 'sha256',      val: node.sha256, suffix: 'SHA256' });
      if (node.md5)    qBlocks.push({ col: 'md5',         val: node.md5,    suffix: 'MD5' });
      if (node.sha1)   qBlocks.push({ col: 'sha1',        val: node.sha1,   suffix: 'SHA1' });
      if (node.cmdline) qBlocks.push({ col: 'process command line', val: node.cmdline, suffix: 'cmdline' });
      if (node.fname)  qBlocks.push({ col: 'file name',   val: node.fname,  suffix: 'process' });
      remoteIps.slice(0, 2).forEach(function(ip) {
        qBlocks.push({ col: 'remote ip', val: ip, suffix: ip });
      });
      remoteUrls.slice(0, 2).forEach(function(url) {
        qBlocks.push({ col: 'remote url', val: url, suffix: url.length > 30 ? url.slice(0,27)+'…' : url });
      });
      qBlocks.forEach(function(b) {
        var q = ctxQueryItems(b.col, b.val, b.suffix);
        if (q.length) { items.push({ type: 'sep' }); q.forEach(function(qi) { items.push(qi); }); }
      });
    }

    showCtxMenu(e, items);
  }

  // Close modal on backdrop click
