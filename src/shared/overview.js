// overview.js — Data-driven overview dashboard
// Computation runs in a web worker; main thread only builds DOM.

  var overviewVisible  = false;
  var _ovWorker        = null;
  var _ovRenderTimer   = null;
  var _ovProfile       = null; // null = default | tactic name | technique ID
  var _ovCustomActive  = null; // active custom profile { name, cards, customFields } | null
  var _ovCardSizes     = {};   // { cardKey: 'compact'|'normal'|'wide'|'full' }
  var _ovCardHeights   = {};   // { cardKey: pixels (number) } — explicit height, null = auto
  var _ovCardOrder     = [];   // [cardKey, ...] — current drag order, empty = default
  var _ovDragKey       = null; // key of card being dragged
  var _ovChartModes    = {};   // { cardId: 'list'|'pie'|'bars'|'donut' } — persist chart toggles across re-renders
  var _ovListenersAC   = null; // AbortController for per-render document click listeners (dropdown close handlers)

  // ── All standard card definitions for the custom profile builder ──────────────
  var CARD_DEFS = [
    { key: 'time',          label: 'Timeline',            desc: 'First/last event and duration' },
    { key: 'scope',         label: 'Scope',               desc: 'Device and user counts' },
    { key: 'activity',      label: 'Activity',            desc: 'Action type frequency bar chart' },
    { key: 'severity',      label: 'Severity',            desc: 'Alert severity breakdown' },
    { key: 'hostsAccounts', label: 'Hosts & Accounts',    desc: 'Top devices and users' },
    { key: 'process',       label: 'Processes',           desc: 'Top process names' },
    { key: 'procPairs',     label: 'Process Spawn Pairs', desc: 'Parent → child process chains' },
    { key: 'network',       label: 'Network',             desc: 'External IPs, domains, ports, beaconing' },
    { key: 'registry',      label: 'Registry',            desc: 'Registry key modifications' },
    { key: 'hashes',        label: 'File Hashes',         desc: 'SHA256/MD5 with VirusTotal links' },
  ];

  // ── localStorage helpers ──────────────────────────────────────────────────────
  function _cpSave(profile) {
    try {
      const all = _cpAll();
      const idx = all.findIndex(p => p.name === profile.name);
      if (idx >= 0) all[idx] = profile; else all.push(profile);
      localStorage.setItem('sift_custom_profiles', JSON.stringify(all));
    } catch(e) {}
  }
  function _cpAll() {
    try { return JSON.parse(localStorage.getItem('sift_custom_profiles') || '[]'); } catch(e) { return []; }
  }
  function _cpDelete(name) {
    try {
      localStorage.setItem('sift_custom_profiles', JSON.stringify(_cpAll().filter(p => p.name !== name)));
    } catch(e) {}
  }

  // ── Typeahead navigation ─────────────────────────────────────────────────────
  var _ovTypeaheadStr  = '';
  var _ovTypeaheadTimer = null;
  var _ovHoveredList   = null;  // last .ov-card-list the mouse entered
  var _ovHoveredRegion = null;  // 'ttp' | 'list' | null

  function _ovKeydown(e) {
    if (!overviewVisible) return;
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if (e.ctrlKey || e.altKey || e.metaKey) return;
    if (!/^[a-zA-Z0-9.\-_]$/.test(e.key)) return;

    _ovTypeaheadStr += e.key.toLowerCase();
    clearTimeout(_ovTypeaheadTimer);
    _ovTypeaheadTimer = setTimeout(() => { _ovTypeaheadStr = ''; }, 1000);

    // If hovering TTP selector, route to its search box
    if (_ovHoveredRegion === 'ttp') {
      const ttpSearch = document.querySelector('.ov-ttp-search');
      if (ttpSearch) {
        ttpSearch.value = _ovTypeaheadStr;
        ttpSearch.dispatchEvent(new Event('input'));
        ttpSearch.focus();
      }
      return;
    }

    // Otherwise jump to first matching item in the hovered list
    if (!_ovHoveredList) return;
    const rows = _ovHoveredList.querySelectorAll('.ov-list-row');
    for (const row of rows) {
      const lbl = row.querySelector('.ov-list-label');
      if (lbl && lbl.textContent.trim().toLowerCase().startsWith(_ovTypeaheadStr)) {
        row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        row.style.transition = 'background 0.1s';
        row.style.background = 'rgba(255,215,0,0.35)';
        setTimeout(() => { row.style.background = ''; }, 700);
        break;
      }
    }
  }

  document.addEventListener('keydown', _ovKeydown);

  function scheduleOverviewRender() {
    clearTimeout(_ovRenderTimer);
    _ovRenderTimer = setTimeout(renderOverview, 350);
  }

  function toggleOverview() {
    overviewVisible = !overviewVisible;
    const btn     = document.getElementById('overviewBtn');
    const panel   = document.getElementById('overviewPanel');
    const tblWrap = document.getElementById('tableWrap');
    const pgBar   = document.getElementById('paginationBar');

    if (overviewVisible) {
      tblWrap.style.display = 'none';
      pgBar.classList.remove('visible');
      panel.style.display = 'flex';
      if (btn) btn.classList.add('active');
      renderOverview();
    } else {
      _killWorker();
      panel.style.display = 'none';
      tblWrap.style.display = filteredSorted.length ? 'block' : 'none';
      if (btn) btn.classList.remove('active');
      renderPage();
    }
  }

  function _killWorker() {
    if (_ovWorker) { _ovWorker.terminate(); _ovWorker = null; }
    _ovTypeaheadStr = ''; clearTimeout(_ovTypeaheadTimer);
    _ovHoveredList = null; _ovHoveredRegion = null;
  }

  function resetOvProfile() { _ovProfile = null; _ovCardSizes = {}; _ovCardHeights = {}; _ovCardOrder = []; _ovChartModes = {}; }

  function _sortIndicatorsByProfile(indicators) {
    if (!_ovProfile || !indicators.length) return indicators;
    const profileDef = _ovGetProfileDef();
    const profileTactic = profileDef.tactic || _ovProfile;

    // Determine which tactic this profile maps to
    let targetTactic = _ovProfile;
    if (typeof TECHNIQUE_PROFILES !== 'undefined' && TECHNIQUE_PROFILES[_ovProfile]) {
      // technique override — get its tactic from MITRE_TECHNIQUES
      const tech = typeof MITRE_TECHNIQUES !== 'undefined' ? MITRE_TECHNIQUES.find(t => t.id === _ovProfile) : null;
      if (tech) targetTactic = tech.tactic;
    }

    // Score each indicator: 0 = profile-relevant, 1 = same tactic, 2 = other
    const score = ind => {
      if (ind.techId === _ovProfile) return 0;
      if (ind.tactic === targetTactic) return 1;
      return 2;
    };

    // Stable sort — relevant indicators float to top, order within groups preserved
    return [...indicators].sort((a, b) => score(a) - score(b));
  }

  // ── Render: launch worker ────────────────────────────────────────────────────
  function renderOverview() {
    const panel = document.getElementById('overviewPanel');
    if (!panel) return;

    const rows = filteredSorted.length ? filteredSorted : allRows;
    if (!rows.length) {
      panel.innerHTML = '<div style="padding:40px;color:var(--cb-muted);text-align:center;font-size:14px">No data loaded</div>';
      return;
    }

    if (!Object.keys(ptColMap).length) ptResolveColumns(headers);

    // Show spinner immediately
    panel.innerHTML = '<div class="ov-loading"><div class="ov-spinner"></div><span id="ovLoadMsg">Analyzing…</span></div>';

    // Extract only the columns the worker needs — flat string arrays, fast to transfer
    const COL_KEYS = {
      ts: ptColMap.ts, action: ptColMap.action, device: ptColMap.device,
      user: ptColMap.user, cmdline: ptColMap.cmdline, fileName: ptColMap.fileName,
      initFile: ptColMap.initFile, initCmd: ptColMap.initCmd, filePath: ptColMap.filePath,
      remoteIp: ptColMap.remoteIp, remoteUrl: ptColMap.remoteUrl, remotePort: ptColMap.remotePort,
      regKey: ptColMap.regKey, regVal: ptColMap.regVal, regData: ptColMap.regData,
      sha256: ptColMap.sha256, sha1: ptColMap.sha1, md5: ptColMap.md5,
      integrity: ptColMap.integrity,
      // Windows Security Log specific columns
      winEventId:     ptColMap.winEventId,
      winLogonType:   ptColMap.winLogonType,
      winSubjectUser: ptColMap.winSubjectUser,
      winTargetUser:  ptColMap.winTargetUser,
      winStatus:      ptColMap.winStatus,
      winAuthPkg:     ptColMap.winAuthPkg,
    };

    // Detect severity column
    const severityColName = headers.find(h => {
      const l = h.toLowerCase().trim();
      return l === 'security_result.severity' || l === 'udm.security_result.severity' ||
             l === 'severity' || l === 'alert severity';
    }) || '';

    if (severityColName) COL_KEYS.severity = severityColName;

    // Filtered cols — used for all cards (processes, network, etc.)
    const cols = {};
    Object.entries(COL_KEYS).forEach(([key, col]) => {
      if (col) cols[key] = rows.map(r => r[col] || '');
    });

    // MITRE cols — always from allRows so coverage map never changes with filters
    const mitreCols = {};
    Object.entries(COL_KEYS).forEach(([key, col]) => {
      if (col) mitreCols[key] = allRows.map(r => r[col] || '');
    });

    _killWorker();
    _ovWorker = createBlobWorker('overview-worker-src');

    _ovWorker.onmessage = function(e) {
      if (e.data.type === 'progress') {
        const el = document.getElementById('ovLoadMsg');
        if (el) el.textContent = e.data.msg;
      } else if (e.data.type === 'done') {
        _ovWorker = null;
        renderFromData(e.data.data, rows);
      }
    };

    _ovWorker.onerror = function(err) {
      _ovWorker = null;
      console.error('Overview worker error:', err);
      renderFromData(_computeFallback(rows), rows);
    };

    _ovWorker.postMessage({ cols, mitreCols, ptColMap, isChronicleData,
      isWindowsSecLog: (typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog),
      severityColName, activeProfile: _ovProfile || '',
      buildFeatures: (typeof SIFT_FEATURES !== 'undefined') ? SIFT_FEATURES : {} });
  }

  // ── Render: build DOM from worker data ───────────────────────────────────────
  function renderFromData(d, rows) {
    const panel = document.getElementById('overviewPanel');
    if (!panel || !overviewVisible) return;
    // Abort previous render's document click listeners (dropdown close handlers) to prevent accumulation
    if (_ovListenersAC) _ovListenersAC.abort();
    _ovListenersAC = new AbortController();
    // Clean up any card settings dropdowns portalled to body from the previous render
    document.querySelectorAll('.ov-card-dd-portal').forEach(el => el.remove());
    panel.innerHTML = '';

    const s = d.s;

    // Header
    const hdr = document.createElement('div');
    hdr.className = 'ov-header';

    const hdrTop = document.createElement('div'); hdrTop.className = 'ov-header-top';
    const hdrTitle = document.createElement('div');
    hdrTitle.className = 'ov-header-title';
    hdrTitle.textContent = 'Overview';
    const srcBadge = document.createElement('span');
    srcBadge.className = 'ov-source-badge';
    if (isChronicleData) {
      srcBadge.textContent = 'Chronicle';
      srcBadge.style.cssText = 'background:#FFFFFF;border:1px solid #4285f4;color:#4285f4';
    } else if (typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog) {
      srcBadge.textContent = 'Windows Security';
      srcBadge.style.cssText = 'background:#FFFFFF;border:1px solid #00bc66;color:#00bc66';
    } else if (ptHasDefenderCols()) {
      srcBadge.textContent = 'Defender';
      srcBadge.style.cssText = 'background:#FFFFFF;border:1px solid #0078d4;color:#0078d4';
    } else {
      srcBadge.textContent = 'CSV';
      srcBadge.style.cssText = 'background:#FFFFFF;border:1px solid var(--cb-os2);color:var(--cb-os2)';
    }
    hdrTitle.appendChild(srcBadge);

    const filterNote = document.createElement('span');
    filterNote.className = 'ov-filter-note';
    filterNote.textContent = filteredSorted.length < allRows.length
      ? `${d.rowCount.toLocaleString()} filtered of ${allRows.length.toLocaleString()} total`
      : `${d.rowCount.toLocaleString()} rows`;

    // "View in table" button — only shown when filters are active
    const viewTableBtn = document.createElement('button');
    viewTableBtn.className = 'ov-view-table-btn';
    viewTableBtn.textContent = '→ View in table';
    viewTableBtn.title = 'Switch to table view with current filters';
    viewTableBtn.onclick = () => toggleOverview();

    // ── Investigating: profile selector (hidden when MITRE is disabled — profiles are MITRE-based) ──
    const _mitrEnabledHdr = (typeof SIFT_FEATURES === 'undefined') || SIFT_FEATURES.mitre !== false;
    const profileDef = _ovGetProfileDef();
    const profileWrap = document.createElement('div'); profileWrap.style.cssText = 'position:relative;margin-left:auto';
    const profileBtn  = document.createElement('button'); profileBtn.className = 'ov-profile-btn';
    profileBtn.innerHTML = `${profileDef.icon} <span>Investigating: <strong>${profileDef.label}</strong></span> ▾`;
    profileBtn.title = 'Switch investigation profile — reshapes the dashboard for your focus area';

    const profileDropdown = document.createElement('div'); profileDropdown.className = 'ov-profile-dropdown';
    profileDropdown.style.display = 'none';

    // ── Saved custom profiles — always at the top ─────────────────────────────
    const saved = _cpAll();
    if (saved.length) {
      const savedLbl = document.createElement('div'); savedLbl.style.cssText = 'font-size:9px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--cb-muted);padding:2px 10px 4px'; savedLbl.textContent = 'Custom Profiles'; profileDropdown.appendChild(savedLbl);
      saved.forEach(sp => {
        const opt = document.createElement('div'); opt.className = 'ov-profile-opt';
        if (_ovCustomActive && _ovCustomActive.name === sp.name) opt.classList.add('ov-profile-opt-active');
        opt.style.cssText = 'justify-content:space-between';
        const left = document.createElement('div'); left.style.cssText = 'display:flex;align-items:center;gap:6px;flex:1;min-width:0;cursor:pointer';
        const icon = document.createElement('span'); icon.textContent = '⭐'; icon.style.cssText = 'flex-shrink:0;width:16px';
        const lbl  = document.createElement('span'); lbl.style.cssText = 'font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'; lbl.textContent = sp.name;
        left.appendChild(icon); left.appendChild(lbl);
        left.onclick = () => {
          _ovCustomActive = sp; _ovProfile = null;
          profileDropdown.style.display = 'none';
          profileBtn.innerHTML = `⭐ <span>Investigating: <strong>${sp.name}</strong></span> ▾`;
          scheduleOverviewRender();
        };
        const del = document.createElement('span');
        del.textContent = '×'; del.title = 'Delete profile';
        del.style.cssText = 'color:var(--cb-muted);cursor:pointer;padding:0 4px;font-size:13px;flex-shrink:0';
        del.onmouseover = () => del.style.color = '#e83e3e';
        del.onmouseout  = () => del.style.color = '';
        del.onclick = e => { e.stopPropagation(); _cpDelete(sp.name); if (_ovCustomActive && _ovCustomActive.name === sp.name) { _ovCustomActive = null; profileBtn.innerHTML = `🔍 <span>Investigating: <strong>General</strong></span> ▾`; } scheduleOverviewRender(); };
        opt.appendChild(left); opt.appendChild(del);
        profileDropdown.appendChild(opt);
      });
      const sepS = document.createElement('div'); sepS.style.cssText = 'border-top:1px solid var(--cb-border);margin:4px 0'; profileDropdown.appendChild(sepS);
    }

    // ── Build custom profile entry ──
    const customOpt = document.createElement('div'); customOpt.className = 'ov-profile-opt';
    customOpt.style.cssText = 'color:var(--cb-yellow-text)';
    customOpt.innerHTML = '<span style="flex-shrink:0;width:16px">＋</span><span style="font-size:12px">Build custom profile…</span>';
    customOpt.onclick = () => { profileDropdown.style.display = 'none'; _openCustomProfileBuilder(profileBtn); };
    profileDropdown.appendChild(customOpt);

    // ── Separator then standard profiles ──────────────────────────────────────
    const sep = document.createElement('div'); sep.style.cssText = 'border-top:1px solid var(--cb-border);margin:4px 0'; profileDropdown.appendChild(sep);

    // General (default)
    _addProfileOption(profileDropdown, null, 'default', d.mitreResults || {}, profileBtn);

    // ── General IT profiles — always shown regardless of MITRE setting ─────────
    const genItSep = document.createElement('div'); genItSep.style.cssText = 'border-top:1px solid var(--cb-border);margin:4px 0'; profileDropdown.appendChild(genItSep);
    const genItLbl = document.createElement('div'); genItLbl.style.cssText = 'font-size:9px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--cb-muted);padding:2px 10px 4px'; genItLbl.textContent = 'General IT'; profileDropdown.appendChild(genItLbl);
    if (typeof GENERAL_PROFILES !== 'undefined') {
      Object.entries(GENERAL_PROFILES).forEach(([id, def]) => {
        const opt = document.createElement('div'); opt.className = 'ov-profile-opt';
        if (_ovProfile === id) opt.classList.add('ov-profile-opt-active');
        const icon = document.createElement('span'); icon.style.cssText = 'flex-shrink:0;width:16px'; icon.textContent = def.icon || '';
        const lbl  = document.createElement('span'); lbl.style.cssText = 'flex:1;font-size:12px'; lbl.textContent = def.label;
        opt.appendChild(icon); opt.appendChild(lbl);
        opt.title = def.hint || '';
        opt.onclick = () => {
          _ovProfile = id; _ovCustomActive = null;
          profileDropdown.style.display = 'none';
          profileBtn.innerHTML = `${def.icon} <span>Investigating: <strong>${def.label}</strong></span> ▾`;
          scheduleOverviewRender();
        };
        profileDropdown.appendChild(opt);
      });
    }

    // ── MITRE tactic / technique profiles — only when MITRE is enabled ─────────
    if (_mitrEnabledHdr) {
    const sepT = document.createElement('div'); sepT.style.cssText = 'border-top:1px solid var(--cb-border);margin:4px 0'; profileDropdown.appendChild(sepT);
    const tacticLbl = document.createElement('div'); tacticLbl.style.cssText = 'font-size:9px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--cb-muted);padding:2px 10px 4px'; tacticLbl.textContent = 'Tactic'; profileDropdown.appendChild(tacticLbl);
    const tacticOrder = ['Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion',
      'Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact'];
    tacticOrder.forEach(tac => _addProfileOption(profileDropdown, tac, 'tactic', d.mitreResults || {}, profileBtn));

    // Technique overrides with hits
    const techHits = Object.keys(d.mitreResults || {}).filter(id => TECHNIQUE_PROFILES && TECHNIQUE_PROFILES[id]);
    if (techHits.length) {
      const sep2 = document.createElement('div'); sep2.style.cssText = 'border-top:1px solid var(--cb-border);margin:4px 0;'; profileDropdown.appendChild(sep2);
      const techLbl = document.createElement('div'); techLbl.style.cssText = 'font-size:9px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--cb-muted);padding:2px 10px 4px'; techLbl.textContent = 'Technique Focus'; profileDropdown.appendChild(techLbl);
      techHits.forEach(id => _addProfileOption(profileDropdown, id, 'technique', d.mitreResults || {}, profileBtn));
    }
    } // end if (_mitrEnabledHdr)

    profileBtn.onclick = e => { e.stopPropagation(); profileDropdown.style.display = profileDropdown.style.display === 'none' ? 'block' : 'none'; };
    document.addEventListener('click', function _closeProfile(e) {
      if (!profileWrap.contains(e.target)) { profileDropdown.style.display = 'none'; }
    }, { signal: _ovListenersAC.signal });

    profileWrap.appendChild(profileBtn); profileWrap.appendChild(profileDropdown);

    // Profile hint bar
    if (_ovProfile && profileDef.hint) {
      const hintBar = document.createElement('div'); hintBar.className = 'ov-profile-hint';
      hintBar.innerHTML = `<span style="opacity:0.6">Focus:</span> ${profileDef.hint}`;
      if (profileDef.badge) {
        const badge = document.createElement('span'); badge.className = 'ov-profile-badge'; badge.textContent = profileDef.badge;
        hintBar.appendChild(badge);
      }
      hdrTop.appendChild(hintBar);
    }

    hdrTop.appendChild(hdrTitle);
    hdrTop.appendChild(filterNote);
    hdrTop.appendChild(profileWrap);
    hdrTop.appendChild(viewTableBtn);
    hdr.appendChild(hdrTop);

    // Active filter chips strip — shown when any filters are active
    const activeFilters = ovGetActiveFilters();
    if (activeFilters.length) {
      const strip = document.createElement('div'); strip.className = 'ov-filter-strip';
      activeFilters.forEach(f => {
        const chip = document.createElement('span'); chip.className = 'ov-filter-strip-chip';
        chip.title = f.label;
        const lbl = document.createElement('span'); lbl.textContent = f.shortLabel;
        const rm  = document.createElement('span'); rm.className = 'ov-filter-strip-rm'; rm.textContent = '×';
        rm.onclick = () => { f.remove(); renderPage(); scheduleOverviewRender(); };
        chip.appendChild(lbl); chip.appendChild(rm);
        strip.appendChild(chip);
      });
      const clearAll = document.createElement('span'); clearAll.className = 'ov-filter-strip-clearall';
      clearAll.textContent = 'Clear all';
      clearAll.onclick = () => { clearAllFilters(); scheduleOverviewRender(); };
      strip.appendChild(clearAll);
      hdr.appendChild(strip);
    }

    // ── Missing column hints ──────────────────────────────────────────────────
    const missing = [];
    if (!s.cmdCol && !s.initCmdCol)  missing.push('command lines (Process Command Line / Initiating Process Command Line)');
    if (!s.remoteIpCol)              missing.push('network data (Remote IP)');
    if (!s.regKeyCol)                missing.push('registry data (Registry Key)');
    if (!s.sha256Col && !s.md5Col)   missing.push('file hashes (Sha256 / MD5)');
    if (missing.length && missing.length < 4) { // only show if partial — all missing = generic CSV, expected
      const hint = document.createElement('div'); hint.className = 'ov-col-hint';
      hint.innerHTML = `<span>ℹ</span> Some cards hidden — export missing: ${missing.join(' · ')}`;
      hdr.appendChild(hint);
    }

    panel.appendChild(hdr);

    // ── ATT&CK row: Coverage + TTP Selector — hidden in custom profile mode or when mitre disabled ──
    const _mitrEnabled = (typeof SIFT_FEATURES === 'undefined') || SIFT_FEATURES.mitre !== false;
    if (!_ovCustomActive && _mitrEnabled) {
      const attackRow = document.createElement('div'); attackRow.className = 'ov-row';
      const coverageCard = buildMitreSummaryCard(d.mitreResults || {});
      coverageCard.style.flex = '3';
      attackRow.appendChild(coverageCard);
      const ttpCard = buildMitreTtpSelector(d.mitreResults || {});
      ttpCard.style.flex = '1'; ttpCard.style.minWidth = '200px';
      attackRow.appendChild(ttpCard);
      panel.appendChild(attackRow);

      // TTP context card — full investigative detail for active technique
      if (d.ttpContext && d.ttpContext.records && d.ttpContext.records.length) {
        panel.appendChild(buildTtpContextCard(d.ttpContext, s));
      }
    }

    // ── Feature 1: Event Frequency Timeline — suppressed in custom profiles ───────
    if (!_ovCustomActive && d.freqTimeline) panel.appendChild(buildFreqTimelineCard(d.freqTimeline));

    // ── Feature 2: Top-N Offenders — always shown, useful for pivot regardless of profile ──
    const topNCard = d.topN ? buildTopNCard(d.topN) : null;
    if (topNCard) panel.appendChild(topNCard);

    // ── Build all available data cards ───────────────────────────────────────────
    const allCards = {};
    if (d.time)   allCards.time  = buildTimeCard(d.time);
    allCards.scope    = buildScopeCard(d.scope, d.rowCount);
    if (d.activity)   allCards.activity = buildActivityCard(d.activity, s);
    if (d.severity)   allCards.severity = buildSeverityCard(d.severity);
    if (d.scope.devicesSorted.length || d.scope.usersSorted.length)
      allCards.hostsAccounts = buildHostsAccountsCard(d.scope, s);
    if (d.process)    allCards.process  = buildProcessCard(d.process, s);
    if (d.procPairs && d.procPairs.sorted.length) {
      const pc = buildProcPairsCard(d.procPairs, s); if (pc) allCards.procPairs = pc;
    }
    if (d.network)    allCards.network  = buildNetworkCard(d.network, s);
    if (d.registry)   allCards.registry = buildRegistryCard(d.registry, s);
    if (d.hashes)     allCards.hashes   = buildHashesCard(d.hashes, s);

    // ── Add custom field cards into allCards so they join the draggable grid ────
    const _customFields = _ovCustomActive ? (_ovCustomActive.customFields || []) : [];
    _customFields.forEach(col => {
      const card = buildCustomFieldCard(col, rows);
      if (card) allCards['field:' + col] = card;
    });

    // ── When a custom profile is active, strip allCards to only selected keys ────
    // Include field: cards — they are always shown when in a custom profile
    if (_ovCustomActive) {
      const selected = new Set(_ovCustomActive.cards || []);
      Object.keys(allCards).forEach(k => {
        if (!k.startsWith('field:') && !selected.has(k)) delete allCards[k];
      });
    }

    // ── Windows Security Log cards — only when no custom profile active ───────────
    if (!_ovCustomActive && d.winSec && typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog) {
      _layoutWinSecCards(panel, d.winSec, s, _ovProfile);
    }

    // ── Layout all cards (including custom field cards) through the draggable grid ─
    _layoutCards(panel, allCards, profileDef);

    // ── Feature 4: Attack Chain Strip ────────────────────────────────────────────
    const chainCard = d.attackChain ? buildAttackChainCard(d.attackChain, s) : null;
    if (chainCard) panel.appendChild(chainCard);

    // Notable indicators — suppressed in custom profiles or when mitre disabled
    if (!_ovCustomActive && _mitrEnabled) {
      panel.appendChild(buildIndicatorsCard(_sortIndicatorsByProfile(d.indicators || []), s));
    }

    // Generic fallback
    if (!ptHasDefenderCols() && !isChronicleData && !(typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog))
      panel.appendChild(buildColumnStatsCard(rows));

    // Bottom spacer — ensures last card is fully visible when scrolled to bottom
    const spacer = document.createElement('div'); spacer.style.minHeight = '120px'; spacer.style.flexShrink = '0';
    panel.appendChild(spacer);
  }

  // ── Profile helpers ───────────────────────────────────────────────────────────
  function _ovGetProfileDef() {
    if (_ovCustomActive) {
      const cards = _ovCustomActive.cards || [];
      return { label: _ovCustomActive.name, icon: '⭐', hint: 'Custom profile', primary: cards.slice(0, 4), secondary: cards.slice(4) };
    }
    if (!_ovProfile) return (typeof TACTIC_PROFILES !== 'undefined' && TACTIC_PROFILES['default']) || { label:'General', icon:'🔍', hint:'', primary:['time','scope','activity','severity'], secondary:['hostsAccounts','process','procPairs','network','registry','hashes'] };
    // General IT profiles (non-MITRE)
    if (typeof GENERAL_PROFILES !== 'undefined' && GENERAL_PROFILES[_ovProfile])
      return GENERAL_PROFILES[_ovProfile];
    if (typeof TECHNIQUE_PROFILES !== 'undefined' && TECHNIQUE_PROFILES[_ovProfile])
      return TECHNIQUE_PROFILES[_ovProfile];
    if (typeof TACTIC_PROFILES !== 'undefined' && TACTIC_PROFILES[_ovProfile])
      return TACTIC_PROFILES[_ovProfile];
    return TACTIC_PROFILES['default'];
  }

  function _layoutCards(panel, cards, profileDef) {
    const primary   = (profileDef.primary   || []).filter(k => cards[k]);
    const secondary = (profileDef.secondary || []).filter(k => cards[k]);
    const used      = new Set([...primary, ...secondary]);
    const fieldCards = Object.keys(cards).filter(k => k.startsWith('field:'));
    const remaining  = _ovCustomActive ? [] : Object.keys(cards).filter(k => !used.has(k) && !k.startsWith('field:'));
    const ordered    = [...primary, ...secondary, ...remaining, ...fieldCards];

    let finalOrder = ordered;
    if (_ovCardOrder.length) {
      const orderSet = new Set(_ovCardOrder);
      const extra = ordered.filter(k => !orderSet.has(k));
      finalOrder = [..._ovCardOrder.filter(k => cards[k]), ...extra];
    }

    const grid = document.createElement('div'); grid.className = 'ov-grid';

    finalOrder.forEach(key => {
      const card = cards[key];
      if (!card) return;
      const size = _ovCardSizes[key] || 'normal';
      card.classList.remove('ov-size-compact','ov-size-normal','ov-size-wide','ov-size-full');
      card.classList.add('ov-size-' + size);
      // Apply stored height (height resize)
      const cardH = _ovCardHeights[key];
      if (cardH) {
        card.style.minHeight = cardH + 'px';
        card.querySelectorAll('.ov-card-list, .ov-ctx-list, .ov-chart-area, .ov-activity-chart').forEach(l => l.style.maxHeight = Math.max(80, cardH - 60) + 'px');
      } else {
        card.style.minHeight = '';
      }
      card.dataset.cardKey = key;
      card.removeAttribute('draggable');
      _addCardControls(card, key, grid);
      grid.appendChild(card);
    });

    panel.appendChild(grid);
  }

  const _SIZE_CYCLE = ['normal','wide','full','compact'];

  const _sizeLabels = { compact:'Compact', normal:'Normal', wide:'Wide', full:'Full' };

  function _addCardControls(card, key, grid) {
    const title = card.querySelector('.ov-card-title');
    if (!title || title.querySelector('.ov-card-drag-handle')) return;

    // ── Drag handle — mouse-event based (no HTML5 DnD) ────────────────────────
    const handle = document.createElement('span'); handle.className = 'ov-card-drag-handle';
    handle.textContent = '⠿'; handle.title = 'Drag to reorder';
    handle.style.cssText = 'cursor:grab;color:rgba(255,215,0,0.5);font-size:14px;margin-right:6px;flex-shrink:0;user-select:none;transition:color .15s;-webkit-user-select:none';
    handle.onmouseover = () => handle.style.color = 'var(--cb-yellow)';
    handle.onmouseout  = () => handle.style.color = 'rgba(255,215,0,0.5)';

    handle.onmousedown = e => {
      if (e.button !== 0) return;
      e.preventDefault(); e.stopPropagation();

      const rect = card.getBoundingClientRect();
      // Bug fix 1: offsetX/Y relative to card origin, not the handle span
      const offsetX = e.clientX - rect.left;
      const offsetY = e.clientY - rect.top;

      // Ghost element follows cursor maintaining original card offset
      const ghost = card.cloneNode(true);
      ghost.style.cssText = `position:fixed;left:${rect.left}px;top:${rect.top}px;width:${rect.width}px;max-height:${rect.height}px;overflow:hidden;opacity:0.75;pointer-events:none;z-index:9999;box-shadow:0 12px 40px rgba(0,0,0,0.5);border-radius:8px;border:2px solid var(--cb-yellow);transition:none`;
      document.body.appendChild(ghost);

      // Placeholder holds the spot
      const g = grid || card.closest('.ov-grid');
      // Bug fix: placeholder mirrors the dragged card's actual size class
      const dragSize = _ovCardSizes[key] || 'normal';
      const sizeFlexMap = { compact:'0 1 calc(25% - 9px)', normal:'1 1 calc(33% - 8px)', wide:'2 1 calc(50% - 6px)', full:'1 0 100%' };
      const ph = document.createElement('div');
      ph.dataset.placeholder = '1';
      ph.style.cssText = `flex:${sizeFlexMap[dragSize]};min-width:180px;border:2px dashed rgba(255,215,0,0.4);border-radius:8px;background:rgba(255,215,0,0.03);min-height:60px`;
      card.parentNode.insertBefore(ph, card);
      card.style.display = 'none';

      const onMove = ev => {
        // Bug fix 1: use computed offset from card rect
        ghost.style.left = (ev.clientX - offsetX) + 'px';
        ghost.style.top  = (ev.clientY - offsetY) + 'px';

        // Bug fix 3: fallback to grid end when only one other card
        const siblings = [...g.querySelectorAll('[data-card-key]')];
        let bestEl = null; let bestBefore = true; let bestDist = Infinity;
        siblings.forEach(sib => {
          if (sib === card) return;
          const r = sib.getBoundingClientRect();
          const midX = r.left + r.width / 2;
          const dist = Math.abs(ev.clientX - midX) + Math.abs(ev.clientY - (r.top + r.height / 2)) * 0.3;
          if (dist < bestDist) { bestDist = dist; bestEl = sib; bestBefore = ev.clientX < midX; }
        });
        if (bestEl) {
          if (bestBefore) bestEl.before(ph);
          else bestEl.after(ph);
        } else {
          // Bug fix 3: no siblings found — append to end of grid
          g.appendChild(ph);
        }
      };

      const cleanup = () => {
        ghost.remove();
        if (ph.parentNode) ph.remove();
        card.style.display = '';
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        // Bug fix 4: also clean up on window blur
        window.removeEventListener('blur', cleanup);
      };

      const onUp = () => {
        // Bug fix 2: read order from DOM before removing placeholder
        const allKeys = [...g.children]
          .filter(el => el.dataset.cardKey || el.dataset.placeholder)
          .reduce((acc, el) => {
            if (el.dataset.placeholder) acc.push(key); // insert dragged card here
            else if (el.dataset.cardKey !== key) acc.push(el.dataset.cardKey);
            return acc;
          }, []);
        _ovCardOrder = allKeys;

        cleanup();
        scheduleOverviewRender();
      };

      // Bug fix 4: clean up if window loses focus
      window.addEventListener('blur', cleanup, { once: true });
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    };

    title.insertBefore(handle, title.firstChild);

    // Dismiss button — only for pinned field cards
    if (key.startsWith('field:')) {
      const colName = key.slice(6);
      const dismiss = document.createElement('span');
      dismiss.title = 'Remove card';
      dismiss.style.cssText = 'cursor:pointer;color:var(--cb-muted);font-size:13px;margin-left:4px;flex-shrink:0;padding:0 2px;transition:color .15s';
      dismiss.textContent = '×';
      dismiss.onmouseover = () => dismiss.style.color = '#e83e3e';
      dismiss.onmouseout  = () => dismiss.style.color = 'var(--cb-muted)';
      dismiss.onclick = e => {
        e.stopPropagation();
        if (_ovCustomActive) _ovCustomActive.customFields = (_ovCustomActive.customFields || []).filter(f => f !== colName);
        _ovCardOrder = _ovCardOrder.filter(k => k !== key);
        delete _ovCardSizes[key];
        scheduleOverviewRender();
      };
      title.appendChild(dismiss);
    }

    // ── Settings dropdown — size + chart type ────────────────────────────────
    const _userSizes = [
      { key:'compact', label:'Small',  icon:'▪' },
      { key:'normal',  label:'Medium', icon:'▪▪' },
      { key:'wide',    label:'Large',  icon:'▪▪▪' },
      { key:'full',    label:'Full',   icon:'▬' },
    ];
    const chartKey = card.dataset.chartKey || null; // set by card builders that support charts
    const _chartOptions = [
      { key:'list', label:'≡ List' },
      { key:'pie',  label:'◉ Chart' },
    ];

    const settingsBtn = document.createElement('span');
    settingsBtn.style.cssText = 'cursor:pointer;font-size:13px;margin-left:auto;flex-shrink:0;padding:0 4px;border:none;color:rgba(255,255,255,0.4);background:transparent;transition:color .15s;user-select:none;line-height:1;letter-spacing:1px';
    settingsBtn.textContent = '···';
    settingsBtn.title = 'Card options';
    const _refreshSettingsBtn = () => {
      const s = _ovCardSizes[key] || 'normal';
      settingsBtn.style.color = s !== 'normal' ? 'var(--cb-yellow)' : 'rgba(255,255,255,0.4)';
    };
    settingsBtn.onmouseover = () => settingsBtn.style.color = 'var(--cb-yellow)';
    settingsBtn.onmouseout  = () => _refreshSettingsBtn();
    _refreshSettingsBtn();

    // Dropdown panel — fixed position to avoid overflow clipping
    const ddWrap = document.createElement('div'); ddWrap.style.cssText = 'margin-left:auto;flex-shrink:0';
    const dd = document.createElement('div');
    dd.className = 'ov-card-dd-portal';
    dd.style.cssText = 'display:none;position:fixed;background:var(--modal-bg);border:1px solid var(--cb-yellow);border-radius:4px;box-shadow:0 4px 14px rgba(0,0,0,0.65);z-index:9990;min-width:76px;padding:2px 0;font-size:10px;user-select:none';
    document.body.appendChild(dd);

    const sizeHdr = document.createElement('div');
    sizeHdr.style.cssText = 'padding:2px 8px 1px;font-size:7px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--cb-os3);pointer-events:none';
    sizeHdr.textContent = 'Size';
    dd.appendChild(sizeHdr);

    const _buildDdItems = () => {
      dd.querySelectorAll('.ov-dd-item').forEach(el => el.remove());
      const curSize = _ovCardSizes[key] || 'normal';
      _userSizes.forEach(({ key: sKey, label, icon }) => {
        const item = document.createElement('div'); item.className = 'ov-dd-item';
        const active = curSize === sKey;
        item.style.cssText = `display:flex;align-items:center;gap:5px;padding:2px 8px;cursor:pointer;color:${active ? 'var(--cb-yellow)' : 'var(--cb-text)'};background:${active ? 'rgba(255,215,0,0.1)' : 'transparent'};white-space:nowrap;transition:background .1s`;
        item.onmouseover = () => { if (!active) item.style.background = 'rgba(255,215,0,0.12)'; };
        item.onmouseout  = () => { if (!active) item.style.background = 'transparent'; };
        const dot = document.createElement('span'); dot.style.cssText = `font-size:9px;width:10px;flex-shrink:0;color:${active ? 'var(--cb-yellow)' : 'var(--cb-os3)'}`;
        dot.textContent = active ? '●' : '○';
        const lbl = document.createElement('span'); lbl.textContent = label;
        item.appendChild(dot); item.appendChild(lbl);
        item.onclick = e => {
          e.stopPropagation();
          _ovCardSizes[key] = sKey;
          card.classList.remove('ov-size-compact','ov-size-normal','ov-size-wide','ov-size-full');
          card.classList.add('ov-size-' + sKey);
          _refreshSettingsBtn();
          _buildDdItems();
        };
        dd.appendChild(item);
      });

      // Chart type section if applicable
      dd.querySelectorAll('.ov-dd-chart,.ov-dd-chart-hdr').forEach(el => el.remove());
      if (chartKey) {
        const sep = document.createElement('div'); sep.className = 'ov-dd-chart-hdr';
        sep.style.cssText = 'border:none;border-top:1px solid var(--cb-os1);margin:3px 0';
        dd.appendChild(sep);
        const chartHdr = document.createElement('div'); chartHdr.className = 'ov-dd-chart-hdr';
        chartHdr.style.cssText = 'padding:2px 8px 1px;font-size:7px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--cb-os3);pointer-events:none';
        chartHdr.textContent = 'View as';
        dd.appendChild(chartHdr);
        const curChart = _ovChartModes[chartKey] || 'list';
        _chartOptions.forEach(({ key: cKey, label }) => {
          const cActive = curChart === cKey;
          const item = document.createElement('div'); item.className = 'ov-dd-chart';
          item.style.cssText = `display:flex;align-items:center;gap:5px;padding:2px 8px;cursor:pointer;color:${cActive ? 'var(--cb-yellow)' : 'var(--cb-text)'};background:${cActive ? 'rgba(255,215,0,0.1)' : 'transparent'};white-space:nowrap;transition:background .1s`;
          item.onmouseover = () => { if (!cActive) item.style.background = 'rgba(255,215,0,0.12)'; };
          item.onmouseout  = () => { if (!cActive) item.style.background = 'transparent'; };
          const dot = document.createElement('span'); dot.style.cssText = `font-size:9px;width:10px;flex-shrink:0;color:${cActive ? 'var(--cb-yellow)' : 'var(--cb-os3)'}`;
          dot.textContent = cActive ? '●' : '○';
          const lbl = document.createElement('span'); lbl.textContent = label;
          item.appendChild(dot); item.appendChild(lbl);
          item.onclick = e => {
            e.stopPropagation();
            _ovChartModes[chartKey] = cKey;
            _buildDdItems();
            // Fire event so card areas re-render without full overview rebuild
            card.dispatchEvent(new CustomEvent('ov-chart-change'));
          };
          dd.appendChild(item);
        });
      }
    };
    _buildDdItems();

    settingsBtn.onclick = e => {
      e.stopPropagation();
      const open = dd.style.display !== 'none';
      if (open) { dd.style.display = 'none'; return; }
      _buildDdItems();
      dd.style.display = 'block';
      // Position relative to button, flip if near right/bottom edge
      const r = settingsBtn.getBoundingClientRect();
      dd.style.left = 'auto'; dd.style.right = 'auto';
      dd.style.top = 'auto'; dd.style.bottom = 'auto';
      const spaceRight = window.innerWidth - r.right;
      const spaceBelow = window.innerHeight - r.bottom;
      const ddW = dd.offsetWidth || 80; const ddH = dd.offsetHeight || 120;
      if (spaceRight >= ddW) dd.style.left = r.right - ddW + 'px';
      else dd.style.left = Math.max(4, r.left - ddW) + 'px';
      if (spaceBelow >= ddH) dd.style.top = (r.bottom + 3) + 'px';
      else dd.style.bottom = (window.innerHeight - r.top + 3) + 'px';
    };
    document.addEventListener('click', () => { dd.style.display = 'none'; }, { signal: _ovListenersAC.signal });
    dd.onclick = e => e.stopPropagation();

    ddWrap.appendChild(settingsBtn);
    title.appendChild(ddWrap);

    // ── Resize handles ────────────────────────────────────────────────────────
    card.style.position = 'relative';

    const _makeTip = () => {
      const t = document.createElement('div');
      t.style.cssText = 'position:fixed;background:var(--cb-dark);color:#2dd4bf;font-size:11px;font-weight:700;padding:3px 10px;border-radius:4px;border:1px solid rgba(45,212,191,0.5);pointer-events:none;z-index:9999;white-space:nowrap';
      document.body.appendChild(t); return t;
    };

    // ── Right edge — width ────────────────────────────────────────────────────
    const rHandle = document.createElement('div');
    rHandle.style.cssText = 'position:absolute;right:0;top:20px;bottom:20px;width:6px;cursor:ew-resize;z-index:10;display:flex;align-items:center;justify-content:center';
    const rGrip = document.createElement('div');
    rGrip.style.cssText = 'width:3px;height:36px;border-radius:2px;background:rgba(120,143,141,0.25);transition:background .15s;pointer-events:none';
    rHandle.appendChild(rGrip);
    rHandle.onmouseover = () => rGrip.style.background = 'rgba(45,212,191,0.7)';
    rHandle.onmouseout  = () => rGrip.style.background = 'rgba(120,143,141,0.25)';

    rHandle.onmousedown = e => {
      e.preventDefault(); e.stopPropagation();
      const g = grid || card.closest('.ov-grid');
      const gridW = g ? g.offsetWidth : window.innerWidth;
      const startX = e.clientX;
      const startW = card.getBoundingClientRect().width;
      // Midpoint snap zones computed once from grid width at drag start
      const W = { compact: gridW*0.25, normal: gridW*0.33, wide: gridW*0.50, full: gridW };
      const snapW = px => px < (W.compact+W.normal)/2 ? 'compact'
                        : px < (W.normal+W.wide)/2    ? 'normal'
                        : px < (W.wide+W.full)/2      ? 'wide' : 'full';
      let curSize = _ovCardSizes[key] || 'normal';
      rGrip.style.background = 'rgba(45,212,191,0.9)';
      const tip = _makeTip();

      const onMove = ev => {
        const newPx = Math.max(120, startW + ev.clientX - startX);
        const snap  = snapW(newPx);
        if (snap !== curSize) {
          curSize = snap;
          card.classList.remove('ov-size-compact','ov-size-normal','ov-size-wide','ov-size-full');
          card.classList.add('ov-size-' + curSize);
        }
        tip.textContent = '↔ ' + _sizeLabels[curSize];
        tip.style.left = (ev.clientX + 14) + 'px';
        tip.style.top  = (ev.clientY - 14) + 'px';
      };
      const rUp = () => {
        _ovCardSizes[key] = curSize;
        _refreshSettingsBtn();
        rGrip.style.background = 'rgba(120,143,141,0.25)';
        tip.remove();
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', rUp);
        window.removeEventListener('blur', rUp);
      };
      window.addEventListener('blur', rUp, { once: true });
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', rUp);
    };
    card.appendChild(rHandle);

    // ── Bottom edge — height ──────────────────────────────────────────────────
    const bHandle = document.createElement('div');
    bHandle.style.cssText = 'position:absolute;bottom:0;left:24px;right:24px;height:7px;cursor:ns-resize;z-index:10;display:flex;align-items:center;justify-content:center';
    const bGrip = document.createElement('div');
    bGrip.style.cssText = 'height:3px;width:40px;border-radius:2px;background:rgba(120,143,141,0.25);transition:background .15s;pointer-events:none';
    bHandle.appendChild(bGrip);
    bHandle.onmouseover = () => bGrip.style.background = 'rgba(45,212,191,0.7)';
    bHandle.onmouseout  = () => bGrip.style.background = 'rgba(120,143,141,0.25)';

    bHandle.onmousedown = e => {
      e.preventDefault(); e.stopPropagation();
      const startY = e.clientY;
      const startH = card.getBoundingClientRect().height;
      let curH = startH;
      bGrip.style.background = 'rgba(45,212,191,0.9)';
      const tip = _makeTip();

      const onMove = ev => {
        curH = Math.max(100, startH + ev.clientY - startY);
        card.style.minHeight = curH + 'px';
        card.querySelectorAll('.ov-card-list, .ov-ctx-list, .ov-chart-area, .ov-activity-chart').forEach(l => l.style.maxHeight = Math.max(60, curH - 58) + 'px');
        tip.textContent = '↕ ' + Math.round(curH) + 'px';
        tip.style.left = (ev.clientX + 14) + 'px';
        tip.style.top  = (ev.clientY + 8) + 'px';
      };
      const bUp = () => {
        // Only discard if user barely moved (accidental click) — compare to startH not scrollHeight
        if (Math.abs(curH - startH) < 16) {
          card.style.minHeight = '';
          card.querySelectorAll('.ov-card-list, .ov-ctx-list, .ov-chart-area, .ov-activity-chart').forEach(l => l.style.maxHeight = '');
          delete _ovCardHeights[key];
        } else {
          _ovCardHeights[key] = Math.round(curH);
        }
        bGrip.style.background = 'rgba(120,143,141,0.25)';
        tip.remove();
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', bUp);
        window.removeEventListener('blur', bUp);
      };
      window.addEventListener('blur', bUp, { once: true });
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', bUp);
    };
    card.appendChild(bHandle);
  }

  function _addProfileOption(dropdown, id, type, mitreResults, profileBtn) {
    const def = id === null
      ? (typeof TACTIC_PROFILES !== 'undefined' && TACTIC_PROFILES['default'])
      : type === 'tactic'
        ? (typeof TACTIC_PROFILES !== 'undefined' && TACTIC_PROFILES[id])
        : (typeof TECHNIQUE_PROFILES !== 'undefined' && TECHNIQUE_PROFILES[id]);
    if (!def) return;

    // Count hits for this tactic/technique
    let hitCount = 0;
    if (id === null) {
      hitCount = Object.values(mitreResults).reduce((s, v) => s + v, 0);
    } else if (type === 'tactic') {
      Object.entries(mitreResults).forEach(([techId, cnt]) => {
        const tech = typeof MITRE_TECHNIQUES !== 'undefined' ? MITRE_TECHNIQUES.find(t => t.id === techId) : null;
        if (tech && tech.tactic === id) hitCount += cnt;
      });
    } else {
      hitCount = mitreResults[id] || 0;
    }

    const opt = document.createElement('div'); opt.className = 'ov-profile-opt';
    if (_ovProfile === id || (id === null && !_ovProfile)) opt.classList.add('ov-profile-opt-active');
    if (!hitCount && id !== null) opt.style.opacity = '0.45';

    const icon = document.createElement('span'); icon.style.cssText = 'flex-shrink:0;width:16px'; icon.textContent = def.icon || '';
    const lbl  = document.createElement('span'); lbl.style.cssText = 'flex:1;font-size:12px'; lbl.textContent = def.label;
    const cnt  = document.createElement('span'); cnt.style.cssText = 'font-size:10px;color:var(--cb-muted);margin-left:auto;flex-shrink:0';
    if (hitCount) { cnt.textContent = hitCount.toLocaleString(); cnt.style.color = tacticColor(type === 'tactic' ? id : (typeof MITRE_TECHNIQUES !== 'undefined' ? (MITRE_TECHNIQUES.find(t=>t.id===id)||{}).tactic : '')); }

    opt.appendChild(icon); opt.appendChild(lbl); opt.appendChild(cnt);
    opt.onclick = () => {
      _ovProfile = id;
      _ovCustomActive = null; // clear any active custom profile when switching to a standard profile
      dropdown.style.display = 'none';
      profileBtn.innerHTML = `${def.icon} <span>Investigating: <strong>${def.label}</strong></span> ▾`;
      scheduleOverviewRender();
    };
    dropdown.appendChild(opt);
  }

  // ── TTP Context Card — structured per-event investigation detail ─────────────
  function buildTtpContextCard(ctx, s) {
    const card = document.createElement('div'); card.className = 'ov-card ov-card-full ov-ttp-ctx-card';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = ctx.label;
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = ctx.count.toLocaleString() + ' events · most recent shown · right-click any field for options';
    title.appendChild(sub); card.appendChild(title);

    const list = document.createElement('div'); list.className = 'ov-ctx-list';

    ctx.records.forEach(rec => {
      const row = document.createElement('div'); row.className = 'ov-ctx-row';

      // ── Header line: who / where / when ──────────────────────────────────────
      const hdr = document.createElement('div'); hdr.className = 'ov-ctx-hdr';

      const addChip = (col, val, label) => {
        if (!val) return;
        const chip = document.createElement('span'); chip.className = 'ov-ctx-chip';
        chip.textContent = val; chip.title = (label ? label + ': ' : '') + val;
        chip.style.cursor = 'pointer';
        chip.onclick = () => filterFromOverview(col, val);
        chip.addEventListener('contextmenu', e => { e.preventDefault(); if (typeof openCellMenu === 'function') openCellMenu(e, col, val, null); });
        hdr.appendChild(chip);
      };

      // Device, user, time
      addChip(s.deviceCol, rec.device || rec.srcDevice, 'Device');
      addChip(s.userCol,   rec.user, 'User');
      if (rec.time) {
        const timeEl = document.createElement('span'); timeEl.className = 'ov-ctx-time'; timeEl.textContent = rec.time;
        hdr.appendChild(timeEl);
      }
      // Tags (encoded, download-cradle)
      if (rec.tags && rec.tags.length) {
        rec.tags.forEach(tag => {
          const t = document.createElement('span'); t.className = 'ov-ctx-tag ov-ctx-tag-' + tag.replace('-','_');
          t.textContent = tag; hdr.appendChild(t);
        });
      }
      row.appendChild(hdr);

      // ── Detail fields — varies by TTP ────────────────────────────────────────
      const addField = (label, col, val, mono) => {
        if (!val) return;
        const field = document.createElement('div'); field.className = 'ov-ctx-field';
        const lbl = document.createElement('span'); lbl.className = 'ov-ctx-lbl'; lbl.textContent = label;
        const v   = document.createElement('span'); v.className = 'ov-ctx-val' + (mono ? ' ov-ctx-mono' : '');
        v.textContent = val; v.title = val;
        v.style.cursor = 'pointer';
        v.onclick = () => filterFromOverview(col, val);
        v.addEventListener('contextmenu', e => { e.preventDefault(); if (typeof openCellMenu === 'function') openCellMenu(e, col, val, null); });
        field.appendChild(lbl); field.appendChild(v);
        row.appendChild(field);
      };

      // T1059.001 PowerShell
      if (ctx.techId === 'T1059.001') {
        addField('Parent',  s.initFileCol, rec.parent);
        addField('Process', s.fileCol,     rec.process);
        addField('Cmdline', s.cmdCol,      rec.cmdline, true);
      }
      // T1003.001 LSASS
      else if (ctx.techId === 'T1003.001') {
        addField('Tool',      s.fileCol,      rec.process);
        addField('Parent',    s.initFileCol,  rec.parent);
        addField('Cmdline',   s.cmdCol,       rec.cmdline, true);
        addField('Integrity', s.integrityCol,  rec.integrity);
      }
      // T1204.002 Malicious File
      else if (ctx.techId === 'T1204.002') {
        addField('Office App', s.initFileCol, rec.officeApp);
        addField('Spawned',    s.fileCol,     rec.spawned);
        addField('Cmdline',    s.cmdCol,      rec.cmdline, true);
        addField('Path',       s.pathCol,     rec.path);
      }
      // T1021.002 SMB
      else if (ctx.techId === 'T1021.002') {
        addField('Process',   s.initFileCol,   rec.process);
        addField('Dest IP',   s.remoteIpCol,   rec.destIp);
        addField('Port',      s.remotePortCol, rec.destPort);
        addField('Cmdline',   s.cmdCol,        rec.cmdline, true);
      }
      // T1547.001 Registry Persistence
      else if (ctx.techId === 'T1547.001') {
        addField('Registry Key',   s.regKeyCol,  rec.regKey,  true);
        addField('Value Name',     s.regValCol,  rec.regVal);
        addField('Value Data',     s.regDataCol, rec.regData, true);
        addField('Written by',     s.initFileCol, rec.process);
      }
      // T1071 C2
      else if (ctx.techId === 'T1071') {
        addField('Process',   s.initFileCol,    rec.process);
        addField('Remote IP', s.remoteIpCol,    rec.remoteIp);
        addField('Domain',    s.remoteUrlCol,   rec.remoteUrl);
        addField('Port',      s.remotePortCol,  rec.remotePort);
        addField('Cmdline',   s.cmdCol,         rec.cmdline, true);
      }
      // T1059.003 Cmd Shell
      else if (ctx.techId === 'T1059.003') {
        addField('Parent',  s.initFileCol, rec.parent);
        addField('Process', s.fileCol,     rec.process);
        addField('Cmdline', s.cmdCol,      rec.cmdline, true);
      }
      // T1047 WMI
      else if (ctx.techId === 'T1047') {
        addField('Process',      s.fileCol,      rec.process);
        addField('Parent',       s.initFileCol,  rec.parent);
        addField('Remote Target',s.remoteIpCol,  rec.remoteTarget);
        addField('Cmdline',      s.cmdCol,       rec.cmdline, true);
      }
      // T1053.005 Scheduled Task
      else if (ctx.techId === 'T1053.005') {
        addField('Task Name', s.cmdCol,       rec.taskName);
        addField('Runs',      s.cmdCol,       rec.taskRun,  true);
        addField('Created by',s.initFileCol,  rec.process);
        addField('Cmdline',   s.cmdCol,       rec.cmdline,  true);
      }
      // T1543.003 Windows Service
      else if (ctx.techId === 'T1543.003') {
        addField('Service',     s.cmdCol,      rec.serviceName);
        addField('Binary Path', s.cmdCol,      rec.binaryPath, true);
        addField('Registry Key',s.regKeyCol,   rec.regKey,     true);
        addField('Cmdline',     s.cmdCol,      rec.cmdline,    true);
      }
      // T1003.006 DCSync
      else if (ctx.techId === 'T1003.006') {
        addField('Process',        s.initFileCol, rec.process);
        addField('Target Domain',  s.cmdCol,      rec.targetDomain);
        addField('Target Account', s.userCol,     rec.targetUser);
        addField('Cmdline',        s.cmdCol,      rec.cmdline, true);
      }
      // T1558.003 Kerberoasting
      else if (ctx.techId === 'T1558.003') {
        addField('Process', s.initFileCol, rec.process);
        addField('Cmdline', s.cmdCol,      rec.cmdline, true);
      }
      // T1021.001 RDP
      else if (ctx.techId === 'T1021.001') {
        addField('Process',   s.initFileCol,    rec.process);
        addField('Dest IP',   s.remoteIpCol,    rec.destIp);
        addField('Port',      s.remotePortCol,  rec.destPort);
        addField('Cmdline',   s.cmdCol,         rec.cmdline, true);
      }
      // T1021.006 WinRM
      else if (ctx.techId === 'T1021.006') {
        addField('Process',   s.initFileCol,    rec.process);
        addField('Dest IP',   s.remoteIpCol,    rec.destIp);
        addField('Port',      s.remotePortCol,  rec.destPort);
        addField('Cmdline',   s.cmdCol,         rec.cmdline, true);
      }
      // T1027 Obfuscation
      else if (ctx.techId === 'T1027') {
        addField('Parent',  s.initFileCol, rec.parent);
        addField('Process', s.fileCol,     rec.process);
        addField('Cmdline', s.cmdCol,      rec.cmdline, true);
      }
      // T1218.011 Rundll32
      else if (ctx.techId === 'T1218.011') {
        addField('Parent', s.initFileCol, rec.parent);
        addField('DLL',    s.cmdCol,      rec.dll, true);
        addField('Cmdline',s.cmdCol,      rec.cmdline, true);
      }
      // T1105 Tool Transfer
      else if (ctx.techId === 'T1105') {
        addField('Process',   s.initFileCol,   rec.process);
        addField('Source URL',s.remoteUrlCol,  rec.downloadUrl, true);
        addField('Cmdline',   s.cmdCol,        rec.cmdline,     true);
      }
      // T1571 Non-Standard Port
      else if (ctx.techId === 'T1571') {
        addField('Process',   s.initFileCol,    rec.process);
        addField('Remote IP', s.remoteIpCol,    rec.remoteIp);
        addField('Port',      s.remotePortCol,  rec.remotePort);
        addField('Cmdline',   s.cmdCol,         rec.cmdline, true);
      }
      // T1486 Ransomware
      else if (ctx.techId === 'T1486') {
        addField('Process', s.initFileCol, rec.process);
        addField('Path',    s.pathCol,     rec.path);
        addField('Cmdline', s.cmdCol,      rec.cmdline, true);
      }
      // T1490 Inhibit Recovery
      else if (ctx.techId === 'T1490') {
        addField('Process', s.initFileCol, rec.process);
        addField('Cmdline', s.cmdCol,      rec.cmdline, true);
      }
      // T1562.001 Disable Security Tools
      else if (ctx.techId === 'T1562.001') {
        addField('Process',  s.initFileCol, rec.process);
        addField('Disabled', s.cmdCol,      rec.toolDisabled);
        addField('Cmdline',  s.cmdCol,      rec.cmdline, true);
      }
      // T1496 Cryptomining
      else if (ctx.techId === 'T1496') {
        addField('Process',     s.fileCol,       rec.process);
        addField('Mining Pool', s.remoteUrlCol,  rec.miningPool, true);
        addField('Remote IP',   s.remoteIpCol,   rec.remoteIp);
        addField('Port',        s.remotePortCol, rec.remotePort);
        addField('Cmdline',     s.cmdCol,        rec.cmdline, true);
      }

      list.appendChild(row);
    });

    // Scroll container
    const wrap = document.createElement('div'); wrap.className = 'ov-ctx-scroll';
    wrap.appendChild(list);
    card.appendChild(wrap);
    return card;
  }

  // ── Card: time ────────────────────────────────────────────────────────────────
  function buildTimeCard(time) {
    const fmt = ms => {
      const d = new Date(ms);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit' });
    };
    const dur = time.maxTs - time.minTs;
    const durStr = dur < 60000 ? Math.round(dur/1000)+'s'
      : dur < 3600000  ? Math.round(dur/60000)+'m'
      : dur < 86400000 ? (dur/3600000).toFixed(1)+'h'
      : (dur/86400000).toFixed(1)+'d';
    return buildCard('Timeline', [
      { label:'First event', value: fmt(time.minTs) },
      { label:'Last event',  value: fmt(time.maxTs) },
      { label:'Duration',    value: durStr, highlight: true },
    ]);
  }

  // ── Card: scope (compact summary row 1) ──────────────────────────────────────
  function buildScopeCard(scope, total) {
    const items = [];
    if (scope.devicesSorted.length)
      items.push({ label: 'Devices', value: scope.devicesSorted.length.toLocaleString(), highlight: true });
    if (scope.usersSorted.length)
      items.push({ label: 'Users', value: scope.usersSorted.length.toLocaleString() });
    items.push({ label: 'Events', value: total.toLocaleString() });
    return buildCard('Scope', items);
  }

  // ── Card: hosts + accounts (two sections, one card) ──────────────────────────
  function buildHostsAccountsCard(scope, s) {
    const card = document.createElement('div'); card.className = 'ov-card';
    card.dataset.chartKey = 'hosts';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Hosts & Accounts';
    card.appendChild(title);

    if (scope.devicesSorted.length) {
      const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr';
      hdr.textContent = `Devices / Hosts (${scope.devicesSorted.length.toLocaleString()} unique)`;
      card.appendChild(hdr);
      // Chart toggle for devices
      const devWrap = document.createElement('div');
      const devArea = document.createElement('div'); devArea.className = 'ov-chart-area';
      const renderDev = () => {
        devArea.innerHTML = '';
        if (_ovChartModes['hosts'] === 'pie') devArea.appendChild(_buildDonutChart(scope.devicesSorted.slice(0,10), s.deviceCol));
        else _appendCappedRows(devArea, scope.devicesSorted, ([d,c]) => ovRow(s.deviceCol, d, d, c.toLocaleString()));
      };
      renderDev(); card.addEventListener('ov-chart-change', renderDev); card.appendChild(devArea);
    }

    if (scope.usersSorted.length) {
      const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr';
      hdr.textContent = `Accounts (${scope.usersSorted.length.toLocaleString()} unique)`;
      card.appendChild(hdr);
      const usrArea = document.createElement('div'); usrArea.className = 'ov-chart-area';
      const renderUsr = () => {
        usrArea.innerHTML = '';
        if (_ovChartModes['hosts'] === 'pie') usrArea.appendChild(_buildDonutChart(scope.usersSorted.slice(0,10), s.userCol));
        else _appendCappedRows(usrArea, scope.usersSorted, ([u,c]) => ovRow(s.userCol, u, u, c.toLocaleString()));
      };
      renderUsr(); card.addEventListener('ov-chart-change', renderUsr); card.appendChild(usrArea);
    }

    return card;
  }

  // ── Card: activity ────────────────────────────────────────────────────────────
  // buildActivityCard is defined below with chart toggle support

  // ── Card: severity ────────────────────────────────────────────────────────────
  function buildSeverityCard(severity) {
    const order  = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'];
    const colors = { CRITICAL:'#e83e3e', HIGH:'#f0a500', MEDIUM:'#f0e050', LOW:'#4caf80', INFO:'#3a9fd6', UNKNOWN:'#778F8D' };
    const items  = order.filter(k => severity.counts[k]).map(k => ({ label:k, value:severity.counts[k].toLocaleString(), dot:colors[k] }));
    Object.keys(severity.counts).filter(k => !order.includes(k)).forEach(k => items.push({ label:k, value:severity.counts[k].toLocaleString() }));
    return buildCard('Severity', items);
  }

  // ── Card: processes ───────────────────────────────────────────────────────────
  function buildProcessCard(process, s) {
    const card = document.createElement('div'); card.className = 'ov-card';
    card.dataset.chartKey = 'process';
    const title = document.createElement('div'); title.className = 'ov-card-title'; title.textContent = 'Processes';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub'; sub.textContent = process.uniqueTotal.toLocaleString()+' unique';
    title.appendChild(sub); card.appendChild(title);
    const area = document.createElement('div'); area.className = 'ov-chart-area';
    const render = () => { area.innerHTML = '';
      if (_ovChartModes['process'] === 'pie') area.appendChild(_buildDonutChart(process.sorted.slice(0,12), s.fileCol));
      else _appendCappedRows(area, process.sorted, ([n,c]) => ovRow(s.fileCol, n, n, c.toLocaleString()));
    };
    render(); card.addEventListener('ov-chart-change', render); card.appendChild(area);
    return card;
  }

  // ── Card: process pairs ───────────────────────────────────────────────────────
  function buildProcPairsCard(procPairs, s) {
    if (!procPairs.sorted.length) return null;
    const card = document.createElement('div'); card.className = 'ov-card ov-card-wide';
    const title = document.createElement('div'); title.className = 'ov-card-title'; title.textContent = 'Process Spawn Pairs';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub'; sub.textContent = procPairs.sorted.length.toLocaleString()+' pairs · click parent or child to filter';
    title.appendChild(sub); card.appendChild(title);
    card.appendChild(ovScrollList(procPairs.sorted, ([pair, count]) => {
      const [parent, child] = pair.split(' → ');
      const isSusp = isSuspiciousPair(parent, child);

      const row = document.createElement('div'); row.className = 'ov-list-row';
      const lbl = document.createElement('span'); lbl.className = 'ov-list-label';

      // Parent — independently clickable
      const parentEl = document.createElement('span');
      parentEl.style.cssText = 'color:var(--cb-muted);cursor:pointer;border-bottom:1px dotted var(--cb-os2)';
      parentEl.textContent = parent; parentEl.title = 'Filter to parent: ' + parent;
      parentEl.onclick = e => { e.stopPropagation(); filterFromOverview(s.initFileCol || s.fileCol, parent); };
      parentEl.addEventListener('contextmenu', e => { e.preventDefault(); e.stopPropagation(); if (typeof openCellMenu==='function') openCellMenu(e, s.initFileCol||s.fileCol, parent, null); });

      const arrow = document.createElement('span');
      arrow.style.cssText = 'opacity:0.4;margin:0 5px;font-size:10px'; arrow.textContent = '→';

      // Child — independently clickable
      const childEl = document.createElement('span');
      childEl.style.cssText = `color:${isSusp?'#f0a500':'var(--modal-text)'};font-weight:${isSusp?'600':'400'};cursor:pointer;border-bottom:1px dotted ${isSusp?'#f0a500':'var(--cb-os2)'}`;
      childEl.textContent = child; childEl.title = 'Filter to child: ' + child;
      childEl.onclick = e => { e.stopPropagation(); filterFromOverview(s.fileCol, child); };
      childEl.addEventListener('contextmenu', e => { e.preventDefault(); e.stopPropagation(); if (typeof openCellMenu==='function') openCellMenu(e, s.fileCol, child, null); });

      lbl.appendChild(parentEl); lbl.appendChild(arrow); lbl.appendChild(childEl);
      if (isSusp) { const w = document.createElement('span'); w.style.cssText='font-size:10px;color:#f0a500;margin-left:4px'; w.textContent='⚠'; lbl.appendChild(w); }

      const cnt = document.createElement('span'); cnt.className = 'ov-list-count'; cnt.textContent = count.toLocaleString();
      row.appendChild(lbl); row.appendChild(cnt);
      return row;
    }));
    return card;
  }

  function isSuspiciousPair(parent, child) {
    return /\b(winword|excel|outlook|onenote|powerpnt|mspub|acrord32|chrome|firefox|msedge|iexplore|svchost|lsass|spoolsv|winlogon|smss|csrss)\b/i.test(parent)
        && /\b(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|bash|sh)\b/i.test(child);
  }

  // ── Card: network ─────────────────────────────────────────────────────────────
  function buildNetworkCard(network, s) {
    const card = document.createElement('div'); card.className = 'ov-card';
    card.dataset.chartKey = 'net-ip';
    const title = document.createElement('div'); title.className = 'ov-card-title'; title.textContent = 'Network';
    card.appendChild(title);

    if (network.ipSorted && network.ipSorted.length) {
      const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr';
      hdr.textContent = `External IPs (${network.ipCount.toLocaleString()} unique)`;
      card.appendChild(hdr);
      // Bug fix 4: persist chart mode across re-renders
      const ipArea = document.createElement('div'); ipArea.className = 'ov-chart-area';
      const renderIp = () => {
        ipArea.innerHTML = '';
        if (_ovChartModes['net-ip'] === 'pie') {
          ipArea.appendChild(_buildDonutChart(network.ipSorted.slice(0,10), s.remoteIpCol));
        } else {
          _appendCappedRows(ipArea, network.ipSorted, ([ip,c]) => ovRow(s.remoteIpCol, ip, ip, c.toLocaleString()));
          // Bug fix 2: beaconing inside ipArea so it hides when chart mode is active
          if (network.beacons && network.beacons.length) {
            const bhdr = document.createElement('div'); bhdr.className = 'ov-section-hdr';
            bhdr.innerHTML = '⚠ Potential Beaconing'; bhdr.style.color = '#f0a500';
            ipArea.appendChild(bhdr);
            network.beacons.slice(0, 3).forEach(b => {
              const row = ovRow(s.remoteIpCol, b.ip, b.ip, '~'+b.avgInterval+' interval');
              row.querySelector('.ov-list-count').style.color = '#f0a500';
              row.title = `${b.count} connections · avg interval ${b.avgInterval} · regularity ${b.score}%`;
              ipArea.appendChild(row);
            });
          }
        }
      };
      renderIp(); card.addEventListener('ov-chart-change', renderIp); card.appendChild(ipArea);
    }

    if (network.urlSorted && network.urlSorted.length) {
      const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr';
      hdr.textContent = `Domains (${network.urlSorted.length.toLocaleString()} unique)`;
      card.appendChild(hdr);
      card.appendChild(ovScrollList(network.urlSorted, ([domain, count]) => ovRow(s.remoteUrlCol, domain, domain, count.toLocaleString())));
    }

    if (network.portSorted && network.portSorted.length) {
      const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr'; hdr.textContent = 'Ports';
      card.appendChild(hdr);
      card.appendChild(ovScrollList(network.portSorted, ([port, count]) => ovRow(s.remotePortCol, port, port+portService(port), count.toLocaleString())));
    }

    return card;
  }

  // ── Card: registry ────────────────────────────────────────────────────────────
  function buildRegistryCard(registry, s) {
    const card = document.createElement('div'); card.className = 'ov-card';
    const title = document.createElement('div'); title.className = 'ov-card-title'; title.textContent = 'Registry';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub'; sub.textContent = registry.sorted.length.toLocaleString()+' unique keys';
    title.appendChild(sub); card.appendChild(title);
    card.appendChild(ovScrollList(registry.sorted, ([key, count]) => {
      const shortKey = key.length > 52 ? '…'+key.slice(-50) : key;
      const row = ovRow(s.regKeyCol, key, shortKey, count.toLocaleString());
      const lbl = row.querySelector('.ov-list-label'); if (lbl) lbl.title = key;
      return row;
    }));
    return card;
  }

  // ── Card: hashes ──────────────────────────────────────────────────────────────
  function buildHashesCard(hashes, s) {
    const card = document.createElement('div'); card.className = 'ov-card';
    const title = document.createElement('div'); title.className = 'ov-card-title'; title.textContent = 'File Hashes';
    card.appendChild(title);
    [['sha256', s.sha256Col], ['sha1', s.sha1Col], ['md5', s.md5Col]].forEach(([key, col]) => {
      if (!hashes[key] || !hashes[key].length) return;
      const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr';
      hdr.textContent = key.toUpperCase()+' ('+hashes[key].length.toLocaleString()+' unique)';
      card.appendChild(hdr);
      card.appendChild(ovScrollList(hashes[key], ([hash, count]) => {
        const row = ovRow(col, hash, hash.slice(0,16)+'…', count.toLocaleString());
        const lbl = row.querySelector('.ov-list-label'); if (lbl) lbl.title = hash;
        const vtLink = document.createElement('a');
        vtLink.href = 'https://www.virustotal.com/gui/search/'+encodeURIComponent(hash);
        vtLink.target = '_blank'; vtLink.rel = 'noopener'; vtLink.textContent = 'VT'; vtLink.className = 'ov-vt-link';
        vtLink.onclick = e => e.stopPropagation();
        row.insertBefore(vtLink, row.lastChild);
        return row;
      }));
    });
    return card;
  }

  // ── Card: Activity with chart toggle ─────────────────────────────────────────
  // _activityChartMode is now stored in _ovChartModes['activity']

  function buildActivityCard(activity, s) {
    const card = document.createElement('div'); card.className = 'ov-card ov-card-wide';
    card.dataset.chartKey = 'activity'; // enables View section in settings dropdown
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Activity';
    card.appendChild(title);

    const chartWrap = document.createElement('div'); chartWrap.className = 'ov-activity-chart';
    const _renderActivity = () => {
      chartWrap.innerHTML = '';
      chartWrap.appendChild((_ovChartModes['activity'] || 'list') === 'pie'
        ? _buildDonutChart(activity.sorted) : _buildActivityBars(activity, s));
    };
    _renderActivity();
    // Listen for chart mode changes triggered by dropdown
    card.addEventListener('ov-chart-change', _renderActivity);
    card.appendChild(chartWrap);
    return card;
  }

  function _buildActivityBars(activity, s) {
    const wrap = document.createElement('div'); wrap.className = 'ov-card-list';
    const total = activity.sorted.reduce((sum, [,c]) => sum + c, 0);
    activity.sorted.forEach(([action, count]) => {
      const pct = Math.max(2, Math.round((count/total)*100));
      const color = (typeof udmEventColor === 'function' && udmEventColor(action)) || actionColor(action);
      const row = document.createElement('div'); row.className = 'ov-bar-row';
      row.style.cursor = 'pointer';
      row.onclick = () => filterFromOverview(s.actionCol, action);
      row.addEventListener('contextmenu', e => { e.preventDefault(); if (typeof openCellMenu==='function') openCellMenu(e, s.actionCol, action, null); });
      const isWinSec = typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog;
      const displayAction = isWinSec && /^\d+$/.test(action.trim())
        ? `${action} · ${winEventName(action.trim())}` : action;
      const lbl = document.createElement('span'); lbl.className = 'ov-bar-label'; lbl.textContent = displayAction; lbl.title = displayAction;
      const bar = document.createElement('div'); bar.className = 'ov-bar-track';
      const fill = document.createElement('div'); fill.className = 'ov-bar-fill'; fill.style.width = pct+'%'; fill.style.background = color || 'var(--cb-yellow)';
      bar.appendChild(fill);
      const cnt = document.createElement('span'); cnt.className = 'ov-bar-count'; cnt.textContent = count.toLocaleString();
      row.appendChild(lbl); row.appendChild(bar); row.appendChild(cnt);
      wrap.appendChild(row);
    });
    return wrap;
  }

  function _buildDonutChart(entries, colName) {
    const size = 200; const cx = size/2; const cy = size/2; const r = 75; const innerR = 42;
    const total = entries.reduce((s,[,c])=>s+c,0);
    const svg = document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('viewBox',`0 0 ${size} ${size}`); svg.style.cssText='width:200px;height:200px;flex-shrink:0';

    const COLORS = ['#e05c3a','#3a9fd6','#c45ab3','#f0a500','#4caf80','#9c6ade','#26a69a','#f06292','#42a5f5','#ffca28'];
    let angle = -Math.PI/2;
    entries.slice(0,10).forEach(([label, count], i) => {
      const sweep = (count/total) * Math.PI * 2;
      const x1 = cx + r*Math.cos(angle), y1 = cy + r*Math.sin(angle);
      const x2 = cx + r*Math.cos(angle+sweep), y2 = cy + r*Math.sin(angle+sweep);
      const ix1= cx + innerR*Math.cos(angle), iy1 = cy + innerR*Math.sin(angle);
      const ix2= cx + innerR*Math.cos(angle+sweep), iy2 = cy + innerR*Math.sin(angle+sweep);
      const large = sweep > Math.PI ? 1 : 0;
      const path = document.createElementNS('http://www.w3.org/2000/svg','path');
      path.setAttribute('d', `M${x1},${y1} A${r},${r} 0 ${large},1 ${x2},${y2} L${ix2},${iy2} A${innerR},${innerR} 0 ${large},0 ${ix1},${iy1} Z`);
      path.setAttribute('fill', COLORS[i % COLORS.length]);
      path.setAttribute('stroke','var(--modal-bg)'); path.setAttribute('stroke-width','1.5');
      path.style.cursor = 'pointer';
      const svgTitle = document.createElementNS('http://www.w3.org/2000/svg','title');
      svgTitle.textContent = `${label}: ${count.toLocaleString()} (${Math.round(count/total*100)}%)`;
      path.appendChild(svgTitle);
      path.onclick = () => filterFromOverview(colName || '', label);
      const mid = angle + sweep/2;
      path.onmouseover = () => path.setAttribute('opacity','0.8');
      path.onmouseout  = () => path.removeAttribute('opacity');
      svg.appendChild(path);
      angle += sweep;
    });
    // Centre total
    const txt = document.createElementNS('http://www.w3.org/2000/svg','text');
    txt.setAttribute('x',cx); txt.setAttribute('y',cy-4); txt.setAttribute('text-anchor','middle');
    txt.setAttribute('fill','var(--modal-text)'); txt.setAttribute('font-size','11'); txt.setAttribute('font-weight','700');
    txt.textContent = total.toLocaleString();
    const sub = document.createElementNS('http://www.w3.org/2000/svg','text');
    sub.setAttribute('x',cx); sub.setAttribute('y',cy+10); sub.setAttribute('text-anchor','middle');
    sub.setAttribute('fill','var(--cb-muted)'); sub.setAttribute('font-size','9');
    sub.textContent = 'events';
    svg.appendChild(txt); svg.appendChild(sub);

    // Legend
    const wrap = document.createElement('div'); wrap.style.cssText='display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap;padding:8px 0';
    const legend = document.createElement('div'); legend.style.cssText='display:flex;flex-direction:column;gap:4px;flex:1;min-width:140px;max-height:200px;overflow-y:auto';
    entries.slice(0,10).forEach(([label,count],i) => {
      const row = document.createElement('div'); row.style.cssText='display:flex;align-items:center;gap:5px;cursor:pointer;font-size:10px';
      row.onclick = () => filterFromOverview(colName || '', label);
      const dot = document.createElement('span'); dot.style.cssText=`width:8px;height:8px;border-radius:50%;background:${COLORS[i%COLORS.length]};flex-shrink:0`;
      const lbl = document.createElement('span'); lbl.style.cssText='color:var(--modal-text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'; lbl.textContent=label; lbl.title=label;
      const pct = document.createElement('span'); pct.style.cssText='color:var(--cb-muted)'; pct.textContent=Math.round(count/total*100)+'%';
      row.appendChild(dot); row.appendChild(lbl); row.appendChild(pct);
      legend.appendChild(row);
    });
    wrap.appendChild(svg); wrap.appendChild(legend);
    return wrap;
  }

  // ── Card: generic column stats fallback ───────────────────────────────────────
  // ── Windows Security card layout — profile-driven ordering ─────────────────
  function _layoutWinSecCards(panel, ws, s, profile) {
    // Build available cards
    const available = {};
    available.logon    = buildLogonAnalysisCard(ws);
    if (ws.accountChanges.length)                           available.accounts = buildAccountChangesCard(ws, s);
    if (ws.kerberosEvents.length)                           available.kerberos = buildKerberosCard(ws, s);
    if (ws.sprayTargets.length || ws.spraySourceIPs.length || ws.logonFailed > 10)
                                                            available.spray    = buildSprayDetectionCard(ws, s);
    if (ws.netLogons.length)                                available.netlogon = buildNetLogonCard(ws, s);
    if (ws.hasRDP && ws.rdpSessions.length)                 available.rdp      = buildRDPSessionCard(ws, s);

    // Profile → preferred order [row1 keys, row2 keys]
    const ORDERS = {
      'Credential Access':   [['kerberos','logon'],        ['spray','accounts','netlogon','rdp']],
      'Lateral Movement':    [['rdp','netlogon','spray'],  ['logon','accounts','kerberos']],
      'Persistence':         [['accounts','logon'],        ['spray','netlogon','kerberos','rdp']],
      'Initial Access':      [['spray','logon'],           ['accounts','netlogon','kerberos','rdp']],
      'Discovery':           [['logon','netlogon'],        ['accounts','spray','kerberos','rdp']],
      'Privilege Escalation':[['accounts','logon'],        ['spray','kerberos','netlogon','rdp']],
      'Defense Evasion':     [['accounts','logon'],        ['spray','netlogon','kerberos','rdp']],
      'Impact':              [['accounts','spray'],        ['logon','netlogon','kerberos','rdp']],
      'T1003.001':           [['kerberos','logon'],        ['spray','accounts','netlogon','rdp']],
      'T1558.003':           [['kerberos','spray'],        ['logon','accounts','netlogon','rdp']],
      'T1021.001':           [['rdp','netlogon','logon'],  ['spray','accounts','kerberos']],
      'T1021.002':           [['netlogon','spray'],        ['logon','accounts','kerberos','rdp']],
      'T1110.003':           [['spray','logon'],           ['kerberos','accounts','netlogon','rdp']],
      'T1136':               [['accounts','logon'],        ['spray','netlogon','kerberos','rdp']],
    };

    const order = ORDERS[profile] || [['logon','spray'], ['accounts','kerberos','netlogon']];
    const [row1Keys, row2Keys] = order;
    const usedKeys = new Set([...row1Keys, ...row2Keys]);

    const buildRow = keys => {
      const row = document.createElement('div'); row.className = 'ov-row';
      keys.forEach(k => { if (available[k]) row.appendChild(available[k]); });
      return row.children.length ? row : null;
    };

    const r1 = buildRow(row1Keys); if (r1) panel.appendChild(r1);
    // Remaining cards not in the order go in row 2 alongside row2Keys
    const allRow2 = [...row2Keys, ...Object.keys(available).filter(k => !usedKeys.has(k))];
    const r2 = buildRow(allRow2); if (r2) panel.appendChild(r2);
  }

  // ── Card: RDP Session Analysis ────────────────────────────────────────────
  function buildRDPSessionCard(ws, s) {
    const card = document.createElement('div'); card.className = 'ov-card ov-card-wide ov-ttp-ctx-card';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'RDP Session Activity';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';

    // Count by event type
    const evtCounts = {};
    ws.rdpSessions.forEach(s => { evtCounts[s.eventId] = (evtCounts[s.eventId]||0)+1; });
    const logons = (evtCounts['21']||0) + (evtCounts['131']||0);
    const discon = (evtCounts['23']||0) + (evtCounts['24']||0) + (evtCounts['65']||0);
    sub.textContent = `${ws.rdpSessions.length} events · ${logons} connections · ${discon} disconnects`;
    title.appendChild(sub); card.appendChild(title);

    // Event type breakdown
    const breakdown = document.createElement('div'); breakdown.className = 'ov-active-filters-grid';
    breakdown.style.marginBottom = '8px';
    Object.entries(evtCounts).sort((a,b)=>b[1]-a[1]).forEach(([eid, cnt]) => {
      const chip = document.createElement('span'); chip.className = 'ov-ctx-chip';
      chip.style.cursor = 'pointer';
      chip.textContent = eid + ' · ' + (RDP_EVENT_NAMES[eid]||'Event '+eid) + ' (' + cnt + ')';
      chip.onclick = () => filterFromOverview(s.actionCol||'EventID', eid);
      breakdown.appendChild(chip);
    });
    card.appendChild(breakdown);

    // Session list
    const list = document.createElement('div'); list.className = 'ov-ctx-list';
    ws.rdpSessions.slice(0, 50).forEach(ev => {
      const row = document.createElement('div'); row.className = 'ov-ctx-row';
      const hdr = document.createElement('div'); hdr.className = 'ov-ctx-hdr';

      // Event badge
      const evBadge = document.createElement('span'); evBadge.className = 'ov-ctx-chip';
      evBadge.style.cssText = 'font-size:9px;font-weight:700;min-width:28px;text-align:center;' +
        (ev.eventId==='21'||ev.eventId==='131' ? 'background:rgba(58,159,214,0.15);border-color:rgba(58,159,214,0.5);color:#3a9fd6' :
         ev.eventId==='25' ? 'background:rgba(76,175,128,0.15);border-color:rgba(76,175,128,0.5);color:#4caf80' :
         'background:rgba(240,165,0,0.1);border-color:rgba(240,165,0,0.4);color:#f0a500');
      evBadge.textContent = ev.eventId;
      evBadge.title = ev.eventName;

      const evName = document.createElement('span'); evName.style.cssText = 'font-size:11px;font-weight:600;color:var(--modal-text)';
      evName.textContent = ev.eventName;

      const timeEl = document.createElement('span'); timeEl.className = 'ov-ctx-time'; timeEl.textContent = ev.time;
      hdr.appendChild(evBadge); hdr.appendChild(evName); hdr.appendChild(timeEl);
      row.appendChild(hdr);

      // Detail fields
      const addF = (lbl, col, val) => {
        if (!val) return;
        const f = document.createElement('div'); f.className = 'ov-ctx-field';
        const l = document.createElement('span'); l.className = 'ov-ctx-lbl'; l.textContent = lbl;
        const v = document.createElement('span'); v.className = 'ov-ctx-val'; v.textContent = val;
        v.style.cursor = 'pointer'; v.onclick = () => filterFromOverview(col, val);
        v.addEventListener('contextmenu', e => { e.preventDefault(); if (typeof openCellMenu==='function') openCellMenu(e, col, val, null); });
        f.appendChild(l); f.appendChild(v); row.appendChild(f);
      };

      addF('User',    s.userCol||'TargetUserName', ev.user);
      addF('From',    s.remoteIpCol||'IpAddress',  ev.srcIp);
      addF('Session', 'SessionID',                  ev.sessionId);
      addF('Host',    s.deviceCol||'Computer',     ev.device);
      list.appendChild(row);
    });

    const wrap = document.createElement('div'); wrap.className = 'ov-ctx-scroll'; wrap.appendChild(list);
    card.appendChild(wrap);
    return card;
  }

  // RDP event name lookup (used in the card)
  const RDP_EVENT_NAMES = {
    '21':'Logon Success','22':'Shell Start','23':'Logoff',
    '24':'Disconnect (Net)','25':'Reconnect','39':'Disc by Session',
    '40':'Disc Reason','41':'Logon Failed','131':'TCP Connect',
    '98':'RDP Connect','65':'Client Disconnect','72':'Conn Closed',
  };

  // ── Windows Security: Event ID name lookup ────────────────────────────────
  function winEventName(id) {
    return (typeof WIN_EVENT_NAMES !== 'undefined' && WIN_EVENT_NAMES[id]) || ('Event ' + id);
  }
  function winLogonTypeName(t) {
    return (typeof WIN_LOGON_TYPES !== 'undefined' && WIN_LOGON_TYPES[t]) || ('Type ' + t);
  }

  // ── Card: Logon Analysis ─────────────────────────────────────────────────
  function buildLogonAnalysisCard(ws) {
    const card = document.createElement('div'); card.className = 'ov-card';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Logon Analysis';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    const total = ws.logonSuccess + ws.logonFailed;
    const failPct = total ? Math.round((ws.logonFailed / total) * 100) : 0;
    sub.textContent = `${total.toLocaleString()} events · ${failPct}% failed`;
    title.appendChild(sub); card.appendChild(title);

    // Success vs failed summary
    const summary = document.createElement('div'); summary.className = 'ov-kv';
    const sl = document.createElement('span'); sl.className = 'ov-kv-label'; sl.textContent = 'Successful';
    const sv = document.createElement('span'); sv.className = 'ov-kv-value'; sv.style.color = '#4caf80';
    sv.textContent = ws.logonSuccess.toLocaleString();
    const fl = document.createElement('span'); fl.className = 'ov-kv-label'; fl.textContent = 'Failed';
    const fv = document.createElement('span'); fv.className = 'ov-kv-value'; fv.style.color = ws.logonFailed > 10 ? '#e83e3e' : 'var(--modal-text)';
    fv.textContent = ws.logonFailed.toLocaleString();
    summary.appendChild(sl); summary.appendChild(sv);
    card.appendChild(summary);
    const summary2 = document.createElement('div'); summary2.className = 'ov-kv';
    summary2.appendChild(fl); summary2.appendChild(fv);
    card.appendChild(summary2);

    // Logon type breakdown
    const typeEntries = Object.entries(ws.logonTypes).sort((a,b) => b[1]-a[1]);
    if (typeEntries.length) {
      const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr'; hdr.textContent = 'By Logon Type';
      card.appendChild(hdr);
      const typeCol = (typeof ptColMap !== 'undefined' && ptColMap.winLogonType) || '';
      typeEntries.forEach(([type, count]) => {
        const row = ovRow(typeCol, type, `${winLogonTypeName(type)} (Type ${type})`, count.toLocaleString());
        card.appendChild(row);
      });
    }
    return card;
  }

  // ── Card: Account Changes ────────────────────────────────────────────────
  function buildAccountChangesCard(ws, s) {
    const card = document.createElement('div'); card.className = 'ov-card';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Account Activity';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = ws.accountChanges.length.toLocaleString() + ' change events';
    title.appendChild(sub); card.appendChild(title);

    if (!ws.accountChanges.length) {
      const empty = document.createElement('div'); empty.style.cssText = 'font-size:11px;color:var(--modal-muted);padding:6px 0';
      empty.textContent = 'No account change events detected.'; card.appendChild(empty);
      return card;
    }

    const list = document.createElement('div'); list.className = 'ov-ctx-list';
    ws.accountChanges.slice(0, 30).forEach(ev => {
      const row = document.createElement('div'); row.className = 'ov-ctx-row';
      const hdr = document.createElement('div'); hdr.className = 'ov-ctx-hdr';

      const evBadge = document.createElement('span'); evBadge.className = 'ov-ctx-chip';
      evBadge.style.cssText = 'font-size:9px;font-weight:700;background:rgba(255,215,0,0.1);border-color:rgba(255,215,0,0.4)';
      evBadge.textContent = ev.eventId;
      evBadge.title = winEventName(ev.eventId);

      const evName = document.createElement('span'); evName.style.cssText = 'font-size:11px;color:var(--modal-text);flex:1';
      evName.textContent = winEventName(ev.eventId);

      const timeEl = document.createElement('span'); timeEl.className = 'ov-ctx-time'; timeEl.textContent = ev.time;
      hdr.appendChild(evBadge); hdr.appendChild(evName); hdr.appendChild(timeEl);
      row.appendChild(hdr);

      if (ev.tgtUser) {
        const f = document.createElement('div'); f.className = 'ov-ctx-field';
        const l = document.createElement('span'); l.className = 'ov-ctx-lbl'; l.textContent = 'Target';
        const v = document.createElement('span'); v.className = 'ov-ctx-val'; v.textContent = ev.tgtUser;
        v.style.cursor = 'pointer'; v.onclick = () => filterFromOverview(s.userCol, ev.tgtUser);
        f.appendChild(l); f.appendChild(v); row.appendChild(f);
      }
      if (ev.subUser && ev.subUser !== ev.tgtUser) {
        const f2 = document.createElement('div'); f2.className = 'ov-ctx-field';
        const l2 = document.createElement('span'); l2.className = 'ov-ctx-lbl'; l2.textContent = 'By';
        const v2 = document.createElement('span'); v2.className = 'ov-ctx-val'; v2.textContent = ev.subUser;
        v2.style.cursor = 'pointer'; v2.onclick = () => filterFromOverview(s.userCol, ev.subUser);
        f2.appendChild(l2); f2.appendChild(v2); row.appendChild(f2);
      }
      if (ev.device) {
        const f3 = document.createElement('div'); f3.className = 'ov-ctx-field';
        const l3 = document.createElement('span'); l3.className = 'ov-ctx-lbl'; l3.textContent = 'Host';
        const v3 = document.createElement('span'); v3.className = 'ov-ctx-val'; v3.textContent = ev.device;
        v3.style.cursor = 'pointer'; v3.onclick = () => filterFromOverview(s.deviceCol, ev.device);
        f3.appendChild(l3); f3.appendChild(v3); row.appendChild(f3);
      }
      list.appendChild(row);
    });
    const wrap = document.createElement('div'); wrap.className = 'ov-ctx-scroll'; wrap.appendChild(list);
    card.appendChild(wrap);
    return card;
  }

  // ── Card: Kerberos / Authentication ──────────────────────────────────────
  function buildKerberosCard(ws, s) {
    const card = document.createElement('div'); card.className = 'ov-card';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Authentication Events';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = ws.kerberosEvents.length.toLocaleString() + ' Kerberos/NTLM events';
    title.appendChild(sub); card.appendChild(title);

    // Event ID breakdown
    const evCounts = {};
    ws.kerberosEvents.forEach(e => { evCounts[e.eventId] = (evCounts[e.eventId]||0)+1; });
    const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr'; hdr.textContent = 'Event Breakdown';
    card.appendChild(hdr);
    Object.entries(evCounts).sort((a,b)=>b[1]-a[1]).forEach(([id,cnt]) => {
      const row = ovRow(s.actionCol, id, `${id} · ${winEventName(id)}`, cnt.toLocaleString());
      if (id === '4771' || id === '4777') row.querySelector('.ov-list-label').style.color = '#e83e3e';
      if (id === '4769') row.querySelector('.ov-list-label').style.color = '#f0a500';
      card.appendChild(row);
    });

    // Recent events
    const hdr2 = document.createElement('div'); hdr2.className = 'ov-section-hdr'; hdr2.textContent = 'Recent Events';
    card.appendChild(hdr2);
    const list = document.createElement('div'); list.className = 'ov-card-list';
    ws.kerberosEvents.slice(0,15).forEach(ev => {
      const row = document.createElement('div'); row.className = 'ov-list-row'; row.style.flexDirection = 'column'; row.style.alignItems = 'flex-start'; row.style.gap = '2px';
      const top = document.createElement('div'); top.style.cssText = 'display:flex;gap:6px;width:100%;font-size:11px';
      const badge = document.createElement('span'); badge.style.cssText = 'font-size:9px;font-weight:700;color:var(--cb-yellow)'; badge.textContent = ev.eventId;
      const user = document.createElement('span'); user.style.cssText = 'flex:1;color:var(--modal-text)'; user.textContent = ev.tgtUser || '—';
      user.style.cursor = 'pointer'; user.onclick = () => filterFromOverview(s.userCol, ev.tgtUser);
      const time = document.createElement('span'); time.className = 'ov-ctx-time'; time.textContent = ev.time;
      top.appendChild(badge); top.appendChild(user); top.appendChild(time);
      row.appendChild(top);
      if (ev.srcIp) {
        const ip = document.createElement('div'); ip.style.cssText = 'font-size:10px;color:var(--modal-muted);padding-left:4px';
        ip.textContent = `from ${ev.srcIp} on ${ev.device||'—'}`;
        ip.style.cursor = 'pointer'; ip.onclick = () => filterFromOverview(s.remoteIpCol, ev.srcIp);
        row.appendChild(ip);
      }
      list.appendChild(row);
    });
    card.appendChild(list);
    return card;
  }

  // ── Card: Spray / Brute Force Detection ──────────────────────────────────
  function buildSprayDetectionCard(ws, s) {
    const card = document.createElement('div'); card.className = 'ov-card ov-ttp-ctx-card';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Spray / Brute Force Detection';
    const total = ws.logonFailed;
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = `${total.toLocaleString()} failed logons`;
    title.appendChild(sub); card.appendChild(title);

    if (ws.spraySourceIPs.length) {
      const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr';
      hdr.innerHTML = '⚠ Password Spray — Source IPs targeting multiple accounts';
      hdr.style.color = '#e83e3e'; card.appendChild(hdr);
      ws.spraySourceIPs.forEach(({ ip, count, accounts }) => {
        const row = ovRow(s.remoteIpCol, ip, ip,
          `${count.toLocaleString()} attempts · ${accounts} accounts`);
        row.querySelector('.ov-list-count').style.color = '#e83e3e';
        card.appendChild(row);
      });
    }

    if (ws.sprayTargets.length) {
      const hdr2 = document.createElement('div'); hdr2.className = 'ov-section-hdr';
      hdr2.innerHTML = '⚠ Brute Force — Accounts hit from multiple sources';
      hdr2.style.color = '#f0a500'; card.appendChild(hdr2);
      ws.sprayTargets.forEach(({ account, count, sources }) => {
        const row = ovRow(s.userCol, account, account,
          `${count.toLocaleString()} attempts · ${sources} sources`);
        row.querySelector('.ov-list-count').style.color = '#f0a500';
        card.appendChild(row);
      });
    }

    if (!ws.spraySourceIPs.length && !ws.sprayTargets.length) {
      const ok = document.createElement('div'); ok.style.cssText = 'font-size:11px;color:#4caf80;padding:6px 0';
      ok.textContent = '✓ No spray or brute force patterns detected.'; card.appendChild(ok);
    }

    return card;
  }

  // ── Card: Network Logons (lateral movement) ───────────────────────────────
  function buildNetLogonCard(ws, s) {
    const card = document.createElement('div'); card.className = 'ov-card';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Network Logons';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = ws.netLogons.length.toLocaleString() + ' network/remote logons';
    title.appendChild(sub); card.appendChild(title);

    const list = document.createElement('div'); list.className = 'ov-card-list';
    ws.netLogons.slice(0, 30).forEach(ev => {
      const row = document.createElement('div'); row.className = 'ov-list-row';
      row.style.flexDirection = 'column'; row.style.alignItems = 'flex-start'; row.style.gap = '2px';
      const top = document.createElement('div'); top.style.cssText = 'display:flex;gap:6px;width:100%';
      const typeBadge = document.createElement('span');
      typeBadge.style.cssText = `font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;background:rgba(255,215,0,0.1);border:1px solid rgba(255,215,0,0.3);color:var(--cb-yellow);flex-shrink:0`;
      typeBadge.textContent = winLogonTypeName(ev.type);
      const user = document.createElement('span'); user.style.cssText = 'flex:1;font-size:11px;color:var(--modal-text)';
      user.textContent = ev.tgtUser || '—';
      user.style.cursor = 'pointer'; user.onclick = () => filterFromOverview(s.userCol, ev.tgtUser);
      const time = document.createElement('span'); time.className = 'ov-ctx-time'; time.textContent = ev.time;
      top.appendChild(typeBadge); top.appendChild(user); top.appendChild(time);
      row.appendChild(top);
      if (ev.srcIp || ev.device) {
        const detail = document.createElement('div'); detail.style.cssText = 'font-size:10px;color:var(--modal-muted);padding-left:4px';
        detail.textContent = [ev.srcIp && `from ${ev.srcIp}`, ev.device && `on ${ev.device}`].filter(Boolean).join(' → ');
        if (ev.srcIp) { detail.style.cursor = 'pointer'; detail.onclick = () => filterFromOverview(s.remoteIpCol, ev.srcIp); }
        row.appendChild(detail);
      }
      list.appendChild(row);
    });
    card.appendChild(list);
    return card;
  }

  function buildColumnStatsCard(rows) {
    const card = document.createElement('div'); card.className = 'ov-card ov-card-full';
    const title = document.createElement('div'); title.className = 'ov-card-title'; title.textContent = 'Column Summary';
    card.appendChild(title);
    const grid = document.createElement('div'); grid.className = 'ov-col-grid';
    const interesting = headers.filter(h => {
      const vals = rows.slice(0,200).map(r => r[h]).filter(v => v && v.trim());
      if (vals.length < 5) return false;
      const uniq = new Set(vals);
      return uniq.size >= 2 && uniq.size <= 500;
    }).slice(0,12);
    interesting.forEach(h => {
      const counts = {};
      rows.forEach(r => { const v=(r[h]||'').trim(); if (v) counts[v]=(counts[v]||0)+1; });
      const top3 = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,3);
      const colEl = document.createElement('div'); colEl.className = 'ov-col-stat';
      const hdr = document.createElement('div'); hdr.className = 'ov-col-stat-hdr'; hdr.textContent = h; hdr.title = h;
      const uniq = document.createElement('div'); uniq.className = 'ov-col-stat-uniq'; uniq.textContent = Object.keys(counts).length.toLocaleString()+' unique';
      colEl.appendChild(hdr); colEl.appendChild(uniq);
      top3.forEach(([v, c]) => {
        const item = document.createElement('div'); item.className = 'ov-col-stat-item'; item.style.cursor = 'pointer';
        item.onclick = () => filterFromOverview(h, v);
        item.addEventListener('contextmenu', e => { e.preventDefault(); if (typeof openCellMenu==='function') openCellMenu(e, h, v, null); });
        const vEl = document.createElement('span'); vEl.textContent = v.length>30 ? v.slice(0,28)+'…' : v; vEl.title = v;
        const cEl = document.createElement('span'); cEl.className = 'ov-list-count'; cEl.textContent = c.toLocaleString();
        item.appendChild(vEl); item.appendChild(cEl); colEl.appendChild(item);
      });
      grid.appendChild(colEl);
    });
    card.appendChild(grid);
    return card;
  }

  // ── Card: Event Frequency Timeline ──────────────────────────────────────────
  function buildFreqTimelineCard(freq) {
    const card = document.createElement('div'); card.className = 'ov-card ov-card-full';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Event Frequency';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = freq.bucketSizeLabel + ' buckets · click bar to set time filter';
    title.appendChild(sub); card.appendChild(title);

    // Legend
    const legend = document.createElement('div'); legend.className = 'ov-freq-legend';
    freq.categories.forEach(cat => {
      const item = document.createElement('span'); item.className = 'ov-freq-legend-item';
      const dot = document.createElement('span'); dot.style.cssText = `display:inline-block;width:9px;height:9px;border-radius:2px;background:${freq.catColors[cat]};margin-right:4px;flex-shrink:0`;
      item.appendChild(dot); item.appendChild(document.createTextNode(cat));
      legend.appendChild(item);
    });
    card.appendChild(legend);

    // Canvas container
    const wrap = document.createElement('div'); wrap.className = 'ov-freq-wrap';
    const canvas = document.createElement('canvas'); canvas.className = 'ov-freq-canvas';
    const tip = document.createElement('div'); tip.className = 'ov-freq-tip'; tip.style.display = 'none';
    wrap.appendChild(canvas); wrap.appendChild(tip); card.appendChild(wrap);

    // Deferred render — needs layout to know pixel width
    requestAnimationFrame(() => {
      const dpr = window.devicePixelRatio || 1;
      const W = wrap.clientWidth || 600, H = wrap.clientHeight || 120;
      canvas.width = W * dpr; canvas.height = H * dpr;
      canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);

      const ML = 28, MR = 8, MT = 6, MB = 20;
      const cW = W - ML - MR, cH = H - MT - MB;
      const nb = freq.buckets.length;
      const bW = Math.max(1.5, (cW / nb) - 0.5);
      const gap = (cW - bW * nb) / nb;

      // Y axis label
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--cb-muted').trim() || '#668';
      ctx.font = `9px system-ui,sans-serif`;

      // Draw stacked bars
      freq.buckets.forEach((b, i) => {
        if (!b.total) return;
        const x = ML + i * (bW + gap);
        let y = MT + cH;
        freq.categories.forEach(cat => {
          const cc = b.cats[cat]; if (!cc) return;
          const bh = Math.max(1, (cc / freq.maxTotal) * cH);
          y -= bh;
          ctx.fillStyle = freq.catColors[cat];
          ctx.fillRect(x, y, bW, bh);
        });
      });

      // X-axis time labels
      const isDark = document.documentElement.classList.contains('light-theme') ? false : true;
      ctx.fillStyle = isDark ? '#778899' : '#99aabb';
      ctx.font = '9px system-ui,sans-serif'; ctx.textAlign = 'center';
      const step = Math.max(1, Math.ceil(nb / 10));
      freq.buckets.forEach((b, i) => {
        if (i % step !== 0) return;
        ctx.fillText(b.label, ML + i * (bW + gap) + bW / 2, H - 4);
      });

      // Hover + click
      const hitIdx = (clientX) => {
        const rect = canvas.getBoundingClientRect();
        const mx = (clientX - rect.left) - ML;
        return Math.max(0, Math.min(nb - 1, Math.floor(mx / (bW + gap))));
      };

      canvas.onmousemove = (e) => {
        const i = hitIdx(e.clientX);
        const b = freq.buckets[i];
        if (!b || !b.total) { tip.style.display = 'none'; return; }
        let html = `<strong>${b.label}</strong><div style="margin-top:3px">${b.total.toLocaleString()} events</div>`;
        freq.categories.forEach(cat => {
          if (b.cats[cat]) html += `<div style="color:${freq.catColors[cat]}">${cat}: ${b.cats[cat]}</div>`;
        });
        tip.innerHTML = html; tip.style.display = 'block';
        const rect = canvas.getBoundingClientRect();
        const tx = e.clientX - rect.left;
        tip.style.left = Math.min(tx + 10, W - 160) + 'px';
        tip.style.top  = '4px';
      };
      canvas.onmouseleave = () => { tip.style.display = 'none'; };

      canvas.onclick = (e) => {
        const i = hitIdx(e.clientX);
        const b = freq.buckets[i]; if (!b || !b.total) return;
        const pad = ms => new Date(ms).toISOString().slice(0,16);
        const fromEl = document.getElementById('tsFrom');
        const toEl   = document.getElementById('tsTo');
        if (!fromEl || !toEl) return;
        fromEl.value = pad(b.tStart); toEl.value = pad(b.tEnd);
        applyFilter(); scheduleOverviewRender();
      };
    });

    return card;
  }

  // ── Card: Top-N Tables ────────────────────────────────────────────────────────
  function buildTopNCard(topN) {
    if (!topN || !topN.panels || !topN.panels.some(p => p.rows.length)) return null;
    const card = document.createElement('div'); card.className = 'ov-card ov-card-full';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Top Offenders';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = 'click any row to filter';
    title.appendChild(sub); card.appendChild(title);

    const grid = document.createElement('div'); grid.className = 'ov-topn-grid';

    topN.panels.forEach(panel => {
      const col = document.createElement('div'); col.className = 'ov-topn-col';

      const hdr = document.createElement('div'); hdr.className = 'ov-section-hdr';
      hdr.textContent = panel.name; col.appendChild(hdr);

      if (!panel.rows.length) {
        const empty = document.createElement('div');
        empty.style.cssText = 'font-size:11px;color:var(--cb-muted);padding:4px 0;font-style:italic';
        empty.textContent = 'No data'; col.appendChild(empty);
      } else {
        panel.rows.forEach(([val, count]) => {
          const row = document.createElement('div'); row.className = 'ov-topn-row';
          row.style.cursor = 'pointer';
          row.title = `Filter: ${val}`;
          row.onclick = () => { if (panel.filterCol) filterFromOverview(panel.filterCol, val); };
          row.addEventListener('contextmenu', e => { e.preventDefault(); if (panel.filterCol && typeof openCellMenu==='function') openCellMenu(e, panel.filterCol, val, null); });

          const lbl = document.createElement('span'); lbl.className = 'ov-topn-label';
          lbl.textContent = val; lbl.title = val;

          const barWrap = document.createElement('div'); barWrap.className = 'ov-topn-bar-wrap';
          const barFill = document.createElement('div'); barFill.className = 'ov-topn-bar-fill';
          barFill.style.width = Math.max(2, Math.round((count / panel.max) * 100)) + '%';
          barWrap.appendChild(barFill);

          const cnt = document.createElement('span'); cnt.className = 'ov-topn-count';
          cnt.textContent = count.toLocaleString();

          row.appendChild(lbl); row.appendChild(barWrap); row.appendChild(cnt);
          col.appendChild(row);
        });
      }
      grid.appendChild(col);
    });

    card.appendChild(grid);
    return card;
  }

  // ── Card: Attack Chain Strip ──────────────────────────────────────────────────
  function buildAttackChainCard(chain, s) {
    if (!chain || !chain.events || !chain.events.length) return null;
    const card = document.createElement('div'); card.className = 'ov-card ov-card-full';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'Attack Chain';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = `${chain.events.length} event${chain.events.length!==1?'s':''} · chronological · click to filter`;
    title.appendChild(sub); card.appendChild(title);

    // Stage color legend
    const legend = document.createElement('div'); legend.className = 'ov-freq-legend';
    const seenStages = [...new Set(chain.events.map(e => e.stage))];
    seenStages.forEach(st => {
      const color = chain.stageColors[st] || '#556677';
      const item = document.createElement('span'); item.className = 'ov-freq-legend-item';
      const dot = document.createElement('span'); dot.style.cssText = `display:inline-block;width:9px;height:9px;border-radius:2px;background:${color};margin-right:4px;flex-shrink:0`;
      item.appendChild(dot); item.appendChild(document.createTextNode(st));
      legend.appendChild(item);
    });
    card.appendChild(legend);

    // Scrollable horizontal strip
    const strip = document.createElement('div'); strip.className = 'ov-chain-strip';

    // Group events into stage runs for visual separation
    let lastStage = null;
    chain.events.forEach((ev, idx) => {
      // Stage transition marker
      if (ev.stage !== lastStage) {
        if (lastStage !== null) {
          const sep = document.createElement('div'); sep.className = 'ov-chain-sep';
          strip.appendChild(sep);
        }
        const stageHdr = document.createElement('div'); stageHdr.className = 'ov-chain-stage-hdr';
        stageHdr.style.color = chain.stageColors[ev.stage] || '#556677';
        stageHdr.textContent = ev.stage;
        strip.appendChild(stageHdr);
        lastStage = ev.stage;
      }

      // Event badge
      const badge = document.createElement('div'); badge.className = 'ov-chain-badge';
      badge.style.borderColor = ev.color;
      badge.style.cursor = 'pointer';
      badge.title = `${ev.stage}: ${ev.label}${ev.detail ? ' · '+ev.detail : ''}${ev.ts ? '\n'+ev.ts : ''}`;

      badge.onclick = () => {
        if (s.actionCol) filterFromOverview(s.actionCol, ev.eid);
      };
      badge.addEventListener('contextmenu', e => {
        e.preventDefault();
        if (s.actionCol && typeof openCellMenu==='function') openCellMenu(e, s.actionCol, ev.eid, null);
      });

      const evLabel = document.createElement('div'); evLabel.className = 'ov-chain-badge-label';
      evLabel.style.color = ev.color;
      evLabel.textContent = ev.label;

      const evDetail = document.createElement('div'); evDetail.className = 'ov-chain-badge-detail';
      evDetail.textContent = ev.detail || ev.eid;

      const evTime = document.createElement('div'); evTime.className = 'ov-chain-badge-time';
      evTime.textContent = (ev.ts || '').slice(11,19); // HH:MM:SS

      badge.appendChild(evLabel); badge.appendChild(evDetail); badge.appendChild(evTime);

      // Repeat count bubble
      if (ev.count > 1) {
        const cnt = document.createElement('div'); cnt.className = 'ov-chain-badge-cnt';
        cnt.textContent = '×'+ev.count;
        badge.appendChild(cnt);
      }

      strip.appendChild(badge);
    });

    const outer = document.createElement('div'); outer.className = 'ov-chain-outer';
    outer.appendChild(strip);
    card.appendChild(outer);
    return card;
  }

  // ── Card: ATT&CK auto-summary ────────────────────────────────────────────────
  // Returns the active tactic name — null if General or a technique is selected, tactic string only when a tactic is directly chosen
  function _getActiveTactic() {
    if (!_ovProfile) return null;
    if (typeof TACTIC_PROFILES !== 'undefined' && TACTIC_PROFILES[_ovProfile]) return _ovProfile;
    if (typeof MITRE_TECHNIQUES !== 'undefined') {
      const tech = MITRE_TECHNIQUES.find(t => t.id === _ovProfile);
      if (tech) return tech.tactic;
    }
    return null;
  }

  // Like _getActiveTactic but only returns a value when a tactic is directly selected —
  // technique selections return null so the coverage card shows all tactics
  function _getDirectTactic() {
    if (!_ovProfile) return null;
    if (typeof TACTIC_PROFILES !== 'undefined' && TACTIC_PROFILES[_ovProfile]) return _ovProfile;
    return null;
  }

  function buildMitreSummaryCard(mitreResults) {
    const activeTactic = _getDirectTactic(); // only filter when a tactic is directly selected, not a technique
    const card = document.createElement('div'); card.className = 'ov-card ov-card-full';
    const title = document.createElement('div'); title.className = 'ov-card-title';
    title.textContent = 'ATT&CK Coverage';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = activeTactic ? activeTactic : 'Automatically mapped from detected activity';
    if (activeTactic) sub.style.color = tacticColor(activeTactic);
    title.appendChild(sub); card.appendChild(title);

    // ── Default view — all tactics summary (filtered to active tactic if set) ──
    const tacticMap = {};
    Object.entries(mitreResults).forEach(([id, count]) => {
      const tech = (typeof MITRE_TECHNIQUES !== 'undefined') ? MITRE_TECHNIQUES.find(t => t.id === id) : null;
      const tactic = tech ? tech.tactic : 'Unknown';
      if (!tacticMap[tactic]) tacticMap[tactic] = { total: 0, techs: [] };
      tacticMap[tactic].total += count;
      tacticMap[tactic].techs.push({ id, name: tech ? tech.name : id, count });
    });

    const tacticOrder = ['Execution','Persistence','Privilege Escalation','Defense Evasion',
      'Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact','Initial Access'];
    const allSorted = tacticOrder.filter(t => tacticMap[t]).concat(Object.keys(tacticMap).filter(t => !tacticOrder.includes(t)));
    // When a tactic is active, show only that bar
    const sorted = activeTactic ? allSorted.filter(t => t === activeTactic) : allSorted;

    if (!sorted.length) {
      const empty = document.createElement('div'); empty.style.cssText = 'color:var(--cb-muted);font-size:12px;padding:8px 0';
      empty.textContent = 'No matching ATT&CK techniques detected in this dataset.';
      card.appendChild(empty); return card;
    }

    const maxTotal = Math.max(...sorted.map(t => tacticMap[t].total));
    const grid = document.createElement('div'); grid.className = 'ov-mitre-summary-grid';

    sorted.forEach(tactic => {
      const entry = tacticMap[tactic];
      const topTechs = entry.techs.sort((a, b) => b.count - a.count).slice(0, 3);
      const pct = Math.max(4, Math.round((entry.total / maxTotal) * 100));
      const row = document.createElement('div'); row.className = 'ov-mitre-summary-row';
      const tacticEl = document.createElement('span'); tacticEl.className = 'ov-mitre-tactic-label'; tacticEl.textContent = tactic; tacticEl.title = tactic;
      row.appendChild(tacticEl);
      const barWrap = document.createElement('div'); barWrap.className = 'ov-mitre-bar-wrap';
      const bar = document.createElement('div'); bar.className = 'ov-mitre-bar'; bar.style.width = pct+'%'; bar.style.background = tacticColor(tactic);
      barWrap.appendChild(bar); row.appendChild(barWrap);
      const techPills = document.createElement('div'); techPills.className = 'ov-mitre-pills';
      topTechs.forEach(t => {
        const pill = document.createElement('span'); pill.className = 'ov-mitre-pill'; pill.textContent = t.id;
        pill.title = t.name+' — '+t.count.toLocaleString()+' events'; pill.style.cursor = 'pointer';
        pill.onclick = () => addTtpFilterKeepOverview(t.id);
        techPills.appendChild(pill);
      });
      if (entry.techs.length > 3) { const more = document.createElement('span'); more.className = 'ov-mitre-pill ov-mitre-pill-more'; more.textContent = '+'+(entry.techs.length-3)+' more'; techPills.appendChild(more); }
      row.appendChild(techPills);
      const cnt = document.createElement('span'); cnt.className = 'ov-mitre-total'; cnt.textContent = entry.total.toLocaleString();
      row.appendChild(cnt);
      grid.appendChild(row);
    });

    card.appendChild(grid);
    return card;
  }

  // ── Card: ATT&CK TTP selector ────────────────────────────────────────────────
  function buildMitreTtpSelector(mitreResults) {
    const activeTactic = _getDirectTactic(); // only narrow to one tactic when explicitly selected, not via technique
    const wrapper = document.createElement('div'); wrapper.className = 'ov-card ov-card-full';
    wrapper.addEventListener('mouseenter', () => { _ovHoveredRegion = 'ttp'; _ovHoveredList = null; });
    wrapper.addEventListener('mouseleave', () => { if (_ovHoveredRegion === 'ttp') _ovHoveredRegion = null; });
    const headerRow = document.createElement('div'); headerRow.className = 'ov-card-title';

    const titleSpan = document.createElement('span'); titleSpan.textContent = 'TTP Selector';

    // ── Default view — tactic accordion ──────────────────────────────────────
    headerRow.style.cursor = 'pointer';
    const expandAllBtn = document.createElement('button');
    expandAllBtn.style.cssText = 'font-size:9px;padding:1px 6px;margin-left:auto;background:transparent;border:1px solid var(--cb-os2);border-radius:3px;color:var(--cb-os3);cursor:pointer';
    expandAllBtn.textContent = '⊞ All'; expandAllBtn.title = 'Expand all tactics';
    const collapseAllBtn = document.createElement('button');
    collapseAllBtn.style.cssText = 'font-size:9px;padding:1px 6px;background:transparent;border:1px solid var(--cb-os2);border-radius:3px;color:var(--cb-os3);cursor:pointer';
    collapseAllBtn.textContent = '⊟ All'; collapseAllBtn.title = 'Collapse all tactics';
    const chevron = document.createElement('span'); chevron.style.cssText = 'font-size:10px;color:var(--cb-os3);margin-left:6px'; chevron.textContent = '▾';

    headerRow.appendChild(titleSpan); headerRow.appendChild(expandAllBtn); headerRow.appendChild(collapseAllBtn); headerRow.appendChild(chevron);
    wrapper.appendChild(headerRow);

    const body = document.createElement('div');
    const searchInput = document.createElement('input'); searchInput.type = 'text';
    searchInput.placeholder = 'Search ID or name…'; searchInput.className = 'ov-ttp-search';
    searchInput.style.cssText = 'width:100%;margin:8px 0 6px;box-sizing:border-box';
    const hitCount = document.createElement('div'); hitCount.className = 'ov-ttp-hit-count'; hitCount.style.marginBottom = '6px';
    const hitN = Object.keys(mitreResults).length;
    hitCount.textContent = hitN ? hitN + ' technique' + (hitN !== 1 ? 's' : '') + ' detected — click a tactic to expand' : 'No techniques detected in current data';
    body.appendChild(searchInput);
    body.appendChild(hitCount);

    // Build tactic sections
    const tacticOrder = ['Execution','Persistence','Privilege Escalation','Defense Evasion',
      'Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact','Initial Access'];

    const techsByTactic = {};
    if (typeof MITRE_TECHNIQUES !== 'undefined') {
      MITRE_TECHNIQUES.forEach(t => {
        if (t.parent) return; // only top-level for tactic grouping
        if (!techsByTactic[t.tactic]) techsByTactic[t.tactic] = [];
        techsByTactic[t.tactic].push(t);
      });
    }

    const allSubtechs = {};
    if (typeof MITRE_TECHNIQUES !== 'undefined') {
      MITRE_TECHNIQUES.filter(t => t.parent).forEach(t => {
        if (!allSubtechs[t.parent]) allSubtechs[t.parent] = [];
        allSubtechs[t.parent].push(t);
      });
    }

    const tacticSections = [];

    tacticOrder.forEach(tactic => {
      const techs = techsByTactic[tactic] || [];
      if (!techs.length) return;

      const section = document.createElement('div'); section.className = 'ov-ttp-tactic-section';
      section.dataset.tactic = tactic;

      const tacticHdr = document.createElement('div'); tacticHdr.className = 'ov-ttp-tactic-hdr';
      tacticHdr.style.borderLeftColor = tacticColor(tactic);

      const tacticHits = techs.reduce((sum, t) => {
        const sub = allSubtechs[t.id] || [];
        const techCount = mitreResults[t.id] || 0;
        const subCount = sub.reduce((s, st) => s + (mitreResults[st.id] || 0), 0);
        return sum + techCount + subCount;
      }, 0);

      const tacticName = document.createElement('span'); tacticName.className = 'ov-ttp-tactic-name';
      tacticName.textContent = tactic;
      const tacticEvts = document.createElement('span'); tacticEvts.className = 'ov-ttp-tactic-evts';
      if (tacticHits > 0) {
        tacticEvts.textContent = tacticHits.toLocaleString() + ' events detected';
        tacticEvts.style.color = tacticColor(tactic);
      }
      if (!tacticHits) return; // skip tactics with no hits

      const tacticChevron = document.createElement('span'); tacticChevron.className = 'ov-ttp-chevron';
      tacticChevron.textContent = '▸';

      tacticHdr.appendChild(tacticName); tacticHdr.appendChild(tacticEvts); tacticHdr.appendChild(tacticChevron);

      const techList = document.createElement('div'); techList.className = 'ov-ttp-tech-list';
      techList.style.display = 'none';

      const makeRow = (id, name, count, hasDetection, isSub) => {
        const row = document.createElement('div'); row.className = isSub ? 'ov-ttp-sub-row' : 'ov-ttp-tech-row';
        if (count > 0) row.classList.add('ov-ttp-hit');
        row.dataset.techId = id; row.dataset.techName = name.toLowerCase();

        const idEl   = document.createElement('span'); idEl.className   = 'ov-ttp-id'   + (isSub ? ' ov-ttp-sub-id' : ''); idEl.textContent = id;
        const nameEl = document.createElement('span'); nameEl.className = 'ov-ttp-name'; nameEl.textContent = name;
        const cntEl  = document.createElement('span'); cntEl.className  = 'ov-ttp-count';

        if (count > 0) {
          cntEl.textContent = count.toLocaleString(); cntEl.style.color = tacticColor(tactic);
          row.style.cursor = 'pointer';
          row.title = 'Click to add as filter (stay in overview) · Right-click for options';
          row.onclick = () => addTtpFilterKeepOverview(id);
        } else if (hasDetection) {
          cntEl.textContent = '0'; row.style.cursor = 'pointer';
          row.title = 'No hits in current data — click to search anyway';
          row.onclick = () => addTtpFilterKeepOverview(id);
        } else {
          cntEl.textContent = '—'; cntEl.title = 'No detection signature for CSV logs';
        }

        // Right-click: add as filter
        row.addEventListener('contextmenu', e => {
          e.preventDefault();
          if (hasDetection || count > 0) addTtpFilterKeepOverview(id);
        });

        row.appendChild(idEl); row.appendChild(nameEl); row.appendChild(cntEl);
        return row;
      };

      techs.forEach(tech => {
        const techCount = mitreResults[tech.id] || 0;
        const subs      = allSubtechs[tech.id] || [];
        const subHits   = subs.filter(s => mitreResults[s.id] > 0);
        // Only show parent if it has hits directly, or has sub-technique hits
        if (techCount > 0) {
          techList.appendChild(makeRow(tech.id, tech.name, techCount, true, false));
        }
        subHits.forEach(sub => {
          const subCount = mitreResults[sub.id] || 0;
          techList.appendChild(makeRow(sub.id, sub.name, subCount, true, true));
        });
      });

      tacticHdr.onclick = () => {
        const open = techList.style.display !== 'none';
        techList.style.display = open ? 'none' : 'block';
        tacticChevron.textContent = open ? '▸' : '▾';
      };

      section.appendChild(tacticHdr); section.appendChild(techList);
      body.appendChild(section);
      tacticSections.push({ section, techList, tacticChevron, tactic });
    });

    // When a tactic is active: hide all other sections, expand the matching one
    if (activeTactic) {
      expandAllBtn.style.display = 'none';
      collapseAllBtn.style.display = 'none';
      tacticSections.forEach(({ section, techList, tacticChevron, tactic }) => {
        if (tactic === activeTactic) {
          techList.style.display = 'block';
          tacticChevron.textContent = '▾';
        } else {
          section.style.display = 'none';
        }
      });
    }

    // Expand All / Collapse All
    expandAllBtn.onclick = e => {
      e.stopPropagation();
      tacticSections.forEach(({ techList, tacticChevron }) => {
        techList.style.display = 'block'; tacticChevron.textContent = '▾';
      });
    };
    collapseAllBtn.onclick = e => {
      e.stopPropagation();
      tacticSections.forEach(({ techList, tacticChevron }) => {
        techList.style.display = 'none'; tacticChevron.textContent = '▸';
      });
    };

    // Search handler — respects active tactic filter (won't re-show hidden sections)
    searchInput.oninput = () => {
      const q = searchInput.value.trim().toLowerCase();
      if (!q) {
        tacticSections.forEach(({ section, techList, tacticChevron, tactic }) => {
          if (activeTactic && tactic !== activeTactic) return; // keep hidden
          section.style.display = '';
          techList.querySelectorAll('.ov-ttp-tech-row,.ov-ttp-sub-row').forEach(r => r.style.display = '');
        });
        return;
      }
      tacticSections.forEach(({ section, techList, tacticChevron, tactic }) => {
        if (activeTactic && tactic !== activeTactic) return; // keep hidden
        let anyVisible = false;
        techList.querySelectorAll('.ov-ttp-tech-row,.ov-ttp-sub-row').forEach(r => {
          const match = (r.dataset.techId||'').toLowerCase().includes(q) || (r.dataset.techName||'').includes(q);
          r.style.display = match ? '' : 'none';
          if (match) anyVisible = true;
        });
        section.style.display = anyVisible ? '' : 'none';
        if (anyVisible) { techList.style.display = 'block'; tacticChevron.textContent = '▾'; }
      });
    };

    // Toggle card expand/collapse
    headerRow.onclick = () => {
      const open = body.style.display !== 'none';
      body.style.display = open ? 'none' : 'block';
      chevron.textContent = open ? '▸' : '▾';
    };

    wrapper.appendChild(body);
    return wrapper;
  }

  // Add TTP filter but STAY in overview — overview re-renders via applyFilter debounce
  function addTtpFilterKeepOverview(techId) {
    if (typeof MITRE_DETECTIONS === 'undefined' || !MITRE_DETECTIONS[techId]) return;
    // Auto-switch investigation profile to match technique or its parent tactic
    if (typeof TECHNIQUE_PROFILES !== 'undefined' && TECHNIQUE_PROFILES[techId]) {
      _ovProfile = techId;
    } else {
      const tech = typeof MITRE_TECHNIQUES !== 'undefined' ? MITRE_TECHNIQUES.find(t => t.id === techId) : null;
      if (tech && typeof TACTIC_PROFILES !== 'undefined' && TACTIC_PROFILES[tech.tactic]) _ovProfile = tech.tactic;
    }
    const fn   = MITRE_DETECTIONS[techId];
    const tech = typeof MITRE_TECHNIQUES !== 'undefined' ? MITRE_TECHNIQUES.find(t => t.id === techId) : null;
    const cols = [ptColMap.cmdline, ptColMap.fileName, ptColMap.initFile, ptColMap.filePath,
      ptColMap.remoteIp, ptColMap.remoteUrl, ptColMap.remotePort, ptColMap.regKey,
      ptColMap.action, ptColMap.initCmd].map(col => allRows.map(r => col ? (r[col]||'') : ''));
    const [c,f,fi,p,ri,ru,rp,rk,a,ic] = cols;
    const matchingSet = new Set(allRows.filter((row, i) => {
      try { return fn(c,f,fi,p,ri,ru,rp,rk,a,ic,i); } catch(e) { return false; }
    }));
    const id = ++filterRowCounter;
    filterRows.push({ id, col: '__TTP__', mode: 'ttp', value: techId,
      techName: tech ? tech.name : techId, tactic: tech ? tech.tactic : '',
      matchingSet, connector: 'AND' });
    renderFilterRows();
    document.getElementById('filterBar').classList.remove('hidden');
    applyFilter(); // triggers scheduleOverviewRender — overview stays open and re-renders
  }

  function filterFromOverview_mitre(techId) {
    if (typeof MITRE_DETECTIONS === 'undefined' || !MITRE_DETECTIONS[techId]) return;
    const fn   = MITRE_DETECTIONS[techId];
    const tech = typeof MITRE_TECHNIQUES !== 'undefined' ? MITRE_TECHNIQUES.find(t => t.id === techId) : null;

    // Build column arrays from allRows for the detection function
    const cols = [ptColMap.cmdline, ptColMap.fileName, ptColMap.initFile, ptColMap.filePath,
      ptColMap.remoteIp, ptColMap.remoteUrl, ptColMap.remotePort, ptColMap.regKey,
      ptColMap.action, ptColMap.initCmd].map(col => allRows.map(r => col ? (r[col]||'') : ''));
    const [c,f,fi,p,ri,ru,rp,rk,a,ic] = cols;

    // Build a Set of matching row references for O(1) lookup in applyFilter
    const matchingSet = new Set(allRows.filter((row, i) => {
      try { return fn(c,f,fi,p,ri,ru,rp,rk,a,ic,i); } catch(e) { return false; }
    }));

    if (!matchingSet.size) { alert('No matching rows for ' + techId + ' in current data.'); return; }

    // Close overview, add TTP filter row, apply
    overviewVisible = false; _killWorker();
    const panel = document.getElementById('overviewPanel');
    const btn   = document.getElementById('overviewBtn');
    if (panel) panel.style.display = 'none';
    document.getElementById('tableWrap').style.display = 'block';
    if (btn) btn.classList.remove('active');

    const id = ++filterRowCounter;
    filterRows.push({
      id, col: '__TTP__', mode: 'ttp',
      value: techId,
      techName: tech ? tech.name : techId,
      tactic: tech ? tech.tactic : '',
      matchingSet,
      connector: 'AND',
    });
    renderFilterRows();
    document.getElementById('filterBar').classList.remove('hidden');
    applyFilter();
  }

  function openMitreTechDetail(techId, mitreResults) {
    const tech = typeof MITRE_TECHNIQUES !== 'undefined' ? MITRE_TECHNIQUES.find(t => t.id === techId) : null;
    if (!tech) return;
    alert(techId + ' — ' + (tech ? tech.name : '') + '\nTactic: ' + (tech ? tech.tactic : '') + '\nDetected events: ' + (mitreResults[techId]||0).toLocaleString() + '\n\nClick OK then use the TTP Selector to filter the table.');
  }

  function tacticColor(tactic) {
    const map = {
      'Initial Access':        '#e05c3a',
      'Execution':             '#e07a3a',
      'Persistence':           '#c45ab3',
      'Privilege Escalation':  '#9b59b6',
      'Defense Evasion':       '#3a9fd6',
      'Credential Access':     '#e83e3e',
      'Discovery':             '#26a69a',
      'Lateral Movement':      '#f0a500',
      'Collection':            '#4caf80',
      'Command and Control':   '#f06292',
      'Exfiltration':          '#ff7043',
      'Impact':                '#b71c1c',
    };
    return map[tactic] || '#778F8D';
  }

  // ── Notable indicators card (collapsible, always shown) ──────────────────────
  function buildIndicatorsCard(indicators, s) {
    const card = document.createElement('div'); card.className = 'ov-card ov-card-full';
    const title = document.createElement('div'); title.className = 'ov-card-title'; title.style.cursor = 'pointer';
    title.textContent = 'Notable Indicators';
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    const profileDef = _ovGetProfileDef();
    const sortedNote = _ovProfile && indicators.length ? ` · sorted for ${profileDef.label}` : '';
    sub.textContent = indicators.length
      ? indicators.length + ' rule' + (indicators.length !== 1 ? 's' : '') + ' fired' + sortedNote
      : 'No suspicious patterns detected';
    const chevron = document.createElement('span');
    chevron.style.cssText = 'font-size:10px;color:var(--cb-os3);margin-left:8px';
    chevron.textContent = '▾';
    title.appendChild(sub); title.appendChild(chevron); card.appendChild(title);

    const body = document.createElement('div');

    if (!indicators.length) {
      const empty = document.createElement('div');
      empty.style.cssText = 'font-size:12px;color:var(--cb-muted);padding:8px 0';
      empty.textContent = 'No known attack patterns matched in the current dataset.';
      body.appendChild(empty);
    }

    const grid = document.createElement('div'); grid.className = 'ov-indicator-grid';
    indicators.forEach(ind => {
      const wrapper = document.createElement('div'); wrapper.className = 'ov-indicator-wrap';
      const chip = document.createElement('div'); chip.className = 'ov-indicator'; chip.dataset.sev = ind.sev; chip.style.cursor = 'pointer';
      const icon = document.createElement('span'); icon.className = 'ov-ind-icon'; icon.textContent = ind.icon;
      const indBody = document.createElement('div'); indBody.className = 'ov-ind-body';
      const ttl  = document.createElement('div'); ttl.className  = 'ov-ind-title'; ttl.textContent = ind.title;
      const cnt  = document.createElement('div'); cnt.className  = 'ov-ind-count';
      cnt.textContent = ind.count.toLocaleString()+' event'+(ind.count!==1?'s':'')+' — click to expand';
      const indChevron = document.createElement('span'); indChevron.className = 'ov-ind-chevron'; indChevron.textContent = '▸';
      indBody.appendChild(ttl); indBody.appendChild(cnt);
      chip.appendChild(icon); chip.appendChild(indBody); chip.appendChild(indChevron);
      chip.onclick = () => {
        const existing = wrapper.querySelector('.ov-ind-detail');
        if (existing) { existing.remove(); indChevron.textContent = '▸'; chip.classList.remove('ov-indicator-expanded'); }
        else { wrapper.appendChild(buildIndicatorDetail(ind)); indChevron.textContent = '▾'; chip.classList.add('ov-indicator-expanded'); }
      };
      wrapper.appendChild(chip);
      grid.appendChild(wrapper);
    });
    body.appendChild(grid);
    card.appendChild(body);

    // Title toggles body
    title.onclick = () => {
      const open = body.style.display !== 'none';
      body.style.display = open ? 'none' : 'block';
      chevron.textContent = open ? '▸' : '▾';
    };

    return card;
  }

  // ── Indicator detail panel ────────────────────────────────────────────────────
  function buildIndicatorDetail(ind) {
    const detail = document.createElement('div'); detail.className = 'ov-ind-detail';
    const det = ind.detail;

    if (det.devices && det.devices.length) addDetailSection(detail, 'Affected Devices', det.devices.map(([v,c])=>`${v} (${c})`).join('  ·  '));
    if (det.users   && det.users.length)   addDetailSection(detail, 'Accounts',         det.users.map(([v,c])=>`${v} (${c})`).join('  ·  '));

    if (det.timeRange) {
      const fmtShort = ms => new Date(ms).toLocaleString([], { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit' });
      const txt = det.timeRange.minTs === det.timeRange.maxTs
        ? fmtShort(det.timeRange.minTs)
        : `${fmtShort(det.timeRange.minTs)}  →  ${fmtShort(det.timeRange.maxTs)}`;
      addDetailSection(detail, 'Time Range', txt);
    }

    if (det.procChains && det.procChains.length) {
      addDetailSection(detail, 'Process Chains', det.procChains.map(([k,c])=>`${k} (${c})`).join('\n'));
    } else if (det.samples && det.samples.length) {
      const sec = document.createElement('div'); sec.className = 'ov-detail-section';
      const lbl = document.createElement('div'); lbl.className = 'ov-detail-label'; lbl.textContent = det.extraLabel || 'Sample Evidence';
      sec.appendChild(lbl);
      det.samples.forEach(sample => {
        const code = document.createElement('div'); code.className = 'ov-detail-sample';
        code.textContent = sample.length > 200 ? sample.slice(0,197)+'…' : sample;
        code.title = sample; code.style.cursor = 'context-menu';
        code.addEventListener('contextmenu', e => { e.preventDefault(); if (typeof openCellMenu==='function') openCellMenu(e, ind.filterCol, sample, null); });
        sec.appendChild(code);
      });
      detail.appendChild(sec);
    }

    const actions = document.createElement('div'); actions.className = 'ov-detail-actions';
    const filterBtn = document.createElement('button'); filterBtn.className = 'ov-detail-filter-btn';
    filterBtn.textContent = `→ View all ${ind.count.toLocaleString()} rows in table`;
    filterBtn.onclick = e => { e.stopPropagation(); filterFromOverview(ind.filterCol, ind.filterVal, ind.filterMode); };
    actions.appendChild(filterBtn);
    detail.appendChild(actions);
    return detail;
  }

  // ── Shared list helpers ───────────────────────────────────────────────────────
  const OV_CAP = 100;

  function ovRow(col, val, labelHtml, countText) {
    const row = document.createElement('div'); row.className = 'ov-list-row'; row.style.cursor = 'pointer';
    row.title = 'Left-click to filter · Right-click for options';
    row.onclick = () => filterFromOverview(col, val);
    row.addEventListener('contextmenu', e => { e.preventDefault(); if (typeof openCellMenu==='function') openCellMenu(e, col, val, null); });
    const lbl = document.createElement('span'); lbl.className = 'ov-list-label';
    if (typeof labelHtml === 'string' && labelHtml.includes('<')) lbl.innerHTML = labelHtml;
    else lbl.textContent = labelHtml;
    row.appendChild(lbl);
    if (countText !== undefined) {
      const cnt = document.createElement('span'); cnt.className = 'ov-list-count'; cnt.textContent = countText;
      row.appendChild(cnt);
    }
    return row;
  }

  function ovScrollList(entries, renderFn) {
    const wrap = document.createElement('div'); wrap.className = 'ov-card-list';
    entries.slice(0, OV_CAP).forEach(e => { const el = renderFn(e); if (el) wrap.appendChild(el); });
    if (entries.length > OV_CAP) {
      const more = document.createElement('div'); more.className = 'ov-list-more';
      more.textContent = `…and ${(entries.length-OV_CAP).toLocaleString()} more`;
      wrap.appendChild(more);
    }
    // Track which list the mouse is over for typeahead
    wrap.addEventListener('mouseenter', () => { _ovHoveredList = wrap; _ovHoveredRegion = 'list'; });
    wrap.addEventListener('mouseleave', () => { if (_ovHoveredList === wrap) _ovHoveredList = null; });
    return wrap;
  }

  // Append capped rows directly to an existing area (for chart-toggle cards
  // that re-render in place and can't use ovScrollList's wrapper)
  function _appendCappedRows(area, entries, makeRow) {
    entries.slice(0, OV_CAP).forEach(e => { const el = makeRow(e); if (el) area.appendChild(el); });
    if (entries.length > OV_CAP) {
      const more = document.createElement('div'); more.className = 'ov-list-more';
      more.textContent = `…and ${(entries.length-OV_CAP).toLocaleString()} more`;
      area.appendChild(more);
    }
  }

  // ── Card: custom pinned field ─────────────────────────────────────────────────
  function buildCustomFieldCard(colName, rows) {
    const counts = {};
    rows.forEach(row => { const v = (row[colName]||'').trim(); if (v) counts[v] = (counts[v]||0)+1; });
    const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,25);
    if (!sorted.length) return null;
    const card = document.createElement('div'); card.className = 'ov-card'; card.style.position = 'relative';
    const title = document.createElement('div'); title.className = 'ov-card-title'; title.style.paddingRight = '24px';
    const short = colName.length > 32 ? '…'+colName.slice(-30) : colName;
    title.textContent = short; title.title = colName;
    const sub = document.createElement('span'); sub.className = 'ov-card-sub';
    sub.textContent = Object.keys(counts).length.toLocaleString()+' unique'; title.appendChild(sub);
    card.appendChild(title);
    card.appendChild(ovScrollList(sorted, ([val,count]) => ovRow(colName, val, val, count.toLocaleString())));
    return card;
  }

  // ── Custom profile builder modal ──────────────────────────────────────────────
  function _openCustomProfileBuilder(profileBtn) {
    // Remove any existing builder
    const existing = document.getElementById('sift-cpb-modal');
    if (existing) existing.remove();

    const initial = _ovCustomActive || { name: '', cards: ['hostsAccounts','activity','process','procPairs','network','time'], customFields: [] };

    const overlay = document.createElement('div'); overlay.id = 'sift-cpb-modal';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:600;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(3px)';
    overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

    const box = document.createElement('div');
    box.style.cssText = 'background:var(--modal-bg);border:1px solid var(--cb-yellow);border-radius:10px;width:520px;max-width:95vw;max-height:85vh;display:flex;flex-direction:column;box-shadow:0 24px 64px rgba(0,0,0,0.7)';

    // Header
    const hdr = document.createElement('div');
    hdr.style.cssText = 'display:flex;align-items:center;padding:14px 18px;border-bottom:1px solid var(--cb-os1);background:var(--cb-dark);border-radius:10px 10px 0 0';
    const hdrTitle = document.createElement('span');
    hdrTitle.style.cssText = 'font-size:14px;font-weight:700;color:var(--cb-yellow-text)';
    hdrTitle.textContent = '⭐ Custom Profile Builder';
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕'; closeBtn.style.cssText = 'margin-left:auto;background:none;border:none;color:var(--cb-muted);font-size:15px;cursor:pointer;padding:0 4px';
    closeBtn.onclick = () => overlay.remove();
    hdr.appendChild(hdrTitle); hdr.appendChild(closeBtn);
    box.appendChild(hdr);

    // Body
    const body = document.createElement('div');
    body.style.cssText = 'overflow-y:auto;padding:18px;display:flex;flex-direction:column;gap:18px;flex:1';

    // ── Section 1: Standard cards ──
    const sec1 = document.createElement('div');
    const sec1Hdr = document.createElement('div'); sec1Hdr.style.cssText = 'font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--cb-muted);margin-bottom:10px';
    sec1Hdr.textContent = 'Standard Cards — select and order'; sec1.appendChild(sec1Hdr);

    const sub1 = document.createElement('div'); sub1.style.cssText = 'font-size:10px;color:var(--cb-muted);margin-bottom:10px';
    sub1.textContent = 'First 4 checked = primary row (top) · rest = secondary rows below'; sec1.appendChild(sub1);

    let selectedCards = [...(initial.cards || [])];

    const cardGrid = document.createElement('div');
    cardGrid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:6px';

    const rebuildGrid = () => {
      cardGrid.innerHTML = '';
      // Show checked first (in order), then unchecked
      const checked   = selectedCards.filter(k => CARD_DEFS.find(d => d.key === k));
      const unchecked = CARD_DEFS.filter(d => !selectedCards.includes(d.key));
      const ordered   = [...checked.map(k => CARD_DEFS.find(d => d.key === k)), ...unchecked];

      ordered.forEach((def, idx) => {
        const isChecked = selectedCards.includes(def.key);
        const pos = isChecked ? selectedCards.indexOf(def.key) + 1 : null;

        const item = document.createElement('div');
        item.style.cssText = `display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:6px;cursor:pointer;border:1px solid ${isChecked ? 'rgba(255,215,0,0.4)' : 'var(--cb-os1)'};background:${isChecked ? 'rgba(255,215,0,0.06)' : 'transparent'};transition:all .15s`;
        item.onmouseover = () => { if (!isChecked) item.style.background = 'rgba(255,255,255,0.04)'; };
        item.onmouseout  = () => { if (!isChecked) item.style.background = 'transparent'; };

        if (pos) {
          const badge = document.createElement('span');
          badge.style.cssText = `font-size:9px;font-weight:700;background:${pos <= 4 ? 'rgba(255,215,0,0.2)' : 'rgba(100,100,100,0.2)'};color:${pos <= 4 ? 'var(--cb-yellow)' : 'var(--cb-muted)'};padding:1px 5px;border-radius:3px;min-width:18px;text-align:center;flex-shrink:0`;
          badge.textContent = pos <= 4 ? 'P'+pos : 'S'+(pos-4);
          item.appendChild(badge);
        } else {
          const spacer = document.createElement('span'); spacer.style.cssText = 'width:24px;flex-shrink:0'; item.appendChild(spacer);
        }

        const lbl = document.createElement('div'); lbl.style.cssText = 'flex:1;min-width:0';
        const name = document.createElement('div'); name.style.cssText = `font-size:11px;font-weight:600;color:${isChecked ? 'var(--modal-text)' : 'var(--cb-muted)'}`;
        name.textContent = def.label;
        const desc = document.createElement('div'); desc.style.cssText = 'font-size:9px;color:var(--cb-muted);margin-top:1px'; desc.textContent = def.desc;
        lbl.appendChild(name); lbl.appendChild(desc); item.appendChild(lbl);

        if (isChecked) {
          const mv = document.createElement('span'); mv.style.cssText = 'font-size:11px;color:var(--cb-muted);cursor:pointer;flex-shrink:0;padding:0 2px';
          mv.textContent = '↑↓'; mv.title = 'Move up/down';
          mv.onclick = e => {
            e.stopPropagation();
            const i = selectedCards.indexOf(def.key);
            if (i > 0) { selectedCards.splice(i,1); selectedCards.splice(i-1,0,def.key); rebuildGrid(); }
          };
          item.appendChild(mv);
        }

        item.onclick = () => {
          if (selectedCards.includes(def.key)) selectedCards = selectedCards.filter(k => k !== def.key);
          else selectedCards.push(def.key);
          rebuildGrid();
        };

        cardGrid.appendChild(item);
      });
    };
    rebuildGrid();
    sec1.appendChild(cardGrid);
    body.appendChild(sec1);

    // ── Section 2: Custom field cards ──
    const sec2 = document.createElement('div');
    const sec2Hdr = document.createElement('div'); sec2Hdr.style.cssText = 'font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--cb-muted);margin-bottom:6px';
    sec2Hdr.textContent = 'Column Cards — pin any column from your file'; sec2.appendChild(sec2Hdr);

    const sec2Sub = document.createElement('div'); sec2Sub.style.cssText = 'font-size:10px;color:var(--cb-muted);margin-bottom:10px';
    sec2Sub.textContent = 'Each selected column appears as a frequency card in the overview — click any value to filter.'; sec2.appendChild(sec2Sub);

    let customFields = [...(initial.customFields || [])];

    // Search input — always visible
    const fpSearch = document.createElement('input'); fpSearch.type = 'text'; fpSearch.placeholder = 'Search columns…';
    fpSearch.style.cssText = 'width:100%;box-sizing:border-box;padding:5px 9px;background:rgba(0,0,0,0.12);border:1px solid var(--cb-os1);border-radius:4px;color:var(--cb-text-inverse);font-size:11px;outline:none;margin-bottom:6px';
    sec2.appendChild(fpSearch);

    // Always-visible scrollable checklist of all CSV columns
    const fpList = document.createElement('div');
    fpList.style.cssText = 'overflow-y:auto;max-height:200px;border:1px solid var(--cb-os1);border-radius:6px;background:var(--modal-section)';

    const buildFpList = (filter) => {
      fpList.innerHTML = '';
      const allCols = (typeof headers !== 'undefined' ? headers : []).filter(h => h && h.trim());
      const filtered = filter ? allCols.filter(h => h.toLowerCase().includes(filter.toLowerCase())) : allCols;
      if (!filtered.length) {
        const empty = document.createElement('div'); empty.style.cssText = 'font-size:11px;color:var(--cb-muted);padding:10px 12px';
        empty.textContent = allCols.length ? 'No columns match' : 'No file loaded yet'; fpList.appendChild(empty); return;
      }
      filtered.forEach(col => {
        const already = customFields.includes(col);
        const row = document.createElement('div');
        row.style.cssText = `display:flex;align-items:center;gap:8px;padding:6px 12px;cursor:pointer;border-bottom:1px solid rgba(0,0,0,0.05);transition:background 0.1s;background:${already ? 'rgba(255,215,0,0.07)' : 'transparent'}`;
        row.onmouseover = () => { if (!already) row.style.background = 'rgba(255,255,255,0.04)'; };
        row.onmouseout  = () => { row.style.background = already ? 'rgba(255,215,0,0.07)' : 'transparent'; };

        const chk = document.createElement('span');
        chk.style.cssText = `width:14px;height:14px;border-radius:3px;border:1px solid ${already ? 'var(--cb-yellow-text)' : 'var(--cb-os1)'};background:${already ? 'var(--cb-yellow-text)' : 'transparent'};display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:9px;color:var(--modal-bg)`;
        chk.textContent = already ? '✓' : '';

        const lbl = document.createElement('span');
        lbl.style.cssText = `flex:1;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:${already ? 'var(--modal-text)' : 'var(--cb-muted)'}`;
        lbl.textContent = col; lbl.title = col;
        lbl.style.fontWeight = already ? '600' : '400';

        row.appendChild(chk); row.appendChild(lbl);
        row.onclick = () => {
          if (customFields.includes(col)) customFields = customFields.filter(f => f !== col);
          else customFields.push(col);
          buildFpList(fpSearch.value);
        };
        fpList.appendChild(row);
      });
    };

    buildFpList('');
    fpSearch.oninput = () => buildFpList(fpSearch.value);
    sec2.appendChild(fpList);
    body.appendChild(sec2);
    box.appendChild(body);

    // Footer
    const footer = document.createElement('div');
    footer.style.cssText = 'display:flex;align-items:center;gap:8px;padding:12px 18px;border-top:1px solid var(--cb-os1);background:var(--cb-dark);border-radius:0 0 10px 10px;flex-wrap:wrap';

    const nameInput = document.createElement('input'); nameInput.type='text'; nameInput.placeholder='Profile name…';
    nameInput.value = initial.name || '';
    nameInput.style.cssText = 'flex:1;min-width:120px;padding:5px 9px;background:rgba(0,0,0,0.3);border:1px solid var(--cb-os1);border-radius:4px;color:var(--cb-text-inverse);font-size:11px;outline:none';

    const saveBtn = document.createElement('button'); saveBtn.textContent = '💾 Save';
    saveBtn.style.cssText = 'font-size:11px;padding:5px 12px;background:rgba(255,215,0,0.15);border:1px solid var(--cb-yellow);border-radius:4px;color:var(--cb-yellow);cursor:pointer;font-weight:700';
    saveBtn.onclick = () => {
      const name = nameInput.value.trim();
      if (!name) { nameInput.style.borderColor='#e83e3e'; setTimeout(()=>nameInput.style.borderColor='',1500); return; }
      const profile = { name, cards: selectedCards, customFields };
      _cpSave(profile);
      _ovCustomActive = profile; _ovProfile = null;
      profileBtn.innerHTML = `⭐ <span>Investigating: <strong>${name}</strong></span> ▾`;
      overlay.remove();
      scheduleOverviewRender();
    };

    const applyBtn = document.createElement('button'); applyBtn.textContent = '✓ Apply';
    applyBtn.style.cssText = 'font-size:11px;padding:5px 12px;background:transparent;border:1px solid var(--cb-os1);border-radius:4px;color:var(--cb-text-inverse);cursor:pointer';
    applyBtn.onclick = () => {
      const name = nameInput.value.trim() || 'Custom';
      _ovCustomActive = { name, cards: selectedCards, customFields };
      _ovProfile = null;
      profileBtn.innerHTML = `⭐ <span>Investigating: <strong>${name}</strong></span> ▾`;
      overlay.remove();
      scheduleOverviewRender();
    };

    const cancelBtn = document.createElement('button'); cancelBtn.textContent = 'Cancel';
    cancelBtn.style.cssText = 'font-size:11px;padding:5px 10px;background:none;border:none;color:var(--cb-muted);cursor:pointer';
    cancelBtn.onclick = () => overlay.remove();

    footer.appendChild(nameInput); footer.appendChild(saveBtn); footer.appendChild(applyBtn); footer.appendChild(cancelBtn);
    box.appendChild(footer);
    overlay.appendChild(box);
    document.body.appendChild(overlay);
  }

  // ── Generic card builder ──────────────────────────────────────────────────────
  function buildCard(titleText, items) {
    const card = document.createElement('div'); card.className = 'ov-card';
    const title = document.createElement('div'); title.className = 'ov-card-title'; title.textContent = titleText;
    card.appendChild(title);
    items.forEach(item => {
      if (!item.label && !item.value) return;
      const row = document.createElement('div'); row.className = item.sub ? 'ov-kv-sub' : 'ov-kv';
      if (item.label) { const lbl = document.createElement('span'); lbl.className = 'ov-kv-label'; lbl.textContent = item.label; row.appendChild(lbl); }
      const val = document.createElement('span'); val.className = 'ov-kv-value'+(item.highlight?' ov-kv-highlight':'');
      if (item.dot) { const dot = document.createElement('span'); dot.style.cssText = `display:inline-block;width:8px;height:8px;border-radius:50%;background:${item.dot};margin-right:5px;flex-shrink:0`; val.appendChild(dot); }
      val.appendChild(document.createTextNode(item.value));
      row.appendChild(val); card.appendChild(row);
    });
    return card;
  }

  // ── Filter from overview — stays in overview, cards update live ──────────────
  function filterFromOverview(col, val, mode) {
    const m = mode || 'contains';
    // If col is undefined (column not mapped for this data source) fall back to
    // all-columns search so the filter still does something meaningful
    const effectiveCol = col || '';
    const already = (filterRows || []).some(r => r.col === effectiveCol && r.value === val && r.mode === m);
    if (already) return;
    const id = ++filterRowCounter;
    filterRows.push({ id, col: effectiveCol, mode: m, value: val, connector: 'AND' });
    renderFilterRows();
    document.getElementById('filterBar').classList.remove('hidden');
    applyFilter();
  }

  // ── Active filter summary for the header strip ────────────────────────────────
  function ovGetActiveFilters() {
    const list = [];
    // Text / regex / TTP filter rows
    (filterRows || []).filter(r => r.value && r.value.trim()).forEach(r => {
      const shortLabel = r.mode === 'ttp'
        ? `🎯 ${r.value}`
        : (r.col ? r.col.split(/[\s_]/).pop() : 'All') + ': ' + (r.value.length > 18 ? r.value.slice(0,16)+'…' : r.value);
      const label = r.mode === 'ttp'
        ? `TTP: ${r.value} · ${r.techName || ''}`
        : `${r.col || 'All columns'}: "${r.value}" (${r.mode})`;
      list.push({ shortLabel, label, remove: () => {
        filterRows = filterRows.filter(fr => fr.id !== r.id);
        renderFilterRows();
        applyFilter();
      }});
    });
    // Column value filters
    Object.entries(columnFilters || {}).filter(([,v]) => v !== null).forEach(([col, allowed]) => {
      const colShort = col.split(/[\s_]/).pop();
      list.push({
        shortLabel: `${colShort}: ${allowed.size} val${allowed.size !== 1 ? 's' : ''}`,
        label: `Column filter: ${col} (${allowed.size} values selected)`,
        remove: () => { columnFilters[col] = null; applyFilter(); renderColFilterChips(); }
      });
    });
    // Timestamp range
    const tsFrom = document.getElementById('tsFrom')?.value;
    const tsTo   = document.getElementById('tsTo')?.value;
    if (tsFrom || tsTo) {
      const fmt = v => v ? v.replace('T',' ').slice(0,16) : '…';
      list.push({
        shortLabel: `⏱ ${fmt(tsFrom)} → ${fmt(tsTo)}`,
        label: `Time range: ${fmt(tsFrom)} to ${fmt(tsTo)}`,
        remove: () => {
          document.getElementById('tsFrom').value = '';
          document.getElementById('tsTo').value = '';
          applyFilter();
        }
      });
    }
    return list;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────────
  function addDetailSection(parent, label, text) {
    const sec = document.createElement('div'); sec.className = 'ov-detail-section';
    const lbl = document.createElement('div'); lbl.className = 'ov-detail-label'; lbl.textContent = label;
    const val = document.createElement('div'); val.className = 'ov-detail-value'; val.textContent = text;
    sec.appendChild(lbl); sec.appendChild(val); parent.appendChild(sec);
  }

  function portService(port) {
    const p = parseInt(port,10);
    const map = { 80:'HTTP',443:'HTTPS',22:'SSH',21:'FTP',25:'SMTP',53:'DNS',3389:'RDP',445:'SMB',135:'RPC',3306:'MySQL',8080:'HTTP-Alt',8443:'HTTPS-Alt',1433:'MSSQL',4444:'Meterpreter',5985:'WinRM',5986:'WinRM-S' };
    return map[p] ? ' · '+map[p] : '';
  }

  function actionColor(action) {
    const a = (action||'').toLowerCase();
    if (a.includes('process'))  return '#e05c3a';
    if (a.includes('network') || a.includes('connection')) return '#3a9fd6';
    if (a.includes('file'))     return '#c45ab3';
    if (a.includes('registry')) return '#f0a500';
    if (a.includes('logon') || a.includes('login')) return '#f06292';
    if (a.includes('dns'))      return '#26a69a';
    return null;
  }

  // Fallback if worker fails — thin synchronous version (no indicators)
  function _computeFallback(rows) {
    if (!Object.keys(ptColMap).length) ptResolveColumns(headers);
    return { s: { actionCol: ptColMap.action||'', fileCol: ptColMap.fileName||'', remoteIpCol: ptColMap.remoteIp||'', cmdCol: ptColMap.cmdline||'' }, rowCount: rows.length, indicators: [] };
  }
