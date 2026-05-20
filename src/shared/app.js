// app.js — Core application: state, tabs, CSV parsing, filtering, rendering

// ── State ──
  var HIGHLIGHT_STORAGE_KEY = 'csv-viewer-highlights';
  var FILTER_LOCK_STORAGE_KEY = 'csv-viewer-filter-locked';
  var SIDEBAR_TOP_ADJUST_KEY = 'csv-viewer-sidebar-top-adjust';
  var GLOBAL_MODE_KEY = 'csv-viewer-global-mode';
  var globalMode = false;
 
  // ── Tab Management ──
  var tabs = [];        // [{name, rawText, records, headers, parsed: bool}]
  var activeTabIndex = -1;
  var filterLocked = false;
  var lockedFilter = null; // saved when locked, reapplied to new tabs
  var sidebarTopBasePx = null;
  var sidebarTopAdjustPx = 0;
 
  // Shorthand for active tab
  function activeTab() {
    return activeTabIndex >= 0 && activeTabIndex < tabs.length ? tabs[activeTabIndex] : null;
  }
 
  var allRows   = [];   // raw parsed rows [{col:val,...}] (kept in sync with activeTab)
  var headers   = [];
  var hiddenCols = new Set();
  var sortCol   = null;
  var sortDir   = 1;    // 1 asc, -1 desc
  var tags      = [];   // [{term, colour}]
  var hlOnly    = false;
 
  // ── Filter Row State ──
  var filterRows        = []; // [{id, col, mode, value, connector}]
  var filterRowCounter  = 0;
 
  // ── Timestamp & Modal State ──
  var visibleRows   = [];   // all filtered+sorted rows (for modal prev/next)
  var modalRowIdx   = 0;
  var timestampCols = [];   // auto-detected timestamp column names
  var detailViewMode = 'sidebar'; // 'modal' | 'sidebar'
  var allFieldsExpanded = true;
  var fieldExpandOverrides = {};
 
  // ── Pagination State ──
  var currentPage = 1;
  var filteredSorted = []; // full filtered+sorted set, sliced for display
 
  // ── Column Value Filter State ──
  var columnFilters = {};  // { colName: Set<string> | null }  null = no filter
  var cpCol = null;        // column currently open in picker
  var cpAllValues = [];    // [{val, count}] for current picker column
  var cpPending = null;    // Set<string> being edited in picker (null = all)
  var cpSortMode = 'count-desc'; // 'count-desc' | 'count-asc' | 'val-asc' | 'val-desc'
  var saveHighlightsTimer = null;
 
  // ── Debounce ──
  var filterTimer = null;
  function scheduleFilter() {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(applyFilter, 220);
  }

  // ── Performance caches ──
  var _lastHeadKey  = '';   // detects when thead needs rebuild
  var _chartRafId   = null; // requestAnimationFrame id for deferred chart render

  // Coalesce timeline+bytes redraws into one RAF frame
  function scheduleChartRender() {
    if (_chartRafId !== null) return;
    _chartRafId = requestAnimationFrame(function() {
      _chartRafId = null;
      if (timelineVisible) renderTimeline();
      if (bytesVisible)    renderBytesChart();
    });
  }
 
  // Pre-loaded TH highlight terms
  var defaultTags = [
    { term: 'powershell',  colour: 'hl-red'    },
    { term: 'encoded',     colour: 'hl-red'    },
    { term: 'base64',      colour: 'hl-red'    },
    { term: 'mimikatz',    colour: 'hl-red'    },
    { term: 'rundll32',    colour: 'hl-orange' },
    { term: 'certutil',    colour: 'hl-yellow' },
    { term: 'mshta',       colour: 'hl-orange' },
  ];
 
  // ── Theme (light/dark toggle) ──
  var THEME_STORAGE_KEY = 'csv-viewer-theme';

  function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem(THEME_STORAGE_KEY); } catch(e) {}
    var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    var isDark = saved ? (saved === 'dark') : prefersDark;
    applyTheme(isDark);
  }

  function applyTheme(isDark) {
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
    var toggle = document.getElementById('themeToggle');
    var label  = document.getElementById('themeToggleLabel');
    if (toggle) toggle.classList.toggle('is-dark', isDark);
    if (label)  label.textContent = isDark ? 'Dark' : 'Light';
    try { localStorage.setItem(THEME_STORAGE_KEY, isDark ? 'dark' : 'light'); } catch(e) {}
  }

  function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme');
    applyTheme(current !== 'dark');
  }

  // ── Init ──
  window.onload = function() {
    initTheme();
    try {
      var gm = localStorage.getItem(GLOBAL_MODE_KEY);
      if (gm !== null) globalMode = JSON.parse(gm);
    } catch(e) {}
    var gmCb = document.getElementById('globalModeCheckbox');
    if (gmCb) gmCb.checked = globalMode;
    updateGlobalModeText(globalMode);
    loadHighlights();
    loadFilterLockState();
    loadSidebarTopAdjust();
    setDetailViewMode('sidebar');
    setAllFieldExpandState(true);
    updateSidebarTopOffset();

    // Verify FileReader is available (blocked in some corporate browsers)
    if (typeof FileReader === 'undefined') {
      var dz = document.getElementById('dropZone');
      if (dz) dz.innerHTML = '<div style="color:#e83e3e;font-size:14px;padding:20px;text-align:center">⚠ Your browser blocks file access.<br>Try opening this in Chrome or Edge.</div>';
    }
  };
 
  window.addEventListener('resize', updateSidebarTopOffset);
 
  function loadSidebarTopAdjust() {
    try {
      const raw = localStorage.getItem(SIDEBAR_TOP_ADJUST_KEY);
      if (raw !== null) {
        const n = parseInt(raw, 10);
        if (!Number.isNaN(n)) sidebarTopAdjustPx = n;
      }
    } catch {}
  }
 
  function saveSidebarTopAdjust() {
    try { localStorage.setItem(SIDEBAR_TOP_ADJUST_KEY, String(sidebarTopAdjustPx)); } catch {}
  }
 
  function updateSidebarTopOffset(forceRebase = false) {
    const tableWrap = document.getElementById('tableWrap');
    if (!tableWrap) return;
 
    const wrapVisible = tableWrap.offsetParent !== null && getComputedStyle(tableWrap).display !== 'none';
    if (wrapVisible) {
      const rect = tableWrap.getBoundingClientRect();
      const head = document.getElementById('csvHead');
      const headHeight = head ? Math.max(28, Math.round(head.getBoundingClientRect().height || 0)) : 34;
      if (forceRebase || sidebarTopBasePx === null) {
        // Align under CSV column header row so sticky headers remain visible.
        sidebarTopBasePx = Math.max(80, Math.round(rect.top + headHeight));
      }
    } else if (sidebarTopBasePx === null) {
      // Fallback before first dataset render; do not lock base yet.
      const fallbackTop = Math.max(60, 180 + sidebarTopAdjustPx);
      document.documentElement.style.setProperty('--row-sidebar-top', `${fallbackTop}px`);
      return;
    }
 
    const minTop = 60;
    // Allow shrinking sidebar down close to one field-height.
    const minSidebarHeight = 72;
    const maxTop = Math.max(minTop, window.innerHeight - minSidebarHeight);
    const rawTop = (sidebarTopBasePx || 180) + sidebarTopAdjustPx;
    const topPx = Math.max(minTop, Math.min(maxTop, rawTop));
    document.documentElement.style.setProperty('--row-sidebar-top', `${topPx}px`);
  }
 
  function adjustSidebarTop(delta) {
    sidebarTopAdjustPx = Math.max(-2000, Math.min(2000, sidebarTopAdjustPx + delta));
    saveSidebarTopAdjust();
    updateSidebarTopOffset(false);
  }
 
  function resetSidebarTop() {
    sidebarTopAdjustPx = 0;
    saveSidebarTopAdjust();
    updateSidebarTopOffset(true);
  }
 
  function startSidebarTopDrag(e) {
    e.preventDefault();
    const handle = document.getElementById('rowSidebarTopHandle');
    if (!handle) return;
 
    handle.classList.add('dragging');
    const startY = e.clientY;
    const startAdjust = sidebarTopAdjustPx;
 
    const onMove = (ev) => {
      const delta = ev.clientY - startY;
      sidebarTopAdjustPx = Math.max(-2000, Math.min(2000, startAdjust + delta));
      updateSidebarTopOffset(false);
    };
 
    const onUp = () => {
      handle.classList.remove('dragging');
      saveSidebarTopAdjust();
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
 
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }
 
  function startSidebarResize(e) {
    e.preventDefault();
    const sidebar = document.getElementById('rowSidebar');
    if (!sidebar) return;
 
    sidebar.classList.add('resizing');
    const startX = e.clientX;
    const startWidth = sidebar.getBoundingClientRect().width;
    const minWidth = 420;
 
    const onMove = (ev) => {
      const maxWidth = Math.max(minWidth, window.innerWidth - 120);
      let nextWidth = startWidth + (startX - ev.clientX);
      nextWidth = Math.max(minWidth, Math.min(maxWidth, nextWidth));
      document.documentElement.style.setProperty('--row-sidebar-width', `${Math.round(nextWidth)}px`);
    };
 
    const onUp = () => {
      sidebar.classList.remove('resizing');
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
 
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }
 
  // ── Drag & Drop ──
  function onDragOver(e)  { e.preventDefault(); document.getElementById('dropZone').classList.add('drag-over'); }
  function onDragLeave(e) { document.getElementById('dropZone').classList.remove('drag-over'); }
  function onDrop(e) {
    e.preventDefault();
    document.getElementById('dropZone').classList.remove('drag-over');
    try {
      var files = e.dataTransfer ? e.dataTransfer.files : null;
      if (!files || !files.length) return;
      var fileArr = [];
      for (var i = 0; i < files.length; i++) fileArr.push(files[i]);
      var evtxEnabled = typeof SIFT_FEATURES !== 'undefined' && SIFT_FEATURES.evtx;
      var invalid = fileArr.filter(function(f) {
        var n = f.name.toLowerCase();
        return !n.endsWith('.csv') && !(evtxEnabled && n.endsWith('.evtx'));
      });
      if (invalid.length) {
        alert(evtxEnabled ? 'Supported formats: .csv and .evtx (Windows Event Log)' : 'Supported format: .csv');
        return;
      }
      loadFiles(fileArr);
    } catch(err) {
      alert('Drop error: ' + err.message);
    }
  }
 
  // ── Tab Management ──
  function loadFiles(fileList) {
    if (!fileList || fileList.length === 0) return;
    var validFiles = [];
    for (var fi = 0; fi < fileList.length; fi++) {
      var n = fileList[fi].name.toLowerCase();
      var _evtxOk = typeof SIFT_FEATURES !== 'undefined' && SIFT_FEATURES.evtx;
      if (n.endsWith('.csv') || (_evtxOk && n.endsWith('.evtx'))) validFiles.push(fileList[fi]);
    }
    if (validFiles.length === 0) return;

    for (var fi2 = 0; fi2 < validFiles.length; fi2++) {
      (function(file) {
        var isEvtx = (typeof SIFT_FEATURES !== 'undefined' && SIFT_FEATURES.evtx) && file.name.toLowerCase().endsWith('.evtx');
        var reader = new FileReader();
        reader.onerror = function() {
          alert('Could not read "' + file.name + '".\nYour browser may be blocking local file access.\nTry Chrome or Edge.');
        };

        if (isEvtx) {
          // ── .evtx binary parsing ──────────────────────────────────────
          reader.onload = function(e) {
            if (typeof EVTXParser === 'undefined') {
              alert('evtx-parser.js not loaded — make sure all files are in the same folder.');
              return;
            }
            showLoading('Parsing ' + file.name + '…');
            setTimeout(function() {
              try {
                var evtxRows = EVTXParser.parseFile(e.target.result);
                if (!evtxRows.length) { hideLoading(); alert('No events found in ' + file.name); return; }
                var evtxHeaders = EVTXParser.getHeaders(evtxRows);
                var tabName = file.name.replace(/\.evtx$/i, '').slice(0, 22);
                var tabObj = {
                  name: tabName,
                  rawText: null,
                  records: null,
                  headers: evtxHeaders,
                  allRows: evtxRows,
                  parsed: true,  // already parsed by EVTXParser
                  isEvtx: true,
                  sortCol: null, sortDir: 1,
                  filterRows: [],
                  columnFilters: {},
                  currentPage: 1,
                  filteredSorted: [],
                  visibleRows: [],
                  modalRowIdx: 0,
                  filterEnabled: true,
                  tsFrom: '', tsTo: '', tsCol: '',
                  tags: tags.slice(),
                };
                var curTab = activeTabIndex >= 0 && activeTabIndex < tabs.length ? tabs[activeTabIndex] : null;
                if (curTab && curTab.blank) {
                  tabs[activeTabIndex] = tabObj;
                  document.getElementById('tabBar').innerHTML = '';
                  switchTab(activeTabIndex);
                } else {
                  tabs.push(tabObj);
                  document.getElementById('tabBar').innerHTML = '';
                  switchTab(activeTabIndex === -1 ? 0 : tabs.length - 1);
                }
                document.getElementById('dropZone').style.display = 'none';
                document.getElementById('tableWrap').style.display = 'block';
                document.getElementById('tabBar').classList.remove('hidden');
                document.getElementById('btnExport').style.display = '';
                hideLoading();
              } catch(err) {
                hideLoading();
                alert('Error parsing .evtx file: ' + err.message);
              }
            }, 0);
          };
          reader.readAsArrayBuffer(file);

        } else {
          // ── .csv text parsing (existing flow) ────────────────────────
          reader.onload = function(e) {
            var tabName = file.name.replace(/\.csv$/i, '').slice(0, 20);
            var tabObj = {
              name: tabName,
              rawText: e.target.result,
              records: null,
              headers: [],
              allRows: [],
              parsed: false,
              sortCol: null, sortDir: 1,
              filterRows: [],
              columnFilters: {},
              currentPage: 1,
              filteredSorted: [],
              visibleRows: [],
              modalRowIdx: 0,
              filterEnabled: true,
              tsFrom: '', tsTo: '', tsCol: '',
              tags: tags.slice(),
            };
            var curTab = activeTabIndex >= 0 && activeTabIndex < tabs.length ? tabs[activeTabIndex] : null;
            if (curTab && curTab.blank) {
              tabs[activeTabIndex] = tabObj;
              document.getElementById('tabBar').innerHTML = '';
              switchTab(activeTabIndex);
            } else {
              tabs.push(tabObj);
              document.getElementById('tabBar').innerHTML = '';
              switchTab(activeTabIndex === -1 ? 0 : tabs.length - 1);
            }
            document.getElementById('dropZone').style.display = 'none';
            document.getElementById('tableWrap').style.display = 'block';
            document.getElementById('tabBar').classList.remove('hidden');
            document.getElementById('btnExport').style.display = '';
          };
          reader.readAsText(file, 'UTF-8');
        }
      })(validFiles[fi2]);
    }
  }
 
  function switchTab(idx) {
    if (idx < 0 || idx >= tabs.length) return;

    // Auto-collapse sidebar when switching tabs
    closeRowSidebar();

    // Save outgoing tab's per-tab state before switching (skip on self-calls from parseTabData)
    const outgoingIdx = activeTabIndex;
    if (outgoingIdx >= 0 && outgoingIdx < tabs.length && outgoingIdx !== idx) {
      const outgoing = tabs[outgoingIdx];
      if (outgoing && !outgoing.blank) {
        // Timeline/bytes are always per-tab regardless of global mode
        outgoing.timelineVisible = timelineVisible;
        outgoing.bytesVisible    = bytesVisible;
        if (!globalMode) {
          // Flush any DOM-typed-but-not-yet-debounced filter values
          filterRows.forEach(row => {
            const input = document.getElementById(`fr-input-${row.id}`);
            if (input) row.value = input.value;
            const colEl = document.getElementById(`fr-col-${row.id}`);
            if (colEl) row.col = colEl.value;
          });
          outgoing.filterRows    = JSON.parse(JSON.stringify(filterRows || []));
          outgoing.columnFilters = cloneColumnFilters(columnFilters || {});
          outgoing.tags          = [...tags];
        }
      }
    }

    activeTabIndex = idx;
    const tab = tabs[idx];
   
    // Parse tab if not already parsed
    if (!tab.parsed && !tab.blank) {
      parseTabData(tab);
      return; // parseTabData will call switchTab again after parsing
    }
 
    // Blank tab - hide everything until a CSV is loaded
    if (tab.blank) {
      document.getElementById('dropZone').style.display = 'flex';
      document.getElementById('tableWrap').style.display = 'none';
      document.getElementById('analysisToolbar').classList.add('hidden');
      document.getElementById('filterBar').classList.add('hidden');
      document.getElementById('btnExport').style.display = 'none'; var _dsb = document.getElementById('dataSourceBadge'); if (_dsb) _dsb.style.display = 'none';
      if (typeof overviewVisible !== 'undefined' && overviewVisible) { overviewVisible = false; var _op = document.getElementById('overviewPanel'); if (_op) _op.style.display = 'none'; }
      allRows = []; headers = []; filteredSorted = []; visibleRows = [];
      filterRows = []; filterRowCounter = 0; hiddenCols = new Set();
      renderTabBar();
      const countEl = document.getElementById('rowCount');
      if (countEl) countEl.textContent = '';
      return;
    }
 
    // Real CSV tab - ensure table is visible again after leaving blank tabs
    document.getElementById('dropZone').style.display = 'none';
    document.getElementById('tableWrap').style.display = 'block';
   
    // Restore tab state into global variables
    allRows = tab.allRows;
    headers = tab.headers;
    hiddenCols = new Set(tab.hiddenCols || []);
    sortCol = tab.sortCol;
    sortDir = tab.sortDir;
    // Always restore filters (they persist by default)
    filterRows = JSON.parse(JSON.stringify(tab.filterRows || []));
    columnFilters = cloneColumnFilters(tab.columnFilters || {});
    currentPage = tab.currentPage;
    filteredSorted = tab.filteredSorted;
    visibleRows = tab.visibleRows;
    modalRowIdx = tab.modalRowIdx;
   
    // Ensure at least one filter row exists in UI
    if (!filterRows.length) {
      const id = ++filterRowCounter;
      filterRows = [{ id, col: '', mode: 'contains', value: '', connector: 'AND' }];
    }
 
    // Restore timestamp filter values for this tab
    document.getElementById('tsFrom').value = tab.tsFrom || '';
    document.getElementById('tsTo').value   = tab.tsTo   || '';
 
    // Update filter checkbox to reflect current tab's filter enabled state
    document.getElementById('filterLockCheckbox').checked = tab.filterEnabled !== false;
    updateFilterToggleText(tab.filterEnabled !== false);

    // Restore per-tab highlights
    if (!globalMode) {
      if (!tab.tags) tab.tags = [...tags]; // initialise if never saved
      tags = [...tab.tags];
      rebuildTagUI();
    }

    renderTabBar();
    buildColumnSelect();
    detectTimestampColumns();
    detectChronicleData(headers);
    // Pre-compute _ts (parsed ms) on each row for fast timestamp filtering
    if (timestampCols.length && !tab._tsPrecached) {
      const tsCol = timestampCols[0];
      allRows.forEach(function(r) { r._ts = r[tsCol] ? Date.parse(r[tsCol]) : NaN; });
      tab._tsPrecached = tsCol; // track which col was cached
    }
    // Reveal filter bar now that a CSV is loaded
    document.getElementById('filterBar').classList.remove('hidden');
    updateProcTreeBtn();

    // Reset highlight-only filter on tab switch
    if (hlOnly) {
      hlOnly = false;
      const btn = document.getElementById('hlOnlyBtn');
      if (btn) { btn.textContent = '🎯 Show highlighted'; btn.classList.remove('active'); }
    }

    // Timeline / bytes are always per-tab regardless of global mode
    timelineVisible = !!tab.timelineVisible;
    bytesVisible    = !!tab.bytesVisible;
    const tlBar = document.getElementById('timelineBar');
    const tlBtn = document.getElementById('timelineToggle');
    tlBar.classList.toggle('hidden', !timelineVisible);
    tlBtn.classList.toggle('active',  timelineVisible);
    const byBar = document.getElementById('bytesBar');
    const byBtn = document.getElementById('bytesToggle');
    byBar.classList.toggle('hidden', !bytesVisible);
    byBtn.classList.toggle('active',  bytesVisible);
    if (bytesVisible) populateBytesColSelects();

    applyFilter();
    renderColFilterChips();
  }

  function openBlankTab() {
    closeRowSidebar();
    // Create a placeholder tab with no data - shows drop zone
    const tabObj = {
      name: 'New tab',
      rawText: null,
      records: null,
      headers: [],
      allRows: [],
      parsed: false,
      blank: true, // marker for blank tabs
      sortCol: null, sortDir: 1,
      filterRows: [], columnFilters: {},
      currentPage: 1, filteredSorted: [], visibleRows: [], modalRowIdx: 0,
      filterEnabled: true, tsFrom: '', tsTo: '', tsCol: '', tags: [...tags],
    };
    tabs.push(tabObj);
    // Force full re-render of tab bar (new tab added)
    const tabBar = document.getElementById('tabBar');
    tabBar.innerHTML = '';
    activeTabIndex = tabs.length - 1;
    renderTabBar();
    // Show drop zone only - hide everything until CSV is loaded
    document.getElementById('dropZone').style.display = 'flex';
    document.getElementById('tableWrap').style.display = 'none';
    document.getElementById('btnExport').style.display = 'none'; var _dsb = document.getElementById('dataSourceBadge'); if (_dsb) _dsb.style.display = 'none';
    document.getElementById('analysisToolbar').classList.add('hidden');
    document.getElementById('filterBar').classList.add('hidden');
    if (typeof overviewVisible !== 'undefined' && overviewVisible) { overviewVisible = false; var _op2 = document.getElementById('overviewPanel'); if (_op2) _op2.style.display = 'none'; }
    allRows = []; headers = []; filteredSorted = []; visibleRows = [];
    filterRows = []; filterRowCounter = 0;
    const countEl = document.getElementById('rowCount');
    if (countEl) countEl.textContent = '';
  }
 
  function cloneColumnFilters(src) {
    const out = {};
    Object.entries(src || {}).forEach(([col, val]) => {
      if (val === null) out[col] = null;
      else if (val instanceof Set) out[col] = new Set(Array.from(val));
      else if (Array.isArray(val)) out[col] = new Set(val);
      else out[col] = null;
    });
    return out;
  }
 
  function parseTabData(tab) {
    if (tab.parsed) return;

    showLoading('Parsing ' + tab.name + '\u2026 0%');

    // Split into lines (fast native operation — much quicker than char-by-char)
    var rawLines = tab.rawText.split(/\r?\n/);
    var totalLines = rawLines.length;

    if (totalLines < 2) {
      console.warn('Tab "' + tab.name + '" has fewer than 2 rows');
      hideLoading();
      return;
    }

    // Parse header row immediately
    var parsedHeaders = csvParseLine(rawLines[0]).map(function(h) {
      return (h || '').replace(/^\uFEFF/, '').trim();
    });

    var parsedRows = [];
    var lineIndex  = 1;
    var CHUNK      = 3000; // rows per chunk — yields to browser between chunks

    function processChunk() {
      var end = Math.min(lineIndex + CHUNK, totalLines);

      while (lineIndex < end) {
        var line = rawLines[lineIndex];
        if (line && line.trim()) {
          var vals = csvParseLine(line);
          var row  = {};
          parsedHeaders.forEach(function(h, j) { row[h] = vals[j] !== undefined ? vals[j] : ''; });
          row._rt = parsedHeaders.map(function(h) { return row[h]; }).join(' ').toLowerCase();
          parsedRows.push(row);
        }
        lineIndex++;
      }

      var pct = Math.round((lineIndex / totalLines) * 100);
      document.getElementById('loadingMsg').textContent = 'Parsing ' + tab.name + '\u2026 ' + pct + '%';

      if (lineIndex < totalLines) {
        setTimeout(processChunk, 0); // yield control — lets browser repaint the progress %
      } else {
        // Done
        tab.headers = parsedHeaders;
        tab.allRows = parsedRows;
        tab.parsed  = true;

        if (activeTabIndex >= 0 && activeTabIndex < tabs.length && tabs[activeTabIndex] === tab) {
          switchTab(activeTabIndex);
          // Auto-apply severity highlights on first Chronicle load
          if (typeof applyChronicleAutoHighlights === 'function') applyChronicleAutoHighlights();
        }
        hideLoading();
      }
    }

    setTimeout(processChunk, 0); // kick off first chunk on next tick so overlay renders first
  }

  // Parses one line of CSV, handling quoted fields
  function csvParseLine(line) {
    var fields = [];
    var cur    = '';
    var inQ    = false;
    for (var i = 0; i < line.length; i++) {
      var c = line[i];
      if (c === '"') {
        if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
        else inQ = !inQ;
      } else if (c === ',' && !inQ) {
        fields.push(cur); cur = '';
      } else {
        cur += c;
      }
    }
    fields.push(cur);
    return fields;
  }


 
  function renderTabBar() {
    const tabBar = document.getElementById('tabBar');
   
    // Fast path: if tab count matches, just update active classes without rebuilding DOM
    const existing = tabBar.querySelectorAll('.tab:not(.tab-add)');
    if (existing.length === tabs.length) {
      existing.forEach((el, i) => {
        el.classList.toggle('active', i === activeTabIndex);
      });
      return;
    }
   
    tabBar.innerHTML = '';
   
    tabs.forEach((tab, idx) => {
      const tabEl = document.createElement('div');
      tabEl.className = 'tab' + (idx === activeTabIndex ? ' active' : '');
      tabEl.title = tab.name;
      tabEl.style.cursor = 'pointer';
      tabEl.onclick = () => switchTab(idx);
     
      const nameSpan = document.createElement('span');
      nameSpan.textContent = tab.name;
     
      const closeBtn = document.createElement('button');
      closeBtn.className = 'tab-close';
      closeBtn.textContent = '✕';
      closeBtn.title = 'Close tab';
      closeBtn.onclick = (e) => {
        e.stopPropagation();
        closeTab(idx);
      };
     
      tabEl.appendChild(nameSpan);
      tabEl.appendChild(closeBtn);
      tabBar.appendChild(tabEl);
    });
 
    // Single + button at the far right (browser-style) - opens a new blank tab
    const addBtn = document.createElement('button');
    addBtn.className = 'tab tab-add';
    addBtn.textContent = '+ New tab';
    addBtn.title = 'Open a new blank tab';
    addBtn.style.cursor = 'pointer';
    addBtn.onclick = () => openBlankTab();
    tabBar.appendChild(addBtn);
  }
 
  function closeTab(idx) {
    const isOnlyTab = tabs.length <= 1;
    const isBlank = tabs[idx] && tabs[idx].blank;
    // Allow closing blank tabs even if only one tab; block closing real tabs if only one left
    if (isOnlyTab && !isBlank) return;
   
    tabs.splice(idx, 1);
   
    if (activeTabIndex >= tabs.length) {
      activeTabIndex = tabs.length - 1;
    }
   
    if (tabs.length === 0) {
      activeTabIndex = -1;
      allRows = [];
      headers = [];
      filterRows = [];
      columnFilters = {};
      document.getElementById('dropZone').style.display = 'flex';
      document.getElementById('tableWrap').style.display = 'none';
      document.getElementById('btnExport').style.display = 'none'; var _dsb = document.getElementById('dataSourceBadge'); if (_dsb) _dsb.style.display = 'none';
      document.getElementById('tabBar').classList.add('hidden');
      renderPage();
    } else {
      switchTab(activeTabIndex);
    }
   
    renderTabBar();
  }
 
  function showLoading(msg) {
    document.getElementById('loadingMsg').textContent = msg || 'Loading…';
    document.getElementById('loadingOverlay').classList.add('show');
  }
  function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('show');
  }
 
  // Legacy parseCSV kept for potential backward compatibility
  function parseCSV(text) {
    // This is replaced by parseTabData now, but kept for reference
    parseTabData({ rawText: text, parsed: false, headers: [], allRows: [] });
  }
 
 
  // ── Column Select (updates filter row dropdowns when CSV loads) ──
  function buildColumnSelect() {
    renderFilterRows(); // repopulate column options in all existing rows
  }
 
  // ── Timestamp Detection ──
  function detectTimestampColumns() {
    timestampCols = headers.filter(h => {
      const samples = allRows.slice(0, 20).map(r => r[h]).filter(v => v && v.trim());
      if (samples.length < 2) return false;
      const valid = samples.filter(v => !isNaN(Date.parse(v)));
      return valid.length >= Math.ceil(samples.length * 0.7);
    });
    const toolbar = document.getElementById('analysisToolbar');
    const sel = document.getElementById('tsColSelect');
    if (!timestampCols.length) {
      toolbar.classList.add('hidden');
      updateSidebarTopOffset();
      return;
    }
    sel.innerHTML = '';
    timestampCols.forEach(h => {
      const o = document.createElement('option');
      o.value = h; o.textContent = h;
      sel.appendChild(o);
    });
    toolbar.classList.remove('hidden');
    updateSidebarTopOffset();
  }
 
  function applyTimestampFilter(rows) {
    const sel  = document.getElementById('tsColSelect');
    const from = document.getElementById('tsFrom').value;
    const to   = document.getElementById('tsTo').value;
    if (!sel || !sel.value || (!from && !to)) return rows;
    const fromMs = from ? new Date(from).getTime() : -Infinity;
    const toMs   = to   ? new Date(to).getTime()   :  Infinity;
    // Use pre-computed _ts only when the cached column matches the selected column
    const tab = activeTab();
    const useCached = tab && tab._tsPrecached === sel.value && rows.length && rows[0]._ts !== undefined;
    return rows.filter(row => {
      const t = useCached ? row._ts : Date.parse((row[sel.value] != null ? row[sel.value] : ''));
      if (isNaN(t)) return true;
      return t >= fromMs && t <= toMs;
    });
  }
 
  // ── Row Expand Modal ──
  function openRowModal(index) {
    modalRowIdx = index;
    renderDetailView();
    saveTabState();
    if (detailViewMode === 'sidebar') {
      closeRowModal();
      document.getElementById('rowSidebar').classList.add('open');
      document.body.classList.add('sidebar-open');
      updateSidebarPanelStatus();
    } else {
      closeRowSidebar();
      document.getElementById('rowModal').classList.add('open');
    }
  }
 
  function closeRowModal() {
    document.getElementById('rowModal').classList.remove('open');
  }
 
  function closeRowSidebar() {
    document.getElementById('rowSidebar').classList.remove('open');
    document.body.classList.remove('sidebar-open');
    updateSidebarPanelStatus();
  }
 
  function modalNav(delta) {
    modalRowIdx = Math.max(0, Math.min(visibleRows.length - 1, modalRowIdx + delta));
    renderDetailView();
    saveTabState();
  }
 
  function renderDetailView() {
    const row = visibleRows[modalRowIdx];
    if (!row) return;
    const title = `Row ${modalRowIdx + 1} of ${visibleRows.length}`;
    document.getElementById('rowModalTitle').textContent = title;
    document.getElementById('rowSidebarTitle').textContent = title;
 
    const modalBody = document.getElementById('rowModalBody');
    const sideBody = document.getElementById('rowSidebarBody');
    modalBody.innerHTML = '';
    sideBody.innerHTML = '';
    headers.forEach(h => {
      const val = (row[h] != null ? row[h] : '');
      const renderedValue = val === '' ? '(empty)' : val;
 
      const modalField = document.createElement('div');
      modalField.className = 'modal-field';
      modalField.dataset.fieldName = h;
      const modalHead = document.createElement('div');
      modalHead.className = 'modal-field-head';
      const modalName = document.createElement('div');
      modalName.className = 'modal-field-name';
      modalName.textContent = h;
      const modalToggle = document.createElement('button');
      modalToggle.className = 'field-toggle-btn';
      modalToggle.title = `Toggle ${h}`;
      modalToggle.textContent = '−';
      modalToggle.onclick = () => toggleSingleFieldExpand(h);
      modalHead.appendChild(modalName);
      modalHead.appendChild(modalToggle);
      const modalVal = document.createElement('textarea');
      modalVal.className = 'modal-field-value' + (val === '' ? ' empty' : '');
      modalVal.readOnly = true;
      modalVal.spellcheck = false;
      modalVal.value = renderedValue;
      if (val) modalVal.addEventListener('contextmenu', function(e) {
        const sel = modalVal.value.slice(modalVal.selectionStart, modalVal.selectionEnd).trim();
        openCellMenu(e, h, sel || val, row);
      });
      modalField.appendChild(modalHead);
      modalField.appendChild(modalVal);

      const sideField = document.createElement('div');
      sideField.className = 'modal-field';
      sideField.dataset.fieldName = h;
      const sideHead = document.createElement('div');
      sideHead.className = 'modal-field-head';
      const sideName = document.createElement('div');
      sideName.className = 'modal-field-name';
      sideName.textContent = h;
      const sideToggle = document.createElement('button');
      sideToggle.className = 'field-toggle-btn';
      sideToggle.title = `Toggle ${h}`;
      sideToggle.textContent = '−';
      sideToggle.onclick = () => toggleSingleFieldExpand(h);
      sideHead.appendChild(sideName);
      sideHead.appendChild(sideToggle);
      const sideVal = document.createElement('textarea');
      sideVal.className = 'modal-field-value' + (val === '' ? ' empty' : '');
      sideVal.readOnly = true;
      sideVal.spellcheck = false;
      sideVal.value = renderedValue;
      if (val) sideVal.addEventListener('contextmenu', function(e) {
        const sel = sideVal.value.slice(sideVal.selectionStart, sideVal.selectionEnd).trim();
        openCellMenu(e, h, sel || val, row);
      });
      sideField.appendChild(sideHead);
      sideField.appendChild(sideVal);
 
      modalBody.appendChild(modalField);
      sideBody.appendChild(sideField);
    });
 
    applyAllFieldExpandState();
    applySidebarSearchFilter();
  }
 
  function applySidebarSearchFilter() {
    const input = document.getElementById('rowSidebarSearch');
    const query = (input && input.value || '').trim().toLowerCase();
    const body = document.getElementById('rowSidebarBody');
    if (!body) return;
    body.querySelectorAll('.modal-field').forEach(field => {
      if (!query) {
        field.style.display = '';
        return;
      }
      const name = (field.dataset.fieldName || '').toLowerCase();
      const val = (field.querySelector('.modal-field-value')?.value || '').toLowerCase();
      field.style.display = (name.includes(query) || val.includes(query)) ? '' : 'none';
    });
  }
 
  function isFieldExpanded(fieldName) {
    return Object.prototype.hasOwnProperty.call(fieldExpandOverrides, fieldName)
      ? fieldExpandOverrides[fieldName]
      : allFieldsExpanded;
  }
 
  function applyFieldExpandToContainer(container) {
    if (!container) return;
    container.querySelectorAll('.modal-field').forEach(field => {
      const key = field.dataset.fieldName || '';
      const expanded = isFieldExpanded(key);
      field.classList.toggle('is-collapsed', !expanded);
      const toggleBtn = field.querySelector('.field-toggle-btn');
      if (toggleBtn) toggleBtn.textContent = expanded ? '−' : '+';
      const area = field.querySelector('.modal-field-value');
      if (!area) return;
      if (expanded) {
        area.style.display = 'block';
        area.style.height = 'auto';
        area.style.overflowY = 'hidden';
        area.style.resize = 'none';
        area.style.height = `${Math.max(area.scrollHeight, 36)}px`;
      } else {
        area.style.display = 'none';
        area.style.height = '';
        area.style.overflowY = '';
        area.style.resize = '';
      }
    });
  }
 
  function applyAllFieldExpandState() {
    applyFieldExpandToContainer(document.getElementById('rowModalBody'));
    applyFieldExpandToContainer(document.getElementById('rowSidebarBody'));
    const label = allFieldsExpanded ? 'Collapse fields' : 'Expand fields';
    const modalBtn = document.getElementById('rowModalExpandToggle');
    const sideBtn = document.getElementById('rowSidebarExpandToggle');
    if (modalBtn) modalBtn.textContent = label;
    if (sideBtn) sideBtn.textContent = label;
  }
 
  function setAllFieldExpandState(expanded) {
    allFieldsExpanded = !!expanded;
    fieldExpandOverrides = {};
    applyAllFieldExpandState();
  }
 
  function toggleAllFieldExpand() {
    setAllFieldExpandState(!allFieldsExpanded);
  }
 
  function toggleSingleFieldExpand(fieldName) {
    const current = isFieldExpanded(fieldName);
    const next = !current;
    if (next === allFieldsExpanded) delete fieldExpandOverrides[fieldName];
    else fieldExpandOverrides[fieldName] = next;
    applyAllFieldExpandState();
  }
 
  function updateSidebarPanelStatus() {
    const sideBtn = document.getElementById('sidebarCollapseToggle');
    const sideLabel = document.getElementById('sidebarPanelStatusLabel');
    const sidebar = document.getElementById('rowSidebar');
    const inSidebarMode = detailViewMode === 'sidebar';
    const isOpen = !!(sidebar && sidebar.classList.contains('open'));
 
    if (sideLabel) sideLabel.textContent = 'Sidebar';
    if (sideBtn) {
      sideBtn.disabled = !inSidebarMode;
      sideBtn.style.opacity = inSidebarMode ? '1' : '0.45';
      sideBtn.textContent = `▣ ${inSidebarMode && isOpen ? 'On' : 'Off'}`;
    }
  }
 
  function setDetailViewMode(mode) {
    detailViewMode = mode === 'sidebar' ? 'sidebar' : 'modal';
    const btn = document.getElementById('detailViewToggle');
    const label = document.getElementById('detailViewModeLabel');
    if (detailViewMode === 'sidebar') {
      label.textContent = 'Detail view: Sidebar';
      btn.textContent = '◧ Sidebar';
    } else {
      label.textContent = 'Detail view: Full log';
      btn.textContent = '◨ Full log';
    }
    updateSidebarPanelStatus();
  }
 
  function toggleSidebarPanel() {
    if (detailViewMode !== 'sidebar') return;
    const sidebar = document.getElementById('rowSidebar');
    if (!sidebar) return;
    if (sidebar.classList.contains('open')) {
      closeRowSidebar();
      return;
    }
    if (visibleRows && visibleRows.length) {
      const idx = Math.max(0, Math.min(visibleRows.length - 1, modalRowIdx || 0));
      openRowModal(idx);
    }
  }
 
  function toggleDetailViewMode() {
    const next = detailViewMode === 'modal' ? 'sidebar' : 'modal';
    const wasModalOpen = document.getElementById('rowModal').classList.contains('open');
    const wasSideOpen = document.getElementById('rowSidebar').classList.contains('open');
    setDetailViewMode(next);
    if (wasModalOpen || wasSideOpen) {
      openRowModal(modalRowIdx);
    }
  }
 
  // ── Gear menu ──
  function toggleGearMenu(event) {
    event.stopPropagation();
    document.getElementById('gearPanel').classList.toggle('open');
  }

  document.addEventListener('click', function(e) {
    const wrap = document.getElementById('gearWrap');
    if (wrap && !wrap.contains(e.target)) {
      const panel = document.getElementById('gearPanel');
      if (panel) panel.classList.remove('open');
    }
  });

  // ── Highlight section toggle ──
  function toggleHighlightSection() {
    const section = document.getElementById('highlightSection');
    const btn = document.getElementById('btnHighlights');
    const isOpen = section.style.display !== 'none';
    section.style.display = isOpen ? 'none' : 'block';
    if (btn) btn.style.borderColor = isOpen ? '' : 'var(--cb-yellow)';
  }

  // Close modal/sidebar/column picker on Escape
  document.addEventListener('keydown', e => {
    const modalOpen = document.getElementById('rowModal').classList.contains('open');
    const sideOpen = document.getElementById('rowSidebar').classList.contains('open');
    if (e.key === 'Escape') {
      closeRowModal();
      closeRowSidebar();
      closeColPicker();
      closeProcTree();
      closeNetworkMap();
      closeAmsiExtractor();
    }
    if (e.key === 'ArrowLeft'  && (modalOpen || sideOpen)) modalNav(-1);
    if (e.key === 'ArrowRight' && (modalOpen || sideOpen)) modalNav(1);
  });
 
  // ── Filter Builder ──
 
  function addFilterRow(connector) {
    const id = ++filterRowCounter;
    filterRows.push({ id, col: '', mode: 'contains', value: '', connector: connector || 'AND' });
    renderFilterRows();
    // Show bar once there's at least one row
    document.getElementById('filterBar').classList.remove('hidden');
  }
 
  function removeFilterRow(id) {
    filterRows = filterRows.filter(r => r.id !== id);
    renderFilterRows();
    applyFilter();
    if (!filterRows.length) document.getElementById('filterBar').classList.add('hidden');
  }
 
  function clearAllFilters() {
    filterRows = [];
    filterRowCounter = 0;
    columnFilters = {};
    closeColPicker();
    document.getElementById('filterRowsContainer').innerHTML = '';
    applyFilter();
    renderColFilterChips();
    // Re-add a blank first row
    addFilterRow(null);
  }
 
  function renderFilterRows() {
    const container = document.getElementById('filterRowsContainer');
    container.innerHTML = '';
 
    filterRows.forEach((row, index) => {
      // ── TTP filter row — non-editable chip ──
      if (row.mode === 'ttp') {
        const div = document.createElement('div');
        div.className = 'filter-row filter-row-ttp';
        if (index > 0) {
          const connSel = document.createElement('select');
          connSel.className = 'connector-sel';
          connSel.innerHTML = `<option value="AND" ${row.connector==='AND'?'selected':''}>AND</option><option value="OR" ${row.connector==='OR'?'selected':''}>OR</option>`;
          connSel.onchange = () => { updateRowProp(row.id, 'connector', connSel.value); applyFilter(); };
          div.appendChild(connSel);
        } else {
          const spacer = document.createElement('span'); spacer.className = 'connector-spacer'; div.appendChild(spacer);
        }
        const badge = document.createElement('span');
        badge.className = 'ttp-filter-badge';
        badge.innerHTML = `🎯 <strong>${escapeHtml(row.value)}</strong> · ${escapeHtml(row.techName || '')}`;
        badge.title = (row.tactic || '') + ' — ' + (row.techName || '');
        const btn = document.createElement('button');
        btn.className = 'btn-remove-row'; btn.textContent = '×'; btn.title = 'Remove TTP filter';
        btn.onclick = () => removeFilterRow(row.id);
        div.appendChild(badge); div.appendChild(btn);
        container.appendChild(div);
        return;
      }

      const div = document.createElement('div');
      div.className = 'filter-row';

      // Connector inline at the start of rows after the first
      if (index > 0) {
        const connSel = document.createElement('select');
        connSel.className = 'connector-sel';
        connSel.title = 'How this row combines with the previous';
        connSel.innerHTML = `
          <option value="AND" ${row.connector==='AND'?'selected':''}>AND</option>
          <option value="OR"  ${row.connector==='OR' ?'selected':''}>OR</option>`;
        connSel.onchange = () => { updateRowProp(row.id, 'connector', connSel.value); applyFilter(); };
        div.appendChild(connSel);
      } else {
        // Spacer so first row inputs align with subsequent rows
        const spacer = document.createElement('span');
        spacer.className = 'connector-spacer';
        div.appendChild(spacer);
      }

      // Column selector
      const colSel = document.createElement('select');
      colSel.className = 'col-sel';
      colSel.id = `fr-col-${row.id}`;
      const allOpt = document.createElement('option');
      allOpt.value = ''; allOpt.textContent = 'All columns';
      colSel.appendChild(allOpt);
      headers.forEach(h => {
        const o = document.createElement('option');
        o.value = h; o.textContent = h;
        if (row.col === h) o.selected = true;
        colSel.appendChild(o);
      });
      colSel.onchange = () => { updateRowProp(row.id, 'col', colSel.value); applyFilter(); };

      // Match mode
      const modeSel = document.createElement('select');
      modeSel.className = 'mode-sel';
      modeSel.innerHTML = `
        <option value="contains"    ${row.mode==='contains'   ?'selected':''}>contains</option>
        <option value="notcontains" ${row.mode==='notcontains'?'selected':''}>does not contain</option>
        <option value="equals"      ${row.mode==='equals'     ?'selected':''}>equals</option>
        <option value="notequals"   ${row.mode==='notequals'  ?'selected':''}>not equals</option>
        <option value="startswith"  ${row.mode==='startswith' ?'selected':''}>starts with</option>
        <option value="endswith"    ${row.mode==='endswith'   ?'selected':''}>ends with</option>
        <option value="regex"       ${row.mode==='regex'      ?'selected':''}>matches regex</option>
        <option value="notregex"    ${row.mode==='notregex'   ?'selected':''}>not regex</option>
      `;
      modeSel.onchange = () => { updateRowProp(row.id, 'mode', modeSel.value); applyFilter(); };

      // Text input
      const input = document.createElement('input');
      input.type        = 'text';
      input.id          = `fr-input-${row.id}`;
      input.placeholder = 'Filter value…';
      input.value       = row.value;
      input.oninput     = () => { updateRowProp(row.id, 'value', input.value); scheduleFilter(); };

      // Remove button
      const btn = document.createElement('button');
      btn.className = 'btn-remove-row';
      btn.textContent = '×';
      btn.title = 'Remove row';
      btn.onclick = () => removeFilterRow(row.id);

      div.appendChild(colSel);
      div.appendChild(modeSel);
      div.appendChild(input);
      div.appendChild(btn);
      container.appendChild(div);
    });
 
    updateSidebarTopOffset();
  }
 
  function updateRowProp(id, key, value) {
    const row = filterRows.find(r => r.id === id);
    if (row) row[key] = value;
  }
 
  function evaluateFilterRow(dataRow, filterRow) {
    const val = filterRow.value || '';
    if (!val.trim()) return true; // blank row = pass everything
    // TTP filter — uses precomputed Set of matching row references
    if (filterRow.mode === 'ttp') {
      return filterRow.matchingSet ? filterRow.matchingSet.has(dataRow) : true;
    }
    const text = filterRow.col
      ? ((dataRow[filterRow.col] != null ? dataRow[filterRow.col] : '')).toLowerCase()
      : (dataRow._rt || '');
    switch (filterRow.mode) {
      case 'contains':    return text.includes(val.toLowerCase());
      case 'notcontains': return !text.includes(val.toLowerCase());
      case 'equals':      return text === val.toLowerCase();
      case 'notequals':   return text !== val.toLowerCase();
      case 'startswith':  return text.startsWith(val.toLowerCase());
      case 'endswith':    return text.endsWith(val.toLowerCase());
      case 'regex': {
        // Cache compiled regex on the filter row — only recompile when value changes
        if (!filterRow._re || filterRow._reVal !== val) {
          try { filterRow._re = new RegExp(val, 'i'); filterRow._reVal = val; } catch(e) { filterRow._re = null; }
        }
        return filterRow._re ? filterRow._re.test(text) : false;
      }
      case 'notregex': {
        if (!filterRow._re || filterRow._reVal !== val) {
          try { filterRow._re = new RegExp(val, 'i'); filterRow._reVal = val; } catch(e) { filterRow._re = null; }
        }
        return filterRow._re ? !filterRow._re.test(text) : true;
      }
      default: return true;
    }
  }
 
  function applyFilter() {
    let rows = allRows;
     const tab = activeTab();
     // If filters are disabled for this tab, don't apply them
     if (tab && !tab.filterEnabled) {
       rows = allRows;
     } else {
       // Text filter rows
       if (filterRows.some(r => r.value.trim())) {
      rows = rows.filter(dataRow => {
        let result = evaluateFilterRow(dataRow, filterRows[0]);
        for (let i = 1; i < filterRows.length; i++) {
          const next = evaluateFilterRow(dataRow, filterRows[i]);
          result = filterRows[i].connector === 'OR' ? result || next : result && next;
        }
        return result;
      });
       }
       // Column value filters
       const activeColFilters = Object.entries(columnFilters).filter(([,s]) => s !== null);
       if (activeColFilters.length) {
         rows = rows.filter(dataRow =>
           activeColFilters.every(([col, allowed]) => allowed.has((dataRow[col] != null ? dataRow[col] : '')))
         );
       }
       rows = applyTimestampFilter(rows);
     }
    // Highlight-only filter
    if (hlOnly && tags.length) {
      rows = rows.filter(row => {
        const rowText = row._rt || '';
        return tags.some(t => rowText.includes(t.term.toLowerCase()));
      });
    }
    renderTable(rows);
    if (typeof overviewVisible !== 'undefined' && overviewVisible) scheduleOverviewRender();
    saveTabState();
  }
 
  function saveTabState() {
    const tab = activeTab();
    if (!tab) return;
    tab.sortCol = sortCol;
    tab.sortDir = sortDir;
    tab.filterRows = (filterRows || []).map(function(r) {
      return { id: r.id, col: r.col, mode: r.mode, value: r.value, connector: r.connector };
    });
    tab.columnFilters = cloneColumnFilters(columnFilters || {});
    tab.currentPage = currentPage;
    tab.filteredSorted = filteredSorted;
    tab.visibleRows = visibleRows;
    tab.modalRowIdx = modalRowIdx;
    tab.tsFrom = document.getElementById('tsFrom').value;
    tab.tsTo   = document.getElementById('tsTo').value;
    const tsColEl = document.getElementById('tsColSelect');
    if (tsColEl) tab.tsCol = tsColEl.value;
    if (!globalMode) tab.tags = [...tags];
    tab.timelineVisible = timelineVisible;
    tab.bytesVisible    = bytesVisible;
    tab.hiddenCols = [...hiddenCols];
  }
 
  // ── Sort ──
  function sortBy(col) {
    if (sortCol === col) sortDir *= -1;
    else { sortCol = col; sortDir = 1; }
    currentPage = 1;
    applyFilter();
  }
 
  // ── Pagination helpers ──
  function pageSize()   { return parseInt(document.getElementById('pgSize').value) || 0; }
  function totalPages() {
    const ps = pageSize();
    if (!ps) return 1;
    return Math.max(1, Math.ceil(filteredSorted.length / ps));
  }
  function goPage(n) {
    currentPage = Math.max(1, Math.min(totalPages(), Math.round(n)));
    renderPage();
    saveTabState();
    document.getElementById('tableWrap').scrollTop = 0;
  }
 
  // ── Render (two-phase: filter -> page) ──
  function renderTable(rows) {
    // Sort — Schwartzian transform with numeric detection (avoids costly localeCompare)
    if (sortCol) {
      var col = sortCol, dir = sortDir;
      var sample = [];
      for (var si = 0; si < Math.min(50, rows.length); si++) {
        var sv = rows[si][col]; if (sv) sample.push(sv);
      }
      var isNum = sample.length > 0 && sample.every(function(v) { return !isNaN(parseFloat(v)) && v.trim() !== ''; });
      var keyed = rows.map(function(r) { return [r, r[col] != null ? r[col] : '']; });
      if (isNum) {
        keyed.sort(function(a, b) { return (parseFloat(a[1]) - parseFloat(b[1])) * dir; });
      } else {
        keyed.sort(function(a, b) { return a[1] < b[1] ? -dir : a[1] > b[1] ? dir : 0; });
      }
      rows = keyed.map(function(x) { return x[0]; });
    }
    filteredSorted = rows;
    visibleRows    = rows; // for modal — navigates full filtered set
    currentPage    = Math.min(currentPage, totalPages());
    renderPage();
  }
 
  function renderPage() {
    const ps    = pageSize();
    const start = ps ? (currentPage - 1) * ps : 0;
    const end   = ps ? start + ps : filteredSorted.length;
    const page  = filteredSorted.slice(start, end);
    const tab = activeTab();
    const filtersEnabled = !(tab && tab.filterEnabled === false); // gates text/column filtering + term marks
    // Highlights (row colour) are ALWAYS shown regardless of filter toggle
 
    // Head — only rebuild when sort/filter state actually changes
    const head = document.getElementById('csvHead');
    const filteredColKeys = Object.keys(columnFilters)
      .filter(function(k) { return columnFilters[k] !== null; }).sort().join(',');
    const visHeaders = headers.filter(h => !hiddenCols.has(h));
    const headKey = visHeaders.join('\x00') + '~' + sortCol + '~' + sortDir + '~' + filtersEnabled + '~' + filteredColKeys;
    if (headKey !== _lastHeadKey || !head.firstChild) {
      _lastHeadKey = headKey;
      head.innerHTML = '';
      const tr = document.createElement('tr');

    const rowNumTh = document.createElement('th');
    rowNumTh.className = 'rownum-col';
    rowNumTh.textContent = '#';
    tr.appendChild(rowNumTh);

    visHeaders.forEach(h => {
      const th = document.createElement('th');
      if (sortCol === h) th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
      if (filtersEnabled && columnFilters[h]) th.classList.add('col-filtered');
 
      const inner = document.createElement('div');
      inner.className = 'th-inner';
 
      const label = document.createElement('span');
      label.className = 'th-label';
      label.textContent = h;
      label.onclick = () => sortBy(h);

      const arrow = document.createElement('span');
      arrow.className = 'th-arrow';
      arrow.textContent = (filtersEnabled && columnFilters[h]) ? '▼' : '▾';
      arrow.title = 'Filter column values';
      arrow.onclick = (e) => { e.stopPropagation(); openColPicker(h, arrow); };

      inner.appendChild(label);
      inner.appendChild(arrow);
      th.appendChild(inner);

      // Right-click header → move column menu
      th.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        const colIdx = headers.indexOf(h);
        showCtxMenu(e, [
          { type:'label',   text: h },
          { type:'sep' },
          { type:'item', icon:'←', text:'Move left',    fn: () => moveCol(h, -1) },
          { type:'item', icon:'→', text:'Move right',   fn: () => moveCol(h,  1) },
          { type:'item', icon:'⇤', text:'Move to first',fn: () => moveCol(h, -colIdx) },
          { type:'item', icon:'⇥', text:'Move to last', fn: () => moveCol(h, headers.length - 1 - colIdx) },
          { type:'sep' },
          { type:'item', icon:'↕', text:'Sort ascending',  fn: () => { sortCol = h; sortDir =  1; currentPage = 1; applyFilter(); } },
          { type:'item', icon:'↕', text:'Sort descending', fn: () => { sortCol = h; sortDir = -1; currentPage = 1; applyFilter(); } },
          { type:'item', icon:'⊘', text:'Hide column',     fn: () => toggleColVisibility(h, true) },
        ]);
      });

      // Header drag-to-reorder (Option A)
      th.draggable = true;
      th.addEventListener('dragstart', function(e) {
        e.dataTransfer.setData('text/plain', h);
        th.style.opacity = '0.5';
        document.body.style.cursor = 'grabbing';
      });
      th.addEventListener('dragend', function() {
        th.style.opacity = '';
        document.body.style.cursor = '';
        document.querySelectorAll('thead th.col-drag-over').forEach(el => el.classList.remove('col-drag-over'));
      });
      th.addEventListener('dragover',  function(e) { e.preventDefault(); th.classList.add('col-drag-over'); });
      th.addEventListener('dragleave', function()  { th.classList.remove('col-drag-over'); });
      th.addEventListener('drop', function(e) {
        e.preventDefault(); th.classList.remove('col-drag-over');
        const srcCol = e.dataTransfer.getData('text/plain');
        if (!srcCol || srcCol === h) return;
        const fromIdx = headers.indexOf(srcCol);
        const toIdx   = headers.indexOf(h);
        if (fromIdx < 0 || toIdx < 0) return;
        headers.splice(fromIdx, 1);
        headers.splice(toIdx, 0, srcCol);
        const tab = activeTab(); if (tab) tab.headers = headers;
        _lastHeadKey = ''; renderPage(); saveTabState();
      });

      // Resize handle
      const resizeHandle = document.createElement('div');
      resizeHandle.className = 'col-resize-handle';
      resizeHandle.addEventListener('mousedown', e => startColResize(e, th));
      th.appendChild(resizeHandle);
 
      tr.appendChild(th);
    });
    head.appendChild(tr);
    } // end head cache block

    // Pre-compile highlight mark regexes once per render — reused for every cell
    // Maps column name (or '' for all-column) → [{re, term}]
    const _hlRegexMap = {};
    if (filtersEnabled) {
      filterRows.filter(fr => fr.mode === 'contains' && fr.value.trim()).forEach(fr => {
        const key = fr.col || '';
        if (!_hlRegexMap[key]) _hlRegexMap[key] = [];
        const escaped = escapeRegex(escapeHtml(fr.value.trim()));
        try { _hlRegexMap[key].push({ re: new RegExp(escaped, 'gi'), term: fr.value.trim() }); } catch(e) {}
      });
    }

    // Body — use DocumentFragment for fast batch insert
    const frag = document.createDocumentFragment();
    page.forEach((row, pageIdx) => {
      const globalIdx = start + pageIdx;
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      tr.onclick = () => openRowModal(globalIdx);

      const priority = ['hl-red','hl-orange','hl-yellow','hl-green','hl-purple','hl-pink','hl-teal','hl-cyan','hl-grey'];
      const rowText = row._rt || '';
      // Collect ALL matching highlight colours (not just highest priority)
      const allHlClasses = priority.filter(p =>
        tags.find(t => t.colour === p && rowText.includes(t.term.toLowerCase()))
      );
      if (allHlClasses.length) tr.classList.add(allHlClasses[0]);

      const rowNumTd = document.createElement('td');
      rowNumTd.className = 'rownum-col';

      if (allHlClasses.length > 0) {
        const dotsWrap = document.createElement('span');
        dotsWrap.className = 'hl-dots';
        allHlClasses.forEach(cls => {
          const dot = document.createElement('span');
          dot.className = 'hl-dot ' + cls;
          dotsWrap.appendChild(dot);
        });
        rowNumTd.appendChild(dotsWrap);
      }

      const numSpan = document.createElement('span');
      numSpan.textContent = (globalIdx + 1).toLocaleString();
      rowNumTd.appendChild(numSpan);

      const matchingTerms = allHlClasses.flatMap(cls => tags.filter(t => t.colour === cls && rowText.includes(t.term.toLowerCase())).map(t => t.term));
      rowNumTd.title = 'Row ' + (globalIdx + 1) + (matchingTerms.length ? ' — matches: ' + matchingTerms.join(', ') : '');
      tr.appendChild(rowNumTd);
 
      visHeaders.forEach(h => {
        const td = document.createElement('td');
        const val = (row[h] != null ? row[h] : '');
        // Use pre-compiled regexes (column-specific + all-column)
        const hlEntries = filtersEnabled ? [...(_hlRegexMap[h] || []), ...(_hlRegexMap[''] || [])] : [];
        if (hlEntries.length) {
          let html = escapeHtml(val);
          hlEntries.forEach(({ re }) => {
            re.lastIndex = 0; // reset global regex state
            html = html.replace(re, m => `<mark>${m}</mark>`);
          });
          td.innerHTML = html;
        } else {
          td.textContent = val;
        }
        td.title = val;
        if (val) {
          td.addEventListener('contextmenu', function(e) { openCellMenu(e, h, val, row); });
        }
        tr.appendChild(td);
      });
      frag.appendChild(tr);
    });
 
    const body = document.getElementById('csvBody');
    body.innerHTML = '';
    body.appendChild(frag);
 
    // Row count
    const total = allRows.length;
    const filt  = filteredSorted.length;
    const countEl = document.getElementById('rowCount');
    if (ps && filteredSorted.length > ps) {
      countEl.textContent = `Showing ${(start+1).toLocaleString()}–${Math.min(end,filt).toLocaleString()} of ${filt.toLocaleString()} filtered (${total.toLocaleString()} total)`;
    } else {
      countEl.textContent = `${filt.toLocaleString()} of ${total.toLocaleString()} rows`;
    }
 
    // Pagination bar
    const pgBar = document.getElementById('paginationBar');
    const tp = totalPages();
    if (tp > 1) {
      pgBar.classList.add('visible');
      document.getElementById('pgFirst').disabled = currentPage <= 1;
      document.getElementById('pgPrev').disabled  = currentPage <= 1;
      document.getElementById('pgNext').disabled  = currentPage >= tp;
      document.getElementById('pgLast').disabled  = currentPage >= tp;
      document.getElementById('pgInfo').textContent = `Page ${currentPage} of ${tp}`;
      document.getElementById('pgJump').value = '';
      document.documentElement.style.setProperty('--pg-bar-height', pgBar.offsetHeight + 'px');
    } else {
      pgBar.classList.remove('visible');
      document.documentElement.style.setProperty('--pg-bar-height', '0px');
    }

    scheduleChartRender();
  }
 
  // ── Column Value Picker ──
 
  function openColPicker(col, anchorEl) {
    cpCol = col;
    // Lazy per-column cache — computed once per tab, reused on subsequent opens
    const tab = activeTab();
    if (tab && !tab._colCounts) tab._colCounts = {};
    if (tab && !tab._colCounts[col]) {
      const counts = {};
      allRows.forEach(function(r) { const v = r[col] != null ? r[col] : ''; counts[v] = (counts[v] || 0) + 1; });
      tab._colCounts[col] = counts;
    }
    const cachedCounts = tab && tab._colCounts ? tab._colCounts[col] : null;
    if (cachedCounts) {
      cpAllValues = Object.entries(cachedCounts)
        .sort(function(a, b) { return b[1] - a[1]; })
        .map(function(e) { return { val: e[0], count: e[1] }; });
    } else {
      const counts = {};
      allRows.forEach(r => { const v = (r[col] != null ? r[col] : ''); counts[v] = (counts[v] || 0) + 1; });
      cpAllValues = Object.entries(counts).sort((a,b) => b[1]-a[1]).map(([val,count]) => ({val,count}));
    }
 
    // If a filter already exists for this column, pre-check those values
    cpPending = columnFilters[col] ? new Set(columnFilters[col]) : null;
 
    document.getElementById('cpTitle').textContent = col;
    document.getElementById('cpSearch').value = '';
    cpRenderList();
 
    // Position panel near the arrow
    const panel = document.getElementById('colPickerPanel');
    panel.classList.remove('hidden');
    const rect = anchorEl.getBoundingClientRect();
    const pw = 300, ph = 420;
    let left = rect.left;
    let top  = rect.bottom + 4;
    if (left + pw > window.innerWidth  - 8) left = window.innerWidth  - pw - 8;
    if (top  + ph > window.innerHeight - 8) top  = rect.top - ph - 4;
    panel.style.left = left + 'px';
    panel.style.top  = top  + 'px';
  }
 
  function cpGetVisibleValues() {
    const search = document.getElementById('cpSearch').value.toLowerCase();
    return cpAllValues
      .filter(({val}) => !search || val.toLowerCase().includes(search))
      .map(({val}) => val);
  }
 
  function cpUpdateActionLabels() {
    const hasSearch = document.getElementById('cpSearch').value.trim().length > 0;
    document.getElementById('cpSelectAction').textContent = hasSearch ? 'Select shown' : 'Select all';
    document.getElementById('cpClearAction').textContent = hasSearch ? 'Clear shown' : 'Clear all';
  }

  function cpCycleSort(by) {
    if (by === 'val') {
      cpSortMode = cpSortMode === 'val-asc' ? 'val-desc' : 'val-asc';
    } else {
      cpSortMode = cpSortMode === 'count-desc' ? 'count-asc' : 'count-desc';
    }
    cpRenderList();
    cpUpdateSortBtns();
  }

  function cpUpdateSortBtns() {
    const valBtn   = document.getElementById('cpSortVal');
    const cntBtn   = document.getElementById('cpSortCount');
    if (!valBtn || !cntBtn) return;
    const activeStyle   = 'color:var(--cb-yellow);border-color:var(--cb-yellow)';
    const inactiveStyle = '';
    if (cpSortMode === 'val-asc')    { valBtn.textContent = 'A–Z ↑'; valBtn.style.cssText = activeStyle; cntBtn.style.cssText = inactiveStyle; }
    else if (cpSortMode === 'val-desc')  { valBtn.textContent = 'A–Z ↓'; valBtn.style.cssText = activeStyle; cntBtn.style.cssText = inactiveStyle; }
    else if (cpSortMode === 'count-asc') { cntBtn.textContent = 'Count ↑'; cntBtn.style.cssText = activeStyle; valBtn.style.cssText = inactiveStyle; valBtn.textContent = 'A–Z'; }
    else                                 { cntBtn.textContent = 'Count ↓'; cntBtn.style.cssText = activeStyle; valBtn.style.cssText = inactiveStyle; valBtn.textContent = 'A–Z'; }
  }

  function cpRenderList() {
    const search = document.getElementById('cpSearch').value.toLowerCase();
    const list   = document.getElementById('cpList');
    list.innerHTML = '';
    cpUpdateActionLabels();
    cpUpdateSortBtns();
    let visible = cpAllValues.filter(({val}) => !search || val.toLowerCase().includes(search));
    if (cpSortMode === 'val-asc')    visible = visible.slice().sort((a, b) => a.val.localeCompare(b.val));
    else if (cpSortMode === 'val-desc')  visible = visible.slice().sort((a, b) => b.val.localeCompare(a.val));
    else if (cpSortMode === 'count-asc') visible = visible.slice().sort((a, b) => a.count - b.count);
    // count-desc is already the default order of cpAllValues
    visible.forEach(({val, count}) => {
      const item = document.createElement('label');
      item.className = 'cp-item';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      // checked = included. If cpPending is null (no filter) all are checked.
      cb.checked = cpPending === null || cpPending.has(val);
      cb.onchange = () => {
        if (!cpPending) {
          // First edit: start with all values checked, then uncheck this one
          cpPending = new Set(cpAllValues.map(v => v.val));
        }
        if (cb.checked) cpPending.add(val);
        else cpPending.delete(val);
      };
      const valEl = document.createElement('span');
      valEl.className = 'cp-item-val' + (val === '' ? ' empty-val' : '');
      valEl.textContent = val === '' ? '(blank)' : val;
      const cntEl = document.createElement('span');
      cntEl.className = 'cp-item-count';
      cntEl.textContent = count.toLocaleString();
      item.appendChild(cb);
      item.appendChild(valEl);
      item.appendChild(cntEl);
      list.appendChild(item);
    });
    if (!visible.length) {
      const empty = document.createElement('div');
      empty.style.cssText = 'padding:12px;color:var(--cb-muted);text-align:center';
      empty.textContent = 'No matching values';
      list.appendChild(empty);
    }
  }
 
  function cpSelectAll(checked) {
    const hasSearch = document.getElementById('cpSearch').value.trim().length > 0;
 
    if (!hasSearch) {
      if (checked) {
        cpPending = null; // null = all
      } else {
        cpPending = new Set();
      }
      cpRenderList();
      return;
    }
 
    if (!cpPending) {
      cpPending = new Set(cpAllValues.map(v => v.val));
    }
 
    cpGetVisibleValues().forEach(val => {
      if (checked) cpPending.add(val);
      else cpPending.delete(val);
    });
 
    if (cpPending.size === cpAllValues.length) {
      cpPending = null;
    }
    cpRenderList();
  }
 
  function cpClearFilter() {
    columnFilters[cpCol] = null;
    closeColPicker();
    currentPage = 1;
    applyFilter();
    renderColFilterChips();
  }

  function cpApply() {
    // If pending is null or has all values, remove filter
    if (!cpPending || cpPending.size === cpAllValues.length) {
      columnFilters[cpCol] = null;
    } else {
      columnFilters[cpCol] = new Set(cpPending);
    }
    closeColPicker();
    currentPage = 1;
    applyFilter();
    renderColFilterChips();
  }
 
  // Render active column-value filter chips in the filter bar
  function renderColFilterChips() {
    const el = document.getElementById('colFilterChips');
    if (!el) return;
    const active = Object.entries(columnFilters).filter(function(e) { return e[1] !== null; });
    if (!active.length) { el.style.display = 'none'; el.innerHTML = ''; return; }

    el.style.display = 'flex';
    el.innerHTML = '';

    const label = document.createElement('span');
    label.style.cssText = 'font-size:10px;color:var(--cb-text-inverse);opacity:0.65;white-space:nowrap;font-weight:600';
    label.textContent = 'Column:';
    el.appendChild(label);

    const tab = activeTab();
    active.forEach(function(entry) {
      const col = entry[0], allowed = entry[1];
      const colCounts = tab && tab._colCounts ? tab._colCounts[col] : null;
      const totalUniq  = colCounts ? Object.keys(colCounts).length : null;
      const selCount   = allowed.size;

      // Smart label: show excluded values if only a few excluded, otherwise show included
      var desc;
      if (totalUniq !== null && totalUniq - selCount > 0 && totalUniq - selCount <= 3) {
        const excluded = Object.keys(colCounts).filter(function(v) { return !allowed.has(v); });
        desc = 'excludes ' + excluded.map(function(v) { return v || '(blank)'; }).join(', ');
      } else if (selCount <= 3) {
        desc = [...allowed].map(function(v) { return v || '(blank)'; }).join(', ');
      } else {
        desc = selCount + (totalUniq ? ' of ' + totalUniq : '') + ' values';
      }

      const chip = document.createElement('span');
      chip.style.cssText = 'display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:500;background:rgba(255,215,0,0.12);border:1px solid var(--cb-yellow);color:var(--cb-text-inverse)';
      chip.title = col + ': ' + desc + ' — click × to remove';

      const txt = document.createElement('span');
      txt.textContent = col + ': ' + desc;
      chip.appendChild(txt);

      const rm = document.createElement('span');
      rm.textContent = '×';
      rm.style.cssText = 'cursor:pointer;opacity:0.6;font-size:13px;line-height:1;margin-left:2px';
      rm.onmouseover = function() { rm.style.opacity = '1'; };
      rm.onmouseout  = function() { rm.style.opacity = '0.6'; };
      rm.onclick = function() {
        columnFilters[col] = null;
        currentPage = 1;
        applyFilter();
        renderColFilterChips();
      };
      chip.appendChild(rm);
      el.appendChild(chip);
    });
  }

  function closeColPicker() {
    document.getElementById('colPickerPanel').classList.add('hidden');
    document.getElementById('cpSearch').value = '';
    cpUpdateActionLabels();
    cpCol = null;
  }
 
  // Close picker when clicking outside — but not after a resize drag
  var cpResizing = false;
  document.getElementById('colPickerPanel').addEventListener('mousedown', e => {
    // Detect resize handle grab: click near bottom-right corner of the panel
    const panel = document.getElementById('colPickerPanel');
    const r = panel.getBoundingClientRect();
    if (e.clientX > r.right - 18 && e.clientY > r.bottom - 18) {
      cpResizing = true;
      document.addEventListener('mouseup', () => {
        // Give a tick for the click event to fire and be ignored, then clear flag
        setTimeout(() => { cpResizing = false; }, 50);
      }, { once: true });
    }
  });
 
  document.addEventListener('click', e => {
    if (cpResizing) return;
    const panel = document.getElementById('colPickerPanel');
    if (!panel.classList.contains('hidden') && !panel.contains(e.target)) {
      closeColPicker();
    }
  });
 
  // ── Column Resize ──
  function startColResize(e, th) {
    e.preventDefault();
    e.stopPropagation();
    const startX   = e.clientX;
    const startW   = th.offsetWidth;
    const handle   = e.target;
    handle.classList.add('dragging');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
 
    function onMove(e) {
      const newW = Math.max(40, startW + (e.clientX - startX));
      th.style.width    = newW + 'px';
      th.style.minWidth = newW + 'px';
      th.style.maxWidth = newW + 'px';
    }
    function onUp() {
      handle.classList.remove('dragging');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup',   onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup',   onUp);
  }
 
  // ── Global mode ──
  function updateGlobalModeText(enabled) {
    const el = document.getElementById('globalModeText');
    if (el) el.textContent = enabled ? 'Global filters enabled' : 'Global filters disabled';
  }

  function toggleGlobalMode() {
    globalMode = document.getElementById('globalModeCheckbox').checked;
    localStorage.setItem(GLOBAL_MODE_KEY, JSON.stringify(globalMode));
    updateGlobalModeText(globalMode);
    // When enabling global mode: push current tab's tags/filters to all tabs so they stay in sync
    if (globalMode) {
      tabs.forEach(t => {
        if (!t.blank) {
          t.tags       = [...tags];
          t.filterRows = JSON.parse(JSON.stringify(filterRows || []));
          t.columnFilters = cloneColumnFilters(columnFilters || {});
        }
      });
    }
  }

  // Rebuild the tag chip UI from the current `tags` array
  function rebuildTagUI() {
    const container = document.getElementById('tagContainer');
    if (!container) return;
    container.innerHTML = '';
    const saved = [...tags];
    tags = [];
    saved.forEach(t => addTagObj(t));
  }

  // ── Tags ──
  function addTag() {
    const input  = document.getElementById('newHighlight');
    const colour = document.getElementById('tagColour').value;
    const term   = input.value.trim();
    if (!term) return;
    addTagObj({ term, colour });
    input.value = '';
    applyFilter();
  }
 
  function addTagObj({ term, colour }) {
    if (tags.find(t => t.term.toLowerCase() === term.toLowerCase())) return;
    tags.push({ term, colour });
 
    const colours = {
      'hl-red':    { bg:'#ffe3e3', border:'#f5b5b5', text:'#8a1f1f' },
      'hl-orange': { bg:'#ffedd5', border:'#f6c690', text:'#8a4b10' },
      'hl-yellow': { bg:'#fff9db', border:'#f3e08a', text:'#6f5a00' },
      'hl-green':  { bg:'#e6f9ec', border:'#b7e7c4', text:'#1f6b36' },
      'hl-purple': { bg:'#f3e8ff', border:'#d8b8ff', text:'#5b2d86' },
      'hl-pink':   { bg:'#ffe4ef', border:'#f8bdd6', text:'#8a2f5f' },
      'hl-teal':   { bg:'#dff7f5', border:'#aee7df', text:'#0f5f5a' },
      'hl-cyan':   { bg:'#e0f7ff', border:'#a8e7ff', text:'#0b5f78' },
      'hl-grey':   { bg:'#f1f3f5', border:'#d0d7de', text:'#4b5563' },
    };
    const c = colours[colour] || colours['hl-red'];
 
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.style.cssText = `background:${c.bg};border:1px solid ${c.border};color:${c.text}`;
    tag.appendChild(document.createTextNode(`${term} `));
    const removeEl = document.createElement('span');
    removeEl.className = 'remove';
    removeEl.textContent = '×';
    removeEl.onclick = () => removeTag(term);
    tag.appendChild(removeEl);
    document.getElementById('tagContainer').appendChild(tag);
  }
 
  function removeTag(term) {
    tags = tags.filter(t => t.term.toLowerCase() !== String(term).toLowerCase());
    // Rebuild tag container
    const container = document.getElementById('tagContainer');
    container.innerHTML = '';
    const saved = [...tags];
    tags = [];
    saved.forEach(t => addTagObj(t));
    applyFilter();
  }
 
  function saveHighlights() {
    const status = document.getElementById('saveHighlightsStatus');
    try {
      localStorage.setItem(HIGHLIGHT_STORAGE_KEY, JSON.stringify(tags));
      if (status) {
        status.textContent = '✓ Highlights saved';
        status.classList.add('show');
      }
    } catch {
      if (status) {
        status.textContent = '⚠ Save failed';
        status.classList.add('show');
      }
    }
    clearTimeout(saveHighlightsTimer);
    saveHighlightsTimer = setTimeout(() => {
      if (!status) return;
      status.classList.remove('show');
      status.textContent = '';
    }, 1700);
  }
 
  function toggleHighlightedOnly() {
    hlOnly = !hlOnly;
    const btn = document.getElementById('hlOnlyBtn');
    if (btn) {
      btn.textContent = hlOnly ? '🎯 Show all' : '🎯 Show highlighted';
      btn.classList.toggle('active', hlOnly);
    }
    applyFilter();
  }

  function resetHighlights() {
    try { localStorage.removeItem(HIGHLIGHT_STORAGE_KEY); } catch {}
    const container = document.getElementById('tagContainer');
    if (container) container.innerHTML = '';
    tags = [];
    const tab = activeTab();
    if (tab && !globalMode) tab.tags = [];
    applyFilter();
    const status = document.getElementById('saveHighlightsStatus');
    if (status) {
      status.textContent = '↺ Highlights cleared';
      status.classList.add('show');
      clearTimeout(saveHighlightsTimer);
      saveHighlightsTimer = setTimeout(() => {
        status.classList.remove('show');
        status.textContent = '';
      }, 1700);
    }
  }

  function loadHighlights() {
    let saved = [];
    try {
      const raw = localStorage.getItem(HIGHLIGHT_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          saved = parsed.filter(t => t && typeof t.term === 'string' && typeof t.colour === 'string');
        }
      }
    } catch {}

    const container = document.getElementById('tagContainer');
    if (container) container.innerHTML = '';
    tags = [];
    saved.forEach(t => addTagObj(t));
  }
 
 
   // ── Filter Enable/Disable Per Tab ──
   function loadFilterLockState() {
     // Legacy - no longer used, kept for reference
   }
   function toggleFilterEnable() {
     const tab = activeTab();
     if (!tab) return;
  
    tab.filterEnabled = document.getElementById('filterLockCheckbox').checked;
    updateFilterToggleText(tab.filterEnabled);
  
    // Re-render in either mode; disabled mode bypasses filtering/highlighting.
    applyFilter();
    saveTabState();
   }
 
  function updateFilterToggleText(enabled) {
    const textEl = document.getElementById('filterToggleText');
    if (!textEl) return;
    textEl.textContent = enabled ? 'Filters enabled' : 'Filters disabled';
  }

  // ── Export ──
  function exportFiltered() {
    if (!headers.length || !allRows.length) return;
    // Use current rendered dataset so export respects ALL active filters:
    // text filter rows, column value picker filters, timestamp range, and sorting.
    let rows = filteredSorted;
    if (!rows || !Array.isArray(rows)) rows = [];
 
    const lines = [headers.join(','), ...rows.map(r => headers.map(h => `"${((r[h] != null ? r[h] : '')).replace(/"/g,'""')}"`).join(','))];
    const blob  = new Blob([lines.join('\r\n')], { type:'text/csv' });
    const a     = document.createElement('a');
    a.href      = URL.createObjectURL(blob);
    a.download  = 'filtered-export.csv';
    a.click();
  }
 
  // ── Helpers ──
  function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // Creates a Web Worker from an embedded <script type="text/js-worker"> tag.
  // Works with file:// (no server needed) because we use a Blob URL.
  function createBlobWorker(scriptId) {
    const src = document.getElementById(scriptId);
    if (!src) throw new Error('Worker script not found: ' + scriptId);
    const blob = new Blob([src.textContent], { type: 'application/javascript' });
    const url  = URL.createObjectURL(blob);
    const worker = new Worker(url);
    // Revoke after a short delay to ensure the worker has loaded the script
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    return worker;
  }

  // ── Column Visibility ─────────────────────────────────────────────────────
  function toggleColVisPanel(e) {
    e.stopPropagation();
    const panel = document.getElementById('colVisPanel');
    if (panel.style.display === 'block') {
      panel.style.display = 'none';
    } else {
      renderColVisList();
      panel.style.display = 'block';
    }
  }

  // ── Column reorder ────────────────────────────────────────────────────────────
  function moveCol(col, delta) {
    const idx = headers.indexOf(col);
    if (idx < 0) return;
    const newIdx = Math.max(0, Math.min(headers.length - 1, idx + delta));
    if (newIdx === idx) return;
    headers.splice(idx, 1);
    headers.splice(newIdx, 0, col);
    const tab = activeTab();
    if (tab) tab.headers = headers;
    _lastHeadKey = '';
    renderPage();
    saveTabState();
    renderColVisList();
  }

  function renderColVisList() {
    const list = document.getElementById('colVisList');
    list.innerHTML = '';
    var _dragSrc = null;

    headers.forEach(function(h, idx) {
      const row = document.createElement('div');
      row.className = 'col-vis-row';
      row.draggable = true;
      row.dataset.col = h;

      // Drag handle
      const grip = document.createElement('span');
      grip.className = 'col-vis-grip';
      grip.textContent = '⠿';
      grip.title = 'Drag to reorder';

      // Checkbox
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = !hiddenCols.has(h);
      cb.onchange = function() { toggleColVisibility(h, !cb.checked); };

      // Label
      const lbl = document.createElement('span');
      lbl.className = 'col-vis-label';
      lbl.textContent = h;
      lbl.title = h;
      lbl.onclick = function() { cb.checked = !cb.checked; toggleColVisibility(h, !cb.checked); };

      row.appendChild(grip);
      row.appendChild(cb);
      row.appendChild(lbl);
      list.appendChild(row);

      // Drag-to-reorder within the panel
      row.addEventListener('dragstart', function() { _dragSrc = h; row.style.opacity = '0.4'; });
      row.addEventListener('dragend',   function() { row.style.opacity = ''; _dragSrc = null; });
      row.addEventListener('dragover',  function(e) { e.preventDefault(); row.style.background = 'var(--cb-yellow-soft)'; });
      row.addEventListener('dragleave', function()  { row.style.background = ''; });
      row.addEventListener('drop', function(e) {
        e.preventDefault(); row.style.background = '';
        if (!_dragSrc || _dragSrc === h) return;
        const fromIdx = headers.indexOf(_dragSrc);
        const toIdx   = headers.indexOf(h);
        if (fromIdx < 0 || toIdx < 0) return;
        headers.splice(fromIdx, 1);
        headers.splice(toIdx, 0, _dragSrc);
        const tab = activeTab(); if (tab) tab.headers = headers;
        _lastHeadKey = ''; renderPage(); saveTabState(); renderColVisList();
      });
    });
  }

  function toggleColVisibility(col, hide) {
    if (hide) hiddenCols.add(col);
    else hiddenCols.delete(col);
    _lastHeadKey = '';
    renderPage();
    saveTabState();
    renderColVisList();
  }

  function colVisSelectAll(show) {
    if (show) hiddenCols.clear();
    else headers.forEach(function(h) { hiddenCols.add(h); });
    _lastHeadKey = '';
    renderPage();
    saveTabState();
    renderColVisList();
  }

  // ── Timeline quick picks ──────────────────────────────────────────────────
  function tlQuickPick(hours) {
    const colSel = document.getElementById('tsColSelect');
    const col    = colSel ? colSel.value : '';
    const useCol = col || (timestampCols[0] || '');
    if (!useCol) return;

    var maxMs = -Infinity;
    allRows.forEach(function(r) {
      const ms = Date.parse(r[useCol]);
      if (!isNaN(ms) && ms > maxMs) maxMs = ms;
    });
    if (!isFinite(maxMs)) return;

    const fromMs = maxMs - hours * 3600000;
    function fmt(ms) {
      const d = new Date(ms);
      const p = function(n) { return String(n).padStart(2,'0'); };
      return d.getFullYear() + '-' + p(d.getMonth()+1) + '-' + p(d.getDate()) +
             'T' + p(d.getHours()) + ':' + p(d.getMinutes());
    }
    document.getElementById('tsFrom').value = fmt(fromMs);
    document.getElementById('tsTo').value   = fmt(maxMs);

    document.querySelectorAll('.tl-qp').forEach(function(b) { b.classList.remove('active'); });
    if (event && event.target) event.target.classList.add('active');

    applyFilter();
  }

  // Deactivate quick pick highlight on manual datetime edit
  ['tsFrom','tsTo'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('input', function() {
      document.querySelectorAll('.tl-qp').forEach(function(b) { b.classList.remove('active'); });
    });
  });

  // ── Shared Right-Click Context Menu ──────────────────────────────────────
  var FILTER_PRESETS_KEY = 'csv-viewer-filter-presets';
  var _ctxCol = '';
  var _ctxVal = '';
  var _ctxRow = null;

  (function() {
    document.addEventListener('click', function(e) {
      closeCellMenu();
      const presetPanel = document.getElementById('presetPanel');
      if (presetPanel && !presetPanel.contains(e.target) && !(e.target.closest && e.target.closest('.btn-presets'))) {
        closePresetPanel();
      }
      const colPanel = document.getElementById('colVisPanel');
      if (colPanel && !colPanel.contains(e.target) && e.target.id !== 'btnColVis') {
        colPanel.style.display = 'none';
      }
    });
    document.addEventListener('keydown', function(e) { if (e.key === 'Escape') { closeCellMenu(); closePresetPanel(); } });
  })();

  // Build and show the shared context menu from a descriptor array.
  // items: [{type:'label',text}, {type:'preview',text}, {type:'sep'},
  //         {type:'item',icon,text,fn} | {type:'item',icon,text,url}]
  function showCtxMenu(e, items) {
    e.preventDefault();
    e.stopPropagation();
    const menu = document.getElementById('cellContextMenu');
    menu.innerHTML = '';
    items.forEach(function(item) {
      if (item.type === 'label') {
        const el = document.createElement('div');
        el.className = 'ctx-label';
        el.textContent = item.text;
        menu.appendChild(el);
      } else if (item.type === 'preview') {
        const el = document.createElement('div');
        el.className = 'ctx-val-preview';
        el.textContent = item.text.length > 60 ? item.text.slice(0, 57) + '…' : item.text;
        menu.appendChild(el);
      } else if (item.type === 'sep') {
        const el = document.createElement('hr');
        el.className = 'ctx-sep';
        menu.appendChild(el);
      } else if (item.type === 'item') {
        const el = document.createElement('div');
        el.className = 'ctx-item';
        el.textContent = (item.icon ? item.icon + '  ' : '') + item.text;
        if (item.fn)  el.onclick = function() { closeCellMenu(); item.fn(); };
        if (item.url) el.onclick = function() { window.open(item.url, '_blank', 'noopener'); closeCellMenu(); };
        menu.appendChild(el);
      }
    });
    menu.style.display = 'block';
    const vw = window.innerWidth, vh = window.innerHeight;
    const mw = menu.offsetWidth || 240, mh = menu.offsetHeight || 200;
    let x = e.clientX + 2, y = e.clientY + 2;
    if (x + mw > vw) x = vw - mw - 8;
    if (y + mh > vh) y = vh - mh - 8;
    menu.style.left = x + 'px';
    menu.style.top  = y + 'px';
  }

  function closeCellMenu() {
    document.getElementById('cellContextMenu').style.display = 'none';
  }

  function openCellMenu(e, col, val, row) {
    _ctxCol = col;
    _ctxVal = val;
    _ctxRow = row || null;

    const items = [
      { type: 'label',   text: col || 'Cell' },
      { type: 'preview', text: val },
      { type: 'sep' },
      { type: 'item', icon: '🔍', text: 'Filter by this value',  fn: function() { _ctxAddFilter('contains'); } },
      { type: 'item', icon: '⊘',  text: 'Exclude this value',    fn: function() { _ctxAddFilter('notcontains'); } },
      { type: 'sep' },
      { type: 'item', icon: '📋', text: 'Copy value',            fn: function() { navigator.clipboard.writeText(_ctxVal).catch(function(){}); } },
      { type: 'item', icon: '📄', text: 'Copy row as JSON',      fn: function() { ctxCopyRow('json'); } },
      { type: 'item', icon: '📊', text: 'Copy row as CSV',       fn: function() { ctxCopyRow('csv'); } },
    ];

    if (typeof isChronicleData !== 'undefined' && isChronicleData && typeof copyYaraL === 'function') {
      items.push({ type: 'item', icon: '📝', text: 'Copy as YARA-L rule', fn: function() { copyYaraL(_ctxCol, _ctxVal); } });
    }

    if (typeof _isQueryableIoc === 'function' && _isQueryableIoc(col, val)) {
      var _qItems = ctxQueryItems(col, val);
      if (_qItems.length) { items.push({ type: 'sep' }); _qItems.forEach(function(q) { items.push(q); }); }
      items.push({ type: 'item', icon: '➕', text: 'Add to query builder', fn: function() {
        var shortV = _ctxVal.length > 25 ? _ctxVal.slice(0, 22) + '…' : _ctxVal;
        qbAddCondition(_ctxCol, _ctxVal, (_ctxCol ? _ctxCol + ': ' : '') + shortV);
      }});
    }

    const pivots = buildPivots(val, col);
    if (pivots.length) {
      items.push({ type: 'sep' });
      pivots.forEach(function(p) { items.push({ type: 'item', icon: p.icon, text: p.label, url: p.url }); });
    }

    showCtxMenu(e, items);
  }

  function _ctxAddFilter(mode) {
    const id = ++filterRowCounter;
    filterRows.push({ id, col: _ctxCol, mode: mode, value: _ctxVal, connector: 'AND' });
    renderFilterRows();
    document.getElementById('filterBar').classList.remove('hidden');
    applyFilter();
  }

  function ctxCopyRow(fmt) {
    if (!_ctxRow) return;
    let text;
    if (fmt === 'csv') {
      const vals = headers.map(function(h) {
        const v = String(_ctxRow[h] != null ? _ctxRow[h] : '');
        return v.includes(',') || v.includes('"') || v.includes('\n') ? '"' + v.replace(/"/g, '""') + '"' : v;
      });
      text = vals.join(',');
    } else {
      // JSON — omit internal _rt field
      const obj = {};
      headers.forEach(function(h) { obj[h] = _ctxRow[h] != null ? _ctxRow[h] : ''; });
      text = JSON.stringify(obj, null, 2);
    }
    navigator.clipboard.writeText(text).catch(function() {});
    closeCellMenu();
  }

  // buildPivots lives in datasource.js

  // ── Filter Presets ────────────────────────────────────────────────────────
  function loadPresets() {
    try {
      return JSON.parse(localStorage.getItem(FILTER_PRESETS_KEY) || '[]');
    } catch { return []; }
  }

  function savePresetsToStorage(presets) {
    try { localStorage.setItem(FILTER_PRESETS_KEY, JSON.stringify(presets)); } catch {}
  }

  function togglePresetPanel(e) {
    e.stopPropagation();
    const panel = document.getElementById('presetPanel');
    if (panel.style.display === 'block') {
      closePresetPanel();
    } else {
      renderPresetList();
      panel.style.display = 'block';
      document.getElementById('presetNameInput').focus();
    }
  }

  function closePresetPanel() {
    const panel = document.getElementById('presetPanel');
    if (panel) panel.style.display = 'none';
  }

  function renderPresetList() {
    const presets = loadPresets();
    const list = document.getElementById('presetList');
    list.innerHTML = '';
    if (!presets.length) {
      const empty = document.createElement('div');
      empty.className = 'preset-empty';
      empty.textContent = 'No saved presets yet.';
      list.appendChild(empty);
      return;
    }
    presets.forEach(function(p, i) {
      const item = document.createElement('div');
      item.className = 'preset-item';
      const name = document.createElement('span');
      name.className = 'preset-item-name';
      name.textContent = p.name;
      name.title = p.name + ' (' + (p.rows || []).length + ' filter' + ((p.rows||[]).length !== 1 ? 's' : '') + ')';
      name.onclick = function() { loadPreset(i); };
      const del = document.createElement('span');
      del.className = 'preset-del';
      del.textContent = '✕';
      del.title = 'Delete preset';
      del.onclick = function(e) { e.stopPropagation(); deletePreset(i); };
      item.appendChild(name);
      item.appendChild(del);
      list.appendChild(item);
    });
  }

  function savePreset() {
    const nameInput = document.getElementById('presetNameInput');
    const name = (nameInput.value || '').trim();
    if (!name) { nameInput.focus(); return; }
    if (!filterRows.some(r => r.value.trim())) { return; }
    const presets = loadPresets();
    // Replace if name already exists
    const existing = presets.findIndex(p => p.name.toLowerCase() === name.toLowerCase());
    const entry = { name: name, rows: JSON.parse(JSON.stringify(filterRows)) };
    if (existing >= 0) presets[existing] = entry;
    else presets.push(entry);
    savePresetsToStorage(presets);
    nameInput.value = '';
    renderPresetList();
  }

  function loadPreset(index) {
    const presets = loadPresets();
    const p = presets[index];
    if (!p) return;
    filterRows = JSON.parse(JSON.stringify(p.rows));
    filterRowCounter = filterRows.reduce(function(m, r) { return Math.max(m, r.id || 0); }, 0);
    renderFilterRows();
    document.getElementById('filterBar').classList.remove('hidden');
    applyFilter();
    closePresetPanel();
  }

  function deletePreset(index) {
    const presets = loadPresets();
    presets.splice(index, 1);
    savePresetsToStorage(presets);
    renderPresetList();
  }

  // ═══════════════════════════════════════════════════

  // ── Query Builder ─────────────────────────────────────────────────────────
  var QB_POS_KEY = 'csv-viewer-qb-pos';
  var qbConditions = [];
  var qbLogic = 'AND';

  function qbOpen() {
    var panel = document.getElementById('queryBuilderPanel');
    if (!panel) return;
    try {
      var saved = JSON.parse(localStorage.getItem(QB_POS_KEY) || 'null');
      if (saved && saved.left && saved.top) {
        // Clamp to current viewport so panel is never off-screen after a window resize
        var lv = Math.max(0, Math.min(parseFloat(saved.left), window.innerWidth  - 200));
        var tv = Math.max(0, Math.min(parseFloat(saved.top),  window.innerHeight - 120));
        panel.style.left   = lv + 'px';
        panel.style.top    = tv + 'px';
        panel.style.right  = 'auto';
        panel.style.bottom = 'auto';
      }
    } catch(e) {}
    panel.style.display = 'flex';
    qbRender();
  }

  function qbClose() {
    var panel = document.getElementById('queryBuilderPanel');
    if (panel) panel.style.display = 'none';
  }

  function qbToggle() {
    var panel = document.getElementById('queryBuilderPanel');
    if (!panel) return;
    if (panel.style.display === 'none' || !panel.style.display) { qbOpen(); } else { qbClose(); }
  }

  function qbAddCondition(col, val, label) {
    if (!val || !val.trim()) return;
    if (qbConditions.some(function(c) { return c.col === col && c.val === val; })) { qbOpen(); return; }
    var shortVal = val.length > 25 ? val.slice(0, 22) + '…' : val;
    qbConditions.push({ col: col, val: val, label: label || (col ? col + ': ' + shortVal : shortVal) });
    qbOpen();
  }

  function qbRemoveCondition(idx) {
    qbConditions.splice(idx, 1);
    qbRender();
  }

  function qbClear() {
    qbConditions = [];
    qbRender();
  }

  function qbToggleLogic() {
    qbLogic = qbLogic === 'AND' ? 'OR' : 'AND';
    var btn = document.getElementById('qbLogicBtn');
    if (btn) btn.textContent = qbLogic;
    qbRender();
  }

  function qbCopy(platform, btn) {
    var id = platform === 'chronicle' ? 'qbChronicleText'
           : platform === 'sentinel'  ? 'qbSentinelText'
           : 'qbDefenderText';
    var el = document.getElementById(id);
    if (!el || !el.value) return;
    navigator.clipboard.writeText(el.value).catch(function(){});
    if (btn) {
      var orig = btn.textContent;
      btn.textContent = '✓ Copied';
      btn.style.borderColor = '#4ade80';
      btn.style.color       = '#4ade80';
      setTimeout(function() {
        btn.textContent   = orig;
        btn.style.borderColor = '';
        btn.style.color       = '';
      }, 1400);
    }
  }

  function qbRender() {
    var chips    = document.getElementById('qbChips');
    var empty    = document.getElementById('qbEmptyMsg');
    var chrEl    = document.getElementById('qbChronicleText');
    var defEl    = document.getElementById('qbDefenderText');
    var senEl    = document.getElementById('qbSentinelText');
    var chrBlock = document.getElementById('qbChronicleBlock');
    var defBlock = document.getElementById('qbDefenderBlock');
    var senBlock = document.getElementById('qbSentinelBlock');
    var logicBtn = document.getElementById('qbLogicBtn');
    var isWinSec = typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog;
    if (!chips) return;

    if (logicBtn) logicBtn.textContent = qbLogic;
    chips.innerHTML = '';

    if (!qbConditions.length) {
      if (empty)    empty.style.display    = '';
      if (chrBlock) chrBlock.style.display = 'none';
      if (defBlock) defBlock.style.display = 'none';
      if (senBlock) senBlock.style.display = 'none';
      return;
    }

    if (empty)    empty.style.display    = 'none';
    // Show Sentinel panel for Windows Security logs, Defender+Chronicle for others
    if (senBlock) senBlock.style.display = isWinSec ? '' : 'none';
    if (chrBlock) chrBlock.style.display = isWinSec ? 'none' : '';
    if (defBlock) defBlock.style.display = isWinSec ? 'none' : '';

    qbConditions.forEach(function(c, i) {
      var chip = document.createElement('span');
      chip.className = 'qb-chip';
      chip.title = c.col + ': ' + c.val;
      var txt = document.createElement('span');
      txt.textContent = c.label;
      var rm = document.createElement('span');
      rm.className = 'qb-chip-remove';
      rm.textContent = '✕';
      rm.onclick = (function(idx) { return function() { qbRemoveCondition(idx); }; })(i);
      chip.appendChild(txt);
      chip.appendChild(rm);
      chips.appendChild(chip);
    });

    var chrQuery = typeof buildChronicleQueryMulti === 'function'
      ? buildChronicleQueryMulti(qbConditions, qbLogic) : '';
    var defQuery = typeof buildDefenderQueryMulti === 'function'
      ? buildDefenderQueryMulti(qbConditions, qbLogic) : '';
    var senQuery = isWinSec && typeof buildSentinelKQLMulti === 'function'
      ? buildSentinelKQLMulti(qbConditions, qbLogic) : '';

    if (chrEl) chrEl.value = chrQuery;
    if (defEl) defEl.value = defQuery;
    if (senEl) senEl.value = senQuery;

    // Show multi-table warning badge when Defender AND spans multiple tables
    var warnEl = document.getElementById('qbMultiTableWarn');
    var isMultiTable = qbLogic === 'AND' && defQuery.indexOf('// AND conditions span') !== -1;
    if (isMultiTable && !warnEl) {
      warnEl = document.createElement('div');
      warnEl.id = 'qbMultiTableWarn';
      warnEl.style.cssText = 'font-size:10px;color:#f0a500;background:rgba(240,165,0,0.1);border:1px solid rgba(240,165,0,0.4);border-radius:4px;padding:4px 8px;margin-top:4px;line-height:1.4';
      warnEl.textContent = '⚠ Defender: AND conditions span multiple tables — separate queries generated below. See the correlation block to find matching devices.';
      chips.parentElement.appendChild(warnEl);
    } else if (!isMultiTable && warnEl) {
      warnEl.parentElement.removeChild(warnEl);
    }

    // Auto-size textareas — allow up to 400px for multi-table outputs
    [chrEl, defEl].forEach(function(el) {
      if (!el) return;
      el.style.height = 'auto';
      el.style.height = Math.min(400, Math.max(56, el.scrollHeight)) + 'px';
    });
  }

  // Drag
  (function() {
    var _panel, _dragging = false, _sx, _sy, _ol, _ot;
    document.getElementById('qbDragHandle').addEventListener('mousedown', function(e) {
      if (e.target.tagName === 'BUTTON') return;
      _panel = document.getElementById('queryBuilderPanel');
      var r = _panel.getBoundingClientRect();
      _dragging = true; _sx = e.clientX; _sy = e.clientY; _ol = r.left; _ot = r.top;
      _panel.style.left = _ol + 'px'; _panel.style.top = _ot + 'px';
      _panel.style.right = 'auto'; _panel.style.bottom = 'auto';
      e.preventDefault();
    });
    document.addEventListener('mousemove', function(e) {
      if (!_dragging || !_panel) return;
      var x = Math.max(0, Math.min(window.innerWidth  - _panel.offsetWidth,  _ol + (e.clientX - _sx)));
      var y = Math.max(0, Math.min(window.innerHeight - _panel.offsetHeight, _ot + (e.clientY - _sy)));
      _panel.style.left = x + 'px'; _panel.style.top = y + 'px';
    });
    document.addEventListener('mouseup', function() {
      if (!_dragging || !_panel) return;
      _dragging = false;
      try { localStorage.setItem(QB_POS_KEY, JSON.stringify({ left: _panel.style.left, top: _panel.style.top })); } catch(e) {}
    });
  })();
