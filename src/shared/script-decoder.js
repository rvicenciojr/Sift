// script-decoder.js — Script Decoder UI
/* globals allRows, headers, escapeHtml */

// AMSI CONTENT EXTRACTOR
  // ════════════════════════════════════════════════════════════════

  var amsiRecords = [];

  function amsiHasEventData() {
    if (!allRows.length) return false;
    ptResolveColumns(headers);
    return allRows.some(r => {
      const action  = ptGet(r,'action') || '';
      const cmdline = ptGet(r,'cmdline') || ptGet(r,'initCmd') || '';
      return /amsi|visualbasic|script|encoded/i.test(action) ||
        /^(4104|4103)$/.test(action.trim()) ||   // Windows Security PS script block / module logging
        /-enc(?:odedCommand)?\s+[A-Za-z0-9+\/=]{16,}/i.test(cmdline) ||
        /FromBase64String|base64String|::FromBase64/i.test(cmdline);
    });
  }

  // ── Web Worker bridge ─────────────────────────────────────────────────────
  var _amsiWorker = null;

  function amsiCol(pat) {
    return headers.find(h => pat.test((h||'').toLowerCase().replace(/[\s_]/g,''))) || '';
  }

  function openAmsiExtractor() {
    ptResolveColumns(headers);
    document.getElementById('amsiModal').style.display = 'flex';
    buildAmsiContent();
  }

  function closeAmsiExtractor() {
    document.getElementById('amsiModal').style.display = 'none';
  }

  function buildAmsiContent() {
    ptResolveColumns(headers);
    amsiRecords = [];

    const addFieldsCol = amsiCol(/additionalfield/);
    const typedDetsCol = amsiCol(/typeddetail/);

    // Show loading state
    const body = document.getElementById('amsiBody');
    body.innerHTML = '<div style="color:var(--modal-muted);text-align:center;padding:60px">Scanning records…</div>';
    document.getElementById('amsiStats').textContent = '';

    if (_amsiWorker) _amsiWorker.terminate();
    _amsiWorker = createBlobWorker('amsi-worker-src');

    _amsiWorker.onmessage = function (e) {
      if (e.data.type === 'progress') {
        body.innerHTML = `<div style="color:var(--modal-muted);text-align:center;padding:60px">${e.data.msg}</div>`;
        return;
      }
      if (e.data.type === 'done') {
        amsiRecords = e.data.records;
        // Pre-compute a single lowercase search string per record — avoids
        // repeated .toLowerCase() on large content/cmdline fields every keystroke
        amsiRecords.forEach(function(r) {
          r._s = [r.action, r.fname, r.pid, r.device, r.user, r.ts,
                  r.source, r.cmdline, r.content, r.decodedPS]
            .filter(Boolean).join(' ').toLowerCase();
        });
        const { encCnt, amsiCnt } = e.data;
        document.getElementById('amsiStats').innerHTML =
          `<strong style="color:var(--cb-yellow)">${amsiRecords.length}</strong> captures · ` +
          `<strong>${amsiCnt}</strong> AMSI events · ` +
          `<strong style="color:#f0a500">${encCnt}</strong> decoded`;
        document.getElementById('amsiSearch').value = '';
        renderAmsiList();
        _amsiWorker.terminate();
        _amsiWorker = null;
      }
    };

    _amsiWorker.onerror = function (err) {
      console.error('AMSI worker error:', err);
      body.innerHTML = '<div style="color:#e83e3e;text-align:center;padding:60px">Error scanning records. Check console.</div>';
    };

    const activeRows = (typeof filteredSorted !== 'undefined' && filteredSorted.length) ? filteredSorted : allRows;
    _amsiWorker.postMessage({
      rows: activeRows,
      ptColMap,
      addFieldsColName: addFieldsCol,
      typedDetsColName: typedDetsCol,
    });
  }

  function amsiCopy(id, which, btn) {
    const r=amsiRecords[id]; if(!r) return;
    const txt = which==='decoded' ? (r.decodedPS||'') : (r.content||'');
    navigator.clipboard.writeText(txt).catch(()=>{});
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = '✓ Copied';
      btn.classList.add('copy-success');
      btn.style.borderColor = '#4ade80';
      btn.style.color = '#4ade80';
      setTimeout(() => {
        btn.textContent = orig;
        btn.classList.remove('copy-success');
        btn.style.borderColor = '';
        btn.style.color = '';
      }, 1400);
    }
  }

  // Debounce timer for search — avoids rebuilding DOM on every keystroke
  var _amsiSearchTimer = null;
  function amsiScheduleSearch() {
    clearTimeout(_amsiSearchTimer);
    _amsiSearchTimer = setTimeout(renderAmsiList, 200);
  }

  function renderAmsiList() {
    const query=(document.getElementById('amsiSearch').value||'').toLowerCase().trim();
    const body=document.getElementById('amsiBody');
    // Use pre-computed _s field (covers all fields including device, user, ts, source)
    // Falls back to per-field search for records built before _s was added
    const filtered=amsiRecords.filter(function(r) {
      if(!query) return true;
      if(r._s) return r._s.includes(query);
      return (r.content||'').toLowerCase().includes(query)||
             (r.decodedPS||'').toLowerCase().includes(query)||
             (r.fname||'').toLowerCase().includes(query)||
             (r.action||'').toLowerCase().includes(query)||
             (r.cmdline||'').toLowerCase().includes(query)||
             (r.device||'').toLowerCase().includes(query)||
             (r.user||'').toLowerCase().includes(query);
    });
    body.innerHTML='';
    if (!filtered.length) {
      body.innerHTML=`<div style="color:var(--modal-muted);text-align:center;padding:40px;font-style:italic">${amsiRecords.length?'No matches for search.':'No AMSI or encoded PowerShell found in this dataset.'}</div>`;
      return;
    }
    const frag=document.createDocumentFragment();
    filtered.forEach(rec => {
      const actionCol = /amsi/i.test(rec.action)?'#e83e3e':/visual|vba/i.test(rec.action)?'#f0a500':'#c45ab3';
      const card=document.createElement('div');
      card.className='amsi-card';
      card.style.borderLeftColor=actionCol; card.style.borderLeftWidth='3px';

      // Header row
      const hdr=document.createElement('div');
      hdr.className='amsi-card-header';
      hdr.innerHTML=
        `<span style="font-size:9px;font-weight:700;color:${actionCol};border:1px solid ${actionCol};border-radius:3px;padding:1px 6px;text-transform:uppercase;flex-shrink:0">${escapeHtml(rec.action)}</span>`+
        (rec.ts?`<span style="font-family:monospace;font-size:10px;color:var(--cb-os3);flex-shrink:0">${rec.ts.slice(0,19).replace('T',' ')}</span>`:'')+
        (rec.fname?`<span style="font-size:12px;color:var(--cb-yellow);font-family:monospace;font-weight:700">${escapeHtml(rec.fname)}</span>`:'')+
        (rec.pid?`<span style="font-size:10px;color:var(--cb-os3)">PID:${rec.pid}</span>`:'')+
        (rec.device?`<span style="font-size:10px;color:var(--cb-os4)">${escapeHtml(rec.device)}</span>`:'')+
        (rec.user?`<span style="font-size:10px;color:var(--cb-os4)">${escapeHtml(rec.user)}</span>`:'')+
        `<span style="font-size:9px;color:var(--cb-os3);margin-left:auto;flex-shrink:0">${escapeHtml(rec.source)}</span>`;
      card.appendChild(hdr);

      const body2=document.createElement('div');
      body2.style.cssText='padding:10px 12px;display:flex;flex-direction:column;gap:8px';

      // Command line (if informative and differs from content)
      if (rec.cmdline && rec.cmdline!==rec.content && rec.cmdline.length>5) {
        const d=document.createElement('div');
        d.innerHTML=`<div style="font-size:9px;color:#537173;text-transform:uppercase;font-weight:700;margin-bottom:4px">Command Line</div>
          <div class="amsi-code capped">${amsiHlCmd(rec.cmdline,query)}</div>`;
        body2.appendChild(d);
      }

      // Decoded PowerShell
      if (rec.decodedPS) {
        const d=document.createElement('div');
        d.innerHTML=`<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
          <div style="font-size:9px;color:#4caf80;text-transform:uppercase;font-weight:700">🔓 Decoded PowerShell</div>
          <button onclick="amsiCopy(${rec.amsiId},'decoded',this)" style="font-size:9px;padding:1px 7px;background:rgba(255,215,0,0.1);border:1px solid var(--cb-yellow);color:var(--cb-yellow);border-radius:3px;cursor:pointer">Copy</button>
        </div>
        <div class="amsi-code">${amsiHlPS(rec.decodedPS,query)}</div>`;
        body2.appendChild(d);
      }

      // Raw / additional content
      if (rec.content && rec.content!==rec.cmdline) {
        const d=document.createElement('div');
        d.innerHTML=`<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
          <div style="font-size:9px;color:#537173;text-transform:uppercase;font-weight:700">${escapeHtml(rec.source)}</div>
          <button onclick="amsiCopy(${rec.amsiId},'raw',this)" style="font-size:9px;padding:1px 7px;background:rgba(255,215,0,0.1);border:1px solid var(--cb-yellow);color:var(--cb-yellow);border-radius:3px;cursor:pointer">Copy</button>
        </div>
        <div class="amsi-code">${amsiIsJson(rec.content)?amsiHlJSON(rec.content,query):amsiHlPS(rec.content,query)}</div>`;
        body2.appendChild(d);
      }

      card.appendChild(body2);

      card.addEventListener('contextmenu', function(e) {
        function clip(text) { navigator.clipboard.writeText(text||'').catch(function(){}); }
        const items = [
          { type: 'label',   text: (rec.fname || rec.action || 'Script') + (rec.pid ? '  ·  PID ' + rec.pid : '') },
          { type: 'preview', text: rec.decodedPS || rec.content || rec.cmdline || '' },
          { type: 'sep' },
        ];
        if (rec.decodedPS) items.push({ type: 'item', icon: '📋', text: 'Copy decoded PowerShell', fn: function(){ clip(rec.decodedPS); } });
        if (rec.content && rec.content !== rec.cmdline) items.push({ type: 'item', icon: '📋', text: 'Copy raw content', fn: function(){ clip(rec.content); } });
        if (rec.cmdline)  items.push({ type: 'item', icon: '📋', text: 'Copy command line', fn: function(){ clip(rec.cmdline); } });
        if (rec.fname)    items.push({ type: 'item', icon: '📋', text: 'Copy process name', fn: function(){ clip(rec.fname); } });
        if (rec.device)   items.push({ type: 'item', icon: '📋', text: 'Copy device',       fn: function(){ clip(rec.device); } });
        items.push({ type: 'sep' });
        if (rec.fname)  items.push({ type: 'item', icon: '🔍', text: 'Filter table by process', fn: function(){
          const id = ++filterRowCounter;
          filterRows.push({ id, col:'', mode:'contains', value: rec.fname, connector:'AND' });
          renderFilterRows();
          document.getElementById('filterBar').classList.remove('hidden');
          applyFilter();
        }});
        if (rec.device) items.push({ type: 'item', icon: '🔍', text: 'Filter table by device', fn: function(){
          const id = ++filterRowCounter;
          filterRows.push({ id, col:'', mode:'contains', value: rec.device, connector:'AND' });
          renderFilterRows();
          document.getElementById('filterBar').classList.remove('hidden');
          applyFilter();
        }});
        // CyberChef pivot for encoded content
        const b64m = (rec.cmdline||'').match(/-enc(?:odedCommand)?\s+([A-Za-z0-9+\/=]+)/i);
        if (b64m) items.push({ type: 'sep' }, { type: 'item', icon: '⚗️', text: 'CyberChef  (decode -enc)', url: 'https://cyberchef.org/#input=' + encodeURIComponent(btoa(b64m[1])) });
        // Query builders
        if (typeof ctxQueryItems === 'function' && rec.cmdline) {
          var _sq = ctxQueryItems('process command line', rec.cmdline, 'cmdline');
          if (_sq.length) { items.push({ type: 'sep' }); _sq.forEach(function(q){ items.push(q); }); }
        }
        if (typeof ctxQueryItems === 'function' && rec.fname) {
          var _sfq = ctxQueryItems('file name', rec.fname, rec.fname);
          if (_sfq.length) { items.push({ type: 'sep' }); _sfq.forEach(function(q){ items.push(q); }); }
        }
        // Add to query builder
        if (typeof qbAddCondition === 'function') {
          if (rec.cmdline) items.push({ type:'item', icon:'➕', text:'Add cmdline to QB',
            fn: (function(v){ return function(){ qbAddCondition('process command line', v, 'cmdline: '+(v.length>20?v.slice(0,17)+'…':v)); }; })(rec.cmdline) });
          if (rec.fname)   items.push({ type:'item', icon:'➕', text:'Add process to QB',
            fn: (function(v){ return function(){ qbAddCondition('file name', v, 'process: '+v); }; })(rec.fname) });
        }
        showCtxMenu(e, items);
      });

      frag.appendChild(card);
    });
    body.appendChild(frag);
  }

  function amsiIsJson(text) {
    const t = (text || '').trim();
    return (t.startsWith('{') || t.startsWith('['));
  }

  function amsiHlJSON(text, q) {
    let s = escapeHtml(text);
    // JSON keys
    s = s.replace(/"([^"\\]*(?:\\.[^"\\]*)*)"\s*:/g,
      '<span style="color:#3a9fd6">"$1"</span>:');
    // String values
    s = s.replace(/:\s*"([^"\\]*(?:\\.[^"\\]*)*)"/g,
      (m, v) => `: <span style="color:#4caf80">"${v}"</span>`);
    // Numbers
    s = s.replace(/:\s*(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
      (m, n) => `: <span style="color:#f0a500">${n}</span>`);
    // Booleans and null
    s = s.replace(/:\s*(true|false|null)\b/g,
      (m, b) => `: <span style="color:#c45ab3">${b}</span>`);
    if (q) {
      const esc = escapeHtml(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      s = s.replace(new RegExp(`(${esc})`, 'gi'),
        '<mark style="background:rgba(255,215,0,0.35);color:inherit;border-radius:2px;padding:0 1px">$1</mark>');
    }
    return s;
  }

  function amsiHlPS(text, q) {
    let s=escapeHtml(text);
    // Comments first — before other replacements inject # into CSS color values
    // Only match # after whitespace or start of line (PS comments), not inside CSS color:#xxx
    s=s.replace(/(^|[ \t])(#[^\n]+)/gm,'$1<span style="color:#537173;font-style:italic">$2</span>');
    // Dangerous/suspicious
    s=s.replace(/\b(Invoke-Expression|IEX|DownloadString|DownloadFile|WebClient|Net\.WebClient|FromBase64String|EncodedCommand|Bypass|Unrestricted|Hidden|Reflection\.Assembly|Assembly\.Load|shellcode|VirtualAlloc|CreateThread)\b/gi,
      '<span style="color:#e05c3a;font-weight:700">$1</span>');
    // Keywords
    s=s.replace(/\b(function|param|return|if|else|foreach|for|while|try|catch|finally|class|new|import|require|using)\b/gi,
      '<span style="color:#3a9fd6">$1</span>');
    // Variables
    s=s.replace(/\$[\w:]+/g,'<span style="color:#c45ab3">$&</span>');
    // Strings
    s=s.replace(/"(?:[^"\\]|\\.)*"/g,'<span style="color:#4caf80">$&</span>');
    s=s.replace(/'[^']*'/g,'<span style="color:#4caf80">$&</span>');
    // Search highlight
    if (q) {
      const esc=escapeHtml(q).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      s=s.replace(new RegExp(`(${esc})`,'gi'),'<mark style="background:rgba(255,215,0,0.35);color:inherit;border-radius:2px;padding:0 1px">$1</mark>');
    }
    return s;
  }

  function amsiHlCmd(text, q) {
    let s=escapeHtml(text);
    s=s.replace(/((?:^|\s)-[\w]+)/g,'<span style="color:#e05c3a">$1</span>');
    s=s.replace(/([A-Za-z]:\\[^\s&lt;&gt;"]+)/g,'<span style="color:#3a9fd6">$1</span>');
    s=s.replace(/-enc(?:odedCommand)?\s+([A-Za-z0-9+\/=]+)/gi,
      (m,b64)=>`-enc <span style="color:#f0a500;font-weight:700" title="base64 encoded">${b64}</span>`);
    if (q) {
      const esc=escapeHtml(q).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      s=s.replace(new RegExp(`(${esc})`,'gi'),'<mark style="background:rgba(255,215,0,0.35);color:inherit;border-radius:2px;padding:0 1px">$1</mark>');
    }
    return s;
  }
