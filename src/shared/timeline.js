// timeline.js — Timeline & Bytes chart
/* globals allRows, tags, applyFilter, toDatetimeLocal */

// ── Timeline ──
  var timelineVisible = false;
  var tlDragStart = null; // bucket index where drag began

  var TL_HL_COLORS = {
    'hl-red':'#f87171','hl-orange':'#fb923c','hl-yellow':'#eab308',
    'hl-green':'#4ade80','hl-purple':'#c084fc','hl-pink':'#f472b6',
    'hl-teal':'#2dd4bf','hl-cyan':'#22d3ee','hl-grey':'#9ca3af',
  };
  var TL_PRIORITY = ['hl-red','hl-orange','hl-yellow','hl-green','hl-purple','hl-pink','hl-teal','hl-cyan','hl-grey'];

  function toggleTimeline() {
    timelineVisible = !timelineVisible;
    const bar = document.getElementById('timelineBar');
    const btn = document.getElementById('timelineToggle');
    if (timelineVisible) {
      bar.classList.remove('hidden');
      btn.classList.add('active');
      renderTimeline();
    } else {
      bar.classList.add('hidden');
      btn.classList.remove('active');
    }
    saveTabState();
  }

  function tlBucketSize(spanMs) {
    if (spanMs <= 2  * 60 * 60 * 1000)  return 60 * 1000;           // ≤2h  → 1min buckets
    if (spanMs <= 48 * 60 * 60 * 1000)  return 60 * 60 * 1000;      // ≤2d  → 1hr buckets
    if (spanMs <= 60 * 24 * 60 * 60 * 1000) return 24 * 60 * 60 * 1000; // ≤60d → 1day
    return 7 * 24 * 60 * 60 * 1000;                                  // else → 1week
  }

  function tlFormatLabel(t, bucketMs) {
    const d = new Date(t);
    if (bucketMs < 60 * 60 * 1000)
      return d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0');
    if (bucketMs < 24 * 60 * 60 * 1000)
      return (d.getMonth()+1) + '/' + d.getDate() + ' ' + d.getHours() + 'h';
    return (d.getMonth()+1) + '/' + d.getDate();
  }

  function tlFormatFull(t) {
    const d = new Date(t);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
  }

  function renderTimeline() {
    if (!timelineVisible) return;
    const canvas = document.getElementById('timelineCanvas');
    if (!canvas) return;

    const tsColEl = document.getElementById('tsColSelect');
    const tsCol = tsColEl ? tsColEl.value : '';
    if (!tsCol || !allRows.length) return;

    // Build timestamped row list
    const stamped = allRows.map(row => {
      const t = Date.parse((row[tsCol] != null ? row[tsCol] : ''));
      return isNaN(t) ? null : { row, t };
    }).filter(Boolean);
    if (!stamped.length) return;

    const times = stamped.map(r => r.t);
    let minT = times[0], maxT = times[0];
    for (let i = 1; i < times.length; i++) { if (times[i] < minT) minT = times[i]; if (times[i] > maxT) maxT = times[i]; }
    const spanMs = maxT - minT || 1;

    let bucketMs = tlBucketSize(spanMs);
    // Clamp to at most 300 bars
    while (Math.ceil(spanMs / bucketMs) > 300) bucketMs *= 2;

    const startT = Math.floor(minT / bucketMs) * bucketMs;
    const numBuckets = Math.ceil((maxT - startT + 1) / bucketMs);

    // Build buckets
    const buckets = Array.from({ length: numBuckets }, (_, i) => ({
      t: startT + i * bucketMs,
      total: 0,
      hl: {},       // { 'hl-red': count, ... }
    }));

    stamped.forEach(({ row, t }) => {
      const bi = Math.floor((t - startT) / bucketMs);
      if (bi < 0 || bi >= buckets.length) return;
      buckets[bi].total++;
      const rowText = row._rt || Object.values(row).join(' ').toLowerCase();
      const hlCls = TL_PRIORITY.find(p => tags.find(tag => tag.colour === p && rowText.includes(tag.term.toLowerCase())));
      if (hlCls) buckets[bi].hl[hlCls] = (buckets[bi].hl[hlCls] || 0) + 1;
    });

    // Canvas sizing
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.parentElement.clientWidth - 32; // account for padding
    const H = 88;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, W, H);

    const padT = 4, padB = 20;
    const chartH = H - padT - padB;
    let maxTotal = 1; buckets.forEach(b => { if (b.total > maxTotal) maxTotal = b.total; });
    const barW = W / buckets.length;

    // Current filter range
    const fromMs = document.getElementById('tsFrom').value ? new Date(document.getElementById('tsFrom').value).getTime() : null;
    const toMs   = document.getElementById('tsTo').value   ? new Date(document.getElementById('tsTo').value).getTime()   : null;

    // Draw range highlight overlay
    if (fromMs || toMs) {
      const x1 = fromMs ? Math.max(0, ((fromMs - startT) / bucketMs) * barW) : 0;
      const x2 = toMs   ? Math.min(W, ((toMs - startT) / bucketMs + 1) * barW) : W;
      ctx.fillStyle = 'rgba(255,215,0,0.08)';
      ctx.fillRect(x1, padT, x2 - x1, chartH);
      ctx.strokeStyle = 'rgba(255,215,0,0.35)';
      ctx.lineWidth = 1;
      if (fromMs) { ctx.beginPath(); ctx.moveTo(x1, padT); ctx.lineTo(x1, padT + chartH); ctx.stroke(); }
      if (toMs)   { ctx.beginPath(); ctx.moveTo(x2, padT); ctx.lineTo(x2, padT + chartH); ctx.stroke(); }
    }

    // Draw bars
    buckets.forEach((b, i) => {
      if (!b.total) return;
      const x  = i * barW;
      const bh = Math.max(2, (b.total / maxTotal) * chartH);
      const y  = padT + chartH - bh;
      const inRange = (!fromMs || b.t + bucketMs > fromMs) && (!toMs || b.t <= toMs);

      // Base bar
      ctx.fillStyle = inRange ? '#537173' : '#304D4A';
      ctx.fillRect(x + 0.5, y, Math.max(1, barW - 1), bh);

      // Highlight colour stacked on top
      const topHl = TL_PRIORITY.find(p => b.hl[p] > 0);
      if (topHl) {
        const hlH = Math.max(2, (b.hl[topHl] / b.total) * bh);
        ctx.fillStyle = TL_HL_COLORS[topHl];
        ctx.fillRect(x + 0.5, y, Math.max(1, barW - 1), hlH);
      }
    });

    // Time axis labels
    ctx.fillStyle = '#778F8D';
    ctx.font = '9px system-ui, sans-serif';
    ctx.textAlign = 'center';
    const maxLabels = Math.floor(W / 60);
    const labelStep = Math.max(1, Math.round(buckets.length / maxLabels));
    for (let i = 0; i < buckets.length; i += labelStep) {
      const x = (i + 0.5) * barW;
      ctx.fillText(tlFormatLabel(buckets[i].t, bucketMs), x, H - 5);
    }

    // Store buckets for mouse interaction
    canvas._buckets  = buckets;
    canvas._startT   = startT;
    canvas._bucketMs = bucketMs;
    canvas._barW     = barW;
    canvas._padT     = padT;
    canvas._chartH   = chartH;
    canvas._maxTotal = maxTotal;
    // Save pixel data so drag overlay can restore bars cheaply without a full redraw
    canvas._basePixels = ctx.getImageData(0, 0, canvas.width, canvas.height);

    // Attach mouse handlers once
    if (!canvas._tlReady) {
      canvas._tlReady = true;

      const tooltip = document.getElementById('timelineTooltip');

      canvas.addEventListener('mousemove', e => {
        const rect = canvas.getBoundingClientRect();
        const bi = Math.floor((e.clientX - rect.left) / canvas._barW);
        const b  = (canvas._buckets || [])[bi];

        // Tooltip
        if (!b || !b.total) {
          tooltip.style.display = 'none';
        } else {
          const lines = [`🕐 ${tlFormatFull(b.t)} — ${tlFormatFull(b.t + canvas._bucketMs)}`];
          lines.push(`Events: ${b.total.toLocaleString()}`);
          const topHl = TL_PRIORITY.find(p => b.hl[p] > 0);
          if (topHl) lines.push(`Highlighted: ${Object.values(b.hl).reduce((a,v)=>a+v,0).toLocaleString()}`);
          tooltip.innerHTML = lines.join('<br>');
          tooltip.style.display = 'block';
          const tx = Math.min(e.clientX + 14, window.innerWidth - 220);
          tooltip.style.left = tx + 'px';
          tooltip.style.top  = (e.clientY - 10) + 'px';
        }

        if (tlDragStart !== null) {
          const lo = Math.min(tlDragStart, bi);
          const hi = Math.max(tlDragStart, bi);
          const b1 = (canvas._buckets || [])[lo];
          const b2 = (canvas._buckets || [])[hi];
          if (b1 && b2) {
            // Update inputs for display — no applyFilter during drag
            document.getElementById('tsFrom').value = toDatetimeLocal(new Date(b1.t));
            document.getElementById('tsTo').value   = toDatetimeLocal(new Date(b2.t + canvas._bucketMs - 1));
            // Draw selection overlay using RAF — canvas only, no DOM/filter work
            if (!canvas._rafPending) {
              canvas._rafPending = true;
              requestAnimationFrame(() => {
                canvas._rafPending = false;
                tlDrawDragOverlay(canvas, lo, hi);
              });
            }
          }
        }
      });

      canvas.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });

      canvas.addEventListener('mousedown', e => {
        const rect = canvas.getBoundingClientRect();
        tlDragStart = Math.floor((e.clientX - rect.left) / canvas._barW);
      });

      canvas.addEventListener('mouseup', e => {
        if (tlDragStart === null) return;
        const rect = canvas.getBoundingClientRect();
        const bi   = Math.floor((e.clientX - rect.left) / canvas._barW);
        const lo   = Math.min(tlDragStart, bi);
        const hi   = Math.max(tlDragStart, bi);
        tlDragStart = null;

        const bs = canvas._buckets || [];
        const b1 = bs[lo], b2 = bs[hi];
        if (!b1 || !b2) return;

        // Single click on empty bar = do nothing (double-click clears range)
        if (lo === hi && !b1.total) return;
        document.getElementById('tsFrom').value = toDatetimeLocal(new Date(b1.t));
        document.getElementById('tsTo').value   = toDatetimeLocal(new Date(b2.t + canvas._bucketMs - 1));
        applyFilter();
      });

      // Double-click clears range
      canvas.addEventListener('dblclick', () => {
        tlDragStart = null;
        document.getElementById('tsFrom').value = '';
        document.getElementById('tsTo').value   = '';
        applyFilter();
      });
    }
  }

  // Draw drag selection overlay — restores saved pixels then draws rect, no DOM/filter work
  function tlDrawDragOverlay(canvas, lo, hi) {
    const ctx = canvas.getContext('2d');
    if (canvas._basePixels) ctx.putImageData(canvas._basePixels, 0, 0);
    const dpr  = window.devicePixelRatio || 1;
    const barW = canvas._barW || 1;
    const padT = canvas._padT || 4;
    const chartH = canvas._chartH || 64;
    const x1 = lo * barW;
    const x2 = (hi + 1) * barW;
    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.fillStyle = 'rgba(255,215,0,0.18)';
    ctx.fillRect(x1, padT, x2 - x1, chartH);
    ctx.strokeStyle = 'rgba(255,215,0,0.7)';
    ctx.lineWidth = 1.5;
    ctx.strokeRect(x1 + 0.5, padT + 0.5, x2 - x1 - 1, chartH - 1);
    ctx.restore();
  }

  function toDatetimeLocal(d) {
    // Returns yyyy-MM-ddTHH:mm for datetime-local input
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  // ── Bytes Chart ──
  var bytesVisible = false;

  var BC_COL1_COLOR = '#2dd4bf'; // teal — col 1 (e.g. received)
  var BC_COL2_COLOR = '#fb923c'; // orange — col 2 (e.g. sent)

  function toggleBytesChart() {
    bytesVisible = !bytesVisible;
    const bar = document.getElementById('bytesBar');
    const btn = document.getElementById('bytesToggle');
    if (bytesVisible) {
      bar.classList.remove('hidden');
      btn.classList.add('active');
      populateBytesColSelects();
      renderBytesChart();
    } else {
      bar.classList.add('hidden');
      btn.classList.remove('active');
    }
    saveTabState();
  }

  function detectByteColumns() {
    const BYTE_KW = ['byte','sent','received','upload','download','size','transfer','traffic','rx','tx','octet','length','data','in','out','network'];
    return headers.filter(h => {
      const lower = h.toLowerCase();
      if (!BYTE_KW.some(k => lower.includes(k))) return false;
      const samples = allRows.slice(0, 30).map(r => r[h]).filter(v => v && String(v).trim());
      if (!samples.length) return false;
      return samples.filter(v => !isNaN(parseFloat(v))).length >= Math.ceil(samples.length * 0.6);
    });
  }

  function populateBytesColSelects() {
    const detected = detectByteColumns();
    const safeH = h => h.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    const makeOptions = (includeNone) => {
      const none = includeNone ? '<option value="">— none —</option>' : '<option value="">— auto —</option>';
      return none + headers.map(h => `<option value="${safeH(h)}">${h}</option>`).join('');
    };
    const sel1 = document.getElementById('bytesColSelect');
    const sel2 = document.getElementById('bytesCol2Select');
    sel1.innerHTML = makeOptions(false);
    sel2.innerHTML = makeOptions(true);
    if (detected[0]) sel1.value = detected[0];
    if (detected[1]) sel2.value = detected[1];
    updateBytesLegend();
  }

  function updateBytesLegend() {
    const col1 = document.getElementById('bytesColSelect').value;
    const col2 = document.getElementById('bytesCol2Select').value;
    const legend = document.getElementById('bytesLegend');
    if (!legend) return;
    legend.innerHTML = '';
    if (col1) {
      const sw = document.createElement('span');
      sw.style.cssText = `display:inline-block;width:10px;height:10px;background:${BC_COL1_COLOR};border-radius:2px;margin-right:3px`;
      legend.appendChild(sw);
      legend.appendChild(document.createTextNode(col1));
    }
    if (col2) {
      const sw = document.createElement('span');
      sw.style.cssText = `display:inline-block;width:10px;height:10px;background:${BC_COL2_COLOR};border-radius:2px;margin-left:10px;margin-right:3px`;
      legend.appendChild(sw);
      legend.appendChild(document.createTextNode(col2));
    }
  }

  function formatBytes(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
    if (b >= 1048576)    return (b / 1048576).toFixed(1)    + ' MB';
    if (b >= 1024)       return (b / 1024).toFixed(1)       + ' KB';
    return Math.round(b).toLocaleString() + ' B';
  }

  function renderBytesChart() {
    if (!bytesVisible) return;
    const canvas = document.getElementById('bytesCanvas');
    if (!canvas) return;
    updateBytesLegend();

    const tsColEl = document.getElementById('tsColSelect');
    const tsCol   = tsColEl ? tsColEl.value : '';
    const col1    = document.getElementById('bytesColSelect').value;
    const col2    = document.getElementById('bytesCol2Select').value;
    if (!tsCol || !col1 || !allRows.length) return;

    const stamped = allRows.map(row => {
      const t = Date.parse((row[tsCol] != null ? row[tsCol] : ''));
      if (isNaN(t)) return null;
      return { t, v1: parseFloat((row[col1] != null ? row[col1] : '')) || 0, v2: col2 ? (parseFloat((row[col2] != null ? row[col2] : '')) || 0) : 0, row };
    }).filter(Boolean);
    if (!stamped.length) return;

    const times  = stamped.map(r => r.t);
    let minT = times[0], maxT = times[0];
    for (let i = 1; i < times.length; i++) { if (times[i] < minT) minT = times[i]; if (times[i] > maxT) maxT = times[i]; }
    const spanMs = maxT - minT || 1;

    let bucketMs = tlBucketSize(spanMs);
    while (Math.ceil(spanMs / bucketMs) > 300) bucketMs *= 2;

    const startT     = Math.floor(minT / bucketMs) * bucketMs;
    const numBuckets = Math.ceil((maxT - startT + 1) / bucketMs);
    const buckets    = Array.from({ length: numBuckets }, (_, i) => ({ t: startT + i * bucketMs, v1: 0, v2: 0, hlV1: 0, hlV2: 0, hlColor: null }));

    stamped.forEach(({ t, v1, v2, row }) => {
      const bi = Math.floor((t - startT) / bucketMs);
      if (bi < 0 || bi >= buckets.length) return;
      buckets[bi].v1 += v1;
      buckets[bi].v2 += v2;
      const rowText = row._rt || Object.values(row).join(' ').toLowerCase();
      const hlCls = TL_PRIORITY.find(p => tags.find(tag => tag.colour === p && rowText.includes(tag.term.toLowerCase())));
      if (hlCls) {
        buckets[bi].hlV1 += v1;
        buckets[bi].hlV2 += v2;
        if (!buckets[bi].hlColor) buckets[bi].hlColor = hlCls;
      }
    });

    const dpr    = window.devicePixelRatio || 1;
    const W      = canvas.parentElement.clientWidth - 32;
    const H      = 100;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    const ctx    = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, W, H);

    const padL = 62, padT = 6, padB = 20, padR = 8;
    const chartW = W - padL - padR;
    const chartH = H - padT - padB;
    let maxVal = 1; buckets.forEach(b => { const s = b.v1 + b.v2; if (s > maxVal) maxVal = s; });
    const barW   = chartW / buckets.length;

    // Grid + Y-axis labels
    ctx.textAlign = 'right';
    ctx.font      = '9px system-ui, sans-serif';
    [0, 0.25, 0.5, 0.75, 1].forEach(pct => {
      const y = padT + chartH - pct * chartH;
      ctx.fillStyle   = '#778F8D';
      ctx.fillText(formatBytes(pct * maxVal), padL - 4, y + 3);
      ctx.strokeStyle = '#304D4A';
      ctx.lineWidth   = 0.5;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + chartW, y); ctx.stroke();
    });

    // Time range overlay
    const fromMs = document.getElementById('tsFrom').value ? new Date(document.getElementById('tsFrom').value).getTime() : null;
    const toMs   = document.getElementById('tsTo').value   ? new Date(document.getElementById('tsTo').value).getTime()   : null;
    if (fromMs || toMs) {
      const x1 = padL + (fromMs ? Math.max(0, ((fromMs - startT) / bucketMs) * barW) : 0);
      const x2 = padL + (toMs   ? Math.min(chartW, ((toMs - startT)   / bucketMs + 1) * barW) : chartW);
      ctx.fillStyle   = 'rgba(255,215,0,0.08)';
      ctx.fillRect(x1, padT, x2 - x1, chartH);
      ctx.strokeStyle = 'rgba(255,215,0,0.35)';
      ctx.lineWidth   = 1;
      if (fromMs) { ctx.beginPath(); ctx.moveTo(x1, padT); ctx.lineTo(x1, padT + chartH); ctx.stroke(); }
      if (toMs)   { ctx.beginPath(); ctx.moveTo(x2, padT); ctx.lineTo(x2, padT + chartH); ctx.stroke(); }
    }

    // Bars
    buckets.forEach((b, i) => {
      const total = b.v1 + b.v2;
      if (!total) return;
      const x   = padL + i * barW;
      const bw  = Math.max(1, barW - 1);

      if (col2) {
        // Stacked: col1 (teal) bottom, col2 (orange) on top
        const h1 = Math.max(1, (b.v1 / maxVal) * chartH);
        const h2 = Math.max(1, (b.v2 / maxVal) * chartH);
        const y1 = padT + chartH - h1;
        ctx.fillStyle = BC_COL1_COLOR; ctx.fillRect(x + 0.5, y1,      bw, h1);
        ctx.fillStyle = BC_COL2_COLOR; ctx.fillRect(x + 0.5, y1 - h2, bw, h2);
      } else {
        const h = Math.max(1, (b.v1 / maxVal) * chartH);
        ctx.fillStyle = BC_COL1_COLOR;
        ctx.fillRect(x + 0.5, padT + chartH - h, bw, h);
      }

      // Highlight cap: colour the top portion of the bar by bytes from highlighted rows
      if (b.hlColor && (b.hlV1 + b.hlV2) > 0) {
        const totalH  = col2 ? Math.max(1,(b.v1/maxVal)*chartH) + Math.max(1,(b.v2/maxVal)*chartH)
                              : Math.max(1,(b.v1/maxVal)*chartH);
        const hlH     = Math.max(2, ((b.hlV1 + b.hlV2) / maxVal) * chartH);
        const capH    = Math.min(hlH, totalH);
        const topY    = padT + chartH - totalH;
        ctx.fillStyle = TL_HL_COLORS[b.hlColor];
        ctx.fillRect(x + 0.5, topY, bw, capH);
      }
    });

    // X-axis labels
    ctx.fillStyle  = '#778F8D';
    ctx.font       = '9px system-ui, sans-serif';
    ctx.textAlign  = 'center';
    const maxLbls  = Math.floor(chartW / 60);
    const lblStep  = Math.max(1, Math.round(buckets.length / maxLbls));
    for (let i = 0; i < buckets.length; i += lblStep) {
      ctx.fillText(tlFormatLabel(buckets[i].t, bucketMs), padL + (i + 0.5) * barW, H - 5);
    }

    // Store state for mouse events
    canvas._bc = { buckets, startT, bucketMs, barW, padL, padT, chartH, maxVal, col1, col2 };
    canvas._basePixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);

    if (!canvas._bcReady) {
      canvas._bcReady = true;
      const tooltip   = document.getElementById('bytesTooltip');
      let   bcDrag    = null;

      canvas.addEventListener('mousemove', e => {
        const s  = canvas._bc;
        if (!s) return;
        const rect = canvas.getBoundingClientRect();
        const bi = Math.floor((e.clientX - rect.left - s.padL) / s.barW);
        const b  = (s.buckets || [])[bi];
        if (!b) { tooltip.style.display = 'none'; return; }

        const _esc = c => String(c).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        const lines = [`🕐 ${tlFormatFull(b.t)}`];
        lines.push(`${_esc(s.col1)}: ${formatBytes(b.v1)}`);
        if (s.col2) lines.push(`${_esc(s.col2)}: ${formatBytes(b.v2)}`);
        if (s.col2) lines.push(`Total: ${formatBytes(b.v1 + b.v2)}`);

        tooltip.innerHTML = lines.join('<br>');
        tooltip.style.display = 'block';
        tooltip.style.left = Math.min(e.clientX + 14, window.innerWidth - 240) + 'px';
        tooltip.style.top  = (e.clientY - 10) + 'px';

        if (bcDrag !== null) {
          const lo = Math.min(bcDrag, bi), hi = Math.max(bcDrag, bi);
          const b1 = (s.buckets || [])[lo], b2 = (s.buckets || [])[hi];
          if (b1 && b2) {
            // Update inputs only — applyFilter fires on mouseup
            document.getElementById('tsFrom').value = toDatetimeLocal(new Date(b1.t));
            document.getElementById('tsTo').value   = toDatetimeLocal(new Date(b2.t + s.bucketMs - 1));
            // RAF-throttled drag indicator on bytes canvas
            if (!canvas._rafPending) {
              canvas._rafPending = true;
              requestAnimationFrame(() => {
                canvas._rafPending = false;
                const ctx2 = canvas.getContext('2d');
                if (canvas._basePixels) ctx2.putImageData(canvas._basePixels, 0, 0);
                const dpr2 = window.devicePixelRatio || 1;
                const x1 = s.padL + lo * s.barW, x2 = s.padL + (hi + 1) * s.barW;
                ctx2.save(); ctx2.scale(dpr2, dpr2);
                ctx2.fillStyle = 'rgba(255,215,0,0.15)';
                ctx2.fillRect(x1, s.padT, x2 - x1, s.chartH);
                ctx2.strokeStyle = 'rgba(255,215,0,0.6)'; ctx2.lineWidth = 1.5;
                ctx2.strokeRect(x1 + 0.5, s.padT + 0.5, x2 - x1 - 1, s.chartH - 1);
                ctx2.restore();
              });
            }
          }
        }
      });

      canvas.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });

      canvas.addEventListener('mousedown', e => {
        const s = canvas._bc; if (!s) return;
        const rect = canvas.getBoundingClientRect();
        bcDrag = Math.floor((e.clientX - rect.left - s.padL) / s.barW);
      });

      canvas.addEventListener('mouseup', e => {
        if (bcDrag === null) return;
        const s = canvas._bc; if (!s) return;
        const rect = canvas.getBoundingClientRect();
        const bi = Math.floor((e.clientX - rect.left - s.padL) / s.barW);
        const lo = Math.min(bcDrag, bi), hi = Math.max(bcDrag, bi);
        bcDrag   = null;
        const b1 = (s.buckets || [])[lo], b2 = (s.buckets || [])[hi];
        if (!b1 || !b2) return;
        // Single click on empty bar = do nothing (double-click clears range)
        if (lo === hi && !(b1.v1 + b1.v2)) return;
        document.getElementById('tsFrom').value = toDatetimeLocal(new Date(b1.t));
        document.getElementById('tsTo').value   = toDatetimeLocal(new Date(b2.t + s.bucketMs - 1));
        applyFilter();
      });

      canvas.addEventListener('dblclick', () => {
        bcDrag = null;
        document.getElementById('tsFrom').value = '';
        document.getElementById('tsTo').value   = '';
        applyFilter();
      });
    }
  }
