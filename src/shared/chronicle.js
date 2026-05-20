// chronicle.js — Chronicle / Google SecOps specific features
// Detection, column mapping, and query building live in datasource.js

  var CHRONICLE_URL_KEY = 'csv-viewer-chronicle-url';

  // ── Instance URL ──────────────────────────────────────────────────────────
  function getChronicleUrl() {
    try { return localStorage.getItem(CHRONICLE_URL_KEY) || ''; } catch { return ''; }
  }

  function setChronicleUrl(url) {
    try { localStorage.setItem(CHRONICLE_URL_KEY, (url || '').trim()); } catch {}
  }

  function openChronicleSettings() {
    const cur = getChronicleUrl();
    const url = prompt(
      'Enter your Chronicle / Google SecOps instance URL:\n' +
      'e.g.  https://yourorg.backstory.chronicle.security\n' +
      '      https://console.cloud.google.com/chronicle',
      cur
    );
    if (url !== null) setChronicleUrl(url);
  }

  // ── YARA-L generator ──────────────────────────────────────────────────────
  function generateYaraL(col, val) {
    const v    = (val  || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const udm  = colToUdmField(col) || 'metadata.description';
    const slug = (col || 'value').replace(/[^a-z0-9]/gi, '_').toLowerCase().slice(0, 28);

    let eventType = '';
    if (/process/.test(udm))  eventType = 'PROCESS_LAUNCH';
    else if (/target\.ip|target\.hostname|target\.port|network/.test(udm)) eventType = 'NETWORK_CONNECTION';
    else if (/target\.file/.test(udm))    eventType = 'FILE_CREATION';
    else if (/registry/.test(udm))        eventType = 'REGISTRY_VALUE_SET';
    else if (/user/.test(udm))            eventType = 'USER_LOGIN';

    const evtLine = eventType ? `    \$e.metadata.event_type = "${eventType}"\n` : '';

    return `rule detect_${slug} {
  meta:
    author      = "threat-hunter"
    description = "Detection: ${(col || 'field').slice(0, 40)} = ${val.slice(0, 40)}"
    severity    = "MEDIUM"
    priority    = "MEDIUM"

  events:
${evtLine}    \$e.${udm} = "${v}"

  condition:
    \$e
}`;
  }

  function copyYaraL(col, val) {
    const rule = generateYaraL(col, val);
    navigator.clipboard.writeText(rule).catch(function(){});
  }

  // ── Severity auto-highlight ───────────────────────────────────────────────
  var UDM_SEVERITY_COLOURS = {
    'critical':      'hl-red',
    'high':          'hl-orange',
    'medium':        'hl-yellow',
    'low':           'hl-green',
    'informational': 'hl-grey',
    'info':          'hl-grey',
    'none':          'hl-grey',
  };

  function applyChronicleAutoHighlights() {
    if (!isChronicleData) return;
    const sevCol = headers.find(function(h) {
      return /security_result\.severity$/i.test(h) || /^severity$/i.test(h);
    });
    if (!sevCol) return;
    const found = new Set(allRows.map(function(r) { return (r[sevCol] || '').toLowerCase(); }).filter(Boolean));
    let added = 0;
    Object.keys(UDM_SEVERITY_COLOURS).forEach(function(sev) {
      if (found.has(sev) && !tags.find(function(t) { return t.term.toLowerCase() === sev; })) {
        addTagObj({ term: sev, colour: UDM_SEVERITY_COLOURS[sev] });
        added++;
      }
    });
    if (added) applyFilter();
  }
