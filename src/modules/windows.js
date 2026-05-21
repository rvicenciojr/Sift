// modules/windows.js — Windows Security Event Log
// Registers with Sift plugin system. References shared functions (loaded before modules).

(function() {
  'use strict';

  Sift.register({
    name: 'windows',

    detect: function(headers) {
      if (!headers || !headers.length) return false;
      var SIGNALS = [
        'eventid','event id','subjectusername','subject user name',
        'targetusername','target user name','logontype','logon type',
        'newprocessname','parentprocessname','ipaddress',
        'authenticationpackagename','workstationname',
      ];
      var lower = headers.map(function(h) { return (h||'').toLowerCase().trim(); });
      var hits = SIGNALS.filter(function(s) { return lower.indexOf(s) >= 0; });
      return hits.length >= 3;
    },

    badge: {
      text: 'Windows Security', bg: 'rgba(0,188,102,0.15)',
      border: '1px solid #00bc66', color: '#00bc66',
    },

    columns: {
      ts:         'TimeCreated',
      device:     'Computer',
      action:     'EventID',
      user:       'TargetUserName',
      cmdline:    'CommandLine',
      fileName:   'NewProcessName',
      initFile:   'ParentProcessName',
      remoteIp:   'IpAddress',
      remotePort: 'IpPort',
      winEventId:     'EventID',
      winLogonType:   'LogonType',
      winSubjectUser: 'SubjectUserName',
      winTargetUser:  'TargetUserName',
      winStatus:      'Status',
      winAuthPkg:     'AuthenticationPackageName',
    },

    features: [
      'overview', 'timeline',
      'process-tree', 'script-decoder', 'query-builder',
      // network-map intentionally excluded — not useful for Security log data
    ],

    get actionCategories() {
      return (typeof PT_ACTION_CATS_WINSEC !== 'undefined') ? PT_ACTION_CATS_WINSEC : [];
    },

    queryLabel: 'Sentinel KQL',
    buildQuery: function(col, val) {
      return (typeof buildSentinelKQL === 'function') ? buildSentinelKQL(col, val) : null;
    },
    buildQueryMulti: function(conditions, logic) {
      return (typeof buildSentinelKQLMulti === 'function') ? buildSentinelKQLMulti(conditions, logic) : null;
    },
  });

  window.SIFT_MODULE_WINDOWS = true;
})();
