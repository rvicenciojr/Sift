// modules/defender.js — Microsoft Defender for Endpoint
// Registers with Sift plugin system. References shared functions (loaded before modules).

(function() {
  'use strict';

  Sift.register({
    name: 'defender',

    detect: function() {
      return (typeof ptHasDefenderCols === 'function') ? ptHasDefenderCols() : false;
    },

    badge: {
      text: 'Defender', bg: 'rgba(0,120,212,0.15)',
      border: '1px solid #0078d4', color: '#0078d4',
    },

    columns: {
      ts: 'Timestamp', device: 'DeviceName', user: 'AccountName',
      action: 'ActionType', fileName: 'FileName', cmdline: 'ProcessCommandLine',
      initFile: 'InitiatingProcessFileName', initCmd: 'InitiatingProcessCommandLine',
      remoteIp: 'RemoteIP', remoteUrl: 'RemoteUrl', remotePort: 'RemotePort',
      regKey: 'RegistryKey', regVal: 'RegistryValueName', regData: 'RegistryValueData',
      sha256: 'SHA256', sha1: 'SHA1', md5: 'MD5',
      integrity: 'ProcessIntegrityLevel', filePath: 'FolderPath',
    },

    features: [
      'overview', 'timeline', 'bytes',
      'process-tree', 'network-map', 'script-decoder', 'query-builder',
    ],

    get actionCategories() {
      return (typeof PT_ACTION_CATS_DEFENDER !== 'undefined') ? PT_ACTION_CATS_DEFENDER : [];
    },

    queryLabel: 'Defender KQL',
    buildQuery: function(col, val) {
      return (typeof buildDefenderQuery === 'function') ? buildDefenderQuery(col, val) : null;
    },
    buildQueryMulti: function(conditions, logic) {
      return (typeof buildDefenderQueryMulti === 'function') ? buildDefenderQueryMulti(conditions, logic) : null;
    },
  });

  window.SIFT_MODULE_DEFENDER = true;
})();
