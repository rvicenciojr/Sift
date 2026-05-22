// modules/chronicle.js — Google Chronicle / UDM
// Registers with Sift plugin system. References shared functions (loaded before modules).

(function() {
  'use strict';

  Sift.register({
    name: 'chronicle',

    detect: function(headers) {
      // isChronicleData is set by detectChronicleData() BEFORE Sift.detect() is invoked,
      // so we just read the flag here. Calling detectChronicleData() back would recurse.
      return (typeof isChronicleData !== 'undefined') && isChronicleData;
    },

    badge: {
      text: 'Chronicle', bg: 'rgba(66,133,244,0.15)',
      border: '1px solid #4285f4', color: '#4285f4',
    },

    columns: {
      ts:         'metadata.event_timestamp',
      device:     'principal.hostname',
      user:       'principal.user.userid',
      action:     'metadata.event_type',
      cmdline:    'principal.process.command_line',
      remoteIp:   'target.ip',
      remotePort: 'target.port',
      sha256:     'principal.process.file.sha256',
      severity:   'security_result.severity',
    },

    features: [
      'overview', 'timeline', 'bytes',
      'process-tree', 'network-map', 'script-decoder', 'query-builder',
    ],

    get actionCategories() {
      return (typeof PT_ACTION_CATS_DEFENDER !== 'undefined') ? PT_ACTION_CATS_DEFENDER : [];
    },

    queryLabel: 'Chronicle UDM',
    buildQuery: function(col, val) {
      return (typeof buildChronicleQuery === 'function') ? buildChronicleQuery(col, val) : null;
    },
    buildQueryMulti: function(conditions, logic) {
      return (typeof buildChronicleQueryMulti === 'function') ? buildChronicleQueryMulti(conditions, logic) : null;
    },
  });

  window.SIFT_MODULE_CHRONICLE = true;
})();
