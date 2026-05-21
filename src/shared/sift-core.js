// sift-core.js — Sift plugin registration system
// Modules call Sift.register() to declare detection, columns, features, and UI.
// The core (app, overview, proctree, query builder) reads from the active module
// instead of having hardcoded knowledge of each data source.

(function(global) {
  'use strict';

  var _modules     = [];   // all registered modules in priority order
  var _active      = null; // the currently detected module

  var Sift = {

    // ── Registration ─────────────────────────────────────────────────────────
    // Called by each module file to declare itself
    register: function(config) {
      _modules.push(config);
    },

    // ── Detection ─────────────────────────────────────────────────────────────
    // Called after a file loads — runs each module's detect() until one matches
    detect: function(headers) {
      _active = null;
      for (var i = 0; i < _modules.length; i++) {
        var mod = _modules[i];
        if (mod.detect && mod.detect(headers)) {
          _active = mod;
          break;
        }
      }

      // Keep global flags in sync for backward compatibility with existing code
      global.isChronicleData      = _active ? _active.name === 'chronicle'  : false;
      global.isWindowsSecurityLog = _active ? _active.name === 'windows'    : false;

      return _active;
    },

    // ── Active module access ──────────────────────────────────────────────────
    getActiveModule:   function() { return _active; },
    getModuleName:     function() { return _active ? _active.name : null; },

    // Column mapping — returns the actual CSV column name for a semantic key
    // e.g. Sift.col('ts') → 'Timestamp' or 'TimeCreated' depending on source
    col: function(key) {
      if (_active && _active.columns && _active.columns[key]) return _active.columns[key];
      return null;
    },

    // Feature flag — should this toolbar button / feature be shown?
    hasFeature: function(feature) {
      if (!_active || !_active.features) return true; // default: show everything
      return _active.features.indexOf(feature) >= 0;
    },

    // Process tree action categories for the active module
    getActionCategories: function() {
      return _active && _active.actionCategories ? _active.actionCategories : null;
    },

    // Query builder — build a native query string for the active module
    buildQuery: function(column, value, operator) {
      if (_active && _active.buildQuery) return _active.buildQuery(column, value, operator || 'eq');
      return null;
    },

    // Source badge config { text, background, border, color }
    getBadge: function() {
      return _active && _active.badge ? _active.badge : null;
    },

    // Custom toolbar buttons registered by the active module
    getCustomButtons: function() {
      return _active && _active.customButtons ? _active.customButtons : [];
    },

    // Overview cards — module-specific cards to render in the overview panel
    // Returns array of DOM elements or null
    getOverviewCards: function(data, s) {
      if (_active && _active.overviewCards) return _active.overviewCards(data, s);
      return [];
    },

    // Investigation profile card ordering override from active module
    getProfileOrder: function(profile) {
      if (_active && _active.profileCards && _active.profileCards[profile]) {
        return _active.profileCards[profile];
      }
      return null;
    },

    // Reset — called when a new file loads before detection runs
    reset: function() {
      _active = null;
      global.isChronicleData      = false;
      global.isWindowsSecurityLog = false;
    },

    // List all registered module names (for debugging)
    listModules: function() {
      return _modules.map(function(m) { return m.name; });
    },
  };

  global.Sift = Sift;

})(window);
