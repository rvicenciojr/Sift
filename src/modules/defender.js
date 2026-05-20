// modules/defender.js — Microsoft Defender for Endpoint module
// Loaded only in defender-enabled variants.
// Defender detection (ptHasDefenderCols) lives in shared/datasource.js for now.
// Defender-specific KQL query building and overview cards will migrate here over time.

(function() {
  window.SIFT_MODULE_DEFENDER = true;
})();
