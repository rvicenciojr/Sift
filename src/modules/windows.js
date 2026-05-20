// modules/windows.js — Windows Security Event Log module
// Loaded only in windows-enabled variants.
// Sets the module flag so shared code knows Windows features are available.
// Windows-specific detection (isWindowsSecurityLog) and overview cards live in
// shared/datasource.js and shared/overview.js for now and will migrate here over time.

(function() {
  window.SIFT_MODULE_WINDOWS = true;
})();
