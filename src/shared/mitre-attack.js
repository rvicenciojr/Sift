// mitre-attack.js — MITRE ATT&CK Enterprise catalog + endpoint detection signatures
// Catalog: all Enterprise techniques + sub-techniques (ID, name, tactic)
// Detections: ~80 signatures detectable from Defender / Chronicle endpoint CSV logs

// ── Tactic definitions ────────────────────────────────────────────────────────
const MITRE_TACTICS = [
  { id:'TA0001', name:'Initial Access' },
  { id:'TA0002', name:'Execution' },
  { id:'TA0003', name:'Persistence' },
  { id:'TA0004', name:'Privilege Escalation' },
  { id:'TA0005', name:'Defense Evasion' },
  { id:'TA0006', name:'Credential Access' },
  { id:'TA0007', name:'Discovery' },
  { id:'TA0008', name:'Lateral Movement' },
  { id:'TA0009', name:'Collection' },
  { id:'TA0010', name:'Exfiltration' },
  { id:'TA0011', name:'Command and Control' },
  { id:'TA0040', name:'Impact' },
];

// ── Full technique catalog ────────────────────────────────────────────────────
// Format: { id, name, tactic, parent? }
// Sub-techniques have parent set to their parent technique ID
const MITRE_TECHNIQUES = [
  // ── Initial Access ──────────────────────────────────────────────────────────
  { id:'T1189', name:'Drive-by Compromise',                        tactic:'Initial Access' },
  { id:'T1190', name:'Exploit Public-Facing Application',          tactic:'Initial Access' },
  { id:'T1133', name:'External Remote Services',                   tactic:'Initial Access' },
  { id:'T1200', name:'Hardware Additions',                         tactic:'Initial Access' },
  { id:'T1566', name:'Phishing',                                   tactic:'Initial Access' },
  { id:'T1566.001', name:'Spearphishing Attachment',  parent:'T1566', tactic:'Initial Access' },
  { id:'T1566.002', name:'Spearphishing Link',        parent:'T1566', tactic:'Initial Access' },
  { id:'T1566.003', name:'Spearphishing via Service', parent:'T1566', tactic:'Initial Access' },
  { id:'T1091', name:'Replication Through Removable Media',        tactic:'Initial Access' },
  { id:'T1195', name:'Supply Chain Compromise',                    tactic:'Initial Access' },
  { id:'T1195.001', name:'Compromise Software Dependencies',       parent:'T1195', tactic:'Initial Access' },
  { id:'T1195.002', name:'Compromise Software Supply Chain',       parent:'T1195', tactic:'Initial Access' },
  { id:'T1195.003', name:'Compromise Hardware Supply Chain',       parent:'T1195', tactic:'Initial Access' },
  { id:'T1199', name:'Trusted Relationship',                       tactic:'Initial Access' },
  { id:'T1078', name:'Valid Accounts',                             tactic:'Initial Access' },
  { id:'T1078.001', name:'Default Accounts',          parent:'T1078', tactic:'Initial Access' },
  { id:'T1078.002', name:'Domain Accounts',           parent:'T1078', tactic:'Initial Access' },
  { id:'T1078.003', name:'Local Accounts',            parent:'T1078', tactic:'Initial Access' },
  { id:'T1078.004', name:'Cloud Accounts',            parent:'T1078', tactic:'Initial Access' },

  // ── Execution ───────────────────────────────────────────────────────────────
  { id:'T1059', name:'Command and Scripting Interpreter',          tactic:'Execution' },
  { id:'T1059.001', name:'PowerShell',                parent:'T1059', tactic:'Execution' },
  { id:'T1059.002', name:'AppleScript',               parent:'T1059', tactic:'Execution' },
  { id:'T1059.003', name:'Windows Command Shell',     parent:'T1059', tactic:'Execution' },
  { id:'T1059.004', name:'Unix Shell',                parent:'T1059', tactic:'Execution' },
  { id:'T1059.005', name:'Visual Basic',              parent:'T1059', tactic:'Execution' },
  { id:'T1059.006', name:'Python',                    parent:'T1059', tactic:'Execution' },
  { id:'T1059.007', name:'JavaScript',                parent:'T1059', tactic:'Execution' },
  { id:'T1059.008', name:'Network Device CLI',        parent:'T1059', tactic:'Execution' },
  { id:'T1059.009', name:'Cloud API',                 parent:'T1059', tactic:'Execution' },
  { id:'T1609', name:'Container Administration Command',           tactic:'Execution' },
  { id:'T1610', name:'Deploy Container',                           tactic:'Execution' },
  { id:'T1203', name:'Exploitation for Client Execution',          tactic:'Execution' },
  { id:'T1559', name:'Inter-Process Communication',                tactic:'Execution' },
  { id:'T1559.001', name:'Component Object Model',    parent:'T1559', tactic:'Execution' },
  { id:'T1559.002', name:'Dynamic Data Exchange',     parent:'T1559', tactic:'Execution' },
  { id:'T1106', name:'Native API',                                 tactic:'Execution' },
  { id:'T1053', name:'Scheduled Task / Job',                       tactic:'Execution' },
  { id:'T1053.001', name:'At',                        parent:'T1053', tactic:'Execution' },
  { id:'T1053.002', name:'At (Linux)',                parent:'T1053', tactic:'Execution' },
  { id:'T1053.003', name:'Cron',                      parent:'T1053', tactic:'Execution' },
  { id:'T1053.005', name:'Scheduled Task',            parent:'T1053', tactic:'Execution' },
  { id:'T1053.006', name:'Systemd Timers',            parent:'T1053', tactic:'Execution' },
  { id:'T1053.007', name:'Container Orchestration Job', parent:'T1053', tactic:'Execution' },
  { id:'T1129', name:'Shared Modules',                             tactic:'Execution' },
  { id:'T1072', name:'Software Deployment Tools',                  tactic:'Execution' },
  { id:'T1569', name:'System Services',                            tactic:'Execution' },
  { id:'T1569.001', name:'Launchctl',                 parent:'T1569', tactic:'Execution' },
  { id:'T1569.002', name:'Service Execution',         parent:'T1569', tactic:'Execution' },
  { id:'T1204', name:'User Execution',                             tactic:'Execution' },
  { id:'T1204.001', name:'Malicious Link',            parent:'T1204', tactic:'Execution' },
  { id:'T1204.002', name:'Malicious File',            parent:'T1204', tactic:'Execution' },
  { id:'T1204.003', name:'Malicious Image',           parent:'T1204', tactic:'Execution' },
  { id:'T1047', name:'Windows Management Instrumentation',         tactic:'Execution' },

  // ── Persistence ─────────────────────────────────────────────────────────────
  { id:'T1098', name:'Account Manipulation',                       tactic:'Persistence' },
  { id:'T1098.001', name:'Additional Cloud Credentials',  parent:'T1098', tactic:'Persistence' },
  { id:'T1098.002', name:'Additional Email Delegate Permissions', parent:'T1098', tactic:'Persistence' },
  { id:'T1098.003', name:'Additional Cloud Roles',        parent:'T1098', tactic:'Persistence' },
  { id:'T1098.004', name:'SSH Authorized Keys',           parent:'T1098', tactic:'Persistence' },
  { id:'T1098.005', name:'Device Registration',           parent:'T1098', tactic:'Persistence' },
  { id:'T1197', name:'BITS Jobs',                                  tactic:'Persistence' },
  { id:'T1547', name:'Boot or Logon Autostart Execution',          tactic:'Persistence' },
  { id:'T1547.001', name:'Registry Run Keys / Startup Folder', parent:'T1547', tactic:'Persistence' },
  { id:'T1547.002', name:'Authentication Package',        parent:'T1547', tactic:'Persistence' },
  { id:'T1547.003', name:'Time Providers',                parent:'T1547', tactic:'Persistence' },
  { id:'T1547.004', name:'Winlogon Helper DLL',           parent:'T1547', tactic:'Persistence' },
  { id:'T1547.005', name:'Security Support Provider',     parent:'T1547', tactic:'Persistence' },
  { id:'T1547.006', name:'Kernel Modules and Extensions', parent:'T1547', tactic:'Persistence' },
  { id:'T1547.007', name:'Re-opened Applications',        parent:'T1547', tactic:'Persistence' },
  { id:'T1547.008', name:'LSASS Driver',                  parent:'T1547', tactic:'Persistence' },
  { id:'T1547.009', name:'Shortcut Modification',         parent:'T1547', tactic:'Persistence' },
  { id:'T1547.010', name:'Port Monitors',                 parent:'T1547', tactic:'Persistence' },
  { id:'T1547.012', name:'Print Processors',              parent:'T1547', tactic:'Persistence' },
  { id:'T1547.013', name:'XDG Autostart Entries',         parent:'T1547', tactic:'Persistence' },
  { id:'T1547.014', name:'Active Setup',                  parent:'T1547', tactic:'Persistence' },
  { id:'T1037', name:'Boot or Logon Initialization Scripts',       tactic:'Persistence' },
  { id:'T1037.001', name:'Logon Script (Windows)',        parent:'T1037', tactic:'Persistence' },
  { id:'T1037.002', name:'Logon Script (Mac)',            parent:'T1037', tactic:'Persistence' },
  { id:'T1037.003', name:'Network Logon Script',          parent:'T1037', tactic:'Persistence' },
  { id:'T1037.004', name:'RC Scripts',                    parent:'T1037', tactic:'Persistence' },
  { id:'T1037.005', name:'Startup Items',                 parent:'T1037', tactic:'Persistence' },
  { id:'T1176', name:'Browser Extensions',                         tactic:'Persistence' },
  { id:'T1554', name:'Compromise Client Software Binary',          tactic:'Persistence' },
  { id:'T1136', name:'Create Account',                             tactic:'Persistence' },
  { id:'T1136.001', name:'Local Account',                 parent:'T1136', tactic:'Persistence' },
  { id:'T1136.002', name:'Domain Account',                parent:'T1136', tactic:'Persistence' },
  { id:'T1136.003', name:'Cloud Account',                 parent:'T1136', tactic:'Persistence' },
  { id:'T1543', name:'Create or Modify System Process',            tactic:'Persistence' },
  { id:'T1543.001', name:'Launch Agent',                  parent:'T1543', tactic:'Persistence' },
  { id:'T1543.002', name:'Systemd Service',               parent:'T1543', tactic:'Persistence' },
  { id:'T1543.003', name:'Windows Service',               parent:'T1543', tactic:'Persistence' },
  { id:'T1543.004', name:'Launch Daemon',                 parent:'T1543', tactic:'Persistence' },
  { id:'T1546', name:'Event Triggered Execution',                  tactic:'Persistence' },
  { id:'T1546.001', name:'Change Default File Association', parent:'T1546', tactic:'Persistence' },
  { id:'T1546.002', name:'Screensaver',                   parent:'T1546', tactic:'Persistence' },
  { id:'T1546.003', name:'Windows Management Instrumentation Event Subscription', parent:'T1546', tactic:'Persistence' },
  { id:'T1546.004', name:'.bash_profile and .bashrc',     parent:'T1546', tactic:'Persistence' },
  { id:'T1546.005', name:'Trap',                          parent:'T1546', tactic:'Persistence' },
  { id:'T1546.006', name:'LC_LOAD_DYLIB Addition',        parent:'T1546', tactic:'Persistence' },
  { id:'T1546.007', name:'Netsh Helper DLL',              parent:'T1546', tactic:'Persistence' },
  { id:'T1546.008', name:'Accessibility Features',        parent:'T1546', tactic:'Persistence' },
  { id:'T1546.009', name:'AppCert DLLs',                  parent:'T1546', tactic:'Persistence' },
  { id:'T1546.010', name:'AppInit DLLs',                  parent:'T1546', tactic:'Persistence' },
  { id:'T1546.011', name:'Application Shimming',          parent:'T1546', tactic:'Persistence' },
  { id:'T1546.012', name:'Image File Execution Options Injection', parent:'T1546', tactic:'Persistence' },
  { id:'T1546.013', name:'PowerShell Profile',            parent:'T1546', tactic:'Persistence' },
  { id:'T1546.014', name:'Emond',                         parent:'T1546', tactic:'Persistence' },
  { id:'T1546.015', name:'Component Object Model Hijacking', parent:'T1546', tactic:'Persistence' },
  { id:'T1546.016', name:'Installer Packages',            parent:'T1546', tactic:'Persistence' },
  { id:'T1133', name:'External Remote Services',                   tactic:'Persistence' },
  { id:'T1574', name:'Hijack Execution Flow',                      tactic:'Persistence' },
  { id:'T1574.001', name:'DLL Search Order Hijacking',    parent:'T1574', tactic:'Persistence' },
  { id:'T1574.002', name:'DLL Side-Loading',              parent:'T1574', tactic:'Persistence' },
  { id:'T1574.004', name:'Dylib Hijacking',               parent:'T1574', tactic:'Persistence' },
  { id:'T1574.005', name:'Executable Installer File Permissions Weakness', parent:'T1574', tactic:'Persistence' },
  { id:'T1574.006', name:'Dynamic Linker Hijacking',      parent:'T1574', tactic:'Persistence' },
  { id:'T1574.007', name:'Path Interception by PATH Variable', parent:'T1574', tactic:'Persistence' },
  { id:'T1574.008', name:'Path Interception by Search Order Hijacking', parent:'T1574', tactic:'Persistence' },
  { id:'T1574.009', name:'Path Interception by Unquoted Path', parent:'T1574', tactic:'Persistence' },
  { id:'T1574.010', name:'Services File Permissions Weakness', parent:'T1574', tactic:'Persistence' },
  { id:'T1574.011', name:'Services Registry Permissions Weakness', parent:'T1574', tactic:'Persistence' },
  { id:'T1574.012', name:'COR_PROFILER',                  parent:'T1574', tactic:'Persistence' },
  { id:'T1574.013', name:'KernelCallbackTable',           parent:'T1574', tactic:'Persistence' },
  { id:'T1525', name:'Implant Internal Image',                     tactic:'Persistence' },
  { id:'T1556', name:'Modify Authentication Process',              tactic:'Persistence' },
  { id:'T1556.001', name:'Domain Controller Authentication', parent:'T1556', tactic:'Persistence' },
  { id:'T1556.002', name:'Password Filter DLL',           parent:'T1556', tactic:'Persistence' },
  { id:'T1556.003', name:'Pluggable Authentication Modules', parent:'T1556', tactic:'Persistence' },
  { id:'T1556.004', name:'Network Device Authentication', parent:'T1556', tactic:'Persistence' },
  { id:'T1556.005', name:'Reversible Encryption',         parent:'T1556', tactic:'Persistence' },
  { id:'T1556.006', name:'Multi-Factor Authentication',   parent:'T1556', tactic:'Persistence' },
  { id:'T1137', name:'Office Application Startup',                 tactic:'Persistence' },
  { id:'T1137.001', name:'Office Template Macros',        parent:'T1137', tactic:'Persistence' },
  { id:'T1137.002', name:'Office Test',                   parent:'T1137', tactic:'Persistence' },
  { id:'T1137.003', name:'Outlook Forms',                 parent:'T1137', tactic:'Persistence' },
  { id:'T1137.004', name:'Outlook Home Page',             parent:'T1137', tactic:'Persistence' },
  { id:'T1137.005', name:'Outlook Rules',                 parent:'T1137', tactic:'Persistence' },
  { id:'T1137.006', name:'Add-ins',                       parent:'T1137', tactic:'Persistence' },
  { id:'T1542', name:'Pre-OS Boot',                                tactic:'Persistence' },
  { id:'T1542.001', name:'System Firmware',               parent:'T1542', tactic:'Persistence' },
  { id:'T1542.002', name:'Component Firmware',            parent:'T1542', tactic:'Persistence' },
  { id:'T1542.003', name:'Bootkit',                       parent:'T1542', tactic:'Persistence' },
  { id:'T1542.004', name:'ROMMONkit',                     parent:'T1542', tactic:'Persistence' },
  { id:'T1542.005', name:'TFTP Boot',                     parent:'T1542', tactic:'Persistence' },
  { id:'T1053', name:'Scheduled Task / Job',                       tactic:'Persistence' },
  { id:'T1505', name:'Server Software Component',                  tactic:'Persistence' },
  { id:'T1505.001', name:'SQL Stored Procedures',         parent:'T1505', tactic:'Persistence' },
  { id:'T1505.002', name:'Transport Agent',               parent:'T1505', tactic:'Persistence' },
  { id:'T1505.003', name:'Web Shell',                     parent:'T1505', tactic:'Persistence' },
  { id:'T1505.004', name:'IIS Components',                parent:'T1505', tactic:'Persistence' },
  { id:'T1505.005', name:'Terminal Services DLL',         parent:'T1505', tactic:'Persistence' },
  { id:'T1205', name:'Traffic Signaling',                          tactic:'Persistence' },
  { id:'T1078', name:'Valid Accounts',                             tactic:'Persistence' },

  // ── Privilege Escalation ────────────────────────────────────────────────────
  { id:'T1548', name:'Abuse Elevation Control Mechanism',          tactic:'Privilege Escalation' },
  { id:'T1548.001', name:'Setuid and Setgid',             parent:'T1548', tactic:'Privilege Escalation' },
  { id:'T1548.002', name:'Bypass User Account Control',   parent:'T1548', tactic:'Privilege Escalation' },
  { id:'T1548.003', name:'Sudo and Sudo Caching',         parent:'T1548', tactic:'Privilege Escalation' },
  { id:'T1548.004', name:'Elevated Execution with Prompt', parent:'T1548', tactic:'Privilege Escalation' },
  { id:'T1134', name:'Access Token Manipulation',                  tactic:'Privilege Escalation' },
  { id:'T1134.001', name:'Token Impersonation/Theft',     parent:'T1134', tactic:'Privilege Escalation' },
  { id:'T1134.002', name:'Create Process with Token',     parent:'T1134', tactic:'Privilege Escalation' },
  { id:'T1134.003', name:'Make and Impersonate Token',    parent:'T1134', tactic:'Privilege Escalation' },
  { id:'T1134.004', name:'Parent PID Spoofing',           parent:'T1134', tactic:'Privilege Escalation' },
  { id:'T1134.005', name:'SID-History Injection',         parent:'T1134', tactic:'Privilege Escalation' },
  { id:'T1098', name:'Account Manipulation',                       tactic:'Privilege Escalation' },
  { id:'T1547', name:'Boot or Logon Autostart Execution',          tactic:'Privilege Escalation' },
  { id:'T1037', name:'Boot or Logon Initialization Scripts',       tactic:'Privilege Escalation' },
  { id:'T1543', name:'Create or Modify System Process',            tactic:'Privilege Escalation' },
  { id:'T1484', name:'Domain Policy Modification',                 tactic:'Privilege Escalation' },
  { id:'T1484.001', name:'Group Policy Modification',     parent:'T1484', tactic:'Privilege Escalation' },
  { id:'T1484.002', name:'Domain Trust Modification',     parent:'T1484', tactic:'Privilege Escalation' },
  { id:'T1611', name:'Escape to Host',                             tactic:'Privilege Escalation' },
  { id:'T1546', name:'Event Triggered Execution',                  tactic:'Privilege Escalation' },
  { id:'T1068', name:'Exploitation for Privilege Escalation',      tactic:'Privilege Escalation' },
  { id:'T1574', name:'Hijack Execution Flow',                      tactic:'Privilege Escalation' },
  { id:'T1055', name:'Process Injection',                          tactic:'Privilege Escalation' },
  { id:'T1055.001', name:'Dynamic-link Library Injection', parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.002', name:'Portable Executable Injection', parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.003', name:'Thread Execution Hijacking',    parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.004', name:'Asynchronous Procedure Call',   parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.005', name:'Thread Local Storage',          parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.008', name:'Ptrace System Calls',           parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.009', name:'Proc Memory',                   parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.011', name:'Extra Window Memory Injection', parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.012', name:'Process Hollowing',             parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.013', name:'Process Doppelgänging',         parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.014', name:'VDSO Hijacking',                parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1055.015', name:'ListPlanting',                  parent:'T1055', tactic:'Privilege Escalation' },
  { id:'T1053', name:'Scheduled Task / Job',                       tactic:'Privilege Escalation' },
  { id:'T1078', name:'Valid Accounts',                             tactic:'Privilege Escalation' },

  // ── Defense Evasion ─────────────────────────────────────────────────────────
  { id:'T1548', name:'Abuse Elevation Control Mechanism',          tactic:'Defense Evasion' },
  { id:'T1134', name:'Access Token Manipulation',                  tactic:'Defense Evasion' },
  { id:'T1197', name:'BITS Jobs',                                  tactic:'Defense Evasion' },
  { id:'T1612', name:'Build Image on Host',                        tactic:'Defense Evasion' },
  { id:'T1622', name:'Debugger Evasion',                           tactic:'Defense Evasion' },
  { id:'T1140', name:'Deobfuscate/Decode Files or Information',    tactic:'Defense Evasion' },
  { id:'T1610', name:'Deploy Container',                           tactic:'Defense Evasion' },
  { id:'T1006', name:'Direct Volume Access',                       tactic:'Defense Evasion' },
  { id:'T1484', name:'Domain Policy Modification',                 tactic:'Defense Evasion' },
  { id:'T1480', name:'Execution Guardrails',                       tactic:'Defense Evasion' },
  { id:'T1480.001', name:'Environmental Keying',          parent:'T1480', tactic:'Defense Evasion' },
  { id:'T1211', name:'Exploitation for Defense Evasion',           tactic:'Defense Evasion' },
  { id:'T1222', name:'File and Directory Permissions Modification', tactic:'Defense Evasion' },
  { id:'T1222.001', name:'Windows File and Directory Permissions', parent:'T1222', tactic:'Defense Evasion' },
  { id:'T1222.002', name:'Linux and Mac File and Directory Permissions', parent:'T1222', tactic:'Defense Evasion' },
  { id:'T1564', name:'Hide Artifacts',                             tactic:'Defense Evasion' },
  { id:'T1564.001', name:'Hidden Files and Directories',  parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1564.002', name:'Hidden Users',                  parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1564.003', name:'Hidden Window',                 parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1564.004', name:'NTFS File Attributes',          parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1564.005', name:'Hidden File System',            parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1564.006', name:'Run Virtual Instance',          parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1564.007', name:'VBA Stomping',                  parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1564.008', name:'Email Hiding Rules',            parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1564.009', name:'Resource Forking',              parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1564.010', name:'Process Argument Spoofing',     parent:'T1564', tactic:'Defense Evasion' },
  { id:'T1574', name:'Hijack Execution Flow',                      tactic:'Defense Evasion' },
  { id:'T1562', name:'Impair Defenses',                            tactic:'Defense Evasion' },
  { id:'T1562.001', name:'Disable or Modify Tools',       parent:'T1562', tactic:'Defense Evasion' },
  { id:'T1562.002', name:'Disable Windows Event Logging', parent:'T1562', tactic:'Defense Evasion' },
  { id:'T1562.003', name:'Impair Command History Logging', parent:'T1562', tactic:'Defense Evasion' },
  { id:'T1562.004', name:'Disable or Modify System Firewall', parent:'T1562', tactic:'Defense Evasion' },
  { id:'T1562.006', name:'Indicator Blocking',            parent:'T1562', tactic:'Defense Evasion' },
  { id:'T1562.007', name:'Disable or Modify Cloud Firewall', parent:'T1562', tactic:'Defense Evasion' },
  { id:'T1562.008', name:'Disable or Modify Cloud Logs',  parent:'T1562', tactic:'Defense Evasion' },
  { id:'T1562.009', name:'Safe Mode Boot',                parent:'T1562', tactic:'Defense Evasion' },
  { id:'T1562.010', name:'Downgrade Attack',              parent:'T1562', tactic:'Defense Evasion' },
  { id:'T1656', name:'Impersonation',                              tactic:'Defense Evasion' },
  { id:'T1070', name:'Indicator Removal',                          tactic:'Defense Evasion' },
  { id:'T1070.001', name:'Clear Windows Event Logs',      parent:'T1070', tactic:'Defense Evasion' },
  { id:'T1070.002', name:'Clear Linux or Mac System Logs', parent:'T1070', tactic:'Defense Evasion' },
  { id:'T1070.003', name:'Clear Command History',         parent:'T1070', tactic:'Defense Evasion' },
  { id:'T1070.004', name:'File Deletion',                 parent:'T1070', tactic:'Defense Evasion' },
  { id:'T1070.005', name:'Network Share Connection Removal', parent:'T1070', tactic:'Defense Evasion' },
  { id:'T1070.006', name:'Timestomp',                     parent:'T1070', tactic:'Defense Evasion' },
  { id:'T1202', name:'Indirect Command Execution',                 tactic:'Defense Evasion' },
  { id:'T1036', name:'Masquerading',                               tactic:'Defense Evasion' },
  { id:'T1036.001', name:'Invalid Code Signature',        parent:'T1036', tactic:'Defense Evasion' },
  { id:'T1036.002', name:'Right-to-Left Override',        parent:'T1036', tactic:'Defense Evasion' },
  { id:'T1036.003', name:'Rename System Utilities',       parent:'T1036', tactic:'Defense Evasion' },
  { id:'T1036.004', name:'Masquerade Task or Service',    parent:'T1036', tactic:'Defense Evasion' },
  { id:'T1036.005', name:'Match Legitimate Name or Location', parent:'T1036', tactic:'Defense Evasion' },
  { id:'T1036.006', name:'Space after Filename',          parent:'T1036', tactic:'Defense Evasion' },
  { id:'T1036.007', name:'Double File Extension',         parent:'T1036', tactic:'Defense Evasion' },
  { id:'T1556', name:'Modify Authentication Process',              tactic:'Defense Evasion' },
  { id:'T1578', name:'Modify Cloud Compute Infrastructure',        tactic:'Defense Evasion' },
  { id:'T1112', name:'Modify Registry',                            tactic:'Defense Evasion' },
  { id:'T1601', name:'Modify System Image',                        tactic:'Defense Evasion' },
  { id:'T1599', name:'Network Boundary Bridging',                  tactic:'Defense Evasion' },
  { id:'T1027', name:'Obfuscated Files or Information',            tactic:'Defense Evasion' },
  { id:'T1027.001', name:'Binary Padding',                parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.002', name:'Software Packing',              parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.003', name:'Steganography',                 parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.004', name:'Compile After Delivery',        parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.005', name:'Indicator Removal from Tools',  parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.006', name:'HTML Smuggling',                parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.007', name:'Dynamic API Resolution',        parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.008', name:'Stripped Payloads',             parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.009', name:'Embedded Payloads',             parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.010', name:'Command Obfuscation',           parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.011', name:'Fileless Storage',              parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1027.012', name:'LNK Icon Smuggling',            parent:'T1027', tactic:'Defense Evasion' },
  { id:'T1542', name:'Pre-OS Boot',                                tactic:'Defense Evasion' },
  { id:'T1055', name:'Process Injection',                          tactic:'Defense Evasion' },
  { id:'T1207', name:'Rogue Domain Controller',                    tactic:'Defense Evasion' },
  { id:'T1014', name:'Rootkit',                                    tactic:'Defense Evasion' },
  { id:'T1218', name:'System Binary Proxy Execution',              tactic:'Defense Evasion' },
  { id:'T1218.001', name:'Compiled HTML File',            parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.002', name:'Control Panel',                 parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.003', name:'CMSTP',                         parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.004', name:'InstallUtil',                   parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.005', name:'Mshta',                         parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.007', name:'Msiexec',                       parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.008', name:'Odbcconf',                      parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.009', name:'Regsvcs/Regasm',                parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.010', name:'Regsvr32',                      parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.011', name:'Rundll32',                      parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.012', name:'Verclsid',                      parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.013', name:'Mavinject',                     parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1218.014', name:'MMC',                           parent:'T1218', tactic:'Defense Evasion' },
  { id:'T1216', name:'System Script Proxy Execution',              tactic:'Defense Evasion' },
  { id:'T1216.001', name:'PubPrn',                        parent:'T1216', tactic:'Defense Evasion' },
  { id:'T1221', name:'Template Injection',                         tactic:'Defense Evasion' },
  { id:'T1205', name:'Traffic Signaling',                          tactic:'Defense Evasion' },
  { id:'T1127', name:'Trusted Developer Utilities Proxy Execution', tactic:'Defense Evasion' },
  { id:'T1127.001', name:'MSBuild',                       parent:'T1127', tactic:'Defense Evasion' },
  { id:'T1535', name:'Unused/Unsupported Cloud Regions',           tactic:'Defense Evasion' },
  { id:'T1550', name:'Use Alternate Authentication Material',      tactic:'Defense Evasion' },
  { id:'T1550.001', name:'Application Access Token',      parent:'T1550', tactic:'Defense Evasion' },
  { id:'T1550.002', name:'Pass the Hash',                 parent:'T1550', tactic:'Defense Evasion' },
  { id:'T1550.003', name:'Pass the Ticket',               parent:'T1550', tactic:'Defense Evasion' },
  { id:'T1550.004', name:'Web Session Cookie',            parent:'T1550', tactic:'Defense Evasion' },
  { id:'T1078', name:'Valid Accounts',                             tactic:'Defense Evasion' },
  { id:'T1497', name:'Virtualization/Sandbox Evasion',             tactic:'Defense Evasion' },
  { id:'T1497.001', name:'System Checks',                 parent:'T1497', tactic:'Defense Evasion' },
  { id:'T1497.002', name:'User Activity Based Checks',    parent:'T1497', tactic:'Defense Evasion' },
  { id:'T1497.003', name:'Time Based Evasion',            parent:'T1497', tactic:'Defense Evasion' },
  { id:'T1600', name:'Weaken Encryption',                          tactic:'Defense Evasion' },
  { id:'T1220', name:'XSL Script Processing',                      tactic:'Defense Evasion' },

  // ── Credential Access ────────────────────────────────────────────────────────
  { id:'T1557', name:'Adversary-in-the-Middle',                    tactic:'Credential Access' },
  { id:'T1557.001', name:'LLMNR/NBT-NS Poisoning and SMB Relay', parent:'T1557', tactic:'Credential Access' },
  { id:'T1557.002', name:'ARP Cache Poisoning',           parent:'T1557', tactic:'Credential Access' },
  { id:'T1110', name:'Brute Force',                                tactic:'Credential Access' },
  { id:'T1110.001', name:'Password Guessing',             parent:'T1110', tactic:'Credential Access' },
  { id:'T1110.002', name:'Password Cracking',             parent:'T1110', tactic:'Credential Access' },
  { id:'T1110.003', name:'Password Spraying',             parent:'T1110', tactic:'Credential Access' },
  { id:'T1110.004', name:'Credential Stuffing',           parent:'T1110', tactic:'Credential Access' },
  { id:'T1555', name:'Credentials from Password Stores',          tactic:'Credential Access' },
  { id:'T1555.001', name:'Keychain',                      parent:'T1555', tactic:'Credential Access' },
  { id:'T1555.002', name:'Securityd Memory',              parent:'T1555', tactic:'Credential Access' },
  { id:'T1555.003', name:'Credentials from Web Browsers', parent:'T1555', tactic:'Credential Access' },
  { id:'T1555.004', name:'Windows Credential Manager',    parent:'T1555', tactic:'Credential Access' },
  { id:'T1555.005', name:'Password Managers',             parent:'T1555', tactic:'Credential Access' },
  { id:'T1212', name:'Exploitation for Credential Access',        tactic:'Credential Access' },
  { id:'T1187', name:'Forced Authentication',                     tactic:'Credential Access' },
  { id:'T1606', name:'Forge Web Credentials',                     tactic:'Credential Access' },
  { id:'T1606.001', name:'Web Cookies',                   parent:'T1606', tactic:'Credential Access' },
  { id:'T1606.002', name:'SAML Tokens',                   parent:'T1606', tactic:'Credential Access' },
  { id:'T1056', name:'Input Capture',                             tactic:'Credential Access' },
  { id:'T1056.001', name:'Keylogging',                    parent:'T1056', tactic:'Credential Access' },
  { id:'T1056.002', name:'GUI Input Capture',             parent:'T1056', tactic:'Credential Access' },
  { id:'T1056.003', name:'Web Portal Capture',            parent:'T1056', tactic:'Credential Access' },
  { id:'T1056.004', name:'Credential API Hooking',        parent:'T1056', tactic:'Credential Access' },
  { id:'T1557', name:'Man-in-the-Middle',                         tactic:'Credential Access' },
  { id:'T1556', name:'Modify Authentication Process',             tactic:'Credential Access' },
  { id:'T1111', name:'Multi-Factor Authentication Interception',  tactic:'Credential Access' },
  { id:'T1621', name:'Multi-Factor Authentication Request Generation', tactic:'Credential Access' },
  { id:'T1040', name:'Network Sniffing',                          tactic:'Credential Access' },
  { id:'T1003', name:'OS Credential Dumping',                     tactic:'Credential Access' },
  { id:'T1003.001', name:'LSASS Memory',                  parent:'T1003', tactic:'Credential Access' },
  { id:'T1003.002', name:'Security Account Manager',      parent:'T1003', tactic:'Credential Access' },
  { id:'T1003.003', name:'NTDS',                          parent:'T1003', tactic:'Credential Access' },
  { id:'T1003.004', name:'LSA Secrets',                   parent:'T1003', tactic:'Credential Access' },
  { id:'T1003.005', name:'Cached Domain Credentials',     parent:'T1003', tactic:'Credential Access' },
  { id:'T1003.006', name:'DCSync',                        parent:'T1003', tactic:'Credential Access' },
  { id:'T1003.007', name:'Proc Filesystem',               parent:'T1003', tactic:'Credential Access' },
  { id:'T1003.008', name:'/etc/passwd and /etc/shadow',   parent:'T1003', tactic:'Credential Access' },
  { id:'T1528', name:'Steal Application Access Token',            tactic:'Credential Access' },
  { id:'T1649', name:'Steal or Forge Authentication Certificates', tactic:'Credential Access' },
  { id:'T1558', name:'Steal or Forge Kerberos Tickets',           tactic:'Credential Access' },
  { id:'T1558.001', name:'Golden Ticket',                 parent:'T1558', tactic:'Credential Access' },
  { id:'T1558.002', name:'Silver Ticket',                 parent:'T1558', tactic:'Credential Access' },
  { id:'T1558.003', name:'Kerberoasting',                 parent:'T1558', tactic:'Credential Access' },
  { id:'T1558.004', name:'AS-REP Roasting',               parent:'T1558', tactic:'Credential Access' },
  { id:'T1539', name:'Steal Web Session Cookie',                  tactic:'Credential Access' },
  { id:'T1552', name:'Unsecured Credentials',                     tactic:'Credential Access' },
  { id:'T1552.001', name:'Credentials In Files',          parent:'T1552', tactic:'Credential Access' },
  { id:'T1552.002', name:'Credentials in Registry',       parent:'T1552', tactic:'Credential Access' },
  { id:'T1552.003', name:'Bash History',                  parent:'T1552', tactic:'Credential Access' },
  { id:'T1552.004', name:'Private Keys',                  parent:'T1552', tactic:'Credential Access' },
  { id:'T1552.005', name:'Cloud Instance Metadata API',   parent:'T1552', tactic:'Credential Access' },
  { id:'T1552.006', name:'Group Policy Preferences',      parent:'T1552', tactic:'Credential Access' },
  { id:'T1552.007', name:'Container API',                 parent:'T1552', tactic:'Credential Access' },

  // ── Discovery ────────────────────────────────────────────────────────────────
  { id:'T1087', name:'Account Discovery',                         tactic:'Discovery' },
  { id:'T1087.001', name:'Local Account',                 parent:'T1087', tactic:'Discovery' },
  { id:'T1087.002', name:'Domain Account',                parent:'T1087', tactic:'Discovery' },
  { id:'T1087.003', name:'Email Account',                 parent:'T1087', tactic:'Discovery' },
  { id:'T1087.004', name:'Cloud Account',                 parent:'T1087', tactic:'Discovery' },
  { id:'T1010', name:'Application Window Discovery',              tactic:'Discovery' },
  { id:'T1217', name:'Browser Information Discovery',             tactic:'Discovery' },
  { id:'T1580', name:'Cloud Infrastructure Discovery',            tactic:'Discovery' },
  { id:'T1538', name:'Cloud Service Dashboard',                   tactic:'Discovery' },
  { id:'T1526', name:'Cloud Service Discovery',                   tactic:'Discovery' },
  { id:'T1619', name:'Cloud Storage Object Discovery',            tactic:'Discovery' },
  { id:'T1613', name:'Container and Resource Discovery',          tactic:'Discovery' },
  { id:'T1622', name:'Debugger Evasion',                          tactic:'Discovery' },
  { id:'T1482', name:'Domain Trust Discovery',                    tactic:'Discovery' },
  { id:'T1083', name:'File and Directory Discovery',              tactic:'Discovery' },
  { id:'T1615', name:'Group Policy Discovery',                    tactic:'Discovery' },
  { id:'T1654', name:'Log Enumeration',                           tactic:'Discovery' },
  { id:'T1046', name:'Network Service Discovery',                 tactic:'Discovery' },
  { id:'T1135', name:'Network Share Discovery',                   tactic:'Discovery' },
  { id:'T1040', name:'Network Sniffing',                          tactic:'Discovery' },
  { id:'T1201', name:'Password Policy Discovery',                 tactic:'Discovery' },
  { id:'T1120', name:'Peripheral Device Discovery',               tactic:'Discovery' },
  { id:'T1069', name:'Permission Groups Discovery',               tactic:'Discovery' },
  { id:'T1069.001', name:'Local Groups',                  parent:'T1069', tactic:'Discovery' },
  { id:'T1069.002', name:'Domain Groups',                 parent:'T1069', tactic:'Discovery' },
  { id:'T1069.003', name:'Cloud Groups',                  parent:'T1069', tactic:'Discovery' },
  { id:'T1057', name:'Process Discovery',                         tactic:'Discovery' },
  { id:'T1012', name:'Query Registry',                            tactic:'Discovery' },
  { id:'T1018', name:'Remote System Discovery',                   tactic:'Discovery' },
  { id:'T1518', name:'Software Discovery',                        tactic:'Discovery' },
  { id:'T1518.001', name:'Security Software Discovery',   parent:'T1518', tactic:'Discovery' },
  { id:'T1082', name:'System Information Discovery',              tactic:'Discovery' },
  { id:'T1614', name:'System Location Discovery',                 tactic:'Discovery' },
  { id:'T1614.001', name:'System Language Discovery',     parent:'T1614', tactic:'Discovery' },
  { id:'T1016', name:'System Network Configuration Discovery',    tactic:'Discovery' },
  { id:'T1016.001', name:'Internet Connection Discovery', parent:'T1016', tactic:'Discovery' },
  { id:'T1049', name:'System Network Connections Discovery',      tactic:'Discovery' },
  { id:'T1033', name:'System Owner/User Discovery',               tactic:'Discovery' },
  { id:'T1007', name:'System Service Discovery',                  tactic:'Discovery' },
  { id:'T1124', name:'System Time Discovery',                     tactic:'Discovery' },
  { id:'T1497', name:'Virtualization/Sandbox Evasion',            tactic:'Discovery' },

  // ── Lateral Movement ────────────────────────────────────────────────────────
  { id:'T1210', name:'Exploitation of Remote Services',           tactic:'Lateral Movement' },
  { id:'T1534', name:'Internal Spearphishing',                    tactic:'Lateral Movement' },
  { id:'T1570', name:'Lateral Tool Transfer',                     tactic:'Lateral Movement' },
  { id:'T1563', name:'Remote Service Session Hijacking',          tactic:'Lateral Movement' },
  { id:'T1563.001', name:'SSH Hijacking',                 parent:'T1563', tactic:'Lateral Movement' },
  { id:'T1563.002', name:'RDP Hijacking',                 parent:'T1563', tactic:'Lateral Movement' },
  { id:'T1021', name:'Remote Services',                           tactic:'Lateral Movement' },
  { id:'T1021.001', name:'Remote Desktop Protocol',       parent:'T1021', tactic:'Lateral Movement' },
  { id:'T1021.002', name:'SMB/Windows Admin Shares',      parent:'T1021', tactic:'Lateral Movement' },
  { id:'T1021.003', name:'Distributed Component Object Model', parent:'T1021', tactic:'Lateral Movement' },
  { id:'T1021.004', name:'SSH',                           parent:'T1021', tactic:'Lateral Movement' },
  { id:'T1021.005', name:'VNC',                           parent:'T1021', tactic:'Lateral Movement' },
  { id:'T1021.006', name:'Windows Remote Management',     parent:'T1021', tactic:'Lateral Movement' },
  { id:'T1021.007', name:'Cloud Services',                parent:'T1021', tactic:'Lateral Movement' },
  { id:'T1091', name:'Replication Through Removable Media',       tactic:'Lateral Movement' },
  { id:'T1072', name:'Software Deployment Tools',                 tactic:'Lateral Movement' },
  { id:'T1550', name:'Use Alternate Authentication Material',     tactic:'Lateral Movement' },
  { id:'T1047', name:'Windows Management Instrumentation',        tactic:'Lateral Movement' },

  // ── Collection ───────────────────────────────────────────────────────────────
  { id:'T1557', name:'Adversary-in-the-Middle',                   tactic:'Collection' },
  { id:'T1560', name:'Archive Collected Data',                    tactic:'Collection' },
  { id:'T1560.001', name:'Archive via Utility',           parent:'T1560', tactic:'Collection' },
  { id:'T1560.002', name:'Archive via Library',           parent:'T1560', tactic:'Collection' },
  { id:'T1560.003', name:'Archive via Custom Method',     parent:'T1560', tactic:'Collection' },
  { id:'T1123', name:'Audio Capture',                             tactic:'Collection' },
  { id:'T1119', name:'Automated Collection',                      tactic:'Collection' },
  { id:'T1185', name:'Browser Session Hijacking',                 tactic:'Collection' },
  { id:'T1115', name:'Clipboard Data',                            tactic:'Collection' },
  { id:'T1530', name:'Data from Cloud Storage',                   tactic:'Collection' },
  { id:'T1602', name:'Data from Configuration Repository',        tactic:'Collection' },
  { id:'T1213', name:'Data from Information Repositories',        tactic:'Collection' },
  { id:'T1213.001', name:'Confluence',                    parent:'T1213', tactic:'Collection' },
  { id:'T1213.002', name:'Sharepoint',                    parent:'T1213', tactic:'Collection' },
  { id:'T1213.003', name:'Code Repositories',             parent:'T1213', tactic:'Collection' },
  { id:'T1005', name:'Data from Local System',                    tactic:'Collection' },
  { id:'T1039', name:'Data from Network Shared Drive',            tactic:'Collection' },
  { id:'T1025', name:'Data from Removable Media',                 tactic:'Collection' },
  { id:'T1074', name:'Data Staged',                               tactic:'Collection' },
  { id:'T1074.001', name:'Local Data Staging',            parent:'T1074', tactic:'Collection' },
  { id:'T1074.002', name:'Remote Data Staging',           parent:'T1074', tactic:'Collection' },
  { id:'T1114', name:'Email Collection',                          tactic:'Collection' },
  { id:'T1114.001', name:'Local Email Collection',        parent:'T1114', tactic:'Collection' },
  { id:'T1114.002', name:'Remote Email Collection',       parent:'T1114', tactic:'Collection' },
  { id:'T1114.003', name:'Email Forwarding Rule',         parent:'T1114', tactic:'Collection' },
  { id:'T1056', name:'Input Capture',                             tactic:'Collection' },
  { id:'T1113', name:'Screen Capture',                            tactic:'Collection' },
  { id:'T1125', name:'Video Capture',                             tactic:'Collection' },

  // ── Command and Control ──────────────────────────────────────────────────────
  { id:'T1071', name:'Application Layer Protocol',                tactic:'Command and Control' },
  { id:'T1071.001', name:'Web Protocols',                 parent:'T1071', tactic:'Command and Control' },
  { id:'T1071.002', name:'File Transfer Protocols',       parent:'T1071', tactic:'Command and Control' },
  { id:'T1071.003', name:'Mail Protocols',                parent:'T1071', tactic:'Command and Control' },
  { id:'T1071.004', name:'DNS',                           parent:'T1071', tactic:'Command and Control' },
  { id:'T1092', name:'Communication Through Removable Media',     tactic:'Command and Control' },
  { id:'T1132', name:'Data Encoding',                             tactic:'Command and Control' },
  { id:'T1132.001', name:'Standard Encoding',             parent:'T1132', tactic:'Command and Control' },
  { id:'T1132.002', name:'Non-Standard Encoding',         parent:'T1132', tactic:'Command and Control' },
  { id:'T1001', name:'Data Obfuscation',                          tactic:'Command and Control' },
  { id:'T1001.001', name:'Junk Data',                     parent:'T1001', tactic:'Command and Control' },
  { id:'T1001.002', name:'Steganography',                 parent:'T1001', tactic:'Command and Control' },
  { id:'T1001.003', name:'Protocol Impersonation',        parent:'T1001', tactic:'Command and Control' },
  { id:'T1568', name:'Dynamic Resolution',                        tactic:'Command and Control' },
  { id:'T1568.001', name:'Fast Flux DNS',                 parent:'T1568', tactic:'Command and Control' },
  { id:'T1568.002', name:'Domain Generation Algorithms',  parent:'T1568', tactic:'Command and Control' },
  { id:'T1568.003', name:'DNS Calculation',               parent:'T1568', tactic:'Command and Control' },
  { id:'T1573', name:'Encrypted Channel',                         tactic:'Command and Control' },
  { id:'T1573.001', name:'Symmetric Cryptography',        parent:'T1573', tactic:'Command and Control' },
  { id:'T1573.002', name:'Asymmetric Cryptography',       parent:'T1573', tactic:'Command and Control' },
  { id:'T1008', name:'Fallback Channels',                         tactic:'Command and Control' },
  { id:'T1105', name:'Ingress Tool Transfer',                     tactic:'Command and Control' },
  { id:'T1104', name:'Multi-Stage Channels',                      tactic:'Command and Control' },
  { id:'T1095', name:'Non-Application Layer Protocol',            tactic:'Command and Control' },
  { id:'T1571', name:'Non-Standard Port',                         tactic:'Command and Control' },
  { id:'T1572', name:'Protocol Tunneling',                        tactic:'Command and Control' },
  { id:'T1090', name:'Proxy',                                     tactic:'Command and Control' },
  { id:'T1090.001', name:'Internal Proxy',                parent:'T1090', tactic:'Command and Control' },
  { id:'T1090.002', name:'External Proxy',                parent:'T1090', tactic:'Command and Control' },
  { id:'T1090.003', name:'Multi-hop Proxy',               parent:'T1090', tactic:'Command and Control' },
  { id:'T1090.004', name:'Domain Fronting',               parent:'T1090', tactic:'Command and Control' },
  { id:'T1219', name:'Remote Access Software',                    tactic:'Command and Control' },
  { id:'T1205', name:'Traffic Signaling',                         tactic:'Command and Control' },
  { id:'T1102', name:'Web Service',                               tactic:'Command and Control' },
  { id:'T1102.001', name:'Dead Drop Resolver',            parent:'T1102', tactic:'Command and Control' },
  { id:'T1102.002', name:'Bidirectional Communication',   parent:'T1102', tactic:'Command and Control' },
  { id:'T1102.003', name:'One-Way Communication',         parent:'T1102', tactic:'Command and Control' },

  // ── Exfiltration ─────────────────────────────────────────────────────────────
  { id:'T1020', name:'Automated Exfiltration',                    tactic:'Exfiltration' },
  { id:'T1020.001', name:'Traffic Duplication',           parent:'T1020', tactic:'Exfiltration' },
  { id:'T1030', name:'Data Transfer Size Limits',                 tactic:'Exfiltration' },
  { id:'T1048', name:'Exfiltration Over Alternative Protocol',    tactic:'Exfiltration' },
  { id:'T1048.001', name:'Exfiltration Over Symmetric Encrypted Non-C2 Protocol', parent:'T1048', tactic:'Exfiltration' },
  { id:'T1048.002', name:'Exfiltration Over Asymmetric Encrypted Non-C2 Protocol', parent:'T1048', tactic:'Exfiltration' },
  { id:'T1048.003', name:'Exfiltration Over Unencrypted Non-C2 Protocol', parent:'T1048', tactic:'Exfiltration' },
  { id:'T1041', name:'Exfiltration Over C2 Channel',              tactic:'Exfiltration' },
  { id:'T1011', name:'Exfiltration Over Other Network Medium',    tactic:'Exfiltration' },
  { id:'T1011.001', name:'Exfiltration Over Bluetooth',   parent:'T1011', tactic:'Exfiltration' },
  { id:'T1052', name:'Exfiltration Over Physical Medium', tactic:'Exfiltration' },
  { id:'T1052.001', name:'Exfiltration over USB',         parent:'T1052', tactic:'Exfiltration' },
  { id:'T1567', name:'Exfiltration Over Web Service',             tactic:'Exfiltration' },
  { id:'T1567.001', name:'Exfiltration to Code Repository', parent:'T1567', tactic:'Exfiltration' },
  { id:'T1567.002', name:'Exfiltration to Cloud Storage',  parent:'T1567', tactic:'Exfiltration' },
  { id:'T1029', name:'Scheduled Transfer',                        tactic:'Exfiltration' },
  { id:'T1537', name:'Transfer Data to Cloud Account',            tactic:'Exfiltration' },

  // ── Impact ───────────────────────────────────────────────────────────────────
  { id:'T1531', name:'Account Access Removal',                    tactic:'Impact' },
  { id:'T1485', name:'Data Destruction',                          tactic:'Impact' },
  { id:'T1486', name:'Data Encrypted for Impact',                 tactic:'Impact' },
  { id:'T1565', name:'Data Manipulation',                         tactic:'Impact' },
  { id:'T1565.001', name:'Stored Data Manipulation',      parent:'T1565', tactic:'Impact' },
  { id:'T1565.002', name:'Transmitted Data Manipulation', parent:'T1565', tactic:'Impact' },
  { id:'T1565.003', name:'Runtime Data Manipulation',     parent:'T1565', tactic:'Impact' },
  { id:'T1491', name:'Defacement',                                tactic:'Impact' },
  { id:'T1491.001', name:'Internal Defacement',           parent:'T1491', tactic:'Impact' },
  { id:'T1491.002', name:'External Defacement',           parent:'T1491', tactic:'Impact' },
  { id:'T1561', name:'Disk Wipe',                                 tactic:'Impact' },
  { id:'T1561.001', name:'Disk Content Wipe',             parent:'T1561', tactic:'Impact' },
  { id:'T1561.002', name:'Disk Structure Wipe',           parent:'T1561', tactic:'Impact' },
  { id:'T1499', name:'Endpoint Denial of Service',                tactic:'Impact' },
  { id:'T1499.001', name:'OS Exhaustion Flood',           parent:'T1499', tactic:'Impact' },
  { id:'T1499.002', name:'Service Exhaustion Flood',      parent:'T1499', tactic:'Impact' },
  { id:'T1499.003', name:'Application Exhaustion Flood',  parent:'T1499', tactic:'Impact' },
  { id:'T1499.004', name:'Application or System Exploitation', parent:'T1499', tactic:'Impact' },
  { id:'T1657', name:'Financial Theft',                           tactic:'Impact' },
  { id:'T1495', name:'Firmware Corruption',                       tactic:'Impact' },
  { id:'T1490', name:'Inhibit System Recovery',                   tactic:'Impact' },
  { id:'T1498', name:'Network Denial of Service',                 tactic:'Impact' },
  { id:'T1498.001', name:'Direct Network Flood',          parent:'T1498', tactic:'Impact' },
  { id:'T1498.002', name:'Reflection Amplification',      parent:'T1498', tactic:'Impact' },
  { id:'T1496', name:'Resource Hijacking',                        tactic:'Impact' },
  { id:'T1489', name:'Service Stop',                              tactic:'Impact' },
  { id:'T1529', name:'System Shutdown/Reboot',                    tactic:'Impact' },
];

// ── Detection signatures (endpoint CSV detectable) ────────────────────────────
// Each entry: test(cmdArr, fileArr, initFileArr, pathArr, remoteIpArr, remoteUrlArr,
//             remotePortArr, regKeyArr, actionArr, initCmdArr, i) → bool
// Columns passed as flat arrays; i = row index
// Returns true if row i matches this technique

const MITRE_DETECTIONS = {
  // Execution
  'T1059.001': (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /powershell|pwsh/i.test(f[i]||'') || /powershell|pwsh/i.test(fi[i]||'') ||
    /powershell|pwsh/i.test(c[i]||'') || /powershell|pwsh/i.test(ic[i]||''),
  'T1059.003': (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /\bcmd\.exe\b/i.test(f[i]||'') || /\bcmd\.exe\b/i.test(fi[i]||'') ||
    /\bcmd(\.exe)?\s+\/[ck]/i.test(c[i]||'') || /\bcmd(\.exe)?\s+\/[ck]/i.test(ic[i]||''),
  'T1059.005': (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /wscript|cscript|vbscript/i.test(f[i]||'') || /wscript|cscript|vbscript/i.test(fi[i]||'') ||
    /\.vbs?["'\s]/i.test(c[i]||'') || /\.vbs?["'\s]/i.test(ic[i]||''),
  'T1059.007': (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /wscript|cscript/i.test(f[i]||'') && /\.js["'\s]/i.test(c[i]||''),
  'T1047':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /wmic|WmiPrvSE/i.test(f[i]||'') || /wmic|WmiPrvSE/i.test(fi[i]||'') ||
    /wmic.*\/(node:|process|call)/i.test(c[i]||'') || /Invoke-WmiMethod|Invoke-CimMethod/i.test(c[i]||''),
  'T1053.005':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /schtasks/i.test(f[i]||'') || /schtasks.*\/create/i.test(c[i]||'') ||
    /Register-ScheduledTask|New-ScheduledTask/i.test(c[i]||''),
  'T1204.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /\b(winword|excel|outlook|powerpnt|onenote|mspub)\.exe\b/i.test(fi[i]||'') &&
    /\b(cmd|powershell|wscript|cscript|mshta|rundll32)\.exe\b/i.test(f[i]||''),
  'T1569.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /sc\s+(create|start|config)/i.test(c[i]||'') || /New-Service|Install-Service/i.test(c[i]||''),

  // Persistence
  'T1547.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /Software\\Microsoft\\Windows\\CurrentVersion\\Run/i.test(rk[i]||''),
  'T1543.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /SYSTEM\\CurrentControlSet\\Services/i.test(rk[i]||'') ||
    /sc\s+create/i.test(c[i]||'') || /New-Service/i.test(c[i]||''),
  'T1136.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+user.*\/add/i.test(c[i]||'') || /New-LocalUser/i.test(c[i]||''),
  'T1136.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+user.*\/add.*\/domain/i.test(c[i]||'') || /New-ADUser/i.test(c[i]||''),
  'T1197':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /bitsadmin/i.test(f[i]||'') || /bitsadmin/i.test(fi[i]||'') ||
    /bitsadmin.*\/transfer/i.test(c[i]||'') || /Start-BitsTransfer/i.test(c[i]||''),
  'T1546.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /mofcomp|wbemtest/i.test(f[i]||'') ||
    /__EventFilter|__EventConsumer|__FilterToConsumerBinding/i.test(rk[i]||''),
  'T1546.008':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /(sethc|utilman|osk|magnify|narrator)\.exe/i.test(f[i]||'') ||
    /Image File Execution Options.*(sethc|utilman)/i.test(rk[i]||''),
  'T1546.012':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /Image File Execution Options/i.test(rk[i]||''),
  'T1505.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /aspx?|\.php|\.jsp/i.test(p[i]||'') && /inetpub|wwwroot|htdocs/i.test(p[i]||''),

  // Privilege Escalation
  'T1548.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /eventvwr|fodhelper|computerdefaults|sdclt/i.test(f[i]||'') ||
    /bypassuac|bypass.*uac/i.test(c[i]||''),
  'T1134.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /runas|token.*impersonat/i.test(c[i]||'') ||
    /Invoke-TokenManipulation|Get-System/i.test(c[i]||''),
  'T1134.004':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /ppid.*spoof|parent.*pid.*spoof/i.test(c[i]||''),
  'T1055.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /Invoke-DllInjection|ReflectivePEInjection/i.test(c[i]||''),
  'T1055.012':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /process.*hollow|hollowing/i.test(c[i]||''),

  // Defense Evasion
  'T1027':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /-enc(?:odedCommand)?\s+[A-Za-z0-9+\/]{16,}/i.test(c[i]||'') ||
    /FromBase64String|::FromBase64/i.test(c[i]||'') ||
    (c[i]||'').length > 500,
  'T1027.010':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /-enc(?:odedCommand)?\s+[A-Za-z0-9+\/]{16,}/i.test(c[i]||'') ||
    /\^|`[a-z]|char\(\d+\)/i.test(c[i]||''),
  'T1140':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /certutil.*-decode/i.test(c[i]||'') || /FromBase64String/i.test(c[i]||'') ||
    /expand.*-f/i.test(c[i]||''),
  'T1218.005':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /mshta/i.test(f[i]||'') || /mshta/i.test(fi[i]||''),
  'T1218.007':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /msiexec/i.test(f[i]||'') && /\/q|\/quiet|\/i\s+http/i.test(c[i]||''),
  'T1218.009':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /regsvcs|regasm/i.test(f[i]||'') || /regsvcs|regasm/i.test(fi[i]||''),
  'T1218.010':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /regsvr32/i.test(f[i]||'') || /regsvr32/i.test(fi[i]||''),
  'T1218.011':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /rundll32/i.test(f[i]||'') || /rundll32/i.test(fi[i]||''),
  'T1218.004':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /installutil/i.test(f[i]||'') || /installutil/i.test(fi[i]||''),
  'T1127.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /msbuild/i.test(f[i]||'') || /msbuild/i.test(fi[i]||''),
  'T1220':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /wmic.*\/format|msxsl/i.test(c[i]||''),
  'T1562.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /Set-MpPreference.*Disable|Add-MpPreference.*Exclusion/i.test(c[i]||'') ||
    /netsh.*firewall.*disable|sc.*stop.*windefend/i.test(c[i]||''),
  'T1562.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /wevtutil.*cl|Clear-EventLog/i.test(c[i]||'') ||
    /auditpol.*\/set.*no.*auditing/i.test(c[i]||''),
  'T1070.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /wevtutil.*cl|wevtutil.*clear/i.test(c[i]||'') || /Clear-EventLog/i.test(c[i]||''),
  'T1070.004':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /del\s+.*\.(exe|dll|ps1|bat|cmd)|rm\s+-.*force/i.test(c[i]||'') ||
    /Remove-Item.*force/i.test(c[i]||''),
  'T1036.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /svchost|lsass|csrss|winlogon|services/i.test(f[i]||'') &&
    !/System32|SysWOW64/i.test(p[i]||'') && (p[i]||'').length > 0,
  'T1112':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /RegistryValueSet|RegistryKeyCreated|RegistryValueDeleted/i.test(a[i]||'') ||
    /reg\s+(add|delete|import)/i.test(c[i]||'') || /Set-ItemProperty.*HKLM/i.test(c[i]||''),
  'T1202':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /pcalua|forfiles|pcwrun/i.test(f[i]||'') ||
    /forfiles.*\/c|pcalua.*-a/i.test(c[i]||''),
  'T1550.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /sekurlsa::pth|pass.the.hash|mimikatz.*pth/i.test(c[i]||''),

  // Credential Access
  'T1003.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /procdump.*lsass|lsass.*dump|comsvcs.*minidump|mimikatz|wce\.exe|lazagne/i.test(c[i]||'') ||
    /sekurlsa|hashdump|lsadump/i.test(c[i]||''),
  'T1003.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /reg\s+save.*sam|reg\s+save.*system|ntdsutil/i.test(c[i]||'') ||
    /lsadump::sam|lsadump::lsa/i.test(c[i]||''),
  'T1003.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /ntdsutil|vssadmin.*create.*shadow/i.test(c[i]||'') ||
    /lsadump::dcsync|drsuapi/i.test(c[i]||''),
  'T1003.006':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /lsadump::dcsync|drsuapi|DCSync/i.test(c[i]||''),
  'T1558.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /kerberoast|Invoke-Kerberoast|GetUserSPNs/i.test(c[i]||''),
  'T1558.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /golden.*ticket|kerberos::golden|mimikatz.*krbtgt/i.test(c[i]||''),
  'T1555.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /lazagne.*browsers|Get-WebCredentials|SharpWeb/i.test(c[i]||''),
  'T1552.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /findstr.*password|type.*unattend|Get-Content.*password/i.test(c[i]||''),
  'T1552.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /reg\s+query.*password|Get-ItemProperty.*password/i.test(c[i]||''),
  'T1187':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /responder|inveigh/i.test(f[i]||'') || /responder|inveigh/i.test(c[i]||''),
  'T1110.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /spray|DomainPasswordSpray|Invoke-BruteForce/i.test(c[i]||''),

  // Discovery
  'T1082':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /systeminfo|Get-ComputerInfo|uname\s+-a/i.test(c[i]||''),
  'T1083':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /dir\s+\/s|Get-ChildItem.*-recurse|find\s+.*-name/i.test(c[i]||''),
  'T1057':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /tasklist|Get-Process|ps\s+-ef/i.test(c[i]||''),
  'T1049':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /netstat|Get-NetTCPConnection|ss\s+-/i.test(c[i]||''),
  'T1033':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /whoami|Get-LocalUser|query\s+user/i.test(c[i]||''),
  'T1016':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /ipconfig|Get-NetIPAddress|ifconfig/i.test(c[i]||''),
  'T1087.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+user\b|Get-LocalUser|wmic\s+useraccount/i.test(c[i]||''),
  'T1087.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+user\s+\/domain|Get-ADUser|dsquery\s+user/i.test(c[i]||''),
  'T1069.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+localgroup|Get-LocalGroup/i.test(c[i]||''),
  'T1069.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+group\s+\/domain|Get-ADGroup/i.test(c[i]||''),
  'T1018':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+view|nltest.*\/dclist|ping\s+-n.*255|arp\s+-a|Resolve-DNSName/i.test(c[i]||''),
  'T1135':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+view.*\\\\/i.test(c[i]||'') || /net\s+share/i.test(c[i]||''),
  'T1046':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /nmap|masscan|portscan|Test-NetConnection.*-port/i.test(c[i]||''),
  'T1012':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /reg\s+query|Get-ItemProperty.*HKLM|Get-ItemProperty.*HKCU/i.test(c[i]||''),
  'T1518.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /Get-MpComputerStatus|sc\s+query\s+windefend|tasklist.*defender/i.test(c[i]||''),
  'T1482':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /nltest.*\/domain_trusts|Get-ADTrust|([Aa]dmPwd)/i.test(c[i]||''),

  // Lateral Movement
  'T1021.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /mstsc|rdp|RemoteDesktop/i.test(f[i]||'') ||
    (rp[i]==='3389') || /mstsc.*\/v:/i.test(c[i]||''),
  'T1021.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+use.*\\\\/i.test(c[i]||'') || (rp[i]==='445') ||
    /PsExec|Invoke-SMBExec/i.test(c[i]||''),
  'T1021.006':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /winrm|Enter-PSSession|Invoke-Command.*-ComputerName/i.test(c[i]||'') ||
    (rp[i]==='5985') || (rp[i]==='5986'),
  'T1570':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /PsExec|xcopy.*\\\\/i.test(c[i]||'') ||
    /robocopy.*\\\\/i.test(c[i]||''),
  'T1550.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /mimikatz.*kerberos|pass.the.ticket|Rubeus/i.test(c[i]||''),

  // Collection
  'T1560.001':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /7z|WinRAR|zip.*-r.*password|Compress-Archive/i.test(c[i]||''),
  'T1005':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /xcopy.*documents|robocopy.*desktop|copy.*\.docx/i.test(c[i]||''),
  'T1113':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /screenshot|PrintScreen|[Ss]nipping|psr\.exe/i.test(c[i]||'') ||
    /psr/i.test(f[i]||''),
  'T1115':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /Get-Clipboard|xclip|xdotool.*getclipboard/i.test(c[i]||''),

  // Command and Control
  'T1105':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /DownloadString|DownloadFile|WebClient|Invoke-WebRequest|wget|curl/i.test(c[i]||'') ||
    /certutil.*-urlcache/i.test(c[i]||'') || /bitsadmin.*\/transfer/i.test(c[i]||''),
  'T1219':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /teamviewer|anydesk|vnc|ngrok|radmin|LogMeIn/i.test(f[i]||'') ||
    /teamviewer|anydesk|vnc|ngrok/i.test(c[i]||''),
  'T1571':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) => {
    const p2 = parseInt(rp[i]||'0',10);
    return p2 > 49151 || [4444,4445,8888,1337,31337,6666,7777,9001,9090].includes(p2);
  },
  'T1071.004':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    (rp[i]==='53') || /nslookup|Resolve-DnsName.*TXT/i.test(c[i]||''),
  'T1572':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /ssh.*-R|ssh.*-L|plink.*-R|chisel|ngrok/i.test(c[i]||''),
  'T1090':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /proxychains|socksify|netsh.*portproxy/i.test(c[i]||''),

  // Exfiltration
  'T1041':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /Invoke-WebRequest.*-Method\s+POST|curl.*-d\s+@/i.test(c[i]||''),
  'T1048.003':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /ftp.*-s|tftp|xcopy.*\\\\/i.test(c[i]||''),
  'T1567.002':(c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /OneDrive|SharePoint|Dropbox|aws\s+s3\s+cp/i.test(c[i]||''),

  // Impact
  'T1486':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /ransomware|\.locked|\.encrypted|vssadmin.*delete.*shadow/i.test(c[i]||'') ||
    /wbadmin.*delete|bcdedit.*safeboot/i.test(c[i]||''),
  'T1490':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /vssadmin.*delete.*shadow|wbadmin.*delete|bcdedit.*recoveryenabled.*no/i.test(c[i]||''),
  'T1489':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /net\s+stop|sc\s+stop|Stop-Service/i.test(c[i]||''),
  'T1485':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /format\s+[a-z]:|sdelete|cipher\s+\/w/i.test(c[i]||''),
  'T1496':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /xmrig|minerd|cryptonight|stratum\+tcp/i.test(c[i]||'') ||
    /xmrig|minerd/i.test(f[i]||''),
  'T1529':    (c,f,fi,p,ri,ru,rp,rk,a,ic,i) =>
    /shutdown\s+\/r|shutdown\s+\/s|Restart-Computer/i.test(c[i]||''),
};

// ── Investigation profiles ────────────────────────────────────────────────────
// cardOrder keys: time | scope | activity | severity | hostsAccounts |
//                 process | procPairs | network | registry | hashes
// primary = top row (most important for this investigation)
// secondary = second row
// remaining cards always appended after

const TACTIC_PROFILES = {
  'default': {
    label: 'General', icon: '🔍',
    hint: 'Full overview — all cards in standard layout',
    primary:   ['time', 'scope', 'activity', 'severity'],
    secondary: ['hostsAccounts', 'process', 'procPairs', 'network', 'registry', 'hashes'],
  },
  'Initial Access': {
    label: 'Initial Access', icon: '🚪',
    hint: 'Phishing, exploits, valid accounts — look for first execution after delivery',
    primary:   ['procPairs', 'hostsAccounts', 'time'],
    secondary: ['network', 'activity', 'process', 'hashes'],
  },
  'Execution': {
    label: 'Execution', icon: '⚡',
    hint: 'What ran, what spawned it, command lines and script activity',
    primary:   ['procPairs', 'process', 'activity'],
    secondary: ['hostsAccounts', 'time', 'network', 'hashes'],
  },
  'Persistence': {
    label: 'Persistence', icon: '🔒',
    hint: 'Registry run keys, scheduled tasks, services — what survived a reboot',
    primary:   ['registry', 'process', 'time'],
    secondary: ['hostsAccounts', 'activity', 'network', 'hashes'],
  },
  'Privilege Escalation': {
    label: 'Privilege Escalation', icon: '⬆',
    hint: 'UAC bypass, token manipulation, elevated processes — who got admin',
    primary:   ['hostsAccounts', 'process', 'procPairs'],
    secondary: ['activity', 'time', 'registry', 'network'],
  },
  'Defense Evasion': {
    label: 'Defense Evasion', icon: '🥷',
    hint: 'LOLBins, obfuscation, log clearing, masquerading — hiding the attack',
    primary:   ['procPairs', 'process', 'registry'],
    secondary: ['hostsAccounts', 'activity', 'time', 'network'],
  },
  'Credential Access': {
    label: 'Credential Access', icon: '🔑',
    hint: 'LSASS dumps, hash theft, password spraying — what credentials were stolen',
    primary:   ['hostsAccounts', 'hashes', 'process'],
    secondary: ['activity', 'time', 'network', 'registry'],
  },
  'Discovery': {
    label: 'Discovery', icon: '🔭',
    hint: 'Recon commands, system/network enumeration — what was the attacker mapping',
    primary:   ['hostsAccounts', 'activity', 'process'],
    secondary: ['network', 'time', 'registry', 'hashes'],
  },
  'Lateral Movement': {
    label: 'Lateral Movement', icon: '↔',
    hint: 'RDP, SMB, WMI, WinRM — connections between hosts, spread pattern',
    primary:   ['network', 'hostsAccounts', 'time'],
    secondary: ['activity', 'process', 'procPairs', 'registry'],
  },
  'Collection': {
    label: 'Collection', icon: '📦',
    hint: 'Files accessed, data staged, archive tools — what was gathered before exfil',
    primary:   ['process', 'network', 'hostsAccounts'],
    secondary: ['activity', 'time', 'hashes', 'registry'],
  },
  'Command and Control': {
    label: 'Command & Control', icon: '📡',
    hint: 'Beaconing, external IPs, C2 domains — the attacker\'s communication channel',
    primary:   ['network', 'time', 'hostsAccounts'],
    secondary: ['activity', 'process', 'hashes', 'registry'],
  },
  'Exfiltration': {
    label: 'Exfiltration', icon: '📤',
    hint: 'Outbound transfers, unusual protocols, data volumes — what left the network',
    primary:   ['network', 'hostsAccounts', 'time'],
    secondary: ['activity', 'process', 'hashes', 'registry'],
  },
  'Impact': {
    label: 'Impact', icon: '💥',
    hint: 'Ransomware, service stops, data destruction — what damage was done',
    primary:   ['activity', 'hostsAccounts', 'time'],
    secondary: ['process', 'registry', 'network', 'hashes'],
  },
};

// ── Technique-level overrides (most common investigations) ────────────────────
const TECHNIQUE_PROFILES = {
  'T1059.001': {
    label: 'PowerShell', icon: '💻',
    hint: 'Encoded commands, download cradles, spawning shells — follow the PowerShell chain',
    primary:   ['procPairs', 'process', 'hostsAccounts'],
    secondary: ['time', 'activity', 'network', 'hashes'],
    badge: 'Open Script Decoder for encoded content',
  },
  'T1059.003': {
    label: 'Cmd Shell', icon: '💻',
    hint: 'What spawned cmd.exe, what commands ran — trace the execution chain',
    primary:   ['procPairs', 'process', 'activity'],
    secondary: ['hostsAccounts', 'time', 'network'],
  },
  'T1047': {
    label: 'WMI Execution', icon: '⚙',
    hint: 'WMI process creation, wmiprvse spawning — remote execution via WMI',
    primary:   ['procPairs', 'process', 'hostsAccounts'],
    secondary: ['network', 'time', 'activity'],
  },
  'T1053.005': {
    label: 'Scheduled Task', icon: '📅',
    hint: 'Task creation events, registry keys — what was scheduled and by whom',
    primary:   ['registry', 'process', 'hostsAccounts'],
    secondary: ['activity', 'time', 'hashes'],
  },
  'T1547.001': {
    label: 'Registry Run Keys', icon: '🗝',
    hint: 'Run key modifications — what process wrote persistence, which machines affected',
    primary:   ['registry', 'hostsAccounts', 'process'],
    secondary: ['activity', 'time', 'hashes'],
  },
  'T1543.003': {
    label: 'Windows Service', icon: '🔧',
    hint: 'New/modified services — service name, binary path, which hosts',
    primary:   ['registry', 'process', 'hostsAccounts'],
    secondary: ['activity', 'time', 'network'],
  },
  'T1003.001': {
    label: 'LSASS Credential Dump', icon: '🔑',
    hint: 'Processes touching lsass, credential tools — which machines, which accounts exposed',
    primary:   ['hostsAccounts', 'process', 'hashes'],
    secondary: ['activity', 'time', 'procPairs'],
  },
  'T1003.006': {
    label: 'DCSync', icon: '🔑',
    hint: 'Domain controller replication abuse — which accounts targeted, source hosts',
    primary:   ['hostsAccounts', 'network', 'process'],
    secondary: ['activity', 'time', 'hashes'],
  },
  'T1558.003': {
    label: 'Kerberoasting', icon: '🎟',
    hint: 'SPN enumeration, ticket requests — targeted service accounts, source hosts',
    primary:   ['hostsAccounts', 'activity', 'process'],
    secondary: ['time', 'network', 'hashes'],
  },
  'T1021.001': {
    label: 'RDP Lateral Movement', icon: '🖥',
    hint: 'Port 3389 connections, source to destination hosts, logon accounts',
    primary:   ['network', 'hostsAccounts', 'time'],
    secondary: ['activity', 'process'],
  },
  'T1021.002': {
    label: 'SMB / Admin Shares', icon: '📁',
    hint: 'Port 445 connections, admin share access, PsExec patterns',
    primary:   ['network', 'hostsAccounts', 'time'],
    secondary: ['process', 'activity', 'procPairs'],
  },
  'T1021.006': {
    label: 'WinRM Lateral Movement', icon: '🖥',
    hint: 'Ports 5985/5986, remote PS sessions, source and destination hosts',
    primary:   ['network', 'hostsAccounts', 'time'],
    secondary: ['process', 'activity'],
  },
  'T1027': {
    label: 'Obfuscation / Encoding', icon: '🥷',
    hint: 'Encoded PowerShell, long cmdlines, base64 — decode to find the real payload',
    primary:   ['procPairs', 'process', 'hostsAccounts'],
    secondary: ['activity', 'time', 'network'],
    badge: 'Open Script Decoder for encoded content',
  },
  'T1218.011': {
    label: 'Rundll32 Proxy Exec', icon: '🔧',
    hint: 'Rundll32 executing DLLs — what DLL, what export, which process spawned it',
    primary:   ['procPairs', 'process', 'hostsAccounts'],
    secondary: ['activity', 'time', 'network'],
  },
  'T1105': {
    label: 'Ingress Tool Transfer', icon: '⬇',
    hint: 'Downloads via PowerShell/certutil/bitsadmin — what was pulled, from where',
    primary:   ['network', 'process', 'hostsAccounts'],
    secondary: ['time', 'activity', 'hashes'],
  },
  'T1071': {
    label: 'C2 Application Layer', icon: '📡',
    hint: 'Web/DNS/mail C2 — beaconing intervals, external IPs, suspicious domains',
    primary:   ['network', 'time', 'hostsAccounts'],
    secondary: ['process', 'activity'],
  },
  'T1571': {
    label: 'Non-Standard Port C2', icon: '📡',
    hint: 'Unusual ports (4444, 8888, 31337) — which process, which external IP',
    primary:   ['network', 'process', 'hostsAccounts'],
    secondary: ['time', 'activity'],
  },
  'T1486': {
    label: 'Data Encrypted (Ransomware)', icon: '🔐',
    hint: 'Mass file encryption, shadow copy deletion, spread speed across hosts',
    primary:   ['activity', 'hostsAccounts', 'time'],
    secondary: ['process', 'registry', 'network'],
  },
  'T1490': {
    label: 'Inhibit System Recovery', icon: '💣',
    hint: 'vssadmin/wbadmin/bcdedit — pre-ransomware staging, which hosts affected',
    primary:   ['process', 'hostsAccounts', 'time'],
    secondary: ['activity', 'registry'],
  },
  'T1562.001': {
    label: 'Disable Security Tools', icon: '🛡',
    hint: 'Defender/AV disabled, firewall changes, audit policy cleared — evasion prep',
    primary:   ['process', 'activity', 'hostsAccounts'],
    secondary: ['registry', 'time'],
  },
  'T1204.002': {
    label: 'Malicious File Execution', icon: '🎣',
    hint: 'Office apps spawning shells — who opened it, what ran, which user targeted',
    primary:   ['procPairs', 'hostsAccounts', 'time'],
    secondary: ['process', 'network', 'activity'],
  },
  'T1496': {
    label: 'Cryptomining', icon: '⛏',
    hint: 'Mining processes, stratum connections, high-CPU processes — which hosts compromised',
    primary:   ['process', 'network', 'hostsAccounts'],
    secondary: ['time', 'activity'],
  },
};
