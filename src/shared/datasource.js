// datasource.js — Data source detection, column mapping, and query building
// Shared by chronicle.js, proctree-ui.js, networkmap.js, script-decoder.js

  // ── Detection ─────────────────────────────────────────────────────────────
  var isChronicleData      = false;
  var isWindowsSecurityLog = false;

  // ── Windows Security Event Log — Event ID to name/ATT&CK mapping ──────────
  var WIN_EVENT_NAMES = {
    '4624':'Logon Success',         '4625':'Logon Failed',
    '4634':'Logoff',                '4647':'User Initiated Logoff',
    '4648':'Explicit Logon',        '4649':'Replay Attack Detected',
    '4672':'Special Privileges',    '4673':'Privileged Service Call',
    '4674':'Privileged Object Op',
    '4688':'Process Created',       '4689':'Process Terminated',
    '4697':'Service Installed',
    '4698':'Scheduled Task Created','4699':'Scheduled Task Deleted',
    '4700':'Scheduled Task Enabled','4701':'Scheduled Task Disabled',
    '4702':'Scheduled Task Updated',
    '4703':'Token Right Adjusted',
    '4704':'User Right Assigned',   '4705':'User Right Removed',
    '4706':'Domain Trust Created',  '4707':'Domain Trust Removed',
    '4713':'Kerberos Policy Change',
    '4716':'Trusted Domain Modified',
    '4719':'Audit Policy Changed',
    '4720':'Account Created',       '4722':'Account Enabled',
    '4723':'Password Change Attempt','4724':'Password Reset',
    '4725':'Account Disabled',      '4726':'Account Deleted',
    '4727':'Global Group Created',  '4728':'Member Added to Global Group',
    '4729':'Member Removed from Global Group',
    '4730':'Global Group Deleted',
    '4731':'Local Group Created',   '4732':'Member Added to Local Group',
    '4733':'Member Removed from Local Group',
    '4734':'Local Group Deleted',   '4735':'Local Group Changed',
    '4737':'Global Group Changed',
    '4738':'Account Changed',       '4740':'Account Locked Out',
    '4741':'Computer Account Created','4742':'Computer Account Changed',
    '4743':'Computer Account Deleted',
    '4756':'Member Added to Universal Group',
    '4757':'Member Removed from Universal Group',
    '4767':'Account Unlocked',
    '4768':'Kerberos TGT Request',  '4769':'Kerberos Service Ticket',
    '4770':'Kerberos Ticket Renewed','4771':'Kerberos Pre-Auth Failed',
    '4776':'NTLM Auth Attempt',     '4777':'NTLM Auth Failed',
    '4778':'Session Reconnected',   '4779':'Session Disconnected',
    '4781':'Account Name Changed',
    '4798':'User Local Groups Enumerated',
    '4799':'Local Group Membership Enumerated',
    '5140':'Network Share Accessed','5145':'Share Access Checked',
    '7034':'Service Crashed',       '7035':'Service Sent Control',
    '7036':'Service State Changed', '7040':'Service Start Type Changed',
    '7045':'New Service Installed',
    '4103':'PS Module Logging',     '4104':'PS Script Block Logged',
    '4105':'PS Script Block Start', '4106':'PS Script Block Stop',
    '1102':'Audit Log Cleared',     '1100':'Event Logging Stopped',
    '4656':'Object Handle Requested','4663':'Object Accessed',
    '4670':'Object Permissions Changed',
  };

  // ATT&CK technique mapped to key Event IDs
  var WIN_EVENT_TTP_MAP = {
    '4688':'T1059',   '4104':'T1059.001', '4103':'T1059.001',
    '4698':'T1053.005','4702':'T1053.005',
    '7045':'T1543.003','4697':'T1543.003',
    '4624':'T1078',   '4625':'T1110',
    '4768':'T1558',   '4769':'T1558.003', '4771':'T1558',
    '4776':'T1550.002',
    '4720':'T1136',   '4726':'T1531',
    '4728':'T1098',   '4732':'T1098',
    '1102':'T1070.001','1100':'T1562.002',
    '4719':'T1562.002',
    '5140':'T1039',   '5145':'T1039',
    '4648':'T1021',
  };

  var WIN_LOGON_TYPES = {
    '2':'Interactive','3':'Network','4':'Batch','5':'Service',
    '7':'Unlock','8':'NetworkCleartext','9':'NewCredentials',
    '10':'RemoteInteractive','11':'CachedInteractive',
  };

  var UDM_SIGNALS = [
    // Without udm. prefix (older exports)
    'metadata.event_type','metadata.event_timestamp','metadata.ingested_timestamp',
    'principal.hostname','principal.ip','principal.process.command_line',
    'principal.process.file.full_path','principal.user.userid',
    'target.ip','target.hostname','target.port',
    'security_result.severity','security_result.summary','security_result.rule_name',
    'network.application_protocol','principal.process.file.sha256',
    // With udm. prefix (newer Chronicle CSV exports)
    'udm.metadata.event_type','udm.metadata.event_timestamp','udm.metadata.ingested_timestamp',
    'udm.metadata.log_type','udm.metadata.description','udm.metadata.product_name',
    'udm.principal.hostname','udm.principal.ip','udm.principal.process.command_line',
    'udm.principal.process.file.full_path','udm.principal.user.userid',
    'udm.target.ip','udm.target.hostname','udm.target.port',
    'udm.security_result.severity','udm.security_result.summary','udm.security_result.rule_name',
    'udm.network.application_protocol','udm.principal.process.file.sha256',
  ];

  var DEFENDER_SIGNALS = [
    'action type','actiontype','initiating process file name','initiatingprocessfilename',
    'initiating process id','initiatingprocessid','process command line','processcommandline',
    'initiating process command line','folder path','folderpath','process creation time',
    'initiating process sha256','report id','reportid','additional fields',
  ];

  var WINDOWS_SECURITY_SIGNALS = [
    'eventid','event id','subjectusername','subject user name',
    'targetusername','target user name','logontype','logon type',
    'subjectdomainname','targetdomainname','newprocessname',
    'parentprocessname','authenticationpackagename',
    'workstationname','ipaddress','ipport','status','substatus',
  ];

  function detectChronicleData(hdrs) {
    if (!hdrs || !hdrs.length) {
      isChronicleData = false; isWindowsSecurityLog = false;
      udmUpdateBadge(); return false;
    }
    const lower = hdrs.map(h => (h || '').toLowerCase().trim());
    const udmHits      = UDM_SIGNALS.filter(s => lower.includes(s) || lower.includes(s.replace(/^udm\./, '')));
    const defenderHits = DEFENDER_SIGNALS.filter(s => lower.includes(s));
    const winSecHits   = WINDOWS_SECURITY_SIGNALS.filter(s => lower.includes(s));

    isChronicleData      = udmHits.length >= 2;
    isWindowsSecurityLog = !isChronicleData && defenderHits.length < 2 && winSecHits.length >= 3;

    // Run Sift module detection — sets active module + syncs global flags
    if (typeof Sift !== 'undefined') Sift.detect(hdrs);

    udmUpdateBadge(defenderHits.length >= 2);
    return isChronicleData;
  }

  function udmUpdateBadge(isDefender) {
    const dsb = document.getElementById('dataSourceBadge');
    if (!dsb) return;

    // If a Sift module is active, use its badge config
    if (typeof Sift !== 'undefined' && Sift.getBadge()) {
      const b = Sift.getBadge();
      dsb.textContent  = b.text;
      dsb.style.display    = '';
      dsb.style.background = b.bg;
      dsb.style.border     = b.border;
      dsb.style.color      = b.color;
      return;
    }

    // Fallback for when no module is loaded
    if (isChronicleData) {
      dsb.textContent = 'Chronicle';
      dsb.style.display = '';
      dsb.style.background = 'rgba(66,133,244,0.15)';
      dsb.style.border = '1px solid #4285f4';
      dsb.style.color = '#4285f4';
    } else if (isDefender) {
      dsb.textContent = 'Defender';
      dsb.style.display = '';
      dsb.style.background = 'rgba(0,120,212,0.15)';
      dsb.style.border = '1px solid #0078d4';
      dsb.style.color = '#0078d4';
    } else if (isWindowsSecurityLog) {
      dsb.textContent = 'Windows Security';
      dsb.style.display = '';
      dsb.style.background = 'rgba(0,188,102,0.15)';
      dsb.style.border = '1px solid #00bc66';
      dsb.style.color = '#00bc66';
    } else {
      dsb.style.display = 'none';
    }
  }

  // ── Chronicle query building ───────────────────────────────────────────────
  // Chronicle UDM field mappings — validated against Chronicle UDM schema reference
  var UDM_COL_MAP = {
    // Action / event type
    'action type':                        'metadata.event_type',
    'actiontype':                         'metadata.event_type',
    // Device / host
    'computer name':                      'principal.hostname',
    'devicename':                         'principal.hostname',
    'machine id':                         'principal.hostname',
    'deviceid':                           'principal.asset.id',
    // User / account
    'account name':                       'principal.user.userid',
    'accountname':                        'principal.user.userid',
    'initiatingprocessaccountname':       'principal.user.userid',
    'accountupn':                         'principal.user.email_addresses',
    // Process file
    'file name':                          'principal.process.file.full_path',
    'filename':                           'principal.process.file.full_path',
    'folder path':                        'principal.process.file.full_path',
    'folderpath':                         'principal.process.file.full_path',
    'initiating process file name':       'principal.process.file.full_path',
    'initiatingprocessfilename':          'principal.process.file.full_path',
    // Process identifiers
    'process id':                         'principal.process.pid',
    'processid':                          'principal.process.pid',
    // Command lines
    'process command line':               'principal.process.command_line',
    'processcommandline':                 'principal.process.command_line',
    'initiating process command line':    'principal.process.command_line',
    'initiatingprocesscommandline':       'principal.process.command_line',
    // Network — target
    'remote ip':                          'target.ip',
    'remoteip':                           'target.ip',
    'remote url':                         'target.hostname',
    'remoteurl':                          'target.hostname',
    'remotednsname':                      'target.hostname',
    'remote port':                        'target.port',
    'remoteport':                         'target.port',
    // Network — principal
    'local ip':                           'principal.ip',
    'localip':                            'principal.ip',
    'local port':                         'principal.port',
    'localport':                          'principal.port',
    // Protocol
    'protocol':                           'network.ip_protocol',
    // Hashes — correct UDM paths use hashes.* sub-object
    'sha256':                             'principal.process.file.hashes.sha256',
    'initiating process sha256':          'principal.process.file.hashes.sha256',
    'initiatingprocesssha256':            'principal.process.file.hashes.sha256',
    'md5':                                'principal.process.file.hashes.md5',
    'initiatingprocessmd5':               'principal.process.file.hashes.md5',
    'sha1':                               'principal.process.file.hashes.sha1',
    'initiatingprocesssha1':              'principal.process.file.hashes.sha1',
    // Registry
    'registry key':                       'target.registry.registry_key',
    'registrykey':                        'target.registry.registry_key',
    'registry value name':                'target.registry.registry_value_name',
    'registryvaluename':                  'target.registry.registry_value_name',
    'registry value data':                'target.registry.registry_value_data',
    'registryvaluedata':                  'target.registry.registry_value_data',
    // Metadata
    'report id':                          'metadata.id',
    'reportid':                           'metadata.id',
  };

  function colToUdmField(col) {
    const c = (col || '').trim();
    if (c.toLowerCase().startsWith('udm.')) return c.slice(4);
    if (c.includes('.')) return c;
    return UDM_COL_MAP[c.toLowerCase()] || null;
  }

  // Chronicle SIEM Search query builder — schema: chronicle-udm-schema-reference.md
  // Syntax: exact match uses =, substring/regex uses /.../nocase, numerics unquoted
  function buildChronicleQuery(col, val) {
    var v   = (val || '').trim();
    var udm = colToUdmField(col);
    var c   = (col || '').trim().toLowerCase().replace(/[\s_]/g, '');

    var isIP     = /^(\d{1,3}\.){3}\d{1,3}$/.test(v);
    var isMd5    = /^[0-9a-f]{32}$/i.test(v);
    var isSha1   = /^[0-9a-f]{40}$/i.test(v);
    var isSha256 = /^[0-9a-f]{64}$/i.test(v);
    var isNum    = /^\d+$/.test(v);

    // Fields that use regex/substring matching (per Chronicle search syntax docs)
    var isSubstringField = udm && /command_line|full_path|hostname|url/.test(udm);
    // Fields that are numeric (no quotes)
    var isNumericField   = udm && /\.port$|\.pid$|\.id$|num_/.test(udm);

    // Escape all RE2 metacharacters so the value is treated as a literal within /.../ syntax
    var regEsc = v.replace(/[\\\/.*+?^${}()|[\]]/g, '\\$&');
    var strEsc = v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

    if (udm) {
      if (isNumericField && isNum)  return udm + ' = ' + v;
      if (isSubstringField)         return udm + ' = /' + regEsc + '/ nocase';
      return udm + ' = "' + strEsc + '"';
    }

    // No UDM mapping — use value shape detection
    // Hashes: search principal (process) and target (file) — per UDM schema hashes.* paths
    if (isSha256)
      return 'principal.process.file.hashes.sha256 = "' + strEsc + '" OR target.file.hashes.sha256 = "' + strEsc + '"';
    if (isSha1)
      return 'principal.process.file.hashes.sha1 = "' + strEsc + '" OR target.file.hashes.sha1 = "' + strEsc + '"';
    if (isMd5)
      return 'principal.process.file.hashes.md5 = "' + strEsc + '" OR target.file.hashes.md5 = "' + strEsc + '"';
    // IP: search both principal (source) and target (destination)
    if (isIP)
      return 'principal.ip = "' + strEsc + '" OR target.ip = "' + strEsc + '"';

    return '"' + strEsc + '"';
  }

  function buildChronicleSearchUrl(col, val) {
    const base = (typeof getChronicleUrl === 'function') ? getChronicleUrl() : '';
    if (!base) return null;
    const query = buildChronicleQuery(col, val);
    return base.replace(/\/$/, '') + '/search?query=' + encodeURIComponent(query);
  }

  function chroniclePivot(col, val) {
    const url = buildChronicleSearchUrl(col, val);
    if (!url) return null;
    const query = buildChronicleQuery(col, val);
    const label = 'Chronicle  ' + (query.length > 40 ? query.slice(0, 37) + '…' : query);
    return { icon: '🔵', label, url };
  }

  function udmEventColor(action) {
    const a = (action || '').toUpperCase();
    if (a === 'PROCESS_LAUNCH' || a === 'PROCESS_TERMINATION')  return '#e05c3a';
    if (a === 'NETWORK_CONNECTION' || a === 'DNS_QUERY')        return '#3a9fd6';
    if (a === 'FILE_CREATION' || a === 'FILE_MODIFICATION' ||
        a === 'FILE_DELETION')                                  return '#c45ab3';
    if (a === 'REGISTRY_VALUE_SET' || a === 'REGISTRY_VALUE_DELETION') return '#f0a500';
    if (a === 'USER_LOGIN' || a === 'USER_LOGOUT' ||
        a === 'USER_RESOURCE_ACCESS')                           return '#f06292';
    if (a === 'SCAN_UNCATEGORIZED' || a === 'SCAN_VULN_HOST')  return '#9c6ade';
    if (a === 'EMAIL_TRANSACTION' || a === 'EMAIL_UNCATEGORIZED') return '#26a69a';
    return null;
  }

  // ── Column resolution (shared by proctree, networkmap, script-decoder) ─────
  var PT_COL = {
    ts:            ['Event Time','Timestamp','timestamp','EventTime',
                    'TimeCreated','timecreated','Time Created',
                    'metadata.event_timestamp','metadata.ingested_timestamp','event_timestamp',
                    'udm.metadata.event_timestamp','udm.metadata.ingested_timestamp','udm.metadata.collected_timestamp'],
    action:        ['Action Type','ActionType','actiontype',
                    'EventID','eventid','Event ID',
                    'metadata.event_type','udm.metadata.event_type'],
    fileName:      ['File Name','FileName','filename',
                    'NewProcessName','newprocessname','New Process Name',
                    'ProcessName','processname',
                    'principal.process.file.full_path','principal.process.file.basename',
                    'udm.principal.process.file.full_path','udm.principal.process.file.basename'],
    filePath:      ['Folder Path','FolderPath','folderpath',
                    'ProcessPath','processpath',
                    'principal.process.file.full_path','udm.principal.process.file.full_path'],
    pid:           ['Process Id','ProcessId','processid',
                    'NewProcessId','newprocessid','ProcessId',
                    'principal.process.pid','udm.principal.process.pid'],
    cmdline:       ['Process Command Line','ProcessCommandLine','CommandLine','commandline',
                    'Command Line','ProcessCommandline',
                    'principal.process.command_line','udm.principal.process.command_line'],
    initFile:      ['Initiating Process File Name','InitiatingProcessFileName','InitiatingProcessfilename',
                    'ParentProcessName','parentprocessname','Parent Process Name',
                    'principal.process.parent_process.file.full_path','principal.process.parent_process.file.basename',
                    'udm.principal.process.parent_process.file.full_path','udm.principal.process.parent_process.file.basename'],
    initPid:       ['Initiating Process Id','InitiatingProcessId',
                    'ProcessId','principal.process.parent_process.pid','udm.principal.process.parent_process.pid'],
    initCmd:       ['Initiating Process Command Line','InitiatingProcessCommandLine',
                    'principal.process.parent_process.command_line','udm.principal.process.parent_process.command_line'],
    initPath:      ['Initiating Process Folder Path','InitiatingProcessFolderPath',
                    'principal.process.parent_process.file.full_path','udm.principal.process.parent_process.file.full_path'],
    initParentId:  ['Initiating Process Parent Id','InitiatingProcessParentId'],
    initParentFile:['Initiating Process Parent File Name','InitiatingProcessParentFileName'],
    initCreation:  ['Initiating Process Creation Time','InitiatingProcessCreationTime'],
    initParentCreation: ['Initiating Process Parent Creation Time','InitiatingProcessParentCreationTime'],
    device:        ['Computer Name','DeviceName','devicename','ComputerName','Machine Id',
                    'Computer','computer','WorkstationName','workstationname','Workstation Name',
                    'principal.hostname','principal.asset.hostname',
                    'udm.principal.hostname','udm.principal.asset.hostname'],
    user:          ['Account Name','AccountName','InitiatingProcessAccountName','Initiating Process Account Name',
                    'SubjectUserName','subjectusername','Subject User Name',
                    'TargetUserName','targetusername','Target User Name',
                    'principal.user.userid','principal.user.user_display_name',
                    'udm.principal.user.userid','udm.principal.user.user_display_name'],
    remoteIp:      ['Remote IP','RemoteIP','remoteip',
                    'IpAddress','ipaddress','Ip Address','IpAddres',
                    'target.ip','network.destination.ip',
                    'udm.target.ip','udm.network.destination.ip'],
    remoteUrl:     ['Remote Url','RemoteUrl','RemoteDnsName','Remote Computer Name',
                    'target.hostname','target.url',
                    'udm.target.hostname','udm.target.url'],
    remotePort:    ['Remote Port','RemotePort',
                    'IpPort','ipport','Ip Port',
                    'target.port','network.destination.port',
                    'udm.target.port','udm.network.destination.port'],
    localPort:     ['Local Port','LocalPort',
                    'principal.port','network.source.port',
                    'udm.principal.port','udm.network.source.port'],
    localIp:       ['Local IP','LocalIP',
                    'principal.ip',
                    'udm.principal.ip'],
    sha256:        ['Sha256','SHA256','sha256','Initiating Process SHA256',
                    'principal.process.file.sha256','target.file.sha256',
                    'udm.principal.process.file.sha256','udm.target.file.sha256'],
    sha1:          ['Sha1','SHA1','sha1',
                    'principal.process.file.sha1','target.file.sha1',
                    'udm.principal.process.file.sha1','udm.target.file.sha1'],
    md5:           ['MD5','md5',
                    'principal.process.file.md5','target.file.md5',
                    'udm.principal.process.file.md5','udm.target.file.md5'],
    regKey:        ['Registry Key','RegistryKey',
                    'target.registry.registry_key',
                    'udm.target.registry.registry_key'],
    regVal:        ['Registry Value Name','RegistryValueName',
                    'target.registry.registry_value_name',
                    'udm.target.registry.registry_value_name'],
    regData:       ['Registry Value Data','RegistryValueData',
                    'target.registry.registry_value_data',
                    'udm.target.registry.registry_value_data'],
    procCreation:  ['Process Creation Time','ProcessCreationTime'],
    integrity:     ['Process Integrity Level','ProcessIntegrityLevel'],
    reportId:      ['Report Id','ReportId','metadata.id','udm.metadata.id'],
    // ── Windows Security Log specific ────────────────────────────────────────
    winEventId:    ['EventID','eventid','Event ID'],
    winLogonType:  ['LogonType','logontype','Logon Type'],
    winSubjectUser:['SubjectUserName','subjectusername','Subject User Name'],
    winTargetUser: ['TargetUserName','targetusername','Target User Name'],
    winSubjectDomain:['SubjectDomainName','subjectdomainname'],
    winTargetDomain: ['TargetDomainName','targetdomainname'],
    winStatus:     ['Status','status','FailureReason','failurereason'],
    winSubStatus:  ['SubStatus','substatus'],
    winAuthPkg:    ['AuthenticationPackageName','authenticationpackagename','Authentication Package Name'],
    winKeyLen:     ['KeyLength','keylength'],
    winLogonProcess:['LogonProcessName','logonprocessname'],
    winChannel:    ['Channel','channel','Keywords','keywords'],
  };

  var ptColMap = {};

  function ptResolveColumns(hdrs) {
    ptColMap = {};
    const cleaned = hdrs.map(h => (h || '').replace(/^﻿/, '').trim().toLowerCase());
    Object.entries(PT_COL).forEach(([key, candidates]) => {
      for (const c of candidates) {
        const idx = cleaned.indexOf(c.toLowerCase().trim());
        if (idx !== -1) { ptColMap[key] = hdrs[idx]; return; }
      }
    });

    // Windows Security 4688 PID override:
    // Defender:  ProcessId = child PID,  InitiatingProcessId = parent PID
    // Win 4688:  NewProcessId = child,   ProcessId = parent/creator PID
    // Without this fix both pid and initPid resolve to ProcessId and the tree links to itself.
    if (typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog) {
      const newProcId = hdrs.find(h => h.replace(/^﻿/,'').trim().toLowerCase() === 'newprocessid');
      const procId    = hdrs.find(h => h.replace(/^﻿/,'').trim().toLowerCase() === 'processid');
      if (newProcId) ptColMap.pid    = newProcId;
      if (procId)    ptColMap.initPid = procId;
    }
  }

  function ptGet(row, key) {
    const col = ptColMap[key];
    if (!col) return '';
    if (col in row) return row[col] || '';
    const trimmedCol = col.trim();
    const found = Object.keys(row).find(k => k.trim() === trimmedCol);
    return found ? (row[found] || '') : '';
  }

  function ptHasDefenderCols() {
    if (!headers.length) return false;
    const lower = headers.map(h => h.toLowerCase().trim().replace(/^﻿/, ''));
    const defenderSignals = [
      'event time', 'action type', 'file name', 'folder path',
      'process id', 'process command line', 'process creation time',
      'initiating process file name', 'initiating process id',
      'initiating process command line', 'initiating process folder path',
      'initiating process parent file name',
      'computer name', 'machine id', 'account name', 'account domain',
      'remote ip', 'remote url', 'remote port', 'local ip', 'local port',
      'registry key', 'registry value name',
      'sha1', 'sha256', 'md5',
      'report id', 'additional fields',
      'actiontype', 'filename', 'processid', 'initiatingprocessfilename',
      'devicename', 'processcommandline',
    ];
    const udmSignals = [
      'metadata.event_type', 'principal.process.command_line', 'principal.hostname',
      'principal.process.file.full_path', 'principal.process.pid',
      'target.ip', 'target.hostname', 'target.port',
    ];
    const matchesDefender = defenderSignals.filter(sig =>
      lower.some(h => h === sig || h.includes(sig))
    ).length;
    const matchesUdm = udmSignals.filter(sig =>
      lower.includes(sig) || lower.includes('udm.' + sig)
    ).length;
    return matchesDefender >= 2 || matchesUdm >= 2;
  }

  // ── IOC pivot detection ────────────────────────────────────────────────────
  function buildPivots(val, col) {
    const v = (val || '').trim();
    if (!v || v.length < 3) return [];
    const pivots = [];
    const isIP     = /^(\d{1,3}\.){3}\d{1,3}$/.test(v);
    const isHash   = /^[0-9a-f]{32}$/i.test(v) || /^[0-9a-f]{40}$/i.test(v) || /^[0-9a-f]{64}$/i.test(v);
    const isDomain = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/i.test(v) && !isIP;
    const isUrl    = /^https?:\/\//i.test(v);
    const isB64    = /^[A-Za-z0-9+\/]{40,}={0,2}$/.test(v);

    if (isIP || isHash || isDomain || isUrl) {
      pivots.push({ icon: '🦠', label: 'VirusTotal', url: 'https://www.virustotal.com/gui/search/' + encodeURIComponent(v) });
    }
    if (isIP) {
      pivots.push({ icon: '🔭', label: 'Shodan', url: 'https://www.shodan.io/host/' + encodeURIComponent(v) });
    }
    if (isB64 || isHash || v.length > 8) {
      pivots.push({ icon: '⚗️', label: 'CyberChef', url: 'https://cyberchef.org/#input=' + encodeURIComponent(btoa(v)) });
    }
    if (typeof chroniclePivot === 'function') {
      const cp = chroniclePivot(col || '', v);
      if (cp) pivots.push(cp);
    }
    return pivots;
  }

  // ── Defender Advanced Hunting KQL query builder ───────────────────────────
  // Defender Advanced Hunting query builder — schema: ms-defender-schema-reference.md
  function buildDefenderQuery(col, val) {
    var v = (val || '').trim();
    if (!v) return null;
    // Normalise column name: lowercase, strip spaces/underscores for hint matching
    var c = (col || '').trim().toLowerCase().replace(/[\s_]/g, '');

    var isIP     = /^(\d{1,3}\.){3}\d{1,3}$/.test(v);
    var isMd5    = /^[0-9a-f]{32}$/i.test(v);
    var isSha1   = /^[0-9a-f]{40}$/i.test(v);
    var isSha256 = /^[0-9a-f]{64}$/i.test(v);
    var isDomain = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/i.test(v) && !isIP;
    var isUrl    = /^https?:\/\//i.test(v);

    // Column hints — matched against normalised col name
    var colSha256   = /sha256/.test(c);
    var colSha1     = /sha1/.test(c) && !/sha256/.test(c);
    var colMd5      = /\bmd5\b|(?:^|[^a-z])md5(?:[^a-z]|$)/.test(c) || c === 'md5';
    var colIp       = /remoteip|localip|ipaddress|fileoriginip|requestsourceip/.test(c) || c === 'ip';
    var colUrl      = /remoteurl|fileoriginurl|url/.test(c);
    var colDomain   = /remotedns|domain/.test(c);
    var colCmdline  = /commandline|cmdline/.test(c);
    var colFile     = /^filename$|^folderpath$|^filepath$|^folder$/.test(c);
    var colProcName = /^initiatingprocessfilename$|^processname$/.test(c);
    var colAccount  = /^accountname$|^initiatingprocessaccountname$/.test(c);
    var colUpn      = /accountupn|userprincipal|upn/.test(c);
    var colDevice   = /^devicename$|^computername$|^deviceid$/.test(c);
    var colReg      = /registrykey|registryvalue|registryvaluedata/.test(c);
    var colAction   = /^actiontype$/.test(c);
    var colLogon    = /^logontype$|^failurereason$/.test(c);
    var colProtocol = /^protocol$/.test(c);
    var colPort     = /^remoteport$|^localport$/.test(c);
    var colSeverity = /^severity$|^alertid$|^title$|^category$|^attacktechniques$/.test(c);
    var colInteg    = /integritylevel|tokenelevation/.test(c);
    var colDomain2  = /^accountdomain$/.test(c);
    var colReportId = /^reportid$/.test(c);

    var esc = v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

    // SHA256 — DeviceProcessEvents covers both the process file hash and initiating process hash
    if (isSha256 || colSha256)
      return 'DeviceProcessEvents\n| where SHA256 == "' + esc + '" or InitiatingProcessSHA256 == "' + esc + '"';

    // SHA1
    if (isSha1 || colSha1)
      return 'DeviceProcessEvents\n| where SHA1 == "' + esc + '" or InitiatingProcessSHA1 == "' + esc + '"';

    // MD5
    if (isMd5 || colMd5)
      return 'DeviceProcessEvents\n| where MD5 == "' + esc + '" or InitiatingProcessMD5 == "' + esc + '"';

    // IP address — DeviceNetworkEvents: RemoteIP, LocalIP
    if (isIP || colIp)
      return 'DeviceNetworkEvents\n| where RemoteIP == "' + esc + '" or LocalIP == "' + esc + '"';

    // URL — DeviceNetworkEvents: RemoteUrl
    if (isUrl || colUrl)
      return 'DeviceNetworkEvents\n| where RemoteUrl has "' + esc + '"';

    // Domain — DeviceNetworkEvents: RemoteUrl
    if (isDomain || colDomain)
      return 'DeviceNetworkEvents\n| where RemoteUrl has "' + esc + '"';

    // Command line — DeviceProcessEvents: ProcessCommandLine + InitiatingProcessCommandLine
    if (colCmdline)
      return 'DeviceProcessEvents\n| where ProcessCommandLine has "' + esc + '" or InitiatingProcessCommandLine has "' + esc + '"';

    // File name / folder path — DeviceFileEvents: FileName, FolderPath
    if (colFile)
      return 'DeviceFileEvents\n| where FileName has "' + esc + '" or FolderPath has "' + esc + '"';

    // Initiating process / process name — DeviceProcessEvents: FileName, InitiatingProcessFileName
    if (colProcName)
      return 'DeviceProcessEvents\n| where FileName == "' + esc + '" or InitiatingProcessFileName == "' + esc + '"';

    // Account UPN — DeviceLogonEvents: AccountUpn (per schema IdentityLogonEvents / DeviceLogonEvents)
    if (colUpn)
      return 'DeviceLogonEvents\n| where AccountUpn == "' + esc + '"';

    // Account name — DeviceLogonEvents: AccountName, AccountDomain
    if (colAccount)
      return 'DeviceLogonEvents\n| where AccountName == "' + esc + '"';

    // Device name — DeviceProcessEvents: DeviceName (present in all tables)
    if (colDevice)
      return 'DeviceProcessEvents\n| where DeviceName == "' + esc + '"';

    // Registry — DeviceEvents: RegistryKey, RegistryValueName, RegistryValueData
    if (colReg)
      return 'DeviceEvents\n| where RegistryKey has "' + esc + '" or RegistryValueName has "' + esc + '" or RegistryValueData has "' + esc + '"';

    // Logon type / failure / protocol — DeviceLogonEvents
    if (colLogon)
      return 'DeviceLogonEvents\n| where LogonType == "' + esc + '" or FailureReason has "' + esc + '"';

    // Integrity / token elevation — DeviceProcessEvents: ProcessIntegrityLevel, ProcessTokenElevation
    if (colInteg)
      return 'DeviceProcessEvents\n| where ProcessIntegrityLevel == "' + esc + '"';

    // ActionType — present across all Device* tables; DeviceEvents is the broadest
    if (colAction)
      return 'DeviceEvents\n| where ActionType == "' + esc + '"';

    // Logon type / failure reason — DeviceLogonEvents
    if (colLogon)
      return 'DeviceLogonEvents\n| where LogonType == "' + esc + '" or FailureReason has "' + esc + '"';

    // Protocol — DeviceNetworkEvents: Protocol (TCP, UDP, etc.)
    if (colProtocol)
      return 'DeviceNetworkEvents\n| where Protocol == "' + esc + '"';

    // Remote/Local port — DeviceNetworkEvents
    if (colPort)
      return 'DeviceNetworkEvents\n| where RemotePort == ' + (isNaN(v) ? '"' + esc + '"' : v) + ' or LocalPort == ' + (isNaN(v) ? '"' + esc + '"' : v);

    // Alert severity / title / attack techniques — AlertEvidence / AlertInfo
    if (colSeverity)
      return 'AlertEvidence\n| where Severity == "' + esc + '" or Title has "' + esc + '" or AttackTechniques has "' + esc + '"';

    // Account domain — DeviceLogonEvents
    if (colDomain2)
      return 'DeviceLogonEvents\n| where AccountDomain == "' + esc + '"';

    // ReportId — present in most Device* tables
    if (colReportId)
      return 'DeviceProcessEvents\n| where ReportId == ' + (isNaN(v) ? '"' + esc + '"' : v);

    // Fallback — search process command lines and file names
    return 'DeviceProcessEvents\n| where ProcessCommandLine has "' + esc + '" or FileName has "' + esc + '"';
  }

  // Returns true if a value+column combo is worth showing query items for.
  // Covers any field searchable in Defender Advanced Hunting or Chronicle UDM.
  function _isQueryableIoc(col, val) {
    var v = (val || '').trim();
    var c = (col || '').trim().toLowerCase().replace(/[\s_]/g, '');
    if (!v || v.length < 2) return false;

    // IOC value shapes — always show regardless of column
    var isHash   = /^[0-9a-f]{32}$/i.test(v) || /^[0-9a-f]{40}$/i.test(v) || /^[0-9a-f]{64}$/i.test(v);
    var isIP     = /^(\d{1,3}\.){3}\d{1,3}$/.test(v);
    var isDomain = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/i.test(v) && !isIP;
    var isUrl    = /^https?:\/\//i.test(v);
    if (isHash || isIP || isDomain || isUrl) return true;

    // Defender schema columns (DeviceProcessEvents, DeviceFileEvents,
    // DeviceNetworkEvents, DeviceLogonEvents, DeviceEvents, AlertEvidence, AlertInfo)
    var defenderCol = /sha256|sha1|md5|remoteip|localip|remoteurl|remotedns|remoteport|localport|processcommandline|initiatingprocesscommandline|commandline|cmdline|filename|folderpath|filepath|fileoriginurl|fileoriginip|actiontype|logontype|protocol|failurereason|islocaladmin|accountname|accountdomain|accountsid|accountupn|accountobjectid|devicename|deviceid|computername|hostname|machineid|registrykey|registryvaluename|registryvaluedata|processid|initiatingprocessid|processintegritylevel|processtokenelevation|initiatingprocessfilename|initiatingprocesssha256|initiatingprocesssha1|initiatingprocessmd5|severity|alertid|title|category|attacktechniques|threatfamily|entitytype|evidencerole|detectionsource|reportid|additionalfields|remotedevicename|logonid|sessionid/.test(c);
    if (defenderCol) return true;

    // Chronicle / UDM fields (bare or udm. prefixed)
    var udmCol = /metadata\b|principal\b|target\b|network\b|security.?result|event.?type|event.?timestamp|log.?type|userid|command.?line|registry.?key|registry.?value|application.?protocol/.test(c);
    if (udmCol) return true;

    // Windows Security Event Log columns
    var winSecCol = /eventid|subjectusername|targetusername|subjectdomainname|targetdomainname|logontype|ipaddress|ipport|newprocessname|parentprocessname|commandline|workstationname|authenticationpackagename|logonprocessname|status|substatus|servicename|servicefilename|membername|groupname|groupdomain|newprocessid|processid|failurereason|keylength|channel/.test(c);
    if (winSecCol) return true;

    // Allow any value longer than 3 chars from any column when Windows Security log is active
    if (typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog && v.length > 3) return true;

    return false;
  }

  // ── Multi-condition query builders ───────────────────────────────────────
  function buildChronicleQueryMulti(conditions, logic) {
    if (!conditions.length) return '';
    var parts = conditions.map(function(c) {
      return buildChronicleQuery(c.col, c.val);
    }).filter(Boolean);
    if (!parts.length) return '';
    var op = '\n' + (logic === 'OR' ? 'OR ' : 'AND ');
    // Wrap conditions that contain their own OR in parens to preserve operator precedence
    if (logic === 'AND') {
      parts = parts.map(function(p) {
        return p.indexOf(' OR ') !== -1 ? '(' + p + ')' : p;
      });
    }
    return parts.join(op);
  }

  function buildDefenderQueryMulti(conditions, logic) {
    if (!conditions.length) return '';

    // Parse each condition into { table, cond } pairs
    var parsed = [];
    conditions.forEach(function(c) {
      var q = buildDefenderQuery(c.col, c.val);
      if (!q) return;
      var lines = q.split('\n');
      var table = lines[0].trim();
      var cond  = (lines[1] || '').replace(/^\|\s*where\s+/, '').trim();
      if (table && cond) parsed.push({ table: table, cond: cond });
    });
    if (!parsed.length) return '';

    // Group conditions by table
    var tableMap = {};
    parsed.forEach(function(p) {
      if (!tableMap[p.table]) tableMap[p.table] = [];
      tableMap[p.table].push(p.cond);
    });
    var tables = Object.keys(tableMap);

    if (logic === 'OR') {
      // OR across multiple tables: union works correctly in KQL because missing
      // columns resolve to null (falsy), so only the right table matches each condition.
      var prefix = tables.length === 1 ? tables[0] : 'union ' + tables.join(', ');
      var allConds = parsed.map(function(p) {
        return p.cond.indexOf(' or ') !== -1 ? '(' + p.cond + ')' : p.cond;
      });
      return prefix + '\n| where ' + allConds.join('\nor ');
    }

    // AND logic ──────────────────────────────────────────────────────────────
    if (tables.length === 1) {
      // All conditions in the same table: chain | where clauses (AND semantics in KQL)
      return tables[0] + '\n| where ' + tableMap[tables[0]].join('\n| where ');
    }

    // AND across multiple tables: chaining | where on a union returns zero results
    // because each table is missing the other table's columns.
    // Generate separate per-table queries + a DeviceName correlation template.
    var parts = [];
    tables.forEach(function(t) {
      var conds = tableMap[t];
      parts.push('// ' + t + '\n' + t + '\n| where ' + conds.join('\n| where '));
    });

    // Correlation template: find devices appearing in ALL table results
    var lets = tables.map(function(t, i) {
      var conds = tableMap[t];
      return 'let q' + (i + 1) + ' = ' + t + '\n    | where ' + conds.join('\n    | where ') + '\n    | distinct DeviceName;';
    });
    var joinChain = 'q1';
    for (var i = 1; i < tables.length; i++) {
      joinChain += '\n| join kind=inner q' + (i + 1) + ' on DeviceName';
    }

    return [
      '// AND conditions span multiple tables — separate queries below.',
      '// Run each individually, or use the correlation block to find devices matching ALL.',
      '',
      parts.join('\n\n'),
      '',
      '// ── Correlate by DeviceName (devices matching ALL conditions) ──',
      lets.join('\n'),
      joinChain,
    ].join('\n');
  }

  // Returns ready-to-push menu items for Chronicle + Defender queries.
  // suffix is an optional short label shown in parentheses, e.g. "SHA256" or "1.2.3.4".
  // Always returns both options — callers decide when to show them.
  // ── Sentinel SecurityEvent KQL builder ───────────────────────────────────────
  function buildSentinelKQL(col, val) {
    var v = (val || '').trim();
    if (!v) return null;
    var c = (col || '').trim().toLowerCase().replace(/[\s_]/g, '');
    var esc = v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    var isIP   = /^(\d{1,3}\.){3}\d{1,3}$/.test(v);
    var isNum  = /^\d+$/.test(v);

    // EventID — exact match with name hint
    if (c === 'eventid' || c === 'wineventid') {
      var ename = (typeof WIN_EVENT_NAMES !== 'undefined' && WIN_EVENT_NAMES[v]) ? ' // ' + WIN_EVENT_NAMES[v] : '';
      return 'SecurityEvent\n| where EventID == ' + v + ename;
    }
    // Account / user columns
    if (/subjectusername|targetusername|accountname|username/.test(c))
      return 'SecurityEvent\n| where SubjectUserName =~ "' + esc + '" or TargetUserName =~ "' + esc + '"';
    // Computer / device
    if (/computer|devicename|workstation/.test(c))
      return 'SecurityEvent\n| where Computer =~ "' + esc + '"';
    // Command line — process creation context
    if (/commandline|cmdline/.test(c))
      return 'SecurityEvent\n| where EventID == 4688\n| where CommandLine has "' + esc + '"';
    // Process name
    if (/newprocessname|processname|filename|filepath/.test(c))
      return 'SecurityEvent\n| where EventID == 4688\n| where NewProcessName has "' + esc + '"';
    // IP Address — logon context
    if (/ipaddress|remoteip/.test(c) || isIP)
      return 'SecurityEvent\n| where IpAddress == "' + esc + '"';
    // Logon type
    if (/logontype/.test(c))
      return 'SecurityEvent\n| where EventID in (4624, 4625)\n| where LogonType == ' + (isNum ? v : '"' + esc + '"');
    // Auth package
    if (/authenticationpackage|authpkg/.test(c))
      return 'SecurityEvent\n| where AuthenticationPackageName =~ "' + esc + '"';
    // Status codes
    if (/status|substatus/.test(c))
      return 'SecurityEvent\n| where EventID == 4625\n| where Status == "' + esc + '" or SubStatus == "' + esc + '"';
    // Group / member
    if (/groupname|membername/.test(c))
      return 'SecurityEvent\n| where EventID in (4728,4729,4732,4733,4756,4757)\n| where TargetUserName =~ "' + esc + '" or MemberName has "' + esc + '"';
    // Service name
    if (/servicename/.test(c))
      return 'SecurityEvent\n| where EventID in (4697,7045)\n| where ServiceName =~ "' + esc + '"';
    // Fallback — broad search
    return 'SecurityEvent\n| where * has "' + esc + '"';
  }

  function buildSentinelKQLMulti(conditions, logic) {
    if (!conditions.length) return '';
    // Group conditions — try to merge into one SecurityEvent query
    var parts = conditions.map(function(c) {
      var q = buildSentinelKQL(c.col, c.val);
      if (!q) return null;
      var lines = q.split('\n');
      return (lines[1] || '').replace(/^\|\s*where\s+/, '').trim();
    }).filter(Boolean);
    if (!parts.length) return '';
    var op = logic === 'OR' ? '\nor ' : '\nand ';
    return 'SecurityEvent\n| where ' + parts.join(op);
  }

  function ctxQueryItems(col, val, suffix) {
    var label = suffix ? '  (' + suffix + ')' : '';
    var items = [];
    var isWinSec = typeof isWindowsSecurityLog !== 'undefined' && isWindowsSecurityLog;

    if (isWinSec) {
      // Windows Security logs → Sentinel SecurityEvent KQL
      var sq = buildSentinelKQL(col, val);
      if (sq) items.push({ type: 'item', icon: '🔷', text: 'Copy Sentinel KQL' + label,
        fn: (function(q) { return function() { navigator.clipboard.writeText(q).catch(function(){}); }; })(sq) });
    } else {
      // Defender / Chronicle
      var cq = buildChronicleQuery(col, val);
      var dq = buildDefenderQuery(col, val);
      if (cq) items.push({ type: 'item', icon: '🔵', text: 'Copy Chronicle query' + label,
        fn: (function(q) { return function() { navigator.clipboard.writeText(q).catch(function(){}); }; })(cq) });
      if (dq) items.push({ type: 'item', icon: '🛡', text: 'Copy Defender KQL' + label,
        fn: (function(q) { return function() { navigator.clipboard.writeText(q).catch(function(){}); }; })(dq) });
    }
    return items;
  }
