// evtx-parser.js — Windows Event Log (.evtx) native browser parser
// Based on analysis of python-evtx and the libevtx format specification.
//
// Binary structure per record:
//   Record header: magic(4) + size(4) + record_id(8) + timestamp(8) = 24 bytes
//   BinXML: fragment_header(4) + TemplateInstance(10) + [inline template(24+data_len)] + substitutions
//   Substitutions: count(uint32) + descriptors(count*4: uint16_size+uint8_type+uint8_pad) + values
//
// System section substitution indices (same for ALL standard Windows events):
//   The template BinXML maps fixed indices to System section fields.
//   For standard events the mapping is consistent and well-known.

(function(global) {
  'use strict';

  // ── EventData field names per EventID (indices 17+ in standard System section) ──
  var EVENT_FIELDS = {
    4624: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId',
           'TargetUserSid','TargetUserName','TargetDomainName','TargetLogonId',
           'LogonType','LogonProcessName','AuthenticationPackageName','WorkstationName',
           'LogonGuid','TransmittedServices','LmPackageName','KeyLength',
           'ProcessId','ProcessName','IpAddress','IpPort','ImpersonationLevel',
           'RestrictedAdminMode','TargetOutboundUserName','TargetOutboundDomainName',
           'VirtualAccount','TargetLinkedLogonId','ElevatedToken'],
    4625: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId',
           'TargetUserSid','TargetUserName','TargetDomainName','Status','FailureReason',
           'SubStatus','LogonType','LogonProcessName','AuthenticationPackageName',
           'WorkstationName','TransmittedServices','LmPackageName','KeyLength',
           'ProcessId','ProcessName','IpAddress','IpPort'],
    4634: ['TargetUserSid','TargetUserName','TargetDomainName','TargetLogonId','LogonType'],
    4647: ['TargetUserSid','TargetUserName','TargetDomainName','TargetLogonId'],
    4648: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId',
           'LogonGuid','TargetUserName','TargetDomainName','TargetServerName',
           'TargetInfo','ProcessId','ProcessName','IpAddress','IpPort'],
    4688: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId',
           'NewProcessId','NewProcessName','TokenElevationType','ProcessId',
           'CommandLine','TargetUserSid','TargetUserName','TargetDomainName',
           'TargetLogonId','ParentProcessName','MandatoryLabel'],
    4689: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId',
           'Status','ProcessId','ProcessName'],
    4720: ['TargetUserName','TargetDomainName','TargetSid','SubjectUserSid',
           'SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    4722: ['TargetUserSid','TargetUserName','TargetDomainName',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId'],
    4723: ['TargetUserSid','TargetUserName','TargetDomainName',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId'],
    4724: ['TargetUserSid','TargetUserName','TargetDomainName',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId'],
    4725: ['TargetUserSid','TargetUserName','TargetDomainName',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId'],
    4726: ['TargetUserSid','TargetUserName','TargetDomainName',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    4728: ['MemberSid','MemberName','TargetUserName','TargetDomainName','TargetSid',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    4729: ['MemberSid','MemberName','TargetUserName','TargetDomainName','TargetSid',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    4732: ['MemberSid','MemberName','TargetUserName','TargetDomainName','TargetSid',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    4733: ['MemberSid','MemberName','TargetUserName','TargetDomainName','TargetSid',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    4738: ['DummyParam','TargetUserName','TargetDomainName','TargetSid',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId'],
    4740: ['TargetUserName','TargetDomainName','TargetSid','SubjectUserSid',
           'SubjectUserName','SubjectDomainName','SubjectLogonId','CallerComputerName'],
    4756: ['MemberSid','MemberName','TargetUserName','TargetDomainName','TargetSid',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    4757: ['MemberSid','MemberName','TargetUserName','TargetDomainName','TargetSid',
           'SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    4768: ['TargetUserName','TargetDomainName','TargetSid','ServiceName','ServiceSid',
           'TicketOptions','Status','TicketEncryptionType','PreAuthType','IpAddress','IpPort'],
    4769: ['TargetUserName','TargetDomainName','ServiceName','ServiceSid',
           'TicketOptions','TicketEncryptionType','IpAddress','IpPort','Status'],
    4771: ['TargetUserName','TargetSid','ServiceName','TicketOptions','Status',
           'PreAuthType','IpAddress','IpPort'],
    4776: ['PackageName','TargetUserName','Workstation','Status'],
    4672: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    4697: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId',
           'ServiceName','ServiceFileName','ServiceType','ServiceStartType','ServiceAccount'],
    7045: ['ServiceName','ImagePath','ServiceType','StartType','AccountName'],
    4698: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','TaskName','TaskContent'],
    4699: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','TaskName','TaskContent'],
    4702: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','TaskName','TaskContentNew'],
    1102: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId'],
    4719: ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId',
           'CategoryId','SubcategoryId','SubcategoryGuid','AuditPolicyChanges'],
    4103: ['ContextInfo','Payload'],
    4104: ['MessageNumber','MessageTotal','ScriptBlockText','ScriptBlockId','Path'],
    // Terminal Services
    21: ['User','SessionID','Address'],
    22: ['User','SessionID'],
    23: ['User','SessionID','Address'],
    24: ['User','SessionID','Address'],
    25: ['User','SessionID','Address'],
    39: ['SessionID','User','SessionID2'],
    40: ['SessionID','User','Reason'],
    // RDP Core TS
    131: ['ClientIP','ConnectionId'],
    98:  ['SessionID'],
    65:  ['ConnectionID','Reason'],
  };

  // ── FILETIME to ISO string ───────────────────────────────────────────────────
  var EPOCH_DIFF = 11644473600000n;

  function filetimeToISO(view, off) {
    if (off + 8 > view.byteLength) return '';
    var lo = view.getUint32(off, true), hi = view.getUint32(off+4, true);
    if (lo === 0 && hi === 0) return '';
    try {
      var ms = Number((BigInt(hi) << 32n | BigInt(lo >>> 0)) / 10000n) - Number(EPOCH_DIFF);
      if (ms < 0 || ms > 99999999999999) return '';
      return new Date(ms).toISOString().replace('T',' ').replace('Z','');
    } catch(e) { return ''; }
  }

  // ── Read UTF-16LE string ─────────────────────────────────────────────────────
  function readWStr(bytes, off, byteLen) {
    var s = '', n = Math.floor(byteLen / 2);
    for (var i = 0; i < n; i++) {
      var idx = off + i*2;
      if (idx+1 >= bytes.length) break;
      var c = bytes[idx] | (bytes[idx+1] << 8);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  // ── SID to string ────────────────────────────────────────────────────────────
  function sidStr(bytes, off, len) {
    if (len < 8 || off+len > bytes.length) return '';
    try {
      var rev = bytes[off], cnt = bytes[off+1], auth = 0;
      for (var i=2; i<8; i++) auth = auth*256 + bytes[off+i];
      var s = 'S-'+rev+'-'+auth;
      var dv = new DataView(bytes.buffer, bytes.byteOffset+off+8);
      for (var j=0; j<cnt && j<(len-8)/4; j++) s += '-'+dv.getUint32(j*4, true);
      return s;
    } catch(e) { return ''; }
  }

  // ── Read a substitution value by type ────────────────────────────────────────
  function readVal(bytes, view, off, type, size) {
    if (size === 0 || off+size > bytes.length) return null;
    try {
      switch (type) {
        case 0x00: return null;
        case 0x01: return readWStr(bytes, off, size);        // UTF-16LE string
        case 0x02: {                                          // ANSI string
          var s='';
          for (var i=0;i<size-1&&off+i<bytes.length;i++){
            if(bytes[off+i]===0)break; s+=String.fromCharCode(bytes[off+i]);
          } return s;
        }
        case 0x03: return view.getInt8(off);
        case 0x04: return view.getUint8(off);
        case 0x05: return view.getInt16(off,true);
        case 0x06: return view.getUint16(off,true);
        case 0x07: return view.getInt32(off,true);
        case 0x08: return view.getUint32(off,true);
        case 0x09: case 0x0A: {
          var lo=view.getUint32(off,true),hi=view.getUint32(off+4,true);
          return Number((BigInt(hi)<<32n)|BigInt(lo>>>0));
        }
        case 0x0D: return view.getUint8(off) !== 0;
        case 0x0F: {  // GUID
          if (size < 16) return null;
          var d1=view.getUint32(off,true).toString(16).padStart(8,'0');
          var d2=view.getUint16(off+4,true).toString(16).padStart(4,'0');
          var d3=view.getUint16(off+6,true).toString(16).padStart(4,'0');
          var d4=Array.from(bytes.slice(off+8,off+10)).map(b=>b.toString(16).padStart(2,'0')).join('');
          var d5=Array.from(bytes.slice(off+10,off+16)).map(b=>b.toString(16).padStart(2,'0')).join('');
          return '{'+d1+'-'+d2+'-'+d3+'-'+d4+'-'+d5+'}';
        }
        case 0x11: return filetimeToISO(view, off);           // FileTime
        case 0x12: {  // SYSTEMTIME
          if (size<16) return null;
          var yr=view.getUint16(off,true),mo=view.getUint16(off+2,true);
          var dy=view.getUint16(off+6,true),hr=view.getUint16(off+8,true);
          var mn=view.getUint16(off+10,true),sc=view.getUint16(off+12,true);
          return yr+'-'+String(mo).padStart(2,'0')+'-'+String(dy).padStart(2,'0')+
                 ' '+String(hr).padStart(2,'0')+':'+String(mn).padStart(2,'0')+':'+String(sc).padStart(2,'0');
        }
        case 0x13: return sidStr(bytes, off, size);           // SID
        case 0x14: return '0x'+view.getUint32(off,true).toString(16).toUpperCase();
        case 0x15: {
          var lo2=view.getUint32(off,true),hi2=view.getUint32(off+4,true);
          return '0x'+((BigInt(hi2)<<32n)|BigInt(lo2>>>0)).toString(16).toUpperCase();
        }
        case 0x21: return null;  // nested BinXml — skip
        default: return null;
      }
    } catch(e) { return null; }
  }

  // ── Parse BinXML substitutions from a record ─────────────────────────────────
  // Structure:
  //   [0:4]   Fragment header (0x0F 0x01 0x01 0x00)
  //   [4]     TemplateInstance token (0x0C or 0x4C)
  //   [5]     Unknown byte
  //   [6:10]  template_id (uint32, ignore)
  //   [10:14] template_offset (uint32, chunk-relative)
  //   [14:]   If resident template:
  //             next_offset(4) + GUID(starts at+4, 16 bytes) + data_length(at+20, 4 bytes)
  //             = 24-byte template header, then data_length bytes of template BinXML
  //   [14 + template_size:]
  //             sub_count (uint32)
  //             descriptors: sub_count * 4 bytes (uint16 size + uint8 type + uint8 pad)
  //             values: concatenated per descriptor sizes
  function parseBinXML(bytes, view, binxmlOff, maxOff) {
    var pos = binxmlOff;

    // Fragment header
    if (pos + 4 > maxOff || bytes[pos] !== 0x0F) return null;
    pos += 4;

    // TemplateInstance token
    if (pos >= maxOff) return null;
    var tok = bytes[pos];
    if (tok !== 0x0C && tok !== 0x4C) return null;
    pos += 1 + 1 + 4 + 4;  // token + unknown + template_id + template_offset
    // pos is now 14 bytes from binxmlOff

    // Detect inline (resident) template:
    // At pos+20 should be the template data_length (uint32).
    // If pos+24 < maxOff AND bytes[pos+24] == 0x0F (nested fragment header),
    // this is a resident template — data is inline.
    var dataLength = 0;
    if (pos + 24 < maxOff) {
      var candLen = view.getUint32(pos + 20, true);
      if (candLen > 0 && candLen < 0x8000 && pos + 24 + candLen <= maxOff) {
        // Verify: template BinXML should start with 0x0F
        if (bytes[pos + 24] === 0x0F) {
          dataLength = candLen;
          pos += 24 + dataLength;  // skip template header (24) + template BinXML
        }
      }
    }

    // Substitution count (uint32)
    if (pos + 4 > maxOff) return null;
    var numSubs = view.getUint32(pos, true);
    pos += 4;
    if (numSubs === 0 || numSubs > 512 || pos + numSubs * 4 > maxOff) return null;

    // Descriptors: numSubs * 4 bytes (uint16 size + uint8 type + uint8 pad)
    var descs = [];
    for (var i = 0; i < numSubs; i++) {
      descs.push({ sz: view.getUint16(pos, true), type: bytes[pos + 2] });
      pos += 4;
    }

    // Values
    var vals = [];
    for (var j = 0; j < descs.length; j++) {
      var d = descs[j];
      if (pos + d.sz > maxOff) { vals.push(null); pos += d.sz; continue; }
      vals.push(readVal(bytes, view, pos, d.type, d.sz));
      pos += d.sz;
    }

    return vals;
  }

  // ── Find EventID in the values array ─────────────────────────────────────────
  // For standard Windows events, the System section template maps specific
  // indices to fields. EventID is a UInt16. We scan the first ~6 values for it.
  function extractEventId(vals, descs) {
    // Standard mapping: EventID is typically at index 2 or 3 (UInt16, type 0x06)
    // Priority order: check expected positions first
    var candidates = [2, 3, 1, 4, 0];
    for (var ci = 0; ci < candidates.length; ci++) {
      var idx = candidates[ci];
      if (idx < descs.length && descs[idx].type === 0x06 && vals[idx] !== null) {
        return String(vals[idx]);
      }
    }
    // Fallback: first UInt16
    for (var i = 0; i < Math.min(descs.length, 8); i++) {
      if (descs[i].type === 0x06 && vals[i] !== null) return String(vals[i]);
    }
    return '';
  }

  // ── Map parsed values to HuntDefender row columns ─────────────────────────────
  // Standard System section mapping (same for all Windows events):
  // The template maps these substitution indices:
  //   Version(UInt8), Level(UInt8), EventID(UInt16), Task(UInt16), [null/optional],
  //   Keywords(HexInt64), TimeCreated(FileTime), ActivityID(GUID), ProcessID(UInt32),
  //   ThreadID(UInt32), EventRecordID(UInt64), [Level again?], UserID(SID),
  //   [RelatedActivityID(null)], Channel(String), ProviderGuid(GUID), Computer(String),
  //   [EventData fields 17+]
  // Note: exact ordering is determined by the template BinXML. For standard events
  // the System section uses a well-known template with consistent index assignments.
  function valsToRow(vals, descs, fallbackTs) {
    if (!vals || vals.length < 3) return null;

    // Build descriptor-indexed lookup
    var row = {};

    // Find EventID (UInt16, type 0x06) — usually at index 2 or 3
    var eventId = extractEventId(vals, descs);
    if (!eventId) return null;
    row.EventID = eventId;
    var evtIdNum = parseInt(eventId, 10);

    // Find TimeCreated (FileTime, type 0x11)
    var ts = fallbackTs || '';
    for (var i = 0; i < Math.min(descs.length, 12); i++) {
      if (descs[i].type === 0x11 && vals[i]) { ts = String(vals[i]); break; }
    }
    row.TimeCreated = ts;

    // Find Computer (String, type 0x01) — longest string in first ~18 values
    // and Channel (another string)
    var strings = [];
    for (var i = 0; i < Math.min(descs.length, 18); i++) {
      if (descs[i].type === 0x01 && vals[i] && String(vals[i]).length > 1) {
        strings.push({ idx: i, val: String(vals[i]) });
      }
    }
    // Computer is usually the longest hostname-like string; Channel contains '/'
    strings.sort(function(a,b){ return b.val.length - a.val.length; });
    var computerFound = false, channelFound = false;
    for (var si = 0; si < strings.length; si++) {
      var sv = strings[si].val;
      if (!channelFound && sv.indexOf('/') >= 0) {
        row.Channel = sv; channelFound = true;
      } else if (!computerFound) {
        row.Computer = sv; computerFound = true;
      }
    }
    row.Channel = row.Channel || '';
    row.Computer = row.Computer || '';

    // Find EventRecordID (UInt64, type 0x0A)
    for (var i = 0; i < Math.min(descs.length, 15); i++) {
      if (descs[i].type === 0x0A && vals[i] !== null) { row.EventRecordID = String(vals[i]); break; }
    }
    row.EventRecordID = row.EventRecordID || '';

    // Find UserID (SID, type 0x13)
    var userSID = '';
    for (var i = 0; i < Math.min(descs.length, 18); i++) {
      if (descs[i].type === 0x13 && vals[i]) { userSID = String(vals[i]); break; }
    }

    // Find ProcessID and ThreadID (UInt32, type 0x08) — usually consecutive
    var uint32s = [];
    for (var i = 0; i < Math.min(descs.length, 15); i++) {
      if (descs[i].type === 0x08 && vals[i] !== null) uint32s.push(vals[i]);
    }
    row._processId = uint32s.length > 0 ? String(uint32s[0]) : '';
    row._threadId  = uint32s.length > 1 ? String(uint32s[1]) : '';

    // EventData fields (indices 17+, or wherever the BinXml value appears)
    // Find the nested BinXml substitution (type 0x21) — this is the EventData section
    // For non-nested events, EventData fields are plain string/int values after index 16
    var fieldNames = EVENT_FIELDS[evtIdNum] || [];
    var dataFieldIdx = 0;
    for (var i = 0; i < descs.length; i++) {
      if (descs[i].type === 0x21) continue; // skip nested BinXml
      if (i < 17) continue; // skip System section
      if (vals[i] === null || vals[i] === undefined) { dataFieldIdx++; continue; }
      var name = fieldNames[dataFieldIdx] || ('Data' + dataFieldIdx);
      row[name] = String(vals[i]);
      dataFieldIdx++;
    }

    // Normalize to HuntDefender standard columns
    row.SubjectUserName   = row.SubjectUserName   || '';
    row.SubjectDomainName = row.SubjectDomainName || '';
    row.SubjectLogonId    = row.SubjectLogonId    || '';
    row.SubjectUserSid    = row.SubjectUserSid    || userSID || '';
    row.TargetUserName    = row.TargetUserName    || '';
    row.TargetDomainName  = row.TargetDomainName  || '';
    row.TargetLogonId     = row.TargetLogonId     || '';
    row.LogonType         = row.LogonType         ? String(row.LogonType)         : '';
    row.IpAddress         = row.IpAddress         || row.Address                  || row.ClientIP || '';
    row.IpPort            = row.IpPort            ? String(row.IpPort)            : '';
    row.Status            = row.Status            || '';
    row.SubStatus         = row.SubStatus         || '';
    row.FailureReason     = row.FailureReason     || '';
    row.AuthenticationPackageName = row.AuthenticationPackageName || '';
    row.LogonProcessName  = row.LogonProcessName  || '';
    row.WorkstationName   = row.WorkstationName   || '';
    row.KeyLength         = row.KeyLength         ? String(row.KeyLength)         : '';
    row.NewProcessName    = row.NewProcessName    || '';
    row.ParentProcessName = row.ParentProcessName || '';
    row.CommandLine       = row.CommandLine       || '';
    row.NewProcessId      = row.NewProcessId      ? String(row.NewProcessId)      : '';
    row.ProcessId         = row.ProcessId         ? String(row.ProcessId)         : '';
    row.GroupName         = row.GroupName         || '';
    row.GroupDomain       = row.GroupDomain       || row.TargetDomainName         || '';
    row.MemberName        = row.MemberName        || '';
    row.MemberSid         = row.MemberSid         || '';
    row.ServiceName       = row.ServiceName       || '';
    row.ServiceFileName   = row.ServiceFileName   || row.ImagePath                || '';
    row.ServiceType       = row.ServiceType       ? String(row.ServiceType)       : '';
    row.ServiceStartType  = row.ServiceStartType  ? String(row.ServiceStartType)  : '';
    row.SessionID         = row.SessionID         ? String(row.SessionID)         : '';

    // PS script block: use script text as CommandLine
    if (row.ScriptBlockText && !row.CommandLine) row.CommandLine = row.ScriptBlockText;
    if (row.Payload && !row.CommandLine) row.CommandLine = row.Payload;

    // Full-text search string
    row._rt = Object.values(row).filter(function(v){
      return v && typeof v==='string' && v.length>1 && !v.startsWith('{');
    }).join(' ').toLowerCase();

    return row;
  }

  // ── Main parse function ───────────────────────────────────────────────────────
  function parseFile(arrayBuffer) {
    var bytes = new Uint8Array(arrayBuffer);
    var view  = new DataView(arrayBuffer);

    // Verify file magic "ElfFile\x00"
    if (bytes.length < 8 || String.fromCharCode(bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6]) !== 'ElfFile') {
      throw new Error('Not a valid .evtx file');
    }

    var events = [];

    // Scan chunks — each 65536 bytes, first chunk at file offset 0x1000
    for (var chunkOff = 0x1000; chunkOff < bytes.length - 128; chunkOff += 0x10000) {
      // Verify chunk magic "ElfChnk\x00"
      var cm = String.fromCharCode(bytes[chunkOff],bytes[chunkOff+1],bytes[chunkOff+2],bytes[chunkOff+3],
                                   bytes[chunkOff+4],bytes[chunkOff+5],bytes[chunkOff+6]);
      if (cm !== 'ElfChnk') break;

      var chunkEnd = Math.min(chunkOff + 0x10000, bytes.length);

      // Scan for event records — start at offset 128 (just after chunk header)
      var off = chunkOff + 128;
      while (off < chunkEnd - 8) {
        // Record magic: 0x2a 0x2a 0x00 0x00
        if (bytes[off]===0x2a && bytes[off+1]===0x2a && bytes[off+2]===0x00 && bytes[off+3]===0x00) {
          var recSize = view.getUint32(off + 4, true);
          if (recSize < 28 || recSize > 0x10000 || off + recSize > chunkEnd) { off++; continue; }

          // Timestamp at record+16 (FILETIME)
          var fallbackTs = filetimeToISO(view, off + 16);

          // BinXML starts at record+0x18 (24 bytes), ends at record+recSize-4
          var binxmlOff = off + 0x18;
          var binxmlEnd = off + recSize - 4;

          try {
            var result = parseBinXMLWithDescs(bytes, view, binxmlOff, binxmlEnd);
            if (result) {
              var row = valsToRow(result.vals, result.descs, fallbackTs);
              if (row) events.push(row);
            }
          } catch(e) { /* skip malformed */ }

          off += recSize;
        } else {
          off++;
        }
      }
    }

    return events;
  }

  // Wrapper that returns both vals and descs (needed for column type info)
  function parseBinXMLWithDescs(bytes, view, binxmlOff, maxOff) {
    var pos = binxmlOff;
    if (pos + 4 > maxOff || bytes[pos] !== 0x0F) return null;
    pos += 4;
    if (pos >= maxOff) return null;
    var tok = bytes[pos];
    if (tok !== 0x0C && tok !== 0x4C) return null;
    pos += 1 + 1 + 4 + 4;  // token + unknown + template_id + template_offset

    // Detect and skip inline template
    if (pos + 24 < maxOff) {
      var candLen = view.getUint32(pos + 20, true);
      if (candLen > 0 && candLen < 0x8000 && pos + 24 + candLen <= maxOff && bytes[pos+24] === 0x0F) {
        pos += 24 + candLen;
      }
    }

    if (pos + 4 > maxOff) return null;
    var numSubs = view.getUint32(pos, true); pos += 4;
    if (numSubs === 0 || numSubs > 512 || pos + numSubs * 4 > maxOff) return null;

    var descs = [];
    for (var i = 0; i < numSubs; i++) {
      descs.push({ sz: view.getUint16(pos, true), type: bytes[pos+2] });
      pos += 4;
    }
    var vals = [];
    for (var j = 0; j < descs.length; j++) {
      var d = descs[j];
      if (pos + d.sz > maxOff) { vals.push(null); pos += d.sz; continue; }
      vals.push(readVal(bytes, view, pos, d.type, d.sz));
      pos += d.sz;
    }
    return { vals: vals, descs: descs };
  }

  // ── Get column headers from parsed events ─────────────────────────────────────
  function getHeaders(events) {
    if (!events.length) return [];
    var standard = ['TimeCreated','EventID','Channel','Computer',
      'SubjectUserName','SubjectDomainName','SubjectUserSid','SubjectLogonId',
      'TargetUserName','TargetDomainName','TargetLogonId',
      'LogonType','LogonProcessName','AuthenticationPackageName','WorkstationName',
      'IpAddress','IpPort','Status','SubStatus','FailureReason','KeyLength',
      'NewProcessName','ParentProcessName','CommandLine','NewProcessId','ProcessId',
      'GroupName','GroupDomain','MemberName','MemberSid',
      'ServiceName','ServiceFileName','ServiceType','ServiceStartType',
      'SessionID','EventRecordID'];
    var extra = [], seen = new Set(standard);
    seen.add('_rt'); seen.add('_processId'); seen.add('_threadId');
    events.forEach(function(ev){
      Object.keys(ev).forEach(function(k){
        if (!k.startsWith('_') && !seen.has(k)){ seen.add(k); extra.push(k); }
      });
    });
    return standard.concat(extra).filter(function(c){
      return events.some(function(e){ return e[c] && e[c] !== ''; });
    });
  }

  global.EVTXParser = { parseFile: parseFile, getHeaders: getHeaders };

})(window);
