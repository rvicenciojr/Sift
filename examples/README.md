# Examples

Sample data files for trying Sift before loading real data.

## sample-defender.csv

A small Microsoft Defender for Endpoint Advanced Hunting export (~25 rows) showing a fabricated attacker scenario:

- User opens a malicious Word document (`Invoice_Q2.docm`) on `WS-FINANCE-04`
- Word spawns an encoded PowerShell process
- PowerShell beacons to a staging server (`198.51.100.42:443`)
- Discovery commands run (`whoami`, `nltest /domain_trusts`, `net group "Domain Admins"`)
- LSASS dump via `comsvcs.dll` MiniDump
- Persistence via `schtasks` creating a SYSTEM-level scheduled task
- Second-stage payload pulled via `certutil` (LOLBin transfer)
- Same encoded PowerShell pattern appears on a second host (`WS-LEGAL-12`) — suggesting lateral movement or shared phishing

**To try it:**

1. Open `dist/hunt-investigator.html` in Chrome or Edge
2. Drag `sample-defender.csv` onto the page
3. Click **📋 Overview** — you should see MITRE coverage light up for Execution, Credential Access, Discovery, Command and Control, and Persistence
4. Open the **🌲 Process Tree** to see the WINWORD → powershell → tool chain
5. Open the **🗺 Network Map** to see the C2 connection
6. Pick **T1059.001 PowerShell** from the Investigating dropdown to see the TTP Context Card in action

**All data in this file is fabricated.** Hostnames, usernames, IPs, hashes, and URLs are placeholder values. The IPs `198.51.100.42` and `203.0.113.55` are from RFC 5737 reserved documentation ranges. The hashes are not real file hashes.

## Adding your own samples

If you want to contribute a sanitised sample for a different log source (Chronicle UDM, Windows Security `.evtx`, etc.), open a PR. Requirements:

- All identifiers (host, user, IP, domain, hash) must be obviously fabricated
- Use reserved IP ranges (RFC 5737, RFC 6598)
- Keep file size under 100 KB — these are for demos, not benchmarks
- Include a brief description in this README
