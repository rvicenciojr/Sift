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

## sample-windows-security.csv

A small Windows Security Event Log export (~53 events) showing a fabricated full-spectrum attack chain that exercises every Windows Security-specific card in Sift:

- **Baseline interactive logons** (4624 LogonType 2) — five users logging in for the day
- **Password spray** (4625) — 17 failed network logons from `198.51.100.42` against different accounts in ~90 seconds, classic spray pattern
- **Account lockout** (4740) — one user gets locked out from the spray
- **Successful auth** (4624 LogonType 3, then RDP LogonType 10) — `jsmith` falls to the spray, attacker pivots to `WS-FINANCE-04` via RDP
- **RDP session** (21) — session connected from the same hostile IP
- **Discovery** (4688) — `whoami /all`, `nltest /domain_trusts`, `net group "Domain Admins"`
- **Kerberos activity** (4768 TGT, 4769 service tickets for SQL-PROD-01, FS-FILES, DC01)
- **Pre-auth failure** (4771 code 0x18) — possible Kerberoasting signal
- **Lateral movement** (4624 LogonType 3 to SQL-PROD-01 and FS-FILES, 4648 explicit credentials)
- **Account creation** (4720, 4722, 4728, 4732, 4738) — new `supportadmin` account created and added to admin groups
- **Service install** (7045, 4697) — persistence via fake service pointing at `C:\Users\Public\svc.exe`
- **Credential dump** (4688) — `rundll32` calling `comsvcs.dll MiniDump` against LSASS PID 716
- **Log clear attempt** (1102) — audit log cleared on DC01
- **Session disconnect** (4634, 4647, 22) — attacker logs off
- **Follow-on logins** (4624) — both `jsmith` and the new `supportadmin` account log back in from the hostile IP

**To try it:**

1. Open `dist/sift-windows.html` (or `sift-chronicle-windows.html` / `sift-defender-windows.html`) in Chrome or Edge
2. Drag `sample-windows-security.csv` onto the page
3. Click **📋 Overview** — you should see:
   - **Logon Analysis** card: success vs failed ratio, LogonType breakdown
   - **Spray / Brute Force** card: `198.51.100.42` flagged hitting 18+ accounts
   - **Account Changes** card: `supportadmin` creation + group additions
   - **Authentication Events** card: Kerberos TGT/TGS activity
   - **Network Logons** card: lateral movement paths between hosts
   - **RDP Sessions** card: the `198.51.100.42` RDP session

**All data is fabricated.** The IP `198.51.100.42` is from RFC 5737 reserved documentation range. Hostnames, usernames, and computer names are placeholder values.

## Adding your own samples

If you want to contribute a sanitised sample for a different log source (Chronicle UDM, Windows Security `.evtx`, etc.), open a PR. Requirements:

- All identifiers (host, user, IP, domain, hash) must be obviously fabricated
- Use reserved IP ranges (RFC 5737, RFC 6598)
- Keep file size under 100 KB — these are for demos, not benchmarks
- Include a brief description in this README
