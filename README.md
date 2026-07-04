# AD-Defender

**ADAttackWatch** — a single-file PowerShell detection engine for Active Directory attack techniques. It polls Windows Security, PowerShell, DNS Server, System, and ADFS event logs — locally or on remote Domain Controllers/endpoints — and correlates Event IDs into alerts.

> **Detection only.** This tool does not perform, simulate, or automate any attack technique. It reads and correlates event log and file data to surface signs that these techniques are being used against your domain.

## Coverage

| Category | Techniques |
|---|---|
| **Recon** | Account/Group Enumeration, SPN Scanning |
| **Privilege Escalation** | AdminSDHolder abuse, BadSuccessor (dMSA), sAMAccountName spoofing, AD CS abuse, PetitPotam, Zerologon, GPP cpassword / unattend.xml credentials in SYSVOL, MS14-068, DNSAdmins, unconstrained/RBCD delegation, GPO abuse, ACL/DACL abuse, domain trust abuse, Exchange PrivExchange-style escalation |
| **Ticket Attacks** | Kekeo, Silver Ticket, Golden Ticket, Kerberoasting, S4U2Proxy |
| **Lateral Movement** | Pass-the-Hash, NTLM relay, generic multi-host lateral movement (incl. BloodHound-driven tooling) |
| **Credential Dumping** | NTDS.dit extraction, SAM dump, LSASS access, AS-REP Roasting, DPAPI abuse, LAPS password read |
| **Defense Evasion** | Suspicious/AMSI-bypass PowerShell, security log cleared, audit policy tampering, Event Log/Sysmon service killed, LOLBin abuse |
| **Persistence** | DCShadow, Skeleton Key, SID History injection, SeEnableDelegationPrivilege grant, SSP registration, DSRM persistence |
| **Other** | ADFS suspicious activity (e.g. token-signing cert export) |

### Explicitly out of scope

Some techniques need telemetry the Windows Security event log can't provide. These are documented, not faked:

| Technique | Requires |
|---|---|
| SQL Server DB-link movement / PowerUpSQL data mining | SQL Server Audit |
| SCCM / WSUS abuse | SCCM/WSUS server logs |
| LLMNR/NBT-NS poisoning, mitm6 | Network IDS / packet capture |
| RID hijacking | Sysmon Registry auditing (Event 13) on `HKLM\SAM` |
| Diamond Ticket | No reliable log-only signature exists |
| In-memory/EDR evasion, direct syscalls, sRDI | EDR/ETW sensor |
| Honeytoken evasion | Only the honeytoken tool itself can see this |
| Internal Monologue (NTLM without touching LSASS) | SSPI-level sensor |
| MailSniper / mailbox data mining | Exchange/M365 audit log |

## Requirements

- **Advanced Audit Policy** enabled for: Account Logon, Logon/Logoff, Account Management, DS Access, Detailed Tracking, Object Access, Privilege Use, Policy Change.
- **PowerShell Script Block + Module Logging** (via GPO) for the PowerShell detections.
- **"Include command line in process creation events"** GPO for the NTDS.dit / SAM / DPAPI / LOLBin command-line detections.
- **DNS Server auditing** (Event IDs 150/541/770) for the DNSAdmin detection.
- **AD CS auditing** enabled on the CA for the AD CS detections.
- **Object Access SACLs** on `lsass.exe`, `ms-Mcs-AdmPwd`, and the LSA registry keys for LSASS-access, LAPS-read, and SSP/DSRM persistence detections — these are the noisiest to enable, so start narrow.
- The account running the script needs **Event Log Readers** rights (or a delegated equivalent) on every target host.

## Usage

```powershell
# Single pass, print results, exit
.\ADAttackWatch.ps1 -Once

# Continuous monitoring (default loop)
.\ADAttackWatch.ps1

# Target remote Domain Controllers
.\ADAttackWatch.ps1 -ComputerName DC01,DC02

# Persist alerts to CSV
.\ADAttackWatch.ps1 -OutCsv .\alerts.csv

# Include a SYSVOL scan for GPP cpassword / unattend.xml credential exposure
.\ADAttackWatch.ps1 -SysvolPath \\corp.local\SYSVOL\corp.local\Policies
```

# Guide to Running ADAttackWatch

This guide walks you through validating connectivity, permissions, audit configuration, and running **ADAttackWatch** for the first time.

---

## 1. Prerequisites

Before running the script, verify that your administration workstation can communicate with the Domain Controller.

### Verify WinRM connectivity

```powershell
Test-WSMan DC01.corp.local
```

### Verify remote Security Log access

This is the actual permissions test.

```powershell
Get-WinEvent -ComputerName DC01.corp.local -LogName Security -MaxEvents 1
```

### If the command fails

**Access Denied**

Your account must belong to one of the following:

- **Event Log Readers** (local group on the Domain Controller)
- **Domain Admins**
- Another delegated group with permission to read the Security log

**Connection Failure**

Verify that:

- WinRM is enabled (`Enable-PSRemoting`)
- Windows Firewall allows TCP **5985** (HTTP) or **5986** (HTTPS)
- You are running the command from a **domain-joined computer**
- You are logged in using a **domain account**
- Kerberos authentication is being used instead of NTLM

---

## 2. Verify the Audit Policy

Ensure Windows is actually auditing the events required by ADAttackWatch.

Run:

```powershell
Invoke-Command -ComputerName DC01.corp.local -ScriptBlock {
    auditpol /get /category:*
}
```

Verify that the following categories have **Success** and/or **Failure** auditing enabled (not **No Auditing**):

- Account Logon
- Logon/Logoff
- Account Management
- DS Access
- Detailed Tracking
- Object Access
- Privilege Use
- Policy Change

> **Note**
>
> A clean run with no auditing enabled appears identical to a system where nothing is happening. Always verify the audit policy first.

---

## 3. First Run (Single Pass)

Run a single collection cycle with verbose logging:

```powershell
.\ADAttackWatch.ps1 `
    -ComputerName DC01.corp.local `
    -Once `
    -Verbose
```

During startup, the script displays the number of loaded detections, for example:

```
Loaded 45 per-host detections...
```

If the script immediately fails on `Get-WinEvent`, the issue is almost certainly related to permissions or connectivity—not the script itself.

---

## 4. Run with Output Files

Once the initial validation succeeds, enable CSV and JSONL output.

```powershell
.\ADAttackWatch.ps1 `
    -ComputerName DC01.corp.local `
    -PowerShellHosts DC01.corp.local `
    -DnsServerHosts DC01.corp.local `
    -Once `
    -Verbose `
    -OutCsv .\alerts.csv `
    -OutJsonLines .\alerts.jsonl
```

This generates:

- **alerts.csv** — spreadsheet-friendly output
- **alerts.jsonl** — JSON Lines format for SIEMs and log ingestion

---

## 5. Generate a Test Detection

To verify the complete detection pipeline, generate a harmless event by repeatedly enumerating the local Administrators group:

```powershell
1..20 | ForEach-Object {
    Get-LocalGroupMember Administrators -ErrorAction SilentlyContinue | Out-Null
}
```

Re-run the previous command **within the configured** `-EnumerationWindowMinutes` **window** (default: **5 minutes**).

You should receive an **Account/Group Enumeration** alert.

This confirms that the entire pipeline is functioning correctly:

```
Audit Policy
      ↓
Windows Security Event Log
      ↓
Remote Event Collection
      ↓
Correlation Engine
      ↓
Alert Generation
```

---

## 6. Continuous Monitoring

Once validation is complete, switch to continuous monitoring.

```powershell
.\ADAttackWatch.ps1 `
    -ComputerName DC01.corp.local `
    -PollSeconds 60 `
    -OutCsv .\alerts.csv
```

The script performs a collection pass every **60 seconds** (or the value specified by `-PollSeconds`) and continues running until stopped.

### Production Deployment

The script is **not daemonized** and should be hosted by one of the following:

- Windows Scheduled Task ("Run whether user is logged on or not")
- Persistent PowerShell session
- NSSM (Non-Sucking Service Manager)
- Any Windows service wrapper

These options allow monitoring to continue after logoff or system reboot.

---

## Validation Checklist

Before relying on ADAttackWatch in production, verify:

- ✅ WinRM connectivity works
- ✅ Security log can be read remotely
- ✅ Audit Policy is correctly configured
- ✅ Initial run completes successfully
- ✅ Alerts are written to CSV/JSONL
- ✅ A test event generates an alert
- ✅ Continuous monitoring is running
