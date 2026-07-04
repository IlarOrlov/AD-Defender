# AD-Defender

ADAttackWatch - Unified Active Directory Attack Detection Engine (single module)

Blue-team monitoring tool that polls Windows Security / PowerShell / DNS Server /
System / ADFS event logs (locally or on remote Domain Controllers / endpoints)
and correlates Event IDs to raise alerts for AD attack techniques across:

  Recon:              Account/Group Enumeration, SPN Scanning
  Privilege Esc:      AdminSDHolder, BadSuccessor (dMSA), sAMAccountName Spoofing,
                       AD CS abuse, PetitPotam, Zerologon, GPP cpassword/unattend.xml
                       credentials in SYSVOL, MS14-068, DNSAdmins, Unconstrained/RBCD
                       delegation, GPO abuse, ACL/DACL abuse, Domain Trust abuse,
                       Exchange PrivExchange-style escalation
  Ticket Attacks:     Kekeo, Silver Ticket, Golden Ticket, Kerberoasting, S4U2Proxy
  Lateral Movement:   Pass-the-Hash, NTLM Relay, generic multi-host lateral movement
                       (incl. BloodHound-driven automated tooling)
  Credential Dumping: NTDS.dit extraction, SAM dump, LSASS access, AS-REP Roasting,
                       DPAPI abuse, LAPS password read
  Defense Evasion:    Suspicious/AMSI-bypass PowerShell, Security log cleared,
                       audit policy tampering, Event Log/Sysmon service killed,
                       LOLBin abuse
  Persistence:        DCShadow, Skeleton Key, SID History injection,
                       SeEnableDelegationPrivilege grant, SSP registration,
                       DSRM persistence
  Other:              ADFS suspicious activity (token-signing cert export etc.)

This tool is DETECTION ONLY. It does not perform, simulate, or automate any
attack technique - it reads and correlates event log / file data to surface
signs of these techniques being used against the domain.

Explicitly OUT OF SCOPE (documented, not faked - these need different telemetry
than the Windows Security event log can provide):
  - SQL Server DB-link lateral movement / PowerUpSQL data mining -> SQL Server Audit
  - SCCM / WSUS abuse                                            -> SCCM/WSUS server logs
  - LLMNR/NBT-NS poisoning, mitm6                                -> network IDS/packet capture
  - RID Hijacking                                                -> Sysmon Registry (Event 13) on HKLM\SAM
  - Diamond Ticket                                               -> no reliable log-only signature exists
  - In-memory/EDR evasion, direct syscalls, sRDI                 -> EDR/ETW sensor
  - Honeytoken evasion                                           -> only the honeytoken tool itself sees this
  - Internal Monologue (NTLM without touching LSASS)             -> needs an SSPI-level sensor
  - MailSniper / mailbox data mining                             -> Exchange/M365 audit log, not AD Security log


Requires:
  - Advanced Audit Policy: Account Logon, Logon/Logoff, Account Management,
    DS Access, Detailed Tracking, Object Access, Privilege Use, Policy Change.
  - PowerShell Script Block + Module Logging (GPO) for PowerShell detections.
  - "Include command line in process creation events" GPO for NTDS.dit/SAM/
    DPAPI/LOLBin command-line detections.
  - DNS Server auditing (150/541/770) for the DNSAdmin detection.
  - AD CS auditing enabled on the CA for the AD CS detections.
  - Object Access SACLs on lsass.exe / ms-Mcs-AdmPwd / LSA registry keys for the
    LSASS-access, LAPS-read, and SSP/DSRM persistence detections (these are the
    noisiest to enable - start narrow).
  - Run with "Event Log Readers" rights on target hosts, or a delegated equivalent.

Run modes:
  .\ADAttackWatch.ps1 -Once                                   # single pass, print + exit
  .\ADAttackWatch.ps1                                         # continuous loop (default)
  .\ADAttackWatch.ps1 -ComputerName DC01,DC02                 # remote DCs
  .\ADAttackWatch.ps1 -OutCsv .\alerts.csv                    # persist alerts
  .\ADAttackWatch.ps1 -SysvolPath \\corp.local\SYSVOL\corp.local\Policies
