[CmdletBinding()]
param(
    # Domain Controllers / endpoints to pull Security & System logs from.
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    # Additional hosts to pull the "Microsoft-Windows-PowerShell/Operational" log from.
    [string[]]$PowerShellHosts = $ComputerName,

    # Additional hosts to pull the DNS Server event log from (Event IDs 150/541/770).
    [string[]]$DnsServerHosts = @(),

    # Additional hosts to pull the ADFS admin log from (if any ADFS servers exist).
    [string[]]$AdfsHosts = @(),

    # How far back to look on the very first pass.
    [int]$InitialLookbackMinutes = 15,

    # Poll interval for continuous mode.
    [int]$PollSeconds = 30,

    # Run exactly one collection/analysis pass then exit.
    [switch]$Once,

    # Optional CSV to append all raised alerts to.
    [string]$OutCsv,

    # Optional path to also write alerts as JSON lines (for SIEM ingestion).
    [string]$OutJsonLines,

    # Optional path to a SYSVOL Policies share to scan for GPP cpassword / unattend.xml
    # credential remnants. This is a point-in-time file scan, not an event correlation.
    [string]$SysvolPath,

    # ---- Thresholds (tunable without touching detection logic) ----
    [int]$EnumerationEventThreshold   = 15,   # 4798/4799 from one source in window
    [int]$EnumerationWindowMinutes    = 5,
    [int]$SpnScanDistinctThreshold    = 8,    # distinct SPNs requested by one account, any etype
    [int]$SpnScanWindowMinutes        = 10,
    [int]$KerberoastTgsThreshold      = 5,    # RC4 4769s for distinct SPNs, one requester
    [int]$KerberoastWindowMinutes     = 10,
    [int]$SprayDistinctAccountThresh  = 8,    # distinct accounts failing from one source
    [int]$SprayWindowMinutes          = 10,
    [int]$LateralHopThreshold         = 3,    # distinct destination hosts for one account
    [int]$LateralWindowMinutes        = 15,
    [int]$NtlmRelayDistinctThreshold  = 5,    # distinct target accounts via NTLM from one source IP
    [int]$NtlmRelayWindowMinutes      = 5,
    [int]$PthHopThreshold             = 3,    # distinct hosts via NTLM logon + immediate admin token
    [int]$PthWindowMinutes            = 10
)

$ErrorActionPreference = 'Stop'
$script:AlertBuffer = New-Object System.Collections.Generic.List[object]

#region ---------------------------------------------------------------- Helpers

function New-Alert {
    param(
        [Parameter(Mandatory)][string]$Attack,
        [Parameter(Mandatory)][string]$Severity,   # Low / Medium / High / Critical
        [Parameter(Mandatory)][string]$Message,
        [string]$Computer,
        [string]$Account,
        [string]$SourceIp,
        [int[]]$EventIds,
        [datetime]$TimeCreated = (Get-Date)
    )
    $alert = [pscustomobject]@{
        TimeRaised  = Get-Date
        TimeCreated = $TimeCreated
        Attack      = $Attack
        Severity    = $Severity
        Computer    = $Computer
        Account     = $Account
        SourceIp    = $SourceIp
        EventIds    = ($EventIds -join ',')
        Message     = $Message
    }
    $script:AlertBuffer.Add($alert) | Out-Null

    $color = switch ($Severity) {
        'Critical' { 'Red' }
        'High'     { 'Red' }
        'Medium'   { 'Yellow' }
        default    { 'Gray' }
    }
    Write-Host ("[{0}] {1,-8} {2,-34} {3}" -f $alert.TimeRaised.ToString('HH:mm:ss'), $Severity, $Attack, $Message) -ForegroundColor $color

    if ($OutCsv) {
        $alert | Export-Csv -Path $OutCsv -Append -NoTypeInformation -Force
    }
    if ($OutJsonLines) {
        ($alert | ConvertTo-Json -Compress) | Add-Content -Path $OutJsonLines
    }
}

# Wraps Get-WinEvent with a FilterHashtable, tolerating hosts/logs that don't exist
# or that have no matching events (Get-WinEvent throws on "no events found").
function Get-SafeWinEvent {
    param(
        [string]$ComputerName,
        [string]$LogName,
        [int[]]$Id,
        [datetime]$StartTime
    )
    $ht = @{ LogName = $LogName; StartTime = $StartTime }
    if ($Id) { $ht['Id'] = $Id }
    $params = @{ FilterHashtable = $ht; ErrorAction = 'SilentlyContinue' }
    if ($ComputerName -and $ComputerName -ne $env:COMPUTERNAME) {
        $params['ComputerName'] = $ComputerName
    }
    try {
        Get-WinEvent @params
    } catch {
        @()
    }
}

# Pulls the value of a named data field out of an event's XML.
function Get-EventField {
    param($Event, [string]$Name)
    try {
        $xml = [xml]$Event.ToXml()
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name }
        if ($node) { return $node.'#text' }
    } catch { }
    return $null
}

#endregion -------------------------------------------------------------------

#region ---------------------------------------------------------- Detections: Core
#region ---------------------------------------------------------- Detections

# Account and Group Enumeration -> 4798 / 4799
function Test-AccountGroupEnumeration {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4798,4799 -StartTime $Since
    if (-not $events) { return }

    $events |
        Group-Object { Get-EventField $_ 'SubjectUserName' } |
        Where-Object { $_.Count -ge $EnumerationEventThreshold } |
        ForEach-Object {
            $recent = $_.Group | Where-Object { $_.TimeCreated -ge (Get-Date).AddMinutes(-$EnumerationWindowMinutes) }
            if ($recent.Count -ge $EnumerationEventThreshold) {
                New-Alert -Attack 'Account/Group Enumeration' -Severity 'Medium' -Computer $Computer `
                    -Account $_.Name -EventIds 4798,4799 -TimeCreated ($recent | Select-Object -Last 1).TimeCreated `
                    -Message "Account '$($_.Name)' generated $($recent.Count) local/group membership enumeration events (4798/4799) in $EnumerationWindowMinutes min - possible recon (BloodHound/PowerView-style)."
            }
        }
}

# AdminSDHolder abuse -> 4780
function Test-AdminSDHolderAbuse {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4780 -StartTime $Since
    foreach ($e in $events) {
        $target = Get-EventField $e 'TargetUserName'
        $subject = Get-EventField $e 'SubjectUserName'
        New-Alert -Attack 'AdminSDHolder ACL Change' -Severity 'High' -Computer $Computer `
            -Account $subject -EventIds 4780 -TimeCreated $e.TimeCreated `
            -Message "ACL set on privileged-group member '$target' by '$subject' (4780). Verify this matches a known admin/delegation change - AdminSDHolder is a common persistence vector."
    }
}

# Kekeo-style ticket abuse (admin token granted alongside a TGS request but no matching interactive logon)
function Test-KekeoPattern {
    param([string]$Computer, [datetime]$Since)
    $tgs   = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4768 -StartTime $Since
    $admin = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4672 -StartTime $Since
    $logon = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4624 -StartTime $Since

    foreach ($a in $admin) {
        $acct = Get-EventField $a 'SubjectUserName'
        if (-not $acct) { continue }
        $matchingLogon = $logon | Where-Object {
            (Get-EventField $_ 'TargetUserName') -eq $acct -and
            [math]::Abs(($_.TimeCreated - $a.TimeCreated).TotalSeconds) -lt 5
        }
        $matchingTgs = $tgs | Where-Object {
            (Get-EventField $_ 'TargetUserName') -eq $acct -and
            [math]::Abs(($_.TimeCreated - $a.TimeCreated).TotalMinutes) -lt 10
        }
        if (-not $matchingLogon -and $matchingTgs) {
            New-Alert -Attack 'Kekeo / Ticket Forging (suspected)' -Severity 'High' -Computer $Computer `
                -Account $acct -EventIds 4624,4672,4768 -TimeCreated $a.TimeCreated `
                -Message "Privileged token assigned (4672) for '$acct' with a nearby TGS request (4768) but no corresponding interactive/network logon (4624) - consistent with crafted/injected Kerberos tickets (Kekeo)."
        }
    }
}

# Silver Ticket (service ticket used without a corresponding TGT/logon chain, admin rights granted)
function Test-SilverTicket {
    param([string]$Computer, [datetime]$Since)
    $logon  = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4624 -StartTime $Since
    $logoff = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4634 -StartTime $Since
    $admin  = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4672 -StartTime $Since

    foreach ($l in $logon) {
        $authPkg = Get-EventField $l 'AuthenticationPackageName'
        $acct    = Get-EventField $l 'TargetUserName'
        $logonId = Get-EventField $l 'TargetLogonId'
        if ($authPkg -ne 'Kerberos') { continue }

        $hasAdmin = $admin | Where-Object {
            (Get-EventField $_ 'SubjectUserName') -eq $acct -and
            [math]::Abs(($_.TimeCreated - $l.TimeCreated).TotalSeconds) -lt 5
        }
        $hasLogoff = $logoff | Where-Object { (Get-EventField $_ 'TargetLogonId') -eq $logonId }

        if ($hasAdmin -and -not $hasLogoff) {
            New-Alert -Attack 'Silver Ticket (suspected)' -Severity 'High' -Computer $Computer `
                -Account $acct -EventIds 4624,4634,4672 -TimeCreated $l.TimeCreated `
                -Message "Kerberos logon for '$acct' granted admin-equivalent rights (4672) with no matching logoff (4634) yet - cross-check against DC 4768/4769 logs; a forged service ticket never touches the KDC."
        }
    }
}

# Golden Ticket (admin logon with no corresponding krbtgt-issued TGT on this host)
function Test-GoldenTicket {
    param([string]$Computer, [datetime]$Since)
    $logon = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4624 -StartTime $Since
    $admin = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4672 -StartTime $Since

    foreach ($a in $admin) {
        $acct = Get-EventField $a 'SubjectUserName'
        if ($acct -match '\$$') { continue } # ignore machine accounts
        $sid = Get-EventField $a 'SubjectUserSid'

        $recentLogon = $logon | Where-Object {
            (Get-EventField $_ 'TargetUserName') -eq $acct -and
            [math]::Abs(($_.TimeCreated - $a.TimeCreated).TotalSeconds) -lt 5
        }
        if (-not $recentLogon) {
            New-Alert -Attack 'Golden Ticket (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account $acct -EventIds 4624,4672 -TimeCreated $a.TimeCreated `
                -Message "Admin-equivalent privileges asserted (4672, SID $sid) for '$acct' with no correlating 4624 logon on this host - validate the account still exists and its krbtgt-issued TGT lifetime is normal (default 10h); mismatched lifetimes or disabled/deleted accounts with valid tickets indicate a Golden Ticket."
        }
    }
}

# Suspicious PowerShell (script block / module logging)
# NOTE: 4103/4104 (script block + module logging) live in the modern
# "Microsoft-Windows-PowerShell/Operational" channel. 400/403 (Engine Lifecycle)
# and 600 (Provider Lifecycle) live in the CLASSIC "Windows PowerShell" log - a
# different channel entirely. Querying only one log misses the other's events.
function Test-SuspiciousPowerShell {
    param([string]$Computer, [datetime]$Since)
    $opEvents      = Get-SafeWinEvent -ComputerName $Computer -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4103,4104 -StartTime $Since
    $classicEvents = Get-SafeWinEvent -ComputerName $Computer -LogName 'Windows PowerShell' -Id 400,403,600 -StartTime $Since
    $events = @($opEvents) + @($classicEvents)
    if (-not $events) { return }

    $patterns = @(
        'Invoke-Mimikatz', 'mimikatz', 'Invoke-DCSync', 'Invoke-Kerberoast', 'Invoke-SkeletonKey',
        'AmsiUtils', 'amsiInitFailed', '\[Ref\]\.Assembly', 'System\.Reflection\.Assembly', 'DownloadString',
        'IEX\s*\(', 'Invoke-Expression', '-EncodedCommand', 'FromBase64String', 'Invoke-ReflectivePEInjection',
        'Add-Type.*Win32', 'bypass', 'Invoke-DCShadow'
    )
    $regex = ($patterns -join '|')

    foreach ($e in $events) {
        # 400/403/600 classic events carry a HostApplication field (the launching
        # command line) instead of ScriptBlockText - check both.
        $text = ($e.Message + ' ' + (Get-EventField $e 'ScriptBlockText') + ' ' + (Get-EventField $e 'HostApplication'))
        if ($text -match $regex) {
            $hit = [regex]::Match($text, $regex).Value
            New-Alert -Attack 'Suspicious PowerShell' -Severity 'High' -Computer $Computer `
                -Account (Get-EventField $e 'UserId') -EventIds $e.Id -TimeCreated $e.TimeCreated `
                -Message "PowerShell log ($($e.Id)) matched offensive-tooling indicator '$hit' - review full script block for context."
        }
        # 400/600 with no matching keyword still deserve a low-severity presence
        # note if the host application looks like a non-standard PS host (e.g.
        # loaded via a .NET assembly rather than powershell.exe/powershell_ise.exe).
        if ($e.Id -in 400,600) {
            $hostApp = Get-EventField $e 'HostApplication'
            if ($hostApp -and $hostApp -notmatch 'powershell(_ise)?\.exe|pwsh\.exe') {
                New-Alert -Attack 'Non-Standard PowerShell Host' -Severity 'Medium' -Computer $Computer `
                    -Account (Get-EventField $e 'UserId') -EventIds $e.Id -TimeCreated $e.TimeCreated `
                    -Message "Engine/Provider Lifecycle event ($($e.Id)) shows PowerShell hosted by a non-standard process: '$hostApp'. Legitimate interactive use is almost always powershell.exe/pwsh.exe - a different host process often means PowerShell is being invoked reflectively from another language/runtime (e.g. C#/VBA loaders)."
            }
        }
    }
}

# DCShadow (rogue DC registration / replication metadata manipulation)
function Test-DCShadow {
    param([string]$Computer, [datetime]$Since)
    $compChange = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4742 -StartTime $Since
    $objCreate  = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 5137 -StartTime $Since
    $objDelete  = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 5141 -StartTime $Since
    $replRemove = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4929 -StartTime $Since

    foreach ($c in $compChange) {
        $window = ($objCreate + $objDelete + $replRemove) | Where-Object {
            [math]::Abs(($_.TimeCreated - $c.TimeCreated).TotalMinutes) -lt 5
        }
        if ($window) {
            New-Alert -Attack 'DCShadow (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account (Get-EventField $c 'SubjectUserName') -EventIds 4742,5137,5141,4929 -TimeCreated $c.TimeCreated `
                -Message "Computer account change (4742) correlated within 5 min with directory object create/delete (5137/5141) and/or replication source removal (4929) - classic DCShadow pattern (rogue DC registers, pushes a change, then de-registers)."
        }
    }
}

# Skeleton Key (lsass patched to accept a universal password)
function Test-SkeletonKey {
    param([string]$Computer, [datetime]$Since)
    $priv    = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4673 -StartTime $Since
    $lsaReg  = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4611 -StartTime $Since
    $procNew = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4688 -StartTime $Since
    $procEnd = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4689 -StartTime $Since

    foreach ($r in $lsaReg) {
        $procName = Get-EventField $r 'ProcessName'
        # Correlate: a non-standard process created (4688) shortly before this LSA
        # registration, which then exits quickly (4689) - consistent with a helper
        # process injecting into lsass.exe and detaching (mimikatz misc::skeleton
        # style one-shot patch), rather than a persistent legitimate SSP/AP.
        $nearbyProc = $procNew | Where-Object {
            (Get-EventField $_ 'NewProcessName') -notmatch '(lsass\.exe|services\.exe|winlogon\.exe|wininit\.exe|svchost\.exe)$' -and
            [math]::Abs(($_.TimeCreated - $r.TimeCreated).TotalSeconds) -lt 30
        }
        $quickExit = $nearbyProc | ForEach-Object {
            $spawnedProc = $_
            $pid_ = Get-EventField $spawnedProc 'NewProcessId'
            $procEnd | Where-Object { (Get-EventField $_ 'ProcessId') -eq $pid_ -and [math]::Abs(($_.TimeCreated - $spawnedProc.TimeCreated).TotalSeconds) -lt 60 }
        }

        if ($procName -and $procName -notmatch '(lsass\.exe|services\.exe|winlogon\.exe|wininit\.exe)$') {
            $sev = if ($nearbyProc) { 'Critical' } else { 'High' }
            $corr = if ($nearbyProc) { " Corroborated by a non-standard process launch (4688: $((Get-EventField $nearbyProc[0] 'NewProcessName'))) within 30s of registration$(if ($quickExit) { ', which exited shortly after (4689) - classic inject-and-detach pattern.' } else { '.' })" } else { '' }
            New-Alert -Attack 'Skeleton Key (suspected)' -Severity $sev -Computer $Computer `
                -EventIds 4611,4688,4689 -TimeCreated $r.TimeCreated `
                -Message "Unusual trusted logon process registered with LSA (4611): '$procName'.$corr This is the signature technique behind Skeleton Key malware patching lsass.exe to accept a master password."
        }
    }
    foreach ($p in $priv) {
        $svc = Get-EventField $p 'ServiceName'
        if ($svc -match 'LsaRegisterLogonProcess|SeTcbPrivilege') {
            New-Alert -Attack 'Skeleton Key (suspected)' -Severity 'High' -Computer $Computer `
                -EventIds 4673 -TimeCreated $p.TimeCreated `
                -Message "Privileged service call (4673) referencing '$svc' - correlate with 4611/4688 around lsass.exe for Skeleton Key confirmation."
        }
    }
}

# PYKEK / MS14-068 (forged PAC - admin rights that don't line up with a legitimate group path)
function Test-MS14068 {
    param([string]$Computer, [datetime]$Since)
    $tgs   = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4768 -StartTime $Since
    $admin = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4672 -StartTime $Since
    $logon = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4624 -StartTime $Since

    foreach ($a in $admin) {
        $acct = Get-EventField $a 'SubjectUserName'
        $sid  = Get-EventField $a 'SubjectUserSid'
        $matchingLogon = $logon | Where-Object {
            (Get-EventField $_ 'TargetUserName') -eq $acct -and
            [math]::Abs(($_.TimeCreated - $a.TimeCreated).TotalSeconds) -lt 5
        }
        $matchingTgs = $tgs | Where-Object {
            (Get-EventField $_ 'TargetUserName') -eq $acct -and
            [math]::Abs(($_.TimeCreated - $a.TimeCreated).TotalMinutes) -lt 5
        }
        if ($matchingTgs -and $matchingLogon) {
            $level = Get-EventField $matchingLogon[0] 'LogonType'
            New-Alert -Attack 'MS14-068 / pykek (verify)' -Severity 'High' -Computer $Computer `
                -Account $acct -EventIds 4624,4672,4768 -TimeCreated $a.TimeCreated `
                -Message "Account '$acct' (SID $sid) obtained admin token (4672) immediately after a TGS request (4768), LogonType $level. If '$acct' is not a legitimate member of a privileged group in AD, this matches forged-PAC (MS14-068) elevation - confirm DC patch level and AD group membership."
        }
    }
}

# Kerberoasting (bulk TGS requests, especially RC4/etype 0x17, for service accounts)
function Test-Kerberoasting {
    param([string]$Computer, [datetime]$Since)
    $tgs = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4769 -StartTime $Since
    if (-not $tgs) { return }

    $rc4 = $tgs | Where-Object { (Get-EventField $_ 'TicketEncryptionType') -eq '0x17' }
    $rc4 |
        Group-Object { Get-EventField $_ 'TargetUserName' } |
        ForEach-Object {
            $recent = $_.Group | Where-Object { $_.TimeCreated -ge (Get-Date).AddMinutes(-$KerberoastWindowMinutes) }
            $distinctSpns = ($recent | ForEach-Object { Get-EventField $_ 'ServiceName' } | Select-Object -Unique)
            if ($recent.Count -ge $KerberoastTgsThreshold -or $distinctSpns.Count -ge $KerberoastTgsThreshold) {
                New-Alert -Attack 'Kerberoasting' -Severity 'High' -Computer $Computer `
                    -Account $_.Name -EventIds 4769 -TimeCreated ($recent | Select-Object -Last 1).TimeCreated `
                    -Message "Requester '$($_.Name)' made $($recent.Count) RC4 (etype 0x17) TGS requests (4769) across $($distinctSpns.Count) distinct SPNs in $KerberoastWindowMinutes min - classic Kerberoasting sweep (e.g. Rubeus/Invoke-Kerberoast)."
            }
        }
}

# S4U2Proxy abuse (constrained/resource-based delegation misuse)
function Test-S4U2Proxy {
    param([string]$Computer, [datetime]$Since)
    $tgs = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4769 -StartTime $Since
    foreach ($e in $tgs) {
        $flags = Get-EventField $e 'TicketOptions'
        $svc   = Get-EventField $e 'ServiceName'
        $target= Get-EventField $e 'TargetUserName'
        if ($flags -eq '0x40810000') {
            New-Alert -Attack 'S4U2Proxy Delegation Abuse (suspected)' -Severity 'High' -Computer $Computer `
                -Account $target -EventIds 4769 -TimeCreated $e.TimeCreated `
                -Message "TGS request (4769) for service '$svc' shows TicketOptions 0x40810000 (constrained-delegation / S4U2Proxy pattern) requested on behalf of '$target' - verify the delegating account's msDS-AllowedToDelegateTo / RBCD configuration is expected."
        }
    }
}

# Lateral Movement (same account, many destination hosts, in a short window)
# Spec calls for 4624 (success), 4625 (failure), 4688 (process created), 4689
# (process exited). Successes/process-creation drive the "confirmed hop" alert;
# failures across many hosts for one account are surfaced as a separate,
# lower-severity "movement attempt" signal (e.g. PsExec hitting hosts where the
# account doesn't have rights, before landing somewhere it does).
function Test-LateralMovement {
    param([hashtable]$AllHostEvents)
    $byAccount = @{}
    $failByAccount = @{}
    foreach ($hostName in $AllHostEvents.Keys) {
        foreach ($e in $AllHostEvents[$hostName]) {
            if ($e.Id -in 4624,4688) {
                $acct = if ($e.Id -eq 4624) { Get-EventField $e 'TargetUserName' } else { Get-EventField $e 'SubjectUserName' }
                if (-not $acct -or $acct -match '\$$') { continue }
                if (-not $byAccount.ContainsKey($acct)) { $byAccount[$acct] = New-Object System.Collections.Generic.List[object] }
                $byAccount[$acct].Add([pscustomobject]@{ Host = $hostName; Event = $e })
            }
            elseif ($e.Id -eq 4625) {
                $acct = Get-EventField $e 'TargetUserName'
                if (-not $acct -or $acct -match '\$$') { continue }
                if (-not $failByAccount.ContainsKey($acct)) { $failByAccount[$acct] = New-Object System.Collections.Generic.List[object] }
                $failByAccount[$acct].Add([pscustomobject]@{ Host = $hostName; Event = $e })
            }
            # 4689 (process exit) has no independent alerting value here - it's
            # consumed by other correlators (e.g. Skeleton Key quick-exit check)
            # rather than lateral-movement scoring on its own.
        }
    }
    foreach ($acct in $byAccount.Keys) {
        $recent = $byAccount[$acct] | Where-Object { $_.Event.TimeCreated -ge (Get-Date).AddMinutes(-$LateralWindowMinutes) }
        $distinctHosts = $recent.Host | Select-Object -Unique
        if ($distinctHosts.Count -ge $LateralHopThreshold) {
            New-Alert -Attack 'Lateral Movement' -Severity 'High' -Computer ($distinctHosts -join ',') `
                -Account $acct -EventIds 4624,4688 -TimeCreated (Get-Date) `
                -Message "Account '$acct' authenticated/spawned processes on $($distinctHosts.Count) distinct hosts within $LateralWindowMinutes min ($($distinctHosts -join ', ')) - pattern consistent with lateral movement (PsExec/WMI/WinRM-style pivoting)."
        }
    }
    foreach ($acct in $failByAccount.Keys) {
        $recent = $failByAccount[$acct] | Where-Object { $_.Event.TimeCreated -ge (Get-Date).AddMinutes(-$LateralWindowMinutes) }
        $distinctHosts = $recent.Host | Select-Object -Unique
        if ($distinctHosts.Count -ge $LateralHopThreshold) {
            New-Alert -Attack 'Lateral Movement Attempt (failed)' -Severity 'Medium' -Computer ($distinctHosts -join ',') `
                -Account $acct -EventIds 4625 -TimeCreated (Get-Date) `
                -Message "Account '$acct' failed to logon (4625) on $($distinctHosts.Count) distinct hosts within $LateralWindowMinutes min ($($distinctHosts -join ', ')) - consistent with a lateral-movement sweep hitting hosts where the account lacks rights before finding one where it works."
        }
    }
}

# DNSAdmin -> arbitrary DLL load on DC via ServerLevelPluginDll
function Get-DnsAdminMessage {
    param($EventId)
    switch ($EventId) {
        541 { "ServerLevelPluginDll registry value was set (541) - a DnsAdmins-group member (or equivalent right) can load an arbitrary DLL into dns.exe running as SYSTEM on the DC. Verify the DLL path is expected." }
        770 { "DNS Server loaded a plugin DLL (770) - confirm this corresponds to an approved deployment, not attacker-supplied code via the DnsAdmins ServerLevelPluginDll technique." }
        150 { "DNS Server failed to load/initialize a plugin DLL (150) - a failed attempt is still a strong indicator someone tried the DnsAdmins DLL-load privilege-escalation technique." }
        default { "DNS Server event $EventId related to plugin DLL handling." }
    }
}
function Test-DnsAdminAbuse {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'DNS Server' -Id 150,541,770 -StartTime $Since
    foreach ($e in $events) {
        $sev = if ($e.Id -eq 541) { 'Critical' } else { 'High' }
        New-Alert -Attack 'DNSAdmin -> DC Compromise' -Severity $sev -Computer $Computer `
            -EventIds $e.Id -TimeCreated $e.TimeCreated -Message (Get-DnsAdminMessage -EventId $e.Id)
    }
}

# DCSync (replication rights used from a non-DC to pull password hashes)
function Test-DCSync {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4662 -StartTime $Since
    if (-not $events) { return }

    $replGuids = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'
    foreach ($e in $events) {
        $props = Get-EventField $e 'Properties'
        if (-not $props) { continue }
        $hit = $replGuids | Where-Object { $props -match [regex]::Escape($_) }
        if ($hit) {
            $subject = Get-EventField $e 'SubjectUserName'
            New-Alert -Attack 'DCSync' -Severity 'Critical' -Computer $Computer `
                -Account $subject -EventIds 4662 -TimeCreated $e.TimeCreated `
                -Message "Directory-replication access rights ($($hit -join ', ')) exercised (4662) by '$subject'. If this account is not a Domain Controller computer account or Azure AD Connect service account, this is DCSync - domain password hashes were likely just pulled."
        }
    }
}

# Password Spraying (many distinct accounts failing from one source in a short window)
function Test-PasswordSpray {
    param([string]$Computer, [datetime]$Since)
    $fail     = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4625 -StartTime $Since
    $preAuth  = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4771 -StartTime $Since
    $explicit = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4648 -StartTime $Since
    $all = @($fail) + @($preAuth) + @($explicit)
    if (-not $all) { return }

    $all |
        Group-Object { Get-EventField $_ 'IpAddress' } |
        Where-Object { $_.Name -and $_.Name -ne '-' } |
        ForEach-Object {
            $recent = $_.Group | Where-Object { $_.TimeCreated -ge (Get-Date).AddMinutes(-$SprayWindowMinutes) }
            $distinctAccounts = ($recent | ForEach-Object { Get-EventField $_ 'TargetUserName' } | Select-Object -Unique) | Where-Object { $_ }
            if ($distinctAccounts.Count -ge $SprayDistinctAccountThresh) {
                New-Alert -Attack 'Password Spraying' -Severity 'High' -Computer $Computer `
                    -SourceIp $_.Name -EventIds 4625,4771,4648 -TimeCreated ($recent | Select-Object -Last 1).TimeCreated `
                    -Message "Source IP $($_.Name) generated failed-auth/pre-auth events (4625/4771/4648) against $($distinctAccounts.Count) distinct accounts within $SprayWindowMinutes min - password spraying pattern, not a single-account brute force."
            }
        }
}

#endregion

#endregion

#region ------------------------------------------------------- Detections: Extended
#region --------------------------------------------------------------- Recon

# SPN Scanning / Service Discovery: broad 4769 sweeps across many distinct SPNs
# from one requester, WITHOUT the RC4 filter Kerberoasting detection uses - this
# catches reconnaissance sweeps (setspn.exe /T, GetUserSPNs.ps1, etc.) that may
# use AES tickets and therefore evade the Kerberoasting-specific check.
function Test-SPNScanning {
    param([string]$Computer, [datetime]$Since)
    $tgs = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4769 -StartTime $Since
    if (-not $tgs) { return }
    $tgs | Group-Object { Get-EventField $_ 'TargetUserName' } | ForEach-Object {
        $recent = $_.Group | Where-Object { $_.TimeCreated -ge (Get-Date).AddMinutes(-$SpnScanWindowMinutes) }
        $distinctSpns = ($recent | ForEach-Object { Get-EventField $_ 'ServiceName' } | Select-Object -Unique)
        if ($distinctSpns.Count -ge $SpnScanDistinctThreshold) {
            New-Alert -Attack 'SPN Scanning' -Severity 'Medium' -Computer $Computer `
                -Account $_.Name -EventIds 4769 -TimeCreated ($recent | Select-Object -Last 1).TimeCreated `
                -Message "Requester '$($_.Name)' requested TGS tickets for $($distinctSpns.Count) distinct SPNs in $SpnScanWindowMinutes min - broad service-account enumeration sweep, independent of ticket encryption type."
        }
    }
}

#endregion

#region ---------------------------------------------------------- Privilege Escalation

# BadSuccessor: abuse of delegated Managed Service Account (dMSA) creation/link
# to inherit the privileges of a preceding (often privileged) account.
function Test-BadSuccessorDMSA {
    param([string]$Computer, [datetime]$Since)
    $create = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 5137 -StartTime $Since
    foreach ($e in $create) {
        $objClass = Get-EventField $e 'ObjectClass'
        if ($objClass -eq 'msDS-DelegatedManagedServiceAccount') {
            New-Alert -Attack 'BadSuccessor (dMSA created)' -Severity 'High' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 5137 -TimeCreated $e.TimeCreated `
                -Message "A delegated Managed Service Account (dMSA) object was created. If an OU delegate created this and then set msDS-ManagedAccountPrecededByLink to a privileged account, the dMSA inherits that account's effective privileges on next authentication - verify who created it and what account (if any) it is linked to precede."
        }
    }
}

# sAMAccountName Spoofing (CVE-2021-42278/42287 weaponization): rename a computer
# account to look like a DC, request a TGT, then rename back.
function Test-SamAccountNameSpoofing {
    param([string]$Computer, [datetime]$Since)
    $renames = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4781 -StartTime $Since
    foreach ($e in $renames) {
        $old = Get-EventField $e 'OldTargetUserName'
        $new = Get-EventField $e 'NewTargetUserName'
        # Real DC/computer accounts always end in '$'. A rename that drops the
        # trailing '$' (impersonating a user-like name) or renames toward a name
        # matching a DC's hostname is the CVE-2021-42278/42287 chain's signature.
        if ($old -match '\$$' -and $new -notmatch '\$$') {
            New-Alert -Attack 'sAMAccountName Spoofing (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4781 -TimeCreated $e.TimeCreated `
                -Message "Computer account '$old' was renamed to '$new' (4781), dropping the trailing '$' - matches the sAMAccountName-spoofing chain (rename to impersonate a DC, request a TGT, then usually rename back). Check for a 4768 immediately after and a follow-up 4781 renaming it back."
        }
    }
}

# AD CS abuse ("Certified Pre-Owned" / ESC1 etc.): certificate requests/issuance
# worth a second look - especially templates allowing client auth + attacker-
# supplied SAN (ESC1), or enrollment agent misuse.
function Test-ADCSAbuse {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4886,4887,4888 -StartTime $Since
    foreach ($e in $events) {
        $tmpl = Get-EventField $e 'CertificateTemplate'
        $requester = Get-EventField $e 'RequesterSubject'
        if ($e.Id -eq 4887 -and $tmpl) {
            New-Alert -Attack 'AD CS Certificate Issued' -Severity 'Low' -Computer $Computer `
                -Account $requester -EventIds 4887 -TimeCreated $e.TimeCreated `
                -Message "Certificate issued (4887) from template '$tmpl' for '$requester'. If this template allows client authentication and a caller-supplied SAN (a classic ESC1 misconfiguration), and the requester is not the SAN's principal, this is Certified-Pre-Owned style privilege escalation - review the template's enrollment permissions and SAN policy."
        }
    }
}

# PetitPotam: coerces a DC to authenticate via MS-EFSRPC over the \pipe\efsrpc
# or \pipe\lsarpc named pipe, typically to relay to AD CS web enrollment (ESC8).
function Test-PetitPotam {
    param([string]$Computer, [datetime]$Since)
    $shareAccess = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 5145 -StartTime $Since
    foreach ($e in $shareAccess) {
        $share = Get-EventField $e 'ShareName'
        $rel   = Get-EventField $e 'RelativeTargetName'
        if ($share -match 'IPC\$' -and $rel -match 'efsrpc|lsarpc') {
            New-Alert -Attack 'PetitPotam (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 5145 -TimeCreated $e.TimeCreated `
                -Message "Named-pipe access to '$rel' over IPC$ (5145) - matches the MS-EFSRPC coercion technique used by PetitPotam to force a DC to authenticate to an attacker-controlled listener, usually chained into an NTLM relay against AD CS web enrollment (ESC8)."
        }
    }
}

# Zerologon (CVE-2020-1472): exploit ends with the DC's own computer account
# password effectively reset (often to empty) via a spoofed Netlogon channel.
function Test-Zerologon {
    param([string]$Computer, [datetime]$Since)
    $compChange = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4742 -StartTime $Since
    foreach ($e in $compChange) {
        $target = Get-EventField $e 'TargetUserName'
        $subject = Get-EventField $e 'SubjectUserName'
        if ($target -match '\$$' -and $target -eq $Computer.TrimEnd('.') + '$' -and $subject -ne $target) {
            New-Alert -Attack 'Zerologon (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account $subject -EventIds 4742 -TimeCreated $e.TimeCreated `
                -Message "The Domain Controller's own computer account '$target' had its account changed (4742) by a different principal ('$subject'). A DC changing its own machine account password is normal; a THIRD PARTY changing it is the classic Zerologon (CVE-2020-1472) exploitation tell - if unpatched, treat as an active compromise."
        }
    }
}

# GPP cpassword remnants in SYSVOL - this is a point-in-time file scan (MS14-025),
# not an event correlation, since the exposure is a static file, not a log event.
function Test-GPPCpasswordSysvol {
    param([string]$Path)
    if (-not $Path) { return }
    try {
        $xmls = Get-ChildItem -Path $Path -Recurse -Include *.xml -ErrorAction SilentlyContinue
        foreach ($f in $xmls) {
            $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match 'cpassword="[^"]+"') {
                New-Alert -Attack 'GPP Password Exposure' -Severity 'Critical' -Computer 'SYSVOL' `
                    -EventIds @() -Message "Group Policy Preferences file '$($f.FullName)' contains a non-empty cpassword attribute. This AES key was published by Microsoft (MS14-025) - any authenticated user can decrypt it. Remove the GPP-stored credential and rotate the affected account immediately."
            }
        }
    } catch { }
}

# Unconstrained delegation grant: TRUSTED_FOR_DELEGATION UserAccountControl flag
# newly set on a computer or user account.
function Test-UnconstrainedDelegationGrant {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4738,4742 -StartTime $Since
    foreach ($e in $events) {
        $flags = Get-EventField $e 'UserAccountControl'
        if ($flags -and $flags -match 'TRUSTED_FOR_DELEGATION') {
            New-Alert -Attack 'Unconstrained Delegation Grant' -Severity 'High' -Computer $Computer `
                -Account (Get-EventField $e 'TargetUserName') -EventIds $e.Id -TimeCreated $e.TimeCreated `
                -Message "Account '$(Get-EventField $e 'TargetUserName')' had TRUSTED_FOR_DELEGATION set ($($e.Id)) - unconstrained delegation means any Kerberos ticket cached on that host can be extracted from memory and replayed as the delegating user. Confirm this is an approved server role, not attacker-added."
        }
    }
}

# Resource-Based Constrained Delegation (RBCD): write to msDS-AllowedToActOnBehalfOfOtherIdentity.
function Test-RBCDChange {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4662 -StartTime $Since
    foreach ($e in $events) {
        $props = Get-EventField $e 'Properties'
        if ($props -match '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79') {
            New-Alert -Attack 'RBCD Configuration Change' -Severity 'High' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4662 -TimeCreated $e.TimeCreated `
                -Message "msDS-AllowedToActOnBehalfOfOtherIdentity was modified (4662) by '$(Get-EventField $e 'SubjectUserName')' - this is the Resource-Based Constrained Delegation attribute. Attackers with WriteProperty/GenericWrite on a computer object commonly set this to hijack it via S4U2Proxy. Verify the change was intentional."
        }
    }
}

# GPO permission abuse: modifications to a groupPolicyContainer object's ACL/content.
function Test-GPOAbuse {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 5136 -StartTime $Since
    foreach ($e in $events) {
        $objClass = Get-EventField $e 'ObjectClass'
        if ($objClass -eq 'groupPolicyContainer') {
            New-Alert -Attack 'GPO Modification' -Severity 'Medium' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 5136 -TimeCreated $e.TimeCreated `
                -Message "A Group Policy Object was modified (5136) by '$(Get-EventField $e 'SubjectUserName')'. GPO edits by anyone outside your GPO-admin group are a common persistence/lateral-movement vector (SharpGPOAbuse-style) - verify against your GPO change-control list."
        }
    }
}

# ACL/DACL abuse: WriteDacl / WriteOwner exercised against a directory object.
function Test-ACLAbuse {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4662 -StartTime $Since
    foreach ($e in $events) {
        $mask = Get-EventField $e 'AccessMask'
        if ($mask -in '0x40000', '0x80000', '0xC0000') {
            New-Alert -Attack 'ACL/DACL Abuse (suspected)' -Severity 'High' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4662 -TimeCreated $e.TimeCreated `
                -Message "WriteDacl/WriteOwner rights (AccessMask $mask) were exercised (4662) by '$(Get-EventField $e 'SubjectUserName')' against object $(Get-EventField $e 'ObjectName') - this is how ACL-based persistence/escalation (DCSync-grant backdoors, AdminSDHolder abuse, etc.) is planted. Compare against expected delegation."
        }
    }
}

# Domain Trust abuse: new trust created, or an existing trust's attributes
# changed (e.g. disabling SID filtering / enabling SID history / quarantine off).
function Test-DomainTrustAbuse {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4706,4716 -StartTime $Since
    foreach ($e in $events) {
        $sev = if ($e.Id -eq 4716) { 'Critical' } else { 'High' }
        $target = Get-EventField $e 'TargetDomainName'
        New-Alert -Attack 'Domain Trust Change' -Severity $sev -Computer $Computer `
            -Account (Get-EventField $e 'SubjectUserName') -EventIds $e.Id -TimeCreated $e.TimeCreated `
            -Message "$(if ($e.Id -eq 4706) { 'A new trust was created' } else { 'An existing trust had its attributes modified' }) ($($e.Id)) toward domain '$target'. Verify this is a planned trust change - attribute changes disabling SID filtering are a common forest-trust escalation path."
    }
}

#endregion

#region ---------------------------------------------------- Credential Relay / PtH

# Pass-the-Hash: NTLM logon immediately followed by an admin-equivalent token,
# repeated for the same account across multiple destination hosts quickly.
function Test-PassTheHash {
    param([hashtable]$AllHostEvents)
    $byAccount = @{}
    foreach ($hostName in $AllHostEvents.Keys) {
        $logons = $AllHostEvents[$hostName] | Where-Object { $_.Id -eq 4624 }
        $admin  = $AllHostEvents[$hostName] | Where-Object { $_.Id -eq 4672 }
        foreach ($l in $logons) {
            $pkg = Get-EventField $l 'AuthenticationPackageName'
            if ($pkg -ne 'NTLM') { continue }
            $acct = Get-EventField $l 'TargetUserName'
            if (-not $acct -or $acct -match '\$$') { continue }
            $hasAdmin = $admin | Where-Object { (Get-EventField $_ 'SubjectUserName') -eq $acct -and [math]::Abs(($_.TimeCreated - $l.TimeCreated).TotalSeconds) -lt 5 }
            if ($hasAdmin) {
                if (-not $byAccount.ContainsKey($acct)) { $byAccount[$acct] = New-Object System.Collections.Generic.List[object] }
                $byAccount[$acct].Add([pscustomobject]@{ Host = $hostName; Time = $l.TimeCreated })
            }
        }
    }
    foreach ($acct in $byAccount.Keys) {
        $recent = $byAccount[$acct] | Where-Object { $_.Time -ge (Get-Date).AddMinutes(-$PthWindowMinutes) }
        $distinctHosts = $recent.Host | Select-Object -Unique
        if ($distinctHosts.Count -ge $PthHopThreshold) {
            New-Alert -Attack 'Pass-the-Hash (suspected)' -Severity 'Critical' -Computer ($distinctHosts -join ',') `
                -Account $acct -EventIds 4624,4672 -TimeCreated (Get-Date) `
                -Message "'$acct' authenticated via NTLM with an immediate admin-equivalent token on $($distinctHosts.Count) distinct hosts within $PthWindowMinutes min ($($distinctHosts -join ', ')) - NTLM auth + instant privilege across many hosts for one account is the Pass-the-Hash signature (mimikatz sekurlsa::pth)."
        }
    }
}

# NTLM Relay: one source IP authenticating (via NTLM) as many distinct target
# accounts in a short window - relayed credentials, not one user's normal traffic.
function Test-NtlmRelay {
    param([string]$Computer, [datetime]$Since)
    $logons = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4624 -StartTime $Since
    $ntlm = $logons | Where-Object { (Get-EventField $_ 'AuthenticationPackageName') -eq 'NTLM' }
    if (-not $ntlm) { return }
    $ntlm | Group-Object { Get-EventField $_ 'IpAddress' } | Where-Object { $_.Name -and $_.Name -ne '-' -and $_.Name -ne '127.0.0.1' } | ForEach-Object {
        $recent = $_.Group | Where-Object { $_.TimeCreated -ge (Get-Date).AddMinutes(-$NtlmRelayWindowMinutes) }
        $distinctAccounts = ($recent | ForEach-Object { Get-EventField $_ 'TargetUserName' } | Select-Object -Unique) | Where-Object { $_ }
        if ($distinctAccounts.Count -ge $NtlmRelayDistinctThreshold) {
            New-Alert -Attack 'NTLM Relay (suspected)' -Severity 'High' -Computer $Computer `
                -SourceIp $_.Name -EventIds 4624 -TimeCreated ($recent | Select-Object -Last 1).TimeCreated `
                -Message "Source $($_.Name) produced NTLM logons as $($distinctAccounts.Count) distinct accounts within $NtlmRelayWindowMinutes min - one endpoint authenticating as many different identities in quick succession is the ntlmrelayx/Responder relay pattern, not normal single-machine traffic. Confirm SMB/LDAP signing is enforced."
        }
    }
}

#endregion

#region ---------------------------------------------------------------- Evasion

# The single highest-signal "someone is covering tracks" event: audit log cleared.
function Test-SecurityLogCleared {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 1102 -StartTime $Since
    foreach ($e in $events) {
        New-Alert -Attack 'Security Log Cleared' -Severity 'Critical' -Computer $Computer `
            -Account (Get-EventField $e 'SubjectUserName') -EventIds 1102 -TimeCreated $e.TimeCreated `
            -Message "The Security event log was cleared (1102) by '$(Get-EventField $e 'SubjectUserName')'. This is almost never legitimate mid-operations and strongly suggests anti-forensic activity following a compromise - investigate immediately and pull any forwarded/WEF copies of the log before this point."
    }
}

# Audit policy tampering: disabling the very subcategories this tool depends on.
function Test-AuditPolicyTampering {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4719 -StartTime $Since
    foreach ($e in $events) {
        New-Alert -Attack 'Audit Policy Tampering' -Severity 'Critical' -Computer $Computer `
            -Account (Get-EventField $e 'SubjectUserName') -EventIds 4719 -TimeCreated $e.TimeCreated `
            -Message "System audit policy was changed (4719) by '$(Get-EventField $e 'SubjectUserName')' - category: $(Get-EventField $e 'SubcategoryString'). If a monitored subcategory was disabled, this tool (and your SIEM) may now be blind to follow-on activity on this host."
    }
}

# Event Log / Sysmon service killed (Invoke-Phant0m, Shhmon-style evasion):
# watch the System log for the logging services themselves stopping.
function Test-LoggingServiceKilled {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'System' -Id 7036,1100 -StartTime $Since
    foreach ($e in $events) {
        $msg = $e.Message
        if ($msg -match 'Event Log' -or $msg -match 'Sysmon') {
            New-Alert -Attack 'Logging Service Killed (suspected)' -Severity 'Critical' -Computer $Computer `
                -EventIds $e.Id -TimeCreated $e.TimeCreated `
                -Message "System log ($($e.Id)) indicates a logging-related service transitioned state, matching text: '$($msg.Substring(0,[Math]::Min(120,$msg.Length)))'. If this is the Windows Event Log service or Sysmon stopping outside a planned maintenance window, this matches Invoke-Phant0m / Sysmon-driver-unload evasion - expect a gap in subsequent telemetry."
        }
    }
}

#endregion

#region --------------------------------------------------------- Credential Dumping

# NTDS.dit extraction: process-creation command lines matching the standard
# ntdsutil / vssadmin-shadow-copy / esentutl exfiltration recipe.
function Test-NTDSExtraction {
    param([string]$Computer, [datetime]$Since)
    $procs = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4688 -StartTime $Since
    $patterns = 'ntdsutil.*ifm', 'ntdsutil.*create full', 'vssadmin.*create shadow', 'esentutl.*ntds\.dit', 'diskshadow'
    $regex = ($patterns -join '|')
    foreach ($e in $procs) {
        $cmd = Get-EventField $e 'CommandLine'
        if ($cmd -and $cmd -match $regex) {
            New-Alert -Attack 'NTDS.dit Extraction (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4688 -TimeCreated $e.TimeCreated `
                -Message "Process creation (4688) command line matched an NTDS.dit-extraction pattern: '$cmd'. This is the standard recipe for pulling the AD database (via shadow copy + ntdsutil/esentutl) to dump every domain password hash offline."
        }
    }
}

# LSASS access: any handle opened to lsass.exe with access rights beyond the
# routine minimum - requires Object Access auditing configured on the process.
function Test-LSASSAccess {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4663 -StartTime $Since
    foreach ($e in $events) {
        $obj = Get-EventField $e 'ObjectName'
        if ($obj -match 'lsass\.exe$') {
            New-Alert -Attack 'LSASS Access (suspected credential dumping)' -Severity 'Critical' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4663 -TimeCreated $e.TimeCreated `
                -Message "An access attempt was made against lsass.exe (4663) by '$(Get-EventField $e 'SubjectUserName')'. Full-access handles to LSASS from anything other than known-good AV/EDR is the mimikatz sekurlsa:: / procdump credential-dumping pattern. For higher fidelity, prefer Sysmon Event ID 10 (ProcessAccess) with a GrantedAccess filter."
        }
    }
}

# AS-REP Roasting: 4768 where the account does not require Kerberos pre-auth.
function Test-ASREPRoasting {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4768 -StartTime $Since
    foreach ($e in $events) {
        $preAuth = Get-EventField $e 'PreAuthType'
        if ($preAuth -eq '0') {
            New-Alert -Attack 'AS-REP Roasting' -Severity 'High' -Computer $Computer `
                -Account (Get-EventField $e 'TargetUserName') -EventIds 4768 -TimeCreated $e.TimeCreated `
                -Message "TGT issued (4768) with PreAuthType 0 for '$(Get-EventField $e 'TargetUserName')' - this account has 'Do not require Kerberos preauthentication' enabled, letting anyone request and offline-crack its AS-REP (Rubeus/GetNPUsers.py). Disable the DONT_REQUIRE_PREAUTH flag unless there's a specific reason for it."
        }
    }
}

# DPAPI abuse via command-line tooling (mimikatz dpapi::, vaultcmd, SharpDPAPI).
function Test-DPAPIAbuse {
    param([string]$Computer, [datetime]$Since)
    $procs = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4688 -StartTime $Since
    foreach ($e in $procs) {
        $cmd = Get-EventField $e 'CommandLine'
        if ($cmd -and $cmd -match 'dpapi::|vaultcmd|SharpDPAPI|CredMan::') {
            New-Alert -Attack 'DPAPI Abuse (suspected)' -Severity 'High' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4688 -TimeCreated $e.TimeCreated `
                -Message "Process creation (4688) matched a DPAPI-abuse command line: '$cmd' - consistent with offline decryption of saved credentials/cookies/RDP passwords via Windows DPAPI blobs."
        }
    }
}

#endregion

#region ----------------------------------------------------------------- Persistence

# SID History injection: 4765 (added) / 4766 (attempt failed).
function Test-SIDHistoryInjection {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4765,4766 -StartTime $Since
    foreach ($e in $events) {
        $sev = if ($e.Id -eq 4765) { 'Critical' } else { 'High' }
        New-Alert -Attack 'SID History Injection' -Severity $sev -Computer $Computer `
            -Account (Get-EventField $e 'SubjectUserName') -EventIds $e.Id -TimeCreated $e.TimeCreated `
            -Message "$(if ($e.Id -eq 4765) { 'SID History was added to an account' } else { 'An attempt to add SID History failed' }) ($($e.Id)) by '$(Get-EventField $e 'SubjectUserName')'. Legitimate SID History use is limited to inter-domain migrations (ADMT); outside that context this is a well-known cross-domain/forest persistence and privilege-escalation technique."
    }
}

# SeEnableDelegationPrivilege grant: this right lets its holder mark any account
# 'trusted for delegation' - handing it to a non-Tier-0 account is a backdoor.
function Test-SeEnableDelegationPrivilegeGrant {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4704 -StartTime $Since
    foreach ($e in $events) {
        $rights = Get-EventField $e 'PrivilegeList'
        if ($rights -match 'SeEnableDelegationPrivilege') {
            New-Alert -Attack 'SeEnableDelegationPrivilege Grant' -Severity 'Critical' -Computer $Computer `
                -Account (Get-EventField $e 'TargetUserName') -EventIds 4704 -TimeCreated $e.TimeCreated `
                -Message "SeEnableDelegationPrivilege was assigned (4704) to '$(Get-EventField $e 'TargetUserName')'. This right allows configuring Kerberos delegation on any account/computer - one of the least-known but most dangerous AD backdoors. Confirm this is a deliberate Tier-0 delegation, not attacker-planted persistence."
        }
    }
}

# Security Support Provider (SSP) persistence: registry change loading an extra
# SSP DLL into LSASS - requires Registry object-access auditing on the LSA key.
function Test-SSPPersistence {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4657 -StartTime $Since
    foreach ($e in $events) {
        $obj = Get-EventField $e 'ObjectName'
        if ($obj -match 'Control\\Lsa\\(Security Packages|OSConfig\\Security Packages)') {
            New-Alert -Attack 'Security Support Provider Persistence (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4657 -TimeCreated $e.TimeCreated `
                -Message "The LSA Security Packages registry value was modified (4657) by '$(Get-EventField $e 'SubjectUserName')'. Adding a rogue SSP DLL here (e.g. mimilib.dll) captures every credential authenticating through LSASS from that point on, surviving reboots. Verify the new value against your known-good SSP list, and check for the DLL on disk."
        }
    }
}

# DSRM persistence: enabling network logon for the local DSRM administrator
# account (DsrmAdminLogonBehavior) turns a rarely-used recovery account into
# a durable, often-unmonitored backdoor to every DC.
function Test-DSRMPersistence {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4657 -StartTime $Since
    foreach ($e in $events) {
        $obj = Get-EventField $e 'ObjectName'
        if ($obj -match 'DsrmAdminLogonBehavior') {
            New-Alert -Attack 'DSRM Persistence (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4657 -TimeCreated $e.TimeCreated `
                -Message "DsrmAdminLogonBehavior was modified (4657) by '$(Get-EventField $e 'SubjectUserName')'. Setting this to allow network logon lets the local DSRM administrator account authenticate to the DC like a domain account - a durable backdoor that bypasses normal domain account monitoring and password policy. Confirm the DSRM password was not also changed around this time."
        }
    }
}

#endregion

#endregion

#region ---------------------------------------------------------- Detections: Gap-fill additions

# LAPS password read abuse: ms-Mcs-AdmPwd (or the newer LAPS v2 attribute) is a
# confidential attribute - reading it grants the local admin password for that
# computer. A 4662 read-property event against it, from an account outside your
# approved LAPS-reader group, is the tell.
function Test-LAPSPasswordRead {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4662 -StartTime $Since
    foreach ($e in $events) {
        $props = Get-EventField $e 'Properties'
        if ($props -match 'ms-Mcs-AdmPwd|msLAPS-Password') {
            New-Alert -Attack 'LAPS Password Read' -Severity 'High' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4662 -TimeCreated $e.TimeCreated `
                -Message "The LAPS local-admin-password attribute was read (4662) by '$(Get-EventField $e 'SubjectUserName')' on object $(Get-EventField $e 'ObjectName'). Confirm this account is in your approved LAPS-readers delegation - this attribute directly yields a local admin credential."
        }
    }
}

# SAM registry hive dump: reg.exe (or equivalent) saving HKLM\SAM/SYSTEM to disk
# for offline extraction, the classic non-LSASS credential-dumping path.
function Test-SAMDump {
    param([string]$Computer, [datetime]$Since)
    $procs = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4688 -StartTime $Since
    foreach ($e in $procs) {
        $cmd = Get-EventField $e 'CommandLine'
        if ($cmd -and $cmd -match 'reg(\.exe)?\s+save\s+.*\\(SAM|SYSTEM|SECURITY)\b') {
            New-Alert -Attack 'SAM Hive Dump (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account (Get-EventField $e 'SubjectUserName') -EventIds 4688 -TimeCreated $e.TimeCreated `
                -Message "Process creation (4688) command line matched a registry-hive-save pattern: '$cmd'. Saving SAM/SYSTEM/SECURITY hives to disk is the standard precursor to offline SAM/LSA-secrets extraction (e.g. via secretsdump.py or Mimikatz lsadump::sam)."
        }
    }
}

# LOLBin abuse (AppLocker/Device Guard bypass via living-off-the-land binaries):
# well-known signed Microsoft binaries used to execute/download attacker payloads,
# most commonly seen bypassing AppLocker rules that only block unsigned .exe files.
function Test-LOLBinAbuse {
    param([string]$Computer, [datetime]$Since)
    $procs = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4688 -StartTime $Since
    # Pair each LOLBin with the argument pattern that actually indicates abuse
    # (not just "was launched", since these binaries have legitimate uses too).
    $lolbinPatterns = @{
        'msbuild\.exe'   = 'http|\.xml.*Task|InlineTask'
        'mshta\.exe'     = 'http|javascript:|vbscript:'
        'regsvr32\.exe'  = '/i:http|scrobj\.dll'
        'rundll32\.exe'  = 'javascript:|http'
        'certutil\.exe'  = '-urlcache|-decode|-encode'
        'installutil\.exe' = '/logfile=|/U\b'
        'wmic\.exe'      = 'process\s+call\s+create.*http'
    }
    foreach ($e in $procs) {
        $cmd = Get-EventField $e 'CommandLine'
        if (-not $cmd) { continue }
        foreach ($bin in $lolbinPatterns.Keys) {
            if ($cmd -match $bin -and $cmd -match $lolbinPatterns[$bin]) {
                New-Alert -Attack 'LOLBin Abuse (suspected)' -Severity 'High' -Computer $Computer `
                    -Account (Get-EventField $e 'SubjectUserName') -EventIds 4688 -TimeCreated $e.TimeCreated `
                    -Message "Process creation (4688) invoked '$bin' with arguments matching a known AppLocker/Device-Guard-bypass pattern: '$cmd'. Signed Microsoft binaries executing remote/inline code this way is a classic LOLBins technique to evade application whitelisting."
                break
            }
        }
    }
}

# Exchange PrivExchange-style escalation: an Exchange server computer account
# (which by default holds WriteDacl on the domain object pre-patch) modifying
# a domain-level ACL is the signature of this privesc chain.
function Test-ExchangePrivEsc {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'Security' -Id 4662 -StartTime $Since
    foreach ($e in $events) {
        $subject = Get-EventField $e 'SubjectUserName'
        $mask    = Get-EventField $e 'AccessMask'
        $objType = Get-EventField $e 'ObjectType'
        if ($subject -match '\$$' -and $mask -in '0x40000', '0x80000', '0xC0000' -and $objType -match 'domainDNS') {
            New-Alert -Attack 'Exchange PrivExchange (suspected)' -Severity 'Critical' -Computer $Computer `
                -Account $subject -EventIds 4662 -TimeCreated $e.TimeCreated `
                -Message "A computer account ('$subject') exercised WriteDacl/WriteOwner rights (4662) against the domain object itself. If '$subject' is an Exchange server, this matches the PrivExchange chain (NTLM-relay a forced Exchange auth into a domain-object ACL write) - verify Exchange's default over-privileged ACL has been remediated (CVE-2019-0724 patch / removed WriteDacl grant)."
        }
    }
}

# ADFS suspicious activity: token-signing certificate export or a spike in
# ADFS Admin log errors, both associated with Golden SAML-style attacks and
# ADFS endpoint enumeration tooling (e.g. LyncSniper-adjacent recon).
function Test-ADFSSuspiciousActivity {
    param([string]$Computer, [datetime]$Since)
    $events = Get-SafeWinEvent -ComputerName $Computer -LogName 'AD FS/Admin' -Id 342,501,1202 -StartTime $Since
    foreach ($e in $events) {
        New-Alert -Attack 'ADFS Suspicious Activity' -Severity 'High' -Computer $Computer `
            -EventIds $e.Id -TimeCreated $e.TimeCreated `
            -Message "ADFS Admin log event $($e.Id) recorded. Event 1202 repeated failures can indicate credential-stuffing against ADFS; token-signing-certificate-related events warrant checking whether the cert (and therefore SAML-token forging capability, i.e. 'Golden SAML') was exported. Requires the AD FS/Admin log to be enabled on this host."
    }
}

# Extends the GPP cpassword scanner: also flags unattend.xml / sysprep.inf /
# other SYSVOL-adjacent files with plaintext or lightly-obfuscated passwords.
function Test-UnattendCredentials {
    param([string]$Path)
    if (-not $Path) { return }
    try {
        $files = Get-ChildItem -Path $Path -Recurse -Include 'unattend.xml','sysprep.xml','sysprep.inf','autounattend.xml' -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match '<Password>|AdminPassword') {
                New-Alert -Attack 'Unattend.xml Credential Exposure' -Severity 'High' -Computer 'SYSVOL' `
                    -EventIds @() -Message "File '$($f.FullName)' contains a Password/AdminPassword element - unattend/sysprep files often store local admin credentials in Base64 (trivially decoded) or plaintext. Remove and rotate the exposed credential."
            }
        }
    } catch { }
}

#endregion

#region ------------------------------------------------------------- Main Loop

# Functions that take -Computer/-Since but must run against a NON-default host
# list (their own log lives on different servers) rather than $ComputerName.
$script:SpecialHostFunctions = @{
    'Test-SuspiciousPowerShell'    = { $PowerShellHosts }
    'Test-DnsAdminAbuse'           = { $DnsServerHosts }
    'Test-ADFSSuspiciousActivity'  = { $AdfsHosts }
}

# Multi-host correlators: take -AllHostEvents (built from a shared per-host event
# cache) instead of a single -Computer/-Since pair.
$script:MultiHostFunctions = @('Test-LateralMovement', 'Test-PassTheHash')

# File-scan detections: operate on a SYSVOL path snapshot, not event logs at all.
$script:FileScanFunctions = @('Test-GPPCpasswordSysvol', 'Test-UnattendCredentials')

function Get-PerHostDetectionFunctions {
    Get-Command -CommandType Function |
        Where-Object {
            $_.Name -like 'Test-*' -and
            $_.Parameters.ContainsKey('Computer') -and
            $_.Parameters.ContainsKey('Since') -and
            $_.Name -notin $script:SpecialHostFunctions.Keys
        } |
        Sort-Object Name
}

function Invoke-DetectionPass {
    param([datetime]$Since)

    Write-Host "`n=== Pass @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (since $Since) ===" -ForegroundColor Cyan

    $perHostFns = Get-PerHostDetectionFunctions
    Write-Verbose "Running $($perHostFns.Count) per-host detections: $($perHostFns.Name -join ', ')"

    $hostEvents = @{}

    foreach ($c in $ComputerName) {
        Write-Verbose "Scanning $c ..."
        foreach ($fn in $perHostFns) {
            & $fn.Name -Computer $c -Since $Since
        }
        # Shared event cache for the multi-host correlators (lateral movement, PtH)
        # so we don't re-query 4624/4672/4688 redundantly per correlator.
        # Includes 4625 (failed logon) and 4689 (process exit) alongside 4624/4672/4688
        # so Test-LateralMovement (needs 4624/4625/4688/4689 per spec) and other
        # correlators reading this cache all get what they need in one query.
        $hostEvents[$c] = @(Get-SafeWinEvent -ComputerName $c -LogName 'Security' -Id 4624,4625,4672,4688,4689 -StartTime $Since)
    }

    foreach ($name in $script:SpecialHostFunctions.Keys) {
        $hosts = & $script:SpecialHostFunctions[$name]
        foreach ($c in $hosts) {
            & $name -Computer $c -Since $Since
        }
    }

    foreach ($name in $script:MultiHostFunctions) {
        if (Get-Command $name -ErrorAction SilentlyContinue) {
            & $name -AllHostEvents $hostEvents
        }
    }

    if ($SysvolPath) {
        foreach ($name in $script:FileScanFunctions) {
            if (Get-Command $name -ErrorAction SilentlyContinue) {
                & $name -Path $SysvolPath
            }
        }
    }
}

# ---- Entry point --------------------------------------------------------

Write-Host "ADAttackWatch (unified) starting. Targets: $($ComputerName -join ', ')" -ForegroundColor Green
if ($PowerShellHosts) { Write-Host "PowerShell log hosts: $($PowerShellHosts -join ', ')" -ForegroundColor Green }
if ($DnsServerHosts)  { Write-Host "DNS Server log hosts: $($DnsServerHosts -join ', ')" -ForegroundColor Green }
if ($AdfsHosts)       { Write-Host "ADFS log hosts: $($AdfsHosts -join ', ')" -ForegroundColor Green }
if ($SysvolPath)      { Write-Host "SYSVOL scan path: $SysvolPath" -ForegroundColor Green }
Write-Host "Loaded $((Get-PerHostDetectionFunctions).Count) per-host detections + $($script:MultiHostFunctions.Count) multi-host correlators + $($script:FileScanFunctions.Count) file-scan checks." -ForegroundColor Green

$lastRun = (Get-Date).AddMinutes(-$InitialLookbackMinutes)

if ($Once) {
    Invoke-DetectionPass -Since $lastRun
    Write-Host "`nTotal alerts this pass: $($script:AlertBuffer.Count)" -ForegroundColor Cyan
    return
}

while ($true) {
    $passStart = Get-Date
    Invoke-DetectionPass -Since $lastRun
    $lastRun = $passStart
    Start-Sleep -Seconds $PollSeconds
}

#endregion
