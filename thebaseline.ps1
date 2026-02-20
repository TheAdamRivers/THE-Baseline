<#
WINDOWS REBUILD + HARDEN (STATEFUL, ROLE-AWARE, BASELINE FRAMEWORK)
Version 6.0

Phases:
Migration, ConfigCheck, Preflight, Platform, Upgrade, Updates, Validation,
Inventory, BitLocker, Defender, Enforcement, Identity, Legacy, Network,
AppControl, WDAC, ExploitProtection, Privacy, Debloat, Services, Firewall,
AuditPolicy, PowerShellLogging, Health

Config: C:\WinRebuild\config.json
State:  C:\WinRebuild\state.json

Note:
- WDAC: expects WDAC_Audit.bin / WDAC_Enforced.bin in WorkDir if used.
- AppLocker: expects AppLocker.xml in WorkDir.
- Exploit Protection: expects ExploitProtection.xml (e.g., baseline EP file).
- Sysmon: expects Sysmon64.exe and SysmonConfig.xml in WorkDir.
#>

$ScriptVersion            = "6.0"
$ErrorActionPreference    = "Stop"

$WorkDir                  = "C:\WinRebuild"
$LogFile                  = "$WorkDir\rebuild.log"
$StateFile                = "$WorkDir\state.json"
$ConfigFile               = "$WorkDir\config.json"
$InventoryDir             = "$WorkDir\Inventory"

New-Item -ItemType Directory -Force -Path $WorkDir,$InventoryDir | Out-Null

# -------------------------
# DEFAULT CONFIG
# -------------------------
if (!(Test-Path $ConfigFile)) {
@{
    Role                    = "Workstation"         # Workstation|Dev|Lab|Lockdown
    BitLockerMode           = "TPM"                 # Off|TPM|TPMAndPIN
    DebloatPackages         = @(
        "Microsoft.XboxGamingOverlay",
        "Microsoft.BingNews"
    )
    ServicesToDisable       = @(
        "RemoteRegistry"
    )
    RemoteAccess            = "Off"                # Off|On
    RemoteAccessAllowedCIDR = "10.0.0.0/8"
    PrivacyLevel            = "Medium"            # Low|Medium|High
    EnforcementReady        = "No"               # CFA/ASR enforce
    AppControlReady         = "No"               # AppLocker enforce
    WDACReady               = "No"               # WDAC enforce
    PrivacyReady            = "No"               # Apply privacy changes
    UseSysmon               = "No"               # Yes|No
    NoReboot                = "No"               # Yes|No
} | ConvertTo-Json | Set-Content $ConfigFile
}

$Config = Get-Content $ConfigFile | ConvertFrom-Json

# -------------------------
# LOGGING
# -------------------------
function Log {
    param($m)
    $l = "$(Get-Date -Format s) :: $m"
    $l | Tee-Object -FilePath $LogFile -Append
}

# -------------------------
# STATE MGMT
# -------------------------
function Save-State {
    param($k,$v)
    $s = @{}
    if (Test-Path $StateFile) { $s = Get-Content $StateFile | ConvertFrom-Json }
    $s | Add-Member -Force -NotePropertyName $k -NotePropertyValue $v
    $s.ScriptVersion = $ScriptVersion
    $s | ConvertTo-Json | Set-Content $StateFile
}

$State = @{}
if (Test-Path $StateFile) { $State = Get-Content $StateFile | ConvertFrom-Json }

# -------------------------
# MIGRATION
# -------------------------
if ($State.ScriptVersion -and $State.ScriptVersion -ne $ScriptVersion) {
    Log "Migrating state from $($State.ScriptVersion) to $ScriptVersion"
    foreach ($k in @("Identity","AppControl","ExploitProtection","Health","WDAC")) {
        if (-not ($State.PSObject.Properties.Name -contains $k)) { Save-State $k "Pending" }
    }
}
Save-State "ScriptVersion" $ScriptVersion

Log "=== REBUILD START v$ScriptVersion ==="

# -------------------------
# CONFIG VALIDATION (LIGHT SCHEMA)
# -------------------------
if ($State.ConfigCheck -ne "Completed") {
    Log "Validating config..."
    $validRoles          = @("Workstation","Dev","Lab","Lockdown")
    $validBLModes        = @("Off","TPM","TPMAndPIN")
    $validRemote         = @("Off","On")
    $validPrivacy        = @("Low","Medium","High")
    $validYesNo          = @("Yes","No")

    if ($validRoles   -notcontains $Config.Role)             { throw "Config.Role invalid: $($Config.Role)" }
    if ($validBLModes -notcontains $Config.BitLockerMode)    { throw "Config.BitLockerMode invalid: $($Config.BitLockerMode)" }
    if ($validRemote  -notcontains $Config.RemoteAccess)     { throw "Config.RemoteAccess invalid: $($Config.RemoteAccess)" }
    if ($validPrivacy -notcontains $Config.PrivacyLevel)     { throw "Config.PrivacyLevel invalid: $($Config.PrivacyLevel)" }
    if ($validYesNo   -notcontains $Config.EnforcementReady) { throw "Config.EnforcementReady invalid: $($Config.EnforcementReady)" }
    if ($validYesNo   -notcontains $Config.AppControlReady)  { throw "Config.AppControlReady invalid: $($Config.AppControlReady)" }
    if ($validYesNo   -notcontains $Config.PrivacyReady)     { throw "Config.PrivacyReady invalid: $($Config.PrivacyReady)" }
    if ($validYesNo   -notcontains $Config.UseSysmon)        { throw "Config.UseSysmon invalid: $($Config.UseSysmon)" }
    if ($validYesNo   -notcontains $Config.NoReboot)         { throw "Config.NoReboot invalid: $($Config.NoReboot)" }

    Save-State "ConfigCheck" "Completed"
}

# -------------------------
# PREFLIGHT OS CHECK
# -------------------------
$os           = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$ProductName  = $os.ProductName
$AlreadyWin11 = $ProductName -like "*Windows 11*"
Log "Detected OS: $ProductName"

# -------------------------
# PLATFORM SECURITY
# -------------------------
if ($State.Platform -ne "Completed") {
    Log "Checking platform security..."
    $tpm = Get-Tpm
    Log "TPM Present=$($tpm.TpmPresent) Version=$($tpm.SpecVersion)"
    try { $sb = Confirm-SecureBootUEFI } catch { $sb = $false }
    Log "SecureBoot=$sb"
    Save-State "Platform" "Completed"
}

# -------------------------
# TLS 1.2+
# -------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -------------------------
# DOWNLOAD WINDOWS INSTALLATION ASSISTANT
# -------------------------
$AssistantUrl = "https://go.microsoft.com/fwlink/?linkid=2171764"
$AssistantExe = "$WorkDir\Win11Upgrade.exe"

if (-not $AlreadyWin11 -and $State.Upgrade -ne "Completed") {
    if (!(Test-Path $AssistantExe)) {
        Log "Downloading Windows Installation Assistant..."
        $tries = 0
        do {
            Invoke-WebRequest -Uri $AssistantUrl -OutFile $AssistantExe -UseBasicParsing
            $tries++
        } while ((Get-Item $AssistantExe).Length -lt 5MB -and $tries -lt 3)
    }

    if (Test-Path $AssistantExe) {
        $sig = Get-AuthenticodeSignature $AssistantExe
        if ($sig.Status -ne "Valid") { throw "Win11Upgrade.exe signature invalid: $($sig.Status)" }
        Log "Win11Upgrade.exe signature valid: $($sig.SignerCertificate.Subject)"
    }

    Log "Starting in-place upgrade..."
    Start-Process $AssistantExe -ArgumentList "/quietinstall /skipeula /auto upgrade /norestartui" -Wait
    Save-State "Upgrade" "Completed"
}

# -------------------------
# REBOOT CHECK (POST-UPGRADE)
# -------------------------
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    Log "Reboot required after upgrade/servicing."
    if ($Config.NoReboot -ne "Yes") {
        shutdown /r /t 15
        exit
    }
}

# -------------------------
# WINDOWS UPDATE
# -------------------------
if ($State.Updates -ne "Completed") {
    Log "Installing Windows updates..."
    Install-PackageProvider NuGet -Force
    Install-Module PSWindowsUpdate -Force
    Import-Module PSWindowsUpdate
    Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot
    Save-State "Updates" "Completed"
}

# -------------------------
# REBOOT CHECK (POST-UPDATES)
# -------------------------
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    Log "Reboot required after updates."
    if ($Config.NoReboot -ne "Yes") {
        shutdown /r /t 15
        exit
    }
}

# -------------------------
# VALIDATION (SFC/DISM)
# -------------------------
if ($State.Validation -ne "Completed") {
    Log "Running SFC..."
    sfc /scannow | Out-Null
    Log "Running DISM..."
    DISM /Online /Cleanup-Image /RestoreHealth | Out-Null
    Save-State "Validation" "Completed"
}

# -------------------------
# INVENTORY SNAPSHOT
# -------------------------
if ($State.Inventory -ne "Completed") {
    Log "Collecting inventory..."
    Get-ComputerInfo | ConvertTo-Json | Set-Content "$InventoryDir\system.json"
    Get-Service | ConvertTo-Json | Set-Content "$InventoryDir\services.json"
    Get-ScheduledTask | ConvertTo-Json | Set-Content "$InventoryDir\tasks.json"

    Get-NetTCPConnection | Select LocalAddress,LocalPort,OwningProcess |
      ForEach-Object {
        $_ | Add-Member ProcessName (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -Force
        $_
      } | ConvertTo-Json | Set-Content "$InventoryDir\ports.json"

    Get-LocalUser | ConvertTo-Json | Set-Content "$InventoryDir\users.json"
    Get-Package | ConvertTo-Json | Set-Content "$InventoryDir\programs.json"
    Get-WmiObject Win32_SystemDriver | ConvertTo-Json | Set-Content "$InventoryDir\drivers.json"

    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
      Select-Object FullName,Name,LastWriteTime |
      ConvertTo-Json | Set-Content "$InventoryDir\autoruns.json"

    Save-State "Inventory" "Completed"
}

# -------------------------
# BITLOCKER
# -------------------------
if ($State.BitLocker -ne "Completed") {
    Log "Configuring BitLocker..."
    if ($Config.BitLockerMode -ne "Off") {
        $t = Get-Tpm
        if ($t.TpmPresent) {
            Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "Fixed" } | ForEach-Object {
                if ($_.ProtectionStatus -eq "Off") {
                    if ($Config.BitLockerMode -eq "TPMAndPIN") {
                        Enable-BitLocker -MountPoint $_.MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
                        Add-BitLockerKeyProtector -MountPoint $_.MountPoint -TPMandPin
                        Log "BitLocker enabled with TPM+PIN on $($_.MountPoint)"
                    } else {
                        Enable-BitLocker -MountPoint $_.MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
                        Log "BitLocker enabled with TPM on $($_.MountPoint)"
                    }
                }
            }
        } else {
            Log "No TPM present; skipping BitLocker"
        }
    }
    Save-State "BitLocker" "Completed"
}

# -------------------------
# DEFENDER BASELINE (AUDIT)
# -------------------------
if ($State.Defender -ne "Completed") {
    Log "Applying Defender baseline (audit)..."
    Set-MpPreference -PUAProtection Enabled
    Set-MpPreference -EnableNetworkProtection Enabled
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples

    Set-MpPreference -EnableControlledFolderAccess AuditMode
    Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Users\*\Documents","C:\Users\*\Pictures"

    $ASR = @(
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
        "3B576869-A4EC-4529-8536-B80A7769E899",
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
        "26190899-1602-49e8-8b27-eb1d0a1ce869"
    )
    foreach ($r in $ASR) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $r -AttackSurfaceReductionRules_Actions AuditMode
    }
    Save-State "Defender" "Completed"
}

# -------------------------
# DEFENDER ENFORCEMENT (GUARDED)
# -------------------------
if ($Config.EnforcementReady -eq "Yes" -and $State.Enforcement -ne "Completed") {
    Log "Enabling CFA enforcement..."
    Set-MpPreference -EnableControlledFolderAccess Enabled
    Save-State "Enforcement" "Completed"
}

# -------------------------
# CREDENTIAL HARDENING (LSASS/WDIGEST)
# -------------------------
if ($State.Creds -ne "Completed") {
    Log "Applying credential protections..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
    Save-State "Creds" "Completed"
}

# -------------------------
# IDENTITY PHASE
# -------------------------
if ($State.Identity -ne "Completed") {
    Log "Identity hardening..."
    if ($Config.Role -ne "Lab") {
        $admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if ($admin) {
            Rename-LocalUser -Name "Administrator" -NewName "Admin_Disabled" -ErrorAction SilentlyContinue
            Disable-LocalUser "Admin_Disabled" -ErrorAction SilentlyContinue
        }
        if (-not (Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -ne "Admin_Disabled" })) {
            New-LocalUser "standarduser" -NoPassword
            Log "Created local standarduser (no password) – set credentials manually."
        }

        secedit /export /cfg "$WorkDir\secpol.cfg" | Out-Null
        (Get-Content "$WorkDir\secpol.cfg") -replace "MinimumPasswordLength = .*","MinimumPasswordLength = 14" |
            Set-Content "$WorkDir\secpol.cfg"
        secedit /configure /db secedit.sdb /cfg "$WorkDir\secpol.cfg" /areas SECURITYPOLICY | Out-Null
    }
    Save-State "Identity" "Completed"
}

# -------------------------
# LEGACY PROTOCOLS
# -------------------------
if ($State.Legacy -ne "Completed") {
    Log "Disabling legacy protocols..."
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableLLMNR /t REG_DWORD /d 0 /f | Out-Null

    Get-NetAdapter | ForEach-Object {
        try {
            Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "NetBIOS over TCP/IP" -DisplayValue "Disabled"
        } catch {
            Log "NetBIOS disable failed on adapter $($_.Name)"
        }
    }
    Save-State "Legacy" "Completed"
}

# -------------------------
# NETWORK BASELINE
# -------------------------
if ($State.Network -ne "Completed") {
    Log "Applying network baseline..."
    if ($Config.RemoteAccess -eq "Off") {
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop","Windows Remote Management","Remote Assistance"
        Stop-Service TermService,WinRM -ErrorAction SilentlyContinue
        Set-Service TermService,WinRM -StartupType Disabled -ErrorAction SilentlyContinue
    } else {
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop","Windows Remote Management"
        Set-NetFirewallRule -DisplayGroup "Remote Desktop" -RemoteAddress $Config.RemoteAccessAllowedCIDR
    }
    Save-State "Network" "Completed"
}

# -------------------------
# APP CONTROL (APPLOCKER)
# -------------------------
if ($State.AppControl -ne "Completed") {
    $policy = "$WorkDir\AppLocker.xml"
    if (Test-Path $policy) {
        if ($Config.AppControlReady -eq "No") {
            Log "Importing AppLocker AUDIT policy..."
            Set-AppLockerPolicy -XmlPolicy $policy -Merge
            Save-State "AppControl" "Audit"
        } else {
            Log "Importing AppLocker ENFORCE policy..."
            Set-AppLockerPolicy -XmlPolicy $policy -Enforce
            Save-State "AppControl" "Enforced"
        }
    } else {
        Log "No AppLocker policy found at $policy"
        Save-State "AppControl" "Skipped"
    }
}

# -------------------------
# WDAC (OPTIONAL, DUAL-TRACK WITH APPLOCKER)
# -------------------------
if ($State.WDAC -ne "Completed") {
    Log "WDAC phase..."
    $wdacAudit    = "$WorkDir\WDAC_Audit.bin"
    $wdacEnforced = "$WorkDir\WDAC_Enforced.bin"

    if (Test-Path $wdacAudit -or Test-Path $wdacEnforced) {
        if ($Config.WDACReady -eq "No") {
            if (Test-Path $wdacAudit) {
                Log "Applying WDAC AUDIT policy (WDAC_Audit.bin)"
                # CI policies typically go in C:\Windows\System32\CodeIntegrity
                Copy-Item $wdacAudit "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b" -Force
                Save-State "WDAC" "Audit"
            } else {
                Log "WDACReady=No but WDAC_Audit.bin not found; skipping."
                Save-State "WDAC" "Skipped"
            }
        } else {
            if (Test-Path $wdacEnforced) {
                Log "Applying WDAC ENFORCED policy (WDAC_Enforced.bin)"
                Copy-Item $wdacEnforced "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b" -Force
                Save-State "WDAC" "Enforced"
            } else {
                Log "WDACReady=Yes but WDAC_Enforced.bin not found; skipping."
                Save-State "WDAC" "Skipped"
            }
        }
    } else {
        Log "No WDAC policy binaries found in $WorkDir"
        Save-State "WDAC" "Skipped"
    }
}

# -------------------------
# EXPLOIT PROTECTION
# -------------------------
if ($State.ExploitProtection -ne "Completed") {
    $xml = "$WorkDir\ExploitProtection.xml"
    if (Test-Path $xml) {
        Set-ProcessMitigation -PolicyFilePath $xml
        Log "Imported Exploit Protection policy from $xml"
    } else {
        Log "No ExploitProtection XML found at $xml"
    }
    Save-State "ExploitProtection" "Completed"
}

# -------------------------
# SYSMON (OPTIONAL)
# -------------------------
if ($Config.UseSysmon -eq "Yes" -and $State.Sysmon -ne "Completed") {
    $sysmon = "$WorkDir\Sysmon64.exe"
    $cfg    = "$WorkDir\SysmonConfig.xml"
    if (Test-Path $sysmon -and Test-Path $cfg) {
        Start-Process $sysmon -ArgumentList "-accepteula -i `"$cfg`"" -Wait
        Log "Sysmon installed with config $cfg"
    } else {
        Log "Sysmon requested but Sysmon64.exe or SysmonConfig.xml not found in $WorkDir"
    }
    Save-State "Sysmon" "Completed"
}

# -------------------------
# PRIVACY
# -------------------------
if ($Config.PrivacyReady -eq "Yes" -and $State.Privacy -ne "Completed") {
    Log "Applying privacy level: $($Config.PrivacyLevel)"
    switch ($Config.PrivacyLevel) {
        "Low"    { }
        "Medium" {
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 1 /f | Out-Null
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
        }
        "High" {
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f | Out-Null
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerFeatures /t REG_DWORD /d 1 /f | Out-Null
        }
    }
    Save-State "Privacy" "Completed"
}

# -------------------------
# DEBLOAT
# -------------------------
if ($State.Debloat -ne "Completed") {
    Log "Debloating packages from config..."
    foreach ($pkg in $Config.DebloatPackages) {
        Get-AppxPackage $pkg -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
    }
    Save-State "Debloat" "Completed"
}

# -------------------------
# SERVICES
# -------------------------
if ($State.Services -ne "Completed") {
    Log "Disabling configured services..."
    foreach ($svc in $Config.ServicesToDisable) {
        Stop-Service $svc -ErrorAction SilentlyContinue
        Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
    Save-State "Services" "Completed"
}

# -------------------------
# FIREWALL
# -------------------------
if ($State.Firewall -ne "Completed") {
    Log "Configuring firewall profiles..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$WorkDir\firewall.log"
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
    Save-State "Firewall" "Completed"
}

# -------------------------
# AUDIT POLICY
# -------------------------
if ($State.AuditPolicy -ne "Completed") {
    Log "Setting audit policy..."
    auditpol /set /subcategory:"Logon","Logoff","Account Lockout","Process Creation","Policy Change","Privilege Use","Object Access" /success:enable /failure:enable | Out-Null
    wevtutil sl Security    /ms:196608 | Out-Null
    wevtutil sl System      /ms:65536  | Out-Null
    wevtutil sl Application /ms:65536  | Out-Null
    Save-State "AuditPolicy" "Completed"
}

# -------------------------
# POWERSHELL LOGGING
# -------------------------
if ($State.Logging -ne "Completed") {
    Log "Enabling PowerShell logging..."
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
    Save-State "Logging" "Completed"
}

# -------------------------
# HEALTH SUMMARY (JSON + CSV, ASR DETAIL)
# -------------------------
if ($State.Health -ne "Completed") {
    Log "Writing health summary..."

    $mp         = Get-MpPreference
    $bl         = Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus
    $lsa        = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    $dnsClient  = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
    $rdpSvc     = Get-Service TermService -ErrorAction SilentlyContinue
    $winrmSvc   = Get-Service WinRM -ErrorAction SilentlyContinue

    # Build ASR detail: GUID -> action
    $asrDetail = @()
    if ($mp.AttackSurfaceReductionRules_Ids -and $mp.AttackSurfaceReductionRules_Actions) {
        for ($i=0; $i -lt $mp.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $asrDetail += [pscustomobject]@{
                Id     = $mp.AttackSurfaceReductionRules_Ids[$i]
                Action = $mp.AttackSurfaceReductionRules_Actions[$i]
            }
        }
    }

    $summary = [ordered]@{
        BitLocker        = $bl
        CFA              = $mp.EnableControlledFolderAccess
        ASR              = $asrDetail
        LSASS_PPL        = $lsa.RunAsPPL
        LLMNR            = $dnsClient.EnableLLMNR
        RDP              = $rdpSvc.Status
        WinRM            = $winrmSvc.Status
        Role             = $Config.Role
        BitLockerMode    = $Config.BitLockerMode
        RemoteAccess     = $Config.RemoteAccess
        PrivacyLevel     = $Config.PrivacyLevel
        AppControlState  = $State.AppControl
        WDACState        = $State.WDAC
    }

    $summary | ConvertTo-Json | Set-Content "$WorkDir\HealthSummary.json"

    # SIEM-friendly CSV line (flattened top-level)
    $csv = [pscustomobject]@{
        Timestamp       = Get-Date -Format s
        Role            = $Config.Role
        BitLockerMode   = $Config.BitLockerMode
        BitLockerAnyOn  = ($bl | Where-Object { $_.ProtectionStatus -eq 1 }).Count -gt 0
        CFA             = $mp.EnableControlledFolderAccess
        LSASS_PPL       = $lsa.RunAsPPL
        LLMNR           = $dnsClient.EnableLLMNR
        RDP             = $rdpSvc.Status
        WinRM           = $winrmSvc.Status
        AppControlState = $State.AppControl
        WDACState       = $State.WDAC
        PrivacyLevel    = $Config.PrivacyLevel
    }
    $csv | Export-Csv "$WorkDir\HealthSummary.csv" -NoTypeInformation -Append

    Save-State "Health" "Completed"
}

Log "=== REBUILD + HARDEN COMPLETE v$ScriptVersion ==="

if ($Config.NoReboot -ne "Yes") {
    shutdown /r /t 20
}
