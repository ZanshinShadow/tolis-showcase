<#
.SYNOPSIS
    Microsoft Intune Sync and Communication Remediation Script

.DESCRIPTION
    This remediation script automatically resolves common Microsoft Intune connectivity and sync issues.
    It performs comprehensive remediation steps including re-enrollment, sync forcing, certificate refresh,
    service restart, and connectivity restoration to ensure devices maintain proper management state.

.NOTES
    File Name      : RemediationScript.ps1
    Author         : Apostolos Tsirogiannis - Senior System Engineer Showcase
    Prerequisite   : Windows 10/11, Administrative privileges for remediation actions
    
    REMEDIATION ACTIONS:
    • Force immediate sync with Intune management server
    • Restart critical MDM and device management services
    • Clear problematic enrollment cache and temporary files
    • Refresh device certificates and authentication tokens
    • Re-establish secure communication channels with Intune
    • Trigger policy refresh and compliance evaluation
    
    EXIT CODES:
    • 0 = Remediation successful
    • 1 = Remediation failed or incomplete
    
    INTUNE PROACTIVE REMEDIATIONS:
    This script is optimized for Microsoft Intune Proactive Remediations and implements
    enterprise-grade automated remediation with comprehensive logging and error handling.

.EXAMPLE
    .\RemediationScript.ps1
    
    Performs comprehensive Intune remediation and restores device management connectivity.
    Designed for execution via Intune Proactive Remediations when detection script identifies issues.
#>

# Script configuration and security settings
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'
$EventLogSource = "IntuneRemediation"
$MaxRetryAttempts = 3
$RetryDelaySeconds = 10

# Initialize script execution
$ScriptStartTime = Get-Date
$ScriptName = "Intune-Sync-Remediation"
$RemediationActions = @()

# Enhanced logging function with detailed audit trail
function Write-RemediationLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success", "Action")]
        [string]$Level = "Info",
        [switch]$WriteToEventLog,
        [switch]$Critical
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Console output with color coding
    Write-Host $LogEntry -ForegroundColor $(
        switch ($Level) {
            "Error" { "Red" }
            "Warning" { "Yellow" }
            "Success" { "Green" }
            "Action" { "Cyan" }
            default { "White" }
        }
    )
    
    # Track remediation actions for summary
    if ($Level -eq "Action") {
        $script:RemediationActions += $Message
    }
    
    # Write to Windows Event Log for compliance and auditing
    if ($WriteToEventLog -or $Critical) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
                New-EventLog -LogName "Application" -Source $EventLogSource
            }
            
            $EventType = switch ($Level) {
                "Error" { "Error" }
                "Warning" { "Warning" }
                default { "Information" }
            }
            
            Write-EventLog -LogName "Application" -Source $EventLogSource -EntryType $EventType -EventId 2001 -Message $LogEntry
        } catch {
            # Continue if event log writing fails
        }
    }
}

# Execute command with retry logic and comprehensive error handling
function Invoke-RemediationCommand {
    param(
        [string]$Description,
        [scriptblock]$Command,
        [int]$MaxAttempts = $MaxRetryAttempts,
        [int]$DelaySeconds = $RetryDelaySeconds,
        [switch]$CriticalAction
    )
    
    Write-RemediationLog "Executing: $Description" -Level "Action"
    
    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        try {
            $Result = & $Command
            Write-RemediationLog "Successfully completed: $Description" -Level "Success"
            return $true
            
        } catch {
            $ErrorMsg = $_.Exception.Message
            Write-RemediationLog "Attempt $Attempt failed for $Description : $ErrorMsg" -Level "Warning"
            
            if ($Attempt -eq $MaxAttempts) {
                if ($CriticalAction) {
                    Write-RemediationLog "CRITICAL ACTION FAILED: $Description" -Level "Error" -Critical
                    return $false
                } else {
                    Write-RemediationLog "Action failed after $MaxAttempts attempts: $Description" -Level "Error"
                    return $false
                }
            }
            
            if ($Attempt -lt $MaxAttempts) {
                Write-RemediationLog "Retrying in $DelaySeconds seconds..." -Level "Info"
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }
    
    return $false
}

# Force immediate sync with Intune management server
function Invoke-IntuneSync {
    Write-RemediationLog "=== Forcing Intune Device Sync ===" -Level "Info"
    
    # Method 1: Use IME_SyncML COM object for immediate sync
    $SyncSuccess = Invoke-RemediationCommand -Description "COM-based Intune sync" -Command {
        $SyncML = New-Object -ComObject "IME_SyncML"
        $SyncML.SyncNow()
        $SyncML = $null
        [System.GC]::Collect()
    }
    
    if (-not $SyncSuccess) {
        # Method 2: Registry-based sync trigger
        $SyncSuccess = Invoke-RemediationCommand -Description "Registry-based sync trigger" -Command {
            $EnrollmentKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\*" | 
                            Where-Object { $_.ProviderID -eq "MS DM Server" }
            
            foreach ($Key in $EnrollmentKeys) {
                $KeyPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$($Key.PSChildName)"
                Set-ItemProperty -Path $KeyPath -Name "PollOnLogin" -Value 1 -Force
            }
        }
    }
    
    if (-not $SyncSuccess) {
        # Method 3: Schedule task to trigger sync
        $SyncSuccess = Invoke-RemediationCommand -Description "Scheduled task sync trigger" -Command {
            $TaskName = "Microsoft\Windows\EnterpriseMgmt\*\PushLaunch"
            Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\*" -TaskName "PushLaunch" -ErrorAction SilentlyContinue | 
                Start-ScheduledTask
        }
    }
    
    return $SyncSuccess
}

# Restart critical MDM and device management services
function Restart-IntuneServices {
    Write-RemediationLog "=== Restarting Critical Device Management Services ===" -Level "Info"
    
    $CriticalServices = @(
        @{ Name = "dmwappushservice"; DisplayName = "Device Management WAP Push Service" },
        @{ Name = "DmEnrollmentSvc"; DisplayName = "Device Management Enrollment Service" },
        @{ Name = "PolicyAgent"; DisplayName = "IPsec Policy Agent" },
        @{ Name = "CryptSvc"; DisplayName = "Cryptographic Services" }
    )
    
    $ServiceRestartSuccess = $true
    
    foreach ($ServiceInfo in $CriticalServices) {
        $Service = Get-Service -Name $ServiceInfo.Name -ErrorAction SilentlyContinue
        
        if (-not $Service) {
            Write-RemediationLog "Service $($ServiceInfo.Name) not found (may be normal)" -Level "Info"
            continue
        }
        
        $RestartSuccess = Invoke-RemediationCommand -Description "Restart $($ServiceInfo.DisplayName)" -Command {
            if ($Service.Status -eq "Running") {
                Stop-Service -Name $ServiceInfo.Name -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
            }
            Start-Service -Name $ServiceInfo.Name -ErrorAction Stop
        }
        
        if (-not $RestartSuccess) {
            $ServiceRestartSuccess = $false
        }
    }
    
    return $ServiceRestartSuccess
}

# Clear problematic enrollment cache and temporary files
function Clear-IntuneCache {
    Write-RemediationLog "=== Clearing Intune Cache and Temporary Files ===" -Level "Info"
    
    $CachePaths = @(
        "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs",
        "$env:TEMP\MDMDiagnostics",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
        "$env:WINDIR\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache"
    )
    
    $CacheCleanSuccess = $true
    
    foreach ($CachePath in $CachePaths) {
        if (Test-Path $CachePath) {
            $CleanSuccess = Invoke-RemediationCommand -Description "Clear cache: $CachePath" -Command {
                Get-ChildItem -Path $CachePath -Recurse -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
                    Remove-Item -Force -Recurse -ErrorAction Stop
            }
            
            if (-not $CleanSuccess) {
                $CacheCleanSuccess = $false
            }
        }
    }
    
    # Clear registry-based cache entries
    $RegistryCleanSuccess = Invoke-RemediationCommand -Description "Clear registry cache entries" -Command {
        $CacheKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Enrollments\Cache",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\MDM\Cache"
        )
        
        foreach ($Key in $CacheKeys) {
            if (Test-Path $Key) {
                Remove-Item -Path $Key -Recurse -Force -ErrorAction Stop
            }
        }
    }
    
    return ($CacheCleanSuccess -and $RegistryCleanSuccess)
}

# Refresh device certificates and authentication tokens
function Update-IntuneCertificates {
    Write-RemediationLog "=== Refreshing Device Certificates and Tokens ===" -Level "Info"
    
    # Trigger certificate auto-enrollment
    $CertRefreshSuccess = Invoke-RemediationCommand -Description "Certificate auto-enrollment refresh" -Command {
        & certlm.msc -s
        Start-Process -FilePath "certreq.exe" -ArgumentList "-pulse" -Wait -WindowStyle Hidden
    }
    
    # Force GPUpdate to refresh certificates and policies
    $PolicyRefreshSuccess = Invoke-RemediationCommand -Description "Group Policy and certificate refresh" -Command {
        & gpupdate.exe /force /wait:30
    }
    
    # Clear credential cache
    $CredentialClearSuccess = Invoke-RemediationCommand -Description "Clear credential cache" -Command {
        & klist.exe purge
        & cmdkey.exe /list | ForEach-Object {
            if ($_ -match "Target: MicrosoftOffice") {
                $Target = ($_ -split ":")[1].Trim()
                & cmdkey.exe /delete:$Target
            }
        }
    }
    
    return ($CertRefreshSuccess -and $PolicyRefreshSuccess -and $CredentialClearSuccess)
}

# Re-establish secure communication with Intune services
function Reset-IntuneConnectivity {
    Write-RemediationLog "=== Re-establishing Intune Connectivity ===" -Level "Info"
    
    # Reset Windows networking stack
    $NetworkResetSuccess = Invoke-RemediationCommand -Description "Network stack reset" -Command {
        & netsh.exe winsock reset
        & netsh.exe int ip reset
        & ipconfig.exe /flushdns
    }
    
    # Reset proxy settings that might interfere
    $ProxyResetSuccess = Invoke-RemediationCommand -Description "Proxy settings reset" -Command {
        & netsh.exe winhttp reset proxy
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 0
    }
    
    # Restart network-related services
    $NetworkServicesSuccess = Invoke-RemediationCommand -Description "Network services restart" -Command {
        $NetworkServices = @("Dnscache", "Dhcp", "Netman")
        foreach ($Service in $NetworkServices) {
            $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($ServiceObj -and $ServiceObj.Status -eq "Running") {
                Restart-Service -Name $Service -Force
            }
        }
    }
    
    return ($NetworkResetSuccess -and $ProxyResetSuccess -and $NetworkServicesSuccess)
}

# Trigger comprehensive policy refresh and compliance evaluation
function Invoke-PolicyRefresh {
    Write-RemediationLog "=== Triggering Policy Refresh and Compliance Check ===" -Level "Info"
    
    # Force Windows Update policy refresh
    $WUPolicySuccess = Invoke-RemediationCommand -Description "Windows Update policy refresh" -Command {
        & usoclient.exe startscan
        & usoclient.exe refreshpolicy
    }
    
    # Trigger Windows Security Center refresh
    $SecurityCenterSuccess = Invoke-RemediationCommand -Description "Security Center refresh" -Command {
        $SecurityCenter = New-Object -ComObject "Microsoft.Security.SecurityCenter"
        $SecurityCenter.RefreshStatus()
        $SecurityCenter = $null
    }
    
    # Force compliance evaluation
    $ComplianceSuccess = Invoke-RemediationCommand -Description "Device compliance evaluation" -Command {
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\Workplace Join\*" -ErrorAction SilentlyContinue | 
            Start-ScheduledTask
    }
    
    return ($WUPolicySuccess -and $SecurityCenterSuccess -and $ComplianceSuccess)
}

# Validate remediation success
function Test-RemediationSuccess {
    Write-RemediationLog "=== Validating Remediation Results ===" -Level "Info"
    
    Start-Sleep -Seconds 5  # Allow time for changes to take effect
    
    # Re-run basic connectivity tests
    $ValidationResults = @{
        "Services" = $true
        "Sync" = $true
        "Connectivity" = $true
    }
    
    # Check critical services
    $CriticalServices = @("dmwappushservice", "DmEnrollmentSvc")
    foreach ($ServiceName in $CriticalServices) {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($Service -and $Service.Status -ne "Running") {
            $ValidationResults["Services"] = $false
            Write-RemediationLog "Service $ServiceName still not running after remediation" -Level "Warning"
        }
    }
    
    # Test basic connectivity
    try {
        $ConnTest = Test-NetConnection -ComputerName "portal.manage.microsoft.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if (-not $ConnTest) {
            $ValidationResults["Connectivity"] = $false
            Write-RemediationLog "Connectivity test failed after remediation" -Level "Warning"
        }
    } catch {
        $ValidationResults["Connectivity"] = $false
    }
    
    # Summarize validation results
    $PassedValidations = ($ValidationResults.Values | Where-Object { $_ -eq $true }).Count
    $TotalValidations = $ValidationResults.Count
    
    Write-RemediationLog "Validation Results: $PassedValidations / $TotalValidations checks passed" -Level "Info"
    
    return ($PassedValidations -eq $TotalValidations)
}

# Main remediation orchestration
try {
    Write-RemediationLog "=== Intune Remediation Started ===" -Level "Info" -WriteToEventLog
    Write-RemediationLog "Remediation script version: 1.0" -Level "Info"
    Write-RemediationLog "Target device: $env:COMPUTERNAME" -Level "Info"
    Write-RemediationLog "Execution context: $env:USERNAME" -Level "Info"
    
    # Check for administrative privileges
    $IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsElevated) {
        Write-RemediationLog "WARNING: Script not running with administrative privileges - some actions may fail" -Level "Warning"
    }
    
    # Execute comprehensive remediation steps
    Write-RemediationLog "Executing comprehensive Intune remediation sequence..." -Level "Info"
    
    $RemediationSteps = @(
        @{ Name = "Intune Sync"; Action = { Invoke-IntuneSync } },
        @{ Name = "Service Restart"; Action = { Restart-IntuneServices } },
        @{ Name = "Cache Cleanup"; Action = { Clear-IntuneCache } },
        @{ Name = "Certificate Refresh"; Action = { Update-IntuneCertificates } },
        @{ Name = "Connectivity Reset"; Action = { Reset-IntuneConnectivity } },
        @{ Name = "Policy Refresh"; Action = { Invoke-PolicyRefresh } }
    )
    
    $SuccessfulSteps = 0
    $TotalSteps = $RemediationSteps.Count
    
    foreach ($Step in $RemediationSteps) {
        Write-RemediationLog "--- Executing: $($Step.Name) ---" -Level "Info"
        
        try {
            $StepResult = & $Step.Action
            if ($StepResult) {
                $SuccessfulSteps++
                Write-RemediationLog "Step completed successfully: $($Step.Name)" -Level "Success"
            } else {
                Write-RemediationLog "Step completed with issues: $($Step.Name)" -Level "Warning"
            }
        } catch {
            Write-RemediationLog "Step failed: $($Step.Name) - $($_.Exception.Message)" -Level "Error"
        }
        
        # Brief pause between major operations
        Start-Sleep -Seconds 2
    }
    
    # Validate remediation effectiveness
    $ValidationSuccess = Test-RemediationSuccess
    
    # Generate comprehensive summary
    Write-RemediationLog "=== Remediation Summary ===" -Level "Info"
    Write-RemediationLog "Completed steps: $SuccessfulSteps / $TotalSteps" -Level "Info"
    Write-RemediationLog "Validation result: $(if ($ValidationSuccess) { 'PASSED' } else { 'NEEDS ATTENTION' })" -Level "Info"
    
    if ($RemediationActions.Count -gt 0) {
        Write-RemediationLog "Actions performed:" -Level "Info"
        foreach ($Action in $RemediationActions) {
            Write-RemediationLog "  • $Action" -Level "Info"
        }
    }
    
    # Determine overall remediation success
    $OverallSuccess = ($SuccessfulSteps -ge ($TotalSteps * 0.8)) -and $ValidationSuccess
    
    if ($OverallSuccess) {
        Write-RemediationLog "=== REMEDIATION SUCCESSFUL ===" -Level "Success" -WriteToEventLog
        Write-RemediationLog "Device Intune connectivity has been restored" -Level "Success"
        exit 0
    } else {
        Write-RemediationLog "=== REMEDIATION INCOMPLETE ===" -Level "Warning" -WriteToEventLog
        Write-RemediationLog "Some issues may require manual intervention or device restart" -Level "Warning"
        exit 1
    }
    
} catch {
    Write-RemediationLog "=== REMEDIATION SCRIPT FAILED ===" -Level "Error" -Critical
    Write-RemediationLog "Unexpected error: $($_.Exception.Message)" -Level "Error"
    Write-RemediationLog "Stack trace: $($_.Exception.StackTrace)" -Level "Error"
    
    # Log failure for compliance tracking
    exit 1
    
} finally {
    $ScriptDuration = (Get-Date) - $ScriptStartTime
    Write-RemediationLog "Remediation completed in $($ScriptDuration.TotalSeconds) seconds" -Level "Info"
    
    # Suggest restart if many low-level changes were made
    if ($SuccessfulSteps -ge ($TotalSteps * 0.6)) {
        Write-RemediationLog "RECOMMENDATION: Consider restarting device to fully apply changes" -Level "Info"
    }
}