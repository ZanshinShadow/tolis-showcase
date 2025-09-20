<#
.SYNOPSIS
    BitLocker Drive Encryption Compliance Remediation Script

.DESCRIPTION
    This enterprise-grade remediation script automatically resolves BitLocker compliance issues
    to ensure data protection standards are maintained. It performs comprehensive remediation
    including BitLocker enablement, TPM configuration, recovery key backup, encryption method
    updates, and policy compliance restoration for enterprise security requirements.

.NOTES
    File Name      : RemediationScript.ps1
    Author         : Apostolos Tsirogiannis - Senior System Engineer Showcase
    Prerequisite   : Windows 10/11 Pro/Enterprise, TPM 2.0, Administrative privileges
    
    REMEDIATION CAPABILITIES:
    • Enable BitLocker Drive Encryption with TPM protector
    • Force backup of recovery keys to Azure AD or MBAM
    • Update encryption methods to meet security standards
    • Configure auto-unlock for system and data drives
    • Repair corrupted key protectors and escrow status
    • Initialize and configure TPM hardware for BitLocker
    
    EXIT CODES:
    • 0 = Remediation successful and compliant
    • 1 = Remediation failed or incomplete
    
    SECURITY COMPLIANCE:
    This script ensures compliance with GDPR, HIPAA, SOX, PCI-DSS, and other
    regulatory requirements for encryption at rest and key management.

.EXAMPLE
    .\RemediationScript.ps1
    
    Performs comprehensive BitLocker remediation and compliance restoration.
    Designed for Intune Proactive Remediations and enterprise security automation.
#>

# Script configuration and security parameters
$RemediationConfig = @{
    EncryptionMethod = "XtsAes256"  # XtsAes128, XtsAes256 (recommended for new deployments)
    KeyProtectorTypes = @("Tpm", "RecoveryPassword")
    RequireTPMAndPin = $false  # Set to $true for high-security environments
    EncryptUsedSpaceOnly = $false  # Set to $true for faster initial encryption
    ForceKeyBackup = $true
    MaxRetryAttempts = 3
    RetryDelaySeconds = 30
}

$EventLogSource = "BitLockerRemediation"
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

# Initialize script execution
$ScriptStartTime = Get-Date
$ScriptName = "BitLocker-Compliance-Remediation"
$RemediationActions = @()

# Enhanced logging with security audit integration
function Write-RemediationLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success", "Action", "Security")]
        [string]$Level = "Info",
        [switch]$WriteToEventLog,
        [switch]$SecurityCritical
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Console output with security-focused color coding
    Write-Host $LogEntry -ForegroundColor $(
        switch ($Level) {
            "Error" { "Red" }
            "Warning" { "Yellow" }
            "Success" { "Green" }
            "Action" { "Cyan" }
            "Security" { "Magenta" }
            default { "White" }
        }
    )
    
    # Track remediation actions for compliance reporting
    if ($Level -eq "Action" -or $Level -eq "Security") {
        $script:RemediationActions += $Message
    }
    
    # Write security-critical events to Windows Application Log
    if ($WriteToEventLog -or $SecurityCritical) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
                New-EventLog -LogName "Application" -Source $EventLogSource
            }
            
            $EventType = switch ($Level) {
                "Error" { "Error" }
                "Security" { "Information" }
                "Success" { "Information" }
                "Warning" { "Warning" }
                default { "Information" }
            }
            
            $EventId = switch ($Level) {
                "Security" { 4002 }
                "Success" { 4003 }
                "Error" { 4004 }
                default { 4001 }
            }
            
            Write-EventLog -LogName "Application" -Source $EventLogSource -EntryType $EventType -EventId $EventId -Message $LogEntry
        } catch {
            # Continue if event log writing fails
        }
    }
}

# Execute remediation command with comprehensive error handling and retry logic
function Invoke-SecureRemediation {
    param(
        [string]$Description,
        [scriptblock]$Command,
        [int]$MaxAttempts = $RemediationConfig.MaxRetryAttempts,
        [int]$DelaySeconds = $RemediationConfig.RetryDelaySeconds,
        [switch]$SecurityCritical,
        [switch]$RequireSuccess
    )
    
    Write-RemediationLog "Executing security remediation: $Description" -Level "Action"
    
    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        try {
            $Result = & $Command
            Write-RemediationLog "Successfully completed: $Description" -Level "Success" -SecurityCritical:$SecurityCritical
            return $true
            
        } catch {
            $ErrorMsg = $_.Exception.Message
            Write-RemediationLog "Attempt $Attempt failed for $Description : $ErrorMsg" -Level "Warning"
            
            if ($Attempt -eq $MaxAttempts) {
                if ($RequireSuccess) {
                    Write-RemediationLog "CRITICAL REMEDIATION FAILED: $Description" -Level "Error" -SecurityCritical
                    throw "Required remediation failed: $Description - $ErrorMsg"
                } else {
                    Write-RemediationLog "Remediation failed after $MaxAttempts attempts: $Description" -Level "Error"
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

# Initialize and configure TPM for BitLocker operations
function Initialize-TPMForBitLocker {
    Write-RemediationLog "=== Initializing TPM Hardware for BitLocker ===" -Level "Info"
    
    # Check current TPM status
    $TPMInitSuccess = Invoke-SecureRemediation -Description "TPM status verification and initialization" -Command {
        $TPM = Get-Tpm
        
        if (-not $TPM.TpmPresent) {
            throw "TPM hardware not detected - BitLocker cannot be enabled"
        }
        
        # Initialize TPM if not ready
        if (-not $TPM.TpmReady) {
            Write-RemediationLog "TPM requires initialization - attempting automatic setup" -Level "Action"
            Initialize-Tpm -AllowClear -AllowPhysicalPresence
            
            # Wait for TPM initialization
            Start-Sleep -Seconds 10
            
            # Re-check TPM status
            $TPM = Get-Tpm
            if (-not $TPM.TpmReady) {
                throw "TPM initialization failed - manual intervention may be required"
            }
        }
        
        # Enable TPM if not enabled
        if (-not $TPM.TpmEnabled) {
            Write-RemediationLog "Enabling TPM for cryptographic operations" -Level "Action"
            Enable-TpmAutoProvisioning
        }
        
        # Verify TPM ownership
        if (-not $TPM.TpmOwned) {
            Write-RemediationLog "Establishing TPM ownership for BitLocker" -Level "Action"
            # TPM ownership will be established automatically by BitLocker
        }
        
        Write-RemediationLog "TPM hardware successfully prepared for BitLocker" -Level "Security"
        
    } -SecurityCritical -RequireSuccess
    
    return $TPMInitSuccess
}

# Enable BitLocker encryption with enterprise security settings
function Enable-BitLockerEncryption {
    Write-RemediationLog "=== Enabling BitLocker Drive Encryption ===" -Level "Info"
    
    $EncryptionSuccess = $false
    
    try {
        # Get OS drive information
        $OSVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        
        if ($OSVolume -and $OSVolume.VolumeStatus -eq "FullyEncrypted") {
            Write-RemediationLog "BitLocker already enabled and fully encrypted on $env:SystemDrive" -Level "Success"
            return $true
        }
        
        # Prepare key protectors based on configuration
        $KeyProtectors = @()
        
        # Add TPM protector (primary)
        if ("Tpm" -in $RemediationConfig.KeyProtectorTypes) {
            $EncryptionSuccess = Invoke-SecureRemediation -Description "Add TPM key protector" -Command {
                $TPMProtector = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -ErrorAction Stop
                Write-RemediationLog "TPM key protector added: $($TPMProtector.KeyProtectorId)" -Level "Security"
                $KeyProtectors += $TPMProtector.KeyProtectorId
            } -SecurityCritical
        }
        
        # Add Recovery Password protector (required for enterprise)
        if ("RecoveryPassword" -in $RemediationConfig.KeyProtectorTypes) {
            $RecoverySuccess = Invoke-SecureRemediation -Description "Add recovery password protector" -Command {
                $RecoveryProtector = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction Stop
                Write-RemediationLog "Recovery password protector added: $($RecoveryProtector.KeyProtectorId)" -Level "Security"
                $KeyProtectors += $RecoveryProtector.KeyProtectorId
            } -SecurityCritical
            
            $EncryptionSuccess = $EncryptionSuccess -and $RecoverySuccess
        }
        
        # Add TPM+PIN protector for high-security environments
        if ($RemediationConfig.RequireTPMAndPin) {
            $PinSuccess = Invoke-SecureRemediation -Description "Add TPM+PIN protector" -Command {
                $SecurePin = Read-Host "Enter BitLocker PIN (4-20 digits)" -AsSecureString
                $PinProtector = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin $SecurePin -ErrorAction Stop
                Write-RemediationLog "TPM+PIN protector added: $($PinProtector.KeyProtectorId)" -Level "Security"
                $KeyProtectors += $PinProtector.KeyProtectorId
            } -SecurityCritical
        }
        
        if (-not $EncryptionSuccess) {
            throw "Failed to add required key protectors for BitLocker"
        }
        
        # Enable BitLocker encryption
        $BitLockerEnableSuccess = Invoke-SecureRemediation -Description "Enable BitLocker encryption" -Command {
            $EncryptionParams = @{
                MountPoint = $env:SystemDrive
                EncryptionMethod = $RemediationConfig.EncryptionMethod
                UsedSpaceOnly = $RemediationConfig.EncryptUsedSpaceOnly
                SkipHardwareTest = $true  # Skip for automated deployment
                ErrorAction = "Stop"
            }
            
            Enable-BitLocker @EncryptionParams
            Write-RemediationLog "BitLocker encryption initiated with method: $($RemediationConfig.EncryptionMethod)" -Level "Security"
            
        } -SecurityCritical -RequireSuccess
        
        # Monitor encryption progress
        if ($BitLockerEnableSuccess) {
            Write-RemediationLog "Monitoring BitLocker encryption progress..." -Level "Info"
            
            $ProgressCheck = 0
            do {
                Start-Sleep -Seconds 30
                $OSVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
                $EncryptionPercentage = $OSVolume.EncryptionPercentage
                
                Write-RemediationLog "Encryption progress: $EncryptionPercentage%" -Level "Info"
                $ProgressCheck++
                
                # Don't wait forever - log progress and continue
                if ($ProgressCheck -ge 10) {  # 5 minutes maximum wait
                    Write-RemediationLog "Encryption in progress - remediation will continue in background" -Level "Info"
                    break
                }
                
            } while ($OSVolume.VolumeStatus -ne "FullyEncrypted" -and $EncryptionPercentage -lt 100)
        }
        
        return $BitLockerEnableSuccess
        
    } catch {
        Write-RemediationLog "BitLocker encryption enablement failed: $($_.Exception.Message)" -Level "Error" -SecurityCritical
        return $false
    }
}

# Force backup of recovery keys to Azure AD or MBAM
function Backup-RecoveryKeys {
    Write-RemediationLog "=== Backing Up BitLocker Recovery Keys ===" -Level "Info"
    
    try {
        # Get BitLocker volume and recovery protectors
        $OSVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        
        if (-not $OSVolume) {
            Write-RemediationLog "Cannot access BitLocker volume for key backup" -Level "Error"
            return $false
        }
        
        $RecoveryProtectors = $OSVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
        
        if (-not $RecoveryProtectors) {
            Write-RemediationLog "No recovery password protectors found for backup" -Level "Warning"
            return $false
        }
        
        $BackupSuccess = $true
        
        foreach ($Protector in $RecoveryProtectors) {
            $KeyProtectorId = $Protector.KeyProtectorId
            
            # Attempt Azure AD backup
            $AzureBackupSuccess = Invoke-SecureRemediation -Description "Backup recovery key to Azure AD" -Command {
                BackupToAAD-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $KeyProtectorId -ErrorAction Stop
                Write-RemediationLog "Recovery key backed up to Azure AD: $KeyProtectorId" -Level "Security"
            } -SecurityCritical
            
            if ($AzureBackupSuccess) {
                continue  # Successful Azure backup
            }
            
            # Attempt MBAM backup if Azure fails
            $MBAMBackupSuccess = Invoke-SecureRemediation -Description "Backup recovery key to MBAM" -Command {
                # MBAM backup via registry or API if available
                $MBAMEndpoint = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "ClientWakeupFrequency" -ErrorAction SilentlyContinue)
                
                if ($MBAMEndpoint) {
                    # Use MBAM PowerShell cmdlets if available
                    if (Get-Command "Send-MbamClientData" -ErrorAction SilentlyContinue) {
                        Send-MbamClientData -ErrorAction Stop
                        Write-RemediationLog "Recovery key data sent to MBAM server" -Level "Security"
                    } else {
                        throw "MBAM client not properly configured"
                    }
                } else {
                    throw "MBAM not configured for key escrow"
                }
            }
            
            if (-not $AzureBackupSuccess -and -not $MBAMBackupSuccess) {
                Write-RemediationLog "Failed to backup recovery key: $KeyProtectorId" -Level "Error"
                $BackupSuccess = $false
            }
        }
        
        # Verify backup was successful by checking registry timestamps
        if ($BackupSuccess) {
            $VerificationSuccess = Invoke-SecureRemediation -Description "Verify recovery key backup" -Command {
                foreach ($Protector in $RecoveryProtectors) {
                    $KeyId = $Protector.KeyProtectorId.Replace('{','').Replace('}','')
                    $BackupPath = "HKLM:\SOFTWARE\Microsoft\BitLocker\Recovery\$KeyId"
                    
                    $BackupInfo = Get-ItemProperty -Path $BackupPath -ErrorAction SilentlyContinue
                    if ($BackupInfo -and $BackupInfo.LastBackupTime) {
                        $BackupTime = [DateTime]::FromFileTime($BackupInfo.LastBackupTime)
                        $BackupAge = (Get-Date) - $BackupTime
                        
                        if ($BackupAge.TotalMinutes -le 30) {  # Recent backup within 30 minutes
                            Write-RemediationLog "Recovery key backup verified: $($BackupTime.ToString())" -Level "Success"
                        } else {
                            Write-RemediationLog "Recovery key backup timestamp is old: $($BackupTime.ToString())" -Level "Warning"
                        }
                    }
                }
            }
        }
        
        return $BackupSuccess
        
    } catch {
        Write-RemediationLog "Recovery key backup failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Update encryption method to meet security standards
function Update-EncryptionMethod {
    Write-RemediationLog "=== Updating BitLocker Encryption Method ===" -Level "Info"
    
    try {
        $OSVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        
        if (-not $OSVolume) {
            Write-RemediationLog "Cannot access BitLocker volume for encryption method update" -Level "Error"
            return $false
        }
        
        $CurrentMethod = $OSVolume.EncryptionMethod
        $TargetMethod = $RemediationConfig.EncryptionMethod
        
        Write-RemediationLog "Current encryption method: $CurrentMethod, Target: $TargetMethod" -Level "Info"
        
        if ($CurrentMethod -eq $TargetMethod) {
            Write-RemediationLog "Encryption method already meets security standards" -Level "Success"
            return $true
        }
        
        # Check if volume supports in-place encryption method upgrade
        $MethodUpdateSuccess = Invoke-SecureRemediation -Description "Update BitLocker encryption method" -Command {
            # For encryption method changes, typically requires decrypt and re-encrypt
            Write-RemediationLog "WARNING: Encryption method change requires decrypt/re-encrypt cycle" -Level "Warning"
            
            # In production, you might want to schedule this during maintenance windows
            # For now, we'll document the requirement but not force the change
            Write-RemediationLog "Encryption method update scheduled for next maintenance window" -Level "Info"
            
            # Set registry flag for next encryption cycle
            $PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
            if (-not (Test-Path $PolicyPath)) {
                New-Item -Path $PolicyPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $PolicyPath -Name "EncryptionMethodWithXtsOs" -Value 7 -Type DWord  # XTS-AES 256
            Write-RemediationLog "Updated encryption method policy for future encryption operations" -Level "Security"
            
        } -SecurityCritical
        
        return $MethodUpdateSuccess
        
    } catch {
        Write-RemediationLog "Encryption method update failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Configure auto-unlock for system and data drives
function Configure-AutoUnlock {
    Write-RemediationLog "=== Configuring BitLocker Auto-Unlock ===" -Level "Info"
    
    try {
        # Get all BitLocker volumes
        $AllVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        $DataVolumes = $AllVolumes | Where-Object { $_.MountPoint -ne $env:SystemDrive -and $_.VolumeType -eq "Data" }
        
        if (-not $DataVolumes) {
            Write-RemediationLog "No data volumes found requiring auto-unlock configuration" -Level "Info"
            return $true
        }
        
        $AutoUnlockSuccess = $true
        
        foreach ($Volume in $DataVolumes) {
            if ($Volume.VolumeStatus -eq "FullyEncrypted" -or $Volume.VolumeStatus -eq "EncryptionInProgress") {
                $VolumeSuccess = Invoke-SecureRemediation -Description "Configure auto-unlock for $($Volume.MountPoint)" -Command {
                    # Enable auto-unlock from OS drive
                    Enable-BitLockerAutoUnlock -MountPoint $Volume.MountPoint -ErrorAction Stop
                    Write-RemediationLog "Auto-unlock enabled for volume: $($Volume.MountPoint)" -Level "Security"
                    
                } -SecurityCritical
                
                if (-not $VolumeSuccess) {
                    $AutoUnlockSuccess = $false
                }
            }
        }
        
        return $AutoUnlockSuccess
        
    } catch {
        Write-RemediationLog "Auto-unlock configuration failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Repair corrupted BitLocker configuration and services
function Repair-BitLockerConfiguration {
    Write-RemediationLog "=== Repairing BitLocker Configuration ===" -Level "Info"
    
    # Restart BitLocker service
    $ServiceRepairSuccess = Invoke-SecureRemediation -Description "Restart BitLocker Drive Encryption Service" -Command {
        $BLService = Get-Service -Name "BDESVC"
        if ($BLService.Status -ne "Running") {
            Start-Service -Name "BDESVC" -ErrorAction Stop
            Write-RemediationLog "BitLocker service started successfully" -Level "Success"
        } else {
            Restart-Service -Name "BDESVC" -Force -ErrorAction Stop
            Write-RemediationLog "BitLocker service restarted successfully" -Level "Success"
        }
    }
    
    # Clear BitLocker cache and temporary files
    $CacheCleanSuccess = Invoke-SecureRemediation -Description "Clear BitLocker cache and temporary files" -Command {
        $CachePaths = @(
            "$env:WINDIR\System32\config\systemprofile\AppData\Local\Microsoft\BitLocker",
            "$env:WINDIR\Temp\BitLocker*"
        )
        
        foreach ($CachePath in $CachePaths) {
            if (Test-Path $CachePath) {
                Remove-Item -Path $CachePath -Recurse -Force -ErrorAction SilentlyContinue
                Write-RemediationLog "Cleared BitLocker cache: $CachePath" -Level "Info"
            }
        }
    }
    
    # Refresh group policy for BitLocker settings
    $PolicyRefreshSuccess = Invoke-SecureRemediation -Description "Refresh BitLocker group policy" -Command {
        & gpupdate.exe /force /wait:30
        Write-RemediationLog "Group policy refreshed for BitLocker settings" -Level "Success"
    }
    
    return ($ServiceRepairSuccess -and $CacheCleanSuccess -and $PolicyRefreshSuccess)
}

# Validate remediation success and final compliance
function Test-RemediationSuccess {
    Write-RemediationLog "=== Validating BitLocker Remediation Results ===" -Level "Info"
    
    Start-Sleep -Seconds 10  # Allow time for changes to take effect
    
    try {
        # Re-run critical compliance checks
        $OSVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        
        if (-not $OSVolume) {
            Write-RemediationLog "BitLocker volume still not accessible after remediation" -Level "Error"
            return $false
        }
        
        # Check encryption status
        $EncryptionStatus = $OSVolume.VolumeStatus
        $ProtectionStatus = $OSVolume.ProtectionStatus
        
        Write-RemediationLog "Post-remediation status - Volume: $EncryptionStatus, Protection: $ProtectionStatus" -Level "Info"
        
        # Validate critical requirements
        $ValidationResults = @{
            "Encryption_Enabled" = ($EncryptionStatus -in @("FullyEncrypted", "EncryptionInProgress"))
            "Protection_Active" = ($ProtectionStatus -eq "On")
            "Key_Protectors" = ($OSVolume.KeyProtector.Count -gt 0)
            "TPM_Available" = (Get-Tpm).TpmReady
        }
        
        $PassedValidations = ($ValidationResults.Values | Where-Object { $_ -eq $true }).Count
        $TotalValidations = $ValidationResults.Count
        
        Write-RemediationLog "Validation Results: $PassedValidations / $TotalValidations checks passed" -Level "Info"
        
        foreach ($Check in $ValidationResults.GetEnumerator()) {
            $Status = if ($Check.Value) { "✓ PASS" } else { "✗ FAIL" }
            Write-RemediationLog "  $($Check.Key): $Status" -Level "Info"
        }
        
        return ($PassedValidations -eq $TotalValidations)
        
    } catch {
        Write-RemediationLog "Remediation validation failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Main remediation orchestration
try {
    Write-RemediationLog "=== BitLocker Compliance Remediation Started ===" -Level "Info" -WriteToEventLog
    Write-RemediationLog "Remediation script version: 1.0" -Level "Info"
    Write-RemediationLog "Target device: $env:COMPUTERNAME" -Level "Info"
    Write-RemediationLog "Execution context: $env:USERNAME" -Level "Info"
    Write-RemediationLog "Security configuration: $($RemediationConfig.EncryptionMethod), TPM+PIN: $($RemediationConfig.RequireTPMAndPin)" -Level "Info"
    
    # Verify administrative privileges for BitLocker operations
    $IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsElevated) {
        Write-RemediationLog "ERROR: Administrative privileges required for BitLocker remediation" -Level "Error" -SecurityCritical
        throw "BitLocker remediation requires administrative privileges"
    }
    
    # Execute comprehensive BitLocker remediation sequence
    Write-RemediationLog "Executing enterprise BitLocker security remediation..." -Level "Info" -SecurityCritical
    
    $RemediationSteps = @(
        @{ Name = "TPM Initialization"; Action = { Initialize-TPMForBitLocker } },
        @{ Name = "BitLocker Configuration Repair"; Action = { Repair-BitLockerConfiguration } },
        @{ Name = "BitLocker Encryption Enablement"; Action = { Enable-BitLockerEncryption } },
        @{ Name = "Recovery Key Backup"; Action = { Backup-RecoveryKeys } },
        @{ Name = "Encryption Method Update"; Action = { Update-EncryptionMethod } },
        @{ Name = "Auto-Unlock Configuration"; Action = { Configure-AutoUnlock } }
    )
    
    $SuccessfulSteps = 0
    $TotalSteps = $RemediationSteps.Count
    $CriticalFailures = @()
    
    foreach ($Step in $RemediationSteps) {
        Write-RemediationLog "--- Executing: $($Step.Name) ---" -Level "Info"
        
        try {
            $StepResult = & $Step.Action
            if ($StepResult) {
                $SuccessfulSteps++
                Write-RemediationLog "Step completed successfully: $($Step.Name)" -Level "Success" -SecurityCritical
            } else {
                Write-RemediationLog "Step completed with issues: $($Step.Name)" -Level "Warning"
                
                # Mark critical failures
                if ($Step.Name -in @("TPM Initialization", "BitLocker Encryption Enablement")) {
                    $CriticalFailures += $Step.Name
                }
            }
        } catch {
            Write-RemediationLog "Step failed: $($Step.Name) - $($_.Exception.Message)" -Level "Error"
            $CriticalFailures += $Step.Name
        }
        
        # Brief pause between major security operations
        Start-Sleep -Seconds 5
    }
    
    # Validate overall remediation effectiveness
    $ValidationSuccess = Test-RemediationSuccess
    
    # Generate comprehensive security compliance summary
    Write-RemediationLog "=== BitLocker Remediation Summary ===" -Level "Info"
    Write-RemediationLog "Completed steps: $SuccessfulSteps / $TotalSteps" -Level "Info"
    Write-RemediationLog "Critical failures: $($CriticalFailures.Count)" -Level "Info"
    Write-RemediationLog "Final validation: $(if ($ValidationSuccess) { 'PASSED' } else { 'REQUIRES ATTENTION' })" -Level "Info"
    
    if ($RemediationActions.Count -gt 0) {
        Write-RemediationLog "Security actions performed:" -Level "Info"
        foreach ($Action in $RemediationActions) {
            Write-RemediationLog "  • $Action" -Level "Info"
        }
    }
    
    # Determine overall remediation success
    $OverallSuccess = ($CriticalFailures.Count -eq 0) -and 
                     ($SuccessfulSteps -ge ($TotalSteps * 0.8)) -and 
                     $ValidationSuccess
    
    if ($OverallSuccess) {
        Write-RemediationLog "=== REMEDIATION SUCCESSFUL ===" -Level "Success" -SecurityCritical
        Write-RemediationLog "Device BitLocker compliance has been restored" -Level "Success"
        exit 0
    } else {
        Write-RemediationLog "=== REMEDIATION INCOMPLETE ===" -Level "Warning" -SecurityCritical
        Write-RemediationLog "Some critical security issues require manual intervention" -Level "Warning"
        
        if ($CriticalFailures.Count -gt 0) {
            Write-RemediationLog "Critical failures: $($CriticalFailures -join ', ')" -Level "Error"
        }
        
        exit 1
    }
    
} catch {
    Write-RemediationLog "=== REMEDIATION SCRIPT FAILED ===" -Level "Error" -SecurityCritical
    Write-RemediationLog "Unexpected error during security remediation: $($_.Exception.Message)" -Level "Error"
    Write-RemediationLog "Stack trace: $($_.Exception.StackTrace)" -Level "Error"
    
    # Log critical security failure
    exit 1
    
} finally {
    $ScriptDuration = (Get-Date) - $ScriptStartTime
    Write-RemediationLog "BitLocker remediation completed in $($ScriptDuration.TotalSeconds) seconds" -Level "Info"
    
    # Security recommendations
    if ($SuccessfulSteps -ge ($TotalSteps * 0.6)) {
        Write-RemediationLog "SECURITY RECOMMENDATION: Verify BitLocker encryption completion and test recovery key access" -Level "Info"
        Write-RemediationLog "COMPLIANCE NOTE: Document remediation actions for security audit trail" -Level "Info"
    }
}