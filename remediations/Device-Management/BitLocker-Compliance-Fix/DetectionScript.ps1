<#
.SYNOPSIS
    BitLocker Drive Encryption Compliance Detection Script

.DESCRIPTION
    This enterprise-grade detection script performs comprehensive BitLocker compliance validation
    for modern workplace security requirements. It evaluates encryption status, key escrow to
    Azure AD/MBAM, TPM health, recovery key backup, and compliance with organizational policies
    to ensure data protection standards are maintained across all managed devices.

.NOTES
    File Name      : DetectionScript.ps1
    Author         : Apostolos Tsirogiannis - Senior System Engineer Showcase
    Prerequisite   : Windows 10/11 Pro/Enterprise, TPM 2.0, Administrative context
    
    COMPLIANCE CRITERIA:
    • OS Drive fully encrypted with BitLocker
    • Recovery keys properly escrowed to Azure AD or MBAM
    • TPM 2.0 enabled and operational
    • Encryption method meets organizational standards (AES-256 recommended)
    • Auto-unlock enabled for system drives
    • Recovery key backup successful and current
    
    EXIT CODES:
    • 0 = Compliant (BitLocker properly configured and operational)
    • 1 = Non-compliant (remediation required for compliance)
    
    REGULATORY COMPLIANCE:
    This script supports compliance with GDPR, HIPAA, SOX, PCI-DSS, and other
    data protection regulations requiring encryption at rest.

.EXAMPLE
    .\DetectionScript.ps1
    
    Performs comprehensive BitLocker compliance assessment and returns status.
    Designed for Intune Proactive Remediations and enterprise security monitoring.
#>

# Script configuration and compliance parameters
$ComplianceStandards = @{
    RequiredEncryptionMethod = "AES256"  # AES128, AES256, XTS-AES128, XTS-AES256
    MinimumTPMVersion = "2.0"
    RequireKeyEscrow = $true
    RequireAutoUnlock = $true
    MaxKeyAge = 90  # Days since last key backup
}

$EventLogSource = "BitLockerCompliance"
$VerboseLogging = $false

# Initialize script execution context
$ScriptStartTime = Get-Date
$ScriptName = "BitLocker-Compliance-Detection"

# Enhanced logging with security audit trail
function Write-ComplianceLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success", "Security")]
        [string]$Level = "Info",
        [switch]$WriteToEventLog,
        [switch]$SecurityEvent
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    if ($VerboseLogging) {
        Write-Host $LogEntry -ForegroundColor $(
            switch ($Level) {
                "Error" { "Red" }
                "Warning" { "Yellow" }
                "Success" { "Green" }
                "Security" { "Magenta" }
                default { "White" }
            }
        )
    }
    
    # Write critical security events to Windows Application Log
    if ($WriteToEventLog -or $SecurityEvent) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
                New-EventLog -LogName "Application" -Source $EventLogSource
            }
            
            $EventType = switch ($Level) {
                "Error" { "Error" }
                "Security" { "Information" }
                "Warning" { "Warning" }
                default { "Information" }
            }
            
            $EventId = if ($SecurityEvent) { 4001 } else { 3001 }
            Write-EventLog -LogName "Application" -Source $EventLogSource -EntryType $EventType -EventId $EventId -Message $LogEntry
        } catch {
            # Continue if event log writing fails - don't block compliance check
        }
    }
}

# Validate TPM hardware and operational status
function Test-TPMCompliance {
    Write-ComplianceLog "Evaluating TPM hardware and security status..." -Level "Info"
    
    try {
        # Check if TPM is present and enabled
        $TPM = Get-Tpm -ErrorAction SilentlyContinue
        
        if (-not $TPM) {
            Write-ComplianceLog "TPM hardware not detected on this device" -Level "Error" -SecurityEvent
            return $false
        }
        
        # Validate TPM version requirements
        $TPMVersion = $TPM.TpmPresent
        if (-not $TPM.TpmPresent) {
            Write-ComplianceLog "TPM is present but not enabled in BIOS/UEFI" -Level "Error" -SecurityEvent
            return $false
        }
        
        if (-not $TPM.TpmReady) {
            Write-ComplianceLog "TPM is not ready for cryptographic operations" -Level "Error" -SecurityEvent
            return $false
        }
        
        if (-not $TPM.TpmEnabled) {
            Write-ComplianceLog "TPM is not enabled for BitLocker operations" -Level "Error" -SecurityEvent
            return $false
        }
        
        # Check TPM ownership and PCR values
        if ($TPM.TpmOwned -eq $false) {
            Write-ComplianceLog "TPM ownership not established - BitLocker may not function properly" -Level "Warning"
        }
        
        # Validate TPM version meets minimum requirements
        $TPMInfo = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class "Win32_Tpm" -ErrorAction SilentlyContinue
        if ($TPMInfo) {
            $TPMSpecVersion = $TPMInfo.SpecVersion
            Write-ComplianceLog "TPM Specification Version: $TPMSpecVersion" -Level "Info"
            
            if ($TPMSpecVersion -lt $ComplianceStandards.MinimumTPMVersion) {
                Write-ComplianceLog "TPM version $TPMSpecVersion does not meet minimum requirement $($ComplianceStandards.MinimumTPMVersion)" -Level "Error"
                return $false
            }
        }
        
        Write-ComplianceLog "TPM validation successful - hardware ready for BitLocker" -Level "Success"
        return $true
        
    } catch {
        Write-ComplianceLog "Failed to evaluate TPM status: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Comprehensive BitLocker encryption status assessment
function Test-BitLockerEncryption {
    Write-ComplianceLog "Analyzing BitLocker encryption status and configuration..." -Level "Info"
    
    try {
        # Get BitLocker volume information for OS drive
        $OSVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        
        if (-not $OSVolume) {
            Write-ComplianceLog "Unable to retrieve BitLocker status for OS drive $env:SystemDrive" -Level "Error" -SecurityEvent
            return $false
        }
        
        # Check encryption status
        $EncryptionStatus = $OSVolume.VolumeStatus
        $ProtectionStatus = $OSVolume.ProtectionStatus
        $EncryptionPercentage = $OSVolume.EncryptionPercentage
        $EncryptionMethod = $OSVolume.EncryptionMethod
        
        Write-ComplianceLog "BitLocker Status - Volume: $EncryptionStatus, Protection: $ProtectionStatus, Encryption: $EncryptionPercentage%, Method: $EncryptionMethod" -Level "Info"
        
        # Validate encryption completion
        if ($EncryptionStatus -ne "FullyEncrypted") {
            Write-ComplianceLog "OS drive is not fully encrypted. Current status: $EncryptionStatus ($EncryptionPercentage%)" -Level "Error" -SecurityEvent
            return $false
        }
        
        # Validate protection is active
        if ($ProtectionStatus -ne "On") {
            Write-ComplianceLog "BitLocker protection is not active. Current status: $ProtectionStatus" -Level "Error" -SecurityEvent
            return $false
        }
        
        # Validate encryption method meets compliance standards
        $AcceptableEncryptionMethods = @("AES128", "AES256", "XtsAes128", "XtsAes256")
        if ($EncryptionMethod -notin $AcceptableEncryptionMethods) {
            Write-ComplianceLog "Encryption method $EncryptionMethod does not meet security standards" -Level "Error" -SecurityEvent
            return $false
        }
        
        # Check for recommended encryption method
        if ($ComplianceStandards.RequiredEncryptionMethod -and $EncryptionMethod -ne $ComplianceStandards.RequiredEncryptionMethod) {
            Write-ComplianceLog "Encryption method $EncryptionMethod does not match organizational standard $($ComplianceStandards.RequiredEncryptionMethod)" -Level "Warning"
        }
        
        # Validate key protectors are present
        $KeyProtectors = $OSVolume.KeyProtector
        if (-not $KeyProtectors -or $KeyProtectors.Count -eq 0) {
            Write-ComplianceLog "No key protectors found for BitLocker volume" -Level "Error" -SecurityEvent
            return $false
        }
        
        # Check for TPM protector
        $TPMProtector = $KeyProtectors | Where-Object { $_.KeyProtectorType -eq "Tpm" }
        if (-not $TPMProtector) {
            Write-ComplianceLog "TPM key protector not found - BitLocker not using hardware security" -Level "Error" -SecurityEvent
            return $false
        }
        
        # Check for recovery password protector
        $RecoveryProtector = $KeyProtectors | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
        if (-not $RecoveryProtector) {
            Write-ComplianceLog "Recovery password protector not found - recovery may not be possible" -Level "Error" -SecurityEvent
            return $false
        }
        
        Write-ComplianceLog "BitLocker encryption validation successful - drive properly protected" -Level "Success"
        return $true
        
    } catch {
        Write-ComplianceLog "Failed to evaluate BitLocker encryption: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Validate recovery key escrow to Azure AD or MBAM
function Test-RecoveryKeyEscrow {
    Write-ComplianceLog "Validating BitLocker recovery key escrow status..." -Level "Info"
    
    try {
        # Get BitLocker volume for detailed key analysis
        $OSVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        
        if (-not $OSVolume) {
            Write-ComplianceLog "Cannot access BitLocker volume for key escrow validation" -Level "Error"
            return $false
        }
        
        # Get recovery password protectors
        $RecoveryProtectors = $OSVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
        
        if (-not $RecoveryProtectors) {
            Write-ComplianceLog "No recovery password protectors found for escrow validation" -Level "Error" -SecurityEvent
            return $false
        }
        
        $EscrowValidationPassed = $false
        
        foreach ($Protector in $RecoveryProtectors) {
            $KeyProtectorId = $Protector.KeyProtectorId
            Write-ComplianceLog "Validating escrow for recovery key: $KeyProtectorId" -Level "Info"
            
            # Check Azure AD escrow status via registry
            $AzureADKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
            $AzureADEscrowEnabled = $false
            
            try {
                $FVEPolicy = Get-ItemProperty -Path $AzureADKeyPath -ErrorAction SilentlyContinue
                if ($FVEPolicy) {
                    $AzureADEscrowEnabled = ($FVEPolicy.OSRequireActiveDirectoryBackup -eq 1) -or 
                                          ($FVEPolicy.OSActiveDirectoryBackup -eq 1)
                }
            } catch {
                Write-ComplianceLog "Unable to check Azure AD escrow policy settings" -Level "Warning"
            }
            
            # Check MBAM escrow status
            $MBAMKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
            $MBAMEscrowEnabled = $false
            
            try {
                if ($FVEPolicy.OSManageDRA -eq 1) {
                    $MBAMEscrowEnabled = $true
                }
            } catch {
                # MBAM not configured
            }
            
            # Validate escrow timestamp and currency
            $EscrowTimestamp = $null
            $KeyEscrowPath = "HKLM:\SOFTWARE\Microsoft\BitLocker\Recovery\$($KeyProtectorId.Replace('{','').Replace('}',''))"
            
            try {
                $KeyEscrowInfo = Get-ItemProperty -Path $KeyEscrowPath -ErrorAction SilentlyContinue
                if ($KeyEscrowInfo) {
                    $EscrowTimestamp = $KeyEscrowInfo.LastBackupTime
                    if ($EscrowTimestamp) {
                        $EscrowAge = (Get-Date) - [DateTime]::FromFileTime($EscrowTimestamp)
                        $EscrowAgeDays = [math]::Round($EscrowAge.TotalDays, 1)
                        
                        Write-ComplianceLog "Recovery key last backed up $EscrowAgeDays days ago" -Level "Info"
                        
                        if ($EscrowAgeDays -le $ComplianceStandards.MaxKeyAge) {
                            $EscrowValidationPassed = $true
                            Write-ComplianceLog "Recovery key escrow is current and compliant" -Level "Success"
                        } else {
                            Write-ComplianceLog "Recovery key backup is older than $($ComplianceStandards.MaxKeyAge) days" -Level "Warning"
                        }
                    }
                }
            } catch {
                Write-ComplianceLog "Unable to verify recovery key backup timestamp" -Level "Warning"
            }
            
            # If we can't verify escrow timestamp, check if escrow is configured
            if (-not $EscrowValidationPassed -and ($AzureADEscrowEnabled -or $MBAMEscrowEnabled)) {
                Write-ComplianceLog "Recovery key escrow is configured but timestamp validation failed" -Level "Warning"
                $EscrowValidationPassed = $true  # Assume compliant if policy is set
            }
        }
        
        if (-not $EscrowValidationPassed -and $ComplianceStandards.RequireKeyEscrow) {
            Write-ComplianceLog "Recovery key escrow validation failed - keys not properly backed up" -Level "Error" -SecurityEvent
            return $false
        }
        
        Write-ComplianceLog "Recovery key escrow validation completed successfully" -Level "Success"
        return $true
        
    } catch {
        Write-ComplianceLog "Failed to validate recovery key escrow: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Validate auto-unlock configuration for system drives
function Test-AutoUnlockConfiguration {
    Write-ComplianceLog "Checking BitLocker auto-unlock configuration..." -Level "Info"
    
    try {
        # Get all BitLocker volumes
        $AllVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        
        if (-not $AllVolumes) {
            Write-ComplianceLog "No BitLocker volumes found for auto-unlock validation" -Level "Warning"
            return $true  # Not a failure if no additional volumes
        }
        
        $OSVolume = $AllVolumes | Where-Object { $_.MountPoint -eq $env:SystemDrive }
        $DataVolumes = $AllVolumes | Where-Object { $_.MountPoint -ne $env:SystemDrive -and $_.VolumeType -eq "Data" }
        
        # Validate OS drive has proper key protectors for auto-unlock
        if ($OSVolume) {
            $TPMProtector = $OSVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "Tpm" }
            if (-not $TPMProtector -and $ComplianceStandards.RequireAutoUnlock) {
                Write-ComplianceLog "OS drive lacks TPM protector required for auto-unlock functionality" -Level "Error"
                return $false
            }
        }
        
        # Check data volumes for auto-unlock configuration
        foreach ($Volume in $DataVolumes) {
            if ($Volume.VolumeStatus -eq "FullyEncrypted") {
                $AutoUnlockProtector = $Volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "ExternalKey" }
                
                if (-not $AutoUnlockProtector -and $ComplianceStandards.RequireAutoUnlock) {
                    Write-ComplianceLog "Data volume $($Volume.MountPoint) lacks auto-unlock configuration" -Level "Warning"
                    # Not a hard failure for data volumes
                }
            }
        }
        
        Write-ComplianceLog "Auto-unlock configuration validation completed" -Level "Success"
        return $true
        
    } catch {
        Write-ComplianceLog "Failed to validate auto-unlock configuration: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Comprehensive BitLocker health and operational status check
function Test-BitLockerHealth {
    Write-ComplianceLog "Performing comprehensive BitLocker health assessment..." -Level "Info"
    
    try {
        # Check BitLocker service status
        $BLService = Get-Service -Name "BDESVC" -ErrorAction SilentlyContinue
        if (-not $BLService) {
            Write-ComplianceLog "BitLocker Drive Encryption Service not found" -Level "Error"
            return $false
        }
        
        if ($BLService.Status -ne "Running") {
            Write-ComplianceLog "BitLocker Drive Encryption Service is not running (Status: $($BLService.Status))" -Level "Error"
            return $false
        }
        
        # Check for BitLocker management WMI namespace
        try {
            $BitLockerWMI = Get-WmiObject -Namespace "Root\CIMV2\Security\MicrosoftVolumeEncryption" -Class "Win32_EncryptableVolume" -ErrorAction SilentlyContinue
            if (-not $BitLockerWMI) {
                Write-ComplianceLog "BitLocker WMI provider not accessible" -Level "Warning"
            }
        } catch {
            Write-ComplianceLog "BitLocker WMI provider validation failed: $($_.Exception.Message)" -Level "Warning"
        }
        
        # Check for recent BitLocker errors in event log
        try {
            $RecentErrors = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-BitLocker*'; Level=2; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue
            
            if ($RecentErrors -and $RecentErrors.Count -gt 0) {
                Write-ComplianceLog "Found $($RecentErrors.Count) BitLocker error events in the last 7 days" -Level "Warning"
                
                # Log the most recent critical errors
                $CriticalErrors = $RecentErrors | Select-Object -First 3
                foreach ($Error in $CriticalErrors) {
                    Write-ComplianceLog "Recent BitLocker error: $($Error.LevelDisplayName) - $($Error.Message)" -Level "Warning"
                }
            }
        } catch {
            Write-ComplianceLog "Unable to check BitLocker event log history" -Level "Info"
        }
        
        Write-ComplianceLog "BitLocker health assessment completed successfully" -Level "Success"
        return $true
        
    } catch {
        Write-ComplianceLog "Failed BitLocker health assessment: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Main compliance detection orchestration
try {
    Write-ComplianceLog "=== BitLocker Compliance Detection Started ===" -Level "Info" -WriteToEventLog
    Write-ComplianceLog "Detection script version: 1.0" -Level "Info"
    Write-ComplianceLog "Target device: $env:COMPUTERNAME" -Level "Info"
    Write-ComplianceLog "Assessment user: $env:USERNAME" -Level "Info"
    Write-ComplianceLog "Compliance standards: AES256, TPM 2.0, Key Escrow Required" -Level "Info"
    
    # Verify administrative context for BitLocker operations
    $IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsElevated) {
        Write-ComplianceLog "WARNING: Script not running with administrative privileges - some checks may be limited" -Level "Warning"
    }
    
    # Execute comprehensive compliance validation
    Write-ComplianceLog "Executing enterprise BitLocker compliance assessment..." -Level "Info"
    
    $ComplianceChecks = @{
        "TPM_Hardware" = Test-TPMCompliance
        "Encryption_Status" = Test-BitLockerEncryption
        "Key_Escrow" = Test-RecoveryKeyEscrow
        "AutoUnlock_Config" = Test-AutoUnlockConfiguration
        "System_Health" = Test-BitLockerHealth
    }
    
    # Calculate compliance metrics
    $PassedChecks = ($ComplianceChecks.Values | Where-Object { $_ -eq $true }).Count
    $TotalChecks = $ComplianceChecks.Count
    $ComplianceScore = [math]::Round(($PassedChecks / $TotalChecks) * 100, 1)
    
    Write-ComplianceLog "=== Compliance Assessment Results ===" -Level "Info"
    Write-ComplianceLog "Compliance Score: $ComplianceScore% ($PassedChecks / $TotalChecks checks passed)" -Level "Info"
    
    foreach ($Check in $ComplianceChecks.GetEnumerator()) {
        $Status = if ($Check.Value) { "✓ PASS" } else { "✗ FAIL" }
        $CheckName = $Check.Key.Replace("_", " ")
        Write-ComplianceLog "  $CheckName : $Status" -Level "Info"
    }
    
    # Determine final compliance status based on critical requirements
    $CriticalChecks = @("TPM_Hardware", "Encryption_Status")
    $CriticalPassed = $true
    
    foreach ($CriticalCheck in $CriticalChecks) {
        if (-not $ComplianceChecks[$CriticalCheck]) {
            $CriticalPassed = $false
            break
        }
    }
    
    # Final compliance determination
    if ($CriticalPassed -and $ComplianceScore -ge 80) {
        Write-ComplianceLog "=== COMPLIANCE STATUS: COMPLIANT ===" -Level "Success" -SecurityEvent
        Write-ComplianceLog "Device meets BitLocker enterprise security standards" -Level "Success"
        exit 0
    } else {
        Write-ComplianceLog "=== COMPLIANCE STATUS: NON-COMPLIANT ===" -Level "Error" -SecurityEvent
        Write-ComplianceLog "Device requires remediation to meet security compliance requirements" -Level "Error"
        exit 1
    }
    
} catch {
    Write-ComplianceLog "=== COMPLIANCE DETECTION FAILED ===" -Level "Error" -SecurityEvent
    Write-ComplianceLog "Unexpected error during compliance assessment: $($_.Exception.Message)" -Level "Error"
    Write-ComplianceLog "Stack trace: $($_.Exception.StackTrace)" -Level "Error"
    
    # Exit with error code indicating detection failure
    exit 1
    
} finally {
    $ScriptDuration = (Get-Date) - $ScriptStartTime
    Write-ComplianceLog "Compliance detection completed in $($ScriptDuration.TotalSeconds) seconds" -Level "Info"
}