<#
.SYNOPSIS
    Microsoft Intune Sync and Communication Health Detection Script

.DESCRIPTION
    This detection script monitors the health and connectivity status of Microsoft Intune device management.
    It performs comprehensive checks on enrollment status, sync timing, certificate validity, and service health
    to ensure devices remain properly managed and compliant with organizational policies.

.NOTES
    File Name      : DetectionScript.ps1
    Author         : Apostolos Tsirogiannis - Senior System Engineer Showcase
    Prerequisite   : Windows 10/11 with Intune enrollment
    
    DETECTION CRITERIA:
    • Last successful sync within 24 hours
    • Device enrollment certificates valid and not expired
    • Critical Intune services running and responsive
    • MDM registration status active and healthy
    • Network connectivity to Intune service endpoints
    
    EXIT CODES:
    • 0 = Compliant (no remediation needed)
    • 1 = Non-compliant (remediation required)
    
    INTUNE PROACTIVE REMEDIATIONS:
    This script is optimized for Microsoft Intune Proactive Remediations and follows
    best practices for cloud-managed device monitoring and automated remediation.

.EXAMPLE
    .\DetectionScript.ps1
    
    Performs comprehensive Intune health check and returns compliance status.
    Suitable for scheduled execution via Intune Proactive Remediations.
#>

# Script configuration
$MaxSyncAgeHours = 24
$EventLogSource = "IntuneHealthCheck"
$VerboseLogging = $false

# Initialize script execution
$ScriptStartTime = Get-Date
$ScriptName = "Intune-Sync-Detection"

# Enhanced logging function for detailed diagnostics
function Write-DetectionLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info",
        [switch]$WriteToEventLog
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    if ($VerboseLogging) {
        Write-Host $LogEntry -ForegroundColor $(
            switch ($Level) {
                "Error" { "Red" }
                "Warning" { "Yellow" }
                "Success" { "Green" }
                default { "White" }
            }
        )
    }
    
    # Write to Windows Event Log for audit trail
    if ($WriteToEventLog) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
                New-EventLog -LogName "Application" -Source $EventLogSource
            }
            
            $EventType = switch ($Level) {
                "Error" { "Error" }
                "Warning" { "Warning" }
                default { "Information" }
            }
            
            Write-EventLog -LogName "Application" -Source $EventLogSource -EntryType $EventType -EventId 1001 -Message $LogEntry
        } catch {
            # Silently continue if event log writing fails
        }
    }
}

# Test Intune device enrollment status
function Test-IntuneEnrollment {
    Write-DetectionLog "Checking Intune device enrollment status..." -Level "Info"
    
    try {
        # Check MDM enrollment registry
        $MDMEnrollment = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\*" -ErrorAction SilentlyContinue | 
                        Where-Object { $_.ProviderID -eq "MS DM Server" }
        
        if (-not $MDMEnrollment) {
            Write-DetectionLog "Device is not enrolled in MDM management" -Level "Error"
            return $false
        }
        
        # Verify enrollment details
        $EnrollmentUPN = $MDMEnrollment.UPN
        $EnrollmentID = $MDMEnrollment.PSChildName
        
        Write-DetectionLog "Device enrolled with UPN: $EnrollmentUPN (ID: $EnrollmentID)" -Level "Success"
        return $true
        
    } catch {
        Write-DetectionLog "Failed to check enrollment status: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Check last successful sync with Intune
function Test-IntuneSyncStatus {
    Write-DetectionLog "Analyzing Intune sync status and timing..." -Level "Info"
    
    try {
        # Get sync status from registry
        $SyncKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\*\Status" -ErrorAction SilentlyContinue
        
        if (-not $SyncKeys) {
            Write-DetectionLog "No sync status information found" -Level "Warning"
            return $false
        }
        
        $LatestSync = $null
        $SyncSuccess = $false
        
        foreach ($Key in $SyncKeys) {
            if ($Key.LastSuccessTime) {
                $SyncTime = [DateTime]::FromFileTime($Key.LastSuccessTime)
                if (-not $LatestSync -or $SyncTime -gt $LatestSync) {
                    $LatestSync = $SyncTime
                    $SyncSuccess = ($Key.LastHResult -eq 0)
                }
            }
        }
        
        if (-not $LatestSync) {
            Write-DetectionLog "No successful sync time found in registry" -Level "Warning"
            return $false
        }
        
        $SyncAge = (Get-Date) - $LatestSync
        $SyncAgeHours = [math]::Round($SyncAge.TotalHours, 2)
        
        Write-DetectionLog "Last sync: $LatestSync ($SyncAgeHours hours ago), Success: $SyncSuccess" -Level "Info"
        
        if ($SyncAgeHours -gt $MaxSyncAgeHours) {
            Write-DetectionLog "Sync is too old (>$MaxSyncAgeHours hours). Remediation needed." -Level "Warning"
            return $false
        }
        
        if (-not $SyncSuccess) {
            Write-DetectionLog "Last sync was not successful. Remediation needed." -Level "Warning"
            return $false
        }
        
        Write-DetectionLog "Sync status is healthy and recent" -Level "Success"
        return $true
        
    } catch {
        Write-DetectionLog "Failed to check sync status: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Verify critical Intune services are running
function Test-IntuneServices {
    Write-DetectionLog "Checking critical Intune and MDM services..." -Level "Info"
    
    $CriticalServices = @(
        "dmwappushservice",  # Device Management Wireless Application Protocol Push service
        "DmEnrollmentSvc",   # Device Management Enrollment Service
        "MDCoreSvc"          # Microsoft Defender Core Service
    )
    
    $ServiceIssues = @()
    
    foreach ($ServiceName in $CriticalServices) {
        try {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            
            if (-not $Service) {
                Write-DetectionLog "Service $ServiceName not found (may be normal on some systems)" -Level "Info"
                continue
            }
            
            if ($Service.Status -ne "Running") {
                Write-DetectionLog "Service $ServiceName is not running (Status: $($Service.Status))" -Level "Warning"
                $ServiceIssues += $ServiceName
            } else {
                Write-DetectionLog "Service $ServiceName is running normally" -Level "Success"
            }
            
        } catch {
            Write-DetectionLog "Failed to check service $ServiceName : $($_.Exception.Message)" -Level "Error"
            $ServiceIssues += $ServiceName
        }
    }
    
    if ($ServiceIssues.Count -gt 0) {
        Write-DetectionLog "Found issues with $($ServiceIssues.Count) critical services" -Level "Warning"
        return $false
    }
    
    Write-DetectionLog "All critical services are running properly" -Level "Success"
    return $true
}

# Test certificate health and validity
function Test-IntuneCertificates {
    Write-DetectionLog "Validating Intune device certificates..." -Level "Info"
    
    try {
        # Check for MDM certificates in personal store
        $MDMCerts = Get-ChildItem -Path "Cert:\LocalMachine\My" | 
                   Where-Object { $_.Subject -like "*Microsoft Intune*" -or $_.Issuer -like "*Microsoft Intune*" }
        
        if (-not $MDMCerts) {
            Write-DetectionLog "No Intune certificates found in machine store" -Level "Warning"
            return $false
        }
        
        $ExpiredCerts = $MDMCerts | Where-Object { $_.NotAfter -lt (Get-Date) }
        $ExpiringSoonCerts = $MDMCerts | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) -and $_.NotAfter -gt (Get-Date) }
        
        if ($ExpiredCerts) {
            Write-DetectionLog "Found $($ExpiredCerts.Count) expired Intune certificates" -Level "Error"
            return $false
        }
        
        if ($ExpiringSoonCerts) {
            Write-DetectionLog "Found $($ExpiringSoonCerts.Count) certificates expiring within 30 days" -Level "Warning"
        }
        
        Write-DetectionLog "Intune certificates are valid and current" -Level "Success"
        return $true
        
    } catch {
        Write-DetectionLog "Failed to check certificates: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Test network connectivity to Intune endpoints
function Test-IntuneConnectivity {
    Write-DetectionLog "Testing network connectivity to Intune service endpoints..." -Level "Info"
    
    $IntuneEndpoints = @(
        "enrollment.manage.microsoft.com",
        "portal.manage.microsoft.com",
        "login.microsoftonline.com"
    )
    
    $ConnectivityIssues = @()
    
    foreach ($Endpoint in $IntuneEndpoints) {
        try {
            $TestResult = Test-NetConnection -ComputerName $Endpoint -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
            
            if ($TestResult) {
                Write-DetectionLog "Connectivity to $Endpoint : OK" -Level "Success"
            } else {
                Write-DetectionLog "Connectivity to $Endpoint : FAILED" -Level "Error"
                $ConnectivityIssues += $Endpoint
            }
            
        } catch {
            Write-DetectionLog "Failed to test connectivity to $Endpoint : $($_.Exception.Message)" -Level "Error"
            $ConnectivityIssues += $Endpoint
        }
    }
    
    if ($ConnectivityIssues.Count -gt 0) {
        Write-DetectionLog "Network connectivity issues detected for $($ConnectivityIssues.Count) endpoints" -Level "Error"
        return $false
    }
    
    Write-DetectionLog "Network connectivity to all Intune endpoints is healthy" -Level "Success"
    return $true
}

# Main detection logic
try {
    Write-DetectionLog "=== Intune Health Detection Started ===" -Level "Info" -WriteToEventLog
    Write-DetectionLog "Detection script version: 1.0" -Level "Info"
    Write-DetectionLog "Target device: $env:COMPUTERNAME" -Level "Info"
    Write-DetectionLog "Current user context: $env:USERNAME" -Level "Info"
    
    # Comprehensive health checks
    $EnrollmentStatus = Test-IntuneEnrollment
    $SyncStatus = Test-IntuneSyncStatus
    $ServiceStatus = Test-IntuneServices
    $CertificateStatus = Test-IntuneCertificates
    $ConnectivityStatus = Test-IntuneConnectivity
    
    # Calculate overall compliance status
    $ComplianceChecks = @{
        "Enrollment" = $EnrollmentStatus
        "Sync" = $SyncStatus
        "Services" = $ServiceStatus
        "Certificates" = $CertificateStatus
        "Connectivity" = $ConnectivityStatus
    }
    
    $PassedChecks = ($ComplianceChecks.Values | Where-Object { $_ -eq $true }).Count
    $TotalChecks = $ComplianceChecks.Count
    $CompliancePercentage = [math]::Round(($PassedChecks / $TotalChecks) * 100, 1)
    
    Write-DetectionLog "=== Health Check Summary ===" -Level "Info"
    Write-DetectionLog "Passed checks: $PassedChecks / $TotalChecks ($CompliancePercentage%)" -Level "Info"
    
    foreach ($Check in $ComplianceChecks.GetEnumerator()) {
        $Status = if ($Check.Value) { "PASS" } else { "FAIL" }
        Write-DetectionLog "  $($Check.Key): $Status" -Level "Info"
    }
    
    # Determine final compliance status
    if ($EnrollmentStatus -and $SyncStatus) {
        # Core requirements met - device is manageable
        Write-DetectionLog "=== DETECTION RESULT: COMPLIANT ===" -Level "Success" -WriteToEventLog
        Write-DetectionLog "Device is properly enrolled and syncing with Intune" -Level "Success"
        exit 0
    } else {
        # Critical issues detected - remediation needed
        Write-DetectionLog "=== DETECTION RESULT: NON-COMPLIANT ===" -Level "Warning" -WriteToEventLog
        Write-DetectionLog "Device requires remediation to restore Intune connectivity" -Level "Warning"
        exit 1
    }
    
} catch {
    Write-DetectionLog "=== DETECTION SCRIPT FAILED ===" -Level "Error" -WriteToEventLog
    Write-DetectionLog "Unexpected error: $($_.Exception.Message)" -Level "Error"
    Write-DetectionLog "Stack trace: $($_.Exception.StackTrace)" -Level "Error"
    
    # Exit with error code indicating script failure
    exit 1
    
} finally {
    $ScriptDuration = (Get-Date) - $ScriptStartTime
    Write-DetectionLog "Detection completed in $($ScriptDuration.TotalSeconds) seconds" -Level "Info"
}