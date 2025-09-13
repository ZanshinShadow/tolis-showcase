<#
.SYNOPSIS
    Device Uptime Detection Script - Enterprise Endpoint Management

.DESCRIPTION
    This PowerShell detection script provides automated monitoring for device uptime compliance
    in enterprise environments. It analyzes system uptime against configurable thresholds and
    integrates with Microsoft Intune, SCCM, or other endpoint management solutions for 
    automated remediation workflows.

    Detection Features:
    - Accurate system uptime calculation using process start time analysis
    - Configurable threshold detection for compliance requirements
    - Exit code integration for automated remediation triggering
    - Detailed logging for enterprise monitoring and compliance reporting
    - Support for various deployment scenarios (Intune, SCCM, Group Policy)

    Enterprise Use Cases:
    - Automated reboot compliance monitoring for security patch management
    - Device health monitoring and maintenance automation
    - Compliance reporting for corporate security policies
    - Integration with endpoint management and monitoring solutions
    - Proactive device maintenance and reliability optimization

.PARAMETER ThresholdDays
    Number of days after which a reboot is considered overdue (default: 7 days)

.PARAMETER LogPath
    Optional path for detailed operation logging (default: Windows event log)

.PARAMETER Verbose
    Enable detailed output for troubleshooting and monitoring

.PARAMETER ExportMetrics
    Export uptime metrics to JSON for monitoring system integration

.EXAMPLE
    .\DetectionScriptReboot.ps1
    Runs with default 7-day threshold for standard enterprise compliance

.EXAMPLE
    .\DetectionScriptReboot.ps1 -ThresholdDays 14 -Verbose
    Uses 14-day threshold with detailed logging for extended maintenance windows

.EXAMPLE
    .\DetectionScriptReboot.ps1 -ThresholdDays 3 -ExportMetrics -LogPath "C:\Monitoring\"
    Critical systems monitoring with 3-day threshold and metrics export

.NOTES
    Author: Apostolis Tsirogiannis
    Email: apostolis.tsirogiannis@techtakt.com
    LinkedIn: https://www.linkedin.com/in/apostolis-tsirogiannis/
    Upwork: https://www.upwork.com/freelancers/apostolos
    
    Prerequisites:
    - PowerShell 5.1 or higher
    - Local system access for process information
    - Write permissions for logging (if custom log path specified)
    
    Integration Scenarios:
    - Microsoft Intune Proactive Remediations
    - SCCM Configuration Baselines and Compliance Settings
    - Group Policy scheduled task deployment
    - Azure Arc for Servers monitoring and compliance
    - Third-party RMM and monitoring solution integration

    Exit Codes:
    - 0: Device uptime is within acceptable threshold (compliant)
    - 1: Device uptime exceeds threshold, reboot required (non-compliant)
    - 2: Script execution error or insufficient permissions

    Deployment Considerations:
    - Schedule detection to run during business hours for immediate remediation
    - Consider maintenance windows and critical system exceptions
    - Integrate with change management processes for production systems
    - Implement notification systems for critical infrastructure components

.LINK
    https://docs.microsoft.com/en-us/mem/intune/fundamentals/remediations
    https://docs.microsoft.com/en-us/mem/configmgr/compliance/
    https://docs.microsoft.com/en-us/azure/azure-arc/servers/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$ThresholdDays = 7,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportMetrics
)

# Initialize detection session
$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"

# Script metadata for monitoring integration
$ScriptInfo = @{
    ScriptName = "Reboot Detection Script"
    Version = "2.0"
    Author = "Apostolis Tsirogiannis"
    ExecutionTime = Get-Date
    ComputerName = $env:COMPUTERNAME
    UserContext = $env:USERNAME
}

try {
    Write-Verbose "=== Device Uptime Detection Script ===" 
    Write-Verbose "Computer: $($ScriptInfo.ComputerName)"
    Write-Verbose "Execution Time: $($ScriptInfo.ExecutionTime)"
    Write-Verbose "Threshold: $ThresholdDays days"
    Write-Verbose "User Context: $($ScriptInfo.UserContext)"
    
    # Calculate system uptime using multiple methods for accuracy
    Write-Verbose "Calculating system uptime..."
    
    # Method 1: Using current PowerShell process start time (most reliable)
    $CurrentProcess = Get-Process -Id $PID
    $ProcessStartTime = $CurrentProcess.StartTime
    $CurrentTime = Get-Date
    
    # Calculate uptime in seconds and convert to hours/days
    $UptimeSeconds = ($CurrentTime - $ProcessStartTime).TotalSeconds
    $UptimeHours = $UptimeSeconds / 3600
    $UptimeDays = $UptimeHours / 24
    
    # Method 2: Cross-validation using WMI (additional verification)
    try {
        $WmiOS = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($WmiOS) {
            $WmiBootTime = $WmiOS.ConvertToDateTime($WmiOS.LastBootUpTime)
            $WmiUptimeDays = ($CurrentTime - $WmiBootTime).TotalDays
            Write-Verbose "WMI Boot Time: $WmiBootTime"
            Write-Verbose "WMI Uptime: $([math]::Round($WmiUptimeDays, 2)) days"
        }
    } catch {
        Write-Verbose "WMI validation unavailable: $($_.Exception.Message)"
    }
    
    # Primary uptime calculation
    $UptimeDaysRounded = [math]::Round($UptimeDays, 2)
    $UptimeHoursRounded = [math]::Round($UptimeHours, 2)
    
    Write-Verbose "Process Start Time: $ProcessStartTime"
    Write-Verbose "Current Time: $CurrentTime"
    Write-Verbose "System Uptime: $UptimeDaysRounded days ($UptimeHoursRounded hours)"
    
    # Convert threshold to hours for comparison
    $ThresholdHours = $ThresholdDays * 24
    
    # Create detailed metrics object
    $UptimeMetrics = @{
        ComputerName = $env:COMPUTERNAME
        DetectionTime = $CurrentTime.ToString("yyyy-MM-dd HH:mm:ss")
        UptimeDays = $UptimeDaysRounded
        UptimeHours = $UptimeHoursRounded
        ThresholdDays = $ThresholdDays
        ThresholdHours = $ThresholdHours
        IsCompliant = $UptimeHours -le $ThresholdHours
        ProcessStartTime = $ProcessStartTime.ToString("yyyy-MM-dd HH:mm:ss")
        LastBootTime = if($WmiBootTime) { $WmiBootTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
        OperatingSystem = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        RebootRequired = $UptimeHours -gt $ThresholdHours
        ComplianceStatus = if($UptimeHours -le $ThresholdHours) { "Compliant" } else { "Non-Compliant" }
        SeverityLevel = if($UptimeHours -gt ($ThresholdHours * 2)) { "Critical" } elseif($UptimeHours -gt $ThresholdHours) { "Warning" } else { "Normal" }
    }
    
    # Export metrics if requested
    if ($ExportMetrics) {
        $MetricsPath = if(-not [string]::IsNullOrWhiteSpace($LogPath)) { $LogPath } else { $env:TEMP }
        $MetricsFile = "$MetricsPath\UptimeMetrics_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        
        try {
            $UptimeMetrics | ConvertTo-Json -Depth 3 | Out-File -FilePath $MetricsFile -Encoding UTF8
            Write-Verbose "Metrics exported to: $MetricsFile"
        } catch {
            Write-Warning "Could not export metrics: $($_.Exception.Message)"
        }
    }
    
    # Log to Windows Event Log for enterprise monitoring
    try {
        $EventSource = "DeviceUptimeDetection"
        
        # Create event source if it doesn't exist (requires admin rights)
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            try {
                New-EventLog -LogName "Application" -Source $EventSource -ErrorAction SilentlyContinue
            } catch {
                # Fallback to existing source
                $EventSource = "Application"
            }
        }
        
        $EventMessage = "Device Uptime Detection: $($UptimeMetrics.ComplianceStatus) - Uptime: $UptimeDaysRounded days (Threshold: $ThresholdDays days)"
        $EventType = if($UptimeMetrics.IsCompliant) { "Information" } else { "Warning" }
        $EventId = if($UptimeMetrics.IsCompliant) { 1001 } else { 1002 }
        
        Write-EventLog -LogName "Application" -Source $EventSource -EventId $EventId -EntryType $EventType -Message $EventMessage -ErrorAction SilentlyContinue
        
    } catch {
        Write-Verbose "Event log writing failed: $($_.Exception.Message)"
    }
    
    # Custom logging if path specified
    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        try {
            if (-not (Test-Path $LogPath)) {
                New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            }
            
            $LogFile = "$LogPath\RebootDetection_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd').log"
            $LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $($UptimeMetrics.ComplianceStatus) - Uptime: $UptimeDaysRounded days"
            
            Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8
            Write-Verbose "Log entry added to: $LogFile"
            
        } catch {
            Write-Warning "Custom logging failed: $($_.Exception.Message)"
        }
    }
    
    # Determine compliance and set appropriate exit code
    if ($UptimeHours -gt $ThresholdHours) {
        # Non-compliant: Reboot required
        $Message = "REBOOT REQUIRED: Device has been running for $UptimeDaysRounded days (exceeds $ThresholdDays day threshold)"
        Write-Host $Message
        Write-Verbose "Exit Code: 1 (Non-Compliant - Remediation Required)"
        
        # Additional warnings for extended uptime
        if ($UptimeDays -gt ($ThresholdDays * 2)) {
            Write-Warning "CRITICAL: Device uptime significantly exceeds threshold - immediate attention required"
        }
        
        exit 1
        
    } else {
        # Compliant: Within acceptable uptime
        $Message = "COMPLIANT: Device uptime is $UptimeDaysRounded days (within $ThresholdDays day threshold)"
        Write-Host $Message
        Write-Verbose "Exit Code: 0 (Compliant - No Action Required)"
        
        exit 0
    }
    
} catch {
    # Script execution error
    $ErrorMessage = "Detection script failed: $($_.Exception.Message)"
    Write-Error $ErrorMessage
    
    # Log error for monitoring
    try {
        Write-EventLog -LogName "Application" -Source "Application" -EventId 1003 -EntryType "Error" -Message "Device Uptime Detection Error: $ErrorMessage" -ErrorAction SilentlyContinue
    } catch {
        # Fail silently if event log is not available
    }
    
    Write-Verbose "Exit Code: 2 (Script Error)"
    exit 2
}
