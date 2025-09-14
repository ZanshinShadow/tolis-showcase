<#
.SYNOPSIS
    Disk Space Detection Script - Enterprise Storage Management

.DESCRIPTION
    This PowerShell detection script provides automated monitoring for disk space compliance
    in enterprise environments. It analyzes available disk space across all system drives
    against configurable thresholds and integrates with Microsoft Intune, SCCM, or other
    endpoint management solutions for automated storage remediation workflows.

    Detection Features:
    - Comprehensive disk space analysis across all mounted drives
    - Configurable threshold detection for storage compliance requirements
    - Intelligent drive filtering to exclude network and removable drives
    - Exit code integration for automated remediation triggering
    - Detailed logging for enterprise monitoring and capacity planning
    - Support for various deployment scenarios (Intune, SCCM, Group Policy)

    Enterprise Use Cases:
    - Automated storage compliance monitoring for system reliability
    - Proactive disk space management and cleanup automation
    - Capacity planning and storage optimization workflows
    - Integration with endpoint management and monitoring solutions
    - Prevention of system failures due to insufficient disk space

.PARAMETER ThresholdPercent
    Minimum percentage of free disk space required (default: 10%)

.PARAMETER ExcludeNetworkDrives
    Switch to exclude network mapped drives from analysis (default: enabled)

.PARAMETER ExcludeRemovableDrives
    Switch to exclude removable drives (USB, CD/DVD) from analysis (default: enabled)

.PARAMETER MinimumDriveSize
    Minimum drive size in GB to include in analysis (default: 1GB - excludes small system partitions)

.PARAMETER LogPath
    Optional path for detailed operation logging (default: Windows event log)

.PARAMETER ExportMetrics
    Export disk space metrics to JSON for monitoring system integration

.PARAMETER Verbose
    Enable detailed output for troubleshooting and monitoring

.EXAMPLE
    .\DetectionScript.ps1
    Runs with default 10% threshold for standard enterprise compliance

.EXAMPLE
    .\DetectionScript.ps1 -ThresholdPercent 15 -Verbose
    Uses 15% threshold with detailed logging for systems requiring higher free space

.EXAMPLE
    .\DetectionScript.ps1 -ThresholdPercent 5 -MinimumDriveSize 10 -ExportMetrics
    Critical systems monitoring with 5% threshold for drives larger than 10GB

.EXAMPLE
    .\DetectionScript.ps1 -ThresholdPercent 20 -LogPath "C:\Monitoring\" -ExcludeRemovableDrives:$false
    High-availability systems with 20% threshold including removable drives

.NOTES
    Author: Apostolis Tsirogiannis
    Email: apostolis.tsirogiannis@techtakt.com
    LinkedIn: https://www.linkedin.com/in/apostolis-tsirogiannis/
    Upwork: https://www.upwork.com/freelancers/apostolos
    
    Prerequisites:
    - PowerShell 5.1 or higher
    - Local system access for drive information
    - Write permissions for logging (if custom log path specified)
    
    Integration Scenarios:
    - Microsoft Intune Proactive Remediations
    - SCCM Configuration Baselines and Compliance Settings
    - Group Policy scheduled task deployment
    - Azure Arc for Servers monitoring and compliance
    - Third-party RMM and monitoring solution integration

    Exit Codes:
    - 0: All drives have sufficient free space (compliant)
    - 1: One or more drives below threshold, cleanup required (non-compliant)
    - 2: Script execution error or insufficient permissions

    Deployment Considerations:
    - Schedule detection to run multiple times daily for proactive monitoring
    - Consider different thresholds for system vs. data drives
    - Integrate with automated cleanup and maintenance workflows
    - Implement alerting for critical storage situations

.LINK
    https://docs.microsoft.com/en-us/mem/intune/fundamentals/remediations
    https://docs.microsoft.com/en-us/mem/configmgr/compliance/
    https://docs.microsoft.com/en-us/azure/azure-arc/servers/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50)]
    [int]$ThresholdPercent = 10,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExcludeNetworkDrives,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExcludeRemovableDrives,
    
    [Parameter(Mandatory = $false)]
    [double]$MinimumDriveSize = 1, # GB
    
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
    ScriptName = "Disk Space Detection Script"
    Version = "2.0"
    Author = "Apostolis Tsirogiannis"
    ExecutionTime = Get-Date
    ComputerName = $env:COMPUTERNAME
    UserContext = $env:USERNAME
}

try {
    Write-Verbose "=== Disk Space Detection Script ==="
    Write-Verbose "Computer: $($ScriptInfo.ComputerName)"
    Write-Verbose "Execution Time: $($ScriptInfo.ExecutionTime)"
    Write-Verbose "Threshold: $ThresholdPercent% free space"
    Write-Verbose "User Context: $($ScriptInfo.UserContext)"
    Write-Verbose "Minimum Drive Size: $MinimumDriveSize GB"
    
    # Set default behavior for switches (exclude network and removable drives by default)
    $ExcludeNetworkDrivesEnabled = $ExcludeNetworkDrives.IsPresent -or $PSBoundParameters.ContainsKey('ExcludeNetworkDrives') -eq $false
    $ExcludeRemovableDrivesEnabled = $ExcludeRemovableDrives.IsPresent -or $PSBoundParameters.ContainsKey('ExcludeRemovableDrives') -eq $false
    
    Write-Verbose "Exclude Network Drives: $ExcludeNetworkDrivesEnabled"
    Write-Verbose "Exclude Removable Drives: $ExcludeRemovableDrivesEnabled"
    
    # Get all FileSystem drives with sophisticated filtering
    Write-Verbose "Analyzing system drives..."
    
    $AllDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Used -ne $null -and 
        $_.Free -ne $null -and 
        $_.Used -gt 0 -and 
        $_.Free -gt 0
    }
    
    Write-Verbose "Found $($AllDrives.Count) potential drives for analysis"
    
    # Apply filtering based on parameters
    $FilteredDrives = $AllDrives | Where-Object {
        $drive = $_
        $include = $true
        
        # Calculate total size in GB
        $totalSizeGB = [math]::Round(($drive.Used + $drive.Free) / 1GB, 2)
        
        # Filter by minimum size
        if ($totalSizeGB -lt $MinimumDriveSize) {
            Write-Verbose "Excluding drive $($drive.Name): Size $totalSizeGB GB below minimum $MinimumDriveSize GB"
            $include = $false
        }
        
        # Get detailed drive information for additional filtering
        try {
            $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($drive.Name):'" -ErrorAction SilentlyContinue
            
            if ($driveInfo) {
                # Filter network drives
                if ($ExcludeNetworkDrivesEnabled -and $driveInfo.DriveType -eq 4) {
                    Write-Verbose "Excluding network drive $($drive.Name):"
                    $include = $false
                }
                
                # Filter removable drives
                if ($ExcludeRemovableDrivesEnabled -and ($driveInfo.DriveType -eq 2 -or $driveInfo.DriveType -eq 5)) {
                    Write-Verbose "Excluding removable drive $($drive.Name): (Type: $($driveInfo.DriveType))"
                    $include = $false
                }
            }
        } catch {
            Write-Verbose "Could not get detailed info for drive $($drive.Name): - including in analysis"
        }
        
        return $include
    }
    
    Write-Verbose "Analyzing $($FilteredDrives.Count) drives after filtering"
    
    if ($FilteredDrives.Count -eq 0) {
        Write-Warning "No drives found matching the specified criteria"
        exit 2
    }
    
    # Analyze disk space for each filtered drive
    $DriveAnalysis = @()
    $LowSpaceDetected = $false
    $CriticalSpaceDetected = $false
    
    foreach ($drive in $FilteredDrives) {
        try {
            # Calculate space metrics
            $totalSpace = $drive.Used + $drive.Free
            $percentFree = [math]::Round(($drive.Free / $totalSpace) * 100, 2)
            $percentUsed = [math]::Round(($drive.Used / $totalSpace) * 100, 2)
            
            # Convert to human-readable sizes
            $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
            $usedSpaceGB = [math]::Round($drive.Used / 1GB, 2)
            $totalSpaceGB = [math]::Round($totalSpace / 1GB, 2)
            
            # Get additional drive information
            $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($drive.Name):'" -ErrorAction SilentlyContinue
            $driveLabel = if($driveInfo -and $driveInfo.VolumeName) { $driveInfo.VolumeName } else { "Local Disk" }
            $driveType = if($driveInfo) { 
                switch ($driveInfo.DriveType) {
                    2 { "Removable" }
                    3 { "Fixed" }
                    4 { "Network" }
                    5 { "CD-ROM" }
                    default { "Unknown" }
                }
            } else { "Unknown" }
            
            # Determine compliance status
            $isCompliant = $percentFree -ge $ThresholdPercent
            $severityLevel = if ($percentFree -lt ($ThresholdPercent / 2)) { "Critical" } 
                           elseif ($percentFree -lt $ThresholdPercent) { "Warning" } 
                           else { "Normal" }
            
            # Create drive analysis object
            $analysis = [PSCustomObject]@{
                DriveLetter = $drive.Name
                DriveLabel = $driveLabel
                DriveType = $driveType
                TotalSpaceGB = $totalSpaceGB
                UsedSpaceGB = $usedSpaceGB
                FreeSpaceGB = $freeSpaceGB
                PercentFree = $percentFree
                PercentUsed = $percentUsed
                IsCompliant = $isCompliant
                SeverityLevel = $severityLevel
                ThresholdPercent = $ThresholdPercent
            }
            
            $DriveAnalysis += $analysis
            
            # Update detection flags
            if (-not $isCompliant) {
                $LowSpaceDetected = $true
                if ($severityLevel -eq "Critical") {
                    $CriticalSpaceDetected = $true
                }
            }
            
            # Log drive analysis
            $complianceStatus = if($isCompliant) { "COMPLIANT" } else { "NON-COMPLIANT" }
            Write-Verbose "Drive $($drive.Name): [$complianceStatus] $percentFree% free ($freeSpaceGB GB / $totalSpaceGB GB) - $severityLevel"
            
            if (-not $isCompliant) {
                Write-Host "Drive $($drive.Name): ($driveLabel) Only $percentFree% free space remaining ($freeSpaceGB GB available)"
            }
            
        } catch {
            Write-Warning "Error analyzing drive $($drive.Name):: $($_.Exception.Message)"
        }
    }
    
    # Create comprehensive metrics object
    $DiskSpaceMetrics = @{
        ComputerName = $env:COMPUTERNAME
        DetectionTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        ThresholdPercent = $ThresholdPercent
        TotalDrivesAnalyzed = $DriveAnalysis.Count
        CompliantDrives = ($DriveAnalysis | Where-Object IsCompliant).Count
        NonCompliantDrives = ($DriveAnalysis | Where-Object { -not $_.IsCompliant }).Count
        CriticalDrives = ($DriveAnalysis | Where-Object { $_.SeverityLevel -eq "Critical" }).Count
        WarningDrives = ($DriveAnalysis | Where-Object { $_.SeverityLevel -eq "Warning" }).Count
        OverallCompliance = -not $LowSpaceDetected
        HasCriticalIssues = $CriticalSpaceDetected
        DriveDetails = $DriveAnalysis
        OperatingSystem = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        TotalSystemStorage = [math]::Round(($DriveAnalysis | Measure-Object TotalSpaceGB -Sum).Sum, 2)
        TotalFreeStorage = [math]::Round(($DriveAnalysis | Measure-Object FreeSpaceGB -Sum).Sum, 2)
        SystemStorageUtilization = [math]::Round((1 - (($DriveAnalysis | Measure-Object FreeSpaceGB -Sum).Sum / ($DriveAnalysis | Measure-Object TotalSpaceGB -Sum).Sum)) * 100, 2)
    }
    
    # Export metrics if requested
    if ($ExportMetrics) {
        $MetricsPath = if(-not [string]::IsNullOrWhiteSpace($LogPath)) { $LogPath } else { $env:TEMP }
        $MetricsFile = "$MetricsPath\DiskSpaceMetrics_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        
        try {
            if (-not (Test-Path (Split-Path $MetricsFile -Parent))) {
                New-Item -Path (Split-Path $MetricsFile -Parent) -ItemType Directory -Force | Out-Null
            }
            
            $DiskSpaceMetrics | ConvertTo-Json -Depth 4 | Out-File -FilePath $MetricsFile -Encoding UTF8
            Write-Verbose "Metrics exported to: $MetricsFile"
        } catch {
            Write-Warning "Could not export metrics: $($_.Exception.Message)"
        }
    }
    
    # Log to Windows Event Log for enterprise monitoring
    try {
        $EventSource = "DiskSpaceDetection"
        
        # Create event source if it doesn't exist (requires admin rights)
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            try {
                New-EventLog -LogName "Application" -Source $EventSource -ErrorAction SilentlyContinue
            } catch {
                # Fallback to existing source
                $EventSource = "Application"
            }
        }
        
        $EventMessage = "Disk Space Detection: $($DiskSpaceMetrics.NonCompliantDrives) of $($DiskSpaceMetrics.TotalDrivesAnalyzed) drives below $ThresholdPercent% threshold"
        $EventType = if($DiskSpaceMetrics.OverallCompliance) { "Information" } elseif($DiskSpaceMetrics.HasCriticalIssues) { "Error" } else { "Warning" }
        $EventId = if($DiskSpaceMetrics.OverallCompliance) { 3001 } elseif($DiskSpaceMetrics.HasCriticalIssues) { 3003 } else { 3002 }
        
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
            
            $LogFile = "$LogPath\DiskSpaceDetection_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd').log"
            $LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Compliance: $($DiskSpaceMetrics.OverallCompliance) - $($DiskSpaceMetrics.NonCompliantDrives)/$($DiskSpaceMetrics.TotalDrivesAnalyzed) drives below threshold"
            
            Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8
            Write-Verbose "Log entry added to: $LogFile"
            
        } catch {
            Write-Warning "Custom logging failed: $($_.Exception.Message)"
        }
    }
    
    # Display summary information
    Write-Verbose "`nDisk Space Analysis Summary:"
    Write-Verbose "Total Drives Analyzed: $($DiskSpaceMetrics.TotalDrivesAnalyzed)"
    Write-Verbose "Compliant Drives: $($DiskSpaceMetrics.CompliantDrives)"
    Write-Verbose "Non-Compliant Drives: $($DiskSpaceMetrics.NonCompliantDrives)"
    Write-Verbose "Critical Issues: $($DiskSpaceMetrics.CriticalDrives)"
    Write-Verbose "Overall System Storage Utilization: $($DiskSpaceMetrics.SystemStorageUtilization)%"
    
    # Determine compliance and set appropriate exit code
    if ($LowSpaceDetected) {
        # Non-compliant: Disk cleanup required
        $Message = "DISK CLEANUP REQUIRED: $($DiskSpaceMetrics.NonCompliantDrives) drive(s) below $ThresholdPercent% free space threshold"
        Write-Host $Message
        Write-Verbose "Exit Code: 1 (Non-Compliant - Remediation Required)"
        
        # Additional warnings for critical space issues
        if ($CriticalSpaceDetected) {
            Write-Warning "CRITICAL: One or more drives have extremely low free space - immediate attention required"
        }
        
        exit 1
        
    } else {
        # Compliant: All drives have sufficient space
        $Message = "COMPLIANT: All $($DiskSpaceMetrics.TotalDrivesAnalyzed) drive(s) have more than $ThresholdPercent% free space"
        Write-Host $Message
        Write-Verbose "Exit Code: 0 (Compliant - No Action Required)"
        
        exit 0
    }
    
} catch {
    # Script execution error
    $ErrorMessage = "Disk space detection script failed: $($_.Exception.Message)"
    Write-Error $ErrorMessage
    
    # Log error for monitoring
    try {
        Write-EventLog -LogName "Application" -Source "Application" -EventId 3004 -EntryType "Error" -Message "Disk Space Detection Error: $ErrorMessage" -ErrorAction SilentlyContinue
    } catch {
        # Fail silently if event log is not available
    }
    
    Write-Verbose "Exit Code: 2 (Script Error)"
    exit 2
}
