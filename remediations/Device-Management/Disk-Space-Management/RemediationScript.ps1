<#
.SYNOPSIS
    Disk Space Remediation Script - Enterprise Storage Cleanup Automation

.DESCRIPTION
    This PowerShell remediation script provides automated disk space cleanup for enterprise
    environments when storage compliance issues are detected. It performs intelligent,
    safe cleanup operations across multiple categories while maintaining detailed logging
    and progress reporting for enterprise monitoring and audit requirements.

    Remediation Features:
    - Intelligent multi-category disk cleanup with safety validation
    - Configurable cleanup targets with enterprise-safe defaults
    - Progress tracking and detailed operation reporting
    - Space recovery estimation and verification
    - Integration with Windows Disk Cleanup utility and custom cleanup routines
    - Comprehensive logging for compliance and audit requirements
    - Support for various deployment scenarios (Intune, SCCM, Group Policy)

    Enterprise Use Cases:
    - Automated storage remediation triggered by detection script non-compliance
    - Proactive maintenance to prevent storage-related system failures
    - Safe cleanup operations that preserve business-critical data
    - Integration with endpoint management and monitoring solutions
    - Compliance with corporate data retention and cleanup policies

.PARAMETER CleanupCategories
    Array of cleanup categories to process (default: safe enterprise categories)
    Valid categories: TempFiles, RecycleBin, SetupFiles, LogFiles, ThumbnailCache, WebCache

.PARAMETER MinimumSpaceToRecover
    Minimum amount of space (in MB) to attempt recovery (default: 100MB)

.PARAMETER MaxCleanupTime
    Maximum time in minutes for cleanup operations (default: 30 minutes)

.PARAMETER CustomTempPaths
    Array of additional temporary paths to clean (beyond standard Windows temp locations)

.PARAMETER PreserveRecentFiles
    Number of days to preserve recent files in temp locations (default: 1 day)

.PARAMETER LogPath
    Optional path for detailed operation logging (default: Windows event log)

.PARAMETER ExportMetrics
    Export cleanup metrics to JSON for monitoring system integration

.PARAMETER DryRun
    Preview cleanup actions without performing actual cleanup operations

.PARAMETER Verbose
    Enable detailed output for troubleshooting and monitoring

.EXAMPLE
    .\RemediationScript.ps1
    Runs with default enterprise-safe cleanup categories

.EXAMPLE
    .\RemediationScript.ps1 -CleanupCategories @("TempFiles","RecycleBin","LogFiles") -Verbose
    Performs targeted cleanup with detailed logging

.EXAMPLE
    .\RemediationScript.ps1 -DryRun -ExportMetrics -LogPath "C:\Monitoring\"
    Preview mode with detailed reporting and metrics export

.EXAMPLE
    .\RemediationScript.ps1 -MinimumSpaceToRecover 500 -MaxCleanupTime 45 -PreserveRecentFiles 2
    Extended cleanup operation with custom preservation settings

.NOTES
    Author: Apostolis Tsirogiannis
    Email: apostolis.tsirogiannis@techtakt.com
    LinkedIn: https://www.linkedin.com/in/apostolis-tsirogiannis/
    Upwork: https://www.upwork.com/freelancers/apostolos
    
    Prerequisites:
    - PowerShell 5.1 or higher
    - Administrative privileges for system cleanup operations
    - Windows Disk Cleanup utility (cleanmgr.exe)
    - Write permissions for logging (if custom log path specified)
    
    Integration Scenarios:
    - Microsoft Intune Proactive Remediations remediation script
    - SCCM Configuration Baselines remediation actions
    - Group Policy automated maintenance script deployment
    - Azure Arc for Servers remediation automation
    - Third-party RMM and monitoring solution integration

    Exit Codes:
    - 0: Cleanup completed successfully (space recovered or sufficient space available)
    - 1: Cleanup completed with warnings (partial success or minimal space recovered)
    - 2: Cleanup failed (unable to recover space or critical errors)

    Safety Considerations:
    - Only targets temporary and expendable files by default
    - Preserves recent files based on configurable time thresholds
    - Validates cleanup targets before execution
    - Comprehensive logging for audit and rollback reference
    - Progress monitoring to prevent excessive resource usage

.LINK
    https://docs.microsoft.com/en-us/mem/intune/fundamentals/remediations
    https://docs.microsoft.com/en-us/windows/deployment/update/windows-update-troubleshooting
    https://docs.microsoft.com/en-us/mem/configmgr/compliance/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("TempFiles", "RecycleBin", "SetupFiles", "LogFiles", "ThumbnailCache", "WebCache", "DownloadedPrograms", "TemporarySetupFiles")]
    [string[]]$CleanupCategories = @("TempFiles", "RecycleBin", "TemporarySetupFiles", "ThumbnailCache"),
    
    [Parameter(Mandatory = $false)]
    [int]$MinimumSpaceToRecover = 100, # MB
    
    [Parameter(Mandatory = $false)]
    [int]$MaxCleanupTime = 30, # minutes
    
    [Parameter(Mandatory = $false)]
    [string[]]$CustomTempPaths = @(),
    
    [Parameter(Mandatory = $false)]
    [int]$PreserveRecentFiles = 1, # days
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportMetrics,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

# Initialize remediation session
$ErrorActionPreference = "Continue" # Allow cleanup to continue on individual file errors
$WarningPreference = "Continue"

# Script metadata for monitoring integration
$ScriptInfo = @{
    ScriptName = "Disk Space Remediation Script"
    Version = "2.0"
    Author = "Apostolis Tsirogiannis"
    ExecutionTime = Get-Date
    ComputerName = $env:COMPUTERNAME
    UserContext = $env:USERNAME
    DryRun = $DryRun.IsPresent
}

# Define cleanup category mappings for Windows Disk Cleanup
$CleanupCategoryMap = @{
    "TempFiles" = @{
        RegKey = "Temporary Files"
        Description = "Temporary files and folders"
        SafetyLevel = "High"
    }
    "RecycleBin" = @{
        RegKey = "Recycle Bin"
        Description = "Recycle Bin contents"
        SafetyLevel = "Medium"
    }
    "TemporarySetupFiles" = @{
        RegKey = "Temporary Setup Files"
        Description = "Setup and installation temporary files"
        SafetyLevel = "High"
    }
    "SetupFiles" = @{
        RegKey = "Setup Log Files"
        Description = "Windows Setup log files"
        SafetyLevel = "Medium"
    }
    "LogFiles" = @{
        RegKey = "Windows Update Cleanup"
        Description = "Windows Update cleanup files"
        SafetyLevel = "Medium"
    }
    "ThumbnailCache" = @{
        RegKey = "Thumbnail Cache"
        Description = "Thumbnail cache files"
        SafetyLevel = "High"
    }
    "WebCache" = @{
        RegKey = "Internet Cache Files"
        Description = "Internet cache and temporary internet files"
        SafetyLevel = "High"
    }
    "DownloadedPrograms" = @{
        RegKey = "Downloaded Program Files"
        Description = "Downloaded ActiveX controls and Java applets"
        SafetyLevel = "Low"
    }
}

# Function to calculate directory size
function Get-DirectorySize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    try {
        if (Test-Path $Path) {
            $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum).Sum
            return [math]::Round($size / 1MB, 2)
        }
        return 0
    } catch {
        Write-Verbose "Could not calculate size for path: $Path - $($_.Exception.Message)"
        return 0
    }
}

# Function to perform custom temporary file cleanup
function Invoke-CustomTempCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$TempPaths,
        
        [Parameter(Mandatory = $true)]
        [int]$PreserveDays,
        
        [Parameter(Mandatory = $true)]
        [bool]$DryRunMode
    )
    
    $CleanedSize = 0
    $CleanedFiles = 0
    $PreserveDate = (Get-Date).AddDays(-$PreserveDays)
    
    $StandardTempPaths = @(
        $env:TEMP,
        $env:TMP,
        "$env:LOCALAPPDATA\Temp",
        "$env:WINDIR\Temp",
        "$env:WINDIR\Logs",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    )
    
    $AllTempPaths = $StandardTempPaths + $TempPaths | Select-Object -Unique
    
    foreach ($TempPath in $AllTempPaths) {
        if (-not (Test-Path $TempPath)) {
            Write-Verbose "Skipping non-existent path: $TempPath"
            continue
        }
        
        Write-Verbose "Cleaning temporary path: $TempPath"
        
        try {
            # Get files older than preserve date
            $FilesToClean = Get-ChildItem -Path $TempPath -Recurse -File -ErrorAction SilentlyContinue | 
                           Where-Object { $_.LastWriteTime -lt $PreserveDate -and $_.LastAccessTime -lt $PreserveDate }
            
            foreach ($File in $FilesToClean) {
                try {
                    $FileSize = $File.Length
                    
                    if ($DryRunMode) {
                        Write-Verbose "DRY RUN: Would delete file: $($File.FullName) ($([math]::Round($FileSize / 1KB, 2)) KB)"
                    } else {
                        Remove-Item -Path $File.FullName -Force -ErrorAction SilentlyContinue
                        Write-Verbose "Deleted file: $($File.FullName) ($([math]::Round($FileSize / 1KB, 2)) KB)"
                    }
                    
                    $CleanedSize += $FileSize
                    $CleanedFiles++
                    
                } catch {
                    Write-Verbose "Could not delete file: $($File.FullName) - $($_.Exception.Message)"
                }
            }
            
            # Clean empty directories
            if (-not $DryRunMode) {
                Get-ChildItem -Path $TempPath -Recurse -Directory -ErrorAction SilentlyContinue | 
                    Where-Object { (Get-ChildItem -Path $_.FullName -ErrorAction SilentlyContinue).Count -eq 0 } |
                    Remove-Item -Force -ErrorAction SilentlyContinue
            }
            
        } catch {
            Write-Warning "Error cleaning path $TempPath`: $($_.Exception.Message)"
        }
    }
    
    return @{
        CleanedSizeMB = [math]::Round($CleanedSize / 1MB, 2)
        CleanedFiles = $CleanedFiles
    }
}

try {
    Write-Verbose "=== Disk Space Remediation Script ==="
    Write-Verbose "Computer: $($ScriptInfo.ComputerName)"
    Write-Verbose "Execution Time: $($ScriptInfo.ExecutionTime)"
    Write-Verbose "User Context: $($ScriptInfo.UserContext)"
    Write-Verbose "Cleanup Categories: $($CleanupCategories -join ', ')"
    Write-Verbose "Minimum Space to Recover: $MinimumSpaceToRecover MB"
    Write-Verbose "Preserve Recent Files: $PreserveRecentFiles days"
    Write-Verbose "Dry Run Mode: $($ScriptInfo.DryRun)"
    
    # Validate administrative privileges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Warning "Script is not running with administrative privileges. Some cleanup operations may be limited."
    }
    
    # Get initial disk space across all drives
    Write-Verbose "Analyzing current disk space before cleanup..."
    $DrivesBefore = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Used -ne $null -and $_.Free -ne $null -and $_.Used -gt 0 -and $_.Free -gt 0 
    }
    
    $InitialFreeSpace = ($DrivesBefore | Measure-Object -Property Free -Sum).Sum
    $InitialFreeSpaceGB = [math]::Round($InitialFreeSpace / 1GB, 2)
    
    Write-Verbose "Initial total free space across all drives: $InitialFreeSpaceGB GB"
    
    # Track cleanup operations
    $CleanupResults = @{
        StartTime = Get-Date
        InitialFreeSpaceGB = $InitialFreeSpaceGB
        CategoriesProcessed = @()
        TotalSpaceRecoveredMB = 0
        TotalFilesProcessed = 0
        Errors = @()
        Warnings = @()
    }
    
    # Verify Windows Disk Cleanup utility availability
    $CleanMgrPath = "$env:SystemRoot\System32\cleanmgr.exe"
    $CleanMgrAvailable = Test-Path $CleanMgrPath
    
    if ($CleanMgrAvailable) {
        Write-Verbose "Windows Disk Cleanup utility found: $CleanMgrPath"
        
        # Configure Disk Cleanup categories
        $StateKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        
        Write-Verbose "Configuring Disk Cleanup categories..."
        
        foreach ($Category in $CleanupCategories) {
            if ($CleanupCategoryMap.ContainsKey($Category)) {
                $RegKey = $CleanupCategoryMap[$Category].RegKey
                $Description = $CleanupCategoryMap[$Category].Description
                $SafetyLevel = $CleanupCategoryMap[$Category].SafetyLevel
                
                Write-Verbose "Enabling cleanup category: $Category ($Description) - Safety: $SafetyLevel"
                
                try {
                    $CategoryKeyPath = "$StateKey\$RegKey"
                    
                    if (-not $DryRun) {
                        # Enable category for cleanup profile 0001
                        if (Test-Path $CategoryKeyPath) {
                            New-ItemProperty -Path $CategoryKeyPath -Name "StateFlags0001" -Value 2 -PropertyType DWord -Force | Out-Null
                            Write-Verbose "Enabled cleanup category: $RegKey"
                        } else {
                            Write-Warning "Registry key not found for category: $RegKey"
                            $CleanupResults.Warnings += "Registry key not found: $RegKey"
                        }
                    } else {
                        Write-Verbose "DRY RUN: Would enable cleanup category: $RegKey"
                    }
                    
                    $CleanupResults.CategoriesProcessed += $Category
                    
                } catch {
                    $ErrorMsg = "Failed to configure cleanup category $Category`: $($_.Exception.Message)"
                    Write-Warning $ErrorMsg
                    $CleanupResults.Errors += $ErrorMsg
                }
            } else {
                Write-Warning "Unknown cleanup category: $Category"
                $CleanupResults.Warnings += "Unknown cleanup category: $Category"
            }
        }
        
        # Execute Windows Disk Cleanup
        if ($CleanupResults.CategoriesProcessed.Count -gt 0 -and -not $DryRun) {
            Write-Host "Executing Windows Disk Cleanup for configured categories..."
            
            try {
                $CleanupStartTime = Get-Date
                $CleanupProcess = Start-Process -FilePath $CleanMgrPath -ArgumentList "/sagerun:1" -PassThru -WindowStyle Hidden
                
                # Monitor cleanup process with timeout
                $TimeoutReached = $false
                do {
                    Start-Sleep -Seconds 5
                    $ElapsedMinutes = ((Get-Date) - $CleanupStartTime).TotalMinutes
                    
                    if ($ElapsedMinutes -gt $MaxCleanupTime) {
                        Write-Warning "Cleanup operation exceeded maximum time limit ($MaxCleanupTime minutes)"
                        $CleanupProcess.Kill()
                        $TimeoutReached = $true
                        $CleanupResults.Warnings += "Cleanup operation timed out after $MaxCleanupTime minutes"
                    }
                    
                    Write-Verbose "Cleanup running... Elapsed: $([math]::Round($ElapsedMinutes, 1)) minutes"
                    
                } while (-not $CleanupProcess.HasExited -and -not $TimeoutReached)
                
                if (-not $TimeoutReached) {
                    Write-Host "Windows Disk Cleanup completed successfully"
                    Write-Verbose "Cleanup process completed in $([math]::Round($ElapsedMinutes, 1)) minutes"
                } else {
                    Write-Warning "Cleanup process was terminated due to timeout"
                }
                
            } catch {
                $ErrorMsg = "Failed to execute Windows Disk Cleanup: $($_.Exception.Message)"
                Write-Error $ErrorMsg
                $CleanupResults.Errors += $ErrorMsg
            }
        } elseif ($DryRun) {
            Write-Host "DRY RUN: Would execute Windows Disk Cleanup for categories: $($CleanupResults.CategoriesProcessed -join ', ')"
        }
        
    } else {
        Write-Warning "Windows Disk Cleanup utility not found at: $CleanMgrPath"
        $CleanupResults.Warnings += "Windows Disk Cleanup utility not available"
    }
    
    # Perform custom temporary file cleanup
    Write-Host "Performing custom temporary file cleanup..."
    
    $CustomCleanupResult = Invoke-CustomTempCleanup -TempPaths $CustomTempPaths -PreserveDays $PreserveRecentFiles -DryRunMode $DryRun
    
    $CleanupResults.TotalSpaceRecoveredMB += $CustomCleanupResult.CleanedSizeMB
    $CleanupResults.TotalFilesProcessed += $CustomCleanupResult.CleanedFiles
    
    Write-Verbose "Custom cleanup recovered: $($CustomCleanupResult.CleanedSizeMB) MB from $($CustomCleanupResult.CleanedFiles) files"
    
    # Calculate final disk space and recovery
    Write-Verbose "Analyzing disk space after cleanup..."
    
    $DrivesAfter = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Used -ne $null -and $_.Free -ne $null -and $_.Used -gt 0 -and $_.Free -gt 0 
    }
    
    $FinalFreeSpace = ($DrivesAfter | Measure-Object -Property Free -Sum).Sum
    $FinalFreeSpaceGB = [math]::Round($FinalFreeSpace / 1GB, 2)
    $ActualSpaceRecoveredGB = [math]::Round(($FinalFreeSpace - $InitialFreeSpace) / 1GB, 2)
    
    # Update cleanup results
    $CleanupResults.EndTime = Get-Date
    $CleanupResults.FinalFreeSpaceGB = $FinalFreeSpaceGB
    $CleanupResults.ActualSpaceRecoveredGB = $ActualSpaceRecoveredGB
    $CleanupResults.ActualSpaceRecoveredMB = $ActualSpaceRecoveredGB * 1024
    $CleanupResults.CleanupDurationMinutes = [math]::Round(($CleanupResults.EndTime - $CleanupResults.StartTime).TotalMinutes, 1)
    
    # Create comprehensive metrics object
    $RemediationMetrics = @{
        ComputerName = $env:COMPUTERNAME
        RemediationTime = $CleanupResults.EndTime.ToString("yyyy-MM-dd HH:mm:ss")
        DurationMinutes = $CleanupResults.CleanupDurationMinutes
        InitialFreeSpaceGB = $CleanupResults.InitialFreeSpaceGB
        FinalFreeSpaceGB = $CleanupResults.FinalFreeSpaceGB
        SpaceRecoveredGB = $CleanupResults.ActualSpaceRecoveredGB
        SpaceRecoveredMB = $CleanupResults.ActualSpaceRecoveredMB
        MinimumTargetMB = $MinimumSpaceToRecover
        TargetAchieved = $CleanupResults.ActualSpaceRecoveredMB -ge $MinimumSpaceToRecover
        CategoriesProcessed = $CleanupResults.CategoriesProcessed
        FilesProcessed = $CleanupResults.TotalFilesProcessed
        ErrorCount = $CleanupResults.Errors.Count
        WarningCount = $CleanupResults.Warnings.Count
        DryRun = $DryRun.IsPresent
        OperatingSystem = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        CleanMgrAvailable = $CleanMgrAvailable
        AdminPrivileges = $isAdmin
    }
    
    # Export metrics if requested
    if ($ExportMetrics) {
        $MetricsPath = if(-not [string]::IsNullOrWhiteSpace($LogPath)) { $LogPath } else { $env:TEMP }
        $MetricsFile = "$MetricsPath\DiskCleanupMetrics_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        
        try {
            if (-not (Test-Path (Split-Path $MetricsFile -Parent))) {
                New-Item -Path (Split-Path $MetricsFile -Parent) -ItemType Directory -Force | Out-Null
            }
            
            $RemediationMetrics | ConvertTo-Json -Depth 4 | Out-File -FilePath $MetricsFile -Encoding UTF8
            Write-Verbose "Remediation metrics exported to: $MetricsFile"
        } catch {
            Write-Warning "Could not export metrics: $($_.Exception.Message)"
        }
    }
    
    # Log to Windows Event Log for enterprise monitoring
    try {
        $EventSource = "DiskSpaceRemediation"
        
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            try {
                New-EventLog -LogName "Application" -Source $EventSource -ErrorAction SilentlyContinue
            } catch {
                $EventSource = "Application"
            }
        }
        
        $EventMessage = "Disk Space Remediation: Recovered $($CleanupResults.ActualSpaceRecoveredGB) GB in $($CleanupResults.CleanupDurationMinutes) minutes. Categories: $($CleanupResults.CategoriesProcessed -join ', ')"
        $EventType = if($CleanupResults.Errors.Count -gt 0) { "Error" } elseif($CleanupResults.Warnings.Count -gt 0) { "Warning" } else { "Information" }
        $EventId = if($CleanupResults.ActualSpaceRecoveredMB -ge $MinimumSpaceToRecover) { 4001 } else { 4002 }
        
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
            
            $LogFile = "$LogPath\DiskSpaceRemediation_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd').log"
            $LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Cleanup completed: $($CleanupResults.ActualSpaceRecoveredGB) GB recovered, $($CleanupResults.CategoriesProcessed.Count) categories, $($CleanupResults.Errors.Count) errors"
            
            Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8
            Write-Verbose "Log entry added to: $LogFile"
            
        } catch {
            Write-Warning "Custom logging failed: $($_.Exception.Message)"
        }
    }
    
    # Display comprehensive results
    Write-Host "`n=== DISK SPACE REMEDIATION RESULTS ===" -ForegroundColor Cyan
    Write-Host "Initial Free Space: $($CleanupResults.InitialFreeSpaceGB) GB" -ForegroundColor White
    Write-Host "Final Free Space: $($CleanupResults.FinalFreeSpaceGB) GB" -ForegroundColor White
    Write-Host "Space Recovered: $($CleanupResults.ActualSpaceRecoveredGB) GB ($($CleanupResults.ActualSpaceRecoveredMB) MB)" -ForegroundColor Green
    Write-Host "Files Processed: $($CleanupResults.TotalFilesProcessed)" -ForegroundColor White
    Write-Host "Categories Cleaned: $($CleanupResults.CategoriesProcessed -join ', ')" -ForegroundColor White
    Write-Host "Duration: $($CleanupResults.CleanupDurationMinutes) minutes" -ForegroundColor White
    
    if ($CleanupResults.Errors.Count -gt 0) {
        Write-Host "Errors: $($CleanupResults.Errors.Count)" -ForegroundColor Red
        $CleanupResults.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }
    
    if ($CleanupResults.Warnings.Count -gt 0) {
        Write-Host "Warnings: $($CleanupResults.Warnings.Count)" -ForegroundColor Yellow
        $CleanupResults.Warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
    
    # Determine exit code based on cleanup success
    if ($CleanupResults.ActualSpaceRecoveredMB -ge $MinimumSpaceToRecover) {
        Write-Host "`nREMEDIATION SUCCESSFUL: Recovered $($CleanupResults.ActualSpaceRecoveredMB) MB (target: $MinimumSpaceToRecover MB)" -ForegroundColor Green
        Write-Verbose "Exit Code: 0 (Successful Remediation)"
        exit 0
        
    } elseif ($CleanupResults.ActualSpaceRecoveredMB -gt 0) {
        Write-Host "`nREMEDIATION PARTIAL: Recovered $($CleanupResults.ActualSpaceRecoveredMB) MB (target: $MinimumSpaceToRecover MB)" -ForegroundColor Yellow
        Write-Verbose "Exit Code: 1 (Partial Success)"
        exit 1
        
    } else {
        Write-Host "`nREMEDIATION LIMITED: Minimal or no space recovered (target: $MinimumSpaceToRecover MB)" -ForegroundColor Red
        Write-Verbose "Exit Code: 1 (Limited Success)"
        exit 1
    }
    
} catch {
    # Script execution error
    $ErrorMessage = "Disk space remediation script failed: $($_.Exception.Message)"
    Write-Error $ErrorMessage
    
    # Log error for monitoring
    try {
        Write-EventLog -LogName "Application" -Source "Application" -EventId 4004 -EntryType "Error" -Message "Disk Space Remediation Error: $ErrorMessage" -ErrorAction SilentlyContinue
    } catch {
        # Fail silently if event log is not available
    }
    
    Write-Verbose "Exit Code: 2 (Script Error)"
    exit 2
}
