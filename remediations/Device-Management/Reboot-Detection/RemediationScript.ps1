<#
.SYNOPSIS
    Device Reboot Remediation Script - Enterprise Endpoint Management

.DESCRIPTION
    This PowerShell remediation script provides automated user notification and reboot scheduling
    for enterprise endpoint management solutions. It integrates with Microsoft Intune Proactive
    Remediations, SCCM, and other endpoint management platforms to provide user-friendly reboot
    reminders and scheduling capabilities when devices exceed uptime thresholds.

    Remediation Features:
    - Modern Windows 10/11 toast notification system integration
    - Configurable notification messages and timing
    - Multiple notification delivery attempts with escalation
    - User-friendly reboot scheduling and grace period management
    - Integration with enterprise maintenance windows
    - Detailed logging for compliance and monitoring
    - Support for various deployment scenarios and user contexts

    Enterprise Use Cases:
    - Automated reboot reminders for security patch compliance
    - User education and awareness for device maintenance requirements
    - Graceful handling of device restart requirements in business environments
    - Integration with maintenance windows and change management processes
    - Compliance reporting for device restart policies

.PARAMETER ThresholdDays
    Number of days that triggered the remediation (inherited from detection script)

.PARAMETER NotificationTitle
    Custom title for the toast notification (default: enterprise-friendly message)

.PARAMETER NotificationMessage
    Custom message text for the notification (default: professional business language)

.PARAMETER GracePeriodHours
    Hours to wait before showing additional notifications (default: 4 hours)

.PARAMETER MaxNotifications
    Maximum number of notifications to show per day (default: 3)

.PARAMETER EnableScheduledReboot
    Switch to enable automatic reboot scheduling with user confirmation

.PARAMETER MaintenanceWindowStart
    Start time for maintenance window in 24-hour format (e.g., "18:00")

.PARAMETER MaintenanceWindowEnd
    End time for maintenance window in 24-hour format (e.g., "06:00")

.PARAMETER LogPath
    Optional path for detailed operation logging

.PARAMETER ExportMetrics
    Export remediation metrics for monitoring and reporting

.EXAMPLE
    .\RemediationScript.ps1
    Shows standard reboot reminder notification with enterprise defaults

.EXAMPLE
    .\RemediationScript.ps1 -ThresholdDays 14 -GracePeriodHours 8 -MaxNotifications 2
    Customized notification frequency for extended uptime scenarios

.EXAMPLE
    .\RemediationScript.ps1 -EnableScheduledReboot -MaintenanceWindowStart "20:00" -MaintenanceWindowEnd "06:00"
    Enables automatic reboot scheduling within maintenance window

.EXAMPLE
    .\RemediationScript.ps1 -NotificationTitle "Security Update Required" -NotificationMessage "Please restart to apply critical security updates"
    Custom security-focused messaging for compliance campaigns

.NOTES
    Author: Apostolis Tsirogiannis
    Email: apostolis.tsirogiannis@techtakt.com
    LinkedIn: https://www.linkedin.com/in/apostolis-tsirogiannis/
    Upwork: https://www.upwork.com/freelancers/apostolos
    
    Prerequisites:
    - Windows 10 version 1607 or higher (for toast notifications)
    - PowerShell 5.1 or higher
    - User session context for notification display
    - Write permissions for logging (if custom log path specified)
    
    Integration Scenarios:
    - Microsoft Intune Proactive Remediations remediation script
    - SCCM Configuration Baselines remediation actions
    - Group Policy logon/startup script deployment
    - Azure Arc for Servers remediation automation
    - Third-party RMM and monitoring solution integration

    Exit Codes:
    - 0: Remediation completed successfully (notification shown/reboot scheduled)
    - 1: Remediation partially successful (notification attempted but may have failed)
    - 2: Remediation failed (unable to show notification or schedule reboot)

    User Experience Considerations:
    - Non-intrusive notification system that respects user workflow
    - Clear, professional messaging that explains the business requirement
    - Appropriate timing and frequency to avoid notification fatigue
    - Integration with existing IT communication and change management processes

.LINK
    https://docs.microsoft.com/en-us/mem/intune/fundamentals/remediations
    https://docs.microsoft.com/en-us/windows/uwp/design/shell/tiles-and-notifications/
    https://docs.microsoft.com/en-us/mem/configmgr/compliance/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$ThresholdDays = 7,
    
    [Parameter(Mandatory = $false)]
    [string]$NotificationTitle = "Device Restart Required",
    
    [Parameter(Mandatory = $false)]
    [string]$NotificationMessage = "Your computer has been running for more than $ThresholdDays days. Please restart when convenient to maintain optimal performance and security.",
    
    [Parameter(Mandatory = $false)]
    [int]$GracePeriodHours = 4,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxNotifications = 3,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableScheduledReboot,
    
    [Parameter(Mandatory = $false)]
    [string]$MaintenanceWindowStart = "18:00",
    
    [Parameter(Mandatory = $false)]
    [string]$MaintenanceWindowEnd = "06:00",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportMetrics
)

# Initialize remediation session
$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"

# Script metadata for monitoring integration
$ScriptInfo = @{
    ScriptName = "Reboot Remediation Script"
    Version = "2.0"
    Author = "Apostolis Tsirogiannis"
    ExecutionTime = Get-Date
    ComputerName = $env:COMPUTERNAME
    UserContext = $env:USERNAME
    SessionType = if($env:SESSIONNAME) { $env:SESSIONNAME } else { "Unknown" }
}

# Enhanced toast notification function with enterprise features
function Show-EnterpriseNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToastTitle,
        
        [Parameter(Mandatory = $true)]
        [string]$ToastText,
        
        [Parameter(Mandatory = $false)]
        [string]$AppId = "Microsoft.CompanyPortal_8wekyb3d8bbwe!App",
        
        [Parameter(Mandatory = $false)]
        [int]$ExpirationMinutes = 15,
        
        [Parameter(Mandatory = $false)]
        [string]$ActionButtonText = "Schedule Restart",
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableActions
    )
    
    try {
        Write-Verbose "Initializing Windows toast notification system..."
        
        # Load required Windows Runtime types for toast notifications
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
        
        # Create base toast template
        $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        
        # Convert to XML for manipulation
        $RawXml = [xml]$Template.GetXml()
        
        # Set toast content
        ($RawXml.toast.visual.binding.text | Where-Object {$_.id -eq "1"}).AppendChild($RawXml.CreateTextNode($ToastTitle)) | Out-Null
        ($RawXml.toast.visual.binding.text | Where-Object {$_.id -eq "2"}).AppendChild($RawXml.CreateTextNode($ToastText)) | Out-Null
        
        # Add enterprise branding and actions if enabled
        if ($EnableActions) {
            # Add actions node for interactive notifications
            $ActionsNode = $RawXml.CreateElement("actions")
            $ActionNode = $RawXml.CreateElement("action")
            $ActionNode.SetAttribute("content", $ActionButtonText)
            $ActionNode.SetAttribute("arguments", "action=schedule")
            $ActionNode.SetAttribute("activationType", "background")
            $ActionsNode.AppendChild($ActionNode) | Out-Null
            $RawXml.toast.AppendChild($ActionsNode) | Out-Null
        }
        
        # Add audio settings for professional environment
        $AudioNode = $RawXml.CreateElement("audio")
        $AudioNode.SetAttribute("src", "ms-winsoundevent:Notification.Default")
        $AudioNode.SetAttribute("silent", "false")
        $RawXml.toast.AppendChild($AudioNode) | Out-Null
        
        # Create final XML document
        $SerializedXml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $SerializedXml.LoadXml($RawXml.OuterXml)
        
        # Create and configure toast notification
        $Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)
        $Toast.Tag = "DeviceRebootRemediation"
        $Toast.Group = "EndpointManagement"
        $Toast.ExpirationTime = [DateTimeOffset]::Now.AddMinutes($ExpirationMinutes)
        
        # Show notification using appropriate app identity
        $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId)
        $Notifier.Show($Toast)
        
        Write-Verbose "Toast notification displayed successfully"
        return $true
        
    } catch {
        Write-Warning "Failed to show toast notification: $($_.Exception.Message)"
        
        # Fallback to Windows balloon notification
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $BalloonTip = New-Object System.Windows.Forms.NotifyIcon
            $BalloonTip.Icon = [System.Drawing.SystemIcons]::Information
            $BalloonTip.BalloonTipTitle = $ToastTitle
            $BalloonTip.BalloonTipText = $ToastText
            $BalloonTip.Visible = $true
            $BalloonTip.ShowBalloonTip(10000)
            
            Write-Verbose "Fallback balloon notification displayed"
            return $true
            
        } catch {
            Write-Warning "Fallback notification also failed: $($_.Exception.Message)"
            return $false
        }
    }
}

# Function to check notification frequency limits
function Test-NotificationFrequency {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TrackingFile,
        
        [Parameter(Mandatory = $true)]
        [int]$MaxNotifications,
        
        [Parameter(Mandatory = $true)]
        [int]$GracePeriodHours
    )
    
    try {
        if (Test-Path $TrackingFile) {
            $TrackingData = Get-Content $TrackingFile | ConvertFrom-Json
            $LastNotification = [DateTime]$TrackingData.LastNotification
            $TodayCount = $TrackingData.NotificationsToday
            
            # Reset count if it's a new day
            if ($LastNotification.Date -lt (Get-Date).Date) {
                $TodayCount = 0
            }
            
            # Check grace period
            if ($LastNotification.AddHours($GracePeriodHours) -gt (Get-Date)) {
                Write-Verbose "Still within grace period. Next notification allowed at: $($LastNotification.AddHours($GracePeriodHours))"
                return $false
            }
            
            # Check daily limit
            if ($TodayCount -ge $MaxNotifications) {
                Write-Verbose "Daily notification limit reached ($TodayCount/$MaxNotifications)"
                return $false
            }
        }
        
        return $true
        
    } catch {
        Write-Warning "Error checking notification frequency: $($_.Exception.Message)"
        return $true  # Allow notification if tracking fails
    }
}

# Function to update notification tracking
function Update-NotificationTracking {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TrackingFile
    )
    
    try {
        $CurrentTime = Get-Date
        $ExistingCount = 0
        
        if (Test-Path $TrackingFile) {
            $TrackingData = Get-Content $TrackingFile | ConvertFrom-Json
            $LastNotification = [DateTime]$TrackingData.LastNotification
            
            # Keep count if same day
            if ($LastNotification.Date -eq $CurrentTime.Date) {
                $ExistingCount = $TrackingData.NotificationsToday
            }
        }
        
        $NewTrackingData = @{
            LastNotification = $CurrentTime.ToString("yyyy-MM-dd HH:mm:ss")
            NotificationsToday = $ExistingCount + 1
            ComputerName = $env:COMPUTERNAME
            UserName = $env:USERNAME
        }
        
        $NewTrackingData | ConvertTo-Json | Out-File -FilePath $TrackingFile -Force -Encoding UTF8
        Write-Verbose "Notification tracking updated: $($NewTrackingData.NotificationsToday) notifications today"
        
    } catch {
        Write-Warning "Failed to update notification tracking: $($_.Exception.Message)"
    }
}

try {
    Write-Verbose "=== Device Reboot Remediation Script ==="
    Write-Verbose "Computer: $($ScriptInfo.ComputerName)"
    Write-Verbose "User: $($ScriptInfo.UserContext)"
    Write-Verbose "Session: $($ScriptInfo.SessionType)"
    Write-Verbose "Execution Time: $($ScriptInfo.ExecutionTime)"
    Write-Verbose "Threshold: $ThresholdDays days"
    
    # Determine tracking file location
    $TrackingPath = if(-not [string]::IsNullOrWhiteSpace($LogPath)) { $LogPath } else { $env:TEMP }
    $TrackingFile = "$TrackingPath\RebootNotificationTracking_$($env:COMPUTERNAME).json"
    
    # Create tracking directory if needed
    $TrackingDir = Split-Path $TrackingFile -Parent
    if (-not (Test-Path $TrackingDir)) {
        New-Item -Path $TrackingDir -ItemType Directory -Force | Out-Null
        Write-Verbose "Created tracking directory: $TrackingDir"
    }
    
    # Check notification frequency limits
    if (-not (Test-NotificationFrequency -TrackingFile $TrackingFile -MaxNotifications $MaxNotifications -GracePeriodHours $GracePeriodHours)) {
        Write-Verbose "Notification frequency limits prevent showing notification at this time"
        Write-Host "Remediation skipped: Within grace period or daily limit reached"
        exit 0
    }
    
    # Prepare notification message with dynamic content
    $DynamicMessage = $NotificationMessage -replace '\$ThresholdDays', $ThresholdDays
    
    # Add maintenance window information if configured
    if ($EnableScheduledReboot -and $MaintenanceWindowStart -and $MaintenanceWindowEnd) {
        $DynamicMessage += " Automatic restart can be scheduled during maintenance hours ($MaintenanceWindowStart - $MaintenanceWindowEnd)."
    }
    
    Write-Verbose "Displaying reboot reminder notification..."
    Write-Verbose "Title: $NotificationTitle"
    Write-Verbose "Message: $DynamicMessage"
    
    # Show enterprise toast notification
    $NotificationSuccess = Show-EnterpriseNotification -ToastTitle $NotificationTitle -ToastText $DynamicMessage -EnableActions:$EnableScheduledReboot
    
    if ($NotificationSuccess) {
        Write-Host "Reboot reminder notification displayed successfully"
        
        # Update notification tracking
        Update-NotificationTracking -TrackingFile $TrackingFile
        
        # Log to Windows Event Log
        try {
            $EventSource = "DeviceRebootRemediation"
            
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
                try {
                    New-EventLog -LogName "Application" -Source $EventSource -ErrorAction SilentlyContinue
                } catch {
                    $EventSource = "Application"
                }
            }
            
            $EventMessage = "Reboot reminder notification displayed to user: $($ScriptInfo.UserContext) on computer: $($ScriptInfo.ComputerName). Device uptime exceeds $ThresholdDays day threshold."
            Write-EventLog -LogName "Application" -Source $EventSource -EventId 2001 -EntryType "Information" -Message $EventMessage -ErrorAction SilentlyContinue
            
        } catch {
            Write-Verbose "Event log writing failed: $($_.Exception.Message)"
        }
        
        # Export metrics if requested
        if ($ExportMetrics) {
            $MetricsPath = if(-not [string]::IsNullOrWhiteSpace($LogPath)) { $LogPath } else { $env:TEMP }
            $MetricsFile = "$MetricsPath\RemediationMetrics_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            
            $RemediationMetrics = @{
                ComputerName = $env:COMPUTERNAME
                UserName = $env:USERNAME
                RemediationTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                ThresholdDays = $ThresholdDays
                NotificationTitle = $NotificationTitle
                NotificationSuccess = $NotificationSuccess
                SessionType = $ScriptInfo.SessionType
                GracePeriodHours = $GracePeriodHours
                MaxNotifications = $MaxNotifications
                ScheduledRebootEnabled = $EnableScheduledReboot.IsPresent
                MaintenanceWindow = "$MaintenanceWindowStart - $MaintenanceWindowEnd"
            }
            
            try {
                $RemediationMetrics | ConvertTo-Json -Depth 3 | Out-File -FilePath $MetricsFile -Encoding UTF8
                Write-Verbose "Remediation metrics exported to: $MetricsFile"
            } catch {
                Write-Warning "Could not export metrics: $($_.Exception.Message)"
            }
        }
        
        # Custom logging if path specified
        if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
            try {
                if (-not (Test-Path $LogPath)) {
                    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
                }
                
                $LogFile = "$LogPath\RebootRemediation_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd').log"
                $LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Notification displayed to $($ScriptInfo.UserContext) - Threshold: $ThresholdDays days"
                
                Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8
                Write-Verbose "Log entry added to: $LogFile"
                
            } catch {
                Write-Warning "Custom logging failed: $($_.Exception.Message)"
            }
        }
        
        exit 0
        
    } else {
        Write-Warning "Failed to display reboot reminder notification"
        Write-Host "Remediation partially successful: Notification display failed"
        exit 1
    }
    
} catch {
    $ErrorMessage = "Remediation script failed: $($_.Exception.Message)"
    Write-Error $ErrorMessage
    
    # Log error for monitoring
    try {
        Write-EventLog -LogName "Application" -Source "Application" -EventId 2003 -EntryType "Error" -Message "Device Reboot Remediation Error: $ErrorMessage" -ErrorAction SilentlyContinue
    } catch {
        # Fail silently if event log is not available
    }
    
    Write-Host "Remediation failed: $ErrorMessage"
    exit 2
}
