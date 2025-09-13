<#
.SYNOPSIS
    Security Monitoring Runbook - Failed Authentication Detection and Alerting

.DESCRIPTION
    This PowerShell runbook provides automated security monitoring for Azure AD sign-in failures
    with real-time alerting capabilities. It analyzes authentication logs, identifies users with
    suspicious failed login patterns, and sends automated alerts to Microsoft Teams channels.

    Security Features:
    - Real-time Azure AD sign-in log analysis using Microsoft Graph API
    - Configurable threshold detection for failed authentication attempts
    - Automated threat detection and incident response workflow
    - Microsoft Teams integration for immediate security team notification
    - JSON export for SIEM integration and forensic analysis
    - Time-based analysis with customizable monitoring windows

    Runbook Capabilities:
    - Automated execution via Azure Automation, Task Scheduler, or cron jobs
    - Integration with Security Operations Center (SOC) workflows
    - Compliance reporting for security audits and governance
    - Incident response automation and escalation procedures

.PARAMETER TimeWindowHours
    Number of hours to look back for failed sign-in attempts (default: 1 hour)

.PARAMETER FailureThreshold
    Minimum number of failed attempts to trigger an alert (default: 5 attempts)

.PARAMETER TeamsWebhookUrl
    Microsoft Teams webhook URL for security alerts and notifications

.PARAMETER OutputPath
    Local path for JSON export of failed attempts data (default: C:\SecurityLogs\)

.PARAMETER IncludeUserDetails
    Switch to include additional user details in the analysis and alerts

.PARAMETER EnableTeamsAlert
    Switch to enable Microsoft Teams notifications (requires TeamsWebhookUrl)

.PARAMETER UseManagedIdentity
    Switch to use Azure Managed Identity for authentication (default: true, recommended for Azure Automation runbooks)

.EXAMPLE
    .\SecurityFailedLoginsRunbook.ps1
    Runs with default settings using Managed Identity (1 hour window, 5+ failures, no Teams alert)

.EXAMPLE
    .\SecurityFailedLoginsRunbook.ps1 -TimeWindowHours 2 -FailureThreshold 3 -EnableTeamsAlert -TeamsWebhookUrl "https://company.webhook.office.com/..." -UseManagedIdentity
    Azure Automation runbook execution with Teams notifications and Managed Identity

.EXAMPLE
    .\SecurityFailedLoginsRunbook.ps1 -UseManagedIdentity:$false -OutputPath "D:\SecurityReports\" -IncludeUserDetails
    Interactive execution for testing with user authentication

.NOTES
    Author: Apostolis Tsirogiannis
    Email: apostolis.tsirogiannis@techtakt.com
    LinkedIn: https://www.linkedin.com/in/apostolis-tsirogiannis/
    Upwork: https://www.upwork.com/freelancers/apostolos
    
    Prerequisites:
    - Microsoft.Graph PowerShell module installed
    - AuditLog.Read.All and User.Read.All Graph API permissions
    - For Azure Automation: System-assigned or User-assigned Managed Identity with required permissions
    - For interactive use: Valid Azure AD authentication context
    - Microsoft Teams webhook configured (for alerts)
    
    Required Permissions for Managed Identity:
    - Microsoft Graph API permissions: AuditLog.Read.All, User.Read.All
    - These permissions must be granted to the Managed Identity through Azure CLI, PowerShell, or Azure Portal
    
    How to Grant Permissions:
    
    Method 1 - Azure Portal:
    1. Navigate to Azure Active Directory > Enterprise Applications
    2. Search for your Automation Account's Managed Identity name
    3. Go to Permissions > Add a permission > Microsoft Graph > Application permissions
    4. Add: AuditLog.Read.All and User.Read.All
    5. Click "Grant admin consent" for your tenant
    
    Method 2 - Azure CLI:
    az ad app permission add --id <managed-identity-object-id> --api 00000003-0000-0000-c000-000000000000 --api-permissions b0afded3-3588-46d8-8b3d-9842eff778da=Role df021288-bdef-4463-88db-98f22de89214=Role
    az ad app permission grant --id <managed-identity-object-id> --api 00000003-0000-0000-c000-000000000000
    
    Method 3 - PowerShell (see setup instructions below for detailed commands)
    
    Security Use Cases:
    - Real-time threat detection and incident response
    - SOC automation and security monitoring workflows
    - Compliance reporting for failed authentication attempts
    - Integration with SIEM solutions (Sentinel, Splunk, QRadar)
    - Automated security incident escalation procedures

    Deployment Scenarios:
    - Azure Automation runbook for cloud-native monitoring
    - On-premises Task Scheduler for hybrid environments
    - SCCM or Intune deployment for endpoint-based monitoring
    - Docker container for containerized security monitoring

.LINK
    https://docs.microsoft.com/en-us/graph/api/resources/signin
    https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/
    https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/
    https://docs.microsoft.com/en-us/azure/automation/automation-security-overview#managed-identities

.COMPONENT
    Required PowerShell Modules: Microsoft.Graph

.FUNCTIONALITY
    Security Monitoring, Threat Detection, Incident Response, SIEM Integration

#>

<#
AZURE AUTOMATION SETUP INSTRUCTIONS:

1. Create Azure Automation Account with System-assigned Managed Identity enabled

2. Grant Microsoft Graph API permissions to the Managed Identity:
   
   # Get the Managed Identity Object ID from Azure Portal or CLI
   $ManagedIdentityObjectId = "your-managed-identity-object-id"
   
   # Grant AuditLog.Read.All permission
   New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId -PrincipalId $ManagedIdentityObjectId -AppRoleId "b0afded3-3588-46d8-8b3d-9842eff778da" -ResourceId (Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'").Id
   
   # Grant User.Read.All permission
   New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId -PrincipalId $ManagedIdentityObjectId -AppRoleId "df021288-bdef-4463-88db-98f22de89214" -ResourceId (Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'").Id

3. Alternative: Use Azure CLI to grant permissions:
   az ad app permission grant --id $ManagedIdentityObjectId --api 00000003-0000-0000-c000-000000000000 --scope "AuditLog.Read.All User.Read.All"

4. Import the Microsoft.Graph module in your Azure Automation Account

5. Create a webhook in Microsoft Teams for security alerts

6. Schedule the runbook to run every hour or as needed for your security monitoring requirements
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$TimeWindowHours = 1,
    
    [Parameter(Mandatory = $false)]
    [int]$FailureThreshold = 5,
    
    [Parameter(Mandatory = $false)]
    [string]$TeamsWebhookUrl = "https://democorp.webhook.office.com/webhookb2/12345678-1234-1234-1234-123456789abc@87654321-4321-4321-4321-cba987654321/IncomingWebhook/abcdef1234567890/fedcba0987654321",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\SecurityLogs\",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeUserDetails,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableTeamsAlert,
    
    [Parameter(Mandatory = $false)]
    [switch]$UseManagedIdentity = $true
)

# Initialize security monitoring session
$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    Write-Host "Created security logs directory: $OutputPath" -ForegroundColor Green
}

# Initialize logging
$LogFile = "$OutputPath\SecurityMonitoring_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogFile | Out-Null

try {
    Write-Host "=== Security Monitoring Runbook - Failed Authentication Detection ===" -ForegroundColor Red
    Write-Host "Execution Time: $(Get-Date)" -ForegroundColor White
    Write-Host "Authentication Mode: $(if($UseManagedIdentity){'Managed Identity'}else{'Interactive'})" -ForegroundColor White
    Write-Host "Monitoring Window: Last $TimeWindowHours hour(s)" -ForegroundColor White
    Write-Host "Failure Threshold: $FailureThreshold attempts" -ForegroundColor White
    Write-Host "Teams Alerts: $(if($EnableTeamsAlert){'Enabled'}else{'Disabled'})" -ForegroundColor White
    Write-Host "Output Path: $OutputPath" -ForegroundColor White
    
    # Connect to Microsoft Graph with required security scopes
    Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Yellow
    $RequiredScopes = @("AuditLog.Read.All", "User.Read.All")
    
    if ($UseManagedIdentity) {
        # Use Managed Identity for Azure Automation runbook execution
        Write-Host "Authenticating using Managed Identity..." -ForegroundColor Cyan
        try {
            # Connect using Managed Identity (no interactive login required)
            Connect-MgGraph -Identity -NoWelcome
            Write-Host "Successfully authenticated with Managed Identity" -ForegroundColor Green
            
            # Verify the identity context
            $Context = Get-MgContext
            Write-Host "Connected as: $($Context.Account)" -ForegroundColor White
            Write-Host "Tenant ID: $($Context.TenantId)" -ForegroundColor White
            
        } catch {
            Write-Error "Failed to authenticate with Managed Identity. Ensure the Managed Identity has the required Graph API permissions (AuditLog.Read.All, User.Read.All)"
            throw
        }
    } else {
        # Use interactive authentication for development/testing
        Write-Host "Authenticating interactively..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
        Write-Host "Successfully authenticated interactively" -ForegroundColor Green
    }
    
    # Define time range for monitoring window
    $StartTime = (Get-Date).AddHours(-$TimeWindowHours).ToString("o")
    $EndTime = (Get-Date).ToString("o")
    
    Write-Host "`nAnalyzing sign-in logs..." -ForegroundColor Yellow
    Write-Host "Start Time: $StartTime" -ForegroundColor White
    Write-Host "End Time: $EndTime" -ForegroundColor White
    
    # Fetch sign-in logs from Microsoft Graph within the monitoring window
    $SignInLogs = Get-MgAuditLogSignIn -Filter "createdDateTime ge $StartTime and createdDateTime le $EndTime" -All:$true
    Write-Host "Retrieved $($SignInLogs.Count) total sign-in events" -ForegroundColor White
    
    # Filter for failed sign-in attempts (error code != 0 indicates failure)
    $FailedSignInAttempts = $SignInLogs | Where-Object { $_.Status.ErrorCode -ne 0 }
    Write-Host "Found $($FailedSignInAttempts.Count) failed sign-in attempts" -ForegroundColor Yellow
    
    if ($FailedSignInAttempts.Count -eq 0) {
        Write-Host "No failed sign-in attempts detected in the monitoring window" -ForegroundColor Green
        return
    }
    
    # Group by User ID and count failed attempts per user
    $GroupedAttempts = $FailedSignInAttempts | Group-Object UserId
    Write-Host "Analyzing $($GroupedAttempts.Count) unique users with failed attempts" -ForegroundColor White
    
    # Filter for users exceeding the failure threshold
    $SuspiciousUsers = $GroupedAttempts | Where-Object { $_.Count -ge $FailureThreshold } | Sort-Object Count -Descending
    
    if ($SuspiciousUsers.Count -eq 0) {
        Write-Host "No users exceeded the failure threshold of $FailureThreshold attempts" -ForegroundColor Green
        return
    }
    
    Write-Host "`n⚠️  SECURITY ALERT: $($SuspiciousUsers.Count) user(s) exceeded failure threshold" -ForegroundColor Red
    
    # Collect detailed information about suspicious users
    $SecurityIncidents = @()
    
    foreach ($UserGroup in $SuspiciousUsers) {
        Write-Host "Processing user: $($UserGroup.Name)" -ForegroundColor Yellow
        
        try {
            # Get user details
            $UserDetails = Get-MgUser -UserId $UserGroup.Name -ErrorAction SilentlyContinue
            
            # Get failure details for this user
            $UserFailures = $UserGroup.Group | Select-Object CreatedDateTime, Status, ClientAppUsed, IpAddress, Location
            
            # Create security incident object
            $Incident = [PSCustomObject]@{
                Timestamp = Get-Date
                UserId = $UserGroup.Name
                UserPrincipalName = if($UserDetails) { $UserDetails.UserPrincipalName } else { "Unknown" }
                DisplayName = if($UserDetails) { $UserDetails.DisplayName } else { "Unknown" }
                FailedAttempts = $UserGroup.Count
                TimeWindow = "$TimeWindowHours hour(s)"
                IpAddresses = ($UserFailures.IpAddress | Sort-Object -Unique) -join ", "
                ClientApps = ($UserFailures.ClientAppUsed | Sort-Object -Unique) -join ", "
                ErrorCodes = ($UserFailures.Status.ErrorCode | Sort-Object -Unique) -join ", "
                Locations = ($UserFailures.Location.City | Where-Object {$_ -ne $null} | Sort-Object -Unique) -join ", "
                FirstFailure = ($UserFailures.CreatedDateTime | Sort-Object)[0]
                LastFailure = ($UserFailures.CreatedDateTime | Sort-Object)[-1]
            }
            
            if ($IncludeUserDetails -and $UserDetails) {
                $Incident | Add-Member -NotePropertyName "Department" -NotePropertyValue $UserDetails.Department
                $Incident | Add-Member -NotePropertyName "JobTitle" -NotePropertyValue $UserDetails.JobTitle
                $Incident | Add-Member -NotePropertyName "AccountEnabled" -NotePropertyValue $UserDetails.AccountEnabled
            }
            
            $SecurityIncidents += $Incident
            
        } catch {
            Write-Warning "Could not retrieve details for user $($UserGroup.Name): $($_.Exception.Message)"
        }
    }
    
    # Display security incidents
    Write-Host "`n=== SECURITY INCIDENTS DETECTED ===" -ForegroundColor Red
    $SecurityIncidents | Format-Table -Property UserPrincipalName, DisplayName, FailedAttempts, IpAddresses, FirstFailure, LastFailure -AutoSize
    
    # Export to JSON for SIEM integration
    $JsonFile = "$OutputPath\SecurityIncidents_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $SecurityIncidents | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonFile -Force -Encoding UTF8
    Write-Host "Security incidents exported to: $JsonFile" -ForegroundColor Cyan
    
    # Send Teams alert if enabled
    if ($EnableTeamsAlert -and -not [string]::IsNullOrWhiteSpace($TeamsWebhookUrl)) {
        Write-Host "`nSending Teams security alert..." -ForegroundColor Yellow
        
        try {
            # Create Teams message card
            $TeamsMessage = @{
                "@type" = "MessageCard"
                "@context" = "https://schema.org/extensions"
                "summary" = "🚨 Security Alert: Failed Authentication Attempts Detected"
                "themeColor" = "FF0000"
                "title" = "🚨 SECURITY ALERT - Failed Authentication Detection"
                "text" = "**$($SecurityIncidents.Count) user(s)** exceeded the failure threshold of **$FailureThreshold attempts** within **$TimeWindowHours hour(s)**"
                "sections" = @(
                    @{
                        "activityTitle" = "Security Incident Summary"
                        "activitySubtitle" = "Generated by Security Monitoring Runbook"
                        "facts" = @(
                            @{ "name" = "Detection Time"; "value" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC") },
                            @{ "name" = "Monitoring Window"; "value" = "$TimeWindowHours hour(s)" },
                            @{ "name" = "Failure Threshold"; "value" = "$FailureThreshold attempts" },
                            @{ "name" = "Affected Users"; "value" = $SecurityIncidents.Count },
                            @{ "name" = "Total Failed Attempts"; "value" = ($SecurityIncidents.FailedAttempts | Measure-Object -Sum).Sum }
                        )
                    }
                )
            }
            
            # Add user details to Teams message
            if ($SecurityIncidents.Count -le 10) {
                $UserDetails = $SecurityIncidents | ForEach-Object {
                    "**$($_.UserPrincipalName)**: $($_.FailedAttempts) attempts from $($_.IpAddresses)"
                }
                $TeamsMessage.sections += @{
                    "activityTitle" = "Affected Users"
                    "text" = ($UserDetails -join "`n`n")
                }
            }
            
            # Send to Teams
            $TeamsBody = $TeamsMessage | ConvertTo-Json -Depth 10
            Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post -Body $TeamsBody -ContentType "application/json" | Out-Null
            Write-Host "Teams alert sent successfully" -ForegroundColor Green
            
        } catch {
            Write-Error "Failed to send Teams alert: $($_.Exception.Message)"
        }
    }
    
    # Security recommendations
    Write-Host "`n=== SECURITY RECOMMENDATIONS ===" -ForegroundColor Cyan
    Write-Host "1. Review and investigate the affected user accounts immediately" -ForegroundColor White
    Write-Host "2. Consider implementing Conditional Access policies for high-risk sign-ins" -ForegroundColor White
    Write-Host "3. Enable Azure AD Identity Protection for automated risk detection" -ForegroundColor White
    Write-Host "4. Review IP addresses for potential brute force attacks or compromised networks" -ForegroundColor White
    Write-Host "5. Consider mandatory MFA for affected users and high-privilege accounts" -ForegroundColor White
    
    Write-Host "`n=== Security Monitoring Completed Successfully ===" -ForegroundColor Green
    Write-Host "Next scheduled run should occur within the next monitoring window" -ForegroundColor Cyan
    
} catch {
    Write-Error "Security monitoring failed: $($_.Exception.Message)"
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    
    # Send critical failure alert to Teams if possible
    if ($EnableTeamsAlert -and -not [string]::IsNullOrWhiteSpace($TeamsWebhookUrl)) {
        try {
            $FailureAlert = @{
                "@type" = "MessageCard"
                "@context" = "https://schema.org/extensions"
                "summary" = "❌ Security Monitoring Failure"
                "themeColor" = "FF6600"
                "title" = "❌ Security Monitoring Script Failure"
                "text" = "The security monitoring runbook encountered an error and could not complete the analysis."
                "sections" = @(
                    @{
                        "facts" = @(
                            @{ "name" = "Error Time"; "value" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC") },
                            @{ "name" = "Error Message"; "value" = $_.Exception.Message }
                        )
                    }
                )
            }
            
            Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post -Body ($FailureAlert | ConvertTo-Json -Depth 10) -ContentType "application/json"
        } catch {
            Write-Warning "Could not send failure alert to Teams: $($_.Exception.Message)"
        }
    }
    
    exit 1
    
} finally {
    # Cleanup and disconnect
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Yellow
    } catch {
        Write-Warning "Could not disconnect from Microsoft Graph: $($_.Exception.Message)"
    }
    
    try {
        Stop-Transcript
        Write-Host "Security monitoring log saved to: $LogFile" -ForegroundColor Yellow
    } catch {
        Write-Warning "Could not stop transcript: $($_.Exception.Message)"
    }
}
