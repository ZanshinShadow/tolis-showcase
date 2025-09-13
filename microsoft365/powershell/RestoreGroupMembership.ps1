<#
.SYNOPSIS
    Azure AD Group Membership Restoration Tool - Local Administration Script

.DESCRIPTION
    This PowerShell script provides administrative capabilities for restoring Azure AD group memberships
    based on audit log analysis. It connects to Azure Active Directory, analyzes audit logs for group
    removal events, and provides automated restoration functionality for accidental or unauthorized
    group membership changes.

    Administrative Features:
    - Azure AD audit log analysis for group membership tracking
    - Automated restoration of users to previously assigned groups
    - Date-based filtering for specific incident investigation
    - Detailed logging and reporting for administrative oversight
    - Interactive mode for safe, controlled restoration operations
    - Backup and validation capabilities for membership changes

    Local Use Cases:
    - Incident response for accidental group membership removal
    - Administrative restoration after unauthorized changes
    - Compliance auditing and membership history tracking
    - Bulk restoration operations for specific time periods
    - Group membership disaster recovery and rollback procedures

.PARAMETER AuditDate
    The date for which audit logs will be analyzed (format: 'yyyy-MM-dd')
    Supports relative dates like 'today', 'yesterday', or specific dates

.PARAMETER UserId
    The Object ID of the specific user to track for group membership changes
    If not specified, analyzes all users for the given date range

.PARAMETER GroupId
    Optional: Filter restoration to a specific group Object ID
    Useful for targeted restoration operations

.PARAMETER DryRun
    Switch to preview restoration actions without making actual changes
    Recommended for initial analysis and validation

.PARAMETER Interactive
    Switch to enable interactive mode with confirmation prompts
    Provides additional safety for production environments

.PARAMETER ExportReport
    Switch to export detailed findings to CSV report
    Useful for documentation and compliance reporting

.PARAMETER LogPath
    Optional path for detailed operation logging
    Default: Current user's Documents folder

.EXAMPLE
    .\RestoreGroupMembership.ps1 -AuditDate '2024-09-13' -UserId '12345678-1234-1234-1234-123456789abc'
    Analyzes and restores group memberships for a specific user on a specific date

.EXAMPLE
    .\RestoreGroupMembership.ps1 -AuditDate 'yesterday' -DryRun -ExportReport
    Performs dry-run analysis of all group removals from yesterday with detailed reporting

.EXAMPLE
    .\RestoreGroupMembership.ps1 -AuditDate '2024-09-13' -Interactive -LogPath 'C:\AdminLogs\'
    Interactive restoration with detailed logging for administrative oversight

.EXAMPLE
    .\RestoreGroupMembership.ps1 -AuditDate '2024-09-13' -GroupId '87654321-4321-4321-4321-cba987654321' -UserId '12345678-1234-1234-1234-123456789abc'
    Targeted restoration for specific user and group combination

.NOTES
    Author: Apostolis Tsirogiannis
    Email: apostolis.tsirogiannis@techtakt.com
    LinkedIn: https://www.linkedin.com/in/apostolis-tsirogiannis/
    Upwork: https://www.upwork.com/freelancers/apostolos
    
    Prerequisites:
    - Microsoft Graph PowerShell module or AzureAD module installed
    - Global Administrator or appropriate delegated permissions
    - AuditLog.Read.All and Group.ReadWrite.All permissions
    - Valid Azure AD authentication context
    
    Administrative Use Cases:
    - Incident response and disaster recovery operations
    - Compliance auditing and membership history tracking
    - Administrative restoration after security incidents
    - Group membership backup and restore procedures
    - Investigation of unauthorized membership changes

    Security Considerations:
    - Always use -DryRun first to preview changes
    - Enable -Interactive mode for production environments
    - Maintain detailed logs for audit compliance
    - Verify group membership requirements before restoration
    - Consider approval workflows for sensitive group restorations

.LINK
    https://docs.microsoft.com/en-us/graph/api/resources/directoryaudit
    https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/
    https://docs.microsoft.com/en-us/powershell/module/azuread/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AuditDate,
    
    [Parameter(Mandatory = $false)]
    [string]$UserId = "",
    
    [Parameter(Mandatory = $false)]
    [string]$GroupId = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [switch]$Interactive,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportReport,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:USERPROFILE\Documents\AzureAD_Administration\"
)

# Initialize administrative session
$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    Write-Host "Created administration log directory: $LogPath" -ForegroundColor Green
}

# Initialize detailed logging
$LogFile = "$LogPath\GroupMembershipRestore_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogFile | Out-Null

try {
    Write-Host "=== Azure AD Group Membership Restoration Tool ===" -ForegroundColor Cyan
    Write-Host "Execution Time: $(Get-Date)" -ForegroundColor White
    Write-Host "Audit Date: $AuditDate" -ForegroundColor White
    Write-Host "Target User: $(if([string]::IsNullOrWhiteSpace($UserId)){'All Users'}else{$UserId})" -ForegroundColor White
    Write-Host "Target Group: $(if([string]::IsNullOrWhiteSpace($GroupId)){'All Groups'}else{$GroupId})" -ForegroundColor White
    Write-Host "Operation Mode: $(if($DryRun){'Dry Run (Preview Only)'}else{'Live Restoration'})" -ForegroundColor White
    Write-Host "Interactive Mode: $(if($Interactive){'Enabled'}else{'Disabled'})" -ForegroundColor White
    
    # Parse audit date with support for relative dates
    switch ($AuditDate.ToLower()) {
        "today" { $ParsedDate = Get-Date -Format "yyyy-MM-dd" }
        "yesterday" { $ParsedDate = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd") }
        default { 
            try {
                $ParsedDate = ([DateTime]::Parse($AuditDate)).ToString("yyyy-MM-dd")
            } catch {
                throw "Invalid date format. Use 'yyyy-MM-dd', 'today', or 'yesterday'"
            }
        }
    }
    
    Write-Host "Parsed Audit Date: $ParsedDate" -ForegroundColor White
    
    # Connect to Azure AD using Microsoft Graph (modern approach)
    Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        # Try Microsoft Graph first (modern approach)
        Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Microsoft.Graph.Groups, Microsoft.Graph.Users -ErrorAction SilentlyContinue
        
        if (Get-Module Microsoft.Graph.Authentication -ListAvailable) {
            Connect-MgGraph -Scopes "AuditLog.Read.All", "Group.ReadWrite.All", "User.Read.All" -NoWelcome
            $UseGraphAPI = $true
            Write-Host "Connected using Microsoft Graph API" -ForegroundColor Green
        } else {
            throw "Microsoft Graph modules not available"
        }
    } catch {
        # Fallback to AzureAD module
        Write-Host "Falling back to AzureAD module..." -ForegroundColor Yellow
        Import-Module AzureAD -ErrorAction Stop
        Connect-AzureAD | Out-Null
        $UseGraphAPI = $false
        Write-Host "Connected using AzureAD module" -ForegroundColor Green
    }
    
    # Build audit log filter
    $FilterString = "activityDateTime ge $ParsedDate and activityDisplayName eq 'Remove member from group'"
    
    if (-not [string]::IsNullOrWhiteSpace($UserId)) {
        $FilterString += " and targetResources/any(t: t/id eq '$UserId')"
    }
    
    Write-Host "`nRetrieving audit logs..." -ForegroundColor Yellow
    Write-Host "Filter: $FilterString" -ForegroundColor White
    
    # Get audit logs based on available API
    if ($UseGraphAPI) {
        $AuditLogs = Get-MgAuditLogDirectoryAudit -Filter $FilterString -All:$true
    } else {
        $AuditLogs = Get-AzureADAuditDirectoryLogs -Filter $FilterString
    }
    
    Write-Host "Found $($AuditLogs.Count) group removal events" -ForegroundColor White
    
    if ($AuditLogs.Count -eq 0) {
        Write-Host "No group removal events found for the specified criteria" -ForegroundColor Green
        return
    }
    
    # Analyze audit logs and prepare restoration data
    $RestorationActions = @()
    $ProcessedCount = 0
    
    Write-Host "`nAnalyzing audit logs for restoration opportunities..." -ForegroundColor Yellow
    
    foreach ($Log in $AuditLogs) {
        $ProcessedCount++
        Write-Progress -Activity "Analyzing Audit Logs" -Status "Processing log $ProcessedCount of $($AuditLogs.Count)" -PercentComplete (($ProcessedCount / $AuditLogs.Count) * 100)
        
        try {
            # Extract user and group information from audit log
            $LogUserId = ""
            $LogGroupId = ""
            $LogGroupName = ""
            $LogUserName = ""
            
            # Parse target resources to find user and group
            foreach ($TargetResource in $Log.TargetResources) {
                if ($TargetResource.Type -eq "User") {
                    $LogUserId = $TargetResource.Id
                    $LogUserName = $TargetResource.DisplayName
                } elseif ($TargetResource.Type -eq "Group") {
                    $LogGroupId = $TargetResource.Id
                    $LogGroupName = $TargetResource.DisplayName
                }
            }
            
            # Skip if group filter is specified and doesn't match
            if (-not [string]::IsNullOrWhiteSpace($GroupId) -and $LogGroupId -ne $GroupId) {
                continue
            }
            
            # Verify group and user still exist
            if ($UseGraphAPI) {
                $Group = Get-MgGroup -GroupId $LogGroupId -ErrorAction SilentlyContinue
                $User = Get-MgUser -UserId $LogUserId -ErrorAction SilentlyContinue
                
                if ($Group -and $User) {
                    # Check if user is already a member
                    $CurrentMembers = Get-MgGroupMember -GroupId $LogGroupId -All
                    $IsCurrentMember = $CurrentMembers.Id -contains $LogUserId
                }
            } else {
                $Group = Get-AzureADGroup -ObjectId $LogGroupId -ErrorAction SilentlyContinue
                $User = Get-AzureADUser -ObjectId $LogUserId -ErrorAction SilentlyContinue
                
                if ($Group -and $User) {
                    # Check if user is already a member
                    $CurrentMembers = Get-AzureADGroupMember -ObjectId $LogGroupId -All $true
                    $IsCurrentMember = $CurrentMembers.ObjectId -contains $LogUserId
                }
            }
            
            if ($Group -and $User -and -not $IsCurrentMember) {
                $RestorationAction = [PSCustomObject]@{
                    Timestamp = $Log.ActivityDateTime
                    UserId = $LogUserId
                    UserDisplayName = if($User.DisplayName) { $User.DisplayName } else { $LogUserName }
                    UserPrincipalName = $User.UserPrincipalName
                    GroupId = $LogGroupId
                    GroupDisplayName = if($Group.DisplayName) { $Group.DisplayName } else { $LogGroupName }
                    GroupType = if($UseGraphAPI) { $Group.GroupTypes -join ", " } else { $Group.GroupTypes -join ", " }
                    RemovalReason = $Log.Result.FailureReason
                    InitiatedBy = $Log.InitiatedBy.User.DisplayName
                    CanRestore = $true
                    Status = "Pending"
                }
                
                $RestorationActions += $RestorationAction
            }
            
        } catch {
            Write-Warning "Error processing audit log entry: $($_.Exception.Message)"
        }
    }
    
    Write-Progress -Activity "Analyzing Audit Logs" -Completed
    
    Write-Host "`nRestoration Analysis Complete" -ForegroundColor Green
    Write-Host "Total Removal Events: $($AuditLogs.Count)" -ForegroundColor White
    Write-Host "Restorable Actions: $($RestorationActions.Count)" -ForegroundColor White
    
    if ($RestorationActions.Count -eq 0) {
        Write-Host "No restoration actions required - all users are already members of their groups" -ForegroundColor Green
        return
    }
    
    # Display restoration preview
    Write-Host "`n=== RESTORATION PREVIEW ===" -ForegroundColor Cyan
    $RestorationActions | Format-Table -Property UserDisplayName, GroupDisplayName, Timestamp, InitiatedBy -AutoSize
    
    # Export report if requested
    if ($ExportReport) {
        $ReportFile = "$LogPath\GroupMembershipRestoration_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $RestorationActions | Export-Csv -Path $ReportFile -NoTypeInformation -Encoding UTF8
        Write-Host "Detailed report exported to: $ReportFile" -ForegroundColor Cyan
    }
    
    # Perform restoration if not in dry run mode
    if (-not $DryRun) {
        Write-Host "`n=== PERFORMING RESTORATION ===" -ForegroundColor Yellow
        
        $RestoredCount = 0
        $FailedCount = 0
        
        foreach ($Action in $RestorationActions) {
            try {
                $ShouldRestore = $true
                
                if ($Interactive) {
                    $Response = Read-Host "Restore $($Action.UserDisplayName) to group '$($Action.GroupDisplayName)'? (y/n)"
                    $ShouldRestore = $Response.ToLower() -eq 'y'
                }
                
                if ($ShouldRestore) {
                    Write-Host "Restoring $($Action.UserDisplayName) to $($Action.GroupDisplayName)..." -ForegroundColor Yellow
                    
                    if ($UseGraphAPI) {
                        New-MgGroupMember -GroupId $Action.GroupId -DirectoryObjectId $Action.UserId
                    } else {
                        Add-AzureADGroupMember -ObjectId $Action.GroupId -RefObjectId $Action.UserId
                    }
                    
                    $Action.Status = "Restored"
                    $RestoredCount++
                    Write-Host "✓ Successfully restored $($Action.UserDisplayName) to $($Action.GroupDisplayName)" -ForegroundColor Green
                } else {
                    $Action.Status = "Skipped"
                    Write-Host "- Skipped restoration for $($Action.UserDisplayName)" -ForegroundColor Yellow
                }
                
            } catch {
                $Action.Status = "Failed: $($_.Exception.Message)"
                $FailedCount++
                Write-Error "✗ Failed to restore $($Action.UserDisplayName) to $($Action.GroupDisplayName): $($_.Exception.Message)"
            }
        }
        
        Write-Host "`n=== RESTORATION SUMMARY ===" -ForegroundColor Green
        Write-Host "Successfully Restored: $RestoredCount" -ForegroundColor Green
        Write-Host "Failed Restorations: $FailedCount" -ForegroundColor Red
        Write-Host "Total Actions: $($RestorationActions.Count)" -ForegroundColor White
        
        # Export final report with status
        if ($ExportReport) {
            $FinalReportFile = "$LogPath\GroupMembershipRestoration_Final_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $RestorationActions | Export-Csv -Path $FinalReportFile -NoTypeInformation -Encoding UTF8
            Write-Host "Final restoration report exported to: $FinalReportFile" -ForegroundColor Cyan
        }
        
    } else {
        Write-Host "`n=== DRY RUN COMPLETE ===" -ForegroundColor Cyan
        Write-Host "No changes were made. Use without -DryRun to perform actual restoration." -ForegroundColor Yellow
        Write-Host "Review the preview above and consider using -Interactive for additional safety." -ForegroundColor Yellow
    }
    
} catch {
    Write-Error "Group membership restoration failed: $($_.Exception.Message)"
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
    
} finally {
    # Cleanup and disconnect
    try {
        if ($UseGraphAPI) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Yellow
        } else {
            Disconnect-AzureAD -ErrorAction SilentlyContinue
            Write-Host "Disconnected from Azure AD" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Could not disconnect from Azure AD: $($_.Exception.Message)"
    }
    
    try {
        Stop-Transcript
        Write-Host "Administration log saved to: $LogFile" -ForegroundColor Yellow
    } catch {
        Write-Warning "Could not stop transcript: $($_.Exception.Message)"
    }
}
