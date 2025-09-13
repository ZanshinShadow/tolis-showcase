<#
.SYNOPSIS
    Azure AD Group Owner Synchronization Script - Enterprise Automation Example

.DESCRIPTION
    This PowerShell script demonstrates advanced Microsoft Graph API automation for Azure Active Directory 
    group management. It synchronizes group owners between two Azure AD groups with intelligent change 
    tracking and time-based validation.

    Key Features:
    - Automated group owner synchronization between source and destination groups
    - Audit log integration to track ownership changes with timestamps
    - Time-based validation (removes owners added >24 hours ago if not in source)
    - Microsoft Graph PowerShell SDK integration for modern authentication
    - Error handling and logging for enterprise environments
    - Demonstrates Azure AD governance and compliance automation

.PARAMETER SourceGroupId
    The Object ID of the source Azure AD group (owners will be copied from this group)

.PARAMETER DestinationGroupId
    The Object ID of the destination Azure AD group (owners will be synchronized to this group)

.PARAMETER TimeThresholdHours
    Number of hours to wait before removing owners not in source group (default: 24)

.EXAMPLE
    .\GroupOwnerSync.ps1
    Runs the script with demo group IDs for demonstration purposes

.EXAMPLE
    .\GroupOwnerSync.ps1 -SourceGroupId "12345678-1234-1234-1234-123456789abc" -DestinationGroupId "87654321-4321-4321-4321-cba987654321"
    Runs the script with specified group IDs

.NOTES
    Author: Apostolis Tsirogiannis
    Email: apostolis.tsirogiannis@techtakt.com
    LinkedIn: https://www.linkedin.com/in/apostolis-tsirogiannis/
    Upwork: https://www.upwork.com/freelancers/apostolos
    
    Prerequisites:
    - Microsoft.Graph PowerShell module installed
    - Appropriate Azure AD permissions (Group.ReadWrite.All, AuditLog.Read.All)
    - Valid Azure AD authentication context
    
    Use Cases:
    - Automated group governance in enterprise environments
    - Compliance automation for group ownership
    - Integration with Azure Automation or scheduled tasks
    - Part of larger Identity and Access Management (IAM) workflows

.LINK
    https://docs.microsoft.com/en-us/powershell/microsoftgraph/
    https://docs.microsoft.com/en-us/graph/api/resources/group
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SourceGroupId = '12345678-1234-1234-1234-123456789abc',
    
    [Parameter(Mandatory = $false)]
    [string]$DestinationGroupId = '87654321-4321-4321-4321-cba987654321',
    
    [Parameter(Mandatory = $false)]
    [int]$TimeThresholdHours = 24
)

# Display PowerShell version for troubleshooting
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Green

try {
    # Connect to Microsoft Graph with appropriate scopes
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "Group.ReadWrite.All", "AuditLog.Read.All", "User.Read.All"
    
    Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
    Write-Host "Starting group owner synchronization..." -ForegroundColor Cyan
    Write-Host "Source Group ID: $SourceGroupId" -ForegroundColor White
    Write-Host "Destination Group ID: $DestinationGroupId" -ForegroundColor White
    Write-Host "Time Threshold: $TimeThresholdHours hours" -ForegroundColor White
    
    # Get the list of owners for the source and destination groups
    Write-Host "`nRetrieving group owners..." -ForegroundColor Yellow
    $sourceGroupOwners = Get-MgGroupOwner -GroupId $SourceGroupId
    $destinationGroupOwners = Get-MgGroupOwner -GroupId $DestinationGroupId
    
    Write-Host "Source group has $($sourceGroupOwners.Count) owners" -ForegroundColor White
    Write-Host "Destination group has $($destinationGroupOwners.Count) owners" -ForegroundColor White
    
    # Phase 1: Remove owners from destination that are not in source (with time validation)
    Write-Host "`nPhase 1: Validating destination group owners..." -ForegroundColor Cyan
    
    foreach ($owner in $destinationGroupOwners) {
        # Check if the owner is NOT in the source group
        if (-not ($sourceGroupOwners.Id -contains $owner.Id)) {
            Write-Host "Checking owner not in source: $($owner.Id)" -ForegroundColor Yellow
            
            # Get the audit logs for when this owner was added to the destination group
            $auditLogs = Get-MgAuditLogDirectoryAudit -Filter "targetResources/any(t: t/id eq '$DestinationGroupId') and ActivityDisplayName eq 'Add owner to group' and targetResources/any(t: t/id eq '$($owner.Id)')"
            
            if ($null -ne $auditLogs -and $auditLogs.Count -gt 0) {
                $ownerAddedDate = $auditLogs[0].ActivityDateTime
                $currentDate = Get-Date
                $hoursSinceAdded = ($currentDate - $ownerAddedDate).TotalHours
                
                Write-Host "Owner added on: $ownerAddedDate ($([math]::Round($hoursSinceAdded, 2)) hours ago)" -ForegroundColor White
                
                if ($hoursSinceAdded -gt $TimeThresholdHours) {
                    # Remove the owner from the destination group
                    Remove-MgGroupOwnerByRef -GroupId $DestinationGroupId -DirectoryObjectId $owner.Id
                    $user = (Get-MgUser -UserId $owner.Id).DisplayName
                    Write-Host "REMOVED: $user (not in source group for >$TimeThresholdHours hours)" -ForegroundColor Red
                } else {
                    Write-Host "KEPT: Owner added recently, within $TimeThresholdHours hour threshold" -ForegroundColor Green
                }
            } else {
                Write-Host "No audit log found for this owner addition" -ForegroundColor Yellow
            }
        }
    }
    
    # Phase 2: Add owners from source that are not in destination
    Write-Host "`nPhase 2: Adding missing owners from source group..." -ForegroundColor Cyan
    
    foreach ($person in $sourceGroupOwners) {
        # Check if the owner from source group is NOT in the destination group
        if (-not ($destinationGroupOwners.Id -contains $person.Id)) {
            Write-Host "Adding owner from source: $($person.Id)" -ForegroundColor Yellow
            
            # Add the owner to the destination group
            $newGroupOwner = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($person.Id)"
            }
            
            New-MgGroupOwnerByRef -GroupId $DestinationGroupId -BodyParameter $newGroupOwner
            $user = (Get-MgUser -UserId $person.Id).DisplayName
            Write-Host "ADDED: $user" -ForegroundColor Green
        }
    }
    
    Write-Host "`nGroup owner synchronization completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "An error occurred during group owner synchronization: $($_.Exception.Message)"
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
} finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph
        Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Yellow
    } catch {
        Write-Warning "Could not disconnect from Microsoft Graph: $($_.Exception.Message)"
    }
}
