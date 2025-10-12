<#
.SYNOPSIS
    Comprehensive audit script for hybrid security group usage across Azure and Microsoft 365 services.

.DESCRIPTION
    This script audits security group usage across multiple Azure and M365 services.
    It can audit all security groups in the tenant or a specific group based on user selection.
    It identifies where groups are referenced for access control, permissions, or roles to help
    assess the impact before deletion.

.PARAMETER GroupIdentifier
    Optional. The display name or Object ID of a specific security group to audit.
    If not provided, script will prompt whether to audit all groups or specific one.

.PARAMETER ExportPath
    Optional path to export the audit results. For single group, exports JSON file.
    For all groups, exports to a directory with individual JSON files and summary CSV.

.PARAMETER AuditAll
    Switch to automatically audit all groups without prompting.

.PARAMETER OnlyHybridGroups
    Switch to audit only hybrid (on-premises synced) security groups.

.PARAMETER SecurityEnabledOnly
    Switch to audit only security-enabled groups (excludes pure M365 groups).

.PARAMETER MaxGroups
    Maximum number of groups to audit (useful for testing). Default is unlimited.

.EXAMPLE
    .\Audit-SecurityGroupUsage-v2.ps1
    Interactive mode - prompts to select all groups or specific group.

.EXAMPLE
    .\Audit-SecurityGroupUsage-v2.ps1 -AuditAll -OnlyHybridGroups
    Automatically audits all hybrid groups without prompting.

.EXAMPLE
    .\Audit-SecurityGroupUsage-v2.ps1 -GroupIdentifier "SG-HybridUsers"
    Audits a specific group by name.

.EXAMPLE
    .\Audit-SecurityGroupUsage-v2.ps1 -AuditAll -ExportPath "C:\Audits" -MaxGroups 10
    Audits first 10 groups and exports to directory.

.NOTES
    Requires:
    - Microsoft.Graph PowerShell SDK (Install-Module -Name Microsoft.Graph)
    
    No Azure PowerShell (Az) modules required - uses only Microsoft Graph API!
    
    Permissions Required (Microsoft Graph):
    - Directory.Read.All
    - RoleManagement.Read.All
    - Group.Read.All
    - User.Read.All (optional)
    - Policy.Read.All (for Conditional Access)
    - Application.Read.All (for App Roles)
    
    What This Script Audits (Graph API Only):
    - Entra ID (Azure AD) Role Assignments
    - Directory-level RBAC Roles
    - Conditional Access Policies
    - Application Role Assignments
    - Microsoft Teams associations
    - SharePoint Sites (for M365 Groups)
    - Group memberships and properties
    
    Note: Azure subscription-level RBAC requires Azure PowerShell module.
    This version focuses on identity and directory-level access only.
    
    Author: Apostolos Tsirogiannis
    Date: October 12, 2025
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Group name or Object ID to audit (optional)")]
    [string]$GroupIdentifier,
    
    [Parameter(Mandatory = $false, HelpMessage = "Path to export audit results")]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false, HelpMessage = "Audit all groups without prompting")]
    [switch]$AuditAll,
    
    [Parameter(Mandatory = $false, HelpMessage = "Audit only hybrid (on-premises synced) groups")]
    [switch]$OnlyHybridGroups,
    
    [Parameter(Mandatory = $false, HelpMessage = "Audit only security-enabled groups")]
    [switch]$SecurityEnabledOnly,
    
    [Parameter(Mandatory = $false, HelpMessage = "Maximum number of groups to audit")]
    [int]$MaxGroups = 0
)

#Requires -Modules Microsoft.Graph.Authentication

# Global variables for tracking progress
$script:TotalGroupsProcessed = 0
$script:TotalGroupsWithReferences = 0
$script:AllGroupResults = @()

# Cache for subscriptions to avoid repeated API calls
$script:CachedSubscriptions = $null

#region Helper Functions

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        default { 'Cyan' }
    }
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host $Message -ForegroundColor $color
}

function Test-ModuleAvailability {
    param([string]$ModuleName)
    
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-AuditLog "Module '$ModuleName' is not installed. Some checks will be skipped." -Level Warning
        return $false
    }
    return $true
}

function Connect-AuditServices {
    Write-AuditLog "Connecting to Microsoft Graph..." -Level Info
    
    # Connect to Microsoft Graph (only service needed)
    try {
        $graphContext = Get-MgContext
        
        # Required scopes for this script
        $requiredScopes = @(
            "Directory.Read.All",
            "RoleManagement.Read.All",
            "Group.Read.All",
            "User.Read.All",
            "Policy.Read.All",
            "Application.Read.All"
        )
        
        if (-not $graphContext) {
            Write-AuditLog "Requesting Microsoft Graph authentication..." -Level Info
            Write-Host "`nThis script requires admin consent for the following permissions:" -ForegroundColor Yellow
            $requiredScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
            Write-Host ""
            
            try {
                Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
            }
            catch {
                Write-AuditLog "Full scope connection failed, trying with minimal scopes..." -Level Warning
                # Try with minimal scopes
                Connect-MgGraph -Scopes "Directory.Read.All","Group.Read.All","RoleManagement.Read.All" -NoWelcome -ErrorAction Stop
            }
        }
        else {
            # Check if existing context has required permissions
            $missingScopes = $requiredScopes | Where-Object { $graphContext.Scopes -notcontains $_ }
            
            if ($missingScopes.Count -gt 0) {
                Write-AuditLog "Existing connection found but missing required permissions." -Level Warning
                Write-Host "`nMissing permissions:" -ForegroundColor Yellow
                $missingScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
                Write-Host ""
                
                $reconnect = Read-Host "Reconnect with full permissions? (y/n)"
                if ($reconnect -eq 'y') {
                    Disconnect-MgGraph | Out-Null
                    Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
                }
                else {
                    Write-AuditLog "Continuing with existing permissions - some checks may fail." -Level Warning
                }
            }
        }
        
        $graphCtx = Get-MgContext
        Write-AuditLog "Microsoft Graph connected successfully!" -Level Success
        Write-AuditLog "  Tenant: $($graphCtx.TenantId)" -Level Info
        Write-AuditLog "  Account: $($graphCtx.Account)" -Level Info
        Write-AuditLog "  Scopes: $($graphCtx.Scopes -join ', ')" -Level Info
        
        # Verify we have at least Group.Read.All or Directory.Read.All
        if (($graphCtx.Scopes -notcontains "Group.Read.All") -and 
            ($graphCtx.Scopes -notcontains "Directory.Read.All")) {
            Write-AuditLog "ERROR: Missing critical permissions to read groups!" -Level Error
            Write-Host "`nThis script requires at minimum:" -ForegroundColor Red
            Write-Host "  - Group.Read.All OR Directory.Read.All" -ForegroundColor Yellow
            Write-Host "`nPlease disconnect and reconnect with admin consent:" -ForegroundColor Yellow
            Write-Host "  Disconnect-MgGraph" -ForegroundColor White
            Write-Host "  Connect-MgGraph -Scopes 'Directory.Read.All','Group.Read.All','RoleManagement.Read.All'" -ForegroundColor White
            throw "Insufficient permissions to proceed"
        }
    }
    catch {
        Write-AuditLog "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
        Write-Host "`nTroubleshooting Steps:" -ForegroundColor Yellow
        Write-Host "1. Disconnect: Disconnect-MgGraph" -ForegroundColor White
        Write-Host "2. Reconnect with admin consent: Connect-MgGraph -Scopes 'Directory.Read.All','Group.Read.All'" -ForegroundColor White
        Write-Host "3. If you're not a Global Admin, ask your admin to consent to these permissions" -ForegroundColor White
        throw
    }
    
    Write-AuditLog "Note: Using Microsoft Graph API for all checks (no Azure PowerShell required)" -Level Info
}

function Get-GroupsToAudit {
    param(
        [string]$SpecificIdentifier,
        [bool]$OnlyHybrid,
        [bool]$SecurityOnly,
        [int]$Max
    )
    
    Write-AuditLog "Retrieving groups to audit..." -Level Info
    
    try {
        if ($SpecificIdentifier) {
            # Single group specified
            $group = $null
            
            if ($SpecificIdentifier -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                $group = Get-MgGroup -GroupId $SpecificIdentifier -ErrorAction SilentlyContinue
            }
            
            if (-not $group) {
                $group = Get-MgGroup -Filter "displayName eq '$SpecificIdentifier'" -ErrorAction Stop
            }
            
            if (-not $group) {
                throw "Group not found: $SpecificIdentifier"
            }
            
            return @($group)
        }
        else {
            # Get all groups based on filters
            $filter = @()
            
            if ($SecurityOnly) {
                $filter += "securityEnabled eq true"
            }
            
            $filterString = if ($filter.Count -gt 0) { $filter -join " and " } else { $null }
            
            Write-AuditLog "Fetching groups from tenant (this may take a moment)..." -Level Info
            
            if ($filterString) {
                $groups = Get-MgGroup -Filter $filterString -All
            }
            else {
                $groups = Get-MgGroup -All
            }
            
            # Apply additional filters
            if ($OnlyHybrid) {
                $groups = $groups | Where-Object { $_.OnPremisesSyncEnabled -eq $true }
            }
            
            if ($Max -gt 0) {
                $groups = $groups | Select-Object -First $Max
            }
            
            Write-AuditLog "Found $($groups.Count) group(s) matching criteria" -Level Success
            
            return $groups
        }
    }
    catch {
        Write-AuditLog "Failed to retrieve groups: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Initialize-AuditResults {
    return @{
        GroupInfo = @{}
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        IdentityAndAccess = @{}
        AzureResources = @{}
        Microsoft365 = @{}
        SecurityCompliance = @{}
        DeviceManagement = @{}
        Summary = @{
            TotalReferences = 0
            CriticalReferences = @()
            Warnings = @()
        }
    }
}

#endregion

#region Main Audit Functions (same as before but using local $auditResults parameter)

function Get-GroupInformation {
    param(
        [object]$Group,
        [hashtable]$AuditResults
    )
    
    try {
        $groupDetails = @{
            ObjectId = $Group.Id
            DisplayName = $Group.DisplayName
            Description = $Group.Description
            MailEnabled = $Group.MailEnabled
            SecurityEnabled = $Group.SecurityEnabled
            GroupTypes = $Group.GroupTypes -join ", "
            OnPremisesSyncEnabled = $Group.OnPremisesSyncEnabled
            OnPremisesDomainName = $Group.OnPremisesDomainName
            OnPremisesSamAccountName = $Group.OnPremisesSamAccountName
            CreatedDateTime = $Group.CreatedDateTime
            MemberCount = (Get-MgGroupMember -GroupId $Group.Id -All -ErrorAction SilentlyContinue).Count
        }
        
        $AuditResults.GroupInfo = $groupDetails
        
        return $Group
    }
    catch {
        Write-AuditLog "Failed to retrieve group information: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-EntraIDRoleAssignments {
    param(
        [string]$GroupId,
        [hashtable]$AuditResults
    )
    
    $roleAssignments = @()
    
    try {
        $directoryRoles = Get-MgDirectoryRole -All
        
        foreach ($role in $directoryRoles) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
            
            if ($members.Id -contains $GroupId) {
                $roleAssignments += @{
                    RoleName = $role.DisplayName
                    RoleId = $role.Id
                    Description = $role.Description
                    RoleTemplateId = $role.RoleTemplateId
                    Type = "Directory Role"
                    Critical = $true
                }
            }
        }
        
        try {
            $pimAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$GroupId'" -All -ErrorAction SilentlyContinue
            
            foreach ($assignment in $pimAssignments) {
                $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId
                
                $roleAssignments += @{
                    RoleName = $roleDefinition.DisplayName
                    RoleId = $roleDefinition.Id
                    Description = $roleDefinition.Description
                    AssignmentType = $assignment.AssignmentType
                    Type = "Role Management"
                    Critical = $true
                }
            }
        }
        catch { }
        
        $AuditResults.IdentityAndAccess.EntraIDRoles = @{
            Count = $roleAssignments.Count
            Assignments = $roleAssignments
        }
        
        if ($roleAssignments.Count -gt 0) {
            $AuditResults.Summary.CriticalReferences += "Entra ID: $($roleAssignments.Count) role assignment(s)"
        }
    }
    catch {
        $AuditResults.IdentityAndAccess.EntraIDRoles = @{ Error = $_.Exception.Message }
    }
}

function Test-AzureRBACAssignments {
    param(
        [string]$GroupId,
        [hashtable]$AuditResults
    )
    
    $rbacAssignments = @()
    
    try {
        # Use Microsoft Graph to query Azure RBAC role assignments
        # Note: This requires specific Graph permissions
        
        # Get role assignments using Graph API
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$GroupId'"
        
        try {
            $assignments = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction SilentlyContinue
            
            if ($assignments.value) {
                foreach ($assignment in $assignments.value) {
                    try {
                        # Get role definition details
                        $roleDefUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$($assignment.roleDefinitionId)"
                        $roleDef = Invoke-MgGraphRequest -Uri $roleDefUri -Method GET -ErrorAction SilentlyContinue
                        
                        $rbacAssignments += @{
                            RoleName = $roleDef.displayName
                            RoleId = $assignment.roleDefinitionId
                            AssignmentId = $assignment.id
                            Scope = $assignment.directoryScopeId
                            Type = "Directory RBAC"
                        }
                    }
                    catch {
                        # Skip if can't get role details
                    }
                }
            }
        }
        catch {
            Write-AuditLog "Note: Azure subscription RBAC check requires Azure PowerShell (skipped)" -Level Warning
        }
        
        $AuditResults.AzureResources.RBAC = @{
            Count = $rbacAssignments.Count
            Assignments = $rbacAssignments
            Note = "Azure subscription-level RBAC requires Azure PowerShell module. This shows directory-level roles only."
        }
        
        if ($rbacAssignments.Count -gt 0) {
            $AuditResults.Summary.TotalReferences += $rbacAssignments.Count
        }
    }
    catch {
        $AuditResults.AzureResources.RBAC = @{ 
            Error = $_.Exception.Message
            Note = "Full Azure RBAC audit requires Azure PowerShell module"
        }
    }
}

function Test-ConditionalAccessPolicies {
    param(
        [string]$GroupId,
        [hashtable]$AuditResults
    )
    
    $complianceRefs = @()
    
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
        
        foreach ($policy in $caPolicies) {
            $includesGroup = $false
            
            if ($policy.Conditions.Users.IncludeGroups -contains $GroupId) {
                $includesGroup = $true
                $inclusionType = "Included"
            }
            elseif ($policy.Conditions.Users.ExcludeGroups -contains $GroupId) {
                $includesGroup = $true
                $inclusionType = "Excluded"
            }
            
            if ($includesGroup) {
                $complianceRefs += @{
                    Type = "Conditional Access Policy"
                    PolicyName = $policy.DisplayName
                    State = $policy.State
                    InclusionType = $inclusionType
                }
            }
        }
        
        $AuditResults.SecurityCompliance.ConditionalAccess = @{
            Count = $complianceRefs.Count
            References = $complianceRefs
        }
        
        if ($complianceRefs.Count -gt 0) {
            $AuditResults.Summary.TotalReferences += $complianceRefs.Count
            $AuditResults.Summary.CriticalReferences += "Conditional Access: $($complianceRefs.Count) policy(ies)"
        }
    }
    catch {
        $AuditResults.SecurityCompliance.ConditionalAccess = @{ Error = $_.Exception.Message }
    }
}

#endregion

#region Audit Single Group

function Test-MicrosoftTeamsUsage {
    param(
        [string]$GroupId,
        [object]$Group,
        [hashtable]$AuditResults
    )
    
    $teamsRefs = @()
    
    try {
        # Check if group is associated with a Team using Graph API
        if ($Group.GroupTypes -contains "Unified") {
            try {
                $uri = "https://graph.microsoft.com/v1.0/teams/$GroupId"
                $team = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction SilentlyContinue
                
                if ($team) {
                    $teamsRefs += @{
                        Type = "Microsoft Team"
                        TeamName = $team.displayName
                        Description = $team.description
                        Visibility = $team.visibility
                    }
                }
            }
            catch {
                # Group is not a Team
            }
        }
        
        $AuditResults.Microsoft365.Teams = @{
            Count = $teamsRefs.Count
            References = $teamsRefs
        }
        
        if ($teamsRefs.Count -gt 0) {
            $AuditResults.Summary.TotalReferences += $teamsRefs.Count
        }
    }
    catch {
        $AuditResults.Microsoft365.Teams = @{ Error = $_.Exception.Message }
    }
}

function Test-SharePointSites {
    param(
        [string]$GroupId,
        [object]$Group,
        [hashtable]$AuditResults
    )
    
    $spoRefs = @()
    
    try {
        if ($Group.GroupTypes -contains "Unified") {
            try {
                $sites = Get-MgGroupSite -GroupId $GroupId -All -ErrorAction SilentlyContinue
                
                foreach ($site in $sites) {
                    $spoRefs += @{
                        Type = "SharePoint Site"
                        SiteUrl = $site.WebUrl
                        SiteName = $site.DisplayName
                    }
                }
            }
            catch { }
        }
        
        $AuditResults.Microsoft365.SharePoint = @{
            Count = $spoRefs.Count
            References = $spoRefs
        }
        
        if ($spoRefs.Count -gt 0) {
            $AuditResults.Summary.TotalReferences += $spoRefs.Count
        }
    }
    catch {
        $AuditResults.Microsoft365.SharePoint = @{ Error = $_.Exception.Message }
    }
}

function Test-AppRoleAssignments {
    param(
        [string]$GroupId,
        [hashtable]$AuditResults
    )
    
    $appRoleRefs = @()
    
    try {
        # Get app role assignments (includes SSO assignments and role-based assignments)
        $appRoleAssignments = Get-MgGroupAppRoleAssignment -GroupId $GroupId -All -ErrorAction SilentlyContinue
        
        foreach ($assignment in $appRoleAssignments) {
            try {
                $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue
                
                # Get app role details (if a specific role is assigned)
                $appRole = $servicePrincipal.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
                
                # Determine assignment type
                $roleName = if ($appRole) { $appRole.DisplayName } else { "User/Default Access (SSO)" }
                $roleValue = if ($appRole) { $appRole.Value } else { "Default" }
                $assignmentType = if ($appRole) { "App Role" } else { "SSO/User Assignment" }
                
                $appRoleRefs += @{
                    AppDisplayName = $servicePrincipal.DisplayName
                    AppId = $servicePrincipal.AppId
                    ServicePrincipalId = $servicePrincipal.Id
                    AssignmentType = $assignmentType
                    RoleName = $roleName
                    RoleValue = $roleValue
                    AppOwnerOrganizationId = $servicePrincipal.AppOwnerOrganizationId
                    CreatedDateTime = $assignment.CreatedDateTime
                }
            }
            catch { }
        }
        
        $AuditResults.SecurityCompliance.AppRoles = @{
            Count = $appRoleRefs.Count
            Assignments = $appRoleRefs
        }
        
        if ($appRoleRefs.Count -gt 0) {
            $AuditResults.Summary.TotalReferences += $appRoleRefs.Count
        }
    }
    catch {
        $AuditResults.SecurityCompliance.AppRoles = @{ Error = $_.Exception.Message }
    }
}

function Invoke-GroupAudit {
    param(
        [object]$Group,
        [bool]$Verbose = $true
    )
    
    $auditResults = Initialize-AuditResults
    
    try {
        if ($Verbose) {
            Write-AuditLog "Auditing group: $($Group.DisplayName)" -Level Info
        }
        
        # Get group information
        Get-GroupInformation -Group $Group -AuditResults $auditResults | Out-Null
        
        # Run all audits using Microsoft Graph only
        Test-EntraIDRoleAssignments -GroupId $Group.Id -AuditResults $auditResults
        Test-AzureRBACAssignments -GroupId $Group.Id -AuditResults $auditResults
        Test-ConditionalAccessPolicies -GroupId $Group.Id -AuditResults $auditResults
        Test-AppRoleAssignments -GroupId $Group.Id -AuditResults $auditResults
        Test-MicrosoftTeamsUsage -GroupId $Group.Id -Group $Group -AuditResults $auditResults
        Test-SharePointSites -GroupId $Group.Id -Group $Group -AuditResults $auditResults
        
        if ($Verbose) {
            $refCount = $auditResults.Summary.TotalReferences
            if ($refCount -gt 0) {
                Write-AuditLog "Group has $refCount reference(s)" -Level Warning
            }
            else {
                Write-AuditLog "Group has no references" -Level Success
            }
        }
        
        return $auditResults
    }
    catch {
        Write-AuditLog "Error auditing group $($Group.DisplayName): $($_.Exception.Message)" -Level Error
        return $auditResults
    }
}

#endregion

#region Export Functions

function Export-SingleGroupResult {
    param(
        [hashtable]$AuditResults,
        [string]$Path
    )
    
    try {
        $AuditResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        Write-AuditLog "Exported results to: $Path" -Level Success
    }
    catch {
        Write-AuditLog "Failed to export results: $($_.Exception.Message)" -Level Error
    }
}

function Export-MultipleGroupResults {
    param(
        [array]$Results,
        [string]$DirectoryPath
    )
    
    try {
        # Create directory if it doesn't exist
        if (-not (Test-Path $DirectoryPath)) {
            New-Item -Path $DirectoryPath -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        
        # Export individual group files
        $exportCount = 0
        foreach ($result in $Results) {
            $groupName = $result.GroupInfo.DisplayName -replace '[\\/:*?"<>|]', '_'
            $filename = "$groupName-$($result.GroupInfo.ObjectId).json"
            $filepath = Join-Path $DirectoryPath $filename
            
            $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $filepath -Encoding UTF8
            $exportCount++
        }
        
        # Create summary JSON with detailed information
        $summary = $Results | ForEach-Object {
            [PSCustomObject]@{
                GroupName = $_.GroupInfo.DisplayName
                ObjectId = $_.GroupInfo.ObjectId
                GroupInfo = [PSCustomObject]@{
                    IsHybrid = $_.GroupInfo.OnPremisesSyncEnabled
                    IsSecurityEnabled = $_.GroupInfo.SecurityEnabled
                    GroupTypes = $_.GroupInfo.GroupTypes
                    MemberCount = $_.GroupInfo.MemberCount
                    Description = $_.GroupInfo.Description
                    CreatedDateTime = $_.GroupInfo.CreatedDateTime
                    OnPremisesDomainName = $_.GroupInfo.OnPremisesDomainName
                    OnPremisesSamAccountName = $_.GroupInfo.OnPremisesSamAccountName
                }
                TotalReferences = $_.Summary.TotalReferences
                # Entra ID Roles
                EntraIDRoles = [PSCustomObject]@{
                    Count = $_.IdentityAndAccess.EntraIDRoles.Count
                    Roles = if ($_.IdentityAndAccess.EntraIDRoles.Assignments) {
                        $_.IdentityAndAccess.EntraIDRoles.Assignments | ForEach-Object {
                            [PSCustomObject]@{
                                RoleName = $_.RoleName
                                Description = $_.Description
                                Type = $_.Type
                            }
                        }
                    } else { @() }
                }
                # Directory RBAC
                DirectoryRBAC = [PSCustomObject]@{
                    Count = $_.AzureResources.RBAC.Count
                    Roles = if ($_.AzureResources.RBAC.Assignments) {
                        $_.AzureResources.RBAC.Assignments | ForEach-Object {
                            [PSCustomObject]@{
                                RoleName = $_.RoleName
                                Scope = $_.Scope
                                Type = $_.Type
                            }
                        }
                    } else { @() }
                }
                # Conditional Access
                ConditionalAccess = [PSCustomObject]@{
                    Count = $_.SecurityCompliance.ConditionalAccess.Count
                    Policies = if ($_.SecurityCompliance.ConditionalAccess.References) {
                        $_.SecurityCompliance.ConditionalAccess.References | ForEach-Object {
                            [PSCustomObject]@{
                                PolicyName = $_.PolicyName
                                State = $_.State
                                InclusionType = $_.InclusionType
                            }
                        }
                    } else { @() }
                }
                # App Roles
                AppRoles = [PSCustomObject]@{
                    Count = $_.SecurityCompliance.AppRoles.Count
                    Assignments = if ($_.SecurityCompliance.AppRoles.Assignments) {
                        $_.SecurityCompliance.AppRoles.Assignments | ForEach-Object {
                            [PSCustomObject]@{
                                AppDisplayName = $_.AppDisplayName
                                AppId = $_.AppId
                                AssignmentType = $_.AssignmentType
                                RoleName = $_.RoleName
                                RoleValue = $_.RoleValue
                                CreatedDateTime = $_.CreatedDateTime
                            }
                        }
                    } else { @() }
                }
                # Teams
                Teams = [PSCustomObject]@{
                    Count = $_.Microsoft365.Teams.Count
                    Details = if ($_.Microsoft365.Teams.References) {
                        $_.Microsoft365.Teams.References | ForEach-Object {
                            [PSCustomObject]@{
                                TeamName = $_.TeamName
                                Description = $_.Description
                                Visibility = $_.Visibility
                            }
                        }
                    } else { @() }
                }
                # SharePoint
                SharePoint = [PSCustomObject]@{
                    Count = $_.Microsoft365.SharePoint.Count
                    Sites = if ($_.Microsoft365.SharePoint.References) {
                        $_.Microsoft365.SharePoint.References | ForEach-Object {
                            [PSCustomObject]@{
                                SiteName = $_.SiteName
                                SiteUrl = $_.SiteUrl
                            }
                        }
                    } else { @() }
                }
                # Summary
                CriticalReferences = $_.Summary.CriticalReferences
                AuditTimestamp = $_.Timestamp
            }
        }
        
        # Export as consolidated JSON
        $summaryPath = Join-Path $DirectoryPath "Summary-$timestamp.json"
        $summaryObject = [PSCustomObject]@{
            AuditDate = $timestamp
            TotalGroupsAudited = $Results.Count
            GroupsWithReferences = ($Results | Where-Object { $_.Summary.TotalReferences -gt 0 }).Count
            GroupsWithoutReferences = ($Results | Where-Object { $_.Summary.TotalReferences -eq 0 }).Count
            Groups = $summary
        }
        
        $summaryObject | ConvertTo-Json -Depth 15 | Out-File -FilePath $summaryPath -Encoding UTF8
        
        Write-AuditLog "Exported $exportCount group audit(s) to: $DirectoryPath" -Level Success
        Write-AuditLog "Summary JSON: $summaryPath" -Level Success
    }
    catch {
        Write-AuditLog "Failed to export results: $($_.Exception.Message)" -Level Error
    }
}

#endregion

#region Main Execution

try {
    Write-Host "`n╔════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Security Group Usage Audit Tool      ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════╝`n" -ForegroundColor Cyan
    
    # Connect to services
    Connect-AuditServices
    
    # Determine audit mode
    $auditMode = $null
    $groupsToAudit = @()
    
    if ($GroupIdentifier) {
        # Specific group provided via parameter
        $auditMode = "SPECIFIC"
        Write-AuditLog "Auditing specific group: $GroupIdentifier" -Level Info
    }
    elseif ($AuditAll) {
        # Audit all groups via parameter
        $auditMode = "ALL"
        Write-AuditLog "Auditing all groups (parameter specified)" -Level Info
    }
    else {
        # Interactive mode - ask user
        Write-Host "`nAudit Mode Selection:" -ForegroundColor Yellow
        Write-Host "  [1] Audit a specific group" -ForegroundColor White
        Write-Host "  [2] Audit all groups in tenant" -ForegroundColor White
        Write-Host "  [3] Audit all HYBRID groups only" -ForegroundColor White
        Write-Host "  [4] Audit all SECURITY-ENABLED groups only" -ForegroundColor White
        Write-Host ""
        
        do {
            $choice = Read-Host "Select option (1-4)"
        } while ($choice -notmatch '^[1-4]$')
        
        switch ($choice) {
            "1" {
                $auditMode = "SPECIFIC"
                $GroupIdentifier = Read-Host "Enter group name or Object ID"
            }
            "2" {
                $auditMode = "ALL"
                $confirm = Read-Host "This will audit ALL groups. Continue? (y/n)"
                if ($confirm -ne 'y') {
                    Write-Host "Operation cancelled." -ForegroundColor Yellow
                    return
                }
            }
            "3" {
                $auditMode = "HYBRID"
                $OnlyHybridGroups = $true
            }
            "4" {
                $auditMode = "SECURITY"
                $SecurityEnabledOnly = $true
            }
        }
    }
    
    # Get groups to audit
    $groupsToAudit = Get-GroupsToAudit -SpecificIdentifier $GroupIdentifier `
                                        -OnlyHybrid $OnlyHybridGroups `
                                        -SecurityOnly $SecurityEnabledOnly `
                                        -Max $MaxGroups
    
    if ($groupsToAudit.Count -eq 0) {
        Write-AuditLog "No groups found to audit." -Level Warning
        return
    }
    
    Write-Host "`n" + ("═" * 50) -ForegroundColor Cyan
    Write-Host "Starting audit of $($groupsToAudit.Count) group(s)..." -ForegroundColor Yellow
    Write-Host ("═" * 50) + "`n" -ForegroundColor Cyan
    
    # Audit groups
    $results = @()
    $currentCount = 0
    
    foreach ($group in $groupsToAudit) {
        $currentCount++
        
        if ($groupsToAudit.Count -gt 1) {
            Write-Host "`n[$currentCount/$($groupsToAudit.Count)] " -NoNewline -ForegroundColor Gray
        }
        
        $result = Invoke-GroupAudit -Group $group -Verbose:($groupsToAudit.Count -le 10)
        $results += $result
        
        if ($result.Summary.TotalReferences -gt 0) {
            $script:TotalGroupsWithReferences++
        }
        $script:TotalGroupsProcessed++
        
        # Progress indicator for large batches
        if ($groupsToAudit.Count -gt 10 -and $currentCount % 10 -eq 0) {
            Write-AuditLog "Progress: $currentCount/$($groupsToAudit.Count) groups audited" -Level Info
        }
    }
    
    # Display summary
    Write-Host "`n" + ("═" * 50) -ForegroundColor Cyan
    Write-Host "Audit Complete - Summary" -ForegroundColor Cyan
    Write-Host ("═" * 50) + "`n" -ForegroundColor Cyan
    
    Write-Host "Total groups audited: $($results.Count)" -ForegroundColor White
    Write-Host "Groups with references: $script:TotalGroupsWithReferences" -ForegroundColor Yellow
    Write-Host "Groups without references: $($results.Count - $script:TotalGroupsWithReferences)" -ForegroundColor Green
    
    # Show groups with references
    $groupsWithRefs = $results | Where-Object { $_.Summary.TotalReferences -gt 0 }
    if ($groupsWithRefs.Count -gt 0) {
        Write-Host "`nGroups with Active References:" -ForegroundColor Red
        foreach ($result in $groupsWithRefs) {
            Write-Host "  • $($result.GroupInfo.DisplayName) - $($result.Summary.TotalReferences) reference(s)" -ForegroundColor Yellow
            if ($result.Summary.CriticalReferences.Count -gt 0) {
                foreach ($ref in $result.Summary.CriticalReferences) {
                    Write-Host "    - $ref" -ForegroundColor Red
                }
            }
        }
    }
    
    # Export results
    if ($ExportPath) {
        if ($results.Count -eq 1) {
            # Single group - export as JSON file
            if (-not $ExportPath.EndsWith('.json')) {
                $ExportPath = $ExportPath + ".json"
            }
            Export-SingleGroupResult -AuditResults $results[0] -Path $ExportPath
        }
        else {
            # Multiple groups - export to directory
            Export-MultipleGroupResults -Results $results -DirectoryPath $ExportPath
        }
    }
    else {
        Write-Host "`nTo export results, use the -ExportPath parameter." -ForegroundColor Gray
    }
    
    Write-Host "`nAudit completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray
    
    # Return results
    if ($results.Count -eq 1) {
        return $results[0]
    }
    else {
        return $results
    }
}
catch {
    Write-AuditLog "Fatal error during audit: $($_.Exception.Message)" -Level Error
    Write-AuditLog "Stack trace: $($_.ScriptStackTrace)" -Level Error
    throw
}

#endregion
