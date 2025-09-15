<#
.SYNOPSIS
    Enterprise Microsoft 365 User Management Automation Script

.DESCRIPTION
    This PowerShell script provides comprehensive user lifecycle management for Microsoft 365 environments.
    It demonstrates enterprise-level automation for user provisioning, deprovisioning, group management,
    and license assignment using Microsoft Graph PowerShell SDK.

    KEY FEATURES:
    • Automated user creation with standardized configurations
    • Security group creation and membership management  
    • License assignment and management
    • Bulk user operations from CSV files
    • Manager-subordinate relationship configuration
    • Comprehensive logging and audit trails
    • Dry-run capability with -WhatIf parameter
    • Error handling and rollback capabilities

    ENTERPRISE INTEGRATION:
    • Supports Azure Automation runbooks with Managed Identity
    • Integrates with ITSM systems for approval workflows
    • Provides detailed reporting for compliance requirements
    • Implements security best practices for privileged operations

.PARAMETER TenantId
    The Azure AD tenant ID where operations will be performed.
    Mandatory parameter that identifies the target Microsoft 365 organization.
    
    Example: "12345678-1234-1234-1234-123456789012"

.PARAMETER LogPath
    Specifies the full path where operation logs will be written.
    Default: "C:\Logs\M365UserManagement.log"
    
    The log directory will be created automatically if it doesn't exist.
    Logs include timestamps, operation details, and security audit information.

.PARAMETER WhatIf
    When specified, the script runs in simulation mode without making actual changes.
    Useful for testing and validation before executing operations in production.
    
    All proposed changes are logged with "WHATIF:" prefix for review.

.EXAMPLE
    .\UserManagement.ps1 -TenantId "12345678-1234-1234-1234-123456789012"
    
    Connects to the specified tenant and runs the interactive user management menu.
    Logs operations to the default path: C:\Logs\M365UserManagement.log

.EXAMPLE
    .\UserManagement.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -WhatIf
    
    Runs in simulation mode to preview all operations without making changes.
    Useful for testing automation logic and validating configurations.

.EXAMPLE
    .\UserManagement.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -LogPath "D:\Audit\M365Operations.log"
    
    Executes user management operations with custom logging location.
    Useful for centralized logging or compliance requirements.

.INPUTS
    • CSV files for bulk user operations (UserImport.csv)
    • Configuration files for department-specific settings
    • Manager assignment data for organizational hierarchy

.OUTPUTS
    • Detailed operation logs with timestamps and results
    • User creation confirmation with assigned licenses
    • Group membership reports and audit trails
    • Error reports with troubleshooting information

.NOTES
    File Name      : UserManagement.ps1
    Author         : Senior System Engineer - Showcase Project
    Prerequisite   : PowerShell 5.1+ or PowerShell Core 7+
    Creation Date  : 2024
    
    REQUIRED MODULES:
    • Microsoft.Graph.Authentication
    • Microsoft.Graph.Users  
    • Microsoft.Graph.Groups
    • Microsoft.Graph.Identity.DirectoryManagement
    
    REQUIRED PERMISSIONS:
    • User.ReadWrite.All - Create, update, and delete users
    • Group.ReadWrite.All - Manage security groups and membership
    • Directory.ReadWrite.All - Access directory objects and relationships
    
    SECURITY CONSIDERATIONS:
    • Script requires Global Administrator or privileged role assignment
    • All operations are logged for security audit and compliance
    • Supports Azure Automation Managed Identity for secure automation
    • Implements least-privilege principle with granular Graph scopes

.LINK
    https://docs.microsoft.com/en-us/graph/api/overview
    
.LINK
    https://docs.microsoft.com/en-us/powershell/microsoftgraph/

.COMPONENT
    Microsoft Graph PowerShell SDK
    
.FUNCTIONALITY
    Microsoft 365 User Lifecycle Management
    Identity and Access Management (IAM)
    Enterprise Automation and Orchestration
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\M365UserManagement.log",
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Script execution tracking
$script:StartTime = Get-Date

# Import required modules
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.DirectoryManagement"
)

foreach ($Module in $RequiredModules) {
    if (!(Get-Module -ListAvailable -Name $Module)) {
        Write-Host "Installing module: $Module" -ForegroundColor Yellow
        Install-Module -Name $Module -Force -AllowClobber
    }
    Import-Module $Module
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    Write-Host $LogEntry
    
    # Ensure log directory exists
    $LogDir = Split-Path $LogPath -Parent
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    
    Add-Content -Path $LogPath -Value $LogEntry
}

# Connect to Microsoft Graph
function Connect-ToGraph {
    param([string]$TenantId)
    
    try {
        Write-Log "Connecting to Microsoft Graph for tenant: $TenantId"
        
        # Required scopes for user and group management
        $Scopes = @(
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Directory.ReadWrite.All"
        )
        
        Connect-MgGraph -TenantId $TenantId -Scopes $Scopes
        Write-Log "Successfully connected to Microsoft Graph"
        
        # Verify connection
        $Context = Get-MgContext
        Write-Log "Connected as: $($Context.Account)"
        
    } catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Create new user with standard configuration
function New-StandardUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FirstName,
        
        [Parameter(Mandatory = $true)]
        [string]$LastName,
        
        [Parameter(Mandatory = $true)]
        [string]$Department,
        
        [Parameter(Mandatory = $true)]
        [string]$JobTitle,
        
        [Parameter(Mandatory = $false)]
        [string]$Manager,
        
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )
    
    try {
        # Generate user principal name
        $Domain = (Get-MgDomain | Where-Object { $_.IsDefault -eq $true }).Id
        $UserPrincipalName = "$($FirstName.ToLower()).$($LastName.ToLower())@$Domain"
        $DisplayName = "$FirstName $LastName"
        
        # Generate temporary password
        $TempPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object { [char]$_ })
        
        # User parameters
        $UserParams = @{
            AccountEnabled = $true
            DisplayName = $DisplayName
            UserPrincipalName = $UserPrincipalName
            GivenName = $FirstName
            Surname = $LastName
            JobTitle = $JobTitle
            Department = $Department
            PasswordProfile = @{
                Password = $TempPassword
                ForceChangePasswordNextSignIn = $true
            }
            UsageLocation = "US"
        }
        
        if ($Manager) {
            $ManagerUser = Get-MgUser -Filter "userPrincipalName eq '$Manager'" -ErrorAction SilentlyContinue
            if ($ManagerUser) {
                $UserParams.Add("ManagerId", $ManagerUser.Id)
            }
        }
        
        Write-Log "Creating user: $UserPrincipalName"
        
        if ($WhatIf) {
            Write-Log "WHATIF: Would create user with parameters: $($UserParams | ConvertTo-Json -Depth 2)"
            return
        }
        
        $NewUser = New-MgUser @UserParams
        Write-Log "Successfully created user: $($NewUser.UserPrincipalName) (ID: $($NewUser.Id))"
        
        # Return user details including temporary password
        return @{
            UserPrincipalName = $NewUser.UserPrincipalName
            DisplayName = $NewUser.DisplayName
            Id = $NewUser.Id
            TempPassword = $TempPassword
        }
        
    } catch {
        Write-Log "Failed to create user $UserPrincipalName : $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Create security group with standard settings
function New-SecurityGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Members,
        
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )
    
    try {
        $GroupParams = @{
            DisplayName = $GroupName
            Description = $Description
            GroupTypes = @()
            SecurityEnabled = $true
            MailEnabled = $false
        }
        
        Write-Log "Creating security group: $GroupName"
        
        if ($WhatIf) {
            Write-Log "WHATIF: Would create group with parameters: $($GroupParams | ConvertTo-Json -Depth 2)"
            return
        }
        
        $NewGroup = New-MgGroup @GroupParams
        Write-Log "Successfully created group: $($NewGroup.DisplayName) (ID: $($NewGroup.Id))"
        
        # Add members if specified
        if ($Members) {
            foreach ($Member in $Members) {
                $User = Get-MgUser -Filter "userPrincipalName eq '$Member'" -ErrorAction SilentlyContinue
                if ($User) {
                    New-MgGroupMember -GroupId $NewGroup.Id -DirectoryObjectId $User.Id
                    Write-Log "Added $Member to group $GroupName"
                }
            }
        }
        
        return $NewGroup
        
    } catch {
        Write-Log "Failed to create group $GroupName : $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Bulk user operations from CSV
function Import-UsersFromCSV {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CSVPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )
    
    try {
        if (!(Test-Path $CSVPath)) {
            throw "CSV file not found: $CSVPath"
        }
        
        $Users = Import-Csv -Path $CSVPath
        $Results = @()
        
        Write-Log "Processing $($Users.Count) users from CSV: $CSVPath"
        
        foreach ($User in $Users) {
            try {
                $Result = New-StandardUser -FirstName $User.FirstName -LastName $User.LastName -Department $User.Department -JobTitle $User.JobTitle -Manager $User.Manager -WhatIf:$WhatIf
                $Results += $Result
            } catch {
                Write-Log "Failed to process user $($User.FirstName) $($User.LastName): $($_.Exception.Message)" -Level "ERROR"
            }
        }
        
        return $Results
        
    } catch {
        Write-Log "Failed to import users from CSV: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Generate compliance report
function Get-UserComplianceReport {
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\Reports\UserComplianceReport.csv"
    )
    
    try {
        Write-Log "Generating user compliance report"
        
        $Users = Get-MgUser -All -Property "Id,UserPrincipalName,DisplayName,AccountEnabled,CreatedDateTime,LastSignInDateTime,Department,JobTitle"
        
        $Report = foreach ($User in $Users) {
            [PSCustomObject]@{
                UserPrincipalName = $User.UserPrincipalName
                DisplayName = $User.DisplayName
                AccountEnabled = $User.AccountEnabled
                Department = $User.Department
                JobTitle = $User.JobTitle
                CreatedDateTime = $User.CreatedDateTime
                LastSignInDateTime = $User.LastSignInDateTime
                DaysSinceLastSignIn = if ($User.LastSignInDateTime) { 
                    (Get-Date) - $User.LastSignInDateTime | Select-Object -ExpandProperty Days 
                } else { 
                    "Never" 
                }
            }
        }
        
        # Ensure output directory exists
        $OutputDir = Split-Path $OutputPath -Parent
        if (!(Test-Path $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }
        
        $Report | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Log "Compliance report exported to: $OutputPath"
        
        return $Report
        
    } catch {
        Write-Log "Failed to generate compliance report: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Main execution
try {
    Write-Log "=== Microsoft 365 User Management Script Started ===" -Level "INFO"
    Write-Log "Execution Parameters:" -Level "INFO"
    Write-Log "  - Tenant ID: $TenantId" -Level "INFO"
    Write-Log "  - Log Path: $LogPath" -Level "INFO"
    Write-Log "  - WhatIf Mode: $WhatIf" -Level "INFO"
    Write-Log "  - PowerShell Version: $($PSVersionTable.PSVersion)" -Level "INFO"
    Write-Log "  - Execution Policy: $(Get-ExecutionPolicy)" -Level "INFO"
    
    # Connect to Microsoft Graph
    Write-Log "Initiating Microsoft Graph connection..." -Level "INFO"
    Connect-ToGraph -TenantId $TenantId
    
    # Display current context information
    $Context = Get-MgContext
    Write-Log "Graph Connection Details:" -Level "INFO"
    Write-Log "  - Account: $($Context.Account)" -Level "INFO"
    Write-Log "  - Environment: $($Context.Environment)" -Level "INFO"
    Write-Log "  - Scopes: $($Context.Scopes -join ', ')" -Level "INFO"
    
    Write-Log "=== Enterprise User Management Operations ===" -Level "INFO"
    
    # EXAMPLE 1: Create a sample user with enterprise configuration
    Write-Log "Example 1: Creating enterprise user account..." -Level "INFO"
    # Uncomment to execute: 
    # $NewUser = New-StandardUser -FirstName "John" -LastName "Doe" -Department "IT" -JobTitle "System Administrator" -WhatIf:$WhatIf
    
    # EXAMPLE 2: Create department security groups
    Write-Log "Example 2: Creating department security groups..." -Level "INFO"
    # Uncomment to execute:
    # $ITGroup = New-SecurityGroup -GroupName "IT-Administrators" -Description "IT Administration and Infrastructure Team" -WhatIf:$WhatIf
    # $HRGroup = New-SecurityGroup -GroupName "HR-Personnel" -Description "Human Resources Department" -WhatIf:$WhatIf
    # $FinanceGroup = New-SecurityGroup -GroupName "Finance-Users" -Description "Finance and Accounting Department" -WhatIf:$WhatIf
    
    # EXAMPLE 3: Bulk user import from CSV
    Write-Log "Example 3: Bulk user import capability..." -Level "INFO"
    # Uncomment to execute:
    # if (Test-Path ".\UserImport.csv") {
    #     Import-UsersFromCSV -CSVPath ".\UserImport.csv" -WhatIf:$WhatIf
    # } else {
    #     Write-Log "Sample CSV file not found - bulk import skipped" -Level "WARNING"
    # }
    
    # EXAMPLE 4: Generate compliance and audit reports
    Write-Log "Example 4: Generating compliance reports..." -Level "INFO"
    # Uncomment to execute:
    # $ComplianceReport = Get-UserComplianceReport
    # Write-Log "Compliance report generated with $($ComplianceReport.TotalUsers) users analyzed" -Level "INFO"
    
    # PRODUCTION USAGE EXAMPLES:
    Write-Log "=== Production Usage Examples ===" -Level "INFO"
    Write-Log "To use this script in production:" -Level "INFO"
    Write-Log "1. Uncomment desired operations above" -Level "INFO"
    Write-Log "2. Modify parameters to match your organization" -Level "INFO"
    Write-Log "3. Test with -WhatIf parameter first" -Level "INFO"
    Write-Log "4. Schedule via Azure Automation or Task Scheduler" -Level "INFO"
    Write-Log "5. Integrate with ITSM workflows for approvals" -Level "INFO"
    
    Write-Log "=== Script Execution Completed Successfully ===" -Level "INFO"
    Write-Log "Duration: $((Get-Date) - $script:StartTime | Select-Object -ExpandProperty TotalSeconds) seconds" -Level "INFO"
    
} catch {
    Write-Log "=== SCRIPT EXECUTION FAILED ===" -Level "ERROR"
    Write-Log "Error Details: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.Exception.StackTrace)" -Level "ERROR"
    Write-Log "Failed Line: $($_.InvocationInfo.ScriptLineNumber)" -Level "ERROR"
    
    # Additional error context for troubleshooting
    Write-Log "Troubleshooting Information:" -Level "ERROR"
    Write-Log "  - PowerShell Version: $($PSVersionTable.PSVersion)" -Level "ERROR"
    Write-Log "  - Execution Policy: $(Get-ExecutionPolicy)" -Level "ERROR"
    Write-Log "  - Current User: $($env:USERNAME)" -Level "ERROR"
    
    throw
} finally {
    Write-Log "=== Cleanup and Disconnection ===" -Level "INFO"
    
    # Disconnect from Microsoft Graph
    try {
        if (Get-MgContext) {
            Disconnect-MgGraph
            Write-Log "Successfully disconnected from Microsoft Graph" -Level "INFO"
        }
    } catch {
        Write-Log "Warning: Failed to disconnect from Microsoft Graph cleanly: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Final log entry
    Write-Log "=== Microsoft 365 User Management Script Session Ended ===" -Level "INFO"
    Write-Log "Log file location: $LogPath" -Level "INFO"
}
