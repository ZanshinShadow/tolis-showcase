# Microsoft 365 User Management Automation
# Demonstrates enterprise-level user provisioning and management

param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\M365UserManagement.log",
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

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
    Write-Log "Starting Microsoft 365 User Management script"
    Write-Log "Parameters: TenantId=$TenantId, WhatIf=$WhatIf"
    
    # Connect to Microsoft Graph
    Connect-ToGraph -TenantId $TenantId
    
    # Example operations (uncomment as needed)
    
    # Create a sample user
    # $NewUser = New-StandardUser -FirstName "John" -LastName "Doe" -Department "IT" -JobTitle "System Administrator" -WhatIf:$WhatIf
    
    # Create a security group
    # $NewGroup = New-SecurityGroup -GroupName "IT-Administrators" -Description "IT Administration team" -WhatIf:$WhatIf
    
    # Generate compliance report
    # $ComplianceReport = Get-UserComplianceReport
    
    Write-Log "Script completed successfully"
    
} catch {
    Write-Log "Script failed: $($_.Exception.Message)" -Level "ERROR"
    throw
} finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph
        Write-Log "Disconnected from Microsoft Graph"
    } catch {
        Write-Log "Warning: Failed to disconnect from Microsoft Graph" -Level "WARNING"
    }
}
