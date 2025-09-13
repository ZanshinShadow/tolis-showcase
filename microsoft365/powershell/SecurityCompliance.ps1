# Microsoft 365 Security and Compliance Automation
# Demonstrates enterprise security monitoring and compliance management

param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\M365Security.log",
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Import required modules
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Security",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Reports",
    "ExchangeOnlineManagement"
)

foreach ($Module in $RequiredModules) {
    if (!(Get-Module -ListAvailable -Name $Module)) {
        Write-Host "Installing module: $Module" -ForegroundColor Yellow
        Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
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
    
    Write-Host $LogEntry -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
    
    # Ensure log directory exists
    $LogDir = Split-Path $LogPath -Parent
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    
    Add-Content -Path $LogPath -Value $LogEntry
}

# Connect to Microsoft Graph with security scopes
function Connect-ToGraphSecurity {
    param([string]$TenantId)
    
    try {
        Write-Log "Connecting to Microsoft Graph Security for tenant: $TenantId"
        
        $Scopes = @(
            "SecurityEvents.Read.All",
            "SecurityActions.Read.All",
            "AuditLog.Read.All",
            "Reports.Read.All",
            "Directory.Read.All",
            "Policy.Read.All"
        )
        
        Connect-MgGraph -TenantId $TenantId -Scopes $Scopes
        Write-Log "Successfully connected to Microsoft Graph Security" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Get security incidents and alerts
function Get-SecurityIncidents {
    param(
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 30,
        
        [Parameter(Mandatory = $false)]
        [string]$Severity = "All"
    )
    
    try {
        Write-Log "Retrieving security incidents from the last $DaysBack days"
        
        $StartDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        # Get security alerts
        $Filter = "createdDateTime ge $StartDate"
        if ($Severity -ne "All") {
            $Filter += " and severity eq '$Severity'"
        }
        
        $Alerts = Get-MgSecurityAlert -Filter $Filter -All
        
        Write-Log "Found $($Alerts.Count) security alerts"
        
        $IncidentSummary = $Alerts | Group-Object Severity | Select-Object Name, Count
        
        foreach ($Summary in $IncidentSummary) {
            Write-Log "  $($Summary.Name): $($Summary.Count) alerts"
        }
        
        return $Alerts
        
    } catch {
        Write-Log "Failed to retrieve security incidents: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Analyze risky sign-ins
function Get-RiskySignIns {
    param(
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 7
    )
    
    try {
        Write-Log "Analyzing risky sign-ins from the last $DaysBack days"
        
        $StartDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
        
        # Get risky sign-ins
        $RiskySignIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $StartDate and riskLevelDuringSignIn ne 'none'" -All
        
        Write-Log "Found $($RiskySignIns.Count) risky sign-ins"
        
        # Analyze by risk level
        $RiskAnalysis = $RiskySignIns | Group-Object RiskLevelDuringSignIn | Select-Object Name, Count
        
        foreach ($Risk in $RiskAnalysis) {
            Write-Log "  $($Risk.Name): $($Risk.Count) sign-ins" -Level "WARNING"
        }
        
        # Top risky users
        $TopRiskyUsers = $RiskySignIns | Group-Object UserPrincipalName | Sort-Object Count -Descending | Select-Object -First 10
        
        Write-Log "Top 10 users with risky sign-ins:"
        foreach ($User in $TopRiskyUsers) {
            Write-Log "  $($User.Name): $($User.Count) risky sign-ins" -Level "WARNING"
        }
        
        return $RiskySignIns
        
    } catch {
        Write-Log "Failed to analyze risky sign-ins: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Generate conditional access policy report
function Get-ConditionalAccessReport {
    try {
        Write-Log "Generating Conditional Access policy report"
        
        $CAPolicies = Get-MgIdentityConditionalAccessPolicy -All
        
        $PolicyReport = foreach ($Policy in $CAPolicies) {
            [PSCustomObject]@{
                DisplayName = $Policy.DisplayName
                State = $Policy.State
                CreatedDateTime = $Policy.CreatedDateTime
                ModifiedDateTime = $Policy.ModifiedDateTime
                IncludedUsers = ($Policy.Conditions.Users.IncludeUsers -join ", ")
                ExcludedUsers = ($Policy.Conditions.Users.ExcludeUsers -join ", ")
                IncludedApplications = ($Policy.Conditions.Applications.IncludeApplications -join ", ")
                GrantControls = ($Policy.GrantControls.BuiltInControls -join ", ")
                SessionControls = if ($Policy.SessionControls) { "Configured" } else { "None" }
            }
        }
        
        Write-Log "Found $($PolicyReport.Count) Conditional Access policies"
        
        # Count by state
        $StateCount = $PolicyReport | Group-Object State | Select-Object Name, Count
        foreach ($State in $StateCount) {
            Write-Log "  $($State.Name): $($State.Count) policies"
        }
        
        return $PolicyReport
        
    } catch {
        Write-Log "Failed to generate Conditional Access report: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Monitor suspicious activities
function Get-SuspiciousActivities {
    param(
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 7
    )
    
    try {
        Write-Log "Monitoring suspicious activities from the last $DaysBack days"
        
        $StartDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
        
        # Failed sign-ins
        $FailedSignIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $StartDate and status/errorCode ne 0" -All
        
        # Multiple failures by user
        $SuspiciousUsers = $FailedSignIns | 
            Group-Object UserPrincipalName | 
            Where-Object { $_.Count -gt 10 } | 
            Sort-Object Count -Descending
        
        Write-Log "Users with multiple failed sign-ins (>10):"
        foreach ($User in $SuspiciousUsers | Select-Object -First 10) {
            Write-Log "  $($User.Name): $($User.Count) failed attempts" -Level "WARNING"
        }
        
        # Sign-ins from unusual locations
        $UnusualLocations = $FailedSignIns | 
            Where-Object { $_.Location.CountryOrRegion -and $_.Location.CountryOrRegion -notin @("United States", "Canada") } |
            Group-Object @{Expression={$_.Location.CountryOrRegion}} |
            Sort-Object Count -Descending
        
        Write-Log "Failed sign-ins from unusual locations:"
        foreach ($Location in $UnusualLocations | Select-Object -First 5) {
            Write-Log "  $($Location.Name): $($Location.Count) attempts" -Level "WARNING"
        }
        
        return @{
            FailedSignIns = $FailedSignIns
            SuspiciousUsers = $SuspiciousUsers
            UnusualLocations = $UnusualLocations
        }
        
    } catch {
        Write-Log "Failed to monitor suspicious activities: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Generate comprehensive security report
function New-SecurityReport {
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\Reports\M365SecurityReport.html",
        
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 30
    )
    
    try {
        Write-Log "Generating comprehensive security report for the last $DaysBack days"
        
        # Collect data
        $SecurityAlerts = Get-SecurityIncidents -DaysBack $DaysBack
        $RiskySignIns = Get-RiskySignIns -DaysBack $DaysBack
        $CAPolicies = Get-ConditionalAccessReport
        $SuspiciousActivities = Get-SuspiciousActivities -DaysBack $DaysBack
        
        # Generate HTML report
        $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft 365 Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1 class="header">Microsoft 365 Security Report</h1>
    <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p>Reporting period: Last $DaysBack days</p>
    
    <div class="section">
        <h2>Security Alerts Summary</h2>
        <p>Total alerts: $($SecurityAlerts.Count)</p>
        $(if ($SecurityAlerts.Count -gt 0) {
            $AlertTable = $SecurityAlerts | Group-Object Severity | ConvertTo-Html -Fragment -Property Name, Count
            $AlertTable -replace '<table>', '<table style="width:100%; border-collapse:collapse;">'
        } else {
            "<p class='success'>No security alerts found.</p>"
        })
    </div>
    
    <div class="section">
        <h2>Risky Sign-ins</h2>
        <p>Total risky sign-ins: $($RiskySignIns.Count)</p>
        $(if ($RiskySignIns.Count -gt 0) {
            "<div class='warning'>Warning: Risky sign-ins detected. Review immediately.</div>"
        } else {
            "<p class='success'>No risky sign-ins detected.</p>"
        })
    </div>
    
    <div class="section">
        <h2>Conditional Access Policies</h2>
        <p>Total policies: $($CAPolicies.Count)</p>
        $(
            $EnabledPolicies = ($CAPolicies | Where-Object { $_.State -eq "enabled" }).Count
            $DisabledPolicies = ($CAPolicies | Where-Object { $_.State -eq "disabled" }).Count
            "<p>Enabled: $EnabledPolicies | Disabled: $DisabledPolicies</p>"
        )
    </div>
    
    <div class="section">
        <h2>Suspicious Activities</h2>
        <p>Failed sign-ins: $($SuspiciousActivities.FailedSignIns.Count)</p>
        <p>Users with multiple failures: $($SuspiciousActivities.SuspiciousUsers.Count)</p>
        $(if ($SuspiciousActivities.SuspiciousUsers.Count -gt 0) {
            "<div class='warning'>Warning: Multiple suspicious users detected.</div>"
        })
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            $(if ($RiskySignIns.Count -gt 0) { "<li>Review and investigate risky sign-ins</li>" })
            $(if ($SuspiciousActivities.SuspiciousUsers.Count -gt 0) { "<li>Investigate users with multiple failed sign-ins</li>" })
            $(if ($DisabledPolicies -gt 0) { "<li>Review disabled Conditional Access policies</li>" })
            <li>Ensure MFA is enabled for all users</li>
            <li>Review privileged access regularly</li>
            <li>Monitor for new security alerts daily</li>
        </ul>
    </div>
</body>
</html>
"@
        
        # Ensure output directory exists
        $OutputDir = Split-Path $OutputPath -Parent
        if (!(Test-Path $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }
        
        $HTML | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Log "Security report generated: $OutputPath" -Level "SUCCESS"
        
        return $OutputPath
        
    } catch {
        Write-Log "Failed to generate security report: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Main execution
try {
    Write-Log "Starting Microsoft 365 Security and Compliance script"
    Write-Log "Parameters: TenantId=$TenantId, WhatIf=$WhatIf"
    
    # Connect to Microsoft Graph
    Connect-ToGraphSecurity -TenantId $TenantId
    
    # Generate comprehensive security report
    if (!$WhatIf) {
        $ReportPath = New-SecurityReport -DaysBack 30
        Write-Log "Security analysis completed. Report available at: $ReportPath" -Level "SUCCESS"
    } else {
        Write-Log "WHATIF: Would generate security report for the last 30 days"
    }
    
    Write-Log "Script completed successfully" -Level "SUCCESS"
    
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
