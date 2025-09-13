# Azure Resource Monitoring and Cost Management
# Demonstrates enterprise Azure resource governance and optimization

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\AzureMonitoring.log",
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Import required modules
$RequiredModules = @(
    "Az.Accounts",
    "Az.Resources",
    "Az.Monitor",
    "Az.Billing",
    "Az.PolicyInsights",
    "Az.Security"
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

# Connect to Azure
function Connect-ToAzure {
    param([string]$SubscriptionId)
    
    try {
        Write-Log "Connecting to Azure subscription: $SubscriptionId"
        
        # Check if already connected
        $Context = Get-AzContext
        if ($Context -and $Context.Subscription.Id -eq $SubscriptionId) {
            Write-Log "Already connected to the correct subscription"
            return
        }
        
        # Connect to Azure
        Connect-AzAccount -Subscription $SubscriptionId
        
        # Verify connection
        $Context = Get-AzContext
        Write-Log "Successfully connected to Azure subscription: $($Context.Subscription.Name)" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to connect to Azure: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Get resource inventory
function Get-ResourceInventory {
    param(
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName
    )
    
    try {
        Write-Log "Collecting resource inventory"
        
        if ($ResourceGroupName) {
            $Resources = Get-AzResource -ResourceGroupName $ResourceGroupName
            Write-Log "Found $($Resources.Count) resources in resource group: $ResourceGroupName"
        } else {
            $Resources = Get-AzResource
            Write-Log "Found $($Resources.Count) total resources in subscription"
        }
        
        # Group by resource type
        $ResourceTypes = $Resources | Group-Object ResourceType | Sort-Object Count -Descending
        
        Write-Log "Resource breakdown by type:"
        foreach ($Type in $ResourceTypes | Select-Object -First 10) {
            Write-Log "  $($Type.Name): $($Type.Count)"
        }
        
        # Group by location
        $Locations = $Resources | Group-Object Location | Sort-Object Count -Descending
        
        Write-Log "Resource breakdown by location:"
        foreach ($Location in $Locations) {
            Write-Log "  $($Location.Name): $($Location.Count)"
        }
        
        return $Resources
        
    } catch {
        Write-Log "Failed to collect resource inventory: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Analyze cost and usage
function Get-CostAnalysis {
    param(
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 30
    )
    
    try {
        Write-Log "Analyzing costs for the last $DaysBack days"
        
        $EndDate = Get-Date
        $StartDate = $EndDate.AddDays(-$DaysBack)
        
        # Get cost data (Note: This requires appropriate permissions)
        try {
            $CostData = Get-AzConsumptionUsageDetail -StartDate $StartDate -EndDate $EndDate
            
            if ($CostData) {
                # Analyze by resource group
                $CostByRG = $CostData | Group-Object ResourceGroup | 
                    ForEach-Object {
                        [PSCustomObject]@{
                            ResourceGroup = $_.Name
                            TotalCost = ($_.Group | Measure-Object PretaxCost -Sum).Sum
                            ResourceCount = $_.Count
                        }
                    } | Sort-Object TotalCost -Descending
                
                Write-Log "Top 10 resource groups by cost:"
                foreach ($RG in $CostByRG | Select-Object -First 10) {
                    Write-Log "  $($RG.ResourceGroup): $([math]::Round($RG.TotalCost, 2))"
                }
                
                # Analyze by service
                $CostByService = $CostData | Group-Object ConsumedService | 
                    ForEach-Object {
                        [PSCustomObject]@{
                            Service = $_.Name
                            TotalCost = ($_.Group | Measure-Object PretaxCost -Sum).Sum
                            UsageCount = $_.Count
                        }
                    } | Sort-Object TotalCost -Descending
                
                Write-Log "Top 10 services by cost:"
                foreach ($Service in $CostByService | Select-Object -First 10) {
                    Write-Log "  $($Service.Service): $([math]::Round($Service.TotalCost, 2))"
                }
                
                return @{
                    CostByResourceGroup = $CostByRG
                    CostByService = $CostByService
                    TotalCost = ($CostData | Measure-Object PretaxCost -Sum).Sum
                }
            }
        } catch {
            Write-Log "Unable to retrieve detailed cost data. This may require billing reader permissions." -Level "WARNING"
            return $null
        }
        
    } catch {
        Write-Log "Failed to analyze costs: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Check compliance with Azure Policy
function Get-PolicyCompliance {
    try {
        Write-Log "Checking Azure Policy compliance"
        
        # Get policy assignments
        $PolicyAssignments = Get-AzPolicyAssignment
        Write-Log "Found $($PolicyAssignments.Count) policy assignments"
        
        # Get compliance states
        $ComplianceStates = Get-AzPolicyState
        
        if ($ComplianceStates) {
            # Summarize compliance
            $ComplianceSummary = $ComplianceStates | Group-Object ComplianceState | 
                Select-Object Name, Count
            
            Write-Log "Policy compliance summary:"
            foreach ($State in $ComplianceSummary) {
                $Level = if ($State.Name -eq "NonCompliant") { "WARNING" } else { "INFO" }
                Write-Log "  $($State.Name): $($State.Count)" -Level $Level
            }
            
            # Non-compliant resources
            $NonCompliant = $ComplianceStates | Where-Object { $_.ComplianceState -eq "NonCompliant" }
            
            if ($NonCompliant) {
                Write-Log "Non-compliant resources found:" -Level "WARNING"
                $NonCompliantByPolicy = $NonCompliant | Group-Object PolicyDefinitionName | 
                    Sort-Object Count -Descending
                
                foreach ($Policy in $NonCompliantByPolicy | Select-Object -First 5) {
                    Write-Log "  $($Policy.Name): $($Policy.Count) resources" -Level "WARNING"
                }
            }
            
            return @{
                PolicyAssignments = $PolicyAssignments
                ComplianceStates = $ComplianceStates
                NonCompliantResources = $NonCompliant
            }
        }
        
    } catch {
        Write-Log "Failed to check policy compliance: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Security recommendations
function Get-SecurityRecommendations {
    try {
        Write-Log "Retrieving security recommendations from Azure Security Center"
        
        try {
            # Get security assessments
            $SecurityAssessments = Get-AzSecurityAssessment
            
            if ($SecurityAssessments) {
                # Group by status
                $AssessmentSummary = $SecurityAssessments | Group-Object Status | 
                    Select-Object Name, Count
                
                Write-Log "Security assessment summary:"
                foreach ($Status in $AssessmentSummary) {
                    $Level = if ($Status.Name -in @("Unhealthy", "NotApplicable")) { "WARNING" } else { "INFO" }
                    Write-Log "  $($Status.Name): $($Status.Count)" -Level $Level
                }
                
                # High severity recommendations
                $HighSeverity = $SecurityAssessments | Where-Object { 
                    $_.Status -eq "Unhealthy" -and $_.Severity -eq "High" 
                }
                
                if ($HighSeverity) {
                    Write-Log "High severity security issues found:" -Level "WARNING"
                    foreach ($Issue in $HighSeverity | Select-Object -First 5) {
                        Write-Log "  $($Issue.DisplayName)" -Level "WARNING"
                    }
                }
                
                return $SecurityAssessments
            }
        } catch {
            Write-Log "Unable to retrieve security assessments. Azure Security Center may not be enabled." -Level "WARNING"
            return $null
        }
        
    } catch {
        Write-Log "Failed to get security recommendations: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Resource optimization recommendations
function Get-OptimizationRecommendations {
    param([array]$Resources)
    
    try {
        Write-Log "Generating resource optimization recommendations"
        
        $Recommendations = @()
        
        # Check for unattached disks
        $UnattachedDisks = $Resources | Where-Object { 
            $_.ResourceType -eq "Microsoft.Compute/disks" -and 
            (Get-AzDisk -ResourceGroupName $_.ResourceGroupName -DiskName $_.Name).DiskState -eq "Unattached"
        }
        
        if ($UnattachedDisks) {
            $Recommendations += "Found $($UnattachedDisks.Count) unattached disks that could be deleted to save costs"
        }
        
        # Check for unused public IPs
        $UnusedPublicIPs = $Resources | Where-Object { 
            $_.ResourceType -eq "Microsoft.Network/publicIPAddresses"
        } | ForEach-Object {
            $PIP = Get-AzPublicIpAddress -ResourceGroupName $_.ResourceGroupName -Name $_.Name
            if (-not $PIP.IpConfiguration) {
                $_
            }
        }
        
        if ($UnusedPublicIPs) {
            $Recommendations += "Found $($UnusedPublicIPs.Count) unused public IP addresses"
        }
        
        # Check for old snapshots
        $OldSnapshots = $Resources | Where-Object { 
            $_.ResourceType -eq "Microsoft.Compute/snapshots"
        } | ForEach-Object {
            $Snapshot = Get-AzSnapshot -ResourceGroupName $_.ResourceGroupName -SnapshotName $_.Name
            if ($Snapshot.TimeCreated -lt (Get-Date).AddDays(-30)) {
                $_
            }
        }
        
        if ($OldSnapshots) {
            $Recommendations += "Found $($OldSnapshots.Count) snapshots older than 30 days"
        }
        
        # Check for oversized VMs
        $VMs = $Resources | Where-Object { $_.ResourceType -eq "Microsoft.Compute/virtualMachines" }
        foreach ($VM in $VMs) {
            try {
                $VMDetails = Get-AzVM -ResourceGroupName $VM.ResourceGroupName -Name $VM.Name
                $VMSize = $VMDetails.HardwareProfile.VmSize
                
                # Simple check for potentially oversized VMs
                if ($VMSize -match "Standard_D[4-9]|Standard_E[4-9]|Standard_F[4-9]") {
                    $Recommendations += "VM $($VM.Name) is using size $VMSize - consider rightsizing if underutilized"
                }
            } catch {
                # Skip if unable to get VM details
            }
        }
        
        Write-Log "Generated $($Recommendations.Count) optimization recommendations"
        foreach ($Rec in $Recommendations) {
            Write-Log "  • $Rec" -Level "WARNING"
        }
        
        return $Recommendations
        
    } catch {
        Write-Log "Failed to generate optimization recommendations: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Generate comprehensive monitoring report
function New-MonitoringReport {
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\Reports\AzureMonitoringReport.html"
    )
    
    try {
        Write-Log "Generating comprehensive Azure monitoring report"
        
        # Collect all data
        $Resources = Get-ResourceInventory -ResourceGroupName $ResourceGroupName
        $CostAnalysis = Get-CostAnalysis -DaysBack 30
        $PolicyCompliance = Get-PolicyCompliance
        $SecurityRecommendations = Get-SecurityRecommendations
        $OptimizationRecommendations = Get-OptimizationRecommendations -Resources $Resources
        
        # Generate HTML report
        $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Monitoring Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .info { background-color: #e7f3ff; border-color: #bee5eb; }
        ul { margin: 10px 0; }
        li { margin: 5px 0; }
    </style>
</head>
<body>
    <h1 class="header">Azure Monitoring Report</h1>
    <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p>Subscription ID: $SubscriptionId</p>
    $(if ($ResourceGroupName) { "<p>Resource Group: $ResourceGroupName</p>" })
    
    <div class="section info">
        <h2>Resource Inventory</h2>
        <p>Total resources: $($Resources.Count)</p>
        <p>Resource types: $(($Resources | Group-Object ResourceType).Count)</p>
        <p>Locations: $(($Resources | Group-Object Location).Count)</p>
    </div>
    
    $(if ($CostAnalysis) {
        "<div class='section info'>
            <h2>Cost Analysis (Last 30 Days)</h2>
            <p>Total cost: $([math]::Round($CostAnalysis.TotalCost, 2))</p>
            <p>Top cost drivers identified</p>
        </div>"
    } else {
        "<div class='section warning'>
            <h2>Cost Analysis</h2>
            <p>Cost data unavailable - requires billing reader permissions</p>
        </div>"
    })
    
    $(if ($PolicyCompliance) {
        $NonCompliantCount = ($PolicyCompliance.ComplianceStates | Where-Object { $_.ComplianceState -eq "NonCompliant" }).Count
        if ($NonCompliantCount -gt 0) {
            "<div class='section warning'>
                <h2>Policy Compliance</h2>
                <p>Non-compliant resources: $NonCompliantCount</p>
                <p>Review required for policy violations</p>
            </div>"
        } else {
            "<div class='section success'>
                <h2>Policy Compliance</h2>
                <p>All resources are compliant with assigned policies</p>
            </div>"
        }
    })
    
    $(if ($OptimizationRecommendations.Count -gt 0) {
        "<div class='section warning'>
            <h2>Optimization Recommendations</h2>
            <ul>
                $(foreach ($Rec in $OptimizationRecommendations) { "<li>$Rec</li>" })
            </ul>
        </div>"
    } else {
        "<div class='section success'>
            <h2>Optimization</h2>
            <p>No immediate optimization opportunities identified</p>
        </div>"
    })
    
    <div class="section info">
        <h2>Recommendations</h2>
        <ul>
            <li>Review cost analysis monthly to identify spending trends</li>
            <li>Implement Azure Policy for governance and compliance</li>
            <li>Enable Azure Security Center for security recommendations</li>
            <li>Set up monitoring alerts for critical resources</li>
            <li>Regular review of resource utilization and rightsizing</li>
            <li>Implement backup strategies for critical data</li>
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
        Write-Log "Monitoring report generated: $OutputPath" -Level "SUCCESS"
        
        return $OutputPath
        
    } catch {
        Write-Log "Failed to generate monitoring report: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Main execution
try {
    Write-Log "Starting Azure Resource Monitoring and Cost Management script"
    Write-Log "Parameters: SubscriptionId=$SubscriptionId, ResourceGroupName=$ResourceGroupName, WhatIf=$WhatIf"
    
    # Connect to Azure
    Connect-ToAzure -SubscriptionId $SubscriptionId
    
    # Generate comprehensive monitoring report
    if (!$WhatIf) {
        $ReportPath = New-MonitoringReport
        Write-Log "Azure monitoring analysis completed. Report available at: $ReportPath" -Level "SUCCESS"
    } else {
        Write-Log "WHATIF: Would generate comprehensive Azure monitoring report"
    }
    
    Write-Log "Script completed successfully" -Level "SUCCESS"
    
} catch {
    Write-Log "Script failed: $($_.Exception.Message)" -Level "ERROR"
    throw
} finally {
    # Cleanup
    Write-Log "Script execution finished"
}
