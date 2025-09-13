# Terraform Deployment Script for Azure Infrastructure
# This script demonstrates enterprise deployment practices

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("dev", "staging", "prod")]
    [string]$Environment,
    
    [Parameter(Mandatory = $false)]
    [string]$TerraformPath = ".\terraform",
    
    [Parameter(Mandatory = $false)]
    [switch]$Plan,
    
    [Parameter(Mandatory = $false)]
    [switch]$Apply,
    
    [Parameter(Mandatory = $false)]
    [switch]$Destroy,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Set error action preference
$ErrorActionPreference = "Stop"

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
}

# Check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check if Terraform is installed
    try {
        $TerraformVersion = terraform --version
        Write-Log "Terraform found: $($TerraformVersion.Split([Environment]::NewLine)[0])"
    } catch {
        Write-Log "Terraform is not installed or not in PATH" -Level "ERROR"
        throw "Please install Terraform and ensure it's in your PATH"
    }
    
    # Check if Azure CLI is installed
    try {
        $AzVersion = az --version
        Write-Log "Azure CLI found"
    } catch {
        Write-Log "Azure CLI is not installed or not in PATH" -Level "ERROR"
        throw "Please install Azure CLI and ensure it's in your PATH"
    }
    
    # Check if logged into Azure
    try {
        $AzAccount = az account show --output json | ConvertFrom-Json
        Write-Log "Logged into Azure as: $($AzAccount.user.name)"
        Write-Log "Active subscription: $($AzAccount.name) ($($AzAccount.id))"
    } catch {
        Write-Log "Not logged into Azure" -Level "ERROR"
        throw "Please run 'az login' to authenticate with Azure"
    }
    
    # Check if Terraform directory exists
    if (!(Test-Path $TerraformPath)) {
        Write-Log "Terraform directory not found: $TerraformPath" -Level "ERROR"
        throw "Terraform directory does not exist"
    }
    
    Write-Log "All prerequisites met" -Level "SUCCESS"
}

# Initialize Terraform
function Initialize-Terraform {
    param([string]$WorkingDirectory)
    
    Write-Log "Initializing Terraform in: $WorkingDirectory"
    
    Push-Location $WorkingDirectory
    try {
        # Initialize Terraform
        $InitResult = terraform init -input=false
        
        if ($LASTEXITCODE -ne 0) {
            throw "Terraform init failed"
        }
        
        Write-Log "Terraform initialized successfully" -Level "SUCCESS"
        
        # Validate configuration
        Write-Log "Validating Terraform configuration..."
        $ValidateResult = terraform validate
        
        if ($LASTEXITCODE -ne 0) {
            throw "Terraform validation failed"
        }
        
        Write-Log "Terraform configuration is valid" -Level "SUCCESS"
        
    } finally {
        Pop-Location
    }
}

# Create Terraform plan
function New-TerraformPlan {
    param(
        [string]$WorkingDirectory,
        [string]$Environment,
        [switch]$WhatIf
    )
    
    Write-Log "Creating Terraform plan for environment: $Environment"
    
    $VarFile = "environments\$Environment\terraform.tfvars"
    $PlanFile = "terraform-$Environment.tfplan"
    
    if (!(Test-Path (Join-Path $WorkingDirectory $VarFile))) {
        throw "Variable file not found: $VarFile"
    }
    
    Push-Location $WorkingDirectory
    try {
        if ($WhatIf) {
            Write-Log "WHATIF: Would create Terraform plan using var file: $VarFile"
            return
        }
        
        # Create plan
        $PlanArgs = @(
            "plan",
            "-var-file=$VarFile",
            "-out=$PlanFile",
            "-input=false"
        )
        
        Write-Log "Running: terraform $($PlanArgs -join ' ')"
        $PlanResult = & terraform @PlanArgs
        
        if ($LASTEXITCODE -ne 0) {
            throw "Terraform plan failed"
        }
        
        Write-Log "Terraform plan created successfully: $PlanFile" -Level "SUCCESS"
        
        # Show plan summary
        Write-Log "Plan summary:"
        terraform show -no-color $PlanFile | Select-String "Plan:" | ForEach-Object {
            Write-Log "  $($_)" -Level "INFO"
        }
        
    } finally {
        Pop-Location
    }
}

# Apply Terraform plan
function Invoke-TerraformApply {
    param(
        [string]$WorkingDirectory,
        [string]$Environment,
        [switch]$WhatIf
    )
    
    Write-Log "Applying Terraform plan for environment: $Environment"
    
    $PlanFile = "terraform-$Environment.tfplan"
    
    if (!(Test-Path (Join-Path $WorkingDirectory $PlanFile))) {
        throw "Plan file not found: $PlanFile. Run with -Plan first."
    }
    
    Push-Location $WorkingDirectory
    try {
        if ($WhatIf) {
            Write-Log "WHATIF: Would apply Terraform plan: $PlanFile"
            return
        }
        
        # Prompt for confirmation in production
        if ($Environment -eq "prod") {
            $Confirmation = Read-Host "You are about to deploy to PRODUCTION. Type 'yes' to continue"
            if ($Confirmation -ne "yes") {
                Write-Log "Production deployment cancelled by user" -Level "WARNING"
                return
            }
        }
        
        # Apply plan
        Write-Log "Applying plan: $PlanFile"
        $ApplyResult = terraform apply -input=false $PlanFile
        
        if ($LASTEXITCODE -ne 0) {
            throw "Terraform apply failed"
        }
        
        Write-Log "Terraform apply completed successfully" -Level "SUCCESS"
        
        # Show outputs
        Write-Log "Deployment outputs:"
        $Outputs = terraform output -json | ConvertFrom-Json
        foreach ($Output in $Outputs.PSObject.Properties) {
            if ($Output.Value.sensitive -eq $false) {
                Write-Log "  $($Output.Name): $($Output.Value.value)"
            } else {
                Write-Log "  $($Output.Name): [SENSITIVE]"
            }
        }
        
    } finally {
        Pop-Location
    }
}

# Destroy Terraform infrastructure
function Remove-TerraformInfrastructure {
    param(
        [string]$WorkingDirectory,
        [string]$Environment,
        [switch]$WhatIf
    )
    
    Write-Log "Destroying Terraform infrastructure for environment: $Environment" -Level "WARNING"
    
    $VarFile = "environments\$Environment\terraform.tfvars"
    
    Push-Location $WorkingDirectory
    try {
        if ($WhatIf) {
            Write-Log "WHATIF: Would destroy infrastructure for environment: $Environment"
            return
        }
        
        # Multiple confirmations for production
        if ($Environment -eq "prod") {
            Write-Log "WARNING: You are about to DESTROY PRODUCTION infrastructure!" -Level "ERROR"
            $Confirmation1 = Read-Host "Type 'DESTROY' to continue"
            if ($Confirmation1 -ne "DESTROY") {
                Write-Log "Destruction cancelled" -Level "WARNING"
                return
            }
            
            $Confirmation2 = Read-Host "Are you absolutely sure? Type 'yes' to confirm"
            if ($Confirmation2 -ne "yes") {
                Write-Log "Destruction cancelled" -Level "WARNING"
                return
            }
        } else {
            $Confirmation = Read-Host "Type 'yes' to destroy $Environment infrastructure"
            if ($Confirmation -ne "yes") {
                Write-Log "Destruction cancelled by user" -Level "WARNING"
                return
            }
        }
        
        # Destroy infrastructure
        $DestroyArgs = @(
            "destroy",
            "-var-file=$VarFile",
            "-auto-approve",
            "-input=false"
        )
        
        Write-Log "Running: terraform $($DestroyArgs -join ' ')"
        $DestroyResult = & terraform @DestroyArgs
        
        if ($LASTEXITCODE -ne 0) {
            throw "Terraform destroy failed"
        }
        
        Write-Log "Infrastructure destroyed successfully" -Level "SUCCESS"
        
    } finally {
        Pop-Location
    }
}

# Main execution
try {
    Write-Log "Starting Terraform deployment script"
    Write-Log "Environment: $Environment"
    Write-Log "Terraform Path: $TerraformPath"
    Write-Log "Operations: Plan=$Plan, Apply=$Apply, Destroy=$Destroy, WhatIf=$WhatIf"
    
    # Check prerequisites
    Test-Prerequisites
    
    # Initialize Terraform
    Initialize-Terraform -WorkingDirectory $TerraformPath
    
    # Execute requested operations
    if ($Destroy) {
        Remove-TerraformInfrastructure -WorkingDirectory $TerraformPath -Environment $Environment -WhatIf:$WhatIf
    } elseif ($Plan) {
        New-TerraformPlan -WorkingDirectory $TerraformPath -Environment $Environment -WhatIf:$WhatIf
    } elseif ($Apply) {
        Invoke-TerraformApply -WorkingDirectory $TerraformPath -Environment $Environment -WhatIf:$WhatIf
    } else {
        Write-Log "No operation specified. Use -Plan, -Apply, or -Destroy" -Level "WARNING"
        Write-Log "Example usage:"
        Write-Log "  .\Deploy-Infrastructure.ps1 -Environment dev -Plan"
        Write-Log "  .\Deploy-Infrastructure.ps1 -Environment dev -Apply"
        Write-Log "  .\Deploy-Infrastructure.ps1 -Environment dev -Destroy"
    }
    
    Write-Log "Script completed successfully" -Level "SUCCESS"
    
} catch {
    Write-Log "Script failed: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
