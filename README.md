# Tolis Showcase Project (Apostolos Tsirogiannis)

[![Terraform](https://img.shields.io/badge/Terraform-1.0+-purple.svg)](https://terraform.io)
[![Azure](https://img.shields.io/badge/Azure-Cloud-blue.svg)](https://azure.microsoft.com)
[![Microsoft 365](https://img.shields.io/badge/Microsoft_365-Admin-orange.svg)](https://www.microsoft.com/microsoft-365)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)

> **A comprehensive showcase of enterprise-level expertise in Terraform Infrastructure as Code, Microsoft 365 administration, and Azure cloud services.**

This repository demonstrates real-world, production-ready examples and best practices for modern enterprise infrastructure management, automation, and cloud governance.

## 🎯 Project Overview

This showcase project highlights advanced system engineering capabilities across three core technology areas:

### 🏗️ **Infrastructure as Code (Terraform)**
- **Enterprise-grade Azure infrastructure** with modular design
- **Multi-environment support** (dev, staging, production)
- **Security-first approach** with Key Vault integration
- **Automated deployment** with comprehensive validation
- **Cost optimization** and resource governance

### ☁️ **Microsoft 365 Administration**
- **Automated user provisioning** and lifecycle management
- **Security compliance monitoring** and reporting
- **Conditional Access policy management**
- **Risk-based authentication analysis**
- **Audit log analysis** and threat detection

### 🔧 **Azure Cloud Services**
- **Resource monitoring** and cost management
- **Security Center integration** and compliance checking
- **Policy enforcement** and governance automation
- **Performance optimization** recommendations
- **Automated reporting** and alerting

## 📁 Project Structure

```
📦 Tolis Showcase
├── 🗂️ terraform/                      # Infrastructure as Code
│   ├── 📄 main.tf                     # Main Terraform configuration
│   ├── 📄 variables.tf                # Input variables
│   ├── 📄 outputs.tf                  # Output values
│   ├── 🗂️ modules/                    # Reusable Terraform modules
│   │   ├── 🗂️ networking/             # Virtual networks, subnets, NSGs
│   │   ├── 🗂️ security/               # Key Vault, security configurations
│   │   ├── 🗂️ compute/                # Virtual machines, load balancers
│   │   └── 🗂️ storage/                # Storage accounts, databases
│   └── 🗂️ environments/               # Environment-specific configurations
│       └── 🗂️ dev/                    # Development environment settings
├── 🗂️ microsoft365/                   # M365 Administration & Automation
│   └── 🗂️ powershell/                 # PowerShell automation scripts
│       ├── 📄 UserManagement.ps1      # User provisioning & lifecycle
│       └── 📄 SecurityCompliance.ps1  # Security monitoring & compliance
├── 🗂️ azure/                          # Azure Cloud Services
│   └── 🗂️ powershell/                 # Azure management scripts
│       └── 📄 ResourceMonitoring.ps1  # Resource governance & monitoring
├── 🗂️ scripts/                        # Deployment & automation scripts
│   └── 📄 Deploy-Infrastructure.ps1   # Terraform deployment automation
└── 🗂️ docs/                           # Documentation
    └── 📄 README.md                   # You are here!
```

## 🚀 Quick Start

### Prerequisites

Before you begin, ensure you have the following tools installed:

- **Terraform** (v1.0+) - [Download](https://terraform.io/downloads.html)
- **Azure CLI** (v2.0+) - [Install Guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **PowerShell** (v7.0+) - [Install Guide](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell)
- **Git** - [Download](https://git-scm.com/downloads)

### 1. Clone the Repository

```bash
git clone https://github.com/ZanshinShadow/tolis-showcase.git
cd tolis-showcase
```

### 2. Azure Authentication

```bash
# Login to Azure
az login

# Set your subscription
az account set --subscription "your-subscription-id"
```

### 3. Deploy Infrastructure

```powershell
# Navigate to the project root
cd tolis-showcase

# Deploy to development environment
.\scripts\Deploy-Infrastructure.ps1 -Environment dev -Plan
.\scripts\Deploy-Infrastructure.ps1 -Environment dev -Apply
```

### 4. Verify Deployment

```powershell
# Check deployed resources
az resource list --resource-group rg-tolis-showcase-dev-eus --output table

# Test the deployed web application
# The load balancer public IP will be shown in the Terraform outputs
```

## 🛠️ Key Features & Capabilities

### 🏗️ Terraform Infrastructure

#### **Modular Architecture**
- **Networking Module**: VNet, subnets, NSGs, route tables
- **Security Module**: Key Vault, certificates, SSH keys, Log Analytics
- **Compute Module**: Load balancer, VMs, availability sets
- **Storage Module**: Storage accounts, SQL Database, backup vault

#### **Enterprise Patterns**
- **Environment separation** with tfvars files
- **State management** with Azure Storage backend
- **Resource tagging** for cost allocation and governance
- **Naming conventions** following Azure best practices
- **Security hardening** with least privilege access

#### **Automation Features**
- **Automated deployments** with validation checks
- **Plan verification** before apply operations
- **Multi-environment support** (dev/staging/prod)
- **Rollback capabilities** and state management

### ☁️ Microsoft 365 Administration

#### **User Management Automation**
```powershell
# Bulk user provisioning from CSV
Import-UsersFromCSV -CSVPath "users.csv"

# Create standardized users with governance
New-StandardUser -FirstName "John" -LastName "Doe" -Department "IT" -JobTitle "Engineer"

# Generate compliance reports
Get-UserComplianceReport
```

#### **Security & Compliance Monitoring**
```powershell
# Analyze security incidents
Get-SecurityIncidents -DaysBack 30

# Monitor risky sign-ins
Get-RiskySignIns -DaysBack 7

# Generate comprehensive security report
New-SecurityReport -OutputPath "SecurityReport.html"
```

### 🔧 Azure Resource Management

#### **Resource Governance**
```powershell
# Complete resource inventory
Get-ResourceInventory -ResourceGroupName "rg-tolis-showcase-dev"

# Cost analysis and optimization
Get-CostAnalysis -DaysBack 30

# Policy compliance checking
Get-PolicyCompliance
```

#### **Monitoring & Optimization**
```powershell
# Security recommendations
Get-SecurityRecommendations

# Resource optimization suggestions
Get-OptimizationRecommendations

# Automated monitoring reports
New-MonitoringReport
```

## 📊 Architecture Diagrams

### **High-Level Architecture**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Microsoft 365 │    │      Azure      │    │   Terraform     │
│                 │    │                 │    │                 │
│  • User Mgmt    │◄───┤  • Infrastructure │◄───┤  • IaC Modules  │
│  • Security     │    │  • Monitoring   │    │  • Environments │
│  • Compliance   │    │  • Governance   │    │  • Automation   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### **Azure Infrastructure Layout**
```
📡 Internet
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Azure Subscription                       │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Resource Group                         │   │
│  │                                                         │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │   │
│  │  │  VNet   │  │Key Vault│  │ Storage │  │   SQL   │   │   │
│  │  │         │  │         │  │Account  │  │Database │   │   │
│  │  │ ┌─────┐ │  │         │  │         │  │         │   │   │
│  │  │ │ VM1 │ │  │         │  │         │  │         │   │   │
│  │  │ └─────┘ │  │         │  │         │  │         │   │   │
│  │  │ ┌─────┐ │  │         │  │         │  │         │   │   │
│  │  │ │ VM2 │ │  │         │  │         │  │         │   │   │
│  │  │ └─────┘ │  │         │  │         │  │         │   │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 🔒 Security Best Practices

This project implements enterprise security standards:

### **Infrastructure Security**
- ✅ **Network segmentation** with dedicated subnets
- ✅ **Key Vault integration** for secrets management
- ✅ **NSG rules** for traffic control
- ✅ **SSH key authentication** (no passwords)
- ✅ **Resource encryption** at rest and in transit

### **Identity & Access**
- ✅ **Azure RBAC** with least privilege principle
- ✅ **Conditional Access** policy enforcement
- ✅ **Multi-factor authentication** requirements
- ✅ **Privileged access management**
- ✅ **Regular access reviews** and auditing

### **Monitoring & Compliance**
- ✅ **Security Center** integration
- ✅ **Log Analytics** centralized logging
- ✅ **Policy compliance** monitoring
- ✅ **Threat detection** and response
- ✅ **Automated security reporting**

## 💰 Cost Optimization

### **Resource Efficiency**
- **Right-sizing recommendations** based on utilization
- **Automated cleanup** of unused resources
- **Storage optimization** with lifecycle policies
- **Reserved capacity** planning and recommendations

### **Governance Controls**
- **Budget alerts** and spending limits
- **Resource tagging** for cost allocation
- **Policy enforcement** for resource types
- **Regular cost reviews** and optimization reports

## 🔄 DevOps & Automation

### **CI/CD Integration Ready**
```yaml
# Example Azure DevOps pipeline integration
stages:
- stage: Plan
  jobs:
  - job: TerraformPlan
    steps:
    - script: terraform plan -var-file=environments/$(environment)/terraform.tfvars

- stage: Deploy
  jobs:
  - job: TerraformApply
    steps:
    - script: terraform apply -auto-approve
```

### **GitOps Workflow**
1. **Infrastructure changes** via pull requests
2. **Automated validation** and security scanning
3. **Peer review** and approval process
4. **Automated deployment** to environments
5. **Monitoring** and rollback capabilities

## 🧪 Testing & Validation

### **Infrastructure Testing**
```bash
# Terraform validation
terraform validate

# Security scanning
checkov -f main.tf

# Cost estimation
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan | infracost breakdown --path=-
```

### **Script Testing**
```powershell
# PowerShell script analysis
Invoke-ScriptAnalyzer -Path .\scripts\ -Recurse

# Dry-run mode for all scripts
.\Deploy-Infrastructure.ps1 -Environment dev -Plan -WhatIf
```

## 📈 Monitoring & Metrics

### **Key Performance Indicators**
- **Infrastructure deployment time**: < 15 minutes
- **Security compliance score**: > 95%
- **Cost optimization savings**: 20-30%
- **Automated task coverage**: > 80%
- **Mean time to resolution**: < 2 hours

### **Dashboards & Reports**
- **Azure Cost Management** dashboards
- **Security compliance** scorecards
- **Resource utilization** trends
- **Automation success** metrics
- **Custom PowerBI** integration ready

## 🤝 Contributing

The **tolis-showcase** project demonstrates professional expertise, but contributions and suggestions are welcome:

1. **Fork** the repository
2. **Create** a feature branch
3. **Implement** your changes
4. **Test** thoroughly
5. **Submit** a pull request

## 📚 Additional Resources

### **Learning Paths**
- [Azure Architecture Center](https://docs.microsoft.com/en-us/azure/architecture/)
- [Terraform Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- [Microsoft 365 Admin Center](https://docs.microsoft.com/en-us/microsoft-365/admin/)

### **Certification Paths**
- **Microsoft Certified: Azure Administrator Associate**
- **Microsoft 365 Certified: Endpoint Administrator Associate**
- **HashiCorp logo HashiCorp Certified: Terraform Associate (003)**
- **Certified DevSecOps Professional (CDP)**
- **Windows PowerShell Scripting and Toolmaking**

## 📞 Contact

**Professional LinkedIn**: https://www.linkedin.com/in/atsirogiannis/

**Expertise Areas**:
- ☁️ Azure Cloud Architecture & Implementation
- 🏗️ Infrastructure as Code (Terraform, ARM, Bicep)
- 🔧 Microsoft 365 Administration & Security
- 🔒 Enterprise Security & Compliance
- 🤖 PowerShell Automation & Scripting
- 📊 Cloud Governance & Cost Optimization

---

### 🏆 **This project demonstrates enterprise-level system engineering expertise with real-world, production-ready solutions.**

**Key Differentiators:**
- ✅ **Production-ready** code with enterprise patterns
- ✅ **Security-first** approach with compliance focus
- ✅ **Comprehensive automation** reducing manual effort
- ✅ **Cost-optimized** solutions with governance controls
- ✅ **Scalable architecture** supporting growth
- ✅ **Monitoring & observability** built-in from day one

*Built with ❤️ by Tolis. Passionate about cloud automation and enterprise architecture.*
