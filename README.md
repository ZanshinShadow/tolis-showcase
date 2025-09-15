# Tolis Showcase Project (Apostolos Tsirogiannis)

[![Terraform](https://img.shields.io/badge/Terraform-1.0+-purple.svg)](https://terraform.io)
[![Azure](https://img.shields.io/badge/Azure-Cloud-blue.svg)](https://azure.microsoft.com)
[![Microsoft 365](https://img.shields.io/badge/Microsoft_365-Admin-orange.svg)](https://www.microsoft.com/microsoft-365)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Security%20First-red.svg)](https://github.com/ZanshinShadow/tolis-showcase)
[![Endpoint Management](https://img.shields.io/badge/Endpoint-Management-brightgreen.svg)](https://github.com/ZanshinShadow/tolis-showcase/tree/main/remediations)
[![Security](https://img.shields.io/badge/Security-Automated-green.svg)](https://github.com/ZanshinShadow/tolis-showcase/security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **A comprehensive showcase of enterprise-level expertise in Terraform Infrastructure as Code, Microsoft 365 administration, Azure cloud services, endpoint management automation, and DevSecOps security practices.**

⚠️ **IMPORTANT**: This is a **professional showcase project** for demonstration purposes. Please read the [DISCLAIMER](DISCLAIMER.md) and [LICENSE](LICENSE) before use.

This repository demonstrates real-world, production-ready examples and best practices for modern enterprise infrastructure management, security automation, endpoint compliance, and cloud governance across hybrid environments.

## 🎯 Project Overview

This showcase project highlights advanced system engineering capabilities across five core technology areas:

### 🏗️ **Infrastructure as Code (Terraform)**
- **Enterprise-grade Azure infrastructure** with modular design
- **Multi-environment support** (dev, staging, production)
- **Security-first approach** with Key Vault integration
- **Automated deployment** with comprehensive validation
- **Cost optimization** and resource governance

### ☁️ **Microsoft 365 Administration**
- **Advanced user provisioning** and lifecycle management with Microsoft Graph
- **Enterprise security monitoring** with threat detection and incident response
- **Compliance automation** supporting SOC2, ISO27001, NIST, GDPR frameworks
- **Risk-based authentication** analysis and conditional access optimization
- **Executive reporting** with security KPIs and compliance dashboards

### 🔧 **Azure Cloud Services**
- **Resource monitoring** and cost management with advanced analytics
- **Security Center integration** and compliance checking automation
- **Policy enforcement** and governance automation with drift detection
- **Performance optimization** recommendations and automated remediation
- **Threat detection** with automated response and SIEM integration

### 🖥️ **Enterprise Endpoint Management**
- **Proactive Remediations** framework for Windows device compliance
- **Intelligent automation** for reboot management and maintenance windows
- **Advanced disk space management** with multi-category cleanup automation
- **Enterprise deployment** support for Intune, SCCM, and Group Policy
- **Comprehensive monitoring** with progress tracking and event log integration

### 🔒 **DevSecOps & Security Automation**
- **Comprehensive CI/CD pipelines** with security-first approach
- **Multi-layered security scanning** including SAST, DAST, and infrastructure analysis
- **Automated compliance monitoring** with Azure Policy and Security Center
- **Threat detection** and incident response automation
- **Cost governance** and optimization with budget alerts and recommendations

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
│       ├── 🗂️ dev/                    # Development environment settings
│       └── 🗂️ prod/                   # Production environment settings
├── 🗂️ microsoft365/                   # M365 Administration & Automation
│   └── 🗂️ powershell/                 # PowerShell automation scripts
│       ├── 📄 UserManagement.ps1      # Enterprise user provisioning & lifecycle
│       ├── 📄 SecurityCompliance.ps1  # Advanced security monitoring & compliance
│       └── 📄 RestoreGroupMembership.ps1 # Group membership disaster recovery
├── 🗂️ azure/                          # Azure Cloud Services
│   └── 🗂️ powershell/                 # Azure management scripts
│       ├── 📄 ResourceMonitoring.ps1  # Resource governance & monitoring
│       ├── 📄 GroupOwnerSync.ps1      # Azure AD group ownership automation
│       └── 📄 SecurityFailedLoginsRunbook.ps1 # Security threat detection
├── 🗂️ remediations/                   # Enterprise Endpoint Management
│   └── 🗂️ Device-Management/          # Windows endpoint automation
│       ├── 🗂️ Reboot-Detection/       # Intelligent reboot management
│       │   ├── 📄 DetectionScript.ps1 # Uptime monitoring & compliance
│       │   ├── 📄 RemediationScript.ps1 # Automated reboot orchestration
│       │   └── 📄 README.md           # Implementation guide
│       └── 🗂️ Disk-Space-Management/  # Storage optimization automation
│           ├── 📄 DetectionScript.ps1 # Disk space monitoring
│           ├── 📄 RemediationScript.ps1 # Automated cleanup & optimization
│           └── 📄 README.md           # Configuration guide
├── 🗂️ scripts/                        # Deployment & automation scripts
│   ├── 📄 Deploy-Infrastructure.ps1   # Terraform deployment automation
│   └── 📄 LockScreenCustomization.ps1 # Enterprise desktop management
├── 🗂️ .github/workflows/              # DevSecOps CI/CD Pipelines
│   ├── 📄 devsecops-pipeline.yml      # Main security & deployment pipeline
│   ├── 📄 azure-compliance.yml        # Azure compliance monitoring
│   └── 📄 security-scanning.yml       # Code & infrastructure security
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

## 🔒 DevSecOps Integration

This project demonstrates enterprise-level DevSecOps practices with automated security throughout the development lifecycle:

### **Security Automation Pipeline**
- **🔍 Vulnerability Scanning**: Trivy, Checkov, Snyk integration
- **🛡️ Infrastructure Security**: Terraform security validation with tfsec and Terrascan
- **🔐 Secret Detection**: GitLeaks and TruffleHog for credential scanning
- **📋 Compliance Monitoring**: Automated Azure Security Center integration
- **💰 Cost Governance**: Resource cost tracking and budget monitoring
- **🚨 Drift Detection**: Infrastructure drift monitoring and alerting

### **⚠️ Expected Security Findings**
**Note**: This is a **showcase project** designed to demonstrate capabilities. Security findings in automated scans are expected and include:
- Demo configurations optimized for learning rather than production hardening
- Public network access enabled for demonstration purposes
- Simplified authentication for showcase environments
- Standard Azure service configurations without enterprise-specific hardening

**For Production Use**: All security findings should be addressed according to your organization's security requirements.

### **Continuous Security Workflows**
```yaml
# Automated security checks on every commit
- Security vulnerability scanning
- Infrastructure compliance validation
- Secret detection and prevention
- Cost optimization analysis
- Azure Policy compliance monitoring
```

### **Security Features**
- **Zero-trust architecture** with private endpoints
- **Azure Key Vault** integration for secrets management
- **Network security groups** with least privilege access
- **Azure Security Center** continuous monitoring
- **Log Analytics** for security event correlation
- **Automated security recommendations** and remediation

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

#### **Enterprise User Management Automation**
```powershell
# Advanced user provisioning with enterprise configuration
New-StandardUser -FirstName "John" -LastName "Doe" -Department "IT" -JobTitle "Engineer" -Manager "jane.doe@company.com"

# Bulk user operations from CSV with validation
Import-UsersFromCSV -CSVPath "users.csv" -WhatIf

# Comprehensive compliance and governance reporting
Get-UserComplianceReport -IncludeRiskAnalysis -ExportPath "ComplianceReport.xlsx"
```

**Enterprise Features:**
- **🔐 Microsoft Graph Integration**: Advanced API automation with proper scoping
- **👥 Lifecycle Management**: Complete user provisioning, modification, and deprovisioning
- **🛡️ Security Integration**: Risk assessment and conditional access automation
- **📊 Compliance Reporting**: Detailed audit trails and governance analytics
- **⚙️ Automation Ready**: Azure Automation and Managed Identity support

#### **Advanced Security & Compliance Monitoring**
```powershell
# Comprehensive security incident analysis
Get-SecurityIncidents -DaysBack 30 -Severity "High" -IncludeIOCs

# Risk-based authentication monitoring
Get-RiskySignIns -DaysBack 7 -RiskLevel "Medium" -AnalyzePatterns

# Executive security dashboard generation
New-SecurityReport -ReportType "Executive" -IncludeKPIs -OutputFormat "HTML"
```

**Advanced Security Operations:**
- **🚨 Threat Detection**: Advanced analytics with IOC correlation and attack timeline analysis
- **🔍 Identity Protection**: Risk-based authentication assessment and anomaly detection
- **📈 Executive Dashboards**: Security KPIs, threat metrics, and compliance scorecards
- **🛡️ SIEM Integration**: Azure Sentinel connector and security orchestration support
- **⚡ Automated Response**: Incident response workflows and security playbook execution
- **📋 Compliance Frameworks**: SOC2, ISO27001, NIST, GDPR mapping and assessment

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

### 🖥️ Enterprise Endpoint Management

#### **Proactive Remediations Framework**
A comprehensive endpoint management solution demonstrating enterprise-grade automation for Windows device compliance and optimization.

#### **Reboot Management Automation**
```powershell
# Intelligent uptime monitoring with maintenance windows
.\DetectionScript.ps1 -MaxUptimeDays 7 -MaintenanceWindow "02:00-04:00"

# Automated reboot orchestration with user notifications
.\RemediationScript.ps1 -DelayMinutes 30 -ForceReboot $false
```

**Enterprise Features:**
- **📊 Compliance Monitoring**: Real-time uptime tracking with configurable thresholds
- **🔔 User Notifications**: Professional Windows toast notifications with countdown timers
- **⏰ Maintenance Windows**: Intelligent scheduling respecting business hours
- **📈 Progress Tracking**: Comprehensive logging and event log integration
- **🎯 Deployment Flexibility**: Support for Intune, SCCM, Group Policy deployment

#### **Disk Space Management Automation**
```powershell
# Comprehensive disk space monitoring
.\DetectionScript.ps1 -ThresholdGB 10 -CheckAllDrives $true

# Advanced cleanup automation with safety validation
.\RemediationScript.ps1 -CleanupCategories @("TempFiles", "Logs", "Cache") -SafetyMode $true
```

**Advanced Capabilities:**
- **🧹 Multi-Category Cleanup**: 15+ cleanup categories including temp files, logs, downloads, cache
- **⚡ Windows Disk Cleanup Integration**: Native tool integration plus custom cleanup routines
- **🛡️ Safety Validation**: Recent file preservation and intelligent cleanup selection
- **📊 Before/After Analysis**: Detailed space recovery reporting and metrics
- **⏱️ Progress Monitoring**: Real-time cleanup progress with timeout protection
- **🔧 Enterprise Integration**: JSON metrics export, Event Log integration, monitoring support

#### **Deployment Scenarios**
- **Microsoft Intune**: Proactive Remediations for cloud-managed devices
- **System Center Configuration Manager**: Configuration Baselines and compliance rules
- **Group Policy**: Scheduled tasks and startup scripts for domain environments
- **Azure Automation**: Hybrid Worker Groups for cross-cloud management

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

**Upwork Freelance Profile**: https://www.upwork.com/freelancers/apostolos

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
- ✅ **Production-ready** code with enterprise patterns and comprehensive documentation
- ✅ **Security-first** approach with automated threat detection and compliance monitoring
- ✅ **Comprehensive automation** reducing manual effort across infrastructure and endpoints
- ✅ **Cost-optimized** solutions with governance controls and budget management
- ✅ **Scalable architecture** supporting growth with modular design patterns
- ✅ **Monitoring & observability** built-in from day one with advanced analytics
- ✅ **Enterprise endpoint management** with proactive remediation and compliance automation
- ✅ **Advanced PowerShell expertise** with professional documentation and error handling
- ✅ **DevSecOps integration** with comprehensive CI/CD pipelines and security automation
- ✅ **Multi-platform support** for cloud, hybrid, and on-premises environments

## ⚖️ Legal Information

### 📄 License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for full details.

### ⚠️ Disclaimer
**IMPORTANT**: This is a professional showcase project. Please read the comprehensive [DISCLAIMER](DISCLAIMER.md) which includes:

- **Liability limitations** and usage warnings
- **Azure cost considerations** and management advice
- **Security guidelines** and best practices
- **Compliance notices** and professional review requirements

### 🛡️ No Warranty
This software is provided "AS IS" without warranty of any kind. Use at your own risk and responsibility.

---

*© 2025 Apostolos Tsirogiannis. All rights reserved. Licensed under MIT License.*

*Built with ❤️ by Tolis. Passionate about cloud automation and enterprise architecture.*
