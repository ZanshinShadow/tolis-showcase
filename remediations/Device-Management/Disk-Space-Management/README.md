# Disk Space Management Detection & Remediation Solution

## Overview
This solution provides automated disk space monitoring and management for enterprise environments. It consists of detection and remediation scripts designed to integrate with Microsoft Intune Proactive Remediations, SCCM Compliance Settings, or other endpoint management platforms to ensure optimal system storage health.

## Components

### DetectionScript.ps1
- **Purpose**: Monitors disk space across all system drives and determines compliance status
- **Function**: Analyzes available disk space against configurable thresholds with intelligent filtering
- **Features**:
  - Comprehensive multi-drive analysis with sophisticated filtering options
  - Configurable thresholds and minimum drive size requirements
  - Automatic exclusion of network and removable drives (configurable)
  - Detailed metrics export for monitoring and capacity planning
  - Windows Event Log integration for enterprise monitoring systems
- **Exit Codes**: 
  - `0`: Compliant (all drives above threshold)
  - `1`: Non-compliant (cleanup required)
  - `2`: Script error

### RemediationScript.ps1 *(Coming Next)*
- **Purpose**: Provides automated disk cleanup and space optimization
- **Function**: Performs intelligent cleanup operations to free disk space
- **Integration**: Triggered automatically when detection script reports non-compliance

## Enterprise Use Cases

### Microsoft Intune Proactive Remediations
- Deploy as detection/remediation script pair for automated storage management
- Real-time storage monitoring with automated cleanup capabilities
- Integration with device compliance policies and conditional access

### SCCM Configuration Manager
- Deploy as Configuration Baseline with automatic remediation actions
- Integration with maintenance windows and deployment schedules
- Centralized reporting and storage compliance monitoring

### Azure Arc for Servers
- Monitor hybrid and multi-cloud server storage environments
- Centralized governance and storage compliance reporting
- Integration with Azure Policy and governance frameworks

### Capacity Planning & Monitoring
- Export detailed storage metrics for SIEM and monitoring dashboard integration
- Historical storage trend analysis for capacity planning
- Proactive storage optimization and cost management

## Configuration Options

### Threshold Settings
- **Default**: 10% free space (recommended for most systems)
- **Workstations**: 15-20% for systems with frequent file operations
- **Servers**: 5-10% with careful monitoring for database/file servers
- **Critical Systems**: 20%+ with enhanced monitoring and alerting

### Drive Filtering Options
- **Network Drives**: Excluded by default (configurable)
- **Removable Drives**: Excluded by default (USB, CD/DVD)
- **Minimum Drive Size**: 1GB default (excludes small system partitions)
- **Custom Filtering**: Support for specific drive letter exclusions

### Logging and Monitoring
- **Windows Event Log**: Automatic integration for enterprise monitoring systems
- **Custom Log Files**: Detailed operation logs for audit and troubleshooting
- **JSON Metrics Export**: Structured data for SIEM and dashboard integration
- **Real-time Alerts**: Integration with monitoring and alerting platforms

## Usage Examples

### Basic Detection
```powershell
# Standard enterprise detection with 10% threshold
.\DetectionScript.ps1 -Verbose

# Custom threshold for high-availability systems
.\DetectionScript.ps1 -ThresholdPercent 20 -Verbose
```

### Advanced Configuration
```powershell
# Include removable drives with custom logging
.\DetectionScript.ps1 -ThresholdPercent 15 -ExcludeRemovableDrives:$false -LogPath "C:\Monitoring\" -ExportMetrics

# Large drive focus with detailed metrics
.\DetectionScript.ps1 -ThresholdPercent 5 -MinimumDriveSize 50 -ExportMetrics
```

### Microsoft Intune Deployment
```powershell
# Detection Script Configuration
# - Run as System account for comprehensive drive access
# - Schedule: Every 6 hours during business hours
# - Timeout: 10 minutes
# - Use default settings for most enterprise environments

# Remediation Script Configuration (Coming Soon)
# - Run as System account for cleanup operations
# - Triggered only when detection fails
# - Focus on safe, non-destructive cleanup operations
```

## Storage Compliance Benefits

### System Reliability
- Prevents system failures due to insufficient disk space
- Maintains optimal system performance through proactive space management
- Reduces support tickets related to storage issues

### Security and Compliance
- Ensures adequate space for security updates and patches
- Supports compliance with data retention and storage policies
- Maintains audit trails and logging capabilities

### Cost Optimization
- Proactive identification of storage inefficiencies
- Automated cleanup reduces manual intervention requirements
- Capacity planning data supports infrastructure optimization decisions

### Monitoring Integration
- Real-time storage health visibility across enterprise environments
- Integration with existing monitoring and alerting infrastructure
- Detailed metrics for capacity planning and trend analysis

## Deployment Considerations

### Permissions and Access
- **System Account**: Recommended for comprehensive drive access
- **User Context**: Limited to user-accessible drives only
- **Network Drives**: May require additional authentication considerations

### Scheduling and Frequency
- **High-Usage Systems**: Every 2-4 hours during business hours
- **Standard Workstations**: 2-3 times daily
- **Servers**: Hourly monitoring with immediate remediation
- **Critical Systems**: Continuous monitoring with real-time alerting

### Threshold Recommendations by System Type
- **Domain Controllers**: 20% minimum for AD database operations
- **File Servers**: 10-15% with aggressive cleanup policies
- **Database Servers**: 15-25% depending on transaction log requirements
- **Standard Workstations**: 10-15% for general productivity
- **Developer Workstations**: 20%+ for build operations and tools

## Author Information
**Apostolis Tsirogiannis**  
Senior System Engineer | Azure & Microsoft 365 Specialist  
📧 apostolis.tsirogiannis@techtakt.com  
🔗 [LinkedIn](https://www.linkedin.com/in/apostolis-tsirogiannis/)  
💼 [Upwork](https://www.upwork.com/freelancers/apostolos)

---
*This solution demonstrates enterprise-level endpoint management and storage optimization expertise for modern IT environments.*
