# Reboot Detection and Remediation Solution

## Overview
This solution provides automated device uptime monitoring and remediation for enterprise environments. It consists of detection and remediation scripts designed to integrate with Microsoft Intune Proactive Remediations, SCCM Compliance Settings, or other endpoint management platforms.

## Components

### DetectionScript.ps1
- **Purpose**: Monitors device uptime and determines compliance status
- **Function**: Calculates system uptime and compares against configurable thresholds
- **Integration**: Works with endpoint management solutions for automated remediation triggering
- **Exit Codes**: 
  - `0`: Compliant (within threshold)
  - `1`: Non-compliant (reboot required)
  - `2`: Script error

### RemediationScript.ps1
- **Purpose**: Provides user-friendly reboot notifications and scheduling capabilities
- **Function**: Shows modern toast notifications with grace periods and frequency limiting
- **Features**: 
  - Enterprise-grade Windows 10/11 toast notifications
  - Configurable notification frequency and grace periods
  - Maintenance window scheduling support
  - Fallback notification methods for compatibility
  - Comprehensive tracking and compliance reporting
- **Integration**: Triggered automatically when detection script reports non-compliance

## Enterprise Use Cases

### Microsoft Intune Proactive Remediations
- Deploy as detection/remediation script pair
- Automated scheduling and reporting through Intune console
- Integration with device compliance policies

### SCCM Configuration Manager
- Deploy as Configuration Baseline with automatic remediation
- Integration with maintenance windows and deployment schedules
- Centralized reporting and compliance monitoring

### Azure Arc for Servers
- Monitor hybrid and multi-cloud server environments
- Centralized governance and compliance reporting
- Integration with Azure Policy and governance frameworks

## Configuration Options

### Threshold Settings
- **Default**: 7 days (recommended for workstations)
- **Servers**: 30+ days (with maintenance window coordination)
- **Critical Systems**: Custom thresholds based on business requirements

### Logging and Monitoring
- Windows Event Log integration for enterprise monitoring
- Custom log file export for SIEM integration
- JSON metrics export for monitoring system integration

## Usage Examples

### Basic Detection and Remediation
```powershell
# Detection (run first)
.\DetectionScript.ps1 -ThresholdDays 7 -Verbose

# Remediation (triggered automatically if detection returns exit code 1)
.\RemediationScript.ps1 -ThresholdDays 7
```

### Advanced Enterprise Configuration
```powershell
# Detection with custom logging and metrics export
.\DetectionScript.ps1 -ThresholdDays 14 -LogPath "C:\Monitoring\" -ExportMetrics

# Remediation with maintenance window and custom notifications
.\RemediationScript.ps1 -ThresholdDays 14 -EnableScheduledReboot -MaintenanceWindowStart "20:00" -MaintenanceWindowEnd "06:00" -GracePeriodHours 8 -MaxNotifications 2
```

### Microsoft Intune Deployment
```powershell
# Detection Script Configuration
# - Run as System account
# - Schedule: Every 4 hours during business hours
# - Timeout: 30 minutes

# Remediation Script Configuration  
# - Run in user context for notifications
# - Triggered only when detection fails
# - Use default notification settings for user-friendly experience
```

### Deployment Considerations
- **Permissions**: Requires local system access for process information
- **Scheduling**: Recommend hourly detection during business hours
- **Exceptions**: Consider maintenance windows and critical system exclusions
- **Notifications**: Integrate with help desk and change management systems

## Security and Compliance Benefits

### Patch Management Support
- Ensures systems restart to apply security updates
- Supports compliance with corporate security policies
- Integrates with vulnerability management workflows

### System Reliability
- Prevents memory leaks and resource exhaustion
- Improves overall system performance and stability
- Reduces support tickets related to system performance

### Compliance Reporting
- Automated documentation of system restart compliance
- Integration with audit and governance frameworks
- Historical tracking of device maintenance compliance

## Author Information
**Apostolis Tsirogiannis**  
Senior System Engineer | Azure & Microsoft 365 Specialist  
📧 apostolis.tsirogiannis@techtakt.com  
💼 [LinkedIn](https://www.linkedin.com/in/apostolis-tsirogiannis/)  
🔗 [Upwork](https://www.upwork.com/freelancers/apostolos)

---
*This solution demonstrates enterprise-level endpoint management automation and integration capabilities for modern IT infrastructure.*
