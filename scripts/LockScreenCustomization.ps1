<#
.SYNOPSIS
    Windows Lock Screen Customization Script - Enterprise Desktop Management Example

.DESCRIPTION
    This PowerShell script demonstrates enterprise-level Windows endpoint management by 
    automating lock screen customization through registry manipulation and web-based 
    image deployment. Ideal for Microsoft Intune, Group Policy, or SCCM deployment scenarios.

    Key Features:
    - Automated lock screen image deployment from cloud storage
    - Registry-based Windows personalization using PersonalizationCSP
    - Web client integration for downloading corporate branding assets
    - Logging and transcript capabilities for enterprise auditing
    - Error handling and validation for production environments
    - Demonstrates Windows endpoint configuration management expertise

.PARAMETER LockScreenSource
    URL to the lock screen image source (supports Azure Blob Storage, SharePoint, or any web-accessible image)

.PARAMETER LogPath
    Optional path for logging script execution (creates transcript logs for auditing)

.PARAMETER LockScreenImagePath
    Local path where the lock screen image will be stored (default: C:\Windows\System32\oobe\LockScreen.jpg)

.EXAMPLE
    .\LockScreenCustomization.ps1
    Runs the script with default demo image source

.EXAMPLE
    .\LockScreenCustomization.ps1 -LockScreenSource "https://company.blob.core.windows.net/branding/lockscreen.jpg" -LogPath "C:\Logs"
    Deploys custom lock screen with logging enabled

.EXAMPLE
    .\LockScreenCustomization.ps1 -LockScreenSource "https://sharepoint.company.com/assets/branding.png"
    Uses SharePoint-hosted image for lock screen customization

.NOTES
    Author: Apostolis Tsirogiannis
    Email: apostolis.tsirogiannis@techtakt.com
    LinkedIn: https://www.linkedin.com/in/apostolis-tsirogiannis/
    Upwork: https://www.upwork.com/freelancers/apostolos
    
    Prerequisites:
    - Administrator privileges (required for HKLM registry access)
    - Internet connectivity to download lock screen image
    - Windows 10/11 Enterprise or Education (PersonalizationCSP support)
    
    Use Cases:
    - Corporate branding deployment via Microsoft Intune
    - Automated desktop standardization in enterprise environments
    - Group Policy extension for advanced personalization
    - SCCM application deployment for endpoint configuration
    - Azure AD joined device management and branding

.LINK
    https://docs.microsoft.com/en-us/windows/configuration/windows-10-start-layout-options-and-policies
    https://docs.microsoft.com/en-us/mem/intune/configuration/device-restrictions-windows-10
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$LockScreenSource = "https://democorp.blob.core.windows.net/branding/corporate-lockscreen.jpg?sv=2023-11-03&st=2024-01-01T00:00:00Z&se=2026-12-31T23:59:59Z&sr=b&sp=r&sig=DemoSignatureForShowcaseOnly",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory = $false)]
    [string]$LockScreenImagePath = "C:\Windows\System32\oobe\LockScreen.jpg"
)

# Initialize logging if LogPath is provided
if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
    # Ensure log directory exists
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        Write-Host "Created log directory: $LogPath" -ForegroundColor Green
    }
    
    $LogFile = "$LogPath\LockScreenCustomization_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $LogFile | Out-Null
    Write-Host "Logging enabled. Transcript: $LogFile" -ForegroundColor Green
}

# Set error handling
$ErrorActionPreference = "Stop"

try {
    Write-Host "=== Windows Lock Screen Customization Script ===" -ForegroundColor Cyan
    Write-Host "Computer: $($env:COMPUTERNAME)" -ForegroundColor White
    Write-Host "User: $($env:USERNAME)" -ForegroundColor White
    Write-Host "Date: $(Get-Date)" -ForegroundColor White
    Write-Host "Lock Screen Source: $LockScreenSource" -ForegroundColor White
    Write-Host "Target Path: $LockScreenImagePath" -ForegroundColor White
    
    # Registry configuration for PersonalizationCSP
    $RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
    $LockScreenPath = "LockScreenImagePath"
    $LockScreenStatus = "LockScreenImageStatus"
    $LockScreenUrl = "LockScreenImageUrl"
    $StatusValue = "1"

    # Validate input parameters
    if ([string]::IsNullOrWhiteSpace($LockScreenSource)) {
        throw "LockScreenSource parameter is required and cannot be empty."
    }

    # Validate administrator privileges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script requires administrator privileges to modify HKLM registry keys."
    }

    Write-Host "`nValidating registry path..." -ForegroundColor Yellow
    
    # Create registry path if it doesn't exist
    if (-not (Test-Path $RegKeyPath)) {
        Write-Host "Creating registry path: $RegKeyPath" -ForegroundColor Yellow
        New-Item -Path $RegKeyPath -Force | Out-Null
        Write-Host "Registry path created successfully" -ForegroundColor Green
    } else {
        Write-Host "Registry path already exists: $RegKeyPath" -ForegroundColor Green
    }

    Write-Host "`nDownloading lock screen image..." -ForegroundColor Yellow
    Write-Host "Source: $LockScreenSource" -ForegroundColor White
    Write-Host "Destination: $LockScreenImagePath" -ForegroundColor White
    
    # Create backup of existing lock screen if it exists
    if (Test-Path $LockScreenImagePath) {
        $BackupPath = "$($LockScreenImagePath).backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item -Path $LockScreenImagePath -Destination $BackupPath -Force
        Write-Host "Existing lock screen backed up to: $BackupPath" -ForegroundColor Yellow
    }
    
    # Download the new lock screen image
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($LockScreenSource, $LockScreenImagePath)
    $WebClient.Dispose()
    
    # Verify download
    if (Test-Path $LockScreenImagePath) {
        $ImageInfo = Get-Item $LockScreenImagePath
        Write-Host "Image downloaded successfully" -ForegroundColor Green
        Write-Host "Size: $([math]::Round($ImageInfo.Length / 1KB, 2)) KB" -ForegroundColor White
        Write-Host "Modified: $($ImageInfo.LastWriteTime)" -ForegroundColor White
    } else {
        throw "Failed to download lock screen image to $LockScreenImagePath"
    }

    Write-Host "`nConfiguring registry entries for lock screen..." -ForegroundColor Yellow
    
    # Set registry values for PersonalizationCSP
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenStatus -Value $StatusValue -PropertyType DWORD -Force | Out-Null
    Write-Host "Set $LockScreenStatus = $StatusValue" -ForegroundColor Green
    
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenPath -Value $LockScreenImagePath -PropertyType STRING -Force | Out-Null
    Write-Host "Set $LockScreenPath = $LockScreenImagePath" -ForegroundColor Green
    
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenUrl -Value $LockScreenImagePath -PropertyType STRING -Force | Out-Null
    Write-Host "Set $LockScreenUrl = $LockScreenImagePath" -ForegroundColor Green

    Write-Host "`n=== Lock Screen Customization Completed Successfully ===" -ForegroundColor Green
    Write-Host "The new lock screen will be applied after the next system lock or reboot." -ForegroundColor Cyan
    
    # Display current registry configuration
    Write-Host "`nCurrent PersonalizationCSP Configuration:" -ForegroundColor Cyan
    Get-ItemProperty -Path $RegKeyPath | Select-Object LockScreenImageStatus, LockScreenImagePath, LockScreenImageUrl | Format-List

} catch {
    Write-Error "Lock screen customization failed: $($_.Exception.Message)"
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    
    # Attempt to restore backup if it exists and download failed
    $BackupFiles = Get-ChildItem -Path (Split-Path $LockScreenImagePath) -Filter "LockScreen.jpg.backup.*" -ErrorAction SilentlyContinue
    if ($BackupFiles) {
        $LatestBackup = $BackupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-Host "Attempting to restore from backup: $($LatestBackup.FullName)" -ForegroundColor Yellow
        try {
            Copy-Item -Path $LatestBackup.FullName -Destination $LockScreenImagePath -Force
            Write-Host "Restored previous lock screen from backup" -ForegroundColor Green
        } catch {
            Write-Warning "Could not restore backup: $($_.Exception.Message)"
        }
    }
    
    exit 1
} finally {
    # Stop logging transcript
    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        try {
            Stop-Transcript
            Write-Host "Transcript saved to: $LogFile" -ForegroundColor Yellow
        } catch {
            Write-Warning "Could not stop transcript: $($_.Exception.Message)"
        }
    }
}
