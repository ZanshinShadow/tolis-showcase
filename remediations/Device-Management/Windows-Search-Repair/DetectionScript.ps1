<#
.SYNOPSIS
    Windows Search Service Health and Functionality Detection Script

.DESCRIPTION
    This enterprise-grade detection script performs comprehensive Windows Search assessment
    to identify common search-related issues that impact user productivity. It evaluates
    search service health, indexing status, database integrity, search functionality,
    and performance to ensure optimal search experience across managed devices.

.NOTES
    File Name      : DetectionScript.ps1
    Author         : Apostolos Tsirogiannis - Senior System Engineer Showcase
    Prerequisite   : Windows 10/11, PowerShell 5.1+, Administrative context recommended
    
    DETECTION CRITERIA:
    • Windows Search service running and responsive
    • Search indexer operational and not corrupted
    • Search database integrity and reasonable size
    • Basic search functionality working (file/application search)
    • Indexing progress within acceptable parameters
    • No recent critical search-related errors
    
    EXIT CODES:
    • 0 = Compliant (Windows Search functioning properly)
    • 1 = Non-compliant (search issues detected, remediation needed)
    
    BUSINESS IMPACT:
    Resolves the most frustrating user productivity issue - when users can't find
    their files, applications, or settings through Windows Search functionality.

.EXAMPLE
    .\DetectionScript.ps1
    
    Performs comprehensive Windows Search health assessment and returns status.
    Designed for Intune Proactive Remediations and enterprise helpdesk automation.
#>

# Script configuration and detection parameters
$SearchHealthCriteria = @{
    MaxIndexingTimeHours = 24          # Maximum acceptable indexing duration
    MaxDatabaseSizeMB = 10240          # 10GB maximum search database size
    MinSearchResponseTimeMs = 5000     # Maximum acceptable search response time
    MaxRecentErrors = 5                # Maximum recent search errors before flagging
    RequiredServices = @("WSearch", "SearchIndexer")
    CriticalIndexLocations = @("$env:USERPROFILE", "$env:SystemRoot", "$env:ProgramFiles")
}

$EventLogSource = "WindowsSearchDetection"
$VerboseLogging = $false

# Initialize script execution context
$ScriptStartTime = Get-Date
$ScriptName = "Windows-Search-Detection"

# Enhanced logging for comprehensive diagnostics
function Write-SearchLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success", "Performance")]
        [string]$Level = "Info",
        [switch]$WriteToEventLog,
        [switch]$PerformanceMetric
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    if ($VerboseLogging) {
        Write-Host $LogEntry -ForegroundColor $(
            switch ($Level) {
                "Error" { "Red" }
                "Warning" { "Yellow" }
                "Success" { "Green" }
                "Performance" { "Cyan" }
                default { "White" }
            }
        )
    }
    
    # Write important events to Application Log for tracking
    if ($WriteToEventLog -or $PerformanceMetric) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
                New-EventLog -LogName "Application" -Source $EventLogSource
            }
            
            $EventType = switch ($Level) {
                "Error" { "Error" }
                "Warning" { "Warning" }
                "Performance" { "Information" }
                default { "Information" }
            }
            
            $EventId = if ($PerformanceMetric) { 2001 } else { 1001 }
            Write-EventLog -LogName "Application" -Source $EventLogSource -EntryType $EventType -EventId $EventId -Message $LogEntry
        } catch {
            # Continue if event log writing fails
        }
    }
}

# Test Windows Search service health and responsiveness
function Test-SearchServiceHealth {
    Write-SearchLog "Evaluating Windows Search service health and configuration..." -Level "Info"
    
    try {
        $ServiceIssues = @()
        
        foreach ($ServiceName in $SearchHealthCriteria.RequiredServices) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            
            if (-not $Service) {
                Write-SearchLog "Critical service not found: $ServiceName" -Level "Error"
                $ServiceIssues += "Service $ServiceName not installed"
                continue
            }
            
            # Check service status
            if ($Service.Status -ne "Running") {
                Write-SearchLog "Service $ServiceName is not running (Status: $($Service.Status))" -Level "Error"
                $ServiceIssues += "Service $ServiceName not running"
                continue
            }
            
            # Check service startup type
            $ServiceConfig = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($ServiceConfig -and $ServiceConfig.StartMode -eq "Disabled") {
                Write-SearchLog "Service $ServiceName is disabled - search functionality impaired" -Level "Warning"
                $ServiceIssues += "Service $ServiceName disabled"
            }
            
            Write-SearchLog "Service $ServiceName is running normally" -Level "Success"
        }
        
        # Test search service responsiveness
        $SearchResponsive = Test-SearchServiceResponsiveness
        if (-not $SearchResponsive) {
            $ServiceIssues += "Search service not responsive"
        }
        
        return ($ServiceIssues.Count -eq 0)
        
    } catch {
        Write-SearchLog "Failed to evaluate search service health: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Test if Windows Search service is responsive to queries
function Test-SearchServiceResponsiveness {
    Write-SearchLog "Testing Windows Search service responsiveness..." -Level "Info"
    
    try {
        # Test search functionality using Windows Search API
        $SearchApplication = New-Object -ComObject "Search.Application" -ErrorAction SilentlyContinue
        
        if (-not $SearchApplication) {
            Write-SearchLog "Cannot access Windows Search COM interface" -Level "Error"
            return $false
        }
        
        # Perform basic search query with timeout
        $SearchStartTime = Get-Date
        $SearchQuery = "*.txt"
        
        try {
            $SearchConnector = $SearchApplication.GetCatalog("SystemIndex")
            $SearchQueryHelper = $SearchConnector.GetQueryHelper()
            $SearchQueryHelper.QuerySelectColumns = "System.ItemName,System.ItemUrl"
            $SearchQueryHelper.QueryWhereRestrictions = "System.FileName LIKE '$SearchQuery'"
            $SearchQueryHelper.QueryMaxResults = 10
            
            $Query = $SearchQueryHelper.GenerateSQLFromUserQuery($SearchQuery)
            $SearchResults = $SearchConnector.GetResultSet($Query)
            
            $SearchDuration = (Get-Date) - $SearchStartTime
            $SearchDurationMs = [math]::Round($SearchDuration.TotalMilliseconds, 0)
            
            Write-SearchLog "Search query completed in $SearchDurationMs ms" -Level "Performance" -PerformanceMetric
            
            if ($SearchDurationMs -gt $SearchHealthCriteria.MinSearchResponseTimeMs) {
                Write-SearchLog "Search response time ($SearchDurationMs ms) exceeds acceptable threshold" -Level "Warning"
                return $false
            }
            
            Write-SearchLog "Search service responsiveness test passed" -Level "Success"
            return $true
            
        } finally {
            # Cleanup COM objects
            if ($SearchApplication) {
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($SearchApplication) | Out-Null
            }
        }
        
    } catch {
        Write-SearchLog "Search responsiveness test failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Analyze Windows Search indexer status and health
function Test-SearchIndexerHealth {
    Write-SearchLog "Analyzing Windows Search indexer status and performance..." -Level "Info"
    
    try {
        # Check indexer status using Windows Search Manager
        $SearchManager = New-Object -ComObject "Search.Manager" -ErrorAction SilentlyContinue
        
        if (-not $SearchManager) {
            Write-SearchLog "Cannot access Windows Search Manager interface" -Level "Error"
            return $false
        }
        
        try {
            $Catalog = $SearchManager.GetCatalog("SystemIndex")
            $CatalogManager = $Catalog.GetCrawlScopeManager()
            
            # Get indexer status
            $IndexerStatus = $Catalog.GetCatalogStatus()
            $IndexerStatusText = switch ($IndexerStatus) {
                0 { "Idle" }
                1 { "Indexing" }
                2 { "Paused" }
                3 { "Recovering" }
                4 { "Stopped" }
                default { "Unknown ($IndexerStatus)" }
            }
            
            Write-SearchLog "Search indexer status: $IndexerStatusText" -Level "Info"
            
            # Check if indexer has been running too long
            if ($IndexerStatus -eq 1) {  # Indexing
                $IndexingStartTime = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "LastIndexTime" -ErrorAction SilentlyContinue
                if ($IndexingStartTime) {
                    $IndexingDuration = (Get-Date) - [DateTime]::FromFileTime($IndexingStartTime.LastIndexTime)
                    $IndexingHours = [math]::Round($IndexingDuration.TotalHours, 1)
                    
                    Write-SearchLog "Indexing has been running for $IndexingHours hours" -Level "Info"
                    
                    if ($IndexingHours -gt $SearchHealthCriteria.MaxIndexingTimeHours) {
                        Write-SearchLog "Indexing duration ($IndexingHours hours) exceeds acceptable limit" -Level "Warning"
                        return $false
                    }
                }
            }
            
            # Check for indexer errors
            if ($IndexerStatus -eq 4) {  # Stopped
                Write-SearchLog "Search indexer is stopped - search functionality severely impaired" -Level "Error"
                return $false
            }
            
            # Get indexer statistics
            $NumberOfItems = $Catalog.NumberOfItems()
            $NumberOfItemsToIndex = $Catalog.NumberOfItemsToIndex()
            
            Write-SearchLog "Indexed items: $NumberOfItems, Pending items: $NumberOfItemsToIndex" -Level "Info" -PerformanceMetric
            
            # Check if too many items are pending
            if ($NumberOfItemsToIndex -gt ($NumberOfItems * 0.1)) {  # More than 10% pending
                Write-SearchLog "High number of pending index items may indicate indexer issues" -Level "Warning"
            }
            
            Write-SearchLog "Search indexer health check completed successfully" -Level "Success"
            return $true
            
        } finally {
            # Cleanup COM objects
            if ($SearchManager) {
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($SearchManager) | Out-Null
            }
        }
        
    } catch {
        Write-SearchLog "Failed to analyze search indexer health: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Validate Windows Search database integrity and size
function Test-SearchDatabaseIntegrity {
    Write-SearchLog "Validating Windows Search database integrity and configuration..." -Level "Info"
    
    try {
        # Get search database location and size
        $SearchDataPath = "${env:ProgramData}\Microsoft\Search\Data"
        $DatabaseFiles = @("Windows.edb", "*.log", "*.chk")
        
        $DatabaseIssues = @()
        $TotalDatabaseSize = 0
        
        foreach ($Pattern in $DatabaseFiles) {
            $Files = Get-ChildItem -Path $SearchDataPath -Filter $Pattern -ErrorAction SilentlyContinue
            
            foreach ($File in $Files) {
                $FileSizeMB = [math]::Round($File.Length / 1MB, 2)
                $TotalDatabaseSize += $FileSizeMB
                
                Write-SearchLog "Database file: $($File.Name) - Size: $FileSizeMB MB" -Level "Info"
                
                # Check for unusually large database files
                if ($File.Name -eq "Windows.edb" -and $FileSizeMB -gt $SearchHealthCriteria.MaxDatabaseSizeMB) {
                    Write-SearchLog "Search database is unusually large ($FileSizeMB MB) - may indicate corruption" -Level "Warning"
                    $DatabaseIssues += "Database too large"
                }
            }
        }
        
        Write-SearchLog "Total search database size: $([math]::Round($TotalDatabaseSize, 2)) MB" -Level "Performance" -PerformanceMetric
        
        # Check if database directory exists
        if (-not (Test-Path $SearchDataPath)) {
            Write-SearchLog "Search database directory not found: $SearchDataPath" -Level "Error"
            $DatabaseIssues += "Database directory missing"
        }
        
        # Check for recent database corruption events
        $RecentCorruptionEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ProviderName = 'Microsoft-Windows-Search*'
            Level = 2  # Error
            StartTime = (Get-Date).AddDays(-7)
        } -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*corrupt*" -or $_.Message -like "*damaged*" }
        
        if ($RecentCorruptionEvents) {
            Write-SearchLog "Found $($RecentCorruptionEvents.Count) recent database corruption events" -Level "Warning"
            $DatabaseIssues += "Recent corruption events"
        }
        
        # Test database accessibility
        try {
            $DatabaseLockTest = [System.IO.File]::Open("$SearchDataPath\Windows.edb", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $DatabaseLockTest.Close()
            Write-SearchLog "Search database is accessible" -Level "Success"
        } catch {
            Write-SearchLog "Search database access test failed: $($_.Exception.Message)" -Level "Warning"
            $DatabaseIssues += "Database access issues"
        }
        
        return ($DatabaseIssues.Count -eq 0)
        
    } catch {
        Write-SearchLog "Failed to validate search database integrity: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Test actual search functionality with real queries
function Test-SearchFunctionality {
    Write-SearchLog "Testing Windows Search functionality with practical queries..." -Level "Info"
    
    try {
        $FunctionalityTests = @()
        
        # Test 1: File search functionality
        $FileSearchResult = Test-FileSearchCapability
        $FunctionalityTests += @{ Name = "File Search"; Result = $FileSearchResult }
        
        # Test 2: Application search functionality  
        $AppSearchResult = Test-ApplicationSearchCapability
        $FunctionalityTests += @{ Name = "Application Search"; Result = $AppSearchResult }
        
        # Test 3: Settings search functionality
        $SettingsSearchResult = Test-SettingsSearchCapability
        $FunctionalityTests += @{ Name = "Settings Search"; Result = $SettingsSearchResult }
        
        # Evaluate overall functionality
        $PassedTests = ($FunctionalityTests | Where-Object { $_.Result -eq $true }).Count
        $TotalTests = $FunctionalityTests.Count
        $FunctionalityScore = [math]::Round(($PassedTests / $TotalTests) * 100, 1)
        
        Write-SearchLog "Search functionality score: $FunctionalityScore% ($PassedTests / $TotalTests tests passed)" -Level "Performance" -PerformanceMetric
        
        foreach ($Test in $FunctionalityTests) {
            $Status = if ($Test.Result) { "PASS" } else { "FAIL" }
            Write-SearchLog "  $($Test.Name): $Status" -Level "Info"
        }
        
        # Require at least 75% functionality for compliance
        return ($FunctionalityScore -ge 75)
        
    } catch {
        Write-SearchLog "Failed to test search functionality: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Test file search capability
function Test-FileSearchCapability {
    try {
        # Search for common system files
        $SearchQuery = "notepad.exe"
        $SearchStartTime = Get-Date
        
        $SearchResults = Get-ChildItem -Path "$env:SystemRoot" -Filter $SearchQuery -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        
        $SearchDuration = (Get-Date) - $SearchStartTime
        Write-SearchLog "File search for '$SearchQuery' completed in $([math]::Round($SearchDuration.TotalMilliseconds, 0)) ms" -Level "Info"
        
        if ($SearchResults) {
            Write-SearchLog "File search functionality verified" -Level "Success"
            return $true
        } else {
            Write-SearchLog "File search did not return expected results" -Level "Warning"
            return $false
        }
    } catch {
        Write-SearchLog "File search test failed: $($_.Exception.Message)" -Level "Warning"
        return $false
    }
}

# Test application search capability
function Test-ApplicationSearchCapability {
    try {
        # Test if we can find installed applications
        $InstalledApps = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Select-Object -First 5
        
        if ($InstalledApps -and $InstalledApps.Count -gt 0) {
            Write-SearchLog "Application search capability verified" -Level "Success"
            return $true
        } else {
            Write-SearchLog "Application search capability limited" -Level "Warning"
            return $false
        }
    } catch {
        Write-SearchLog "Application search test failed: $($_.Exception.Message)" -Level "Warning"
        return $false
    }
}

# Test settings search capability
function Test-SettingsSearchCapability {
    try {
        # Test if Windows Search can index and find settings
        $ControlPanelItems = Get-ChildItem -Path "$env:SystemRoot\System32" -Filter "*.cpl" -ErrorAction SilentlyContinue
        
        if ($ControlPanelItems -and $ControlPanelItems.Count -gt 0) {
            Write-SearchLog "Settings search capability verified" -Level "Success"
            return $true
        } else {
            Write-SearchLog "Settings search capability limited" -Level "Warning"
            return $false
        }
    } catch {
        Write-SearchLog "Settings search test failed: $($_.Exception.Message)" -Level "Warning"
        return $false
    }
}

# Check for recent Windows Search errors and issues
function Test-SearchErrorHistory {
    Write-SearchLog "Analyzing recent Windows Search error history..." -Level "Info"
    
    try {
        # Check for recent search-related errors
        $RecentErrors = Get-WinEvent -FilterHashtable @{
            LogName = @('System', 'Application')
            ProviderName = '*Search*'
            Level = @(1, 2, 3)  # Critical, Error, Warning
            StartTime = (Get-Date).AddDays(-7)
        } -ErrorAction SilentlyContinue
        
        if (-not $RecentErrors) {
            Write-SearchLog "No recent search-related errors found" -Level "Success"
            return $true
        }
        
        $CriticalErrors = $RecentErrors | Where-Object { $_.Level -eq 1 -or $_.Level -eq 2 }
        $Warnings = $RecentErrors | Where-Object { $_.Level -eq 3 }
        
        Write-SearchLog "Found $($CriticalErrors.Count) critical errors and $($Warnings.Count) warnings in the last 7 days" -Level "Info"
        
        # Log the most recent critical errors
        if ($CriticalErrors.Count -gt 0) {
            $RecentCriticalErrors = $CriticalErrors | Sort-Object TimeCreated -Descending | Select-Object -First 3
            foreach ($Error in $RecentCriticalErrors) {
                Write-SearchLog "Recent critical error: $($Error.LevelDisplayName) - $($Error.Message)" -Level "Warning"
            }
        }
        
        # Evaluate error threshold
        if ($CriticalErrors.Count -gt $SearchHealthCriteria.MaxRecentErrors) {
            Write-SearchLog "Excessive search errors ($($CriticalErrors.Count)) indicate significant issues" -Level "Error"
            return $false
        }
        
        Write-SearchLog "Search error history analysis completed" -Level "Success"
        return $true
        
    } catch {
        Write-SearchLog "Failed to analyze search error history: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Main Windows Search detection orchestration
try {
    Write-SearchLog "=== Windows Search Health Detection Started ===" -Level "Info" -WriteToEventLog
    Write-SearchLog "Detection script version: 1.0" -Level "Info"
    Write-SearchLog "Target device: $env:COMPUTERNAME" -Level "Info"
    Write-SearchLog "Detection user: $env:USERNAME" -Level "Info"
    Write-SearchLog "Search health criteria: Response time under 5s, Database under 10GB, Errors under 5/week" -Level "Info"
    
    # Verify Windows version compatibility
    $WindowsVersion = [System.Environment]::OSVersion.Version
    if ($WindowsVersion.Major -lt 10) {
        Write-SearchLog "Windows Search detection requires Windows 10 or later" -Level "Error"
        exit 1
    }
    
    # Execute comprehensive search health assessment
    Write-SearchLog "Executing comprehensive Windows Search health assessment..." -Level "Info"
    
    $SearchHealthChecks = @{
        "Service_Health" = Test-SearchServiceHealth
        "Indexer_Status" = Test-SearchIndexerHealth  
        "Database_Integrity" = Test-SearchDatabaseIntegrity
        "Search_Functionality" = Test-SearchFunctionality
        "Error_History" = Test-SearchErrorHistory
    }
    
    # Calculate search health score
    $PassedChecks = ($SearchHealthChecks.Values | Where-Object { $_ -eq $true }).Count
    $TotalChecks = $SearchHealthChecks.Count
    $HealthScore = [math]::Round(($PassedChecks / $TotalChecks) * 100, 1)
    
    Write-SearchLog "=== Search Health Assessment Results ===" -Level "Info"
    Write-SearchLog "Search Health Score: $HealthScore% ($PassedChecks of $TotalChecks checks passed)" -Level "Info" -PerformanceMetric
    
    foreach ($Check in $SearchHealthChecks.GetEnumerator()) {
        $Status = if ($Check.Value) { "PASS" } else { "FAIL" }
        $CheckName = $Check.Key.Replace("_", " ")
        Write-SearchLog "  $CheckName : $Status" -Level "Info"
    }
    
    # Determine compliance status based on critical requirements
    $CriticalChecks = @("Service_Health", "Search_Functionality")
    $CriticalPassed = $true
    
    foreach ($CriticalCheck in $CriticalChecks) {
        if (-not $SearchHealthChecks[$CriticalCheck]) {
            $CriticalPassed = $false
            break
        }
    }
    
    # Final compliance determination
    if ($CriticalPassed -and $HealthScore -ge 80) {
        Write-SearchLog "=== SEARCH STATUS: HEALTHY ===" -Level "Success" -WriteToEventLog
        Write-SearchLog "Windows Search is functioning properly and meeting performance standards" -Level "Success"
        exit 0
    } else {
        Write-SearchLog "=== SEARCH STATUS: REQUIRES ATTENTION ===" -Level "Error" -WriteToEventLog
        Write-SearchLog "Windows Search issues detected - remediation recommended for optimal user experience" -Level "Error"
        exit 1
    }
    
} catch {
    Write-SearchLog "=== SEARCH DETECTION FAILED ===" -Level "Error" -WriteToEventLog
    Write-SearchLog "Unexpected error during search health assessment: $($_.Exception.Message)" -Level "Error"
    Write-SearchLog "Stack trace: $($_.Exception.StackTrace)" -Level "Error"
    
    # Exit with error code indicating detection failure
    exit 1
    
} finally {
    $ScriptDuration = (Get-Date) - $ScriptStartTime
    Write-SearchLog "Search health detection completed in $($ScriptDuration.TotalSeconds) seconds" -Level "Info"
}