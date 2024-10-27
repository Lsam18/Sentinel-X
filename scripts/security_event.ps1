# Run as Administrator check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    Exit
}

# Required modules
$modules = @("Microsoft.PowerShell.Security", "Microsoft.PowerShell.Management")
foreach ($module in $modules) {
    if (-not (Get-Module -Name $module)) {
        Import-Module $module
    }
}

# Configuration
$LOG_DIR = "C:\ProgramData\RDPSecurity"
$LOGFILE_PATH = Join-Path $LOG_DIR "failed_rdp.log"
$BLOCKED_IPS_PATH = Join-Path $LOG_DIR "blocked_ips.json"
$ANALYTICS_PATH = Join-Path $LOG_DIR "rdp_analytics.json"
$ATTACK_LOG_PATH = Join-Path $LOG_DIR "attack_patterns.log"
$DETAILED_EVENTS_PATH = Join-Path $LOG_DIR "detailed_events.json"
$API_KEY = "1dbc58de95974eccaec705e34187d208"  # Replace with your API key

#fetch pc info
# security_event.ps1
$SystemInfo = @{
    ComputerName = $env:COMPUTERNAME
    Username = $env:USERNAME
    Domain = $env:USERDOMAIN
    IP = (Get-NetIPAddress -AddressFamily IPv4).IPAddress[0]
    OSVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
}

$SystemInfo | ConvertTo-Json


# Create directory if it doesn't exist
if (-not (Test-Path $LOG_DIR)) {
    New-Item -ItemType Directory -Path $LOG_DIR | Out-Null
}

# XML Filter for Windows Event Log
$XMLFilter = @'
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">*[System[(EventID='4625')]]</Select>
    </Query>
</QueryList>
'@

# MITRE ATT&CK Techniques
$MITRE_TECHNIQUES = @{
    "T1110.001" = @{
        Name = "Brute Force"
        Tactic = "Credential Access"
        Description = "Adversary attempting to gain access using systematic guessing of credentials"
    }
    "T1110.003" = @{
        Name = "Password Spraying"
        Tactic = "Credential Access"
        Description = "Adversary attempting to access many accounts using a single password"
    }
    "T1078" = @{
        Name = "Valid Accounts"
        Tactic = "Defense Evasion, Persistence, Privilege Escalation, Initial Access"
        Description = "Adversary attempting to use legitimate credentials for malicious access"
    }
    "T1059" = @{
        Name = "Command and Scripting Interpreter"
        Tactic = "Execution"
        Description = "Adversary attempting to execute malicious commands or scripts"
    }
}

# Enhanced attack pattern definitions
$script:AttackPatterns = @{
    BruteForce = @{
        Threshold = 5
        TimeWindow = 5  # minutes
        Color = "Red"
        Severity = "Critical"
        Description = "Multiple failed login attempts from same IP using same username"
        MitigationAdvice = "Implement account lockout policies and IP blocking"
        MITRE = "T1110.001"
    }
    PasswordSpray = @{
        Threshold = 3
        TimeWindow = 5  # minutes
        Color = "Magenta"
        Severity = "High"
        Description = "Multiple failed attempts using different usernames"
        MitigationAdvice = "Implement MFA and complex password policies"
        MITRE = "T1110.003"
    }
    OutsideHours = @{
        StartHour = 18  # 6 PM
        EndHour = 6    # 6 AM
        Color = "Blue"
        Severity = "Medium"
        Description = "Login attempts outside business hours"
        MitigationAdvice = "Review legitimate access hours and implement time-based access controls"
        MITRE = "T1059"
    }
    HighPrivilegeAttempt = @{
        Threshold = 2
        TimeWindow = 5  # minutes
        Color = "Yellow"
        Severity = "High"
        Description = "Attempts to access privileged accounts"
        MitigationAdvice = "Implement PAM and just-in-time access"
        MITRE = "T1078"
    }
}

# Initialize state
$script:BlockedIPs = @{}
$script:AttackHistory = @{}
$script:GlobalStats = @{
    TotalAttempts = 0
    UniqueIPs = @{}
    UniqueUsernames = @{}
    AttackPatterns = @{
        BruteForce = 0
        PasswordSpray = 0
        OutsideHours = 0
        HighPrivilegeAttempt = 0
    }
    CountryStats = @{}
}

function Get-GeoIPInfo {
    param (
        [string]$IP
    )
    try {
        $url = "https://api.ipgeolocation.io/ipgeo?apiKey=$API_KEY&ip=$IP"
        $response = Invoke-RestMethod -Uri $url -Method Get
        return @{
            Country = $response.country_name
            City = $response.city
            Region = $response.state_prov
            Latitude = $response.latitude
            Longitude = $response.longitude
            ISP = $response.isp
            Timezone = $response.time_zone.name
            Success = $true
        }
    }
    catch {
        return @{
            Country = "Unknown"
            City = "Unknown"
            Region = "Unknown"
            Latitude = "0"
            Longitude = "0"
            ISP = "Unknown"
            Timezone = "Unknown"
            Success = $false
        }
    }
}

function Format-LogAnalyticsJson {
    param (
        [hashtable]$Data
    )
    
    $Data.Add("TimeGenerated", (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))
    $Data.Add("Computer", $env:COMPUTERNAME)
    return $Data | ConvertTo-Json -Compress
}

function Write-LogAnalytics {
    param (
        [string]$LogType,
        [hashtable]$Data
    )
    
    $formattedJson = Format-LogAnalyticsJson -Data $Data
    Add-Content -Path $DETAILED_EVENTS_PATH -Value $formattedJson
    return $formattedJson
}

function Write-FailedRDPLog {
    param (
        [PSCustomObject]$LogEntry
    )
    $logMessage = "$($LogEntry.Timestamp) - Failed RDP from IP: $($LogEntry.SourceIP), Username: $($LogEntry.Username), Country: $($LogEntry.GeoLocation.Country)"
    Add-Content -Path $LOGFILE_PATH -Value $logMessage
}

function Detect-AttackPatterns {
    param (
        [string]$sourceIP,
        [string]$username,
        [datetime]$timestamp,
        [string]$accountType
    )
    
    $patterns = @()
    
    if (-not $script:AttackHistory.ContainsKey($sourceIP)) {
        $script:AttackHistory[$sourceIP] = @{
            Attempts = [System.Collections.ArrayList]@()
            Usernames = @{}
            PrivilegedAttempts = 0
            FirstSeen = $timestamp
            LastSeen = $timestamp
            TotalAttempts = 0
        }
    }
    
    $history = $script:AttackHistory[$sourceIP]
    $history.LastSeen = $timestamp
    $history.TotalAttempts++
    [void]$history.Attempts.Add($timestamp)
    
    if (-not $history.Usernames.ContainsKey($username)) {
        $history.Usernames[$username] = @{
            Count = 0
            FirstAttempt = $timestamp
            LastAttempt = $timestamp
        }
    }
    $history.Usernames[$username].Count++
    $history.Usernames[$username].LastAttempt = $timestamp

    # Check for privileged account attempts
    if ($accountType -eq "Administrator" -or $username -like "*admin*") {
        $history.PrivilegedAttempts++
    }

    # Pattern detection
    $recentAttempts = $history.Attempts | Where-Object { $_ -gt $timestamp.AddMinutes(-5) }
    
    # Brute Force Detection
    if ($recentAttempts.Count -ge $script:AttackPatterns.BruteForce.Threshold) {
        $patterns += @{
            Type = "Brute Force Attack"
            Severity = $script:AttackPatterns.BruteForce.Severity
            Details = "Multiple login attempts ($($recentAttempts.Count) in $($script:AttackPatterns.BruteForce.TimeWindow) minutes)"
            MITRE = $script:AttackPatterns.BruteForce.MITRE
            MitigationAdvice = $script:AttackPatterns.BruteForce.MitigationAdvice
        }
        $script:GlobalStats.AttackPatterns.BruteForce++
    }

    # Password Spray Detection
    if ($history.Usernames.Count -ge $script:AttackPatterns.PasswordSpray.Threshold) {
        $patterns += @{
            Type = "Password Spray Attack"
            Severity = $script:AttackPatterns.PasswordSpray.Severity
            Details = "Multiple usernames attempted ($($history.Usernames.Count) unique accounts)"
            MITRE = $script:AttackPatterns.PasswordSpray.MITRE
            MitigationAdvice = $script:AttackPatterns.PasswordSpray.MitigationAdvice
        }
        $script:GlobalStats.AttackPatterns.PasswordSpray++
    }

    # Outside Hours Detection
    $hour = $timestamp.Hour
    if ($hour -ge $script:AttackPatterns.OutsideHours.StartHour -or $hour -lt $script:AttackPatterns.OutsideHours.EndHour) {
        $patterns += @{
            Type = "Outside Hours Activity"
            Severity = $script:AttackPatterns.OutsideHours.Severity
            Details = "Login attempt at $($timestamp.ToString('HH:mm'))"
            MITRE = $script:AttackPatterns.OutsideHours.MITRE
            MitigationAdvice = $script:AttackPatterns.OutsideHours.MitigationAdvice
        }
        $script:GlobalStats.AttackPatterns.OutsideHours++
    }

    # High Privilege Attempt Detection
    if ($history.PrivilegedAttempts -ge $script:AttackPatterns.HighPrivilegeAttempt.Threshold) {
        $patterns += @{
            Type = "High Privilege Account Attack"
            Severity = $script:AttackPatterns.HighPrivilegeAttempt.Severity
            Details = "Multiple attempts on privileged accounts ($($history.PrivilegedAttempts) attempts)"
            MITRE = $script:AttackPatterns.HighPrivilegeAttempt.MITRE
            MitigationAdvice = $script:AttackPatterns.HighPrivilegeAttempt.MitigationAdvice
        }
        $script:GlobalStats.AttackPatterns.HighPrivilegeAttempt++
    }

    # Log attack patterns
    if ($patterns.Count -gt 0) {
        $attackLog = @{
            Timestamp = $timestamp.ToString("yyyy-MM-dd HH:mm:ss")
            SourceIP = $sourceIP
            Patterns = $patterns
            TotalAttempts = $history.TotalAttempts
            UniqueUsernames = $history.Usernames.Keys
            AttackDuration = ($timestamp - $history.FirstSeen).TotalMinutes
        }
        
        Write-LogAnalytics -LogType "RDPAttackPatterns" -Data $attackLog
    }

    return $patterns
}

function Block-MaliciousIP {
    param (
        [string]$IP,
        [string]$Reason,
        [hashtable]$AttackHistory
    )
    
    if (-not $script:BlockedIPs.ContainsKey($IP)) {
        $ruleName = "RDP-Security-Block-$IP"
        try {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $IP
            
            $blockData = @{
                TimeBlocked = (Get-Date)
                Reason = $Reason
                AttackHistory = @{
                    TotalAttempts = $AttackHistory.TotalAttempts
                    UniqueUsernames = @($AttackHistory.Usernames.Keys)
                    FirstSeen = $AttackHistory.FirstSeen
                    LastSeen = $AttackHistory.LastSeen
                    PrivilegedAttempts = $AttackHistory.PrivilegedAttempts
                }
                FirewallRule = $ruleName
            }
            
            $script:BlockedIPs[$IP] = $blockData
            
            Write-LogAnalytics -LogType "RDPIPBlocks" -Data @{
                IP = $IP
                BlockReason = $Reason
                AttackMetrics = $blockData.AttackHistory
            }
            
            return $true
        }
        catch {
            Write-Warning "Failed to block IP $IP`: $_"
            return $false
        }
    }
    return $false
}

function Show-MenuBar {
    $menuBar = @"
╔════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ [F1] Help | [F2] Show Threats | [F3] Show Stats | [F4] Export Data | [CTRL+C] Exit                ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════╝
"@
    Write-Host $menuBar -ForegroundColor DarkCyan
}

function Show-Header {
    $header = @"
██████╗ ██████╗ ██████╗     ███████╗ ██████╗  ██████╗
██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔═══██╗██╔════╝
██████╔╝██║  ██║██████╔╝    ███████╗██║   ██║██║     
██╔══██╗██║  ██║██╔═══╝     ╚════██║██║   ██║██║     
██║  ██║██████╔╝██║         ███████║╚██████╔╝╚██████╗
╚═╝  ╚═╝╚═════╝ ╚═╝         ╚══════╝ ╚═════╝  ╚═════╝
"@
    Write-Host $header -ForegroundColor Cyan
    Write-Host "Advanced Security Operations Center - RDP Threat Monitor v2.1" -ForegroundColor Yellow
    Write-Host "═" * 100 -ForegroundColor DarkCyan
}
function Show-ThreatIndicator {
    param (
        [string]$ThreatLevel
    )
    
    $color = switch ($ThreatLevel) {
        "Critical" { "Red" }
        "High" { "Yellow" }
        "Medium" { "Cyan" }
        "Low" { "Green" }
        default { "White" }
    }
    
    Write-Host "`nCurrent Threat Level: $ThreatLevel" -ForegroundColor $color
}

function Show-AttackDetails {
    param (
        [PSCustomObject]$Attack,
        [hashtable]$GeoIP
    )
    
    Write-Host "`nLatest Attack Details:" -ForegroundColor Yellow
    Write-Host "╔═════════════════════════════════════════════════════════════════════════════╗"
    Write-Host "║ Time: $($Attack.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Host "║ Source IP: $($Attack.SourceIP)"
    Write-Host "║ Location: $($GeoIP.City), $($GeoIP.Region), $($GeoIP.Country)"
    Write-Host "║ ISP: $($GeoIP.ISP)"
    Write-Host "║ Target Username: $($Attack.Username)"
    Write-Host "║ Account Type: $($Attack.AccountType)"
    Write-Host "╚═════════════════════════════════════════════════════════════════════════════╝"
}

function Show-Statistics {
    Write-Host "`nGlobal Statistics:" -ForegroundColor Cyan
    Write-Host "╔═════════════════════════════════════════════════════════════════════════════╗"
    Write-Host "║ Total Attempts: $($script:GlobalStats.TotalAttempts.ToString('N0').PadLeft(10))"
    Write-Host "║ Unique IPs: $($script:GlobalStats.UniqueIPs.Count.ToString('N0').PadLeft(14))"
    Write-Host "║ Unique Usernames: $($script:GlobalStats.UniqueUsernames.Count.ToString('N0').PadLeft(8))"
    Write-Host "║"
    Write-Host "║ Attack Patterns:"
    Write-Host "║   Brute Force: $($script:GlobalStats.AttackPatterns.BruteForce.ToString('N0').PadLeft(13))"
    Write-Host "║   Password Spray: $($script:GlobalStats.AttackPatterns.PasswordSpray.ToString('N0').PadLeft(9))"
    Write-Host "║   Outside Hours: $($script:GlobalStats.AttackPatterns.OutsideHours.ToString('N0').PadLeft(11))"
    Write-Host "║   High Privilege: $($script:GlobalStats.AttackPatterns.HighPrivilegeAttempt.ToString('N0').PadLeft(10))"
    Write-Host "╚═════════════════════════════════════════════════════════════════════════════╝"
}

function Show-RealTimeMap {
    param (
        [hashtable]$GeoIP
    )
    Write-Host "`nLast Attack Origin:" -ForegroundColor Magenta
    Write-Host "╔═════════════════════════════════════════════════════════════════════════════╗"
    Write-Host "║ Location: $($GeoIP.City), $($GeoIP.Region), $($GeoIP.Country)"
    Write-Host "║ Coordinates: $($GeoIP.Latitude), $($GeoIP.Longitude)"
    Write-Host "║ Timezone: $($GeoIP.Timezone)"
    Write-Host "╚═════════════════════════════════════════════════════════════════════════════╝"
}

function Show-TopThreats {
    Write-Host "`nTop Threats:" -ForegroundColor Red
    Write-Host "╔═════════════════════════════════════════════════════════════════════════════╗"
    $script:BlockedIPs.GetEnumerator() | 
        Sort-Object { $_.Value.AttackHistory.TotalAttempts } -Descending | 
        Select-Object -First 3 | 
        ForEach-Object {
            Write-Host "║ IP: $($_.Key.PadRight(15)) | Attempts: $($_.Value.AttackHistory.TotalAttempts.ToString().PadLeft(5)) | Reason: $($_.Value.Reason)"
        }
    Write-Host "╚═════════════════════════════════════════════════════════════════════════════╝"
}

function Update-Dashboard {
    param (
        [PSCustomObject]$CurrentEvent,
        [array]$AttackPatterns,
        [hashtable]$GeoIP
    )
    
    Clear-Host
    Show-Header
    Show-MenuBar
    
    # Calculate threat level
    $threatLevel = if ($AttackPatterns.Count -gt 2) { "Critical" }
    elseif ($AttackPatterns.Count -eq 2) { "High" }
    elseif ($AttackPatterns.Count -eq 1) { "Medium" }
    else { "Low" }
    
    Show-ThreatIndicator -ThreatLevel $threatLevel
    Show-AttackDetails -Attack $CurrentEvent -GeoIP $GeoIP
    Show-Statistics
    Show-RealTimeMap -GeoIP $GeoIP
    Show-TopThreats
}

function Show-Help {
    Clear-Host
    Write-Host @"
╔════════════════════════ HELP ════════════════════════╗
║ F1  - Show this help menu                           ║
║ F2  - Display current threats and blocked IPs       ║
║ F3  - Show detailed statistics                      ║
║ F4  - Export security data to files                 ║
║ CTRL+C - Exit the monitoring system                 ║
╚═══════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    Write-Host "`nPress Enter to return..." -ForegroundColor Yellow
    Read-Host
}

function Show-CurrentThreats {
    Clear-Host
    Write-Host "Current Threats and Blocked IPs" -ForegroundColor Red
    Write-Host "═" * 50
    
    foreach ($ip in $script:BlockedIPs.Keys) {
        $blockInfo = $script:BlockedIPs[$ip]
        Write-Host "`nBlocked IP: $ip" -ForegroundColor Red
        Write-Host "  Blocked at: $($blockInfo.TimeBlocked)"
        Write-Host "  Reason: $($blockInfo.Reason)"
        Write-Host "  Total Attempts: $($blockInfo.AttackHistory.TotalAttempts)"
        Write-Host "  Unique Usernames: $($blockInfo.AttackHistory.UniqueUsernames.Count)"
    }
    
    Write-Host "`nPress Enter to return..." -ForegroundColor Yellow
    Read-Host
}

function Show-DetailedStatistics {
    Clear-Host
    Write-Host "Detailed Security Statistics" -ForegroundColor Cyan
    Write-Host "═" * 50
    
    Write-Host "`nGeneral Statistics:"
    Write-Host "  Total Attempts: $($script:GlobalStats.TotalAttempts)"
    Write-Host "  Unique IPs: $($script:GlobalStats.UniqueIPs.Count)"
    Write-Host "  Unique Usernames: $($script:GlobalStats.UniqueUsernames.Count)"
    
    Write-Host "`nAttack Patterns:"
    Write-Host "  Brute Force Attacks: $($script:GlobalStats.AttackPatterns.BruteForce)"
    Write-Host "  Password Spray Attacks: $($script:GlobalStats.AttackPatterns.PasswordSpray)"
    Write-Host "  Outside Hours Activity: $($script:GlobalStats.AttackPatterns.OutsideHours)"
    Write-Host "  High Privilege Attempts: $($script:GlobalStats.AttackPatterns.HighPrivilegeAttempt)"
    
    Write-Host "`nTop Countries:"
    $script:GlobalStats.CountryStats.GetEnumerator() | 
        Sort-Object Value -Descending | 
        Select-Object -First 5 | 
        ForEach-Object {
            Write-Host "  $($_.Key): $($_.Value) attempts"
        }
    
    Write-Host "`nPress Enter to return..." -ForegroundColor Yellow
    Read-Host
}

function Export-SecurityData {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportDir = Join-Path $LOG_DIR "exports"
    
    if (-not (Test-Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir | Out-Null
    }
    
    $exportFiles = @{
        "blocked_ips_$timestamp.json" = $script:BlockedIPs
        "attack_history_$timestamp.json" = $script:AttackHistory
        "global_stats_$timestamp.json" = $script:GlobalStats
    }
    
    foreach ($file in $exportFiles.Keys) {
        $exportFiles[$file] | ConvertTo-Json -Depth 10 | 
            Set-Content -Path (Join-Path $exportDir $file)
    }
    
    Write-Host "`nData exported to $exportDir" -ForegroundColor Green
    Write-Host "Press Enter to return..." -ForegroundColor Yellow
    Read-Host
}

# Main monitoring loop
try {
    $script:MonitoringStartTime = Get-Date
    Write-Host "Starting Advanced SOC Monitor..." -ForegroundColor Green
    Write-Host "Press Enter to begin monitoring..." -ForegroundColor Yellow
    Read-Host

    while ($true) {
        try {
            $events = Get-WinEvent -FilterXml $XMLFilter -MaxEvents 10 -ErrorAction SilentlyContinue
            
            if ($null -ne $events) {
                foreach ($event in $events) {
                    $eventXML = [xml]$event.ToXml()
                    
                    # Extract event details
                    $sourceIP = ($eventXML.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                    $username = ($eventXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                    $accountType = ($eventXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserType" }).'#text'
                    $timestamp = $event.TimeCreated
                    
                    # Update global statistics
                    $script:GlobalStats.TotalAttempts++
                    if (-not $script:GlobalStats.UniqueIPs.ContainsKey($sourceIP)) {
                        $script:GlobalStats.UniqueIPs[$sourceIP] = 0
                    }
                    $script:GlobalStats.UniqueIPs[$sourceIP]++
                    
                    if (-not $script:GlobalStats.UniqueUsernames.ContainsKey($username)) {
                        $script:GlobalStats.UniqueUsernames[$username] = 0
                    }
                    $script:GlobalStats.UniqueUsernames[$username]++
                    
                    # Get geolocation data
                    $geoIP = Get-GeoIPInfo -IP $sourceIP
                    
                    # Update country statistics
                    if (-not $script:GlobalStats.CountryStats.ContainsKey($geoIP.Country)) {
                        $script:GlobalStats.CountryStats[$geoIP.Country] = 0
                    }
                    $script:GlobalStats.CountryStats[$geoIP.Country]++
                    
                    # Detect attack patterns
                    $attackPatterns = Detect-AttackPatterns -sourceIP $sourceIP -username $username -timestamp $timestamp -accountType $accountType
                    
                    # Create current event object
                    $currentEvent = @{
                        Timestamp = $timestamp
                        SourceIP = $sourceIP
                        Username = $username
                        AccountType = $accountType
                        Country = $geoIP.Country
                        City = $geoIP.City
                        State = $geoIP.Region
                        Latitude = $geoIP.Latitude
                        Longitude = $geoIP.Longitude
                        ISP = $geoIP.ISP
                        IsBlocked = $script:BlockedIPs.ContainsKey($sourceIP)
                    }
                    
                    # Update dashboard
                    Update-Dashboard -CurrentEvent $currentEvent -AttackPatterns $attackPatterns -GeoIP $geoIP
                    
                    # Check if IP should be blocked
                    if ($attackPatterns.Count -gt 0) {
                        $shouldBlock = $false
                        $blockReason = ""
                        
                        # Determine if IP should be blocked based on attack patterns
                        foreach ($pattern in $attackPatterns) {
                            if ($pattern.Severity -eq "Critical") {
                                $shouldBlock = $true
                                $blockReason = $pattern.Type
                                break
                            }
                        }
                        
                        # Block IP if criteria met
                        if ($shouldBlock) {
                            $blocked = Block-MaliciousIP -IP $sourceIP -Reason $blockReason -AttackHistory $script:AttackHistory[$sourceIP]
                            if ($blocked) {
                                Write-Host "IP $sourceIP has been blocked due to $blockReason" -ForegroundColor Red
                            }
                        }
                    }
                    
                    # Log event details
                    $logEntry = @{
                        Timestamp = $timestamp.ToString("yyyy-MM-dd HH:mm:ss")
                        SourceIP = $sourceIP
                        Username = $username
                        AccountType = $accountType
                        GeoLocation = $geoIP
                        AttackPatterns = $attackPatterns
                        IsBlocked = $script:BlockedIPs.ContainsKey($sourceIP)
                    }
                    
                    Write-LogAnalytics -LogType "RDPFailedLogins" -Data $logEntry
                    Write-FailedRDPLog -LogEntry $logEntry
                }
            }
            
            # Handle user input for menu options
            if ($host.UI.RawUI.KeyAvailable) {
                $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                switch ($key.VirtualKeyCode) {
                    112 { Show-Help }  # F1
                    113 { Show-CurrentThreats }  # F2
                    114 { Show-DetailedStatistics }  # F3
                    115 { Export-SecurityData }  # F4
                }
            }
            
            Start-Sleep -Milliseconds 500
        }
        catch {
            Write-Warning "Error in monitoring loop: $_"
            Start-Sleep -Seconds 5
        }
    }
}
catch {
    Write-Host "Critical error: $_" -ForegroundColor Red
}
finally {
    # Save state and cleanup
    $script:BlockedIPs | ConvertTo-Json | Set-Content -Path $BLOCKED_IPS_PATH
    $script:GlobalStats | ConvertTo-Json | Set-Content -Path $ANALYTICS_PATH
    
    Write-Host "`nMonitoring stopped. Data has been saved." -ForegroundColor Yellow
}
    