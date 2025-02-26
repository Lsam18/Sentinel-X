# Get API key from here: https://ip-api.com/ (Note: No API key is needed for the free plan)
$LOGFILE_NAME = "failed_rdp.log"
$LOG_DIRECTORY = "C:\ProgramData\RDPLogs"
$BLOCKED_IP_DIRECTORY = "C:\ProgramData\RDPLogs"
$LOGFILE_PATH = "$LOG_DIRECTORY\$($LOGFILE_NAME)"
$BLOCKED_IPS_FILE = "C:\ProgramData\BlockedIPs\blocked_ips.txt"
$WHITELIST_IP_FILE = "C:\ProgramData\RDPLogs\whitelisted_ips.txt"

$SystemInfo = @{
    ComputerName = $env:COMPUTERNAME
    Username = $env:USERNAME
    Domain = $env:USERDOMAIN
    IP = (Get-NetIPAddress -AddressFamily IPv4).IPAddress[0]
    OSVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
}

$SystemInfo | ConvertTo-Json

# This filter will be used to filter failed RDP events from Windows Event Viewer
$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@

# Load whitelisted IPs from file
$whitelistedIPs = @{}
if (-not (Test-Path $WHITELIST_IP_FILE)) {
    # Create the whitelisted IP file if it doesn't exist
    New-Item -ItemType File -Path $WHITELIST_IP_FILE -Force | Out-Null
    Write-Host "Whitelisted IPs file created at $WHITELIST_IP_FILE" -ForegroundColor Green
}

# Load IPs from the whitelisted file if it exists
$whitelistedIPsArray = Get-Content -Path $WHITELIST_IP_FILE
foreach ($ip in $whitelistedIPsArray) {
    $whitelistedIPs[$ip.Trim()] = $true
}

# Function to write sample log files to train the Log Analytics workspace
Function write-Sample-Log() {
    @(
        "latitude=47.91542,longitude=-120.60306,destinationhost=samplehost,username=fakeuser,sourcehost=24.16.97.222,state=Washington,country=United States,label=United States - 24.16.97.222,timestamp=2021-10-26 03:28:29",
        "latitude=-22.90906,longitude=-47.06455,destinationhost=samplehost,username=lnwbaq,sourcehost=20.195.228.49,state=Sao Paulo,country=Brazil,label=Brazil - 20.195.228.49,timestamp=2021-10-26 05:46:20"
    ) | ForEach-Object {
        $_ | Out-File $LOGFILE_PATH -Append -Encoding utf8
    }
}

# Check if log file exists, otherwise create it and write sample data
if (-not (Test-Path $LOG_DIRECTORY)) {
    New-Item -ItemType Directory -Path $LOG_DIRECTORY -Force | Out-Null
}
if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
    write-Sample-Log
}

if (-not (Test-Path $BLOCKED_IP_DIRECTORY)) {
    New-Item -ItemType Directory -Path $BLOCKED_IP_DIRECTORY -Force | Out-Null
}
$BLOCKED_IPS_FILE = "$BLOCKED_IP_DIRECTORY\blocked_ips.txt"
if (-not (Test-Path $BLOCKED_IPS_FILE)) {
    New-Item -ItemType File -Path $BLOCKED_IPS_FILE -Force | Out-Null
}

# Function to check if an IP address is private
Function Is-PrivateIP($ip) {
    return $ip -match "^10\." -or
           $ip -match "^172\.(1[6-9]|2[0-9]|3[0-1])\." -or
           $ip -match "^192\.168\." -or
           $ip -eq "127.0.0.1"
}

# Dictionary to track failed attempts
$failedAttempts = @{}
$userAttempts = @{}
$blockedIPs = @{}

# Load blocked IPs from file
if (Test-Path $BLOCKED_IPS_FILE) {
    $blockedIPsArray = Get-Content -Path $BLOCKED_IPS_FILE
    foreach ($ip in $blockedIPsArray) {
        $blockedIPs[$ip.Trim()] = $true
    }
}

# Function to block an IP address
Function Block-IP($ip) {
    if ($whitelistedIPs.ContainsKey($ip)) {
        Write-Host "IP $ip is whitelisted, skipping block." -ForegroundColor Yellow
    }
    elseif (-not $blockedIPs.ContainsKey($ip)) {
        # Example command to block IP (replace with actual firewall rule command)
        Write-Host "Blocking IP: $ip" -ForegroundColor Red
        "Blocked IP: $ip" | Out-File -FilePath $BLOCKED_IPS_FILE -Append -Encoding utf8
        $blockedIPs[$ip] = $true
    }
}

# Function to unblock an IP address
Function Unblock-IP($ip) {
    if ($blockedIPs.ContainsKey($ip)) {
        Write-Host "Unblocking IP: $ip" -ForegroundColor Green
        $blockedIPs.Remove($ip)
        # Remove IP from blocked IPs file
        $blockedIPsArray = Get-Content -Path $BLOCKED_IPS_FILE | Where-Object { $_ -ne "Blocked IP: $ip" }
        $blockedIPsArray | Out-File -FilePath $BLOCKED_IPS_FILE -Force -Encoding utf8
    }
}

# Function to check for suspicious time-based activity
Function Is-OutsideNormalHours($timestamp) {
    $hour = [int]$timestamp.Split(' ')[1].Split(':')[0]
    return ($hour -lt 8 -or $hour -gt 18) # Outside of 8 AM to 6 PM
}

# Infinite Loop that keeps checking the Event Viewer logs.
$summaryInterval = 10 # Interval for event summary output
$processedEvents = @()
while ($true)
{
    Start-Sleep -Seconds 1
    $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        # Ensure the event contains a valid source IP address
        if ($event.properties[19].Value.Length -ge 5) {
            # Extract timestamp and event details
            $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            $destinationHost = $event.MachineName
            $username = $event.properties[5].Value
            $sourceHost = $event.properties[11].Value
            $sourceIp = $event.properties[19].Value
            
            # Skip processing if the IP is in the whitelist
            if ($whitelistedIPs.ContainsKey($sourceIp)) {
                Write-Host "Skipping whitelisted IP: $sourceIp" -ForegroundColor Yellow
                continue
            }
            
            $eventId = $event.Id
            $rawLogonType = $event.properties[8].Value
            $logonType = switch ($rawLogonType) {
                '2'  { 'Interactive' }
                '3'  { 'Network' }
                '4'  { 'Batch' }
                '5'  { 'Service' }
                '7'  { 'Unlock' }
                '8'  { 'NetworkCleartext' }
                '9'  { 'NewCredentials' }
                '10' { 'RemoteInteractive' }
                '11' { 'CachedInteractive' }
                default { "Unknown Logon Type ($rawLogonType)" }
            }

            $failureReason = $event.properties[13].Value

            # Get the current contents of the Log file
            $log_contents = Get-Content -Path $LOGFILE_PATH

            # Check if the entry already exists in the log file
            if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
                # Announce geolocation lookup and add a pause to avoid API rate limiting
                Start-Sleep -Seconds 1

                # Check if the IP address is private
                if (Is-PrivateIP($sourceIp)) {
                    # Set values for private IP addresses
                    $latitude = "N/A"
                    $longitude = "N/A"
                    $state_prov = "Local Network"
                    $country = "Local Network"
                    $isp = "Local Network"
                    $org = "Local Network"
                }
                else {
                    # Make the web request to the geolocation API with error handling
                    try {
                        $API_ENDPOINT = "http://ip-api.com/json/$($sourceIp)?fields=status,message,country,regionName,lat,lon,isp,org"
                        $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT
                        $responseData = $response.Content | ConvertFrom-Json

                        # Extract geolocation data from API response
                        if ($responseData.status -eq "success") {
                            $latitude = if ($responseData.lat) { $responseData.lat } else { "unknown" }
                            $longitude = if ($responseData.lon) { $responseData.lon } else { "unknown" }
                            $state_prov = if ($responseData.regionName) { $responseData.regionName } else { "unknown" }
                            $country = if ($responseData.country) { $responseData.country } else { "unknown" }
                            $isp = if ($responseData.isp) { $responseData.isp } else { "unknown" }
                            $org = if ($responseData.org) { $responseData.org } else { "unknown" }
                        }
                        else {
                            Write-Warning "Failed to retrieve geolocation for IP: $sourceIp. Reason: $($responseData.message)"
                            $latitude = "unknown"
                            $longitude = "unknown"
                            $state_prov = "unknown"
                            $country = "unknown"
                            $isp = "unknown"
                            $org = "unknown"
                        }
                    }
                    catch {
                        # Handle the error if the web request fails and set default values
                        Write-Warning "Failed to retrieve geolocation for IP: $sourceIp. Setting default values."
                        $latitude = "unknown"
                        $longitude = "unknown"
                        $state_prov = "unknown"
                        $country = "unknown"
                        $isp = "unknown"
                        $org = "unknown"
                    }
                }

                # Determine attack type based on advanced conditions
                $attackType = "Unknown"
                $currentTime = Get-Date

                # Detect Brute Force (Multiple failed attempts from the same IP within 10 minutes)
                if (-not $failedAttempts.ContainsKey($sourceIp)) {
                    $failedAttempts[$sourceIp] = [System.Collections.Generic.List[DateTime]]::new()
                }
                $failedAttempts[$sourceIp].Add($currentTime)
                $recentAttempts = $failedAttempts[$sourceIp] | Where-Object { ($_ -ge $currentTime.AddMinutes(-10)) }
                $numAttempts = $recentAttempts.Count
                if ($numAttempts -ge 10) {
                    $attackType = "Advanced Brute Force"
                    Block-IP $sourceIp
                }

                # Detect Password Spraying (Same password tried with different usernames)
                if (-not $userAttempts.ContainsKey($username)) {
                    $userAttempts[$username] = [System.Collections.Generic.List[DateTime]]::new()
                }
                $userAttempts[$username].Add($currentTime)
                $recentUserAttempts = $userAttempts[$username] | Where-Object { ($_ -ge $currentTime.AddMinutes(-30)) }
                if ($recentUserAttempts.Count -ge 5) {
                    $attackType = "Password Spraying"
                    Block-IP $sourceIp
                }

                # Detect Impossible Travel (Logging in from distant locations in a short time)
                if (-not [string]::IsNullOrEmpty($latitude) -and -not [string]::IsNullOrEmpty($longitude)) {
                    if ($userAttempts[$username].Count -ge 2) {
                        # Add logic here to compare geolocation and time
                        $attackType = "Impossible Travel"
                        Block-IP $sourceIp
                    }
                }

                # Detect Suspicious Login Times
                if (Is-OutsideNormalHours($timestamp)) {
                    $attackType = "Suspicious Time-Based Activity"
                    Block-IP $sourceIp
                }

                # MITRE ATT&CK Technique Descriptions (Example: mapping attack types to MITRE descriptions)
                $mitreAttackTechnique = "Brute Force (T1110)" # Default to Brute Force
                switch ($attackType) {
                    "Advanced Brute Force" { $mitreAttackTechnique = "Password Cracking - Brute Force (T1110.001)" }
                    "Password Spraying" { $mitreAttackTechnique = "Password Spraying (T1110.003)" }
                    "Impossible Travel" { $mitreAttackTechnique = "Use of Valid Accounts - Impossible Travel (T1078)" }
                    "Suspicious Time-Based Activity" { $mitreAttackTechnique = "Application Layer Protocol - Suspicious Time (T1071)" }
                }

                # Format and write the log entry in a structured way (as key-value pairs)
                $log_entry = "timestamp=$($timestamp),destinationhost=$($destinationHost),username=$($username),sourcehost=$($sourceHost),sourceip=$($sourceIp),latitude=$($latitude),longitude=$($longitude),state=$($state_prov),country=$($country),isp=$($isp),org=$($org),attacktype=$($attackType),numattempts=$($numAttempts),mitreattacktechnique=$($mitreAttackTechnique),eventid=$($eventId),logontype=$($logonType),failurereason=$($failureReason)"
                $log_entry | Out-File $LOGFILE_PATH -Append -Encoding utf8

                # Add the processed event to the summary list
                $processedEvents += [PSCustomObject]@{
                    EventCount = $processedEvents.Count + 1
                    EventTime = $timestamp
                    Username = $username
                    SourceIP = $sourceIp
                    AttackType = $attackType
                    MITRETechnique = $mitreAttackTechnique
                    EventID = $eventId
                    LogonType = $logonType
                    FailureReason = $failureReason
                }

                # Display the log entry in a clear, detailed format
                Write-Host "[EVENT DETECTED]" -ForegroundColor Green
                Write-Host "  Timestamp       : $timestamp" -ForegroundColor Cyan
                Write-Host "  Destination Host: $destinationHost" -ForegroundColor Cyan
                Write-Host "  Username        : $username" -ForegroundColor Cyan
                Write-Host "  Source IP       : $sourceIp" -ForegroundColor Cyan
                Write-Host "  Location        : $country, $state_prov" -ForegroundColor Cyan
                Write-Host "  ISP             : $isp" -ForegroundColor Cyan
                Write-Host "  Organization    : $org" -ForegroundColor Cyan
                Write-Host "  Event ID        : $eventId" -ForegroundColor Cyan
                Write-Host "  Logon Type      : $logonType" -ForegroundColor Cyan
                Write-Host "  Failure Reason  : $failureReason" -ForegroundColor Cyan
                Write-Host "  Attack Type     : $attackType" -ForegroundColor Green
                Write-Host "  MITRE Technique : $mitreAttacktechnique`n" -ForegroundColor Green
            }
        }
    }

    # Check for successful logins and unblock IPs if necessary
    $successfulEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue
    foreach ($event in $successfulEvents) {
        $sourceIp = $event.properties[18].Value
        if ($blockedIPs.ContainsKey($sourceIp)) {
            Unblock-IP $sourceIp
        }
    }

    # Output summary at regular intervals
    if ($processedEvents.Count -ge $summaryInterval) {
        Show-Menu
        $processedEvents.Clear()
    }
}
