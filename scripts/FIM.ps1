# Function to get detailed system info
Function Get-SystemDetails {
    $systemInfo = @{
        ComputerName = $env:COMPUTERNAME
        Username = $env:USERNAME
        Domain = $env:USERDOMAIN
        OSVersion = [System.Environment]::OSVersion.Version
        ProcessorCount = [System.Environment]::ProcessorCount
        SystemDirectory = [System.Environment]::SystemDirectory
        IP = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -notlike '127.*' }).IPAddress
    }
    return $systemInfo
}

# Function to get process details
Function Get-ProcessDetails($processId) {
    try {
        $process = Get-Process -Id $processId -ErrorAction Stop
        return @{
            Name = $process.ProcessName
            ID = $process.Id
            StartTime = $process.StartTime
            CPU = $process.CPU
            Memory = [math]::Round($process.WorkingSet64 / 1MB, 2)
            Path = $process.Path
        }
    }
    catch {
        return $null
    }
}

# Enhanced logging function with detailed security information
Function Log-SecurityEvent($eventType, $path, $details) {
    $currentDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $systemDetails = Get-SystemDetails
    $processDetails = Get-ProcessDetails($PID)
    
    $securityEvent = @{
        Timestamp = $currentDate
        EventType = $eventType
        Path = $path
        Details = $details
        User = @{
            Name = $systemDetails.Username
            Domain = $systemDetails.Domain
        }
        System = @{
            ComputerName = $systemDetails.ComputerName
            IP = $systemDetails.IP
            OSVersion = $systemDetails.OSVersion
        }
        Process = @{
            Name = $processDetails.Name
            ID = $processDetails.ID
            Path = $processDetails.Path
        }
    }

    # Create detailed log entry
    $logEntry = @"
[SECURITY EVENT DETECTED]
Timestamp: $($securityEvent.Timestamp)
Event Type: $($securityEvent.EventType)
Path: $($securityEvent.Path)

Details:
$($securityEvent.Details)

User Information:
- Username: $($securityEvent.User.Name)
- Domain: $($securityEvent.User.Domain)

System Information:
- Computer Name: $($securityEvent.System.ComputerName)
- IP Address: $($securityEvent.System.IP)
- OS Version: $($securityEvent.System.OSVersion)

Process Information:
- Process Name: $($securityEvent.Process.Name)
- Process ID: $($securityEvent.Process.ID)
- Process Path: $($securityEvent.Process.Path)

$("-" * 100)
"@

    # Write to log file
    $logEntry | Out-File -FilePath "C:\ProgramData\security_events.log" -Append -Encoding utf8

    # Console output with background color and text color
    $bgColor = "Black"  # Background color (change to "DarkGray" for gray)
    switch ($eventType) {
        "FolderCreated" { $textColor = "Green" }
        "FolderDeleted" { $textColor = "Red" }
        "FileModified" { $textColor = "Magenta" }
        "FileCreated" { $textColor = "Green" }
        "FileDeleted" { $textColor = "Red" }
        "SuspiciousActivity" { $textColor = "Pink" }
        default { $textColor = "White" }
    }

    # Set background color and write the log entry
    Write-Host $logEntry -BackgroundColor $bgColor -ForegroundColor $textColor
}


# Function to calculate file hash
Function Calculate-File-Hash($filepath) {
    if (Test-Path -Path $filepath -PathType Leaf) {
        $filehash = Get-FileHash -Path $filepath -Algorithm SHA512
        return $filehash
    }
    return $null
}

# Enhanced function to compare file contents with security context
Function Compare-FileContents($filePath) {
    $contentStoragePath = "C:\ProgramData\FileContents"
    
    if (-not (Test-Path $contentStoragePath)) {
        New-Item -ItemType Directory -Path $contentStoragePath -Force | Out-Null
    }

    $safeFileName = [System.IO.Path]::GetFileName($filePath)
    $contentFile = Join-Path $contentStoragePath "$safeFileName.previous"

    try {
        $currentContent = Get-Content -Path $filePath -Raw -ErrorAction Stop

        if (Test-Path $contentFile) {
            $previousContent = Get-Content -Path $contentFile -Raw -ErrorAction Stop

            if ($previousContent -ne $currentContent) {
                $previousLines = $previousContent -split "`n"
                $currentLines = $currentContent -split "`n"
                
                $diff = Compare-Object -ReferenceObject $previousLines -DifferenceObject $currentLines
                
                $changes = "Content Changes:`n"
                foreach ($change in $diff) {
                    $indicator = if ($change.SideIndicator -eq "=>") { "+" } else { "-" }
                    $lineContent = $change.InputObject.Trim()
                    $changes += "${indicator} ${lineContent}`n"
                }

                # Check for suspicious content
                $suspiciousPatterns = @(
                    'password=',
                    'secret',
                    'token=',
                    'api_key',
                    'delete.*from',
                    'drop.*table',
                    'rm -rf',
                    'format.*drive'
                )

                foreach ($pattern in $suspiciousPatterns) {
                    if ($currentContent -match $pattern) {
                        Log-SecurityEvent "SuspiciousActivity" $filePath "Suspicious pattern detected: $pattern"
                    }
                }

                $currentContent | Out-File -FilePath $contentFile -Force
                return $changes
            }
        } else {
            $currentContent | Out-File -FilePath $contentFile -Force
            return "Initial content baseline created"
        }
    }
    catch {
        return "Error: $($_.Exception.Message)"
    }
    
    return $null
}

# Function to create a Security Hub UI
Function Security-Hub-UI {
    Clear-Host
    $systemDetails = Get-SystemDetails
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                   SECURITY MONITORING HUB v3.0                    ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "SYSTEM INFORMATION:" -ForegroundColor Yellow
    Write-Host "• Computer Name: $($systemDetails.ComputerName)" -ForegroundColor Gray
    Write-Host "• Current User: $($systemDetails.Username)" -ForegroundColor Gray
    Write-Host "• Domain: $($systemDetails.Domain)" -ForegroundColor Gray
    Write-Host "• IP Address: $($systemDetails.IP)" -ForegroundColor Gray
    Write-Host "• OS Version: $($systemDetails.OSVersion)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "MONITORING STATUS:" -ForegroundColor Yellow
    Write-Host "• Service Status: Active" -ForegroundColor Green
    Write-Host "• Monitoring Mode: Real-Time" -ForegroundColor Green
    Write-Host "• Log Location: C:\ProgramData\security_events.log" -ForegroundColor Gray
    Write-Host ""
}

# Function to display the menu
Function Show-Menu {
    Write-Host "AVAILABLE OPERATIONS:" -ForegroundColor Yellow
    Write-Host "    1) Initialize Security Baseline" -ForegroundColor Cyan
    Write-Host "    2) Start Security Monitoring" -ForegroundColor Cyan
    Write-Host "    3) View Security Events" -ForegroundColor Cyan
    Write-Host "    4) Exit Security Hub" -ForegroundColor Cyan
    Write-Host ""
}

# Initialize monitoring
$script:fileHashDictionary = @{}
$script:folderDictionary = @{}

# Get the monitoring path
$monitorPath = Read-Host -Prompt "Enter path to monitor (e.g., C:\Path\To\Monitor)"

if (-not (Test-Path -Path $monitorPath)) {
    Write-Host "Path does not exist. Creating directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $monitorPath -Force
}

Security-Hub-UI
Show-Menu

do {
    $choice = Read-Host -Prompt "Select operation (1-4)"

    switch ($choice) {
        "1" {
            Write-Host "Initializing security baseline..." -ForegroundColor Yellow
            
            # Initialize file baseline
            Get-ChildItem -Path $monitorPath -File -Recurse | ForEach-Object {
                $hash = Calculate-File-Hash $_.FullName
                if ($hash) {
                    $script:fileHashDictionary[$_.FullName] = $hash.Hash
                    Compare-FileContents $_.FullName
                }
            }

            # Initialize folder baseline
            Get-ChildItem -Path $monitorPath -Directory -Recurse | ForEach-Object {
                $script:folderDictionary[$_.FullName] = $_.CreationTime
            }

            Write-Host "Security baseline created successfully!" -ForegroundColor Green
            Show-Menu
        }
        "2" {
            if ($script:fileHashDictionary.Count -eq 0) {
                Write-Host "Please initialize security baseline first." -ForegroundColor Red
                continue
            }

            Write-Host "Starting security monitoring..." -ForegroundColor Green
            Write-Host "Press Ctrl+C to stop monitoring." -ForegroundColor Yellow

            while ($true) {
                Start-Sleep -Milliseconds 500
                
                # Monitor files
                Get-ChildItem -Path $monitorPath -File -Recurse | ForEach-Object {
                    $hash = Calculate-File-Hash $_.FullName
                    if ($hash) {
                        if ($script:fileHashDictionary.ContainsKey($_.FullName)) {
                            if ($script:fileHashDictionary[$_.FullName] -ne $hash.Hash) {
                                $changes = Compare-FileContents $_.FullName
                                if ($changes) {
                                    Log-SecurityEvent "FileModified" $_.FullName $changes
                                }
                                $script:fileHashDictionary[$_.FullName] = $hash.Hash
                            }
                        } else {
                            Log-SecurityEvent "FileCreated" $_.FullName "New file detected"
                            $script:fileHashDictionary[$_.FullName] = $hash.Hash
                            Compare-FileContents $_.FullName
                        }
                    }
                }

                # Monitor folders
                Get-ChildItem -Path $monitorPath -Directory -Recurse | ForEach-Object {
                    if (-not $script:folderDictionary.ContainsKey($_.FullName)) {
                        Log-SecurityEvent "FolderCreated" $_.FullName "New folder detected"
                        $script:folderDictionary[$_.FullName] = $_.CreationTime
                    }
                }

                # Check for deleted folders
                $deletedFolders = @($script:folderDictionary.Keys | Where-Object { -not (Test-Path $_) })
                foreach ($deletedFolder in $deletedFolders) {
                    Log-SecurityEvent "FolderDeleted" $deletedFolder "Folder was deleted"
                    $script:folderDictionary.Remove($deletedFolder)
                }

                # Check for deleted files
                $deletedFiles = @($script:fileHashDictionary.Keys | Where-Object { -not (Test-Path $_) })
                foreach ($deletedFile in $deletedFiles) {
                    Log-SecurityEvent "FileDeleted" $deletedFile "File was deleted"
                    $script:fileHashDictionary.Remove($deletedFile)
                }
            }
        }
        "3" {
            if (Test-Path "C:\ProgramData\security_events.log") {
                Write-Host "`nRecent Security Events:" -ForegroundColor Cyan
                Get-Content "C:\ProgramData\security_events.log" -Tail 30
            } else {
                Write-Host "No security events logged yet." -ForegroundColor Yellow
            }
            Show-Menu
        }
        "4" {
            Write-Host "Exiting Security Hub..." -ForegroundColor Green
            return
        }
        default {
            Write-Host "Invalid option. Please select 1-4." -ForegroundColor Red
            Show-Menu
        }
    }
} while ($choice -ne "4")