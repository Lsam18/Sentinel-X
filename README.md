# RDP Monitoring Tool - GUIDE

## Part 1: Pre-requisites Installation Script
This script installs all pre-requisites necessary to run the RDP monitoring tool. Save this script as `install-prerequisites.ps1`.

### Script Details
- **Ensure Administrative Privileges**: The script checks if it is being run with administrative privileges.
- **Create Necessary Directories**: The script creates the following directories if they do not exist:
  - `C:\ProgramData\RDPLogs`
  - `C:\ProgramData\BlockedIPs`

#### Example Usage
Run the script with administrative privileges:
```powershell
powershell.exe -ExecutionPolicy Bypass -File "install-prerequisites.ps1"
```

### Script Code
```powershell
# Ensure the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as an administrator." -ForegroundColor Red
    exit
}

Write-Host "[INSTALLATION STARTED] Installing pre-requisites..." -ForegroundColor Green

# Check if the necessary directories exist, if not, create them
$directories = @("C:\ProgramData\RDPLogs", "C:\ProgramData\BlockedIPs")
foreach ($directory in $directories) {
    if (-not (Test-Path $directory)) {
        Write-Host "Creating directory: $directory" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

Write-Host "[INSTALLATION COMPLETE] Pre-requisites installed successfully." -ForegroundColor Green
```

---

## Part 2: Configuration Script
Save this script as `configure-rdp-monitor.ps1`.

### Script Details
- **Log File and Blocked IPs File**: This script sets up configuration settings, such as creating the log file and blocked IPs file.
- **Files Created**:
  - `C:\ProgramData\RDPLogs\failed_rdp.log`
  - `C:\ProgramData\BlockedIPs\blocked_ips.txt`

#### Example Usage
Run the script with administrative privileges:
```powershell
powershell.exe -ExecutionPolicy Bypass -File "configure-rdp-monitor.ps1"
```

### Script Code
```powershell
Write-Host "[CONFIGURATION STARTED] Configuring the RDP Monitoring Tool..." -ForegroundColor Green

# Set up configuration settings, such as creating the log file and blocked IPs file
$logfile = "C:\ProgramData\RDPLogs\failed_rdp.log"
$blockedIpsFile = "C:\ProgramData\BlockedIPs\blocked_ips.txt"

if (-not (Test-Path $logfile)) {
    Write-Host "Creating log file at $logfile" -ForegroundColor Yellow
    New-Item -ItemType File -Path $logfile -Force | Out-Null
    Write-Host "Sample log data will be written to the log file for training purposes." -ForegroundColor Cyan
}

if (-not (Test-Path $blockedIpsFile)) {
    Write-Host "Creating blocked IPs file at $blockedIpsFile" -ForegroundColor Yellow
    New-Item -ItemType File -Path $blockedIpsFile -Force | Out-Null
}

Write-Host "[CONFIGURATION COMPLETE] Configuration completed successfully." -ForegroundColor Green
```

---

## Part 3: Main Execution Script
Save this script as `start-rdp-monitor.ps1`.

### Script Details
- **Ensure Administrative Privileges**: This script also checks if it is being run with administrative privileges.
- **Run the Monitoring Script**: The script starts the RDP monitoring tool.

#### Example Usage
Run the script with administrative privileges:
```powershell
powershell.exe -ExecutionPolicy Bypass -File "start-rdp-monitor.ps1"
```

### Script Code
```powershell
# Ensure this script is running as administrator to have necessary permissions
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as an administrator." -ForegroundColor Red
    exit
}

Write-Host "[RDP MONITOR TOOL] Starting RDP Monitoring..." -ForegroundColor Green

# Define the path of the RDP monitoring script
$monitoringScriptPath = "C:\Path\To\rdp-monitor-script.ps1"

# Check if the monitoring script is available
if (-not (Test-Path $monitoringScriptPath)) {
    Write-Host "Monitoring script not found. Please ensure the script is in the correct path: $monitoringScriptPath" -ForegroundColor Red
    exit
}

# Run the monitoring script
Write-Host "[RDP MONITOR TOOL] Executing monitoring script..." -ForegroundColor Green
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$monitoringScriptPath`"" -NoNewWindow

Write-Host "[RDP MONITOR TOOL] Monitoring started successfully." -ForegroundColor Green
```

---

## Part 4: Running the Tool

### Steps to Run the RDP Monitoring Tool

1. **Install Pre-requisites**: Run the pre-requisites script with administrator privileges.
   ```
   powershell.exe -ExecutionPolicy Bypass -File "install-prerequisites.ps1"
   ```

2. **Configuration**: Set up all required configurations by running the configuration script.
   ```
   powershell.exe -ExecutionPolicy Bypass -File "configure-rdp-monitor.ps1"
   ```

3. **Start the Monitoring Tool**: Start the monitoring by running the main execution script.
   ```
   powershell.exe -ExecutionPolicy Bypass -File "start-rdp-monitor.ps1"
   ```

### Important Notes
- Always run these scripts with administrative privileges to ensure access to Windows Event Logs and firewall rules.
- Make sure to change the path of the monitoring script to its actual location in the main execution script.

### Stopping the Tool
To stop the monitoring tool, simply close the PowerShell window running the monitoring script.
