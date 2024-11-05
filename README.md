# Next-Gen SIEM Tool: Azure Sentinel Integration for PowerShell-Based RDP and Web-Based FIM
## PART 1 - FILE INTEGRITY MONITORING TOOL - WITH LOG TRANSFER TO AZURE SENTINEL - GRAFANA DASHBOARDS
# Security Monitoring Dashboard - README

## Overview

The **Security Monitoring Dashboard** is a real-time, web-based monitoring tool designed to track and analyze various security-related events on your system. It integrates **Node.js** on the backend, **Socket.IO** for real-time communication, and **Chart.js** for visual representation of event data. This monitoring system provides a stunning UI for monitoring file changes, viewing system information, and controlling monitoring tasks, all in one cohesive interface.

The dashboard is ideal for keeping track of file system changes, visualizing different types of events, and maintaining a record of all critical activities for enhanced security and transparency.

### Key Features:
- **Real-Time Monitoring**: Displays ongoing file system changes instantly.
- **Stunning UI**: Uses Tailwind CSS for a visually appealing dashboard.
- **Advanced Event Logging**: Logs all actions in detail, including user and system information.
- **Control Panel**: Allows easy initialization and stopping of monitoring.
- **System Information**: Provides key details about the system being monitored.

## Table of Contents
1. [Installation](#installation)
2. [Running the Application](#running-the-application)
3. [Configuration](#configuration)
4. [Usage](#usage)
5. [Components](#components)
6. [API Endpoints](#api-endpoints)
7. [Technology Stack](#technology-stack)
8. [Acknowledgements](#acknowledgements)

## Installation

To run the Security Monitoring Dashboard locally, follow these steps:

### Prerequisites
- **Node.js** and **npm**: Ensure Node.js and npm are installed on your system. You can download them from [nodejs.org](https://nodejs.org/).

### Steps
1. **Clone the repository**:
   ```sh
   git clone https://github.com/your-username/Security-Monitoring-Dashboard.git
   cd Security-Monitoring-Dashboard
   ```

2. **Install dependencies**:
   ```sh
   npm install
   ```

3. **Install additional dependencies for monitoring**:
   - **Chokidar**: For monitoring file changes.
   - **Socket.IO**: For real-time communication between the server and client.
   - **Chart.js**: For displaying visual charts.
   ```sh
   npm install chokidar socket.io chart.js diff
   ```

## Running the Application

Once all the dependencies are installed, you can run the application using the following command:

```sh
npm start
```

The application will run on `http://localhost:3000`. Open your web browser and visit this address to access the dashboard.

## Configuration

Before starting the monitoring process, ensure you provide the correct configuration details for the system:

1. **Port Configuration**: The default port is set to `3000`. You can modify the `PORT` constant in the `server.js` file if required.
2. **Log File Path**: Make sure to specify the correct path for the log files.

## Usage

### Accessing the Dashboard
- Navigate to `http://localhost:3000` to access the dashboard.

### Main Features:
1. **System Information Panel**: Displays system-specific information such as computer name, domain, IP address, and OS version.
2. **Control Panel**: Initialize monitoring by entering the file path to be monitored and the desired log file path.
   - **Initialize Baseline**: Click to set up the security baseline, and the system will generate initial logs.
   - **Start/Stop Monitoring**: Use this button to start or stop monitoring activities.
3. **File System Changes**: Displays logs of changes in real-time, with detailed event types, timestamps, and affected files.
4. **Event Statistics**: A visual representation of the statistics for different event types (file created, modified, deleted, etc.) using a doughnut chart.
5. **Security Events Log**: Displays a detailed record of detected security events.

### Event Types & Color Coding
- **FileModified**: Displayed in a blue color with changes highlighted.
- **FileCreated**: Displayed in a green color.
- **FileDeleted/FolderDeleted**: Displayed in red.
- **FolderCreated**: Displayed in orange.

## Components

### **Frontend**
- **HTML/CSS**: Utilizes **Tailwind CSS** for styling and **Chart.js** for chart representation.
- **JavaScript**: Implements client-side logic for event handling, monitoring toggles, and system information updates.

### **Backend**
- **Express.js**: Serves the static files and handles the APIs required for initializing the baseline, starting/stopping monitoring, and fetching system information.
- **Chokidar**: Monitors the specified paths for changes.
- **Socket.IO**: Enables real-time updates on file events between the server and connected clients.
- **Diff Module**: Provides enhanced logging for file modifications, including line-by-line changes.

## API Endpoints

The application provides several RESTful API endpoints to interact with the monitoring process:

1. **GET /api/system-info**: Returns system information such as computer name, username, domain, IP address, and OS version.
2. **POST /api/initialize-baseline**: Initializes monitoring by specifying the path to monitor and log file path. Logs the initialization details.
3. **POST /api/start-monitoring**: Starts monitoring for the specified file path and begins logging events.
4. **POST /api/stop-monitoring**: Stops the monitoring process.

## Technology Stack

- **Backend**: Node.js, Express.js
- **Frontend**: HTML, CSS (Tailwind), JavaScript, Chart.js
- **Real-Time Communication**: Socket.IO
- **File Monitoring**: Chokidar

## Enhancements

The **Security Monitoring Dashboard** aims to provide real-time information and event tracking in a simple yet powerful interface. Future enhancements may include:
- **User Authentication**: Secure the dashboard with login and admin privileges.
- **Multiple System Support**: Expand monitoring to support multiple systems from one dashboard.
- **Customizable Alert Mechanisms**: Send alerts based on specific rules (e.g., email, SMS notifications).

## Acknowledgements

- **Tailwind CSS**: For the elegant and responsive UI components.
- **Chart.js**: For the charts used to display event statistics.
- **Chokidar**: For providing efficient file system monitoring.
- **Socket.IO**: For real-time client-server communication.

Feel free to open issues or submit pull requests for improvements and bug fixes. Thank you for using the **Security Monitoring Dashboard**!


# PART 2 - REMOTE DESKTOP PROTOCOL FAILIURE CAPTURING TOOL - WITH LOG TRANSFER TO AZURE SENTINEL - GRAFANA DASHBOARDS

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
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
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
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
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
Save this script as `rdp-sentinelx.ps1`.

### Script Details
- **Ensure Administrative Privileges**: This script also checks if it is being run with administrative privileges.
- **Run the Monitoring Script**: The script starts the RDP monitoring tool.

#### Example Usage
Run the script with administrative privileges:
```powershell
./rdp-sentinelx.ps1
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

1. **Set Admin Priveliges**: Run the pre-requisites script with administrator privileges.
   ```
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

2. **Start the Monitoring Tool**: Start the monitoring by running the main execution script.
   ```
   ./rdp-sentinelx.ps1
   ```

### Important Notes
- Always run these scripts with administrative privileges to ensure access to Windows Event Logs and firewall rules.
- Make sure to change the path of the monitoring script to its actual location in the main execution script.

### Stopping the Tool
To stop the monitoring tool, simply close the PowerShell window running the monitoring script.
