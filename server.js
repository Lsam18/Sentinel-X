const express = require('express');
const path = require('path');
const os = require('os');
const { exec } = require('child_process');
const chokidar = require('chokidar');
const { Server } = require('socket.io');
const http = require('http');
const fs = require('fs');
const diff = require('diff');
const session = require('express-session');

const app = express();
const PORT = 3000;

// In-memory user store (In production, use a proper database)
const users = [];

// Register Route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    // Store the new user (no hashing now)
    users.push({ username, password });

    res.status(201).send('User registered successfully');
});

// Keep track of the log file path to ignore it in the watcher
let currentLogPath = null;

// Store previous file contents for diff comparison
const fileContents = new Map();

// Store active watchers for each monitored path
const activeWatchers = new Map();

// Store the monitoring configuration
let monitoringConfig = {
    paths: [],
    logFilePath: null,
    active: false
};

// Function to ensure log directory exists
function ensureLogDirectory(logFilePath) {
    const logDir = path.dirname(logFilePath);
    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
        console.log(`Created log directory: ${logDir}`);
    }
}

// Enhanced function to get file differences
function getFileDiff(filePath) {
    try {
        const currentContent = fs.readFileSync(filePath, 'utf8');
        const previousContent = fileContents.get(filePath);

        if (previousContent) {
            const differences = diff.diffLines(previousContent, currentContent);
            let formattedDiff = '';

            differences.forEach(part => {
                if (part.added) {
                    formattedDiff += `\n+ ${part.value.trim()}`;
                }
                if (part.removed) {
                    formattedDiff += `\n- ${part.value.trim()}`;
                }
            });

            // Store current content for next comparison
            fileContents.set(filePath, currentContent);

            if (formattedDiff.length > 0) {
                return `Content Changes:\n${formattedDiff}`;
            }
            return 'File modified but no content changes detected';
        } else {
            // First time seeing this file
            fileContents.set(filePath, currentContent);
            return `Modified content Detected: "${currentContent.trim()}"`;
        }
    } catch (err) {
        console.error(`Error getting file diff: ${err.message}`);
        return 'Unable to read file content';
    }
}

// Enhanced function to get file information
function getFileInfo(filePath) {
    try {
        const stats = fs.statSync(filePath);
        return {
            size: stats.size,
            created: stats.birthtime.toISOString(),
            modified: stats.mtime.toISOString(),
            type: path.extname(filePath) || 'No extension'
        };
    } catch (err) {
        console.error(`Error getting file info: ${err.message}`);
        return null;
    }
}

// Function to get system information
function getSystemInformation() {
    return {
        computerName: os.hostname(),
        username: os.userInfo().username,
        domain: os.hostname(),
        ipAddress: getLocalIPAddress(),
        osVersion: os.version() || os.release()
    };
}

// Function to handle file events with enhanced logging
function logFileEvent(eventType, filePath, details, logFilePath, monitoredPath, changes = '') {
    if (filePath === currentLogPath) {
        return;
    }

    const fileInfo = getFileInfo(filePath);
    const systemInfo = getSystemInformation();

    const entry = {
        type: eventType,
        path: filePath,
        monitoredPath: monitoredPath,
        details,
        changes,
        fileInfo,
        user: {
            name: systemInfo.username,
            domain: systemInfo.domain,
        },
        system: {
            computerName: systemInfo.computerName,
            ipAddress: systemInfo.ipAddress,
            osVersion: systemInfo.osVersion,
        },
        process: {
            name: process.title,
            id: process.pid,
            path: process.execPath,
        }
    };

    writeToLogFile(logFilePath, entry);

    const uiEvent = {
        ...entry,
        timestamp: new Date().toISOString(),
        formattedChanges: changes
    };

    io.emit('file-event', uiEvent);
}

// Function to write to log file with error handling
function writeToLogFile(logFilePath, entry) {
    const logEntry = `
--------------------------------------------------------------------------------
[EVENT: ${entry.type}]
Time: ${new Date().toLocaleString()}
File Path: ${entry.path}
Monitored Path: ${entry.monitoredPath || 'N/A'}
Details: ${entry.details}

Changes:
${entry.changes}

File Information:
${entry.fileInfo ? `Size: ${entry.fileInfo.size} bytes
Created: ${entry.fileInfo.created}
Last Modified: ${entry.fileInfo.modified}
File Type: ${entry.fileInfo.type}` : 'N/A'}

System Information:
Computer Name: ${entry.system.computerName}
Username: ${entry.user.name}
Domain: ${entry.user.domain}
IP Address: ${entry.system.ipAddress}
OS Version: ${entry.system.osVersion}

Process Information:
Process Name: ${entry.process.name}
Process ID: ${entry.process.id}
Process Path: ${entry.process.path}
--------------------------------------------------------------------------------
`;

    try {
        ensureLogDirectory(logFilePath);
        fs.appendFileSync(logFilePath, logEntry, 'utf8');
        console.log(`Log entry written successfully to ${logFilePath}`);
    } catch (err) {
        console.error(`Failed to write to log file: ${err.message}`);
    }
}

// Initialize HTTP server and Socket.io
const httpServer = http.createServer(app);
const io = new Server(httpServer);

io.on('connection', (socket) => {
    console.log('A user connected');
    
    // Send current monitoring config to the new client
    socket.emit('monitoring-config', monitoringConfig);
});

// Add system info endpoint
app.get('/api/system-info', (req, res) => {
    const systemInfo = getSystemInformation();
    res.json({
        ComputerName: systemInfo.computerName,
        Username: systemInfo.username,
        Domain: systemInfo.domain,
        IP: systemInfo.ipAddress,
        OSVersion: systemInfo.osVersion,
    });
});

// Get the current monitoring configuration
app.get('/api/monitoring-config', (req, res) => {
    res.json(monitoringConfig);
});

// Initialize baseline endpoint
app.post('/api/initialize-baseline', express.json(), (req, res) => {
    const { paths, logFilePath } = req.body;

    if (!paths || !paths.length || !logFilePath) {
        return res.status(400).send('Both monitoring paths and log file path are required');
    }

    try {
        // Stop any existing watchers
        stopAllWatchers();
        
        currentLogPath = logFilePath;
        ensureLogDirectory(logFilePath);

        if (!fs.existsSync(logFilePath)) {
            fs.writeFileSync(logFilePath, '--- Security Monitoring Log ---\n\n', 'utf8');
            console.log(`Log file created at: ${logFilePath}`);
        }

        // Update monitoring configuration
        monitoringConfig = {
            paths: paths,
            logFilePath: logFilePath,
            active: false
        };

        // Log initialization for each path
        paths.forEach(pathToMonitor => {
            const initEntry = {
                type: 'SystemInitialized',
                path: pathToMonitor,
                monitoredPath: pathToMonitor,
                details: 'Security baseline initialized',
                user: getSystemInformation(),
                system: getSystemInformation(),
                process: {
                    name: process.title,
                    id: process.pid,
                    path: process.execPath,
                }
            };

            writeToLogFile(logFilePath, initEntry);
        });

        // Broadcast the updated configuration
        io.emit('monitoring-config', monitoringConfig);
        
        res.send('Baseline initialized successfully');
    } catch (err) {
        console.error('Failed to initialize baseline:', err);
        res.status(500).send(`Failed to initialize baseline: ${err.message}`);
    }
});

// Start monitoring endpoint
app.post('/api/start-monitoring', express.json(), (req, res) => {
    const { paths, logFilePath } = req.body;

    if (!paths || !paths.length || !logFilePath) {
        return res.status(400).send('Both monitoring paths and log file path are required');
    }

    try {
        currentLogPath = logFilePath;
        
        // Stop any existing watchers first
        stopAllWatchers();

        // Create watchers for each path
        paths.forEach(pathToMonitor => {
            const watcher = chokidar.watch(pathToMonitor, {
                ignored: [/(^|[\/\\])\../, filePath => filePath === currentLogPath],
                persistent: true,
                ignoreInitial: true
            });

            watcher
                .on('add', (filePath) => logFileEvent('FileCreated', filePath, 'New file created', logFilePath, pathToMonitor))
                .on('change', (filePath) => {
                    const diffResult = getFileDiff(filePath);
                    logFileEvent('FileModified', filePath, 'File content changed', logFilePath, pathToMonitor, diffResult);
                })
                .on('unlink', (filePath) => logFileEvent('FileDeleted', filePath, 'File deleted', logFilePath, pathToMonitor))
                .on('addDir', (dirPath) => logFileEvent('FolderCreated', dirPath, 'New folder created', logFilePath, pathToMonitor))
                .on('unlinkDir', (dirPath) => logFileEvent('FolderDeleted', dirPath, 'Folder deleted', logFilePath, pathToMonitor));

            // Store the watcher with the path as the key
            activeWatchers.set(pathToMonitor, watcher);
        });

        // Update monitoring configuration
        monitoringConfig = {
            paths: paths,
            logFilePath: logFilePath,
            active: true
        };

        // Log start monitoring for each path
        paths.forEach(pathToMonitor => {
            const startEntry = {
                type: 'MonitoringStarted',
                path: pathToMonitor,
                monitoredPath: pathToMonitor,
                details: 'File system monitoring initiated',
                user: getSystemInformation(),
                system: getSystemInformation(),
                process: {
                    name: process.title,
                    id: process.pid,
                    path: process.execPath,
                }
            };

            writeToLogFile(logFilePath, startEntry);
        });

        // Broadcast the updated configuration
        io.emit('monitoring-config', monitoringConfig);

        res.send('Monitoring started successfully');
    } catch (err) {
        console.error('Failed to start monitoring:', err);
        res.status(500).send(`Failed to start monitoring: ${err.message}`);
    }
});

// Stop monitoring endpoint
app.post('/api/stop-monitoring', express.json(), (req, res) => {
    try {
        stopAllWatchers();
        
        // Update monitoring configuration
        monitoringConfig.active = false;
        
        // Broadcast the updated configuration
        io.emit('monitoring-config', monitoringConfig);
        
        if (monitoringConfig.logFilePath) {
            const stopEntry = {
                type: 'MonitoringPaused',
                path: 'All paths',
                details: 'File system monitoring paused',
                user: getSystemInformation(),
                system: getSystemInformation(),
                process: {
                    name: process.title,
                    id: process.pid,
                    path: process.execPath,
                }
            };

            writeToLogFile(monitoringConfig.logFilePath, stopEntry);
        }

        res.send('Monitoring stopped successfully');
    } catch (err) {
        console.error('Failed to stop monitoring:', err);
        res.status(500).send(`Failed to stop monitoring: ${err.message}`);
    }
});

// Function to stop all active watchers
function stopAllWatchers() {
    for (const [path, watcher] of activeWatchers.entries()) {
        watcher.close();
        console.log(`Closed watcher for path: ${path}`);
    }
    activeWatchers.clear();
}

// Get local IP address
function getLocalIPAddress() {
    const interfaces = os.networkInterfaces();
    for (let interfaceName in interfaces) {
        for (let iface of interfaces[interfaceName]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return '127.0.0.1';
}

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'webinterface.html'));
});

// Start server
httpServer.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});