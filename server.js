const express = require('express');
const path = require('path');
const os = require('os');
const { exec } = require('child_process');
const chokidar = require('chokidar');
const { Server } = require('socket.io');
const http = require('http');
const fs = require('fs');
const diff = require('diff');

const app = express();
const PORT = 3000;

// Keep track of the log file path to ignore it in the watcher
let currentLogPath = null;

// Store previous file contents for diff comparison
const fileContents = new Map();

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
            return `Initial content: "${currentContent.trim()}"`;
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
function logFileEvent(eventType, filePath, details, logFilePath, changes = '') {
    if (filePath === currentLogPath) {
        return;
    }

    const fileInfo = getFileInfo(filePath);
    const systemInfo = getSystemInformation();

    const entry = {
        type: eventType,
        path: filePath,
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

let watcher;

// Initialize baseline endpoint
app.post('/api/initialize-baseline', express.json(), (req, res) => {
    const { path: pathToMonitor, logFilePath } = req.body;

    if (!pathToMonitor || !logFilePath) {
        return res.status(400).send('Both monitoring path and log file path are required');
    }

    try {
        currentLogPath = logFilePath;
        ensureLogDirectory(logFilePath);

        if (!fs.existsSync(logFilePath)) {
            fs.writeFileSync(logFilePath, '--- Security Monitoring Log ---\n\n', 'utf8');
            console.log(`Log file created at: ${logFilePath}`);
        }

        const initEntry = {
            type: 'SystemInitialized',
            path: pathToMonitor,
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
        res.send('Baseline initialized successfully');
    } catch (err) {
        console.error('Failed to initialize baseline:', err);
        res.status(500).send(`Failed to initialize baseline: ${err.message}`);
    }
});

// Start monitoring endpoint
app.post('/api/start-monitoring', express.json(), (req, res) => {
    const { path: pathToMonitor, logFilePath } = req.body;

    if (!pathToMonitor || !logFilePath) {
        return res.status(400).send('Both monitoring path and log file path are required');
    }

    try {
        currentLogPath = logFilePath;

        if (watcher) {
            watcher.close();
        }

        watcher = chokidar.watch(pathToMonitor, {
            ignored: [/(^|[\/\\])\../, filePath => filePath === currentLogPath],
            persistent: true,
            ignoreInitial: true
        });

        watcher
            .on('add', (filePath) => logFileEvent('FileCreated', filePath, 'New file created', logFilePath))
            .on('change', (filePath) => {
                const diffResult = getFileDiff(filePath);
                logFileEvent('FileModified', filePath, 'File content changed', logFilePath, diffResult);
            })
            .on('unlink', (filePath) => logFileEvent('FileDeleted', filePath, 'File deleted', logFilePath))
            .on('addDir', (dirPath) => logFileEvent('FolderCreated', dirPath, 'New folder created', logFilePath))
            .on('unlinkDir', (dirPath) => logFileEvent('FolderDeleted', dirPath, 'Folder deleted', logFilePath));

        const startEntry = {
            type: 'MonitoringStarted',
            path: pathToMonitor,
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
        res.send('Monitoring started successfully');
    } catch (err) {
        console.error('Failed to start monitoring:', err);
        res.status(500).send(`Failed to start monitoring: ${err.message}`);
    }
});

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
