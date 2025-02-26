document.addEventListener('DOMContentLoaded', () => {
    fetch('/api/system-info')
        .then(response => response.json())
        .then(data => {
            document.getElementById('computerName').textContent = data.ComputerName;
            document.getElementById('username').textContent = data.Username;
            document.getElementById('domain').textContent = data.Domain;
            document.getElementById('osVersion').textContent = data.OSVersion;
        })
        .catch(error => console.error('Error fetching system info:', error));
});


async function initializeBaseline() {
    const path = document.getElementById('monitorPath').value;
    if (!path) {
        alert('Please enter a path to monitor');
        return;
    }

    try {
        const response = await fetch('/api/initialize-baseline', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ path })
        });

        if (response.ok) {
            alert('Baseline initialized successfully');
        } else {
            throw new Error('Failed to initialize baseline');
        }
    } catch (error) {
        console.error('Error initializing baseline:', error);
        alert('Failed to initialize baseline');
    }
}

// Establish a connection to the server using Socket.io
const socket = io();

// Listen for real-time file events and update the UI accordingly
socket.on('file-event', (event) => {
    const eventsContainer = document.getElementById('securityEvents');
    const eventElement = document.createElement('div');
    eventElement.className = 'event-item';

    const timestamp = new Date().toLocaleTimeString();
    eventElement.innerHTML = `
        <strong>${event.type}</strong> at ${event.path} <span class="timestamp">[${timestamp}]</span>
    `;

    eventsContainer.insertBefore(eventElement, eventsContainer.firstChild);
});

// Function to start monitoring
async function startMonitoring() {
    const path = document.getElementById('monitorPath').value;
    if (!path) {
        alert('Please enter a path to monitor');
        return;
    }

    try {
        const response = await fetch('/api/start-monitoring', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ path })
        });

        if (response.ok) {
            alert('Monitoring started successfully');
        } else {
            throw new Error('Failed to start monitoring');
        }
    } catch (error) {
        console.error('Error starting monitoring:', error);
        alert('Failed to start monitoring');
    }
}
