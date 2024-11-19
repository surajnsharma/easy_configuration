document.addEventListener('DOMContentLoaded', (event) => {
    var socket = io();

    socket.on('connect', function() {
        console.log('Connected to server');
    });

    socket.on('disconnect', function() {
        console.log('Disconnected from server');
    });

    const progressMap = new Map();

    /*const updateProgress = (ip, progress, error) => {
        const progressElement = document.getElementById(`progress_${ip}`);
        const progressTextElement = document.getElementById(`progress_text_${ip}`);
        if (progressElement) {
            progressElement.value = progress;
            progressTextElement.innerText = `${progress}%`;
            if (error) {
                progressTextElement.innerText += ` - Error: ${error}`;
            }
            progressMap.set(ip, progress);
        }
        // Check if all devices are at 100%
            if (Array.from(progressMap.values()).every(val => val === 100)) {
                document.getElementById('progressContainer').innerHTML = '';
            }
    };*/

    const updateProgress = (ip, progress, error) => {
        const progressElement = document.getElementById(`progress_${ip}`);
        const progressTextElement = document.getElementById(`progress_text_${ip}`);

        if (progressElement) {
            progressElement.value = progress;
            progressTextElement.innerText = `${progress}%`;

            if (error) {
                progressTextElement.innerText += ` - Error: ${error}`;
            }

            // If progress reaches 100%, remove it from the progress container
            if (progress === 100) {
                const progressBarContainer = progressElement.parentNode;
                progressBarContainer.remove();
            }

            progressMap.set(ip, progress);
        }
    };

    socket.on('progress', function(data) {
        updateProgress(data.ip, data.progress, data.error);
        //console.log(`Progress update for ${data.ip}: ${data.progress}%`);
    });

    /*async function uploadAndPushConfig(event) {
        event.preventDefault();
        const form = document.getElementById('uploadConfigForm');
        const formData = new FormData(form);
        const routerIps = document.getElementById('router_ips').value.split(',');
        const progressContainer = document.getElementById('progressContainer');
        progressContainer.innerHTML = '';

        routerIps.forEach(ip => {
            const progressBar = document.createElement('div');
            progressBar.innerHTML = `<strong>${ip}:</strong> <progress id="progress_${ip}" value="0" max="100"></progress> <span id="progress_text_${ip}">0%</span>`;
            progressContainer.appendChild(progressBar);
        });

        const response = await fetch('/upload_config', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            alert('Error uploading configuration');
            return;
        }

        const data = await response.json();

        if (data.success) {
            alert('Configuration uploaded successfully');
        } else {
            alert('Error uploading configuration');
            Object.keys(data.results).forEach(ip => {
                if (!data.results[ip].success) {
                    alert(`Error on ${ip}: ${data.results[ip].message}`);
                }
            });
        }

        // Finalize progress updates for all IPs
        routerIps.forEach(ip => {
            if (!progressMap.has(ip)) {
                updateProgress(ip, 100, null); // Ensure all devices show 100% after completion
            }
        });
    }*/

async function uploadAndPushConfig(event) {
        event.preventDefault();
        const form = document.getElementById('uploadConfigForm');
        const formData = new FormData(form);
        const routerIps = document.getElementById('router_ips').value.split(',');
        const progressContainer = document.getElementById('progressContainer');
        progressContainer.innerHTML = ''; // Clear previous progress bars

        routerIps.forEach(ip => {
            const progressBar = document.createElement('div');
            progressBar.innerHTML = `<strong>${ip}:</strong> <progress id="progress_${ip}" value="0" max="100"></progress> <span id="progress_text_${ip}">0%</span>`;
            progressContainer.appendChild(progressBar);
        });

        const response = await fetch('/upload_config', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            alert('Error uploading configuration');
            return;
        }

        const data = await response.json();

        if (data.success) {
            alert('Configuration uploaded successfully');
        } else {
            alert('Error uploading configuration');
            Object.keys(data.results).forEach(ip => {
                if (!data.results[ip].success) {
                    alert(`Error on ${ip}: ${data.results[ip].message}`);
                }
            });
        }
        // Finalize progress updates for all IPs
        routerIps.forEach(ip => {
            if (!progressMap.has(ip)) {
                updateProgress(ip, 100, null); // Ensure all devices show 100% after completion
            }
        });
    }

    const form = document.getElementById('uploadConfigForm');
    form.addEventListener('submit', uploadAndPushConfig);

    //------- adding textarea input text for Upload Device Config ----//
    const textarea = document.getElementById('config_textarea');
    const configText =
`#delete config#
delete interfaces
delete protocols
delete vlans
delete firewall
#add config#
set protocols lldp interface all
set policy-options policy-statement load_balance then load-balance per-packet
set routing-options forwarding-table export load_balance
#Telemetry Config#
set system services extension-service request-response grpc clear-text address 0.0.0.0
set system services extension-service request-response grpc clear-text port 8080
set system services extension-service request-response grpc skip-authentication
set system services extension-service notification allow-clients address 0.0.0.0/0

## *Input is also acceptable in text format* ##
## **Test it out with no change, just press button for push config**##
 `;
    textarea.value = configText;

    // Fetch devices from database
    fetchDevicesFromDatabase();
});

// Debounce function to limit the rate of function execution
function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

//-------------------- Upload devices from database  -------------------------//
async function fetchDevicesFromDatabase() {
    try {
        const response = await fetch('/api/devices', {
            headers: { 'Content-Type': 'application/json' }
        });
        if (!response.ok) {
            throw new Error('Failed to fetch devices from database');
        }
        const devices = await response.json();
        const ips = devices.map(device => device.hostname);
        document.getElementById('router_ips').value = ips.join(',');
    } catch (error) {
        console.error('Error fetching devices from database:', error);
    }
}
