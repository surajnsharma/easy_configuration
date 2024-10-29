document.addEventListener('DOMContentLoaded', function () {
    const pathsModal = document.getElementById('pathsModal');
    const pathsContainer = document.getElementById('paths-container');
    const gnmiPathsInput = document.getElementById('gnmi_paths');
    const savePathsBtn = document.getElementById('savePathsBtn');
    const managePathsBtn = document.querySelector('[data-target="#pathsModal"]'); // Button that opens the modal

    // Load device options
    $.ajax({
        url: '/api/devices',
        method: 'GET',
        success: function (data) {
            const deviceSelect = $('#deviceSelect');
            deviceSelect.empty();

            // Add "All Devices" option
            const allDevicesOption = $('<option></option>')
                .attr('value', 'all')
                .attr('selected', 'selected') // Default option
                .text('All Devices');
            deviceSelect.append(allDevicesOption);

            // Append the devices fetched from the API
            data.forEach(function (device) {
                const option = $('<option></option>')
                    .attr('value', device.ip)
                    .text(device.hostname);
                deviceSelect.append(option);
            });
        },
        error: function (xhr, status, error) {
            console.error('Failed to fetch devices:', error);
        }
    });

    // Fetch GNMI servers and populate dropdown
    fetch('/get_gpu_systems')
        .then(response => response.json())
        .then(data => {
            const gnmiServerSelect = document.getElementById('gnmiServerSelect');
            if (data.status === 'success') {
                data.gpu_systems.forEach(system => {
                    const option = document.createElement('option');
                    option.value = system.node_ip;
                    option.text = `${system.node_ip} (${system.color})`;
                    gnmiServerSelect.appendChild(option);
                });
            } else {
                gnmiServerSelect.innerHTML = '<option value="">Failed to load GNMI servers</option>';
            }
        })
        .catch(error => {
            const gnmiServerSelect = document.getElementById('gnmiServerSelect');
            gnmiServerSelect.innerHTML = '<option value="">Error loading GNMI servers</option>';
        });

    const gnmiForm = document.querySelector('#deviceTelemetryForm');
    const startStreamBtn = document.querySelector('#startStreamBtn');
    const stopStreamBtn = document.querySelector('#stopStreamBtn');
    const viewLogLinkContainer = document.querySelector('#viewLogLinkContainer');
    const downloadLinkContainer = document.querySelector('#downloadLinkContainer');
    const subscribeBtn = document.querySelector('#subscribeBtn');

    // Show/Hide Start/Stop buttons
    function showStopButton() {
        if (startStreamBtn) startStreamBtn.style.display = 'none';
        if (stopStreamBtn) stopStreamBtn.style.display = 'inline-block';
    }

    function showStartButton() {
        if (stopStreamBtn) stopStreamBtn.style.display = 'none';
        if (startStreamBtn) startStreamBtn.style.display = 'inline-block';
    }

    // Reset log container
    function resetViewLogLinkContainer() {
        viewLogLinkContainer.innerHTML = ''; // Clear view log container
    }

    // Reset download container
    function resetDownloadLinkContainer() {
        downloadLinkContainer.innerHTML = ''; // Clear download link container
    }

    // Subscribe button event
    if (subscribeBtn) {
        subscribeBtn.addEventListener('click', function (event) {
            event.preventDefault(); // Prevent form submission
            resetDownloadLinkContainer();

            // Submit form via fetch
            fetch('/gnmi_subscription', {
                method: 'POST',
                body: new FormData(gnmiForm)
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success' && data.download_link) {
                    const downloadLink = document.createElement('a');
                    downloadLink.href = data.download_link;
                    downloadLink.textContent = 'Download GNMI Config';
                    downloadLink.style.color = 'green';
                    downloadLink.style.textDecoration = 'underline';
                    downloadLink.setAttribute('download', 'gnmi-config.yaml');
                    downloadLinkContainer.appendChild(downloadLink);
                }
            })
            .catch(error => console.error('Error during subscription:', error));
        });
    }

    // Start telemetry stream
    if (startStreamBtn) {
        startStreamBtn.addEventListener('click', function () {
            const formData = new FormData(gnmiForm);
            resetViewLogLinkContainer();
            fetch('/start_telemetry_stream', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    alert('Telemetry stream started successfully!');
                    showStopButton();
                    const viewLogLink = document.createElement('a');
                    viewLogLink.href = '/view_telemetry_log';
                    viewLogLink.textContent = 'View Debug Log';
                    viewLogLink.style.color = 'green';
                    viewLogLink.style.textDecoration = 'underline';
                    viewLogLink.target = '_blank'; // Open in new tab
                    viewLogLinkContainer.appendChild(viewLogLink);
                } else {
                    alert('Failed to start telemetry stream: ' + data.message);
                }
            })
            .catch(error => console.error('Error starting telemetry stream:', error));
        });
    }

    // Stop telemetry stream
    if (stopStreamBtn) {
        stopStreamBtn.addEventListener('click', function () {
            fetch('/stop_telemetry_stream', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    showStartButton();
                    alert('Telemetry stream stopped successfully!');
                } else {
                    alert('Failed to stop telemetry stream: ' + data.message);
                }
            })
            .catch(error => console.error('Error stopping telemetry stream:', error));
        });
    }

    // Check telemetry stream status on load
    fetch('/check_telemetry_status')
        .then(response => response.json())
        .then(data => {
            if (data.status === "running") {
                showStopButton();
            } else {
                showStartButton();
            }
        })
        .catch(error => console.error('Error checking telemetry status:', error));

    // Check for existing GNMI config and log files
    fetch('/check_files_exist')
        .then(response => response.json())
        .then(data => {
            if (data.gnmi_config_exists && data.gnmi_config_path) {
                const downloadLink = document.createElement('a');
                downloadLink.href = data.gnmi_config_path;
                downloadLink.textContent = 'Download GNMI Config';
                downloadLink.style.color = 'green';
                downloadLink.style.textDecoration = 'underline';
                downloadLink.setAttribute('download', 'gnmi-config.yaml');
                downloadLinkContainer.appendChild(downloadLink);
            }

            if (data.telemetry_log_exists && data.telemetry_log_path) {
                const viewLogLink = document.createElement('a');
                viewLogLink.href = data.telemetry_log_path;
                viewLogLink.textContent = 'View Debug Log';
                viewLogLink.style.color = 'green';
                viewLogLink.style.textDecoration = 'underline';
                viewLogLinkContainer.appendChild(viewLogLink);
            }
        })
        .catch(error => console.error('Error checking file existence:', error));

    // Query button to open interface counters
    const queryBtn = document.getElementById('queryBtn');
    if (queryBtn) {
        queryBtn.addEventListener('click', function () {
            window.open('/interface_counters', '_blank');
        });
    }

    // Function to load existing GNMI paths into the modal and the input field
    function loadExistingPaths() {
        fetch('/get_gnmi_paths')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    const paths = data.paths;

                    // Update the gnmi_paths input field with a comma-separated list of paths
                    gnmiPathsInput.value = paths.join(',');

                    // Clear the pathsContainer before adding paths
                    pathsContainer.innerHTML = '';

                    // Populate paths in the modal
                    paths.forEach((path, index) => {
                        const pathDiv = document.createElement('div');
                        pathDiv.className = 'path-container mb-2';
                        pathDiv.innerHTML = `
                            <input type="text" class="form-control mb-2" value="${path}">
                            <button type="button" class="btn btn-danger" onclick="removePath(this)">Remove</button>
                        `;
                        pathsContainer.appendChild(pathDiv);
                    });
                } else {
                    console.error('Failed to load GNMI paths:', data.message);
                }
            })
            .catch(error => console.error('Error fetching GNMI paths:', error));
    }


        loadExistingPaths();


    // Add a new empty path field
    document.getElementById('add-path-button').addEventListener('click', function () {
        const newPathContainer = document.createElement('div');
        newPathContainer.className = 'path-container';
        newPathContainer.innerHTML = `
            <input type="text" placeholder="/another/path" class="form-control mb-2">
            <button type="button" class="btn btn-danger" onclick="removePath(this)">Remove</button>
        `;
        pathsContainer.appendChild(newPathContainer);
    });

    // Save the paths and close the modal
    savePathsBtn.addEventListener('click', function () {
        const inputs = document.querySelectorAll('#paths-container input');
        const paths = Array.from(inputs).map(input => input.value.trim()).filter(value => value);
        gnmiPathsInput.value = paths.join(','); // Update the gnmi_paths input field
        $('#pathsModal').modal('hide'); // Close the modal
    });

});

// Function to remove a path
function removePath(button) {
    button.parentElement.remove();
}
