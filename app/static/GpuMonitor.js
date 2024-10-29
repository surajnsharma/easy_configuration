document.addEventListener('DOMContentLoaded', async function() {
    const gpuMonitoringForm = document.getElementById('gpuMonitoringForm');
    const gpuOnboardingForm = document.getElementById('gpuOnboardingForm');
    const startAllEventBtn = document.getElementById('startAllEventBtn');

    if (gpuMonitoringForm && gpuOnboardingForm) {
        // Function to populate the GPU systems table
        async function populateGpuSystemsTable() {
            try {
                const response = await fetch('/get_gpu_systems');
                const result = await response.json();

                if (result.status === 'success') {
                    const gpuSystemsTableBody = document.getElementById('gpuSystemsTableBody');
                    gpuSystemsTableBody.innerHTML = ''; // Clear the table body
                    result.gpu_systems.forEach(system => {
                        const newRow = document.createElement('tr');
                        newRow.setAttribute('data-id', system.id); // Set the data-id attribute

                        // Set row color based on the system's color attribute
                        newRow.style.color = system.color || 'black';  // Default to black if color is not set

                        newRow.innerHTML = `
                            <td>${system.node_ip}</td>
                            <td>${system.user}</td>
                            <td>${system.password}</td>
                            <td>
                                <a href="#" onclick="editSystem('${system.id}', '${system.node_ip}', '${system.user}', '${system.password}')">
                                    <i class="fas fa-edit" title="Edit this system"></i>
                                </a>
                                <a href="#" onclick="deleteSystem('${system.id}')">
                                    <i class="fas fa-trash-alt text-danger" title="Delete this system"></i>
                                </a>
                                <a href="#" onclick="startSystemTelemetry('${system.id}')">
                                    <i class="fas fa-play text-success" title="Start Telemetry on this System"></i>
                                </a>
                                <span class="telemetry-icon"></span> <!-- Placeholder for the success/failure icon -->
                            </td>
                        `;
                        gpuSystemsTableBody.appendChild(newRow);
                    });
                } else {
                    console.error('Failed to load GPU systems:', result.message);
                }
            } catch (error) {
                console.error('Error:', error);
            }
        }

        populateGpuSystemsTable();

        // Toggle sections based on the selected button
        document.getElementById('toggleGpuOnboarding').addEventListener('click', function() {
            document.getElementById('gpuOnboardingSection').classList.toggle('hidden');
            document.getElementById('gpuMonitoringSection').classList.add('hidden'); // Hide monitoring section
            populateGpuSystemsTable(); // Refresh the table when toggling to onboarding section
        });

        // Function to start telemetry for all Node IPs in the table in parallel
        async function startAllSystemTelemetry() {
            if (confirm('Are you sure you want to start telemetry for all GPU systems?')) {
                const gpuSystemsTableBody = document.getElementById('gpuSystemsTableBody');
                const rows = gpuSystemsTableBody.getElementsByTagName('tr');
                const promises = [];
                const errorMessages = [];

                for (let row of rows) {
                    const systemId = row.getAttribute('data-id');
                    if (systemId) {
                        // Add each startSystemTelemetry promise to the array
                        promises.push(
                            startSystemTelemetry(systemId)
                            .then(result => {
                                if (result.status !== 'success') {
                                    const errorMessage = `Telemetry failed for system ID ${systemId}: ${result.message}`;
                                    //console.error(errorMessage);
                                    errorMessages.push(errorMessage);
                                }
                                return result;
                            })
                            .catch(error => {
                                const errorMessage = `Telemetry failed for system ID ${systemId}: ${error.message}`;
                                //console.error(errorMessage);
                                errorMessages.push(errorMessage);
                                return { status: 'error', systemId, message: error.message };
                            })
                        );
                    }
                }

                // Execute all promises in parallel
                try {
                    const results = await Promise.all(promises);
                    if (errorMessages.length > 0) {
                        alert(`Telemetry failed for the following systems:\n${errorMessages.join('\n')}`);
                    } else {
                        alert('Telemetry started successfully for all systems.');
                    }
                } catch (error) {
                    //console.error('Error occurred while starting telemetry:', error);
                    alert('An error occurred while starting telemetry for one or more systems.');
                }
            }
        }


// Ensure startSystemTelemetry is accessible globally
        window.startSystemTelemetry = async function(systemId) {
            try {
                const response = await fetch(`/startAllSystemTelemetry/${systemId}`, {
                    method: 'POST'
                });
                const result = await response.json();

                const telemetryIcon = document.querySelector(`tr[data-id='${systemId}'] .telemetry-icon`);

                if (result.status === 'success') {
                    telemetryIcon.innerHTML = `<i class="fas fa-check-circle text-success" title="Telemetry started successfully"></i>`;
                    return { status: 'success', systemId };
                } else {
                    telemetryIcon.innerHTML = `<i class="fas fa-times-circle text-danger" title="Failed to start telemetry"></i>`;
                    alert(`Failed to start telemetry for system ID: ${systemId}\nReason: ${result.message}`);
                    return { status: 'error', systemId, message: result.message };
                }
            } catch (error) {
                //console.error(`Error starting telemetry for system ID: ${systemId}:`, error);
                const telemetryIcon = document.querySelector(`tr[data-id='${systemId}'] .telemetry-icon`);
                telemetryIcon.innerHTML = `<i class="fas fa-exclamation-circle text-warning" title="Error starting telemetry"></i>`;
                alert(`Error starting telemetry for system ID: ${systemId}\nReason: ${error.message}`);
                return { status: 'error', systemId, message: error.message };
            }
        };


        /*async function startSystemTelemetry(systemId) {
            try {
                const response = await fetch(`/startAllSystemTelemetry/${systemId}`, {
                    method: 'POST'
                });
                const result = await response.json();

                const telemetryIcon = document.querySelector(`tr[data-id='${systemId}'] .telemetry-icon`);

                if (result.status === 'success') {
                    //console.log(`Telemetry started successfully for system ID: ${systemId}`);
                    // Update the table cell with a success icon
                    telemetryIcon.innerHTML = `<i class="fas fa-check-circle text-success" title="Telemetry started successfully"></i>`;
                    return { status: 'success', systemId };
                } else {
                    //console.error(`Failed to start telemetry for system ID: ${systemId}: ${result.message}`);
                    // Optionally, you could update the icon to show a failure state
                    telemetryIcon.innerHTML = `<i class="fas fa-times-circle text-danger" title="Failed to start telemetry"></i>`;
                    return { status: 'error', systemId, message: result.message };
                }
            } catch (error) {
                console.error(`Error starting telemetry for system ID: ${systemId}:`, error);
                // Optionally, update the icon to indicate an error
                const telemetryIcon = document.querySelector(`tr[data-id='${systemId}'] .telemetry-icon`);
                telemetryIcon.innerHTML = `<i class="fas fa-exclamation-circle text-warning" title="Error starting telemetry"></i>`;
                return { status: 'error', systemId, message: error.message };
            }
        }*/


        // Attach event listener to the "Start All Events" button
        if (startAllEventBtn) {
            startAllEventBtn.addEventListener('click', startAllSystemTelemetry);
        }

        // AJAX form submission for GPU onboarding
        gpuOnboardingForm.addEventListener('submit', async function(event) {
            event.preventDefault();

            const formData = new FormData(this);

            try {
                const response = await fetch('/gpu_onboarding', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.status === 'success') {
                    populateGpuSystemsTable(); // Refresh the table after successful onboarding
                    this.reset(); // Reset the form
                } else {
                    alert('Failed to onboard GPU system: ' + result.message);
                }
            } catch (error) {
                console.error('Error:', error);
                alert('An error occurred while onboarding the GPU system.');
            }
        });

        // Show the edit modal with pre-filled data
        window.editSystem = function(id, nodeIp, user, password) {
            document.getElementById('editSystemId').value = id;
            document.getElementById('editNodeIp').value = nodeIp;
            document.getElementById('editUser').value = user;
            document.getElementById('editPassword').value = password;
            $('#editSystemModal').modal('show');
        };

        // AJAX submission for editing a GPU system
        document.getElementById('editSystemForm').addEventListener('submit', async function(event) {
            event.preventDefault();

            const formData = new FormData(this);

            try {
                const response = await fetch('/update_gpu_system', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.status === 'success') {
                    populateGpuSystemsTable(); // Refresh the table after successful update
                    $('#editSystemModal').modal('hide'); // Hide the modal after successful update
                } else {
                    alert('Failed to update GPU system: ' + result.message);
                }
            } catch (error) {
                console.error('Error:', error);
                alert('An error occurred while updating the GPU system.');
            }
        });

        // AJAX request to delete a GPU system
        window.deleteSystem = async function(id) {
            if (confirm('Are you sure you want to delete this GPU system?')) {
                try {
                    const response = await fetch(`/delete_gpu_system/${id}`, {
                        method: 'DELETE'
                    });

                    const result = await response.json();

                    if (result.status === 'success') {
                        populateGpuSystemsTable(); // Refresh the table after successful deletion
                    } else {
                        alert('Failed to delete GPU system: ' + result.message);
                    }
                } catch (error) {
                    console.error('Error:', error);
                    alert('An error occurred while deleting the GPU system.');
                }
            }
        };

        // Function to delete a specific metric
        window.deleteMetric = async function(host, time, field) {
            if (confirm('Are you sure you want to delete this metric?')) {
                try {
                    const response = await fetch('/delete_metric', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ host, time, field })
                    });
                    const result = await response.json();
                    if (result.status === 'success') {
                        //alert('Metric deleted successfully.');
                        fetchMetrics(); // Refresh the table
                    } else {
                        alert('Failed to delete the metric: ' + result.message);
                    }
                } catch (error) {
                    console.error('Error deleting the metric:', error);
                    alert('An error occurred while deleting the metric.');
                }
            }
        }

        // Fetch and display GPU Metrics
        async function fetchMetrics() {
            try {
                const recordLimit = document.getElementById('recordLimitInput').value || 10;

                const response = await fetch('/gpu_monitoring', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ limit: recordLimit })
                });

                if (!response.ok) {
                    throw new Error(`Network response was not ok: ${response.status} ${response.statusText}`);
                }

                const result = await response.json();
                console.log(result)
                const metricsTableBody = document.getElementById('metricsTableBody');
                const hostFilterDropdown = document.getElementById('hostFilter');
                const metricFilterDropdown = document.getElementById('metricFilter');
                const dateFilterDropdown = document.getElementById('dateFilter');
                metricsTableBody.innerHTML = ''; // Clear the table before displaying new metrics

                if (result.status === 'success') {
                    const metrics = result.metrics;

                    if (metrics.length === 0) {
                        // Inform the user if the table is empty
                        const noDataRow = document.createElement('tr');
                        noDataRow.innerHTML = '<td colspan="5">No metrics available.</td>';
                        metricsTableBody.appendChild(noDataRow);
                        return;
                    }

                    // Populate the date filter dropdown
                    const dates = [...new Set(metrics.map(metric => new Date(metric._time).toLocaleDateString()))]; // Get unique dates
                    dateFilterDropdown.innerHTML = `<option value="">All Dates</option>`;
                    dates.forEach(date => {
                        const option = document.createElement('option');
                        option.value = date;
                        option.textContent = date;
                        dateFilterDropdown.appendChild(option);
                    });


                    // Populate the host filter dropdown
                    const hosts = [...new Set(metrics.map(metric => metric.host))]; // Get unique hosts
                    hostFilterDropdown.innerHTML = `<option value="">All Hosts</option>`;
                    hosts.forEach(host => {
                        const option = document.createElement('option');
                        option.value = host;
                        option.textContent = host;
                        hostFilterDropdown.appendChild(option);
                    });

                    // Filter and display metrics based on the selected host and metric
                    function displayMetrics(selectedHost, selectedMetric) {
                        metricsTableBody.innerHTML = ''; // Clear the table body
                        const filteredMetrics = metrics.filter(metric => {
                            return (!selectedHost || metric.host === selectedHost) &&
                                   (!selectedMetric || metric._field === selectedMetric.toLowerCase().replace(' ', '_'));
                        });

                        filteredMetrics.forEach(metric => {
                            const metricRow = document.createElement('tr');
                            metricRow.innerHTML = `
                                <td>${new Date(metric._time).toLocaleString()}</td>
                                <td>${metric.host}</td>
                                <td>${metric._field.replace('_', ' ').toUpperCase()}</td>
                                <td>${metric._value}</td>
                                <td>
                                    <a href="#" onclick="deleteMetric('${metric.host}', '${metric._time}', '${metric._field}')">
                                        <i class="fas fa-trash-alt text-danger" title="Delete this metric"></i>
                                    </a>
                                </td>
                            `;
                            metricsTableBody.appendChild(metricRow);
                        });

                        if (filteredMetrics.length === 0) {
                            const noDataRow = document.createElement('tr');
                            noDataRow.innerHTML = '<td colspan="5">No metrics available for the selected filters.</td>';
                            metricsTableBody.appendChild(noDataRow);
                        }
                    }

                    // Event listeners for filtering by host and metric
                    hostFilterDropdown.addEventListener('change', function() {
                        displayMetrics(this.value, metricFilterDropdown.value);
                    });

                    metricFilterDropdown.addEventListener('change', function() {
                        displayMetrics(hostFilterDropdown.value, this.value);
                    });

                    dateFilterDropdown.addEventListener('change', function() {
                        displayMetrics(hostFilterDropdown.value, metricFilterDropdown.value, this.value);
                    });
                    // Display metrics for the initially selected filters
                    displayMetrics(hostFilterDropdown.value, metricFilterDropdown.value);
                } else {
                    const noDataRow = document.createElement('tr');
                    noDataRow.innerHTML = '<td colspan="5">No metrics available.</td>';
                    metricsTableBody.appendChild(noDataRow);
                }
            } catch (error) {
                console.error('Error fetching GPU metrics:', error);
                alert(`An error occurred while fetching the GPU metrics: ${error.message}`);
            }
        }

        document.getElementById('monitorGpuBtn').addEventListener('click', fetchMetrics);

    } else {
        console.error('GPU Monitoring or Onboarding form not found in the DOM.');
    }


});
