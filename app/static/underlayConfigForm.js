document.addEventListener('DOMContentLoaded', function () {
        const socket = io({
            reconnection: true,
            reconnectionAttempts: 5,
            reconnectionDelay: 2000
        });



        socket.on('underlay_progress', function (data) {
            console.log("Connected to Underlay Config Form WebSocket server.");
            console.log('Received progress update:', data);

            const { progress, stage, failed_hosts, success_hosts, message, fail } = data;

            // Update progress bar
            if (progressBar && typeof progress !== 'undefined') {
                progressBar.value = progress;
                progressText.textContent = `${progress}% Complete`;
            } else {
                console.error('Progress bar or progress value is missing.');
            }

            // Update stage text
            if (stageText) {
                if (stage) {
                    stageText.textContent = `Current Stage: ${stage}`;
                } else {
                    stageText.textContent = 'Stage information not available.';
                }
            } else {
                console.error('Stage text element not found.');
            }

            // Update success and failed hosts lists
            if (successHostList) successHostList.innerHTML = '';
            if (failedHostList) failedHostList.innerHTML = '';

            if (success_hosts && Array.isArray(success_hosts) && success_hosts.length > 0) {
                success_hosts.forEach(host => {
                    const successHostElement = document.createElement('li');
                    successHostElement.textContent = `${host}: Success`;
                    successHostElement.style.color = 'green';
                    successHostList.appendChild(successHostElement);
                });
            }

            if (failed_hosts && Array.isArray(failed_hosts) && failed_hosts.length > 0) {
                failed_hosts.forEach(([hostname, reason]) => {
                    const failedHostElement = document.createElement('li');
                    failedHostElement.textContent = `${hostname}: ${reason}`;
                    failedHostElement.style.color = 'red';
                    failedHostList.appendChild(failedHostElement);
                });
            } else if (fail) {
                // Handle case where 'fail' message is provided directly
                const failedHostElement = document.createElement('li');
                failedHostElement.textContent = `Error: ${fail}`;
                failedHostElement.style.color = 'red';
                failedHostList.appendChild(failedHostElement);
            }

            // Display final message if provided
            if (message && stageText) {
                stageText.textContent += ` - ${message}`;
            }

            // Show configuration button if progress is 100 and stage is completed
            if (progress === 100 && stage === 'Completed' && showConfigBtn) {
                showConfigBtn.style.display = 'block';
            }
        });







    let deviceHealthInterval;
    let linkHealthInterval;
    let cy;
    let healthCheckInterval;
    let isDeviceRequestInProgress = false; // Waiting for previous device health check
    let isLinkRequestInProgress = false;  // Waiting for previous link health check
    const state = {
        devices: {}, // { deviceId: { status: 'reachable', color: 'green' } }
        links: {}    // { linkId: { status: 'reachable', color: 'purple' } }
    };

    // Cached DOM elements
    const stageText = document.getElementById('underlayConfigStageText');
    const topologyModal = document.getElementById('topologyModal');
    const closeModalButton = document.querySelector('.topology-modal-close');
    const statusMessage = document.getElementById('statusMessage');
    const progressBar = document.getElementById('underlayconfigProgressBar');
    const progressText = document.getElementById('underlayConfigprogressText');
    const deviceProgressList = document.getElementById('deviceProgressList');
    const failedHostList = document.getElementById('failedHostList');
    const successHostList = document.getElementById('successHostList');
    const showConfigBtn = document.getElementById('showConfigBtn');
    const errorLogModal = document.getElementById('errorLogModal');
    const errorLogList = document.getElementById('errorLogList');
    const closeErrorLogButton = document.getElementById('closeErrorLogBtn');
    const showConfigButton = document.getElementById('showUnderlayConfigBtn');




        if (closeModalButton) {
            closeModalButton.addEventListener('click', closeTopologyModal);
        } else {
            console.error("Close button for topology modal not found.");
        }


        // Close the modal when clicking outside the modal content
        window.addEventListener('click', function (event) {
            if (event.target === topologyModal) {
                topologyModal.style.display = 'none';
                stopPeriodicHealthCheck();
                console.log("Topology modal closed via outside click.");
            }
        });

        // Function to close the progress modal
        window.closeProgressModal = function () {
            const underlayConfigprogressModal = document.getElementById('underlayConfigprogressModal');
            if (underlayConfigprogressModal) underlayConfigprogressModal.style.display = 'none';
        };

        window.closeErrorLogModal = function() {
            const errorLogModal = document.getElementById("errorLogModal");
            if (errorLogModal) {
                errorLogModal.style.display = "none";
            }
        };

        // Function to set the clicked button's value
        window.setButtonClicked = function (value) {
            const buttonClickedInput = document.querySelector('input[name="button_clicked"]');
            if (buttonClickedInput) {
                buttonClickedInput.value = value;
            }
        };
        // Function to show generated configuration and initiate the progress
        window.showGeneratedConfig = function () {
            resetProgressModal();
            setButtonClicked('showGeneratedConfigBtn');
            const form = document.getElementById('underlayConfigForm');
            const configMethod = document.getElementById('config_method').value;

            // Open the progress modal
            const modal = document.getElementById('underlayConfigprogressModal');
            if (modal) modal.style.display = 'block';
            if (progressBar) progressBar.value = 0;
            if (progressText) progressText.textContent = '0% Complete';
            if (deviceProgressList) deviceProgressList.innerHTML = '';
            if (failedHostList) failedHostList.innerHTML = '';
            if (successHostList) successHostList.innerHTML = '';
            if (showConfigBtn) showConfigBtn.style.display = 'none';
            // Set the correct URL for `showConfigBtn` based on the selected configuration method
            if (configMethod === 'csv') {
                showConfigBtn.onclick = function () {
                    window.open('/view_underlay_csv_config', '_blank');
                };
            } else if (configMethod === 'lldp') {
                showConfigBtn.onclick = function () {
                    window.open('/view_underlay_lldp_config', '_blank');
                };
            }
            showConfigBtn.style.display = 'block';
            let url;
            if (configMethod === 'csv') {
                url = '/show_underlay_csv_config';
            } else {
                url = '/show_underlay_lldp_config';
            }

            // Send the form data using AJAX
            const formData = new FormData(form);
            $.ajax({
                url: url,
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function (response) {
                    console.log('Processing started successfully.');
                },
                /*error: function (xhr, status, error) {
                    alert('Error occurred while starting the configuration: ' + error );
                }*/
                error: function (xhr) {
                    let errorMessage = 'Error occurred while starting the configuration.';
                    let duplicateDetails = '';
                    if (xhr.responseJSON) {
                        // Check for specific error messages in the response
                        if (xhr.responseJSON.message) {
                            errorMessage = xhr.responseJSON.message;
                        }
                        if (xhr.responseJSON.fail) {
                            errorMessage = xhr.responseJSON.fail;
                        }
                    }
                alert(errorMessage);
            }
            });
        };
        if (showConfigButton) {
            showConfigButton.addEventListener('click', function (event) {
                const configMethod = document.getElementById('config_method').value;
                const csvFileInput = document.getElementById('csv_file');

                // Check if config method is "CSV File" and if no file is attached
                if (configMethod === 'csv' && !csvFileInput.files.length) {
                    event.preventDefault();
                    alert('Please attach a CSV file before proceeding.');
                } else {
                    showGeneratedConfig();
                }
            });
        }
        //END show generated config


        const pushConfigButton = document.querySelector('input[type="submit"]');
        if (pushConfigButton) {
            pushConfigButton.addEventListener('click', function () {
                setButtonClicked('transferConfigBtn');
            });
        }

        function stopPeriodicHealthCheck() {
            if (deviceHealthInterval) {
                clearInterval(deviceHealthInterval);
                deviceHealthInterval = null;
            }
            if (linkHealthInterval) {
                clearInterval(linkHealthInterval);
                linkHealthInterval = null;
            }
            isDeviceRequestInProgress = false;
            isLinkRequestInProgress = false;
            console.log("Periodic health checks stopped.");
        }

        window.addEventListener('beforeunload', stopPeriodicHealthCheck);

    // Function to log errors and show the modal
    function logError(message) {
        if (errorLogList) {
            const errorItem = document.createElement('li');
            errorItem.textContent = message;
            errorLogList.appendChild(errorItem);

            // Show the error log modal if it's not already displayed
            if (errorLogModal && errorLogModal.style.display !== 'block') {
                errorLogModal.style.display = 'block';
            }
        }
    }

    // Show and close error log modal
    function showErrorLogModal() {
        errorLogModal.style.display = 'block';
    }

    // Function to close the error log modal
    function closeErrorLogModal() {
        if (errorLogModal) {
            errorLogModal.style.display = 'none';
            // Clear the error list when the modal is closed
            if (errorLogList) {
                errorLogList.innerHTML = '';
            }
        }
    }

    if (closeErrorLogButton) {
        closeErrorLogButton.addEventListener('click', closeErrorLogModal);
    } else {
        console.error("Close button for error log modal not found.");
    }

    // Utility function to update device state
    function updateDeviceState(deviceId, status) {
        const color = status === 'reachable' ? 'green' : 'lightgrey';
        if (!state.devices[deviceId] || state.devices[deviceId].color !== color) {
            state.devices[deviceId] = { status, color };
            cy.getElementById(deviceId).style('background-color', color);
        }
    }



    function updateLinkState(linkId, status) {
        const color = status === 'Healthy' ? 'purple' : 'lightgrey';

        if (!state.links[linkId] || state.links[linkId].color !== color) {
            state.links[linkId] = { status, color };

            cy.batch(() => {
                const link = cy.getElementById(linkId);
                if (link) {
                    link.style('line-color', color);
                } else {
                    console.warn(`Link with ID ${linkId} not found in the topology.`);
                }
            });
        }
    }




    // Function to update the progress bar
    function updateProgressBar(progress, stage) {
        const progressBar = document.getElementById('underlayconfigProgressBar');
        const progressText = document.getElementById('underlayConfigprogressText');

        if (progressBar) {
            progressBar.value = progress;
        }
        if (progressText) {
            progressText.textContent = `${progress}% Complete - ${stage}`;
        }
    }

    // Reset progress modal state
    function resetProgressModal() {
        if (progressBar) progressBar.value = 0;
        if (progressText) progressText.textContent = '0% Complete';
        if (stageText) stageText.textContent = '';
        if (failedHostList) failedHostList.innerHTML = '';
        if (successHostList) successHostList.innerHTML = '';
        if (showConfigBtn) showConfigBtn.style.display = 'none';
    }

    // Handle AJAX retries
    function retryAjaxRequest(url, data, retries = 3, delay = 2000) {
        return new Promise((resolve, reject) => {
            $.ajax({
                url: url,
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(data),
                success: resolve,
                error: function (xhr, status, error) {
                    if (retries > 0) {
                        setTimeout(() => {
                            retryAjaxRequest(url, data, retries - 1, delay * 2).then(resolve).catch(reject);
                        }, delay);
                    } else {
                        reject(error);
                    }
                }
            });
        });
    }
/*
function startPeriodicHealthCheck(devices, edges) {
    console.log("Starting periodic health checks...");
    stopPeriodicHealthCheck();

    // Device health check every 60 seconds
    deviceHealthInterval = setInterval(() => {
        if (!isDeviceRequestInProgress) {
            console.log("Initiating device health check...");
            checkDeviceHealth(devices);
        }
    }, 60000);

    // Determine the interval for link health check based on the number of edges
    const linkHealthCheckInterval = edges.length > 30 ? 60000 : 30000; // 60 sec if edges > 30, else 45 sec
    console.log(`Link health check interval set to ${linkHealthCheckInterval / 1000} seconds.`);

    // Link health check at the determined interval
    linkHealthInterval = setInterval(() => {
        if (!isLinkRequestInProgress) {
            console.log("Initiating link health check...");
            checkLinkHealth(edges);
        }
    }, linkHealthCheckInterval);
}

*/

// Function to Start and Stop Health Check
function startPeriodicHealthCheck(devices, edges) {
    console.log("✅ Health check started after refresh...");
    stopPeriodicHealthCheck();  // Ensure previous intervals are cleared

    // **Run Device Health Check Once**
    if (!isDeviceRequestInProgress) {
        console.log("🛠️ Initiating device health check...");
        checkDeviceHealth(devices);
    }

    // **Run Link Health Check Once**
    if (!isLinkRequestInProgress) {
        console.log("🔗 Initiating link health check...");
        checkLinkHealth(edges);
    }

    // **Stop Health Check Automatically After One Run**
    setTimeout(() => {
        console.log("✅ Health check completed. Stopping periodic checks.");
        stopPeriodicHealthCheck();
    }, 60000); // Stops checks after 60 seconds
}



function checkDeviceHealth(devices) {
    if (isDeviceRequestInProgress) {
        console.log("Device health check already in progress.");
        return Promise.resolve(); // Skip if already in progress
    }

    isDeviceRequestInProgress = true; // Set flag
    console.log("Starting device health check with devices:", devices);

    return retryAjaxRequest('/check_device_health', { devices }, 3, 2000)
        .then(response => {
            console.log("Device health check response:", response);
            const deviceHealth = response.device_health_status;

            cy.batch(() => {
                devices.forEach(device => {
                    const status = deviceHealth[device.id] || 'unreachable';
                    updateDeviceState(device.id, status);
                });
            });
        })
        .catch(error => {
            console.error("Device health check failed:", error);
            logError(`Device health check failed: ${error}`);
        })
        .finally(() => {
            isDeviceRequestInProgress = false; // Reset flag
            console.log("Device health check completed.");
        });
}


let updateTimeout;
function throttleUpdateEdges(edges, linkHealth) {
    clearTimeout(updateTimeout);
    updateTimeout = setTimeout(() => {
        cy.batch(() => {
            edges.forEach(edge => {
                const status = linkHealth[edge.data.id] || 'unreachable';
                const color = status === 'Healthy' ? 'purple' : 'lightgrey';
                const link = cy.getElementById(edge.data.id);
                if (link) {
                    link.style('line-color', color);
                }
            });
        });
    }, 200); // Delay in milliseconds
}


function checkLinkHealth(edges) {
    if (isLinkRequestInProgress) {
        console.log("Link health check already in progress.");
        return Promise.resolve();
    }

    isLinkRequestInProgress = true;
    console.log("Starting link health check with edges:", edges);

    // Set all edges to orange at the start of the health check
    cy.batch(() => {
        edges.forEach(edge => {
            const link = cy.getElementById(edge.data.id);
            if (link) {
                link.style('line-color', 'orange'); // Set to orange while checking
            } else {
                console.warn(`Edge with ID ${edge.data.id} not found in the topology.`);
            }
        });
    });

    return retryAjaxRequest('/check_link_health', { edges }, 3, 2000)
        .then(response => {
            console.log("Link health check response:", response);
            const linkHealth = response.link_health_status;
            throttleUpdateEdges(edges, linkHealth); // Use throttled updates
        })
        .catch(error => {
            console.error("Link health check failed:", error);
            logError(`Link health check failed: ${error}`);
        })
        .finally(() => {
            isLinkRequestInProgress = false;
            console.log("Link health check completed.");
        });
}

function makeModalDraggable(modal, header) {
    let isDragging = false;
    let startX = 0;
    let startY = 0;

    // Track initial mouse and modal positions on mousedown
    header.addEventListener('mousedown', function (event) {
        isDragging = true;
        startX = event.clientX - modal.offsetLeft;
        startY = event.clientY - modal.offsetTop;
        modal.style.cursor = 'move'; // Change cursor to indicate dragging
    });

    // Update modal position on mousemove
    document.addEventListener('mousemove', function (event) {
        if (isDragging) {
            let newX = event.clientX - startX;
            let newY = event.clientY - startY;

            // Constrain the modal within the viewport
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            const modalWidth = modal.offsetWidth;
            const modalHeight = modal.offsetHeight;

            newX = Math.max(0, Math.min(newX, viewportWidth - modalWidth));
            newY = Math.max(0, Math.min(newY, viewportHeight - modalHeight));

            // Apply the new position
            modal.style.left = `${newX}px`;
            modal.style.top = `${newY}px`;
        }
    });

    // Stop dragging on mouseup
    document.addEventListener('mouseup', function () {
        if (isDragging) {
            isDragging = false;
            modal.style.cursor = 'default'; // Restore default cursor
        }
    });
}


document.addEventListener('DOMContentLoaded', function () {
    const modal = document.getElementById('topologyModal');
    const header = document.getElementById('topologyModalHeader');
    let isDragging = false;
    let offsetX = 0;
    let offsetY = 0;

    // Mouse down on the header
    header.addEventListener('mousedown', function (e) {
        isDragging = true;
        offsetX = e.clientX - modal.offsetLeft;
        offsetY = e.clientY - modal.offsetTop;
        document.body.style.userSelect = 'none'; // Prevent text selection while dragging
    });

    // Mouse move to drag
    document.addEventListener('mousemove', function (e) {
        if (isDragging) {
            modal.style.left = `${e.clientX - offsetX}px`;
            modal.style.top = `${e.clientY - offsetY}px`;
        }
    });

    // Mouse up to stop dragging
    document.addEventListener('mouseup', function () {
        isDragging = false;
        document.body.style.userSelect = 'auto'; // Re-enable text selection
    });
});


document.addEventListener('DOMContentLoaded', function () {
    // Attach right-click listener to a device list or other UI element
    document.querySelectorAll('.device-item').forEach(deviceElement => {
        deviceElement.addEventListener('contextmenu', function (event) {
            event.preventDefault(); // Prevent the default browser context menu
            const deviceHostname = deviceElement.dataset.hostname; // Get hostname from data attribute
            const sshUsername = 'root';
            const sshPort = 22;

            console.log(`Right-clicked on device: ${deviceHostname}`);

            if (!deviceHostname) {
                alert('Invalid device data. No hostname available.');
                return;
            }

            const userConfirmed = confirm(`Do you want to SSH into ${deviceHostname}?`);

            if (userConfirmed) {
                const sshUrl = `ssh://${sshUsername}@${deviceHostname}:${sshPort}`;
                window.open(sshUrl, '_blank');
            }
        });
    });
});




function showTooltip(id, label, status) {
    const tooltip = document.getElementById('tooltip');
    if (tooltip) {
        tooltip.style.display = 'block';
        tooltip.textContent = `ID: ${id}, Label: ${label}, Status: ${status}`;
    }
}

function hideTooltip() {
    const tooltip = document.getElementById('tooltip');
    if (tooltip) {
        tooltip.style.display = 'none';
    }
}

function renderTopologyInModal(devices, edges) {
    const underlayTopologyModal = document.getElementById('topologyModal');
    underlayTopologyModal.style.display = 'block';
    const cyContainer = document.getElementById('cyModalContent');
    const savedPositions = JSON.parse(localStorage.getItem('topologyPositions')) || {};
    // Initialize Cytoscape with updated settings
    cy = cytoscape({
        container: cyContainer,
        elements: [].concat(
            devices.map((d, index) => ({
                data: d,
                position: savedPositions[d.id] || { x: index * 100, y: index * 100 }
            })),
            edges
        ),
        style: [
            // Node styling
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'background-color': 'green',
                    'shape': 'rectangle',
                    'width': 'mapData(label.length, 0, 20, 30, 200)',
                    'height': 40,
                    'text-wrap': 'wrap',
                    'text-max-width': 100,
                    'border-width': 1,
                    'border-color': '#000'
                }
            },
            {
                selector: 'node[status="unreachable"]',
                style: {
                    'background-color': 'red',
                    'border-color': 'darkred',
                    'border-width': 2
                }
            },
            // Default edge styling
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': 'orange', // Default link color
                    'label': 'data(label)',
                    'curve-style': 'bezier'
                }
            },
            {
                selector: 'edge[status="Healthy"]',
                style: {
                    'line-color': 'purple', // Healthy link color
                }
            },
            {
                selector: 'edge[status="unreachable"]',
                style: {
                    'line-color': 'lightgrey', // Unreachable link color
                    'line-style': 'dashed'
                }
            }
        ],
        layout: {
            name: 'preset',
            fit: true,
            padding: 20 // Add padding around the graph
        },
        userPanningEnabled: true,
        userZoomingEnabled: true,
        boxSelectionEnabled: false
    });

    // Automatically fit and center the graph
    cy.fit();
    cy.center();

    // Tooltip for nodes and edges
    cy.on('mouseover', 'node, edge', function (evt) {
        const element = evt.target;
        if (element.isNode()) {
            showTooltip(element.id(), element.data('label'), element.data('status'));
        } else if (element.isEdge()) {
            showTooltip(element.id(), element.data('label'), element.data('status'));
        }
    });

    cy.on('mouseout', 'node, edge', function () {
        hideTooltip();
    });

    // Save positions on drag
    cy.on('dragfree', 'node', function () {
        const positions = {};
        cy.nodes().forEach(node => {
            positions[node.id()] = node.position();
        });
        localStorage.setItem('topologyPositions', JSON.stringify(positions));
    });

    // Re-center graph when window is resized
    window.addEventListener('resize', () => {
        cy.fit();
        cy.center();
    });
}




function addModalEventListeners(modalId, closeButtons) {
    const modal = document.getElementById(modalId);

    if (modal) {
        // Close modal when clicking on close buttons
        closeButtons.forEach(buttonSelector => {
            const button = document.querySelector(buttonSelector);
            if (button) {
                button.addEventListener('click', () => closeModal(modalId));
            }
        });

        // Close modal when clicking outside modal content
        window.addEventListener('click', event => {
            if (event.target === modal) {
                closeModal(modalId);
            }
        });
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        if (modalId === 'topologyModal') {
            stopPeriodicHealthCheck();
        }
        console.log(`${modalId} closed.`);
    }
}

// Example usage
addModalEventListeners('topologyModal', ['#closeTopologyBtn', '.topology-modal-close']);
addModalEventListeners('errorLogModal', ['#closeErrorLogBtn']);
document.querySelector('.btn-close').addEventListener('click', () => {
    const topologyModal = bootstrap.Modal.getInstance(document.getElementById('topologyModal'));
    if (topologyModal) {
        topologyModal.hide();
    }
});


// Event handler for showing the topology



        $('#showMytopologyBtn').on('click', function () {
            $.ajax({
                url: '/get_my_topology',
                type: 'GET',
                success: function (response) {
                    console.log("API response for topology:", response);

                    const rawTopologyData = response.topology || [];
                    const { devices, edges } = transformTopologyData(rawTopologyData);

                    console.log("Transformed devices:", devices);
                    console.log("Transformed edges:", edges);

                    if (!devices.length || !edges.length) {
                        console.error("Devices or edges are empty after transformation.");
                    }

                    renderTopologyInModal(devices, edges);
                    //startPeriodicHealthCheck(devices, edges); // Pass devices and edges

                    // Ensure health check starts only when refresh button is clicked
                    $('#refreshTopologyBtn').off('click').on('click', function () {
                        console.log("🔄 Refresh button clicked. Reloading topology and starting health check...");

                        // Clear existing topology before reloading
                        $('#cyModalContent').empty();

                        fetchTopologyData().then(({ devices, edges }) => {
                            renderTopologyInModal(devices, edges);
                            startPeriodicHealthCheck(devices, edges);  // ✅ Start health check after refresh
                        }).catch(error => {
                            console.error("❌ Error fetching topology data:", error);
                        });
                    });

                },
                error: function (xhr, status, error) {
                    console.error("Error loading topology:", status, error);
                }
            });
        });


        $('#closeTopologyBtn, .topology-modal-close').on('click', function () {
            closeTopologyModal();
        });

        function fetchTopologyData() {
            return new Promise((resolve, reject) => {
                $.ajax({
                    url: '/get_my_topology',
                    type: 'GET',
                    success: function (response) {
                        console.log("✅ Fetched latest topology data:", response);

                        const rawTopologyData = response.topology || [];
                        const { devices, edges } = transformTopologyData(rawTopologyData);

                        console.log("📌 Updated devices:", devices);
                        console.log("📌 Updated edges:", edges);

                        resolve({ devices, edges });
                    },
                    error: function (xhr, status, error) {
                        console.error("❌ Failed to fetch topology data:", error);
                        reject(error);
                    }
                });
            });
        }


       // Function to close the topology modal
        function closeTopologyModal() {
            if (topologyModal) {
                topologyModal.style.display = 'none';
                stopPeriodicHealthCheck();
                console.log("Topology modal closed.");
            }
        }
        // Close the modal when clicking outside the modal content
        window.addEventListener('click', function (event) {
            if (event.target === topologyModal) {
                closeTopologyModal();
            }
        });


    function transformTopologyData(rawTopologyData) {
        console.log("Raw topology data:", rawTopologyData);

        if (!rawTopologyData || !Array.isArray(rawTopologyData)) {
            console.error("Invalid or empty topology data.");
            return { devices: [], edges: [] };
        }

        const devices = [];
        const edges = [];
        const deviceSet = new Set();

        rawTopologyData.forEach(({ device1, device2, interface1, interface2 }) => {
            //console.log("Processing connection:", { device1, device2, interface1, interface2 });

            if (!deviceSet.has(device1)) {
                devices.push({ id: device1, label: device1 });
                deviceSet.add(device1);
            }
            if (!deviceSet.has(device2)) {
                devices.push({ id: device2, label: device2 });
                deviceSet.add(device2);
            }

            edges.push({
                data: {
                    id: `${device1}-${interface1}--${device2}-${interface2}`,
                    source: device1,
                    target: device2,
                    label: `${interface1}--${interface2}`
                }
            });
        });

        console.log("Transformed devices:", devices);
        console.log("Transformed edges:", edges);

        return { devices, edges };
    }

$(document).ready(function () {
    $('#saveTopoCsvBtn').on('click', function () {
        resetProgressModal();
        const configMethod = document.getElementById('config_method').value;
        const fileInput = document.getElementById('csv_file');

        // Show progress modal
        const progressModal = $('#underlayConfigprogressModal');
        progressModal.css('display', 'block');
        // Clear success and failed host lists
        $('#successHostList').empty();
        $('#failedHostList').empty();
        // Hide showConfigBtn
        $('#showConfigBtn').css('display', 'none');

        if (configMethod === 'csv') {
            const formData = new FormData($('#underlayConfigForm')[0]);

            $.ajax({
                url: '/save_underlay_topology_csv',
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function (response) {
                    // Handle success and progress completion
                    if (response.success) {
                        updateProgressBar(100, 'Completed');
                        $('#showConfigBtn').css('display', 'none');
                    } else {
                        alert('Error..! Invalid response format.');
                        progressModal.css('display', 'none');
                    }
                },
                error: function () {
                    alert('Error..! Error saving CSV file. Check if the CSV file is selected.');
                    progressModal.css('display', 'none');
                }
            });
        } else if (configMethod === 'lldp') {
            $.ajax({
                url: '/save_underlay_topology_lldp',
                type: 'POST',
                success: function (response) {
                    if (response.success) {
                        updateProgressBar(100, 'Completed');
                        $('#showConfigBtn').css('display', 'none');
                    } else {
                        alert('Error..! Invalid response format.');
                        progressModal.css('display', 'none');
                    }
                },
                error: function () {
                    alert('Error generating LLDP connections.');
                    progressModal.css('display', 'none');
                }
            });
        }
    }); // Closing for $('#saveTopoCsvBtn').on('click', function () {...})
}); // Closing for $(document).ready(function () {...})

});
