document.addEventListener('DOMContentLoaded', function () {
    const socket = io();
    let cy;
    let healthCheckInterval;
    let isDeviceRequestInProgress = false; // waiting for previous link health to complete
    let isLinkRequestInProgress = false;

    // Function to close the progress modal
    window.closeProgressModal = function () {
        const underlayConfigprogressModal = document.getElementById('underlayConfigprogressModal');
        if (underlayConfigprogressModal) underlayConfigprogressModal.style.display = 'none';
    };
    // Function to show generated configuration and initiate the progress
    window.showGeneratedConfig = function () {
        setButtonClicked('showGeneratedConfigBtn');
        const form = document.getElementById('underlayConfigForm');
        const configMethod = document.getElementById('config_method').value;

        // Open the progress modal
        const modal = document.getElementById('underlayConfigprogressModal');
        if (modal) modal.style.display = 'block';
        // Reset the progress bar, progress text, and host lists
        const progressBar = document.getElementById('underlayconfigProgressBar');
        const progressText = document.getElementById('underlayConfigprogressText');
        const deviceProgressList = document.getElementById('deviceProgressList');
        const failedHostList = document.getElementById('failedHostList');
        const successHostList = document.getElementById('successHostList');
        const showConfigBtn = document.getElementById('showConfigBtn');
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
            if (xhr.responseJSON && xhr.responseJSON.error) {
                errorMessage = xhr.responseJSON.error;
                if (xhr.responseJSON.duplicates && xhr.responseJSON.duplicate_interfaces) {
                    duplicateDetails = '\n\nDuplicates:\n' + JSON.stringify(xhr.responseJSON.duplicates, null, 2) +
                                       '\n\nDuplicate Interfaces:\n' + xhr.responseJSON.duplicate_interfaces.join('\n');
                    alert(errorMessage + duplicateDetails);
                }
            }
            alert(errorMessage);
        }
        });
    };

    // Socket listener for progress updates
    socket.on('overall_progress', function (data) {
        const { progress, stage, failed_hosts, success_hosts } = data;
        const progressBar = document.getElementById('underlayconfigProgressBar');
        const progressText = document.getElementById('underlayConfigprogressText');
        const failedHostList = document.getElementById('failedHostList');
        const successHostList = document.getElementById('successHostList');
        const showConfigBtn = document.getElementById('showConfigBtn');

        // Update the overall progress bar and text
        if (progressBar && progress !== undefined) {
            progressBar.value = progress;
            progressText.textContent = `${progress}% Complete`;
        }

        // Only update host lists when stage is 'Completed'
        if (stage === 'Completed') {
            if (failedHostList) failedHostList.innerHTML = '';
            if (successHostList) successHostList.innerHTML = '';

            // Display the success hosts
            if (success_hosts && success_hosts.length > 0) {
                success_hosts.forEach(host => {
                    const successHostElement = document.createElement('li');
                    successHostElement.textContent = `${host}: Success`;
                    successHostElement.style.color = 'green';
                    successHostList.appendChild(successHostElement);
                });
            }

            // Display the failed hosts
            if (failed_hosts && failed_hosts.length > 0) {
                failed_hosts.forEach(failure => {
                    const failedHostElement = document.createElement('li');
                    failedHostElement.textContent = `${failure[0]}: ${failure[1]}`;
                    failedHostElement.style.color = 'red';
                    failedHostList.appendChild(failedHostElement);
                });
            }

            // Show the "Show Configurations" button if progress completes
            if (progress === 100 && showConfigBtn) {
                showConfigBtn.style.display = 'block';
            }
        }
    });

    // Function to set the clicked button's value
    window.setButtonClicked = function (value) {
        const buttonClickedInput = document.querySelector('input[name="button_clicked"]');
        if (buttonClickedInput) {
            buttonClickedInput.value = value;
        }
    };

    // Event listener for the Show Config button
    const showConfigButton = document.getElementById('showUnderlayConfigBtn');
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

    const pushConfigButton = document.querySelector('input[type="submit"]');
    if (pushConfigButton) {
        pushConfigButton.addEventListener('click', function () {
            setButtonClicked('transferConfigBtn');
        });
    }

    $(document).ready(function () {
        $('#saveTopoCsvBtn').on('click', function () {
            const configMethod = document.getElementById('config_method').value;
            const fileInput = document.getElementById('csv_file');

            if (configMethod === 'csv') {
                const formData = new FormData($('#underlayConfigForm')[0]);
                $.ajax({
                    url: '/save_underlay_topology_csv',
                    type: 'POST',
                    data: formData,
                    processData: false,
                    contentType: false,
                    success: function (response) {
                        alert('Success..! CSV file saved successfully.');
                    },
                    error: function () {
                        alert('Error..! Error saving CSV file. Check if the CSV file is selected.');
                    }
                });
            } else if (configMethod === 'lldp') {
                $('#underlayConfigprogressModal').css('display', 'block');
                $.ajax({
                    url: '/save_underlay_topology_lldp',
                    type: 'POST',
                    success: function (response) {
                        if (response.success) {
                            alert('Success..! LLDP Neighbors Saved.');
                            $('#underlayConfigprogressModal').css('display', 'none');
                        } else {
                            alert('Error..! Invalid response format.');
                        }
                    },
                    error: function () {
                        alert('Error generating LLDP connections.');
                    }
                });
            }
        });
    });

           // Draggable modal function
        function makeModalDraggable(topologyModal, header) {
            let isDragging = false;
            let offsetX = 0, offsetY = 0;

            header.onmousedown = function(e) {
                e.preventDefault();
                isDragging = true;
                offsetX = e.clientX - topologyModal.offsetLeft;
                offsetY = e.clientY - topologyModal.offsetTop;
                document.onmousemove = dragModal;
                document.onmouseup = stopDragging;
            };

            function dragModal(e) {
                if (isDragging) {
                    topologyModal.style.left = (e.clientX - offsetX) + "px";
                    topologyModal.style.top = (e.clientY - offsetY) + "px";
                }
            }

            function stopDragging() {
                isDragging = false;
                document.onmousemove = null;
                document.onmouseup = null;
            }
        }

        // Get modal elements for dragging
        const topologyModal = document.getElementById('topologyModal');
        const modalContent = document.getElementById('topologyModalContent');
        const modalHeader = document.getElementById('topologyModalHeader');
        makeModalDraggable(topologyModal, modalHeader); // Make the modal draggable


function renderTopologyInModal(devices, edges) {
    const underlayTopologyModal = document.getElementById('topologyModal');
    underlayTopologyModal.style.display = 'block';

    const cyContainer = document.getElementById('cyModalContent');

    // Load saved positions from local storage or backend
    const savedPositions = JSON.parse(localStorage.getItem('topologyPositions')) || {};

    // Initialize Cytoscape with custom or default positions
    cy = cytoscape({
        container: cyContainer,
        elements: [].concat(
            devices.map((d, index) => ({
                data: d,
                position: savedPositions[d.id] || { x: index * 100, y: index * 100 }  // Use saved or default positions
            })),
            edges
        ),
        style: [
            {
                selector: 'node[label]',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'background-color': 'green',
                    'shape': 'rectangle',
                    'width': 'mapData(label.length, 0, 20, 30, 200)',
                    'height': '40px',
                    'text-wrap': 'wrap',
                    'text-max-width': 80
                }
            },
            {
                selector: 'edge[label]',
                style: {
                    'width': 2,
                    'line-color': '#ccc',
                    'target-arrow-color': '#ccc',
                    'target-arrow-shape': 'none',
                    'label': 'data(label)',
                    'font-size': '9px',
                    'color': 'black',
                    'curve-style': 'bezier',
                    'control-point-distance': function (ele) {
                        return ele.data('curveOffset') || 10;
                    },
                    'control-point-weight': function (ele) {
                        return ele.data('curveWeight') || 0.5;
                    },
                    'line-style': 'solid'
                }
            }
        ],
        layout: {
            name: 'preset',  // Use 'preset' layout to apply custom positions
            fit: true
        }
    });

    // Save the current positions when nodes are moved
    cy.on('dragfree', 'node', function (evt) {
        const positions = {};
        cy.nodes().forEach(node => {
            positions[node.id()] = node.position();
        });
        localStorage.setItem('topologyPositions', JSON.stringify(positions));  // Save to local storage
    });
}


        const statusMessage = document.getElementById('statusMessage');
        function showStatusMessage(message, color) {
            statusMessage.textContent = message;
            statusMessage.style.color = color;
            statusMessage.style.display = 'block';
        }

        /*function hideStatusMessage() {
            statusMessage.style.display = 'none';
        } */


       function transformTopologyData(rawTopologyData) {
            const devices = [];
            const edges = [];
            const deviceSet = new Set();

            rawTopologyData.forEach(connection => {
                const device1 = connection.device1;
                const device2 = connection.device2;
                const interface1 = connection.interface1;
                const interface2 = connection.interface2;

                // Add device1 and device2 to devices if not already added
                if (!deviceSet.has(device1)) {
                    devices.push({ id: device1, label: device1 }); // Ensure 'label' is included
                    deviceSet.add(device1);
                }
                if (!deviceSet.has(device2)) {
                    devices.push({ id: device2, label: device2 }); // Ensure 'label' is included
                    deviceSet.add(device2);
                }

                // Add edge representing the connection, with 'label' included
                edges.push({
                    data: {
                        id: `${device1}--${interface1}--${device2}--${interface2}`,
                        source: device1,
                        target: device2,
                        label: `${interface1}--${interface2}` // Ensure 'label' is included
                    }
                });
            });

            return { devices, edges };
        }




        // Close modal on clicking the close button
        const closeModalBtn = document.querySelector('.topology-modal-close');
        closeModalBtn.onclick = function() {
            topologyModal.style.display = 'none';
        };

        // Prevent closing when dragging
        topologyModal.onmousedown = function(event) {
            event.stopPropagation(); // Prevent closing when clicking to drag
        };



$('#showMytopologyBtn').on('click', function () {
    $.ajax({
        url: '/get_my_topology',
        type: 'GET',
        success: function(response) {
            const rawTopologyData = response.topology || [];
            const { devices, edges } = transformTopologyData(rawTopologyData);
            renderTopologyInModal(devices, edges);

            startPeriodicHealthCheck(devices, edges);
        },
        error: function() {
            alert('Error loading topology.');
        }
    });
});

function startPeriodicHealthCheck(devices, edges) {
    if (healthCheckInterval) {
        clearInterval(healthCheckInterval);
    }

    healthCheckInterval = setInterval(() => {
        checkDeviceHealth(devices);
        checkLinkHealth(edges);
    }, 5000); // Check every 5 seconds
}

function checkDeviceHealth(devices) {
    if (isDeviceRequestInProgress) {
        console.log("Previous device health check request still in progress.");
        return;
    }
    isDeviceRequestInProgress = true;
    //showStatusMessage("Checking device health...", "blue");

    $.ajax({
        url: '/check_device_health',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ devices: devices }),
        success: function(response) {
            const deviceHealth = response.device_health_status;
            //console.log("Device Health:", deviceHealth);

            cy.batch(() => {
                devices.forEach(device => {
                    const status = deviceHealth[device.id];
                    const deviceColor = (status === 'reachable') ? 'green' : 'lightgrey';
                    cy.getElementById(device.id).style('background-color', deviceColor);
                });
            });
            //showStatusMessage("Device health check completed!", "green");
        },
        error: function(xhr, status, error) {
            console.error('Error checking device health:', error);
            //showStatusMessage("Error checking device health.", "red");
        },
        complete: function() {
            isDeviceRequestInProgress = false;
            //setTimeout(hideStatusMessage, 3000);
        }
    });
}

function checkLinkHealth(edges) {
    if (isLinkRequestInProgress) {
        console.log("Previous link health check request still in progress.");
        return;
    }
    isLinkRequestInProgress = true;
    //showStatusMessage("Checking link health...", "blue");

    $.ajax({
        url: '/check_link_health',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ edges: edges }),
        success: function(response) {
            const linkHealth = response.link_health_status;
            //console.log("Link Health:", linkHealth);

            cy.batch(() => {
                edges.forEach(edge => {
                    const linkStatus = linkHealth[edge.data.id];
                    const linkColor = (linkStatus === 'reachable') ? 'purple' : 'lightgrey';
                    cy.getElementById(edge.data.id).style('line-color', linkColor);
                });
            });
            //showStatusMessage("Link health check completed!", "green");
        },
        error: function(xhr, status, error) {
            console.error('Error checking link health:', error);
            //showStatusMessage("Error checking link health.", "red");
        },
        complete: function() {
            isLinkRequestInProgress = false;
            //setTimeout(hideStatusMessage, 3000);
        }
    });
}



});
