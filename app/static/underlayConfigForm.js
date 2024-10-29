document.addEventListener('DOMContentLoaded', function() {
    const socket = io();

// Define closeProgressModal function
    window.closeProgressModal = function() {
        const modal = document.getElementById('underlayConfigprogressModal');
        modal.style.display = 'none';  // Hide the modal
    }

    // Optionally, close modal when clicking outside of it
    window.onclick = function(event) {
        const modal = document.getElementById('underlayConfigprogressModal');
        if (event.target === modal) {
            modal.style.display = 'none';  // Hide the modal if clicked outside
        }
    };

window.showGeneratedConfig = function() {
    setButtonClicked('showGeneratedConfigBtn');
    const form = document.getElementById('underlayConfigForm');
    const configMethod = document.getElementById('config_method').value;

    // Open the progress modal
    const modal = document.getElementById('underlayConfigprogressModal');
    modal.style.display = 'block';

    // Reset the progress bar and text
    const progressBar = document.getElementById('underlayconfigProgressBar');
    const progressText = document.getElementById('underlayConfigprogressText');
    const deviceProgressList = document.getElementById('deviceProgressList');
    const failedHostList = document.getElementById('failedHostList');
    progressBar.value = 0;
    progressText.textContent = '0% Complete';
    deviceProgressList.innerHTML = '';  // Clear previous device statuses
    failedHostList.innerHTML = '';  // Clear previous failed hosts

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
        success: function(response) {
            // Successfully triggered the processing
            console.log('Processing started successfully.');
        },
        error: function(xhr, status, error) {
            alert('Error occurred while starting the configuration: ' + error);
        }
    });
};



function showConfigs() {
    // Open a new window that shows the configurations
    window.open('/show_configs_underlay_lldp', '_blank');
}
socket.on('overall_progress', function (data) {
    const { device, progress, stage, fail, message, failed_hosts, success_hosts } = data;
    const progressBar = document.getElementById('underlayconfigProgressBar');
    const progressText = document.getElementById('underlayConfigprogressText');
    const deviceProgressList = document.getElementById('deviceProgressList');
    const failedHostList = document.getElementById('failedHostList');
    const successHostList = document.getElementById('successHostList');

    // Update the overall progress bar
    if (progressBar) {
        progressBar.value = progress;
        progressText.textContent = `${progress}% Complete`;
    }
    if (progress === 100) {
        showConfigBtn.style.display = 'block';  // Show the button
    }
    // Ensure that device name is not undefined or null
    const deviceName = device ? device : 'Device not identified';

    // Handle the progress and status of each device
    if (deviceProgressList && stage !== 'Completed') {
        let deviceStatusElement = document.querySelector(`#device-status-${deviceName}`);

        // If no element exists for this device, create one
        if (!deviceStatusElement) {
            deviceStatusElement = document.createElement('li');
            deviceStatusElement.id = `device-status-${deviceName}`;
            deviceProgressList.appendChild(deviceStatusElement);
        }
        // Update the status of the device based on the current stage
        if (stage === 'Completed') {
            deviceStatusElement.innerHTML = `<strong>${deviceName}</strong>: Success`;
            deviceStatusElement.style.color = 'green';
        } else if (stage === 'Error') {
            const message = fail || 'Error';
            deviceStatusElement.innerHTML = `<strong>${deviceName}</strong>: Failed - ${message}`;
            deviceStatusElement.style.color = 'red';
        } else if (stage === 'simplified_neighbors') {
            deviceStatusElement.innerHTML = `<strong>${deviceName}</strong>: Fetching LLDP Neighbors...`;
            deviceStatusElement.style.color = 'blue';
        } else if (stage === 'lldp_builder') {
            deviceStatusElement.innerHTML = `<strong>${deviceName}</strong>: Building LLDP Data...`;
            deviceStatusElement.style.color = 'blue';
        } else if (stage === 'generate_config') {
            deviceStatusElement.innerHTML = `<strong>${deviceName}</strong>: Generating Configuration...`;
            deviceStatusElement.style.color = 'blue';
        } else {
            deviceStatusElement.innerHTML = `<strong>${deviceName}</strong>: In progress...`;
            deviceStatusElement.style.color = 'blue';
        }
    }

    // Handle the "Completed" stage to show both success and failed hosts
    if (stage === 'Completed') {
        // Clear the previous lists for success and failed hosts
        failedHostList.innerHTML = '';
        successHostList.innerHTML = '';

        // Display the success hosts
        if (success_hosts && success_hosts.length > 0) {
            //successHostList.innerHTML = `<strong>Success Hosts:</strong>`;
            success_hosts.forEach(host => {
                const successHostElement = document.createElement('li');
                successHostElement.textContent = `${host}: Success`;
                successHostElement.style.color = 'green';
                successHostList.appendChild(successHostElement);
            });
        }

        // Display the failed hosts
        if (failed_hosts && failed_hosts.length > 0) {
            //failedHostList.innerHTML = `<strong>Failed Hosts:</strong>`;
            failed_hosts.forEach(failure => {
                const failedHostElement = document.createElement('li');
                failedHostElement.textContent = `${failure[0]}: ${failure[1]}`;
                failedHostElement.style.color = 'red';
                failedHostList.appendChild(failedHostElement);
            });
        }
    }
});






/*
    /*window.showGeneratedConfig = function() {
        setButtonClicked('showGeneratedConfigBtn');
        const form = document.getElementById('underlayConfigForm');
        const configMethod = document.getElementById('config_method').value;
        if (configMethod === 'csv') {
            form.action = '/show_underlay_csv_config';
        } else {
            form.action = '/show_underlay_lldp_config';
        }
        form.submit();
    };

*/
/*
window.showGeneratedConfig = function() {
    setButtonClicked('showGeneratedConfigBtn');
    const form = document.getElementById('underlayConfigForm');
    const configMethod = document.getElementById('config_method').value;

    // Open the progress modal
    const modal = document.getElementById('underlayConfigprogressModal');
    modal.style.display = 'block';

    // Reset the progress bar and text
    const progressBar = document.getElementById('underlayconfigProgressBar');
    const progressText = document.getElementById('underlayConfigprogressText');
    progressBar.value = 0;
    progressText.textContent = '0% Complete';

    let url;
    if (configMethod === 'csv') {
        url = '/show_underlay_csv_config';
    } else {
        url = '/show_underlay_lldp_config';
    }

    // Simulate the progress updates in case of no response
    let progress = 0;
    const progressInterval = setInterval(function() {
        progress += 10;  // Increment progress by 10% for demo purposes
        if (progress <= 100) {
            progressBar.value = progress;
            progressText.textContent = `${progress}% Complete`;
        } else {
            clearInterval(progressInterval);
        }
    }, 1000);  // Update every second

    // Submit the form to trigger the server-side processing and redirection
    form.action = url;
    form.submit();  // Submit the form normally, which will trigger the redirection
};

// Set up the event listener for progress updates from SocketIO
socket.on('overall_progress', function (data) {
    const { device, progress, stage, fail, error } = data;
    const progressBar = document.getElementById('underlayconfigProgressBar');
    const progressText = document.getElementById('underlayConfigprogressText');
    const deviceProgressList = document.getElementById('deviceProgressList');
    if (progressBar) {
        progressBar.value = progress;
        progressText.textContent = `${progress}% Complete`;

    }

    // Handle the progress and status of each device
    if (deviceProgressList) {
        let simplifiedDeviceName = device;  // Remove domain suffix, if any
        let deviceStatusElement = document.querySelector(`#device-status-${simplifiedDeviceName}`);
        // If no element exists for this device, create one
        if (deviceStatusElement) {
            deviceStatusElement = document.createElement('li');
            deviceStatusElement.id = `device-status-${simplifiedDeviceName}`;
            deviceProgressList.appendChild(deviceStatusElement);
        }

        // Update the status of the device
        if (stage === 'Completed') {
            deviceStatusElement.innerHTML = `<strong>${simplifiedDeviceName}</strong>: Success`;
            deviceStatusElement.style.color = 'green';
        } else if (stage === 'Error') {
            const message = fail || error;
            deviceStatusElement.innerHTML = `<strong>${simplifiedDeviceName}</strong>: Failed - ${message}`;
            deviceStatusElement.style.color = 'red';
        } else {
            deviceStatusElement.innerHTML = `<strong>${simplifiedDeviceName}</strong>: In progress...`;
            deviceStatusElement.style.color = 'blue';
        }
    }
});

*/


    window.setButtonClicked = function(value) {
        const buttonClickedInput = document.querySelector('input[name="button_clicked"]');
        buttonClickedInput.value = value;
    };

    // Attach event listeners to the buttons
    const showConfigButton = document.getElementById('showUnderlayConfigBtn');
    if (showConfigButton) {
        showConfigButton.addEventListener('click', showGeneratedConfig);
    }

    const pushConfigButton = document.querySelector('input[type="submit"]');
    if (pushConfigButton) {
        pushConfigButton.addEventListener('click', function() {
            setButtonClicked('transferConfigBtn');
        });
    }

    $(document).ready(function () {
        $('#saveTopoCsvBtn').on('click', function () {
            const configMethod = document.getElementById('config_method').value;
            var fileInput = document.getElementById('csv_file');

            if (configMethod === 'csv') {
                var formData = new FormData($('#underlayConfigForm')[0]);
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
                        alert('Error..! Error saving CSV file. check if csv file is selected.');
                    }
                });
            } else if (configMethod === 'lldp') {
                $('#underlayConfigprogressModal').css('display', 'block');
                /*$.ajax({
                    url: '/save_underlay_topology_lldp',
                    type: 'POST',
                    success: function (response) {
                        if (response.connections) {
                            alert('Success..! LLDP Neighbors Saved.', response.connections);
                        } else {
                            alert('Error..! Invalid response format.', response.connections);
                        }
                    },
                    error: function () {
                        alert('Error generating LLDP connections.');
                    }
                });*/
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

        // Draggable modal function
        function makeModalDraggable(modal, header) {
            let isDragging = false;
            let offsetX = 0, offsetY = 0;

            header.onmousedown = function(e) {
                e.preventDefault();
                isDragging = true;
                offsetX = e.clientX - modal.offsetLeft;
                offsetY = e.clientY - modal.offsetTop;
                document.onmousemove = dragModal;
                document.onmouseup = stopDragging;
            };

            function dragModal(e) {
                if (isDragging) {
                    modal.style.left = (e.clientX - offsetX) + "px";
                    modal.style.top = (e.clientY - offsetY) + "px";
                }
            }

            function stopDragging() {
                isDragging = false;
                document.onmousemove = null;
                document.onmouseup = null;
            }
        }

        // Get modal elements for dragging
        const modal = document.getElementById('topologyModal');
        const modalContent = document.getElementById('topologyModalContent');
        const modalHeader = document.getElementById('topologyModalHeader');

        makeModalDraggable(modal, modalHeader); // Make the modal draggable

        function renderTopologyInModal(topology) {
            modal.style.display = 'block'; // Show the modal

            const cy = cytoscape({
                container: document.getElementById('cyModalContent'),
                elements: [],
                style: [
                    {
                        selector: 'node',
                        style: {
                            'label': 'data(label)',
                            'text-valign': 'center',
                            'text-halign': 'center',
                            'background-color': 'green',
                            'shape': 'rectangle',
                            'width': 'mapData(label.length, 0, 20, 30, 200)',  // Dynamic width based on label length
                            'height': '40px',  // Fixed height
                            'text-wrap': 'wrap',  // Allow wrapping of labels
                            'text-max-width': 80  // Max width for wrapped text
                        }
                    },
                    {
                        selector: 'edge',
                        style: {
                            'width': 2,
                            'line-color': '#ccc',
                            'target-arrow-color': '#ccc',
                            'target-arrow-shape': 'none',
                            'label': 'data(label)',
                            'font-size': '9px',
                            'color': 'pink',
                            'text-margin-y': 'data(textOffset)',
                            'curve-style': 'straight'
                        }
                    }
                ],
                layout: {
                    name: 'cose'
                }
            });

            var nodes = [];
            var edges = [];

            var device1Key = Object.keys(topology[0]).find(key => key.toLowerCase().includes('device1'));
            var device2Key = Object.keys(topology[0]).find(key => key.toLowerCase().includes('device2'));
            var interface1Key = Object.keys(topology[0]).find(key => key.toLowerCase().includes('interface1'));
            var interface2Key = Object.keys(topology[0]).find(key => key.toLowerCase().includes('interface2'));

            topology.forEach(function (connection) {
                var device1 = connection[device1Key];
                var device2 = connection[device2Key];
                var interface1 = connection[interface1Key];
                var interface2 = connection[interface2Key];

                if (!nodes.find(node => node.data.id === device1)) {
                    nodes.push({ data: { id: device1, label: device1, entityType: 'device' } });
                }

                if (!nodes.find(node => node.data.id === device2)) {
                    nodes.push({ data: { id: device2, label: device2, entityType: 'device' } });
                }

                var edgeId = `${device1}--${interface1}--${device2}--${interface2}`;
                var textOffset = (edges.length - (edges.length - 1) / 6) * 10;

                edges.push({
                    data: {
                        id: edgeId,
                        source: device1,
                        target: device2,
                        label: interface1 + '--' + interface2,
                        lineStyle: 'solid',
                        textOffset: textOffset
                    },
                    classes: 'multiedge'
                });
            });

            cy.add(nodes);
            cy.add(edges);
            cy.layout({ name: 'cose' }).run();
        }

        // Handle Show My Topology button click
        $('#showMytopologyBtn').on('click', function () {
            $.ajax({
                url: '/get_my_topology',
                type: 'GET',
                success: function (response) {
                    renderTopologyInModal(response.topology);
                },
                error: function () {
                    alert('Error loading topology.');
                }
            });
        });

        // Close modal on clicking the close button
        const closeModalBtn = document.querySelector('.topology-modal-close');
        closeModalBtn.onclick = function() {
            modal.style.display = 'none';
        };

        // Prevent closing when dragging
        modal.onmousedown = function(event) {
            event.stopPropagation(); // Prevent closing when clicking to drag
        };

        // Close modal if user clicks outside the modal content
        window.onclick = function(event) {
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        };
    });
});
