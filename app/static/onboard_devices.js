document.addEventListener('DOMContentLoaded', function() {
    const socket = io();

    // Check if the element exists before adding an event listener
    const deleteSelectedImageBtn = document.getElementById('deleteSelectedImageBtn');
    if (deleteSelectedImageBtn) {
        deleteSelectedImageBtn.addEventListener('click', function() {
            const selectedImage = document.getElementById('uploadedImagesSelect').value;
            if (selectedImage) {
                deleteImage(selectedImage);
            } else {
                console.error('No image selected for deletion');
            }
        });
    }

async function uploadCsvFile() {
    const csvFileInput = document.getElementById('csvFile');
    const file = csvFileInput.files[0];
    console.log()
    const formData = new FormData();
    formData.append('file', file);
    try {
        const response = await fetch('/onboard_devices', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        console.log(result)
        if (response.ok) {
            let message = 'CSV file uploaded successfully.\n\n';
            if (result.added_devices && result.added_devices.length > 0) {
                message += 'Added devices:\n' + result.added_devices.join('\n') + '\n\n';
            }
            if (result.duplicated_devices && result.duplicated_devices.length > 0) {
                message += 'Duplicated devices (not added):\n' + result.duplicated_devices.join('\n') + '\n\n';
            }
            if (result.conflicting_devices && result.conflicting_devices.length > 0) {
                message += 'IP conflicts detected:\n';
                result.conflicting_devices.forEach(conflict => {
                    message += `IP: ${conflict.ip}, used by user: ${conflict.conflicting_user}\n`;
                });
                message += '\nNo devices added due to conflicts.';
            }
            alert(message);
            // Call fetchOnboardedDevices and fetchUploadedImages
            fetchOnboardedDevices();  // This fetches the onboarded devices after upload
            //fetchUploadedImages();    // Call this after the CSV upload is successful
        } else {
            let errorMessage = 'Error uploading CSV file.';
            if (result.message) {
                errorMessage += ' ' + result.message;
            }
            alert(errorMessage);
        }
    } catch (error) {
        alert('Error uploading CSV file.');
    }
}

document.getElementById('csvFile').addEventListener('change', function(e) {
        var fileName = e.target.files[0].name;
        var label = document.querySelector('.custom-file-label');
        label.textContent = fileName;
    });

document.getElementById('imageFile').addEventListener('change', function(e) {
    var fileName = e.target.files[0].name;  // Get the selected file name
    var label = this.nextElementSibling;  // Target the next sibling, which is the label for the file input
    label.textContent = fileName;  // Replace the label content with the file name
});

async function uploadImageFile() {
    const imageFileInput = document.getElementById('imageFile');
    const uploadProgressContainer = document.getElementById('uploadProgressContainer');
    const uploadProgress = document.getElementById('uploadProgress');
    const uploadProgressText = document.getElementById('uploadProgressText');
    const file = imageFileInput.files[0];

    if (!file) {
        alert('Please select an image file.');
        return;
    }

    const formData = new FormData();
    formData.append('imageFile', file);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/upload_image', true);

    xhr.upload.onprogress = function(event) {
        if (event.lengthComputable) {
            const percentComplete = Math.round((event.loaded / event.total) * 100);
            uploadProgress.value = percentComplete;
            uploadProgressText.textContent = percentComplete + '%';
        }
    };

    xhr.onloadstart = function() {
        uploadProgressContainer.style.display = 'block';
    };

    xhr.onloadend = function() {
        uploadProgressContainer.style.display = 'none';
        uploadProgress.value = 0;
        uploadProgressText.textContent = '0%';
    };

    xhr.onload = function() {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);
            if (response.success) {
                alert('Image file uploaded successfully.');

                // Check if upload progress reached 100%
                if (uploadProgress.value === 100) {
                    fetchUploadedImages();  // Fetch uploaded images if the upload is complete
                }
            } else {
                alert('Error uploading image file.');
            }
        } else {
            alert('Error uploading image file.');
        }
    };

    xhr.onerror = function() {
        alert('Error uploading image file.');
    };

    xhr.send(formData);
}

async function deleteImage(imageName) {
    try {
        const response = await fetch(`/delete_image/${encodeURIComponent(imageName)}`, {
            method: 'DELETE',
        });
        const result = await response.json();
        if (response.ok) {
            alert('Image deleted successfully.');
            fetchUploadedImages();
        } else {
            alert('Error deleting image: ' + result.error);
        }
    } catch (error) {
        console.error('Error deleting image:', error);
        alert('Error deleting image.');
    }
}

async function stopImageCopy() {
            const checkboxes = document.querySelectorAll('.device-checkbox:checked');
            const deviceIds = Array.from(checkboxes).map(checkbox => {
                const tr = checkbox.closest('tr');
                return tr ? tr.getAttribute('data-device-id') : null;
            }).filter(id => id !== null);

            if (deviceIds.length === 0) {
                alert('Please select at least one device to stop.');
                return;
            }

            try {
                for (let deviceId of deviceIds) {
                    const payload = JSON.stringify({ device_id: deviceId });
                    const response = await fetch('/stop_image_copy', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: payload
                    });

                    if (!response.ok) {
                        const errorText = await response.text();
                        console.error('Error stopping image copy:', errorText);
                        alert('Error stopping image copy or not started.!!');
                        return;
                    }
                    alert(`Image copy process stopped for device ${deviceId}.`);
                }
            } catch (error) {
                console.error('Error stopping image copy:', error);
                alert('Error stopping image copy. Please check the console for more details.');
            }
        }
/*
socket.on('overall_progress', function(data) {
    const { progress } = data;
    const overallProgressBar = document.getElementById('overallProgressBar');
    const progressText = document.getElementById('progressText');
    if (overallProgressBar) {
        overallProgressBar.value = progress;
        progressText.textContent = `${progress.toFixed(2)}% Complete`;
    }
});*/

    // Set up the event listener for progress updates
    socket.on('overall_progress', function(data) {
        const { device, progress, stage, fail, error } = data;
        const overallProgressBar = document.getElementById('overallProgressBar');
        const progressText = document.getElementById('progressText');
        const deviceProgressList = document.getElementById('deviceProgressList');

        if (overallProgressBar) {
            overallProgressBar.value = progress;
            progressText.textContent = `${progress}% Complete`;
        }

        if (deviceProgressList) {
            let deviceStatusElement = document.querySelector(`#device-status-${device}`);

            // If no element exists for this device, create one
            if (!deviceStatusElement) {
                deviceStatusElement = document.createElement('li');
                deviceStatusElement.id = `device-status-${device}`;
                deviceProgressList.appendChild(deviceStatusElement);
            }

            // Update the status of the device
            if (stage === 'Completed') {
                deviceStatusElement.textContent = `Device ${device}: Success`;
                deviceStatusElement.style.color = 'green';
            }
            else if (stage === 'Error') {
                const message = fail || error;
                deviceStatusElement.textContent = `Device ${device}: Failed - ${message}`;
                deviceStatusElement.style.color = 'red';
            }
        }
    });




    async function saveAllDevicesConfig() {
        // Show the modal or loader
        document.getElementById('progressModal').style.display = 'block';

        try {
            // Make the POST request to save all device configs
            const response = await fetch('/save_all_device_configs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const result = await response.json();
            console.log(result);

            if (response.ok) {
                if (result.success) {
                    alert('All device configurations saved successfully.');
                } else {
                    // Display failed devices in the UI
                    displayFailedDevices(result.errors);
                }
            }
        } catch (error) {
            console.error('Error saving all device configurations:', error);
            alert('An error occurred while saving device configurations.');
        } finally {
            // Hide the modal after completion
            //document.getElementById('progressModal').style.display = 'none';
        }
    }

    // Function to display failed devices
    function displayFailedDevices(errors) {
        const deviceProgressList = document.getElementById('deviceProgressList');
        if (deviceProgressList) {
            errors.forEach(error => {
                let deviceStatusElement = document.querySelector(`#device-status-${error.device}`);

                // If no element exists for this device, create one
                if (!deviceStatusElement) {
                    deviceStatusElement = document.createElement('li');
                    deviceStatusElement.id = `device-status-${error.device}`;
                    deviceProgressList.appendChild(deviceStatusElement);
                }

                // Mark the device as failed
                deviceStatusElement.textContent = `Device ${error.device}: Failed - ${error.message}`;
                deviceStatusElement.style.color = 'red';
            });
        }
    }

async function restoreDeviceConfig(hostname) {
    document.getElementById('progressModal').style.display = 'block';  // Show the progress modal

    try {
        // Make the POST request to restore the device configuration
        const response = await fetch(`/restore_device_config/${hostname}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const result = await response.json();
        console.log(result)

        if (result.success) {
            // If restoration succeeds, show success
            let deviceStatusElement = document.querySelector(`#device-status-${hostname}`);
            if (!deviceStatusElement) {
                deviceStatusElement = document.createElement('li');
                deviceStatusElement.id = `device-status-${hostname}`;
                document.getElementById('deviceProgressList').appendChild(deviceStatusElement);
            }
            deviceStatusElement.textContent = `Device ${hostname}: Restored successfully`;
            deviceStatusElement.style.color = 'green';
        } else {
            // If restoration fails, show the error
            let deviceStatusElement = document.querySelector(`#device-status-${hostname}`);
            if (!deviceStatusElement) {
                deviceStatusElement = document.createElement('li');
                deviceStatusElement.id = `device-status-${hostname}`;
                document.getElementById('deviceProgressList').appendChild(deviceStatusElement);
            }
            deviceStatusElement.textContent = `Device ${hostname}: Failed - ${result.error}`;
            deviceStatusElement.style.color = 'red';
        }
    } catch (error) {
        // Handle any general errors
        console.error('Error restoring device configuration:', error);
        let deviceStatusElement = document.querySelector(`#device-status-${hostname}`);
        if (!deviceStatusElement) {
            deviceStatusElement = document.createElement('li');
            deviceStatusElement.id = `device-status-${hostname}`;
            document.getElementById('deviceProgressList').appendChild(deviceStatusElement);
        }
        deviceStatusElement.textContent = `Device ${hostname}: Failed - ${error.message}`;
        deviceStatusElement.style.color = 'red';
    }
}

async function restoreAllDevicesConfig() {
    // Show the modal
    document.getElementById('progressModal').style.display = 'block';

    // Close modal when clicking on <span> (x) or outside the modal (optional, but not required for your case)
    const closeProgressModalModal = document.querySelector('#progressModal .close');
    if (closeProgressModalModal) {
        closeProgressModalModal.onclick = function() {
            const progressModal = document.getElementById('progressModal');
            progressModal.style.display = 'none';
        };
    }

    try {
        // Make the POST request to start restoring device configurations
        const response = await fetch('/restore_all_device_configs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const result = await response.json();

        // No need to show alerts, as progress will be shown in the modal
        if (result.success) {
            // Logic here is replaced by real-time updates using Socket.IO
        } else {
            // Errors will be handled and displayed through the progress modal, no alerts needed
            const errorMessages = result.errors.map(error => `Device: ${error.device}, Message: ${error.message}`).join('\n');
            console.log(`Failed to restore all device configurations:\n${errorMessages}`);
        }
    } catch (error) {
        console.error('Error restoring all device configurations:', error);
        // Progress modal will show failures, no need for an alert
    }
}

/*
async function restoreAllDevicesConfig() {
        // Show the modal
        document.getElementById('progressModal').style.display = 'block';
        // Close modal when clicking on <span> (x) or outside the modal
        const closeProgressModalModal = document.querySelector('#progressModal .close');
        closeProgressModalModal.onclick = function() {
            progressModal.style.display = 'none';
        };
        try {
            const response = await fetch('/restore_all_device_configs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const result = await response.json();
            //console.log(result);
            if (result.success) {
                alert('All device configurations restored successfully.');
            } else {
                const errorMessages = result.errors.map(error => `Device: ${error.device}, Message: ${error.message}`).join('\n');
                alert(`Failed to restore all device configurations:\n${errorMessages}`);
            }
        } catch (error) {
            console.error('Error restoring all device configurations:', error);
            alert('Error restoring all device configurations: ' + error.message);
        }
    }
*/
async function showGeneratedConfig() {
            setButtonClicked('showGeneratedConfigBtn');
            const form = document.getElementById('uploadForm');
            const configMethod = document.getElementById('config_method').value;
            if (configMethod === 'csv') {
                form.action = '/show_csvgenerated_config';
            } else {
                form.action = '/show_generated_config';
            }
            form.submit();
        }

window.onload = function() {
    var addDeviceModal = document.getElementById("addDeviceModal");
    var addDeviceBtn = document.getElementById("addDeviceBtn");
    var closeDeviceModal = document.getElementById("closeDeviceModal");
    var addDeviceForm = document.getElementById("addDeviceForm");

    // Check if addDeviceForm exists
    if (addDeviceForm) {
        // Handle form submission via AJAX
        addDeviceForm.onsubmit = async function(event) {
            event.preventDefault(); // Prevent default form submission

            // Collect form data
            const formData = {
                hostname: document.getElementById('newDeviceHostname').value,
                ip: document.getElementById('newDeviceIP').value,
                username: document.getElementById('newDeviceUsername').value,
                password: document.getElementById('newDevicePassword').value,
            };

            try {
                // Send form data via POST request to /add_device
                const response = await fetch('/add_device', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();

                if (response.ok) {
                    alert('Device added successfully!');
                    addDeviceModal.style.display = "none"; // Close modal on success
                    fetchOnboardedDevices(); // Fetch the updated list of onboarded devices
                } else {
                    alert('Failed to add device: ' + result.message);
                }
            } catch (error) {
                console.error('Error adding device:', error);
                alert('Error adding device.');
            }
        };
    } else {
        console.error('Form with id "addDeviceForm" not found');
    }

    // Show modal when Add Device button is clicked
    if (addDeviceBtn) {

        addDeviceBtn.onclick = function() {
            addDeviceModal.style.display = "block";
        };
    }
    // Close the modal when the 'X' is clicked
    if (closeDeviceModal) {
        closeDeviceModal.onclick = function() {
            addDeviceModal.style.display = "none";
        };
    }
    // Close the modal when clicking outside the modal content
    window.onclick = function(event) {
        if (event.target == addDeviceModal) {
            addDeviceModal.style.display = "none";
        }
    };
};
    //delete Onboarded Devices
async function deleteDevice(deviceId) {
        try {
            const response = await fetch(`/delete_device/${deviceId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const result = await response.json();
            if (result.success) {
                fetchOnboardedDevices();
            } else {
                console.error('Failed to delete device');
            }
        } catch (error) {
            console.error('Error deleting device:', error);
        }
    }

async function showDeviceConfig(deviceId, hostname) {
    // Show the progress modal
    const progressModal = document.getElementById('progressModal');
    progressModal.style.display = 'block';

    // Set up close behavior to clear the progress when the modal is closed
    const closeModalButton = document.getElementById('cancelButton'); // Assuming there's a cancel button to close the modal
    if (closeModalButton) {
        closeModalButton.onclick = function () {
            clearProgressBar();
            progressModal.style.display = 'none';
        };
    }

    try {
        // Fetch the device configuration
        const response = await fetch(`/fetch_device_config/${deviceId}`);
        const data = await response.json();

        if (response.ok) {
            // Open a new window to display the configuration
            const configWindow = window.open('', '_blank', 'width=800,height=600');

            // Write the fetched config data into the new window
            configWindow.document.write(`
                <html>
                <head>
                    <title>Device Configuration - ${hostname}</title>
                    <style>
                        body { font-family: Arial, sans-serif; padding: 20px; }
                        pre { white-space: pre-wrap; word-wrap: break-word; }
                    </style>
                </head>
                <body>
                    <h2>Configuration for ${hostname}</h2>
                    <pre>${data.config}</pre>
                    <button id="downloadBtn">Download Config</button>
                </body>
                </html>
            `);

            // Add functionality to download the configuration in the new window
            const downloadBtn = configWindow.document.getElementById('downloadBtn');
            downloadBtn.onclick = function () {
                const blob = new Blob([data.config], { type: 'text/plain' });
                const link = configWindow.document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = `${hostname}_config.txt`;
                link.click();
                URL.revokeObjectURL(link.href);  // Clean up URL after download
            };

            // Close the progress modal after success
            clearProgressBar();
            progressModal.style.display = 'none';

        } else {
            // Handle the error in case of a failure
            console.error('Failed to fetch device config:', data.message);

            // Update progress bar or progress text to show the error
            const progressText = document.getElementById('progressText');
            progressText.textContent = `Error: ${data.message}`;
        }

    } catch (error) {
        // Keep the modal open and show the error message if there is a failure
        console.error('Error fetching device configuration:', error);

        // Update the progress text to show the error
        const progressText = document.getElementById('progressText');
        progressText.textContent = `Error: ${error.message}`;
    }
}

// Function to clear the progress bar and list
function clearProgressBar() {
    // Reset the progress bar value and progress text
    const overallProgressBar = document.getElementById('overallProgressBar');
    const progressText = document.getElementById('progressText');
    if (overallProgressBar) {
        overallProgressBar.value = 0;
    }
    if (progressText) {
        progressText.textContent = '0% Complete';
    }

    // Clear the device progress list (if you have a list showing progress per device)
    const deviceProgressList = document.getElementById('deviceProgressList');
    if (deviceProgressList) {
        deviceProgressList.innerHTML = '';  // Clear all list items
    }
}



   // Define the updateDeviceConfiguration function
async function updateDeviceConfiguration(deviceId, config) {
    try {
        const response = await fetch(`/update_device_configuration/${deviceId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: config })
        });
        const result = await response.json();
        if (result.success) {
            alert('Device configuration updated successfully.');
        } else {
            alert(`Failed to update device configuration: ${result.error}`);
        }
    } catch (error) {
        console.error('Error updating device configuration:', error);
        alert(`Error updating device configuration: ${error.message}`);
    }
}

    // Example of how downloadConfig function could be defined
function downloadConfig(content, filename) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}
    // Show device configuration
async function saveDeviceConfig(row, deviceId) {
    // Ensure the modal is shown when the save process begins
    document.getElementById('progressModal').style.display = 'block';

    if (row.cells.length < 4) {
        console.error(`Row structure is incorrect or missing cells. Cells found: ${row.cells.length}`);
        return;  // Exit without alerts; console log will suffice
    }

    const hostname = row.cells[1].textContent.trim();
    const username = row.cells[3].querySelector('input').value.trim();
    const password = row.cells[4].querySelector('input').value.trim();
    const deviceData = { id: deviceId, hostname: hostname, username: username, password: password };

    const overallProgressBar = document.getElementById('overallProgressBar');
    const progressText = document.getElementById('progressText');
    const deviceProgressList = document.getElementById('deviceProgressList');

    try {
        // Fetch the current configuration of the device
        const configResponse = await fetch(`/fetch_device_config/${deviceId}`);
        if (!configResponse.ok) {
            if (configResponse.status === 401) {
                window.location.href = '/login';
                return;
            }
            const errorData = await configResponse.json();
            throw new Error(errorData.message || 'Failed to fetch device configuration');
        }

        const configData = await configResponse.json();
        const dataToSend = { deviceData, configData };

        // Start saving the device configuration
        const response = await fetch('/save_device_config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(dataToSend)
        });

        if (!response.ok) {
            if (response.status === 401) {
                window.location.href = '/login';
                return;
            }
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to save device configuration');
        }

        // Handle the result of the save operation
        const result = await response.json();
        if (result.success) {
            // Update progress for the specific device
            let deviceStatusElement = document.querySelector(`#device-status-${hostname}`);
            if (!deviceStatusElement) {
                deviceStatusElement = document.createElement('li');
                deviceStatusElement.id = `device-status-${hostname}`;
                deviceProgressList.appendChild(deviceStatusElement);
            }
            deviceStatusElement.textContent = `Device ${hostname}: Configuration saved successfully`;
            deviceStatusElement.style.color = 'green';

            // Update overall progress bar (assuming it's part of a bigger operation)
            if (overallProgressBar) {
                overallProgressBar.value = 100;  // Since it's a single device, you can set it to 100%
                progressText.textContent = `100% Complete`;
            }
        } else {
            // Handle failure case
            let deviceStatusElement = document.querySelector(`#device-status-${hostname}`);
            if (!deviceStatusElement) {
                deviceStatusElement = document.createElement('li');
                deviceStatusElement.id = `device-status-${hostname}`;
                deviceProgressList.appendChild(deviceStatusElement);
            }
            deviceStatusElement.textContent = `Device ${hostname}: Failed to save configuration - ${result.error}`;
            deviceStatusElement.style.color = 'red';
        }

    } catch (error) {
        // Handle any errors during the process
        console.error('Error saving device configuration:', error);
        let deviceStatusElement = document.querySelector(`#device-status-${hostname}`);
        if (!deviceStatusElement) {
            deviceStatusElement = document.createElement('li');
            deviceStatusElement.id = `device-status-${hostname}`;
            deviceProgressList.appendChild(deviceStatusElement);
        }
        deviceStatusElement.textContent = `Device ${hostname}: Error - ${error.message}`;
        deviceStatusElement.style.color = 'red';
    }
}


async function updateDeviceConfig(row, hostname) {
        // Extracting values from the row
        const username = row.cells[3].querySelector('input').value.trim();
        const password = row.cells[4].querySelector('input').value.trim();
        // Preparing the data to send to the server
        const deviceData = { hostname: hostname, username: username, password: password };
        try {
            // Making the POST request to update the device configuration
            const response = await fetch('/update_device_config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(deviceData)  // Send hostname instead of deviceId
            });

            // Parsing the response
            const result = await response.json();

            // Handling the response
            if (result.success) {
                alert('Device username/password updated successfully.');
            } else {
                alert(`Failed to update device configuration: ${result.error}`);
            }
        } catch (error) {
            // Catching any errors and displaying them
            console.error('Error updating device username/password:', error);
            alert(`Error updating device configuration: ${error.message}`);
        }
    }



// Handle Copy Image button
const copyOnboardSelectedImageBtn = document.getElementById('copyOnboardSelectedImage');
if (copyOnboardSelectedImageBtn) {
    copyOnboardSelectedImageBtn.addEventListener('click', function() {
        const imageSelect = document.getElementById('installImageSelect');
        const image = imageSelect.value;
        installImage(image, 'copyOnboardSelectedImage');
    });
}

// Handle Install Image button
const installSelectedImageBtn = document.getElementById('installSelectedImageBtn');
if (installSelectedImageBtn) {
    installSelectedImageBtn.addEventListener('click', function() {
        const imageSelect = document.getElementById('installImageSelect');
        const image = imageSelect.value;
        installImage(image, 'installSelectedImageBtn');
    });
}



// Handle Show File button click
const showSelectedImageBtn = document.getElementById('showSelectedImageBtn');
if (showSelectedImageBtn) {
    showSelectedImageBtn.addEventListener('click', function() {
        var selectedFile = document.getElementById('uploadedImagesSelect').value;
        if (selectedFile) {
            $.ajax({
                url: '/show_file_content',
                type: 'POST',
                data: { filename: selectedFile },
                success: function(response) {
                    var editor = ace.edit("editor");
                    editor.setTheme("ace/theme/monokai");
                    editor.session.setMode("ace/mode/text");
                    editor.setValue(response.content, -1);
                    document.getElementById('fileContentEditor').dataset.filename = selectedFile;
                    document.getElementById('fileContentEditor').classList.remove('hidden');
                },
                error: function() {
                    alert('Error loading file content.');
                }
            });
        } else {
            alert('Please select a file first.');
        }
    });
}
// Handle Save File Content button click
const saveFileContentBtn = document.getElementById('saveFileContentBtn');
if (saveFileContentBtn) {
    saveFileContentBtn.addEventListener('click', function() {
        var editor = ace.edit("editor");
        var content = editor.getValue();
        var filename = document.getElementById('fileContentEditor').dataset.filename;
        $.ajax({
            url: '/save_file_content',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ filename: filename, content: content }),
            success: function(response) {
                alert('File content saved successfully.');
            },
            error: function() {
                alert('Error saving file content.');
            }
        });
    });
}

let devices = [];  // This will hold the list of devices fetched initially

// Function to fetch the list of devices when the app starts
async function fetchOnboardedDevices() {
    try {
        const response = await fetch('/api/devices');
        if (!response.ok) {
            throw new Error('Failed to fetch onboarded devices');
        }
        devices = await response.json();  // Store the devices in a global variable

        const tableBody = document.querySelector('#onboardedDevicesTable tbody');
        tableBody.innerHTML = '';  // Clear the table before updating

        // Populate the table with the fetched devices
        devices.forEach(device => {
            const row = tableBody.insertRow();
            row.setAttribute('data-device-id', device.hostname);
            const checkboxCell = row.insertCell(0);
            checkboxCell.innerHTML = '<input type="checkbox" class="device-checkbox">';
            const hostnameCell = row.insertCell(1);
            hostnameCell.textContent = device.hostname;
            row.insertCell(2).textContent = device.ip;
            row.insertCell(3).innerHTML = `<input type="text" value="${device.username}" />`;
            row.insertCell(4).innerHTML = `<input type="text" value="${device.password}" />`;
            const actionsCell = row.insertCell(5);

            const deleteButton = document.createElement('button');
            deleteButton.innerHTML = '🗑️';
            deleteButton.title = 'Delete Device';
            deleteButton.classList.add('small-btn');
            deleteButton.type = 'button'; // Prevent form submission
            deleteButton.addEventListener('click', function() {
                deleteDevice(device.hostname);
            });

            const saveButton = document.createElement('button');
            saveButton.innerHTML = '💾';
            saveButton.title = 'Save Device Config';
            saveButton.classList.add('small-btn');
            saveButton.type = 'button'; // Prevent form submission
            saveButton.addEventListener('click', function() {
                saveDeviceConfig(row, device.hostname);
            });

            const updateButton = document.createElement('button');
            updateButton.innerHTML = '🔄';
            updateButton.title = 'Update User/Pass';
            updateButton.classList.add('small-btn');
            updateButton.type = 'button'; // Prevent form submission
            updateButton.addEventListener('click', function() {
                updateDeviceConfig(row, device.hostname);
            });

            const showButton = document.createElement('button');
            showButton.innerHTML = '👁️';
            showButton.title = 'Show Device Config';
            showButton.classList.add('small-btn');
            showButton.type = 'button'; // Prevent form submission
            showButton.addEventListener('click', function() {
                showDeviceConfig(device.hostname, device.hostname);
            });

            const restoreButton = document.createElement('button');
            restoreButton.innerHTML = '♻️';
            restoreButton.title = 'Restore Device Config';
            restoreButton.classList.add('small-btn');
            restoreButton.type = 'button'; // Prevent form submission
            restoreButton.addEventListener('click', function() {
                restoreDeviceConfig(device.hostname);
            });

            actionsCell.appendChild(deleteButton);
            actionsCell.appendChild(saveButton);
            actionsCell.appendChild(updateButton);
            actionsCell.appendChild(showButton);
            actionsCell.appendChild(restoreButton);
            const progressCell = row.insertCell(6);
        });

    } catch (error) {
        console.error('Error fetching devices:', error);
    }
}
fetchOnboardedDevices();


// Function to periodically check the device health
async function checkDeviceHealth() {
    try {
        if (devices.length === 0) {
            console.warn('No devices to check health for.');
            return;
        }

        const healthStatusResponse = await fetch('/check_device_health', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ devices })
        });
        const healthData = await healthStatusResponse.json();
        const healthStatus = healthData.health_status;

        //console.log("Health status object:", healthStatus);

        const tableBody = document.querySelector('#onboardedDevicesTable tbody');

        devices.forEach(device => {
            const row = tableBody.querySelector(`tr[data-device-id="${device.hostname}"]`);
            if (row) {
                const hostnameCell = row.cells[1];
                let color = '';
                let tooltip = '';

                const status = healthStatus[device.hostname];

                if (status === 'unreachable') {
                    color = '#ec7063';
                    tooltip = 'Unreachable';
                } else if (status === 'unknown') {
                    color = 'gray';
                    tooltip = 'Unknown, not in database';
                } else if (status === 'connect_error') {
                    color = '#FFA07A';
                    tooltip = 'Connection Error';
                } else if (status === 'auth_error') {
                    color = '#FF8000';
                    tooltip = 'Authentication Error';
                } else if (status === 'reachable') {
                    color = 'green';
                    tooltip = 'Reachable';
                }

                hostnameCell.style.color = color;
                hostnameCell.title = tooltip;
            }
        });

    } catch (error) {
        console.error('Error checking device health:', error);
    }
}




async function fetchUploadedImages() {
    try {
        const response = await fetch('/api/images');
        if (!response.ok) {
            throw new Error('Failed to fetch images');
        }
        const result = await response.json();
        if (!result.success) {
            console.error('Error fetching images:', result.error);
            return;
        }

        const images = result.images;
        //console.log(images)
        const uploadedImagesSelect = document.getElementById('uploadedImagesSelect');
        uploadedImagesSelect.innerHTML = '<option value="" disabled selected>Select file to delete</option>';

        const installImageSelect = document.getElementById('installImageSelect');
        installImageSelect.innerHTML = '<option value="" disabled selected>Select an image to install</option>';

        images.forEach(image => {
            const deleteOption = document.createElement('option');
            deleteOption.value = image;
            deleteOption.textContent = image;
            uploadedImagesSelect.appendChild(deleteOption);

            if (image.includes('install')) {
                const installOption = document.createElement('option');
                installOption.value = image;
                installOption.textContent = image;
                installImageSelect.appendChild(installOption);
            }
        });
    } catch (error) {
        console.error('Error fetching uploaded images:', error);
    }
}
fetchUploadedImages();


//**** Event listeners for device and image management ****//
const uploadCsvBtn = document.getElementById('uploadCsvBtn');
if (uploadCsvBtn) {
    uploadCsvBtn.addEventListener('click', uploadCsvFile);
}

const uploadImageBtn = document.getElementById('uploadImageBtn');
if (uploadImageBtn) {
    uploadImageBtn.addEventListener('click', uploadImageFile);
}



const stopImageCopyBtn = document.getElementById('stopImageCopyBtn');
if (stopImageCopyBtn) {
    stopImageCopyBtn.addEventListener('click', stopImageCopy);
}

const saveAllBtn = document.getElementById('saveAllBtn');
if (saveAllBtn) {
    saveAllBtn.addEventListener('click', saveAllDevicesConfig);

}


const restoreAllBtn = document.getElementById('restoreAllBtn');
if (restoreAllBtn) {
    restoreAllBtn.addEventListener('click', restoreAllDevicesConfig);
}
//*** END of Event Listener ***//

const button = document.getElementById('toggleOnboardFormBtn');
        if (button) {
            button.addEventListener('click', function() {
                fetchOnboardedDevices();
                fetchUploadedImages();
            });
        }

function openModal() {
        document.getElementById('progressModal').style.display = 'block';
    }

// Function to close the modal and clear the device progress list
    function closeModalAndClearProgress() {
        const progressModal = document.getElementById('progressModal');
        progressModal.style.display = 'none';

        // Clear the device progress list
        const deviceProgressList = document.getElementById('deviceProgressList');
        deviceProgressList.innerHTML = '';  // Clear all list items
    }


 // Set up the event listener for the "Cancel" button to close modal and clear progress
    const cancelButton = document.getElementById('cancelButton');
    if (cancelButton) {
        cancelButton.addEventListener('click', closeModalAndClearProgress);
    }


  // Get the modal
var sampleCsvOnboardModal = document.getElementById("sampleCsvOnboardDeviceModal");

if (sampleCsvOnboardModal) {
    // Add the content to the modal
    sampleCsvOnboardModal.innerHTML = `
        <div class="modal-content">
            <span class="close">&times;</span>
            <p>CSV File Example:</p>
            <pre>
hostname,ip,username,password
san-q5120-02,san-q5120-02,root,Embe1mpls
san-q5120-03,san-q5120-03,root,Embe1mpls
san-q5130-02,san-q5130-02,root,Embe1mpls
            </pre>
        <button id="OnboardmodalCloseBtn" class="btn btn-secondary">Close</button>
        </div>
    `;

    // Get the button that opens the modal
    var sampleuploadCsvBtn = document.getElementById("OnBoardSampleCsvBtn");
    // Get the <span> element that closes the modal
    var sampleuploadCsvBtnClose = sampleCsvOnboardModal.querySelector(".close");
    var OnboardmodalCloseBtn = document.getElementById("OnboardmodalCloseBtn");
    // Open the modal when the button is clicked
    if (sampleuploadCsvBtn) {
        sampleuploadCsvBtn.onclick = function() {
            sampleCsvOnboardModal.style.display = "block";
        }
    }

    // Close the modal when the close button is clicked
    if (sampleuploadCsvBtnClose) {
        sampleuploadCsvBtnClose.onclick = function() {
            sampleCsvOnboardModal.style.display = "none";
        }
    }
    // Close the modal when the close button inside the modal is clicked
    if (OnboardmodalCloseBtn) {
        OnboardmodalCloseBtn.onclick = function() {
            sampleCsvOnboardModal.style.display = "none";
        }
    }
    // Close the modal when the user clicks outside the modal
    window.onclick = function(event) {
        if (event.target == sampleCsvOnboardModal) {
            sampleCsvOnboardModal.style.display = "none";
        }
    }
}



async function installImage(image, action) {
    const checkboxes = document.querySelectorAll('.device-checkbox:checked');
    const deviceIds = Array.from(checkboxes).map(checkbox => {
        const tr = checkbox.closest('tr');
        return tr ? tr.getAttribute('data-device-id') : null;
    }).filter(id => id !== null);

    if (deviceIds.length === 0) {
        alert('Please select at least one device.');
        return;
    }

    if (!image) {
        alert('Missing image name.');
        console.error('Image name:', image, 'Device IDs:', deviceIds);
        return;
    }

    try {
        const payload = JSON.stringify({ imageName: image, deviceIds: deviceIds, action: action });
        const response = await fetch('/install_image', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload
        });

        if (!response.ok) {
            const errorText = await response.text();
            alert('Error uploading Image: ' + errorText);
            return;
        }

        const result = await response.json();
        if (result.success) {
            result.status.forEach((stage, index) => {
                const deviceId = deviceIds[index];
                if (stage === 200) {
                    console.log('Image exists');
                    //updateProgress(deviceId, 'exists', 100);
                } else if (stage === 201) {
                    console.log('Image Copying');
                    //updateProgress(deviceId, 'copying', 100);
                } else if (stage === 202) {
                    console.log('Image Installing');
                    //updateProgress(deviceId, 'installing', 100);
                }
            });
        } else {
            if (result.errors && Array.isArray(result.errors)) {
                result.errors.forEach(error => alert(`Device Error: ${error}`));
            } else {
                alert('Error during operation: ' + (result.errors || 'Unknown error occurred'));
            }
        }
    } catch (error) {
        console.error('Error performing operation:', error);
        alert('Error during operation. Please check the console for more details.');
    }
}




let progressCache = {};

function debounce(func, delay) {
    let timeoutId;
    return function (...args) {
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
        timeoutId = setTimeout(() => {
            func(...args);
        }, delay);
    };
}





// Function to retry fetching the device row if it's not found immediately
function getDeviceRow(device_id, attempt = 0, maxAttempts = 3, retryDelay = 100) {
    return new Promise((resolve, reject) => {
        const deviceRow = document.querySelector(`tr[data-device-id="${device_id}"]`);
        if (deviceRow) {
            console.log(`Device row found for ${device_id}, attempt: ${attempt}`);
            resolve(deviceRow);
        } else if (attempt < maxAttempts) {
            console.log(`Retrying to find device row: ${device_id}, attempt: ${attempt}`);
            setTimeout(() => {
                resolve(getDeviceRow(device_id, attempt + 1, maxAttempts, retryDelay));
            }, retryDelay);
        } else {
            console.error(`Failed to find device row for ${device_id} after ${maxAttempts} attempts`);
            reject(`Device row not found for device: ${device_id}`);
        }
    });
}


// Listen for install progress updates from the server
socket.on('install_progress', function (data) {
    const { device_id, stage, progress, message } = data;  // Ensure message is included
    // Log the data received for debugging
    //console.log(`Received progress for Device: ${device_id}, Stage: ${stage}, Progress: ${progress}%, Message: ${message || 'No message'}`);

    // Fetch device row with retries
    getDeviceRow(device_id)
        .then(deviceRow => {
            const progressCell = deviceRow.querySelector('.progress-cell');
            if (progressCell) {
                let newText = '';

                // Handle different stages of progress
                switch(stage) {
                    case 'installing':
                        newText = `Installing.. ${progress}%`;  // Show installing state
                        break;
                    case 'copying':
                        newText = `Copying.. ${progress}%`;  // Show copying progress
                        break;
                    case 'exists':
                        newText = message;  // Image already exists
                        break;
                    case 'copycomplete':
                        newText = message;  // Copying complete message
                        break;
                    case 'install_complete':
                        newText = `Install.. ${progress}%`;  // Installation complete
                        break;
                    case 'rebooting':
                        newText = 'Rebooting';  // Device is rebooting
                        break;
                    case 'DupVersion':
                        newText = 'Matching Version';
                        break;
                    case 'device_online':
                        newText = 'Device online';  // Device is back online
                        break;
                    case 'version_check':
                        newText = message || 'Version Match Success';  // Installed version verified
                        break;
                    case 'error':
                        //newText = `Error: ${message}`;  // Display error message
                        newText = message.startsWith('ERROR') ? `Error: ${message}` : message;  // Display error message
                        break;
                    case 'message':
                        newText = message;
                        break;
                    default:
                        newText = '';  // Clear progress for other stages
                }

                progressCell.textContent = newText;
                console.log(`Progress updated for ${device_id}: ${newText}`); // Debugging log
            } else {
                console.error(`Progress cell not found for device: ${device_id}`);
            }
        })
        .catch(error => {
            console.error(error);
        });
});



//progress bar for restoreAllDevicesConfig//
const updateProgress2 = (device_ip, stage, progress, error) => {
const deviceRow = document.querySelector(`tr[data-device-ip="${device_ip}"]`);
if (deviceRow) {
    const progressCell = deviceRow.querySelector('.progress-cell');
    if (progressCell) {
        if (error) {
            progressCell.textContent = 'Error occurred';
            alert('Error: ' + error);
        } else {
            progressCell.textContent = `${stage}... ${progress}%`;
        }
    }
}
};
/*
//progress bar for restoreAllDevicesConfig//
socket.on('progress', function(data) {
    const { ip, stage, progress, error } = data;
    updateProgress2(ip, stage, progress, error);
});
*/



/*
//progress bar for saveAllDeviceConfig//
const updateProgressSave = (device_hostname, stage, progress, error) => {
const deviceRow = document.querySelector(`tr[data-device-hostname="${device_hostname}"]`);
if (deviceRow) {
    const progressCell = deviceRow.querySelector('.progress-cell');
    if (progressCell) {
        if (error) {
            progressCell.textContent = 'Error occurred';
            alert('Error: ' + error);
        } else {
            progressCell.textContent = `${stage}... ${progress}%`;
        }
    }
    }
};

socket.on('save_progress', function(data) {
    const { device, stage, progress, error } = data;
    updateProgressSave(device, stage, progress, error);
 });


// Close modal event listener
const progressModal = document.getElementById('progressModal');
const closeModal = document.querySelector('#progressModal .close');
closeModal.onclick = function() {
progressModal.classList.add('hidden');
progressModal.style.display = 'none';
};
window.onclick = function(event) {
if (event.target === progressModal) {
    progressModal.classList.add('hidden');
    progressModal.style.display = 'none';
}
};
*/
 // Function to load the uploaded images into the select element
        function loadUploadedImages() {
            $.ajax({
                url: '/list_uploaded_images',
                type: 'GET',
                success: function(response) {
                    var select = $('#uploadedImagesSelect');
                    select.empty();
                    select.append('<option value="" disabled selected>Select file to delete</option>');
                    response.files.forEach(function(file) {
                        select.append('<option value="' + file + '">' + file + '</option>');
                    });
                },
                error: function() {
                    alert('Error loading uploaded images.');
                }
            });
        }

        $(document).ready(function() {
            loadUploadedImages();
        });



        // Handle Close Editor button click
        $('#closeEditorBtn').on('click', function() {
            $('#fileContentEditor').addClass('hidden');
        });

});
