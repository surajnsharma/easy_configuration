//Backup of onboard_devices.js //

document.addEventListener('DOMContentLoaded', function() {
        let devices = [];  // This will hold the list of devices fetched initially
        const socket = io(); // Ensure it's connecting


      // Check if the element exists before adding an event listener
        const deleteSelectedImageBtn = document.getElementById('deleteSelectedImageBtn');
        if (deleteSelectedImageBtn) {
            deleteSelectedImageBtn.addEventListener('click', async function () {
                const selectedImage = document.getElementById('uploadedImagesSelect').value;

                if (!selectedImage) {
                    console.error('No image selected for deletion');
                    alert('Please select a file first.');
                    return;
                }

                try {
                    // Split the selectedImage into folder and filename
                    const parts = selectedImage.split('/');
                    const filename = parts.pop(); // Extract the last part as filename
                    const folder = parts.join('/'); // Remaining parts as the folder path

                    if (!filename || !folder) {
                        console.error('Invalid file or folder selection.');
                        alert('Invalid file or folder selection.');
                        return;
                    }

                    const response = await fetch(`/delete_file/${encodeURIComponent(filename)}?folder=${encodeURIComponent(folder)}`, {
                        method: 'DELETE',
                    });

                    if (response.ok) {
                        const result = await response.json();
                        if (result.success) {
                            alert(result.message || 'File deleted successfully.');
                            loadUploadedImages(); // Refresh the file list
                        } else {
                            alert(result.error || 'Error deleting file.');
                        }
                    } else {
                        const errorText = await response.text();
                        console.error(`Server error: ${errorText}`);
                        alert(`Error deleting file: ${errorText}`);
                    }
                } catch (error) {
                    console.error('Error deleting file:', error);
                    alert(`An error occurred: ${error.message}`);
                }
            });
        }

        async function openSshTerminal(ip, username, password) {
            console.log("Opening SSH Terminal:", { ip, username, password }); // Debugging

            if (!ip || !username || !password) {
                alert("Missing IP, username, or password.");
                return;
            }

            fetch('/open_ssh_terminal', {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ip, username, password })
            })
            .then(response => response.json())
            .then(result => {
                console.log("SSH Response:", result);
                if (!result.success) {
                    alert("Failed to open SSH terminal: " + result.message);
                }
            })
            .catch(error => {
                console.error("Error opening SSH terminal:", error);
            });
        }

        async function deleteSelectedDevices() {
            const selectedDevices = Array.from(document.querySelectorAll('.device-checkbox:checked'))
                .map(checkbox => checkbox.closest('tr').getAttribute('data-device-id'));

            if (selectedDevices.length === 0) {
                alert('No devices selected for deletion.');
                return;
            }

            try {
                const response = await fetch('/delete_selected_devices', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ devices: selectedDevices })
                });

                if (!response.ok) {
                    const text = await response.text();
                    console.error('Server error response:', text);
                    throw new Error(`Server error: ${text}`);
                }

                const result = await response.json();
                if (result.success) {
                    fetchOnboardedDevices();
                } else {
                    console.error('Failed to delete selected devices:', result.message);
                }
            } catch (error) {
                console.error('Error deleting selected devices:', error);
            }
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
                    loadUploadedImages()    // Call this after the CSV upload is successful
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
                            loadUploadedImages();  // Fetch uploaded images if the upload is complete
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

        function getDeviceRow(device_id, maxAttempts = 3, retryDelay = 100) {
            return new Promise((resolve, reject) => {
                let attempts = 0;
                const interval = setInterval(() => {
                    const deviceRow = document.querySelector(`tr[data-device-id="${device_id}"]`);
                    if (deviceRow) {
                        //console.log(`✅ Device row found for ${device_id} after ${attempts} attempts`);
                        clearInterval(interval);
                        resolve(deviceRow);
                    } else if (++attempts >= maxAttempts) {
                        clearInterval(interval);
                        console.error(`❌ Failed to find device row for ${device_id} after ${maxAttempts} attempts`);
                        reject(`Device row not found for device: ${device_id}`);
                    }
                }, retryDelay);
            });
        }

        async function saveAllDevicesConfig() {
                const progressModal = document.getElementById('onboardProgressModal');
                const progressBar = document.getElementById('overallProgressBar');
                const progressText = document.getElementById('progressText');
                const deviceProgressList = document.getElementById('deviceProgressList');

                if (progressBar) progressBar.value = 0; // Reset the progress bar to 0
                if (progressText) progressText.textContent = '0% Complete'; // Reset progress text
                if (deviceProgressList) deviceProgressList.innerHTML = ''; // Clear the device progress list

                // Show the modal or loader
                document.getElementById('onboardProgressModal').style.display = 'block';

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
                            loadUploadedImages();
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
        // Clear the modal content before showing it
            const progressModal = document.getElementById('onboardProgressModal');
            const progressBar = document.getElementById('overallProgressBar');
            const progressText = document.getElementById('progressText');
            const deviceProgressList = document.getElementById('deviceProgressList');

            if (progressBar) progressBar.value = 0; // Reset the progress bar to 0
            if (progressText) progressText.textContent = '0% Complete'; // Reset progress text
            if (deviceProgressList) deviceProgressList.innerHTML = ''; // Clear the device progress list

            document.getElementById('onboardProgressModal').style.display = 'block';  // Show the progress modal

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
            const progressModal = document.getElementById('onboardProgressModal');
            const progressBar = document.getElementById('overallProgressBar');
            const progressText = document.getElementById('progressText');
            const deviceProgressList = document.getElementById('deviceProgressList');

            if (progressBar) progressBar.value = 0; // Reset the progress bar to 0
            if (progressText) progressText.textContent = '0% Complete'; // Reset progress text
            if (deviceProgressList) deviceProgressList.innerHTML = ''; // Clear the device progress list

            // Show the modal
            document.getElementById('onboardProgressModal').style.display = 'block';

            // Close modal when clicking on <span> (x) or outside the modal (optional, but not required for your case)
            const closeProgressModalModal = document.querySelector('#onboardProgressModal .close');
            if (closeProgressModalModal) {
                closeProgressModalModal.onclick = function() {
                    const progressModal = document.getElementById('onboardProgressModal');
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
            // Get necessary UI elements
            const progressModal = document.getElementById('onboardProgressModal');
            const progressBar = document.getElementById('overallProgressBar');
            const progressText = document.getElementById('progressText');
            const deviceProgressList = document.getElementById('deviceProgressList');
            const errorContainer = document.getElementById('progressErrorMessage'); // Dedicated error message container
            const closeModalButton = document.getElementById('cancelButton');

            // Reset UI elements before starting
            if (progressBar) progressBar.value = 0; // Reset progress bar
            if (progressText) progressText.textContent = '0% Complete'; // Reset progress text
            if (deviceProgressList) deviceProgressList.innerHTML = ''; // Clear previous device progress
            if (errorContainer) {
                errorContainer.textContent = ''; // Clear previous errors
                errorContainer.style.display = 'none'; // Hide error message initially
            }

            // Show the progress modal
            progressModal.style.display = 'block';

            // Set up modal close behavior
            if (closeModalButton) {
                closeModalButton.onclick = function () {
                    clearProgressBar();
                    progressModal.style.display = 'none';
                };
            }

            try {
                // Fetch the device configuration from the server
                const response = await fetch(`/fetch_device_config/${deviceId}`);
                const data = await response.json();

                if (response.ok) {
                    // Open a new window for displaying the configuration
                    const configWindow = window.open('', '_blank', 'width=800,height=600');

                    // Inject configuration details into the new window
                    configWindow.document.write(`
                        <html>
                        <head>
                            <title>Device Configuration - ${hostname}</title>
                            <style>
                                body { font-family: Arial, sans-serif; padding: 20px; }
                                pre { white-space: pre-wrap; word-wrap: break-word; }
                                button { margin-top: 10px; padding: 8px 12px; font-size: 14px; cursor: pointer; }
                            </style>
                        </head>
                        <body>
                            <h2>Configuration for ${hostname}</h2>
                            <pre>${data.config}</pre>
                            <button id="downloadBtn">Download Config</button>
                        </body>
                        </html>
                    `);

                    // Attach download functionality inside the new window
                    configWindow.document.getElementById('downloadBtn').onclick = function () {
                        const blob = new Blob([data.config], { type: 'text/plain' });
                        const link = configWindow.document.createElement('a');
                        link.href = URL.createObjectURL(blob);
                        link.download = `${hostname}_config.txt`;
                        link.click();
                        URL.revokeObjectURL(link.href); // Cleanup
                    };

                    // Close the progress modal on success
                    clearProgressBar();
                    progressModal.style.display = 'none';

                } else {
                    // API failure: Show error **ONLY IN THE PROGRESS MODAL**, not the table
                    console.error(`❌ Failed to fetch config for ${hostname}:`, data.message);


                }

            } catch (error) {
                // Handle unexpected errors (e.g., network issues)
                console.error('❌ Network or Server Error:', error);


            }
        }

        socket.on('install_progress', function (data) {
            //console.log('🔥 WebSocket Event Received:', JSON.stringify(data, null, 2));

            let { device_id, stage, progress, message } = data;

            if (!device_id || typeof device_id !== "string") {
                console.error("❌ Invalid device_id received:", data);
                return;
            }
            device_id = device_id.trim();

            getDeviceRow(device_id)
                .then(deviceRow => {
                    if (!deviceRow) {
                        console.error(`❌ Device row not found for device ID: ${device_id}`);
                        return;
                    }

                    // ✅ Find the correct progress cell (Column Index: 7)
                    let columns = deviceRow.querySelectorAll("td");
                    let progressCell = columns[7]; // Updated index from 6 to 7

                    if (!progressCell) {
                        console.warn(`⚠️ Progress cell missing for ${device_id}, creating dynamically.`);
                        progressCell = document.createElement("td");
                        progressCell.classList.add("progress-status-cell");
                        deviceRow.appendChild(progressCell); // Append to row if missing
                    }

                    // ✅ Ensure progress bar exists inside progressCell
                    let progressBar = progressCell.querySelector('.progress-bar');
                    if (!progressBar) {
                        console.warn(`⚠️ Progress bar missing for ${device_id}, adding dynamically.`);
                        progressCell.innerHTML = `
                            <div class="progress" style="height: 20px;">
                                <div class="progress-bar bg-warning text-dark-blue" role="progressbar"
                                     style="width: 0%; color: #003366; font-weight: bold; padding: 5px; white-space: nowrap;"
                                     aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">Initializing...</div>
                            </div>
                        `;
                        progressBar = progressCell.querySelector('.progress-bar');
                    }

                    //console.log(`🔄 Progress Update: Stage: ${stage}, Message: ${message}`);

                    // ✅ **Always ensure message is displayed**
                    let newText = message || 'Processing...';
                    let newColor = "bg-warning"; // Default color

                    switch (stage) {
                        case 'installing':
                            newText = `🚀 Installing.. ${progress}% - ${message}`;
                            newColor = "bg-warning";
                            break;
                        case 'message':
                            newText = `${message}`;
                            newColor = "bg-primary";
                            break;
                        case 'copying':
                            newText = `📤 Copying.. ${progress}%`;
                            newColor = "bg-warning";
                            break;
                        case 'exists':
                            newText = `✅ ${message}`;
                            newColor = "bg-success";
                            progress = 100;
                            break;
                        case 'copycomplete':
                            newText = `✅ ${message}`;
                            newColor = "bg-success";
                            progress = 100;
                            break;
                        case 'install_complete':
                            newText = `✅ Installation Complete`;
                            newColor = "bg-success";
                            progress = 100;
                            refreshDeviceVersions();
                            break;
                        case 'validation_failed':
                            newText = `❌ Validation Failed! - ${message}`;
                            newColor = "bg-danger";
                            progress = 100;
                            progressBar.dataset.errorOccurred = "true";
                            break;
                        case 'rebooting':
                            newText = `🔄 ${message}`;
                            newColor = "bg-info";
                            break;
                        case 'device_online':
                            newText = `✅ ${message}`;
                            newColor = "bg-success";
                            progress = 100;
                            refreshDeviceVersions();
                            break;
                        case 'version_check':
                            newText = `🔍 ${message || 'Version Match'}`;
                            newColor = "bg-info";
                            break;
                        case 'error':
                            newText = `❌ ${message || 'Installation Error'}`;
                            newColor = "bg-danger";
                            progress = 100;
                            progressBar.dataset.errorOccurred = "true";
                            console.error(`⛔ ERROR detected for ${device_id}: ${newText}`);
                            break;
                        default:
                            newText = `⚠️ Unknown Status - ${message}`;
                            newColor = "bg-secondary";
                            progress = 0;
                            break;
                    }

                    // ✅ **Update Progress Bar**
                    progressBar.style.width = `${progress}%`;
                    progressBar.setAttribute("aria-valuenow", progress);
                    progressBar.textContent = newText;

                    // ✅ **Ensure only the correct class is applied**
                    progressBar.classList.remove("bg-warning", "bg-success", "bg-danger", "bg-info", "bg-secondary", "bg-primary");
                    progressBar.classList.add(newColor);

                    // ✅ **Ensure text visibility**
                    progressBar.style.color = "#003366";  // Dark blue text
                    progressBar.style.fontWeight = "bold";  // Make text bold
                    progressBar.style.padding = "5px";  // Add padding for better visibility
                    progressBar.style.whiteSpace = "nowrap";  // Prevent text cutoff

                    //console.log(`✅ Progress updated for ${device_id}: ${newText}`);
                })
                .catch(error => {
                    console.error(`❌ Error fetching device row for ${device_id}:`, error);
                });
        });

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
            const progressModal = document.getElementById('onboardProgressModal');
            const progressBar = document.getElementById('overallProgressBar');
            const progressText = document.getElementById('progressText');
            const deviceProgressList = document.getElementById('deviceProgressList');

            if (progressBar) progressBar.value = 0; // Reset the progress bar to 0
            if (progressText) progressText.textContent = '0% Complete'; // Reset progress text
            if (deviceProgressList) deviceProgressList.innerHTML = ''; // Clear the device progress list

            // Ensure the modal is shown when the save process begins
            progressModal.style.display = 'block';


            if (row.cells.length < 4) {
                console.error(`Row structure is incorrect or missing cells. Cells found: ${row.cells.length}`);
                return;  // Exit without alerts; console log will suffice
            }

            const hostname = row.cells[1].textContent.trim();
            const username = row.cells[3].querySelector('input').value.trim();
            const password = row.cells[4].querySelector('input').value.trim();
            const deviceData = { id: deviceId, hostname: hostname, username: username, password: password };

            //const overallProgressBar = document.getElementById('overallProgressBar');
            //const progressText = document.getElementById('progressText');
            //const deviceProgressList = document.getElementById('deviceProgressList');

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
                    loadUploadedImages();
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

        // ✅ Refresh Device Versions

        async function refreshDeviceVersions() {
            console.log("🔄 Refreshing Device Versions...");

            try {
                const response = await fetch('/api/refresh_versions', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                const result = await response.json();
                console.log("✅ Device Versions Updated: ", result);

                if (result.success) {
                    Object.keys(result.updated_versions).forEach(hostname => {
                        const deviceData = result.updated_versions[hostname];

                        const row = document.querySelector(`tr[data-device-id="${hostname}"]`);
                        if (row) {
                            // ✅ Update Version in Main Row (Column Index: 5)
                            row.cells[6].innerHTML = formatVersion(deviceData.version);

                            // ✅ Find the Expandable Row
                            const expandableRow = row.nextElementSibling;
                            if (expandableRow && expandableRow.classList.contains("expandable-row")) {
                                // ✅ Update Expandable Row Content
                                expandableRow.innerHTML = `
                                    <td colspan="8">
                                        <div style="display: flex; justify-content: space-between; flex-wrap: wrap; padding: 5px;">
                                            <span><strong>Model:</strong> ${deviceData.model || "Unknown"}</span>
                                            <span><strong>Serial Number:</strong> ${deviceData.serial_number || "N/A"}</span>
                                            <span><strong>Up Time:</strong> ${deviceData.up_time || "Unknown"}</span>
                                            <span><strong>Last Reboot Reason:</strong> ${deviceData.last_reboot_reason || "N/A"}</span>
                                        </div>
                                    </td>
                                `;
                            }
                        }
                    });

                    alert("✅ Device versions refreshed successfully!");
                } else {
                    alert("⚠️ Error refreshing device versions: " + result.error);
                }
            } catch (error) {
                console.error("❌ Error refreshing versions:", error);
                alert("❌ Error refreshing device versions.");
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


        function determineFolderKey(selectedFile) {
                    //console.log("📌 Entering determineFolderKey with:", selectedFile); // ✅ Debugging log

                    if (!selectedFile) {
                        console.error("❌ ERROR: selectedFile is undefined or empty in determineFolderKey!");
                        return "UPLOAD_FOLDER"; // Default fallback
                    }

                    const trimmedFile = selectedFile.trim(); // ✅ Trim spaces for safety
                    //console.log("🔍 Trimmed selectedFile:", trimmedFile); // ✅ Debugging log

                    if (trimmedFile.startsWith("DEVICE_CONFIG_FOLDER/")) {
                        return "DEVICE_CONFIG_FOLDER";
                    } else if (trimmedFile.startsWith("ALL_USER_UPLOAD_FOLDER/")) {
                        return "ALL_USER_UPLOAD_FOLDER";
                    } else if (trimmedFile.startsWith("TEMPLATE_FOLDER/")) {
                        return "TEMPLATE_FOLDER"; // ✅ Fix for Template Folder
                    } else {
                        return "UPLOAD_FOLDER"; // Default case
                    }
                }

        const showSelectedImageBtn = document.getElementById('showSelectedImageBtn');
        if (showSelectedImageBtn) {
            showSelectedImageBtn.addEventListener('click', async function () {
                const selectedFile = document.getElementById('uploadedImagesSelect').value;
                //console.log(selectedFile);
                if (!selectedFile) {
                    alert('Please select a file first.');
                    return;
                }

                // Validate the selected file
                if (!isValidFile(selectedFile)) {
                    alert('Please select a valid file. Folders, .tgz, .zip, .tar, iso, and .rar files are not allowed.');
                    return;
                }


                try {
                    const folderKey = determineFolderKey(selectedFile);
                    const filename = selectedFile.split('/').pop(); // Extract only the filename

                    const response = await fetch('/show_file_content', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ filename, folder_key: folderKey }),
                    });

                    if (response.ok) {
                        const result = await response.json();
                        displayFileContent(result.content, selectedFile);
                    } else {
                        const errorText = await response.text();
                        console.error(`Server error: ${errorText}`);
                        alert(errorText);
                    }
                } catch (error) {
                    console.error('Error fetching file content:', error);
                    alert(`An error occurred: ${error.message}`);
                }
            });

            document.getElementById('closeEditorBtn').addEventListener('click', function () {
                document.getElementById('fileContentEditor').classList.add('hidden');
            });
        }

        function displayFileContent(content, selectedFile) {
            const editor = ace.edit('editor');
            editor.setTheme('ace/theme/monokai');
            editor.session.setMode('ace/mode/text');
            editor.setValue(content || '', -1);

            const fileContentEditor = document.getElementById('fileContentEditor');
            fileContentEditor.dataset.filename = selectedFile;
            fileContentEditor.classList.remove('hidden');
        }

        function isValidFile(filePath) {
            // Check if the filePath ends with a valid file extension
            const invalidExtensions = ['.tgz', '.zip', '.tar', '.rar','.iso'];
            const isFolder = filePath.endsWith('/');
            const hasInvalidExtension = invalidExtensions.some(ext => filePath.endsWith(ext));

            return !isFolder && !hasInvalidExtension;
        }

        function displayFileContent(content, selectedFile) {
            const editor = ace.edit('editor');
            editor.setTheme('ace/theme/monokai');
            editor.session.setMode('ace/mode/text');
            editor.setValue(content || '', -1);

            const fileContentEditor = document.getElementById('fileContentEditor');
            fileContentEditor.dataset.filename = selectedFile;
            fileContentEditor.classList.remove('hidden');
        }

        function isValidFile(filePath) {
            // Check if the filePath ends with a valid file extension
            const invalidExtensions = ['.tgz', '.zip', '.tar', '.rar'];
            const isFolder = filePath.endsWith('/');
            const hasInvalidExtension = invalidExtensions.some(ext => filePath.endsWith(ext));

            return !isFolder && !hasInvalidExtension;
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


        function formatVersion(version, maxLength = 15) {
            if (!version || version === "Unknown") return "Unknown";
            return version.length > maxLength ? `<span title="${version}">${version.substring(0, maxLength)}...</span>` : version;
        }


 /*
   async function fetchOnboardedDevices() {
        try {
            const response = await fetch('/api/devices');

            if (!response.ok) {
                throw new Error('Failed to fetch onboarded devices');
            }
            const devices = await response.json();
            const tableBody = document.querySelector('#onboardedDevicesTable tbody');
            tableBody.innerHTML = ''; // Clear the table before updating
            //console.log(devices)
            // **Fixing the Table Header**
            const thead = document.querySelector('#onboardedDevicesTable thead');
            thead.innerHTML = `
                <tr>
                    <th style="width: 50px;">
                        <input type="checkbox" id="selectAllDevices">
                    </th>

                    <th style="width: 150px;">

                    <i id="expandAllIcon" class="fa-solid fa-angles-down" onclick="toggleAllRows()"
                        style="cursor: pointer; margin-right: 8px; display: inline-block;"></i>
                    Hostname
                    </th>
                    <th style="width: 150px;">IP Address</th>
                    <th style="width: 150px;">Username</th>
                    <th style="width: 150px;">Password</th>
                    <th style="width: 80px;">
                        Version
                        <i class="fa-solid fa-arrows-rotate" id="refreshVersionBtn" title="Refresh Version" style="cursor: pointer; margin-left: 5px;"></i>
                    </th>
                    <th style="width: 150px;">Actions</th>
                    <th style="width: 200px;">Progress</th>
                </tr>
            `;

            // **Attach Event Listener for Refresh Version Button**
            document.getElementById('refreshVersionBtn').addEventListener('click', refreshDeviceVersions);

            // **Ensure Select All Checkbox Works Correctly**
            document.getElementById('selectAllDevices').addEventListener('change', toggleSelectAllDevices);

            // **Populate the table with the fetched devices**
            devices.forEach(device => {
                const row = tableBody.insertRow();
                row.setAttribute('data-device-id', device.hostname);

                // **Checkbox Column**
                const checkboxCell = row.insertCell(0);
                checkboxCell.innerHTML = `<input type="checkbox" class="device-checkbox">`;

                // **Hostname Column with Dropdown Icon**
                const hostnameCell = row.insertCell(1);
                hostnameCell.innerHTML = `
                    <i class="fas fa-chevron-down dropdown-icon" onclick="toggleRow(this)" style="cursor: pointer; margin-right: 5px;"></i>
                    ${device.hostname}
                `;

                // **Device Data Columns**
                row.insertCell(2).textContent = device.ip;
                row.insertCell(3).innerHTML = `<input type="text" value="${device.username}" style="width: 100%;" />`;
                row.insertCell(4).innerHTML = `<input type="text" class="passwordInput" value="${device.password}" style="width: 100%;" />`;
                row.insertCell(5).innerHTML = formatVersion(device.version);


                // **Actions Column**
                const actionsCell = row.insertCell(6);


                function createIconSpan(iconClass, title, onClickHandler) {
                    const span = document.createElement('span');
                    span.innerHTML = `<i class="${iconClass}"></i>`;
                    span.title = title;
                    span.classList.add('icon-span');
                    span.style.cursor = 'pointer';
                    span.style.marginRight = '5px';
                    span.style.fontSize = "14px";
                    span.addEventListener('click', onClickHandler);
                    return span;
                }



                actionsCell.appendChild(createIconSpan('fa-solid fa-trash', 'Delete Device', () => deleteDevice(device.hostname)));
                actionsCell.appendChild(createIconSpan('fa-solid fa-floppy-disk', 'Save Device Config', () => saveDeviceConfig(row, device.hostname)));
                actionsCell.appendChild(createIconSpan('fa-solid fa-rotate', 'Update User/Pass', () => updateDeviceConfig(row, device.hostname)));
                actionsCell.appendChild(createIconSpan('fa-solid fa-eye', 'Show Device Config', () => showDeviceConfig(device.hostname, device.hostname)));
                actionsCell.appendChild(createIconSpan('fa-solid fa-recycle', 'Restore Device Config', () => restoreDeviceConfig(device.hostname)));
                actionsCell.appendChild(createIconSpan('fa-solid fa-terminal', 'SSH into Device', () => openSshTerminal(device.ip, device.username, device.password)));

                // **Progress Column**
                row.insertCell(7).innerHTML = `
                    <div class="progress" style="height: 20px;">
                        <div class="progress-bar bg-warning" role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                    </div>
                `;

                 // **Get Device Facts**
                const deviceFacts = device.device_facts || {};
                const model = deviceFacts.model || "Unknown";
                const serialNumber = deviceFacts.serialnumber || "N/A";
                const uptime = deviceFacts.RE0?.up_time || "Unknown";
                const lastRebootReason = deviceFacts.RE0?.last_reboot_reason || "N/A";

                // **Expandable Row (Initially Hidden)**
                const expandableRow = tableBody.insertRow();
                expandableRow.className = "expandable-row";
                expandableRow.style.display = "none";

                expandableRow.innerHTML = `
                <td colspan="7">
                    <div style="display: flex; justify-content: space-between; padding: 5px;">
                        <span><strong>Model:</strong> ${device.model || "Unknown"}</span>
                        <span><strong>Serial Number:</strong> ${device.serial_number || "N/A"}</span>
                        <span><strong>Up Time:</strong> ${device.up_time || "Unknown"}</span>
                        <span><strong>Last Reboot Reason:</strong> ${device.last_reboot_reason || "N/A"}</span>
                    </div>
                </td>
                <td class="progress-status-cell"></td> <!-- Keep Progress Column Fixed -->
            `;
            });

            // **Ensure Delete Selected Devices Button Works**
            const deleteSelectedBtn = document.getElementById('deleteSelectedDevices');
            if (deleteSelectedBtn) {
                deleteSelectedBtn.addEventListener('click', deleteSelectedDevices);
            }
        } catch (error) {
            console.error('Error fetching devices:', error);
        }
    }
*/


async function fetchOnboardedDevices() {
    try {
        const response = await fetch('/api/devices');

        if (!response.ok) {
            throw new Error('Failed to fetch onboarded devices');
        }

        const devices = await response.json();
        const tableBody = document.querySelector('#onboardedDevicesTable tbody');
        tableBody.innerHTML = ''; // Clear the table before updating

        // **Fixing the Table Header**
        const thead = document.querySelector('#onboardedDevicesTable thead');
        thead.innerHTML = `
            <tr>
                <th style="width: 50px;">
                    <input type="checkbox" id="selectAllDevices">
                </th>


                <th style="width: 50px;">
                    <i class="fa-solid fa-network-wired" id="checkAllDevicesHealth"
                       style="cursor: pointer;" title="Check Device Reachability"></i>
                </th>

                <th style="width: 150px;">
                    <i id="expandAllIcon" class="fa-solid fa-angles-down" onclick="toggleAllRows()"
                        style="cursor: pointer; margin-right: 8px; display: inline-block;"></i>
                    Hostname
                </th>
                <th style="width: 150px;">IP Address</th>
                <th style="width: 150px;">Username</th>
                <th style="width: 150px;">Password</th>
                <th style="width: 80px;">
                    Version
                    <i class="fa-solid fa-arrows-rotate" id="refreshVersionBtn" title="Refresh Version" style="cursor: pointer; margin-left: 5px;"></i>
                </th>
                <th style="width: 150px;">Actions</th>
                <th style="width: 200px;">Progress</th>
            </tr>
        `;

        // **Attach Event Listener for Refresh Version Button**
        document.getElementById('refreshVersionBtn').addEventListener('click', refreshDeviceVersions);

        // **Ensure Select All Checkbox Works Correctly**
        document.getElementById('selectAllDevices').addEventListener('change', toggleSelectAllDevices);


        // **Populate the table with the fetched devices**
        devices.forEach(device => {
            const row = tableBody.insertRow();
            row.setAttribute('data-device-id', device.hostname);

            // **Checkbox Column**
            row.insertCell(0).innerHTML = `<input type="checkbox" class="device-checkbox">`;

            // **State Column (Device Reachability)**
            const stateCell = row.insertCell(1);
            stateCell.classList.add("device-state");
            stateCell.setAttribute("data-ip", device.ip);
            stateCell.innerHTML = getReachabilityIcon(device.reachability_status);
            //stateCell.innerHTML = `<i class="fa-solid fa-circle text-secondary"></i>`; // Default Gray

            // **Hostname Column with Dropdown Icon**
            row.insertCell(2).innerHTML = `
                <i class="fas fa-chevron-down dropdown-icon" onclick="toggleRow(this)" style="cursor: pointer; margin-right: 5px;"></i>
                ${device.hostname}
            `;

            // **Device Data Columns**
            row.insertCell(3).textContent = device.ip;
            row.insertCell(4).innerHTML = `<input type="text" value="${device.username}" style="width: 100%;" />`;
            row.insertCell(5).innerHTML = `<input type="text" class="passwordInput" value="${device.password}" style="width: 100%;" />`;
            row.insertCell(6).innerHTML = formatVersion(device.version);

            // **Actions Column**
            const actionsCell = row.insertCell(7);
            function createIconSpan(iconClass, title, onClickHandler) {
                const span = document.createElement('span');
                span.innerHTML = `<i class="${iconClass}"></i>`;
                span.title = title;
                span.classList.add('icon-span');
                span.style.cursor = 'pointer';
                span.style.marginRight = '5px';
                span.style.fontSize = "14px";
                span.addEventListener('click', onClickHandler);
                return span;
            }
            actionsCell.appendChild(createIconSpan('fa-solid fa-trash', 'Delete Device', () => deleteDevice(device.hostname)));
            actionsCell.appendChild(createIconSpan('fa-solid fa-floppy-disk', 'Save Device Config', () => saveDeviceConfig(row, device.hostname)));
            actionsCell.appendChild(createIconSpan('fa-solid fa-rotate', 'Update User/Pass', () => updateDeviceConfig(row, device.hostname)));
            actionsCell.appendChild(createIconSpan('fa-solid fa-eye', 'Show Device Config', () => showDeviceConfig(device.hostname, device.hostname)));
            actionsCell.appendChild(createIconSpan('fa-solid fa-recycle', 'Restore Device Config', () => restoreDeviceConfig(device.hostname)));
            actionsCell.appendChild(createIconSpan('fa-solid fa-terminal', 'SSH into Device', () => openSshTerminal(device.ip, device.username, device.password)));

            // **Progress Column**
            row.insertCell(8).innerHTML = `
                <div class="progress" style="height: 20px;">
                    <div class="progress-bar bg-warning" role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                </div>
            `;

            // **Add Expandable Row (Ensure It's Directly After)**
            const expandableRow = tableBody.insertRow();
            expandableRow.classList.add("expandable-row");
            expandableRow.style.display = "none";

            expandableRow.innerHTML = `
                <td colspan="9">
                    <div style="display: flex; flex-wrap: wrap; justify-content: space-between; padding: 10px; background-color: #f8f9fa; border-radius: 5px;">
                        <span><i class="fa-solid fa-server"></i> <strong>Model:</strong> ${device.model || "Unknown"}</span>
                        <span><i class="fa-solid fa-barcode"></i> <strong>Serial Number:</strong> ${device.serial_number || "N/A"}</span>
                        <span><i class="fa-solid fa-clock"></i> <strong>Up Time:</strong> ${device.up_time || "Unknown"}</span>
                        <span><i class="fa-solid fa-power-off"></i> <strong>Last Reboot Reason:</strong> ${device.last_reboot_reason || "N/A"}</span>
                    </div>
                </td>
            `;
        });

        // **Check Device Health after loading**
        checkDeviceHealth(devices);

        // **Ensure Delete Selected Devices Button Works**
        const deleteSelectedBtn = document.getElementById('deleteSelectedDevices');
        if (deleteSelectedBtn) {
            deleteSelectedBtn.addEventListener('click', deleteSelectedDevices);
        }
        const checkAllHealthIcon = document.getElementById("checkAllDevicesHealth");
        if (checkAllHealthIcon) {
            checkAllHealthIcon.addEventListener("click", checkDeviceOnlineStatus);
        } else {
            console.warn("⚠️ Warning: 'fa-network-wired' icon for health check not found.");
        }

    } catch (error) {
        console.error('Error fetching devices:', error);
    }
}
fetchOnboardedDevices();



function getReachabilityIcon(status) {
    let colorClass = "text-secondary"; // Default gray
    let tooltip = "Unknown";

    switch (status) {
        case "reachable":
            colorClass = "text-success"; // Green
            tooltip = "Reachable";
            break;
        case "unreachable":
            colorClass = "text-danger"; // Red
            tooltip = "Unreachable";
            break;
        case "connect_error":
            colorClass = "text-warning"; // Yellow
            tooltip = "Connection Error";
            break;
        case "auth_error":
            colorClass = "text-orange"; // Orange
            tooltip = "Authentication Error";
            break;
        default:
            colorClass = "text-secondary"; // Gray
            tooltip = "Unknown";
    }

    return `<i class="fa-solid fa-circle ${colorClass}" title="${tooltip}"></i>`;
}


// ✅ Function to Check Device Online Status
async function checkDeviceOnlineStatus() {
    try {
        const deviceRows = document.querySelectorAll("#onboardedDevicesTable tbody tr[data-device-id]");
        if (deviceRows.length === 0) {
            console.warn("No devices found to check health for.");
            return;
        }

        // ✅ Collect Devices for API Request
        const devices = [];
        deviceRows.forEach(row => {
            const hostname = row.getAttribute("data-device-id");
            const stateCell = row.querySelector(".device-state");

            if (!stateCell) {
                console.warn(`No state cell found for ${hostname}`);
                return;
            }

            const ip = stateCell.getAttribute("data-ip");
            if (!ip) {
                console.warn(`No IP found for ${hostname}, skipping.`);
                return;
            }

            devices.push({ id: hostname, ip: ip });
        });

        if (devices.length === 0) {
            console.warn("No valid devices with IPs found.");
            return;
        }

        // ✅ Send API Request to Check Device Health
        const response = await fetch("/api/check_device_health", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ devices })
        });

        if (!response.ok) {
            throw new Error("Failed to fetch device health");
        }

        const healthData = await response.json();
        const healthStatus = healthData.health_status;

        // ✅ Update UI Based on Health Status
        deviceRows.forEach(row => {
            const stateCell = row.querySelector(".device-state i");
            const hostname = row.getAttribute("data-device-id");

            if (!stateCell) {
                console.warn(`State icon missing for ${hostname}`);
                return;
            }

            const status = healthStatus[hostname] || "unknown";
            let colorClass = "text-secondary"; // Default gray
            let tooltip = "Unknown";

            switch (status) {
                case "reachable":
                    colorClass = "text-success"; // Green
                    tooltip = "Reachable";
                    break;
                case "unreachable":
                    colorClass = "text-danger"; // Red
                    tooltip = "Unreachable";
                    break;
                case "connect_error":
                    colorClass = "text-warning"; // Yellow
                    tooltip = "Connection Error";
                    break;
                case "auth_error":
                    colorClass = "text-orange"; // Orange
                    tooltip = "Authentication Error";
                    break;
                default:
                    colorClass = "text-secondary"; // Gray
                    tooltip = "Unknown";
            }

            // Apply new styles and tooltip
            stateCell.className = `fa-solid fa-circle ${colorClass}`;
            stateCell.setAttribute("title", tooltip);
        });

    } catch (error) {
        console.error("Error checking device health:", error);
    }
}





        //****************************//



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

        //**** Event listeners for device and image management ****//
        const uploadCsvBtn = document.getElementById('uploadCsvBtn');
        if (uploadCsvBtn) {
            uploadCsvBtn.addEventListener('click', uploadCsvFile);
        }

        const uploadImageBtn = document.getElementById('uploadImageBtn');
        if (uploadImageBtn) {
            uploadImageBtn.addEventListener('click', uploadImageFile);
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
                        loadUploadedImages();
                    });
                }

        function openModal() {
                document.getElementById('onboardProgressModal').style.display = 'block';
            }

// Function to close the modal and clear the device progress list
    function closeModalAndClearProgress() {
        const progressModal = document.getElementById('onboardProgressModal');
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
                alert('⚠️ Please select at least one device.');
                return;
            }

            if (!image) {
                alert('⚠️ Missing image name.');
                return;
            }

            try {
                const payload = JSON.stringify({ imageName: image, deviceIds: deviceIds, action: action });
                console.log("📤 Sending install request:", payload);

                // ✅ **Send Request**
                const response = await fetch('/install_image', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: payload
                });

                const result = await response.json();
                console.log("📥 Install Response:", result);

                if (!response.ok) {
                    alert(`❌ Error: ${result.error || 'Unknown error occurred.'}`);
                    return;
                }

                // ✅ **Extract status codes from response**
                const statusCodes = new Set(Object.values(result.status));

                // ✅ **Check if install should fail**
                if (statusCodes.has(200) && statusCodes.has(202)) {
                    console.error("❌ Install failed: Both 200 (exists) and 202 (install failed) found.");
                    alert("❌ Install failed! A device had an image, but installation did not complete successfully.");
                    return;
                }

                console.log("✅ Install request processed successfully. Waiting for WebSocket updates...");
            } catch (error) {
                console.error('🚨 Error performing operation:', error);
                alert('❌ Error during operation. Please check the console for details.');
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


        async function loadUploadedImages() {
            try {
                const response = await fetch('/list_uploaded_images');
                const result = await response.json();

                if (response.ok) {
                    const uploadedImagesSelect = document.getElementById('uploadedImagesSelect');
                    const installImageSelect = document.getElementById('installImageSelect');

                    uploadedImagesSelect.innerHTML = '<option value="" disabled selected>Select file to delete</option>';
                    installImageSelect.innerHTML = '<option value="" disabled selected>Select an image to install</option>';

                    Object.entries(result.files).forEach(([folderName, files]) => {
                        const validFiles = files.filter(file => file.endsWith('.tgz') || file.endsWith('.iso'));

                        if (files.length > 0) {
                            const optgroupUploaded = document.createElement('optgroup');
                            optgroupUploaded.label = folderName;

                            files.forEach(file => {
                                const option = document.createElement('option');
                                option.value = `${folderName}/${file}`;
                                option.textContent = file;
                                optgroupUploaded.appendChild(option);
                            });

                            uploadedImagesSelect.appendChild(optgroupUploaded);
                        }

                        if (validFiles.length > 0) {
                            const optgroupInstall = document.createElement('optgroup');
                            optgroupInstall.label = folderName;

                            validFiles.forEach(file => {
                                const option = document.createElement('option');
                                option.value = `${folderName}/${file}`;
                                option.textContent = file;
                                optgroupInstall.appendChild(option);
                            });

                            installImageSelect.appendChild(optgroupInstall);
                        }
                    });
                } else {
                    alert(result.error || 'Error loading files.');
                }
            } catch (error) {
                console.error('Error loading uploaded images:', error);
                alert('An error occurred while loading uploaded images.');
            }
        }
        loadUploadedImages();


});

function toggleRow(icon) {
    let row = icon.closest("tr"); // Find the main row
    let nextRow = row.nextElementSibling;

    // Search for the expandable row in case it's not immediately next
    while (nextRow && !nextRow.classList.contains("expandable-row")) {
        nextRow = nextRow.nextElementSibling;
    }

    // Ensure an expandable row is found
    if (!nextRow) {
        console.warn("Warning: No expandable row found after", row);
        return;
    }

    // Toggle display
    nextRow.style.display = nextRow.style.display === "none" ? "table-row" : "none";

    // Toggle icons
    icon.classList.toggle("fa-chevron-right");
    icon.classList.toggle("fa-chevron-down");
}


/*
// **Make `toggleRow` Available Globally**
function toggleRow(icon) {
    let row = icon.closest("tr").nextElementSibling;
    row.style.display = row.style.display === "none" ? "table-row" : "none";
    icon.classList.toggle("fa-chevron-right");
    icon.classList.toggle("fa-chevron-down");
}
*/
// **Helper Function to Handle "Select All" Checkbox**
function toggleSelectAllDevices(event) {
    document.querySelectorAll('.device-checkbox').forEach(checkbox => {
        checkbox.checked = event.target.checked;
    });
}


function toggleAllRows() {
    const expandAllIcon = document.getElementById('expandAllIcon');
    const expandableRows = document.querySelectorAll('.expandable-row');

    // Determine if we are expanding or collapsing
    const isExpanding = expandAllIcon.classList.contains("fa-angles-down");

    expandableRows.forEach(row => {
        row.style.display = isExpanding ? "table-row" : "none"; // Show or hide rows
    });

    // Toggle the icon state
    if (isExpanding) {
        expandAllIcon.classList.remove("fa-angles-down");
        expandAllIcon.classList.add("fa-angles-up"); // Change to up arrow when expanded
    } else {
        expandAllIcon.classList.remove("fa-angles-up");
        expandAllIcon.classList.add("fa-angles-down"); // Change back to down arrow when collapsed
    }
}




//---------------------//
