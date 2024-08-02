document.addEventListener('DOMContentLoaded', function() {
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

                const formData = new FormData();
                formData.append('file', file);

                try {
                    const response = await fetch('/onboard_devices', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();
                    if (response.ok) {
                        let message = 'CSV file uploaded successfully.\n\n';
                        if (result.added_devices.length > 0) {
                            message += 'Added devices:\n' + result.added_devices.join('\n') + '\n\n';
                        }
                        if (result.duplicated_devices.length > 0) {
                            message += 'Duplicated devices (not added):\n' + result.duplicated_devices.join('\n') + '\n';
                        }
                        alert(message);
                        fetchOnboardedDevices();
                    } else {
                        alert('Error uploading CSV file, missing format/key. Click Sample CSV button to verify: ' + result.error);
                    }
                } catch (error) {
                    alert('Error uploading CSV file.');
                }
            }
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
                            fetchUploadedImages();
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
    /*async function saveAllDevicesConfig() {
                try {
                    const response = await fetch('/save_all_device_configs', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    if (!response.ok) {
                        if (response.status === 401) {
                            window.location.href = '/login';
                            return;
                        }
                        throw new Error('Failed to save all device configurations');
                    }
                    const result = await response.json();
                    if (result.success) {
                        alert('All device configurations saved successfully.');
                    } else {
                        alert('Failed to save some device configurations. Please check the logs.');
                    }
                } catch (error) {
                    console.error('Error saving all device configurations:', error);
                    alert('An error occurred while saving all device configurations.');
                }
            }*/

    async function saveAllDevicesConfig() {
        // Show the modal
        document.getElementById('progressModal').style.display = 'block';

        try {
            const response = await fetch('/save_all_device_configs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const result = await response.json();
            console.log(result);
            if (result.success) {
                alert('All device configurations saved successfully.');
            } else {
                const errorMessages = result.errors.map(error => `Device: ${error.device}, Message: ${error.message}`).join('\n');
                alert(`Failed to save all device configurations:\n${errorMessages}`);
            }
        } catch (error) {
            console.error('Error saving all device configurations:', error);
            alert('Error saving all device configurations: ' + error.message);
        } finally {
            // Hide the modal after completion
            document.getElementById('progressModal').style.display = 'none';
        }
    }

    async function restoreDeviceConfig(deviceId) {
                try {
                    const response = await fetch(`/restore_device_config/${deviceId}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    const result = await response.json();
                    if (result.success) {
                        alert('Device configuration restored successfully.');
                    } else {
                        alert(`Failed to restore device configuration: ${result.error}`);
                    }
                } catch (error) {
                    console.error('Error restoring device configuration:', error);
                    alert('An error occurred while restoring the device configuration.');
                }
            }
    async function restoreAllDevicesConfig() {
            // Show the modal
            document.getElementById('progressModal').style.display = 'block';
            // Close modal when clicking on <span> (x) or outside the modal
            const closeModal = document.querySelector('#progressModal .close');
            closeModal.onclick = function() {
                progressModal.style.display = 'none';
            };
            try {
                const response = await fetch('/restore_all_device_configs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const result = await response.json();
                console.log(result);
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
            try {
                //console.log('Fetching device config for device ID:', deviceId);
                const response = await fetch(`/fetch_device_config/${deviceId}`);
                const data = await response.json();
                if (response.ok) {
                    //console.log('Fetched config data:', data);

                    // Set the configuration in the textarea
                    const configTextarea = document.getElementById('configTextarea');
                    configTextarea.value = data.config;
                    // Display the modal
                    const showConfigModal = document.getElementById('showConfigModal');
                    showConfigModal.classList.remove('hidden');
                    showConfigModal.style.display = 'block';


                    // Set up the download button
                    const downloadConfigBtn = document.getElementById('downloadConfigBtn');
                    downloadConfigBtn.onclick = function() {
                        downloadConfig(data.config, `${hostname}_config.txt`);
                    };
                    // Set up the update button
                    const updateConfigBtn = document.getElementById('updateConfigBtn');
                    updateConfigBtn.onclick = function() {
                        updateDeviceConfiguration(deviceId, configTextarea.value);
                    };
                   // Add event listener to close the modal
                    const closeModal = document.querySelector('#showConfigModal .close');
                    closeModal.onclick = function() {
                        showConfigModal.classList.add('hidden');
                        showConfigModal.style.display = 'none';
                    };
                    window.onclick = function(event) {
                        if (event.target === showConfigModal) {
                            showConfigModal.classList.add('hidden');
                            showConfigModal.style.display = 'none';
                        }
                    };

                } else {
                    alert(data.message);
                }
                } catch (error) {
                    console.error('Error fetching device configuration:', error);
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
        if (row.cells.length < 4) {
            console.error(`Row structure is incorrect or missing cells. Cells found: ${row.cells.length}`);
            alert('Row structure is incorrect or missing cells.');
            return;
        }
        const hostname = row.cells[1].textContent.trim();
        const username = row.cells[3].querySelector('input').value.trim();
        const password = row.cells[4].querySelector('input').value.trim();
        const deviceData = { id: deviceId, hostname: hostname, username: username, password: password };
        try {
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
            const result = await response.json();
            if (result.success) {
                alert('Device configuration saved successfully.');
            } else {
                alert(`Failed to save device configuration: ${result.error}`);
            }
        } catch (error) {
            console.error('Error saving device configuration:', error);
            alert(`Error saving device configuration: ${error.message}`);
        }
    }
    async function updateDeviceConfig(row, deviceId) {
                const username = row.cells[3].querySelector('input').value.trim();
                const password = row.cells[4].querySelector('input').value.trim();
                const deviceData = { id: deviceId, username: username, password: password };
                try {
                    const response = await fetch('/update_device_config', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(deviceData)
                    });
                    const result = await response.json();
                    if (result.success) {
                        alert('Device user/pass updated successfully.');
                    } else {
                        alert(`Failed to update device configuration: ${result.error}`);
                    }
                } catch (error) {
                    console.error('Error updating device user/pass:', error);
                    alert(`Error updating device configuration: ${error.message}`);
                }
            }
    async function installImage(image) {
        const checkboxes = document.querySelectorAll('.device-checkbox:checked');
        const deviceIds = Array.from(checkboxes).map(checkbox => {
            const tr = checkbox.closest('tr');
            return tr ? tr.getAttribute('data-device-id') : null;
        }).filter(id => id !== null);

        if (deviceIds.length === 0) {
            alert('Please select at least one device.');
            return;
        }

        if (!image || deviceIds.length === 0) {
            alert('Missing image name or device ID');
            console.error('Image name:', image, 'Device IDs:', deviceIds);
            return;
        }

        try {
            const payload = JSON.stringify({ imageName: image, deviceIds: deviceIds });
            const response = await fetch('/install_image', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: payload
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Error uploading Image:', errorText);
                alert('Error uploading Image: ' + errorText);
                return;
            }
            const result = await response.json();
            console.log(result)
            if (result.success) {
                alert('Image copied successfully on selected devices.');
            } else {
                if (result.errors && result.errors.includes("Image copy process stopped.")) {
                    alert('Image copy process stopped by user.');
                } else {
                    console.error('Server error response:', result);
                    alert('Error copying image: ' + (result.errors || 'Unknown error occurred'));
                }
            }
        } catch (error) {
            console.error('Error copying image:', error);
            alert('Error copying image. Please check the console for more details.');
        }
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

    // Functions for onboarded devices and images
    async function fetchOnboardedDevices() {
        try {
            const response = await fetch('/api/devices');
            if (!response.ok) {
                throw new Error('Failed to fetch onboarded devices');
            }
            const devices = await response.json();
            const tableBody = document.querySelector('#onboardedDevicesTable tbody');
            tableBody.innerHTML = '';

            devices.forEach(device => {
                const row = tableBody.insertRow();
                row.setAttribute('data-device-id', device.id); // Ensure data-device-id is set

                const checkboxCell = row.insertCell(0);
                checkboxCell.innerHTML = '<input type="checkbox" class="device-checkbox">';
                row.insertCell(1).textContent = device.hostname;
                row.insertCell(2).textContent = device.ip;
                row.insertCell(3).innerHTML = `<input type="text" value="${device.username}" />`;
                row.insertCell(4).innerHTML = `<input type="text" value="${device.password}" />`;
                const actionsCell = row.insertCell(5);

                const deleteButton = document.createElement('button');
                deleteButton.innerHTML = '🗑️'; // Unicode for trash icon
                deleteButton.title = 'Delete Device'; // Tooltip text
                deleteButton.classList.add('small-btn');
                deleteButton.addEventListener('click', function() {
                    deleteDevice(device.id);
                });

                const saveButton = document.createElement('button');
                saveButton.innerHTML = '💾'; // Unicode for floppy disk icon
                saveButton.title = 'Save Device Config'; // Tooltip text
                saveButton.classList.add('small-btn');
                saveButton.addEventListener('click', function() {
                    saveDeviceConfig(row, device.id);
                });

                const updateButton = document.createElement('button');
                updateButton.innerHTML = '🔄'; // Unicode for refresh icon
                updateButton.title = 'Update User/Pass'; // Tooltip text
                updateButton.classList.add('small-btn');
                updateButton.addEventListener('click', function() {
                    updateDeviceConfig(row, device.id);
                });

                const showButton = document.createElement('button');
                showButton.innerHTML = '👁️'; // Unicode for eye icon
                showButton.title = 'Show Device Config'; // Tooltip text
                showButton.classList.add('small-btn');
                showButton.addEventListener('click', function() {
                    showDeviceConfig(device.id, device.hostname);
                });

                const restoreButton = document.createElement('button');
                restoreButton.innerHTML = '♻️'; // Unicode for recycle icon
                restoreButton.title = 'Restore Device Config'; // Tooltip text
                restoreButton.classList.add('small-btn');
                restoreButton.addEventListener('click', function() {
                    restoreDeviceConfig(device.id);
                });

                actionsCell.appendChild(deleteButton);
                actionsCell.appendChild(saveButton);
                actionsCell.appendChild(updateButton);
                actionsCell.appendChild(showButton);
                actionsCell.appendChild(restoreButton);
                const progressCell = row.insertCell(6);
                progressCell.classList.add('progress-cell');
                progressCell.textContent = '0%';
            });
            return devices;
        } catch (error) {
            console.error('Error fetching devices:', error);
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

    // Other functions for device and image management

    // Event listeners for device and image management
    const uploadCsvBtn = document.getElementById('uploadCsvBtn');
    if (uploadCsvBtn) {
        uploadCsvBtn.addEventListener('click', uploadCsvFile);
    }

    const uploadImageBtn = document.getElementById('uploadImageBtn');
    if (uploadImageBtn) {
        uploadImageBtn.addEventListener('click', uploadImageFile);
    }

    const installSelectedImageBtn = document.getElementById('installSelectedImageBtn');
    if (installSelectedImageBtn) {
        installSelectedImageBtn.addEventListener('click', function() {
            const imageSelect = document.getElementById('installImageSelect');
            const image = imageSelect.value;
            installImage(image);
        });
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

    const button = document.getElementById('toggleOnboardFormBtn');
            if (button) {
                button.addEventListener('click', function() {
                    fetchOnboardedDevices();
                    fetchUploadedImages();
                });
            }

    const showMytopologyBtn = document.getElementById('showMytopologyBtn');
    if (showMytopologyBtn) {
        showMytopologyBtn.addEventListener('click', function() {
            $.ajax({
                url: '/get_my_topology',
                type: 'GET',
                success: function(response) {
                    var topologyContainer = document.getElementById('topologyContainer');
                    topologyContainer.classList.remove('hidden');
                    renderTopology(response.topology);
                },
                error: function() {
                    alert('Error loading topology.');
                }
            });
        });
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
            </div>
        `;

        // Get the button that opens the modal
        var sampleuploadCsvBtn = document.getElementById("sampleonBoardCsvBtn");
        // Get the <span> element that closes the modal
        var sampleuploadCsvBtnClose = document.querySelector("#sampleCsvOnboardDeviceModal .close");

        if (sampleuploadCsvBtn) {
            // When the user clicks the button, open the modal
            sampleuploadCsvBtn.onclick = function() {
                sampleCsvOnboardModal.style.display = "block";
            }
        }

        if (sampleuploadCsvBtnClose) {
            // When the user clicks on <span> (x), close the modal
            sampleuploadCsvBtnClose.onclick = function() {
                sampleCsvOnboardModal.style.display = "none";
            }
        }

        // When the user clicks anywhere outside of the modal, close it
        window.onclick = function(event) {
            if (event.target == sampleCsvOnboardModal) {
                sampleCsvOnboardModal.style.display = "none";
            }
        }
    }


            //progress bar for image copy//
            function debounce(func, delay) {
                let timeoutId;
                return function(...args) {
                    if (timeoutId) {
                        clearTimeout(timeoutId);
                    }
                    timeoutId = setTimeout(() => {
                        func(...args);
                    }, delay);
                };
            }

            const updateProgress = debounce((device_id, stage, progress, error) => {
                const deviceRow = document.querySelector(`tr[data-device-id="${device_id}"]`);
                if (deviceRow) {
                    const progressCell = deviceRow.querySelector('.progress-cell');
                    if (progressCell) {
                        let newText = '';
                        if (error) {
                            newText = 'Error occurred';
                            alert('Install Error: ' + error);
                        } else {
                            if (stage === 'copying') {
                                newText = `Copying... ${progress}%`;
                            } else if (stage === 'installing') {
                                newText = `Installing... ${progress}%`;
                            }
                        }
                        // Only update if the text content has actually changed
                        if (progressCell.textContent !== newText) {
                            progressCell.textContent = newText;
                        }
                    }
                }
            }, 100); // Adjust the delay as needed
            const socket = io();
            let progressCache = {}; // To store the last progress update for each device
            socket.on('connect', function() {
                console.log('Connected to server');
            });
            socket.on('disconnect', function() {
                console.log('Disconnected from server');
            });
            socket.on('install_progress', function(data) {
                const { device_id, stage, progress, error } = data;
                if (!progressCache[device_id] || progressCache[device_id] < progress) {
                    progressCache[device_id] = progress;
                    updateProgress(device_id, stage, progress, error);
                }
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

            //progress bar for restoreAllDevicesConfig//
            socket.on('progress', function(data) {
                const { ip, stage, progress, error } = data;
                updateProgress2(ip, stage, progress, error);
            });
            socket.on('overall_progress', function(data) {
            const { progress } = data;
            const overallProgressBar = document.getElementById('overallProgressBar');
            const progressText = document.getElementById('progressText');
            if (overallProgressBar) {
                overallProgressBar.value = progress;
                progressText.textContent = `${progress}% Complete`;
            }
        });

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
