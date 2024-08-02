document.addEventListener('DOMContentLoaded', function() {
    const addRowBtn = document.getElementById('addRowBtn');
    if (addRowBtn) {
        addRowBtn.addEventListener('click', function() {
            const table = document.getElementById('triggerEventsTable').getElementsByTagName('tbody')[0];
            const newRow = table.insertRow();
            const selectCell = newRow.insertCell(0);
            const itemNumberCell = newRow.insertCell(1);
            const descriptionCell = newRow.insertCell(2);
            const iterationCell = newRow.insertCell(3);
            const deviceNameCell = newRow.insertCell(4);
            const actionsCell = newRow.insertCell(5);
            selectCell.innerHTML = '<input type="checkbox" class="rowCheckbox">';
            selectCell.classList.add('small-cell');
            itemNumberCell.innerHTML = table.rows.length;
            itemNumberCell.classList.add('small-cell');
            descriptionCell.innerHTML = '<input type="text" name="description" required>';
            iterationCell.innerHTML = '<input type="number" name="iteration" required>';
            const deviceOptions = document.getElementById('deviceNameSelect').innerHTML;
            deviceNameCell.innerHTML = `<select name="device_name" required>${deviceOptions}</select>`;
            actionsCell.innerHTML = `
                <button type="button" class="small-btn edit-btn">Edit</button>
                <button type="button" class="small-btn save-btn">Save</button>
                <button type="button" class="small-btn delete-btn">Delete</button>
                <input type="hidden" name="command" class="command-hidden-input">
            `;
        });
    }

    const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
    if (deleteSelectedBtn) {
        deleteSelectedBtn.addEventListener('click', function() {
            const checkboxes = document.querySelectorAll('.rowCheckbox:checked');
            const eventIds = [];
            checkboxes.forEach(checkbox => {
                const row = checkbox.closest('tr');
                const eventId = row.getAttribute('data-event-id');
                if (eventId) {
                    eventIds.push(eventId);
                }
            });
            if (eventIds.length > 0) {
                fetch('/delete_events', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ event_ids: eventIds })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        checkboxes.forEach(checkbox => {
                            const row = checkbox.closest('tr');
                            row.remove();
                        });
                    }
                })
                .catch(error => console.error('Error:', error));
            } else {
                alert('No events selected for deletion');
            }
        });
    }

    async function fetchDevices() {
        try {
            const response = await fetch('/trigger_events', {
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();
            const deviceSelect = document.getElementById('deviceNameSelect');
            deviceSelect.innerHTML = '';
            data.devices.forEach(device => {
                const option = document.createElement('option');
                option.value = device.hostname;
                option.textContent = device.hostname;
                deviceSelect.appendChild(option);
            });
        } catch (error) {
            console.error('Error fetching devices:', error);
        }
    }

    async function fetchEvents() {
        try {
            const response = await fetch('/api/events');
            const data = await response.json();
            const tableBody = document.getElementById('triggerEventsTable').getElementsByTagName('tbody')[0];
            tableBody.innerHTML = '';
            data.forEach(event => {
                const row = tableBody.insertRow();
                row.setAttribute('data-event-id', event.id);
                row.insertCell(0).innerHTML = '<input type="checkbox" class="rowCheckbox">';
                row.insertCell(1).innerText = event.id;
                row.insertCell(2).innerHTML = `<input type="text" name="description" value="${event.description}" required>`;
                row.insertCell(3).innerHTML = `<input type="number" name="iteration" value="${event.iteration}" required>`;
                row.insertCell(4).innerHTML = `<select name="device_name" required>${document.getElementById('deviceNameSelect').innerHTML}</select>`;
                row.querySelector('select[name="device_name"]').value = event.device_name;
                row.insertCell(5).innerHTML = `
                    <button type="button" class="small-btn edit-btn">Edit</button>
                    <button type="button" class="small-btn save-btn">Save</button>
                    <button type="button" class="small-btn delete-btn">Delete</button>
                    <input type="hidden" name="command" class="command-hidden-input" value="${event.command}">
                `;
            });
        } catch (error) {
            console.error('Error fetching events:', error);
        }
    }

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

    document.addEventListener('click', function(event) {
        if (event.target && event.target.classList.contains('save-btn')) {
            const row = event.target.closest('tr');
            const description = row.querySelector('input[name="description"]').value;
            const iteration = row.querySelector('input[name="iteration"]').value;
            const deviceName = row.querySelector('select[name="device_name"]').value;
            const command = row.querySelector('.command-hidden-input').value;
            const eventData = {
                description: description,
                iteration: iteration,
                device_name: deviceName,
                command: command
            };
            const eventId = row.getAttribute('data-event-id');
            if (eventId) {
                fetch(`/edit_event/${eventId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(eventData)
                })
                .then(response => response.json())
                .then(data => {
                    if (!data.success) {
                        console.error('Failed to update event');
                    }
                })
                .catch(error => console.error('Error:', error));
            } else {
                fetch('/trigger_events', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(eventData)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        row.setAttribute('data-event-id', data.id);
                    } else {
                        console.error('Failed to save event');
                    }
                })
                .catch(error => console.error('Error:', error));
            }
        }

        if (event.target && event.target.classList.contains('delete-btn')) {
            const row = event.target.closest('tr');
            const eventId = row.getAttribute('data-event-id');
            if (eventId) {
                fetch(`/delete_event/${eventId}`, {
                    method: 'POST'
                })
                .then(response => {
                    if (response.ok) {
                        row.remove();
                    } else {
                        console.error('Failed to delete event');
                    }
                })
                .catch(error => console.error('Error deleting event:', error));
            } else {
                row.remove();
            }
        }
    });

    const modal = document.getElementById("editModal");
    const saveCommandBtn = document.getElementById("saveCommandBtn");
    let currentCommandRow = null;

    document.addEventListener('click', function(event) {
        if (event.target && event.target.classList.contains('edit-btn')) {
            const row = event.target.closest('tr');
            const commandHiddenInput = row.querySelector('.command-hidden-input');
            document.getElementById('commandTextArea').value = commandHiddenInput ? commandHiddenInput.value : '';
            currentCommandRow = row;
            modal.style.display = "block";
        }
    });

    if (saveCommandBtn) {
        saveCommandBtn.addEventListener('click', function() {
            const command = document.getElementById('commandTextArea').value;
            let commandHiddenInput = currentCommandRow.querySelector('.command-hidden-input');
            if (!commandHiddenInput) {
                commandHiddenInput = document.createElement('input');
                commandHiddenInput.type = 'hidden';
                commandHiddenInput.name = 'command';
                commandHiddenInput.classList.add('command-hidden-input');
                currentCommandRow.appendChild(commandHiddenInput);
            }
            commandHiddenInput.value = command;
            const eventId = currentCommandRow.getAttribute('data-event-id');
            if (eventId) {
                fetch(`/edit_event/${eventId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ command: command })
                })
                .then(response => response.json())
                .then(data => {
                    if (!data.success) {
                        console.error('Failed to update command');
                    }
                })
                .catch(error => console.error('Error:', error));
            }
            modal.style.display = "none";
        });
    }

    // Get the modal
    var sampleCsvModal = document.getElementById("sampleCsvModal");

    // Get the button that opens the modal
    var sampleCsvBtn = document.getElementById("sampleCsvBtn");

    // Get the <span> element that closes the modal
    var sampleCsvClose = document.getElementsByClassName("close")[0];

    // When the user clicks the button, open the modal
    if (sampleCsvBtn) {
        sampleCsvBtn.onclick = function() {
            sampleCsvModal.style.display = "block";
        }
    }

    // When the user clicks on <span> (x), close the modal
    if (sampleCsvClose) {
        sampleCsvClose.onclick = function() {
            sampleCsvModal.style.display = "none";
        }
    }

    // When the user clicks anywhere outside of the modal, close it
    window.onclick = function(event) {
        if (event.target == sampleCsvModal) {
            sampleCsvModal.style.display = "none";
        }
    }
});
