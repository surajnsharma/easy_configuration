document.addEventListener('DOMContentLoaded', function() {
    let devices = [];

    // Fetch devices and store them in the devices array
    const fetchDevices = async () => {
        try {
            const response = await fetch('/trigger_events', {
                headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
            });

            if (!response.ok) throw new Error('Network response was not ok');

            const data = await response.json();
            devices = data.devices;  // Populate devices list
        } catch (error) {
            console.error('Error fetching devices:', error);
        }
    };

    // Populate device dropdown for each row
    const populateDeviceSelect = (selectElement) => {
        selectElement.innerHTML = '';
        devices.forEach(device => {
            const option = document.createElement('option');
            option.value = device.hostname;
            option.textContent = device.hostname;
            selectElement.appendChild(option);
        });
    };

    // Function to add a new row in the table
    const addNewRow = () => {
        const table = document.getElementById('triggerEventsTable').getElementsByTagName('tbody')[0];
        const newRow = table.insertRow();
        newRow.innerHTML = `
            <td class="small-cell"><input type="checkbox" class="rowCheckbox"></td>
            <td class="small-cell">${table.rows.length}</td>
            <td><input type="text" name="description" required></td>
            <td><input type="number" name="iteration" required></td>
            <td><select name="device_name" required></select></td>
            <td>
                <button type="button" class="small-btn edit-btn">Edit</button>
                <button type="button" class="small-btn save-btn">Save</button>
                <button type="button" class="small-btn delete-btn">Delete</button>
                <input type="hidden" name="command" class="command-hidden-input">
            </td>
        `;

        const deviceSelect = newRow.querySelector('select[name="device_name"]');
        populateDeviceSelect(deviceSelect);
    };

    // Fetch devices initially to populate the select elements
    fetchDevices();

    // Add row button listener
    document.getElementById('addRowBtn')?.addEventListener('click', addNewRow);

    // Delete selected rows
    document.getElementById('deleteSelectedBtn')?.addEventListener('click', function() {
        const selectedCheckboxes = document.querySelectorAll('.rowCheckbox:checked');
        const eventIds = Array.from(selectedCheckboxes).map(checkbox => {
            const row = checkbox.closest('tr');
            return row.getAttribute('data-event-id');
        }).filter(eventId => eventId);

        if (eventIds.length > 0) {
            fetch('/delete_events', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ event_ids: eventIds })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    selectedCheckboxes.forEach(checkbox => checkbox.closest('tr').remove());
                }
            })
            .catch(error => console.error('Error deleting events:', error));
        } else {
            alert('No events selected for deletion');
        }
    });

    // Event listeners for edit, save, and delete buttons in table rows
    document.addEventListener('click', function(event) {
        const row = event.target.closest('tr');

        // Save event
        if (event.target.classList.contains('save-btn')) {
            const eventData = {
                description: row.querySelector('input[name="description"]').value,
                iteration: row.querySelector('input[name="iteration"]').value,
                device_name: row.querySelector('select[name="device_name"]').value,
                command: row.querySelector('.command-hidden-input').value
            };
            const eventId = row.getAttribute('data-event-id');
            const url = eventId ? `/edit_event/${eventId}` : '/trigger_events';

            fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(eventData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && !eventId) {
                    row.setAttribute('data-event-id', data.id);  // Set event ID if it's a new event
                }
            })
            .catch(error => console.error('Error saving event:', error));
        }

        // Delete event
        if (event.target.classList.contains('delete-btn')) {
            const eventId = row.getAttribute('data-event-id');
            if (eventId) {
                fetch(`/delete_event/${eventId}`, { method: 'POST' })
                .then(response => {
                    if (response.ok) row.remove();
                })
                .catch(error => console.error('Error deleting event:', error));
            } else {
                row.remove();
            }
        }
    });

    // Modal handling for editing commands
    const modal = document.getElementById("triggerEventEditModal");
    const commandTextArea = document.getElementById('commandTextArea');
    const saveCommandBtn = document.getElementById("saveCommandBtn");
    const closeModalButton = modal.querySelector(".close");
    let currentCommandRow = null;

    // Open modal to edit command
    document.addEventListener('click', function(event) {
        if (event.target.classList.contains('edit-btn')) {
            currentCommandRow = event.target.closest('tr');
            const command = currentCommandRow.querySelector('.command-hidden-input').value;
            commandTextArea.value = command;
            modal.style.display = "block";
        }
    });

    // Close modal when close button is clicked
    closeModalButton.addEventListener('click', () => {
        modal.style.display = "none";
    });

    // Close modal when clicking outside of it
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    });

    // Save command and other fields from the modal to the database
    saveCommandBtn.addEventListener('click', function() {
        const description = currentCommandRow.querySelector('input[name="description"]').value;
        const iteration = currentCommandRow.querySelector('input[name="iteration"]').value;
        const deviceName = currentCommandRow.querySelector('select[name="device_name"]').value;
        const command = commandTextArea.value;
        const eventId = currentCommandRow.getAttribute('data-event-id');

        const eventData = {
            description: description,
            iteration: iteration,
            device_name: deviceName,
            command: command
        };

        const url = eventId ? `/edit_event/${eventId}` : '/trigger_events';

        fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(eventData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Set the event ID on the row if this is a new event
                if (!eventId && data.id) {
                    currentCommandRow.setAttribute('data-event-id', data.id);
                }
                console.log('Event saved successfully');
            } else {
                console.error('Failed to save event:', data.message);
            }
        })
        .catch(error => console.error('Error saving event:', error));

        modal.style.display = "none";  // Close the modal
    });
});
