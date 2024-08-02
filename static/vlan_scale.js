// Function to toggle the display of the native VLAN ID input field
function toggleNativeVlanIdInput() {
    const checkbox = document.getElementById('native_vlanid_checkbox');
    const input = document.getElementById('native_vlanid_input');
    input.style.display = checkbox.checked ? 'inline-block' : 'none';
}

// Function to handle the access checkbox logic
function checkAccessCheckbox() {
    const accessCheckbox = document.getElementById('access_checkbox');
    const numVlansInput = document.getElementById('num_vlans_per_interface');

    if (accessCheckbox.checked) {
        numVlansInput.value = 1;
        numVlansInput.max = 1;
        numVlansInput.min = 1;
        numVlansInput.readOnly = true; // Make the field read-only to prevent user from changing the value
    } else {
        numVlansInput.removeAttribute('max');
        numVlansInput.removeAttribute('min');
        numVlansInput.readOnly = false; // Allow the field to be edited again
    }
}

document.addEventListener('DOMContentLoaded', function() {
    // Attach event listeners to the checkboxes and input fields
    document.getElementById('native_vlanid_checkbox').addEventListener('change', toggleNativeVlanIdInput);
    document.getElementById('access_checkbox').addEventListener('change', checkAccessCheckbox);

    document.getElementById('num_vlans_per_interface').addEventListener('input', function(event) {
        const numVlansInput = event.target;
        const accessCheckbox = document.getElementById('access_checkbox');

        if (accessCheckbox.checked && numVlansInput.value > 1) {
            alert('When Access VLAN is selected, the number of VLANs per interface cannot be greater than 1.');
            numVlansInput.value = 1;
        }
    });

    // Ensure initial state is set correctly
    checkAccessCheckbox();
    toggleNativeVlanIdInput();
});
