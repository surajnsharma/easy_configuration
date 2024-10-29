
function updateBaseIpParts() {
            const ipv4Checkbox = document.getElementById('ipv4');
            const ipv6Checkbox = document.getElementById('ipv6');
            const baseIpPartsInput = document.getElementById('base_ip_parts_config');

            if (ipv4Checkbox.checked && ipv6Checkbox.checked) {
                baseIpPartsInput.value = "192.168.0/2001:192::";
            } else if (ipv4Checkbox.checked) {
                baseIpPartsInput.value = "192.168.0";
            } else if (ipv6Checkbox.checked) {
                baseIpPartsInput.value = "2001:192::";
            } else {
                baseIpPartsInput.value = "";
            }
        }

function checkAccessCheckbox() {
            const accessCheckbox = document.getElementById('access_checkbox');
            const trunkCheckbox = document.getElementById('trunk_checkbox');
            if (accessCheckbox.checked) {
                trunkCheckbox.checked = false;
            }
        }

function toggleNativeVlanIdInput() {
            const nativeVlanIdCheckbox = document.getElementById('native_vlanid_checkbox');
            const nativeVlanIdInput = document.getElementById('native_vlanid_input');
            nativeVlanIdInput.style.display = nativeVlanIdCheckbox.checked ? 'inline' : 'none';
        }
function checkAccessCheckbox() {
            const accessCheckbox = document.getElementById('access_checkbox');
            const trunkCheckbox = document.getElementById('trunk_checkbox');
            const numVlansPerInterfaceInput = document.getElementById('num_vlans_per_interface');

            if (accessCheckbox.checked) {
                trunkCheckbox.checked = false;
                numVlansPerInterfaceInput.value = 1;
                numVlansPerInterfaceInput.disabled = true;
            } else {
                numVlansPerInterfaceInput.disabled = false;
            }
        }
