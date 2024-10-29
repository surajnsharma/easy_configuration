        function updateBaseBgp() {
            const ipv4Checkbox = document.getElementById('ipv4_bgp');
            const ipv6Checkbox = document.getElementById('ipv6_bgp');
            const baseIpPartsInput = document.getElementById('bgp_base_neighbor');

            if (ipv4Checkbox.checked && ipv6Checkbox.checked) {
                baseIpPartsInput.value = "192.168.0.1/2001:192:168::1";
            } else if (ipv4Checkbox.checked) {
                baseIpPartsInput.value = "192.168.0.1";
            } else if (ipv6Checkbox.checked) {
                baseIpPartsInput.value = "2001:192:168::1";
            } else {
                baseIpPartsInput.value = "";
            }
        }

        function toggleBgpInterfaceName() {
            const bgp_interface_checkbox = document.getElementById('bgp_interface_checkbox');
            const bgp_interface_name_input = document.getElementById('bgp_interface_name_input');
            if (bgp_interface_checkbox.checked) {
                bgp_interface_name_input.style.display = 'inline';
                bgp_interface_name_input.setAttribute('required', 'required');
                bgp_interface_name_input.value = bgp_interface_name_input.getAttribute('data-saved-value') || 'et-0/0/0'; // Restore value if available
            } else {
                bgp_interface_name_input.setAttribute('data-saved-value', bgp_interface_name_input.value); // Save the current value
                bgp_interface_name_input.style.display = 'none';
                bgp_interface_name_input.removeAttribute('required');
                bgp_interface_name_input.value = ''; // Clear the value only when unchecked
            }
        }