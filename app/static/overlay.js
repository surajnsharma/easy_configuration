//overlay.js//
       document.addEventListener('DOMContentLoaded', function() {
            const numSpinesElement = document.getElementById('num_spines');
            const numLeafsElement = document.getElementById('num_leafs');
            const leafServiceCheckbox = document.getElementById('leafServiceCheckbox');
            const leafServiceTable = document.getElementById('leafServiceTable');
            const nestedLeafServiceTable = document.getElementById('nestedLeafServiceTable');
            const leafIpsRow = document.getElementById('leafIpsRow');
            const spineIps = document.getElementById('spineIps');

            // Toggle Leaf Service Table visibility
            function toggleLeafServiceTable() {
                if (leafServiceCheckbox.checked) {
                    leafServiceTable.style.display = 'table';
                    updateLeafServiceTable(parseInt(numLeafsElement.value, 10));
                } else {
                    leafServiceTable.style.display = 'none';
                    nestedLeafServiceTable.innerHTML = '';  // Clear the leaf table when disabled
                }
            }

            // Update Spine Input Fields
            function updateSpineInputs() {
                const numSpines = parseInt(numSpinesElement.value, 10);
                spineIps.innerHTML = '';

                if (numSpines > 0) {
                    spineIps.classList.remove('hidden');
                    let rowContent = '';
                    for (let i = 0; i < numSpines; i++) {
                        rowContent += `
                            <tr>
                                <td class="cell">
                                    <label for="spine_ip_${i}" style="margin-right: 5px;">Spine IP ${i + 1}:</label>
                                    <input type="text" id="spine_ip_${i}" name="spine_ip_${i}" required>
                                </td>
                            </tr>`;
                    }
                    spineIps.innerHTML = rowContent;
                } else {
                    spineIps.classList.add('hidden');
                }

                if (numSpines > 4) {
                    alert('Number of spines cannot be more than 4');
                    numSpinesElement.value = 4;
                }
            }

            // Update Leaf Input Fields
            function updateLeafInputs() {
                const numLeafs = parseInt(numLeafsElement.value, 10);
                leafIpsRow.innerHTML = '';
                nestedLeafServiceTable.innerHTML = '';

                if (numLeafs > 4) {
                    alert('Number of leafs cannot be more than 4');
                    numLeafsElement.value = 4;
                    return;
                }

                if (numLeafs > 0) {
                    leafIpsRow.classList.remove('hidden');
                    let leafRowContent = '';

                    for (let i = 0; i < numLeafs; i++) {
                        leafRowContent += `
                            <tr>
                                <td class="cell">
                                    <label for="leaf_ip_${i}" style="margin-right: 15px;">Leaf IP ${i + 1}:</label>
                                    <input type="text" id="leaf_ip_${i}" name="leaf_ip_${i}" required>
                                </td>
                            </tr>`;
                    }
                    leafIpsRow.innerHTML = leafRowContent;

                    if (leafServiceCheckbox.checked) {
                        updateLeafServiceTable(numLeafs);
                    }
                } else {
                    leafIpsRow.classList.add('hidden');
                }
            }

            // Update Leaf Service Table based on leaf count
            function updateLeafServiceTable(numLeafs) {
                nestedLeafServiceTable.innerHTML = '';

                for (let i = 0; i < numLeafs; i++) {
                    let row = `
                        <tr>
                            <td class="cell" colspan="4">
                                <label for="service_int_${i}">Service Intf Leaf ${i + 1}:</label>
                                <input type="text" id="service_int_${i}" name="service_int_${i}" placeholder="Interface Name">
                            </td>
                        </tr>
                        <tr>
                            <td colspan="4">
                                <label><input type="checkbox" id="enable_esi_lag_${i}" onchange="toggleESILAG(${i})"> Enable ESI LAG</label>
                            </td>
                        </tr>
                        <tr id="esi_lag_config_${i}" class="esi-lag-config hidden">
                            <td colspan="4">
                                <div>
                                    <label for="esi_id_${i}">ESI ID:</label>
                                    <input type="text" id="esi_id_${i}" name="esi_id_${i}" placeholder="ESI ID">
                                    <label for="lacp_mode_${i}">LACP Mode:</label>
                                    <select id="lacp_mode_${i}" name="lacp_mode_${i}">
                                        <option value="active">Active</option>
                                        <option value="passive">Passive</option>
                                    </select>
                                    <label for="lag_intfs_${i}">LAG Interfaces:</label>
                                    <input type="text" id="lag_intfs_${i}" name="lag_intfs_${i}" placeholder="e.g., et-0/0/0, et-0/0/1">
                                </div>
                            </td>
                        </tr>`;
                    nestedLeafServiceTable.innerHTML += row;
                }

                // Dynamically assign toggleESILAG handler to each row
                for (let i = 0; i < numLeafs; i++) {
                    document.getElementById(`enable_esi_lag_${i}`).addEventListener('change', function() {
                        toggleESILAG(i);
                    });
                }
            }

            // Toggle ESI LAG configuration visibility
            function toggleESILAG(index) {
                const esiLagConfig = document.getElementById(`esi_lag_config_${index}`);
                const checkbox = document.getElementById(`enable_esi_lag_${index}`);

                if (checkbox.checked) {
                    esiLagConfig.style.display = 'table-row';
                } else {
                    esiLagConfig.style.display = 'none';
                }
            }

            // Event listeners for changes in spines and leaves
            numSpinesElement.addEventListener('change', updateSpineInputs);
            numLeafsElement.addEventListener('change', updateLeafInputs);
            leafServiceCheckbox.addEventListener('change', toggleLeafServiceTable);

            updateSpineInputs();
            updateLeafInputs();
        });