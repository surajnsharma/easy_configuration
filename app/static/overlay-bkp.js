//overlay.js//
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded and parsed');

    const numSpinesElement = document.getElementById('num_spines');
    const numLeafsElement = document.getElementById('num_leafs');
    const leafServiceCheckbox = document.getElementById('leafServiceCheckbox');
    const leafServiceTable = document.getElementById('leafServiceTable');
    const nestedLeafServiceTable = document.getElementById('nestedLeafServiceTable');
    const leafIpsRow = document.getElementById('leafIpsRow');
    const spineIps = document.getElementById('spineIps');

    function updateSpineInputs() {
        const numSpines = parseInt(numSpinesElement.value, 10);

        // Clear existing inputs
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

    function updateLeafInputs() {
        const numLeafs = parseInt(numLeafsElement.value, 10);

        // Clear existing inputs
        leafIpsRow.innerHTML = '';
        nestedLeafServiceTable.innerHTML = ''; // Clear service interface table

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

            // Update the Leaf Service Table if the checkbox is checked
            if (leafServiceCheckbox.checked) {
                updateLeafServiceTable(numLeafs);
            }
        } else {
            leafIpsRow.classList.add('hidden');
        }
    }

    function toggleLeafServiceTable() {
        if (leafServiceCheckbox.checked) {
            leafServiceTable.style.display = 'table'; // Show table
            updateLeafServiceTable(parseInt(numLeafsElement.value, 10)); // Update rows based on leaf count
        } else {
            leafServiceTable.style.display = 'none'; // Hide table
        }
    }


        // Get necessary elements
        //const numLeafsElement = document.getElementById('num_leafs');
        //const nestedLeafServiceTable = document.getElementById('nestedLeafServiceTable');

        function updateLeafServiceTable(numLeafs) {
            console.log("Updating leaf service table for", numLeafs, "leafs");

            // Clear any existing rows
            nestedLeafServiceTable.innerHTML = '';

            // Add new rows based on the number of leafs
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

                nestedLeafServiceTable.innerHTML += row; // Add the row to the table
            }
        }

        function toggleESILAG(index) {
            const esiLagConfig = document.getElementById(`esi_lag_config_${index}`);
            const checkbox = document.getElementById(`enable_esi_lag_${index}`);

            if (checkbox.checked) {
                esiLagConfig.style.display = 'table-row'; // Show the ESI LAG configuration
            } else {
                esiLagConfig.style.display = 'none'; // Hide the ESI LAG configuration
            }
        }

        // Trigger initial table update when the form loads
        if (numLeafsElement) {
            updateLeafServiceTable(numLeafsElement.value);

            // Update the table whenever the number of leafs changes
            numLeafsElement.addEventListener('change', function() {
                updateLeafServiceTable(this.value);
            });
        }



    /*function updateLeafServiceTable(numLeafs) {
        let rowContent = '';
        for (let i = 0; i < numLeafs; i++) {
            rowContent += `
                <td class="cell" colspan="4">
                    <label for="service_int_${i}" style="display: block; margin-bottom: 5px;">Service Intf Leaf ${i + 1}:</label>
                    <input type="text" id="service_int_${i}" name="service_int_${i}">
                </td>`;
        }
        nestedLeafServiceTable.innerHTML = rowContent;
    }*/

    // Event listeners for number of spines and leaves
    numSpinesElement.addEventListener('change', updateSpineInputs);
    numLeafsElement.addEventListener('change', updateLeafInputs);
    leafServiceCheckbox.addEventListener('change', toggleLeafServiceTable);

    // Trigger initial visibility checks
    updateSpineInputs();
    updateLeafInputs();
});




/*
function updateLeafServiceTable(numLeafs) {
    const nestedLeafServiceTable = document.getElementById('nestedLeafServiceTable');
    let rowContent = '<tr>'; // Start a new row

    for (let i = 0; i < numLeafs; i++) {
        rowContent += `
            <td class="cell">
                <label for="service_int_${i}" style="margin-right: 15px;">Service Intf Leaf${i + 1}:</label>
                <input type="text" id="service_int_${i}" name="service_int_${i}" >
            </td>`;

        // Every 4 columns, close the row and start a new one
        if ((i + 1) % 4 === 0) {
            rowContent += '</tr><tr>'; // Close the row and start a new one
        }
    }

    // Close the final row if it's not already closed
    if (numLeafs % 4 !== 0) {
        rowContent += '</tr>';
    }

    nestedLeafServiceTable.innerHTML = rowContent; // Add the content to the table
} */





/*document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded and parsed');
    const numSpinesElement = document.getElementById('num_spines');
    const numLeafsElement = document.getElementById('num_leafs');

    function updateSpineInputs() {
        const numSpines = numSpinesElement.value;
        const spineIpsRow = document.getElementById('spineIpsRow');
        const spineIps = document.getElementById('spineIps');

        // Clear existing inputs
        spineIps.innerHTML = '';

        if (numSpines > 0) {
            spineIps.classList.remove('hidden');
            spineIpsRow.classList.remove('hidden');
            for (let i = 0; i < numSpines; i++) {
                if (i % 4 === 0 && i !== 0) {
                    spineIps.innerHTML += '</tr><tr>';
                }
                spineIps.innerHTML += `<td class="cell"><label for="spine_ip_${i}">Spine IP ${i + 1}:</label><input type="text" id="spine_ip_${i}" name="spine_ip_${i}" required></td>`;
            }
        } else {
            spineIpsRow.classList.add('hidden');
            spineIps.classList.add('hidden');
        }

        if (numSpines > 4) {
            alert('Number of spines cannot be more than 4');
            numSpinesElement.value = 4;
        }
    }

    function updateLeafInputs() {
        const numLeafs = numLeafsElement.value;
        const leafIps = document.getElementById('leafIps');
        const leafIpsRow = document.getElementById('leafIpsRow');

        // Clear existing inputs
        leafIps.innerHTML = '';

        if (numLeafs > 4) {
            alert('Number of leafs cannot be more than 4');
            numLeafsElement.value = 4;
            return;
        }
        if (numLeafs > 0) {
            leafIps.classList.remove('hidden');
            leafIpsRow.classList.remove('hidden');
            for (let i = 0; i < numLeafs; i++) {
                if (i % 4 === 0 && i !== 0) {
                    leafIps.innerHTML += '</tr><tr>';
                }
                leafIps.innerHTML += `<td class="cell"><label for="leaf_ip_${i}">Leaf IP ${i + 1}:</label><input type="text" id="leaf_ip_${i}" name="leaf_ip_${i}" required></td>`;
            }
        } else {
            leafIps.classList.add('hidden');
            leafIpsRow.classList.add('hidden');
        }
    }

    if (numSpinesElement) {
        numSpinesElement.addEventListener('change', function() {
            console.log('num_spines changed', numSpinesElement.value);
            updateSpineInputs();
        });

        // Trigger the initial visibility check for num_spines
        updateSpineInputs();
    } else {
        console.error('num_spines element not found');
    }

    if (numLeafsElement) {
        numLeafsElement.addEventListener('change', function() {
            console.log('num_leafs changed', numLeafsElement.value);
            updateLeafInputs();
        });

        // Trigger the initial visibility check for num_leafs
        updateLeafInputs();
    } else {
        console.error('num_leafs element not found');
    }
});
*/