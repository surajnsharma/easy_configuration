document.addEventListener('DOMContentLoaded', function() {
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
