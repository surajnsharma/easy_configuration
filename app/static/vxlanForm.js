 //vxlanForm.js//





        // Function to always show spine and leaf tag inputs
        function toggleTagInputs() {
            const spineTagsContainer = document.getElementById('spineTagsContainer');
            const leafTagsContainer = document.getElementById('leafTagsContainer');

            // Always show spine and leaf tag inputs
            spineTagsContainer.style.display = 'block';  // Show spine tags
            leafTagsContainer.style.display = 'block';   // Show leaf tags
        }

        // Attach event listener to the overlay service type dropdown
        document.getElementById('overlay_service_type').addEventListener('change', toggleTagInputs);
        // Call the function on page load to set initial state
        document.addEventListener('DOMContentLoaded', toggleTagInputs);

        function showCustomAlert(message) {
            const modalMessage = document.getElementById('vxlanFormAlertMessage');
            modalMessage.innerHTML = message;
            const vxlanFormAlertModal = new bootstrap.Modal(document.getElementById('vxlanFormAlertModal'));
            vxlanFormAlertModal.show();
        }

        function isValidIpAddress(ip) {
            // Regular expression for validating IPv4
            const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

            // Regular expression for validating IPv6, including compressed formats like '2001:db8::'
            const ipv6Regex = /^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|::$/;

            // Split the input based on "/" to check both IPv4 and IPv6 parts
            const ips = ip.split('/');

            // Allow for two parts (IPv4 and IPv6)
            if (ips.length === 2) {
                const ipv4Part = ips[0];
                const ipv6Part = ips[1];

                // Validate IPv4 and IPv6 parts separately
                if (!ipv4Regex.test(ipv4Part)) {
                    return false; // Invalid IPv4 address
                }

                // Ensure the IPv6 part contains "::" for compression
                if (!ipv6Regex.test(ipv6Part) || !ipv6Part.includes('::')) {
                    return false; // Invalid IPv6 address or missing "::"
                }

                return true; // Both parts are valid
            }

            return false; // Input doesn't match the expected IPv4/IPv6 format
        }


        function validateForm() {
            const numSpinesElement = document.getElementById('num_spines');
            const numLeafsElement = document.getElementById('num_leafs');
            const overlayServiceTypeElement = document.getElementById('overlay_service_type');
            const numSpines = parseInt(numSpinesElement.value, 10);
            const numLeafs = parseInt(numLeafsElement.value, 10);
            const overlayServiceType = overlayServiceTypeElement.value;
            const baseIpInput = document.getElementById('base_ip_parts_vxlan').value;
            // Validate number of spines and leafs for vxlan_vlan_aware_t2_seamless_stitching
            if (overlayServiceType === 'vxlan_vlan_aware_t2_seamless_stitching') {
                if (numSpines < 2 || numLeafs < 2) {
                    showCustomAlert("For 'VLAN_AWARE_T2_SEAMLESS_STITCHING', both the number of spines and leafs must be 2 or greater.<br>" +
                                    "Stitching will happen at Spine1 and Spine2 for the VXLAN tunnels from Leaf1 and Leaf2:<br>" +
                                    "Leaf1---T2 VXLAN---Spine1/GW1====Spine2/GW2---T2 VXLAN---Leaf2<br>");
                    return false; // Prevent form submission
                }
            }

            // Validate IP address (IPv4/IPv6 combination)
            if (!isValidIpAddress(baseIpInput)) {
                //alert('Invalid IP address format. Please enter valid IPv4 or IPv6 addresses.');
                alert(`❌ Invalid IP address format: "${baseIpInput}"\n✅ Enter a valid IPv4 or IPv6 address.`);
                return false;  // Prevent form submission
            }

            if (overlayServiceType === "custom_template" && !customTemplateSelect.value) {
                alert("Please select a custom template.");
                return false;
            }
            return true;  // Allow form submission
        }

        // ✅ Attach validation to form submission
        document.addEventListener("DOMContentLoaded", function () {
            const vxlanForm = document.getElementById("vxlanForm");
            if (vxlanForm) {
                vxlanForm.addEventListener("submit", function (event) {
                    if (!validateForm(event)) {
                        event.preventDefault(); // 🚫 Prevent form submission if validation fails
                    }
                });
            }
        });




        function downloadTemplate(event) {
            event.preventDefault(); // Prevent default behavior
            // Get the selected overlay service type from the dropdown
            const selectedService = document.getElementById('overlay_service_type')?.value.trim();
            // Validate if a service type is selected
            if (!selectedService) {
                alert("Please select an overlay service type before downloading the template.");
                return;
            }
            // Log for debugging
            console.log(`Downloading template for: ${selectedService}`);
            // Redirect to the download URL with the selected template type
            window.location.href = `/download_template?template_type=${encodeURIComponent(selectedService)}`;
        }
        function downloadTemplateVariables(event) {
            event.preventDefault();
            console.log(`Downloading generic template variables`);
            // Redirect to the generic variable download URL
            window.location.href = `/download_template_variables`;
        }


    // ✅ Prevent form submission when uploading a custom template
        async function uploadCustomTemplate(event) {
            event.preventDefault(); // 🔴 Prevents form submission

            const fileInput = document.getElementById("customTemplateFile");
            if (!fileInput.files.length) {
                alert("❌ Please select a Jinja2 template file.");
                return;
            }

            const formData = new FormData();
            formData.append("file", fileInput.files[0]);

            try {
                const response = await fetch("/upload_template", {
                    method: "POST",
                    body: formData,
                });

                const result = await response.json();
                if (result.success) {
                    alert("✅ Template uploaded successfully.");
                    fileInput.value = ""; // Reset input field after upload
                    loadUploadedTemplates();
                } else {
                    alert("❌ Error: " + result.error);
                }
            } catch (error) {
                console.error("❌ Error uploading template:", error);
                alert("❌ Failed to upload the template.");
            }
        }

// ✅ Attach event listener to Upload button dynamically
document.addEventListener("DOMContentLoaded", function () {
    const uploadButton = document.getElementById("uploadCustomTemplateBtn");
    if (uploadButton) {
        uploadButton.addEventListener("click", uploadCustomTemplate);
    }
});

// Function to fetch and populate uploaded templates
async function loadUploadedTemplates() {
    try {
        const response = await fetch("/list_uploaded_templates"); // API should return JSON { success: true, templates: [] }
        const result = await response.json();

        if (result.success) {
            const dropdown = document.getElementById("customTemplateSelect");
            dropdown.innerHTML = ""; // Clear previous options

            if (result.templates.length === 0) {
                dropdown.innerHTML = `<option value="">No templates uploaded</option>`;
            } else {
                result.templates.forEach((template) => {
                    const option = document.createElement("option");
                    option.value = template;
                    option.textContent = template;
                    dropdown.appendChild(option);
                });
            }
        } else {
            console.error("Error fetching templates:", result.error);
        }
    } catch (error) {
        console.error("Error loading uploaded templates:", error);
    }
}



document.addEventListener('DOMContentLoaded', function() {

        /*const downloadButton = document.getElementById('downloadTemplateBtn');
        if (downloadButton) {
            downloadButton.addEventListener('click', function(event) {
                event.preventDefault(); // Stop any unintended form submission
                window.location.href = "/download_template"; // Redirect to the download route
            });
        }*/


        const overlayServiceType = document.getElementById("overlay_service_type");
        const customTemplateSection = document.getElementById("customTemplateSection");
        const customTemplateSelect = document.getElementById("customTemplateSelect");



        const numSpinesElement = document.getElementById('num_spines');
        const numLeafsElement = document.getElementById('num_leafs');
        const spineIpsRow = document.getElementById('spineIpsRow');
        const leafIpsRow = document.getElementById('leafIpsRow');
        const leafServiceCheckbox = document.getElementById('leafServiceCheckbox');
        const leafServiceTableBody = document.querySelector('#leafServiceTable tbody');
        const spineTagsContainer = document.getElementById('spineTagsContainer');
        const leafTagsContainer = document.getElementById('leafTagsContainer');

        // Function to update Spine Tags (as select dropdowns) and IPs in one row with 1-col wide select
        function updateSpineTagsAndIps() {
            const spineTagsContainer = document.getElementById('spineTagsContainer');
            spineTagsContainer.innerHTML = '';  // Clear existing tags and inputs
            const numSpines = parseInt(document.getElementById('num_spines').value);

            // Sample options for the select dropdown (replace with actual tag options as needed)
            const tagOptions = ['Tag 1', 'Tag 2', 'Tag 3', 'Tag 4'];

            // Create a row div to contain all spine tag and IP inputs in one row
            const rowDiv = document.createElement('div');
            rowDiv.classList.add('row', 'gx-2', 'mb-2');  // Bootstrap row with gutter spacing

            for (let i = 1; i <= numSpines; i++) {
                // Create a column div for each spine tag + input group (spanning the whole row)
                const colDiv = document.createElement('div');
                colDiv.classList.add('col-md-3');  // Each tag and input takes 3 columns
                // Create the input group div
                const inputGroupDiv = document.createElement('div');
                inputGroupDiv.classList.add('input-group', 'input-group-sm');  // Bootstrap input-group
                // Create the select dropdown for Spine Tag (1-column wide equivalent)
                const selectTag = document.createElement('select');
                selectTag.classList.add('form-select');  // Bootstrap select dropdown styling
                selectTag.id = `spine_tag_${i}`;
                selectTag.name = `spine_tag_${i}`;
                selectTag.style.width = '5%';  // Similar to the 1-column width for input-group-text

                // Populate the select dropdown with options
                tagOptions.forEach(optionText => {
                    const option = document.createElement('option');
                    option.value = optionText;
                    option.textContent = optionText;
                    selectTag.appendChild(option);
                });

                // Create the input for Spine IP
                const inputIp = document.createElement('input');
                inputIp.type = 'text';
                inputIp.id = `spine_ip_${i}`;
                inputIp.name = `spine_ip_${i}`;
                inputIp.classList.add('form-control');  // Use form-control for Bootstrap styling
                inputIp.placeholder = `Spine ${i} IP`;  // Placeholder for the IP
                inputIp.style.width = '50%';

                // Append the select dropdown and input to the input group
                inputGroupDiv.appendChild(selectTag);
                inputGroupDiv.appendChild(inputIp);

                // Append the input group to the column div
                colDiv.appendChild(inputGroupDiv);

                // Append the column div to the row div
                rowDiv.appendChild(colDiv);
            }

            // Append the row div to the spineTagsContainer
            spineTagsContainer.appendChild(rowDiv);
        }

        // Call the function on form load or when number of spines changes
        document.getElementById('num_spines').addEventListener('change', updateSpineTagsAndIps);

        // Initial call to display inputs on page load
        updateSpineTagsAndIps();


        // Function to update Leaf Tags (as select dropdowns) and Leaf IPs in one row
        function updateLeafTagsAndIps() {
            const leafTagsContainer = document.getElementById('leafTagsContainer');
            leafTagsContainer.innerHTML = '';  // Clear existing tags and inputs
            const numLeafs = parseInt(document.getElementById('num_leafs').value);  // Fetch the number of leafs

            // Sample options for the select dropdown (replace with actual tag options as needed)
            const tagOptions = ['Tag 1', 'Tag 2', 'Tag 3', 'Tag 4'];

            // Create a row div to contain all leaf tag and IP inputs in one row
            const rowDiv = document.createElement('div');
            rowDiv.classList.add('row', 'gx-2', 'mb-2');  // Bootstrap row with gutter spacing

            for (let i = 1; i <= numLeafs; i++) {
                // Create a column div for each leaf tag + IP input group
                const colDiv = document.createElement('div');
                colDiv.classList.add('col-md-3');  // Each tag and input takes 3 columns
                // Create the input group div
                const inputGroupDiv = document.createElement('div');
                inputGroupDiv.classList.add('input-group', 'input-group-sm');  // Bootstrap input-group
                // Create the select dropdown for Leaf Tag (25% width)
                const selectTag = document.createElement('select');
                selectTag.classList.add('form-select');  // Bootstrap select dropdown styling
                selectTag.id = `leaf_tag_${i}`;
                selectTag.name = `leaf_tag_${i}`;
                selectTag.style.width = '5%';  // Make the tag select take up 25% of the space
                // Populate the select dropdown with options
                tagOptions.forEach(optionText => {
                    const option = document.createElement('option');
                    option.value = optionText;
                    option.textContent = optionText;
                    selectTag.appendChild(option);
                });

                // Create the input for Leaf IP (75% width)
                const inputIp = document.createElement('input');
                inputIp.type = 'text';
                inputIp.id = `leaf_ip_${i}`;
                inputIp.name = `leaf_ip_${i}`;
                inputIp.classList.add('form-control');  // Bootstrap form-control
                inputIp.placeholder = `Leaf ${i} IP`;  // Placeholder for Leaf IP
                inputIp.style.width = '50%';  // Make the input take up 75% of the space

                // Append the select dropdown and input to the input group
                inputGroupDiv.appendChild(selectTag);
                inputGroupDiv.appendChild(inputIp);

                // Append the input group to the column div
                colDiv.appendChild(inputGroupDiv);

                // Append the column div to the row div
                rowDiv.appendChild(colDiv);
            }

            // Append the row div to the leafTagsContainer
            leafTagsContainer.appendChild(rowDiv);
        }

        // Call the function on form load or when the number of leafs changes
        document.getElementById('num_leafs').addEventListener('change', updateLeafTagsAndIps);

        // Initial call to display inputs on page load
        updateLeafTagsAndIps();



        // Function to update Leaf Service Table inputs
        function updateLeafServiceTable(numLeafs) {
            leafServiceTableBody.innerHTML = ''; // Clear existing table
            for (let i = 0; i < numLeafs; i++) {
                let row = `
                    <tr>
                        <td><input type="text" id="service_int_${i}" name="service_int_${i}" class="form-control" placeholder="Comma Sep Interface for Leaf ${i + 1}"></td>
                        <td>
                            <select id="Intf_style_${i}" name="Intf_style_${i}" class="form-select">
                                <option value="epStyle">EP</option>
                                <option value="spStyle">SP</option>
                            </select>
                        </td>
                        <td class="text-center align-middle">
                            <div class="d-flex justify-content-center align-items-center">
                                <input type="checkbox" id="enable_esi_lag_${i}" name="enable_esi_lag_${i}" value="true" class="form-check-input" onchange="toggleESILAG(${i})">
                            </div>
                        </td>
                        <td><input type="text" id="esi_id_${i}" name="esi_id_${i}" class="form-control" value="0001:0001:0001:0001:0001" disabled></td>
                        <td>
                            <select id="lacp_mode_${i}" name="lacp_mode_${i}" class="form-select" disabled>
                                <option value="active">Active</option>
                                <option value="passive">Passive</option>
                            </select>
                        </td>
                        <td><input type="text" id="lag_intfs_${i}" name="lag_intfs_${i}" class="form-control" value="ae0" disabled></td>
                    </tr>`;
                leafServiceTableBody.innerHTML += row;
            }
        }

        // Global function to toggle ESI LAG configuration visibility
        window.toggleESILAG = function(index) {
            const checkbox = document.getElementById(`enable_esi_lag_${index}`);
            const esiID = document.getElementById(`esi_id_${index}`);
            const lacpMode = document.getElementById(`lacp_mode_${index}`);
            const lagIntfs = document.getElementById(`lag_intfs_${index}`);
            if (checkbox && esiID && lacpMode && lagIntfs) {
                const enable = checkbox.checked;
                esiID.disabled = !enable;
                lacpMode.disabled = !enable;
                lagIntfs.disabled = !enable;
            }
        };


        leafServiceCheckbox.addEventListener('change', function() {
            if (leafServiceCheckbox.checked) {
                updateLeafServiceTable(parseInt(numLeafsElement.value, 10));
            } else {
                leafServiceTableBody.innerHTML = ''; // Clear table if unchecked
            }
        });


    // Radio button toggle behavior (uncheck when clicked again)
    let lastChecked = null;  // Store the last checked radio button
    const radios = document.querySelectorAll('.btn-check');
    radios.forEach(radio => {
        radio.addEventListener('click', function() {
            if (lastChecked === this) {
                this.checked = false;  // Uncheck the radio button if it's clicked again
                lastChecked = null;    // Reset the last checked variable
            } else {
                lastChecked = this;    // Update the last checked variable
            }
            // Log the currently checked radio or show null if none selected
            //console.log(`Currently checked: ${lastChecked ? lastChecked.id : 'None'}`);
        });
    });



// Function to handle visibility of upload & select dropdown
function handleOverlaySelection() {
    const overlayServiceType = document.getElementById("overlay_service_type").value;
    const customTemplateSection = document.getElementById("customTemplateSection");
    const uploadedTemplatesDropdown = document.getElementById("customTemplateSelect");

    if (overlayServiceType === "custom_template") {
        customTemplateSection.style.display = "block";

        if (uploadedTemplatesDropdown) {
            loadUploadedTemplates(); // ✅ Fetch existing templates
        }
    } else {
        customTemplateSection.style.display = "none";
    }
}

        // Toggle custom template upload input
        function toggleCustomTemplateUpload() {
            const overlayServiceType = document.getElementById("overlay_service_type").value;
            const uploadSection = document.getElementById("customTemplateUpload");

            if (overlayServiceType === "custom_template") {
                uploadSection.style.display = "block";
            } else {
                uploadSection.style.display = "none";
            }
        }



    function downloadTemplate(event) {
        event.preventDefault();
        const selectedService = document.getElementById('overlay_service_type')?.value.trim();
        if (!selectedService) {
            alert("Please select an overlay service type.");
            return;
        }
        window.location.href = `/download_template?template_type=${encodeURIComponent(selectedService)}`;
    }

    function downloadTemplateVariables(event) {
        event.preventDefault();
        const selectedService = document.getElementById('overlay_service_type')?.value.trim();
        if (!selectedService) {
            alert("Please select an overlay service type.");
            return;
        }
        window.location.href = `/download_template_variables?template_type=${encodeURIComponent(selectedService)}`;
    }

    // Attach event listener for the dropdown to ensure visibility toggle
    document.getElementById('overlay_service_type').addEventListener('change', handleOverlaySelection);



    if (overlayServiceType) {
        overlayServiceType.addEventListener("change", function () {
            handleOverlaySelection();
        });


        // ✅ Ensure the function runs properly on page load
        handleOverlaySelection();
    }
    // ✅ Event Listener to Show File Name When Browsing
    document.getElementById("customTemplateFile").addEventListener("change", function () {
        const fileName = this.files.length ? this.files[0].name : "No file chosen";
        document.getElementById("selectedFileName").value = fileName;
    });

});

