document.addEventListener('DOMContentLoaded', () => {
    const cardHeaders = document.querySelectorAll('.card-header');

    cardHeaders.forEach(header => {
        header.addEventListener('click', () => {
            const cardBody = header.nextElementSibling;

            if (cardBody.style.display === 'none' || cardBody.style.display === '') {
                cardBody.style.display = 'block'; // Show the card body
            } else {
                cardBody.style.display = 'none'; // Hide the card body
            }
        });
    });
});



document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.getElementById('fileInput');
    const resultDisplay = document.getElementById('result');
    const xmlprogressBar = document.getElementById('xmlprogressBar');
    const socket = io();
    console.log("Initialized xml Robot WebSocket connection with Socket.IO");


// Handle progress updates from the server
socket.on('xmlRobotprogress', (data) => {
    console.log("Progress update received:", data);

    // Ensure the progress bar is visible
    progressContainer.style.display = 'block';

    if (data.progress !== undefined) {
        const progress = Math.min(Math.max(data.progress, 0), 100); // Clamp between 0 and 100
        xmlprogressBar.style.width = `${progress}%`;
        xmlprogressBar.textContent = `${progress}%`;
        console.log(`Progress bar updated to: ${progress}%`);

        // Hide the progress bar after reaching 100%
        if (progress === 100) {
            setTimeout(() => {
                xmlprogressBar.style.width = '0%'; // Reset the width for next use
                xmlprogressBar.textContent = ''; // Clear the text content
                progressContainer.style.display = 'none'; // Hide the progress bar container
                console.log("Progress bar hidden after completion.");
            }, 2000); // Brief delay before hiding
        }
    }

    // Display status messages
    const messageElement = document.createElement('div');
    messageElement.textContent = `${data.status.toUpperCase()}: ${data.message}`;
    resultDisplay.appendChild(messageElement);
});




    uploadForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        // Clear previous results
        if (resultDisplay) {
            resultDisplay.innerHTML = ''; // Clear the Parse Results section
            //console.log("Parse Results cleared.");
        }
        const file = fileInput.files[0];
        if (!file) {
            resultDisplay.textContent = "Please select a file before uploading.";
            return;
        }

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        const nameSuggestions = document.getElementById('nameSuggestions').checked;
        formData.append('nameSuggestions', nameSuggestions);
        xmlprogressBar.style.width = '0%';
        xmlprogressBar.textContent = '0%';



        try {
            const response = await fetch('/api/uploadRobotDebugFile', {
                method: 'POST',
                body: formData,
            });

            const result = await response.json();

            if (response.ok) {
                resultDisplay.innerHTML = ""; // Clear previous content

                // Display the uploaded filename
                if (result.filename) {
                    const fileNameElement = document.createElement('div');
                    fileNameElement.textContent = `Uploaded File: ${result.filename}`;
                    fileNameElement.style.fontWeight = "bold";
                    fileNameElement.style.marginBottom = "10px";
                    resultDisplay.appendChild(fileNameElement);
                }

                // Display failures
                if (result.failures) {
                    const failureHeader = document.createElement('div');
                    failureHeader.textContent = "Failures:";
                    failureHeader.style.fontWeight = "bold";
                    resultDisplay.appendChild(failureHeader);

                    const lines = result.failures.split("\n");
                    lines.forEach((line) => {
                        const lineElement = document.createElement('div');
                        if (line.startsWith("=> General Failures") || line.startsWith("=>")) {
                            lineElement.style.color = "blue"; // Apply blue color
                        }else if (line.startsWith("[TestCase Description]")) {
                            lineElement.style.color = "#2972b6 ";
                        }

                        lineElement.textContent = line;
                        resultDisplay.appendChild(lineElement);
                    });
                }

                // Display suggestions
                if (result.suggestions) {
                    const suggestionHeader = document.createElement('div');
                    suggestionHeader.textContent = "Corrective Actions:";
                    suggestionHeader.style.fontWeight = "bold";
                    suggestionHeader.style.marginTop = "20px";
                    resultDisplay.appendChild(suggestionHeader);

                    const suggestionLines = result.suggestions.split("\n");
                    suggestionLines.forEach((line) => {
                        const suggestionElement = document.createElement('div');
                        suggestionElement.style.color = "green"; // Apply green color for suggestions
                        if (line.startsWith("Suggested Action:")) {
                            suggestionElement.style.color = "blue"; // Apply black color for suggestions
                        }
                        suggestionElement.textContent = line;
                        resultDisplay.appendChild(suggestionElement);
                    });
                }

                // Display unmatched message if present
                if (result.unmatched_message) {
                    const unmatchedHeader = document.createElement('div');
                    unmatchedHeader.textContent = "Unmatched Errors:";
                    unmatchedHeader.style.fontWeight = "bold";
                    unmatchedHeader.style.color = "red";
                    unmatchedHeader.style.marginTop = "20px";
                    resultDisplay.appendChild(unmatchedHeader);

                    const unmatchedMessageElement = document.createElement('div');
                    unmatchedMessageElement.style.color = "red";
                    unmatchedMessageElement.textContent = result.unmatched_message;
                    resultDisplay.appendChild(unmatchedMessageElement);
                }
            } else {
                resultDisplay.textContent = `Error: ${result.message || 'Unknown error occurred'}`;
            }
        } catch (error) {
            resultDisplay.textContent = `Error: ${error.message}`;
        }
    });

});



// Display Results Function
function displayResults(data) {
    const resultElement = document.getElementById("result");
    if (data.status === "error") {
        resultElement.textContent = `Error: ${data.message}`;
        return;
    }
    if (data.failures && Object.keys(data.failures).length > 0) {
        let resultText = "";
        for (const [testName, failureDetails] of Object.entries(data.failures)) {
            resultText += `Testcase: ${testName}\n`;
            if (failureDetails.failures.length > 0) {
                resultText += "  Failures:\n";
                failureDetails.failures.forEach(msg => (resultText += `    - ${msg}\n`));
            }
            if (failureDetails.teardown_failures.length > 0) {
                resultText += "  Teardown Failures:\n";
                failureDetails.teardown_failures.forEach(msg => (resultText += `    - ${msg}\n`));
            }
            if (failureDetails.parent_teardown_failures.length > 0) {
                resultText += "  Parent Teardown Failures:\n";
                failureDetails.parent_teardown_failures.forEach(msg => (resultText += `    - ${msg}\n`));
            }
            resultText += "\n";
        }
        resultElement.textContent = resultText;
    } else {
        resultElement.textContent = "No failures detected in the uploaded XML.";
    }
}



// Load Categories
async function loadCategories() {
    try {
        const response = await fetch("/getCategories");
        const data = await response.json();
        const categoryInput = document.getElementById("categoryInput");
        categoryInput.innerHTML = '<option value="">Select a category</option>';
        data.categories.forEach((category) => {
            const option = document.createElement("option");
            option.value = category;
            option.textContent = category;
            categoryInput.appendChild(option);
        });
    } catch (error) {
        console.error("Error loading categories:", error);
    }
}

// Save Changes to an Existing Pattern
async function updatePatternChanges() {
    const pattern = document.getElementById("patternInput").value.trim();
    const suggestion = document.getElementById("suggestionInput").value.trim();
    if (!pattern || !suggestion) {
        alert("Please select a pattern and provide a suggestion.");
        return;
    }
    try {
        const response = await fetch("/updatePattern", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pattern, suggestion }),
        });
        const result = await response.json();
        alert(result.message);
    } catch (error) {
        console.error("Error saving changes:", error);
    }
}


// Initialize Input Method Toggle
document.addEventListener("DOMContentLoaded", function () {
    const inputMethodSelect = document.getElementById("inputMethodSelect");
    inputMethodSelect.value = "text"; // Default to "Text Input"
    inputMethodSelect.dispatchEvent(new Event("change")); // Trigger initial toggle
    // Initialize Save, Add, and Delete Actions
    document.getElementById("updatePatternIcon").addEventListener("click", updatePatternChanges);
    document.getElementById("addNewPatternModalSave").addEventListener("click", addNewPatternSave);
    //document.getElementById("deleteIcon").addEventListener("click", deletePattern);
    // Load Categories on Page Load
    loadCategories();
});


// Initialize on page load to set the correct visibility
document.addEventListener("DOMContentLoaded", function () {
    const method = document.getElementById("inputMethodSelect").value;
    const submitButtonGroup = document.getElementById("submitButtonGroup");
    if (method === "text") {
        submitButtonGroup.style.display = "none";
    } else {
        submitButtonGroup.style.display = "block";
    }
});

// Toggle Input Fields Based on Selected Method
document.getElementById("inputMethodSelect").addEventListener("change", function () {
    const method = this.value;
    const submitButtonGroup = document.getElementById("submitButtonGroup");
    if (method === "text") {
        // Hide the submit button when "text" is selected
        submitButtonGroup.style.display = "none";
    } else {
        // Show the submit button for other methods
        submitButtonGroup.style.display = "block";
    }
    // Toggle visibility
    //document.getElementById("fileInputGroup").style.display = method === "file" ? "block" : "none";
    document.getElementById("jsonInputGroup").style.display = method === "json" ? "block" : "none";
    document.getElementById("textInputGroup").style.display = method === "text" ? "block" : "none";
    // Populate categories for text input
    if (method === "text") {
        fetch("/getCategories")
            .then(response => {
                if (!response.ok) throw new Error("Failed to fetch categories");
                return response.json();
            })
            .then(data => {
                const categoryInput = document.getElementById("categoryInput");
                categoryInput.innerHTML = '<option value="">Select a category</option>'; // Clear options
                data.categories.forEach(category => {
                    const option = document.createElement("option");
                    option.value = category;
                    option.textContent = category;
                    categoryInput.appendChild(option);
                });
            })
            .catch(error => console.error("Error loading categories:", error));
    }
});



document.getElementById("trainingForm").onsubmit = async function (event) {
    event.preventDefault();
    const method = document.getElementById("inputMethodSelect").value;
    if (method === "json") {
        const jsonFile = document.getElementById("jsonDataFile").files[0];
        if (!jsonFile) {
            alert("Please select a JSON file.");
            return;
        }
        const formData = new FormData();
        formData.append("file", jsonFile);
        try {
            const response = await fetch("/uploadJsonTrainingFile", { method: "POST", body: formData });
            const result = await response.json();
            alert(result.message);
        } catch (error) {
            console.error("JSON upload failed:", error);
        }
    }  else {
        alert("Invalid input method selected.");
    }
};


document.getElementById("openAddPatternModel").addEventListener("click", function (event) {
    event.preventDefault(); // Prevent any default action
    const category = document.getElementById("categoryInput").value.trim(); // Get the selected category
    // Check if a category is selected
    if (!category) {
        alert("Please select a category before adding a new pattern.");
        return; // Exit if no category is selected
    }
    // Open the modal for adding a new pattern
    openAddPatternModal();
});


function openAddPatternModal() {
// Open the modal for adding a new pattern
    // Clear modal inputs
    document.getElementById("newPatternInput").value = "";
    document.getElementById("newSuggestionInput").value = "";
    // Show modal
    document.getElementById("addPatternModal").style.display = "block";
}


document.getElementById("categoryInput").addEventListener("change", async function () {
    const category = this.value;

    if (!category) {
        alert("Please select a category.");
        return;
    }

    try {
        const response = await fetch(`/getTrainingData?category=${encodeURIComponent(category)}`);
        if (!response.ok) {
            throw new Error("Failed to fetch training data.");
        }
        const data = await response.json();

        // Populate match pattern dropdown
        const matchPatternSelect = document.getElementById("patternInput");
        matchPatternSelect.innerHTML = '<option value="">Select a match pattern</option>'; // Clear existing options

        data.forEach(item => {
            const option = document.createElement("option");
            option.value = item.pattern;
            option.textContent = item.pattern;
            matchPatternSelect.appendChild(option);
        });

        // Clear suggestion input
        document.getElementById("suggestionInput").value = "";

    } catch (error) {
        console.error("Error fetching training data:", error);
        alert("An error occurred while fetching training data.");
    }
});

document.getElementById("patternInput").addEventListener("change", function () {
    const selectedPattern = this.value;
    if (selectedPattern) {
        fetch(`/getTrainingData?category=${encodeURIComponent(document.getElementById("categoryInput").value)}`)
            .then(response => {
                if (!response.ok) throw new Error("Failed to fetch training data.");
                return response.json();
            })
            .then(data => {
                const suggestion = data.find(item => item.pattern === selectedPattern)?.suggestion || "";
                document.getElementById("suggestionInput").value = suggestion;
            })
            .catch(error => {
                console.error("Error fetching suggestions:", error);
                alert("An error occurred while fetching suggestions.");
            });
    } else {
        document.getElementById("suggestionInput").value = "";
    }
});


document.addEventListener("DOMContentLoaded", function () {
    const categoryInput = document.getElementById("categoryInput");
    const patternInput = document.getElementById("patternInput");
    const saveBtn = document.getElementById("saveBtn");
    const addBtn = document.getElementById("addBtn");

    // Clear the suggestion input on page load
    const suggestionInput = document.getElementById("suggestionInput");
    if (suggestionInput) {
        suggestionInput.value = ""; // Clear the textarea
    }

    // Load categories on page load
    fetch("/getCategories")
        .then((response) => response.json())
        .then((data) => {
            const categories = data.categories || [];
            categoryInput.innerHTML = '<option value="">Select a category</option>';
            categories.forEach((category) => {
                const option = document.createElement("option");
                option.value = category;
                option.textContent = category;
                categoryInput.appendChild(option);
            });
        })
        .catch((error) => console.error("Error loading categories:", error));

    // Load patterns when a category is selected
    categoryInput.addEventListener("change", function () {
        const category = categoryInput.value;
        if (category) {
            fetch(`/getPatterns?category=${encodeURIComponent(category)}`)
                .then((response) => response.json())
                .then((data) => {
                    const patterns = data.patterns || [];
                    patternInput.innerHTML = '<option value="">Select a match pattern</option>';
                    patterns.forEach((pattern) => {
                        const option = document.createElement("option");
                        option.value = pattern;
                        option.textContent = pattern;
                        patternInput.appendChild(option);
                    });
                })
                .catch((error) => console.error("Error loading patterns:", error));
        } else {
            patternInput.innerHTML = '<option value="">Select a match pattern</option>';
        }
        suggestionInput.value = ""; // Clear suggestion field
    });

    // Load suggestion when a pattern is selected
    patternInput.addEventListener("change", function () {
        const pattern = patternInput.value;
        if (pattern) {
            fetch(`/getSuggestion?pattern=${encodeURIComponent(pattern)}`)
                .then((response) => response.json())
                .then((data) => {
                    suggestionInput.value = data.suggestion || "No suggestion available.";
                })
                .catch((error) => console.error("Error loading suggestion:", error));
        } else {
            suggestionInput.value = ""; // Clear suggestion field
        }
    });
});


// Delete Pattern
document.getElementById("deleteIcon").addEventListener("click", async function () {
    const pattern = document.getElementById("patternInput").value.trim();
    if (!pattern) {
        alert("Please select a pattern to delete.");
        return;
    }
    const confirmDelete = confirm(`Are you sure you want to delete the pattern "${pattern}"?`);
    if (!confirmDelete) return;
    try {
        const response = await fetch("/deletePattern", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pattern }),
        });
        const result = await response.json();
        if (response.ok) {
            alert(result.message || "Pattern deleted successfully.");

            // Clear the suggestion field
            document.getElementById("suggestionInput").value = "";

            // Refresh the patterns dropdown
            const category = document.getElementById("categoryInput").value.trim();
            if (category) {
                const patternsResponse = await fetch(`/getPatterns?category=${encodeURIComponent(category)}`);
                const patternsData = await patternsResponse.json();
                const patternInput = document.getElementById("patternInput");
                patternInput.innerHTML = '<option value="">Select a match pattern</option>'; // Clear current options
                patternsData.patterns.forEach((pattern) => {
                    const option = document.createElement("option");
                    option.value = pattern;
                    option.textContent = pattern;
                    patternInput.appendChild(option);
                });
            }
        } else {
            alert(result.message || "Failed to delete the pattern.");
        }
    } catch (error) {
        console.error("Error deleting pattern:", error);
        alert("An error occurred. Please try again.");
    }
});


// Open the modal
function openAddPatternModal() {
    document.getElementById("addPatternModal").style.display = "block";
}


// Close Modal
function closeAddPatternModal() {
    const modal = document.getElementById("addPatternModal");
    modal.style.display = "none";
    modal.querySelector("#newPatternInput").value = "";
    modal.querySelector("#newSuggestionInput").value = "";
}



// Close the modal
function closeAddPatternModal() {
    document.getElementById("addPatternModal").style.display = "none";
}

// Save new pattern and suggestion to the selected category
async function addNewPatternSave() {
    const category = document.getElementById("categoryInput").value.trim();
    const pattern = document.getElementById("newPatternInput").value.trim();
    const suggestion = document.getElementById("newSuggestionInput").value.trim();

    if (!category || !pattern || !suggestion) {
        alert("Please provide both pattern and suggestion.");
        return;
    }

    try {
        const response = await fetch("/addPattern", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ category, pattern, suggestion }),
        });

        const result = await response.json();
        if (response.ok) {
            alert(result.message || "Pattern added successfully.");

            // Refresh patterns dropdown
            const patternsResponse = await fetch(`/getPatterns?category=${encodeURIComponent(category)}`);
            const patternsData = await patternsResponse.json();

            const patternInput = document.getElementById("patternInput");
            patternInput.innerHTML = '<option value="">Select a match pattern</option>'; // Clear current options
            patternsData.patterns.forEach((pattern) => {
                const option = document.createElement("option");
                option.value = pattern;
                option.textContent = pattern;
                patternInput.appendChild(option);
            });

            closeAddPatternModal(); // Close the modal
        } else {
            alert(result.message || "Failed to add pattern.");
        }
    } catch (error) {
        console.error("Error adding new pattern:", error);
        alert("An error occurred. Please try again.");
    }
}




