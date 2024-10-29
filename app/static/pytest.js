document.addEventListener('DOMContentLoaded', function() {
    const pytestForm = document.getElementById('pytestForm');
    const newInputCheckbox = document.getElementById('new_input');
    const logOutput = document.getElementById('log_output');
    const keywordInputsContainer = document.getElementById('keyword-inputs-container');
    const scriptContainer = document.getElementById('generated_pytest_script');

    let allTestCases = '';

    pytestForm.addEventListener('submit', function(event) {
        event.preventDefault();
        generatePytestScript(false);
    });

    document.getElementById('mergeTestCasesBtn').addEventListener('click', function() {
        generatePytestScript(true);
    });

    function generatePytestScript(isMerge) {
        const formData = new FormData(pytestForm);

        fetch(isMerge ? '/merge_pytest' : '/generate_pytest', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                if (isMerge) {
                    scriptContainer.innerText += "\n\n" + data.pytest_code;
                    allTestCases += "\n\n" + data.pytest_code;
                } else {
                    scriptContainer.innerText = data.pytest_code;
                    allTestCases = data.pytest_code;  // Reset and start fresh
                    console.log(allTestCases); // Log scriptContainer content for debugging
                    // Write the entire scriptContainer content to a file
                    writePytestFile(allTestCases);
                }
            } else {
                scriptContainer.innerText = 'Error: ' + data.error;
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });

        if (isMerge && newInputCheckbox.checked) {
            logOutput.value = '';
            keywordInputsContainer.innerHTML = '<input type="text" class="form-control mb-2" name="keyword_inputs" placeholder="Enter keywords, separated by commas">';
            newInputCheckbox.checked = false;
        }
    }

    function writePytestFile(pytestCode) {
        fetch('/write_pytest_file', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ pytest_code: pytestCode })  // Send entire scriptContainer content
        })
        .catch(error => console.error('Error writing file:', error));
    }
});

function addKeywordInput() {
    const keywordInputsContainer = document.getElementById('keyword-inputs-container');
    const newInput = document.createElement('input');
    newInput.type = 'text';
    newInput.className = 'form-control mb-2';
    newInput.name = 'keyword_inputs';
    newInput.placeholder = 'Enter keywords, separated by commas';
    keywordInputsContainer.appendChild(newInput);
}
