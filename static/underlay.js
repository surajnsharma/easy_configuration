document.addEventListener('DOMContentLoaded', function() {
    window.showGeneratedConfig = function() {
        setButtonClicked('showGeneratedConfigBtn');
        const form = document.getElementById('uploadForm');
        const configMethod = document.getElementById('config_method').value;
        if (configMethod === 'csv') {
            form.action = '/show_csvgenerated_config';
        } else {
            form.action = '/show_generated_config';
        }
        form.submit();
    };

    window.setButtonClicked = function(value) {
        const buttonClickedInput = document.querySelector('input[name="button_clicked"]');
        buttonClickedInput.value = value;
    };

    // Attach event listeners to the buttons
    const showConfigButton = document.getElementById('showConfigBtn');
    if (showConfigButton) {
        showConfigButton.addEventListener('click', showGeneratedConfig);
    }

    const pushConfigButton = document.querySelector('input[type="submit"]');
    if (pushConfigButton) {
        pushConfigButton.addEventListener('click', function() {
            setButtonClicked('transferConfigBtn');
        });
    }
    // Get the modal
        var sampleCsvModal = document.getElementById("sampleCsvModal");
        // Get the button that opens the modal
        var sampleCsvBtn = document.getElementById("sampleCsvBtn");
        // Get the <span> element that closes the modal
        var sampleCsvClose = document.getElementsByClassName("close")[0];
        // When the user clicks the button, open the modal
        sampleCsvBtn.onclick = function() {
            sampleCsvModal.style.display = "block";
        }
        // When the user clicks on <span> (x), close the modal
        sampleCsvClose.onclick = function() {
            sampleCsvModal.style.display = "none";
        }
        // When the user clicks anywhere outside of the modal, close it
        window.onclick = function(event) {
            if (event.target == sampleCsvModal) {
                sampleCsvModal.style.display = "none";
            }
        }

});
