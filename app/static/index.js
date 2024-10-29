


    document.addEventListener('DOMContentLoaded', function () {
            const forms = [
                'vlanConfigForm', 'bgpForm', 'vxlanForm', 'underlayConfigForm', 'uploadConfigForm',
                'onboardDevicesForm', 'generateConfigForm','telemetryForm',
               'deviceTelemetryForm','triggerEventsForm'
            ];
            const toggleButtons = [
                'toggleVlanFormBtn', 'toggleBgpFormBtn', 'toggleVxlanFormBtn', 'toggleunderlayConfigBtn',
                'toggleUploadConfigFormBtn', 'toggleOnboardFormBtn', 'toggleGenerateConfigFormBtn', 'toggleTriggerEventsFormBtn',
                'toggleTelemetryBtn'
            ];

        toggleButtons.forEach((btnId, index) => {
                const button = document.getElementById(btnId);
                if (button) {
                    button.addEventListener('click', function () {
                        forms.forEach((formId, formIndex) => {
                            const form = document.getElementById(formId);
                            if (form) {
                                if (formIndex === index) {
                                    form.classList.toggle('hidden');
                                    button.classList.toggle('active-button');
                                } else {
                                    form.classList.add('hidden');
                                    const toggleBtn = document.getElementById(toggleButtons[formIndex]);
                                    if (toggleBtn) {
                                        toggleBtn.classList.remove('active-button');
                                    }
                                }
                            }
                        });
                    });
                }
            });


            document.querySelectorAll('#sidebar .nav-link').forEach(link => {
                link.addEventListener('click', function (event) {
                    event.preventDefault();
                    const targetId = link.getAttribute('href').substring(1);
                    forms.forEach(formId => {
                        const form = document.getElementById(formId);
                        if (form) {
                            form.classList.add('hidden');
                        }
                    });
                    const targetForm = document.getElementById(targetId);
                    if (targetForm) {
                        targetForm.classList.remove('hidden');
                    }
                });
            });
        });
