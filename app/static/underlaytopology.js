document.addEventListener('DOMContentLoaded', function() {
        $(document).ready(function () {
        $('#saveTopoCsvBtn').on('click', function () {
        //var configMethod = $('#config_method').val();
        const configMethod = document.getElementById('config_method').value;
         //console.log(configMethod)
        var fileInput = document.getElementById('csv_file');
        //console.log(fileInput)
        if (configMethod === 'csv') {
            var formData = new FormData($('#underlayConfigForm')[0]);
            $.ajax({
                url: '/save_underlay_topology_csv',
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function (response) {
                    alert('Success..! CSV file saved successfully.');
                },
                error: function () {
                    alert('Error..! Error saving CSV file. check if csv file is selected.');
                }
            });
        } else if (configMethod === 'lldp') {
            $.ajax({
                url: '/save_underlay_topology_lldp',
                type: 'POST',
                success: function (response) {
                    if (response.connections) {
                        alert('Success..! LLDP Neighbors Saved.', response.connections);
                    } else {
                        alert('Error..! Invalid response format.', response.connections);
                    }
                },
                error: function () {
                    alert('Error generating LLDP connections.');
                }
            });
        }
    });

function renderTopology(topology) {
    var cy = cytoscape({
        container: document.getElementById('cy'),
        elements: [],
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'background-color': 'green',
                    'shape': 'rectangle',
                    'width': 'label',
                    'height': 'label',
                    'padding': '10px',
                    'color': '#fff',
                    'font-size': '12px'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#ccc',
                    'target-arrow-color': '#ccc',
                    'target-arrow-shape': 'none',
                    'label': 'data(label)',
                    'font-size': '9px',
                    'color': 'pink',
                    'text-margin-y': 'data(textOffset)',
                    'curve-style': 'straight'
                }
            }
        ],
        layout: {
            name: 'cose'
        }
    });

    var nodes = [];
    var edges = [];

    // Dynamically determine the keys for devices and interfaces
    var device1Key = Object.keys(topology[0]).find(key => key.toLowerCase().includes('device1'));
    var device2Key = Object.keys(topology[0]).find(key => key.toLowerCase().includes('device2'));
    var interface1Key = Object.keys(topology[0]).find(key => key.toLowerCase().includes('interface1'));
    var interface2Key = Object.keys(topology[0]).find(key => key.toLowerCase().includes('interface2'));

    topology.forEach(function (connection) {
        var device1 = connection[device1Key];
        var device2 = connection[device2Key];
        var interface1 = connection[interface1Key];
        var interface2 = connection[interface2Key];

        if (!nodes.find(node => node.data.id === device1)) {
            nodes.push({ data: { id: device1, label: device1, entityType: 'device' } });
        }

        if (!nodes.find(node => node.data.id === device2)) {
            nodes.push({ data: { id: device2, label: device2, entityType: 'device' } });
        }

        var edgeId = `${device1}--${interface1}--${device2}--${interface2}`;
        var textOffset = (edges.length - (edges.length - 1) / 6) * 10;

        edges.push({
            data: {
                id: edgeId,
                source: device1,
                target: device2,
                label: interface1 + '--' + interface2,
                lineStyle: 'solid',
                textOffset: textOffset
            },
            classes: 'multiedge'
        });
    });

    cy.add(nodes);
    cy.add(edges);
    cy.layout({ name: 'cose' }).run();

    cy.ready(function() {
        checkHealth(cy, nodes, edges);

        setInterval(function() {
            checkHealth(cy, nodes, edges);
        }, 30000); // 30 seconds interval

        cy.contextMenus({
            menuItems: [
                {
                    id: 'ssh',
                    content: 'SSH to Device',
                    selector: 'node',
                    onClickFunction: function (event) {
                        var target = event.target || event.cyTarget;
                        var deviceId = target.id();
                        openTerminal(deviceId);
                    },
                    hasTrailingDivider: true
                }
            ]
        });
    });
}

     function checkHealth(cy, nodes, edges) {
        var devices = nodes.map(node => node.data);

        $.ajax({
            url: '/check_device_health',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ devices: devices, edges: edges }),
            success: function(response) {
                var healthStatus = response.health_status;

                devices.forEach(function(device) {
                    var status = healthStatus[device.id];
                    var color = '#088A4B'; // Default to green
                    var tooltip = 'Reachable';

                    if (status === 'unreachable') {
                        color = '#4B0082';
                        tooltip = 'Unreachable';
                    } else if (status === 'unknown') {
                        color = '#4B0082';
                        tooltip = 'Unknown, not in database';
                    } else if (status === 'connect_error') {
                        color = '#FF7F00';
                        tooltip = 'Connection Error';
                    } else if (status === 'auth_error') {
                        color = '##FF7F00';
                        tooltip = 'Authentication Error';
                    }

                    var node = cy.getElementById(device.id);
                    node.style('background-color', color);
                    node.data('tooltip', tooltip);
                });

                edges.forEach(function(edge) {
                    var status = healthStatus[edge.data.id];
                    var color = '#088A4B'; // Default to green
                    var tooltip = 'Reachable';

                    if (status === 'unreachable') {
                        color = '#ec7063';
                        tooltip = 'Unreachable';
                    } else if (status === 'unknown') {
                        color = 'gray';
                        tooltip = 'Unknown';
                    } else if (status === 'connect_error') {
                        color = '#FFA07A';
                        tooltip = 'Connection Error';
                    } else if (status === 'auth_error') {
                        color = '#FF8000';
                        tooltip = 'Authentication Error';
                    }

                    var edgeElement = cy.getElementById(edge.data.id);
                    edgeElement.style('line-color', color);
                    edgeElement.data('tooltip', tooltip);
                });

                // Add tooltips
                cy.elements().forEach(function(ele) {
                    ele.qtip({
                        content: ele.data('tooltip'),
                        show: {
                            event: 'mouseover'
                        },
                        hide: {
                            event: 'mouseout'
                        },
                        style: {
                            classes: 'qtip-bootstrap',
                            tip: {
                                width: 16,
                                height: 8
                            }
                        },
                        position: {
                            my: 'top center',
                            at: 'bottom center'
                        }
                    });
                });
            },
            error: function() {
                alert('Error checking device health.');
            }
        });
    }

    function initiateSSH(deviceId) {
        // Send request to backend to initiate SSH session
        $.ajax({
            url: '/initiate_ssh',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ device_id: deviceId }),
            success: function (response) {
                if (response.success) {
                    window.open(response.ssh_url, '_blank'); // Open SSH session in a new tab
                } else {
                    alert('Error initiating SSH session.');
                }
            },
            error: function () {
                alert('Error initiating SSH session.');
            }
        });
    }

    // Handle Show My Topology button click
    $('#showMytopologyBtn').on('click', function () {
        $.ajax({
            url: '/get_my_topology',
            type: 'GET',
            success: function (response) {
            //console.log(response.topology)
                var topologyContainer = $('#topologyContainer');
                topologyContainer.removeClass('hidden');
                renderTopology(response.topology);
            },
            error: function () {
                alert('Error loading topology.');
            }
        });
    });
});
});
