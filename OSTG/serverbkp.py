# make changes to below server code and integrate scapy #
from flask import Flask, jsonify, request
from flask_cors import CORS
import psutil
import random

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

## here is the old code...
def get_dynamic_interfaces():
    """
    Dynamically fetch network interfaces and their statuses.
    """
    interfaces = []
    for name, stats in psutil.net_if_stats().items():
        is_up = stats.isup
        tx, rx = random.randint(100, 1000), random.randint(50, 800)  # Simulate TX/RX
        interfaces.append({
            "name": name,
            "status": "up" if is_up else "down",
            "tx": tx if is_up else 0,
            "rx": rx if is_up else 0
        })
    return interfaces

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """
    API endpoint to fetch dynamic network interfaces.
    """
    interfaces = get_dynamic_interfaces()
    return jsonify(interfaces)

@app.route('/api/interfaces/<interface_name>/statistics', methods=['GET'])
def get_interface_statistics(interface_name):
    """
    API endpoint to fetch statistics for a specific interface.
    """
    interfaces = get_dynamic_interfaces()
    interface = next((i for i in interfaces if i["name"] == interface_name), None)
    if not interface:
        return jsonify({"error": "Interface not found"}), 404
    return jsonify({"tx": interface["tx"], "rx": interface["rx"]})

@app.route('/api/interfaces/<interface_name>', methods=['PUT'])
def update_interface_status(interface_name):
    """
    API endpoint to update the status of an interface (up/down).
    """
    data = request.get_json()
    status = data.get("status")
    if status not in ["up", "down"]:
        return jsonify({"error": "Invalid status"}), 400

    # Simulate updating interface status (actual implementation may depend on platform)
    return jsonify({"message": f"Interface {interface_name} updated to {status}."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)