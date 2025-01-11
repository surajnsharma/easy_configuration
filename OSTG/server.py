from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import Ether, Dot1Q, IP, TCP, sendp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread, Event, Lock
import logging
import psutil, time
import random

# Initialize Flask app and CORS
app = Flask(__name__)
CORS(app)

# Thread pool and active streams tracking
executor = ThreadPoolExecutor(max_workers=10)

# Active streams tracking
active_streams = {}
active_streams_lock = Lock()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def increment_value(base, step, count, is_ip=False):
    """Increment a base value by a step for a specified count."""
    results = []
    try:
        if is_ip:
            # Handle IP address increments
            octets = list(map(int, base.split(".")))
            for i in range(int(count)):
                incremented = octets[:]
                incremented[-1] += step * i
                for j in range(3, -1, -1):  # Handle overflow
                    if incremented[j] > 255:
                        incremented[j] -= 256
                        if j > 0:
                            incremented[j - 1] += 1
                        else:
                            raise ValueError(f"IP address overflow: {base}")
                results.append(".".join(map(str, incremented)))
        elif ":" in base:  # Handle MAC address increments
            mac_parts = base.split(":")
            mac_int = int("".join(mac_parts), 16)
            for i in range(int(count)):
                incremented = mac_int + step * i
                mac_str = f"{incremented:012x}"  # Convert back to hex string
                mac_str = ":".join(mac_str[i:i+2] for i in range(0, 12, 2))
                results.append(mac_str)
        else:
            # Handle numeric increments (e.g., VLAN ID)
            base = int(base)
            for i in range(int(count)):
                incremented = base + step * i
                results.append(str(incremented))
    except Exception as e:
        logging.error(f"Error in increment_value: {e}")
        raise
    return results




def generate_packets(stream_data, interface, stop_event):
    """Generate and send packets dynamically based on stream configuration."""
    try:
        logging.info(f"Starting packet generation for interface '{interface}'.")

        protocol_selection = stream_data.get("protocol_selection", {})
        protocol_data = stream_data.get("protocol_data", {})
        stream_rate_control = stream_data.get("stream_rate_control", {})

        if not protocol_selection or not protocol_data or not stream_rate_control:
            logging.error("Missing protocol selection, protocol data, or stream rate control in stream data.")
            return

        # Parse rate and duration
        pps_rate = int(stream_rate_control.get("stream_pps_rate", 1000))
        interval = 1 / pps_rate
        duration_mode = stream_rate_control.get("stream_duration_mode", "Continuous")
        duration_seconds = int(stream_rate_control.get("stream_duration_seconds", 10)) if duration_mode == "Seconds" else None

        # Construct packet
        mac_data = protocol_data.get("mac", {})
        ipv4_data = protocol_data.get("ipv4", {})
        tcp_data = protocol_data.get("tcp", {})
        packet = Ether(src=mac_data.get("mac_source_address", "00:00:00:00:00:00"),
                       dst=mac_data.get("mac_destination_address", "00:00:00:00:00:01"))
        if protocol_selection.get("L3") == "IPv4":
            packet /= IP(src=ipv4_data.get("ipv4_source", "0.0.0.0"), dst=ipv4_data.get("ipv4_destination", "0.0.0.0"))
        if protocol_selection.get("L4") == "TCP":
            packet /= TCP(sport=int(tcp_data.get("tcp_source_port", 1024)),
                          dport=int(tcp_data.get("tcp_destination_port", 80)))

        # Start sending packets
        if duration_mode == "Continuous":
            logging.info(f"Sending traffic continuously on {interface} at {pps_rate} PPS.")
            while not stop_event.is_set():
                sendp(packet, iface=interface, verbose=False, count=1)
                time.sleep(interval)
        elif duration_mode == "Seconds":
            logging.info(f"Sending traffic for {duration_seconds} seconds on {interface} at {pps_rate} PPS.")
            end_time = time.time() + duration_seconds
            while time.time() < end_time and not stop_event.is_set():
                sendp(packet, iface=interface, verbose=False, count=1)
                time.sleep(interval)

        logging.info(f"Stopped sending traffic on {interface}.")

    except Exception as e:
        logging.error(f"Error generating packets on {interface}: {e}")


@app.route("/api/traffic/start", methods=["POST"])
def start_traffic():
    """Start traffic streams."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    logging.info(f"Incoming payload to start traffic: {data}")
    streams = data.get("streams", {})
    if not streams:
        return jsonify({"error": "No streams provided"}), 400

    started_streams = []

    for interface, stream_list in streams.items():
        for stream_data in stream_list:
            protocol_selection = stream_data.get("protocol_selection")
            if not protocol_selection or not protocol_selection.get("enabled", False):
                logging.info(f"Stream on interface {interface} is disabled. Skipping...")
                continue

            logging.info(f"Processing stream: {protocol_selection['name']} on {interface}")

            # Extract relevant fields
            stream_name = protocol_selection.get("name", "Unnamed Stream")

            # Parse interface name
            interface_parts = interface.split(": ")
            if len(interface_parts) > 1:
                interface_name = interface_parts[1]
            else:
                logging.error(f"Invalid interface format: {interface}")
                continue

            # Initialize stop_event
            stop_event = Event()
            with active_streams_lock:
                active_streams[interface_name] = stop_event

            # Start packet generation in a separate thread
            try:
                executor.submit(generate_packets, stream_data, interface_name, stop_event)
                started_streams.append({
                    "interface": interface,
                    "stream_name": stream_name,
                    "status": "started"
                })
                logging.info(f"Stream '{stream_name}' started on interface '{interface_name}'.")
            except Exception as e:
                logging.error(f"Failed to start stream '{stream_name}' on interface '{interface_name}': {e}")
                with active_streams_lock:
                    active_streams.pop(interface_name, None)

    return jsonify({
        "message": "Traffic streams started successfully.",
        "started_streams": started_streams
    }), 200

@app.route('/api/traffic/stop', methods=['POST'])
def stop_traffic():
    """Stop specified traffic streams."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    streams_to_stop = data.get("streams", [])
    responses = []

    for stream in streams_to_stop:
        interface = stream.get("interface")
        stream_name = stream.get("name")

        if not interface or not stream_name:
            responses.append(f"Invalid stream data: {stream}")
            logging.warning(f"Invalid stream data: {stream}")
            continue

        # Normalize interface name
        interface_name = interface.split(": ")[-1]  # Extract the interface part (e.g., 'en0')

        with active_streams_lock:
            stop_event = active_streams.pop(interface_name, None)

        if stop_event:
            stop_event.set()
            responses.append(f"Stream '{stream_name}' stopped on interface '{interface_name}'")
            logging.info(f"Stream '{stream_name}' stopped on interface '{interface_name}'")
        else:
            responses.append(f"No active stream found for interface '{interface_name}'")
            logging.warning(f"No active stream found for interface '{interface_name}'")

    return jsonify({"message": "Traffic streams processed", "details": responses}), 200


@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """
    API endpoint to fetch dynamic network interfaces with traffic statistics.
    """
    interfaces = []
    try:
        # Use psutil to fetch network interface details
        for name, stats in psutil.net_if_stats().items():
            is_up = stats.isup
            # Simulate traffic statistics for demonstration purposes
            tx = random.randint(100, 1000) if is_up else 0  # Transmitted packets
            rx = random.randint(50, 800) if is_up else 0   # Received packets
            sent_bytes = tx * random.randint(64, 1500)  # Simulate bytes sent
            received_bytes = rx * random.randint(64, 1500)  # Simulate bytes received
            errors = random.randint(0, 10) if is_up else 0  # Simulate errors

            interfaces.append({
                "name": name,
                "status": "up" if is_up else "down",
                "mtu": stats.mtu,
                "speed": stats.speed if hasattr(stats, 'speed') else "Unknown",
                "ip_addresses": psutil.net_if_addrs().get(name, []),  # Add IP addresses if available
                "tx": tx,
                "rx": rx,
                "sent_bytes": sent_bytes,
                "received_bytes": received_bytes,
                "errors": errors,
            })
        return jsonify(interfaces)
    except Exception as e:
        logging.error(f"Error fetching interfaces: {e}")
        return jsonify({"error": "Unable to fetch interfaces"}), 500






if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
