from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import Ether, Dot1Q, IP, IPv6, TCP, UDP, ARP, Raw, sendp
from scapy.contrib.igmp import IGMP
from scapy.contrib.mpls import MPLS
from concurrent.futures import ThreadPoolExecutor
from threading import  Event, Lock
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




'''def generate_packets(stream_data, interface, stop_event):
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
        logging.error(f"Error generating packets on {interface}: {e}")'''




def generate_packets(stream_data, interface, stop_event):
    """Generate and send packets dynamically based on stream configuration."""
    try:
        logging.info(f"Starting packet generation for interface '{interface}'.")

        # Extract stream details
        protocol_selection = stream_data.get("protocol_selection", {})
        protocol_data = stream_data.get("protocol_data", {})
        stream_rate_control = stream_data.get("stream_rate_control", {})

        if not protocol_selection or not protocol_data or not stream_rate_control:
            logging.error("Missing protocol selection, protocol data, or stream rate control in stream data.")
            return

        # Parse rate and duration
        try:
            pps_rate = int(stream_rate_control.get("stream_pps_rate", 1000))
            interval = 1 / max(pps_rate, 1)  # Prevent division by zero
            duration_mode = stream_rate_control.get("stream_duration_mode", "Continuous")
            duration_seconds = int(stream_rate_control.get("stream_duration_seconds", 10)) if duration_mode == "Seconds" else None
        except ValueError as ve:
            logging.error(f"Invalid stream rate control values: {stream_rate_control}. Error: {ve}")
            return

        # Initialize the packet
        packet = None

        # Handle L1 (MAC or RAW)
        if protocol_selection.get("L1") == "MAC":
            mac_data = protocol_data.get("mac", {})
            packet = Ether(
                src=mac_data.get("mac_source_address", "00:00:00:00:00:00"),
                dst=mac_data.get("mac_destination_address", "00:00:00:00:00:01")
            )
        elif protocol_selection.get("L1") == "RAW":
            logging.info("L1 set to RAW: Starting packet construction from L3.")
        else:
            logging.error(f"Unsupported L1 protocol: {protocol_selection.get('L1')}")
            return

        # Handle L2 (Ethernet II, 802.1Q, MPLS)
        l2_protocol = protocol_selection.get("L2")
        if l2_protocol == "802.1Q":
            try:
                vlan_data = protocol_data.get("vlan", {})
                dot1q_layer = Dot1Q(
                    vlan=int(vlan_data.get("vlan_id", 1)),
                    prio=int(vlan_data.get("vlan_priority", 0))
                )
                packet = packet / dot1q_layer if packet else dot1q_layer
            except ValueError as ve:
                logging.error(f"Invalid VLAN data: {vlan_data}. Error: {ve}")
                return
        elif l2_protocol == "MPLS":
            try:
                mpls_data = protocol_data.get("mpls", {})
                mpls_layer = MPLS(
                    label=int(mpls_data.get("mpls_label", 16)),
                    ttl=int(mpls_data.get("mpls_ttl", 64))
                )
                packet = packet / mpls_layer if packet else mpls_layer
            except ValueError as ve:
                logging.error(f"Invalid MPLS data: {mpls_data}. Error: {ve}")
                return

        # Handle L3 (IPv4, IPv6, ARP)
        l3_protocol = protocol_selection.get("L3")
        if l3_protocol == "IPv4":
            ipv4_data = protocol_data.get("ipv4", {})
            ipv4_layer = IP(
                src=ipv4_data.get("ipv4_source", "0.0.0.0"),
                dst=ipv4_data.get("ipv4_destination", "0.0.0.0"),
                ttl=int(ipv4_data.get("ipv4_ttl", 64))
            )
            packet = packet / ipv4_layer if packet else ipv4_layer
        elif l3_protocol == "IPv6":
            ipv6_data = protocol_data.get("ipv6", {})
            ipv6_layer = IPv6(
                src=ipv6_data.get("ipv6_source", "::"),
                dst=ipv6_data.get("ipv6_destination", "::"),
                hlim=int(ipv6_data.get("ipv6_hlim", 64))
            )
            packet = packet / ipv6_layer if packet else ipv6_layer
        elif l3_protocol == "ARP":
            arp_data = protocol_data.get("arp", {})
            arp_layer = ARP(
                hwsrc=arp_data.get("arp_source_mac", "00:00:00:00:00:00"),
                hwdst=arp_data.get("arp_destination_mac", "00:00:00:00:00:01"),
                psrc=arp_data.get("arp_source_ip", "0.0.0.0"),
                pdst=arp_data.get("arp_destination_ip", "0.0.0.1"),
                op=int(arp_data.get("arp_op", 1))  # 1 = ARP request, 2 = ARP reply
            )
            packet = packet / arp_layer if packet else arp_layer

        # Handle L4 (TCP, UDP, ICMP, IGMP, RoCEv2)
        l4_protocol = protocol_selection.get("L4")
        if l4_protocol == "TCP":
            tcp_data = protocol_data.get("tcp", {})
            tcp_layer = TCP(
                sport=int(tcp_data.get("tcp_source_port", 1024)),
                dport=int(tcp_data.get("tcp_destination_port", 80)),
                flags=tcp_data.get("tcp_flags", "S")
            )
            packet = packet / tcp_layer if packet else tcp_layer
        elif l4_protocol == "UDP":
            udp_data = protocol_data.get("udp", {})
            udp_layer = UDP(
                sport=int(udp_data.get("udp_source_port", 1024)),
                dport=int(udp_data.get("udp_destination_port", 80))
            )
            packet = packet / udp_layer if packet else udp_layer
        elif l4_protocol == "ICMP":
            icmp_layer = ICMP()  # Minimal configuration
            packet = packet / icmp_layer if packet else icmp_layer
        elif l4_protocol == "IGMP":
            igmp_data = protocol_data.get("igmp", {})
            igmp_layer = IGMP(
                type=int(igmp_data.get("igmp_type", 22))  # Default to membership report
            )
            packet = packet / igmp_layer if packet else igmp_layer
        elif l4_protocol == "RoCEv2":
            roce_data = protocol_data.get("rocev2", {})
            roce_layer = Raw(
                load=roce_data.get("payload_data", "0000")
            )
            packet = packet / roce_layer if packet else roce_layer

        # Ensure a packet was constructed
        if not packet:
            logging.error("No valid protocol layers were selected for packet generation.")
            return

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
        logging.error(f"Error generating packets on {interface}: {e}, Stream Data: {stream_data}")




class StreamTracker:
    def __init__(self):
        self.active_streams = []
        self.lock = Lock()

    def add_stream(self, stream):
        with self.lock:
            self.active_streams.append(stream)

    def remove_stream(self, interface_name, stream_name):
        with self.lock:
            self.active_streams = [
                s for s in self.active_streams
                if not (s["interface"] == interface_name and s["stream_name"] == stream_name)
            ]

    def get_streams(self):
        with self.lock:
            return list(self.active_streams)


# Initialize the tracker globally
stream_tracker = StreamTracker()


@app.route("/api/traffic/start", methods=["POST"])
def start_traffic():
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

            stream_name = protocol_selection.get("name", "Unnamed Stream")
            interface_name = interface.split(": ")[-1]

            stop_event = Event()
            stream_tracker.add_stream({
                "interface": interface_name,
                "stream_name": stream_name,
                "stop_event": stop_event
            })

            # Start packet generation
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
                stream_tracker.remove_stream(interface_name, stream_name)

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

        interface_name = interface.split(": ")[-1]

        # Match the stream to stop
        all_streams = stream_tracker.get_streams()
        matching_stream = next(
            (s for s in all_streams if s["interface"] == interface_name and s["stream_name"] == stream_name),
            None
        )

        if matching_stream:
            matching_stream["stop_event"].set()
            stream_tracker.remove_stream(interface_name, stream_name)
            responses.append(f"Stream '{stream_name}' stopped on interface '{interface_name}'")
            logging.info(f"Stream '{stream_name}' stopped on interface '{interface_name}'")
        else:
            responses.append(f"No matching stream found for '{stream_name}' on '{interface_name}'")
            logging.warning(f"No matching stream found for '{stream_name}' on '{interface_name}'")

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
    app.run(host='0.0.0.0', port=5201, debug=True)
