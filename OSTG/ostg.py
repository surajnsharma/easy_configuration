## here is the current client code
import logging
import sys
import requests
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,QStackedWidget,
    QTableWidgetItem, QDialog, QFormLayout, QLineEdit, QComboBox, QDialogButtonBox, QWidget, QMessageBox,
    QRadioButton, QGroupBox, QGridLayout, QTabWidget, QScrollArea, QCheckBox, QInputDialog, QSplitter, QAction, QMenu,
    QAbstractItemView,QSizePolicy, QHeaderView, QTreeWidget, QTreeWidgetItem, QListWidget, QListWidgetItem, QTextEdit,QSpacerItem
)
from PyQt5.QtCore import QTimer, Qt, QRegExp,QSize,QItemSelectionModel
from PyQt5.QtGui import QIntValidator, QBrush, QIntValidator, QRegExpValidator,QIcon,QValidator
import json
from functools import partial

# Server URL (replace with actual server IP and port)
SERVER_URL = "http://127.0.0.1:5001"



class Unsigned32BitValidator(QValidator):
    """Custom validator for 32-bit unsigned integers."""
    def validate(self, input, pos):
        if not input:  # Allow empty field for user input
            return QValidator.Intermediate, input, pos
        try:
            value = int(input)
            if 0 <= value <= 4294967295:
                return QValidator.Acceptable, input, pos
            return QValidator.Invalid, input, pos
        except ValueError:
            return QValidator.Invalid, input, pos

class TrafficGeneratorClient(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Traffic Generator Client")
        self.setGeometry(100, 100, 1400, 800)

        # Dictionary to store streams for each interface
        self.streams = {}

        # List to store server interfaces with TG IDs
        self.server_interfaces = []  # Start with an empty list

        # Set to track removed interfaces
        self.removed_interfaces = set()

        # List to track selected servers
        self.selected_servers = []  # Track multiple selected servers

        # Set up UI
        self.central_widget = QWidget()
        self.main_layout = QVBoxLayout(self.central_widget)
        self.setCentralWidget(self.central_widget)
        self.setup_menu_bar()
        self.copied_stream = None
        self.setup_ui()

        # Timer for periodic updates
        self.timer = QTimer()
        self.timer.timeout.connect(self.fetch_and_update_statistics)
        self.timer.start(5000)  # Periodically fetch statistics, if servers are present

        # Load session.json if available
        self.load_session()




    def setup_menu_bar(self):
        """Set up the menu bar for server and stream management."""
        menu_bar = self.menuBar()

        # File menu for Server Management
        file_menu = QMenu("File", self)
        menu_bar.addMenu(file_menu)

        # Add Server Action
        add_server_action = QAction("Add Tgen Chassis", self)
        add_server_action.triggered.connect(self.add_server_interface)
        file_menu.addAction(add_server_action)

        # Remove Server Action
        remove_server_action = QAction("Remove Tgen Chassis", self)
        remove_server_action.triggered.connect(self.remove_selected_server)
        file_menu.addAction(remove_server_action)

        # Save Session Action
        save_session_action = QAction("Save Session", self)
        save_session_action.triggered.connect(self.save_session)
        file_menu.addAction(save_session_action)

        # Edit menu for Stream Management
        edit_menu = QMenu("Edit", self)
        menu_bar.addMenu(edit_menu)

        # Copy Stream Action
        copy_stream_action = QAction("Copy Stream", self)
        copy_stream_action.triggered.connect(self.copy_selected_stream)
        edit_menu.addAction(copy_stream_action)

        # Paste Stream Action
        paste_stream_action = QAction("Paste Stream", self)
        paste_stream_action.triggered.connect(self.paste_stream_to_interface)
        edit_menu.addAction(paste_stream_action)

    def setup_ui(self):
        """Set up the main UI layout."""
        # Split main layout into two sections: Top and Bottom
        self.splitter = QSplitter(Qt.Vertical)
        # Top Section: Ports and Streams
        self.top_section = QSplitter(Qt.Horizontal)
        self.splitter.addWidget(self.top_section)
        # Left: Server Address Management
        self.setup_server_section()
        # Right: Stream Management
        self.setup_stream_section()
        # Set stretch factors: Stream section wider than Server Address section
        self.top_section.setStretchFactor(0, 1)  # Server Address
        self.top_section.setStretchFactor(1, 5)  # Stream Management
        # Bottom Section: Traffic Statistics
        self.setup_traffic_statistics_section()
        # Add Start/Stop Buttons
        self.setup_stream_start_stop_buttons()

        # Add splitter to the main layout
        self.main_layout.addWidget(self.splitter)


    def setup_server_section(self):
        """Set up the server management section."""
        self.server_group = QGroupBox("Server Address")
        layout = QVBoxLayout()

        # Server Tree
        self.server_tree = QTreeWidget()
        self.server_tree.setColumnCount(3)
        self.server_tree.setHeaderLabels(["TG ID", "Server Address / Ports", "Selected"])

        # Enable extended selection for multiple ports using Ctrl/Command
        self.server_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.server_tree)

        # Adjust column widths
        self.server_tree.setColumnWidth(0, 200)  # Increase width for TG ID
        self.server_tree.setColumnWidth(1, 300)  # Adjust width for Server Address
        self.server_tree.setColumnWidth(2, 50)  # Adjust width for Selected column

        # Connect selection change signal to dynamically update streams
        self.server_tree.itemSelectionChanged.connect(self.update_stream_table)

        # Buttons for Server Management
        button_layout = QHBoxLayout()

        # Remove Interface Button
        remove_interface_button = QPushButton(" Delete Port")
        remove_interface_button.setIcon(QIcon("resources/icons/Trash.png"))
        remove_interface_button.setIconSize(QSize(16, 16))
        remove_interface_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        remove_interface_button.clicked.connect(self.remove_selected_interface)
        button_layout.addWidget(remove_interface_button)

        # Spacer to control button distance
        spacer = QSpacerItem(1, 0, QSizePolicy.Minimum, QSizePolicy.Minimum)
        button_layout.addItem(spacer)

        # Readd Port Button
        readd_port_button = QPushButton(" Add Ports")
        readd_port_button.setIcon(QIcon("resources/icons/readd.png"))
        readd_port_button.setIconSize(QSize(16, 16))
        readd_port_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        readd_port_button.clicked.connect(self.readd_ports_dialog)
        button_layout.addWidget(readd_port_button)

        # Add a stretchable spacer to align buttons to the left
        button_layout.addStretch(1)

        # Add buttons to layout
        layout.addLayout(button_layout)
        self.server_group.setLayout(layout)
        self.top_section.addWidget(self.server_group)

        # Populate the tree initially
        self.update_server_tree()

    def readd_ports_dialog(self):
        """Display a dialog to re-add removed ports with checkboxes."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Re-add Ports")
        dialog.setGeometry(300, 300, 400, 400)

        layout = QVBoxLayout(dialog)

        # Tree widget to display available ports grouped by TG with checkboxes
        tree_widget = QTreeWidget()
        tree_widget.setColumnCount(2)
        tree_widget.setHeaderLabels(["TG ID", "Port Name"])
        layout.addWidget(tree_widget)

        # Populate the tree widget with removed ports grouped by TG
        tg_ports_map = {}
        for port in sorted(self.removed_interfaces):  # Sort ports for better grouping
            if " - Port: " in port:
                tg_id, port_name = port.split(" - Port: ")
                tg_ports_map.setdefault(tg_id, []).append(port_name)

        for tg_id, ports in tg_ports_map.items():
            tg_item = QTreeWidgetItem([tg_id, ""])
            tg_item.setFlags(tg_item.flags() & ~Qt.ItemIsSelectable)  # Make TG ID unselectable
            tree_widget.addTopLevelItem(tg_item)
            for port_name in ports:
                port_item = QTreeWidgetItem(["", port_name])
                port_item.setFlags(port_item.flags() | Qt.ItemIsUserCheckable)  # Enable checkbox
                port_item.setCheckState(0, Qt.Unchecked)
                tg_item.addChild(port_item)

        # Confirm and Cancel buttons
        button_layout = QHBoxLayout()
        confirm_button = QPushButton("Re-add Selected Ports")
        confirm_button.clicked.connect(lambda: self.readd_ports_from_tree(tree_widget, dialog))
        button_layout.addWidget(confirm_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)
        dialog.exec()

    def readd_ports_from_tree(self, tree_widget, dialog):
        """Re-add selected ports based on checkboxes in the tree widget."""
        selected_ports = []

        # Iterate through the tree widget to find checked items
        for i in range(tree_widget.topLevelItemCount()):
            tg_item = tree_widget.topLevelItem(i)
            for j in range(tg_item.childCount()):
                port_item = tg_item.child(j)
                if port_item.checkState(0) == Qt.Checked:  # Check if the port is selected
                    tg_id = tg_item.text(0)
                    port_name = port_item.text(1)
                    selected_ports.append(f"{tg_id} - Port: {port_name}")

        # Re-add the selected ports
        for port in selected_ports:
            if port in self.removed_interfaces:
                self.removed_interfaces.remove(port)

        # Update the server tree and close the dialog
        self.update_server_tree()
        dialog.accept()

    def readd_ports(self, list_widget, dialog):
        """Re-add the selected ports from the dialog."""
        readded_ports = []
        for i in range(list_widget.count()):
            item = list_widget.item(i)
            if item.checkState() == Qt.Checked:
                port = item.text().strip()
                if " - Port: " in port:  # Ensure correct format
                    tg_id, port_name = port.split(" - Port: ", 1)

                    # Ensure TG ID is properly matched
                    tg_item = None
                    for j in range(self.server_tree.topLevelItemCount()):
                        top_item = self.server_tree.topLevelItem(j)
                        if top_item.text(0) == tg_id:
                            tg_item = top_item
                            break

                    if tg_item:
                        # Avoid duplicates within the TG
                        existing_ports = [tg_item.child(k).text(0) for k in range(tg_item.childCount())]
                        if f"Port: {port_name}" not in existing_ports:
                            port_item = QTreeWidgetItem([f"Port: {port_name}", ""])
                            tg_item.addChild(port_item)
                            readded_ports.append(port)
                            # Remove from removed_interfaces
                            self.removed_interfaces.discard(port)

        if readded_ports:
            print(f"Re-added ports: {readded_ports}")
            self.save_session()  # Save updated session
            #QMessageBox.information(self, "Ports Re-added", f"Re-added ports: {', '.join(readded_ports)}")
        else:
            QMessageBox.information(self, "No Ports Selected", "No ports were selected to re-add.")

        dialog.accept()

    def update_server_tree(self):
        """Update the server tree with servers and their ports."""
        self.server_tree.clear()  # Clear the tree before updating

        if not self.server_interfaces:
            # Display a placeholder message when no servers are added
            placeholder_item = QTreeWidgetItem(["No Servers", "", ""])
            self.server_tree.addTopLevelItem(placeholder_item)
            return

        for server in self.server_interfaces:
            tg_id = f"TG {server['tg_id']}"
            server_address = server["address"]

            # Add top-level item for the server
            server_item = QTreeWidgetItem([tg_id, server_address, ""])
            self.server_tree.addTopLevelItem(server_item)

            # Add a checkbox for selecting the server
            checkbox = QCheckBox()
            checkbox.setChecked(server in self.selected_servers)
            checkbox.stateChanged.connect(
                lambda state, idx=server['tg_id']: self.on_server_checkbox_state_changed(idx, state)
            )
            self.server_tree.setItemWidget(server_item, 2, checkbox)

            # Fetch ports dynamically
            try:
                response = requests.get(f"{server_address}/api/interfaces", timeout=5)
                if response.status_code == 200:
                    interfaces = response.json()
                    if interfaces:
                        for interface in interfaces:
                            port_name = f"{interface['name']}"
                            full_interface_name = f"{tg_id} - Port: {port_name}"

                            # Skip removed interfaces
                            if full_interface_name in self.removed_interfaces:
                                continue

                            port_item = QTreeWidgetItem([f"Port: {port_name}", ""])
                            server_item.addChild(port_item)
                    else:
                        print(f"No interfaces returned by {server_address}. Adding dummy ports.")
                        self.add_dummy_ports(server_item, tg_id)
                else:
                    print(f"Server {server_address} returned status code: {response.status_code}")
                    QMessageBox.warning(
                        self,
                        "Server Error",
                        f"Failed to fetch interfaces from {server_address} (status code: {response.status_code})."
                    )
                    self.add_dummy_ports(server_item, tg_id)
            except requests.RequestException as e:
                print(f"Error fetching ports for {server_address}: {e}")
                QMessageBox.warning(
                    self,
                    "Server Not Reachable",
                    f"Could not connect to {server_address}. Adding dummy ports."
                )
                self.add_dummy_ports(server_item, tg_id)

    def add_dummy_ports(self, server_item, tg_id):
        """Add dummy ports to the server item as a fallback."""
        for i in range(3):
            port_name = f"eth{i}"
            full_interface_name = f"{tg_id} - Port: {port_name}"

            # Skip removed interfaces
            if full_interface_name in self.removed_interfaces:
                continue

            port_item = QTreeWidgetItem([f"Port: {port_name}", ""])
            server_item.addChild(port_item)

        print(f"Dummy ports added for {tg_id}.")

    def add_server_interface(self):
        """Add a new server interface."""
        server_url, ok = QInputDialog.getText(self, "Add Server", "Enter Server Address (e.g., 127.0.0.1):")
        if not ok or not server_url.strip():
            return

        port, ok = QInputDialog.getText(self, "Add Port", "Enter Port (default: 80):")
        port = port.strip() if port else "80"

        try:
            full_url = f"http://{server_url.strip()}:{int(port)}"
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "Port must be a valid number.")
            return

        if full_url not in [server["address"] for server in self.server_interfaces]:
            tg_id = len(self.server_interfaces)  # Assign the next TG ID
            self.server_interfaces.append({"tg_id": tg_id, "address": full_url})
            self.update_server_tree()
            self.save_server_interfaces()
        else:
            QMessageBox.warning(self, "Duplicate Server", "This server is already added.")

    def remove_selected_server(self):
        """Remove the currently selected server(s) from the tree."""
        selected_items = self.server_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a server to remove.")
            return

        for item in selected_items:
            if item.parent() is None:  # Ensure it's a top-level item (server)
                server_address = item.text(1)  # Server address column
                tg_id = item.text(0)  # TG ID column

                # Remove the server and its ports from the server interfaces
                self.server_interfaces = [
                    server for server in self.server_interfaces if server["address"] != server_address
                ]

                # Remove related entries from removed_interfaces
                self.removed_interfaces = {
                    port for port in self.removed_interfaces if not port.startswith(f"{tg_id} - Port:")
                }

                # Remove the selected server from selected_servers if applicable
                self.selected_servers = [
                    server for server in self.selected_servers if server["address"] != server_address
                ]

                # Remove the server item from the tree
                index = self.server_tree.indexOfTopLevelItem(item)
                self.server_tree.takeTopLevelItem(index)

                print(f"Removed server: {server_address} and all associated ports.")

        # Save the updated server interfaces and removed_interfaces
        self.save_session()
        self.save_server_interfaces()

        #QMessageBox.information(self, "Server Removed", "Selected server(s) and associated ports removed successfully.")

    def remove_selected_interface(self):
        """Remove the selected ports (interfaces) from the server tree."""
        selected_items = self.server_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select one or more ports to remove.")
            return

        removed_ports = []  # Track removed ports for feedback

        for item in selected_items:
            parent_item = item.parent()
            if parent_item:  # Only process child items (ports)
                tg_id = parent_item.text(0)  # TG ID (e.g., "TG 0")
                port_name = item.text(0)  # Port name (e.g., "Port: eth0")
                full_port_name = f"{tg_id} - {port_name}"

                # Add the full port name to removed interfaces
                self.removed_interfaces.add(full_port_name)
                removed_ports.append(full_port_name)

                # Remove the port from the tree
                index = parent_item.indexOfChild(item)
                if index >= 0:  # Ensure index is valid
                    parent_item.takeChild(index)

        if removed_ports:
            print(f"Removed ports: {', '.join(removed_ports)}")
            self.save_session()  # Save the session to persist changes
            """QMessageBox.information(
                self,
                "Ports Removed",
                f"The following ports were removed:\n{', '.join(removed_ports)}"
            )"""
        else:
            QMessageBox.warning(self, "No Ports Removed", "No valid ports were selected for removal.")

    def load_server_interfaces(self):
        """Load server interfaces from a file and assign TG IDs."""
        try:
            with open("server_interfaces.txt", "r") as f:
                servers = [line.strip() for line in f.readlines()]
            self.server_interfaces = [{"tg_id": i, "address": server} for i, server in enumerate(servers)]
            print(f"Loaded servers: {self.server_interfaces}")
        except FileNotFoundError:
            print("server_interfaces.txt not found. Starting with an empty server list.")
            self.server_interfaces = []

    def save_server_interfaces(self):
        """Save the server interfaces to a file."""
        try:
            with open("server_interfaces.txt", "w") as f:
                for server in self.server_interfaces:
                    f.write(f"{server['address']}\n")
            print("Server interfaces saved successfully.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not save server interfaces: {e}")



    def save_session(self):
        """Save the current session to a JSON file."""
        updated_streams = {}

        for port, stream_list in self.streams.items():
            updated_streams[port] = []

            for stream in stream_list:
                # Retrieve stream details from the dialog or use the existing stream data
                if hasattr(stream, "get_stream_details"):
                    stream_data = stream.get_stream_details()
                else:
                    stream_data = stream

                # Debugging: Log the raw stream data
                print(f"save_session, stream_data: {stream_data}")

                # Extract and merge RoCEv2 data
                rocev2_data = {
                    "traffic_class": stream_data.get("rocev2_traffic_class", "0"),
                    "flow_label": stream_data.get("rocev2_flow_label", "000000"),
                    "source_gid": stream_data.get("rocev2_source_gid", "0:0:0:0:0:ffff:192.168.1.1"),
                    "destination_gid": stream_data.get("rocev2_destination_gid", "0:0:0:0:0:ffff:192.168.1.2"),
                    "source_qp": stream_data.get("rocev2_source_qp", "0"),
                    "destination_qp": stream_data.get("rocev2_destination_qp", "0"),
                }
                if "rocev2" in stream_data:
                    rocev2_data.update(stream_data["rocev2"])

                # Extract TOS/DSCP/Custom settings
                tos_dscp_data = {
                    "tos_dscp_mode": stream_data.get("tos_dscp_mode", "TOS"),
                    "ipv4_tos": stream_data.get("ipv4_tos", "Routine"),
                    "ipv4_dscp": stream_data.get("ipv4_dscp", "cs0"),
                    "ipv4_ecn": stream_data.get("ipv4_ecn", "Not-ECT"),
                    "ipv4_custom_tos": stream_data.get("ipv4_custom_tos", ""),
                }
                # Categorize data into protocol_selection and protocol_data
                categorized_stream = {
                    "protocol_selection": {
                        "name": stream_data.get("name", ""),
                        "enabled": stream_data.get("enabled", False),
                        "details": stream_data.get("details", ""),
                        "frame_type": stream_data.get("frame_type", "Fixed"),
                        "frame_min": stream_data.get("frame_min", "64"),
                        "frame_max": stream_data.get("frame_max", "1518"),
                        "frame_size": stream_data.get("frame_size", "64"),
                        "L1": stream_data.get("L1", "None"),
                        "VLAN": stream_data.get("VLAN", "Untagged"),
                        "L2": stream_data.get("L2", "None"),
                        "L3": stream_data.get("L3", "None"),
                        "L4": stream_data.get("L4", "None"),
                        "Payload": stream_data.get("Payload", "None"),
                    },
                    "protocol_data": {
                        "mac": {
                            "mac_destination_mode": stream_data.get("mac_destination_mode", "Fixed"),
                            "mac_destination_address": stream_data.get("mac_destination_address", "00:00:00:00:00:00"),
                            "mac_destination_count": stream_data.get("mac_destination_count", "1"),
                            "mac_destination_step": stream_data.get("mac_destination_step", "1"),
                            "mac_source_mode": stream_data.get("mac_source_mode", "Fixed"),
                            "mac_source_address": stream_data.get("mac_source_address", "00:00:00:00:00:00"),
                            "mac_source_count": stream_data.get("mac_source_count", "1"),
                            "mac_source_step": stream_data.get("mac_source_step", "1"),
                        },
                        "vlan": {
                            "vlan_priority": stream_data.get("vlan_priority", "0"),
                            "vlan_cfi_dei": stream_data.get("vlan_cfi_dei", "0"),
                            "vlan_id": stream_data.get("vlan_id", "1"),
                            "vlan_tpid": stream_data.get("vlan_tpid", "81 00"),
                            "vlan_increment": stream_data.get("vlan_increment", False),
                            "vlan_increment_value": stream_data.get("vlan_increment_value", "1"),
                            "vlan_increment_count": stream_data.get("vlan_increment_count", "1"),
                        },
                        "ipv4": {
                            "ipv4_source": stream_data.get("ipv4_source", "0.0.0.0"),
                            "ipv4_destination": stream_data.get("ipv4_destination", "0.0.0.0"),
                            "ipv4_source_mode": stream_data.get("ipv4_source_mode", "Fixed"),
                            "ipv4_destination_mode": stream_data.get("ipv4_destination_mode", "Fixed"),
                            "ipv4_tos": stream_data.get("ipv4_tos", None),
                            "ipv4_dscp": stream_data.get("ipv4_dscp", None),
                            "ipv4_ecn": stream_data.get("ipv4_ecn", None),
                            "ipv4_custom_tos": stream_data.get("ipv4_custom_tos", None),
                            "ipv4_ttl": stream_data.get("ipv4_ttl", "64"),
                            "ipv4_identification": stream_data.get("ipv4_identification", "0000"),
                            "ipv4_increment_source": stream_data.get("ipv4_increment_source", False),
                            "ipv4_source_increment_step": stream_data.get("ipv4_source_increment_step", "1"),
                            "ipv4_source_increment_count": stream_data.get("ipv4_source_increment_count", "1"),
                            "ipv4_increment_destination": stream_data.get("ipv4_increment_destination", False),
                            "ipv4_destination_increment_step": stream_data.get("ipv4_destination_increment_step", "1"),
                            "ipv4_destination_increment_count": stream_data.get("ipv4_destination_increment_count",
                                                                                "1"),
                            "ipv4_df": stream_data.get("ipv4_df", False),
                            "ipv4_mf": stream_data.get("ipv4_mf", False),
                            "ipv4_fragment_offset": stream_data.get("ipv4_fragment_offset", "0"),
                            **tos_dscp_data,
                        },
                        "tcp": {
                            "tcp_source_port": stream_data.get("tcp_source_port", "0"),
                            "tcp_destination_port": stream_data.get("tcp_destination_port", "0"),
                            "tcp_sequence_number": stream_data.get("tcp_sequence_number", "0"),
                            "tcp_acknowledgement_number": stream_data.get("tcp_acknowledgement_number", "0"),
                            "tcp_window": stream_data.get("tcp_window", "1024"),
                            "tcp_checksum": stream_data.get("tcp_checksum", ""),
                            "tcp_flags": stream_data.get("tcp_flags", ""),
                            "tcp_increment_source_port": stream_data.get("tcp_increment_source_port", False),
                            "tcp_source_port_step": stream_data.get("tcp_source_port_step", "1"),
                            "tcp_source_port_count": stream_data.get("tcp_source_port_count", "1"),
                            "tcp_increment_destination_port": stream_data.get("tcp_increment_destination_port", False),
                            "tcp_destination_port_step": stream_data.get("tcp_destination_port_step", "1"),
                            "tcp_destination_port_count": stream_data.get("tcp_destination_port_count", "1"),
                        },
                        "rocev2": rocev2_data,
                        "payload_data": {
                            "payload_data": stream_data.get("payload_data", ""),
                        },
                    },
                    "override_settings": {
                        "override_source_tcp_port": stream_data.get("override_source_tcp_port", False),
                        "override_destination_tcp_port": stream_data.get("override_destination_tcp_port", False),
                        "override_vlan_tpid": stream_data.get("override_vlan_tpid", False),
                    },
                    "stream_rate_control": {
                        "stream_rate_type": stream_data.get("stream_rate_type", "Packets Per Second (PPS)"),
                        "stream_pps_rate": stream_data.get("stream_pps_rate", None),
                        "stream_bit_rate": stream_data.get("stream_bit_rate", None),
                        "stream_load_percentage": stream_data.get("stream_load_percentage", None),
                        "stream_duration_mode": stream_data.get("stream_duration_mode", "Continuous"),
                        "stream_duration_seconds": stream_data.get("stream_duration_seconds", "10"),
                    },
                }

                updated_streams[port].append(categorized_stream)

        session_data = {
            "servers": self.server_interfaces,
            "streams": updated_streams,
            "removed_interfaces": list(self.removed_interfaces),
            "selected_servers": [server["address"] for server in self.selected_servers],
        }

        # Save to session file
        try:
            with open("session.json", "w") as session_file:
                json.dump(session_data, session_file, indent=4)
            print("Session saved successfully.")
        except Exception as e:
            QMessageBox.warning(self, "Save Session", f"Failed to save session: {e}")


    def _initialize_empty_session(self):
        """Initialize an empty session with default values."""
        print("Initializing an empty session.")
        self.server_interfaces = []
        self.streams = {}
        self.removed_interfaces = set()
        self.selected_servers = []

        # Update UI components to reflect the reset state
        self.update_server_tree()
        self.update_stream_table()
        print("Empty session initialized.")
    def load_session(self):
        """Load the session from a JSON file."""
        try:
            with open("session.json", "r") as session_file:
                session_data = json.load(session_file)

            # Load servers, removed interfaces, and selected servers
            self.server_interfaces = session_data.get("servers", [])
            self.streams = {}

            # Process each port and its associated streams
            for port, stream_list in session_data.get("streams", {}).items():
                self.streams[port] = []
                for stream in stream_list:
                    protocol_selection = stream.get("protocol_selection", {})
                    protocol_data = stream.get("protocol_data", {})
                    override_settings = stream.get("override_settings", {})
                    stream_rate_control = stream.get("stream_rate_control", {})

                    # Extract protocol-specific data
                    mac_data = protocol_data.get("mac", {})
                    vlan_data = protocol_data.get("vlan", {})
                    ipv4_data = protocol_data.get("ipv4", {})
                    tcp_data = protocol_data.get("tcp", {})
                    payload_data = protocol_data.get("payload_data", {})
                    rocev2_data = protocol_data.get("rocev2", {})

                    # Extract TOS/DSCP/Custom fields
                    tos_dscp_data = {
                        "tos_dscp_mode": ipv4_data.get("tos_dscp_mode", "TOS"),
                        "ipv4_tos": ipv4_data.get("ipv4_tos", "Routine"),
                        "ipv4_dscp": ipv4_data.get("ipv4_dscp", "cs0"),
                        "ipv4_ecn": ipv4_data.get("ipv4_ecn", "Not-ECT"),
                        "ipv4_custom_tos": ipv4_data.get("ipv4_custom_tos", ""),
                    }
                    # Merge fields into a flat structure for compatibility
                    merged_stream = {
                        **protocol_selection,
                        **{
                            "mac_destination_mode": mac_data.get("mac_destination_mode", "Fixed"),
                            "mac_destination_address": mac_data.get("mac_destination_address", "00:00:00:00:00:00"),
                            "mac_source_mode": mac_data.get("mac_source_mode", "Fixed"),
                            "mac_source_address": mac_data.get("mac_source_address", "00:00:00:00:00:00"),
                            "mac_source_count": mac_data.get("mac_source_count", "1"),
                            "mac_destination_count": mac_data.get("mac_destination_count", "1"),
                        },
                        **{
                            "vlan_priority": vlan_data.get("vlan_priority", "0"),
                            "vlan_cfi_dei": vlan_data.get("vlan_cfi_dei", "0"),
                            "vlan_id": vlan_data.get("vlan_id", "1"),
                            "vlan_tpid": vlan_data.get("vlan_tpid", "81 00"),
                            "vlan_increment": vlan_data.get("vlan_increment", False),
                            "vlan_increment_value": vlan_data.get("vlan_increment_value", "1"),
                            "vlan_increment_count": vlan_data.get("vlan_increment_count", "1"),
                        },
                        **{
                            "ipv4_source": ipv4_data.get("ipv4_source", "0.0.0.0"),
                            "ipv4_destination": ipv4_data.get("ipv4_destination", "0.0.0.0"),
                            "ipv4_source_mode": ipv4_data.get("ipv4_source_mode", "Fixed"),
                            "ipv4_destination_mode": ipv4_data.get("ipv4_destination_mode", "Fixed"),
                            "ipv4_tos": ipv4_data.get("ipv4_tos", "Routine"),
                            "ipv4_dscp": ipv4_data.get("ipv4_dscp", None),
                            "ipv4_ecn": ipv4_data.get("ipv4_ecn", None),
                            "ipv4_ttl": ipv4_data.get("ipv4_ttl", "64"),
                            "ipv4_identification": ipv4_data.get("ipv4_identification", "0000"),
                            "ipv4_increment_source": ipv4_data.get("ipv4_increment_source", False),
                            "ipv4_source_increment_step": ipv4_data.get("ipv4_source_increment_step", "1"),
                            "ipv4_source_increment_count": ipv4_data.get("ipv4_source_increment_count", "1"),
                            "ipv4_increment_destination": ipv4_data.get("ipv4_increment_destination", False),
                            "ipv4_destination_increment_step": ipv4_data.get("ipv4_destination_increment_step", "1"),
                            "ipv4_destination_increment_count": ipv4_data.get("ipv4_destination_increment_count", "1"),
                            "ipv4_df": ipv4_data.get("ipv4_df", False),
                            "ipv4_mf": ipv4_data.get("ipv4_mf", False),
                            "ipv4_fragment_offset": ipv4_data.get("ipv4_fragment_offset", "0"),
                            **tos_dscp_data,
                        },
                        **{
                            "tcp_source_port": tcp_data.get("tcp_source_port", "0"),
                            "tcp_destination_port": tcp_data.get("tcp_destination_port", "0"),
                            "tcp_sequence_number": tcp_data.get("tcp_sequence_number", "0"),
                            "tcp_acknowledgement_number": tcp_data.get("tcp_acknowledgement_number", "0"),
                            "tcp_window": tcp_data.get("tcp_window", "1024"),
                            "tcp_checksum": tcp_data.get("tcp_checksum", ""),
                            "tcp_flags": tcp_data.get("tcp_flags", ""),
                            "tcp_increment_source_port": tcp_data.get("tcp_increment_source_port", False),
                            "tcp_source_port_step": tcp_data.get("tcp_source_port_step", "1"),
                            "tcp_source_port_count": tcp_data.get("tcp_source_port_count", "1"),
                            "tcp_increment_destination_port": tcp_data.get("tcp_increment_destination_port", False),
                            "tcp_destination_port_step": tcp_data.get("tcp_destination_port_step", "1"),
                            "tcp_destination_port_count": tcp_data.get("tcp_destination_port_count", "1"),
                        },
                        **{
                            "payload_data": payload_data.get("payload_data", ""),
                        },
                        **{
                            "rocev2_traffic_class": rocev2_data.get("traffic_class", "0"),
                            "rocev2_flow_label": rocev2_data.get("flow_label", "000000"),
                            "rocev2_source_gid": rocev2_data.get("source_gid", "0:0:0:0:0:ffff:192.168.1.1"),
                            "rocev2_destination_gid": rocev2_data.get("destination_gid", "0:0:0:0:0:ffff:192.168.1.2"),
                            "rocev2_source_qp": rocev2_data.get("source_qp", "0"),
                            "rocev2_destination_qp": rocev2_data.get("destination_qp", "0"),
                        },
                        **{
                            "override_source_tcp_port": override_settings.get("override_source_tcp_port", False),
                            "override_destination_tcp_port": override_settings.get("override_destination_tcp_port",
                                                                                   False),
                            "override_vlan_tpid": override_settings.get("override_vlan_tpid", False),
                        },
                        **{
                            "stream_rate_type": stream_rate_control.get("stream_rate_type", "Packets Per Second (PPS)"),
                            "stream_pps_rate": stream_rate_control.get("stream_pps_rate", None),
                            "stream_bit_rate": stream_rate_control.get("stream_bit_rate", None),
                            "stream_load_percentage": stream_rate_control.get("stream_load_percentage", None),
                            "stream_duration_mode": stream_rate_control.get("stream_duration_mode", "Continuous"),
                            "stream_duration_seconds": stream_rate_control.get("stream_duration_seconds", "10"),
                        },
                    }

                    self.streams[port].append(merged_stream)

            # Load removed interfaces and selected servers
            self.removed_interfaces = set(session_data.get("removed_interfaces", []))
            self.selected_servers = [
                server for server in self.server_interfaces
                if server["address"] in session_data.get("selected_servers", [])
            ]

            # Update UI components
            self.update_server_tree()
            self.update_stream_table()
            print("Session loaded successfully.")

        except FileNotFoundError:
            print("No session file found. Starting fresh.")
            self._initialize_empty_session()

        except json.JSONDecodeError:
            print("Invalid session file format. Starting fresh.")
            self._initialize_empty_session()

        except Exception as e:
            print(f"Failed to load session: {e}")
            self._initialize_empty_session()

    def reset_session(self):
        """Reset the session data to default."""
        self.server_interfaces = []
        self.streams = {}
        self.removed_interfaces = set()
        self.selected_servers = []
        self.update_server_tree()
        self.update_stream_table()

    '''def fetch_and_update_statistics(self):
        """Fetch traffic statistics from all selected servers and calculate all fields locally."""
        if not self.selected_servers:
            print("No servers selected. Clearing traffic statistics.")
            self.clear_statistics_table()
            return

        merged_statistics = {}

        for server in self.selected_servers:
            tg_id = server["tg_id"]  # Get the TG ID of the server
            server_address = server["address"]
            try:
                print(f"Fetching data from {server_address}...")
                response = requests.get(f"{server_address}/api/interfaces", timeout=5)
                if response.status_code == 200:
                    interfaces = response.json()
                    print(f"Fetched interfaces: {interfaces}")
                    for interface in interfaces:
                        # Create a unique interface name with TG ID
                        interface_name = f"TG {tg_id} - Port: {interface['name']}"

                        # Skip removed interfaces
                        if interface_name in self.removed_interfaces:
                            print(f"Skipping removed interface: {interface_name}")
                            continue

                        # Get raw values or default to 0
                        tx = interface.get("tx", 0)
                        rx = interface.get("rx", 0)
                        sent_bytes = interface.get("sent_bytes", tx * 64)  # Assume 64 bytes per frame
                        received_bytes = interface.get("received_bytes", rx * 64)
                        send_fps = tx // 10  # Approximation, replace `10` with the correct time window
                        receive_fps = rx // 10
                        send_bps = sent_bytes * 8  # Convert bytes to bits
                        receive_bps = received_bytes * 8
                        errors = interface.get("errors", 0)

                        # Initialize or update statistics for the interface
                        if interface_name not in merged_statistics:
                            merged_statistics[interface_name] = {
                                "status": interface.get("status", "N/A"),
                                "tx": tx,
                                "rx": rx,
                                "sent_bytes": sent_bytes,
                                "received_bytes": received_bytes,
                                "send_fps": send_fps,
                                "receive_fps": receive_fps,
                                "send_bps": send_bps,
                                "receive_bps": receive_bps,
                                "errors": errors,
                            }
                else:
                    print(f"Failed to fetch statistics from {server_address}. Status code: {response.status_code}")
            except requests.RequestException as e:
                print(f"Error fetching statistics from {server_address}: {e}")

        if merged_statistics:
            self.update_statistics_table(merged_statistics)
        else:
            print("No statistics were fetched or merged. Clearing statistics table.")
            self.clear_statistics_table()'''

    def fetch_and_update_statistics(self):
        """Fetch traffic statistics from all selected servers and calculate all fields locally."""
        if not self.selected_servers:
            print("No servers selected. Clearing traffic statistics.")
            self.clear_statistics_table()
            return

        if not hasattr(self, 'current_statistics'):
            self.current_statistics = {}  # Retain previously fetched stats

        merged_statistics = self.current_statistics.copy()  # Start with existing stats

        for server in self.selected_servers:
            tg_id = server["tg_id"]  # Get the TG ID of the server
            server_address = server["address"]
            try:
                #print(f"Fetching data from {server_address}...")
                response = requests.get(f"{server_address}/api/interfaces", timeout=5)
                if response.status_code == 200:
                    interfaces = response.json()
                    #print(f"Fetched interfaces: {interfaces}")
                    for interface in interfaces:
                        # Create a unique interface name with TG ID
                        interface_name = f"TG {tg_id} - Port: {interface['name']}"

                        # Skip removed interfaces
                        if interface_name in self.removed_interfaces:
                            #print(f"Skipping removed interface: {interface_name}")
                            merged_statistics.pop(interface_name, None)  # Remove stale stats
                            continue

                        # Get raw values or default to 0
                        tx = interface.get("tx", 0)
                        rx = interface.get("rx", 0)
                        sent_bytes = interface.get("sent_bytes", tx * 64)  # Assume 64 bytes per frame
                        received_bytes = interface.get("received_bytes", rx * 64)
                        send_fps = tx // 10  # Approximation, replace `10` with the correct time window
                        receive_fps = rx // 10
                        send_bps = sent_bytes * 8  # Convert bytes to bits
                        receive_bps = received_bytes * 8
                        errors = interface.get("errors", 0)

                        # Update statistics for the interface
                        merged_statistics[interface_name] = {
                            "status": interface.get("status", "N/A"),
                            "tx": tx,
                            "rx": rx,
                            "sent_bytes": sent_bytes,
                            "received_bytes": received_bytes,
                            "send_fps": send_fps,
                            "receive_fps": receive_fps,
                            "send_bps": send_bps,
                            "receive_bps": receive_bps,
                            "errors": errors,
                        }
                else:
                    print(f"Failed to fetch statistics from {server_address}. Status code: {response.status_code}")
            except requests.RequestException as e:
                print(f"Error fetching statistics from {server_address}: {e}")

        # Update or retain previous statistics
        if merged_statistics:
            self.current_statistics = merged_statistics  # Retain current statistics for next fetch
            self.update_statistics_table(merged_statistics)
        else:
            print("No statistics were fetched or merged. Retaining existing statistics.")

    def update_statistics_table(self, statistics):
        """Update the traffic statistics table with the merged statistics."""
        self.statistics_table.clearContents()
        self.statistics_table.setColumnCount(len(statistics))
        self.statistics_table.setHorizontalHeaderLabels(statistics.keys())

        for col, (interface_name, stats) in enumerate(statistics.items()):
            self.statistics_table.setItem(0, col, QTableWidgetItem(stats["status"]))
            self.statistics_table.setItem(1, col, QTableWidgetItem(str(stats["tx"])))
            self.statistics_table.setItem(2, col, QTableWidgetItem(str(stats["rx"])))
            self.statistics_table.setItem(3, col, QTableWidgetItem(str(stats["sent_bytes"])))
            self.statistics_table.setItem(4, col, QTableWidgetItem(str(stats["received_bytes"])))
            self.statistics_table.setItem(5, col, QTableWidgetItem(str(stats["send_fps"])))
            self.statistics_table.setItem(6, col, QTableWidgetItem(str(stats["receive_fps"])))
            self.statistics_table.setItem(7, col, QTableWidgetItem(str(stats["send_bps"])))
            self.statistics_table.setItem(8, col, QTableWidgetItem(str(stats["receive_bps"])))
            self.statistics_table.setItem(9, col, QTableWidgetItem(str(stats["errors"])))

        print(f"Updated statistics table with {len(statistics)} interfaces.")

    def clear_statistics_table(self):
        """Clear the traffic statistics table."""
        self.statistics_table.clearContents()
        self.statistics_table.setColumnCount(0)
        self.statistics_table.setRowCount(10)  # Reset rows for default structure
        #print("Traffic statistics cleared.")




    def setup_stream_section(self):
        """Set up the streams management section."""
        self.stream_group = QGroupBox("Streams")
        layout = QVBoxLayout()

        # Add Start and Stop Stream Buttons at the Top
        start_stop_button_layout = QHBoxLayout()

        # Start Stream Button
        self.start_stream_button = QPushButton()
        self.start_stream_button.setText("")
        self.start_stream_button.setIcon(QIcon("resources/icons/start.png"))  # Use the correct icon path
        self.start_stream_button.setIconSize(QSize(16, 16))
        self.start_stream_button.clicked.connect(self.start_stream)
        start_stop_button_layout.addWidget(self.start_stream_button)

        # Stop Stream Button
        self.stop_stream_button = QPushButton()
        self.stop_stream_button.setText("")
        self.stop_stream_button.setIcon(QIcon("resources/icons/stop.png"))  # Use the correct icon path
        self.stop_stream_button.setIconSize(QSize(16, 16))
        self.stop_stream_button.clicked.connect(self.stop_stream)
        start_stop_button_layout.addWidget(self.stop_stream_button)

        # Align buttons to the left by adding a spacer
        start_stop_button_layout.addStretch(1)

        # Add the Start/Stop button layout to the main layout
        layout.addLayout(start_stop_button_layout)

        # Stream Table
        self.stream_table = QTableWidget()
        self.stream_table.setColumnCount(16)  # Ensure column count matches the table's updated structure
        self.stream_table.setHorizontalHeaderLabels([
            "Status", "Interface", "Name", "Enabled", "Details", "Frame Type",
            "Min Size", "Max Size", "Fixed Size", "L1", "VLAN", "L2", "L3", "L4", "Payload"
        ])
        layout.addWidget(self.stream_table)

        # Stream Buttons (Add, Edit, Remove) with Icons and Text
        button_layout = QHBoxLayout()

        # Add Stream Button
        add_stream_button = QPushButton()
        add_stream_button.setText(" Add")
        add_stream_button.setIcon(QIcon("resources/icons/add.png"))
        add_stream_button.setIconSize(QSize(16, 16))
        add_stream_button.clicked.connect(self.open_add_stream_dialog)
        add_stream_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        button_layout.addWidget(add_stream_button)

        # Edit Stream Button
        edit_stream_button = QPushButton()
        edit_stream_button.setText(" Edit")
        edit_stream_button.setIcon(QIcon("resources/icons/edit.png"))
        edit_stream_button.setIconSize(QSize(16, 16))
        edit_stream_button.clicked.connect(self.edit_selected_stream)
        edit_stream_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        button_layout.addWidget(edit_stream_button)

        # Remove Stream Button
        remove_stream_button = QPushButton()
        remove_stream_button.setText(" Delete")
        remove_stream_button.setIcon(QIcon("resources/icons/Trash.png"))
        remove_stream_button.setIconSize(QSize(16, 16))
        remove_stream_button.clicked.connect(self.remove_selected_stream)
        remove_stream_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        button_layout.addWidget(remove_stream_button)

        # Add spacer to push Add/Edit/Delete buttons to the left
        button_layout.addStretch(1)

        # Add buttons layout to the main layout
        layout.addLayout(button_layout)

        # Set the final layout for the stream group
        self.stream_group.setLayout(layout)
        self.top_section.addWidget(self.stream_group)
    def update_stream_table(self):
        """Update the stream table with streams for all selected TG ports."""
        # Save currently selected rows
        selected_rows = set(
            index.row() for index in self.stream_table.selectionModel().selectedRows()
        )

        # Clear the table for a fresh update
        self.stream_table.setRowCount(0)

        # Get selected ports
        selected_ports = []
        selected_items = self.server_tree.selectedItems()
        for item in selected_items:
            parent = item.parent()
            if parent:  # It's a port (child item)
                tg_id = parent.text(0)
                port_name = item.text(0)
                full_port_name = f"{tg_id} - {port_name}"
                selected_ports.append(full_port_name)

        # Populate streams for all ports or only selected ports
        for port, streams in self.streams.items():
            if not selected_ports or port in selected_ports:  # Include all if no selection
                for stream_index, stream in enumerate(streams):
                    row_position = self.stream_table.rowCount()
                    self.stream_table.insertRow(row_position)

                    # Add Status Column (0)
                    status_icon = QIcon("resources/icons/red_dot.png")  # Default to red dot
                    if stream.get("status") == "running":
                        status_icon = QIcon("resources/icons/green_dot.png")  # Green dot if running
                    status_item = QTableWidgetItem()
                    status_item.setIcon(status_icon)
                    status_item.setFlags(Qt.ItemIsEnabled)  # Make the status column read-only
                    self.stream_table.setItem(row_position, 0, status_item)

                    # Interface Column (1)
                    self.stream_table.setItem(row_position, 1, QTableWidgetItem(port))

                    # Name Column (2)
                    stream_name = stream.get("name", f"Unnamed Stream {stream_index}")
                    self.stream_table.setItem(row_position, 2, QTableWidgetItem(stream_name))

                    # Enabled Column (3)
                    enabled_text = "Yes" if stream.get("enabled") else "No"
                    self.stream_table.setItem(row_position, 3, QTableWidgetItem(enabled_text))

                    # Populate Remaining Columns
                    column_keys = [
                        "details", "frame_type", "frame_min", "frame_max", "frame_size",
                        "L1", "VLAN", "L2", "L3", "L4", "Payload"
                    ]
                    for col_index, key in enumerate(column_keys, start=4):  # Start from column 4
                        value = stream.get(key, "")
                        self.stream_table.setItem(row_position, col_index, QTableWidgetItem(str(value)))

        # Restore previously selected rows
        selection_model = self.stream_table.selectionModel()
        for row_index in selected_rows:
            if row_index < self.stream_table.rowCount():  # Ensure the row still exists
                selection_model.select(
                    self.stream_table.model().index(row_index, 0),
                    QItemSelectionModel.Select | QItemSelectionModel.Rows
                )

        print(f"Stream table updated {self.stream_table.rowCount()} rows.")  # Debugging

    '''def start_stream(self):
        """Start the selected streams, update their statuses, and notify the server."""
        selected_rows = self.stream_table.selectionModel().selectedRows()

        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a stream to start.")
            return

        streams_to_start = {}

        for row in selected_rows:
            row_index = row.row()  # Get the selected row index
            port = self.stream_table.item(row_index, 1).text()  # Interface column
            stream_name = self.stream_table.item(row_index, 2).text()  # Stream name column

            # Identify the stream based on its row index
            streams = self.streams.get(port, [])
            if row_index < len(streams):
                stream = streams[row_index]
                if stream.get("name", f"Unnamed Stream {row_index}") == stream_name:
                    stream["status"] = "running"  # Update the stream status to 'running'
                    print(f"Stream '{stream_name}' on {port} started successfully.")

                    # Collect stream data for server
                    if port not in streams_to_start:
                        streams_to_start[port] = []
                    streams_to_start[port].append(stream)
                else:
                    print(f"Stream '{stream_name}' not found in interface '{port}'.")
            else:
                print(f"Stream at row {row_index} for port {port} not found.")

        # Send stream data to the server
        for port, streams in streams_to_start.items():
            # Identify the server for the port
            server_info = next(
                (s for s in self.server_interfaces if f"TG {s.get('tg_id', '')} - Port: {s.get('port', '')}" in port),
                None
            )
            if not server_info:
                QMessageBox.warning(self, "Stream Error", f"No server address found for port: {port}")
                print(f"No server found for port: {port}. Available server interfaces: {self.server_interfaces}")
                continue

            server_address = server_info["address"]

            try:
                payload = {
                    "streams": {port: streams},
                }
                print(f"Sending payload to {server_address}: {payload}")
                response = requests.post(f"{server_address}/api/traffic/start", json=payload)
                if response.status_code == 200:
                    #QMessageBox.information(self, "Start Stream", f"Streams on {port} started successfully.")
                    print(f"Stream '{stream_name}' on {port} Server response ok {response.status_code}.")
                else:
                    QMessageBox.critical(self, "Stream Error", f"Failed to start streams on {port}: {response.text}")
            except Exception as e:
                QMessageBox.critical(self, "Stream Error", f"Error connecting to server {server_address}: {e}")

        self.update_stream_table()  # Refresh the table'''

    def start_stream(self):
        """Start the selected streams, update their statuses, and notify the server."""
        selected_rows = self.stream_table.selectionModel().selectedRows()

        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a stream to start.")
            return

        streams_to_start = {}

        for row in selected_rows:
            row_index = row.row()  # Get the selected row index
            port = self.stream_table.item(row_index, 1).text()  # Interface column
            stream_name = self.stream_table.item(row_index, 2).text()  # Stream name column

            # Identify the stream based on its row index
            streams = self.streams.get(port, [])
            if row_index < len(streams):
                stream = streams[row_index]
                if stream.get("name", f"Unnamed Stream {row_index}") == stream_name:
                    stream["status"] = "running"  # Update the stream status to 'running'
                    print(f"Stream '{stream_name}' on {port} started successfully.")

                    # Format stream data for the server
                    structured_stream = {
                        "protocol_selection": {
                            "name": stream.get("name", ""),
                            "enabled": stream.get("enabled", False),
                            "details": stream.get("details", ""),
                            "frame_type": stream.get("frame_type", "Fixed"),
                            "frame_min": stream.get("frame_min", "64"),
                            "frame_max": stream.get("frame_max", "1518"),
                            "frame_size": stream.get("frame_size", "64"),
                            "L1": stream.get("L1", "None"),
                            "VLAN": stream.get("VLAN", "Untagged"),
                            "L2": stream.get("L2", "None"),
                            "L3": stream.get("L3", "None"),
                            "L4": stream.get("L4", "None"),
                            "Payload": stream.get("Payload", "None"),
                        },
                        "protocol_data": {
                            "mac": {
                                "mac_destination_mode": stream.get("mac_destination_mode", "Fixed"),
                                "mac_destination_address": stream.get("mac_destination_address", "00:00:00:00:00:00"),
                                "mac_destination_count": stream.get("mac_destination_count", "1"),
                                "mac_destination_step": stream.get("mac_destination_step", "1"),
                                "mac_source_mode": stream.get("mac_source_mode", "Fixed"),
                                "mac_source_address": stream.get("mac_source_address", "00:00:00:00:00:00"),
                                "mac_source_count": stream.get("mac_source_count", "1"),
                                "mac_source_step": stream.get("mac_source_step", "1"),
                            },
                            "vlan": {
                                "vlan_priority": stream.get("vlan_priority", "0"),
                                "vlan_cfi_dei": stream.get("vlan_cfi_dei", "0"),
                                "vlan_id": stream.get("vlan_id", "1"),
                                "vlan_tpid": stream.get("vlan_tpid", "81 00"),
                                "vlan_increment": stream.get("vlan_increment", False),
                                "vlan_increment_value": stream.get("vlan_increment_value", "1"),
                                "vlan_increment_count": stream.get("vlan_increment_count", "1"),
                            },
                            "ipv4": {
                                "ipv4_source": stream.get("ipv4_source", "0.0.0.0"),
                                "ipv4_destination": stream.get("ipv4_destination", "0.0.0.0"),
                                "ipv4_source_mode": stream.get("ipv4_source_mode", "Fixed"),
                                "ipv4_destination_mode": stream.get("ipv4_destination_mode", "Fixed"),
                                "ipv4_tos": stream.get("ipv4_tos", None),
                                "ipv4_dscp": stream.get("ipv4_dscp", None),
                                "ipv4_ecn": stream.get("ipv4_ecn", None),
                                "ipv4_custom_tos": stream.get("ipv4_custom_tos", None),
                                "ipv4_ttl": stream.get("ipv4_ttl", "64"),
                                "ipv4_identification": stream.get("ipv4_identification", "0000"),
                                "ipv4_increment_source": stream.get("ipv4_increment_source", False),
                                "ipv4_source_increment_step": stream.get("ipv4_source_increment_step", "1"),
                                "ipv4_source_increment_count": stream.get("ipv4_source_increment_count", "1"),
                                "ipv4_increment_destination": stream.get("ipv4_increment_destination", False),
                                "ipv4_destination_increment_step": stream.get("ipv4_destination_increment_step", "1"),
                                "ipv4_destination_increment_count": stream.get("ipv4_destination_increment_count", "1"),
                                "ipv4_df": stream.get("ipv4_df", False),
                                "ipv4_mf": stream.get("ipv4_mf", False),
                                "ipv4_fragment_offset": stream.get("ipv4_fragment_offset", "0"),
                            },
                            "tcp": {
                                "tcp_source_port": stream.get("tcp_source_port", "0"),
                                "tcp_destination_port": stream.get("tcp_destination_port", "0"),
                                "tcp_sequence_number": stream.get("tcp_sequence_number", "0"),
                                "tcp_acknowledgement_number": stream.get("tcp_acknowledgement_number", "0"),
                                "tcp_window": stream.get("tcp_window", "1024"),
                                "tcp_checksum": stream.get("tcp_checksum", ""),
                                "tcp_flags": stream.get("tcp_flags", ""),
                                "tcp_increment_source_port": stream.get("tcp_increment_source_port", False),
                                "tcp_source_port_step": stream.get("tcp_source_port_step", "1"),
                                "tcp_source_port_count": stream.get("tcp_source_port_count", "1"),
                                "tcp_increment_destination_port": stream.get("tcp_increment_destination_port", False),
                                "tcp_destination_port_step": stream.get("tcp_destination_port_step", "1"),
                                "tcp_destination_port_count": stream.get("tcp_destination_port_count", "1"),
                            },
                            "rocev2": {
                                "traffic_class": stream.get("rocev2_traffic_class", "0"),
                                "flow_label": stream.get("rocev2_flow_label", "000000"),
                                "source_gid": stream.get("rocev2_source_gid", "0:0:0:0:0:ffff:192.168.1.1"),
                                "destination_gid": stream.get("rocev2_destination_gid", "0:0:0:0:0:ffff:192.168.1.2"),
                                "source_qp": stream.get("rocev2_source_qp", "0"),
                                "destination_qp": stream.get("rocev2_destination_qp", "0"),
                            },
                            "payload_data": {
                                "payload_data": stream.get("payload_data", ""),
                            },
                        },
                        "override_settings": {
                            "override_source_tcp_port": stream.get("override_source_tcp_port", False),
                            "override_destination_tcp_port": stream.get("override_destination_tcp_port", False),
                            "override_vlan_tpid": stream.get("override_vlan_tpid", False),
                        },
                        "stream_rate_control": {
                            "stream_rate_type": stream.get("stream_rate_type", "Packets Per Second (PPS)"),
                            "stream_pps_rate": stream.get("stream_pps_rate", None),
                            "stream_bit_rate": stream.get("stream_bit_rate", None),
                            "stream_load_percentage": stream.get("stream_load_percentage", None),
                            "stream_duration_mode": stream.get("stream_duration_mode", "Continuous"),
                            "stream_duration_seconds": stream.get("stream_duration_seconds", "10"),
                        },
                    }
                    # Add formatted stream to the server payload
                    if port not in streams_to_start:
                        streams_to_start[port] = []
                    streams_to_start[port].append(structured_stream)
                else:
                    print(f"Stream '{stream_name}' not found in interface '{port}'.")

        # Send stream data to the server
        for port, streams in streams_to_start.items():
            server_info = next(
                (s for s in self.server_interfaces if f"TG {s.get('tg_id', '')} - Port: {s.get('port', '')}" in port),
                None
            )
            if not server_info:
                QMessageBox.warning(self, "Stream Error", f"No server address found for port: {port}")
                print(f"No server found for port: {port}. Available server interfaces: {self.server_interfaces}")
                continue

            server_address = server_info["address"]
            try:
                payload = {"streams": {port: streams}}
                print(f"Sending payload to {server_address}: {payload}")
                response = requests.post(f"{server_address}/api/traffic/start", json=payload)
                if response.status_code == 200:
                    print(f"Streams on {port} started successfully: {response.json()}")
                else:
                    QMessageBox.critical(self, "Stream Error", f"Failed to start streams on {port}: {response.text}")
            except Exception as e:
                QMessageBox.critical(self, "Stream Error", f"Error connecting to server {server_address}: {e}")

        self.update_stream_table()  # Refresh the table

    '''def stop_stream(self):
        """Stop the selected streams, update their statuses, and notify the server."""
        selected_rows = self.stream_table.selectionModel().selectedRows()

        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a stream to stop.")
            return

        streams_to_stop = []  # List to send to the server

        for row in selected_rows:
            row_index = row.row()  # Get the selected row index
            port = self.stream_table.item(row_index, 1).text()  # Interface column
            stream_name = self.stream_table.item(row_index, 2).text()  # Stream name column

            # Identify the stream based on the port and index
            streams = self.streams.get(port, [])
            if row_index < len(streams):
                stream = streams[row_index]
                if stream.get("name", f"Unnamed Stream {row_index}") == stream_name:
                    stream["status"] = "stopped"  # Mark stream as stopped
                    streams_to_stop.append(stream)  # Add to the list to notify the server
                    print(f"Stream '{stream_name}' on {port} marked as stopped.")
                else:
                    print(f"Stream '{stream_name}' not found in interface '{port}'.")
            else:
                print(f"Stream at row {row_index} for port {port} not found.")

        if not streams_to_stop:
            QMessageBox.warning(self, "No Streams to Stop", "No streams could be stopped.")
            return

        # Notify the server
        server_address = self.selected_servers[0]["address"] if self.selected_servers else None
        if server_address:
            try:
                response = requests.post(
                    f"{server_address}/api/traffic/stop",
                    json={"streams": streams_to_stop},
                    timeout=5,
                )
                if response.status_code == 200:
                    #QMessageBox.information(self, "Stop Stream", "Selected streams have been stopped.")
                    print("Selected streams have been stopped")
                else:
                    QMessageBox.critical(self, "Stop Stream", f"Server Error: {response.text}")
            except requests.RequestException as e:
                QMessageBox.critical(self, "Stop Stream", f"Error connecting to server: {e}")
        else:
            QMessageBox.critical(self, "Stop Stream", "No server address found.")

        self.update_stream_table()  # Refresh the table'''

    def stop_stream(self):
        """Stop the selected streams, update their statuses, and notify the server."""
        selected_rows = self.stream_table.selectionModel().selectedRows()

        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a stream to stop.")
            return

        streams_to_stop = []  # List to send to the server

        for row in selected_rows:
            row_index = row.row()  # Get the selected row index
            port = self.stream_table.item(row_index, 1).text()  # Interface column
            stream_name = self.stream_table.item(row_index, 2).text()  # Stream name column

            # Identify the stream based on the port and index
            streams = self.streams.get(port, [])
            if row_index < len(streams):
                stream = streams[row_index]
                if stream.get("name", f"Unnamed Stream {row_index}") == stream_name:
                    stream["status"] = "stopped"  # Mark stream as stopped
                    streams_to_stop.append(
                        {"name": stream_name, "interface": port})  # Add to the list to notify the server
                    print(f"Stream '{stream_name}' on {port} marked as stopped.")
                else:
                    print(f"Stream '{stream_name}' not found in interface '{port}'.")
            else:
                print(f"Stream at row {row_index} for port {port} not found.")

        if not streams_to_stop:
            QMessageBox.warning(self, "No Streams to Stop", "No streams could be stopped.")
            return

        # Notify the server
        server_address = self.selected_servers[0]["address"] if self.selected_servers else None
        if server_address:
            try:
                response = requests.post(
                    f"{server_address}/api/traffic/stop",
                    json={"streams": streams_to_stop},
                    timeout=5,
                )
                if response.status_code == 200:
                    print("Selected streams have been stopped successfully.")
                else:
                    QMessageBox.critical(self, "Stop Stream", f"Server Error: {response.text}")
            except requests.RequestException as e:
                QMessageBox.critical(self, "Stop Stream", f"Error connecting to server: {e}")
        else:
            QMessageBox.critical(self, "Stop Stream", "No server address found.")

        self.update_stream_table()  # Refresh the table

    def update_stream_status(self, row, color):
        """Update the stream status to green or red dot for a specific row."""
        status_icon = QIcon(f"resources/icons/{color}_dot.png")  # Green or red dot icon
        status_item = QTableWidgetItem()
        status_item.setIcon(status_icon)
        status_item.setFlags(Qt.ItemIsEnabled)  # Read-only status column
        self.stream_table.setItem(row, 0, status_item)

    def setup_stream_start_stop_buttons(self):
        """Set up Start and Stop Stream buttons."""
        button_layout = QHBoxLayout()

        # Start Stream Button
        self.start_stream_button = QPushButton("Start Stream")
        self.start_stream_button.clicked.connect(self.start_stream)
        button_layout.addWidget(self.start_stream_button)
        # Stop Stream Button
        self.stop_stream_button = QPushButton("Stop Stream")
        self.stop_stream_button.clicked.connect(self.stop_stream)
        button_layout.addWidget(self.stop_stream_button)

        # Align buttons to the left
        button_layout.addStretch()  # Adds spacing to the right to align buttons to the left

        return button_layout



    def copy_selected_stream(self):
        """Copy the selected stream to a temporary variable."""
        selected_rows = self.stream_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a stream to copy.")
            return

        # Get the selected stream's details
        selected_row = selected_rows[0].row()
        interface = self.stream_table.item(selected_row, 0).text()
        stream_name = self.stream_table.item(selected_row, 1).text()

        # Find the stream in the dictionary
        stream = next((s for s in self.streams.get(interface, []) if s["name"] == stream_name), None)
        if not stream:
            QMessageBox.warning(self, "Error", "Stream not found.")
            return

        # Save the stream to a temporary variable
        self.copied_stream = stream
        print(f"Copied Stream: {self.copied_stream}")
        #QMessageBox.information(self, "Stream Copied", f"Stream '{stream_name}' copied successfully.")

    def paste_stream_to_interface(self):
        """Paste the copied stream to the selected interface."""
        if not hasattr(self, 'copied_stream') or not self.copied_stream:
            QMessageBox.warning(self, "No Stream Copied", "Please copy a stream first.")
            return

        selected_items = self.server_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a TG port to paste the stream.")
            return

        selected_item = selected_items[0]
        parent_item = selected_item.parent()

        # Ensure a port is selected (not a TG server)
        if parent_item is None:
            QMessageBox.warning(self, "Invalid Selection", "Please select a TG port, not a server.")
            return

        tg_id = parent_item.text(0)
        port_name = selected_item.text(0)
        full_port_name = f"{tg_id} - {port_name}"

        # Ensure the target port exists in the streams dictionary
        if full_port_name not in self.streams:
            self.streams[full_port_name] = []

        # Copy the stream data and ensure the name is unique
        pasted_stream = self.copied_stream.copy()
        pasted_stream["name"] = f"{pasted_stream['name']}_copy"

        # Append the copied stream to the target port
        self.streams[full_port_name].append(pasted_stream)
        print(f"Pasted Stream to {full_port_name}: {pasted_stream}")
        # Refresh the stream table
        self.update_stream_table()
        #QMessageBox.information(self, "Stream Pasted", f"Stream pasted to {full_port_name}.")

    def setup_traffic_statistics_section(self):
        """Set up the traffic statistics section."""
        self.statistics_group = QGroupBox("Traffic Statistics")
        layout = QVBoxLayout()

        # Statistics Table
        self.statistics_table = QTableWidget()
        self.statistics_table.setRowCount(10)
        self.statistics_table.setColumnCount(0)
        self.statistics_table.setVerticalHeaderLabels([
            "Status", "Sent Frames", "Received Frames", "Sent Bytes", "Received Bytes",
            "Send Frame Rate (fps)", "Receive Frame Rate (fps)", "Send Bit Rate (bps)",
            "Receive Bit Rate (bps)", "Errors"
        ])
        layout.addWidget(self.statistics_table)
        self.statistics_group.setLayout(layout)
        self.splitter.addWidget(self.statistics_group)

    def save_removed_interfaces(self):
        """Save removed interfaces to a file."""
        try:
            with open("removed_interfaces.txt", "w") as f:
                for interface in self.removed_interfaces:
                    f.write(f"{interface}\n")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not save removed interfaces: {e}")

    def save_interfaces(self):
        """Save the current list of interfaces to a file."""
        try:
            # Collect current interfaces from the statistics table
            interfaces = [self.statistics_table.horizontalHeaderItem(col).text()
                          for col in range(self.statistics_table.columnCount())]

            # Save the interfaces to a file
            with open("interfaces.txt", "w") as f:
                for interface in interfaces:
                    f.write(f"{interface}\n")

            QMessageBox.information(self, "Save Successful", "Current interfaces have been saved.")
        except Exception as e:
            QMessageBox.warning(self, "Save Failed", f"An error occurred while saving: {str(e)}")

    def load_removed_interfaces(self):
        """Load removed interfaces from a file."""
        try:
            with open("removed_interfaces.txt", "r") as f:
                self.removed_interfaces = {line.strip() for line in f.readlines()}
        except FileNotFoundError:
            self.removed_interfaces = set()


    def open_add_stream_dialog(self):
        """Open a dialog to add a stream for the selected TG port."""
        selected_items = self.server_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a TG port to add a stream.")
            return

        selected_item = selected_items[0]
        parent_item = selected_item.parent()

        # Ensure a port is selected (not a TG server)
        if parent_item is None:
            QMessageBox.warning(self, "Invalid Selection", "Please select a TG port, not a server.")
            return

        tg_id = parent_item.text(0)
        port_name = selected_item.text(0)
        full_port_name = f"{tg_id} - {port_name}"

        # Open the stream dialog
        dialog = AddStreamDialog(self, full_port_name)
        if dialog.exec() == QDialog.Accepted:
            stream_details = dialog.get_stream_details()

            # Ensure a list exists for the TG port in the streams dictionary
            if full_port_name not in self.streams:
                self.streams[full_port_name] = []  # Initialize the list for the port

            # Generate a unique name for the stream
            existing_names = {stream["name"] for stream in self.streams[full_port_name]}
            base_name = stream_details.get("name", "NewStream")
            unique_name = base_name
            counter = 1

            while unique_name in existing_names:
                unique_name = f"{base_name}_{counter}"
                counter += 1

            # Assign the unique name to the stream details
            stream_details["name"] = unique_name

            # Append the new stream to the list for the selected TG port
            self.streams[full_port_name].append(stream_details)

            print(f"Stream added for {full_port_name}: {stream_details}")  # Debugging

            # Refresh the stream table
            self.update_stream_table()


    def edit_selected_stream(self):
        """Edit the selected stream."""
        # Get selected rows
        selected_rows = self.stream_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a stream to edit.")
            return

        try:
            # Extract selected row details
            selected_row = selected_rows[0].row()  # Use the first selected row
            interface_item = self.stream_table.item(selected_row, 1)  # Interface is column 1
            stream_name_item = self.stream_table.item(selected_row, 2)  # Name is column 2

            if not interface_item or not stream_name_item:
                raise ValueError("The selected row does not contain valid stream data.")

            interface = interface_item.text().strip()
            stream_name = stream_name_item.text().strip()
            print(f"Selected Interface: {interface}, Selected Stream Name: {stream_name}")  # Debug

            # Locate the stream in the dictionary
            if interface not in self.streams:
                raise KeyError(f"Interface '{interface}' not found in streams dictionary.")

            stream = next((s for s in self.streams[interface] if s.get("name") == stream_name), None)
            if not stream:
                raise KeyError(f"Stream '{stream_name}' not found in interface '{interface}'.")

            print(f"Stream to be edited: {stream}")  # Debug
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
            return

        # Open the dialog and handle edits
        try:
            dialog = AddStreamDialog(self, interface, stream_data=stream)
            if dialog.exec() == QDialog.Accepted:
                # Retrieve updated stream details
                edited_stream = dialog.get_stream_details()
                print(f"Edited Stream Details: {edited_stream}")  # Debug

                if not edited_stream:
                    QMessageBox.warning(self, "Edit Stream", "No changes were made to the stream.")
                    return

                # Update the stream details in place
                for key, value in edited_stream.items():
                    stream[key] = value

                # Refresh the stream table
                self.update_stream_table()
                print(f"Stream '{stream_name}' updated successfully.")  # Debug
            else:
                print("Edit operation canceled.")  # Debug
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to edit the stream: {e}")

    def remove_selected_stream(self):
        """Remove the selected stream from the table and data structure."""
        selected_rows = self.stream_table.selectionModel().selectedRows()

        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a stream to remove.")
            return

        try:
            for row in selected_rows:
                row_index = row.row()
                interface_item = self.stream_table.item(row_index, 1)  # Assuming column 1 is for the interface
                stream_name_item = self.stream_table.item(row_index, 2)  # Assuming column 2 is for the stream name

                # Validate interface and stream name
                if not interface_item or not stream_name_item:
                    QMessageBox.critical(self, "Error", "Invalid row selection. Missing interface or stream name.")
                    continue

                interface = interface_item.text()
                stream_name = stream_name_item.text()

                # Debugging: Log interface and stream name
                print(f"Removing stream '{stream_name}' from interface '{interface}'")

                # Check if interface exists in the data structure
                if interface not in self.streams:
                    QMessageBox.warning(self, "Error", f"Interface '{interface}' not found.")
                    continue

                # Remove the stream from the data structure
                self.streams[interface] = [s for s in self.streams[interface] if s["name"] != stream_name]

            # Refresh the stream table
            self.update_stream_table()

            QMessageBox.information(self, "Stream Removed", "Selected streams have been removed.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred while removing the stream: {e}")

    def on_server_checkbox_state_changed(self, index, state):
        """Handle state changes for the server selection checkboxes."""
        server = self.server_interfaces[index]
        if state == Qt.Checked:
            if server not in self.selected_servers:
                self.selected_servers.append(server)
                print(f"Server selected: {server['address']}")
        else:
            if server in self.selected_servers:
                self.selected_servers.remove(server)
                print(f"Server deselected: {server['address']}")

        # Update statistics when selection changes
        self.fetch_and_update_statistics()
class AddStreamDialog(QDialog):
    def __init__(self, parent=None, interface=None, stream_data=None):
        super().__init__(parent)
        self.setWindowTitle("Add/Edit Traffic Stream")
        self.interface = interface
        self.setGeometry(200, 200, 1000, 600)

        # Main Tab layout
        self.tabs = QTabWidget()

        # Protocol Selection Tab
        self.protocol_tab = QWidget()
        self.protocol_tab_layout = QVBoxLayout()
        self.protocol_tab.setLayout(self.protocol_tab_layout)
        self.setup_protocol_selection_tab()

        # Protocol Data Tab
        self.protocol_data_tab = QWidget()
        self.protocol_data_layout = QVBoxLayout()
        self.protocol_data_tab.setLayout(self.protocol_data_layout)
        self.setup_protocol_data_tab()

        # Packet View Tab
        self.packet_view_tab = QWidget()
        self.packet_view_layout = QVBoxLayout()
        self.packet_view_tab.setLayout(self.packet_view_layout)
        self.setup_packet_view_tab()

        # Stream Control Tab
        self.stream_control_tab = QWidget()
        self.setup_stream_control_tab()

        # Variable Fields Tab (Optional)
        self.variable_fields_tab = QWidget()
        # Uncomment the line below to implement the Variable Fields tab setup
        # self.setup_variable_fields_tab()

        # Add tabs
        self.tabs.addTab(self.protocol_tab, "Protocol Selection")
        self.tabs.addTab(self.protocol_data_tab, "Protocol Data")
        self.tabs.addTab(self.variable_fields_tab, "Variable Fields")  # Include only if implemented
        self.tabs.addTab(self.stream_control_tab, "Stream Control")
        self.tabs.addTab(self.packet_view_tab, "Packet View")

        # Scroll Area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(self.tabs)

        # Main Layout
        self.main_layout = QVBoxLayout()
        self.main_layout.addWidget(self.scroll_area)

        # Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.validate_and_accept)
        self.buttons.rejected.connect(self.reject)
        self.main_layout.addWidget(self.buttons)
        self.setLayout(self.main_layout)

        # Populate fields if editing an existing stream
        print(f"__init__ stream_data: {stream_data}")
        if stream_data:
            self.populate_stream_fields(stream_data)

        # Connect Protocol Data fields to Packet View
        self.connect_protocol_data_to_packet_view()

    # Option 1: Implement setup_variable_fields_tab if required

    def validate_and_accept(self):
        """Validates the stream name, generates a dynamic name if empty, and accepts the dialog if valid."""
        stream_name = self.stream_name.text().strip()

        # Generate a default stream name if none is provided
        if not stream_name:
            stream_name = self.generate_default_stream_name()
            self.stream_name.setText(stream_name)  # Update the field for consistency

        # Fetch existing stream names
        existing_stream_names = self.get_existing_stream_names()
        print(f"Validating stream name: {stream_name}")  # Debugging
        print(f"Existing stream names: {existing_stream_names}")  # Debugging

        # Check for duplicates
        if stream_name in existing_stream_names:
            QMessageBox.critical(self, "Duplicate Name", f"The stream name '{stream_name}' is already in use.")
            return  # Do not proceed

        # Add the new name to the list (if applicable)
        if self.parent() and hasattr(self.parent(), "stream_list"):
            self.parent().stream_list.append({"name": stream_name})

        # If all validations pass, call accept to close the dialog
        print("Validation passed, accepting the dialog.")
        self.accept()

    def setup_variable_fields_tab(self):
        """Set up the Variable Fields tab."""
        layout = QVBoxLayout()
        label = QLabel("Variable Fields configuration goes here.")
        layout.addWidget(label)
        self.variable_fields_tab.setLayout(layout)

    def setup_stream_control_tab(self):
        """Sets up the Stream Control Tab with rate control and duration settings."""
        # Main layout for the tab
        control_layout = QVBoxLayout()

        # Rate Control Section
        rate_group = QGroupBox("Rate Control")
        rate_layout = QFormLayout()

        # Rate Type Dropdown
        self.rate_type_dropdown = QComboBox()
        self.rate_type_dropdown.addItems(["Packets Per Second (PPS)", "Bit Rate", "Load (%)"])
        rate_layout.addRow("Rate Type:", self.rate_type_dropdown)

        # Packets Per Second (PPS) Field
        self.stream_pps_rate = QLineEdit("1000")  # Default PPS value
        self.stream_pps_rate.setValidator(QIntValidator(1, 1000000))  # PPS range: 1 - 1,000,000
        rate_layout.addRow("Packets Per Second (PPS):", self.stream_pps_rate)

        # Bit Rate Field
        self.stream_bit_rate = QLineEdit("100")  # Default Bit Rate value in Mbps
        self.stream_bit_rate.setValidator(QIntValidator(1, 1000000))  # Bit Rate range: 1 - 1,000,000 Mbps
        rate_layout.addRow("Bit Rate (Mbps):", self.stream_bit_rate)

        # Load Percentage Field
        self.stream_load_percentage = QLineEdit("50")  # Default Load Percentage
        self.stream_load_percentage.setValidator(QIntValidator(1, 100))  # Load range: 1% - 100%
        rate_layout.addRow("Load (%):", self.stream_load_percentage)

        # Add the rate layout to the rate group
        rate_group.setLayout(rate_layout)
        control_layout.addWidget(rate_group)

        # Duration Control Section
        duration_group = QGroupBox("Duration Control")
        duration_layout = QFormLayout()

        # Duration Mode Dropdown
        self.duration_mode_dropdown = QComboBox()
        self.duration_mode_dropdown.addItems(["Continuous", "Seconds"])
        duration_layout.addRow("Duration Mode:", self.duration_mode_dropdown)

        # Duration Field
        self.stream_duration_field = QLineEdit("10")  # Default duration: 10 seconds
        self.stream_duration_field.setValidator(QIntValidator(1, 3600))  # Duration range: 1 to 3600 seconds
        duration_layout.addRow("Duration (Seconds):", self.stream_duration_field)

        # Add the duration layout to the duration group
        duration_group.setLayout(duration_layout)
        control_layout.addWidget(duration_group)

        # Add stretch to align content at the top
        control_layout.addStretch(1)

        # Set the main layout for the Stream Control tab
        self.stream_control_tab.setLayout(control_layout)

    def setup_protocol_selection_tab(self):
        """Sets up the Protocol Selection Tab with reduced vertical spacing and compact sections."""
        # Set layout for the protocol selection tab
        self.protocol_tab_layout.setSpacing(5)  # Minimal spacing between sections
        self.protocol_tab_layout.setContentsMargins(10, 5, 10, 5)  # Minimal margins

        # Basics Section
        basics_group = QGroupBox("Basics")
        basics_layout = QFormLayout()
        basics_layout.setContentsMargins(5, 5, 5, 5)  # Tighten margins
        basics_layout.setSpacing(2)  # Reduce spacing between rows
        self.stream_name = QLineEdit()
        self.enabled_checkbox = QCheckBox("Enabled")
        self.details_field = QLineEdit()  # Field for stream details
        basics_layout.addRow("Name:", self.stream_name)
        basics_layout.addRow("Enabled:", self.enabled_checkbox)
        basics_layout.addRow("Details:", self.details_field)
        basics_group.setLayout(basics_layout)
        basics_group.setMaximumHeight(90)  # Compact height for Basics Section
        self.protocol_tab_layout.addWidget(basics_group)

        # Frame Length Section
        frame_length_group = QGroupBox("Frame Length (including FCS)")
        frame_length_layout = QGridLayout()
        frame_length_layout.setContentsMargins(5, 5, 5, 5)  # Tighten margins
        frame_length_layout.setSpacing(2)  # Reduce spacing between widgets
        self.frame_type = QComboBox()
        self.frame_type.addItems(["Fixed", "Random", "IMIX"])
        self.frame_min = QLineEdit("64")
        self.frame_max = QLineEdit("1518")
        self.frame_size = QLineEdit("64")
        self.frame_min.setValidator(QIntValidator(64, 1518))
        self.frame_max.setValidator(QIntValidator(64, 1518))
        self.frame_size.setValidator(QIntValidator(64, 1518))
        frame_length_layout.addWidget(QLabel("Frame Type:"), 0, 0)
        frame_length_layout.addWidget(self.frame_type, 0, 1)
        frame_length_layout.addWidget(QLabel("Min:"), 1, 0)
        frame_length_layout.addWidget(self.frame_min, 1, 1)
        frame_length_layout.addWidget(QLabel("Max:"), 1, 2)
        frame_length_layout.addWidget(self.frame_max, 1, 3)
        frame_length_layout.addWidget(QLabel("Fixed Size:"), 2, 0)
        frame_length_layout.addWidget(self.frame_size, 2, 1)
        frame_length_group.setLayout(frame_length_layout)
        frame_length_group.setMaximumHeight(110)  # Compact height for Frame Length Section
        self.protocol_tab_layout.addWidget(frame_length_group)

        # Simple Section (L1, VLAN, L2, L3, L4, Payload)
        simple_group = QGroupBox("Simple")
        simple_layout = QGridLayout()
        simple_layout.setContentsMargins(5, 5, 5, 5)  # Tighten margins
        simple_layout.setSpacing(5)  # Adjust spacing between sections

        # L1 Selection
        l1_group = QGroupBox("L1")
        l1_layout = QVBoxLayout()
        self.l1_none = QRadioButton("None")
        self.l1_mac = QRadioButton("MAC")
        self.l1_none.setChecked(True)
        l1_layout.addWidget(self.l1_none)
        l1_layout.addWidget(self.l1_mac)
        l1_group.setLayout(l1_layout)
        simple_layout.addWidget(l1_group, 0, 0)

        # VLAN Selection
        vlan_group = QGroupBox("VLAN")
        vlan_layout = QVBoxLayout()
        self.vlan_untagged = QRadioButton("Untagged")
        self.vlan_tagged = QRadioButton("Tagged")
        self.vlan_stacked = QRadioButton("Stacked")
        self.vlan_untagged.setChecked(True)
        vlan_layout.addWidget(self.vlan_untagged)
        vlan_layout.addWidget(self.vlan_tagged)
        vlan_layout.addWidget(self.vlan_stacked)
        vlan_group.setLayout(vlan_layout)
        simple_layout.addWidget(vlan_group, 0, 1)

        # L2 Selection
        l2_group = QGroupBox("L2")
        l2_layout = QVBoxLayout()
        self.l2_none = QRadioButton("None")
        self.l2_ethernet = QRadioButton("Ethernet II")
        self.l2_none.setChecked(True)
        l2_layout.addWidget(self.l2_none)
        l2_layout.addWidget(self.l2_ethernet)
        l2_group.setLayout(l2_layout)
        simple_layout.addWidget(l2_group, 0, 2)

        # L3 Selection
        l3_group = QGroupBox("L3")
        l3_layout = QVBoxLayout()
        self.l3_none = QRadioButton("None")
        self.l3_arp = QRadioButton("ARP")
        self.l3_ipv4 = QRadioButton("IPv4")
        self.l3_ipv6 = QRadioButton("IPv6")
        self.l3_none.setChecked(True)
        l3_layout.addWidget(self.l3_none)
        l3_layout.addWidget(self.l3_arp)
        l3_layout.addWidget(self.l3_ipv4)
        l3_layout.addWidget(self.l3_ipv6)
        l3_group.setLayout(l3_layout)
        simple_layout.addWidget(l3_group, 1, 0)

        # L4 Selection
        l4_group = QGroupBox("L4")
        l4_layout = QVBoxLayout()
        self.l4_none = QRadioButton("None")
        self.l4_icmp = QRadioButton("ICMP")
        self.l4_igmp = QRadioButton("IGMP")
        self.l4_tcp = QRadioButton("TCP")
        self.l4_udp = QRadioButton("UDP")
        self.l4_rocev2 = QRadioButton("RoCEv2")
        self.l4_none.setChecked(True)
        l4_layout.addWidget(self.l4_none)
        l4_layout.addWidget(self.l4_icmp)
        l4_layout.addWidget(self.l4_igmp)
        l4_layout.addWidget(self.l4_tcp)
        l4_layout.addWidget(self.l4_udp)
        l4_layout.addWidget(self.l4_rocev2)
        l4_group.setLayout(l4_layout)
        simple_layout.addWidget(l4_group, 1, 1)
        # Payload Section
        payload_group = QGroupBox("Payload")
        payload_layout = QVBoxLayout()
        self.payload_none = QRadioButton("None")
        self.payload_pattern = QRadioButton("Pattern")
        self.payload_hex = QRadioButton("Hex Dump")
        self.payload_none.setChecked(True)
        payload_layout.addWidget(self.payload_none)
        payload_layout.addWidget(self.payload_pattern)
        payload_layout.addWidget(self.payload_hex)
        payload_group.setLayout(payload_layout)
        simple_layout.addWidget(payload_group, 1, 2)
        simple_group.setLayout(simple_layout)
        self.protocol_tab_layout.addWidget(simple_group)
        # Add Stretch for Bottom Alignment
        self.protocol_tab_layout.addStretch(1)

    def add_simple_section(self):
        """Adds the Simple Section to the Protocol Selection Tab."""
        simple_group = QGroupBox("Simple")
        simple_layout = QGridLayout()
        simple_layout.setContentsMargins(5, 5, 5, 5)
        simple_layout.setSpacing(5)

        # L1 Selection
        l1_group = QGroupBox("L1")
        l1_layout = QVBoxLayout()
        self.l1_none = QRadioButton("None")
        self.l1_mac = QRadioButton("MAC")
        self.l1_none.setChecked(True)
        l1_layout.addWidget(self.l1_none)
        l1_layout.addWidget(self.l1_mac)
        l1_group.setLayout(l1_layout)
        simple_layout.addWidget(l1_group, 0, 0)

        # VLAN Selection
        vlan_group = QGroupBox("VLAN")
        vlan_layout = QVBoxLayout()
        self.vlan_untagged = QRadioButton("Untagged")
        self.vlan_tagged = QRadioButton("Tagged")
        self.vlan_stacked = QRadioButton("Stacked")
        self.vlan_untagged.setChecked(True)
        vlan_layout.addWidget(self.vlan_untagged)
        vlan_layout.addWidget(self.vlan_tagged)
        vlan_layout.addWidget(self.vlan_stacked)
        vlan_group.setLayout(vlan_layout)
        simple_layout.addWidget(vlan_group, 0, 1)

        # Add additional sections similarly...

        simple_group.setLayout(simple_layout)
        self.protocol_tab_layout.addWidget(simple_group)

    def setup_protocol_data_tab(self):
        """Sets up the Protocol Data Tab."""
        self.add_mac_section()
        self.add_vlan_section()
        self.add_ipv4_section()
        self.add_tcp_section()
        self.add_payload_data_section()
        self.add_rocev2_section()



    def populate_stream_fields(self, stream_data=None):
        """Populates the dialog fields with the existing stream data or default values."""
        if not stream_data:
            stream_data = {}
        print(f"**** Populating fields with: {stream_data}")  # Debugging

        # Basics Section
        self.stream_name.setText(stream_data.get("name", ""))
        self.enabled_checkbox.setChecked(stream_data.get("enabled", False))
        self.details_field.setText(stream_data.get("details", ""))

        # Frame Length Section
        self.frame_type.setCurrentText(stream_data.get("frame_type", "Fixed"))
        self.frame_min.setText(stream_data.get("frame_min", "64"))
        self.frame_max.setText(stream_data.get("frame_max", "1518"))
        self.frame_size.setText(stream_data.get("frame_size", "64"))

        # L1 Section
        l1_value = stream_data.get("L1", "None")
        self.l1_none.setChecked(l1_value == "None")
        self.l1_mac.setChecked(l1_value == "MAC")

        # VLAN Section
        vlan_value = stream_data.get("VLAN", "Untagged")
        self.vlan_tagged.setChecked(vlan_value == "Tagged")
        self.vlan_stacked.setChecked(vlan_value == "Stacked")
        self.vlan_untagged.setChecked(vlan_value == "Untagged")

        vlan_increment = stream_data.get("vlan_increment", False)
        self.vlan_increment_checkbox.setChecked(vlan_increment)
        self.vlan_increment_value.setText(stream_data.get("vlan_increment_value", "1"))
        self.vlan_increment_count.setText(stream_data.get("vlan_increment_count", "1"))
        self.vlan_increment_value.setEnabled(vlan_increment)
        self.vlan_increment_count.setEnabled(vlan_increment)
        self.priority_field.setCurrentText(stream_data.get("vlan_priority", "0"))
        self.cfi_dei_field.setCurrentText(stream_data.get("vlan_cfi_dei", "0"))
        self.vlan_id_field.setText(stream_data.get("vlan_id", "1"))
        self.tpid_field.setText(stream_data.get("vlan_tpid", "81 00"))
        self.override_tpid_checkbox.setChecked(stream_data.get("override_vlan_tpid", False))
        self.tpid_field.setEnabled(self.override_tpid_checkbox.isChecked())

        # L2 Section
        l2_value = stream_data.get("L2", "None")
        self.l2_none.setChecked(l2_value == "None")
        self.l2_ethernet.setChecked(l2_value == "Ethernet II")

        # L3 Section
        l3_value = stream_data.get("L3", "None")
        self.l3_none.setChecked(l3_value == "None")
        self.l3_arp.setChecked(l3_value == "ARP")
        self.l3_ipv4.setChecked(l3_value == "IPv4")
        self.l3_ipv6.setChecked(l3_value == "IPv6")

        # L4 Section
        l4_value = stream_data.get("L4", "None")
        self.l4_none.setChecked(l4_value == "None")
        self.l4_icmp.setChecked(l4_value == "ICMP")
        self.l4_igmp.setChecked(l4_value == "IGMP")
        self.l4_tcp.setChecked(l4_value == "TCP")
        self.l4_udp.setChecked(l4_value == "UDP")
        self.l4_rocev2.setChecked(l4_value == "RoCEv2")

        # Populate TCP Flags if L4 is TCP

        tcp_flags = stream_data.get("tcp_flags", "")
        flags = [flag.strip() for flag in tcp_flags.split(",")] if tcp_flags else []
        for flag, widget in [
            ("URG", self.flag_urg),
            ("ACK", self.flag_ack),
            ("PSH", self.flag_psh),
            ("RST", self.flag_rst),
            ("SYN", self.flag_syn),
            ("FIN", self.flag_fin),
        ]:
            widget.setChecked(flag in flags)
        # Populate RoCEv2 Fields if L4 is RoCEv2
        print("Populating RoCEv2 fields...")
        self.rocev2_traffic_class.setCurrentText(stream_data.get("rocev2_traffic_class", "0"))
        self.rocev2_flow_label.setText(stream_data.get("rocev2_flow_label", "000000"))
        self.rocev2_source_gid.setText(stream_data.get("rocev2_source_gid", "0:0:0:0:0:ffff:192.168.1.1"))
        self.rocev2_destination_gid.setText(stream_data.get("rocev2_destination_gid", "0:0:0:0:0:ffff:192.168.1.2"))
        self.rocev2_source_qp.setText(stream_data.get("rocev2_source_qp", "0"))
        self.rocev2_destination_qp.setText(stream_data.get("rocev2_destination_qp", "0"))

        # Payload Section
        payload_value = stream_data.get("Payload", "None")
        self.payload_none.setChecked(payload_value == "None")
        self.payload_pattern.setChecked(payload_value == "Pattern")
        self.payload_hex.setChecked(payload_value == "Hex Dump")

        # MAC Section
        # Populate MAC Destination Fields
        self.mac_destination_mode.setCurrentText(stream_data.get("mac_destination_mode", "Fixed"))
        self.mac_destination_address.setText(stream_data.get("mac_destination_address", "00:00:00:00:00:00"))
        self.mac_destination_count.setText(stream_data.get("mac_destination_count", "1"))
        self.mac_destination_step.setText(stream_data.get("mac_destination_step", "1"))
        self.toggle_mac_fields(
            mode=self.mac_destination_mode.currentText(),
            count_field=self.mac_destination_count,
            step_field=self.mac_destination_step,
        )

        # Populate MAC Source Fields
        self.mac_source_mode.setCurrentText(stream_data.get("mac_source_mode", "Fixed"))
        self.mac_source_address.setText(stream_data.get("mac_source_address", "00:00:00:00:00:00"))
        self.mac_source_count.setText(stream_data.get("mac_source_count", "1"))
        self.mac_source_step.setText(stream_data.get("mac_source_step", "1"))
        self.toggle_mac_fields(
            mode=self.mac_source_mode.currentText(),
            count_field=self.mac_source_count,
            step_field=self.mac_source_step,
        )

        # IPv4 Section
        self.source_field.setText(stream_data.get("ipv4_source", "0.0.0.0"))
        self.destination_field.setText(stream_data.get("ipv4_destination", "0.0.0.0"))
        self.ttl_field.setText(stream_data.get("ipv4_ttl", "64"))
        self.identification_field.setText(stream_data.get("ipv4_identification", "0000"))
        self.source_mode_dropdown.setCurrentText(stream_data.get("ipv4_source_mode", "Fixed"))
        self.destination_mode_dropdown.setCurrentText(stream_data.get("ipv4_destination_mode", "Fixed"))

        # IPv4 Increment
        self.increment_source_checkbox.setChecked(stream_data.get("ipv4_increment_source", False))
        self.source_increment_step.setText(stream_data.get("ipv4_source_increment_step", "1"))
        self.source_increment_count.setText(stream_data.get("ipv4_source_increment_count", "1"))
        self.source_increment_step.setEnabled(self.increment_source_checkbox.isChecked())
        self.source_increment_count.setEnabled(self.increment_source_checkbox.isChecked())

        self.increment_destination_checkbox.setChecked(stream_data.get("ipv4_increment_destination", False))
        self.destination_increment_step.setText(stream_data.get("ipv4_destination_increment_step", "1"))
        self.destination_increment_count.setText(stream_data.get("ipv4_destination_increment_count", "1"))
        self.destination_increment_step.setEnabled(self.increment_destination_checkbox.isChecked())
        self.destination_increment_count.setEnabled(self.increment_destination_checkbox.isChecked())
        self.df_checkbox.setChecked(stream_data.get("ipv4_df", False))
        self.mf_checkbox.setChecked(stream_data.get("ipv4_mf", False))
        self.fragment_offset_field.setText(stream_data.get("ipv4_fragment_offset", "0"))

        # TOS/DSCP/Custom
        tos_dscp_mode = stream_data.get("tos_dscp_mode", "TOS")
        self.tos_dscp_custom_mode.setCurrentText(tos_dscp_mode)
        if tos_dscp_mode == "TOS":
            self.tos_dropdown.setCurrentText(stream_data.get("ipv4_tos", "Routine"))
        elif tos_dscp_mode == "DSCP":
            self.dscp_dropdown.setCurrentText(stream_data.get("ipv4_dscp", "cs0"))
            self.ecn_dropdown.setCurrentText(stream_data.get("ipv4_ecn", "Not-ECT"))
        elif tos_dscp_mode == "Custom":
            self.custom_tos_field.setText(stream_data.get("ipv4_custom_tos", ""))

        # TCP Section
        self.source_port_field.setText(stream_data.get("tcp_source_port", "0"))
        self.destination_port_field.setText(stream_data.get("tcp_destination_port", "0"))
        self.window_field.setText(stream_data.get("tcp_window", "1024"))
        self.tcp_checksum_field.setText(stream_data.get("tcp_checksum", ""))
        self.override_source_port_checkbox.setChecked(stream_data.get("override_source_tcp_port", False))
        self.source_port_field.setEnabled(self.override_source_port_checkbox.isChecked())
        self.override_destination_port_checkbox.setChecked(stream_data.get("override_destination_tcp_port", False))
        self.destination_port_field.setEnabled(self.override_destination_port_checkbox.isChecked())
        self.increment_tcp_source_checkbox.setChecked(stream_data.get("tcp_increment_source_port", False))
        self.tcp_source_increment_step.setText(stream_data.get("tcp_source_port_step", "1"))
        self.tcp_source_increment_count.setText(stream_data.get("tcp_source_port_count", "1"))
        self.increment_tcp_destination_checkbox.setChecked(stream_data.get("tcp_increment_destination_port", False))
        self.tcp_destination_increment_step.setText(stream_data.get("tcp_destination_port_step", "1"))
        self.tcp_destination_increment_count.setText(stream_data.get("tcp_destination_port_count", "1"))

        # Payload Data
        self.payload_data_field.setText(stream_data.get("payload_data", ""))

        # Stream Rate Section
        self.rate_type_dropdown.setCurrentText(stream_data.get("stream_rate_type", "Packets Per Second (PPS)"))
        self.stream_pps_rate.setText(stream_data.get("stream_pps_rate", "1000"))
        self.stream_bit_rate.setText(stream_data.get("stream_bit_rate", "100"))
        self.stream_load_percentage.setText(stream_data.get("stream_load_percentage", "50"))

        # Stream Duration Section
        duration_mode = stream_data.get("stream_duration_mode", "Continuous")
        self.duration_mode_dropdown.setCurrentText(duration_mode)

        if duration_mode == "Seconds":
            duration_value = stream_data.get("stream_duration_seconds", "10")
            self.stream_duration_field.setText(str(duration_value))
        else:
            self.stream_duration_field.clear()

        print("**** Finished populating fields.")  # Debugging end

    def toggle_mac_fields(self, mode, count_field, step_field):
        """
        Enables or disables count and step fields for MAC based on the selected mode.
        Sets default values for Fixed mode.
        """
        if mode == "Fixed":
            count_field.setText("1")
            step_field.setText("1")
            count_field.setDisabled(True)
            step_field.setDisabled(True)
        else:
            count_field.setEnabled(True)
            step_field.setEnabled(True)
    def add_mac_section(self):
        """Adds the MAC section to the Protocol Data tab."""
        mac_group = QGroupBox("MAC (Media Access Protocol)")
        mac_layout = QGridLayout()
        # Destination MAC Address
        mac_layout.addWidget(QLabel("Destination"), 0, 0)
        self.mac_destination_mode = QComboBox()
        self.mac_destination_mode.addItems(["Fixed", "Increment", "Decrement"])
        self.mac_destination_address = QLineEdit("00:00:00:00:00:00")
        self.mac_destination_count = QLineEdit("16")
        self.mac_destination_step = QLineEdit("1")

        mac_layout.addWidget(self.mac_destination_mode, 0, 1)
        mac_layout.addWidget(self.mac_destination_address, 0, 2)
        mac_layout.addWidget(QLabel("Count"), 0, 3)
        mac_layout.addWidget(self.mac_destination_count, 0, 4)
        mac_layout.addWidget(QLabel("Step"), 0, 5)
        mac_layout.addWidget(self.mac_destination_step, 0, 6)

        # Connect mode dropdown to toggle_mac_fields
        self.mac_destination_mode.currentTextChanged.connect(
            lambda mode: self.toggle_mac_fields(
                mode, self.mac_destination_count, self.mac_destination_step
            )
        )

        # Source MAC Address
        mac_layout.addWidget(QLabel("Source"), 1, 0)
        self.mac_source_mode = QComboBox()
        self.mac_source_mode.addItems(["Fixed", "Increment", "Decrement", "Resolve"])
        self.mac_source_address = QLineEdit("00:00:00:00:00:00")
        self.mac_source_count = QLineEdit("16")
        self.mac_source_step = QLineEdit("1")

        mac_layout.addWidget(self.mac_source_mode, 1, 1)
        mac_layout.addWidget(self.mac_source_address, 1, 2)
        mac_layout.addWidget(QLabel("Count"), 1, 3)
        mac_layout.addWidget(self.mac_source_count, 1, 4)
        mac_layout.addWidget(QLabel("Step"), 1, 5)
        mac_layout.addWidget(self.mac_source_step, 1, 6)

        # Connect mode dropdown to toggle_mac_fields
        self.mac_source_mode.currentTextChanged.connect(
            lambda mode: self.toggle_mac_fields(
                mode, self.mac_source_count, self.mac_source_step
            )
        )

        # Information Label
        mac_info_label = QLabel(
            "Please ensure that a corresponding device is configured on the port to enable "
            "source/destination MAC address resolution. A corresponding device is one which "
            "has VLANs and source/gateway IP corresponding to this stream."
        )
        mac_info_label.setWordWrap(True)
        mac_layout.addWidget(mac_info_label, 2, 0, 1, 7)

        mac_group.setLayout(mac_layout)
        self.protocol_data_layout.addWidget(mac_group)



    def add_vlan_section(self):
        """Adds the VLAN section to the Protocol Data tab."""
        vlan_group = QGroupBox("VLAN")
        vlan_layout = QGridLayout()

        # VLAN ID, Priority, CFI/DEI, and Override TPID in the same row
        vlan_layout.addWidget(QLabel("VLAN ID"), 0, 0)
        self.vlan_id_field = QLineEdit("10")
        vlan_layout.addWidget(self.vlan_id_field, 0, 1)

        vlan_layout.addWidget(QLabel("Priority"), 0, 2)
        self.priority_field = QComboBox()
        self.priority_field.addItems([str(i) for i in range(8)])
        vlan_layout.addWidget(self.priority_field, 0, 3)

        vlan_layout.addWidget(QLabel("CFI/DEI"), 0, 4)
        self.cfi_dei_field = QComboBox()
        self.cfi_dei_field.addItems(["0", "1"])
        vlan_layout.addWidget(self.cfi_dei_field, 0, 5)

        self.override_tpid_checkbox = QCheckBox("Override TPID")
        vlan_layout.addWidget(self.override_tpid_checkbox, 0, 6)

        self.tpid_field = QLineEdit("81 00")
        self.tpid_field.setDisabled(True)
        vlan_layout.addWidget(self.tpid_field, 0, 7)

        # Connect checkbox to enable/disable TPID field
        self.override_tpid_checkbox.toggled.connect(
            lambda checked: self.tpid_field.setEnabled(checked)
        )

        # Increment VLAN Option
        self.vlan_increment_checkbox = QCheckBox("Increment VLAN")
        vlan_layout.addWidget(self.vlan_increment_checkbox, 1, 0)

        self.vlan_increment_value = QLineEdit("1")
        self.vlan_increment_value.setValidator(QIntValidator(1, 4094))
        self.vlan_increment_value.setDisabled(True)
        vlan_layout.addWidget(QLabel("Increment Value"), 1, 1)
        vlan_layout.addWidget(self.vlan_increment_value, 1, 2)

        self.vlan_increment_count = QLineEdit("1")
        self.vlan_increment_count.setValidator(QIntValidator(1, 4094))
        self.vlan_increment_count.setDisabled(True)
        vlan_layout.addWidget(QLabel("Increment Count"), 1, 3)
        vlan_layout.addWidget(self.vlan_increment_count, 1, 4)

        # Enable increment fields only when the checkbox is checked
        self.vlan_increment_checkbox.toggled.connect(
            lambda checked: [
                self.vlan_increment_value.setEnabled(checked),
                self.vlan_increment_count.setEnabled(checked),
            ]
        )

        vlan_group.setLayout(vlan_layout)
        self.protocol_data_layout.addWidget(vlan_group)

    def add_ipv4_section(self):
        """Adds the IPv4 section to the Protocol Data tab."""
        ipv4_group = QGroupBox("Internet Protocol ver 4")
        ipv4_layout = QGridLayout()

        # Source IP Section
        ipv4_layout.addWidget(QLabel("Source IP"), 0, 0)
        self.source_field = QLineEdit("0.0.0.0")
        ipv4_layout.addWidget(self.source_field, 0, 1)

        self.source_mode_dropdown = QComboBox()
        self.source_mode_dropdown.addItems(["Fixed", "Increment"])
        ipv4_layout.addWidget(self.source_mode_dropdown, 0, 2)

        self.increment_source_checkbox = QCheckBox("Increment Source")
        ipv4_layout.addWidget(self.increment_source_checkbox, 0, 3)

        self.source_increment_step = QLineEdit("1")
        self.source_increment_step.setValidator(QIntValidator(1, 255))
        self.source_increment_step.setDisabled(True)
        ipv4_layout.addWidget(QLabel("Step"), 0, 4)
        ipv4_layout.addWidget(self.source_increment_step, 0, 5)

        self.source_increment_count = QLineEdit("1")
        self.source_increment_count.setValidator(QIntValidator(1, 255))
        self.source_increment_count.setDisabled(True)
        ipv4_layout.addWidget(QLabel("Count"), 0, 6)
        ipv4_layout.addWidget(self.source_increment_count, 0, 7)

        # Enable/disable increment fields based on checkbox
        self.increment_source_checkbox.toggled.connect(
            lambda checked: [
                self.source_increment_step.setEnabled(checked),
                self.source_increment_count.setEnabled(checked),
            ]
        )

        # Destination IP Section
        ipv4_layout.addWidget(QLabel("Destination IP"), 1, 0)
        self.destination_field = QLineEdit("0.0.0.0")
        ipv4_layout.addWidget(self.destination_field, 1, 1)

        self.destination_mode_dropdown = QComboBox()
        self.destination_mode_dropdown.addItems(["Fixed", "Increment"])
        ipv4_layout.addWidget(self.destination_mode_dropdown, 1, 2)

        self.increment_destination_checkbox = QCheckBox("Increment Destination")
        ipv4_layout.addWidget(self.increment_destination_checkbox, 1, 3)

        self.destination_increment_step = QLineEdit("1")
        self.destination_increment_step.setValidator(QIntValidator(1, 255))
        self.destination_increment_step.setDisabled(True)
        ipv4_layout.addWidget(QLabel("Step"), 1, 4)
        ipv4_layout.addWidget(self.destination_increment_step, 1, 5)

        self.destination_increment_count = QLineEdit("1")
        self.destination_increment_count.setValidator(QIntValidator(1, 255))
        self.destination_increment_count.setDisabled(True)
        ipv4_layout.addWidget(QLabel("Count"), 1, 6)
        ipv4_layout.addWidget(self.destination_increment_count, 1, 7)

        # Enable/disable increment fields based on checkbox
        self.increment_destination_checkbox.toggled.connect(
            lambda checked: [
                self.destination_increment_step.setEnabled(checked),
                self.destination_increment_count.setEnabled(checked),
            ]
        )

        # Time to Live (TTL) and Identification
        ipv4_layout.addWidget(QLabel("Time To Live (TTL)"), 2, 0)
        self.ttl_field = QLineEdit("64")
        self.ttl_field.setValidator(QIntValidator(1, 255))
        ipv4_layout.addWidget(self.ttl_field, 2, 1)

        ipv4_layout.addWidget(QLabel("Identification"), 2, 2)
        self.identification_field = QLineEdit("0000")
        self.identification_field.setValidator(QIntValidator(0, 65535))
        ipv4_layout.addWidget(self.identification_field, 2, 3)

        # Flags Section
        self.df_checkbox = QCheckBox("Don't Fragment (DF)")
        self.mf_checkbox = QCheckBox("More Fragments (MF)")
        ipv4_layout.addWidget(self.df_checkbox, 3, 0)
        ipv4_layout.addWidget(self.mf_checkbox, 3, 1)

        ipv4_layout.addWidget(QLabel("Fragment Offset"), 3, 2)
        self.fragment_offset_field = QLineEdit("0")
        self.fragment_offset_field.setValidator(QIntValidator(0, 8191))  # 13-bit field
        ipv4_layout.addWidget(self.fragment_offset_field, 3, 3)

        # TOS/DSCP/Custom Section
        self.tos_dscp_custom_mode = QComboBox()
        self.tos_dscp_custom_mode.addItems(["TOS", "DSCP", "Custom"])
        ipv4_layout.addWidget(self.tos_dscp_custom_mode, 4, 0)

        self.tos_dscp_custom_stack = QStackedWidget()
        ipv4_layout.addWidget(self.tos_dscp_custom_stack, 4, 1, 1, 6)  # Spanning columns 1 to 6

        # TOS Widget
        tos_widget = QWidget()
        tos_layout = QHBoxLayout(tos_widget)
        self.tos_dropdown = QComboBox()
        self.tos_dropdown.addItems(
            ["Routine", "Priority", "Immediate", "Flash", "Flash Override", "Critical", "Internetwork Control",
             "Network Control"])
        tos_layout.addWidget(self.tos_dropdown)

        # DSCP Widget
        dscp_widget = QWidget()
        dscp_layout = QHBoxLayout(dscp_widget)
        self.dscp_dropdown = QComboBox()
        self.dscp_dropdown.addItems([
            "cs0", "cs1", "cs2", "cs3", "cs4", "cs5", "cs6", "cs7",
            "af11", "af12", "af13", "af21", "af22", "af23",
            "af31", "af32", "af33", "af41", "af42", "af43", "ef"
        ])
        dscp_layout.addWidget(self.dscp_dropdown)
        self.ecn_dropdown = QComboBox()
        self.ecn_dropdown.addItems(["CE", "Not-ECT", "ECT(1)", "ECT(0)"])
        dscp_layout.addWidget(self.ecn_dropdown)

        # Custom Widget
        custom_widget = QWidget()
        custom_layout = QHBoxLayout(custom_widget)
        self.custom_tos_field = QLineEdit("")
        self.custom_tos_field.setPlaceholderText("Custom")
        custom_layout.addWidget(self.custom_tos_field)

        # Add Widgets to QStackedWidget
        self.tos_dscp_custom_stack.addWidget(tos_widget)
        self.tos_dscp_custom_stack.addWidget(dscp_widget)
        self.tos_dscp_custom_stack.addWidget(custom_widget)

        # Update QStackedWidget based on dropdown selection
        self.tos_dscp_custom_mode.currentIndexChanged.connect(
            lambda index: self.tos_dscp_custom_stack.setCurrentIndex(index)
        )

        # Add IPv4 group to layout
        ipv4_group.setLayout(ipv4_layout)
        self.protocol_data_layout.addWidget(ipv4_group)



    def add_tcp_section(self):
        """Adds the TCP section to the Protocol Data tab."""

        def validate_32bit_unsigned(field):
            """
            Validates if the text in the given field is a 32-bit unsigned integer.
            If the value is invalid, it resets the field to 0.
            """
            try:
                value = int(field.text())
                if not (0 <= value <= 4294967295):
                    raise ValueError
            except ValueError:
                field.setText("0")

        tcp_group = QGroupBox("Transmission Control Protocol (stateless)")
        tcp_layout = QGridLayout()

        # Override Source Port
        self.override_source_port_checkbox = QCheckBox("Override Source Port")
        tcp_layout.addWidget(self.override_source_port_checkbox, 0, 0)

        self.source_port_field = QLineEdit("0")
        self.source_port_field.setValidator(QIntValidator(0, 65535))
        self.source_port_field.setDisabled(True)  # Initially disabled
        tcp_layout.addWidget(self.source_port_field, 0, 1)

        # Connect checkbox to enable/disable source port field
        self.override_source_port_checkbox.toggled.connect(
            lambda checked: self.source_port_field.setEnabled(checked)
        )

        # Increment Source Port
        self.increment_tcp_source_checkbox = QCheckBox("Increment Source Port")
        tcp_layout.addWidget(self.increment_tcp_source_checkbox, 0, 2)

        self.tcp_source_increment_step = QLineEdit("1")
        self.tcp_source_increment_step.setValidator(QIntValidator(1, 65535))
        self.tcp_source_increment_step.setDisabled(True)
        tcp_layout.addWidget(QLabel("Step"), 0, 3)
        tcp_layout.addWidget(self.tcp_source_increment_step, 0, 4)

        self.tcp_source_increment_count = QLineEdit("1")
        self.tcp_source_increment_count.setValidator(QIntValidator(1, 65535))
        self.tcp_source_increment_count.setDisabled(True)
        tcp_layout.addWidget(QLabel("Count"), 0, 5)
        tcp_layout.addWidget(self.tcp_source_increment_count, 0, 6)

        # Enable/disable fields based on increment checkbox
        self.increment_tcp_source_checkbox.toggled.connect(
            lambda checked: [
                self.tcp_source_increment_step.setEnabled(checked),
                self.tcp_source_increment_count.setEnabled(checked),
            ]
        )

        # Override Destination Port
        self.override_destination_port_checkbox = QCheckBox("Override Destination Port")
        tcp_layout.addWidget(self.override_destination_port_checkbox, 1, 0)

        self.destination_port_field = QLineEdit("0")
        self.destination_port_field.setValidator(QIntValidator(0, 65535))
        self.destination_port_field.setDisabled(True)  # Initially disabled
        tcp_layout.addWidget(self.destination_port_field, 1, 1)

        # Connect checkbox to enable/disable destination port field
        self.override_destination_port_checkbox.toggled.connect(
            lambda checked: self.destination_port_field.setEnabled(checked)
        )

        # Increment Destination Port
        self.increment_tcp_destination_checkbox = QCheckBox("Increment Destination Port")
        tcp_layout.addWidget(self.increment_tcp_destination_checkbox, 1, 2)

        self.tcp_destination_increment_step = QLineEdit("1")
        self.tcp_destination_increment_step.setValidator(QIntValidator(1, 65535))
        self.tcp_destination_increment_step.setDisabled(True)
        tcp_layout.addWidget(QLabel("Step"), 1, 3)
        tcp_layout.addWidget(self.tcp_destination_increment_step, 1, 4)

        self.tcp_destination_increment_count = QLineEdit("1")
        self.tcp_destination_increment_count.setValidator(QIntValidator(1, 65535))
        self.tcp_destination_increment_count.setDisabled(True)
        tcp_layout.addWidget(QLabel("Count"), 1, 5)
        tcp_layout.addWidget(self.tcp_destination_increment_count, 1, 6)

        # Enable/disable fields based on increment checkbox
        self.increment_tcp_destination_checkbox.toggled.connect(
            lambda checked: [
                self.tcp_destination_increment_step.setEnabled(checked),
                self.tcp_destination_increment_count.setEnabled(checked),
            ]
        )

        # Sequence Number
        tcp_layout.addWidget(QLabel("Sequence Number"), 2, 0)
        self.sequence_number_field = QLineEdit("129018")
        tcp_layout.addWidget(self.sequence_number_field, 2, 1)
        self.sequence_number_field.editingFinished.connect(
            lambda: validate_32bit_unsigned(self.sequence_number_field)
        )

        # Acknowledgement Number
        tcp_layout.addWidget(QLabel("Acknowledgement Number"), 2, 2)
        self.acknowledgement_number_field = QLineEdit("0")
        tcp_layout.addWidget(self.acknowledgement_number_field, 2, 3)
        self.acknowledgement_number_field.editingFinished.connect(
            lambda: validate_32bit_unsigned(self.acknowledgement_number_field)
        )

        # Window
        tcp_layout.addWidget(QLabel("Window"), 3, 0)
        self.window_field = QLineEdit("1024")
        self.window_field.setValidator(QIntValidator(1, 65535))
        tcp_layout.addWidget(self.window_field, 3, 1)

        # Override Checksum
        self.override_checksum_checkbox = QCheckBox("Override Checksum")
        tcp_layout.addWidget(self.override_checksum_checkbox, 3, 2)

        self.tcp_checksum_field = QLineEdit("B3 E7")
        self.tcp_checksum_field.setDisabled(True)
        tcp_layout.addWidget(self.tcp_checksum_field, 3, 3)

        # Connect checkbox to enable/disable checksum field
        self.override_checksum_checkbox.toggled.connect(
            lambda checked: self.tcp_checksum_field.setEnabled(checked)
        )

        # Flags Section
        flags_group = QGroupBox("Flags")
        flags_layout = QGridLayout()
        self.flag_urg = QCheckBox("URG")
        self.flag_ack = QCheckBox("ACK")
        self.flag_psh = QCheckBox("PSH")
        self.flag_rst = QCheckBox("RST")
        self.flag_syn = QCheckBox("SYN")
        self.flag_fin = QCheckBox("FIN")
        flags_layout.addWidget(self.flag_urg, 0, 0)
        flags_layout.addWidget(self.flag_ack, 0, 1)
        flags_layout.addWidget(self.flag_psh, 0, 2)
        flags_layout.addWidget(self.flag_rst, 1, 0)
        flags_layout.addWidget(self.flag_syn, 1, 1)
        flags_layout.addWidget(self.flag_fin, 1, 2)
        flags_group.setLayout(flags_layout)
        tcp_layout.addWidget(flags_group, 4, 0, 1, 6)
        tcp_group.setLayout(tcp_layout)
        self.protocol_data_layout.addWidget(tcp_group)

    def add_rocev2_section(self):
        """Adds the RoCEv2 section to the Protocol Data tab."""
        rocev2_group = QGroupBox("RoCEv2 (RDMA over Converged Ethernet v2)")
        rocev2_layout = QGridLayout()

        # Traffic Class
        rocev2_layout.addWidget(QLabel("Traffic Class"), 0, 0)
        self.rocev2_traffic_class = QComboBox()
        self.rocev2_traffic_class.addItems([str(i) for i in range(8)])  # Traffic class 0-7
        rocev2_layout.addWidget(self.rocev2_traffic_class, 0, 1)

        # Flow Label
        rocev2_layout.addWidget(QLabel("Flow Label"), 0, 2)
        self.rocev2_flow_label = QLineEdit("000000")
        self.rocev2_flow_label.setMaxLength(6)  # Limit to 6 hex digits
        rocev2_layout.addWidget(self.rocev2_flow_label, 0, 3)

        # Source QP
        rocev2_layout.addWidget(QLabel("Source QP"), 0, 4)
        self.rocev2_source_qp = QLineEdit("0")
        self.rocev2_source_qp.setValidator(Unsigned32BitValidator())
        rocev2_layout.addWidget(self.rocev2_source_qp, 0, 5)

        # Destination QP
        rocev2_layout.addWidget(QLabel("Destination QP"), 0, 6)
        self.rocev2_destination_qp = QLineEdit("0")
        self.rocev2_destination_qp.setValidator(Unsigned32BitValidator())
        rocev2_layout.addWidget(self.rocev2_destination_qp, 0, 7)

        # Source GID
        rocev2_layout.addWidget(QLabel("Source GID"), 1, 0)
        self.rocev2_source_gid = QLineEdit("0:0:0:0:0:ffff:192.168.1.1")
        rocev2_layout.addWidget(self.rocev2_source_gid, 1, 1, 1, 3)  # Span 3 columns

        # Destination GID
        rocev2_layout.addWidget(QLabel("Destination GID"), 1, 4)
        self.rocev2_destination_gid = QLineEdit("0:0:0:0:0:ffff:192.168.1.2")
        rocev2_layout.addWidget(self.rocev2_destination_gid, 1, 5, 1, 3)  # Span 3 columns

        rocev2_group.setLayout(rocev2_layout)
        self.protocol_data_layout.addWidget(rocev2_group)

    def add_payload_data_section(self):
        """Adds the Payload Data section to the Protocol Data tab."""
        payload_group = QGroupBox("Payload Data")
        payload_layout = QVBoxLayout()

        self.payload_data_field = QLineEdit("0000")
        payload_layout.addWidget(QLabel("Data:"))
        payload_layout.addWidget(self.payload_data_field)

        payload_group.setLayout(payload_layout)
        self.protocol_data_layout.addWidget(payload_group)

    def setup_packet_view_tab(self):
        """Sets up the Packet View Tab."""
        self.packet_tree = QTreeWidget()
        self.packet_tree.setHeaderLabels(["Protocol Layer", "Configuration Details"])
        self.packet_view_layout.addWidget(self.packet_tree)
        # Populate Packet View only when the Packet View tab is selected
        self.tabs.currentChanged.connect(self.handle_tab_changed)

    def handle_tab_changed(self, index):
        """Handles tab change events."""
        if self.tabs.tabText(index) == "Packet View":
            # Fetch the current stream data
            stream_data = self.get_stream_details()
            self.populate_packet_view(stream_data)

    def generate_protocol_data(self, stream_data):
        """
        Generate Protocol Data based on stream configuration.
        Skip sections with 'None' in protocol_selection.
        :param stream_data: Dictionary containing the stream configuration.
        :return: Filtered Protocol Data dictionary.
        """
        protocol_selection = stream_data.get("protocol_selection", {})
        protocol_data = stream_data.get("protocol_data", {})
        print(f"Protocol selection received: {protocol_selection}")  # Debug log

        # Initialize filtered protocol data
        filtered_protocol_data = {}

        # Include MAC section only if L2 is not "None"
        if protocol_selection.get("L2") and protocol_selection["L2"] != "None":
            filtered_protocol_data["mac"] = protocol_data.get("mac", {})

        # Include VLAN section only if VLAN is not "None"
        if protocol_selection.get("VLAN") and protocol_selection["VLAN"] != "None":
            filtered_protocol_data["vlan"] = protocol_data.get("vlan", {})

        # Include IPv4 section only if L3 is not "None"
        if protocol_selection.get("L3") and protocol_selection["L3"] != "None":
            filtered_protocol_data["ipv4"] = protocol_data.get("ipv4", {})

        # Include TCP section only if L4 is not "None"
        if protocol_selection.get("L4") and protocol_selection["L4"] != "None":
            filtered_protocol_data["tcp"] = protocol_data.get("tcp", {})

        # Include Payload section only if Payload is not "None"
        if protocol_selection.get("Payload") and protocol_selection["Payload"] != "None":
            filtered_protocol_data["payload_data"] = protocol_data.get("payload_data", {})

        print(f"Filtered protocol_data: {filtered_protocol_data}")  # Debug log
        return filtered_protocol_data



    def populate_packet_view(self, stream_data=None):
        """
        Populates the Packet View tab with configured Protocol Data.
        :param stream_data: Dictionary containing the stream configuration.
        """
        self.packet_tree.clear()

        # Ensure the input is valid
        if not isinstance(stream_data, dict):
            print(f"Invalid stream_data: {stream_data}. Expected a dictionary.")
            return

        # Debugging: Log the valid stream data
        print("Populating Packet View with Stream Data:", stream_data)

        # Helper function to generate incremented values
        def increment_value(base, step, count, is_ip=False):
            results = []
            for i in range(int(count)):
                if is_ip:
                    octets = list(map(int, base.split(".")))
                    octets[-1] += step * i
                    results.append(".".join(map(str, octets)))
                else:
                    results.append(str(int(base) + step * i))
            return results

        # MAC Section
        if stream_data.get('L2') != 'None':
            mac_item = QTreeWidgetItem(["MAC (Media Access Protocol)"])
            mac_item.addChild(QTreeWidgetItem(
                ["Destination",
                 f"{stream_data.get('mac_destination_mode', 'None')} - {stream_data.get('mac_destination_address', '00:00:00:00:00:00')}"]
            ))
            mac_item.addChild(QTreeWidgetItem(
                ["Source",
                 f"{stream_data.get('mac_source_mode', 'None')} - {stream_data.get('mac_source_address', '00:00:00:00:00:00')}"]
            ))
            mac_item.addChild(QTreeWidgetItem(["Destination Count", stream_data.get('mac_destination_count', '1')]))
            mac_item.addChild(QTreeWidgetItem(["Destination Step", stream_data.get('mac_destination_step', '1')]))
            mac_item.addChild(QTreeWidgetItem(["Source Count", stream_data.get('mac_source_count', '1')]))
            mac_item.addChild(QTreeWidgetItem(["Source Step", stream_data.get('mac_source_step', '1')]))
            self.packet_tree.addTopLevelItem(mac_item)

        # Helper function to generate incremented values within range
        from PyQt5.QtWidgets import QMessageBox

        def increment_value(base, step, count, is_ip=False, range_min=None, range_max=None, parent=None):
            results = []
            try:
                if is_ip:
                    # Validate base IP address
                    octets = list(map(int, base.split(".")))
                    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
                        raise ValueError(f"Invalid IP address: {base}")

                    for i in range(int(count)):
                        incremented_octets = octets[:]
                        incremented_octets[-1] += step * i
                        for j in range(3, -1, -1):  # Handle overflow (e.g., 255 -> 0)
                            if incremented_octets[j] > 255:
                                incremented_octets[j] -= 256
                                if j > 0:
                                    incremented_octets[j - 1] += 1
                                else:
                                    raise ValueError(f"IP address overflow: {base}")
                        results.append(".".join(map(str, incremented_octets)))
                else:
                    # Validate numeric value range
                    try:
                        base = int(base)
                    except ValueError:
                        raise ValueError(f"Invalid numeric value: {base}")

                    if range_min is not None and base < range_min:
                        raise ValueError(f"Value below minimum range: {base}")
                    if range_max is not None and base > range_max:
                        raise ValueError(f"Value above maximum range: {base}")

                    for i in range(int(count)):
                        incremented_value = base + step * i
                        if range_min is not None and incremented_value < range_min:
                            raise ValueError(f"Value below minimum range: {incremented_value}")
                        if range_max is not None and incremented_value > range_max:
                            raise ValueError(f"Value above maximum range: {incremented_value}")
                        results.append(str(incremented_value))

            except ValueError as e:
                # Log the error and display notifications
                error_message = f"Error in increment_value: {e}"
                print(error_message)  # Console log
                QMessageBox.critical(parent, "Increment Value Error", error_message)  # Popup notification
                return []  # Return empty list on error

            return results


        # VLAN Section
        if stream_data.get('VLAN') != 'None':
            vlan_item = QTreeWidgetItem(["VLAN"])
            vlan_item.addChild(QTreeWidgetItem(["Priority", stream_data.get('vlan_priority', 'None')]))
            vlan_item.addChild(QTreeWidgetItem(["CFI/DEI", stream_data.get('vlan_cfi_dei', 'None')]))
            vlan_base = int(stream_data.get("vlan_id", 1))
            if stream_data.get("vlan_increment", False):
                vlan_step = int(stream_data.get("vlan_increment_value", 1))
                vlan_count = int(stream_data.get("vlan_increment_count", 1))
                vlan_values = increment_value(
                    base=vlan_base,
                    step=vlan_step,
                    count=vlan_count,
                    range_min=0,
                    range_max=4096,
                )
                vlan_item.addChild(QTreeWidgetItem(["VLAN ID", ", ".join(vlan_values)]))
            else:
                if 0 <= vlan_base <= 4096:
                    vlan_item.addChild(QTreeWidgetItem(["VLAN ID", str(vlan_base)]))
                else:
                    vlan_item.addChild(QTreeWidgetItem(["VLAN ID", "Invalid (Out of Range)"]))
            vlan_item.addChild(QTreeWidgetItem(["TPID", stream_data.get('vlan_tpid', '81 00')]))
            self.packet_tree.addTopLevelItem(vlan_item)

        # L3 Section
        if stream_data.get('L3') != 'None':
            l3_item = QTreeWidgetItem(["L3 (Network Layer)"])
            l3_item.addChild(QTreeWidgetItem(["Type", stream_data.get('L3', 'None')]))
            if stream_data.get("ipv4_increment_source", False):
                ip_base = stream_data.get("ipv4_source", "0.0.0.0")
                ip_step = int(stream_data.get("ipv4_source_increment_step", 1))
                ip_count = int(stream_data.get("ipv4_source_increment_count", 1))
                source_ips = increment_value(ip_base, ip_step, ip_count, is_ip=True)
                l3_item.addChild(QTreeWidgetItem(["Source", ", ".join(source_ips)]))
            else:
                l3_item.addChild(QTreeWidgetItem(["Source", stream_data.get('ipv4_source', 'None')]))

            if stream_data.get("ipv4_increment_destination", False):
                ip_base = stream_data.get("ipv4_destination", "0.0.0.0")
                ip_step = int(stream_data.get("ipv4_destination_increment_step", 1))
                ip_count = int(stream_data.get("ipv4_destination_increment_count", 1))
                destination_ips = increment_value(ip_base, ip_step, ip_count, is_ip=True)
                l3_item.addChild(QTreeWidgetItem(["Destination", ", ".join(destination_ips)]))
            else:
                l3_item.addChild(QTreeWidgetItem(["Destination", stream_data.get('ipv4_destination', 'None')]))
            l3_item.addChild(QTreeWidgetItem(["TOS", stream_data.get('ipv4_tos', 'None')]))
            l3_item.addChild(QTreeWidgetItem(["DSCP", stream_data.get('ipv4_dscp', 'None')]))
            l3_item.addChild(QTreeWidgetItem(["ECN", stream_data.get('ipv4_ecn', 'None')]))
            l3_item.addChild(QTreeWidgetItem(["TTL", stream_data.get('ipv4_ttl', 'None')]))
            l3_item.addChild(QTreeWidgetItem(["Identification", stream_data.get('ipv4_identification', 'None')]))
            self.packet_tree.addTopLevelItem(l3_item)

        # L4 Section
        if stream_data.get('L4') != 'None':
            l4_item = QTreeWidgetItem(["L4 (Transport Layer)"])
            l4_item.addChild(QTreeWidgetItem(["Type", stream_data.get('L4', 'None')]))
            if stream_data.get('L4') == "RoCEv2":
                l4_item.addChild(QTreeWidgetItem(["Traffic Class", stream_data.get("rocev2_traffic_class", "0")]))
                l4_item.addChild(QTreeWidgetItem(["Flow Label", stream_data.get("rocev2_flow_label", "000000")]))
                l4_item.addChild(
                    QTreeWidgetItem(["Source GID", stream_data.get("rocev2_source_gid", "0:0:0:0:0:ffff:192.168.1.1")]))
                l4_item.addChild(QTreeWidgetItem(
                    ["Destination GID", stream_data.get("rocev2_destination_gid", "0:0:0:0:0:ffff:192.168.1.2")]))
                l4_item.addChild(QTreeWidgetItem(["Source QP", stream_data.get("rocev2_source_qp", "0")]))
                l4_item.addChild(QTreeWidgetItem(["Destination QP", stream_data.get("rocev2_destination_qp", "0")]))
            else:
                if stream_data.get("tcp_increment_source_port", False):
                    port_base = int(stream_data.get("tcp_source_port", 0))
                    port_step = int(stream_data.get("tcp_source_port_step", 1))
                    port_count = int(stream_data.get("tcp_source_port_count", 1))
                    source_ports = increment_value(port_base, port_step, port_count)
                    l4_item.addChild(QTreeWidgetItem(["Source Port", ", ".join(source_ports)]))
                else:
                    l4_item.addChild(QTreeWidgetItem(["Source Port", stream_data.get('tcp_source_port', 'None')]))

                if stream_data.get("tcp_increment_destination_port", False):
                    port_base = int(stream_data.get("tcp_destination_port", 0))
                    port_step = int(stream_data.get("tcp_destination_port_step", 1))
                    port_count = int(stream_data.get("tcp_destination_port_count", 1))
                    destination_ports = increment_value(port_base, port_step, port_count)
                    l4_item.addChild(QTreeWidgetItem(["Destination Port", ", ".join(destination_ports)]))
                else:
                    l4_item.addChild(
                        QTreeWidgetItem(["Destination Port", stream_data.get('tcp_destination_port', 'None')]))
                l4_item.addChild(QTreeWidgetItem(["Sequence Number", stream_data.get('tcp_sequence_number', 'None')]))
                l4_item.addChild(
                    QTreeWidgetItem(["Acknowledgement Number", stream_data.get('tcp_acknowledgement_number', 'None')]))
                l4_item.addChild(QTreeWidgetItem(["Window", stream_data.get('tcp_window', 'None')]))
                l4_item.addChild(QTreeWidgetItem(["Checksum", stream_data.get('tcp_checksum', 'None')]))
                l4_item.addChild(QTreeWidgetItem(["Flags", stream_data.get('tcp_flags', 'None')]))
            self.packet_tree.addTopLevelItem(l4_item)

        # Payload Section
        if stream_data.get('Payload') != 'None':
            payload_item = QTreeWidgetItem(["Payload"])
            payload_item.addChild(QTreeWidgetItem(["Data", stream_data.get('payload_data', 'None')]))
            self.packet_tree.addTopLevelItem(payload_item)

    def connect_protocol_data_to_packet_view(self):
        """Connect Protocol Data fields to update Packet View dynamically."""

        def update_packet_view():
            # Fetch the current stream data dynamically
            stream_data = self.get_stream_details()
            self.populate_packet_view(stream_data)

        # MAC
        self.mac_destination_address.textChanged.connect(update_packet_view)
        self.mac_source_address.textChanged.connect(update_packet_view)

        # VLAN
        self.priority_field.currentIndexChanged.connect(update_packet_view)
        self.vlan_id_field.textChanged.connect(update_packet_view)

        # IPv4
        self.source_field.textChanged.connect(update_packet_view)
        self.destination_field.textChanged.connect(update_packet_view)

        # TCP
        self.source_port_field.textChanged.connect(update_packet_view)
        self.destination_port_field.textChanged.connect(update_packet_view)
        self.sequence_number_field.textChanged.connect(update_packet_view)

        # Payload
        self.payload_data_field.textChanged.connect(update_packet_view)

        # RoCEv2
        self.rocev2_traffic_class.currentIndexChanged.connect(update_packet_view)
        self.rocev2_flow_label.textChanged.connect(update_packet_view)
        self.rocev2_source_gid.textChanged.connect(update_packet_view)
        self.rocev2_destination_gid.textChanged.connect(update_packet_view)
        self.rocev2_source_qp.textChanged.connect(update_packet_view)
        self.rocev2_destination_qp.textChanged.connect(update_packet_view)

    def setup_frame_length_section(self):
        """Sets up the Frame Length section in the Protocol Data tab."""
        frame_length_group = QGroupBox("Frame Length (including FCS)")
        frame_length_layout = QGridLayout()

        self.frame_type = QComboBox()  # Initialize frame_type
        self.frame_type.addItems(["Fixed", "Random", "IMIX"])
        self.frame_min = QLineEdit("64")  # Initialize frame_min
        self.frame_max = QLineEdit("1518")  # Initialize frame_max
        self.frame_size = QLineEdit("64")  # Initialize frame_size
        self.frame_min.setValidator(QIntValidator(64, 1518))
        self.frame_max.setValidator(QIntValidator(64, 1518))
        self.frame_size.setValidator(QIntValidator(64, 1518))

        frame_length_layout.addWidget(QLabel("Frame Type:"), 0, 0)
        frame_length_layout.addWidget(self.frame_type, 0, 1)
        frame_length_layout.addWidget(QLabel("Min:"), 1, 0)
        frame_length_layout.addWidget(self.frame_min, 1, 1)
        frame_length_layout.addWidget(QLabel("Max:"), 1, 2)
        frame_length_layout.addWidget(self.frame_max, 1, 3)
        frame_length_layout.addWidget(QLabel("Fixed Size:"), 2, 0)
        frame_length_layout.addWidget(self.frame_size, 2, 1)

        frame_length_group.setLayout(frame_length_layout)
        self.protocol_data_layout.addWidget(frame_length_group)

    def generate_default_stream_name(self):
        """Generates a unique default stream name."""
        existing_stream_names = self.get_existing_stream_names()
        index = 1
        default_name = f"Stream {index}"
        while default_name in existing_stream_names:
            index += 1
            default_name = f"Stream {index}"
        return default_name

    def get_existing_stream_names(self):
        """
        Retrieves existing stream names from the parent dialog or a shared source.
        If no parent is set, return an empty list.
        """
        if self.parent() and hasattr(self.parent(), "stream_list"):
            return [stream["name"] for stream in self.parent().stream_list]
        return []  # Fallback if no parent or `stream_list`

    def get_stream_details(self):
        """Retrieve stream details entered in the dialog."""
        stream_name = self.stream_name.text().strip()
        if not stream_name:
            # Generate a default name if the user did not provide one
            stream_name = self.generate_default_stream_name()
            self.stream_name.setText(stream_name)  # Update the field for consistency
        # Rest of the method remains unchanged
        # General Stream Details
        stream_details = {
            "name": stream_name,
            "enabled": self.enabled_checkbox.isChecked(),
            "details": self.details_field.text() or "",
            "frame_type": self.frame_type.currentText() or "Fixed",
            "frame_min": self.frame_min.text() or "64",
            "frame_max": self.frame_max.text() or "1518",
            "frame_size": self.frame_size.text() or "64",
            "L1": "MAC" if self.l1_mac.isChecked() else "None",
            "VLAN": (
                "Tagged" if self.vlan_tagged.isChecked() else
                "Stacked" if self.vlan_stacked.isChecked() else
                "Untagged"
            ),
            "L2": "Ethernet II" if self.l2_ethernet.isChecked() else "None",
            "L3": (
                "IPv4" if self.l3_ipv4.isChecked() else
                "IPv6" if self.l3_ipv6.isChecked() else
                "ARP" if self.l3_arp.isChecked() else
                "None"
            ),
            "L4": (
                "TCP" if self.l4_tcp.isChecked() else
                "UDP" if self.l4_udp.isChecked() else
                "ICMP" if self.l4_icmp.isChecked() else
                "IGMP" if self.l4_igmp.isChecked() else
                "RoCEv2" if self.l4_rocev2.isChecked() else
                "None"
            ),
            "Payload": (
                "Pattern" if self.payload_pattern.isChecked() else
                "Hex Dump" if self.payload_hex.isChecked() else
                "None"
            ),
        }

        # MAC Details
        stream_details.update({
            "mac_destination_mode": self.mac_destination_mode.currentText() or "Fixed",
            "mac_destination_address": self.mac_destination_address.text() or "00:00:00:00:00:00",
            "mac_source_mode": self.mac_source_mode.currentText() or "Fixed",
            "mac_source_address": self.mac_source_address.text() or "00:00:00:00:00:00",
            "mac_destination_count": self.mac_destination_count.text() or "1",
            "mac_destination_step": self.mac_destination_step.text() or "1",
            "mac_source_count": self.mac_source_count.text() or "1",
            "mac_source_step": self.mac_source_step.text() or "1",
        })

        # VLAN Details
        stream_details.update({
            "vlan_priority": self.priority_field.currentText() or "0",
            "vlan_cfi_dei": self.cfi_dei_field.currentText() or "0",
            "vlan_id": self.vlan_id_field.text() or "1",
            "vlan_tpid": self.tpid_field.text() if self.override_tpid_checkbox.isChecked() else "81 00",
            "override_vlan_tpid": self.override_tpid_checkbox.isChecked(),
            "vlan_increment": self.vlan_increment_checkbox.isChecked(),
            "vlan_increment_value": self.vlan_increment_value.text() or "1",
            "vlan_increment_count": self.vlan_increment_count.text() or "1",
        })

        # IPv4 Details
        stream_details.update({
            "ipv4_source": self.source_field.text() or "0.0.0.0",
            "ipv4_destination": self.destination_field.text() or "0.0.0.0",
            "ipv4_ttl": self.ttl_field.text() or "64",
            "ipv4_identification": self.identification_field.text() or "0000",
            "ipv4_increment_source": self.increment_source_checkbox.isChecked(),
            "ipv4_source_increment_step": self.source_increment_step.text() or "1",
            "ipv4_source_increment_count": self.source_increment_count.text() or "1",
            "ipv4_increment_destination": self.increment_destination_checkbox.isChecked(),
            "ipv4_destination_increment_step": self.destination_increment_step.text() or "1",
            "ipv4_destination_increment_count": self.destination_increment_count.text() or "1",
            "ipv4_df": self.df_checkbox.isChecked(),
            "ipv4_mf": self.mf_checkbox.isChecked(),
            "ipv4_fragment_offset": self.fragment_offset_field.text() or "0",
            # TOS/DSCP/Custom
            "tos_dscp_mode": self.tos_dscp_custom_mode.currentText() or "TOS",
            "ipv4_tos": self.tos_dropdown.currentText() if self.tos_dscp_custom_mode.currentText() == "TOS" else None,
            "ipv4_dscp": self.dscp_dropdown.currentText() if self.tos_dscp_custom_mode.currentText() == "DSCP" else None,
            "ipv4_ecn": self.ecn_dropdown.currentText() if self.tos_dscp_custom_mode.currentText() == "DSCP" else None,
            "ipv4_custom_tos": self.custom_tos_field.text() if self.tos_dscp_custom_mode.currentText() == "Custom" else None,
            "ipv4_source_mode": self.source_mode_dropdown.currentText() or "Fixed",
            "ipv4_destination_mode": self.destination_mode_dropdown.currentText() or "Fixed",
        })

        # TCP Details
        stream_details.update({
            "tcp_source_port": self.source_port_field.text() or "0",
            "tcp_destination_port": self.destination_port_field.text() or "0",
            "tcp_increment_source_port": self.increment_tcp_source_checkbox.isChecked(),
            "tcp_source_port_step": self.tcp_source_increment_step.text() or "1",
            "tcp_source_port_count": self.tcp_source_increment_count.text() or "1",
            "tcp_increment_destination_port": self.increment_tcp_destination_checkbox.isChecked(),
            "tcp_destination_port_step": self.tcp_destination_increment_step.text() or "1",
            "tcp_destination_port_count": self.tcp_destination_increment_count.text() or "1",
            "tcp_sequence_number": self.sequence_number_field.text() or "0",
            "tcp_acknowledgement_number": self.acknowledgement_number_field.text() or "0",
            "tcp_window": self.window_field.text() or "1024",
            "tcp_checksum": self.tcp_checksum_field.text() or "",
            "tcp_flags": ", ".join([
                flag for flag, widget in [
                    ("URG", self.flag_urg),
                    ("ACK", self.flag_ack),
                    ("PSH", self.flag_psh),
                    ("RST", self.flag_rst),
                    ("SYN", self.flag_syn),
                    ("FIN", self.flag_fin),
                ] if widget.isChecked()
            ]),
        })

        # Payload Data
        stream_details.update({
            "payload_data": self.payload_data_field.text() or "",
            "override_source_tcp_port": self.override_source_port_checkbox.isChecked(),
            "override_destination_tcp_port": self.override_destination_port_checkbox.isChecked(),
        })

        # Stream Rate Control
        stream_details.update({
            "stream_rate_type": self.rate_type_dropdown.currentText(),
            "stream_pps_rate": (
                self.stream_pps_rate.text() if self.rate_type_dropdown.currentText() == "Packets Per Second (PPS)" else None
            ),
            "stream_bit_rate": (
                self.stream_bit_rate.text() if self.rate_type_dropdown.currentText() == "Bit Rate" else None
            ),
            "stream_load_percentage": (
                self.stream_load_percentage.text() if self.rate_type_dropdown.currentText() == "Load (%)" else None
            ),
            "stream_duration_mode": self.duration_mode_dropdown.currentText(),
            "stream_duration_seconds": (
                self.stream_duration_field.text() if self.duration_mode_dropdown.currentText() == "Seconds" else None
            ),
        })

        # RoCEv2 Details
        if self.l4_rocev2.isChecked():
            stream_details["rocev2"] = {
                "traffic_class": self.rocev2_traffic_class.currentText(),
                "flow_label": self.rocev2_flow_label.text() or "000000",
                "source_gid": self.rocev2_source_gid.text() or "0:0:0:0:0:ffff:192.168.1.1",
                "destination_gid": self.rocev2_destination_gid.text() or "0:0:0:0:0:ffff:192.168.1.2",
                "source_qp": self.rocev2_source_qp.text() or "0",
                "destination_qp": self.rocev2_destination_qp.text() or "0",
            }

        print(f"**get_stream_details: {stream_details}")
        return stream_details

    def get_tcp_flags(self):
        """Returns a string representation of the selected TCP flags."""
        flags = []
        if hasattr(self, 'flag_urg') and self.flag_urg.isChecked():
            flags.append("URG")
        if hasattr(self, 'flag_ack') and self.flag_ack.isChecked():
            flags.append("ACK")
        if hasattr(self, 'flag_psh') and self.flag_psh.isChecked():
            flags.append("PSH")
        if hasattr(self, 'flag_rst') and self.flag_rst.isChecked():
            flags.append("RST")
        if hasattr(self, 'flag_syn') and self.flag_syn.isChecked():
            flags.append("SYN")
        if hasattr(self, 'flag_fin') and self.flag_fin.isChecked():
            flags.append("FIN")
        return ", ".join(flags) if flags else "None"


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_DontUseNativeMenuBar)  # Ensures menu bar stays in the app window
    window = TrafficGeneratorClient()
    window.show()
    sys.exit(app.exec_())