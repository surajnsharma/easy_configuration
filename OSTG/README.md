
setup_protocol_selection_tab -> edit_selected_stream->get_stream_details -> populate_stream_fields -> update_stream_table -> 
    """" sets up protocol section """"

setup_protocol_data_tab

    """Sets up the Protocol Data tab with all protocol-specific sections."""

load_session → UI Update:

    Loads a session from a file and updates the UI components (update_server_tree and update_stream_table).

populate_stream_fields:

    When a specific stream is selected in the table, this function populates the dialog fields for editing.

update_stream_table:

    Reflects the latest stream data in the UI table whenever changes are made.

save_session:

    Saves the current state, including edits made via populate_stream_fields.

Debugging Suggestions

    Verify Key Mappings:
    Ensure keys in stream_data match between save_session, load_session, and populate_stream_fields.

    Check Conditional Logic:
    For fields like VLAN, ensure the selection logic matches saved values.

    Validate Saved JSON:
    Manually inspect session.json to verify the saved structure and ensure compatibility during loading.

Steps to Set Up DPDK-Pktgen on macOS
- brew install meson ninja cmake libpcap
git clone https://github.com/DPDK/dpdk.git
cd dpdk
- meson setup build --libdir=lib --default-library=shared -Dexamples=all
ninja -C build
sudo ninja -C build install
- dpdk-testpmd --version
- git clone https://github.com/pktgen/Pktgen-DPDK.git
cd Pktgen-DPDK
- meson setup -Dexamples=all build
ninja -C build
sudo ninja -C build install
- pktgen --version
- 4. Configure Network Interface

macOS does not support binding NICs to DPDK drivers (vfio-pci), so you'll need to use the pcap driver for traffic generation.

Identify the available interfaces using:
ifconfig
Run Pktgen using the pcap PMD:
sudo pktgen -l 0 -n 1 --vdev=net_pcap0,iface=en0 -- -P

"""install DPDK-Pktgen on linux """
sudo apt update
sudo apt install -y build-essential gcc meson ninja-build libnuma-dev python3-pip git
git clone https://github.com/DPDK/dpdk.git
cd dpdk
meson setup build
ninja -C build
sudo ninja -C build install
sudo ldconfig
dpdk-testpmd --version
git clone https://github.com/pktgen/Pktgen-DPDK.git
cd Pktgen-DPDK
meson setup -Dexamples=all build
ninja -C build
sudo ninja -C build install
pktgen --version
"""Configure Hugepages"""
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
nodev /mnt/huge hugetlbfs defaults 0 0
 """Bind Network Interfaces to DPDK"""
sudo dpdk-devbind.py --status
sudo dpdk-devbind.py --bind=vfio-pci <PCI_ADDRESS>
Example: sudo dpdk-devbind.py --bind=vfio-pci 0000:03:00.0
"""Run Pktgen"""
sudo pktgen -l 0-3 -n 4 -- -P -m [1].0
Interactive Mode: Run Pktgen with an interactive CLI:
sudo pktgen -l 0-3 -n 4 -- -P -m [1].0 --interactive



Scapy with DPDK or PF_RING

    Overview: Python-based packet crafting and traffic generation tool.
    Features:
        Combines Scapy’s flexibility with DPDK or PF_RING for high-speed traffic.
        Suitable for customized traffic scenarios and packet-level testing.
        Limited by hardware capabilities but scalable with efficient libraries.
    Use Case: Custom traffic patterns and functional testing.
    Website: Scapy

pip install scapy
