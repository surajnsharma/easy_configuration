# changing stream keyword
AddStreamDialog class ->
__init__ -> setup_protocol_data_tab( pick the section for chaning )
update : populate_stream_fields, edit_selected_stream(get_stream_details, update_stream_table) , 
populate_stream_fields, load_session, save_session


# Adding Stream
AddStreamDialog class -> 
--> open_add_stream_dialog -> (get_stream_details ->(store data in stream_details)->update_stream_table)


# loading stream from json
TrafficGeneratorClient class -> load_session (update_server_tree, update_stream_table)

# Adding new Protocol data section
AddStreamDialog class ->
__init__ -> setup_protocol_data_tab (
        self.add_mac_section()
        self.add_vlan_section()
        self.add_ipv4_section()
        self.add_ipv6_section()
        self.add_tcp_section()
        self.add_mpls_section()
        self.add_payload_data_section()
        self.add_rocev2_section()
)

# Populating Protocol data
AddStreamDialog class ->
Check Stream data loaded by loading stream from json 
populate_stream_fields->



pip install scapy
