# app/juniper_connectivity.py

from ncclient import manager

def check_juniper_connectivity(host, port=830, username='root', password='Embe1mpls'):
    try:
        with manager.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            hostkey_verify=False,
            device_params={'name': 'junos'},
            timeout=30
        ) as m:
            return m.connected
    except Exception as e:
        print(f"Failed to connect to {host}: {e}")
        return False

