from jnpr.junos import Device
from jnpr.junos.utils.config import Config
import time  # Ensure time module is imported
from jnpr.junos.exception import (
    ConnectError,
    LockError,
    UnlockError,
    ConfigLoadError,
    CommitError,
    RpcTimeoutError,
)
import logging

def connect_to_device(host, username, password, timeout=30):
    """Establish a connection to the Juniper device."""
    try:
        logging.info(f"Connecting to device {host}...")
        dev = Device(host=host, user=username, passwd=password, timeout=timeout)
        dev.open()
        logging.info(f"Successfully connected to {host}.")
        return dev
    except ConnectError as e:
        logging.error(f"Failed to connect to device {host}: {e}")
        print(f"Failed to connect to device {host}: {e}", flush=True)  # Display error to console
        return None

def disable_interface(device, username, password, interface_name, **kwargs):
    """Disable a network interface on the device."""
    dev = connect_to_device(device["host"], username, password)
    if not dev:
        logging.error(f"Unable to execute 'disable_interface' on {device['name']}. Connection failed.")
        print(f"Unable to execute 'disable_interface' on {device['name']}. Connection failed.", flush=True)
        return False

    try:
        with Config(dev, mode="exclusive") as cu:
            retry_count = 3
            for attempt in range(1, retry_count + 1):
                try:
                    logging.info(f"Attempting to lock configuration on {device['name']} (Attempt {attempt}/{retry_count})...")
                    cu.lock()
                    logging.info(f"Configuration locked on {device['name']}.")
                    break
                except LockError as e:
                    logging.error(f"Configuration lock failed on {device['name']}: {e}")
                    if attempt < retry_count:
                        logging.info(f"Retrying configuration lock on {device['name']} after delay...")
                        time.sleep(5)  # Wait 5 seconds before retrying
                    else:
                        logging.error(f"Exceeded maximum retries for configuration lock on {device['name']}. Skipping operation.")
                        return False

            try:
                logging.info(f"Disabling interface {interface_name} on {device['name']}...")
                cu.load(f"set interfaces {interface_name} disable", format="set")
                cu.commit(timeout=30)
                logging.info(f"Interface {interface_name} successfully disabled on {device['name']}.")
                return True
            except ConfigLoadError as e:
                logging.error(f"Configuration load failed on {device['name']}: {e}")
            except CommitError as e:
                logging.error(f"Commit failed on {device['name']}: {e}")
            except RpcTimeoutError as e:
                logging.error(f"RPC timeout on {device['name']} while disabling interface: {e}")
            finally:
                try:
                    cu.unlock()
                except UnlockError as e:
                    logging.warning(f"Failed to unlock configuration on {device['name']}: {e}")
    finally:
        dev.close()
        logging.info(f"Connection to {device['name']} closed.")
    return False

def enable_interface(device, username, password, interface_name, **kwargs):
    """Enable a network interface on the device."""
    dev = connect_to_device(device["host"], username, password)
    if not dev:
        logging.error(f"Unable to execute 'enable_interface' on {device['name']}. Connection failed.")
        print(f"Unable to execute 'enable_interface' on {device['name']}. Connection failed.", flush=True)
        return False

    try:
        with Config(dev, mode="exclusive") as cu:
            logging.info(f"Locking configuration on {device['name']}...")
            try:
                cu.lock()
            except LockError as e:
                logging.error(f"Configuration lock failed on {device['name']}: {e}")
                return False

            try:
                logging.info(f"Enabling interface {interface_name} on {device['name']}...")
                cu.load(f"delete interfaces {interface_name} disable", format="set")
                cu.commit(timeout=30)
                logging.info(f"Interface {interface_name} successfully enabled on {device['name']}.")
                return True
            except ConfigLoadError as e:
                logging.error(f"Configuration load failed on {device['name']}: {e}")
            except CommitError as e:
                logging.error(f"Commit failed on {device['name']}: {e}")
            except RpcTimeoutError as e:
                logging.error(f"RPC timeout on {device['name']} while enabling interface: {e}")
            finally:
                try:
                    cu.unlock()
                except UnlockError as e:
                    logging.warning(f"Failed to unlock configuration on {device['name']}: {e}")
    finally:
        dev.close()
        logging.info(f"Connection to {device['name']} closed.")
    return False
