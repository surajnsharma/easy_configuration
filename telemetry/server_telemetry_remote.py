import paramiko
import sys
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# SSH connection details
REMOTE_HOST = "q-dell-srv02"  # Replace with your remote host IP
USERNAME = "root"  # Replace with your remote username
PASSWORD = "Embe1mpls"  # Replace with your remote password
SSH_TIMEOUT = 10  # Set a timeout for the SSH connection attempt (in seconds)

# InfluxDB v2 connection details
INFLUXDB_URL = "http://localhost:8086"
INFLUXDB_TOKEN = "SOE3N4jpxrsAK7_Ovh2XZB5gu_38UkRutkHr6_t06GcfGeXVwkxdwA_VCx-N3yned7VXx75wb4DkqvtHI0NbmQ=="  # Replace with your generated token
INFLUXDB_ORG = "juniper"
INFLUXDB_BUCKET = "telemetry"

print(f"Starting connection to {REMOTE_HOST}...")

try:
    # Initialize the SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(REMOTE_HOST, username=USERNAME, password=PASSWORD, timeout=SSH_TIMEOUT)
    print(f"Successfully connected to {REMOTE_HOST}.")
except paramiko.AuthenticationException:
    print(f"Authentication failed when connecting to {REMOTE_HOST}. Please check the username/password.")
    sys.exit(1)
except paramiko.SSHException as sshException:
    print(f"Unable to establish SSH connection: {sshException}")
    sys.exit(1)
except Exception as e:
    print(f"Exception occurred: {e}")
    sys.exit(1)

try:
    # Python script to collect system metrics using psutil
    python_script = """
import psutil
cpu_usage = psutil.cpu_percent(interval=1)
memory_usage = psutil.virtual_memory().percent
disk_usage = psutil.disk_usage('/').percent
print(cpu_usage)
print(memory_usage)
print(disk_usage)
"""

    # Execute the Python script on the remote machine
    stdin, stdout, stderr = ssh.exec_command(f"python3 -c \"{python_script}\"")
    output = stdout.read().decode().splitlines()
    error_output = stderr.read().decode()

    if error_output:
        print(f"Error output from remote host {REMOTE_HOST}: {error_output}")

    if len(output) != 3:
        print(f"Unexpected output from remote host {REMOTE_HOST}: {output}")
        ssh.close()
        sys.exit(1)

    cpu_usage = float(output[0])
    memory_usage = float(output[1])
    disk_usage = float(output[2])

    ssh.close()

    # Initialize the InfluxDB v2 client
    client = InfluxDBClient(
        url=INFLUXDB_URL,
        token=INFLUXDB_TOKEN,
        org=INFLUXDB_ORG
    )

    # Disable the signout to prevent errors during garbage collection
    client.api_client.__del__ = lambda *args, **kwargs: None

    try:
        write_api = client.write_api(write_options=SYNCHRONOUS)

        # Create data point
        point = Point("server_metrics") \
            .tag("host", REMOTE_HOST) \
            .field("cpu_usage", cpu_usage) \
            .field("memory_usage", memory_usage) \
            .field("disk_usage", disk_usage)

        # Write data point to InfluxDB
        write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)

        print("Data written to InfluxDB")
    finally:
        client.close()
except Exception as e:
    print(f"Failed to collect metrics or write to InfluxDB: {e}")
    sys.exit(1)
