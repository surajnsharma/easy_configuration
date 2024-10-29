import psutil
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# InfluxDB v2 connection details
INFLUXDB_URL = "http://localhost:8086"
INFLUXDB_TOKEN = "SOE3N4jpxrsAK7_Ovh2XZB5gu_38UkRutkHr6_t06GcfGeXVwkxdwA_VCx-N3yned7VXx75wb4DkqvtHI0NbmQ=="  # Replace with your generated token
INFLUXDB_ORG = "juniper"
INFLUXDB_BUCKET = "telemetry"

# Initialize the InfluxDB v2 client
client = InfluxDBClient(
    url=INFLUXDB_URL,
    token=INFLUXDB_TOKEN,
    org=INFLUXDB_ORG
)

write_api = client.write_api(write_options=SYNCHRONOUS)

# Collect system metrics
cpu_usage = psutil.cpu_percent(interval=1)
memory_info = psutil.virtual_memory()
disk_usage = psutil.disk_usage('/')

# Create data point
point = Point("server_metrics") \
        .tag("host", "q-dell-srv02") \
        .field("cpu_usage", cpu_usage) \
        .field("memory_usage", memory_info.percent) \
        .field("disk_usage", disk_usage.percent)

# Write data point to InfluxDB
write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)

print("Data written to InfluxDB")
