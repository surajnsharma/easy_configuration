# telemetry.py

from influxdb_client import InfluxDBClient

# InfluxDB configuration
INFLUXDB_URL = "http://localhost:8086"
INFLUXDB_TOKEN = "your_influxdb_token"
INFLUXDB_ORG = "your_organization"
INFLUXDB_BUCKET = "telemetry"

# Create a client for InfluxDB
client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
query_api = client.query_api()

def get_cpu_data(device_ip):
    cpu_query = f'''
    from(bucket: "{INFLUXDB_BUCKET}")
    |> range(start: -1h)
    |> filter(fn: (r) => r["_measurement"] == "cpu")
    |> filter(fn: (r) => r["source"] == "{device_ip}")
    |> filter(fn: (r) => r["_field"] == "value")
    |> sort(columns: ["_time"], desc: true)
    |> limit(n: 10)
    '''

    cpu_result = query_api.query(org=INFLUXDB_ORG, query=cpu_query)
    cpu_data = []
    for table in cpu_result:
        for record in table.records:
            cpu_data.append({
                "time": record.get_time(),
                "value": record.get_value(),
            })
    return cpu_data

def get_interface_data(device_ip):
    interface_query = f'''
    from(bucket: "{INFLUXDB_BUCKET}")
    |> range(start: -1h)
    |> filter(fn: (r) => r["_measurement"] == "interface-counters")
    |> filter(fn: (r) => r["source"] == "{device_ip}")
    |> sort(columns: ["_time"], desc: true)
    |> limit(n: 10)
    '''

    interface_result = query_api.query(org=INFLUXDB_ORG, query=interface_query)
    interface_data = []
    for table in interface_result:
        for record in table.records:
            interface_data.append({
                "time": record.get_time(),
                "if_name": record["if_name"],
                "if_in_octets": record.get_value_by_key("if_in_octets"),
                "if_out_octets": record.get_value_by_key("if_out_octets"),
            })
    return interface_data
