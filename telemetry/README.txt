Install psutil
***************
psutil is used to collect telemetry data from servers
make sure to install following Python packages
#sudo apt install python3-pip
#pip3 uninstall psutil



Install Influx DB and Telegraph on MAC
****************************************
#brew install influxdb
#brew install telegraf
#brew services start telegraf
#brew services stop telegraf
#brew services start influxdb
#brew install influxdb-cli

#Setup influx user/password to login into influxdb web URL
./influx setup \
  --username admin \
  --password Embe1mpls \
  --token admintoken \
  --org juniper \
  --bucket metrics \
  --force
  
  
# setup INFLUX_TOKEN -> will be used for influx cli 
export INFLUX_TOKEN="your_auth_token_here"

login to http://localhost:8086 -> root/Embe1mpls
Click- Python -> click- Get Token -> Click- COPY TO CLIPBOARD
--> paste the following copied command to your Shell
export INFLUXDB_TOKEN=EJsRHSnhYzd2AUhdp-TGUznx-w23NkDCiSrJJagWXyVGpGBPl0s8z5cx8-W0DE55lTdjui8xNld-x4UfTKVEeg==


#login to influxdb URL and check the auth token. 
influx v1 shell
> show databases


To start Telegraf using the default configuration:
#telegraf --config /usr/local/etc/telegraf.conf
#brew services start telegraf


## Verify Service is running on Mac
surajsharma@surajsharma-mbp ~ % brew services list
Name     Status     User        File
influxdb started    surajsharma ~/Library/LaunchAgents/homebrew.mxcl.influxdb.plist
telegraf error  256 surajsharma ~/Library/LaunchAgents/homebrew.mxcl.telegraf.plist




Install Influxdb 2 in Ubuntu
**************************
curl -LO https://download.influxdata.com/influxdb/releases/influxdb2_2.7.6-1_amd64.deb
sudo dpkg -i influxdb2_2.7.6-1_amd64.deb
sudo service influxdb start
sudo service influxdb status

Install Influx2 client
***********************
wget https://download.influxdata.com/influxdb/releases/influxdb2-client-2.7.5-linux-amd64.tar.gz
tar xvzf ./influxdb2-client-2.7.5-linux-amd64.tar.gz


(venv3) surajsharma@surajsharma-mbp ~ % influxd version
InfluxDB 2.7.9 (git: 91c1a5d3d8) build_date: 2024-08-09T17:22:19Z

login to influx ui.
http://localhost:8086
user/pass: root/Embe1mpls

Click- Python -> click- Get Token -> Click- COPY TO CLIPBOARD
--> paste the following copied command to your Shell
export INFLUXDB_TOKEN=EJsRHSnhYzd2AUhdp-TGUznx-w23NkDCiSrJJagWXyVGpGBPl0s8z5cx8-W0DE55lTdjui8xNld-x4UfTKVEeg==




#extract and run the command below
root@q-dell-srv02:~# ./influx org list
ID                      Name
24059422c1bb00d8        JUNIPER

./influx setup \
  --username admin \
  --password Embe1mpls \
  --token admintoken \
  --org juniper \
  --bucket metrics \
  --force

# setup INFLUX_TOKEN -> will be used for influx cli 
export INFLUX_TOKEN="your_auth_token_here"
Click- Python -> click- Get Token -> Click- COPY TO CLIPBOARD
--> paste the following copied command to your Shell
export INFLUXDB_TOKEN=EJsRHSnhYzd2AUhdp-TGUznx-w23NkDCiSrJJagWXyVGpGBPl0s8z5cx8-W0DE55lTdjui8xNld-x4UfTKVEeg==

#login to influxdb URL and check the auth token. 
influx v1 shell
> show databases


root@q-dell-srv02:~# ./influx bucket list
ID                      Name            Retention       Shard group duration    Organization ID         Schema Type
7ae9f18b9fce9786        _monitoring     168h0m0s        24h0m0s                 a8a3b3f718815132        implicit
c3bd98f7444eecc4        _tasks          72h0m0s         24h0m0s                 a8a3b3f718815132        implicit
a3a2ec21d39a8400        metrics         infinite        168h0m0s                a8a3b3f718815132        implicit

#Creating additonal persistant bucket
./influx bucket create -n telemetry -o juniper --retention 0

(venv3) root@q-dell-srv02:~# ./influx bucket list
ID                      Name            Retention       Shard group duration    Organization ID         Schema Type
7ae9f18b9fce9786        _monitoring     168h0m0s        24h0m0s                 a8a3b3f718815132        implicit
c3bd98f7444eecc4        _tasks          72h0m0s         24h0m0s                 a8a3b3f718815132        implicit
a3a2ec21d39a8400        metrics         infinite        168h0m0s                a8a3b3f718815132        implicit
40753f52b314377d        telemetry       infinite        168h0m0s                a8a3b3f718815132        implicit


root@q-dell-srv02:~# ./influx auth list
ID                      Description     Token           User Name       User ID                 Permissions
0d7fb7c890436000        root's Token    Embe1mpls       root            0d7fb7c87a836000        [read:/authorizations write:/authorizations read:/buckets write:/buckets read:/dashboards write:/dashboards read:/orgs write:/orgs read:/sources write:/sources read:/tasks write:/tasks read:/telegrafs write:/telegrafs read:/users write:/users read:/variables write:/variables read:/scrapers write:/scrapers read:/secrets write:/secrets read:/labels write:/labels read:/views write:/views read:/documents write:/documents read:/notificationRules write:/notificationRules read:/notificationEndpoints write:/notificationEndpoints read:/checks write:/checks read:/dbrp write:/dbrp read:/notebooks write:/notebooks read:/annotations write:/annotations read:/remotes write:/remotes read:/replications write:/replications]

root@q-dell-srv02:~# ./influx org list
ID                      Name
a8a3b3f718815132        juniper

(venv3) surajsharma@surajsharma-mbp telemetry % influx config
Active  Name    URL                     Org
*       default http://localhost:8086   juniper


Click- Python -> click- Get Token -> Click- COPY TO CLIPBOARD
--> paste the following copied command to your Shell
export INFLUXDB_TOKEN=EJsRHSnhYzd2AUhdp-TGUznx-w23NkDCiSrJJagWXyVGpGBPl0s8z5cx8-W0DE55lTdjui8xNld-x4UfTKVEeg==


## Sample GNMI Paths
/interfaces/interface/state/counters
/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/state
/system/processes/process/cpu-usage
/interfaces/interface/config


Click- Python -> click- Get Token -> Click- COPY TO CLIPBOARD
--> paste the following copied command to your Shell
export INFLUX_TOKEN=EJsRHSnhYzd2AUhdp-TGUznx-w23NkDCiSrJJagWXyVGpGBPl0s8z5cx8-W0DE55lTdjui8xNld-x4UfTKVEeg==

--> limit to last 4 records    
root@q-dell-srv02:~# ./influx query '
  from(bucket: "metrics")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "interface_counters")
  |> limit(n: 4)
'

--> limit to last 1 records
root@q-dell-srv02:~# ./influx query '
  from(bucket: "metrics")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "interface_counters")
  |> limit(n: 1)

--> query all records
influx query '
  from(bucket: "telemetry")
    |> range(start: 0)
' --org 'juniper'

--> last one record in 24h
influx query '
  from(bucket: "telemetry")
    |> range(start: -24h)
    |> filter(fn: (r) => r._measurement == "server_metrics")
    |> limit(n: 1) 
' --org 'juniper'

---> Selected host=q-dell-srv01
(venv3) surajsharma@surajsharma-mbp telemetry % influx query '
  from(bucket: "telemetry")
    |> range(start: -24h)
    |> filter(fn: (r) => r._measurement == "server_metrics" and r.host == "q-dell-srv01")
    |> limit(n: 10)
' --org 'juniper'


---> Query between dates.. example dates between start and stop
 --> start: 2024-08-17T00:00:00Z, stop: 2024-08-17T23:59:59Z
(venv3) surajsharma@surajsharma-mbp FLASK % influx query 'from(bucket: "telemetry")
  |> range(start: 2024-08-17T00:00:00Z, stop: 2024-08-17T23:59:59Z) 
  |> filter(fn: (r) => r._measurement == "server_metrics" and r.host == "q-dell-srv02")
  |> sort(columns: ["_time"], desc: true)
  |> limit(n: 10)
' --org 'juniper'
        


## checking all records
curl --get http://localhost:8086/query?db=metrics --header "Authorization: Token Embe1mpls" --data-urlencode "q=SELECT * FROM "interface_counters""

## checking last one record
curl --get http://localhost:8086/query \
  --header "Authorization: Token $INFLUXDB_TOKEN" \
  --data-urlencode "db=metrics" \
  --data-urlencode "q=SELECT * FROM \"interface_counters\" ORDER BY time DESC LIMIT 1"

curl --get http://localhost:8086/query \
  --header "Authorization: Token $INFLUXDB_TOKEN" \
  --data-urlencode "db=metrics" \
  --data-urlencode 'q=SELECT * FROM "svla-q5240-08_network-instances_network-instance_protocols_protocol_bgp_neighbors" ORDER BY time DESC LIMIT 1' 
  
curl --get http://localhost:8086/query \
  --header "Authorization: Token $INFLUXDB_TOKEN" \
  --data-urlencode "db=metrics" \
  --data-urlencode "q=show measurements"




Click- Python -> click- Get Token -> Click- COPY TO CLIPBOARD
--> paste the following copied command to your Shell
export INFLUXDB_TOKEN=EJsRHSnhYzd2AUhdp-TGUznx-w23NkDCiSrJJagWXyVGpGBPl0s8z5cx8-W0DE55lTdjui8xNld-x4UfTKVEeg==


Example1:
curl --get http://localhost:8086/query \
  --header "Authorization: Token $INFLUXDB_TOKEN" \
  --data-urlencode "db=telemetry" \
  --data-urlencode "q=SELECT * FROM \"server_metrics\" ORDER BY time DESC LIMIT 1"

Example2:
curl --get http://localhost:8086/query \
  --header "Authorization: Token $INFLUXDB_TOKEN" \
  --data-urlencode "db=metrics" \
  --data-urlencode "q=SELECT * FROM \"interface_counters\" ORDER BY time DESC LIMIT 1"

Example3: using flux query
(venv3) surajsharma@surajsharma-mbp telemetry % influx query 'from(bucket: "metrics") |> range(start: -1w) |> filter(fn: (r) => r._measurement == "interface_counters") |> sort(columns: ["_time"], desc: true) |> limit(n: 1)' --org 'juniper'


# Remove all Influx config
sudo systemctl stop influxdb
sudo rm -rf /var/lib/influxdb
sudo rm -rf /var/lib/influxdb2
sudo rm -rf /etc/influxdb
sudo rm -rf /root/.influxdbv2/


Install GNMIC on Ubuntu
***********************
# bash -c "$(curl -sL https://get-gnmic.openconfig.net)"
 


Basic Configuration
# influx
# CREATE DATABASE telemetry

Telegraf
********
Telegraf’s configuration file is located at /usr/local/etc/telegraf.conf.
#nano /usr/local/etc/telegraf.conf
#brew services restart telegraf

To ensure Telegraf is collecting metrics, you can check the logs:
#tail -f /usr/local/var/log/telegraf/telegraf.log

Configurting Telegraf
#sudo mkdir -p /opt/homebrew/etc/telegraf/
#sudo sh -c 'telegraf config > /opt/homebrew/etc/telegraf/telegraf.conf'



Juniper Side Configuration
**************************
root@stqncy-qfx5130-01# show system 
services {
    extension-service {
        request-response {
            grpc {
                clear-text {
                    address 0.0.0.0;
                    port 50051;
                }
                skip-authentication;
            }
        }
        notification {
            allow-clients {
                address 0.0.0.0/0;
            }
        }
    }


# enable http access for influxdb /etc/influxdb/influxdb.conf 
[http]
  enabled = true
  bind-address = ":8086"
  auth-enabled = true
  log-enabled = true
  

# sudo systemctl start influxdb
# sudo systemctl status influxdb

root@q-dell-srv01:~# netstat -tuln | grep 8086
tcp6       0      0 :::8086                 :::*                    LISTEN     

(venv3) root@q-dell-srv02:~# lsof -i :8086
COMMAND     PID     USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
influxd 3314323 influxdb   25u  IPv6 27321188      0t0  TCP *:8086 (LISTEN)

# Chaning default port 
edit /lib/systemd/system/influxdb.service
ARG1="--http-bind-address :8087"
ExecStart=/usr/bin/influxd $ARG1 $ARG2





Add folloing lines in /etc/telegraf/telegraf.conf      


#disable following if not needed
#[[outputs.prometheus_client]]
#   ## Address to listen on
#    listen = ":9275"

[[inputs.gnmi]]
  addresses = ["10.48.53.103:50051"]
  username = "root"
  password = "Embe1mpls"
  redial = "10s"

[[inputs.gnmi.subscription]]
   name = "cpu"
   origin = "openconfig-platform"
   path = "/components/component/cpu/utilization"
   subscription_mode = "sample"
   sample_interval = "5s"

[[inputs.gnmi.subscription]]
  name = "interface-counters"
  origin = "openconfig-interfaces"
  path = "/interfaces/interface/state/counters"
  subscription_mode = "sample"
  sample_interval = "10s"

[[outputs.influxdb]]
  urls = ["http://localhost:8086"]
  database = "telemetry"
  username = "root"
  password = "Embe1mpls"
  

# sudo systemctl restart telegraf  
curl -G http://localhost:8086/query --data-urlencode "db=telemetry" --data-urlencode "q=SELECT * FROM cpu WHERE device_name = 'stqncy-qfx5130-01'"




--> debugging
journalctl -u telegraf -f
Aug 10 06:08:14 q-dell-srv01 telegraf[719188]: 2024-08-10T06:08:14Z E! [inputs.gnmi] Error in plugin: failed to setup subscription: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 10.48.53.103:8080: connect: connection refused"
Aug 10 06:08:24 q-dell-srv01 telegraf[719188]: 2024-08-10T06:08:24Z E! [inputs.gnmi] Error in plugin: failed to setup subscription: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 10.48.53.103:8080: connect: connection refused"
Aug 10 06:08:34 q-dell-srv01 telegraf[719188]: 2024-08-10T06:08:34Z E! [inputs.gnmi] Error in plugin: failed to setup subscription: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 10.48.53.103:8080: connect: connection refused"


root@q-dell-srv01:/home/lab/telemetry# telegraf --config /etc/telegraf/telegraf.conf --debug
2024-08-10T06:09:24Z I! Starting Telegraf 1.21.4+ds1-0ubuntu2
2024-08-10T06:09:24Z I! Loaded inputs: cpu disk diskio gnmi kernel mem processes swap system
2024-08-10T06:09:24Z I! Loaded aggregators: 
2024-08-10T06:09:24Z I! Loaded processors: 
2024-08-10T06:09:24Z I! Loaded outputs: influxdb prometheus_client
2024-08-10T06:09:24Z I! Tags enabled: host=q-dell-srv01
2024-08-10T06:09:24Z I! [agent] Config: Interval:10s, Quiet:false, Hostname:"q-dell-srv01", Flush Interval:10s
2024-08-10T06:09:24Z D! [agent] Initializing plugins
2024-08-10T06:09:24Z D! [agent] Connecting outputs
2024-08-10T06:09:24Z D! [agent] Attempting connection to [outputs.prometheus_client]
2024-08-10T06:09:24Z E! [agent] Failed to connect to [outputs.prometheus_client], retrying in 15s, error was 'listen tcp :9273: bind: address already in use'
^C2024-08-10T06:09:36Z E! [telegraf] Error running agent: connecting output outputs.prometheus_client: context canceled




root@q-dell-srv01:/home/lab/telemetry# lsof -i :9273
COMMAND     PID      USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
telegraf 719188 _telegraf    7u  IPv6 18670031      0t0  TCP *:9273 (LISTEN)



## check the capability of junos 
root@q-dell-srv01:~# gnmic -a 10.48.53.103:50051 -u root -p Embe1mpls capabilities --insecure 
gNMI version: 0.7.0
supported models:
  - ietf-yang-metadata, IETF NETMOD (NETCONF Data Modeling Language) Working Group, 2016-08-05
  - junos-configuration-metadata, Juniper Networks, Inc., 2021-09-01
  - junos-common-types, Juniper Networks, Inc., 2023-01-01
  - junos-conf-access-profile, Juniper Networks, Inc., 2023-01-01
  - junos-conf-access, Juniper Networks, Inc., 2023-01-01
  - junos-conf-accounting-options, Juniper Networks, Inc., 

## fetch interface counter using gnmi cli
root@q-dell-srv01:~#  gnmic -a 10.48.53.103:50051 -u root -p Embe1mpls --insecure sub --path /interfaces/interface/state/counters


## Influxdb version 1
influx -username root -password Embe1mpls -database telemetry
or influx -host localhost -port 8080 -username root -password Embe1mpls -database telemetry
> USE telemetry;
> SHOW MEASUREMENTS;
> SELECT * FROM cpu;


Host: Helps to identify the source of the metrics from a Telegraf perspective. This is useful when you have multiple Telegraf instances collecting data from various sources, and you want to know which instance collected which data.

IP Address (source): This is crucial for identifying the actual network device that the telemetry data pertains to. When analyzing network telemetry, this is the primary identifier for the device in question.

> SELECT * FROM "interface-counters" LIMIT 1
name: interface-counters
time                carrier_transitions host         if_in_1sec_octets if_in_1sec_pkts if_in_bc_pkts if_in_ipv4_1sec_octets if_in_ipv4_1sec_pkts if_in_ipv4_bytes if_in_ipv4_pkts if_in_ipv6_1sec_octets if_in_ipv6_1sec_pkts if_in_ipv6_bytes if_in_ipv6_pkts if_in_mc_pkts if_in_octets if_in_pause_pkts if_in_pkts if_in_uc_pkts if_name     if_out_1sec_octets if_out_1sec_pkts if_out_bc_pkts if_out_ipv4_1sec_octets if_out_ipv4_1sec_pkts if_out_ipv4_bytes if_out_ipv4_pkts if_out_ipv6_1sec_octets if_out_ipv6_1sec_pkts if_out_ipv6_bytes if_out_ipv6_pkts if_out_mc_pkts if_out_octets if_out_pause_pkts if_out_pkts if_out_uc_pkts in_discards in_errors in_multicast_pkts in_octets in_pkts last_clear name out_errors out_multicast_pkts out_octets out_pkts path                                 source
----                ------------------- ----         ----------------- --------------- ------------- ---------------------- -------------------- ---------------- --------------- ---------------------- -------------------- ---------------- --------------- ------------- ------------ ---------------- ---------- ------------- -------     ------------------ ---------------- -------------- ----------------------- --------------------- ----------------- ---------------- ----------------------- --------------------- ----------------- ---------------- -------------- ------------- ----------------- ----------- -------------- ----------- --------- ----------------- --------- ------- ---------- ---- ---------- ------------------ ---------- -------- ----                                 ------
1723274711915606016                     q-dell-srv01 0                 0               0             0                      0                    0                0               0                      0                    0                0               0             0            0                0          0             et-0/0/20:3 0                  0                0              0                       0                     0                 0                0                       0                     0                 0                0              0             0                 0           0                                                                                                                                          /interfaces/interface/state/counters 10.48.53.103
> 



> SELECT * FROM "interface-counters" WHERE "if_name" = 'et-0/0/20:3' LIMIT 10
name: interface-counters
time                carrier_transitions host         if_in_1sec_octets if_in_1sec_pkts if_in_bc_pkts if_in_ipv4_1sec_octets if_in_ipv4_1sec_pkts if_in_ipv4_bytes if_in_ipv4_pkts if_in_ipv6_1sec_octets if_in_ipv6_1sec_pkts if_in_ipv6_bytes if_in_ipv6_pkts if_in_mc_pkts if_in_octets if_in_pause_pkts if_in_pkts if_in_uc_pkts if_name     if_out_1sec_octets if_out_1sec_pkts if_out_bc_pkts if_out_ipv4_1sec_octets if_out_ipv4_1sec_pkts if_out_ipv4_bytes if_out_ipv4_pkts if_out_ipv6_1sec_octets if_out_ipv6_1sec_pkts if_out_ipv6_bytes if_out_ipv6_pkts if_out_mc_pkts if_out_octets if_out_pause_pkts if_out_pkts if_out_uc_pkts in_discards in_errors in_multicast_pkts in_octets in_pkts last_clear name out_errors out_multicast_pkts out_octets out_pkts path                                 source
----                ------------------- ----         ----------------- --------------- ------------- ---------------------- -------------------- ---------------- --------------- ---------------------- -------------------- ---------------- --------------- ------------- ------------ ---------------- ---------- ------------- -------     ------------------ ---------------- -------------- ----------------------- --------------------- ----------------- ---------------- ----------------------- --------------------- ----------------- ---------------- -------------- ------------- ----------------- ----------- -------------- ----------- --------- ----------------- --------- ------- ---------- ---- ---------- ------------------ ---------- -------- ----                                 ------
1723274711915606016                     q-dell-srv01 0                 0               0             0                      0                    0                0               0                      0                    0                0               0             0            0                0          0             et-0/0/20:3 0                  0                0              0                       0                     0                 0                0                       0                     0                 0                0              0             0                 0           0                                                                                                                                          /interfaces/interface/state/counters 10.48.53.103


> SELECT * FROM "interface-counters" WHERE "source" = '10.48.53.103' LIMIT 1
name: interface-counters
time                carrier_transitions host         if_in_1sec_octets if_in_1sec_pkts if_in_bc_pkts if_in_ipv4_1sec_octets if_in_ipv4_1sec_pkts if_in_ipv4_bytes if_in_ipv4_pkts if_in_ipv6_1sec_octets if_in_ipv6_1sec_pkts if_in_ipv6_bytes if_in_ipv6_pkts if_in_mc_pkts if_in_octets if_in_pause_pkts if_in_pkts if_in_uc_pkts if_name     if_out_1sec_octets if_out_1sec_pkts if_out_bc_pkts if_out_ipv4_1sec_octets if_out_ipv4_1sec_pkts if_out_ipv4_bytes if_out_ipv4_pkts if_out_ipv6_1sec_octets if_out_ipv6_1sec_pkts if_out_ipv6_bytes if_out_ipv6_pkts if_out_mc_pkts if_out_octets if_out_pause_pkts if_out_pkts if_out_uc_pkts in_discards in_errors in_multicast_pkts in_octets in_pkts last_clear name out_errors out_multicast_pkts out_octets out_pkts path                                 source
----                ------------------- ----         ----------------- --------------- ------------- ---------------------- -------------------- ---------------- --------------- ---------------------- -------------------- ---------------- --------------- ------------- ------------ ---------------- ---------- ------------- -------     ------------------ ---------------- -------------- ----------------------- --------------------- ----------------- ---------------- ----------------------- --------------------- ----------------- ---------------- -------------- ------------- ----------------- ----------- -------------- ----------- --------- ----------------- --------- ------- ---------- ---- ---------- ------------------ ---------- -------- ----                                 ------
1723274711915606016                     q-dell-srv01 0                 0               0             0                      0                    0                0               0                      0                    0                0               0             0            0                0          0             et-0/0/20:3 0                  0                0              0                       0                     0                 0                0                       0                     0                 0                0              0             0                 0           0                                                                                                                                          /interfaces/interface/state/counters 10.48.53.103



Useing GNMIC with Influxdb version 1 
**************************************
gnmic --config gnmic-config.yaml --debug subscribe
#without debug# gnmic --config gnmic-config.yaml --debug subscribe


root@q-dell-srv01:/home/lab/telemetry# cat gnmic-config.yaml 
targets:
  device1:
    address: 10.48.53.103:50051
    username: root
    password: Embe1mpls    
    tls:
      enabled: false
    insecure: true

outputs:
  default:
    type: influxdb
    address: http://localhost:8086
    database: telemetry
    username: root
    password: Embe1mpls

subscriptions:
  interface_counters:
    paths:
      - /interfaces/interface/state/counters
      - /interfaces/interface/state/admin-status
      - /interfaces/interface/state/oper-status
    mode: stream
    encoding: proto
    sample_interval: 10s

  system_counters:
    paths:
      - /system/processes/process/cpu-usage
      - /system/memory/state/total
      - /system/memory/state/used
      - /components/component/state
      - /components/component/state/temperature
      - /system/alarms/alarm
    mode: stream
    encoding: proto
    sample_interval: 10s

  protocol_counters:
    paths:
      - /network-instances/network-instance/protocols/protocol/bgp/neighbor
    mode: stream
    encoding: proto
    sample_interval: 10s



sqlite3 handeling
*******************
(venv3) surajsharma@surajsharma-mbp instance % sqlite3 app_database.db
SQLite version 3.43.2 2023-10-10 13:08:14
Enter ".help" for usage hints.
sqlite> .tables
alembic_version  gnmi_paths       influx_query     trigger_event  
device_info      gpu_system       topology         user           

sqlite> SELECT * FROM influx_query;
1|1|svla-q5240-08_interfaces_interface_state_counters|carrier-transitions,if_in_1sec_octets,if_in_1sec_pkts,if_in_bc_pkts,if_in_ipv4_1sec_octets,if_in_ipv4_1sec_pkts
2|1|svla-q5240-06_interfaces_interface_state_counters|carrier-transitions,if_in_1sec_octets,if_in_1sec_pkts,if_in_bc_pkts,if_in_ipv4_1sec_octets,if_in_ipv4_1sec_pkts





    