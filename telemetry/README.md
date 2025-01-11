

Author: surajsharma@juniper.net 
--------------------------------

## All In One Telemetry ## 
User Instructions:

This setup script deploys and manages the following telemetry components:
- OpenTelemetry Collector: Collects telemetry data, processes it, and exports to Prometheus or other backends.
- Prometheus Time Series Database: Collects and stores metrics data, scrapes configured sources, and provides a Web UI for monitoring.
- Telegraf Collector: Collects metrics from various sources, formats them, and sends them to Prometheus.
- gNMIc: Subscribes to gNMI telemetry from network devices, works independent of any of the above services.

Prerequisites:
Ensure git, curl, and wget are installed. The script will install these if they are missing.

### Setup Steps:
1. Clone the Repository:
- git clone https://github.com/surajnsharma/telemetry.git
- cd telemetry
2. Run the Main Script:
- Run ./setup_telemetry.sh and select from the following options:
- 1) Configure Telegraf: Sets up and verifies the Telegraf configuration.
- 2) Run GNMIc: Subscribes to gNMI telemetry from configured devices.
- 3) Install/Uninstall: Installs/Uninstall and configures services.
- 4) Exit: Exits the script.
3. Install Services:
- If selecting Install, you'll be prompted to install Telegraf, Prometheus, OpenTelemetry Collector, and gNMIc. You can choose any combination or install all.
- Each service's configuration file is stored in /etc, e.g., /etc/otelcol/otel-collector-config.yaml for OpenTelemetry.
4. Testing the Services:
- After installation, validate data collection and service connections using the following:
- Prometheus Web UI: http://localhost:9091
- Telegraf Prometheus Metrics: curl http://localhost:9273/metrics
- OpenTelemetry Prometheus Metrics: curl http://localhost:9464/metrics

### Configuration:
- Configuration files:
- OpenTelemetry: /etc/otelcol/otel-collector-config.yaml
- Prometheus: /etc/prometheus/prometheus.yml
- Telegraf: /etc/telegraf/telegraf.conf
- Each configuration file can be modified as needed for custom sources, processing rules, or export destinations.

### Service Management:
- Check Status: Use the Check status of services option in the script to confirm that each service is running and connections are established.
- Restart Services: Use the Restart services option if any service is inactive.
- Troubleshooting: The Troubleshooting option provides commands for common issues, such as viewing logs, testing configurations, and checking network connections.

### Important Notes:
- The default ports for each service are as follows:
- Prometheus: 9091
- Telegraf: 9273
- OpenTelemetry Collector: 9464 and 4317
- Ensure these ports are accessible if running on a remote server or through a firewall.
- For Telegraf and OpenTelemetry to export data properly to Prometheus, establish connections between them.
- This setup supports Git LFS for managing large files. If you encounter large files that GitHub rejects, consider external storage solutions or reducing the file size.

### Example Usage:
- To configure Telegraf: Run the main script (./setup_telemetry.sh), select 1) Configure Telegraf, and follow the prompts.
- To install all services: From the main script menu, select 3) Install, then 5) All.
- To test Prometheus and OpenTelemetry integration: After installation, run:
- curl http://localhost:9273/metrics for Telegraf metrics in Prometheus format.
- curl http://localhost:9464/metrics for OpenTelemetry metrics.
- Checking logs: View logs for each service in /var/log or use sudo journalctl -u <service-name> (e.g., journalctl -u prometheus).
Contact:
For issues, feature requests, or further configuration help, contact surajsharma@juniper.net.


```bash
## End of User Instructions.
 ```bash
root@q-dell-srv02:/suraj# git clone https://github.com/surajnsharma/telemetry.git 
Cloning into 'telemetry'... remote: Enumerating objects: 37, done. 
remote: Counting objects: 100% (15/15), done. remote: Compressing objects: 100% (8/8), done. 
remote: Total 37 (delta 5), reused 14 (delta 5), pack-reused 22 (from 1) Receiving objects: 100% (37/37), 59.90 MiB | 58.14 MiB/s, done. 
Resolving deltas: 100% (9/9), done. 

root@q-dell-srv02:/suraj# cd telemetry/ 
root@q-dell-srv02:~/suraj/telemetry# ls 
config_telegraf.sh gnmic_0.38.2_linux_x86_64.tar.gz 
gnmic_telemetry.log otelcol_0.111.0_linux_amd64.tar.gz 
README.md setup_git_repo.sh test.sh config_telegraf.sh.org 
gnmic.sh install.sh otel-collector-config.yaml 
setup_telemetry.sh
telegraf_generated.conf 
devices.text gnmic.sh.org 
install.sh.org otelcol.log 
sensor.text 
telegraf.log

## update devices.text you want to collect telemetry data ##
root@q-dell-srv01:~/suraj# cat devices.text 
username=root, password=Embe1mpls
10.155.0.50:57400
10.155.0.51:57400

## update sensor.text you are interested to collect telemetry ##
root@q-dell-srv01:~/suraj# cat sensor.text 
/junos/system/linecard/cpu/memory
/junos/system/linecard/firewall/
/junos/system/linecard/interface/
/junos/system/linecard/interface/logical/usage
/junos/system/linecard/packet/usage/
/interfaces/interface/state/
/junos/system/linecard/optics/


## Install telemetry package ##
root@q-dell-srv02:~/suraj/telemetry# ./setup_telemetry.sh 
Choose a script to run:
    1) Configure Telegraf
    2) Run GNMIc
    3) Install/Uninstall
    4) Exit 
    Enter your choice (1-4): 3 
Running install.sh... Choose an action:
    1) Install services
    2) Uninstall services
    3) Check status of services
    4) Restart services
    5) Troubleshooting
    6) Back to main script (setup_telemetry.sh) 
Enter your choice: 1 
Choose services to install:
   1) Telegraf
   2) Prometheus
   3) OpenTelemetry Collector
   4) gnmic
   5) All
   6) Back to main menu 
Enter your choice (e.g., 1 3 for Telegraf and OpenTelemetry): 5 


telegraf is either not installed or not running. 
Installing Telegraf... Hit:1 http://archive.ubuntu.com/ubuntu jammy 
InRelease Hit:2 http://archive.ubuntu.com/ubuntu jammy-updates 
InRelease Hit:3 http://archive.ubuntu.com/ubuntu jammy-security 
InRelease Hit:4 http://archive.ubuntu.com/ubuntu jammy-backports 
InRelease Reading package lists... Done Reading package lists... Done 
Building dependency tree... Done Reading state information... Done 
telegraf is already the newest version (1.21.4+ds1-0ubuntu2). 
0 upgraded, 0 newly installed, 0 to remove and 64 not upgraded. 
Created symlink /etc/systemd/system/multi-user.target.wants/telegraf.service → /lib/systemd/system/telegraf.service. 
Waiting for telegraf to become active... telegraf is running. 
prometheus is either not installed or not running. 
Downloading Prometheus... --2024-10-26 14:47:34-- 
https://github.com/prometheus/prometheus/releases/download/v2.54.1/prometheus-2.54.1.linux-amd64.tar.gz Resolving github.com (github.com)... 140.82.116.4 
Connecting to github.com (github.com)|140.82.116.4|:443... connected. 
HTTP request sent, awaiting response... 302 
Found Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/6838921/04e495b6-6719-4ec2-b374-4f31fac8dd23?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20241026%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20241026T214734Z&X-Amz-Expires=300&X-Amz-Signature=60581d82266cc3994deb8fc491388f1ad795d6af4f2e90d7ff8f4c454a73fe94&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dprometheus-2.54.1.linux-amd64.tar.gz&response-content-type=application%2Foctet-stream [following] --2024-10-26 14:47:34-- https://objects.githubusercontent.com/github-production-release-asset-2e65be/6838921/04e495b6-6719-4ec2-b374-4f31fac8dd23?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20241026%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20241026T214734Z&X-Amz-Expires=300&X-Amz-Signature=60581d82266cc3994deb8fc491388f1ad795d6af4f2e90d7ff8f4c454a73fe94&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dprometheus-2.54.1.linux-amd64.tar.gz&response-content-type=application%2Foctet-stream Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.110.133, ... Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected. HTTP request sent, awaiting response... 200 OK Length: 105689699 (101M) [application/octet-stream] Saving to: ‘prometheus-2.54.1.linux-amd64.tar.gz’

prometheus-2.54.1.linux-amd64.tar.gz 100%[=============================================================================================================================>] 100.79M 107MB/s in 0.9s

2024-10-26 14:47:35 (107 MB/s) - ‘prometheus-2.54.1.linux-amd64.tar.gz’ saved [105689699/105689699]
prometheus-1.54.1.linux-amd64/ prometheus-2.54.1.linux-amd64/NOTICE prometheus-2.54.1.linux-amd64/LICENSE 
prometheus-2.54.1.linux-amd64/prometheus.yml prometheus-2.54.1.linux-amd64/prometheus prometheus-2.54.1.linux-amd64/consoles/ 
prometheus-2.54.1.linux-amd64/consoles/prometheus-overview.html prometheus-2.54.1.linux-amd64/consoles/node-overview.html 
prometheus-2.54.1.linux-amd64/consoles/index.html.example prometheus-2.54.1.linux-amd64/consoles/node.html 
prometheus-2.54.1.linux-amd64/consoles/node-disk.html prometheus-2.54.1.linux-amd64/consoles/prometheus.html 
prometheus-2.54.1.linux-amd64/consoles/node-cpu.html prometheus-2.54.1.linux-amd64/promtool 
prometheus-2.54.1.linux-amd64/console_libraries/ prometheus-2.54.1.linux-amd64/console_libraries/menu.lib 
prometheus-2.54.1.linux-amd64/console_libraries/prom.lib 
Created symlink /etc/systemd/system/multi-user.target.wants/prometheus.service → /etc/systemd/system/prometheus.service. 
Prometheus installed and configuration file created at /etc/prometheus/prometheus.yml 
Waiting for prometheus to become active... prometheus is running. otelcol is either not installed or not running. 
Found OpenTelemetry Collector package locally. README.md otelcol 
Created symlink /etc/systemd/system/multi-user.target.wants/otelcol.service → /etc/systemd/system/otelcol.service. 
OpenTelemetry Collector installed and configuration file created at /etc/otelcol/otel-collector-config.yaml 
Waiting for otelcol to become active... otelcol is running. Local gnmic package found. Installing gnmic from local file... 
gnmic installed successfully from local package. 

Choose services to install:
    1) Telegraf
    2) Prometheus
    3) OpenTelemetry Collector
    4) gnmic
    5) All
    6) Back to main menu 
Enter your choice (e.g., 1 3 for Telegraf and OpenTelemetry): 6 

Returning to main menu... Choose an action:
    1) Install services
    2) Uninstall services
    3) Check status of services
    4) Restart services
    5) Troubleshooting
    6) Back to main script (setup_telemetry.sh) 
Enter your choice: 3 

Checking the status of all services... 
Checking Telegraf status... 
telegraf-src-port-prometheus is LISTENING on port 9273. 
Checking OpenTelemetry Collector status... 
otelcol-src-to-prometheus is LISTENING on port 9464. 
otelcol-src-port-telegraf is LISTENING on port 4317. 
Checking Prometheus status... prometheus-web-port is LISTENING on port 9091. 
Prometheus has an ESTABLISHED connection to Telegraf on port 9273. 
Telegraf has an ESTABLISHED connection to Prometheus on port 9273. 
Prometheus has an ESTABLISHED connection to OpenTelemetry on port 9464. 
OpenTelemetry has an ESTABLISHED connection to Prometheus on port 9464. 
No ESTABLISHED connection found between otelcol and Telegraf on port 4317. 

You can use the following curl links to test the services 
Telegraf->Prometheus-Scrape-data-> curl http://localhost:9273/metrics 
OpenTelemetry->Prometheus-Scrape-data-> curl http://localhost:9464/metrics 
Prometheus Web Link-> http://<server ip:9091

Configuration file paths: 
OpenTelemetry Collector: /etc/otelcol/otel-collector-config.yaml 
Telegraf: /etc/telegraf/telegraf.conf 
Prometheus: /etc/prometheus/prometheus.yml 

Choose an action:

    1) Install services
    2) Uninstall services
    3) Check status of services
    4) Restart services
    5) Troubleshooting
    6) Back to main script (setup_telemetry.sh) 
    Enter your choice:

## END ##

