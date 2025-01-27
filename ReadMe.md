README for rbuster-py
Overview
rbuster-py is a simple and effective Python tool for scanning RSYNC services on a network. It utilizes nmap to identify hosts with the RSYNC port (default: 873) open and checks for anonymous access. This tool is intended for administrators and security professionals to audit their network for potential RSYNC vulnerabilities.

Features
Scan a host or IP range (CIDR format) for RSYNC services using nmap.
Detect and report hosts that allow anonymous access to their RSYNC service.

Ensure nmap is installed:
sudo apt update && sudo apt install nmap
Usage
Run the script with the following syntax:

sudo python3 rbuster-py.py -t <target> [-p <port>]
Options:
-t, --target: (Required) Host or IP range to scan (e.g., 192.168.1.0/24).
-p, --port: (Optional) Port to scan (default: 873).

Examples
Scan a Single Host:

sudo python3 rbuster-py.py -t 192.168.1.10
Scan an Entire Subnet:

sudo python3 rbuster-py.py -t 192.168.1.0/24
Scan a Host with a Custom Port:

sudo python3 rbuster-py.py -t 192.168.1.10 -p 10873
