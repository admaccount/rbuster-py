README for rbuster-py
Overview
rbuster-py is a simple and effective Python tool for scanning RSYNC services on a network. It utilizes nmap to identify hosts with the RSYNC port (default: 873) open and checks for anonymous access. This tool is intended for administrators and security professionals to audit their network for potential RSYNC vulnerabilities.

Features
Scan a host or IP range (CIDR format) for RSYNC services using nmap.
Detect and report hosts that allow anonymous access to their RSYNC service.
Requirements
Python 3.x
nmap must be installed on the system.
Root privileges are required to run this tool.
Installation
Clone this repository:
git clone https://github.com/your-repo/rbuster-py.git
cd rbuster-py
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
Output
Displays information about open RSYNC ports on the target hosts.
Indicates whether anonymous access is allowed for each detected host.
Notes
This tool must be run with root privileges since nmap requires elevated permissions for certain types of scans.
Ensure you have proper authorization to scan the network or hosts to avoid legal or ethical issues.
Disclaimer
This tool is provided "as-is" for educational and security auditing purposes. The author is not responsible for any misuse or damage caused by this tool.


