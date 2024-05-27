# Initial Reconnaissance Script

This repository contains a Python script designed for performing network reconnaissance. The script can scan a given IP address or subnet, identify active hosts, perform an aggressive Nmap scan on them, and output detailed information about open ports, services, and potential vulnerabilities.

## Features

- Subnet scanning to identify active hosts.
- Aggressive scanning using Nmap to gather detailed information about open ports, services, and vulnerabilities.
- Outputs results in a structured format, suitable for documentation and further analysis.

## Prerequisites

Before running the script, ensure you have the following dependencies installed:

- Python 3.x
- Scapy
- Nmap
- python-nmap

You can install the required Python packages using pip:

```bash
pip install scapy python-nmap
```

Additionally, make sure Nmap is installed on your system. You can download and install Nmap from [here](https://nmap.org/download.html).

## Usage

Clone the repository:

```bash
git clone https://github.com/tanishq200/initial-recon.git
cd initial-recon
```

Run the script:

```bash
python initial_recon.py <TARGET>
```

Replace `<TARGET>` with a single IP address or a subnet (e.g., `192.168.1.0/24`).

### Example

```bash
python initial_recon.py 192.168.1.0/24
```

This will scan the subnet `192.168.1.0/24`, identify active hosts, and perform an aggressive scan on each discovered host.

## Output

The script will save the results to a file named `output.txt` in the current directory. The output will include:

- Host Information: IP address and state (up/down).
- Open Ports and Services: Detailed information about each open port, including service name, product, version, extra info, and CPE.
- Vulnerabilities: List of vulnerabilities for each service detected, with identifiers, severity scores, and links to detailed descriptions and potential exploits.
- Summary: A summary of open ports, services, products, and vulnerabilities.

### Example Output

```
Host Information:
IP Address: 10.10.10.10
State: up

Open Ports and Services:
Port 22 (SSH)

State: open
Service: ssh
Product: OpenSSH
Version: 7.2p2 Ubuntu 4ubuntu2.7
Extra Info: Ubuntu Linux; protocol 2.0
CPE (Common Platform Enumeration): cpe:/o:linux, cpe:/a:openbsd:openssh:7.2p2

Port 80 (HTTP)

State: open
Service: http
Product: Apache httpd
Version: 2.4.18
Extra Info: (Ubuntu)
CPE: cpe:/a:apache:http_server:2.4.18

...

Vulnerabilities:
The scan output includes a list of vulnerabilities for each service detected. These vulnerabilities are listed with identifiers (like CVE, PacketStorm, etc.), severity scores, and links to detailed descriptions and potential exploits.

Summary:
Open Ports: 22, 80, 139, 445
Services: SSH, HTTP, NetBIOS-SSN
Products: OpenSSH, Apache HTTP Server, Samba smbd
Vulnerabilities: Numerous vulnerabilities with various severity levels and available exploits.
```

## Contributing

Contributions are welcome! Please fork this repository and submit pull requests with any enhancements or bug fixes.

## Acknowledgments

- [Nmap](https://nmap.org) for the network scanning capabilities.
- [Scapy](https://scapy.net) for the subnet scanning functionality.
- [Python-Nmap](https://pypi.org/project/python-nmap/) for integrating Nmap with Python.
