import nmap
import sys
from scapy.all import ARP, Ether, srp

def subnet_scan(subnet):
    print(f"Scanning subnet: {subnet}...")
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []

    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

def aggressive_scan(ip):
    nm = nmap.PortScanner()
    print(f"Performing aggressive scan on {ip}...")
    nm.scan(ip, arguments='-A --script vulners')
    scan_results = nm[ip]
    return scan_results

def format_results(subnet_clients, scan_results):
    output = []

    if subnet_clients:
        output.append("Subnet Scan Results:\n")
        for client in subnet_clients:
            output.append(f"IP: {client['ip']}, MAC: {client['mac']}\n")
        output.append("\n")

    for ip, result in scan_results.items():
        output.append(f"Host Information:\nIP Address: {ip}\nState: {result.state()}\n")
        output.append("Open Ports and Services:\n")
        
        for proto in result.all_protocols():
            lport = result[proto].keys()
            for port in lport:
                service = result[proto][port]
                output.append(f"Port {port} ({service['name'].upper()})\n\n")
                output.append(f"State: {service['state']}\n")
                output.append(f"Service: {service['name']}\n")
                if 'product' in service:
                    output.append(f"Product: {service['product']}\n")
                if 'version' in service:
                    output.append(f"Version: {service['version']}\n")
                if 'extrainfo' in service:
                    output.append(f"Extra Info: {service['extrainfo']}\n")
                if 'cpe' in service:
                    output.append(f"CPE: {', '.join(service['cpe'])}\n")
                output.append("\n")
        
        vulnerabilities_info = "Vulnerabilities:\n"
        for proto in result.all_protocols():
            lport = result[proto].keys()
            for port in lport:
                service = result[proto][port]
                if 'script' in service and 'vulners' in service['script']:
                    vulnerabilities_info += f"Port {port} ({service['name'].upper()}) Vulnerabilities:\n\n"
                    vuln_output = service['script']['vulners']
                    if isinstance(vuln_output, dict):
                        for vuln_id, vuln_info in vuln_output.items():
                            vulnerabilities_info += f"{vuln_id}: Severity {vuln_info.get('cvss', 'N/A')}, {vuln_info.get('title', 'N/A')}\n"
                        vulnerabilities_info += "...and many more.\n\n"
                    else:
                        vulnerabilities_info += vuln_output
                vulnerabilities_info += "\n"
        
        output.append(vulnerabilities_info)

    summary = f"Summary:\nOpen Ports: {', '.join([str(port) for proto in result.all_protocols() for port in result[proto].keys()])}\n"
    summary += f"Services: {', '.join([service['name'].upper() for proto in result.all_protocols() for service in result[proto].values()])}\n"
    summary += f"Products: {', '.join([service['product'] for proto in result.all_protocols() for service in result[proto].values() if 'product' in service])}\n"
    summary += "Vulnerabilities: Numerous vulnerabilities with various severity levels and available exploits.\n"

    output.append(summary)
    
    return ''.join(output)

def write_to_file(filename, data):
    with open(filename, 'w') as f:
        f.write(data)

def main(target):
    subnet_clients = []
    scan_results = {}

    if '/' in target:
        # Perform subnet scan
        subnet_clients = subnet_scan(target)
        # Perform aggressive scan on each discovered IP
        for client in subnet_clients:
            ip = client['ip']
            scan_results[ip] = aggressive_scan(ip)
    else:
        # Perform aggressive scan on a single IP
        scan_results[target] = aggressive_scan(target)
    
    # Format and write results to file
    output = format_results(subnet_clients, scan_results)
    output_filename = "output.txt"
    write_to_file(output_filename, output)
    print(f"Reconnaissance results saved to {output_filename}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python initial_recon.py <TARGET>")
        print("TARGET can be a single IP address or a subnet (e.g., 192.168.1.0/24)")
        sys.exit(1)
    target = sys.argv[1]
    main(target)
