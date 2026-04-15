from flask import Flask, render_template
import nmap
import socket

app = Flask(__name__)

def scan_network():
    # 1. Get Local IP and Network Range
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()

    network = local_ip.rsplit('.', 1)[0] + '.0/24'

    # 2. Initialize Nmap and discover active hosts
    scanner = nmap.PortScanner()
    scanner.scan(hosts=network, arguments='-sn')

    results = []

    # 3. Iterate through found hosts
    for host in scanner.all_hosts():
        # Updated host_data structure
        host_data = {"ip": host, "ports": [], "os": "Unknown"}

        # Perform OS Detection and Port/Service Scan (-O for OS, -sS for Stealth, -sV for Service)
        # Note: -O requires root/administrator privileges
        try:
            scanner.scan(hosts=host, arguments='-sS -sV -O')
            
            # OS Detection Logic
            if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                host_data["os"] = scanner[host]['osmatch'][0]['name']
            else:
                host_data["os"] = "Unknown"
        except Exception:
            host_data["os"] = "Error"

        # Port Extraction Logic
        if 'tcp' in scanner[host]:
            for port in scanner[host]['tcp']:
                if scanner[host]['tcp'][port]['state'] == 'open':
                    service = scanner[host]['tcp'][port]['name']
                    host_data["ports"].append(f"{port} ({service})")

        results.append(host_data)

    return results

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan")
def scan():
    data = scan_network()
    return render_template("result.html", data=data)

if __name__ == "__main__":
    # Running with debug=True. 
    # Remember: For OS Detection to work, the script must be run as sudo/Administrator.
    app.run(debug=True)
