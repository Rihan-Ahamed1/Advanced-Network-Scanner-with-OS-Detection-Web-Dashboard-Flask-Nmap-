import nmap
import socket
from flask import Flask, render_template

app = Flask(__name__)

def get_network_info():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to a dummy address to find local IP
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    
    network = local_ip.rsplit('.', 1)[0] + '.0/24'
    return local_ip, network

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    local_ip, network = get_network_info()
    scanner = nmap.PortScanner()
    
    # 1. Ping Scan to find active hosts
    scanner.scan(hosts=network, arguments='-sn')
    active_hosts = scanner.all_hosts()
    
    data_results = []

    for host in active_hosts:
        host_entry = {"ip": host, "os": "Unknown", "ports": []}
        
        # 2. OS Detection and Service Scan
        # Note: OS detection often requires sudo/administrative privileges
        try:
            # Combining OS detection (-O) and Service Scan (-sV)
            scanner.scan(hosts=host, arguments='-O -sV')
            
            # Extract OS
            if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                host_entry["os"] = scanner[host]['osmatch'][0]['name']
            
            # Extract Ports
            if 'tcp' in scanner[host]:
                for port in scanner[host]['tcp']:
                    if scanner[host]['tcp'][port]['state'] == 'open':
                        host_entry["ports"].append(port)
        except Exception as e:
            host_entry["os"] = f"Scan Error: {str(e)}"
            
        data_results.append(host_entry)

    return render_template('report.html', data=data_results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
