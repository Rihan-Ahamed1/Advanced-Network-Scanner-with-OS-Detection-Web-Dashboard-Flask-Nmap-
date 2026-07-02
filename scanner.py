import socket
from flask import Flask, render_template

app = Flask(__name__)

# Get network range
def get_network_info():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except:
        local_ip = "127.0.0.1"
    finally:
        s.close()

    network = local_ip.rsplit('.', 1)[0] + '.0/24'
    return network


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan')
def scan():
    network = get_network_info()
    scanner = nmap.PortScanner()

    print(f"[*] Fast scanning {network}...")

    # STEP 1: Find active devices
    scanner.scan(hosts=network, arguments='-sn')
    active_hosts = scanner.all_hosts()

    data_results = []

    if not active_hosts:
        return render_template('report.html', data=[])

    # STEP 2: Scan all devices together (FAST)
    scanner.scan(hosts=" ".join(active_hosts), arguments='-F -T4')

    for host in active_hosts:
        host_data = {
            "ip": host,
            "ports": [],
            "os": "Unknown Device"
        }

        try:
            # Hostname
            hostname = scanner[host].hostname()
            if hostname:
                host_data["os"] = hostname

            # Ports
            if 'tcp' in scanner[host]:
                for port in scanner[host]['tcp']:
                    if scanner[host]['tcp'][port]['state'] == 'open':
                        service = scanner[host]['tcp'][port]['name']
                        host_data["ports"].append(f"{port} ({service})")

        except:
            pass

        data_results.append(host_data)

    return render_template('report.html', data=data_results)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
