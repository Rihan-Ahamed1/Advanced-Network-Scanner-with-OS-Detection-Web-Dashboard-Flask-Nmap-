import nmap
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

    print("Local IP:", local_ip)
    print("Network:", network)

    return network


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan')
def scan():

    network = get_network_info()

    scanner = nmap.PortScanner()

    print(f"[*] Scanning {network}...")

    # Discover active hosts
    scanner.scan(
    hosts=network,
    arguments='-sn -T5 --min-rate 1000'
)

    active_hosts = scanner.all_hosts()

    print("Active Hosts:", active_hosts)

    data_results = []

    for host in active_hosts:

        host_data = {
            "ip": host,
            "ports": [],
            "os": "Connected Device",
            "risk": "LOW"
        }

        try:

            # Fast port scan
            scanner.scan(hosts=host, arguments='-F -T5')

            hostname = scanner[host].hostname()

            if hostname:
                host_data["os"] = hostname

            if 'tcp' in scanner[host]:

                for port in scanner[host]['tcp']:

                    if scanner[host]['tcp'][port]['state'] == 'open':

                        service = scanner[host]['tcp'][port]['name']

                        host_data["ports"].append(
                            f"{port} ({service})"
                        )

                        # Risk Detection
                        if port == 23:
                            host_data["risk"] = "CRITICAL"

                        elif port == 21:
                            if host_data["risk"] != "CRITICAL":
                                host_data["risk"] = "HIGH"

                        elif port in [80, 443]:
                            if host_data["risk"] == "LOW":
                                host_data["risk"] = "MEDIUM"

        except Exception as e:
            print("Error:", e)

        data_results.append(host_data)

    print("Results:", len(data_results))

    return render_template(
        'report.html',
        data=data_results
    )


if __name__ == '__main__':
    app.run(
        debug=False,
        host='0.0.0.0',
        port=5000
    )
