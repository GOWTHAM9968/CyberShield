import nmap


def scan_network(target):

    nm = nmap.PortScanner()

    nm.scan(
        hosts=target,
        arguments="-Pn -sV"
    )

    devices = []

    for host in nm.all_hosts():

        hostname = nm[host].hostname()

        state = nm[host].state()

        ports = []

        services = []

        if "tcp" in nm[host]:

            for port in nm[host]["tcp"]:

                ports.append(port)

                service = nm[host]["tcp"][port]["name"]

                services.append(service)

        devices.append({

            "ip": host,

            "hostname": hostname,

            "status": state,

            "ports": ports,

            "services": services

        })

    return devices