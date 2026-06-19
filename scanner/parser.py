def parse_results(scanner):
    results = []

    for host in scanner.all_hosts():

        host_info = {
            "host": host,
            "state": scanner[host].state(),
            "protocols": []
        }

        for protocol in scanner[host].all_protocols():

            protocol_info = {
                "protocol": protocol,
                "ports": []
            }

            for port in sorted(scanner[host][protocol].keys()):

                info = scanner[host][protocol][port]

                protocol_info["ports"].append({
                    "port": port,
                    "state": info.get("state"),
                    "service": info.get("name"),
                    "product": info.get("product"),
                    "version": info.get("version"),
                    "extrainfo": info.get("extrainfo")
                })

            host_info["protocols"].append(protocol_info)

        results.append(host_info)

    return results