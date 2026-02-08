import json

def print_summary(results):
    hosts = results.get("hosts", {})

    active_hosts = list(hosts.keys())
    hosts_with_ports = {
        ip: data["ports"]
        for ip, data in hosts.items()
        if data.get("ports")
    }

    print("\nScan Summary")
    print("=" * 12)

    print(f"\nActive hosts ({len(active_hosts)}):")
    for ip in active_hosts:
        ports = hosts[ip]["ports"]
        if ports:
            port_list = ", ".join(str(p["port"]) for p in ports)
            print(f"  - {ip:<15} [{port_list}]")
        else:
            print(f"  - {ip}")

    print(f"\nHosts with open ports ({len(hosts_with_ports)}):")
    for ip in hosts_with_ports:
        print(f"  - {ip}")


def print_json(results):
    print("\nRaw JSON Output")
    print("=" * 15)
    print(json.dumps(results, indent=2))
