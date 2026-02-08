def print_summary(results):
    hosts = results.get("hosts", {})

    active_hosts = {
        ip: data for ip, data in hosts.items()
        if data.get("active")
    }

    hosts_with_ports = {
        ip: data for ip, data in active_hosts.items()
        if data.get("ports")
    }

    print("\nScan Summary")
    print("=" * 12)

    print(f"\nActive hosts ({len(active_hosts)}):")
    if not active_hosts:
        print("  (none)")
    else:
        for ip in sorted(active_hosts):
            ports = active_hosts[ip]["ports"]
            if ports:
                port_list = ", ".join(str(p["port"]) for p in ports)
                print(f"  - {ip:<15} [{port_list}]")
            else:
                print(f"  - {ip}")

    if results["metadata"].get("scan_ports"):
        print(f"\nHosts with open ports ({len(hosts_with_ports)}):")
        if not hosts_with_ports:
            print("  (none)")
        else:
            for ip in sorted(hosts_with_ports):
                print(f"  - {ip}")
