def print_summary(results, show_all=False, only_active=False, open_ports=False):
    hosts = results.get("hosts", {})

    # classify
    all_hosts = hosts
    active_hosts = {
        ip: data for ip, data in hosts.items()
        if data.get("ports")
    }

    if open_ports:
        display_hosts = active_hosts
        title = "Hosts with Open Ports"
    elif show_all:
        display_hosts = all_hosts
        title = "All Scanned Hosts"
    else:
        # default behavior
        display_hosts = active_hosts
        title = "Active Hosts"

    print("\nScan Summary")
    print("=" * 12)
    print(f"\n{title} ({len(display_hosts)}):")

    if not display_hosts:
        print("  (none)")
        return

    for ip, data in sorted(display_hosts.items()):
        ports = data.get("ports", [])
        if ports:
            port_list = ", ".join(str(p["port"]) for p in ports)
            print(f"  - {ip:<15} [{port_list}]")
        else:
            print(f"  - {ip}")
