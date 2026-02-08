import argparse
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

from discovery import expand_targets
from ports import detect_service
from rate import rate_limit
from mitre import discovery_metadata
from window import utc_timestamp
from output import print_summary


COMMON_PORTS = [22, 80, 443, 3389]


def ping_host(host):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def resolve_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def tcp_scan(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def parse_range(value, min_val, max_val, name):
    try:
        start, end = map(int, value.split(","))
        if start < min_val or end > max_val or start > end:
            raise ValueError
        return list(range(start, end + 1))
    except Exception:
        raise argparse.ArgumentTypeError(
            f"{name} must be START,END within {min_val}-{max_val}"
        )


def filter_hosts_by_range(hosts, subnet, host_range):
    filtered = []
    for ip in hosts:
        last_octet = int(ip.split(".")[-1])
        if last_octet in host_range:
            filtered.append(ip)
    return filtered


def scan_host(host, ports, delay, scan_ports, verbose):
    active = ping_host(host)

    if not active:
        if verbose:
            print(f"[-] {host} inactive")
        return host, {
            "active": False,
            "hostname": None,
            "ports": []
        }

    hostname = resolve_hostname(host)

    if verbose:
        if hostname:
            print(f"[+] {host} active ({hostname})")
        else:
            print(f"[+] {host} active")

    open_ports = []

    if scan_ports:
        for port in ports:
            if tcp_scan(host, port):
                service = detect_service(port)
                open_ports.append({
                    "port": port,
                    "service": service
                })
                if verbose:
                    print(f"    [+] {host}:{port} open ({service})")
            elif verbose:
                print(f"    [-] {host}:{port} closed")

            rate_limit(delay)

    return host, {
        "active": True,
        "hostname": hostname,
        "ports": open_ports
    }


def main():
    parser = argparse.ArgumentParser(
        description="Authorized Network Discovery Tool"
    )

    parser.add_argument("--subnets", required=True)
    parser.add_argument("--rate-limit", type=float, default=0.2)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--verbose", action="store_true")

    parser.add_argument("--scan-active", action="store_true")
    parser.add_argument("--scan-all-ports", action="store_true")

    parser.add_argument(
        "--scan-ports",
        help="Scan port range START,END (e.g. 1,1000)"
    )

    parser.add_argument(
        "--host-range",
        help="Limit subnet host range START,END (e.g. 1,50)"
    )

    args = parser.parse_args()

    # Decide port behavior
    if args.scan_all_ports:
        ports = list(range(1, 65536))
        scan_ports = True
    elif args.scan_ports:
        ports = parse_range(args.scan_ports, 1, 65535, "scan-ports")
        scan_ports = True
    elif args.scan_active:
        ports = COMMON_PORTS
        scan_ports = True
    else:
        ports = []
        scan_ports = False

    targets = expand_targets(args.subnets)

    if args.host_range:
        host_range = parse_range(args.host_range, 1, 254, "host-range")
        targets = filter_hosts_by_range(targets, args.subnets, host_range)

    results = {
        "metadata": {
            "timestamp": utc_timestamp(),
            "mitre_attack": discovery_metadata(),
            "scan_active": args.scan_active,
            "scan_ports": args.scan_ports,
            "scan_all_ports": args.scan_all_ports,
            "host_range": args.host_range
        },
        "hosts": {}
    }

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(
                scan_host,
                host,
                ports,
                args.rate_limit,
                scan_ports,
                args.verbose
            )
            for host in targets
        ]

        for future in as_completed(futures):
            host, data = future.result()
            results["hosts"][host] = data

    print_summary(results)


if __name__ == "__main__":
    main()
