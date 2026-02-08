import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from discovery import expand_targets
from ports import detect_service
from rate import rate_limit
from mitre import discovery_metadata
from window import utc_timestamp
from output import print_summary


def tcp_scan(host, port, timeout=1.0):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


def scan_host(host, ports, delay, verbose):
    open_ports = []

    for port in ports:
        if tcp_scan(host, port):
            open_ports.append({
                "port": port,
                "service": detect_service(port)
            })
            if verbose:
                print(f"[+] {host}:{port} open")
        else:
            if verbose:
                print(f"[-] {host}:{port} closed")

    rate_limit(delay)

    return host, {
        "hostname": host,
        "ports": open_ports
    }


def main():
    parser = argparse.ArgumentParser(
        description="Authorized Network Discovery Scanner"
    )

    parser.add_argument("--subnets", required=True)
    parser.add_argument("--ports", default="22,80,443,3389")
    parser.add_argument("--rate-limit", type=float, default=0.2)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--verbose", action="store_true")

    # 👇 output control flags
    parser.add_argument("--show-all", action="store_true",
                        help="Show all scanned IPs")
    parser.add_argument("--only-active", action="store_true",
                        help="Show only active IPs (default)")
    parser.add_argument("--open-ports", action="store_true",
                        help="Show only hosts with open ports")

    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(",")]
    targets = expand_targets(args.subnets)

    results = {
        "metadata": {
            "timestamp": utc_timestamp(),
            "rate_limit_seconds": args.rate_limit,
            "mitre_attack": discovery_metadata()
        },
        "hosts": {}
    }

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(scan_host, h, ports, args.rate_limit, args.verbose)
            for h in targets
        ]

        for future in as_completed(futures):
            host, data = future.result()
            results["hosts"][host] = data

    print_summary(
        results,
        show_all=args.show_all,
        only_active=args.only_active,
        open_ports=args.open_ports
    )


if __name__ == "__main__":
    main()
