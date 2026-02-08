import argparse
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from discovery import expand_targets
from ports import detect_service
from rate import rate_limit
from mitre import discovery_metadata
from window import utc_timestamp
from output import print_summary


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


def tcp_scan(host, port, timeout=1.0):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


def scan_host(host, ports, delay, scan_ports, verbose):
    is_active = ping_host(host)

    if not is_active:
        if verbose:
            print(f"[-] {host} inactive (no ping)")
        return host, {
            "active": False,
            "ports": []
        }

    if verbose:
        print(f"[+] {host} active")

    open_ports = []

    if scan_ports:
        for port in ports:
            if tcp_scan(host, port):
                open_ports.append({
                    "port": port,
                    "service": detect_service(port)
                })
                if verbose:
                    print(f"    [+] {host}:{port} open")
            else:
                if verbose:
                    print(f"    [-] {host}:{port} closed")

        rate_limit(delay)

    return host, {
        "active": True,
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

    parser.add_argument(
        "--scan-ports",
        action="store_true",
        help="Scan selected ports on active hosts"
    )

    parser.add_argument(
        "--scan-all-ports",
        action="store_true",
        help="Scan ALL 1–65535 ports on active hosts (slow)"
    )

    args = parser.parse_args()

    # Decide port list
    if args.scan_all_ports:
        ports = list(range(1, 65536))
        scan_ports = True
    elif args.scan_ports:
        ports = [int(p) for p in args.ports.split(",")]
        scan_ports = True
    else:
        ports = []
        scan_ports = False

    targets = expand_targets(args.subnets)

    results = {
        "metadata": {
            "timestamp": utc_timestamp(),
            "mitre_attack": discovery_metadata(),
            "scan_ports": scan_ports,
            "scan_all_ports": args.scan_all_ports
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
