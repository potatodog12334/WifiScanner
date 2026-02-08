import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from discovery import expand_targets
from ports import detect_service
from rate import rate_limit
from mitre import discovery_metadata
from window import utc_timestamp
from output import print_json


def tcp_scan(host, port, timeout=1.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.close()
        return True
    except Exception:
        return False


def scan_host(host, ports, delay, verbose):
    open_ports = []

    for port in ports:
        if tcp_scan(host, port):
            service = detect_service(port)
            open_ports.append({
                "port": port,
                "service": service
            })
            if verbose:
                print(f"[+] {host}:{port} open ({service})")
        else:
            if verbose:
                print(f"[-] {host}:{port} closed")

    rate_limit(delay)

    return host, {
        "source": "active",
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

    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(",")]
    targets = expand_targets(args.subnets)

    print(f"[i] Targets expanded: {len(targets)} hosts")

    results = {
        "metadata": {
            "engagement": "UNSPECIFIED",
            "timestamp": utc_timestamp(),
            "scan_window": "00:00-23:59",
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
            print(f"[✓] Completed {host}", flush=True)

    print_json(results)


if __name__ == "__main__":
    main()
