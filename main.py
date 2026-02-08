import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from discovery import expand_targets
from ports import detect_service, ssh_reachable, rdp_reachable
from rate import rate_limit
from mitre import discovery_metadata
from window import utc_timestamp
from output import stream_host, final_output, progress


def tcp_scan(host, port, timeout=1.0):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


def scan_host(host, ports, delay, verbose):
    open_ports = []
    reachability = {}

    for port in ports:
        if tcp_scan(host, port):
            service = detect_service(port)
            entry = {"port": port, "service": service}

            if port == 22:
                entry["ssh_reachable"] = ssh_reachable(host)
            if port == 3389:
                entry["rdp_reachable"] = rdp_reachable(host)

            open_ports.append(entry)

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
    parser.add_argument("--stream", action="store_true")

    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(",")]
    targets = expand_targets(args.subnets)
    total = len(targets)

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

    completed = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(scan_host, h, ports, args.rate_limit, args.verbose)
            for h in targets
        ]

        for future in as_completed(futures):
            host, data = future.result()
            results["hosts"][host] = data
            completed += 1

            progress(completed, total)

            if args.stream:
                stream_host(host, data)

    if not args.stream:
        final_output(results)


if __name__ == "__main__":
    main()
