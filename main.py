import argparse
from discovery import discover_hosts
from passive import passive_hosts
from ports import scan_ports
from rate import RateLimiter
from window import parse_window
from output import emit

def main():
    parser = argparse.ArgumentParser(
        description="Authorized Network Visibility Scanner (Discovery Only)"
    )

    parser.add_argument("--subnets", required=True)
    parser.add_argument("--ports", default="22,80,443,3389")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--rate", type=float, default=0.2)
    parser.add_argument("--window", default="00:00-23:59")
    parser.add_argument("--engagement", default="UNSPECIFIED")

    args = parser.parse_args()

    subnets = [s.strip() for s in args.subnets.split(",")]
    ports = [int(p.strip()) for p in args.ports.split(",")]
    window = parse_window(args.window)
    limiter = RateLimiter(args.rate)

    # Passive first
    hosts = passive_hosts()

    # Active discovery
    active_hosts = discover_hosts(subnets, limiter, window)
    hosts.update(active_hosts)

    # Port scanning
    for ip in hosts:
        hosts[ip]["ports"] = scan_ports(
            ip,
            ports,
            args.timeout,
            limiter
        )

    emit(
        hosts,
        args.engagement,
        args.window,
        args.rate
    )

if __name__ == "__main__":
    main()
