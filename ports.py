import socket

SERVICE_MAP = {
    22: "ssh",
    80: "http",
    443: "https",
    3389: "rdp"
}

def scan_ports(ip, ports, timeout, limiter, verbose=False):
    open_ports = []

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))

            service = SERVICE_MAP.get(port, "unknown")
            open_ports.append({
                "port": port,
                "service": service
            })

            if verbose:
                print(f"[+] {ip}:{port} open ({service})")

            s.close()
        except:
            if verbose:
                print(f"[-] {ip}:{port} closed")

        limiter.wait()

    return open_ports
