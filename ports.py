import socket

SERVICE_MAP = {
    22: "ssh",
    80: "http",
    443: "https",
    3389: "rdp"
}

def detect_service(port):
    return SERVICE_MAP.get(port, "unknown")


def ssh_reachable(host, timeout=2):
    try:
        sock = socket.create_connection((host, 22), timeout=timeout)
        banner = sock.recv(64).decode(errors="ignore")
        sock.close()
        return banner.startswith("SSH")
    except Exception:
        return False


def rdp_reachable(host, timeout=2):
    try:
        sock = socket.create_connection((host, 3389), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False
