SERVICE_MAP = {
    22: "ssh",
    80: "http",
    443: "https",
    3389: "rdp"
}

def detect_service(port):
    return SERVICE_MAP.get(port, "unknown")
