import ipaddress
import platform
import socket
import subprocess
from window import within_window

def ping(ip):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    return subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).returncode == 0

def resolve_hostname(ip):
    try:
        return socket.getfqdn(ip)
    except:
        return None

def discover_hosts(subnets, limiter, window):
    hosts = {}

    for subnet in subnets:
        net = ipaddress.IPv4Network(subnet, strict=False)
        if"/" not in subnets:
            print(f"[!] Treating {subnet} as single host (/32)")
            subnet = f"{subnet}/32"
        for ip in net:
            if not within_window(*window):
                return hosts

            ip = str(ip)

            if ip in hosts:
                continue

            if ping(ip):
                hosts[ip] = {
                    "source": "active",
                    "hostname": resolve_hostname(ip),
                    "ports": []
                }

            limiter.wait()

    return hosts
