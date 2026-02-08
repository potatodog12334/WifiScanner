import socket

def scan_ports(ip, ports, timeout, limiter):
    open_ports = []

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            pass

        limiter.wait()

    return open_ports
