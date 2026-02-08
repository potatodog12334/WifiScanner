import ipaddress

def expand_targets(target):
    """
    Expand CIDR or return a single IP.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [target]
