import subprocess

def passive_hosts():
    hosts = {}

    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")

        for line in output.splitlines():
            if "(" in line and ")" in line:
                ip = line.split("(")[1].split(")")[0]
                hosts[ip] = {
                    "source": "passive",
                    "hostname": None,
                    "ports": []
                }
    except:
        pass

    return hosts
