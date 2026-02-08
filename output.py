import json
from datetime import datetime
from mitre import MITRE_MAPPING

def emit(hosts, engagement, window, rate):
    output = {
        "metadata": {
            "engagement": engagement,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "scan_window": window,
            "rate_limit_seconds": rate,
            "mitre_attack": MITRE_MAPPING
        },
        "hosts": hosts
    }

    print(json.dumps(output, indent=2))
