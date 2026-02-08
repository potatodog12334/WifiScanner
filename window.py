from datetime import datetime

def in_scan_window(window="00:00-23:59"):
    """
    Placeholder for future enforcement.
    Always returns True for now.
    """
    return True

def utc_timestamp():
    return datetime.utcnow().isoformat() + "Z"
