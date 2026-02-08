import json
import sys

def stream_host(host, data):
    """
    Stream a single host result as JSON (one line).
    """
    record = {host: data}
    print(json.dumps(record), flush=True)


def final_output(results):
    """
    Print final aggregated JSON.
    """
    print(json.dumps(results, indent=2))


def progress(current, total):
    percent = int((current / total) * 100)
    bar_len = 30
    filled = int(bar_len * current / total)
    bar = "#" * filled + "-" * (bar_len - filled)
    sys.stdout.write(f"\r[{bar}] {percent}% ({current}/{total})")
    sys.stdout.flush()

    if current == total:
        print()
