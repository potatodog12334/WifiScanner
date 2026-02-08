import time

def rate_limit(seconds):
    if seconds > 0:
        time.sleep(seconds)
