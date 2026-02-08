import time

class RateLimiter:
    def __init__(self, delay):
        self.delay = delay

    def wait(self):
        if self.delay > 0:
            time.sleep(self.delay)
