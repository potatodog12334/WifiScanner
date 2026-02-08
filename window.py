from datetime import datetime, time as dtime

def parse_window(window):
    start, end = window.split("-")
    h1, m1 = map(int, start.split(":"))
    h2, m2 = map(int, end.split(":"))
    return dtime(h1, m1), dtime(h2, m2)

def within_window(start, end):
    now = datetime.now().time()
    return start <= now <= end
