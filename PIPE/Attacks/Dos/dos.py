import requests
from concurrent.futures import ThreadPoolExecutor

URL = "http://192.168.29.19:5000/main?search=Piyush"

def hit():
    try:
        requests.get(URL, timeout=2)
    except Exception:
        pass

with ThreadPoolExecutor(max_workers=20) as ex:
    for _ in range(200):
        ex.submit(hit)


# http://192.168.29.19:5000/main?search=a
# http://192.168.29.19:5000/main?search=Piyush
# http://192.168.29.19:5000/api/profile/name&display_name=a
# http://192.168.29.19:5000/api/tweets?q=a