
import requests
import time
from concurrent.futures import ThreadPoolExecutor

URL = "http://127.0.0.1:5000/test"

def send_request(_):
    try:
        requests.get(URL, timeout=5)
    except requests.RequestException as e:
        print("Request failed:", e)

print("Generating local test traffic...")

for batch in range(10):
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(send_request, range(20))

    print("Requests sent:", (batch + 1) * 20)
    time.sleep(1)

print("Test completed!")

