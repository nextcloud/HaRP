#!/usr/bin/env python3

import time
import requests
import multiprocessing
import random

ADD_BAN_URL = "http://127.0.0.1:8784/blacklist/ip/"
EXAPPS_URL = "http://127.0.0.1:8784/exapp_storage"
AUTH = ("app_api_harp", "mysecret")
PROCESSES = 8
REQUESTS_PER_PROCESS = 1000

RANDOM_BAN_IPS = 1000
WHITELIST_IP = ["172.17.0.1"]


def worker(num_requests, url, auth):
    """Each worker sends `num_requests` GET requests and returns how many received the expected response."""
    session = requests.Session()
    session.auth = auth
    successful = 0

    for _ in range(num_requests):
        try:
            r = session.get(url)
            # Check status and that response body is exactly "{}"
            if r.status_code == 200 and r.text.strip() == "{}":
                successful += 1
        except Exception as e:
            # For real benchmarks, you might want to log or ignore these
            print(f"Request error: {e}")

    return successful


def main():
    total_requests = PROCESSES * REQUESTS_PER_PROCESS
    print(f"Starting benchmark against {EXAPPS_URL} with {PROCESSES} processes, "
          f"{REQUESTS_PER_PROCESS} requests each (total {total_requests}).")

    start_time = time.time()

    # Create a process pool
    with multiprocessing.Pool(PROCESSES) as pool:
        # Launch all workers
        results = [
            pool.apply_async(worker, (REQUESTS_PER_PROCESS, EXAPPS_URL, AUTH))
            for _ in range(PROCESSES)
        ]
        pool.close()
        pool.join()

    end_time = time.time()

    total_success = sum(r.get() for r in results)
    total_time = end_time - start_time
    rps = total_success / total_time if total_time > 0 else 0

    print(f"Total requests attempted: {total_requests}")
    print(f"Total successful responses: {total_success}")
    print(f"Total time taken: {total_time:.2f} seconds")
    print(f"Requests per second (RPS): {rps:.2f}")


if __name__ == "__main__":
    print("=======================================================")
    ban_session = requests.Session()
    ban_session.auth = AUTH
    start_ban_time = time.time()
    for _ in range(RANDOM_BAN_IPS):
        while True:
            # Randomly generate a.b.c.d in [0..255], with a in [1..255] to avoid 0.x.x.x
            a = random.randint(1, 255)
            b = random.randint(0, 255)
            c = random.randint(0, 255)
            d = random.randint(0, 255)

            random_ip = f"{a}.{b}.{c}.{d}"

            # Skip if it's the IP you need to exclude
            if random_ip in WHITELIST_IP:
                continue

            # Add to the set
            ban_url = ADD_BAN_URL + random_ip
            r = ban_session.post(ban_url)
            if r.status_code != 204:
                raise ValueError(f"Invalid response code: {r.status_code} for url: {ban_url}")
            # Break from the while-loop to move on to the next of the 100,000
            break
    print(f"Time taken for ban: {time.time() - start_ban_time:.2f} seconds ({RANDOM_BAN_IPS} ban records)")
    print("=======================================================")
    main()
