#!/usr/bin/env python3

import time
import requests
import multiprocessing

EXAPPS_URL = "http://127.0.0.1:8780/exapps/test/http"
AUTH = ("app_api", "mysecret")
PROCESSES = 6
REQUESTS_PER_PROCESS = 1000


def worker(num_requests, url, auth):
    """Each worker sends `num_requests` GET requests and returns how many received the expected response."""
    session = requests.Session()
    session.auth = auth
    successful = 0

    for _ in range(num_requests):
        try:
            r = session.get(url)
            # Check status and that response body is exactly "{}"
            if r.status_code == 200 and r.text.strip() == '{"message":"Hello from HTTP endpoint!"}':
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
    main()
