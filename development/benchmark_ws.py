#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import time
import multiprocessing
import websocket
import base64

WS_URL = "ws://nextcloud.local/exapps/app-skeleton-python/ws"
AUTH = ("admin", "admin")
PROCESSES = 8
MESSAGES_PER_PROCESS = 1000
RECV_TIMEOUT = 10  # seconds for each recv() call


def worker(num_messages, url, auth):
    """Each worker creates an authenticated WebSocket connection using Basic Auth,
    sends messages, and counts successful echo responses."""
    successful = 0

    # Create the Basic Authorization header.
    credentials = f"{auth[0]}:{auth[1]}".encode("utf-8")  # noqa
    encoded_credentials = base64.b64encode(credentials).decode("utf-8")
    headers = {"Authorization": f"Basic {encoded_credentials}"}

    try:
        ws = websocket.create_connection(url, timeout=RECV_TIMEOUT, header=headers)
        ws.settimeout(RECV_TIMEOUT)
    except Exception as e:
        print(f"WebSocket connection error: {e}")
        return 0

    for i in range(num_messages):
        msg = f"Message {i}"
        try:
            ws.send(msg)
        except Exception as e:
            print(f"Send error: {e}")
            continue

        # Wait for the expected echo response.
        echo_received = False
        start_wait = time.time()
        while time.time() - start_wait < 5:  # Wait up to 5 seconds for each message.
            try:
                resp = ws.recv()
            except Exception:
                continue
            if resp == f"Echo: {msg}":
                echo_received = True
                break
            # Ignore non-echo messages.
        if echo_received:
            successful += 1

    ws.close()
    return successful


def main():
    total_messages = PROCESSES * MESSAGES_PER_PROCESS
    print(f"Starting WebSocket benchmark against {WS_URL} with {PROCESSES} processes, "
          f"{MESSAGES_PER_PROCESS} messages each (total {total_messages}).")
    start_time = time.time()

    with multiprocessing.Pool(PROCESSES) as pool:
        results = [
            pool.apply_async(worker, (MESSAGES_PER_PROCESS, WS_URL, AUTH))
            for _ in range(PROCESSES)
        ]
        pool.close()
        pool.join()

    end_time = time.time()
    total_success = sum(r.get() for r in results)
    total_time = end_time - start_time
    mps = total_success / total_time if total_time > 0 else 0

    print(f"Total messages attempted: {total_messages}")
    print(f"Total successful echoes received: {total_success}")
    print(f"Total time taken: {total_time:.2f} seconds")
    print(f"Messages per second (MPS): {mps:.2f}")


if __name__ == "__main__":
    main()
