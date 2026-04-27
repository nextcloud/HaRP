# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""K8s ExApp routing integration test.

Verifies that HaRP keeps routing requests to a K8s-deployed ExApp correctly across the full enable/disable lifecycle.
Catches the cache-overwrite bug where AppAPI's `harpExAppUpdate(true)` push (POST /exapp_storage/{appId})
ran at the end of `enableExApp` and replaced the K8s upstream that `/k8s/exapp/expose` had correctly
resolved earlier with the logical Docker-style host (the appId).

Test flow:
  1. Register `app-skeleton-python` on the K8s daemon
    (deploy -> expose -> init -> enable -> harpExAppUpdate(true) chain has fully completed by the time the call returns)
  2. Hit /exapps/<appid>/public via HaRP. The /public route is declared PUBLIC in app-skeleton-python's info.xml,
     so no AppAPI auth headers are needed; we just need HaRP to route successfully
  3. Disable, then re-enable. Re-enable also runs harpExAppUpdate(true)
  4. Hit /public again — must still return 200

Prerequisites (provided by the K8s test workflows):
  - Nextcloud + AppAPI installed, k3s running, HaRP container with K8s backend up, k8s_test daemon registered as default
  - app-skeleton-python image pre-pulled into k3s
  - NODE_IP env var pointing to the k3s node

Env:
  NODE_IP            (required) k3s node IP exposing HaRP and NodePort Services
  HP_SHARED_KEY      HaRP shared key (only used in failure messages)
  K8S_EXPOSE_TYPE    informational; matches the workflow under test
  ROUTING_TEST_RETRIES   override the retry count for routing checks
  ROUTING_TEST_RETRY_INTERVAL  override the per-retry sleep (seconds)
"""

import json
import os
import sys
import time
from subprocess import run

import requests

EXPOSE_TYPE = os.environ.get("K8S_EXPOSE_TYPE", "nodeport")
NODE_IP = os.environ.get("NODE_IP", "")
HP_SHARED_KEY = os.environ.get("HP_SHARED_KEY", "test_shared_key_12345")
MANUAL_CLUSTER_IP = os.environ.get("MANUAL_CLUSTER_IP", "10.43.200.200")
ROUTING_RETRIES = int(os.environ.get("ROUTING_TEST_RETRIES", "15"))
ROUTING_INTERVAL = float(os.environ.get("ROUTING_TEST_RETRY_INTERVAL", "1.0"))

DAEMON = "k8s_test"
APP_ID = "app-skeleton-python"
NAMESPACE = "nextcloud-exapps"
APP_PORT = 23000
SKELETON_XML_URL = "https://raw.githubusercontent.com/nextcloud/app-skeleton-python/main/appinfo/info.xml"


def _harp_url() -> str:
    if not NODE_IP:
        sys.exit("NODE_IP env var required (export from kubectl get node ...)")
    return f"http://{NODE_IP}:8780"


def occ(args: list[str], *, check: bool = False, timeout: int | None = None):
    cmd = ["php", "occ", "--no-warnings", *args]
    return run(cmd, capture_output=True, check=check, timeout=timeout)


def http_get_via_harp(path: str, *, timeout: float = 10.0) -> requests.Response:
    """Hit HaRP's HTTP frontend (port 8780) directly, bypassing nginx."""
    return requests.get(f"{_harp_url()}/exapps/{APP_ID}{path}", timeout=timeout)


def assert_routing_works(label: str) -> None:
    """Make a routed request via HaRP and assert the ExApp pod responded.

    `/public` is a PUBLIC route in app-skeleton-python's info.xml, so it needs no AppAPI auth
    """
    last: str | None = None
    for attempt in range(ROUTING_RETRIES):
        try:
            r = http_get_via_harp("/public")
        except requests.RequestException as e:
            last = f"request error: {e}"
        else:
            if r.status_code == 200:
                print(f"  [{label}] routing OK (attempt {attempt + 1})")
                return
            last = f"HTTP {r.status_code}: {r.text[:200]!r}"
        time.sleep(ROUTING_INTERVAL)

    raise AssertionError(
        f"[{label}] HaRP routing to '{APP_ID}' failed after {ROUTING_RETRIES} attempts: "
        f"{last}\n"
        f"A 404 here typically means HaRP's cached `host` for the ExApp is the appId rather "
        f"than a K8s upstream (NodePort/ClusterIP/LB), and the SPOA agent's resolve_ip() returned NXDOMAIN."
        f"See the comment on haproxy_agent.py:add_exapp."
    )


def ensure_manual_service() -> None:
    """Pre-create the operator-managed Service for manual expose tests.

    For expose_type=manual, HaRP doesn't create a K8s Service — the operator is expected to.
    The k8s_test daemon is registered with a fixed upstream_host (MANUAL_CLUSTER_IP),
    so the Service we create here uses the same ClusterIP. No-op for other expose types.
    """
    if EXPOSE_TYPE != "manual":
        return
    svc_name = f"nc-app-{APP_ID}"
    manifest = json.dumps({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": svc_name, "namespace": NAMESPACE},
        "spec": {
            "clusterIP": MANUAL_CLUSTER_IP,
            "selector": {"app": svc_name},
            "ports": [{"name": "http", "port": APP_PORT, "targetPort": APP_PORT}],
        },
    })
    r = run(
        ["kubectl", "-n", NAMESPACE, "apply", "-f", "-"],
        input=manifest.encode(), capture_output=True,
    )
    if r.returncode != 0:
        sys.exit(
            f"Failed to pre-create operator Service '{svc_name}': "
            f"{r.stderr.decode(errors='replace')}"
        )


def cleanup() -> None:
    occ(
        ["app_api:app:unregister", APP_ID, "--rm-data", "--silent", "--force"],
        timeout=180,
    )
    if EXPOSE_TYPE == "manual":
        run(
            ["kubectl", "-n", NAMESPACE, "delete", "service",
             f"nc-app-{APP_ID}", "--ignore-not-found=true"],
            capture_output=True,
        )


def register_app() -> None:
    print(f"Registering {APP_ID} on daemon '{DAEMON}'...")
    r = occ(
        [
            "app_api:app:register", APP_ID, DAEMON,
            "--info-xml", SKELETON_XML_URL,
            "--wait-finish",
        ],
        timeout=600,
    )
    if r.returncode != 0:
        sys.exit(
            f"Register failed (exit {r.returncode}):\n"
            f"  stdout: {r.stdout.decode(errors='replace')}\n"
            f"  stderr: {r.stderr.decode(errors='replace')}"
        )


def disable_then_enable() -> None:
    print("Disabling...")
    r = occ(["app_api:app:disable", APP_ID], timeout=180)
    if r.returncode != 0:
        sys.exit(f"Disable failed: {r.stdout.decode(errors='replace')}")

    print("Re-enabling...")
    r = occ(["app_api:app:enable", APP_ID], timeout=300)
    if r.returncode != 0:
        sys.exit(f"Enable failed: {r.stdout.decode(errors='replace')}")


def main() -> None:
    print(f"K8s routing test (expose_type={EXPOSE_TYPE}, harp={_harp_url()})")

    cleanup()  # any leftover from a previous test run
    ensure_manual_service()
    register_app()

    try:
        # After register:
        # expose populated cache correctly, then init=100% triggered enableExApp -> harpExAppUpdate(true).
        assert_routing_works("after-register")

        # Re-enable goes through harpExAppUpdate(true) again,
        # exercising the same cache write path without a preceding expose call.
        disable_then_enable()
        assert_routing_works("after-re-enable")

        print("\nPASS: HaRP keeps routing correct across the enable lifecycle.")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
