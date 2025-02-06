"""An agent for HaProxy that takes care of most of the authentication logic of AppAPI"""

import asyncio
import ipaddress
import logging
import base64
import os
import re
import time
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from aiohttp import web
from haproxyspoa.payloads.ack import AckPayload
from haproxyspoa.spoa_server import SpoaServer


APPID_PATTERN = re.compile(r"(?:^|/)exapps/([^/]+)")
SHARED_KEY = os.environ.get("NC_HAPROXY_SHARED_KEY")
# Set up the logging configuration
LOG_LEVEL = os.environ["HP_LOG_LEVEL"].upper()
logging.basicConfig(level=LOG_LEVEL)
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(level=LOG_LEVEL)
logging.getLogger("haproxyspoa").setLevel(level=LOG_LEVEL)
logging.getLogger("aiohttp").setLevel(level=LOG_LEVEL)

SPOA_AGENT = SpoaServer()

###############################################################################
# In-memory caches
###############################################################################

EXAPP_CACHE_LOCK = asyncio.Lock()
EXAPP_CACHE: dict[str, dict[str, Any]] = {}
"""
Example of EXAPP_CACHE[app_id]:
{
  "exapp_token": str,
  "exapp_version": str,
  "port": int,
  "routes": [
    {
      "url": str,                    # REGEX for URL, e.g. r"^api/w/nextcloud/jobs/.*"
      "access_level": str,           # "ADMIN", "USER", or "PUBLIC"
      "bruteforce_protection": list  # e.g. [401, 403], etc.
    },
    ...
  ]
}
"""

SESSION_CACHE_LOCK = asyncio.Lock()
SESSION_CACHE: dict[str, dict[str, str]] = {}
"""
Example of SESSION_CACHE[session_passphrase]:
{
  "user_id": str,
  "access_level": str  # "ADMIN", "USER", "PUBLIC"
}
"""

BLACKLIST_CACHE_LOCK = asyncio.Lock()
BLACKLIST_CACHE: dict[str, list[float]] = {}  # ip_str -> list of timestamps of failures
BLACKLIST_REQUEST_WINDOW = 300  # 5 minutes in seconds
BLACKLIST_MAX_FAILS_COUNT = 5  # 5 invalid attempts during BLACKLIST_REQUEST_WINDOW


###############################################################################
# BLACKLIST CACHE functions
###############################################################################

async def record_ip_failure(ip_address: str | IPv4Address | IPv6Address) -> None:
    """Record a failed request attempt for this IP using BLACKLIST_CACHE."""
    ip_str = str(ip_address)
    now = time.time()
    async with BLACKLIST_CACHE_LOCK:
        attempts = BLACKLIST_CACHE.get(ip_str, [])
        # Purge attempts that are older than the allowed window.
        attempts = [ts for ts in attempts if now - ts < BLACKLIST_REQUEST_WINDOW]
        attempts.append(now)
        BLACKLIST_CACHE[ip_str] = attempts
        LOGGER.debug("Recorded failure for IP %s. Failures in window: %d", ip_str, len(attempts))


async def is_ip_banned(ip_address: str | IPv4Address | IPv6Address) -> bool:
    """Return True if IP has exceeded the maximum allowed failures in the request window."""
    ip_str = str(ip_address)
    now = time.time()
    async with BLACKLIST_CACHE_LOCK:
        attempts = BLACKLIST_CACHE.get(ip_str, [])
        # Purge expired attempts.
        attempts = [ts for ts in attempts if now - ts < BLACKLIST_REQUEST_WINDOW]
        BLACKLIST_CACHE[ip_str] = attempts
        if len(attempts) >= BLACKLIST_MAX_FAILS_COUNT:
            return True
    return False


###############################################################################
# SPOA Handlers
###############################################################################

@SPOA_AGENT.handler("exapps_msg")
async def exapps_msg(path: str, headers: str, client_ip):
    client_ip_str = str(client_ip)
    LOGGER.debug("Incoming request to ExApp: path=%s, headers=%s, ip=%s", path, headers, client_ip_str)

    # Check if the IP is banned based on failed attempts in BLACKLIST_CACHE.
    if await is_ip_banned(client_ip_str):
        LOGGER.warning("IP %s is banned due to excessive failed attempts.", client_ip_str)
        return AckPayload().set_txn_var("good", 0)

    match = APPID_PATTERN.search(path)
    if not match:
        LOGGER.error("Invalid request path, cannot find AppID: %s", path)
        await record_ip_failure(client_ip_str)
        return AckPayload().set_txn_var("not_found", 1)

    exapp_id = match.group(1)

    if exapp_id == "app_api":
        # Special case: AppAPI can send requests to control this Agent
        reply = AckPayload()
        reply = reply.set_txn_var("app_api", 1)
        if not perform_basic_auth(headers, "app_api", SHARED_KEY):
            await record_ip_failure(client_ip)
            return reply.set_txn_var("app_api_auth", 0)
        reply = reply.set_txn_var("target_path", path.removeprefix(f"/exapps/{exapp_id}"))
        return reply.set_txn_var("app_api_auth", 1)

    async with EXAPP_CACHE_LOCK:
        record = EXAPP_CACHE.get(exapp_id.lower())
        if record is None:
            # TO-DO: query AppAPI endpoint for such record
            record = {
                "exapp_token": "12345",
                "exapp_version": "1.1.1",
                "port": 23000,
                "routes": [
                    {"url": "/http", "access_level": "PUBLIC"},
                    {"url": "/ws", "access_level": "PUBLIC"}
                ]
            }
            #=========================================================================
            EXAPP_CACHE[exapp_id.lower()] = record

    if not record:
        LOGGER.error("No such ExApp enabled: %s", exapp_id)
        await record_ip_failure(client_ip_str)
        return AckPayload().set_txn_var("not_found", 1)

    target_path = path.removeprefix(f"/exapps/{exapp_id}")
    target_port = record["port"]

    route_allowed = False
    for route in record.get("routes", []):
        if route in ("/heartbeat", "/init", "/enabled"):
            route_allowed = True  # this is internal ExApp endpoint - they are always allowed.
            break
        try:
            if re.match(route["url"], target_path):
                route_allowed = True  # TO-DO: we also need to implement access check(ADMIN, USER, PUBLIC)
                break
        except re.error as err:
            LOGGER.error("Invalid regex %s in route for exapp %s: %s", route["url"], exapp_id, err)

    if not route_allowed:
        LOGGER.error("No defined route for handling %s", target_path)
        await record_ip_failure(client_ip_str)
        return AckPayload().set_txn_var("not_found", 1)

    LOGGER.info("Rerouting request to %s:%s", target_path, target_port)

    reply = AckPayload()
    reply = reply.set_txn_var("not_found", 0)
    reply = reply.set_txn_var("app_api", 0)
    reply = reply.set_txn_var("target_port", target_port)
    reply = reply.set_txn_var("target_path", target_path)
    reply = reply.set_txn_var("exapp_token", record["exapp_token"])
    reply = reply.set_txn_var("exapp_version", record["exapp_version"])
    reply = reply.set_txn_var("exapp_id", exapp_id)
    return reply


@SPOA_AGENT.handler("basic_auth_msg")
async def basic_auth_msg(headers: str, client_ip):
    LOGGER.debug("Received headers: %s, from IP: %s", headers, client_ip)
    auth_ok = perform_basic_auth(headers, "app_api", SHARED_KEY)
    if auth_ok:
        LOGGER.debug("Basic auth succeeded for IP: %s", client_ip)
    else:
        await record_ip_failure(client_ip)
    return AckPayload().set_txn_var("good", auth_ok)


@SPOA_AGENT.handler("check_client_ip_msg")
async def check_client_ip(client_ip):
    client_ip_str = str(client_ip)
    if await is_ip_banned(client_ip_str):
        LOGGER.warning("IP %s is banned due to excessive failed attempts.", client_ip_str)
        return AckPayload().set_txn_var("good", 0)

    LOGGER.debug("IP %s is allowed. GOOD.", client_ip_str)
    return AckPayload().set_txn_var("good", 1)


###############################################################################
# Helper functions
###############################################################################

def perform_basic_auth(headers: str, username: str, password: str) -> bool:
    # Parse the headers to find the Authorization header.
    auth_line = None
    for line in headers.splitlines():
        if line.lower().startswith("authorization:"):
            auth_line = line
            break

    if auth_line is None:
        LOGGER.error("Authorization header not found.")
        return False
    try:
        # Split on the colon to extract the value.
        _, value = auth_line.split(":", 1)
        value = value.strip()
        if not value.startswith("Basic "):
            LOGGER.error("Authorization header does not use Basic authentication.")
            return False

        encoded_credentials = value[6:].strip()
        decoded_str = base64.b64decode(encoded_credentials).decode("utf-8")
        if ":" not in decoded_str:
            LOGGER.error("Invalid credentials format.")
            return False

        in_username, in_password = decoded_str.split(":", 1)
        if in_username == username and in_password == password:
            return True
        LOGGER.error("Invalid username or password.")
    except Exception as e:
        LOGGER.error("Error processing basic auth credentials: %s", e)
    return False


async def nc_get_exapp(appid: str) -> dict[str, Any] | None:
    pass


###############################################################################
# ExApp routes
###############################################################################

async def list_exapps(request: web.Request):
    return web.json_response(EXAPP_CACHE)


async def get_exapp(request: web.Request):
    async with EXAPP_CACHE_LOCK:
        record = EXAPP_CACHE.get(request.match_info["app_id"].lower())
    if record is None:
        raise web.HTTPNotFound()
    return web.json_response(record)


async def add_exapp(request: web.Request):
    data = await request.json()
    if not isinstance(data, dict):
        raise web.HTTPBadRequest()
    if "app_api_token" not in data or not isinstance(data["app_api_token"], str):
        raise web.HTTPBadRequest()
    if "routes" not in data or not isinstance(data["routes"], list):
        raise web.HTTPBadRequest()

    for route in data["routes"]:
        if not isinstance(route, dict):
            raise web.HTTPBadRequest()
        if "url" not in route or not isinstance(route["url"], str):
            raise web.HTTPBadRequest()
        if "access_level" not in route or route["access_level"] not in ["ADMIN", "USER", "PUBLIC"]:
            raise web.HTTPBadRequest()
        if "bruteforce_protection" in route:
            if not isinstance(route["bruteforce_protection"], list):
                raise web.HTTPBadRequest()
            for code in route["bruteforce_protection"]:
                if not isinstance(code, int):
                    raise web.HTTPBadRequest()

    # Overwrite if already exists
    async with EXAPP_CACHE_LOCK:
        EXAPP_CACHE[request.match_info["app_id"].lower()] = data
    return web.HTTPNoContent()


async def delete_exapp(request: web.Request):
    async with EXAPP_CACHE_LOCK:
        old = EXAPP_CACHE.pop(request.match_info["app_id"].lower(), None)
    if old is None:
        raise web.HTTPNotFound()
    return web.HTTPNoContent()


###############################################################################
# Session routes
###############################################################################

async def list_sessions(request: web.Request):
    return web.json_response(SESSION_CACHE)


async def get_session(request: web.Request):
    record = SESSION_CACHE.get(request.match_info["passphrase"])
    if record is None:
        raise web.HTTPNotFound()
    return web.json_response(record)


async def add_session(request: web.Request):
    data = await request.json()
    if not isinstance(data, dict):
        raise web.HTTPBadRequest()
    if "user_id" not in data or not isinstance(data["user_id"], str):
        raise web.HTTPBadRequest()
    if "access_level" not in data or data["access_level"] not in ["ADMIN", "USER", "PUBLIC"]:
        raise web.HTTPBadRequest()

    # Overwrite if already exists
    SESSION_CACHE[request.match_info["passphrase"]] = data
    return web.HTTPNoContent()


async def delete_session(request: web.Request):
    old = SESSION_CACHE.pop(request.match_info["passphrase"], None)
    if old is None:
        raise web.HTTPNotFound()
    return web.HTTPNoContent()


###############################################################################
# Blacklist Cache clearance routes
###############################################################################

async def clear_blacklist_ip(request: web.Request):
    """Clear the blacklist cache for a specific IP."""
    ip = request.match_info["ip"]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise web.HTTPBadRequest() from None

    async with BLACKLIST_CACHE_LOCK:
        if ip in BLACKLIST_CACHE:
            del BLACKLIST_CACHE[ip]
            LOGGER.info("Cleared blacklist cache for IP %s", ip)
            return web.HTTPNoContent()
        raise web.HTTPNotFound()


async def clear_blacklist_cache(request: web.Request):
    """Clear the entire blacklist cache."""
    async with BLACKLIST_CACHE_LOCK:
        BLACKLIST_CACHE.clear()
    LOGGER.info("Cleared entire blacklist cache.")
    return web.Response(text="Cleared entire blacklist cache.")


###############################################################################
# Special routes for AppAPI
###############################################################################

async def get_frp_certificates(request: web.Request):
    """
    Returns the generated FRP TLS certificate files for the client:
      - client.crt, ca.crt, client.key
    If any of these files do not exist, TLS is considered disabled.
    """
    cert_dir = "/certs/frp"
    client_crt_path = os.path.join(cert_dir, "client.crt")
    ca_crt_path = os.path.join(cert_dir, "ca.crt")
    client_key_path = os.path.join(cert_dir, "client.key")

    if not (os.path.exists(client_crt_path) and os.path.exists(ca_crt_path) and os.path.exists(client_key_path)):
        return web.json_response({"tls_enabled": False})

    with open(client_crt_path) as f:
        client_crt = f.read()
    with open(ca_crt_path) as f:
        ca_crt = f.read()
    with open(client_key_path) as f:
        client_key = f.read()

    return web.json_response({
        "tls_enabled": True,
        "ca_crt": ca_crt,
        "client_crt": client_crt,
        "client_key": client_key,
    })


###############################################################################
# FRP Plugin Authentication
###############################################################################

async def frp_auth(request: web.Request):
    if request.method != "POST":
        raise web.HTTPBadRequest()
    try:
        json_data = await request.json()
        client_ip = str(json_data["content"]["client_address"]).split(":")[0]
    except Exception:
        raise web.HTTPBadRequest() from None

    if await is_ip_banned(client_ip):
        return web.json_response({"reject": True, "reject_reason": "banned"})

    auth_token = json_data["content"]["metas"].get("token", "")
    if auth_token == SHARED_KEY:
        return web.json_response({"reject": False, "unchange": True})

    await record_ip_failure(client_ip)
    raise web.HTTPBadRequest()


###############################################################################
# HTTP Server Setup
###############################################################################

def create_web_app() -> web.Application:
    app = web.Application()

    # ExApp routes
    app.router.add_get("/exapp_storage", list_exapps)
    app.router.add_get("/exapp_storage/{app_id}", get_exapp)
    app.router.add_post("/exapp_storage/{app_id}", add_exapp)
    app.router.add_delete("/exapp_storage/{app_id}", delete_exapp)

    # Session routes
    app.router.add_get("/session_storage", list_sessions)
    app.router.add_get("/session_storage/{passphrase}", get_session)
    app.router.add_post("/session_storage/{passphrase}", add_session)
    app.router.add_delete("/session_storage/{passphrase}", delete_session)

    # Blacklist
    app.router.add_delete("/blacklist_cache/ip/{ip}", clear_blacklist_ip)
    app.router.add_delete("/blacklist_cache", clear_blacklist_cache)

    # FRP certificates
    app.router.add_get("/frp_certificates", get_frp_certificates)

    # FRP auth
    app.router.add_post("/frp_handler", frp_auth)
    return app


async def run_http_server(host="127.0.0.1", port=8200):
    app = create_web_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    LOGGER.info("HTTP server listening at %s:%s", host, port)
    await site.start()
    while True:
        await asyncio.sleep(3600)


###############################################################################
# Main entry point: run both SPOA & HTTP
###############################################################################

async def main():
    spoa_task = asyncio.create_task(SPOA_AGENT._run(host="127.0.0.1", port=9600))  # noqa
    http_task = asyncio.create_task(run_http_server(host="127.0.0.1", port=8200))

    LOGGER.info("Starting both servers: SPOA on 127.0.0.1:9600, HTTP on 127.0.0.1:8200")
    await asyncio.gather(spoa_task, http_task)


if __name__ == "__main__":
    asyncio.run(main())
    SPOA_AGENT.run()
