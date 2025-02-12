"""An agent for HaProxy that takes care of most of the authentication logic of AppAPI. Python 3.12 required."""

import asyncio
import ipaddress
import logging
import os
import re
import time
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address

import aiohttp
import pydantic
from aiohttp import web
from haproxyspoa.payloads.ack import AckPayload
from haproxyspoa.spoa_server import SpoaServer
from pydantic import BaseModel, Field

APPID_PATTERN = re.compile(r"(?:^|/)exapps/([^/]+)")
SHARED_KEY = os.environ.get("HP_SHARED_KEY")
NC_INSTANCE_URL = os.environ.get("NC_INSTANCE_URL")
# Set up the logging configuration
LOG_LEVEL = os.environ["HP_LOG_LEVEL"].upper()
logging.basicConfig(level=LOG_LEVEL)
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(level=LOG_LEVEL)
logging.getLogger("haproxyspoa").setLevel(level=LOG_LEVEL)
logging.getLogger("aiohttp").setLevel(level=LOG_LEVEL)

SPOA_AGENT = SpoaServer()

###############################################################################
# Definitions
###############################################################################

class AccessLevel(IntEnum):
    PUBLIC = 0
    USER = 1
    ADMIN = 2


class ExAppRoute(BaseModel):
    url: str = Field(..., description="REGEX for URL, e.g. r'^api/w/nextcloud/jobs/.*'")
    access_level: AccessLevel = Field(..., description="ADMIN(2), USER(1), or PUBLIC(0)")
    bruteforce_protection: list[int] = Field([], description="e.g. [401, 403], etc.")


class ExApp(BaseModel):
    exapp_token: str = Field(...)
    exapp_version: str = Field(...)
    port: int = Field(...)
    routes: list[ExAppRoute] = Field([])


class NcUser(BaseModel):
    user_id: str | None = Field(default=None)
    access_level: AccessLevel = Field(..., description="ADMIN(2), USER(1), or PUBLIC(0)")


###############################################################################
# In-memory caches
###############################################################################

EXAPP_CACHE_LOCK = asyncio.Lock()
EXAPP_CACHE: dict[str, ExApp] = {}

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
    reply = AckPayload()
    LOGGER.debug("Incoming request to ExApp: path=%s, headers=%s, ip=%s", path, headers, client_ip_str)

    # Check if the IP is banned based on failed attempts in BLACKLIST_CACHE.
    if await is_ip_banned(client_ip_str):
        LOGGER.warning("IP %s is banned due to excessive failed attempts.", client_ip_str)
        return reply.set_txn_var("bad_request", 1)

    match = APPID_PATTERN.search(path)
    if not match:
        LOGGER.error("Invalid request path, cannot find AppID: %s", path)
        await record_ip_failure(client_ip_str)
        return reply.set_txn_var("not_found", 1)
    exapp_id = match.group(1)
    exapp_id_lower = exapp_id.lower()
    target_path = path.removeprefix(f"/exapps/{exapp_id}")
    reply = reply.set_txn_var("target_path", target_path)

    request_headers = parse_headers(headers)
    if exapp_id == "app_api":
        LOGGER.debug("Request from AppAPI received: %s", target_path)
        # Special case: AppAPI can send requests to control this Agent
        if request_headers.get("harp-shared-key") != SHARED_KEY:
            await record_ip_failure(client_ip)
            return reply.set_txn_var("unauthorized", 1)
        docker_engine_port = request_headers.get("docker-engine-port")
        if docker_engine_port:
            reply = reply.set_txn_var("target_port", int(docker_engine_port))
            return reply.set_txn_var("backend", "docker_engine_backend")
        return reply.set_txn_var("backend", "nextcloud_control_backend")

    nextcloud_direct_request = False
    exapp_record = None
    if all(
        key in request_headers
        for key in ["ex-app-version", "ex-app-id", "ex-app-port", "authorization-app-api", "harp-shared-key"]
    ):
        # This is a direct request from AppAPI to ExApp using AppAPI PHP functions "requestToExAppXXX"
        if request_headers["harp-shared-key"] == SHARED_KEY:
            nextcloud_direct_request = True
            exapp_record = ExApp(
                exapp_token=request_headers["authorization-app-api"],
                exapp_version=request_headers["ex-app-version"],
                port=int(request_headers["ex-app-port"]),
            )
        else:
            await record_ip_failure(client_ip)
            return reply.set_txn_var("bad_request", 1)

    if not exapp_record:
        async with EXAPP_CACHE_LOCK:
            exapp_record = EXAPP_CACHE.get(exapp_id_lower)
            if not exapp_record:
                try:
                    exapp_record = await nc_get_exapp(exapp_id_lower)
                    if not exapp_record:
                        LOGGER.error("No such ExApp enabled: %s", exapp_id)
                        await record_ip_failure(client_ip_str)
                        return reply.set_txn_var("not_found", 1)
                    EXAPP_CACHE[exapp_id_lower] = exapp_record
                except pydantic.ValidationError as e:
                    LOGGER.error("Invalid ExApp metadata from Nextcloud: %s", e)
                    return reply.set_txn_var("not_found", 1)
                except Exception as e:
                    LOGGER.exception("Failed to fetch ExApp metadata from Nextcloud", exc_info=e)
                    return reply.set_txn_var("not_found", 1)

    route_allowed = False
    if target_path in ("/heartbeat", "/init", "/enabled"):
        if not nextcloud_direct_request:
            await record_ip_failure(client_ip_str)
            return reply.set_txn_var("bad_request", 1)
        route_allowed = True  # this is internal ExApp endpoint and request comes from AppAPI
    else:
        for route in exapp_record.routes:
            try:
                if re.match(route.url, target_path):
                    if route.access_level == AccessLevel.PUBLIC:
                        route_allowed = True
                        break

                    user = nc_get_user(request_headers)
                    if route.access_level <= user.access_level:
                        route_allowed = True
                        break

                    LOGGER.error("Access denied for %s to %s", user.user_id, target_path)
                    await record_ip_failure(client_ip_str)
                    return reply.set_txn_var("unauthorized", 1) # todo: or forbidden
            except re.error as err:
                LOGGER.error("Invalid regex %s in route for exapp %s: %s", route.url, exapp_id, err)

    if not route_allowed:
        LOGGER.error("No defined route for handling %s", target_path)
        await record_ip_failure(client_ip_str)
        return reply.set_txn_var("not_found", 1)

    LOGGER.info("Rerouting request to %s:%s", target_path, exapp_record.port)
    reply = reply.set_txn_var("backend", "ex_apps_backend")
    reply = reply.set_txn_var("target_port", exapp_record.port)
    reply = reply.set_txn_var("exapp_token", exapp_record.exapp_token)
    reply = reply.set_txn_var("exapp_version", exapp_record.exapp_version)
    return reply.set_txn_var("exapp_id", exapp_id)


###############################################################################
# Helper functions
###############################################################################


def parse_headers(headers_str: str) -> dict[str, str]:
    """Parse a string containing HTTP headers into a dictionary.

    Each header should be on its own line in the format "Header-Name: value".
    The header names are normalized to lowercase.
    """
    headers = {}
    for line in headers_str.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            LOGGER.info("Malformed line in header: %s", line)
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


EX_APP_URL = f"{ \
    NC_INSTANCE_URL.removesuffix('/').removesuffix('/index.php') \
}/index.php/apps/app_api/harp/exapp-meta"


async def nc_get_exapp(app_id: str) -> ExApp | None:
    async with aiohttp.ClientSession() as session, session.get(
        EX_APP_URL, headers={"harp-shared-key": SHARED_KEY}, params={"appId": app_id}
    ) as resp:
        if not resp.ok:
            if resp.status == 404:
                return None
            raise Exception("Failed to fetch ExApp metadata from Nextcloud.", await resp.text())
        data = await resp.json()
        return ExApp.model_validate(data)


USER_INFO_URL = f"{ \
    NC_INSTANCE_URL.removesuffix('/').removesuffix('/index.php') \
}/index.php/apps/app_api/harp/user-info"
EXCLUDE_HEADERS_USER_INFO = {
    "host": None
}


async def nc_get_user(all_headers: dict[str, str]) -> NcUser | None:
    ext_headers = {k: v for k, v in all_headers.items() if k.lower() not in EXCLUDE_HEADERS_USER_INFO}
    # todo
    LOGGER.debug("all_headers = %s\next_headers = %s", str(all_headers), str(ext_headers))
    async with aiohttp.ClientSession() as session, session.get(
        EX_APP_URL, headers={"harp-shared-key": SHARED_KEY, **ext_headers}
    ) as resp:
        if not resp.ok:
            LOGGER.debug("Failed to fetch ExApp metadata from Nextcloud.", await resp.text())
            if resp.status // 100 == 4:
                return None
            raise Exception("Failed to fetch ExApp metadata from Nextcloud.", await resp.text())
        data = await resp.json()
        return NcUser.model_validate(data)


###############################################################################
# ExApp routes
###############################################################################


async def add_exapp(request: web.Request):
    data = await request.json()
    if not isinstance(data, dict):
        raise web.HTTPBadRequest()

    # Overwrite if already exists
    async with EXAPP_CACHE_LOCK:
        EXAPP_CACHE[request.match_info["app_id"].lower()] = ExApp.model_validate(data)
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
    """Returns the generated FRP TLS certificate files(client.crt, ca.crt, client.key) for the client.

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

    return web.json_response(
        {
            "tls_enabled": True,
            "ca_crt": ca_crt,
            "client_crt": client_crt,
            "client_key": client_key,
        }
    )


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
    app.router.add_post("/exapp_storage/{app_id}", add_exapp)
    app.router.add_delete("/exapp_storage/{app_id}", delete_exapp)

    # Session routes
    app.router.add_post("/session_storage/{passphrase}", add_session)
    app.router.add_delete("/session_storage/{passphrase}", delete_session)

    # Blacklist
    app.router.add_delete("/blacklist_cache/ip/{ip}", clear_blacklist_ip)
    app.router.add_delete("/blacklist_cache", clear_blacklist_cache)

    # FRP certificates
    app.router.add_get("/frp_certificates", get_frp_certificates)

    # FRP auth (FRP Server will call it)
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
