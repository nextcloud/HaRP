"""An agent for HaProxy that takes care of most of the authentication logic of AppAPI. Python 3.12 required."""

# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
from base64 import b64encode
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Self

import aiohttp
from aiohttp import web
from haproxyspoa.payloads.ack import AckPayload
from haproxyspoa.spoa_server import SpoaServer
from pydantic import BaseModel, Field, ValidationError, model_validator

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

NC_REQ_URL = NC_INSTANCE_URL.removesuffix("/").removesuffix("/index.php")
EX_APP_URL = f"{NC_REQ_URL}/index.php/apps/app_api/harp/exapp-meta"
USER_INFO_URL = f"{NC_REQ_URL}/index.php/apps/app_api/harp/user-info"
EXCLUDE_HEADERS_USER_INFO = {"host", "content-length"}

SPOA_AGENT = SpoaServer()

###############################################################################
# Definitions
###############################################################################


class AccessLevel(IntEnum):
    PUBLIC = 0
    USER = 1
    ADMIN = 2


class ExAppRoute(BaseModel):
    url: str = Field(..., description="REGEX for URL, e.g. r'^/private/.*'")
    access_level: AccessLevel = Field(..., description="ADMIN(2), USER(1), or PUBLIC(0)")
    bruteforce_protection: list[int] = Field(
        [], description="List with HTTP statuses to trigger the bruteforce protection."
    )
    str_bruteforce_protection: str = Field(
        "", description="Private field, that will be automatically initialized from the 'bruteforce_protection' value."
    )

    @model_validator(mode="after")
    def encode_bruteforce_protection_values(self) -> Self:
        self.str_bruteforce_protection = json.dumps(self.bruteforce_protection) if self.bruteforce_protection else ""
        return self


class ExApp(BaseModel):
    exapp_token: str = Field(...)
    exapp_version: str = Field(...)
    port: int = Field(...)
    routes: list[ExAppRoute] = Field([])


class NcUser(BaseModel):
    user_id: str = Field("", description="The Nextcloud user ID if not an anonymous user.")
    access_level: AccessLevel = Field(..., description="ADMIN(2), USER(1), or PUBLIC(0)")


###############################################################################
# In-memory caches
###############################################################################

EXAPP_CACHE_LOCK = asyncio.Lock()
EXAPP_CACHE: dict[str, ExApp] = {}

SESSION_CACHE_LOCK = asyncio.Lock()
SESSION_CACHE: dict[str, tuple[NcUser, float]] = {}  # Stores NcUser and timestamp
SESSION_REQUEST_WINDOW = float(os.environ.get("HP_SESSION_LIFETIME", "3"))  # Keep session information for 3 seconds
if SESSION_REQUEST_WINDOW < 0:
    raise ValueError("`HP_SESSION_LIFETIME` cannot be less than 0")
if SESSION_REQUEST_WINDOW > 10:
    raise ValueError("`HP_SESSION_LIFETIME` cannot be greater than 10")

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
# SESSION CACHE functions
###############################################################################


async def record_session(pass_cookie: str, nc_user: NcUser) -> None:
    now = time.time()
    async with SESSION_CACHE_LOCK:
        SESSION_CACHE[pass_cookie] = (nc_user, now)
    LOGGER.error("Recorded session for cookie %s, User %s", pass_cookie, nc_user.user_id)


async def get_session(pass_cookie: str) -> NcUser | None:
    """Retrieve the session for the given IP address."""
    now = time.time()
    async with SESSION_CACHE_LOCK:
        session_data = SESSION_CACHE.get(pass_cookie)
        if session_data:
            nc_user, timestamp = session_data
            # Check if the session is still valid based on the SESSION_REQUEST_WINDOW
            if now - timestamp <= SESSION_REQUEST_WINDOW:
                return nc_user
            # Session expired, remove it
            del SESSION_CACHE[pass_cookie]
            LOGGER.error("Session for cookie %s expired", pass_cookie)
    return None


###############################################################################
# SPOA Handlers
###############################################################################


@SPOA_AGENT.handler("exapps_msg")
async def exapps_msg(
    path: str, headers: str, client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, pass_cookie: str
) -> AckPayload:
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

    # Special handling for AppAPI requests
    if exapp_id == "app_api":
        return await handle_app_api_request(target_path, request_headers, client_ip_str, reply)

    exapp_route_bruteforce_protection = None
    authorization_app_api = ""
    exapp_record = None
    if all(
        key in request_headers
        for key in ["ex-app-version", "ex-app-id", "ex-app-port", "authorization-app-api", "harp-shared-key"]
    ):
        # This is a direct request from AppAPI to ExApp using AppAPI PHP functions "requestToExAppXXX"
        if request_headers["harp-shared-key"] != SHARED_KEY:
            await record_ip_failure(client_ip)
            return reply.set_txn_var("bad_request", 1)
        exapp_record = ExApp(
            exapp_token="",
            exapp_version=request_headers["ex-app-version"],
            port=int(request_headers["ex-app-port"]),
        )
        authorization_app_api = request_headers["authorization-app-api"]

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
                    LOGGER.info("Received new ExApp record: %s", exapp_record)
                    EXAPP_CACHE[exapp_id_lower] = exapp_record
                except ValidationError as e:
                    LOGGER.error("Invalid ExApp metadata from Nextcloud: %s", e)
                    return reply.set_txn_var("not_found", 1)
                except Exception as e:
                    LOGGER.exception("Failed to fetch ExApp metadata from Nextcloud", exc_info=e)
                    return reply.set_txn_var("not_found", 1)

    route_allowed = False
    if authorization_app_api:
        route_allowed = True  # We skip routes checking for AppAPI signed requests
    elif target_path in ("/heartbeat", "/init", "/enabled"):
        LOGGER.error("Only requests from AppAPI allowed to the internal endpoints.")
        await record_ip_failure(client_ip_str)
        return reply.set_txn_var("bad_request", 1)
    else:
        nc_user = None
        if pass_cookie or "authorization" in request_headers:
            # We also pass requests with "authorization" to the Nextcloud to support App Passwords and Basic Auth.
            nc_user = await get_session(pass_cookie)
            if not nc_user:
                try:
                    nc_user = await nc_get_user(exapp_id_lower, request_headers)
                    if nc_user and pass_cookie:
                        await record_session(pass_cookie, nc_user)
                except ValidationError as e:
                    LOGGER.error("Invalid user info from Nextcloud: %s", e)
                    return reply.set_txn_var("unauthorized", 1)
                except Exception as e:
                    LOGGER.exception("Failed to fetch user info from Nextcloud", exc_info=e)
                    return reply.set_txn_var("unauthorized", 1)

        for route in exapp_record.routes:
            try:
                if re.match(route.url, target_path):
                    if route.access_level == AccessLevel.PUBLIC:
                        exapp_route_bruteforce_protection = route.str_bruteforce_protection
                        route_allowed = True
                        break

                    if nc_user and route.access_level <= nc_user.access_level:
                        exapp_route_bruteforce_protection = route.str_bruteforce_protection
                        route_allowed = True
                        break

                    LOGGER.error("Access denied for '%s' to %s", nc_user.user_id if nc_user else "", target_path)
                    await record_ip_failure(client_ip_str)
                    return reply.set_txn_var("forbidden", 1)
            except re.error as err:
                LOGGER.error("Invalid regex %s in route for exapp %s: %s", route.url, exapp_id, err)

    if not route_allowed:
        LOGGER.error("No defined route for handling %s", target_path)
        await record_ip_failure(client_ip_str)
        return reply.set_txn_var("not_found", 1)

    if not authorization_app_api:
        user_id = nc_user.user_id if nc_user else ""
        authorization_app_api = b64encode(f"{user_id}:{exapp_record.exapp_token}".encode(errors="ignore"))

    if exapp_route_bruteforce_protection:
        reply = reply.set_txn_var("statuses_to_trigger_bp", exapp_route_bruteforce_protection)
        reply = reply.set_txn_var("backend", "ex_apps_backend_w_bruteforce")
    else:
        reply = reply.set_txn_var("backend", "ex_apps_backend")

    LOGGER.info("Rerouting request to %s:%s", target_path, exapp_record.port)
    reply = reply.set_txn_var("target_port", exapp_record.port)
    reply = reply.set_txn_var("exapp_token", authorization_app_api)
    reply = reply.set_txn_var("exapp_version", exapp_record.exapp_version)
    return reply.set_txn_var("exapp_id", exapp_id)


@SPOA_AGENT.handler("exapps_response_status_msg")
async def exapps_response_status_msg(
    status: int, client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, statuses_to_trigger_bp: str
) -> AckPayload:
    reply = AckPayload()
    if not statuses_to_trigger_bp:
        return reply.set_txn_var("bp_triggered", 0)
    statuses = json.loads(statuses_to_trigger_bp)
    if status not in statuses:
        return reply.set_txn_var("bp_triggered", 0)
    str_client_ip = str(client_ip)
    LOGGER.warning("Bruteforce protection(status=%s) triggered IP=%s.", status, str_client_ip)
    await record_ip_failure(str_client_ip)
    return reply.set_txn_var("bp_triggered", 1)


###############################################################################
# Helper functions
###############################################################################


async def handle_app_api_request(
    target_path: str,
    request_headers: dict[str, str],
    str_client_ip: str,
    reply: AckPayload,
) -> AckPayload:
    """Handle the special case where the ExApp ID is 'app_api'."""
    LOGGER.debug("Request from AppAPI received: %s", target_path)
    if request_headers.get("harp-shared-key") != SHARED_KEY:
        await record_ip_failure(str_client_ip)
        return reply.set_txn_var("unauthorized", 1)
    docker_engine_port = request_headers.get("docker-engine-port")
    if docker_engine_port:
        reply = reply.set_txn_var("target_port", int(docker_engine_port))
        return reply.set_txn_var("backend", "docker_engine_backend")
    return reply.set_txn_var("backend", "nextcloud_control_backend")


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


async def nc_get_user(app_id: str, all_headers: dict[str, str]) -> NcUser | None:
    ext_headers = {k: v for k, v in all_headers.items() if k.lower() not in EXCLUDE_HEADERS_USER_INFO}
    LOGGER.debug("all_headers = %s\next_headers = %s", str(all_headers), str(ext_headers))
    async with aiohttp.ClientSession() as session, session.get(
        USER_INFO_URL,
        headers={**ext_headers, "harp-shared-key": SHARED_KEY},
        params={"appId": app_id},
    ) as resp:
        if not resp.ok:
            LOGGER.info("Failed to fetch ExApp metadata from Nextcloud.", await resp.text())
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
    # Overwrite if already exists
    async with EXAPP_CACHE_LOCK:
        try:
            EXAPP_CACHE[request.match_info["app_id"].lower()] = ExApp.model_validate(data)
        except ValidationError:
            raise web.HTTPBadRequest() from None
    return web.HTTPNoContent()


async def delete_exapp(request: web.Request):
    async with EXAPP_CACHE_LOCK:
        old = EXAPP_CACHE.pop(request.match_info["app_id"].lower(), None)
    if old is None:
        raise web.HTTPNotFound()
    return web.HTTPNoContent()


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
