"""An agent for HaProxy that takes care of most of the authentication logic of AppAPI. Python 3.12 required."""

# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import contextlib
import io
import ipaddress
import json
import logging
import os
import re
import socket
import tarfile
import time
from base64 import b64encode
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Literal, Self

import aiohttp
from aiohttp import web
from haproxyspoa.payloads.ack import AckPayload
from haproxyspoa.spoa_server import SpoaServer
from pydantic import BaseModel, Field, ValidationError, computed_field, model_validator

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
DOCKER_API_HOST = "127.0.0.1"

TRUSTED_PROXIES_STR = os.environ.get("HP_TRUSTED_PROXY_IPS", "")
TRUSTED_PROXIES = []
if TRUSTED_PROXIES_STR:
    try:
        TRUSTED_PROXIES = [
            ipaddress.ip_network(proxy.strip()) for proxy in TRUSTED_PROXIES_STR.split(",") if proxy.strip()
        ]
        LOGGER.info("Trusting reverse proxies for client IP detection: %s", [str(p) for p in TRUSTED_PROXIES])
    except ValueError as e:
        LOGGER.error(
            "Invalid value for HP_TRUSTED_PROXY_IPS: %s. Client IP detection from headers is disabled. "
            "The X-Forwarded-For and X-Real-IP headers will not be respected. "
            "This can lead to the outer proxy's IP being blocked during a bruteforce attempt instead of the actual client's IP.",
            e,
        )
        TRUSTED_PROXIES = []

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
    host: str = Field(...)
    port: int = Field(...)
    routes: list[ExAppRoute] = Field([])
    resolved_host: str = Field("", description="Contains resolved host field to the IP address.")


class NcUser(BaseModel):
    user_id: str = Field("", description="The Nextcloud user ID if not an anonymous user.")
    access_level: AccessLevel = Field(..., description="ADMIN(2), USER(1), or PUBLIC(0)")


class ExAppName(BaseModel):
    name: str = Field(..., description="ExApp name.")
    instance_id: str = Field("", description="Nextcloud instance ID.")

    @computed_field
    @property
    def exapp_container_name(self) -> str:
        return f"nc_app_{self.instance_id}_{self.name}" if self.instance_id else f"nc_app_{self.name}"

    @computed_field
    @property
    def exapp_container_volume(self) -> str:
        return f"{self.exapp_container_name}_data"


class CreateExAppMounts(BaseModel):
    source: str = Field(...)
    target: str = Field(...)
    mode: str = Field("rw")


class CreateExAppPayload(ExAppName):
    image_id: str = Field(..., description="Docker image ID.")
    network_mode: str = Field(..., description="Desired NetworkMode for the container.")
    environment_variables: list[str] = Field([], description="ExApp environment variables.")
    restart_policy: str = Field("unless-stopped", description="Desired RestartPolicy for the container.")
    compute_device: Literal["cpu", "rocm", "cuda"] = Field(
        "cpu", description="Possible values: 'cpu', 'rocm' or 'cuda'"
    )
    mount_points: list[CreateExAppMounts] = Field([], description="List of mount points for the container.")
    resource_limits: dict[str, Any] = Field({}, description="Resource limits for the container.")


class RemoveExAppPayload(ExAppName):
    remove_data: bool = Field(False, description="Flag indicating whether the Docker ExApp volume should be deleted.")


class InstallCertificatesPayload(ExAppName):
    system_certs_bundle: str | None = Field(None, description="Content of the system CA bundle (concatenated PEMs).")
    install_frp_certs: bool = Field(True, description="Flag to control installation of FRP certificates.")


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
# 5 minutes in seconds
BLACKLIST_REQUEST_WINDOW = int(os.getenv("HP_BLACKLIST_WINDOW", "300"))
# 10 invalid attempts during BLACKLIST_REQUEST_WINDOW
BLACKLIST_MAX_FAILS_COUNT = int(os.getenv("HP_BLACKLIST_COUNT", "10"))


###############################################################################
# BLACKLIST CACHE functions
###############################################################################


def get_true_client_ip(
    direct_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, headers: dict[str, str]
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Determine the true client IP by inspecting headers from trusted proxies."""
    if not TRUSTED_PROXIES:
        return direct_ip

    is_trusted = any(direct_ip in network for network in TRUSTED_PROXIES)
    if not is_trusted:
        return direct_ip

    # The request is from a trusted proxy, so we can check the headers.
    # X-Forwarded-For can be a list: client, proxy1, proxy2. We want the first one.
    x_forwarded_for = headers.get("x-forwarded-for")
    if x_forwarded_for:
        true_ip_str = x_forwarded_for.split(",")[0].strip()
        try:
            return ipaddress.ip_address(true_ip_str)
        except ValueError:
            LOGGER.warning("Could not parse IP from X-Forwarded-For header: %s", true_ip_str)

    x_real_ip = headers.get("x-real-ip")
    if x_real_ip:
        try:
            return ipaddress.ip_address(x_real_ip)
        except ValueError:
            LOGGER.warning("Could not parse IP from X-Real-IP header: %s", x_real_ip)
    return direct_ip  # If headers are present but invalid, fall back to the direct IP of the proxy


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
        LOGGER.warning("Recorded failure for IP %s. Failures in window: %d", ip_str, len(attempts))


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
    reply = AckPayload()
    request_headers = parse_headers(headers)
    client_ip_str = str(get_true_client_ip(client_ip, request_headers))
    reply = reply.set_txn_var("true_client_ip", client_ip_str)
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

    # Special handling for AppAPI requests
    if exapp_id == "app_api":
        return await handle_app_api_request(target_path, request_headers, client_ip_str, reply)

    exapp_route_bruteforce_protection = None
    authorization_app_api = ""
    exapp_record = None
    if all(
        key in request_headers
        for key in [
            "ex-app-version",
            "ex-app-id",
            "ex-app-host",
            "ex-app-port",
            "authorization-app-api",
            "harp-shared-key",
        ]
    ):
        # This is a direct request from AppAPI to ExApp using AppAPI PHP functions "requestToExAppXXX"
        if request_headers["harp-shared-key"] != SHARED_KEY:
            await record_ip_failure(client_ip)
            return reply.set_txn_var("bad_request", 1)
        exapp_record = ExApp(
            exapp_token="",
            exapp_version=request_headers["ex-app-version"],
            host=request_headers["ex-app-host"],
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

    if not exapp_record.resolved_host:
        try:
            ip_address(exapp_record.host)
            exapp_record.resolved_host = exapp_record.host
        except ValueError:
            exapp_record.resolved_host = resolve_ip(exapp_record.host)
        if not exapp_record.resolved_host:
            LOGGER.error("Cannot resolve '%s' to IP address.", exapp_record.host)
            return reply.set_txn_var("not_found", 1)

    LOGGER.info("Rerouting request to %s:%s with path=%s", exapp_record.resolved_host, exapp_record.port, target_path)
    reply = reply.set_txn_var("target_ip", exapp_record.resolved_host)
    reply = reply.set_txn_var("target_port", exapp_record.port)
    reply = reply.set_txn_var("exapp_token", authorization_app_api)
    reply = reply.set_txn_var("exapp_version", exapp_record.exapp_version)
    return reply.set_txn_var("exapp_id", exapp_id)


@SPOA_AGENT.handler("exapps_response_status_msg")
async def exapps_response_status_msg(status: int, client_ip: str, statuses_to_trigger_bp: str) -> AckPayload:
    reply = AckPayload()
    if not statuses_to_trigger_bp:
        return reply.set_txn_var("bp_triggered", 0)
    statuses = json.loads(statuses_to_trigger_bp)
    if status not in statuses:
        return reply.set_txn_var("bp_triggered", 0)
    LOGGER.warning("Bruteforce protection(status=%s) triggered IP=%s.", status, client_ip)
    await record_ip_failure(client_ip)
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
    if docker_engine_port and not target_path.startswith("/docker/"):
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


def resolve_ip(hostname: str) -> str:
    with contextlib.suppress(socket.gaierror):
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            if family == socket.AF_INET:  # IPv4
                return sockaddr[0]
        # If no IPv4, return first IPv6
        for family, _, _, _, sockaddr in addr_info:
            if family == socket.AF_INET6:  # IPv6
                return sockaddr[0]
    return ""


###############################################################################
# Misc routes
###############################################################################


async def get_info(request: web.Request):
    return web.json_response({"version": 0.3})


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
# Endpoints for AppAPI to work with the Docker API
###############################################################################


def get_docker_engine_port(request: web.Request) -> int:
    docker_engine_port_str = request.headers.get("docker-engine-port")
    if not docker_engine_port_str:
        LOGGER.error("Missing 'docker-engine-port' header.")
        raise web.HTTPBadRequest(text="Missing 'docker-engine-port' header.")

    try:
        docker_engine_port = int(docker_engine_port_str)
        if not (0 < docker_engine_port < 65536):
            raise ValueError("Port out of valid range") from None
        return docker_engine_port
    except ValueError:
        LOGGER.error("Invalid 'docker-engine-port' header value: %s", docker_engine_port_str)
        raise web.HTTPBadRequest(text=f"Invalid 'docker-engine-port' header value: {docker_engine_port_str}") from None


async def docker_exapp_exists(request: web.Request):
    docker_engine_port = get_docker_engine_port(request)
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = ExAppName.model_validate(payload_dict)
    except ValidationError as e:
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    container_name = payload.exapp_container_name
    docker_api_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_name}/json"
    LOGGER.debug("Checking for container '%s' via Docker API at %s", container_name, docker_api_url)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15.0)) as session:
        try:
            async with session.get(docker_api_url) as resp:
                if resp.status == 200:
                    LOGGER.info("Container '%s' exists.", container_name)
                    return web.json_response({"exists": True})
                if resp.status == 404:
                    LOGGER.info("Container '%s' does not exist.", container_name)
                    return web.json_response({"exists": False})
                error_text = await resp.text()
                LOGGER.error(
                    "Error checking container '%s' with Docker API (status %s): %s",
                    container_name,
                    resp.status,
                    error_text,
                )
                raise web.HTTPServiceUnavailable(text=f"Error communicating with Docker Engine: Status {resp.status}")
        except aiohttp.ClientConnectorError as e:
            LOGGER.error("Could not connect to Docker Engine at %s:%s: %s", DOCKER_API_HOST, docker_engine_port, e)
            raise web.HTTPServiceUnavailable(
                text=f"Could not connect to Docker Engine on port {docker_engine_port}"
            ) from e
        except TimeoutError as e:
            LOGGER.error(
                "Timeout while trying to communicate with Docker Engine at %s:%s for container '%s'",
                DOCKER_API_HOST,
                docker_engine_port,
                container_name,
            )
            raise web.HTTPGatewayTimeout(
                text=f"Timeout communicating with Docker Engine on port {docker_engine_port}"
            ) from e
        except Exception as e:
            LOGGER.exception("Unexpected error while checking container '%s' existence via Docker API.", container_name)
            raise web.HTTPInternalServerError(
                text="An unexpected error occurred while checking container status."
            ) from e


async def docker_exapp_create(request: web.Request):
    docker_engine_port = get_docker_engine_port(request)
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /docker/exapp/create")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = CreateExAppPayload.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /docker/exapp/create: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    container_name = payload.exapp_container_name
    volume_name = payload.exapp_container_volume
    image_id = payload.image_id

    container_config = {
        "Image": image_id,
        "Hostname": payload.name,
        "HostConfig": {
            "NetworkMode": payload.network_mode,
            "Mounts": [
                {
                    "Type": "volume",
                    "Source": volume_name,
                    "Target": f"/{volume_name}",
                    "ReadOnly": False,
                }
            ],
            "RestartPolicy": {
                "Name": payload.restart_policy,
            },
        },
        "Env": payload.environment_variables,
    }
    if payload.network_mode not in ("host", "bridge"):
        container_config["NetworkingConfig"] = {"EndpointsConfig": {payload.network_mode: {"Aliases": [payload.name]}}}

    if payload.compute_device == "cuda":
        container_config["HostConfig"]["DeviceRequests"] = [
            {
                "Driver": "nvidia",
                "Count": -1,
                "Capabilities": [["compute", "utility"]],
            }
        ]
    elif payload.compute_device == "rocm":
        devices = []
        for device in ("/dev/kfd", "/dev/dri"):
            devices.append({"PathOnHost": device, "PathInContainer": device, "CgroupPermissions": "rwm"})
        container_config["HostConfig"]["Devices"] = devices

    if payload.resource_limits:
        if "memory" in payload.resource_limits:
            container_config["HostConfig"]["Memory"] = payload.resource_limits["memory"]
        if "nanoCPUs" in payload.resource_limits:
            container_config["HostConfig"]["NanoCPUs"] = payload.resource_limits["nanoCPUs"]

    for extra_mount in payload.mount_points:
        container_config["HostConfig"]["Mounts"].append(
            {
                "Source": extra_mount.source,
                "Target": extra_mount.target,
                "Type": "bind",
                "Readonly": extra_mount.mode == "ro",
            }
        )

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60.0)) as session:
        create_volume_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/volumes/create"
        inspect_volume_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/volumes/{volume_name}"

        LOGGER.debug("Checking/Creating volume '%s' via Docker API", volume_name)
        try:
            async with session.get(inspect_volume_url) as resp_inspect:
                if resp_inspect.status == 200:
                    LOGGER.info("Volume '%s' already exists.", volume_name)
                elif resp_inspect.status == 404:
                    LOGGER.info("Volume '%s' not found, attempting to create.", volume_name)
                    async with session.post(create_volume_url, json={"Name": volume_name}) as resp_create:
                        if resp_create.status == 201:
                            LOGGER.info("Volume '%s' created successfully.", volume_name)
                        else:
                            error_text = await resp_create.text()
                            LOGGER.error(
                                "Failed to create volume '%s' (status %s): %s",
                                volume_name,
                                resp_create.status,
                                error_text,
                            )
                            raise web.HTTPServiceUnavailable(
                                text=f"Failed to create volume '{volume_name}': Status {resp_create.status}"
                            )
                else:
                    error_text = await resp_inspect.text()
                    LOGGER.error(
                        "Error inspecting volume '%s' (status %s): %s", volume_name, resp_inspect.status, error_text
                    )
                    raise web.HTTPServiceUnavailable(
                        text=f"Error inspecting volume '{volume_name}': Status {resp_inspect.status}"
                    )
        except aiohttp.ClientConnectorError as e:
            LOGGER.error("Could not connect to Docker Engine for volume operation: %s", e)
            raise web.HTTPServiceUnavailable(
                text=f"Could not connect to Docker Engine on port {docker_engine_port}"
            ) from e
        except TimeoutError as e:
            LOGGER.error("Timeout during volume operation for '%s'", volume_name)
            raise web.HTTPGatewayTimeout(text="Timeout communicating with Docker Engine for volume operation") from e
        except web.HTTPServiceUnavailable:
            raise
        except Exception as e:
            LOGGER.exception("Unexpected error during volume management for '%s'", volume_name)
            raise web.HTTPInternalServerError(text="Unexpected error during volume management.") from e

        create_container_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/create?name={container_name}"
        LOGGER.debug(
            "Attempting to create container '%s' with image '%s' via Docker API at %s",
            container_name,
            image_id,
            create_container_url,
        )
        try:
            async with session.post(create_container_url, json=container_config) as resp:
                if resp.status == 201:
                    container_data = await resp.json()
                    container_id = container_data.get("Id")
                    LOGGER.info("Container '%s' (ID: %s) created successfully.", container_name, container_id)
                    return web.json_response({"id": container_id, "name": container_name}, status=201)
                if resp.status == 409:
                    error_text = await resp.text()
                    LOGGER.warning("Container '%s' already exists (status 409): %s.", container_name, error_text)
                    raise web.HTTPConflict(text=f"Container with name '{container_name}' already exists.")
                error_text = await resp.text()
                LOGGER.error(
                    "Error creating container '%s' with Docker API (status %s): %s",
                    container_name,
                    resp.status,
                    error_text,
                )
                raise web.HTTPServiceUnavailable(
                    text=f"Error creating container '{container_name}': Status {resp.status}"
                )
        except aiohttp.ClientConnectorError as e:
            LOGGER.error("Could not connect to Docker Engine for container creation: %s", e)
            raise web.HTTPServiceUnavailable(
                text=f"Could not connect to Docker Engine on port {docker_engine_port}"
            ) from e
        except TimeoutError as e:
            LOGGER.error("Timeout during container creation for '%s'", container_name)
            raise web.HTTPGatewayTimeout(text="Timeout communicating with Docker Engine for container creation") from e
        except (web.HTTPServiceUnavailable, web.HTTPConflict, web.HTTPInternalServerError):
            raise
        except Exception as e:
            LOGGER.exception("Unexpected error during container creation for '%s'", container_name)
            raise web.HTTPInternalServerError(text="An unexpected error occurred during container creation.") from e


async def docker_exapp_start(request: web.Request):
    docker_engine_port = get_docker_engine_port(request)
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /docker/exapp/start")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = ExAppName.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /docker/exapp/start: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    container_name = payload.exapp_container_name
    start_container_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_name}/start"

    LOGGER.info("Attempting to start container '%s' via Docker API at %s", container_name, start_container_url)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30.0)) as session:
        try:
            async with session.post(start_container_url) as resp:
                if resp.status == 204:
                    LOGGER.info("Container '%s' started successfully.", container_name)
                    return web.HTTPNoContent()
                if resp.status == 304:
                    LOGGER.info("Container '%s' was already started.", container_name)
                    return web.HTTPOk(text="Container already started")
                if resp.status == 404:
                    LOGGER.warning("Container '%s' not found, cannot start.", container_name)
                    raise web.HTTPNotFound(text=f"Container '{container_name}' not found.")
                error_text = await resp.text()
                LOGGER.error(
                    "Error starting container '%s' with Docker API (status %s): %s",
                    container_name,
                    resp.status,
                    error_text,
                )
                raise web.HTTPServiceUnavailable(
                    text=f"Error starting container '{container_name}' via Docker Engine: Status {resp.status}"
                )
        except aiohttp.ClientConnectorError as e:
            LOGGER.error(
                "Could not connect to Docker Engine at %s:%s to start container: %s",
                DOCKER_API_HOST,
                docker_engine_port,
                e,
            )
            raise web.HTTPServiceUnavailable(
                text=f"Could not connect to Docker Engine on port {docker_engine_port}"
            ) from e
        except TimeoutError as e:
            LOGGER.error(
                "Timeout while trying to start container '%s' via Docker Engine at %s:%s",
                DOCKER_API_HOST,
                container_name,
                docker_engine_port,
            )
            raise web.HTTPGatewayTimeout(text="Timeout communicating with Docker Engine for container start") from e
        except (web.HTTPNotFound, web.HTTPServiceUnavailable):
            raise
        except Exception as e:
            LOGGER.exception("Unexpected error while starting container '%s' via Docker API.", container_name)
            raise web.HTTPInternalServerError(text="An unexpected error occurred during container start.") from e


async def docker_exapp_stop(request: web.Request):
    docker_engine_port = get_docker_engine_port(request)
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /docker/exapp/stop")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = ExAppName.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /docker/exapp/stop: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    container_name = payload.exapp_container_name
    stop_container_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_name}/stop"

    LOGGER.info("Attempting to stop container '%s' via Docker API at %s", container_name, stop_container_url)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30.0)) as session:
        try:
            async with session.post(stop_container_url) as resp:
                if resp.status == 204:
                    LOGGER.info("Container '%s' stopped successfully.", container_name)
                    return web.HTTPNoContent()
                if resp.status == 304:
                    LOGGER.info("Container '%s' was already stopped.", container_name)
                    return web.HTTPOk(text="Container already stopped")
                if resp.status == 404:
                    LOGGER.warning("Container '%s' not found, cannot stop.", container_name)
                    raise web.HTTPNotFound(text=f"Container '{container_name}' not found.")
                error_text = await resp.text()
                LOGGER.error(
                    "Error stopping container '%s' with Docker API (status %s): %s",
                    container_name,
                    resp.status,
                    error_text,
                )
                raise web.HTTPServiceUnavailable(
                    text=f"Error stopping container '{container_name}' via Docker Engine: Status {resp.status}"
                )
        except aiohttp.ClientConnectorError as e:
            LOGGER.error(
                "Could not connect to Docker Engine at %s:%s to stop container: %s",
                DOCKER_API_HOST,
                docker_engine_port,
                e,
            )
            raise web.HTTPServiceUnavailable(
                text=f"Could not connect to Docker Engine on port {docker_engine_port}"
            ) from e
        except TimeoutError as e:
            LOGGER.error(
                "Timeout while trying to stop container '%s' via Docker Engine at %s:%s",
                DOCKER_API_HOST,
                container_name,
                docker_engine_port,
            )
            raise web.HTTPGatewayTimeout(text="Timeout communicating with Docker Engine for container stop") from e
        except (web.HTTPNotFound, web.HTTPServiceUnavailable):
            raise
        except Exception as e:
            LOGGER.exception("Unexpected error while stopping container '%s' via Docker API.", container_name)
            raise web.HTTPInternalServerError(text="An unexpected error occurred during container stop.") from e


async def docker_exapp_wait_for_start(request: web.Request):
    docker_engine_port = get_docker_engine_port(request)
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /docker/exapp/wait_for_start")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = ExAppName.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /docker/exapp/wait_for_start: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    container_name = payload.exapp_container_name
    inspect_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_name}/json"

    max_tries = 180
    sleep_interval = 0.5
    total_wait_time = max_tries * sleep_interval
    client_timeout = aiohttp.ClientTimeout(total=total_wait_time + 15.0)

    LOGGER.info(
        "Waiting for container '%s' to start (max %d tries, interval %.1fs, total wait %.1fs).",
        container_name,
        max_tries,
        sleep_interval,
        total_wait_time,
    )

    last_known_status: str | None = "unknown"
    last_known_health: str | None = None

    async with aiohttp.ClientSession(timeout=client_timeout) as session:
        for attempt in range(max_tries):
            try:
                async with session.get(inspect_url) as resp:
                    if resp.status == 200:
                        container_info = await resp.json()
                        state = container_info.get("State", {})
                        current_status = state.get("Status")
                        current_health = state.get("Health", {}).get("Status")

                        last_known_status = current_status
                        last_known_health = current_health

                        LOGGER.debug(
                            "Container '%s' attempt %d/%d: Status='%s', Health='%s'",
                            container_name,
                            attempt + 1,
                            max_tries,
                            current_status,
                            current_health,
                        )
                        if current_status == "running":
                            if current_health is None or current_health == "healthy":
                                LOGGER.info(
                                    "Container '%s' is running and healthy (or no healthcheck).", container_name
                                )
                                return web.json_response(
                                    {"started": True, "status": current_status, "health": current_health}
                                )
                            if current_health == "unhealthy":
                                LOGGER.warning(
                                    "Container '%s' is running but unhealthy. Reporting as not successfully started.",
                                    container_name,
                                )
                                return web.json_response(
                                    {
                                        "started": True,
                                        "status": current_status,
                                        "health": current_health,
                                        "reason": "unhealthy",
                                    }
                                )
                            if current_health == "starting":
                                LOGGER.info(
                                    "Container '%s' is running, health status is 'starting'. Continuing to wait.",
                                    container_name,
                                )
                        elif current_status in ("created", "restarting"):
                            LOGGER.info("Container '%s' is '%s'. Continuing to wait.", container_name, current_status)
                        elif current_status in ("paused", "exited", "dead"):
                            LOGGER.warning(
                                "Container '%s' is in a non-recoverable state (current state: %s). Stopping wait.",
                                container_name,
                                current_status,
                            )
                            return web.json_response(
                                {
                                    "started": False,
                                    "status": current_status,
                                    "health": current_health,
                                    "reason": f"non-recoverable state: {current_status}",
                                }
                            )
                    elif resp.status == 404:
                        LOGGER.warning(
                            "Container '%s' not found while waiting for start (attempt %d).",
                            container_name,
                            attempt + 1,
                        )
                        return web.json_response(
                            {"started": False, "status": "not_found", "reason": "container not found"}
                        )
                    else:
                        error_text = await resp.text()
                        LOGGER.error(
                            "Error inspecting container '%s' while waiting (status %s, attempt %d): %s",
                            container_name,
                            resp.status,
                            attempt + 1,
                            error_text,
                        )
                        raise web.HTTPServiceUnavailable(
                            text=f"Error inspecting container '{container_name}': Status {resp.status}"
                        )
            except aiohttp.ClientConnectorError as e:
                LOGGER.error(
                    "Could not connect to Docker Engine at %s:%s while waiting for container '%s' (attempt %d): %s",
                    DOCKER_API_HOST,
                    docker_engine_port,
                    container_name,
                    attempt + 1,
                    e,
                )
                raise web.HTTPServiceUnavailable(
                    text=f"Could not connect to Docker Engine on port {docker_engine_port}"
                ) from e
            except TimeoutError:
                LOGGER.warning(
                    "Overall timeout reached while waiting for container '%s' to start after %d attempts.",
                    container_name,
                    attempt + 1,
                )
                return web.json_response(
                    {
                        "started": False,
                        "status": last_known_status,
                        "health": last_known_health,
                        "reason": "overall timeout",
                    }
                )
            except web.HTTPServiceUnavailable:
                raise
            except Exception as e:
                LOGGER.exception(
                    "Unexpected error while waiting for container '%s' to start (attempt %d).",
                    container_name,
                    attempt + 1,
                )
                raise web.HTTPInternalServerError(
                    text="An unexpected error occurred while waiting for container start."
                ) from e
            if attempt < max_tries - 1:
                await asyncio.sleep(sleep_interval)
            else:
                LOGGER.info("Max tries reached for container '%s'. Reporting last known state.", container_name)

        LOGGER.warning(
            "Container '%s' did not reach desired 'running' and 'healthy' state within %d attempts.",
            container_name,
            max_tries,
        )
        return web.json_response(
            {
                "started": False,
                "status": last_known_status,
                "health": last_known_health,
                "reason": "timeout after max tries",
            }
        )


async def docker_exapp_remove(request: web.Request):
    docker_engine_port = get_docker_engine_port(request)
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /docker/exapp/remove")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = RemoveExAppPayload.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /docker/exapp/remove: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    container_name = payload.exapp_container_name
    volume_name = payload.exapp_container_volume

    remove_container_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_name}?force=true"
    remove_volume_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/volumes/{volume_name}"

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30.0)) as session:
        LOGGER.info("Attempting to remove container '%s' via Docker API at %s", container_name, remove_container_url)
        try:
            async with session.delete(remove_container_url) as resp:
                if resp.status == 204:
                    LOGGER.info("Container '%s' removed successfully.", container_name)
                elif resp.status == 404:
                    LOGGER.info("Container '%s' not found, considering it removed.", container_name)
                elif resp.status == 409:
                    error_text = await resp.text()
                    LOGGER.warning(
                        "Conflict while removing container '%s' (status %s): %s. Assuming it might be gone or handled.",
                        container_name,
                        resp.status,
                        error_text,
                    )
                else:
                    error_text = await resp.text()
                    LOGGER.error(
                        "Error removing container '%s' with Docker API (status %s): %s",
                        container_name,
                        resp.status,
                        error_text,
                    )
                    raise web.HTTPServiceUnavailable(
                        text=f"Error removing container '{container_name}' via Docker Engine: Status {resp.status}"
                    )
        except aiohttp.ClientConnectorError as e:
            LOGGER.error(
                "Could not connect to Docker Engine at %s:%s to remove container: %s",
                DOCKER_API_HOST,
                docker_engine_port,
                e,
            )
            raise web.HTTPServiceUnavailable(
                text=f"Could not connect to Docker Engine on port {docker_engine_port}"
            ) from e
        except TimeoutError as e:
            LOGGER.error(
                "Timeout while trying to remove container '%s' via Docker Engine at %s:%s",
                DOCKER_API_HOST,
                container_name,
                docker_engine_port,
            )
            raise web.HTTPGatewayTimeout(text="Timeout communicating with Docker Engine for container removal") from e
        except web.HTTPServiceUnavailable:
            raise
        except Exception as e:
            LOGGER.exception("Unexpected error while removing container '%s' via Docker API.", container_name)
            raise web.HTTPInternalServerError(text="An unexpected error occurred during container removal.") from e

        if payload.remove_data:
            LOGGER.info("Attempting to remove volume '%s' via Docker API at %s", volume_name, remove_volume_url)
            try:
                async with session.delete(remove_volume_url) as resp:
                    if resp.status == 204:
                        LOGGER.info("Volume '%s' removed successfully.", volume_name)
                    elif resp.status == 404:
                        LOGGER.info("Volume '%s' not found, considering it removed.", volume_name)
                    elif resp.status == 409:
                        error_text = await resp.text()
                        LOGGER.error(
                            "Cannot remove volume '%s' as it is in use (status %s): %s.",
                            volume_name,
                            resp.status,
                            error_text,
                        )
                        raise web.HTTPConflict(text=f"Volume '{volume_name}' is in use and could not be removed.")
                    else:
                        error_text = await resp.text()
                        LOGGER.error(
                            "Error removing volume '%s' with Docker API (status %s): %s",
                            volume_name,
                            resp.status,
                            error_text,
                        )
                        raise web.HTTPServiceUnavailable(
                            text=f"Error removing volume '{volume_name}' via Docker Engine: Status {resp.status}"
                        )
            except aiohttp.ClientConnectorError as e:
                LOGGER.error(
                    "Could not connect to Docker Engine at %s:%s to remove volume: %s",
                    DOCKER_API_HOST,
                    docker_engine_port,
                    e,
                )
                raise web.HTTPServiceUnavailable(
                    text=f"Could not connect to Docker Engine on port {docker_engine_port} for volume removal"
                ) from e
            except TimeoutError as e:
                LOGGER.error(
                    "Timeout while trying to remove volume '%s' via Docker Engine at %s:%s",
                    DOCKER_API_HOST,
                    volume_name,
                    docker_engine_port,
                )
                raise web.HTTPGatewayTimeout(text="Timeout communicating with Docker Engine for volume removal") from e
            except (web.HTTPServiceUnavailable, web.HTTPConflict):
                raise
            except Exception as e:
                LOGGER.exception("Unexpected error while removing volume '%s' via Docker API.", volume_name)
                raise web.HTTPInternalServerError(text="An unexpected error occurred during volume removal.") from e

    LOGGER.info(
        "ExApp remove operation completed for container '%s' (remove_data=%s).",
        container_name,
        payload.remove_data,
    )
    return web.HTTPNoContent()


async def docker_exapp_install_certificates(request: web.Request):
    docker_engine_port = get_docker_engine_port(request)
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /docker/exapp/install_certificates")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = InstallCertificatesPayload.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /docker/exapp/install_certificates: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    container_name = payload.exapp_container_name
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120.0)) as session:
        original_state_running = False
        try:
            inspect_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_name}/json"
            async with session.get(inspect_url) as resp_inspect:
                if resp_inspect.status == 200:
                    inspect_data = await resp_inspect.json()
                    original_state_running = inspect_data.get("State", {}).get("Running", False)
                elif resp_inspect.status == 404:
                    LOGGER.error("Container '%s' not found for certificate installation.", container_name)
                    raise web.HTTPNotFound(text=f"Container '{container_name}' not found.")
                else:
                    error_text = await resp_inspect.text()
                    LOGGER.error(
                        "Failed to inspect container '%s' (status %s): %s",
                        container_name,
                        resp_inspect.status,
                        error_text,
                    )
                    raise web.HTTPServiceUnavailable(text=f"Failed to inspect container: Status {resp_inspect.status}")

            if not original_state_running:
                LOGGER.info(
                    "Container '%s' is not running. Attempting to start for certificate installation.", container_name
                )
                start_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_name}/start"
                async with session.post(start_url) as resp_start:
                    if resp_start.status not in (204, 304):
                        error_text = await resp_start.text()
                        LOGGER.error(
                            "Failed to start container '%s' for cert install (status %s): %s",
                            container_name,
                            resp_start.status,
                            error_text,
                        )
                        raise web.HTTPServiceUnavailable(text=f"Failed to start container: Status {resp_start.status}")
                    LOGGER.info("Container '%s' started/is running for certificate installation.", container_name)

            exit_code, os_info_content = await _execute_command_in_container_simplified(
                session, docker_engine_port, container_name, ["cat", "/etc/os-release"]
            )
            if exit_code != 0:
                LOGGER.error(
                    "Failed to get OS info from container '%s'. Exit code: %s, Raw Output: %s",
                    container_name,
                    exit_code,
                    os_info_content,
                )
                raise web.HTTPInternalServerError(
                    text=f"Failed to get OS info. Exit: {exit_code}. Output: {os_info_content[:200]}"
                )
            LOGGER.info("OS Info for container '%s':\n%s", container_name, os_info_content.strip())

            if payload.system_certs_bundle:
                await _install_system_certificates(
                    session, docker_engine_port, container_name, payload.system_certs_bundle, os_info_content
                )
            else:
                LOGGER.info(
                    "No system_certs_bundle provided for container '%s'. Skipping system cert installation.",
                    container_name,
                )

            if payload.install_frp_certs:
                await _install_frp_certificates(session, docker_engine_port, container_name)
            else:
                LOGGER.info(
                    "install_frp_certs is false. Skipping FRP cert installation for container '%s'.", container_name
                )

            return web.HTTPNoContent()

        except (web.HTTPException, aiohttp.ClientError) as e:
            LOGGER.error("Error during certificate installation for '%s': %s", container_name, e)
            raise
        except Exception as e:
            LOGGER.exception("Unexpected fatal error during certificate installation for '%s'", container_name)
            raise web.HTTPInternalServerError(text=f"Unexpected error during certificate installation: {e}") from e
        finally:
            if not original_state_running:
                LOGGER.info(
                    "Attempting to stop container '%s' as it was started for certificate installation.", container_name
                )
                stop_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_name}/stop"
                try:
                    async with session.post(stop_url) as resp_stop:
                        if resp_stop.status not in (204, 304, 404):
                            error_text = await resp_stop.text()
                            LOGGER.warning(
                                "Failed to stop container '%s' after cert install (status %s): %s",
                                container_name,
                                resp_stop.status,
                                error_text,
                            )
                        else:
                            LOGGER.info(
                                "Container '%s' stopped or was already stopped/gone after cert install.", container_name
                            )
                except Exception as e_stop:
                    LOGGER.error("Error stopping container '%s' in finally block: %s", container_name, e_stop)


async def _install_system_certificates(
    session: aiohttp.ClientSession,
    docker_engine_port: int,
    container_name: str,
    system_certs_bundle: str,
    os_info_content: str,
) -> None:
    target_cert_dir = _get_target_cert_dir(os_info_content)
    if not target_cert_dir:
        LOGGER.warning(
            "OS in container '%s' not supported for sys cert installation, or bundle empty. Skipping.",
            container_name,
        )
        return

    LOGGER.info("Target system cert directory for container '%s': %s", container_name, target_cert_dir)
    exit_code, raw_output = await _execute_command_in_container_simplified(
        session, docker_engine_port, container_name, ["mkdir", "-p", target_cert_dir]
    )
    if exit_code != 0:
        LOGGER.error(
            "Failed to create cert dir '%s' in container '%s'. Exit: %s, Raw Output: %s",
            target_cert_dir,
            container_name,
            exit_code,
            raw_output,
        )
        raise web.HTTPInternalServerError(
            text=f"Failed to create cert directory. Exit: {exit_code}. Output: {raw_output[:200]}"
        )

    certs_to_install = {}
    parsed_certs = _parse_certs_from_bundle(system_certs_bundle)
    for i, cert_content in enumerate(parsed_certs):
        cert_filename = f"custom_ca_cert_{i}.crt"
        certs_to_install[os.path.join(target_cert_dir.lstrip("/"), cert_filename)] = cert_content

    if not certs_to_install:
        LOGGER.info(
            "No individual certificates parsed from system_certs_bundle for container '%s'.",
            container_name,
        )
        return

    tar_bytes = _create_tar_archive_in_memory(certs_to_install)
    await _put_archive_to_container(session, docker_engine_port, container_name, "/", tar_bytes)
    LOGGER.info(
        "Installed %d system CA certificates into '%s' in container '%s'.",
        len(parsed_certs),
        target_cert_dir,
        container_name,
    )

    update_cmd_list = _get_certificate_update_command(os_info_content)
    if update_cmd_list:
        LOGGER.info("Running certificate update command: %s", " ".join(update_cmd_list))
        exit_code, raw_output = await _execute_command_in_container_simplified(
            session, docker_engine_port, container_name, update_cmd_list
        )
        if exit_code != 0:
            LOGGER.error(
                "Certificate update command failed in container '%s'. Exit: %s, Raw Output: %s",
                container_name,
                exit_code,
                raw_output,
            )
        else:
            LOGGER.info("Certificate update command successful. Raw Output: %s", raw_output.strip())
    else:
        LOGGER.warning("No certificate update command found for OS in container '%s'.", container_name)


async def _install_frp_certificates(
    session: aiohttp.ClientSession, docker_engine_port: int, container_name: str
) -> None:
    frp_cert_dir_on_harp = "/certs/frp"
    frp_target_dir_in_container = "/certs/frp"

    frp_files_to_read = {
        "ca.crt": os.path.join(frp_cert_dir_on_harp, "ca.crt"),
        "client.crt": os.path.join(frp_cert_dir_on_harp, "client.crt"),
        "client.key": os.path.join(frp_cert_dir_on_harp, "client.key"),
    }
    frp_certs_content = {}
    all_frp_files_exist = True
    for name, path_on_harp in frp_files_to_read.items():
        if os.path.exists(path_on_harp):
            try:
                with open(path_on_harp, encoding="utf-8") as f:
                    frp_certs_content[name] = f.read()
            except Exception as e_read:
                LOGGER.error("Failed to read FRP cert file '%s' from HaRP agent: %s", path_on_harp, e_read)
                all_frp_files_exist = False
                break
        else:
            LOGGER.warning(
                "FRP certificate file '%s' not found on HaRP agent. Skipping FRP cert installation.",
                path_on_harp,
            )
            all_frp_files_exist = False
            break

    if all_frp_files_exist and frp_certs_content:
        LOGGER.info(
            "Installing FRP certificates from HaRP agent into '%s' in container '%s'.",
            frp_target_dir_in_container,
            container_name,
        )
        exit_code, raw_output = await _execute_command_in_container_simplified(
            session, docker_engine_port, container_name, ["mkdir", "-p", frp_target_dir_in_container]
        )
        if exit_code != 0:
            LOGGER.error(
                "Failed to create FRP cert dir '%s' in container '%s'. Exit: %s, Raw Output: %s",
                frp_target_dir_in_container,
                container_name,
                exit_code,
                raw_output,
            )
            raise web.HTTPInternalServerError(
                text=f"Failed to create FRP cert directory. Exit: {exit_code}. Output: {raw_output[:200]}"
            )

        frp_files_for_tar = {
            os.path.join(frp_target_dir_in_container.lstrip("/"), "ca.crt"): frp_certs_content["ca.crt"],
            os.path.join(frp_target_dir_in_container.lstrip("/"), "client.crt"): frp_certs_content["client.crt"],
            os.path.join(frp_target_dir_in_container.lstrip("/"), "client.key"): frp_certs_content["client.key"],
        }
        tar_bytes_frp = _create_tar_archive_in_memory(frp_files_for_tar)
        await _put_archive_to_container(session, docker_engine_port, container_name, "/", tar_bytes_frp)
        LOGGER.info("FRP certificates installed successfully into '%s'.", frp_target_dir_in_container)
    elif not all_frp_files_exist:
        LOGGER.info(
            "One or more FRP cert files missing, skipping FRP installation for container '%s'",
            container_name,
        )
    else:
        LOGGER.warning(
            "FRP cert content is empty. Skipping FRP installation for '%s'",
            container_name,
        )


def _create_tar_archive_in_memory(files_to_add: dict[str, str]) -> bytes:
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        for path_in_archive, content_str in files_to_add.items():
            content_bytes = content_str.encode("utf-8")
            tarinfo = tarfile.TarInfo(name=path_in_archive)
            tarinfo.size = len(content_bytes)
            tarinfo.mtime = int(time.time())
            tar.addfile(tarinfo, io.BytesIO(content_bytes))
    return tar_stream.getvalue()


async def _put_archive_to_container(
    session: aiohttp.ClientSession, docker_engine_port: int, container_name: str, path: str, data: bytes
):
    upload_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_name}/archive?path={path}"
    headers = {"Content-Type": "application/x-tar"}
    try:
        async with session.put(upload_url, data=data, headers=headers) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                LOGGER.error(
                    "Failed to put archive to container '%s' at path '%s' (status %s): %s",
                    container_name,
                    path,
                    resp.status,
                    error_text,
                )
                raise web.HTTPServiceUnavailable(text=f"Failed to upload archive: Status {resp.status}")
            LOGGER.info("Successfully put archive to container '%s' at path '%s'", container_name, path)
    except aiohttp.ClientError as e:
        LOGGER.error("Client error putting archive to container '%s': %s", container_name, e)
        raise web.HTTPServiceUnavailable(text=f"Client error uploading archive: {e}") from e
    except Exception as e:
        LOGGER.exception("Unexpected error putting archive to container '%s'", container_name)
        raise web.HTTPInternalServerError(text=f"Unexpected error uploading archive: {e}") from e


def _parse_certs_from_bundle(bundle_content: str) -> list[str]:
    """Parses individual PEM certificates from a bundle string."""
    return re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", bundle_content, re.DOTALL)


async def _execute_command_in_container_simplified(
    session: aiohttp.ClientSession, docker_engine_port: int, container_id_or_name: str, cmd: list[str]
) -> tuple[int, str]:
    """Executes a command in a running container and returns (exit_code, raw_output_str)."""
    exec_create_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/containers/{container_id_or_name}/exec"
    exec_create_payload = {
        "AttachStdout": True,
        "AttachStderr": True,
        "Cmd": cmd,
    }
    exec_id = None
    raw_output_str = ""
    exit_code = -1  # Default to error

    try:
        async with session.post(exec_create_url, json=exec_create_payload) as resp:
            if resp.status != 201:
                error_text = await resp.text()
                LOGGER.error(
                    "Failed to create exec instance for command '%s' in container '%s' (status %s): %s",
                    " ".join(cmd),
                    container_id_or_name,
                    resp.status,
                    error_text,
                )
                raise web.HTTPServiceUnavailable(text=f"Failed to create exec for command: {error_text}")
            exec_id_data = await resp.json()
            exec_id = exec_id_data.get("Id")

        if not exec_id:
            raise web.HTTPInternalServerError(text="Exec ID not found after creation.")

        exec_start_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/exec/{exec_id}/start"
        exec_start_payload = {"Detach": False, "Tty": False}  # Tty=False gives raw stream

        async with session.post(exec_start_url, json=exec_start_payload) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                LOGGER.error(
                    "Failed to start exec instance '%s' for command '%s' in container '%s' (status %s): %s",
                    exec_id,
                    " ".join(cmd),
                    container_id_or_name,
                    resp.status,
                    error_text,
                )
                raise web.HTTPServiceUnavailable(text=f"Failed to start exec: {error_text}")
            raw_output_bytes = await resp.read()
            raw_output_str = raw_output_bytes.decode(errors="ignore")

        exec_inspect_url = f"http://{DOCKER_API_HOST}:{docker_engine_port}/exec/{exec_id}/json"
        async with session.get(exec_inspect_url) as resp_inspect:
            if resp_inspect.status != 200:
                error_text = await resp_inspect.text()
                LOGGER.error(
                    "Failed to inspect exec instance '%s' (status %s): %s. Output was: %s",
                    exec_id,
                    resp_inspect.status,
                    error_text,
                    raw_output_str,
                )
            else:
                exec_info = await resp_inspect.json()
                ret_code = exec_info.get("ExitCode")
                if ret_code is None:  # Should not happen if process exited
                    LOGGER.warning(
                        "Exec inspect for '%s' did not contain ExitCode. Output was: %s", exec_id, raw_output_str
                    )
                else:
                    exit_code = ret_code

            return exit_code, raw_output_str

    except aiohttp.ClientError as e:
        LOGGER.error(
            "Client error during exec command '%s' in container '%s': %s", " ".join(cmd), container_id_or_name, e
        )
        raise web.HTTPServiceUnavailable(text=f"Client error during exec: {e}") from e
    except Exception as e:
        LOGGER.exception(
            "Unexpected error during exec command '%s' in container '%s'", " ".join(cmd), container_id_or_name
        )
        raise web.HTTPInternalServerError(text=f"Unexpected error during exec: {e}") from e


def _get_target_cert_dir(os_info_content: str | None) -> str | None:
    if not os_info_content:
        LOGGER.warning("OS info content is empty, cannot determine target cert directory.")
        return None
    os_info_lower = os_info_content.lower()
    if "alpine" in os_info_lower:
        return "/usr/local/share/ca-certificates"
    if "debian" in os_info_lower or "ubuntu" in os_info_lower:
        return "/usr/local/share/ca-certificates"
    if (
        "centos" in os_info_lower
        or "almalinux" in os_info_lower
        or "rhel" in os_info_lower
        or "fedora" in os_info_lower
    ):
        return "/etc/pki/ca-trust/source/anchors"
    LOGGER.warning(
        "Unsupported OS for SSL certificate installation: %s",
        os_info_content.splitlines()[0] if os_info_content else "Unknown",
    )
    return None


def _get_certificate_update_command(os_info_content: str | None) -> list[str] | None:
    if not os_info_content:
        LOGGER.warning("OS info content is empty, cannot determine certificate update command.")
        return None
    os_info_lower = os_info_content.lower()
    if "alpine" in os_info_lower:
        return ["update-ca-certificates"]
    if "debian" in os_info_lower or "ubuntu" in os_info_lower:
        return ["update-ca-certificates"]
    if (
        "centos" in os_info_lower
        or "almalinux" in os_info_lower
        or "rhel" in os_info_lower
        or "fedora" in os_info_lower
    ):
        return ["update-ca-trust", "extract"]
    return None


###############################################################################
# HTTP Server Setup
###############################################################################


def create_web_app() -> web.Application:
    app = web.Application()

    app.router.add_get("/info", get_info)

    # ExApp routes
    app.router.add_post("/exapp_storage/{app_id}", add_exapp)
    app.router.add_delete("/exapp_storage/{app_id}", delete_exapp)

    # FRP auth (FRP Server will call it)
    app.router.add_post("/frp_handler", frp_auth)

    # Docker Engine APIs wrappers
    app.router.add_post("/docker/exapp/exists", docker_exapp_exists)
    app.router.add_post("/docker/exapp/create", docker_exapp_create)
    app.router.add_post("/docker/exapp/start", docker_exapp_start)
    app.router.add_post("/docker/exapp/stop", docker_exapp_stop)
    app.router.add_post("/docker/exapp/wait_for_start", docker_exapp_wait_for_start)
    app.router.add_post("/docker/exapp/remove", docker_exapp_remove)
    app.router.add_post("/docker/exapp/install_certificates", docker_exapp_install_certificates)
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
