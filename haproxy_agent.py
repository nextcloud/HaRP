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
import ssl
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
SPOA_ADDRESS = os.environ.get("HP_SPOA_ADDRESS", "127.0.0.1:9600")
SPOA_HOST, SPOA_PORT = SPOA_ADDRESS.rsplit(":", 1)
SPOA_PORT = int(SPOA_PORT)
# Kubernetes environment variables
K8S_ENABLED = os.environ.get("HP_K8S_ENABLED", "false").lower() in {"1", "true", "yes"}
K8S_NAMESPACE = os.environ.get("HP_K8S_NAMESPACE", "nextcloud-exapps")
K8S_API_SERVER = os.environ.get("HP_K8S_API_SERVER")  # e.g. https://kubernetes.default.svc
K8S_CA_FILE = os.environ.get("HP_K8S_CA_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
K8S_TOKEN = os.environ.get("HP_K8S_BEARER_TOKEN")
K8S_TOKEN_FILE = os.environ.get("HP_K8S_BEARER_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token")
K8S_VERIFY_SSL = os.environ.get("HP_K8S_VERIFY_SSL", "true").lower() != "false"
K8S_STORAGE_CLASS = os.environ.get("HP_K8S_STORAGE_CLASS", "")
K8S_DEFAULT_STORAGE_SIZE = os.environ.get("HP_K8S_DEFAULT_STORAGE_SIZE", "10Gi")
if not K8S_API_SERVER and os.environ.get("KUBERNETES_SERVICE_HOST"):
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    K8S_API_SERVER = f"https://{host}:{port}"

K8S_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=60.0)
K8S_NAME_MAX_LENGTH = 63
# Set up the logging configuration
LOG_LEVEL = os.environ.get("HP_LOG_LEVEL", "INFO").upper()
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
            "This can lead to the outer proxy's IP being blocked "
            "during a bruteforce attempt instead of the actual client's IP.",
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


def _sanitize_k8s_name(raw: str) -> str:
    """Convert an arbitrary string into a DNS-1123 compatible name for Kubernetes."""
    name = raw.lower().replace("_", "-")
    name = re.sub(r"[^a-z0-9-]", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    if not name:
        name = "exapp"
    if len(name) > K8S_NAME_MAX_LENGTH:
        name = name[:K8S_NAME_MAX_LENGTH].rstrip("-")
    return name


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

    @computed_field
    @property
    def exapp_k8s_name(self) -> str:
        """Name used for Deployment / Pods."""
        return _sanitize_k8s_name(self.exapp_container_name)

    @computed_field
    @property
    def exapp_k8s_volume_name(self) -> str:
        """PVC name for ExApp's data volume."""
        base = _sanitize_k8s_name(self.exapp_container_volume)
        if len(base) > K8S_NAME_MAX_LENGTH:
            base = base[:K8S_NAME_MAX_LENGTH].rstrip("-")
        return base


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

    @model_validator(mode="before")
    @classmethod
    def accept_k8s_friendly_payload(cls, data: Any) -> Any:
        """Allow K8s-style payloads like:

          {
            "image": "ghcr.io/nextcloud/test-deploy:release",
            "resource_limits": {"cpu": "500m", "memory": "512Mi"}
          }
        by mapping 'image' -> 'image_id' and defaulting network_mode.
        """
        if isinstance(data, dict):
            if "image_id" not in data and "image" in data:
                data = {**data, "image_id": data["image"]}  # Allow 'image' instead of 'image_id'
            if "network_mode" not in data:
                data = {**data, "network_mode": "bridge"}  # Default network_mode (used only for Docker)
        return data


class RemoveExAppPayload(ExAppName):
    remove_data: bool = Field(False, description="Flag indicating whether the Docker ExApp volume should be deleted.")


class InstallCertificatesPayload(ExAppName):
    system_certs_bundle: str | None = Field(None, description="Content of the system CA bundle (concatenated PEMs).")
    install_frp_certs: bool = Field(True, description="Flag to control installation of FRP certificates.")


class ExposeExAppPayload(ExAppName):
    port: int = Field(..., ge=1, le=65535, description="Port on which the ExApp listens inside the Pod/container.")
    expose_type: Literal["nodeport", "clusterip", "loadbalancer", "manual"] = Field(
        "nodeport",
        description="How HaRP should make the ExApp reachable (and which endpoint it registers).",
    )
    upstream_host: str | None = Field(
        None,
        description=(
            "Override the host that HaRP should use to reach the ExApp. "
            "For expose_type=manual this is required. "
            "For nodeport it is strongly recommended (stable VIP/LB/edge-node)."
        ),
    )
    upstream_port: int | None = Field(
        None,
        ge=1,
        le=65535,
        description=(
            "Override the port that HaRP should use to reach the ExApp. "
            "Only used for expose_type=manual (otherwise computed from Service)."
        ),
    )
    service_port: int | None = Field(
        None,
        ge=1,
        le=65535,
        description="Service 'port' value (defaults to payload.port). targetPort always equals payload.port.",
    )
    node_port: int | None = Field(
        None,
        ge=30000,
        le=32767,
        description="Requested nodePort when expose_type=nodeport (optional).",
    )
    external_traffic_policy: Literal["Cluster", "Local"] | None = Field(
        None,
        description="Service spec.externalTrafficPolicy (NodePort/LoadBalancer only).",
    )
    load_balancer_ip: str | None = Field(
        None,
        description="Optional spec.loadBalancerIP when expose_type=loadbalancer (provider-specific).",
    )
    service_annotations: dict[str, str] = Field(
        default_factory=dict,
        description="Annotations applied to the generated Service.",
    )
    service_labels: dict[str, str] = Field(
        default_factory=dict,
        description="Extra labels applied to the generated Service.",
    )
    wait_timeout_seconds: float = Field(
        60.0,
        ge=0,
        le=600,
        description="How long to wait for a LoadBalancer ingress hostname/IP.",
    )
    wait_interval_seconds: float = Field(
        1.0,
        ge=0.1,
        le=10.0,
        description="Polling interval when waiting for a LoadBalancer address.",
    )
    # Node auto-selection (only used if expose_type=nodeport AND upstream_host is not provided)
    node_address_type: Literal["InternalIP", "ExternalIP"] = Field(
        "InternalIP",
        description="Which node address type to prefer when auto-picking a node address for NodePort.",
    )
    node_name: str | None = Field(
        None,
        description="If set, pick this exact node by metadata.name when auto-picking node address.",
    )
    node_label_selector: str | None = Field(
        None,
        description="If set, list nodes with this labelSelector when auto-picking node address.",
    )

    @model_validator(mode="after")
    def validate_expose_payload(self) -> Self:
        if self.expose_type == "manual" and not self.upstream_host:
            raise ValueError("upstream_host is required when expose_type='manual'")
        return self


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
        authorization_app_api = request_headers["authorization-app-api"]
        # Prefer cached upstream (K8s expose sets correct host/port in cache)
        async with EXAPP_CACHE_LOCK:
            cached = EXAPP_CACHE.get(exapp_id_lower)
        if cached:
            exapp_record = cached
        else:
            exapp_record = ExApp(
                exapp_token="",
                exapp_version=request_headers["ex-app-version"],
                host=request_headers["ex-app-host"],
                port=int(request_headers["ex-app-port"]),
            )
            # For K8s ExApps: resolve upstream from live Service
            k8s_upstream = await _k8s_resolve_exapp_upstream(exapp_id_lower)
            if k8s_upstream:
                # Fetch full record (with token & routes) so cache is complete
                try:
                    full_record = await nc_get_exapp(exapp_id_lower)
                except Exception:
                    full_record = None
                if full_record:
                    exapp_record = full_record
                exapp_record.host, exapp_record.port = k8s_upstream
                exapp_record.resolved_host = ""
                LOGGER.info("Resolved K8s upstream for '%s': %s:%d", exapp_id, *k8s_upstream)
                # Only cache if we have the full record (token + routes)
                if full_record:
                    async with EXAPP_CACHE_LOCK:
                        EXAPP_CACHE[exapp_id_lower] = exapp_record

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
                    # For K8s ExApps: resolve upstream from live Service
                    k8s_upstream = await _k8s_resolve_exapp_upstream(exapp_id_lower)
                    if k8s_upstream:
                        exapp_record.host, exapp_record.port = k8s_upstream
                        exapp_record.resolved_host = ""
                        LOGGER.info("Resolved K8s upstream for '%s': %s:%d", exapp_id, *k8s_upstream)
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
# Kubernetes helpers functions
###############################################################################


def _get_k8s_token() -> str | None:
    """Get (and cache) the Kubernetes bearer token."""
    global K8S_TOKEN
    if K8S_TOKEN:
        return K8S_TOKEN.strip()
    if K8S_TOKEN_FILE and os.path.exists(K8S_TOKEN_FILE):
        try:
            with open(K8S_TOKEN_FILE, encoding="utf-8") as f:
                token = f.read().strip()
                if token:
                    K8S_TOKEN = token
                    return token
        except Exception as e:
            LOGGER.error("Failed to read Kubernetes token file '%s': %s", K8S_TOKEN_FILE, e)
    LOGGER.error(
        "Kubernetes bearer token not found. "
        "Set HP_K8S_BEARER_TOKEN or HP_K8S_BEARER_TOKEN_FILE when HP_K8S_ENABLED=true."
    )
    return None


def _get_k8s_ssl_context() -> ssl.SSLContext | bool:
    """Return SSL context (or False to disable verification) for K8s API."""
    if not K8S_API_SERVER or not K8S_API_SERVER.startswith("https"):
        return False
    if not K8S_VERIFY_SSL:
        return False
    try:
        cafile = K8S_CA_FILE if K8S_CA_FILE and os.path.exists(K8S_CA_FILE) else None
        return ssl.create_default_context(cafile=cafile)
    except Exception as e:
        LOGGER.warning("Failed to create SSL context for Kubernetes API: %s", e)
        return ssl.create_default_context()


def _ensure_k8s_configured() -> None:
    if not K8S_ENABLED:
        LOGGER.error("Kubernetes backend requested but HP_K8S_ENABLED is not true.")
        raise web.HTTPServiceUnavailable(text="Kubernetes backend is disabled in HaRP.")
    if not K8S_API_SERVER:
        LOGGER.error("Kubernetes backend requested but HP_K8S_API_SERVER is not configured.")
        raise web.HTTPServiceUnavailable(text="Kubernetes API server is not configured.")
    if not _get_k8s_token():
        raise web.HTTPServiceUnavailable(text="Kubernetes token is not configured.")


async def _k8s_request(
    method: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    json_body: Any | None = None,
    content_type: str | None = None,
) -> tuple[int, dict[str, Any] | None, str]:
    """Low-level helper for talking to the Kubernetes API."""
    _ensure_k8s_configured()
    token = _get_k8s_token()
    assert token  # ensured by _ensure_k8s_configured  # noqa TO-DO

    headers: dict[str, str] = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if json_body is not None:
        headers["Content-Type"] = content_type or "application/json"

    url = f"{K8S_API_SERVER}{path}"
    ssl_ctx = _get_k8s_ssl_context()
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)

    async with aiohttp.ClientSession(timeout=K8S_HTTP_TIMEOUT, connector=connector) as session:
        try:
            async with session.request(method.upper(), url, headers=headers, params=query, json=json_body) as resp:
                text = await resp.text()
                data: dict[str, Any] | None = None
                if "application/json" in resp.headers.get("Content-Type", "") and text:
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        LOGGER.warning("Failed to parse JSON from Kubernetes API %s %s: %s", method, url, text[:200])
                return resp.status, data, text
        except aiohttp.ClientError as e:
            LOGGER.error("Error communicating with Kubernetes API (%s %s): %s", method, url, e)
            raise web.HTTPServiceUnavailable(text="Error communicating with Kubernetes API") from e


def _k8s_parse_env(env_list: list[str]) -> list[dict[str, str]]:
    """Convert ['KEY=VALUE', ...] to Kubernetes env entries."""
    result: list[dict[str, str]] = []
    for raw in env_list:
        if not raw:
            continue
        if "=" in raw:
            name, value = raw.split("=", 1)
            result.append({"name": name, "value": value})
        else:
            result.append({"name": raw, "value": ""})  # No '=', keep name and use empty value
    return result


def _k8s_build_resources(resource_limits: dict[str, Any]) -> dict[str, Any]:
    """Convert limits to Kubernetes resources.

    Supports both:
      - Docker-style: {"memory": <bytes>, "nanoCPUs": <int>}
      - K8s-style:    {"memory": "512Mi", "cpu": "500m"}
    """
    if not resource_limits:
        return {}
    limits: dict[str, str] = {}
    requests: dict[str, str] = {}

    # Memory
    mem_val = resource_limits.get("memory")
    mem_str: str | None = None
    if isinstance(mem_val, int) and mem_val > 0:
        # bytes -> Mi (ceil)
        mem_mi = (mem_val + (1024 * 1024 - 1)) // (1024 * 1024)
        mem_str = f"{mem_mi}Mi"
    elif isinstance(mem_val, str) and mem_val:
        mem_str = mem_val  # Already in K8s units, e.g. "512Mi"

    if mem_str:
        limits["memory"] = mem_str
        requests["memory"] = mem_str  # conservative: same as limit

    # CPU
    cpu_str: str | None = None
    nano_cpus = resource_limits.get("nanoCPUs")
    if isinstance(nano_cpus, int) and nano_cpus > 0:
        milli = (nano_cpus * 1000 + 1_000_000_000 - 1) // 1_000_000_000  # 1e9 nanoCPUs = 1 CPU => millicores
        milli = max(1, milli)
        cpu_str = f"{milli}m"
    else:
        cpu_val = resource_limits.get("cpu")
        if isinstance(cpu_val, str) and cpu_val:
            cpu_str = cpu_val  # Already in K8s units, e.g. "500m"

    if cpu_str:
        limits["cpu"] = cpu_str
        requests["cpu"] = cpu_str

    res: dict[str, Any] = {}
    if limits:
        res["limits"] = limits
    if requests:
        res["requests"] = requests
    return res


def _k8s_build_deployment_manifest(payload: CreateExAppPayload, replicas: int) -> dict[str, Any]:
    """Build a Deployment manifest from CreateExAppPayload."""
    deployment_name = payload.exapp_k8s_name
    pvc_name = payload.exapp_k8s_volume_name

    labels = {
        "app": deployment_name,
        "app.kubernetes.io/name": deployment_name,
        "app.kubernetes.io/component": "exapp",
    }
    if payload.instance_id:
        labels["app.kubernetes.io/instance"] = payload.instance_id

    container: dict[str, Any] = {
        "name": "app",
        "image": payload.image_id,
        "imagePullPolicy": "IfNotPresent",
        "env": _k8s_parse_env(payload.environment_variables),
    }

    resources = _k8s_build_resources(payload.resource_limits)
    if resources:
        container["resources"] = resources

    # Main data volume
    volumes = [
        {
            "name": "data",
            "persistentVolumeClaim": {"claimName": pvc_name},
        }
    ]
    volume_mounts = [
        {
            "name": "data",
            "mountPath": f"/{payload.exapp_container_volume}",
        }
    ]

    if payload.mount_points:
        LOGGER.warning(
            "Kubernetes backend currently ignores additional mount_points for ExApp '%s'.",
            deployment_name,
        )

    container["volumeMounts"] = volume_mounts

    manifest: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": deployment_name, "labels": labels},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": deployment_name}},
            "template": {"metadata": {"labels": labels}, "spec": {"containers": [container], "volumes": volumes}},
        },
    }
    manifest["spec"]["template"]["spec"] = {"containers": [container], "volumes": volumes}
    return manifest


def _k8s_build_service_manifest(
    payload: ExposeExAppPayload, service_type: Literal["NodePort", "ClusterIP", "LoadBalancer"]
) -> dict[str, Any]:
    service_name = payload.exapp_k8s_name
    labels = {
        "app": service_name,
        "app.kubernetes.io/name": service_name,
        "app.kubernetes.io/component": "exapp",
        **(payload.service_labels or {}),
    }
    if payload.instance_id:
        labels.setdefault("app.kubernetes.io/instance", payload.instance_id)

    metadata: dict[str, Any] = {"name": service_name, "labels": labels}
    if payload.service_annotations:
        metadata["annotations"] = payload.service_annotations

    svc_port = payload.service_port or payload.port
    port_entry: dict[str, Any] = {
        "name": "http",
        "port": svc_port,
        "targetPort": payload.port,
    }
    if service_type == "NodePort" and payload.node_port:
        port_entry["nodePort"] = payload.node_port

    spec: dict[str, Any] = {
        "type": service_type,
        "selector": {"app": service_name},
        "ports": [port_entry],
    }

    if payload.external_traffic_policy and service_type in ("NodePort", "LoadBalancer"):
        spec["externalTrafficPolicy"] = payload.external_traffic_policy

    if service_type == "LoadBalancer" and payload.load_balancer_ip:
        spec["loadBalancerIP"] = payload.load_balancer_ip

    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata,
        "spec": spec,
    }


async def _k8s_resolve_exapp_upstream(app_name: str) -> tuple[str, int] | None:
    """Look up the K8s Service for an ExApp and return the correct (host, port).

    Called on cache miss so that after a HaRP restart the correct upstream
    address is recovered from the live Service rather than relying on
    Nextcloud metadata (which stores the container-internal host/port).
    Returns None if K8s is disabled or no matching Service exists.
    """
    if not K8S_ENABLED or not K8S_API_SERVER or not _get_k8s_token():
        return None

    try:
        exapp = ExAppName(name=app_name)
    except Exception:
        return None

    service_name = exapp.exapp_k8s_name
    status, svc, _ = await _k8s_request(
        "GET",
        f"/api/v1/namespaces/{K8S_NAMESPACE}/services/{service_name}",
    )
    if status != 200 or not isinstance(svc, dict):
        return None

    svc_type = (svc.get("spec") or {}).get("type", "ClusterIP")
    try:
        if svc_type == "NodePort":
            port = _k8s_extract_nodeport(svc)
            host = await _k8s_pick_node_address(preferred_type="InternalIP")
            return (host, port)
        elif svc_type == "ClusterIP":
            port = _k8s_extract_service_port(svc)
            host = _k8s_service_dns_name(service_name, K8S_NAMESPACE)
            return (host, port)
        elif svc_type == "LoadBalancer":
            port = _k8s_extract_service_port(svc)
            host = _k8s_extract_loadbalancer_host(svc)
            if host:
                return (host, port)
    except Exception as e:
        LOGGER.warning("Failed to resolve K8s upstream for '%s': %s", app_name, e)
    return None


def _k8s_service_dns_name(service_name: str, namespace: str) -> str:
    # Cluster domain suffix is typically .svc.cluster.local, but .svc is enough inside most resolvers.
    return f"{service_name}.{namespace}.svc"


async def _k8s_pick_node_address(
    *,
    preferred_type: Literal["InternalIP", "ExternalIP"],
    node_name: str | None = None,
    label_selector: str | None = None,
) -> str:
    query = {"labelSelector": label_selector} if label_selector else None
    status, nodes_data, text = await _k8s_request("GET", "/api/v1/nodes", query=query)
    if status != 200 or not isinstance(nodes_data, dict):
        msg = (nodes_data or {}).get("message") if isinstance(nodes_data, dict) else text
        raise web.HTTPServiceUnavailable(text=f"Failed to list Kubernetes nodes: Status {status}, {msg}")

    items = nodes_data.get("items", [])
    if node_name:
        items = [n for n in items if n.get("metadata", {}).get("name") == node_name]

    if not items:
        raise web.HTTPServiceUnavailable(text="No Kubernetes nodes found (after filtering).")

    def is_ready(node: dict[str, Any]) -> bool:
        for cond in node.get("status", {}).get("conditions", []) or []:
            if cond.get("type") == "Ready" and cond.get("status") == "True":
                return True
        return False

    ready_nodes = [n for n in items if is_ready(n)]
    nodes = ready_nodes or items

    fallback_type = "ExternalIP" if preferred_type == "InternalIP" else "InternalIP"
    address_type_order = [preferred_type, fallback_type, "Hostname"]

    for node in nodes:
        for t in address_type_order:
            for addr in node.get("status", {}).get("addresses", []) or []:
                if addr.get("type") == t and addr.get("address"):
                    return str(addr["address"])

    raise web.HTTPServiceUnavailable(text="Could not determine a node address (no InternalIP/ExternalIP/Hostname).")


def _k8s_extract_nodeport(service: dict[str, Any]) -> int:
    ports = (service.get("spec") or {}).get("ports") or []
    if not ports or "nodePort" not in ports[0]:
        raise web.HTTPServiceUnavailable(text="Service has no nodePort assigned.")
    return int(ports[0]["nodePort"])


def _k8s_extract_service_port(service: dict[str, Any]) -> int:
    ports = (service.get("spec") or {}).get("ports") or []
    if not ports or "port" not in ports[0]:
        raise web.HTTPServiceUnavailable(text="Service has no port defined.")
    return int(ports[0]["port"])


def _k8s_extract_loadbalancer_host(service: dict[str, Any]) -> str | None:
    ingress = ((service.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []
    if not ingress:
        return None
    first = ingress[0] or {}
    return first.get("ip") or first.get("hostname")


async def _k8s_wait_for_loadbalancer_host(service_name: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.time() + max(0.0, timeout_s)
    while True:
        status, svc, text = await _k8s_request(
            "GET",
            f"/api/v1/namespaces/{K8S_NAMESPACE}/services/{service_name}",
        )
        if status != 200 or not isinstance(svc, dict):
            msg = (svc or {}).get("message") if isinstance(svc, dict) else text
            raise web.HTTPServiceUnavailable(text=f"Failed to read Service '{service_name}': Status {status}, {msg}")

        host = _k8s_extract_loadbalancer_host(svc)
        if host:
            return host

        if time.time() >= deadline:
            raise web.HTTPServiceUnavailable(
                text=f"Timed out waiting for LoadBalancer address for Service '{service_name}'"
            )

        await asyncio.sleep(interval_s)


###############################################################################
# Endpoints for AppAPI to work with the Kubernetes API
###############################################################################


async def k8s_exapp_exists(request: web.Request):
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = ExAppName.model_validate(payload_dict)
    except ValidationError as e:
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    deployment_name = payload.exapp_k8s_name
    LOGGER.debug(
        "Checking for Kubernetes deployment '%s' in namespace '%s'.",
        deployment_name,
        K8S_NAMESPACE,
    )
    status, data, _ = await _k8s_request(
        "GET",
        f"/apis/apps/v1/namespaces/{K8S_NAMESPACE}/deployments/{deployment_name}",
    )
    if status == 200:
        LOGGER.info("Kubernetes deployment '%s' exists.", deployment_name)
        return web.json_response({"exists": True})
    if status == 404:
        LOGGER.info("Kubernetes deployment '%s' does not exist.", deployment_name)
        return web.json_response({"exists": False})
    msg = (data or {}).get("message", "")
    LOGGER.error(
        "Error checking Kubernetes deployment '%s' (status %s): %s",
        deployment_name,
        status,
        msg,
    )
    raise web.HTTPServiceUnavailable(text=f"Error checking Kubernetes deployment '{deployment_name}': Status {status}")


async def k8s_exapp_create(request: web.Request):
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /k8s/exapp/create")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = CreateExAppPayload.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /k8s/exapp/create: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    deployment_name = payload.exapp_k8s_name
    pvc_name = payload.exapp_k8s_volume_name

    LOGGER.info(
        "Creating Kubernetes resources for ExApp '%s' (Deployment=%s, PVC=%s, namespace=%s).",
        payload.name,
        deployment_name,
        pvc_name,
        K8S_NAMESPACE,
    )

    # 1) PVC for data
    pvc_manifest: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": pvc_name,
            "labels": {
                "app": deployment_name,
                "app.kubernetes.io/name": deployment_name,
                "app.kubernetes.io/component": "exapp",
            },
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": K8S_DEFAULT_STORAGE_SIZE}},
        },
    }
    if K8S_STORAGE_CLASS:
        pvc_manifest["spec"]["storageClassName"] = K8S_STORAGE_CLASS

    status, data, text = await _k8s_request(
        "POST",
        f"/api/v1/namespaces/{K8S_NAMESPACE}/persistentvolumeclaims",
        json_body=pvc_manifest,
    )
    if status in (200, 201):
        LOGGER.info("PVC '%s' created for ExApp '%s'.", pvc_name, deployment_name)
    elif status == 409:
        LOGGER.info("PVC '%s' already exists for ExApp '%s'.", pvc_name, deployment_name)
    else:
        msg = (data or {}).get("message") if isinstance(data, dict) else text
        LOGGER.error(
            "Failed to create PVC '%s' for exapp '%s' (status %s): %s",
            pvc_name,
            deployment_name,
            status,
            msg,
        )
        raise web.HTTPServiceUnavailable(text=f"Failed to create PVC '{pvc_name}': Status {status}")

    # 2) Deployment with replicas=0 (start/stop handled separately)
    deployment_manifest = _k8s_build_deployment_manifest(payload, replicas=0)
    status, data, text = await _k8s_request(
        "POST",
        f"/apis/apps/v1/namespaces/{K8S_NAMESPACE}/deployments",
        json_body=deployment_manifest,
    )
    if status in (200, 201):
        LOGGER.info("Kubernetes deployment '%s' created.", deployment_name)
        # Docker endpoint returns {"id": ..., "name": ...}; we don't have Deployment UID here, only name.
        return web.json_response({"name": deployment_name}, status=201)
    if status == 409:
        LOGGER.warning("Kubernetes deployment '%s' already exists.", deployment_name)
        raise web.HTTPConflict(text=f"Deployment '{deployment_name}' already exists.")
    msg = (data or {}).get("message") if isinstance(data, dict) else text
    LOGGER.error(
        "Error creating Kubernetes deployment '%s' (status %s): %s",
        deployment_name,
        status,
        msg,
    )
    raise web.HTTPServiceUnavailable(text=f"Error creating deployment '{deployment_name}': Status {status}")


async def k8s_exapp_start(request: web.Request):
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /k8s/exapp/start")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = ExAppName.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /k8s/exapp/start: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    deployment_name = payload.exapp_k8s_name
    patch_body = {"spec": {"replicas": 1}}

    LOGGER.info(
        "Scaling Kubernetes deployment '%s' to 1 replica in namespace '%s'.",
        deployment_name,
        K8S_NAMESPACE,
    )

    status, data, text = await _k8s_request(
        "PATCH",
        f"/apis/apps/v1/namespaces/{K8S_NAMESPACE}/deployments/{deployment_name}",
        json_body=patch_body,
        content_type="application/strategic-merge-patch+json",
    )
    if status in (200, 201):
        LOGGER.info("Deployment '%s' scaled to 1 replica.", deployment_name)
        return web.HTTPNoContent()
    if status == 404:
        LOGGER.warning("Deployment '%s' not found when trying to start.", deployment_name)
        raise web.HTTPNotFound(text=f"Deployment '{deployment_name}' not found.")
    msg = (data or {}).get("message") if isinstance(data, dict) else text
    LOGGER.error(
        "Error scaling deployment '%s' to 1 replica (status %s): %s",
        deployment_name,
        status,
        msg,
    )
    raise web.HTTPServiceUnavailable(text=f"Error starting deployment '{deployment_name}': Status {status}")


async def k8s_exapp_stop(request: web.Request):
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /k8s/exapp/stop")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = ExAppName.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /k8s/exapp/stop: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    deployment_name = payload.exapp_k8s_name
    patch_body = {"spec": {"replicas": 0}}

    LOGGER.info(
        "Scaling Kubernetes deployment '%s' to 0 replicas in namespace '%s'.",
        deployment_name,
        K8S_NAMESPACE,
    )

    status, data, text = await _k8s_request(
        "PATCH",
        f"/apis/apps/v1/namespaces/{K8S_NAMESPACE}/deployments/{deployment_name}",
        json_body=patch_body,
        content_type="application/strategic-merge-patch+json",
    )
    if status in (200, 201):
        LOGGER.info("Deployment '%s' scaled to 0 replicas.", deployment_name)
        return web.HTTPNoContent()
    if status == 404:
        LOGGER.warning("Deployment '%s' not found when trying to stop.", deployment_name)
        raise web.HTTPNotFound(text=f"Deployment '{deployment_name}' not found.")
    msg = (data or {}).get("message") if isinstance(data, dict) else text
    LOGGER.error(
        "Error scaling deployment '%s' to 0 replicas (status %s): %s",
        deployment_name,
        status,
        msg,
    )
    raise web.HTTPServiceUnavailable(text=f"Error stopping deployment '{deployment_name}': Status {status}")


async def k8s_exapp_wait_for_start(request: web.Request):
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /k8s/exapp/wait_for_start")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = ExAppName.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /k8s/exapp/wait_for_start: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    deployment_name = payload.exapp_k8s_name
    label_selector = f"app={deployment_name}"

    max_tries = 180
    sleep_interval = 0.5

    LOGGER.info(
        "Waiting for Kubernetes pod(s) of deployment '%s' to become Ready "
        "(namespace=%s, max_tries=%d, interval=%.1fs).",
        deployment_name,
        K8S_NAMESPACE,
        max_tries,
        sleep_interval,
    )

    last_phase: str | None = None
    last_reason: str | None = None
    last_message: str | None = None

    for attempt in range(max_tries):
        status, data, text = await _k8s_request(
            "GET",
            f"/api/v1/namespaces/{K8S_NAMESPACE}/pods",
            query={"labelSelector": label_selector},
        )
        if status != 200:
            msg = (data or {}).get("message") if isinstance(data, dict) else text
            LOGGER.error(
                "Error listing pods for deployment '%s' (status %s, attempt %d): %s",
                deployment_name,
                status,
                attempt + 1,
                msg,
            )
            raise web.HTTPServiceUnavailable(
                text=f"Error listing pods for deployment '{deployment_name}': Status {status}"
            )

        items = (data or {}).get("items", []) if isinstance(data, dict) else []
        if not items:
            LOGGER.debug(
                "No pods yet for deployment '%s' (attempt %d/%d).",
                deployment_name,
                attempt + 1,
                max_tries,
            )
            last_phase = "Pending"
        else:
            # Take the first pod; for single-replica deployments this is enough.
            pod = items[0]
            pod_status = pod.get("status", {})
            phase = pod_status.get("phase", "Unknown")
            last_phase = phase
            conditions = pod_status.get("conditions", [])
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
            last_reason = pod_status.get("reason")
            last_message = pod_status.get("message")

            LOGGER.debug(
                "Pod status for '%s' (attempt %d/%d): phase=%s, ready=%s, reason=%s, message=%s",
                deployment_name,
                attempt + 1,
                max_tries,
                phase,
                ready,
                last_reason,
                last_message,
            )

            if phase == "Running" and ready:
                LOGGER.info("Deployment '%s' pod is Running and Ready.", deployment_name)
                return web.json_response(
                    {
                        "started": True,
                        "status": "running",
                        "health": "ready",
                        "reason": last_reason,
                        "message": last_message,
                    }
                )

            if phase in ("Failed", "Unknown", "Succeeded"):
                LOGGER.warning(
                    "Deployment '%s' pod is in phase '%s', treating as not successfully started.",
                    deployment_name,
                    phase,
                )
                return web.json_response(
                    {
                        "started": False,
                        "status": phase,
                        "health": "not_ready",
                        "reason": last_reason,
                        "message": last_message,
                    }
                )

        if attempt < max_tries - 1:
            await asyncio.sleep(sleep_interval)

    LOGGER.warning(
        "Deployment '%s' did not become Ready within %d attempts.",
        deployment_name,
        max_tries,
    )
    return web.json_response(
        {
            "started": False,
            "status": last_phase or "unknown",
            "health": "timeout",
            "reason": last_reason,
            "message": last_message,
        }
    )


async def k8s_exapp_remove(request: web.Request):
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /k8s/exapp/remove")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    try:
        payload = RemoveExAppPayload.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /k8s/exapp/remove: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    deployment_name = payload.exapp_k8s_name
    pvc_name = payload.exapp_k8s_volume_name
    service_name = payload.exapp_k8s_name

    LOGGER.info(
        "Removing Kubernetes deployment '%s' (namespace=%s, remove_data=%s).",
        deployment_name,
        K8S_NAMESPACE,
        payload.remove_data,
    )

    # Delete Deployment
    status, data, text = await _k8s_request(
        "DELETE",
        f"/apis/apps/v1/namespaces/{K8S_NAMESPACE}/deployments/{deployment_name}",
    )
    if status in (200, 202, 404):
        LOGGER.info("Deployment '%s' removed or did not exist (status=%s).", deployment_name, status)
    else:
        msg = (data or {}).get("message") if isinstance(data, dict) else text
        LOGGER.error(
            "Error removing deployment '%s' (status %s): %s",
            deployment_name,
            status,
            msg,
        )
        raise web.HTTPServiceUnavailable(text=f"Error removing deployment '{deployment_name}': Status {status}")

    # Optionally delete PVC (data)
    if payload.remove_data:
        LOGGER.info("Removing PVC '%s' for deployment '%s'.", pvc_name, deployment_name)
        status, data, text = await _k8s_request(
            "DELETE",
            f"/api/v1/namespaces/{K8S_NAMESPACE}/persistentvolumeclaims/{pvc_name}",
        )
        if status in (200, 202, 404):
            LOGGER.info("PVC '%s' removed or did not exist (status=%s).", pvc_name, status)
        else:
            msg = (data or {}).get("message") if isinstance(data, dict) else text
            LOGGER.error(
                "Error removing PVC '%s' (status %s): %s",
                pvc_name,
                status,
                msg,
            )
            raise web.HTTPServiceUnavailable(text=f"Error removing PVC '{pvc_name}': Status {status}")

    # Always try to delete Service (if ExApp was exposed)
    LOGGER.info("Removing Service '%s' for deployment '%s'.", service_name, deployment_name)
    status, data, text = await _k8s_request(
        "DELETE",
        f"/api/v1/namespaces/{K8S_NAMESPACE}/services/{service_name}",
    )

    if status in (200, 202, 404):
        LOGGER.info("Service '%s' removed or did not exist (status=%s).", service_name, status)
        return web.HTTPNoContent()
    msg = (data or {}).get("message") if isinstance(data, dict) else text
    LOGGER.error("Error removing Service '%s' (status %s): %s", service_name, status, msg)
    raise web.HTTPServiceUnavailable(text=f"Error removing Service '{service_name}': Status {status}")


async def k8s_exapp_install_certificates(request: web.Request):
    """Kubernetes backend: install_certificates is currently a no-op.

    For Kubernetes, we recommend handling system and FRP certificates via Secrets
    and volume mounts in the Deployment spec rather than exec'ing into containers.
    """
    try:
        _ = InstallCertificatesPayload.model_validate(await request.json())
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /k8s/exapp/install_certificates")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /k8s/exapp/install_certificates: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    LOGGER.info(
        "Kubernetes backend: /k8s/exapp/install_certificates is a no-op. "
        "Use Kubernetes Secrets + volume mounts instead."
    )
    return web.HTTPNoContent()


async def k8s_exapp_expose(request: web.Request):
    try:
        payload_dict = await request.json()
    except json.JSONDecodeError:
        LOGGER.warning("Invalid JSON body received for /k8s/exapp/expose")
        raise web.HTTPBadRequest(text="Invalid JSON body") from None

    try:
        payload = ExposeExAppPayload.model_validate(payload_dict)
    except ValidationError as e:
        LOGGER.warning("Payload validation error for /k8s/exapp/expose: %s", e)
        raise web.HTTPBadRequest(text=f"Payload validation error: {e}") from None

    app_id = payload.name.lower()
    service_name = payload.exapp_k8s_name

    # 0) Manual mode: no Kubernetes calls, just register upstream endpoint
    if payload.expose_type == "manual":
        upstream_host = payload.upstream_host  # validated non-empty
        upstream_port = int(payload.upstream_port or payload.port)
        LOGGER.info(
            "Expose ExApp '%s' (manual): registering upstream %s:%d",
            app_id,
            upstream_host,
            upstream_port,
        )
    else:
        _ensure_k8s_configured()

        # 1) Ensure Service exists with desired type
        if payload.expose_type == "nodeport":
            desired_type: Literal["NodePort", "ClusterIP", "LoadBalancer"] = "NodePort"
        elif payload.expose_type == "clusterip":
            desired_type = "ClusterIP"
        elif payload.expose_type == "loadbalancer":
            desired_type = "LoadBalancer"
        else:
            raise web.HTTPBadRequest(text=f"Unknown expose_type '{payload.expose_type}'")

        service_manifest = _k8s_build_service_manifest(payload, desired_type)
        LOGGER.info(
            "Ensuring Service for ExApp '%s' (service=%s, type=%s, namespace=%s).",
            app_id,
            service_name,
            desired_type,
            K8S_NAMESPACE,
        )

        status, data, text = await _k8s_request(
            "POST",
            f"/api/v1/namespaces/{K8S_NAMESPACE}/services",
            json_body=service_manifest,
        )
        if status in (200, 201):
            LOGGER.info("Service '%s' created.", service_name)
        elif status == 409:
            LOGGER.info("Service '%s' already exists, will re-use it.", service_name)
        else:
            msg = (data or {}).get("message") if isinstance(data, dict) else text
            LOGGER.error("Failed to create Service '%s' (status %s): %s", service_name, status, msg)
            raise web.HTTPServiceUnavailable(text=f"Failed to create Service '{service_name}': Status {status}")

        # 2) Read Service back
        status, svc, text = await _k8s_request(
            "GET",
            f"/api/v1/namespaces/{K8S_NAMESPACE}/services/{service_name}",
        )
        if status != 200 or not isinstance(svc, dict):
            msg = (svc or {}).get("message") if isinstance(svc, dict) else text
            LOGGER.error("Failed to read Service '%s' (status %s): %s", service_name, status, msg)
            raise web.HTTPServiceUnavailable(text=f"Failed to read Service '{service_name}': Status {status}")

        # 3) Determine upstream endpoint HaRP should use
        if payload.expose_type == "nodeport":
            node_port = _k8s_extract_nodeport(svc)
            upstream_port = node_port

            # Prefer explicit upstream_host (recommended); else auto-pick a node address
            if payload.upstream_host:
                upstream_host = payload.upstream_host
            else:
                upstream_host = await _k8s_pick_node_address(
                    preferred_type=payload.node_address_type,
                    node_name=payload.node_name,
                    label_selector=payload.node_label_selector,
                )

            LOGGER.info(
                "Expose ExApp '%s' (nodeport): upstream %s:%d (service=%s).",
                app_id,
                upstream_host,
                upstream_port,
                service_name,
            )

        elif payload.expose_type == "clusterip":
            upstream_port = _k8s_extract_service_port(svc)
            upstream_host = payload.upstream_host or _k8s_service_dns_name(service_name, K8S_NAMESPACE)

            LOGGER.info(
                "Expose ExApp '%s' (clusterip): upstream %s:%d (service=%s).",
                app_id,
                upstream_host,
                upstream_port,
                service_name,
            )

        else:  # loadbalancer
            upstream_port = _k8s_extract_service_port(svc)

            if payload.upstream_host:
                upstream_host = payload.upstream_host
            else:
                upstream_host = _k8s_extract_loadbalancer_host(svc)
                if not upstream_host:
                    upstream_host = await _k8s_wait_for_loadbalancer_host(
                        service_name,
                        timeout_s=payload.wait_timeout_seconds,
                        interval_s=payload.wait_interval_seconds,
                    )

            LOGGER.info(
                "Expose ExApp '%s' (loadbalancer): upstream %s:%d (service=%s).",
                app_id,
                upstream_host,
                upstream_port,
                service_name,
            )

    # 4) Fetch ExApp metadata from Nextcloud and override host/port registered in HaRP cache
    try:
        exapp_meta = await nc_get_exapp(app_id)
        if not exapp_meta:
            LOGGER.error("No ExApp metadata for '%s' in Nextcloud.", app_id)
            raise web.HTTPNotFound(text=f"No ExApp metadata for '{app_id}'")
    except web.HTTPException:
        raise
    except Exception as e:
        LOGGER.exception("Failed to fetch ExApp metadata for '%s'", app_id)
        raise web.HTTPServiceUnavailable(text=f"Failed to fetch metadata for '{app_id}'") from e

    exapp_meta.host = upstream_host
    exapp_meta.port = int(upstream_port)
    exapp_meta.resolved_host = ""  # force resolve_ip again

    async with EXAPP_CACHE_LOCK:
        EXAPP_CACHE[app_id] = exapp_meta

    # Keep old response fields, add useful extras
    return web.json_response(
        {
            "appId": app_id,
            "host": upstream_host,
            "port": int(upstream_port),
            "exposeType": payload.expose_type,
            "serviceName": service_name,
            "namespace": K8S_NAMESPACE,
        }
    )


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

    # Kubernetes APIs wrappers
    app.router.add_post("/k8s/exapp/exists", k8s_exapp_exists)
    app.router.add_post("/k8s/exapp/create", k8s_exapp_create)
    app.router.add_post("/k8s/exapp/start", k8s_exapp_start)
    app.router.add_post("/k8s/exapp/stop", k8s_exapp_stop)
    app.router.add_post("/k8s/exapp/wait_for_start", k8s_exapp_wait_for_start)
    app.router.add_post("/k8s/exapp/remove", k8s_exapp_remove)
    app.router.add_post("/k8s/exapp/install_certificates", k8s_exapp_install_certificates)
    app.router.add_post("/k8s/exapp/expose", k8s_exapp_expose)
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
    spoa_task = asyncio.create_task(SPOA_AGENT._run(host=SPOA_HOST, port=SPOA_PORT))  # noqa
    http_task = asyncio.create_task(run_http_server(host="127.0.0.1", port=8200))

    LOGGER.info("Starting both servers: SPOA on %s:%d, HTTP on 127.0.0.1:8200", SPOA_HOST, SPOA_PORT)
    await asyncio.gather(spoa_task, http_task)


if __name__ == "__main__":
    asyncio.run(main())
