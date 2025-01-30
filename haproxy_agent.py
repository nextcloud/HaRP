"""An agent for HaProxy that takes care of most of the authentication logic of AppAPI"""

import asyncio
import ipaddress
import logging
import os
from typing import Any

from aiohttp import web
from haproxyspoa.payloads.ack import AckPayload
from haproxyspoa.spoa_server import SpoaServer

# Set up the logging configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING")
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)
logger.setLevel(level=LOG_LEVEL)
logging.getLogger("haproxyspoa").setLevel(level=LOG_LEVEL)
logging.getLogger("aiohttp").setLevel(level=LOG_LEVEL)

SPOA_AGENT = SpoaServer()

###############################################################################
# In-memory caches
###############################################################################

EXAPP_CACHE: dict[str, dict[str, Any]] = {}
"""
Example of EXAPP_CACHE[app_id]:
{
  "app_api_token": str,
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

SESSION_CACHE: dict[str, dict[str, str]] = {}
"""
Example of SESSION_CACHE[session_passphrase]:
{
  "user_id": str,
  "access_level": str  # "ADMIN", "USER", "PUBLIC"
}
"""

BLACKLISTED_IPS = set()
BLACKLISTED_SUBNETS = set()

###############################################################################
# SPOA Handlers
###############################################################################


@SPOA_AGENT.handler("check_client_ip")
async def check_client_ip(ip):
    ip_str = str(ip)
    logger.debug(f"Incoming IP: {ip_str}")  # noqa

    # 1) Check direct IP membership in BLACKLISTED_IPS
    if ip_str in BLACKLISTED_IPS:
        logger.warning(f"IP {ip_str} is in the blacklist. BANNED.")  # noqa
        return AckPayload().set_txn_var("good", 0)

    # 2) Check if belongs to any blacklisted subnet
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        # If for some reason not a valid IP, mark as not good
        logger.error(f"Invalid IP address format: {ip_str}. BANNED.")  # noqa
        return AckPayload().set_txn_var("good", 0)

    for subnet_str in BLACKLISTED_SUBNETS:
        if ip_obj in ipaddress.ip_network(subnet_str):
            logger.warning(f"IP {ip_str} is in blacklisted subnet {subnet_str}. BANNED.")  # noqa
            return AckPayload().set_txn_var("good", 0)

    logger.debug(f"IP {ip_str} is allowed. GOOD.")  # noqa
    # Otherwise it's good
    return AckPayload().set_txn_var("good", 1)


@SPOA_AGENT.handler("exapps_msg")
async def exapps_msg(path: str, hdrs: str):
    logger.debug("exapps_msg triggered!")
    logger.debug(f"path: {path} ---- headers: {hdrs}")  # noqa
    return AckPayload()


###############################################################################
# ExApp routes
###############################################################################


async def list_exapps(request: web.Request):
    return web.json_response(EXAPP_CACHE)


async def get_exapp(request: web.Request):
    record = EXAPP_CACHE.get(request.match_info["app_id"])
    if record is None:
        raise web.HTTPNotFound()
    return web.json_response(record)


async def add_exapp(request: web.Request):
    data = await request.json()

    # Minimal validation
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
        # "bruteforce_protection" may or may not be present, but if present, must be valid
        if "bruteforce_protection" in route:
            if not isinstance(route["bruteforce_protection"], list):
                raise web.HTTPBadRequest()
            for code in route["bruteforce_protection"]:
                if not isinstance(code, int):
                    raise web.HTTPBadRequest()

    # Overwrite if already exists
    EXAPP_CACHE[request.match_info["app_id"]] = data
    return web.HTTPNoContent()


async def delete_exapp(request: web.Request):
    old = EXAPP_CACHE.pop(request.match_info["app_id"], None)
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

    # Minimal validation
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
# Blacklist routes (IP addresses / subnets)
###############################################################################


async def add_ip(request: web.Request):
    """Adds either an IPv4 or IPv6 single address to BLACKLISTED_IPS."""
    ip_str = request.match_info["ip"]
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        raise web.HTTPBadRequest() from None

    BLACKLISTED_IPS.add(ip_str)
    logger.info("Added IP %s to the blacklist.", ip_str)
    return web.HTTPNoContent()


async def delete_ip(request: web.Request):
    ip_str = request.match_info["ip"]
    try:
        BLACKLISTED_IPS.remove(ip_str)
        logger.info("Removed IP %s from the blacklist.", ip_str)
    except KeyError:
        raise web.HTTPNotFound() from None
    return web.HTTPNoContent()


async def add_subnet(request: web.Request):
    """Adds either an IPv4 or IPv6 subnet (CIDR) to BLACKLISTED_SUBNETS."""
    cidr_str = request.match_info["cidr"]
    try:
        ipaddress.ip_network(cidr_str)
    except ValueError:
        raise web.HTTPBadRequest() from None

    BLACKLISTED_SUBNETS.add(cidr_str)
    logger.info("Added subnet %s to the blacklist.", cidr_str)
    return web.HTTPNoContent()


async def delete_subnet(request: web.Request):
    cidr_str = request.match_info["cidr"]
    try:
        BLACKLISTED_SUBNETS.remove(cidr_str)
        logger.info("Removed subnet %s from the blacklist.", cidr_str)
    except KeyError:
        raise web.HTTPNotFound() from None
    return web.HTTPNoContent()


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

    # Blacklist routes
    app.router.add_post("/blacklist/ip/{ip}", add_ip)
    app.router.add_delete("/blacklist/ip/{ip}", delete_ip)
    app.router.add_post("/blacklist/subnet/{cidr}", add_subnet)
    app.router.add_delete("/blacklist/subnet/{cidr}", delete_subnet)

    return app


async def run_http_server(host="127.0.0.1", port=8000):
    app = create_web_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    logger.info("HTTP server listening at %s:%s", host, port)
    await site.start()

    # Keep running forever
    while True:
        await asyncio.sleep(3600)


###############################################################################
# Main entry point: run both SPOA & HTTP
###############################################################################


async def main():
    spoa_task = asyncio.create_task(SPOA_AGENT._run(host="127.0.0.1", port=9600))  # noqa
    http_task = asyncio.create_task(run_http_server(host="127.0.0.1", port=8000))

    logger.info("Starting both servers: SPOA on 127.0.0.1:9600, HTTP on 127.0.0.1:8000")
    await asyncio.gather(spoa_task, http_task)


if __name__ == "__main__":
    asyncio.run(main())
    SPOA_AGENT.run()
