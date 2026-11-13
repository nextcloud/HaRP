# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""How `/docker/exapp/create` requests GPUs: the "nvidia" driver on Docker, CDI devices on Podman 5.4 or later."""

import asyncio
import logging

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import haproxy_agent as agent

from .payloads import DOCKER_CREATE_PAYLOAD

AUTH = {"harp-shared-key": "unit-test-shared-key"}
NVIDIA_REQUEST = [{"Driver": "nvidia", "Count": -1, "Capabilities": [["compute", "utility"]]}]
CDI_REQUEST = [{"Driver": "cdi", "DeviceIDs": ["nvidia.com/gpu=all"]}]
# AppAPI adds these for a "cuda" daemon.
NVIDIA_ENV = ["NVIDIA_VISIBLE_DEVICES=all", "NVIDIA_DRIVER_CAPABILITIES=compute,utility"]
OTHER_ENV = [agent.with_exapp_frp_token([entry])[0] for entry in DOCKER_CREATE_PAYLOAD["environment_variables"]]


def create_on_engine(monkeypatch, podman_version: str | None, compute_device: str) -> dict:
    """Create an ExApp container on a fake engine, Podman when a version is given; return the container config."""
    configs = []

    @web.middleware
    async def engine_headers(request, handler):
        response = await handler(request)
        if podman_version is not None:
            response.headers["Libpod-Api-Version"] = podman_version
        return response

    async def volume_missing(_request):
        return web.Response(status=404)

    async def volume_created(_request):
        return web.json_response({}, status=201)

    async def container_created(request):
        configs.append(await request.json())
        return web.json_response({"Id": "0123456789ab"}, status=201)

    engine = web.Application(middlewares=[engine_headers])
    engine.router.add_get("/volumes/{name}", volume_missing)
    engine.router.add_post("/volumes/create", volume_created)
    engine.router.add_post("/containers/create", container_created)
    payload = {
        **DOCKER_CREATE_PAYLOAD,
        "compute_device": compute_device,
        "environment_variables": [*DOCKER_CREATE_PAYLOAD["environment_variables"], *NVIDIA_ENV],
    }

    async def run():
        async with TestServer(engine) as engine_server, TestClient(TestServer(agent.create_web_app())) as client:
            monkeypatch.setattr(agent, "DOCKER_ENGINE_PORTS", [(engine_server.port, engine_server.port)])
            headers = {**AUTH, "docker-engine-port": str(engine_server.port)}
            response = await client.post("/docker/exapp/create", json=payload, headers=headers)
            assert response.status == 201, await response.text()

    asyncio.run(run())
    return configs[0]


@pytest.mark.parametrize(
    ("podman_version", "device_requests", "env", "warning"),
    [
        (None, NVIDIA_REQUEST, OTHER_ENV + NVIDIA_ENV, False),
        ("6.1.3", CDI_REQUEST, OTHER_ENV, False),
        ("5.4.0-dev", CDI_REQUEST, OTHER_ENV, False),
        ("5.3.2", NVIDIA_REQUEST, OTHER_ENV + NVIDIA_ENV, True),
        ("unknown", NVIDIA_REQUEST, OTHER_ENV + NVIDIA_ENV, True),
    ],
)
def test_cuda_gets_cdi_devices_only_on_podman_5_4_or_later(
    monkeypatch, caplog, podman_version, device_requests, env, warning
):
    with caplog.at_level(logging.WARNING, logger="haproxy_agent"):
        config = create_on_engine(monkeypatch, podman_version, "cuda")
    assert config["HostConfig"]["DeviceRequests"] == device_requests
    assert config["Env"] == env
    assert ("GPUs need Podman 5.4 or later" in caplog.text) is warning


@pytest.mark.parametrize("podman_version", [None, "6.1.3"])
@pytest.mark.parametrize("compute_device", ["cpu", "rocm"])
def test_cpu_and_rocm_containers_are_the_same_on_docker_and_podman(monkeypatch, podman_version, compute_device):
    config = create_on_engine(monkeypatch, podman_version, compute_device)
    assert "DeviceRequests" not in config["HostConfig"]
    assert config["Env"] == OTHER_ENV + NVIDIA_ENV
    devices = [device["PathOnHost"] for device in config["HostConfig"].get("Devices", [])]
    assert devices == (["/dev/kfd", "/dev/dri"] if compute_device == "rocm" else [])
