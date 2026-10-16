# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validation of the payloads AppAPI sends to the `/docker/exapp/*` and `/k8s/exapp/*` endpoints."""

import pytest
from pydantic import ValidationError

import haproxy_agent as agent

from .payloads import DOCKER_CREATE_PAYLOAD, K8S_CREATE_PAYLOAD


def create_payload(**changes):
    return agent.CreateExAppPayload.model_validate({**DOCKER_CREATE_PAYLOAD, **changes})


# AppAPI 32 sends no resource limits; the restart policy defaults to unless-stopped.
@pytest.mark.parametrize("left_out", [(), ("resource_limits", "mount_points", "restart_policy")])
def test_docker_create_payload_is_accepted(left_out):
    payload = {k: v for k, v in DOCKER_CREATE_PAYLOAD.items() if k not in left_out}
    assert agent.CreateExAppPayload.model_validate(payload).restart_policy == "unless-stopped"


def test_k8s_create_payload_is_accepted():
    payload = agent.CreateExAppPayload.model_validate(K8S_CREATE_PAYLOAD)
    assert (payload.network_mode, payload.role_suffix) == ("bridge", "rp")


@pytest.mark.parametrize("name", ["context_chat_backend", "test-deploy", "a.b", "A1", "x" * 63])
def test_name_accepted(name):
    assert agent.ExAppName(name=name).name == name


@pytest.mark.parametrize("name", ["", "../etc", "a b", "a?force=true", "-a", "_a", "a\n", "ä", "x" * 64])
def test_name_rejected(name):
    with pytest.raises(ValidationError):
        agent.ExAppName(name=name)


@pytest.mark.parametrize("field", ["instance_id", "role_suffix"])
@pytest.mark.parametrize(
    ("value", "valid"),
    [("", True), ("_idx.1", True), ("x" * 63, True), ("a/b", False), ("a b", False), ("a\n", False), ("x" * 64, False)],
)
def test_name_parts(field, value, valid):
    if valid:
        assert getattr(agent.ExAppName(name="app", **{field: value}), field) == value
    else:
        with pytest.raises(ValidationError):
            agent.ExAppName(name="app", **{field: value})


@pytest.mark.parametrize("network_mode", ["host", "bridge", "nextcloud-aio", "master_bridge", "my.net", "n" * 255])
def test_network_mode_accepted(network_mode):
    assert create_payload(network_mode=network_mode).network_mode == network_mode


@pytest.mark.parametrize("network_mode", ["", "container:nc_app_other", "my net", "net\x01", "net\x7f", "n" * 256])
def test_network_mode_rejected(network_mode):
    with pytest.raises(ValidationError):
        create_payload(network_mode=network_mode)


@pytest.mark.parametrize("restart_policy", ["", "no", "always", "unless-stopped", "on-failure"])
def test_restart_policy_accepted(restart_policy):
    assert create_payload(restart_policy=restart_policy).restart_policy == restart_policy


@pytest.mark.parametrize("restart_policy", ["on-failure:3", None])
def test_restart_policy_rejected(restart_policy):
    with pytest.raises(ValidationError):
        create_payload(restart_policy=restart_policy)


@pytest.mark.parametrize(
    ("path", "normalized"),
    [
        ("/mnt//models/", "/mnt/models"),
        ("//mnt/./models", "/mnt/models"),
        ("/", "/"),
        ("/mnt/AI models/", "/mnt/AI models"),
    ],
)
def test_mount_paths_are_normalized(path, normalized):
    mount = agent.CreateExAppMounts(source=path, target=path)
    assert (mount.source, mount.target, mount.mode) == (normalized, normalized, "rw")


@pytest.mark.parametrize(
    ("field", "path"),
    [
        ("source", ""),
        ("source", "./models"),
        ("source", "/mnt/../etc"),
        ("source", "/mnt/a:b"),
        ("source", "/mnt/a\nb"),
        ("source", "/mnt/a\x7fb"),
        ("target", "models"),
    ],
)
def test_mount_path_rejected(field, path):
    with pytest.raises(ValidationError):
        agent.CreateExAppMounts(**{"source": "/mnt/a", "target": "/mnt/a", field: path})


@pytest.mark.parametrize("mode", ["ro", "rw", "RO", "z", ""])
def test_mount_mode_is_kept_as_stored(mode):
    # `occ app_api:app:register --mount SRC:DST:MODE` stores any text; check_mount_modes decides about it.
    assert agent.CreateExAppMounts(source="/mnt/a", target="/mnt/a", mode=mode).mode == mode


@pytest.mark.parametrize("limits", [{}, {"memory": 0, "nanoCPUs": 1500000000}, {"memory": None}, {"cpu": "500m"}])
def test_docker_resource_limits_accepted(limits):
    assert agent.check_docker_resource_limits(limits) is None


@pytest.mark.parametrize("limits", [{"memory": 1.5}, {"memory": -1}, {"memory": True}, {"nanoCPUs": "2"}])
def test_docker_resource_limits_rejected(limits):
    assert "must be a non-negative integer" in agent.check_docker_resource_limits(limits)
