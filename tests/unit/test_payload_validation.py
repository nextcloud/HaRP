# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validation of the payloads AppAPI sends to the `/docker/exapp/*` and `/k8s/exapp/*` endpoints."""

import pytest
from pydantic import ValidationError

import haproxy_agent as agent

from .payloads import DOCKER_CREATE_PAYLOAD, K8S_CREATE_PAYLOAD


def create_payload(**changes):
    return agent.CreateExAppPayload.model_validate({**DOCKER_CREATE_PAYLOAD, **changes})


def test_docker_create_payload_is_accepted():
    payload = create_payload()
    assert payload.exapp_container_name == "nc_app_app-skeleton-python"
    assert payload.exapp_container_volume == "nc_app_app-skeleton-python_data"


def test_docker_create_payload_without_optional_fields_is_accepted():
    # AppAPI 32 sends no resource limits.
    payload = {k: v for k, v in DOCKER_CREATE_PAYLOAD.items() if k not in ("resource_limits", "mount_points")}
    assert agent.CreateExAppPayload.model_validate(payload).mount_points == []


def test_k8s_create_payload_is_accepted():
    payload = agent.CreateExAppPayload.model_validate(K8S_CREATE_PAYLOAD)
    assert payload.image_id == K8S_CREATE_PAYLOAD["image"]
    assert payload.network_mode == "bridge"
    assert payload.exapp_k8s_name == "nc-app-app-skeleton-python-rp"


@pytest.mark.parametrize(
    "name", ["app-skeleton-python", "test-deploy", "context_chat_backend", "llm2", "nc_py_api", "a.b", "A1", "x" * 63]
)
def test_name_accepted(name):
    assert agent.ExAppName(name=name).name == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "../etc",
        "a/b",
        "a b",
        "a?force=true",
        "a%2Fb",
        "a#b",
        "a:b",
        "-a",
        ".a",
        "_a",
        "a\n",
        "a\x00",
        "ä",
        "x" * 64,
    ],
)
def test_name_rejected(name):
    with pytest.raises(ValidationError):
        agent.ExAppName(name=name)


@pytest.mark.parametrize("field", ["instance_id", "role_suffix"])
@pytest.mark.parametrize("value", ["", "oc1a2b3c4d5e", "rp", "idx_1"])
def test_name_parts_accepted(field, value):
    assert getattr(agent.ExAppName(name="app", **{field: value}), field) == value


@pytest.mark.parametrize("field", ["instance_id", "role_suffix"])
@pytest.mark.parametrize("value", ["a/b", "a b", "../x", "a?b", "a\n", "x" * 64])
def test_name_parts_rejected(field, value):
    with pytest.raises(ValidationError):
        agent.ExAppName(name="app", **{field: value})


@pytest.mark.parametrize("model", [agent.RemoveExAppPayload, agent.InstallCertificatesPayload])
def test_name_is_checked_for_every_payload_type(model):
    with pytest.raises(ValidationError):
        model.model_validate({"name": "a/../b"})


@pytest.mark.parametrize("network_mode", ["host", "bridge", "nextcloud", "nextcloud-aio", "master_bridge", "my.net"])
def test_network_mode_accepted(network_mode):
    assert create_payload(network_mode=network_mode).network_mode == network_mode


@pytest.mark.parametrize(
    "network_mode",
    ["", "container:nc_app_other", "ns:/proc/1/ns/net", "my net", "a\tb", "a\nb", "net\x01", "\x1bnet", "n" * 256],
)
def test_network_mode_rejected(network_mode):
    with pytest.raises(ValidationError):
        create_payload(network_mode=network_mode)


@pytest.mark.parametrize("restart_policy", ["", "no", "always", "unless-stopped", "on-failure"])
def test_restart_policy_accepted(restart_policy):
    assert create_payload(restart_policy=restart_policy).restart_policy == restart_policy


@pytest.mark.parametrize("restart_policy", ["sometimes", "on-failure:3", "Always", None])
def test_restart_policy_rejected(restart_policy):
    with pytest.raises(ValidationError):
        create_payload(restart_policy=restart_policy)


@pytest.mark.parametrize(
    ("path", "normalized"),
    [
        ("/mnt/models", "/mnt/models"),
        ("/mnt//models/", "/mnt/models"),
        ("//mnt/models", "/mnt/models"),
        ("/mnt/./models", "/mnt/models"),
        ("/", "/"),
    ],
)
def test_mount_paths_are_normalized(path, normalized):
    mount = agent.CreateExAppMounts(source=path, target=path)
    assert (mount.source, mount.target, mount.mode) == (normalized, normalized, "rw")


@pytest.mark.parametrize(
    "path", ["", "models", "./models", "/mnt/../etc", "/mnt/..", "/mnt/a:b", "/mnt/a\x00b", "/a\nb"]
)
@pytest.mark.parametrize("field", ["source", "target"])
def test_mount_path_rejected(field, path):
    with pytest.raises(ValidationError):
        agent.CreateExAppMounts(**{"source": "/mnt/a", "target": "/mnt/a", field: path})


@pytest.mark.parametrize("mode", ["RO", "rw,z", "", "readonly", None])
def test_mount_mode_rejected(mode):
    # Anything but "ro" used to be treated as read-write.
    with pytest.raises(ValidationError):
        agent.CreateExAppMounts(source="/mnt/a", target="/mnt/a", mode=mode)


def test_mounts_of_a_create_payload_are_validated():
    with pytest.raises(ValidationError):
        create_payload(mount_points=[{"source": "/mnt/a", "target": "/mnt/a", "mode": "ro "}])
    payload = create_payload(mount_points=[{"source": "/mnt/a/", "target": "/data", "mode": "ro"}])
    assert payload.mount_points[0].source == "/mnt/a"


@pytest.mark.parametrize(
    "limits", [{}, {"memory": 0}, {"memory": 536870912, "nanoCPUs": 1500000000}, {"memory": None}, {"cpu": "500m"}]
)
def test_docker_resource_limits_accepted(limits):
    assert agent.check_docker_resource_limits(limits) is None


@pytest.mark.parametrize(
    "limits", [{"memory": "512Mi"}, {"memory": 1.5}, {"memory": -1}, {"memory": True}, {"nanoCPUs": "2"}]
)
def test_docker_resource_limits_rejected(limits):
    assert "must be a non-negative integer" in agent.check_docker_resource_limits(limits)


def test_the_restart_policy_defaults_to_unless_stopped():
    payload = {k: v for k, v in DOCKER_CREATE_PAYLOAD.items() if k != "restart_policy"}
    assert agent.CreateExAppPayload.model_validate(payload).restart_policy == "unless-stopped"


def test_mount_paths_may_contain_blanks():
    mount = agent.CreateExAppMounts(source="/mnt/AI models/", target="/models dir", mode="ro")
    assert (mount.source, mount.target) == ("/mnt/AI models", "/models dir")
