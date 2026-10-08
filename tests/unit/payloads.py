# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Payloads shaped like the ones AppAPI sends, shared by the tests."""

# What AppAPI sends to `/docker/exapp/create` (DockerActions::deployExAppHarp).
DOCKER_CREATE_PAYLOAD = {
    "name": "app-skeleton-python",
    "instance_id": "",
    "image_id": "ghcr.io/nextcloud/app-skeleton-python:latest",
    "network_mode": "host",
    "environment_variables": ["APP_ID=app-skeleton-python", "APP_PORT=23000", "HP_FRP_PORT=8782"],
    "restart_policy": "unless-stopped",
    "compute_device": "cpu",
    "mount_points": [],
    "start_container": True,
    "resource_limits": {"memory": 536870912, "nanoCPUs": 1500000000},
}
# What AppAPI sends to `/k8s/exapp/create` (KubernetesActions); the resource limits may also be given in
# Kubernetes units, which `_k8s_build_resources` accepts.
K8S_CREATE_PAYLOAD = {
    "name": "app-skeleton-python",
    "instance_id": "",
    "role_suffix": "rp",
    "image": "ghcr.io/nextcloud/app-skeleton-python:latest",
    "image_pull_policy": "Never",
    "environment_variables": ["APP_ID=app-skeleton-python"],
    "compute_device": "cpu",
    "resource_limits": {"memory": "512Mi", "cpu": "500m"},
}
