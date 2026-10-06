# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared key comparison, the `docker-engine-port` header and what the endpoints answer to a refused request."""

import asyncio
import ipaddress
import logging

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request
from haproxyspoa.payloads.ack import AckPayload

import haproxy_agent as agent

from .payloads import DOCKER_CREATE_PAYLOAD, K8S_CREATE_PAYLOAD

KEY = "unit-test-shared-key"
AUTH = {"harp-shared-key": KEY}


def txn_vars(reply: AckPayload) -> dict:
    return {action.name: action.value for action in reply.actions}


def app_api_request(path: str, headers: dict) -> dict:
    return txn_vars(asyncio.run(agent.handle_app_api_request(path, headers, "192.0.2.1", AckPayload())))


def post(path: str, payload: dict, headers: dict) -> tuple[int, str]:
    async def run() -> tuple[int, str]:
        async with TestClient(TestServer(agent.create_web_app())) as client:
            response = await client.post(path, json=payload, headers=headers)
            return response.status, await response.text()

    return asyncio.run(run())


@pytest.fixture
def no_docker_engine(monkeypatch):
    """Fail the test when a handler tries to reach the Docker Engine."""

    def unexpected_session(*_args, **_kwargs):
        raise AssertionError("the request must be refused before the Docker Engine is contacted")

    monkeypatch.setattr(agent.aiohttp, "ClientSession", unexpected_session)


def test_shared_key_matches_only_the_configured_key():
    assert agent.is_shared_key(KEY) is True
    for value in (KEY + "x", KEY[:-1], KEY.upper(), "", None, 0, KEY.encode(), [KEY], "ключ", "\udc80"):
        assert agent.is_shared_key(value) is False


@pytest.mark.parametrize("unset", [None, ""])
def test_an_unset_shared_key_never_matches(monkeypatch, unset):
    monkeypatch.setattr(agent, "SHARED_KEY", unset)
    for value in (None, "", KEY):
        assert agent.is_shared_key(value) is False


@pytest.mark.parametrize(("value", "port"), [("24000", 24000), ("24001", 24001), ("24099", 24099), (" 24042 ", 24042)])
def test_docker_engine_port_accepted(value, port):
    assert agent.parse_docker_engine_port(value) == port
    request = make_mocked_request("POST", "/docker/exapp/exists", headers={"docker-engine-port": value})
    assert agent.get_docker_engine_port(request) == port


@pytest.mark.parametrize("value", ["23999", "24100", "23000", "8200", "2375", "0", "-24000", "65536", "abc", "24000.0"])
def test_docker_engine_port_rejected(value):
    assert agent.parse_docker_engine_port(value) is None
    request = make_mocked_request("POST", "/docker/exapp/exists", headers={"docker-engine-port": value})
    with pytest.raises(web.HTTPBadRequest) as error:
        agent.get_docker_engine_port(request)
    assert "allowed: 24000-24099" in error.value.text


def test_docker_engine_port_header_is_required():
    with pytest.raises(web.HTTPBadRequest) as error:
        agent.get_docker_engine_port(make_mocked_request("POST", "/docker/exapp/exists"))
    assert "Missing" in error.value.text


def test_docker_api_requests_go_to_the_engine_tunnel():
    assert app_api_request("/v1.44/_ping", {**AUTH, "docker-engine-port": "24001"}) == {
        "target_port": 24001,
        "backend": "docker_engine_backend",
    }


@pytest.mark.parametrize("port", ["8200", "23000", "65536", "abc"])
def test_docker_api_requests_to_other_ports_are_refused(port):
    assert app_api_request("/v1.44/_ping", {**AUTH, "docker-engine-port": port}) == {"forbidden": 1}


def test_agent_endpoints_are_not_routed_by_the_port_header():
    for headers in (AUTH, {**AUTH, "docker-engine-port": "24000"}, {**AUTH, "docker-engine-port": "8200"}):
        assert app_api_request("/docker/exapp/create", headers) == {"backend": "nextcloud_control_backend"}
    assert app_api_request("/info", AUTH) == {"backend": "nextcloud_control_backend"}


@pytest.mark.parametrize("headers", [{}, {"harp-shared-key": "wrong"}, {"harp-shared-key": ""}])
def test_requests_without_the_shared_key_are_unauthorized(headers):
    assert app_api_request("/info", headers) == {"unauthorized": 1}


@pytest.mark.parametrize(
    ("mount", "reason"),
    [
        ({"source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}, "HP_EXAPP_BIND_MOUNTS_DENIED"),
        ({"source": "/", "target": "/host", "mode": "ro"}, "HP_EXAPP_BIND_MOUNTS_DENIED"),
        ({"source": "/etc/shadow", "target": "/etc/shadow", "mode": "ro"}, "rule '/etc/shadow'"),
        (
            {"source": "/mnt/models", "target": "/models", "mode": "RO"},
            "mount_points.0.mode: Input should be 'ro' or 'rw'",
        ),
        ({"source": "models", "target": "/models"}, "mount_points.0.source: must be an absolute path"),
    ],
)
def test_create_refuses_a_mount_before_contacting_the_engine(no_docker_engine, mount, reason):
    status, text = post(
        "/docker/exapp/create", {**DOCKER_CREATE_PAYLOAD, "mount_points": [mount]}, {"docker-engine-port": "24000"}
    )
    assert status == 400
    assert reason in text


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "app/../other"},
        {"network_mode": "container:nc_app_other"},
        {"restart_policy": "sometimes"},
        {"resource_limits": {"memory": "512m"}},
    ],
)
def test_create_refuses_invalid_values_before_contacting_the_engine(no_docker_engine, changes):
    status, _ = post("/docker/exapp/create", {**DOCKER_CREATE_PAYLOAD, **changes}, {"docker-engine-port": "24000"})
    assert status == 400


@pytest.mark.parametrize("endpoint", ["exists", "start", "stop", "wait_for_start", "remove", "install_certificates"])
def test_endpoints_refuse_an_invalid_name_and_port(no_docker_engine, endpoint):
    path = f"/docker/exapp/{endpoint}"
    assert post(path, {"name": "app/../other"}, {"docker-engine-port": "24000"})[0] == 400
    assert post(path, {"name": "app"}, {"docker-engine-port": "8200"})[0] == 400


def test_exapp_record_repr_hides_the_token():
    record = agent.ExApp(exapp_token="app-secret-value", exapp_version="1.0.0", host="app", port=23000)
    assert "app-secret-value" not in repr(record)
    assert "app-secret-value" not in str(record)
    assert record.exapp_token == "app-secret-value"


def test_headers_are_redacted_for_the_log():
    headers = {
        "harp-shared-key": KEY,
        "Authorization": "Basic YWRtaW46YWRtaW4=",
        "authorization-app-api": "dXNlcjpzZWNyZXQ=",
        "cookie": "oc_sessionPassphrase=passphrase-value",
        "ex-app-id": "app",
    }
    redacted = agent.redact_headers(headers)
    assert redacted == {
        "harp-shared-key": "[REDACTED]",
        "Authorization": "[REDACTED]",
        "authorization-app-api": "[REDACTED]",
        "cookie": "[REDACTED]",
        "ex-app-id": "app",
    }
    assert headers["cookie"] == "oc_sessionPassphrase=passphrase-value"  # the original is untouched


def test_incoming_request_log_has_no_secrets(caplog):
    headers = {"harp-shared-key": KEY, "cookie": "oc_sessionPassphrase=passphrase-value", "ex-app-id": "app"}
    with caplog.at_level(logging.DEBUG, logger=agent.LOGGER.name):
        agent.log_incoming_request("/exapps/app/x", headers, "192.0.2.1")
    assert "ex-app-id" in caplog.text
    assert KEY not in caplog.text
    assert "passphrase-value" not in caplog.text


def test_session_log_lines_have_no_cookie_value(caplog, monkeypatch):
    monkeypatch.setattr(agent, "SESSION_CACHE", {})
    user = agent.NcUser(user_id="admin", access_level=agent.AccessLevel.ADMIN)
    with caplog.at_level(logging.INFO, logger=agent.LOGGER.name):
        asyncio.run(agent.record_session("passphrase-value", user))
        assert asyncio.run(agent.get_session("passphrase-value")) == user
        agent.SESSION_CACHE["passphrase-value"] = (user, 0.0)  # recorded long ago
        assert asyncio.run(agent.get_session("passphrase-value")) is None
    assert "Recorded session" in caplog.text
    assert "expired" in caplog.text
    assert "passphrase-value" not in caplog.text
    assert agent.session_log_id("passphrase-value") in caplog.text


def frp_login(content: dict) -> tuple[int, str]:
    return post("/frp_handler", {"version": "0.1.0", "op": "Login", "content": content}, {})


def test_frp_login_with_the_shared_key_is_accepted(monkeypatch):
    monkeypatch.setattr(agent, "BLACKLIST_CACHE", {})
    status, text = frp_login({"client_address": "198.51.100.7:40000", "metas": {"token": KEY}})
    assert (status, text) == (200, '{"reject": false, "unchange": true}')
    assert agent.BLACKLIST_CACHE.get("198.51.100.7", []) == []  # no failure recorded


@pytest.mark.parametrize(
    "content",
    [
        {"client_address": "198.51.100.7:40000", "metas": {"token": "wrong"}},
        {"client_address": "198.51.100.7:40000", "metas": {"token": 12345}},
        {"client_address": "198.51.100.7:40000", "metas": {}},
        {"client_address": "198.51.100.7:40000", "metas": None},  # frpc without `metadatas`
        {"client_address": "198.51.100.7:40000"},
    ],
)
def test_frp_login_without_the_shared_key_is_refused_and_counted(monkeypatch, content):
    monkeypatch.setattr(agent, "BLACKLIST_CACHE", {})
    status, _ = frp_login(content)
    assert status == 400
    assert len(agent.BLACKLIST_CACHE["198.51.100.7"]) == 1


def test_validation_errors_name_the_field_and_leave_out_the_value(no_docker_engine):
    payload = {**DOCKER_CREATE_PAYLOAD, "environment_variables": {"APP_SECRET": "secret-value"}, "name": "a/b"}
    status, text = post("/docker/exapp/create", payload, {"docker-engine-port": "24000"})
    assert status == 400
    assert text.startswith("Payload validation error: name: String should match pattern")
    assert "environment_variables: Input should be a valid list" in text
    assert "secret-value" not in text
    assert "errors.pydantic.dev" not in text
    assert "\n" not in text


def test_engine_ports_are_parsed_from_a_comma_separated_list():
    assert agent._parse_port_ranges("TEST", "24000-24099") == [(24000, 24099)]
    assert agent._parse_port_ranges("TEST", " '24000-24099', 2375 ,,") == [(24000, 24099), (2375, 2375)]
    assert agent._describe_port_ranges([(24000, 24099), (2375, 2375)]) == "24000-24099, 2375"


@pytest.mark.parametrize("value", ["", "abc", "24099-24000", "0", "65536", "24000-", "-24099", "2375:2376"])
def test_a_malformed_engine_port_list_stops_the_agent(value):
    with pytest.raises(SystemExit, match="TEST"):
        agent._parse_port_ranges("TEST", value)


def test_extra_engine_ports_are_accepted_when_configured(monkeypatch):
    monkeypatch.setattr(agent, "DOCKER_ENGINE_PORTS", [(24000, 24099), (2375, 2375)])
    assert agent.parse_docker_engine_port("2375") == 2375
    assert agent.parse_docker_engine_port("2376") is None
    assert app_api_request("/v1.44/_ping", {**AUTH, "docker-engine-port": "2375"}) == {
        "target_port": 2375,
        "backend": "docker_engine_backend",
    }
    request = make_mocked_request("POST", "/docker/exapp/exists", headers={"docker-engine-port": "2376"})
    with pytest.raises(web.HTTPBadRequest) as error:
        agent.get_docker_engine_port(request)
    assert "allowed: 24000-24099, 2375" in error.value.text


@pytest.mark.parametrize(
    ("address", "host"),
    [
        ("198.51.100.7:40000", "198.51.100.7"),
        ("[2001:db8::1]:40000", "2001:db8::1"),
        ("[::1]:7000", "::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("198.51.100.7", "198.51.100.7"),
    ],
)
def test_frp_client_host(address, host):
    assert agent.frp_client_host(address) == host


def test_failed_frp_logins_from_ipv6_clients_are_counted_per_address():
    for address in ("[2001:db8::1]:40000", "[2001:db8::2]:40000"):
        assert frp_login({"client_address": address, "metas": {"token": "wrong"}})[0] == 400
    # `is_ip_banned` creates an empty entry for every address it sees, so count the recorded failures.
    assert {ip: len(failures) for ip, failures in agent.BLACKLIST_CACHE.items()} == {"2001:db8::1": 1, "2001:db8::2": 1}


def test_a_wrong_key_on_an_appapi_request_counts_against_the_client_behind_the_proxy(monkeypatch):
    monkeypatch.setattr(agent, "TRUSTED_PROXIES", [ipaddress.ip_network("10.0.0.0/8")])
    headers = "\n".join(
        [
            "x-forwarded-for: 198.51.100.20",
            "ex-app-version: 1.0.0",
            "ex-app-id: app",
            "ex-app-host: app",
            "ex-app-port: 23000",
            "authorization-app-api: eA==",
            "harp-shared-key: wrong",
        ]
    )
    reply = asyncio.run(agent._exapps_msg("/exapps/app/heartbeat", headers, ipaddress.ip_address("10.0.0.5"), ""))
    assert txn_vars(reply)["bad_request"] == 1
    assert len(agent.BLACKLIST_CACHE["198.51.100.20"]) == 1
    assert agent.BLACKLIST_CACHE.get("10.0.0.5", []) == []  # not the proxy


def test_k8s_create_refuses_an_invalid_role_before_contacting_the_cluster(no_docker_engine):
    status, text = post("/k8s/exapp/create", {**K8S_CREATE_PAYLOAD, "role_suffix": "web ui"}, {})
    assert status == 400
    assert text.startswith("Payload validation error: role_suffix: String should match pattern")


def test_user_info_requests_keep_the_credentials_but_the_log_does_not(monkeypatch, caplog):
    sent = {}

    class Response:
        ok = True

        async def json(self):
            return {"user_id": "admin", "access_level": 2}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

    class Session:
        def get(self, url, headers, params):
            sent.update(headers)
            return Response()

    monkeypatch.setattr(agent, "_get_nc_session", Session)
    headers = {"authorization": "Basic YWRtaW46YWRtaW4=", "cookie": "oc_sessionPassphrase=passphrase-value"}
    with caplog.at_level(logging.DEBUG, logger=agent.LOGGER.name):
        user = asyncio.run(agent.nc_get_user("app", headers))
    assert user.user_id == "admin"
    assert sent["authorization"] == "Basic YWRtaW46YWRtaW4="  # Nextcloud still gets them
    assert sent["cookie"] == "oc_sessionPassphrase=passphrase-value"
    assert "Requesting user info for ExApp 'app'" in caplog.text
    assert "YWRtaW46YWRtaW4=" not in caplog.text
    assert "passphrase-value" not in caplog.text


def test_create_refuses_a_read_write_system_mount_once_enforced(no_docker_engine, monkeypatch):
    # By default the read-write entries only warn (see test_bind_mounts.py); HP_EXAPP_BIND_MOUNTS_ENFORCE_ALL
    # empties the warn-only set.
    monkeypatch.setattr(agent, "BIND_MOUNTS_WARN_ONLY", frozenset())
    mount = {"source": "/etc/hosts", "target": "/etc/hosts", "mode": "rw"}
    status, text = post(
        "/docker/exapp/create", {**DOCKER_CREATE_PAYLOAD, "mount_points": [mount]}, {"docker-engine-port": "24000"}
    )
    assert (status, text) == (400, "HP_EXAPP_BIND_MOUNTS_DENIED rule '/etc:rw' forbids mounting '/etc/hosts' (rw).")


def test_a_valid_shared_key_is_never_counted_as_a_failure():
    asyncio.run(agent.record_failure_unless_trusted("192.0.2.9", {"harp-shared-key": KEY}))
    assert agent.BLACKLIST_CACHE.get("192.0.2.9", []) == []
    asyncio.run(agent.record_failure_unless_trusted("192.0.2.9", {"harp-shared-key": "wrong"}))
    asyncio.run(agent.record_failure_unless_trusted("192.0.2.9", {}))
    assert len(agent.BLACKLIST_CACHE["192.0.2.9"]) == 2


@pytest.mark.parametrize(
    ("payload", "port"),
    [({"image_ref": ""}, "24000"), ({}, "24000"), ({"image_ref": "alpine:latest"}, "8200")],
)
def test_image_remove_refuses_invalid_requests_before_contacting_the_engine(no_docker_engine, payload, port):
    assert post("/docker/exapp/image_remove", payload, {"docker-engine-port": port})[0] == 400


@pytest.mark.parametrize(("value", "ranges"), [("1", [(1, 1)]), ("65535", [(65535, 65535)]), ("1-65535", [(1, 65535)])])
def test_engine_port_boundaries(value, ranges):
    assert agent._parse_port_ranges("TEST", value) == ranges
