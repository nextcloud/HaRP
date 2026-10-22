# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared key comparison, the `docker-engine-port` header and what the endpoints answer to a refused request."""

import asyncio
import gc
import ipaddress
import logging
import re

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


def agent_request(method: str, path: str, payload: dict | None, headers: dict) -> tuple[int, str]:
    """Send a request to the agent's HTTP port with exactly these headers."""

    async def run() -> tuple[int, str]:
        async with TestClient(TestServer(agent.create_web_app())) as client:
            response = await client.request(method, path, json=payload, headers=headers)
            return response.status, await response.text()

    return asyncio.run(run())


def post(path: str, payload: dict, headers: dict) -> tuple[int, str]:
    """POST to the agent's HTTP port as HAProxy forwards a request from AppAPI: with the shared key."""
    return agent_request("POST", path, payload, {**AUTH, **headers})


@pytest.fixture
def no_docker_engine(monkeypatch):
    """Fail the test when a handler tries to reach the Docker Engine."""

    def unexpected_session(*_args, **_kwargs):
        raise AssertionError("the request must be refused before the Docker Engine is contacted")

    monkeypatch.setattr(agent.aiohttp, "ClientSession", unexpected_session)


def test_shared_key_matches_only_the_configured_key():
    assert agent.is_shared_key(KEY) is True
    for value in (KEY + "x", KEY[:-1], KEY.upper(), "", None, KEY.encode(), "\udc80"):
        assert agent.is_shared_key(value) is False


@pytest.mark.parametrize("unset", [None, ""])
def test_an_unset_shared_key_never_matches(monkeypatch, unset):
    monkeypatch.setattr(agent, "SHARED_KEY", unset)
    for value in (None, "", KEY):
        assert agent.is_shared_key(value) is False


@pytest.mark.parametrize(("value", "port"), [("24000", 24000), ("24099", 24099), (" 24042 ", 24042)])
def test_docker_engine_port_accepted(value, port):
    assert agent.parse_docker_engine_port(value) == port
    request = make_mocked_request("POST", "/docker/exapp/exists", headers={"docker-engine-port": value})
    assert agent.get_docker_engine_port(request) == port


@pytest.mark.parametrize("value", ["23999", "24100", "abc", "24000.0"])
def test_docker_engine_port_rejected(value):
    assert agent.parse_docker_engine_port(value) is None
    request = make_mocked_request("POST", "/docker/exapp/exists", headers={"docker-engine-port": value})
    with pytest.raises(web.HTTPBadRequest) as error:
        agent.get_docker_engine_port(request)
    assert "allowed: 24000-24099" in error.value.text


def test_a_rejected_port_value_is_shortened_and_escaped(caplog):
    value = "1\x1b[31m" + "9" * 100
    with caplog.at_level(logging.ERROR, logger=agent.LOGGER.name):
        assert agent.parse_docker_engine_port(value) is None
    request = make_mocked_request("POST", "/docker/exapp/exists", headers={"docker-engine-port": value})
    with pytest.raises(web.HTTPBadRequest) as error:
        agent.get_docker_engine_port(request)
    for text in (caplog.text, error.value.text):
        assert repr(value[:32]) in text
        assert "\x1b" not in text  # only its escaped form
        assert "9" * 33 not in text


def test_docker_api_requests_go_to_the_engine_tunnel():
    assert app_api_request("/v1.44/_ping", {**AUTH, "docker-engine-port": "24001"}) == {
        "target_port": 24001,
        "backend": "docker_engine_backend",
    }


@pytest.mark.parametrize("port", ["23000", "abc"])
def test_docker_api_requests_to_other_ports_are_refused(port):
    assert app_api_request("/v1.44/_ping", {**AUTH, "docker-engine-port": port}) == {"forbidden": 1}


def test_agent_endpoints_are_not_routed_by_the_port_header():
    for headers in (AUTH, {**AUTH, "docker-engine-port": "24000"}, {**AUTH, "docker-engine-port": "8200"}):
        assert app_api_request("/docker/exapp/create", headers) == {"backend": "nextcloud_control_backend"}
    assert app_api_request("/info", AUTH) == {"backend": "nextcloud_control_backend"}


@pytest.mark.parametrize("headers", [{}, {"harp-shared-key": "wrong"}, {"harp-shared-key": agent.EXAPP_FRP_TOKEN}])
def test_requests_without_the_shared_key_are_unauthorized(headers):
    assert app_api_request("/info", headers) == {"unauthorized": 1}


def routes_that_need_the_key() -> list[tuple[str, str]]:
    """Every route of the agent's HTTP port, apart from the health check and the FRP login hook."""
    routes = {
        (route.method, route.resource.canonical.replace("{app_id}", "app"))
        for route in agent.create_web_app().router.routes()
        if route.method != "HEAD"
    }
    return sorted(routes - {("GET", "/heartbeat"), ("POST", "/frp_handler")})


@pytest.mark.parametrize("headers", [{}, {"harp-shared-key": "wrong"}, {"harp-shared-key": agent.EXAPP_FRP_TOKEN}])
@pytest.mark.parametrize(("method", "path"), routes_that_need_the_key())
def test_the_agent_port_refuses_requests_without_the_shared_key(no_docker_engine, headers, method, path):
    # A process that reaches the port directly, bypassing HAProxy, such as an ExApp next to a host-network HaRP.
    assert agent_request(method, path, None, {**headers, "docker-engine-port": "24000"})[0] == 401
    assert agent.BLACKLIST_CACHE == {}  # its address is also the one of HaRP's own callers


def test_the_agent_port_answers_the_health_check_without_the_shared_key():
    assert agent_request("GET", "/heartbeat", None, {})[0] == 200


@pytest.mark.parametrize(
    ("mount", "reason"),
    [
        ({"source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}, "HP_EXAPP_BIND_MOUNTS_DENIED"),
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


def test_incoming_request_log_has_no_secrets(caplog):
    headers = "\n".join(
        [
            f"harp-shared-key: {KEY}",
            "Authorization: Basic YWRtaW46YWRtaW4=",
            "authorization-app-api: dXNlcjpzZWNyZXQ=",
            "cookie: oc_sessionPassphrase=passphrase-value",
            "ex-app-id: app",
        ]
    )
    with caplog.at_level(logging.DEBUG, logger=agent.LOGGER.name):
        asyncio.run(agent._exapps_msg("/exapps/app_api/info", headers, ipaddress.ip_address("192.0.2.1"), ""))
    assert "Incoming request to ExApp: path=/exapps/app_api/info, ip=192.0.2.1, headers=" in caplog.text
    assert "'ex-app-id': 'app'" in caplog.text
    assert caplog.text.count("[REDACTED]") == 4
    for secret in (KEY, "YWRtaW46YWRtaW4=", "dXNlcjpzZWNyZXQ=", "passphrase-value"):
        assert secret not in caplog.text


def test_session_log_lines_have_no_cookie_value(caplog):
    user = agent.NcUser(user_id="admin", access_level=agent.AccessLevel.ADMIN)
    with caplog.at_level(logging.INFO, logger=agent.LOGGER.name):
        asyncio.run(agent.record_session("passphrase-value", user))
        assert asyncio.run(agent.get_session("passphrase-value")) == user
        agent.SESSION_CACHE["passphrase-value"] = (user, 0.0)  # recorded long ago
        assert asyncio.run(agent.get_session("passphrase-value")) is None
    session_id = agent.session_log_id("passphrase-value")
    assert re.fullmatch(r"[0-9a-f]{12}", session_id)
    assert f"Recorded session {session_id} for user admin" in caplog.text
    assert f"Session {session_id} expired" in caplog.text
    assert "passphrase-value" not in caplog.text


def frp_login(content: dict) -> tuple[int, str]:
    # The FRP server calls the login hook like this: without the shared key, and with the operation in the query.
    return agent_request(
        "POST", "/frp_handler?version=0.1.0&op=Login", {"version": "0.1.0", "op": "Login", "content": content}, {}
    )


def test_the_exapp_frp_token_never_changes():
    # ExApp containers keep the token they were deployed with, so a new derivation would lock them all out.
    assert agent.EXAPP_FRP_TOKEN == "07ab64c523d2a112a38f7b2b0a5575b36f1a35d9d4c63c255ae5de8936b77eb2"


def test_exapp_containers_get_the_frp_token_instead_of_the_shared_key():
    assert agent.with_exapp_frp_token(["APP_ID=app", f"HP_SHARED_KEY={KEY}"]) == [
        "APP_ID=app",
        f"HP_SHARED_KEY={agent.EXAPP_FRP_TOKEN}",
    ]


@pytest.mark.parametrize("token", [KEY, agent.EXAPP_FRP_TOKEN])
def test_frp_login_with_the_shared_key_or_the_exapp_token_is_accepted(token):
    status, text = frp_login({"client_address": "198.51.100.7:40000", "metas": {"token": token}})
    assert (status, text) == (200, '{"reject": false, "unchange": true}')
    assert agent.BLACKLIST_CACHE.get("198.51.100.7", []) == []  # no failure recorded


@pytest.mark.parametrize(
    "content",
    [
        {"client_address": "198.51.100.7:40000", "metas": {"token": "wrong"}},
        {"client_address": "198.51.100.7:40000", "metas": {"token": 12345}},
        {"client_address": "198.51.100.7:40000", "metas": None},  # frpc without `metadatas`
    ],
)
def test_frp_login_without_the_shared_key_is_refused_and_counted(content):
    status, _ = frp_login(content)
    assert status == 400
    assert len(agent.BLACKLIST_CACHE["198.51.100.7"]) == 1


def test_validation_errors_name_the_field_and_leave_out_the_value(no_docker_engine):
    payload = {**DOCKER_CREATE_PAYLOAD, "environment_variables": {"APP_SECRET": "secret-value"}, "name": "a/b"}
    status, text = post("/docker/exapp/create", payload, {"docker-engine-port": "24000"})
    assert status == 400
    assert text.startswith("Payload validation error: name: ")
    assert "; environment_variables: " in text
    assert "secret-value" not in text
    assert "errors.pydantic.dev" not in text
    assert "\n" not in text


def test_engine_ports_are_parsed_from_a_comma_separated_list():
    assert agent._parse_port_ranges("TEST", "24000-24099") == [(24000, 24099)]
    assert agent._parse_port_ranges("TEST", " '24000-24099', 2375 ,,") == [(24000, 24099), (2375, 2375)]
    assert agent._parse_port_ranges("TEST", "1,1-65535") == [(1, 1), (1, 65535)]


@pytest.mark.parametrize("value", ["abc", "24099-24000", "0", "65536", "24000-"])
def test_a_malformed_engine_port_list_stops_the_agent(value):
    with pytest.raises(SystemExit, match="TEST"):
        agent._parse_port_ranges("TEST", value)


def test_extra_engine_ports_are_accepted_when_configured(monkeypatch):
    monkeypatch.setattr(agent, "DOCKER_ENGINE_PORTS", [(24000, 24099), (2375, 2375)])
    monkeypatch.setattr(agent, "DOCKER_ENGINE_PORTS_TEXT", "24000-24099, 2375")
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
        ("198.51.100.7", "198.51.100.7"),
        ("2001:db8::1", "2001:db8::1"),
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
    assert text.startswith("Payload validation error: role_suffix: ")


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
    [({"image_ref": ""}, "24000"), ({"image_ref": "alpine:latest"}, "8200")],
)
def test_image_remove_refuses_invalid_requests_before_contacting_the_engine(no_docker_engine, payload, port):
    assert post("/docker/exapp/image_remove", payload, {"docker-engine-port": port})[0] == 400


def test_create_permits_a_staged_mount_and_sends_the_normalized_mounts_to_the_engine(monkeypatch, caplog):
    sent = []

    class Response:
        def __init__(self, status, body=None):
            self.status, self.body = status, body or {}

        async def json(self):
            return self.body

        async def text(self):
            return ""

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

    class Session:
        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        def get(self, url):
            return Response(200)  # the volume exists

        def post(self, url, json):
            sent.append((url, json))
            return Response(201, {"Id": "abc"})

    monkeypatch.setattr(agent.aiohttp, "ClientSession", Session)
    mounts = [
        {"source": "/dev/shm/", "target": "/dev/shm"},
        {"source": "/etc//localtime", "target": "/etc/localtime", "mode": "ro"},
        {"source": "/srv/data", "target": "/data", "mode": "z"},  # an SELinux option typed into occ
        {"source": "/srv/models", "target": "/models", "mode": "RO"},  # read-write, as it always was
        {"source": "/srv/cache", "target": "/cache", "mode": " ro"},
        {"source": "/srv/logs", "target": "/logs", "mode": "ro,z"},
    ]
    with caplog.at_level(logging.WARNING, logger=agent.LOGGER.name):
        status, _ = post(
            "/docker/exapp/create", {**DOCKER_CREATE_PAYLOAD, "mount_points": mounts}, {"docker-engine-port": "24000"}
        )
    assert status == 201
    assert "Bind mount of '/dev/shm' (rw) for 'nc_app_app-skeleton-python' is permitted for now" in caplog.text
    assert "Bind mount of '/srv/data' for 'nc_app_app-skeleton-python' has mode 'z', which mounts it read-write" in (
        caplog.text
    )
    assert sent[-1][1]["Env"][-1] == f"HP_SHARED_KEY={agent.EXAPP_FRP_TOKEN}"
    binds = [m for m in sent[-1][1]["HostConfig"]["Mounts"] if m["Type"] == "bind"]
    assert [(m["Source"], m["Readonly"]) for m in binds] == [
        ("/dev/shm", False),
        ("/etc/localtime", True),
        ("/srv/data", False),
        ("/srv/models", False),
        ("/srv/cache", False),
        ("/srv/logs", False),
    ]


def appapi_request_headers(key: str) -> str:
    return "\n".join(
        [
            "ex-app-version: 1.0.0",
            "ex-app-id: app",
            "ex-app-host: 127.0.0.1",
            "ex-app-port: 23000",
            "authorization-app-api: eA==",
            f"harp-shared-key: {key}",
        ]
    )


def test_an_appapi_request_with_the_shared_key_is_routed_to_the_exapp(monkeypatch):
    async def no_record(_app_id):
        return None

    monkeypatch.setattr(agent, "_get_or_fetch_exapp", no_record)
    reply = asyncio.run(
        agent._exapps_msg("/exapps/app/heartbeat", appapi_request_headers(KEY), ipaddress.ip_address("192.0.2.1"), "")
    )
    assert txn_vars(reply) == {
        "true_client_ip": "192.0.2.1",
        "target_path": "/heartbeat",
        "backend": "ex_apps_backend",
        "target_ip": "127.0.0.1",
        "target_port": 23000,
        "exapp_token": "eA==",
        "exapp_version": "1.0.0",
        "exapp_id": "app",
    }
    assert agent.BLACKLIST_CACHE.get("192.0.2.1", []) == []


def appapi_requests(count: int = 1) -> list[AckPayload]:
    async def send():
        return await asyncio.gather(
            *(
                agent._exapps_msg(
                    "/exapps/app/heartbeat", appapi_request_headers(KEY), ipaddress.ip_address("192.0.2.1"), ""
                )
                for _ in range(count)
            )
        )

    return asyncio.run(send())


def unreachable_nextcloud():
    raise OSError("Name or service not known")


def invalid_nextcloud_answer():
    return agent.ExApp.model_validate({"exapp_token": "", "exapp_version": "1", "host": "h", "port": "secret-value"})


def kubernetes_api_error():
    raise web.HTTPServiceUnavailable(text="K8s API error during Service lookup for 'app'")


def total_timeout():
    raise TimeoutError


LOOKUP_FAILED = "Cannot look up ExApp 'app', routing this AppAPI request by its headers: "


@pytest.mark.parametrize(
    ("lookup", "reason"),
    [
        (unreachable_nextcloud, "OSError: Name or service not known"),
        (invalid_nextcloud_answer, "port: Input should be a valid integer, unable to parse string as an integer"),
        (kubernetes_api_error, "HTTPServiceUnavailable: K8s API error during Service lookup for 'app'"),
        (total_timeout, "TimeoutError"),
    ],
)
def test_a_failed_lookup_for_an_appapi_request_is_logged_once_and_the_headers_route_it(
    monkeypatch, caplog, lookup, reason
):
    async def fetch(_app_id):
        return lookup()

    monkeypatch.setattr(agent, "_fetch_exapp_record", fetch)
    with caplog.at_level(logging.WARNING, logger=agent.LOGGER.name):
        [reply] = appapi_requests()
        gc.collect()  # asyncio logs an exception nobody retrieved when its future is collected
    assert txn_vars(reply)["target_ip"] == "127.0.0.1"
    assert caplog.messages == [LOOKUP_FAILED + reason]


@pytest.mark.parametrize("record", [None, agent.ExApp(exapp_token="", exapp_version="1", host="127.0.0.1", port=23000)])
def test_a_lookup_that_succeeds_or_finds_no_exapp_logs_nothing(monkeypatch, caplog, record):
    async def fetch(_app_id):
        return record

    monkeypatch.setattr(agent, "_fetch_exapp_record", fetch)
    with caplog.at_level(logging.WARNING, logger=agent.LOGGER.name):
        [reply] = appapi_requests()
    assert txn_vars(reply)["target_ip"] == "127.0.0.1"
    assert caplog.text == ""


def test_concurrent_appapi_requests_share_one_failed_lookup(monkeypatch, caplog):
    fetches = []

    async def fetch(app_id):
        fetches.append(app_id)
        await asyncio.sleep(0.01)
        raise OSError("Name or service not known")

    monkeypatch.setattr(agent, "_fetch_exapp_record", fetch)
    with caplog.at_level(logging.WARNING, logger=agent.LOGGER.name):
        replies = appapi_requests(20)
        gc.collect()
    assert fetches == ["app"]
    assert {txn_vars(reply)["target_ip"] for reply in replies} == {"127.0.0.1"}
    assert caplog.messages == [LOOKUP_FAILED + "OSError: Name or service not known"] * 20  # one per request


def test_a_cancelled_waiter_leaves_the_shared_lookup_intact(monkeypatch):
    async def fetch(_app_id):
        await asyncio.sleep(0.01)
        return agent.ExApp(exapp_token="", exapp_version="1", host="127.0.0.1", port=23000)

    async def lookups():
        leader = asyncio.ensure_future(agent._get_or_fetch_exapp("app"))
        await asyncio.sleep(0)
        waiter = asyncio.ensure_future(agent._get_or_fetch_exapp("app"))
        await asyncio.sleep(0)
        waiter.cancel()
        return await leader

    monkeypatch.setattr(agent, "_fetch_exapp_record", fetch)
    assert asyncio.run(lookups()).host == "127.0.0.1"
    assert agent.EXAPP_CACHE["app"].host == "127.0.0.1"


@pytest.mark.parametrize(
    ("lookup", "model", "path", "headers", "answer", "message"),
    [
        ("_get_or_fetch_exapp", agent.ExApp, "/exapps/app/x", "", "not_found", "Invalid ExApp metadata from Nextcloud"),
        (
            "nc_get_user",
            agent.NcUser,
            "/exapps/app/x",
            "authorization: Basic eA==",
            "unauthorized",
            "Invalid user info",
        ),
    ],
)
def test_invalid_answers_from_nextcloud_are_logged_without_their_values(
    monkeypatch, caplog, lookup, model, path, headers, answer, message
):
    async def invalid_answer(*_args):
        model.model_validate({"exapp_token": "secret-value", "access_level": "secret-value"})

    async def record(_app_id):
        return agent.ExApp(exapp_token="", exapp_version="1", host="127.0.0.1", port=23000)

    monkeypatch.setattr(agent, "_get_or_fetch_exapp", record)
    monkeypatch.setattr(agent, lookup, invalid_answer)
    with caplog.at_level(logging.ERROR, logger=agent.LOGGER.name):
        reply = asyncio.run(agent._exapps_msg(path, headers, ipaddress.ip_address("192.0.2.1"), ""))
    assert txn_vars(reply)[answer] == 1
    assert message in caplog.text
    assert "secret-value" not in caplog.text


@pytest.mark.parametrize("mode", ["z", "RO", "ro,z", "", " ro", "rw "])
def test_a_mode_other_than_ro_or_rw_mounts_read_write_until_enforced(caplog, mode):
    mounts = [agent.CreateExAppMounts(source="/srv/data", target="/data", mode=mode)]
    with caplog.at_level(logging.WARNING, logger=agent.LOGGER.name):
        assert agent.check_mount_modes(mounts, False, "nc_app_x") is None
    assert f"Bind mount of '/srv/data' for 'nc_app_x' has mode '{mode}', which mounts it read-write" in caplog.text
    assert agent.check_mount_modes(mounts, True) == (
        f"HP_EXAPP_BIND_MOUNTS_ENFORCE_ALL refuses mode '{mode}' of '/srv/data': use 'ro' or 'rw'."
    )


def test_ro_and_rw_modes_need_no_warning(caplog):
    mounts = [agent.CreateExAppMounts(source="/srv/data", target="/data", mode=mode) for mode in ("ro", "rw")]
    with caplog.at_level(logging.WARNING, logger=agent.LOGGER.name):
        assert agent.check_mount_modes(mounts, True) is None
        assert agent.check_mount_modes(mounts, False) is None
    assert caplog.text == ""


def test_create_refuses_an_unknown_mode_once_enforced(no_docker_engine, monkeypatch):
    monkeypatch.setattr(agent, "BIND_MOUNTS_ENFORCE_ALL", True)
    mount = {"source": "/srv/data", "target": "/data", "mode": "RO"}
    status, text = post(
        "/docker/exapp/create", {**DOCKER_CREATE_PAYLOAD, "mount_points": [mount]}, {"docker-engine-port": "24000"}
    )
    assert (status, text) == (
        400,
        "HP_EXAPP_BIND_MOUNTS_ENFORCE_ALL refuses mode 'RO' of '/srv/data': use 'ro' or 'rw'.",
    )


@pytest.mark.parametrize(
    ("host", "url"),
    [("10.96.0.1", "https://10.96.0.1:443"), ("fd00:10:96::1", "https://[fd00:10:96::1]:443")],
)
def test_in_cluster_api_server_url(monkeypatch, host, url):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", host)
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")
    assert agent._in_cluster_api_server() == url


@pytest.mark.parametrize(
    ("value", "aliases"),
    [
        ("nc.example.com:10.0.0.5", [{"ip": "10.0.0.5", "hostnames": ["nc.example.com"]}]),
        ("nc.example.com:fd00::5", [{"ip": "fd00::5", "hostnames": ["nc.example.com"]}]),
        (
            "nc.example.com:[fd00::5], office.example.com:fd00::5,nc.example.com:10.0.0.5",
            [
                {"ip": "fd00::5", "hostnames": ["nc.example.com", "office.example.com"]},
                {"ip": "10.0.0.5", "hostnames": ["nc.example.com"]},
            ],
        ),
    ],
)
def test_k8s_host_aliases(monkeypatch, value, aliases):
    monkeypatch.setattr(agent, "K8S_HOST_ALIASES_RAW", value)
    assert agent._k8s_parse_host_aliases() == aliases


def test_k8s_service_lookup_works_for_any_app_id(monkeypatch):
    calls = []

    async def k8s_request(method, path, **kwargs):
        calls.append(path)
        # No Service of that name, and none labelled for the ExApp.
        return (200, {"items": []}, "") if "query" in kwargs else (404, None, "")

    async def no_manual_upstream(*_args):
        return None

    monkeypatch.setattr(agent, "K8S_ENABLED", True)
    monkeypatch.setattr(agent, "K8S_API_SERVER", "https://k8s.example")
    monkeypatch.setattr(agent, "_get_k8s_token", lambda: "token")
    monkeypatch.setattr(agent, "_k8s_request", k8s_request)
    monkeypatch.setattr(agent, "_k8s_resolve_manual_upstream", no_manual_upstream)
    # An id outside the name rules for new containers still gets its Service looked up.
    assert asyncio.run(agent._k8s_resolve_exapp_upstream("_hidden")) is None
    assert calls[0].endswith("/services/nc-app-hidden")
