# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Route checks decide on the path as the ExApp reads it, and HaRP forwards a path that every server reads alike."""

import asyncio
import ipaddress

import pytest

import haproxy_agent as agent

from .test_route_verbs import IP, decide, exapp, outcome, request, strikes, txn_vars

ADMIN_AREA = exapp(
    {"url": "^/admin/.*", "verb": "GET", "access_level": 2},
    {"url": "^/api/admin/.*", "verb": "GET", "access_level": 2},
    {"url": "^/settings$", "verb": "GET", "access_level": 2},
    {"url": ".*", "verb": "GET,POST,PUT", "access_level": 1},
)


def forwarded(monkeypatch, path: str, level: int = 2) -> str:
    found = decide(monkeypatch, ADMIN_AREA, "GET", path, level)
    assert outcome(found) == "ALLOW", found
    return found["target_path"]


@pytest.mark.parametrize(
    "path",
    [
        "/api/%61dmin/x",  # FastAPI, aiohttp, Flask and Tomcat decode before they route
        "/api/admin%2Fx",
        "/%61dmin/x",
        "//admin/x",  # Tomcat and nginx merge slashes
        "/api//admin/x",
        "/api/%2Fadmin/x",  # a wrapper ExApp may pass `/api//admin/x` on to a server that merges slashes
        "/Admin/x",  # Express routes ignoring case
        "/API/ADMIN/x",
        "/settings/",  # Express also ignores a trailing slash
        "/Settings/",
        "/admin;x/y",  # Tomcat drops `;` parameters
        "/admin;/x",
        "/;x/admin/x",  # and merges the empty segment that is left
        "/settings%3Fx",  # a wrapper ExApp that re-sends the decoded path cuts it at `?` or `#`
        "/settings%23x",
        "/settings%3Fx%3Fy",
        "/settings/%3Fx",
        "/%2Fsettings%3Fx",
        "/settings%3Bx",  # and Tomcat behind it drops `;` parameters
        "/settings;x%3F/y",
        "/admin%3Bv=1/x",
        "/%3Bx/admin/x",
    ],
)
def test_a_stricter_route_is_not_skipped_by_another_spelling_of_its_path(monkeypatch, path):
    assert outcome(decide(monkeypatch, ADMIN_AREA, "GET", path, 1)) == "403"
    assert outcome(decide(monkeypatch, ADMIN_AREA, "GET", path, 2)) == "ALLOW"


def test_a_stricter_route_is_not_skipped_by_an_escaped_slash(monkeypatch):
    # Express, aiohttp and Go's ServeMux route `a%2Fb` as one segment, so their `/files/:name` serves it.
    record = exapp(
        {"url": "^/files/[^/]+$", "verb": "GET", "access_level": 2}, {"url": ".*", "verb": "GET", "access_level": 1}
    )
    for path in ("/files/a%2Fb", "/files/a%2fb", "/files/a%2Fb/"):
        assert request(monkeypatch, record, "GET", path, 1) == "403"
        assert request(monkeypatch, record, "GET", path, 2) == "ALLOW"


def test_a_stricter_route_is_not_skipped_by_a_decoded_slash_next_to_another(monkeypatch):
    # Starlette reads `/files/%2Fa.txt` as `/files//a.txt` and runs its `/files/{rest:path}` handler.
    record = exapp(
        {"url": "^/files/[^/]+$", "verb": "GET", "access_level": 0},
        {"url": "^/files/.*", "verb": "GET", "access_level": 2},
        {"url": ".*", "verb": "GET", "access_level": 0},
    )
    assert request(monkeypatch, record, "GET", "/files/a.txt") == "ALLOW"
    assert request(monkeypatch, record, "GET", "/files/%2Fa.txt") == "403"


def test_the_forwarded_path_reads_as_the_checked_one(monkeypatch):
    assert forwarded(monkeypatch, "/files/%6d%4A%39%2d%2e%5f%7e") == "/files/mJ9-._~"
    assert forwarded(monkeypatch, "/files/%a.png") == "/files/%25a.png"
    assert forwarded(monkeypatch, "/api/%61dmin/x") == "/api/admin/x"
    assert forwarded(monkeypatch, "//admin/x") == "/admin/x"
    assert forwarded(monkeypatch, "/files/%7Euser") == "/files/~user"
    assert forwarded(monkeypatch, "/files/100%") == "/files/100%25"


def test_other_escapes_are_forwarded_as_sent(monkeypatch):
    for path in ("/files/My%20File.txt", "/files/caf%C3%A9", "/files/caf%c3%a9", "/files/a%2Fb", "/files/%25", "/a;b"):
        assert forwarded(monkeypatch, path, level=1) == path


def test_a_path_too_long_to_forward_is_refused(monkeypatch):
    # Each lone `%` is forwarded as `%25`: the reply to HAProxy would exceed one SPOE frame and stall its connection.
    assert decide(monkeypatch, ADMIN_AREA, "GET", "/x/" + "%" * 6000, 1)["bad_request"] == 1
    assert forwarded(monkeypatch, "/x/" + "%" * 4700, level=1) == "/x/" + "%25" * 4700


def test_a_backslash_is_forwarded_escaped(monkeypatch):
    # WHATWG URL parsers (Hono, Node's `new URL()`) read a raw `\` as `/`; `%5C` is a `\` for every server.
    assert forwarded(monkeypatch, "/\\x/admin/x", level=1) == "/%5Cx/admin/x"
    assert forwarded(monkeypatch, "/api\\admin/x", level=1) == "/api%5Cadmin/x"


def test_a_stricter_route_is_not_skipped_by_dropping_semicolon_parameters_before_decoding(monkeypatch):
    # Tomcat drops `;` parameters before it decodes, so `%3B` stays: `/;/files/%3B/a` runs its `/files/*` servlet.
    record = exapp(
        {"url": "^/files/[^/]+$", "verb": "GET", "access_level": 0},
        {"url": "^/files/.*", "verb": "GET", "access_level": 2},
        {"url": ".*", "verb": "GET", "access_level": 0},
    )
    assert request(monkeypatch, record, "GET", "/;/files/%3B/a") == "403"


def test_a_route_for_a_name_with_spaces_or_accents_matches_the_encoded_request(monkeypatch):
    record = exapp({"url": "^/files/Café menu\\.pdf$", "verb": "GET", "access_level": 0})
    assert request(monkeypatch, record, "GET", "/files/Caf%C3%A9%20menu.pdf") == "ALLOW"


def test_visionatrix_double_slash_api_calls_reach_its_api_route(monkeypatch):
    # Its UI joins the base URL `/exapps/visionatrix/` and `/vapi/...`.
    record = exapp(
        {"url": "^/vapi/.*", "verb": "GET", "access_level": 1}, {"url": ".*", "verb": "GET", "access_level": 2}
    )
    found = decide(monkeypatch, record, "GET", "//vapi/flows/installed", 1)
    assert outcome(found) == "ALLOW"
    assert found["target_path"] == "/vapi/flows/installed"


@pytest.mark.parametrize(
    "path",
    [
        "/p/../admin/x",
        "/p/..;/admin/x",
        "/p/%2e%2e;/admin/x",
        "/p/..%3Bx/admin/x",
        "/./admin/x",
        "/p/.;x/",
        "/%2F.%2Fb",
        "/public/..\\admin/x",  # WHATWG URL parsers read `\` as `/` and then resolve the dots
        "/p\\..\\admin/x",
        "/p/%2E%2E/admin/x",
        "/p%2f..%2fadmin/x",
        "/admin/x/..",
        "/p/..%3F/admin/x",  # a wrapper ExApp that decodes the path cuts it at `?` or `#`
        "/p/.%23x",
    ],
)
def test_dot_segments_are_refused_in_every_form(monkeypatch, path):
    found = decide(monkeypatch, ADMIN_AREA, "GET", path, 2)
    assert found["bad_request"] == 1
    assert strikes() == 1


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/Init/"),  # Express: any case, trailing slash
        ("PUT", "/%65nabled"),  # Python servers decode
        ("PUT", "//enabled"),
        ("GET", "/HEARTBEAT"),
        ("GET", "/heartbeat/"),
        ("PUT", "/enabled%0A"),  # Starlette's `$` also matches before a trailing newline
        ("PUT", "/enabled;x"),  # Tomcat
        ("PUT", "/;x/enabled"),
    ],
)
def test_the_internal_endpoints_are_refused_in_every_spelling(monkeypatch, method, path):
    found = decide(monkeypatch, ADMIN_AREA, method, path, 2)
    assert found["bad_request"] == 1
    assert strikes() == 1


def test_a_route_matching_only_in_another_letter_case_does_not_lower_the_access_level(monkeypatch):
    record = exapp(
        {"url": "^/static/.*", "verb": "GET", "access_level": 0}, {"url": ".*", "verb": "GET", "access_level": 2}
    )
    assert request(monkeypatch, record, "GET", "/static/app.js") == "ALLOW"
    assert request(monkeypatch, record, "GET", "/STATIC/app.js") == "403"


def test_a_path_without_a_route_in_its_letter_case_is_still_refused(monkeypatch):
    record = exapp({"url": "^/x$", "verb": "GET", "access_level": 0})
    assert request(monkeypatch, record, "GET", "/X") == "404"


def test_a_directory_path_is_not_refused_for_lack_of_a_route_without_its_slash(monkeypatch):
    record = exapp({"url": "^/api/.*", "verb": "GET", "access_level": 1})
    assert request(monkeypatch, record, "GET", "/api/", 1) == "ALLOW"


def test_the_route_of_the_first_reading_decides_between_routes_of_the_same_level(monkeypatch):
    record = exapp(
        {"url": "^/a/x/$", "verb": "GET", "access_level": 2, "bruteforce_protection": [401]},
        {"url": "^/A/x$", "verb": "GET", "access_level": 2},
        {"url": ".*", "verb": "GET", "access_level": 1},
    )
    found = decide(monkeypatch, record, "GET", "/A/x/", 2)
    assert outcome(found) == "ALLOW"
    assert found["statuses_to_trigger_bp"] == "[401]"


def test_a_request_to_appapi_keeps_its_path():
    # The Docker Engine API through the FRP tunnel, as AppAPI sends it.
    headers = "harp-shared-key: unit-test-shared-key\ndocker-engine-port: 24001"
    reply = asyncio.run(agent.exapps_msg("/exapps/app_api/v1.44/_ping", headers, ipaddress.ip_address(IP), "", "GET"))
    assert txn_vars(reply)["target_path"] == "/v1.44/_ping"


def test_a_request_signed_by_appapi_is_forwarded_as_sent(monkeypatch):
    signed = "\n".join(
        [
            "harp-shared-key: unit-test-shared-key",
            "authorization-app-api: dXNlcjpzZWNyZXQ=",
            "ex-app-version: 1",
            "ex-app-id: app",
            "ex-app-host: 127.0.0.1",
            "ex-app-port: 23000",
        ]
    )
    assert decide(monkeypatch, ADMIN_AREA, "GET", "//x;y/%61", headers=signed)["target_path"] == "//x;y/%61"
