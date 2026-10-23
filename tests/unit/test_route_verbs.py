# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Route verbs: first match by path and method, HEAD implied by GET, 405 with Allow for a method no route lists."""

import asyncio
import ipaddress

from haproxyspoa.payloads.ack import AckPayload

import haproxy_agent as agent

IP = "192.0.2.7"

SAME_URL = [  # a public GET route listed before an admin POST route of the same URL
    {"url": "^/x$", "verb": "GET", "access_level": 0},
    {"url": "^/x$", "verb": "POST", "access_level": 2},
]


def txn_vars(reply: AckPayload) -> dict:
    return {action.name: action.value for action in reply.actions}


def exapp(*routes) -> agent.ExApp:
    return agent.ExApp.model_validate(
        {"exapp_token": "t", "exapp_version": "1", "host": "127.0.0.1", "port": 23000, "routes": list(routes)}
    )


def decide(monkeypatch, record, method, path, level=None, lookups=None, headers="") -> dict:
    """The txn vars the agent sets for this request; `level` sends credentials of a user with that access level.

    `method=None` calls the handler without it, as for a custom spoe-agent.conf without `method`.
    """

    async def fetch(_app_id):
        return record

    async def user(_app_id, _headers):
        if lookups is not None:
            lookups.append(path)
        return agent.NcUser(user_id="u", access_level=level)

    monkeypatch.setattr(agent, "_get_or_fetch_exapp", fetch)
    monkeypatch.setattr(agent, "nc_get_user", user)
    if level is not None:
        headers = "authorization: Basic eDp5"
    args = {"path": f"/exapps/app{path}", "headers": headers, "client_ip": ipaddress.ip_address(IP), "pass_cookie": ""}
    if method is not None:
        args["method"] = method
    return txn_vars(asyncio.run(agent.exapps_msg(**args)))  # the handler, called the way haproxyspoa calls it


def outcome(found: dict) -> str:
    if "backend" in found:
        return "ALLOW"
    for name, code in (("method_not_allowed", "405"), ("forbidden", "403"), ("not_found", "404")):
        if found.get(name) == 1:
            return code
    return repr(found)


def request(monkeypatch, record, method, path, level=None) -> str:
    return outcome(decide(monkeypatch, record, method, path, level))


def strikes():
    return len(agent.BLACKLIST_CACHE.get(IP, []))


def test_first_match_by_path_and_method(monkeypatch):
    assert request(monkeypatch, exapp(*SAME_URL), "GET", "/x") == "ALLOW"
    assert request(monkeypatch, exapp(*SAME_URL), "POST", "/x") == "403"
    assert strikes() == 1
    assert request(monkeypatch, exapp(*SAME_URL), "POST", "/x", level=2) == "ALLOW"


def test_bruteforce_protection_comes_from_the_deciding_route(monkeypatch):
    record = exapp(
        {"url": "^/login$", "verb": "GET", "access_level": 0},
        {"url": "^/login$", "verb": "POST", "access_level": 0, "bruteforce_protection": [401]},
    )
    found = decide(monkeypatch, record, "GET", "/login")
    assert found["backend"] == "ex_apps_backend"
    assert "statuses_to_trigger_bp" not in found
    found = decide(monkeypatch, record, "POST", "/login")
    assert found["backend"] == "ex_apps_backend_w_bruteforce"
    assert found["statuses_to_trigger_bp"] == "[401]"


def test_unlisted_method_is_405_with_allow_and_no_ban_strike(monkeypatch):
    other_url = {"url": "^/other$", "verb": "PUT", "access_level": 0}  # not part of the Allow header of /x
    found = decide(monkeypatch, exapp(*SAME_URL, other_url), "DELETE", "/x")
    assert found["method_not_allowed"] == 1
    assert found["not_found"] == 1  # a custom /haproxy.cfg without the 405 rule answers 404
    assert found["allow"] == "GET, HEAD, POST"
    for _ in range(20):  # a link checker or monitor cannot get its address banned this way
        assert request(monkeypatch, exapp(*SAME_URL), "PATCH", "/x") == "405"
    assert strikes() == 0
    assert request(monkeypatch, exapp(*SAME_URL), "GET", "/x") == "ALLOW"


def test_unlisted_method_is_refused_before_the_user_lookup(monkeypatch):
    # Not counted toward the ban, so it must not let a client make Nextcloud check credentials without limit.
    lookups = []
    found = decide(monkeypatch, exapp(*SAME_URL), "DELETE", "/x", level=1, lookups=lookups)
    assert outcome(found) == "405"
    assert lookups == []
    assert outcome(decide(monkeypatch, exapp(*SAME_URL), "POST", "/x", level=2, lookups=lookups)) == "ALLOW"
    assert lookups == ["/x"]


def test_head_is_implied_by_get(monkeypatch):
    assert request(monkeypatch, exapp(*SAME_URL), "HEAD", "/x") == "ALLOW"
    only_post = exapp({"url": "^/y$", "verb": "POST", "access_level": 0})
    assert request(monkeypatch, only_post, "HEAD", "/y") == "405"


def test_options_is_not_special(monkeypatch):
    assert request(monkeypatch, exapp(*SAME_URL), "OPTIONS", "/x") == "405"
    listed = exapp({"url": "^/y$", "verb": "POST,OPTIONS", "access_level": 0})
    assert request(monkeypatch, listed, "OPTIONS", "/y") == "ALLOW"


def test_route_with_several_verbs(monkeypatch):
    record = exapp({"url": "^/z$", "verb": "GET,POST", "access_level": 0})
    assert request(monkeypatch, record, "POST", "/z") == "ALLOW"
    assert request(monkeypatch, record, "PUT", "/z") == "405"


def test_verb_as_appapi_before_35_stores_it(monkeypatch):
    # AppAPI before 35 stores the text of <verb> as it is in info.xml, line breaks and case included.
    record = exapp({"url": "^/z$", "verb": "\n      get, POST\n    ", "access_level": 0})
    assert request(monkeypatch, record, "GET", "/z") == "ALLOW"
    assert request(monkeypatch, record, "POST", "/z") == "ALLOW"
    assert decide(monkeypatch, record, "PUT", "/z")["allow"] == "GET, HEAD, POST"


def test_method_is_case_sensitive(monkeypatch):
    assert request(monkeypatch, exapp(*SAME_URL), "get", "/x") == "405"


def test_methods_are_compared_as_tokens(monkeypatch):
    record = exapp({"url": "^/z$", "verb": "GET,POST", "access_level": 0})
    for method in ("ET", "OS", "GETPOST"):  # a client may send any method token
        assert request(monkeypatch, record, method, "/z") == "405"


def test_route_without_verb_matches_every_method(monkeypatch):
    older_appapi = exapp({"url": "^/x$", "access_level": 0})
    assert request(monkeypatch, older_appapi, "DELETE", "/x") == "ALLOW"


def test_request_without_method_keeps_the_first_path_match(monkeypatch):
    # A custom spoe-agent.conf without `method`: the first route of the path decides, as before.
    assert request(monkeypatch, exapp(*SAME_URL), None, "/x") == "ALLOW"
    assert request(monkeypatch, exapp(*reversed(SAME_URL)), None, "/x") == "403"


def test_request_signed_by_appapi_skips_the_route_check(monkeypatch):
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
    assert outcome(decide(monkeypatch, exapp(*SAME_URL), "DELETE", "/x", headers=signed)) == "ALLOW"
    assert outcome(decide(monkeypatch, exapp(*SAME_URL), "PUT", "/enabled", headers=signed)) == "ALLOW"


def test_public_route_still_tells_the_exapp_who_the_user_is(monkeypatch):
    found = decide(monkeypatch, exapp(*SAME_URL), "GET", "/x", level=1)
    assert found["exapp_token"] == agent.b64encode(b"u:t")


def test_unknown_path_is_still_404_and_counted(monkeypatch):
    assert request(monkeypatch, exapp(*SAME_URL), "GET", "/nope") == "404"
    assert strikes() == 1


def test_route_with_invalid_regex_is_not_a_path_match(monkeypatch):
    # AppAPI does not check route regexes, and Python's re rejects some PCRE patterns.
    record = exapp({"url": "^/x(", "verb": "PUT", "access_level": 0})
    assert request(monkeypatch, record, "GET", "/x") == "404"
    assert strikes() == 1
