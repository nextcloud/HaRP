# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The HP_EXAPP_BIND_MOUNTS_* rules for bind mounts of ExApp containers."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import haproxy_agent as agent

DEFAULT_DENIED = agent._parse_mount_rules("TEST", agent.DEFAULT_BIND_MOUNTS_DENIED, rw_suffix=True)
# The default list, written out independently of the agent: the hard core, and the entries that only warn for now.
HARD_CORE = frozenset(
    "/proc,/sys,/boot,/var/lib/docker,/var/lib/containerd,/var/lib/containers,/run/docker.sock,/var/run/docker.sock,"
    "/run/containerd,/var/run/containerd,/run/podman,/var/run/podman,/run/crio,/var/run/crio,/etc/shadow,/etc/gshadow,"
    "/etc/sudoers,/etc/sudoers.d,/etc/ssh".split(",")
)
WARN_ONLY = frozenset(
    "/dev,/run,/var/run,/root,/var/lib/docker/volumes,/var/lib/containers/storage/volumes,/etc:rw,/usr:rw,/bin:rw,"
    "/sbin:rw,/lib:rw,/lib64:rw,/var/spool:rw".split(",")
)


def mount(source, mode="rw"):
    return agent.CreateExAppMounts(source=source, target="/mnt/target", mode=mode)


def check(source, mode="rw", allowed=(), denied=DEFAULT_DENIED, warn_only=frozenset(), container_name=""):
    """Without `warn_only` every rule is enforced, as with HP_EXAPP_BIND_MOUNTS_ENFORCE_ALL=true."""
    return agent.check_bind_mounts([mount(source, mode)], False, list(allowed), list(denied), warn_only, container_name)


def test_no_mounts_are_always_permitted():
    assert agent.check_bind_mounts([], True, ["/mnt"], DEFAULT_DENIED) is None


def test_disabled_refuses_every_mount():
    assert agent.check_bind_mounts([mount("/mnt/models")], True, [], []) == (
        "HP_EXAPP_BIND_MOUNTS_DISABLED is set, so no bind mount is permitted."
    )


def test_the_agent_starts_with_the_default_rules():
    assert agent.BIND_MOUNTS_DISABLED is False
    assert agent.BIND_MOUNTS_ENFORCE_ALL is False
    assert agent.BIND_MOUNTS_ALLOWED == []
    assert agent.BIND_MOUNTS_DENIED == DEFAULT_DENIED
    assert {agent._rule_label(*rule) for rule in DEFAULT_DENIED} == HARD_CORE | WARN_ONLY
    assert agent.BIND_MOUNTS_WARN_ONLY == WARN_ONLY


@pytest.mark.parametrize(
    ("source", "mode"),
    [
        ("/mnt/models", "rw"),
        ("/var/lib/dockerfiles", "rw"),  # only shares a name prefix with /var/lib/docker
        ("/runner", "rw"),
        ("/etc/localtime", "ro"),
        ("/var/spool", "ro"),
    ],
)
def test_permitted(source, mode):
    assert check(source, mode) is None


@pytest.mark.parametrize(
    ("source", "mode", "rule"),
    [
        ("/proc", "ro", "/proc"),
        ("/var/lib/docker/image", "rw", "/var/lib/docker"),
        ("/var/lib/docker/volumes/v/_data", "ro", "/var/lib/docker/volumes"),
        ("/dev/sda", "ro", "/dev"),
        ("/etc/passwd", "rw", "/etc:rw"),
        ("/lib64", "rw", "/lib64:rw"),
        ("/etc", "ro", "/etc/shadow"),  # a parent of a denied path
        ("/", "ro", "/proc"),
    ],
)
def test_refused(source, mode, rule):
    assert f"HP_EXAPP_BIND_MOUNTS_DENIED rule '{rule}' forbids mounting '{source}' ({mode})" in check(source, mode)


def test_hard_core_of_the_default_list_is_refused_although_some_entries_only_warn():
    for path in HARD_CORE:
        assert f"rule '{path}' forbids" in check(f"{path}/x", "ro", warn_only=WARN_ONLY)
    for parent in ("/", "/var", "/etc", "/run", "/var/run"):
        assert check(parent, "ro", warn_only=WARN_ONLY).endswith("the mount contains it.")


def test_refusal_names_the_mount_and_the_rule():
    # The rule comes first: AppAPI shows only the first 120 characters of the answer to the administrator.
    assert check("/var/run/docker.sock") == (
        "HP_EXAPP_BIND_MOUNTS_DENIED rule '/var/run/docker.sock' forbids mounting '/var/run/docker.sock' (rw)."
    )


@pytest.mark.parametrize(
    ("source", "permitted"), [("/mnt/models/llm", True), ("/srv/data", True), ("/mnt", False), ("/mnt/models2", False)]
)
def test_allowed_list(source, permitted):
    result = check(source, allowed=["/mnt/models", "/srv/data"])
    assert result is None if permitted else result == f"HP_EXAPP_BIND_MOUNTS_ALLOWED does not cover '{source}'."


def test_a_denied_entry_wins_a_tie():
    assert "rule '/var/run/docker.sock'" in check("/var/run/docker.sock", allowed=["/var/run/docker.sock"])
    assert "rule '/etc:rw'" in check("/etc/hosts", "rw", allowed=["/etc"])


@pytest.mark.parametrize(
    ("allowed", "source", "rule"),
    [
        ("/var/run/mysqld", "/var/run/mysqld/mysqld.sock", None),
        ("/usr/local/models", "/usr/local/models", None),
        ("/var/run/mysqld", "/var/run/docker.sock", "/var/run/docker.sock"),  # only its own subtree
        ("/var/run/mysqld", "/var/run", "/var/run"),  # the parent itself stays refused
        ("/usr/local/models", "/usr/bin", "/usr:rw"),
        ("/var", "/var", "/var/lib/docker"),  # an allowed parent of a denied path
    ],
)
def test_an_allowed_entry_below_a_denied_one_permits_only_its_own_part(allowed, source, rule):
    result = check(source, allowed=[allowed])
    assert result is None if rule is None else f"rule '{rule}'" in result


def test_custom_denied_lists():
    strict = [("/", False)]
    assert check("/mnt/models/llm", allowed=["/mnt/models"], denied=strict) is None
    assert (
        check("/opt", allowed=["/mnt/models"], denied=strict) == "HP_EXAPP_BIND_MOUNTS_ALLOWED does not cover '/opt'."
    )
    # Without an allowed list, or when an allowed entry ties with it, denying the root refuses and names the rule.
    assert "rule '/'" in check("/opt", denied=strict)
    assert "rule '/'" in check("/opt", allowed=["/"], denied=strict)
    assert check("/opt", "ro", denied=[("/", True)]) is None
    assert check("/", denied=[]) is None
    # A ":rw" entry inside a read-only mount does not refuse it.
    assert check("/srv/data", "ro", denied=[("/srv/data/config", True)]) is None
    assert check("/srv/data", "rw", denied=[("/srv/data/config", True)]).endswith("the mount contains it.")


def test_rules_are_parsed_from_a_comma_separated_list():
    assert agent._parse_mount_rules("TEST", "") == []
    assert agent._parse_mount_rules("TEST", " /mnt/models/ ,,'/srv/data', \"/mnt/AI models\" ") == [
        ("/mnt/models", False),
        ("/srv/data", False),
        ("/mnt/AI models", False),
    ]
    assert agent._parse_mount_rules("TEST", '"/etc:rw,/proc"', rw_suffix=True) == [("/etc", True), ("/proc", False)]
    assert agent._parse_mount_rules("TEST", "'/etc':rw, /usr :rw", rw_suffix=True) == [("/etc", True), ("/usr", True)]


@pytest.mark.parametrize(
    ("value", "rw_suffix"),
    [("models", False), ("/mnt/../etc", False), ("/mnt/models:rw", False), ("/etc:ro", True), ("/proc /sys", True)],
)
def test_a_malformed_rule_stops_the_agent(value, rw_suffix):
    with pytest.raises(SystemExit, match="in TEST"):
        agent._parse_mount_rules("TEST", value, rw_suffix=rw_suffix)


FIRST_ALLOWED = "list it, together with every other host path your ExApps mount, in HP_EXAPP_BIND_MOUNTS_ALLOWED"


@pytest.mark.parametrize(
    ("source", "mode", "allowed", "rule", "remedy"),
    [
        ("/etc/localtime", "rw", [], "/etc:rw", f"mount it read-only or {FIRST_ALLOWED}"),
        ("/dev/shm", "ro", [], "/dev", FIRST_ALLOWED),
        ("/var/lib/docker/volumes/v/_data", "ro", [], "/var/lib/docker/volumes", FIRST_ALLOWED),
        # With an allowed list already set, adding the path to it is enough.
        ("/var/run/mysqld/mysqld.sock", "rw", ["/var"], "/var/run", "list it in HP_EXAPP_BIND_MOUNTS_ALLOWED"),
        # An allowed entry at the rule's own path ties and loses, so only the fitting remedies are offered.
        ("/usr", "rw", [], "/usr:rw", "mount it read-only"),
        ("/dev", "ro", [], "/dev", "set HP_EXAPP_BIND_MOUNTS_DENIED to your own list without that rule"),
    ],
)
def test_a_warn_only_rule_permits_the_mount_and_logs_a_warning(caplog, source, mode, allowed, rule, remedy):
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert check(source, mode, allowed=allowed, warn_only=WARN_ONLY, container_name="nc_app_llm2") is None
    assert caplog.text.rstrip().endswith(
        f"Bind mount of '{source}' ({mode}) for 'nc_app_llm2' is permitted for now, but a later release will refuse "
        f"it: HP_EXAPP_BIND_MOUNTS_DENIED rule '{rule}' forbids mounting '{source}' ({mode}). To keep it, {remedy}; "
        "HP_EXAPP_BIND_MOUNTS_ENFORCE_ALL=true refuses it now."
    )
    # Every remedy offered really makes the mount pass once all rules are enforced.
    if "read-only" in remedy:
        assert check(source, "ro", allowed=allowed) is None
    if "ALLOWED" in remedy:
        assert check(source, mode, allowed=[*allowed, source]) is None


def test_warn_only_rules_log_nothing_for_a_mount_they_do_not_decide(caplog):
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert check("/etc/localtime", "ro", warn_only=WARN_ONLY) is None
        assert check("/usr/local/models", allowed=["/usr/local/models"], warn_only=WARN_ONLY) is None
        assert check("/mnt/models/llm", allowed=["/mnt/models"], warn_only=WARN_ONLY) is None
        # Not covered by the allowed list: refused, whatever the read-write rule says.
        assert check("/etc/localtime", allowed=["/mnt/models"], warn_only=WARN_ONLY) == (
            "HP_EXAPP_BIND_MOUNTS_ALLOWED does not cover '/etc/localtime'."
        )
    assert caplog.text == ""


def test_a_warn_only_rule_below_an_enforced_one_permits_only_its_own_part():
    assert check("/var/lib/docker/volumes/v/_data", "rw", warn_only=WARN_ONLY) is None
    assert "rule '/var/lib/docker' forbids" in check("/var/lib/docker/image", "ro", warn_only=WARN_ONLY)
    # An allowed list still has to cover it.
    assert check("/var/lib/docker/volumes/v/_data", allowed=["/mnt/models"], warn_only=WARN_ONLY) == (
        "HP_EXAPP_BIND_MOUNTS_ALLOWED does not cover '/var/lib/docker/volumes/v/_data'."
    )


def test_a_warn_only_rule_inside_the_mount_only_warns(caplog):
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert (
            check("/srv/data", denied=[("/srv/data/config", True)], warn_only=frozenset({"/srv/data/config:rw"}))
            is None
        )
    assert "rule '/srv/data/config:rw' forbids mounting '/srv/data' (rw): the mount contains it." in caplog.text


def test_every_mount_of_a_request_is_checked(caplog):
    mounts = [mount("/etc/localtime"), mount("/var/run/docker.sock")]
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert "rule '/var/run/docker.sock'" in agent.check_bind_mounts(mounts, False, [], DEFAULT_DENIED, WARN_ONLY)
    assert "'/etc/localtime' (rw) is permitted for now" in caplog.text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, False),
        ("  ", False),
        ("TRUE", True),
        ("'1'", True),
        ('"yes"', True),
        ("false", False),
        ("No", False),
        ("0", False),
    ],
)
def test_boolean_settings(monkeypatch, value, expected):
    if value is not None:
        monkeypatch.setenv("HP_TEST_SETTING", value)
    assert agent._parse_bool("HP_TEST_SETTING") is expected


@pytest.mark.parametrize("value", ["on", "2", "truee"])
def test_an_unknown_boolean_value_stops_the_agent(monkeypatch, value):
    monkeypatch.setenv("HP_TEST_SETTING", value)
    with pytest.raises(SystemExit, match=f"invalid value '{value}' in HP_TEST_SETTING: expected true or false"):
        agent._parse_bool("HP_TEST_SETTING")


def run_agent_import(**env):
    """Import the agent in a fresh interpreter, the way HaRP starts it, and return its log."""
    repo = Path(__file__).resolve().parents[2]
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import haproxy_agent"],
        env={**os.environ, "HP_LOG_LEVEL": "INFO", "PYTHONPATH": str(repo), "PYTHONDONTWRITEBYTECODE": "1", **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_settings_are_read_at_startup():
    out = run_agent_import()
    assert out.returncode == 0
    assert f"only a warning for {sorted(WARN_ONLY)}" in out.stderr
    assert "Docker Engine ports accepted from AppAPI: 24000-24099." in out.stderr

    out = run_agent_import(
        HP_EXAPP_BIND_MOUNTS_ENFORCE_ALL="true",
        HP_EXAPP_BIND_MOUNTS_ALLOWED="/srv/data",
        HP_DOCKER_ENGINE_PORTS="24000-24099, 2375",
    )
    assert out.returncode == 0
    assert "allowed below ['/srv/data']" in out.stderr
    assert "only a warning" not in out.stderr
    assert "Docker Engine ports accepted from AppAPI: 24000-24099, 2375." in out.stderr

    out = run_agent_import(HP_EXAPP_BIND_MOUNTS_DENIED="/proc,/data:rw")
    assert "HP_EXAPP_BIND_MOUNTS_DENIED replaces the default list" in out.stderr
    assert "denied ['/proc', '/data:rw']." in out.stderr  # a list set by the administrator is enforced as written

    out = run_agent_import(HP_EXAPP_BIND_MOUNTS_DENIED="", HP_DOCKER_ENGINE_PORTS="''")
    assert "HP_EXAPP_BIND_MOUNTS_DENIED is empty: no host path is denied" in out.stderr
    assert "Docker Engine ports accepted from AppAPI: 24000-24099." in out.stderr  # an empty value means the default

    out = run_agent_import(HP_EXAPP_BIND_MOUNTS_DISABLED="true")
    assert "Bind mounts for ExApp containers are disabled." in out.stderr

    out = run_agent_import(HP_EXAPP_BIND_MOUNTS_DENIED="/proc /sys")
    assert out.returncode != 0
    assert out.stderr.splitlines()[-1].startswith("ERROR: invalid entry '/proc /sys' in HP_EXAPP_BIND_MOUNTS_DENIED")
