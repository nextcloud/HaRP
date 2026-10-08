# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The HP_EXAPP_BIND_MOUNTS_* rules for bind mounts of ExApp containers."""

import pytest

import haproxy_agent as agent

DEFAULT_DENIED = agent._parse_mount_rules("TEST", agent.DEFAULT_BIND_MOUNTS_DENIED, rw_suffix=True)
# The entries of the default list that only warn in this release, written out independently of the agent.
WARN_ONLY = frozenset(
    "/dev,/run,/var/run,/root,/etc:rw,/usr:rw,/bin:rw,/sbin:rw,/lib:rw,/lib64:rw,/var/spool:rw".split(",")
)


def check(source, mode="rw", disabled=False, allowed=(), denied=DEFAULT_DENIED):
    mounts = [agent.CreateExAppMounts(source=source, target="/mnt/target", mode=mode)]
    return agent.check_bind_mounts(mounts, disabled, list(allowed), list(denied))


def test_no_mounts_are_always_permitted():
    assert agent.check_bind_mounts([], True, ["/mnt"], DEFAULT_DENIED) is None


def test_the_agent_starts_with_the_default_rules():
    assert agent.BIND_MOUNTS_DISABLED is False
    assert agent.BIND_MOUNTS_ENFORCE_ALL is False
    assert agent.BIND_MOUNTS_ALLOWED == []
    assert agent.BIND_MOUNTS_DENIED == DEFAULT_DENIED
    assert ("/var/run", False) in DEFAULT_DENIED
    assert ("/etc", True) in DEFAULT_DENIED
    # For now, the read-write entries of the default list only log a warning.
    assert agent.BIND_MOUNTS_WARN_ONLY == WARN_ONLY
    assert agent.DEFAULT_BIND_MOUNTS_STAGED == WARN_ONLY


@pytest.mark.parametrize(
    ("source", "mode"),
    [
        ("/mnt/models", "rw"),
        ("/srv/exapps/data", "rw"),
        ("/home/user/models", "ro"),
        ("/var/lib/exapps", "rw"),
        ("/var/lib/dockerfiles", "rw"),  # only shares a name prefix with /var/lib/docker
        ("/runner", "rw"),
        ("/opt/models", "rw"),
        ("/etc/localtime", "ro"),
        ("/etc/ssl/certs", "ro"),
        ("/usr/share/models", "ro"),
        ("/home/user/models", "rw"),
        ("/var/spool", "ro"),
    ],
)
def test_permitted_by_default(source, mode):
    assert check(source, mode) is None


@pytest.mark.parametrize(
    "source",
    [
        "/",
        "/var",
        "/var/lib",
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/user/1000/docker.sock",
        "/run/containerd/containerd.sock",
        "/proc",
        "/proc/1/root",
        "/sys/fs/cgroup",
        "/dev/sda",
        "/boot",
        "/root/.ssh",
        "/var/lib/docker",
        "/var/lib/docker/volumes",
        "/var/lib/containerd",
        "//var//run/docker.sock",
        "/var/./run/docker.sock/",
        "/etc",  # a parent of /etc/shadow
        "/etc/shadow",
        "/etc/sudoers.d/exapp",
        "/etc/ssh/sshd_config",
    ],
)
@pytest.mark.parametrize("mode", ["ro", "rw"])
def test_refused_by_default(source, mode):
    assert "HP_EXAPP_BIND_MOUNTS_DENIED" in check(source, mode)


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("/etc/passwd", "/etc:rw"),
        ("/etc/cron.d", "/etc:rw"),
        ("/usr/bin", "/usr:rw"),
        ("/usr/lib/systemd/system", "/usr:rw"),
        ("/bin", "/bin:rw"),
        ("/sbin/init", "/sbin:rw"),
        ("/lib/modules", "/lib:rw"),
        ("/lib64", "/lib64:rw"),
        ("/var/spool/cron", "/var/spool:rw"),
    ],
)
def test_read_write_only_rules(source, rule):
    assert check(source, "ro") is None
    assert f"HP_EXAPP_BIND_MOUNTS_DENIED rule '{rule}'" in check(source, "rw")


def test_refusal_names_the_mount_and_the_rule():
    # The rule comes first: AppAPI shows only the first 120 characters of the answer to the administrator.
    assert check("/var/run/docker.sock") == (
        "HP_EXAPP_BIND_MOUNTS_DENIED rule '/var/run/docker.sock' forbids mounting '/var/run/docker.sock' (rw)."
    )


def test_every_mount_is_checked():
    mounts = [
        agent.CreateExAppMounts(source="/mnt/models", target="/models"),
        agent.CreateExAppMounts(source="/proc", target="/host-proc"),
    ]
    assert "'/proc'" in agent.check_bind_mounts(mounts, False, [], DEFAULT_DENIED)


def test_disabled_refuses_every_mount():
    assert check("/mnt/models", disabled=True) == "HP_EXAPP_BIND_MOUNTS_DISABLED is set, so no bind mount is permitted."


@pytest.mark.parametrize("source", ["/mnt/models", "/mnt/models/llm", "/srv/data/a"])
def test_allowed_list_permits_paths_at_or_below_an_entry(source):
    assert check(source, allowed=["/mnt/models", "/srv/data"]) is None


@pytest.mark.parametrize("source", ["/mnt", "/mnt/models2", "/srv", "/opt/other"])
def test_allowed_list_refuses_everything_else(source):
    assert "HP_EXAPP_BIND_MOUNTS_ALLOWED" in check(source, allowed=["/mnt/models", "/srv/data"])


def test_a_denied_entry_wins_a_tie():
    assert "rule '/var/run'" in check("/var/run/mysqld", allowed=["/var/run"])
    # An allowed entry at exactly a denied path ties, and the denied one wins.
    assert "rule '/var/run/docker.sock'" in check("/var/run/docker.sock", allowed=["/var/run/docker.sock"])
    assert "rule '/var/run'" in check("/var/run", allowed=["/var/run"])
    assert "rule '/etc:rw'" in check("/etc/hosts", "rw", allowed=["/etc"])


@pytest.mark.parametrize(
    ("allowed", "source", "mode"),
    [
        (["/var/run/mysqld"], "/var/run/mysqld/mysqld.sock", "rw"),
        (["/var/run/mysqld"], "/var/run/mysqld", "rw"),
        (["/dev/shm"], "/dev/shm", "rw"),
        (["/usr/local/models"], "/usr/local/models", "rw"),
        (["/usr/local/models"], "/usr/local/models/llm", "rw"),
        (["/etc/ssl/private"], "/etc/ssl/private", "ro"),
    ],
)
def test_a_more_specific_allowed_entry_permits_part_of_a_denied_path(allowed, source, mode):
    assert check(source, mode, allowed=allowed) is None


@pytest.mark.parametrize(
    ("allowed", "source", "rule"),
    [
        (["/var/run/mysqld"], "/var/run/docker.sock", "/var/run/docker.sock"),  # only its own subtree
        (["/var/run/mysqld"], "/var/run/lock", "/var/run"),
        (["/dev/shm"], "/dev/sda", "/dev"),
        (["/usr/local/models"], "/usr/bin", "/usr:rw"),
        (["/var/run/mysqld"], "/var/run", "/var/run"),  # the parent itself stays refused
    ],
)
def test_an_exception_does_not_widen_beyond_its_path(allowed, source, rule):
    assert f"rule '{rule}'" in check(source, "rw", allowed=allowed)


@pytest.mark.parametrize(
    ("allowed", "source", "mode", "inside"),
    [(["/var"], "/var", "rw", "/var/lib/docker"), (["/etc"], "/etc", "ro", "/etc/shadow"), (["/"], "/", "ro", "/proc")],
)
def test_an_allowed_parent_of_a_denied_path_is_still_refused(allowed, source, mode, inside):
    message = check(source, mode, allowed=allowed)
    assert f"rule '{inside}'" in message
    assert message.endswith("the mount contains it.")


def test_strict_mode_denies_the_root_and_allows_a_list():
    strict = [("/", False)]
    assert check("/mnt/models/llm", allowed=["/mnt/models"], denied=strict) is None
    assert (
        check("/mnt", allowed=["/mnt/models"], denied=strict) == "HP_EXAPP_BIND_MOUNTS_ALLOWED does not cover '/mnt'."
    )
    assert (
        check("/opt", allowed=["/mnt/models"], denied=strict) == "HP_EXAPP_BIND_MOUNTS_ALLOWED does not cover '/opt'."
    )
    # Without an allowed list, denying the root refuses every mount and names the rule.
    assert "rule '/'" in check("/opt", denied=strict)


def test_allowing_the_root_permits_any_path_that_is_not_denied():
    assert check("/mnt/models", allowed=["/"]) is None
    assert "HP_EXAPP_BIND_MOUNTS_DENIED" in check("/proc", allowed=["/"])


def test_an_empty_denied_list_permits_everything():
    assert check("/var/run/docker.sock", denied=[]) is None
    assert check("/", denied=[]) is None


def test_denying_the_root_refuses_everything():
    assert "HP_EXAPP_BIND_MOUNTS_DENIED" in check("/mnt/models", denied=[("/", False)])
    assert check("/mnt/models", "ro", denied=[("/", True)]) is None


def test_rules_are_parsed_from_a_comma_separated_list():
    assert agent._parse_mount_rules("TEST", "") == []
    assert agent._parse_mount_rules("TEST", " /mnt/models/ ,,'/srv/data', \"/opt\" ") == [
        ("/mnt/models", False),
        ("/srv/data", False),
        ("/opt", False),
    ]
    assert agent._parse_mount_rules("TEST", '"/etc:rw,/proc"', rw_suffix=True) == [("/etc", True), ("/proc", False)]
    # Quotes or blanks around the path itself, with the suffix outside them.
    assert agent._parse_mount_rules("TEST", "'/etc':rw, /usr :rw", rw_suffix=True) == [("/etc", True), ("/usr", True)]


@pytest.mark.parametrize(
    ("value", "rw_suffix"),
    [("models", False), ("/mnt/../etc", False), ("/mnt/models:rw", False), ("/etc:ro", True), ("/a,b", True)],
)
def test_a_malformed_rule_stops_the_agent(value, rw_suffix):
    with pytest.raises(SystemExit, match="in TEST"):
        agent._parse_mount_rules("TEST", value, rw_suffix=rw_suffix)


def check_staged(source, mode="rw", allowed=(), denied=DEFAULT_DENIED):
    mounts = [agent.CreateExAppMounts(source=source, target="/mnt/target", mode=mode)]
    return agent.check_bind_mounts(mounts, False, list(allowed), list(denied), WARN_ONLY)


@pytest.mark.parametrize(
    ("source", "mode", "rule", "remedy"),
    [
        ("/etc/localtime", "rw", "/etc:rw", "mount it read-only or list it in"),
        ("/usr/share/zoneinfo", "rw", "/usr:rw", "mount it read-only or list it in"),
        ("/var/spool/cron", "rw", "/var/spool:rw", "mount it read-only or list it in"),
        ("/dev/shm", "rw", "/dev", "list it in"),
        ("/dev/shm", "ro", "/dev", "list it in"),
        ("/run/desktop/mnt/host/c/models", "ro", "/run", "list it in"),  # Docker Desktop for Windows
        ("/var/run/mysqld/mysqld.sock", "rw", "/var/run", "list it in"),
        ("/root/.cache/huggingface", "rw", "/root", "list it in"),
        ("/dev", "rw", "/dev", "list it in"),
    ],
)
def test_a_warn_only_rule_permits_the_mount_and_logs_a_warning(caplog, source, mode, rule, remedy):
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert check_staged(source, mode) is None
    assert f"Bind mount of '{source}' ({mode}) is permitted for now, but a later release will refuse it" in caplog.text
    assert f"HP_EXAPP_BIND_MOUNTS_DENIED rule '{rule}' forbids mounting '{source}' ({mode})" in caplog.text
    assert f"To keep it, {remedy} HP_EXAPP_BIND_MOUNTS_ALLOWED;" in caplog.text
    assert "HP_EXAPP_BIND_MOUNTS_ENFORCE_ALL=true refuses it now." in caplog.text


def test_the_warning_names_the_container(caplog):
    mounts = [agent.CreateExAppMounts(source="/dev/shm", target="/dev/shm")]
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert agent.check_bind_mounts(mounts, False, [], DEFAULT_DENIED, WARN_ONLY, "nc_app_llm2") is None
    assert "Bind mount of '/dev/shm' (rw) for 'nc_app_llm2' is permitted for now" in caplog.text


@pytest.mark.parametrize(
    ("source", "mode", "rule"),
    [
        ("/proc", "ro", "/proc"),
        ("/sys/fs/cgroup", "ro", "/sys"),
        ("/boot", "ro", "/boot"),
        ("/var/run/docker.sock", "rw", "/var/run/docker.sock"),
        ("/run/docker.sock", "ro", "/run/docker.sock"),
        ("/run/containerd/containerd.sock", "rw", "/run/containerd"),
        ("/var/run/containerd", "ro", "/var/run/containerd"),
        ("/run/podman/podman.sock", "rw", "/run/podman"),
        ("/run/crio/crio.sock", "rw", "/run/crio"),
        ("/var/lib/docker/volumes", "rw", "/var/lib/docker"),
        ("/var/lib/containerd", "ro", "/var/lib/containerd"),
        ("/etc/shadow", "ro", "/etc/shadow"),
        ("/etc/sudoers.d/exapp", "rw", "/etc/sudoers.d"),
        ("/etc/ssh", "ro", "/etc/ssh"),
        ("/etc", "rw", "/etc/shadow"),  # contains a refused path
        ("/run", "ro", "/run/docker.sock"),
        ("/var/run", "rw", "/var/run/docker.sock"),
        ("/var", "rw", "/var/lib/docker"),
        ("/", "ro", "/proc"),
    ],
)
def test_warn_only_rules_do_not_weaken_the_other_rules(source, mode, rule):
    assert f"HP_EXAPP_BIND_MOUNTS_DENIED rule '{rule}'" in check_staged(source, mode)


def test_a_read_only_mount_logs_no_warning(caplog):
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert check_staged("/etc/localtime", "ro") is None
    assert caplog.text == ""


def test_a_warn_only_rule_inside_the_mount_only_warns(caplog):
    denied = [("/srv/data/config", True)]
    mounts = [agent.CreateExAppMounts(source="/srv/data", target="/data", mode="rw")]
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert agent.check_bind_mounts(mounts, False, [], denied, frozenset({"/srv/data/config:rw"})) is None
        assert "the mount contains it" in agent.check_bind_mounts(mounts, False, [], denied)
    assert "rule '/srv/data/config:rw' forbids mounting '/srv/data' (rw): the mount contains it." in caplog.text


def test_settings_are_read_at_startup(tmp_path):
    def start(**env):
        return run_agent_import(tmp_path, env)

    out = start()
    assert out.returncode == 0
    assert f"only a warning for {sorted(WARN_ONLY)}" in out.stderr

    out = start(HP_EXAPP_BIND_MOUNTS_ENFORCE_ALL="'true'")
    assert out.returncode == 0
    assert "only a warning" not in out.stderr

    out = start(HP_EXAPP_BIND_MOUNTS_DENIED="/proc,/data:rw")
    assert "HP_EXAPP_BIND_MOUNTS_DENIED replaces the default list" in out.stderr
    assert "only a warning" not in out.stderr  # a list set by the administrator is enforced as written

    out = start(HP_EXAPP_BIND_MOUNTS_DENIED="")
    assert "HP_EXAPP_BIND_MOUNTS_DENIED is empty: no host path is denied" in out.stderr

    out = start(HP_EXAPP_BIND_MOUNTS_DENIED="/proc /sys /var/run/docker.sock")
    assert out.returncode != 0
    assert (
        "invalid entry '/proc /sys /var/run/docker.sock' in HP_EXAPP_BIND_MOUNTS_DENIED: separate the paths"
        in out.stderr
    )

    out = start(HP_EXAPP_BIND_MOUNTS_ALLOWED="/mnt/AI models,/srv/data")  # a path may contain a blank
    assert out.returncode == 0
    assert "allowed below ['/mnt/AI models', '/srv/data']" in out.stderr

    out = start(HP_EXAPP_BIND_MOUNTS_ALLOWED="/mnt/models:rw")  # ':rw' only exists in the denied list
    assert out.returncode != 0
    assert "invalid entry '/mnt/models:rw' in HP_EXAPP_BIND_MOUNTS_ALLOWED: must not contain ':'" in out.stderr

    out = start(HP_EXAPP_BIND_MOUNTS_DISABLED='"true"')
    assert out.returncode == 0
    assert "Bind mounts for ExApp containers are disabled." in out.stderr


@pytest.mark.parametrize("name", ["HP_EXAPP_BIND_MOUNTS_DISABLED", "HP_EXAPP_BIND_MOUNTS_ENFORCE_ALL"])
@pytest.mark.parametrize("value", ["on", "enabled", "2", "truee"])
def test_an_unknown_boolean_value_stops_the_agent(tmp_path, name, value):
    out = run_agent_import(tmp_path, {name: value})
    assert out.returncode != 0
    assert f"invalid value {value!r} in {name}: expected true or false" in out.stderr


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, False),
        ("", False),
        ("  ", False),
        ("true", True),
        ("TRUE", True),
        ("'1'", True),
        ('"yes"', True),
        ("false", False),
        ("0", False),
        ("No", False),
    ],
)
def test_boolean_settings(value, expected):
    assert agent._parse_bool("TEST", value, False) is expected


def run_agent_import(tmp_path, env):
    """Import the agent in a fresh interpreter, the way HaRP starts it, and return the result."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    clean = {k: v for k, v in os.environ.items() if not k.startswith(("HP_", "KUBERNETES_SERVICE_"))}
    clean.update(NC_INSTANCE_URL="http://nextcloud.local", HP_SHARED_KEY="unit-test-shared-key", HP_LOG_LEVEL="INFO")
    clean.update(env)
    repo = Path(__file__).resolve().parents[2]
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import haproxy_agent"],
        cwd=tmp_path,
        env={**clean, "PYTHONPATH": str(repo), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_warn_only_rules_do_not_bypass_the_allowed_list(caplog):
    # /etc/localtime is not covered by the allowed list: refused, whatever the read-write rule says.
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert check_staged("/etc/localtime", allowed=["/mnt/models"]) == (
            "HP_EXAPP_BIND_MOUNTS_ALLOWED does not cover '/etc/localtime'."
        )
        assert check_staged("/mnt/models/llm", allowed=["/mnt/models"]) is None
    assert caplog.text == ""  # a refused or unaffected mount needs no warning


def test_an_allowed_entry_below_a_warn_only_rule_needs_no_warning(caplog):
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert check_staged("/usr/local/models", allowed=["/usr/local/models"]) is None
    assert caplog.text == ""


def test_every_mount_of_a_request_is_checked_with_warn_only_rules(caplog):
    mounts = [
        agent.CreateExAppMounts(source="/etc/localtime", target="/etc/localtime", mode="rw"),
        agent.CreateExAppMounts(source="/var/run/docker.sock", target="/var/run/docker.sock", mode="rw"),
    ]
    with caplog.at_level("WARNING", logger=agent.LOGGER.name):
        assert "rule '/var/run/docker.sock'" in agent.check_bind_mounts(mounts, False, [], DEFAULT_DENIED, WARN_ONLY)
    assert "'/etc/localtime' (rw) is permitted for now" in caplog.text


def test_a_read_only_mount_may_contain_a_read_write_rule():
    denied = [("/srv/data/config", True)]
    assert check("/srv/data", "ro", denied=denied) is None
    assert check("/srv/data", "rw", denied=denied).endswith("the mount contains it.")
