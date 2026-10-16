# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests import the agent as a module, which reads its configuration from the environment at import time."""

import os

import pytest

# Nothing from the developer's shell may reach that configuration.
for name in [name for name in os.environ if name.startswith(("HP_", "KUBERNETES_SERVICE_"))]:
    del os.environ[name]
os.environ["NC_INSTANCE_URL"] = "http://nextcloud.local"
os.environ["HP_SHARED_KEY"] = "unit-test-shared-key"


@pytest.fixture(autouse=True)
def fresh_agent_caches():
    """Bans, sessions, ExApp records and negative lookups recorded by one test must not leak into the next."""
    import haproxy_agent

    for cache in (
        haproxy_agent.BLACKLIST_CACHE,
        haproxy_agent.SESSION_CACHE,
        haproxy_agent.EXAPP_CACHE,
        haproxy_agent._EXAPP_NEGATIVE_CACHE,
    ):
        cache.clear()
    yield
    # A lookup removes itself from the in-flight map when it ends, so a test must not leave one behind.
    assert haproxy_agent._EXAPP_INFLIGHT == {}
