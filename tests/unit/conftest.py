# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests import the agent as a module, which reads its configuration from the environment at import time."""

import os
import sys
from pathlib import Path

import pytest

# Nothing from the developer's shell may reach that configuration.
for name in [name for name in os.environ if name.startswith(("HP_", "KUBERNETES_SERVICE_"))]:
    del os.environ[name]
os.environ["NC_INSTANCE_URL"] = "http://nextcloud.local"
os.environ["HP_SHARED_KEY"] = "unit-test-shared-key"

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(autouse=True)
def fresh_agent_caches():
    """Bans, sessions and ExApp records recorded by one test must not leak into the next."""
    import haproxy_agent

    caches = (haproxy_agent.BLACKLIST_CACHE, haproxy_agent.SESSION_CACHE, haproxy_agent.EXAPP_CACHE)
    for cache in caches:
        cache.clear()
    yield
    for cache in caches:
        cache.clear()
