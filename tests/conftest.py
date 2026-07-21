from __future__ import annotations

import pytest

from aegis.core.authorization import localhost_scope
from aegis.core.config import Config, LoopConfig, TargetConfig


@pytest.fixture
def scope():
    return localhost_scope()


@pytest.fixture
def llm_config(tmp_path, scope):
    cfg = Config(engagement="test", scope=scope, workdir=tmp_path,
                 db_path=tmp_path / "t.db",
                 loop=LoopConfig(max_rounds=3, probes_per_round=14, min_rounds=1))
    cfg.targets = [TargetConfig(id="mock-llm", kind="local_llm", provider="mock",
                                model="mock-secure-1", mode="grey_box")]
    return cfg
