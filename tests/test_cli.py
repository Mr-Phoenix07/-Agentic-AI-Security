from __future__ import annotations

from aegis.cli import main
from aegis.core.config import Config


def test_set_workdir_moves_derived_db(tmp_path):
    cfg = Config(engagement="t")                       # db_path derived from workdir
    cfg.set_workdir(tmp_path / "run")
    assert cfg.db_path == tmp_path / "run" / "aegis.db"


def test_set_workdir_respects_explicit_db_path(tmp_path):
    explicit = tmp_path / "custom.db"
    cfg = Config(engagement="t", db_path=explicit)     # explicit db_path
    cfg.set_workdir(tmp_path / "elsewhere")
    assert cfg.db_path == explicit                     # not moved


def test_cli_run_writes_db_under_workdir(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"engagement":"wd","authorization":{"rules":[{"label":"lab",'
                   '"model_ids":["mock-*"],"hosts":["localhost"]}]},'
                   '"targets":[{"id":"m","kind":"local_llm","provider":"mock",'
                   '"model":"mock-secure-1"}],"loop":{"max_rounds":1,"min_rounds":1,'
                   '"probes_per_round":6}}')
    wd = tmp_path / "out"
    assert main(["run", str(cfg), "--workdir", str(wd), "--quiet"]) == 0
    # the assessment DB (not just the report) must live under the given workdir
    assert (wd / "aegis.db").exists()
    assert list(wd.glob("assess_*/report.md"))


def test_cli_agents(capsys):
    assert main(["agents"]) == 0
    out = capsys.readouterr().out
    assert "adaptive_evaluation" in out
    assert "risk_analysis" in out


def test_cli_mutate(capsys):
    assert main(["mutate", "Explain HTTP caching.", "--count", "4"]) == 0
    out = capsys.readouterr().out
    assert "identity" in out
    assert "variants" in out


def test_cli_scope_check(tmp_path, capsys):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"engagement":"t","authorization":{"rules":[{"label":"lab",'
                   '"model_ids":["mock-*"],"hosts":["localhost"]}]},'
                   '"targets":[]}')
    assert main(["scope-check", str(cfg), "--model", "mock-1",
                 "--url", "https://evil.com"]) == 0
    out = capsys.readouterr().out
    assert "ALLOWED" in out and "DENIED" in out


def test_cli_demo(tmp_path, capsys):
    assert main(["demo", "--rounds", "1", "--workdir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Findings:" in out


def test_cli_run_empty_scope_fails(tmp_path, capsys):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"engagement":"t","authorization":{"rules":[]},"targets":[]}')
    # empty scope is fail-closed -> exit code 2
    assert main(["run", str(cfg), "--workdir", str(tmp_path)]) == 2
