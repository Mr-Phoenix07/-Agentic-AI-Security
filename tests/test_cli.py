from __future__ import annotations

from aegis.cli import main


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
