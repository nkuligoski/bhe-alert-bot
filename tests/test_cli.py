from alertbot.cli import main
from alertbot.cli import _write_json_output
from alertbot.models import RunResult


def test_run_missing_config_returns_error(tmp_path):
    missing = tmp_path / "missing.json"

    assert main(["--config", str(missing), "run"]) == 1


def test_help_returns_success(capsys):
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0


def test_write_json_output(tmp_path):
    output_path = tmp_path / "nested" / "alerts.json"
    result = RunResult(
        total_attack_paths=1,
        candidate_attack_paths=1,
        dry_run=True,
        payloads=[{"event_type": "new_attack_path"}],
    )

    _write_json_output(output_path, result)

    assert '"event_type": "new_attack_path"' in output_path.read_text(encoding="utf-8")
