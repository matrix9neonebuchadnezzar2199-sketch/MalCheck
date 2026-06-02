"""Surface runner with mocked Docker."""

from unittest.mock import MagicMock, patch

from mau.surface_runner import _docker_sdk_exec


@patch("mau.surface_runner.docker.from_env")
def test_docker_sdk_exec_json(mock_from_env):
    mock_c = MagicMock()
    mock_c.exec_run.return_value = (0, b'{"ok": true, "hashes": {}}')
    mock_from_env.return_value.containers.get.return_value = mock_c

    out = _docker_sdk_exec("surface-analyzer", "/scripts/analyze.py", "/samples/a.exe")
    assert out["ok"] is True
