from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def test_backend_is_a_locked_uv_project():
    project = tomllib.loads((BACKEND / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["name"] == "netaudit"
    assert project["project"]["version"] == "1.0.0"
    assert project["project"]["requires-python"] == ">=3.11"
    assert project["project"]["dependencies"] == [
        "fastapi==0.141.1",
        "uvicorn[standard]==0.52.0",
        "pydantic==2.13.4",
        "psutil==7.2.2",
        'scapy==2.7.0; platform_system == "Windows"',
        "python-multipart==0.0.32",
    ]
    assert project["dependency-groups"]["dev"] == [
        "pytest==9.1.1",
        "httpx==0.28.1",
    ]
    assert not (BACKEND / "requirements.txt").exists()
    assert (BACKEND / "uv.lock").is_file()


def test_windows_launcher_syncs_and_runs_the_backend_with_uv():
    launcher = (ROOT / "start.ps1").read_text(encoding="utf-8")

    assert "Get-Command uv -ErrorAction Stop" in launcher
    assert "& $uv sync --project $backend" in launcher
    assert "'run', '--directory', $backend, '--no-sync', '-m', 'netaudit.server'" in launcher
    assert "pip install" not in launcher
    assert "python -m venv" not in launcher


def test_readme_documents_the_uv_project_workflow():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Requires uv and Node.js 20+" in readme
    assert "uv sync --project backend" in readme
    assert "uv run --directory backend -m netaudit.server" in readme
    assert "python3 -m venv backend/.venv" not in readme
    assert "pip install -r backend/requirements.txt" not in readme
    assert "python -m netaudit.server" not in readme