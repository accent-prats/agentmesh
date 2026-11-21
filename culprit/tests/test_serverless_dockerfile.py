"""culprit/serverless/Dockerfile - a static text check, not a build (no
Docker daemon in this test environment - see the Dockerfile's own
docstring for how this was actually smoke-tested, via a real Azure
deployment's Application Insights trace).

Found live (2026-11-21): the Azure Functions Python worker builds its own
sys.path from a fixed set of locations and does NOT honor this
container's PYTHONPATH env var, so function_app.py's own
`from culprit.serverless import activities, orchestrators` raised
`ModuleNotFoundError: No module named 'culprit'` even though /app/culprit
existed - /app was simply never on the worker's sys.path. This guards the
fix: the `culprit` and `shared` packages must be reachable directly from
/home/site/wwwroot, the one location the worker's sys.path is guaranteed
to include.
"""
from __future__ import annotations

from pathlib import Path

_DOCKERFILE = (
    Path(__file__).resolve().parent.parent / "culprit" / "serverless" / "Dockerfile"
)


def _dockerfile_text() -> str:
    assert _DOCKERFILE.is_file(), f"expected a Dockerfile at {_DOCKERFILE}"
    return _DOCKERFILE.read_text(encoding="utf-8")


def test_the_culprit_package_is_reachable_from_wwwroot_directly():
    text = _dockerfile_text()
    assert "ln -s /app/culprit /home/site/wwwroot/culprit" in text, (
        "function_app.py's own `from culprit.serverless import ...` needs the "
        "culprit package importable from /home/site/wwwroot - the one location "
        "the Python worker's sys.path is guaranteed to include, unlike PYTHONPATH"
    )


def test_the_shared_package_is_reachable_from_wwwroot_directly():
    text = _dockerfile_text()
    assert "ln -s /app/shared /home/site/wwwroot/shared" in text, (
        "culprit/api/deps.py imports from the shared package (the multi-provider "
        "LLM adapters the real RCA agent calls through) - it needs the same fix "
        "as the culprit package itself, or a real (non-demo) run would crash on "
        "ModuleNotFoundError: No module named 'shared' the first time it's used"
    )


def test_function_app_and_host_json_still_land_in_wwwroot():
    text = _dockerfile_text()
    assert "cp culprit/culprit/serverless/host.json /home/site/wwwroot/host.json" in text
    assert (
        "cp culprit/culprit/serverless/function_app.py /home/site/wwwroot/function_app.py"
        in text
    )
