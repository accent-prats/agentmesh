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

Found AGAIN live (2026-11-22), one restart later: the first attempt at
this fix symlinked /app/culprit itself, not /app/culprit/culprit, and
only swapped the error for `ModuleNotFoundError: No module named
'culprit.serverless'` - this repo's own `culprit/` top-level directory is
NOT the importable package; the real package (with its own __init__.py)
is nested one level deeper, at culprit/culprit/. `shared` has no such
extra nesting. The test below checks the Dockerfile's symlink target
AND, separately, re-derives the same nesting fact directly from this
repo's own real directory layout - so if the repo's layout ever changes,
this fails for the right reason instead of happily agreeing with a
Dockerfile that's silently gone stale again.
"""
from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DOCKERFILE = _REPO_ROOT / "culprit" / "culprit" / "serverless" / "Dockerfile"


def _dockerfile_text() -> str:
    assert _DOCKERFILE.is_file(), f"expected a Dockerfile at {_DOCKERFILE}"
    return _DOCKERFILE.read_text(encoding="utf-8")


def test_the_repos_own_layout_really_does_nest_culprit_one_level_deeper_than_shared():
    """Re-derives the nesting fact the Dockerfile's symlink depends on,
    directly from disk - not just from another copy of the same claim."""
    assert (_REPO_ROOT / "culprit" / "culprit" / "__init__.py").is_file(), (
        "the real importable `culprit` package is expected at culprit/culprit/, "
        "one level below this repo's own culprit/ directory"
    )
    assert not (_REPO_ROOT / "culprit" / "__init__.py").is_file(), (
        "culprit/ itself (one level up from the real package) must NOT be "
        "importable on its own, or the Dockerfile's extra /culprit symlink "
        "segment would be wrong"
    )
    assert (_REPO_ROOT / "shared" / "src" / "llm" / "catalog.py").is_file(), (
        "shared, unlike culprit, has no extra nesting - shared/src/... sits "
        "directly under this repo's own shared/ directory"
    )


def test_the_culprit_package_is_reachable_from_wwwroot_at_the_correct_nesting_level():
    text = _dockerfile_text()
    assert "ln -s /app/culprit/culprit /home/site/wwwroot/culprit" in text, (
        "function_app.py's own `from culprit.serverless import ...` needs the "
        "REAL nested package (culprit/culprit/, not culprit/ itself) importable "
        "from /home/site/wwwroot - the one location the Python worker's sys.path "
        "is guaranteed to include, unlike PYTHONPATH. Symlinking /app/culprit "
        "itself (one level too shallow) only trades 'No module named culprit' "
        "for 'No module named culprit.serverless' - a real regression hit "
        "2026-11-22 on the very first live redeploy of the first fix."
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
