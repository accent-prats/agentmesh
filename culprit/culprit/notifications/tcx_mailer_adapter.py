"""Email delivery through IT's own internal "_mailer" (tcx-mailer) utility -
a custom OAuth2 client-credentials-with-tenant-impersonation grant against
IT's own token endpoint, then a multipart POST to IT's own
"email-notification-jobs" REST API. See models/settings.py::
TcxMailerSettingsInput for the Settings-screen shape this reads.

This is a SIBLING to SMTP (email_sender.py::send_email) and Microsoft 365
OAuth (m365_oauth.py), never a replacement - which one actually sends is a
separate, explicit admin choice (EmailMethodSettingsInput); see
email_sender.py::resolve_active_email_config for how the three are picked
between.

Requires the vendor-provided `_mailer` package (IT's own wheel/git repo,
installed separately by ops onto wherever Culprit runs - not something this
codebase's own requirements.txt can pull, since it needs IT's private
GitLab credentials). Guarded the same way `msal`/azure-mgmt-compute are
guarded elsewhere in this codebase, so a deployment that hasn't installed
it yet degrades to "not installed" rather than failing to start.

Two real gotchas in the vendor's own `_mailer.mailer` module (read directly
from IT's shared source, not guessed), both worked around here:

1. `_mailer.mailer.send_email()`/`_get_token()` read ALL their configuration
   - tenant, username, password, token/API URLs, from-name - from process
   environment variables, not function parameters. Culprit stores these
   encrypted in its own database instead, and may have several callers in
   the same long-running process (concurrent HTTP requests, a background
   scheduler cycle), so every call here pushes the configured values into
   `os.environ` for the duration of the call, under a process-wide lock,
   and restores whatever was there before in a `finally` block - this
   module's use of the vendor package never leaks into or races with
   anything else running in the same process.

2. `_get_token()` caches its acquired token in a module-global `_TOKEN` with
   NO expiry check - once acquired in this process, every later call reuses
   it forever, even after Culprit saves different credentials, even once
   the real token has expired. This module resets `_mailer.mailer._TOKEN =
   None` before every call, forcing a fresh token every time (one extra
   token round-trip per send - negligible, since this sends at most a
   handful of emails a day). This is a deliberate reach into the vendor
   module's own private attribute - there's no public API to invalidate it.
"""
from __future__ import annotations

import os
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

try:
    import _mailer.mailer as _vendor_mailer

    _MAILER_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via the "not installed" branch below
    _MAILER_AVAILABLE = False

_NOT_INSTALLED_MESSAGE = "_mailer is not installed on this deployment - ask IT for the tcx-mailer wheel and pip install it"

# Every call - a real send or a credential test - goes through this lock,
# since both temporarily mutate process-global state (os.environ, the
# vendor module's own cached _TOKEN) that isn't safe to touch concurrently.
_SEND_LOCK = threading.Lock()

_ENV_KEYS = (
    "EMAIL_OAUTH_TENANT",
    "EMAIL_OAUTH_USERNAME",
    "EMAIL_OAUTH_PASSWORD",
    "EMAIL_FROM_NAME",
    "EMAIL_OAUTH_TOKEN_URL",
    "EMAIL_API_URL",
    "EMAIL_FROM_APP",
)


@contextmanager
def _vendor_env(cfg):
    """Pushes `cfg`'s fields into the env vars _mailer.mailer actually reads,
    resets its cached token so this call is guaranteed to use THESE
    credentials (not a stale token from an earlier call), and restores the
    previous environment exactly on the way out - success or failure."""
    values = {
        "EMAIL_OAUTH_TENANT": cfg.tenant,
        "EMAIL_OAUTH_USERNAME": cfg.username,
        "EMAIL_OAUTH_PASSWORD": cfg.password,
        "EMAIL_FROM_NAME": cfg.from_name,
    }
    # Blank means "let the installed package use its own hardcoded default" -
    # never force-clear a value that might already be set in this process's
    # environment (e.g. by the deployment's own .env) with an empty string.
    if cfg.token_url:
        values["EMAIL_OAUTH_TOKEN_URL"] = cfg.token_url
    if cfg.api_url:
        values["EMAIL_API_URL"] = cfg.api_url
    if cfg.from_app:
        values["EMAIL_FROM_APP"] = cfg.from_app

    previous = {key: os.environ.get(key) for key in _ENV_KEYS}
    with _SEND_LOCK:
        try:
            os.environ.update(values)
            _vendor_mailer._TOKEN = None
            yield
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def send_tcx_mailer(
    cfg, to: list[str], subject: str, body: str, attachments: list[tuple[str, bytes]] | None = None,
) -> tuple[bool, str]:
    """Real send via IT's own utility - never raises, same (ok, message)
    contract as email_sender.py::send_email/send_email_oauth. `cfg` is a
    fully decrypted TcxMailerSettingsInput (db/repository.py::
    load_tcx_mailer_settings) - callers never pass a Fernet ciphertext here.
    `attachments` is (filename, content) pairs - the vendor function only
    accepts file paths, so each is written to a temp file for the duration
    of this call and always cleaned up afterward, never left on disk."""
    if not _MAILER_AVAILABLE:
        return False, _NOT_INSTALLED_MESSAGE
    if not (cfg.tenant and cfg.username and cfg.password):
        return False, "tcx-mailer is not configured for this deployment"
    if not to:
        return False, "No recipients given"

    temp_paths: list[str] = []
    try:
        for filename, content in attachments or []:
            suffix = Path(filename).suffix or ""
            handle = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
            try:
                handle.write(content)
            finally:
                handle.close()
            temp_paths.append(handle.name)

        with _vendor_env(cfg):
            _vendor_mailer.send_email(to=to, subject=subject, body=body, attachments=temp_paths)
        return True, f"Sent to {len(to)} recipient(s)"
    except Exception as exc:  # noqa: BLE001 - reporting the real error is the point of a send attempt
        return False, str(exc)[:480]
    finally:
        for path in temp_paths:
            try:
                os.remove(path)
            except OSError:
                pass


def test_tcx_mailer_credentials(cfg) -> tuple[bool, str]:
    """Acquires a token only - never sends a real message, same "test auth,
    don't actually deliver" contract as every other credential test in this
    app (security/credential_test.py). Reaches into the vendor module's own
    private `_get_token()` - there's no public token-only check, and sending
    a real email just to "test" the connection would be worse (every test
    click would spam a real recipient)."""
    if not _MAILER_AVAILABLE:
        return False, _NOT_INSTALLED_MESSAGE
    if not (cfg.tenant and cfg.username and cfg.password):
        return False, "Tenant, username, and password are all required"

    try:
        with _vendor_env(cfg):
            _vendor_mailer._get_token()
        return True, "Credentials accepted - token acquired"
    except Exception as exc:  # noqa: BLE001 - any failure degrades to (False, message), never raises
        return False, f"{type(exc).__name__}: {str(exc)[:400]}"
