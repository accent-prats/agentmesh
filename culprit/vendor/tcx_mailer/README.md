# Vendored `tcx_mailer` (optional)

Drop IT's real `tcx_mailer` package source here (the directory containing
its own `pyproject.toml` - the same thing `pip install .` already works
against on a VM where you've tested it from the command line) before
building the Culprit image, and it will be installed automatically. For
example, copy the whole checked-out repo in:

```bash
cp -r ~/tcx-mailer/tcx-mailer/* culprit/vendor/tcx_mailer/
```

so this directory ends up containing `pyproject.toml`, `tcx_mailer/`, etc.
directly (not another nested `tcx_mailer/` wrapper folder).

This directory is safe to leave empty (as it ships, with only this file
and a `.gitkeep`) - `culprit/notifications/tcx_mailer_adapter.py`
guard-imports the package and degrades to a clear "not installed" message
everywhere it's used, the same way `msal`/`azure-mgmt-compute` already do
for their own optional dependencies elsewhere in this app.

**Why vendor it instead of adding it to `requirements.txt`**: IT's package
isn't on any index this build can reach without private GitLab
credentials this repo doesn't have - vendoring the source directly into
the build context is the only way to bake it into the image without those
credentials. If your build process DOES have access to IT's GitLab, add
it to `culprit/requirements.txt` as a git URL instead and remove this
vendoring step from the Dockerfile - whichever is more convenient for your
own deployment.

**A real package here must be installed INSIDE the same container Culprit
itself runs in** - a separate venv on the host VM (e.g. one you built just
to test `tcx-mailer --help` from the command line) is invisible to the
Culprit container, which has its own isolated Python environment baked
into the image. This vendoring step is what gets it into that image for
real, surviving every future rebuild/redeploy - not a one-off
`docker exec ... pip install` into an already-running container, which
gets wiped the next time the image is rebuilt.
