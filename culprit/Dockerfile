FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 culprit

WORKDIR /app

COPY culprit/requirements.txt ./culprit/requirements.txt
RUN pip install --no-cache-dir -r culprit/requirements.txt

# Vendored, optional: IT's own `tcx_mailer` package for the "tcx-mailer"
# email method (culprit/notifications/tcx_mailer_adapter.py) - not on any
# index this build can reach (needs IT's private GitLab credentials), so
# it's vendored into the build context instead of listed in requirements.txt.
# See culprit/vendor/tcx_mailer/README.md for how to drop the real source
# in. Safe to leave empty (ships with only a README + .gitkeep) - the `if`
# below just skips installing anything when it is, same "degrade to not
# installed" contract as every other optional dependency in this app.
COPY culprit/vendor/tcx_mailer/ /tmp/vendor/tcx_mailer/
RUN if [ -f /tmp/vendor/tcx_mailer/pyproject.toml ] || [ -f /tmp/vendor/tcx_mailer/setup.py ]; then \
        pip install --no-cache-dir /tmp/vendor/tcx_mailer/; \
    fi \
    && rm -rf /tmp/vendor

COPY culprit/ ./culprit/
COPY shared/ ./shared/

# /app/culprit is this build's copy of the top-level culprit/ directory,
# which itself contains the importable `culprit` python package
# (/app/culprit/culprit/...) — PYTHONPATH needs the parent of that package.
# /app is also on it so `shared.src.llm` (the multi-provider AI adapters -
# see api/deps.py::get_rca_agent) resolves the same way Portal's own
# Dockerfile already does for `shared.src.feature_flags`.
ENV PYTHONPATH=/app/culprit:/app

RUN mkdir -p /app/data && chown -R culprit /app/data

USER culprit

EXPOSE 8000
CMD ["uvicorn", "culprit.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
