# Azure Functions custom-container image for the Durable Functions port of
# Culprit's pipeline (culprit/culprit/serverless/). Built from the repo
# root, exactly like culprit/Dockerfile (same build context), so this is a
# second front door onto the SAME package - not a second copy of it.
#
# NOT YET BUILT OR DEPLOYED in this repo - no Docker daemon was available
# to validate this build locally. Smoke-test it (`docker build` + `docker
# run`, or `func start` against the built image) on the lab host before
# any real deployment - see this directory's README.md for exactly what
# has and hasn't been verified.
FROM mcr.microsoft.com/azure-functions/python:4-python3.12

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# /home/site/wwwroot is where the Azure Functions host (baked into this
# base image) looks for host.json/function_app.py - everything else (the
# actual pipeline/collectors/models/reporting code) stays importable from
# /app via PYTHONPATH below, the same layout culprit/Dockerfile already
# uses for the Docker Compose deployment.
ENV AzureFunctionsJobHost__Logging__Console__IsEnabled=true \
    PYTHONPATH=/app/culprit:/app

WORKDIR /app

COPY culprit/requirements.txt ./culprit/requirements.txt
RUN pip install --no-cache-dir -r culprit/requirements.txt azure-functions azure-functions-durable

# Vendored, optional: IT's own `tcx_mailer` package - same conditional-
# install convention as culprit/Dockerfile (see culprit/vendor/tcx_mailer/
# README.md).
COPY culprit/vendor/tcx_mailer/ /tmp/vendor/tcx_mailer/
RUN if [ -f /tmp/vendor/tcx_mailer/pyproject.toml ] || [ -f /tmp/vendor/tcx_mailer/setup.py ]; then \
        pip install --no-cache-dir /tmp/vendor/tcx_mailer/; \
    fi \
    && rm -rf /tmp/vendor

COPY culprit/ ./culprit/
COPY shared/ ./shared/

RUN mkdir -p /home/site/wwwroot \
    && cp culprit/culprit/serverless/host.json /home/site/wwwroot/host.json \
    && cp culprit/culprit/serverless/function_app.py /home/site/wwwroot/function_app.py
