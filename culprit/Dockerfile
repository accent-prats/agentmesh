FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 culprit

WORKDIR /app

COPY culprit/requirements.txt ./culprit/requirements.txt
RUN pip install --no-cache-dir -r culprit/requirements.txt

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
