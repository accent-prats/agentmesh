FROM python:3.12-alpine AS builder

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

WORKDIR /build
COPY portal/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-alpine

RUN adduser -D -u 1000 portal

WORKDIR /app

COPY --from=builder /install /usr/local

COPY portal/ /app/portal/
COPY shared/ /app/shared/

ENV PYTHONPATH=/app

RUN chown -R portal /app

USER portal

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

CMD ["uvicorn", "portal.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
