# 生产镜像：仅标准库依赖，适合内网/离线部署
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY policies ./policies
COPY contracts ./contracts
COPY datasets ./datasets
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN pip install --no-cache-dir . \
    && chmod +x /usr/local/bin/entrypoint.sh \
    && useradd --create-home --shell /usr/sbin/nologin judge \
    && mkdir -p /app/var \
    && chown -R judge:judge /app

USER judge

ENV AGENTJUDGE_POLICY=/app/policies/default.toml \
    PORT=8737

EXPOSE 8737

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8737\")}/api/v1/health', timeout=3)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
