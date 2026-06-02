FROM python:3.11-slim-bookworm

LABEL maintainer="malware-unified-analyzer"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY build/orchestrator/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY mau /app/mau

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Compose 起動時は常駐させる（解析は docker exec で個別に実行する）
CMD ["sleep", "infinity"]
