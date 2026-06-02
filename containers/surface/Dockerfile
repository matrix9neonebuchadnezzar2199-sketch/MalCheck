FROM python:3.11-slim-bookworm

LABEL maintainer="malware-unified-analyzer"
LABEL description="Lightweight surface analysis (alternative to full REMnux)"

RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
        file \
    && rm -rf /var/lib/apt/lists/*

COPY containers/surface/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

RUN mkdir -p /scripts /rules /samples /results
# Build with context repo root: docker build -f containers/surface/Dockerfile .
COPY scripts/remnux/analyze.py /scripts/analyze.py
RUN chmod +x /scripts/analyze.py

ENV RULES_DIR=/rules
WORKDIR /scripts

# Default: idle (orchestrator uses docker exec)
CMD ["sleep", "infinity"]
