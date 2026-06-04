FROM python:3.11-slim-bookworm

LABEL maintainer="malware-unified-analyzer"
LABEL description="Lightweight surface analysis (alternative to full REMnux)"

RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
        file \
        upx-ucl \
    && rm -rf /var/lib/apt/lists/*

COPY containers/surface/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

RUN mkdir -p /scripts /rules /samples /results
# Build with context repo root: docker build -f containers/surface/Dockerfile .
COPY scripts/remnux/analyze.py /scripts/analyze.py
COPY scripts/remnux/format_scanners.py /scripts/format_scanners.py
COPY scripts/remnux/ioc_extract.py /scripts/ioc_extract.py
COPY scripts/remnux/fuzzy_hash.py /scripts/fuzzy_hash.py
COPY scripts/remnux/attack_map.py /scripts/attack_map.py
COPY scripts/remnux/scanner_dedup.py /scripts/scanner_dedup.py
RUN chmod +x /scripts/analyze.py

ENV RULES_DIR=/rules
WORKDIR /scripts

# Default: idle (orchestrator uses docker exec)
CMD ["sleep", "infinity"]
