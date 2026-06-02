# Ghidra 11.4.3 + JDK 21 — place ghidra_11.4.3_PUBLIC_20251203.zip next to this Dockerfile
FROM eclipse-temurin:21-jdk-jammy

LABEL maintainer="malware-unified-analyzer"
LABEL description="Disposable Ghidra headless for automated decompilation"

RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip \
        python3 \
        file \
    && rm -rf /var/lib/apt/lists/*

ARG GHIDRA_ZIP=ghidra_11.4.3_PUBLIC_20251203.zip
COPY ${GHIDRA_ZIP} /tmp/ghidra.zip

RUN unzip /tmp/ghidra.zip -d /opt/ \
    && mv /opt/ghidra_11.4.3_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && chmod +x /opt/ghidra/support/analyzeHeadless

ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="${GHIDRA_HOME}/support:${PATH}"

COPY scripts/ /ghidra-scripts/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /samples /output /tmp/ghidra-project
WORKDIR /output

RUN useradd -m -s /bin/bash analyzer \
    && chown -R analyzer:analyzer /samples /output /tmp/ghidra-project /ghidra-scripts
USER analyzer

ENTRYPOINT ["/entrypoint.sh"]
