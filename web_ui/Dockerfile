FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY build/orchestrator/requirements.txt /tmp/orchestrator-req.txt
RUN pip install --no-cache-dir -r /tmp/orchestrator-req.txt
RUN pip install --no-cache-dir "fastapi>=0.115.0" "uvicorn[standard]>=0.30.0" "python-multipart>=0.0.9"

COPY mau /app/mau
COPY web_ui /app/web_ui

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["uvicorn", "web_ui.app:app", "--host", "0.0.0.0", "--port", "8080"]
