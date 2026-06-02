# MalCheck

> Unified Malware Analysis Orchestrator for local, offline-first workflows.

[![Python](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](#)
[![FastAPI](https://img.shields.io/badge/web-fastapi-009688?logo=fastapi&logoColor=white)](#)
[![Docker](https://img.shields.io/badge/runtime-docker%20compose-2496ED?logo=docker&logoColor=white)](#)
[![Ghidra](https://img.shields.io/badge/static-ghidra%20headless-orange)](#)
[![Report](https://img.shields.io/badge/output-json%20%2B%20html-4C1)](#)
[![Status](https://img.shields.io/badge/status-active-success)](#)

**Tags:** malware-analysis, ghidra, yara, capa, triage, offline, usb-deploy, reverse-engineering

---

## What MalCheck Is

MalCheck is a **phase-based malware analysis orchestrator** that runs:

- **Phase 1 - Surface Analysis** (hashes, strings, IOC extraction, YARA/capa, entropy/packer hints)
- **Phase 2 - Dynamic Analysis Contract** (hook-first, sandbox integration ready)
- **Phase 3 - Static Analysis** (Ghidra headless in a network-isolated container)

It generates:

- **Machine-readable JSON report**
- **Analyst-friendly HTML report**

MalCheck is designed for **local and air-gapped environments** and keeps explicit safety boundaries for malware workflows.

For Japanese docs, see [`README_JP.md`](README_JP.md).

---

## Product Positioning

MalCheck is the orchestration home for integrated analysis.

- Keep phase orchestration and report contract in `mau/`
- Integrate richer static/reverse-engineering capabilities incrementally
- Avoid monolithic one-shot rewrites

Current architecture and roadmap:

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/milestones.md`](docs/milestones.md)
- [`docs/implementation-rules.md`](docs/implementation-rules.md)
- [`docs/development-diary.md`](docs/development-diary.md)

---

## Core Features

### 1) Phase-Oriented Pipeline

`mau.phase_router.run_pipeline()` orchestrates:

- `surface` -> resilient fast triage
- `dynamic` -> skipped / not_implemented / hook result
- `static` -> Ghidra container execution

Failures are isolated by phase and embedded into report payloads instead of crashing the full run.

### 2) Offline-First Deployment

- USB/offline packaging scripts are included
- Air-gap-friendly deployment paths exist for Windows/Linux
- Ghidra static analysis remains network-isolated by default

### 3) Report-First Design

Every run produces structured report artifacts:

- `results/reports/<sample>.json`
- `results/reports/<sample>.html`

Recent report contract includes:

- `meta.schema_version`
- `phase_status.surface/dynamic/static`
- normalized phase payloads

### 4) Extensible Dynamic Integration

Dynamic analysis is intentionally hook-first:

- Safe default: disabled (`skipped`)
- Enabled without hook: `not_implemented`
- Enabled with `MAU_DYNAMIC_HOOK`: normalized dynamic payload

---

## Quick Start

### A. Local Docker stack

```text
docker compose up -d
```

Run one sample from orchestrator:

```text
docker exec orchestrator python -m mau.main suspect.exe
```

Web UI:

```text
http://127.0.0.1:8080
```

### B. FLARE VM / Offline workflow (Windows)

1. Prepare images on a connected host
   - Place `ghidra_11.4.3_PUBLIC_20251203.zip` in `build/ghidra-headless/`
   - Run:
   ```text
   bash make_usb.sh
   ```
2. On offline analysis machine:
   ```text
   deploy.bat
   ```
3. Analyze:
   ```text
   copy suspect.exe samples\
   docker exec orchestrator python -m mau.main suspect.exe
   ```

Stop:

```text
docker compose -f docker-compose.usb.yml --env-file compose\.env.runtime down
```

---

## Ghidra Image Build

Build the static-analysis image after placing the Ghidra zip:

```text
docker build -t ghidra-headless:latest -f build/ghidra-headless/Dockerfile build/ghidra-headless
```

If the image is missing, static phase records an error payload but the pipeline can still emit reports from other phases.

---

## Configuration

Primary config file:

- `compose/config/analyzer.yaml`

Or override with env:

- `MAU_CONFIG=<path-to-yaml>`

High-impact keys:

- `phases.dynamic.enabled`
- `phases.static.ghidra_image`
- `report.executive_summary_llm`
- `ollama.base_url`
- `ollama.model`

---

## Testing

Host test command:

```text
pip install -r requirements-dev.txt
pytest tests -v
```

The current suite validates:

- config loading/merge behavior
- surface analyzer JSON contract
- report aggregation and verdict logic
- dynamic hook normalization
- CLI error/exit behavior

---

## Security and OPSEC Boundaries

MalCheck is for malware analysis. Treat all sample-derived data as hostile.

- Do not commit samples, payloads, or IOC-heavy artifacts
- Do not add automatic online IOC enrichment by default
- Keep static/Ghidra containers network-isolated
- Keep dynamic detonation opt-in and lab-backed

See full rules in [`docs/implementation-rules.md`](docs/implementation-rules.md).

---

## Repository Map

```text
mau/                     # core orchestrator and report generation
scripts/remnux/          # surface analysis script
build/ghidra-headless/   # Ghidra static image assets
containers/surface/      # lightweight surface-analysis container
web_ui/                  # FastAPI + Jinja web interface
compose/config/          # runtime analyzer config
rules/yara/              # YARA rules
tests/                   # pytest suite
docs/                    # architecture, milestones, rules, diary
```

---

## Roadmap Snapshot

Near-term milestones:

1. Surface analysis consolidation (stable scanner contract)
2. Richer static output integration
3. Report/UI improvements
4. Dynamic hook contract hardening
5. Optional CAPE/VM integration

Detailed plan: [`docs/milestones.md`](docs/milestones.md)

---

## License / Usage Note

This repository is intended for defensive research, reverse engineering, and controlled lab workflows.
Use only in environments and jurisdictions where you are authorized to perform malware analysis.
