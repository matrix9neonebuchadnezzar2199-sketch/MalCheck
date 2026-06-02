# Malware Unified Analyzer (v1.0)

Python orchestrator that runs **Phase 1 (surface)**, optional **Phase 2 (dynamic stub)**, **Phase 3 (Ghidra headless in Docker, network-isolated)**, and produces **JSON + HTML** reports.

## Quick Start (FLARVM: Windows 10 / offline VM)

1. Prepare images (host / network available)

   - Put `ghidra_11.4.3_PUBLIC_20251203.zip` into `build/ghidra-headless/` (first time only)
   - Run the packaging script:
     ```text
     bash make_usb.sh
     ```

2. Deploy on FLARVM (offline VM, Windows)
   ```text
   deploy.bat
   ```
   (`deploy.bat` loads `images/*.tar.gz` and starts containers with `docker-compose.usb.yml`.)

3. Put a sample and run analysis
   ```text
   copy suspect.exe samples\
   docker exec orchestrator python -m mau.main suspect.exe
   ```

4. Open the Web UI (after step 2)
   ```text
   http://127.0.0.1:8080
   ```

Reports are written under `results/reports/` (JSON + HTML).

Stop:
```text
docker compose -f docker-compose.usb.yml --env-file compose\.env.runtime down
```

## Ghidra headless image

Place `ghidra_11.4.3_PUBLIC_20251203.zip` in `build/ghidra-headless/` (see `PLACE_GHIDRA_ZIP_HERE.txt`), then:

```text
docker build -t ghidra-headless:latest -f build/ghidra-headless/Dockerfile build/ghidra-headless
```

Without this image, Phase 3 records an error in the report but Phases 1–2 still complete.

## REMnux (full USB / air-gap workflow)

Use `docker-compose.remnux.yml` instead of the default file when the REMnux image is loaded. Adjust `SURFACE_CONTAINER` / `REMNUX_CONTAINER` to `remnux-analyzer`.

## USB deploy

- **Development machine:** run `bash build/build_and_pack.sh` (requires Ghidra zip for that step).
- **Analysis machine:** run `deploy.sh` or `deploy.bat`, then `docker compose` as printed.

## Configuration

Edit `compose/config/analyzer.yaml` or set `MAU_CONFIG` to a YAML file path.

- `phases.dynamic.enabled`: set `true` only with a custom hook (`MAU_DYNAMIC_HOOK` env) that prints JSON.
- `report.executive_summary_llm`: requires a reachable Ollama API (`ollama.base_url`).

## Tests (host)

```text
pip install -r requirements-dev.txt
pytest tests -v
```

## Error handling

Phases catch failures and embed `{ "error": true, ... }` in the report instead of stopping the whole run, except when report generation itself fails. Set `MAU_LOG_LEVEL=DEBUG` for more detail.
