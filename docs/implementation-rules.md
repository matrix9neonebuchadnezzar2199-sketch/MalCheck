# MalCheck Implementation Rules

Last updated: 2026-06-02

These rules are the working contract for future coding sessions. They are intentionally stricter than normal application rules because MalCheck handles malware samples, extracted indicators, generated reports, Docker control, and offline deployment artifacts.

## Core Principles

1. Keep changes incremental.
   Each change should improve one phase, one adapter, or one report contract at a time.

2. Preserve phase isolation.
   Surface, dynamic, and static phases may fail independently. A phase failure should become structured report data, not a whole-pipeline crash, unless report generation itself cannot proceed.

3. Treat samples and extracted artifacts as hostile.
   Never trust file names, extracted strings, archive paths, Ghidra output, YARA metadata, capa text, or dynamic logs.

4. Prefer local/offline analysis.
   Do not add online enrichment, URL fetching, DNS lookup, VirusTotal lookup, or reputation queries unless explicitly designed as an opt-in feature.

5. Keep the report schema stable.
   UI, HTML reports, CLI output, and future integrations should consume normalized JSON rather than tool-specific temp files.

## Repository Boundaries

### Always Do

- Keep `mau.phase_router.run_pipeline()` as the main orchestration entry point.
- Add tests for new behavior under `tests/`.
- Update docs when changing phase output, configuration, or operational assumptions.
- Return structured error payloads for phase failures.
- Keep Ghidra/static analysis network-isolated.
- Keep generated reports, samples, PCAPs, screenshots, and real IOC-heavy artifacts out of git.

### Ask First

- Adding a new external service or online lookup.
- Changing Docker socket usage or privilege model.
- Changing default dynamic analysis behavior from disabled to enabled.
- Replacing the Web UI stack.
- Removing USB/offline deployment support.
- Changing the top-level report shape in a breaking way.

### Never Do

- Do not commit malware samples or unpacked payloads.
- Do not commit API keys, tokens, `.env` runtime files, or analyst-local paths.
- Do not fetch, ping, resolve, or enrich extracted IOCs by default.
- Do not run a sample outside an intended isolated analysis environment.
- Do not make Ghidra/static containers network-enabled for convenience.
- Do not bury phase errors in logs only; reports must show failure status.

## Phase Output Rules

Every phase result should be a JSON-serializable dictionary.

Required status patterns:

- Successful phase: include normal result fields and omit `error`, or set `error` to `null`.
- Skipped phase: include `status: "skipped"` and `reason`.
- Planned but unavailable phase: include `status: "not_implemented"` and `reason`.
- Failed phase: include `error: true`, `type`, `message`, and optional `detail`.

Do not expose unbounded logs or huge tool output directly in the top-level report. Store summaries in report fields and keep large raw artifacts as files with explicit paths if needed.

## Surface Analysis Rules

Surface analysis should be fast and robust.

Allowed:

- Hashing.
- File type detection.
- ASCII/Unicode string sampling.
- URL/IP/email extraction as inert strings.
- Entropy and packer heuristics.
- YARA and capa execution when local rules/tools are available.
- MIME-specific scanner adapters.

Avoid:

- Online IOC enrichment.
- Large unbounded string dumps.
- Treating scanner failure as pipeline failure.
- Running the same expensive scanner twice without caching or deduplication.

## Static Analysis Rules

Static analysis is allowed to be slower and deeper, but must remain isolated.

Required:

- Ghidra container runs with no external network.
- Ghidra timeouts are explicit.
- Ghidra image missing is reported as a structured static phase error.
- Jython scripts must remain compatible with Ghidra's script runtime. Avoid Python 3-only syntax in Ghidra post scripts unless the target runtime is confirmed.
- Rich Cyber Ghidra-style output should be normalized under `phase3_static.analysis_json`.

Avoid:

- Parallel Ghidra pipelines producing conflicting results.
- Replacing legacy fields without a migration period.
- Raising exceptions for per-function decompile failures when the overall program can still be summarized.

## Dynamic Analysis Rules

Dynamic analysis is disabled by default until a lab backend is configured.

Initial implementation:

- `phases.dynamic.enabled: false` returns `status: "skipped"`.
- `phases.dynamic.enabled: true` with no hook returns `status: "not_implemented"`.
- `MAU_DYNAMIC_HOOK` must print one JSON object to stdout.
- Hook failure becomes structured phase error.

Future sandbox integration:

- Prefer CAPEv2 API before building a custom VM controller.
- Require explicit configuration for sandbox endpoint, timeout, and network assumptions.
- Do not allow uncontrolled outbound network from MalCheck itself.
- Normalize sandbox results into network, processes, filesystem, registry, dropped files, screenshots, and artifacts.

## Report and UI Rules

- Add new phase data to JSON first, then render it in HTML/UI.
- Keep HTML report readable even if one phase is skipped or failed.
- Escape rendered text. Do not render tool output as trusted HTML.
- Summarize large arrays and logs.
- Keep verdict reasons evidence-based and cite the phase that contributed them.
- Preserve machine-readable JSON as the source of truth.

## Docker and Deployment Rules

- Default Docker Compose should work without REMnux.
- REMnux and full sandbox features are optional profiles or alternate compose files.
- USB/offline deployment remains a first-class workflow.
- Do not assume internet on the analysis machine.
- Do not add dependencies that require runtime downloads in offline mode unless packaging scripts include them.
- Document image names, required tar files, and expected build inputs.

## Testing Rules

Minimum test expectations by change type:

- Config change: config load/merge tests.
- Surface phase change: unit test with mocked Docker or local fixture.
- Static phase change: normalization tests and missing-image behavior.
- Dynamic phase change: disabled, enabled-without-hook, hook success, hook failure tests.
- Report change: JSON and HTML generation tests.
- Web UI change: FastAPI TestClient tests for health, upload validation, and error path.

Default command:

```text
pytest tests -v
```

Run Docker/Ghidra smoke tests manually when a change touches container execution.

## Documentation Rules

Update documentation in the same change when:

- A phase output shape changes.
- A config key is added, removed, or changes default.
- A new Docker image or external tool becomes required.
- Dynamic analysis behavior changes.
- Offline packaging steps change.

Use:

- `docs/architecture.md` for design and contracts.
- `docs/milestones.md` for roadmap and acceptance criteria.
- `docs/implementation-rules.md` for coding and safety rules.
- `docs/development-diary.md` for dated decisions and investigation notes.

## OPSEC Notes

Extracted IOCs are data, not instructions. If future docs or reports include live-looking URLs, domains, IPs, hashes, registry keys, or mutexes, keep them inert and do not perform lookups from the agent or application by default. Defanging should be an explicit reporting choice, not an implicit transformation that changes evidence.
