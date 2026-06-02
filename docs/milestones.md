# MalCheck Development Milestones

Last updated: 2026-06-02

## Strategy

Build MalCheck as a phase-based malware analysis orchestrator. Do not attempt to complete surface, static, dynamic, UI, reporting, and USB distribution in one pass. Each milestone must leave the repository in a working, testable state.

Priority order:

1. Freeze the integration spec and report contract.
2. Consolidate surface analysis.
3. Upgrade static analysis with Cyber Ghidra-compatible output.
4. Improve reports and UI.
5. Formalize dynamic analysis hooks.
6. Add optional sandbox integration.
7. Harden packaging and offline deployment.

## Milestone 0: Foundation Documents and Contracts

Purpose: make the intended direction unambiguous before implementation begins.

Scope:

- Architecture: `docs/architecture.md`.
- Milestones: `docs/milestones.md`.
- Implementation rules: `docs/implementation-rules.md`.
- Development diary: `docs/development-diary.md`.
- Agent guidance: `AGENTS.md`.

Acceptance criteria:

- The target report schema is documented.
- The relationship between MalCheck and Cyber Ghidra WebUI is documented.
- Dynamic analysis is clearly marked as hook-first, not full sandbox-first.
- Safety boundaries for samples, IOCs, network isolation, and Docker are written down.

Verification:

- Read the docs from a fresh session and confirm the next implementation slice is obvious.
- Run `pytest tests -v` to ensure documentation changes did not disturb the current package.

## Milestone 1: Surface Analysis Consolidation

Purpose: make Phase 1 the reliable entry point for fast triage.

Scope:

- Keep existing hash, file type, string sample, URL/IP, entropy, YARA, capa, and DIE behavior.
- Add a stable `scanner_results` list under `phase1_surface`.
- Design or implement an adapter for Cyber Ghidra scanner plugin results.
- Deduplicate overlapping YARA/capa output.

Acceptance criteria:

- `python -m mau.main <sample>` still produces JSON and HTML reports.
- `phase1_surface` contains the legacy fields plus `scanner_results`.
- A single scanner failure is recorded but does not abort the pipeline.
- Tests cover success, scanner failure, and missing optional tool cases.

Verification:

- `pytest tests -v`
- Manual CLI smoke with a benign local sample in `samples/`.

Files likely touched:

- `mau/surface_runner.py`
- `scripts/remnux/analyze.py`
- `mau/report_generator.py`
- `tests/`
- Optional adapter module under `mau/`

## Milestone 2: Static Analysis Upgrade

Purpose: replace MalCheck's simple Ghidra output with richer Cyber Ghidra-compatible static analysis.

Scope:

- Introduce a `phase3_static.engine` field.
- Add `phase3_static.analysis_json` for rich Ghidra output.
- Preserve legacy `decompiled_c`, `functions`, and `metadata` compatibility during migration.
- Keep static analysis network-isolated.

Acceptance criteria:

- Ghidra image missing still produces a structured `phase3_static.error` report.
- Ghidra success produces function-level analysis JSON.
- The report can summarize function count, imports, strings, suspicious APIs, and truncation status.
- Static analysis failures do not block report generation.

Verification:

- Unit tests for static result normalization.
- Manual Ghidra smoke when the Ghidra image is available.

Files likely touched:

- `mau/static_analyzer.py`
- `build/ghidra-headless/scripts/`
- `scripts/ghidra/`
- `mau/report_generator.py`
- `tests/`

## Milestone 3: Report Schema v2 and HTML Improvements

Purpose: make the report useful for analysts and stable for future UI work.

Scope:

- Add `meta.schema_version`.
- Normalize IOC aggregation from surface, static, and dynamic phases.
- Improve verdict reasons so they cite phase evidence.
- Show phase status clearly in HTML: completed, skipped, not implemented, failed.
- Add sections for Ghidra summary and dynamic status.

Acceptance criteria:

- Existing reports remain readable.
- New reports include schema version and phase status.
- HTML report does not render raw unbounded JSON by default.
- Large phase payloads are summarized with links or collapsible sections.

Verification:

- `pytest tests/test_report_generator.py -v`
- Manual HTML report review.

Files likely touched:

- `mau/report_generator.py`
- `mau/templates/report.html`
- `tests/test_report_generator.py`

## Milestone 4: Web UI Baseline

Purpose: turn the current upload endpoint into a usable local analyst UI without rebuilding Cyber Ghidra's full React UI yet.

Scope:

- Upload sample.
- Run pipeline.
- Show status/result links.
- List generated reports.
- Display verdict, hashes, phase status, and top findings.

Acceptance criteria:

- `http://127.0.0.1:8080` can upload and run a sample.
- The UI links to JSON and HTML report outputs.
- Errors are readable and do not expose internal stack traces by default.
- Filename sanitization and size limits are enforced.

Verification:

- FastAPI TestClient tests for upload validation and health.
- Manual local upload smoke.

Files likely touched:

- `web_ui/app.py`
- `web_ui/templates_web/index.html`
- `tests/`

## Milestone 5: Dynamic Hook Contract

Purpose: make Phase 2 integration-ready without pretending a sandbox exists.

Scope:

- Define required and optional keys for `MAU_DYNAMIC_HOOK` output.
- Add validation/normalization for hook output.
- Add test fixtures for skipped, not implemented, hook success, and hook failure.
- Show dynamic status in reports.

Acceptance criteria:

- Dynamic disabled returns `status=skipped`.
- Dynamic enabled with no hook returns `status=not_implemented`.
- Hook success returns normalized dynamic JSON.
- Hook failure is captured as `error=true` and report generation continues.

Verification:

- `pytest tests -v`
- Mock hook script integration test.

Files likely touched:

- `mau/dynamic_analyzer.py`
- `mau/report_generator.py`
- `tests/`
- `docs/architecture.md`

## Milestone 6: Optional CAPE or VM Integration

Purpose: add real dynamic analysis through an external sandbox backend.

Preferred first backend: CAPEv2 API.

Scope:

- Submit sample to sandbox.
- Poll task status.
- Fetch behavioral report.
- Normalize network, process, registry, filesystem, and dropped-file summaries.
- Keep lab network assumptions explicit.

Acceptance criteria:

- Sandbox integration is disabled by default.
- CAPE API failures are recorded without aborting surface/static phases.
- No live IOC lookup or uncontrolled outbound connection is performed by MalCheck itself.
- Dynamic output fits the Phase 2 contract from Milestone 5.

Verification:

- Mock CAPE API tests.
- Manual lab-only smoke test.

## Milestone 7: Offline Packaging and Release Hygiene

Purpose: preserve MalCheck's USB/offline strength as integrations grow.

Scope:

- Update `make_usb.sh`, `deploy.sh`, and `deploy.bat`.
- Document required image tar files and expected sizes.
- Ensure Ghidra ZIP handling remains reproducible.
- Add release checklist.

Acceptance criteria:

- Offline deployment docs match actual scripts.
- Missing optional images degrade gracefully.
- Sample files and real reports are never included in release artifacts.

Verification:

- Dry-run packaging on a development machine.
- Manual deploy smoke in an isolated test environment.

## Backlog

- React-based deep analysis view adapted from Cyber Ghidra WebUI.
- Function-level LLM annotation.
- Diff view between two reports.
- Data xrefs and string/import caller tracing.
- Redis or task queue if local parallel jobs become necessary.
- Stronger Docker socket isolation.
- PDF export from HTML report.

## Definition of Done

For each milestone:

- Tests pass with `pytest tests -v`.
- Documentation is updated in the same change.
- Any new phase output is included in the report schema.
- Failure paths are represented in JSON rather than crashing the whole run.
- No sample binaries, generated report payloads with real IOCs, secrets, or local-only paths are committed.
