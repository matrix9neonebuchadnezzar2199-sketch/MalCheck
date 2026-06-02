# MalCheck Development Diary

This diary records design decisions, investigation notes, and context that should survive across coding sessions. Keep entries factual and short enough to be useful.

## 2026-06-02: Establishing MalCheck as the Integration Home

### Context

Two related projects were compared:

- `MalCheck`: a Python malware analysis orchestrator with surface, dynamic, and static phases, JSON/HTML reports, USB/offline deployment, and a minimal FastAPI Web UI.
- `cyber-ghidra-webui-main`: a richer Ghidra WebUI with FastAPI, React, static scanner plugins, unpacking, history, CFG/call graph/xref views, and detailed `*_analysis.json`.

The GitHub repository `matrix9neonebuchadnezzar2199-sketch/MalCheck` was created as the intended storage location. At the time of the comparison, the remote repository appeared empty, while the local `F:\Cursor\MalCheck` directory contained the working project.

### Findings

MalCheck strengths:

- Clear `surface -> dynamic -> static -> report` phase model.
- Phase-level error isolation in `mau.phase_router`.
- JSON and HTML report generation.
- USB/offline deployment workflow.
- Existing YARA/capa-oriented surface analysis.
- Dynamic phase has a hook point via `MAU_DYNAMIC_HOOK`.

Cyber Ghidra strengths:

- Rich Ghidra output with per-function decompile data.
- CFG, call graph, xrefs, line-address map, suspicious API extraction.
- MIME-routed static scanner plugin architecture.
- Upload routing, archive handling, static-only path for documents/APK/PDF/Office.
- React UI patterns for reverse engineering workflows.

Shared ground:

- Python/FastAPI/Docker/Ghidra.
- Local-first malware analysis.
- Network-isolated Ghidra/static analysis.
- JSON outputs suitable for aggregation.

Main gaps:

- Dynamic analysis is not complete in either project.
- Ghidra output schemas are incompatible.
- UI depth differs significantly: MalCheck UI is minimal; Cyber Ghidra UI is analyst-focused.
- Docker security models differ: MalCheck uses Docker socket orchestration; Cyber Ghidra uses compose services and a network-isolated worker.

### Decision

Use MalCheck as the parent project and integration home.

Reasoning:

- MalCheck already expresses the product goal: unified malware analysis across phases.
- Its report generator and USB/offline workflow should not be rebuilt from scratch.
- Cyber Ghidra can be integrated as a static analysis and UI capability provider.
- A report-schema-first migration reduces the risk of merging two Ghidra pipelines blindly.

### Architecture Direction

The first stable target is:

```text
MalCheck CLI/Web
  -> phase_router
      -> Phase 1 surface analysis
      -> Phase 2 dynamic hook or skipped/not_implemented
      -> Phase 3 Cyber Ghidra-compatible static analysis
  -> unified JSON/HTML report
```

The report schema is the stable contract. Tool-specific outputs can be nested, but UI and reports should read normalized fields.

### Implementation Order

1. Add foundation documents.
2. Consolidate surface analysis and scanner results.
3. Upgrade static analysis output to Cyber Ghidra-compatible JSON.
4. Improve report and minimal Web UI.
5. Formalize dynamic hook JSON.
6. Add optional sandbox integration later.
7. Preserve USB/offline packaging.

### Non-Goals for the Next Slice

- Do not implement CAPE/VM dynamic analysis yet.
- Do not port the entire Cyber Ghidra React UI immediately.
- Do not run two independent Ghidra pipelines in parallel.
- Do not add online IOC lookups.
- Do not change default dynamic analysis from disabled to enabled.

### Safety Notes

MalCheck handles malware samples and extracted indicators. Future code should treat all sample-derived text as hostile data. Extracted URLs, IPs, hashes, registry keys, and mutexes must not trigger online lookup by default.

Ghidra/static analysis should remain network-isolated. Dynamic analysis requires an explicit lab backend and should stay opt-in.

### Files Created in This Foundation Pass

- `docs/architecture.md`: target architecture and integration contracts.
- `docs/milestones.md`: milestone roadmap and acceptance criteria.
- `docs/implementation-rules.md`: coding, safety, testing, and documentation rules.
- `docs/development-diary.md`: this diary.
- `AGENTS.md`: short operational guidance for future agents.

### Next Recommended Work

Start with Milestone 1 from `docs/milestones.md`: add a stable `phase1_surface.scanner_results` shape and decide how to adapt Cyber Ghidra scanner output without duplicating expensive YARA/capa scans.
